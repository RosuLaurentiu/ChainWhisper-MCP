import {
  request as httpRequest,
  type IncomingMessage,
} from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Script } from 'node:vm';

import { afterEach, describe, expect, it } from 'vitest';

import {
  LocalWebFormElicitor,
  loadSignerConfig,
  saveAgentWallet,
  type ConfirmationRequest,
  type WalletControlState,
} from '../src/signer/index.js';
import {
  agentControlStateKey,
  renderAgentControlPage,
} from '../src/signer/localControlPage.js';

const CONFIRMATION: ConfirmationRequest = {
  operationId: 'diagnostic',
  operationHash: `0x${'00'.repeat(32)}`,
  stepId: 'diagnostic',
  stepIndex: 0,
  stepCount: 1,
  wallet: '0x1111111111111111111111111111111111111111',
  contract: '0x0000000000000000000000000000000000000000',
  action: 'create_recurring',
  orderType: {
    id: 'recurring.private-liquidity.public',
    cadence: 'recurring',
    route: 'recurring-escrow',
    access: 'public',
    termsVisibility: 'hidden-liquidity',
    assetPrivacy: 'fully-private',
    relation: 'primary',
  },
  orderTypeLabel: 'Recurring · private liquidity · public price',
  assets: ['p.WISP', 'p.COTI'],
  amounts: ['12.5 p.WISP', '25 p.COTI'],
  details: [
    { label: 'You send', value: '12.5 p.WISP' },
    { label: 'You receive', value: '25 p.COTI' },
    { label: 'Buy price', value: '0.9 p.COTI per p.WISP' },
    { label: 'Sell price', value: '1.1 p.COTI per p.WISP' },
    { label: 'Market reference', value: '1 p.COTI per p.WISP · Carbon' },
    { label: 'Reference timestamp', value: '2026-07-29T10:00:00Z' },
    { label: 'Buy deviation', value: '-10%' },
    { label: 'Sell deviation', value: '+10%' },
    {
      label: 'On-chain visibility',
      value:
        'Sell inventory and buy budget are encrypted. Buy and sell prices, addresses, and order activity are public.',
    },
    { label: 'Maximum network fee', value: '0.08 COTI' },
    {
      label: 'Allowance spender',
      value: '0x2222222222222222222222222222222222222222',
    },
  ],
  counterparty: null,
  spender: '0x2222222222222222222222222222222222222222',
  fee: '0.1 COTI',
  nativeValue: '0',
  gasCap: '450000',
  expectedResult: 'A recurring order is created.',
  summary: 'Create a recurring private-liquidity order.',
};

const PRIVATE_AMOUNT_AUTHORITY_ENABLED =
  'The agent may both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.';

type HttpResult = {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
};

const rawRequest = (
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  } = {},
): Promise<HttpResult> =>
  new Promise((resolve, reject) => {
    const request = httpRequest(
      url,
      {
        method: options.method ?? 'GET',
        headers: options.headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(chunk));
        response.on('end', () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    request.once('error', reject);
    if (options.body) request.write(options.body);
    request.end();
  });

const header = (result: HttpResult, name: string): string => {
  const value = result.headers[name.toLowerCase()];
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
};

const hiddenValue = (html: string, name: string): string => {
  const match = html.match(
    new RegExp(`name="${name}" value="([^"]+)"`, 'u'),
  );
  if (!match?.[1]) throw new Error(`Missing ${name} form field.`);
  return match[1];
};

const establishSession = async (
  bootstrapUrl: string,
): Promise<{
  origin: string;
  controlUrl: string;
  cookie: string;
  bootstrap: HttpResult;
  page: HttpResult;
}> => {
  const bootstrap = await rawRequest(bootstrapUrl, {
    headers: {
      'Sec-Fetch-Site': 'none',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
    },
  });
  expect(bootstrap.status).toBe(303);
  expect(header(bootstrap, 'location')).toBe('/control');
  const setCookie = header(bootstrap, 'set-cookie');
  expect(setCookie).toContain('HttpOnly');
  expect(setCookie).toContain('SameSite=Strict');
  const cookie = setCookie.split(';')[0] ?? '';
  const origin = new URL(bootstrapUrl).origin;
  const controlUrl = `${origin}/control`;
  const page = await rawRequest(controlUrl, {
    headers: {
      Cookie: cookie,
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
    },
  });
  return { origin, controlUrl, cookie, bootstrap, page };
};

const submit = (
  session: {
    origin: string;
    cookie: string;
  },
  body: URLSearchParams | string,
  extraHeaders: Record<string, string> = {},
): Promise<HttpResult> => {
  const encoded = typeof body === 'string' ? body : body.toString();
  return rawRequest(`${session.origin}/action`, {
    method: 'POST',
    headers: {
      Cookie: session.cookie,
      Origin: session.origin,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': String(Buffer.byteLength(encoded)),
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Dest': 'document',
      ...extraHeaders,
    },
    body: encoded,
  });
};

type SseEvent = {
  event: string;
  data: string;
};

type SseWaiter = {
  event: string;
  settle: (result: SseEvent) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

type SseClient = {
  status: number;
  headers: IncomingMessage['headers'];
  nextEvent: (event?: string, timeoutMs?: number) => Promise<SseEvent>;
  close: () => void;
};

const sseClients: SseClient[] = [];

const openEventStream = (
  session: {
    origin: string;
    cookie: string;
  },
): Promise<SseClient> =>
  new Promise((resolve, reject) => {
    let buffer = '';
    let closed = false;
    const queued: SseEvent[] = [];
    const waiters: SseWaiter[] = [];

    const failWaiters = (error: Error): void => {
      for (const waiter of waiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(error);
      }
    };
    const emit = (result: SseEvent): void => {
      const index = waiters.findIndex(
        (waiter) => waiter.event === result.event,
      );
      if (index < 0) {
        queued.push(result);
        return;
      }
      const [waiter] = waiters.splice(index, 1);
      if (!waiter) return;
      clearTimeout(waiter.timer);
      waiter.settle(result);
    };
    const parse = (): void => {
      buffer = buffer.replaceAll('\r\n', '\n');
      let boundary = buffer.indexOf('\n\n');
      while (boundary >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        let event = 'message';
        const data: string[] = [];
        for (const line of block.split('\n')) {
          if (line.startsWith(':')) continue;
          if (line.startsWith('event:')) {
            event = line.slice('event:'.length).trim();
          } else if (line.startsWith('data:')) {
            data.push(line.slice('data:'.length).trimStart());
          }
        }
        if (data.length > 0) emit({ event, data: data.join('\n') });
        boundary = buffer.indexOf('\n\n');
      }
    };

    const request = httpRequest(
      `${session.origin}/events`,
      {
        headers: {
          Cookie: session.cookie,
          Origin: session.origin,
          Accept: 'text/event-stream',
          'Sec-Fetch-Site': 'same-origin',
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Dest': 'empty',
        },
      },
      (incoming) => {
        incoming.setEncoding('utf8');
        incoming.on('data', (chunk: string) => {
          buffer += chunk;
          parse();
        });
        incoming.once('error', (error) => {
          if (!closed) failWaiters(error);
        });
        incoming.once('end', () => {
          if (!closed) {
            failWaiters(
              new Error('Agent Control event stream ended unexpectedly.'),
            );
          }
        });
        const client: SseClient = {
          status: incoming.statusCode ?? 0,
          headers: incoming.headers,
          nextEvent: (event = 'state', timeoutMs = 2_000) => {
            const queuedIndex = queued.findIndex(
              (candidate) => candidate.event === event,
            );
            if (queuedIndex >= 0) {
              const [result] = queued.splice(queuedIndex, 1);
              return Promise.resolve(result!);
            }
            return new Promise<SseEvent>((settle, rejectEvent) => {
              const waiter: SseWaiter = {
                event,
                settle,
                reject: rejectEvent,
                timer: setTimeout(() => {
                  const index = waiters.indexOf(waiter);
                  if (index >= 0) waiters.splice(index, 1);
                  rejectEvent(
                    new Error(`Timed out waiting for SSE ${event} event.`),
                  );
                }, timeoutMs),
              };
              waiters.push(waiter);
            });
          },
          close: () => {
            if (closed) return;
            closed = true;
            failWaiters(new Error('Agent Control event stream closed.'));
            incoming.destroy();
            request.destroy();
          },
        };
        sseClients.push(client);
        resolve(client);
      },
    );
    request.once('error', (error) => {
      if (!closed) reject(error);
    });
    request.end();
  });

const eliciters: LocalWebFormElicitor[] = [];

afterEach(async () => {
  for (const client of sseClients.splice(0)) client.close();
  await Promise.all(eliciters.splice(0).map((elicitor) => elicitor.close()));
});

describe('local Agent Control elicitor', () => {
  it('uses a consumed bootstrap URL and renders a structured action card', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    let markBrowserStarted!: () => void;
    const browserStarted = new Promise<void>((resolve) => {
      markBrowserStarted = resolve;
    });
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.controlUrl).not.toContain('/open/');
          expect(session.page.status).toBe(200);
          expect(header(session.page, 'cache-control')).toContain('no-store');
          expect(header(session.bootstrap, 'referrer-policy')).toBe(
            'no-referrer',
          );
          expect(header(session.page, 'referrer-policy')).toBe(
            'same-origin',
          );
          expect(header(session.page, 'x-frame-options')).toBe('DENY');
          expect(header(session.page, 'access-control-allow-origin')).toBe('');
          const csp = header(session.page, 'content-security-policy');
          expect(csp).toContain("frame-ancestors 'none'");
          expect(csp).toContain("style-src 'nonce-");
          expect(csp).not.toContain("'unsafe-inline'");
          expect(session.page.body).toContain(
            'Create recurring private-liquidity order',
          );
          expect(session.page.body).toContain(
            'Private inventory · public prices',
          );
          expect(session.page.body).toContain(
            'Sell inventory and buy budget are encrypted. Buy and sell prices, addresses, and order activity are public.',
          );
          expect(session.page.body).toContain(
            'Recurring · private liquidity · public price',
          );
          expect(session.page.body).toContain(
            'Sell-side inventory · encrypted on-chain',
          );
          expect(session.page.body).toContain('12.5 p.WISP');
          expect(session.page.body).toContain(
            'Buy-side budget · encrypted on-chain',
          );
          expect(session.page.body).toContain('25 p.COTI');
          expect(session.page.body).toContain(
            'reusable two-sided liquidity',
          );
          expect(session.page.body).toContain(
            'It does not schedule automatic trades',
          );
          expect(session.page.body).toContain(
            '0.9 p.COTI per p.WISP',
          );
          expect(session.page.body).toContain(
            '1.1 p.COTI per p.WISP',
          );
          expect(session.page.body).toContain(
            '1 p.COTI per p.WISP · Carbon',
          );
          expect(session.page.body).toContain(
            '2026-07-29T10:00:00Z',
          );
          expect(session.page.body).toContain('-10%');
          expect(session.page.body).toContain('+10%');
          expect(session.page.body).toContain('Maximum network cost');
          expect(
            session.page.body.match(/Protocol fee/gu),
          ).toHaveLength(1);
          expect(session.page.body).toContain(
            'Confirm complete order creation',
          );
          const beforeTechnical =
            session.page.body.split(
              '<summary>Technical details</summary>',
            )[0] ?? '';
          expect(beforeTechnical).not.toContain('Native value');
          expect(beforeTechnical).not.toContain('Gas limit');
          expect(beforeTechnical).not.toContain('Allowance spender');
          expect(session.page.body).toContain(
            '<summary>Technical details</summary>',
          );
          expect(session.page.body).not.toContain(
            '<details open>',
          );
          expect(session.page.body).not.toContain('>Submit<');
          expect(session.page.body).not.toContain('type="checkbox"');
          expect(session.page.body).not.toMatch(
            /<(?:script|img|link)[^>]+https?:/iu,
          );
          expect(session.page.body).toContain(
            'const submitter = event.submitter',
          );
          expect(session.page.body).toContain(
            'event.preventDefault()',
          );
          expect(session.page.body).toContain(
            'const formData = new FormData(form)',
          );
          expect(session.page.body).toContain(
            'const response = await fetch(actionUrl',
          );
          expect(session.page.body).toContain(
            'patchSurface(source)',
          );
          expect(session.page.body).toContain(
            'data-dashboard-region',
          );
          expect(session.page.body).toContain(
            'data-review-region',
          );
          expect(session.page.body).not.toContain(
            'currentMain.replaceWith',
          );
          expect(
            session.page.body.match(/new EventSource\(/gu),
          ).toHaveLength(1);
          const clientScript = session.page.body.match(
            /<script nonce="[^"]+">([\s\S]*?)<\/script>/u,
          )?.[1];
          expect(clientScript).toBeDefined();
          expect(() => new Script(clientScript)).not.toThrow();
          expect(session.page.body).not.toContain(
            'window.location.assign',
          );
          expect(session.page.body).not.toContain(
            'window.location.href =',
          );

          const csrf = hiddenValue(session.page.body, 'csrf');
          const promptId = hiddenValue(session.page.body, 'promptId');
          const result = await submit(
            session,
            new URLSearchParams({
              csrf,
              promptId,
              intent: 'prompt',
              action: 'confirm',
            }),
          );
          expect(result.status).toBe(200);

          const replay = await rawRequest(url, {
            headers: {
              'Sec-Fetch-Site': 'none',
              'Sec-Fetch-Mode': 'navigate',
              'Sec-Fetch-Dest': 'document',
            },
          });
          expect(replay.status).toBe(401);
        })();
        markBrowserStarted();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    await browserStarted;
    await browserDone;
    await expect(confirmation).resolves.toEqual({
      outcome: 'accepted',
    });
  });

  it('collects private values only through the authenticated local form', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.page.body).toContain('Enter private order values');
          expect(session.page.body).toContain(
            'To let the agent choose these trade values',
          );
          expect(session.page.body).toContain('inputmode="decimal"');
          const snapshot = await rawRequest(`${session.origin}/snapshot`, {
            headers: { Cookie: session.cookie },
          });
          expect(snapshot.status).toBe(200);
          expect(snapshot.body).toContain('"kind":"private-values"');
          expect(snapshot.body).not.toContain('12.5');

          const result = await submit(
            session,
            new URLSearchParams({
              csrf: hiddenValue(session.page.body, 'csrf'),
              promptId: hiddenValue(session.page.body, 'promptId'),
              intent: 'prompt',
              action: 'confirm',
              sellBaseLiquidity: '12.5',
            }),
          );
          expect(result.status).toBe(200);
          expect(result.body).not.toContain('12.5');
        })();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestPrivateValues(
        {
          operationId: 'operation-1',
          operationHash: `0x${'11'.repeat(32)}`,
          wallet: CONFIRMATION.wallet,
          fields: [
            {
              id: 'sellBaseLiquidity',
              title: 'Private p.WISP inventory',
              description: 'Amount available to recurring sells.',
              kind: 'decimal-amount',
            },
          ],
        },
        5_000,
      ),
    ).resolves.toEqual({
      outcome: 'accepted',
      values: { sellBaseLiquidity: '12.5' },
    });
    await browserDone;
    expect(elicitor.focusedOperationId).toBeNull();
  });

  it('returns an explicit decline without requiring form values', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          const result = await submit(
            session,
            new URLSearchParams({
              csrf: hiddenValue(session.page.body, 'csrf'),
              promptId: hiddenValue(session.page.body, 'promptId'),
              intent: 'prompt',
              action: 'decline',
            }),
          );
          expect(result.status).toBe(200);
        })();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestConfirmation(CONFIRMATION, 5_000),
    ).resolves.toMatchObject({
      outcome: 'declined',
      reason: 'client-declined',
    });
    await browserDone;
  });

  it('rejects cross-origin, missing-CSRF, and replayed submissions', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          const csrf = hiddenValue(session.page.body, 'csrf');
          const promptId = hiddenValue(session.page.body, 'promptId');
          const valid = new URLSearchParams({
            csrf,
            promptId,
            intent: 'prompt',
            action: 'confirm',
          });
          const crossOrigin = await submit(session, valid, {
            Origin: 'https://chainwhisper.example',
          });
          expect(crossOrigin.status).toBe(403);
          const missingCsrf = await submit(
            session,
            new URLSearchParams({
              promptId,
              intent: 'prompt',
              action: 'confirm',
            }),
          );
          expect(missingCsrf.status).toBe(403);
          const accepted = await submit(session, valid);
          expect(accepted.status).toBe(200);
          const replay = await submit(session, valid);
          expect(replay.status).toBe(403);
        })();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestConfirmation(CONFIRMATION, 5_000),
    ).resolves.toEqual({ outcome: 'accepted' });
    await browserDone;
  });

  it('accepts each one-time CSRF token from concurrent same-session pages', async () => {
    let bootstrapUrl = '';
    const submitted: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        balance: '1 COTI',
        privacyStatus: 'onboarding-required',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations: 0,
        recentOperations: [],
        diagnostics: [],
        controlActions: { onboardPrivacy: true },
      }),
      onControlAction: (action) => {
        submitted.push(action);
        return { ok: true, message: 'Local action accepted.' };
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    const concurrentPage = await rawRequest(session.controlUrl, {
      headers: {
        Cookie: session.cookie,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(concurrentPage.status).toBe(200);

    const firstSubmission = new URLSearchParams({
      csrf: hiddenValue(session.page.body, 'csrf'),
      intent: 'control',
      action: 'onboard-privacy',
    });
    const secondSubmission = new URLSearchParams({
      csrf: hiddenValue(concurrentPage.body, 'csrf'),
      intent: 'control',
      action: 'onboard-privacy',
    });

    expect((await submit(session, firstSubmission)).status).toBe(200);
    expect(
      (
        await submit(session, secondSubmission, {
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Dest': 'empty',
        })
      ).status,
    ).toBe(200);
    expect(submitted).toEqual(['onboard-privacy', 'onboard-privacy']);
    expect((await submit(session, firstSubmission)).status).toBe(403);
    expect((await submit(session, secondSubmission)).status).toBe(403);
  });

  it('reuses a live SSE control page and publishes the pending prompt without opening a duplicate tab', async () => {
    const openedUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        openedUrls.push(url);
      },
      activeBrowserGraceMs: 40,
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(openedUrls[0] ?? '');
    const events = await openEventStream(session);
    expect(events.status).toBe(200);
    expect(events.headers['content-type']).toContain(
      'text/event-stream',
    );
    const initial = JSON.parse(
      (await events.nextEvent()).data,
    ) as { revision: number; stateKey: string };
    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    const pending = JSON.parse(
      (await events.nextEvent()).data,
    ) as { revision: number; stateKey: string };
    expect(pending.revision).toBeGreaterThan(initial.revision);
    expect(pending.stateKey).not.toBe(initial.stateKey);
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    expect(openedUrls).toHaveLength(1);

    const promptPage = await rawRequest(session.controlUrl, {
      headers: {
        Cookie: session.cookie,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(promptPage.status).toBe(200);
    expect(
      await submit(
        session,
        new URLSearchParams({
          csrf: hiddenValue(promptPage.body, 'csrf'),
          promptId: hiddenValue(promptPage.body, 'promptId'),
          intent: 'prompt',
          action: 'confirm',
        }),
      ),
    ).toMatchObject({ status: 200 });
    await expect(confirmation).resolves.toEqual({
      outcome: 'accepted',
    });
    expect(elicitor.focusedOperationId).toBe(
      CONFIRMATION.operationId,
    );
    expect(openedUrls).toHaveLength(1);
  });

  it('keeps an accepted manual operation focused until an authenticated local dismissal', async () => {
    let bootstrapUrl = '';
    let delegatedActions = 0;
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      activeBrowserGraceMs: 1_000,
      getControlSummary: () => ({
        wallet: CONFIRMATION.wallet,
        network: 'COTI Mainnet',
        balance: '1 COTI',
        privacyStatus: 'ready',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations: 0,
        recentOperations: [],
        diagnostics: [],
        controlActions: { onboardPrivacy: true },
      }),
      onControlAction: () => {
        delegatedActions += 1;
        return { ok: true, message: 'Unexpected delegated action.' };
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    const promptPage = await rawRequest(session.controlUrl, {
      headers: {
        Cookie: session.cookie,
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    const accepted = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(promptPage.body, 'csrf'),
        promptId: hiddenValue(promptPage.body, 'promptId'),
        intent: 'prompt',
        action: 'confirm',
      }),
    );
    expect(accepted.status).toBe(200);
    await expect(confirmation).resolves.toEqual({
      outcome: 'accepted',
    });
    expect(elicitor.focusedOperationId).toBe(
      CONFIRMATION.operationId,
    );

    const dismissed = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(accepted.body, 'csrf'),
        intent: 'control',
        action: 'dismiss-focused-operation',
      }),
    );
    expect(dismissed.status).toBe(200);
    expect(dismissed.body).toContain('Operation details closed.');
    expect(elicitor.focusedOperationId).toBeNull();
    expect(delegatedActions).toBe(0);
  });

  it('does not treat an authenticated page load without SSE as a live control tab', async () => {
    const openedUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        openedUrls.push(url);
      },
      activeBrowserGraceMs: 25,
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    await establishSession(openedUrls[0] ?? '');

    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    await expect.poll(() => openedUrls.length).toBe(2);
    expect(openedUrls[1]).toMatch(/\/control$/u);

    await elicitor.close();
    await expect(confirmation).resolves.toEqual({
      outcome: 'cancelled',
    });
  });

  it('waits for the SSE disconnect grace period and then opens exactly one replacement tab', async () => {
    const openedUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        openedUrls.push(url);
      },
      activeBrowserGraceMs: 80,
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(openedUrls[0] ?? '');
    const events = await openEventStream(session);
    await events.nextEvent();
    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    await events.nextEvent();
    expect(openedUrls).toHaveLength(1);

    events.close();
    await new Promise<void>((resolve) => setTimeout(resolve, 30));
    expect(openedUrls).toHaveLength(1);
    await expect.poll(() => openedUrls.length).toBe(2);
    expect(openedUrls[1]).toMatch(/\/control$/u);
    await new Promise<void>((resolve) => setTimeout(resolve, 180));
    expect(openedUrls).toHaveLength(2);

    await elicitor.close();
    await expect(confirmation).resolves.toEqual({
      outcome: 'cancelled',
    });
  });

  it('rejects unauthenticated and cross-origin SSE connections', async () => {
    let bootstrapUrl = '';
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    const eventHeaders = {
      Accept: 'text/event-stream',
      'Sec-Fetch-Site': 'same-origin',
      'Sec-Fetch-Mode': 'cors',
      'Sec-Fetch-Dest': 'empty',
    };
    expect(
      (
        await rawRequest(`${session.origin}/events`, {
          headers: {
            Origin: session.origin,
            ...eventHeaders,
          },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await rawRequest(`${session.origin}/events`, {
          headers: {
            Cookie: session.cookie,
            Origin: 'https://attacker.example',
            ...eventHeaders,
          },
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await rawRequest(`${session.origin}/events`, {
          headers: {
            Cookie: session.cookie,
            Origin: session.origin,
            ...eventHeaders,
            Accept: 'text/html',
          },
        })
      ).status,
    ).toBe(403);
  });

  it('publishes SSE state events when the signer summary changes', async () => {
    let bootstrapUrl = '';
    let pendingOperations = 0;
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        balance: '1 COTI',
        privacyStatus: 'ready',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations,
        recentOperations: [],
        diagnostics: [],
      }),
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    const events = await openEventStream(session);
    const initial = JSON.parse(
      (await events.nextEvent()).data,
    ) as { revision: number; stateKey: string };

    pendingOperations = 1;
    const updated = JSON.parse(
      (await events.nextEvent('state', 2_500)).data,
    ) as { revision: number; stateKey: string };
    expect(updated.revision).toBeGreaterThan(initial.revision);
    expect(updated.stateKey).not.toBe(initial.stateKey);
  });

  it('does not issue a new-session CSRF token from an old delayed response', async () => {
    let initialSession:
      | Awaited<ReturnType<typeof establishSession>>
      | undefined;
    let replacementSession:
      | Awaited<ReturnType<typeof establishSession>>
      | undefined;
    let openAttempt = 0;
    let releaseFirstAction!: () => void;
    const firstActionRelease = new Promise<void>((resolve) => {
      releaseFirstAction = resolve;
    });
    let firstActionStarted!: () => void;
    const firstActionStart = new Promise<void>((resolve) => {
      firstActionStarted = resolve;
    });
    let actionCount = 0;
    const elicitor = new LocalWebFormElicitor({
      requireBrowserArrival: true,
      browserArrivalTimeoutMs: 500,
      openUrl: async (url) => {
        openAttempt += 1;
        if (openAttempt === 1) {
          initialSession = await establishSession(url);
        } else if (openAttempt === 3) {
          replacementSession = await establishSession(url);
        }
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        balance: '1 COTI',
        privacyStatus: 'onboarding-required',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations: 0,
        recentOperations: [],
        diagnostics: [],
        controlActions: { onboardPrivacy: true },
      }),
      onControlAction: async () => {
        actionCount += 1;
        if (actionCount === 1) {
          firstActionStarted();
          await firstActionRelease;
        }
        return { ok: true, message: 'Local action accepted.' };
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    if (!initialSession) throw new Error('Initial session was not opened.');
    const firstSession = initialSession;
    const delayedResponse = submit(
      firstSession,
      new URLSearchParams({
        csrf: hiddenValue(firstSession.page.body, 'csrf'),
        intent: 'control',
        action: 'onboard-privacy',
      }),
    );
    await firstActionStart;

    await expect(elicitor.openControlPanel()).resolves.toMatchObject({
      opened: true,
      ready: true,
    });
    if (!replacementSession) {
      throw new Error('Replacement session was not opened.');
    }
    releaseFirstAction();

    const staleResponse = await delayedResponse;
    expect(staleResponse.status).toBe(401);
    expect(staleResponse.body).not.toContain('name="csrf"');
    const currentSession = replacementSession;
    expect(
      await submit(
        currentSession,
        new URLSearchParams({
          csrf: hiddenValue(currentSession.page.body, 'csrf'),
          intent: 'control',
          action: 'onboard-privacy',
        }),
      ),
    ).toMatchObject({ status: 200 });
    expect(actionCount).toBe(2);
  });

  it('rotates an unconsumed bootstrap token and returns no URL', async () => {
    const bootstrapUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrls.push(url);
      },
    });
    eliciters.push(elicitor);

    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: true,
      ready: true,
      activePrompt: false,
    });
    const second = await elicitor.openControlPanel();
    expect(second).toEqual({
      opened: true,
      ready: true,
      activePrompt: false,
    });
    expect(JSON.stringify(second)).not.toContain('http');
    expect(bootstrapUrls).toHaveLength(2);

    const oldBootstrap = await rawRequest(bootstrapUrls[0] ?? '');
    expect(oldBootstrap.status).toBe(401);
    const currentBootstrap = await rawRequest(bootstrapUrls[1] ?? '', {
      headers: {
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(currentBootstrap.status).toBe(303);
  });

  it('reports success only after the browser reaches Agent Control when arrival acknowledgement is required', async () => {
    let browserSession:
      | Promise<Awaited<ReturnType<typeof establishSession>>>
      | undefined;
    const elicitor = new LocalWebFormElicitor({
      requireBrowserArrival: true,
      browserArrivalTimeoutMs: 250,
      openUrl: (url) => {
        browserSession = establishSession(url);
      },
    });
    eliciters.push(elicitor);

    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: true,
      ready: true,
      activePrompt: false,
    });
    expect(browserSession).toBeDefined();
    await browserSession;
  });

  it('coalesces concurrent opens and waits for the authenticated control page', async () => {
    const openedUrls: string[] = [];
    let resolveOpenedUrl!: (url: string) => void;
    const openedUrl = new Promise<string>((resolve) => {
      resolveOpenedUrl = resolve;
    });
    const elicitor = new LocalWebFormElicitor({
      requireBrowserArrival: true,
      browserArrivalTimeoutMs: 250,
      openUrl: (url) => {
        openedUrls.push(url);
        resolveOpenedUrl(url);
      },
    });
    eliciters.push(elicitor);

    const first = elicitor.openControlPanel();
    const second = elicitor.openControlPanel();
    let settled = 0;
    void first.then(() => {
      settled += 1;
    });
    void second.then(() => {
      settled += 1;
    });

    const bootstrapUrl = await openedUrl;
    expect(openedUrls).toEqual([bootstrapUrl]);
    const bootstrap = await rawRequest(bootstrapUrl, {
      headers: {
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(bootstrap.status).toBe(303);
    const cookie = header(bootstrap, 'set-cookie').split(';')[0] ?? '';
    const origin = new URL(bootstrapUrl).origin;

    expect(
      (
        await rawRequest(`${origin}/snapshot`, {
          headers: { Cookie: cookie },
        })
      ).status,
    ).toBe(200);
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(settled).toBe(0);

    expect(
      (
        await rawRequest(`${origin}/control`, {
          headers: {
            Cookie: cookie,
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
          },
        })
      ).status,
    ).toBe(200);
    await expect(Promise.all([first, second])).resolves.toEqual([
      {
        opened: true,
        ready: true,
        activePrompt: false,
      },
      {
        opened: true,
        ready: true,
        activePrompt: false,
      },
    ]);
    expect(openedUrls).toHaveLength(1);
  });

  it('returns a retryable result when the browser command launches but no page arrives', async () => {
    const openedUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      requireBrowserArrival: true,
      browserArrivalTimeoutMs: 25,
      openUrl: (url) => {
        openedUrls.push(url);
      },
    });
    eliciters.push(elicitor);

    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: false,
      ready: true,
      activePrompt: false,
      reason: 'browser-arrival-timeout',
    });
    expect(openedUrls).toHaveLength(1);
    expect(openedUrls[0]).toMatch(/\/open\/[A-Za-z0-9_-]+$/u);
  });

  it('preserves a pending card when no browser page arrives', async () => {
    const elicitor = new LocalWebFormElicitor({
      requireBrowserArrival: true,
      browserArrivalTimeoutMs: 20,
      openUrl: () => undefined,
    });
    eliciters.push(elicitor);

    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    await new Promise<void>((resolve) => setTimeout(resolve, 30));
    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: false,
      ready: true,
      activePrompt: true,
      reason: 'browser-arrival-timeout',
    });
    await elicitor.close();
    await expect(confirmation).resolves.toEqual({
      outcome: 'cancelled',
    });
  });

  it('opens the authenticated control route for an established session', async () => {
    const openedUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        openedUrls.push(url);
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(openedUrls[0] ?? '');
    const snapshot = await rawRequest(`${session.origin}/snapshot`, {
      headers: { Cookie: session.cookie },
    });
    expect(snapshot.status).toBe(200);

    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: true,
      ready: true,
      activePrompt: false,
    });
    expect(openedUrls).toEqual([
      expect.stringMatching(/\/open\/[A-Za-z0-9_-]+$/u),
      `${session.origin}/control`,
    ]);
  });

  it('renders local Agent Wallet setup while redacting generated keys from snapshots', async () => {
    let bootstrapUrl = '';
    const generatedKey = `0x${'ab'.repeat(32)}`;
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        balance: '1.25 COTI',
        privacyStatus: 'onboarding-required',
        signerStatus: 'setup-required',
        autonomy: { mode: 'manual' },
        walletSetup: {
          required: true,
          environmentFilePath: 'C:\\ChainWhisper\\signer.env',
          generatedBackup: {
            address: '0x1111111111111111111111111111111111111111',
            privateKey: generatedKey,
          },
        },
      }),
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    expect(session.page.body).toContain('Use existing wallet');
    expect(session.page.body).toContain('Create new wallet');
    expect(session.page.body).toMatch(
      /name="environmentFilePath"[^>]*readonly/u,
    );
    expect(session.page.body).toContain('Copy private key');
    expect(session.page.body).toContain(generatedKey);
    expect(session.page.body).not.toContain(
      'CHAINWHISPER_SIGNER_AES_KEY',
    );
    expect(session.page.body).not.toContain('vault passphrase');
    const snapshot = await rawRequest(`${session.origin}/snapshot`, {
      headers: { Cookie: session.cookie },
    });
    expect(snapshot.status).toBe(200);
    expect(snapshot.body).not.toContain(generatedKey);
    expect(snapshot.body).toContain('"privateKey":"[redacted]"');
  });

  it('renders contextual token setup with inline recovery and exact discard controls', async () => {
    let bootstrapUrl = '';
    const operationHash = `0x${'44'.repeat(32)}`;
    const diagnosticSecret = `0x${'de'.repeat(32)}`;
    const submitted: Array<{
      action: string;
      fields: Readonly<Record<string, string>>;
    }> = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        balance: '1 COTI',
        privacyStatus: 'ready',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations: 1,
        recentOperations: [
          {
            label: 'Create recurring private-liquidity order',
            status: 'needs_confirmation',
            transactionUrl:
              'https://mainnet.cotiscan.io/tx/0x1234',
            operationId: 'order-1',
            operationHash,
            recoverable: true,
            discardable: true,
            setupAssets: ['p.WISP'],
          },
        ],
        diagnostics: [
          {
            label: 'Unsafe test diagnostic',
            value: `private key ${diagnosticSecret}`,
          },
        ],
        controlActions: {
          enablePrivateToken: true,
        },
      }),
      onControlAction: (action, fields) => {
        submitted.push({ action, fields });
        return { ok: true, message: 'Local action accepted.' };
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    expect(session.page.body).toContain('Prepare p.WISP');
    expect(session.page.body).toContain('name="token"');
    expect(session.page.body).toContain('p.WISP');
    expect(session.page.body).not.toContain('Choose a token');
    expect(session.page.body).toContain(
      '<strong>Create recurring private-liquidity order</strong>',
    );
    expect(session.page.body).toContain('<small>Needs Confirmation</small>');
    expect(session.page.body).not.toContain('<strong>order-1</strong>');
    expect(session.page.body).toContain(
      'href="https://mainnet.cotiscan.io/tx/0x1234"',
    );
    expect(session.page.body).toContain('View transaction');
    expect(session.page.body).toContain('Reconcile');
    expect(session.page.body).toContain('name="operationId"');
    expect(session.page.body).toContain('Discard local data');
    expect(session.page.body).toContain('name="operationHash"');
    expect(session.page.body).toContain(operationHash);

    const snapshot = await rawRequest(`${session.origin}/snapshot`, {
      headers: { Cookie: session.cookie },
    });
    expect(snapshot.status).toBe(200);
    expect(snapshot.body).not.toContain(diagnosticSecret);
    expect(snapshot.body).toContain('"value":"[redacted]"');
    expect(snapshot.body).toContain(operationHash);

    const missingToken = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(session.page.body, 'csrf'),
        intent: 'control',
        action: 'enable-private-token',
      }),
    );
    expect(missingToken.status).toBe(400);
    expect(submitted).toHaveLength(0);

    const extraSecret = `0x${'ab'.repeat(32)}`;
    const tokenSetup = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(missingToken.body, 'csrf'),
        intent: 'control',
        action: 'enable-private-token',
        token: ' p.WISP ',
        privateKey: extraSecret,
      }),
    );
    expect(tokenSetup.status).toBe(200);
    expect(tokenSetup.body).not.toContain(extraSecret);
    expect(submitted.at(-1)).toEqual({
      action: 'enable-private-token',
      fields: { token: 'p.WISP' },
    });

    const invalidRecovery = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(tokenSetup.body, 'csrf'),
        intent: 'control',
        action: 'recover-operation',
        operationId: '../order-1',
      }),
    );
    expect(invalidRecovery.status).toBe(400);
    expect(submitted).toHaveLength(1);

    const recovery = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(invalidRecovery.body, 'csrf'),
        intent: 'control',
        action: 'recover-operation',
        operationId: 'order-1',
      }),
    );
    expect(recovery.status).toBe(200);
    expect(submitted.at(-1)).toEqual({
      action: 'recover-operation',
      fields: { operationId: 'order-1' },
    });

    const invalidDiscard = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(recovery.body, 'csrf'),
        intent: 'control',
        action: 'discard-operation',
        operationId: 'order-1',
        operationHash: '0x1234',
      }),
    );
    expect(invalidDiscard.status).toBe(400);
    expect(submitted).toHaveLength(2);

    const discardBody = new URLSearchParams({
      csrf: hiddenValue(invalidDiscard.body, 'csrf'),
      intent: 'control',
      action: 'discard-operation',
      operationId: 'order-1',
      operationHash,
    });
    const discard = await submit(session, discardBody);
    expect(discard.status).toBe(200);
    expect(submitted.at(-1)).toEqual({
      action: 'discard-operation',
      fields: { operationId: 'order-1', operationHash },
    });

    const replay = await submit(session, discardBody);
    expect(replay.status).toBe(403);
    expect(submitted).toHaveLength(3);
  });

  it('imports an Agent Wallet through authenticated Agent Control and requires restart', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-control-wallet-'));
    const environmentFilePath = join(root, 'agent.env');
    const privateKey = `0x${'22'.repeat(32)}`;
    const state: WalletControlState = {
      environmentFilePath,
      displayAddress: null,
      generatedBackup: null,
      restartRequired: false,
      lastDiagnostic: null,
    };
    let bootstrapUrl = '';
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: state.displayAddress,
        network: 'COTI Mainnet',
        balance: 'Fund after wallet setup',
        privacyStatus: 'onboarding-required',
        signerStatus: state.restartRequired
          ? 'read-only'
          : 'setup-required',
        autonomy: { mode: 'manual' },
        walletSetup: {
          required: true,
          environmentFilePath: state.environmentFilePath,
          restartRequired: state.restartRequired,
        },
      }),
      onControlAction: (action, fields) => {
        if (action !== 'import-wallet') {
          return { ok: false, message: 'Unsupported test action.' };
        }
        return saveAgentWallet({
          action,
          fields,
          state,
          replacing: false,
          environment: {},
        });
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    const response = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(session.page.body, 'csrf'),
        intent: 'control',
        action: 'import-wallet',
        environmentFilePath,
        privateKey,
      }),
    );

    expect(response.status).toBe(200);
    expect(response.body).toContain('Restart the signer');
    expect(response.body).not.toContain(privateKey);
    expect(state.restartRequired).toBe(true);
    expect(state.lastDiagnostic).toBe(
      'agent-wallet-saved-restart-required',
    );
    const reloaded = await loadSignerConfig({
      CHAINWHISPER_SIGNER_ENV_FILE: environmentFilePath,
      CHAINWHISPER_STATE_DIRECTORY: join(root, 'state'),
    });
    expect(reloaded.walletConfigured).toBe(true);
    expect(reloaded.credentialMaterial().privateKey).toBe(privateKey);
    expect(reloaded.credentialMaterial().aesKey).toBe('');
  });

  it('renders configured wallets as a balance-first dashboard and refreshes balances locally', async () => {
    let bootstrapUrl = '';
    const submitted: Array<{
      action: string;
      fields: Readonly<Record<string, string>>;
    }> = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrl = url;
      },
      getControlSummary: () => ({
        wallet: '0x1111111111111111111111111111111111111111',
        network: 'COTI Mainnet',
        privacyStatus: 'ready',
        signerStatus: 'ready',
        autonomy: { mode: 'manual' },
        pendingOperations: 0,
        balances: {
          refreshedAt: '2026-07-30T12:00:00.000Z',
          stale: false,
          revision: 7,
          rows: [
            {
              symbol: 'COTI',
              kind: 'native',
              displayAmount: '12.345678',
              exactAmount: '12.34567890123456789',
              readiness: 'ready',
              defaultVisible: true,
              stale: false,
            },
            {
              symbol: 'WISP',
              kind: 'erc20',
              displayAmount: '4',
              exactAmount: '4',
              readiness: 'ready',
              defaultVisible: true,
              stale: false,
            },
            {
              symbol: 'p.WISP',
              kind: 'private-erc20',
              displayAmount: '0',
              exactAmount: '0',
              readiness: 'ready',
              defaultVisible: true,
              stale: false,
            },
            {
              symbol: 'p.COTI',
              kind: 'private-erc20',
              readiness: 'setup-required',
              defaultVisible: false,
              stale: false,
            },
          ],
        },
        walletSetup: {
          required: false,
          environmentFilePath: 'C:\\ChainWhisper\\signer.env',
        },
        controlActions: {
          refreshBalances: true,
          enablePrivateToken: true,
        },
      }),
      onControlAction: (action, fields) => {
        submitted.push({ action, fields });
        return { ok: true, message: 'Balances refreshed.' };
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrl);
    expect(session.page.body.indexOf('Wallet balances')).toBeLessThan(
      session.page.body.indexOf('Agent mode'),
    );
    expect(session.page.body).toContain('12.345678');
    expect(session.page.body).toContain('12.34567890123456789 COTI');
    expect(session.page.body).toContain('<strong>p.WISP</strong>');
    expect(session.page.body).toContain('Show all assets');
    expect(session.page.body).toContain('Prepare private token');
    expect(session.page.body).toContain(
      'Ask your agent for bounded or 24-hour autonomy.',
    );
    expect(session.page.body).toContain(
      '<strong>Wallet settings</strong>',
    );
    expect(session.page.body).toContain(
      '<summary>Replace Agent Wallet</summary>',
    );
    expect(session.page.body).not.toContain(
      '<section class="wallet-setup"',
    );

    const response = await submit(
      session,
      new URLSearchParams({
        csrf: hiddenValue(session.page.body, 'csrf'),
        intent: 'control',
        action: 'refresh-balances',
      }),
    );
    expect(response.status).toBe(200);
    expect(submitted).toEqual([
      { action: 'refresh-balances', fields: {} },
    ]);
  });

  it('requires both explicit acknowledgements for full autonomy', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.page.body).toContain(
            'Required acknowledgements',
          );
          const base = {
            csrf: hiddenValue(session.page.body, 'csrf'),
            promptId: hiddenValue(session.page.body, 'promptId'),
            intent: 'prompt',
            action: 'confirm',
          };
          const incomplete = await submit(
            session,
            new URLSearchParams({ ...base, ack0: 'yes' }),
          );
          expect(incomplete.status).toBe(400);
          const accepted = await submit(
            session,
            new URLSearchParams({
              csrf: hiddenValue(incomplete.body, 'csrf'),
              promptId: hiddenValue(incomplete.body, 'promptId'),
              intent: 'prompt',
              action: 'confirm',
              ack0: 'yes',
              ack1: 'yes',
            }),
          );
          expect(accepted.status).toBe(200);
        })();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestConfirmation(
        {
          ...CONFIRMATION,
          action: 'activate_full_autonomy',
          acknowledgements: [
            'I use a dedicated Agent Wallet.',
            'I understand the audited 24-hour boundary.',
          ],
        },
        5_000,
      ),
    ).resolves.toEqual({ outcome: 'accepted' });
    await browserDone;
    expect(elicitor.focusedOperationId).toBeNull();
  });

  it('accepts human token, COTI, price, and local-time policy limits while returning exact atomic values', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.page.body).toContain('Ends (local time)');
          expect(session.page.body).toContain('10');
          expect(session.page.body).toContain(
            'Maximum network cost per action (COTI)',
          );
          expect(session.page.body).toContain('p.COTI per p.WISP');
          expect(session.page.body).not.toContain('p.WISP base units');
          const accepted = await submit(
            session,
            new URLSearchParams({
              csrf: hiddenValue(session.page.body, 'csrf'),
              promptId: hiddenValue(session.page.body, 'promptId'),
              intent: 'prompt',
              action: 'confirm',
              'autonomy.expiresAt': '2026-08-01T12:00',
              'autonomy.agentVisiblePrivateAmounts': 'true',
              'autonomy.perAction.0': '5',
              'autonomy.cumulative.0': '9',
              'autonomy.maximumNativeValuePerAction': '0',
              'autonomy.maximumNativeValueCumulative': '0',
              'autonomy.maximumNetworkFeePerAction': '0.01',
              'autonomy.maximumNetworkFeeCumulative': '0.02',
              'autonomy.maximumActions': '4',
              'autonomy.maximumMessages': '2',
              'autonomy.price.0.minimum': '0.95',
              'autonomy.price.0.maximum': '1.05',
            }),
          );
          expect(accepted.status).toBe(200);
        })();
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    const result = await elicitor.requestConfirmation(
      {
        ...CONFIRMATION,
        action: 'activate_bounded_autonomy',
        autonomyEditor: {
          startsAt: '2026-07-30T12:00:00.000Z',
          expiresAt: '2026-08-01T12:00:00.000Z',
          duration: '2 days',
          agentVisiblePrivateAmounts: true,
          perActionSpend: [
            {
              asset: 'p.wisp',
              amount: '10000000000000000000',
              symbol: 'p.WISP',
              decimals: 18,
              displayAmount: '10',
            },
          ],
          cumulativeSpend: [
            {
              asset: 'p.wisp',
              amount: '20000000000000000000',
              symbol: 'p.WISP',
              decimals: 18,
              displayAmount: '20',
            },
          ],
          maximumNativeValuePerAction: '0',
          maximumNativeValueCumulative: '0',
          maximumNetworkFeePerAction: '10000000000000000',
          maximumNetworkFeeCumulative: '20000000000000000',
          maximumActions: 5,
          maximumMessages: 3,
          priceBands: [
            {
              sellAsset: 'p.wisp',
              buyAsset: 'p.coti',
              minimumNumerator: '9',
              minimumDenominator: '10',
              maximumNumerator: '11',
              maximumDenominator: '10',
              sellSymbol: 'p.WISP',
              buySymbol: 'p.COTI',
              sellDecimals: 18,
              buyDecimals: 18,
              minimumDisplay: '0.9',
              maximumDisplay: '1.1',
            },
          ],
        },
      },
      5_000,
    );

    expect(result).toMatchObject({
      outcome: 'accepted',
      values: {
        'autonomy.agentVisiblePrivateAmounts': 'true',
        'autonomy.perAction.0': '5000000000000000000',
        'autonomy.cumulative.0': '9000000000000000000',
        'autonomy.maximumNativeValuePerAction': '0',
        'autonomy.maximumNativeValueCumulative': '0',
        'autonomy.maximumNetworkFeePerAction': '10000000000000000',
        'autonomy.maximumNetworkFeeCumulative': '20000000000000000',
        'autonomy.maximumActions': '4',
        'autonomy.maximumMessages': '2',
        'autonomy.price.0.minNumerator': '19',
        'autonomy.price.0.minDenominator': '20',
        'autonomy.price.0.maxNumerator': '21',
        'autonomy.price.0.maxDenominator': '20',
      },
    });
    await browserDone;
  });

  it('enforces exact Host, Fetch Metadata, body, and rate limits', async () => {
    const bootstrapUrls: string[] = [];
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        bootstrapUrls.push(url);
      },
    });
    eliciters.push(elicitor);

    await elicitor.openControlPanel();
    const firstBootstrap = bootstrapUrls.at(-1) ?? '';
    const invalidHost = await rawRequest(firstBootstrap, {
      headers: {
        Host: `localhost:${new URL(firstBootstrap).port}`,
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(invalidHost.status).toBe(421);
    const unsafeNavigation = await rawRequest(firstBootstrap, {
      headers: {
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Dest': 'document',
      },
    });
    expect(unsafeNavigation.status).toBe(403);

    await elicitor.openControlPanel();
    const session = await establishSession(bootstrapUrls.at(-1) ?? '');
    const oversizedBody = `csrf=${'a'.repeat(16_384)}`;
    const oversized = await submit(session, oversizedBody);
    expect(oversized.status).toBe(413);
    const unsafeSubmission = await submit(session, 'csrf=invalid', {
      'Sec-Fetch-Site': 'cross-site',
    });
    expect(unsafeSubmission.status).toBe(403);

    for (let attempt = 0; attempt < 28; attempt += 1) {
      expect((await submit(session, 'csrf=invalid')).status).toBe(403);
    }
    const limited = await submit(session, 'csrf=invalid');
    expect(limited.status).toBe(429);
    expect(header(limited, 'retry-after')).toBe('60');
  });

  it('keeps pending confirmation available after browser failure and retries successfully', async () => {
    let attempts = 0;
    let retrySession:
      | Awaited<ReturnType<typeof establishSession>>
      | undefined;
    let firstAttemptFinished!: () => void;
    const firstAttempt = new Promise<void>((resolve) => {
      firstAttemptFinished = resolve;
    });
    const elicitor = new LocalWebFormElicitor({
      openUrl: async (url) => {
        attempts += 1;
        if (attempts === 1) {
          firstAttemptFinished();
          throw new Error('No desktop browser');
        }
        retrySession = await establishSession(url);
      },
    });
    eliciters.push(elicitor);

    const confirmation = elicitor.requestConfirmation(
      CONFIRMATION,
      5_000,
    );
    await firstAttempt;
    expect(elicitor.isSupported()).toBe(true);

    await expect(elicitor.openControlPanel()).resolves.toEqual({
      opened: true,
      ready: true,
      activePrompt: true,
    });
    expect(retrySession).toBeDefined();
    if (!retrySession) throw new Error('Retry session was not opened.');
    const session = retrySession;
    const csrf = hiddenValue(session.page.body, 'csrf');
    await expect(
      submit(
        session,
        new URLSearchParams({
          csrf,
          promptId: hiddenValue(session.page.body, 'promptId'),
          intent: 'prompt',
          action: 'confirm',
        }).toString(),
      ),
    ).resolves.toMatchObject({ status: 200 });
    await expect(confirmation).resolves.toEqual({
      outcome: 'accepted',
    });
    expect(attempts).toBe(2);
  });
});

describe('Agent Control state refresh key', () => {
  it('renders manual, bounded, full, paused, expired, and revoked autonomy states', () => {
    const cases = [
      {
        autonomy: { mode: 'manual' as const },
        expected: ['Manual approval', 'Ask your agent for bounded'],
      },
      {
        autonomy: { mode: 'bounded' as const, state: 'active' as const },
        expected: ['Bounded autonomy', 'Active'],
      },
      {
        autonomy: { mode: 'full' as const, state: 'active' as const },
        expected: ['Full autonomy', 'Active'],
      },
      {
        autonomy: { mode: 'bounded' as const, state: 'paused' as const },
        expected: ['Bounded autonomy', 'Paused'],
      },
      {
        autonomy: { mode: 'bounded' as const, state: 'expired' as const },
        expected: ['Bounded autonomy', 'Expired'],
      },
      {
        autonomy: { mode: 'full' as const, state: 'revoked' as const },
        expected: ['Full autonomy', 'Revoked'],
      },
    ];
    for (const { autonomy, expected } of cases) {
      const page = renderAgentControlPage(
        {
          csrfToken: 'csrf',
          pending: null,
          summary: { autonomy },
        },
        'nonce',
      );
      for (const value of expected) expect(page).toContain(value);
    }
  });

  it('keeps blocked wallet replacement collapsed and disabled', () => {
    const reason =
      'Wallet replacement is blocked while an operation is pending.';
    const page = renderAgentControlPage(
      {
        csrfToken: 'csrf',
        pending: null,
        summary: {
          wallet: '0x1111111111111111111111111111111111111111',
          autonomy: { mode: 'manual' },
          walletSetup: {
            required: false,
            environmentFilePath: 'C:\\ChainWhisper\\signer.env',
            replacementBlockedReason: reason,
          },
        },
      },
      'nonce',
    );
    expect(page).toContain('<strong>Wallet settings</strong>');
    expect(page).toContain('<summary>Replace Agent Wallet</summary>');
    expect(page).toContain(reason);
    expect(page).toMatch(
      /name="action" value="import-wallet" disabled/u,
    );
    expect(page).toMatch(
      /name="action" value="generate-wallet" disabled/u,
    );
  });

  it('uses the balance revision without serializing decrypted amounts', () => {
    const summary = {
      balances: {
        refreshedAt: '2026-07-30T12:00:00.000Z',
        stale: false,
        revision: 1,
        rows: [
          {
            symbol: 'p.WISP',
            kind: 'private-erc20' as const,
            displayAmount: '8.123456',
            exactAmount: '8.123456789',
            readiness: 'ready' as const,
            defaultVisible: true,
            stale: false,
          },
        ],
      },
    };
    const first = agentControlStateKey({
      pending: null,
      summary,
    });
    const next = agentControlStateKey({
      pending: null,
      summary: {
        ...summary,
        balances: { ...summary.balances, revision: 2 },
      },
    });
    expect(first).not.toContain('8.123456789');
    expect(first).not.toBe(next);
  });

  it('renders the complete private authority in the policy editor and active summary', () => {
    const activationPage = renderAgentControlPage(
      {
        csrfToken: 'csrf',
        pending: {
          id: 'activate-policy',
          kind: 'confirmation',
          request: {
            ...CONFIRMATION,
            action: 'activate_bounded_autonomy',
            summary: PRIVATE_AMOUNT_AUTHORITY_ENABLED,
            expectedResult: PRIVATE_AMOUNT_AUTHORITY_ENABLED,
            details: [
              {
                label:
                  'Private amount choice and policy-scoped state viewing',
                value: PRIVATE_AMOUNT_AUTHORITY_ENABLED,
              },
            ],
            autonomyEditor: {
              expiresAt: '2026-08-05T12:00:00.000Z',
              agentVisiblePrivateAmounts: true,
              perActionSpend: [],
              cumulativeSpend: [],
              priceBands: [],
            },
          },
        },
        summary: { autonomy: { mode: 'manual' } },
      },
      'nonce',
    );
    expect(activationPage).toContain(
      'Private amount choice and policy-scoped state viewing',
    );
    expect(activationPage).toContain(PRIVATE_AMOUNT_AUTHORITY_ENABLED);
    expect(activationPage).toContain(
      'Allow this agent to both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.',
    );

    const activeSummary = renderAgentControlPage(
      {
        csrfToken: 'csrf',
        pending: null,
        summary: {
          autonomy: {
            mode: 'bounded',
            state: 'active',
            agentVisiblePrivateAmounts: true,
          },
        },
      },
      'nonce',
    );
    expect(activeSummary).toContain(
      'This policy lets the agent both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.',
    );
    expect(
      agentControlStateKey({
        pending: null,
        summary: {
          autonomy: {
            mode: 'bounded',
            state: 'active',
            agentVisiblePrivateAmounts: true,
          },
        },
      }),
    ).not.toBe(
      agentControlStateKey({
        pending: null,
        summary: {
          autonomy: {
            mode: 'bounded',
            state: 'active',
            agentVisiblePrivateAmounts: false,
          },
        },
      }),
    );
  });

  it('keeps the same private-input region across unrelated activity updates', () => {
    const pending = {
      id: 'private-operation',
      kind: 'private-values' as const,
      request: {
        operationId: 'private-operation',
        operationHash: `0x${'44'.repeat(32)}` as `0x${string}`,
        wallet: CONFIRMATION.wallet,
        fields: [
          {
            id: 'sellBaseLiquidity',
            title: 'Private p.WISP inventory',
            description: 'Amount available to recurring sells.',
            kind: 'decimal-amount' as const,
          },
        ],
      },
    };
    const firstModel = {
      csrfToken: 'csrf-1',
      pending,
      summary: {
        wallet: CONFIRMATION.wallet,
        pendingOperations: 0,
        autonomy: { mode: 'manual' as const },
      },
    };
    const nextModel = {
      ...firstModel,
      csrfToken: 'csrf-2',
      summary: {
        ...firstModel.summary,
        pendingOperations: 1,
      },
    };
    const firstPage = renderAgentControlPage(firstModel, 'nonce-1');
    const nextPage = renderAgentControlPage(nextModel, 'nonce-2');
    const reviewKey = (page: string): string | undefined =>
      page.match(
        /data-review-region data-region-key="([^"]+)"/u,
      )?.[1];

    expect(agentControlStateKey(firstModel)).not.toBe(
      agentControlStateKey(nextModel),
    );
    expect(reviewKey(firstPage)).toBe(
      'prompt:private-values:private-operation',
    );
    expect(reviewKey(nextPage)).toBe(reviewKey(firstPage));
    expect(nextPage).toContain('value="csrf-2"');
    expect(nextPage).toContain(
      "region.querySelectorAll('input:not([type=\"hidden\"]), textarea, select')",
    );
    expect(nextPage).toContain(
      "state.key !== (region.dataset.regionKey || '')",
    );
    expect(nextPage).toContain('restoreRegionState(current, state)');
  });

  it('changes when a new operation has the same status', () => {
    const base = {
      pending: null,
      summary: {
        recentOperations: [
          { label: 'Order 1', status: 'confirming' },
        ],
      },
    };
    const next = {
      ...base,
      summary: {
        recentOperations: [
          { label: 'Order 2', status: 'confirming' },
        ],
      },
    };

    expect(agentControlStateKey(base)).not.toBe(
      agentControlStateKey(next),
    );
  });
});
