import { request as httpRequest } from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  LocalWebFormElicitor,
  loadSignerConfig,
  saveAgentWallet,
  type ConfirmationRequest,
  type WalletControlState,
} from '../src/signer/index.js';

const CONFIRMATION: ConfirmationRequest = {
  operationId: 'diagnostic',
  operationHash: `0x${'00'.repeat(32)}`,
  stepId: 'diagnostic',
  stepIndex: 0,
  stepCount: 1,
  wallet: '0x1111111111111111111111111111111111111111',
  contract: '0x0000000000000000000000000000000000000000',
  action: 'create_recurring',
  orderType: null,
  orderTypeLabel: 'Recurring · private liquidity · public price',
  assets: ['p.WISP', 'p.COTI'],
  amounts: ['12.5 p.WISP', '25 p.COTI'],
  details: [
    { label: 'You send', value: '12.5 p.WISP' },
    { label: 'You receive', value: '25 p.COTI' },
    { label: 'Maximum network fee', value: '0.08 COTI' },
  ],
  counterparty: null,
  spender: '0x2222222222222222222222222222222222222222',
  fee: '0.1 COTI',
  nativeValue: '0',
  gasCap: '450000',
  expectedResult: 'A recurring order is created.',
  summary: 'Create a recurring private-liquidity order.',
};

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
  return { origin, controlUrl, cookie, page };
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

const eliciters: LocalWebFormElicitor[] = [];

afterEach(async () => {
  await Promise.all(eliciters.splice(0).map((elicitor) => elicitor.close()));
});

describe('local Agent Control elicitor', () => {
  it('uses a consumed bootstrap URL and renders a structured action card', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.controlUrl).not.toContain('/open/');
          expect(session.page.status).toBe(200);
          expect(header(session.page, 'cache-control')).toContain('no-store');
          expect(header(session.page, 'x-frame-options')).toBe('DENY');
          expect(header(session.page, 'access-control-allow-origin')).toBe('');
          const csp = header(session.page, 'content-security-policy');
          expect(csp).toContain("frame-ancestors 'none'");
          expect(csp).toContain("style-src 'nonce-");
          expect(csp).not.toContain("'unsafe-inline'");
          expect(session.page.body).toContain('Create recurring order');
          expect(session.page.body).toContain(
            'Recurring · private liquidity · public price',
          );
          expect(session.page.body).toContain('12.5 p.WISP');
          expect(session.page.body).toContain(
            'Confirm complete recurring order',
          );
          expect(session.page.body).not.toContain('>Submit<');
          expect(session.page.body).not.toContain('type="checkbox"');
          expect(session.page.body).not.toMatch(
            /<(?:script|img|link)[^>]+https?:/iu,
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
        return browserDone;
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestConfirmation(CONFIRMATION, 5_000),
    ).resolves.toEqual({ outcome: 'accepted' });
    await browserDone;
  });

  it('collects private values only through the authenticated local form', async () => {
    let browserDone: Promise<void> = Promise.resolve();
    const elicitor = new LocalWebFormElicitor({
      openUrl: (url) => {
        browserDone = (async () => {
          const session = await establishSession(url);
          expect(session.page.body).toContain('Enter private order values');
          expect(session.page.body).toContain(
            'never sent through the agent conversation',
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

  it('rotates the only active browser session and returns no URL', async () => {
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

  it('fails closed when the OS browser cannot be opened', async () => {
    const elicitor = new LocalWebFormElicitor({
      openUrl: () => {
        throw new Error('No desktop browser');
      },
    });
    eliciters.push(elicitor);

    await expect(
      elicitor.requestConfirmation(CONFIRMATION, 5_000),
    ).resolves.toEqual({ outcome: 'cancelled' });
    expect(elicitor.isSupported()).toBe(false);
  });
});
