import {
  createHash,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';

import {
  renderAgentControlPage,
  type AgentControlPageModel,
  type AgentControlPendingPrompt,
  type AgentControlSummary,
} from './localControlPage.js';
import type {
  ConfirmationRequest,
  ConfirmationResult,
  FormElicitor,
  PrivateValueElicitor,
  PrivateValueRequest,
  PrivateValueResult,
} from './types.js';

type OpenUrl = (url: string) => Promise<void> | void;

export type OpenControlPanelResult = {
  opened: boolean;
  ready: boolean;
  activePrompt: boolean;
  reason?: 'browser-open-failed' | 'server-unavailable' | 'closed';
};

export type AgentControlAction =
  | 'pause-autonomy'
  | 'resume-autonomy'
  | 'revoke-autonomy'
  | 'import-wallet'
  | 'generate-wallet'
  | 'clear-wallet-backup'
  | 'onboard-privacy';

export type AgentControlActionResult = {
  ok: boolean;
  message: string;
};

export type LocalWebFormElicitorOptions = {
  openUrl?: OpenUrl;
  getControlSummary?: () =>
    | AgentControlSummary
    | Promise<AgentControlSummary>;
  onControlAction?: (
    action: AgentControlAction,
    fields: Readonly<Record<string, string>>,
  ) => AgentControlActionResult | Promise<AgentControlActionResult>;
};

type PendingConfirmation = {
  id: string;
  kind: 'confirmation';
  request: ConfirmationRequest;
  resolve: (result: ConfirmationResult) => void;
  timer: ReturnType<typeof setTimeout>;
};

type PendingPrivateValues = {
  id: string;
  kind: 'private-values';
  request: PrivateValueRequest;
  resolve: (result: PrivateValueResult) => void;
  timer: ReturnType<typeof setTimeout>;
};

type PendingPrompt = PendingConfirmation | PendingPrivateValues;

type RateWindow = {
  startedAt: number;
  requests: number;
  submissions: number;
};

class BodyTooLargeError extends Error {}

const COOKIE_NAME = 'cw_agent_control';
const MAX_BODY_BYTES = 16_384;
const RATE_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const MAX_SUBMISSIONS_PER_WINDOW = 30;
const BOOTSTRAP_LIFETIME_MS = 60_000;
const SESSION_LIFETIME_SECONDS = 8 * 60 * 60;

const digest = (value: string): Buffer =>
  createHash('sha256').update(value).digest();

const matchesDigest = (
  value: string | undefined,
  expected: Buffer | null,
): boolean => {
  if (!value || !expected) return false;
  const actual = digest(value);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
};

const randomToken = (bytes = 32): string =>
  randomBytes(bytes).toString('base64url');

const openDefaultBrowser: OpenUrl = (url) =>
  new Promise<void>((resolve, reject) => {
    const command =
      process.platform === 'win32'
        ? 'rundll32.exe'
        : process.platform === 'darwin'
          ? 'open'
          : 'xdg-open';
    const args =
      process.platform === 'win32'
        ? ['url.dll,FileProtocolHandler', url]
        : [url];
    const child = spawn(command, args, {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    const handleError = (error: Error): void => reject(error);
    child.once('error', handleError);
    child.once('spawn', () => {
      child.off('error', handleError);
      child.unref();
      resolve();
    });
  });

const securityHeaders = (
  cspNonce?: string,
): Record<string, string> => ({
  'Cache-Control': 'no-store, max-age=0',
  'Content-Security-Policy': cspNonce
    ? `default-src 'none'; style-src 'nonce-${cspNonce}'; script-src 'nonce-${cspNonce}'; img-src 'none'; font-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'`
    : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), clipboard-write=(self)',
  Pragma: 'no-cache',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
});

const readBody = async (request: IncomingMessage): Promise<string> => {
  const declaredLength = Number(request.headers['content-length'] ?? 0);
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_BODY_BYTES
  ) {
    throw new BodyTooLargeError('Form body is too large.');
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > MAX_BODY_BYTES) {
      throw new BodyTooLargeError('Form body is too large.');
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
};

const parseCookies = (request: IncomingMessage): Map<string, string> => {
  const cookies = new Map<string, string>();
  for (const part of (request.headers.cookie ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name && value) cookies.set(name, value);
  }
  return cookies;
};

const singleFormValue = (
  form: URLSearchParams,
  name: string,
): string | null => {
  const values = form.getAll(name);
  return values.length === 1 ? values[0] ?? null : null;
};

const isLoopbackAddress = (value: string | undefined): boolean =>
  value === '127.0.0.1' ||
  value === '::1' ||
  value === '::ffff:127.0.0.1';

const isSafeNavigationMetadata = (request: IncomingMessage): boolean => {
  const site = request.headers['sec-fetch-site'];
  const mode = request.headers['sec-fetch-mode'];
  const destination = request.headers['sec-fetch-dest'];
  if (site && site !== 'none' && site !== 'same-origin') return false;
  if (mode && mode !== 'navigate') return false;
  if (destination && destination !== 'document') return false;
  return true;
};

const isSafeSubmissionMetadata = (request: IncomingMessage): boolean => {
  const site = request.headers['sec-fetch-site'];
  const mode = request.headers['sec-fetch-mode'];
  const destination = request.headers['sec-fetch-dest'];
  if (site && site !== 'same-origin') return false;
  if (mode && mode !== 'navigate') return false;
  if (destination && destination !== 'document') return false;
  return true;
};

const defaultSummary = (
  pending: PendingPrompt | null,
): AgentControlSummary => ({
  wallet: pending?.request.wallet ?? null,
  network: 'COTI',
  balance: 'Connect signer runtime',
  privacyStatus: 'unknown',
  signerStatus: pending ? 'ready' : 'setup-required',
  autonomy: { mode: 'manual' },
  pendingOperations: pending ? 1 : 0,
  recentOperations: [],
  diagnostics: [],
});

/**
 * A persistent, signer-owned loopback control surface.
 *
 * The bootstrap URL is intentionally passed only to the OS browser opener. It is
 * consumed on first navigation and redirected to a clean, cookie-authenticated
 * URL. MCP tools should expose only {@link openControlPanel}'s safe result.
 */
export class LocalWebFormElicitor
  implements FormElicitor, PrivateValueElicitor
{
  readonly #openUrl: OpenUrl;
  readonly #getControlSummary?: LocalWebFormElicitorOptions['getControlSummary'];
  readonly #onControlAction?: LocalWebFormElicitorOptions['onControlAction'];
  readonly #rateWindows = new Map<string, RateWindow>();

  #server: Server | null = null;
  #serverStart: Promise<boolean> | null = null;
  #port: number | null = null;
  #expectedHost: string | null = null;
  #bootstrapToken: string | null = null;
  #bootstrapExpiresAt = 0;
  #sessionDigest: Buffer | null = null;
  #csrfDigest: Buffer | null = null;
  #pending: PendingPrompt | null = null;
  #closed = false;
  #browserAvailable: boolean | null = null;

  constructor(options: LocalWebFormElicitorOptions = {}) {
    this.#openUrl = options.openUrl ?? openDefaultBrowser;
    this.#getControlSummary = options.getControlSummary;
    this.#onControlAction = options.onControlAction;
  }

  isSupported(): boolean {
    return !this.#closed && this.#browserAvailable !== false;
  }

  get controlPageReady(): boolean {
    return !this.#closed && this.#server !== null && this.#port !== null;
  }

  async startControlServer(): Promise<boolean> {
    if (this.#closed) return false;
    return this.#ensureServer();
  }

  async openControlPanel(): Promise<OpenControlPanelResult> {
    if (this.#closed) {
      return {
        opened: false,
        ready: false,
        activePrompt: Boolean(this.#pending),
        reason: 'closed',
      };
    }
    if (!(await this.#ensureServer()) || this.#port === null) {
      this.#browserAvailable = false;
      return {
        opened: false,
        ready: false,
        activePrompt: Boolean(this.#pending),
        reason: 'server-unavailable',
      };
    }

    const bootstrapToken = randomToken();
    this.#bootstrapToken = bootstrapToken;
    this.#bootstrapExpiresAt = Date.now() + BOOTSTRAP_LIFETIME_MS;
    this.#sessionDigest = null;
    this.#csrfDigest = null;
    try {
      await this.#openUrl(
        `http://127.0.0.1:${this.#port}/open/${bootstrapToken}`,
      );
      this.#browserAvailable = true;
      return {
        opened: true,
        ready: true,
        activePrompt: Boolean(this.#pending),
      };
    } catch {
      this.#browserAvailable = false;
      this.#bootstrapToken = null;
      return {
        opened: false,
        ready: true,
        activePrompt: Boolean(this.#pending),
        reason: 'browser-open-failed',
      };
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#bootstrapToken = null;
    this.#sessionDigest = null;
    this.#csrfDigest = null;
    this.#settlePending('cancelled');
    const server = this.#server;
    this.#server = null;
    this.#port = null;
    this.#expectedHost = null;
    if (!server) return;
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }

  requestConfirmation(
    request: ConfirmationRequest,
    timeoutMs: number,
  ): Promise<ConfirmationResult> {
    if (this.#pending) {
      return Promise.resolve({
        outcome: 'cancelled',
      });
    }
    return new Promise<ConfirmationResult>((resolve) => {
      const id = randomToken(18);
      const timer = setTimeout(() => {
        if (this.#pending?.id !== id) return;
        this.#pending = null;
        resolve({ outcome: 'timeout' });
      }, timeoutMs);
      this.#pending = {
        id,
        kind: 'confirmation',
        request,
        resolve,
        timer,
      };
      void this.openControlPanel().then((result) => {
        if (!result.opened && this.#pending?.id === id) {
          this.#settlePending('cancelled');
        }
      });
    });
  }

  requestPrivateValues(
    request: PrivateValueRequest,
    timeoutMs: number,
  ): Promise<PrivateValueResult> {
    if (this.#pending) {
      return Promise.resolve({
        outcome: 'cancelled',
      });
    }
    return new Promise<PrivateValueResult>((resolve) => {
      const id = randomToken(18);
      const timer = setTimeout(() => {
        if (this.#pending?.id !== id) return;
        this.#pending = null;
        resolve({ outcome: 'timeout' });
      }, timeoutMs);
      this.#pending = {
        id,
        kind: 'private-values',
        request,
        resolve,
        timer,
      };
      void this.openControlPanel().then((result) => {
        if (!result.opened && this.#pending?.id === id) {
          this.#settlePending('cancelled');
        }
      });
    });
  }

  async #ensureServer(): Promise<boolean> {
    if (this.#server && this.#port !== null) return true;
    if (this.#serverStart) return this.#serverStart;
    this.#serverStart = new Promise<boolean>((resolve) => {
      let settled = false;
      const finish = (result: boolean): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };
      const server = createServer((request, response) => {
        void this.#handleRequest(request, response).catch(() => {
          if (response.headersSent) {
            response.end();
            return;
          }
          this.#sendEmpty(response, 500);
        });
      });
      server.once('error', () => {
        if (this.#server === server) {
          this.#server = null;
          this.#port = null;
          this.#expectedHost = null;
        }
        finish(false);
      });
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        if (!address || typeof address === 'string') {
          server.close();
          finish(false);
          return;
        }
        this.#server = server;
        this.#port = address.port;
        this.#expectedHost = `127.0.0.1:${address.port}`;
        server.unref();
        finish(true);
      });
    }).finally(() => {
      this.#serverStart = null;
    });
    return this.#serverStart;
  }

  async #handleRequest(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    if (
      !isLoopbackAddress(request.socket.remoteAddress) ||
      !this.#expectedHost ||
      request.headers.host !== this.#expectedHost
    ) {
      this.#sendEmpty(response, 421);
      return;
    }
    if (!this.#allowRequest(request)) {
      response.writeHead(429, {
        ...securityHeaders(),
        'Retry-After': '60',
      });
      response.end();
      return;
    }
    const requestUrl = request.url ?? '';
    if (!requestUrl.startsWith('/') || requestUrl.startsWith('//')) {
      this.#sendEmpty(response, 400);
      return;
    }

    if (
      request.method === 'GET' &&
      this.#bootstrapToken &&
      requestUrl === `/open/${this.#bootstrapToken}`
    ) {
      if (
        Date.now() > this.#bootstrapExpiresAt ||
        !isSafeNavigationMetadata(request)
      ) {
        this.#bootstrapToken = null;
        this.#sendEmpty(response, 403);
        return;
      }
      this.#bootstrapToken = null;
      const sessionToken = randomToken();
      this.#sessionDigest = digest(sessionToken);
      this.#csrfDigest = null;
      response.writeHead(303, {
        ...securityHeaders(),
        Location: '/control',
        'Set-Cookie': `${COOKIE_NAME}=${sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_LIFETIME_SECONDS}`,
      });
      response.end();
      return;
    }

    if (!this.#hasValidSession(request)) {
      this.#sendEmpty(response, 401);
      return;
    }
    if (request.method === 'GET' && requestUrl === '/control') {
      await this.#sendPage(response, 200);
      return;
    }
    if (request.method === 'GET' && requestUrl === '/snapshot') {
      await this.#sendSnapshot(response);
      return;
    }
    if (request.method === 'POST' && requestUrl === '/action') {
      await this.#handleAction(request, response);
      return;
    }
    if (
      request.method !== 'GET' &&
      request.method !== 'POST'
    ) {
      response.writeHead(405, {
        ...securityHeaders(),
        Allow: 'GET, POST',
      });
      response.end();
      return;
    }
    this.#sendEmpty(response, 404);
  }

  #allowRequest(request: IncomingMessage): boolean {
    const key = request.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    let window = this.#rateWindows.get(key);
    if (!window || now - window.startedAt >= RATE_WINDOW_MS) {
      window = { startedAt: now, requests: 0, submissions: 0 };
      this.#rateWindows.set(key, window);
    }
    window.requests += 1;
    if (request.method === 'POST') window.submissions += 1;
    return (
      window.requests <= MAX_REQUESTS_PER_WINDOW &&
      window.submissions <= MAX_SUBMISSIONS_PER_WINDOW
    );
  }

  #hasValidSession(request: IncomingMessage): boolean {
    const session = parseCookies(request).get(COOKIE_NAME);
    return matchesDigest(session, this.#sessionDigest);
  }

  async #summary(): Promise<AgentControlSummary> {
    if (!this.#getControlSummary) return defaultSummary(this.#pending);
    try {
      return await this.#getControlSummary();
    } catch {
      return {
        ...defaultSummary(this.#pending),
        signerStatus: 'unavailable',
        diagnostics: [
          {
            label: 'Control summary',
            value: 'Signer status is temporarily unavailable.',
          },
        ],
      };
    }
  }

  #publicPending(): AgentControlPendingPrompt | null {
    if (!this.#pending) return null;
    return {
      id: this.#pending.id,
      kind: this.#pending.kind,
      request: this.#pending.request,
    } as AgentControlPendingPrompt;
  }

  async #sendPage(
    response: ServerResponse,
    status: number,
    messages: { flash?: string; error?: string } = {},
  ): Promise<void> {
    const csrfToken = randomToken();
    this.#csrfDigest = digest(csrfToken);
    const nonce = randomToken(18);
    const model: AgentControlPageModel = {
      csrfToken,
      pending: this.#publicPending(),
      summary: await this.#summary(),
      ...messages,
    };
    response.writeHead(status, {
      ...securityHeaders(nonce),
      'Content-Type': 'text/html; charset=utf-8',
    });
    response.end(renderAgentControlPage(model, nonce));
  }

  async #sendSnapshot(response: ServerResponse): Promise<void> {
    const pending = this.#publicPending();
    const safePending = pending
      ? pending.kind === 'confirmation'
        ? {
            id: pending.id,
            kind: pending.kind,
            action: pending.request.action,
            orderTypeLabel: pending.request.orderTypeLabel ?? null,
            stepIndex: pending.request.stepIndex,
            stepCount: pending.request.stepCount,
          }
        : {
            id: pending.id,
            kind: pending.kind,
            fields: pending.request.fields.map(({ id, title, kind }) => ({
              id,
              title,
              kind,
            })),
          }
      : null;
    const summary = await this.#summary();
    const safeSummary = summary.walletSetup?.generatedBackup
      ? {
          ...summary,
          walletSetup: {
            ...summary.walletSetup,
            generatedBackup: {
              address: summary.walletSetup.generatedBackup.address,
              privateKey: '[redacted]',
            },
          },
        }
      : summary;
    response.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': 'application/json; charset=utf-8',
    });
    response.end(
      JSON.stringify({
        pending: safePending,
        summary: safeSummary,
      }),
    );
  }

  async #handleAction(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    const contentType = request.headers['content-type'] ?? '';
    const expectedOrigin = `http://${this.#expectedHost ?? ''}`;
    if (
      !contentType
        .toLowerCase()
        .startsWith('application/x-www-form-urlencoded') ||
      request.headers.origin !== expectedOrigin ||
      !isSafeSubmissionMetadata(request)
    ) {
      this.#sendEmpty(response, 403);
      return;
    }
    let body: string;
    try {
      body = await readBody(request);
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        this.#sendEmpty(response, 413);
        return;
      }
      this.#sendEmpty(response, 400);
      return;
    }
    const form = new URLSearchParams(body);
    const csrf = singleFormValue(form, 'csrf');
    if (!matchesDigest(csrf ?? undefined, this.#csrfDigest)) {
      this.#sendEmpty(response, 403);
      return;
    }
    // A form token is valid for one submission, including a rejected one.
    this.#csrfDigest = null;
    const intent = singleFormValue(form, 'intent');
    if (intent === 'control') {
      await this.#handleControlAction(form, response);
      return;
    }
    if (intent !== 'prompt') {
      await this.#sendPage(response, 400, {
        error: 'The local request could not be verified. Refresh and try again.',
      });
      return;
    }
    await this.#handlePromptAction(form, response);
  }

  async #handleControlAction(
    form: URLSearchParams,
    response: ServerResponse,
  ): Promise<void> {
    const action = singleFormValue(form, 'action');
    if (
      action !== 'pause-autonomy' &&
      action !== 'resume-autonomy' &&
      action !== 'revoke-autonomy' &&
      action !== 'import-wallet' &&
      action !== 'generate-wallet' &&
      action !== 'clear-wallet-backup' &&
      action !== 'onboard-privacy'
    ) {
      await this.#sendPage(response, 400, {
        error: 'Unknown Agent Control action.',
      });
      return;
    }
    if (!this.#onControlAction) {
      await this.#sendPage(response, 409, {
        error: 'Autonomy controls are not available in this signer session.',
      });
      return;
    }
    try {
      const fields = Object.fromEntries(
        [...form.entries()]
          .filter(([key]) => !['csrf', 'intent', 'action'].includes(key))
          .map(([key, value]) => [key, value]),
      );
      const result = await this.#onControlAction(action, fields);
      await this.#sendPage(response, result.ok ? 200 : 409, {
        ...(result.ok
          ? { flash: result.message }
          : { error: result.message }),
      });
    } catch {
      await this.#sendPage(response, 500, {
        error: 'The signer could not update autonomy safely.',
      });
    }
  }

  async #handlePromptAction(
    form: URLSearchParams,
    response: ServerResponse,
  ): Promise<void> {
    const prompt = this.#pending;
    const promptId = singleFormValue(form, 'promptId');
    const action = singleFormValue(form, 'action');
    if (!prompt || prompt.id !== promptId) {
      await this.#sendPage(response, 409, {
        error:
          'This request is no longer active. No transaction was authorized.',
      });
      return;
    }
    if (action === 'decline') {
      this.#settlePending('declined');
      await this.#sendPage(response, 200, {
        flash: 'Request declined. Nothing was authorized.',
      });
      return;
    }
    if (action !== 'confirm') {
      await this.#sendPage(response, 400, {
        error: 'Choose confirm or decline.',
      });
      return;
    }
    if (prompt.kind === 'confirmation') {
      if (
        prompt.request.acknowledgements?.some(
          (_acknowledgement, index) =>
            singleFormValue(form, `ack${index}`) !== 'yes',
        )
      ) {
        await this.#sendPage(response, 400, {
          error: 'Complete every required acknowledgement before approving.',
        });
        return;
      }
      const values: Record<string, string> = {};
      const editor = prompt.request.autonomyEditor;
      if (editor) {
        const expiresAt = singleFormValue(form, 'autonomy.expiresAt');
        if (!expiresAt || !Number.isFinite(Date.parse(expiresAt))) {
          await this.#sendPage(response, 400, {
            error: 'Enter a valid ISO 8601 policy expiry.',
          });
          return;
        }
        values['autonomy.expiresAt'] = new Date(expiresAt).toISOString();
        values['autonomy.agentVisiblePrivateAmounts'] =
          singleFormValue(
            form,
            'autonomy.agentVisiblePrivateAmounts',
          ) === 'true'
            ? 'true'
            : 'false';
        const numericNames = [
          ...editor.perActionSpend.map(
            (_entry, index) => `autonomy.perAction.${index}`,
          ),
          ...editor.cumulativeSpend.map(
            (_entry, index) => `autonomy.cumulative.${index}`,
          ),
          ...[
            'maximumNativeValuePerAction',
            'maximumNativeValueCumulative',
            'maximumNetworkFeePerAction',
            'maximumNetworkFeeCumulative',
            'maximumActions',
            'maximumMessages',
          ].filter(
            (name) =>
              editor[
                name as keyof typeof editor
              ] !== undefined,
          ).map((name) => `autonomy.${name}`),
          ...editor.priceBands.flatMap((_band, index) => [
            `autonomy.price.${index}.minNumerator`,
            `autonomy.price.${index}.minDenominator`,
            `autonomy.price.${index}.maxNumerator`,
            `autonomy.price.${index}.maxDenominator`,
          ]),
        ];
        for (const name of numericNames) {
          const value = singleFormValue(form, name);
          if (!value || !/^(?:0|[1-9][0-9]*)$/u.test(value)) {
            await this.#sendPage(response, 400, {
              error: 'Policy budgets and limits must be whole base-unit values.',
            });
            return;
          }
          if (
            (name.endsWith('Denominator') ||
              name === 'autonomy.maximumActions') &&
            value === '0'
          ) {
            await this.#sendPage(response, 400, {
              error: 'Policy denominators and maximum actions must be positive.',
            });
            return;
          }
          values[name] = value;
        }
      }
      this.#settlePending('accepted', editor ? values : undefined);
      await this.#sendPage(response, 200, {
        flash:
          'Action approved. The signer will verify each bound transaction before signing.',
      });
      return;
    }

    const values: Record<string, string> = {};
    for (const field of prompt.request.fields) {
      const rawValue = singleFormValue(form, field.id);
      const value = rawValue?.trim() ?? '';
      const valid =
        field.kind === 'access-secret'
          ? /^0x[0-9a-fA-F]{64}$/u.test(value)
          : /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value);
      if (!valid) {
        await this.#sendPage(response, 400, {
          error: `${field.title} is invalid.`,
        });
        return;
      }
      values[field.id] = value;
    }
    this.#settlePending('accepted', values);
    await this.#sendPage(response, 200, {
      flash:
        'Private values received locally. Review the complete action before signing.',
    });
  }

  #settlePending(
    outcome: 'accepted' | 'declined' | 'cancelled',
    values?: Record<string, string>,
  ): void {
    const prompt = this.#pending;
    if (!prompt) return;
    this.#pending = null;
    clearTimeout(prompt.timer);
    if (prompt.kind === 'confirmation') {
      prompt.resolve(
        outcome === 'declined'
          ? { outcome, reason: 'client-declined' }
          : outcome === 'accepted' && values
            ? { outcome, values }
            : { outcome },
      );
      return;
    }
    prompt.resolve(
      outcome === 'accepted'
        ? { outcome, values: values ?? {} }
        : { outcome },
    );
  }

  #sendEmpty(response: ServerResponse, status: number): void {
    response.writeHead(status, securityHeaders());
    response.end();
  }
}

export type {
  AgentControlOperation,
  AgentControlPendingPrompt,
  AgentControlSummary,
} from './localControlPage.js';
