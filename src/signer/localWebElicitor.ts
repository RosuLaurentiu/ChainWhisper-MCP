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

import { isSafeOperationId } from '../shared/index.js';
import {
  agentControlStateKey,
  renderAgentControlPage,
  type AgentControlPageModel,
  type AgentControlPendingPrompt,
  type AgentControlSummary,
} from './localControlPage.js';
import {
  policyAmountFromDisplay,
  policyPriceFromDisplay,
} from './autonomyPresentation.js';
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
  reason?:
    | 'browser-open-failed'
    | 'browser-arrival-timeout'
    | 'server-unavailable'
    | 'closed';
};

export type AgentControlAction =
  | 'pause-autonomy'
  | 'resume-autonomy'
  | 'revoke-autonomy'
  | 'dismiss-focused-operation'
  | 'history-previous'
  | 'history-next'
  | 'refresh-balances'
  | 'import-wallet'
  | 'generate-wallet'
  | 'clear-wallet-backup'
  | 'onboard-privacy'
  | 'enable-private-token'
  | 'recover-operation'
  | 'discard-operation';

export type AgentControlActionResult = {
  ok: boolean;
  message: string;
};

export type LocalWebFormElicitorOptions = {
  openUrl?: OpenUrl;
  requireBrowserArrival?: boolean;
  browserArrivalTimeoutMs?: number;
  activeBrowserGraceMs?: number;
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

type BrowserArrivalWaiter = {
  bootstrapToken: string | null;
  sessionDigest: Buffer | null;
  settle: (arrived: boolean) => void;
};

type EventClient = {
  response: ServerResponse;
  sessionGeneration: number;
};

class BodyTooLargeError extends Error {}

const COOKIE_NAME = 'cw_agent_control';
const MAX_BODY_BYTES = 16_384;
const RATE_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 120;
const MAX_SUBMISSIONS_PER_WINDOW = 30;
const BOOTSTRAP_LIFETIME_MS = 60_000;
const SESSION_LIFETIME_SECONDS = 8 * 60 * 60;
const DEFAULT_BROWSER_ARRIVAL_TIMEOUT_MS = 5_000;
const MAX_ACTIVE_CSRF_TOKENS = 8;
const DEFAULT_ACTIVE_BROWSER_GRACE_MS = 5_000;
const MAX_EVENT_CONNECTIONS = 4;
const EVENT_STATE_REFRESH_MS = 750;
const EVENT_KEEPALIVE_MS = 15_000;

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

const isPrivateTokenIdentifier = (value: string): boolean =>
  /^(?:0x[0-9a-fA-F]{40}|[A-Za-z0-9][A-Za-z0-9._-]{0,63})$/u.test(
    value,
  );

const isExactOperationHash = (value: string): boolean =>
  /^0x[0-9a-fA-F]{64}$/u.test(value);

const redactSnapshotDiagnostic = (value: string): string => {
  if (
    /(?:private.?key|mnemonic|recovery.?phrase|aes.?key|passphrase|secret)/iu.test(
      value,
    )
  ) {
    return '[redacted]';
  }
  return value.replace(/\b0x[0-9a-f]{64}\b/giu, '[redacted]');
};

const openDefaultBrowser: OpenUrl = (url) =>
  new Promise<void>((resolve, reject) => {
    if (
      !/^http:\/\/127\.0\.0\.1:\d+\/(?:control|open\/[A-Za-z0-9_-]+)$/u.test(
        url,
      )
    ) {
      reject(new Error('Refusing to open a non-local Agent Control URL.'));
      return;
    }
    const command =
      process.platform === 'win32'
        ? 'explorer.exe'
        : process.platform === 'darwin'
          ? 'open'
          : 'xdg-open';
    const child = spawn(command, [url], {
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
  return (
    ((!mode || mode === 'navigate') &&
      (!destination || destination === 'document')) ||
    ((!mode || mode === 'cors' || mode === 'same-origin') &&
      (!destination || destination === 'empty'))
  );
};

const isSafeEventMetadata = (
  request: IncomingMessage,
  expectedOrigin: string,
): boolean => {
  const origin = request.headers.origin;
  const site = request.headers['sec-fetch-site'];
  const mode = request.headers['sec-fetch-mode'];
  const destination = request.headers['sec-fetch-dest'];
  const accept = request.headers.accept ?? '';
  if (origin && origin !== expectedOrigin) return false;
  if (site && site !== 'same-origin') return false;
  if (mode && mode !== 'cors' && mode !== 'same-origin') return false;
  if (destination && destination !== 'empty') return false;
  return accept
    .split(',')
    .some((value) => value.trim().toLowerCase() === 'text/event-stream');
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
  readonly #requireBrowserArrival: boolean;
  readonly #browserArrivalTimeoutMs: number;
  readonly #activeBrowserGraceMs: number;
  readonly #getControlSummary?: LocalWebFormElicitorOptions['getControlSummary'];
  readonly #onControlAction?: LocalWebFormElicitorOptions['onControlAction'];
  readonly #rateWindows = new Map<string, RateWindow>();
  readonly #browserArrivalWaiters = new Set<BrowserArrivalWaiter>();
  readonly #eventClients = new Set<EventClient>();
  readonly #responseSessionGenerations = new WeakMap<
    ServerResponse,
    number
  >();

  #server: Server | null = null;
  #serverStart: Promise<boolean> | null = null;
  #controlOpen: Promise<OpenControlPanelResult> | null = null;
  #port: number | null = null;
  #expectedHost: string | null = null;
  #bootstrapToken: string | null = null;
  #bootstrapExpiresAt = 0;
  #sessionDigest: Buffer | null = null;
  #sessionGeneration = 0;
  #csrfDigests: Buffer[] = [];
  #promptOpenTimer: ReturnType<typeof setTimeout> | null = null;
  #promptOpenAttempted = false;
  #lastEventDisconnectedAt = 0;
  #eventStateTimer: ReturnType<typeof setTimeout> | null = null;
  #eventKeepaliveTimer: ReturnType<typeof setTimeout> | null = null;
  #eventStateRefresh: Promise<void> | null = null;
  #eventForcePublish = false;
  #eventStateKey: string | null = null;
  #eventStateRevision = 0;
  #focusedOperationId: string | null = null;
  #pending: PendingPrompt | null = null;
  #closed = false;

  constructor(options: LocalWebFormElicitorOptions = {}) {
    this.#openUrl = options.openUrl ?? openDefaultBrowser;
    this.#requireBrowserArrival =
      options.requireBrowserArrival ?? options.openUrl === undefined;
    this.#browserArrivalTimeoutMs =
      options.browserArrivalTimeoutMs ??
      DEFAULT_BROWSER_ARRIVAL_TIMEOUT_MS;
    this.#activeBrowserGraceMs =
      options.activeBrowserGraceMs ??
      DEFAULT_ACTIVE_BROWSER_GRACE_MS;
    this.#getControlSummary = options.getControlSummary;
    this.#onControlAction = options.onControlAction;
  }

  isSupported(): boolean {
    return !this.#closed;
  }

  get controlPageReady(): boolean {
    return !this.#closed && this.#server !== null && this.#port !== null;
  }

  get controlPort(): number | null {
    return this.controlPageReady ? this.#port : null;
  }

  get focusedOperationId(): string | null {
    return this.#focusedOperationId;
  }

  async startControlServer(): Promise<boolean> {
    if (this.#closed) return false;
    return this.#ensureServer();
  }

  async openControlPanel(): Promise<OpenControlPanelResult> {
    if (this.#controlOpen) {
      const result = await this.#controlOpen;
      if (
        result.reason === 'browser-open-failed' &&
        !this.#closed
      ) {
        return this.openControlPanel();
      }
      return result;
    }
    const opening = this.#performOpenControlPanel();
    this.#controlOpen = opening;
    try {
      return await opening;
    } finally {
      if (this.#controlOpen === opening) this.#controlOpen = null;
    }
  }

  async #performOpenControlPanel(): Promise<OpenControlPanelResult> {
    if (this.#closed) {
      return {
        opened: false,
        ready: false,
        activePrompt: Boolean(this.#pending),
        reason: 'closed',
      };
    }
    if (!(await this.#ensureServer()) || this.#port === null) {
      return {
        opened: false,
        ready: false,
        activePrompt: Boolean(this.#pending),
        reason: 'server-unavailable',
      };
    }
    if (this.#hasLiveControlPage()) {
      return {
        opened: true,
        ready: true,
        activePrompt: Boolean(this.#pending),
      };
    }
    const open = async (): Promise<
      OpenControlPanelResult['reason'] | null
    > => {
      const sessionAtOpen = this.#sessionDigest;
      let bootstrapAtOpen: string | null = null;
      const controlUrl = sessionAtOpen
        ? `http://127.0.0.1:${this.#port}/control`
        : (() => {
            bootstrapAtOpen = randomToken();
            this.#bootstrapToken = bootstrapAtOpen;
            this.#bootstrapExpiresAt =
              Date.now() + BOOTSTRAP_LIFETIME_MS;
            this.#csrfDigests = [];
            return `http://127.0.0.1:${this.#port}/open/${bootstrapAtOpen}`;
          })();
      const reason = await this.#openAndAwaitArrival(controlUrl, {
        bootstrapToken: bootstrapAtOpen,
        sessionDigest: sessionAtOpen,
      });
      if (
        reason &&
        bootstrapAtOpen &&
        this.#bootstrapToken === bootstrapAtOpen
      ) {
        this.#bootstrapToken = null;
      }
      if (
        reason === 'browser-arrival-timeout' &&
        sessionAtOpen &&
        this.#sessionDigest === sessionAtOpen
      ) {
        this.#sessionDigest = null;
        this.#sessionGeneration += 1;
        this.#csrfDigests = [];
        this.#disconnectEventClients();
      }
      return reason;
    };

    const hadSession = this.#sessionDigest !== null;
    let reason = await open();
    // A browser cookie can be cleared while the signer still remembers the
    // old session. Rotate to a fresh one-time bootstrap and try once more.
    if (
      reason === 'browser-arrival-timeout' &&
      hadSession &&
      this.#sessionDigest === null
    ) {
      reason = await open();
    }
    if (reason) {
      return {
        opened: false,
        ready: true,
        activePrompt: Boolean(this.#pending),
        reason,
      };
    }
    return {
      opened: true,
      ready: true,
      activePrompt: Boolean(this.#pending),
    };
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#bootstrapToken = null;
    this.#sessionDigest = null;
    this.#sessionGeneration += 1;
    this.#csrfDigests = [];
    this.#clearPromptOpenTimer();
    this.#clearEventTimers();
    this.#disconnectEventClients();
    this.#signalBrowserArrival(null, false);
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

  async #openAndAwaitArrival(
    url: string,
    expected: {
      bootstrapToken: string | null;
      sessionDigest: Buffer | null;
    },
  ): Promise<
    'browser-open-failed' | 'browser-arrival-timeout' | null
  > {
    const arrival = this.#requireBrowserArrival
      ? this.#waitForBrowserArrival(expected)
      : null;
    try {
      await this.#openUrl(url);
    } catch {
      arrival?.cancel();
      return 'browser-open-failed';
    }
    if (!arrival) return null;
    return (await arrival.promise)
      ? null
      : 'browser-arrival-timeout';
  }

  #waitForBrowserArrival(expected: {
    bootstrapToken: string | null;
    sessionDigest: Buffer | null;
  }): {
    promise: Promise<boolean>;
    cancel: () => void;
  } {
    let settle!: (arrived: boolean) => void;
    let waiter!: BrowserArrivalWaiter;
    const promise = new Promise<boolean>((resolve) => {
      let settled = false;
      const timer = setTimeout(
        () => settle(false),
        this.#browserArrivalTimeoutMs,
      );
      settle = (arrived) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.#browserArrivalWaiters.delete(waiter);
        resolve(arrived);
      };
      waiter = {
        bootstrapToken: expected.bootstrapToken,
        sessionDigest: expected.sessionDigest,
        settle,
      };
      this.#browserArrivalWaiters.add(waiter);
    });
    return { promise, cancel: () => settle(false) };
  }

  #bindBrowserArrivalSession(
    bootstrapToken: string,
    sessionDigest: Buffer,
  ): void {
    for (const waiter of this.#browserArrivalWaiters) {
      if (waiter.bootstrapToken !== bootstrapToken) continue;
      waiter.bootstrapToken = null;
      waiter.sessionDigest = sessionDigest;
    }
  }

  #signalBrowserArrival(
    request: IncomingMessage | null = null,
    arrived = true,
  ): void {
    if (!arrived) {
      for (const waiter of [...this.#browserArrivalWaiters]) {
        waiter.settle(false);
      }
      return;
    }
    const session = request
      ? parseCookies(request).get(COOKIE_NAME)
      : undefined;
    for (const waiter of [...this.#browserArrivalWaiters]) {
      if (matchesDigest(session, waiter.sessionDigest)) {
        waiter.settle(true);
      }
    }
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
        this.#clearPromptOpenTimer();
        this.#publishStateChange();
        resolve({ outcome: 'timeout' });
      }, timeoutMs);
      this.#pending = {
        id,
        kind: 'confirmation',
        request,
        resolve,
        timer,
      };
      this.#publishStateChange();
      this.#openForPendingPrompt(id);
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
        this.#clearPromptOpenTimer();
        this.#publishStateChange();
        resolve({ outcome: 'timeout' });
      }, timeoutMs);
      this.#pending = {
        id,
        kind: 'private-values',
        request,
        resolve,
        timer,
      };
      this.#publishStateChange();
      this.#openForPendingPrompt(id);
    });
  }

  #openForPendingPrompt(id: string): void {
    this.#clearPromptOpenTimer();
    this.#promptOpenAttempted = false;
    if (this.#hasLiveControlPage()) return;
    this.#schedulePendingPromptOpen(id);
  }

  #schedulePendingPromptOpen(id: string): void {
    if (
      this.#pending?.id !== id ||
      this.#hasLiveControlPage() ||
      this.#promptOpenAttempted ||
      this.#promptOpenTimer
    ) {
      return;
    }
    const elapsedSinceDisconnect =
      this.#lastEventDisconnectedAt > 0
        ? Date.now() - this.#lastEventDisconnectedAt
        : this.#activeBrowserGraceMs;
    const delay = Math.max(
      0,
      this.#activeBrowserGraceMs - elapsedSinceDisconnect,
    );
    this.#promptOpenTimer = setTimeout(() => {
      this.#promptOpenTimer = null;
      if (
        this.#pending?.id !== id ||
        this.#hasLiveControlPage() ||
        this.#promptOpenAttempted
      ) {
        return;
      }
      this.#promptOpenAttempted = true;
      void this.openControlPanel();
    }, delay);
    this.#promptOpenTimer.unref?.();
  }

  #hasLiveControlPage(): boolean {
    return this.#eventClients.size > 0;
  }

  #clearPromptOpenTimer(): void {
    if (!this.#promptOpenTimer) return;
    clearTimeout(this.#promptOpenTimer);
    this.#promptOpenTimer = null;
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
      const sessionDigest = digest(sessionToken);
      this.#disconnectEventClients();
      this.#sessionDigest = sessionDigest;
      this.#sessionGeneration += 1;
      this.#csrfDigests = [];
      this.#bindBrowserArrivalSession(
        requestUrl.slice('/open/'.length),
        sessionDigest,
      );
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
      this.#responseSessionGenerations.set(
        response,
        this.#sessionGeneration,
      );
      await this.#sendPage(response, 200);
      this.#signalBrowserArrival(request);
      return;
    }
    if (request.method === 'GET' && requestUrl === '/snapshot') {
      await this.#sendSnapshot(response);
      return;
    }
    if (request.method === 'GET' && requestUrl === '/events') {
      const expectedOrigin = `http://${this.#expectedHost}`;
      if (!isSafeEventMetadata(request, expectedOrigin)) {
        this.#sendEmpty(response, 403);
        return;
      }
      if (this.#eventClients.size >= MAX_EVENT_CONNECTIONS) {
        response.writeHead(429, {
          ...securityHeaders(),
          'Retry-After': '5',
        });
        response.end();
        return;
      }
      this.#openEventStream(request, response);
      return;
    }
    if (request.method === 'POST' && requestUrl === '/action') {
      this.#responseSessionGenerations.set(
        response,
        this.#sessionGeneration,
      );
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

  #openEventStream(
    request: IncomingMessage,
    response: ServerResponse,
  ): void {
    const client: EventClient = {
      response,
      sessionGeneration: this.#sessionGeneration,
    };
    response.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': 'text/event-stream; charset=utf-8',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    response.flushHeaders();
    response.write('retry: 1000\n: connected\n\n');
    this.#eventClients.add(client);
    response.once('close', () => this.#removeEventClient(client));
    this.#lastEventDisconnectedAt = 0;
    this.#promptOpenAttempted = false;
    this.#clearPromptOpenTimer();
    this.#signalBrowserArrival(request);
    this.#publishStateChange(true);
    this.#scheduleEventKeepalive();
  }

  #removeEventClient(client: EventClient): void {
    if (!this.#eventClients.delete(client)) return;
    if (this.#eventClients.size > 0) return;
    this.#lastEventDisconnectedAt = Date.now();
    this.#clearEventTimers();
    this.#promptOpenAttempted = false;
    const pendingId = this.#pending?.id;
    if (pendingId) this.#schedulePendingPromptOpen(pendingId);
  }

  #disconnectEventClients(): void {
    if (this.#eventClients.size === 0) return;
    const clients = [...this.#eventClients];
    this.#eventClients.clear();
    this.#clearEventTimers();
    this.#lastEventDisconnectedAt = Date.now();
    for (const { response } of clients) response.end();
  }

  #publishStateChange(force = false): void {
    if (this.#eventClients.size === 0 || this.#closed) return;
    this.#eventForcePublish ||= force;
    if (this.#eventStateRefresh) return;
    const refresh = this.#refreshEventState();
    this.#eventStateRefresh = refresh;
    void refresh.finally(() => {
      if (this.#eventStateRefresh === refresh) {
        this.#eventStateRefresh = null;
      }
      if (this.#eventForcePublish && this.#eventClients.size > 0) {
        this.#publishStateChange();
        return;
      }
      this.#scheduleEventStateRefresh();
    });
  }

  async #refreshEventState(): Promise<void> {
    const force = this.#eventForcePublish;
    this.#eventForcePublish = false;
    const pending = this.#publicPending();
    const summary = await this.#summary();
    if (this.#closed || this.#eventClients.size === 0) return;
    const stateKey = agentControlStateKey({ pending, summary });
    const changed = stateKey !== this.#eventStateKey;
    if (!force && !changed) return;
    if (changed) {
      this.#eventStateKey = stateKey;
      this.#eventStateRevision += 1;
    }
    const payload = JSON.stringify({
      revision: this.#eventStateRevision,
      stateKey,
    });
    for (const client of [...this.#eventClients]) {
      if (client.sessionGeneration !== this.#sessionGeneration) {
        this.#removeEventClient(client);
        client.response.end();
        continue;
      }
      client.response.write(`event: state\ndata: ${payload}\n\n`);
    }
  }

  #scheduleEventStateRefresh(): void {
    if (
      this.#closed ||
      this.#eventClients.size === 0 ||
      this.#eventStateTimer ||
      this.#eventStateRefresh
    ) {
      return;
    }
    this.#eventStateTimer = setTimeout(() => {
      this.#eventStateTimer = null;
      this.#publishStateChange();
    }, EVENT_STATE_REFRESH_MS);
    this.#eventStateTimer.unref?.();
  }

  #scheduleEventKeepalive(): void {
    if (
      this.#closed ||
      this.#eventClients.size === 0 ||
      this.#eventKeepaliveTimer
    ) {
      return;
    }
    this.#eventKeepaliveTimer = setTimeout(() => {
      this.#eventKeepaliveTimer = null;
      for (const { response } of this.#eventClients) {
        response.write(`: keepalive ${Date.now()}\n\n`);
      }
      this.#scheduleEventKeepalive();
    }, EVENT_KEEPALIVE_MS);
    this.#eventKeepaliveTimer.unref?.();
  }

  #clearEventTimers(): void {
    if (this.#eventStateTimer) {
      clearTimeout(this.#eventStateTimer);
      this.#eventStateTimer = null;
    }
    if (this.#eventKeepaliveTimer) {
      clearTimeout(this.#eventKeepaliveTimer);
      this.#eventKeepaliveTimer = null;
    }
  }

  async #summary(): Promise<AgentControlSummary> {
    if (!this.#getControlSummary) {
      return {
        ...defaultSummary(this.#pending),
        focusedOperationId: this.#focusedOperationId,
      };
    }
    try {
      return {
        ...(await this.#getControlSummary()),
        focusedOperationId: this.#focusedOperationId,
      };
    } catch {
      return {
        ...defaultSummary(this.#pending),
        focusedOperationId: this.#focusedOperationId,
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
    const sessionGeneration =
      this.#responseSessionGenerations.get(response);
    const model: AgentControlPageModel = {
      csrfToken: '',
      pending: this.#publicPending(),
      summary: await this.#summary(),
      ...messages,
    };
    if (
      this.#sessionDigest === null ||
      sessionGeneration === undefined ||
      this.#sessionGeneration !== sessionGeneration
    ) {
      this.#sendEmpty(response, 401);
      return;
    }
    model.csrfToken = this.#issueCsrfToken();
    const nonce = randomToken(18);
    response.writeHead(status, {
      ...securityHeaders(nonce),
      // Chrome serializes Origin as "null" for form submissions from a
      // document using no-referrer. Keep bootstrap responses on no-referrer,
      // but let the authenticated page provide the exact same-origin value
      // required by #handleAction.
      'Referrer-Policy': 'same-origin',
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
    const safeSummary: AgentControlSummary = {
      ...summary,
      ...(summary.diagnostics
        ? {
            diagnostics: summary.diagnostics.map(({ label, value }) => ({
              label,
              value: redactSnapshotDiagnostic(value),
            })),
          }
        : {}),
      ...(summary.walletSetup?.generatedBackup
        ? {
            walletSetup: {
              ...summary.walletSetup,
              generatedBackup: {
                address: summary.walletSetup.generatedBackup.address,
                privateKey: '[redacted]',
              },
            },
          }
        : {}),
    };
    response.writeHead(200, {
      ...securityHeaders(),
      'Content-Type': 'application/json; charset=utf-8',
    });
    response.end(
      JSON.stringify({
        pending: safePending,
        summary: safeSummary,
        stateKey: agentControlStateKey({
          pending,
          summary: safeSummary,
        }),
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
    if (!this.#consumeCsrfToken(csrf)) {
      this.#sendEmpty(response, 403);
      return;
    }
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

  #issueCsrfToken(): string {
    const token = randomToken();
    this.#csrfDigests.push(digest(token));
    if (this.#csrfDigests.length > MAX_ACTIVE_CSRF_TOKENS) {
      this.#csrfDigests.splice(
        0,
        this.#csrfDigests.length - MAX_ACTIVE_CSRF_TOKENS,
      );
    }
    return token;
  }

  #consumeCsrfToken(value: string | null): boolean {
    if (!value) return false;
    const actual = digest(value);
    const index = this.#csrfDigests.findIndex(
      (expected) =>
        actual.length === expected.length &&
        timingSafeEqual(actual, expected),
    );
    if (index < 0) return false;
    this.#csrfDigests.splice(index, 1);
    return true;
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
      action !== 'dismiss-focused-operation' &&
      action !== 'history-previous' &&
      action !== 'history-next' &&
      action !== 'refresh-balances' &&
      action !== 'import-wallet' &&
      action !== 'generate-wallet' &&
      action !== 'clear-wallet-backup' &&
      action !== 'onboard-privacy' &&
      action !== 'enable-private-token' &&
      action !== 'recover-operation' &&
      action !== 'discard-operation'
    ) {
      await this.#sendPage(response, 400, {
        error: 'Unknown Agent Control action.',
      });
      return;
    }
    if (action === 'dismiss-focused-operation') {
      this.#focusedOperationId = null;
      this.#publishStateChange();
      await this.#sendPage(response, 200, {
        flash: 'Operation details closed.',
      });
      return;
    }
    if (!this.#onControlAction) {
      await this.#sendPage(response, 409, {
        error: 'Agent Control actions are not available in this signer session.',
      });
      return;
    }
    try {
      let fields: Record<string, string> = Object.fromEntries(
        [...form.entries()]
          .filter(([key]) => !['csrf', 'intent', 'action'].includes(key))
          .map(([key, value]) => [key, value]),
      );
      if (action === 'enable-private-token') {
        const token = singleFormValue(form, 'token')?.trim() ?? '';
        if (!isPrivateTokenIdentifier(token)) {
          await this.#sendPage(response, 400, {
            error:
              'Enter one verified private-token symbol or 20-byte token address.',
          });
          return;
        }
        fields = { token };
      } else if (action === 'recover-operation') {
        const operationId =
          singleFormValue(form, 'operationId')?.trim() ?? '';
        if (!isSafeOperationId(operationId)) {
          await this.#sendPage(response, 400, {
            error: 'Enter a valid local operation ID.',
          });
          return;
        }
        fields = { operationId };
      } else if (action === 'discard-operation') {
        const operationId =
          singleFormValue(form, 'operationId')?.trim() ?? '';
        const operationHash =
          singleFormValue(form, 'operationHash')?.trim() ?? '';
        if (!isSafeOperationId(operationId)) {
          await this.#sendPage(response, 400, {
            error: 'Enter a valid local operation ID.',
          });
          return;
        }
        if (!isExactOperationHash(operationHash)) {
          await this.#sendPage(response, 400, {
            error:
              'Enter the exact 0x-prefixed 32-byte operation hash.',
          });
          return;
        }
        fields = { operationId, operationHash };
      }
      const result = await this.#onControlAction(action, fields);
      this.#publishStateChange();
      await this.#sendPage(response, result.ok ? 200 : 409, {
        ...(result.ok
          ? { flash: result.message }
          : { error: result.message }),
      });
    } catch {
      await this.#sendPage(response, 500, {
        error: 'The signer could not complete that local action safely.',
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
        for (const [prefix, entries] of [
          ['perAction', editor.perActionSpend],
          ['cumulative', editor.cumulativeSpend],
        ] as const) {
          for (const [index, entry] of entries.entries()) {
            const name = `autonomy.${prefix}.${index}`;
            const input = singleFormValue(form, name);
            const amount =
              input &&
              entry.decimals !== undefined &&
              entry.displayAmount !== undefined
                ? policyAmountFromDisplay(input, entry.decimals)
                : input && /^(?:0|[1-9][0-9]*)$/u.test(input)
                  ? input
                  : undefined;
            if (amount === undefined) {
              await this.#sendPage(response, 400, {
                error: 'Enter a valid token amount for every policy budget.',
              });
              return;
            }
            values[name] = amount;
          }
        }
        for (const name of [
          'maximumNativeValuePerAction',
          'maximumNativeValueCumulative',
          'maximumNetworkFeePerAction',
          'maximumNetworkFeeCumulative',
        ] as const) {
          if (editor[name] === undefined) continue;
          const input = singleFormValue(form, `autonomy.${name}`);
          const amount = input
            ? policyAmountFromDisplay(input, 18)
            : undefined;
          if (amount === undefined) {
            await this.#sendPage(response, 400, {
              error: 'Enter valid COTI amounts for value and network limits.',
            });
            return;
          }
          values[`autonomy.${name}`] = amount;
        }
        for (const name of [
          'maximumActions',
          'maximumMessages',
        ] as const) {
          if (editor[name] === undefined) continue;
          const field = `autonomy.${name}`;
          const value = singleFormValue(form, field);
          if (
            !value ||
            !/^(?:0|[1-9][0-9]*)$/u.test(value) ||
            (name === 'maximumActions' && value === '0')
          ) {
            await this.#sendPage(response, 400, {
              error:
                'Maximum actions must be positive and message limits must be whole numbers.',
            });
            return;
          }
          values[field] = value;
        }
        for (const [index, band] of editor.priceBands.entries()) {
          const human =
            band.minimumDisplay !== undefined &&
            band.maximumDisplay !== undefined &&
            band.sellDecimals !== undefined &&
            band.buyDecimals !== undefined;
          if (human) {
            const minimum = policyPriceFromDisplay(
              singleFormValue(
                form,
                `autonomy.price.${index}.minimum`,
              ) ?? '',
              band.sellDecimals,
              band.buyDecimals,
            );
            const maximum = policyPriceFromDisplay(
              singleFormValue(
                form,
                `autonomy.price.${index}.maximum`,
              ) ?? '',
              band.sellDecimals,
              band.buyDecimals,
            );
            if (!minimum || !maximum) {
              await this.#sendPage(response, 400, {
                error: 'Enter valid positive prices for every policy band.',
              });
              return;
            }
            values[`autonomy.price.${index}.minNumerator`] =
              minimum.numerator;
            values[`autonomy.price.${index}.minDenominator`] =
              minimum.denominator;
            values[`autonomy.price.${index}.maxNumerator`] =
              maximum.numerator;
            values[`autonomy.price.${index}.maxDenominator`] =
              maximum.denominator;
            continue;
          }
          for (const suffix of [
            'minNumerator',
            'minDenominator',
            'maxNumerator',
            'maxDenominator',
          ]) {
            const name = `autonomy.price.${index}.${suffix}`;
            const value = singleFormValue(form, name);
            if (
              !value ||
              !/^[1-9][0-9]*$/u.test(value)
            ) {
              await this.#sendPage(response, 400, {
                error: 'Policy price ratios must be positive whole numbers.',
              });
              return;
            }
            values[name] = value;
          }
        }
      }
      if (
        !prompt.request.autonomyEditor &&
        !prompt.request.action.toLowerCase().includes('autonomy')
      ) {
        this.#focusedOperationId = prompt.request.operationId;
      }
      this.#settlePending('accepted', editor ? values : undefined);
      await this.#sendPage(response, 200, {
        flash:
          'Approved. The signer is validating the bound transactions and will show progress here.',
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
    this.#clearPromptOpenTimer();
    this.#publishStateChange();
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
