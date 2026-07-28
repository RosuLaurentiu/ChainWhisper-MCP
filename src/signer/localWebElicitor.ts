import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { buildConfirmationMessage } from './mcpElicitor.js';
import type {
  ConfirmationRequest,
  ConfirmationResult,
  FormElicitor,
  PrivateValueElicitor,
  PrivateValueRequest,
  PrivateValueResult,
} from './types.js';

type OpenUrl = (url: string) => Promise<void> | void;

const escapeHtml = (value: string): string =>
  value.replace(
    /[&<>"']/gu,
    (character) =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      })[character] ?? character,
  );

const openDefaultBrowser: OpenUrl = (url) => {
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
  child.unref();
};

const headers = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy':
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
};

const page = (
  title: string,
  message: string,
  fields: string,
  error = '',
): string => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>${escapeHtml(title)}</title><style>
body{font:16px/1.45 system-ui,sans-serif;background:#101215;color:#eef1f5;margin:0;padding:32px}
main{max-width:760px;margin:auto;background:#191d22;border:1px solid #30363d;border-radius:14px;padding:28px}
h1{margin-top:0;font-size:24px}pre{white-space:pre-wrap;background:#101215;padding:16px;border-radius:8px}
label{display:block;margin:18px 0 6px}input[type=text]{box-sizing:border-box;width:100%;padding:11px}
.check{display:flex;gap:10px;align-items:center}.error{color:#ff8d8d}.actions{display:flex;gap:12px;margin-top:24px}
button{padding:11px 18px;border-radius:8px;border:0;font-weight:650;cursor:pointer}
.confirm{background:#37c878;color:#07140d}.decline{background:#30363d;color:#eef1f5}
</style></head><body><main><h1>${escapeHtml(title)}</h1>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<pre>${escapeHtml(message)}</pre><form method="post">${fields}
<div class="actions"><button class="confirm" name="action" value="confirm">Submit</button>
<button class="decline" name="action" value="decline" formnovalidate>Decline</button></div></form>
</main></body></html>`;

const readBody = async (request: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > 16_384) throw new Error('Form body is too large.');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
};

const sendHtml = (
  response: ServerResponse,
  status: number,
  html: string,
): void => {
  response.writeHead(status, {
    ...headers,
    'Content-Type': 'text/html; charset=utf-8',
  });
  response.end(html);
};

export class LocalWebFormElicitor
  implements FormElicitor, PrivateValueElicitor
{
  readonly #openUrl: OpenUrl;

  constructor(options: { openUrl?: OpenUrl } = {}) {
    this.#openUrl = options.openUrl ?? openDefaultBrowser;
  }

  isSupported(): boolean {
    return true;
  }

  async #serve<T>(
    timeoutMs: number,
    render: (error?: string) => string,
    submit: (values: URLSearchParams) => T | string,
    timeoutResult: T,
    cancelledResult: T,
  ): Promise<T> {
    const token = randomBytes(32).toString('hex');
    const path = `/chainwhisper-confirm/${token}`;
    return new Promise<T>((resolve) => {
      let settled = false;
      const finish = (result: T): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        server.close();
        resolve(result);
      };
      const server = createServer(async (request, response) => {
        if (request.url !== path) {
          response.writeHead(404, headers);
          response.end();
          return;
        }
        if (request.method === 'GET') {
          sendHtml(response, 200, render());
          return;
        }
        if (request.method !== 'POST') {
          response.writeHead(405, headers);
          response.end();
          return;
        }
        try {
          const values = new URLSearchParams(await readBody(request));
          const result = submit(values);
          if (typeof result === 'string') {
            sendHtml(response, 400, render(result));
            return;
          }
          sendHtml(
            response,
            200,
            page(
              'ChainWhisper',
              'Response received. You may close this tab.',
              '',
            ),
          );
          finish(result);
        } catch {
          sendHtml(response, 400, render('Invalid form submission.'));
        }
      });
      const timer = setTimeout(() => finish(timeoutResult), timeoutMs);
      server.listen(0, '127.0.0.1', async () => {
        const address = server.address();
        if (!address || typeof address === 'string') {
          finish(cancelledResult);
          return;
        }
        try {
          await this.#openUrl(`http://127.0.0.1:${address.port}${path}`);
        } catch {
          finish(cancelledResult);
        }
      });
      server.on('error', () => finish(cancelledResult));
    });
  }

  requestConfirmation(
    request: ConfirmationRequest,
    timeoutMs: number,
  ): Promise<ConfirmationResult> {
    const fields =
      '<label class="check"><input type="checkbox" name="confirm" value="yes" required> Confirm this exact request</label>';
    return this.#serve<ConfirmationResult>(
      timeoutMs,
      (error) =>
        page(
          request.action === 'confirmation_form_diagnostic'
            ? 'Test ChainWhisper confirmation'
            : 'Confirm ChainWhisper write',
          buildConfirmationMessage(request),
          fields,
          error,
        ),
      (values) => {
        if (values.get('action') === 'decline') {
          return {
            outcome: 'declined',
            reason: 'client-declined',
          } satisfies ConfirmationResult;
        }
        return values.get('confirm') === 'yes'
          ? ({ outcome: 'accepted' } satisfies ConfirmationResult)
          : 'Confirmation must be enabled.';
      },
      { outcome: 'timeout' },
      { outcome: 'cancelled' },
    );
  }

  requestPrivateValues(
    request: PrivateValueRequest,
    timeoutMs: number,
  ): Promise<PrivateValueResult> {
    const fields = request.fields
      .map(
        (field) =>
          `<label for="${escapeHtml(field.id)}">${escapeHtml(field.title)}</label>` +
          `<p>${escapeHtml(field.description)}</p>` +
          `<input id="${escapeHtml(field.id)}" name="${escapeHtml(field.id)}" type="text" required autocomplete="off">`,
      )
      .join('');
    return this.#serve<PrivateValueResult>(
      timeoutMs,
      (error) =>
        page(
          'Enter private ChainWhisper values',
          [
            `Wallet: ${request.wallet}`,
            `Operation hash: ${request.operationHash}`,
            'Values are posted only to the local signer.',
            'Never enter a wallet private key, mnemonic, AES key, or vault passphrase.',
          ].join('\n'),
          fields,
          error,
        ),
      (form) => {
        if (form.get('action') === 'decline') {
          return { outcome: 'declined' } satisfies PrivateValueResult;
        }
        const values: Record<string, string> = {};
        for (const field of request.fields) {
          const value = form.get(field.id)?.trim() ?? '';
          const valid =
            field.kind === 'access-secret'
              ? /^0x[0-9a-fA-F]{64}$/u.test(value)
              : /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value);
          if (!valid) return `${field.title} is invalid.`;
          values[field.id] = value;
        }
        return {
          outcome: 'accepted',
          values,
        } satisfies PrivateValueResult;
      },
      { outcome: 'timeout' },
      { outcome: 'cancelled' },
    );
  }
}
