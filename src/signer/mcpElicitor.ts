import type { Server } from '@modelcontextprotocol/sdk/server/index.js';

import type {
  ConfirmationRequest,
  ConfirmationResult,
  FormElicitor,
  PrivateValueElicitor,
  PrivateValueRequest,
  PrivateValueResult,
} from './types.js';

const display = (values: string[]): string =>
  values.length ? values.join(', ') : 'None';

const transactionDetails = (request: ConfirmationRequest): string[] =>
  request.details?.length
    ? [
        'Exact transaction terms:',
        ...request.details.map(
          (detail) => `- ${detail.label}: ${detail.value}`,
        ),
      ]
    : [
        `Assets: ${display(request.assets)}`,
        `Amounts: ${display(request.amounts)}`,
      ];

const orderTypeDisplay = (request: ConfirmationRequest): string => {
  if (!request.orderType) {
    if (request.orderTypeLabel) return request.orderTypeLabel;
    return request.action === 'send_order_message'
      ? 'Not applicable'
      : 'Legacy envelope (classification unavailable)';
  }
  return `${request.orderTypeLabel ?? request.orderType.id} [${request.orderType.id}]`;
};

export const buildConfirmationMessage = (
  request: ConfirmationRequest,
): string => {
  return [
    'Confirm one ChainWhisper signer write.',
    `Wallet: ${request.wallet}`,
    `Contract: ${request.contract}`,
    `Action: ${request.action}`,
    `Order type: ${orderTypeDisplay(request)}`,
    `Step: ${request.stepIndex + 1}/${request.stepCount} (${request.stepId})`,
    ...transactionDetails(request),
    `Counterparty: ${request.counterparty ?? 'None'}`,
    `Spender: ${request.spender ?? 'None'}`,
    `Protocol fee: ${request.fee}`,
    `Native value: ${request.nativeValue}`,
    `Gas cap: ${request.gasCap}`,
    `Expected result: ${request.expectedResult}`,
    `Summary: ${request.summary}`,
    `Operation hash: ${request.operationHash}`,
    'Nothing is signed unless you explicitly enable the confirmation field and submit this form.',
  ].join('\n');
};

export class McpFormElicitor
  implements FormElicitor, PrivateValueElicitor
{
  readonly #server: Server;

  constructor(server: Server) {
    this.#server = server;
  }

  isSupported(): boolean {
    return Boolean(this.#server.getClientCapabilities()?.elicitation?.form);
  }

  async requestConfirmation(
    request: ConfirmationRequest,
    timeoutMs: number,
  ): Promise<ConfirmationResult> {
    if (!this.isSupported()) return { outcome: 'cancelled' };
    const result = await this.#server.elicitInput(
      {
        mode: 'form',
        message: buildConfirmationMessage(request),
        requestedSchema: {
          type: 'object',
          properties: {
            confirm: {
              type: 'boolean',
              title: 'Confirm this exact write',
              description:
                'Enable only after reviewing every displayed transaction term.',
              default: false,
            },
          },
          required: ['confirm'],
        },
      },
      { timeout: timeoutMs },
    );
    if (result.action === 'decline') {
      return { outcome: 'declined', reason: 'client-declined' };
    }
    if (result.action === 'cancel') return { outcome: 'cancelled' };
    return result.content?.confirm === true
      ? { outcome: 'accepted' }
      : {
          outcome: 'declined',
          reason: 'confirmation-not-enabled',
        };
  }

  requestPrivateValues(
    _request: PrivateValueRequest,
    _timeoutMs: number,
  ): Promise<PrivateValueResult> {
    // MCP form responses are visible to the MCP host. Confidential amounts
    // and access secrets therefore use the signer-owned local-web channel.
    return Promise.resolve({ outcome: 'cancelled' });
  }
}

export class DeferredMcpFormElicitor
  implements FormElicitor, PrivateValueElicitor
{
  #delegate: McpFormElicitor | null = null;

  attach(server: Server): void {
    if (this.#delegate) {
      throw new Error('MCP form elicitor is already attached.');
    }
    this.#delegate = new McpFormElicitor(server);
  }

  isSupported(): boolean {
    return this.#delegate?.isSupported() ?? false;
  }

  requestConfirmation(
    request: ConfirmationRequest,
    timeoutMs: number,
  ): Promise<ConfirmationResult> {
    return this.#delegate
      ? this.#delegate.requestConfirmation(request, timeoutMs)
      : Promise.resolve({ outcome: 'cancelled' });
  }

  requestPrivateValues(
    request: PrivateValueRequest,
    timeoutMs: number,
  ): Promise<PrivateValueResult> {
    return this.#delegate
      ? this.#delegate.requestPrivateValues(request, timeoutMs)
      : Promise.resolve({ outcome: 'cancelled' });
  }
}
