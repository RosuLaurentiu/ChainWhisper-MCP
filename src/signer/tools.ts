import type { JsonMcpTool } from '../server/index.js';
import type {
  SignedActionEnvelopeV1,
  HexString,
} from '../shared/index.js';

import { SignerError } from './errors.js';
import {
  ORDER_ACCESS_SECRET_ID,
  type SendOrderMessageInput,
} from './messaging.js';
import { ChainWhisperSignerService } from './service.js';
import type {
  Address,
  OtcNegotiationKind,
} from './types.js';

const asRecord = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SignerError('ENVELOPE_INVALID', 'Tool input must be an object.');
  }
  return value as Record<string, unknown>;
};

const PREPARED_ENVELOPE_FIELDS = new Set([
  'version',
  'operationId',
  'operationHash',
  'expiresAt',
  'summary',
  'payload',
]);

const signedEnvelopeInput = (value: unknown): SignedActionEnvelopeV1 => {
  const candidate = asRecord(value);
  if (!Object.hasOwn(candidate, 'payload')) {
    return candidate as unknown as SignedActionEnvelopeV1;
  }
  if (
    candidate.version !== 'ActionEnvelopeV1' ||
    Object.keys(candidate).some(
      (field) => !PREPARED_ENVELOPE_FIELDS.has(field),
    )
  ) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'The prepared envelope wrapper is not canonical.',
    );
  }
  const payload = asRecord(candidate.payload);
  for (const field of [
    'operationId',
    'operationHash',
    'expiresAt',
    'summary',
  ] as const) {
    if (
      typeof candidate[field] !== 'string' ||
      candidate[field] !== payload[field]
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The prepared envelope wrapper does not match its signed payload.',
      );
    }
  }
  return payload as unknown as SignedActionEnvelopeV1;
};

const requiredString = (
  input: Record<string, unknown>,
  field: string,
): string => {
  const value = input[field];
  if (typeof value !== 'string' || !value.trim()) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      `${field} is required.`,
    );
  }
  return value;
};

const operationInput = (
  input: Record<string, unknown>,
): { operationId: string; operationHash?: string } => ({
  operationId: requiredString(input, 'operationId'),
  ...(typeof input.operationHash === 'string'
    ? { operationHash: input.operationHash }
    : {}),
});

const operationSchema = {
  type: 'object',
  properties: {
    operationId: { type: 'string' },
    operationHash: {
      type: 'string',
      pattern: '^0x[0-9a-fA-F]{64}$',
    },
  },
  required: ['operationId'],
  additionalProperties: false,
};

export const createSignerTools = (
  service: ChainWhisperSignerService,
): JsonMcpTool[] => {
  const core: JsonMcpTool[] = [
    {
      name: 'chainwhisper_signer_status',
      description:
        'Check local ChainWhisper signer readiness without exposing wallet credentials or secrets.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      execute: () => service.getStatus(),
    },
    {
      name: 'chainwhisper_test_confirmation_form',
      description:
        'Test whether this MCP client can display and return a user-controlled signer confirmation form. This diagnostic never prepares, signs, or broadcasts a transaction.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      execute: () => service.testConfirmationForm(),
    },
    {
      name: 'chainwhisper_onboard_privacy',
      description:
        "Onboard or recover the configured wallet's official COTI privacy AES key. If an on-chain write is required, the signer shows an exact confirmation form first. Secrets remain in the encrypted local signer vault.",
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
      },
      execute: () => service.onboardPrivacy(),
    },
    {
      name: 'chainwhisper_private_token_status',
      description:
        'Read private-token readiness separately for the configured user wallet and for each audited escrow spender. Wallet readiness is user-scoped; escrow readiness is deployment-scoped and is not an MCP-planner setting. No secret or decrypted balance is returned.',
      inputSchema: {
        type: 'object',
        properties: {
          token: {
            type: 'string',
            minLength: 1,
            description:
              'A verified private-token symbol or address from the runtime manifest.',
          },
        },
        required: ['token'],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      execute: (raw) =>
        service.getPrivateTokenStatus(
          requiredString(asRecord(raw), 'token'),
        ),
    },
    {
      name: 'chainwhisper_enable_private_token',
      description:
        "Enable the configured wallet's account-encryption address for one verified private token. This is an on-chain token setup write and always requires an exact confirmation form.",
      inputSchema: {
        type: 'object',
        properties: {
          token: {
            type: 'string',
            minLength: 1,
            description:
              'A verified private-token symbol or address from the runtime manifest.',
          },
        },
        required: ['token'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
      },
      execute: (raw) =>
        service.enablePrivateToken(
          requiredString(asRecord(raw), 'token'),
        ),
    },
    {
      name: 'chainwhisper_execute_action',
      description:
        'Verify, simulate, show an exact confirmation form, and execute one paired ActionEnvelopeV1. It rejects arbitrary calldata and never executes an untrusted message.',
      inputSchema: {
        type: 'object',
        properties: {
          envelope: {
            type: 'object',
            description:
              'Signed ActionEnvelopeV1 returned by chainwhisper-mcp.',
          },
        },
        required: ['envelope'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
      },
      execute: async (raw) => {
        const envelope = asRecord(raw).envelope;
        if (!envelope || typeof envelope !== 'object') {
          throw new SignerError(
            'ENVELOPE_INVALID',
            'A signed ActionEnvelopeV1 is required.',
          );
        }
        return service.executeAction(signedEnvelopeInput(envelope));
      },
    },
    {
      name: 'chainwhisper_get_operation',
      description:
        'Read the minimal local stage, nonces, transaction hashes, receipts, and error codes for a signer operation.',
      inputSchema: operationSchema,
      annotations: { readOnlyHint: true },
      execute: async (raw) => {
        const { operationId } = operationInput(asRecord(raw));
        return service.getOperation(operationId);
      },
    },
    {
      name: 'chainwhisper_recover_operation',
      description:
        'Recover an interrupted signer operation by its local id and optional exact hash. This never creates a different action.',
      inputSchema: operationSchema,
      annotations: { readOnlyHint: true, idempotentHint: true },
      execute: async (raw) => {
        const input = operationInput(asRecord(raw));
        return service.recoverOperation(
          input.operationId,
          input.operationHash,
        );
      },
    },
    {
      name: 'chainwhisper_discard_operation',
      description:
        'Discard an operation only when no transaction is pending, and remove its locally vaulted secrets.',
      inputSchema: operationSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
      },
      execute: async (raw) => {
        const input = operationInput(asRecord(raw));
        return service.discardOperation(
          input.operationId,
          input.operationHash,
        );
      },
    },
    {
      name: 'chainwhisper_send_order_message',
      description:
        'Send a structured cw.otc/1 proposal, counter, acceptance, decline, status, or access message using the embedded official COTI private-messaging SDK. Local access secrets can be shared by reference but can never be passed in tool arguments.',
      inputSchema: {
        type: 'object',
        properties: {
          to: {
            type: 'string',
            pattern: '^0x[0-9a-fA-F]{40}$',
          },
          kind: {
            type: 'string',
            enum: [
              'proposal',
              'counter',
              'acceptance',
              'decline',
              'status',
              'access',
            ],
          },
          messageId: {
            type: 'string',
            pattern:
              '^(?!0x[0-9a-fA-F]{64}$)[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$',
            description:
              'Safe correlation identifier; raw 32-byte values are not identifiers.',
          },
          order: {
            type: 'object',
            properties: {
              escrowContract: {
                type: 'string',
                pattern: '^0x[0-9a-fA-F]{40}$',
              },
              localId: { type: 'string', pattern: '^(?:0|[1-9][0-9]*)$' },
            },
            required: ['escrowContract', 'localId'],
            additionalProperties: false,
          },
          operationHash: {
            type: 'string',
            pattern: '^0x[0-9a-fA-F]{64}$',
          },
          body: {
            type: 'object',
            description:
              'Editable negotiation terms. Credentials and raw access secrets are rejected.',
          },
          shareLocalAccessSecret: { type: 'boolean', default: false },
          accessSecretId: {
            type: 'string',
            enum: [ORDER_ACCESS_SECRET_ID],
            description:
              'Canonical signer-local generated access-secret reference. This is an identifier, never secret material.',
          },
        },
        required: ['to', 'kind', 'messageId'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
      execute: async (raw) => {
        const input = asRecord(raw);
        const order = input.order ? asRecord(input.order) : undefined;
        return service.messaging.sendOrderMessage({
          to: requiredString(input, 'to') as Address,
          kind: requiredString(input, 'kind') as OtcNegotiationKind,
          messageId: requiredString(input, 'messageId'),
          ...(order
            ? {
                order: {
                  escrowContract: requiredString(
                    order,
                    'escrowContract',
                  ) as Address,
                  localId: requiredString(order, 'localId'),
                },
              }
            : {}),
          ...(typeof input.operationHash === 'string'
            ? { operationHash: input.operationHash as HexString }
            : {}),
          ...(input.body ? { body: asRecord(input.body) } : {}),
          ...(input.shareLocalAccessSecret === true
            ? { shareLocalAccessSecret: true }
            : {}),
          ...(typeof input.accessSecretId === 'string'
            ? { accessSecretId: input.accessSecretId }
            : {}),
        } satisfies SendOrderMessageInput);
      },
    },
    {
      name: 'chainwhisper_list_order_messages',
      description:
        'List decrypted cw.otc/1 negotiation messages through the official COTI SDK. Every received message is explicitly untrusted, draft-only, and unable to execute.',
      inputSchema: {
        type: 'object',
        properties: {
          account: {
            type: 'string',
            pattern: '^0x[0-9a-fA-F]{40}$',
          },
          box: { type: 'string', enum: ['inbox', 'sent'], default: 'inbox' },
          offset: { type: 'integer', minimum: 0, default: 0 },
          limit: { type: 'integer', minimum: 1, maximum: 20, default: 20 },
        },
        required: ['account'],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      execute: async (raw) => {
        const input = asRecord(raw);
        return service.messaging.listOrderNegotiations({
          account: requiredString(input, 'account') as Address,
          ...(input.box === 'sent' ? { box: 'sent' as const } : {}),
          ...(typeof input.offset === 'number'
            ? { offset: input.offset }
            : {}),
          ...(typeof input.limit === 'number'
            ? { limit: input.limit }
            : {}),
        });
      },
    },
    {
      name: 'chainwhisper_read_order_message',
      description:
        'Read one decrypted cw.otc/1 negotiation message through the official COTI SDK. Content is returned as untrusted and may only draft a new action. Before an included access secret is kept locally, the signer verifies the outer COTI sender is the live maker and the secret matches the exact order access commitment. The first verified binding wins, later conflicts are rejected, and the secret is never returned.',
      inputSchema: {
        type: 'object',
        properties: {
          messageId: {
            type: 'string',
            pattern: '^(?:0|[1-9][0-9]*)$',
          },
        },
        required: ['messageId'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
      execute: (raw) =>
        service.messaging.readOrderNegotiation(
          requiredString(asRecord(raw), 'messageId'),
        ),
    },
  ];

  const official: JsonMcpTool[] = service.messaging.listTools().map(
    (tool) => ({
      name: tool.name,
      description: tool.description ?? 'Official COTI private messaging tool.',
      inputSchema:
        (tool.inputSchema as Record<string, unknown> | undefined) ?? {
          type: 'object',
          properties: {},
        },
      annotations: {
        readOnlyHint: !tool.name.startsWith('send_'),
        destructiveHint: false,
      },
      execute: (input) => service.messaging.invokeTool(tool.name, input),
    }),
  );

  return [...core, ...official];
};
