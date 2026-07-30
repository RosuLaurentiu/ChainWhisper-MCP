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
import type { AutonomyPolicyProposalV1 } from './autonomy.js';
import type {
  Address,
  OtcNegotiationKind,
  PrivateStateQueryV1,
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

const operationSchema = {
  type: 'object',
  properties: {
    operationId: { type: 'string' },
  },
  required: ['operationId'],
  additionalProperties: false,
};

const privateStateQuerySchema = {
  oneOf: [
    {
      type: 'object',
      properties: {
        kind: { type: 'string', const: 'balances' },
        assets: {
          type: 'array',
          minItems: 1,
          maxItems: 16,
          uniqueItems: true,
          items: { type: 'string', minLength: 1, maxLength: 128 },
          description:
            'Verified private-token symbols or addresses from the audited runtime.',
        },
      },
      required: ['kind', 'assets'],
      additionalProperties: false,
    },
    {
      type: 'object',
      properties: {
        kind: { type: 'string', const: 'order' },
        route: {
          type: 'string',
          enum: ['one-off', 'recurring'],
        },
        orderId: {
          type: 'string',
          pattern: '^[1-9][0-9]*$',
        },
        fromBlock: {
          type: 'integer',
          minimum: 0,
          description:
            'Optional first block for wallet-scoped receipt history.',
        },
        receiptLimit: {
          type: 'integer',
          minimum: 1,
          maximum: 50,
          default: 20,
        },
      },
      required: ['kind', 'route', 'orderId'],
      additionalProperties: false,
    },
  ],
};

const autonomyAssetAmountSchema = {
  type: 'object',
  properties: {
    asset: { type: 'string', minLength: 1 },
    amount: { type: 'string', pattern: '^(?:0|[1-9][0-9]*)$' },
  },
  required: ['asset', 'amount'],
  additionalProperties: false,
};

const autonomyPairSchema = {
  type: 'object',
  properties: {
    sellAsset: { type: 'string', minLength: 1 },
    buyAsset: { type: 'string', minLength: 1 },
  },
  required: ['sellAsset', 'buyAsset'],
  additionalProperties: false,
};

const autonomyCommonProperties = {
  version: { type: 'string', const: 'cw.autonomy-policy/1' },
  wallet: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' },
  chainId: { type: 'integer', const: 2_632_500 },
  manifestHash: { type: 'string', pattern: '^0x[0-9a-fA-F]{64}$' },
  startsAt: { type: 'string', format: 'date-time' },
  expiresAt: { type: 'string', format: 'date-time' },
  agentVisiblePrivateAmounts: {
    type: 'boolean',
    description:
      'Policy-wide consent. When true, the agent may both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.',
  },
};

const autonomyProposalSchema = {
  oneOf: [
    {
      type: 'object',
      properties: {
        ...autonomyCommonProperties,
        mode: { type: 'string', const: 'bounded' },
        scope: {
          type: 'object',
          properties: {
            allowedActions: {
              type: 'array',
              items: {
                type: 'string',
                enum: [
                  'create_trade',
                  'create_recurring',
                  'fill',
                  'counter',
                  'edit',
                  'order_update',
                  'privacy_bridge',
                  'send_order_message',
                ],
              },
            },
            allowedAssets: { type: 'array', items: { type: 'string' } },
            allowedPairs: { type: 'array', items: autonomyPairSchema },
            allowedOrderTypes: {
              type: 'array',
              items: { type: 'string' },
            },
            allowedCounterparties: {
              type: 'array',
              items: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' },
            },
            allowedBridgeRoutes: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  pair: { type: 'string' },
                  direction: {
                    type: 'string',
                    enum: ['public-to-private', 'private-to-public'],
                  },
                },
                required: ['pair', 'direction'],
                additionalProperties: false,
              },
            },
            messaging: {
              type: 'object',
              properties: {
                enabled: { type: 'boolean' },
                counterparties: {
                  type: 'array',
                  items: {
                    type: 'string',
                    pattern: '^0x[0-9a-fA-F]{40}$',
                  },
                },
              },
              required: ['enabled', 'counterparties'],
              additionalProperties: false,
            },
          },
          required: [
            'allowedActions',
            'allowedAssets',
            'allowedPairs',
            'allowedOrderTypes',
            'allowedCounterparties',
            'allowedBridgeRoutes',
            'messaging',
          ],
          additionalProperties: false,
        },
        limits: {
          type: 'object',
          properties: {
            perActionSpend: {
              type: 'array',
              items: autonomyAssetAmountSchema,
            },
            cumulativeSpend: {
              type: 'array',
              items: autonomyAssetAmountSchema,
            },
            maximumNativeValuePerAction: {
              type: 'string',
              pattern: '^(?:0|[1-9][0-9]*)$',
            },
            maximumNativeValueCumulative: {
              type: 'string',
              pattern: '^(?:0|[1-9][0-9]*)$',
            },
            maximumNetworkFeePerAction: {
              type: 'string',
              pattern: '^(?:0|[1-9][0-9]*)$',
            },
            maximumNetworkFeeCumulative: {
              type: 'string',
              pattern: '^(?:0|[1-9][0-9]*)$',
            },
            maximumActions: { type: 'integer', minimum: 1 },
            maximumMessages: { type: 'integer', minimum: 0 },
            priceBands: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  ...autonomyPairSchema.properties,
                  minimumBuyPerSellNumerator: {
                    type: 'string',
                    pattern: '^(?:0|[1-9][0-9]*)$',
                  },
                  minimumBuyPerSellDenominator: {
                    type: 'string',
                    pattern: '^[1-9][0-9]*$',
                  },
                  maximumBuyPerSellNumerator: {
                    type: 'string',
                    pattern: '^(?:0|[1-9][0-9]*)$',
                  },
                  maximumBuyPerSellDenominator: {
                    type: 'string',
                    pattern: '^[1-9][0-9]*$',
                  },
                },
                required: [
                  'sellAsset',
                  'buyAsset',
                  'minimumBuyPerSellNumerator',
                  'minimumBuyPerSellDenominator',
                  'maximumBuyPerSellNumerator',
                  'maximumBuyPerSellDenominator',
                ],
                additionalProperties: false,
              },
            },
          },
          required: [
            'perActionSpend',
            'cumulativeSpend',
            'maximumNativeValuePerAction',
            'maximumNativeValueCumulative',
            'maximumNetworkFeePerAction',
            'maximumNetworkFeeCumulative',
            'maximumActions',
            'maximumMessages',
            'priceBands',
          ],
          additionalProperties: false,
        },
      },
      required: [
        ...Object.keys(autonomyCommonProperties),
        'mode',
        'scope',
        'limits',
      ],
      additionalProperties: false,
    },
    {
      type: 'object',
      properties: {
        ...autonomyCommonProperties,
        mode: { type: 'string', const: 'full' },
        allowlistedEconomicSurface: { type: 'boolean', const: true },
      },
      required: [
        ...Object.keys(autonomyCommonProperties),
        'mode',
        'allowlistedEconomicSurface',
      ],
      additionalProperties: false,
    },
  ],
};

export const signerStatusInputSchema = {
  type: 'object',
  properties: {
    requiredAssets: {
      type: 'array',
      maxItems: 16,
      uniqueItems: true,
      items: { type: 'string', minLength: 1, maxLength: 128 },
      description:
        'Optional verified private assets needed by the intended ChainWhisper action, such as p.WISP and p.COTI.',
    },
  },
  additionalProperties: false,
};

export const signerStatusRequiredAssets = (raw: unknown): string[] => {
  const assets = asRecord(raw).requiredAssets;
  return Array.isArray(assets)
    ? assets.filter(
        (asset): asset is string =>
          typeof asset === 'string',
      )
    : [];
};

export const createSignerTools = (
  service: ChainWhisperSignerService,
): JsonMcpTool[] => {
  const core: JsonMcpTool[] = [
    {
      name: 'chainwhisper_signer_status',
      description:
        'Check wallet, privacy, required private-asset, Agent Control, autonomy, and pending-operation readiness without exposing credentials or secrets.',
      inputSchema: signerStatusInputSchema,
      annotations: { readOnlyHint: true },
      execute: (raw) =>
        service.getStatus(signerStatusRequiredAssets(raw)),
    },
    {
      name: 'chainwhisper_open_control_panel',
      description:
        'Open the signer-owned local ChainWhisper Agent Control page. The agent never receives its URL, bootstrap token, session, wallet key, or other local secrets.',
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
      execute: () => service.openControlPanel(),
    },
    {
      name: 'chainwhisper_autonomy_status',
      description:
        'Read active local autonomy modes, lifecycle state, and remaining policy budgets. These budgets are intentionally visible to the user’s chosen agent; wallet credentials and signer secrets are never returned.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
      execute: () => service.autonomyStatus(),
    },
    {
      name: 'chainwhisper_private_state',
      description:
        'Reveal only this Agent Wallet’s verified private-token balances or wallet-scoped ChainWhisper hidden order inventory, progress, and participant receipts. These trading values are visible to the user’s chosen agent while remaining private on-chain; they are not wallet credentials. Without policyId, one clear local Agent Control confirmation is required. A policyId must name the exact active wallet-bound policy with agentVisiblePrivateAmounts enabled. Policy-authorized reads do not consume action budget, public-order participants do not need individual allowlisting, and fixed-recipient orders still enforce counterparty scope. Policy mismatches fail closed without opening a fallback prompt.',
      inputSchema: {
        type: 'object',
        properties: {
          query: privateStateQuerySchema,
          policyId: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            description:
              'Optional exact active local autonomy policy for this disclosure.',
          },
        },
        required: ['query'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
      execute: (raw) => {
        const input = asRecord(raw);
        if (
          Object.hasOwn(input, 'policyId') &&
          (typeof input.policyId !== 'string' ||
            !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(
              input.policyId,
            ))
        ) {
          throw new SignerError(
            'ENVELOPE_INVALID',
            'policyId must be one exact local autonomy policy identifier.',
          );
        }
        return service.getPrivateState(
          asRecord(input.query) as unknown as PrivateStateQueryV1,
          typeof input.policyId === 'string'
            ? input.policyId
            : undefined,
        );
      },
    },
    {
      name: 'chainwhisper_request_autonomy',
      description:
        'Request a bounded policy of up to 30 days or full audited economic autonomy of up to 24 hours. Activation always requires review in local Agent Control; a local edit may narrow but never broaden the request.',
      inputSchema: {
        type: 'object',
        properties: { proposal: autonomyProposalSchema },
        required: ['proposal'],
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
      execute: (raw) =>
        service.requestAutonomy(
          asRecord(asRecord(raw).proposal) as unknown as AutonomyPolicyProposalV1,
        ),
    },
    {
      name: 'chainwhisper_pause_autonomy',
      description:
        'Immediately pause every local autonomy policy. Pause is fail-closed and does not require signing or a confirmation prompt.',
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false,
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
      },
      execute: () => service.pauseAutonomy(),
    },
    {
      name: 'chainwhisper_execute_action',
      description:
        'Validate and durably queue one exact paired ActionEnvelopeV1, then return its operation id immediately. Signing continues asynchronously through Agent Control or an active policy; poll chainwhisper_get_operation for progress.',
      inputSchema: {
        type: 'object',
        properties: {
          envelope: {
            type: 'object',
            description:
              'Signed ActionEnvelopeV1 returned by chainwhisper-mcp.',
          },
          policyId: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
            description:
              'Optional active local autonomy policy. A mismatch returns a structured denial and never opens a fallback confirmation.',
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
        const policyId =
          typeof asRecord(raw).policyId === 'string'
            ? asRecord(raw).policyId as string
            : undefined;
        return service.executeAction(
          signedEnvelopeInput(envelope),
          policyId,
        );
      },
    },
    {
      name: 'chainwhisper_get_operation',
      description:
        'Poll safe semantic status, required user action, transaction links, and the completed result for a queued signer operation. Broadcast recovery is reconciled automatically.',
      inputSchema: operationSchema,
      annotations: { readOnlyHint: true },
      execute: async (raw) => {
        const operationId = requiredString(asRecord(raw), 'operationId');
        return service.getOperation(operationId);
      },
    },
    {
      name: 'chainwhisper_send_order_message',
      description:
        'Send a structured cw.otc/1 proposal, counter, acceptance, decline, status, or access message using the embedded official COTI private-messaging SDK. Local access secrets can be shared by reference but can never be passed in tool arguments. The result includes a safe operationId that can be polled with chainwhisper_get_operation when delivery is pending or uncertain.',
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
          policyId: {
            type: 'string',
            minLength: 1,
            maxLength: 128,
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
          ...(typeof input.policyId === 'string'
            ? { policyId: input.policyId }
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

  return core;
};
