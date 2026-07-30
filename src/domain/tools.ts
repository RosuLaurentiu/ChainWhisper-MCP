import { ChainWhisperDomainService } from './service.js';
import type {
  ComparePriceReferencesInput,
  CounterInput,
  CreateRecurringInput,
  CreateTradeInput,
  DomainToolDefinition,
  EditInput,
  FillInput,
  ListOrdersInput,
  OrderIdentityInput,
  OrderUpdateInput,
  PrepareSwapInput,
  PrivacyBridgeInput,
  PrivacyBridgeStatusInput,
  ToolResult
} from './types.js';
import { assertAllowedKeys, assertPlainRecord } from './validation.js';
import { toolFailure } from './errors.js';
import { MAX_DECIMAL_INPUT_LENGTH } from './decimal.js';

const addressSchema = { type: 'string', pattern: '^0x[a-fA-F0-9]{40}$' };
const decimalSchema = {
  type: 'string',
  maxLength: MAX_DECIMAL_INPUT_LENGTH,
  pattern: '^(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?$',
  description: 'A base-10 decimal string. JSON numbers are not accepted.'
};
const privateAmountModeSchema = {
  enum: ['signer-input', 'agent-provided'],
  default: 'signer-input',
  description:
    'signer-input collects private values inside Agent Control. agent-provided binds agent-visible private values into the envelope for either normal local confirmation or a matching autonomy policy.'
};
const liquidityVisibilitySchema = {
  enum: ['visible', 'private'],
  default: 'visible',
  description:
    'visible publishes inventory amounts. private keeps eligible private-token liquidity encrypted on-chain.'
};
const recurringPriceSchema = {
  anyOf: [
    decimalSchema,
    {
      type: 'object',
      additionalProperties: false,
      required: ['reference', 'offsetBps'],
      properties: {
        reference: { const: 'market' },
        offsetBps: {
          type: 'integer',
          minimum: -9999,
          maximum: 10000,
          description:
            '-1000 is 10% below and 1000 is 10% above the live market reference.'
        }
      }
    }
  ],
  description:
    'An exact quote-per-base decimal or an offset from the current compatible market reference.'
};
const assetSchema = {
  anyOf: [
    { type: 'string', minLength: 1 },
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        kind: { enum: ['native', 'erc20', 'private-erc20'] },
        symbol: { type: 'string', minLength: 1 },
        address: addressSchema
      }
    }
  ],
  description: 'Native, a verified token symbol, or a verified token address.'
};
const orderSchema = {
  oneOf: [
    {
      type: 'object',
      additionalProperties: false,
      required: ['escrowContract', 'localId'],
      properties: {
        escrowContract: addressSchema,
        localId: { type: 'string', pattern: '^(?:0|[1-9][0-9]*)$' }
      }
    },
    {
      type: 'object',
      additionalProperties: false,
      required: ['handle'],
      properties: {
        handle: { type: 'string', pattern: '^cw_[a-zA-Z0-9_-]{8,160}$' }
      }
    }
  ]
};
const privacyBridgePairs = [
  'coti',
  'weth',
  'wbtc',
  'usdt',
  'usdc-e',
  'wada',
  'gcoti',
  'wisp'
] as const;
const ORDER_TYPE_CATALOG = [
  {
    id: 'one-off.standard-public',
    label: 'One-off · public listing · visible amounts',
    cadence: 'one-off',
    access: 'public',
    terms: 'public',
    liquidity: 'visible',
    fillStyle: 'partial or full',
    supported: true
  },
  {
    id: 'one-off.unlisted',
    label: 'One-off · unlisted link · encrypted exact terms',
    cadence: 'one-off',
    access: 'unlisted',
    terms: 'encrypted',
    liquidity: 'visible after authorized reveal',
    fillStyle: 'exact full fill',
    supported: true
  },
  {
    id: 'one-off.direct',
    label: 'One-off · fixed recipient · encrypted exact terms',
    cadence: 'one-off',
    access: 'direct',
    terms: 'encrypted',
    liquidity: 'visible after participant reveal',
    fillStyle: 'exact full fill',
    supported: true
  },
  {
    id: 'one-off.private-liquidity.public',
    label: 'One-off · public listing · hidden private-token liquidity',
    cadence: 'one-off',
    access: 'public',
    terms: 'public price terms',
    liquidity: 'hidden',
    fillStyle: 'signer-confirmed private fill',
    supported: true
  },
  {
    id: 'one-off.private-liquidity.unlisted',
    label: 'One-off · unlisted link · hidden private-token liquidity',
    cadence: 'one-off',
    access: 'unlisted',
    terms: 'encrypted',
    liquidity: 'hidden',
    fillStyle: 'signer-confirmed private fill',
    supported: true
  },
  {
    id: 'one-off.private-liquidity.direct',
    label: 'One-off · fixed recipient · hidden private-token liquidity',
    cadence: 'one-off',
    access: 'direct',
    terms: 'public price terms',
    liquidity: 'hidden',
    fillStyle: 'signer-confirmed private fill',
    supported: true
  },
  {
    id: 'recurring.public',
    label: 'Recurring · public access · visible inventory',
    cadence: 'recurring',
    access: 'public',
    terms: 'public prices',
    liquidity: 'visible',
    fillStyle: 'reusable buy and sell sides',
    supported: true
  },
  {
    id: 'recurring.direct',
    label: 'Recurring · fixed recipient · visible inventory',
    cadence: 'recurring',
    access: 'direct',
    terms: 'public prices',
    liquidity: 'visible',
    fillStyle: 'reusable buy and sell sides',
    supported: true
  },
  {
    id: 'recurring.private-liquidity.public',
    label: 'Recurring · public access · hidden private-token inventory',
    cadence: 'recurring',
    access: 'public',
    terms: 'public prices',
    liquidity: 'private-token sides hidden; public-token sides visible',
    fillStyle: 'reusable signer-confirmed sides',
    supported: true
  },
  {
    id: 'recurring.private-liquidity.direct',
    label: 'Recurring · fixed recipient · hidden private-token inventory',
    cadence: 'recurring',
    access: 'direct',
    terms: 'public prices',
    liquidity: 'private-token sides hidden; public-token sides visible',
    fillStyle: 'reusable signer-confirmed sides',
    supported: true
  }
] as const;

const safeExecute =
  <TInput>(handler: (input: TInput) => Promise<ToolResult<unknown>>) =>
  async (input: unknown): Promise<ToolResult<unknown>> => {
    try {
      return await handler(assertPlainRecord(input) as TInput);
    } catch (error) {
      return toolFailure(error);
    }
  };

export const createChainWhisperDomainTools = (
  service: ChainWhisperDomainService
): DomainToolDefinition[] => [
  {
    name: 'chainwhisper_order_types',
    description:
      'Explain the canonical ChainWhisper order classifications returned by the public beta. Create tools derive the classification from economic intent, so no orderType pre-call is required.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    },
    execute: async (input) => {
      try {
        assertPlainRecord(input);
        return {
          ok: true,
          data: {
            version: 'OrderTypeCatalogV1',
            orderTypes: ORDER_TYPE_CATALOG.filter(
              ({ id }) =>
                id !== 'recurring.direct' &&
                id !== 'recurring.private-liquidity.direct'
            )
          }
        };
      } catch (error) {
        return toolFailure(error);
      }
    }
  },
  {
    name: 'chainwhisper_status',
    description:
      'Check the keyless ChainWhisper planner, COTI Mainnet registry snapshot, and write compatibility. This tool never connects a wallet.',
    inputSchema: { type: 'object', additionalProperties: false, properties: {} },
    execute: async (input) => {
      try {
        assertPlainRecord(input);
        return await service.status();
      } catch (error) {
        return toolFailure(error);
      }
    }
  },
  {
    name: 'chainwhisper_list_orders',
    description:
      'List up to 20 safe ChainWhisper order summaries. Hidden amounts and access secrets are never returned.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        wallet: addressSchema,
        role: { enum: ['all', 'maker', 'recipient', 'filler'] },
        kind: { enum: ['all', 'trade', 'recurring'] },
        status: { enum: ['all', 'open', 'filled', 'cancelled', 'expired', 'declined', 'paused'] },
        access: { enum: ['all', 'public', 'unlisted', 'direct'] },
        baseAsset: assetSchema,
        quoteAsset: assetSchema,
        cursor: { type: 'string', maxLength: 512 },
        limit: { type: 'integer', minimum: 1, maximum: 20 }
      }
    },
    execute: safeExecute<ListOrdersInput>((input) => service.listOrders(input))
  },
  {
    name: 'chainwhisper_get_order',
    description:
      'Read one ChainWhisper order using its verified contract-local identity or opaque trusted handle.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: { order: orderSchema }
    },
    execute: safeExecute<{ order: OrderIdentityInput }>((input) => service.getOrder(input))
  },
  {
    name: 'chainwhisper_compare_price_references',
    description:
      'Compare ChainWhisper and compatible market price references in quote-per-base orientation. Amount is optional. A best-execution ranking is returned only when an amount is supplied and executable liquidity was actually checked.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['baseAsset', 'quoteAsset', 'side'],
      properties: {
        baseAsset: assetSchema,
        quoteAsset: assetSchema,
        side: { enum: ['buy', 'sell'], description: 'Buy or sell the base asset.' },
        amount: decimalSchema
      }
    },
    execute: safeExecute<ComparePriceReferencesInput>((input) => service.comparePriceReferences(input))
  },
  {
    name: 'chainwhisper_prepare_swap',
    description:
      'Select the best single visible public ChainWhisper order that can fill the complete requested amount, then prepare its canonical fill envelope. It safely refuses when the complete listing does not fit in one response; it never combines orders, uses hidden liquidity, signs, or broadcasts.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        wallet: addressSchema,
        sellAsset: assetSchema,
        buyAsset: assetSchema,
        inputMode: {
          enum: ['sell', 'buy'],
          default: 'sell',
          description:
            'sell treats amount as the exact asset paid; buy treats amount as the exact asset received.'
        },
        amount: decimalSchema
      }
    },
    execute: safeExecute<PrepareSwapInput>((input) =>
      service.prepareSwap(input)
    )
  },
  {
    name: 'chainwhisper_privacy_bridge_status',
    description:
      'Read and verify one allowlisted Privacy Portal bridge pair, live pause/deposit policy, wallet blacklist status, limits, and an optional exact amount fee quote. This is keyless and read-only.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['pair'],
      properties: {
        wallet: addressSchema,
        pair: { enum: privacyBridgePairs },
        direction: { enum: ['public-to-private', 'private-to-public'] },
        amount: decimalSchema
      }
    },
    execute: safeExecute<PrivacyBridgeStatusInput>((input) =>
      service.privacyBridgeStatus(input)
    )
  },
  {
    name: 'chainwhisper_prepare_privacy_bridge',
    description:
      'Prepare an exact shield (public-to-private) or unshield (private-to-public) transaction for one of the eight current allowlisted Privacy Portal pairs. The amount is necessarily public in the deployed bridge calldata. Exact approvals and the quoted portal fee are bound into the paired envelope; this planner never signs or broadcasts.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['pair', 'direction'],
      properties: {
        wallet: addressSchema,
        pair: { enum: privacyBridgePairs },
        direction: { enum: ['public-to-private', 'private-to-public'] },
        amount: decimalSchema
      }
    },
    execute: safeExecute<PrivacyBridgeInput>((input) =>
      service.preparePrivacyBridge(input)
    )
  },
  {
      name: 'chainwhisper_prepare_create_trade',
      description:
        'Prepare a one-off OTC order from its assets, access, liquidity visibility, amounts, recipient, expiry, and fill policy. The canonical order type is derived and returned. Confidential amounts default to local Agent Control; agent-provided values can use local confirmation or a matching autonomy policy.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        wallet: addressSchema,
        offerAsset: assetSchema,
        requestAsset: assetSchema,
        access: {
          enum: ['public', 'unlisted', 'direct'],
          default: 'public',
          description:
            'Public listing, unlisted shareable link, or a fixed direct recipient.'
        },
        liquidityVisibility: liquidityVisibilitySchema,
        privateAmountMode: privateAmountModeSchema,
        offerAmount: {
          ...decimalSchema,
          description:
            'Include public amounts. For confidential terms, omit in signer-input mode or include the exact amount in agent-provided mode.'
        },
        requestAmount: {
          ...decimalSchema,
          description:
            'Include public amounts. For confidential terms, omit in signer-input mode or include the exact amount in agent-provided mode.'
        },
        recipient: addressSchema,
        expiresAt: { anyOf: [{ type: 'string', format: 'date-time' }, { type: 'null' }] },
        fillPolicy: {
          type: 'object',
          additionalProperties: false,
          properties: {
            partialFillsAllowed: { type: 'boolean' },
            minPartialFillBps: { type: 'integer', minimum: 0, maximum: 5000 },
            minRequestAmount: decimalSchema,
            maxRequestAmountPerWallet: decimalSchema,
            oneFillPerWallet: { type: 'boolean' }
          }
        }
      }
    },
    execute: safeExecute<CreateTradeInput>((input) => {
      assertAllowedKeys(input, [
        'wallet',
        'offerAsset',
        'requestAsset',
        'offerAmount',
        'requestAmount',
        'access',
        'recipient',
        'liquidityVisibility',
        'privateAmountMode',
        'expiresAt',
        'fillPolicy'
      ]);
      return service.prepareCreateTrade(input);
    })
  },
  {
      name: 'chainwhisper_prepare_create_recurring',
      description:
        'Prepare public-access reusable two-sided liquidity from a pair, maker buy budget and price, maker sell inventory and price, and liquidity visibility. The canonical recurring type is derived and returned. Each price may be exact or a live market offset in basis points.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        wallet: addressSchema,
        baseAsset: assetSchema,
        quoteAsset: assetSchema,
        buyPrice: recurringPriceSchema,
        sellPrice: recurringPriceSchema,
        liquidityVisibility: liquidityVisibilitySchema,
        privateAmountMode: privateAmountModeSchema,
        buyQuoteLiquidity: {
          ...decimalSchema,
          description:
            'Include public inventory. For private inventory, omit in signer-input mode or include it in agent-provided mode.'
        },
        sellBaseLiquidity: {
          ...decimalSchema,
          description:
            'Include public inventory. For private inventory, omit in signer-input mode or include it in agent-provided mode.'
        }
      }
    },
    execute: safeExecute<CreateRecurringInput>((input) => {
      assertAllowedKeys(input, [
        'wallet',
        'baseAsset',
        'quoteAsset',
        'buyPrice',
        'sellPrice',
        'buyQuoteLiquidity',
        'sellBaseLiquidity',
        'liquidityVisibility',
        'privateAmountMode'
      ]);
      return service.prepareCreateRecurring(input);
    })
  },
  {
    name: 'chainwhisper_prepare_fill',
    description:
      'Prepare a fill for an existing trusted ChainWhisper order. Confidential amounts default to Agent Control; agent-provided values can use local confirmation or a matching autonomy policy.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        privateAmountMode: privateAmountModeSchema,
        inputAmount: {
          ...decimalSchema,
          description:
            'Include visible payments, including private-token amounts on public Standard and explicitly labeled legacy Standard orders. For an encrypted private-token payment, omit in signer-input mode or include it in agent-provided mode.'
        },
        minOutputAmount: {
          ...decimalSchema,
          description:
            'Visible output limits only. Omit when the output asset is private because the deployed fill field is public calldata.'
        },
        recurringSide: {
          enum: ['buy', 'sell'],
          description:
            'User action relative to the base asset: buy means pay quote and receive base; sell means pay base and receive quote.'
        }
      }
    },
    execute: safeExecute<FillInput>((input) => service.prepareFill(input))
  },
  {
    name: 'chainwhisper_prepare_counter',
    description:
      'Prepare a canonical Direct counterorder against a trusted one-off order. Counter terms are recipient-bound to the original maker. Confidential amounts default to Agent Control; agent-provided values can use local confirmation or a matching autonomy policy.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        privateAmountMode: privateAmountModeSchema,
        offerAmount: {
          ...decimalSchema,
          description:
            'Include public terms and visibly bound private-token amounts when superseding an explicitly labeled legacy Standard counter. For confidential Direct terms, omit in signer-input mode or include in agent-provided mode.'
        },
        requestAmount: {
          ...decimalSchema,
          description:
            'Include public terms and visibly bound private-token amounts when superseding an explicitly labeled legacy Standard counter. For confidential Direct terms, omit in signer-input mode or include in agent-provided mode.'
        },
        expiresAt: { anyOf: [{ type: 'string', format: 'date-time' }, { type: 'null' }] }
      }
    },
    execute: safeExecute<CounterInput>((input) => service.prepareCounter(input))
  },
  {
    name: 'chainwhisper_prepare_edit',
    description:
      'Prepare an edit to a trusted owned ChainWhisper order. Only allowlisted order terms are accepted.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        privateAmountMode: privateAmountModeSchema,
        changes: {
          type: 'object',
          additionalProperties: false,
          properties: {
            offerAmount: decimalSchema,
            requestAmount: decimalSchema,
            expiresAt: { anyOf: [{ type: 'string', format: 'date-time' }, { type: 'null' }] },
            partialFillsAllowed: { type: 'boolean' },
            minPartialFillBps: { type: 'integer', minimum: 0, maximum: 5000 },
            minRequestAmount: decimalSchema,
            maxRequestAmountPerWallet: decimalSchema,
            oneFillPerWallet: { type: 'boolean' },
            buyPrice: decimalSchema,
            sellPrice: decimalSchema,
            addBuyQuoteLiquidity: decimalSchema,
            addSellBaseLiquidity: decimalSchema,
            removeBuyQuoteLiquidity: decimalSchema,
            removeSellBaseLiquidity: decimalSchema,
            replaceConfidentialTerms: {
              type: 'boolean',
              description:
                'For Direct or private-liquidity one-off replacements, collect the complete resulting confidential terms inside the signer.'
            },
            adjustPrivateLiquidity: {
              type: 'boolean',
              description:
                'For private-inventory recurring orders, collect private add/remove deltas inside the signer.'
            }
          }
        }
      }
    },
    execute: safeExecute<EditInput>((input) => service.prepareEdit(input))
  },
  {
    name: 'chainwhisper_prepare_order_update',
    description:
      'Prepare an allowlisted lifecycle update for a trusted ChainWhisper order. Administrative and arbitrary contract actions are unavailable.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order', 'update'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        update: {
          enum: [
            'cancel',
            'close',
            'decline',
            'pause',
            'resume',
            'settle_inventory',
            'reclaim_expired',
            'refresh',
            'extend_expiry'
          ],
          description:
            'close resolves to maker cancel or fixed-recipient decline. Pause, resume, refresh, extend, cancel, and settle_inventory enforce the deployed maker role; reclaim_expired is permissionless and only releases expired inventory to its maker.'
        },
        expiresAt: { anyOf: [{ type: 'string', format: 'date-time' }, { type: 'null' }] }
      }
    },
    execute: safeExecute<OrderUpdateInput>((input) => service.prepareOrderUpdate(input))
  }
];
