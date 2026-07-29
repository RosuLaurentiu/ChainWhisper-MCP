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
  PrivacyBridgeInput,
  PrivacyBridgeStatusInput,
  ToolResult
} from './types.js';
import { assertPlainRecord } from './validation.js';
import { toolFailure } from './errors.js';
import { ORDER_CLASSIFICATION_IDS_V1 } from '../shared/orderClassification.js';
import { MAX_DECIMAL_INPUT_LENGTH } from './decimal.js';

const addressSchema = { type: 'string', pattern: '^0x[a-fA-F0-9]{40}$' };
const decimalSchema = {
  type: 'string',
  maxLength: MAX_DECIMAL_INPUT_LENGTH,
  pattern: '^(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?$',
  description: 'A base-10 decimal string. JSON numbers are not accepted.'
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
const oneOffOrderTypes = ORDER_CLASSIFICATION_IDS_V1.filter((id) =>
  id.startsWith('one-off.')
);
const recurringOrderTypes = ORDER_CLASSIFICATION_IDS_V1.filter((id) =>
  id.startsWith('recurring.')
);
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
      'List every canonical ChainWhisper order type, its access model, term and liquidity visibility, fill style, and whether the deployed route is currently safe to execute. Call this before asking the user to choose an orderType.',
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
            orderTypes: ORDER_TYPE_CATALOG
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
        'Validate and prepare an audited ChainWhisper one-off OTC order. Select an explicit orderType so public, unlisted, direct-recipient, and private-liquidity routes cannot be confused. Hidden amounts stay in the local signer. This tool never signs or submits.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['orderType'],
      properties: {
        wallet: addressSchema,
        orderType: {
          enum: oneOffOrderTypes,
          description:
            'Required. Use chainwhisper_order_types to explain the exact listing, recipient, terms, and liquidity privacy before the user chooses.'
        },
        offerAsset: assetSchema,
        requestAsset: assetSchema,
        offerAmount: {
          ...decimalSchema,
          description:
            'Include only for a public amount. Omit for every private-liquidity orderType and when an unlisted or Direct order offers a private token; the signer collects confidential amounts locally.'
        },
        requestAmount: {
          ...decimalSchema,
          description:
            'Include only for a public amount. Omit for every private-liquidity orderType and when an unlisted or Direct order requests a private token; the signer collects confidential amounts locally.'
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
    execute: safeExecute<CreateTradeInput>((input) => service.prepareCreateTrade(input))
  },
  {
      name: 'chainwhisper_prepare_create_recurring',
      description:
        'Validate and prepare a public or fixed-recipient recurring ChainWhisper order with an explicit orderType. Visible and private-token inventory routes are supported. Prices use quote per base.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['orderType'],
      properties: {
        wallet: addressSchema,
        orderType: {
          enum: recurringOrderTypes,
          description:
            'Required. Use chainwhisper_order_types before the user chooses between the actual public and fixed-recipient recurring variants.'
        },
        baseAsset: assetSchema,
        quoteAsset: assetSchema,
        buyPrice: decimalSchema,
        sellPrice: decimalSchema,
        buyQuoteLiquidity: {
          ...decimalSchema,
          description:
            'Include when the quote-token inventory side is public. Omit when quoteAsset is private for a private-liquidity orderType; the signer collects that side locally.'
        },
        sellBaseLiquidity: {
          ...decimalSchema,
          description:
            'Include when the base-token inventory side is public. Omit when baseAsset is private for a private-liquidity orderType; the signer collects that side locally.'
        },
        recipient: addressSchema
      }
    },
    execute: safeExecute<CreateRecurringInput>((input) => service.prepareCreateRecurring(input))
  },
  {
    name: 'chainwhisper_prepare_fill',
    description:
      'Prepare a fill for an existing trusted ChainWhisper order. Public visible amounts remain planner input. Only confidential hidden-liquidity or Direct private-token inputs are collected inside the signer.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        inputAmount: {
          ...decimalSchema,
          description:
            'Planner input for publicly visible payment amounts, including private-token amounts on public Standard and explicitly labeled legacy Standard orders. Omit only for hidden-liquidity/private-inventory or Direct encrypted private-token payments; the signer collects those locally.'
        },
        minOutputAmount: {
          ...decimalSchema,
          description:
            'Visible orders only. Confidential output limits stay inside the local signer.'
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
      'Prepare a canonical Direct counterorder against a trusted one-off order. Counter terms are recipient-bound to the original maker; confidential token amounts stay in the local signer. Existing recipient-bound Standard orders use an explicitly labeled legacy compatibility route and cannot be confused with newly created Direct orders.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['order'],
      properties: {
        wallet: addressSchema,
        order: orderSchema,
        offerAmount: {
          ...decimalSchema,
          description:
            'Include for public assets and for visibly bound private-token amounts when superseding an explicitly labeled legacy Standard counter. Omit for confidential Direct counter amounts; the signer collects those locally.'
        },
        requestAmount: {
          ...decimalSchema,
          description:
            'Include for public assets and for visibly bound private-token amounts when superseding an explicitly labeled legacy Standard counter. Omit for confidential Direct counter amounts; the signer collects those locally.'
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
