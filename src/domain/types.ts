import type { OrderClassificationV1 } from '../shared/orderClassification.js';
import type {
  PrivacyBridgeDirection,
  PrivacyBridgePairId
} from '../shared/privacyBridge.js';

export const CHAINWHISPER_CHAIN_ID = 2_632_500;
export const MAX_ORDER_PAGE_SIZE = 20;

export type Address = `0x${string}`;
export type DecimalString = string;
export type OrderAccess = 'public' | 'unlisted' | 'direct';
export type AmountVisibility = 'visible' | 'private';
export type AssetKind = 'native' | 'erc20' | 'private-erc20';
export type OrderKind = 'trade' | 'recurring';
export type OrderRole = 'all' | 'maker' | 'recipient' | 'filler';
export type OrderHistoryRole = Exclude<OrderRole, 'all'>;
export type OrderStatus = 'open' | 'filled' | 'cancelled' | 'expired' | 'declined' | 'paused';
export type TradeSide = 'buy' | 'sell';

export type AssetReference =
  | string
  | {
      kind?: AssetKind;
      symbol?: string;
      address?: string;
    };

export type ResolvedAsset = {
  id: string;
  kind: AssetKind;
  symbol: string;
  decimals: number;
  address: Address | null;
  verified: true;
  publicCounterpart?: {
    symbol: string;
    address: Address;
  };
};

export type OrderIdentityInput =
  | {
      escrowContract: string;
      localId: string;
      handle?: never;
    }
  | {
      handle: string;
      escrowContract?: never;
      localId?: never;
    };

export type TrustedOrderIdentity = {
  escrowContract: Address;
  localId: string;
  handle: string;
};

export type SafeOrderSummary = {
  identity: TrustedOrderIdentity;
  orderType?: OrderClassificationV1;
  /**
   * A trusted read-only marker for orders created through a superseded
   * deployed route that cannot be represented by the canonical new-order
   * taxonomy. New creates must never select this compatibility mode.
   */
  legacyCompatibility?: {
    kind: 'standard-recipient-bound';
    displayType: 'Legacy one-off / fixed recipient / public terms';
    canonicalReplacementType: 'one-off.direct';
  };
  kind: OrderKind;
  status: OrderStatus;
  maker: Address;
  recipient: Address | null;
  access: OrderAccess;
  amountVisibility: AmountVisibility;
  offerAsset: ResolvedAsset;
  requestAsset: ResolvedAsset;
  offerAmount: DecimalString | null;
  requestAmount: DecimalString | null;
  remainingOfferAmount: DecimalString | null;
  remainingRequestAmount: DecimalString | null;
  price: DecimalString | null;
  priceBasis: 'quote_per_base';
  expiresAt: string | null;
  updatedAt: string;
  snapshotHash: string;
  relation?: {
    kind: 'primary' | 'counter' | 'replacement';
    parentOrder: TrustedOrderIdentity | null;
    rootOrder: TrustedOrderIdentity | null;
    replacesOrder: TrustedOrderIdentity | null;
    replacementOrder: TrustedOrderIdentity | null;
  };
  fillPolicy?: FillPolicy;
  directTerms?: {
    termsHash: `0x${string}` | null;
    hasTermsPayload: boolean;
    hasMakerAccessSecret: boolean;
    hasTakerAccessSecret: boolean;
    offerAmountPrivate: boolean;
    requestAmountPrivate: boolean;
  };
  recurring?: {
    baseAsset: ResolvedAsset;
    quoteAsset: ResolvedAsset;
    buyBaseAmount?: DecimalString | null;
    buyQuoteAmount?: DecimalString | null;
    sellBaseAmount?: DecimalString | null;
    sellQuoteAmount?: DecimalString | null;
    buyPrice: DecimalString | null;
    sellPrice: DecimalString | null;
    buyQuoteLiquidity: DecimalString | null;
    sellBaseLiquidity: DecimalString | null;
    buySideOpen: boolean;
    sellSideOpen: boolean;
    privateBaseInventory?: boolean;
    privateQuoteInventory?: boolean;
  };
};

export type ListOrdersInput = {
  wallet?: string;
  role?: OrderRole;
  kind?: OrderKind | 'all';
  status?: OrderStatus | 'all';
  access?: OrderAccess | 'all';
  baseAsset?: AssetReference;
  quoteAsset?: AssetReference;
  cursor?: string;
  limit?: number;
};

export type ListOrdersResult = {
  orders: SafeOrderSummary[];
  nextCursor: string | null;
  truncated: boolean;
};

export type RegistrySnapshot = {
  chainId: typeof CHAINWHISPER_CHAIN_ID;
  registryAddress: Address;
  snapshotHash: string;
  blockNumber: string;
  contracts: Readonly<Record<string, Address>>;
  recurringWritesEnabled: boolean;
  verifiedAt: string;
  warnings: string[];
};

export type DomainStatus = {
  service: 'chainwhisper-mcp';
  mode: 'keyless';
  chainId: typeof CHAINWHISPER_CHAIN_ID;
  ready: boolean;
  readOnly: boolean;
  registry: RegistrySnapshot;
  capabilities: {
    reads: true;
    priceReferences: true;
    unsignedPlanning: true;
    recurringWrites: boolean;
    privacyBridge?: boolean;
  };
};

export type RawPriceReference = {
  id: string;
  venue: 'chainwhisper' | 'carbon' | 'uniswap' | string;
  source: 'order' | 'market' | 'quote';
  baseAsset: ResolvedAsset;
  quoteAsset: ResolvedAsset;
  price: DecimalString;
  basis: 'quote_per_base' | 'base_per_quote';
  observedAt: string;
  expiresAt?: string | null;
  executable: boolean;
  liquidityChecked: boolean;
  canExecuteAmount?: boolean;
  executionPrice?: DecimalString | null;
  availableBaseAmount?: DecimalString | null;
  availableQuoteAmount?: DecimalString | null;
  order?: TrustedOrderIdentity;
  note?: string;
};

export type NormalizedPriceReference = Omit<RawPriceReference, 'basis'> & {
  basis: 'quote_per_base';
  originalBasis: RawPriceReference['basis'];
};

export type ComparePriceReferencesInput = {
  baseAsset: AssetReference;
  quoteAsset: AssetReference;
  side: TradeSide;
  amount?: DecimalString;
};

export type PriceRanking = {
  basis: 'quote_per_base';
  side: TradeSide;
  amount: DecimalString;
  rankedReferenceIds: string[];
  bestReferenceId: string;
  rationale: string;
};

export type ComparePriceReferencesResult = {
  pair: {
    baseAsset: ResolvedAsset;
    quoteAsset: ResolvedAsset;
    basis: 'quote_per_base';
  };
  side: TradeSide;
  amount: DecimalString | null;
  references: NormalizedPriceReference[];
  executableReferences: NormalizedPriceReference[];
  referenceOnly: NormalizedPriceReference[];
  ranking: PriceRanking | null;
  rankingUnavailableReason:
    | 'amount_not_supplied'
    | 'executable_liquidity_not_available'
    | 'no_compatible_references'
    | null;
};

export type FillPolicy = {
  partialFillsAllowed: boolean;
  minPartialFillBps: number;
  minRequestAmount: DecimalString | null;
  maxRequestAmountPerWallet: DecimalString | null;
  oneFillPerWallet: boolean;
};

export type SecretPolicy =
  | {
      kind: 'none';
    }
  | {
      kind: 'generate-local';
      share: 'encrypted-coti-message-only';
    }
  | {
      kind: 'recipient-bound';
      recipient: Address | null;
    }
  | {
      kind: 'resolve-from-local-vault';
      orderHandle: string;
    };

export type CreateTradeIntent = {
  action: 'create_trade';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  offerAsset: ResolvedAsset | null;
  requestAsset: ResolvedAsset | null;
  offerAmount: DecimalString | null;
  requestAmount: DecimalString | null;
  access: OrderAccess;
  recipient: Address | null;
  amountVisibility: AmountVisibility;
  expiresAt: string | null;
  fillPolicy: FillPolicy;
  secretPolicy: SecretPolicy;
};

export type CreateRecurringIntent = {
  action: 'create_recurring';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  baseAsset: ResolvedAsset | null;
  quoteAsset: ResolvedAsset | null;
  buyPrice: DecimalString | null;
  sellPrice: DecimalString | null;
  buyQuoteLiquidity: DecimalString | null;
  sellBaseLiquidity: DecimalString | null;
  access: OrderAccess;
  recipient: Address | null;
  amountVisibility: AmountVisibility;
  secretPolicy: SecretPolicy;
};

export type FillIntent = {
  action: 'fill';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  order: SafeOrderSummary;
  inputAmount: DecimalString | null;
  minOutputAmount: DecimalString | null;
  recurringSide: 'buy' | 'sell' | null;
  secretPolicy: SecretPolicy;
};

export type CounterIntent = {
  action: 'counter';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  order: SafeOrderSummary;
  offerAsset: ResolvedAsset;
  requestAsset: ResolvedAsset;
  offerAmount: DecimalString | null;
  requestAmount: DecimalString | null;
  expiresAt: string | null;
  recipient: Address;
  access: 'direct';
  amountVisibility: AmountVisibility;
  secretPolicy: SecretPolicy;
};

export type EditIntent = {
  action: 'edit';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  order: SafeOrderSummary;
  changes: {
    offerAmount?: DecimalString;
    requestAmount?: DecimalString;
    expiresAt?: string | null;
    partialFillsAllowed?: boolean;
    minPartialFillBps?: number;
    minRequestAmount?: DecimalString | null;
    maxRequestAmountPerWallet?: DecimalString | null;
    oneFillPerWallet?: boolean;
    buyPrice?: DecimalString;
    sellPrice?: DecimalString;
    addBuyQuoteLiquidity?: DecimalString;
    addSellBaseLiquidity?: DecimalString;
    removeBuyQuoteLiquidity?: DecimalString;
    removeSellBaseLiquidity?: DecimalString;
    /**
     * Requests signer-local entry of the complete resulting one-off terms.
     * No confidential amount is accepted in the MCP argument.
     */
    replaceConfidentialTerms?: boolean;
    /**
     * Requests signer-local entry of recurring private inventory deltas.
     */
    adjustPrivateLiquidity?: boolean;
  };
};

export type OrderUpdateKind =
  | 'cancel'
  | 'close'
  | 'decline'
  | 'pause'
  | 'resume'
  | 'settle_inventory'
  | 'reclaim_expired'
  | 'refresh'
  | 'extend_expiry';

export type OrderUpdateIntent = {
  action: 'order_update';
  orderType?: OrderClassificationV1;
  wallet: Address | null;
  order: SafeOrderSummary;
  update: OrderUpdateKind;
  expiresAt: string | null;
};

export type PrivacyBridgeIntent = {
  action: 'privacy_bridge';
  wallet: Address | null;
  pair: PrivacyBridgePairId;
  direction: PrivacyBridgeDirection;
  publicAsset: ResolvedAsset | null;
  privateAsset: ResolvedAsset | null;
  amount: DecimalString | null;
};

export type DomainIntent =
  | CreateTradeIntent
  | CreateRecurringIntent
  | FillIntent
  | CounterIntent
  | EditIntent
  | OrderUpdateIntent
  | PrivacyBridgeIntent;

export type MissingDetail = {
  field: string;
  reason: string;
  editable: true;
};

export type PlanStep = {
  id: string;
  kind: 'approval' | 'protocol';
  contract: Address;
  description: string;
  nativeValue: string;
  gasCap?: string;
  token?: Address;
  amount?: DecimalString;
  approvalScheme?: 'erc20-exact' | 'erc20-reset' | 'coti-private-exact';
  privateInputPlaceholders?: PlanPrivateInputPlaceholder[];
  privateArtifactGroups?: PlanPrivateArtifactGroup[];
  /**
   * An adapter-created, registry-allowlisted selector and arguments. Public tool
   * input can never provide this object.
   */
  encoding?: {
    selector: `0x${string}`;
    arguments: unknown[];
  };
};

export type PlanPrivateInputPlaceholder = {
  id: string;
  kind:
    | 'itUint256'
    | 'access-secret'
    | 'encrypted-recovery-note';
  source: 'wallet-aes' | 'local-vault' | 'generated-local';
  decimalValue?: string;
  jsonPointer: string;
};

export type PlanPrivateArtifactValueSource =
  | 'intent-sell-amount'
  | 'intent-buy-amount'
  | 'trusted-order-visible-amount'
  | 'recurring-sell-base-liquidity'
  | 'recurring-buy-quote-liquidity'
  | 'signer-elicitation'
  | 'local-order-vault'
  | 'generated-local'
  | 'constant-zero';

export type PlanPrivateArtifactGroup = {
  id: string;
  recipe:
    | 'direct-order-v1'
    | 'direct-counter-v1'
    | 'direct-edit-v1'
    | 'private-liquidity-v1'
    | 'private-liquidity-edit-v1'
    | 'private-recurring-v1'
    | 'private-recurring-fill-v1'
    | 'recurring-edit-v1'
    | 'private-fill-v1'
    | 'coti-private-exact-allowance-v1';
  values: Array<{
    id: string;
    kind: 'uint256' | 'access-secret';
    source: PlanPrivateArtifactValueSource;
    asset?: ResolvedAsset;
    allowZero?: boolean;
  }>;
  outputs: Array<{
    kind:
      | 'uint256'
      | 'itUint256'
      | 'keccak256'
      | 'direct-terms-v1'
      | 'terms-hash-v1'
      | 'trade-recovery-v1'
      | 'recurring-recovery-v1'
      | 'coti-private-exact-allowance';
    valueId?: string;
    jsonPointer: string;
  }>;
  context?: Record<string, string | boolean | null>;
};

export type SimulationResult = {
  ok: boolean;
  /**
   * True when signer-local confidential values must be materialized before the
   * exact calldata can be simulated. Public preflight may still have passed.
   */
  deferredPrivateArtifacts?: boolean;
  blockNumber: string;
  expectedResult: string;
  warnings: string[];
  errorCode?: string;
};

export type DomainExecutionPlan = {
  wallet: Address;
  registry: RegistrySnapshot;
  steps: PlanStep[];
  fee: {
    token: 'native';
    /** Fee charged by this exact action. */
    amount: string;
    /** Current live fee configured on the target contract. */
    scheduleAmount: string;
    recipient: Address;
  };
  exactNativeValue: string;
  gasCap: string;
  simulation: SimulationResult;
  expiresAt: string;
  intentMetadata?: Record<string, string | number | boolean | null>;
};

export type PreparedEnvelope = {
  version: 'ActionEnvelopeV1';
  operationId: string;
  operationHash: string;
  expiresAt: string;
  summary: string;
  payload: unknown;
};

export type PrepareResult = {
  status: 'ready' | 'needs_input' | 'unsupported';
  intent: DomainIntent;
  missing: MissingDetail[];
  warnings: string[];
  envelope: PreparedEnvelope | null;
  reason?: string;
};

export type DomainEnvelopeFactory = {
  create(intent: DomainIntent, execution: DomainExecutionPlan): Promise<PreparedEnvelope>;
};

export type DomainGateway = {
  getStatus(): Promise<DomainStatus>;
  isTrustedEscrow(address: Address): Promise<boolean>;
  resolveAsset(reference: AssetReference): Promise<ResolvedAsset | null>;
  listOrders(input: {
    wallet: Address | null;
    role: OrderRole;
    kind: OrderKind | 'all';
    status: OrderStatus | 'all';
    access: OrderAccess | 'all';
    baseAsset: ResolvedAsset | null;
    quoteAsset: ResolvedAsset | null;
    cursor: string | null;
    limit: number;
  }): Promise<ListOrdersResult>;
  getOrder(identity: OrderIdentityInput): Promise<SafeOrderSummary | null>;
  getPriceReferences(input: {
    baseAsset: ResolvedAsset;
    quoteAsset: ResolvedAsset;
    side: TradeSide;
    amount: DecimalString | null;
  }): Promise<RawPriceReference[]>;
  getPrivacyBridgeStatus?(
    input: PrivacyBridgeStatusInput
  ): Promise<PrivacyBridgeStatus>;
  buildExecutionPlan(intent: DomainIntent): Promise<DomainExecutionPlan>;
};

export type ToolFailureCode =
  | 'invalid_input'
  | 'not_found'
  | 'unsupported'
  | 'provider_error'
  | 'internal_error';

export type ToolResult<T> =
  | {
      ok: true;
      data: T;
    }
  | {
      ok: false;
      error: {
        code: ToolFailureCode;
        message: string;
        details?: Array<{ field: string; message: string }>;
      };
    };

export type CreateTradeInput = {
  wallet?: string;
  orderType?: OrderClassificationV1['id'];
  offerAsset?: AssetReference;
  requestAsset?: AssetReference;
  offerAmount?: DecimalString;
  requestAmount?: DecimalString;
  access?: OrderAccess;
  recipient?: string;
  amountVisibility?: AmountVisibility;
  expiresAt?: string | null;
  fillPolicy?: Partial<FillPolicy>;
};

export type CreateRecurringInput = {
  wallet?: string;
  orderType?: OrderClassificationV1['id'];
  baseAsset?: AssetReference;
  quoteAsset?: AssetReference;
  buyPrice?: DecimalString;
  sellPrice?: DecimalString;
  buyQuoteLiquidity?: DecimalString;
  sellBaseLiquidity?: DecimalString;
  access?: OrderAccess;
  recipient?: string;
  amountVisibility?: AmountVisibility;
};

export type FillInput = {
  wallet?: string;
  order: OrderIdentityInput;
  inputAmount?: DecimalString;
  minOutputAmount?: DecimalString;
  recurringSide?: 'buy' | 'sell';
};

export type CounterInput = {
  wallet?: string;
  order: OrderIdentityInput;
  offerAmount?: DecimalString;
  requestAmount?: DecimalString;
  expiresAt?: string | null;
};

export type EditInput = {
  wallet?: string;
  order: OrderIdentityInput;
  changes?: EditIntent['changes'];
};

export type OrderUpdateInput = {
  wallet?: string;
  order: OrderIdentityInput;
  update: OrderUpdateKind;
  expiresAt?: string | null;
};

export type PrivacyBridgeInput = {
  wallet?: string;
  pair: PrivacyBridgePairId;
  direction: PrivacyBridgeDirection;
  amount?: DecimalString;
};

export type PrivacyBridgeStatusInput = {
  wallet?: string;
  pair: PrivacyBridgePairId;
  direction?: PrivacyBridgeDirection;
  amount?: DecimalString;
};

export type PrivacyBridgeStatus = {
  pair: PrivacyBridgePairId;
  provider: 'official-coti' | 'chainwhisper';
  bridge: Address;
  publicAsset: ResolvedAsset;
  privateAsset: ResolvedAsset;
  ready: boolean;
  paused: boolean;
  depositEnabled: boolean;
  privatePublicAmountsEnabled: boolean;
  blacklisted: boolean | null;
  direction: PrivacyBridgeDirection | null;
  amount: DecimalString | null;
  amountAtomic: string | null;
  minAmountAtomic: string | null;
  maxAmountAtomic: string | null;
  portalFeeAtomic: string | null;
  cotiOracleTimestamp: string | null;
  tokenOracleTimestamp: string | null;
  blockTimestamp: string | null;
  warnings: string[];
};

export type DomainToolDefinition = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  execute(input: unknown): Promise<ToolResult<unknown>>;
};
