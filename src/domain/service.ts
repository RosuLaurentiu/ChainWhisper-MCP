import {
  canonicalDecimal,
  compareDecimals,
  divideDecimals,
  invertDecimal,
  isPositiveDecimal,
  multiplyDecimals,
  parseDecimal
} from './decimal.js';
import { DomainInputError, toolFailure } from './errors.js';
import {
  MARKET_REFERENCE_MAX_AGE_MS,
  MARKET_REFERENCE_MAX_FUTURE_SKEW_MS
} from '../shared/marketReference.js';
import { deriveOrderClassificationV1 } from '../shared/orderClassification.js';
import type {
  Address,
  ComparePriceReferencesInput,
  ComparePriceReferencesResult,
  CounterInput,
  CounterIntent,
  CreateRecurringInput,
  CreateRecurringIntent,
  CreateTradeInput,
  CreateTradeIntent,
  DomainEnvelopeFactory,
  DomainExecutionPlan,
  DomainGateway,
  DomainIntent,
  DomainStatus,
  EditInput,
  EditIntent,
  FillInput,
  FillIntent,
  ListOrdersInput,
  ListOrdersResult,
  MarketReferencePriceInput,
  MissingDetail,
  NormalizedPriceReference,
  OrderIdentityInput,
  OrderUpdateInput,
  OrderUpdateIntent,
  PrivacyBridgeInput,
  PrivacyBridgeIntent,
  PrivacyBridgeStatus,
  PrivacyBridgeStatusInput,
  PrivateAmountMode,
  PrepareSwapInput,
  PrepareSwapResult,
  PrepareResult,
  RawPriceReference,
  ResolvedAsset,
  SafeOrderSummary,
  SecretPolicy,
  SwapSelection,
  ToolResult
} from './types.js';
import { privacyBridgePair } from '../shared/privacyBridge.js';
import {
  assertDistinctAssets,
  assertAllowedKeys,
  assertTrustedOrder,
  normalizeAccess,
  normalizeAddress,
  normalizeAmountVisibility,
  normalizeExpiry,
  normalizeFillPolicy,
  normalizeNonNegativeAmount,
  normalizeOrderIdentity,
  normalizePositiveAmount,
  rejectSensitiveOrArbitraryInput,
  requireMissing,
  resolveAsset
} from './validation.js';
import { CHAINWHISPER_CHAIN_ID, MAX_ORDER_PAGE_SIZE } from './types.js';

const safeString = (value: unknown, fallback = ''): string => (typeof value === 'string' ? value : fallback);
const resolveCreateAxes = (
  input: {
    access?: unknown;
    liquidityVisibility?: unknown;
  }
): {
  access: 'public' | 'unlisted' | 'direct';
  amountVisibility: 'visible' | 'private';
} => ({
  access: normalizeAccess(input.access),
  amountVisibility: normalizeAmountVisibility(input.liquidityVisibility)
});

const rejectSignerLocalAmount = (
  value: unknown,
  field: string,
  description: string
): void => {
  if (value === undefined) return;
  throw new DomainInputError(
    `${description} must be entered only in the local signer confirmation.`,
    [
      {
        field,
        message:
          'Remove this confidential amount from the keyless MCP request; the signer collects it locally.'
      }
    ]
  );
};

const normalizePrivateAmountMode = (
  value: unknown
): PrivateAmountMode => {
  if (value === undefined || value === null || value === '') {
    return 'signer-input';
  }
  if (value !== 'signer-input' && value !== 'agent-provided') {
    throw new DomainInputError(
      'privateAmountMode must be signer-input or agent-provided.',
      [
        {
          field: 'privateAmountMode',
          message:
            'Use signer-input for local entry, or agent-provided to bind agent-visible private values for local confirmation or an active policy with agentVisiblePrivateAmounts enabled.'
        }
      ]
    );
  }
  return value;
};

const sanitizeAsset = (asset: ResolvedAsset): ResolvedAsset => ({
  id: asset.id,
  kind: asset.kind,
  symbol: asset.symbol,
  decimals: asset.decimals,
  address: asset.address,
  verified: true,
  ...(asset.publicCounterpart
    ? {
        publicCounterpart: {
          symbol: asset.publicCounterpart.symbol,
          address: asset.publicCounterpart.address
        }
      }
    : {})
});

const sanitizeIdentity = (identity: SafeOrderSummary['identity']): SafeOrderSummary['identity'] => ({
  escrowContract: identity.escrowContract,
  localId: identity.localId,
  handle: identity.handle
});

const sanitizeOrder = (order: SafeOrderSummary): SafeOrderSummary => ({
  identity: sanitizeIdentity(order.identity),
  ...(order.orderType ? { orderType: order.orderType } : {}),
  ...(order.legacyCompatibility?.kind ===
    'standard-recipient-bound'
    ? {
        legacyCompatibility: {
          kind: 'standard-recipient-bound' as const,
          displayType:
            'Legacy one-off / fixed recipient / public terms' as const,
          canonicalReplacementType: 'one-off.direct' as const
        }
      }
    : {}),
  kind: order.kind,
  status: order.status,
  maker: order.maker,
  recipient: order.recipient,
  access: order.access,
  amountVisibility: order.amountVisibility,
  offerAsset: sanitizeAsset(order.offerAsset),
  requestAsset: sanitizeAsset(order.requestAsset),
  offerAmount: order.amountVisibility === 'private' ? null : order.offerAmount,
  requestAmount: order.amountVisibility === 'private' ? null : order.requestAmount,
  remainingOfferAmount: order.amountVisibility === 'private' ? null : order.remainingOfferAmount,
  remainingRequestAmount: order.amountVisibility === 'private' ? null : order.remainingRequestAmount,
  price: order.price,
  priceBasis: 'quote_per_base',
  expiresAt: order.expiresAt,
  updatedAt: order.updatedAt,
  snapshotHash: order.snapshotHash,
  ...(order.relation
    ? {
        relation: {
          kind: order.relation.kind,
          parentOrder: order.relation.parentOrder
            ? sanitizeIdentity(order.relation.parentOrder)
            : null,
          rootOrder: order.relation.rootOrder
            ? sanitizeIdentity(order.relation.rootOrder)
            : null,
          replacesOrder: order.relation.replacesOrder
            ? sanitizeIdentity(order.relation.replacesOrder)
            : null,
          replacementOrder: order.relation.replacementOrder
            ? sanitizeIdentity(order.relation.replacementOrder)
            : null
        }
      }
    : {}),
  ...(order.fillPolicy ? { fillPolicy: { ...order.fillPolicy } } : {}),
  ...(order.directTerms
    ? { directTerms: { ...order.directTerms } }
    : {}),
  ...(order.recurring
    ? {
        recurring: {
          baseAsset: sanitizeAsset(order.recurring.baseAsset),
          quoteAsset: sanitizeAsset(order.recurring.quoteAsset),
          buyBaseAmount: order.recurring.buyBaseAmount,
          buyQuoteAmount: order.recurring.buyQuoteAmount,
          sellBaseAmount: order.recurring.sellBaseAmount,
          sellQuoteAmount: order.recurring.sellQuoteAmount,
          buyPrice: order.recurring.buyPrice,
          sellPrice: order.recurring.sellPrice,
          buyQuoteLiquidity:
            order.amountVisibility === 'private' ? null : order.recurring.buyQuoteLiquidity,
          sellBaseLiquidity:
            order.amountVisibility === 'private' ? null : order.recurring.sellBaseLiquidity,
          buySideOpen: order.recurring.buySideOpen,
          sellSideOpen: order.recurring.sellSideOpen,
          privateBaseInventory: order.recurring.privateBaseInventory,
          privateQuoteInventory: order.recurring.privateQuoteInventory
        }
      }
    : {})
});

const secretPolicyFor = (
  access: CreateTradeIntent['access'],
  recipient: Address | null,
  orderHandle?: string
): SecretPolicy => {
  if (orderHandle) {
    return { kind: 'resolve-from-local-vault', orderHandle };
  }
  if (access === 'unlisted') {
    return { kind: 'generate-local', share: 'encrypted-coti-message-only' };
  }
  if (access === 'direct') {
    return { kind: 'recipient-bound', recipient };
  }
  return { kind: 'none' };
};

const normalizeWallet = (value: unknown): Address | null => normalizeAddress(value, 'wallet', false);

const sameAddress = (left: Address | null, right: Address | null): boolean =>
  Boolean(left && right && left.toLowerCase() === right.toLowerCase());

const assertLifecycleState = (
  order: SafeOrderSummary,
  update: OrderUpdateIntent['update']
): void => {
  const tradeOpenState = order.status === 'open' || order.status === 'expired';
  if (update === 'cancel') {
    const canCancel =
      order.kind === 'recurring'
        ? order.status === 'open' || order.status === 'paused'
        : tradeOpenState;
    if (!canCancel) {
      throw new DomainInputError(
        'Only an open trade, or an active or paused recurring order, can be cancelled.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'decline') {
    if (order.kind !== 'trade' || !tradeOpenState || !order.recipient) {
      throw new DomainInputError(
        'Decline is only available for an open fixed-recipient one-off order.',
        [{ field: 'update', message: 'This order cannot be declined.' }]
      );
    }
    return;
  }
  if (update === 'pause') {
    if (order.kind !== 'recurring' || order.status !== 'open') {
      throw new DomainInputError(
        'Pause is only available for an active recurring order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'resume') {
    if (order.kind !== 'recurring' || order.status !== 'paused') {
      throw new DomainInputError(
        'Resume is only available for a paused recurring order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'settle_inventory') {
    if (order.kind !== 'recurring' || order.status !== 'cancelled') {
      throw new DomainInputError(
        'Inventory settlement is only available for a cancelled recurring order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'reclaim_expired') {
    if (order.kind !== 'trade' || order.status !== 'expired') {
      throw new DomainInputError(
        'Expired-offer reclaim is only available for an expired one-off order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'refresh') {
    if (order.kind !== 'trade' || order.status !== 'open') {
      throw new DomainInputError(
        'Refresh is only available for an open one-off order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
    return;
  }
  if (update === 'extend_expiry') {
    if (order.kind !== 'trade' || order.status !== 'open') {
      throw new DomainInputError(
        'Expiry extension is only available for an open one-off order.',
        [{ field: 'update', message: `The order is currently ${order.status}.` }]
      );
    }
  }
};

const assertLifecycleRole = (
  order: SafeOrderSummary,
  wallet: Address,
  update: OrderUpdateIntent['update']
): void => {
  if (update === 'reclaim_expired') return;
  if (update === 'decline') {
    if (!sameAddress(wallet, order.recipient)) {
      throw new DomainInputError(
        'Only the fixed recipient can decline this order.',
        [{ field: 'wallet', message: 'Choose the order recipient wallet.' }]
      );
    }
    return;
  }
  if (!sameAddress(wallet, order.maker)) {
    throw new DomainInputError(
      `Only the maker can ${update.replaceAll('_', ' ')} this order.`,
      [{ field: 'wallet', message: 'Choose the order maker wallet.' }]
    );
  }
};

const assertLifecycleContract = (
  order: SafeOrderSummary,
  update: OrderUpdateIntent['update'],
  status: DomainStatus
): void => {
  const target = order.identity.escrowContract.toLowerCase();
  const standard = status.registry.contracts.standardEscrow?.toLowerCase();
  const privateEscrow =
    status.registry.contracts.privateEscrow?.toLowerCase();
  if (
    update === 'refresh' &&
    target !== standard &&
    target !== privateEscrow
  ) {
    throw new DomainInputError(
      'Refresh is only deployed for standard or private-liquidity one-off orders.',
      [{ field: 'update', message: 'This escrow does not expose refreshTrade.' }]
    );
  }
  if (update === 'extend_expiry' && target !== standard) {
    throw new DomainInputError(
      'Expiry extension is only deployed for standard public one-off orders.',
      [
        {
          field: 'update',
          message: 'This escrow does not expose extendTradeExpiry.'
        }
      ]
    );
  }
};

const validatePlan = (intent: DomainIntent, plan: DomainExecutionPlan): void => {
  if (!intent.wallet || plan.wallet.toLowerCase() !== intent.wallet.toLowerCase()) {
    throw new DomainInputError('The execution plan wallet does not match the requested wallet.', [], 'provider_error');
  }
  if (plan.registry.chainId !== CHAINWHISPER_CHAIN_ID) {
    throw new DomainInputError('The execution plan targets the wrong chain.', [], 'provider_error');
  }
  if (!Array.isArray(plan.steps) || plan.steps.length === 0) {
    throw new DomainInputError('The provider did not produce an executable ChainWhisper plan.', [], 'provider_error');
  }
  for (const step of plan.steps) {
    if (step.kind !== 'approval' && step.kind !== 'protocol') {
      throw new DomainInputError('The provider produced an unsupported transaction step.', [], 'provider_error');
    }
    if (step.kind === 'approval') {
      const privateExact =
        step.approvalScheme === 'coti-private-exact';
      if (privateExact) {
        const committedPrivateAmount =
          step.amount === '0' &&
          step.privateArtifactGroups?.some(
            (group) =>
              group.recipe ===
              'coti-private-exact-allowance-v1',
          );
        if (!committedPrivateAmount) {
          throw new DomainInputError(
            'Private approval steps must hide their public amount and commit an exact signer-local allowance artifact.',
            [],
            'provider_error'
          );
        }
      } else if (
        step.approvalScheme !== 'erc20-reset' &&
        (!step.amount || step.amount === '0')
      ) {
        throw new DomainInputError(
          'Approval steps must use the exact positive amount.',
          [],
          'provider_error'
        );
      }
    }
  }
};

const normalizeReference = (
  reference: RawPriceReference,
  baseAsset: ResolvedAsset,
  quoteAsset: ResolvedAsset
): NormalizedPriceReference | null => {
  const direct =
    reference.baseAsset.id === baseAsset.id && reference.quoteAsset.id === quoteAsset.id;
  const reversed =
    reference.baseAsset.id === quoteAsset.id && reference.quoteAsset.id === baseAsset.id;
  if (!direct && !reversed) return null;
  if (!isPositiveDecimal(reference.price)) return null;
  const observedAt =
    typeof reference.observedAt === 'string'
      ? Date.parse(reference.observedAt)
      : reference.observedAt === null
        ? null
        : Number.NaN;
  const expiresAt =
    reference.expiresAt === undefined || reference.expiresAt === null
      ? null
      : Date.parse(reference.expiresAt);
  if (
    (observedAt !== null && !Number.isFinite(observedAt)) ||
    (expiresAt !== null && !Number.isFinite(expiresAt))
  ) {
    return null;
  }

  const invert = direct
    ? reference.basis === 'base_per_quote'
    : reference.basis === 'quote_per_base';
  const normalizePrice = (value: string | null | undefined): string | null => {
    if (!value || !isPositiveDecimal(value)) return null;
    return invert ? invertDecimal(value) : canonicalDecimal(value);
  };

  return {
    id: reference.id,
    venue: reference.venue,
    source: reference.source,
    baseAsset: sanitizeAsset(baseAsset),
    quoteAsset: sanitizeAsset(quoteAsset),
    price: normalizePrice(reference.price)!,
    basis: 'quote_per_base',
    originalBasis: reference.basis,
    observedAt: reference.observedAt,
    expiresAt: reference.expiresAt ?? null,
    executable: reference.executable,
    liquidityChecked: reference.liquidityChecked,
    canExecuteAmount: reference.canExecuteAmount,
    executionPrice: normalizePrice(reference.executionPrice),
    availableBaseAmount: reversed
      ? reference.availableQuoteAmount ?? null
      : reference.availableBaseAmount ?? null,
    availableQuoteAmount: reversed
      ? reference.availableBaseAmount ?? null
      : reference.availableQuoteAmount ?? null,
    ...(reference.order ? { order: sanitizeIdentity(reference.order) } : {}),
    ...(reference.note ? { note: reference.note } : {})
  };
};

const rankingPrice = (reference: NormalizedPriceReference): string =>
  reference.executionPrice ?? reference.price;

const referenceObservationTime = (
  reference: NormalizedPriceReference
): number =>
  reference.observedAt === null
    ? Number.NEGATIVE_INFINITY
    : Date.parse(reference.observedAt);

const sortExecutableReferences = (
  references: NormalizedPriceReference[],
  side: ComparePriceReferencesInput['side']
): NormalizedPriceReference[] =>
  [...references].sort((left, right) => {
    const priceOrder = compareDecimals(rankingPrice(left), rankingPrice(right));
    if (priceOrder !== 0) return side === 'buy' ? priceOrder : -priceOrder;
    const timeOrder =
      referenceObservationTime(right) - referenceObservationTime(left);
    return timeOrder || left.id.localeCompare(right.id);
  });

const decimalToAtomic = (value: string, decimals: number): bigint | null => {
  const parsed = parseDecimal(value);
  if (!parsed || parsed.coefficient <= 0n || parsed.scale > decimals) {
    return null;
  }
  return parsed.coefficient * 10n ** BigInt(decimals - parsed.scale);
};

type TimestampedPriceReference = NormalizedPriceReference & {
  observedAt: string;
};

const isFreshMarketReference = (
  reference: NormalizedPriceReference,
  now: number
): reference is TimestampedPriceReference => {
  if (reference.observedAt === null) return false;
  const observedAt = Date.parse(reference.observedAt);
  const expiresAt = reference.expiresAt
    ? Date.parse(reference.expiresAt)
    : null;
  return (
    Number.isFinite(observedAt) &&
    observedAt <= now + MARKET_REFERENCE_MAX_FUTURE_SKEW_MS &&
    now - observedAt <= MARKET_REFERENCE_MAX_AGE_MS &&
    (expiresAt === null || (Number.isFinite(expiresAt) && expiresAt > now))
  );
};

const atomicToDecimal = (value: bigint, decimals: number): string => {
  const digits = value.toString().padStart(decimals + 1, '0');
  return canonicalDecimal(
    decimals === 0
      ? digits
      : `${digits.slice(0, -decimals)}.${digits.slice(-decimals)}`
  );
};

const floorDecimalToScale = (value: string, decimals: number): string => {
  const parsed = parseDecimal(value);
  if (!parsed || parsed.coefficient <= 0n) {
    throw new DomainInputError('The market reference price is invalid.', [], 'provider_error');
  }
  const coefficient =
    parsed.scale <= decimals
      ? parsed.coefficient * 10n ** BigInt(decimals - parsed.scale)
      : parsed.coefficient / 10n ** BigInt(parsed.scale - decimals);
  if (coefficient <= 0n) {
    throw new DomainInputError(
      'The market reference price is below the supported token precision.',
      [],
      'provider_error'
    );
  }
  return atomicToDecimal(coefficient, decimals);
};

const ceilDecimalToScale = (value: string, decimals: number): string => {
  const parsed = parseDecimal(value);
  if (!parsed || parsed.coefficient <= 0n) {
    throw new DomainInputError('The market reference price is invalid.', [], 'provider_error');
  }
  if (parsed.scale <= decimals) {
    return atomicToDecimal(
      parsed.coefficient * 10n ** BigInt(decimals - parsed.scale),
      decimals
    );
  }
  const divisor = 10n ** BigInt(parsed.scale - decimals);
  return atomicToDecimal(
    (parsed.coefficient + divisor - 1n) / divisor,
    decimals
  );
};

const basisPointFactor = (offsetBps: number): string => {
  if (
    !Number.isInteger(offsetBps) ||
    offsetBps < -9_999 ||
    offsetBps > 10_000
  ) {
    throw new DomainInputError(
      'A market price offset must be an integer from -9,999 to 10,000 basis points.',
      [
        {
          field: 'offsetBps',
          message: 'Use -1000 for 10% below or 1000 for 10% above.'
        }
      ]
    );
  }
  return atomicToDecimal(BigInt(10_000 + offsetBps), 4);
};

type NormalizedRecurringPriceInput =
  | { kind: 'exact'; price: string }
  | { kind: 'market'; offsetBps: number }
  | null;

const normalizeRecurringPriceInput = (
  value: unknown,
  field: 'buyPrice' | 'sellPrice',
  decimals: number
): NormalizedRecurringPriceInput => {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'string') {
    return {
      kind: 'exact',
      price: normalizePositiveAmount(value, field, decimals, true)!
    };
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DomainInputError(
      `${field} must be an exact decimal or a market-reference offset.`,
      [{ field, message: 'Use a decimal string or { reference: "market", offsetBps }.' }]
    );
  }
  assertAllowedKeys(value, ['reference', 'offsetBps'], `input.${field}`);
  const price = value as Partial<MarketReferencePriceInput>;
  if (price.reference !== 'market') {
    throw new DomainInputError(
      `${field} has an unsupported price reference.`,
      [{ field: `${field}.reference`, message: 'Use market.' }]
    );
  }
  basisPointFactor(price.offsetBps as number);
  return { kind: 'market', offsetBps: price.offsetBps! };
};

type SwapCandidate = {
  order: SafeOrderSummary;
  source: SwapSelection['source'];
  recurringSide: SwapSelection['recurringSide'];
  unitSell: bigint;
  unitBuy: bigint;
  maxSell: bigint | null;
  maxBuy: bigint;
};

const recurringCandidate = (
  order: SafeOrderSummary,
  sellAsset: ResolvedAsset,
  buyAsset: ResolvedAsset
): SwapCandidate | null => {
  const recurring = order.recurring;
  if (!recurring || order.kind !== 'recurring') return null;
  const baseIsBuy =
    recurring.baseAsset.id === buyAsset.id &&
    recurring.quoteAsset.id === sellAsset.id;
  const baseIsSell =
    recurring.baseAsset.id === sellAsset.id &&
    recurring.quoteAsset.id === buyAsset.id;
  if (!baseIsBuy && !baseIsSell) return null;
  const recurringSide = baseIsBuy ? 'buy' : 'sell';
  if (
    (recurringSide === 'buy' && !recurring.sellSideOpen) ||
    (recurringSide === 'sell' && !recurring.buySideOpen)
  ) {
    return null;
  }
  const unitSellText = baseIsBuy
    ? recurring.sellQuoteAmount
    : recurring.buyBaseAmount;
  const unitBuyText = baseIsBuy
    ? recurring.sellBaseAmount
    : recurring.buyQuoteAmount;
  const unitSell =
    (unitSellText && decimalToAtomic(unitSellText, sellAsset.decimals)) ??
    (baseIsBuy && recurring.sellPrice
      ? decimalToAtomic(
          floorDecimalToScale(recurring.sellPrice, sellAsset.decimals),
          sellAsset.decimals
        )
      : 10n ** BigInt(sellAsset.decimals));
  const unitBuy =
    (unitBuyText && decimalToAtomic(unitBuyText, buyAsset.decimals)) ??
    (baseIsSell && recurring.buyPrice
      ? decimalToAtomic(
          floorDecimalToScale(recurring.buyPrice, buyAsset.decimals),
          buyAsset.decimals
        )
      : 10n ** BigInt(buyAsset.decimals));
  const maxBuyText = baseIsBuy
    ? recurring.sellBaseLiquidity
    : recurring.buyQuoteLiquidity;
  const maxBuy =
    maxBuyText && decimalToAtomic(maxBuyText, buyAsset.decimals);
  if (!unitSell || !unitBuy || !maxBuy) return null;
  return {
    order,
    source: 'recurring',
    recurringSide,
    unitSell,
    unitBuy,
    maxSell: null,
    maxBuy
  };
};

const oneOffCandidate = (
  order: SafeOrderSummary,
  sellAsset: ResolvedAsset,
  buyAsset: ResolvedAsset
): SwapCandidate | null => {
  if (
    order.kind !== 'trade' ||
    order.offerAsset.id !== buyAsset.id ||
    order.requestAsset.id !== sellAsset.id
  ) {
    return null;
  }
  const buyAmount = order.remainingOfferAmount ?? order.offerAmount;
  const sellAmount = order.remainingRequestAmount ?? order.requestAmount;
  const maxBuy =
    buyAmount && decimalToAtomic(buyAmount, buyAsset.decimals);
  const maxSell =
    sellAmount && decimalToAtomic(sellAmount, sellAsset.decimals);
  if (!maxBuy || !maxSell) return null;
  return {
    order,
    source: 'one-off',
    recurringSide: null,
    unitSell: maxSell,
    unitBuy: maxBuy,
    maxSell,
    maxBuy
  };
};

const quoteSwapCandidate = (
  candidate: SwapCandidate,
  amount: bigint,
  inputMode: PrepareSwapInput['inputMode'],
  sellDecimals: number
): (SwapCandidate & { sellAmount: bigint; buyAmount: bigint }) | null => {
  const sellAmount =
    inputMode === 'buy'
      ? (amount * candidate.unitSell + candidate.unitBuy - 1n) /
        candidate.unitBuy
      : amount;
  const buyAmount =
    (sellAmount * candidate.unitBuy) / candidate.unitSell;
  if (
    sellAmount <= 0n ||
    buyAmount <= 0n ||
    (inputMode === 'buy' && buyAmount < amount) ||
    buyAmount > candidate.maxBuy ||
    (candidate.maxSell !== null && sellAmount > candidate.maxSell)
  ) {
    return null;
  }
  const policy = candidate.order.fillPolicy;
  if (candidate.source === 'one-off' && policy && candidate.maxSell !== null) {
    const maximum = policy.maxRequestAmountPerWallet
      ? decimalToAtomic(policy.maxRequestAmountPerWallet, sellDecimals)
      : null;
    if (maximum !== null && maximum > 0n && sellAmount > maximum) return null;

    const finalFill = sellAmount === candidate.maxSell;
    if (!finalFill) {
      if (!policy.partialFillsAllowed) return null;
      const configuredMinimum = policy.minRequestAmount
        ? decimalToAtomic(policy.minRequestAmount, sellDecimals) ?? 0n
        : 0n;
      const originalRequestAmount = candidate.order.requestAmount
        ? decimalToAtomic(candidate.order.requestAmount, sellDecimals)
        : null;
      if (!originalRequestAmount) return null;
      const bpsMinimum =
        (originalRequestAmount * BigInt(policy.minPartialFillBps)) / 10_000n;
      const minimum = [1n, configuredMinimum, bpsMinimum].reduce(
        (highest, value) => (value > highest ? value : highest)
      );
      if (sellAmount < minimum) return null;
    }
  }
  return { ...candidate, sellAmount, buyAmount };
};

export class ChainWhisperDomainService {
  readonly #gateway: DomainGateway;
  readonly #envelopeFactory: DomainEnvelopeFactory;
  readonly #now: () => number;

  constructor(
    gateway: DomainGateway,
    envelopeFactory: DomainEnvelopeFactory,
    now: () => number = Date.now
  ) {
    this.#gateway = gateway;
    this.#envelopeFactory = envelopeFactory;
    this.#now = now;
  }

  async status(): Promise<ToolResult<DomainStatus>> {
    try {
      const status = await this.#gateway.getStatus();
      if (
        status.chainId !== CHAINWHISPER_CHAIN_ID ||
        status.registry.chainId !== CHAINWHISPER_CHAIN_ID ||
        status.mode !== 'keyless'
      ) {
        throw new DomainInputError('The ChainWhisper runtime manifest is not valid for COTI Mainnet.', [], 'provider_error');
      }
      return {
        ok: true,
        data: {
          service: 'chainwhisper-mcp',
          mode: 'keyless',
          chainId: CHAINWHISPER_CHAIN_ID,
          ready: status.ready,
          readOnly: status.readOnly,
          registry: status.registry,
          capabilities: {
            reads: true,
            priceReferences: true,
              unsignedPlanning: true,
            recurringWrites: status.registry.recurringWritesEnabled,
            privacyBridge: Boolean(this.#gateway.getPrivacyBridgeStatus)
          }
        }
      };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async listOrders(input: ListOrdersInput = {}): Promise<ToolResult<ListOrdersResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'role',
        'kind',
        'status',
        'access',
        'baseAsset',
        'quoteAsset',
        'cursor',
        'limit'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const baseAsset = input.baseAsset
        ? await resolveAsset(this.#gateway, input.baseAsset, 'baseAsset')
        : null;
      const quoteAsset = input.quoteAsset
        ? await resolveAsset(this.#gateway, input.quoteAsset, 'quoteAsset')
        : null;
      assertDistinctAssets(baseAsset, quoteAsset, ['baseAsset', 'quoteAsset']);
      const requestedLimit = input.limit ?? MAX_ORDER_PAGE_SIZE;
      if (!Number.isInteger(requestedLimit) || requestedLimit < 1) {
        throw new DomainInputError('Limit must be a positive integer.', [
          { field: 'limit', message: `The maximum page size is ${MAX_ORDER_PAGE_SIZE}.` }
        ]);
      }
      const limit = Math.min(requestedLimit, MAX_ORDER_PAGE_SIZE);
      const role = input.role ?? 'all';
      if (!['all', 'maker', 'recipient', 'filler'].includes(role)) {
        throw new DomainInputError('Choose a supported wallet role.', [
          { field: 'role', message: 'Expected all, maker, recipient, or filler.' }
        ]);
      }
      if (!['all', 'trade', 'recurring'].includes(input.kind ?? 'all')) {
        throw new DomainInputError('Choose a supported order kind.', [{ field: 'kind', message: 'Unknown order kind.' }]);
      }
      if (!['all', 'open', 'filled', 'cancelled', 'expired', 'declined', 'paused'].includes(input.status ?? 'open')) {
        throw new DomainInputError('Choose a supported order status.', [{ field: 'status', message: 'Unknown order status.' }]);
      }
      if (!['all', 'public', 'unlisted', 'direct'].includes(input.access ?? 'all')) {
        throw new DomainInputError('Choose a supported access type.', [{ field: 'access', message: 'Unknown access type.' }]);
      }
      if (role !== 'all' && !wallet) {
        throw new DomainInputError('A wallet is required when filtering orders by wallet role.', [
          { field: 'wallet', message: 'Use the public wallet address whose orders should be listed.' }
        ]);
      }
      const result = await this.#gateway.listOrders({
        wallet,
        role,
        kind: input.kind ?? 'all',
        status: input.status ?? 'open',
        access: input.access ?? 'all',
        baseAsset,
        quoteAsset,
        cursor: input.cursor?.trim() || null,
        limit
      });
      return {
        ok: true,
        data: {
          orders: result.orders.slice(0, limit).map(sanitizeOrder),
          nextCursor: result.nextCursor,
          truncated: result.orders.length > limit || result.truncated || requestedLimit > MAX_ORDER_PAGE_SIZE
        }
      };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async getOrder(input: { order: OrderIdentityInput }): Promise<ToolResult<SafeOrderSummary>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, ['order']);
      const identity = normalizeOrderIdentity(input.order);
      await assertTrustedOrder(this.#gateway, identity);
      const order = await this.#gateway.getOrder(identity);
      if (!order) {
        throw new DomainInputError('The ChainWhisper order was not found.', [], 'not_found');
      }
      if (!(await this.#gateway.isTrustedEscrow(order.identity.escrowContract))) {
        throw new DomainInputError('The resolved order is not from a verified ChainWhisper contract.', [], 'provider_error');
      }
      return { ok: true, data: sanitizeOrder(order) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async comparePriceReferences(
    input: ComparePriceReferencesInput
  ): Promise<ToolResult<ComparePriceReferencesResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, ['baseAsset', 'quoteAsset', 'side', 'amount']);
      if (input.side !== 'buy' && input.side !== 'sell') {
        throw new DomainInputError('Choose whether to buy or sell the base asset.', [
          { field: 'side', message: 'Expected buy or sell.' }
        ]);
      }
      const baseAsset = await resolveAsset(this.#gateway, input.baseAsset, 'baseAsset');
      const quoteAsset = await resolveAsset(this.#gateway, input.quoteAsset, 'quoteAsset');
      assertDistinctAssets(baseAsset, quoteAsset, ['baseAsset', 'quoteAsset']);
      const amount = normalizePositiveAmount(input.amount, 'amount', baseAsset!.decimals);
      const raw = await this.#gateway.getPriceReferences({
        baseAsset: baseAsset!,
        quoteAsset: quoteAsset!,
        side: input.side,
        amount
      });
      const references = raw
        .map((reference) => normalizeReference(reference, baseAsset!, quoteAsset!))
        .filter((reference): reference is NormalizedPriceReference => Boolean(reference));
      const now = Date.now();
      const executableReferences = amount
        ? sortExecutableReferences(
            references.filter(
              (reference) =>
                reference.executable &&
                reference.liquidityChecked &&
                reference.canExecuteAmount === true &&
                (!reference.expiresAt || Date.parse(reference.expiresAt) > now)
            ),
            input.side
          )
        : [];
      const executableIds = new Set(executableReferences.map((reference) => reference.id));
      const referenceOnly = references.filter((reference) => !executableIds.has(reference.id));
      const ranking =
        amount && executableReferences.length > 0
          ? {
              basis: 'quote_per_base' as const,
              side: input.side,
              amount,
              rankedReferenceIds: executableReferences.map((reference) => reference.id),
              bestReferenceId: executableReferences[0]!.id,
              rationale:
                input.side === 'buy'
                  ? 'Lowest verified executable quote-per-base price for the requested base amount.'
                  : 'Highest verified executable quote-per-base price for the requested base amount.'
            }
          : null;
      return {
        ok: true,
        data: {
          pair: {
            baseAsset: sanitizeAsset(baseAsset!),
            quoteAsset: sanitizeAsset(quoteAsset!),
            basis: 'quote_per_base'
          },
          side: input.side,
          amount,
          references,
          executableReferences,
          referenceOnly,
          ranking,
          rankingUnavailableReason:
            references.length === 0
              ? 'no_compatible_references'
              : !amount
                ? 'amount_not_supplied'
                : executableReferences.length === 0
                  ? 'executable_liquidity_not_available'
                  : null
        }
      };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareSwap(
    input: PrepareSwapInput
  ): Promise<ToolResult<PrepareSwapResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'sellAsset',
        'buyAsset',
        'inputMode',
        'amount'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const sellAsset = await resolveAsset(
        this.#gateway,
        input.sellAsset,
        'sellAsset',
        false
      );
      const buyAsset = await resolveAsset(
        this.#gateway,
        input.buyAsset,
        'buyAsset',
        false
      );
      assertDistinctAssets(sellAsset, buyAsset, ['sellAsset', 'buyAsset']);
      const inputMode = input.inputMode ?? 'sell';
      if (inputMode !== 'sell' && inputMode !== 'buy') {
        throw new DomainInputError('Choose whether the entered amount is sold or bought.', [
          { field: 'inputMode', message: 'Expected sell or buy.' }
        ]);
      }
      const amountAsset = inputMode === 'sell' ? sellAsset : buyAsset;
      const amount = amountAsset
        ? normalizePositiveAmount(
            input.amount,
            'amount',
            amountAsset.decimals
          )
        : null;
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(sellAsset), 'sellAsset', 'Choose the asset to sell.');
      requireMissing(missing, Boolean(buyAsset), 'buyAsset', 'Choose the asset to buy.');
      requireMissing(missing, Boolean(amount), 'amount', 'Enter the swap amount.');
      if (!sellAsset || !buyAsset || !amount) {
        return {
          ok: true,
          data: {
            status: 'needs_input',
            intent: null,
            selection: null,
            missing,
            warnings: [],
            envelope: null
          }
        };
      }
      const amountAtomic = decimalToAtomic(amount, amountAsset!.decimals)!;
      const pages = await Promise.all([
        this.#gateway.listOrders({
          wallet: null,
          role: 'all',
          kind: 'all',
          status: 'open',
          access: 'public',
          baseAsset: buyAsset,
          quoteAsset: sellAsset,
          cursor: null,
          limit: MAX_ORDER_PAGE_SIZE
        }),
        this.#gateway.listOrders({
          wallet: null,
          role: 'all',
          kind: 'all',
          status: 'open',
          access: 'public',
          baseAsset: sellAsset,
          quoteAsset: buyAsset,
          cursor: null,
          limit: MAX_ORDER_PAGE_SIZE
        })
      ]);
      if (
        pages.some(
          (page) => page.truncated || page.nextCursor !== null
        )
      ) {
        return {
          ok: true,
          data: {
            status: 'unsupported',
            intent: null,
            selection: null,
            missing: [],
            warnings: [],
            envelope: null,
            reason:
              'Best-single-order Swap selection requires a complete order listing, but this market has additional pages.'
          }
        };
      }
      const orders = new Map<string, SafeOrderSummary>();
      for (const order of pages.flatMap((page) => page.orders)) {
        if (
          order.status === 'open' &&
          order.access === 'public' &&
          order.amountVisibility === 'visible' &&
          !order.recipient
        ) {
          orders.set(order.identity.handle, sanitizeOrder(order));
        }
      }
      const candidates = [...orders.values()].flatMap((order) => {
        const candidate =
          recurringCandidate(order, sellAsset, buyAsset) ??
          oneOffCandidate(order, sellAsset, buyAsset);
        return candidate ? [candidate] : [];
      });
      const executable = candidates
        .flatMap((candidate) => {
          const quoted = quoteSwapCandidate(
            candidate,
            amountAtomic,
            inputMode,
            sellAsset.decimals
          );
          return quoted ? [quoted] : [];
        })
        .sort((left, right) => {
          if (inputMode === 'buy' && left.sellAmount !== right.sellAmount) {
            return left.sellAmount < right.sellAmount ? -1 : 1;
          }
          if (inputMode === 'sell' && left.buyAmount !== right.buyAmount) {
            return left.buyAmount > right.buyAmount ? -1 : 1;
          }
          const observed =
            Date.parse(right.order.updatedAt) -
            Date.parse(left.order.updatedAt);
          return (
            observed ||
            left.order.identity.handle.localeCompare(
              right.order.identity.handle
            )
          );
        });
      if (executable.length === 0) {
        return {
          ok: true,
          data: {
            status: 'unsupported',
            intent: null,
            selection: null,
            missing: missing.filter(({ field }) => field === 'wallet'),
            warnings: [],
            envelope: null,
            reason:
              'No single visible public ChainWhisper order can fill the requested amount.'
          }
        };
      }
      let selected: (typeof executable)[number] | null = null;
      let prepared: { ok: true; data: PrepareResult } | null = null;
      const unsupportedWarnings = new Set<string>();
      for (const candidate of executable) {
        if (
          !(await this.#gateway.isTrustedEscrow(
            candidate.order.identity.escrowContract
          ))
        ) {
          throw new DomainInputError(
            'The selected swap order is not from a verified ChainWhisper contract.',
            [],
            'provider_error'
          );
        }
        const attempt = await this.prepareFill({
          ...(input.wallet ? { wallet: input.wallet } : {}),
          order: { handle: candidate.order.identity.handle },
          inputAmount: atomicToDecimal(
            candidate.sellAmount,
            sellAsset.decimals
          ),
          minOutputAmount: atomicToDecimal(
            candidate.buyAmount,
            buyAsset.decimals
          ),
          ...(candidate.recurringSide
            ? { recurringSide: candidate.recurringSide }
            : {})
        });
        if (!attempt.ok) return attempt;
        if (attempt.data.status === 'unsupported') {
          for (const warning of attempt.data.warnings) {
            unsupportedWarnings.add(warning);
          }
          continue;
        }
        selected = candidate;
        prepared = attempt;
        break;
      }
      if (!selected || !prepared) {
        return {
          ok: true,
          data: {
            status: 'unsupported',
            intent: null,
            selection: null,
            missing: missing.filter(({ field }) => field === 'wallet'),
            warnings: [...unsupportedWarnings],
            envelope: null,
            reason:
              'No ranked single-order Swap candidate passed canonical preparation.'
          }
        };
      }
      if (prepared.data.intent.action !== 'fill') {
        throw new DomainInputError(
          'The selected swap did not produce a fill intent.',
          [],
          'provider_error'
        );
      }
      const sellAmount = atomicToDecimal(
        selected.sellAmount,
        sellAsset.decimals
      );
      const buyAmount = atomicToDecimal(
        selected.buyAmount,
        buyAsset.decimals
      );
      const selectedPolicy =
        selected.source === 'one-off' ? selected.order.fillPolicy : null;
      const selectedMaxPerWallet = selectedPolicy?.maxRequestAmountPerWallet
        ? decimalToAtomic(
            selectedPolicy.maxRequestAmountPerWallet,
            sellAsset.decimals
          )
        : null;
      const warnings = [...prepared.data.warnings];
      if (
        selectedPolicy?.oneFillPerWallet ||
        (selectedMaxPerWallet !== null && selectedMaxPerWallet > 0n)
      ) {
        warnings.push(
          'Wallet fill-history eligibility is verified again during preparation and execution; oneFillPerWallet or prior maxRequestAmountPerWallet usage can make this quote ineligible.'
        );
      }
      const selection: SwapSelection = {
        source: selected.source,
        order: sanitizeIdentity(selected.order.identity),
        orderType: selected.order.orderType ?? null,
        recurringSide: selected.recurringSide,
        inputMode,
        sellAsset: sanitizeAsset(sellAsset),
        buyAsset: sanitizeAsset(buyAsset),
        sellAmount,
        buyAmount,
        price: divideDecimals(sellAmount, buyAmount),
        priceBasis: 'sell_per_buy',
        visibleCandidateCount: candidates.length
      };
      return {
        ok: true,
        data: {
          ...prepared.data,
          intent: prepared.data.intent,
          warnings,
          selection
        }
      };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareCreateTrade(input: CreateTradeInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
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
      assertAllowedKeys(input.fillPolicy, [
        'partialFillsAllowed',
        'minPartialFillBps',
        'minRequestAmount',
        'maxRequestAmountPerWallet',
        'oneFillPerWallet'
      ], 'input.fillPolicy');
      const wallet = normalizeWallet(input.wallet);
      const offerAsset = await resolveAsset(this.#gateway, input.offerAsset, 'offerAsset', false);
      const requestAsset = await resolveAsset(this.#gateway, input.requestAsset, 'requestAsset', false);
      assertDistinctAssets(offerAsset, requestAsset, ['offerAsset', 'requestAsset']);
      const selectedAxes = resolveCreateAxes(input);
      const access = selectedAxes.access;
      const recipient = normalizeAddress(input.recipient, 'recipient', false);
      const amountVisibility = selectedAxes.amountVisibility;
      const privateAmountMode = normalizePrivateAmountMode(
        input.privateAmountMode
      );
      const privateLiquidity = amountVisibility === 'private';
      const confidentialOffer =
        privateLiquidity ||
        (access !== 'public' && offerAsset?.kind === 'private-erc20');
      const confidentialRequest =
        privateLiquidity ||
        (access !== 'public' && requestAsset?.kind === 'private-erc20');
      if (confidentialOffer && privateAmountMode === 'signer-input') {
        rejectSignerLocalAmount(
          input.offerAmount,
          'offerAmount',
          'Confidential offer amounts'
        );
      }
      if (confidentialRequest && privateAmountMode === 'signer-input') {
        rejectSignerLocalAmount(
          input.requestAmount,
          'requestAmount',
          'Confidential request amounts'
        );
      }
      const offerAmount =
        offerAsset &&
        (!confidentialOffer || privateAmountMode === 'agent-provided')
        ? normalizePositiveAmount(input.offerAmount, 'offerAmount', offerAsset.decimals)
        : null;
      const requestAmount =
        requestAsset &&
        (!confidentialRequest || privateAmountMode === 'agent-provided')
        ? normalizePositiveAmount(input.requestAmount, 'requestAmount', requestAsset.decimals)
        : null;
      if (access !== 'direct' && recipient) {
        throw new DomainInputError('Only Direct orders can be recipient-bound.', [
          { field: 'recipient', message: 'Choose Direct access to bind a recipient.' }
        ]);
      }
      if (amountVisibility === 'private' && offerAsset && offerAsset.kind !== 'private-erc20') {
        throw new DomainInputError('Private liquidity requires a private token on the offered side.', [
          { field: 'offerAsset', message: 'Use a verified private ERC-20 token.' }
        ]);
      }
      const fillPolicy = normalizeFillPolicy(
        privateLiquidity ? undefined : input.fillPolicy,
        requestAsset?.decimals ?? 78
      );
      const intent: CreateTradeIntent = {
        action: 'create_trade',
        orderType: deriveOrderClassificationV1({
          route:
            amountVisibility === 'private'
              ? 'private-liquidity-escrow'
              : access === 'public'
                ? 'standard-escrow'
                : 'direct-escrow',
          access,
          privateLiquidity: amountVisibility === 'private',
          assets: [offerAsset, requestAsset],
          relation: 'primary'
        }),
        wallet,
        offerAsset,
        requestAsset,
        offerAmount,
        requestAmount,
        access,
        recipient: access === 'direct' ? recipient : null,
        amountVisibility,
        privateAmountMode,
        expiresAt: normalizeExpiry(input.expiresAt),
        fillPolicy,
        secretPolicy: secretPolicyFor(access, recipient)
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(offerAsset), 'offerAsset', 'Choose the asset to sell.');
      requireMissing(missing, Boolean(requestAsset), 'requestAsset', 'Choose the asset to receive.');
      requireMissing(
        missing,
        (confidentialOffer && privateAmountMode === 'signer-input') ||
          Boolean(offerAmount),
        'offerAmount',
        'Enter the amount to sell.'
      );
      requireMissing(
        missing,
        (confidentialRequest && privateAmountMode === 'signer-input') ||
          Boolean(requestAmount),
        'requestAmount',
        'Enter the amount to receive.'
      );
      requireMissing(missing, access !== 'direct' || Boolean(recipient), 'recipient', 'Choose the direct recipient.');
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async privacyBridgeStatus(
    input: PrivacyBridgeStatusInput
  ): Promise<ToolResult<PrivacyBridgeStatus>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, ['wallet', 'pair', 'direction', 'amount']);
      const pair = privacyBridgePair(input.pair);
      if (!pair) {
        throw new DomainInputError('Choose one of the eight current Privacy Portal pairs.');
      }
      const wallet = normalizeWallet(input.wallet);
      if (
        input.direction !== undefined &&
        input.direction !== 'public-to-private' &&
        input.direction !== 'private-to-public'
      ) {
        throw new DomainInputError('Choose public-to-private or private-to-public.');
      }
      const amount = input.amount
        ? normalizePositiveAmount(input.amount, 'amount', pair.decimals)
        : null;
      if (!this.#gateway.getPrivacyBridgeStatus) {
        throw new DomainInputError('Privacy Portal reads are unavailable.', [], 'unsupported');
      }
      return {
        ok: true,
        data: await this.#gateway.getPrivacyBridgeStatus({
          pair: pair.id,
          ...(wallet ? { wallet } : {}),
          ...(input.direction ? { direction: input.direction } : {}),
          ...(amount ? { amount } : {})
        })
      };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async preparePrivacyBridge(
    input: PrivacyBridgeInput
  ): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, ['wallet', 'pair', 'direction', 'amount']);
      const pair = privacyBridgePair(input.pair);
      if (!pair) {
        throw new DomainInputError('Choose one of the eight current Privacy Portal pairs.');
      }
      if (
        input.direction !== 'public-to-private' &&
        input.direction !== 'private-to-public'
      ) {
        throw new DomainInputError('Choose public-to-private or private-to-public.');
      }
      const wallet = normalizeWallet(input.wallet);
      const publicAsset = await resolveAsset(
        this.#gateway,
        pair.publicSymbol,
        'pair'
      );
      const privateAsset = await resolveAsset(
        this.#gateway,
        pair.privateSymbol,
        'pair'
      );
      const amount = normalizePositiveAmount(
        input.amount,
        'amount',
        pair.decimals
      );
      const intent: PrivacyBridgeIntent = {
        action: 'privacy_bridge',
        wallet,
        pair: pair.id,
        direction: input.direction,
        publicAsset,
        privateAsset,
        amount
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(amount), 'amount', 'Enter the amount to shield or unshield.');
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareCreateRecurring(input: CreateRecurringInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'baseAsset',
        'quoteAsset',
        'buyPrice',
        'sellPrice',
        'buyQuoteLiquidity',
        'sellBaseLiquidity',
        'access',
        'recipient',
        'liquidityVisibility',
        'privateAmountMode'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const baseAsset = await resolveAsset(this.#gateway, input.baseAsset, 'baseAsset', false);
      const quoteAsset = await resolveAsset(this.#gateway, input.quoteAsset, 'quoteAsset', false);
      assertDistinctAssets(baseAsset, quoteAsset, ['baseAsset', 'quoteAsset']);
      const selectedAxes = resolveCreateAxes(input);
      const access = selectedAxes.access;
      if (access === 'unlisted') {
        throw new DomainInputError(
          'Recurring orders support only public or fixed-recipient access.',
          [{ field: 'access', message: 'Choose public or direct access.' }]
        );
      }
      const recipient = normalizeAddress(input.recipient, 'recipient', false);
      const amountVisibility = selectedAxes.amountVisibility;
      const privateAmountMode = normalizePrivateAmountMode(
        input.privateAmountMode
      );
      const privateLiquidity = amountVisibility === 'private';
      const buyPriceInput = normalizeRecurringPriceInput(
        input.buyPrice,
        'buyPrice',
        quoteAsset?.decimals ?? 78
      );
      const sellPriceInput = normalizeRecurringPriceInput(
        input.sellPrice,
        'sellPrice',
        quoteAsset?.decimals ?? 78
      );
      const needsMarketReference =
        buyPriceInput?.kind === 'market' ||
        sellPriceInput?.kind === 'market';
      let marketReference: TimestampedPriceReference | null = null;
      if (needsMarketReference && baseAsset && quoteAsset) {
        const references = (
          await this.#gateway.getPriceReferences({
            baseAsset,
            quoteAsset,
            side: 'buy',
            amount: null
          })
        )
          .map((reference) =>
            normalizeReference(reference, baseAsset, quoteAsset)
          )
          .filter(
            (reference): reference is TimestampedPriceReference =>
              reference !== null &&
              reference.source === 'market' &&
              isFreshMarketReference(reference, this.#now())
          )
          .sort((left, right) => {
            const time =
              referenceObservationTime(right) -
              referenceObservationTime(left);
            return time || left.id.localeCompare(right.id);
          });
        marketReference = references[0] ?? null;
        if (!marketReference) {
          throw new DomainInputError(
            'No compatible live market reference is available for this pair.',
            [
              {
                field: 'buyPrice',
                message: 'Use exact buy and sell prices or retry the market reference.'
              }
            ],
            'provider_error'
          );
        }
      }
      const resolvePrice = (
        price: NormalizedRecurringPriceInput,
        roundUp: boolean
      ): string | null => {
        if (!price) return null;
        if (price.kind === 'exact') return price.price;
        if (!marketReference || !quoteAsset) return null;
        const adjusted = multiplyDecimals(
          marketReference.price,
          basisPointFactor(price.offsetBps)
        );
        return roundUp
          ? ceilDecimalToScale(adjusted, quoteAsset.decimals)
          : floorDecimalToScale(adjusted, quoteAsset.decimals);
      };
      const buyPrice = resolvePrice(buyPriceInput, false);
      const sellPrice = resolvePrice(sellPriceInput, true);
      if (
        privateLiquidity &&
        quoteAsset?.kind === 'private-erc20' &&
        privateAmountMode === 'signer-input'
      ) {
        rejectSignerLocalAmount(
          input.buyQuoteLiquidity,
          'buyQuoteLiquidity',
          'Private quote-token recurring inventory'
        );
      }
      if (
        privateLiquidity &&
        baseAsset?.kind === 'private-erc20' &&
        privateAmountMode === 'signer-input'
      ) {
        rejectSignerLocalAmount(
          input.sellBaseLiquidity,
          'sellBaseLiquidity',
          'Private base-token recurring inventory'
        );
      }
      const buyQuoteLiquidity =
        privateLiquidity &&
        quoteAsset?.kind === 'private-erc20' &&
        privateAmountMode === 'signer-input'
        ? null
        : normalizePositiveAmount(
            input.buyQuoteLiquidity,
            'buyQuoteLiquidity',
            quoteAsset?.decimals ?? 78
          );
      const sellBaseLiquidity =
        privateLiquidity &&
        baseAsset?.kind === 'private-erc20' &&
        privateAmountMode === 'signer-input'
        ? null
        : normalizePositiveAmount(
            input.sellBaseLiquidity,
            'sellBaseLiquidity',
            baseAsset?.decimals ?? 78
          );
      if (access !== 'direct' && recipient) {
        throw new DomainInputError('Only Direct recurring orders can be recipient-bound.', [
          { field: 'recipient', message: 'Choose Direct access to bind a recipient.' }
        ]);
      }
      if (
        amountVisibility === 'private' &&
        baseAsset &&
        quoteAsset &&
        baseAsset.kind !== 'private-erc20' &&
        quoteAsset.kind !== 'private-erc20'
      ) {
        throw new DomainInputError('Private recurring liquidity requires a verified private token.', [
          { field: 'liquidityVisibility', message: 'Use visible liquidity for a fully public-token pair.' }
        ]);
      }
      const intent: CreateRecurringIntent = {
        action: 'create_recurring',
        orderType: deriveOrderClassificationV1({
          route: 'recurring-escrow',
          access,
          privateLiquidity: amountVisibility === 'private',
          assets: [baseAsset, quoteAsset],
          relation: 'primary'
        }),
        wallet,
        baseAsset,
        quoteAsset,
        buyPrice,
        sellPrice,
        buyQuoteLiquidity,
        sellBaseLiquidity,
        access,
        recipient: access === 'direct' ? recipient : null,
        amountVisibility,
        privateAmountMode,
        ...(marketReference
          ? {
              priceReference: {
                id: marketReference.id,
                venue: marketReference.venue,
                price: marketReference.price,
                observedAt: marketReference.observedAt,
                expiresAt: marketReference.expiresAt,
                buyOffsetBps:
                  buyPriceInput?.kind === 'market'
                    ? buyPriceInput.offsetBps
                    : null,
                sellOffsetBps:
                  sellPriceInput?.kind === 'market'
                    ? sellPriceInput.offsetBps
                    : null
              }
            }
          : {}),
        secretPolicy: secretPolicyFor(access, recipient)
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(baseAsset), 'baseAsset', 'Choose the recurring base asset.');
      requireMissing(missing, Boolean(quoteAsset), 'quoteAsset', 'Choose the recurring quote asset.');
      requireMissing(missing, Boolean(buyPrice), 'buyPrice', 'Enter the maker buy price in quote per base.');
      requireMissing(missing, Boolean(sellPrice), 'sellPrice', 'Enter the maker sell price in quote per base.');
      requireMissing(
        missing,
        (privateLiquidity && privateAmountMode === 'signer-input') ||
          Boolean(buyQuoteLiquidity || sellBaseLiquidity),
        'liquidity',
        'Fund at least the buy or sell side.'
      );
      requireMissing(missing, access !== 'direct' || Boolean(recipient), 'recipient', 'Choose the direct recipient.');

      const status = await this.#gateway.getStatus();
      if (!status.registry.recurringWritesEnabled) {
        return {
          ok: true,
          data: {
            status: 'unsupported',
            intent,
            missing,
            warnings: status.registry.warnings,
            envelope: null,
            reason: 'Recurring writes are disabled until the runtime manifest and deployed bytecode audit agree.'
          }
        };
      }
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareFill(input: FillInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'order',
        'inputAmount',
        'minOutputAmount',
        'recurringSide',
        'privateAmountMode'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const privateAmountMode = normalizePrivateAmountMode(
        input.privateAmountMode
      );
      const order = await this.#resolveOrder(input.order);
      const legacyStandardRecipientBound =
        order.legacyCompatibility?.kind ===
        'standard-recipient-bound';
      const legacyStandardCounterAcceptance =
        legacyStandardRecipientBound &&
        order.relation?.kind === 'counter';
      if (
        legacyStandardRecipientBound &&
        wallet &&
        order.recipient?.toLowerCase() !== wallet.toLowerCase()
      ) {
        throw new DomainInputError(
          'Only the fixed recipient can fill this legacy Standard order.',
          [
            {
              field: 'wallet',
              message: 'Choose the order recipient wallet.'
            }
          ]
        );
      }
      const recurringSide = input.recurringSide ?? null;
      if (order.kind === 'recurring' && recurringSide !== 'buy' && recurringSide !== 'sell') {
        // This is intentionally editable rather than a hard validation error.
      } else if (order.kind !== 'recurring' && recurringSide) {
        throw new DomainInputError('A recurring side cannot be used for a one-off order.', [
          { field: 'recurringSide', message: 'Remove this field for a standard fill.' }
        ]);
      }
      const inputDecimals =
        order.kind === 'recurring' && order.recurring
          ? recurringSide === 'buy'
            ? order.recurring.quoteAsset.decimals
            : order.recurring.baseAsset.decimals
          : order.requestAsset.decimals;
      const outputDecimals =
        order.kind === 'recurring' && order.recurring
          ? recurringSide === 'buy'
            ? order.recurring.baseAsset.decimals
            : order.recurring.quoteAsset.decimals
          : order.offerAsset.decimals;
      const recurringInputAsset =
        order.kind === 'recurring' && order.recurring
          ? recurringSide === 'buy'
            ? order.recurring.quoteAsset
            : order.recurring.baseAsset
          : null;
      const recurringOutputAsset =
        order.kind === 'recurring' && order.recurring
          ? recurringSide === 'buy'
            ? order.recurring.baseAsset
            : order.recurring.quoteAsset
          : null;
      const signerLocalPrivateAmount =
        order.kind === 'recurring'
          ? order.amountVisibility === 'private' &&
            recurringInputAsset?.kind === 'private-erc20'
          : order.requestAsset.kind === 'private-erc20' &&
            !legacyStandardRecipientBound &&
            (
              order.amountVisibility === 'private' ||
              order.access !== 'public'
            );
      const signerLocalPrivateOutput =
        order.kind === 'recurring'
          ? order.amountVisibility === 'private' &&
            recurringOutputAsset?.kind === 'private-erc20'
          : order.offerAsset.kind === 'private-erc20' &&
            (
              order.amountVisibility === 'private' ||
              order.access !== 'public'
            );
      if (
        signerLocalPrivateAmount &&
        privateAmountMode === 'signer-input' &&
        input.inputAmount !== undefined
      ) {
        throw new DomainInputError(
          'Confidential fill amounts must be entered only in the local signer confirmation.',
          [
            {
              field: 'inputAmount',
              message:
                'Remove private amounts from the MCP request; the signer collects them locally.'
            }
          ]
        );
      }
      if (
        signerLocalPrivateOutput &&
        input.minOutputAmount !== undefined
      ) {
        throw new DomainInputError(
          'The deployed private fill route does not accept an encrypted output limit.',
          [
            {
              field: 'minOutputAmount',
              message:
                'Remove this field. Agent-provided private amounts remain encrypted on-chain; this contract field would be public calldata.'
            }
          ]
        );
      }
      if (
        legacyStandardCounterAcceptance &&
        input.minOutputAmount !== undefined
      ) {
        throw new DomainInputError(
          'Legacy Standard counter acceptance settles the exact remaining terms.',
          [
            {
              field: 'minOutputAmount',
              message:
                'Remove this field; the deployed atomic counter acceptance does not accept a separate output limit.'
            }
          ]
        );
      }
      let normalizedInputAmount =
        signerLocalPrivateAmount &&
        privateAmountMode === 'signer-input'
        ? null
        : normalizePositiveAmount(
            input.inputAmount,
            'inputAmount',
            inputDecimals
          );
      if (legacyStandardCounterAcceptance) {
        const trustedCounterAmount = normalizePositiveAmount(
          order.remainingRequestAmount ?? order.requestAmount ?? undefined,
          'inputAmount',
          inputDecimals
        );
        if (!trustedCounterAmount) {
          throw new DomainInputError(
            'The exact remaining legacy counter payment could not be verified.',
            [
              {
                field: 'order',
                message:
                  'Refresh the order from the trusted Standard escrow before accepting it.'
              }
            ],
            'provider_error'
          );
        }
        if (
          normalizedInputAmount &&
          compareDecimals(
            normalizedInputAmount,
            trustedCounterAmount
          ) !== 0
        ) {
          throw new DomainInputError(
            'Legacy Standard counter acceptance requires the exact remaining payment.',
            [
              {
                field: 'inputAmount',
                message: `Use the trusted remaining amount ${trustedCounterAmount}.`
              }
            ]
          );
        }
        normalizedInputAmount = trustedCounterAmount;
      }
      const intent: FillIntent = {
        action: 'fill',
        ...(order.orderType ? { orderType: order.orderType } : {}),
        wallet,
        order,
        inputAmount: normalizedInputAmount,
        minOutputAmount:
          signerLocalPrivateOutput &&
          privateAmountMode === 'signer-input'
            ? null
            : normalizePositiveAmount(
                input.minOutputAmount,
                'minOutputAmount',
                outputDecimals
              ),
        recurringSide,
        privateAmountMode,
        secretPolicy:
          order.access === 'unlisted'
            ? secretPolicyFor('public', null, order.identity.handle)
            : order.access === 'direct'
              ? { kind: 'recipient-bound', recipient: order.recipient }
              : { kind: 'none' }
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(
        missing,
        (signerLocalPrivateAmount &&
          privateAmountMode === 'signer-input') ||
          Boolean(intent.inputAmount),
        'inputAmount',
        'Enter the amount to fill.'
      );
      requireMissing(
        missing,
        order.kind !== 'recurring' || Boolean(recurringSide),
        'recurringSide',
        'Choose the recurring buy or sell side.'
      );
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareCounter(input: CounterInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'order',
        'offerAmount',
        'requestAmount',
        'expiresAt',
        'privateAmountMode'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const privateAmountMode = normalizePrivateAmountMode(
        input.privateAmountMode
      );
      const order = await this.#resolveOrder(input.order);
      if (order.kind === 'trade' && order.status !== 'open') {
        throw new DomainInputError(
          'Only an open one-off order can be countered.',
          [
            {
              field: 'order',
              message: `The selected order is currently ${order.status}.`
            }
          ]
        );
      }
      if (
        wallet &&
        order.kind === 'trade' &&
        wallet.toLowerCase() === order.maker.toLowerCase()
      ) {
        throw new DomainInputError(
          'The maker cannot create a counter addressed back to the same maker.',
          [
            {
              field: 'wallet',
              message: 'Use a non-maker counterparty wallet.'
            }
          ]
        );
      }
      if (
        wallet &&
        order.kind === 'trade' &&
        order.access === 'direct' &&
        order.recipient &&
        wallet.toLowerCase() !== order.recipient.toLowerCase()
      ) {
        throw new DomainInputError(
          order.relation?.kind === 'counter'
            ? 'Only the recipient of a Direct counter can supersede it.'
            : 'Only the fixed recipient can counter this Direct order.',
          [
            {
              field: 'wallet',
              message: `Use the Direct order recipient ${order.recipient}.`
            }
          ]
        );
      }
      const counterOfferAsset = order.requestAsset;
      const counterRequestAsset = order.offerAsset;
      const legacyStandardCounterReplacement =
        order.legacyCompatibility?.kind ===
          'standard-recipient-bound' &&
        order.relation?.kind === 'counter';
      if (
        legacyStandardCounterReplacement &&
        wallet &&
        order.recipient?.toLowerCase() !== wallet.toLowerCase()
      ) {
        throw new DomainInputError(
          'Only the fixed recipient can replace this legacy Standard counter.',
          [
            {
              field: 'wallet',
              message: 'Choose the selected counterorder recipient wallet.'
            }
          ]
        );
      }
      const confidentialOffer =
        counterOfferAsset.kind === 'private-erc20' &&
        !legacyStandardCounterReplacement;
      const confidentialRequest =
        counterRequestAsset.kind === 'private-erc20' &&
        !legacyStandardCounterReplacement;
      if (confidentialOffer && privateAmountMode === 'signer-input') {
        rejectSignerLocalAmount(
          input.offerAmount,
          'offerAmount',
          'Confidential counter offer amounts'
        );
      }
      if (confidentialRequest && privateAmountMode === 'signer-input') {
        rejectSignerLocalAmount(
          input.requestAmount,
          'requestAmount',
          'Confidential counter request amounts'
        );
      }
      const intent: CounterIntent = {
        action: 'counter',
        ...(legacyStandardCounterReplacement
          ? {}
          : {
              orderType: deriveOrderClassificationV1({
                route: 'direct-escrow',
                access: 'direct',
                privateLiquidity: false,
                assets: [order.requestAsset, order.offerAsset],
                relation: 'counter'
              })
            }),
        wallet,
        order,
        offerAsset: counterOfferAsset,
        requestAsset: counterRequestAsset,
        offerAmount:
          confidentialOffer &&
          privateAmountMode === 'signer-input'
          ? null
          : normalizePositiveAmount(
              input.offerAmount,
              'offerAmount',
              counterOfferAsset.decimals
            ),
        requestAmount:
          confidentialRequest &&
          privateAmountMode === 'signer-input'
          ? null
          : normalizePositiveAmount(
              input.requestAmount,
              'requestAmount',
              counterRequestAsset.decimals
            ),
        expiresAt: normalizeExpiry(input.expiresAt),
        recipient: order.maker,
        access: 'direct',
        amountVisibility: 'visible',
        privateAmountMode,
        secretPolicy: { kind: 'recipient-bound', recipient: order.maker }
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(
        missing,
        (confidentialOffer &&
          privateAmountMode === 'signer-input') ||
          Boolean(intent.offerAmount),
        'offerAmount',
        'Enter what the counterparty receives.'
      );
      requireMissing(
        missing,
        (confidentialRequest &&
          privateAmountMode === 'signer-input') ||
          Boolean(intent.requestAmount),
        'requestAmount',
        'Enter what you receive.'
      );
      if (order.kind === 'recurring') {
        return {
          ok: true,
          data: {
            status: 'unsupported',
            intent,
            missing,
            warnings: [],
            envelope: null,
            reason: 'Recurring orders do not support counters.'
          }
        };
      }
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareEdit(input: EditInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'order',
        'changes',
        'privateAmountMode'
      ]);
      assertAllowedKeys(input.changes, [
        'offerAmount',
        'requestAmount',
        'expiresAt',
        'partialFillsAllowed',
        'minPartialFillBps',
        'minRequestAmount',
        'maxRequestAmountPerWallet',
        'oneFillPerWallet',
        'buyPrice',
        'sellPrice',
        'addBuyQuoteLiquidity',
        'addSellBaseLiquidity',
        'removeBuyQuoteLiquidity',
        'removeSellBaseLiquidity',
        'replaceConfidentialTerms',
        'adjustPrivateLiquidity'
      ], 'input.changes');
      const wallet = normalizeWallet(input.wallet);
      const privateAmountMode = normalizePrivateAmountMode(
        input.privateAmountMode
      );
      const order = await this.#resolveOrder(input.order);
      if (
        (
          order.kind === 'trade' &&
          order.status !== 'open'
        ) ||
        (
          order.kind === 'recurring' &&
          order.status !== 'open' &&
          order.status !== 'paused'
        )
      ) {
        throw new DomainInputError(
          'Only an open one-off order, or an active or paused recurring order, can be edited.',
          [
            {
              field: 'order',
              message: `The selected order is currently ${order.status}.`
            }
          ]
        );
      }
      if (wallet && !sameAddress(wallet, order.maker)) {
        throw new DomainInputError(
          'Only the maker can edit this order.',
          [
            {
              field: 'wallet',
              message: 'Choose the order maker wallet.'
            }
          ]
        );
      }
      const changes = input.changes ?? {};
      const normalizedChanges: EditIntent['changes'] = {};
      if (changes.offerAmount !== undefined) {
        const confidentialOffer =
          order.amountVisibility === 'private' ||
          (order.orderType?.route === 'direct-escrow' &&
            order.offerAsset.kind === 'private-erc20');
        if (
          confidentialOffer &&
          privateAmountMode === 'signer-input'
        ) {
          throw new DomainInputError(
            'Confidential offer amounts must be entered in the local signer.',
            [
              {
                field: 'changes.offerAmount',
                message:
                  'Remove the amount and set replaceConfidentialTerms to true.'
              }
            ]
          );
        }
        normalizedChanges.offerAmount = normalizePositiveAmount(
          changes.offerAmount,
          'changes.offerAmount',
          order.offerAsset.decimals,
          true
        )!;
      }
      if (changes.requestAmount !== undefined) {
        const confidentialRequest =
          order.amountVisibility === 'private' ||
          (order.orderType?.route === 'direct-escrow' &&
            order.requestAsset.kind === 'private-erc20');
        if (
          confidentialRequest &&
          privateAmountMode === 'signer-input'
        ) {
          throw new DomainInputError(
            'Confidential request amounts must be entered in the local signer.',
            [
              {
                field: 'changes.requestAmount',
                message:
                  'Remove the amount and set replaceConfidentialTerms to true.'
              }
            ]
          );
        }
        normalizedChanges.requestAmount = normalizePositiveAmount(
          changes.requestAmount,
          'changes.requestAmount',
          order.requestAsset.decimals,
          true
        )!;
      }
      if ('expiresAt' in changes) normalizedChanges.expiresAt = normalizeExpiry(changes.expiresAt, 'changes.expiresAt');
      if (changes.partialFillsAllowed !== undefined) {
        if (typeof changes.partialFillsAllowed !== 'boolean') {
          throw new DomainInputError('changes.partialFillsAllowed must be true or false.');
        }
        normalizedChanges.partialFillsAllowed = changes.partialFillsAllowed;
      }
      if (changes.oneFillPerWallet !== undefined) {
        if (typeof changes.oneFillPerWallet !== 'boolean') {
          throw new DomainInputError('changes.oneFillPerWallet must be true or false.');
        }
        normalizedChanges.oneFillPerWallet = changes.oneFillPerWallet;
      }
      if (changes.minPartialFillBps !== undefined) {
        if (
          !Number.isInteger(changes.minPartialFillBps) ||
          changes.minPartialFillBps < 0 ||
          changes.minPartialFillBps > 5_000
        ) {
          throw new DomainInputError('changes.minPartialFillBps must be from 0 to 5,000.');
        }
        normalizedChanges.minPartialFillBps = changes.minPartialFillBps;
      }
      const requestAmountFields = [
        'minRequestAmount',
        'maxRequestAmountPerWallet'
      ] as const;
      for (const field of requestAmountFields) {
        if (changes[field] !== undefined) {
          normalizedChanges[field] = normalizeNonNegativeAmount(
            changes[field],
            `changes.${field}`,
            order.requestAsset.decimals
          );
        }
      }
      const recurringPriceFields = ['buyPrice', 'sellPrice'] as const;
      for (const field of recurringPriceFields) {
        if (changes[field] !== undefined) {
          normalizedChanges[field] = normalizePositiveAmount(
            changes[field],
            `changes.${field}`,
            order.recurring?.quoteAsset.decimals ?? order.requestAsset.decimals,
            true
          )!;
        }
      }
      const recurringLiquidityFields = [
        ['addBuyQuoteLiquidity', order.recurring?.quoteAsset.decimals],
        ['addSellBaseLiquidity', order.recurring?.baseAsset.decimals],
        ['removeBuyQuoteLiquidity', order.recurring?.quoteAsset.decimals],
        ['removeSellBaseLiquidity', order.recurring?.baseAsset.decimals]
      ] as const;
      for (const [field, decimals] of recurringLiquidityFields) {
        if (changes[field] !== undefined) {
          if (order.kind !== 'recurring' || decimals === undefined) {
            throw new DomainInputError(`${field} is only available for recurring orders.`);
          }
          const adjustsQuoteInventory =
            field === 'addBuyQuoteLiquidity' ||
            field === 'removeBuyQuoteLiquidity';
          const inventoryAsset = adjustsQuoteInventory
            ? order.recurring?.quoteAsset
            : order.recurring?.baseAsset;
          if (
            order.amountVisibility === 'private' &&
            inventoryAsset?.kind === 'private-erc20' &&
            privateAmountMode === 'signer-input'
          ) {
            throw new DomainInputError(
              'Private recurring inventory changes must be entered in the local signer.',
              [
                {
                  field: `changes.${field}`,
                  message:
                    'Remove this amount and set changes.adjustPrivateLiquidity to true.'
                }
              ]
            );
          }
          normalizedChanges[field] = normalizePositiveAmount(
            changes[field],
            `changes.${field}`,
            decimals,
            true
          )!;
        }
      }
      if (changes.replaceConfidentialTerms !== undefined) {
        if (
          typeof changes.replaceConfidentialTerms !== 'boolean' ||
          order.kind !== 'trade' ||
          (
            order.amountVisibility !== 'private' &&
            order.orderType?.route !== 'direct-escrow'
          )
        ) {
          throw new DomainInputError(
            'replaceConfidentialTerms is only available for private-liquidity or Direct one-off orders.'
          );
        }
        if (changes.replaceConfidentialTerms) {
          normalizedChanges.replaceConfidentialTerms = true;
        }
      }
      if (changes.adjustPrivateLiquidity !== undefined) {
        if (
          typeof changes.adjustPrivateLiquidity !== 'boolean' ||
          order.kind !== 'recurring' ||
          order.amountVisibility !== 'private'
        ) {
          throw new DomainInputError(
            'adjustPrivateLiquidity is only available for private-inventory recurring orders.'
          );
        }
        if (changes.adjustPrivateLiquidity) {
          normalizedChanges.adjustPrivateLiquidity = true;
        }
      }
      const policyChangeRequested = [
        changes.partialFillsAllowed,
        changes.minPartialFillBps,
        changes.minRequestAmount,
        changes.maxRequestAmountPerWallet,
        changes.oneFillPerWallet
      ].some((value) => value !== undefined);
      if (
        policyChangeRequested &&
        order.orderType?.route !== 'standard-escrow'
      ) {
        throw new DomainInputError(
          'Fill-policy edits are only supported by standard public one-off orders.'
        );
      }
      const recurringChangeRequested = [
        changes.buyPrice,
        changes.sellPrice,
        changes.addBuyQuoteLiquidity,
        changes.addSellBaseLiquidity,
        changes.removeBuyQuoteLiquidity,
        changes.removeSellBaseLiquidity,
        changes.adjustPrivateLiquidity
      ].some((value) => value !== undefined);
      if (recurringChangeRequested && order.kind !== 'recurring') {
        throw new DomainInputError(
          'Recurring price and liquidity changes require a recurring order.'
        );
      }
      const intent: EditIntent = {
        action: 'edit',
        ...(order.orderType
          ? {
              orderType:
                order.kind === 'recurring'
                  ? order.orderType
                  : { ...order.orderType, relation: 'replacement' }
            }
          : {}),
        wallet,
        order,
        privateAmountMode,
        changes: normalizedChanges
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      const confidentialOneOff =
        order.kind === 'trade' &&
        (
          order.amountVisibility === 'private' ||
          order.orderType?.route === 'direct-escrow'
        );
      requireMissing(
        missing,
        !confidentialOneOff ||
          normalizedChanges.replaceConfidentialTerms === true,
        'changes.replaceConfidentialTerms',
        'Set replaceConfidentialTerms to true so the complete replacement terms are collected inside the local signer.'
      );
      requireMissing(
        missing,
        !confidentialOneOff ||
          privateAmountMode === 'signer-input' ||
          Boolean(
            normalizedChanges.offerAmount &&
              normalizedChanges.requestAmount
          ),
        'changes.offerAmount',
        'Agent-provided confidential replacements must include both complete resulting amounts.'
      );
      requireMissing(missing, Object.keys(normalizedChanges).length > 0, 'changes', 'Describe at least one order change.');
      if (order.kind === 'recurring') {
        const status = await this.#gateway.getStatus();
        if (!status.registry.recurringWritesEnabled) {
          return {
            ok: true,
            data: {
              status: 'unsupported',
              intent,
              missing,
              warnings: status.registry.warnings,
              envelope: null,
              reason: 'Recurring writes are disabled until the runtime manifest and deployed bytecode audit agree.'
            }
          };
        }
      }
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async prepareOrderUpdate(input: OrderUpdateInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, ['wallet', 'order', 'update', 'expiresAt']);
      const wallet = normalizeWallet(input.wallet);
      const order = await this.#resolveOrder(input.order);
      const allowedUpdates = new Set([
        'cancel',
        'close',
        'decline',
        'pause',
        'resume',
        'settle_inventory',
        'reclaim_expired',
        'refresh',
        'extend_expiry'
      ]);
      if (!allowedUpdates.has(input.update)) {
        throw new DomainInputError('Choose a supported order update.', [
          { field: 'update', message: 'Arbitrary or administrative actions are not supported.' }
        ]);
      }
      const expiresAt = normalizeExpiry(input.expiresAt);
      const resolvedUpdate =
        input.update === 'close' && wallet
          ? wallet.toLowerCase() === order.maker.toLowerCase()
            ? 'cancel'
            : order.kind === 'trade' &&
                order.recipient?.toLowerCase() === wallet.toLowerCase()
              ? 'decline'
              : (() => {
                  throw new DomainInputError(
                    'Only the maker or fixed recipient can close this order.'
                  );
                })()
          : input.update;
      if (resolvedUpdate !== 'close') {
        assertLifecycleState(order, resolvedUpdate);
        if (wallet) assertLifecycleRole(order, wallet, resolvedUpdate);
      }
      const status = await this.#gateway.getStatus();
      if (resolvedUpdate !== 'close') {
        assertLifecycleContract(order, resolvedUpdate, status);
      }
      const intent: OrderUpdateIntent = {
        action: 'order_update',
        ...(order.orderType ? { orderType: order.orderType } : {}),
        wallet,
        order,
        update: resolvedUpdate,
        expiresAt
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(
        missing,
        resolvedUpdate !== 'extend_expiry' || Boolean(expiresAt),
        'expiresAt',
        'Choose the new expiry.'
      );
      if (order.kind === 'recurring') {
        if (!status.registry.recurringWritesEnabled) {
          return {
            ok: true,
            data: {
              status: 'unsupported',
              intent,
              missing,
              warnings: status.registry.warnings,
              envelope: null,
              reason: 'Recurring writes are disabled until the runtime manifest and deployed bytecode audit agree.'
            }
          };
        }
      }
      return { ok: true, data: await this.#finishPreparation(intent, missing) };
    } catch (error) {
      return toolFailure(error);
    }
  }

  async #resolveOrder(input: OrderIdentityInput): Promise<SafeOrderSummary> {
    const identity = normalizeOrderIdentity(input);
    await assertTrustedOrder(this.#gateway, identity);
    const rawOrder = await this.#gateway.getOrder(identity);
    if (!rawOrder) throw new DomainInputError('The ChainWhisper order was not found.', [], 'not_found');
    if (!(await this.#gateway.isTrustedEscrow(rawOrder.identity.escrowContract))) {
      throw new DomainInputError('The resolved order is not from a verified ChainWhisper contract.', [], 'provider_error');
    }
    return sanitizeOrder(rawOrder);
  }

  async #finishPreparation(intent: DomainIntent, missing: MissingDetail[]): Promise<PrepareResult> {
    if (missing.length > 0) {
      return {
        status: 'needs_input',
        intent,
        missing,
        warnings: [],
        envelope: null
      };
    }
    const execution = await this.#gateway.buildExecutionPlan(intent);
    validatePlan(intent, execution);
    if (!execution.simulation.ok) {
      return {
        status: 'unsupported',
        intent,
        missing: [],
        warnings: execution.simulation.warnings,
        envelope: null,
        reason: safeString(execution.simulation.errorCode, 'simulation_failed')
      };
    }
    const envelope = await this.#envelopeFactory.create(intent, execution);
    return {
      status: 'ready',
      intent,
      missing: [],
      warnings: execution.simulation.warnings,
      envelope
    };
  }
}
