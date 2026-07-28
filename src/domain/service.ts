import { canonicalDecimal, compareDecimals, invertDecimal, isPositiveDecimal } from './decimal.js';
import { DomainInputError, toolFailure } from './errors.js';
import {
  ORDER_CLASSIFICATION_IDS_V1,
  deriveOrderClassificationV1,
  type OrderClassificationIdV1
} from '../shared/orderClassification.js';
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
  MissingDetail,
  NormalizedPriceReference,
  OrderIdentityInput,
  OrderUpdateInput,
  OrderUpdateIntent,
  PrivacyBridgeInput,
  PrivacyBridgeIntent,
  PrivacyBridgeStatus,
  PrivacyBridgeStatusInput,
  PrepareResult,
  RawPriceReference,
  ResolvedAsset,
  SafeOrderSummary,
  SecretPolicy,
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

type CreateCadence = 'one-off' | 'recurring';

const CREATE_ORDER_TYPES = new Set<string>(ORDER_CLASSIFICATION_IDS_V1);

const axesForOrderType = (
  value: unknown,
  cadence: CreateCadence
): {
  id: OrderClassificationIdV1 | null;
  access: 'public' | 'unlisted' | 'direct';
  amountVisibility: 'visible' | 'private';
} | null => {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || !CREATE_ORDER_TYPES.has(value)) {
    throw new DomainInputError('Choose a canonical ChainWhisper order type.', [
      {
        field: 'orderType',
        message: `Use a ${cadence} order type returned by the tool schema.`
      }
    ]);
  }
  const id = value as OrderClassificationIdV1;
  if (
    (cadence === 'one-off' && !id.startsWith('one-off.')) ||
    (cadence === 'recurring' && !id.startsWith('recurring.'))
  ) {
    throw new DomainInputError(
      `${id} cannot be used for a ${cadence} order.`,
      [{ field: 'orderType', message: 'Order cadence does not match this tool.' }]
    );
  }
  const privateLiquidity = id.includes('.private-liquidity.');
  const access =
    id.endsWith('.unlisted') || id === 'one-off.unlisted'
      ? 'unlisted'
      : id.endsWith('.direct') || id === 'one-off.direct'
        ? 'direct'
        : 'public';
  return {
    id,
    access,
    amountVisibility: privateLiquidity ? 'private' : 'visible'
  };
};

const resolveCreateAxes = (
  input: {
    orderType?: unknown;
    access?: unknown;
    amountVisibility?: unknown;
  },
  cadence: CreateCadence
): {
  access: 'public' | 'unlisted' | 'direct';
  amountVisibility: 'visible' | 'private';
  explicitlySelected: boolean;
} => {
  const selected = axesForOrderType(input.orderType, cadence);
  const legacyAccess = normalizeAccess(input.access);
  const legacyVisibility = normalizeAmountVisibility(input.amountVisibility);
  if (
    selected &&
    input.access !== undefined &&
    legacyAccess !== selected.access
  ) {
    throw new DomainInputError('orderType conflicts with access.', [
      { field: 'access', message: `Expected ${selected.access}.` }
    ]);
  }
  if (
    selected &&
    input.amountVisibility !== undefined &&
    legacyVisibility !== selected.amountVisibility
  ) {
    throw new DomainInputError('orderType conflicts with amountVisibility.', [
      {
        field: 'amountVisibility',
        message: `Expected ${selected.amountVisibility}.`
      }
    ]);
  }
  return {
    access: selected?.access ?? legacyAccess,
    amountVisibility: selected?.amountVisibility ?? legacyVisibility,
    // Keep legacy axes useful for internal draft rendering, but never let
    // them authorize a new create flow. Public MCP callers must choose one
    // canonical orderType.
    explicitlySelected: Boolean(selected)
  };
};

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

const sortExecutableReferences = (
  references: NormalizedPriceReference[],
  side: ComparePriceReferencesInput['side']
): NormalizedPriceReference[] =>
  [...references].sort((left, right) => {
    const priceOrder = compareDecimals(rankingPrice(left), rankingPrice(right));
    if (priceOrder !== 0) return side === 'buy' ? priceOrder : -priceOrder;
    const timeOrder = Date.parse(right.observedAt) - Date.parse(left.observedAt);
    return timeOrder || left.id.localeCompare(right.id);
  });

export class ChainWhisperDomainService {
  readonly #gateway: DomainGateway;
  readonly #envelopeFactory: DomainEnvelopeFactory;

  constructor(gateway: DomainGateway, envelopeFactory: DomainEnvelopeFactory) {
    this.#gateway = gateway;
    this.#envelopeFactory = envelopeFactory;
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

  async prepareCreateTrade(input: CreateTradeInput): Promise<ToolResult<PrepareResult>> {
    try {
      rejectSensitiveOrArbitraryInput(input);
      assertAllowedKeys(input, [
        'wallet',
        'orderType',
        'offerAsset',
        'requestAsset',
        'offerAmount',
        'requestAmount',
        'access',
        'recipient',
        'amountVisibility',
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
      const selectedAxes = resolveCreateAxes(input, 'one-off');
      const access = selectedAxes.access;
      const recipient = normalizeAddress(input.recipient, 'recipient', false);
      const amountVisibility = selectedAxes.amountVisibility;
      const privateLiquidity = amountVisibility === 'private';
      const confidentialOffer =
        privateLiquidity ||
        (access !== 'public' && offerAsset?.kind === 'private-erc20');
      const confidentialRequest =
        privateLiquidity ||
        (access !== 'public' && requestAsset?.kind === 'private-erc20');
      if (confidentialOffer) {
        rejectSignerLocalAmount(
          input.offerAmount,
          'offerAmount',
          'Confidential offer amounts'
        );
      }
      if (confidentialRequest) {
        rejectSignerLocalAmount(
          input.requestAmount,
          'requestAmount',
          'Confidential request amounts'
        );
      }
      const offerAmount = offerAsset && !confidentialOffer
        ? normalizePositiveAmount(input.offerAmount, 'offerAmount', offerAsset.decimals)
        : null;
      const requestAmount = requestAsset && !confidentialRequest
        ? normalizePositiveAmount(input.requestAmount, 'requestAmount', requestAsset.decimals)
        : null;
      if (access === 'public' && recipient) {
        throw new DomainInputError('Public orders cannot be recipient-bound.', [
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
        expiresAt: normalizeExpiry(input.expiresAt),
        fillPolicy,
        secretPolicy: secretPolicyFor(access, recipient)
      };
      const missing: MissingDetail[] = [];
      requireMissing(
        missing,
        selectedAxes.explicitlySelected,
        'orderType',
        'Choose the exact one-off order type before preparing a transaction.'
      );
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(offerAsset), 'offerAsset', 'Choose the asset to sell.');
      requireMissing(missing, Boolean(requestAsset), 'requestAsset', 'Choose the asset to receive.');
      requireMissing(
        missing,
        confidentialOffer || Boolean(offerAmount),
        'offerAmount',
        'Enter the amount to sell.'
      );
      requireMissing(
        missing,
        confidentialRequest || Boolean(requestAmount),
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
        'orderType',
        'baseAsset',
        'quoteAsset',
        'buyPrice',
        'sellPrice',
        'buyQuoteLiquidity',
        'sellBaseLiquidity',
        'access',
        'recipient',
        'amountVisibility'
      ]);
      const wallet = normalizeWallet(input.wallet);
      const baseAsset = await resolveAsset(this.#gateway, input.baseAsset, 'baseAsset', false);
      const quoteAsset = await resolveAsset(this.#gateway, input.quoteAsset, 'quoteAsset', false);
      assertDistinctAssets(baseAsset, quoteAsset, ['baseAsset', 'quoteAsset']);
      const selectedAxes = resolveCreateAxes(input, 'recurring');
      const access = selectedAxes.access;
      const recipient = normalizeAddress(input.recipient, 'recipient', false);
      const amountVisibility = selectedAxes.amountVisibility;
      const privateLiquidity = amountVisibility === 'private';
      const buyPrice = normalizePositiveAmount(input.buyPrice, 'buyPrice', quoteAsset?.decimals ?? 78);
      const sellPrice = normalizePositiveAmount(input.sellPrice, 'sellPrice', quoteAsset?.decimals ?? 78);
      if (privateLiquidity && quoteAsset?.kind === 'private-erc20') {
        rejectSignerLocalAmount(
          input.buyQuoteLiquidity,
          'buyQuoteLiquidity',
          'Private quote-token recurring inventory'
        );
      }
      if (privateLiquidity && baseAsset?.kind === 'private-erc20') {
        rejectSignerLocalAmount(
          input.sellBaseLiquidity,
          'sellBaseLiquidity',
          'Private base-token recurring inventory'
        );
      }
      const buyQuoteLiquidity =
        privateLiquidity && quoteAsset?.kind === 'private-erc20'
        ? null
        : normalizePositiveAmount(
            input.buyQuoteLiquidity,
            'buyQuoteLiquidity',
            quoteAsset?.decimals ?? 78
          );
      const sellBaseLiquidity =
        privateLiquidity && baseAsset?.kind === 'private-erc20'
        ? null
        : normalizePositiveAmount(
            input.sellBaseLiquidity,
            'sellBaseLiquidity',
            baseAsset?.decimals ?? 78
          );
      if (access === 'public' && recipient) {
        throw new DomainInputError('Public recurring orders cannot be recipient-bound.', [
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
          { field: 'amountVisibility', message: 'Use visible amounts for a fully public-token pair.' }
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
        secretPolicy: secretPolicyFor(access, recipient)
      };
      const missing: MissingDetail[] = [];
      requireMissing(
        missing,
        selectedAxes.explicitlySelected,
        'orderType',
        'Choose the exact recurring order type before preparing a transaction.'
      );
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(missing, Boolean(baseAsset), 'baseAsset', 'Choose the recurring base asset.');
      requireMissing(missing, Boolean(quoteAsset), 'quoteAsset', 'Choose the recurring quote asset.');
      requireMissing(missing, Boolean(buyPrice), 'buyPrice', 'Enter the maker buy price in quote per base.');
      requireMissing(missing, Boolean(sellPrice), 'sellPrice', 'Enter the maker sell price in quote per base.');
      requireMissing(
        missing,
        privateLiquidity || Boolean(buyQuoteLiquidity || sellBaseLiquidity),
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
      assertAllowedKeys(input, ['wallet', 'order', 'inputAmount', 'minOutputAmount', 'recurringSide']);
      const wallet = normalizeWallet(input.wallet);
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
          'Private-liquidity output limits must stay inside the local signer.',
          [
            {
              field: 'minOutputAmount',
              message:
                'Remove this field from the public planner request.'
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
      let normalizedInputAmount = signerLocalPrivateAmount
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
          signerLocalPrivateOutput
            ? null
            : normalizePositiveAmount(
                input.minOutputAmount,
                'minOutputAmount',
                outputDecimals
              ),
        recurringSide,
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
        signerLocalPrivateAmount || Boolean(intent.inputAmount),
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
      assertAllowedKeys(input, ['wallet', 'order', 'offerAmount', 'requestAmount', 'expiresAt']);
      const wallet = normalizeWallet(input.wallet);
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
      if (confidentialOffer) {
        rejectSignerLocalAmount(
          input.offerAmount,
          'offerAmount',
          'Confidential counter offer amounts'
        );
      }
      if (confidentialRequest) {
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
        offerAmount: confidentialOffer
          ? null
          : normalizePositiveAmount(
              input.offerAmount,
              'offerAmount',
              counterOfferAsset.decimals
            ),
        requestAmount: confidentialRequest
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
        secretPolicy: { kind: 'recipient-bound', recipient: order.maker }
      };
      const missing: MissingDetail[] = [];
      requireMissing(missing, Boolean(wallet), 'wallet', 'Choose the local signer wallet.');
      requireMissing(
        missing,
        confidentialOffer || Boolean(intent.offerAmount),
        'offerAmount',
        'Enter what the counterparty receives.'
      );
      requireMissing(
        missing,
        confidentialRequest || Boolean(intent.requestAmount),
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
      assertAllowedKeys(input, ['wallet', 'order', 'changes']);
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
        if (
          order.amountVisibility === 'private' ||
          (order.orderType?.route === 'direct-escrow' &&
            order.offerAsset.kind === 'private-erc20')
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
        if (
          order.amountVisibility === 'private' ||
          (order.orderType?.route === 'direct-escrow' &&
            order.requestAsset.kind === 'private-erc20')
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
            inventoryAsset?.kind === 'private-erc20'
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
