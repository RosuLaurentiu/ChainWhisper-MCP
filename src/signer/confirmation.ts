import type {
  Address,
  ConfirmationRequest,
  FormElicitor,
  HexString,
  MaterializedActionStep,
  TransactionFeeQuote,
} from './types.js';
import type { SignedActionEnvelopeV1 } from '../shared/index.js';
import {
  canonicalize,
  orderClassificationLabel,
  sha256Hex,
} from '../shared/index.js';
import { formatUnits } from 'viem';

import { SignerError } from './errors.js';

const withTimeout = async <T>(
  promise: Promise<T>,
  timeoutMs: number,
): Promise<T | 'timeout'> => {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<'timeout'>((resolve) => {
        timeout = setTimeout(() => resolve('timeout'), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
};

const assetLabel = (
  asset: SignedActionEnvelopeV1['intent']['sellAsset'],
): string | null => asset?.symbol ?? asset?.reference ?? asset?.address ?? null;

const privateAmountLabel = (id: string): string => {
  const normalized = id.toLowerCase();
  if (
    normalized.includes('recurring-base-inventory') ||
    normalized.includes('recurring-sell-base-liquidity')
  ) {
    return 'Private sell-side inventory';
  }
  if (
    normalized.includes('recurring-quote-inventory') ||
    normalized.includes('recurring-buy-quote-liquidity')
  ) {
    return 'Private buy-side budget';
  }
  if (
    normalized.includes('offer') ||
    normalized.includes('sell') ||
    normalized.includes('input')
  ) {
    return 'Private send amount';
  }
  if (
    normalized.includes('request') ||
    normalized.includes('buy') ||
    normalized.includes('output')
  ) {
    return 'Private receive amount';
  }
  if (normalized.includes('inventory')) return 'Private inventory';
  if (normalized.includes('allowance')) return 'Exact private allowance';
  return 'Private signer amount';
};

const formatCotiAtomic = (atomic: string): string =>
  `${formatUnits(BigInt(atomic), 18)} COTI (${atomic} wei)`;

const formatCotiHuman = (atomic: string): string =>
  `${formatUnits(BigInt(atomic), 18)} COTI`;

const formatBasisPointDeviation = (basisPoints: number): string => {
  const sign = basisPoints > 0 ? '+' : '';
  return `${sign}${basisPoints / 100}% (${sign}${basisPoints} bps)`;
};

export type OrderReviewV1 = {
  version: 'cw.order-review/1';
  kind: 'recurring-create';
  title: string;
  pair: string;
  badges: string[];
  sellSide: {
    label: 'Sell inventory';
    asset: string;
    amount: string | null;
    price: string | null;
    priceUnit: string;
    offsetBps: number | null;
  };
  buySide: {
    label: 'Buy budget';
    asset: string;
    amount: string | null;
    price: string | null;
    priceUnit: string;
    offsetBps: number | null;
  };
  marketReference: {
    venue: string;
    price: string | null;
    priceUnit: string;
    observedAt: string | null;
    sourceId: string | null;
  } | null;
  protocolFeeCoti: string;
  maximumNetworkFeeCoti: string | null;
  networkTransactionCount: number;
  recurringExplanation: string;
  privacyExplanation: string;
  confirmationExplanation: string;
  confirmLabel: string;
};

export type ConfirmationRequestWithOrderReview =
  ConfirmationRequest & {
    /**
     * Local presentation data only. It is derived from the signed envelope and
     * exact materialized steps, and is never part of a planner/MCP schema.
     */
    orderReview?: OrderReviewV1;
  };

const LEGACY_STANDARD_ORDER_TYPE_LABEL =
  'Legacy one-off / fixed recipient / public terms';

const completeActionButtonLabel = (
  action: string,
): string => {
  switch (action) {
    case 'create_trade':
      return 'Confirm order';
    case 'create_recurring':
      return 'Confirm recurring order';
    case 'fill':
      return 'Confirm complete order fill';
    case 'counter':
      return 'Confirm complete counterorder creation';
    case 'edit':
      return 'Confirm complete order edit';
    case 'order_update':
      return 'Confirm complete order update';
    case 'privacy_bridge':
      return 'Confirm complete privacy conversion';
    default:
      return 'Confirm complete action';
  }
};

export const materializedActionStepDigest = (
  step: MaterializedActionStep,
): HexString =>
  sha256Hex(
    canonicalize({
      id: step.id,
      kind: step.kind,
      to: step.to.toLowerCase(),
      data: step.data.toLowerCase(),
      value: step.value,
      gasCap: step.gasCap,
    }),
  );

export const buildActionConfirmation = (
  envelope: SignedActionEnvelopeV1,
  stepOrSteps: MaterializedActionStep | MaterializedActionStep[],
  stepIndex: number,
  feeQuoteOrQuotes?: TransactionFeeQuote | Array<TransactionFeeQuote | undefined>,
): ConfirmationRequestWithOrderReview => {
  const steps = Array.isArray(stepOrSteps)
    ? stepOrSteps
    : [stepOrSteps];
  const quotes = Array.isArray(feeQuoteOrQuotes)
    ? feeQuoteOrQuotes
    : [feeQuoteOrQuotes];
  const protocolStep =
    [...steps].reverse().find((candidate) => candidate.kind === 'protocol') ??
    steps.at(-1);
  if (!protocolStep) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'The action has no materialized steps to confirm.',
    );
  }
  const sellAsset = assetLabel(envelope.intent.sellAsset);
  const buyAsset = assetLabel(envelope.intent.buyAsset);
  const assets = [sellAsset, buyAsset].filter(
    (asset): asset is string => Boolean(asset),
  );
  const amounts = [
    envelope.intent.sellAmount,
    envelope.intent.buyAmount,
    ...steps.flatMap((step) =>
      (step.privateDisplayAmounts ?? []).map(
        (entry) => `${entry.amount} ${entry.symbol} (${entry.id})`,
      ),
    ),
  ].filter((amount): amount is string => Boolean(amount));
  const details: NonNullable<ConfirmationRequest['details']> = [];
  if (envelope.intent.sellAmount && sellAsset) {
    details.push({
      label: 'You send',
      value: `${envelope.intent.sellAmount} ${sellAsset}`,
    });
  } else if (sellAsset) {
    details.push({ label: 'Sell asset', value: sellAsset });
  }
  if (envelope.intent.buyAmount && buyAsset) {
    details.push({
      label: 'You receive',
      value: `${envelope.intent.buyAmount} ${buyAsset}`,
    });
  } else if (buyAsset) {
    details.push({ label: 'Buy asset', value: buyAsset });
  }
  const displayedPrivateAmounts = new Set<string>();
  for (const entry of steps.flatMap(
    (step) => step.privateDisplayAmounts ?? [],
  )) {
    const displayKey = `${entry.id}:${entry.amount}:${entry.symbol}`;
    if (displayedPrivateAmounts.has(displayKey)) continue;
    displayedPrivateAmounts.add(displayKey);
    details.push({
      label: `${privateAmountLabel(entry.id)} (${entry.id})`,
      value: `${entry.amount} ${entry.symbol}`,
    });
  }
  const spenders = [
    ...new Set(
      steps
        .map((step) => step.approval?.spender)
        .filter((value): value is Address => Boolean(value)),
    ),
  ];
  for (const spender of spenders) {
    details.push({
      label: 'Allowance spender',
      value: spender,
    });
  }
  const maximumNetworkFeeWei = quotes.reduce(
    (total, quote) =>
      total + BigInt(quote?.maximumNetworkFeeWei ?? '0'),
    0n,
  );
  const maximumNetworkFeeCoti = formatUnits(
    maximumNetworkFeeWei,
    18,
  );
  if (quotes.some(Boolean)) {
    details.push({
      label: 'Maximum network cost',
      value: `${maximumNetworkFeeCoti} COTI (${maximumNetworkFeeWei.toString()} wei)`,
    });
  }
  const addDetail = (label: string, value: unknown): void => {
    if (typeof value === 'string' && value) {
      details.push({ label, value });
    }
  };
  addDetail('Expiry', envelope.intent.expiresAt);
  addDetail('Recurring side', envelope.intent.metadata?.recurringSide);
  const recurringPriceUnit =
    sellAsset && buyAsset ? `${buyAsset} per ${sellAsset}` : null;
  const privateRecurring =
    envelope.intent.orderType?.cadence === 'recurring' &&
    envelope.intent.orderType.id.includes('private-liquidity');
  const addRecurringPrice = (label: string, value: unknown): void => {
    if (typeof value !== 'string' || !value) return;
    details.push({
      label: recurringPriceUnit ? `${label} (${recurringPriceUnit})` : label,
      value: recurringPriceUnit ? `${value} ${recurringPriceUnit}` : value,
    });
  };
  addRecurringPrice(
    privateRecurring ? 'Buy price · public on-chain' : 'Buy price',
    envelope.intent.metadata?.buyPrice,
  );
  addRecurringPrice(
    privateRecurring ? 'Sell price · public on-chain' : 'Sell price',
    envelope.intent.metadata?.sellPrice,
  );
  if (privateRecurring) {
    const sellIsPrivate =
      envelope.intent.sellAsset?.kind === 'private-erc20';
    const buyIsPrivate =
      envelope.intent.buyAsset?.kind === 'private-erc20';
    const privateSides = [
      ...(sellIsPrivate ? ['sell inventory'] : []),
      ...(buyIsPrivate ? ['buy budget'] : []),
    ];
    const publicSides = [
      ...(!sellIsPrivate ? ['sell inventory'] : []),
      ...(!buyIsPrivate ? ['buy budget'] : []),
    ];
    const visibilityClause = (
      sides: string[],
      visibility: 'encrypted' | 'public',
    ): string =>
      `${sides.join(' and ')} ${sides.length === 1 ? 'is' : 'are'} ${visibility}.`;
    const amountVisibility =
      privateSides.length === 2
        ? 'Sell inventory and buy budget are encrypted.'
        : [
            ...(privateSides.length
              ? [visibilityClause(privateSides, 'encrypted')]
              : []),
            ...(publicSides.length
              ? [visibilityClause(publicSides, 'public')]
              : []),
          ].join(' ');
    details.push({
      label: 'On-chain visibility',
      value:
        `${amountVisibility} Buy and sell prices, addresses, and order activity are public.`,
    });
  }
  const buyBudget = envelope.intent.metadata?.buyQuoteLiquidity;
  if (typeof buyBudget === 'string' && buyBudget) {
    const privacySuffix = privateRecurring
      ? envelope.intent.buyAsset?.kind === 'private-erc20'
        ? ' · encrypted on-chain'
        : ' · public on-chain'
      : '';
    details.push({
      label: buyAsset
        ? `Buy-side budget${privacySuffix} (${buyAsset})`
        : `Buy-side budget${privacySuffix}`,
      value: buyAsset ? `${buyBudget} ${buyAsset}` : buyBudget,
    });
  }
  const sellInventory = envelope.intent.metadata?.sellBaseLiquidity;
  if (typeof sellInventory === 'string' && sellInventory) {
    const privacySuffix = privateRecurring
      ? envelope.intent.sellAsset?.kind === 'private-erc20'
        ? ' · encrypted on-chain'
        : ' · public on-chain'
      : '';
    details.push({
      label: sellAsset
        ? `Sell-side inventory${privacySuffix} (${sellAsset})`
        : `Sell-side inventory${privacySuffix}`,
      value: sellAsset
        ? `${sellInventory} ${sellAsset}`
        : sellInventory,
    });
  }
  addDetail(
    'Signed market reference source',
    envelope.intent.metadata?.marketReferenceId,
  );
  addDetail(
    'Signed market reference venue',
    envelope.intent.metadata?.marketReferenceVenue,
  );
  addRecurringPrice(
    'Signed market reference price',
    envelope.intent.metadata?.marketReferencePrice,
  );
  addDetail(
    'Signed market reference observed at',
    envelope.intent.metadata?.marketReferenceObservedAt,
  );
  const buyOffset = envelope.intent.metadata?.buyPriceOffsetBps;
  if (typeof buyOffset === 'number' && Number.isInteger(buyOffset)) {
    details.push({
      label: 'Buy-price deviation from market',
      value: formatBasisPointDeviation(buyOffset),
    });
  }
  const sellOffset = envelope.intent.metadata?.sellPriceOffsetBps;
  if (typeof sellOffset === 'number' && Number.isInteger(sellOffset)) {
    details.push({
      label: 'Sell-price deviation from market',
      value: formatBasisPointDeviation(sellOffset),
    });
  }
  addDetail('Bridge direction', envelope.intent.metadata?.bridgeDirection);
  addDetail('Privacy pair', envelope.intent.metadata?.bridgePair);
  const signedLegacyOrderTypeLabel =
    envelope.intent.metadata?.legacyCompatibility ===
      'standard-recipient-bound' &&
    envelope.intent.metadata?.legacyOrderTypeLabel ===
      LEGACY_STANDARD_ORDER_TYPE_LABEL
      ? LEGACY_STANDARD_ORDER_TYPE_LABEL
      : null;
  const standaloneApproval =
    steps.length === 1 && protocolStep.kind === 'approval';
  const recurringOrderReview = (() => {
    if (
      envelope.intent.action !== 'create_recurring' ||
      envelope.intent.orderType?.cadence !== 'recurring'
    ) {
      return undefined;
    }
    const metadata = envelope.intent.metadata;
    const priceUnit =
      sellAsset && buyAsset ? `${buyAsset} per ${sellAsset}` : 'quote per base';
    const privateAmounts = steps.flatMap(
      (step) => step.privateDisplayAmounts ?? [],
    );
    const privateAmount = (
      pattern: RegExp,
    ): string | null =>
      privateAmounts.find(({ id }) => pattern.test(id))?.amount ?? null;
    const metadataString = (key: string): string | null => {
      const value = metadata?.[key];
      return typeof value === 'string' && value.length > 0 ? value : null;
    };
    const metadataInteger = (key: string): number | null => {
      const value = metadata?.[key];
      return typeof value === 'number' && Number.isInteger(value)
        ? value
        : null;
    };
    const sellAmount =
      metadataString('sellBaseLiquidity') ??
      privateAmount(/(?:recurring-base-inventory|recurring-sell-base-liquidity)/iu);
    const buyAmount =
      metadataString('buyQuoteLiquidity') ??
      privateAmount(/(?:recurring-quote-inventory|recurring-buy-quote-liquidity)/iu);
    const accessBadge =
      envelope.intent.orderType.access === 'public'
        ? 'Public access'
        : envelope.intent.orderType.access === 'direct'
          ? 'Direct recipient'
          : 'Unlisted access';
    const liquidityBadge =
      envelope.intent.orderType.termsVisibility === 'hidden-liquidity'
        ? 'Private liquidity'
        : 'Visible liquidity';
    const assetsBadge =
      envelope.intent.orderType.assetPrivacy === 'fully-private'
        ? 'Private assets'
        : envelope.intent.orderType.assetPrivacy === 'hybrid-private'
          ? 'Public/private assets'
          : null;
    const marketVenue =
      metadataString('marketReferenceVenue') ?? 'Market reference';
    const marketPrice = metadataString('marketReferencePrice');
    const marketObservedAt = metadataString(
      'marketReferenceObservedAt',
    );
    const marketSourceId = metadataString('marketReferenceId');
    const hasMarketReference = Boolean(
      marketPrice ||
        marketObservedAt ||
        marketSourceId ||
        metadataString('marketReferenceVenue'),
    );
    const privateSell =
      envelope.intent.sellAsset?.kind === 'private-erc20';
    const privateBuy =
      envelope.intent.buyAsset?.kind === 'private-erc20';
    const privacyExplanation =
      privateSell && privateBuy
        ? 'Sell inventory and buy budget are encrypted on-chain. Prices, access, addresses, and order activity remain public.'
        : envelope.intent.orderType.termsVisibility === 'hidden-liquidity'
          ? 'Hidden liquidity is encrypted on-chain. Prices, access, addresses, and order activity remain public.'
          : 'Inventory, prices, access, addresses, and order activity are public on-chain.';
    return {
      version: 'cw.order-review/1',
      kind: 'recurring-create',
      title: 'Create recurring order',
      pair: `${sellAsset ?? 'Sell asset'} / ${buyAsset ?? 'Buy asset'}`,
      badges: [
        'Recurring',
        liquidityBadge,
        accessBadge,
        ...(assetsBadge ? [assetsBadge] : []),
      ],
      sellSide: {
        label: 'Sell inventory',
        asset: sellAsset ?? 'Sell asset',
        amount: sellAmount,
        price: metadataString('sellPrice'),
        priceUnit,
        offsetBps: metadataInteger('sellPriceOffsetBps'),
      },
      buySide: {
        label: 'Buy budget',
        asset: buyAsset ?? 'Buy asset',
        amount: buyAmount,
        price: metadataString('buyPrice'),
        priceUnit,
        offsetBps: metadataInteger('buyPriceOffsetBps'),
      },
      marketReference: hasMarketReference
        ? {
            venue: marketVenue,
            price: marketPrice,
            priceUnit,
            observedAt: marketObservedAt,
            sourceId: marketSourceId,
          }
        : null,
      protocolFeeCoti: standaloneApproval
        ? '0 COTI'
        : formatCotiHuman(envelope.fee.amount),
      maximumNetworkFeeCoti: quotes.some(Boolean)
        ? `${maximumNetworkFeeCoti} COTI`
        : null,
      networkTransactionCount: steps.length,
      recurringExplanation:
        'Recurring provides reusable two-sided liquidity. It does not schedule automatic trades.',
      privacyExplanation,
      confirmationExplanation:
        steps.length === 1
          ? 'This confirmation authorizes the exact order transaction shown here. The signer re-checks it before signing.'
          : `This one confirmation authorizes ${steps.length} exact network transactions needed for the complete order. The signer re-checks every transaction before signing.`,
      confirmLabel: 'Confirm recurring order',
    } satisfies OrderReviewV1;
  })();
  return {
    operationId: envelope.operationId,
    operationHash: envelope.operationHash,
    stepId:
      steps.length === 1
        ? protocolStep.id
        : `complete-action:${stepIndex}`,
    stepIndex,
    stepCount: envelope.steps.length,
    wallet: envelope.wallet,
    contract: protocolStep.to,
    action: envelope.intent.action,
    orderType: envelope.intent.orderType ?? null,
    orderTypeLabel: envelope.intent.orderType
      ? orderClassificationLabel(envelope.intent.orderType)
      : signedLegacyOrderTypeLabel,
    assets,
    amounts,
    details,
    counterparty: envelope.intent.recipient ?? null,
    spender: spenders[0] ?? null,
    fee:
      standaloneApproval
        ? '0 COTI (0 wei; approval step)'
        : envelope.intent.action === 'privacy_bridge'
        ? `${formatCotiAtomic(
            String(envelope.intent.metadata?.portalFeeAtomic ?? '0'),
          )}; Privacy Portal fee`
        : formatCotiAtomic(envelope.fee.amount),
    nativeValue: steps
      .reduce((total, step) => total + BigInt(step.value), 0n)
      .toString(),
    gasCap: steps
      .reduce((total, step) => total + BigInt(step.gasCap), 0n)
      .toString(),
    expectedResult: standaloneApproval
      ? 'Only the exact token allowance is updated. The order is not created until its separately confirmed protocol step succeeds.'
      : envelope.summary,
    summary: standaloneApproval
      ? protocolStep.summary
      : envelope.summary,
    authorizationScope: 'complete-logical-action',
    actionButtonLabel: completeActionButtonLabel(envelope.intent.action),
    maximumNetworkFeeWei: maximumNetworkFeeWei.toString(),
    maximumNetworkFeeCoti,
    stepDigests: steps.map(materializedActionStepDigest),
    ...(recurringOrderReview
      ? { orderReview: recurringOrderReview }
      : {}),
    technicalDetails: steps.map((step, index) => ({
      stepId: step.id,
      kind: step.kind,
      contract: step.to,
      selector: step.data.slice(0, 10) as HexString,
      calldataDigest: materializedActionStepDigest(step),
      gasCap: step.gasCap,
      maximumNetworkFeeWei:
        quotes[index]?.maximumNetworkFeeWei ?? '0',
    })),
  };
};

export class ConfirmationGate {
  readonly #elicitor: FormElicitor;
  readonly #timeoutMs: number;

  constructor(elicitor: FormElicitor, timeoutMs: number) {
    this.#elicitor = elicitor;
    this.#timeoutMs = timeoutMs;
  }

  get isWriteAvailable(): boolean {
    return this.#elicitor.isSupported();
  }

  async confirm(
    request: ConfirmationRequest,
  ): Promise<Record<string, string>> {
    if (!this.#elicitor.isSupported()) {
      throw new SignerError(
        'ELICITATION_UNSUPPORTED',
        'This MCP client does not support confirmation forms; signer tools are read-only.',
      );
    }
    const result = await withTimeout(
      this.#elicitor.requestConfirmation(request, this.#timeoutMs),
      this.#timeoutMs,
    );
    if (result === 'timeout' || result.outcome === 'timeout') {
      throw new SignerError(
        'CONFIRMATION_TIMEOUT',
        'Transaction confirmation timed out before signing.',
      );
    }
    if (
      result.outcome === 'declined' ||
      result.outcome === 'cancelled'
    ) {
      throw new SignerError(
        'CONFIRMATION_DECLINED',
        'Transaction confirmation was declined.',
      );
    }
    return result.values ?? {};
  }
}
