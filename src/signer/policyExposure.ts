import { parseUnits } from 'ethers';

import type {
  NormalizedAssetV1,
  SignedActionEnvelopeV1,
} from '../shared/index.js';
import type {
  PrivacyBridgeDirection,
  PrivacyBridgePairId,
} from '../shared/privacyBridge.js';
import type {
  AutonomyAssetAmountV1,
  AutonomyPairV1,
  PolicyExposureV1,
} from './autonomy.js';
import type {
  MaterializedActionStep,
  TransactionFeeQuote,
} from './types.js';
import { materializedActionStepDigest } from './confirmation.js';

const unsigned = (value: unknown): value is string =>
  typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value);

const assetId = (asset: NormalizedAssetV1): string =>
  (asset.address ?? asset.reference ?? asset.symbol ?? '').toLowerCase();

const baseUnits = (amount: string, asset: NormalizedAssetV1): string =>
  parseUnits(amount, asset.decimals ?? 18).toString();

const positiveUnsigned = (value: unknown): value is string =>
  unsigned(value) && BigInt(value) > 0n;

const addAtomicAmount = (
  target: AutonomyAssetAmountV1[],
  asset: NormalizedAssetV1 | undefined,
  amount: unknown,
): void => {
  if (!asset || !positiveUnsigned(amount)) return;
  const id = assetId(asset);
  if (!id) return;
  const existing = target.find((entry) => entry.asset === id);
  if (existing) {
    existing.amount = (BigInt(existing.amount) + BigInt(amount)).toString();
  } else {
    target.push({ asset: id, amount });
  }
};

const decimalAmount = (
  value: unknown,
  asset: NormalizedAssetV1 | undefined,
): string | undefined => {
  if (!asset || typeof value !== 'string' || !value) return undefined;
  try {
    return baseUnits(value, asset);
  } catch {
    return undefined;
  }
};

const privateAmount = (
  envelope: SignedActionEnvelopeV1,
  steps: readonly MaterializedActionStep[],
  asset: NormalizedAssetV1 | undefined,
  ids: readonly string[],
): string | undefined => {
  if (!asset) return undefined;
  const expectedAsset = assetId(asset);
  for (const id of ids) {
    const definition = (envelope.privateArtifacts ?? [])
      .flatMap((group) => group.values)
      .find(
        (value) =>
          value.id === id &&
          value.kind === 'uint256' &&
          value.asset &&
          assetId(value.asset) === expectedAsset,
      );
    if (!definition) continue;
    const values = [
      ...new Set(
        steps.flatMap((step) => {
          const value = step.privateValues?.[id];
          return value === undefined ? [] : [value];
        }),
      ),
    ];
    if (values.length === 1 && unsigned(values[0])) return values[0];
    return undefined;
  }
  return undefined;
};

const exactAmount = (
  envelope: SignedActionEnvelopeV1,
  steps: readonly MaterializedActionStep[],
  asset: NormalizedAssetV1 | undefined,
  decimal: unknown,
  privateIds: readonly string[],
): string | undefined =>
  decimalAmount(decimal, asset) ??
  privateAmount(envelope, steps, asset, privateIds);

const hasPrivateAmount = (
  envelope: SignedActionEnvelopeV1,
  asset: NormalizedAssetV1 | undefined,
  id: string,
): boolean =>
  Boolean(
    asset &&
      (envelope.privateArtifacts ?? []).some((group) =>
        group.values.some(
          (value) =>
            value.id === id &&
            value.kind === 'uint256' &&
            value.asset &&
            assetId(value.asset) === assetId(asset),
        ),
      ),
  );

const exactRecurringDelta = (
  envelope: SignedActionEnvelopeV1,
  steps: readonly MaterializedActionStep[],
  asset: NormalizedAssetV1 | undefined,
  metadataField: string,
  privateId: string,
): string | undefined => {
  const signed = decimalAmount(
    envelope.intent.metadata?.[metadataField],
    asset,
  );
  if (signed !== undefined) return signed;
  if (hasPrivateAmount(envelope, asset, privateId)) {
    return privateAmount(envelope, steps, asset, [privateId]);
  }
  return '0';
};

type ExactPrice = {
  sellAmount: string;
  buyAmount: string;
};

const exactPrice = (
  sellAmount: string | undefined,
  buyAmount: string | undefined,
): ExactPrice | undefined =>
  positiveUnsigned(sellAmount) && positiveUnsigned(buyAmount)
    ? { sellAmount, buyAmount }
    : undefined;

const recurringEditPrice = (
  envelope: SignedActionEnvelopeV1,
  side: 'buy' | 'sell',
  baseAsset: NormalizedAssetV1,
  quoteAsset: NormalizedAssetV1,
): ExactPrice | undefined => {
  const metadata = envelope.intent.metadata;
  const changed = decimalAmount(metadata?.[`${side}Price`], quoteAsset);
  if (changed) {
    return exactPrice(baseUnits('1', baseAsset), changed);
  }
  const trustedBase = decimalAmount(
    metadata?.[
      side === 'buy' ? 'trustedBuyBaseAmount' : 'trustedSellBaseAmount'
    ],
    baseAsset,
  );
  const trustedQuote = decimalAmount(
    metadata?.[
      side === 'buy' ? 'trustedBuyQuoteAmount' : 'trustedSellQuoteAmount'
    ],
    quoteAsset,
  );
  if (trustedBase && trustedQuote) {
    return exactPrice(trustedBase, trustedQuote);
  }
  const trustedPrice = decimalAmount(
    metadata?.[side === 'buy' ? 'trustedBuyPrice' : 'trustedSellPrice'],
    quoteAsset,
  );
  return trustedPrice
    ? exactPrice(baseUnits('1', baseAsset), trustedPrice)
    : undefined;
};

const optionalBridge = (
  envelope: SignedActionEnvelopeV1,
): PolicyExposureV1['bridge'] => {
  if (envelope.intent.action !== 'privacy_bridge') return undefined;
  const pair = envelope.intent.metadata?.bridgePair;
  const direction = envelope.intent.metadata?.bridgeDirection;
  if (
    typeof pair !== 'string' ||
    (direction !== 'public-to-private' &&
      direction !== 'private-to-public')
  ) {
    return undefined;
  }
  return {
    pair: pair as PrivacyBridgePairId,
    direction: direction as PrivacyBridgeDirection,
  };
};

export const buildPolicyExposure = (options: {
  envelope: SignedActionEnvelopeV1;
  wallet: string;
  steps: MaterializedActionStep[];
  feeQuotes: Array<TransactionFeeQuote | undefined>;
}): PolicyExposureV1 => {
  const { envelope } = options;
  const sellAsset = envelope.intent.sellAsset;
  const buyAsset = envelope.intent.buyAsset;
  const recurring =
    envelope.intent.action === 'create_recurring' ||
    (
      envelope.intent.action === 'edit' &&
      envelope.intent.orderType?.cadence === 'recurring'
    );
  const pairs: AutonomyPairV1[] =
    sellAsset && buyAsset
      ? recurring
        ? [
            {
              sellAsset: assetId(sellAsset),
              buyAsset: assetId(buyAsset),
            },
            {
              sellAsset: assetId(buyAsset),
              buyAsset: assetId(sellAsset),
            },
          ]
        : [
            {
              sellAsset: assetId(sellAsset),
              buyAsset: assetId(buyAsset),
            },
          ]
      : [];
  const grossSpend: AutonomyAssetAmountV1[] = [];
  const minimumReceive: AutonomyAssetAmountV1[] = [];
  const priceQuotes: PolicyExposureV1['priceQuotes'] = [];
  let boundedRiskComplete: boolean;

  if (envelope.intent.action === 'create_recurring') {
    const baseInventory = exactRecurringDelta(
      envelope,
      options.steps,
      sellAsset,
      'sellBaseLiquidity',
      'recurring-base-inventory',
    );
    const quoteInventory = exactRecurringDelta(
      envelope,
      options.steps,
      buyAsset,
      'buyQuoteLiquidity',
      'recurring-quote-inventory',
    );
    addAtomicAmount(grossSpend, sellAsset, baseInventory);
    addAtomicAmount(grossSpend, buyAsset, quoteInventory);
    const buyPrice = decimalAmount(
      envelope.intent.metadata?.buyPrice,
      buyAsset,
    );
    const sellPrice = decimalAmount(
      envelope.intent.metadata?.sellPrice,
      buyAsset,
    );
    if (sellAsset && buyAsset && buyPrice && sellPrice) {
      priceQuotes.push(
        {
          sellAsset: assetId(sellAsset),
          buyAsset: assetId(buyAsset),
          sellAmount: baseUnits('1', sellAsset),
          buyAmount: sellPrice,
        },
        {
          sellAsset: assetId(buyAsset),
          buyAsset: assetId(sellAsset),
          sellAmount: buyPrice,
          buyAmount: baseUnits('1', sellAsset),
        },
      );
    }
    boundedRiskComplete =
      baseInventory !== undefined &&
      quoteInventory !== undefined &&
      priceQuotes.length === 2 &&
      grossSpend.length > 0;
  } else if (
    envelope.intent.action === 'edit' &&
    recurring &&
    sellAsset &&
    buyAsset
  ) {
    const addBase = exactRecurringDelta(
      envelope,
      options.steps,
      sellAsset,
      'addSellBaseLiquidity',
      'recurring-edit-add-base',
    );
    const addQuote = exactRecurringDelta(
      envelope,
      options.steps,
      buyAsset,
      'addBuyQuoteLiquidity',
      'recurring-edit-add-quote',
    );
    addAtomicAmount(grossSpend, sellAsset, addBase);
    addAtomicAmount(grossSpend, buyAsset, addQuote);
    const buyPrice = recurringEditPrice(
      envelope,
      'buy',
      sellAsset,
      buyAsset,
    );
    const sellPrice = recurringEditPrice(
      envelope,
      'sell',
      sellAsset,
      buyAsset,
    );
    if (buyPrice && sellPrice) {
      priceQuotes.push(
        {
          sellAsset: assetId(sellAsset),
          buyAsset: assetId(buyAsset),
          ...sellPrice,
        },
        {
          sellAsset: assetId(buyAsset),
          buyAsset: assetId(sellAsset),
          sellAmount: buyPrice.buyAmount,
          buyAmount: buyPrice.sellAmount,
        },
      );
    }
    boundedRiskComplete =
      addBase !== undefined &&
      addQuote !== undefined &&
      priceQuotes.length === 2;
  } else if (
    envelope.intent.action === 'create_trade' ||
    envelope.intent.action === 'counter' ||
    envelope.intent.action === 'edit'
  ) {
    const sellAmount = exactAmount(
      envelope,
      options.steps,
      sellAsset,
      envelope.intent.sellAmount,
      ['hidden-offer-amount', 'offer-amount'],
    );
    const buyAmount = exactAmount(
      envelope,
      options.steps,
      buyAsset,
      envelope.intent.buyAmount,
      ['hidden-request-amount', 'request-amount'],
    );
    addAtomicAmount(grossSpend, sellAsset, sellAmount);
    addAtomicAmount(minimumReceive, buyAsset, buyAmount);
    if (sellAsset && buyAsset) {
      const quote = exactPrice(sellAmount, buyAmount);
      if (quote) {
        priceQuotes.push({
          sellAsset: assetId(sellAsset),
          buyAsset: assetId(buyAsset),
          ...quote,
        });
      }
    }
    boundedRiskComplete =
      positiveUnsigned(sellAmount) && positiveUnsigned(buyAmount);
  } else if (envelope.intent.action === 'fill') {
    const sellAmount = exactAmount(
      envelope,
      options.steps,
      sellAsset,
      envelope.intent.sellAmount,
      ['recurring-fill-input', 'request-amount'],
    );
    const buyAmount = decimalAmount(
      envelope.intent.buyAmount,
      buyAsset,
    );
    addAtomicAmount(grossSpend, sellAsset, sellAmount);
    addAtomicAmount(minimumReceive, buyAsset, buyAmount);
    if (sellAsset && buyAsset) {
      const quote = exactPrice(sellAmount, buyAmount);
      if (quote) {
        priceQuotes.push({
          sellAsset: assetId(sellAsset),
          buyAsset: assetId(buyAsset),
          ...quote,
        });
      }
    }
    boundedRiskComplete =
      positiveUnsigned(sellAmount) && positiveUnsigned(buyAmount);
  } else if (envelope.intent.action === 'privacy_bridge') {
    const amount = decimalAmount(envelope.intent.sellAmount, sellAsset);
    addAtomicAmount(grossSpend, sellAsset, amount);
    addAtomicAmount(minimumReceive, buyAsset, amount);
    boundedRiskComplete = positiveUnsigned(amount);
  } else {
    // Lifecycle updates and structured messaging have no asset-price or
    // principal-spend term. Native value and fees remain bound below.
    boundedRiskComplete = true;
  }

  const maximumNetworkFee = options.feeQuotes
    .reduce(
      (sum, quote) =>
        sum + BigInt(quote?.maximumNetworkFeeWei ?? '0'),
      0n,
    )
    .toString();
  const nativeValue = unsigned(envelope.exactNativeValue)
    ? envelope.exactNativeValue
    : '0';
  const privateAmountMode = envelope.intent.metadata?.privateAmountMode;
  const sourceMaker =
    envelope.intent.action === 'fill'
      ? envelope.intent.metadata?.sourceMaker
      : undefined;
  const counterparty =
    envelope.intent.action === 'fill'
      ? typeof sourceMaker === 'string'
        ? sourceMaker
        : undefined
      : envelope.intent.recipient;

  return {
    wallet: options.wallet.toLowerCase(),
    chainId: envelope.chainId,
    manifestHash: envelope.registrySnapshot.manifestHash,
    operationHash: envelope.operationHash,
    action: envelope.intent.action,
    ...(envelope.intent.orderType
      ? { orderType: envelope.intent.orderType.id }
      : {}),
    pairs,
    priceQuotes,
    grossSpend,
    minimumReceive,
    ...(counterparty
      ? { counterparty: counterparty.toLowerCase() }
      : {}),
    ...(optionalBridge(envelope)
      ? { bridge: optionalBridge(envelope) }
      : {}),
    messageCount: envelope.intent.action === 'send_order_message' ? 1 : 0,
    nativeValue,
    maximumNetworkFee,
    boundedRiskComplete,
    agentProvidedPrivateAmounts: privateAmountMode === 'agent-provided',
    stepDigests: options.steps.map((step) =>
      materializedActionStepDigest(step),
    ),
  };
};
