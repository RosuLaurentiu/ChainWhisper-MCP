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

const addAmount = (
  target: AutonomyAssetAmountV1[],
  asset: NormalizedAssetV1 | undefined,
  amount: unknown,
): void => {
  if (!asset || typeof amount !== 'string' || !amount) return;
  const id = assetId(asset);
  if (!id) return;
  const normalized = baseUnits(amount, asset);
  const existing = target.find((entry) => entry.asset === id);
  if (existing) {
    existing.amount = (BigInt(existing.amount) + BigInt(normalized)).toString();
  } else {
    target.push({ asset: id, amount: normalized });
  }
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
  const pairs: AutonomyPairV1[] =
    sellAsset && buyAsset
      ? [
          {
            sellAsset: assetId(sellAsset),
            buyAsset: assetId(buyAsset),
          },
        ]
      : [];
  const grossSpend: AutonomyAssetAmountV1[] = [];
  const minimumReceive: AutonomyAssetAmountV1[] = [];
  addAmount(grossSpend, sellAsset, envelope.intent.sellAmount);
  addAmount(minimumReceive, buyAsset, envelope.intent.buyAmount);

  if (envelope.intent.action === 'create_recurring') {
    addAmount(
      grossSpend,
      sellAsset,
      envelope.intent.metadata?.sellBaseLiquidity,
    );
    addAmount(
      grossSpend,
      buyAsset,
      envelope.intent.metadata?.buyQuoteLiquidity,
    );
  }

  const priceQuotes =
    sellAsset &&
    buyAsset &&
    typeof envelope.intent.sellAmount === 'string' &&
    typeof envelope.intent.buyAmount === 'string'
      ? [
          {
            sellAsset: assetId(sellAsset),
            buyAsset: assetId(buyAsset),
            sellAmount: baseUnits(envelope.intent.sellAmount, sellAsset),
            buyAmount: baseUnits(envelope.intent.buyAmount, buyAsset),
          },
        ]
      : [];
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
    ...(envelope.intent.recipient
      ? { counterparty: envelope.intent.recipient.toLowerCase() }
      : {}),
    ...(optionalBridge(envelope)
      ? { bridge: optionalBridge(envelope) }
      : {}),
    messageCount: envelope.intent.action === 'send_order_message' ? 1 : 0,
    nativeValue,
    maximumNetworkFee,
    agentProvidedPrivateAmounts: privateAmountMode === 'agent-provided',
    stepDigests: options.steps.map((step) =>
      materializedActionStepDigest(step),
    ),
  };
};
