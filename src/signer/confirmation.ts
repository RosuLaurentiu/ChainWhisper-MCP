import type {
  Address,
  ConfirmationDiagnosticResult,
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

const LEGACY_STANDARD_ORDER_TYPE_LABEL =
  'Legacy one-off / fixed recipient / public terms';

const completeActionButtonLabel = (
  action: string,
): string => {
  switch (action) {
    case 'create_trade':
    case 'create_recurring':
      return 'Confirm complete order creation';
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
): ConfirmationRequest => {
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
  const metadataDetails = [
    ['Expiry', envelope.intent.expiresAt],
    ['Recurring side', envelope.intent.metadata?.recurringSide],
    ['Buy price', envelope.intent.metadata?.buyPrice],
    ['Sell price', envelope.intent.metadata?.sellPrice],
    [
      'Buy-side liquidity',
      envelope.intent.metadata?.buyQuoteLiquidity,
    ],
    [
      'Sell-side liquidity',
      envelope.intent.metadata?.sellBaseLiquidity,
    ],
    ['Bridge direction', envelope.intent.metadata?.bridgeDirection],
    ['Privacy pair', envelope.intent.metadata?.bridgePair],
  ] as const;
  for (const [label, value] of metadataDetails) {
    if (typeof value === 'string' && value) {
      details.push({ label, value });
    }
  }
  const signedLegacyOrderTypeLabel =
    envelope.intent.metadata?.legacyCompatibility ===
      'standard-recipient-bound' &&
    envelope.intent.metadata?.legacyOrderTypeLabel ===
      LEGACY_STANDARD_ORDER_TYPE_LABEL
      ? LEGACY_STANDARD_ORDER_TYPE_LABEL
      : null;
  const standaloneApproval =
    steps.length === 1 && protocolStep.kind === 'approval';
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
        ? '0 native on this approval step'
        : envelope.intent.action === 'privacy_bridge'
        ? `${String(envelope.intent.metadata?.portalFeeAtomic ?? '0')} atomic COTI portal fee`
        : `${envelope.fee.amount} native`,
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

  async diagnoseForm(
    wallet: Address,
  ): Promise<ConfirmationDiagnosticResult> {
    if (!this.#elicitor.isSupported()) {
      return {
        supported: false,
        outcome: 'unsupported',
        writeAttempted: false,
      };
    }
    const result = await withTimeout(
      this.#elicitor.requestConfirmation(
        {
          operationId: 'confirmation-form-diagnostic',
          operationHash: `0x${'00'.repeat(32)}`,
          stepId: 'diagnostic',
          stepIndex: 0,
          stepCount: 1,
          wallet,
          contract: '0x0000000000000000000000000000000000000000',
          action: 'confirmation_form_diagnostic',
          orderType: null,
          orderTypeLabel: 'Not applicable',
          assets: [],
          amounts: [],
          counterparty: null,
          spender: null,
          fee: '0',
          nativeValue: '0',
          gasCap: '0',
          expectedResult:
            'Only the MCP confirmation response is returned.',
          summary:
            'Read-only signer confirmation-form diagnostic; no transaction is prepared, signed, or broadcast.',
        },
        this.#timeoutMs,
      ),
      this.#timeoutMs,
    );
    if (result === 'timeout') {
      return {
        supported: true,
        outcome: 'timeout',
        writeAttempted: false,
      };
    }
    return {
      supported: true,
      outcome: result.outcome,
      ...('reason' in result && result.reason
        ? { reason: result.reason }
        : {}),
      writeAttempted: false,
    };
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
