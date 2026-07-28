import type {
  Address,
  ConfirmationDiagnosticResult,
  ConfirmationRequest,
  FormElicitor,
  MaterializedActionStep,
} from './types.js';
import type { SignedActionEnvelopeV1 } from '../shared/index.js';
import { orderClassificationLabel } from '../shared/index.js';

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

const LEGACY_STANDARD_ORDER_TYPE_LABEL =
  'Legacy one-off / fixed recipient / public terms';

export const buildActionConfirmation = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  stepIndex: number,
): ConfirmationRequest => {
  const assets = [
    assetLabel(envelope.intent.sellAsset),
    assetLabel(envelope.intent.buyAsset),
  ].filter((asset): asset is string => Boolean(asset));
  const amounts = [
    envelope.intent.sellAmount,
    envelope.intent.buyAmount,
    ...(step.privateDisplayAmounts ?? []).map(
      (entry) => `${entry.amount} ${entry.symbol} (${entry.id})`,
    ),
  ].filter((amount): amount is string => Boolean(amount));
  const signedLegacyOrderTypeLabel =
    envelope.intent.metadata?.legacyCompatibility ===
      'standard-recipient-bound' &&
    envelope.intent.metadata?.legacyOrderTypeLabel ===
      LEGACY_STANDARD_ORDER_TYPE_LABEL
      ? LEGACY_STANDARD_ORDER_TYPE_LABEL
      : null;
  return {
    operationId: envelope.operationId,
    operationHash: envelope.operationHash,
    stepId: step.id,
    stepIndex,
    stepCount: envelope.steps.length,
    wallet: envelope.wallet,
    contract: step.to,
    action: envelope.intent.action,
    orderType: envelope.intent.orderType ?? null,
    orderTypeLabel: envelope.intent.orderType
      ? orderClassificationLabel(envelope.intent.orderType)
      : signedLegacyOrderTypeLabel,
    assets,
    amounts,
    counterparty: envelope.intent.recipient ?? null,
    spender: step.approval?.spender ?? null,
    fee:
      step.kind === 'approval'
        ? '0 native on this approval step'
        : envelope.intent.action === 'privacy_bridge'
          ? `${String(envelope.intent.metadata?.portalFeeAtomic ?? '0')} atomic COTI portal fee`
        : `${envelope.fee.amount} native`,
    nativeValue: step.value,
    gasCap: step.gasCap,
    expectedResult:
      step.kind === 'approval'
        ? 'Only the exact token allowance is updated. The order is not created until its separately confirmed protocol step succeeds.'
        : envelope.summary,
    summary: step.summary,
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

  async confirm(request: ConfirmationRequest): Promise<void> {
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
  }
}
