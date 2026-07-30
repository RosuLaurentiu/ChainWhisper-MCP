import {
  canonicalize,
  type SignedActionEnvelopeV1,
} from '../shared/index.js';

import {
  ConfirmationGate,
  buildActionConfirmation,
  materializedActionStepDigest,
} from './confirmation.js';
import { asSignerErrorCode, SignerError } from './errors.js';
import { OperationJournal } from './journal.js';
import { NonceQueue } from './nonceQueue.js';
import { EncryptedSecretVault } from './vault.js';
import { ActionEnvelopeVerifier } from './verification.js';
import {
  AutonomyPolicyManager,
  type AutonomyDecision,
  type AutonomyReservationV1,
  type AutonomyStatusV1,
  type PolicyExposureV1,
} from './autonomy.js';
import { buildPolicyExposure } from './policyExposure.js';
import { decodeCreatedOrderResult } from './orderResult.js';
import type {
  ExecuteActionResult,
  JournalReceipt,
  MaterializedActionStep,
  MaterializedIntentValidator,
  OperationJournalRecord,
  OperationSemanticResultV2,
  OperationStatusV2,
  PrivateInputMaterializer,
  RecoverOperationResult,
  TransactionSimulator,
  TransactionFeeQuote,
  WalletTransport,
} from './types.js';

const sameHex = (left: string, right: string): boolean =>
  left.toLowerCase() === right.toLowerCase();

const safeSimulationError = (value: string): string =>
  /^[A-Z0-9_-]{1,64}$/u.test(value) ? value : 'SIMULATION_FAILED';

const storedOperationReference = (operationId: string): string =>
  `operation:${operationId}:request`;

const storedResultReference = (operationId: string): string =>
  `operation:${operationId}:result`;

const isMessageOperationId = (operationId: string): boolean =>
  /^message-[0-9a-f]{16}$/u.test(operationId);

type StoredOperationV1 = {
  version: 1;
  envelope: SignedActionEnvelopeV1;
  policyId?: string;
  policyExposure?: PolicyExposureV1;
  /** Per-envelope-step network-fee ceilings captured at authorization time. */
  policyStepFeeCeilings?: string[];
};

type StoredResultV1 = {
  version: 1;
  summary: string;
  result: OperationSemanticResultV2;
};

const parseStoredOperation = (value: string | null): StoredOperationV1 | null => {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<StoredOperationV1>;
    return parsed.version === 1 &&
      parsed.envelope?.version === 'cw.action/1' &&
      typeof parsed.envelope.operationId === 'string' &&
      typeof parsed.envelope.operationHash === 'string' &&
      (parsed.policyId === undefined || typeof parsed.policyId === 'string') &&
      (parsed.policyExposure === undefined ||
        (typeof parsed.policyExposure === 'object' &&
          parsed.policyExposure !== null &&
          !Array.isArray(parsed.policyExposure))) &&
      (parsed.policyStepFeeCeilings === undefined ||
        (Array.isArray(parsed.policyStepFeeCeilings) &&
          parsed.policyStepFeeCeilings.every(
            (entry) =>
              typeof entry === 'string' &&
              /^(?:0|[1-9][0-9]*)$/u.test(entry),
          )))
      ? (parsed as StoredOperationV1)
      : null;
  } catch {
    return null;
  }
};

const parseStoredResult = (value: string | null): StoredResultV1 | null => {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<StoredResultV1>;
    return parsed.version === 1 &&
      typeof parsed.summary === 'string' &&
      parsed.result?.status === 'completed' &&
      typeof parsed.result.action === 'string'
      ? (parsed as StoredResultV1)
      : null;
  } catch {
    return null;
  }
};

const operationState = (
  record: OperationJournalRecord,
  active: boolean,
): OperationStatusV2['status'] => {
  const errorCode = record.errorCodes.at(-1);
  if (record.stage === 'completed') {
    return active ? 'confirming' : 'completed';
  }
  if (record.stage === 'declined') return 'declined';
  if (record.stage === 'discarded') return 'declined';
  if (
    errorCode === 'ELICITATION_UNSUPPORTED' ||
    errorCode === 'CONTROL_PANEL_OPEN_REQUIRED'
  ) {
    return 'needs_confirmation';
  }
  if (
    errorCode === 'CONFIRMATION_DECLINED' ||
    errorCode === 'CONFIRMATION_TIMEOUT'
  ) {
    return 'declined';
  }
  if (
    errorCode === 'ENVELOPE_EXPIRED' ||
    errorCode === 'STALE_STATE' ||
    errorCode === 'OPERATION_REPREPARE_REQUIRED'
  ) {
    return 'needs_reprepare';
  }
  if (
    errorCode === 'PRIVACY_SETUP_REQUIRED' ||
    errorCode === 'PRIVATE_TOKEN_SETUP_REQUIRED'
  ) {
    return 'needs_setup';
  }
  if (errorCode === 'PRIVATE_INPUT_UNAVAILABLE') {
    return 'needs_private_input';
  }
  if (record.stage === 'awaiting-confirmation') {
    return 'needs_confirmation';
  }
  if (record.stage === 'awaiting-broadcast') return 'signing';
  if (record.stage === 'prepared-broadcast') {
    return active ? 'broadcasting' : 'uncertain';
  }
  if (record.stage === 'broadcast') return 'confirming';
  if (record.stage === 'failed' && !active) return 'failed';
  if (record.nextStepIndex > 0) return 'signing';
  return active ? 'queued' : 'needs_reprepare';
};

const publicErrorCode = (
  record: OperationJournalRecord,
): string | undefined => {
  if (record.stage === 'declined') {
    return [...record.errorCodes]
      .reverse()
      .find(
        (code) =>
          code === 'CONFIRMATION_DECLINED' ||
          code === 'CONFIRMATION_TIMEOUT',
      ) ?? record.errorCodes.at(-1);
  }
  return record.errorCodes.at(-1);
};

const isFailedOperation = (
  record: OperationJournalRecord,
): boolean => operationState(record, false) === 'failed';

const isTerminalReplayError = (errorCode: string | undefined): boolean =>
  errorCode === 'CONFIRMATION_DECLINED' ||
  errorCode === 'CONFIRMATION_TIMEOUT' ||
  errorCode?.startsWith('AUTONOMY_') === true;

const requiresFreshEnvelope = (errorCode: string | undefined): boolean =>
  errorCode === 'ENVELOPE_EXPIRED' ||
  errorCode === 'STALE_STATE' ||
  errorCode === 'OPERATION_REPREPARE_REQUIRED';

const semanticResult = (
  envelope: SignedActionEnvelopeV1 | null,
  createdOrder?: OperationSemanticResultV2,
): OperationSemanticResultV2 | undefined => {
  if (createdOrder) return createdOrder;
  if (!envelope) return undefined;
  return {
    action: envelope.intent.action,
    status: 'completed',
    ...(envelope.intent.orderType
      ? { canonicalType: envelope.intent.orderType }
      : {}),
  };
};

const expectsCreatedOrderResult = (
  envelope: SignedActionEnvelopeV1 | null,
): boolean =>
  Boolean(
    envelope?.intent.orderType?.relation === 'primary' &&
      (
        envelope.intent.action === 'create_trade' ||
        envelope.intent.action === 'create_recurring'
      ),
  );

const redactedSummary = (envelope: SignedActionEnvelopeV1): string =>
  `ChainWhisper ${envelope.intent.action.replaceAll('_', ' ')} completed.`;

const feeQuoteAtCeiling = (
  maximumNetworkFeeWei: string,
): TransactionFeeQuote => ({
  model: 'eip1559',
  maximumNetworkFeeWei,
  maximumNetworkFeeCoti: '0',
  maximumFeePerGasWei: '0',
});

const sameAutonomyTermsExceptNetworkFee = (
  authorized: PolicyExposureV1,
  current: PolicyExposureV1,
): boolean => {
  const {
    maximumNetworkFee: _authorizedNetworkFee,
    ...authorizedTerms
  } = authorized;
  const {
    maximumNetworkFee: _currentNetworkFee,
    ...currentTerms
  } = current;
  return canonicalize(authorizedTerms) === canonicalize(currentTerms);
};

const privateAssetSymbols = (
  envelope: SignedActionEnvelopeV1 | null,
): string[] => {
  if (!envelope) return [];
  const assets = [
    envelope.intent.sellAsset,
    envelope.intent.buyAsset,
    ...(envelope.privateArtifacts ?? []).flatMap(({ values }) =>
      values.map(({ asset }) => asset),
    ),
  ];
  return [
    ...new Set(
      assets.flatMap((asset) =>
        asset?.kind === 'private-erc20'
          ? [asset.symbol ?? asset.reference]
          : [],
      ),
    ),
  ];
};

const toResult = (
  record: OperationJournalRecord,
  status: ExecuteActionResult['status'],
  errorCode?: string,
): ExecuteActionResult => ({
  operationId: record.operationId,
  operationHash: record.operationHash,
  status,
  transactionHashes: [...record.transactionHashes],
  ...(errorCode ? { errorCode } : {}),
});

export class SignerEngine {
  readonly #verifier: ActionEnvelopeVerifier;
  readonly #wallet: WalletTransport;
  readonly #materializer: PrivateInputMaterializer;
  readonly #confirmation: ConfirmationGate;
  readonly #simulator: TransactionSimulator;
  readonly #intentValidator: MaterializedIntentValidator;
  readonly #journal: OperationJournal;
  readonly #vault: EncryptedSecretVault;
  readonly #nonceQueue: NonceQueue;
  readonly #autonomy: AutonomyPolicyManager | null;
  readonly #activeOperations = new Map<string, Promise<ExecuteActionResult>>();
  readonly #discardingOperations = new Set<string>();
  #manualExecutionQueue: Promise<void> = Promise.resolve();

  constructor(options: {
    verifier: ActionEnvelopeVerifier;
    wallet: WalletTransport;
    materializer: PrivateInputMaterializer;
    confirmation: ConfirmationGate;
    simulator: TransactionSimulator;
    intentValidator: MaterializedIntentValidator;
    journal: OperationJournal;
    vault: EncryptedSecretVault;
    nonceQueue?: NonceQueue;
    autonomy?: AutonomyPolicyManager;
  }) {
    this.#verifier = options.verifier;
    this.#wallet = options.wallet;
    this.#materializer = options.materializer;
    this.#confirmation = options.confirmation;
    this.#simulator = options.simulator;
    this.#intentValidator = options.intentValidator;
    this.#journal = options.journal;
    this.#vault = options.vault;
    this.#nonceQueue =
      options.nonceQueue ??
      new NonceQueue(() => this.#wallet.getPendingNonce());
    this.#autonomy = options.autonomy ?? null;
  }

  get nonceQueue(): NonceQueue {
    return this.#nonceQueue;
  }

  pauseAutonomy(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#nonceQueue.runExclusive(() =>
      this.#autonomy
        ? this.#autonomy.pauseGlobal()
        : Promise.resolve({
            allowed: true,
            value: {
              globalPaused: false,
              policies: [],
              activeReservationCount: 0,
            },
          }),
    );
  }

  async queueAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
  ): Promise<OperationStatusV2> {
    const wallet = await this.#wallet.getAddress();
    if ((await this.#wallet.getChainId()) !== envelope.chainId) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The configured wallet is connected to an unexpected chain.',
      );
    }
    await this.#verifier.verify(envelope, wallet);
    let record = await this.#journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );
    if (!sameHex(record.operationHash, envelope.operationHash)) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Operation id was already used for a different action hash.',
      );
    }
    if (record.stage === 'discarded') {
      throw new SignerError(
        'OPERATION_DISCARDED',
        'This operation was discarded locally.',
      );
    }
    if (record.stage === 'completed') {
      if (!record.semanticResult && expectsCreatedOrderResult(envelope)) {
        record = await this.#backfillCreatedOrderResult(record, envelope);
      }
      return this.#publicStatus(
        record,
        envelope,
        parseStoredResult(
          await this.#vault.get(
            storedResultReference(envelope.operationId),
          ),
        ),
      );
    }
    const lastError = record.errorCodes.at(-1);
    if (
      record.stage === 'declined' ||
      isFailedOperation(record) ||
      isTerminalReplayError(lastError) ||
      requiresFreshEnvelope(lastError)
    ) {
      return this.#publicStatus(record, null);
    }
    const existingStored = parseStoredOperation(
      await this.#vault.get(storedOperationReference(envelope.operationId)),
    );
    const matchingStored =
      existingStored &&
      existingStored.envelope.operationId === envelope.operationId &&
      sameHex(existingStored.envelope.operationHash, envelope.operationHash)
        ? existingStored
        : null;
    if (this.#discardingOperations.has(envelope.operationId)) {
      throw new SignerError(
        'OPERATION_IN_PROGRESS',
        'This operation is being discarded in local Agent Control.',
      );
    }
    if (this.#activeOperations.has(envelope.operationId)) {
      return this.#publicStatus(record, envelope);
    }
    if (
      matchingStored?.policyExposure &&
      matchingStored.policyId !== policyId
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'This operation is already bound to a different autonomy authorization.',
      );
    }
    const policyExposure =
      matchingStored && matchingStored.policyId === policyId
        ? matchingStored.policyExposure
        : undefined;
    const policyStepFeeCeilings =
      matchingStored && matchingStored.policyId === policyId
        ? matchingStored.policyStepFeeCeilings
        : undefined;
    await this.#storeOperation(
      envelope,
      policyId,
      policyExposure,
      policyStepFeeCeilings,
    );
    if (!policyId && !this.#confirmation.isWriteAvailable) {
      record =
        (await this.#journal.recordError(
          envelope.operationId,
          'CONTROL_PANEL_OPEN_REQUIRED',
          true,
        )) ?? record;
      return this.#publicStatus(record, envelope);
    }
    if (this.#discardingOperations.has(envelope.operationId)) {
      throw new SignerError(
        'OPERATION_IN_PROGRESS',
        'This operation is being discarded in local Agent Control.',
      );
    }
    this.#startBackground(
      envelope,
      policyId,
      policyExposure,
      policyStepFeeCeilings,
    );
    record =
      (await this.#journal.get(envelope.operationId)) ?? record;
    return this.#publicStatus(record, envelope);
  }

  #startBackground(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
    policyExposure?: PolicyExposureV1,
    policyStepFeeCeilings?: string[],
  ): void {
    if (this.#activeOperations.has(envelope.operationId)) return;
    const execution = this.#scheduleExecution(
      envelope,
      policyId,
      policyExposure,
      policyStepFeeCeilings,
    )
      .then(async (result) => {
        if (
          result.status === 'completed' ||
          result.status === 'declined' ||
          result.status === 'denied' ||
          result.status === 'read-only'
        ) {
          try {
            if (result.status === 'completed') {
              const completedRecord = await this.#journal.get(
                envelope.operationId,
              );
              const completedResult = semanticResult(
                envelope,
                completedRecord?.semanticResult,
              )!;
              await this.#vault.put(
                storedResultReference(envelope.operationId),
                JSON.stringify({
                  version: 1,
                  summary: redactedSummary(envelope),
                  result: completedResult,
                } satisfies StoredResultV1),
                { kind: 'recovery-note' },
              );
              if (
                expectsCreatedOrderResult(envelope) &&
                !completedResult.order
              ) {
                return result;
              }
            }
            await this.#vault.delete(
              storedOperationReference(envelope.operationId),
            );
          } catch {
            await this.#journal.recordError(
              envelope.operationId,
              'LOCAL_CLEANUP_REQUIRED',
              false,
            );
          }
        }
        return result;
      })
      .catch(async (error): Promise<ExecuteActionResult> => {
        const errorCode = asSignerErrorCode(error);
        const record =
          (await this.#journal.recordError(
            envelope.operationId,
            errorCode,
            true,
          )) ??
          (await this.#journal.get(envelope.operationId));
        if (!record) throw error;
        return toResult(record, 'retryable', errorCode);
      })
      .finally(() => {
        this.#activeOperations.delete(envelope.operationId);
      });
    this.#activeOperations.set(envelope.operationId, execution);
  }

  #scheduleExecution(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
    policyExposure?: PolicyExposureV1,
    policyStepFeeCeilings?: string[],
  ): Promise<ExecuteActionResult> {
    if (policyId) {
      return this.#executeAction(
        envelope,
        policyId,
        policyExposure,
        policyStepFeeCeilings,
      );
    }
    const execution = this.#manualExecutionQueue.then(() =>
      this.#executeAction(envelope),
    );
    this.#manualExecutionQueue = execution.then(
      () => undefined,
      () => undefined,
    );
    return execution;
  }

  async #storeOperation(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
    policyExposure?: PolicyExposureV1,
    policyStepFeeCeilings?: string[],
  ): Promise<void> {
    await this.#vault.put(
      storedOperationReference(envelope.operationId),
      JSON.stringify({
        version: 1,
        envelope,
        ...(policyId ? { policyId } : {}),
        ...(policyExposure ? { policyExposure } : {}),
        ...(policyStepFeeCeilings
          ? { policyStepFeeCeilings }
          : {}),
      } satisfies StoredOperationV1),
      { kind: 'recovery-note' },
    );
  }

  async executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
  ): Promise<ExecuteActionResult> {
    const active = this.#activeOperations.get(envelope.operationId);
    if (active) return active;
    const execution = this.#scheduleExecution(envelope, policyId).finally(
      () => {
        this.#activeOperations.delete(envelope.operationId);
      },
    );
    this.#activeOperations.set(envelope.operationId, execution);
    return execution;
  }

  async restorePendingOperations(): Promise<void> {
    const records = await this.#journal.list();
    for (const record of records) {
      if (isMessageOperationId(record.operationId)) continue;
      const lastError = record.errorCodes.at(-1);
      if (
        record.stage === 'completed' ||
        record.stage === 'declined' ||
        record.stage === 'discarded' ||
        isFailedOperation(record) ||
        isTerminalReplayError(lastError) ||
        requiresFreshEnvelope(lastError)
      ) {
        continue;
      }
      const stored = parseStoredOperation(
        await this.#vault.get(
          storedOperationReference(record.operationId),
        ),
      );
      if (
        !stored ||
        stored.envelope.operationId !== record.operationId ||
        !sameHex(stored.envelope.operationHash, record.operationHash)
      ) {
        await this.#journal.recordError(
          record.operationId,
          'OPERATION_REPREPARE_REQUIRED',
          true,
        );
        continue;
      }
      this.#startBackground(
        stored.envelope,
        stored.policyId,
        stored.policyExposure,
        stored.policyStepFeeCeilings,
      );
    }
  }

  async #executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
    storedPolicyExposure?: PolicyExposureV1,
    storedPolicyStepFeeCeilings?: string[],
  ): Promise<ExecuteActionResult> {
    const wallet = await this.#wallet.getAddress();
    const walletChainId = await this.#wallet.getChainId();
    if (walletChainId !== envelope.chainId) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The configured wallet is connected to an unexpected chain.',
      );
    }
    await this.#verifier.verify(envelope, wallet);
    if (!policyId && !this.#confirmation.isWriteAvailable) {
      return {
        operationId: envelope.operationId,
        operationHash: envelope.operationHash,
        status: 'read-only',
        transactionHashes: [],
        errorCode: 'ELICITATION_UNSUPPORTED',
      };
    }

    let record = await this.#journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );
    if (!sameHex(record.operationHash, envelope.operationHash)) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Operation id was already used for a different action hash.',
      );
    }
    if (record.stage === 'discarded') {
      throw new SignerError(
        'OPERATION_DISCARDED',
        'This operation was discarded locally.',
      );
    }
    if (record.stage === 'declined') {
      return toResult(
        record,
        'declined',
        record.errorCodes.at(-1),
      );
    }
    if (record.stage === 'completed') return toResult(record, 'completed');
    const previousError = record.errorCodes.at(-1);
    if (requiresFreshEnvelope(previousError)) {
      return toResult(record, 'retryable', previousError);
    }

    if (
      record.stage === 'broadcast' ||
      record.stage === 'prepared-broadcast' ||
      record.stage === 'awaiting-broadcast'
    ) {
      const recovered = await this.recoverOperation(
        record.operationId,
        record.operationHash,
      );
      if (recovered.status === 'processing') {
        return {
          operationId: recovered.operationId,
          operationHash: recovered.operationHash,
          status: 'processing',
          transactionHashes: recovered.transactionHashes,
        };
      }
      record =
        (await this.#journal.get(envelope.operationId)) ??
        record;
    }

    const firstStepIndex = record.nextStepIndex;
    let policyExposure = storedPolicyExposure;
    let policyStepFeeCeilings = storedPolicyStepFeeCeilings;
    if (policyId && (!policyExposure || !policyStepFeeCeilings)) {
      const stored = parseStoredOperation(
        await this.#vault.get(
          storedOperationReference(envelope.operationId),
        ),
      );
      if (
        stored?.policyId === policyId &&
        stored.envelope.operationId === envelope.operationId &&
        sameHex(stored.envelope.operationHash, envelope.operationHash)
      ) {
        policyExposure ??= stored.policyExposure;
        policyStepFeeCeilings ??= stored.policyStepFeeCeilings;
      }
    }
    const materializedSteps: MaterializedActionStep[] = [];
    const exposureSteps: MaterializedActionStep[] = [];
    const authorizedFeeQuotes: Array<
      TransactionFeeQuote | undefined
    > = [];
    const authorizedStepDigests: string[] = [];
    let autonomyReservation: AutonomyReservationV1 | null = null;
    let autonomySigned = false;

    for (
      let stepIndex = policyId ? 0 : firstStepIndex;
      stepIndex < envelope.steps.length;
      stepIndex += 1
    ) {
      try {
        await this.#verifier.verify(envelope, wallet);
        const materialized = await this.#materializer.materializeStep(
          envelope,
          stepIndex,
        );
        this.#assertMaterialization(
          envelope,
          stepIndex,
          materialized,
        );
        if (policyId) {
          exposureSteps.push(materialized);
        }
        if (stepIndex < firstStepIndex) {
          continue;
        }
        await this.#intentValidator.validate(
          envelope,
          materialized,
          stepIndex,
        );
        const simulation = await this.#simulator.simulate(
          {
            to: materialized.to,
            data: materialized.data,
            value: BigInt(materialized.value),
            gasLimit: BigInt(materialized.gasCap),
          },
          wallet,
        );
        if (!simulation.ok) {
          const errorCode = safeSimulationError(simulation.errorCode);
          record =
            (await this.#journal.recordError(
              envelope.operationId,
              errorCode,
              true,
            )) ?? record;
          return toResult(record, 'retryable', errorCode);
        }
        if (policyStepFeeCeilings) {
          const ceiling = policyStepFeeCeilings[stepIndex];
          if (ceiling === undefined) {
            throw new SignerError(
              'OPERATION_REPREPARE_REQUIRED',
              'The stored autonomy authorization is missing a per-step fee ceiling.',
            );
          }
          this.#assertPersistedFeeCeiling(
            ceiling,
            simulation.feeQuote,
          );
        }
        materializedSteps.push(materialized);
        authorizedFeeQuotes.push(simulation.feeQuote);
        authorizedStepDigests.push(
          materializedActionStepDigest(materialized),
        );
      } catch (error) {
        const errorCode = asSignerErrorCode(error);
        if (
          errorCode === 'CONFIRMATION_DECLINED' ||
          errorCode === 'CONFIRMATION_TIMEOUT' ||
          errorCode === 'ELICITATION_UNSUPPORTED'
        ) {
          await this.#journal.recordError(
            envelope.operationId,
            errorCode,
            false,
          );
          record =
            (await this.#journal.get(envelope.operationId)) ??
            record;
          return toResult(record, 'declined', errorCode);
        }
        await this.#journal.recordError(
          envelope.operationId,
          errorCode,
          true,
        );
        record =
          (await this.#journal.updateStage(
            envelope.operationId,
            'validated',
            firstStepIndex,
          )) ?? record;
        return toResult(record, 'retryable', errorCode);
      }
    }

    try {
      if (policyId) {
        if (!this.#autonomy) {
          const errorCode = 'AUTONOMY_UNAVAILABLE';
          await this.#journal.recordError(
            envelope.operationId,
            errorCode,
            true,
          );
          record =
            (await this.#journal.get(envelope.operationId)) ??
            record;
          return {
            operationId: envelope.operationId,
            operationHash: envelope.operationHash,
            status: 'denied',
            transactionHashes: [...record.transactionHashes],
            errorCode,
            autonomyDenial: {
              code: 'POLICY_NOT_FOUND',
              message: 'Autonomy is not available in this signer session.',
              policyId,
            },
          };
        }
        if (!policyExposure || !policyStepFeeCeilings) {
          if (
            firstStepIndex > 0 ||
            policyExposure !== undefined ||
            policyStepFeeCeilings !== undefined
          ) {
            throw new SignerError(
              'OPERATION_REPREPARE_REQUIRED',
              'The stored autonomy authorization is incomplete and cannot be resumed.',
            );
          }
          policyStepFeeCeilings = authorizedFeeQuotes.map(
            (quote) => quote?.maximumNetworkFeeWei ?? '0',
          );
          policyExposure = buildPolicyExposure({
            envelope,
            wallet,
            steps: exposureSteps,
            feeQuotes: authorizedFeeQuotes,
          });
          await this.#storeOperation(
            envelope,
            policyId,
            policyExposure,
            policyStepFeeCeilings,
          );
        } else {
          if (
            policyStepFeeCeilings.length !== envelope.steps.length ||
            policyStepFeeCeilings.reduce(
              (total, ceiling) => total + BigInt(ceiling),
              0n,
            ) !== BigInt(policyExposure.maximumNetworkFee)
          ) {
            throw new SignerError(
              'OPERATION_REPREPARE_REQUIRED',
              'The stored autonomy fee authorization does not match the complete action.',
            );
          }
          const currentFeeQuotes = envelope.steps.map(
            (_step, stepIndex) =>
              stepIndex < firstStepIndex
                ? feeQuoteAtCeiling(policyStepFeeCeilings![stepIndex]!)
                : authorizedFeeQuotes[stepIndex - firstStepIndex],
          );
          const currentExposure = buildPolicyExposure({
            envelope,
            wallet,
            steps: exposureSteps,
            feeQuotes: currentFeeQuotes,
          });
          if (
            !sameAutonomyTermsExceptNetworkFee(
              policyExposure,
              currentExposure,
            )
          ) {
            throw new SignerError(
              'OPERATION_REPREPARE_REQUIRED',
              'The freshly materialized action no longer matches its autonomy authorization.',
            );
          }
        }
        const reserved = await this.#autonomy.reserve(
          policyId,
          policyExposure,
        );
        if (!reserved.allowed) {
          const errorCode = `AUTONOMY_${reserved.denial.code}`;
          await this.#journal.recordError(
            envelope.operationId,
            errorCode,
            true,
          );
          record =
            (await this.#journal.get(envelope.operationId)) ??
            record;
          return {
            operationId: envelope.operationId,
            operationHash: envelope.operationHash,
            status: 'denied',
            transactionHashes: [...record.transactionHashes],
            errorCode,
            autonomyDenial: reserved.denial,
          };
        }
        autonomyReservation = reserved.value;
      } else {
        await this.#journal.updateStage(
          envelope.operationId,
          'awaiting-confirmation',
          firstStepIndex,
        );
        await this.#confirmation.confirm(
          buildActionConfirmation(
            envelope,
            materializedSteps,
            firstStepIndex,
            authorizedFeeQuotes,
          ),
        );
      }
    } catch (error) {
      const errorCode = asSignerErrorCode(error);
      if (
        errorCode === 'CONFIRMATION_DECLINED' ||
        errorCode === 'CONFIRMATION_TIMEOUT' ||
        errorCode === 'ELICITATION_UNSUPPORTED'
      ) {
        await this.#journal.recordError(
          envelope.operationId,
          errorCode,
          false,
        );
        record =
          (await this.#journal.get(envelope.operationId)) ??
          record;
        return toResult(record, 'declined', errorCode);
      }
      await this.#journal.recordError(
        envelope.operationId,
        errorCode,
        true,
      );
      record =
        (await this.#journal.updateStage(
          envelope.operationId,
          'validated',
          firstStepIndex,
        )) ?? record;
      return toResult(record, 'retryable', errorCode);
    }

    for (
      let offset = 0;
      offset < materializedSteps.length;
      offset += 1
    ) {
      const stepIndex = firstStepIndex + offset;
      const materialized = materializedSteps[offset]!;
      const requestWithoutNonce = {
        to: materialized.to,
        data: materialized.data,
        value: BigInt(materialized.value),
        gasLimit: BigInt(materialized.gasCap),
      };
      try {
        await this.#verifier.verify(envelope, wallet);
        this.#assertMaterialization(
          envelope,
          stepIndex,
          materialized,
        );
        if (
          materializedActionStepDigest(materialized) !==
          authorizedStepDigests[offset]
        ) {
          throw new SignerError(
            'ENVELOPE_TAMPERED',
            'Materialized calldata changed after the complete action was authorized.',
          );
        }
        await this.#intentValidator.validate(
          envelope,
          materialized,
          stepIndex,
        );
        const confirmedSimulation = await this.#simulator.simulate(
          requestWithoutNonce,
          wallet,
        );
        if (!confirmedSimulation.ok) {
          const errorCode = safeSimulationError(
            confirmedSimulation.errorCode,
          );
          record =
            (await this.#journal.recordError(
              envelope.operationId,
              errorCode,
              true,
            )) ?? record;
          if (autonomyReservation && this.#autonomy) {
            if (autonomySigned) {
              await this.#autonomy.markUncertain(
                autonomyReservation.id,
              );
            } else {
              await this.#autonomy.releaseBeforeSigning(
                autonomyReservation.id,
              );
            }
          }
          return toResult(record, 'retryable', errorCode);
        }
        if (policyId) {
          const ceiling = policyStepFeeCeilings?.[stepIndex];
          if (ceiling === undefined) {
            throw new SignerError(
              'OPERATION_REPREPARE_REQUIRED',
              'The autonomy authorization is missing this step fee ceiling.',
            );
          }
          this.#assertPersistedFeeCeiling(
            ceiling,
            confirmedSimulation.feeQuote,
          );
        } else {
          this.#assertFeeAuthorization(
            authorizedFeeQuotes[offset],
            confirmedSimulation.feeQuote,
          );
        }
        const broadcast = await this.#nonceQueue.runTransaction(
          async (nonce) => {
            if (autonomyReservation && this.#autonomy) {
              const authorized =
                await this.#autonomy.authorizeReservedWrite(
                  autonomyReservation.id,
                );
              if (!authorized.allowed) {
                throw new SignerError(
                  'WRITE_UNAVAILABLE',
                  `Autonomy write authorization is no longer active: ${authorized.denial.code}.`,
                );
              }
              autonomyReservation = authorized.value;
            }
            const prepared = await this.#wallet.prepareTransaction({
              ...requestWithoutNonce,
              nonce,
            });
            await this.#journal.recordPreparedTransaction(
              envelope.operationId,
              nonce,
              prepared.hash,
              stepIndex,
            );
            if (autonomyReservation && this.#autonomy) {
              const marked = await this.#autonomy.markSigned(
                autonomyReservation.id,
                prepared.hash,
              );
              if (!marked.allowed) {
                throw new SignerError(
                  'WRITE_UNAVAILABLE',
                  `Autonomy reservation could not record the signed transaction: ${marked.denial.code}.`,
                );
              }
              autonomySigned = true;
              autonomyReservation = marked.value;
            }
            let observed = true;
            try {
              const sent = await this.#wallet.broadcastTransaction(
                prepared.signedTransaction,
              );
              if (!sameHex(sent.hash, prepared.hash)) {
                throw new SignerError(
                  'ENVELOPE_TAMPERED',
                  'Broadcast transaction hash does not match the locally signed transaction.',
                );
              }
            } catch {
              try {
                observed = Boolean(
                  await this.#wallet.getTransaction(prepared.hash),
                );
              } catch {
                observed = false;
              }
            }
            return { hash: prepared.hash, observed };
          },
        );
        record =
          (await this.#journal.recordBroadcast(
            envelope.operationId,
            broadcast.nonce,
            broadcast.result.hash,
            stepIndex,
          )) ?? record;
        if (!broadcast.result.observed) {
          if (autonomyReservation && this.#autonomy) {
            await this.#autonomy.markUncertain(autonomyReservation.id);
          }
          return toResult(record, 'processing');
        }
        const receipt = await this.#wallet.waitForTransaction(
          broadcast.result.hash,
        );
        if (
          !sameHex(
            receipt.transactionHash,
            broadcast.result.hash,
          )
        ) {
          throw new SignerError(
            'ENVELOPE_TAMPERED',
            'Transaction receipt does not match the locally signed transaction.',
          );
        }
        record =
          (await this.#journal.recordReceipt(
            envelope.operationId,
            receipt,
            decodeCreatedOrderResult(envelope, receipt) ?? undefined,
          )) ?? record;
        if (receipt.status === 'pending') {
          if (autonomyReservation && this.#autonomy) {
            await this.#autonomy.markPending(autonomyReservation.id);
          }
          return toResult(record, 'processing');
        }
        if (receipt.status !== 'success') {
          if (autonomyReservation && this.#autonomy) {
            await this.#autonomy.markSettled(autonomyReservation.id);
          }
          record =
            (await this.#journal.recordError(
              envelope.operationId,
              'TRANSACTION_REVERTED',
              true,
            )) ?? record;
          return toResult(record, 'retryable', 'TRANSACTION_REVERTED');
        }
        record =
          (await this.#journal.updateStage(
            envelope.operationId,
            'validated',
            stepIndex + 1,
          )) ?? record;
      } catch (error) {
        const errorCode = asSignerErrorCode(error);
        await this.#journal.recordError(
          envelope.operationId,
          errorCode,
          true,
        );
        record =
          (await this.#journal.get(envelope.operationId)) ??
          record;
        if (autonomyReservation && this.#autonomy) {
          if (autonomySigned) {
            await this.#autonomy.markUncertain(autonomyReservation.id);
          } else {
            await this.#autonomy.releaseBeforeSigning(
              autonomyReservation.id,
            );
          }
        }
        if (
          record.stage === 'failed' ||
          (record.stage === 'awaiting-broadcast' &&
            record.transactionHashes.length === 0)
        ) {
          record =
            (await this.#journal.updateStage(
              envelope.operationId,
              'validated',
              stepIndex,
            )) ?? record;
          return toResult(record, 'retryable', errorCode);
        }
        if (
          record.stage === 'broadcast' ||
          record.stage === 'prepared-broadcast' ||
          record.stage === 'awaiting-broadcast'
        ) {
          return toResult(record, 'processing', errorCode);
        }
        return toResult(record, 'retryable', errorCode);
      }
    }

    record =
      (await this.#journal.updateStage(
        envelope.operationId,
        'completed',
        envelope.steps.length,
      )) ?? record;
    if (autonomyReservation && this.#autonomy) {
      await this.#autonomy.markSettled(autonomyReservation.id);
    }
    return toResult(record, 'completed');
  }

  #assertMaterialization(
    envelope: SignedActionEnvelopeV1,
    stepIndex: number,
    materialized: MaterializedActionStep,
  ): void {
    const signed = envelope.steps[stepIndex];
    if (
      !signed ||
      materialized.id !== signed.id ||
      materialized.kind !== signed.kind ||
      !sameHex(materialized.to, signed.to) ||
      materialized.value !== signed.value ||
      materialized.gasCap !== signed.gasCap ||
      materialized.data.slice(0, 10).toLowerCase() !==
        signed.data.slice(0, 10).toLowerCase()
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Private input materialization changed signed transaction terms.',
      );
    }
  }

  #assertFeeAuthorization(
    authorized: TransactionFeeQuote | undefined,
    current: TransactionFeeQuote | undefined,
  ): void {
    if (!authorized && !current) return;
    if (!authorized || !current) {
      throw new SignerError(
        'FEE_CHANGED',
        'The network fee quote changed after the complete action was authorized.',
      );
    }
    if (
      BigInt(current.maximumNetworkFeeWei) >
      BigInt(authorized.maximumNetworkFeeWei)
    ) {
      throw new SignerError(
        'FEE_CHANGED',
        'The maximum network cost now exceeds the locally authorized ceiling.',
      );
    }
  }

  #assertPersistedFeeCeiling(
    maximumNetworkFeeWei: string,
    current: TransactionFeeQuote | undefined,
  ): void {
    const currentMaximum = BigInt(
      current?.maximumNetworkFeeWei ?? '0',
    );
    if (currentMaximum > BigInt(maximumNetworkFeeWei)) {
      throw new SignerError(
        'FEE_CHANGED',
        'The current network cost exceeds this step’s persisted autonomy ceiling.',
      );
    }
  }

  async getOperation(
    operationId: string,
  ): Promise<OperationJournalRecord | null> {
    return this.#journal.get(operationId);
  }

  async getOperationStatus(
    operationId: string,
  ): Promise<OperationStatusV2 | null> {
    let record = await this.#journal.get(operationId);
    if (!record) return null;
    const reconciling =
      record.stage === 'awaiting-broadcast' ||
      record.stage === 'prepared-broadcast' ||
      record.stage === 'broadcast';
    if (reconciling) {
      await this.recoverOperation(operationId, record.operationHash);
      record = (await this.#journal.get(operationId)) ?? record;
    }
    const stored = parseStoredOperation(
      await this.#vault.get(storedOperationReference(operationId)),
    );
    const envelope =
      stored &&
      stored.envelope.operationId === record.operationId &&
      sameHex(stored.envelope.operationHash, record.operationHash)
        ? stored.envelope
        : null;
    const storedResult = parseStoredResult(
      await this.#vault.get(storedResultReference(operationId)),
    );
    if (
      record.stage === 'completed' &&
      !record.semanticResult &&
      envelope
    ) {
      record = await this.#backfillCreatedOrderResult(record, envelope);
    }
    if (
      reconciling &&
      record.stage === 'validated' &&
      envelope
    ) {
      this.#startBackground(
        envelope,
        stored?.policyId,
        stored?.policyExposure,
        stored?.policyStepFeeCeilings,
      );
    }
    return this.#publicStatus(record, envelope, storedResult);
  }

  async #backfillCreatedOrderResult(
    record: OperationJournalRecord,
    envelope: SignedActionEnvelopeV1,
  ): Promise<OperationJournalRecord> {
    for (const transactionHash of [...record.transactionHashes].reverse()) {
      try {
        const receipt =
          await this.#wallet.getTransactionReceipt(transactionHash);
        if (
          !receipt ||
          !sameHex(receipt.transactionHash, transactionHash) ||
          receipt.status !== 'success'
        ) {
          continue;
        }
        const semantic = decodeCreatedOrderResult(envelope, receipt);
        if (!semantic) continue;
        const updated =
          (await this.#journal.recordReceipt(
            record.operationId,
            receipt,
            semantic,
          )) ?? record;
        try {
          await this.#vault.put(
            storedResultReference(record.operationId),
            JSON.stringify({
              version: 1,
              summary: redactedSummary(envelope),
              result: semantic,
            } satisfies StoredResultV1),
            { kind: 'recovery-note' },
          );
          await this.#vault.delete(
            storedOperationReference(record.operationId),
          );
        } catch {
          await this.#journal.recordError(
            record.operationId,
            'LOCAL_CLEANUP_REQUIRED',
            false,
          );
          return (await this.#journal.get(record.operationId)) ?? updated;
        }
        return updated;
      } catch {
        return record;
      }
    }
    return record;
  }

  async listPendingOperationIds(): Promise<string[]> {
    const pending: string[] = [];
    for (const record of await this.#journal.list()) {
      if (isMessageOperationId(record.operationId)) continue;
      if (
        record.stage !== 'completed' &&
        record.stage !== 'declined' &&
        record.stage !== 'discarded' &&
        !isFailedOperation(record)
      ) {
        pending.push(record.operationId);
        continue;
      }
      if (record.stage !== 'completed' || record.semanticResult?.order) {
        continue;
      }
      const stored = parseStoredOperation(
        await this.#vault.get(storedOperationReference(record.operationId)),
      );
      if (stored && expectsCreatedOrderResult(stored.envelope)) {
        pending.push(record.operationId);
      }
    }
    return pending;
  }

  async markSetupCompleted(): Promise<void> {
    for (const record of await this.#journal.list()) {
      if (isMessageOperationId(record.operationId)) continue;
      if (
        record.errorCodes.at(-1) !== 'PRIVACY_SETUP_REQUIRED' &&
        record.errorCodes.at(-1) !== 'PRIVATE_TOKEN_SETUP_REQUIRED'
      ) {
        continue;
      }
      await this.#journal.recordError(
        record.operationId,
        'OPERATION_REPREPARE_REQUIRED',
        true,
      );
    }
  }

  #publicStatus(
    record: OperationJournalRecord,
    envelope: SignedActionEnvelopeV1 | null,
    storedResult: StoredResultV1 | null = null,
  ): OperationStatusV2 {
    const journalStatus = operationState(
      record,
      this.#activeOperations.has(record.operationId),
    );
    const identityPending =
      journalStatus === 'completed' &&
      expectsCreatedOrderResult(envelope) &&
      !record.semanticResult?.order &&
      !storedResult?.result.order;
    const status = identityPending ? 'uncertain' : journalStatus;
    const terminal =
      status === 'completed' ||
      status === 'declined' ||
      status === 'failed';
    const userActionRequired = [
      'needs_setup',
      'needs_reprepare',
      'needs_private_input',
      'needs_confirmation',
    ].includes(status);
    const errorCode = publicErrorCode(record);
    const setupRequirement =
      errorCode === 'PRIVACY_SETUP_REQUIRED'
        ? {
            kind: 'privacy-onboarding' as const,
            assets: [] as [],
          }
        : errorCode === 'PRIVATE_TOKEN_SETUP_REQUIRED'
          ? {
              kind: 'private-token-setup' as const,
              assets: privateAssetSymbols(envelope),
            }
          : undefined;
    const result =
      status === 'completed'
        ? record.semanticResult?.order
          ? record.semanticResult
          : storedResult?.result ??
            semanticResult(envelope, record.semanticResult)
        : undefined;
    return {
      version: 'cw.operation-status/2',
      operationId: record.operationId,
      operationHash: record.operationHash,
      status,
      summary:
        storedResult?.summary ??
        (status === 'completed' && envelope
          ? redactedSummary(envelope)
          : envelope?.summary) ??
        `ChainWhisper operation ${record.operationId}`,
      transactionHashes: [...record.transactionHashes],
      transactionLinks: record.transactionHashes.map(
        (hash) => `https://mainnet.cotiscan.io/tx/${hash}`,
      ),
      userActionRequired,
      nextPollingIntervalMs: terminal ? null : 1_000,
      ...(identityPending
        ? { errorCode: 'ORDER_RESULT_RECONCILIATION_REQUIRED' }
        : errorCode
          ? { errorCode }
          : {}),
      ...(setupRequirement ? { setupRequirement } : {}),
      ...(result ? { result } : {}),
    };
  }

  async recoverOperation(
    operationId: string,
    operationHash?: string,
  ): Promise<RecoverOperationResult> {
    let record = await this.#journal.get(operationId);
    if (!record) {
      throw new SignerError(
        'OPERATION_NOT_FOUND',
        'No local operation matches this identifier.',
      );
    }
    if (
      operationHash &&
      !sameHex(record.operationHash, operationHash)
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Operation hash does not match the local journal.',
      );
    }
    if (record.stage === 'discarded') {
      return {
        operationId,
        operationHash: record.operationHash,
        status: 'discarded',
        transactionHashes: [...record.transactionHashes],
        errorCodes: [...record.errorCodes],
      };
    }
    if (record.stage === 'completed') {
      return {
        operationId,
        operationHash: record.operationHash,
        status: 'completed',
        transactionHashes: [...record.transactionHashes],
        errorCodes: [...record.errorCodes],
      };
    }
    const transactionHash = record.transactionHashes.at(-1);
    let receiptStatus: JournalReceipt['status'] | null = null;
    if (transactionHash) {
      const stored = parseStoredOperation(
        await this.#vault.get(storedOperationReference(operationId)),
      );
      const recoveryEnvelope =
        stored &&
        stored.envelope.operationId === record.operationId &&
        sameHex(stored.envelope.operationHash, record.operationHash)
          ? stored.envelope
          : null;
      const recordedReceipt: JournalReceipt | undefined =
        record.receipts.find(
        (receipt) =>
          sameHex(receipt.transactionHash, transactionHash) &&
          receipt.status !== 'pending',
      );
      let receipt: JournalReceipt | null | undefined =
        recordedReceipt;
      if (receipt && !record.semanticResult && recoveryEnvelope) {
        try {
          receipt =
            (await this.#wallet.getTransactionReceipt(
              transactionHash,
            )) ?? receipt;
        } catch {
          // The persisted successful receipt still safely advances recovery.
          // Semantic identity can be backfilled on a later status poll.
        }
      }
      if (!receipt) {
        try {
          receipt = await this.#wallet.getTransactionReceipt(
            transactionHash,
          );
        } catch {
          return {
            operationId,
            operationHash: record.operationHash,
            status: 'processing',
            transactionHashes: [...record.transactionHashes],
            errorCodes: [...record.errorCodes],
          };
        }
      }
      if (!receipt || receipt.status === 'pending') {
        return {
          operationId,
          operationHash: record.operationHash,
          status: 'processing',
          transactionHashes: [...record.transactionHashes],
          errorCodes: [...record.errorCodes],
        };
      }
      if (!sameHex(receipt.transactionHash, transactionHash)) {
        return {
          operationId,
          operationHash: record.operationHash,
          status: 'processing',
          transactionHashes: [...record.transactionHashes],
          errorCodes: [...record.errorCodes],
        };
      }
      record =
        (await this.#journal.recordReceipt(
          operationId,
          receipt,
          recoveryEnvelope
            ? decodeCreatedOrderResult(recoveryEnvelope, receipt) ??
                undefined
            : undefined,
        )) ??
        record;
      receiptStatus = receipt.status;
    }
    if (
      record.transactionHashes.length === 0 &&
      record.nonces.length > 0
    ) {
      // Broadcasting is only attempted after recordPreparedTransaction
      // persists the locally derived transaction hash. A nonce without a
      // hash therefore cannot identify this operation's transaction, and
      // adopting an arbitrary wallet transaction by nonce would be unsafe.
      record =
        (await this.#journal.updateStage(
          operationId,
          'validated',
          record.nextStepIndex,
        )) ?? record;
    }
    if (receiptStatus === 'reverted') {
      record =
        (await this.#journal.recordError(
          operationId,
          'TRANSACTION_REVERTED',
          true,
        )) ?? record;
    } else if (
      receiptStatus === 'success' &&
      (record.stage === 'broadcast' ||
        record.stage === 'prepared-broadcast')
    ) {
      record =
        (await this.#journal.updateStage(
          operationId,
          'validated',
          record.nextStepIndex + 1,
        )) ?? record;
    }
    return {
      operationId,
      operationHash: record.operationHash,
      status: 'retryable',
      transactionHashes: [...record.transactionHashes],
      errorCodes: [...record.errorCodes],
    };
  }

  async #assertDiscardableOperation(
    record: OperationJournalRecord,
  ): Promise<void> {
    if (
      record.stage === 'prepared-broadcast' ||
      record.stage === 'broadcast' ||
      (record.stage === 'awaiting-broadcast' &&
        record.transactionHashes.length > 0)
    ) {
      throw new SignerError(
        'OPERATION_IN_PROGRESS',
        'An operation with an allocated nonce or uncertain broadcast cannot be discarded.',
      );
    }
    for (const transactionHash of record.transactionHashes) {
      const receipt = await this.#wallet.getTransactionReceipt(
        transactionHash,
      );
      const transaction =
        receipt && receipt.status !== 'pending'
          ? null
          : await this.#wallet.getTransaction(transactionHash);
      if (transaction || receipt?.status === 'pending') {
        throw new SignerError(
          'OPERATION_IN_PROGRESS',
          'An operation with a pending transaction cannot be discarded.',
        );
      }
    }
    for (let index = 0; index < record.nonces.length; index += 1) {
      const nonce = record.nonces[index];
      if (nonce === undefined) continue;
      const correspondingHash = record.transactionHashes[index];
      if (correspondingHash) {
        const receipt = await this.#wallet.getTransactionReceipt(
          correspondingHash,
        );
        if (receipt && receipt.status !== 'pending') continue;
      }
      const transaction = await this.#wallet.findTransactionByNonce(nonce);
      if (transaction) {
        throw new SignerError(
          'OPERATION_IN_PROGRESS',
          'An operation with a pending transaction cannot be discarded.',
        );
      }
    }
  }

  async discardOperation(
    operationId: string,
    operationHash: string,
  ): Promise<RecoverOperationResult> {
    if (!/^0x[0-9a-fA-F]{64}$/u.test(operationHash)) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'An exact 32-byte operation hash is required before local state can be discarded.',
      );
    }
    const initialRecord = await this.#journal.get(operationId);
    if (!initialRecord) {
      throw new SignerError(
        'OPERATION_NOT_FOUND',
        'No local operation matches this identifier.',
      );
    }
    if (!sameHex(initialRecord.operationHash, operationHash)) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Operation hash does not match the local journal.',
      );
    }
    if (
      this.#activeOperations.has(operationId) ||
      this.#discardingOperations.has(operationId)
    ) {
      throw new SignerError(
        'OPERATION_IN_PROGRESS',
        'An active or already-discarding operation cannot be discarded.',
      );
    }
    this.#discardingOperations.add(operationId);
    try {
      await this.#assertDiscardableOperation(initialRecord);
      await this.#confirmation.confirm({
        operationId,
        operationHash: initialRecord.operationHash,
        stepId: 'discard-operation',
        stepIndex: 0,
        stepCount: 1,
        wallet: await this.#wallet.getAddress(),
        contract: '0x0000000000000000000000000000000000000000',
        action: 'discard_operation',
        orderType: null,
        orderTypeLabel: 'Local recovery operation',
        assets: [],
        amounts: [],
        details: [
          { label: 'Operation', value: operationId },
          {
            label: 'Exact operation hash',
            value: initialRecord.operationHash,
          },
        ],
        counterparty: null,
        spender: null,
        fee: '0',
        nativeValue: '0',
        gasCap: '0',
        expectedResult:
          'Local recovery data and signer-held operation secrets are deleted. No transaction is signed or broadcast.',
        summary: 'Discard this exact local ChainWhisper operation.',
        authorizationScope: 'complete-logical-action',
        actionButtonLabel: 'Confirm discard and delete local data',
        maximumNetworkFeeWei: '0',
        maximumNetworkFeeCoti: '0',
      });
      if (this.#activeOperations.has(operationId)) {
        throw new SignerError(
          'OPERATION_IN_PROGRESS',
          'The operation became active while discard confirmation was open.',
        );
      }
      const record = await this.#journal.get(operationId);
      if (
        !record ||
        !sameHex(record.operationHash, initialRecord.operationHash)
      ) {
        throw new SignerError(
          'ENVELOPE_TAMPERED',
          'Operation state changed while discard confirmation was open.',
        );
      }
      await this.#assertDiscardableOperation(record);
      const discarded =
        (await this.#journal.discard(operationId)) ?? record;
      await Promise.all([
        this.#vault.delete(storedOperationReference(operationId)),
        this.#vault.delete(storedResultReference(operationId)),
        this.#vault.deletePrefix(`${record.operationHash}:`),
      ]);
      return {
        operationId,
        operationHash: discarded.operationHash,
        status: 'discarded',
        transactionHashes: [...discarded.transactionHashes],
        errorCodes: [...discarded.errorCodes],
      };
    } finally {
      this.#discardingOperations.delete(operationId);
    }
  }
}
