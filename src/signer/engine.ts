import type { SignedActionEnvelopeV1 } from '../shared/index.js';

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
  type AutonomyReservationV1,
} from './autonomy.js';
import { buildPolicyExposure } from './policyExposure.js';
import type {
  ExecuteActionResult,
  JournalReceipt,
  MaterializedActionStep,
  MaterializedIntentValidator,
  OperationJournalRecord,
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

  async executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
  ): Promise<ExecuteActionResult> {
    const active = this.#activeOperations.get(envelope.operationId);
    if (active) return active;
    const execution = this.#executeAction(envelope, policyId).finally(() => {
      this.#activeOperations.delete(envelope.operationId);
    });
    this.#activeOperations.set(envelope.operationId, execution);
    return execution;
  }

  async #executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
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
    if (record.stage === 'completed') return toResult(record, 'completed');

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
    const materializedSteps: MaterializedActionStep[] = [];
    const authorizedFeeQuotes: Array<
      TransactionFeeQuote | undefined
    > = [];
    const authorizedStepDigests: string[] = [];
    let autonomyReservation: AutonomyReservationV1 | null = null;
    let autonomySigned = false;

    for (
      let stepIndex = firstStepIndex;
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
          return {
            operationId: envelope.operationId,
            operationHash: envelope.operationHash,
            status: 'denied',
            transactionHashes: [...record.transactionHashes],
            errorCode: 'AUTONOMY_UNAVAILABLE',
            autonomyDenial: {
              code: 'POLICY_NOT_FOUND',
              message: 'Autonomy is not available in this signer session.',
              policyId,
            },
          };
        }
        const reserved = await this.#autonomy.reserve(
          policyId,
          buildPolicyExposure({
            envelope,
            wallet,
            steps: materializedSteps,
            feeQuotes: authorizedFeeQuotes,
          }),
        );
        if (!reserved.allowed) {
          return {
            operationId: envelope.operationId,
            operationHash: envelope.operationHash,
            status: 'denied',
            transactionHashes: [...record.transactionHashes],
            errorCode: `AUTONOMY_${reserved.denial.code}`,
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
        this.#assertFeeAuthorization(
          authorizedFeeQuotes[offset],
          confirmedSimulation.feeQuote,
        );
        const broadcast = await this.#nonceQueue.runTransaction(
          async (nonce) => {
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
        record =
          (await this.#journal.recordReceipt(
            envelope.operationId,
            receipt,
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

  async getOperation(
    operationId: string,
  ): Promise<OperationJournalRecord | null> {
    return this.#journal.get(operationId);
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
      const recordedReceipt: JournalReceipt | undefined =
        record.receipts.find(
        (receipt) =>
          sameHex(receipt.transactionHash, transactionHash) &&
          receipt.status !== 'pending',
      );
      let receipt: JournalReceipt | null | undefined =
        recordedReceipt;
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
      record =
        (await this.#journal.recordReceipt(operationId, receipt)) ??
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
    const record = await this.#journal.get(operationId);
    if (!record) {
      throw new SignerError(
        'OPERATION_NOT_FOUND',
        'No local operation matches this identifier.',
      );
    }
    if (
      !sameHex(record.operationHash, operationHash)
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Operation hash does not match the local journal.',
      );
    }
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
    await this.#confirmation.confirm({
      operationId,
      operationHash: record.operationHash,
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
        { label: 'Exact operation hash', value: record.operationHash },
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
    const discarded =
      (await this.#journal.discard(operationId)) ?? record;
    await this.#vault.deletePrefix(`${record.operationHash}:`);
    return {
      operationId,
      operationHash: discarded.operationHash,
      status: 'discarded',
      transactionHashes: [...discarded.transactionHashes],
      errorCodes: [...discarded.errorCodes],
    };
  }
}
