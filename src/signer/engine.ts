import type { SignedActionEnvelopeV1 } from '../shared/index.js';

import { ConfirmationGate, buildActionConfirmation } from './confirmation.js';
import { asSignerErrorCode, SignerError } from './errors.js';
import { OperationJournal } from './journal.js';
import { NonceQueue } from './nonceQueue.js';
import { EncryptedSecretVault } from './vault.js';
import { ActionEnvelopeVerifier } from './verification.js';
import type {
  ExecuteActionResult,
  MaterializedActionStep,
  MaterializedIntentValidator,
  OperationJournalRecord,
  PrivateInputMaterializer,
  RecoverOperationResult,
  TransactionSimulator,
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
  }

  get nonceQueue(): NonceQueue {
    return this.#nonceQueue;
  }

  async executeAction(
    envelope: SignedActionEnvelopeV1,
  ): Promise<ExecuteActionResult> {
    const active = this.#activeOperations.get(envelope.operationId);
    if (active) return active;
    const execution = this.#executeAction(envelope).finally(() => {
      this.#activeOperations.delete(envelope.operationId);
    });
    this.#activeOperations.set(envelope.operationId, execution);
    return execution;
  }

  async #executeAction(
    envelope: SignedActionEnvelopeV1,
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
    if (!this.#confirmation.isWriteAvailable) {
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

    for (
      let stepIndex = record.nextStepIndex;
      stepIndex < envelope.steps.length;
      stepIndex += 1
    ) {
      let materialized: MaterializedActionStep;
      try {
        await this.#verifier.verify(envelope, wallet);
        materialized = await this.#materializer.materializeStep(
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
        const requestWithoutNonce = {
          to: materialized.to,
          data: materialized.data,
          value: BigInt(materialized.value),
          gasLimit: BigInt(materialized.gasCap),
        };
        const simulation = await this.#simulator.simulate(
          requestWithoutNonce,
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
        await this.#journal.updateStage(
          envelope.operationId,
          'awaiting-confirmation',
          stepIndex,
        );
        await this.#confirmation.confirm(
          buildActionConfirmation(envelope, materialized, stepIndex),
        );
        await this.#verifier.verify(envelope, wallet);
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
          return toResult(record, 'retryable', errorCode);
        }
        const broadcast = await this.#nonceQueue.runTransaction(
          async (nonce) => {
            await this.#journal.reserveNonce(
              envelope.operationId,
              nonce,
              stepIndex,
            );
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
            } catch (error) {
              const accepted = await this.#wallet.getTransaction(
                prepared.hash,
              );
              if (!accepted) throw error;
            }
            return { hash: prepared.hash };
          },
        );
        record =
          (await this.#journal.recordBroadcast(
            envelope.operationId,
            broadcast.nonce,
            broadcast.result.hash,
            stepIndex,
          )) ?? record;
        const receipt = await this.#wallet.waitForTransaction(
          broadcast.result.hash,
        );
        record =
          (await this.#journal.recordReceipt(
            envelope.operationId,
            receipt,
          )) ?? record;
        if (receipt.status === 'pending') {
          return toResult(record, 'processing');
        }
        if (receipt.status !== 'success') {
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
          (await this.#journal.get(envelope.operationId)) ??
          record;
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
    let hasPending = false;
    let hasPreparedButUnbroadcast = false;
    let hasReverted = false;
    for (const transactionHash of record.transactionHashes) {
      const receipt = await this.#wallet.getTransactionReceipt(
        transactionHash,
      );
      if (!receipt || receipt.status === 'pending') {
        const transaction = await this.#wallet.getTransaction(
          transactionHash,
        );
        if (transaction) hasPending = true;
        else hasPreparedButUnbroadcast = true;
        continue;
      }
      record =
        (await this.#journal.recordReceipt(operationId, receipt)) ??
        record;
      if (receipt.status === 'reverted') hasReverted = true;
    }
    if (
      record.transactionHashes.length === 0 &&
      record.nonces.length > 0
    ) {
      for (const nonce of record.nonces) {
        const transaction = await this.#wallet.findTransactionByNonce(
          nonce,
        );
        if (transaction) {
          record =
            (await this.#journal.recordBroadcast(
              operationId,
              nonce,
              transaction.hash,
              record.nextStepIndex,
            )) ?? record;
          hasPending = true;
        } else {
          hasPreparedButUnbroadcast = true;
        }
      }
    }
    if (hasPending) {
      return {
        operationId,
        operationHash: record.operationHash,
        status: 'processing',
        transactionHashes: [...record.transactionHashes],
        errorCodes: [...record.errorCodes],
      };
    }
    if (hasReverted) {
      record =
        (await this.#journal.recordError(
          operationId,
          'TRANSACTION_REVERTED',
          true,
        )) ?? record;
    } else if (hasPreparedButUnbroadcast) {
      record =
        (await this.#journal.updateStage(
          operationId,
          'validated',
          record.nextStepIndex,
        )) ?? record;
    } else if (record.stage === 'broadcast') {
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
    operationHash?: string,
  ): Promise<RecoverOperationResult> {
    const record = await this.#journal.get(operationId);
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
    if (
      record.stage === 'awaiting-broadcast' ||
      record.stage === 'prepared-broadcast' ||
      record.stage === 'broadcast'
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
