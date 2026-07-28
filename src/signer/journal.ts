import { resolve } from 'node:path';

import type {
  HexString,
  JournalReceipt,
  OperationJournalRecord,
  OperationStage,
} from './types.js';
import { AtomicJsonStore } from './atomicStore.js';
import { isSafeOperationId } from '../shared/index.js';
import { SignerError } from './errors.js';

type JournalFileV1 = {
  version: 1;
  operations: Record<string, OperationJournalRecord>;
};

const emptyJournal = (): JournalFileV1 => ({
  version: 1,
  operations: Object.create(null) as Record<
    string,
    OperationJournalRecord
  >,
});

const safeErrorCode = (value: string): string =>
  /^[A-Z0-9_-]{1,64}$/u.test(value) ? value : 'REDACTED_ERROR';

const cloneRecord = (
  record: OperationJournalRecord,
): OperationJournalRecord => ({
  ...record,
  nonces: [...record.nonces],
  transactionHashes: [...record.transactionHashes],
  receipts: record.receipts.map((receipt) => ({ ...receipt })),
  errorCodes: [...record.errorCodes],
});

const assertOperationId = (operationId: string): void => {
  if (!isSafeOperationId(operationId)) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Operation id contains unsupported characters or a reserved name.',
    );
  }
};

const ownOperation = (
  operations: Record<string, OperationJournalRecord>,
  operationId: string,
): OperationJournalRecord | undefined =>
  Object.hasOwn(operations, operationId)
    ? operations[operationId]
    : undefined;

export class OperationJournal {
  readonly #store: AtomicJsonStore<JournalFileV1>;
  readonly #clock: () => Date;

  constructor(stateDirectory: string, clock: () => Date = () => new Date()) {
    this.#store = new AtomicJsonStore(
      resolve(stateDirectory, 'operations.v1.json'),
      emptyJournal,
    );
    this.#clock = clock;
  }

  get path(): string {
    return this.#store.path;
  }

  async get(operationId: string): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    const state = await this.#store.read();
    const record = ownOperation(state.operations, operationId);
    return record ? cloneRecord(record) : null;
  }

  async begin(
    operationId: string,
    operationHash: HexString,
  ): Promise<OperationJournalRecord> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const current = ownOperation(state.operations, operationId);
      if (current) return cloneRecord(current);
      const record: OperationJournalRecord = {
        operationId,
        operationHash,
        stage: 'validated',
        nextStepIndex: 0,
        nonces: [],
        transactionHashes: [],
        receipts: [],
        errorCodes: [],
        updatedAt: this.#clock().toISOString(),
      };
      state.operations[operationId] = record;
      return cloneRecord(record);
    });
  }

  async updateStage(
    operationId: string,
    stage: OperationStage,
    nextStepIndex?: number,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      record.stage = stage;
      if (nextStepIndex !== undefined) record.nextStepIndex = nextStepIndex;
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async recordBroadcast(
    operationId: string,
    nonce: number,
    transactionHash: HexString,
    nextStepIndex: number,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      if (!record.transactionHashes.includes(transactionHash)) {
        record.nonces.push(nonce);
        record.transactionHashes.push(transactionHash);
      }
      record.stage = 'broadcast';
      record.nextStepIndex = nextStepIndex;
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async reserveNonce(
    operationId: string,
    nonce: number,
    nextStepIndex: number,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      if (!record.nonces.includes(nonce)) record.nonces.push(nonce);
      record.stage = 'awaiting-broadcast';
      record.nextStepIndex = nextStepIndex;
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async recordPreparedTransaction(
    operationId: string,
    nonce: number,
    transactionHash: HexString,
    nextStepIndex: number,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      if (!record.nonces.includes(nonce)) record.nonces.push(nonce);
      if (!record.transactionHashes.includes(transactionHash)) {
        record.transactionHashes.push(transactionHash);
      }
      record.stage = 'prepared-broadcast';
      record.nextStepIndex = nextStepIndex;
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async recordReceipt(
    operationId: string,
    receipt: JournalReceipt,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      const index = record.receipts.findIndex(
        (entry) => entry.transactionHash === receipt.transactionHash,
      );
      const safeReceipt: JournalReceipt = {
        transactionHash: receipt.transactionHash,
        status: receipt.status,
        ...(receipt.blockNumber === undefined
          ? {}
          : { blockNumber: receipt.blockNumber }),
      };
      if (index >= 0) record.receipts[index] = safeReceipt;
      else record.receipts.push(safeReceipt);
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async recordError(
    operationId: string,
    errorCode: string,
    retryable: boolean,
  ): Promise<OperationJournalRecord | null> {
    assertOperationId(operationId);
    return this.#store.mutate((state) => {
      const record = ownOperation(state.operations, operationId);
      if (!record) return null;
      record.errorCodes.push(safeErrorCode(errorCode));
      if (
        retryable &&
        ![
          'awaiting-broadcast',
          'prepared-broadcast',
          'broadcast',
        ].includes(record.stage)
      ) {
        record.stage = 'failed';
      }
      record.updatedAt = this.#clock().toISOString();
      return cloneRecord(record);
    });
  }

  async discard(operationId: string): Promise<OperationJournalRecord | null> {
    return this.updateStage(operationId, 'discarded');
  }
}
