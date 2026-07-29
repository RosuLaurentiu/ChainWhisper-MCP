import type {
  AuthenticatedEncryptedAutonomyStore,
  AutonomyStoreSnapshotV1,
  AutonomyStoreTransactionResult,
} from './autonomyStore.js';
import { createEmptyAutonomyStoreSnapshot } from './autonomyStore.js';
import type { Address } from './types.js';
import { EncryptedSecretVault } from './vault.js';

const normalizeWallet = (wallet: Address): string => {
  if (!/^0x[0-9a-fA-F]{40}$/u.test(wallet)) {
    throw new Error('Autonomy storage requires an exact Agent Wallet address.');
  }
  return wallet.toLowerCase();
};

const parseSnapshot = (encoded: string | null): AutonomyStoreSnapshotV1 => {
  if (!encoded) return createEmptyAutonomyStoreSnapshot();
  const parsed = JSON.parse(encoded) as Partial<AutonomyStoreSnapshotV1>;
  if (
    parsed.version !== 'cw.autonomy-store/1' ||
    !Number.isSafeInteger(parsed.revision) ||
    typeof parsed.globalPaused !== 'boolean' ||
    !parsed.policies ||
    typeof parsed.policies !== 'object' ||
    Array.isArray(parsed.policies) ||
    !parsed.reservations ||
    typeof parsed.reservations !== 'object' ||
    Array.isArray(parsed.reservations)
  ) {
    throw new Error('The encrypted autonomy state is invalid or unsupported.');
  }
  return parsed as AutonomyStoreSnapshotV1;
};

/**
 * Wallet-namespaced production adapter for autonomy policy state.
 *
 * The outer signer instance lock provides cross-process exclusion. This
 * adapter additionally serializes all in-process transactions, while
 * EncryptedSecretVault authenticates and atomically replaces the encrypted
 * bytes on disk.
 */
export class VaultAutonomyStore
  implements AuthenticatedEncryptedAutonomyStore
{
  readonly protection = {
    authenticated: true,
    encryptedAtRest: true,
    atomicTransactions: true,
  } as const;

  readonly #vault: EncryptedSecretVault;
  readonly #reference: string;
  #transactionTail: Promise<void> = Promise.resolve();

  constructor(options: {
    vault: EncryptedSecretVault;
    wallet: Address;
  }) {
    this.#vault = options.vault;
    this.#reference = `autonomy/${normalizeWallet(options.wallet)}/state`;
  }

  async read(): Promise<AutonomyStoreSnapshotV1> {
    return parseSnapshot(await this.#vault.get(this.#reference));
  }

  async transact<T>(
    mutation: (
      current: AutonomyStoreSnapshotV1,
    ) =>
      | AutonomyStoreTransactionResult<T>
      | Promise<AutonomyStoreTransactionResult<T>>,
  ): Promise<T> {
    const previous = this.#transactionTail;
    let release: () => void = () => undefined;
    this.#transactionTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const outcome = await mutation(await this.read());
      await this.#vault.put(
        this.#reference,
        JSON.stringify(outcome.next),
        { kind: 'generic' },
      );
      return outcome.result;
    } finally {
      release();
    }
  }
}
