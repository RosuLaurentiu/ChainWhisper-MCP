import type {
  ActiveAutonomyPolicyV1,
  AutonomyReservationV1,
} from './autonomy.js';

export const AUTONOMY_STORE_VERSION = 'cw.autonomy-store/1' as const;

/**
 * Persistent state owned by the signer. Implementations must never expose this
 * value through an MCP response: reservations can contain private trade
 * amounts which are safe only inside the authenticated, encrypted signer
 * store.
 */
export type AutonomyStoreSnapshotV1 = {
  version: typeof AUTONOMY_STORE_VERSION;
  revision: number;
  globalPaused: boolean;
  policies: Record<string, ActiveAutonomyPolicyV1>;
  reservations: Record<string, AutonomyReservationV1>;
};

export type AutonomyStoreTransactionResult<T> = {
  next: AutonomyStoreSnapshotV1;
  result: T;
};

/**
 * Storage boundary used by AutonomyPolicyManager.
 *
 * The adapter must:
 * - authenticate persisted bytes before returning a snapshot;
 * - encrypt persisted bytes at rest;
 * - serialize `transact` calls across processes which can access the same
 *   signer state; and
 * - commit the returned snapshot atomically or not at all.
 *
 * A production adapter should bind its authentication context to the wallet
 * namespace and store version. The marker is deliberately checked by the
 * manager so a plaintext AtomicJsonStore cannot be wired accidentally.
 */
export interface AuthenticatedEncryptedAutonomyStore {
  readonly protection: {
    readonly authenticated: true;
    readonly encryptedAtRest: true;
    readonly atomicTransactions: true;
  };

  read(): Promise<AutonomyStoreSnapshotV1>;

  transact<T>(
    mutation: (
      current: AutonomyStoreSnapshotV1,
    ) =>
      | AutonomyStoreTransactionResult<T>
      | Promise<AutonomyStoreTransactionResult<T>>,
  ): Promise<T>;
}

export const createEmptyAutonomyStoreSnapshot =
  (): AutonomyStoreSnapshotV1 => ({
    version: AUTONOMY_STORE_VERSION,
    revision: 0,
    globalPaused: false,
    policies: {},
    reservations: {},
  });
