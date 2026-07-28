import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomUUID,
  scrypt as scryptCallback,
} from 'node:crypto';
import {
  link,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  stat,
  unlink,
} from 'node:fs/promises';
import { promisify } from 'node:util';
import { resolve } from 'node:path';

import { AtomicJsonStore } from './atomicStore.js';

const scrypt = promisify(scryptCallback);
const CLAIM_FILE_PATTERN = /^[0-9a-f]{64}\.enc\.json$/u;
const TOMBSTONE_FILE_SUFFIX = '.deleted';
const CLAIM_CONTENTION_RETRIES = 8;

type VaultEntry = {
  value: string;
  createdAt: string;
  kind:
    | 'access-secret'
    | 'private-uint256'
    | 'recovery-note'
    | 'received-access-secret'
    | 'generic';
  binding?: {
    operationHash?: string;
    recipient?: string;
    escrowContract?: string;
    localId?: string;
  };
};

type VaultPlaintextV1 = {
  version: 1;
  entries: Record<string, VaultEntry>;
};

type EncryptedVaultV1 = {
  version: 1;
  kdf: 'scrypt';
  cipher: 'aes-256-gcm';
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
};

const emptyEncryptedVault = (): EncryptedVaultV1 => ({
  version: 1,
  kdf: 'scrypt',
  cipher: 'aes-256-gcm',
  salt: '',
  iv: '',
  authTag: '',
  ciphertext: '',
});

const emptyPlaintextVault = (): VaultPlaintextV1 => ({
  version: 1,
  entries: {},
});

const deriveKey = async (
  passphrase: string,
  salt: Buffer,
): Promise<Buffer> => (await scrypt(passphrase, salt, 32)) as Buffer;

const validateReference = (reference: string): void => {
  if (!/^[a-zA-Z0-9:._/-]{1,200}$/u.test(reference)) {
    throw new Error('Invalid local secret reference.');
  }
};

const isMissing = (error: unknown): boolean =>
  Boolean(
    error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: string }).code === 'ENOENT',
  );

const isAlreadyExists = (error: unknown): boolean =>
  Boolean(
    error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: string }).code === 'EEXIST',
  );

const waitForContention = async (attempt: number): Promise<void> => {
  await new Promise<void>((resolveWait) => {
    setTimeout(resolveWait, Math.min(2 ** attempt, 25));
  });
};

const encodedAccessSecret = (value: string): string | null => {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (
      parsed.version !== 1 ||
      typeof parsed.operationHash !== 'string' ||
      !/^0x[0-9a-fA-F]{64}$/u.test(parsed.operationHash) ||
      (parsed.recipient !== null &&
        (typeof parsed.recipient !== 'string' ||
          !/^0x[0-9a-fA-F]{40}$/u.test(parsed.recipient))) ||
      typeof parsed.escrowContract !== 'string' ||
      !/^0x[0-9a-fA-F]{40}$/u.test(parsed.escrowContract) ||
      (parsed.localId !== null &&
        (typeof parsed.localId !== 'string' ||
          !/^(?:0|[1-9][0-9]*)$/u.test(parsed.localId))) ||
      typeof parsed.secret !== 'string' ||
      !/^0x[0-9a-fA-F]{64}$/u.test(parsed.secret) ||
      /^0x0{64}$/u.test(parsed.secret)
    ) {
      return null;
    }
    return parsed.secret.toLowerCase();
  } catch {
    return null;
  }
};

const entryContainsAccessSecret = (
  entry: VaultEntry,
  normalizedCandidate: string,
): boolean =>
  ((entry.kind === 'access-secret' ||
    entry.kind === 'received-access-secret') &&
    /^0x[0-9a-fA-F]{64}$/u.test(entry.value) &&
    !/^0x0{64}$/u.test(entry.value) &&
    entry.value.toLowerCase() === normalizedCandidate) ||
  encodedAccessSecret(entry.value) === normalizedCandidate;

export class EncryptedSecretVault {
  readonly #store: AtomicJsonStore<EncryptedVaultV1>;
  readonly #claimDirectory: string;
  readonly #passphrase: string;
  readonly #clock: () => Date;
  #mutationTail: Promise<void> = Promise.resolve();

  constructor(
    stateDirectory: string,
    passphrase: string,
    clock: () => Date = () => new Date(),
  ) {
    if (passphrase.length < 16) {
      throw new Error('Vault passphrase must contain at least 16 characters.');
    }
    this.#store = new AtomicJsonStore(
      resolve(stateDirectory, 'secrets.v1.enc.json'),
      emptyEncryptedVault,
    );
    this.#claimDirectory = resolve(
      stateDirectory,
      '.secrets.v1.claims',
    );
    this.#passphrase = passphrase;
    this.#clock = clock;
  }

  get path(): string {
    return this.#store.path;
  }

  #claimPath(reference: string): string {
    const digest = createHmac('sha256', this.#passphrase)
      .update(reference, 'utf8')
      .digest('hex');
    return resolve(this.#claimDirectory, `${digest}.enc.json`);
  }

  #tombstonePath(reference: string): string {
    return `${this.#claimPath(reference)}${TOMBSTONE_FILE_SUFFIX}`;
  }

  async #isTombstoned(reference: string): Promise<boolean> {
    try {
      await stat(this.#tombstonePath(reference));
      return true;
    } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
  }

  async #createTombstone(reference: string): Promise<boolean> {
    await mkdir(this.#claimDirectory, {
      recursive: true,
      mode: 0o700,
    });
    try {
      const handle = await open(
        this.#tombstonePath(reference),
        'wx',
        0o600,
      );
      try {
        await handle.writeFile('deleted\n', 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      return true;
    } catch (error) {
      if (isAlreadyExists(error)) return false;
      throw error;
    }
  }

  async #encryptPlaintext(
    plaintext: VaultPlaintextV1,
  ): Promise<EncryptedVaultV1> {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKey(this.#passphrase, salt);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(plaintext), 'utf8'),
      cipher.final(),
    ]);
    return {
      version: 1,
      kdf: 'scrypt',
      cipher: 'aes-256-gcm',
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
  }

  async #decryptPlaintext(
    encrypted: EncryptedVaultV1,
  ): Promise<VaultPlaintextV1> {
    if (
      encrypted.version !== 1 ||
      encrypted.kdf !== 'scrypt' ||
      encrypted.cipher !== 'aes-256-gcm'
    ) {
      throw new Error('Unsupported encrypted vault format.');
    }
    if (!encrypted.ciphertext) return emptyPlaintextVault();
    const salt = Buffer.from(encrypted.salt, 'base64');
    const iv = Buffer.from(encrypted.iv, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    const key = await deriveKey(this.#passphrase, salt);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
      decipher.final(),
    ]);
    const parsed = JSON.parse(plaintext.toString('utf8')) as VaultPlaintextV1;
    if (parsed.version !== 1 || !parsed.entries) {
      throw new Error('Unsupported encrypted vault format.');
    }
    return parsed;
  }

  async #readPlaintext(): Promise<VaultPlaintextV1> {
    if (!(await this.#store.exists())) return emptyPlaintextVault();
    const encrypted = await this.#store.read();
    return this.#decryptPlaintext(encrypted);
  }

  async #writePlaintext(plaintext: VaultPlaintextV1): Promise<void> {
    await this.#store.write(await this.#encryptPlaintext(plaintext));
  }

  async #mutate<R>(
    mutation: (vault: VaultPlaintextV1) => Promise<R> | R,
  ): Promise<R> {
    const previous = this.#mutationTail;
    let release: () => void = () => undefined;
    this.#mutationTail = new Promise<void>((resolveMutation) => {
      release = resolveMutation;
    });
    await previous;
    try {
      const vault = await this.#readPlaintext();
      const result = await mutation(vault);
      await this.#writePlaintext(vault);
      return result;
    } finally {
      release();
    }
  }

  async #readClaimFile(
    path: string,
    expectedReference?: string,
  ): Promise<{ reference: string; entry: VaultEntry }> {
    const encrypted = JSON.parse(
      await readFile(path, 'utf8'),
    ) as EncryptedVaultV1;
    const plaintext = await this.#decryptPlaintext(encrypted);
    const entries = Object.entries(plaintext.entries);
    if (
      entries.length !== 1 ||
      !entries[0] ||
      (expectedReference !== undefined &&
        entries[0][0] !== expectedReference)
    ) {
      throw new Error('Invalid encrypted vault claim.');
    }
    const [reference, entry] = entries[0];
    validateReference(reference);
    if (this.#claimPath(reference) !== path) {
      throw new Error('Invalid encrypted vault claim reference.');
    }
    return { reference, entry };
  }

  async #readClaim(reference: string): Promise<VaultEntry | null> {
    try {
      return (
        await this.#readClaimFile(
          this.#claimPath(reference),
          reference,
        )
      ).entry;
    } catch (error) {
      if (isMissing(error)) return null;
      throw error;
    }
  }

  async #readAllClaims(): Promise<
    Array<{ reference: string; entry: VaultEntry }>
  > {
    let names: string[];
    try {
      names = await readdir(this.#claimDirectory);
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
    const claims = await Promise.all(
      names
        .filter((name) => CLAIM_FILE_PATTERN.test(name))
        .map((name) =>
          this.#readClaimFile(resolve(this.#claimDirectory, name)),
        ),
    );
    return claims;
  }

  async #createClaimIfAbsent(
    reference: string,
    entry: VaultEntry,
  ): Promise<{ inserted: boolean; entry: VaultEntry }> {
    await mkdir(this.#claimDirectory, {
      recursive: true,
      mode: 0o700,
    });
    const claimPath = this.#claimPath(reference);
    const temporaryPath = resolve(
      this.#claimDirectory,
      `.${process.pid}.${randomUUID()}.claim.tmp`,
    );
    const encrypted = await this.#encryptPlaintext({
      version: 1,
      entries: { [reference]: entry },
    });
    const handle = await open(temporaryPath, 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(encrypted), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      for (
        let attempt = 0;
        attempt < CLAIM_CONTENTION_RETRIES;
        attempt += 1
      ) {
        if (await this.#isTombstoned(reference)) {
          throw new Error(
            'A deleted local secret reference cannot be reused.',
          );
        }
        try {
          await link(temporaryPath, claimPath);
          if (await this.#isTombstoned(reference)) {
            await this.#removeClaim(reference);
            throw new Error(
              'A deleted local secret reference cannot be reused.',
            );
          }
          return { inserted: true, entry };
        } catch (error) {
          if (!isAlreadyExists(error)) throw error;
          const existing = await this.#readClaim(reference);
          if (existing) {
            return { inserted: false, entry: existing };
          }
          await waitForContention(attempt);
        }
      }
      throw new Error('Encrypted vault claim contention did not settle.');
    } finally {
      await unlink(temporaryPath).catch(() => undefined);
    }
  }

  async #removeClaim(reference: string): Promise<boolean> {
    const claimPath = this.#claimPath(reference);
    const tombstonePath = resolve(
      this.#claimDirectory,
      `.${process.pid}.${randomUUID()}.delete.tmp`,
    );
    try {
      await rename(claimPath, tombstonePath);
    } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
    await unlink(tombstonePath);
    return true;
  }

  async put(
    reference: string,
    value: string,
    options: {
      kind?: VaultEntry['kind'];
      binding?: VaultEntry['binding'];
    } = {},
  ): Promise<void> {
    validateReference(reference);
    if (!value) throw new Error('A local secret cannot be empty.');
    if (await this.#isTombstoned(reference)) {
      throw new Error('A deleted local secret reference cannot be reused.');
    }
    if (
      reference.startsWith('order:') &&
      (options.kind === 'access-secret' ||
        options.kind === 'received-access-secret')
    ) {
      const binding = await this.putIfAbsent(
        reference,
        value,
        options,
      );
      if (binding.value !== value) {
        throw new Error(
          'A different access secret is already bound to this order reference.',
        );
      }
      return;
    }
    await this.#mutate((vault) => {
      vault.entries[reference] = {
        value,
        createdAt: this.#clock().toISOString(),
        kind: options.kind ?? 'generic',
        ...(options.binding ? { binding: options.binding } : {}),
      };
    });
  }

  async putIfAbsent(
    reference: string,
    value: string,
    options: {
      kind?: VaultEntry['kind'];
      binding?: VaultEntry['binding'];
    } = {},
  ): Promise<{ inserted: boolean; value: string }> {
    validateReference(reference);
    if (!value) throw new Error('A local secret cannot be empty.');
    if (await this.#isTombstoned(reference)) {
      throw new Error('A deleted local secret reference cannot be reused.');
    }
    const plaintext = await this.#readPlaintext();
    const existing = plaintext.entries[reference];
    const candidate =
      existing ??
      ({
        value,
        createdAt: this.#clock().toISOString(),
        kind: options.kind ?? 'generic',
        ...(options.binding ? { binding: options.binding } : {}),
      } satisfies VaultEntry);
    const claim = await this.#createClaimIfAbsent(
      reference,
      candidate,
    );
    await this.#mutate((vault) => {
      vault.entries[reference] = claim.entry;
    });
    return {
      inserted: claim.inserted && !existing,
      value: claim.entry.value,
    };
  }

  async createAccessSecret(
    reference: string,
    binding: NonNullable<VaultEntry['binding']>,
  ): Promise<void> {
    await this.put(reference, `0x${randomBytes(32).toString('hex')}`, {
      kind: 'access-secret',
      binding,
    });
  }

  async get(reference: string): Promise<string | null> {
    validateReference(reference);
    if (await this.#isTombstoned(reference)) return null;
    const claim = await this.#readClaim(reference);
    if (claim) return claim.value;
    const vault = await this.#readPlaintext();
    return vault.entries[reference]?.value ?? null;
  }

  async has(reference: string): Promise<boolean> {
    return (await this.get(reference)) !== null;
  }

  async hasAccessSecretValue(candidate: string): Promise<boolean> {
    if (
      !/^0[xX][0-9a-fA-F]{64}$/u.test(candidate) ||
      /^0[xX]0{64}$/u.test(candidate)
    ) {
      return false;
    }
    const normalized = candidate.toLowerCase();
    const vault = await this.#readPlaintext();
    const activeEntries = await Promise.all(
      Object.entries(vault.entries).map(
        async ([reference, entry]) => ({
          active: !(await this.#isTombstoned(reference)),
          entry,
        }),
      ),
    );
    if (activeEntries.some(
      ({ active, entry }) =>
        active && entryContainsAccessSecret(entry, normalized),
    )) {
      return true;
    }
    const claims = await Promise.all(
      (await this.#readAllClaims()).map(
        async ({ reference, entry }) => ({
          active: !(await this.#isTombstoned(reference)),
          entry,
        }),
      ),
    );
    return claims.some(
      ({ active, entry }) =>
        active && entryContainsAccessSecret(entry, normalized),
    );
  }

  async delete(reference: string): Promise<boolean> {
    validateReference(reference);
    const tombstoneCreated = await this.#createTombstone(reference);
    const claimDeleted = await this.#removeClaim(reference);
    const entryDeleted = await this.#mutate((vault) => {
      const existed = reference in vault.entries;
      delete vault.entries[reference];
      return existed;
    });
    return tombstoneCreated && (claimDeleted || entryDeleted);
  }

  async deletePrefix(prefix: string): Promise<number> {
    validateReference(prefix);
    const claimReferences = (await this.#readAllClaims())
      .map(({ reference }) => reference)
      .filter((reference) => reference.startsWith(prefix));
    const deletedClaims = new Set<string>();
    for (const reference of claimReferences) {
      await this.#createTombstone(reference);
      if (await this.#removeClaim(reference)) {
        deletedClaims.add(reference);
      }
    }
    const plaintext = await this.#readPlaintext();
    const aggregateReferences = Object.keys(plaintext.entries).filter(
      (reference) => reference.startsWith(prefix),
    );
    for (const reference of aggregateReferences) {
      await this.#createTombstone(reference);
    }
    const deletedEntries = await this.#mutate((vault) => {
      const matches = Object.keys(vault.entries).filter((reference) =>
        reference.startsWith(prefix),
      );
      for (const reference of matches) delete vault.entries[reference];
      return matches;
    });
    return new Set([...deletedClaims, ...deletedEntries]).size;
  }

  async getAccessSecret(
    reference: string,
    expected: {
      operationHash: string;
      recipient: string;
      escrowContract: string;
      localId: string;
    },
  ): Promise<string | null> {
    validateReference(reference);
    if (await this.#isTombstoned(reference)) return null;
    const claim = await this.#readClaim(reference);
    const entry =
      claim ?? (await this.#readPlaintext()).entries[reference];
    if (
      entry?.kind !== 'access-secret' ||
      entry.binding?.operationHash?.toLowerCase() !==
        expected.operationHash.toLowerCase() ||
      entry.binding?.recipient?.toLowerCase() !==
        expected.recipient.toLowerCase() ||
      entry.binding?.escrowContract?.toLowerCase() !==
        expected.escrowContract.toLowerCase() ||
      entry.binding?.localId !== expected.localId
    ) {
      return null;
    }
    return entry.value;
  }
}
