import {
  mkdtemp,
  readFile,
  readdir,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  EncryptedSecretVault,
  orderAccessSecretReference,
  type Address,
  type HexString,
} from '../src/signer/index.js';

const PASSPHRASE = 'a-long-shared-vault-passphrase';
const RECIPIENT =
  '0x1111111111111111111111111111111111111111' as Address;
const ESCROW =
  '0x2222222222222222222222222222222222222222' as Address;
const FIRST_OPERATION = `0x${'33'.repeat(32)}` as HexString;
const SECOND_OPERATION = `0x${'44'.repeat(32)}` as HexString;
const FIRST_SECRET = `0x${'55'.repeat(32)}` as HexString;
const SECOND_SECRET = `0x${'66'.repeat(32)}` as HexString;

const storedAccessSecret = (
  operationHash: HexString,
  secret: HexString,
): string =>
  JSON.stringify({
    version: 1,
    operationHash,
    recipient: RECIPIENT,
    escrowContract: ESCROW,
    localId: '9',
    secret,
  });

describe('encrypted signer vault cross-instance safety', () => {
  it('atomically preserves one putIfAbsent winner across two vault instances', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-vault-cas-'),
    );
    const firstVault = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    const secondVault = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    const reference = orderAccessSecretReference(
      RECIPIENT,
      ESCROW,
      '9',
    );
    const firstRecord = storedAccessSecret(
      FIRST_OPERATION,
      FIRST_SECRET,
    );
    const secondRecord = storedAccessSecret(
      SECOND_OPERATION,
      SECOND_SECRET,
    );

    const [first, second] = await Promise.all([
      firstVault.putIfAbsent(reference, firstRecord, {
        kind: 'received-access-secret',
        binding: {
          operationHash: FIRST_OPERATION,
          recipient: RECIPIENT,
          escrowContract: ESCROW,
          localId: '9',
        },
      }),
      secondVault.putIfAbsent(reference, secondRecord, {
        kind: 'received-access-secret',
        binding: {
          operationHash: SECOND_OPERATION,
          recipient: RECIPIENT,
          escrowContract: ESCROW,
          localId: '9',
        },
      }),
    ]);

    expect([first.inserted, second.inserted].sort()).toEqual([
      false,
      true,
    ]);
    const winningRecord = first.inserted ? firstRecord : secondRecord;
    const losingRecord = first.inserted ? secondRecord : firstRecord;
    const losingVault = first.inserted ? secondVault : firstVault;
    expect(first.value).toBe(winningRecord);
    expect(second.value).toBe(winningRecord);
    expect(await firstVault.get(reference)).toBe(winningRecord);
    expect(await secondVault.get(reference)).toBe(winningRecord);

    const retry = await losingVault.putIfAbsent(
      reference,
      losingRecord,
      { kind: 'received-access-secret' },
    );
    expect(retry).toEqual({
      inserted: false,
      value: winningRecord,
    });

    // The immutable claim is authoritative if a process crashes after
    // publishing it but before the aggregate vault file is durable.
    await unlink(join(stateDirectory, 'secrets.v1.enc.json'));
    const recoveredVault = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    expect(await recoveredVault.get(reference)).toBe(winningRecord);

    const claimDirectory = join(
      stateDirectory,
      '.secrets.v1.claims',
    );
    const encryptedFiles = await Promise.all([
      ...(await readdir(claimDirectory)).map((name) =>
        readFile(join(claimDirectory, name), 'utf8'),
      ),
    ]);
    for (const encrypted of encryptedFiles) {
      expect(encrypted).not.toContain(FIRST_SECRET);
      expect(encrypted).not.toContain(SECOND_SECRET);
      expect(encrypted).not.toContain(RECIPIENT);
    }
  });

  it('recognizes a structurally valid encoded access secret without trusting its entry kind', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-vault-encoded-'),
    );
    const vault = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    await vault.put(
      'migration:encoded-record',
      storedAccessSecret(FIRST_OPERATION, FIRST_SECRET),
      { kind: 'generic' },
    );
    await vault.put('migration:raw-generic', SECOND_SECRET, {
      kind: 'generic',
    });

    expect(await vault.hasAccessSecretValue(FIRST_SECRET)).toBe(true);
    expect(
      await vault.hasAccessSecretValue(
        `0X${FIRST_SECRET.slice(2).toUpperCase()}`,
      ),
    ).toBe(true);
    expect(await vault.hasAccessSecretValue(SECOND_SECRET)).toBe(false);
    expect(
      await vault.hasAccessSecretValue(
        `0x${'00'.repeat(32)}`,
      ),
    ).toBe(false);
  });

  it('keeps deletion authoritative over a delayed stale aggregate write', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-vault-delete-'),
    );
    const vault = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    const reference = orderAccessSecretReference(
      RECIPIENT,
      ESCROW,
      '9',
    );
    const record = storedAccessSecret(
      FIRST_OPERATION,
      FIRST_SECRET,
    );
    await vault.putIfAbsent(reference, record, {
      kind: 'received-access-secret',
    });
    const staleAggregate = await readFile(vault.path);

    expect(await vault.delete(reference)).toBe(true);
    // Model a second process that completed an already-started write
    // using the aggregate snapshot from before deletion.
    await writeFile(vault.path, staleAggregate);

    const recovered = new EncryptedSecretVault(
      stateDirectory,
      PASSPHRASE,
    );
    expect(await recovered.get(reference)).toBeNull();
    expect(
      await recovered.hasAccessSecretValue(FIRST_SECRET),
    ).toBe(false);
    await expect(
      recovered.putIfAbsent(reference, record, {
        kind: 'received-access-secret',
      }),
    ).rejects.toThrow('deleted local secret reference');
  });
});
