import { randomBytes } from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import { resolve } from 'node:path';

import { SignerError } from './errors.js';

const LOCK_FILE_NAME = 'signer.instance.lock';

const errorCode = (error: unknown): string | undefined =>
  error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;

type LockOwnerV1 = {
  version: 1;
  token: string;
  pid: number;
  createdAt: string;
};

const parseOwner = (serialized: string): LockOwnerV1 | null => {
  try {
    const value = JSON.parse(serialized) as Partial<LockOwnerV1>;
    return value.version === 1 &&
      typeof value.token === 'string' &&
      /^[0-9a-f]{64}$/u.test(value.token) &&
      Number.isSafeInteger(value.pid) &&
      typeof value.createdAt === 'string'
      ? (value as LockOwnerV1)
      : null;
  } catch {
    return null;
  }
};

export class SignerInstanceLock {
  readonly path: string;
  readonly #token: string;
  readonly #handle: FileHandle;
  #released = false;

  constructor(path: string, token: string, handle: FileHandle) {
    this.path = path;
    this.#token = token;
    this.#handle = handle;
  }

  async release(): Promise<void> {
    if (this.#released) return;

    let owner: LockOwnerV1 | null = null;
    try {
      owner = parseOwner(await readFile(this.path, 'utf8'));
    } catch {
      owner = null;
    }
    if (!owner || owner.token !== this.#token) {
      this.#released = true;
      await this.#handle.close().catch(() => undefined);
      throw new SignerError(
        'SIGNER_LOCK_OWNERSHIP_LOST',
        'The signer lock ownership changed; the lock was left in place.',
      );
    }

    this.#released = true;
    await this.#handle.close();
    try {
      await unlink(this.path);
    } catch {
      throw new SignerError(
        'SIGNER_LOCK_OWNERSHIP_LOST',
        'The signer lock could not be released safely.',
      );
    }
  }
}

export const acquireSignerInstanceLock = async (
  stateDirectory: string,
): Promise<SignerInstanceLock> => {
  const directory = resolve(stateDirectory);
  const path = resolve(directory, LOCK_FILE_NAME);
  await mkdir(directory, { recursive: true, mode: 0o700 });

  let handle: FileHandle;
  try {
    handle = await open(path, 'wx', 0o600);
  } catch (error) {
    if (errorCode(error) === 'EEXIST') {
      throw new SignerError(
        'SIGNER_ALREADY_RUNNING',
        'The signer state directory is already locked. Stale locks are not removed automatically.',
      );
    }
    throw error;
  }

  const token = randomBytes(32).toString('hex');
  const owner: LockOwnerV1 = {
    version: 1,
    token,
    pid: process.pid,
    createdAt: new Date().toISOString(),
  };
  try {
    await handle.writeFile(`${JSON.stringify(owner)}\n`, 'utf8');
    await handle.sync();
    return new SignerInstanceLock(path, token, handle);
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(path).catch(() => undefined);
    throw error;
  }
};
