import { randomBytes } from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  rename,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import { connect } from 'node:net';
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
  controlPort?: number;
};

const parseOwner = (serialized: string): LockOwnerV1 | null => {
  try {
    const value = JSON.parse(serialized) as Partial<LockOwnerV1>;
    return value.version === 1 &&
      typeof value.token === 'string' &&
      /^[0-9a-f]{64}$/u.test(value.token) &&
      Number.isSafeInteger(value.pid) &&
      typeof value.createdAt === 'string' &&
      (value.controlPort === undefined ||
        (Number.isSafeInteger(value.controlPort) &&
          value.controlPort >= 1 &&
          value.controlPort <= 65_535))
      ? (value as LockOwnerV1)
      : null;
  } catch {
    return null;
  }
};

const pidIsAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== 'ESRCH';
  }
};

const loopbackPortIsClosed = async (port: number): Promise<boolean> =>
  new Promise((resolveClosed) => {
    let settled = false;
    const socket = connect({ host: '127.0.0.1', port });
    const finish = (closed: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolveClosed(closed);
    };
    socket.setTimeout(500);
    socket.once('connect', () => finish(false));
    socket.once('timeout', () => finish(false));
    socket.once('error', (error) =>
      finish(errorCode(error) === 'ECONNREFUSED'),
    );
  });

const ownerIsGone = async (owner: LockOwnerV1): Promise<boolean> =>
  !pidIsAlive(owner.pid) &&
  owner.controlPort !== undefined &&
  (await loopbackPortIsClosed(owner.controlPort));

const reclaimDeadOwner = async (
  path: string,
  observed: LockOwnerV1,
): Promise<boolean> => {
  if (!(await ownerIsGone(observed))) return false;
  const stalePath = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.stale`;
  try {
    await rename(path, stalePath);
  } catch (error) {
    return errorCode(error) === 'ENOENT';
  }
  const moved = parseOwner(await readFile(stalePath, 'utf8').catch(() => ''));
  if (
    !moved ||
    moved.token !== observed.token ||
    !(await ownerIsGone(moved))
  ) {
    await rename(stalePath, path).catch(() => undefined);
    return false;
  }
  await unlink(stalePath);
  return true;
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

  async setControlPort(controlPort: number): Promise<void> {
    if (
      this.#released ||
      !Number.isSafeInteger(controlPort) ||
      controlPort < 1 ||
      controlPort > 65_535
    ) {
      throw new SignerError(
        'SIGNER_LOCK_OWNERSHIP_LOST',
        'The signer control health binding could not be recorded safely.',
      );
    }
    const owner = parseOwner(await readFile(this.path, 'utf8').catch(() => ''));
    if (!owner || owner.token !== this.#token || owner.pid !== process.pid) {
      throw new SignerError(
        'SIGNER_LOCK_OWNERSHIP_LOST',
        'The signer lock ownership changed; its control health binding was not updated.',
      );
    }
    const updated: LockOwnerV1 = { ...owner, controlPort };
    const serialized = Buffer.from(`${JSON.stringify(updated)}\n`, 'utf8');
    await this.#handle.truncate(0);
    await this.#handle.write(serialized, 0, serialized.length, 0);
    await this.#handle.sync();
  }

  async release(): Promise<void> {
    if (this.#released) return;

    let owner: LockOwnerV1 | null;
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

  let handle: FileHandle | null = null;
  for (let attempt = 0; attempt < 2 && !handle; attempt += 1) {
    try {
      handle = await open(path, 'wx', 0o600);
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error;
      const observed = parseOwner(
        await readFile(path, 'utf8').catch(() => ''),
      );
      if (
        attempt === 0 &&
        observed &&
        (await reclaimDeadOwner(path, observed))
      ) {
        continue;
      }
      throw new SignerError(
        'SIGNER_ALREADY_RUNNING',
        'The signer state directory is locked by a live or unverifiable signer.',
      );
    }
  }
  if (!handle) {
    throw new SignerError(
      'SIGNER_ALREADY_RUNNING',
      'The signer state directory could not be locked.',
    );
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
