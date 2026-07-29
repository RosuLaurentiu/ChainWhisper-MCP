import { randomBytes } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  assertPrivateCredentialFile,
  ensurePrivateStateDirectory,
  isMissingPathError,
} from './stateSecurity.js';

const STORAGE_KEY_FILE_NAME = 'storage.key';
const STORAGE_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;

const validateStorageKey = (value: string): string => {
  const normalized = value.trim();
  if (!STORAGE_KEY_PATTERN.test(normalized)) {
    throw new Error('The internal signer storage key is invalid.');
  }
  return normalized;
};

export const resolveInternalStorageKeyPath = (
  stateDirectory: string,
): string => resolve(stateDirectory, STORAGE_KEY_FILE_NAME);

export const getOrCreateInternalStorageKey = async (
  stateDirectory: string,
): Promise<string> => {
  const directory = await ensurePrivateStateDirectory(stateDirectory);
  const path = resolveInternalStorageKeyPath(directory);
  try {
    await assertPrivateCredentialFile(path);
    return validateStorageKey(await readFile(path, 'utf8'));
  } catch (error) {
    if (!isMissingPathError(error)) throw error;
  }

  const generated = randomBytes(32).toString('base64url');
  try {
    const handle = await open(path, 'wx', 0o600);
    try {
      await handle.writeFile(`${generated}\n`, 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    return generated;
  } catch (error) {
    if (!(
      error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: unknown }).code === 'EEXIST'
    )) {
      throw error;
    }
    await assertPrivateCredentialFile(path);
    return validateStorageKey(await readFile(path, 'utf8'));
  }
};
