import { randomBytes } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';

const MINIMUM_PAIRING_SECRET_LENGTH = 32;

const assertPrivatePath = async (
  path: string,
  kind: 'directory' | 'file',
): Promise<void> => {
  const details = await lstat(path);
  const expectedType =
    kind === 'directory' ? details.isDirectory() : details.isFile();
  if (!expectedType || details.isSymbolicLink()) {
    throw new Error(
      `The ChainWhisper pairing ${kind} must be a regular, non-symbolic-link ${kind}.`,
    );
  }
  if (
    process.platform !== 'win32' &&
    (details.mode & 0o077) !== 0
  ) {
    throw new Error(
      `The ChainWhisper pairing ${kind} must not be accessible by group or other users.`,
    );
  }
};

export interface PairingSecretOptions {
  environment?: NodeJS.ProcessEnv;
  pairingFile?: string;
  stateDirectory?: string;
}

const validatePairingSecret = (value: string): string => {
  const normalized = value.trim();
  if (normalized.length < MINIMUM_PAIRING_SECRET_LENGTH) {
    throw new Error('The ChainWhisper pairing secret must contain at least 32 characters.');
  }
  return normalized;
};

export const resolvePairingSecretPath = (options: PairingSecretOptions = {}): string => {
  const environment = options.environment ?? process.env;
  const requested =
    options.pairingFile ??
    environment.CHAINWHISPER_PAIRING_FILE ??
    resolve(
      options.stateDirectory ??
        environment.CHAINWHISPER_STATE_DIRECTORY ??
        resolve(homedir(), '.chainwhisper-agent'),
      'pairing.key'
    );
  return resolve(requested);
};

export const getOrCreatePairingSecret = async (
  options: PairingSecretOptions = {}
): Promise<string> => {
  const environment = options.environment ?? process.env;
  const configured = environment.CHAINWHISPER_PAIRING_SECRET?.trim();
  if (configured) {
    return validatePairingSecret(configured);
  }

  const pairingPath = resolvePairingSecretPath(options);
  const pairingDirectory = dirname(pairingPath);
  await mkdir(pairingDirectory, { recursive: true, mode: 0o700 });
  await assertPrivatePath(pairingDirectory, 'directory');
  try {
    await assertPrivatePath(pairingPath, 'file');
    return validatePairingSecret(await readFile(pairingPath, 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
  }

  const generated = randomBytes(32).toString('base64url');
  try {
    await writeFile(pairingPath, `${generated}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    });
    return generated;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      throw error;
    }
    await assertPrivatePath(pairingPath, 'file');
    return validatePairingSecret(await readFile(pairingPath, 'utf8'));
  }
};
