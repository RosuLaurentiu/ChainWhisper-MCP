import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';

const MINIMUM_PAIRING_SECRET_LENGTH = 32;

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
  await mkdir(dirname(pairingPath), { recursive: true, mode: 0o700 });
  try {
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
    return validatePairingSecret(await readFile(pairingPath, 'utf8'));
  }
};
