import { isAbsolute, resolve } from 'node:path';

import {
  readPrivateCredentialFile,
  writePrivateCredentialFileAtomic,
} from './stateSecurity.js';

export const DEFAULT_SIGNER_ENV_FILE_NAME = 'signer.env';

const SIGNER_ENV_KEYS = [
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_COTI_RPC_URL',
  'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
  'CHAINWHISPER_STATE_DIRECTORY',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  'CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL',
  'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
  'CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS',
  // Accepted for one beta as a migration path. New setup never writes these.
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
] as const;

export type SignerEnvKey = (typeof SIGNER_ENV_KEYS)[number];
export type SignerEnvValues = Partial<Record<SignerEnvKey, string>>;
export type AgentWalletEnvInput = {
  privateKey: string;
  rpcUrl?: string;
  stateDirectory?: string;
};

const SIGNER_ENV_KEY_SET = new Set<string>(SIGNER_ENV_KEYS);
const PRIVATE_KEY_PATTERN = /^0x[0-9a-fA-F]{64}$/u;

const parseQuotedValue = (
  rawValue: string,
  lineNumber: number,
): string => {
  if (rawValue.startsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(rawValue);
      if (typeof parsed !== 'string') throw new Error('not a string');
      return parsed;
    } catch {
      throw new Error(
        `Signer environment line ${lineNumber} has an invalid quoted value.`,
      );
    }
  }
  if (rawValue.startsWith("'")) {
    if (rawValue.length < 2 || !rawValue.endsWith("'")) {
      throw new Error(
        `Signer environment line ${lineNumber} has an invalid quoted value.`,
      );
    }
    return rawValue.slice(1, -1);
  }
  if (/["']/u.test(rawValue)) {
    throw new Error(
      `Signer environment line ${lineNumber} has an invalid unquoted value.`,
    );
  }
  return rawValue.trim();
};

export const parseSignerEnv = (serialized: string): SignerEnvValues => {
  const values: SignerEnvValues = {};
  const seen = new Set<string>();
  const lines = serialized.replace(/^\uFEFF/u, '').split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index] ?? '';
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!match) {
      throw new Error(
        `Signer environment line ${index + 1} must use KEY=VALUE syntax.`,
      );
    }
    const key = match[1]!;
    if (!SIGNER_ENV_KEY_SET.has(key)) {
      throw new Error(
        `Signer environment line ${index + 1} contains an unsupported key.`,
      );
    }
    if (seen.has(key)) {
      throw new Error(
        `Signer environment line ${index + 1} duplicates a key.`,
      );
    }
    const value = parseQuotedValue(match[2]!, index + 1);
    if (
      value.includes(String.fromCharCode(0)) ||
      value.includes('\r') ||
      value.includes('\n')
    ) {
      throw new Error(
        `Signer environment line ${index + 1} contains an invalid value.`,
      );
    }
    seen.add(key);
    values[key as SignerEnvKey] = value;
  }
  return values;
};

export const serializeSignerEnv = (values: SignerEnvValues): string => {
  const unsupported = Object.keys(values).filter(
    (key) => !SIGNER_ENV_KEY_SET.has(key),
  );
  if (unsupported.length > 0) {
    throw new Error('Signer environment values contain an unsupported key.');
  }
  const lines = SIGNER_ENV_KEYS.flatMap((key) => {
    const value = values[key];
    return value === undefined ? [] : [`${key}=${JSON.stringify(value)}`];
  });
  return lines.length > 0 ? `${lines.join('\n')}\n` : '';
};

export const resolveSignerEnvFilePath = (
  environment: Record<string, string | undefined>,
  stateDirectory: string,
): { path: string; explicitlySelected: boolean } => {
  const configured = environment.CHAINWHISPER_SIGNER_ENV_FILE;
  if (configured !== undefined && !configured.trim()) {
    throw new Error(
      'CHAINWHISPER_SIGNER_ENV_FILE must not be empty when configured.',
    );
  }
  const requested = configured?.trim();
  if (!requested) {
    return {
      path: resolve(stateDirectory, DEFAULT_SIGNER_ENV_FILE_NAME),
      explicitlySelected: false,
    };
  }
  return {
    path: isAbsolute(requested)
      ? resolve(requested)
      : resolve(process.cwd(), requested),
    explicitlySelected: true,
  };
};

export const readSignerEnvFile = async (
  path: string,
): Promise<{ exists: boolean; values: SignerEnvValues }> => {
  const serialized = await readPrivateCredentialFile(path, {
    allowMissing: true,
  });
  return serialized === null
    ? { exists: false, values: {} }
    : { exists: true, values: parseSignerEnv(serialized) };
};

export const writeSignerEnvFile = async (
  path: string,
  updates: Partial<Record<SignerEnvKey, string | null>>,
): Promise<void> => {
  const current = await readSignerEnvFile(path);
  const next: SignerEnvValues = { ...current.values };
  for (const [key, value] of Object.entries(updates)) {
    if (!SIGNER_ENV_KEY_SET.has(key)) {
      throw new Error('Signer environment update contains an unsupported key.');
    }
    if (value === null) {
      delete next[key as SignerEnvKey];
    } else if (typeof value === 'string') {
      next[key as SignerEnvKey] = value;
    } else {
      throw new Error('Signer environment updates must be strings or null.');
    }
  }
  await writePrivateCredentialFileAtomic(path, serializeSignerEnv(next));
};

export const writeAgentWalletEnvFile = async (
  path: string,
  input: AgentWalletEnvInput,
): Promise<void> => {
  if (!PRIVATE_KEY_PATTERN.test(input.privateKey)) {
    throw new Error('The Agent Wallet private key must be 32-byte hexadecimal.');
  }
  await writeSignerEnvFile(path, {
    CHAINWHISPER_SIGNER_PRIVATE_KEY: input.privateKey.toLowerCase(),
    // Privacy material and an expected-wallet pin are wallet-bound. A wallet
    // import or replacement must never inherit them from the previous key.
    // The new wallet completes privacy onboarding only after the signer
    // activates it; replacement remains restart-gated for beta.
    CHAINWHISPER_SIGNER_AES_KEY: null,
    CHAINWHISPER_SIGNER_EXPECTED_WALLET: null,
    ...(input.rpcUrl === undefined
      ? {}
      : { CHAINWHISPER_COTI_RPC_URL: input.rpcUrl }),
    ...(input.stateDirectory === undefined
      ? {}
      : {
          CHAINWHISPER_SIGNER_STATE_DIRECTORY:
            input.stateDirectory,
        }),
  });
};
