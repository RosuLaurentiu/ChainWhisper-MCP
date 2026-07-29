import { lstat, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';
import { getOrCreatePairingSecret } from '../shared/index.js';

import { isCotiAesKey } from './cotiAes.js';
import { SignerError } from './errors.js';
import type {
  Address,
  FormElicitor,
  HexString,
  PublicSignerStatus,
  SignerRuntimeConfig,
  SignerSecrets,
} from './types.js';

const PRIVATE_HEX_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;

type SignerConfigFile = {
  rpcUrl?: unknown;
  stateDirectory?: unknown;
  expectedWallet?: unknown;
  privateKey?: unknown;
  aesKey?: unknown;
  vaultPassphrase?: unknown;
  confirmationChannel?: unknown;
  confirmationTimeoutMs?: unknown;
  operationExpirySkewMs?: unknown;
};

export type SignerConfigEnvironment = Record<string, string | undefined>;

const requireString = (
  value: unknown,
  name: string,
  minimumLength = 1,
): string => {
  if (typeof value !== 'string' || value.length < minimumLength) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `${name} must be configured outside the MCP conversation.`,
    );
  }
  return value;
};

const requirePrivateHex = (value: unknown, name: string): HexString => {
  const parsed = requireString(value, name);
  if (!PRIVATE_HEX_PATTERN.test(parsed)) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `${name} must be a 32-byte hexadecimal value.`,
    );
  }
  return parsed.toLowerCase() as HexString;
};

const requireAesBootstrapHex = (value: unknown, name: string): string => {
  const parsed = requireString(value, name);
  if (
    !/^(?:0x)?(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})$/u.test(parsed)
  ) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `${name} must be hexadecimal. COTI account keys are 16 bytes; a legacy 32-byte bootstrap value is accepted only so the wallet can be onboarded.`,
    );
  }
  return parsed;
};

const optionalAddress = (value: unknown, name: string): Address | undefined => {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `${name} must be a valid EVM address.`,
    );
  }
  return value.toLowerCase() as Address;
};

const positiveInteger = (
  value: unknown,
  fallback: number,
  name: string,
): number => {
  if (value === undefined || value === '') return fallback;
  const parsed =
    typeof value === 'number' ? value : Number.parseInt(String(value), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `${name} must be a positive integer.`,
    );
  }
  return parsed;
};

const confirmationChannel = (
  value: unknown,
): 'mcp' | 'local-web' => {
  if (value === undefined || value === '') return 'local-web';
  if (value !== 'mcp' && value !== 'local-web') {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      'CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL must be "mcp" or "local-web".',
    );
  }
  return value;
};

const resolveStateDirectory = (value: unknown): string => {
  const requested =
    typeof value === 'string' && value.trim()
      ? value.trim()
      : resolve(homedir(), '.chainwhisper-agent');
  return isAbsolute(requested) ? requested : resolve(process.cwd(), requested);
};

const loadConfigFile = async (
  environment: SignerConfigEnvironment,
): Promise<SignerConfigFile> => {
  const requested = environment.CHAINWHISPER_SIGNER_CONFIG_FILE?.trim();
  if (!requested) return {};
  const absolute = isAbsolute(requested)
    ? requested
    : resolve(process.cwd(), requested);
  try {
    const details = await lstat(absolute);
    if (!details.isFile() || details.isSymbolicLink()) {
      throw new Error('configuration path must be a regular, non-symbolic-link file');
    }
    if (
      process.platform !== 'win32' &&
      (details.mode & 0o077) !== 0
    ) {
      throw new Error(
        'configuration file must not be readable or writable by group or other users (use chmod 600)',
      );
    }
    const parsed: unknown = JSON.parse(await readFile(absolute, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('configuration root must be an object');
    }
    return parsed as SignerConfigFile;
  } catch (error) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      `Unable to load the signer configuration file: ${
        error instanceof Error ? error.message : 'invalid file'
      }`,
    );
  }
};

const choose = (
  environment: SignerConfigEnvironment,
  environmentName: string,
  fileValue: unknown,
): unknown => environment[environmentName] ?? fileValue;

export class LoadedSignerConfig {
  readonly chainId: number;
  readonly rpcUrl: string;
  readonly stateDirectory: string;
  readonly expectedWallet?: Address;
  readonly confirmationChannel: 'mcp' | 'local-web';
  readonly confirmationTimeoutMs: number;
  readonly operationExpirySkewMs: number;
  readonly #secrets: SignerSecrets;

  constructor(config: SignerRuntimeConfig) {
    this.chainId = config.chainId;
    this.rpcUrl = config.rpcUrl;
    this.stateDirectory = config.stateDirectory;
    this.expectedWallet = config.expectedWallet;
    this.confirmationChannel = config.confirmationChannel ?? 'local-web';
    this.confirmationTimeoutMs = config.confirmationTimeoutMs;
    this.operationExpirySkewMs = config.operationExpirySkewMs;
    this.#secrets = { ...config.secrets };
  }

  credentialMaterial(): SignerSecrets {
    return { ...this.#secrets };
  }

  toJSON(): Record<string, unknown> {
    return {
      chainId: this.chainId,
      rpcUrl: this.rpcUrl,
      stateDirectory: this.stateDirectory,
      expectedWallet: this.expectedWallet ?? null,
      confirmationChannel: this.confirmationChannel,
      configured: true,
      secrets: '[redacted]',
    };
  }
}

export const loadSignerConfig = async (
  environment: SignerConfigEnvironment = process.env,
): Promise<LoadedSignerConfig> => {
  const file = await loadConfigFile(environment);
  const privateKey = requirePrivateHex(
    choose(environment, 'CHAINWHISPER_SIGNER_PRIVATE_KEY', file.privateKey),
    'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  );
  const aesKey = requireAesBootstrapHex(
    choose(environment, 'CHAINWHISPER_SIGNER_AES_KEY', file.aesKey),
    'CHAINWHISPER_SIGNER_AES_KEY',
  );
  const vaultPassphrase = requireString(
    choose(
      environment,
      'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
      file.vaultPassphrase,
    ),
    'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
    16,
  );
  const rpcUrl = requireString(
    choose(environment, 'CHAINWHISPER_COTI_RPC_URL', file.rpcUrl) ??
      'https://mainnet.coti.io/rpc',
    'CHAINWHISPER_COTI_RPC_URL',
  );
  let parsedRpcUrl: URL;
  try {
    parsedRpcUrl = new URL(rpcUrl);
  } catch {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      'CHAINWHISPER_COTI_RPC_URL must be a valid URL.',
    );
  }
  if (!['https:', 'http:'].includes(parsedRpcUrl.protocol)) {
    throw new SignerError(
      'CONFIGURATION_REQUIRED',
      'CHAINWHISPER_COTI_RPC_URL must use HTTP or HTTPS.',
    );
  }

  const stateDirectory = resolveStateDirectory(
    choose(
      environment,
      'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
      file.stateDirectory,
    ) ?? environment.CHAINWHISPER_STATE_DIRECTORY,
  );
  const pairingSecret = await getOrCreatePairingSecret({
    environment,
    stateDirectory,
  });

  return new LoadedSignerConfig({
    chainId: 2_632_500,
    rpcUrl: parsedRpcUrl.toString(),
    stateDirectory,
    expectedWallet: optionalAddress(
      choose(
        environment,
        'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
        file.expectedWallet,
      ),
      'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
    ),
    confirmationChannel: confirmationChannel(
      choose(
        environment,
        'CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL',
        file.confirmationChannel,
      ),
    ),
    confirmationTimeoutMs: positiveInteger(
      choose(
        environment,
        'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
        file.confirmationTimeoutMs,
      ),
      60_000,
      'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
    ),
    operationExpirySkewMs: positiveInteger(
      choose(
        environment,
        'CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS',
        file.operationExpirySkewMs,
      ),
      5_000,
      'CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS',
    ),
    secrets: {
      privateKey,
      aesKey,
      pairingSecret,
      vaultPassphrase,
    },
  });
};

export const buildPublicSignerStatus = (
  config: LoadedSignerConfig | null,
  wallet: Address | null,
  elicitor: FormElicitor | null,
  privacyReady?: boolean,
): PublicSignerStatus => {
  if (!config) {
    return {
      chainId: 2_632_500,
      wallet,
      configured: false,
      aesConfigured: false,
      privateTransactions: 'onboarding-required',
      pairingConfigured: false,
      confirmation: elicitor?.isSupported() ? 'available' : 'unsupported',
      mode: 'configuration-required',
    };
  }
  const confirmation = elicitor?.isSupported()
    ? 'available'
    : 'unsupported';
  const hasPrivacyKey =
    privacyReady ??
    isCotiAesKey(config.credentialMaterial().aesKey);
  return {
    chainId: config.chainId,
    wallet,
    configured: true,
    aesConfigured: hasPrivacyKey,
    privateTransactions: hasPrivacyKey
      ? 'ready'
      : 'onboarding-required',
    pairingConfigured: true,
    confirmation,
    mode: confirmation === 'available' ? 'read-write' : 'read-only',
  };
};
