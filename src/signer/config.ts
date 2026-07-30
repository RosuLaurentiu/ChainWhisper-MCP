import { access } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { getOrCreatePairingSecret } from '../shared/index.js';

import { isCotiAesKey } from './cotiAes.js';
import { SignerError } from './errors.js';
import {
  ensurePrivateStateDirectory,
  readPrivateCredentialFile,
} from './stateSecurity.js';
import {
  getOrCreateInternalStorageKey,
  resolveInternalStorageKeyPath,
} from './storageKey.js';
import type {
  Address,
  FormElicitor,
  HexString,
  PublicSignerStatus,
  SignerRuntimeConfig,
  SignerSecrets,
} from './types.js';
import {
  readSignerEnvFile,
  resolveSignerEnvFilePath,
  type SignerEnvValues,
} from './walletEnv.js';

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

export type SignerConfigurationDiagnosticCode =
  | 'ready'
  | 'wallet-setup-required'
  | 'privacy-onboarding-required'
  | 'invalid-private-key'
  | 'invalid-aes-key'
  | 'invalid-rpc-url'
  | 'invalid-state-path'
  | 'invalid-env-file'
  | 'invalid-legacy-config'
  | 'legacy-storage-passphrase-required';

export class SignerConfigurationError extends SignerError {
  readonly diagnosticCode: Exclude<
    SignerConfigurationDiagnosticCode,
    'ready' | 'wallet-setup-required' | 'privacy-onboarding-required'
  >;

  constructor(
    diagnosticCode: SignerConfigurationError['diagnosticCode'],
    message: string,
  ) {
    super('CONFIGURATION_REQUIRED', message);
    this.name = 'SignerConfigurationError';
    this.diagnosticCode = diagnosticCode;
  }
}

type LoadedSignerSecrets = {
  privateKey?: HexString;
  aesKey?: string;
  pairingSecret: string;
  vaultPassphrase: string;
};

type LoadedSignerConfigInput = Omit<SignerRuntimeConfig, 'secrets'> & {
  secrets: LoadedSignerSecrets;
  environmentFilePath?: string | null;
  environmentFileExists?: boolean;
  aesExpectedWallet?: Address;
};

const requireString = (
  value: unknown,
  name: string,
  minimumLength = 1,
): string => {
  if (typeof value !== 'string' || value.length < minimumLength) {
    throw new SignerConfigurationError(
      name === 'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE'
        ? 'legacy-storage-passphrase-required'
        : 'invalid-legacy-config',
      `${name} must be configured outside the MCP conversation.`,
    );
  }
  return value;
};

const optionalPrivateHex = (
  value: unknown,
  name: string,
): HexString | undefined => {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string') {
    throw new SignerConfigurationError(
      'invalid-private-key',
      `${name} must be a 32-byte hexadecimal value.`,
    );
  }
  const parsed = value;
  if (!PRIVATE_HEX_PATTERN.test(parsed)) {
    throw new SignerConfigurationError(
      'invalid-private-key',
      `${name} must be a 32-byte hexadecimal value.`,
    );
  }
  return parsed.toLowerCase() as HexString;
};

const optionalAesBootstrapHex = (
  value: unknown,
  name: string,
): string | undefined => {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string') {
    throw new SignerConfigurationError(
      'invalid-aes-key',
      `${name} must be a hexadecimal COTI account key.`,
    );
  }
  const parsed = value;
  if (
    !/^(?:0x)?(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{64})$/u.test(parsed)
  ) {
    throw new SignerConfigurationError(
      'invalid-aes-key',
      `${name} must be hexadecimal. COTI account keys are 16 bytes; a legacy 32-byte bootstrap value is accepted only so the wallet can be onboarded.`,
    );
  }
  return parsed;
};

const optionalAddress = (value: unknown, name: string): Address | undefined => {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    throw new SignerConfigurationError(
      'invalid-legacy-config',
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
    throw new SignerConfigurationError(
      'invalid-legacy-config',
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
    throw new SignerConfigurationError(
      'invalid-legacy-config',
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
  return resolve(requested);
};

const loadConfigFile = async (
  environment: SignerConfigEnvironment,
): Promise<SignerConfigFile> => {
  const requested = environment.CHAINWHISPER_SIGNER_CONFIG_FILE?.trim();
  if (!requested) return {};
  const absolute = resolve(requested);
  try {
    const serialized = await readPrivateCredentialFile(absolute);
    const parsed: unknown = JSON.parse(serialized ?? '');
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid root');
    }
    return parsed as SignerConfigFile;
  } catch {
    throw new SignerConfigurationError(
      'invalid-legacy-config',
      'The legacy signer configuration file is missing, invalid, linked, or not private.',
    );
  }
};

const choose = (
  environment: SignerConfigEnvironment,
  dotenv: SignerEnvValues,
  environmentName: string,
  fileValue: unknown,
): unknown =>
  environment[environmentName] ??
  dotenv[environmentName as keyof SignerEnvValues] ??
  fileValue;

const chooseWalletBound = (
  environment: SignerConfigEnvironment,
  dotenv: SignerEnvValues,
  environmentName: 'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  fileValue: unknown,
): unknown => {
  if (environment.CHAINWHISPER_SIGNER_PRIVATE_KEY !== undefined) {
    return environment[environmentName];
  }
  if (dotenv.CHAINWHISPER_SIGNER_PRIVATE_KEY !== undefined) {
    return environment[environmentName] ?? dotenv[environmentName];
  }
  return choose(environment, dotenv, environmentName, fileValue);
};

const chooseAesBootstrap = (
  environment: SignerConfigEnvironment,
  dotenv: SignerEnvValues,
  file: SignerConfigFile,
): { value: unknown; expectedWallet: unknown } => {
  if (
    environment.CHAINWHISPER_SIGNER_PRIVATE_KEY !== undefined ||
    environment.CHAINWHISPER_SIGNER_AES_KEY !== undefined
  ) {
    return {
      value: environment.CHAINWHISPER_SIGNER_AES_KEY,
      expectedWallet:
        environment.CHAINWHISPER_SIGNER_EXPECTED_WALLET,
    };
  }
  if (
    dotenv.CHAINWHISPER_SIGNER_PRIVATE_KEY !== undefined ||
    dotenv.CHAINWHISPER_SIGNER_AES_KEY !== undefined
  ) {
    return {
      value: dotenv.CHAINWHISPER_SIGNER_AES_KEY,
      expectedWallet:
        dotenv.CHAINWHISPER_SIGNER_EXPECTED_WALLET,
    };
  }
  return {
    value: file.aesKey,
    expectedWallet: file.expectedWallet,
  };
};

const chooseStateDirectory = (
  environment: SignerConfigEnvironment,
  dotenv: SignerEnvValues,
  fileValue: unknown,
): unknown =>
  environment.CHAINWHISPER_SIGNER_STATE_DIRECTORY ??
  environment.CHAINWHISPER_STATE_DIRECTORY ??
  dotenv.CHAINWHISPER_SIGNER_STATE_DIRECTORY ??
  dotenv.CHAINWHISPER_STATE_DIRECTORY ??
  fileValue;

const isLoopbackHostname = (hostname: string): boolean => {
  const normalized = hostname
    .toLowerCase()
    .replace(/^\[/u, '')
    .replace(/\]$/u, '')
    .replace(/\.$/u, '');
  return normalized === 'localhost' ||
    normalized === '::1' ||
    /^127(?:\.\d{1,3}){3}$/u.test(normalized);
};

const validateRpcUrl = (value: unknown): string => {
  const rpcUrl = requireString(
    value ?? 'https://mainnet.coti.io/rpc',
    'CHAINWHISPER_COTI_RPC_URL',
  );
  let parsedRpcUrl: URL;
  try {
    parsedRpcUrl = new URL(rpcUrl);
  } catch {
    throw new SignerConfigurationError(
      'invalid-rpc-url',
      'CHAINWHISPER_COTI_RPC_URL must be a valid URL.',
    );
  }
  if (
    parsedRpcUrl.protocol !== 'https:' &&
    !(
      parsedRpcUrl.protocol === 'http:' &&
      isLoopbackHostname(parsedRpcUrl.hostname)
    )
  ) {
    throw new SignerConfigurationError(
      'invalid-rpc-url',
      'CHAINWHISPER_COTI_RPC_URL must use HTTPS; HTTP is allowed only for loopback development endpoints.',
    );
  }
  return parsedRpcUrl.toString();
};

const pathExists = async (path: string): Promise<boolean> => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};

export class LoadedSignerConfig {
  readonly chainId: number;
  readonly rpcUrl: string;
  readonly stateDirectory: string;
  readonly environmentFilePath: string | null;
  readonly environmentFileExists: boolean;
  readonly expectedWallet?: Address;
  readonly confirmationChannel: 'mcp' | 'local-web';
  readonly confirmationTimeoutMs: number;
  readonly operationExpirySkewMs: number;
  readonly #secrets: LoadedSignerSecrets;
  readonly #aesExpectedWallet?: Address;

  constructor(config: SignerRuntimeConfig | LoadedSignerConfigInput) {
    this.chainId = config.chainId;
    this.rpcUrl = config.rpcUrl;
    this.stateDirectory = config.stateDirectory;
    this.environmentFilePath =
      'environmentFilePath' in config
        ? config.environmentFilePath ?? null
        : null;
    this.environmentFileExists =
      'environmentFileExists' in config
        ? config.environmentFileExists ?? false
        : false;
    this.expectedWallet = config.expectedWallet;
    this.confirmationChannel = config.confirmationChannel ?? 'local-web';
    this.confirmationTimeoutMs = config.confirmationTimeoutMs;
    this.operationExpirySkewMs = config.operationExpirySkewMs;
    this.#secrets = { ...config.secrets };
    this.#aesExpectedWallet =
      'aesExpectedWallet' in config
        ? config.aesExpectedWallet
        : config.expectedWallet;
  }

  get walletConfigured(): boolean {
    return Boolean(this.#secrets.privateKey);
  }

  get aesConfigured(): boolean {
    return Boolean(this.#aesExpectedWallet) &&
      isCotiAesKey(this.#secrets.aesKey);
  }

  /**
   * Legacy environment/JSON AES material is usable only when its explicit
   * expected-wallet pin matches the active Agent Wallet. Wallet-scoped vault
   * material is supplied separately by the caller.
   */
  aesKeyForWallet(wallet: Address): string {
    if (
      !this.#aesExpectedWallet ||
      this.#aesExpectedWallet.toLowerCase() !== wallet.toLowerCase() ||
      !isCotiAesKey(this.#secrets.aesKey)
    ) {
      return '';
    }
    return this.#secrets.aesKey ?? '';
  }

  get configurationDiagnostic(): SignerConfigurationDiagnosticCode {
    if (!this.walletConfigured) return 'wallet-setup-required';
    if (!this.aesConfigured) return 'privacy-onboarding-required';
    return 'ready';
  }

  credentialMaterial(): SignerSecrets {
    if (!this.#secrets.privateKey) {
      throw new SignerError(
        'CONFIGURATION_REQUIRED',
        'Set up an Agent Wallet in the local ChainWhisper control page.',
      );
    }
    return {
      privateKey: this.#secrets.privateKey,
      aesKey: this.#secrets.aesKey ?? '',
      pairingSecret: this.#secrets.pairingSecret,
      vaultPassphrase: this.#secrets.vaultPassphrase,
    };
  }

  toJSON(): Record<string, unknown> {
    return {
      chainId: this.chainId,
      rpcUrl: this.rpcUrl,
      stateDirectory: this.stateDirectory,
      expectedWallet: this.expectedWallet ?? null,
      confirmationChannel: this.confirmationChannel,
      configured: this.walletConfigured,
      diagnosticCode: this.configurationDiagnostic,
      secrets: '[redacted]',
    };
  }
}

export const loadSignerConfig = async (
  environment: SignerConfigEnvironment = process.env,
): Promise<LoadedSignerConfig> => {
  const file = await loadConfigFile(environment);
  const preliminaryStateDirectory = resolveStateDirectory(
    environment.CHAINWHISPER_SIGNER_STATE_DIRECTORY ??
      environment.CHAINWHISPER_STATE_DIRECTORY ??
      file.stateDirectory,
  );
  let environmentFilePath: string;
  let environmentFileExists: boolean;
  let dotenv: SignerEnvValues;
  let environmentFileSelection: ReturnType<
    typeof resolveSignerEnvFilePath
  >;
  try {
    environmentFileSelection = resolveSignerEnvFilePath(
      environment,
      preliminaryStateDirectory,
    );
  } catch {
    throw new SignerConfigurationError(
      'invalid-env-file',
      'The signer environment file selection is invalid.',
    );
  }
  if (!environmentFileSelection.explicitlySelected) {
    try {
      await ensurePrivateStateDirectory(preliminaryStateDirectory);
    } catch {
      throw new SignerConfigurationError(
        'invalid-state-path',
        'The signer state directory is linked, unsafe, or accessible by other users.',
      );
    }
  }
  try {
    environmentFilePath = environmentFileSelection.path;
    const loaded = await readSignerEnvFile(environmentFileSelection.path);
    environmentFileExists = loaded.exists;
    dotenv = loaded.values;
  } catch {
    throw new SignerConfigurationError(
      'invalid-env-file',
      'The signer environment file is missing, invalid, linked, or not private.',
    );
  }

  const stateDirectory = resolveStateDirectory(
    chooseStateDirectory(environment, dotenv, file.stateDirectory),
  );
  try {
    await ensurePrivateStateDirectory(stateDirectory);
  } catch {
    throw new SignerConfigurationError(
      'invalid-state-path',
      'The signer state directory is linked, unsafe, or accessible by other users.',
    );
  }

  const privateKey = optionalPrivateHex(
    choose(
      environment,
      dotenv,
      'CHAINWHISPER_SIGNER_PRIVATE_KEY',
      file.privateKey,
    ),
    'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  );
  const aesBootstrap = chooseAesBootstrap(
    environment,
    dotenv,
    file,
  );
  const aesKey = optionalAesBootstrapHex(
    aesBootstrap.value,
    'CHAINWHISPER_SIGNER_AES_KEY',
  );
  const aesExpectedWallet = aesKey
    ? optionalAddress(
        aesBootstrap.expectedWallet,
        'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
      )
    : undefined;
  const configuredPassphrase = choose(
    environment,
    dotenv,
    'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
    file.vaultPassphrase,
  );
  let vaultPassphrase: string;
  if (configuredPassphrase === undefined || configuredPassphrase === '') {
    const storageKeyPath = resolveInternalStorageKeyPath(stateDirectory);
    const encryptedVaultExists = await pathExists(
      resolve(stateDirectory, 'secrets.v1.enc.json'),
    );
    if (encryptedVaultExists && !(await pathExists(storageKeyPath))) {
      throw new SignerConfigurationError(
        'legacy-storage-passphrase-required',
        'An existing encrypted signer store requires its legacy passphrase for migration.',
      );
    }
    try {
      vaultPassphrase = await getOrCreateInternalStorageKey(stateDirectory);
    } catch {
      throw new SignerConfigurationError(
        'invalid-state-path',
        'The internal signer storage key could not be loaded safely.',
      );
    }
  } else {
    vaultPassphrase = requireString(
      configuredPassphrase,
      'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
      16,
    );
  }

  const rpcUrl = validateRpcUrl(
    choose(
      environment,
      dotenv,
      'CHAINWHISPER_COTI_RPC_URL',
      file.rpcUrl,
    ),
  );
  const pairingSecret = await getOrCreatePairingSecret({
    environment,
    stateDirectory,
  });

  return new LoadedSignerConfig({
    chainId: 2_632_500,
    rpcUrl,
    stateDirectory,
    environmentFilePath,
    environmentFileExists,
    aesExpectedWallet,
    expectedWallet: optionalAddress(
      chooseWalletBound(
        environment,
        dotenv,
        'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
        file.expectedWallet,
      ),
      'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
    ),
    confirmationChannel: confirmationChannel(
      choose(
        environment,
        dotenv,
        'CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL',
        file.confirmationChannel,
      ),
    ),
    confirmationTimeoutMs: positiveInteger(
      choose(
        environment,
        dotenv,
        'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
        file.confirmationTimeoutMs,
      ),
      60_000,
      'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
    ),
    operationExpirySkewMs: positiveInteger(
      choose(
        environment,
        dotenv,
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
  options: {
    controlPageReadiness?: PublicSignerStatus['controlPageReadiness'];
    autonomy?: PublicSignerStatus['autonomy'];
    diagnosticCodes?: string[];
    requiredAssets?: string[];
  } = {},
): PublicSignerStatus => {
  const defaultAutonomy: PublicSignerStatus['autonomy'] = {
    mode: 'manual',
    state: 'inactive',
    activePolicyCount: 0,
    globalPaused: false,
  };
  const requiredAssets = [
    ...new Set(
      (options.requiredAssets ?? [])
        .map((asset) => asset.trim())
        .filter(Boolean),
    ),
  ].slice(0, 16);
  if (!config) {
    return {
      version: 'cw.signer-status/2',
      network: {
        name: 'COTI Mainnet',
        chainId: 2_632_500,
      },
      chainId: 2_632_500,
      wallet,
      configured: false,
      aesConfigured: false,
      privateTransactions: 'onboarding-required',
      pairingConfigured: false,
      confirmation: elicitor?.isSupported() ? 'available' : 'unsupported',
      mode: 'configuration-required',
      walletSetup: 'required',
      signerReadiness: 'wallet-setup-required',
      privacyReadiness: 'wallet-setup-required',
      controlPageReadiness:
        options.controlPageReadiness ?? 'unavailable',
      autonomy: options.autonomy ?? defaultAutonomy,
      requiredAssets: requiredAssets.map((asset) => ({
        asset,
        status: 'unavailable',
      })),
      pendingOperations: {
        count: 0,
        operationIds: [],
      },
      nextAction: {
        tool: null,
        arguments: {},
        reason: 'configuration-invalid',
      },
      diagnosticCodes: options.diagnosticCodes ?? [
        'wallet-setup-required',
      ],
    };
  }
  const confirmation = elicitor?.isSupported()
    ? 'available'
    : 'unsupported';
  const hasPrivacyKey =
    privacyReady ??
    config.aesConfigured;
  return {
    version: 'cw.signer-status/2',
    network: {
      name: 'COTI Mainnet',
      chainId: config.chainId,
    },
    chainId: config.chainId,
    wallet,
    configured: config.walletConfigured,
    aesConfigured: hasPrivacyKey,
    privateTransactions: hasPrivacyKey
      ? 'ready'
      : 'onboarding-required',
    pairingConfigured: true,
    confirmation,
    mode: !config.walletConfigured
      ? 'configuration-required'
      : confirmation === 'available'
        ? 'read-write'
        : 'read-only',
    walletSetup: config.walletConfigured ? 'ready' : 'required',
    signerReadiness: !config.walletConfigured
      ? 'wallet-setup-required'
      : confirmation !== 'available'
        ? 'confirmation-unavailable'
        : hasPrivacyKey
          ? 'ready'
          : 'privacy-onboarding-required',
    privacyReadiness: !config.walletConfigured
      ? 'wallet-setup-required'
      : hasPrivacyKey
        ? 'ready'
        : 'onboarding-required',
    controlPageReadiness:
      options.controlPageReadiness ?? 'unavailable',
    autonomy: options.autonomy ?? defaultAutonomy,
    requiredAssets: requiredAssets.map((asset) => ({
      asset,
      status: config.walletConfigured
        ? hasPrivacyKey
          ? 'unavailable'
          : 'privacy-onboarding-required'
        : 'wallet-setup-required',
    })),
    pendingOperations: {
      count: 0,
      operationIds: [],
    },
    nextAction: !config.walletConfigured
      ? {
          tool: 'chainwhisper_open_control_panel',
          arguments: {},
          reason: 'wallet-setup-required',
        }
      : !hasPrivacyKey
        ? {
            tool: 'chainwhisper_open_control_panel',
            arguments: {},
            reason: 'privacy-onboarding-required',
          }
        : confirmation !== 'available'
          ? {
              tool: 'chainwhisper_open_control_panel',
              arguments: {},
              reason: 'control-panel-required',
            }
          : {
              tool: null,
              arguments: {},
              reason: 'ready',
            },
    diagnosticCodes:
      options.diagnosticCodes ??
      [
        !config.walletConfigured
          ? 'wallet-setup-required'
          : !hasPrivacyKey
            ? 'privacy-onboarding-required'
            : confirmation !== 'available'
              ? 'confirmation-unavailable'
              : 'ready',
      ],
  };
};
