import { isAbsolute } from 'node:path';

import { Wallet as EthersWallet } from 'ethers';

import type { AutonomyPolicyManager } from './autonomy.js';
import type { LoadedSignerConfig } from './config.js';
import type { OperationJournal } from './journal.js';
import type {
  AgentControlAction,
  AgentControlActionResult,
} from './localWebElicitor.js';
import type {
  Address,
  OperationJournalRecord,
} from './types.js';
import type { EncryptedSecretVault } from './vault.js';
import { writeAgentWalletEnvFile } from './walletEnv.js';

export type WalletControlState = {
  environmentFilePath: string;
  displayAddress: Address | null;
  generatedBackup: {
    address: Address;
    privateKey: string;
  } | null;
  restartRequired: boolean;
  lastDiagnostic: string | null;
};

export const safeAgentControlErrorMessage = (error: unknown): string => {
  const value = error instanceof Error ? error.message : '';
  return /(?:path|file|wallet|policy|operation|restart|format|private key)/iu.test(
    value,
  )
    ? value.replace(/0x[0-9a-fA-F]{64}/gu, '[redacted]')
    : 'The local signer could not complete that action safely.';
};

const normalizePrivateKey = (value: string | undefined): string => {
  const candidate = value?.trim() ?? '';
  const normalized = candidate.startsWith('0x')
    ? candidate
    : `0x${candidate}`;
  if (!/^0x[0-9a-fA-F]{64}$/u.test(normalized)) {
    throw new Error('Enter a standard 32-byte EVM private key.');
  }
  return new EthersWallet(normalized).privateKey.toLowerCase();
};

const WALLET_BOUND_PROCESS_SETTINGS = [
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
] as const;

export const saveAgentWallet = async (options: {
  action: Extract<AgentControlAction, 'import-wallet' | 'generate-wallet'>;
  fields: Readonly<Record<string, string>>;
  state: WalletControlState;
  replacing: boolean;
  replacementBlockedReason?: string;
  environment?: Readonly<Record<string, string | undefined>>;
}): Promise<AgentControlActionResult> => {
  if (options.replacementBlockedReason) {
    return { ok: false, message: options.replacementBlockedReason };
  }
  if (
    options.replacing &&
    options.fields.confirmReplacement !== 'replace-agent-wallet'
  ) {
    return {
      ok: false,
      message: 'Approve the local Agent Wallet replacement first.',
    };
  }
  const environment = options.environment ?? process.env;
  if (
    WALLET_BOUND_PROCESS_SETTINGS.some(
      (name) => Boolean(environment[name]?.trim()),
    )
  ) {
    return {
      ok: false,
      message:
        'Process-level Agent Wallet or legacy privacy settings override the selected .env file. Remove those overrides before changing the Agent Wallet here.',
    };
  }
  const environmentFilePath =
    options.fields.environmentFilePath?.trim() ?? '';
  if (!environmentFilePath || !isAbsolute(environmentFilePath)) {
    return {
      ok: false,
      message: 'Choose an absolute path for the local signer .env file.',
    };
  }
  try {
    const wallet =
      options.action === 'generate-wallet'
        ? EthersWallet.createRandom()
        : new EthersWallet(
            normalizePrivateKey(options.fields.privateKey),
          );
    await writeAgentWalletEnvFile(environmentFilePath, {
      privateKey: wallet.privateKey,
    });
    options.state.environmentFilePath = environmentFilePath;
    options.state.displayAddress = wallet.address as Address;
    options.state.generatedBackup =
      options.action === 'generate-wallet'
        ? {
            address: wallet.address as Address,
            privateKey: wallet.privateKey,
          }
        : null;
    options.state.restartRequired = true;
    options.state.lastDiagnostic = 'agent-wallet-saved-restart-required';
    return {
      ok: true,
      message:
        options.action === 'generate-wallet'
          ? 'Agent Wallet created and saved locally. Back up the displayed private key, then restart the signer.'
          : 'Agent Wallet saved locally. Restart the signer to load it.',
    };
  } catch (error) {
    return {
      ok: false,
      message: safeAgentControlErrorMessage(error),
    };
  }
};

export const pendingOperation = (
  record: OperationJournalRecord,
): boolean =>
  !['completed', 'failed', 'discarded'].includes(record.stage);

export const replacementBlockReason = async (
  journal: Pick<OperationJournal, 'list'>,
  autonomy: Pick<AutonomyPolicyManager, 'status'>,
): Promise<string | undefined> => {
  if ((await journal.list()).some(pendingOperation)) {
    return 'Agent Wallet replacement is blocked while a signer operation is pending.';
  }
  const status = await autonomy.status();
  if (!status.allowed) {
    return 'Agent Wallet replacement is blocked until autonomy state can be verified.';
  }
  if (
    status.value.policies.some(({ policy }) =>
      ['active', 'paused'].includes(policy.lifecycle.state),
    )
  ) {
    return 'Pause is not enough for wallet replacement. Revoke every active autonomy policy first.';
  }
  return undefined;
};

/**
 * Resolve privacy material exclusively from the active wallet namespace or
 * from a legacy value explicitly pinned to that same wallet. Root signer
 * vaults are intentionally not accepted here.
 */
export const resolveWalletPrivacyKey = async (
  walletVault: Pick<EncryptedSecretVault, 'get'>,
  config: LoadedSignerConfig,
  wallet: Address,
): Promise<string> =>
  (await walletVault.get('signer/aes-key')) ??
  config.aesKeyForWallet(wallet);
