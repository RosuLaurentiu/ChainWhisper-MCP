import {
  mkdir,
  mkdtemp,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Wallet as EthersWallet } from 'ethers';
import { describe, expect, it } from 'vitest';

import {
  replacementBlockReason,
  resolveWalletPrivacyKey,
  saveAgentWallet,
  type WalletControlState,
} from '../src/signer/agentWallet.js';
import type { AutonomyPolicyManager } from '../src/signer/autonomy.js';
import { loadSignerConfig } from '../src/signer/config.js';
import { OperationJournal } from '../src/signer/journal.js';
import type { Address } from '../src/signer/types.js';
import { EncryptedSecretVault } from '../src/signer/vault.js';
import { readSignerEnvFile } from '../src/signer/walletEnv.js';

const PRIVATE_KEY_A = `0x${'11'.repeat(32)}`;
const PRIVATE_KEY_B = `0x${'22'.repeat(32)}`;
const LEGACY_AES_KEY = `0x${'33'.repeat(16)}`;
const OPERATION_HASH = `0x${'44'.repeat(32)}` as const;

const controlState = (environmentFilePath: string): WalletControlState => ({
  environmentFilePath,
  displayAddress: null,
  generatedBackup: null,
  restartRequired: false,
  lastDiagnostic: null,
});

const autonomyWithStatus = (
  status: unknown,
): Pick<AutonomyPolicyManager, 'status'> =>
  ({
    status: async () => status,
  }) as Pick<AutonomyPolicyManager, 'status'>;

describe('Agent Wallet control integration', () => {
  it('imports, clears incompatible wallet metadata, and reloads the new wallet', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-import-'));
    const environmentFile = join(root, 'agent.env');
    const stateDirectory = join(root, 'state');
    const legacyConfigFile = join(root, 'legacy.json');
    await writeFile(
      legacyConfigFile,
      JSON.stringify({
        privateKey: PRIVATE_KEY_A,
        aesKey: LEGACY_AES_KEY,
        expectedWallet:
          '0x1111111111111111111111111111111111111111',
        stateDirectory,
      }),
      { mode: 0o600 },
    );
    await writeFile(
      environmentFile,
      [
        `CHAINWHISPER_SIGNER_PRIVATE_KEY=${PRIVATE_KEY_A}`,
        `CHAINWHISPER_SIGNER_AES_KEY=${LEGACY_AES_KEY}`,
        'CHAINWHISPER_SIGNER_EXPECTED_WALLET=0x1111111111111111111111111111111111111111',
        'CHAINWHISPER_COTI_RPC_URL=https://mainnet.coti.io/rpc',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    const state = controlState(environmentFile);

    await expect(
      saveAgentWallet({
        action: 'import-wallet',
        fields: {
          environmentFilePath: environmentFile,
          privateKey: PRIVATE_KEY_B,
          confirmReplacement: 'replace-agent-wallet',
        },
        state,
        replacing: true,
        environment: {},
      }),
    ).resolves.toMatchObject({
      ok: true,
      message: expect.stringContaining('Restart'),
    });

    const expectedWallet = new EthersWallet(PRIVATE_KEY_B).address;
    expect(state).toMatchObject({
      environmentFilePath: environmentFile,
      displayAddress: expectedWallet,
      generatedBackup: null,
      restartRequired: true,
      lastDiagnostic: 'agent-wallet-saved-restart-required',
    });
    const saved = await readSignerEnvFile(environmentFile);
    expect(saved.values).toMatchObject({
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
      CHAINWHISPER_COTI_RPC_URL: 'https://mainnet.coti.io/rpc',
    });
    expect(saved.values).not.toHaveProperty(
      'CHAINWHISPER_SIGNER_AES_KEY',
    );
    expect(saved.values).not.toHaveProperty(
      'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
    );

    const reloaded = await loadSignerConfig({
      CHAINWHISPER_SIGNER_ENV_FILE: environmentFile,
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
      CHAINWHISPER_SIGNER_CONFIG_FILE: legacyConfigFile,
    });
    expect(reloaded.walletConfigured).toBe(true);
    expect(reloaded.credentialMaterial().privateKey).toBe(PRIVATE_KEY_B);
    expect(reloaded.credentialMaterial().aesKey).toBe('');
    expect(reloaded.expectedWallet).toBeUndefined();
    expect(reloaded.configurationDiagnostic).toBe(
      'privacy-onboarding-required',
    );
    expect(
      reloaded.aesKeyForWallet(expectedWallet as Address),
    ).toBe('');
  });

  it('generates a locally recoverable wallet and marks the signer for restart', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-generate-'));
    const environmentFile = join(root, 'agent.env');
    const state = controlState(environmentFile);

    const result = await saveAgentWallet({
      action: 'generate-wallet',
      fields: { environmentFilePath: environmentFile },
      state,
      replacing: false,
      environment: {},
    });

    expect(result.ok).toBe(true);
    expect(state.restartRequired).toBe(true);
    expect(state.generatedBackup?.privateKey).toMatch(
      /^0x[0-9a-f]{64}$/u,
    );
    const generated = new EthersWallet(
      state.generatedBackup?.privateKey ?? '',
    );
    expect(state.generatedBackup?.address).toBe(generated.address);
    expect(state.displayAddress).toBe(generated.address);
    expect(
      (await readSignerEnvFile(environmentFile)).values,
    ).toEqual({
      CHAINWHISPER_SIGNER_PRIVATE_KEY:
        state.generatedBackup?.privateKey,
    });
  });

  it('marks a first wallet for in-process activation without losing its backup', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-hot-'));
    const environmentFile = join(root, 'agent.env');
    const state = controlState(environmentFile);

    const result = await saveAgentWallet({
      action: 'generate-wallet',
      fields: { environmentFilePath: environmentFile },
      state,
      replacing: false,
      activateInProcess: true,
      environment: {},
    });

    expect(result).toMatchObject({
      ok: true,
      message: expect.stringContaining('activat'),
    });
    expect(state.restartRequired).toBe(false);
    expect(state.lastDiagnostic).toBe('agent-wallet-saved-activating');
    expect(state.generatedBackup?.privateKey).toMatch(
      /^0x[0-9a-f]{64}$/u,
    );
  });

  it('blocks replacement for missing local approval, process overrides, pending operations, and active policies', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-block-'));
    const environmentFile = join(root, 'agent.env');
    const state = controlState(environmentFile);

    await expect(
      saveAgentWallet({
        action: 'import-wallet',
        fields: {
          environmentFilePath: environmentFile,
          privateKey: PRIVATE_KEY_B,
        },
        state,
        replacing: true,
        environment: {},
      }),
    ).resolves.toMatchObject({
      ok: false,
      message: expect.stringContaining('Approve'),
    });
    await expect(
      saveAgentWallet({
        action: 'import-wallet',
        fields: {
          environmentFilePath: environmentFile,
          privateKey: PRIVATE_KEY_B,
          confirmReplacement: 'replace-agent-wallet',
        },
        state,
        replacing: true,
        environment: {
          CHAINWHISPER_SIGNER_AES_KEY: LEGACY_AES_KEY,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      message: expect.stringContaining('Process-level'),
    });

    const journal = new OperationJournal(root);
    await journal.begin('pending-wallet-replacement', OPERATION_HASH);
    const inactive = autonomyWithStatus({
      allowed: true,
      value: {
        globalPaused: false,
        policies: [],
        activeReservationCount: 0,
      },
    });
    await expect(
      replacementBlockReason(journal, inactive),
    ).resolves.toContain('pending');

    await journal.updateStage(
      'pending-wallet-replacement',
      'completed',
    );
    const active = autonomyWithStatus({
      allowed: true,
      value: {
        globalPaused: false,
        policies: [
          {
            policy: { lifecycle: { state: 'active' } },
          },
        ],
        activeReservationCount: 0,
      },
    });
    await expect(
      replacementBlockReason(journal, active),
    ).resolves.toContain('Revoke');
    await expect(
      replacementBlockReason(journal, inactive),
    ).resolves.toBeUndefined();
  });

  it('ignores an unbound root-vault AES key for a new wallet namespace', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-privacy-'),
    );
    const config = await loadSignerConfig({
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
    });
    const wallet = new EthersWallet(PRIVATE_KEY_B).address
      .toLowerCase() as Address;
    const passphrase = config.credentialMaterial().vaultPassphrase;
    const legacyRootVault = new EncryptedSecretVault(
      stateDirectory,
      passphrase,
    );
    await legacyRootVault.put('signer/aes-key', LEGACY_AES_KEY);
    const walletDirectory = join(
      stateDirectory,
      'wallets',
      wallet,
    );
    await mkdir(walletDirectory, { recursive: true, mode: 0o700 });
    const walletVault = new EncryptedSecretVault(
      walletDirectory,
      passphrase,
    );

    await expect(
      resolveWalletPrivacyKey(walletVault, config, wallet),
    ).resolves.toBe('');
    await expect(
      legacyRootVault.get('signer/aes-key'),
    ).resolves.toBe(LEGACY_AES_KEY);
    await expect(
      walletVault.get('signer/aes-key'),
    ).resolves.toBeNull();
  });

  it('accepts legacy AES material only for its explicit wallet pin', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-bound-aes-'));
    const walletA = new EthersWallet(PRIVATE_KEY_A).address as Address;
    const walletB = new EthersWallet(PRIVATE_KEY_B).address as Address;
    const configFile = join(root, 'legacy.json');
    await writeFile(
      configFile,
      JSON.stringify({
        privateKey: PRIVATE_KEY_A,
        aesKey: LEGACY_AES_KEY,
        expectedWallet: walletA,
        stateDirectory: join(root, 'state'),
      }),
      { mode: 0o600 },
    );
    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_CONFIG_FILE: configFile,
    });

    expect(config.aesConfigured).toBe(true);
    expect(config.aesKeyForWallet(walletA)).toBe(LEGACY_AES_KEY);
    expect(config.aesKeyForWallet(walletB)).toBe('');
  });

  it('does not inherit lower-precedence wallet metadata when the process selects another wallet', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-precedence-'));
    const environmentFile = join(root, 'agent.env');
    const walletA = new EthersWallet(PRIVATE_KEY_A).address;
    await writeFile(
      environmentFile,
      [
        `CHAINWHISPER_SIGNER_PRIVATE_KEY=${PRIVATE_KEY_A}`,
        `CHAINWHISPER_SIGNER_AES_KEY=${LEGACY_AES_KEY}`,
        `CHAINWHISPER_SIGNER_EXPECTED_WALLET=${walletA}`,
        '',
      ].join('\n'),
      { mode: 0o600 },
    );

    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_ENV_FILE: environmentFile,
      CHAINWHISPER_STATE_DIRECTORY: join(root, 'state'),
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
    });

    expect(config.credentialMaterial().privateKey).toBe(PRIVATE_KEY_B);
    expect(config.credentialMaterial().aesKey).toBe('');
    expect(config.expectedWallet).toBeUndefined();
  });
});
