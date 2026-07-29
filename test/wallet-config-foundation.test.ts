import {
  mkdtemp,
  readFile,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  SignerConfigurationError,
  loadSignerConfig,
} from '../src/signer/config.js';
import {
  parseSignerEnv,
  readSignerEnvFile,
  writeAgentWalletEnvFile,
} from '../src/signer/walletEnv.js';

const PRIVATE_KEY_A = `0x${'11'.repeat(32)}`;
const PRIVATE_KEY_B = `0x${'22'.repeat(32)}`;

describe('Agent Wallet configuration foundation', () => {
  it('starts in wallet setup mode and creates internal secrets automatically', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-setup-'),
    );
    const config = await loadSignerConfig({
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
    });

    expect(config.walletConfigured).toBe(false);
    expect(config.aesConfigured).toBe(false);
    expect(config.configurationDiagnostic).toBe('wallet-setup-required');
    expect(() => config.credentialMaterial()).toThrow(
      'Set up an Agent Wallet',
    );
    expect(
      (await readFile(join(stateDirectory, 'storage.key'), 'utf8')).trim(),
    ).toHaveLength(43);
    expect(
      (await readFile(join(stateDirectory, 'pairing.key'), 'utf8')).trim(),
    ).toHaveLength(43);
    expect(JSON.stringify(config)).not.toContain(PRIVATE_KEY_A.slice(2, 18));
  });

  it('loads a selected signer env file with process environment precedence', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-env-'));
    const stateDirectory = join(root, 'state');
    const environmentFile = join(root, 'agent-wallet.env');
    await writeAgentWalletEnvFile(environmentFile, {
      privateKey: PRIVATE_KEY_A,
      rpcUrl: 'https://mainnet.coti.io/rpc',
      stateDirectory,
    });

    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_ENV_FILE: environmentFile,
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
    });

    expect(config.environmentFilePath).toBe(environmentFile);
    expect(config.environmentFileExists).toBe(true);
    expect(config.stateDirectory).toBe(stateDirectory);
    expect(config.credentialMaterial().privateKey).toBe(
      PRIVATE_KEY_B.toLowerCase(),
    );
    expect(config.credentialMaterial().aesKey).toBe('');
  });

  it('keeps legacy JSON lowest-precedence without cross-binding wallet metadata', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-legacy-'));
    const stateDirectory = join(root, 'state');
    const configFile = join(root, 'signer.json');
    await writeFile(
      configFile,
      JSON.stringify({
        privateKey: PRIVATE_KEY_A,
        aesKey: `0x${'33'.repeat(16)}`,
        vaultPassphrase: 'legacy-passphrase-at-least-sixteen',
        stateDirectory,
      }),
      { mode: 0o600 },
    );

    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_CONFIG_FILE: configFile,
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
    });
    expect(config.credentialMaterial().privateKey).toBe(
      PRIVATE_KEY_B.toLowerCase(),
    );
    expect(config.aesConfigured).toBe(false);
    expect(config.credentialMaterial().aesKey).toBe('');
  });

  it('allows HTTP only for loopback RPC endpoints', async () => {
    const remoteState = await mkdtemp(join(tmpdir(), 'cw-wallet-rpc-'));
    await expect(
      loadSignerConfig({
        CHAINWHISPER_STATE_DIRECTORY: remoteState,
        CHAINWHISPER_COTI_RPC_URL: 'http://rpc.example.test',
      }),
    ).rejects.toMatchObject({
      code: 'CONFIGURATION_REQUIRED',
      diagnosticCode: 'invalid-rpc-url',
    });

    const loopbackState = await mkdtemp(
      join(tmpdir(), 'cw-wallet-loopback-'),
    );
    const config = await loadSignerConfig({
      CHAINWHISPER_STATE_DIRECTORY: loopbackState,
      CHAINWHISPER_COTI_RPC_URL: 'http://127.0.0.1:8545',
    });
    expect(config.rpcUrl).toBe('http://127.0.0.1:8545/');
  });

  it('rejects unsupported or duplicate dotenv keys and writes private files', async () => {
    expect(() => parseSignerEnv('PATH=/tmp\n')).toThrow('unsupported key');
    expect(() =>
      parseSignerEnv(
        `CHAINWHISPER_SIGNER_PRIVATE_KEY=${PRIVATE_KEY_A}\n` +
          `CHAINWHISPER_SIGNER_PRIVATE_KEY=${PRIVATE_KEY_B}\n`,
      ),
    ).toThrow('duplicates a key');

    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-write-'));
    const environmentFile = join(root, 'wallet.env');
    await writeAgentWalletEnvFile(environmentFile, {
      privateKey: PRIVATE_KEY_A,
    });
    const loaded = await readSignerEnvFile(environmentFile);
    expect(loaded.values.CHAINWHISPER_SIGNER_PRIVATE_KEY).toBe(
      PRIVATE_KEY_A,
    );
    if (process.platform !== 'win32') {
      expect((await stat(environmentFile)).mode & 0o077).toBe(0);
    }
  });

  it('removes wallet-bound legacy values when replacing the Agent Wallet', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-replace-'));
    const environmentFile = join(root, 'wallet.env');
    await writeFile(
      environmentFile,
      [
        `CHAINWHISPER_SIGNER_PRIVATE_KEY=${PRIVATE_KEY_A}`,
        `CHAINWHISPER_SIGNER_AES_KEY=0x${'33'.repeat(16)}`,
        'CHAINWHISPER_SIGNER_EXPECTED_WALLET=0x1111111111111111111111111111111111111111',
        'CHAINWHISPER_COTI_RPC_URL=https://mainnet.coti.io/rpc',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );

    await writeAgentWalletEnvFile(environmentFile, {
      privateKey: PRIVATE_KEY_B,
    });

    const loaded = await readSignerEnvFile(environmentFile);
    expect(loaded.values).toMatchObject({
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY_B,
      CHAINWHISPER_COTI_RPC_URL: 'https://mainnet.coti.io/rpc',
    });
    expect(loaded.values).not.toHaveProperty(
      'CHAINWHISPER_SIGNER_AES_KEY',
    );
    expect(loaded.values).not.toHaveProperty(
      'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
    );
  });

  it('uses secret-safe diagnostics for invalid credentials', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-diagnostic-'),
    );
    const invalidSecret = 'do-not-echo-this-private-value';
    let captured: unknown;
    try {
      await loadSignerConfig({
        CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
        CHAINWHISPER_SIGNER_PRIVATE_KEY: invalidSecret,
      });
    } catch (error) {
      captured = error;
    }
    expect(captured).toBeInstanceOf(SignerConfigurationError);
    expect(captured).toMatchObject({
      diagnosticCode: 'invalid-private-key',
    });
    expect(String(captured)).not.toContain(invalidSecret);
  });

  it('rejects a non-directory signer state path', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-wallet-state-'));
    const statePath = join(root, 'not-a-directory');
    await writeFile(statePath, 'not state', { mode: 0o600 });
    await expect(
      loadSignerConfig({
        CHAINWHISPER_STATE_DIRECTORY: statePath,
      }),
    ).rejects.toMatchObject({
      code: 'CONFIGURATION_REQUIRED',
      diagnosticCode: 'invalid-state-path',
    });
  });
});
