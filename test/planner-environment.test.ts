import { describe, expect, it } from 'vitest';

import { removeSignerOnlyEnvironment } from '../src/planner/environment.js';

describe('keyless planner environment', () => {
  it('removes signer-only credentials and configuration before planner startup', () => {
    const environment: Record<string, string | undefined> = {
      CHAINWHISPER_SIGNER_PRIVATE_KEY: 'private-key',
      CHAINWHISPER_SIGNER_AES_KEY: 'privacy-key',
      CHAINWHISPER_SIGNER_VAULT_PASSPHRASE: 'passphrase',
      CHAINWHISPER_SIGNER_ENV_FILE: '/secret/signer.env',
      CHAINWHISPER_SIGNER_CONFIG_FILE: '/secret/legacy.json',
      CHAINWHISPER_SIGNER_EXPECTED_WALLET: '0xwallet',
      CHAINWHISPER_SIGNER_STATE_DIRECTORY: '/secret/state',
      CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL: 'local-web',
      CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS: '60000',
      CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS: '30000',
      CHAINWHISPER_PAIRING_SECRET: 'planner-pairing-secret',
      CHAINWHISPER_COTI_RPC_URL: 'https://mainnet.coti.io/rpc',
    };

    removeSignerOnlyEnvironment(environment);

    expect(environment).toEqual({
      CHAINWHISPER_PAIRING_SECRET: 'planner-pairing-secret',
      CHAINWHISPER_COTI_RPC_URL: 'https://mainnet.coti.io/rpc',
    });
  });
});
