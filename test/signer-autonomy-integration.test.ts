import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { SignedActionEnvelopeV1 } from '../src/shared/index.js';
import {
  EncryptedSecretVault,
  VaultAutonomyStore,
  buildPolicyExposure,
  type MaterializedActionStep,
} from '../src/signer/index.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
});

describe('autonomy signer integration', () => {
  it('persists wallet-namespaced policy state only through authenticated encrypted storage', async () => {
    const directory = await mkdtemp(
      join(tmpdir(), 'chainwhisper-autonomy-store-'),
    );
    temporaryDirectories.push(directory);
    const vault = new EncryptedSecretVault(
      directory,
      'test-only-storage-passphrase',
    );
    const store = new VaultAutonomyStore({
      vault,
      wallet: '0x1111111111111111111111111111111111111111',
    });

    await store.transact((current) => ({
      next: { ...current, revision: 1, globalPaused: true },
      result: undefined,
    }));

    await expect(store.read()).resolves.toMatchObject({
      revision: 1,
      globalPaused: true,
    });
    const persisted = await readFile(vault.path, 'utf8');
    expect(persisted).toContain('"cipher":"aes-256-gcm"');
    expect(persisted).not.toContain('globalPaused');
    expect(persisted).not.toContain(
      '0x1111111111111111111111111111111111111111',
    );
  });

  it('binds private agent-provided amounts, exact steps, and fee ceilings into policy exposure', () => {
    const step: MaterializedActionStep = {
      id: 'create-private-order',
      kind: 'protocol',
      to: '0x2222222222222222222222222222222222222222',
      data: '0x12345678',
      value: '0',
      gasCap: '400000',
      summary: 'Create private order',
    };
    const envelope = {
      chainId: 2_632_500,
      operationHash: `0x${'12'.repeat(32)}`,
      exactNativeValue: '100',
      registrySnapshot: {
        manifestHash: `0x${'34'.repeat(32)}`,
      },
      intent: {
        action: 'create_trade',
        sellAsset: {
          kind: 'private-erc20',
          reference: 'p.WISP',
          address: '0x3333333333333333333333333333333333333333',
          symbol: 'p.WISP',
          decimals: 18,
        },
        buyAsset: {
          kind: 'private-erc20',
          reference: 'p.COTI',
          address: '0x4444444444444444444444444444444444444444',
          symbol: 'p.COTI',
          decimals: 18,
        },
        sellAmount: '1.5',
        buyAmount: '3',
        recipient: '0x5555555555555555555555555555555555555555',
        metadata: { privateAmountMode: 'agent-provided' },
      },
    } as SignedActionEnvelopeV1;

    const exposure = buildPolicyExposure({
      envelope,
      wallet: '0x1111111111111111111111111111111111111111',
      steps: [step],
      feeQuotes: [
        {
          model: 'eip1559',
          maximumNetworkFeeWei: '250',
          maximumNetworkFeeCoti: '0.00000000000000025',
          maximumFeePerGasWei: '1',
        },
      ],
    });

    expect(exposure.agentProvidedPrivateAmounts).toBe(true);
    expect(exposure.grossSpend).toEqual([
      {
        asset: '0x3333333333333333333333333333333333333333',
        amount: '1500000000000000000',
      },
    ]);
    expect(exposure.minimumReceive[0]?.amount).toBe(
      '3000000000000000000',
    );
    expect(exposure.maximumNetworkFee).toBe('250');
    expect(exposure.nativeValue).toBe('100');
    expect(exposure.stepDigests).toHaveLength(1);
    expect(exposure.stepDigests[0]).toMatch(/^0x[0-9a-f]{64}$/u);
  });
});
