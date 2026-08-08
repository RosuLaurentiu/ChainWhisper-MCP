import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';
import {
  encodeAbiParameters,
  encodeFunctionResult,
  parseAbi,
  toFunctionSelector,
} from 'viem';
import { prepareIT256 } from '@coti-io/coti-sdk-typescript';
import { Wallet } from '@coti-io/coti-ethers';

import type {
  CreateRecurringIntent,
  CreateTradeIntent,
  DomainStatus,
  ResolvedAsset,
} from '../src/domain/types.js';
import {
  ManifestExecutionPlanner,
  SignedDomainEnvelopeFactory,
  type PlannerRpc,
} from '../src/planner/index.js';
import {
  hashRuntimeManifest,
  loadRuntimeManifest,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader,
  type SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  AbiCallTemplateMaterializer,
  ActionEnvelopeVerifier,
  CotiTransactionSimulator,
  EncryptedSecretVault,
  LoadedSignerConfig,
  PrivateTokenAccountService,
  StrictMaterializedIntentValidator,
  VaultBackedPrivateInputMaterializer,
  buildActionConfirmation,
  buildPublicSignerStatus,
  isCotiAesKey,
  loadSignerConfig,
  type Address,
  type PrivateValueElicitor,
  type RuntimeRegistryState,
  type RuntimeStateReader,
  type WalletTransport,
} from '../src/signer/index.js';

const PAIRING = 'private-route-test-pairing-secret-is-long-enough';
const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const FEE_RECIPIENT =
  '0x2222222222222222222222222222222222222222' as Address;
const NOW = new Date('2026-07-27T12:00:00.000Z');

class FakePlannerRpc implements PlannerRpc {
  async request<T>(method: string, params: unknown[]): Promise<T> {
    if (method === 'eth_blockNumber') return '0x1234' as T;
    if (method !== 'eth_call') throw new Error('unsupported-rpc-method');
    const transaction = params[0] as { data?: string };
    const selector = transaction.data?.slice(0, 10).toLowerCase();
    if (selector === toFunctionSelector('feeAmount()').toLowerCase()) {
      return encodeAbiParameters([{ type: 'uint256' }], [123n]) as T;
    }
    if (
      selector === toFunctionSelector('feeRecipient()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [FEE_RECIPIENT],
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector('allowance(address,address)').toLowerCase()
    ) {
      return encodeAbiParameters([{ type: 'uint256' }], [0n]) as T;
    }
    return '0x' as T;
  }
}

const asset = (
  manifest: ChainWhisperRuntimeManifestV1,
  symbol: string,
): ResolvedAsset => {
  const token = manifest.tokens.find(
    (candidate) => candidate.symbol === symbol,
  );
  if (!token) throw new Error(`missing token ${symbol}`);
  return {
    id:
      token.kind === 'native'
        ? 'native:coti'
        : token.address!.toLowerCase(),
    kind: token.kind,
    symbol: token.symbol,
    decimals: token.decimals,
    address:
      token.kind === 'native'
        ? null
        : (token.address!.toLowerCase() as Address),
    verified: true,
  };
};

const status = (
  manifest: ChainWhisperRuntimeManifestV1,
): DomainStatus => ({
  service: 'chainwhisper-mcp',
  mode: 'keyless',
  chainId: 2_632_500,
  ready: true,
  readOnly: false,
  registry: {
    chainId: 2_632_500,
    registryAddress: manifest.registry.address,
    snapshotHash: hashRuntimeManifest(manifest),
    blockNumber: '0x1234',
    contracts: Object.fromEntries(
      Object.entries(manifest.contracts).map(([name, contract]) => [
        name,
        contract.address,
      ]),
    ),
    recurringWritesEnabled: true,
    verifiedAt: NOW.toISOString(),
    warnings: [],
  },
  capabilities: {
    reads: true,
    priceReferences: true,
    unsignedPlanning: true,
    recurringWrites: true,
  },
});

const config = (
  manifest: ChainWhisperRuntimeManifestV1,
): LoadedSignerConfig =>
  new LoadedSignerConfig({
    chainId: manifest.network.chainId,
    rpcUrl: manifest.network.rpcUrl,
    stateDirectory: join(tmpdir(), 'chainwhisper-private-test'),
    expectedWallet: WALLET,
    confirmationTimeoutMs: 5_000,
    operationExpirySkewMs: 1_000,
    secrets: {
      privateKey: `0x${'11'.repeat(32)}`,
      aesKey: '22'.repeat(16),
      pairingSecret: PAIRING,
      vaultPassphrase: 'private-route-test-passphrase',
    },
  });

const runtimeState = (
  manifest: ChainWhisperRuntimeManifestV1,
  signed: SignedActionEnvelopeV1,
): RuntimeStateReader => {
  const state: RuntimeRegistryState = {
    chainId: manifest.network.chainId,
    registryHash: hashRuntimeManifest(manifest),
    fees: { ...signed.registrySnapshot.fees },
    trustedFeeRecipients: Object.fromEntries(
      Object.keys(signed.registrySnapshot.fees).map((key) => [
        key,
        FEE_RECIPIENT,
      ]),
    ),
    allowedContracts: new Set(
      Object.values(manifest.contracts).map((contract) =>
        contract.address.toLowerCase(),
      ),
    ),
    allowedSelectors: new Map(
      Object.values(manifest.contracts).map((contract) => [
        contract.address.toLowerCase(),
        new Set(
          Object.values(contract.selectors).map((selector) =>
            selector.toLowerCase(),
          ),
        ),
      ]),
    ),
  };
  return { readRegistryState: async () => state };
};

const createVisiblePrivateTrade = async (
  manifest: ChainWhisperRuntimeManifestV1,
): Promise<SignedActionEnvelopeV1> => {
  const intent: CreateTradeIntent = {
    action: 'create_trade',
    wallet: WALLET,
    offerAsset: asset(manifest, 'p.WISP'),
    requestAsset: asset(manifest, 'COTI'),
    offerAmount: '1.25',
    requestAmount: '0.5',
    access: 'public',
    recipient: null,
    amountVisibility: 'visible',
    expiresAt: '2026-07-28T12:00:00.000Z',
    fillPolicy: {
      partialFillsAllowed: false,
      minPartialFillBps: 0,
      minRequestAmount: null,
      maxRequestAmountPerWallet: null,
      oneFillPerWallet: true,
    },
    secretPolicy: { kind: 'none' },
  };
  const execution = await new ManifestExecutionPlanner({
    manifest,
    rpc: new FakePlannerRpc(),
    now: () => NOW,
  }).plan(intent, status(manifest));
  return (
    await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW,
    }).create(intent, execution)
  ).payload as SignedActionEnvelopeV1;
};

describe('audited private transaction routes', () => {
  it('distinguishes the official 128-bit COTI AES width from a legacy bootstrap value', async () => {
    expect(isCotiAesKey('ab'.repeat(16))).toBe(true);
    expect(isCotiAesKey(`0x${'ab'.repeat(16)}`)).toBe(true);
    expect(isCotiAesKey(`0x${'ab'.repeat(32)}`)).toBe(false);

    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-aes-config-'),
    );
    const loaded = await loadSignerConfig({
      CHAINWHISPER_SIGNER_PRIVATE_KEY: `0x${'11'.repeat(32)}`,
      CHAINWHISPER_SIGNER_AES_KEY: `0x${'22'.repeat(32)}`,
      CHAINWHISPER_SIGNER_VAULT_PASSPHRASE:
        'a-long-private-route-test-passphrase',
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
    });
    expect(
      buildPublicSignerStatus(loaded, WALLET, null),
    ).toMatchObject({
      configured: true,
      aesConfigured: false,
      privateTransactions: 'onboarding-required',
    });
  });

  it('simulates COTI writes with gas estimation and enforces the signed gas cap', async () => {
    const estimateGas = vi.fn().mockResolvedValue(233_280n);
    const simulator = new CotiTransactionSimulator({
      provider: { estimateGas },
      bindTransactionFees: vi.fn().mockResolvedValue({
        type: 0,
        gasPrice: 1n,
      }),
    } as never);
    const request = {
      to: FEE_RECIPIENT,
      data: '0x8269bcc3' as `0x${string}`,
      value: 0n,
      gasLimit: 6_000_000n,
    };

    await expect(simulator.simulate(request, WALLET)).resolves.toMatchObject({
      ok: true,
    });
    expect(estimateGas).toHaveBeenCalledWith({
      from: WALLET,
      ...request,
    });

    estimateGas.mockResolvedValueOnce(6_000_001n);
    await expect(simulator.simulate(request, WALLET)).resolves.toEqual({
      ok: false,
      errorCode: 'SIMULATION_GAS_CAP_EXCEEDED',
    });

    estimateGas.mockRejectedValueOnce(new Error('reverted'));
    await expect(simulator.simulate(request, WALLET)).resolves.toEqual({
      ok: false,
      errorCode: 'SIMULATION_REVERTED',
    });
  });

  it('verifies and materializes an exact visible p.WISP approval without exposing its amount in approval metadata', async () => {
    const manifest = await loadRuntimeManifest();
    const signed = await createVisiblePrivateTrade(manifest);
    expect(signed.steps[0]?.allowance).toMatchObject({
      scheme: 'coti-private-exact',
      amount: '0',
    });
    await expect(
      new ActionEnvelopeVerifier(
        config(manifest),
        runtimeState(manifest, signed),
        () => NOW,
      ).verify(signed, WALLET),
    ).resolves.toBeTruthy();

    const vault = new EncryptedSecretVault(
      await mkdtemp(join(tmpdir(), 'cw-private-materializer-')),
      'a-long-private-route-test-passphrase',
    );
    const readiness = vi.fn(async () => undefined);
    const noElicitation: PrivateValueElicitor = {
      isSupported: () => false,
      requestPrivateValues: async () => ({
        outcome: 'cancelled',
      }),
    };
    const materializer = new VaultBackedPrivateInputMaterializer({
      vault,
      privateUint256: {
        encodePrivateUint256: async () => ({
          ciphertext: {
            ciphertextHigh: 11n,
            ciphertextLow: 12n,
          },
          signature: `0x${'33'.repeat(65)}`,
        }),
      },
      calldata: new AbiCallTemplateMaterializer(),
      elicitor: noElicitation,
      aesKey: () => '44'.repeat(16),
      timeoutMs: 5_000,
      assertPrivateSpendReady: readiness,
    });
    const approval = await materializer.materializeStep(signed, 0);
    expect(approval.approval?.amount).toBe('1250000');
    expect(readiness).toHaveBeenCalledWith({
      token: asset(manifest, 'p.WISP').address,
      spender:
        manifest.contracts.standardEscrow!.address.toLowerCase(),
      amount: '1250000',
    });
    expect(buildActionConfirmation(signed, approval, 0)).toMatchObject({
      spender: manifest.contracts.standardEscrow!.address,
      fee: '0 COTI (0 wei; approval step)',
      expectedResult: expect.stringContaining(
        'order is not created',
      ),
    });
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        approval,
        0,
      ),
    ).resolves.toBeUndefined();
  });

  it('rejects a paired private recipe missing a mandatory relational output', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: CreateTradeIntent = {
      action: 'create_trade',
      wallet: WALLET,
      offerAsset: asset(manifest, 'WISP'),
      requestAsset: asset(manifest, 'COTI'),
      offerAmount: '10',
      requestAmount: '2',
      access: 'unlisted',
      recipient: null,
      amountVisibility: 'visible',
      expiresAt: '2026-07-28T12:00:00.000Z',
      fillPolicy: {
        partialFillsAllowed: false,
        minPartialFillBps: 0,
        minRequestAmount: null,
        maxRequestAmountPerWallet: null,
        oneFillPerWallet: false,
      },
      secretPolicy: { kind: 'none' },
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakePlannerRpc(),
      now: () => NOW,
    }).plan(intent, status(manifest));
    const protocol = execution.steps.find(
      (step) => step.kind === 'protocol',
    );
    const group = protocol?.privateArtifactGroups?.[0];
    if (!group) throw new Error('Expected a Direct private recipe.');
    group.outputs = group.outputs.filter(
      (output) => output.kind !== 'terms-hash-v1',
    );
    const signed = (
      await new SignedDomainEnvelopeFactory({
        manifest,
        pairingSecret: PAIRING,
        now: () => NOW,
      }).create(intent, execution)
    ).payload as SignedActionEnvelopeV1;

    await expect(
      new ActionEnvelopeVerifier(
        config(manifest),
        runtimeState(manifest, signed),
        () => NOW,
      ).verify(signed, WALLET),
    ).rejects.toMatchObject({
      code: 'ENVELOPE_INVALID',
      message: expect.stringContaining('recipe is incomplete'),
    });
  });

  it('binds each visible recurring private allowance to its own signed liquidity field', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: CreateRecurringIntent = {
      action: 'create_recurring',
      wallet: WALLET,
      baseAsset: asset(manifest, 'p.WISP'),
      quoteAsset: asset(manifest, 'p.USDT'),
      buyPrice: '2',
      sellPrice: '2.1',
      buyQuoteLiquidity: '4',
      sellBaseLiquidity: '3',
      access: 'public',
      recipient: null,
      amountVisibility: 'visible',
      secretPolicy: { kind: 'none' },
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakePlannerRpc(),
      now: () => NOW,
    }).plan(intent, status(manifest));
    const sources = execution.steps
      .filter((step) => step.kind === 'approval')
      .flatMap((step) =>
        (step.privateArtifactGroups ?? []).flatMap((group) =>
          group.values.map((value) => value.source),
        ),
      );
    expect(sources).toEqual([
      'recurring-sell-base-liquidity',
      'recurring-buy-quote-liquidity',
    ]);
    expect(
      execution.steps
        .filter((step) => step.kind === 'approval')
        .map((step) => step.amount),
    ).toEqual(['0', '0']);
  });

  it('enforces the signed market-reference deadline while preserving exact-price plans', async () => {
    const manifest = await loadRuntimeManifest();
    const marketIntent: CreateRecurringIntent = {
      action: 'create_recurring',
      wallet: WALLET,
      baseAsset: asset(manifest, 'p.WISP'),
      quoteAsset: asset(manifest, 'p.USDT'),
      buyPrice: '2',
      sellPrice: '2.1',
      buyQuoteLiquidity: '4',
      sellBaseLiquidity: '3',
      access: 'public',
      recipient: null,
      amountVisibility: 'visible',
      priceReference: {
        id: 'market-reference-test',
        venue: 'trusted-test-market',
        price: '2.05',
        observedAt: '2026-07-27T11:59:30.000Z',
        expiresAt: null,
        buyOffsetBps: -244,
        sellOffsetBps: 244,
      },
      secretPolicy: { kind: 'none' },
    };
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakePlannerRpc(),
      now: () => NOW,
    });
    const execution = await planner.plan(marketIntent, status(manifest));
    const marketEnvelope = (
      await new SignedDomainEnvelopeFactory({
        manifest,
        pairingSecret: PAIRING,
        now: () => NOW,
      }).create(marketIntent, execution)
    ).payload as SignedActionEnvelopeV1;
    let now = NOW;
    const verifier = new ActionEnvelopeVerifier(
      config(manifest),
      runtimeState(manifest, marketEnvelope),
      () => now,
    );

    expect(marketEnvelope.expiresAt).toBe(
      '2026-07-27T12:04:30.000Z',
    );
    expect(() => verifier.assertFreshness(marketEnvelope)).not.toThrow();
    expect(() =>
      verifier.assertFreshness({
        ...marketEnvelope,
        expiresAt: '2026-07-27T12:15:00.000Z',
      }),
    ).toThrowError(
      expect.objectContaining({ code: 'ENVELOPE_INVALID' }),
    );

    now = new Date('2026-07-27T12:04:30.000Z');
    expect(() => verifier.assertFreshness(marketEnvelope)).toThrowError(
      expect.objectContaining({ code: 'STALE_STATE' }),
    );

    const exactIntent: CreateRecurringIntent = {
      ...marketIntent,
      priceReference: undefined,
    };
    const exactExecution = await planner.plan(
      exactIntent,
      status(manifest),
    );
    const exactEnvelope = (
      await new SignedDomainEnvelopeFactory({
        manifest,
        pairingSecret: PAIRING,
        now: () => NOW,
      }).create(exactIntent, exactExecution)
    ).payload as SignedActionEnvelopeV1;
    expect(exactEnvelope.expiresAt).toBe(
      '2026-07-27T12:15:00.000Z',
    );
    expect(() => verifier.assertFreshness(exactEnvelope)).not.toThrow();
  });

  it('blocks an unconfigured private-token escrow before any approval and accepts a funded configured route', async () => {
    const manifest = await loadRuntimeManifest();
    const privateToken = asset(manifest, 'p.WISP').address!;
    const standard =
      manifest.contracts.standardEscrow!.address.toLowerCase() as Address;
    const direct =
      manifest.contracts.directEscrow!.address.toLowerCase() as Address;
    const aesKey = '55'.repeat(16);
    const encryptionWallet = new Wallet(`0x${'77'.repeat(32)}`);
    const encryptedBalance = prepareIT256(
      2_000_000n,
      { wallet: encryptionWallet, userKey: aesKey },
      privateToken,
      '0x70a08231',
    ).ciphertext;
    const accountAbi = parseAbi([
      'function accountEncryptionAddress(address account) view returns (address)',
      'function balanceOf(address account) view returns ((uint256 ciphertextHigh, uint256 ciphertextLow))',
    ]);
    let balanceReads = 0;
    const rpc: JsonRpcReader = {
      request: async <T>(method: string, params: unknown[]): Promise<T> => {
        expect(method).toBe('eth_call');
        const data = (params[0] as { data: `0x${string}` }).data;
        if (
          data.slice(0, 10).toLowerCase() ===
          toFunctionSelector(
            'accountEncryptionAddress(address)',
          ).toLowerCase()
        ) {
          const account = `0x${data.slice(-40)}`.toLowerCase();
          const configured =
            account === direct
              ? '0x0000000000000000000000000000000000000000'
              : account === WALLET.toLowerCase()
                ? WALLET
                : FEE_RECIPIENT;
          return encodeFunctionResult({
            abi: accountAbi,
            functionName: 'accountEncryptionAddress',
            result: configured,
          }) as T;
        }
        balanceReads += 1;
        return encodeFunctionResult({
          abi: accountAbi,
          functionName: 'balanceOf',
          result: encryptedBalance,
        }) as T;
      },
    };
    const readiness = new PrivateTokenAccountService({
      manifest,
      rpc,
      wallet: {
        getAddress: async () => WALLET,
      } as WalletTransport,
      cotiWallet: {
        getUserOnboardInfo: () => ({ aesKey }),
      } as never,
      confirmation: null as never,
      simulator: null as never,
      nonceQueue: null as never,
      journal: null as never,
    });

    await expect(readiness.status('p.WISP')).resolves.toMatchObject({
      ready: true,
      spenders: {
        standardEscrow: { ready: true },
        privateEscrow: { ready: true },
        directEscrow: { ready: false },
        recurringEscrow: { ready: true },
      },
    });

    await expect(
      readiness.assertSpendReady({
        token: privateToken,
        spender: direct,
        amount: '1250000',
      }),
    ).rejects.toMatchObject({
      code: 'PRIVATE_INPUT_UNAVAILABLE',
      message: expect.stringContaining('No approval was broadcast'),
    });
    expect(balanceReads).toBe(0);

    await expect(
      readiness.assertSpendReady({
        token: privateToken,
        spender: standard,
        amount: '1250000',
      }),
    ).resolves.toBeUndefined();
    expect(balanceReads).toBe(1);
  });
});
