import { describe, expect, it } from 'vitest';
import {
  encodeAbiParameters,
  toFunctionSelector
} from 'viem';

import type {
  CreateRecurringIntent,
  CreateTradeIntent,
  DomainStatus,
  FillIntent,
  OrderUpdateIntent,
  PrivacyBridgeIntent,
  ResolvedAsset,
  SafeOrderSummary
} from '../src/domain/types.js';
import {
  verifySignedActionEnvelope,
  hashRuntimeManifest,
  loadRuntimeManifest,
  PRIVACY_BRIDGE_PAIRS_V1,
  type ChainWhisperRuntimeManifestV1,
  type SignedActionEnvelopeV1
} from '../src/shared/index.js';
import { deriveOrderClassificationV1 } from '../src/shared/orderClassification.js';
import {
  ManifestExecutionPlanner,
  SignedDomainEnvelopeFactory,
  createChainWhisperPlanningRuntime,
  type PlannerRpc
} from '../src/planner/index.js';
import {
  buildActionConfirmation,
  type MaterializedActionStep
} from '../src/signer/index.js';

const PAIRING_SECRET = 'planner-test-pairing-secret-that-is-long-enough';
const FEE_RECIPIENT = '0x1111111111111111111111111111111111111111';
const WALLET = '0x2222222222222222222222222222222222222222';
const NOW = new Date('2026-07-27T12:00:00.000Z');

class FakeRpc implements PlannerRpc {
  readonly calls: Array<{ method: string; params: unknown[] }> = [];
  allowance = 0n;
  fee = 123n;
  chargeFeeOnEdit = true;
  trustsDirectCounterEscrow = true;
  failProtocolSimulation = false;
  bridgePublicToken =
    '0xb70c55bd0823436F44877DC6A9f46E0C55f2C3A8' as `0x${string}`;
  bridgePrivateToken =
    '0x682e3142e62a7aDe2a0CA5bdC87b205CaDe4B17a' as `0x${string}`;

  async request<T>(method: string, params: unknown[]): Promise<T> {
    this.calls.push({ method, params });
    if (method === 'eth_blockNumber') return '0x1234' as T;
    if (method !== 'eth_call') throw new Error('unsupported-rpc-method');
    const tx = params[0] as { data?: string };
    const selector = tx.data?.slice(0, 10).toLowerCase();
    if (selector === toFunctionSelector('feeAmount()').toLowerCase()) {
      return encodeAbiParameters([{ type: 'uint256' }], [this.fee]) as T;
    }
    if (selector === toFunctionSelector('feeRecipient()').toLowerCase()) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [FEE_RECIPIENT]
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector('chargeFeeOnEdit()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'bool' }],
        [this.chargeFeeOnEdit]
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector(
        'trustedDirectCounterEscrow(address)'
      ).toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'bool' }],
        [this.trustsDirectCounterEscrow]
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector('allowance(address,address)').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'uint256' }],
        [this.allowance]
      ) as T;
    }
    if (
      selector === toFunctionSelector('paused()').toLowerCase() ||
      selector === toFunctionSelector('blacklisted(address)').toLowerCase()
    ) {
      return encodeAbiParameters([{ type: 'bool' }], [false]) as T;
    }
    if (
      selector === toFunctionSelector('isDepositEnabled()').toLowerCase()
      || selector === toFunctionSelector('publicAmountsEnabled()').toLowerCase()
    ) {
      return encodeAbiParameters([{ type: 'bool' }], [true]) as T;
    }
    if (
      [
        'minDepositAmount()',
        'minWithdrawAmount()'
      ].map((signature) => toFunctionSelector(signature).toLowerCase()).includes(selector ?? '')
    ) {
      return encodeAbiParameters([{ type: 'uint256' }], [1n]) as T;
    }
    if (
      [
        'maxDepositAmount()',
        'maxWithdrawAmount()'
      ].map((signature) => toFunctionSelector(signature).toLowerCase()).includes(selector ?? '')
    ) {
      return encodeAbiParameters([{ type: 'uint256' }], [10n ** 30n]) as T;
    }
    if (selector === toFunctionSelector('token()').toLowerCase()) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [this.bridgePublicToken]
      ) as T;
    }
    if (
      selector === toFunctionSelector('privateToken()').toLowerCase() ||
      selector === toFunctionSelector('privateCoti()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [this.bridgePrivateToken]
      ) as T;
    }
    if (
      selector === toFunctionSelector('estimateDepositFee(uint256)').toLowerCase() ||
      selector === toFunctionSelector('estimateWithdrawFee(uint256)').toLowerCase()
    ) {
      return encodeAbiParameters(
        [
          { type: 'uint256' },
          { type: 'uint256' },
          { type: 'uint256' },
          { type: 'uint256' }
        ],
        [9n, 100n, 101n, 102n]
      ) as T;
    }
    if (selector === toFunctionSelector('nativeCotiFee()').toLowerCase()) {
      return encodeAbiParameters([{ type: 'uint256' }], [9n]) as T;
    }
    if (
      this.failProtocolSimulation &&
      selector !== toFunctionSelector('approve(address,uint256)').toLowerCase()
    ) {
      throw new Error('execution reverted');
    }
    return '0x' as T;
  }
}

const statusFor = (
  manifest: ChainWhisperRuntimeManifestV1,
  overrides: Partial<Pick<DomainStatus, 'ready' | 'readOnly'>> = {}
): DomainStatus => ({
  service: 'chainwhisper-mcp',
  mode: 'keyless',
  chainId: 2_632_500,
  ready: overrides.ready ?? true,
  readOnly: overrides.readOnly ?? false,
  registry: {
    chainId: 2_632_500,
    registryAddress: manifest.registry.address,
    snapshotHash: hashRuntimeManifest(manifest),
    blockNumber: '0x1234',
    contracts: Object.fromEntries(
      Object.entries(manifest.contracts).map(([name, contract]) => [
        name,
        contract.address
      ])
    ),
    recurringWritesEnabled: true,
    verifiedAt: NOW.toISOString(),
    warnings: []
  },
  capabilities: {
    reads: true,
    priceReferences: true,
    unsignedPlanning: true,
    recurringWrites: true
  }
});

const resolveAsset = (
  manifest: ChainWhisperRuntimeManifestV1,
  symbol: string
): ResolvedAsset => {
  const token = manifest.tokens.find((candidate) => candidate.symbol === symbol);
  if (!token) throw new Error(`missing-test-token:${symbol}`);
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
        : (token.address!.toLowerCase() as `0x${string}`),
    verified: true
  };
};

const createTradeIntent = (
  manifest: ChainWhisperRuntimeManifestV1,
  offerSymbol = 'WISP'
): CreateTradeIntent => ({
  action: 'create_trade',
  wallet: WALLET,
  offerAsset: resolveAsset(manifest, offerSymbol),
  requestAsset: resolveAsset(manifest, 'COTI'),
  offerAmount: offerSymbol === 'WISP' ? '10.25' : '1',
  requestAmount: '2',
  access: 'public',
  recipient: null,
  amountVisibility: 'visible',
  expiresAt: '2026-07-28T12:00:00.000Z',
  fillPolicy: {
    partialFillsAllowed: true,
    minPartialFillBps: 100,
    minRequestAmount: '0',
    maxRequestAmountPerWallet: '2',
    oneFillPerWallet: false
  },
  secretPolicy: { kind: 'none' }
});

const recurringOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  options: {
    baseSymbol?: string;
    quoteSymbol?: string;
    status?: SafeOrderSummary['status'];
  } = {}
): SafeOrderSummary => {
  const baseAsset = resolveAsset(manifest, options.baseSymbol ?? 'gCOTI');
  const quoteAsset = resolveAsset(manifest, options.quoteSymbol ?? 'WISP');
  const escrow = manifest.contracts.recurringEscrow!.address.toLowerCase() as `0x${string}`;
  return {
    identity: {
      escrowContract: escrow,
      localId: '7',
      handle: `cw_${escrow.slice(2)}_7`
    },
    kind: 'recurring',
    status: options.status ?? 'open',
    maker: FEE_RECIPIENT,
    recipient: null,
    access: 'public',
    amountVisibility: 'visible',
    offerAsset: baseAsset,
    requestAsset: quoteAsset,
    offerAmount: '10',
    requestAmount: '20',
    remainingOfferAmount: '10',
    remainingRequestAmount: '20',
    price: '0.3',
    priceBasis: 'quote_per_base',
    expiresAt: null,
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'1'.repeat(64)}`,
    recurring: {
      baseAsset,
      quoteAsset,
      buyPrice: '0.25',
      sellPrice: '0.3',
      buyQuoteLiquidity: '20',
      sellBaseLiquidity: '10',
      buySideOpen: true,
      sellSideOpen: true
    }
  };
};

const lifecycleOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  contractName: 'standardEscrow' | 'privateEscrow' | 'directEscrow'
): SafeOrderSummary => {
  const escrow = manifest.contracts[contractName]!.address.toLowerCase() as `0x${string}`;
  return {
    identity: {
      escrowContract: escrow,
      localId: '9',
      handle: `cw_${escrow.slice(2)}_9`
    },
    kind: 'trade',
    status: 'expired',
    maker: FEE_RECIPIENT,
    recipient: null,
    access: contractName === 'directEscrow' ? 'direct' : 'public',
    amountVisibility:
      contractName === 'privateEscrow' ? 'private' : 'visible',
    offerAsset: resolveAsset(manifest, 'gCOTI'),
    requestAsset: resolveAsset(manifest, 'WISP'),
    offerAmount: contractName === 'privateEscrow' ? null : '1',
    requestAmount: contractName === 'privateEscrow' ? null : '2',
    remainingOfferAmount: contractName === 'privateEscrow' ? null : '1',
    remainingRequestAmount: contractName === 'privateEscrow' ? null : '2',
    price: contractName === 'privateEscrow' ? null : '2',
    priceBasis: 'quote_per_base',
    expiresAt: '2026-07-26T12:00:00.000Z',
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'2'.repeat(64)}`
  };
};

const tradeOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  contractName: 'standardEscrow' | 'privateEscrow' | 'directEscrow',
  options: {
    access?: SafeOrderSummary['access'];
    amountVisibility?: SafeOrderSummary['amountVisibility'];
    offerSymbol?: string;
    requestSymbol?: string;
    recipient?: `0x${string}` | null;
  } = {}
): SafeOrderSummary => {
  const escrow =
    manifest.contracts[contractName]!.address.toLowerCase() as `0x${string}`;
  const offerAsset = resolveAsset(
    manifest,
    options.offerSymbol ?? (contractName === 'privateEscrow' ? 'p.WISP' : 'WISP')
  );
  const requestAsset = resolveAsset(
    manifest,
    options.requestSymbol ?? 'p.gCOTI'
  );
  const amountVisibility =
    options.amountVisibility ??
    (contractName === 'privateEscrow' ? 'private' : 'visible');
  return {
    identity: {
      escrowContract: escrow,
      localId: '11',
      handle: `cw_${escrow.slice(2)}_11`
    },
    kind: 'trade',
    status: 'open',
    maker: FEE_RECIPIENT,
    recipient: options.recipient ?? null,
    access:
      options.access ??
      (contractName === 'directEscrow' ? 'unlisted' : 'public'),
    amountVisibility,
    offerAsset,
    requestAsset,
    offerAmount: amountVisibility === 'private' ? null : '1',
    requestAmount: amountVisibility === 'private' ? null : '2',
    remainingOfferAmount: amountVisibility === 'private' ? null : '1',
    remainingRequestAmount: amountVisibility === 'private' ? null : '2',
    price: amountVisibility === 'private' ? '2' : '2',
    priceBasis: 'quote_per_base',
    expiresAt: '2026-07-28T12:00:00.000Z',
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'4'.repeat(64)}`
  };
};

describe('ManifestExecutionPlanner', () => {
  it('prepares an allowlisted WISP shield with an exact approval and quoted portal fee', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });
    const intent: PrivacyBridgeIntent = {
      action: 'privacy_bridge',
      wallet: WALLET,
      pair: 'wisp',
      direction: 'public-to-private',
      publicAsset: resolveAsset(manifest, 'WISP'),
      privateAsset: resolveAsset(manifest, 'p.WISP'),
      amount: '1'
    };
    const execution = await planner.plan(intent, statusFor(manifest));

    expect(execution.fee.amount).toBe('0');
    expect(execution.exactNativeValue).toBe('9');
    expect(execution.steps).toHaveLength(2);
    expect(execution.steps[0]).toMatchObject({
      kind: 'approval',
      amount: '1000000',
      approvalScheme: 'erc20-exact'
    });
    expect(execution.steps[1]).toMatchObject({
      kind: 'protocol',
      contract: manifest.contracts.privacyBridgeWisp!.address,
      nativeValue: '9'
    });
    expect(execution.intentMetadata).toMatchObject({
      bridgePair: 'wisp',
      bridgeDirection: 'public-to-private',
      amountAtomic: '1000000',
      portalFeeAtomic: '9'
    });
  });

  it.each(
    PRIVACY_BRIDGE_PAIRS_V1.flatMap((pair) =>
      (['public-to-private', 'private-to-public'] as const).map(
        (direction) => ({ pair, direction })
      )
    )
  )(
    'binds the audited Privacy Portal route for $pair.id $direction',
    async ({ pair, direction }) => {
      const manifest = await loadRuntimeManifest();
      const rpc = new FakeRpc();
      rpc.bridgePublicToken =
        pair.publicTokenAddress ??
        '0x0000000000000000000000000000000000000000';
      rpc.bridgePrivateToken = pair.privateTokenAddress;
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc,
        now: () => NOW
      });
      const publicAsset = resolveAsset(manifest, pair.publicSymbol);
      const privateAsset = resolveAsset(manifest, pair.privateSymbol);
      const execution = await planner.plan(
        {
          action: 'privacy_bridge',
          wallet: WALLET,
          pair: pair.id,
          direction,
          publicAsset,
          privateAsset,
          amount: '1'
        },
        statusFor(manifest)
      );

      const amountAtomic = (10n ** BigInt(pair.decimals)).toString();
      const protocol = execution.steps.at(-1);
      expect(protocol).toMatchObject({
        kind: 'protocol',
        contract: manifest.contracts[pair.contractName]!.address,
        nativeValue:
          pair.bridgeKind === 'native'
            ? direction === 'public-to-private'
              ? amountAtomic
              : '0'
            : '9'
      });
      expect(protocol?.encoding?.selector).toBe(
        manifest.contracts[pair.contractName]!.selectors[
          direction === 'public-to-private' ? 'deposit' : 'withdraw'
        ]
      );
      expect(protocol?.encoding?.arguments).toHaveLength(
        pair.bridgeKind === 'native' &&
          direction === 'public-to-private'
          ? 2
          : 3
      );
      expect(execution.intentMetadata).toMatchObject({
        bridgePair: pair.id,
        bridgeDirection: direction,
        amountAtomic,
        portalFeeAtomic: '9'
      });

      if (
        pair.bridgeKind === 'native' &&
        direction === 'public-to-private'
      ) {
        expect(execution.steps).toHaveLength(1);
        expect(execution.exactNativeValue).toBe(amountAtomic);
        return;
      }

      expect(execution.steps).toHaveLength(2);
      expect(execution.steps[0]).toMatchObject({
        kind: 'approval',
        token:
          direction === 'public-to-private'
            ? publicAsset.address
            : privateAsset.address,
        approvalScheme:
          direction === 'public-to-private'
            ? 'erc20-exact'
            : 'coti-private-exact',
        amount:
          direction === 'public-to-private' ? amountAtomic : '0'
      });
      if (direction === 'private-to-public') {
        expect(
          execution.steps[0]?.privateArtifactGroups?.[0]?.values[0]
        ).toMatchObject({
          source: 'intent-sell-amount',
          asset: { symbol: pair.privateSymbol }
        });
      }
      expect(execution.exactNativeValue).toBe(
        pair.bridgeKind === 'native' ? '0' : '9'
      );
    }
  );

  it('binds the live fee, recipient, exact approval, selector, gas, and native value', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });
    const intent = createTradeIntent(manifest);
    const execution = await planner.plan(intent, statusFor(manifest));

    expect(execution.fee).toEqual({
      token: 'native',
      amount: '123',
      scheduleAmount: '123',
      recipient: FEE_RECIPIENT
    });
    expect(execution.steps).toHaveLength(2);
    expect(execution.steps[0]).toMatchObject({
      kind: 'approval',
      amount: '10250000',
      token: resolveAsset(manifest, 'WISP').address,
      nativeValue: '0'
    });
    expect(execution.steps[0]?.encoding?.selector).toBe(
      toFunctionSelector('approve(address,uint256)')
    );
    expect(execution.steps[1]?.encoding?.selector).toBe(
      manifest.contracts.standardEscrow?.selectors.createTradeWithPolicy
    );
    expect(execution.exactNativeValue).toBe('123');
    expect(execution.gasCap).toBe('2250000');
    expect(execution.simulation.ok).toBe(true);
    expect(
      rpc.calls.filter(({ method }) => method === 'eth_call').length
    ).toBeGreaterThanOrEqual(5);
  });

  it('adds native principal to the exact live fee without an approval', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });
    const execution = await planner.plan(
      createTradeIntent(manifest, 'COTI'),
      statusFor(manifest)
    );

    expect(execution.steps).toHaveLength(1);
    expect(execution.exactNativeValue).toBe(
      (10n ** 18n + rpc.fee).toString()
    );
    expect(execution.steps[0]?.nativeValue).toBe(execution.exactNativeValue);
  });

  it('fails closed when the live audit status is not write-ready', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    await expect(
      planner.plan(
        createTradeIntent(manifest),
        statusFor(manifest, { ready: false, readOnly: true })
      )
    ).rejects.toMatchObject({ code: 'unsupported' });
  });

  it.each([
    ['unlisted', null],
    ['direct', FEE_RECIPIENT]
  ] as const)(
    'plans exact visible %s creation through the audited Direct escrow',
    async (access, recipient) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new FakeRpc(),
        now: () => NOW
      });
      const intent: CreateTradeIntent = {
        ...createTradeIntent(manifest),
        access,
        recipient,
        secretPolicy:
          access === 'unlisted'
            ? {
                kind: 'generate-local',
                share: 'encrypted-coti-message-only'
              }
            : { kind: 'recipient-bound', recipient }
      };
      const execution = await planner.plan(intent, statusFor(manifest));
      const protocol = execution.steps.at(-1)!;

      expect(protocol.contract.toLowerCase()).toBe(
        manifest.contracts.directEscrow!.address.toLowerCase()
      );
      expect(protocol.encoding?.selector).toBe('0x74d8da0e');
      expect(protocol.encoding?.arguments.slice(0, 3)).toEqual([
          [1, resolveAsset(manifest, 'WISP').address],
          [0, '0x0000000000000000000000000000000000000000'],
          ['10250000', '2000000000000000000']
      ]);
      expect(protocol.encoding?.arguments).toHaveLength(11);
      expect(protocol.encoding?.arguments[5]).toBe(
        recipient ?? '0x0000000000000000000000000000000000000000'
      );
      expect(
        protocol.privateArtifactGroups?.[0]?.outputs.map(
          ({ kind, jsonPointer }) => `${kind}:${jsonPointer}`
        )
      ).toEqual([
        'keccak256:/arguments/7',
        'direct-terms-v1:/arguments/10',
        'terms-hash-v1:/arguments/8',
        'itUint256:/arguments/9'
      ]);
      expect(execution.exactNativeValue).toBe('123');
      expect(execution.gasCap).toBe('8250000');
      expect(execution.simulation).toMatchObject({
        ok: true,
        deferredPrivateArtifacts: true
      });
    }
  );

  it.each([
    ['public', null],
    ['unlisted', null],
    ['direct', FEE_RECIPIENT]
  ] as const)(
    'plans exact %s private-liquidity creation without exposing hidden inventory',
    async (access, recipient) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new FakeRpc(),
        now: () => NOW
      });
      const intent: CreateTradeIntent = {
        ...createTradeIntent(manifest, 'p.WISP'),
        access,
        recipient,
        amountVisibility: 'private',
        secretPolicy:
          access === 'unlisted'
            ? {
                kind: 'generate-local',
                share: 'encrypted-coti-message-only'
              }
            : access === 'direct'
              ? { kind: 'recipient-bound', recipient }
              : { kind: 'none' }
      };
      const execution = await planner.plan(intent, statusFor(manifest));
      const approval = execution.steps[0]!;
      const protocol = execution.steps.at(-1)!;
      const artifact = protocol.privateArtifactGroups?.[0];
      expect(artifact).toBeDefined();
      if (!artifact) throw new Error('Expected a private artifact group.');

      expect(approval).toMatchObject({
        kind: 'approval',
        approvalScheme: 'coti-private-exact',
        amount: '0',
        gasCap: '8000000',
        encoding: {
          selector: '0x8e532c44'
        }
      });
      expect(approval.encoding?.arguments).toEqual([
        manifest.contracts.privateEscrow!.address,
        [['0', '0'], '0x']
      ]);
      expect(approval.privateArtifactGroups?.[0]).toMatchObject({
        recipe: 'coti-private-exact-allowance-v1',
        outputs: [
          {
            kind: 'coti-private-exact-allowance',
            jsonPointer: '/arguments/1'
          }
        ],
        context: {
          targetContract: resolveAsset(manifest, 'p.WISP').address,
          functionSelector: '0x8e532c44',
          spender: manifest.contracts.privateEscrow!.address,
          accountEncryptionRequired: true
        }
      });
      expect(protocol).toMatchObject({
        contract: manifest.contracts.privateEscrow!.address,
        gasCap: '8000000',
        encoding: { selector: '0xc046ea5d' }
      });
      expect(protocol.encoding?.arguments[2]).toBe(
        recipient ?? '0x0000000000000000000000000000000000000000'
      );
      expect(protocol.encoding?.arguments[4]).toBe(access === 'public');
      expect(protocol.encoding?.arguments[0]).toEqual([
        2,
        resolveAsset(manifest, 'p.WISP').address,
        '0'
      ]);
      expect(protocol.encoding?.arguments[1]).toEqual([
        0,
        '0x0000000000000000000000000000000000000000',
        '0'
      ]);
      expect(artifact.values).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'hidden-offer-amount',
            source: 'signer-elicitation'
          }),
          expect.objectContaining({
            id: 'hidden-request-amount',
            source: 'signer-elicitation'
          })
        ])
      );
      expect(
        artifact.outputs.map(
          ({ kind, jsonPointer }) => `${kind}:${jsonPointer}`
        )
      ).toEqual(
        access === 'unlisted'
          ? [
              'itUint256:/arguments/7',
              'trade-recovery-v1:/arguments/10',
              'keccak256:/arguments/5',
              'direct-terms-v1:/arguments/12',
              'terms-hash-v1:/arguments/6',
              'itUint256:/arguments/8',
              'itUint256:/arguments/9',
              'itUint256:/arguments/11'
            ]
          : [
              'itUint256:/arguments/7',
              'trade-recovery-v1:/arguments/10',
              'uint256:/arguments/0/2',
              'uint256:/arguments/1/2'
            ]
      );
      expect(JSON.stringify(execution)).not.toContain('hiddenAmount');
      expect(execution.exactNativeValue).toBe('123');
      expect(execution.gasCap).toBe('16000000');
    }
  );

  it('plans a trusted cross-escrow Direct counter with the exact deployed selector', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'standardEscrow', {
      requestSymbol: 'COTI'
    });
    const counter = {
      action: 'counter' as const,
      wallet: WALLET,
      order,
      offerAsset: order.requestAsset,
      requestAsset: order.offerAsset,
      offerAmount: '2',
      requestAmount: '1',
      expiresAt: '2026-07-28T12:00:00.000Z',
      recipient: order.maker,
      access: 'direct' as const,
      amountVisibility: 'visible' as const,
      secretPolicy: {
        kind: 'recipient-bound' as const,
        recipient: order.maker
      }
    };
    const execution = await planner.plan(
      counter,
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    expect(protocol).toMatchObject({
      encoding: {
        selector: '0x08c084c6'
      }
    });
    expect(protocol.contract.toLowerCase()).toBe(
      manifest.contracts.directEscrow!.address.toLowerCase()
    );
    expect(
      String(protocol.encoding?.arguments[0]).toLowerCase()
    ).toBe(
      manifest.contracts.standardEscrow!.address.toLowerCase()
    );
    expect(protocol.encoding?.arguments.slice(1, 3)).toEqual([
      '11',
      order.maker
    ]);
    expect(protocol.privateArtifactGroups?.[0]).toMatchObject({
      recipe: 'direct-counter-v1',
      context: {
        parentTradeId: '11'
      }
    });
    expect(
      String(
        protocol.privateArtifactGroups?.[0]?.context
          ?.parentEscrowContract
      ).toLowerCase()
    ).toBe(
      manifest.contracts.standardEscrow!.address.toLowerCase()
    );
    expect(
      rpc.calls.some(({ method, params }) => {
        if (method !== 'eth_call') return false;
        const tx = params[0] as { to?: string; data?: string };
        return (
          tx.to?.toLowerCase() ===
            manifest.contracts.standardEscrow!.address.toLowerCase() &&
          tx.data?.slice(0, 10).toLowerCase() ===
            toFunctionSelector(
              'trustedDirectCounterEscrow(address)'
            ).toLowerCase()
        );
      })
    ).toBe(true);
  });

  it('uses createDirectCounterTrade for a primary Direct parent', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'directEscrow', {
      access: 'direct',
      recipient: WALLET,
      requestSymbol: 'COTI'
    });
    order.relation = {
      kind: 'primary',
      parentOrder: null,
      rootOrder: null,
      replacesOrder: null,
      replacementOrder: null
    };
    const execution = await planner.plan(
      {
        action: 'counter',
        wallet: WALLET,
        order,
        offerAsset: order.requestAsset,
        requestAsset: order.offerAsset,
        offerAmount: '2',
        requestAmount: '1',
        expiresAt: '2026-07-28T12:00:00.000Z',
        recipient: order.maker,
        access: 'direct',
        amountVisibility: 'visible',
        secretPolicy: {
          kind: 'recipient-bound',
          recipient: order.maker
        }
      },
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    expect(protocol.encoding?.selector).toBe('0x61d393f1');
    expect(protocol.encoding?.arguments[0]).toBe('11');
    expect(protocol.privateArtifactGroups?.[0]?.context).toMatchObject({
      counterRoute: 'direct-primary',
      sourceOrderRelation: 'primary',
      sourceMaker: FEE_RECIPIENT,
      sourceRecipient: WALLET,
      parentTradeId: '11',
      counteredTradeId: '11'
    });
  });

  it('uses counterTradeAndCloseCounteredTrade only for a Direct counter-of-counter', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'directEscrow', {
      access: 'direct',
      recipient: WALLET,
      requestSymbol: 'COTI'
    });
    const parentEscrow =
      manifest.contracts.standardEscrow!.address.toLowerCase() as `0x${string}`;
    order.relation = {
      kind: 'counter',
      parentOrder: {
        escrowContract: parentEscrow,
        localId: '7',
        handle: `cw_${parentEscrow.slice(2)}_7`
      },
      rootOrder: null,
      replacesOrder: null,
      replacementOrder: null
    };
    const execution = await planner.plan(
      {
        action: 'counter',
        wallet: WALLET,
        order,
        offerAsset: order.requestAsset,
        requestAsset: order.offerAsset,
        offerAmount: '2',
        requestAmount: '1',
        expiresAt: '2026-07-28T12:00:00.000Z',
        recipient: order.maker,
        access: 'direct',
        amountVisibility: 'visible',
        secretPolicy: {
          kind: 'recipient-bound',
          recipient: order.maker
        }
      },
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    expect(protocol.encoding?.selector).toBe('0x05907ed0');
    expect(protocol.encoding?.arguments[0]).toBe('11');
    expect(protocol.privateArtifactGroups?.[0]?.context).toMatchObject({
      counterRoute: 'direct-counter',
      sourceOrderRelation: 'counter',
      sourceMaker: FEE_RECIPIENT,
      sourceRecipient: WALLET,
      parentEscrowContract: parentEscrow,
      parentTradeId: '7',
      counteredTradeId: '11'
    });
  });

  it('rejects a Direct counter from a wallet that is not the fixed recipient', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'directEscrow', {
      access: 'direct',
      recipient: FEE_RECIPIENT,
      requestSymbol: 'COTI'
    });
    order.maker =
      '0x3333333333333333333333333333333333333333';
    await expect(
      planner.plan(
        {
          action: 'counter',
          wallet: WALLET,
          order,
          offerAsset: order.requestAsset,
          requestAsset: order.offerAsset,
          offerAmount: '2',
          requestAmount: '1',
          expiresAt: '2026-07-28T12:00:00.000Z',
          recipient: order.maker,
          access: 'direct',
          amountVisibility: 'visible',
          secretPolicy: {
            kind: 'recipient-bound',
            recipient: order.maker
          }
        },
        statusFor(manifest)
      )
    ).rejects.toMatchObject({
      code: 'unsupported',
      message: 'Only the fixed recipient can counter this Direct order.'
    });
  });

  it.each([
    ['unlisted', null, '0x543fe0a9'],
    ['direct', WALLET, '0x12923fba']
  ] as const)(
    'plans an exact visible %s Direct fill with signer-bound private token input',
    async (access, recipient, selector) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new FakeRpc(),
        now: () => NOW
      });
      const order = tradeOrder(manifest, 'directEscrow', {
        access,
        recipient,
        requestSymbol: 'p.gCOTI'
      });
      const intent: FillIntent = {
        action: 'fill',
        wallet: WALLET,
        order,
        inputAmount: '2',
        minOutputAmount: null,
        recurringSide: null,
        secretPolicy:
          access === 'unlisted'
            ? {
                kind: 'resolve-from-local-vault',
                orderHandle: order.identity.handle
              }
            : { kind: 'recipient-bound', recipient }
      };
      const execution = await planner.plan(intent, statusFor(manifest));
      const protocol = execution.steps.at(-1)!;
      const artifact = protocol.privateArtifactGroups?.[0];
      expect(artifact).toBeDefined();
      if (!artifact) throw new Error('Expected a private artifact group.');

      expect(execution.steps[0]).toMatchObject({
        kind: 'approval',
        approvalScheme: 'coti-private-exact',
        amount: '0',
        encoding: { selector: '0x8e532c44' }
      });
      expect(protocol.encoding?.selector).toBe(selector);
      expect(protocol.encoding?.arguments[0]).toBe('11');
      expect(protocol.encoding?.arguments).toHaveLength(
        access === 'unlisted' ? 3 : 2
      );
      expect(
        artifact.outputs.map(
          ({ kind, jsonPointer }) => `${kind}:${jsonPointer}`
        )
      ).toEqual(
        access === 'unlisted'
          ? ['itUint256:/arguments/1', 'itUint256:/arguments/2']
          : ['itUint256:/arguments/1']
      );
      expect(
        artifact.values.find(({ id }) => id === 'request-amount')
      ).toMatchObject({ source: 'signer-elicitation' });
      expect(execution.exactNativeValue).toBe('0');
      expect(execution.simulation.deferredPrivateArtifacts).toBe(true);
      const prepared = await new SignedDomainEnvelopeFactory({
        manifest,
        pairingSecret: PAIRING_SECRET,
        now: () => NOW
      }).create(intent, execution);
      expect(
        (prepared.payload as SignedActionEnvelopeV1).intent.metadata
      ).toMatchObject({ sourceMaker: order.maker });
    }
  );

  it.each([
    ['public', null, '0xbecac0e2'],
    ['unlisted', null, '0x359d1061'],
    ['direct', WALLET, '0xbecac0e2']
  ] as const)(
    'plans a %s private-token private-liquidity fill with no amount in the public intent',
    async (access, recipient, selector) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new FakeRpc(),
        now: () => NOW
      });
      const order = tradeOrder(manifest, 'privateEscrow', {
        access,
        recipient,
        requestSymbol: 'p.gCOTI'
      });
      const intent: FillIntent = {
        action: 'fill',
        wallet: WALLET,
        order,
        inputAmount: null,
        minOutputAmount: null,
        recurringSide: null,
        secretPolicy:
          access === 'unlisted'
            ? {
                kind: 'resolve-from-local-vault',
                orderHandle: order.identity.handle
              }
            : access === 'direct'
              ? { kind: 'recipient-bound', recipient }
              : { kind: 'none' }
      };
      const execution = await planner.plan(intent, statusFor(manifest));
      const protocol = execution.steps.at(-1)!;
      const artifact = protocol.privateArtifactGroups?.[0];
      expect(artifact).toBeDefined();
      if (!artifact) throw new Error('Expected a private artifact group.');

      expect(protocol.encoding?.selector).toBe(selector);
      expect(protocol.encoding?.arguments[0]).toBe('11');
      expect(protocol.encoding?.arguments).toHaveLength(
        access === 'unlisted' ? 3 : 2
      );
      expect(artifact.values).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            id: 'request-amount',
            source: 'signer-elicitation'
          })
        ])
      );
      expect(JSON.stringify(execution)).not.toMatch(
        /"inputAmount"|"decimalValue"/u
      );
      expect(execution.exactNativeValue).toBe('0');
    }
  );

  it('binds public/native payment value on an unlisted hybrid private-liquidity fill', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'privateEscrow', {
      access: 'unlisted',
      requestSymbol: 'COTI'
    });
    const execution = await planner.plan(
      {
        action: 'fill',
        wallet: WALLET,
        order,
        inputAmount: '2',
        minOutputAmount: null,
        recurringSide: null,
        secretPolicy: {
          kind: 'resolve-from-local-vault',
          orderHandle: order.identity.handle
        }
      },
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;

    expect(protocol.encoding).toEqual({
      selector: '0x93c30b36',
      arguments: [
        '11',
        '2000000000000000000',
        [['0', '0'], '0x']
      ]
    });
    expect(protocol.nativeValue).toBe('2000000000000000000');
    expect(execution.exactNativeValue).toBe('2000000000000000000');
    expect(
      protocol.privateArtifactGroups?.[0]?.outputs
    ).toEqual([
      {
        kind: 'itUint256',
        valueId: 'order-access-secret',
        jsonPointer: '/arguments/2'
      }
    ]);
  });

  it('builds audited public recurring terms and fails closed when recurring bytecode is not approved', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const intent: CreateRecurringIntent = {
      action: 'create_recurring',
      wallet: WALLET,
      baseAsset: resolveAsset(manifest, 'gCOTI'),
      quoteAsset: resolveAsset(manifest, 'WISP'),
      buyPrice: '0.25',
      sellPrice: '0.3',
      buyQuoteLiquidity: '20',
      sellBaseLiquidity: '10',
      access: 'public',
      recipient: null,
      amountVisibility: 'visible',
      secretPolicy: { kind: 'none' }
    };
    const execution = await planner.plan(intent, statusFor(manifest));
    expect(execution.steps.at(-1)?.encoding?.selector).toBe(
      manifest.contracts.recurringEscrow?.selectors.createRecurringOrder
    );
    expect(execution.steps.at(-1)?.encoding?.arguments).toEqual([
      [1, resolveAsset(manifest, 'gCOTI').address],
      [1, resolveAsset(manifest, 'WISP').address],
      [(10n ** 18n).toString(), '250000'],
      [(10n ** 18n).toString(), '300000'],
      '0x0000000000000000000000000000000000000000',
      true,
      `0x${'0'.repeat(64)}`,
      (10n * 10n ** 18n).toString(),
      '20000000'
    ]);
    const disabled = statusFor(manifest);
    disabled.registry.recurringWritesEnabled = false;
    await expect(planner.plan(intent, disabled)).rejects.toMatchObject({
      code: 'unsupported'
    });
  });

  it('maps a user buying base to fillSellSideWithSecret and approves the quote input exactly', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = recurringOrder(manifest);
    const intent: FillIntent = {
      action: 'fill',
      wallet: WALLET,
      order,
      inputAmount: '5',
      minOutputAmount: '1',
      recurringSide: 'buy',
      secretPolicy: { kind: 'none' }
    };
    const execution = await planner.plan(intent, statusFor(manifest));

    expect(execution.steps[0]).toMatchObject({
      kind: 'approval',
      token: order.recurring!.quoteAsset.address,
      amount: '5000000',
      nativeValue: '0'
    });
    expect(execution.steps[1]?.encoding).toEqual({
      selector:
        manifest.contracts.recurringEscrow?.selectors
          .fillSellSideWithSecret,
      arguments: [
        '7',
        '5000000',
        (10n ** 18n).toString(),
        `0x${'0'.repeat(64)}`
      ]
    });
    expect(execution.exactNativeValue).toBe('0');
    expect(execution.fee.amount).toBe('0');
  });

  it('maps a user selling native base to fillBuySideWithSecret and binds native value', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const order = recurringOrder(manifest, {
      baseSymbol: 'COTI',
      quoteSymbol: 'WISP'
    });
    const intent: FillIntent = {
      action: 'fill',
      wallet: WALLET,
      order,
      inputAmount: '1.5',
      minOutputAmount: '2',
      recurringSide: 'sell',
      secretPolicy: { kind: 'none' }
    };
    const execution = await planner.plan(intent, statusFor(manifest));

    expect(execution.steps).toHaveLength(1);
    expect(execution.steps[0]?.encoding).toEqual({
      selector:
        manifest.contracts.recurringEscrow?.selectors
          .fillBuySideWithSecret,
      arguments: ['7', '1500000000000000000', '2000000', `0x${'0'.repeat(64)}`]
    });
    expect(execution.steps[0]?.nativeValue).toBe(
      '1500000000000000000'
    );
    expect(execution.exactNativeValue).toBe('1500000000000000000');
  });

  it('gates recurring fills and lifecycle writes on the live recurring audit', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const disabled = statusFor(manifest);
    disabled.registry.recurringWritesEnabled = false;
    const order = recurringOrder(manifest);
    const fill: FillIntent = {
      action: 'fill',
      wallet: WALLET,
      order,
      inputAmount: '1',
      minOutputAmount: null,
      recurringSide: 'buy',
      secretPolicy: { kind: 'none' }
    };
    await expect(planner.plan(fill, disabled)).rejects.toMatchObject({
      code: 'unsupported'
    });
    const pause: OrderUpdateIntent = {
      action: 'order_update',
      wallet: WALLET,
      order,
      update: 'pause',
      expiresAt: null
    };
    await expect(planner.plan(pause, disabled)).rejects.toMatchObject({
      code: 'unsupported'
    });
  });

  it('allowlists recurring pause, resume, cancel and expired-trade reclaim only on audited contracts', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const recurring = recurringOrder(manifest);
    for (const update of ['pause', 'resume', 'cancel'] as const) {
      const execution = await planner.plan(
        {
          action: 'order_update',
          wallet: WALLET,
          order: recurring,
          update,
          expiresAt: null
        },
        statusFor(manifest)
      );
      const selectorName =
        update === 'pause'
          ? 'pauseOrder'
          : update === 'resume'
            ? 'resumeOrder'
            : 'cancelOrder';
      expect(execution.steps[0]?.encoding?.selector).toBe(
        manifest.contracts.recurringEscrow?.selectors[selectorName]
      );
    }

    for (const contractName of [
      'standardEscrow',
      'privateEscrow',
      'directEscrow'
    ] as const) {
      const execution = await planner.plan(
        {
          action: 'order_update',
          wallet: WALLET,
          order: lifecycleOrder(manifest, contractName),
          update: 'reclaim_expired',
          expiresAt: null
        },
        statusFor(manifest)
      );
      expect(execution.steps[0]?.encoding?.selector).toBe(
        manifest.contracts[contractName]?.selectors.reclaimExpiredTrade
      );
      expect(execution.exactNativeValue).toBe('0');
    }
  });

  it('accepts a bounded eth_estimateGas fallback when COTI rejects eth_call for a write', async () => {
    const manifest = await loadRuntimeManifest();
    const ethCallRpc = new FakeRpc();
    ethCallRpc.failProtocolSimulation = true;
    const rpc: PlannerRpc = {
      request: async <T>(method: string, params: unknown[]): Promise<T> => {
        if (method === 'eth_estimateGas') return '0xad04c' as T;
        return ethCallRpc.request<T>(method, params);
      }
    };
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });

    const execution = await planner.plan(
      {
        action: 'order_update',
        wallet: WALLET,
        order: recurringOrder(manifest),
        update: 'cancel',
        expiresAt: null
      },
      statusFor(manifest)
    );

    expect(execution.simulation.ok).toBe(true);
    expect(execution.simulation.warnings).toContainEqual(
      expect.stringContaining('eth_estimateGas')
    );
  });
});

describe('SignedDomainEnvelopeFactory', () => {
  it('HMAC-pairs the exact canonical plan and detects any tampering', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const intent = createTradeIntent(manifest);
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    }).plan(intent, statusFor(manifest));
    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;

    expect(verifySignedActionEnvelope(signed, PAIRING_SECRET, NOW).ok).toBe(
      true
    );
    const tampered = structuredClone(signed);
    tampered.steps[1]!.value = '124';
    expect(
      verifySignedActionEnvelope(tampered, PAIRING_SECRET, NOW)
    ).toEqual({ ok: false, error: 'operation-hash-mismatch' });
    expect(signed.registrySnapshot.fees).toEqual({
      [manifest.contracts.standardEscrow!.address.toLowerCase()]: '123'
    });
    expect(signed.intent.metadata).toEqual({
      partialFillsAllowed: true,
      minPartialFillBps: 100,
      minRequestAmount: '0',
      maxRequestAmountPerWallet: '2',
      oneFillPerWallet: false
    });
    expect(signed.steps[1]?.callTemplate?.functionSignature).toBe(
      'createTradeWithPolicy((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,uint256,(bool,uint16,uint256,uint256,bool))'
    );
    expect(
      signed.steps.reduce(
        (total, step) => total + BigInt(step.gasCap),
        0n
      ).toString()
    ).toBe(signed.gasCap);
    expect(signed.fee.recipient).toBe(FEE_RECIPIENT);
  });

  it('signs private artifact commitments without exposing hidden amounts and preserves private gas caps', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const intent: CreateTradeIntent = {
      ...createTradeIntent(manifest, 'p.WISP'),
      amountVisibility: 'private',
      access: 'unlisted',
      secretPolicy: {
        kind: 'generate-local',
        share: 'encrypted-coti-message-only'
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    }).plan(intent, statusFor(manifest));
    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;

    expect(verifySignedActionEnvelope(signed, PAIRING_SECRET, NOW).ok).toBe(
      true
    );
    expect(signed.simulation).toMatchObject({
      status: 'incomplete',
      reason: 'signer-local-private-artifacts-require-simulation'
    });
    expect(signed.intent.sellAmount).toBeUndefined();
    expect(signed.intent.buyAmount).toBeUndefined();
    expect(signed.intent.metadata).toEqual({
      confidentialTerms: 'signer-local'
    });
    expect(signed.secretPolicy).toEqual({
      accessMode: 'unlisted',
      generatedLocally: true,
      mayLeaveSigner: false,
      sharing: 'coti-private-message-only'
    });
    expect(signed.privateArtifacts?.length).toBeGreaterThanOrEqual(2);
    for (const group of signed.privateArtifacts ?? []) {
      expect(group.commitment).toMatch(/^0x[0-9a-f]{64}$/u);
      for (const value of group.values) {
        expect(value.commitment).toMatch(/^0x[0-9a-f]{64}$/u);
        expect(value).not.toHaveProperty('decimalValue');
        expect(value).not.toHaveProperty('secret');
      }
    }
    expect(signed.steps[0]).toMatchObject({
      gasCap: '8000000',
      allowance: {
        scheme: 'coti-private-exact',
        amount: '0',
        amountCommitment: expect.stringMatching(/^0x[0-9a-f]{64}$/u)
      },
      callTemplate: {
        functionSignature: 'approve(address,((uint256,uint256),bytes))'
      }
    });
    expect(signed.steps.at(-1)).toMatchObject({
      gasCap: '8000000',
      callTemplate: {
        functionSignature:
          'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)'
      }
    });
    expect(
      signed.steps.reduce(
        (total, step) => total + BigInt(step.gasCap),
        0n
      ).toString()
    ).toBe(signed.gasCap);

    const tampered = structuredClone(signed);
    tampered.privateArtifacts![0]!.outputs[0]!.jsonPointer = '/arguments/6';
    expect(
      verifySignedActionEnvelope(tampered, PAIRING_SECRET, NOW)
    ).toEqual({ ok: false, error: 'operation-hash-mismatch' });
  });

  it('keeps agent-provided private amounts encrypted in calldata and binds them to the envelope', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: CreateTradeIntent = {
      ...createTradeIntent(manifest, 'p.WISP'),
      amountVisibility: 'private',
      privateAmountMode: 'agent-provided',
      access: 'public',
      offerAmount: '1.25',
      requestAmount: '2.5',
      secretPolicy: { kind: 'none' }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, statusFor(manifest));
    const protocol = execution.steps.at(-1)!;
    const artifact = protocol.privateArtifactGroups?.[0];
    if (!artifact) throw new Error('Expected one private artifact group.');

    expect(protocol.encoding?.arguments[0]).toEqual([
      2,
      resolveAsset(manifest, 'p.WISP').address,
      '0'
    ]);
    expect(protocol.encoding?.arguments[1]?.[2]).toBe('0');
    expect(artifact.values).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'hidden-offer-amount',
          source: 'intent-sell-amount'
        }),
        expect.objectContaining({
          id: 'hidden-request-amount',
          source: 'intent-buy-amount'
        })
      ])
    );

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    expect(signed.intent).toMatchObject({
      amountVisibility: 'private-hidden',
      sellAmount: '1.25',
      buyAmount: '2.5',
      metadata: {
        confidentialTerms: 'agent-visible',
        privateAmountMode: 'agent-provided'
      }
    });
    expect(verifySignedActionEnvelope(signed, PAIRING_SECRET, NOW).ok).toBe(
      true
    );
  });

  it('marks Direct creation as generating a signer-local secret even for recipient-bound access', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: CreateTradeIntent = {
      ...createTradeIntent(manifest),
      access: 'direct',
      recipient: FEE_RECIPIENT,
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: FEE_RECIPIENT
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, statusFor(manifest));
    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;

    expect(signed.secretPolicy).toEqual({
      accessMode: 'direct',
      generatedLocally: true,
      mayLeaveSigner: false,
      sharing: 'coti-private-message-only'
    });
    expect(signed.registrySnapshot.fees).toEqual({
      [manifest.contracts.directEscrow!.address.toLowerCase()]: '123'
    });
  });

  it('builds the complete p.WISP/p.COTI private recurring review at ±10% market price', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new FakeRpc();
    const intent: CreateRecurringIntent = {
      action: 'create_recurring',
      wallet: WALLET,
      baseAsset: resolveAsset(manifest, 'p.WISP'),
      quoteAsset: resolveAsset(manifest, 'p.COTI'),
      orderType: deriveOrderClassificationV1({
        route: 'recurring-escrow',
        access: 'public',
        privateLiquidity: true,
        assets: [
          resolveAsset(manifest, 'p.WISP'),
          resolveAsset(manifest, 'p.COTI')
        ],
        relation: 'primary'
      }),
      buyPrice: '0.9',
      sellPrice: '1.1',
      buyQuoteLiquidity: '10',
      sellBaseLiquidity: '10',
      access: 'public',
      recipient: null,
      amountVisibility: 'private',
      privateAmountMode: 'agent-provided',
      priceReference: {
        id: 'chainwhisper-pwisp-pcoti',
        venue: 'Carbon DeFi',
        price: '1',
        observedAt: '2026-07-27T11:59:30.000Z',
        buyOffsetBps: -1_000,
        sellOffsetBps: 1_000
      },
      secretPolicy: { kind: 'none' }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    }).plan(intent, statusFor(manifest));
    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    const steps: MaterializedActionStep[] = signed.steps.map((step) => ({
      id: step.id,
      kind: step.kind,
      to: step.to,
      data: step.data,
      value: step.value,
      gasCap: step.gasCap,
      summary: step.summary,
      ...(step.allowance
        ? {
            approval: {
              token: step.allowance.token,
              spender: step.allowance.spender,
              amount: step.allowance.amount,
              ...(step.allowance.scheme
                ? { scheme: step.allowance.scheme }
                : {}),
              ...(step.allowance.amountCommitment
                ? { amountCommitment: step.allowance.amountCommitment }
                : {})
            }
          }
        : {})
    }));
    steps.at(-1)!.privateDisplayAmounts = [
      {
        id: 'recurring-base-inventory',
        amount: '10',
        symbol: 'p.WISP'
      },
      {
        id: 'recurring-quote-inventory',
        amount: '10',
        symbol: 'p.COTI'
      }
    ];

    const confirmation = buildActionConfirmation(
      signed,
      steps,
      0
    );

    expect(confirmation.details).toEqual(
      expect.arrayContaining([
        {
          label: 'Buy price · public on-chain (p.COTI per p.WISP)',
          value: '0.9 p.COTI per p.WISP'
        },
        {
          label: 'Sell price · public on-chain (p.COTI per p.WISP)',
          value: '1.1 p.COTI per p.WISP'
        },
        {
          label: 'Buy-side budget · encrypted on-chain (p.COTI)',
          value: '10 p.COTI'
        },
        {
          label: 'Sell-side inventory · encrypted on-chain (p.WISP)',
          value: '10 p.WISP'
        },
        {
          label: 'On-chain visibility',
          value:
            'Sell inventory and buy budget are encrypted. Buy and sell prices, addresses, and order activity are public.'
        },
        {
          label:
            'Private sell-side inventory (recurring-base-inventory)',
          value: '10 p.WISP'
        },
        {
          label:
            'Private buy-side budget (recurring-quote-inventory)',
          value: '10 p.COTI'
        },
        {
          label: 'Signed market reference source',
          value: 'chainwhisper-pwisp-pcoti'
        },
        {
          label: 'Signed market reference venue',
          value: 'Carbon DeFi'
        },
        {
          label: 'Signed market reference price (p.COTI per p.WISP)',
          value: '1 p.COTI per p.WISP'
        },
        {
          label: 'Signed market reference observed at',
          value: '2026-07-27T11:59:30.000Z'
        },
        {
          label: 'Buy-price deviation from market',
          value: '-10% (-1000 bps)'
        },
        {
          label: 'Sell-price deviation from market',
          value: '+10% (+1000 bps)'
        }
      ])
    );
    expect(confirmation.fee).toBe(
      '0.000000000000000123 COTI (123 wei)'
    );
    expect(signed.intent).toMatchObject({
      amountVisibility: 'private-hidden',
      orderType: {
        id: 'recurring.private-liquidity.public'
      },
      metadata: {
        privateAmountMode: 'agent-provided',
        buyQuoteLiquidity: '10',
        sellBaseLiquidity: '10',
        buyPriceOffsetBps: -1000,
        sellPriceOffsetBps: 1000
      }
    });
  });
});

describe('chainwhisper-mcp definition', () => {
  it('registers exactly the bounded keyless domain tools and rejects arbitrary transaction fields', async () => {
    const manifest = await loadRuntimeManifest();
    const runtime = await createChainWhisperPlanningRuntime({
      manifest,
      rpc: new FakeRpc(),
      pairingSecret: PAIRING_SECRET,
      now: () => NOW
    });
    expect(runtime.definition.tools.map(({ name }) => name)).toEqual([
      'chainwhisper_order_types',
      'chainwhisper_status',
      'chainwhisper_list_orders',
      'chainwhisper_get_order',
      'chainwhisper_compare_price_references',
      'chainwhisper_prepare_swap',
      'chainwhisper_privacy_bridge_status',
      'chainwhisper_prepare_privacy_bridge',
      'chainwhisper_prepare_create_trade',
      'chainwhisper_prepare_create_recurring',
      'chainwhisper_prepare_fill',
      'chainwhisper_prepare_counter',
      'chainwhisper_prepare_edit',
      'chainwhisper_prepare_order_update'
    ]);
    for (const tool of runtime.definition.tools) {
      expect(tool.inputSchema).toMatchObject({
        type: 'object',
        additionalProperties: false
      });
      expect(JSON.stringify(tool.inputSchema).toLowerCase()).not.toContain(
        '"abi"'
      );
      expect(JSON.stringify(tool.inputSchema).toLowerCase()).not.toContain(
        '"calldata"'
      );
    }
    const prepare = runtime.tools.find(
      ({ name }) => name === 'chainwhisper_prepare_create_trade'
    );
    const result = await prepare!.execute({
      wallet: WALLET,
      abi: ['function steal()'],
      calldata: '0xdeadbeef',
      contract: FEE_RECIPIENT
    });
    expect(result).toMatchObject({
      ok: false,
      error: { code: 'invalid_input' }
    });
  });

  it('starts without wallet or AES configuration and advertises its keyless boundary', async () => {
    const runtime = await createChainWhisperPlanningRuntime({
      manifest: await loadRuntimeManifest(),
      rpc: new FakeRpc(),
      pairingSecret: PAIRING_SECRET
    });
    expect(runtime.definition.instructions).toContain('keyless');
    expect(runtime.definition.instructions).toContain(
      'never signs, broadcasts'
    );
    expect(runtime.definition.resources?.map(({ uri }) => uri)).toContain(
      'chainwhisper://agent/security-boundary'
    );
  });

});
