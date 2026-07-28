import { describe, expect, it } from 'vitest';
import {
  encodeAbiParameters,
  toFunctionSelector
} from 'viem';

import type {
  Address,
  CreateRecurringIntent,
  DomainStatus,
  EditIntent,
  FillIntent,
  OrderUpdateIntent,
  ResolvedAsset,
  SafeOrderSummary
} from '../src/domain/types.js';
import {
  ManifestExecutionPlanner,
  type PlannerRpc
} from '../src/planner/index.js';
import {
  hashRuntimeManifest,
  loadRuntimeManifest,
  type ChainWhisperRuntimeManifestV1
} from '../src/shared/index.js';

const WALLET =
  '0x2222222222222222222222222222222222222222' as Address;
const RECIPIENT =
  '0x3333333333333333333333333333333333333333' as Address;
const FEE_RECIPIENT =
  '0x1111111111111111111111111111111111111111' as Address;
const NOW = new Date('2026-07-27T12:00:00.000Z');
const EXPIRY = '2026-07-28T12:00:00.000Z';

class PlannerRpcFixture implements PlannerRpc {
  readonly calls: Array<{ method: string; params: unknown[] }> = [];
  allowance = 0n;
  fee = 123n;
  chargeFeeOnEdit = true;

  async request<T>(method: string, params: unknown[]): Promise<T> {
    this.calls.push({ method, params });
    if (method === 'eth_blockNumber') return '0x1234' as T;
    if (method !== 'eth_call') {
      throw new Error('unsupported-rpc-method');
    }
    const tx = params[0] as { data?: string };
    const selector = tx.data?.slice(0, 10).toLowerCase();
    if (selector === toFunctionSelector('feeAmount()').toLowerCase()) {
      return encodeAbiParameters(
        [{ type: 'uint256' }],
        [this.fee]
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector('feeRecipient()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [FEE_RECIPIENT]
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
      selector ===
      toFunctionSelector('chargeFeeOnEdit()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'bool' }],
        [this.chargeFeeOnEdit]
      ) as T;
    }
    return '0x' as T;
  }
}

const statusFor = (
  manifest: ChainWhisperRuntimeManifestV1
): DomainStatus => ({
  service: 'chainwhisper-mcp',
  mode: 'keyless',
  chainId: manifest.network.chainId,
  ready: true,
  readOnly: false,
  registry: {
    chainId: manifest.network.chainId,
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

const asset = (
  manifest: ChainWhisperRuntimeManifestV1,
  symbol: string
): ResolvedAsset => {
  const token = manifest.tokens.find(
    (candidate) => candidate.symbol === symbol
  );
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
        : (token.address!.toLowerCase() as Address),
    verified: true
  };
};

const identity = (
  contract: Address,
  localId = '7'
): SafeOrderSummary['identity'] => ({
  escrowContract: contract,
  localId,
  handle: `cw_${contract.slice(2)}_${localId}`
});

const recurringOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  options: {
    baseSymbol?: string;
    quoteSymbol?: string;
    amountVisibility?: SafeOrderSummary['amountVisibility'];
    status?: SafeOrderSummary['status'];
  } = {}
): SafeOrderSummary => {
  const baseAsset = asset(
    manifest,
    options.baseSymbol ?? 'gCOTI'
  );
  const quoteAsset = asset(
    manifest,
    options.quoteSymbol ?? 'WISP'
  );
  const hidden = options.amountVisibility === 'private';
  const escrow = manifest.contracts.recurringEscrow!
    .address as Address;
  return {
    identity: identity(escrow),
    kind: 'recurring',
    status: options.status ?? 'open',
    maker: WALLET,
    recipient: null,
    access: 'public',
    amountVisibility: hidden ? 'private' : 'visible',
    offerAsset: baseAsset,
    requestAsset: quoteAsset,
    offerAmount: hidden ? null : '10',
    requestAmount: null,
    remainingOfferAmount: hidden ? null : '10',
    remainingRequestAmount: hidden ? null : '20',
    price: '2.666666',
    priceBasis: 'quote_per_base',
    expiresAt: null,
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'1'.repeat(64)}`,
    recurring: {
      baseAsset,
      quoteAsset,
      buyBaseAmount: '2',
      buyQuoteAmount: '5',
      sellBaseAmount: '3',
      sellQuoteAmount: '8',
      buyPrice: '2.5',
      sellPrice: '2.666666',
      buyQuoteLiquidity: hidden ? null : '20',
      sellBaseLiquidity: hidden ? null : '10',
      buySideOpen: true,
      sellSideOpen: true,
      privateBaseInventory:
        hidden && baseAsset.kind === 'private-erc20',
      privateQuoteInventory:
        hidden && quoteAsset.kind === 'private-erc20'
    }
  };
};

const tradeOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  contractName:
    | 'standardEscrow'
    | 'privateEscrow'
    | 'directEscrow',
  options: {
    access?: SafeOrderSummary['access'];
    amountVisibility?: SafeOrderSummary['amountVisibility'];
    offerSymbol?: string;
    requestSymbol?: string;
    recipient?: Address | null;
  } = {}
): SafeOrderSummary => {
  const contract = manifest.contracts[contractName]!.address as Address;
  const offerAsset = asset(
    manifest,
    options.offerSymbol ??
      (contractName === 'privateEscrow' ? 'p.WISP' : 'WISP')
  );
  const requestAsset = asset(
    manifest,
    options.requestSymbol ?? 'COTI'
  );
  const hidden =
    options.amountVisibility ??
    (contractName === 'privateEscrow' ? 'private' : 'visible');
  return {
    identity: identity(contract, '11'),
    kind: 'trade',
    status: 'open',
    maker: WALLET,
    recipient: options.recipient ?? null,
    access:
      options.access ??
      (contractName === 'directEscrow' ? 'unlisted' : 'public'),
    amountVisibility: hidden,
    offerAsset,
    requestAsset,
    offerAmount: hidden === 'private' ? null : '10',
    requestAmount: hidden === 'private' ? null : '20',
    remainingOfferAmount: hidden === 'private' ? null : '8',
    remainingRequestAmount: hidden === 'private' ? null : '16',
    price: hidden === 'private' ? null : '2',
    priceBasis: 'quote_per_base',
    expiresAt: EXPIRY,
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'2'.repeat(64)}`,
    ...(contractName === 'standardEscrow'
      ? {
          fillPolicy: {
            partialFillsAllowed: false,
            minPartialFillBps: 250,
            minRequestAmount: '0.5',
            maxRequestAmountPerWallet: '3',
            oneFillPerWallet: true
          }
        }
      : {})
  };
};

describe('advanced order execution planning', () => {
  it('builds hybrid private recurring creation with encrypted zero on the public side', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new PlannerRpcFixture(),
      now: () => NOW
    });
    const intent: CreateRecurringIntent = {
      action: 'create_recurring',
      wallet: WALLET,
      baseAsset: asset(manifest, 'p.WISP'),
      quoteAsset: asset(manifest, 'WISP'),
      buyPrice: '2',
      sellPrice: '2.1',
      buyQuoteLiquidity: '4',
      sellBaseLiquidity: null,
      access: 'public',
      recipient: null,
      amountVisibility: 'private',
      secretPolicy: { kind: 'none' }
    };

    const execution = await planner.plan(
      intent,
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    const artifacts = protocol.privateArtifactGroups?.[0];

    expect(protocol.encoding?.selector).toBe('0xf3f05fef');
    expect(protocol.encoding?.arguments.slice(7, 9)).toEqual([
      '0',
      '4000000'
    ]);
    expect(artifacts).toMatchObject({
      recipe: 'private-recurring-v1',
      context: {
        requirePositiveValueIds:
          'recurring-base-inventory,recurring-quote-inventory'
      }
    });
    expect(artifacts?.values).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'recurring-base-inventory',
          source: 'signer-elicitation',
          allowZero: true
        }),
        expect.objectContaining({
          id: 'recurring-quote-private-zero',
          source: 'constant-zero',
          allowZero: true
        })
      ])
    );
    expect(
      artifacts?.outputs.map(
        ({ kind, jsonPointer }) => `${kind}:${jsonPointer}`
      )
    ).toEqual([
      'itUint256:/arguments/9',
      'itUint256:/arguments/10',
      'recurring-recovery-v1:/arguments/11'
    ]);
  });

  it.each([
    ['buy', '0x25c2920e', 'constant-zero', true],
    ['sell', '0xe07ad3b3', 'signer-elicitation', false]
  ] as const)(
    'maps private recurring user-%s fills to the deployed selector and canonical encrypted input',
    async (side, selector, source, allowZero) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new PlannerRpcFixture(),
        now: () => NOW
      });
      const order = recurringOrder(manifest, {
        baseSymbol: 'p.WISP',
        quoteSymbol: 'WISP',
        amountVisibility: 'private'
      });
      const intent: FillIntent = {
        action: 'fill',
        wallet: WALLET,
        order,
        inputAmount: side === 'buy' ? '2' : null,
        minOutputAmount: null,
        recurringSide: side,
        secretPolicy: { kind: 'none' }
      };

      const execution = await planner.plan(
        intent,
        statusFor(manifest)
      );
      const protocol = execution.steps.at(-1)!;
      const value =
        protocol.privateArtifactGroups?.[0]?.values[0];
      expect(protocol.encoding?.selector).toBe(selector);
      expect(value).toMatchObject({
        source
      });
      expect(Boolean(value?.allowZero)).toBe(allowZero);
      expect(
        protocol.privateArtifactGroups?.[0]?.outputs
      ).toEqual([
        expect.objectContaining({
          kind: 'itUint256',
          jsonPointer: '/arguments/2'
        })
      ]);
    }
  );

  it('carries the complete Standard fill policy and follows live chargeFeeOnEdit', async () => {
    const manifest = await loadRuntimeManifest();
    const rpc = new PlannerRpcFixture();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc,
      now: () => NOW
    });
    const order = tradeOrder(manifest, 'standardEscrow');
    const intent: EditIntent = {
      action: 'edit',
      wallet: WALLET,
      order,
      changes: {
        requestAmount: '3',
        partialFillsAllowed: true
      }
    };

    const charged = await planner.plan(
      intent,
      statusFor(manifest)
    );
    const chargedProtocol = charged.steps.at(-1)!;
    expect(chargedProtocol.encoding?.selector).toBe('0xcae9fdc4');
    expect(chargedProtocol.encoding?.arguments[1]).toEqual([
      1,
      order.offerAsset.address,
      '8000000'
    ]);
    expect(chargedProtocol.encoding?.arguments[2]).toEqual([
      0,
      '0x0000000000000000000000000000000000000000',
      '3000000000000000000'
    ]);
    expect(chargedProtocol.encoding?.arguments[7]).toEqual([
      true,
      250,
      '500000000000000000',
      '3000000000000000000',
      true
    ]);
    expect(charged.fee.amount).toBe('123');
    expect(
      rpc.calls.some(({ method, params }) => {
        if (method !== 'eth_call') return false;
        const tx = params[0] as { data?: string };
        return (
          tx.data?.slice(0, 10).toLowerCase() ===
          toFunctionSelector('chargeFeeOnEdit()').toLowerCase()
        );
      })
    ).toBe(true);

    rpc.chargeFeeOnEdit = false;
    const uncharged = await planner.plan(
      intent,
      statusFor(manifest)
    );
    expect(uncharged.fee.amount).toBe('0');
  });

  it.each([
    [
      'Direct',
      'directEscrow',
      {
        access: 'direct' as const,
        amountVisibility: 'visible' as const,
        offerSymbol: 'p.WISP',
        requestSymbol: 'WISP',
        recipient: RECIPIENT
      },
      'direct-edit-v1',
      '0x3c565595',
      [
        'itUint256:/arguments/4',
        'keccak256:/arguments/8',
        'terms-hash-v1:/arguments/9',
        'itUint256:/arguments/10',
        'direct-terms-v1:/arguments/11'
      ]
    ],
    [
      'private-liquidity',
      'privateEscrow',
      {
        access: 'unlisted' as const,
        amountVisibility: 'private' as const,
        offerSymbol: 'p.WISP',
        requestSymbol: 'p.USDT',
        recipient: null
      },
      'private-liquidity-edit-v1',
      '0x39502758',
      [
        'itUint256:/arguments/8',
        'trade-recovery-v1:/arguments/11',
        'keccak256:/arguments/6',
        'terms-hash-v1:/arguments/7',
        'itUint256:/arguments/9',
        'itUint256:/arguments/10',
        'itUint256:/arguments/12',
        'direct-terms-v1:/arguments/13'
      ]
    ]
  ] as const)(
    'binds the %s replacement recipe to its exact output indices',
    async (
      _label,
      contractName,
      options,
      recipe,
      selector,
      expectedOutputs
    ) => {
      const manifest = await loadRuntimeManifest();
      const planner = new ManifestExecutionPlanner({
        manifest,
        rpc: new PlannerRpcFixture(),
        now: () => NOW
      });
      const order = tradeOrder(
        manifest,
        contractName,
        options
      );
      const intent: EditIntent = {
        action: 'edit',
        wallet: WALLET,
        order,
        changes: {
          replaceConfidentialTerms: true,
          ...(contractName === 'directEscrow'
            ? { requestAmount: '3' }
            : {}),
          expiresAt: EXPIRY
        }
      };

      const execution = await planner.plan(
        intent,
        statusFor(manifest)
      );
      const protocol = execution.steps.at(-1)!;
      expect(protocol.encoding?.selector).toBe(selector);
      expect(protocol.privateArtifactGroups?.[0]?.recipe).toBe(
        recipe
      );
      expect(
        protocol.privateArtifactGroups?.[0]?.outputs
          .map(
            ({ kind, jsonPointer }) =>
              `${kind}:${jsonPointer}`
          )
          .sort()
      ).toEqual([...expectedOutputs].sort());
    }
  );

  it('carries exact recurring price tuples and binds private add/remove deltas as mutually exclusive', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new PlannerRpcFixture(),
      now: () => NOW
    });
    const order = recurringOrder(manifest, {
      baseSymbol: 'p.WISP',
      quoteSymbol: 'WISP',
      amountVisibility: 'private'
    });
    const intent: EditIntent = {
      action: 'edit',
      wallet: WALLET,
      order,
      changes: {
        adjustPrivateLiquidity: true
      }
    };

    const execution = await planner.plan(
      intent,
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    const artifacts = protocol.privateArtifactGroups?.[0];
    expect(protocol.encoding?.selector).toBe('0x2a275930');
    expect(protocol.encoding?.arguments[1]).toEqual([
      '2000000',
      '5000000'
    ]);
    expect(protocol.encoding?.arguments[2]).toEqual([
      '3000000',
      '8000000'
    ]);
    expect(artifacts).toMatchObject({
      recipe: 'recurring-edit-v1',
      context: {
        mutuallyExclusiveValueIds:
          'recurring-edit-add-base:recurring-edit-remove-base'
      }
    });
    expect(
      artifacts?.outputs.map(
        ({ kind, jsonPointer }) => `${kind}:${jsonPointer}`
      )
    ).toEqual([
      'itUint256:/arguments/5',
      'itUint256:/arguments/9'
    ]);
  });

  it('plans recurring inventory settlement only through settleInventory', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new PlannerRpcFixture(),
      now: () => NOW
    });
    const order = recurringOrder(manifest, {
      status: 'cancelled'
    });
    const intent: OrderUpdateIntent = {
      action: 'order_update',
      wallet: WALLET,
      order,
      update: 'settle_inventory',
      expiresAt: null
    };

    const execution = await planner.plan(
      intent,
      statusFor(manifest)
    );
    const protocol = execution.steps.at(-1)!;
    expect(protocol.encoding).toEqual({
      selector: '0xca9ad1f2',
      arguments: ['7']
    });
    expect(execution.fee.amount).toBe('0');
    expect(execution.exactNativeValue).toBe('0');
  });
});
