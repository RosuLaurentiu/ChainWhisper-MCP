import { describe, expect, it } from 'vitest';
import type { Abi } from 'viem';

import {
  LiveChainWhisperDomainGateway
} from '../src/domain/liveGateway.js';
import type { Address, OrderStatus } from '../src/domain/types.js';
import {
  loadRuntimeManifest,
  type ChainWhisperRuntimeManifestV1
} from '../src/shared/runtimeManifest.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const MAKER =
  '0x2222222222222222222222222222222222222222' as Address;
const OTHER =
  '0x3333333333333333333333333333333333333333' as Address;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;

type HistoryItem = {
  contractAddress: Address;
  localId: bigint;
  kind: number;
  role: number;
  counterparty: Address;
  status: number;
  lastActivityBlock: bigint;
  sequence: bigint;
  amountVisibility: number;
};

const historyItem = (
  manifest: ChainWhisperRuntimeManifestV1,
  localId: number,
  role: number
): HistoryItem => ({
  contractAddress:
    manifest.contracts.standardEscrow!.address.toLowerCase() as Address,
  localId: BigInt(localId),
  kind: 1,
  role,
  counterparty: OTHER,
  status: 1,
  lastActivityBlock: 100n,
  sequence: BigInt(localId),
  amountVisibility: 0
});

const statusCode = (status: OrderStatus): number =>
  status === 'open' ? 1 : status === 'filled' ? 2 : 3;

const standardOrderView = (
  manifest: ChainWhisperRuntimeManifestV1,
  status: OrderStatus,
  relation: {
    parentTradeId?: bigint;
    replacesTradeId?: bigint;
    rootTradeId?: bigint;
  } = {}
): unknown => {
  const offer = manifest.tokens.find(({ symbol }) => symbol === 'WISP')!;
  const request = manifest.tokens.find(({ symbol }) => symbol === 'gCOTI')!;
  return {
    trade: {
      maker: MAKER,
      taker: ZERO_ADDRESS,
      status: statusCode(status),
      offerAsset: {
        assetType: 1,
        token: offer.address,
        amount: 10_000_000n
      },
      requestAsset: {
        assetType: 1,
        token: request.address,
        amount: 2_000_000_000_000_000_000n
      },
      createdAt: 1_700_000_000n,
      expiresAt: 0n
    },
    metadata: {
      isPublic: true,
      accessHash: `0x${'00'.repeat(32)}`,
      parentTradeId: relation.parentTradeId ?? 0n,
      feePaid: 0n
    },
    fillState: {
      remainingOfferAmount:
        status === 'filled' ? 0n : 10_000_000n,
      remainingRequestAmount:
        status === 'filled' ? 0n : 2_000_000_000_000_000_000n,
      filledOfferAmount:
        status === 'filled' ? 10_000_000n : 0n,
      filledRequestAmount:
        status === 'filled' ? 2_000_000_000_000_000_000n : 0n
    },
    fillPolicy: {
      partialFillsAllowed: true,
      minPartialFillBps: 100,
      minRequestAmount: 0n,
      maxRequestAmountPerWallet: 0n,
      oneFillPerWallet: false
    },
    effectiveStatus: statusCode(status),
    replacementTradeId: 0n,
    replacesTradeId: relation.replacesTradeId ?? 0n,
    rootTradeId: relation.rootTradeId ?? 0n
  };
};

const makeGateway = async (options: {
  history: HistoryItem[];
  nextOffset?: bigint;
  statuses?: Readonly<Record<string, OrderStatus>>;
  relations?: Readonly<
    Record<
      string,
      {
        parentTradeId?: bigint;
        replacesTradeId?: bigint;
        rootTradeId?: bigint;
      }
    >
  >;
}) => {
  const manifest = await loadRuntimeManifest();
  const calls: string[] = [];
  const client = {
    async readContract(input: {
      address: Address;
      abi: Abi;
      functionName: string;
      args?: readonly unknown[];
    }): Promise<unknown> {
      calls.push(input.functionName);
      if (input.functionName === 'getWalletHistoryPage') {
        return {
          items: options.history,
          nextOffset: options.nextOffset ?? 0n
        };
      }
      if (input.functionName === 'getTradeView') {
        const localId = String(input.args?.[0] ?? '0');
        return standardOrderView(
          manifest,
          options.statuses?.[localId] ?? 'open',
          options.relations?.[localId]
        );
      }
      throw new Error(`unexpected-read:${input.functionName}`);
    }
  };
  return {
    calls,
    manifest,
    gateway: new LiveChainWhisperDomainGateway({
      manifest,
      client
    })
  };
};

const listFillerOrders = (
  gateway: LiveChainWhisperDomainGateway,
  options: {
    status?: OrderStatus | 'all';
    cursor?: string | null;
    limit?: number;
  } = {}
) =>
  gateway.listOrders({
    wallet: WALLET,
    role: 'filler',
    kind: 'all',
    status: options.status ?? 'all',
    access: 'all',
    baseAsset: null,
    quoteAsset: null,
    cursor: options.cursor ?? null,
    limit: options.limit ?? 20
  });

describe('LiveChainWhisperDomainGateway filler history', () => {
  it('includes only role code 3 and excludes maker, taker, and unknown history roles', async () => {
    const manifest = await loadRuntimeManifest();
    const { gateway } = await makeGateway({
      history: [
        historyItem(manifest, 1, 3),
        historyItem(manifest, 2, 1),
        historyItem(manifest, 3, 2),
        historyItem(manifest, 4, 4)
      ]
    });

    const result = await listFillerOrders(gateway);

    expect(
      result.orders.map(({ identity }) => identity.localId)
    ).toEqual(['1']);
    expect(result).toMatchObject({
      nextCursor: null,
      truncated: false
    });
  });

  it('uses wallet history for an open-only filler query and then applies order status', async () => {
    const manifest = await loadRuntimeManifest();
    const { calls, gateway } = await makeGateway({
      history: [
        historyItem(manifest, 5, 3),
        historyItem(manifest, 6, 3)
      ],
      statuses: { '5': 'open', '6': 'filled' }
    });

    const result = await listFillerOrders(gateway, {
      status: 'open'
    });

    expect(
      result.orders.map(({ identity }) => identity.localId)
    ).toEqual(['5']);
    expect(calls).toContain('getWalletHistoryPage');
    expect(calls).not.toContain('getWalletDeskPageV2');
  });

  it('merges duplicate history roles without losing filler membership and preserves pagination', async () => {
    const manifest = await loadRuntimeManifest();
    const { gateway } = await makeGateway({
      history: [
        historyItem(manifest, 7, 3),
        historyItem(manifest, 7, 1),
        historyItem(manifest, 8, 2)
      ],
      nextOffset: 3n
    });

    const result = await listFillerOrders(gateway, {
      limit: 3
    });

    expect(
      result.orders.map(({ identity }) => identity.localId)
    ).toEqual(['7']);
    expect(result).toMatchObject({
      nextCursor: '3',
      truncated: true
    });
  });

  it('classifies a Standard edit replacement before its inherited parent id', async () => {
    const manifest = await loadRuntimeManifest();
    const { gateway } = await makeGateway({
      history: [],
      relations: {
        '9': {
          parentTradeId: 4n,
          replacesTradeId: 4n,
          rootTradeId: 4n
        }
      }
    });
    const standard =
      manifest.contracts.standardEscrow!.address as Address;

    const order = await gateway.getOrder({
      escrowContract: standard,
      localId: '9'
    });

    expect(order?.relation).toMatchObject({
      kind: 'replacement',
      parentOrder: null,
      replacesOrder: {
        localId: '4'
      },
      rootOrder: {
        localId: '4'
      }
    });
  });
});
