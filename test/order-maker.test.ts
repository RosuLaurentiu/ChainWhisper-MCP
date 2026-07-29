import { describe, expect, it, vi } from 'vitest';
import {
  encodeFunctionResult,
  parseAbi,
  type Hex,
} from 'viem';

import {
  loadRuntimeManifest,
  type JsonRpcReader,
} from '../src/shared/index.js';
import {
  RpcAllowlistedOrderMakerReader,
  type Address,
  type HexString,
} from '../src/signer/index.js';

const MAKER =
  '0x1111111111111111111111111111111111111111' as Address;
const TAKER =
  '0x2222222222222222222222222222222222222222' as Address;
const TOKEN =
  '0x3333333333333333333333333333333333333333' as Address;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;
const ACCESS_HASH = `0x${'ab'.repeat(32)}` as HexString;

const STANDARD_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token, uint256 amount) offerAsset, (uint8 assetType, address token, uint256 amount) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bool isPublic, bytes32 accessHash, uint256 parentTradeId, uint256 feePaid) metadata, (uint256 remainingOfferAmount, uint256 remainingRequestAmount, uint256 filledOfferAmount, uint256 filledRequestAmount) fillState, (bool partialFillsAllowed, uint16 minPartialFillBps, uint256 minRequestAmount, uint256 maxRequestAmountPerWallet, bool oneFillPerWallet) fillPolicy, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId, uint256 rootTradeId))',
]);
const PRIVATE_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token, uint256 amount) offerAsset, (uint8 assetType, address token, uint256 amount) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bool isPublic, bytes32 accessHash, uint256 feePaid, bytes32 termsHash, uint8 mode, bool hasMakerRecoveryNote) metadata, (uint256 remainingOfferAmount, uint256 remainingRequestAmount, uint256 filledOfferAmount, uint256 filledRequestAmount) fillState, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId))',
]);
const DIRECT_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token) offerAsset, (uint8 assetType, address token) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bytes32 accessHash, uint256 parentTradeId, uint256 feePaid, bytes32 termsHash, bool hasTermsPayload, bool hasMakerAccessSecret, bool hasTakerAccessSecret, bool publicAmountCaveat) metadata, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId, uint256 rootTradeId, bool offerAmountPrivate, bool requestAmountPrivate))',
]);
const RECURRING_READ_ABI = parseAbi([
  'function getOrderView(uint256 orderId) view returns (((address maker, address taker, uint8 status, uint8 mode, (uint8 assetType, address token) baseAsset, (uint8 assetType, address token) quoteAsset, (uint256 baseAmount, uint256 quoteAmount) buyTerms, (uint256 baseAmount, uint256 quoteAmount) sellTerms, bool isPublic, bytes32 accessHash, uint64 createdAt, uint32 executionCount, uint256 publicBaseInventory, uint256 publicQuoteInventory) order, bool buySideOpen, bool sellSideOpen, bool hasPrivateBaseInventory, bool hasPrivateQuoteInventory))',
]);

const tradeAsset = {
  assetType: 1,
  token: TOKEN,
  amount: 10n,
} as const;
const directAsset = {
  assetType: 1,
  token: TOKEN,
} as const;

const standardResult = (
  maker: Address = MAKER,
): Hex =>
  encodeFunctionResult({
    abi: STANDARD_READ_ABI,
    functionName: 'getTradeView',
    result: {
      trade: {
        maker,
        taker: TAKER,
        status: 1,
        offerAsset: tradeAsset,
        requestAsset: tradeAsset,
        createdAt: 1n,
        expiresAt: 0n,
      },
      metadata: {
        isPublic: false,
        accessHash: ACCESS_HASH,
        parentTradeId: 0n,
        feePaid: 0n,
      },
      fillState: {
        remainingOfferAmount: 10n,
        remainingRequestAmount: 10n,
        filledOfferAmount: 0n,
        filledRequestAmount: 0n,
      },
      fillPolicy: {
        partialFillsAllowed: false,
        minPartialFillBps: 0,
        minRequestAmount: 0n,
        maxRequestAmountPerWallet: 0n,
        oneFillPerWallet: false,
      },
      effectiveStatus: 1,
      replacementTradeId: 0n,
      replacesTradeId: 0n,
      rootTradeId: 7n,
    },
  });

const privateResult = (): Hex =>
  encodeFunctionResult({
    abi: PRIVATE_READ_ABI,
    functionName: 'getTradeView',
    result: {
      trade: {
        maker: MAKER,
        taker: TAKER,
        status: 1,
        offerAsset: tradeAsset,
        requestAsset: tradeAsset,
        createdAt: 1n,
        expiresAt: 0n,
      },
      metadata: {
        isPublic: false,
        accessHash: ACCESS_HASH,
        feePaid: 0n,
        termsHash: `0x${'00'.repeat(32)}`,
        mode: 1,
        hasMakerRecoveryNote: false,
      },
      fillState: {
        remainingOfferAmount: 10n,
        remainingRequestAmount: 10n,
        filledOfferAmount: 0n,
        filledRequestAmount: 0n,
      },
      effectiveStatus: 1,
      replacementTradeId: 0n,
      replacesTradeId: 0n,
    },
  });

const directResult = (): Hex =>
  encodeFunctionResult({
    abi: DIRECT_READ_ABI,
    functionName: 'getTradeView',
    result: {
      trade: {
        maker: MAKER,
        taker: TAKER,
        status: 1,
        offerAsset: directAsset,
        requestAsset: directAsset,
        createdAt: 1n,
        expiresAt: 0n,
      },
      metadata: {
        accessHash: ACCESS_HASH,
        parentTradeId: 0n,
        feePaid: 0n,
        termsHash: `0x${'00'.repeat(32)}`,
        hasTermsPayload: true,
        hasMakerAccessSecret: true,
        hasTakerAccessSecret: false,
        publicAmountCaveat: false,
      },
      effectiveStatus: 1,
      replacementTradeId: 0n,
      replacesTradeId: 0n,
      rootTradeId: 7n,
      offerAmountPrivate: true,
      requestAmountPrivate: true,
    },
  });

const recurringResult = (): Hex =>
  encodeFunctionResult({
    abi: RECURRING_READ_ABI,
    functionName: 'getOrderView',
    result: {
      order: {
        maker: MAKER,
        taker: TAKER,
        status: 1,
        mode: 1,
        baseAsset: directAsset,
        quoteAsset: directAsset,
        buyTerms: { baseAmount: 10n, quoteAmount: 20n },
        sellTerms: { baseAmount: 10n, quoteAmount: 20n },
        isPublic: false,
        accessHash: ACCESS_HASH,
        createdAt: 1n,
        executionCount: 0,
        publicBaseInventory: 0n,
        publicQuoteInventory: 0n,
      },
      buySideOpen: true,
      sellSideOpen: true,
      hasPrivateBaseInventory: true,
      hasPrivateQuoteInventory: true,
    },
  });

describe('RpcAllowlistedOrderMakerReader', () => {
  it('decodes the live maker and access commitment for all four allowlisted escrows', async () => {
    const manifest = await loadRuntimeManifest();
    const responses = new Map<string, Hex>([
      [
        manifest.contracts.standardEscrow!.address.toLowerCase(),
        standardResult(),
      ],
      [
        manifest.contracts.privateEscrow!.address.toLowerCase(),
        privateResult(),
      ],
      [
        manifest.contracts.directEscrow!.address.toLowerCase(),
        directResult(),
      ],
      [
        manifest.contracts.recurringEscrow!.address.toLowerCase(),
        recurringResult(),
      ],
    ]);
    const request = vi.fn(
      async <T>(method: string, params: unknown[]): Promise<T> => {
        expect(method).toBe('eth_call');
        expect(params[1]).toBe('latest');
        const to = (params[0] as { to: Address }).to.toLowerCase();
        const response = responses.get(to);
        if (!response) throw new Error('unexpected escrow');
        return response as T;
      },
    );
    const reader = new RpcAllowlistedOrderMakerReader({
      rpc: { request } satisfies JsonRpcReader,
      manifest,
    });

    for (const contract of [
      manifest.contracts.standardEscrow!,
      manifest.contracts.privateEscrow!,
      manifest.contracts.directEscrow!,
      manifest.contracts.recurringEscrow!,
    ]) {
      await expect(
        reader.readOrderAccess({
          escrowContract: contract.address,
          localId: '7',
        }),
      ).resolves.toEqual({
        maker: MAKER.toLowerCase(),
        accessHash: ACCESS_HASH,
      });
    }
    expect(request).toHaveBeenCalledTimes(4);
  });

  it('fails closed for unknown escrows, invalid ids, and a zero maker', async () => {
    const manifest = await loadRuntimeManifest();
    const request = vi.fn(
      async <T>(): Promise<T> => standardResult(ZERO_ADDRESS) as T,
    );
    const reader = new RpcAllowlistedOrderMakerReader({
      rpc: { request } satisfies JsonRpcReader,
      manifest,
    });

    await expect(
      reader.readOrderAccess({
        escrowContract:
          '0x9999999999999999999999999999999999999999',
        localId: '7',
      }),
    ).resolves.toBeNull();
    await expect(
      reader.readOrderAccess({
        escrowContract: manifest.contracts.standardEscrow!.address,
        localId: '01',
      }),
    ).resolves.toBeNull();
    expect(request).not.toHaveBeenCalled();

    await expect(
      reader.readOrderAccess({
        escrowContract: manifest.contracts.standardEscrow!.address,
        localId: '7',
      }),
    ).resolves.toBeNull();
    expect(request).toHaveBeenCalledTimes(1);
  });
});
