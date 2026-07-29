import {
  decodeFunctionResult,
  encodeFunctionData,
  parseAbi,
  type Hex,
} from 'viem';

import type {
  ChainWhisperRuntimeManifestV1,
  HexString,
  JsonRpcReader,
} from '../shared/index.js';
import { SignerError } from './errors.js';
import type { Address } from './types.js';

export type OrderMakerReference = {
  escrowContract: Address;
  localId: string;
};

export type OrderAccessFacts = {
  maker: Address;
  accessHash: HexString;
};

/**
 * Returns the live maker and access commitment only for an escrow that the
 * implementation has independently allowlisted. Returning null always means
 * "do not trust".
 */
export interface OrderMakerReader {
  readOrderAccess(
    order: OrderMakerReference,
  ): Promise<OrderAccessFacts | null>;
}

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

const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const MAX_UINT256 = (1n << 256n) - 1n;

type EscrowKind =
  | 'standardEscrow'
  | 'privateEscrow'
  | 'directEscrow'
  | 'recurringEscrow';

const ESCROW_KINDS: readonly EscrowKind[] = [
  'standardEscrow',
  'privateEscrow',
  'directEscrow',
  'recurringEscrow',
];

const parseLocalId = (value: string): bigint | null => {
  if (!/^(?:0|[1-9][0-9]{0,77})$/u.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= MAX_UINT256 ? parsed : null;
};

export class RpcAllowlistedOrderMakerReader
  implements OrderMakerReader
{
  readonly #rpc: JsonRpcReader;
  readonly #escrows: ReadonlyMap<string, EscrowKind>;

  constructor(options: {
    rpc: JsonRpcReader;
    manifest: ChainWhisperRuntimeManifestV1;
  }) {
    this.#rpc = options.rpc;
    this.#escrows = new Map(
      ESCROW_KINDS.map((kind) => {
        const contract = options.manifest.contracts[kind];
        if (!contract) {
          throw new SignerError(
            'CONFIGURATION_REQUIRED',
            `The audited runtime manifest is missing ${kind}.`,
          );
        }
        return [contract.address.toLowerCase(), kind] as const;
      }),
    );
  }

  async readOrderAccess(
    order: OrderMakerReference,
  ): Promise<OrderAccessFacts | null> {
    const kind = this.#escrows.get(order.escrowContract.toLowerCase());
    const localId = parseLocalId(order.localId);
    if (!kind || localId === null) return null;

    try {
      if (kind === 'recurringEscrow') {
        const data = encodeFunctionData({
          abi: RECURRING_READ_ABI,
          functionName: 'getOrderView',
          args: [localId],
        });
        const result = await this.#rpc.request<Hex>('eth_call', [
          { to: order.escrowContract, data },
          'latest',
        ]);
        const view = decodeFunctionResult({
          abi: RECURRING_READ_ABI,
          functionName: 'getOrderView',
          data: result,
        });
        return this.#normalizeFacts(
          view.order.maker,
          view.order.accessHash,
        );
      }

      const abi =
        kind === 'standardEscrow'
          ? STANDARD_READ_ABI
          : kind === 'privateEscrow'
            ? PRIVATE_READ_ABI
            : DIRECT_READ_ABI;
      const data = encodeFunctionData({
        abi,
        functionName: 'getTradeView',
        args: [localId],
      });
      const result = await this.#rpc.request<Hex>('eth_call', [
        { to: order.escrowContract, data },
        'latest',
      ]);
      if (kind === 'standardEscrow') {
        const view = decodeFunctionResult({
          abi: STANDARD_READ_ABI,
          functionName: 'getTradeView',
          data: result,
        });
        return this.#normalizeFacts(
          view.trade.maker,
          view.metadata.accessHash,
        );
      }
      if (kind === 'privateEscrow') {
        const view = decodeFunctionResult({
          abi: PRIVATE_READ_ABI,
          functionName: 'getTradeView',
          data: result,
        });
        return this.#normalizeFacts(
          view.trade.maker,
          view.metadata.accessHash,
        );
      }
      const view = decodeFunctionResult({
        abi: DIRECT_READ_ABI,
        functionName: 'getTradeView',
        data: result,
      });
      return this.#normalizeFacts(
        view.trade.maker,
        view.metadata.accessHash,
      );
    } catch (error) {
      if (error instanceof SignerError) throw error;
      throw new SignerError(
        'STALE_STATE',
        'The signer could not verify the live maker for this allowlisted order.',
      );
    }
  }

  #normalizeFacts(
    maker: string,
    accessHash: string,
  ): OrderAccessFacts | null {
    const normalizedMaker = maker.toLowerCase();
    if (
      normalizedMaker === ZERO_ADDRESS ||
      !/^0x[0-9a-fA-F]{64}$/u.test(accessHash)
    ) {
      return null;
    }
    return {
      maker: normalizedMaker as Address,
      accessHash: accessHash.toLowerCase() as HexString,
    };
  }
}
