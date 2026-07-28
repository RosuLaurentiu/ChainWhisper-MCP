import {
  auditRuntimeManifest,
  hashRuntimeManifest,
  loadRuntimeManifest,
  HttpJsonRpcReader,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader,
  type RuntimeAuditResult,
} from '../shared/index.js';
import {
  decodeAbiParameters,
  decodeFunctionResult,
  encodeFunctionData,
  parseAbi,
  toFunctionSelector,
  type Hex,
} from 'viem';

import { SignerError } from './errors.js';
import type {
  Address,
  RuntimeRegistryState,
  RuntimeStateReader,
  StandardOrderFacts,
  StandardOrderFactsReader,
} from './types.js';

export type RuntimeFeeState = {
  fees: Record<string, string>;
  editFees?: Record<string, string>;
  trustedFeeRecipients: Record<string, Address>;
};

export interface RuntimeFeeReader {
  readFeeState(): Promise<RuntimeFeeState>;
}

export class StaticRuntimeFeeReader implements RuntimeFeeReader {
  readonly #state: RuntimeFeeState;

  constructor(state: RuntimeFeeState) {
    this.#state = {
      fees: { ...state.fees },
      ...(state.editFees
        ? { editFees: { ...state.editFees } }
        : {}),
      trustedFeeRecipients: { ...state.trustedFeeRecipients },
    };
  }

  async readFeeState(): Promise<RuntimeFeeState> {
    return {
      fees: { ...this.#state.fees },
      ...(this.#state.editFees
        ? { editFees: { ...this.#state.editFees } }
        : {}),
      trustedFeeRecipients: {
        ...this.#state.trustedFeeRecipients,
      },
    };
  }
}

const FEE_AMOUNT_SELECTOR = toFunctionSelector('feeAmount()');
const FEE_RECIPIENT_SELECTOR = toFunctionSelector('feeRecipient()');
const CHARGE_FEE_ON_EDIT_SELECTOR =
  toFunctionSelector('chargeFeeOnEdit()');

const STANDARD_GET_TRADE_VIEW_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker,address taker,uint8 status,(uint8 assetType,address token,uint256 amount) offerAsset,(uint8 assetType,address token,uint256 amount) requestAsset,uint64 createdAt,uint64 expiresAt) trade,(bool isPublic,bytes32 accessHash,uint256 parentTradeId,uint256 feePaid) metadata,(uint256 remainingOfferAmount,uint256 remainingRequestAmount,uint256 filledOfferAmount,uint256 filledRequestAmount) fillState,(bool partialFillsAllowed,uint16 minPartialFillBps,uint256 minRequestAmount,uint256 maxRequestAmountPerWallet,bool oneFillPerWallet) fillPolicy,uint8 effectiveStatus,uint256 replacementTradeId,uint256 replacesTradeId,uint256 rootTradeId))',
]);
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';

export class RpcStandardOrderFactsReader
  implements StandardOrderFactsReader
{
  readonly #rpc: JsonRpcReader;

  constructor(rpc: JsonRpcReader) {
    this.#rpc = rpc;
  }

  async readStandardOrderFacts(
    escrowContract: Address,
    localId: string,
  ): Promise<StandardOrderFacts> {
    let tradeId: bigint;
    try {
      tradeId = BigInt(localId);
      if (tradeId < 0n) throw new Error('negative-trade-id');
    } catch {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The Standard order identifier cannot be read from chain.',
      );
    }
    try {
      const data = encodeFunctionData({
        abi: STANDARD_GET_TRADE_VIEW_ABI,
        functionName: 'getTradeView',
        args: [tradeId],
      });
      const result = await this.#rpc.request<Hex>('eth_call', [
        { to: escrowContract, data },
        'latest',
      ]);
      const view = decodeFunctionResult({
        abi: STANDARD_GET_TRADE_VIEW_ABI,
        functionName: 'getTradeView',
        data: result,
      });
      if (view.trade.maker.toLowerCase() === ZERO_ADDRESS) {
        throw new SignerError(
          'STALE_STATE',
          'The live Standard order does not have a maker.',
        );
      }
      return {
        maker: view.trade.maker.toLowerCase() as Address,
        recipient:
          view.trade.taker.toLowerCase() === ZERO_ADDRESS
            ? null
            : (view.trade.taker.toLowerCase() as Address),
      };
    } catch (error) {
      if (error instanceof SignerError) throw error;
      throw new SignerError(
        'STALE_STATE',
        'The signer could not verify the live Standard order maker and recipient.',
      );
    }
  }
}

export class ContractRuntimeFeeReader implements RuntimeFeeReader {
  readonly #rpc: JsonRpcReader;
  readonly #actionContracts: Record<string, Address>;
  readonly #editFeeModes: Record<
    string,
    'always' | 'never' | 'contract-flag'
  >;

  constructor(options: {
    rpc: JsonRpcReader;
    actionContracts: Record<string, Address>;
    editFeeModes?: Record<
      string,
      'always' | 'never' | 'contract-flag'
    >;
  }) {
    this.#rpc = options.rpc;
    this.#actionContracts = { ...options.actionContracts };
    this.#editFeeModes = Object.fromEntries(
      Object.entries(options.editFeeModes ?? {}).map(([address, mode]) => [
        address.toLowerCase(),
        mode,
      ]),
    );
  }

  async readFeeState(): Promise<RuntimeFeeState> {
    const entries = await Promise.all(
      Object.entries(this.#actionContracts).map(
        async ([action, contract]) => {
          const [amountResult, recipientResult] = await Promise.all([
            this.#rpc.request<Hex>('eth_call', [
              { to: contract, data: FEE_AMOUNT_SELECTOR },
              'latest',
            ]),
            this.#rpc.request<Hex>('eth_call', [
              { to: contract, data: FEE_RECIPIENT_SELECTOR },
              'latest',
            ]),
          ]);
          const [amount] = decodeAbiParameters(
            [{ type: 'uint256' }],
            amountResult,
          );
          const [recipient] = decodeAbiParameters(
            [{ type: 'address' }],
            recipientResult,
          );
          const mode =
            this.#editFeeModes[contract.toLowerCase()] ?? 'never';
          let editAmount = 0n;
          if (mode === 'always') {
            editAmount = amount;
          } else if (mode === 'contract-flag') {
            const editFlagResult = await this.#rpc.request<Hex>(
              'eth_call',
              [
                {
                  to: contract,
                  data: CHARGE_FEE_ON_EDIT_SELECTOR,
                },
                'latest',
              ],
            );
            const [chargeFee] = decodeAbiParameters(
              [{ type: 'bool' }],
              editFlagResult,
            );
            editAmount = chargeFee ? amount : 0n;
          }
          return [
            action,
            {
              amount: amount.toString(),
              editAmount: editAmount.toString(),
              recipient: recipient.toLowerCase() as Address,
            },
          ] as const;
        },
      ),
    );
    return {
      fees: Object.fromEntries(
        entries.map(([action, fee]) => [action, fee.amount]),
      ),
      editFees: Object.fromEntries(
        entries.map(([action, fee]) => [action, fee.editAmount]),
      ),
      trustedFeeRecipients: Object.fromEntries(
        entries.map(([action, fee]) => [action, fee.recipient]),
      ),
    };
  }
}

export type RuntimeManifestLoader =
  () => Promise<ChainWhisperRuntimeManifestV1>;

export class AuditedRuntimeStateReader implements RuntimeStateReader {
  readonly #loadManifest: RuntimeManifestLoader;
  readonly #rpc: JsonRpcReader;
  readonly #fees: RuntimeFeeReader;

  constructor(options: {
    loadManifest?: RuntimeManifestLoader;
    rpc: JsonRpcReader;
    fees: RuntimeFeeReader;
  }) {
    this.#loadManifest = options.loadManifest ?? loadRuntimeManifest;
    this.#rpc = options.rpc;
    this.#fees = options.fees;
  }

  async readRegistryState(): Promise<RuntimeRegistryState> {
    const manifest = await this.#loadManifest();
    const [audit, feeState] = await Promise.all([
      auditRuntimeManifest(manifest, this.#rpc),
      this.#fees.readFeeState(),
    ]);
    this.#assertAudit(audit);
    const allowedContracts = new Set<string>();
    const allowedSelectors = new Map<string, ReadonlySet<string>>();
    for (const [name, contract] of Object.entries(manifest.contracts)) {
      if (
        name === 'recurringEscrow' &&
        !audit.recurringWritesEnabled
      ) {
        continue;
      }
      const normalizedAddress = contract.address.toLowerCase();
      allowedContracts.add(normalizedAddress);
      allowedSelectors.set(
        normalizedAddress,
        new Set(
          Object.values(contract.selectors).map((selector) =>
            selector.toLowerCase(),
          ),
        ),
      );
    }
    return {
      chainId: manifest.network.chainId,
      registryHash: hashRuntimeManifest(manifest),
      fees: feeState.fees,
      ...(feeState.editFees
        ? { editFees: feeState.editFees }
        : {}),
      trustedFeeRecipients: feeState.trustedFeeRecipients,
      allowedContracts,
      allowedSelectors,
    };
  }

  #assertAudit(audit: RuntimeAuditResult): void {
    if (!audit.registryContractsMatch) {
      throw new SignerError(
        'REGISTRY_CHANGED',
        'The live registry no longer matches the committed runtime manifest.',
      );
    }
    if (!audit.ok) {
      throw new SignerError(
        'REGISTRY_CHANGED',
        'Live contract bytecode or selectors do not match the committed runtime manifest.',
      );
    }
  }
}

export const createRpcRuntimeStateReader = (options: {
  rpcUrl: string;
  fees: RuntimeFeeReader;
}): AuditedRuntimeStateReader =>
  new AuditedRuntimeStateReader({
    rpc: new HttpJsonRpcReader(options.rpcUrl),
    fees: options.fees,
  });
