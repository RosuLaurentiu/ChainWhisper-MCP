import {
  JsonRpcProvider,
  Wallet,
  type TransactionRequest as EthersTransactionRequest,
} from '@coti-io/coti-ethers';
import {
  createPrivateMessagingClient,
  type PrivateMessagingClient,
} from '@coti-io/coti-sdk-private-messaging';
import { keccak256 } from 'viem';

import type {
  Address,
  HexString,
  TransactionReceipt,
  TransactionRequest,
  TransactionSimulator,
  WalletTransport,
} from './types.js';
import type { LoadedSignerConfig } from './config.js';
import {
  isCotiAesKey,
  normalizeCotiAesKey,
} from './cotiAes.js';

type RpcTransaction = {
  hash?: string;
  from?: string;
  nonce?: string;
};

const asHexHash = (value: string): HexString => value as HexString;

const normalizedRpcTransaction = (
  value: RpcTransaction | null | undefined,
): { hash: HexString; nonce: number } | null => {
  if (
    !value?.hash ||
    !/^0x[0-9a-fA-F]{64}$/u.test(value.hash) ||
    typeof value.nonce !== 'string'
  ) {
    return null;
  }
  const nonce = Number.parseInt(value.nonce, 16);
  return Number.isSafeInteger(nonce)
    ? { hash: asHexHash(value.hash), nonce }
    : null;
};

export class CotiWalletTransport implements WalletTransport {
  readonly wallet: Wallet;
  readonly provider: JsonRpcProvider;
  readonly #receiptTimeoutMs: number;

  constructor(options: {
    wallet: Wallet;
    provider: JsonRpcProvider;
    receiptTimeoutMs?: number;
  }) {
    this.wallet = options.wallet;
    this.provider = options.provider;
    this.#receiptTimeoutMs = options.receiptTimeoutMs ?? 120_000;
  }

  async getAddress(): Promise<Address> {
    return (await this.wallet.getAddress()).toLowerCase() as Address;
  }

  async getChainId(): Promise<number> {
    return Number((await this.provider.getNetwork()).chainId);
  }

  async getPendingNonce(): Promise<number> {
    return this.provider.getTransactionCount(
      await this.getAddress(),
      'pending',
    );
  }

  async prepareTransaction(
    request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }> {
    const populated = await this.wallet.populateTransaction({
      to: request.to,
      data: request.data,
      value: request.value,
      gasLimit: request.gasLimit,
      nonce: request.nonce,
      chainId: await this.getChainId(),
    } satisfies EthersTransactionRequest);
    const signedTransaction = (await this.wallet.signTransaction(
      populated,
    )) as HexString;
    return {
      signedTransaction,
      hash: keccak256(signedTransaction),
    };
  }

  async broadcastTransaction(
    signedTransaction: HexString,
  ): Promise<{ hash: HexString }> {
    const response = await this.provider.broadcastTransaction(
      signedTransaction,
    );
    return { hash: asHexHash(response.hash) };
  }

  async getTransaction(
    hash: HexString,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    const transaction = await this.provider.getTransaction(hash);
    return transaction
      ? { hash: asHexHash(transaction.hash), nonce: transaction.nonce }
      : null;
  }

  async findTransactionByNonce(
    nonce: number,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    const address = (await this.getAddress()).toLowerCase();
    const pending = await this.#readRpcBlock('pending');
    const pendingMatch = pending.find(
      (transaction) =>
        transaction.from?.toLowerCase() === address &&
        Number.parseInt(transaction.nonce ?? '', 16) === nonce,
    );
    const normalizedPending = normalizedRpcTransaction(pendingMatch);
    if (normalizedPending) return normalizedPending;

    const latest = await this.provider.getBlockNumber();
    const oldest = Math.max(0, latest - 128);
    for (let block = latest; block >= oldest; block -= 1) {
      const transactions = await this.#readRpcBlock(
        `0x${block.toString(16)}`,
      );
      const match = transactions.find(
        (transaction) =>
          transaction.from?.toLowerCase() === address &&
          Number.parseInt(transaction.nonce ?? '', 16) === nonce,
      );
      const normalized = normalizedRpcTransaction(match);
      if (normalized) return normalized;
    }
    return null;
  }

  async #readRpcBlock(tag: string): Promise<RpcTransaction[]> {
    try {
      const block = (await this.provider.send('eth_getBlockByNumber', [
        tag,
        true,
      ])) as { transactions?: RpcTransaction[] } | null;
      return Array.isArray(block?.transactions) ? block.transactions : [];
    } catch {
      return [];
    }
  }

  async getTransactionReceipt(
    hash: HexString,
  ): Promise<TransactionReceipt | null> {
    const receipt = await this.provider.getTransactionReceipt(hash);
    if (!receipt) return null;
    return {
      transactionHash: asHexHash(receipt.hash),
      status: receipt.status === 1 ? 'success' : 'reverted',
      blockNumber: receipt.blockNumber,
    };
  }

  async waitForTransaction(hash: HexString): Promise<TransactionReceipt> {
    const receipt = await this.provider.waitForTransaction(
      hash,
      1,
      this.#receiptTimeoutMs,
    );
    if (!receipt) {
      return { transactionHash: hash, status: 'pending' };
    }
    return {
      transactionHash: asHexHash(receipt.hash),
      status: receipt.status === 1 ? 'success' : 'reverted',
      blockNumber: receipt.blockNumber,
    };
  }
}

export class CotiTransactionSimulator implements TransactionSimulator {
  readonly #transport: CotiWalletTransport;

  constructor(transport: CotiWalletTransport) {
    this.#transport = transport;
  }

  async simulate(
    request: Omit<TransactionRequest, 'nonce'>,
    wallet: Address,
  ): Promise<{ ok: true } | { ok: false; errorCode: string }> {
    try {
      const estimatedGas =
        await this.#transport.provider.estimateGas({
          from: wallet,
          to: request.to,
          data: request.data,
          value: request.value,
          gasLimit: request.gasLimit,
        });
      if (estimatedGas > request.gasLimit) {
        return {
          ok: false,
          errorCode: 'SIMULATION_GAS_CAP_EXCEEDED',
        };
      }
      return { ok: true };
    } catch {
      return { ok: false, errorCode: 'SIMULATION_REVERTED' };
    }
  }
}

export type CotiSignerRuntime = {
  provider: JsonRpcProvider;
  wallet: Wallet;
  transport: CotiWalletTransport;
  simulator: CotiTransactionSimulator;
  messagingClient: PrivateMessagingClient;
};

export const createCotiSignerRuntime = (
  config: LoadedSignerConfig,
  aesKeyOverride?: string,
): CotiSignerRuntime => {
  const secrets = config.credentialMaterial();
  const configuredAesKey = aesKeyOverride ?? secrets.aesKey;
  const aesKey = isCotiAesKey(configuredAesKey)
    ? normalizeCotiAesKey(configuredAesKey)
    : null;
  const provider = new JsonRpcProvider(config.rpcUrl);
  const wallet = new Wallet(secrets.privateKey, provider);
  wallet.disableAutoOnboard();
  if (aesKey) wallet.setAesKey(aesKey);
  const transport = new CotiWalletTransport({ wallet, provider });
  return {
    provider,
    wallet,
    transport,
    simulator: new CotiTransactionSimulator(transport),
    messagingClient: createPrivateMessagingClient({
      network: 'mainnet',
      runner: wallet,
      ...(aesKey ? { aesKey } : {}),
    }),
  };
};
