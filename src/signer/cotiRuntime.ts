import {
  JsonRpcProvider,
  Wallet,
  type TransactionRequest as EthersTransactionRequest,
} from '@coti-io/coti-ethers';
import {
  createPrivateMessagingClient,
  type PrivateMessagingClient,
} from '@coti-io/coti-sdk-private-messaging';
import { formatUnits, keccak256 } from 'viem';

import type {
  Address,
  HexString,
  TransactionReceipt,
  TransactionFeeQuote,
  TransactionRequest,
  TransactionSimulator,
  WalletTransport,
} from './types.js';
import type { LoadedSignerConfig } from './config.js';
import {
  isCotiAesKey,
  normalizeCotiAesKey,
} from './cotiAes.js';
import { SignerError } from './errors.js';

type RpcTransaction = {
  hash?: string;
  from?: string;
  nonce?: string;
};

// The signed gas limit and this fixed per-gas ceiling jointly bound the
// maximum network fee even when an RPC returns hostile fee data.
export const COTI_SIGNER_MAX_FEE_PER_GAS_WEI = 100_000_000_000n;
export const COTI_SIGNER_MAX_TRANSACTION_GAS = 12_000_000n;

const boundTransactionFees = Symbol('chainwhisper.boundTransactionFees');

type BoundTransactionFees =
  | {
      type: 0;
      gasPrice: bigint;
    }
  | {
      type: 2;
      maxFeePerGas: bigint;
      maxPriorityFeePerGas: bigint;
    };

type FeeBoundTransactionRequest = Omit<TransactionRequest, 'nonce'> & {
  [boundTransactionFees]?: BoundTransactionFees;
};

const asHexHash = (value: string): HexString => value as HexString;

const receiptLogs = (
  logs: readonly {
    address: string;
    topics: readonly string[];
    data: string;
  }[],
): NonNullable<TransactionReceipt['logs']> =>
  logs.map((log) => ({
    address: log.address as Address,
    topics: log.topics.map((topic) => topic as HexString),
    data: log.data as HexString,
  }));

const feePolicyError = (message: string): SignerError =>
  new SignerError('FEE_CHANGED', message);

const assertFeeWithinPolicy = (
  value: bigint,
  label: string,
): void => {
  if (
    value < 0n ||
    value > COTI_SIGNER_MAX_FEE_PER_GAS_WEI
  ) {
    throw feePolicyError(
      `${label} is outside the signer fee ceiling.`,
    );
  }
};

const asBigInt = (value: unknown): bigint | null => {
  if (
    typeof value !== 'bigint' &&
    typeof value !== 'number' &&
    typeof value !== 'string'
  ) {
    return null;
  }
  try {
    return BigInt(value);
  } catch {
    return null;
  }
};

const bigintMatches = (
  actual: unknown,
  expected: bigint,
): boolean => {
  return asBigInt(actual) === expected;
};

export const assertCotiSignerTransactionFeePolicy = (
  transaction: EthersTransactionRequest,
): void => {
  const gasLimit = asBigInt(transaction.gasLimit);
  if (
    gasLimit === null ||
    gasLimit <= 0n ||
    gasLimit > COTI_SIGNER_MAX_TRANSACTION_GAS
  ) {
    throw feePolicyError(
      'Transaction gas limit is outside the signer policy ceiling.',
    );
  }
  const gasPrice = asBigInt(transaction.gasPrice);
  const maxFeePerGas = asBigInt(transaction.maxFeePerGas);
  const maxPriorityFeePerGas = asBigInt(
    transaction.maxPriorityFeePerGas,
  );
  if (maxFeePerGas !== null || maxPriorityFeePerGas !== null) {
    if (maxFeePerGas === null || maxPriorityFeePerGas === null) {
      throw feePolicyError(
        'The populated transaction has incomplete EIP-1559 fee fields.',
      );
    }
    assertFeeWithinPolicy(maxFeePerGas, 'Maximum gas fee');
    assertFeeWithinPolicy(
      maxPriorityFeePerGas,
      'Maximum priority gas fee',
    );
    if (maxPriorityFeePerGas > maxFeePerGas || gasPrice !== null) {
      throw feePolicyError(
        'The populated transaction has inconsistent EIP-1559 fee fields.',
      );
    }
    return;
  }
  if (gasPrice === null) {
    throw feePolicyError(
      'The populated transaction is missing a bounded gas price.',
    );
  }
  assertFeeWithinPolicy(gasPrice, 'Gas price');
};

export const maximumNetworkFeeDisplay = (
  gasLimit: bigint,
  maximumFeePerGas = COTI_SIGNER_MAX_FEE_PER_GAS_WEI,
): {
  wei: string;
  coti: string;
} => {
  const wei = gasLimit * maximumFeePerGas;
  return {
    wei: wei.toString(),
    coti: formatUnits(wei, 18),
  };
};

const feeQuote = (
  fees: BoundTransactionFees,
  gasLimit: bigint,
): TransactionFeeQuote => {
  const maximumFeePerGas =
    fees.type === 2 ? fees.maxFeePerGas : fees.gasPrice;
  const maximum = maximumNetworkFeeDisplay(
    gasLimit,
    maximumFeePerGas,
  );
  return {
    model: fees.type === 2 ? 'eip1559' : 'legacy',
    maximumNetworkFeeWei: maximum.wei,
    maximumNetworkFeeCoti: maximum.coti,
    maximumFeePerGasWei: maximumFeePerGas.toString(),
    ...(fees.type === 2
      ? {
          maximumPriorityFeePerGasWei:
            fees.maxPriorityFeePerGas.toString(),
        }
      : {}),
  };
};

export class PolicyBoundCotiWallet extends Wallet {
  override async populateTransaction(
    transaction: EthersTransactionRequest,
  ) {
    const populated = await super.populateTransaction(transaction);
    assertCotiSignerTransactionFeePolicy(populated);
    return populated;
  }
}

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

  async bindTransactionFees(
    request: Omit<TransactionRequest, 'nonce'>,
  ): Promise<BoundTransactionFees> {
    const feeBoundRequest = request as FeeBoundTransactionRequest;
    const existing = feeBoundRequest[boundTransactionFees];
    if (existing) return existing;

    const feeData = await this.provider.getFeeData();
    const hasMaxFee = feeData.maxFeePerGas !== null;
    const hasPriorityFee = feeData.maxPriorityFeePerGas !== null;
    let fees: BoundTransactionFees;
    if (hasMaxFee || hasPriorityFee) {
      if (
        feeData.maxFeePerGas === null ||
        feeData.maxPriorityFeePerGas === null
      ) {
        throw feePolicyError(
          'The RPC returned incomplete EIP-1559 fee data.',
        );
      }
      assertFeeWithinPolicy(feeData.maxFeePerGas, 'Maximum gas fee');
      assertFeeWithinPolicy(
        feeData.maxPriorityFeePerGas,
        'Maximum priority gas fee',
      );
      if (feeData.maxPriorityFeePerGas > feeData.maxFeePerGas) {
        throw feePolicyError(
          'The RPC returned a priority gas fee above the maximum gas fee.',
        );
      }
      fees = {
        type: 2,
        maxFeePerGas: feeData.maxFeePerGas,
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      };
    } else {
      if (feeData.gasPrice === null) {
        throw feePolicyError(
          'The RPC did not return usable transaction fee data.',
        );
      }
      assertFeeWithinPolicy(feeData.gasPrice, 'Gas price');
      fees = {
        type: 0,
        gasPrice: feeData.gasPrice,
      };
    }

    Object.defineProperty(feeBoundRequest, boundTransactionFees, {
      value: fees,
      // The execution paths add the nonce with object spread, so this
      // private binding must follow that exact request into preparation.
      enumerable: true,
      configurable: false,
      writable: false,
    });
    return fees;
  }

  async prepareTransaction(
    request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }> {
    const fees = (request as FeeBoundTransactionRequest)[
      boundTransactionFees
    ];
    if (!fees) {
      throw feePolicyError(
        'Transaction fees were not fixed before confirmation.',
      );
    }
    const populated = await this.wallet.populateTransaction({
      to: request.to,
      data: request.data,
      value: request.value,
      gasLimit: request.gasLimit,
      nonce: request.nonce,
      chainId: await this.getChainId(),
      ...(fees.type === 2
        ? {
            type: 2,
            maxFeePerGas: fees.maxFeePerGas,
            maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
          }
        : {
            type: 0,
            gasPrice: fees.gasPrice,
          }),
    } satisfies EthersTransactionRequest);
    if (
      (fees.type === 2 &&
        (populated.type !== 2 ||
          !bigintMatches(
            populated.maxFeePerGas,
            fees.maxFeePerGas,
          ) ||
          !bigintMatches(
            populated.maxPriorityFeePerGas,
            fees.maxPriorityFeePerGas,
          ) ||
          populated.gasPrice != null)) ||
      (fees.type === 0 &&
        (populated.type !== 0 ||
          !bigintMatches(populated.gasPrice, fees.gasPrice) ||
          populated.maxFeePerGas != null ||
          populated.maxPriorityFeePerGas != null))
    ) {
      throw feePolicyError(
        'Wallet transaction population changed the pre-confirmed fee fields.',
      );
    }
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
      logs: receiptLogs(receipt.logs),
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
      logs: receiptLogs(receipt.logs),
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
  ): Promise<
    | { ok: true; feeQuote: TransactionFeeQuote }
    | { ok: false; errorCode: string }
  > {
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
      const fees =
        await this.#transport.bindTransactionFees(request);
      return {
        ok: true,
        feeQuote: feeQuote(fees, request.gasLimit),
      };
    } catch (error) {
      return {
        ok: false,
        errorCode:
          error instanceof SignerError && error.code === 'FEE_CHANGED'
            ? 'SIMULATION_FEE_POLICY_REJECTED'
            : 'SIMULATION_REVERTED',
      };
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
  const provider = new JsonRpcProvider(config.rpcUrl);
  const wallet = new PolicyBoundCotiWallet(
    secrets.privateKey,
    provider,
  );
  const configuredAesKey =
    aesKeyOverride ??
    config.aesKeyForWallet(wallet.address as Address);
  const aesKey = isCotiAesKey(configuredAesKey)
    ? normalizeCotiAesKey(configuredAesKey)
    : null;
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
