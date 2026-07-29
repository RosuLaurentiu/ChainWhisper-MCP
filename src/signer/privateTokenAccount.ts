import { decryptUint256 } from '@coti-io/coti-sdk-typescript';
import type { Wallet } from '@coti-io/coti-ethers';
import {
  decodeFunctionResult,
  encodeFunctionData,
  parseAbi,
} from 'viem';

import {
  canonicalize,
  isHexAddress,
  sha256Hex,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader,
} from '../shared/index.js';
import { isCotiAesKey, normalizeCotiAesKey } from './cotiAes.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerError } from './errors.js';
import { OperationJournal } from './journal.js';
import { NonceQueue } from './nonceQueue.js';
import type {
  Address,
  HexString,
  TransactionSimulator,
  WalletTransport,
} from './types.js';

const PRIVATE_TOKEN_ABI = parseAbi([
  'function accountEncryptionAddress(address account) view returns (address)',
  'function setAccountEncryptionAddress(address offBoardAddress) returns (bool)',
  'function balanceOf(address account) view returns ((uint256 ciphertextHigh, uint256 ciphertextLow))',
]);
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const SETUP_GAS_CAP = 6_000_000n;

type PrivateToken = {
  symbol: string;
  address: Address;
  decimals: number;
};

export type PrivateTokenSpenderStatus = {
  contract: Address;
  accountEncryptionAddress: Address;
  ready: boolean;
};

export type PrivateTokenAccountStatus = {
  token: Address;
  symbol: string;
  wallet: Address;
  accountEncryptionAddress: Address;
  ready: boolean;
  spenders: Record<string, PrivateTokenSpenderStatus>;
};

export type PrivateTokenAccountSetupResult =
  PrivateTokenAccountStatus & {
    transactionHash: HexString | null;
  };

export class PrivateTokenAccountService {
  readonly #tokens: readonly PrivateToken[];
  readonly #spenders: ReadonlyArray<{
    name: string;
    address: Address;
  }>;
  readonly #rpc: JsonRpcReader;
  readonly #wallet: WalletTransport;
  readonly #cotiWallet: Wallet;
  readonly #confirmation: ConfirmationGate;
  readonly #simulator: TransactionSimulator;
  readonly #nonceQueue: NonceQueue;
  readonly #journal: OperationJournal;
  readonly #assertRuntimeAttested: () => Promise<void>;

  constructor(options: {
    manifest: ChainWhisperRuntimeManifestV1;
    rpc: JsonRpcReader;
    wallet: WalletTransport;
    cotiWallet: Wallet;
    confirmation: ConfirmationGate;
    simulator: TransactionSimulator;
    nonceQueue: NonceQueue;
    journal: OperationJournal;
    assertRuntimeAttested?: () => Promise<void>;
  }) {
    this.#tokens = options.manifest.tokens
      .filter(
        (
          token,
        ): token is (typeof options.manifest.tokens)[number] & {
          address: HexString;
        } => token.kind === 'private-erc20' && Boolean(token.address),
      )
      .map((token) => ({
        symbol: token.symbol,
        address: token.address.toLowerCase() as Address,
        decimals: token.decimals,
      }));
    this.#spenders = [
      'standardEscrow',
      'privateEscrow',
      'directEscrow',
      'recurringEscrow',
    ].flatMap((name) => {
      const contract = options.manifest.contracts[name];
      return contract
        ? [
            {
              name,
              address: contract.address.toLowerCase() as Address,
            },
          ]
        : [];
    });
    this.#rpc = options.rpc;
    this.#wallet = options.wallet;
    this.#cotiWallet = options.cotiWallet;
    this.#confirmation = options.confirmation;
    this.#simulator = options.simulator;
    this.#nonceQueue = options.nonceQueue;
    this.#journal = options.journal;
    this.#assertRuntimeAttested =
      options.assertRuntimeAttested ?? (async () => undefined);
  }

  #token(reference: string): PrivateToken {
    const requested = reference.trim().toLowerCase();
    const token = this.#tokens.find(
      (candidate) =>
        candidate.symbol.toLowerCase() === requested ||
        candidate.address.toLowerCase() === requested,
    );
    if (!token) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'Only a verified private token from the signed runtime manifest can be configured.',
      );
    }
    return token;
  }

  async #ethCall(
    to: Address,
    data: HexString,
    from?: Address,
  ): Promise<HexString> {
    return this.#rpc.request<HexString>('eth_call', [
      {
        to,
        data,
        ...(from ? { from } : {}),
      },
      'latest',
    ]);
  }

  async #accountEncryptionAddress(
    token: Address,
    account: Address,
  ): Promise<Address> {
    const data = encodeFunctionData({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'accountEncryptionAddress',
      args: [account],
    });
    const result = await this.#ethCall(token, data);
    const address = decodeFunctionResult({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'accountEncryptionAddress',
      data: result,
    });
    if (!isHexAddress(address)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The private token returned an invalid account encryption address.',
      );
    }
    return address.toLowerCase() as Address;
  }

  async status(reference: string): Promise<PrivateTokenAccountStatus> {
    const token = this.#token(reference);
    const wallet = await this.#wallet.getAddress();
    const [accountEncryptionAddress, spenderEntries] = await Promise.all([
      this.#accountEncryptionAddress(token.address, wallet),
      Promise.all(
        this.#spenders.map(async (spender) => {
          const encryptionAddress =
            await this.#accountEncryptionAddress(
              token.address,
              spender.address,
            );
          return [
            spender.name,
            {
              contract: spender.address,
              accountEncryptionAddress: encryptionAddress,
              ready: encryptionAddress !== ZERO_ADDRESS,
            },
          ] as const;
        }),
      ),
    ]);
    return {
      token: token.address,
      symbol: token.symbol,
      wallet,
      accountEncryptionAddress,
      ready:
        accountEncryptionAddress.toLowerCase() === wallet.toLowerCase(),
      spenders: Object.fromEntries(spenderEntries),
    };
  }

  async enable(reference: string): Promise<PrivateTokenAccountSetupResult> {
    const current = await this.status(reference);
    if (current.ready) {
      return { ...current, transactionHash: null };
    }
    await this.#assertRuntimeAttested();
    const aesKey = this.#cotiWallet.getUserOnboardInfo()?.aesKey;
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'COTI privacy onboarding is required before enabling a private token.',
      );
    }
    const data = encodeFunctionData({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'setAccountEncryptionAddress',
      args: [current.wallet],
    });
    const operationHash = sha256Hex(
      canonicalize({
        domain: 'chainwhisper/private-token-account/1',
        chainId: 2_632_500,
        wallet: current.wallet,
        token: current.token,
        data,
      }),
    );
    const operationId = `private-token-${current.token.slice(2, 18)}`;
    let record = await this.#journal.begin(operationId, operationHash);
    if (
      record.operationHash.toLowerCase() !== operationHash.toLowerCase()
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'The private-token setup id is already bound to different calldata.',
      );
    }
    if (record.stage === 'completed') {
      const refreshed = await this.status(reference);
      if (refreshed.ready) {
        return {
          ...refreshed,
          transactionHash: record.transactionHashes.at(-1) ?? null,
        };
      }
      record =
        (await this.#journal.updateStage(
          operationId,
          'validated',
          0,
        )) ?? record;
    }
    for (const transactionHash of record.transactionHashes) {
      let receipt;
      try {
        receipt =
          await this.#wallet.getTransactionReceipt(transactionHash);
      } catch {
        return {
          ...current,
          transactionHash,
        };
      }
      if (receipt?.status === 'success') {
        await this.#journal.recordReceipt(operationId, receipt);
        const refreshed = await this.status(reference);
        if (refreshed.ready) {
          await this.#journal.updateStage(operationId, 'completed', 1);
          return { ...refreshed, transactionHash };
        }
        record =
          (await this.#journal.updateStage(
            operationId,
            'validated',
            0,
          )) ?? record;
        await this.#journal.recordError(
          operationId,
          'PRIVATE_TOKEN_SETUP_NOT_READY',
          true,
        );
        continue;
      }
      if (receipt?.status === 'reverted') {
        await this.#journal.recordReceipt(operationId, receipt);
        await this.#journal.recordError(
          operationId,
          'TRANSACTION_REVERTED',
          true,
        );
        continue;
      }
      if (receipt?.status === 'pending') {
        await this.#journal.recordReceipt(operationId, receipt);
      }
      return {
        ...current,
        transactionHash,
      };
    }
    if (
      record.transactionHashes.length === 0 &&
      record.nonces.length > 0
    ) {
      // This service never broadcasts before recordPreparedTransaction
      // persists a hash. A nonce-only record is therefore safe to retry,
      // while a different wallet transaction with that nonce is not proof
      // that this setup call was sent.
      record =
        (await this.#journal.updateStage(
          operationId,
          'validated',
          0,
        )) ?? record;
    }
    const request = {
      to: current.token,
      data,
      value: 0n,
      gasLimit: SETUP_GAS_CAP,
    };
    const simulation = await this.#simulator.simulate(
      request,
      current.wallet,
    );
    if (!simulation.ok) {
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The private-token account setup simulation reverted.',
      );
    }
    await this.#journal.updateStage(
      operationId,
      'awaiting-confirmation',
      0,
    );
    await this.#confirmation.confirm({
      operationId,
      operationHash,
      stepId: 'enable-private-token',
      stepIndex: 0,
      stepCount: 1,
      wallet: current.wallet,
      contract: current.token,
      action: 'enable_private_token',
      assets: [current.symbol],
      amounts: [],
      details: simulation.feeQuote
        ? [
            {
              label: 'Maximum network fee',
              value: `${simulation.feeQuote.maximumNetworkFeeCoti} COTI (${simulation.feeQuote.maximumNetworkFeeWei} wei)`,
            },
          ]
        : undefined,
      counterparty: null,
      fee: 'Network gas only',
      nativeValue: '0',
      gasCap: SETUP_GAS_CAP.toString(),
      expectedResult:
        'Set this private token account encryption address to the configured wallet.',
      summary: `Enable private ${current.symbol} balance and allowance access for this wallet.`,
    });
    const confirmedSimulation = await this.#simulator.simulate(
      request,
      current.wallet,
    );
    if (!confirmedSimulation.ok) {
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The confirmed private-token account setup simulation reverted.',
      );
    }
    const broadcast = await this.#nonceQueue.runTransaction(
      async (nonce) => {
        const prepared = await this.#wallet.prepareTransaction({
          ...request,
          nonce,
        });
        await this.#journal.recordPreparedTransaction(
          operationId,
          nonce,
          prepared.hash,
          0,
        );
        let observed = true;
        try {
          const sent = await this.#wallet.broadcastTransaction(
            prepared.signedTransaction,
          );
          if (
            sent.hash.toLowerCase() !== prepared.hash.toLowerCase()
          ) {
            throw new SignerError(
              'TRANSACTION_FAILED',
              'The private-token setup broadcast hash changed unexpectedly.',
            );
          }
        } catch {
          try {
            observed = Boolean(
              await this.#wallet.getTransaction(prepared.hash),
            );
          } catch {
            observed = false;
          }
        }
        return { hash: prepared.hash, observed };
      },
    );
    record =
      (await this.#journal.recordBroadcast(
        operationId,
        broadcast.nonce,
        broadcast.result.hash,
        0,
      )) ?? record;
    if (!broadcast.result.observed) {
      return {
        ...current,
        transactionHash: broadcast.result.hash,
      };
    }
    let receipt;
    try {
      receipt = await this.#wallet.waitForTransaction(
        broadcast.result.hash,
      );
    } catch {
      return {
        ...current,
        transactionHash: broadcast.result.hash,
      };
    }
    await this.#journal.recordReceipt(operationId, receipt);
    if (receipt.status === 'pending') {
      return {
        ...current,
        transactionHash: broadcast.result.hash,
      };
    }
    if (receipt.status !== 'success') {
      await this.#journal.recordError(
        operationId,
        'TRANSACTION_REVERTED',
        true,
      );
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The private-token account setup transaction reverted.',
      );
    }
    const refreshed = await this.status(reference);
    if (!refreshed.ready) {
      await this.#journal.updateStage(operationId, 'validated', 0);
      await this.#journal.recordError(
        operationId,
        'PRIVATE_TOKEN_SETUP_NOT_READY',
        true,
      );
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The private token did not retain the wallet encryption address.',
      );
    }
    await this.#journal.updateStage(operationId, 'completed', 1);
    return {
      ...refreshed,
      transactionHash: broadcast.result.hash,
    };
  }

  async assertSpendReady(input: {
    token: Address;
    spender: Address;
    amount: string;
  }): Promise<void> {
    const token = this.#token(input.token);
    if (!/^(?:0|[1-9][0-9]*)$/u.test(input.amount)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The exact private-token spend amount is invalid.',
      );
    }
    const amount = BigInt(input.amount);
    const wallet = await this.#wallet.getAddress();
    const aesKey = this.#cotiWallet.getUserOnboardInfo()?.aesKey;
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'Run chainwhisper_onboard_privacy before a private-token transaction.',
      );
    }
    const [ownerEncryptionAddress, spenderEncryptionAddress] =
      await Promise.all([
        this.#accountEncryptionAddress(token.address, wallet),
        this.#accountEncryptionAddress(token.address, input.spender),
      ]);
    if (
      ownerEncryptionAddress.toLowerCase() !== wallet.toLowerCase()
    ) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        `Run chainwhisper_enable_private_token for ${token.symbol} before approving it.`,
      );
    }
    if (spenderEncryptionAddress === ZERO_ADDRESS) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        `The ${token.symbol} contract has not configured this escrow for private allowances. No approval was broadcast.`,
      );
    }
    const data = encodeFunctionData({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'balanceOf',
      args: [wallet],
    });
    const raw = await this.#ethCall(token.address, data, wallet);
    const encrypted = decodeFunctionResult({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'balanceOf',
      data: raw,
    });
    let balance: bigint;
    try {
      balance = decryptUint256(
        {
          ciphertextHigh: BigInt(encrypted.ciphertextHigh),
          ciphertextLow: BigInt(encrypted.ciphertextLow),
        },
        normalizeCotiAesKey(aesKey),
      );
    } catch {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        `The signer could not decrypt the private ${token.symbol} balance with this wallet's onboarded privacy key.`,
      );
    }
    if (balance < amount) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        `The private ${token.symbol} balance is below the exact requested spend.`,
      );
    }
  }
}
