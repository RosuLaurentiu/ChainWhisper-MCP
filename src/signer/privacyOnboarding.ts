import {
  Transaction,
  getAccountOnboardContract,
  hexlify,
  keccak256,
  recoverAddress,
  type TransactionReceipt,
  type TransactionRequest,
  type Wallet,
} from '@coti-io/coti-ethers';
import {
  generateRSAKeyPair,
  recoverUserKey,
  sign,
} from '@coti-io/coti-sdk-typescript';

import { sha256Hex } from '../shared/index.js';
import {
  isCotiAesKey,
  normalizeCotiAesKey,
} from './cotiAes.js';
import { ConfirmationGate } from './confirmation.js';
import {
  assertCotiSignerTransactionFeePolicy,
  maximumNetworkFeeDisplay,
} from './cotiRuntime.js';
import { SignerError } from './errors.js';
import { NonceQueue } from './nonceQueue.js';
import type { Address, HexString } from './types.js';
import { EncryptedSecretVault } from './vault.js';

const ACCOUNT_ONBOARD_CONTRACT =
  '0x536A67f0cc46513E7d27a370ed1aF9FDcC7A5095' as Address;
const ACCOUNT_ONBOARD_GAS_LIMIT = 12_000_000n;
const COTI_MAINNET_CHAIN_ID = 2_632_500n;
const ONBOARD_RECOVERY_REFERENCE = 'signer/onboard-recovery';
const ONBOARD_RECEIPT_TIMEOUT_MS = 120_000;
const MAX_RECOVERY_RECORD_LENGTH = 128 * 1024;
const MAX_SIGNED_TRANSACTION_LENGTH = 64 * 1024;
const MAXIMUM_NETWORK_FEE = maximumNetworkFeeDisplay(
  ACCOUNT_ONBOARD_GAS_LIMIT,
);
const ONBOARD_FUNCTION = getAccountOnboardContract(
  ACCOUNT_ONBOARD_CONTRACT,
).interface.getFunction('onboardAccount');
const ONBOARD_SELECTOR = ONBOARD_FUNCTION?.selector.toLowerCase();

if (!ONBOARD_SELECTOR) {
  throw new Error('The COTI onboarding ABI is missing onboardAccount.');
}

type RsaKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

type PrivacyOnboardingRecoveryV1 = {
  version: 1;
  wallet: Address;
  contract: Address;
  operationHash: HexString;
  rsaPublicKey: string;
  rsaPrivateKey: string;
  nonce?: number;
  txHash?: HexString;
  signedTransaction?: HexString;
  revertedTransactionHashes?: HexString[];
};

export type PrivacyOnboardingResult = {
  status: 'ready';
  wallet: Address;
  transactionHash: HexString | null;
  persistedInEncryptedVault: true;
  messagingRestartRecommended: boolean;
};

const isHexHash = (value: unknown): value is HexString =>
  typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/u.test(value);

const isSignedTransaction = (value: unknown): value is HexString =>
  typeof value === 'string' &&
  value.length <= MAX_SIGNED_TRANSACTION_LENGTH &&
  /^0x(?:[0-9a-fA-F]{2})+$/u.test(value);

const parseRevertedTransactionHashes = (
  value: unknown,
): HexString[] => {
  if (value === undefined) return [];
  if (
    !Array.isArray(value) ||
    value.length > 16 ||
    value.some((entry) => !isHexHash(entry))
  ) {
    throw recoveryError(
      'the reverted transaction history is malformed.',
    );
  }
  const unique = new Map<string, HexString>();
  for (const entry of value as HexString[]) {
    unique.set(entry.toLowerCase(), entry);
  }
  return [...unique.values()];
};

const operationHashFor = (wallet: Address): HexString =>
  sha256Hex(`chainwhisper/privacy-onboard/v1:${wallet}`);

const processingError = (): SignerError =>
  new SignerError(
    'OPERATION_IN_PROGRESS',
    'COTI privacy onboarding has a durable pending transaction. Retry this onboarding command to reconcile the same transaction; no replacement transaction will be created.',
  );

const recoveryError = (message: string): SignerError =>
  new SignerError(
    'PRIVATE_INPUT_UNAVAILABLE',
    `The encrypted COTI onboarding recovery record is invalid: ${message}`,
  );

const decodeRsaKey = (value: unknown, name: string): Uint8Array => {
  if (
    typeof value !== 'string' ||
    value.length < 4 ||
    value.length > 16 * 1024 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)
  ) {
    throw recoveryError(`${name} is not canonical base64.`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (
    decoded.length < 128 ||
    decoded.length > 8 * 1024 ||
    decoded.toString('base64') !== value
  ) {
    throw recoveryError(`${name} has an unsupported size or encoding.`);
  }
  return new Uint8Array(decoded);
};

const rsaKeysFromRecovery = (
  recovery: PrivacyOnboardingRecoveryV1,
): RsaKeyPair => ({
  publicKey: decodeRsaKey(recovery.rsaPublicKey, 'RSA public key'),
  privateKey: decodeRsaKey(recovery.rsaPrivateKey, 'RSA private key'),
});

const assertPreparedTransaction = (
  recovery: PrivacyOnboardingRecoveryV1,
): void => {
  const fields = [
    recovery.nonce !== undefined,
    recovery.txHash !== undefined,
    recovery.signedTransaction !== undefined,
  ];
  if (fields.every((present) => !present)) return;
  if (
    !fields.every(Boolean) ||
    !Number.isSafeInteger(recovery.nonce) ||
    recovery.nonce! < 0 ||
    !isHexHash(recovery.txHash) ||
    !isSignedTransaction(recovery.signedTransaction)
  ) {
    throw recoveryError(
      'the prepared transaction fields are incomplete or malformed.',
    );
  }
  if (
    keccak256(recovery.signedTransaction).toLowerCase() !==
    recovery.txHash.toLowerCase()
  ) {
    throw recoveryError(
      'the prepared transaction hash does not match its signed bytes.',
    );
  }
  let transaction: Transaction;
  try {
    transaction = Transaction.from(recovery.signedTransaction);
  } catch {
    throw recoveryError('the signed transaction cannot be decoded.');
  }
  if (
    transaction.from?.toLowerCase() !== recovery.wallet ||
    transaction.to?.toLowerCase() !== recovery.contract ||
    transaction.nonce !== recovery.nonce ||
    transaction.chainId !== COTI_MAINNET_CHAIN_ID ||
    transaction.value !== 0n ||
    transaction.gasLimit !== ACCOUNT_ONBOARD_GAS_LIMIT ||
    transaction.data.slice(0, 10).toLowerCase() !== ONBOARD_SELECTOR
  ) {
    throw recoveryError(
      'the signed transaction is not the confirmed COTI onboarding call.',
    );
  }
  const onboardingInterface = getAccountOnboardContract(
    ACCOUNT_ONBOARD_CONTRACT,
  ).interface;
  let publicKey: string;
  let signedEncryptionKey: string;
  try {
    const decoded = onboardingInterface.decodeFunctionData(
      'onboardAccount',
      transaction.data,
    );
    publicKey = hexlify(decoded[0]);
    signedEncryptionKey = hexlify(decoded[1]);
    const canonicalData = onboardingInterface.encodeFunctionData(
      'onboardAccount',
      [publicKey, signedEncryptionKey],
    );
    if (canonicalData.toLowerCase() !== transaction.data.toLowerCase()) {
      throw new Error('non-canonical onboarding calldata');
    }
  } catch {
    throw recoveryError(
      'the signed transaction calldata is not a canonical onboarding call.',
    );
  }
  const persistedPublicKey = hexlify(
    rsaKeysFromRecovery(recovery).publicKey,
  );
  if (publicKey.toLowerCase() !== persistedPublicKey.toLowerCase()) {
    throw recoveryError(
      'the signed transaction public key does not match the persisted RSA recovery key.',
    );
  }
  let signingWallet: string;
  try {
    signingWallet = recoverAddress(
      keccak256(publicKey),
      signedEncryptionKey,
    ).toLowerCase();
  } catch {
    throw recoveryError(
      'the onboarding encryption-key signature is invalid.',
    );
  }
  if (signingWallet !== recovery.wallet) {
    throw recoveryError(
      'the onboarding encryption-key signature is for a different wallet.',
    );
  }
  assertCotiSignerTransactionFeePolicy({
    gasLimit: transaction.gasLimit,
    gasPrice: transaction.gasPrice,
    maxFeePerGas: transaction.maxFeePerGas,
    maxPriorityFeePerGas: transaction.maxPriorityFeePerGas,
  });
};

const parseRecovery = (
  encoded: string,
  wallet: Address,
): PrivacyOnboardingRecoveryV1 => {
  if (encoded.length > MAX_RECOVERY_RECORD_LENGTH) {
    throw recoveryError('the record exceeds the supported size.');
  }
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw recoveryError('the record is not valid JSON.');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw recoveryError('the record root is not an object.');
  }
  const candidate = value as Record<string, unknown>;
  const legacy = candidate.version === undefined;
  if (
    (!legacy && candidate.version !== 1) ||
    (!legacy &&
      (candidate.wallet !== wallet ||
        candidate.contract?.toString().toLowerCase() !==
          ACCOUNT_ONBOARD_CONTRACT.toLowerCase() ||
        candidate.operationHash !== operationHashFor(wallet)))
  ) {
    throw recoveryError(
      'the record is for a different wallet, contract, or operation.',
    );
  }
  const recovery: PrivacyOnboardingRecoveryV1 = {
    version: 1,
    wallet,
    contract: ACCOUNT_ONBOARD_CONTRACT.toLowerCase() as Address,
    operationHash: operationHashFor(wallet),
    rsaPublicKey:
      typeof candidate.rsaPublicKey === 'string'
        ? candidate.rsaPublicKey
        : '',
    rsaPrivateKey:
      typeof candidate.rsaPrivateKey === 'string'
        ? candidate.rsaPrivateKey
        : '',
    ...(candidate.nonce === undefined
      ? {}
      : { nonce: candidate.nonce as number }),
    ...(candidate.txHash === undefined
      ? {}
      : { txHash: candidate.txHash as HexString }),
    ...(candidate.signedTransaction === undefined
      ? {}
      : {
          signedTransaction: candidate.signedTransaction as HexString,
        }),
    ...(candidate.revertedTransactionHashes === undefined
      ? {}
      : {
          revertedTransactionHashes:
            parseRevertedTransactionHashes(
              candidate.revertedTransactionHashes,
            ),
        }),
  };
  rsaKeysFromRecovery(recovery);
  if (legacy) {
    if (
      candidate.nonce !== undefined ||
      candidate.signedTransaction !== undefined ||
      !isHexHash(candidate.txHash)
    ) {
      throw recoveryError('the legacy recovery record is malformed.');
    }
    recovery.txHash = candidate.txHash;
  } else {
    assertPreparedTransaction(recovery);
  }
  return recovery;
};

const serializeRecovery = (
  recovery: PrivacyOnboardingRecoveryV1,
): string => JSON.stringify(recovery);

const readyResult = (
  wallet: Address,
  transactionHash: HexString | null,
): PrivacyOnboardingResult => ({
  status: 'ready',
  wallet,
  transactionHash,
  persistedInEncryptedVault: true,
  messagingRestartRecommended: false,
});

export class PrivacyOnboardingService {
  readonly #wallet: Wallet;
  readonly #vault: EncryptedSecretVault;
  readonly #confirmation: ConfirmationGate;
  readonly #nonceQueue: NonceQueue;

  constructor(options: {
    wallet: Wallet;
    vault: EncryptedSecretVault;
    confirmation: ConfirmationGate;
    nonceQueue: NonceQueue;
  }) {
    this.#wallet = options.wallet;
    this.#vault = options.vault;
    this.#confirmation = options.confirmation;
    this.#nonceQueue = options.nonceQueue;
  }

  async isReady(): Promise<boolean> {
    const persisted = await this.#vault.get('signer/aes-key');
    const inMemory = this.#wallet.getUserOnboardInfo()?.aesKey;
    return isCotiAesKey(persisted) || isCotiAesKey(inMemory);
  }

  async #persistAesKey(
    wallet: Address,
    value: string,
  ): Promise<string> {
    const normalized = normalizeCotiAesKey(value);
    await this.#vault.put('signer/aes-key', normalized, {
      kind: 'generic',
      binding: { operationHash: operationHashFor(wallet) },
    });
    this.#wallet.setAesKey(normalized);
    return normalized;
  }

  async #adoptReadyKey(
    wallet: Address,
  ): Promise<PrivacyOnboardingResult | null> {
    const persisted = await this.#vault.get('signer/aes-key');
    if (isCotiAesKey(persisted)) {
      this.#wallet.setAesKey(normalizeCotiAesKey(persisted));
      return readyResult(wallet, null);
    }
    const configured = this.#wallet.getUserOnboardInfo()?.aesKey;
    if (isCotiAesKey(configured)) {
      await this.#persistAesKey(wallet, configured);
      return readyResult(wallet, null);
    }
    return null;
  }

  async #loadRecovery(
    wallet: Address,
  ): Promise<PrivacyOnboardingRecoveryV1 | null> {
    const encoded = await this.#vault.get(ONBOARD_RECOVERY_REFERENCE);
    return encoded ? parseRecovery(encoded, wallet) : null;
  }

  async #persistRecovery(
    recovery: PrivacyOnboardingRecoveryV1,
  ): Promise<void> {
    await this.#vault.put(
      ONBOARD_RECOVERY_REFERENCE,
      serializeRecovery(recovery),
      {
        kind: 'recovery-note',
        binding: { operationHash: recovery.operationHash },
      },
    );
  }

  #newRecovery(wallet: Address): PrivacyOnboardingRecoveryV1 {
    const rsaKey = generateRSAKeyPair();
    return {
      version: 1,
      wallet,
      contract: ACCOUNT_ONBOARD_CONTRACT.toLowerCase() as Address,
      operationHash: operationHashFor(wallet),
      rsaPublicKey: Buffer.from(rsaKey.publicKey).toString('base64'),
      rsaPrivateKey: Buffer.from(rsaKey.privateKey).toString('base64'),
    };
  }

  async #prepareTransaction(
    recovery: PrivacyOnboardingRecoveryV1,
    nonce: number,
  ): Promise<PrivacyOnboardingRecoveryV1> {
    const provider = this.#wallet.provider;
    if (!provider) {
      throw new SignerError(
        'WRITE_UNAVAILABLE',
        'COTI privacy onboarding requires a connected RPC provider.',
      );
    }
    const network = await provider.getNetwork();
    if (network.chainId !== COTI_MAINNET_CHAIN_ID) {
      throw new SignerError(
        'WALLET_MISMATCH',
        'COTI privacy onboarding is only enabled for the configured COTI Mainnet chain.',
      );
    }
    const rsaKey = rsaKeysFromRecovery(recovery);
    const signedEncryptionKey = sign(
      keccak256(rsaKey.publicKey),
      this.#wallet.privateKey,
    );
    const contract = getAccountOnboardContract(
      ACCOUNT_ONBOARD_CONTRACT,
    );
    const request = await contract
      .getFunction('onboardAccount')
      .populateTransaction(rsaKey.publicKey, signedEncryptionKey, {
        gasLimit: ACCOUNT_ONBOARD_GAS_LIMIT,
      });
    const populated = await this.#wallet.populateTransaction({
      ...request,
      to: ACCOUNT_ONBOARD_CONTRACT,
      value: 0n,
      gasLimit: ACCOUNT_ONBOARD_GAS_LIMIT,
      nonce,
      chainId: network.chainId,
    } satisfies TransactionRequest);
    assertCotiSignerTransactionFeePolicy(populated);
    const signedTransaction = (await this.#wallet.signTransaction(
      populated,
    )) as HexString;
    const prepared: PrivacyOnboardingRecoveryV1 = {
      ...recovery,
      nonce,
      txHash: keccak256(signedTransaction) as HexString,
      signedTransaction,
    };
    assertPreparedTransaction(prepared);
    await this.#persistRecovery(prepared);
    return prepared;
  }

  async #readReceipt(
    transactionHash: HexString,
  ): Promise<TransactionReceipt | null> {
    const provider = this.#wallet.provider;
    if (!provider) {
      throw new SignerError(
        'WRITE_UNAVAILABLE',
        'COTI privacy onboarding requires a connected RPC provider.',
      );
    }
    try {
      return await provider.getTransactionReceipt(transactionHash);
    } catch {
      throw processingError();
    }
  }

  async #recoverAesKey(
    recovery: PrivacyOnboardingRecoveryV1,
    receipt: TransactionReceipt,
  ): Promise<string> {
    if (
      !recovery.txHash ||
      receipt.hash.toLowerCase() !== recovery.txHash.toLowerCase()
    ) {
      throw recoveryError(
        'the receipt does not match the persisted onboarding transaction.',
      );
    }
    if (receipt.status !== 1) {
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The COTI privacy onboarding transaction reverted.',
      );
    }
    const contract = getAccountOnboardContract(
      ACCOUNT_ONBOARD_CONTRACT,
    );
    let encryptedShareOne: string | null = null;
    let encryptedShareTwo: string | null = null;
    for (const log of receipt.logs) {
      if (
        log.address.toLowerCase() !==
        ACCOUNT_ONBOARD_CONTRACT.toLowerCase()
      ) {
        continue;
      }
      try {
        const decoded = contract.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (
          decoded?.name !== 'AccountOnboarded' ||
          String(decoded.args[0]).toLowerCase() !== recovery.wallet
        ) {
          continue;
        }
        const first = String(decoded.args[1]);
        const second = String(decoded.args[2]);
        if (
          /^0x(?:[0-9a-fA-F]{2})+$/u.test(first) &&
          /^0x(?:[0-9a-fA-F]{2})+$/u.test(second)
        ) {
          encryptedShareOne = first.slice(2);
          encryptedShareTwo = second.slice(2);
          break;
        }
      } catch {
        // Ignore unrelated logs from the onboarding transaction.
      }
    }
    if (!encryptedShareOne || !encryptedShareTwo) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The confirmed COTI onboarding transaction did not contain this wallet’s AccountOnboarded key event.',
      );
    }
    let aesKey: string;
    try {
      aesKey = recoverUserKey(
        rsaKeysFromRecovery(recovery).privateKey,
        encryptedShareOne,
        encryptedShareTwo,
      );
    } catch {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The signer could not recover the COTI AES key from the confirmed onboarding event.',
      );
    }
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'COTI onboarding recovered an invalid wallet AES key.',
      );
    }
    return this.#persistAesKey(recovery.wallet, aesKey);
  }

  async #reconcile(
    recovery: PrivacyOnboardingRecoveryV1,
  ): Promise<PrivacyOnboardingResult> {
    if (!recovery.txHash) {
      throw recoveryError(
        'the recovery record has not prepared a transaction.',
      );
    }
    const provider = this.#wallet.provider;
    if (!provider) {
      throw new SignerError(
        'WRITE_UNAVAILABLE',
        'COTI privacy onboarding requires a connected RPC provider.',
      );
    }
    let receipt = await this.#readReceipt(recovery.txHash);
    if (!receipt) {
      let observed: boolean;
      try {
        observed = Boolean(
          await provider.getTransaction(recovery.txHash),
        );
      } catch {
        throw processingError();
      }
      if (!observed) {
        if (!recovery.signedTransaction) {
          throw processingError();
        }
        try {
          const response = await provider.broadcastTransaction(
            recovery.signedTransaction,
          );
          if (
            response.hash.toLowerCase() !==
            recovery.txHash.toLowerCase()
          ) {
            throw recoveryError(
              'the RPC returned a different hash for the persisted signed transaction.',
            );
          }
          observed = true;
        } catch (error) {
          if (
            error instanceof SignerError &&
            error.code === 'PRIVATE_INPUT_UNAVAILABLE'
          ) {
            throw error;
          }
          receipt = await this.#readReceipt(recovery.txHash);
          if (!receipt) {
            try {
              observed = Boolean(
                await provider.getTransaction(recovery.txHash),
              );
            } catch {
              observed = false;
            }
            if (!observed) throw processingError();
          }
        }
      }
    }
    if (!receipt) {
      try {
        receipt = await provider.waitForTransaction(
          recovery.txHash,
          1,
          ONBOARD_RECEIPT_TIMEOUT_MS,
        );
      } catch {
        throw processingError();
      }
    }
    if (!receipt) throw processingError();
    if (
      receipt.hash.toLowerCase() !== recovery.txHash.toLowerCase()
    ) {
      throw recoveryError(
        'the receipt does not match the persisted onboarding transaction.',
      );
    }
    if (receipt.status !== 1) {
      const revertedTransactionHashes = [
        ...(recovery.revertedTransactionHashes ?? []),
        recovery.txHash,
      ].slice(-16);
      await this.#persistRecovery({
        version: 1,
        wallet: recovery.wallet,
        contract: recovery.contract,
        operationHash: recovery.operationHash,
        rsaPublicKey: recovery.rsaPublicKey,
        rsaPrivateKey: recovery.rsaPrivateKey,
        revertedTransactionHashes,
      });
      throw new SignerError(
        'TRANSACTION_FAILED',
        'The COTI privacy onboarding transaction reverted definitively. Its RSA recovery key was retained; retry the command for a fresh confirmation and nonce.',
      );
    }
    const aesKey = await this.#recoverAesKey(recovery, receipt);
    const rsaKey = rsaKeysFromRecovery(recovery);
    this.#wallet.setUserOnboardInfo({
      aesKey,
      rsaKey,
      txHash: recovery.txHash,
    });
    return readyResult(recovery.wallet, recovery.txHash);
  }

  async onboard(): Promise<PrivacyOnboardingResult> {
    const wallet = (await this.#wallet.getAddress()).toLowerCase() as Address;
    const ready = await this.#adoptReadyKey(wallet);
    if (ready) return ready;

    const existingRecovery = await this.#loadRecovery(wallet);
    if (!existingRecovery?.txHash) {
      await this.#confirmation.confirm({
        operationId: `privacy-onboard-${wallet.slice(2)}`,
        operationHash: operationHashFor(wallet),
        stepId: 'coti-account-onboard',
        stepIndex: 0,
        stepCount: 1,
        wallet,
        contract: ACCOUNT_ONBOARD_CONTRACT,
        action: 'onboard_privacy',
        assets: ['COTI account privacy'],
        amounts: [],
        details: [
          {
            label: 'On-chain action',
            value: 'Register this wallet’s one-time public encryption key',
          },
          {
            label: 'Local result',
            value:
              'Recover and encrypt the wallet AES key in the signer vault',
          },
        ],
        counterparty: null,
        fee: `Network gas only (maximum ${MAXIMUM_NETWORK_FEE.coti} COTI / ${MAXIMUM_NETWORK_FEE.wei} wei)`,
        nativeValue: '0',
        gasCap: ACCOUNT_ONBOARD_GAS_LIMIT.toString(),
        expectedResult:
          'Retrieve this wallet’s unique COTI AES key and store it only in the encrypted local signer vault.',
        summary:
          'Onboard the local signer wallet for COTI private computation.',
      });
    }

    const result = await this.#nonceQueue.runExternalWrite(
      async (pendingNonce) => {
        const becameReady = await this.#adoptReadyKey(wallet);
        if (becameReady) return becameReady;

        let recovery = await this.#loadRecovery(wallet);
        if (!recovery) {
          recovery = this.#newRecovery(wallet);
          await this.#persistRecovery(recovery);
        }
        const rsaKey = rsaKeysFromRecovery(recovery);
        this.#wallet.clearUserOnboardInfo();
        this.#wallet.disableAutoOnboard();
        this.#wallet.setUserOnboardInfo({
          rsaKey,
          ...(recovery.txHash ? { txHash: recovery.txHash } : {}),
        });
        if (!recovery.txHash) {
          recovery = await this.#prepareTransaction(
            recovery,
            pendingNonce,
          );
        }
        return this.#reconcile(recovery);
      },
    );
    return result.result;
  }
}
