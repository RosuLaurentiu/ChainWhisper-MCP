import {
  constants as cryptoConstants,
  publicEncrypt,
} from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  JsonRpcProvider,
  Network,
  Wallet,
  getAccountOnboardContract,
  keccak256,
  type TransactionReceipt,
  type TransactionRequest,
} from '@coti-io/coti-ethers';
import {
  generateRSAKeyPair,
  sign,
} from '@coti-io/coti-sdk-typescript';
import { describe, expect, it, vi } from 'vitest';

import {
  ConfirmationGate,
  EncryptedSecretVault,
  NonceQueue,
  OperationJournal,
  PrivacyOnboardingService,
  privacyOnboardingOperationId,
  type Address,
  type ConfirmationRequest,
  type FormElicitor,
  type HexString,
} from '../src/signer/index.js';

const CHAIN_ID = 2_632_500;
const WALLET =
  '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a' as Address;
const ONBOARD_CONTRACT =
  '0x536a67f0cc46513e7d27a370ed1af9fdcc7a5095' as Address;
const PRIVATE_KEY = `0x${'11'.repeat(32)}` as HexString;
const AES_KEY = 'ab'.repeat(16);
const RECOVERY_REFERENCE = 'signer/onboard-recovery';

type RecoveryRecord = {
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

class AcceptingElicitor implements FormElicitor {
  readonly requests: ConfirmationRequest[] = [];

  isSupported(): boolean {
    return true;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<{ outcome: 'accepted' }> {
    this.requests.push(request);
    return { outcome: 'accepted' };
  }
}

class DecliningElicitor implements FormElicitor {
  readonly requests: ConfirmationRequest[] = [];

  isSupported(): boolean {
    return true;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<{ outcome: 'declined' }> {
    this.requests.push(request);
    return { outcome: 'declined' };
  }
}

const recoveryRecord = async (
  vault: EncryptedSecretVault,
): Promise<RecoveryRecord> => {
  const encoded = await vault.get(RECOVERY_REFERENCE);
  if (!encoded) throw new Error('missing onboarding recovery record');
  return JSON.parse(encoded) as RecoveryRecord;
};

const encryptedAesShares = (
  rsaPublicKey: string,
): [HexString, HexString] => {
  const first = Buffer.alloc(16, 0x5a);
  const aes = Buffer.from(AES_KEY, 'hex');
  const second = Buffer.from(
    aes.map((value, index) => value ^ first[index]!),
  );
  const key = {
    key: Buffer.from(rsaPublicKey, 'base64'),
    format: 'der' as const,
    type: 'spki' as const,
  };
  const encryptShare = (share: Buffer): HexString =>
    `0x${publicEncrypt(
      {
        ...key,
        padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      share,
    ).toString('hex')}`;
  return [encryptShare(first), encryptShare(second)];
};

const successReceipt = (
  transactionHash: HexString,
  rsaPublicKey: string,
): TransactionReceipt => {
  const contract = getAccountOnboardContract(ONBOARD_CONTRACT);
  const event = contract.interface.getEvent('AccountOnboarded');
  if (!event) throw new Error('missing AccountOnboarded event');
  const shares = encryptedAesShares(rsaPublicKey);
  const encoded = contract.interface.encodeEventLog(event, [
    WALLET,
    shares[0],
    shares[1],
  ]);
  return {
    hash: transactionHash,
    status: 1,
    logs: [
      {
        address: ONBOARD_CONTRACT,
        topics: encoded.topics,
        data: encoded.data,
      },
    ],
  } as unknown as TransactionReceipt;
};

const createHarness = async (
  elicitor: FormElicitor & {
    requests: ConfirmationRequest[];
  } = new AcceptingElicitor(),
) => {
  const stateDirectory = await mkdtemp(
    join(tmpdir(), 'cw-privacy-onboarding-'),
  );
  const vault = new EncryptedSecretVault(
    stateDirectory,
    'privacy-onboarding-test-passphrase',
  );
  const provider = new JsonRpcProvider(
    'http://127.0.0.1:8545',
    CHAIN_ID,
    { staticNetwork: true },
  );
  const wallet = new Wallet(PRIVATE_KEY, provider);
  wallet.disableAutoOnboard();
  vi.spyOn(provider, 'getNetwork').mockResolvedValue(
    Network.from(CHAIN_ID),
  );
  vi.spyOn(wallet, 'populateTransaction').mockImplementation(
    async (request: TransactionRequest) => ({
      ...request,
      to: ONBOARD_CONTRACT,
      chainId: CHAIN_ID,
      nonce: request.nonce ?? 7,
      gasLimit: request.gasLimit ?? 12_000_000n,
      gasPrice: 1n,
      type: 0,
    }),
  );
  const pendingNonce = vi.fn(async () => 7);
  const journal = new OperationJournal(stateDirectory);
  const service = new PrivacyOnboardingService({
    wallet,
    vault,
    confirmation: new ConfirmationGate(elicitor, 5_000),
    nonceQueue: new NonceQueue(pendingNonce),
    journal,
  });
  return {
    vault,
    provider,
    wallet,
    elicitor,
    journal,
    pendingNonce,
    service,
  };
};

describe('durable COTI privacy onboarding', () => {
  it('journals a local onboarding decline as terminal without preparing a transaction', async () => {
    const declining = new DecliningElicitor();
    const harness = await createHarness(declining);

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'CONFIRMATION_DECLINED',
    });

    expect(declining.requests).toHaveLength(1);
    expect(
      await harness.journal.get(
        privacyOnboardingOperationId(WALLET),
      ),
    ).toMatchObject({
      stage: 'declined',
      nonces: [],
      transactionHashes: [],
      receipts: [],
      errorCodes: ['CONFIRMATION_DECLINED'],
    });
    expect(await harness.vault.get(RECOVERY_REFERENCE)).toBeNull();
    harness.provider.destroy();
  });

  it('recovers an accepted-but-unobserved broadcast without creating a replacement transaction', async () => {
    const harness = await createHarness();
    const getReceipt = vi
      .spyOn(harness.provider, 'getTransactionReceipt')
      .mockResolvedValue(null);
    vi.spyOn(harness.provider, 'getTransaction').mockResolvedValue(
      null,
    );
    const broadcast = vi
      .spyOn(harness.provider, 'broadcastTransaction')
      .mockRejectedValue(new Error('response lost after acceptance'));
    const wait = vi.spyOn(harness.provider, 'waitForTransaction');

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'OPERATION_IN_PROGRESS',
    });

    const prepared = await recoveryRecord(harness.vault);
    expect(prepared.signedTransaction).toMatch(/^0x[0-9a-f]+$/u);
    expect(prepared.txHash).toBe(
      keccak256(prepared.signedTransaction!),
    );
    expect(prepared.nonce).toBe(7);
    expect(harness.elicitor.requests).toHaveLength(1);
    expect(broadcast).toHaveBeenCalledTimes(1);
    expect(wait).not.toHaveBeenCalled();
    const operationId = privacyOnboardingOperationId(WALLET);
    expect(await harness.journal.get(operationId)).toMatchObject({
      stage: 'prepared-broadcast',
      nonces: [7],
      transactionHashes: [prepared.txHash],
      receipts: [],
      errorCodes: ['OPERATION_IN_PROGRESS'],
    });

    getReceipt.mockResolvedValue(
      successReceipt(prepared.txHash!, prepared.rsaPublicKey),
    );
    const restartElicitor = new AcceptingElicitor();
    const restartedService = new PrivacyOnboardingService({
      wallet: harness.wallet,
      vault: harness.vault,
      confirmation: new ConfirmationGate(restartElicitor, 5_000),
      nonceQueue: new NonceQueue(harness.pendingNonce),
      journal: harness.journal,
    });
    const result = await restartedService.onboard();

    expect(result).toMatchObject({
      status: 'ready',
      wallet: WALLET,
      transactionHash: prepared.txHash,
      persistedInEncryptedVault: true,
    });
    expect(await harness.vault.get('signer/aes-key')).toBe(AES_KEY);
    expect(
      harness.wallet.getUserOnboardInfo()?.aesKey,
    ).toBe(AES_KEY);
    expect(harness.elicitor.requests).toHaveLength(1);
    expect(restartElicitor.requests).toHaveLength(0);
    expect(broadcast).toHaveBeenCalledTimes(1);
    expect(await harness.journal.get(operationId)).toMatchObject({
      stage: 'completed',
      transactionHashes: [prepared.txHash],
      receipts: [
        {
          transactionHash: prepared.txHash,
          status: 'success',
        },
      ],
    });
    harness.provider.destroy();
  });

  it('keeps a timed-out observed transaction in broadcasting recovery until it eventually succeeds', async () => {
    const harness = await createHarness();
    const getReceipt = vi
      .spyOn(harness.provider, 'getTransactionReceipt')
      .mockResolvedValue(null);
    vi.spyOn(harness.provider, 'getTransaction').mockResolvedValue(
      null,
    );
    vi.spyOn(
      harness.provider,
      'broadcastTransaction',
    ).mockImplementation(async (signedTransaction) => ({
      hash: keccak256(signedTransaction),
    }) as never);
    vi.spyOn(
      harness.provider,
      'waitForTransaction',
    ).mockRejectedValue(new Error('receipt polling timed out'));

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'OPERATION_IN_PROGRESS',
    });

    const recovery = await recoveryRecord(harness.vault);
    const operationId = privacyOnboardingOperationId(WALLET);
    expect(await harness.journal.get(operationId)).toMatchObject({
      stage: 'broadcast',
      nonces: [7],
      transactionHashes: [recovery.txHash],
      receipts: [
        {
          transactionHash: recovery.txHash,
          status: 'pending',
        },
      ],
      errorCodes: ['OPERATION_IN_PROGRESS'],
    });

    getReceipt.mockResolvedValue(
      successReceipt(recovery.txHash!, recovery.rsaPublicKey),
    );
    await expect(harness.service.onboard()).resolves.toMatchObject({
      status: 'ready',
      transactionHash: recovery.txHash,
    });
    expect(await harness.journal.get(operationId)).toMatchObject({
      stage: 'completed',
      transactionHashes: [recovery.txHash],
      receipts: [
        {
          transactionHash: recovery.txHash,
          status: 'success',
        },
      ],
    });
    expect(harness.elicitor.requests).toHaveLength(1);
    harness.provider.destroy();
  });

  it('persists the RSA recovery key before transaction preparation and reuses it after fresh confirmation', async () => {
    const harness = await createHarness();
    const populate = vi.mocked(harness.wallet.populateTransaction);
    populate.mockRejectedValueOnce(
      new Error('crash while populating transaction'),
    );

    await expect(harness.service.onboard()).rejects.toThrow(
      'crash while populating transaction',
    );
    const rsaOnly = await recoveryRecord(harness.vault);
    expect(rsaOnly.txHash).toBeUndefined();
    expect(rsaOnly.signedTransaction).toBeUndefined();
    expect(harness.elicitor.requests).toHaveLength(1);
    expect(
      await harness.journal.get(
        privacyOnboardingOperationId(WALLET),
      ),
    ).toMatchObject({
      stage: 'failed',
      transactionHashes: [],
      errorCodes: ['TRANSACTION_FAILED'],
    });

    vi.spyOn(
      harness.provider,
      'getTransactionReceipt',
    ).mockResolvedValue(null);
    vi.spyOn(harness.provider, 'getTransaction').mockResolvedValue(
      null,
    );
    vi.spyOn(
      harness.provider,
      'broadcastTransaction',
    ).mockImplementation(async (signedTransaction) => {
      const hash = keccak256(signedTransaction) as HexString;
      return { hash } as never;
    });
    vi.spyOn(
      harness.provider,
      'waitForTransaction',
    ).mockImplementation(async (transactionHash) => {
      const latest = await recoveryRecord(harness.vault);
      return successReceipt(
        transactionHash as HexString,
        latest.rsaPublicKey,
      );
    });

    const result = await harness.service.onboard();
    const completed = await recoveryRecord(harness.vault);

    expect(result.status).toBe('ready');
    expect(completed.rsaPublicKey).toBe(rsaOnly.rsaPublicKey);
    expect(completed.rsaPrivateKey).toBe(rsaOnly.rsaPrivateKey);
    expect(completed.txHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(await harness.vault.get('signer/aes-key')).toBe(AES_KEY);
    expect(harness.elicitor.requests).toHaveLength(2);
    expect(
      await harness.journal.get(
        privacyOnboardingOperationId(WALLET),
      ),
    ).toMatchObject({
      stage: 'completed',
      transactionHashes: [completed.txHash],
    });
    harness.provider.destroy();
  });

  it('rejects persisted onboarding calldata for a different RSA recovery key', async () => {
    const harness = await createHarness();
    vi.spyOn(
      harness.provider,
      'getTransactionReceipt',
    ).mockResolvedValue(null);
    vi.spyOn(harness.provider, 'getTransaction').mockResolvedValue(
      null,
    );
    const broadcast = vi
      .spyOn(harness.provider, 'broadcastTransaction')
      .mockRejectedValue(new Error('uncertain broadcast response'));

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'OPERATION_IN_PROGRESS',
    });
    const prepared = await recoveryRecord(harness.vault);
    const alternateRsa = generateRSAKeyPair();
    const alternateSignature = sign(
      keccak256(alternateRsa.publicKey),
      PRIVATE_KEY,
    );
    const contract = getAccountOnboardContract(ONBOARD_CONTRACT);
    const alternateData = contract.interface.encodeFunctionData(
      'onboardAccount',
      [alternateRsa.publicKey, alternateSignature],
    );
    const alternateSignedTransaction =
      (await harness.wallet.signTransaction({
        to: ONBOARD_CONTRACT,
        data: alternateData,
        value: 0n,
        gasLimit: 12_000_000n,
        nonce: prepared.nonce,
        chainId: CHAIN_ID,
        gasPrice: 1n,
        type: 0,
      })) as HexString;
    await harness.vault.put(
      RECOVERY_REFERENCE,
      JSON.stringify({
        ...prepared,
        txHash: keccak256(alternateSignedTransaction),
        signedTransaction: alternateSignedTransaction,
      }),
      {
        kind: 'recovery-note',
        binding: { operationHash: prepared.operationHash },
      },
    );

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'PRIVATE_INPUT_UNAVAILABLE',
      message: expect.stringContaining(
        'does not match the persisted RSA recovery key',
      ),
    });
    expect(broadcast).toHaveBeenCalledTimes(1);
    harness.provider.destroy();
  });

  it('requires fresh confirmation and nonce after a definitive onboarding revert', async () => {
    const harness = await createHarness();
    harness.pendingNonce
      .mockResolvedValueOnce(7)
      .mockResolvedValueOnce(8)
      .mockResolvedValue(8);
    const getReceipt = vi
      .spyOn(harness.provider, 'getTransactionReceipt')
      .mockResolvedValue(null);
    vi.spyOn(harness.provider, 'getTransaction').mockResolvedValue(
      null,
    );
    const broadcast = vi
      .spyOn(harness.provider, 'broadcastTransaction')
      .mockRejectedValue(new Error('uncertain broadcast response'));
    const populate = vi.mocked(harness.wallet.populateTransaction);

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'OPERATION_IN_PROGRESS',
    });
    const prepared = await recoveryRecord(harness.vault);
    getReceipt.mockImplementation(async (transactionHash) =>
      transactionHash === prepared.txHash
        ? ({
            hash: prepared.txHash,
            status: 0,
            logs: [],
          } as unknown as TransactionReceipt)
        : null,
    );

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'TRANSACTION_FAILED',
    });
    const retryable = await recoveryRecord(harness.vault);
    expect(retryable).toMatchObject({
      rsaPublicKey: prepared.rsaPublicKey,
      rsaPrivateKey: prepared.rsaPrivateKey,
      revertedTransactionHashes: [prepared.txHash],
    });
    expect(retryable.txHash).toBeUndefined();
    expect(retryable.signedTransaction).toBeUndefined();
    expect(
      await harness.journal.get(
        privacyOnboardingOperationId(WALLET),
      ),
    ).toMatchObject({
      stage: 'failed',
      transactionHashes: [prepared.txHash],
      receipts: [
        {
          transactionHash: prepared.txHash,
          status: 'reverted',
        },
      ],
      errorCodes: expect.arrayContaining(['TRANSACTION_FAILED']),
    });

    await expect(harness.service.onboard()).rejects.toMatchObject({
      code: 'OPERATION_IN_PROGRESS',
    });
    const replacement = await recoveryRecord(harness.vault);
    expect(replacement.txHash).not.toBe(prepared.txHash);
    expect(replacement.nonce).toBe(8);
    expect(replacement.rsaPublicKey).toBe(prepared.rsaPublicKey);
    expect(await harness.vault.get('signer/aes-key')).toBeNull();
    expect(populate).toHaveBeenCalledTimes(2);
    expect(broadcast).toHaveBeenCalledTimes(2);
    expect(harness.elicitor.requests).toHaveLength(2);
    harness.provider.destroy();
  });
});
