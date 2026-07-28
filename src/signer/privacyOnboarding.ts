import type { Wallet } from '@coti-io/coti-ethers';

import { sha256Hex } from '../shared/index.js';
import {
  isCotiAesKey,
  normalizeCotiAesKey,
} from './cotiAes.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerError } from './errors.js';
import { NonceQueue } from './nonceQueue.js';
import type { Address, HexString } from './types.js';
import { EncryptedSecretVault } from './vault.js';

const ACCOUNT_ONBOARD_CONTRACT =
  '0x536A67f0cc46513E7d27a370ed1aF9FDcC7A5095' as Address;

export type PrivacyOnboardingResult = {
  status: 'ready';
  wallet: Address;
  transactionHash: HexString | null;
  persistedInEncryptedVault: true;
  messagingRestartRecommended: boolean;
};

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

  async onboard(): Promise<PrivacyOnboardingResult> {
    const wallet = (await this.#wallet.getAddress()).toLowerCase() as Address;
    const existing = await this.#vault.get('signer/aes-key');
    if (isCotiAesKey(existing)) {
      this.#wallet.setAesKey(normalizeCotiAesKey(existing));
      return {
        status: 'ready',
        wallet,
        transactionHash: null,
        persistedInEncryptedVault: true,
        messagingRestartRecommended: false,
      };
    }

    const configured = this.#wallet.getUserOnboardInfo()?.aesKey;
    if (isCotiAesKey(configured)) {
      const normalized = normalizeCotiAesKey(configured);
      await this.#vault.put('signer/aes-key', normalized, {
        kind: 'generic',
        binding: { operationHash: sha256Hex(wallet) },
      });
      this.#wallet.setAesKey(normalized);
      return {
        status: 'ready',
        wallet,
        transactionHash: null,
        persistedInEncryptedVault: true,
        messagingRestartRecommended: false,
      };
    }

    await this.#confirmation.confirm({
      operationId: `privacy-onboard-${wallet.slice(2)}`,
      operationHash: sha256Hex(
        `chainwhisper/privacy-onboard/v1:${wallet}`,
      ),
      stepId: 'coti-account-onboard',
      stepIndex: 0,
      stepCount: 1,
      wallet,
      contract: ACCOUNT_ONBOARD_CONTRACT,
      action: 'onboard_privacy',
      assets: ['COTI account privacy'],
      amounts: [],
      counterparty: null,
      fee: 'Network gas only',
      nativeValue: '0',
      gasCap: '12000000',
      expectedResult:
        'Retrieve this wallet’s unique COTI AES key and store it only in the encrypted local signer vault.',
      summary: 'Onboard the local signer wallet for COTI private computation.',
    });

    this.#wallet.clearUserOnboardInfo();
    this.#wallet.enableAutoOnboard();
    try {
      await this.#nonceQueue.runExternalWrite(async () => {
        await this.#wallet.generateOrRecoverAes();
      });
    } finally {
      this.#wallet.disableAutoOnboard();
    }
    const onboardInfo = this.#wallet.getUserOnboardInfo();
    const aesKey = onboardInfo?.aesKey?.trim() ?? '';
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'COTI onboarding did not return a valid wallet AES key.',
      );
    }
    const normalizedAesKey = normalizeCotiAesKey(aesKey);
    this.#wallet.setAesKey(normalizedAesKey);
    await this.#vault.put('signer/aes-key', normalizedAesKey, {
      kind: 'generic',
      binding: { operationHash: sha256Hex(wallet) },
    });
    if (onboardInfo?.rsaKey && onboardInfo.txHash) {
      await this.#vault.put(
        'signer/onboard-recovery',
        JSON.stringify({
          txHash: String(onboardInfo.txHash),
          rsaPublicKey: Buffer.from(
            onboardInfo.rsaKey.publicKey,
          ).toString('base64'),
          rsaPrivateKey: Buffer.from(
            onboardInfo.rsaKey.privateKey,
          ).toString('base64'),
        }),
        {
          kind: 'generic',
          binding: { operationHash: sha256Hex(wallet) },
        },
      );
    }
    const transactionHash =
      typeof onboardInfo?.txHash === 'string' &&
      /^0x[0-9a-fA-F]{64}$/u.test(onboardInfo.txHash)
        ? (onboardInfo.txHash as HexString)
        : null;
    return {
      status: 'ready',
      wallet,
      transactionHash,
      persistedInEncryptedVault: true,
      messagingRestartRecommended: false,
    };
  }
}
