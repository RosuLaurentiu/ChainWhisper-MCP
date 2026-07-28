import type { SignedActionEnvelopeV1 } from '../shared/index.js';

import { buildPublicSignerStatus, type LoadedSignerConfig } from './config.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerEngine } from './engine.js';
import { ChainWhisperMessagingBridge } from './messaging.js';
import {
  PrivacyOnboardingService,
  type PrivacyOnboardingResult,
} from './privacyOnboarding.js';
import {
  PrivateTokenAccountService,
  type PrivateTokenAccountSetupResult,
  type PrivateTokenAccountStatus,
} from './privateTokenAccount.js';
import type {
  Address,
  ConfirmationDiagnosticResult,
  ExecuteActionResult,
  OperationJournalRecord,
  PublicSignerStatus,
  RecoverOperationResult,
  WalletTransport,
} from './types.js';

export class ChainWhisperSignerService {
  readonly #config: LoadedSignerConfig;
  readonly #wallet: WalletTransport;
  readonly #confirmation: ConfirmationGate;
  readonly #engine: SignerEngine;
  readonly #messaging: ChainWhisperMessagingBridge;
  readonly #privacyOnboarding: PrivacyOnboardingService;
  readonly #privateTokens: PrivateTokenAccountService;

  constructor(options: {
    config: LoadedSignerConfig;
    wallet: WalletTransport;
    confirmation: ConfirmationGate;
    engine: SignerEngine;
    messaging: ChainWhisperMessagingBridge;
    privacyOnboarding: PrivacyOnboardingService;
    privateTokens: PrivateTokenAccountService;
  }) {
    this.#config = options.config;
    this.#wallet = options.wallet;
    this.#confirmation = options.confirmation;
    this.#engine = options.engine;
    this.#messaging = options.messaging;
    this.#privacyOnboarding = options.privacyOnboarding;
    this.#privateTokens = options.privateTokens;
  }

  get messaging(): ChainWhisperMessagingBridge {
    return this.#messaging;
  }

  async getStatus(): Promise<PublicSignerStatus> {
    let wallet: Address | null = null;
    try {
      wallet = await this.#wallet.getAddress();
    } catch {
      wallet = null;
    }
    return buildPublicSignerStatus(
      this.#config,
      wallet,
      this.#confirmation.isWriteAvailable
        ? {
            isSupported: () => true,
            requestConfirmation: async () => ({ outcome: 'cancelled' }),
          }
        : null,
      await this.#privacyOnboarding.isReady(),
    );
  }

  async testConfirmationForm(): Promise<ConfirmationDiagnosticResult> {
    return this.#confirmation.diagnoseForm(
      await this.#wallet.getAddress(),
    );
  }

  onboardPrivacy(): Promise<PrivacyOnboardingResult> {
    return this.#privacyOnboarding.onboard();
  }

  getPrivateTokenStatus(
    token: string,
  ): Promise<PrivateTokenAccountStatus> {
    return this.#privateTokens.status(token);
  }

  enablePrivateToken(
    token: string,
  ): Promise<PrivateTokenAccountSetupResult> {
    return this.#privateTokens.enable(token);
  }

  executeAction(
    envelope: SignedActionEnvelopeV1,
  ): Promise<ExecuteActionResult> {
    return this.#engine.executeAction(envelope);
  }

  getOperation(
    operationId: string,
  ): Promise<OperationJournalRecord | null> {
    return this.#engine.getOperation(operationId);
  }

  recoverOperation(
    operationId: string,
    operationHash?: string,
  ): Promise<RecoverOperationResult> {
    return this.#engine.recoverOperation(operationId, operationHash);
  }

  discardOperation(
    operationId: string,
    operationHash?: string,
  ): Promise<RecoverOperationResult> {
    return this.#engine.discardOperation(operationId, operationHash);
  }
}
