import type {
  HexString,
  SignedActionEnvelopeV1,
} from '../shared/index.js';

import { buildPublicSignerStatus, type LoadedSignerConfig } from './config.js';
import {
  AutonomyPolicyManager,
  type AutonomyDecision,
  type AutonomyPolicyProposalV1,
  type AutonomyStatusV1,
  type ActiveAutonomyPolicyV1,
} from './autonomy.js';
import { ConfirmationGate } from './confirmation.js';
import { SignerEngine } from './engine.js';
import {
  LocalWebFormElicitor,
  type OpenControlPanelResult,
} from './localWebElicitor.js';
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
  readonly #control: LocalWebFormElicitor | null;
  readonly #autonomy: AutonomyPolicyManager | null;
  readonly #writesBlocked: () => boolean;
  readonly #manifestHash: HexString | null;

  constructor(options: {
    config: LoadedSignerConfig;
    wallet: WalletTransport;
    confirmation: ConfirmationGate;
    engine: SignerEngine;
    messaging: ChainWhisperMessagingBridge;
    privacyOnboarding: PrivacyOnboardingService;
    privateTokens: PrivateTokenAccountService;
    control?: LocalWebFormElicitor;
    autonomy?: AutonomyPolicyManager;
    writesBlocked?: () => boolean;
    manifestHash?: HexString;
  }) {
    this.#config = options.config;
    this.#wallet = options.wallet;
    this.#confirmation = options.confirmation;
    this.#engine = options.engine;
    this.#messaging = options.messaging;
    this.#privacyOnboarding = options.privacyOnboarding;
    this.#privateTokens = options.privateTokens;
    this.#control = options.control ?? null;
    this.#autonomy = options.autonomy ?? null;
    this.#writesBlocked = options.writesBlocked ?? (() => false);
    this.#manifestHash = options.manifestHash ?? null;
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
    const autonomyDecision = await this.autonomyStatus();
    const autonomyStatus = autonomyDecision.allowed
      ? autonomyDecision.value
      : null;
    const activePolicies = autonomyStatus?.policies.filter(({ policy }) =>
      ['active', 'paused'].includes(policy.lifecycle.state),
    ) ?? [];
    const current = activePolicies.at(-1)?.policy;
    const status = buildPublicSignerStatus(
      this.#config,
      wallet,
      this.#confirmation.isWriteAvailable
        ? {
            isSupported: () => true,
            requestConfirmation: async () => ({ outcome: 'cancelled' }),
          }
        : null,
      await this.#privacyOnboarding.isReady(),
      {
        controlPageReadiness: this.#control?.controlPageReady
          ? 'ready'
          : 'starting',
        autonomy: {
          mode: current?.mode ?? 'manual',
          state: current?.lifecycle.state ?? 'inactive',
          activePolicyCount: activePolicies.length,
          globalPaused: autonomyStatus?.globalPaused ?? false,
        },
        diagnosticCodes: [
          ...(this.#writesBlocked() ? ['signer-restart-required'] : []),
          ...(autonomyDecision.allowed
            ? []
            : [`autonomy-${autonomyDecision.denial.code.toLowerCase()}`]),
          this.#control?.controlPageReady
            ? 'control-page-ready'
            : 'control-page-starting',
        ],
      },
    );
    return this.#writesBlocked()
      ? {
          ...status,
          mode: 'read-only',
          signerReadiness: 'confirmation-unavailable',
          diagnosticCodes: [
            ...new Set([
              ...status.diagnosticCodes,
              'signer-restart-required',
            ]),
          ],
        }
      : status;
  }

  openControlPanel(): Promise<OpenControlPanelResult> {
    return this.#control
      ? this.#control.openControlPanel()
      : Promise.resolve({
          opened: false,
          ready: false,
          activePrompt: false,
          reason: 'server-unavailable',
        });
  }

  autonomyStatus(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#autonomy
      ? this.#autonomy.status()
      : Promise.resolve({
          allowed: true,
          value: {
            globalPaused: false,
            policies: [],
            activeReservationCount: 0,
          },
        });
  }

  async requestAutonomy(
    proposal: AutonomyPolicyProposalV1,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    if (this.#writesBlocked()) {
      return {
        allowed: false,
        denial: {
          code: 'POLICY_PAUSED',
          message:
            'Restart the signer before activating a new autonomy policy.',
        },
      };
    }
    if (!this.#autonomy) {
      return {
          allowed: false,
          denial: {
            code: 'POLICY_NOT_FOUND',
            message: 'Autonomy is not available in this signer session.',
          },
        };
    }
    const wallet = await this.#wallet.getAddress();
    if (proposal.wallet.toLowerCase() !== wallet.toLowerCase()) {
      return {
        allowed: false,
        denial: {
          code: 'WALLET_MISMATCH',
          message: 'The requested policy targets a different Agent Wallet.',
          field: 'wallet',
        },
      };
    }
    if (proposal.chainId !== this.#config.chainId) {
      return {
        allowed: false,
        denial: {
          code: 'CHAIN_MISMATCH',
          message: 'The requested policy targets a different chain.',
          field: 'chainId',
        },
      };
    }
    if (
      this.#manifestHash &&
      proposal.manifestHash.toLowerCase() !==
        this.#manifestHash.toLowerCase()
    ) {
      return {
        allowed: false,
        denial: {
          code: 'MANIFEST_MISMATCH',
          message:
            'The requested policy is not bound to the active audited runtime.',
          field: 'manifestHash',
        },
      };
    }
    return this.#autonomy.activate(proposal);
  }

  pauseAutonomy(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#autonomy
      ? this.#autonomy.pauseGlobal()
      : this.autonomyStatus();
  }

  resumeAutonomy(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#autonomy
      ? this.#autonomy.resumeGlobal()
      : this.autonomyStatus();
  }

  revokeAutonomy(
    policyId: string,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    return this.#autonomy
      ? this.#autonomy.revoke(policyId)
      : Promise.resolve({
          allowed: false,
          denial: {
            code: 'POLICY_NOT_FOUND',
            message: 'Autonomy is not available in this signer session.',
            policyId,
          },
        });
  }

  async testConfirmationForm(): Promise<ConfirmationDiagnosticResult> {
    return this.#confirmation.diagnoseForm(
      await this.#wallet.getAddress(),
    );
  }

  onboardPrivacy(): Promise<PrivacyOnboardingResult> {
    if (this.#writesBlocked()) {
      throw new Error('Restart the signer before performing writes.');
    }
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
    if (this.#writesBlocked()) {
      throw new Error('Restart the signer before performing writes.');
    }
    return this.#privateTokens.enable(token);
  }

  executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
  ): Promise<ExecuteActionResult> {
    if (this.#writesBlocked()) {
      return Promise.resolve({
        operationId: envelope.operationId,
        operationHash: envelope.operationHash,
        status: 'read-only',
        transactionHashes: [],
        errorCode: 'SIGNER_RESTART_REQUIRED',
      });
    }
    return this.#engine.executeAction(envelope, policyId);
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
    operationHash: string,
  ): Promise<RecoverOperationResult> {
    return this.#engine.discardOperation(operationId, operationHash);
  }
}
