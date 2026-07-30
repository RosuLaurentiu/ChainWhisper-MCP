import type {
  HexString,
  SignedActionEnvelopeV1,
} from '../shared/index.js';

import { isSafeAgentControlDiagnosticCode } from './agentWallet.js';
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
import { SignerError } from './errors.js';
import {
  LocalWebFormElicitor,
  type OpenControlPanelResult,
} from './localWebElicitor.js';
import {
  ChainWhisperMessagingBridge,
  isMessageOperationId,
} from './messaging.js';
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
  OperationStatusV2,
  PrivateStateDisclosureDecisionV1,
  PrivateStateDisclosureReader,
  PrivateStateQueryV1,
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
  readonly #privateState: PrivateStateDisclosureReader | null;
  readonly #control: LocalWebFormElicitor | null;
  readonly #autonomy: AutonomyPolicyManager | null;
  readonly #writesBlocked: () => boolean;
  readonly #diagnosticCodes: () => string[];
  readonly #manifestHash: HexString | null;

  constructor(options: {
    config: LoadedSignerConfig;
    wallet: WalletTransport;
    confirmation: ConfirmationGate;
    engine: SignerEngine;
    messaging: ChainWhisperMessagingBridge;
    privacyOnboarding: PrivacyOnboardingService;
    privateTokens: PrivateTokenAccountService;
    privateState?: PrivateStateDisclosureReader;
    control?: LocalWebFormElicitor;
    autonomy?: AutonomyPolicyManager;
    writesBlocked?: () => boolean;
    diagnosticCodes?: () => string[];
    manifestHash?: HexString;
  }) {
    this.#config = options.config;
    this.#wallet = options.wallet;
    this.#confirmation = options.confirmation;
    this.#engine = options.engine;
    this.#messaging = options.messaging;
    this.#privacyOnboarding = options.privacyOnboarding;
    this.#privateTokens = options.privateTokens;
    this.#privateState = options.privateState ?? null;
    this.#control = options.control ?? null;
    this.#autonomy = options.autonomy ?? null;
    this.#writesBlocked = options.writesBlocked ?? (() => false);
    this.#diagnosticCodes = options.diagnosticCodes ?? (() => []);
    this.#manifestHash = options.manifestHash ?? null;
  }

  get messaging(): ChainWhisperMessagingBridge {
    return this.#messaging;
  }

  async getStatus(
    requiredAssets: string[] = [],
  ): Promise<PublicSignerStatus> {
    let wallet: Address | null;
    try {
      wallet = await this.#wallet.getAddress();
    } catch {
      wallet = null;
    }
    const autonomyDecision = await this.autonomyStatus();
    const autonomyStatus = autonomyDecision.allowed
      ? autonomyDecision.value
      : null;
    const activePolicies =
      autonomyStatus?.policies.filter(({ policy }) =>
        ['active', 'paused'].includes(policy.lifecycle.state),
      ) ?? [];
    const current = activePolicies.at(-1)?.policy;
    const privacyReady = await this.#privacyOnboarding.isReady();
    const writesBlocked = this.#writesBlocked();
    const localDiagnosticCodes = this.#diagnosticCodes()
      .filter(isSafeAgentControlDiagnosticCode)
      .slice(0, 16);
    const status = buildPublicSignerStatus(
      this.#config,
      wallet,
      this.#confirmation.isWriteAvailable
        ? {
            isSupported: () => true,
            requestConfirmation: async () => ({ outcome: 'cancelled' }),
          }
        : null,
      privacyReady,
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
          ...localDiagnosticCodes,
          ...(writesBlocked ? ['signer-restart-required'] : []),
          ...(autonomyDecision.allowed
            ? []
            : [`autonomy-${autonomyDecision.denial.code.toLowerCase()}`]),
          this.#control?.controlPageReady
            ? 'control-page-ready'
            : 'control-page-starting',
        ],
      },
    );
    const uniqueRequiredAssets = [
      ...new Set(
        requiredAssets
          .map((asset) => asset.trim())
          .filter(Boolean),
      ),
    ].slice(0, 16);
    const assetReadiness = await Promise.all(
      uniqueRequiredAssets.map(async (asset) => {
        if (!privacyReady) {
          return {
            asset,
            status: 'privacy-onboarding-required' as const,
          };
        }
        try {
          const token = await this.#privateTokens.status(asset);
          return {
            asset: token.symbol,
            status: token.ready
              ? ('ready' as const)
              : ('private-token-setup-required' as const),
          };
        } catch (error) {
          return {
            asset,
            status:
              error &&
              typeof error === 'object' &&
              'code' in error &&
              error.code === 'UNSUPPORTED_TOOL'
                ? ('unsupported' as const)
                : ('unavailable' as const),
          };
        }
      }),
    );
    const pendingOperationIds = [
      ...new Set([
        ...(await this.#engine.listPendingOperationIds()),
        ...(await this.#messaging.listPendingOperationIds()),
      ]),
    ];
    const nextAction: PublicSignerStatus['nextAction'] = writesBlocked
      ? {
          tool: null,
          arguments: {},
          reason: 'signer-restart-required',
        }
      : !status.configured
        ? {
            tool: 'chainwhisper_open_control_panel',
            arguments: {},
            reason: 'wallet-setup-required',
          }
        : !privacyReady
          ? {
              tool: 'chainwhisper_open_control_panel',
              arguments: {},
              reason: 'privacy-onboarding-required',
            }
          : assetReadiness.some(
                ({ status: assetStatus }) =>
                  assetStatus ===
                  'private-token-setup-required',
              )
            ? {
                tool: 'chainwhisper_open_control_panel',
                arguments: {},
                reason: 'private-token-setup-required',
              }
            : pendingOperationIds.length > 0
              ? {
                  tool: 'chainwhisper_get_operation',
                  arguments: {
                    operationId: pendingOperationIds[0]!,
                  },
                  reason: 'pending-operation',
                }
              : status.controlPageReadiness !== 'ready'
                ? {
                    tool: 'chainwhisper_open_control_panel',
                    arguments: {},
                    reason: 'control-panel-required',
                  }
                : {
                    tool: null,
                    arguments: {},
                    reason: 'ready',
                  };
    const enriched: PublicSignerStatus = {
      ...status,
      requiredAssets: assetReadiness,
      pendingOperations: {
        count: pendingOperationIds.length,
        operationIds: pendingOperationIds.slice(0, 20),
      },
      nextAction,
    };
    return writesBlocked
      ? {
          ...enriched,
          mode: 'read-only',
          signerReadiness: 'confirmation-unavailable',
          diagnosticCodes: [
            ...new Set([
              ...enriched.diagnosticCodes,
              'signer-restart-required',
            ]),
          ],
        }
      : enriched;
  }

  async openControlPanel(): Promise<OpenControlPanelResult> {
    const result = this.#control
      ? await this.#control.openControlPanel()
      : {
          opened: false,
          ready: false,
          activePrompt: false,
          reason: 'server-unavailable' as const,
        };
    if (result.opened && result.ready) {
      await this.restorePendingOperations();
    }
    return result;
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
    return this.#engine.pauseAutonomy();
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

  async onboardPrivacy(): Promise<PrivacyOnboardingResult> {
    if (this.#writesBlocked()) {
      throw new Error('Restart the signer before performing writes.');
    }
    const result = await this.#privacyOnboarding.onboard();
    if (result.status === 'ready') {
      await this.#engine.markSetupCompleted();
    }
    return result;
  }

  getPrivateTokenStatus(
    token: string,
  ): Promise<PrivateTokenAccountStatus> {
    return this.#privateTokens.status(token);
  }

  async enablePrivateToken(
    token: string,
  ): Promise<PrivateTokenAccountSetupResult> {
    if (this.#writesBlocked()) {
      throw new Error('Restart the signer before performing writes.');
    }
    const result = await this.#privateTokens.enable(token);
    if (result.ready) await this.#engine.markSetupCompleted();
    return result;
  }

  getPrivateState(
    query: PrivateStateQueryV1,
    policyId?: string,
  ): Promise<PrivateStateDisclosureDecisionV1> {
    if (!this.#privateState) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'Private ChainWhisper state disclosure is unavailable in this signer session.',
      );
    }
    return this.#privateState.disclose(query, policyId);
  }

  executeAction(
    envelope: SignedActionEnvelopeV1,
    policyId?: string,
  ): Promise<OperationStatusV2> {
    if (this.#writesBlocked()) {
      return Promise.resolve({
        version: 'cw.operation-status/2',
        operationId: envelope.operationId,
        operationHash: envelope.operationHash,
        status: 'failed',
        summary: envelope.summary,
        transactionHashes: [],
        transactionLinks: [],
        userActionRequired: true,
        nextPollingIntervalMs: null,
        errorCode: 'SIGNER_RESTART_REQUIRED',
      });
    }
    return this.#engine.queueAction(envelope, policyId);
  }

  getOperation(
    operationId: string,
  ): Promise<OperationStatusV2 | null> {
    return isMessageOperationId(operationId)
      ? this.#messaging.getOperationStatus(operationId)
      : this.#engine.getOperationStatus(operationId);
  }

  async restorePendingOperations(): Promise<void> {
    await this.#messaging.restorePendingOperations();
    await this.#engine.restorePendingOperations();
  }

  recoverOperation(
    operationId: string,
    operationHash?: string,
  ): Promise<RecoverOperationResult> {
    return isMessageOperationId(operationId)
      ? this.#messaging.recoverOperation(operationId, operationHash)
      : this.#engine.recoverOperation(operationId, operationHash);
  }

  discardOperation(
    operationId: string,
    operationHash: string,
  ): Promise<RecoverOperationResult> {
    return this.#engine.discardOperation(operationId, operationHash);
  }
}
