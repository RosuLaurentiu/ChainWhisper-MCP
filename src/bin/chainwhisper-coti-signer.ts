#!/usr/bin/env node

import { resolve } from 'node:path';

import {
  getDefaultPrivateMessagingContractAddress,
} from '@coti-io/coti-sdk-private-messaging';
import { Wallet as EthersWallet, formatEther } from 'ethers';

import {
  connectStdioMcpServer,
  createJsonMcpServer,
  writeFatalMcpError,
} from '../server/index.js';
import { LiveChainWhisperDomainGateway } from '../domain/index.js';
import {
  CHAINWHISPER_AGENT_TOOLS_VERSION,
  HttpJsonRpcReader,
  hashRuntimeManifest,
  loadRuntimeManifest,
} from '../shared/index.js';
import {
  ACCOUNT_ONBOARD_CONTRACT,
  AgentActivityReader,
  AgentWalletBalanceReader,
  AbiCallTemplateMaterializer,
  ActionEnvelopeVerifier,
  AuditedRuntimeStateReader,
  AutonomyPolicyManager,
  ChainWhisperMessagingBridge,
  ChainWhisperSignerService,
  ConfirmationGate,
  ContractRuntimeFeeReader,
  ControlPageAutonomyApprovals,
  CotiSdkPrivateUint256Encoder,
  EncryptedSecretVault,
  HotSignerToolRouter,
  LocalWebFormElicitor,
  NonceQueue,
  OperationJournal,
  PrivacyOnboardingService,
  PrivateStateDisclosureService,
  PrivateTokenAccountService,
  RpcAllowlistedOrderMakerReader,
  RpcStandardOrderFactsReader,
  SignerEngine,
  StrictMaterializedIntentValidator,
  VaultAutonomyStore,
  VaultBackedPrivateInputMaterializer,
  acquireSignerInstanceLock,
  buildPublicSignerStatus,
  createCotiSignerRuntime,
  createOfficialMessagingInvoker,
  ensurePrivateStateDirectory,
  loadSignerConfig,
  pendingOperation,
  replacementBlockReason,
  resolveWalletPrivacyKey,
  safeAgentControlErrorCode,
  safeAgentControlErrorMessage,
  saveAgentWallet,
  signerStatusInputSchema,
  signerStatusRequiredAssets,
  type Address,
  type AgentControlAction,
  type AgentControlActionResult,
  type AgentControlSummary,
  type AutonomyStatusV1,
  type LoadedSignerConfig,
  type SignerInstanceLock,
  type WalletControlState,
} from '../signer/index.js';

const inactiveAutonomy = (): AutonomyStatusV1 => ({
  globalPaused: false,
  policies: [],
  activeReservationCount: 0,
});

const readCotiBalance = async (
  rpc: HttpJsonRpcReader,
  wallet: Address | null,
): Promise<string> => {
  if (!wallet) return 'Fund after wallet setup';
  try {
    const value = await rpc.request<string>('eth_getBalance', [
      wallet,
      'latest',
    ]);
    return `${formatEther(BigInt(value))} COTI`;
  } catch {
    return 'Balance unavailable';
  }
};

const startBoundControlServer = async (
  control: LocalWebFormElicitor,
  instanceLock: SignerInstanceLock,
): Promise<void> => {
  if (!(await control.startControlServer()) || control.controlPort === null) {
    throw new Error('The signer-owned Agent Control server could not start.');
  }
  await instanceLock.setControlPort(control.controlPort);
};

const createUnsafeConfigurationServer = (diagnostic: string) => {
  const server = createJsonMcpServer({
    name: 'chainwhisper-coti-signer',
    version: CHAINWHISPER_AGENT_TOOLS_VERSION,
    instructions:
      'The local signer refused unsafe or invalid configuration. No wallet, network, control-page, signing, messaging, or persistence operation is available until the local configuration is corrected.',
    tools: [
      {
        name: 'chainwhisper_signer_status',
        description:
          'Return a secret-safe local configuration diagnostic.',
        inputSchema: signerStatusInputSchema,
        annotations: { readOnlyHint: true },
        execute: async (raw) =>
          buildPublicSignerStatus(null, null, null, false, {
            diagnosticCodes: [diagnostic],
            requiredAssets: signerStatusRequiredAssets(raw),
          }),
      },
    ],
  });
  return server;
};

const configuredControlSummary = async (options: {
  wallet: Address;
  rpc: HttpJsonRpcReader;
  manifest: Awaited<ReturnType<typeof loadRuntimeManifest>>;
  journal: OperationJournal;
  service: ChainWhisperSignerService;
  autonomy: AutonomyPolicyManager;
  privacy: PrivacyOnboardingService;
  balances: AgentWalletBalanceReader;
  activity: AgentActivityReader;
  focusedOperationId?: string | null;
  walletControl: WalletControlState;
}): Promise<AgentControlSummary> => {
  const [operations, privacyReady, autonomyDecision, blockedReason, activity] =
    await Promise.all([
      options.journal.list(),
      options.privacy.isReady(),
      options.autonomy.status(),
      replacementBlockReason(options.journal, options.autonomy),
      options.activity.page(
        options.focusedOperationId
          ? 0
          : options.walletControl.activityPage ?? 0,
      ),
    ]);
  const autonomyStatus = autonomyDecision.allowed
    ? autonomyDecision.value
    : inactiveAutonomy();
  const current =
    autonomyStatus.policies
      .filter(({ policy }) =>
        ['active', 'paused'].includes(policy.lifecycle.state),
      )
      .at(-1) ?? null;
  const remaining = current?.remaining;
  const remainingBudgets = remaining
    ? [
        ...remaining.spendByAsset.map(({ asset, amount }) => ({
          label: `Spend ${asset}`,
          value: `${amount} base units`,
        })),
        ...(remaining.nativeValue === null
          ? []
          : [{ label: 'Native value', value: `${remaining.nativeValue} wei` }]),
        ...(remaining.networkFee === null
          ? []
          : [{ label: 'Network fees', value: `${remaining.networkFee} wei` }]),
        ...(remaining.actions === null
          ? []
          : [{ label: 'Actions', value: String(remaining.actions) }]),
      ...(remaining.messages === null
          ? []
          : [{ label: 'Messages', value: String(remaining.messages) }]),
      ]
    : undefined;
  const pending = operations.filter(pendingOperation);
  const pendingStatuses = new Map(
    await Promise.all(
      pending.map(async (operation) => [
        operation.operationId,
        await options.service
          .getOperation(operation.operationId)
          .catch(() => null),
      ] as const),
    ),
  );
  const recentOperations = await Promise.all(
    operations.slice(0, 5).map(async (operation) => {
      const semanticStatus = pendingStatuses.has(operation.operationId)
        ? pendingStatuses.get(operation.operationId) ?? null
        : await options.service
            .getOperation(operation.operationId)
            .catch(() => null);
      const fallbackTransaction = operation.transactionHashes.at(-1);
      const fallbackUrl = fallbackTransaction
        ? `${options.manifest.network.explorerUrl}/tx/${fallbackTransaction}`
        : undefined;
      const rawLabel =
        semanticStatus?.summary.trim() || 'ChainWhisper operation';
      const label = rawLabel.includes(operation.operationId)
        ? 'ChainWhisper operation'
        : rawLabel;
      const setupAssets =
        semanticStatus?.setupRequirement?.kind ===
        'private-token-setup'
          ? (
              await Promise.all(
                semanticStatus.setupRequirement.assets.map(
                  async (asset) => {
                    const token = options.manifest.tokens.find(
                      (candidate) =>
                        candidate.kind === 'private-erc20' &&
                        (candidate.symbol.toLowerCase() ===
                          asset.toLowerCase() ||
                          candidate.address?.toLowerCase() ===
                            asset.toLowerCase()),
                    );
                    if (!token) return null;
                    try {
                      return (await options.service.getPrivateTokenStatus(
                        token.symbol,
                      )).ready
                        ? null
                        : token.symbol;
                    } catch {
                      return token.symbol;
                    }
                  },
                ),
              )
            ).filter((asset): asset is string => asset !== null)
          : [];
      return {
        label,
        status: semanticStatus?.status ?? 'uncertain',
        operationId: operation.operationId,
        operationHash: operation.operationHash,
        recoverable:
          operation.stage !== 'completed' &&
          operation.stage !== 'declined' &&
          operation.stage !== 'discarded',
        discardable:
          operation.stage !== 'completed' &&
          operation.stage !== 'discarded' &&
          operation.stage !== 'prepared-broadcast' &&
          operation.stage !== 'broadcast' &&
          !(
            operation.stage === 'awaiting-broadcast' &&
            operation.transactionHashes.length > 0
          ),
        ...(semanticStatus?.transactionLinks.at(-1) ?? fallbackUrl
          ? {
              transactionUrl:
                semanticStatus?.transactionLinks.at(-1) ?? fallbackUrl,
            }
          : {}),
        ...(setupAssets.length > 0 ? { setupAssets } : {}),
      };
    }),
  );
  const requiredBalanceAssets = [
    ...[...pendingStatuses.values()].flatMap(
      (status) => status?.setupRequirement?.assets ?? [],
    ),
    ...activity.recentEntries
      .flatMap(({ pair }) =>
        pair
          ? pair
              .split('/')
              .map((asset) => asset.trim())
              .filter(Boolean)
          : [],
      ),
  ];
  const balances = await options.balances.snapshot(
    requiredBalanceAssets,
  );
  return {
    wallet: options.wallet,
    network: options.manifest.network.name,
    balances,
    privacyStatus: privacyReady ? 'ready' : 'onboarding-required',
    signerStatus: options.walletControl.restartRequired
      ? 'read-only'
      : 'ready',
    autonomy: current
      ? {
          mode: current.policy.mode,
          state: current.policy.lifecycle.state,
          expiresAt: current.policy.expiresAt,
          agentVisiblePrivateAmounts:
            current.policy.agentVisiblePrivateAmounts,
          ...(remainingBudgets ? { remainingBudgets } : {}),
        }
      : { mode: 'manual' },
    pendingOperations: pending.length,
    recentOperations,
    activity,
    focusedOperationId: options.focusedOperationId ?? null,
    diagnostics: [
      {
        label: 'Signer',
        value: options.walletControl.restartRequired
          ? 'signer-restart-required'
          : 'ready',
      },
      {
        label: 'Runtime',
        value: 'runtime-attestation-required-before-every-write',
      },
      ...(options.walletControl.lastDiagnostic
        ? [
            {
              label: 'Agent Control',
              value: options.walletControl.lastDiagnostic,
            },
          ]
        : []),
    ],
    walletSetup: {
      required: false,
      environmentFilePath: options.walletControl.environmentFilePath,
      restartRequired: options.walletControl.restartRequired,
      ...(blockedReason ? { replacementBlockedReason: blockedReason } : {}),
      ...(options.walletControl.generatedBackup
        ? { generatedBackup: options.walletControl.generatedBackup }
        : {}),
    },
    controlActions: {
      onboardPrivacy: !privacyReady && !options.walletControl.restartRequired,
      enablePrivateToken:
        privacyReady && !options.walletControl.restartRequired,
      refreshBalances: !options.walletControl.restartRequired,
      pause:
        Boolean(current) &&
        !autonomyStatus.globalPaused &&
        current?.policy.lifecycle.state === 'active',
      resume:
        Boolean(current) &&
        (autonomyStatus.globalPaused ||
          current?.policy.lifecycle.state === 'paused'),
      revoke: Boolean(current),
    },
  };
};

type ConfiguredSignerRuntime = {
  config: LoadedSignerConfig;
  wallet: Address;
  rpc: HttpJsonRpcReader;
  manifest: Awaited<ReturnType<typeof loadRuntimeManifest>>;
  journal: OperationJournal;
  privacy: PrivacyOnboardingService;
  balances: AgentWalletBalanceReader;
  activity: AgentActivityReader;
  autonomy: AutonomyPolicyManager;
  autonomyApprovals: ControlPageAutonomyApprovals;
  service: ChainWhisperSignerService;
};

const initializeConfiguredSigner = async (
  config: LoadedSignerConfig,
  control: LocalWebFormElicitor,
  walletControl: WalletControlState,
): Promise<ConfiguredSignerRuntime> => {
  const manifest = await loadRuntimeManifest();
  const credentials = config.credentialMaterial();
  const walletAddress = new EthersWallet(
    credentials.privateKey,
  ).address.toLowerCase() as Address;
  const walletStateDirectory = resolve(
    config.stateDirectory,
    'wallets',
    walletAddress,
  );
  await ensurePrivateStateDirectory(walletStateDirectory);
  const rpc = new HttpJsonRpcReader(config.rpcUrl);
  const feeReader = new ContractRuntimeFeeReader({
    rpc,
    actionContracts: Object.fromEntries(
      ['standardEscrow', 'privateEscrow', 'directEscrow', 'recurringEscrow']
        .map((name) => manifest.contracts[name]?.address)
        .filter((address): address is Address => Boolean(address))
        .map((address) => [address.toLowerCase(), address]),
    ),
    editFeeModes: Object.fromEntries(
      ([
        ['standardEscrow', 'contract-flag'],
        ['privateEscrow', 'always'],
        ['directEscrow', 'always'],
        ['recurringEscrow', 'never'],
      ] as const).flatMap(([name, mode]) => {
        const address = manifest.contracts[name]?.address;
        return address ? [[address.toLowerCase(), mode]] : [];
      }),
    ) as Record<string, 'always' | 'never' | 'contract-flag'>,
  });
  const runtimeState = new AuditedRuntimeStateReader({
    loadManifest: async () => manifest,
    rpc,
    fees: feeReader,
  });
  const vault = new EncryptedSecretVault(
    walletStateDirectory,
    credentials.vaultPassphrase,
  );
  const walletPrivacyKey = await resolveWalletPrivacyKey(
    vault,
    config,
    walletAddress,
  );
  const runtime = createCotiSignerRuntime(
    config,
    // An unbound root-vault key is deliberately not migrated. A wallet with
    // no namespaced key must re-onboard unless an explicitly wallet-pinned
    // legacy environment/JSON key is available.
    walletPrivacyKey,
  );
  const actualWallet = await runtime.transport.getAddress();
  if (actualWallet.toLowerCase() !== walletAddress) {
    throw new Error('The configured Agent Wallet address changed unexpectedly.');
  }
  const journal = new OperationJournal(walletStateDirectory);
  const confirmation = new ConfirmationGate(
    control,
    config.confirmationTimeoutMs,
  );
  const autonomyApprovals = new ControlPageAutonomyApprovals(confirmation);
  const autonomy = new AutonomyPolicyManager({
    store: new VaultAutonomyStore({
      vault,
      wallet: walletAddress,
    }),
    approvals: autonomyApprovals,
  });
  const nonceQueue = new NonceQueue(() =>
    runtime.transport.getPendingNonce(),
  );
  const assertRuntimeAttested = async (): Promise<void> => {
    if (walletControl.restartRequired) {
      throw new Error('Restart the signer before performing writes.');
    }
    const state = await runtimeState.readRegistryState();
    if (
      state.registryHash.toLowerCase() !==
      hashRuntimeManifest(manifest).toLowerCase()
    ) {
      throw new Error('The audited runtime manifest changed unexpectedly.');
    }
  };
  const messagingAddress = getDefaultPrivateMessagingContractAddress(
    'mainnet',
  ) as Address;
  if (
    manifest.attestations.cotiPrivateMessaging?.address.toLowerCase() !==
      messagingAddress.toLowerCase() ||
    manifest.attestations.cotiAccountOnboarding?.address.toLowerCase() !==
      ACCOUNT_ONBOARD_CONTRACT.toLowerCase()
  ) {
    throw new Error(
      'Signer write targets do not match the audited runtime manifest.',
    );
  }
  const privateTokens = new PrivateTokenAccountService({
    manifest,
    rpc,
    wallet: runtime.transport,
    cotiWallet: runtime.wallet,
    confirmation,
    simulator: runtime.simulator,
    nonceQueue,
    journal,
    assertRuntimeAttested,
  });
  const privateState = new PrivateStateDisclosureService({
    manifest,
    manifestHash: hashRuntimeManifest(manifest),
    rpc,
    wallet: runtime.transport,
    privacyKey: () =>
      runtime.wallet.getUserOnboardInfo()?.aesKey ?? null,
    confirmation,
    autonomy,
    assertRuntimeAttested,
  });
  const balances = new AgentWalletBalanceReader({
    wallet: walletAddress,
    rpc,
    manifest,
    privacyKey: () =>
      runtime.wallet.getUserOnboardInfo()?.aesKey ?? null,
  });
  const verifier = new ActionEnvelopeVerifier(config, runtimeState);
  const materializer = new VaultBackedPrivateInputMaterializer({
    vault,
    privateUint256: new CotiSdkPrivateUint256Encoder(
      runtime.wallet,
      credentials.aesKey,
    ),
    calldata: new AbiCallTemplateMaterializer(),
    elicitor: control,
    aesKey: () => runtime.wallet.getUserOnboardInfo()?.aesKey ?? '',
    timeoutMs: config.confirmationTimeoutMs,
    assertPrivateSpendReady: (input) =>
      privateTokens.assertSpendReady(input),
  });
  const engine = new SignerEngine({
    verifier,
    wallet: runtime.transport,
    materializer,
    confirmation,
    simulator: runtime.simulator,
    intentValidator: new StrictMaterializedIntentValidator({
      standardOrders: new RpcStandardOrderFactsReader(rpc),
    }),
    journal,
    vault,
    nonceQueue,
    autonomy,
  });
  const messaging = new ChainWhisperMessagingBridge({
    invoke: createOfficialMessagingInvoker(runtime.messagingClient),
    wallet: runtime.transport,
    orderMakers: new RpcAllowlistedOrderMakerReader({
      rpc,
      manifest,
    }),
    messagingContract: messagingAddress,
    confirmation,
    nonceQueue,
    journal,
    vault,
    autonomy,
    manifestHash: hashRuntimeManifest(manifest),
    assertRuntimeAttested,
  });
  const privacyOnboarding = new PrivacyOnboardingService({
    wallet: runtime.wallet,
    vault,
    confirmation,
    nonceQueue,
    journal,
    assertRuntimeAttested,
  });
  const service = new ChainWhisperSignerService({
    config,
    wallet: runtime.transport,
    confirmation,
    engine,
    messaging,
    privacyOnboarding,
    privateTokens,
    privateState,
    control,
    autonomy,
    writesBlocked: () => walletControl.restartRequired,
    diagnosticCodes: () =>
      walletControl.lastDiagnosticCode
        ? [walletControl.lastDiagnosticCode]
        : [],
    manifestHash: hashRuntimeManifest(manifest),
  });
  const activity = new AgentActivityReader({
    wallet: walletAddress,
    journal,
    vault,
    orders: new LiveChainWhisperDomainGateway({
      manifest,
      rpc,
    }),
    getOperationStatus: (operationId) =>
      service.getOperation(operationId),
    explorerUrl: manifest.network.explorerUrl,
  });
  await service.restorePendingOperations();
  return {
    config,
    wallet: walletAddress,
    rpc,
    manifest,
    journal,
    privacy: privacyOnboarding,
    balances,
    activity,
    autonomy,
    autonomyApprovals,
    service,
  };
};

const handleConfiguredControlAction = async (
  runtime: ConfiguredSignerRuntime,
  walletControl: WalletControlState,
  action: AgentControlAction,
  fields: Readonly<Record<string, string>>,
): Promise<AgentControlActionResult> => {
  const {
    autonomy,
    autonomyApprovals,
    journal,
    manifest,
    service,
  } = runtime;
  if (action === 'clear-wallet-backup') {
    walletControl.generatedBackup = null;
    return { ok: true, message: 'Generated wallet backup view cleared.' };
  }
  if (action === 'refresh-balances') {
    await runtime.balances.refresh();
    return { ok: true, message: 'Wallet balances refreshed.' };
  }
  if (action === 'history-previous') {
    walletControl.activityPage = Math.max(
      0,
      (walletControl.activityPage ?? 0) - 1,
    );
    return {
      ok: true,
      message: `Showing activity page ${walletControl.activityPage + 1}.`,
    };
  }
  if (action === 'history-next') {
    walletControl.activityPage = Math.min(
      49,
      (walletControl.activityPage ?? 0) + 1,
    );
    return {
      ok: true,
      message: `Showing activity page ${walletControl.activityPage + 1}.`,
    };
  }
  if (action === 'import-wallet' || action === 'generate-wallet') {
    const blockedReason = await replacementBlockReason(journal, autonomy);
    return saveAgentWallet({
      action,
      fields,
      state: walletControl,
      replacing: true,
      replacementBlockedReason: blockedReason,
    });
  }
  if (action === 'pause-autonomy') {
    const paused = await service.pauseAutonomy();
    return paused.allowed
      ? { ok: true, message: 'Autonomy paused immediately.' }
      : { ok: false, message: paused.denial.message };
  }
  if (action === 'resume-autonomy') {
    autonomyApprovals.preapproveNextResumeFromControlPage();
    const resumed = await service.resumeAutonomy();
    return resumed.allowed
      ? { ok: true, message: 'Autonomy resumed under unchanged terms.' }
      : { ok: false, message: resumed.denial.message };
  }
  if (action === 'revoke-autonomy') {
    const status = await service.autonomyStatus();
    const current = status.allowed
      ? status.value.policies
          .filter(({ policy }) =>
            ['active', 'paused'].includes(policy.lifecycle.state),
          )
          .at(-1)?.policy
      : undefined;
    if (!current) {
      return { ok: false, message: 'No active autonomy policy exists.' };
    }
    autonomyApprovals.preapproveNextRevocationFromControlPage(current.id);
    const revoked = await service.revokeAutonomy(current.id);
    return revoked.allowed
      ? { ok: true, message: 'Autonomy policy permanently revoked.' }
      : { ok: false, message: revoked.denial.message };
  }
  if (action === 'onboard-privacy') {
    walletControl.lastDiagnostic =
      'privacy-onboarding-awaiting-local-confirmation';
    walletControl.lastDiagnosticCode =
      'privacy-onboarding-awaiting-local-confirmation';
    void service
      .onboardPrivacy()
      .then(async () => {
        runtime.balances.invalidate();
        await runtime.balances.refresh().catch(() => undefined);
        walletControl.lastDiagnostic = 'privacy-ready';
        walletControl.lastDiagnosticCode = 'privacy-ready';
      })
      .catch((error: unknown) => {
        walletControl.lastDiagnostic = safeAgentControlErrorMessage(error);
        walletControl.lastDiagnosticCode =
          safeAgentControlErrorCode(error);
      });
    return {
      ok: true,
      message: 'Privacy onboarding review is opening in Agent Control.',
    };
  }
  if (action === 'enable-private-token') {
    const token = fields.token?.trim();
    if (!token) {
      return {
        ok: false,
        message: 'Choose a verified private token.',
      };
    }
    const verifiedToken = manifest.tokens.find(
      (candidate) =>
        candidate.kind === 'private-erc20' &&
        Boolean(candidate.address) &&
        (candidate.symbol.toLowerCase() === token.toLowerCase() ||
          candidate.address?.toLowerCase() === token.toLowerCase()),
    );
    if (!verifiedToken) {
      return {
        ok: false,
        message:
          'Only a verified private token from the signed runtime manifest can be prepared.',
      };
    }
    walletControl.lastDiagnostic =
      'private-token-setup-awaiting-local-confirmation';
    walletControl.lastDiagnosticCode =
      'private-token-setup-awaiting-local-confirmation';
    void service
      .enablePrivateToken(verifiedToken.symbol)
      .then((result) => {
        runtime.balances.invalidate();
        walletControl.lastDiagnostic = result.ready
          ? `private-token-${result.symbol}-ready`
          : 'private-token-setup-incomplete';
        walletControl.lastDiagnosticCode = result.ready
          ? 'private-token-ready'
          : 'private-token-setup-incomplete';
      })
      .catch((error: unknown) => {
        walletControl.lastDiagnostic = safeAgentControlErrorMessage(error);
        walletControl.lastDiagnosticCode =
          safeAgentControlErrorCode(error);
      });
    return {
      ok: true,
      message: 'Private-token setup review is opening in Agent Control.',
    };
  }
  if (action === 'recover-operation') {
    const operationId = fields.operationId?.trim();
    if (!operationId) {
      return { ok: false, message: 'Enter a local operation ID.' };
    }
    try {
      const result = await service.recoverOperation(operationId);
      walletControl.lastDiagnostic = `operation-recovery-${result.status}`;
      walletControl.lastDiagnosticCode =
        `operation-recovery-${result.status}`;
      return {
        ok: true,
        message: `Operation recovery completed with status ${result.status}.`,
      };
    } catch (error) {
      walletControl.lastDiagnostic = safeAgentControlErrorMessage(error);
      walletControl.lastDiagnosticCode =
        safeAgentControlErrorCode(error);
      return { ok: false, message: walletControl.lastDiagnostic };
    }
  }
  if (action === 'discard-operation') {
    const operationId = fields.operationId?.trim();
    const operationHash = fields.operationHash?.trim();
    if (!operationId || !operationHash) {
      return {
        ok: false,
        message: 'Enter the operation ID and exact operation hash.',
      };
    }
    try {
      const record = await journal.get(operationId);
      if (!record) {
        return {
          ok: false,
          message: 'No local operation matches this identifier.',
        };
      }
      if (
        record.operationHash.toLowerCase() !== operationHash.toLowerCase()
      ) {
        return {
          ok: false,
          message: 'Operation hash does not match the local journal.',
        };
      }
    } catch (error) {
      return {
        ok: false,
        message: safeAgentControlErrorMessage(error),
      };
    }
    walletControl.lastDiagnostic =
      'operation-discard-awaiting-local-confirmation';
    walletControl.lastDiagnosticCode =
      'operation-discard-awaiting-local-confirmation';
    void service
      .discardOperation(operationId, operationHash)
      .then(() => {
        walletControl.lastDiagnostic = 'operation-discarded';
        walletControl.lastDiagnosticCode = 'operation-discarded';
      })
      .catch((error: unknown) => {
        walletControl.lastDiagnostic = safeAgentControlErrorMessage(error);
        walletControl.lastDiagnosticCode =
          safeAgentControlErrorCode(error);
      });
    return {
      ok: true,
      message: 'Exact discard review is opening in Agent Control.',
    };
  }
  return { ok: false, message: 'Unsupported Agent Control action.' };
};

const runSigner = async (
  initialConfig: LoadedSignerConfig,
  instanceLock: SignerInstanceLock,
): Promise<void> => {
  const walletControl: WalletControlState = {
    environmentFilePath:
      initialConfig.environmentFilePath ??
      resolve(initialConfig.stateDirectory, 'signer.env'),
    displayAddress: initialConfig.walletConfigured
      ? (new EthersWallet(
          initialConfig.credentialMaterial().privateKey,
        ).address.toLowerCase() as Address)
      : null,
    generatedBackup: null,
    restartRequired: false,
    lastDiagnostic: null,
    lastDiagnosticCode: null,
  };
  const setupRpc = new HttpJsonRpcReader(initialConfig.rpcUrl);
  let active: ConfiguredSignerRuntime | null = null;
  let activation: Promise<void> | null = null;

  const activateFromEnvironmentFile = async (
    failOnError = false,
  ): Promise<void> => {
    if (active) return;
    const pending =
      activation ??
      (async () => {
        const config = await loadSignerConfig({
          ...process.env,
          CHAINWHISPER_SIGNER_ENV_FILE:
            walletControl.environmentFilePath,
          CHAINWHISPER_SIGNER_STATE_DIRECTORY:
            initialConfig.stateDirectory,
        });
        if (!config.walletConfigured) return;
        const configured = await initializeConfiguredSigner(
          config,
          control,
          walletControl,
        );
        active = configured;
        walletControl.displayAddress = configured.wallet;
        walletControl.restartRequired = false;
        walletControl.lastDiagnostic = 'agent-wallet-ready';
        walletControl.lastDiagnosticCode = 'agent-wallet-ready';
        router.activate(configured.service);
      })();
    activation = pending;
    try {
      await pending;
    } catch (error) {
      walletControl.restartRequired = false;
      walletControl.lastDiagnostic = safeAgentControlErrorMessage(error);
      walletControl.lastDiagnosticCode =
        safeAgentControlErrorCode(error);
      if (failOnError) throw error;
    } finally {
      if (activation === pending) activation = null;
    }
  };

  const control = new LocalWebFormElicitor({
    getControlSummary: async (): Promise<AgentControlSummary> => {
      if (active) {
        return configuredControlSummary({
          wallet: active.wallet,
          rpc: active.rpc,
          manifest: active.manifest,
          journal: active.journal,
          service: active.service,
          autonomy: active.autonomy,
          privacy: active.privacy,
          balances: active.balances,
          activity: active.activity,
          focusedOperationId: control.focusedOperationId,
          walletControl,
        });
      }
      return {
        wallet: walletControl.displayAddress,
        network: 'COTI Mainnet',
        balance: await readCotiBalance(
          setupRpc,
          walletControl.displayAddress,
        ),
        privacyStatus: 'onboarding-required',
        signerStatus: 'setup-required',
        autonomy: { mode: 'manual' },
        pendingOperations: 0,
        recentOperations: [],
        diagnostics: [
          {
            label: 'Setup',
            value:
              walletControl.lastDiagnostic ?? 'wallet-setup-required',
          },
        ],
        walletSetup: {
          required: true,
          environmentFilePath: walletControl.environmentFilePath,
          restartRequired: false,
          ...(walletControl.generatedBackup
            ? { generatedBackup: walletControl.generatedBackup }
            : {}),
        },
      };
    },
    onControlAction: async (action, fields) => {
      if (active) {
        return handleConfiguredControlAction(
          active,
          walletControl,
          action,
          fields,
        );
      }
      if (action === 'clear-wallet-backup') {
        walletControl.generatedBackup = null;
        return { ok: true, message: 'Generated wallet backup view cleared.' };
      }
      if (action !== 'import-wallet' && action !== 'generate-wallet') {
        return {
          ok: false,
          message: 'Finish Agent Wallet setup before using this control.',
        };
      }
      const saved = await saveAgentWallet({
        action,
        fields,
        state: walletControl,
        replacing: false,
        activateInProcess: true,
      });
      if (!saved.ok) return saved;
      try {
        await activateFromEnvironmentFile(true);
        return {
          ok: true,
          message:
            action === 'generate-wallet'
              ? 'Agent Wallet created and active. Back up the displayed private key, then fund the wallet and enable private trading.'
              : 'Agent Wallet imported and active. Fund the wallet and enable private trading when ready.',
        };
      } catch (error) {
        return {
          ok: false,
          message: safeAgentControlErrorMessage(error),
        };
      }
    },
  });

  const router = new HotSignerToolRouter({
    getStatus: async (requiredAssets) =>
      buildPublicSignerStatus(
        initialConfig,
        walletControl.displayAddress,
        control,
        false,
        {
          controlPageReadiness: control.controlPageReady
            ? 'ready'
            : 'starting',
          requiredAssets,
          diagnosticCodes: [
            walletControl.lastDiagnosticCode ??
              'wallet-setup-required',
            control.controlPageReady
              ? 'control-page-ready'
              : 'control-page-starting',
          ],
        },
      ),
    openControlPanel: () => control.openControlPanel(),
    autonomyStatus: async () => ({
      allowed: true,
      value: inactiveAutonomy(),
    }),
    activateFromEnvironmentFile,
  });

  await startBoundControlServer(control, instanceLock);
  if (initialConfig.walletConfigured) {
    await activateFromEnvironmentFile(true);
  }
  const server = createJsonMcpServer({
    name: 'chainwhisper-coti-signer',
    version: CHAINWHISPER_AGENT_TOOLS_VERSION,
    instructions:
      'Local ChainWhisper COTI signer. Its complete public tool catalog stays stable while Agent Control sets up the first wallet and activates the verified runtime in this process. Wallet credentials, privacy material, policies, and signing authority remain local. Manual actions open signer-owned Agent Control once per complete logical action. Only audited ChainWhisper contracts, selectors, Privacy Portal routes, and embedded official COTI private messaging are supported.',
    tools: router.tools,
  });
  try {
    await connectStdioMcpServer(server);
  } finally {
    await control.close();
  }
};

const main = async (): Promise<void> => {
  let config: LoadedSignerConfig;
  try {
    config = await loadSignerConfig();
  } catch (error) {
    const diagnostic =
      error &&
      typeof error === 'object' &&
      'diagnosticCode' in error &&
      typeof error.diagnosticCode === 'string'
        ? error.diagnosticCode
        : 'configuration-invalid';
    await connectStdioMcpServer(
      createUnsafeConfigurationServer(diagnostic),
    );
    return;
  }
  const instanceLock = await acquireSignerInstanceLock(
    config.stateDirectory,
  );
  try {
    await runSigner(config, instanceLock);
  } finally {
    await instanceLock.release();
  }
};

main().catch((error) => {
  writeFatalMcpError(error, 'chainwhisper-coti-signer');
  process.exitCode = 1;
});
