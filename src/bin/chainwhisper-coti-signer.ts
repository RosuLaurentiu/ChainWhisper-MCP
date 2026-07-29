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
  type JsonMcpTool,
} from '../server/index.js';
import {
  CHAINWHISPER_AGENT_TOOLS_VERSION,
  HttpJsonRpcReader,
  hashRuntimeManifest,
  loadRuntimeManifest,
} from '../shared/index.js';
import {
  ACCOUNT_ONBOARD_CONTRACT,
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
  LocalWebFormElicitor,
  NonceQueue,
  OperationJournal,
  PrivacyOnboardingService,
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
  createSignerTools,
  ensurePrivateStateDirectory,
  loadSignerConfig,
  pendingOperation,
  replacementBlockReason,
  resolveWalletPrivacyKey,
  safeAgentControlErrorMessage,
  saveAgentWallet,
  type Address,
  type AgentControlSummary,
  type AutonomyStatusV1,
  type LoadedSignerConfig,
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
        inputSchema: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
        execute: async () =>
          buildPublicSignerStatus(null, null, null, false, {
            diagnosticCodes: [diagnostic],
          }),
      },
    ],
  });
  return server;
};

const setupSignerTools = (
  config: LoadedSignerConfig,
  control: LocalWebFormElicitor,
): JsonMcpTool[] => [
  {
    name: 'chainwhisper_signer_status',
    description:
      'Report wallet setup and local Agent Control readiness without exposing credentials.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async () =>
      buildPublicSignerStatus(config, null, control, false, {
        controlPageReadiness: control.controlPageReady
          ? 'ready'
          : 'starting',
        diagnosticCodes: [
          'wallet-setup-required',
          control.controlPageReady
            ? 'control-page-ready'
            : 'control-page-starting',
        ],
      }),
  },
  {
    name: 'chainwhisper_open_control_panel',
    description:
      'Open local ChainWhisper Agent Control for Agent Wallet import or generation. The URL, session, and credentials are never returned to the agent.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    execute: () => control.openControlPanel(),
  },
  {
    name: 'chainwhisper_autonomy_status',
    description:
      'Report that autonomy is inactive until an Agent Wallet is configured.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true },
    execute: async () => ({ allowed: true, value: inactiveAutonomy() }),
  },
];

const runWalletSetupSigner = async (
  config: LoadedSignerConfig,
): Promise<void> => {
  const rpc = new HttpJsonRpcReader(config.rpcUrl);
  const state: WalletControlState = {
    environmentFilePath:
      config.environmentFilePath ??
      resolve(config.stateDirectory, 'signer.env'),
    displayAddress: null,
    generatedBackup: null,
    restartRequired: false,
    lastDiagnostic: null,
  };
  const control = new LocalWebFormElicitor({
    getControlSummary: async (): Promise<AgentControlSummary> => ({
      wallet: state.displayAddress,
      network: 'COTI Mainnet',
      balance: await readCotiBalance(rpc, state.displayAddress),
      privacyStatus: 'onboarding-required',
      signerStatus: 'setup-required',
      autonomy: { mode: 'manual' },
      pendingOperations: 0,
      recentOperations: [],
      diagnostics: [
        {
          label: 'Setup',
          value:
            state.lastDiagnostic ?? 'wallet-setup-required',
        },
      ],
      walletSetup: {
        required: true,
        environmentFilePath: state.environmentFilePath,
        restartRequired: state.restartRequired,
        ...(state.generatedBackup
          ? { generatedBackup: state.generatedBackup }
          : {}),
      },
    }),
    onControlAction: async (action, fields) => {
      if (action === 'clear-wallet-backup') {
        state.generatedBackup = null;
        return {
          ok: true,
          message:
            'Backup view cleared. Restart the signer to load the Agent Wallet.',
        };
      }
      if (action !== 'import-wallet' && action !== 'generate-wallet') {
        return {
          ok: false,
          message: 'Finish Agent Wallet setup before using this control.',
        };
      }
      return saveAgentWallet({
        action,
        fields,
        state,
        replacing: false,
      });
    },
  });
  await control.startControlServer();
  const server = createJsonMcpServer({
    name: 'chainwhisper-coti-signer',
    version: CHAINWHISPER_AGENT_TOOLS_VERSION,
    instructions:
      'Local ChainWhisper signer in wallet-setup-required mode. Use chainwhisper_open_control_panel; wallet import and generation exist only on that signer-owned local page. No credentials are accepted through MCP.',
    tools: setupSignerTools(config, control),
  });
  try {
    await connectStdioMcpServer(server);
  } finally {
    await control.close();
  }
};

const configuredControlSummary = async (options: {
  wallet: Address;
  rpc: HttpJsonRpcReader;
  manifest: Awaited<ReturnType<typeof loadRuntimeManifest>>;
  journal: OperationJournal;
  autonomy: AutonomyPolicyManager;
  privacy: PrivacyOnboardingService;
  walletControl: WalletControlState;
}): Promise<AgentControlSummary> => {
  const [balance, operations, privacyReady, autonomyDecision, blockedReason] =
    await Promise.all([
      readCotiBalance(options.rpc, options.wallet),
      options.journal.list(),
      options.privacy.isReady(),
      options.autonomy.status(),
      replacementBlockReason(options.journal, options.autonomy),
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
  return {
    wallet: options.wallet,
    network: options.manifest.network.name,
    balance,
    privacyStatus: privacyReady ? 'ready' : 'onboarding-required',
    signerStatus: options.walletControl.restartRequired
      ? 'read-only'
      : 'ready',
    autonomy: current
      ? {
          mode: current.policy.mode,
          state: current.policy.lifecycle.state,
          expiresAt: current.policy.expiresAt,
          ...(remainingBudgets ? { remainingBudgets } : {}),
        }
      : { mode: 'manual' },
    pendingOperations: pending.length,
    recentOperations: operations.slice(0, 8).map((operation) => ({
      label: operation.operationId,
      status: operation.stage,
      ...(operation.transactionHashes.at(-1)
        ? {
            transactionUrl: `${options.manifest.network.explorerUrl}/tx/${operation.transactionHashes.at(-1)}`,
          }
        : {}),
    })),
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

const runConfiguredSigner = async (
  config: LoadedSignerConfig,
): Promise<void> => {
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
  const walletControl: WalletControlState = {
    environmentFilePath:
      config.environmentFilePath ??
      resolve(config.stateDirectory, 'signer.env'),
    displayAddress: walletAddress,
    generatedBackup: null,
    restartRequired: false,
    lastDiagnostic: null,
  };
  let service: ChainWhisperSignerService | null = null;
  let privacyOnboarding: PrivacyOnboardingService | null = null;
  let autonomy: AutonomyPolicyManager | null = null;
  let autonomyApprovals: ControlPageAutonomyApprovals | null = null;
  const control = new LocalWebFormElicitor({
    getControlSummary: async () =>
      service && privacyOnboarding && autonomy
        ? configuredControlSummary({
            wallet: walletAddress,
            rpc,
            manifest,
            journal,
            autonomy,
            privacy: privacyOnboarding,
            walletControl,
          })
        : {
            wallet: walletAddress,
            network: manifest.network.name,
            signerStatus: 'unavailable',
            privacyStatus: 'unknown',
            autonomy: { mode: 'manual' },
            diagnostics: [
              { label: 'Signer', value: 'starting' },
            ],
          },
    onControlAction: async (action, fields) => {
      if (!service || !autonomy || !autonomyApprovals) {
        return { ok: false, message: 'The signer is still starting.' };
      }
      if (action === 'clear-wallet-backup') {
        walletControl.generatedBackup = null;
        return { ok: true, message: 'Generated wallet backup view cleared.' };
      }
      if (action === 'import-wallet' || action === 'generate-wallet') {
        const blockedReason = await replacementBlockReason(
          journal,
          autonomy,
        );
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
        autonomyApprovals.preapproveNextRevocationFromControlPage(
          current.id,
        );
        const revoked = await service.revokeAutonomy(current.id);
        return revoked.allowed
          ? { ok: true, message: 'Autonomy policy permanently revoked.' }
          : { ok: false, message: revoked.denial.message };
      }
      if (action === 'onboard-privacy') {
        walletControl.lastDiagnostic =
          'privacy-onboarding-awaiting-local-confirmation';
        void service
          .onboardPrivacy()
          .then(() => {
            walletControl.lastDiagnostic = 'privacy-ready';
          })
          .catch((error: unknown) => {
            walletControl.lastDiagnostic =
              safeAgentControlErrorMessage(error);
          });
        return {
          ok: true,
          message:
            'Privacy onboarding review is opening in Agent Control.',
        };
      }
      return { ok: false, message: 'Unsupported Agent Control action.' };
    },
  });
  const confirmation = new ConfirmationGate(
    control,
    config.confirmationTimeoutMs,
  );
  autonomyApprovals = new ControlPageAutonomyApprovals(confirmation);
  autonomy = new AutonomyPolicyManager({
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
  privacyOnboarding = new PrivacyOnboardingService({
    wallet: runtime.wallet,
    vault,
    confirmation,
    nonceQueue,
    assertRuntimeAttested,
  });
  service = new ChainWhisperSignerService({
    config,
    wallet: runtime.transport,
    confirmation,
    engine,
    messaging,
    privacyOnboarding,
    privateTokens,
    control,
    autonomy,
    writesBlocked: () => walletControl.restartRequired,
    manifestHash: hashRuntimeManifest(manifest),
  });
  await control.startControlServer();
  const server = createJsonMcpServer({
    name: 'chainwhisper-coti-signer',
    version: CHAINWHISPER_AGENT_TOOLS_VERSION,
    instructions:
      'Local ChainWhisper COTI signer. Agent Wallet credentials, privacy material, policies, and signing authority stay in this process. Manual actions open signer-owned Agent Control once per complete logical action. A supplied policyId must match an active wallet-bound policy or the write is denied without a fallback prompt. Only audited ChainWhisper contracts, selectors, Privacy Portal routes, and embedded official COTI private messaging are supported.',
    tools: createSignerTools(service),
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
    if (!config.walletConfigured) {
      await runWalletSetupSigner(config);
      return;
    }
    await runConfiguredSigner(config);
  } finally {
    await instanceLock.release();
  }
};

main().catch((error) => {
  writeFatalMcpError(error, 'chainwhisper-coti-signer');
  process.exitCode = 1;
});
