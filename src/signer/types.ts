import type {
  OrderClassificationV1,
  SignedActionEnvelopeV1,
} from '../shared/index.js';

export type HexString = `0x${string}`;
export type Address = `0x${string}`;

export type SignerSecrets = {
  privateKey: HexString;
  aesKey: string;
  pairingSecret: string;
  vaultPassphrase: string;
};

export type SignerRuntimeConfig = {
  chainId: number;
  rpcUrl: string;
  stateDirectory: string;
  expectedWallet?: Address;
  confirmationChannel?: 'mcp' | 'local-web';
  confirmationTimeoutMs: number;
  operationExpirySkewMs: number;
  secrets: SignerSecrets;
};

export type RequiredAssetReadinessV2 = {
  asset: string;
  status:
    | 'ready'
    | 'wallet-setup-required'
    | 'privacy-onboarding-required'
    | 'private-token-setup-required'
    | 'unsupported'
    | 'unavailable';
};

export type SignerNextActionV2 =
  | {
      tool: 'chainwhisper_open_control_panel';
      arguments: Record<string, never>;
      reason:
        | 'wallet-setup-required'
        | 'privacy-onboarding-required'
        | 'private-token-setup-required'
        | 'control-panel-required';
    }
  | {
      tool: 'chainwhisper_get_operation';
      arguments: {
        operationId: string;
      };
      reason: 'pending-operation';
    }
  | {
      tool: null;
      arguments: Record<string, never>;
      reason:
        | 'ready'
        | 'configuration-invalid'
        | 'signer-restart-required';
    };

export type PublicSignerStatus = {
  version: 'cw.signer-status/2';
  network: {
    name: 'COTI Mainnet';
    chainId: number;
  };
  chainId: number;
  wallet: Address | null;
  configured: boolean;
  aesConfigured: boolean;
  privateTransactions: 'ready' | 'onboarding-required';
  pairingConfigured: boolean;
  confirmation: 'available' | 'unsupported';
  mode: 'read-write' | 'read-only' | 'configuration-required';
  walletSetup: 'ready' | 'required';
  signerReadiness:
    | 'ready'
    | 'wallet-setup-required'
    | 'privacy-onboarding-required'
    | 'confirmation-unavailable';
  privacyReadiness:
    | 'ready'
    | 'onboarding-required'
    | 'wallet-setup-required';
  controlPageReadiness: 'ready' | 'starting' | 'unavailable';
  autonomy: {
    mode: 'manual' | 'bounded' | 'full';
    state: 'inactive' | 'active' | 'paused' | 'expired' | 'revoked';
    activePolicyCount: number;
    globalPaused: boolean;
  };
  requiredAssets: RequiredAssetReadinessV2[];
  pendingOperations: {
    count: number;
    operationIds: string[];
  };
  nextAction: SignerNextActionV2;
  diagnosticCodes: string[];
};

export type RuntimeRegistryState = {
  chainId: number;
  registryHash: HexString;
  fees: Record<string, string>;
  editFees?: Record<string, string>;
  trustedFeeRecipients: Record<string, Address>;
  allowedContracts: ReadonlySet<string>;
  allowedSelectors: ReadonlyMap<string, ReadonlySet<string>>;
};

export interface RuntimeStateReader {
  readRegistryState(): Promise<RuntimeRegistryState>;
}

export type ApprovalMetadata = {
  token: Address;
  spender: Address;
  amount: string;
  scheme?: 'erc20-exact' | 'erc20-reset' | 'coti-private-exact';
  amountCommitment?: HexString;
};

export type MaterializedActionStep = {
  id: string;
  kind: 'approval' | 'protocol' | 'message';
  to: Address;
  data: HexString;
  value: string;
  gasCap: string;
  summary: string;
  approval?: ApprovalMetadata;
  privateValues?: Record<string, string>;
  privateDisplayAmounts?: Array<{
    id: string;
    amount: string;
    symbol: string;
  }>;
};

export interface PrivateInputMaterializer {
  materializeStep(
    envelope: SignedActionEnvelopeV1,
    stepIndex: number,
  ): Promise<MaterializedActionStep>;
}

export type ConfirmationRequest = {
  operationId: string;
  operationHash: HexString;
  stepId: string;
  stepIndex: number;
  stepCount: number;
  wallet: Address;
  contract: Address;
  action: string;
  orderType?: OrderClassificationV1 | null;
  orderTypeLabel?: string | null;
  assets: string[];
  amounts: string[];
  details?: Array<{
    label: string;
    value: string;
  }>;
  counterparty: Address | null;
  spender?: Address | null;
  fee: string;
  nativeValue: string;
  gasCap: string;
  expectedResult: string;
  summary: string;
  authorizationScope?: 'complete-logical-action';
  actionButtonLabel?: string;
  maximumNetworkFeeWei?: string;
  maximumNetworkFeeCoti?: string;
  stepDigests?: HexString[];
  technicalDetails?: Array<{
    stepId: string;
    kind: MaterializedActionStep['kind'];
    contract: Address;
    selector: HexString;
    calldataDigest: HexString;
    gasCap: string;
    maximumNetworkFeeWei: string;
  }>;
  acknowledgements?: string[];
  autonomyEditor?: {
    startsAt?: string;
    expiresAt: string;
    duration?: string;
    /**
     * One policy-wide consent for the agent to both choose private amounts and
     * view policy-scoped private balances, hidden order inventory/progress, and
     * participant receipts.
     */
    agentVisiblePrivateAmounts: boolean;
    perActionSpend: Array<{
      asset: string;
      amount: string;
      symbol?: string;
      decimals?: number;
      displayAmount?: string;
    }>;
    cumulativeSpend: Array<{
      asset: string;
      amount: string;
      symbol?: string;
      decimals?: number;
      displayAmount?: string;
    }>;
    maximumNativeValuePerAction?: string;
    maximumNativeValueCumulative?: string;
    maximumNetworkFeePerAction?: string;
    maximumNetworkFeeCumulative?: string;
    maximumActions?: number;
    maximumMessages?: number;
    priceBands: Array<{
      sellAsset: string;
      buyAsset: string;
      minimumNumerator: string;
      minimumDenominator: string;
      maximumNumerator: string;
      maximumDenominator: string;
      sellSymbol?: string;
      buySymbol?: string;
      sellDecimals?: number;
      buyDecimals?: number;
      minimumDisplay?: string;
      maximumDisplay?: string;
    }>;
  };
};

export type ConfirmationResult =
  | { outcome: 'accepted'; values?: Record<string, string> }
  | {
      outcome: 'declined';
      reason?: 'client-declined' | 'confirmation-not-enabled';
    }
  | { outcome: 'cancelled' }
  | { outcome: 'timeout' };

export interface FormElicitor {
  isSupported(): boolean;
  requestConfirmation(
    request: ConfirmationRequest,
    timeoutMs: number,
  ): Promise<ConfirmationResult>;
}

export type PrivateValueField = {
  id: string;
  title: string;
  description: string;
  kind: 'decimal-amount' | 'access-secret';
};

export type PrivateValueRequest = {
  operationId: string;
  operationHash: HexString;
  wallet: Address;
  fields: PrivateValueField[];
};

export type PrivateValueResult =
  | { outcome: 'accepted'; values: Record<string, string> }
  | { outcome: 'declined' | 'cancelled' | 'timeout'; values?: undefined };

export interface PrivateValueElicitor {
  isSupported(): boolean;
  requestPrivateValues(
    request: PrivateValueRequest,
    timeoutMs: number,
  ): Promise<PrivateValueResult>;
}

export type TransactionRequest = {
  to: Address;
  data: HexString;
  value: bigint;
  gasLimit: bigint;
  nonce: number;
};

export type TransactionReceipt = {
  transactionHash: HexString;
  status: 'success' | 'reverted' | 'pending';
  blockNumber?: number;
  logs?: TransactionLog[];
};

export type TransactionLog = {
  address: Address;
  topics: HexString[];
  data: HexString;
};

export type TransactionFeeQuote = {
  model: 'eip1559' | 'legacy';
  maximumNetworkFeeWei: string;
  maximumNetworkFeeCoti: string;
  maximumFeePerGasWei: string;
  maximumPriorityFeePerGasWei?: string;
};

export interface WalletTransport {
  getAddress(): Promise<Address>;
  getChainId(): Promise<number>;
  getPendingNonce(): Promise<number>;
  prepareTransaction(
    request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }>;
  broadcastTransaction(
    signedTransaction: HexString,
  ): Promise<{ hash: HexString }>;
  getTransaction(
    hash: HexString,
  ): Promise<{ hash: HexString; nonce: number } | null>;
  findTransactionByNonce(
    nonce: number,
  ): Promise<{ hash: HexString; nonce: number } | null>;
  getTransactionReceipt(hash: HexString): Promise<TransactionReceipt | null>;
  waitForTransaction(hash: HexString): Promise<TransactionReceipt>;
}

export interface TransactionSimulator {
  simulate(
    request: Omit<TransactionRequest, 'nonce'>,
    wallet: Address,
  ): Promise<
    | { ok: true; feeQuote?: TransactionFeeQuote }
    | { ok: false; errorCode: string }
  >;
}

export interface MaterializedIntentValidator {
  validate(
    envelope: SignedActionEnvelopeV1,
    step: MaterializedActionStep,
    stepIndex: number,
  ): Promise<void>;
}

export type StandardOrderFacts = {
  maker: Address;
  recipient: Address | null;
};

export interface StandardOrderFactsReader {
  readStandardOrderFacts(
    escrowContract: Address,
    localId: string,
  ): Promise<StandardOrderFacts>;
}

export type OperationStage =
  | 'validated'
  | 'awaiting-confirmation'
  | 'awaiting-broadcast'
  | 'prepared-broadcast'
  | 'broadcast'
  | 'completed'
  | 'declined'
  | 'failed'
  | 'discarded';

export type JournalReceipt = {
  transactionHash: HexString;
  status: 'success' | 'reverted' | 'pending';
  blockNumber?: number;
};

export type OperationJournalRecord = {
  operationId: string;
  operationHash: HexString;
  stage: OperationStage;
  nextStepIndex: number;
  nonces: number[];
  transactionHashes: HexString[];
  receipts: JournalReceipt[];
  semanticResult?: OperationSemanticResultV2;
  errorCodes: string[];
  updatedAt: string;
};

export type ExecuteActionResult = {
  operationId: string;
  operationHash: HexString;
  status:
    | 'completed'
    | 'processing'
    | 'retryable'
    | 'declined'
    | 'denied'
    | 'read-only';
  transactionHashes: HexString[];
  errorCode?: string;
  autonomyDenial?: {
    code: string;
    message: string;
    policyId?: string;
    field?: string;
  };
};

export type OperationStatusV2State =
  | 'queued'
  | 'needs_setup'
  | 'needs_reprepare'
  | 'needs_private_input'
  | 'needs_confirmation'
  | 'signing'
  | 'broadcasting'
  | 'confirming'
  | 'uncertain'
  | 'completed'
  | 'declined'
  | 'failed';

export type OperationSemanticResultV2 = {
  action: SignedActionEnvelopeV1['intent']['action'];
  status: 'completed';
  canonicalType?: OrderClassificationV1;
  order?: {
    handle: string;
    status: 'open';
    shareableAppLink: string;
  };
};

export type OperationSetupRequirementV2 =
  | {
      kind: 'privacy-onboarding';
      assets: [];
    }
  | {
      kind: 'private-token-setup';
      assets: string[];
    };

export type OperationStatusV2 = {
  version: 'cw.operation-status/2';
  operationId: string;
  operationHash: HexString;
  status: OperationStatusV2State;
  summary: string;
  transactionHashes: HexString[];
  transactionLinks: string[];
  userActionRequired: boolean;
  nextPollingIntervalMs: number | null;
  errorCode?: string;
  setupRequirement?: OperationSetupRequirementV2;
  result?: OperationSemanticResultV2;
};

export type PrivateStateQueryV1 =
  | {
      kind: 'balances';
      assets: string[];
    }
  | {
      kind: 'order';
      route: 'one-off' | 'recurring';
      orderId: string;
      fromBlock?: number;
      receiptLimit?: number;
    };

export type PrivateStateAuthorizationV1 =
  | {
      mode: 'local-confirmation';
    }
  | {
      mode: 'autonomy-policy';
      policyId: string;
    };

export type PrivateBalanceDisclosureV1 = {
  symbol: string;
  token: Address;
  decimals: number;
  amountAtomic: string;
};

export type PrivateOrderReceiptV1 = {
  fillIndex: number;
  filler: Address;
  side?: 'buy' | 'sell';
  offerAmountAtomic?: string;
  requestAmountAtomic?: string;
  baseAmountAtomic?: string;
  quoteAmountAtomic?: string;
  remainingOfferAmountAtomic?: string;
  remainingBaseInventoryAtomic?: string;
  remainingQuoteInventoryAtomic?: string;
  transactionHash: HexString;
  blockNumber: number;
};

export type PrivateStateResultV1 =
  | {
      version: 'cw.private-state/1';
      wallet: Address;
      authorization: PrivateStateAuthorizationV1;
      data: {
        kind: 'balances';
        balances: PrivateBalanceDisclosureV1[];
      };
    }
  | {
      version: 'cw.private-state/1';
      wallet: Address;
      authorization: PrivateStateAuthorizationV1;
      data: {
        kind: 'order';
        route: 'one-off';
        orderId: string;
        role: 'maker' | 'participant' | 'none';
        orderType: OrderClassificationV1;
        offerAsset: string;
        requestAsset: string;
        remainingOfferAmountAtomic?: string;
        privateFillReceiptTotal: number;
        receipts: PrivateOrderReceiptV1[];
        receiptsTruncated: boolean;
      };
    }
  | {
      version: 'cw.private-state/1';
      wallet: Address;
      authorization: PrivateStateAuthorizationV1;
      data: {
        kind: 'order';
        route: 'recurring';
        orderId: string;
        role: 'maker' | 'participant' | 'none';
        orderType: OrderClassificationV1;
        baseAsset: string;
        quoteAsset: string;
        privateBaseInventoryAtomic?: string;
        privateQuoteInventoryAtomic?: string;
        executionCount: number;
        privateFillReceiptTotal: number;
        receipts: PrivateOrderReceiptV1[];
        receiptsTruncated: boolean;
      };
    };

export type PrivateStateDisclosureDecisionV1 =
  | {
      allowed: true;
      value: PrivateStateResultV1;
    }
  | {
      allowed: false;
      denial: {
        code: string;
        message: string;
        policyId?: string;
        field?: string;
      };
    };

export interface PrivateStateDisclosureReader {
  disclose(
    query: PrivateStateQueryV1,
    policyId?: string,
  ): Promise<PrivateStateDisclosureDecisionV1>;
}

export type RecoverOperationResult = {
  operationId: string;
  operationHash: HexString;
  status: 'completed' | 'processing' | 'retryable' | 'discarded';
  transactionHashes: HexString[];
  errorCodes: string[];
};

export type OfficialMessagingTool = {
  name: string;
  description?: string;
  inputSchema?: unknown;
};

export type OfficialMessagingInvoker = (
  toolName: string,
  input: Record<string, unknown>,
) => Promise<unknown>;

export type OtcNegotiationKind =
  | 'proposal'
  | 'counter'
  | 'acceptance'
  | 'decline'
  | 'status'
  | 'access';

export type OtcNegotiationEnvelopeV1 = {
  protocol: 'cw.otc/1';
  kind: OtcNegotiationKind;
  messageId: string;
  createdAt: string;
  order?: {
    escrowContract: Address;
    localId: string;
  };
  operationHash?: HexString;
  body?: Record<string, unknown>;
  accessSecret?: string;
};

export type UntrustedNegotiationMessage = {
  protocol: 'cw.otc/1';
  trust: 'untrusted';
  mayDraft: true;
  mayExecute: false;
  message: Omit<OtcNegotiationEnvelopeV1, 'accessSecret'> & {
    hasAccessSecret?: boolean;
  };
};
