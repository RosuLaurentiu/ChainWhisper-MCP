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

export type PublicSignerStatus = {
  chainId: number;
  wallet: Address | null;
  configured: boolean;
  aesConfigured: boolean;
  privateTransactions: 'ready' | 'onboarding-required';
  pairingConfigured: boolean;
  confirmation: 'available' | 'unsupported';
  mode: 'read-write' | 'read-only' | 'configuration-required';
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
  counterparty: Address | null;
  spender?: Address | null;
  fee: string;
  nativeValue: string;
  gasCap: string;
  expectedResult: string;
  summary: string;
};

export type ConfirmationResult =
  | { outcome: 'accepted' }
  | {
      outcome: 'declined';
      reason?: 'client-declined' | 'confirmation-not-enabled';
    }
  | { outcome: 'cancelled' }
  | { outcome: 'timeout' };

export type ConfirmationDiagnosticResult = {
  supported: boolean;
  outcome:
    | 'accepted'
    | 'declined'
    | 'cancelled'
    | 'timeout'
    | 'unsupported';
  reason?: 'client-declined' | 'confirmation-not-enabled';
  writeAttempted: false;
};

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
  ): Promise<{ ok: true } | { ok: false; errorCode: string }>;
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
  errorCodes: string[];
  updatedAt: string;
};

export type ExecuteActionResult = {
  operationId: string;
  operationHash: HexString;
  status: 'completed' | 'processing' | 'retryable' | 'declined' | 'read-only';
  transactionHashes: HexString[];
  errorCode?: string;
};

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
