import type { OrderClassificationV1 } from './orderClassification.js';

export const ACTION_ENVELOPE_VERSION = 'cw.action/1' as const;
export const CHAINWHISPER_CHAIN_ID = 2_632_500;

export type HexString = `0x${string}`;
export type DecimalString = `${number}` | `${number}.${number}`;

export type ChainWhisperAccessMode = 'public' | 'unlisted' | 'direct';
export type ChainWhisperAmountVisibility = 'visible' | 'private-hidden';
export type ChainWhisperActionKind =
  | 'create_trade'
  | 'create_recurring'
  | 'fill'
  | 'counter'
  | 'edit'
  | 'order_update'
  | 'privacy_bridge'
  | 'send_order_message';

export interface RuntimeContractSnapshotV1 {
  address: HexString;
  bytecodeHash: HexString;
  selectors: Record<string, HexString>;
}

export interface RegistrySnapshotV1 {
  registryAddress: HexString;
  registryBytecodeHash: HexString;
  manifestHash: HexString;
  observedBlock: string;
  contracts: Record<string, RuntimeContractSnapshotV1>;
  fees: Record<string, string>;
}

export interface NormalizedAssetV1 {
  kind: 'native' | 'erc20' | 'private-erc20';
  reference: string;
  address?: HexString;
  symbol?: string;
  decimals?: number;
}

export interface NormalizedIntentV1 {
  action: ChainWhisperActionKind;
  /**
   * Canonical order classification. Optional only so envelopes prepared by
   * earlier 0.1.0-beta clients can still be inspected and recovered.
   */
  orderType?: OrderClassificationV1;
  accessMode?: ChainWhisperAccessMode;
  amountVisibility?: ChainWhisperAmountVisibility;
  order?: {
    escrowContract: HexString;
    localId: string;
  };
  sellAsset?: NormalizedAssetV1;
  buyAsset?: NormalizedAssetV1;
  sellAmount?: string;
  buyAmount?: string;
  recipient?: HexString;
  expiresAt?: string;
  editableMissing?: string[];
  metadata?: Record<string, string | number | boolean | null>;
}

export interface ExactAllowanceV1 {
  token: HexString;
  spender: HexString;
  amount: string;
  scheme?: 'erc20-exact' | 'erc20-reset' | 'coti-private-exact';
  amountCommitment?: HexString;
}

export type CanonicalCallArgumentV1 =
  | boolean
  | null
  | string
  | CanonicalCallArgumentV1[]
  | { [key: string]: CanonicalCallArgumentV1 };

export interface CanonicalCallTemplateV1 {
  /**
   * A repository-allowlisted canonical Solidity signature, for example
   * `fillPrivateOrder(uint256,((uint256,uint256),bytes))`.
   */
  functionSignature: string;
  arguments: CanonicalCallArgumentV1[];
}

export interface ActionStepV1 {
  id: string;
  kind: 'approval' | 'protocol' | 'message';
  to: HexString;
  data: HexString;
  value: string;
  gasCap: string;
  summary: string;
  allowance?: ExactAllowanceV1;
  /**
   * Present only when local COTI private inputs must be inserted before ABI
   * encoding. The signed selector in `data` must match this template.
   */
  callTemplate?: CanonicalCallTemplateV1;
}

export interface PrivateInputPlaceholderV1 {
  id: string;
  kind:
    | 'itUint256'
    | 'access-secret'
    | 'encrypted-recovery-note';
  source: 'wallet-aes' | 'local-vault' | 'generated-local';
  decimalValue?: string;
  bindToStepId: string;
  jsonPointer: string;
}

export type PrivateArtifactRecipeV1 =
  | 'direct-order-v1'
  | 'direct-counter-v1'
  | 'direct-edit-v1'
  | 'private-liquidity-v1'
  | 'private-liquidity-edit-v1'
  | 'private-recurring-v1'
  | 'private-recurring-fill-v1'
  | 'recurring-edit-v1'
  | 'private-fill-v1'
  | 'coti-private-exact-allowance-v1';

export type PrivateArtifactValueSourceV1 =
  | 'intent-sell-amount'
  | 'intent-buy-amount'
  | 'trusted-order-visible-amount'
  | 'recurring-sell-base-liquidity'
  | 'recurring-buy-quote-liquidity'
  | 'recurring-edit-add-base-liquidity'
  | 'recurring-edit-add-quote-liquidity'
  | 'recurring-edit-remove-base-liquidity'
  | 'recurring-edit-remove-quote-liquidity'
  | 'signer-elicitation'
  | 'local-order-vault'
  | 'generated-local'
  | 'constant-zero';

export interface PrivateArtifactValueV1 {
  id: string;
  kind: 'uint256' | 'access-secret';
  source: PrivateArtifactValueSourceV1;
  asset?: NormalizedAssetV1;
  allowZero?: boolean;
  commitment: HexString;
}

export interface PrivateArtifactOutputV1 {
  kind:
    | 'uint256'
    | 'itUint256'
    | 'keccak256'
    | 'direct-terms-v1'
    | 'terms-hash-v1'
    | 'trade-recovery-v1'
    | 'recurring-recovery-v1'
    | 'coti-private-exact-allowance';
  valueId?: string;
  jsonPointer: string;
}

export interface PrivateArtifactGroupV1 {
  id: string;
  recipe: PrivateArtifactRecipeV1;
  bindToStepId: string;
  commitment: HexString;
  values: PrivateArtifactValueV1[];
  outputs: PrivateArtifactOutputV1[];
  context?: Record<string, string | boolean | null>;
}

export interface SecretPolicyV1 {
  accessMode: ChainWhisperAccessMode;
  generatedLocally: boolean;
  mayLeaveSigner: false;
  sharing: 'none' | 'coti-private-message-only';
}

export interface SimulationResultV1 {
  status: 'passed' | 'failed' | 'not-run' | 'incomplete';
  checkedAt: string;
  blockNumber?: string;
  reason?: string;
}

export interface PairingSignatureV1 {
  algorithm: 'hmac-sha256';
  digest: HexString;
}

export interface ActionEnvelopeV1 {
  version: typeof ACTION_ENVELOPE_VERSION;
  operationId: string;
  operationHash: HexString;
  wallet: HexString;
  chainId: typeof CHAINWHISPER_CHAIN_ID;
  registrySnapshot: RegistrySnapshotV1;
  issuedAt: string;
  expiresAt: string;
  intent: NormalizedIntentV1;
  steps: ActionStepV1[];
  exactNativeValue: string;
  fee: {
    recipient: HexString;
    amount: string;
    asset: 'native';
  };
  gasCap: string;
  privateInputs: PrivateInputPlaceholderV1[];
  /**
   * Signed signer-local derivation recipes. They contain commitments and safe
   * bindings only—never raw access secrets or hidden amounts.
   */
  privateArtifacts?: PrivateArtifactGroupV1[];
  secretPolicy: SecretPolicyV1;
  simulation: SimulationResultV1;
  summary: string;
}

export interface SignedActionEnvelopeV1 extends ActionEnvelopeV1 {
  pairingSignature: PairingSignatureV1;
}

export interface ChainWhisperOperationRefV1 {
  operationId: string;
  operationHash: HexString;
}

export const isHexAddress = (value: unknown): value is HexString =>
  typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/u.test(value);

export const isHexData = (value: unknown): value is HexString =>
  typeof value === 'string' && /^0x(?:[0-9a-fA-F]{2})*$/u.test(value);

export const isUnsignedIntegerString = (value: unknown): value is string =>
  typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value);

export const isDecimalString = (value: unknown): value is string =>
  typeof value === 'string' && /^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value);

const RESERVED_OPERATION_IDS = new Set([
  '__proto__',
  'constructor',
  'prototype',
]);

export const isSafeOperationId = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u.test(value) &&
  !RESERVED_OPERATION_IDS.has(value);
