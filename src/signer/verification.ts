import {
  canonicalize,
  hmacSha256Hex,
  isHexAddress,
  isHexData,
  isSafeOperationId,
  isUnsignedIntegerString,
  MARKET_REFERENCE_MAX_AGE_MS,
  MARKET_REFERENCE_MAX_FUTURE_SKEW_MS,
  marketReferenceDeadlineMs,
  verifySignedActionEnvelope,
  type ActionStepV1,
  type SignedActionEnvelopeV1,
} from '../shared/index.js';
import {
  decodeFunctionData,
  parseAbi,
  toFunctionSelector,
  type Abi,
} from 'viem';

import { SignerError } from './errors.js';
import type { LoadedSignerConfig } from './config.js';
import type {
  Address,
  ApprovalMetadata,
  RuntimeRegistryState,
  RuntimeStateReader,
} from './types.js';

const UINT256_MAX =
  115792089237316195423570985008687907853269984665640564039457584007913129639935n;
const APPROVE_SELECTOR = '095ea7b3';
const PRIVATE_APPROVE_SIGNATURE =
  'approve(address,((uint256,uint256),bytes))';
const LEGACY_STANDARD_COUNTER_REPLACEMENT_SIGNATURE =
  'counterTradeAndCloseCounteredTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),uint64)';
const LEGACY_STANDARD_EDIT_SIGNATURE =
  'editTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32)';

const MARKET_REFERENCE_METADATA_KEYS = [
  'marketReferenceId',
  'marketReferenceVenue',
  'marketReferencePrice',
  'marketReferenceObservedAt',
  'marketReferenceExpiresAt',
  'marketReferenceMaxAgeMs',
] as const;

const assertMarketReferenceFreshness = (
  envelope: SignedActionEnvelopeV1,
  now: Date,
): void => {
  const metadata = envelope.intent.metadata;
  if (
    !metadata ||
    !MARKET_REFERENCE_METADATA_KEYS.some((key) => key in metadata)
  ) {
    return;
  }
  const observedAt = metadata.marketReferenceObservedAt;
  const providerExpiresAt = metadata.marketReferenceExpiresAt;
  if (
    envelope.intent.action !== 'create_recurring' ||
    typeof metadata.marketReferenceId !== 'string' ||
    typeof metadata.marketReferenceVenue !== 'string' ||
    typeof metadata.marketReferencePrice !== 'string' ||
    typeof observedAt !== 'string' ||
    (
      providerExpiresAt !== null &&
      typeof providerExpiresAt !== 'string'
    ) ||
    metadata.marketReferenceMaxAgeMs !==
      MARKET_REFERENCE_MAX_AGE_MS
  ) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'The signed market-reference freshness policy is invalid.',
    );
  }
  const observedAtMs = Date.parse(observedAt);
  const deadline = marketReferenceDeadlineMs(
    observedAt,
    providerExpiresAt,
  );
  if (
    deadline === null ||
    observedAtMs >
      now.getTime() + MARKET_REFERENCE_MAX_FUTURE_SKEW_MS ||
    now.getTime() >= deadline
  ) {
    throw new SignerError(
      'STALE_STATE',
      'The signed market reference is no longer fresh.',
    );
  }
  if (Date.parse(envelope.expiresAt) > deadline) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'The action plan exceeds its signed market-reference deadline.',
    );
  }
};
const LEGACY_STANDARD_UPDATE_SIGNATURES: Readonly<
  Record<string, string>
> = {
  cancel: 'cancelTrade(uint256)',
  decline: 'declineTrade(uint256)',
  reclaim_expired: 'reclaimExpiredTrade(uint256)',
  refresh: 'refreshTrade(uint256)',
  extend_expiry: 'extendTradeExpiry(uint256,uint64)',
};
const PRIVATE_APPROVE_SELECTOR =
  toFunctionSelector(PRIVATE_APPROVE_SIGNATURE).toLowerCase();
const PRIVATE_APPROVE_ABI = parseAbi([
  `function ${PRIVATE_APPROVE_SIGNATURE}`,
] as never) as Abi;

const normalizeAddress = (value: string): string => value.toLowerCase();

const assertUnsignedInteger = (value: unknown, label: string): string => {
  if (!isUnsignedIntegerString(value)) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      `${label} must be an unsigned base-unit integer string.`,
    );
  }
  return value;
};

const decodeApprovalCalldata = (
  data: string,
): { spender: Address; amount: bigint } | null => {
  const normalized = data.toLowerCase().replace(/^0x/u, '');
  if (
    !normalized.startsWith(APPROVE_SELECTOR) ||
    normalized.length !== APPROVE_SELECTOR.length + 64 + 64
  ) {
    return null;
  }
  const spenderWord = normalized.slice(8, 72);
  const amountWord = normalized.slice(72, 136);
  const spender = `0x${spenderWord.slice(24)}` as Address;
  try {
    return { spender, amount: BigInt(`0x${amountWord}`) };
  } catch {
    return null;
  }
};

const assertExactAllowance = (
  step: ActionStepV1,
  allowedContracts: ReadonlySet<string>,
): ApprovalMetadata => {
  const allowance = step.allowance;
  if (
    !allowance ||
    !isHexAddress(allowance.token) ||
    !isHexAddress(allowance.spender) ||
    !isUnsignedIntegerString(allowance.amount)
  ) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval steps must include an exact token, spender, and amount.',
    );
  }
  const amount = BigInt(allowance.amount);
  if (normalizeAddress(step.to) !== normalizeAddress(allowance.token)) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval target does not match the declared token.',
    );
  }
  if (!allowedContracts.has(normalizeAddress(allowance.spender))) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval spender is not a current ChainWhisper contract.',
    );
  }
  if (allowance.scheme === 'coti-private-exact') {
    if (
      amount !== 0n ||
      !allowance.amountCommitment ||
      !/^0x[0-9a-fA-F]{64}$/u.test(allowance.amountCommitment) ||
      step.callTemplate?.functionSignature !== PRIVATE_APPROVE_SIGNATURE ||
      step.data.slice(0, 10).toLowerCase() !== PRIVATE_APPROVE_SELECTOR
    ) {
      throw new SignerError(
        'EXACT_ALLOWANCE_REQUIRED',
        'Private approval metadata is not bound to a committed exact amount.',
      );
    }
    try {
      const decoded = decodeFunctionData({
        abi: PRIVATE_APPROVE_ABI,
        data: step.data,
      });
      const args = decoded.args as readonly unknown[];
      const encrypted = args[1] as
        | readonly [readonly [bigint, bigint], string]
        | undefined;
      if (
        decoded.functionName !== 'approve' ||
        normalizeAddress(String(args[0])) !==
          normalizeAddress(allowance.spender) ||
        encrypted?.[0]?.[0] !== 0n ||
        encrypted?.[0]?.[1] !== 0n ||
        encrypted?.[1] !== '0x'
      ) {
        throw new Error('private approval template mismatch');
      }
    } catch {
      throw new SignerError(
        'EXACT_ALLOWANCE_REQUIRED',
        'Private approval calldata is not the canonical empty signed template.',
      );
    }
    return {
      token: allowance.token,
      spender: allowance.spender,
      amount: allowance.amount,
      scheme: allowance.scheme,
      amountCommitment: allowance.amountCommitment,
    };
  }
  if (
    (allowance.scheme === 'erc20-reset' && amount !== 0n) ||
    (allowance.scheme !== 'erc20-reset' &&
      (amount <= 0n || amount === UINT256_MAX))
  ) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Unlimited or zero public token approvals are not allowed.',
    );
  }
  const decoded = decodeApprovalCalldata(step.data);
  if (
    !decoded ||
    normalizeAddress(decoded.spender) !== normalizeAddress(allowance.spender) ||
    decoded.amount !== amount
  ) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval calldata is not bound to the declared exact allowance.',
    );
  }
  return {
    token: allowance.token,
    spender: allowance.spender,
    amount: allowance.amount,
    ...(allowance.scheme ? { scheme: allowance.scheme } : {}),
  };
};

const assertStep = (
  step: ActionStepV1,
  allowedContracts: ReadonlySet<string>,
): void => {
  if (
    !step.id ||
    !isHexAddress(step.to) ||
    !isHexData(step.data) ||
    !step.summary?.trim()
  ) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Action step contains an invalid id, target, calldata, or summary.',
    );
  }
  assertUnsignedInteger(step.value, 'Step value');
  const gasCap = BigInt(assertUnsignedInteger(step.gasCap, 'Step gas cap'));
  if (gasCap <= 0n) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Every transaction step must have a positive gas cap.',
    );
  }
  if (step.kind === 'approval') {
    assertExactAllowance(step, allowedContracts);
    return;
  }
  if (!allowedContracts.has(normalizeAddress(step.to))) {
    throw new SignerError(
      'REGISTRY_CHANGED',
      'Action step targets a contract outside the current registry.',
    );
  }
};

const assertProtocolSelector = (
  step: ActionStepV1,
  runtime: RuntimeRegistryState,
): void => {
  if (step.kind !== 'protocol') return;
  const selector = step.data.slice(0, 10).toLowerCase();
  if (!/^0x[0-9a-f]{8}$/u.test(selector)) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Protocol calldata is missing a function selector.',
    );
  }
  const selectors = runtime.allowedSelectors.get(normalizeAddress(step.to));
  if (!selectors?.has(selector)) {
    throw new SignerError(
      'REGISTRY_CHANGED',
      'Protocol function selector is not allowlisted by the current manifest.',
    );
  }
  if (
    step.callTemplate &&
    toFunctionSelector(step.callTemplate.functionSignature).toLowerCase() !==
      selector
  ) {
    throw new SignerError(
      'ENVELOPE_TAMPERED',
      'Call template does not match the signed protocol selector.',
    );
  }
};

const assertLegacyStandardCounterActionBinding = (
  envelope: SignedActionEnvelopeV1,
): void => {
  if (
    envelope.intent.metadata?.counterRoute !==
    'legacy-standard-counter'
  ) {
    return;
  }
  const protocolSteps = envelope.steps.filter(
    (step) => step.kind === 'protocol',
  );
  const step = protocolSteps[0];
  const standard =
    envelope.registrySnapshot.contracts.standardEscrow;
  const order = envelope.intent.order;
  if (
    protocolSteps.length !== 1 ||
    !step ||
    !standard ||
    envelope.intent.action !== 'counter' ||
    envelope.intent.orderType ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    envelope.intent.metadata?.sourceOrderRelation !== 'counter' ||
    envelope.intent.metadata?.legacyCompatibility !==
      'standard-recipient-bound' ||
    envelope.intent.metadata?.legacyOrderTypeLabel !==
      'Legacy one-off / fixed recipient / public terms' ||
    envelope.intent.metadata?.sourceOrderType !== null ||
    step.callTemplate?.functionSignature !==
      LEGACY_STANDARD_COUNTER_REPLACEMENT_SIGNATURE ||
    !order ||
    normalizeAddress(order.escrowContract) !==
      normalizeAddress(step.to) ||
    normalizeAddress(step.to) !==
      normalizeAddress(standard.address) ||
    normalizeAddress(
      String(
        envelope.intent.metadata?.counteredEscrowContract ?? '',
      ),
    ) !== normalizeAddress(order.escrowContract) ||
    String(envelope.intent.metadata?.counteredTradeId ?? '') !==
      order.localId ||
    normalizeAddress(
      String(envelope.intent.metadata?.sourceRecipient ?? ''),
    ) !== normalizeAddress(envelope.wallet) ||
    normalizeAddress(
      String(envelope.intent.metadata?.sourceMaker ?? ''),
    ) !==
      normalizeAddress(String(envelope.intent.recipient ?? ''))
  ) {
    throw new SignerError(
      'ENVELOPE_TAMPERED',
      'The legacy Standard counter action binding is invalid.',
    );
  }
};

const assertLegacyStandardLifecycleTypeBinding = (
  envelope: SignedActionEnvelopeV1,
): void => {
  if (
    (
      envelope.intent.action !== 'edit' &&
      envelope.intent.action !== 'order_update'
    )
  ) {
    return;
  }
  const protocolSteps = envelope.steps.filter(
    (step) => step.kind === 'protocol',
  );
  const step = protocolSteps[0];
  const standard =
    envelope.registrySnapshot.contracts.standardEscrow;
  const order = envelope.intent.order;
  const metadata = envelope.intent.metadata;
  const legacyStandardCandidate =
    !envelope.intent.orderType &&
    envelope.intent.accessMode === 'direct' &&
    envelope.intent.amountVisibility === 'visible' &&
    !!step &&
    !!standard &&
    !!order &&
    normalizeAddress(order.escrowContract) ===
      normalizeAddress(step.to) &&
    normalizeAddress(step.to) ===
      normalizeAddress(standard.address);
  if (
    metadata?.legacyCompatibility !==
      'standard-recipient-bound' &&
    !legacyStandardCandidate
  ) {
    return;
  }
  const sourceRelation = metadata?.sourceOrderRelation;
  const sourceMaker = metadata?.sourceMaker;
  const sourceRecipient = metadata?.sourceRecipient;
  const recipient = envelope.intent.recipient;
  const commonInvalid =
    protocolSteps.length !== 1 ||
    !step ||
    !standard ||
    !order ||
    envelope.intent.orderType !== undefined ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    metadata?.legacyCompatibility !==
      'standard-recipient-bound' ||
    metadata?.legacyOrderTypeLabel !==
      'Legacy one-off / fixed recipient / public terms' ||
    metadata?.sourceOrderType !== null ||
    (
      sourceRelation !== 'primary' &&
      sourceRelation !== 'counter' &&
      sourceRelation !== 'replacement'
    ) ||
    !isHexAddress(String(sourceMaker ?? '')) ||
    !isHexAddress(String(sourceRecipient ?? '')) ||
    !recipient ||
    normalizeAddress(String(sourceRecipient)) !==
      normalizeAddress(recipient) ||
    normalizeAddress(String(sourceMaker)) ===
      normalizeAddress(String(sourceRecipient)) ||
    normalizeAddress(order.escrowContract) !==
      normalizeAddress(step.to) ||
    normalizeAddress(step.to) !==
      normalizeAddress(standard.address);
  if (commonInvalid) {
    throw new SignerError(
      'ENVELOPE_TAMPERED',
      'The legacy Standard lifecycle type binding is invalid.',
    );
  }
  if (envelope.intent.action === 'edit') {
    const defaultBps = metadata?.legacyDefaultMinPartialFillBps;
    if (
      sourceRelation === 'counter' ||
      metadata?.orderRelation !== 'replacement' ||
      normalizeAddress(String(sourceMaker)) !==
        normalizeAddress(envelope.wallet) ||
      metadata?.legacyDefaultPolicyPreserved !== true ||
      metadata?.resultingPartialFillsAllowed !== true ||
      metadata?.resultingOneFillPerWallet !== false ||
      !Number.isInteger(defaultBps) ||
      Number(defaultBps) < 0 ||
      Number(defaultBps) > 5_000 ||
      metadata?.resultingMinPartialFillBps !== defaultBps ||
      (metadata?.resultingMinRequestAmount !== null &&
        metadata?.resultingMinRequestAmount !== '0') ||
      (metadata?.resultingMaxRequestAmountPerWallet !== null &&
        metadata?.resultingMaxRequestAmountPerWallet !== '0') ||
      step.callTemplate?.functionSignature !==
        LEGACY_STANDARD_EDIT_SIGNATURE
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'The legacy Standard edit action binding is invalid.',
      );
    }
    return;
  }
  const update =
    typeof metadata?.update === 'string'
      ? metadata.update
      : '';
  if (
    metadata?.orderRelation !== sourceRelation ||
    step.callTemplate?.functionSignature !==
      LEGACY_STANDARD_UPDATE_SIGNATURES[update] ||
    (
      (
        update === 'cancel' ||
        update === 'refresh' ||
        update === 'extend_expiry'
      ) &&
      normalizeAddress(String(sourceMaker)) !==
        normalizeAddress(envelope.wallet)
    ) ||
    (
      update === 'decline' &&
      normalizeAddress(String(sourceRecipient)) !==
        normalizeAddress(envelope.wallet)
    )
  ) {
    throw new SignerError(
      'ENVELOPE_TAMPERED',
      'The legacy Standard order-update action binding is invalid.',
    );
  }
};

const assertPrivateInputPolicy = (
  envelope: SignedActionEnvelopeV1,
): void => {
  const ids = new Set<string>();
  const stepIds = new Set(envelope.steps.map((step) => step.id));
  for (const placeholder of envelope.privateInputs) {
    if (!placeholder.id || ids.has(placeholder.id)) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private input identifiers must be unique.',
      );
    }
    ids.add(placeholder.id);
    if (!stepIds.has(placeholder.bindToStepId)) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private input is not bound to an action step.',
      );
    }
    if (
      placeholder.source === 'local-vault' &&
      placeholder.decimalValue !== undefined
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Vault-backed private values must not appear in an action envelope.',
      );
    }
  }
  if (
    envelope.secretPolicy.mayLeaveSigner !== false ||
    (envelope.secretPolicy.sharing === 'coti-private-message-only' &&
      envelope.secretPolicy.accessMode === 'public')
  ) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'The action envelope contains an invalid secret policy.',
    );
  }
};

const privateArtifactCommitment = (
  pairingSecret: string,
  value: unknown,
): `0x${string}` =>
  hmacSha256Hex(
    pairingSecret,
    canonicalize({ domain: 'cw.private-artifact/1', value }),
  );

const assertSupportedPrivateArtifacts = (
  envelope: SignedActionEnvelopeV1,
  pairingSecret: string,
): boolean => {
  const artifacts = envelope.privateArtifacts ?? [];
  if (!artifacts.length) return false;
  if (envelope.privateInputs.length !== 0) {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'Committed private recipes cannot be mixed with legacy placeholders.',
    );
  }
  const allowedRecipeSignatures: Record<string, ReadonlySet<string>> = {
    'coti-private-exact-allowance-v1': new Set([
      PRIVATE_APPROVE_SIGNATURE,
    ]),
    'direct-order-v1': new Set([
      'createDirectTrade((uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    ]),
    'direct-counter-v1': new Set([
      'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
      'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
      'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    ]),
    'direct-edit-v1': new Set([
      'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    ]),
    'private-liquidity-v1': new Set([
      'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)',
    ]),
    'private-liquidity-edit-v1': new Set([
      'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)',
    ]),
    'private-recurring-v1': new Set([
      'createPrivateRecurringOrderWithRecoveryNote((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),bytes)',
    ]),
    'private-recurring-fill-v1': new Set([
      'fillPrivateBuySideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)',
      'fillPrivateSellSideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)',
    ]),
    'recurring-edit-v1': new Set([
      'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
    ]),
    'private-fill-v1': new Set([
      'acceptDirectTrade(uint256,((uint256,uint256),bytes))',
      'acceptDirectTradeWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
      'acceptCounterTradeAndCloseParent(uint256,((uint256,uint256),bytes))',
      'fillPrivateOrder(uint256,((uint256,uint256),bytes))',
      'fillPrivateOrderWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
      'fillHybridPrivateOrderWithEncryptedAccess(uint256,uint256,((uint256,uint256),bytes))',
    ]),
  };
  const allowedOutputs: Record<string, ReadonlySet<string>> = {
    [PRIVATE_APPROVE_SIGNATURE]: new Set([
      'coti-private-exact-allowance:/arguments/1',
    ]),
    'createDirectTrade((uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/3',
        'itUint256:/arguments/4',
        'keccak256:/arguments/7',
        'terms-hash-v1:/arguments/8',
        'itUint256:/arguments/9',
        'direct-terms-v1:/arguments/10',
      ]),
    'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/4',
        'itUint256:/arguments/5',
        'keccak256:/arguments/7',
        'terms-hash-v1:/arguments/8',
        'itUint256:/arguments/9',
        'direct-terms-v1:/arguments/10',
      ]),
    'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/4',
        'itUint256:/arguments/5',
        'keccak256:/arguments/7',
        'terms-hash-v1:/arguments/8',
        'itUint256:/arguments/9',
        'direct-terms-v1:/arguments/10',
      ]),
    'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/6',
        'itUint256:/arguments/7',
        'keccak256:/arguments/9',
        'terms-hash-v1:/arguments/10',
        'itUint256:/arguments/11',
        'direct-terms-v1:/arguments/12',
      ]),
    'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/4',
        'itUint256:/arguments/5',
        'keccak256:/arguments/8',
        'terms-hash-v1:/arguments/9',
        'itUint256:/arguments/10',
        'direct-terms-v1:/arguments/11',
      ]),
    'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)':
      new Set([
        'uint256:/arguments/0/2',
        'uint256:/arguments/1/2',
        'keccak256:/arguments/5',
        'terms-hash-v1:/arguments/6',
        'itUint256:/arguments/7',
        'itUint256:/arguments/8',
        'itUint256:/arguments/9',
        'trade-recovery-v1:/arguments/10',
        'itUint256:/arguments/11',
        'direct-terms-v1:/arguments/12',
      ]),
    'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)':
      new Set([
        'uint256:/arguments/1/2',
        'uint256:/arguments/2/2',
        'keccak256:/arguments/6',
        'terms-hash-v1:/arguments/7',
        'itUint256:/arguments/8',
        'itUint256:/arguments/9',
        'itUint256:/arguments/10',
        'trade-recovery-v1:/arguments/11',
        'itUint256:/arguments/12',
        'direct-terms-v1:/arguments/13',
      ]),
    'createPrivateRecurringOrderWithRecoveryNote((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),bytes)':
      new Set([
        'itUint256:/arguments/9',
        'itUint256:/arguments/10',
        'recurring-recovery-v1:/arguments/11',
      ]),
    'fillPrivateBuySideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)':
      new Set(['itUint256:/arguments/2']),
    'fillPrivateSellSideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)':
      new Set(['itUint256:/arguments/2']),
    'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))':
      new Set([
        'itUint256:/arguments/5',
        'itUint256:/arguments/6',
        'itUint256:/arguments/9',
        'itUint256:/arguments/10',
      ]),
    'acceptDirectTrade(uint256,((uint256,uint256),bytes))': new Set([
      'itUint256:/arguments/1',
    ]),
    'acceptDirectTradeWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))':
      new Set([
        'itUint256:/arguments/1',
        'itUint256:/arguments/2',
      ]),
    'acceptCounterTradeAndCloseParent(uint256,((uint256,uint256),bytes))':
      new Set(['itUint256:/arguments/1']),
    'fillPrivateOrder(uint256,((uint256,uint256),bytes))': new Set([
      'itUint256:/arguments/1',
    ]),
    'fillPrivateOrderWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))':
      new Set([
        'itUint256:/arguments/1',
        'itUint256:/arguments/2',
      ]),
    'fillHybridPrivateOrderWithEncryptedAccess(uint256,uint256,((uint256,uint256),bytes))':
      new Set(['itUint256:/arguments/2']),
  };
  const definitions = new Map<
    string,
    { kind: string; source: string; asset: string; allowZero: boolean }
  >();
  const groupIds = new Set<string>();
  const destinations = new Set<string>();
  for (const group of artifacts) {
    if (
      !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/u.test(group.id) ||
      groupIds.has(group.id)
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private artifact group identifiers must be unique and safe.',
      );
    }
    groupIds.add(group.id);
    const step = envelope.steps.find(
      (candidate) => candidate.id === group.bindToStepId,
    );
    const signature = step?.callTemplate?.functionSignature;
    if (
      !step ||
      !signature ||
      !allowedRecipeSignatures[group.recipe]?.has(signature) ||
      !group.values.length ||
      !group.outputs.length
    ) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'A committed private artifact recipe is not supported for its signed call.',
      );
    }
    if (group.recipe === 'coti-private-exact-allowance-v1') {
      if (
        step.kind !== 'approval' ||
        step.allowance?.scheme !== 'coti-private-exact' ||
        step.allowance.amount !== '0' ||
        step.allowance.amountCommitment?.toLowerCase() !==
          group.commitment.toLowerCase() ||
        group.context?.accountEncryptionRequired !== true ||
        normalizeAddress(String(group.context?.token ?? '')) !==
          normalizeAddress(step.to) ||
        normalizeAddress(String(group.context?.targetContract ?? '')) !==
          normalizeAddress(step.to) ||
        String(group.context?.functionSelector ?? '').toLowerCase() !==
          PRIVATE_APPROVE_SELECTOR ||
        normalizeAddress(String(group.context?.spender ?? '')) !==
          normalizeAddress(step.allowance.spender)
      ) {
        throw new SignerError(
          'EXACT_ALLOWANCE_REQUIRED',
          'The committed private allowance recipe is not canonical.',
        );
      }
    } else if (
      step.kind !== 'protocol' ||
      (
        group.recipe === 'private-fill-v1' ||
        group.recipe === 'private-recurring-fill-v1'
          ? envelope.intent.action !== 'fill'
          : group.recipe === 'private-recurring-v1'
            ? envelope.intent.action !== 'create_recurring'
            : group.recipe === 'direct-counter-v1'
              ? envelope.intent.action !== 'counter'
              : group.recipe === 'direct-edit-v1' ||
                  group.recipe === 'private-liquidity-edit-v1' ||
                  group.recipe === 'recurring-edit-v1'
                ? envelope.intent.action !== 'edit'
                : envelope.intent.action !== 'create_trade'
      )
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private recipe action binding is invalid.',
      );
    }
    if (group.recipe === 'direct-counter-v1') {
      const expectedCounterRoute =
        signature.startsWith(
          'createDirectCounterTradeForParent(',
        )
          ? 'cross-escrow'
          : signature.startsWith(
                'counterTradeAndCloseCounteredTrade(',
              )
            ? 'direct-counter'
            : 'direct-primary';
      const metadata = envelope.intent.metadata;
      const sourceRecipient = metadata?.sourceRecipient;
      const contextSourceRecipient = group.context?.sourceRecipient;
      const sameOptionalAddress =
        sourceRecipient === null
          ? contextSourceRecipient === null
          : typeof sourceRecipient === 'string' &&
            typeof contextSourceRecipient === 'string' &&
            normalizeAddress(sourceRecipient) ===
              normalizeAddress(contextSourceRecipient);
      if (
        group.context?.access !== 'direct' ||
        normalizeAddress(String(group.context?.maker ?? '')) !==
          normalizeAddress(envelope.wallet) ||
        normalizeAddress(String(group.context?.recipient ?? '')) !==
          normalizeAddress(String(envelope.intent.recipient ?? '')) ||
        group.context?.counterRoute !== expectedCounterRoute ||
        group.context?.counterRoute !== metadata?.counterRoute ||
        group.context?.sourceOrderRelation !==
          metadata?.sourceOrderRelation ||
        normalizeAddress(String(group.context?.sourceMaker ?? '')) !==
          normalizeAddress(String(metadata?.sourceMaker ?? '')) ||
        !sameOptionalAddress ||
        normalizeAddress(
          String(group.context?.parentEscrowContract ?? ''),
        ) !==
          normalizeAddress(
            String(metadata?.parentEscrowContract ?? ''),
          ) ||
        String(group.context?.parentTradeId ?? '') !==
          String(metadata?.parentTradeId ?? '') ||
        normalizeAddress(
          String(group.context?.counteredEscrowContract ?? ''),
        ) !==
          normalizeAddress(
            String(metadata?.counteredEscrowContract ?? ''),
          ) ||
        String(group.context?.counteredTradeId ?? '') !==
          String(metadata?.counteredTradeId ?? '')
      ) {
        throw new SignerError(
          'ENVELOPE_TAMPERED',
          'The Direct-counter private recipe route is not canonical.',
        );
      }
    }
    const signedAccess =
      envelope.intent.orderType?.access ?? envelope.intent.accessMode;
    if (
      [
        'direct-order-v1',
        'direct-edit-v1',
        'private-liquidity-v1',
        'private-liquidity-edit-v1',
      ].includes(group.recipe) &&
      group.context?.access !== signedAccess
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'The private artifact access context does not match the signed order type.',
      );
    }
    const expectedOutputs = new Set(allowedOutputs[signature]);
    const discardOutputs = (...keys: string[]): void => {
      for (const key of keys) expectedOutputs.delete(key);
    };
    const sellIsPrivate =
      envelope.intent.sellAsset?.kind === 'private-erc20';
    const buyIsPrivate =
      envelope.intent.buyAsset?.kind === 'private-erc20';
    if (
      signature ===
      'createDirectTrade((uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
    ) {
      if (!sellIsPrivate) discardOutputs('itUint256:/arguments/3');
      if (!buyIsPrivate) discardOutputs('itUint256:/arguments/4');
    } else if (
      signature ===
        'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)' ||
      signature ===
        'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)' ||
      signature ===
        'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
    ) {
      if (!sellIsPrivate) discardOutputs('itUint256:/arguments/4');
      if (!buyIsPrivate) discardOutputs('itUint256:/arguments/5');
    } else if (
      signature ===
      'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)'
    ) {
      if (!sellIsPrivate) discardOutputs('itUint256:/arguments/6');
      if (!buyIsPrivate) discardOutputs('itUint256:/arguments/7');
    } else if (
      signature ===
      'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)'
    ) {
      if (signedAccess === 'unlisted') {
        discardOutputs(
          'uint256:/arguments/0/2',
          'uint256:/arguments/1/2',
        );
      } else {
        discardOutputs(
          'keccak256:/arguments/5',
          'terms-hash-v1:/arguments/6',
          'itUint256:/arguments/8',
          'itUint256:/arguments/9',
          'itUint256:/arguments/11',
          'direct-terms-v1:/arguments/12',
        );
      }
    } else if (
      signature ===
      'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)'
    ) {
      if (signedAccess === 'unlisted') {
        discardOutputs(
          'uint256:/arguments/1/2',
          'uint256:/arguments/2/2',
        );
      } else {
        discardOutputs(
          'keccak256:/arguments/6',
          'terms-hash-v1:/arguments/7',
          'itUint256:/arguments/9',
          'itUint256:/arguments/10',
          'itUint256:/arguments/12',
          'direct-terms-v1:/arguments/13',
        );
      }
    } else if (
      signature ===
      'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))'
    ) {
      if (!sellIsPrivate) {
        discardOutputs(
          'itUint256:/arguments/5',
          'itUint256:/arguments/9',
        );
      }
      if (!buyIsPrivate) {
        discardOutputs(
          'itUint256:/arguments/6',
          'itUint256:/arguments/10',
        );
      }
    }
    const actualOutputs = new Set(
      group.outputs.map(
        (output) => `${output.kind}:${output.jsonPointer}`,
      ),
    );
    if (
      actualOutputs.size !== expectedOutputs.size ||
      [...expectedOutputs].some((key) => !actualOutputs.has(key))
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'A committed private artifact recipe is incomplete for its signed call.',
      );
    }
    for (const value of group.values) {
      const {
        commitment: _valueCommitment,
        ...safeValue
      } = value;
      if (
        !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/u.test(value.id) ||
        value.commitment.toLowerCase() !==
          privateArtifactCommitment(pairingSecret, {
            bindToStepId: step.id,
            groupId: group.id,
            recipe: group.recipe,
            value: safeValue,
          }).toLowerCase() ||
        (
          value.kind === 'uint256' &&
          (
            !value.asset ||
            (
              canonicalize(value.asset) !==
                canonicalize(envelope.intent.sellAsset) &&
              canonicalize(value.asset) !==
                canonicalize(envelope.intent.buyAsset)
            )
          )
        ) ||
        (value.kind === 'access-secret' && value.asset)
      ) {
        throw new SignerError(
          'ENVELOPE_TAMPERED',
          'A private artifact value binding is invalid.',
        );
      }
      const definition = {
        kind: value.kind,
        source: value.source,
        asset: canonicalize(value.asset ?? null),
        allowZero: Boolean(value.allowZero),
      };
      const previous = definitions.get(value.id);
      if (
        previous &&
        canonicalize(previous) !== canonicalize(definition)
      ) {
        throw new SignerError(
          'ENVELOPE_TAMPERED',
          'A shared private value has conflicting cross-step bindings.',
        );
      }
      definitions.set(value.id, definition);
    }
    for (const output of group.outputs) {
      const key = `${output.kind}:${output.jsonPointer}`;
      const destination = `${step.id}:${output.jsonPointer}`;
      if (
        !allowedOutputs[signature]?.has(key) ||
        destinations.has(destination) ||
        (
          output.valueId !== undefined &&
          !group.values.some((value) => value.id === output.valueId)
        ) ||
        (
          output.valueId === undefined &&
          ![
            'terms-hash-v1',
            'trade-recovery-v1',
            'recurring-recovery-v1',
          ].includes(output.kind)
        )
      ) {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'A private artifact output binding is invalid.',
        );
      }
      destinations.add(destination);
    }
    const {
      commitment: _groupCommitment,
      ...safeGroup
    } = group;
    if (
      group.commitment.toLowerCase() !==
      privateArtifactCommitment(pairingSecret, safeGroup).toLowerCase()
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'A private artifact group commitment is invalid.',
      );
    }
  }
  return true;
};

const assertFeeBinding = (
  envelope: SignedActionEnvelopeV1,
  runtime: RuntimeRegistryState,
): void => {
  assertUnsignedInteger(envelope.fee.amount, 'Fee amount');
  if (!isHexAddress(envelope.fee.recipient) || envelope.fee.asset !== 'native') {
    throw new SignerError('ENVELOPE_INVALID', 'Fee binding is invalid.');
  }
  const protocolTarget = envelope.steps
    .find((step) => step.kind === 'protocol')
    ?.to.toLowerCase();
  if (envelope.intent.action === 'privacy_bridge') {
    if (
      !protocolTarget ||
      envelope.fee.amount !== '0' ||
      normalizeAddress(envelope.fee.recipient) !==
        normalizeAddress(protocolTarget) ||
      envelope.registrySnapshot.fees[protocolTarget] !== '0'
    ) {
      throw new SignerError(
        'FEE_CHANGED',
        'The Privacy Portal envelope fee binding is invalid.',
      );
    }
    return;
  }
  const feeKeyCandidates = [
    protocolTarget
      ? `${envelope.intent.action}:${protocolTarget}`
      : null,
    protocolTarget,
    envelope.intent.action,
    '*',
  ].filter((key): key is string => Boolean(key));
  const trustedFeeKey = feeKeyCandidates.find(
    (key) =>
      runtime.fees[key] !== undefined &&
      runtime.trustedFeeRecipients[key] !== undefined,
  );
  if (!trustedFeeKey) {
    throw new SignerError(
      'FEE_CHANGED',
      'No live contract fee binding exists for this action target.',
    );
  }
  const scheduleAmount = runtime.fees[trustedFeeKey];
  const signedScheduleAmount = protocolTarget
    ? envelope.registrySnapshot.fees[protocolTarget]
    : undefined;
  if (
    signedScheduleAmount === undefined ||
    signedScheduleAmount !== scheduleAmount
  ) {
    throw new SignerError(
      'FEE_CHANGED',
      'The current fee schedule has changed.',
    );
  }
  const chargedAmount =
    envelope.intent.action === 'create_trade' ||
    envelope.intent.action === 'create_recurring' ||
    envelope.intent.action === 'counter'
      ? scheduleAmount
      : envelope.intent.action === 'edit'
        ? runtime.editFees?.[trustedFeeKey] ?? '0'
      : '0';
  if (chargedAmount !== envelope.fee.amount) {
    throw new SignerError('FEE_CHANGED', 'The action fee has changed.');
  }
  const trustedRecipient =
    runtime.trustedFeeRecipients[trustedFeeKey];
  if (
    !trustedRecipient ||
    normalizeAddress(trustedRecipient) !==
      normalizeAddress(envelope.fee.recipient)
  ) {
    throw new SignerError(
      'FEE_CHANGED',
      'The signed fee recipient does not match the current contract.',
    );
  }
};

export type VerifiedAction = {
  envelope: SignedActionEnvelopeV1;
  runtime: RuntimeRegistryState;
};

export class ActionEnvelopeVerifier {
  readonly #config: LoadedSignerConfig;
  readonly #runtimeState: RuntimeStateReader;
  readonly #clock: () => Date;

  constructor(
    config: LoadedSignerConfig,
    runtimeState: RuntimeStateReader,
    clock: () => Date = () => new Date(),
  ) {
    this.#config = config;
    this.#runtimeState = runtimeState;
    this.#clock = clock;
  }

  assertFreshness(signedEnvelope: SignedActionEnvelopeV1): void {
    const now = this.#clock();
    const issuedAt = Date.parse(signedEnvelope.issuedAt);
    const expiresAt = Date.parse(signedEnvelope.expiresAt);
    if (
      issuedAt > now.getTime() + this.#config.operationExpirySkewMs ||
      expiresAt - now.getTime() <= this.#config.operationExpirySkewMs
    ) {
      throw new SignerError(
        'STALE_STATE',
        'The action plan is too close to expiry or was issued in the future.',
      );
    }
    assertMarketReferenceFreshness(signedEnvelope, now);
  }

  async verify(
    signedEnvelope: SignedActionEnvelopeV1,
    wallet: Address,
  ): Promise<VerifiedAction> {
    const now = this.#clock();
    const verified = verifySignedActionEnvelope(
      signedEnvelope,
      this.#config.credentialMaterial().pairingSecret,
      now,
    );
    if (!verified.ok) {
      if (verified.error === 'envelope-expired') {
        throw new SignerError('ENVELOPE_EXPIRED', 'The action plan has expired.');
      }
      if (verified.error === 'pairing-signature-invalid') {
        throw new SignerError(
          'PAIRING_FAILED',
          'The action plan was not signed by the paired planning server.',
        );
      }
      if (verified.error === 'operation-hash-mismatch') {
        throw new SignerError(
          'ENVELOPE_TAMPERED',
          'The action plan changed after it was prepared.',
        );
      }
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The action plan is not supported.',
      );
    }
    if (!isSafeOperationId(signedEnvelope.operationId)) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The action plan contains an invalid operation id.',
      );
    }
    const hasSupportedPrivateArtifacts = assertSupportedPrivateArtifacts(
      signedEnvelope,
      this.#config.credentialMaterial().pairingSecret,
    );

    this.assertFreshness(signedEnvelope);
    if (
      normalizeAddress(signedEnvelope.wallet) !== normalizeAddress(wallet) ||
      (this.#config.expectedWallet &&
        normalizeAddress(this.#config.expectedWallet) !==
          normalizeAddress(wallet))
    ) {
      throw new SignerError(
        'WALLET_MISMATCH',
        'The action plan targets a different wallet.',
      );
    }
    const runtime = await this.#runtimeState.readRegistryState();
    if (
      runtime.chainId !== this.#config.chainId ||
      signedEnvelope.chainId !== runtime.chainId
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The action plan targets an unexpected chain.',
      );
    }
    if (
      normalizeAddress(signedEnvelope.registrySnapshot.manifestHash) !==
      normalizeAddress(runtime.registryHash)
    ) {
      throw new SignerError(
        'REGISTRY_CHANGED',
        'The deployed ChainWhisper registry has changed.',
      );
    }
    if (
      signedEnvelope.simulation.status !== 'passed' &&
      !(
        hasSupportedPrivateArtifacts &&
        signedEnvelope.simulation.status === 'incomplete' &&
        signedEnvelope.simulation.reason ===
          'signer-local-private-artifacts-require-simulation'
      )
    ) {
      throw new SignerError(
        'STALE_STATE',
        'Only a currently successful simulation can be executed.',
      );
    }
    if (!signedEnvelope.steps.length) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'The action plan is incomplete and has no executable steps.',
      );
    }
    const exactNativeValue = BigInt(
      assertUnsignedInteger(
        signedEnvelope.exactNativeValue,
        'Exact native value',
      ),
    );
    const stepValue = signedEnvelope.steps.reduce(
      (total, step) =>
        total + BigInt(assertUnsignedInteger(step.value, 'Step value')),
      0n,
    );
    if (stepValue !== exactNativeValue) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Transaction values do not match the signed exact native value.',
      );
    }
    const gasCap = BigInt(
      assertUnsignedInteger(signedEnvelope.gasCap, 'Envelope gas cap'),
    );
    const totalStepGas = signedEnvelope.steps.reduce(
      (total, step) => total + BigInt(step.gasCap),
      0n,
    );
    if (gasCap <= 0n || totalStepGas > gasCap) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Transaction steps exceed the signed gas cap.',
      );
    }
    assertFeeBinding(signedEnvelope, runtime);
    assertLegacyStandardCounterActionBinding(signedEnvelope);
    assertLegacyStandardLifecycleTypeBinding(signedEnvelope);
    assertPrivateInputPolicy(signedEnvelope);
    for (let index = 0; index < signedEnvelope.steps.length; index += 1) {
      const step = signedEnvelope.steps[index]!;
      if (step.allowance?.scheme !== 'erc20-reset') continue;
      const next = signedEnvelope.steps[index + 1];
      if (
        !next ||
        next.kind !== 'approval' ||
        next.allowance?.scheme !== 'erc20-exact' ||
        normalizeAddress(next.allowance.token) !==
          normalizeAddress(step.allowance.token) ||
        normalizeAddress(next.allowance.spender) !==
          normalizeAddress(step.allowance.spender)
      ) {
        throw new SignerError(
          'EXACT_ALLOWANCE_REQUIRED',
          'An ERC-20 allowance reset must be immediately followed by its exact replacement.',
        );
      }
    }
    for (const step of signedEnvelope.steps) {
      assertStep(step, runtime.allowedContracts);
      assertProtocolSelector(step, runtime);
    }
    for (const placeholder of signedEnvelope.privateInputs) {
      const step = signedEnvelope.steps.find(
        (candidate) => candidate.id === placeholder.bindToStepId,
      );
      if (!step?.callTemplate) {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private inputs require a signed canonical call template.',
        );
      }
    }
    return { envelope: signedEnvelope, runtime };
  }
}
