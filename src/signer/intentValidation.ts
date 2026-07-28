import {
  decodeFunctionData,
  keccak256,
  parseAbi,
  parseUnits,
  type Abi,
  type Hex,
} from 'viem';

import {
  isHexAddress,
  privacyBridgePair,
  type NormalizedAssetV1,
  type SignedActionEnvelopeV1,
} from '../shared/index.js';
import { SignerError } from './errors.js';
import { validateSignedOrderClassification } from './orderClassificationValidation.js';
import type {
  MaterializedActionStep,
  MaterializedIntentValidator,
  StandardOrderFacts,
  StandardOrderFactsReader,
} from './types.js';

const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const ZERO_BYTES32 = `0x${'00'.repeat(32)}`;
const MAX_UINT128 = (1n << 128n) - 1n;

const SIGNATURES = {
  createTrade:
    'createTradeWithPolicy((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,uint256,(bool,uint16,uint256,uint256,bool))',
  createPrivateTrade:
    'createPrivateOrderWithRecoveryNote((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)',
  createDirectTrade:
    'createDirectTrade((uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  createRecurring:
    'createRecurringOrder((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256)',
  createPrivateRecurring:
    'createPrivateRecurringOrderWithRecoveryNote((uint8,address),(uint8,address),(uint256,uint256),(uint256,uint256),address,bool,bytes32,uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),bytes)',
  createDirectCounterForParent:
    'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  createDirectCounter:
    'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  counterDirectAndClose:
    'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  counterLegacyStandardAndClose:
    'counterTradeAndCloseCounteredTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),uint64)',
  editLegacyStandard:
    'editTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32)',
  editStandard:
    'editTradeWithPolicy(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,(bool,uint16,uint256,uint256,bool))',
  editPrivateLiquidity:
    'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)',
  editDirect:
    'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  editRecurring:
    'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
  fillTrade: 'fillTrade(uint256,uint256,uint256)',
  fillRecurringBuy:
    'fillBuySideWithSecret(uint256,uint256,uint256,bytes32)',
  fillRecurringSell:
    'fillSellSideWithSecret(uint256,uint256,uint256,bytes32)',
  fillPrivateRecurringBuy:
    'fillPrivateBuySideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)',
  fillPrivateRecurringSell:
    'fillPrivateSellSideWithSecret(uint256,uint256,((uint256,uint256),bytes),uint256,bytes32)',
  acceptDirect:
    'acceptDirectTrade(uint256,((uint256,uint256),bytes))',
  acceptDirectWithAccess:
    'acceptDirectTradeWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
  acceptDirectCounter:
    'acceptCounterTradeAndCloseParent(uint256,((uint256,uint256),bytes))',
  acceptLegacyStandardCounter:
    'acceptCounterTradeAndCloseParent(uint256)',
  fillPrivate:
    'fillPrivateOrder(uint256,((uint256,uint256),bytes))',
  fillPrivateWithAccess:
    'fillPrivateOrderWithEncryptedAccess(uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
  fillHybridPrivate:
    'fillHybridPrivateOrder(uint256,uint256)',
  fillHybridPrivateWithAccess:
    'fillHybridPrivateOrderWithEncryptedAccess(uint256,uint256,((uint256,uint256),bytes))',
  cancelTrade: 'cancelTrade(uint256)',
  declineTrade: 'declineTrade(uint256)',
  extendTradeExpiry: 'extendTradeExpiry(uint256,uint64)',
  refreshTrade: 'refreshTrade(uint256)',
  reclaimExpiredTrade: 'reclaimExpiredTrade(uint256)',
  pauseOrder: 'pauseOrder(uint256)',
  resumeOrder: 'resumeOrder(uint256)',
  cancelOrder: 'cancelOrder(uint256)',
  settleInventory: 'settleInventory(uint256)',
  bridgeDepositNative: 'deposit(uint256,uint256)',
  bridgeDepositToken: 'deposit(uint256,uint256,uint256)',
  bridgeWithdraw: 'withdraw(uint256,uint256,uint256)',
} as const;

const fail = (message: string): never => {
  throw new SignerError('ENVELOPE_TAMPERED', message);
};

const invalid = (message: string): never => {
  throw new SignerError('ENVELOPE_INVALID', message);
};

const asArguments = (value: unknown): readonly unknown[] => {
  if (!Array.isArray(value)) {
    return invalid('Decoded protocol arguments are not canonical.');
  }
  return value;
};

const asTuple = (
  value: unknown,
  expectedLength: number,
  label: string,
): readonly unknown[] => {
  if (!Array.isArray(value) || value.length !== expectedLength) {
    return fail(`${label} does not match the signed intent.`);
  }
  return value;
};

const asIntegerString = (value: unknown): string => {
  if (
    typeof value !== 'bigint' &&
    typeof value !== 'number' &&
    typeof value !== 'string'
  ) {
    return fail('Protocol calldata contains a non-integer value.');
  }
  const normalized = String(value);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(normalized)) {
    return fail('Protocol calldata contains a non-canonical integer.');
  }
  return normalized;
};

const sameAddress = (left: unknown, right: string): boolean =>
  typeof left === 'string' &&
  left.toLowerCase() === right.toLowerCase();

const requireAddress = (
  actual: unknown,
  expected: string,
  label: string,
): void => {
  if (!sameAddress(actual, expected)) {
    fail(`${label} does not match the signed intent.`);
  }
};

const requireInteger = (
  actual: unknown,
  expected: string,
  label: string,
): void => {
  if (asIntegerString(actual) !== expected) {
    fail(`${label} does not match the signed intent.`);
  }
};

const requireBoolean = (
  actual: unknown,
  expected: boolean,
  label: string,
): void => {
  if (actual !== expected) {
    fail(`${label} does not match the signed intent.`);
  }
};

const requireBytes32 = (
  actual: unknown,
  expected: string,
  label: string,
): void => {
  if (
    typeof actual !== 'string' ||
    actual.toLowerCase() !== expected.toLowerCase()
  ) {
    fail(`${label} does not match the signed intent.`);
  }
};

const requireNonzeroBytes32 = (
  actual: unknown,
  label: string,
): void => {
  if (
    typeof actual !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/u.test(actual) ||
    actual.toLowerCase() === ZERO_BYTES32
  ) {
    fail(`${label} is not a nonzero bytes32 value.`);
  }
};

const requireBytes = (
  actual: unknown,
  label: string,
  allowEmpty = false,
): void => {
  if (
    typeof actual !== 'string' ||
    !/^0x(?:[0-9a-fA-F]{2})*$/u.test(actual) ||
    (!allowEmpty && actual === '0x')
  ) {
    fail(`${label} is not canonical bytes data.`);
  }
};

const requireEmptyBytes = (
  actual: unknown,
  label: string,
): void => {
  requireBytes(actual, label, true);
  if (actual !== '0x') {
    fail(`${label} must be empty.`);
  }
};

const requireEncryptedInput = (
  actual: unknown,
  label: string,
  allowEmpty = false,
): void => {
  const tuple = asTuple(actual, 2, label);
  const ciphertext = asTuple(tuple[0], 2, `${label} ciphertext`);
  const high = BigInt(asIntegerString(ciphertext[0]));
  const low = BigInt(asIntegerString(ciphertext[1]));
  requireBytes(tuple[1], `${label} signature`, allowEmpty);
  if (
    !allowEmpty &&
    high === 0n &&
    low === 0n
  ) {
    fail(`${label} ciphertext is empty.`);
  }
  if (
    allowEmpty &&
    tuple[1] === '0x' &&
    (high !== 0n || low !== 0n)
  ) {
    fail(`${label} empty ciphertext is malformed.`);
  }
};

const requireEmptyEncryptedInput = (
  actual: unknown,
  label: string,
): void => {
  const tuple = asTuple(actual, 2, label);
  const ciphertext = asTuple(tuple[0], 2, `${label} ciphertext`);
  requireInteger(ciphertext[0], '0', `${label} ciphertext high`);
  requireInteger(ciphertext[1], '0', `${label} ciphertext low`);
  requireBytes(tuple[1], `${label} signature`, true);
  if (tuple[1] !== '0x') {
    fail(`${label} must be the canonical empty encrypted input.`);
  }
};

const privateValue = (
  step: MaterializedActionStep,
  ids: readonly string[],
  label: string,
): string => {
  for (const id of ids) {
    const value = step.privateValues?.[id];
    if (value && /^(?:0|[1-9][0-9]*)$/u.test(value)) return value;
  }
  return fail(`The signer-local ${label} is missing.`);
};

const privateSecret = (
  step: MaterializedActionStep,
  id: string,
  label: string,
): Hex => {
  const value = step.privateValues?.[id];
  if (
    typeof value !== 'string' ||
    !/^0x[0-9a-fA-F]{64}$/u.test(value) ||
    value.toLowerCase() === ZERO_BYTES32
  ) {
    return fail(`The signer-local ${label} is missing.`);
  }
  return value as Hex;
};

const requireAccessAndTermsBindings = (
  step: MaterializedActionStep,
  accessHash: unknown,
  termsHash: unknown,
  encryptedAccess: unknown,
  termsPayload: unknown,
  label: string,
): void => {
  const accessSecret = privateSecret(
    step,
    'order-access-secret',
    `${label} access secret`,
  );
  requireBytes32(
    accessHash,
    keccak256(accessSecret),
    `${label} access hash`,
  );
  requireBytes(termsPayload, `${label} encrypted terms`);
  requireBytes32(
    termsHash,
    keccak256(termsPayload as Hex),
    `${label} terms hash`,
  );
  requireEncryptedInput(
    encryptedAccess,
    `${label} encrypted access secret`,
  );
};

const atomic = (
  amount: string | undefined,
  asset: NormalizedAssetV1 | undefined,
  label: string,
  optional = false,
): string => {
  if (!amount) {
    if (optional) return '0';
    return fail(`The signed ${label} is missing.`);
  }
  if (asset?.decimals === undefined) {
    return fail(`The signed ${label} asset precision is missing.`);
  }
  try {
    const value = parseUnits(amount, asset.decimals);
    if (value < 0n || (!optional && value <= 0n)) throw new Error('range');
    return value.toString();
  } catch {
    return fail(`The signed ${label} cannot be represented exactly.`);
  }
};

const assetType = (asset: NormalizedAssetV1): string =>
  asset.kind === 'native' ? '0' : asset.kind === 'erc20' ? '1' : '2';

const assetAddress = (asset: NormalizedAssetV1): string => {
  if (asset.kind === 'native') return ZERO_ADDRESS;
  if (!asset.address) return fail('A signed token address is missing.');
  return asset.address;
};

const requireAssetTuple = (
  value: unknown,
  asset: NormalizedAssetV1 | undefined,
  amount: string | null,
  label: string,
): void => {
  const requiredAsset =
    asset ?? fail(`The signed ${label} is missing.`);
  const tuple = asTuple(value, amount === null ? 2 : 3, label);
  requireInteger(tuple[0], assetType(requiredAsset), `${label} kind`);
  requireAddress(
    tuple[1],
    assetAddress(requiredAsset),
    `${label} address`,
  );
  if (amount !== null) {
    requireInteger(tuple[2], amount, `${label} amount`);
  }
};

const metadataValue = (
  envelope: SignedActionEnvelopeV1,
  key: string,
): string | number | boolean | null => {
  const metadata = envelope.intent.metadata;
  if (!metadata || !(key in metadata)) {
    return fail(`Signed intent metadata is missing ${key}.`);
  }
  return metadata[key] ?? null;
};

const optionalMetadataValue = (
  envelope: SignedActionEnvelopeV1,
  key: string,
): string | number | boolean | null | undefined =>
  envelope.intent.metadata?.[key];

const metadataString = (
  envelope: SignedActionEnvelopeV1,
  key: string,
  nullable = false,
): string | null => {
  const value = metadataValue(envelope, key);
  if (value === null && nullable) return null;
  if (typeof value !== 'string') {
    return fail(`Signed intent metadata ${key} has an invalid type.`);
  }
  return value;
};

const metadataBoolean = (
  envelope: SignedActionEnvelopeV1,
  key: string,
): boolean => {
  const value = metadataValue(envelope, key);
  if (typeof value !== 'boolean') {
    return fail(`Signed intent metadata ${key} has an invalid type.`);
  }
  return value;
};

const metadataInteger = (
  envelope: SignedActionEnvelopeV1,
  key: string,
): string => {
  const value = metadataValue(envelope, key);
  return asIntegerString(value);
};

const optionalMetadataDecimal = (
  envelope: SignedActionEnvelopeV1,
  key: string,
): string | undefined => {
  const value = optionalMetadataValue(envelope, key);
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') {
    return fail(`Signed intent metadata ${key} has an invalid type.`);
  }
  return value;
};

const optionalAtomicMetadata = (
  envelope: SignedActionEnvelopeV1,
  key: string,
  asset: NormalizedAssetV1,
  label: string,
): string =>
  atomic(optionalMetadataDecimal(envelope, key), asset, label, true);

const isoToUnixSeconds = (value: string | undefined): string => {
  if (!value) return '0';
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    return fail('The signed expiry is invalid.');
  }
  return Math.floor(milliseconds / 1_000).toString();
};

const requirePublicVisible = (
  envelope: SignedActionEnvelopeV1,
): void => {
  if (
    envelope.intent.accessMode !== 'public' ||
    envelope.intent.amountVisibility !== 'visible' ||
    envelope.intent.recipient
  ) {
    fail('This public calldata shape is incompatible with the signed access policy.');
  }
};

const requireProtocolValue = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  principal: bigint,
): void => {
  const expected = principal + BigInt(envelope.fee.amount);
  requireInteger(step.value, expected.toString(), 'Protocol native value');
};

const validateCreateTrade = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 8) fail('Create-trade calldata has an invalid shape.');
  requirePublicVisible(envelope);
  const sellAmount = atomic(
    envelope.intent.sellAmount,
    envelope.intent.sellAsset,
    'sell amount',
  );
  const buyAmount = atomic(
    envelope.intent.buyAmount,
    envelope.intent.buyAsset,
    'buy amount',
  );
  requireAssetTuple(
    args[0],
    envelope.intent.sellAsset,
    sellAmount,
    'sell asset',
  );
  requireAssetTuple(
    args[1],
    envelope.intent.buyAsset,
    buyAmount,
    'buy asset',
  );
  requireAddress(args[2], ZERO_ADDRESS, 'Public recipient');
  requireInteger(
    args[3],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Trade expiry',
  );
  requireBoolean(args[4], true, 'Public-order flag');
  requireBytes32(args[5], ZERO_BYTES32, 'Public access secret');
  requireInteger(args[6], '0', 'Parent trade identifier');

  const policy = asTuple(args[7], 5, 'Fill policy');
  requireBoolean(
    policy[0],
    metadataBoolean(envelope, 'partialFillsAllowed'),
    'Partial-fill policy',
  );
  requireInteger(
    policy[1],
    metadataInteger(envelope, 'minPartialFillBps'),
    'Minimum partial-fill basis points',
  );
  const minRequestAmount = metadataString(
    envelope,
    'minRequestAmount',
    true,
  );
  const maxPerWallet = metadataString(
    envelope,
    'maxRequestAmountPerWallet',
    true,
  );
  requireInteger(
    policy[2],
    atomic(
      minRequestAmount ?? undefined,
      envelope.intent.buyAsset,
      'minimum request amount',
      true,
    ),
    'Minimum request amount',
  );
  requireInteger(
    policy[3],
    atomic(
      maxPerWallet ?? undefined,
      envelope.intent.buyAsset,
      'maximum request amount per wallet',
      true,
    ),
    'Maximum request amount per wallet',
  );
  requireBoolean(
    policy[4],
    metadataBoolean(envelope, 'oneFillPerWallet'),
    'One-fill-per-wallet policy',
  );

  const principal =
    envelope.intent.sellAsset?.kind === 'native'
      ? BigInt(sellAmount)
      : 0n;
  requireProtocolValue(envelope, step, principal);
};

const validateCreateDirectTrade = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 11) {
    fail('Direct create calldata has an invalid shape.');
  }
  if (
    envelope.intent.action !== 'create_trade' ||
    envelope.intent.amountVisibility !== 'visible' ||
    (
      envelope.intent.accessMode !== 'direct' &&
      envelope.intent.accessMode !== 'unlisted'
    )
  ) {
    fail('Direct create calldata is incompatible with the signed access policy.');
  }
  const sellAsset =
    envelope.intent.sellAsset ??
    fail('The signed Direct sell asset is missing.');
  const buyAsset =
    envelope.intent.buyAsset ??
    fail('The signed Direct buy asset is missing.');
  requireAssetTuple(args[0], sellAsset, null, 'Direct sell asset');
  requireAssetTuple(args[1], buyAsset, null, 'Direct buy asset');
  const sellAmount =
    sellAsset.kind === 'private-erc20'
      ? privateValue(step, ['offer-amount'], 'Direct sell amount')
      : atomic(envelope.intent.sellAmount, sellAsset, 'Direct sell amount');
  const buyAmount =
    buyAsset.kind === 'private-erc20'
      ? privateValue(step, ['request-amount'], 'Direct buy amount')
      : atomic(envelope.intent.buyAmount, buyAsset, 'Direct buy amount');
  const publicAmounts = asTuple(args[2], 2, 'Direct public amounts');
  requireInteger(
    publicAmounts[0],
    sellAsset.kind === 'private-erc20' ? '0' : sellAmount,
    'Direct public sell amount',
  );
  requireInteger(
    publicAmounts[1],
    buyAsset.kind === 'private-erc20' ? '0' : buyAmount,
    'Direct public buy amount',
  );
  requireEncryptedInput(
    args[3],
    'Direct encrypted sell amount',
    sellAsset.kind !== 'private-erc20',
  );
  requireEncryptedInput(
    args[4],
    'Direct encrypted buy amount',
    buyAsset.kind !== 'private-erc20',
  );
  requireAddress(
    args[5],
    envelope.intent.accessMode === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed Direct recipient is missing.')
      : ZERO_ADDRESS,
    'Direct recipient',
  );
  requireInteger(
    args[6],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Direct expiry',
  );
  requireNonzeroBytes32(args[7], 'Direct access hash');
  requireNonzeroBytes32(args[8], 'Direct terms hash');
  requireEncryptedInput(args[9], 'Direct encrypted access secret');
  requireBytes(args[10], 'Direct encrypted terms');
  requireProtocolValue(
    envelope,
    step,
    sellAsset.kind === 'native' ? BigInt(sellAmount) : 0n,
  );
};

const validateCreatePrivateLiquidity = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 13) {
    fail('Private-liquidity create calldata has an invalid shape.');
  }
  if (
    envelope.intent.action !== 'create_trade' ||
    envelope.intent.amountVisibility !== 'private-hidden' ||
    envelope.intent.sellAsset?.kind !== 'private-erc20'
  ) {
    fail('Private-liquidity calldata is incompatible with the signed intent.');
  }
  const sellAsset = envelope.intent.sellAsset;
  const buyAsset =
    envelope.intent.buyAsset ??
    fail('The signed private-liquidity buy asset is missing.');
  const unlisted = envelope.intent.accessMode === 'unlisted';
  const publicOffer = unlisted
    ? '0'
    : privateValue(
        step,
        ['public-offer-term'],
        'public private-liquidity offer term',
      );
  const publicRequest = unlisted
    ? '0'
    : privateValue(
        step,
        ['public-request-term'],
        'public private-liquidity request term',
      );
  requireAssetTuple(
    args[0],
    sellAsset,
    publicOffer,
    'Private-liquidity sell asset',
  );
  requireAssetTuple(
    args[1],
    buyAsset,
    publicRequest,
    'Private-liquidity buy asset',
  );
  requireAddress(
    args[2],
    envelope.intent.accessMode === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed private-liquidity recipient is missing.')
      : ZERO_ADDRESS,
    'Private-liquidity recipient',
  );
  requireInteger(
    args[3],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Private-liquidity expiry',
  );
  requireBoolean(
    args[4],
    envelope.intent.accessMode === 'public',
    'Private-liquidity public flag',
  );
  if (unlisted) {
    requireNonzeroBytes32(args[5], 'Private-liquidity access hash');
    requireNonzeroBytes32(args[6], 'Private-liquidity terms hash');
  } else {
    requireBytes32(args[5], ZERO_BYTES32, 'Private-liquidity access hash');
    requireBytes32(args[6], ZERO_BYTES32, 'Private-liquidity terms hash');
  }
  requireEncryptedInput(args[7], 'Private-liquidity hidden offer');
  requireEncryptedInput(
    args[8],
    'Private-liquidity linked offer',
    !unlisted,
  );
  requireEncryptedInput(
    args[9],
    'Private-liquidity linked request',
    !unlisted,
  );
  requireBytes(args[10], 'Private-liquidity recovery note');
  requireEncryptedInput(
    args[11],
    'Private-liquidity encrypted access secret',
    !unlisted,
  );
  requireBytes(
    args[12],
    'Private-liquidity encrypted terms',
    !unlisted,
  );
  requireProtocolValue(envelope, step, 0n);
};

const validateCreateRecurring = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 9) {
    fail('Create-recurring calldata has an invalid shape.');
  }
  if (
    envelope.intent.action !== 'create_recurring' ||
    envelope.intent.amountVisibility !== 'visible' ||
    (
      envelope.intent.accessMode !== 'public' &&
      envelope.intent.accessMode !== 'direct'
    )
  ) {
    fail('Visible recurring calldata is incompatible with the signed intent.');
  }
  const baseAsset =
    envelope.intent.sellAsset ??
    fail('The signed recurring base asset is missing.');
  const quoteAsset =
    envelope.intent.buyAsset ??
    fail('The signed recurring quote asset is missing.');
  requireAssetTuple(args[0], baseAsset, null, 'base asset');
  requireAssetTuple(args[1], quoteAsset, null, 'quote asset');

  const baseUnit = (10n ** BigInt(baseAsset.decimals ?? -1)).toString();
  const buyPrice = atomic(
    metadataString(envelope, 'buyPrice') ?? undefined,
    quoteAsset,
    'buy price',
  );
  const sellPrice = atomic(
    metadataString(envelope, 'sellPrice') ?? undefined,
    quoteAsset,
    'sell price',
  );
  const buyTerms = asTuple(args[2], 2, 'Recurring buy terms');
  const sellTerms = asTuple(args[3], 2, 'Recurring sell terms');
  requireInteger(buyTerms[0], baseUnit, 'Recurring buy base unit');
  requireInteger(buyTerms[1], buyPrice, 'Recurring buy price');
  requireInteger(sellTerms[0], baseUnit, 'Recurring sell base unit');
  requireInteger(sellTerms[1], sellPrice, 'Recurring sell price');
  requireAddress(
    args[4],
    envelope.intent.accessMode === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed recurring recipient is missing.')
      : ZERO_ADDRESS,
    'Recurring recipient',
  );
  requireBoolean(
    args[5],
    envelope.intent.accessMode === 'public',
    'Recurring public flag',
  );
  requireBytes32(args[6], ZERO_BYTES32, 'Recurring access secret');

  const baseLiquidity = atomic(
    metadataString(envelope, 'sellBaseLiquidity', true) ?? undefined,
    baseAsset,
    'sell-base liquidity',
    true,
  );
  const quoteLiquidity = atomic(
    metadataString(envelope, 'buyQuoteLiquidity', true) ?? undefined,
    quoteAsset,
    'buy-quote liquidity',
    true,
  );
  if (BigInt(baseLiquidity) <= 0n && BigInt(quoteLiquidity) <= 0n) {
    fail('The signed recurring order has no funded liquidity side.');
  }
  requireInteger(args[7], baseLiquidity, 'Sell-base liquidity');
  requireInteger(args[8], quoteLiquidity, 'Buy-quote liquidity');
  const principal =
    (baseAsset.kind === 'native' ? BigInt(baseLiquidity) : 0n) +
    (quoteAsset.kind === 'native' ? BigInt(quoteLiquidity) : 0n);
  requireProtocolValue(envelope, step, principal);
};

const validateCreatePrivateRecurring = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (
    args.length !== 12 ||
    envelope.intent.action !== 'create_recurring' ||
    envelope.intent.amountVisibility !== 'private-hidden' ||
    (
      envelope.intent.accessMode !== 'public' &&
      envelope.intent.accessMode !== 'direct'
    )
  ) {
    fail('Private recurring calldata is incompatible with the signed intent.');
  }
  const baseAsset =
    envelope.intent.sellAsset ??
    fail('The signed recurring base asset is missing.');
  const quoteAsset =
    envelope.intent.buyAsset ??
    fail('The signed recurring quote asset is missing.');
  if (
    baseAsset.kind !== 'private-erc20' &&
    quoteAsset.kind !== 'private-erc20'
  ) {
    fail('Private recurring inventory has no private token side.');
  }
  requireAssetTuple(args[0], baseAsset, null, 'Recurring base asset');
  requireAssetTuple(args[1], quoteAsset, null, 'Recurring quote asset');
  const baseUnit = (10n ** BigInt(baseAsset.decimals ?? -1)).toString();
  const buyPrice = atomic(
    metadataString(envelope, 'buyPrice') ?? undefined,
    quoteAsset,
    'buy price',
  );
  const sellPrice = atomic(
    metadataString(envelope, 'sellPrice') ?? undefined,
    quoteAsset,
    'sell price',
  );
  const buyTerms = asTuple(args[2], 2, 'Recurring buy terms');
  const sellTerms = asTuple(args[3], 2, 'Recurring sell terms');
  requireInteger(buyTerms[0], baseUnit, 'Recurring buy base unit');
  requireInteger(buyTerms[1], buyPrice, 'Recurring buy price');
  requireInteger(sellTerms[0], baseUnit, 'Recurring sell base unit');
  requireInteger(sellTerms[1], sellPrice, 'Recurring sell price');
  requireAddress(
    args[4],
    envelope.intent.accessMode === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed recurring recipient is missing.')
      : ZERO_ADDRESS,
    'Recurring recipient',
  );
  requireBoolean(
    args[5],
    envelope.intent.accessMode === 'public',
    'Recurring public flag',
  );
  requireBytes32(args[6], ZERO_BYTES32, 'Recurring access hash');

  const baseInventory =
    baseAsset.kind === 'private-erc20'
      ? privateValue(
          step,
          ['recurring-base-inventory'],
          'private recurring base inventory',
        )
      : atomic(
          metadataString(envelope, 'sellBaseLiquidity', true) ?? undefined,
          baseAsset,
          'sell-base liquidity',
          true,
        );
  const quoteInventory =
    quoteAsset.kind === 'private-erc20'
      ? privateValue(
          step,
          ['recurring-quote-inventory'],
          'private recurring quote inventory',
        )
      : atomic(
          metadataString(envelope, 'buyQuoteLiquidity', true) ?? undefined,
          quoteAsset,
          'buy-quote liquidity',
          true,
        );
  if (BigInt(baseInventory) <= 0n && BigInt(quoteInventory) <= 0n) {
    fail('The signed recurring order has no funded liquidity side.');
  }
  requireInteger(
    args[7],
    baseAsset.kind === 'private-erc20' ? '0' : baseInventory,
    'Public base inventory',
  );
  requireInteger(
    args[8],
    quoteAsset.kind === 'private-erc20' ? '0' : quoteInventory,
    'Public quote inventory',
  );
  requireEncryptedInput(args[9], 'Encrypted base inventory');
  requireEncryptedInput(args[10], 'Encrypted quote inventory');
  requireBytes(args[11], 'Recurring recovery note');
  const principal =
    (baseAsset.kind === 'native' ? BigInt(baseInventory) : 0n) +
    (quoteAsset.kind === 'native' ? BigInt(quoteInventory) : 0n);
  requireProtocolValue(envelope, step, principal);
};

const directAmounts = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  label: string,
): {
  sellAsset: NormalizedAssetV1;
  buyAsset: NormalizedAssetV1;
  sellAmount: string;
  buyAmount: string;
} => {
  const sellAsset =
    envelope.intent.sellAsset ??
    fail(`The signed ${label} sell asset is missing.`);
  const buyAsset =
    envelope.intent.buyAsset ??
    fail(`The signed ${label} buy asset is missing.`);
  const values = {
    sellAsset,
    buyAsset,
    sellAmount:
      sellAsset.kind === 'private-erc20'
        ? privateValue(step, ['offer-amount'], `${label} sell amount`)
        : atomic(
            envelope.intent.sellAmount,
            sellAsset,
            `${label} sell amount`,
          ),
    buyAmount:
      buyAsset.kind === 'private-erc20'
        ? privateValue(step, ['request-amount'], `${label} buy amount`)
        : atomic(
            envelope.intent.buyAmount,
            buyAsset,
            `${label} buy amount`,
          ),
  };
  if (
    BigInt(values.sellAmount) <= 0n ||
    BigInt(values.buyAmount) <= 0n
  ) {
    fail(`${label} amounts must be positive.`);
  }
  return values;
};

const requireDirectAmountSlots = (
  args: readonly unknown[],
  publicAmountsIndex: number,
  encryptedSellIndex: number,
  encryptedBuyIndex: number,
  values: ReturnType<typeof directAmounts>,
  label: string,
): void => {
  const publicAmounts = asTuple(
    args[publicAmountsIndex],
    2,
    `${label} public amounts`,
  );
  requireInteger(
    publicAmounts[0],
    values.sellAsset.kind === 'private-erc20'
      ? '0'
      : values.sellAmount,
    `${label} public sell amount`,
  );
  requireInteger(
    publicAmounts[1],
    values.buyAsset.kind === 'private-erc20'
      ? '0'
      : values.buyAmount,
    `${label} public buy amount`,
  );
  if (values.sellAsset.kind === 'private-erc20') {
    requireEncryptedInput(
      args[encryptedSellIndex],
      `${label} encrypted sell amount`,
    );
  } else {
    requireEmptyEncryptedInput(
      args[encryptedSellIndex],
      `${label} encrypted sell amount`,
    );
  }
  if (values.buyAsset.kind === 'private-erc20') {
    requireEncryptedInput(
      args[encryptedBuyIndex],
      `${label} encrypted buy amount`,
    );
  } else {
    requireEmptyEncryptedInput(
      args[encryptedBuyIndex],
      `${label} encrypted buy amount`,
    );
  }
};

const validateLegacyStandardCounterReplacement = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed legacy counter identity is missing.');
  if (
    envelope.intent.action !== 'counter' ||
    envelope.intent.orderType ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    args.length !== 4 ||
    metadataString(envelope, 'counterRoute') !==
      'legacy-standard-counter' ||
    metadataString(envelope, 'sourceOrderRelation') !== 'counter' ||
    metadataString(envelope, 'legacyCompatibility') !==
      'standard-recipient-bound' ||
    metadataString(envelope, 'legacyOrderTypeLabel') !==
      'Legacy one-off / fixed recipient / public terms' ||
    optionalMetadataValue(envelope, 'sourceOrderType') !== null
  ) {
    fail(
      'Legacy Standard counter replacement metadata is invalid.',
    );
  }
  requireAddress(
    order.escrowContract,
    step.to,
    'Legacy Standard counter escrow',
  );
  requireAddress(
    metadataString(envelope, 'counteredEscrowContract'),
    order.escrowContract,
    'Legacy countered escrow',
  );
  requireInteger(
    metadataString(envelope, 'counteredTradeId'),
    order.localId,
    'Legacy countered trade identifier',
  );
  requireInteger(
    args[0],
    order.localId,
    'Legacy countered trade identifier',
  );
  const sourceMaker = metadataString(envelope, 'sourceMaker');
  const sourceRecipient = metadataString(
    envelope,
    'sourceRecipient',
    true,
  );
  const recipient =
    envelope.intent.recipient ??
    fail('The signed legacy counter recipient is missing.');
  requireAddress(
    sourceMaker,
    recipient,
    'Legacy counter source maker',
  );
  if (
    !sourceRecipient ||
    !sameAddress(sourceRecipient, envelope.wallet)
  ) {
    fail(
      'Only the signed legacy counter recipient may supersede it.',
    );
  }
  const parentEscrow = metadataString(
    envelope,
    'parentEscrowContract',
  );
  const parentTradeId = metadataString(
    envelope,
    'parentTradeId',
  );
  requireAddress(
    parentEscrow,
    step.to,
    'Legacy counter parent escrow',
  );
  const canonicalParentTradeId = asIntegerString(parentTradeId);
  if (BigInt(canonicalParentTradeId) <= 0n) {
    fail('The legacy counter parent identifier is invalid.');
  }
  const sellAsset =
    envelope.intent.sellAsset ??
    fail('The signed legacy counter sell asset is missing.');
  const buyAsset =
    envelope.intent.buyAsset ??
    fail('The signed legacy counter buy asset is missing.');
  const sellAmount = atomic(
    envelope.intent.sellAmount,
    sellAsset,
    'legacy counter sell amount',
  );
  const buyAmount = atomic(
    envelope.intent.buyAmount,
    buyAsset,
    'legacy counter buy amount',
  );
  requireAssetTuple(
    args[1],
    sellAsset,
    sellAmount,
    'Legacy counter sell asset',
  );
  requireAssetTuple(
    args[2],
    buyAsset,
    buyAmount,
    'Legacy counter buy asset',
  );
  requireInteger(
    args[3],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Legacy counter expiry',
  );
  requireProtocolValue(
    envelope,
    step,
    sellAsset.kind === 'native' ? BigInt(sellAmount) : 0n,
  );
};

const validateDirectCounter = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  const crossEscrow =
    signature === SIGNATURES.createDirectCounterForParent;
  const directPrimary =
    signature === SIGNATURES.createDirectCounter;
  const directCounter =
    signature === SIGNATURES.counterDirectAndClose;
  const sameEscrow = directPrimary || directCounter;
  if (
    envelope.intent.action !== 'counter' ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    (!crossEscrow && !sameEscrow) ||
    args.length !== (crossEscrow ? 13 : 11)
  ) {
    fail('Direct counter calldata is incompatible with the signed intent.');
  }
  const order =
    envelope.intent.order ??
    fail('The signed countered order identity is missing.');
  const recipient =
    envelope.intent.recipient ??
    fail('The signed Direct counter recipient is missing.');
  const sourceMaker = metadataString(
    envelope,
    'sourceMaker',
  )!;
  const sourceRecipient = metadataString(
    envelope,
    'sourceRecipient',
    true,
  );
  requireAddress(
    sourceMaker,
    recipient,
    'Direct counter source maker',
  );
  if (
    envelope.wallet.toLowerCase() === sourceMaker.toLowerCase()
  ) {
    fail(
      'The source maker cannot create a counter addressed back to itself.',
    );
  }
  const counterRoute = metadataString(envelope, 'counterRoute')!;
  const sourceOrderRelation = metadataString(
    envelope,
    'sourceOrderRelation',
  )!;
  const expectedCounterRoute = crossEscrow
    ? 'cross-escrow'
    : directCounter
      ? 'direct-counter'
      : 'direct-primary';
  if (counterRoute !== expectedCounterRoute) {
    fail(
      'The Direct counter selector does not match its signed counter route.',
    );
  }
  if (
    !['primary', 'counter', 'replacement'].includes(
      sourceOrderRelation,
    ) ||
    (directCounter && sourceOrderRelation !== 'counter') ||
    (directPrimary && sourceOrderRelation === 'counter')
  ) {
    fail(
      'The Direct counter selector does not match the source order relation.',
    );
  }
  const counteredEscrow = metadataString(
    envelope,
    'counteredEscrowContract',
  )!;
  const counteredTradeId = metadataString(
    envelope,
    'counteredTradeId',
  )!;
  requireAddress(
    counteredEscrow,
    order.escrowContract,
    'Countered escrow',
  );
  requireInteger(
    counteredTradeId,
    order.localId,
    'Countered trade identifier',
  );

  const values = directAmounts(envelope, step, 'Direct counter');
  const assetOffset = crossEscrow ? 3 : 1;
  requireAssetTuple(
    args[assetOffset],
    values.sellAsset,
    null,
    'Direct counter sell asset',
  );
  requireAssetTuple(
    args[assetOffset + 1],
    values.buyAsset,
    null,
    'Direct counter buy asset',
  );
  if (crossEscrow) {
    if (
      order.escrowContract.toLowerCase() === step.to.toLowerCase()
    ) {
      fail(
        'A cross-escrow Direct counter cannot identify the Direct escrow as its source.',
      );
    }
    const parentEscrow = metadataString(
      envelope,
      'parentEscrowContract',
    )!;
    const parentTradeId = metadataString(
      envelope,
      'parentTradeId',
    )!;
    requireAddress(args[0], parentEscrow, 'Counter parent escrow');
    requireInteger(args[1], parentTradeId, 'Counter parent identifier');
    requireAddress(args[2], recipient, 'Direct counter recipient');
  } else {
    requireAddress(
      order.escrowContract,
      step.to,
      'Direct counter source escrow',
    );
    requireInteger(args[0], order.localId, 'Countered trade identifier');
    if (
      sourceRecipient &&
      envelope.wallet.toLowerCase() !==
        sourceRecipient.toLowerCase()
    ) {
      fail(
        'The Direct counter signer is not the source order recipient.',
      );
    }
    if (directCounter && !sourceRecipient) {
      fail(
        'A Direct counter-of-counter must bind its current recipient.',
      );
    }
    if (directPrimary) {
      requireAddress(
        metadataString(envelope, 'parentEscrowContract'),
        order.escrowContract,
        'Direct primary parent escrow',
      );
      requireInteger(
        metadataString(envelope, 'parentTradeId'),
        order.localId,
        'Direct primary parent identifier',
      );
    }
  }
  const publicAmountsIndex = crossEscrow ? 5 : 3;
  const encryptedSellIndex = crossEscrow ? 6 : 4;
  const encryptedBuyIndex = crossEscrow ? 7 : 5;
  const expiryIndex = crossEscrow ? 8 : 6;
  const accessHashIndex = crossEscrow ? 9 : 7;
  const termsHashIndex = crossEscrow ? 10 : 8;
  const encryptedAccessIndex = crossEscrow ? 11 : 9;
  const termsPayloadIndex = crossEscrow ? 12 : 10;
  requireDirectAmountSlots(
    args,
    publicAmountsIndex,
    encryptedSellIndex,
    encryptedBuyIndex,
    values,
    'Direct counter',
  );
  requireInteger(
    args[expiryIndex],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Direct counter expiry',
  );
  requireAccessAndTermsBindings(
    step,
    args[accessHashIndex],
    args[termsHashIndex],
    args[encryptedAccessIndex],
    args[termsPayloadIndex],
    'Direct counter',
  );
  requireProtocolValue(
    envelope,
    step,
    values.sellAsset.kind === 'native'
      ? BigInt(values.sellAmount)
      : 0n,
  );
};

const validateStandardEdit = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 8 || envelope.intent.action !== 'edit') {
    fail('Standard edit calldata has an invalid shape.');
  }
  requirePublicVisible(envelope);
  const order =
    envelope.intent.order ??
    fail('The signed edited order identity is missing.');
  const sellAmount = atomic(
    envelope.intent.sellAmount,
    envelope.intent.sellAsset,
    'replacement sell amount',
  );
  const buyAmount = atomic(
    envelope.intent.buyAmount,
    envelope.intent.buyAsset,
    'replacement buy amount',
  );
  if (
    BigInt(sellAmount) > MAX_UINT128 ||
    BigInt(buyAmount) > MAX_UINT128
  ) {
    fail('Standard replacement amounts exceed the deployed uint128 limit.');
  }
  requireInteger(args[0], order.localId, 'Edited order identifier');
  requireAssetTuple(
    args[1],
    envelope.intent.sellAsset,
    sellAmount,
    'Replacement sell asset',
  );
  requireAssetTuple(
    args[2],
    envelope.intent.buyAsset,
    buyAmount,
    'Replacement buy asset',
  );
  requireAddress(args[3], ZERO_ADDRESS, 'Replacement recipient');
  requireInteger(
    args[4],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Replacement expiry',
  );
  requireBoolean(args[5], true, 'Replacement public flag');
  requireBytes32(args[6], ZERO_BYTES32, 'Replacement access hash');
  const policy = asTuple(args[7], 5, 'Replacement fill policy');
  requireBoolean(
    policy[0],
    metadataBoolean(envelope, 'resultingPartialFillsAllowed'),
    'Replacement partial-fill policy',
  );
  requireInteger(
    policy[1],
    metadataInteger(envelope, 'resultingMinPartialFillBps'),
    'Replacement minimum partial-fill basis points',
  );
  const partialFillBps = BigInt(asIntegerString(policy[1]));
  if (partialFillBps > 5_000n) {
    fail('Replacement minimum partial-fill basis points exceed 5,000.');
  }
  requireInteger(
    policy[2],
    atomic(
      metadataString(
        envelope,
        'resultingMinRequestAmount',
        true,
      ) ?? undefined,
      envelope.intent.buyAsset,
      'replacement minimum request amount',
      true,
    ),
    'Replacement minimum request amount',
  );
  requireInteger(
    policy[3],
    atomic(
      metadataString(
        envelope,
        'resultingMaxRequestAmountPerWallet',
        true,
      ) ?? undefined,
      envelope.intent.buyAsset,
      'replacement maximum request amount per wallet',
      true,
    ),
    'Replacement maximum request amount per wallet',
  );
  requireBoolean(
    policy[4],
    metadataBoolean(envelope, 'resultingOneFillPerWallet'),
    'Replacement one-fill-per-wallet policy',
  );
  requireProtocolValue(
    envelope,
    step,
    envelope.intent.sellAsset?.kind === 'native'
      ? BigInt(sellAmount)
      : 0n,
  );
};

const validateLegacyStandardEdit = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed legacy Standard edited-order identity is missing.');
  const sourceRelation = metadataString(
    envelope,
    'sourceOrderRelation',
  );
  const sourceMaker = metadataString(envelope, 'sourceMaker');
  const sourceRecipient = metadataString(
    envelope,
    'sourceRecipient',
    true,
  );
  if (
    args.length !== 7 ||
    envelope.intent.action !== 'edit' ||
    envelope.intent.orderType ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    metadataString(envelope, 'orderRelation') !== 'replacement' ||
    (
      sourceRelation !== 'primary' &&
      sourceRelation !== 'replacement'
    ) ||
    metadataString(envelope, 'legacyCompatibility') !==
      'standard-recipient-bound' ||
    metadataString(envelope, 'legacyOrderTypeLabel') !==
      'Legacy one-off / fixed recipient / public terms' ||
    optionalMetadataValue(envelope, 'sourceOrderType') !== null ||
    !isHexAddress(sourceMaker) ||
    !isHexAddress(sourceRecipient) ||
    metadataBoolean(envelope, 'legacyDefaultPolicyPreserved') !== true ||
    metadataBoolean(envelope, 'resultingPartialFillsAllowed') !== true ||
    metadataBoolean(envelope, 'resultingOneFillPerWallet') !== false ||
    metadataInteger(envelope, 'legacyDefaultMinPartialFillBps') !==
      metadataInteger(envelope, 'resultingMinPartialFillBps') ||
    optionalAtomicMetadata(
      envelope,
      'resultingMinRequestAmount',
      envelope.intent.buyAsset ??
        fail('The signed legacy Standard buy asset is missing.'),
      'legacy Standard minimum request amount',
    ) !== '0' ||
    optionalAtomicMetadata(
      envelope,
      'resultingMaxRequestAmountPerWallet',
      envelope.intent.buyAsset ??
        fail('The signed legacy Standard buy asset is missing.'),
      'legacy Standard maximum request amount per wallet',
    ) !== '0'
  ) {
    fail('Legacy Standard edit metadata is invalid.');
  }
  requireAddress(
    step.to,
    order.escrowContract,
    'Legacy Standard edit escrow',
  );
  requireAddress(
    sourceMaker,
    envelope.wallet,
    'Legacy Standard edit maker',
  );
  const recipient =
    envelope.intent.recipient ??
    fail('The signed legacy Standard fixed recipient is missing.');
  if (
    !sourceRecipient ||
    !sameAddress(sourceRecipient, recipient) ||
    sameAddress(sourceMaker, recipient)
  ) {
    fail('Legacy Standard edit recipient metadata is invalid.');
  }
  const sellAmount = atomic(
    envelope.intent.sellAmount,
    envelope.intent.sellAsset,
    'legacy Standard replacement sell amount',
  );
  const buyAmount = atomic(
    envelope.intent.buyAmount,
    envelope.intent.buyAsset,
    'legacy Standard replacement buy amount',
  );
  if (
    BigInt(sellAmount) > MAX_UINT128 ||
    BigInt(buyAmount) > MAX_UINT128
  ) {
    fail('Legacy Standard replacement amounts exceed the deployed uint128 limit.');
  }
  requireInteger(args[0], order.localId, 'Legacy edited order identifier');
  requireAssetTuple(
    args[1],
    envelope.intent.sellAsset,
    sellAmount,
    'Legacy replacement sell asset',
  );
  requireAssetTuple(
    args[2],
    envelope.intent.buyAsset,
    buyAmount,
    'Legacy replacement buy asset',
  );
  requireAddress(args[3], recipient, 'Legacy replacement recipient');
  requireInteger(
    args[4],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Legacy replacement expiry',
  );
  requireBoolean(args[5], false, 'Legacy replacement public flag');
  requireBytes32(args[6], ZERO_BYTES32, 'Legacy replacement access hash');
  requireProtocolValue(
    envelope,
    step,
    envelope.intent.sellAsset?.kind === 'native'
      ? BigInt(sellAmount)
      : 0n,
  );
};

const validatePrivateLiquidityEdit = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (
    args.length !== 14 ||
    envelope.intent.action !== 'edit' ||
    envelope.intent.amountVisibility !== 'private-hidden' ||
    envelope.intent.sellAsset?.kind !== 'private-erc20'
  ) {
    fail(
      'Private-liquidity replacement calldata is incompatible with the signed intent.',
    );
  }
  const order =
    envelope.intent.order ??
    fail('The signed replaced order identity is missing.');
  const sellAsset = envelope.intent.sellAsset;
  const buyAsset =
    envelope.intent.buyAsset ??
    fail('The signed replacement buy asset is missing.');
  const access = envelope.intent.accessMode;
  if (
    access !== 'public' &&
    access !== 'unlisted' &&
    access !== 'direct'
  ) {
    fail('The signed private-liquidity access mode is invalid.');
  }
  const unlisted = access === 'unlisted';
  const hiddenOffer = privateValue(
    step,
    ['hidden-offer-amount'],
    'replacement hidden offer amount',
  );
  const hiddenRequest = privateValue(
    step,
    ['hidden-request-amount'],
    'replacement hidden request amount',
  );
  const publicOffer = unlisted
    ? '0'
    : privateValue(
        step,
        ['public-offer-term'],
        'replacement public offer term',
      );
  const publicRequest = unlisted
    ? '0'
    : privateValue(
        step,
        ['public-request-term'],
        'replacement public request term',
      );
  requireInteger(args[0], order.localId, 'Replaced order identifier');
  requireAssetTuple(
    args[1],
    sellAsset,
    publicOffer,
    'Replacement private-liquidity sell asset',
  );
  requireAssetTuple(
    args[2],
    buyAsset,
    publicRequest,
    'Replacement private-liquidity buy asset',
  );
  requireAddress(
    args[3],
    access === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed replacement recipient is missing.')
      : ZERO_ADDRESS,
    'Replacement private-liquidity recipient',
  );
  requireInteger(
    args[4],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Replacement private-liquidity expiry',
  );
  requireBoolean(
    args[5],
    access === 'public',
    'Replacement private-liquidity public flag',
  );
  requireEncryptedInput(args[8], 'Replacement hidden offer');
  if (unlisted) {
    requireAccessAndTermsBindings(
      step,
      args[6],
      args[7],
      args[12],
      args[13],
      'Replacement private-liquidity order',
    );
    requireEncryptedInput(args[9], 'Replacement linked offer');
    requireEncryptedInput(args[10], 'Replacement linked request');
  } else {
    requireBytes32(
      args[6],
      ZERO_BYTES32,
      'Replacement private-liquidity access hash',
    );
    requireBytes32(
      args[7],
      ZERO_BYTES32,
      'Replacement private-liquidity terms hash',
    );
    requireEmptyEncryptedInput(args[9], 'Replacement linked offer');
    requireEmptyEncryptedInput(args[10], 'Replacement linked request');
    requireEmptyEncryptedInput(
      args[12],
      'Replacement encrypted access secret',
    );
    requireEmptyBytes(args[13], 'Replacement encrypted terms');
  }
  requireBytes(args[11], 'Replacement recovery note');
  if (
    BigInt(hiddenOffer) <= 0n ||
    BigInt(hiddenRequest) <= 0n
  ) {
    fail('The replacement hidden amounts must be positive.');
  }
  requireProtocolValue(envelope, step, 0n);
};

const validateDirectEdit = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (
    args.length !== 12 ||
    envelope.intent.action !== 'edit' ||
    envelope.intent.amountVisibility !== 'visible' ||
    (
      envelope.intent.accessMode !== 'direct' &&
      envelope.intent.accessMode !== 'unlisted'
    )
  ) {
    fail('Direct replacement calldata is incompatible with the signed intent.');
  }
  const order =
    envelope.intent.order ??
    fail('The signed replaced Direct order identity is missing.');
  const values = directAmounts(envelope, step, 'Direct replacement');
  requireInteger(args[0], order.localId, 'Replaced Direct order identifier');
  requireAssetTuple(
    args[1],
    values.sellAsset,
    null,
    'Direct replacement sell asset',
  );
  requireAssetTuple(
    args[2],
    values.buyAsset,
    null,
    'Direct replacement buy asset',
  );
  requireDirectAmountSlots(
    args,
    3,
    4,
    5,
    values,
    'Direct replacement',
  );
  requireAddress(
    args[6],
    envelope.intent.accessMode === 'direct'
      ? envelope.intent.recipient ??
          fail('The signed Direct replacement recipient is missing.')
      : ZERO_ADDRESS,
    'Direct replacement recipient',
  );
  requireInteger(
    args[7],
    isoToUnixSeconds(envelope.intent.expiresAt),
    'Direct replacement expiry',
  );
  requireAccessAndTermsBindings(
    step,
    args[8],
    args[9],
    args[10],
    args[11],
    'Direct replacement',
  );
  requireProtocolValue(
    envelope,
    step,
    values.sellAsset.kind === 'native'
      ? BigInt(values.sellAmount)
      : 0n,
  );
};

const recurringEditTerms = (
  envelope: SignedActionEnvelopeV1,
  side: 'buy' | 'sell',
  baseAsset: NormalizedAssetV1,
  quoteAsset: NormalizedAssetV1,
): readonly [string, string] => {
  if (
    baseAsset.decimals === undefined ||
    baseAsset.decimals < 0
  ) {
    return fail('The recurring base-asset precision is missing.');
  }
  const changedPrice = optionalMetadataDecimal(
    envelope,
    `${side}Price`,
  );
  const baseUnit = (10n ** BigInt(baseAsset.decimals)).toString();
  if (changedPrice !== undefined) {
    return [
      baseUnit,
      atomic(
        changedPrice,
        quoteAsset,
        `recurring ${side} price`,
      ),
    ];
  }
  const trustedBase = optionalMetadataDecimal(
    envelope,
    side === 'buy'
      ? 'trustedBuyBaseAmount'
      : 'trustedSellBaseAmount',
  );
  const trustedQuote = optionalMetadataDecimal(
    envelope,
    side === 'buy'
      ? 'trustedBuyQuoteAmount'
      : 'trustedSellQuoteAmount',
  );
  if (trustedBase !== undefined || trustedQuote !== undefined) {
    if (trustedBase === undefined || trustedQuote === undefined) {
      return fail(`The trusted recurring ${side} tuple is incomplete.`);
    }
    return [
      atomic(
        trustedBase,
        baseAsset,
        `trusted recurring ${side} base amount`,
      ),
      atomic(
        trustedQuote,
        quoteAsset,
        `trusted recurring ${side} quote amount`,
      ),
    ];
  }
  const trustedPrice = optionalMetadataDecimal(
    envelope,
    side === 'buy' ? 'trustedBuyPrice' : 'trustedSellPrice',
  );
  if (trustedPrice === undefined) {
    return fail(`The trusted recurring ${side} terms are missing.`);
  }
  return [
    baseUnit,
    atomic(
      trustedPrice,
      quoteAsset,
      `trusted recurring ${side} price`,
    ),
  ];
};

const requireRecurringDeltaSide = (
  args: readonly unknown[],
  step: MaterializedActionStep,
  options: {
    label: string;
    asset: NormalizedAssetV1;
    isPrivate: boolean;
    allowPrivateAdjustment: boolean;
    addMetadataKey: string;
    removeMetadataKey: string;
    addValueId: string;
    removeValueId: string;
    publicAddIndex: number;
    encryptedAddIndex: number;
    publicRemoveIndex: number;
    encryptedRemoveIndex: number;
  },
  envelope: SignedActionEnvelopeV1,
): { add: string; remove: string } => {
  const add = options.isPrivate
    ? privateValue(
        step,
        [options.addValueId],
        `${options.label} private addition`,
      )
    : optionalAtomicMetadata(
        envelope,
        options.addMetadataKey,
        options.asset,
        `${options.label} addition`,
      );
  const remove = options.isPrivate
    ? privateValue(
        step,
        [options.removeValueId],
        `${options.label} private removal`,
      )
    : optionalAtomicMetadata(
        envelope,
        options.removeMetadataKey,
        options.asset,
        `${options.label} removal`,
      );
  if (BigInt(add) > 0n && BigInt(remove) > 0n) {
    fail(`A recurring edit cannot add and remove ${options.label} together.`);
  }
  if (
    options.isPrivate &&
    !options.allowPrivateAdjustment &&
    (BigInt(add) !== 0n || BigInt(remove) !== 0n)
  ) {
    fail(
      `${options.label} cannot change without signed private-liquidity adjustment.`,
    );
  }
  requireInteger(
    args[options.publicAddIndex],
    options.isPrivate ? '0' : add,
    `${options.label} public addition`,
  );
  requireInteger(
    args[options.publicRemoveIndex],
    options.isPrivate ? '0' : remove,
    `${options.label} public removal`,
  );
  if (options.isPrivate) {
    requireEncryptedInput(
      args[options.encryptedAddIndex],
      `${options.label} encrypted addition`,
    );
    requireEncryptedInput(
      args[options.encryptedRemoveIndex],
      `${options.label} encrypted removal`,
    );
  } else {
    requireEmptyEncryptedInput(
      args[options.encryptedAddIndex],
      `${options.label} encrypted addition`,
    );
    requireEmptyEncryptedInput(
      args[options.encryptedRemoveIndex],
      `${options.label} encrypted removal`,
    );
  }
  return { add, remove };
};

const validateRecurringEdit = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  if (args.length !== 11 || envelope.intent.action !== 'edit') {
    fail('Recurring edit calldata has an invalid shape.');
  }
  const order =
    envelope.intent.order ??
    fail('The signed recurring order identity is missing.');
  const baseAsset =
    envelope.intent.sellAsset ??
    fail('The signed recurring base asset is missing.');
  const quoteAsset =
    envelope.intent.buyAsset ??
    fail('The signed recurring quote asset is missing.');
  requireInteger(args[0], order.localId, 'Recurring order identifier');
  const buyTerms = recurringEditTerms(
    envelope,
    'buy',
    baseAsset,
    quoteAsset,
  );
  const sellTerms = recurringEditTerms(
    envelope,
    'sell',
    baseAsset,
    quoteAsset,
  );
  const decodedBuyTerms = asTuple(args[1], 2, 'Recurring buy terms');
  const decodedSellTerms = asTuple(args[2], 2, 'Recurring sell terms');
  requireInteger(
    decodedBuyTerms[0],
    buyTerms[0],
    'Recurring buy base amount',
  );
  requireInteger(
    decodedBuyTerms[1],
    buyTerms[1],
    'Recurring buy quote amount',
  );
  requireInteger(
    decodedSellTerms[0],
    sellTerms[0],
    'Recurring sell base amount',
  );
  requireInteger(
    decodedSellTerms[1],
    sellTerms[1],
    'Recurring sell quote amount',
  );
  const privateInventory =
    envelope.intent.amountVisibility === 'private-hidden';
  const adjustPrivateValue = optionalMetadataValue(
    envelope,
    'adjustPrivateLiquidity',
  );
  if (
    adjustPrivateValue !== undefined &&
    adjustPrivateValue !== null &&
    typeof adjustPrivateValue !== 'boolean'
  ) {
    fail(
      'Signed intent metadata adjustPrivateLiquidity has an invalid type.',
    );
  }
  const adjustPrivateLiquidity = adjustPrivateValue === true;
  const basePrivate =
    privateInventory && baseAsset.kind === 'private-erc20';
  const quotePrivate =
    privateInventory && quoteAsset.kind === 'private-erc20';
  const baseDelta = requireRecurringDeltaSide(
    args,
    step,
    {
      label: 'recurring base inventory',
      asset: baseAsset,
      isPrivate: basePrivate,
      allowPrivateAdjustment: adjustPrivateLiquidity,
      addMetadataKey: 'addSellBaseLiquidity',
      removeMetadataKey: 'removeSellBaseLiquidity',
      addValueId: 'recurring-edit-add-base',
      removeValueId: 'recurring-edit-remove-base',
      publicAddIndex: 3,
      encryptedAddIndex: 5,
      publicRemoveIndex: 7,
      encryptedRemoveIndex: 9,
    },
    envelope,
  );
  const quoteDelta = requireRecurringDeltaSide(
    args,
    step,
    {
      label: 'recurring quote inventory',
      asset: quoteAsset,
      isPrivate: quotePrivate,
      allowPrivateAdjustment: adjustPrivateLiquidity,
      addMetadataKey: 'addBuyQuoteLiquidity',
      removeMetadataKey: 'removeBuyQuoteLiquidity',
      addValueId: 'recurring-edit-add-quote',
      removeValueId: 'recurring-edit-remove-quote',
      publicAddIndex: 4,
      encryptedAddIndex: 6,
      publicRemoveIndex: 8,
      encryptedRemoveIndex: 10,
    },
    envelope,
  );
  requireProtocolValue(
    envelope,
    step,
    (baseAsset.kind === 'native' ? BigInt(baseDelta.add) : 0n) +
      (quoteAsset.kind === 'native' ? BigInt(quoteDelta.add) : 0n),
  );
};

const validateFill = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed order identity is missing.');
  const inputAmount = atomic(
    envelope.intent.sellAmount,
    envelope.intent.sellAsset,
    'fill input amount',
  );
  const minOutput = atomic(
    envelope.intent.buyAmount,
    envelope.intent.buyAsset,
    'minimum output amount',
    true,
  );
  const isRecurring =
    signature === SIGNATURES.fillRecurringBuy ||
    signature === SIGNATURES.fillRecurringSell;
  if (args.length !== (isRecurring ? 4 : 3)) {
    fail('Fill calldata has an invalid shape.');
  }
  requireInteger(args[0], order.localId, 'Order identifier');
  requireInteger(args[1], inputAmount, 'Fill input amount');
  requireInteger(args[2], minOutput, 'Minimum output amount');
  if (isRecurring) {
    const recurringSide = metadataString(envelope, 'recurringSide');
    const expectedSignature =
      recurringSide === 'buy'
        ? SIGNATURES.fillRecurringSell
        : recurringSide === 'sell'
          ? SIGNATURES.fillRecurringBuy
          : fail('The signed recurring side is invalid.');
    if (signature !== expectedSignature) {
      fail('Recurring fill direction does not match the signed intent.');
    }
    requireBytes32(args[3], ZERO_BYTES32, 'Public recurring fill secret');
  } else {
    if (signature !== SIGNATURES.fillTrade) {
      fail('Fill function is incompatible with the signed intent.');
    }
    requireAddress(
      order.escrowContract,
      step.to,
      'Standard fill escrow',
    );
    const relation = metadataString(envelope, 'orderRelation');
    if (envelope.intent.accessMode === 'direct') {
      if (
        envelope.intent.orderType ||
        envelope.intent.amountVisibility !== 'visible' ||
        metadataString(envelope, 'legacyCompatibility') !==
          'standard-recipient-bound' ||
        metadataString(envelope, 'legacyOrderTypeLabel') !==
          'Legacy one-off / fixed recipient / public terms' ||
        !envelope.intent.recipient ||
        !sameAddress(envelope.intent.recipient, envelope.wallet)
      ) {
        fail(
          'Legacy Standard recipient-bound fill metadata is invalid.',
        );
      }
      if (relation === 'counter') {
        fail(
          'A legacy Standard counterorder must use atomic counter acceptance.',
        );
      }
    } else if (envelope.intent.accessMode !== 'public') {
      fail('Standard fills must use public or verified legacy access.');
    }
  }
  const principal =
    envelope.intent.sellAsset?.kind === 'native'
      ? BigInt(inputAmount)
      : 0n;
  requireProtocolValue(envelope, step, principal);
};

const validateLegacyStandardCounterAcceptance = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed legacy counter identity is missing.');
  if (
    args.length !== 1 ||
    envelope.intent.orderType ||
    envelope.intent.accessMode !== 'direct' ||
    envelope.intent.amountVisibility !== 'visible' ||
    metadataString(envelope, 'orderRelation') !== 'counter' ||
    metadataString(envelope, 'legacyCompatibility') !==
      'standard-recipient-bound' ||
    metadataString(envelope, 'legacyOrderTypeLabel') !==
      'Legacy one-off / fixed recipient / public terms' ||
    !envelope.intent.recipient ||
    !sameAddress(envelope.intent.recipient, envelope.wallet)
  ) {
    fail(
      'Legacy Standard counter acceptance metadata is invalid.',
    );
  }
  requireAddress(
    order.escrowContract,
    step.to,
    'Legacy Standard counter escrow',
  );
  requireInteger(
    args[0],
    order.localId,
    'Legacy Standard counter identifier',
  );
  const inputAsset =
    envelope.intent.sellAsset ??
    fail('The signed legacy counter payment asset is missing.');
  const inputAmount = atomic(
    envelope.intent.sellAmount,
    inputAsset,
    'legacy counter payment',
  );
  const trustedAmount = atomic(
    metadataString(envelope, 'trustedOrderSellAmount') ?? undefined,
    inputAsset,
    'trusted legacy counter payment',
  );
  if (inputAmount !== trustedAmount || envelope.intent.buyAmount) {
    fail(
      'Legacy Standard counter acceptance must bind its exact trusted remaining terms.',
    );
  }
  requireProtocolValue(
    envelope,
    step,
    inputAsset.kind === 'native' ? BigInt(inputAmount) : 0n,
  );
};

const validatePrivateRecurringFill = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  if (
    args.length !== 5 ||
    envelope.intent.amountVisibility !== 'private-hidden'
  ) {
    fail('Private recurring fill calldata has an invalid shape.');
  }
  const order =
    envelope.intent.order ??
    fail('The signed recurring order identity is missing.');
  const inputAsset =
    envelope.intent.sellAsset ??
    fail('The signed recurring input asset is missing.');
  const recurringSide = metadataString(envelope, 'recurringSide');
  const expectedSignature =
    recurringSide === 'buy'
      ? SIGNATURES.fillPrivateRecurringSell
      : recurringSide === 'sell'
        ? SIGNATURES.fillPrivateRecurringBuy
        : fail('The signed recurring side is invalid.');
  if (signature !== expectedSignature) {
    fail('Private recurring fill direction does not match the signed intent.');
  }
  const inputAmount =
    inputAsset.kind === 'private-erc20' &&
    !envelope.intent.sellAmount
      ? privateValue(
          step,
          ['recurring-fill-input'],
          'private recurring fill input',
        )
      : atomic(
          envelope.intent.sellAmount,
          inputAsset,
          'recurring fill input',
        );
  const minOutput = atomic(
    envelope.intent.buyAmount,
    envelope.intent.buyAsset,
    'recurring minimum output',
    true,
  );
  requireInteger(args[0], order.localId, 'Recurring order identifier');
  requireInteger(
    args[1],
    inputAsset.kind === 'private-erc20' ? '0' : inputAmount,
    'Public recurring input',
  );
  requireEncryptedInput(args[2], 'Encrypted recurring input');
  requireInteger(args[3], minOutput, 'Recurring minimum public output');
  requireBytes32(args[4], ZERO_BYTES32, 'Recurring access secret');
  requireProtocolValue(
    envelope,
    step,
    inputAsset.kind === 'native' ? BigInt(inputAmount) : 0n,
  );
};

const signedOrTrustedSellAmount = (
  envelope: SignedActionEnvelopeV1,
  asset: NormalizedAssetV1,
): string => {
  const amount =
    envelope.intent.sellAmount ??
    (
      typeof envelope.intent.metadata?.trustedOrderSellAmount === 'string'
        ? envelope.intent.metadata.trustedOrderSellAmount
        : undefined
    );
  return atomic(amount, asset, 'fill input amount');
};

const validatePrivateOrDirectFill = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed private order identity is missing.');
  const inputAsset =
    envelope.intent.sellAsset ??
    fail('The signed private fill input asset is missing.');
  const unlisted = envelope.intent.accessMode === 'unlisted';
  const isDirect =
    signature === SIGNATURES.acceptDirect ||
    signature === SIGNATURES.acceptDirectWithAccess ||
    signature === SIGNATURES.acceptDirectCounter;
  const directCounter =
    metadataString(envelope, 'orderRelation') === 'counter';
  if (directCounter && unlisted) {
    fail('Direct counterorders cannot use unlisted access.');
  }
  const isPrivateInput = inputAsset.kind === 'private-erc20';
  const expectedSignature = isDirect
    ? directCounter
      ? SIGNATURES.acceptDirectCounter
      : unlisted
        ? SIGNATURES.acceptDirectWithAccess
        : SIGNATURES.acceptDirect
    : isPrivateInput
      ? unlisted
        ? SIGNATURES.fillPrivateWithAccess
        : SIGNATURES.fillPrivate
      : unlisted
        ? SIGNATURES.fillHybridPrivateWithAccess
        : SIGNATURES.fillHybridPrivate;
  if (signature !== expectedSignature) {
    fail('Private fill selector does not match the signed order route.');
  }
  const expectedLength = unlisted && !directCounter ? 3 : 2;
  if (args.length !== expectedLength) {
    fail('Private fill calldata has an invalid shape.');
  }
  requireInteger(args[0], order.localId, 'Private order identifier');
  if (isDirect) {
    requireEncryptedInput(
      args[1],
      'Direct private payment',
      !isPrivateInput,
    );
  } else if (isPrivateInput) {
    requireEncryptedInput(args[1], 'Private-liquidity payment');
  } else {
    requireInteger(
      args[1],
      signedOrTrustedSellAmount(envelope, inputAsset),
      'Hybrid private payment',
    );
  }
  if (unlisted && !directCounter) {
    requireEncryptedInput(args[2], 'Private order access secret');
  }
  const nativeAmount =
    inputAsset.kind === 'native'
      ? BigInt(signedOrTrustedSellAmount(envelope, inputAsset))
      : 0n;
  requireProtocolValue(envelope, step, nativeAmount);
};

const UPDATE_SIGNATURES: Record<string, readonly string[]> = {
  cancel: [SIGNATURES.cancelTrade, SIGNATURES.cancelOrder],
  decline: [SIGNATURES.declineTrade],
  pause: [SIGNATURES.pauseOrder],
  resume: [SIGNATURES.resumeOrder],
  settle_inventory: [SIGNATURES.settleInventory],
  reclaim_expired: [SIGNATURES.reclaimExpiredTrade],
  refresh: [SIGNATURES.refreshTrade],
  extend_expiry: [SIGNATURES.extendTradeExpiry],
};

const validateLiveStandardLifecycleBinding = (
  envelope: SignedActionEnvelopeV1,
  facts: StandardOrderFacts,
): void => {
  const sourceMaker =
    envelope.intent.metadata?.sourceMaker;
  if (
    typeof sourceMaker !== 'string' ||
    !isHexAddress(sourceMaker) ||
    !sameAddress(sourceMaker, facts.maker)
  ) {
    fail(
      'Live Standard lifecycle maker does not match the signed source maker.',
    );
  }
  const sourceRecipient =
    envelope.intent.metadata?.sourceRecipient;
  const recipient = envelope.intent.recipient ?? null;
  if (facts.recipient) {
    if (
      envelope.intent.orderType !== undefined ||
      envelope.intent.accessMode !== 'direct' ||
      envelope.intent.amountVisibility !== 'visible' ||
      envelope.secretPolicy.accessMode !== 'direct' ||
      envelope.intent.metadata?.legacyCompatibility !==
        'standard-recipient-bound' ||
      envelope.intent.metadata?.legacyOrderTypeLabel !==
        'Legacy one-off / fixed recipient / public terms' ||
      envelope.intent.metadata?.sourceOrderType !== null ||
      typeof sourceRecipient !== 'string' ||
      !isHexAddress(sourceRecipient) ||
      !sameAddress(sourceRecipient, facts.recipient) ||
      recipient === null ||
      !sameAddress(recipient, facts.recipient) ||
      sameAddress(facts.maker, facts.recipient)
    ) {
      fail(
        'Live Standard fixed-recipient lifecycle requires the exact legacy type and recipient binding.',
      );
    }
  } else if (
    sourceRecipient !== null ||
    recipient !== null
  ) {
    fail(
      'Live Standard public lifecycle recipient does not match the on-chain order.',
    );
  }
  if (envelope.intent.action === 'edit') {
    requireAddress(
      facts.maker,
      envelope.wallet,
      'Live Standard lifecycle maker',
    );
    return;
  }
  const update = envelope.intent.metadata?.update;
  if (
    update === 'cancel' ||
    update === 'refresh' ||
    update === 'extend_expiry'
  ) {
    requireAddress(
      facts.maker,
      envelope.wallet,
      'Live Standard lifecycle maker',
    );
  } else if (update === 'decline') {
    if (!facts.recipient) {
      fail(
        'Live Standard lifecycle decline has no fixed recipient.',
      );
    }
    requireAddress(
      facts.recipient,
      envelope.wallet,
      'Live Standard lifecycle recipient',
    );
  }
};

const validateOrderUpdate = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  const order =
    envelope.intent.order ??
    fail('The signed order identity is missing.');
  const update = metadataString(envelope, 'update');
  const expected = update ? UPDATE_SIGNATURES[update] : undefined;
  if (!expected?.includes(signature)) {
    fail('Order lifecycle function does not match the signed update.');
  }
  const expectedLength =
    signature === SIGNATURES.extendTradeExpiry ? 2 : 1;
  if (args.length !== expectedLength) {
    fail('Order lifecycle calldata has an invalid shape.');
  }
  requireInteger(args[0], order.localId, 'Order identifier');
  if (signature === SIGNATURES.extendTradeExpiry) {
    const expiry =
      metadataString(envelope, 'expiresAt', true) ??
      fail('The signed expiry extension is missing.');
    requireInteger(args[1], isoToUnixSeconds(expiry), 'Extended expiry');
  }
  if (
    signature === SIGNATURES.settleInventory &&
    metadataString(envelope, 'orderStatus') !== 'cancelled'
  ) {
    fail('Recurring inventory can only be settled from a cancelled order.');
  }
  const standardEscrow =
    envelope.registrySnapshot.contracts.standardEscrow?.address;
  const unclassifiedStandardLifecycle =
    !envelope.intent.orderType &&
    !!standardEscrow &&
    sameAddress(order.escrowContract, standardEscrow);
  requireAddress(
    step.to,
    order.escrowContract,
    unclassifiedStandardLifecycle
      ? 'Legacy Standard lifecycle escrow'
      : 'Order lifecycle escrow',
  );
  const sourceRelation = metadataString(
    envelope,
    'sourceOrderRelation',
  );
  const orderRelation = metadataString(envelope, 'orderRelation');
  const sourceMaker = metadataString(envelope, 'sourceMaker');
  const sourceRecipient = metadataString(
    envelope,
    'sourceRecipient',
    true,
  );
  const recipient = envelope.intent.recipient ?? null;
  if (
    !isHexAddress(sourceMaker) ||
    (sourceRecipient !== null && !isHexAddress(sourceRecipient)) ||
    (
      sourceRelation !== 'primary' &&
      sourceRelation !== 'counter' &&
      sourceRelation !== 'replacement'
    ) ||
    orderRelation !== sourceRelation ||
    (
      (sourceRecipient === null) !==
      (recipient === null)
    ) ||
    (
      sourceRecipient !== null &&
      recipient !== null &&
      !sameAddress(sourceRecipient, recipient)
    ) ||
    (
      sourceRecipient !== null &&
      sameAddress(sourceMaker, sourceRecipient)
    )
  ) {
    fail('Order lifecycle source and actor metadata is invalid.');
  }
  const legacyMarkerPresent =
    optionalMetadataValue(envelope, 'legacyCompatibility') !==
      undefined ||
    optionalMetadataValue(envelope, 'legacyOrderTypeLabel') !==
      undefined;
  if (
    unclassifiedStandardLifecycle ||
    legacyMarkerPresent
  ) {
    if (
      envelope.intent.orderType ||
      envelope.intent.accessMode !== 'direct' ||
      envelope.intent.amountVisibility !== 'visible' ||
      metadataString(envelope, 'legacyCompatibility') !==
        'standard-recipient-bound' ||
      metadataString(envelope, 'legacyOrderTypeLabel') !==
        'Legacy one-off / fixed recipient / public terms' ||
      optionalMetadataValue(envelope, 'sourceOrderType') !== null ||
      orderRelation !== sourceRelation ||
      !sourceRecipient ||
      !recipient ||
      !sameAddress(sourceRecipient, recipient) ||
      sameAddress(sourceMaker, sourceRecipient) ||
      ![
        'cancel',
        'decline',
        'reclaim_expired',
        'refresh',
        'extend_expiry',
      ].includes(update ?? '')
    ) {
      fail('Legacy Standard lifecycle metadata is invalid.');
    }
    requireAddress(
      step.to,
      order.escrowContract,
      'Legacy Standard lifecycle escrow',
    );
    requireAddress(
      step.to,
      standardEscrow ??
        fail('The signed Standard escrow snapshot is missing.'),
      'Legacy Standard lifecycle registry escrow',
    );
    if (
      update === 'cancel' ||
      update === 'refresh' ||
      update === 'extend_expiry'
    ) {
      requireAddress(
        sourceMaker,
        envelope.wallet,
        'Legacy Standard lifecycle maker',
      );
    } else if (update === 'decline') {
      requireAddress(
        sourceRecipient,
        envelope.wallet,
        'Legacy Standard lifecycle recipient',
      );
    }
  } else if (update === 'decline') {
    if (!sourceRecipient) {
      fail('The signed lifecycle recipient is missing.');
    }
    requireAddress(
      sourceRecipient,
      envelope.wallet,
      'Order lifecycle recipient',
    );
  } else if (update !== 'reclaim_expired') {
    requireAddress(
      sourceMaker,
      envelope.wallet,
      'Order lifecycle maker',
    );
  }
  requireProtocolValue(envelope, step, 0n);
};

type ApprovalCandidate = {
  token: string;
  amount: string;
};

const approvalCandidates = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
): ApprovalCandidate[] => {
  if (envelope.intent.action === 'create_trade') {
    const asset = envelope.intent.sellAsset;
    if (!asset || (asset.kind !== 'erc20' && asset.kind !== 'private-erc20')) {
      return [];
    }
    const amount =
      asset.kind === 'private-erc20' &&
      envelope.intent.amountVisibility === 'private-hidden'
        ? privateValue(
            step,
            ['hidden-offer-amount', 'offer-amount'],
            'private sell allowance',
          )
        : atomic(
            envelope.intent.sellAmount,
            asset,
            'sell amount',
          );
    return [
      {
        token: assetAddress(asset),
        amount,
      },
    ];
  }
  if (envelope.intent.action === 'create_recurring') {
    const candidates: ApprovalCandidate[] = [];
    const baseAsset = envelope.intent.sellAsset;
    const quoteAsset = envelope.intent.buyAsset;
    if (
      baseAsset?.kind === 'erc20' ||
      baseAsset?.kind === 'private-erc20'
    ) {
      const amount =
        envelope.intent.amountVisibility === 'private-hidden' &&
        baseAsset.kind === 'private-erc20'
          ? privateValue(
              step,
              ['recurring-base-inventory'],
              'private recurring base allowance',
            )
          : atomic(
              metadataString(envelope, 'sellBaseLiquidity', true) ?? undefined,
              baseAsset,
              'sell-base liquidity',
              true,
            );
      if (
        BigInt(amount) > 0n ||
        (
          envelope.intent.amountVisibility === 'private-hidden' &&
          baseAsset.kind === 'private-erc20'
        )
      ) {
        candidates.push({ token: assetAddress(baseAsset), amount });
      }
    }
    if (
      quoteAsset?.kind === 'erc20' ||
      quoteAsset?.kind === 'private-erc20'
    ) {
      const amount =
        envelope.intent.amountVisibility === 'private-hidden' &&
        quoteAsset.kind === 'private-erc20'
          ? privateValue(
              step,
              ['recurring-quote-inventory'],
              'private recurring quote allowance',
            )
          : atomic(
              metadataString(envelope, 'buyQuoteLiquidity', true) ?? undefined,
              quoteAsset,
              'buy-quote liquidity',
              true,
            );
      if (
        BigInt(amount) > 0n ||
        (
          envelope.intent.amountVisibility === 'private-hidden' &&
          quoteAsset.kind === 'private-erc20'
        )
      ) {
        candidates.push({ token: assetAddress(quoteAsset), amount });
      }
    }
    return candidates;
  }
  if (envelope.intent.action === 'counter') {
    const asset = envelope.intent.sellAsset;
    if (!asset || (asset.kind !== 'erc20' && asset.kind !== 'private-erc20')) {
      return [];
    }
    return [
      {
        token: assetAddress(asset),
        amount:
          asset.kind === 'private-erc20'
            ? privateValue(
                step,
                ['offer-amount'],
                'private counter allowance',
              )
            : atomic(
                envelope.intent.sellAmount,
                asset,
                'counter offer amount',
              ),
      },
    ];
  }
  if (envelope.intent.action === 'edit') {
    const signature = envelope.steps.find(
      (candidate) => candidate.kind === 'protocol',
    )?.callTemplate?.functionSignature;
    const sellAsset = envelope.intent.sellAsset;
    const buyAsset = envelope.intent.buyAsset;
    if (signature === SIGNATURES.editRecurring) {
      if (!sellAsset || !buyAsset) return [];
      const privateInventory =
        envelope.intent.amountVisibility === 'private-hidden';
      const adjustPrivateLiquidity =
        optionalMetadataValue(
          envelope,
          'adjustPrivateLiquidity',
        ) === true;
      const basePrivate =
        privateInventory && sellAsset.kind === 'private-erc20';
      const quotePrivate =
        privateInventory && buyAsset.kind === 'private-erc20';
      const candidates: ApprovalCandidate[] = [];
      if (
        sellAsset.kind === 'erc20' ||
        sellAsset.kind === 'private-erc20'
      ) {
        const amount = basePrivate
          ? privateValue(
              step,
              ['recurring-edit-add-base'],
              'private recurring base addition',
            )
          : optionalAtomicMetadata(
              envelope,
              'addSellBaseLiquidity',
              sellAsset,
              'recurring base addition',
            );
        if (
          BigInt(amount) > 0n ||
          (basePrivate && adjustPrivateLiquidity)
        ) {
          candidates.push({
            token: assetAddress(sellAsset),
            amount,
          });
        }
      }
      if (
        buyAsset.kind === 'erc20' ||
        buyAsset.kind === 'private-erc20'
      ) {
        const amount = quotePrivate
          ? privateValue(
              step,
              ['recurring-edit-add-quote'],
              'private recurring quote addition',
            )
          : optionalAtomicMetadata(
              envelope,
              'addBuyQuoteLiquidity',
              buyAsset,
              'recurring quote addition',
            );
        if (
          BigInt(amount) > 0n ||
          (quotePrivate && adjustPrivateLiquidity)
        ) {
          candidates.push({
            token: assetAddress(buyAsset),
            amount,
          });
        }
      }
      return candidates;
    }
    if (
      !sellAsset ||
      (
        sellAsset.kind !== 'erc20' &&
        sellAsset.kind !== 'private-erc20'
      )
    ) {
      return [];
    }
    let amount: string;
    if (signature === SIGNATURES.editPrivateLiquidity) {
      amount = privateValue(
        step,
        ['hidden-offer-amount'],
        'private-liquidity replacement allowance',
      );
    } else if (
      signature === SIGNATURES.editDirect &&
      sellAsset.kind === 'private-erc20'
    ) {
      amount = privateValue(
        step,
        ['offer-amount'],
        'Direct replacement allowance',
      );
    } else if (
      signature === SIGNATURES.editLegacyStandard ||
      signature === SIGNATURES.editStandard ||
      signature === SIGNATURES.editDirect
    ) {
      amount = atomic(
        envelope.intent.sellAmount,
        sellAsset,
        'replacement sell amount',
      );
    } else {
      return [];
    }
    return [{ token: assetAddress(sellAsset), amount }];
  }
  if (envelope.intent.action === 'fill') {
    const asset = envelope.intent.sellAsset;
    if (!asset || (asset.kind !== 'erc20' && asset.kind !== 'private-erc20')) {
      return [];
    }
    const amount =
      asset.kind === 'private-erc20' &&
      !envelope.intent.sellAmount &&
      typeof envelope.intent.metadata?.trustedOrderSellAmount !== 'string'
        ? privateValue(
            step,
            ['request-amount', 'recurring-fill-input'],
            'private fill allowance',
          )
        : signedOrTrustedSellAmount(envelope, asset);
    return [
      {
        token: assetAddress(asset),
        amount,
      },
    ];
  }
  if (envelope.intent.action === 'privacy_bridge') {
    const asset = envelope.intent.sellAsset;
    if (
      !asset ||
      (asset.kind !== 'erc20' && asset.kind !== 'private-erc20')
    ) {
      return [];
    }
    return [
      {
        token: assetAddress(asset),
        amount: atomic(
          envelope.intent.sellAmount,
          asset,
          'bridge amount',
        ),
      },
    ];
  }
  return [];
};

const validateApproval = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  stepIndex: number,
): void => {
  if (!step.approval || step.value !== '0') {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval terms are not canonical.',
    );
  }
  const reset =
    envelope.steps[stepIndex]?.allowance?.scheme === 'erc20-reset';
  const candidate = approvalCandidates(envelope, step).find(
    (entry) =>
      sameAddress(step.approval?.token, entry.token) &&
      (reset ? step.approval?.amount === '0' : step.approval?.amount === entry.amount),
  );
  const laterProtocolTargets = new Set(
    envelope.steps
      .slice(stepIndex + 1)
      .filter((candidateStep) => candidateStep.kind === 'protocol')
      .map((candidateStep) => candidateStep.to.toLowerCase()),
  );
  if (
    !candidate ||
    !sameAddress(step.to, candidate.token) ||
    !laterProtocolTargets.has(step.approval.spender.toLowerCase()) ||
    (
      envelope.steps[stepIndex]?.allowance?.scheme ===
        'coti-private-exact'
        ? envelope.intent.sellAsset?.kind !== 'private-erc20' &&
          envelope.intent.buyAsset?.kind !== 'private-erc20'
        : false
    )
  ) {
    throw new SignerError(
      'EXACT_ALLOWANCE_REQUIRED',
      'Approval token, spender, or amount is not exactly bound to the signed action.',
    );
  }
};

const validatePrivacyBridge = (
  envelope: SignedActionEnvelopeV1,
  step: MaterializedActionStep,
  signature: string,
  args: readonly unknown[],
): void => {
  requirePublicVisible(envelope);
  if (envelope.intent.order || envelope.intent.orderType) {
    fail('Privacy Portal actions cannot be bound to an OTC order.');
  }
  const pairId = metadataString(envelope, 'bridgePair');
  const pair =
    privacyBridgePair(pairId ?? '') ??
    fail('The signed Privacy Portal pair is not allowlisted.');
  const direction = metadataString(envelope, 'bridgeDirection');
  if (
    direction !== 'public-to-private' &&
    direction !== 'private-to-public'
  ) {
    fail('The signed Privacy Portal direction is invalid.');
  }
  if (
    metadataString(envelope, 'bridgeContractName') !== pair.contractName ||
    metadataString(envelope, 'bridgeKind') !== pair.bridgeKind ||
    metadataString(envelope, 'bridgeProvider') !== pair.provider
  ) {
    fail('The signed Privacy Portal route metadata is inconsistent.');
  }
  const runtimeBridge =
    envelope.registrySnapshot.contracts[pair.contractName]?.address;
  if (
    !runtimeBridge ||
    !sameAddress(runtimeBridge, pair.bridgeAddress) ||
    !sameAddress(step.to, pair.bridgeAddress)
  ) {
    fail('The Privacy Portal target does not match the audited pair.');
  }
  const expectedSell =
    direction === 'public-to-private'
      ? pair.publicTokenAddress
      : pair.privateTokenAddress;
  const expectedBuy =
    direction === 'public-to-private'
      ? pair.privateTokenAddress
      : pair.publicTokenAddress;
  const sell = envelope.intent.sellAsset;
  const buy = envelope.intent.buyAsset;
  if (
    !sell ||
    !buy ||
    sell.decimals !== pair.decimals ||
    buy.decimals !== pair.decimals ||
    sell.symbol !==
      (direction === 'public-to-private'
        ? pair.publicSymbol
        : pair.privateSymbol) ||
    buy.symbol !==
      (direction === 'public-to-private'
        ? pair.privateSymbol
        : pair.publicSymbol) ||
    (expectedSell
      ? !sameAddress(sell.address, expectedSell)
      : sell.kind !== 'native') ||
    (expectedBuy
      ? !sameAddress(buy.address, expectedBuy)
      : buy.kind !== 'native')
  ) {
    fail('The Privacy Portal assets do not match the allowlisted pair.');
  }
  const amount = atomic(envelope.intent.sellAmount, sell, 'bridge amount');
  if (
    envelope.intent.buyAmount !== envelope.intent.sellAmount ||
    metadataInteger(envelope, 'amountAtomic') !== amount
  ) {
    fail('The Privacy Portal amount binding is inconsistent.');
  }
  const portalFee = metadataInteger(envelope, 'portalFeeAtomic');
  const cotiTimestamp = metadataInteger(envelope, 'cotiOracleTimestamp');
  const tokenTimestamp = metadataInteger(envelope, 'tokenOracleTimestamp');
  metadataInteger(envelope, 'blockTimestamp');
  const expectedSignature =
    pair.bridgeKind === 'native' && direction === 'public-to-private'
      ? SIGNATURES.bridgeDepositNative
      : direction === 'public-to-private'
        ? SIGNATURES.bridgeDepositToken
        : SIGNATURES.bridgeWithdraw;
  if (signature !== expectedSignature) {
    fail('The Privacy Portal function does not match the signed direction.');
  }
  if (expectedSignature === SIGNATURES.bridgeDepositNative) {
    if (args.length !== 2) fail('Native shield calldata has an invalid shape.');
    requireInteger(args[0], cotiTimestamp, 'COTI oracle timestamp');
    requireInteger(args[1], tokenTimestamp, 'Token oracle timestamp');
  } else {
    if (args.length !== 3) fail('Token bridge calldata has an invalid shape.');
    requireInteger(args[0], amount, 'Bridge amount');
    requireInteger(args[1], cotiTimestamp, 'COTI oracle timestamp');
    requireInteger(args[2], tokenTimestamp, 'Token oracle timestamp');
  }
  const expectedValue =
    pair.bridgeKind === 'native'
      ? direction === 'public-to-private'
        ? amount
        : '0'
      : portalFee;
  requireInteger(step.value, expectedValue, 'Privacy Portal native value');
};

const decode = (
  signature: string,
  data: `0x${string}`,
): {
  functionName: string;
  args: readonly unknown[];
} => {
  const functionName = signature.slice(0, signature.indexOf('('));
  const parseRuntimeAbi = parseAbi as unknown as (
    signatures: readonly string[],
  ) => Abi;
  try {
    const decoded = decodeFunctionData({
      abi: parseRuntimeAbi([`function ${signature}`]),
      data,
    });
    if (decoded.functionName !== functionName) {
      fail('Decoded protocol function does not match the signed template.');
    }
    return {
      functionName,
      args: asArguments(decoded.args),
    };
  } catch (error) {
    if (error instanceof SignerError) throw error;
    return invalid(
      'Materialized protocol calldata cannot be decoded by its signed template.',
    );
  }
};

export class StrictMaterializedIntentValidator
  implements MaterializedIntentValidator
{
  readonly #standardOrders: StandardOrderFactsReader | null;

  constructor(options: {
    standardOrders?: StandardOrderFactsReader;
  } = {}) {
    this.#standardOrders = options.standardOrders ?? null;
  }

  async validate(
    envelope: SignedActionEnvelopeV1,
    step: MaterializedActionStep,
    stepIndex: number,
  ): Promise<void> {
    validateSignedOrderClassification(envelope);
    if (
      this.#standardOrders &&
      (
        envelope.intent.action === 'edit' ||
        envelope.intent.action === 'order_update'
      )
    ) {
      const order = envelope.intent.order;
      const standardEscrow =
        envelope.registrySnapshot.contracts.standardEscrow?.address;
      if (
        order &&
        standardEscrow &&
        sameAddress(order.escrowContract, standardEscrow)
      ) {
        const facts =
          await this.#standardOrders.readStandardOrderFacts(
            order.escrowContract,
            order.localId,
          );
        validateLiveStandardLifecycleBinding(envelope, facts);
      }
    }
    if (step.kind === 'approval') {
      validateApproval(envelope, step, stepIndex);
      return;
    }
    if (step.kind !== 'protocol') {
      invalid('Action envelopes cannot execute private-message writes.');
    }
    const signedStep =
      envelope.steps[stepIndex] ??
      fail('The materialized step has no signed counterpart.');
    if (signedStep.id !== step.id) {
      fail('Materialized step order does not match the signed action.');
    }
    const signature =
      signedStep.callTemplate?.functionSignature ??
      invalid(
        'Protocol execution requires a signed canonical call template.',
      );
    const { args } = decode(signature, step.data);
    switch (envelope.intent.action) {
      case 'create_trade':
        if (signature === SIGNATURES.createTrade) {
          validateCreateTrade(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.createDirectTrade) {
          validateCreateDirectTrade(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.createPrivateTrade) {
          validateCreatePrivateLiquidity(envelope, step, args);
          return;
        }
        return fail(
          'Create-trade function does not match the signed action.',
        );
      case 'create_recurring':
        if (signature === SIGNATURES.createRecurring) {
          validateCreateRecurring(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.createPrivateRecurring) {
          validateCreatePrivateRecurring(envelope, step, args);
          return;
        }
        return fail(
          'Create-recurring function does not match the signed action.',
        );
      case 'fill':
        if (signature === SIGNATURES.acceptLegacyStandardCounter) {
          validateLegacyStandardCounterAcceptance(
            envelope,
            step,
            args,
          );
        } else if (
          [
            SIGNATURES.fillPrivateRecurringBuy,
            SIGNATURES.fillPrivateRecurringSell,
          ].includes(signature as never)
        ) {
          validatePrivateRecurringFill(
            envelope,
            step,
            signature,
            args,
          );
        } else if (
          [
            SIGNATURES.acceptDirect,
            SIGNATURES.acceptDirectWithAccess,
            SIGNATURES.acceptDirectCounter,
            SIGNATURES.fillPrivate,
            SIGNATURES.fillPrivateWithAccess,
            SIGNATURES.fillHybridPrivate,
            SIGNATURES.fillHybridPrivateWithAccess,
          ].includes(signature as never)
        ) {
          validatePrivateOrDirectFill(envelope, step, signature, args);
        } else {
          validateFill(envelope, step, signature, args);
        }
        return;
      case 'order_update':
        validateOrderUpdate(envelope, step, signature, args);
        return;
      case 'counter':
        if (
          signature ===
          SIGNATURES.counterLegacyStandardAndClose
        ) {
          validateLegacyStandardCounterReplacement(
            envelope,
            step,
            args,
          );
        } else {
          validateDirectCounter(envelope, step, signature, args);
        }
        return;
      case 'edit':
        if (signature === SIGNATURES.editLegacyStandard) {
          validateLegacyStandardEdit(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.editStandard) {
          validateStandardEdit(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.editPrivateLiquidity) {
          validatePrivateLiquidityEdit(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.editDirect) {
          validateDirectEdit(envelope, step, args);
          return;
        }
        if (signature === SIGNATURES.editRecurring) {
          validateRecurringEdit(envelope, step, args);
          return;
        }
        return fail('Edit function does not match the signed action.');
      case 'privacy_bridge':
        validatePrivacyBridge(envelope, step, signature, args);
        return;
      case 'send_order_message':
        invalid(
          'This action does not have an audited signer execution shape.',
        );
    }
  }
}
