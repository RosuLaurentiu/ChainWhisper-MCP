import { canonicalDecimal, isNonNegativeDecimal, isPositiveDecimal } from './decimal.js';
import { DomainInputError } from './errors.js';
import type {
  Address,
  AmountVisibility,
  AssetReference,
  DomainGateway,
  FillPolicy,
  MissingDetail,
  OrderAccess,
  OrderIdentityInput,
  ResolvedAsset,
  TrustedOrderIdentity
} from './types.js';

const ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/u;
const HASH_PATTERN = /^0x[a-fA-F0-9]{64}$/u;
const HANDLE_PATTERN = /^cw_[a-zA-Z0-9_-]{8,160}$/u;
const LOCAL_ID_PATTERN = /^(?:0|[1-9]\d{0,77})$/u;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?Z$/u;
const FORBIDDEN_INPUT_KEYS = new Set([
  'abi',
  'aes',
  'aeskey',
  'accesssecret',
  'apikey',
  'bearer',
  'calldata',
  'ciphertext',
  'credential',
  'mnemonic',
  'password',
  'privatekey',
  'rawsecret',
  'secret',
  'seedphrase',
  'signature',
  'spender'
]);

export const normalizeAddress = (value: unknown, field: string, required = true): Address | null => {
  if ((value === undefined || value === null || value === '') && !required) return null;
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value.trim())) {
    throw new DomainInputError(`Enter a valid ${field}.`, [{ field, message: 'Expected a 20-byte EVM address.' }]);
  }
  return value.trim().toLowerCase() as Address;
};

export const normalizeOptionalHash = (value: unknown, field: string): string | null => {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || !HASH_PATTERN.test(value.trim())) {
    throw new DomainInputError(`Enter a valid ${field}.`, [{ field, message: 'Expected a 32-byte hex hash.' }]);
  }
  return value.trim().toLowerCase();
};

const MAX_INPUT_DEPTH = 32;
const MAX_INPUT_NODES = 2_048;

export const rejectSensitiveOrArbitraryInput = (value: unknown, path = 'input'): void => {
  const pending: Array<{ value: unknown; path: string; depth: number }> = [
    { value, path, depth: 0 }
  ];
  const visited = new WeakSet<object>();
  let nodes = 0;

  while (pending.length > 0) {
    const current = pending.pop()!;
    if (!current.value || typeof current.value !== 'object') continue;
    if (visited.has(current.value)) continue;
    visited.add(current.value);
    nodes += 1;
    if (current.depth > MAX_INPUT_DEPTH || nodes > MAX_INPUT_NODES) {
      throw new DomainInputError('The request is too deeply nested or complex.', [
        {
          field: current.path,
          message: 'Use a shallow JSON object containing only the documented tool fields.'
        }
      ]);
    }
    if (Array.isArray(current.value)) {
      for (let index = current.value.length - 1; index >= 0; index -= 1) {
        pending.push({
          value: current.value[index],
          path: `${current.path}[${index}]`,
          depth: current.depth + 1
        });
      }
      continue;
    }
    for (const [key, entry] of Object.entries(current.value as Record<string, unknown>)) {
      const normalized = key.replace(/[^a-z]/giu, '').toLowerCase();
      if (FORBIDDEN_INPUT_KEYS.has(normalized)) {
        throw new DomainInputError('Secrets, credentials, signatures, and arbitrary transaction data are not accepted.', [
          { field: `${current.path}.${key}`, message: 'Configure sensitive data only in the local signer adapter.' }
        ]);
      }
      pending.push({
        value: entry,
        path: `${current.path}.${key}`,
        depth: current.depth + 1
      });
    }
  }
};

export const assertAllowedKeys = (
  value: unknown,
  allowed: readonly string[],
  path = 'input'
): void => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  const allowedKeys = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !allowedKeys.has(key));
  if (unknown.length > 0) {
    throw new DomainInputError('The request contains unsupported fields.', unknown.map((key) => ({
      field: `${path}.${key}`,
      message: 'This field is not part of the allowlisted ChainWhisper tool schema.'
    })));
  }
};

export const normalizeOrderIdentity = (value: unknown): OrderIdentityInput => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DomainInputError('Select an order.', [{ field: 'order', message: 'Use an order handle or contract-local ID.' }]);
  }
  const record = value as Record<string, unknown>;
  const hasHandle = typeof record.handle === 'string' && record.handle.trim().length > 0;
  const hasContract = typeof record.escrowContract === 'string' && record.escrowContract.trim().length > 0;
  const hasLocalId = typeof record.localId === 'string' && record.localId.trim().length > 0;
  if (hasHandle === (hasContract || hasLocalId)) {
    throw new DomainInputError('Use exactly one trusted order identity format.', [
      { field: 'order', message: 'Provide handle, or both escrowContract and localId.' }
    ]);
  }
  if (hasHandle) {
    const handle = String(record.handle).trim();
    if (!HANDLE_PATTERN.test(handle)) {
      throw new DomainInputError('The order handle is invalid.', [{ field: 'order.handle', message: 'Expected a cw_ handle.' }]);
    }
    return { handle };
  }
  const escrowContract = normalizeAddress(record.escrowContract, 'order.escrowContract')!;
  const localId = typeof record.localId === 'string' ? record.localId.trim() : '';
  if (!LOCAL_ID_PATTERN.test(localId)) {
    throw new DomainInputError('The contract-local order ID is invalid.', [
      { field: 'order.localId', message: 'Use a non-negative integer string.' }
    ]);
  }
  return { escrowContract, localId };
};

export const assertTrustedOrder = async (
  gateway: DomainGateway,
  identity: OrderIdentityInput
): Promise<TrustedOrderIdentity | null> => {
  if (!('escrowContract' in identity)) return null;
  const address = identity.escrowContract as Address;
  if (!(await gateway.isTrustedEscrow(address))) {
    throw new DomainInputError('The order contract is not in the verified ChainWhisper registry.', [
      { field: 'order.escrowContract', message: 'Arbitrary contracts are not supported.' }
    ]);
  }
  return null;
};

export const resolveAsset = async (
  gateway: DomainGateway,
  reference: AssetReference | undefined,
  field: string,
  required = true
): Promise<ResolvedAsset | null> => {
  if (reference === undefined || reference === null || reference === '') {
    if (!required) return null;
    throw new DomainInputError(`Select ${field}.`, [{ field, message: 'Use native, a verified symbol, or a verified token address.' }]);
  }
  const asset = await gateway.resolveAsset(reference);
  if (!asset || !asset.verified || !Number.isInteger(asset.decimals) || asset.decimals < 0 || asset.decimals > 78) {
    throw new DomainInputError(`${field} is not a verified ChainWhisper asset.`, [
      { field, message: 'Unknown and unverified token references are not supported.' }
    ]);
  }
  return {
    ...asset,
    id: asset.id.trim().toLowerCase(),
    symbol: asset.symbol.trim(),
    address: asset.address ? (asset.address.toLowerCase() as Address) : null
  };
};

export const assertDistinctAssets = (
  first: ResolvedAsset | null,
  second: ResolvedAsset | null,
  fields: [string, string]
): void => {
  if (first && second && first.id === second.id) {
    throw new DomainInputError('Choose two different assets.', [
      { field: fields[0], message: 'This asset matches the other side.' },
      { field: fields[1], message: 'This asset matches the other side.' }
    ]);
  }
};

export const normalizePositiveAmount = (
  value: unknown,
  field: string,
  decimals: number,
  required = false
): string | null => {
  if (value === undefined || value === null || value === '') {
    if (required) {
      throw new DomainInputError(`Enter ${field}.`, [{ field, message: 'Use a positive decimal string.' }]);
    }
    return null;
  }
  if (!isPositiveDecimal(value, decimals)) {
    throw new DomainInputError(`${field} must be a positive decimal string with at most ${decimals} decimal places.`, [
      { field, message: 'JSON numbers and unsupported precision are not accepted.' }
    ]);
  }
  return canonicalDecimal(value);
};

export const normalizeNonNegativeAmount = (
  value: unknown,
  field: string,
  decimals: number
): string | null => {
  if (value === undefined || value === null || value === '') return null;
  if (!isNonNegativeDecimal(value, decimals)) {
    throw new DomainInputError(`${field} must be a non-negative decimal string with at most ${decimals} decimal places.`, [
      { field, message: 'JSON numbers and unsupported precision are not accepted.' }
    ]);
  }
  return canonicalDecimal(value);
};

export const normalizeAccess = (value: unknown, fallback: OrderAccess = 'public'): OrderAccess => {
  if (value === undefined || value === null || value === '') return fallback;
  if (value !== 'public' && value !== 'unlisted' && value !== 'direct') {
    throw new DomainInputError('Choose public, unlisted, or direct access.', [{ field: 'access', message: 'Unknown access type.' }]);
  }
  return value;
};

export const normalizeAmountVisibility = (value: unknown): AmountVisibility => {
  if (value === undefined || value === null || value === '') return 'visible';
  if (value !== 'visible' && value !== 'private') {
    throw new DomainInputError('Choose visible or private amounts.', [
      { field: 'amountVisibility', message: 'Unknown amount visibility.' }
    ]);
  }
  return value;
};

export const normalizeExpiry = (value: unknown, field = 'expiresAt'): string | null => {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || !ISO_DATE_PATTERN.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new DomainInputError('Enter an ISO-8601 UTC expiry or leave it empty for no expiry.', [
      { field, message: 'Example: 2026-08-01T12:00:00Z.' }
    ]);
  }
  return new Date(value).toISOString();
};

export const normalizeFillPolicy = (
  value: Partial<FillPolicy> | undefined,
  requestDecimals: number
): FillPolicy => {
  const minPartialFillBps = value?.minPartialFillBps ?? 0;
  if (!Number.isInteger(minPartialFillBps) || minPartialFillBps < 0 || minPartialFillBps > 5_000) {
    throw new DomainInputError('Minimum partial fill must be from 0 to 5,000 basis points.', [
      { field: 'fillPolicy.minPartialFillBps', message: 'Expected an integer basis-point value.' }
    ]);
  }
  return {
    partialFillsAllowed: value?.partialFillsAllowed ?? true,
    minPartialFillBps,
    minRequestAmount: normalizeNonNegativeAmount(
      value?.minRequestAmount,
      'fillPolicy.minRequestAmount',
      requestDecimals
    ),
    maxRequestAmountPerWallet: normalizeNonNegativeAmount(
      value?.maxRequestAmountPerWallet,
      'fillPolicy.maxRequestAmountPerWallet',
      requestDecimals
    ),
    oneFillPerWallet: value?.oneFillPerWallet ?? false
  };
};

export const requireMissing = (
  missing: MissingDetail[],
  condition: boolean,
  field: string,
  reason: string
): void => {
  if (!condition) missing.push({ field, reason, editable: true });
};

export const assertPlainRecord = (input: unknown): Record<string, unknown> => {
  rejectSensitiveOrArbitraryInput(input);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new DomainInputError('Use a JSON object for this tool.');
  }
  return input as Record<string, unknown>;
};
