import { createHash, randomUUID } from 'node:crypto';

import type {
  ChainWhisperActionKind,
  HexString,
} from '../shared/protocol.js';
import {
  ORDER_CLASSIFICATION_IDS_V1,
  type OrderClassificationIdV1,
} from '../shared/orderClassification.js';
import {
  PRIVACY_BRIDGE_PAIRS_V1,
  type PrivacyBridgeDirection,
  type PrivacyBridgePairId,
} from '../shared/privacyBridge.js';
import {
  AUTONOMY_STORE_VERSION,
  type AuthenticatedEncryptedAutonomyStore,
  type AutonomyStoreSnapshotV1,
} from './autonomyStore.js';

export const AUTONOMY_POLICY_VERSION = 'cw.autonomy-policy/1' as const;
export const AUTONOMY_RESERVATION_VERSION =
  'cw.autonomy-reservation/1' as const;
export const MAX_BOUNDED_POLICY_DURATION_MS = 30 * 24 * 60 * 60 * 1_000;
export const MAX_FULL_POLICY_DURATION_MS = 24 * 60 * 60 * 1_000;

export type AutonomyPolicyMode = 'bounded' | 'full';
export type AutonomyPolicyLifecycleState =
  | 'active'
  | 'paused'
  | 'revoked'
  | 'expired';

export type AutonomyAssetAmountV1 = {
  /**
   * Canonical signer asset identifier. Addresses are normalized to lowercase.
   * `native` is reserved for the chain's native COTI balance.
   */
  asset: string;
  /** Integer base-unit amount. */
  amount: string;
};

export type AutonomyPairV1 = {
  sellAsset: string;
  buyAsset: string;
};

export type AutonomyPriceBandV1 = AutonomyPairV1 & {
  /** Inclusive lower bound expressed as buy units / sell units. */
  minimumBuyPerSellNumerator: string;
  minimumBuyPerSellDenominator: string;
  /** Inclusive upper bound expressed as buy units / sell units. */
  maximumBuyPerSellNumerator: string;
  maximumBuyPerSellDenominator: string;
};

export type AutonomyPriceQuoteV1 = AutonomyPairV1 & {
  /** Exact signer-derived terms used to test the policy price band. */
  sellAmount: string;
  buyAmount: string;
};

export type AutonomyBridgeScopeV1 = {
  pair: PrivacyBridgePairId;
  direction: PrivacyBridgeDirection;
};

export type BoundedAutonomyScopeV1 = {
  allowedActions: ChainWhisperActionKind[];
  allowedAssets: string[];
  allowedPairs: AutonomyPairV1[];
  allowedOrderTypes: OrderClassificationIdV1[];
  allowedCounterparties: string[];
  allowedBridgeRoutes: AutonomyBridgeScopeV1[];
  messaging: {
    enabled: boolean;
    counterparties: string[];
  };
};

export type BoundedAutonomyLimitsV1 = {
  perActionSpend: AutonomyAssetAmountV1[];
  cumulativeSpend: AutonomyAssetAmountV1[];
  maximumNativeValuePerAction: string;
  maximumNativeValueCumulative: string;
  maximumNetworkFeePerAction: string;
  maximumNetworkFeeCumulative: string;
  maximumActions: number;
  maximumMessages: number;
  priceBands: AutonomyPriceBandV1[];
};

type AutonomyPolicyProposalCommonV1 = {
  version: typeof AUTONOMY_POLICY_VERSION;
  wallet: string;
  chainId: number;
  manifestHash: HexString;
  startsAt: string;
  expiresAt: string;
  /**
   * Policy-wide consent for the agent to both choose private amounts and view
   * policy-scoped private balances, hidden order inventory/progress, and
   * participant receipts.
   */
  agentVisiblePrivateAmounts: boolean;
};

export type BoundedAutonomyPolicyProposalV1 =
  AutonomyPolicyProposalCommonV1 & {
    mode: 'bounded';
    scope: BoundedAutonomyScopeV1;
    limits: BoundedAutonomyLimitsV1;
  };

export type FullAutonomyPolicyProposalV1 = AutonomyPolicyProposalCommonV1 & {
  mode: 'full';
  /**
   * Explicit acknowledgement that "full" still means only the signer's
   * audited ChainWhisper economic surface, never arbitrary calldata.
   */
  allowlistedEconomicSurface: true;
};

export type AutonomyPolicyProposalV1 =
  | BoundedAutonomyPolicyProposalV1
  | FullAutonomyPolicyProposalV1;

export type AutonomyPolicyLifecycleV1 = {
  state: AutonomyPolicyLifecycleState;
  changedAt: string;
  reason?: 'global-pause' | 'local-revocation' | 'time-expired';
};

export type ActiveAutonomyPolicyV1 = AutonomyPolicyProposalV1 & {
  id: string;
  activatedAt: string;
  /**
   * SHA-256 commitment to every immutable term, the local policy id, and the
   * activation timestamp. It is checked after every store read.
   */
  termsDigest: HexString;
  lifecycle: AutonomyPolicyLifecycleV1;
};

export type PolicyExposureV1 = {
  wallet: string;
  chainId: number;
  manifestHash: HexString;
  operationHash: HexString;
  action: ChainWhisperActionKind;
  orderType?: OrderClassificationIdV1;
  pairs: AutonomyPairV1[];
  priceQuotes: AutonomyPriceQuoteV1[];
  grossSpend: AutonomyAssetAmountV1[];
  minimumReceive: AutonomyAssetAmountV1[];
  counterparty?: string;
  bridge?: AutonomyBridgeScopeV1;
  messageCount: number;
  nativeValue: string;
  maximumNetworkFee: string;
  /**
   * True only when the signer derived every spend and price-band term needed
   * for bounded-policy evaluation from the exact materialized action.
   */
  boundedRiskComplete: boolean;
  agentProvidedPrivateAmounts: boolean;
  /** Hashes of the exact materialized transaction/message steps. */
  stepDigests: HexString[];
};

/**
 * Wallet-scoped read authorization derived from verified ChainWhisper state.
 * Asset aliases let a bounded policy match either a manifest symbol or its
 * canonical token address without exposing decrypted values to this manager.
 */
export type PrivateStatePolicyScopeV1 = {
  wallet: string;
  chainId: number;
  manifestHash: HexString;
  assets: Array<{ aliases: string[] }>;
  pair?: {
    firstAliases: string[];
    secondAliases: string[];
    bidirectional: boolean;
  };
  orderType?: OrderClassificationIdV1;
  counterparties: string[];
};

export type AutonomyReservationState =
  | 'reserved'
  | 'signed'
  | 'pending'
  | 'uncertain'
  | 'settled'
  | 'released';

export type AutonomyReservationV1 = {
  version: typeof AUTONOMY_RESERVATION_VERSION;
  id: string;
  policyId: string;
  policyTermsDigest: HexString;
  operationHash: HexString;
  exposureDigest: HexString;
  /**
   * Commits the authorization to policy, operation, exposure, exact step
   * digests, native value, and maximum network fee.
   */
  authorizationBinding: HexString;
  exposure: PolicyExposureV1;
  state: AutonomyReservationState;
  createdAt: string;
  updatedAt: string;
  signedTransactionHashes: HexString[];
};

export type AutonomyDenialCode =
  | 'INVALID_PROPOSAL'
  | 'INVALID_EXPOSURE'
  | 'LOCAL_APPROVAL_DECLINED'
  | 'LOCAL_EDIT_BROADENED_POLICY'
  | 'POLICY_NOT_FOUND'
  | 'POLICY_NOT_STARTED'
  | 'POLICY_EXPIRED'
  | 'POLICY_PAUSED'
  | 'POLICY_REVOKED'
  | 'GLOBAL_PAUSED'
  | 'WALLET_MISMATCH'
  | 'CHAIN_MISMATCH'
  | 'MANIFEST_MISMATCH'
  | 'ACTION_NOT_ALLOWED'
  | 'ASSET_NOT_ALLOWED'
  | 'PAIR_NOT_ALLOWED'
  | 'ORDER_TYPE_NOT_ALLOWED'
  | 'COUNTERPARTY_NOT_ALLOWED'
  | 'BRIDGE_NOT_ALLOWED'
  | 'MESSAGING_NOT_ALLOWED'
  | 'PRIVATE_AMOUNT_DISCLOSURE_NOT_ALLOWED'
  | 'ECONOMIC_EXPOSURE_INCOMPLETE'
  | 'PER_ACTION_SPEND_EXCEEDED'
  | 'CUMULATIVE_SPEND_EXCEEDED'
  | 'NATIVE_VALUE_EXCEEDED'
  | 'CUMULATIVE_NATIVE_VALUE_EXCEEDED'
  | 'NETWORK_FEE_EXCEEDED'
  | 'CUMULATIVE_NETWORK_FEE_EXCEEDED'
  | 'ACTION_LIMIT_EXCEEDED'
  | 'MESSAGE_LIMIT_EXCEEDED'
  | 'PRICE_OUT_OF_RANGE'
  | 'OPERATION_ALREADY_RESERVED'
  | 'OPERATION_BINDING_MISMATCH'
  | 'RESERVATION_NOT_FOUND'
  | 'RESERVATION_STATE_INVALID'
  | 'STORE_TAMPERED';

export type AutonomyDenialV1 = {
  code: AutonomyDenialCode;
  message: string;
  policyId?: string;
  field?: string;
};

export type AutonomyDecision<T> =
  | { allowed: true; value: T }
  | { allowed: false; denial: AutonomyDenialV1 };

export type AutonomySignedWriteV1<T> = {
  reservation: AutonomyReservationV1;
  value: T;
};

export type AutonomyRemainingBudgetV1 = {
  spendByAsset: AutonomyAssetAmountV1[];
  nativeValue: string | null;
  networkFee: string | null;
  actions: number | null;
  messages: number | null;
};

export type AutonomyPolicyStatusV1 = {
  policy: ActiveAutonomyPolicyV1;
  remaining: AutonomyRemainingBudgetV1 | null;
};

export type AutonomyStatusV1 = {
  globalPaused: boolean;
  policies: AutonomyPolicyStatusV1[];
  activeReservationCount: number;
};

export type ActivationApprovalRequestV1 = {
  proposal: AutonomyPolicyProposalV1;
  fullAutonomyWarnings:
    | []
    | [
        'Use a dedicated, minimally funded Agent Wallet.',
        'Full autonomy is limited to the audited ChainWhisper economic surface.',
      ];
};

export type ActivationApprovalResultV1 =
  | { approved: false }
  | {
      approved: true;
      /**
       * The local control page may narrow the proposal. Broadening it is
       * rejected, so the agent can reason about the maximum requested grant.
       */
      proposal: AutonomyPolicyProposalV1;
    };

export interface AutonomyLocalApprovalHooks {
  approveActivation(
    request: ActivationApprovalRequestV1,
  ): Promise<ActivationApprovalResultV1>;
  approveResume(request: {
    policies: ActiveAutonomyPolicyV1[];
  }): Promise<boolean>;
  approveRevocation(request: {
    policy: ActiveAutonomyPolicyV1;
  }): Promise<boolean>;
}

export type AutonomyPolicyManagerOptions = {
  store: AuthenticatedEncryptedAutonomyStore;
  approvals: AutonomyLocalApprovalHooks;
  now?: () => Date;
  idFactory?: () => string;
};

const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const ASSET_PATTERN = /^(?:native|0x[0-9a-fA-F]{40}|[A-Za-z0-9][A-Za-z0-9:._-]{0,127})$/;
const POLICY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ACTIONS: readonly ChainWhisperActionKind[] = [
  'create_trade',
  'create_recurring',
  'fill',
  'counter',
  'edit',
  'order_update',
  'privacy_bridge',
  'send_order_message',
];
const PAIR_ACTIONS = new Set<ChainWhisperActionKind>([
  'create_trade',
  'create_recurring',
  'fill',
  'counter',
  'edit',
]);
const ORDER_TYPES = new Set<string>(ORDER_CLASSIFICATION_IDS_V1);
const BRIDGE_PAIRS = new Set<string>(
  PRIVACY_BRIDGE_PAIRS_V1.map((pair) => pair.id),
);
const BRIDGE_DIRECTIONS = new Set<string>([
  'public-to-private',
  'private-to-public',
]);

const denial = (
  code: AutonomyDenialCode,
  message: string,
  details: Pick<AutonomyDenialV1, 'policyId' | 'field'> = {},
): AutonomyDecision<never> => ({
  allowed: false,
  denial: { code, message, ...details },
});

const allowed = <T>(value: T): AutonomyDecision<T> => ({
  allowed: true,
  value,
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === 'object' && !Array.isArray(value));

const clone = <T>(value: T): T => structuredClone(value);

const canonicalStringify = (value: unknown): string => {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalStringify).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonicalStringify(record[key])}`,
    )
    .join(',')}}`;
};

const digest = (value: unknown): HexString =>
  `0x${createHash('sha256').update(canonicalStringify(value)).digest('hex')}`;

/** Commits a global resume approval to the complete affected policy set. */
export const autonomyResumeBinding = (
  policies: readonly ActiveAutonomyPolicyV1[],
): HexString =>
  digest({
    domain: 'chainwhisper/autonomy-resume/2',
    policies: policies
      .map(({ id, termsDigest }) => ({ id, termsDigest }))
      .sort((left, right) =>
        left.id === right.id
          ? left.termsDigest.localeCompare(right.termsDigest)
          : left.id.localeCompare(right.id),
      ),
  });

export const isExactAutonomyResumeBinding = (
  policies: readonly ActiveAutonomyPolicyV1[],
  candidate: unknown,
): candidate is HexString =>
  policies.length > 0 &&
  typeof candidate === 'string' &&
  candidate === autonomyResumeBinding(policies);

const integer = (
  value: unknown,
  field: string,
): AutonomyDecision<bigint> => {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    return denial('INVALID_PROPOSAL', `${field} must be an unsigned base-unit integer.`, {
      field,
    });
  }
  return allowed(BigInt(value));
};

const exposureInteger = (
  value: unknown,
  field: string,
): AutonomyDecision<bigint> => {
  const result = integer(value, field);
  return result.allowed
    ? result
    : denial('INVALID_EXPOSURE', result.denial.message, { field });
};

const isoTime = (
  value: unknown,
  field: string,
): AutonomyDecision<number> => {
  if (typeof value !== 'string') {
    return denial('INVALID_PROPOSAL', `${field} must be an ISO-8601 timestamp.`, {
      field,
    });
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    return denial('INVALID_PROPOSAL', `${field} must be a canonical ISO-8601 timestamp.`, {
      field,
    });
  }
  return allowed(parsed);
};

const normalizeAddress = (value: string): string => value.toLowerCase();
const normalizeAsset = (value: string): string => value.toLowerCase();
const normalizeHash = <T extends string>(value: T): T =>
  value.toLowerCase() as T;
const pairKey = (pair: AutonomyPairV1): string =>
  `${normalizeAsset(pair.sellAsset)}>${normalizeAsset(pair.buyAsset)}`;
const bridgeKey = (route: AutonomyBridgeScopeV1): string =>
  `${route.pair}:${route.direction}`;

const uniqueSorted = (values: readonly string[]): string[] =>
  [...new Set(values)].sort();

const normalizeAmounts = (
  values: readonly AutonomyAssetAmountV1[],
): AutonomyAssetAmountV1[] =>
  [...values]
    .map((value) => ({
      asset: normalizeAsset(value.asset),
      amount: value.amount,
    }))
    .sort((left, right) => left.asset.localeCompare(right.asset));

const normalizePair = (pair: AutonomyPairV1): AutonomyPairV1 => ({
  sellAsset: normalizeAsset(pair.sellAsset),
  buyAsset: normalizeAsset(pair.buyAsset),
});

const normalizeProposal = (
  input: AutonomyPolicyProposalV1,
): AutonomyPolicyProposalV1 => {
  const common = {
    ...input,
    wallet: normalizeAddress(input.wallet),
    manifestHash: normalizeHash(input.manifestHash),
  };
  if (input.mode === 'full') {
    return common;
  }
  return {
    ...common,
    mode: 'bounded',
    scope: {
      allowedActions: uniqueSorted(input.scope.allowedActions) as ChainWhisperActionKind[],
      allowedAssets: uniqueSorted(
        input.scope.allowedAssets.map(normalizeAsset),
      ),
      allowedPairs: [...input.scope.allowedPairs]
        .map(normalizePair)
        .sort((left, right) => pairKey(left).localeCompare(pairKey(right))),
      allowedOrderTypes: uniqueSorted(
        input.scope.allowedOrderTypes,
      ) as OrderClassificationIdV1[],
      allowedCounterparties: uniqueSorted(
        input.scope.allowedCounterparties.map(normalizeAddress),
      ),
      allowedBridgeRoutes: [...input.scope.allowedBridgeRoutes].sort((left, right) =>
        bridgeKey(left).localeCompare(bridgeKey(right)),
      ),
      messaging: {
        enabled: input.scope.messaging.enabled,
        counterparties: uniqueSorted(
          input.scope.messaging.counterparties.map(normalizeAddress),
        ),
      },
    },
    limits: {
      ...input.limits,
      perActionSpend: normalizeAmounts(input.limits.perActionSpend),
      cumulativeSpend: normalizeAmounts(input.limits.cumulativeSpend),
      priceBands: [...input.limits.priceBands]
        .map((band) => ({ ...band, ...normalizePair(band) }))
        .sort((left, right) => pairKey(left).localeCompare(pairKey(right))),
    },
  };
};

const normalizeExposure = (input: PolicyExposureV1): PolicyExposureV1 => ({
  ...input,
  wallet: normalizeAddress(input.wallet),
  manifestHash: normalizeHash(input.manifestHash),
  operationHash: normalizeHash(input.operationHash),
  pairs: [...input.pairs]
    .map(normalizePair)
    .sort((left, right) => pairKey(left).localeCompare(pairKey(right))),
  priceQuotes: [...input.priceQuotes]
    .map((quote) => ({ ...quote, ...normalizePair(quote) }))
    .sort((left, right) => pairKey(left).localeCompare(pairKey(right))),
  grossSpend: normalizeAmounts(input.grossSpend),
  minimumReceive: normalizeAmounts(input.minimumReceive),
  ...(input.counterparty
    ? { counterparty: normalizeAddress(input.counterparty) }
    : {}),
  stepDigests: input.stepDigests.map(normalizeHash),
});

const mapAmounts = (
  amounts: readonly AutonomyAssetAmountV1[],
): Map<string, bigint> =>
  new Map(
    amounts.map((entry) => [normalizeAsset(entry.asset), BigInt(entry.amount)]),
  );

const termsForDigest = (
  policy: Omit<ActiveAutonomyPolicyV1, 'termsDigest' | 'lifecycle'>,
): unknown => policy;

const calculatePolicyDigest = (
  policy: Omit<ActiveAutonomyPolicyV1, 'termsDigest' | 'lifecycle'>,
): HexString => digest(termsForDigest(policy));

const calculateExposureDigest = (exposure: PolicyExposureV1): HexString =>
  digest(exposure);

const calculateAuthorizationBinding = (
  policy: ActiveAutonomyPolicyV1,
  exposure: PolicyExposureV1,
): HexString =>
  digest({
    policyId: policy.id,
    policyTermsDigest: policy.termsDigest,
    operationHash: exposure.operationHash,
    exposure: calculateExposureDigest(exposure),
    stepDigests: exposure.stepDigests,
    nativeValue: exposure.nativeValue,
    maximumNetworkFee: exposure.maximumNetworkFee,
  });

const ratioAtLeast = (
  leftNumerator: bigint,
  leftDenominator: bigint,
  rightNumerator: bigint,
  rightDenominator: bigint,
): boolean =>
  leftNumerator * rightDenominator >=
  rightNumerator * leftDenominator;

const ratioAtMost = (
  leftNumerator: bigint,
  leftDenominator: bigint,
  rightNumerator: bigint,
  rightDenominator: bigint,
): boolean =>
  leftNumerator * rightDenominator <=
  rightNumerator * leftDenominator;

const sumAmounts = (
  reservations: readonly AutonomyReservationV1[],
  selector: (reservation: AutonomyReservationV1) => readonly AutonomyAssetAmountV1[],
): Map<string, bigint> => {
  const result = new Map<string, bigint>();
  for (const reservation of reservations) {
    for (const amount of selector(reservation)) {
      const asset = normalizeAsset(amount.asset);
      result.set(asset, (result.get(asset) ?? 0n) + BigInt(amount.amount));
    }
  }
  return result;
};

const activeReservationsFor = (
  snapshot: AutonomyStoreSnapshotV1,
  policyId: string,
): AutonomyReservationV1[] =>
  Object.values(snapshot.reservations).filter(
    (reservation) =>
      reservation.policyId === policyId && reservation.state !== 'released',
  );

const stringArray = (
  value: unknown,
  field: string,
): AutonomyDecision<string[]> => {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    return denial('INVALID_PROPOSAL', `${field} must be an array of strings.`, {
      field,
    });
  }
  return allowed(value as string[]);
};

const validAddressArray = (
  value: unknown,
  field: string,
): AutonomyDecision<string[]> => {
  const values = stringArray(value, field);
  if (!values.allowed) return values;
  if (values.value.some((entry) => !ADDRESS_PATTERN.test(entry))) {
    return denial(
      'INVALID_PROPOSAL',
      `${field} contains an invalid EVM address.`,
      { field },
    );
  }
  return values;
};

const validateAmounts = (
  value: unknown,
  field: string,
  code: 'INVALID_PROPOSAL' | 'INVALID_EXPOSURE' = 'INVALID_PROPOSAL',
): AutonomyDecision<AutonomyAssetAmountV1[]> => {
  if (!Array.isArray(value)) {
    return denial(code, `${field} must be an array of asset amounts.`, {
      field,
    });
  }
  const output: AutonomyAssetAmountV1[] = [];
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    if (
      !isRecord(entry) ||
      typeof entry.asset !== 'string' ||
      !ASSET_PATTERN.test(entry.asset)
    ) {
      return denial(code, `${field}[${index}].asset is invalid.`, {
        field: `${field}[${index}].asset`,
      });
    }
    const amount =
      code === 'INVALID_EXPOSURE'
        ? exposureInteger(entry.amount, `${field}[${index}].amount`)
        : integer(entry.amount, `${field}[${index}].amount`);
    if (!amount.allowed) return amount;
    const asset = normalizeAsset(entry.asset);
    if (seen.has(asset)) {
      return denial(code, `${field} contains a duplicate asset.`, { field });
    }
    seen.add(asset);
    output.push({ asset, amount: amount.value.toString() });
  }
  return allowed(output);
};

const validatePairs = (
  value: unknown,
  field: string,
  code: 'INVALID_PROPOSAL' | 'INVALID_EXPOSURE' = 'INVALID_PROPOSAL',
): AutonomyDecision<AutonomyPairV1[]> => {
  if (!Array.isArray(value)) {
    return denial(code, `${field} must be an array of asset pairs.`, {
      field,
    });
  }
  const pairs: AutonomyPairV1[] = [];
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    if (
      !isRecord(entry) ||
      typeof entry.sellAsset !== 'string' ||
      typeof entry.buyAsset !== 'string' ||
      !ASSET_PATTERN.test(entry.sellAsset) ||
      !ASSET_PATTERN.test(entry.buyAsset)
    ) {
      return denial(code, `${field}[${index}] is not a valid asset pair.`, {
        field: `${field}[${index}]`,
      });
    }
    const pair = normalizePair({
      sellAsset: entry.sellAsset,
      buyAsset: entry.buyAsset,
    });
    if (pair.sellAsset === pair.buyAsset) {
      return denial(code, `${field}[${index}] must use distinct assets.`, {
        field: `${field}[${index}]`,
      });
    }
    const key = pairKey(pair);
    if (seen.has(key)) {
      return denial(code, `${field} contains a duplicate pair.`, { field });
    }
    seen.add(key);
    pairs.push(pair);
  }
  return allowed(pairs);
};

const validateBridgeScopes = (
  value: unknown,
  field: string,
): AutonomyDecision<AutonomyBridgeScopeV1[]> => {
  if (!Array.isArray(value)) {
    return denial('INVALID_PROPOSAL', `${field} must be an array.`, { field });
  }
  const routes: AutonomyBridgeScopeV1[] = [];
  const seen = new Set<string>();
  for (const [index, entry] of value.entries()) {
    if (
      !isRecord(entry) ||
      typeof entry.pair !== 'string' ||
      !BRIDGE_PAIRS.has(entry.pair) ||
      typeof entry.direction !== 'string' ||
      !BRIDGE_DIRECTIONS.has(entry.direction)
    ) {
      return denial(
        'INVALID_PROPOSAL',
        `${field}[${index}] is not a supported bridge route.`,
        { field: `${field}[${index}]` },
      );
    }
    const route = {
      pair: entry.pair as PrivacyBridgePairId,
      direction: entry.direction as PrivacyBridgeDirection,
    };
    const key = bridgeKey(route);
    if (seen.has(key)) {
      return denial(
        'INVALID_PROPOSAL',
        `${field} contains a duplicate bridge route.`,
        { field },
      );
    }
    seen.add(key);
    routes.push(route);
  }
  return allowed(routes);
};

const validatePriceBands = (
  value: unknown,
  field: string,
): AutonomyDecision<AutonomyPriceBandV1[]> => {
  const pairs = validatePairs(value, field);
  if (!pairs.allowed) return pairs;
  const source = value as Record<string, unknown>[];
  const bands: AutonomyPriceBandV1[] = [];
  for (const [index, pair] of pairs.value.entries()) {
    const entry = source[index]!;
    const minimumNumerator = integer(
      entry.minimumBuyPerSellNumerator,
      `${field}[${index}].minimumBuyPerSellNumerator`,
    );
    if (!minimumNumerator.allowed) return minimumNumerator;
    const minimumDenominator = integer(
      entry.minimumBuyPerSellDenominator,
      `${field}[${index}].minimumBuyPerSellDenominator`,
    );
    if (!minimumDenominator.allowed) return minimumDenominator;
    const maximumNumerator = integer(
      entry.maximumBuyPerSellNumerator,
      `${field}[${index}].maximumBuyPerSellNumerator`,
    );
    if (!maximumNumerator.allowed) return maximumNumerator;
    const maximumDenominator = integer(
      entry.maximumBuyPerSellDenominator,
      `${field}[${index}].maximumBuyPerSellDenominator`,
    );
    if (!maximumDenominator.allowed) return maximumDenominator;
    if (
      minimumDenominator.value === 0n ||
      maximumDenominator.value === 0n
    ) {
      return denial(
        'INVALID_PROPOSAL',
        `${field} denominators must be greater than zero.`,
        { field },
      );
    }
    if (
      !ratioAtMost(
        minimumNumerator.value,
        minimumDenominator.value,
        maximumNumerator.value,
        maximumDenominator.value,
      )
    ) {
      return denial(
        'INVALID_PROPOSAL',
        `${field} has a minimum price greater than its maximum price.`,
        { field },
      );
    }
    bands.push({
      ...pair,
      minimumBuyPerSellNumerator: minimumNumerator.value.toString(),
      minimumBuyPerSellDenominator: minimumDenominator.value.toString(),
      maximumBuyPerSellNumerator: maximumNumerator.value.toString(),
      maximumBuyPerSellDenominator: maximumDenominator.value.toString(),
    });
  }
  return allowed(bands);
};

const parseBoundedProposal = (
  input: Record<string, unknown>,
  common: Omit<AutonomyPolicyProposalCommonV1, 'version'>,
): AutonomyDecision<BoundedAutonomyPolicyProposalV1> => {
  if (!isRecord(input.scope) || !isRecord(input.limits)) {
    return denial(
      'INVALID_PROPOSAL',
      'A bounded policy requires scope and limits.',
    );
  }
  const actions = stringArray(
    input.scope.allowedActions,
    'scope.allowedActions',
  );
  if (!actions.allowed) return actions;
  if (
    actions.value.length === 0 ||
    actions.value.some(
      (action) => !ACTIONS.includes(action as ChainWhisperActionKind),
    )
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'scope.allowedActions must contain supported ChainWhisper actions.',
      { field: 'scope.allowedActions' },
    );
  }
  const assets = stringArray(input.scope.allowedAssets, 'scope.allowedAssets');
  if (!assets.allowed) return assets;
  if (assets.value.some((asset) => !ASSET_PATTERN.test(asset))) {
    return denial(
      'INVALID_PROPOSAL',
      'scope.allowedAssets contains an invalid asset identifier.',
      { field: 'scope.allowedAssets' },
    );
  }
  const pairs = validatePairs(input.scope.allowedPairs, 'scope.allowedPairs');
  if (!pairs.allowed) return pairs;
  const orderTypes = stringArray(
    input.scope.allowedOrderTypes,
    'scope.allowedOrderTypes',
  );
  if (!orderTypes.allowed) return orderTypes;
  if (orderTypes.value.some((orderType) => !ORDER_TYPES.has(orderType))) {
    return denial(
      'INVALID_PROPOSAL',
      'scope.allowedOrderTypes contains an unsupported order type.',
      { field: 'scope.allowedOrderTypes' },
    );
  }
  const counterparties = validAddressArray(
    input.scope.allowedCounterparties,
    'scope.allowedCounterparties',
  );
  if (!counterparties.allowed) return counterparties;
  const bridgeRoutes = validateBridgeScopes(
    input.scope.allowedBridgeRoutes,
    'scope.allowedBridgeRoutes',
  );
  if (!bridgeRoutes.allowed) return bridgeRoutes;
  if (!isRecord(input.scope.messaging)) {
    return denial(
      'INVALID_PROPOSAL',
      'scope.messaging must define an enabled flag and counterparties.',
      { field: 'scope.messaging' },
    );
  }
  if (typeof input.scope.messaging.enabled !== 'boolean') {
    return denial(
      'INVALID_PROPOSAL',
      'scope.messaging.enabled must be a boolean.',
      { field: 'scope.messaging.enabled' },
    );
  }
  const messageCounterparties = validAddressArray(
    input.scope.messaging.counterparties,
    'scope.messaging.counterparties',
  );
  if (!messageCounterparties.allowed) return messageCounterparties;

  const normalizedActions = uniqueSorted(
    actions.value,
  ) as ChainWhisperActionKind[];
  const normalizedAssets = uniqueSorted(assets.value.map(normalizeAsset));
  const requiresPairs = normalizedActions.some((action) =>
    PAIR_ACTIONS.has(action),
  );
  if (requiresPairs && pairs.value.length === 0) {
    return denial(
      'INVALID_PROPOSAL',
      'Trade policies require at least one allowed pair.',
      { field: 'scope.allowedPairs' },
    );
  }
  if (requiresPairs && orderTypes.value.length === 0) {
    return denial(
      'INVALID_PROPOSAL',
      'Trade policies require at least one allowed order type.',
      { field: 'scope.allowedOrderTypes' },
    );
  }
  if (
    normalizedActions.includes('privacy_bridge') &&
    bridgeRoutes.value.length === 0
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Privacy bridge autonomy requires at least one bridge route.',
      { field: 'scope.allowedBridgeRoutes' },
    );
  }
  if (
    normalizedActions.includes('send_order_message') &&
    (!input.scope.messaging.enabled ||
      messageCounterparties.value.length === 0)
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Message autonomy requires an enabled messaging scope and counterparties.',
      { field: 'scope.messaging' },
    );
  }
  const pairAssets = pairs.value.flatMap((pair) => [
    pair.sellAsset,
    pair.buyAsset,
  ]);
  if (pairAssets.some((asset) => !normalizedAssets.includes(asset))) {
    return denial(
      'INVALID_PROPOSAL',
      'Every allowed pair asset must be present in allowedAssets.',
      { field: 'scope.allowedPairs' },
    );
  }

  const perActionSpend = validateAmounts(
    input.limits.perActionSpend,
    'limits.perActionSpend',
  );
  if (!perActionSpend.allowed) return perActionSpend;
  const cumulativeSpend = validateAmounts(
    input.limits.cumulativeSpend,
    'limits.cumulativeSpend',
  );
  if (!cumulativeSpend.allowed) return cumulativeSpend;
  const perActionMap = mapAmounts(perActionSpend.value);
  const cumulativeMap = mapAmounts(cumulativeSpend.value);
  if (
    normalizedAssets.some(
      (asset) => !perActionMap.has(asset) || !cumulativeMap.has(asset),
    ) ||
    [...perActionMap.keys(), ...cumulativeMap.keys()].some(
      (asset) => !normalizedAssets.includes(asset),
    )
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Spend limits must cover exactly the allowed assets.',
      { field: 'limits.perActionSpend' },
    );
  }
  for (const asset of normalizedAssets) {
    if (perActionMap.get(asset)! > cumulativeMap.get(asset)!) {
      return denial(
        'INVALID_PROPOSAL',
        'Each cumulative spend limit must be at least its per-action limit.',
        { field: `limits.cumulativeSpend.${asset}` },
      );
    }
  }

  const integerFields = [
    'maximumNativeValuePerAction',
    'maximumNativeValueCumulative',
    'maximumNetworkFeePerAction',
    'maximumNetworkFeeCumulative',
  ] as const;
  const parsedIntegers = new Map<string, bigint>();
  for (const field of integerFields) {
    const parsed = integer(input.limits[field], `limits.${field}`);
    if (!parsed.allowed) return parsed;
    parsedIntegers.set(field, parsed.value);
  }
  if (
    parsedIntegers.get('maximumNativeValuePerAction')! >
    parsedIntegers.get('maximumNativeValueCumulative')!
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'The cumulative native-value limit must cover one action.',
      { field: 'limits.maximumNativeValueCumulative' },
    );
  }
  if (
    parsedIntegers.get('maximumNetworkFeePerAction')! >
    parsedIntegers.get('maximumNetworkFeeCumulative')!
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'The cumulative network-fee limit must cover one action.',
      { field: 'limits.maximumNetworkFeeCumulative' },
    );
  }
  if (
    !Number.isSafeInteger(input.limits.maximumActions) ||
    (input.limits.maximumActions as number) <= 0
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'limits.maximumActions must be a positive safe integer.',
      { field: 'limits.maximumActions' },
    );
  }
  if (
    !Number.isSafeInteger(input.limits.maximumMessages) ||
    (input.limits.maximumMessages as number) < 0
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'limits.maximumMessages must be a non-negative safe integer.',
      { field: 'limits.maximumMessages' },
    );
  }
  if (
    normalizedActions.includes('send_order_message') &&
    (input.limits.maximumMessages as number) === 0
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Message autonomy requires a positive message limit.',
      { field: 'limits.maximumMessages' },
    );
  }
  const priceBands = validatePriceBands(
    input.limits.priceBands,
    'limits.priceBands',
  );
  if (!priceBands.allowed) return priceBands;
  const pairKeys = new Set(pairs.value.map(pairKey));
  const bandKeys = new Set(priceBands.value.map(pairKey));
  if (
    pairKeys.size !== bandKeys.size ||
    [...pairKeys].some((key) => !bandKeys.has(key))
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Every allowed pair requires exactly one price band.',
      { field: 'limits.priceBands' },
    );
  }

  return allowed(
    normalizeProposal({
      version: AUTONOMY_POLICY_VERSION,
      ...common,
      mode: 'bounded',
      scope: {
        allowedActions: normalizedActions,
        allowedAssets: normalizedAssets,
        allowedPairs: pairs.value,
        allowedOrderTypes:
          orderTypes.value as OrderClassificationIdV1[],
        allowedCounterparties: counterparties.value,
        allowedBridgeRoutes: bridgeRoutes.value,
        messaging: {
          enabled: input.scope.messaging.enabled,
          counterparties: messageCounterparties.value,
        },
      },
      limits: {
        perActionSpend: perActionSpend.value,
        cumulativeSpend: cumulativeSpend.value,
        maximumNativeValuePerAction: parsedIntegers
          .get('maximumNativeValuePerAction')!
          .toString(),
        maximumNativeValueCumulative: parsedIntegers
          .get('maximumNativeValueCumulative')!
          .toString(),
        maximumNetworkFeePerAction: parsedIntegers
          .get('maximumNetworkFeePerAction')!
          .toString(),
        maximumNetworkFeeCumulative: parsedIntegers
          .get('maximumNetworkFeeCumulative')!
          .toString(),
        maximumActions: input.limits.maximumActions as number,
        maximumMessages: input.limits.maximumMessages as number,
        priceBands: priceBands.value,
      },
    }) as BoundedAutonomyPolicyProposalV1,
  );
};

/**
 * Validates and canonicalizes an agent-proposed policy before it can reach the
 * local approval surface.
 */
export const validateAutonomyPolicyProposal = (
  value: unknown,
): AutonomyDecision<AutonomyPolicyProposalV1> => {
  if (!isRecord(value) || value.version !== AUTONOMY_POLICY_VERSION) {
    return denial(
      'INVALID_PROPOSAL',
      `Policy version must be ${AUTONOMY_POLICY_VERSION}.`,
      { field: 'version' },
    );
  }
  if (
    typeof value.wallet !== 'string' ||
    !ADDRESS_PATTERN.test(value.wallet)
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Policy wallet must be a valid EVM address.',
      { field: 'wallet' },
    );
  }
  if (!Number.isSafeInteger(value.chainId) || (value.chainId as number) <= 0) {
    return denial(
      'INVALID_PROPOSAL',
      'Policy chainId must be a positive safe integer.',
      { field: 'chainId' },
    );
  }
  if (
    typeof value.manifestHash !== 'string' ||
    !HASH_PATTERN.test(value.manifestHash)
  ) {
    return denial(
      'INVALID_PROPOSAL',
      'Policy manifestHash must be a 32-byte hash.',
      { field: 'manifestHash' },
    );
  }
  const startsAt = isoTime(value.startsAt, 'startsAt');
  if (!startsAt.allowed) return startsAt;
  const expiresAt = isoTime(value.expiresAt, 'expiresAt');
  if (!expiresAt.allowed) return expiresAt;
  if (expiresAt.value <= startsAt.value) {
    return denial(
      'INVALID_PROPOSAL',
      'Policy expiry must be later than its start time.',
      { field: 'expiresAt' },
    );
  }
  if (typeof value.agentVisiblePrivateAmounts !== 'boolean') {
    return denial(
      'INVALID_PROPOSAL',
      'agentVisiblePrivateAmounts must be a boolean.',
      { field: 'agentVisiblePrivateAmounts' },
    );
  }
  const common = {
    wallet: value.wallet,
    chainId: value.chainId as number,
    manifestHash: value.manifestHash as HexString,
    startsAt: value.startsAt as string,
    expiresAt: value.expiresAt as string,
    agentVisiblePrivateAmounts: value.agentVisiblePrivateAmounts,
  };
  if (value.mode === 'full') {
    if (value.allowlistedEconomicSurface !== true) {
      return denial(
        'INVALID_PROPOSAL',
        'Full autonomy must explicitly retain the allowlisted economic surface.',
        { field: 'allowlistedEconomicSurface' },
      );
    }
    if (expiresAt.value - startsAt.value > MAX_FULL_POLICY_DURATION_MS) {
      return denial(
        'INVALID_PROPOSAL',
        'Full autonomy cannot last longer than 24 hours.',
        { field: 'expiresAt' },
      );
    }
    return allowed(
      normalizeProposal({
        version: AUTONOMY_POLICY_VERSION,
        ...common,
        mode: 'full',
        allowlistedEconomicSurface: true,
      }),
    );
  }
  if (value.mode !== 'bounded') {
    return denial(
      'INVALID_PROPOSAL',
      'Policy mode must be bounded or full.',
      { field: 'mode' },
    );
  }
  if (expiresAt.value - startsAt.value > MAX_BOUNDED_POLICY_DURATION_MS) {
    return denial(
      'INVALID_PROPOSAL',
      'Bounded autonomy cannot last longer than 30 days.',
      { field: 'expiresAt' },
    );
  }
  return parseBoundedProposal(value, common);
};

/**
 * Validates the exact, signer-derived economic exposure which is evaluated
 * after private inputs are materialized and before any transaction is signed.
 */
export const validatePolicyExposure = (
  value: unknown,
): AutonomyDecision<PolicyExposureV1> => {
  if (!isRecord(value)) {
    return denial('INVALID_EXPOSURE', 'Policy exposure must be an object.');
  }
  if (
    typeof value.wallet !== 'string' ||
    !ADDRESS_PATTERN.test(value.wallet)
  ) {
    return denial('INVALID_EXPOSURE', 'Exposure wallet is invalid.', {
      field: 'wallet',
    });
  }
  if (!Number.isSafeInteger(value.chainId) || (value.chainId as number) <= 0) {
    return denial('INVALID_EXPOSURE', 'Exposure chainId is invalid.', {
      field: 'chainId',
    });
  }
  if (
    typeof value.manifestHash !== 'string' ||
    !HASH_PATTERN.test(value.manifestHash)
  ) {
    return denial('INVALID_EXPOSURE', 'Exposure manifestHash is invalid.', {
      field: 'manifestHash',
    });
  }
  if (
    typeof value.operationHash !== 'string' ||
    !HASH_PATTERN.test(value.operationHash)
  ) {
    return denial('INVALID_EXPOSURE', 'Exposure operationHash is invalid.', {
      field: 'operationHash',
    });
  }
  if (
    typeof value.action !== 'string' ||
    !ACTIONS.includes(value.action as ChainWhisperActionKind)
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'Exposure action is outside the ChainWhisper economic surface.',
      { field: 'action' },
    );
  }
  if (
    value.orderType !== undefined &&
    (typeof value.orderType !== 'string' ||
      !ORDER_TYPES.has(value.orderType))
  ) {
    return denial('INVALID_EXPOSURE', 'Exposure orderType is invalid.', {
      field: 'orderType',
    });
  }
  const pairs = validatePairs(value.pairs, 'pairs', 'INVALID_EXPOSURE');
  if (!pairs.allowed) return pairs;
  if (PAIR_ACTIONS.has(value.action as ChainWhisperActionKind)) {
    if (pairs.value.length === 0 || value.orderType === undefined) {
      return denial(
        'INVALID_EXPOSURE',
        'Trade exposure requires at least one pair and an order type.',
      );
    }
  } else if (pairs.value.length > 0) {
    return denial(
      'INVALID_EXPOSURE',
      'Only trade actions may declare price pairs.',
      { field: 'pairs' },
    );
  }
  if (!Array.isArray(value.priceQuotes)) {
    return denial(
      'INVALID_EXPOSURE',
      'Exposure priceQuotes must be an array.',
      { field: 'priceQuotes' },
    );
  }
  const priceQuotePairs = validatePairs(
    value.priceQuotes,
    'priceQuotes',
    'INVALID_EXPOSURE',
  );
  if (!priceQuotePairs.allowed) return priceQuotePairs;
  const priceQuotes: AutonomyPriceQuoteV1[] = [];
  for (const [index, pair] of priceQuotePairs.value.entries()) {
    const entry = (value.priceQuotes as Record<string, unknown>[])[index]!;
    const sellAmount = exposureInteger(
      entry.sellAmount,
      `priceQuotes[${index}].sellAmount`,
    );
    if (!sellAmount.allowed) return sellAmount;
    const buyAmount = exposureInteger(
      entry.buyAmount,
      `priceQuotes[${index}].buyAmount`,
    );
    if (!buyAmount.allowed) return buyAmount;
    if (sellAmount.value === 0n || buyAmount.value === 0n) {
      return denial(
        'INVALID_EXPOSURE',
        'Price-quote amounts must be greater than zero.',
        { field: `priceQuotes[${index}]` },
      );
    }
    priceQuotes.push({
      ...pair,
      sellAmount: sellAmount.value.toString(),
      buyAmount: buyAmount.value.toString(),
    });
  }
  if (typeof value.boundedRiskComplete !== 'boolean') {
    return denial(
      'INVALID_EXPOSURE',
      'boundedRiskComplete must be a boolean.',
      { field: 'boundedRiskComplete' },
    );
  }
  const pairsSet = new Set(pairs.value.map(pairKey));
  const quotePairs = new Set(priceQuotes.map(pairKey));
  if (
    (
      value.boundedRiskComplete &&
      (
        pairsSet.size !== quotePairs.size ||
        [...pairsSet].some((key) => !quotePairs.has(key))
      )
    ) ||
    [...quotePairs].some((key) => !pairsSet.has(key))
  ) {
    return denial(
      'INVALID_EXPOSURE',
      value.boundedRiskComplete
        ? 'Every bounded-compatible trade pair requires exactly one signer-derived price quote.'
        : 'Exposure price quotes must belong to a declared trade pair.',
      { field: 'priceQuotes' },
    );
  }
  const grossSpend = validateAmounts(
    value.grossSpend,
    'grossSpend',
    'INVALID_EXPOSURE',
  );
  if (!grossSpend.allowed) return grossSpend;
  const minimumReceive = validateAmounts(
    value.minimumReceive,
    'minimumReceive',
    'INVALID_EXPOSURE',
  );
  if (!minimumReceive.allowed) return minimumReceive;
  const action = value.action as ChainWhisperActionKind;
  const recurringEdit =
    action === 'edit' &&
    typeof value.orderType === 'string' &&
    value.orderType.startsWith('recurring.');
  const requiresPrincipalSpend =
    action === 'create_trade' ||
    action === 'create_recurring' ||
    action === 'fill' ||
    action === 'counter' ||
    action === 'privacy_bridge' ||
    (action === 'edit' && !recurringEdit);
  if (
    value.boundedRiskComplete &&
    requiresPrincipalSpend &&
    !grossSpend.value.some((entry) => BigInt(entry.amount) > 0n)
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'A bounded-compatible economic write requires exact positive principal exposure.',
      { field: 'grossSpend' },
    );
  }
  const requiresMinimumReceive =
    action === 'create_trade' ||
    action === 'fill' ||
    action === 'counter' ||
    (action === 'edit' && !recurringEdit);
  if (
    value.boundedRiskComplete &&
    requiresMinimumReceive &&
    !minimumReceive.value.some((entry) => BigInt(entry.amount) > 0n)
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'A bounded-compatible trade requires an exact positive minimum receive amount.',
      { field: 'minimumReceive' },
    );
  }
  if (
    value.counterparty !== undefined &&
    (typeof value.counterparty !== 'string' ||
      !ADDRESS_PATTERN.test(value.counterparty))
  ) {
    return denial('INVALID_EXPOSURE', 'Exposure counterparty is invalid.', {
      field: 'counterparty',
    });
  }
  if (action === 'fill' && value.counterparty === undefined) {
    return denial(
      'INVALID_EXPOSURE',
      'Fill exposure must bind the source order maker as its counterparty.',
      { field: 'counterparty' },
    );
  }
  let bridge: AutonomyBridgeScopeV1 | undefined;
  if (value.bridge !== undefined) {
    if (
      !isRecord(value.bridge) ||
      typeof value.bridge.pair !== 'string' ||
      !BRIDGE_PAIRS.has(value.bridge.pair) ||
      typeof value.bridge.direction !== 'string' ||
      !BRIDGE_DIRECTIONS.has(value.bridge.direction)
    ) {
      return denial('INVALID_EXPOSURE', 'Exposure bridge route is invalid.', {
        field: 'bridge',
      });
    }
    bridge = {
      pair: value.bridge.pair as PrivacyBridgePairId,
      direction: value.bridge.direction as PrivacyBridgeDirection,
    };
  }
  if (
    (value.action === 'privacy_bridge' && !bridge) ||
    (value.action !== 'privacy_bridge' && bridge)
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'Bridge scope must be present only for a privacy_bridge action.',
      { field: 'bridge' },
    );
  }
  if (
    !Number.isSafeInteger(value.messageCount) ||
    (value.messageCount as number) < 0
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'Exposure messageCount must be a non-negative safe integer.',
      { field: 'messageCount' },
    );
  }
  if (
    (value.action === 'send_order_message' &&
      ((value.messageCount as number) <= 0 ||
        value.counterparty === undefined)) ||
    (value.action !== 'send_order_message' &&
      (value.messageCount as number) !== 0)
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'Message count and counterparty must match the message action.',
      { field: 'messageCount' },
    );
  }
  const nativeValue = exposureInteger(value.nativeValue, 'nativeValue');
  if (!nativeValue.allowed) return nativeValue;
  const networkFee = exposureInteger(
    value.maximumNetworkFee,
    'maximumNetworkFee',
  );
  if (!networkFee.allowed) return networkFee;
  if (typeof value.agentProvidedPrivateAmounts !== 'boolean') {
    return denial(
      'INVALID_EXPOSURE',
      'agentProvidedPrivateAmounts must be a boolean.',
      { field: 'agentProvidedPrivateAmounts' },
    );
  }
  if (
    !Array.isArray(value.stepDigests) ||
    value.stepDigests.length === 0 ||
    value.stepDigests.some(
      (entry) => typeof entry !== 'string' || !HASH_PATTERN.test(entry),
    )
  ) {
    return denial(
      'INVALID_EXPOSURE',
      'Exposure requires the digest of every materialized step.',
      { field: 'stepDigests' },
    );
  }

  const normalized = normalizeExposure({
    wallet: value.wallet,
    chainId: value.chainId as number,
    manifestHash: value.manifestHash as HexString,
    operationHash: value.operationHash as HexString,
    action: value.action as ChainWhisperActionKind,
    ...(value.orderType
      ? { orderType: value.orderType as OrderClassificationIdV1 }
      : {}),
    pairs: pairs.value,
    priceQuotes,
    grossSpend: grossSpend.value,
    minimumReceive: minimumReceive.value,
    ...(value.counterparty
      ? { counterparty: value.counterparty as string }
      : {}),
    ...(bridge ? { bridge } : {}),
    messageCount: value.messageCount as number,
    nativeValue: nativeValue.value.toString(),
    maximumNetworkFee: networkFee.value.toString(),
    boundedRiskComplete: value.boundedRiskComplete,
    agentProvidedPrivateAmounts: value.agentProvidedPrivateAmounts,
    stepDigests: value.stepDigests as HexString[],
  });
  return allowed(normalized);
};

const isStringSubset = (
  candidate: readonly string[],
  original: readonly string[],
  normalize: (value: string) => string = (value) => value,
): boolean => {
  const allowedValues = new Set(original.map(normalize));
  return candidate.every((entry) => allowedValues.has(normalize(entry)));
};

const noBroaderThan = (
  original: AutonomyPolicyProposalV1,
  candidate: AutonomyPolicyProposalV1,
): boolean => {
  if (
    original.mode !== candidate.mode ||
    normalizeAddress(original.wallet) !== normalizeAddress(candidate.wallet) ||
    original.chainId !== candidate.chainId ||
    normalizeHash(original.manifestHash) !==
      normalizeHash(candidate.manifestHash) ||
    Date.parse(candidate.startsAt) < Date.parse(original.startsAt) ||
    Date.parse(candidate.expiresAt) > Date.parse(original.expiresAt) ||
    (candidate.agentVisiblePrivateAmounts &&
      !original.agentVisiblePrivateAmounts)
  ) {
    return false;
  }
  if (original.mode === 'full' || candidate.mode === 'full') {
    return original.mode === 'full' && candidate.mode === 'full';
  }
  if (
    !isStringSubset(
      candidate.scope.allowedActions,
      original.scope.allowedActions,
    ) ||
    !isStringSubset(
      candidate.scope.allowedAssets,
      original.scope.allowedAssets,
      normalizeAsset,
    ) ||
    !isStringSubset(
      candidate.scope.allowedOrderTypes,
      original.scope.allowedOrderTypes,
    ) ||
    !isStringSubset(
      candidate.scope.allowedCounterparties,
      original.scope.allowedCounterparties,
      normalizeAddress,
    ) ||
    (candidate.scope.messaging.enabled &&
      !original.scope.messaging.enabled) ||
    !isStringSubset(
      candidate.scope.messaging.counterparties,
      original.scope.messaging.counterparties,
      normalizeAddress,
    )
  ) {
    return false;
  }
  const originalPairs = new Set(original.scope.allowedPairs.map(pairKey));
  if (
    candidate.scope.allowedPairs.some(
      (pair) => !originalPairs.has(pairKey(pair)),
    )
  ) {
    return false;
  }
  const originalBridges = new Set(
    original.scope.allowedBridgeRoutes.map(bridgeKey),
  );
  if (
    candidate.scope.allowedBridgeRoutes.some(
      (route) => !originalBridges.has(bridgeKey(route)),
    )
  ) {
    return false;
  }
  const originalPerAction = mapAmounts(original.limits.perActionSpend);
  const originalCumulative = mapAmounts(original.limits.cumulativeSpend);
  if (
    candidate.limits.perActionSpend.some(
      (entry) =>
        !originalPerAction.has(normalizeAsset(entry.asset)) ||
        BigInt(entry.amount) >
          originalPerAction.get(normalizeAsset(entry.asset))!,
    ) ||
    candidate.limits.cumulativeSpend.some(
      (entry) =>
        !originalCumulative.has(normalizeAsset(entry.asset)) ||
        BigInt(entry.amount) >
          originalCumulative.get(normalizeAsset(entry.asset))!,
    ) ||
    BigInt(candidate.limits.maximumNativeValuePerAction) >
      BigInt(original.limits.maximumNativeValuePerAction) ||
    BigInt(candidate.limits.maximumNativeValueCumulative) >
      BigInt(original.limits.maximumNativeValueCumulative) ||
    BigInt(candidate.limits.maximumNetworkFeePerAction) >
      BigInt(original.limits.maximumNetworkFeePerAction) ||
    BigInt(candidate.limits.maximumNetworkFeeCumulative) >
      BigInt(original.limits.maximumNetworkFeeCumulative) ||
    candidate.limits.maximumActions > original.limits.maximumActions ||
    candidate.limits.maximumMessages > original.limits.maximumMessages
  ) {
    return false;
  }
  const originalBands = new Map(
    original.limits.priceBands.map((band) => [pairKey(band), band]),
  );
  return candidate.limits.priceBands.every((band) => {
    const originalBand = originalBands.get(pairKey(band));
    return Boolean(
      originalBand &&
        ratioAtLeast(
          BigInt(band.minimumBuyPerSellNumerator),
          BigInt(band.minimumBuyPerSellDenominator),
          BigInt(originalBand.minimumBuyPerSellNumerator),
          BigInt(originalBand.minimumBuyPerSellDenominator),
        ) &&
        ratioAtMost(
          BigInt(band.maximumBuyPerSellNumerator),
          BigInt(band.maximumBuyPerSellDenominator),
          BigInt(originalBand.maximumBuyPerSellNumerator),
          BigInt(originalBand.maximumBuyPerSellDenominator),
        ),
    );
  });
};

const validateStoredPolicy = (
  value: unknown,
): AutonomyDecision<ActiveAutonomyPolicyV1> => {
  if (
    !isRecord(value) ||
    typeof value.id !== 'string' ||
    !POLICY_ID_PATTERN.test(value.id) ||
    typeof value.activatedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.activatedAt)) ||
    new Date(Date.parse(value.activatedAt)).toISOString() !==
      value.activatedAt ||
    typeof value.termsDigest !== 'string' ||
    !HASH_PATTERN.test(value.termsDigest) ||
    !isRecord(value.lifecycle) ||
    !['active', 'paused', 'revoked', 'expired'].includes(
      String(value.lifecycle.state),
    ) ||
    typeof value.lifecycle.changedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.lifecycle.changedAt)) ||
    new Date(Date.parse(value.lifecycle.changedAt)).toISOString() !==
      value.lifecycle.changedAt
  ) {
    return denial(
      'STORE_TAMPERED',
      'The authenticated autonomy store contains an invalid policy record.',
    );
  }
  const {
    id,
    activatedAt,
    termsDigest,
    lifecycle,
    ...rawProposal
  } = value;
  const proposal = validateAutonomyPolicyProposal(rawProposal);
  if (!proposal.allowed) {
    return denial(
      'STORE_TAMPERED',
      'A stored autonomy policy failed validation.',
      { policyId: id as string },
    );
  }
  const policyWithoutDigest = {
    ...proposal.value,
    id: id as string,
    activatedAt: activatedAt as string,
  };
  const expectedDigest = calculatePolicyDigest(policyWithoutDigest);
  if (normalizeHash(termsDigest as string) !== expectedDigest) {
    return denial(
      'STORE_TAMPERED',
      'A stored autonomy policy no longer matches its immutable terms digest.',
      { policyId: id as string },
    );
  }
  const reason = lifecycle.reason;
  if (
    reason !== undefined &&
    !['global-pause', 'local-revocation', 'time-expired'].includes(
      String(reason),
    )
  ) {
    return denial(
      'STORE_TAMPERED',
      'A stored autonomy policy has an invalid lifecycle reason.',
      { policyId: id as string },
    );
  }
  return allowed({
    ...policyWithoutDigest,
    termsDigest: expectedDigest,
    lifecycle: {
      state: lifecycle.state as AutonomyPolicyLifecycleState,
      changedAt: lifecycle.changedAt as string,
      ...(reason ? { reason: reason as AutonomyPolicyLifecycleV1['reason'] } : {}),
    },
  } as ActiveAutonomyPolicyV1);
};

const RESERVATION_STATES = new Set<AutonomyReservationState>([
  'reserved',
  'signed',
  'pending',
  'uncertain',
  'settled',
  'released',
]);

const validateStoredReservation = (
  value: unknown,
  policies: Readonly<Record<string, ActiveAutonomyPolicyV1>>,
): AutonomyDecision<AutonomyReservationV1> => {
  if (
    !isRecord(value) ||
    value.version !== AUTONOMY_RESERVATION_VERSION ||
    typeof value.id !== 'string' ||
    !POLICY_ID_PATTERN.test(value.id) ||
    typeof value.policyId !== 'string' ||
    !POLICY_ID_PATTERN.test(value.policyId) ||
    typeof value.policyTermsDigest !== 'string' ||
    !HASH_PATTERN.test(value.policyTermsDigest) ||
    typeof value.operationHash !== 'string' ||
    !HASH_PATTERN.test(value.operationHash) ||
    typeof value.exposureDigest !== 'string' ||
    !HASH_PATTERN.test(value.exposureDigest) ||
    typeof value.authorizationBinding !== 'string' ||
    !HASH_PATTERN.test(value.authorizationBinding) ||
    typeof value.state !== 'string' ||
    !RESERVATION_STATES.has(value.state as AutonomyReservationState) ||
    typeof value.createdAt !== 'string' ||
    !Number.isFinite(Date.parse(value.createdAt)) ||
    new Date(Date.parse(value.createdAt)).toISOString() !== value.createdAt ||
    typeof value.updatedAt !== 'string' ||
    !Number.isFinite(Date.parse(value.updatedAt)) ||
    new Date(Date.parse(value.updatedAt)).toISOString() !== value.updatedAt ||
    !Array.isArray(value.signedTransactionHashes) ||
    value.signedTransactionHashes.some(
      (entry) => typeof entry !== 'string' || !HASH_PATTERN.test(entry),
    )
  ) {
    return denial(
      'STORE_TAMPERED',
      'The authenticated autonomy store contains an invalid reservation.',
    );
  }
  const policy = policies[value.policyId];
  if (
    !policy ||
    normalizeHash(value.policyTermsDigest) !== policy.termsDigest
  ) {
    return denial(
      'STORE_TAMPERED',
      'A reservation is not bound to a known immutable policy.',
      { policyId: value.policyId },
    );
  }
  const exposure = validatePolicyExposure(value.exposure);
  if (!exposure.allowed) {
    return denial(
      'STORE_TAMPERED',
      'A stored reservation contains an invalid exposure.',
      { policyId: value.policyId },
    );
  }
  const expectedExposureDigest = calculateExposureDigest(exposure.value);
  if (normalizeHash(value.exposureDigest) !== expectedExposureDigest) {
    return denial(
      'STORE_TAMPERED',
      'A stored reservation no longer matches its exposure digest.',
      { policyId: value.policyId },
    );
  }
  const expectedBinding = calculateAuthorizationBinding(
    policy,
    exposure.value,
  );
  if (normalizeHash(value.authorizationBinding) !== expectedBinding) {
    return denial(
      'STORE_TAMPERED',
      'A stored reservation no longer matches its authorization binding.',
      { policyId: value.policyId },
    );
  }
  const signedTransactionHashes = (
    value.signedTransactionHashes as string[]
  ).map((hash) => normalizeHash(hash) as HexString);
  if (
    ((value.state as AutonomyReservationState) === 'reserved' ||
      (value.state as AutonomyReservationState) === 'released') &&
    signedTransactionHashes.length > 0
  ) {
    return denial(
      'STORE_TAMPERED',
      'An unsigned reservation contains a transaction hash.',
      { policyId: value.policyId },
    );
  }
  if (
    !['reserved', 'released'].includes(value.state) &&
    signedTransactionHashes.length === 0
  ) {
    return denial(
      'STORE_TAMPERED',
      'A signed reservation is missing its transaction hash.',
      { policyId: value.policyId },
    );
  }
  return allowed({
    version: AUTONOMY_RESERVATION_VERSION,
    id: value.id,
    policyId: value.policyId,
    policyTermsDigest: policy.termsDigest,
    operationHash: normalizeHash(value.operationHash) as HexString,
    exposureDigest: expectedExposureDigest,
    authorizationBinding: expectedBinding,
    exposure: exposure.value,
    state: value.state as AutonomyReservationState,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    signedTransactionHashes,
  });
};

const validateSnapshot = (
  value: unknown,
  now: Date,
): AutonomyDecision<AutonomyStoreSnapshotV1> => {
  if (
    !isRecord(value) ||
    value.version !== AUTONOMY_STORE_VERSION ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 0 ||
    typeof value.globalPaused !== 'boolean' ||
    !isRecord(value.policies) ||
    !isRecord(value.reservations)
  ) {
    return denial(
      'STORE_TAMPERED',
      'The authenticated autonomy store snapshot is invalid.',
    );
  }
  const policies: Record<string, ActiveAutonomyPolicyV1> = {};
  for (const [key, rawPolicy] of Object.entries(value.policies)) {
    const policy = validateStoredPolicy(rawPolicy);
    if (!policy.allowed) return policy;
    if (key !== policy.value.id) {
      return denial(
        'STORE_TAMPERED',
        'A policy storage key does not match its local id.',
      );
    }
    policies[key] = policy.value;
  }
  const reservations: Record<string, AutonomyReservationV1> = {};
  const operationHashes = new Set<string>();
  for (const [key, rawReservation] of Object.entries(value.reservations)) {
    const reservation = validateStoredReservation(rawReservation, policies);
    if (!reservation.allowed) return reservation;
    if (
      key !== reservation.value.id ||
      operationHashes.has(reservation.value.operationHash)
    ) {
      return denial(
        'STORE_TAMPERED',
        'Reservation ids and operation hashes must be unique.',
      );
    }
    operationHashes.add(reservation.value.operationHash);
    reservations[key] = reservation.value;
  }
  const timestamp = now.toISOString();
  for (const [id, policy] of Object.entries(policies)) {
    if (
      policy.lifecycle.state !== 'revoked' &&
      policy.lifecycle.state !== 'expired' &&
      Date.parse(policy.expiresAt) <= now.getTime()
    ) {
      policies[id] = {
        ...policy,
        lifecycle: {
          state: 'expired',
          changedAt: timestamp,
          reason: 'time-expired',
        },
      };
    }
  }
  return allowed({
    version: AUTONOMY_STORE_VERSION,
    revision: value.revision as number,
    globalPaused: value.globalPaused,
    policies,
    reservations,
  });
};

const amountRemaining = (
  maximum: bigint,
  used: bigint,
): string => (maximum > used ? maximum - used : 0n).toString();

const remainingBudget = (
  policy: ActiveAutonomyPolicyV1,
  reservations: readonly AutonomyReservationV1[],
): AutonomyRemainingBudgetV1 | null => {
  if (policy.mode === 'full') return null;
  const spend = sumAmounts(reservations, (entry) => entry.exposure.grossSpend);
  const cumulative = mapAmounts(policy.limits.cumulativeSpend);
  const nativeUsed = reservations.reduce(
    (total, entry) => total + BigInt(entry.exposure.nativeValue),
    0n,
  );
  const feeUsed = reservations.reduce(
    (total, entry) => total + BigInt(entry.exposure.maximumNetworkFee),
    0n,
  );
  const messagesUsed = reservations.reduce(
    (total, entry) => total + entry.exposure.messageCount,
    0,
  );
  return {
    spendByAsset: [...cumulative.entries()]
      .map(([asset, maximum]) => ({
        asset,
        amount: amountRemaining(maximum, spend.get(asset) ?? 0n),
      }))
      .sort((left, right) => left.asset.localeCompare(right.asset)),
    nativeValue: amountRemaining(
      BigInt(policy.limits.maximumNativeValueCumulative),
      nativeUsed,
    ),
    networkFee: amountRemaining(
      BigInt(policy.limits.maximumNetworkFeeCumulative),
      feeUsed,
    ),
    actions: Math.max(
      0,
      policy.limits.maximumActions - reservations.length,
    ),
    messages: Math.max(
      0,
      policy.limits.maximumMessages - messagesUsed,
    ),
  };
};

type PolicyBindingV1 = {
  wallet: string;
  chainId: number;
  manifestHash: HexString;
};

const activePolicyAgainstSnapshot = (
  snapshot: AutonomyStoreSnapshotV1,
  policyId: string,
  binding: PolicyBindingV1,
  now: Date,
): AutonomyDecision<ActiveAutonomyPolicyV1> => {
  const policy = snapshot.policies[policyId];
  if (!policy) {
    return denial('POLICY_NOT_FOUND', 'Autonomy policy was not found.', {
      policyId,
    });
  }
  if (snapshot.globalPaused) {
    return denial(
      'GLOBAL_PAUSED',
      'Autonomous signing is globally paused.',
      { policyId },
    );
  }
  if (policy.lifecycle.state === 'revoked') {
    return denial('POLICY_REVOKED', 'Autonomy policy was revoked.', {
      policyId,
    });
  }
  if (
    policy.lifecycle.state === 'expired' ||
    Date.parse(policy.expiresAt) <= now.getTime()
  ) {
    return denial('POLICY_EXPIRED', 'Autonomy policy has expired.', {
      policyId,
    });
  }
  if (policy.lifecycle.state === 'paused') {
    return denial('POLICY_PAUSED', 'Autonomy policy is paused.', {
      policyId,
    });
  }
  if (Date.parse(policy.startsAt) > now.getTime()) {
    return denial(
      'POLICY_NOT_STARTED',
      'Autonomy policy has not started.',
      { policyId },
    );
  }
  if (normalizeAddress(binding.wallet) !== normalizeAddress(policy.wallet)) {
    return denial('WALLET_MISMATCH', 'Exposure wallet is outside the policy.', {
      policyId,
      field: 'wallet',
    });
  }
  if (binding.chainId !== policy.chainId) {
    return denial('CHAIN_MISMATCH', 'Exposure chain is outside the policy.', {
      policyId,
      field: 'chainId',
    });
  }
  if (
    normalizeHash(binding.manifestHash) !==
    normalizeHash(policy.manifestHash)
  ) {
    return denial(
      'MANIFEST_MISMATCH',
      'Runtime manifest changed after policy approval.',
      { policyId, field: 'manifestHash' },
    );
  }
  return allowed(policy);
};

const evaluateAgainstSnapshot = (
  snapshot: AutonomyStoreSnapshotV1,
  policyId: string,
  exposure: PolicyExposureV1,
  now: Date,
): AutonomyDecision<ActiveAutonomyPolicyV1> => {
  const active = activePolicyAgainstSnapshot(
    snapshot,
    policyId,
    exposure,
    now,
  );
  if (!active.allowed) return active;
  const policy = active.value;
  if (
    exposure.agentProvidedPrivateAmounts &&
    !policy.agentVisiblePrivateAmounts
  ) {
    return denial(
      'PRIVATE_AMOUNT_DISCLOSURE_NOT_ALLOWED',
      'agentVisiblePrivateAmounts is disabled. Enabling that policy-wide consent would let the agent both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.',
      { policyId, field: 'agentProvidedPrivateAmounts' },
    );
  }
  if (policy.mode === 'bounded' && !exposure.boundedRiskComplete) {
    return denial(
      'ECONOMIC_EXPOSURE_INCOMPLETE',
      'The signer could not derive every spend and price term required by a bounded policy.',
      { policyId, field: 'boundedRiskComplete' },
    );
  }
  if (policy.mode === 'full') {
    return allowed(policy);
  }
  if (!policy.scope.allowedActions.includes(exposure.action)) {
    return denial(
      'ACTION_NOT_ALLOWED',
      'Action is outside the bounded policy.',
      { policyId, field: 'action' },
    );
  }
  const allowedAssets = new Set(policy.scope.allowedAssets.map(normalizeAsset));
  const exposureAssets = uniqueSorted([
    ...exposure.grossSpend.map((entry) => normalizeAsset(entry.asset)),
    ...exposure.minimumReceive.map((entry) => normalizeAsset(entry.asset)),
    ...exposure.pairs.flatMap((pair) => [
      normalizeAsset(pair.sellAsset),
      normalizeAsset(pair.buyAsset),
    ]),
  ]);
  if (exposureAssets.some((asset) => !allowedAssets.has(asset))) {
    return denial(
      'ASSET_NOT_ALLOWED',
      'Exposure contains an asset outside the bounded policy.',
      { policyId, field: 'grossSpend' },
    );
  }
  const allowedPairs = new Set(policy.scope.allowedPairs.map(pairKey));
  if (exposure.pairs.some((pair) => !allowedPairs.has(pairKey(pair)))) {
    return denial('PAIR_NOT_ALLOWED', 'Trade pair is outside the policy.', {
      policyId,
      field: 'pairs',
    });
  }
  if (
    exposure.orderType &&
    !policy.scope.allowedOrderTypes.includes(exposure.orderType)
  ) {
    return denial(
      'ORDER_TYPE_NOT_ALLOWED',
      'Order type is outside the policy.',
      { policyId, field: 'orderType' },
    );
  }
  if (
    exposure.action !== 'send_order_message' &&
    exposure.counterparty &&
    !policy.scope.allowedCounterparties
      .map(normalizeAddress)
      .includes(normalizeAddress(exposure.counterparty))
  ) {
    return denial(
      'COUNTERPARTY_NOT_ALLOWED',
      'Counterparty is outside the policy.',
      { policyId, field: 'counterparty' },
    );
  }
  if (
    exposure.bridge &&
    !policy.scope.allowedBridgeRoutes
      .map(bridgeKey)
      .includes(bridgeKey(exposure.bridge))
  ) {
    return denial(
      'BRIDGE_NOT_ALLOWED',
      'Privacy bridge route is outside the policy.',
      { policyId, field: 'bridge' },
    );
  }
  if (
    exposure.action === 'send_order_message' &&
    (!policy.scope.messaging.enabled ||
      !exposure.counterparty ||
      !policy.scope.messaging.counterparties
        .map(normalizeAddress)
        .includes(normalizeAddress(exposure.counterparty)))
  ) {
    return denial(
      'MESSAGING_NOT_ALLOWED',
      'Private-message recipient is outside the policy.',
      { policyId, field: 'counterparty' },
    );
  }

  const perActionSpend = mapAmounts(policy.limits.perActionSpend);
  for (const entry of exposure.grossSpend) {
    if (
      BigInt(entry.amount) >
      (perActionSpend.get(normalizeAsset(entry.asset)) ?? -1n)
    ) {
      return denial(
        'PER_ACTION_SPEND_EXCEEDED',
        'Action exceeds its asset spend limit.',
        { policyId, field: `grossSpend.${normalizeAsset(entry.asset)}` },
      );
    }
  }
  if (
    BigInt(exposure.nativeValue) >
    BigInt(policy.limits.maximumNativeValuePerAction)
  ) {
    return denial(
      'NATIVE_VALUE_EXCEEDED',
      'Action exceeds its native-value limit.',
      { policyId, field: 'nativeValue' },
    );
  }
  if (
    BigInt(exposure.maximumNetworkFee) >
    BigInt(policy.limits.maximumNetworkFeePerAction)
  ) {
    return denial(
      'NETWORK_FEE_EXCEEDED',
      'Action exceeds its network-fee limit.',
      { policyId, field: 'maximumNetworkFee' },
    );
  }
  const priceBands = new Map(
    policy.limits.priceBands.map((band) => [pairKey(band), band]),
  );
  for (const quote of exposure.priceQuotes) {
    const band = priceBands.get(pairKey(quote));
    if (
      !band ||
      !ratioAtLeast(
        BigInt(quote.buyAmount),
        BigInt(quote.sellAmount),
        BigInt(band.minimumBuyPerSellNumerator),
        BigInt(band.minimumBuyPerSellDenominator),
      ) ||
      !ratioAtMost(
        BigInt(quote.buyAmount),
        BigInt(quote.sellAmount),
        BigInt(band.maximumBuyPerSellNumerator),
        BigInt(band.maximumBuyPerSellDenominator),
      )
    ) {
      return denial(
        'PRICE_OUT_OF_RANGE',
        'Signer-derived trade price is outside the policy band.',
        { policyId, field: `priceQuotes.${pairKey(quote)}` },
      );
    }
  }
  const reservations = activeReservationsFor(snapshot, policyId);
  const spent = sumAmounts(
    reservations,
    (reservation) => reservation.exposure.grossSpend,
  );
  const cumulativeSpend = mapAmounts(policy.limits.cumulativeSpend);
  for (const entry of exposure.grossSpend) {
    const asset = normalizeAsset(entry.asset);
    if (
      (spent.get(asset) ?? 0n) + BigInt(entry.amount) >
      (cumulativeSpend.get(asset) ?? -1n)
    ) {
      return denial(
        'CUMULATIVE_SPEND_EXCEEDED',
        'Action would exceed the cumulative asset budget.',
        { policyId, field: `grossSpend.${asset}` },
      );
    }
  }
  const nativeUsed = reservations.reduce(
    (total, reservation) =>
      total + BigInt(reservation.exposure.nativeValue),
    0n,
  );
  if (
    nativeUsed + BigInt(exposure.nativeValue) >
    BigInt(policy.limits.maximumNativeValueCumulative)
  ) {
    return denial(
      'CUMULATIVE_NATIVE_VALUE_EXCEEDED',
      'Action would exceed the cumulative native-value budget.',
      { policyId, field: 'nativeValue' },
    );
  }
  const feeUsed = reservations.reduce(
    (total, reservation) =>
      total + BigInt(reservation.exposure.maximumNetworkFee),
    0n,
  );
  if (
    feeUsed + BigInt(exposure.maximumNetworkFee) >
    BigInt(policy.limits.maximumNetworkFeeCumulative)
  ) {
    return denial(
      'CUMULATIVE_NETWORK_FEE_EXCEEDED',
      'Action would exceed the cumulative network-fee budget.',
      { policyId, field: 'maximumNetworkFee' },
    );
  }
  if (reservations.length + 1 > policy.limits.maximumActions) {
    return denial(
      'ACTION_LIMIT_EXCEEDED',
      'Action would exceed the policy action count.',
      { policyId, field: 'maximumActions' },
    );
  }
  const messagesUsed = reservations.reduce(
    (total, reservation) =>
      total + reservation.exposure.messageCount,
    0,
  );
  if (
    messagesUsed + exposure.messageCount >
    policy.limits.maximumMessages
  ) {
    return denial(
      'MESSAGE_LIMIT_EXCEEDED',
      'Action would exceed the policy message count.',
      { policyId, field: 'maximumMessages' },
    );
  }
  return allowed(policy);
};

const assetAliasesInclude = (
  aliases: readonly string[],
  reference: string,
): boolean => {
  const normalizedReference = normalizeAsset(reference);
  return aliases.some(
    (alias) => normalizeAsset(alias) === normalizedReference,
  );
};

const evaluatePrivateStateAgainstSnapshot = (
  snapshot: AutonomyStoreSnapshotV1,
  policyId: string,
  scope: PrivateStatePolicyScopeV1,
  now: Date,
): AutonomyDecision<ActiveAutonomyPolicyV1> => {
  const active = activePolicyAgainstSnapshot(
    snapshot,
    policyId,
    scope,
    now,
  );
  if (!active.allowed) return active;
  const policy = active.value;
  if (!policy.agentVisiblePrivateAmounts) {
    return denial(
      'PRIVATE_AMOUNT_DISCLOSURE_NOT_ALLOWED',
      'The policy does not allow private amounts to be returned to the agent.',
      { policyId, field: 'agentVisiblePrivateAmounts' },
    );
  }
  if (policy.mode === 'full') return allowed(policy);

  const blockedAsset = scope.assets.find(
    ({ aliases }) =>
      !policy.scope.allowedAssets.some((allowedAsset) =>
        assetAliasesInclude(aliases, allowedAsset),
      ),
  );
  if (blockedAsset) {
    return denial(
      'ASSET_NOT_ALLOWED',
      'The private-state request includes an asset outside the bounded policy.',
      { policyId, field: 'assets' },
    );
  }
  if (
    scope.orderType &&
    !policy.scope.allowedOrderTypes.includes(scope.orderType)
  ) {
    return denial(
      'ORDER_TYPE_NOT_ALLOWED',
      'The requested order type is outside the bounded policy.',
      { policyId, field: 'orderType' },
    );
  }
  if (scope.pair) {
    const pairAllowed = policy.scope.allowedPairs.some((pair) => {
      const forward =
        assetAliasesInclude(scope.pair!.firstAliases, pair.sellAsset) &&
        assetAliasesInclude(scope.pair!.secondAliases, pair.buyAsset);
      const reverse =
        scope.pair!.bidirectional &&
        assetAliasesInclude(scope.pair!.secondAliases, pair.sellAsset) &&
        assetAliasesInclude(scope.pair!.firstAliases, pair.buyAsset);
      return forward || reverse;
    });
    if (!pairAllowed) {
      return denial(
        'PAIR_NOT_ALLOWED',
        'The private-state request targets a pair outside the bounded policy.',
        { policyId, field: 'pair' },
      );
    }
  }
  const allowedCounterparties = new Set(
    policy.scope.allowedCounterparties.map(normalizeAddress),
  );
  if (
    scope.counterparties.some(
      (counterparty) =>
        !allowedCounterparties.has(normalizeAddress(counterparty)),
    )
  ) {
    return denial(
      'COUNTERPARTY_NOT_ALLOWED',
      'The private-state request includes a counterparty outside the bounded policy.',
      { policyId, field: 'allowedCounterparties' },
    );
  }
  return allowed(policy);
};

type SnapshotOperationResult<T> = {
  snapshot: AutonomyStoreSnapshotV1;
  decision: AutonomyDecision<T>;
};

const snapshotResult = <T>(
  snapshot: AutonomyStoreSnapshotV1,
  decision: AutonomyDecision<T>,
): SnapshotOperationResult<T> => ({ snapshot, decision });

const authorizeReservedWriteAgainstSnapshot = (
  snapshot: AutonomyStoreSnapshotV1,
  reservationId: string,
  now: Date,
): AutonomyDecision<AutonomyReservationV1> => {
  const reservation = snapshot.reservations[reservationId];
  if (!reservation) {
    return denial(
      'RESERVATION_NOT_FOUND',
      'Autonomy reservation was not found.',
    );
  }
  if (
    !['reserved', 'signed', 'pending', 'uncertain'].includes(
      reservation.state,
    )
  ) {
    return denial(
      'RESERVATION_STATE_INVALID',
      'Only an active, unsettled reservation can authorize a write.',
      { policyId: reservation.policyId },
    );
  }
  if (snapshot.globalPaused) {
    return denial('GLOBAL_PAUSED', 'Autonomy is globally paused.', {
      policyId: reservation.policyId,
    });
  }
  const policy = snapshot.policies[reservation.policyId];
  if (!policy) {
    return denial('POLICY_NOT_FOUND', 'Autonomy policy was not found.', {
      policyId: reservation.policyId,
    });
  }
  if (Date.parse(policy.expiresAt) <= now.getTime()) {
    return denial('POLICY_EXPIRED', 'Autonomy policy has expired.', {
      policyId: policy.id,
    });
  }
  if (Date.parse(policy.startsAt) > now.getTime()) {
    return denial(
      'POLICY_NOT_STARTED',
      'Autonomy policy has not started.',
      { policyId: policy.id },
    );
  }
  if (policy.lifecycle.state !== 'active') {
    const code =
      policy.lifecycle.state === 'revoked'
        ? 'POLICY_REVOKED'
        : policy.lifecycle.state === 'expired'
          ? 'POLICY_EXPIRED'
          : 'POLICY_PAUSED';
    return denial(code, `Autonomy policy is ${policy.lifecycle.state}.`, {
      policyId: policy.id,
    });
  }
  if (reservation.policyTermsDigest !== policy.termsDigest) {
    return denial(
      'STORE_TAMPERED',
      'Autonomy reservation no longer matches its policy.',
      { policyId: policy.id },
    );
  }
  return allowed(clone(reservation));
};

/**
 * Policy and budget authority for autonomous signer execution.
 *
 * All methods return structured decisions for policy/state failures. Storage
 * I/O or a local approval implementation failure is deliberately allowed to
 * throw: callers must fail closed and surface a secret-safe signer diagnostic.
 */
export class AutonomyPolicyManager {
  readonly #store: AuthenticatedEncryptedAutonomyStore;
  readonly #approvals: AutonomyLocalApprovalHooks;
  readonly #now: () => Date;
  readonly #idFactory: () => string;

  constructor(options: AutonomyPolicyManagerOptions) {
    if (
      options.store.protection.authenticated !== true ||
      options.store.protection.encryptedAtRest !== true ||
      options.store.protection.atomicTransactions !== true
    ) {
      throw new Error(
        'Autonomy policies require an authenticated, encrypted store with atomic transactions.',
      );
    }
    this.#store = options.store;
    this.#approvals = options.approvals;
    this.#now = options.now ?? (() => new Date());
    this.#idFactory = options.idFactory ?? randomUUID;
  }

  async #transact<T>(
    operation: (
      snapshot: AutonomyStoreSnapshotV1,
      now: Date,
    ) => SnapshotOperationResult<T>,
  ): Promise<AutonomyDecision<T>> {
    return this.#store.transact((current) => {
      // Capture time only after the serialized store boundary is acquired.
      // A transaction may have waited behind another signer operation long
      // enough for its policy to expire.
      const now = this.#now();
      const validated = validateSnapshot(current, now);
      if (!validated.allowed) {
        return { next: current, result: validated };
      }
      const outcome = operation(validated.value, now);
      return {
        next: {
          ...outcome.snapshot,
          revision: current.revision + 1,
        },
        result: clone(outcome.decision),
      };
    });
  }

  async activate(
    input: AutonomyPolicyProposalV1,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    const requested = validateAutonomyPolicyProposal(input);
    if (!requested.allowed) return requested;
    const approval = await this.#approvals.approveActivation({
      proposal: clone(requested.value),
      fullAutonomyWarnings:
        requested.value.mode === 'full'
          ? [
              'Use a dedicated, minimally funded Agent Wallet.',
              'Full autonomy is limited to the audited ChainWhisper economic surface.',
            ]
          : [],
    });
    if (!approval.approved) {
      return denial(
        'LOCAL_APPROVAL_DECLINED',
        'The local user declined autonomy activation.',
      );
    }
    const approvedProposal = validateAutonomyPolicyProposal(
      approval.proposal,
    );
    if (!approvedProposal.allowed) return approvedProposal;
    if (!noBroaderThan(requested.value, approvedProposal.value)) {
      return denial(
        'LOCAL_EDIT_BROADENED_POLICY',
        'The locally edited policy cannot broaden the agent proposal.',
      );
    }
    return this.#transact((snapshot, now) => {
      if (Date.parse(approvedProposal.value.expiresAt) <= now.getTime()) {
        return snapshotResult(
          snapshot,
          denial(
            'POLICY_EXPIRED',
            'The approved autonomy policy has already expired.',
          ),
        );
      }
      let id = '';
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const candidate = this.#idFactory();
        if (
          POLICY_ID_PATTERN.test(candidate) &&
          !snapshot.policies[candidate]
        ) {
          id = candidate;
          break;
        }
      }
      if (!id) {
        return snapshotResult(
          snapshot,
          denial(
            'STORE_TAMPERED',
            'Could not allocate a unique local policy id.',
          ),
        );
      }
      const activatedAt = now.toISOString();
      const terms = {
        ...approvedProposal.value,
        id,
        activatedAt,
      };
      const policy = {
        ...terms,
        termsDigest: calculatePolicyDigest(terms),
        lifecycle: {
          state: snapshot.globalPaused ? 'paused' : 'active',
          changedAt: activatedAt,
          ...(snapshot.globalPaused
            ? { reason: 'global-pause' as const }
            : {}),
        },
      } as ActiveAutonomyPolicyV1;
      const next = clone(snapshot);
      next.policies[id] = policy;
      return snapshotResult(next, allowed(clone(policy)));
    });
  }

  async status(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#transact((snapshot) => {
      const policies = Object.values(snapshot.policies)
        .sort((left, right) => left.activatedAt.localeCompare(right.activatedAt))
        .map((policy) => {
          const reservations = activeReservationsFor(snapshot, policy.id);
          return {
            policy: clone(policy),
            remaining: remainingBudget(policy, reservations),
          };
        });
      return snapshotResult(
        snapshot,
        allowed({
          globalPaused: snapshot.globalPaused,
          policies,
          activeReservationCount: Object.values(
            snapshot.reservations,
          ).filter((reservation) => reservation.state !== 'released').length,
        }),
      );
    });
  }

  async evaluate(
    policyId: string,
    input: PolicyExposureV1,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    const exposure = validatePolicyExposure(input);
    if (!exposure.allowed) return exposure;
    return this.#transact((snapshot, now) =>
      snapshotResult(
        snapshot,
        evaluateAgainstSnapshot(snapshot, policyId, exposure.value, now),
      ),
    );
  }

  async authorizePrivateStateDisclosure(
    policyId: string,
    scope: PrivateStatePolicyScopeV1,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    return this.#transact((snapshot, now) =>
      snapshotResult(
        snapshot,
        evaluatePrivateStateAgainstSnapshot(
          snapshot,
          policyId,
          scope,
          now,
        ),
      ),
    );
  }

  /**
   * Atomically evaluates and reserves every bounded budget. Repeating the same
   * policy/operation/exposure is idempotent; changing any bound term is denied.
   */
  async reserve(
    policyId: string,
    input: PolicyExposureV1,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    const exposure = validatePolicyExposure(input);
    if (!exposure.allowed) return exposure;
    return this.#transact((snapshot, now) => {
      const exposureDigest = calculateExposureDigest(exposure.value);
      const existing = Object.values(snapshot.reservations).find(
        (reservation) =>
          reservation.operationHash === exposure.value.operationHash,
      );
      if (existing) {
        if (
          existing.policyId === policyId &&
          existing.exposureDigest === exposureDigest &&
          existing.state !== 'released'
        ) {
          return snapshotResult(snapshot, allowed(clone(existing)));
        }
        return snapshotResult(
          snapshot,
          denial(
            existing.policyId === policyId
              ? 'OPERATION_BINDING_MISMATCH'
              : 'OPERATION_ALREADY_RESERVED',
            'Operation hash is already bound to a different autonomy authorization.',
            { policyId },
          ),
        );
      }
      const evaluated = evaluateAgainstSnapshot(
        snapshot,
        policyId,
        exposure.value,
        now,
      );
      if (!evaluated.allowed) {
        return snapshotResult(snapshot, evaluated);
      }
      let reservationId = '';
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const candidate = this.#idFactory();
        if (
          POLICY_ID_PATTERN.test(candidate) &&
          !snapshot.reservations[candidate]
        ) {
          reservationId = candidate;
          break;
        }
      }
      if (!reservationId) {
        return snapshotResult(
          snapshot,
          denial(
            'STORE_TAMPERED',
            'Could not allocate a unique reservation id.',
            { policyId },
          ),
        );
      }
      const timestamp = now.toISOString();
      const reservation: AutonomyReservationV1 = {
        version: AUTONOMY_RESERVATION_VERSION,
        id: reservationId,
        policyId,
        policyTermsDigest: evaluated.value.termsDigest,
        operationHash: exposure.value.operationHash,
        exposureDigest,
        authorizationBinding: calculateAuthorizationBinding(
          evaluated.value,
          exposure.value,
        ),
        exposure: clone(exposure.value),
        state: 'reserved',
        createdAt: timestamp,
        updatedAt: timestamp,
        signedTransactionHashes: [],
      };
      const next = clone(snapshot);
      next.reservations[reservationId] = reservation;
      return snapshotResult(next, allowed(clone(reservation)));
    });
  }

  async markSigned(
    reservationId: string,
    transactionHash: HexString,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    if (!HASH_PATTERN.test(transactionHash)) {
      return denial(
        'INVALID_EXPOSURE',
        'Signed transaction hash must be a 32-byte hash.',
        { field: 'transactionHash' },
      );
    }
    return this.#transact((snapshot, now) => {
      const reservation = snapshot.reservations[reservationId];
      if (!reservation) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_NOT_FOUND',
            'Autonomy reservation was not found.',
          ),
        );
      }
      if (
        !['reserved', 'signed', 'pending', 'uncertain'].includes(
          reservation.state,
        )
      ) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_STATE_INVALID',
            'Only an active, unsettled operation can record a signed transaction.',
            { policyId: reservation.policyId },
          ),
        );
      }
      const normalizedHash = normalizeHash(transactionHash) as HexString;
      const next = clone(snapshot);
      const updated = next.reservations[reservationId]!;
      updated.state = 'signed';
      updated.updatedAt = now.toISOString();
      if (!updated.signedTransactionHashes.includes(normalizedHash)) {
        updated.signedTransactionHashes.push(normalizedHash);
      }
      return snapshotResult(next, allowed(clone(updated)));
    });
  }

  /**
   * Holds the protected store's exclusion boundary across the final lifecycle
   * check, signature-producing callback, and signed-reservation commit.
   * Revocation and global pause therefore commit either before this check (and
   * block the callback) or after the signature has been classified as
   * authorized. Callback values remain inaccessible to the caller until the
   * signed-reservation commit succeeds. Policy expiry is evaluated after
   * acquiring the same boundary and again before prepared bytes can be
   * returned for broadcast.
   */
  async executeAuthorizedWrite<T>(
    reservationId: string,
    write: () => Promise<{
      transactionHash: HexString;
      value: T;
    }>,
  ): Promise<AutonomyDecision<AutonomySignedWriteV1<T>>> {
    let writeOutcome:
      | {
          transactionHash: HexString;
          value: T;
        }
      | undefined;
    const decision = await this.#store.transact(async (current) => {
      const now = this.#now();
      const validated = validateSnapshot(current, now);
      if (!validated.allowed) {
        return {
          next: current,
          result: {
            allowed: false as const,
            denial: validated.denial,
          },
        };
      }
      const authorized = authorizeReservedWriteAgainstSnapshot(
        validated.value,
        reservationId,
        now,
      );
      if (!authorized.allowed) {
        return {
          next: {
            ...validated.value,
            revision: current.revision + 1,
          },
          result: {
            allowed: false as const,
            denial: authorized.denial,
          },
        };
      }

      writeOutcome = await write();
      if (!HASH_PATTERN.test(writeOutcome.transactionHash)) {
        throw new Error(
          'An autonomous write returned an invalid transaction hash.',
        );
      }
      const normalizedHash = normalizeHash(
        writeOutcome.transactionHash,
      ) as HexString;
      const finalNow = this.#now();
      const finalSnapshot = validateSnapshot(validated.value, finalNow);
      if (!finalSnapshot.allowed) {
        throw new Error(
          'Autonomy state became invalid during an authorized write.',
        );
      }
      const next = clone(finalSnapshot.value);
      const updated = next.reservations[reservationId]!;
      updated.state = 'signed';
      updated.updatedAt = finalNow.toISOString();
      if (!updated.signedTransactionHashes.includes(normalizedHash)) {
        updated.signedTransactionHashes.push(normalizedHash);
      }
      const finalAuthorization = authorizeReservedWriteAgainstSnapshot(
        finalSnapshot.value,
        reservationId,
        finalNow,
      );
      if (!finalAuthorization.allowed) {
        // The callback may already have created a signature. Retain its hash
        // and consumed budget, but withhold the callback value so the caller
        // cannot proceed to a separate broadcast step.
        return {
          next: {
            ...next,
            revision: current.revision + 1,
          },
          result: {
            allowed: false as const,
            denial: finalAuthorization.denial,
          },
        };
      }
      return {
        next: {
          ...next,
          revision: current.revision + 1,
        },
        result: allowed(clone(updated)),
      };
    });

    if (!decision.allowed) return decision;
    if (!writeOutcome) {
      throw new Error('An authorized autonomy write did not execute.');
    }
    return allowed({
      reservation: decision.value,
      value: writeOutcome.value,
    });
  }

  /**
   * Rechecks the durable emergency-stop and policy lifecycle inside the shared
   * write queue, immediately before an autonomous signer can create a
   * signature or invoke an SDK write.
   */
  async authorizeReservedWrite(
    reservationId: string,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    return this.#transact((snapshot, now) =>
      snapshotResult(
        snapshot,
        authorizeReservedWriteAgainstSnapshot(
          snapshot,
          reservationId,
          now,
        ),
      ),
    );
  }

  async #transitionReservation(
    reservationId: string,
    target: 'pending' | 'uncertain' | 'settled',
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    const permitted: Record<
      'pending' | 'uncertain' | 'settled',
      readonly AutonomyReservationState[]
    > = {
      pending: ['signed', 'pending'],
      uncertain: ['signed', 'pending', 'uncertain'],
      settled: ['signed', 'pending', 'uncertain', 'settled'],
    };
    return this.#transact((snapshot, now) => {
      const reservation = snapshot.reservations[reservationId];
      if (!reservation) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_NOT_FOUND',
            'Autonomy reservation was not found.',
          ),
        );
      }
      if (!permitted[target].includes(reservation.state)) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_STATE_INVALID',
            `Reservation cannot transition from ${reservation.state} to ${target}.`,
            { policyId: reservation.policyId },
          ),
        );
      }
      const next = clone(snapshot);
      const updated = next.reservations[reservationId]!;
      updated.state = target;
      updated.updatedAt = now.toISOString();
      return snapshotResult(next, allowed(clone(updated)));
    });
  }

  async markPending(
    reservationId: string,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    return this.#transitionReservation(reservationId, 'pending');
  }

  async markUncertain(
    reservationId: string,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    return this.#transitionReservation(reservationId, 'uncertain');
  }

  async markSettled(
    reservationId: string,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    return this.#transitionReservation(reservationId, 'settled');
  }

  async settleByOperationHash(
    operationHash: HexString,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    if (!HASH_PATTERN.test(operationHash)) {
      return denial(
        'INVALID_EXPOSURE',
        'Operation hash must be a 32-byte hash.',
        { field: 'operationHash' },
      );
    }
    return this.#transact((snapshot, now) => {
      const matches = Object.values(snapshot.reservations).filter(
        (reservation) =>
          normalizeHash(reservation.operationHash) ===
          normalizeHash(operationHash),
      );
      if (matches.length !== 1) {
        return snapshotResult(
          snapshot,
          denial(
            matches.length === 0
              ? 'RESERVATION_NOT_FOUND'
              : 'STORE_TAMPERED',
            matches.length === 0
              ? 'Autonomy reservation was not found.'
              : 'Multiple autonomy reservations share one operation hash.',
          ),
        );
      }
      const reservation = matches[0]!;
      if (
        !['signed', 'pending', 'uncertain', 'settled'].includes(
          reservation.state,
        )
      ) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_STATE_INVALID',
            `Reservation cannot transition from ${reservation.state} to settled.`,
            { policyId: reservation.policyId },
          ),
        );
      }
      if (reservation.state === 'settled') {
        return snapshotResult(snapshot, allowed(clone(reservation)));
      }
      const next = clone(snapshot);
      const updated = next.reservations[reservation.id]!;
      updated.state = 'settled';
      updated.updatedAt = now.toISOString();
      return snapshotResult(next, allowed(clone(updated)));
    });
  }

  /**
   * Releases budget only while no transaction hash has ever been signed.
   * Signed, pending, uncertain, and settled operations remain consumed.
   */
  async releaseBeforeSigning(
    reservationId: string,
  ): Promise<AutonomyDecision<AutonomyReservationV1>> {
    return this.#transact((snapshot, now) => {
      const reservation = snapshot.reservations[reservationId];
      if (!reservation) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_NOT_FOUND',
            'Autonomy reservation was not found.',
          ),
        );
      }
      if (reservation.state === 'released') {
        return snapshotResult(snapshot, allowed(clone(reservation)));
      }
      if (
        reservation.state !== 'reserved' ||
        reservation.signedTransactionHashes.length > 0
      ) {
        return snapshotResult(
          snapshot,
          denial(
            'RESERVATION_STATE_INVALID',
            'Budget cannot be released after any transaction is signed.',
            { policyId: reservation.policyId },
          ),
        );
      }
      const next = clone(snapshot);
      const updated = next.reservations[reservationId]!;
      updated.state = 'released';
      updated.updatedAt = now.toISOString();
      return snapshotResult(next, allowed(clone(updated)));
    });
  }

  /** Immediate fail-closed pause; local approval is intentionally not needed. */
  async pauseGlobal(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    return this.#transact((snapshot, now) => {
      const next = clone(snapshot);
      next.globalPaused = true;
      for (const policy of Object.values(next.policies)) {
        if (policy.lifecycle.state === 'active') {
          policy.lifecycle = {
            state: 'paused',
            changedAt: now.toISOString(),
            reason: 'global-pause',
          };
        }
      }
      const statuses = Object.values(next.policies).map((policy) => ({
        policy: clone(policy),
        remaining: remainingBudget(
          policy,
          activeReservationsFor(next, policy.id),
        ),
      }));
      return snapshotResult(
        next,
        allowed({
          globalPaused: true,
          policies: statuses,
          activeReservationCount: Object.values(next.reservations).filter(
            (reservation) => reservation.state !== 'released',
          ).length,
        }),
      );
    });
  }

  async resumeGlobal(): Promise<AutonomyDecision<AutonomyStatusV1>> {
    const before = await this.status();
    if (!before.allowed) return before;
    if (!before.value.globalPaused) return before;
    const pausedPolicies = before.value.policies
      .filter((entry) => entry.policy.lifecycle.state === 'paused')
      .map((entry) => clone(entry.policy));
    const approvedBinding = autonomyResumeBinding(pausedPolicies);
    const approved = await this.#approvals.approveResume({
      policies: pausedPolicies,
    });
    if (!approved) {
      return denial(
        'LOCAL_APPROVAL_DECLINED',
        'The local user declined autonomy resume.',
      );
    }
    return this.#transact((snapshot, now) => {
      const currentPausedPolicies = Object.values(snapshot.policies).filter(
        (policy) => policy.lifecycle.state === 'paused',
      );
      if (
        !snapshot.globalPaused ||
        autonomyResumeBinding(currentPausedPolicies) !== approvedBinding
      ) {
        return snapshotResult(
          snapshot,
          denial(
            'STORE_TAMPERED',
            'Paused autonomy policies changed while resume was awaiting approval.',
          ),
        );
      }
      const next = clone(snapshot);
      next.globalPaused = false;
      for (const policy of Object.values(next.policies)) {
        if (policy.lifecycle.state === 'paused') {
          policy.lifecycle = {
            state: 'active',
            changedAt: now.toISOString(),
          };
        }
      }
      const statuses = Object.values(next.policies).map((policy) => ({
        policy: clone(policy),
        remaining: remainingBudget(
          policy,
          activeReservationsFor(next, policy.id),
        ),
      }));
      return snapshotResult(
        next,
        allowed({
          globalPaused: false,
          policies: statuses,
          activeReservationCount: Object.values(next.reservations).filter(
            (reservation) => reservation.state !== 'released',
          ).length,
        }),
      );
    });
  }

  async revoke(
    policyId: string,
  ): Promise<AutonomyDecision<ActiveAutonomyPolicyV1>> {
    const before = await this.status();
    if (!before.allowed) return before;
    const policy = before.value.policies.find(
      (entry) => entry.policy.id === policyId,
    )?.policy;
    if (!policy) {
      return denial('POLICY_NOT_FOUND', 'Autonomy policy was not found.', {
        policyId,
      });
    }
    if (policy.lifecycle.state === 'revoked') return allowed(policy);
    const approved = await this.#approvals.approveRevocation({
      policy: clone(policy),
    });
    if (!approved) {
      return denial(
        'LOCAL_APPROVAL_DECLINED',
        'The local user declined autonomy revocation.',
        { policyId },
      );
    }
    return this.#transact((snapshot, now) => {
      const current = snapshot.policies[policyId];
      if (!current) {
        return snapshotResult(
          snapshot,
          denial('POLICY_NOT_FOUND', 'Autonomy policy was not found.', {
            policyId,
          }),
        );
      }
      if (current.termsDigest !== policy.termsDigest) {
        return snapshotResult(
          snapshot,
          denial(
            'STORE_TAMPERED',
            'Autonomy policy changed while revocation was awaiting approval.',
            { policyId },
          ),
        );
      }
      if (current.lifecycle.state === 'revoked') {
        return snapshotResult(snapshot, allowed(clone(current)));
      }
      const next = clone(snapshot);
      const updated = next.policies[policyId]!;
      updated.lifecycle = {
        state: 'revoked',
        changedAt: now.toISOString(),
        reason: 'local-revocation',
      };
      return snapshotResult(next, allowed(clone(updated)));
    });
  }
}
