import { decryptUint256 } from '@coti-io/coti-sdk-typescript';
import {
  decodeEventLog,
  decodeFunctionResult,
  encodeEventTopics,
  encodeFunctionData,
  parseAbi,
  type Hex,
} from 'viem';

import {
  canonicalize,
  deriveOrderClassificationV1,
  isHexAddress,
  sha256Hex,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader,
  type OrderClassificationV1,
} from '../shared/index.js';
import type {
  AutonomyPolicyManager,
  PrivateStatePolicyScopeV1,
} from './autonomy.js';
import { ConfirmationGate } from './confirmation.js';
import { isCotiAesKey, normalizeCotiAesKey } from './cotiAes.js';
import { SignerError } from './errors.js';
import type {
  Address,
  HexString,
  PrivateOrderReceiptV1,
  PrivateStateAuthorizationV1,
  PrivateStateDisclosureDecisionV1,
  PrivateStateQueryV1,
  PrivateStateResultV1,
  WalletTransport,
} from './types.js';

const CT_UINT256_ABI =
  '(uint256 ciphertextHigh,uint256 ciphertextLow)';
const UT_UINT256_ABI =
  `(${CT_UINT256_ABI} ciphertext,${CT_UINT256_ABI} userCiphertext)`;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;
const UINT256_MAX = (1n << 256n) - 1n;
const DEFAULT_RECEIPT_LIMIT = 20;
const MAX_RECEIPT_LIMIT = 50;
const PRIVATE_VALUE_SANITY_MAX = 10n ** 48n;
const LOG_BLOCK_WINDOW = 100_000n;
const MAX_LOG_WINDOWS = 128;
const MAX_LOGS_PER_WINDOW = 256;
const PRIVATE_TOKEN_ABI = parseAbi([
  'function balanceOf(address account) view returns ((uint256 ciphertextHigh,uint256 ciphertextLow))',
]);

const PRIVATE_ORDER_ABI = parseAbi([
  'function getTrade(uint256 tradeId) view returns (address maker,address taker,uint8 status,(uint8 assetType,address token,uint256 amount) offerAsset,(uint8 assetType,address token,uint256 amount) requestAsset,uint64 createdAt,uint64 expiresAt)',
  'function getTradeMetadata(uint256 tradeId) view returns (bool isPublic,bytes32 accessHash,uint256 feePaid,bytes32 termsHash,uint8 mode,bool hasMakerRecoveryNote)',
  `function getPrivateOrderAccountSummary(uint256 tradeId,address account) view returns ((uint256 sequence,bool initialized,${UT_UINT256_ABI} remainingOfferAmount,uint256 fillReceiptTotal) summary)`,
  `event PrivateOrderFillReceipt(uint256 indexed tradeId,address indexed recipient,address indexed filler,uint256 fillIndex,${UT_UINT256_ABI} offerAmount,${UT_UINT256_ABI} requestAmount,${UT_UINT256_ABI} remainingOfferAmount)`,
]);

const RECURRING_ORDER_ABI = parseAbi([
  'function getOrderView(uint256 orderId) view returns (((address maker,address taker,uint8 status,uint8 mode,(uint8 assetType,address token) baseAsset,(uint8 assetType,address token) quoteAsset,(uint256 baseAmount,uint256 quoteAmount) buyTerms,(uint256 baseAmount,uint256 quoteAmount) sellTerms,bool isPublic,bytes32 accessHash,uint64 createdAt,uint32 executionCount,uint256 publicBaseInventory,uint256 publicQuoteInventory) order,bool buySideOpen,bool sellSideOpen,bool hasPrivateBaseInventory,bool hasPrivateQuoteInventory))',
  `function getRecurringAccountSummary(uint256 orderId,address account) view returns ((uint256 sequence,bool initialized,${UT_UINT256_ABI} baseInventory,${UT_UINT256_ABI} quoteInventory,uint256 privateFillReceiptTotal) summary)`,
  `event PrivateRecurringFillReceipt(uint256 indexed orderId,address indexed recipient,address indexed filler,uint256 fillIndex,uint8 side,${UT_UINT256_ABI} baseAmount,${UT_UINT256_ABI} quoteAmount,${UT_UINT256_ABI} remainingBaseInventory,${UT_UINT256_ABI} remainingQuoteInventory)`,
]);

type ManifestToken = ChainWhisperRuntimeManifestV1['tokens'][number] & {
  address: Address;
};

type ScopedAsset = {
  symbol: string;
  kind: ChainWhisperRuntimeManifestV1['tokens'][number]['kind'];
  decimals: number;
  address?: Address;
  aliases: string[];
};

type DisclosureScope = {
  wallet: Address;
  contract: Address;
  assets: ScopedAsset[];
  counterparties: Address[];
  pair?: {
    first: ScopedAsset;
    second: ScopedAsset;
    bidirectional: boolean;
  };
  orderType?: OrderClassificationV1;
  summary: string;
  details: Array<{ label: string; value: string }>;
};

type BalancePlan = {
  kind: 'balances';
  query: Extract<PrivateStateQueryV1, { kind: 'balances' }>;
  blockTag: Hex;
  scope: DisclosureScope;
  tokens: ManifestToken[];
};

type OneOffPlan = {
  kind: 'one-off';
  query: Extract<PrivateStateQueryV1, { kind: 'order' }>;
  blockTag: Hex;
  scope: DisclosureScope;
  orderId: bigint;
  maker: Address;
  taker: Address;
  offerAsset: ScopedAsset;
  requestAsset: ScopedAsset;
};

type RecurringPlan = {
  kind: 'recurring';
  query: Extract<PrivateStateQueryV1, { kind: 'order' }>;
  blockTag: Hex;
  scope: DisclosureScope;
  orderId: bigint;
  maker: Address;
  taker: Address;
  baseAsset: ScopedAsset;
  quoteAsset: ScopedAsset;
  executionCount: number;
};

type DisclosurePlan = BalancePlan | OneOffPlan | RecurringPlan;

type RpcLog = {
  address: Address;
  data: Hex;
  topics: Hex[];
  transactionHash: HexString;
  blockNumber: Hex;
  logIndex: Hex;
};

type Ciphertext = {
  ciphertextHigh: bigint;
  ciphertextLow: bigint;
};

type PrivateStateAutonomy = Pick<
  AutonomyPolicyManager,
  'authorizePrivateStateDisclosure'
>;
type PrivateStateDisclosureDenial = Extract<
  PrivateStateDisclosureDecisionV1,
  { allowed: false }
>;
type PrivateStateAuthorizationDecision =
  | {
      allowed: true;
      value: PrivateStateAuthorizationV1;
      policyTermsDigest?: HexString;
    }
  | PrivateStateDisclosureDenial;

type PrivateStateOptions = {
  manifest: ChainWhisperRuntimeManifestV1;
  manifestHash: HexString;
  rpc: JsonRpcReader;
  wallet: WalletTransport;
  privacyKey: () => string | null | undefined;
  confirmation: ConfirmationGate;
  autonomy?: PrivateStateAutonomy;
  assertRuntimeAttested?: () => Promise<void>;
  decrypt?: (ciphertext: Ciphertext, aesKey: string) => bigint;
};

const denied = (
  code: string,
  message: string,
  details: { policyId?: string; field?: string } = {},
): PrivateStateDisclosureDenial => ({
  allowed: false,
  denial: { code, message, ...details },
});

const normalizedAddress = (value: unknown, label: string): Address => {
  if (!isHexAddress(value)) {
    throw new SignerError(
      'STALE_STATE',
      `The live ${label} address is invalid.`,
    );
  }
  return value.toLowerCase() as Address;
};

const integerString = (value: bigint): string => value.toString();

const safeNumber = (value: unknown, label: string): number => {
  let parsed: bigint;
  try {
    parsed = BigInt(value as string | number | bigint);
  } catch {
    throw new SignerError('STALE_STATE', `The live ${label} is invalid.`);
  }
  if (parsed < 0n || parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SignerError(
      'STALE_STATE',
      `The live ${label} is outside the supported range.`,
    );
  }
  return Number(parsed);
};

const tupleField = (
  value: unknown,
  name: string,
  index: number,
): unknown => {
  if (!value || typeof value !== 'object') return undefined;
  const record = value as Record<string | number, unknown>;
  return record[name] ?? record[index];
};

const ciphertextFrom = (value: unknown): Ciphertext => {
  const userCiphertext =
    tupleField(value, 'userCiphertext', 1) ?? value;
  const high = tupleField(userCiphertext, 'ciphertextHigh', 0);
  const low = tupleField(userCiphertext, 'ciphertextLow', 1);
  try {
    return {
      ciphertextHigh: BigInt(high as string | number | bigint),
      ciphertextLow: BigInt(low as string | number | bigint),
    };
  } catch {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'A wallet-scoped private value has an invalid ciphertext.',
    );
  }
};

const operationId = (hash: HexString): string =>
  `private-state-${hash.slice(2, 18)}`;

export class PrivateStateDisclosureService {
  readonly #manifest: ChainWhisperRuntimeManifestV1;
  readonly #manifestHash: HexString;
  readonly #rpc: JsonRpcReader;
  readonly #wallet: WalletTransport;
  readonly #privacyKey: () => string | null | undefined;
  readonly #confirmation: ConfirmationGate;
  readonly #autonomy: PrivateStateAutonomy | null;
  readonly #assertRuntimeAttested: () => Promise<void>;
  readonly #decrypt: (ciphertext: Ciphertext, aesKey: string) => bigint;
  #disclosureTail: Promise<void> = Promise.resolve();

  constructor(options: PrivateStateOptions) {
    this.#manifest = options.manifest;
    this.#manifestHash = options.manifestHash;
    this.#rpc = options.rpc;
    this.#wallet = options.wallet;
    this.#privacyKey = options.privacyKey;
    this.#confirmation = options.confirmation;
    this.#autonomy = options.autonomy ?? null;
    this.#assertRuntimeAttested =
      options.assertRuntimeAttested ?? (async () => undefined);
    this.#decrypt = options.decrypt ?? decryptUint256;
  }

  async disclose(
    rawQuery: PrivateStateQueryV1,
    policyId?: string,
  ): Promise<PrivateStateDisclosureDecisionV1> {
    let release = (): void => undefined;
    const previous = this.#disclosureTail;
    this.#disclosureTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await this.#discloseOnce(rawQuery, policyId);
    } finally {
      release();
    }
  }

  async #discloseOnce(
    rawQuery: PrivateStateQueryV1,
    policyId?: string,
  ): Promise<PrivateStateDisclosureDecisionV1> {
    const query = this.#validateQuery(rawQuery);
    if (
      policyId !== undefined &&
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(policyId)
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'policyId must be one exact local autonomy policy identifier.',
      );
    }
    await this.#assertRuntimeAttested();
    const blockTag = await this.#blockTag();
    const plan = await this.#plan(query, blockTag);
    const authorization = policyId !== undefined
      ? await this.#authorizePolicy(policyId, plan.scope)
      : await this.#authorizeLocally(plan);
    if (!authorization.allowed) return authorization;
    const value = await this.#read(plan, authorization.value);
    if (policyId !== undefined) {
      const finalAuthorization = await this.#authorizePolicy(
        policyId,
        plan.scope,
      );
      if (!finalAuthorization.allowed) return finalAuthorization;
      if (
        authorization.policyTermsDigest !==
        finalAuthorization.policyTermsDigest
      ) {
        return denied(
          'POLICY_REVOKED',
          'The autonomy policy changed while private state was being read.',
          { policyId },
        );
      }
    }
    return { allowed: true, value };
  }

  #validateQuery(query: PrivateStateQueryV1): PrivateStateQueryV1 {
    if (!query || typeof query !== 'object') {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'A private-state query is required.',
      );
    }
    if (query.kind === 'balances') {
      if (
        !Array.isArray(query.assets) ||
        query.assets.length === 0 ||
        query.assets.length > 16 ||
        query.assets.some(
          (asset) =>
            typeof asset !== 'string' ||
            asset.trim().length === 0 ||
            asset.length > 128,
        )
      ) {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Choose between one and sixteen verified private assets.',
        );
      }
      const assets = [
        ...new Set(query.assets.map((asset) => asset.trim())),
      ];
      if (assets.length !== query.assets.length) {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private balance assets must be unique.',
        );
      }
      return { kind: 'balances', assets };
    }
    if (
      query.kind !== 'order' ||
      !['one-off', 'recurring'].includes(query.route)
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private state supports balances or one verified ChainWhisper order.',
      );
    }
    let orderId: bigint;
    try {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(query.orderId)) {
        throw new Error('invalid');
      }
      orderId = BigInt(query.orderId);
    } catch {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'orderId must be a canonical uint256 integer string.',
      );
    }
    if (orderId <= 0n || orderId > UINT256_MAX) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'orderId is outside the supported contract range.',
      );
    }
    if (
      query.fromBlock !== undefined &&
      (!Number.isSafeInteger(query.fromBlock) || query.fromBlock < 0)
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'fromBlock must be a non-negative safe integer.',
      );
    }
    if (
      query.receiptLimit !== undefined &&
      (!Number.isSafeInteger(query.receiptLimit) ||
        query.receiptLimit < 1 ||
        query.receiptLimit > MAX_RECEIPT_LIMIT)
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        `receiptLimit must be between 1 and ${MAX_RECEIPT_LIMIT}.`,
      );
    }
    return {
      kind: 'order',
      route: query.route,
      orderId: orderId.toString(),
      ...(query.fromBlock === undefined
        ? {}
        : { fromBlock: query.fromBlock }),
      ...(query.receiptLimit === undefined
        ? {}
        : { receiptLimit: query.receiptLimit }),
    };
  }

  async #plan(
    query: PrivateStateQueryV1,
    blockTag: Hex,
  ): Promise<DisclosurePlan> {
    const wallet = (await this.#wallet.getAddress()).toLowerCase() as Address;
    if (query.kind === 'balances') {
      const tokens = query.assets.map((asset) =>
        this.#privateToken(asset),
      );
      return {
        kind: 'balances',
        query,
        blockTag,
        tokens,
        scope: {
          wallet,
          contract:
            tokens.length === 1 ? tokens[0]!.address : ZERO_ADDRESS,
          assets: tokens.map((token) => this.#scopedToken(token)),
          counterparties: [],
          summary:
            'Reveal the selected Agent Wallet private-token balances to the connected agent once.',
          details: [
            {
              label: 'Private balances',
              value: tokens.map(({ symbol }) => symbol).join(', '),
            },
            {
              label: 'Disclosure destination',
              value: 'This connected agent only',
            },
          ],
        },
      };
    }
    return query.route === 'one-off'
      ? this.#planOneOff(query, wallet, blockTag)
      : this.#planRecurring(query, wallet, blockTag);
  }

  async #planOneOff(
    query: Extract<PrivateStateQueryV1, { kind: 'order' }>,
    wallet: Address,
    blockTag: Hex,
  ): Promise<OneOffPlan> {
    const contract = this.#contract('privateEscrow');
    const orderId = BigInt(query.orderId);
    const [tradeRaw, metadataRaw] = await Promise.all([
      this.#ethCall(
        contract,
        encodeFunctionData({
          abi: PRIVATE_ORDER_ABI,
          functionName: 'getTrade',
          args: [orderId],
        }),
        wallet,
        blockTag,
      ),
      this.#ethCall(
        contract,
        encodeFunctionData({
          abi: PRIVATE_ORDER_ABI,
          functionName: 'getTradeMetadata',
          args: [orderId],
        }),
        wallet,
        blockTag,
      ),
    ]);
    const trade = (() => {
      try {
        return decodeFunctionResult({
          abi: PRIVATE_ORDER_ABI,
          functionName: 'getTrade',
          data: tradeRaw,
        });
      } catch {
        throw new SignerError(
          'STALE_STATE',
          'The signer rejected an invalid verified order response.',
        );
      }
    })();
    const metadata = (() => {
      try {
        return decodeFunctionResult({
          abi: PRIVATE_ORDER_ABI,
          functionName: 'getTradeMetadata',
          data: metadataRaw,
        });
      } catch {
        throw new SignerError(
          'STALE_STATE',
          'The signer rejected an invalid verified order-metadata response.',
        );
      }
    })();
    const maker = normalizedAddress(trade[0], 'order maker');
    if (maker === ZERO_ADDRESS) {
      throw new SignerError('STALE_STATE', 'The private order does not exist.');
    }
    const taker = normalizedAddress(trade[1], 'order recipient');
    const offerAsset = this.#scopedAsset(trade[3]);
    const requestAsset = this.#scopedAsset(trade[4]);
    const isPublic = Boolean(metadata[0]);
    const orderType = deriveOrderClassificationV1({
      route: 'private-liquidity-escrow',
      access:
        taker !== ZERO_ADDRESS ? 'direct' : isPublic ? 'public' : 'unlisted',
      privateLiquidity: true,
      assets: [offerAsset, requestAsset],
      relation: 'primary',
    });
    return {
      kind: 'one-off',
      query,
      blockTag,
      scope: {
        wallet,
        contract,
        assets: [offerAsset, requestAsset],
        counterparties:
          taker === ZERO_ADDRESS
            ? []
            : this.#counterparties(wallet, maker, taker),
        pair: {
          first: offerAsset,
          second: requestAsset,
          bidirectional: false,
        },
        orderType,
        summary:
          'Reveal wallet-scoped hidden liquidity, progress, and private fill receipts for this ChainWhisper order once.',
        details: [
          { label: 'Order', value: `One-off #${query.orderId}` },
          { label: 'Maker', value: maker },
          ...(taker === ZERO_ADDRESS
            ? []
            : [{ label: 'Direct recipient', value: taker }]),
          {
            label: 'Pair',
            value: `${offerAsset.symbol} → ${requestAsset.symbol}`,
          },
          {
            label: 'Disclosure destination',
            value: 'This connected agent only',
          },
        ],
      },
      orderId,
      maker,
      taker,
      offerAsset,
      requestAsset,
    };
  }

  async #planRecurring(
    query: Extract<PrivateStateQueryV1, { kind: 'order' }>,
    wallet: Address,
    blockTag: Hex,
  ): Promise<RecurringPlan> {
    const contract = this.#contract('recurringEscrow');
    const orderId = BigInt(query.orderId);
    const raw = await this.#ethCall(
      contract,
      encodeFunctionData({
        abi: RECURRING_ORDER_ABI,
        functionName: 'getOrderView',
        args: [orderId],
      }),
      wallet,
      blockTag,
    );
    let view: ReturnType<typeof decodeFunctionResult>;
    try {
      view = decodeFunctionResult({
        abi: RECURRING_ORDER_ABI,
        functionName: 'getOrderView',
        data: raw,
      });
    } catch {
      throw new SignerError(
        'STALE_STATE',
        'The signer rejected an invalid verified recurring-order response.',
      );
    }
    const order = tupleField(view, 'order', 0);
    const maker = normalizedAddress(
      tupleField(order, 'maker', 0),
      'recurring order maker',
    );
    if (maker === ZERO_ADDRESS) {
      throw new SignerError(
        'STALE_STATE',
        'The recurring order does not exist.',
      );
    }
    const taker = normalizedAddress(
      tupleField(order, 'taker', 1),
      'recurring order recipient',
    );
    const mode = safeNumber(
      tupleField(order, 'mode', 3),
      'recurring order mode',
    );
    if (mode === 0) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'This recurring order has visible inventory and no wallet-scoped hidden state to disclose.',
      );
    }
    const baseAsset = this.#scopedAsset(
      tupleField(order, 'baseAsset', 4),
    );
    const quoteAsset = this.#scopedAsset(
      tupleField(order, 'quoteAsset', 5),
    );
    const isPublic = Boolean(tupleField(order, 'isPublic', 8));
    if (!isPublic || taker !== ZERO_ADDRESS) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'Private-state disclosure supports only the public-access recurring orders exposed by the ChainWhisper app.',
      );
    }
    const orderType = deriveOrderClassificationV1({
      route: 'recurring-escrow',
      access: 'public',
      privateLiquidity: true,
      assets: [baseAsset, quoteAsset],
      relation: 'primary',
    });
    return {
      kind: 'recurring',
      query,
      blockTag,
      scope: {
        wallet,
        contract,
        assets: [baseAsset, quoteAsset],
        counterparties: [],
        pair: {
          first: baseAsset,
          second: quoteAsset,
          bidirectional: true,
        },
        orderType,
        summary:
          'Reveal wallet-scoped recurring hidden inventory, progress, and private fill receipts for this ChainWhisper order once.',
        details: [
          { label: 'Order', value: `Recurring #${query.orderId}` },
          { label: 'Maker', value: maker },
          {
            label: 'Pair',
            value: `${baseAsset.symbol} / ${quoteAsset.symbol}`,
          },
          {
            label: 'Disclosure destination',
            value: 'This connected agent only',
          },
        ],
      },
      orderId,
      maker,
      taker,
      baseAsset,
      quoteAsset,
      executionCount: safeNumber(
        tupleField(order, 'executionCount', 11),
        'recurring execution count',
      ),
    };
  }

  async #authorizeLocally(
    plan: DisclosurePlan,
  ): Promise<PrivateStateAuthorizationDecision> {
    const operationHash = sha256Hex(
      canonicalize({
        domain: 'chainwhisper/private-state-disclosure/1',
        chainId: this.#manifest.network.chainId,
        manifestHash: this.#manifestHash,
        wallet: plan.scope.wallet,
        contract: plan.scope.contract,
        query: plan.query,
        orderType: plan.scope.orderType?.id ?? null,
        counterparties: plan.scope.counterparties,
        blockTag: plan.blockTag,
      }),
    );
    await this.#confirmation.confirm({
      operationId: operationId(operationHash),
      operationHash,
      stepId: 'reveal-private-chainwhisper-state',
      stepIndex: 0,
      stepCount: 1,
      wallet: plan.scope.wallet,
      contract: plan.scope.contract,
      action: 'reveal_private_chainwhisper_state',
      orderType: plan.scope.orderType ?? null,
      orderTypeLabel: plan.scope.orderType
        ? `Private state for ${plan.scope.orderType.id}`
        : 'Private Agent Wallet balances',
      assets: plan.scope.assets.map(({ symbol }) => symbol),
      amounts: [],
      details: [
        ...plan.scope.details,
        ...(plan.scope.counterparties.length === 0
          ? []
          : [
              {
                label: 'Order counterparties',
                value: plan.scope.counterparties.join(', '),
              },
            ]),
        {
          label: 'On-chain action',
          value: 'None — this only reads wallet-encrypted values',
        },
      ],
      counterparty:
        plan.scope.counterparties.length === 1
          ? plan.scope.counterparties[0]!
          : null,
      spender: null,
      fee: 'No transaction or protocol fee',
      nativeValue: '0',
      gasCap: '0',
      expectedResult:
        'The signer decrypts only this wallet-scoped request and returns it once to the connected agent. Nothing is signed or broadcast.',
      summary: plan.scope.summary,
      authorizationScope: 'complete-logical-action',
      actionButtonLabel: 'Reveal private state to agent',
      maximumNetworkFeeWei: '0',
      maximumNetworkFeeCoti: '0',
    });
    return {
      allowed: true,
      value: { mode: 'local-confirmation' },
    };
  }

  async #authorizePolicy(
    policyId: string,
    scope: DisclosureScope,
  ): Promise<PrivateStateAuthorizationDecision> {
    if (!this.#autonomy) {
      return denied(
        'POLICY_NOT_FOUND',
        'Autonomy is not available in this signer session.',
        { policyId },
      );
    }
    const policyScope: PrivateStatePolicyScopeV1 = {
      wallet: scope.wallet,
      chainId: this.#manifest.network.chainId,
      manifestHash: this.#manifestHash,
      assets: scope.assets.map(({ aliases }) => ({ aliases })),
      ...(scope.pair
        ? {
            pair: {
              firstAliases: scope.pair.first.aliases,
              secondAliases: scope.pair.second.aliases,
              bidirectional: scope.pair.bidirectional,
            },
          }
        : {}),
      ...(scope.orderType ? { orderType: scope.orderType.id } : {}),
      counterparties: scope.counterparties,
    };
    const decision =
      await this.#autonomy.authorizePrivateStateDisclosure(
        policyId,
        policyScope,
      );
    if (!decision.allowed) return decision;
    return {
      allowed: true,
      value: { mode: 'autonomy-policy', policyId },
      policyTermsDigest: decision.value.termsDigest,
    };
  }

  async #read(
    plan: DisclosurePlan,
    authorization: PrivateStateAuthorizationV1,
  ): Promise<PrivateStateResultV1> {
    const aesKey = this.#privacyKey();
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVACY_SETUP_REQUIRED',
        'Open Agent Control and enable private trading before revealing private state.',
      );
    }
    const normalizedKey = normalizeCotiAesKey(aesKey);
    if (plan.kind === 'balances') {
      const balances = await Promise.all(
        plan.tokens.map(async (token) => {
          const raw = await this.#ethCall(
            token.address,
            encodeFunctionData({
              abi: PRIVATE_TOKEN_ABI,
              functionName: 'balanceOf',
              args: [plan.scope.wallet],
            }),
            plan.scope.wallet,
            plan.blockTag,
          );
          let encrypted: unknown;
          try {
            encrypted = decodeFunctionResult({
              abi: PRIVATE_TOKEN_ABI,
              functionName: 'balanceOf',
              data: raw,
            });
          } catch {
            throw new SignerError(
              'PRIVATE_INPUT_UNAVAILABLE',
              'The signer rejected an invalid private-token balance response.',
            );
          }
          const amount = this.#decryptValue(encrypted, normalizedKey);
          return {
            symbol: token.symbol,
            token: token.address,
            decimals: token.decimals,
            amountAtomic: integerString(amount),
          };
        }),
      );
      return {
        version: 'cw.private-state/1',
        wallet: plan.scope.wallet,
        authorization,
        data: { kind: 'balances', balances },
      };
    }
    return plan.kind === 'one-off'
      ? this.#readOneOff(plan, authorization, normalizedKey)
      : this.#readRecurring(plan, authorization, normalizedKey);
  }

  async #readOneOff(
    plan: OneOffPlan,
    authorization: PrivateStateAuthorizationV1,
    aesKey: string,
  ): Promise<PrivateStateResultV1> {
    const summaryRaw = await this.#ethCall(
      plan.scope.contract,
      encodeFunctionData({
        abi: PRIVATE_ORDER_ABI,
        functionName: 'getPrivateOrderAccountSummary',
        args: [plan.orderId, plan.scope.wallet],
      }),
      plan.scope.wallet,
      plan.blockTag,
    );
    let summary: ReturnType<typeof decodeFunctionResult>;
    try {
      summary = decodeFunctionResult({
        abi: PRIVATE_ORDER_ABI,
        functionName: 'getPrivateOrderAccountSummary',
        data: summaryRaw,
      });
    } catch {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The signer rejected an invalid private order-summary response.',
      );
    }
    const initialized = Boolean(
      tupleField(summary, 'initialized', 1),
    );
    const receiptTotal = safeNumber(
      tupleField(summary, 'fillReceiptTotal', 3),
      'private fill receipt total',
    );
    const { receipts, truncated } = await this.#oneOffReceipts(
      plan,
      aesKey,
      receiptTotal,
    );
    const maker =
      plan.maker.toLowerCase() === plan.scope.wallet.toLowerCase();
    const participant =
      plan.taker.toLowerCase() === plan.scope.wallet.toLowerCase() ||
      receipts.length > 0;
    const remainingOfferAmountAtomic =
      maker && initialized
        ? integerString(
            this.#decryptValue(
              tupleField(summary, 'remainingOfferAmount', 2),
              aesKey,
            ),
          )
        : undefined;
    return {
      version: 'cw.private-state/1',
      wallet: plan.scope.wallet,
      authorization,
      data: {
        kind: 'order',
        route: 'one-off',
        orderId: plan.query.orderId,
        role: maker ? 'maker' : participant ? 'participant' : 'none',
        orderType: plan.scope.orderType!,
        offerAsset: plan.offerAsset.symbol,
        requestAsset: plan.requestAsset.symbol,
        ...(remainingOfferAmountAtomic === undefined
          ? {}
          : { remainingOfferAmountAtomic }),
        privateFillReceiptTotal: receiptTotal,
        receipts,
        receiptsTruncated: truncated,
      },
    };
  }

  async #readRecurring(
    plan: RecurringPlan,
    authorization: PrivateStateAuthorizationV1,
    aesKey: string,
  ): Promise<PrivateStateResultV1> {
    const summaryRaw = await this.#ethCall(
      plan.scope.contract,
      encodeFunctionData({
        abi: RECURRING_ORDER_ABI,
        functionName: 'getRecurringAccountSummary',
        args: [plan.orderId, plan.scope.wallet],
      }),
      plan.scope.wallet,
      plan.blockTag,
    );
    let summary: ReturnType<typeof decodeFunctionResult>;
    try {
      summary = decodeFunctionResult({
        abi: RECURRING_ORDER_ABI,
        functionName: 'getRecurringAccountSummary',
        data: summaryRaw,
      });
    } catch {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The signer rejected an invalid private recurring-summary response.',
      );
    }
    const initialized = Boolean(
      tupleField(summary, 'initialized', 1),
    );
    const receiptTotal = safeNumber(
      tupleField(summary, 'privateFillReceiptTotal', 4),
      'private recurring fill receipt total',
    );
    const { receipts, truncated } = await this.#recurringReceipts(
      plan,
      aesKey,
      receiptTotal,
    );
    const maker =
      plan.maker.toLowerCase() === plan.scope.wallet.toLowerCase();
    const participant =
      plan.taker.toLowerCase() === plan.scope.wallet.toLowerCase() ||
      receipts.length > 0;
    const privateBaseInventoryAtomic =
      maker && initialized && plan.baseAsset.kind === 'private-erc20'
        ? integerString(
            this.#decryptValue(
              tupleField(summary, 'baseInventory', 2),
              aesKey,
            ),
          )
        : undefined;
    const privateQuoteInventoryAtomic =
      maker && initialized && plan.quoteAsset.kind === 'private-erc20'
        ? integerString(
            this.#decryptValue(
              tupleField(summary, 'quoteInventory', 3),
              aesKey,
            ),
          )
        : undefined;
    return {
      version: 'cw.private-state/1',
      wallet: plan.scope.wallet,
      authorization,
      data: {
        kind: 'order',
        route: 'recurring',
        orderId: plan.query.orderId,
        role: maker ? 'maker' : participant ? 'participant' : 'none',
        orderType: plan.scope.orderType!,
        baseAsset: plan.baseAsset.symbol,
        quoteAsset: plan.quoteAsset.symbol,
        ...(privateBaseInventoryAtomic === undefined
          ? {}
          : { privateBaseInventoryAtomic }),
        ...(privateQuoteInventoryAtomic === undefined
          ? {}
          : { privateQuoteInventoryAtomic }),
        executionCount: plan.executionCount,
        privateFillReceiptTotal: receiptTotal,
        receipts,
        receiptsTruncated: truncated,
      },
    };
  }

  async #oneOffReceipts(
    plan: OneOffPlan,
    aesKey: string,
    receiptTotal: number,
  ): Promise<{ receipts: PrivateOrderReceiptV1[]; truncated: boolean }> {
    if (receiptTotal === 0) return { receipts: [], truncated: false };
    const topics = encodeEventTopics({
      abi: PRIVATE_ORDER_ABI,
      eventName: 'PrivateOrderFillReceipt',
      args: {
        tradeId: plan.orderId,
        recipient: plan.scope.wallet,
      },
    });
    const logs = await this.#logs(
      plan.scope.contract,
      topics,
      plan.query,
      plan.blockTag,
      receiptTotal,
    );
    const limit = plan.query.receiptLimit ?? DEFAULT_RECEIPT_LIMIT;
    const decodedReceipts = logs.map((log) => {
      let args: Record<string, unknown>;
      let filler: Address;
      let fillIndex: number;
      try {
        const decoded = decodeEventLog({
          abi: PRIVATE_ORDER_ABI,
          eventName: 'PrivateOrderFillReceipt',
          data: log.data,
          topics: log.topics as [Hex, ...Hex[]],
        });
        args = decoded.args as unknown as Record<string, unknown>;
        if (
          BigInt(args.tradeId as string | number | bigint) !==
            plan.orderId ||
          normalizedAddress(args.recipient, 'receipt recipient') !==
            plan.scope.wallet
        ) {
          throw new Error('receipt-scope-mismatch');
        }
        filler = normalizedAddress(
          args.filler,
          'private fill participant',
        );
        fillIndex = safeNumber(args.fillIndex, 'private fill index');
      } catch {
        throw new SignerError(
          'STALE_STATE',
          'The signer rejected an invalid wallet-scoped receipt response.',
        );
      }
      return {
        fillIndex,
        filler,
        offerAmountAtomic: integerString(
          this.#decryptValue(args.offerAmount, aesKey),
        ),
        requestAmountAtomic: integerString(
          this.#decryptValue(args.requestAmount, aesKey),
        ),
        remainingOfferAmountAtomic: integerString(
          this.#decryptValue(args.remainingOfferAmount, aesKey),
        ),
        transactionHash: log.transactionHash,
        blockNumber: safeNumber(log.blockNumber, 'receipt block number'),
      };
    });
    const unique = this.#uniqueReceipts(decodedReceipts);
    const receipts = unique.slice(-limit);
    return {
      receipts,
      truncated: receiptTotal > receipts.length,
    };
  }

  async #recurringReceipts(
    plan: RecurringPlan,
    aesKey: string,
    receiptTotal: number,
  ): Promise<{ receipts: PrivateOrderReceiptV1[]; truncated: boolean }> {
    if (receiptTotal === 0) return { receipts: [], truncated: false };
    const topics = encodeEventTopics({
      abi: RECURRING_ORDER_ABI,
      eventName: 'PrivateRecurringFillReceipt',
      args: {
        orderId: plan.orderId,
        recipient: plan.scope.wallet,
      },
    });
    const logs = await this.#logs(
      plan.scope.contract,
      topics,
      plan.query,
      plan.blockTag,
      receiptTotal,
    );
    const limit = plan.query.receiptLimit ?? DEFAULT_RECEIPT_LIMIT;
    const decodedReceipts = logs.map((log) => {
      let args: Record<string, unknown>;
      let filler: Address;
      let fillIndex: number;
      let side: 'buy' | 'sell';
      try {
        const decoded = decodeEventLog({
          abi: RECURRING_ORDER_ABI,
          eventName: 'PrivateRecurringFillReceipt',
          data: log.data,
          topics: log.topics as [Hex, ...Hex[]],
        });
        args = decoded.args as unknown as Record<string, unknown>;
        if (
          BigInt(args.orderId as string | number | bigint) !==
            plan.orderId ||
          normalizedAddress(args.recipient, 'receipt recipient') !==
            plan.scope.wallet
        ) {
          throw new Error('receipt-scope-mismatch');
        }
        filler = normalizedAddress(
          args.filler,
          'private fill participant',
        );
        fillIndex = safeNumber(args.fillIndex, 'private fill index');
        const sideValue = safeNumber(
          args.side,
          'recurring fill side',
        );
        if (sideValue !== 0 && sideValue !== 1) {
          throw new Error('invalid-receipt-side');
        }
        side = sideValue === 1 ? 'sell' : 'buy';
      } catch {
        throw new SignerError(
          'STALE_STATE',
          'The signer rejected an invalid wallet-scoped recurring receipt response.',
        );
      }
      return {
        fillIndex,
        filler,
        side,
        baseAmountAtomic: integerString(
          this.#decryptValue(args.baseAmount, aesKey),
        ),
        quoteAmountAtomic: integerString(
          this.#decryptValue(args.quoteAmount, aesKey),
        ),
        remainingBaseInventoryAtomic: integerString(
          this.#decryptValue(args.remainingBaseInventory, aesKey),
        ),
        remainingQuoteInventoryAtomic: integerString(
          this.#decryptValue(args.remainingQuoteInventory, aesKey),
        ),
        transactionHash: log.transactionHash,
        blockNumber: safeNumber(log.blockNumber, 'receipt block number'),
      };
    });
    const unique = this.#uniqueReceipts(decodedReceipts);
    const receipts = unique.slice(-limit);
    return {
      receipts,
      truncated: receiptTotal > receipts.length,
    };
  }

  #uniqueReceipts(
    receipts: PrivateOrderReceiptV1[],
  ): PrivateOrderReceiptV1[] {
    const seen = new Set<string>();
    return receipts.filter((receipt) => {
      const key = [
        receipt.transactionHash.toLowerCase(),
        receipt.fillIndex,
        receipt.filler.toLowerCase(),
        receipt.side ?? 'one-off',
      ].join(':');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  async #logs(
    contract: Address,
    topics: readonly (Hex | readonly Hex[] | null)[],
    query: Extract<PrivateStateQueryV1, { kind: 'order' }>,
    blockTag: Hex,
    receiptTotal: number,
  ): Promise<RpcLog[]> {
    const minimumBlock = BigInt(query.fromBlock ?? 0);
    const pinnedBlock = BigInt(blockTag);
    if (minimumBlock > pinnedBlock || receiptTotal === 0) return [];
    const target = Math.min(
      receiptTotal,
      query.receiptLimit ?? DEFAULT_RECEIPT_LIMIT,
    );
    const logs: RpcLog[] = [];
    const seen = new Set<string>();
    let toBlock = pinnedBlock;
    for (let window = 0; window < MAX_LOG_WINDOWS; window += 1) {
      const candidateFrom = toBlock - LOG_BLOCK_WINDOW + 1n;
      const fromBlock =
        candidateFrom > minimumBlock ? candidateFrom : minimumBlock;
      let response: unknown;
      try {
        response = await this.#rpc.request<unknown>('eth_getLogs', [
          {
            address: contract,
            fromBlock: `0x${fromBlock.toString(16)}`,
            toBlock: `0x${toBlock.toString(16)}`,
            topics,
          },
        ]);
      } catch {
        throw new SignerError(
          'STALE_STATE',
          'The signer could not read wallet-scoped receipt history. Retry with a more recent fromBlock if the RPC limits log ranges.',
        );
      }
      if (
        !Array.isArray(response) ||
        response.length > MAX_LOGS_PER_WINDOW
      ) {
        throw new SignerError(
          'STALE_STATE',
          'The signer rejected an oversized or invalid receipt-history response.',
        );
      }
      for (const item of response) {
        const log = this.#validatedLog(
          item,
          contract,
          topics,
          fromBlock,
          toBlock,
        );
        const key = `${log.transactionHash.toLowerCase()}:${log.logIndex.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          logs.push(log);
        }
      }
      if (logs.length >= target || fromBlock === minimumBlock) {
        const sorted = logs.sort((left, right) => {
          const blockDifference =
            BigInt(left.blockNumber) - BigInt(right.blockNumber);
          if (blockDifference !== 0n) {
            return blockDifference < 0n ? -1 : 1;
          }
          const indexDifference =
            BigInt(left.logIndex) - BigInt(right.logIndex);
          return indexDifference === 0n
            ? 0
            : indexDifference < 0n
              ? -1
              : 1;
        });
        return sorted.slice(-target);
      }
      toBlock = fromBlock - 1n;
    }
    throw new SignerError(
      'STALE_STATE',
      'The receipt history exceeds the bounded scan range. Retry with an order-specific fromBlock.',
    );
  }

  #validatedLog(
    value: unknown,
    contract: Address,
    filters: readonly (Hex | readonly Hex[] | null)[],
    minimumBlock: bigint,
    maximumBlock: bigint,
  ): RpcLog {
    try {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error('invalid-log');
      }
      const record = value as Record<string, unknown>;
      const address = normalizedAddress(record.address, 'receipt contract');
      const data = record.data;
      const rawTopics = record.topics;
      const transactionHash = record.transactionHash;
      const blockNumber = record.blockNumber;
      const logIndex = record.logIndex;
      if (
        address !== contract ||
        typeof data !== 'string' ||
        !/^0x(?:[0-9a-fA-F]{2})*$/u.test(data) ||
        data.length > 8_194 ||
        !Array.isArray(rawTopics) ||
        rawTopics.length === 0 ||
        rawTopics.length > 4 ||
        rawTopics.some(
          (topic) =>
            typeof topic !== 'string' ||
            !/^0x[0-9a-fA-F]{64}$/u.test(topic),
        ) ||
        typeof transactionHash !== 'string' ||
        !/^0x[0-9a-fA-F]{64}$/u.test(transactionHash) ||
        typeof blockNumber !== 'string' ||
        !/^0x[0-9a-fA-F]+$/u.test(blockNumber) ||
        typeof logIndex !== 'string' ||
        !/^0x[0-9a-fA-F]+$/u.test(logIndex)
      ) {
        throw new Error('invalid-log-fields');
      }
      const normalizedTopics = rawTopics.map(
        (topic) => topic.toLowerCase() as Hex,
      );
      for (const [index, filter] of filters.entries()) {
        if (filter === null) continue;
        const actual = normalizedTopics[index];
        const matches =
          typeof filter === 'string'
            ? actual === filter.toLowerCase()
            : filter.some(
                (candidate) =>
                  actual === candidate.toLowerCase(),
              );
        if (!matches) throw new Error('log-topic-mismatch');
      }
      const observedBlock = BigInt(blockNumber);
      if (
        observedBlock < minimumBlock ||
        observedBlock > maximumBlock
      ) {
        throw new Error('log-block-mismatch');
      }
      return {
        address,
        data: data.toLowerCase() as Hex,
        topics: normalizedTopics,
        transactionHash:
          transactionHash.toLowerCase() as HexString,
        blockNumber: blockNumber.toLowerCase() as Hex,
        logIndex: logIndex.toLowerCase() as Hex,
      };
    } catch {
      throw new SignerError(
        'STALE_STATE',
        'The signer rejected an invalid wallet-scoped receipt response.',
      );
    }
  }

  #decryptValue(value: unknown, aesKey: string): bigint {
    const ciphertext = ciphertextFrom(value);
    if (
      ciphertext.ciphertextHigh === 0n &&
      ciphertext.ciphertextLow === 0n
    ) {
      return 0n;
    }
    let amount: bigint;
    try {
      amount = this.#decrypt(ciphertext, aesKey);
    } catch {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The signer could not decrypt wallet-scoped private state with this Agent Wallet privacy key.',
      );
    }
    if (amount < 0n || amount > PRIVATE_VALUE_SANITY_MAX) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The decrypted private value failed the signer sanity check.',
      );
    }
    return amount;
  }

  #privateToken(reference: string): ManifestToken {
    const normalized = reference.trim().toLowerCase();
    const token = this.#manifest.tokens.find(
      (candidate) =>
        candidate.kind === 'private-erc20' &&
        Boolean(candidate.address) &&
        (candidate.symbol.toLowerCase() === normalized ||
          candidate.address?.toLowerCase() === normalized),
    );
    if (!token?.address) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'Only verified private tokens from the signed runtime manifest can be disclosed.',
      );
    }
    return {
      ...token,
      address: token.address.toLowerCase() as Address,
    };
  }

  #scopedToken(token: ManifestToken): ScopedAsset {
    return {
      symbol: token.symbol,
      kind: token.kind,
      decimals: token.decimals,
      address: token.address,
      aliases: [
        token.symbol.toLowerCase(),
        token.address.toLowerCase(),
      ],
    };
  }

  #scopedAsset(value: unknown): ScopedAsset {
    const assetType = safeNumber(
      tupleField(value, 'assetType', 0),
      'asset type',
    );
    const tokenAddress = normalizedAddress(
      tupleField(value, 'token', 1),
      'asset token',
    );
    if (assetType === 0) {
      return {
        symbol: 'COTI',
        kind: 'native',
        decimals: 18,
        aliases: ['native', 'coti'],
      };
    }
    if (assetType !== 1 && assetType !== 2) {
      throw new SignerError(
        'STALE_STATE',
        'The order returned an unsupported asset type.',
      );
    }
    const token = this.#manifest.tokens.find(
      (candidate) =>
        candidate.address?.toLowerCase() === tokenAddress.toLowerCase() &&
        (assetType === 2
          ? candidate.kind === 'private-erc20'
          : candidate.kind === 'erc20'),
    );
    if (!token?.address) {
      throw new SignerError(
        'UNSUPPORTED_TOOL',
        'The order contains an asset outside the verified beta runtime.',
      );
    }
    return {
      symbol: token.symbol,
      kind: token.kind,
      decimals: token.decimals,
      address: token.address.toLowerCase() as Address,
      aliases: [
        token.symbol.toLowerCase(),
        token.address.toLowerCase(),
      ],
    };
  }

  #counterparties(
    wallet: Address,
    ...addresses: Address[]
  ): Address[] {
    return [
      ...new Set(
        addresses
          .map((address) => address.toLowerCase() as Address)
          .filter(
            (address) =>
              address !== ZERO_ADDRESS &&
              address !== wallet.toLowerCase(),
          ),
      ),
    ];
  }

  #contract(name: string): Address {
    const contract = this.#manifest.contracts[name];
    if (!contract || !isHexAddress(contract.address)) {
      throw new SignerError(
        'REGISTRY_CHANGED',
        `The audited ${name} contract is unavailable.`,
      );
    }
    return contract.address.toLowerCase() as Address;
  }

  async #blockTag(): Promise<Hex> {
    try {
      const blockTag = await this.#rpc.request<unknown>(
        'eth_blockNumber',
        [],
      );
      if (
        typeof blockTag !== 'string' ||
        !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/u.test(blockTag)
      ) {
        throw new Error('invalid-block-tag');
      }
      return blockTag.toLowerCase() as Hex;
    } catch {
      throw new SignerError(
        'STALE_STATE',
        'The signer could not pin a coherent ChainWhisper read snapshot.',
      );
    }
  }

  async #ethCall(
    to: Address,
    data: Hex,
    from: Address,
    blockTag: Hex,
  ): Promise<Hex> {
    try {
      return await this.#rpc.request<Hex>('eth_call', [
        { to, from, data },
        blockTag,
      ]);
    } catch {
      throw new SignerError(
        'STALE_STATE',
        'The signer could not read the requested verified ChainWhisper state.',
      );
    }
  }
}
