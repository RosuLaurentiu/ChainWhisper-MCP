import {
  createPublicClient,
  formatUnits,
  http,
  keccak256,
  parseAbi,
  toHex,
  type Abi
} from 'viem';

import {
  HttpJsonRpcReader,
  auditRuntimeManifest,
  hashRuntimeManifest,
  loadRuntimeManifest,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader
} from '../shared/runtimeManifest.js';
import { deriveOrderClassificationV1 } from '../shared/orderClassification.js';
import { compareDecimals, divideDecimals, multiplyDecimals } from './decimal.js';
import type {
  Address,
  AssetReference,
  DomainExecutionPlan,
  DomainGateway,
  DomainIntent,
  DomainStatus,
  ListOrdersResult,
  OrderAccess,
  OrderIdentityInput,
  OrderKind,
  OrderHistoryRole,
  OrderRole,
  OrderStatus,
  RawPriceReference,
  PrivacyBridgeStatus,
  PrivacyBridgeStatusInput,
  RegistrySnapshot,
  ResolvedAsset,
  SafeOrderSummary,
  TradeSide
} from './types.js';
import { CHAINWHISPER_CHAIN_ID } from './types.js';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const ZERO_HASH = `0x${'0'.repeat(64)}`;
const CARBON_NATIVE_ADDRESS = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE';
const CARBON_MARKET_RATE_PATH = '/market-rate';
const DEFAULT_CARBON_API = 'https://api.carbondefi.xyz/v1/coti';

const STANDARD_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token, uint256 amount) offerAsset, (uint8 assetType, address token, uint256 amount) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bool isPublic, bytes32 accessHash, uint256 parentTradeId, uint256 feePaid) metadata, (uint256 remainingOfferAmount, uint256 remainingRequestAmount, uint256 filledOfferAmount, uint256 filledRequestAmount) fillState, (bool partialFillsAllowed, uint16 minPartialFillBps, uint256 minRequestAmount, uint256 maxRequestAmountPerWallet, bool oneFillPerWallet) fillPolicy, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId, uint256 rootTradeId))'
]);
const PRIVATE_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token, uint256 amount) offerAsset, (uint8 assetType, address token, uint256 amount) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bool isPublic, bytes32 accessHash, uint256 feePaid, bytes32 termsHash, uint8 mode, bool hasMakerRecoveryNote) metadata, (uint256 remainingOfferAmount, uint256 remainingRequestAmount, uint256 filledOfferAmount, uint256 filledRequestAmount) fillState, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId))'
]);
const DIRECT_READ_ABI = parseAbi([
  'function getTradeView(uint256 tradeId) view returns (((address maker, address taker, uint8 status, (uint8 assetType, address token) offerAsset, (uint8 assetType, address token) requestAsset, uint64 createdAt, uint64 expiresAt) trade, (bytes32 accessHash, uint256 parentTradeId, uint256 feePaid, bytes32 termsHash, bool hasTermsPayload, bool hasMakerAccessSecret, bool hasTakerAccessSecret, bool publicAmountCaveat) metadata, uint8 effectiveStatus, uint256 replacementTradeId, uint256 replacesTradeId, uint256 rootTradeId, bool offerAmountPrivate, bool requestAmountPrivate))',
  'function counterParentEscrow(uint256 tradeId) view returns (address)'
]);
const RECURRING_READ_ABI = parseAbi([
  'function getOrderView(uint256 orderId) view returns (((address maker, address taker, uint8 status, uint8 mode, (uint8 assetType, address token) baseAsset, (uint8 assetType, address token) quoteAsset, (uint256 baseAmount, uint256 quoteAmount) buyTerms, (uint256 baseAmount, uint256 quoteAmount) sellTerms, bool isPublic, bytes32 accessHash, uint64 createdAt, uint32 executionCount, uint256 publicBaseInventory, uint256 publicQuoteInventory) order, bool buySideOpen, bool sellSideOpen, bool hasPrivateBaseInventory, bool hasPrivateQuoteInventory))'
]);
const READER_ABI = parseAbi([
  'function getPublicDeskPage(address standardEscrow, address privateEscrow, address recurringEscrow, uint256 offset, uint256 limit, bytes32 pairKey, uint8 accessFilter) view returns ((address contractAddress, uint256 localId, uint8 kind, address maker, address taker, uint8 status, bool isPublic, bool hiddenAmount, bool hasPrivateInventory, uint256 lastActivityBlock)[] items, uint256 nextOffset)',
  'function getWalletDeskPageV2(address account, address standardEscrow, address privateEscrow, address directEscrow, address recurringEscrow, uint256 offset, uint256 limit) view returns ((address contractAddress, uint256 localId, uint8 kind, address maker, address taker, uint8 status, bool isPublic, bool hiddenAmount, bool hasPrivateInventory, uint256 lastActivityBlock)[] items, uint256 nextOffset)'
]);
const HISTORY_ABI = parseAbi([
  'function getWalletHistoryPage(address account, address registry, uint256 offset, uint256 limit) view returns ((address contractAddress, uint256 localId, uint8 kind, uint8 role, address counterparty, uint8 status, uint256 lastActivityBlock, uint256 sequence, uint8 amountVisibility)[] items, uint256 nextOffset)'
]);
const REGISTRY_ABI = parseAbi([
  'function getContracts() view returns ((address standardEscrow, address privateEscrow, address directEscrow, address recurringEscrow, address reader, address historyReader))'
]);

type ContractReadClient = {
  readContract(input: {
    address: Address;
    abi: Abi;
    functionName: string;
    args?: readonly unknown[];
  }): Promise<unknown>;
};

export type DomainExecutionPlanner = (
  intent: DomainIntent,
  status: DomainStatus
) => Promise<DomainExecutionPlan>;
export type PrivacyBridgeStatusReader = (
  input: PrivacyBridgeStatusInput
) => Promise<PrivacyBridgeStatus>;

export type LiveDomainGatewayOptions = {
  manifest?: ChainWhisperRuntimeManifestV1;
  rpc?: JsonRpcReader;
  client?: ContractReadClient;
  fetcher?: typeof fetch;
  carbonApiUrl?: string;
  executionPlanner?: DomainExecutionPlanner;
  privacyBridgeStatusReader?: PrivacyBridgeStatusReader;
  auditTtlMs?: number;
  now?: () => number;
};

type PageItem = {
  contractAddress: Address;
  localId: string;
  historyRoles?: readonly OrderHistoryRole[];
};

const field = (value: unknown, name: string, index: number): unknown => {
  if (!value || typeof value !== 'object') return undefined;
  const record = value as Record<string, unknown>;
  return record[name] ?? record[String(index)];
};

const asBigInt = (value: unknown): bigint => {
  try {
    return typeof value === 'bigint' ? value : BigInt(String(value ?? 0));
  } catch {
    return 0n;
  }
};

const asAddress = (value: unknown): Address | null => {
  const normalized = String(value ?? '').trim().toLowerCase();
  return /^0x[a-f0-9]{40}$/u.test(normalized) ? (normalized as Address) : null;
};

const asHistoryRole = (
  value: unknown
): OrderHistoryRole | null => {
  const role = Number(asBigInt(value));
  if (role === 1) return 'maker';
  if (role === 2) return 'recipient';
  if (role === 3) return 'filler';
  return null;
};

const asHash = (value: unknown): `0x${string}` | null => {
  const normalized = String(value ?? '').trim().toLowerCase();
  return /^0x[a-f0-9]{64}$/u.test(normalized)
    ? (normalized as `0x${string}`)
    : null;
};

const toIso = (seconds: unknown): string => {
  const value = Number(asBigInt(seconds));
  return Number.isSafeInteger(value) && value > 0
    ? new Date(value * 1_000).toISOString()
    : new Date(0).toISOString();
};

const mapTradeStatus = (value: unknown, expiresAt?: unknown): OrderStatus => {
  const status = Number(asBigInt(value));
  const expiry = Number(asBigInt(expiresAt));
  if (status === 1 && expiry > 0 && expiry * 1_000 <= Date.now()) return 'expired';
  if (status === 1) return 'open';
  if (status === 2) return 'filled';
  if (status === 3) return 'cancelled';
  if (status === 4) return 'declined';
  if (status === 5) return 'expired';
  return 'cancelled';
};

const mapRecurringStatus = (value: unknown): OrderStatus => {
  const status = Number(asBigInt(value));
  if (status === 1) return 'open';
  if (status === 2) return 'paused';
  return 'cancelled';
};

const ratioFromAtomic = (
  numerator: bigint,
  numeratorDecimals: number,
  denominator: bigint,
  denominatorDecimals: number
): string | null => {
  if (numerator <= 0n || denominator <= 0n) return null;
  return divideDecimals(
    formatUnits(numerator, numeratorDecimals),
    formatUnits(denominator, denominatorDecimals)
  );
};

const accessFrom = (isPublic: unknown, taker: Address | null, _accessHash: unknown): OrderAccess => {
  if (isPublic) return 'public';
  if (taker && taker !== ZERO_ADDRESS) return 'direct';
  return 'unlisted';
};

const makeHandle = (contract: Address, localId: string): string =>
  `cw_${contract.slice(2).toLowerCase()}_${localId}`;

const trimTrailingAscii = (value: string, characterCode: number): string => {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === characterCode) {
    end -= 1;
  }
  return end === value.length ? value : value.slice(0, end);
};

const trustedIdentity = (
  contract: Address,
  localId: bigint
): SafeOrderSummary['identity'] | null =>
  localId > 0n
    ? {
        escrowContract: contract.toLowerCase() as Address,
        localId: localId.toString(),
        handle: makeHandle(contract, localId.toString())
      }
    : null;

const parseHandle = (handle: string): { escrowContract: Address; localId: string } | null => {
  const match = /^cw_([a-fA-F0-9]{40})_((?:0|[1-9]\d*))$/u.exec(handle);
  return match
    ? {
        escrowContract: `0x${match[1]!.toLowerCase()}` as Address,
        localId: match[2]!
      }
    : null;
};

const numberToDecimal = (value: number): string | null => {
  if (!Number.isFinite(value) || value <= 0) return null;
  const withoutZeros = trimTrailingAscii(value.toFixed(18), 48);
  const fixed = trimTrailingAscii(withoutZeros, 46);
  return fixed && fixed !== '0' ? fixed : null;
};

export class LiveChainWhisperDomainGateway implements DomainGateway {
  readonly #manifest: ChainWhisperRuntimeManifestV1;
  readonly #rpc: JsonRpcReader;
  readonly #client: ContractReadClient;
  readonly #fetcher: typeof fetch;
  readonly #carbonApiUrl: string;
  readonly #executionPlanner?: DomainExecutionPlanner;
  readonly #privacyBridgeStatusReader?: PrivacyBridgeStatusReader;
  readonly #auditTtlMs: number;
  readonly #now: () => number;
  readonly #assetsByAddress = new Map<string, ResolvedAsset>();
  readonly #assetsBySymbol = new Map<string, ResolvedAsset>();
  #statusCache: { expiresAt: number; value: Promise<DomainStatus> } | null = null;

  constructor(options: LiveDomainGatewayOptions & { manifest: ChainWhisperRuntimeManifestV1 }) {
    this.#manifest = options.manifest;
    this.#rpc = options.rpc ?? new HttpJsonRpcReader(options.manifest.network.rpcUrl);
    this.#client =
      options.client ??
      (createPublicClient({
        chain: {
          id: CHAINWHISPER_CHAIN_ID,
          name: 'COTI Mainnet',
          nativeCurrency: { name: 'COTI', symbol: 'COTI', decimals: 18 },
          rpcUrls: {
            default: { http: [options.manifest.network.rpcUrl] }
          }
        },
        transport: http(options.manifest.network.rpcUrl)
      }) as unknown as ContractReadClient);
    this.#fetcher = options.fetcher ?? fetch;
    this.#carbonApiUrl = trimTrailingAscii(
      options.carbonApiUrl ?? DEFAULT_CARBON_API,
      47
    );
    this.#executionPlanner = options.executionPlanner;
    this.#privacyBridgeStatusReader = options.privacyBridgeStatusReader;
    this.#auditTtlMs = options.auditTtlMs ?? 60_000;
    this.#now = options.now ?? Date.now;
    this.#indexManifestAssets();
  }

  async getStatus(): Promise<DomainStatus> {
    if (this.#statusCache && this.#statusCache.expiresAt > this.#now()) {
      return this.#statusCache.value;
    }
    const value = this.#buildStatus();
    this.#statusCache = { expiresAt: this.#now() + this.#auditTtlMs, value };
    return value;
  }

  async isTrustedEscrow(address: Address): Promise<boolean> {
    const normalized = address.toLowerCase();
    return ['standardEscrow', 'privateEscrow', 'directEscrow', 'recurringEscrow'].some(
      (name) => this.#contract(name).address.toLowerCase() === normalized
    );
  }

  async resolveAsset(reference: AssetReference): Promise<ResolvedAsset | null> {
    if (typeof reference === 'string') {
      const normalized = reference.trim().toLowerCase();
      if (normalized === 'native') return this.#assetsBySymbol.get('coti') ?? null;
      return this.#assetsByAddress.get(normalized) ?? this.#assetsBySymbol.get(normalized) ?? null;
    }
    const byAddress = reference.address
      ? this.#assetsByAddress.get(reference.address.trim().toLowerCase())
      : null;
    const bySymbol = reference.symbol
      ? this.#assetsBySymbol.get(reference.symbol.trim().toLowerCase())
      : null;
    const asset = byAddress ?? bySymbol ?? null;
    if (!asset || (reference.kind && reference.kind !== asset.kind)) return null;
    return asset;
  }

  async listOrders(input: {
    wallet: Address | null;
    role: OrderRole;
    kind: OrderKind | 'all';
    status: OrderStatus | 'all';
    access: OrderAccess | 'all';
    baseAsset: ResolvedAsset | null;
    quoteAsset: ResolvedAsset | null;
    cursor: string | null;
    limit: number;
  }): Promise<ListOrdersResult> {
    const offset = /^(?:0|[1-9]\d*)$/u.test(input.cursor ?? '') ? BigInt(input.cursor!) : 0n;
    const useHistory = Boolean(
      input.wallet &&
        (input.status === 'all' || input.role === 'filler')
    );
    const page = useHistory
      ? await this.#readHistoryPage(input.wallet!, offset, input.limit)
      : await this.#readDeskPage(input.wallet, offset, input.limit);
    const unique = new Map<string, PageItem>();
    for (const item of page.items) {
      if (await this.isTrustedEscrow(item.contractAddress)) {
        const key = `${item.contractAddress}:${item.localId}`;
        const existing = unique.get(key);
        const historyRoles = [
          ...(existing?.historyRoles ?? []),
          ...(item.historyRoles ?? [])
        ].filter(
          (role, index, roles) => roles.indexOf(role) === index
        );
        unique.set(key, {
          ...(existing ?? item),
          ...(historyRoles.length ? { historyRoles } : {})
        });
      }
    }
    const orders = (
      await Promise.all(
        [...unique.values()].map(async (item) => ({
          item,
          order: await this.getOrder({
            escrowContract: item.contractAddress,
            localId: item.localId
          })
        }))
      )
    ).filter(
      (
        entry
      ): entry is { item: PageItem; order: SafeOrderSummary } =>
        Boolean(entry.order)
    );
    const filtered = orders.filter(({ item, order }) => {
      if (input.role !== 'all' && input.wallet) {
        if (item.historyRoles) {
          if (!item.historyRoles.includes(input.role)) return false;
        } else {
          const wallet = input.wallet.toLowerCase();
          if (
            input.role === 'maker' &&
            order.maker.toLowerCase() !== wallet
          ) {
            return false;
          }
          if (
            input.role === 'recipient' &&
            order.recipient?.toLowerCase() !== wallet
          ) {
            return false;
          }
          if (input.role === 'filler') return false;
        }
      }
      if (input.kind !== 'all' && order.kind !== input.kind) return false;
      if (input.status !== 'all' && order.status !== input.status) return false;
      if (input.access !== 'all' && order.access !== input.access) return false;
      const pair = order.recurring
        ? [order.recurring.baseAsset.id, order.recurring.quoteAsset.id]
        : [order.offerAsset.id, order.requestAsset.id];
      if (input.baseAsset && pair[0] !== input.baseAsset.id) return false;
      if (input.quoteAsset && pair[1] !== input.quoteAsset.id) return false;
      return true;
    });
    return {
      orders: filtered
        .slice(0, input.limit)
        .map(({ order }) => order),
      nextCursor: page.hasMore ? page.nextOffset : null,
      truncated: page.hasMore || filtered.length > input.limit
    };
  }

  async getOrder(identity: OrderIdentityInput): Promise<SafeOrderSummary | null> {
    const parsed =
      typeof identity.handle === 'string'
        ? parseHandle(identity.handle)
        : {
            escrowContract: identity.escrowContract.toLowerCase() as Address,
            localId: identity.localId
          };
    if (!parsed || !(await this.isTrustedEscrow(parsed.escrowContract))) return null;
    const localId = BigInt(parsed.localId);
    try {
      const address = parsed.escrowContract.toLowerCase();
      if (address === this.#contract('standardEscrow').address.toLowerCase()) {
        return await this.#readStandardOrder(parsed.escrowContract, localId);
      }
      if (address === this.#contract('privateEscrow').address.toLowerCase()) {
        return await this.#readPrivateOrder(parsed.escrowContract, localId);
      }
      if (address === this.#contract('directEscrow').address.toLowerCase()) {
        return await this.#readDirectOrder(parsed.escrowContract, localId);
      }
      if (address === this.#contract('recurringEscrow').address.toLowerCase()) {
        return await this.#readRecurringOrder(parsed.escrowContract, localId);
      }
    } catch {
      return null;
    }
    return null;
  }

  async getPriceReferences(input: {
    baseAsset: ResolvedAsset;
    quoteAsset: ResolvedAsset;
    side: TradeSide;
    amount: string | null;
  }): Promise<RawPriceReference[]> {
    const [forward, reverse, carbon] = await Promise.all([
      this.listOrders({
        wallet: null,
        role: 'all',
        kind: 'all',
        status: 'open',
        access: 'public',
        baseAsset: input.baseAsset,
        quoteAsset: input.quoteAsset,
        cursor: null,
        limit: 20
      }),
      this.listOrders({
        wallet: null,
        role: 'all',
        kind: 'all',
        status: 'open',
        access: 'public',
        baseAsset: input.quoteAsset,
        quoteAsset: input.baseAsset,
        cursor: null,
        limit: 20
      }),
      this.#getCarbonReference(input.baseAsset, input.quoteAsset)
    ]);
    const orders = new Map<string, SafeOrderSummary>();
    for (const order of [...forward.orders, ...reverse.orders]) {
      orders.set(order.identity.handle, order);
    }
    const references = [...orders.values()]
      .map((order) => this.#orderPriceReference(order, input))
      .filter((reference): reference is RawPriceReference => Boolean(reference));
    if (carbon) references.push(carbon);
    return references;
  }

  async buildExecutionPlan(intent: DomainIntent): Promise<DomainExecutionPlan> {
    if (!this.#executionPlanner) {
      throw new Error('chainwhisper-execution-planner-not-configured');
    }
    return this.#executionPlanner(intent, await this.getStatus());
  }

  async getPrivacyBridgeStatus(
    input: PrivacyBridgeStatusInput
  ): Promise<PrivacyBridgeStatus> {
    if (!this.#privacyBridgeStatusReader) {
      throw new Error('chainwhisper-privacy-bridge-reader-not-configured');
    }
    return this.#privacyBridgeStatusReader(input);
  }

  async #buildStatus(): Promise<DomainStatus> {
    const audit = await auditRuntimeManifest(this.#manifest, this.#rpc);
    const warnings = audit.contracts
      .filter((entry) => !entry.bytecodeMatches || !entry.selectorsMatch)
      .map((entry) => `${entry.name}: deployed bytecode or selectors do not match the manifest.`);
    let registryMatches = false;
    try {
      const raw = await this.#read(this.#manifest.registry.address as Address, REGISTRY_ABI, 'getContracts');
      const names = ['standardEscrow', 'privateEscrow', 'directEscrow', 'recurringEscrow', 'reader', 'historyReader'];
      registryMatches = names.every((name, index) => {
        const observed = asAddress(field(raw, name, index));
        return observed?.toLowerCase() === this.#contract(name).address.toLowerCase();
      });
    } catch {
      warnings.push('registry: could not verify the live registry contract set.');
    }
    if (!registryMatches && !warnings.some((warning) => warning.startsWith('registry:'))) {
      warnings.push('registry: live contract addresses do not match the committed manifest.');
    }
    const recurringWritesEnabled = audit.recurringWritesEnabled && registryMatches;
    const registry: RegistrySnapshot = {
      chainId: CHAINWHISPER_CHAIN_ID,
      registryAddress: this.#manifest.registry.address.toLowerCase() as Address,
      snapshotHash: hashRuntimeManifest(this.#manifest),
      blockNumber: audit.blockNumber ?? 'latest',
      contracts: Object.fromEntries(
        Object.entries(this.#manifest.contracts).map(([name, contract]) => [
          name,
          contract.address.toLowerCase() as Address
        ])
      ),
      recurringWritesEnabled,
      verifiedAt: audit.checkedAt,
      warnings
    };
    const ready = audit.ok && registryMatches;
    return {
      service: 'chainwhisper-mcp',
      mode: 'keyless',
      chainId: CHAINWHISPER_CHAIN_ID,
      ready,
      readOnly: !ready,
      registry,
      capabilities: {
        reads: true,
        priceReferences: true,
        unsignedPlanning: true,
        recurringWrites: recurringWritesEnabled
      }
    };
  }

  #indexManifestAssets(): void {
    const rawBySymbol = new Map(this.#manifest.tokens.map((token) => [token.symbol.toLowerCase(), token]));
    for (const token of this.#manifest.tokens) {
      const address = token.address?.toLowerCase() as Address | undefined;
      const counterpart = token.publicCounterpart
        ? rawBySymbol.get(token.publicCounterpart.toLowerCase())
        : undefined;
      const asset: ResolvedAsset = {
        id: token.kind === 'native' ? 'native:coti' : address!,
        kind: token.kind,
        symbol: token.symbol,
        decimals: token.decimals,
        address: address ?? null,
        verified: true,
        ...(counterpart
          ? {
              publicCounterpart: {
                symbol: counterpart.symbol,
                address: counterpart.address
                  ? counterpart.address.toLowerCase() as Address
                  : null
              }
            }
          : {})
      };
      this.#assetsBySymbol.set(token.symbol.toLowerCase(), asset);
      if (address) this.#assetsByAddress.set(address, asset);
    }
  }

  #contract(name: string) {
    const contract = this.#manifest.contracts[name];
    if (!contract) throw new Error(`runtime-contract-missing:${name}`);
    return contract;
  }

  #assetFromContract(raw: unknown): ResolvedAsset | null {
    const kindValue = Number(asBigInt(field(raw, 'assetType', 0)));
    if (kindValue === 0) return this.#assetsBySymbol.get('coti') ?? null;
    const address = asAddress(field(raw, 'token', 1));
    const asset = address ? this.#assetsByAddress.get(address) ?? null : null;
    if (!asset) return null;
    if (kindValue === 1 && asset.kind !== 'erc20') return null;
    if (kindValue === 2 && asset.kind !== 'private-erc20') return null;
    return asset;
  }

  async #read(address: Address, abi: Abi, functionName: string, args: readonly unknown[] = []): Promise<unknown> {
    return this.#client.readContract({ address, abi, functionName, args });
  }

  async #readDeskPage(wallet: Address | null, offset: bigint, limit: number) {
    const standard = this.#contract('standardEscrow').address as Address;
    const privateEscrow = this.#contract('privateEscrow').address as Address;
    const direct = this.#contract('directEscrow').address as Address;
    const recurring = this.#contract('recurringEscrow').address as Address;
    const reader = this.#contract('reader').address as Address;
    const raw = wallet
      ? await this.#read(reader, READER_ABI, 'getWalletDeskPageV2', [
          wallet,
          standard,
          privateEscrow,
          direct,
          recurring,
          offset,
          BigInt(limit)
        ])
      : await this.#read(reader, READER_ABI, 'getPublicDeskPage', [
          standard,
          privateEscrow,
          recurring,
          offset,
          BigInt(limit),
          ZERO_HASH,
          0
        ]);
    return this.#parsePage(raw, limit, false);
  }

  async #readHistoryPage(wallet: Address, offset: bigint, limit: number) {
    const history = this.#contract('historyReader').address as Address;
    const raw = await this.#read(history, HISTORY_ABI, 'getWalletHistoryPage', [
      wallet,
      this.#manifest.registry.address,
      offset,
      BigInt(limit)
    ]);
    return this.#parsePage(raw, limit, true);
  }

  #parsePage(
    raw: unknown,
    limit: number,
    includeHistoryRole: boolean
  ): { items: PageItem[]; nextOffset: string; hasMore: boolean } {
    const rawItems = field(raw, 'items', 0);
    const items = Array.isArray(rawItems)
      ? rawItems
          .map((item): PageItem | null => {
            const contractAddress = asAddress(field(item, 'contractAddress', 0));
            const localId = asBigInt(field(item, 'localId', 1)).toString();
            const historyRole = includeHistoryRole
              ? asHistoryRole(field(item, 'role', 3))
              : null;
            return contractAddress
              ? {
                  contractAddress,
                  localId,
                  ...(historyRole
                    ? { historyRoles: [historyRole] }
                    : {})
                }
              : null;
          })
          .filter((item): item is PageItem => Boolean(item))
      : [];
    const nextOffset = asBigInt(field(raw, 'nextOffset', 1)).toString();
    return { items, nextOffset, hasMore: items.length >= limit };
  }

  async #readStandardOrder(contract: Address, id: bigint): Promise<SafeOrderSummary | null> {
    const raw = await this.#read(contract, STANDARD_READ_ABI, 'getTradeView', [id]);
    const trade = field(raw, 'trade', 0);
    const metadata = field(raw, 'metadata', 1);
    const fillState = field(raw, 'fillState', 2);
    const policy = field(raw, 'fillPolicy', 3);
    const offerAsset = this.#assetFromContract(field(trade, 'offerAsset', 3));
    const requestAsset = this.#assetFromContract(field(trade, 'requestAsset', 4));
    const maker = asAddress(field(trade, 'maker', 0));
    const taker = asAddress(field(trade, 'taker', 1));
    if (!offerAsset || !requestAsset || !maker) return null;
    const offerAtomic = asBigInt(field(trade, 'offerAsset', 3) && field(field(trade, 'offerAsset', 3), 'amount', 2));
    const requestAtomic = asBigInt(field(field(trade, 'requestAsset', 4), 'amount', 2));
    const remainingOffer = asBigInt(field(fillState, 'remainingOfferAmount', 0));
    const remainingRequest = asBigInt(field(fillState, 'remainingRequestAmount', 1));
    const expiresAtRaw = field(trade, 'expiresAt', 6);
    const parentId = asBigInt(field(metadata, 'parentTradeId', 2));
    const replacementId = asBigInt(field(raw, 'replacementTradeId', 5));
    const replacesId = asBigInt(field(raw, 'replacesTradeId', 6));
    const rootId = asBigInt(field(raw, 'rootTradeId', 7));
    const access = accessFrom(
      field(metadata, 'isPublic', 0),
      taker,
      field(metadata, 'accessHash', 1)
    );
    return this.#finalizeOrder({
      contract,
      id,
      kind: 'trade',
      status: mapTradeStatus(field(raw, 'effectiveStatus', 4), expiresAtRaw),
      maker,
      recipient: taker && taker !== ZERO_ADDRESS ? taker : null,
      access,
      ...(access === 'direct'
        ? {
            legacyCompatibility: {
              kind: 'standard-recipient-bound' as const,
              displayType:
                'Legacy one-off / fixed recipient / public terms' as const,
              canonicalReplacementType: 'one-off.direct' as const
            }
          }
        : {}),
      amountVisibility: 'visible',
      offerAsset,
      requestAsset,
      offerAmount: formatUnits(offerAtomic, offerAsset.decimals),
      requestAmount: formatUnits(requestAtomic, requestAsset.decimals),
      remainingOfferAmount: formatUnits(remainingOffer, offerAsset.decimals),
      remainingRequestAmount: formatUnits(remainingRequest, requestAsset.decimals),
      price: ratioFromAtomic(requestAtomic, requestAsset.decimals, offerAtomic, offerAsset.decimals),
      expiresAt: asBigInt(expiresAtRaw) > 0n ? toIso(expiresAtRaw) : null,
      updatedAt: toIso(field(trade, 'createdAt', 5)),
      relation: {
        kind:
          replacesId > 0n
            ? 'replacement'
            : parentId > 0n
              ? 'counter'
              : 'primary',
        parentOrder:
          replacesId > 0n
            ? null
            : trustedIdentity(contract, parentId),
        rootOrder:
          rootId > 0n && rootId !== id
            ? trustedIdentity(contract, rootId)
            : null,
        replacesOrder: trustedIdentity(contract, replacesId),
        replacementOrder: trustedIdentity(contract, replacementId)
      },
      fillPolicy: {
        partialFillsAllowed: Boolean(
          field(policy, 'partialFillsAllowed', 0)
        ),
        minPartialFillBps: Number(
          asBigInt(field(policy, 'minPartialFillBps', 1))
        ),
        minRequestAmount: formatUnits(
          asBigInt(field(policy, 'minRequestAmount', 2)),
          requestAsset.decimals
        ),
        maxRequestAmountPerWallet: formatUnits(
          asBigInt(field(policy, 'maxRequestAmountPerWallet', 3)),
          requestAsset.decimals
        ),
        oneFillPerWallet: Boolean(field(policy, 'oneFillPerWallet', 4))
      }
    });
  }

  async #readPrivateOrder(contract: Address, id: bigint): Promise<SafeOrderSummary | null> {
    const raw = await this.#read(contract, PRIVATE_READ_ABI, 'getTradeView', [id]);
    const trade = field(raw, 'trade', 0);
    const metadata = field(raw, 'metadata', 1);
    const offerAsset = this.#assetFromContract(field(trade, 'offerAsset', 3));
    const requestAsset = this.#assetFromContract(field(trade, 'requestAsset', 4));
    const maker = asAddress(field(trade, 'maker', 0));
    const taker = asAddress(field(trade, 'taker', 1));
    if (!offerAsset || !requestAsset || !maker) return null;
    const expiresAtRaw = field(trade, 'expiresAt', 6);
    const replacementId = asBigInt(field(raw, 'replacementTradeId', 4));
    const replacesId = asBigInt(field(raw, 'replacesTradeId', 5));
    return this.#finalizeOrder({
      contract,
      id,
      kind: 'trade',
      status: mapTradeStatus(field(raw, 'effectiveStatus', 3), expiresAtRaw),
      maker,
      recipient: taker && taker !== ZERO_ADDRESS ? taker : null,
      access: accessFrom(field(metadata, 'isPublic', 0), taker, field(metadata, 'accessHash', 1)),
      amountVisibility: 'private',
      offerAsset,
      requestAsset,
      offerAmount: null,
      requestAmount: null,
      remainingOfferAmount: null,
      remainingRequestAmount: null,
      price: null,
      expiresAt: asBigInt(expiresAtRaw) > 0n ? toIso(expiresAtRaw) : null,
      updatedAt: toIso(field(trade, 'createdAt', 5)),
      relation: {
        kind: replacesId > 0n ? 'replacement' : 'primary',
        parentOrder: null,
        rootOrder: null,
        replacesOrder: trustedIdentity(contract, replacesId),
        replacementOrder: trustedIdentity(contract, replacementId)
      }
    });
  }

  async #readDirectOrder(contract: Address, id: bigint): Promise<SafeOrderSummary | null> {
    const raw = await this.#read(contract, DIRECT_READ_ABI, 'getTradeView', [id]);
    const trade = field(raw, 'trade', 0);
    const metadata = field(raw, 'metadata', 1);
    const offerAsset = this.#assetFromContract(field(trade, 'offerAsset', 3));
    const requestAsset = this.#assetFromContract(field(trade, 'requestAsset', 4));
    const maker = asAddress(field(trade, 'maker', 0));
    const taker = asAddress(field(trade, 'taker', 1));
    if (!offerAsset || !requestAsset || !maker) return null;
    const expiresAtRaw = field(trade, 'expiresAt', 6);
    const parentId = asBigInt(field(metadata, 'parentTradeId', 1));
    const parentEscrow =
      parentId > 0n
        ? asAddress(
            await this.#read(
              contract,
              DIRECT_READ_ABI,
              'counterParentEscrow',
              [id]
            )
          ) ?? contract
        : null;
    const replacementId = asBigInt(field(raw, 'replacementTradeId', 3));
    const replacesId = asBigInt(field(raw, 'replacesTradeId', 4));
    const rootId = asBigInt(field(raw, 'rootTradeId', 5));
    const recipient = taker && taker !== ZERO_ADDRESS ? taker : null;
    return this.#finalizeOrder({
      contract,
      id,
      kind: 'trade',
      status: mapTradeStatus(field(raw, 'effectiveStatus', 2), expiresAtRaw),
      maker,
      recipient,
      access: recipient ? 'direct' : 'unlisted',
      // Direct terms are participant-encrypted. This is distinct from the
      // private-liquidity escrow's hidden-liquidity mode.
      amountVisibility: 'visible',
      offerAsset,
      requestAsset,
      // Direct terms are encrypted even when their token amounts are public.
      offerAmount: null,
      requestAmount: null,
      remainingOfferAmount: null,
      remainingRequestAmount: null,
      price: null,
      expiresAt: asBigInt(expiresAtRaw) > 0n ? toIso(expiresAtRaw) : null,
      updatedAt: toIso(field(trade, 'createdAt', 5)),
      relation: {
        kind: parentId > 0n ? 'counter' : replacesId > 0n ? 'replacement' : 'primary',
        parentOrder:
          parentEscrow && parentId > 0n
            ? trustedIdentity(parentEscrow, parentId)
            : null,
        rootOrder:
          rootId > 0n && rootId !== id
            ? trustedIdentity(contract, rootId)
            : null,
        replacesOrder: trustedIdentity(contract, replacesId),
        replacementOrder: trustedIdentity(contract, replacementId)
      },
      directTerms: {
        termsHash: asHash(field(metadata, 'termsHash', 3)),
        hasTermsPayload: Boolean(field(metadata, 'hasTermsPayload', 4)),
        hasMakerAccessSecret: Boolean(
          field(metadata, 'hasMakerAccessSecret', 5)
        ),
        hasTakerAccessSecret: Boolean(
          field(metadata, 'hasTakerAccessSecret', 6)
        ),
        offerAmountPrivate: Boolean(field(raw, 'offerAmountPrivate', 6)),
        requestAmountPrivate: Boolean(field(raw, 'requestAmountPrivate', 7))
      }
    });
  }

  async #readRecurringOrder(contract: Address, id: bigint): Promise<SafeOrderSummary | null> {
    const raw = await this.#read(contract, RECURRING_READ_ABI, 'getOrderView', [id]);
    const order = field(raw, 'order', 0);
    const baseAsset = this.#assetFromContract(field(order, 'baseAsset', 4));
    const quoteAsset = this.#assetFromContract(field(order, 'quoteAsset', 5));
    const maker = asAddress(field(order, 'maker', 0));
    const taker = asAddress(field(order, 'taker', 1));
    if (!baseAsset || !quoteAsset || !maker) return null;
    const buyTerms = field(order, 'buyTerms', 6);
    const sellTerms = field(order, 'sellTerms', 7);
    const buyBase = asBigInt(field(buyTerms, 'baseAmount', 0));
    const buyQuote = asBigInt(field(buyTerms, 'quoteAmount', 1));
    const sellBase = asBigInt(field(sellTerms, 'baseAmount', 0));
    const sellQuote = asBigInt(field(sellTerms, 'quoteAmount', 1));
    const hidden = Number(asBigInt(field(order, 'mode', 3))) !== 0;
    const hasPrivateBase = Boolean(field(raw, 'hasPrivateBaseInventory', 3));
    const hasPrivateQuote = Boolean(field(raw, 'hasPrivateQuoteInventory', 4));
    const publicBase = formatUnits(asBigInt(field(order, 'publicBaseInventory', 12)), baseAsset.decimals);
    const publicQuote = formatUnits(asBigInt(field(order, 'publicQuoteInventory', 13)), quoteAsset.decimals);
    const buyPrice = ratioFromAtomic(buyQuote, quoteAsset.decimals, buyBase, baseAsset.decimals);
    const sellPrice = ratioFromAtomic(sellQuote, quoteAsset.decimals, sellBase, baseAsset.decimals);
    return this.#finalizeOrder({
      contract,
      id,
      kind: 'recurring',
      status: mapRecurringStatus(field(order, 'status', 2)),
      maker,
      recipient: taker && taker !== ZERO_ADDRESS ? taker : null,
      access: accessFrom(field(order, 'isPublic', 8), taker, field(order, 'accessHash', 9)),
      amountVisibility: hidden ? 'private' : 'visible',
      offerAsset: baseAsset,
      requestAsset: quoteAsset,
      offerAmount: hidden ? null : publicBase,
      requestAmount: null,
      remainingOfferAmount: hidden ? null : publicBase,
      remainingRequestAmount: hidden ? null : publicQuote,
      price: sellPrice,
      expiresAt: null,
      updatedAt: toIso(field(order, 'createdAt', 10)),
      recurring: {
        baseAsset,
        quoteAsset,
        buyBaseAmount:
          buyBase > 0n ? formatUnits(buyBase, baseAsset.decimals) : null,
        buyQuoteAmount:
          buyQuote > 0n ? formatUnits(buyQuote, quoteAsset.decimals) : null,
        sellBaseAmount:
          sellBase > 0n ? formatUnits(sellBase, baseAsset.decimals) : null,
        sellQuoteAmount:
          sellQuote > 0n ? formatUnits(sellQuote, quoteAsset.decimals) : null,
        buyPrice,
        sellPrice,
        buyQuoteLiquidity: hidden || hasPrivateQuote ? null : publicQuote,
        sellBaseLiquidity: hidden || hasPrivateBase ? null : publicBase,
        buySideOpen: Boolean(field(raw, 'buySideOpen', 1)),
        sellSideOpen: Boolean(field(raw, 'sellSideOpen', 2)),
        privateBaseInventory: hasPrivateBase,
        privateQuoteInventory: hasPrivateQuote
      }
    });
  }

  #finalizeOrder(
    order: Omit<SafeOrderSummary, 'identity' | 'snapshotHash' | 'priceBasis'>
      & { contract: Address; id: bigint }
  ): SafeOrderSummary {
    const { contract, id, ...safe } = order;
    const identity = {
      escrowContract: contract.toLowerCase() as Address,
      localId: id.toString(),
      handle: makeHandle(contract, id.toString())
    };
    const normalizedContract = contract.toLowerCase();
    const route =
      normalizedContract ===
      this.#contract('standardEscrow').address.toLowerCase()
        ? 'standard-escrow'
        : normalizedContract ===
            this.#contract('privateEscrow').address.toLowerCase()
          ? 'private-liquidity-escrow'
          : normalizedContract ===
              this.#contract('directEscrow').address.toLowerCase()
            ? 'direct-escrow'
            : 'recurring-escrow';
    const legacyStandardRecipientBound =
      route === 'standard-escrow' &&
      safe.legacyCompatibility?.kind === 'standard-recipient-bound';
    const orderType = legacyStandardRecipientBound
      ? undefined
      : deriveOrderClassificationV1({
          route,
          access: safe.access,
          privateLiquidity:
            route === 'private-liquidity-escrow' ||
            (route === 'recurring-escrow' &&
              safe.amountVisibility === 'private'),
          assets: [safe.offerAsset, safe.requestAsset],
          relation: safe.relation?.kind ?? 'primary'
        });
    return {
      identity,
      ...safe,
      ...(orderType ? { orderType } : {}),
      priceBasis: 'quote_per_base',
      // Classification is derived from the same trusted fields and is kept
      // outside the legacy snapshot commitment for handle compatibility.
      snapshotHash: keccak256(toHex(JSON.stringify({ identity, ...safe })))
    };
  }

  #orderPriceReference(
    order: SafeOrderSummary,
    input: {
      baseAsset: ResolvedAsset;
      quoteAsset: ResolvedAsset;
      side: TradeSide;
      amount: string | null;
    }
  ): RawPriceReference | null {
    if (order.kind === 'recurring' && order.recurring) {
      const price = input.side === 'buy' ? order.recurring.sellPrice : order.recurring.buyPrice;
      const liquidity =
        input.side === 'buy'
          ? order.recurring.sellBaseLiquidity
          : order.recurring.buyQuoteLiquidity;
      if (!price) return null;
      const canExecuteAmount =
        input.amount && liquidity
          ? input.side === 'buy'
            ? compareDecimals(input.amount, liquidity) <= 0
            : compareDecimals(multiplyDecimals(input.amount, price), liquidity) <= 0
          : undefined;
      return {
        id: `chainwhisper:${order.identity.handle}:${input.side}`,
        venue: 'chainwhisper',
        source: 'order',
        baseAsset: order.recurring.baseAsset,
        quoteAsset: order.recurring.quoteAsset,
        price,
        basis: 'quote_per_base',
        observedAt: order.updatedAt,
        executable: order.status === 'open',
        liquidityChecked: Boolean(input.amount && liquidity),
        canExecuteAmount,
        availableBaseAmount:
          input.side === 'buy'
            ? liquidity
            : liquidity
              ? divideDecimals(liquidity, price)
              : null,
        availableQuoteAmount:
          input.side === 'sell'
            ? liquidity
            : liquidity
              ? multiplyDecimals(liquidity, price)
              : null,
        order: order.identity
      };
    }
    if (!order.price) return null;
    const forward =
      order.offerAsset.id === input.baseAsset.id && order.requestAsset.id === input.quoteAsset.id;
    const reverse =
      order.offerAsset.id === input.quoteAsset.id && order.requestAsset.id === input.baseAsset.id;
    if (!forward && !reverse) return null;
    const relevantLiquidity = forward ? order.remainingOfferAmount : order.remainingRequestAmount;
    const canExecuteAmount =
      input.amount && relevantLiquidity
        ? compareDecimals(input.amount, relevantLiquidity) <= 0
        : undefined;
    return {
      id: `chainwhisper:${order.identity.handle}`,
      venue: 'chainwhisper',
      source: 'order',
      baseAsset: order.offerAsset,
      quoteAsset: order.requestAsset,
      price: order.price,
      basis: 'quote_per_base',
      observedAt: order.updatedAt,
      expiresAt: order.expiresAt,
      executable: order.status === 'open',
      liquidityChecked: Boolean(input.amount && relevantLiquidity),
      canExecuteAmount,
      availableBaseAmount: order.remainingOfferAmount,
      availableQuoteAmount: order.remainingRequestAmount,
      order: order.identity
    };
  }

  async #getCarbonReference(
    baseAsset: ResolvedAsset,
    quoteAsset: ResolvedAsset
  ): Promise<RawPriceReference | null> {
    const base = this.#carbonAsset(baseAsset);
    const quote = this.#carbonAsset(quoteAsset);
    if (!base || !quote || base.address.toLowerCase() === quote.address.toLowerCase()) return null;
    try {
      const [baseUsd, quoteUsd] = await Promise.all([
        this.#fetchCarbonUsd(base.address),
        this.#fetchCarbonUsd(quote.address)
      ]);
      const price = numberToDecimal(baseUsd / quoteUsd);
      if (!price) return null;
      return {
        id: `carbon:${baseAsset.id}:${quoteAsset.id}`,
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price,
        basis: 'quote_per_base',
        observedAt: new Date(this.#now()).toISOString(),
        executable: false,
        liquidityChecked: false,
        note:
          baseAsset.kind === 'private-erc20' || quoteAsset.kind === 'private-erc20'
            ? 'Public-token counterparts were used for this reference.'
            : 'Reference price only; executable liquidity was not checked.'
      };
    } catch {
      return null;
    }
  }

  #carbonAsset(asset: ResolvedAsset): { address: Address | typeof CARBON_NATIVE_ADDRESS } | null {
    if (asset.kind === 'native') return { address: CARBON_NATIVE_ADDRESS };
    if (asset.kind === 'erc20' && asset.address) return { address: asset.address };
    if (asset.publicCounterpart) {
      return {
        address: asset.publicCounterpart.address ?? CARBON_NATIVE_ADDRESS
      };
    }
    return null;
  }

  async #fetchCarbonUsd(address: string): Promise<number> {
    const url = new URL(`${this.#carbonApiUrl}${CARBON_MARKET_RATE_PATH}`);
    url.searchParams.set('address', address);
    url.searchParams.set('convert', 'USD');
    const response = await this.#fetcher(url, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(15_000)
    });
    if (!response.ok) throw new Error(`carbon-http-${response.status}`);
    const payload = (await response.json()) as { data?: { USD?: unknown } };
    const value = Number(payload.data?.USD);
    if (!Number.isFinite(value) || value <= 0) throw new Error('carbon-invalid-rate');
    return value;
  }
}

export const createLiveChainWhisperDomainGateway = async (
  options: LiveDomainGatewayOptions = {}
): Promise<LiveChainWhisperDomainGateway> =>
  new LiveChainWhisperDomainGateway({
    ...options,
    manifest: options.manifest ?? (await loadRuntimeManifest())
  });
