import { orderClassificationLabel } from '../shared/index.js';
import type {
  ListOrdersResult,
  SafeOrderSummary,
  WalletOrderActivityPage,
  WalletOrderActivityRecord,
} from '../domain/types.js';
import type {
  ConfirmationRequestWithOrderReview,
  OrderReviewV1,
} from './confirmation.js';
import type { OperationJournal } from './journal.js';
import type {
  OperationJournalRecord,
  OperationStatusV2,
} from './types.js';
import type { EncryptedSecretVault } from './vault.js';

const ACTIVITY_PAGE_SIZE = 20;
const MAX_ACTIVITY_PAGE = 49;
const ON_CHAIN_ACTIVITY_CACHE_MS = 30_000;

export type ActivityEntryV1 = {
  version: 'cw.agent-activity/1';
  id: string;
  source: 'local' | 'on-chain' | 'merged';
  activityType:
    | 'trade'
    | 'privacy'
    | 'setup'
    | 'autonomy'
    | 'message'
    | 'recovery';
  label: string;
  status: string;
  updatedAt: string;
  pair?: string;
  orderTypeLabel?: string;
  access?: string;
  privacy?: string;
  amounts?: string[];
  prices?: string[];
  fee?: string;
  operationId?: string;
  operationHash?: string;
  orderHandle?: string;
  orderUrl?: string;
  networkTransactionCount?: number;
  transactionUrls: string[];
};

export type LocalActivitySnapshotV1 = {
  version: 1;
  operationId: string;
  operationHash: string;
  action: string;
  activityType: ActivityEntryV1['activityType'];
  label: string;
  createdAt: string;
  pair?: string;
  orderTypeLabel?: string;
  access?: string;
  privacy?: string;
  amounts?: string[];
  prices?: string[];
  fee?: string;
  networkTransactionCount?: number;
};

export type AgentActivityPageV1 = {
  version: 'cw.agent-activity-page/1';
  recentEntries: ActivityEntryV1[];
  entries: ActivityEntryV1[];
  page: number;
  pageSize: typeof ACTIVITY_PAGE_SIZE;
  hasPrevious: boolean;
  hasNext: boolean;
  refreshedAt: string;
  revision: string;
};

export type WalletOrderHistoryReader = {
  listOrders(input: {
    wallet: `0x${string}`;
    role: 'all';
    kind: 'all';
    status: 'all';
    access: 'all';
    baseAsset: null;
    quoteAsset: null;
    cursor: string | null;
    limit: number;
  }): Promise<ListOrdersResult>;
  listWalletActivity?(input: {
    wallet: `0x${string}`;
    cursor: string | null;
    limit: number;
  }): Promise<WalletOrderActivityPage>;
};

export const activitySnapshotReference = (
  operationId: string,
): string => `operation:${operationId}:activity`;

const activityTypeForAction = (
  action: string,
): ActivityEntryV1['activityType'] => {
  if (
    [
      'create_trade',
      'create_recurring',
      'fill',
      'counter',
      'edit',
      'order_update',
    ].includes(action)
  ) {
    return 'trade';
  }
  if (action === 'privacy_bridge') return 'privacy';
  if (
    action === 'onboard_privacy' ||
    action === 'enable_private_token'
  ) {
    return 'setup';
  }
  if (action.includes('autonomy')) return 'autonomy';
  if (action.includes('message')) return 'message';
  return 'recovery';
};

const sideAmount = (
  side: OrderReviewV1['sellSide'] | OrderReviewV1['buySide'],
): string | null =>
  side.amount ? `${side.amount} ${side.asset}` : null;

const sidePrice = (
  side: OrderReviewV1['sellSide'] | OrderReviewV1['buySide'],
): string | null => {
  if (!side.price) return null;
  const offset =
    side.offsetBps === null
      ? ''
      : ` (${side.offsetBps > 0 ? '+' : ''}${side.offsetBps / 100}%)`;
  return `${side.price} ${side.priceUnit}${offset}`;
};

const humanFee = (value: string): string =>
  value
    .replace(/\s*\([^)]*\bwei\b[^)]*\)/giu, '')
    .replace(/\s*;\s*/gu, ' · ')
    .trim();

export const buildLocalActivitySnapshot = (
  request: ConfirmationRequestWithOrderReview,
  createdAt = new Date().toISOString(),
): LocalActivitySnapshotV1 => {
  const review = request.orderReview;
  const amounts = review
    ? [sideAmount(review.sellSide), sideAmount(review.buySide)].filter(
        (value): value is string => Boolean(value),
      )
    : request.amounts.slice(0, 4);
  const prices = review
    ? [sidePrice(review.sellSide), sidePrice(review.buySide)].filter(
        (value): value is string => Boolean(value),
      )
    : [];
  return {
    version: 1,
    operationId: request.operationId,
    operationHash: request.operationHash,
    action: request.action,
    activityType: activityTypeForAction(request.action),
    label: review?.title ?? request.summary,
    createdAt,
    ...(review?.pair ? { pair: review.pair } : {}),
    ...(request.orderType
      ? { orderTypeLabel: orderClassificationLabel(request.orderType) }
      : request.orderTypeLabel
        ? { orderTypeLabel: request.orderTypeLabel }
        : {}),
    ...(request.orderType?.access
      ? { access: request.orderType.access }
      : {}),
    ...(request.orderType?.termsVisibility
      ? { privacy: request.orderType.termsVisibility }
      : {}),
    ...(amounts.length ? { amounts } : {}),
    ...(prices.length ? { prices } : {}),
    ...(review
      ? {
          fee: `${review.protocolFeeCoti}${
            review.maximumNetworkFeeCoti
              ? ` + up to ${review.maximumNetworkFeeCoti} network`
              : ''
          }`,
          networkTransactionCount: review.networkTransactionCount,
        }
      : request.fee
        ? { fee: humanFee(request.fee) }
        : {}),
  };
};

const parseLocalActivitySnapshot = (
  value: string | null,
): LocalActivitySnapshotV1 | null => {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<LocalActivitySnapshotV1>;
    return parsed.version === 1 &&
      typeof parsed.operationId === 'string' &&
      typeof parsed.operationHash === 'string' &&
      typeof parsed.action === 'string' &&
      typeof parsed.activityType === 'string' &&
      typeof parsed.label === 'string' &&
      typeof parsed.createdAt === 'string'
      ? (parsed as LocalActivitySnapshotV1)
      : null;
  } catch {
    return null;
  }
};

const localFallbackLabel = (
  record: OperationJournalRecord,
): string => {
  if (record.operationId.startsWith('privacy-onboard-')) {
    return 'Enable private trading';
  }
  if (record.operationId.startsWith('private-token-')) {
    return 'Prepare private token';
  }
  return 'ChainWhisper operation';
};

const localFallbackType = (
  record: OperationJournalRecord,
): ActivityEntryV1['activityType'] =>
  record.operationId.startsWith('privacy-onboard-') ||
  record.operationId.startsWith('private-token-')
    ? 'setup'
    : 'recovery';

const localEntry = (
  record: OperationJournalRecord,
  status: OperationStatusV2 | null,
  snapshot: LocalActivitySnapshotV1 | null,
  explorerUrl: string,
): ActivityEntryV1 => {
  const order = status?.result?.order;
  return {
    version: 'cw.agent-activity/1',
    id: order?.handle
      ? `order:${order.handle}`
      : `operation:${record.operationId}`,
    source: 'local',
    activityType:
      snapshot?.activityType ?? localFallbackType(record),
    label:
      snapshot?.label ??
      (status?.summary.includes(record.operationId)
        ? localFallbackLabel(record)
        : status?.summary) ??
      localFallbackLabel(record),
    status: status?.status ?? record.stage,
    updatedAt: record.updatedAt,
    ...(snapshot?.pair ? { pair: snapshot.pair } : {}),
    ...(snapshot?.orderTypeLabel
      ? { orderTypeLabel: snapshot.orderTypeLabel }
      : {}),
    ...(snapshot?.access ? { access: snapshot.access } : {}),
    ...(snapshot?.privacy ? { privacy: snapshot.privacy } : {}),
    ...(snapshot?.amounts ? { amounts: [...snapshot.amounts] } : {}),
    ...(snapshot?.prices ? { prices: [...snapshot.prices] } : {}),
    ...(snapshot?.fee ? { fee: snapshot.fee } : {}),
    ...(snapshot?.networkTransactionCount
      ? {
          networkTransactionCount:
            snapshot.networkTransactionCount,
        }
      : {}),
    operationId: record.operationId,
    operationHash: record.operationHash,
    ...(order?.handle ? { orderHandle: order.handle } : {}),
    ...(order?.shareableAppLink
      ? { orderUrl: order.shareableAppLink }
      : {}),
    transactionUrls:
      status?.transactionLinks ??
      record.transactionHashes.map(
        (hash) => `${explorerUrl}/tx/${hash}`,
      ),
  };
};

const orderPair = (order: SafeOrderSummary): string =>
  order.recurring
    ? `${order.recurring.baseAsset.symbol} / ${order.recurring.quoteAsset.symbol}`
    : `${order.offerAsset.symbol} / ${order.requestAsset.symbol}`;

const onChainOrderUrl = (
  order: SafeOrderSummary,
): string | undefined =>
  order.kind === 'recurring'
    ? `https://chainwhisper.chat/otc/order/recurring/${order.identity.localId}`
    : undefined;

const onChainEntry = (
  order: SafeOrderSummary,
): ActivityEntryV1 => {
  const pair = orderPair(order);
  const amounts = order.recurring
    ? [
        order.recurring.sellBaseLiquidity
          ? `${order.recurring.sellBaseLiquidity} ${order.recurring.baseAsset.symbol} sell inventory`
          : null,
        order.recurring.buyQuoteLiquidity
          ? `${order.recurring.buyQuoteLiquidity} ${order.recurring.quoteAsset.symbol} buy budget`
          : null,
      ].filter((value): value is string => Boolean(value))
    : [
        order.offerAmount
          ? `${order.offerAmount} ${order.offerAsset.symbol}`
          : null,
        order.requestAmount
          ? `${order.requestAmount} ${order.requestAsset.symbol}`
          : null,
      ].filter((value): value is string => Boolean(value));
  const prices = order.recurring
    ? [
        order.recurring.sellPrice
          ? `${order.recurring.sellPrice} ${order.recurring.quoteAsset.symbol}/${order.recurring.baseAsset.symbol} sell`
          : null,
        order.recurring.buyPrice
          ? `${order.recurring.buyPrice} ${order.recurring.quoteAsset.symbol}/${order.recurring.baseAsset.symbol} buy`
          : null,
      ].filter((value): value is string => Boolean(value))
    : order.price
      ? [
          `${order.price} ${order.requestAsset.symbol}/${order.offerAsset.symbol}`,
        ]
      : [];
  const orderUrl = onChainOrderUrl(order);
  return {
    version: 'cw.agent-activity/1',
    id: `order:${order.identity.handle}`,
    source: 'on-chain',
    activityType: 'trade',
    label: `${pair} ${order.kind === 'recurring' ? 'recurring order' : 'order'}`,
    status: order.status,
    updatedAt: order.updatedAt,
    pair,
    ...(order.orderType
      ? { orderTypeLabel: orderClassificationLabel(order.orderType) }
      : order.legacyCompatibility
        ? { orderTypeLabel: order.legacyCompatibility.displayType }
        : {}),
    access: order.access,
    privacy:
      order.amountVisibility === 'private'
        ? 'hidden-liquidity'
        : 'visible-terms',
    ...(amounts.length ? { amounts } : {}),
    ...(prices.length ? { prices } : {}),
    orderHandle: order.identity.handle,
    ...(orderUrl ? { orderUrl } : {}),
    transactionUrls: [],
  };
};

const onChainActivityEntry = (
  record: WalletOrderActivityRecord,
  explorerUrl: string,
): ActivityEntryV1 => {
  const base = onChainEntry(record.order);
  const transactionUrl = record.transactionHash
    ? `${explorerUrl}/tx/${record.transactionHash}`
    : null;
  if (record.kind === 'order') {
    return {
      ...base,
      updatedAt: record.occurredAt,
      transactionUrls: transactionUrl ? [transactionUrl] : [],
    };
  }
  return {
    ...base,
    id: record.transactionHash
      ? `fill:${record.transactionHash}`
      : `fill:${record.orderHandle}:${record.blockNumber ?? 'unknown'}:${record.logIndex ?? 'unknown'}`,
    label: `${orderPair(record.order)} fill`,
    status: 'completed',
    updatedAt: record.occurredAt,
    transactionUrls: transactionUrl ? [transactionUrl] : [],
  };
};

const mergeEntries = (
  local: ActivityEntryV1,
  onChain: ActivityEntryV1,
): ActivityEntryV1 => ({
  ...onChain,
  ...local,
  source: 'merged',
  status: onChain.status,
  updatedAt:
    local.updatedAt > onChain.updatedAt
      ? local.updatedAt
      : onChain.updatedAt,
  orderUrl: local.orderUrl ?? onChain.orderUrl,
  transactionUrls: [
    ...new Set([
      ...local.transactionUrls,
      ...onChain.transactionUrls,
    ]),
  ],
});

const mergeLocalEntries = (
  current: ActivityEntryV1,
  incoming: ActivityEntryV1,
): ActivityEntryV1 => {
  const latest =
    incoming.updatedAt >= current.updatedAt ? incoming : current;
  const earlier = latest === incoming ? current : incoming;
  return {
    ...earlier,
    ...latest,
    source:
      current.source === incoming.source
        ? current.source
        : 'merged',
    transactionUrls: [
      ...new Set([
        ...current.transactionUrls,
        ...incoming.transactionUrls,
      ]),
    ],
  };
};

export class AgentActivityReader {
  readonly #wallet: `0x${string}`;
  readonly #journal: OperationJournal;
  readonly #vault: EncryptedSecretVault;
  readonly #orders: WalletOrderHistoryReader;
  readonly #getOperationStatus: (
    operationId: string,
  ) => Promise<OperationStatusV2 | null>;
  readonly #explorerUrl: string;
  #ordersCache: {
    orders: SafeOrderSummary[];
    activities: WalletOrderActivityRecord[];
    hasMore: boolean;
    requested: number;
    expiresAt: number;
  } | null = null;
  #ordersRefresh: Promise<{
    orders: SafeOrderSummary[];
    activities: WalletOrderActivityRecord[];
    hasMore: boolean;
    requested: number;
  }> | null = null;
  #ordersRequestedCount = 0;
  readonly #statusCache = new Map<
    string,
    { value: OperationStatusV2 | null; expiresAt: number }
  >();
  readonly #snapshotCache = new Map<
    string,
    LocalActivitySnapshotV1
  >();

  constructor(options: {
    wallet: `0x${string}`;
    journal: OperationJournal;
    vault: EncryptedSecretVault;
    orders: WalletOrderHistoryReader;
    getOperationStatus: (
      operationId: string,
    ) => Promise<OperationStatusV2 | null>;
    explorerUrl: string;
  }) {
    this.#wallet = options.wallet;
    this.#journal = options.journal;
    this.#vault = options.vault;
    this.#orders = options.orders;
    this.#getOperationStatus = options.getOperationStatus;
    this.#explorerUrl = options.explorerUrl.replace(/\/+$/u, '');
  }

  async #readOrders(count: number): Promise<{
    orders: SafeOrderSummary[];
    activities: WalletOrderActivityRecord[];
    hasMore: boolean;
  }> {
    if (
      this.#ordersCache &&
      this.#ordersCache.expiresAt > Date.now() &&
      (this.#ordersCache.requested >= count ||
        !this.#ordersCache.hasMore)
    ) {
      return {
        orders: [...this.#ordersCache.orders],
        activities: [...this.#ordersCache.activities],
        hasMore: this.#ordersCache.hasMore,
      };
    }
    if (this.#ordersRefresh) {
      this.#ordersRequestedCount = Math.max(
        this.#ordersRequestedCount,
        count,
      );
      const active = this.#ordersRefresh;
      await active;
      if (this.#ordersRefresh === active) {
        this.#ordersRefresh = null;
      }
      return this.#readOrders(count);
    }
    this.#ordersRequestedCount = count;
    const refresh = (async () => {
      const orders = new Map<string, SafeOrderSummary>();
      const activities = new Map<
        string,
        WalletOrderActivityRecord
      >();
      let cursor: string | null = null;
      let hasMore: boolean;
      let pages = 0;
      do {
        if (this.#orders.listWalletActivity) {
          const page = await this.#orders.listWalletActivity({
            wallet: this.#wallet,
            cursor,
            limit: ACTIVITY_PAGE_SIZE,
          });
          for (const record of page.records) {
            orders.set(record.order.identity.handle, record.order);
            const key = record.transactionHash
              ? `${record.kind}:${record.transactionHash.toLowerCase()}`
              : `${record.kind}:${record.orderHandle}:${record.blockNumber ?? ''}:${record.logIndex ?? ''}`;
            activities.set(key, record);
          }
          cursor = page.nextCursor;
          hasMore = page.truncated;
        } else {
          const page = await this.#orders.listOrders({
            wallet: this.#wallet,
            role: 'all',
            kind: 'all',
            status: 'all',
            access: 'all',
            baseAsset: null,
            quoteAsset: null,
            cursor,
            limit: ACTIVITY_PAGE_SIZE,
          });
          for (const order of page.orders) {
            orders.set(order.identity.handle, order);
          }
          cursor = page.nextCursor;
          hasMore = page.truncated;
        }
        pages += 1;
      } while (
        cursor &&
        (activities.size || orders.size) <
          this.#ordersRequestedCount &&
        pages < MAX_ACTIVITY_PAGE + 1
      );
      const value = {
        orders: [...orders.values()],
        activities: [...activities.values()],
        hasMore: Boolean(cursor) || hasMore,
        requested: this.#ordersRequestedCount,
      };
      this.#ordersCache = {
        ...value,
        expiresAt: Date.now() + ON_CHAIN_ACTIVITY_CACHE_MS,
      };
      return value;
    })();
    this.#ordersRefresh = refresh;
    let value: Awaited<typeof refresh>;
    try {
      value = await refresh;
    } finally {
      if (this.#ordersRefresh === refresh) {
        this.#ordersRefresh = null;
      }
    }
    if (value.requested < count && value.hasMore) {
      return this.#readOrders(count);
    }
    return {
      orders: [...value.orders],
      activities: [...value.activities],
      hasMore: value.hasMore,
    };
  }

  async #readOperationStatus(
    operationId: string,
  ): Promise<OperationStatusV2 | null> {
    const cached = this.#statusCache.get(operationId);
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    const value = await this.#getOperationStatus(operationId).catch(
      () => null,
    );
    const terminal =
      value &&
      ['completed', 'declined', 'failed'].includes(value.status);
    this.#statusCache.set(operationId, {
      value,
      expiresAt: Date.now() + (terminal ? 30_000 : 500),
    });
    return value;
  }

  async #readSnapshot(
    operationId: string,
  ): Promise<LocalActivitySnapshotV1 | null> {
    const cached = this.#snapshotCache.get(operationId);
    if (cached) return cached;
    const snapshot = parseLocalActivitySnapshot(
      await this.#vault
        .get(activitySnapshotReference(operationId))
        .catch(() => null),
    );
    if (snapshot) this.#snapshotCache.set(operationId, snapshot);
    return snapshot;
  }

  async page(requestedPage = 0): Promise<AgentActivityPageV1> {
    const page = Math.max(
      0,
      Math.min(MAX_ACTIVITY_PAGE, Math.trunc(requestedPage)),
    );
    const required = (page + 1) * ACTIVITY_PAGE_SIZE;
    const records = await this.#journal.list();
    const [local, chain] = await Promise.all([
      Promise.all(
        records.map(async (record) =>
          localEntry(
            record,
            await this.#readOperationStatus(record.operationId),
            await this.#readSnapshot(record.operationId),
            this.#explorerUrl,
          ),
        ),
      ),
      this.#readOrders(required).catch(() => ({
        orders: [] as SafeOrderSummary[],
        activities: [] as WalletOrderActivityRecord[],
        hasMore: false,
      })),
    ]);
    const merged = new Map<string, ActivityEntryV1>();
    const transactionOwners = new Map<string, string>();
    const chainEntries = chain.activities.length
      ? chain.activities.map((record) =>
          onChainActivityEntry(record, this.#explorerUrl),
        )
      : chain.orders.map(onChainEntry);
    for (const entry of chainEntries) {
      merged.set(entry.id, entry);
      for (const transactionUrl of entry.transactionUrls) {
        transactionOwners.set(transactionUrl.toLowerCase(), entry.id);
      }
    }
    for (const entry of local) {
      const transactionOwner = entry.transactionUrls
        .map((url) => transactionOwners.get(url.toLowerCase()))
        .find((owner): owner is string => Boolean(owner));
      const key = merged.has(entry.id)
        ? entry.id
        : transactionOwner ?? entry.id;
      const current = merged.get(key);
      const value = current
        ? current.source === 'on-chain' ||
          current.source === 'merged'
          ? mergeEntries(entry, current)
          : mergeLocalEntries(current, entry)
        : entry;
      merged.set(key, value);
      for (const transactionUrl of value.transactionUrls) {
        transactionOwners.set(transactionUrl.toLowerCase(), key);
      }
    }
    const all = [...merged.values()].sort((left, right) =>
      right.updatedAt.localeCompare(left.updatedAt),
    );
    const start = page * ACTIVITY_PAGE_SIZE;
    const entries = all.slice(start, start + ACTIVITY_PAGE_SIZE);
    const recentEntries = all.slice(0, 5);
    const refreshedAt = new Date().toISOString();
    return {
      version: 'cw.agent-activity-page/1',
      recentEntries,
      entries,
      page,
      pageSize: ACTIVITY_PAGE_SIZE,
      hasPrevious: page > 0,
      hasNext:
        all.length > start + ACTIVITY_PAGE_SIZE || chain.hasMore,
      refreshedAt,
      revision: [
        page,
        records[0]?.updatedAt ?? '',
        entries.map(({ id, status, updatedAt }) => [
          id,
          status,
          updatedAt,
        ]),
        recentEntries.map(({ id, status, updatedAt }) => [
          id,
          status,
          updatedAt,
        ]),
      ].join(':'),
    };
  }
}
