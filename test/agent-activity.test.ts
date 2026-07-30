import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import type {
  ListOrdersResult,
  SafeOrderSummary,
  WalletOrderActivityPage,
} from '../src/domain/index.js';
import {
  AgentActivityReader,
  EncryptedSecretVault,
  OperationJournal,
  activitySnapshotReference,
  type Address,
  type HexString,
  type LocalActivitySnapshotV1,
  type OperationStatusV2,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const CONTRACT =
  '0x2222222222222222222222222222222222222222' as Address;
const OPERATION_HASH = `0x${'33'.repeat(32)}` as HexString;
const FILL_TRANSACTION =
  `0x${'55'.repeat(32)}` as HexString;

const recurringOrder = (
  localId: string,
  updatedAt: string,
): SafeOrderSummary => ({
  identity: {
    escrowContract: CONTRACT,
    localId,
    handle: `cw_${CONTRACT.slice(2)}_${localId}`,
  },
  kind: 'recurring',
  status: 'open',
  maker: WALLET,
  recipient: null,
  access: 'public',
  amountVisibility: 'private',
  offerAsset: {
    id: CONTRACT,
    kind: 'private-erc20',
    symbol: 'p.WISP',
    decimals: 6,
    address: CONTRACT,
    verified: true,
  },
  requestAsset: {
    id: WALLET,
    kind: 'private-erc20',
    symbol: 'p.COTI',
    decimals: 18,
    address: WALLET,
    verified: true,
  },
  offerAmount: null,
  requestAmount: null,
  remainingOfferAmount: null,
  remainingRequestAmount: null,
  price: null,
  priceBasis: 'quote_per_base',
  expiresAt: null,
  updatedAt,
  snapshotHash: OPERATION_HASH,
  recurring: {
    baseAsset: {
      id: CONTRACT,
      kind: 'private-erc20',
      symbol: 'p.WISP',
      decimals: 6,
      address: CONTRACT,
      verified: true,
    },
    quoteAsset: {
      id: WALLET,
      kind: 'private-erc20',
      symbol: 'p.COTI',
      decimals: 18,
      address: WALLET,
      verified: true,
    },
    buyPrice: '0.0009',
    sellPrice: '0.0011',
    buyQuoteLiquidity: null,
    sellBaseLiquidity: null,
    buySideOpen: true,
    sellSideOpen: true,
    privateBaseInventory: true,
    privateQuoteInventory: true,
  },
});

describe('AgentActivityReader', () => {
  it('merges a local exact review with the latest on-chain order status', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-agent-activity-'),
    );
    const journal = new OperationJournal(stateDirectory);
    const vault = new EncryptedSecretVault(
      stateDirectory,
      'activity-test-passphrase',
    );
    const operationId = 'recurring-create-activity';
    const order = recurringOrder(
      '7',
      '2026-07-30T12:05:00.000Z',
    );
    await journal.begin(operationId, OPERATION_HASH);
    await journal.updateStage(operationId, 'completed', 3);
    const localSnapshot: LocalActivitySnapshotV1 = {
      version: 1,
      operationId,
      operationHash: OPERATION_HASH,
      action: 'create_recurring',
      activityType: 'trade',
      label: 'Create recurring order',
      createdAt: '2026-07-30T12:00:00.000Z',
      pair: 'p.WISP / p.COTI',
      access: 'public',
      privacy: 'hidden-liquidity',
      amounts: ['10 p.WISP', '10 p.COTI'],
      prices: [
        '0.0011 p.COTI/p.WISP (+10%)',
        '0.0009 p.COTI/p.WISP (-10%)',
      ],
      fee: '5 COTI + up to 0.48 COTI network',
      networkTransactionCount: 3,
    };
    await vault.put(
      activitySnapshotReference(operationId),
      JSON.stringify(localSnapshot),
    );
    const status: OperationStatusV2 = {
      version: 'cw.operation-status/2',
      operationId,
      operationHash: OPERATION_HASH,
      status: 'completed',
      summary: 'ChainWhisper create recurring completed.',
      transactionHashes: [`0x${'44'.repeat(32)}`],
      transactionLinks: [
        `https://mainnet.cotiscan.io/tx/0x${'44'.repeat(32)}`,
      ],
      userActionRequired: false,
      nextPollingIntervalMs: null,
      result: {
        action: 'create_recurring',
        status: 'completed',
        order: {
          handle: order.identity.handle,
          status: 'open',
          shareableAppLink:
            'https://chainwhisper.chat/otc/order/recurring/7',
        },
      },
    };
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal,
      vault,
      orders: {
        listOrders: async (): Promise<ListOrdersResult> => ({
          orders: [order],
          nextCursor: null,
          truncated: false,
        }),
      },
      getOperationStatus: async () => status,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const page = await reader.page();

    expect(page.entries).toHaveLength(1);
    expect(page.entries[0]).toMatchObject({
      source: 'merged',
      label: 'Create recurring order',
      status: 'open',
      pair: 'p.WISP / p.COTI',
      amounts: ['10 p.WISP', '10 p.COTI'],
      orderHandle: order.identity.handle,
      orderUrl:
        'https://chainwhisper.chat/otc/order/recurring/7',
      networkTransactionCount: 3,
    });
    expect(page.entries[0]?.transactionUrls).toHaveLength(1);
  });

  it('includes wallet orders created outside this signer', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-activity-'),
    );
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal: new OperationJournal(stateDirectory),
      vault: new EncryptedSecretVault(
        stateDirectory,
        'external-activity-passphrase',
      ),
      orders: {
        listOrders: async (): Promise<ListOrdersResult> => ({
          orders: [
            recurringOrder('19', '2026-07-30T12:05:00.000Z'),
          ],
          nextCursor: null,
          truncated: false,
        }),
      },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    await expect(reader.page()).resolves.toMatchObject({
      entries: [
        {
          source: 'on-chain',
          activityType: 'trade',
          pair: 'p.WISP / p.COTI',
          orderUrl:
            'https://chainwhisper.chat/otc/order/recurring/19',
        },
      ],
      page: 0,
      hasPrevious: false,
    });
  });

  it('includes an externally executed wallet fill with its on-chain transaction and timestamp', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-external-fill-'),
    );
    const order = recurringOrder(
      '20',
      '2026-07-30T12:05:00.000Z',
    );
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal: new OperationJournal(stateDirectory),
      vault: new EncryptedSecretVault(
        stateDirectory,
        'external-fill-passphrase',
      ),
      orders: {
        listOrders: async (): Promise<ListOrdersResult> => ({
          orders: [],
          nextCursor: null,
          truncated: false,
        }),
        listWalletActivity:
          async (): Promise<WalletOrderActivityPage> => ({
            records: [
              {
                kind: 'fill',
                order,
                orderHandle: order.identity.handle,
                transactionHash: FILL_TRANSACTION,
                blockNumber: '123',
                logIndex: 4,
                occurredAt: '2026-07-30T12:15:00.000Z',
              },
            ],
            nextCursor: null,
            truncated: false,
          }),
      },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    await expect(reader.page()).resolves.toMatchObject({
      entries: [
        {
          source: 'on-chain',
          activityType: 'trade',
          label: 'p.WISP / p.COTI fill',
          status: 'completed',
          updatedAt: '2026-07-30T12:15:00.000Z',
          orderHandle: order.identity.handle,
          transactionUrls: [
            `https://mainnet.cotiscan.io/tx/${FILL_TRANSACTION}`,
          ],
        },
      ],
    });
  });

  it('deduplicates a local fill against the same on-chain fill transaction', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-local-fill-dedupe-'),
    );
    const journal = new OperationJournal(stateDirectory);
    const operationId = 'external-fill-local-copy';
    const order = recurringOrder(
      '22',
      '2026-07-30T12:05:00.000Z',
    );
    await journal.begin(operationId, OPERATION_HASH);
    await journal.recordExternalReceipt(operationId, {
      transactionHash: FILL_TRANSACTION,
      status: 'success',
    });
    const status: OperationStatusV2 = {
      version: 'cw.operation-status/2',
      operationId,
      operationHash: OPERATION_HASH,
      status: 'completed',
      summary: 'Fill recurring order.',
      transactionHashes: [FILL_TRANSACTION],
      transactionLinks: [
        `https://mainnet.cotiscan.io/tx/${FILL_TRANSACTION}`,
      ],
      userActionRequired: false,
      nextPollingIntervalMs: null,
      result: {
        action: 'fill',
        status: 'completed',
      },
    };
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal,
      vault: new EncryptedSecretVault(
        stateDirectory,
        'local-fill-dedupe-passphrase',
      ),
      orders: {
        listOrders: async (): Promise<ListOrdersResult> => ({
          orders: [],
          nextCursor: null,
          truncated: false,
        }),
        listWalletActivity:
          async (): Promise<WalletOrderActivityPage> => ({
            records: [
              {
                kind: 'fill',
                order,
                orderHandle: order.identity.handle,
                transactionHash: FILL_TRANSACTION,
                blockNumber: '123',
                logIndex: 4,
                occurredAt: '2026-07-30T12:15:00.000Z',
              },
            ],
            nextCursor: null,
            truncated: false,
          }),
      },
      getOperationStatus: async () => status,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const page = await reader.page();

    expect(page.entries).toHaveLength(1);
    expect(page.entries[0]).toMatchObject({
      source: 'merged',
      status: 'completed',
      orderHandle: order.identity.handle,
      transactionUrls: [
        `https://mainnet.cotiscan.io/tx/${FILL_TRANSACTION}`,
      ],
    });
  });

  it('deduplicates concurrent wallet-wide history reads and caches them briefly', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-activity-cache-'),
    );
    const listOrders = vi.fn(
      async (): Promise<ListOrdersResult> => ({
        orders: [
          recurringOrder('21', '2026-07-30T12:05:00.000Z'),
        ],
        nextCursor: null,
        truncated: false,
      }),
    );
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal: new OperationJournal(stateDirectory),
      vault: new EncryptedSecretVault(
        stateDirectory,
        'external-activity-cache-passphrase',
      ),
      orders: { listOrders },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const [first, second] = await Promise.all([
      reader.page(),
      reader.page(),
    ]);
    await reader.page();

    expect(first.entries).toEqual(second.entries);
    expect(listOrders).toHaveBeenCalledTimes(1);
  });

  it('keeps five global recent entries while paging full history twenty at a time', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-activity-pages-'),
    );
    const orders = Array.from({ length: 25 }, (_, index) =>
      recurringOrder(
        String(index + 1),
        new Date(
          Date.parse('2026-07-30T12:30:00.000Z') -
            index * 1_000,
        ).toISOString(),
      ),
    );
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal: new OperationJournal(stateDirectory),
      vault: new EncryptedSecretVault(
        stateDirectory,
        'external-activity-pages-passphrase',
      ),
      orders: {
        listOrders: async ({ cursor }): Promise<ListOrdersResult> =>
          cursor
            ? {
                orders: orders.slice(20),
                nextCursor: null,
                truncated: false,
              }
            : {
                orders: orders.slice(0, 20),
                nextCursor: '20',
                truncated: true,
              },
      },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const secondPage = await reader.page(1);

    expect(secondPage.entries).toHaveLength(5);
    expect(secondPage.recentEntries).toHaveLength(5);
    expect(secondPage.recentEntries[0]?.orderHandle).toBe(
      orders[0]?.identity.handle,
    );
    expect(secondPage.entries[0]?.orderHandle).toBe(
      orders[20]?.identity.handle,
    );
    expect(secondPage).toMatchObject({
      page: 1,
      pageSize: 20,
      hasPrevious: true,
      hasNext: false,
    });
  });

  it('coalesces concurrent page-zero and later-page reads to the larger requested history size', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-activity-concurrent-pages-'),
    );
    const orders = Array.from({ length: 40 }, (_, index) =>
      recurringOrder(
        String(index + 1),
        new Date(
          Date.parse('2026-07-30T12:30:00.000Z') -
            index * 1_000,
        ).toISOString(),
      ),
    );
    let releaseFirstPage!: () => void;
    const firstPageGate = new Promise<void>((resolve) => {
      releaseFirstPage = resolve;
    });
    const listOrders = vi.fn(
      async ({ cursor }): Promise<ListOrdersResult> => {
        if (!cursor) {
          await firstPageGate;
          return {
            orders: orders.slice(0, 20),
            nextCursor: '20',
            truncated: true,
          };
        }
        return {
          orders: orders.slice(20),
          nextCursor: null,
          truncated: false,
        };
      },
    );
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal: new OperationJournal(stateDirectory),
      vault: new EncryptedSecretVault(
        stateDirectory,
        'concurrent-pages-passphrase',
      ),
      orders: { listOrders },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const firstPage = reader.page(0);
    await vi.waitFor(() => {
      expect(listOrders).toHaveBeenCalledTimes(1);
    });
    const secondPage = reader.page(1);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    releaseFirstPage();
    const [first, second] = await Promise.all([
      firstPage,
      secondPage,
    ]);

    expect(first.entries).toHaveLength(20);
    expect(second.entries).toHaveLength(20);
    expect(second.entries[0]?.orderHandle).toBe(
      orders[20]?.identity.handle,
    );
    expect(listOrders).toHaveBeenCalledTimes(2);
  });

  it('deduplicates local recovery records that resolve to the same transaction', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-wallet-activity-dedupe-'),
    );
    const journal = new OperationJournal(stateDirectory);
    const sharedTransaction = `0x${'77'.repeat(32)}` as HexString;
    await journal.begin('recovery-copy-1', OPERATION_HASH);
    await journal.begin(
      'recovery-copy-2',
      `0x${'66'.repeat(32)}` as HexString,
    );
    await journal.recordExternalReceipt('recovery-copy-1', {
      transactionHash: sharedTransaction,
      status: 'success',
    });
    await journal.recordExternalReceipt('recovery-copy-2', {
      transactionHash: sharedTransaction,
      status: 'success',
    });
    const reader = new AgentActivityReader({
      wallet: WALLET,
      journal,
      vault: new EncryptedSecretVault(
        stateDirectory,
        'external-activity-dedupe-passphrase',
      ),
      orders: {
        listOrders: async (): Promise<ListOrdersResult> => ({
          orders: [],
          nextCursor: null,
          truncated: false,
        }),
      },
      getOperationStatus: async () => null,
      explorerUrl: 'https://mainnet.cotiscan.io',
    });

    const page = await reader.page();

    expect(page.entries).toHaveLength(1);
    expect(page.entries[0]?.transactionUrls).toEqual([
      `https://mainnet.cotiscan.io/tx/${sharedTransaction}`,
    ]);
  });
});
