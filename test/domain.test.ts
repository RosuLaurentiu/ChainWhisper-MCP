import { describe, expect, it, vi } from 'vitest';

import {
  CHAINWHISPER_CHAIN_ID,
  ChainWhisperDomainService,
  createChainWhisperDomainTools,
  type Address,
  type DomainEnvelopeFactory,
  type DomainExecutionPlan,
  type DomainGateway,
  type DomainIntent,
  type DomainStatus,
  type RawPriceReference,
  type ResolvedAsset,
  type SafeOrderSummary
} from '../src/domain/index.js';

const addresses = {
  wallet: '0x1111111111111111111111111111111111111111' as Address,
  maker: '0x2222222222222222222222222222222222222222' as Address,
  recipient: '0x3333333333333333333333333333333333333333' as Address,
  standard: '0x4444444444444444444444444444444444444444' as Address,
  privateEscrow: '0x5555555555555555555555555555555555555555' as Address,
  direct: '0x6666666666666666666666666666666666666666' as Address,
  recurring: '0x7777777777777777777777777777777777777777' as Address,
  registry: '0x8888888888888888888888888888888888888888' as Address,
  fee: '0x9999999999999999999999999999999999999999' as Address,
  base: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as Address,
  quote: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as Address,
  privateBase: '0xcccccccccccccccccccccccccccccccccccccccc' as Address,
  privateQuote: '0xdddddddddddddddddddddddddddddddddddddddd' as Address
};

const baseAsset: ResolvedAsset = {
  id: addresses.base,
  kind: 'erc20',
  symbol: 'BASE',
  decimals: 6,
  address: addresses.base,
  verified: true
};
const quoteAsset: ResolvedAsset = {
  id: addresses.quote,
  kind: 'erc20',
  symbol: 'QUOTE',
  decimals: 6,
  address: addresses.quote,
  verified: true
};
const privateBaseAsset: ResolvedAsset = {
  id: addresses.privateBase,
  kind: 'private-erc20',
  symbol: 'p.BASE',
  decimals: 6,
  address: addresses.privateBase,
  verified: true,
  publicCounterpart: { symbol: 'BASE', address: addresses.base }
};
const privateQuoteAsset: ResolvedAsset = {
  id: addresses.privateQuote,
  kind: 'private-erc20',
  symbol: 'p.QUOTE',
  decimals: 6,
  address: addresses.privateQuote,
  verified: true,
  publicCounterpart: { symbol: 'QUOTE', address: addresses.quote }
};
const privateWispAsset: ResolvedAsset = {
  ...privateBaseAsset,
  symbol: 'p.WISP',
  publicCounterpart: { symbol: 'WISP', address: addresses.base }
};
const privateCotiAsset: ResolvedAsset = {
  ...privateQuoteAsset,
  symbol: 'p.COTI',
  decimals: 18,
  publicCounterpart: { symbol: 'COTI', address: addresses.quote }
};

const status = (recurringWritesEnabled = true): DomainStatus => ({
  service: 'chainwhisper-mcp',
  mode: 'keyless',
  chainId: CHAINWHISPER_CHAIN_ID,
  ready: true,
  readOnly: false,
  registry: {
    chainId: CHAINWHISPER_CHAIN_ID,
    registryAddress: addresses.registry,
    snapshotHash: `0x${'1'.repeat(64)}`,
    blockNumber: '100',
    contracts: {
      standardEscrow: addresses.standard,
      privateEscrow: addresses.privateEscrow,
      directEscrow: addresses.direct,
      recurringEscrow: addresses.recurring
    },
    recurringWritesEnabled,
    verifiedAt: '2026-07-27T00:00:00.000Z',
    warnings: recurringWritesEnabled ? [] : ['Recurring selector audit pending.']
  },
  capabilities: {
    reads: true,
    priceReferences: true,
    unsignedPlanning: true,
    recurringWrites: recurringWritesEnabled
  }
});

const order = (overrides: Partial<SafeOrderSummary> = {}): SafeOrderSummary => ({
  identity: {
    escrowContract: addresses.standard,
    localId: '7',
    handle: `cw_${addresses.standard.slice(2)}_7`
  },
  kind: 'trade',
  status: 'open',
  maker: addresses.maker,
  recipient: null,
  access: 'public',
  amountVisibility: 'visible',
  offerAsset: baseAsset,
  requestAsset: quoteAsset,
  offerAmount: '10',
  requestAmount: '20',
  remainingOfferAmount: '10',
  remainingRequestAmount: '20',
  price: '2',
  priceBasis: 'quote_per_base',
  expiresAt: null,
  updatedAt: '2026-07-27T00:00:00.000Z',
  snapshotHash: `0x${'2'.repeat(64)}`,
  ...overrides
});

const executionPlan = (intent: DomainIntent): DomainExecutionPlan => ({
  wallet: intent.wallet!,
  registry: status().registry,
  steps: [
    {
      id: 'protocol',
      kind: 'protocol',
      contract: addresses.standard,
      description: 'Execute the allowlisted ChainWhisper action.',
      nativeValue: '0',
      encoding: { selector: '0x12345678', arguments: [] }
    }
  ],
  fee: {
    token: 'native',
    amount: '0',
    scheduleAmount: '0',
    recipient: addresses.fee
  },
  exactNativeValue: '0',
  gasCap: '1000000',
  simulation: {
    ok: true,
    blockNumber: '100',
    expectedResult: 'Order prepared.',
    warnings: []
  },
  expiresAt: '2026-07-27T00:15:00.000Z'
});

class MockGateway implements DomainGateway {
  currentStatus = status();
  orders: SafeOrderSummary[] = [order()];
  references: RawPriceReference[] = [];
  buildExecutionPlan = vi.fn(async (intent: DomainIntent) => executionPlan(intent));

  async getStatus() {
    return this.currentStatus;
  }

  async isTrustedEscrow(address: Address) {
    return Object.values(this.currentStatus.registry.contracts).includes(address);
  }

  async resolveAsset(reference: Parameters<DomainGateway['resolveAsset']>[0]) {
    const key =
      typeof reference === 'string'
        ? reference.toLowerCase()
        : reference.address?.toLowerCase() ?? reference.symbol?.toLowerCase();
    return [
      baseAsset,
      quoteAsset,
      privateBaseAsset,
      privateQuoteAsset,
      privateWispAsset,
      privateCotiAsset
    ].find(
      (asset) => asset.id === key || asset.symbol.toLowerCase() === key
    ) ?? null;
  }

  async listOrders(input: Parameters<DomainGateway['listOrders']>[0]) {
    return {
      orders: this.orders.slice(0, input.limit),
      nextCursor: null,
      truncated: this.orders.length > input.limit
    };
  }

  async getOrder(identity: Parameters<DomainGateway['getOrder']>[0]) {
    const handle =
      'handle' in identity
        ? identity.handle
        : `cw_${identity.escrowContract.slice(2)}_${identity.localId}`;
    return (
      this.orders.find((order) => order.identity.handle === handle) ??
      null
    );
  }

  async getPriceReferences() {
    return this.references;
  }
}

const envelopeFactory: DomainEnvelopeFactory = {
  async create(intent, execution) {
    return {
      version: 'ActionEnvelopeV1',
      operationId: `op-${intent.action}`,
      operationHash: `0x${'3'.repeat(64)}`,
      expiresAt: execution.expiresAt,
      summary: `Prepare ${intent.action}.`,
      payload: { intent, execution }
    };
  }
};

const makeService = (
  now: () => number = () => Date.parse('2026-07-27T00:01:00.000Z')
) => {
  const gateway = new MockGateway();
  return {
    gateway,
    service: new ChainWhisperDomainService(gateway, envelopeFactory, now)
  };
};

describe('ChainWhisperDomainService price references', () => {
  it('does not require an amount and keeps market-only venues out of execution ranking', async () => {
    const { gateway, service } = makeService();
    gateway.references = [
      {
        id: 'carbon',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2.5',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:00.000Z',
        executable: false,
        liquidityChecked: false
      }
    ];

    const result = await service.comparePriceReferences({
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      side: 'buy'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        amount: null,
        ranking: null,
        rankingUnavailableReason: 'amount_not_supplied',
        executableReferences: [],
        referenceOnly: [{ id: 'carbon', price: '2.5' }]
      }
    });
  });

  it('normalizes reverse orientation and ranks only checked executable liquidity', async () => {
    const { gateway, service } = makeService();
    gateway.references = [
      {
        id: 'order-a',
        venue: 'chainwhisper',
        source: 'order',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:00.000Z',
        executable: true,
        liquidityChecked: true,
        canExecuteAmount: true,
        executionPrice: '2.1'
      },
      {
        id: 'order-reversed',
        venue: 'chainwhisper',
        source: 'order',
        baseAsset: quoteAsset,
        quoteAsset: baseAsset,
        price: '0.4',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:01.000Z',
        executable: true,
        liquidityChecked: true,
        canExecuteAmount: true
      },
      {
        id: 'reference-only',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '1.9',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:02.000Z',
        executable: false,
        liquidityChecked: false
      }
    ];

    const result = await service.comparePriceReferences({
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      side: 'buy',
      amount: '3'
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data.references.find((item) => item.id === 'order-reversed')?.price).toBe('2.5');
    expect(result.data.ranking?.rankedReferenceIds).toEqual(['order-a', 'order-reversed']);
    expect(result.data.ranking?.bestReferenceId).toBe('order-a');
    expect(result.data.referenceOnly.map((item) => item.id)).toEqual(['reference-only']);
  });

  it('uses the highest executable quote-per-base price when selling', async () => {
    const { gateway, service } = makeService();
    gateway.references = ['2', '2.2'].map((price, index) => ({
      id: `order-${index}`,
      venue: 'chainwhisper',
      source: 'order',
      baseAsset,
      quoteAsset,
      price,
      basis: 'quote_per_base',
      observedAt: '2026-07-27T00:00:00.000Z',
      executable: true,
      liquidityChecked: true,
      canExecuteAmount: true
    }));
    const result = await service.comparePriceReferences({
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      side: 'sell',
      amount: '1'
    });
    expect(result).toMatchObject({
      ok: true,
      data: { ranking: { bestReferenceId: 'order-1' } }
    });
  });

  it('prepares the best complete single-order Swap as a canonical fill', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order(),
      order({
        identity: {
          escrowContract: addresses.standard,
          localId: '8',
          handle: `cw_${addresses.standard.slice(2)}_8`
        },
        offerAmount: '10',
        requestAmount: '18',
        remainingOfferAmount: '10',
        remainingRequestAmount: '18',
        price: '1.8',
        updatedAt: '2026-07-27T00:00:01.000Z'
      })
    ];

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '3'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          action: 'fill',
          inputAmount: '5.4',
          minOutputAmount: '3',
          order: { identity: { localId: '8' } }
        },
        selection: {
          source: 'one-off',
          order: { localId: '8' },
          inputMode: 'buy',
          sellAmount: '5.4',
          buyAmount: '3',
          price: '1.8',
          priceBasis: 'sell_per_buy',
          visibleCandidateCount: 2
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('refuses best-single-order selection when either order listing is paginated', async () => {
    const { gateway, service } = makeService();
    vi.spyOn(gateway, 'listOrders')
      .mockResolvedValueOnce({
        orders: gateway.orders,
        nextCursor: 'next-page',
        truncated: true
      })
      .mockResolvedValueOnce({
        orders: gateway.orders,
        nextCursor: null,
        truncated: false
      });

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '1'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'unsupported',
        envelope: null,
        reason: expect.stringContaining('complete order listing')
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('refuses best-single-order selection when a listing is truncated without a cursor', async () => {
    const { gateway, service } = makeService();
    vi.spyOn(gateway, 'listOrders')
      .mockResolvedValueOnce({
        orders: gateway.orders,
        nextCursor: null,
        truncated: true
      })
      .mockResolvedValueOnce({
        orders: gateway.orders,
        nextCursor: null,
        truncated: false
      });

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '1'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'unsupported',
        selection: null,
        envelope: null,
        reason: expect.stringContaining('complete order listing')
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('falls back to the next ranked order only when canonical preparation rejects the best', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order(),
      order({
        identity: {
          escrowContract: addresses.standard,
          localId: '8',
          handle: `cw_${addresses.standard.slice(2)}_8`
        },
        offerAmount: '10',
        requestAmount: '18',
        remainingOfferAmount: '10',
        remainingRequestAmount: '18',
        price: '1.8',
        updatedAt: '2026-07-27T00:00:01.000Z'
      })
    ];
    gateway.buildExecutionPlan.mockImplementation(async (intent) => {
      const plan = executionPlan(intent);
      return intent.action === 'fill' &&
        intent.order.identity.localId === '8'
        ? {
            ...plan,
            simulation: {
              ...plan.simulation,
              ok: false,
              warnings: ['The best order is unavailable to this wallet.'],
              errorCode: 'wallet_fill_history_ineligible'
            }
          }
        : plan;
    });

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '3'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        selection: {
          order: { localId: '7' },
          sellAmount: '6',
          buyAmount: '3'
        },
        intent: {
          order: { identity: { localId: '7' } }
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledTimes(2);
  });

  it('returns safe unsupported when canonical preparation rejects every ranked order', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order(),
      order({
        identity: {
          escrowContract: addresses.standard,
          localId: '8',
          handle: `cw_${addresses.standard.slice(2)}_8`
        },
        offerAmount: '10',
        requestAmount: '18',
        remainingOfferAmount: '10',
        remainingRequestAmount: '18',
        price: '1.8'
      })
    ];
    gateway.buildExecutionPlan.mockImplementation(async (intent) => {
      const plan = executionPlan(intent);
      return {
        ...plan,
        simulation: {
          ...plan.simulation,
          ok: false,
          warnings: ['Wallet eligibility could not be established.'],
          errorCode: 'wallet_fill_history_ineligible'
        }
      };
    });

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '3'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'unsupported',
        intent: null,
        selection: null,
        warnings: ['Wallet eligibility could not be established.'],
        envelope: null,
        reason: expect.stringContaining('canonical preparation')
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledTimes(2);
  });

  it('allows a final one-off fill regardless of partial-fill minimums', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        offerAmount: '10',
        requestAmount: '100',
        remainingOfferAmount: '1',
        remainingRequestAmount: '10',
        fillPolicy: {
          partialFillsAllowed: false,
          minPartialFillBps: 5_000,
          minRequestAmount: '25',
          maxRequestAmountPerWallet: null,
          oneFillPerWallet: false
        }
      })
    ];

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '1'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        selection: { source: 'one-off', sellAmount: '10', buyAmount: '1' }
      }
    });
  });

  it('requires partial fills and the largest configured one-off minimum for non-final fills', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        offerAmount: '10',
        requestAmount: '100',
        remainingOfferAmount: '10',
        remainingRequestAmount: '100',
        fillPolicy: {
          partialFillsAllowed: false,
          minPartialFillBps: 500,
          minRequestAmount: '3',
          maxRequestAmountPerWallet: null,
          oneFillPerWallet: false
        }
      })
    ];

    const partialDisabled = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '0.5'
    });
    expect(partialDisabled).toMatchObject({
      ok: true,
      data: { status: 'unsupported', envelope: null }
    });

    gateway.orders[0]!.fillPolicy!.partialFillsAllowed = true;
    const belowFivePercentOfOriginal = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '0.4'
    });
    expect(belowFivePercentOfOriginal).toMatchObject({
      ok: true,
      data: { status: 'unsupported', envelope: null }
    });

    const atFivePercentOfOriginal = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '0.5'
    });
    expect(atFivePercentOfOriginal).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        selection: { sellAmount: '5', buyAmount: '0.5' }
      }
    });
  });

  it('keeps the per-wallet amount guard and warns when fill history affects eligibility', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        fillPolicy: {
          partialFillsAllowed: true,
          minPartialFillBps: 0,
          minRequestAmount: null,
          maxRequestAmountPerWallet: '5',
          oneFillPerWallet: true
        }
      })
    ];

    const eligibleAmount = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '2'
    });
    expect(eligibleAmount).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        warnings: [
          expect.stringContaining('fill-history eligibility')
        ]
      }
    });

    const overMaximum = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '3'
    });
    expect(overMaximum).toMatchObject({
      ok: true,
      data: { status: 'unsupported', envelope: null }
    });
  });

  it('reports the actual recurring output after exact-buy input rounding', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.recurring,
          localId: '9',
          handle: `cw_${addresses.recurring.slice(2)}_9`
        },
        kind: 'recurring',
        recurring: {
          baseAsset,
          quoteAsset,
          buyPrice: null,
          sellPrice: null,
          buyBaseAmount: '0.000003',
          buyQuoteAmount: '0.000002',
          sellBaseAmount: '0.000003',
          sellQuoteAmount: '0.000002',
          buyQuoteLiquidity: '1',
          sellBaseLiquidity: '1',
          buySideOpen: true,
          sellSideOpen: true
        }
      })
    ];

    const result = await service.prepareSwap({
      wallet: addresses.wallet,
      sellAsset: 'QUOTE',
      buyAsset: 'BASE',
      inputMode: 'buy',
      amount: '0.000002'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          recurringSide: 'buy',
          inputAmount: '0.000002',
          minOutputAmount: '0.000003'
        },
        selection: {
          source: 'recurring',
          sellAmount: '0.000002',
          buyAmount: '0.000003'
        }
      }
    });
  });
});

describe('ChainWhisperDomainService preparation', () => {
  it('preserves the trusted legacy Standard route and prepares a fixed-recipient fill without inventing a canonical type', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        recipient: addresses.wallet,
        access: 'direct',
        legacyCompatibility: {
          kind: 'standard-recipient-bound',
          displayType:
            'Legacy one-off / fixed recipient / public terms',
          canonicalReplacementType: 'one-off.direct'
        },
        relation: {
          kind: 'primary',
          parentOrder: null,
          rootOrder: null,
          replacesOrder: null,
          replacementOrder: null
        }
      })
    ];

    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: {
        escrowContract: addresses.standard,
        localId: '7'
      },
      inputAmount: '5',
      minOutputAmount: '2'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          action: 'fill',
          inputAmount: '5',
          order: {
            legacyCompatibility: {
              kind: 'standard-recipient-bound',
              displayType:
                'Legacy one-off / fixed recipient / public terms'
            }
          }
        }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledWith(
      expect.objectContaining({
        order: expect.objectContaining({
          legacyCompatibility: expect.objectContaining({
            kind: 'standard-recipient-bound'
          })
        })
      })
    );
    const preparedIntent =
      gateway.buildExecutionPlan.mock.calls[0]?.[0];
    expect(preparedIntent).not.toHaveProperty('orderType');
  });

  it('derives exact legacy Standard counter acceptance from the trusted remaining amount', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        recipient: addresses.wallet,
        access: 'direct',
        legacyCompatibility: {
          kind: 'standard-recipient-bound',
          displayType:
            'Legacy one-off / fixed recipient / public terms',
          canonicalReplacementType: 'one-off.direct'
        },
        relation: {
          kind: 'counter',
          parentOrder: {
            escrowContract: addresses.standard,
            localId: '3',
            handle: `cw_${addresses.standard.slice(2)}_3`
          },
          rootOrder: null,
          replacesOrder: null,
          replacementOrder: null
        }
      })
    ];

    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: {
        escrowContract: addresses.standard,
        localId: '7'
      }
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          action: 'fill',
          inputAmount: '20',
          minOutputAmount: null
        }
      }
    });
    if (!result.ok) throw new Error('Expected legacy counter preparation.');
    expect(result.data.intent).not.toHaveProperty('orderType');
  });

  it('returns editable missing fields instead of rejecting an incomplete useful trade draft', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      offerAsset: 'BASE',
      requestAsset: 'QUOTE'
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'needs_input',
        intent: { action: 'create_trade', offerAsset: { symbol: 'BASE' }, requestAsset: { symbol: 'QUOTE' } },
        missing: [
          { field: 'wallet' },
          { field: 'offerAmount' },
          { field: 'requestAmount' }
        ],
        envelope: null
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('derives the canonical order type from economic create fields', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      access: 'public',
      liquidityVisibility: 'visible'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          orderType: { id: 'one-off.standard-public' },
          access: 'public',
          amountVisibility: 'visible'
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it.each([
    ['orderType', 'one-off.direct'],
    ['amountVisibility', 'private']
  ] as const)('rejects the removed create alias %s', async (field, value) => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      [field]: value
    } as never);

    expect(result).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: `input.${field}` }]
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it.each([
    ['one-off.standard-public', 'public', undefined, { kind: 'none' }],
    ['one-off.unlisted', 'unlisted', undefined, { kind: 'generate-local', share: 'encrypted-coti-message-only' }],
    ['one-off.direct', 'direct', addresses.recipient, { kind: 'recipient-bound', recipient: addresses.recipient }]
  ] as const)('derives the explicit %s route without accepting an access secret', async (orderType, access, recipient, policy) => {
    const { service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      access,
      recipient
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          access,
          orderType: { id: orderType },
          secretPolicy: policy
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
  });

  it('preserves committed confidential artifact plans for signer-local materialization', async () => {
    const { gateway, service } = makeService();
    gateway.buildExecutionPlan.mockImplementationOnce(async (intent) => {
      const plan = executionPlan(intent);
      return {
        ...plan,
        steps: [
          {
            id: 'approve-p-base',
            kind: 'approval',
            approvalScheme: 'coti-private-exact',
            contract: addresses.privateBase,
            token: addresses.privateBase,
            amount: '0',
            description: 'Set the exact private p.BASE allowance.',
            nativeValue: '0',
            privateArtifactGroups: [
              {
                id: 'private-allowance-p-base',
                recipe: 'coti-private-exact-allowance-v1',
                values: [
                  {
                    id: 'offer-amount',
                    kind: 'uint256',
                    source: 'intent-sell-amount',
                    asset: privateBaseAsset
                  }
                ],
                outputs: [
                  {
                    kind: 'coti-private-exact-allowance',
                    valueId: 'offer-amount',
                    jsonPointer: '/arguments/1'
                  }
                ]
              }
            ]
          },
          ...plan.steps
        ],
        simulation: {
          ...plan.simulation,
          deferredPrivateArtifacts: true,
          warnings: ['Signer-local materialization required.']
        }
      };
    });
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      access: 'public'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        envelope: { version: 'ActionEnvelopeV1' },
        warnings: ['Signer-local materialization required.']
      }
    });
  });

  it('keeps a direct draft useful while the recipient is still missing', async () => {
    const { service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      access: 'direct'
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'needs_input',
        missing: [{ field: 'recipient' }],
        envelope: null
      }
    });
  });

  it('supports private-liquidity drafts only with a private offered asset and signer-local amounts', async () => {
    const { gateway, service } = makeService();
    const invalid = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      liquidityVisibility: 'private'
    });
    expect(invalid).toMatchObject({ ok: false, error: { code: 'invalid_input' } });

    const leaked = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'p.BASE',
      requestAsset: 'QUOTE',
      offerAmount: '987654.321',
      requestAmount: '123456.789',
      liquidityVisibility: 'private'
    });
    expect(leaked).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        message: expect.stringContaining('local signer')
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();

    const valid = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'p.BASE',
      requestAsset: 'QUOTE',
      liquidityVisibility: 'private'
    });
    expect(valid).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          amountVisibility: 'private',
          offerAmount: null,
          requestAmount: null,
          fillPolicy: {
            minRequestAmount: null,
            maxRequestAmountPerWallet: null
          }
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(JSON.stringify(valid)).not.toContain('987654.321');
    expect(JSON.stringify(valid)).not.toContain('123456.789');
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('binds explicitly agent-provided private amounts into the prepared intent', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'p.BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1.25',
      requestAmount: '2.5',
      liquidityVisibility: 'private',
      privateAmountMode: 'agent-provided'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          amountVisibility: 'private',
          privateAmountMode: 'agent-provided',
          offerAmount: '1.25',
          requestAmount: '2.5'
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledWith(
      expect.objectContaining({
        privateAmountMode: 'agent-provided',
        offerAmount: '1.25',
        requestAmount: '2.5'
      })
    );
  });

  it.each([
    ['unlisted', undefined],
    ['direct', addresses.recipient]
  ] as const)(
    'keeps private-token amounts signer-local for %s creation',
    async (access, recipient) => {
      const { gateway, service } = makeService();
      const leaked = await service.prepareCreateTrade({
        wallet: addresses.wallet,
        offerAsset: 'p.BASE',
        requestAsset: 'QUOTE',
        offerAmount: '987654.321',
        requestAmount: '2',
        access,
        recipient
      });
      expect(leaked).toMatchObject({
        ok: false,
        error: {
          code: 'invalid_input',
          details: [{ field: 'offerAmount' }]
        }
      });

      const valid = await service.prepareCreateTrade({
        wallet: addresses.wallet,
        offerAsset: 'p.BASE',
        requestAsset: 'QUOTE',
        requestAmount: '2',
        access,
        recipient
      });
      expect(valid).toMatchObject({
        ok: true,
        data: {
          status: 'ready',
          intent: {
            offerAmount: null,
            requestAmount: '2'
          },
          envelope: { version: 'ActionEnvelopeV1' }
        }
      });
      expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
    }
  );

  it('keeps explicitly visible private-token trade amounts in the signed plan', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'p.BASE',
      requestAsset: 'QUOTE',
      offerAmount: '987654.321',
      requestAmount: '123456.789'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          offerAmount: '987654.321',
          requestAmount: '123456.789'
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('uses quote-per-base recurring prices and disables recurring writes when audit compatibility is pending', async () => {
    const { gateway, service } = makeService();
    gateway.currentStatus = status(false);
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '100'
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'unsupported',
        intent: { buyPrice: '1.9', sellPrice: '2.1', buyQuoteLiquidity: '100' },
        reason: expect.stringContaining('runtime manifest')
      }
    });
  });

  it('rejects a recipient on an unlisted order instead of silently dropping it', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateTrade({
      wallet: addresses.wallet,
      offerAsset: 'BASE',
      requestAsset: 'QUOTE',
      offerAmount: '1',
      requestAmount: '2',
      access: 'unlisted',
      recipient: addresses.recipient
    });

    expect(result).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: 'recipient' }]
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('resolves recurring buy and sell prices from signed market-reference offsets', async () => {
    const { gateway, service } = makeService();
    gateway.references = [
      {
        id: 'carbon-base-quote',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:00.000Z',
        executable: false,
        liquidityChecked: false
      }
    ];

    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: { reference: 'market', offsetBps: -1000 },
      sellPrice: { reference: 'market', offsetBps: 1000 },
      buyQuoteLiquidity: '10',
      sellBaseLiquidity: '10',
      liquidityVisibility: 'visible'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          orderType: { id: 'recurring.public' },
          buyPrice: '1.8',
          sellPrice: '2.2',
          priceReference: {
            id: 'carbon-base-quote',
            venue: 'carbon',
            price: '2',
            buyOffsetBps: -1000,
            sellOffsetBps: 1000
          }
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('prepares the exact private p.WISP/p.COTI recurring strategy an autonomous agent chose', async () => {
    const { gateway, service } = makeService();
    gateway.references = [
      {
        id: 'chainwhisper-pwisp-pcoti',
        venue: 'carbon',
        source: 'market',
        baseAsset: privateWispAsset,
        quoteAsset: privateCotiAsset,
        price: '1',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:00.000Z',
        executable: false,
        liquidityChecked: false
      }
    ];

    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'p.WISP',
      quoteAsset: 'p.COTI',
      buyPrice: { reference: 'market', offsetBps: -1000 },
      sellPrice: { reference: 'market', offsetBps: 1000 },
      buyQuoteLiquidity: '10',
      sellBaseLiquidity: '10',
      liquidityVisibility: 'private',
      privateAmountMode: 'agent-provided'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          orderType: {
            id: 'recurring.private-liquidity.public',
            assetPrivacy: 'fully-private'
          },
          amountVisibility: 'private',
          privateAmountMode: 'agent-provided',
          buyPrice: '0.9',
          sellPrice: '1.1',
          buyQuoteLiquidity: '10',
          sellBaseLiquidity: '10',
          priceReference: {
            id: 'chainwhisper-pwisp-pcoti',
            price: '1',
            buyOffsetBps: -1000,
            sellOffsetBps: 1000
          }
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('rounds market-derived buy and sell prices in the maker-safe direction', async () => {
    const { gateway, service } = makeService();
    gateway.references = [
      {
        id: 'carbon-precision',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '1.23456789',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:00:30.000Z',
        executable: false,
        liquidityChecked: false
      }
    ];

    await expect(service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: { reference: 'market', offsetBps: 0 },
      sellPrice: { reference: 'market', offsetBps: 0 },
      buyQuoteLiquidity: '10'
    })).resolves.toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          buyPrice: '1.234567',
          sellPrice: '1.234568'
        }
      }
    });
  });

  it('rejects stale, expired, future, and malformed recurring market references', async () => {
    const now = Date.parse('2026-07-27T00:10:00.000Z');
    const { gateway, service } = makeService(() => now);
    gateway.references = [
      {
        id: 'stale',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:04:59.999Z',
        executable: false,
        liquidityChecked: false
      },
      {
        id: 'expired',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:09:00.000Z',
        expiresAt: '2026-07-27T00:09:59.999Z',
        executable: false,
        liquidityChecked: false
      },
      {
        id: 'future',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: '2026-07-27T00:10:30.001Z',
        executable: false,
        liquidityChecked: false
      },
      {
        id: 'malformed',
        venue: 'carbon',
        source: 'market',
        baseAsset,
        quoteAsset,
        price: '2',
        basis: 'quote_per_base',
        observedAt: 'not-a-date',
        executable: false,
        liquidityChecked: false
      }
    ];

    await expect(service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: { reference: 'market', offsetBps: -1000 },
      sellPrice: { reference: 'market', offsetBps: 1000 },
      buyQuoteLiquidity: '10'
    })).resolves.toMatchObject({
      ok: false,
      error: {
        code: 'provider_error',
        message: expect.stringContaining('No compatible live market reference')
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('returns missing recurring liquidity without rejecting the draft', async () => {
    const { service } = makeService();
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1'
    });
    expect(result).toMatchObject({
      ok: true,
      data: { status: 'needs_input', missing: [{ field: 'liquidity' }] }
    });
  });

  it('keeps audited public recurring creation executable when the runtime gate is enabled', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '100'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          access: 'public',
          amountVisibility: 'visible',
          buyQuoteLiquidity: '100'
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('keeps only the public side of hybrid private recurring inventory in the planner envelope', async () => {
    const { gateway, service } = makeService();
    const leaked = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'p.BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '998877.66',
      sellBaseLiquidity: '112233.44',
      liquidityVisibility: 'private'
    });
    expect(leaked).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: 'sellBaseLiquidity' }]
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();

    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'p.BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '998877.66',
      liquidityVisibility: 'private'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          amountVisibility: 'private',
          orderType: {
            id: 'recurring.private-liquidity.public',
            termsVisibility: 'hidden-liquidity'
          },
          buyQuoteLiquidity: '998877.66',
          sellBaseLiquidity: null
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(JSON.stringify(result)).not.toContain('112233.44');
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('keeps explicitly visible private-token recurring inventory in the signed plan', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'p.BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '887766.55',
      sellBaseLiquidity: '443322.11'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          buyQuoteLiquidity: '887766.55',
          sellBaseLiquidity: '443322.11'
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('handles explicit fixed-recipient recurring creation', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '100',
      access: 'direct',
      recipient: addresses.recipient
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          access: 'direct',
          orderType: { id: 'recurring.direct' }
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('rejects unsupported unlisted recurring access', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareCreateRecurring({
      wallet: addresses.wallet,
      baseAsset: 'BASE',
      quoteAsset: 'QUOTE',
      buyPrice: '1.9',
      sellPrice: '2.1',
      buyQuoteLiquidity: '100',
      access: 'unlisted'
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: 'invalid_input' }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('derives an explicit Direct counter type and prepares the allowlisted counter write', async () => {
    const { service } = makeService();
    const result = await service.prepareCounter({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.standard, localId: '7' },
      offerAmount: '20',
      requestAmount: '9',
      expiresAt: '2026-07-28T12:00:00.000Z'
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          action: 'counter',
          orderType: {
            id: 'one-off.direct',
            relation: 'counter',
            route: 'direct-escrow'
          },
          offerAsset: { symbol: 'QUOTE' },
          requestAsset: { symbol: 'BASE' },
          recipient: addresses.maker,
          access: 'direct'
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
  });

  it.each([
    ['primary', 'Only the fixed recipient can counter this Direct order.'],
    ['counter', 'Only the recipient of a Direct counter can supersede it.']
  ] as const)(
    'rejects a non-recipient wallet for a Direct %s order counter',
    async (relation, message) => {
      const { gateway, service } = makeService();
      gateway.orders = [
        order({
          identity: {
            escrowContract: addresses.direct,
            localId: '12',
            handle: `cw_${addresses.direct.slice(2)}_12`
          },
          access: 'direct',
          recipient: addresses.recipient,
          relation: {
            kind: relation,
            parentOrder:
              relation === 'counter'
                ? {
                    escrowContract: addresses.standard,
                    localId: '7',
                    handle: `cw_${addresses.standard.slice(2)}_7`
                  }
                : null,
            rootOrder: null,
            replacesOrder: null,
            replacementOrder: null
          }
        })
      ];
      const result = await service.prepareCounter({
        wallet: addresses.wallet,
        order: {
          escrowContract: addresses.direct,
          localId: '12'
        },
        offerAmount: '20',
        requestAmount: '9',
        expiresAt: '2026-07-28T12:00:00.000Z'
      });
      expect(result).toMatchObject({
        ok: false,
        error: {
          code: 'invalid_input',
          message,
          details: [{ field: 'wallet' }]
        }
      });
      expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
    }
  );

  it('rejects confidential counter inputs and prepares them through signer-local collection', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '15',
          handle: `cw_${addresses.privateEscrow.slice(2)}_15`
        },
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null,
        remainingOfferAmount: null,
        remainingRequestAmount: null
      })
    ];
    const leaked = await service.prepareCounter({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.privateEscrow, localId: '15' },
      offerAmount: '556677.88',
      requestAmount: '998811.22',
      expiresAt: '2026-07-28T12:00:00.000Z'
    });
    expect(leaked).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: 'offerAmount' }]
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();

    const result = await service.prepareCounter({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.privateEscrow, localId: '15' },
      expiresAt: '2026-07-28T12:00:00.000Z'
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          offerAmount: null,
          requestAmount: null
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(JSON.stringify(result)).not.toContain('556677.88');
    expect(JSON.stringify(result)).not.toContain('998811.22');
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('keeps hidden private-token fill amounts out of the planner request and intent', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '8',
          handle: `cw_${addresses.privateEscrow.slice(2)}_8`
        },
        access: 'unlisted',
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null,
        remainingOfferAmount: null,
        remainingRequestAmount: null
      })
    ];
    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: {
        escrowContract: addresses.privateEscrow,
        localId: '8'
      }
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          inputAmount: null,
          minOutputAmount: null,
          secretPolicy: {
            kind: 'resolve-from-local-vault'
          }
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('rejects a raw confidential fill amount before it can enter an envelope', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '8',
          handle: `cw_${addresses.privateEscrow.slice(2)}_8`
        },
        access: 'unlisted',
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null
      })
    ];
    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: {
        escrowContract: addresses.privateEscrow,
        localId: '8'
      },
      inputAmount: '123.456'
    });

    expect(result).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        message: expect.stringContaining('local signer')
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('derives a visible Direct private-token fill amount from trusted order data instead of echoing tool input', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.direct,
          localId: '9',
          handle: `cw_${addresses.direct.slice(2)}_9`
        },
        access: 'direct',
        recipient: addresses.wallet,
        requestAsset: privateQuoteAsset,
        requestAmount: '20',
        remainingRequestAmount: '20'
      })
    ];
    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: {
        escrowContract: addresses.direct,
        localId: '9'
      }
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          inputAmount: null,
          minOutputAmount: null
        },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(JSON.stringify(result)).not.toContain('"inputAmount":"20"');
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('rejects a Direct private-token output limit from the keyless fill request', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.direct,
          localId: '10',
          handle: `cw_${addresses.direct.slice(2)}_10`
        },
        access: 'direct',
        recipient: addresses.wallet,
        offerAsset: privateBaseAsset,
        requestAsset: quoteAsset,
        offerAmount: '10',
        requestAmount: '20',
        remainingOfferAmount: '10',
        remainingRequestAmount: '20'
      })
    ];

    const leaked = await service.prepareFill({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.direct, localId: '10' },
      inputAmount: '2',
      minOutputAmount: '0.9'
    });
    expect(leaked).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: 'minOutputAmount' }]
      }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();

    const valid = await service.prepareFill({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.direct, localId: '10' },
      inputAmount: '2'
    });
    expect(valid).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          inputAmount: '2',
          minOutputAmount: null
        }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('keeps a public visible fill executable', async () => {
    const { gateway, service } = makeService();
    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.standard, localId: '7' },
      inputAmount: '2'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          inputAmount: '2',
          order: {
            access: 'public',
            amountVisibility: 'visible'
          }
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it.each([
    ['unlisted', addresses.direct, null],
    ['direct', addresses.direct, addresses.wallet]
  ] as const)('keeps an audited visible public-token %s fill executable', async (
    access,
    escrowContract,
    recipient
  ) => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract,
          localId: '14',
          handle: `cw_${escrowContract.slice(2)}_14`
        },
        access,
        recipient
      })
    ];

    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: { escrowContract, localId: '14' },
      inputAmount: '2'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: { order: { access } },
        missing: [],
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('rejects raw confidential edit amounts before they can enter an envelope', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '12',
          handle: `cw_${addresses.privateEscrow.slice(2)}_12`
        },
        access: 'unlisted',
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null,
        remainingOfferAmount: null,
        remainingRequestAmount: null
      })
    ];

    const result = await service.prepareEdit({
      wallet: addresses.maker,
      order: { escrowContract: addresses.privateEscrow, localId: '12' },
      changes: {
        offerAmount: '998877.66',
        requestAmount: '112233.44'
      }
    });

    expect(result).toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        message: expect.stringContaining('local signer')
      }
    });
    expect(JSON.stringify(result)).not.toContain('998877.66');
    expect(JSON.stringify(result)).not.toContain('112233.44');
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('prepares a confidential replacement only through the explicit signer-local flag', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '12',
          handle: `cw_${addresses.privateEscrow.slice(2)}_12`
        },
        orderType: {
          id: 'one-off.private-liquidity.unlisted',
          cadence: 'one-off',
          route: 'private-liquidity-escrow',
          access: 'unlisted',
          termsVisibility: 'hidden-liquidity',
          assetPrivacy: 'fully-private',
          relation: 'primary'
        },
        access: 'unlisted',
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null,
        remainingOfferAmount: null,
        remainingRequestAmount: null
      })
    ];

    const result = await service.prepareEdit({
      wallet: addresses.maker,
      order: {
        escrowContract: addresses.privateEscrow,
        localId: '12'
      },
      changes: {
        replaceConfidentialTerms: true,
        expiresAt: '2026-07-28T12:00:00.000Z'
      }
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          orderType: {
            id: 'one-off.private-liquidity.unlisted',
            relation: 'replacement'
          },
          changes: {
            replaceConfidentialTerms: true
          }
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('keeps an audited lifecycle update executable without exposing confidential order values', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '13',
          handle: `cw_${addresses.privateEscrow.slice(2)}_13`
        },
        access: 'unlisted',
        amountVisibility: 'private',
        offerAsset: privateBaseAsset,
        requestAsset: privateQuoteAsset,
        offerAmount: null,
        requestAmount: null,
        remainingOfferAmount: null,
        remainingRequestAmount: null
      })
    ];

    const result = await service.prepareOrderUpdate({
      wallet: addresses.maker,
      order: { escrowContract: addresses.privateEscrow, localId: '13' },
      update: 'cancel'
    });

    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: {
          action: 'order_update',
          update: 'cancel',
          order: {
            offerAmount: null,
            requestAmount: null,
            remainingOfferAmount: null,
            remainingRequestAmount: null
          }
        },
        envelope: { version: 'ActionEnvelopeV1' }
      }
    });
    expect(gateway.buildExecutionPlan).toHaveBeenCalledOnce();
  });

  it('returns missing fill amount and recurring side as editable details', async () => {
    const { gateway, service } = makeService();
    gateway.orders = [
      order({
        identity: {
          escrowContract: addresses.recurring,
          localId: '3',
          handle: `cw_${addresses.recurring.slice(2)}_3`
        },
        kind: 'recurring',
        recurring: {
          baseAsset,
          quoteAsset,
          buyPrice: '1.9',
          sellPrice: '2.1',
          buyQuoteLiquidity: '100',
          sellBaseLiquidity: '50',
          buySideOpen: true,
          sellSideOpen: true
        }
      })
    ];
    const result = await service.prepareFill({
      wallet: addresses.wallet,
      order: { escrowContract: addresses.recurring, localId: '3' }
    });
    expect(result).toMatchObject({
      ok: true,
      data: {
        status: 'needs_input',
        missing: [{ field: 'inputAmount' }, { field: 'recurringSide' }]
      }
    });
  });

  it('rejects precision overflow, JSON numeric amounts, untrusted contracts, and credentials', async () => {
    const { service } = makeService();
    await expect(
      service.prepareCreateTrade({
        wallet: addresses.wallet,
        offerAsset: 'BASE',
        requestAsset: 'QUOTE',
        offerAmount: 1 as unknown as string
      })
    ).resolves.toMatchObject({ ok: false, error: { code: 'invalid_input' } });
    await expect(
      service.prepareCreateTrade({
        wallet: addresses.wallet,
        offerAsset: 'BASE',
        requestAsset: 'QUOTE',
        offerAmount: '1.0000001'
      })
    ).resolves.toMatchObject({ ok: false, error: { code: 'invalid_input' } });
    await expect(
      service.getOrder({
        order: {
          escrowContract: '0xdddddddddddddddddddddddddddddddddddddddd',
          localId: '1'
        }
      })
    ).resolves.toMatchObject({ ok: false, error: { code: 'invalid_input' } });
    await expect(
      service.prepareFill({
        order: { escrowContract: addresses.standard, localId: '7' },
        accessSecret: `0x${'4'.repeat(64)}`
      } as never)
    ).resolves.toMatchObject({ ok: false, error: { code: 'invalid_input' } });
  });

  it('requires a wallet for filler history and forwards the exact filler role', async () => {
    const { gateway, service } = makeService();
    const listSpy = vi.spyOn(gateway, 'listOrders');

    await expect(
      service.listOrders({ role: 'filler', status: 'all' })
    ).resolves.toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: [{ field: 'wallet' }]
      }
    });

    await expect(
      service.listOrders({
        wallet: addresses.wallet,
        role: 'filler',
        status: 'all'
      })
    ).resolves.toMatchObject({ ok: true });
    expect(listSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        wallet: addresses.wallet,
        role: 'filler',
        status: 'all'
      })
    );
  });
});

describe('domain tool surface', () => {
  it('exposes exactly the allowlisted public tools and no arbitrary transaction tool', () => {
    const { service } = makeService();
    const tools = createChainWhisperDomainTools(service);
    const names = tools.map((tool) => tool.name);
    expect(names).toEqual([
      'chainwhisper_order_types',
      'chainwhisper_status',
      'chainwhisper_list_orders',
      'chainwhisper_get_order',
      'chainwhisper_compare_price_references',
      'chainwhisper_prepare_swap',
      'chainwhisper_privacy_bridge_status',
      'chainwhisper_prepare_privacy_bridge',
      'chainwhisper_prepare_create_trade',
      'chainwhisper_prepare_create_recurring',
      'chainwhisper_prepare_fill',
      'chainwhisper_prepare_counter',
      'chainwhisper_prepare_edit',
      'chainwhisper_prepare_order_update'
    ]);
    expect(names.join(' ')).not.toMatch(/calldata|abi|admin|approve/u);
    const publicSchemas = JSON.stringify(
      tools.map(({ name, description, inputSchema }) => ({
        name,
        description,
        inputSchema
      }))
    );
    expect(publicSchemas).not.toMatch(
      /accessSecret|privateKey|mnemonic|hiddenAmount|privateLiquidityAmount/u
    );
    expect(publicSchemas).toContain('liquidityVisibility');
    expect(publicSchemas).not.toContain('recurring.private-liquidity.direct');
    expect(publicSchemas).toContain(
      'including private-token amounts on public Standard and explicitly labeled legacy Standard orders'
    );
    expect(publicSchemas).toContain(
      'visibly bound private-token amounts when superseding an explicitly labeled legacy Standard counter'
    );
    expect(publicSchemas).toContain(
      'agent-provided binds agent-visible private values'
    );

    const tradeSchema = tools.find(
      (tool) => tool.name === 'chainwhisper_prepare_create_trade'
    )?.inputSchema as {
      required?: string[];
      properties?: Record<string, unknown>;
    };
    expect(tradeSchema.required ?? []).not.toContain('orderType');
    expect(tradeSchema.properties).toHaveProperty('access');
    expect(tradeSchema.properties).toHaveProperty('liquidityVisibility');
    expect(tradeSchema.properties).not.toHaveProperty('orderType');
    expect(tradeSchema.properties).not.toHaveProperty('amountVisibility');

    const recurringSchema = tools.find(
      (tool) => tool.name === 'chainwhisper_prepare_create_recurring'
    )?.inputSchema as {
      required?: string[];
      properties?: Record<string, unknown>;
    };
    expect(recurringSchema.required ?? []).not.toContain('orderType');
    expect(recurringSchema.properties).toHaveProperty('liquidityVisibility');
    expect(recurringSchema.properties).not.toHaveProperty('access');
    expect(recurringSchema.properties).not.toHaveProperty('recipient');
    expect(recurringSchema.properties).not.toHaveProperty('orderType');
    expect(recurringSchema.properties).not.toHaveProperty('amountVisibility');
  });

  it('explains every actual canonical order type without inventing recurring unlisted variants', async () => {
    const { service } = makeService();
    const tool = createChainWhisperDomainTools(service).find(
      ({ name }) => name === 'chainwhisper_order_types'
    );
    expect(tool).toBeDefined();
    const result = await tool!.execute({});
    expect(result).toMatchObject({
      ok: true,
      data: {
        version: 'OrderTypeCatalogV1',
        orderTypes: expect.arrayContaining([
          expect.objectContaining({
            id: 'one-off.private-liquidity.direct',
            supported: true
          })
        ])
      }
    });
    if (!result.ok) throw new Error('Expected the order-type catalog.');
    const orderTypes = (result.data as {
      orderTypes: Array<{ id: string; liquidity: string }>;
    }).orderTypes;
    expect(orderTypes).toHaveLength(8);
    expect(
      orderTypes.some(
        ({ id }) =>
          id === 'recurring.unlisted' ||
          id === 'recurring.private-liquidity.unlisted' ||
          id === 'recurring.direct' ||
          id === 'recurring.private-liquidity.direct'
      )
    ).toBe(false);
    expect(
      orderTypes.find(
        ({ id }) => id === 'recurring.private-liquidity.public'
      )
    ).toMatchObject({
      liquidity: 'private-token sides hidden; public-token sides visible'
    });
  });

  it('keeps direct-recipient recurring creation outside the public MCP call surface', async () => {
    const { service } = makeService();
    const tool = createChainWhisperDomainTools(service).find(
      ({ name }) => name === 'chainwhisper_prepare_create_recurring'
    )!;
    await expect(
      tool.execute({
        wallet: addresses.wallet,
        orderType: 'recurring.direct',
        baseAsset: 'BASE',
        quoteAsset: 'QUOTE',
        buyPrice: '1.9',
        sellPrice: '2.1',
        buyQuoteLiquidity: '10',
        recipient: addresses.recipient
      })
    ).resolves.toMatchObject({
      ok: false,
      error: {
        code: 'invalid_input',
        details: expect.arrayContaining([
          expect.objectContaining({ field: 'input.orderType' }),
          expect.objectContaining({ field: 'input.recipient' })
        ])
      }
    });
  });

  it('caps lists and removes hidden amounts from gateway DTOs', async () => {
    const { gateway, service } = makeService();
    gateway.orders = Array.from({ length: 25 }, (_, index) =>
      order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: String(index + 1),
          handle: `cw_${addresses.privateEscrow.slice(2)}_${index + 1}`
        },
        amountVisibility: 'private',
        offerAmount: '999',
        requestAmount: '888',
        remainingOfferAmount: '777',
        remainingRequestAmount: '666'
      })
    );
    const result = await service.listOrders({ limit: 100 });
    expect(result).toMatchObject({ ok: true, data: { truncated: true } });
    if (result.ok) {
      expect(result.data.orders).toHaveLength(20);
      expect(result.data.orders[0]).toMatchObject({ offerAmount: null, requestAmount: null });
    }
  });
});
