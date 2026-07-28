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
  privateQuote:
    '0xcccccccccccccccccccccccccccccccccccccccc' as Address
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

const privateQuoteAsset: ResolvedAsset = {
  id: addresses.privateQuote,
  kind: 'private-erc20',
  symbol: 'p.QUOTE',
  decimals: 6,
  address: addresses.privateQuote,
  verified: true,
  publicCounterpart: {
    symbol: quoteAsset.symbol,
    address: addresses.quote
  }
};

const status: DomainStatus = {
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
    recurringWritesEnabled: true,
    verifiedAt: '2026-07-28T00:00:00.000Z',
    warnings: []
  },
  capabilities: {
    reads: true,
    priceReferences: true,
    unsignedPlanning: true,
    recurringWrites: true
  }
};

const order = (
  overrides: Partial<SafeOrderSummary> = {}
): SafeOrderSummary => ({
  identity: {
    escrowContract: addresses.standard,
    localId: '7',
    handle: `cw_${addresses.standard.slice(2)}_7`
  },
  kind: 'trade',
  status: 'open',
  maker: addresses.maker,
  recipient: addresses.recipient,
  access: 'direct',
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
  updatedAt: '2026-07-28T00:00:00.000Z',
  snapshotHash: `0x${'2'.repeat(64)}`,
  ...overrides
});

const recurringOrder = (
  orderStatus: SafeOrderSummary['status']
): SafeOrderSummary =>
  order({
    identity: {
      escrowContract: addresses.recurring,
      localId: '9',
      handle: `cw_${addresses.recurring.slice(2)}_9`
    },
    kind: 'recurring',
    status: orderStatus,
    recipient: null,
    access: 'public'
  });

class LifecycleGateway implements DomainGateway {
  currentOrder: SafeOrderSummary = order();
  buildExecutionPlan = vi.fn(
    async (intent: DomainIntent): Promise<DomainExecutionPlan> => ({
      wallet: intent.wallet!,
      registry: status.registry,
      steps: [
        {
          id: 'update-order',
          kind: 'protocol',
          contract: intent.order.identity.escrowContract,
          description: 'Apply the allowlisted lifecycle update.',
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
        expectedResult: 'Lifecycle update prepared.',
        warnings: []
      },
      expiresAt: '2026-07-28T00:15:00.000Z'
    })
  );

  async getStatus() {
    return status;
  }

  async isTrustedEscrow(address: Address) {
    return Object.values(status.registry.contracts).includes(address);
  }

  async resolveAsset() {
    return null;
  }

  async listOrders() {
    return { orders: [this.currentOrder], nextCursor: null, truncated: false };
  }

  async getOrder() {
    return this.currentOrder;
  }

  async getPriceReferences() {
    return [];
  }
}

const envelopeFactory: DomainEnvelopeFactory = {
  async create(intent, execution) {
    return {
      version: 'ActionEnvelopeV1',
      operationId: `op-${intent.action}`,
      operationHash: `0x${'3'.repeat(64)}`,
      expiresAt: execution.expiresAt,
      summary: 'Lifecycle update prepared.',
      payload: { intent, execution }
    };
  }
};

const makeService = () => {
  const gateway = new LifecycleGateway();
  return {
    gateway,
    service: new ChainWhisperDomainService(gateway, envelopeFactory)
  };
};

describe('lifecycle role and state hardening', () => {
  it('normalizes close to maker cancellation or recipient decline', async () => {
    const { service } = makeService();

    const maker = await service.prepareOrderUpdate({
      wallet: addresses.maker,
      order: { escrowContract: addresses.standard, localId: '7' },
      update: 'close'
    });
    const recipient = await service.prepareOrderUpdate({
      wallet: addresses.recipient,
      order: { escrowContract: addresses.standard, localId: '7' },
      update: 'close'
    });

    expect(maker).toMatchObject({
      ok: true,
      data: { status: 'ready', intent: { update: 'cancel' } }
    });
    expect(recipient).toMatchObject({
      ok: true,
      data: { status: 'ready', intent: { update: 'decline' } }
    });
  });

  it('rejects lifecycle actions from the wrong wallet role', async () => {
    const { gateway, service } = makeService();

    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.wallet,
        order: { escrowContract: addresses.standard, localId: '7' },
        update: 'cancel'
      })
    ).resolves.toMatchObject({
      ok: false,
      error: { message: expect.stringContaining('Only the maker') }
    });
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.standard, localId: '7' },
        update: 'decline'
      })
    ).resolves.toMatchObject({
      ok: false,
      error: { message: expect.stringContaining('fixed recipient') }
    });
    expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();
  });

  it('enforces recurring pause, resume, cancel, and settlement states', async () => {
    const { gateway, service } = makeService();

    gateway.currentOrder = recurringOrder('open');
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.recurring, localId: '9' },
        update: 'pause'
      })
    ).resolves.toMatchObject({ ok: true, data: { status: 'ready' } });

    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.recurring, localId: '9' },
        update: 'resume'
      })
    ).resolves.toMatchObject({
      ok: false,
      error: { message: expect.stringContaining('paused recurring') }
    });

    gateway.currentOrder = recurringOrder('paused');
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.recurring, localId: '9' },
        update: 'resume'
      })
    ).resolves.toMatchObject({ ok: true, data: { status: 'ready' } });

    gateway.currentOrder = recurringOrder('cancelled');
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.recurring, localId: '9' },
        update: 'settle_inventory'
      })
    ).resolves.toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: { update: 'settle_inventory' }
      }
    });
  });

  it('allows permissionless expired reclaim but gates maker-only refresh and extension', async () => {
    const { gateway, service } = makeService();

    gateway.currentOrder = order({ status: 'expired' });
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.wallet,
        order: { escrowContract: addresses.standard, localId: '7' },
        update: 'reclaim_expired'
      })
    ).resolves.toMatchObject({ ok: true, data: { status: 'ready' } });

    gateway.currentOrder = order({
      identity: {
        escrowContract: addresses.direct,
        localId: '8',
        handle: `cw_${addresses.direct.slice(2)}_8`
      }
    });
    await expect(
      service.prepareOrderUpdate({
        wallet: addresses.maker,
        order: { escrowContract: addresses.direct, localId: '8' },
        update: 'refresh'
      })
    ).resolves.toMatchObject({
      ok: false,
      error: { message: expect.stringContaining('standard or private-liquidity') }
    });
  });

  it('publishes settle_inventory in the bounded update schema', () => {
    const { service } = makeService();
    const tool = createChainWhisperDomainTools(service).find(
      (candidate) =>
        candidate.name === 'chainwhisper_prepare_order_update'
    );
    expect(JSON.stringify(tool?.inputSchema)).toContain('settle_inventory');
  });
});

describe('signer-local edit privacy gates', () => {
  it.each([
    {
      label: 'private-liquidity',
      value: order({
        identity: {
          escrowContract: addresses.privateEscrow,
          localId: '10',
          handle: `cw_${addresses.privateEscrow.slice(2)}_10`
        },
        amountVisibility: 'private',
        offerAsset: privateQuoteAsset,
        requestAsset: baseAsset,
        orderType: {
          id: 'one-off.private-liquidity.unlisted',
          cadence: 'one-off',
          route: 'private-liquidity-escrow',
          access: 'unlisted',
          termsVisibility: 'hidden-liquidity',
          assetPrivacy: 'hybrid-private',
          relation: 'primary'
        }
      })
    },
    {
      label: 'Direct',
      value: order({
        identity: {
          escrowContract: addresses.direct,
          localId: '11',
          handle: `cw_${addresses.direct.slice(2)}_11`
        },
        orderType: {
          id: 'one-off.direct',
          cadence: 'one-off',
          route: 'direct-escrow',
          access: 'direct',
          termsVisibility: 'direct-private-terms',
          assetPrivacy: 'public-only',
          relation: 'primary'
        }
      })
    }
  ])(
    'requires replaceConfidentialTerms for $label edits',
    async ({ value }) => {
      const { gateway, service } = makeService();
      gateway.currentOrder = value;

      const missing = await service.prepareEdit({
        wallet: addresses.maker,
        order: {
          escrowContract: value.identity.escrowContract,
          localId: value.identity.localId
        },
        changes: { expiresAt: '2026-08-01T12:00:00Z' }
      });
      expect(missing).toMatchObject({
        ok: true,
        data: {
          status: 'needs_input',
          missing: [{ field: 'changes.replaceConfidentialTerms' }]
        }
      });
      expect(gateway.buildExecutionPlan).not.toHaveBeenCalled();

      const ready = await service.prepareEdit({
        wallet: addresses.maker,
        order: {
          escrowContract: value.identity.escrowContract,
          localId: value.identity.localId
        },
        changes: {
          expiresAt: '2026-08-01T12:00:00Z',
          replaceConfidentialTerms: true
        }
      });
      expect(ready).toMatchObject({
        ok: true,
        data: {
          status: 'ready',
          intent: {
            changes: { replaceConfidentialTerms: true }
          }
        }
      });
    }
  );

  it('routes private recurring inventory deltas to adjustPrivateLiquidity', async () => {
    const { gateway, service } = makeService();
    gateway.currentOrder = recurringOrder('open');
    gateway.currentOrder = order({
      ...gateway.currentOrder,
      amountVisibility: 'private',
      offerAsset: baseAsset,
      requestAsset: privateQuoteAsset,
      recurring: {
        baseAsset,
        quoteAsset: privateQuoteAsset,
        buyPrice: '2',
        sellPrice: '2.1',
        buyQuoteLiquidity: null,
        sellBaseLiquidity: '10',
        buySideOpen: true,
        sellSideOpen: true,
        privateQuoteInventory: true,
        privateBaseInventory: false
      }
    });

    const exposedAmount = await service.prepareEdit({
      wallet: addresses.maker,
      order: {
        escrowContract: addresses.recurring,
        localId: '9'
      },
      changes: {
        addBuyQuoteLiquidity: '5',
        adjustPrivateLiquidity: true
      }
    });
    expect(exposedAmount).toMatchObject({
      ok: false,
      error: {
        message: expect.stringContaining(
          'Private recurring inventory changes'
        ),
        details: [
          {
            field: 'changes.addBuyQuoteLiquidity',
            message: expect.stringContaining('adjustPrivateLiquidity')
          }
        ]
      }
    });

    const signerLocal = await service.prepareEdit({
      wallet: addresses.maker,
      order: {
        escrowContract: addresses.recurring,
        localId: '9'
      },
      changes: { adjustPrivateLiquidity: true }
    });
    expect(signerLocal).toMatchObject({
      ok: true,
      data: {
        status: 'ready',
        intent: { changes: { adjustPrivateLiquidity: true } }
      }
    });
  });
});
