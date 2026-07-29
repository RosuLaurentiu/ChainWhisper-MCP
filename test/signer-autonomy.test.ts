import { describe, expect, it } from 'vitest';

import {
  AUTONOMY_POLICY_VERSION,
  AutonomyPolicyManager,
  type AutonomyLocalApprovalHooks,
  type AutonomyPolicyProposalV1,
  type PolicyExposureV1,
  validateAutonomyPolicyProposal,
} from '../src/signer/autonomy.js';
import { ConfirmationGate } from '../src/signer/confirmation.js';
import { ControlPageAutonomyApprovals } from '../src/signer/controlAutonomyApprovals.js';
import {
  createEmptyAutonomyStoreSnapshot,
  type AuthenticatedEncryptedAutonomyStore,
  type AutonomyStoreSnapshotV1,
  type AutonomyStoreTransactionResult,
} from '../src/signer/autonomyStore.js';
import type {
  ConfirmationRequest,
  ConfirmationResult,
  FormElicitor,
} from '../src/signer/types.js';

const WALLET = '0x1111111111111111111111111111111111111111';
const COUNTERPARTY = '0x2222222222222222222222222222222222222222';
const MANIFEST = `0x${'ab'.repeat(32)}` as const;
const NOW = new Date('2026-07-29T12:00:00.000Z');
const hash = (character: string) =>
  `0x${character.repeat(64)}` as `0x${string}`;

class MemoryProtectedStore implements AuthenticatedEncryptedAutonomyStore {
  readonly protection = {
    authenticated: true,
    encryptedAtRest: true,
    atomicTransactions: true,
  } as const;

  snapshot = createEmptyAutonomyStoreSnapshot();
  #tail: Promise<void> = Promise.resolve();

  async read(): Promise<AutonomyStoreSnapshotV1> {
    return structuredClone(this.snapshot);
  }

  async transact<T>(
    mutation: (
      current: AutonomyStoreSnapshotV1,
    ) =>
      | AutonomyStoreTransactionResult<T>
      | Promise<AutonomyStoreTransactionResult<T>>,
  ): Promise<T> {
    const previous = this.#tail;
    let release = () => undefined;
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const result = await mutation(structuredClone(this.snapshot));
      this.snapshot = structuredClone(result.next);
      return structuredClone(result.result);
    } finally {
      release();
    }
  }
}

class TestApprovals implements AutonomyLocalApprovalHooks {
  activation:
    | { approved: false }
    | { approved: true; proposal: AutonomyPolicyProposalV1 }
    | null = null;
  resume = true;
  revocation = true;

  async approveActivation(request: {
    proposal: AutonomyPolicyProposalV1;
  }): Promise<
    | { approved: false }
    | { approved: true; proposal: AutonomyPolicyProposalV1 }
  > {
    return this.activation ?? { approved: true, proposal: request.proposal };
  }

  async approveResume(): Promise<boolean> {
    return this.resume;
  }

  async approveRevocation(): Promise<boolean> {
    return this.revocation;
  }
}

class ValuesElicitor implements FormElicitor {
  readonly requests: ConfirmationRequest[] = [];

  constructor(readonly values: Readonly<Record<string, string>>) {}

  isSupported(): boolean {
    return true;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<ConfirmationResult> {
    this.requests.push(structuredClone(request));
    return { outcome: 'accepted', values: { ...this.values } };
  }
}

const boundedProposal = (
  overrides: Partial<AutonomyPolicyProposalV1> = {},
): AutonomyPolicyProposalV1 => ({
  version: AUTONOMY_POLICY_VERSION,
  mode: 'bounded',
  wallet: WALLET,
  chainId: 2_632_500,
  manifestHash: MANIFEST,
  startsAt: NOW.toISOString(),
  expiresAt: new Date(
    NOW.getTime() + 7 * 24 * 60 * 60 * 1_000,
  ).toISOString(),
  agentVisiblePrivateAmounts: true,
  scope: {
    allowedActions: ['fill', 'privacy_bridge', 'send_order_message'],
    allowedAssets: ['p.wisp', 'p.coti'],
    allowedPairs: [{ sellAsset: 'p.wisp', buyAsset: 'p.coti' }],
    allowedOrderTypes: ['one-off.private-liquidity.public'],
    allowedCounterparties: [COUNTERPARTY],
    allowedBridgeRoutes: [
      { pair: 'wisp', direction: 'private-to-public' },
    ],
    messaging: { enabled: true, counterparties: [COUNTERPARTY] },
  },
  limits: {
    perActionSpend: [
      { asset: 'p.wisp', amount: '60' },
      { asset: 'p.coti', amount: '10' },
    ],
    cumulativeSpend: [
      { asset: 'p.wisp', amount: '100' },
      { asset: 'p.coti', amount: '20' },
    ],
    maximumNativeValuePerAction: '10',
    maximumNativeValueCumulative: '20',
    maximumNetworkFeePerAction: '5',
    maximumNetworkFeeCumulative: '10',
    maximumActions: 4,
    maximumMessages: 2,
    priceBands: [
      {
        sellAsset: 'p.wisp',
        buyAsset: 'p.coti',
        minimumBuyPerSellNumerator: '1',
        minimumBuyPerSellDenominator: '2',
        maximumBuyPerSellNumerator: '2',
        maximumBuyPerSellDenominator: '1',
      },
    ],
  },
  ...overrides,
} as AutonomyPolicyProposalV1);

const fillExposure = (
  operationCharacter: string,
  spend = '60',
  changes: Partial<PolicyExposureV1> = {},
): PolicyExposureV1 => ({
  wallet: WALLET,
  chainId: 2_632_500,
  manifestHash: MANIFEST,
  operationHash: hash(operationCharacter),
  action: 'fill',
  orderType: 'one-off.private-liquidity.public',
  pairs: [{ sellAsset: 'p.wisp', buyAsset: 'p.coti' }],
  priceQuotes: [
    {
      sellAsset: 'p.wisp',
      buyAsset: 'p.coti',
      sellAmount: '2',
      buyAmount: '3',
    },
  ],
  grossSpend: [{ asset: 'p.wisp', amount: spend }],
  minimumReceive: [{ asset: 'p.coti', amount: '1' }],
  counterparty: COUNTERPARTY,
  messageCount: 0,
  nativeValue: '1',
  maximumNetworkFee: '2',
  agentProvidedPrivateAmounts: true,
  stepDigests: [hash('c'), hash('d')],
  ...changes,
});

const setup = () => {
  const store = new MemoryProtectedStore();
  const approvals = new TestApprovals();
  let counter = 0;
  const manager = new AutonomyPolicyManager({
    store,
    approvals,
    now: () => NOW,
    idFactory: () => `local-${++counter}`,
  });
  return { store, approvals, manager };
};

describe('autonomy policy core', () => {
  it('validates bounded/full durations and required bounded scopes', () => {
    expect(
      validateAutonomyPolicyProposal(
        boundedProposal({
          expiresAt: new Date(
            NOW.getTime() + 31 * 24 * 60 * 60 * 1_000,
          ).toISOString(),
        }),
      ),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'INVALID_PROPOSAL' },
    });

    expect(
      validateAutonomyPolicyProposal({
        version: AUTONOMY_POLICY_VERSION,
        mode: 'full',
        wallet: WALLET,
        chainId: 2_632_500,
        manifestHash: MANIFEST,
        startsAt: NOW.toISOString(),
        expiresAt: new Date(
          NOW.getTime() + 24 * 60 * 60 * 1_000 + 1,
        ).toISOString(),
        agentVisiblePrivateAmounts: true,
        allowlistedEconomicSurface: true,
      }),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'INVALID_PROPOSAL' },
    });

    const proposal = boundedProposal();
    if (proposal.mode !== 'bounded') throw new Error('test proposal');
    expect(
      validateAutonomyPolicyProposal({
        ...proposal,
        scope: { ...proposal.scope, allowedPairs: [] },
      }),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'INVALID_PROPOSAL' },
    });
  });

  it('requires local activation and prevents a local edit from broadening the proposal', async () => {
    const { approvals, manager } = setup();
    const requested = boundedProposal();
    if (requested.mode !== 'bounded') throw new Error('test proposal');
    approvals.activation = {
      approved: true,
      proposal: {
        ...requested,
        limits: {
          ...requested.limits,
          maximumActions: requested.limits.maximumActions + 1,
        },
      },
    };
    expect(await manager.activate(requested)).toMatchObject({
      allowed: false,
      denial: { code: 'LOCAL_EDIT_BROADENED_POLICY' },
    });
    approvals.activation = { approved: false };
    expect(await manager.activate(requested)).toMatchObject({
      allowed: false,
      denial: { code: 'LOCAL_APPROVAL_DECLINED' },
    });
  });

  it('maps every bounded Control Page edit into a policy the manager verifies is strictly narrower', async () => {
    const requested = boundedProposal();
    if (requested.mode !== 'bounded') throw new Error('test proposal');
    const shortenedExpiry = new Date(
      Date.parse(requested.expiresAt) - 24 * 60 * 60 * 1_000,
    ).toISOString();
    const elicitor = new ValuesElicitor({
      'autonomy.expiresAt': shortenedExpiry,
      // An unchecked checkbox is intentionally absent and maps to false.
      // The manager canonicalizes asset entries before displaying the editor.
      'autonomy.perAction.0': '8',
      'autonomy.perAction.1': '50',
      'autonomy.cumulative.0': '18',
      'autonomy.cumulative.1': '90',
      'autonomy.maximumNativeValuePerAction': '8',
      'autonomy.maximumNativeValueCumulative': '18',
      'autonomy.maximumNetworkFeePerAction': '4',
      'autonomy.maximumNetworkFeeCumulative': '9',
      'autonomy.maximumActions': '3',
      'autonomy.maximumMessages': '1',
      'autonomy.price.0.minNumerator': '2',
      'autonomy.price.0.minDenominator': '3',
      'autonomy.price.0.maxNumerator': '3',
      'autonomy.price.0.maxDenominator': '2',
    });
    const store = new MemoryProtectedStore();
    const manager = new AutonomyPolicyManager({
      store,
      approvals: new ControlPageAutonomyApprovals(
        new ConfirmationGate(elicitor, 5_000),
      ),
      now: () => NOW,
      idFactory: () => 'control-page-narrowed',
    });

    const result = await manager.activate(requested);
    expect(result).toMatchObject({
      allowed: true,
      value: {
        mode: 'bounded',
        expiresAt: shortenedExpiry,
        agentVisiblePrivateAmounts: false,
        limits: {
          maximumNativeValuePerAction: '8',
          maximumNativeValueCumulative: '18',
          maximumNetworkFeePerAction: '4',
          maximumNetworkFeeCumulative: '9',
          maximumActions: 3,
          maximumMessages: 1,
          priceBands: [
            {
              minimumBuyPerSellNumerator: '2',
              minimumBuyPerSellDenominator: '3',
              maximumBuyPerSellNumerator: '3',
              maximumBuyPerSellDenominator: '2',
            },
          ],
        },
      },
    });
    if (!result.allowed || result.value.mode !== 'bounded') {
      throw new Error('narrowed policy was not activated');
    }
    expect(
      Object.fromEntries(
        result.value.limits.perActionSpend.map(({ asset, amount }) => [
          asset,
          amount,
        ]),
      ),
    ).toEqual({ 'p.coti': '8', 'p.wisp': '50' });
    expect(
      Object.fromEntries(
        result.value.limits.cumulativeSpend.map(({ asset, amount }) => [
          asset,
          amount,
        ]),
      ),
    ).toEqual({ 'p.coti': '18', 'p.wisp': '90' });
    expect(elicitor.requests).toHaveLength(1);
    expect(elicitor.requests[0]?.autonomyEditor).toMatchObject({
      expiresAt: requested.expiresAt,
      agentVisiblePrivateAmounts: true,
      maximumActions: 4,
      maximumMessages: 2,
    });
  });

  it.each([
    [
      'duration',
      {},
      {
        'autonomy.expiresAt': new Date(
          NOW.getTime() + 8 * 24 * 60 * 60 * 1_000,
        ).toISOString(),
      },
    ],
    [
      'private visibility',
      { agentVisiblePrivateAmounts: false },
      { 'autonomy.agentVisiblePrivateAmounts': 'true' },
    ],
    ['per-action spend', {}, { 'autonomy.perAction.1': '61' }],
    ['cumulative spend', {}, { 'autonomy.cumulative.0': '101' }],
    [
      'native value per action',
      {},
      { 'autonomy.maximumNativeValuePerAction': '11' },
    ],
    [
      'cumulative native value',
      {},
      { 'autonomy.maximumNativeValueCumulative': '21' },
    ],
    [
      'network fee per action',
      {},
      { 'autonomy.maximumNetworkFeePerAction': '6' },
    ],
    [
      'cumulative network fee',
      {},
      { 'autonomy.maximumNetworkFeeCumulative': '11' },
    ],
    ['action count', {}, { 'autonomy.maximumActions': '5' }],
    ['message count', {}, { 'autonomy.maximumMessages': '3' }],
    [
      'minimum price',
      {},
      {
        'autonomy.price.0.minNumerator': '1',
        'autonomy.price.0.minDenominator': '3',
      },
    ],
    [
      'maximum price',
      {},
      {
        'autonomy.price.0.maxNumerator': '3',
        'autonomy.price.0.maxDenominator': '1',
      },
    ],
  ] as const)(
    'rejects a Control Page edit that broadens %s',
    async (_label, proposalOverrides, values) => {
      const store = new MemoryProtectedStore();
      const manager = new AutonomyPolicyManager({
        store,
        approvals: new ControlPageAutonomyApprovals(
          new ConfirmationGate(new ValuesElicitor(values), 5_000),
        ),
        now: () => NOW,
        idFactory: () => 'must-not-activate',
      });

      expect(
        await manager.activate(boundedProposal(proposalOverrides)),
      ).toMatchObject({
        allowed: false,
        denial: { code: 'LOCAL_EDIT_BROADENED_POLICY' },
      });
      expect(store.snapshot.policies).toEqual({});
    },
  );

  it('returns structured mismatch denials without opening a manual fallback', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);

    expect(
      await manager.evaluate(
        activated.value.id,
        fillExposure('1', '1', { action: 'create_trade' }),
      ),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'ACTION_NOT_ALLOWED' },
    });
    expect(
      await manager.evaluate(
        activated.value.id,
        fillExposure('2', '1', {
          agentProvidedPrivateAmounts: false,
          manifestHash: hash('e'),
        }),
      ),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'MANIFEST_MISMATCH' },
    });
  });

  it('serializes concurrent reservations so cumulative spend cannot race', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);

    const results = await Promise.all([
      manager.reserve(activated.value.id, fillExposure('1')),
      manager.reserve(activated.value.id, fillExposure('2')),
    ]);
    expect(results.filter((result) => result.allowed)).toHaveLength(1);
    expect(results.filter((result) => !result.allowed)).toMatchObject([
      {
        allowed: false,
        denial: { code: 'CUMULATIVE_SPEND_EXCEEDED' },
      },
    ]);
  });

  it('is idempotent for an exact operation binding and rejects changed terms', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const first = await manager.reserve(
      activated.value.id,
      fillExposure('1', '30'),
    );
    const repeated = await manager.reserve(
      activated.value.id,
      fillExposure('1', '30'),
    );
    expect(repeated).toEqual(first);
    expect(
      await manager.reserve(
        activated.value.id,
        fillExposure('1', '31'),
      ),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'OPERATION_BINDING_MISMATCH' },
    });
  });

  it('releases only before signing and keeps pending/uncertain spend consumed', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const first = await manager.reserve(
      activated.value.id,
      fillExposure('1'),
    );
    if (!first.allowed) throw new Error(first.denial.code);
    expect(await manager.releaseBeforeSigning(first.value.id)).toMatchObject({
      allowed: true,
      value: { state: 'released' },
    });

    const second = await manager.reserve(
      activated.value.id,
      fillExposure('2'),
    );
    if (!second.allowed) throw new Error(second.denial.code);
    await manager.markSigned(second.value.id, hash('f'));
    await manager.markPending(second.value.id);
    await manager.markUncertain(second.value.id);
    expect(await manager.releaseBeforeSigning(second.value.id)).toMatchObject({
      allowed: false,
      denial: { code: 'RESERVATION_STATE_INVALID' },
    });
    expect(
      await manager.reserve(activated.value.id, fillExposure('3')),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'CUMULATIVE_SPEND_EXCEEDED' },
    });
  });

  it('pauses immediately and requires local approval to resume and revoke', async () => {
    const { approvals, manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    await manager.pauseGlobal();
    expect(
      await manager.reserve(activated.value.id, fillExposure('1')),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'GLOBAL_PAUSED' },
    });
    approvals.resume = false;
    expect(await manager.resumeGlobal()).toMatchObject({
      allowed: false,
      denial: { code: 'LOCAL_APPROVAL_DECLINED' },
    });
    approvals.resume = true;
    expect(await manager.resumeGlobal()).toMatchObject({
      allowed: true,
      value: { globalPaused: false },
    });
    approvals.revocation = true;
    expect(await manager.revoke(activated.value.id)).toMatchObject({
      allowed: true,
      value: { lifecycle: { state: 'revoked' } },
    });
  });

  it('expires policies and detects stored immutable-term tampering', async () => {
    let now = NOW;
    const store = new MemoryProtectedStore();
    const approvals = new TestApprovals();
    let counter = 0;
    const manager = new AutonomyPolicyManager({
      store,
      approvals,
      now: () => now,
      idFactory: () => `expiry-${++counter}`,
    });
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    now = new Date(Date.parse(activated.value.expiresAt) + 1);
    expect(
      await manager.reserve(activated.value.id, fillExposure('1')),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_EXPIRED' },
    });

    const secondSetup = setup();
    const second = await secondSetup.manager.activate(boundedProposal());
    if (!second.allowed) throw new Error(second.denial.code);
    const stored = secondSetup.store.snapshot.policies[second.value.id]!;
    if (stored.mode !== 'bounded') throw new Error('test policy');
    stored.limits.maximumActions += 1;
    expect(await secondSetup.manager.status()).toMatchObject({
      allowed: false,
      denial: { code: 'STORE_TAMPERED' },
    });
  });
});
