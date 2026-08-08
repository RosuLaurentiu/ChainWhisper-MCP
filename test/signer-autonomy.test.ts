import { describe, expect, it } from 'vitest';

import {
  AUTONOMY_POLICY_VERSION,
  AutonomyPolicyManager,
  autonomyResumeBinding,
  isExactAutonomyResumeBinding,
  type AutonomyLocalApprovalHooks,
  type AutonomyPolicyProposalV1,
  type ActiveAutonomyPolicyV1,
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
const PRIVATE_AMOUNT_AUTHORITY_ENABLED =
  'The agent may both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts.';
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
  readonly resumeRequests: ActiveAutonomyPolicyV1[][] = [];

  async approveActivation(request: {
    proposal: AutonomyPolicyProposalV1;
  }): Promise<
    | { approved: false }
    | { approved: true; proposal: AutonomyPolicyProposalV1 }
  > {
    return this.activation ?? { approved: true, proposal: request.proposal };
  }

  async approveResume(request: {
    policies: ActiveAutonomyPolicyV1[];
  }): Promise<boolean> {
    this.resumeRequests.push(structuredClone(request.policies));
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
  boundedRiskComplete: true,
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
    const activationRequest = elicitor.requests[0]!;
    expect(activationRequest.autonomyEditor).toMatchObject({
      expiresAt: requested.expiresAt,
      agentVisiblePrivateAmounts: true,
      maximumActions: 4,
      maximumMessages: 2,
    });
    expect(activationRequest.details).toContainEqual({
      label: 'Private amount choice and policy-scoped state viewing',
      value: PRIVATE_AMOUNT_AUTHORITY_ENABLED,
    });
    expect(activationRequest.details).toEqual(
      expect.arrayContaining([
        {
          label: 'Allowed pairs',
          value: 'p.wisp -> p.coti',
        },
        {
          label: 'Allowed counterparties',
          value: COUNTERPARTY,
        },
        {
          label: 'Allowed Privacy Portal routes',
          value: 'wisp: private to public',
        },
        {
          label: 'Private messaging',
          value: `Enabled only for: ${COUNTERPARTY}`,
        },
      ]),
    );
    expect(activationRequest.summary).toContain(
      PRIVATE_AMOUNT_AUTHORITY_ENABLED,
    );
    expect(activationRequest.expectedResult).toContain(
      PRIVATE_AMOUNT_AUTHORITY_ENABLED,
    );
  });

  it('spells out the combined private authority in resume and revocation confirmations', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);

    const elicitor = new ValuesElicitor({});
    const approvals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(elicitor, 5_000),
    );
    await expect(
      approvals.approveResume({ policies: [activated.value] }),
    ).resolves.toBe(true);
    await expect(
      approvals.approveRevocation({ policy: activated.value }),
    ).resolves.toBe(true);

    expect(elicitor.requests).toHaveLength(2);
    for (const request of elicitor.requests) {
      expect(request.details).toContainEqual({
        label: 'Private amount choice and policy-scoped state viewing',
        value: PRIVATE_AMOUNT_AUTHORITY_ENABLED,
      });
      expect(request.details).toEqual(
        expect.arrayContaining([
          {
            label: 'Allowed pairs',
            value: 'p.wisp -> p.coti',
          },
          {
            label: 'Allowed counterparties',
            value: COUNTERPARTY,
          },
          {
            label: 'Allowed Privacy Portal routes',
            value: 'wisp: private to public',
          },
          {
            label: 'Private messaging',
            value: `Enabled only for: ${COUNTERPARTY}`,
          },
        ]),
      );
      expect(request.summary).toContain(
        'both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts',
      );
      expect(request.expectedResult).toContain(
        'both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts',
      );
    }
  });

  it('discloses and hash-binds every policy affected by a global resume', async () => {
    const { manager } = setup();
    const first = await manager.activate(boundedProposal());
    const second = await manager.activate(
      boundedProposal({
        expiresAt: new Date(
          NOW.getTime() + 8 * 24 * 60 * 60 * 1_000,
        ).toISOString(),
        agentVisiblePrivateAmounts: false,
      }),
    );
    if (!first.allowed) throw new Error(first.denial.code);
    if (!second.allowed) throw new Error(second.denial.code);

    const aggregateElicitor = new ValuesElicitor({});
    const aggregateApprovals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(aggregateElicitor, 5_000),
    );
    await expect(
      aggregateApprovals.approveResume({
        policies: [first.value, second.value],
      }),
    ).resolves.toBe(true);

    const singleElicitor = new ValuesElicitor({});
    const singleApprovals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(singleElicitor, 5_000),
    );
    await expect(
      singleApprovals.approveResume({ policies: [second.value] }),
    ).resolves.toBe(true);

    const aggregateRequest = aggregateElicitor.requests[0]!;
    expect(aggregateRequest.details.map(({ value }) => value)).toEqual(
      expect.arrayContaining([
        first.value.id,
        first.value.termsDigest,
        second.value.id,
        second.value.termsDigest,
      ]),
    );
    expect(aggregateRequest.summary).toContain('2 policies');
    expect(aggregateRequest.operationHash).not.toBe(
      singleElicitor.requests[0]!.operationHash,
    );
  });

  it('scopes a control-page resume preapproval to one exact policy set and attempt', async () => {
    const { manager } = setup();
    const first = await manager.activate(boundedProposal());
    const second = await manager.activate(
      boundedProposal({
        expiresAt: new Date(
          NOW.getTime() + 8 * 24 * 60 * 60 * 1_000,
        ).toISOString(),
      }),
    );
    if (!first.allowed) throw new Error(first.denial.code);
    if (!second.allowed) throw new Error(second.denial.code);

    const elicitor = new ValuesElicitor({});
    const approvals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(elicitor, 5_000),
    );
    const policies = [first.value, second.value];
    const binding = autonomyResumeBinding(policies);
    expect(isExactAutonomyResumeBinding(policies, undefined)).toBe(false);
    expect(isExactAutonomyResumeBinding(policies, 'invalid')).toBe(false);
    expect(
      isExactAutonomyResumeBinding(
        policies,
        autonomyResumeBinding([second.value]),
      ),
    ).toBe(false);
    expect(isExactAutonomyResumeBinding(policies, binding)).toBe(true);
    const clearPreapproval =
      approvals.preapproveNextResumeFromControlPage(
        binding,
      );
    clearPreapproval();
    await expect(approvals.approveResume({ policies })).resolves.toBe(true);
    expect(elicitor.requests).toHaveLength(1);

    const clearAbandonedPreapproval =
      approvals.preapproveNextResumeFromControlPage(binding);
    const clearMissingPreapproval =
      approvals.preapproveNextResumeFromControlPage();
    clearMissingPreapproval();
    clearAbandonedPreapproval();
    await expect(approvals.approveResume({ policies })).resolves.toBe(true);
    expect(elicitor.requests).toHaveLength(2);

    approvals.preapproveNextResumeFromControlPage(
      binding,
    );
    await expect(
      approvals.approveResume({ policies: [second.value] }),
    ).resolves.toBe(false);
    expect(elicitor.requests).toHaveLength(2);
  });

  it('uses one exact control-page binding to resume the unchanged two-policy set', async () => {
    const store = new MemoryProtectedStore();
    const elicitor = new ValuesElicitor({});
    const controlApprovals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(elicitor, 5_000),
    );
    const approvals: AutonomyLocalApprovalHooks = {
      approveActivation: async ({ proposal }) => ({
        approved: true,
        proposal,
      }),
      approveResume: (request) => controlApprovals.approveResume(request),
      approveRevocation: async () => true,
    };
    let nextId = 0;
    const manager = new AutonomyPolicyManager({
      store,
      approvals,
      now: () => NOW,
      idFactory: () => `control-resume-${++nextId}`,
    });
    const first = await manager.activate(boundedProposal());
    const second = await manager.activate(
      boundedProposal({
        expiresAt: new Date(
          NOW.getTime() + 8 * 24 * 60 * 60 * 1_000,
        ).toISOString(),
      }),
    );
    if (!first.allowed) throw new Error(first.denial.code);
    if (!second.allowed) throw new Error(second.denial.code);
    const paused = await manager.pauseGlobal();
    if (!paused.allowed) throw new Error(paused.denial.code);
    const pausedPolicies = paused.value.policies
      .filter(({ policy }) => policy.lifecycle.state === 'paused')
      .map(({ policy }) => policy);
    const clearPreapproval =
      controlApprovals.preapproveNextResumeFromControlPage(
        autonomyResumeBinding(pausedPolicies),
      );

    const resumed = await manager.resumeGlobal();
    clearPreapproval();
    expect(resumed).toMatchObject({
      allowed: true,
      value: {
        globalPaused: false,
        policies: [
          { policy: { id: first.value.id, lifecycle: { state: 'active' } } },
          {
            policy: {
              id: second.value.id,
              lifecycle: { state: 'active' },
            },
          },
        ],
      },
    });
    expect(elicitor.requests).toHaveLength(0);
  });

  it('does not reuse a control preapproval when another resume wins the race', async () => {
    const store = new MemoryProtectedStore();
    const elicitor = new ValuesElicitor({});
    const controlApprovals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(elicitor, 5_000),
    );
    const approvals: AutonomyLocalApprovalHooks = {
      approveActivation: async ({ proposal }) => ({
        approved: true,
        proposal,
      }),
      approveResume: (request) => controlApprovals.approveResume(request),
      approveRevocation: async () => true,
    };
    let nextId = 0;
    const manager = new AutonomyPolicyManager({
      store,
      approvals,
      now: () => NOW,
      idFactory: () => `raced-resume-${++nextId}`,
    });
    const competingManager = new AutonomyPolicyManager({
      store,
      approvals: new TestApprovals(),
      now: () => NOW,
      idFactory: () => `competing-resume-${++nextId}`,
    });
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const paused = await manager.pauseGlobal();
    if (!paused.allowed) throw new Error(paused.denial.code);
    const pausedPolicies = paused.value.policies
      .filter(({ policy }) => policy.lifecycle.state === 'paused')
      .map(({ policy }) => policy);
    const clearPreapproval =
      controlApprovals.preapproveNextResumeFromControlPage(
        autonomyResumeBinding(pausedPolicies),
      );

    await expect(competingManager.resumeGlobal()).resolves.toMatchObject({
      allowed: true,
      value: { globalPaused: false },
    });
    try {
      await expect(manager.resumeGlobal()).resolves.toMatchObject({
        allowed: true,
        value: { globalPaused: false },
      });
    } finally {
      clearPreapproval();
    }

    await manager.pauseGlobal();
    await expect(manager.resumeGlobal()).resolves.toMatchObject({
      allowed: true,
      value: { globalPaused: false },
    });
    expect(elicitor.requests).toHaveLength(1);
  });

  it('spells out the combined private authority in the full-autonomy acknowledgement', async () => {
    const elicitor = new ValuesElicitor({
      'autonomy.agentVisiblePrivateAmounts': 'true',
    });
    const approvals = new ControlPageAutonomyApprovals(
      new ConfirmationGate(elicitor, 5_000),
    );
    const proposal: AutonomyPolicyProposalV1 = {
      version: AUTONOMY_POLICY_VERSION,
      mode: 'full',
      wallet: WALLET,
      chainId: 2_632_500,
      manifestHash: MANIFEST,
      startsAt: NOW.toISOString(),
      expiresAt: new Date(
        NOW.getTime() + 12 * 60 * 60 * 1_000,
      ).toISOString(),
      agentVisiblePrivateAmounts: true,
      allowlistedEconomicSurface: true,
    };

    await expect(
      approvals.approveActivation({ proposal }),
    ).resolves.toMatchObject({
      approved: true,
      proposal: { agentVisiblePrivateAmounts: true },
    });
    expect(elicitor.requests).toHaveLength(1);
    expect(elicitor.requests[0]?.acknowledgements).toContainEqual(
      expect.stringContaining(
        'both choose private amounts and view policy-scoped private balances, hidden order inventory/progress, and participant receipts',
      ),
    );
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

  it('authorizes policy-scoped private state through the policy manager', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    expect(activated.allowed).toBe(true);
    if (!activated.allowed) return;

    const scope = {
      wallet: WALLET,
      chainId: 2_632_500,
      manifestHash: MANIFEST,
      assets: [
        { aliases: ['p.WISP', '0x3333333333333333333333333333333333333333'] },
        { aliases: ['p.COTI', '0x4444444444444444444444444444444444444444'] },
      ],
      pair: {
        firstAliases: ['p.WISP'],
        secondAliases: ['p.COTI'],
        bidirectional: false,
      },
      orderType: 'one-off.private-liquidity.public' as const,
      counterparties: [COUNTERPARTY],
    };
    await expect(
      manager.authorizePrivateStateDisclosure(
        activated.value.id,
        scope,
      ),
    ).resolves.toMatchObject({
      allowed: true,
      value: { id: activated.value.id },
    });
    await expect(
      manager.authorizePrivateStateDisclosure(
        activated.value.id,
        {
          ...scope,
          assets: [{ aliases: ['p.UNKNOWN'] }],
        },
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: {
        code: 'ASSET_NOT_ALLOWED',
        policyId: activated.value.id,
      },
    });
  });

  it('fails bounded autonomy closed when economic exposure cannot be derived', async () => {
    const { manager, store } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);

    await expect(
      manager.reserve(
        activated.value.id,
        fillExposure('8', '0', {
          boundedRiskComplete: false,
          priceQuotes: [],
          grossSpend: [],
          minimumReceive: [],
        }),
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: {
        code: 'ECONOMIC_EXPOSURE_INCOMPLETE',
        field: 'boundedRiskComplete',
      },
    });
    expect(store.snapshot.reservations).toEqual({});

    await expect(
      manager.reserve(
        activated.value.id,
        fillExposure('9', '0', {
          grossSpend: [],
          minimumReceive: [],
        }),
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'INVALID_EXPOSURE', field: 'grossSpend' },
    });
    expect(store.snapshot.reservations).toEqual({});
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

  it('atomically authorizes a legitimate write and records its signature', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const reserved = await manager.reserve(
      activated.value.id,
      fillExposure('a', '10'),
    );
    if (!reserved.allowed) throw new Error(reserved.denial.code);

    const result = await manager.executeAuthorizedWrite(
      reserved.value.id,
      async () => ({
        transactionHash: hash('b'),
        value: { signedTransaction: 'prepared-transaction' },
      }),
    );

    expect(result).toMatchObject({
      allowed: true,
      value: {
        reservation: {
          id: reserved.value.id,
          state: 'signed',
          signedTransactionHashes: [hash('b')],
        },
        value: { signedTransaction: 'prepared-transaction' },
      },
    });
  });

  it('withholds prepared bytes when the policy expires inside the signing callback', async () => {
    let now = NOW;
    const store = new MemoryProtectedStore();
    const manager = new AutonomyPolicyManager({
      store,
      approvals: new TestApprovals(),
      now: () => now,
      idFactory: (() => {
        let nextId = 0;
        return () => `inflight-expiry-${++nextId}`;
      })(),
    });
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const reserved = await manager.reserve(
      activated.value.id,
      fillExposure('8', '10'),
    );
    if (!reserved.allowed) throw new Error(reserved.denial.code);

    const result = await manager.executeAuthorizedWrite(
      reserved.value.id,
      async () => {
        now = new Date(Date.parse(activated.value.expiresAt) + 1);
        return {
          transactionHash: hash('8'),
          value: { signedTransaction: 'must-not-be-returned' },
        };
      },
    );

    expect(result).toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_EXPIRED' },
    });
    expect(result).not.toHaveProperty('value');
    expect(store.snapshot.reservations[reserved.value.id]).toMatchObject({
      state: 'signed',
      signedTransactionHashes: [hash('8')],
    });
    expect(store.snapshot.policies[activated.value.id]).toMatchObject({
      lifecycle: { state: 'expired', reason: 'time-expired' },
    });
  });

  it('does not invoke the signature callback after pause, revocation, or expiry', async () => {
    const pausedSetup = setup();
    const pausedPolicy = await pausedSetup.manager.activate(
      boundedProposal(),
    );
    if (!pausedPolicy.allowed) throw new Error(pausedPolicy.denial.code);
    const pausedReservation = await pausedSetup.manager.reserve(
      pausedPolicy.value.id,
      fillExposure('b', '10'),
    );
    if (!pausedReservation.allowed) {
      throw new Error(pausedReservation.denial.code);
    }
    await pausedSetup.manager.pauseGlobal();

    const revokedSetup = setup();
    const revokedPolicy = await revokedSetup.manager.activate(
      boundedProposal(),
    );
    if (!revokedPolicy.allowed) throw new Error(revokedPolicy.denial.code);
    const revokedReservation = await revokedSetup.manager.reserve(
      revokedPolicy.value.id,
      fillExposure('c', '10'),
    );
    if (!revokedReservation.allowed) {
      throw new Error(revokedReservation.denial.code);
    }
    await revokedSetup.manager.revoke(revokedPolicy.value.id);

    let now = NOW;
    const expiringManager = new AutonomyPolicyManager({
      store: new MemoryProtectedStore(),
      approvals: new TestApprovals(),
      now: () => now,
      idFactory: () => 'expiry-write-policy',
    });
    const expiringPolicy = await expiringManager.activate(
      boundedProposal(),
    );
    if (!expiringPolicy.allowed) throw new Error(expiringPolicy.denial.code);
    const expiringReservation = await expiringManager.reserve(
      expiringPolicy.value.id,
      fillExposure('d', '10'),
    );
    if (!expiringReservation.allowed) {
      throw new Error(expiringReservation.denial.code);
    }
    now = new Date(Date.parse(expiringPolicy.value.expiresAt) + 1);

    let signatures = 0;
    const sign = async () => {
      signatures += 1;
      return { transactionHash: hash('c'), value: 'signed' };
    };
    await expect(
      pausedSetup.manager.executeAuthorizedWrite(
        pausedReservation.value.id,
        sign,
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'GLOBAL_PAUSED' },
    });
    await expect(
      revokedSetup.manager.executeAuthorizedWrite(
        revokedReservation.value.id,
        sign,
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_REVOKED' },
    });
    await expect(
      expiringManager.executeAuthorizedWrite(
        expiringReservation.value.id,
        sign,
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_EXPIRED' },
    });
    expect(signatures).toBe(0);
  });

  it('rechecks expiry after waiting for an in-flight signature transaction', async () => {
    let now = NOW;
    const manager = new AutonomyPolicyManager({
      store: new MemoryProtectedStore(),
      approvals: new TestApprovals(),
      now: () => now,
      idFactory: (() => {
        let nextId = 0;
        return () => `queued-expiry-${++nextId}`;
      })(),
    });
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const first = await manager.reserve(
      activated.value.id,
      fillExposure('e', '10'),
    );
    const second = await manager.reserve(
      activated.value.id,
      fillExposure('f', '10'),
    );
    if (!first.allowed) throw new Error(first.denial.code);
    if (!second.allowed) throw new Error(second.denial.code);

    let signalStarted = () => undefined;
    let releaseFirst = () => undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const firstWrite = manager.executeAuthorizedWrite(
      first.value.id,
      async () => {
        signalStarted();
        await release;
        return { transactionHash: hash('d'), value: 'first' };
      },
    );
    await started;

    let secondSignatures = 0;
    const secondWrite = manager.executeAuthorizedWrite(
      second.value.id,
      async () => {
        secondSignatures += 1;
        return { transactionHash: hash('e'), value: 'second' };
      },
    );
    now = new Date(Date.parse(activated.value.expiresAt) + 1);
    releaseFirst();

    await expect(firstWrite).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_EXPIRED' },
    });
    await expect(secondWrite).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_EXPIRED' },
    });
    expect(secondSignatures).toBe(0);
  });

  it('serializes a committed revocation behind an in-flight signature', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const reserved = await manager.reserve(
      activated.value.id,
      fillExposure('9', '10'),
    );
    if (!reserved.allowed) throw new Error(reserved.denial.code);

    let signalStarted = () => undefined;
    let releaseWrite = () => undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseWrite = resolve;
    });
    const signing = manager.executeAuthorizedWrite(
      reserved.value.id,
      async () => {
        signalStarted();
        await release;
        return { transactionHash: hash('f'), value: 'signed' };
      },
    );
    await started;

    let revocationFinished = false;
    const revoking = manager.revoke(activated.value.id).then((result) => {
      revocationFinished = true;
      return result;
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    expect(revocationFinished).toBe(false);

    releaseWrite();
    await expect(signing).resolves.toMatchObject({ allowed: true });
    await expect(revoking).resolves.toMatchObject({
      allowed: true,
      value: { lifecycle: { state: 'revoked' } },
    });
  });

  it('settles a recovered reservation by its exact operation hash', async () => {
    const { manager } = setup();
    const activated = await manager.activate(boundedProposal());
    expect(activated.allowed).toBe(true);
    if (!activated.allowed) return;
    const exposure = fillExposure('8');
    const reserved = await manager.reserve(activated.value.id, exposure);
    expect(reserved.allowed).toBe(true);
    if (!reserved.allowed) return;
    await manager.markSigned(reserved.value.id, hash('9'));
    await manager.markPending(reserved.value.id);

    await expect(
      manager.settleByOperationHash(exposure.operationHash),
    ).resolves.toMatchObject({
      allowed: true,
      value: {
        id: reserved.value.id,
        state: 'settled',
      },
    });
  });

  it('pauses immediately and requires local approval to resume and revoke', async () => {
    const { approvals, manager } = setup();
    const activated = await manager.activate(boundedProposal());
    if (!activated.allowed) throw new Error(activated.denial.code);
    const reservation = await manager.reserve(
      activated.value.id,
      fillExposure('1'),
    );
    if (!reservation.allowed) throw new Error(reservation.denial.code);
    expect(
      await manager.authorizeReservedWrite(reservation.value.id),
    ).toMatchObject({
      allowed: true,
      value: { id: reservation.value.id, state: 'reserved' },
    });
    await manager.pauseGlobal();
    expect(
      await manager.authorizeReservedWrite(reservation.value.id),
    ).toMatchObject({
      allowed: false,
      denial: { code: 'GLOBAL_PAUSED' },
    });
    expect(
      await manager.reserve(activated.value.id, fillExposure('2')),
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
    expect(
      await manager.authorizeReservedWrite(reservation.value.id),
    ).toMatchObject({ allowed: true });
    approvals.revocation = true;
    expect(await manager.revoke(activated.value.id)).toMatchObject({
      allowed: true,
      value: { lifecycle: { state: 'revoked' } },
    });
  });

  it('fails closed when the paused policy set changes during resume approval', async () => {
    const store = new MemoryProtectedStore();
    let nextId = 0;
    let releaseResume = () => undefined;
    let markResumeRequested = () => undefined;
    const resumeRequested = new Promise<void>((resolve) => {
      markResumeRequested = resolve;
    });
    const resumeApproval = new Promise<void>((resolve) => {
      releaseResume = resolve;
    });
    const approvals: AutonomyLocalApprovalHooks = {
      approveActivation: async ({ proposal }) => ({
        approved: true,
        proposal,
      }),
      approveResume: async () => {
        markResumeRequested();
        await resumeApproval;
        return true;
      },
      approveRevocation: async () => true,
    };
    const manager = new AutonomyPolicyManager({
      store,
      approvals,
      now: () => NOW,
      idFactory: () => `resume-binding-${++nextId}`,
    });
    const first = await manager.activate(boundedProposal());
    if (!first.allowed) throw new Error(first.denial.code);
    await manager.pauseGlobal();

    const resuming = manager.resumeGlobal();
    await resumeRequested;
    const addedWhilePaused = await manager.activate(
      boundedProposal({
        expiresAt: new Date(
          NOW.getTime() + 8 * 24 * 60 * 60 * 1_000,
        ).toISOString(),
      }),
    );
    if (!addedWhilePaused.allowed) {
      throw new Error(addedWhilePaused.denial.code);
    }
    releaseResume();

    await expect(resuming).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'STORE_TAMPERED' },
    });
    await expect(manager.status()).resolves.toMatchObject({
      allowed: true,
      value: {
        globalPaused: true,
        policies: [
          { policy: { id: first.value.id, lifecycle: { state: 'paused' } } },
          {
            policy: {
              id: addedWhilePaused.value.id,
              lifecycle: { state: 'paused' },
            },
          },
        ],
      },
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
