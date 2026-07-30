import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import type { SignedActionEnvelopeV1 } from '../src/shared/index.js';
import {
  AUTONOMY_POLICY_VERSION,
  AutonomyPolicyManager,
  EncryptedSecretVault,
  VaultAutonomyStore,
  buildPolicyExposure,
  validatePolicyExposure,
  type AutonomyPolicyProposalV1,
  type MaterializedActionStep,
} from '../src/signer/index.js';

const temporaryDirectories: string[] = [];
const WALLET = '0x1111111111111111111111111111111111111111';
const BASE_TOKEN = '0x3333333333333333333333333333333333333333';
const QUOTE_TOKEN = '0x4444444444444444444444444444444444444444';
const MAKER = '0x5555555555555555555555555555555555555555';
const MANIFEST_HASH = `0x${'34'.repeat(32)}` as const;
const NOW = new Date('2026-07-30T12:00:00.000Z');

const recurringEnvelope = (): SignedActionEnvelopeV1 =>
  ({
    version: 'cw.action/1',
    operationId: 'create-recurring-policy-exposure',
    operationHash: `0x${'56'.repeat(32)}`,
    chainId: 2_632_500,
    createdAt: NOW.toISOString(),
    expiresAt: new Date(NOW.getTime() + 5 * 60_000).toISOString(),
    exactNativeValue: '0',
    summary: 'Create recurring private-liquidity order',
    registrySnapshot: {
      manifestHash: MANIFEST_HASH,
      chainId: 2_632_500,
      observedAt: NOW.toISOString(),
      contracts: {},
    },
    intent: {
      action: 'create_recurring',
      orderType: {
        version: 1,
        id: 'recurring.private-liquidity.public',
        cadence: 'recurring',
        access: 'public',
        liquidity: 'private',
        route: 'recurring-escrow',
        relation: 'primary',
      },
      sellAsset: {
        kind: 'private-erc20',
        reference: 'p.BASE',
        address: BASE_TOKEN,
        symbol: 'p.BASE',
        decimals: 6,
      },
      buyAsset: {
        kind: 'private-erc20',
        reference: 'p.QUOTE',
        address: QUOTE_TOKEN,
        symbol: 'p.QUOTE',
        decimals: 18,
      },
      metadata: {
        privateAmountMode: 'agent-provided',
        buyPrice: '2',
        sellPrice: '2.5',
        buyQuoteLiquidity: '7.25',
        sellBaseLiquidity: '10.5',
      },
    },
    steps: [],
    privateInputs: [],
  }) as SignedActionEnvelopeV1;

const recurringExposure = () =>
  buildPolicyExposure({
    envelope: recurringEnvelope(),
    wallet: WALLET,
    steps: [
      {
        id: 'create-recurring',
        kind: 'protocol',
        to: '0x2222222222222222222222222222222222222222',
        data: '0x12345678',
        value: '0',
        gasCap: '400000',
        summary: 'Create recurring order',
      },
    ],
    feeQuotes: [],
  });

const recurringEditEnvelope = (
  metadata: Record<string, string | number | boolean | null>,
  privateArtifacts: SignedActionEnvelopeV1['privateArtifacts'] = [],
): SignedActionEnvelopeV1 =>
  ({
    ...recurringEnvelope(),
    operationId: 'edit-recurring-policy-exposure',
    operationHash: `0x${'57'.repeat(32)}`,
    intent: {
      ...recurringEnvelope().intent,
      action: 'edit',
      metadata,
    },
    privateArtifacts,
  }) as SignedActionEnvelopeV1;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) =>
      rm(path, { recursive: true, force: true }),
    ),
  );
});

describe('autonomy signer integration', () => {
  it('persists wallet-namespaced policy state only through authenticated encrypted storage', async () => {
    const directory = await mkdtemp(
      join(tmpdir(), 'chainwhisper-autonomy-store-'),
    );
    temporaryDirectories.push(directory);
    const vault = new EncryptedSecretVault(
      directory,
      'test-only-storage-passphrase',
    );
    const store = new VaultAutonomyStore({
      vault,
      wallet: '0x1111111111111111111111111111111111111111',
    });

    await store.transact((current) => ({
      next: { ...current, revision: 1, globalPaused: true },
      result: undefined,
    }));

    await expect(store.read()).resolves.toMatchObject({
      revision: 1,
      globalPaused: true,
    });
    const persisted = await readFile(vault.path, 'utf8');
    expect(persisted).toContain('"cipher":"aes-256-gcm"');
    expect(persisted).not.toContain('globalPaused');
    expect(persisted).not.toContain(
      '0x1111111111111111111111111111111111111111',
    );
  });

  it('binds private agent-provided amounts, exact steps, and fee ceilings into policy exposure', () => {
    const step: MaterializedActionStep = {
      id: 'create-private-order',
      kind: 'protocol',
      to: '0x2222222222222222222222222222222222222222',
      data: '0x12345678',
      value: '0',
      gasCap: '400000',
      summary: 'Create private order',
    };
    const envelope = {
      chainId: 2_632_500,
      operationHash: `0x${'12'.repeat(32)}`,
      exactNativeValue: '100',
      registrySnapshot: {
        manifestHash: `0x${'34'.repeat(32)}`,
      },
      intent: {
        action: 'create_trade',
        sellAsset: {
          kind: 'private-erc20',
          reference: 'p.WISP',
          address: '0x3333333333333333333333333333333333333333',
          symbol: 'p.WISP',
          decimals: 18,
        },
        buyAsset: {
          kind: 'private-erc20',
          reference: 'p.COTI',
          address: '0x4444444444444444444444444444444444444444',
          symbol: 'p.COTI',
          decimals: 18,
        },
        sellAmount: '1.5',
        buyAmount: '3',
        recipient: '0x5555555555555555555555555555555555555555',
        metadata: { privateAmountMode: 'agent-provided' },
      },
    } as SignedActionEnvelopeV1;

    const exposure = buildPolicyExposure({
      envelope,
      wallet: '0x1111111111111111111111111111111111111111',
      steps: [step],
      feeQuotes: [
        {
          model: 'eip1559',
          maximumNetworkFeeWei: '250',
          maximumNetworkFeeCoti: '0.00000000000000025',
          maximumFeePerGasWei: '1',
        },
      ],
    });

    expect(exposure.agentProvidedPrivateAmounts).toBe(true);
    expect(exposure.grossSpend).toEqual([
      {
        asset: '0x3333333333333333333333333333333333333333',
        amount: '1500000000000000000',
      },
    ]);
    expect(exposure.minimumReceive[0]?.amount).toBe(
      '3000000000000000000',
    );
    expect(exposure.maximumNetworkFee).toBe('250');
    expect(exposure.nativeValue).toBe('100');
    expect(exposure.stepDigests).toHaveLength(1);
    expect(exposure.stepDigests[0]).toMatch(/^0x[0-9a-f]{64}$/u);
  });

  it('exposes both recurring directions at exact prices while preserving gross-spend budgets', () => {
    const exposure = recurringExposure();

    expect(exposure.pairs).toEqual([
      { sellAsset: BASE_TOKEN, buyAsset: QUOTE_TOKEN },
      { sellAsset: QUOTE_TOKEN, buyAsset: BASE_TOKEN },
    ]);
    expect(exposure.priceQuotes).toEqual([
      {
        sellAsset: BASE_TOKEN,
        buyAsset: QUOTE_TOKEN,
        sellAmount: '1000000',
        buyAmount: '2500000000000000000',
      },
      {
        sellAsset: QUOTE_TOKEN,
        buyAsset: BASE_TOKEN,
        sellAmount: '2000000000000000000',
        buyAmount: '1000000',
      },
    ]);
    expect(exposure.grossSpend).toEqual([
      { asset: BASE_TOKEN, amount: '10500000' },
      { asset: QUOTE_TOKEN, amount: '7250000000000000000' },
    ]);
  });

  it('derives recurring edit prices and only added inventory as bounded spend', () => {
    const exposure = buildPolicyExposure({
      envelope: recurringEditEnvelope({
        buyPrice: '2.2',
        trustedSellBaseAmount: '2',
        trustedSellQuoteAmount: '5',
        addSellBaseLiquidity: '3',
        addBuyQuoteLiquidity: '4',
        removeSellBaseLiquidity: '8',
        removeBuyQuoteLiquidity: '9',
      }),
      wallet: WALLET,
      steps: [
        {
          id: 'edit-recurring-order',
          kind: 'protocol',
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          value: '0',
          gasCap: '400000',
          summary: 'Edit recurring order',
        },
      ],
      feeQuotes: [],
    });

    expect(exposure.boundedRiskComplete).toBe(true);
    expect(exposure.grossSpend).toEqual([
      { asset: BASE_TOKEN, amount: '3000000' },
      { asset: QUOTE_TOKEN, amount: '4000000000000000000' },
    ]);
    expect(exposure.priceQuotes).toEqual([
      {
        sellAsset: BASE_TOKEN,
        buyAsset: QUOTE_TOKEN,
        sellAmount: '2000000',
        buyAmount: '5000000000000000000',
      },
      {
        sellAsset: QUOTE_TOKEN,
        buyAsset: BASE_TOKEN,
        sellAmount: '2200000000000000000',
        buyAmount: '1000000',
      },
    ]);
  });

  it('binds signer-input recurring additions while removals consume no spend budget', () => {
    const baseAsset = recurringEnvelope().intent.sellAsset!;
    const quoteAsset = recurringEnvelope().intent.buyAsset!;
    const exposure = buildPolicyExposure({
      envelope: recurringEditEnvelope(
        {
          privateAmountMode: 'signer-input',
          trustedBuyPrice: '2',
          trustedSellPrice: '2.5',
          adjustPrivateLiquidity: true,
        },
        [
          {
            id: 'recurring-edit-artifacts',
            recipe: 'recurring-edit-v1',
            bindToStepId: 'edit-recurring-order',
            commitment: `0x${'61'.repeat(32)}`,
            values: [
              {
                id: 'recurring-edit-add-base',
                kind: 'uint256',
                source: 'signer-elicitation',
                asset: baseAsset,
                allowZero: true,
                commitment: `0x${'62'.repeat(32)}`,
              },
              {
                id: 'recurring-edit-remove-base',
                kind: 'uint256',
                source: 'signer-elicitation',
                asset: baseAsset,
                allowZero: true,
                commitment: `0x${'63'.repeat(32)}`,
              },
              {
                id: 'recurring-edit-add-quote',
                kind: 'uint256',
                source: 'signer-elicitation',
                asset: quoteAsset,
                allowZero: true,
                commitment: `0x${'64'.repeat(32)}`,
              },
              {
                id: 'recurring-edit-remove-quote',
                kind: 'uint256',
                source: 'signer-elicitation',
                asset: quoteAsset,
                allowZero: true,
                commitment: `0x${'65'.repeat(32)}`,
              },
            ],
            outputs: [],
          },
        ],
      ),
      wallet: WALLET,
      steps: [
        {
          id: 'edit-recurring-order',
          kind: 'protocol',
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          value: '0',
          gasCap: '400000',
          summary: 'Edit private recurring inventory',
          privateValues: {
            'recurring-edit-add-base': '1250000',
            'recurring-edit-remove-base': '0',
            'recurring-edit-add-quote': '0',
            'recurring-edit-remove-quote': '2000000000000000000',
          },
        },
      ],
      feeQuotes: [],
    });

    expect(exposure.boundedRiskComplete).toBe(true);
    expect(exposure.agentProvidedPrivateAmounts).toBe(false);
    expect(exposure.grossSpend).toEqual([
      { asset: BASE_TOKEN, amount: '1250000' },
    ]);
    expect(exposure.priceQuotes).toHaveLength(2);
  });

  it('derives signer-input one-off terms from exact materialized private values', () => {
    const source = recurringEnvelope();
    const envelope = {
      ...source,
      operationId: 'private-one-off-policy-exposure',
      operationHash: `0x${'66'.repeat(32)}`,
      intent: {
        ...source.intent,
        action: 'create_trade',
        orderType: {
          ...source.intent.orderType!,
          id: 'one-off.private-liquidity.public',
          cadence: 'one-off',
          route: 'private-escrow',
        },
        metadata: { privateAmountMode: 'signer-input' },
      },
      privateArtifacts: [
        {
          id: 'private-liquidity-create-artifacts',
          recipe: 'private-liquidity-v1',
          bindToStepId: 'create-private-liquidity',
          commitment: `0x${'67'.repeat(32)}`,
          values: [
            {
              id: 'hidden-offer-amount',
              kind: 'uint256',
              source: 'signer-elicitation',
              asset: source.intent.sellAsset!,
              commitment: `0x${'68'.repeat(32)}`,
            },
            {
              id: 'hidden-request-amount',
              kind: 'uint256',
              source: 'signer-elicitation',
              asset: source.intent.buyAsset!,
              commitment: `0x${'69'.repeat(32)}`,
            },
          ],
          outputs: [],
        },
      ],
    } as SignedActionEnvelopeV1;
    const exposure = buildPolicyExposure({
      envelope,
      wallet: WALLET,
      steps: [
        {
          id: 'create-private-liquidity',
          kind: 'protocol',
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          value: '0',
          gasCap: '400000',
          summary: 'Create private-liquidity order',
          privateValues: {
            'hidden-offer-amount': '1500000',
            'hidden-request-amount': '3000000000000000000',
          },
        },
      ],
      feeQuotes: [],
    });

    expect(exposure).toMatchObject({
      boundedRiskComplete: true,
      agentProvidedPrivateAmounts: false,
      grossSpend: [{ asset: BASE_TOKEN, amount: '1500000' }],
      minimumReceive: [
        { asset: QUOTE_TOKEN, amount: '3000000000000000000' },
      ],
    });
    expect(exposure.priceQuotes).toEqual([
      {
        sellAsset: BASE_TOKEN,
        buyAsset: QUOTE_TOKEN,
        sellAmount: '1500000',
        buyAmount: '3000000000000000000',
      },
    ]);
  });

  it('accounts for signer-input fill spend but marks an unknown private output full-only', () => {
    const source = recurringEnvelope();
    const envelope = {
      ...source,
      operationId: 'private-fill-policy-exposure',
      operationHash: `0x${'70'.repeat(32)}`,
      intent: {
        ...source.intent,
        action: 'fill',
        orderType: {
          ...source.intent.orderType!,
          id: 'one-off.private-liquidity.public',
          cadence: 'one-off',
          route: 'private-escrow',
        },
        sellAmount: undefined,
        buyAmount: undefined,
        recipient: WALLET,
        metadata: {
          privateAmountMode: 'signer-input',
          sourceMaker: MAKER,
        },
      },
      privateArtifacts: [
        {
          id: 'private-fill-artifacts',
          recipe: 'private-fill-v1',
          bindToStepId: 'fill-private-liquidity',
          commitment: `0x${'71'.repeat(32)}`,
          values: [
            {
              id: 'request-amount',
              kind: 'uint256',
              source: 'signer-elicitation',
              asset: source.intent.sellAsset!,
              commitment: `0x${'72'.repeat(32)}`,
            },
          ],
          outputs: [],
        },
      ],
    } as SignedActionEnvelopeV1;
    const exposure = buildPolicyExposure({
      envelope,
      wallet: WALLET,
      steps: [
        {
          id: 'fill-private-liquidity',
          kind: 'protocol',
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          value: '0',
          gasCap: '400000',
          summary: 'Fill private-liquidity order',
          privateValues: { 'request-amount': '2500000' },
        },
      ],
      feeQuotes: [],
    });

    expect(exposure.grossSpend).toEqual([
      { asset: BASE_TOKEN, amount: '2500000' },
    ]);
    expect(exposure.minimumReceive).toEqual([]);
    expect(exposure.priceQuotes).toEqual([]);
    expect(exposure.boundedRiskComplete).toBe(false);
    expect(exposure.counterparty).toBe(MAKER);
    const missingMaker = { ...exposure };
    delete missingMaker.counterparty;
    expect(validatePolicyExposure(missingMaker)).toMatchObject({
      allowed: false,
      denial: {
        code: 'INVALID_EXPOSURE',
        field: 'counterparty',
      },
    });
  });

  it('evaluates recurring prices against both bounded bands while full autonomy accepts the audited action', async () => {
    const directory = await mkdtemp(
      join(tmpdir(), 'chainwhisper-recurring-policy-'),
    );
    temporaryDirectories.push(directory);
    const vault = new EncryptedSecretVault(
      directory,
      'test-only-storage-passphrase',
    );
    const store = new VaultAutonomyStore({ vault, wallet: WALLET });
    let nextId = 0;
    const manager = new AutonomyPolicyManager({
      store,
      approvals: {
        approveActivation: async ({ proposal }) => ({
          approved: true,
          proposal,
        }),
        approveResume: async () => true,
        approveRevocation: async () => true,
      },
      now: () => NOW,
      idFactory: () => `recurring-policy-${++nextId}`,
    });
    const bounded: AutonomyPolicyProposalV1 = {
      version: AUTONOMY_POLICY_VERSION,
      mode: 'bounded',
      wallet: WALLET,
      chainId: 2_632_500,
      manifestHash: MANIFEST_HASH,
      startsAt: NOW.toISOString(),
      expiresAt: new Date(
        NOW.getTime() + 24 * 60 * 60_000,
      ).toISOString(),
      agentVisiblePrivateAmounts: true,
      scope: {
        allowedActions: ['create_recurring'],
        allowedAssets: [BASE_TOKEN, QUOTE_TOKEN],
        allowedPairs: [
          { sellAsset: BASE_TOKEN, buyAsset: QUOTE_TOKEN },
          { sellAsset: QUOTE_TOKEN, buyAsset: BASE_TOKEN },
        ],
        allowedOrderTypes: ['recurring.private-liquidity.public'],
        allowedCounterparties: [],
        allowedBridgeRoutes: [],
        messaging: { enabled: false, counterparties: [] },
      },
      limits: {
        perActionSpend: [
          { asset: BASE_TOKEN, amount: '10500000' },
          { asset: QUOTE_TOKEN, amount: '7250000000000000000' },
        ],
        cumulativeSpend: [
          { asset: BASE_TOKEN, amount: '21000000' },
          { asset: QUOTE_TOKEN, amount: '14500000000000000000' },
        ],
        maximumNativeValuePerAction: '0',
        maximumNativeValueCumulative: '0',
        maximumNetworkFeePerAction: '0',
        maximumNetworkFeeCumulative: '0',
        maximumActions: 2,
        maximumMessages: 0,
        priceBands: [
          {
            sellAsset: BASE_TOKEN,
            buyAsset: QUOTE_TOKEN,
            minimumBuyPerSellNumerator: '2500000000000',
            minimumBuyPerSellDenominator: '1',
            maximumBuyPerSellNumerator: '2500000000000',
            maximumBuyPerSellDenominator: '1',
          },
          {
            sellAsset: QUOTE_TOKEN,
            buyAsset: BASE_TOKEN,
            minimumBuyPerSellNumerator: '1',
            minimumBuyPerSellDenominator: '2000000000000',
            maximumBuyPerSellNumerator: '1',
            maximumBuyPerSellDenominator: '2000000000000',
          },
        ],
      },
    };
    const activatedBounded = await manager.activate(bounded);
    expect(activatedBounded.allowed).toBe(true);
    if (!activatedBounded.allowed) throw new Error('bounded activation failed');

    const exposure = recurringExposure();
    const inBand = await manager.evaluate(
      activatedBounded.value.id,
      exposure,
    );
    if (!inBand.allowed) {
      throw new Error(`in-band exposure denied: ${JSON.stringify(inBand.denial)}`);
    }

    const outsideBand = structuredClone(exposure);
    outsideBand.priceQuotes[0]!.buyAmount =
      '2600000000000000000';
    await expect(
      manager.evaluate(activatedBounded.value.id, outsideBand),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'PRICE_OUT_OF_RANGE' },
    });
    const incomplete = {
      ...structuredClone(exposure),
      boundedRiskComplete: false,
      priceQuotes: [],
      grossSpend: [],
    };
    await expect(
      manager.reserve(activatedBounded.value.id, incomplete),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'ECONOMIC_EXPOSURE_INCOMPLETE' },
    });

    const full: AutonomyPolicyProposalV1 = {
      version: AUTONOMY_POLICY_VERSION,
      mode: 'full',
      wallet: WALLET,
      chainId: 2_632_500,
      manifestHash: MANIFEST_HASH,
      startsAt: NOW.toISOString(),
      expiresAt: new Date(
        NOW.getTime() + 23 * 60 * 60_000,
      ).toISOString(),
      agentVisiblePrivateAmounts: true,
      allowlistedEconomicSurface: true,
    };
    const activatedFull = await manager.activate(full);
    expect(activatedFull.allowed).toBe(true);
    if (!activatedFull.allowed) throw new Error('full activation failed');
    await expect(
      manager.evaluate(activatedFull.value.id, outsideBand),
    ).resolves.toMatchObject({ allowed: true });
    await expect(
      manager.evaluate(activatedFull.value.id, incomplete),
    ).resolves.toMatchObject({ allowed: true });
  });
});
