import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it, vi } from 'vitest';
import {
  encodeAbiParameters,
  encodeFunctionData,
  parseAbi,
  toFunctionSelector
} from 'viem';

import type {
  CounterIntent,
  DomainStatus,
  EditIntent,
  FillIntent,
  OrderUpdateIntent,
  ResolvedAsset,
  SafeOrderSummary
} from '../src/domain/types.js';
import {
  ManifestExecutionPlanner,
  SignedDomainEnvelopeFactory,
  type PlannerRpc
} from '../src/planner/index.js';
import {
  hashRuntimeManifest,
  loadRuntimeManifest,
  type ChainWhisperRuntimeManifestV1,
  type SignedActionEnvelopeV1
} from '../src/shared/index.js';
import {
  AbiCallTemplateMaterializer,
  EncryptedSecretVault,
  StrictMaterializedIntentValidator,
  VaultBackedPrivateInputMaterializer,
  buildActionConfirmation,
  type MaterializedActionStep,
  type PrivateValueElicitor,
  type StandardOrderFactsReader
} from '../src/signer/index.js';

const PAIRING =
  'legacy-standard-execution-test-pairing-secret';
const WALLET =
  '0x1111111111111111111111111111111111111111' as const;
const MAKER =
  '0x2222222222222222222222222222222222222222' as const;
const FEE_RECIPIENT =
  '0x3333333333333333333333333333333333333333' as const;
const NOW = new Date('2026-07-28T12:00:00.000Z');
const LEGACY_COUNTER_ABI = parseAbi([
  'function counterTradeAndCloseCounteredTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),uint64)'
]);
const LEGACY_EDIT_ABI = parseAbi([
  'function editTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32)'
]);

class FakeRpc implements PlannerRpc {
  async request<T>(method: string, params: unknown[]): Promise<T> {
    if (method === 'eth_blockNumber') return '0x1234' as T;
    if (method !== 'eth_call') throw new Error('unsupported-rpc');
    const tx = params[0] as { data?: string };
    const selector = tx.data?.slice(0, 10).toLowerCase();
    if (selector === toFunctionSelector('feeAmount()').toLowerCase()) {
      return encodeAbiParameters([{ type: 'uint256' }], [123n]) as T;
    }
    if (
      selector ===
      toFunctionSelector('feeRecipient()').toLowerCase()
    ) {
      return encodeAbiParameters(
        [{ type: 'address' }],
        [FEE_RECIPIENT]
      ) as T;
    }
    if (
      selector ===
      toFunctionSelector('chargeFeeOnEdit()').toLowerCase()
    ) {
      return encodeAbiParameters([{ type: 'bool' }], [true]) as T;
    }
    if (
      selector ===
      toFunctionSelector('defaultMinPartialFillBps()').toLowerCase()
    ) {
      return encodeAbiParameters([{ type: 'uint16' }], [100]) as T;
    }
    return '0x' as T;
  }
}

const asset = (
  manifest: ChainWhisperRuntimeManifestV1,
  symbol: string
): ResolvedAsset => {
  const token = manifest.tokens.find(
    (candidate) => candidate.symbol === symbol
  );
  if (!token) throw new Error(`missing-test-token:${symbol}`);
  return {
    id:
      token.kind === 'native'
        ? 'native:coti'
        : token.address!.toLowerCase(),
    kind: token.kind,
    symbol: token.symbol,
    decimals: token.decimals,
    address:
      token.kind === 'native'
        ? null
        : (token.address!.toLowerCase() as `0x${string}`),
    verified: true
  };
};

const status = (
  manifest: ChainWhisperRuntimeManifestV1
): DomainStatus => ({
  service: 'chainwhisper-mcp',
  mode: 'keyless',
  chainId: 2_632_500,
  ready: true,
  readOnly: false,
  registry: {
    chainId: 2_632_500,
    registryAddress: manifest.registry.address,
    snapshotHash: hashRuntimeManifest(manifest),
    blockNumber: '0x1234',
    contracts: Object.fromEntries(
      Object.entries(manifest.contracts).map(([name, contract]) => [
        name,
        contract.address
      ])
    ),
    recurringWritesEnabled: true,
    verifiedAt: NOW.toISOString(),
    warnings: []
  },
  capabilities: {
    reads: true,
    priceReferences: true,
    unsignedPlanning: true,
    recurringWrites: true
  }
});

const legacyOrder = (
  manifest: ChainWhisperRuntimeManifestV1,
  relation: 'primary' | 'counter' | 'replacement'
): SafeOrderSummary => {
  const escrow =
    manifest.contracts.standardEscrow!.address.toLowerCase() as `0x${string}`;
  return {
    identity: {
      escrowContract: escrow,
      localId: '7',
      handle: `cw_${escrow.slice(2)}_7`
    },
    legacyCompatibility: {
      kind: 'standard-recipient-bound',
      displayType:
        'Legacy one-off / fixed recipient / public terms',
      canonicalReplacementType: 'one-off.direct'
    },
    kind: 'trade',
    status: 'open',
    maker: MAKER,
    recipient: WALLET,
    access: 'direct',
    amountVisibility: 'visible',
    offerAsset: asset(manifest, 'WISP'),
    requestAsset: asset(manifest, 'COTI'),
    offerAmount: '10',
    requestAmount: '2',
    remainingOfferAmount: '10',
    remainingRequestAmount: '2',
    price: '0.2',
    priceBasis: 'quote_per_base',
    expiresAt: '2026-07-29T12:00:00.000Z',
    updatedAt: NOW.toISOString(),
    snapshotHash: `0x${'11'.repeat(32)}`,
    fillPolicy: {
      partialFillsAllowed: true,
      minPartialFillBps: 100,
      minRequestAmount: null,
      maxRequestAmountPerWallet: null,
      oneFillPerWallet: false
    },
    relation: {
      kind: relation,
      parentOrder:
        relation === 'counter'
          ? {
              escrowContract: escrow,
              localId: '3',
              handle: `cw_${escrow.slice(2)}_3`
            }
          : null,
      rootOrder: null,
      replacesOrder: null,
      replacementOrder: null
    }
  };
};

const materialized = (
  step: SignedActionEnvelopeV1['steps'][number]
): MaterializedActionStep => ({
  id: step.id,
  kind: step.kind,
  to: step.to,
  data: step.data,
  value: step.value,
  gasCap: step.gasCap,
  summary: step.summary,
  ...(step.allowance ? { approval: step.allowance } : {})
});

describe('legacy Standard recipient-bound execution', () => {
  it('uses exact atomic Standard counter acceptance and shows its explicit legacy type at confirmation', async () => {
    const manifest = await loadRuntimeManifest();
    const order = legacyOrder(manifest, 'counter');
    const intent: FillIntent = {
      action: 'fill',
      wallet: WALLET,
      order,
      inputAmount: '2',
      minOutputAmount: null,
      recurringSide: null,
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: WALLET
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));

    expect(execution.steps).toHaveLength(1);
    expect(execution.steps[0]).toMatchObject({
      id: 'accept-legacy-standard-counter',
      encoding: {
        selector:
          manifest.contracts.standardEscrow!.selectors
            .acceptCounterTradeAndCloseParent,
        arguments: ['7']
      },
      nativeValue: '2000000000000000000'
    });
    expect(execution.fee.amount).toBe('0');

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    const protocol = signed.steps[0]!;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        materialized(protocol),
        0
      )
    ).resolves.toBeUndefined();

    const confirmation = buildActionConfirmation(
      signed,
      materialized(protocol),
      0
    );
    expect(confirmation).toMatchObject({
      orderType: null,
      orderTypeLabel:
        'Legacy one-off / fixed recipient / public terms',
      action: 'fill'
    });

    const tampered = structuredClone(signed);
    tampered.intent.metadata!.legacyOrderTypeLabel =
      'classification unavailable';
    await expect(
      new StrictMaterializedIntentValidator().validate(
        tampered,
        materialized(tampered.steps[0]!),
        0
      )
    ).rejects.toThrow(
      'Legacy Standard counter acceptance metadata is invalid.'
    );
  });

  it('keeps safe partial fillTrade support for a legacy fixed-recipient primary order', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: FillIntent = {
      action: 'fill',
      wallet: WALLET,
      order: legacyOrder(manifest, 'primary'),
      inputAmount: '1',
      minOutputAmount: '4',
      recurringSide: null,
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: WALLET
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));

    expect(execution.steps[0]).toMatchObject({
      id: 'fill-trade',
      encoding: {
        selector: manifest.contracts.standardEscrow!.selectors.fillTrade,
        arguments: ['7', '1000000000000000000', '4000000']
      }
    });
    expect(execution.simulation.expectedResult).toContain(
      'legacy Standard recipient-bound order'
    );
  });

  it('atomically supersedes a legacy Standard counter without assigning it a canonical new-order type', async () => {
    const manifest = await loadRuntimeManifest();
    const order = legacyOrder(manifest, 'counter');
    const intent: CounterIntent = {
      action: 'counter',
      wallet: WALLET,
      order,
      offerAsset: order.requestAsset,
      requestAsset: order.offerAsset,
      offerAmount: '1',
      requestAmount: '5',
      expiresAt: '2026-07-29T12:00:00.000Z',
      recipient: MAKER,
      access: 'direct',
      amountVisibility: 'visible',
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: MAKER
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));

    expect(execution.steps).toHaveLength(1);
    expect(execution.steps[0]).toMatchObject({
      id: 'replace-legacy-standard-counter',
      encoding: {
        selector:
          manifest.contracts.standardEscrow!.selectors
            .counterTradeAndCloseCounteredTrade,
        arguments: [
          '7',
          [0, '0x0000000000000000000000000000000000000000', '1000000000000000000'],
          [
            1,
            order.offerAsset.address,
            '5000000'
          ],
          '1785326400'
        ]
      },
      nativeValue: '1000000000000000123'
    });
    expect(execution.fee.amount).toBe('123');

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    expect(signed.intent).toMatchObject({
      metadata: {
        counterRoute: 'legacy-standard-counter',
        sourceOrderRelation: 'counter',
        legacyCompatibility: 'standard-recipient-bound',
        legacyOrderTypeLabel:
          'Legacy one-off / fixed recipient / public terms'
      }
    });
    expect(signed.intent).not.toHaveProperty('orderType');
    const protocol = signed.steps[0]!;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        materialized(protocol),
        0
      )
    ).resolves.toBeUndefined();

    const tampered = structuredClone(signed);
    tampered.intent.metadata!.counterRoute = 'direct-counter';
    await expect(
      new StrictMaterializedIntentValidator().validate(
        tampered,
        materialized(tampered.steps[0]!),
        0
      )
    ).rejects.toThrow(
      'Legacy Standard counter replacement metadata is invalid.'
    );

    const parentTampered = structuredClone(signed);
    parentTampered.intent.metadata!.parentEscrowContract =
      FEE_RECIPIENT;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        parentTampered,
        materialized(parentTampered.steps[0]!),
        0
      )
    ).rejects.toThrow('Legacy counter parent escrow');

    const valueTampered = materialized(protocol);
    valueTampered.value = '123';
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        valueTampered,
        0
      )
    ).rejects.toThrow('Protocol native value');

    const expiryArguments = structuredClone(
      protocol.callTemplate!.arguments
    ) as unknown[];
    expiryArguments[3] = '0';
    const expiryTampered = materialized(protocol);
    expiryTampered.data = encodeFunctionData({
      abi: LEGACY_COUNTER_ABI,
      functionName: 'counterTradeAndCloseCounteredTrade',
      args: expiryArguments as never
    });
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        expiryTampered,
        0
      )
    ).rejects.toThrow('Legacy counter expiry');
  });

  it('rejects legacy Standard replacement amounts above the deployed uint128 bound', async () => {
    const manifest = await loadRuntimeManifest();
    const order = legacyOrder(manifest, 'counter');
    const intent: CounterIntent = {
      action: 'counter',
      wallet: WALLET,
      order,
      offerAsset: order.requestAsset,
      requestAsset: order.offerAsset,
      offerAmount: '340282366920938463464',
      requestAmount: '5',
      expiresAt: null,
      recipient: MAKER,
      access: 'direct',
      amountVisibility: 'visible',
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: MAKER
      }
    };

    await expect(
      new ManifestExecutionPlanner({
        manifest,
        rpc: new FakeRpc(),
        now: () => NOW
      }).plan(intent, status(manifest))
    ).rejects.toThrow(
      "Legacy counter offer amount exceeds the deployed standard escrow's uint128 limit."
    );
  });

  it('edits an unfilled legacy Standard primary through exact editTrade while preserving its recipient and type', async () => {
    const manifest = await loadRuntimeManifest();
    const order = legacyOrder(manifest, 'primary');
    const intent: EditIntent = {
      action: 'edit',
      wallet: MAKER,
      order,
      changes: {
        offerAmount: '12',
        requestAmount: '3',
        expiresAt: '2026-07-30T12:00:00.000Z'
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));

    const protocolPlan = execution.steps.at(-1)!;
    expect(protocolPlan).toMatchObject({
      id: 'edit-legacy-standard-trade',
      encoding: {
        selector:
          manifest.contracts.standardEscrow!.selectors.editTrade,
        arguments: [
          '7',
          [1, order.offerAsset.address, '12000000'],
          [
            0,
            '0x0000000000000000000000000000000000000000',
            '3000000000000000000'
          ],
          WALLET,
          Math.floor(
            Date.parse('2026-07-30T12:00:00.000Z') / 1_000
          ).toString(),
          false,
          `0x${'00'.repeat(32)}`
        ]
      },
      nativeValue: '123'
    });
    expect(execution.fee.amount).toBe('123');
    expect(execution.simulation.expectedResult).toContain(
      'same fixed recipient'
    );

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    expect(signed.intent).toMatchObject({
      accessMode: 'direct',
      amountVisibility: 'visible',
      recipient: WALLET,
      sellAmount: '12',
      buyAmount: '3',
      metadata: {
        orderRelation: 'replacement',
        sourceOrderRelation: 'primary',
        sourceMaker: MAKER,
        sourceRecipient: WALLET,
        sourceOrderType: null,
        legacyCompatibility: 'standard-recipient-bound',
        legacyOrderTypeLabel:
          'Legacy one-off / fixed recipient / public terms',
        legacyDefaultPolicyPreserved: true,
        legacyDefaultMinPartialFillBps: 100
      }
    });
    expect(signed.intent).not.toHaveProperty('orderType');

    const protocolIndex = signed.steps.length - 1;
    const protocol = signed.steps[protocolIndex]!;
    expect(protocol.callTemplate?.functionSignature).toBe(
      'editTrade(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32)'
    );
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        materialized(protocol),
        protocolIndex
      )
    ).resolves.toBeUndefined();
    expect(
      buildActionConfirmation(
        signed,
        materialized(protocol),
        protocolIndex
      )
    ).toMatchObject({
      action: 'edit',
      orderType: null,
      orderTypeLabel:
        'Legacy one-off / fixed recipient / public terms',
      counterparty: WALLET
    });

    const recipientArguments = structuredClone(
      protocol.callTemplate!.arguments
    ) as unknown[];
    recipientArguments[3] = FEE_RECIPIENT;
    const recipientTampered = materialized(protocol);
    recipientTampered.data = encodeFunctionData({
      abi: LEGACY_EDIT_ABI,
      functionName: 'editTrade',
      args: recipientArguments as never
    });
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        recipientTampered,
        protocolIndex
      )
    ).rejects.toThrow('Legacy replacement recipient');

    const relationTampered = structuredClone(signed);
    relationTampered.intent.metadata!.sourceOrderRelation = 'counter';
    await expect(
      new StrictMaterializedIntentValidator().validate(
        relationTampered,
        materialized(relationTampered.steps[protocolIndex]!),
        protocolIndex
      )
    ).rejects.toThrow('Legacy Standard edit metadata is invalid.');
  });

  it('refuses legacy Standard counter edits and any edit whose policy would be reset', async () => {
    const manifest = await loadRuntimeManifest();
    const planner = new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    });
    const counterIntent: EditIntent = {
      action: 'edit',
      wallet: MAKER,
      order: legacyOrder(manifest, 'counter'),
      changes: { offerAmount: '12' }
    };
    await expect(
      planner.plan(counterIntent, status(manifest))
    ).rejects.toThrow(
      'Use chainwhisper_prepare_counter to supersede the counter atomically.'
    );

    const policyMismatch = legacyOrder(manifest, 'primary');
    policyMismatch.fillPolicy = {
      ...policyMismatch.fillPolicy!,
      minPartialFillBps: 200
    };
    await expect(
      planner.plan(
        {
          ...counterIntent,
          order: policyMismatch
        },
        status(manifest)
      )
    ).rejects.toThrow(
      'editTrade would reset this order to a different fill policy'
    );

    await expect(
      planner.plan(
        {
          ...counterIntent,
          order: legacyOrder(manifest, 'primary'),
          changes: { partialFillsAllowed: false }
        },
        status(manifest)
      )
    ).rejects.toThrow(
      'can change only the visible offer amount, request amount, or expiry'
    );
  });

  it('materializes the exact visible p.WISP allowance for a legacy Standard edit', async () => {
    const manifest = await loadRuntimeManifest();
    const order = {
      ...legacyOrder(manifest, 'primary'),
      offerAsset: asset(manifest, 'p.WISP'),
      requestAsset: asset(manifest, 'COTI'),
      offerAmount: '3',
      requestAmount: '1',
      remainingOfferAmount: '3',
      remainingRequestAmount: '1'
    };
    const intent: EditIntent = {
      action: 'edit',
      wallet: MAKER,
      order,
      changes: {
        offerAmount: '4',
        requestAmount: '2'
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));
    expect(execution.steps[0]).toMatchObject({
      kind: 'approval',
      approvalScheme: 'coti-private-exact',
      token: order.offerAsset.address,
      privateArtifactGroups: [
        expect.objectContaining({
          recipe: 'coti-private-exact-allowance-v1',
          values: [
            expect.objectContaining({
              id: 'offer-amount',
              source: 'intent-sell-amount'
            })
          ]
        })
      ]
    });

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    expect(signed.intent.sellAmount).toBe('4');
    const readiness = vi.fn(async () => undefined);
    const materializer = new VaultBackedPrivateInputMaterializer({
      vault: new EncryptedSecretVault(
        await mkdtemp(join(tmpdir(), 'cw-legacy-edit-')),
        'legacy-standard-edit-test-passphrase'
      ),
      privateUint256: {
        encodePrivateUint256: async () => ({
          ciphertext: {
            ciphertextHigh: 21n,
            ciphertextLow: 22n
          },
          signature: `0x${'55'.repeat(65)}`
        })
      },
      calldata: new AbiCallTemplateMaterializer(),
      elicitor: {
        isSupported: () => false,
        requestPrivateValues: async () => ({
          outcome: 'cancelled' as const
        })
      },
      aesKey: () => '66'.repeat(16),
      timeoutMs: 5_000,
      assertPrivateSpendReady: readiness
    });
    const approval = await materializer.materializeStep(signed, 0);
    expect(approval.approval?.amount).toBe('4000000');
    expect(approval.privateValues?.['offer-amount']).toBe('4000000');
    await expect(
      new StrictMaterializedIntentValidator({
        standardOrders: {
          readStandardOrderFacts: vi.fn(async () => ({
            maker: FEE_RECIPIENT,
            recipient: WALLET
          }))
        }
      }).validate(signed, approval, 0)
    ).rejects.toThrow(
      'Live Standard lifecycle maker does not match the signed source maker'
    );
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        approval,
        0
      )
    ).resolves.toBeUndefined();
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        materialized(signed.steps[1]!),
        1
      )
    ).resolves.toBeUndefined();
  });

  it('binds legacy Standard lifecycle updates to their explicit type, exact escrow, and maker role', async () => {
    const manifest = await loadRuntimeManifest();
    const intent: OrderUpdateIntent = {
      action: 'order_update',
      wallet: MAKER,
      order: legacyOrder(manifest, 'primary'),
      update: 'cancel',
      expiresAt: null
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));
    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    const protocol = signed.steps[0]!;

    expect(signed.intent).toMatchObject({
      recipient: WALLET,
      metadata: {
        update: 'cancel',
        sourceOrderRelation: 'primary',
        sourceMaker: MAKER,
        sourceRecipient: WALLET,
        sourceOrderType: null,
        legacyCompatibility: 'standard-recipient-bound',
        legacyOrderTypeLabel:
          'Legacy one-off / fixed recipient / public terms'
      }
    });
    expect(signed.intent).not.toHaveProperty('orderType');
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        materialized(protocol),
        0
      )
    ).resolves.toBeUndefined();
    expect(
      buildActionConfirmation(signed, materialized(protocol), 0)
    ).toMatchObject({
      action: 'order_update',
      orderType: null,
      orderTypeLabel:
        'Legacy one-off / fixed recipient / public terms'
    });

    const markerOmitted = structuredClone(signed);
    delete markerOmitted.intent.metadata!.legacyCompatibility;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        markerOmitted,
        materialized(markerOmitted.steps[0]!),
        0
      )
    ).rejects.toThrow(/legacyCompatibility|Legacy Standard lifecycle/u);

    const pairedRouteAndTargetTamper = structuredClone(signed);
    delete pairedRouteAndTargetTamper.intent.metadata!
      .legacyCompatibility;
    delete pairedRouteAndTargetTamper.intent.metadata!
      .legacyOrderTypeLabel;
    pairedRouteAndTargetTamper.intent.accessMode = 'public';
    pairedRouteAndTargetTamper.secretPolicy.accessMode = 'public';
    const pairedTarget = materialized(
      pairedRouteAndTargetTamper.steps[0]!
    );
    pairedTarget.to =
      manifest.contracts.privateEscrow!.address;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        pairedRouteAndTargetTamper,
        pairedTarget,
        0
      )
    ).rejects.toThrow('Legacy Standard lifecycle escrow');

    for (const [
      missingMarkerField,
      expectedError
    ] of [
      [
        'legacyOrderTypeLabel',
        /legacyOrderTypeLabel|Legacy Standard lifecycle metadata/u
      ],
      [
        'sourceOrderType',
        /sourceOrderType|Legacy Standard lifecycle metadata/u
      ]
    ] as const) {
      const incompleteMarker = structuredClone(signed);
      delete incompleteMarker.intent.metadata![missingMarkerField];
      await expect(
        new StrictMaterializedIntentValidator().validate(
          incompleteMarker,
          materialized(incompleteMarker.steps[0]!),
          0
        )
      ).rejects.toThrow(expectedError);
    }

    const reclassifiedActorTamper = structuredClone(signed);
    reclassifiedActorTamper.intent.orderType = {
      id: 'one-off.standard-public',
      cadence: 'one-off',
      route: 'standard-escrow',
      access: 'public',
      termsVisibility: 'public',
      assetPrivacy: 'public-only',
      relation: 'primary'
    };
    reclassifiedActorTamper.intent.accessMode = 'public';
    reclassifiedActorTamper.secretPolicy.accessMode = 'public';
    delete reclassifiedActorTamper.intent.metadata!
      .legacyCompatibility;
    delete reclassifiedActorTamper.intent.metadata!
      .legacyOrderTypeLabel;
    reclassifiedActorTamper.intent.metadata!.sourceOrderType =
      'one-off.standard-public';
    reclassifiedActorTamper.intent.metadata!.sourceMaker =
      FEE_RECIPIENT;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        reclassifiedActorTamper,
        materialized(reclassifiedActorTamper.steps[0]!),
        0
      )
    ).rejects.toThrow('Order lifecycle maker');

    const coordinatedReclassification = structuredClone(signed);
    coordinatedReclassification.intent.orderType = {
      id: 'one-off.standard-public',
      cadence: 'one-off',
      route: 'standard-escrow',
      access: 'public',
      termsVisibility: 'public',
      assetPrivacy: 'public-only',
      relation: 'primary'
    };
    coordinatedReclassification.intent.accessMode = 'public';
    coordinatedReclassification.secretPolicy.accessMode = 'public';
    delete coordinatedReclassification.intent.recipient;
    delete coordinatedReclassification.intent.metadata!
      .sourceRecipient;
    delete coordinatedReclassification.intent.metadata!
      .legacyCompatibility;
    delete coordinatedReclassification.intent.metadata!
      .legacyOrderTypeLabel;
    coordinatedReclassification.intent.metadata!.sourceOrderType =
      'one-off.standard-public';
    expect(
      coordinatedReclassification.intent.metadata!.sourceMaker
    ).toBe(MAKER);
    const standardOrders: StandardOrderFactsReader = {
      readStandardOrderFacts: vi.fn(async () => ({
        maker: MAKER,
        recipient: WALLET
      }))
    };
    await expect(
      new StrictMaterializedIntentValidator({
        standardOrders
      }).validate(
        coordinatedReclassification,
        materialized(coordinatedReclassification.steps[0]!),
        0
      )
    ).rejects.toThrow(
      'Live Standard fixed-recipient lifecycle requires the exact legacy type and recipient binding'
    );
    expect(
      standardOrders.readStandardOrderFacts
    ).toHaveBeenCalledWith(
      manifest.contracts.standardEscrow!.address.toLowerCase(),
      '7'
    );

    const targetTampered = materialized(protocol);
    targetTampered.to = FEE_RECIPIENT;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        targetTampered,
        0
      )
    ).rejects.toThrow('Legacy Standard lifecycle escrow');

    const roleTampered = structuredClone(signed);
    roleTampered.intent.metadata!.sourceMaker = FEE_RECIPIENT;
    await expect(
      new StrictMaterializedIntentValidator().validate(
        roleTampered,
        materialized(roleTampered.steps[0]!),
        0
      )
    ).rejects.toThrow('Legacy Standard lifecycle maker');
  });

  it('uses an exact signer-materialized pToken allowance while keeping legacy Standard counter amounts visibly bound', async () => {
    const manifest = await loadRuntimeManifest();
    const order = {
      ...legacyOrder(manifest, 'counter'),
      offerAsset: asset(manifest, 'COTI'),
      requestAsset: asset(manifest, 'p.WISP'),
      offerAmount: '1',
      requestAmount: '3',
      remainingOfferAmount: '1',
      remainingRequestAmount: '3'
    };
    const intent: CounterIntent = {
      action: 'counter',
      wallet: WALLET,
      order,
      offerAsset: order.requestAsset,
      requestAsset: order.offerAsset,
      offerAmount: '3',
      requestAmount: '1',
      expiresAt: null,
      recipient: MAKER,
      access: 'direct',
      amountVisibility: 'visible',
      secretPolicy: {
        kind: 'recipient-bound',
        recipient: MAKER
      }
    };
    const execution = await new ManifestExecutionPlanner({
      manifest,
      rpc: new FakeRpc(),
      now: () => NOW
    }).plan(intent, status(manifest));

    expect(execution.steps).toHaveLength(2);
    expect(execution.steps[0]).toMatchObject({
      kind: 'approval',
      approvalScheme: 'coti-private-exact',
      token: order.requestAsset.address,
      amount: '0',
      encoding: {
        arguments: [
          manifest.contracts.standardEscrow!.address,
          [['0', '0'], '0x']
        ]
      },
      privateArtifactGroups: [
        expect.objectContaining({
          recipe: 'coti-private-exact-allowance-v1',
          values: [
            expect.objectContaining({
              id: 'offer-amount',
              source: 'intent-sell-amount',
              asset: expect.objectContaining({
                symbol: 'p.WISP'
              })
            })
          ]
        })
      ]
    });
    expect(execution.steps[1]).toMatchObject({
      id: 'replace-legacy-standard-counter',
      encoding: {
        arguments: [
          '7',
          [2, order.requestAsset.address, '3000000'],
          [
            0,
            '0x0000000000000000000000000000000000000000',
            '1000000000000000000'
          ],
          '0'
        ]
      }
    });
    expect(
      execution.steps[1]!.privateArtifactGroups
    ).toBeUndefined();

    const prepared = await new SignedDomainEnvelopeFactory({
      manifest,
      pairingSecret: PAIRING,
      now: () => NOW
    }).create(intent, execution);
    const signed = prepared.payload as SignedActionEnvelopeV1;
    const readiness = vi.fn(async () => undefined);
    const noElicitation: PrivateValueElicitor = {
      isSupported: () => false,
      requestPrivateValues: async () => ({
        outcome: 'cancelled'
      })
    };
    const materializer = new VaultBackedPrivateInputMaterializer({
      vault: new EncryptedSecretVault(
        await mkdtemp(join(tmpdir(), 'cw-legacy-standard-')),
        'legacy-standard-test-vault-passphrase'
      ),
      privateUint256: {
        encodePrivateUint256: async () => ({
          ciphertext: {
            ciphertextHigh: 11n,
            ciphertextLow: 12n
          },
          signature: `0x${'33'.repeat(65)}`
        })
      },
      calldata: new AbiCallTemplateMaterializer(),
      elicitor: noElicitation,
      aesKey: () => '44'.repeat(16),
      timeoutMs: 5_000,
      assertPrivateSpendReady: readiness
    });
    const approval = await materializer.materializeStep(signed, 0);
    expect(approval.approval?.amount).toBe('3000000');
    expect(approval.privateValues?.['offer-amount']).toBe('3000000');
    expect(readiness).toHaveBeenCalledWith({
      token: order.requestAsset.address,
      spender:
        manifest.contracts.standardEscrow!.address.toLowerCase(),
      amount: '3000000'
    });
    await expect(
      new StrictMaterializedIntentValidator().validate(
        signed,
        approval,
        0
      )
    ).resolves.toBeUndefined();
  });
});
