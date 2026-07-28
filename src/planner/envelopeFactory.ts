import type {
  DomainEnvelopeFactory,
  DomainExecutionPlan,
  DomainIntent,
  PreparedEnvelope,
  ResolvedAsset
} from '../domain/types.js';
import {
  canonicalize,
  finalizeActionEnvelope,
  hmacSha256Hex,
  signActionEnvelope
} from '../shared/canonical.js';
import type {
  ActionStepV1,
  ChainWhisperAccessMode,
  ChainWhisperAmountVisibility,
  NormalizedAssetV1,
  NormalizedIntentV1,
  PrivateArtifactGroupV1,
  SecretPolicyV1
} from '../shared/protocol.js';
import {
  hashRuntimeManifest,
  type ChainWhisperRuntimeManifestV1
} from '../shared/runtimeManifest.js';
import { encodeAllowlistedPlanStep } from './allowlist.js';

export interface SignedDomainEnvelopeFactoryOptions {
  manifest: ChainWhisperRuntimeManifestV1;
  pairingSecret: string;
  now?: () => Date;
}

const normalizeAsset = (
  asset: ResolvedAsset | null | undefined
): NormalizedAssetV1 | undefined =>
  asset
    ? {
        kind: asset.kind,
        reference: asset.id,
        ...(asset.address ? { address: asset.address } : {}),
        symbol: asset.symbol,
        decimals: asset.decimals
      }
    : undefined;

const accessMode = (intent: DomainIntent): ChainWhisperAccessMode => {
  if ('access' in intent) return intent.access;
  if ('order' in intent) return intent.order.access;
  return 'public';
};

const amountVisibility = (
  intent: DomainIntent
): ChainWhisperAmountVisibility => {
  const visibility =
    'amountVisibility' in intent
      ? intent.amountVisibility
      : 'order' in intent
        ? intent.order.amountVisibility
        : 'visible';
  return visibility === 'private' ? 'private-hidden' : 'visible';
};

const normalizedIntent = (
  intent: DomainIntent,
  protocolTarget: string,
  executionMetadata?: Record<string, string | number | boolean | null>
): NormalizedIntentV1 => {
  const resolvedOrderType =
    ('orderType' in intent ? intent.orderType : undefined) ??
    ('order' in intent ? intent.order.orderType : undefined);
  const base: NormalizedIntentV1 = {
    action: intent.action,
    accessMode: accessMode(intent),
    amountVisibility: amountVisibility(intent),
    ...(resolvedOrderType ? { orderType: resolvedOrderType } : {})
  };
  if (intent.action === 'privacy_bridge') {
    const sellAsset =
      intent.direction === 'public-to-private'
        ? intent.publicAsset
        : intent.privateAsset;
    const buyAsset =
      intent.direction === 'public-to-private'
        ? intent.privateAsset
        : intent.publicAsset;
    base.sellAsset = normalizeAsset(sellAsset);
    base.buyAsset = normalizeAsset(buyAsset);
    if (intent.amount) {
      base.sellAmount = intent.amount;
      base.buyAmount = intent.amount;
    }
    base.metadata = executionMetadata;
    return base;
  }
  if ('order' in intent) {
    base.order = {
      escrowContract: intent.order.identity.escrowContract,
      localId: intent.order.identity.localId
    };
  }
  if (intent.action === 'create_trade' || intent.action === 'counter') {
    base.sellAsset = normalizeAsset(intent.offerAsset);
    base.buyAsset = normalizeAsset(intent.requestAsset);
    if (intent.amountVisibility === 'visible') {
      if (intent.offerAmount) base.sellAmount = intent.offerAmount;
      if (intent.requestAmount) base.buyAmount = intent.requestAmount;
    }
    if (intent.recipient) base.recipient = intent.recipient;
    if (intent.expiresAt) base.expiresAt = intent.expiresAt;
    if (intent.action === 'create_trade') {
      base.metadata =
        intent.amountVisibility === 'private'
          ? { confidentialTerms: 'signer-local' }
          : {
              partialFillsAllowed: intent.fillPolicy.partialFillsAllowed,
              minPartialFillBps: intent.fillPolicy.minPartialFillBps,
              minRequestAmount: intent.fillPolicy.minRequestAmount,
              maxRequestAmountPerWallet:
                intent.fillPolicy.maxRequestAmountPerWallet,
              oneFillPerWallet: intent.fillPolicy.oneFillPerWallet
            };
    } else {
      const parent =
        intent.order.relation?.parentOrder ?? intent.order.identity;
      const directEscrow =
        intent.order.identity.escrowContract.toLowerCase() ===
        protocolTarget.toLowerCase();
      const sourceOrderRelation =
        intent.order.relation?.kind ?? 'primary';
      const legacyStandardCounter =
        intent.order.legacyCompatibility?.kind ===
          'standard-recipient-bound' &&
        sourceOrderRelation === 'counter';
      const counterRoute = legacyStandardCounter
        ? 'legacy-standard-counter'
        : !directEscrow
          ? 'cross-escrow'
          : sourceOrderRelation === 'counter'
            ? 'direct-counter'
            : 'direct-primary';
      base.metadata = {
        counteredEscrowContract: intent.order.identity.escrowContract,
        counteredTradeId: intent.order.identity.localId,
        parentEscrowContract: parent.escrowContract,
        parentTradeId: parent.localId,
        counterRoute,
        sourceOrderRelation,
        sourceMaker: intent.order.maker,
        sourceRecipient: intent.order.recipient,
        sourceOrderType: intent.order.orderType?.id ?? null,
        ...(intent.order.legacyCompatibility
          ? {
              legacyCompatibility:
                intent.order.legacyCompatibility.kind,
              legacyOrderTypeLabel:
                intent.order.legacyCompatibility.displayType
            }
          : {})
      };
    }
  } else if (intent.action === 'create_recurring') {
    base.sellAsset = normalizeAsset(intent.baseAsset);
    base.buyAsset = normalizeAsset(intent.quoteAsset);
    if (intent.recipient) base.recipient = intent.recipient;
    base.metadata = {
      buyPrice: intent.buyPrice,
      sellPrice: intent.sellPrice,
      buyQuoteLiquidity: intent.buyQuoteLiquidity,
      sellBaseLiquidity: intent.sellBaseLiquidity
    };
  } else if (intent.action === 'fill') {
    base.sellAsset = normalizeAsset(
      intent.order.kind === 'recurring' && intent.order.recurring
        ? intent.recurringSide === 'buy'
          ? intent.order.recurring.quoteAsset
          : intent.order.recurring.baseAsset
        : intent.order.requestAsset
    );
    base.buyAsset = normalizeAsset(
      intent.order.kind === 'recurring' && intent.order.recurring
        ? intent.recurringSide === 'buy'
          ? intent.order.recurring.baseAsset
          : intent.order.recurring.quoteAsset
        : intent.order.offerAsset
    );
    if (intent.order.amountVisibility === 'visible') {
      if (intent.inputAmount) base.sellAmount = intent.inputAmount;
      if (intent.minOutputAmount) base.buyAmount = intent.minOutputAmount;
    } else {
      // Only private-token amounts stay signer-local. Public/native inputs and
      // public minimum outputs remain explicit signed terms.
      if (base.sellAsset?.kind !== 'private-erc20' && intent.inputAmount) {
        base.sellAmount = intent.inputAmount;
      }
      if (base.buyAsset?.kind !== 'private-erc20' && intent.minOutputAmount) {
        base.buyAmount = intent.minOutputAmount;
      }
    }
    if (intent.order.recipient) {
      base.recipient = intent.order.recipient;
    }
    const trustedOrderSellAmount =
      intent.order.kind === 'trade'
        ? intent.order.remainingRequestAmount ??
          intent.order.requestAmount ??
          null
        : null;
    base.metadata = {
      recurringSide: intent.recurringSide,
      orderRelation: intent.order.relation?.kind ?? 'primary',
      ...(intent.order.relation?.parentOrder
        ? {
            parentEscrowContract:
              intent.order.relation.parentOrder.escrowContract,
            parentTradeId:
              intent.order.relation.parentOrder.localId
          }
        : {}),
      ...(intent.order.directTerms?.termsHash
        ? { termsHash: intent.order.directTerms.termsHash }
        : {}),
      ...(trustedOrderSellAmount
        ? { trustedOrderSellAmount }
        : {}),
      ...(intent.order.legacyCompatibility
        ? {
            legacyCompatibility:
              intent.order.legacyCompatibility.kind,
            legacyOrderTypeLabel:
              intent.order.legacyCompatibility.displayType
          }
        : {})
    };
  } else if (intent.action === 'edit') {
    const recurring = intent.order.recurring;
    base.sellAsset = normalizeAsset(
      intent.order.kind === 'recurring' && recurring
        ? recurring.baseAsset
        : intent.order.offerAsset
    );
    base.buyAsset = normalizeAsset(
      intent.order.kind === 'recurring' && recurring
        ? recurring.quoteAsset
        : intent.order.requestAsset
    );
    if (intent.order.kind === 'trade') {
      const resultingOffer =
        intent.changes.offerAmount ??
        intent.order.remainingOfferAmount ??
        intent.order.offerAmount;
      const resultingRequest =
        intent.changes.requestAmount ??
        intent.order.remainingRequestAmount ??
        intent.order.requestAmount;
      if (
        (
          intent.order.offerAsset.kind !== 'private-erc20' ||
          (
            (
              intent.order.access === 'public' ||
              intent.order.legacyCompatibility?.kind ===
                'standard-recipient-bound'
            ) &&
            intent.order.amountVisibility === 'visible'
          )
        ) &&
        resultingOffer
      ) {
        base.sellAmount = resultingOffer;
      }
      if (
        (
          intent.order.requestAsset.kind !== 'private-erc20' ||
          (
            (
              intent.order.access === 'public' ||
              intent.order.legacyCompatibility?.kind ===
                'standard-recipient-bound'
            ) &&
            intent.order.amountVisibility === 'visible'
          )
        ) &&
        resultingRequest
      ) {
        base.buyAmount = resultingRequest;
      }
      if (intent.order.recipient) {
        base.recipient = intent.order.recipient;
      }
      const resultingExpiry =
        'expiresAt' in intent.changes
          ? intent.changes.expiresAt ?? null
          : intent.order.expiresAt;
      if (resultingExpiry) base.expiresAt = resultingExpiry;
    }
    base.metadata = {
      ...Object.fromEntries(
        Object.entries(intent.changes).map(([key, value]) => [
          key,
          value === undefined ? null : value
        ])
      ),
      orderRelation:
        intent.order.kind === 'trade'
          ? 'replacement'
          : intent.order.relation?.kind ?? 'primary',
      sourceOrderRelation:
        intent.order.relation?.kind ?? 'primary',
      sourceMaker: intent.order.maker,
      sourceRecipient: intent.order.recipient,
      sourceOrderType: intent.order.orderType?.id ?? null,
      orderStatus: intent.order.status,
      ...(intent.order.legacyCompatibility
        ? {
            legacyCompatibility:
              intent.order.legacyCompatibility.kind,
            legacyOrderTypeLabel:
              intent.order.legacyCompatibility.displayType,
            legacyDefaultPolicyPreserved: true,
            legacyDefaultMinPartialFillBps:
              intent.order.fillPolicy?.minPartialFillBps ?? null
          }
        : {}),
      ...(intent.order.relation?.parentOrder
        ? {
            parentEscrowContract:
              intent.order.relation.parentOrder.escrowContract,
            parentTradeId:
              intent.order.relation.parentOrder.localId
          }
        : {}),
      ...(intent.order.fillPolicy
        ? {
            resultingPartialFillsAllowed:
              intent.changes.partialFillsAllowed ??
              intent.order.fillPolicy.partialFillsAllowed,
            resultingMinPartialFillBps:
              intent.changes.minPartialFillBps ??
              intent.order.fillPolicy.minPartialFillBps,
            resultingMinRequestAmount:
              intent.changes.minRequestAmount !== undefined
                ? intent.changes.minRequestAmount
                : intent.order.fillPolicy.minRequestAmount,
            resultingMaxRequestAmountPerWallet:
              intent.changes.maxRequestAmountPerWallet !== undefined
                ? intent.changes.maxRequestAmountPerWallet
                : intent.order.fillPolicy.maxRequestAmountPerWallet,
            resultingOneFillPerWallet:
              intent.changes.oneFillPerWallet ??
              intent.order.fillPolicy.oneFillPerWallet
          }
        : {}),
      ...(recurring
        ? {
            trustedBuyBaseAmount:
              recurring.buyBaseAmount ?? null,
            trustedBuyQuoteAmount:
              recurring.buyQuoteAmount ?? null,
            trustedSellBaseAmount:
              recurring.sellBaseAmount ?? null,
            trustedSellQuoteAmount:
              recurring.sellQuoteAmount ?? null,
            trustedBuyPrice: recurring.buyPrice,
            trustedSellPrice: recurring.sellPrice,
            privateBaseInventory:
              recurring.privateBaseInventory ?? false,
            privateQuoteInventory:
              recurring.privateQuoteInventory ?? false
          }
        : {})
    };
  } else if (intent.action === 'order_update') {
    base.sellAsset = normalizeAsset(
      intent.order.kind === 'recurring' && intent.order.recurring
        ? intent.order.recurring.baseAsset
        : intent.order.offerAsset
    );
    base.buyAsset = normalizeAsset(
      intent.order.kind === 'recurring' && intent.order.recurring
        ? intent.order.recurring.quoteAsset
        : intent.order.requestAsset
    );
    if (intent.order.recipient) {
      base.recipient = intent.order.recipient;
    }
    base.metadata = {
      update: intent.update,
      expiresAt: intent.expiresAt,
      orderRelation: intent.order.relation?.kind ?? 'primary',
      sourceOrderRelation:
        intent.order.relation?.kind ?? 'primary',
      sourceMaker: intent.order.maker,
      sourceRecipient: intent.order.recipient,
      sourceOrderType: intent.order.orderType?.id ?? null,
      orderStatus: intent.order.status,
      ...(intent.order.legacyCompatibility
        ? {
            legacyCompatibility:
              intent.order.legacyCompatibility.kind,
            legacyOrderTypeLabel:
              intent.order.legacyCompatibility.displayType
          }
        : {})
    };
  }
  return base;
};

const secretPolicy = (
  intent: DomainIntent,
  privateArtifacts: readonly PrivateArtifactGroupV1[]
): SecretPolicyV1 => {
  const mode = accessMode(intent);
  const generatedLocally = privateArtifacts.some((group) =>
    group.values.some(
      (value) =>
        value.kind === 'access-secret' && value.source === 'generated-local'
    )
  );
  return {
    accessMode: mode,
    generatedLocally,
    mayLeaveSigner: false,
    sharing: generatedLocally ? 'coti-private-message-only' : 'none'
  };
};

const artifactCommitment = (
  pairingSecret: string,
  value: unknown
): `0x${string}` =>
  hmacSha256Hex(
    pairingSecret,
    canonicalize({ domain: 'cw.private-artifact/1', value })
  );

export class SignedDomainEnvelopeFactory implements DomainEnvelopeFactory {
  readonly #manifest: ChainWhisperRuntimeManifestV1;
  readonly #pairingSecret: string;
  readonly #now: () => Date;

  constructor(options: SignedDomainEnvelopeFactoryOptions) {
    this.#manifest = options.manifest;
    this.#pairingSecret = options.pairingSecret;
    this.#now = options.now ?? (() => new Date());
  }

  async create(
    intent: DomainIntent,
    execution: DomainExecutionPlan
  ): Promise<PreparedEnvelope> {
    const protocolTarget = execution.steps.find(
      (step) => step.kind === 'protocol'
    )?.contract;
    if (!protocolTarget) {
      throw new Error('execution-protocol-step-missing');
    }
    const fees = {
      [protocolTarget.toLowerCase()]: execution.fee.scheduleAmount
    };
    const registrySnapshot = {
      registryAddress: this.#manifest.registry.address,
      registryBytecodeHash: this.#manifest.registry.bytecodeHash,
      manifestHash: hashRuntimeManifest(this.#manifest),
      observedBlock: execution.registry.blockNumber,
      contracts: Object.fromEntries(
        Object.entries(this.#manifest.contracts).map(([name, contract]) => [
          name,
          {
            address: contract.address,
            bytecodeHash: contract.bytecodeHash,
            selectors: contract.selectors
          }
        ])
      ),
      fees
    };
    if (
      registrySnapshot.manifestHash.toLowerCase() !==
      execution.registry.snapshotHash.toLowerCase()
    ) {
      throw new Error('execution-registry-snapshot-mismatch');
    }
    const privateArtifacts: PrivateArtifactGroupV1[] =
      execution.steps.flatMap((step) =>
        (step.privateArtifactGroups ?? []).map((group) => {
          const values = group.values.map((value) => {
            const safeValue = {
              id: value.id,
              kind: value.kind,
              source: value.source,
              ...(value.asset
                ? { asset: normalizeAsset(value.asset)! }
                : {}),
              ...(value.allowZero ? { allowZero: true } : {})
            };
            return {
              ...safeValue,
              commitment: artifactCommitment(this.#pairingSecret, {
                bindToStepId: step.id,
                groupId: group.id,
                recipe: group.recipe,
                value: safeValue
              })
            };
          });
          const safeGroup = {
            id: group.id,
            recipe: group.recipe,
            bindToStepId: step.id,
            values,
            outputs: group.outputs,
            ...(group.context ? { context: group.context } : {})
          };
          return {
            ...safeGroup,
            commitment: artifactCommitment(this.#pairingSecret, safeGroup)
          };
        })
      );
    const artifactCommitmentByStep = new Map(
      privateArtifacts.map((group) => [group.bindToStepId, group.commitment])
    );
    const steps: ActionStepV1[] = execution.steps.map((step) => {
      const encoded = encodeAllowlistedPlanStep(this.#manifest, step);
      const amountCommitment =
        step.approvalScheme === 'coti-private-exact'
          ? artifactCommitmentByStep.get(step.id)
          : undefined;
      if (
        step.approvalScheme === 'coti-private-exact' &&
        !amountCommitment
      ) {
        throw new Error(`private-allowance-commitment-missing:${step.id}`);
      }
      return {
        id: step.id,
        kind: step.kind,
        to: step.contract,
        data: encoded.data,
        value: step.nativeValue,
        gasCap:
          step.gasCap ??
          (step.kind === 'approval'
            ? '250000'
            : step.description.startsWith('Create recurring')
              ? '4000000'
              : '2000000'),
        summary: step.description,
        ...(step.kind === 'approval' && step.token && step.amount
          ? {
              allowance: {
                token: step.token,
                spender: String(
                  step.encoding?.arguments[0] ?? ''
                ) as `0x${string}`,
                amount: step.amount,
                ...(step.approvalScheme
                  ? { scheme: step.approvalScheme }
                  : {}),
                ...(step.approvalScheme === 'coti-private-exact'
                  ? { amountCommitment: amountCommitment! }
                  : {})
              }
            }
          : {}),
        ...(encoded.callTemplate
          ? { callTemplate: encoded.callTemplate }
          : {})
      };
    });
    if (
      steps
        .reduce((total, step) => total + BigInt(step.gasCap), 0n)
        .toString() !== execution.gasCap
    ) {
      throw new Error('execution-gas-cap-mismatch');
    }
    if (
      steps
        .reduce((total, step) => total + BigInt(step.value), 0n)
        .toString() !== execution.exactNativeValue
    ) {
      throw new Error('execution-native-value-mismatch');
    }
    const issuedAt = this.#now().toISOString();
    const envelope = finalizeActionEnvelope({
      wallet: execution.wallet,
      registrySnapshot,
      issuedAt,
      expiresAt: execution.expiresAt,
	      intent: normalizedIntent(
        intent,
        protocolTarget,
        execution.intentMetadata
      ),
      steps,
      exactNativeValue: execution.exactNativeValue,
      fee: {
        recipient: execution.fee.recipient,
        amount: execution.fee.amount,
        asset: 'native'
      },
      gasCap: execution.gasCap,
      privateInputs: execution.steps.flatMap((step) =>
        (step.privateInputPlaceholders ?? []).map((placeholder) => ({
          ...placeholder,
          bindToStepId: step.id
        }))
      ),
      ...(privateArtifacts.length ? { privateArtifacts } : {}),
      secretPolicy: secretPolicy(intent, privateArtifacts),
      simulation: {
        status: execution.simulation.deferredPrivateArtifacts
          ? 'incomplete'
          : execution.simulation.ok
            ? 'passed'
            : 'failed',
        checkedAt: issuedAt,
        blockNumber: execution.simulation.blockNumber,
        ...(execution.simulation.deferredPrivateArtifacts
          ? {
              reason: 'signer-local-private-artifacts-require-simulation'
            }
          : !execution.simulation.ok
            ? {
                reason:
                  execution.simulation.errorCode ?? 'simulation-failed'
              }
            : {})
      },
      summary: execution.simulation.expectedResult
    });
    const signed = signActionEnvelope(envelope, this.#pairingSecret);
    return {
      version: 'ActionEnvelopeV1',
      operationId: signed.operationId,
      operationHash: signed.operationHash,
      expiresAt: signed.expiresAt,
      summary: signed.summary,
      payload: signed
    };
  }
}
