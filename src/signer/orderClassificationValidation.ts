import { toFunctionSelector } from 'viem';

import type {
  ChainWhisperAccessMode,
  NormalizedAssetV1,
  OrderAssetPrivacyV1,
  OrderClassificationIdV1,
  OrderClassificationV1,
  OrderRelationV1,
  OrderRouteV1,
  OrderTermsVisibilityV1,
  SignedActionEnvelopeV1,
} from '../shared/index.js';
import { SignerError } from './errors.js';

const CLASSIFICATION_FIELDS = [
  'access',
  'assetPrivacy',
  'cadence',
  'id',
  'relation',
  'route',
  'termsVisibility',
] as const;

const DIRECT_COUNTER_ROUTE_BY_SIGNATURE = new Map<
  string,
  'cross-escrow' | 'direct-primary' | 'direct-counter'
>([
  [
    'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    'cross-escrow',
  ],
  [
    'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    'direct-primary',
  ],
  [
    'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
    'direct-counter',
  ],
]);

const fail = (message: string): never => {
  throw new SignerError('ENVELOPE_TAMPERED', message);
};

const sameAddress = (left: string, right: string): boolean =>
  left.toLowerCase() === right.toLowerCase();

const protocolStep = (
  envelope: SignedActionEnvelopeV1,
): SignedActionEnvelopeV1['steps'][number] => {
  const steps = envelope.steps.filter((step) => step.kind === 'protocol');
  if (steps.length !== 1 || !steps[0]) {
    return fail(
      'A classified action must contain exactly one signed protocol step.',
    );
  }
  return steps[0];
};

const routeForTarget = (
  envelope: SignedActionEnvelopeV1,
  target: string,
): {
  route: OrderRouteV1;
  selectors: Readonly<Record<string, string>>;
} => {
  const candidates: ReadonlyArray<{
    contractName: string;
    route: OrderRouteV1;
  }> = [
    { contractName: 'standardEscrow', route: 'standard-escrow' },
    { contractName: 'directEscrow', route: 'direct-escrow' },
    {
      contractName: 'privateEscrow',
      route: 'private-liquidity-escrow',
    },
    { contractName: 'recurringEscrow', route: 'recurring-escrow' },
  ];
  const matches = candidates.flatMap(({ contractName, route }) => {
    const contract = envelope.registrySnapshot.contracts[contractName];
    return contract && sameAddress(contract.address, target)
      ? [{ route, selectors: contract.selectors }]
      : [];
  });
  if (matches.length !== 1 || !matches[0]) {
    return fail(
      'The signed protocol target does not identify one canonical order route.',
    );
  }
  return matches[0];
};

const requireCanonicalSignature = (
  step: SignedActionEnvelopeV1['steps'][number],
  selectors: Readonly<Record<string, string>>,
): string => {
  const signature =
    step.callTemplate?.functionSignature ??
    fail('A classified protocol step is missing its canonical signature.');
  let selector: string;
  try {
    selector = toFunctionSelector(signature).toLowerCase();
  } catch {
    return fail('The classified protocol signature is not canonical.');
  }
  if (
    !Object.values(selectors).some(
      (allowedSelector) =>
        allowedSelector.toLowerCase() === selector,
    ) ||
    step.data.slice(0, 10).toLowerCase() !== selector
  ) {
    return fail(
      'The classified protocol signature does not belong to its signed order route.',
    );
  }
  return signature;
};

const accessMode = (
  envelope: SignedActionEnvelopeV1,
): ChainWhisperAccessMode => {
  const access = envelope.intent.accessMode;
  if (
    access !== 'public' &&
    access !== 'unlisted' &&
    access !== 'direct'
  ) {
    return fail('The classified action has no canonical access mode.');
  }
  if (envelope.secretPolicy.accessMode !== access) {
    return fail(
      'The order classification access does not match the signer secret policy.',
    );
  }
  return access;
};

const privateLiquidity = (
  envelope: SignedActionEnvelopeV1,
  route: OrderRouteV1,
): boolean => {
  const visibility = envelope.intent.amountVisibility;
  if (visibility !== 'visible' && visibility !== 'private-hidden') {
    return fail(
      'The classified action has no canonical amount-visibility mode.',
    );
  }
  if (route === 'private-liquidity-escrow') {
    if (visibility !== 'private-hidden') {
      return fail(
        'Private-liquidity escrow actions must keep liquidity hidden.',
      );
    }
    return true;
  }
  if (route === 'recurring-escrow') {
    return visibility === 'private-hidden';
  }
  if (visibility !== 'visible') {
    return fail(
      'This order route cannot be classified as hidden liquidity.',
    );
  }
  return false;
};

const requireCompatibleAccess = (
  route: OrderRouteV1,
  access: ChainWhisperAccessMode,
): void => {
  if (route === 'standard-escrow' && access !== 'public') {
    fail('Standard escrow actions must use public access.');
  }
  if (route === 'direct-escrow' && access === 'public') {
    fail('Direct escrow actions must be unlisted or recipient-bound.');
  }
};

const assetPrivacy = (
  sellAsset: NormalizedAssetV1 | undefined,
  buyAsset: NormalizedAssetV1 | undefined,
): Exclude<OrderAssetPrivacyV1, null> => {
  if (!sellAsset || !buyAsset) {
    return fail(
      'A classified action must bind both assets in its signed intent.',
    );
  }
  const privateCount = [sellAsset, buyAsset].filter(
    (asset) => asset.kind === 'private-erc20',
  ).length;
  if (privateCount === 0) return 'public-only';
  return privateCount === 2 ? 'fully-private' : 'hybrid-private';
};

const metadataRelation = (
  envelope: SignedActionEnvelopeV1,
): OrderRelationV1 => {
  const value = envelope.intent.metadata?.orderRelation;
  if (
    value !== 'primary' &&
    value !== 'counter' &&
    value !== 'replacement'
  ) {
    return fail(
      'The classified action is missing its signed order relation.',
    );
  }
  return value;
};

const relation = (
  envelope: SignedActionEnvelopeV1,
  signature: string,
): OrderRelationV1 => {
  switch (envelope.intent.action) {
    case 'create_trade':
    case 'create_recurring':
      return 'primary';
    case 'counter':
      return 'counter';
    case 'fill': {
      const signedRelation = metadataRelation(envelope);
      const isCounterAcceptance = signature.startsWith(
        'acceptCounterTradeAndCloseParent(',
      );
      if (
        (signedRelation === 'counter') !== isCounterAcceptance
      ) {
        return fail(
          'The fill selector does not match the signed order relation.',
        );
      }
      return signedRelation;
    }
    case 'edit':
    case 'order_update':
      return metadataRelation(envelope);
    case 'send_order_message':
      return fail(
        'Private messages do not have an executable order classification.',
      );
    case 'privacy_bridge':
      return fail(
        'Privacy Portal actions do not have an OTC order classification.',
      );
  }
};

const classificationId = (
  route: OrderRouteV1,
  access: ChainWhisperAccessMode,
  isPrivateLiquidity: boolean,
): OrderClassificationIdV1 => {
  if (route === 'recurring-escrow') {
    if (access === 'unlisted') {
      return fail(
        'Recurring orders support only public or fixed-recipient access.',
      );
    }
    return isPrivateLiquidity
      ? `recurring.private-liquidity.${access}`
      : `recurring.${access}`;
  }
  if (route === 'private-liquidity-escrow') {
    return `one-off.private-liquidity.${access}`;
  }
  if (route === 'standard-escrow') {
    return 'one-off.standard-public';
  }
  return access === 'unlisted'
    ? 'one-off.unlisted'
    : 'one-off.direct';
};

const expectedClassification = (
  envelope: SignedActionEnvelopeV1,
): OrderClassificationV1 => {
  const step = protocolStep(envelope);
  const routedTarget = routeForTarget(envelope, step.to);
  const signature = requireCanonicalSignature(
    step,
    routedTarget.selectors,
  );
  if (envelope.intent.action === 'counter') {
    const expectedCounterRoute =
      DIRECT_COUNTER_ROUTE_BY_SIGNATURE.get(signature) ??
      fail(
        'The classified counter does not use a canonical Direct-counter selector.',
      );
    const signedCounterRoute =
      envelope.intent.metadata?.counterRoute;
    const sourceOrderRelation =
      envelope.intent.metadata?.sourceOrderRelation;
    const sourceMaker = envelope.intent.metadata?.sourceMaker;
    const sourceRecipient =
      envelope.intent.metadata?.sourceRecipient;
    const resultingRecipient = envelope.intent.recipient;
    if (
      routedTarget.route !== 'direct-escrow' ||
      signedCounterRoute !== expectedCounterRoute ||
      (
        sourceOrderRelation !== 'primary' &&
        sourceOrderRelation !== 'counter' &&
        sourceOrderRelation !== 'replacement'
      ) ||
      (
        expectedCounterRoute === 'direct-counter' &&
        sourceOrderRelation !== 'counter'
      ) ||
      (
        expectedCounterRoute === 'direct-primary' &&
        sourceOrderRelation === 'counter'
      ) ||
      typeof sourceMaker !== 'string' ||
      typeof resultingRecipient !== 'string' ||
      !sameAddress(sourceMaker, resultingRecipient) ||
      sameAddress(sourceMaker, envelope.wallet) ||
      (
        expectedCounterRoute !== 'cross-escrow' &&
        sourceRecipient !== null &&
        (
          typeof sourceRecipient !== 'string' ||
          !sameAddress(sourceRecipient, envelope.wallet)
        )
      ) ||
      (
        expectedCounterRoute === 'direct-counter' &&
        sourceRecipient === null
      )
    ) {
      fail(
        'The classified Direct-counter route does not match its selector and source relation.',
      );
    }
    const sourceOrder =
      envelope.intent.order ??
      fail('The classified counter is missing its source order.');
    const sameEscrow = sameAddress(sourceOrder.escrowContract, step.to);
    if (
      (expectedCounterRoute === 'cross-escrow') === sameEscrow
    ) {
      fail(
        'The classified Direct-counter route does not match its source escrow.',
      );
    }
  }
  const access = accessMode(envelope);
  requireCompatibleAccess(routedTarget.route, access);
  const hiddenLiquidity = privateLiquidity(
    envelope,
    routedTarget.route,
  );
  const cadence =
    routedTarget.route === 'recurring-escrow'
      ? 'recurring'
      : 'one-off';
  const expectedRelation = relation(envelope, signature);

  if (
    envelope.intent.order &&
    envelope.intent.action !== 'counter' &&
    !sameAddress(envelope.intent.order.escrowContract, step.to)
  ) {
    fail(
      'The classified order identity does not match the protocol target.',
    );
  }

  const termsVisibility: OrderTermsVisibilityV1 = hiddenLiquidity
    ? 'hidden-liquidity'
    : routedTarget.route === 'direct-escrow'
      ? 'direct-private-terms'
      : 'public';
  return {
    id: classificationId(
      routedTarget.route,
      access,
      hiddenLiquidity,
    ),
    cadence,
    route: routedTarget.route,
    access,
    termsVisibility,
    assetPrivacy: assetPrivacy(
      envelope.intent.sellAsset,
      envelope.intent.buyAsset,
    ),
    relation: expectedRelation,
  };
};

const requireCanonicalObject = (
  classification: OrderClassificationV1,
): void => {
  if (
    typeof classification !== 'object' ||
    classification === null ||
    Array.isArray(classification)
  ) {
    fail('The signed order classification is not an object.');
  }
  const actualKeys = Object.keys(classification).sort();
  const expectedKeys = [...CLASSIFICATION_FIELDS].sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail('The signed order classification is not canonical.');
  }
};

/**
 * Recomputes classification exclusively from signed executable facts. This is
 * intentionally independent from the planner-side classification helper.
 * Earlier envelopes without `orderType` remain valid.
 */
export const validateSignedOrderClassification = (
  envelope: SignedActionEnvelopeV1,
): void => {
  const supplied = envelope.intent.orderType;
  if (!supplied) return;
  requireCanonicalObject(supplied);
  const expected = expectedClassification(envelope);
  for (const field of CLASSIFICATION_FIELDS) {
    if (supplied[field] !== expected[field]) {
      fail(
        `Order classification ${field} does not match the signed action.`,
      );
    }
  }
};
