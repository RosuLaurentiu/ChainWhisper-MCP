export const ORDER_CLASSIFICATION_IDS_V1 = [
  'one-off.standard-public',
  'one-off.unlisted',
  'one-off.direct',
  'one-off.private-liquidity.public',
  'one-off.private-liquidity.unlisted',
  'one-off.private-liquidity.direct',
  'recurring.public',
  'recurring.direct',
  'recurring.private-liquidity.public',
  'recurring.private-liquidity.direct',
] as const;

export type OrderClassificationIdV1 =
  (typeof ORDER_CLASSIFICATION_IDS_V1)[number];

export type OrderCadenceV1 = 'one-off' | 'recurring';

export type OrderRouteV1 =
  | 'standard-escrow'
  | 'direct-escrow'
  | 'private-liquidity-escrow'
  | 'recurring-escrow';

export type OrderClassificationAccessV1 =
  | 'public'
  | 'unlisted'
  | 'direct';

export type OrderTermsVisibilityV1 =
  | 'public'
  | 'direct-private-terms'
  | 'hidden-liquidity';

export type OrderAssetPrivacyV1 =
  | 'public-only'
  | 'hybrid-private'
  | 'fully-private'
  | null;

export type OrderRelationV1 = 'primary' | 'counter' | 'replacement';

export interface OrderClassificationV1 {
  id: OrderClassificationIdV1;
  cadence: OrderCadenceV1;
  route: OrderRouteV1;
  access: OrderClassificationAccessV1;
  termsVisibility: OrderTermsVisibilityV1;
  assetPrivacy: OrderAssetPrivacyV1;
  relation: OrderRelationV1;
}

export interface OrderClassificationAssetV1 {
  kind: 'native' | 'erc20' | 'private-erc20';
}

export interface DeriveOrderClassificationV1Input {
  route: OrderRouteV1;
  access: OrderClassificationAccessV1;
  privateLiquidity: boolean;
  assets: readonly (OrderClassificationAssetV1 | null | undefined)[];
  relation: OrderRelationV1;
}

const assetPrivacy = (
  assets: DeriveOrderClassificationV1Input['assets'],
): OrderAssetPrivacyV1 => {
  if (
    assets.length === 0 ||
    assets.some((asset) => asset === null || asset === undefined)
  ) {
    return null;
  }
  const privateAssetCount = assets.filter(
    (asset) => asset?.kind === 'private-erc20',
  ).length;
  if (privateAssetCount === 0) return 'public-only';
  return privateAssetCount === assets.length
    ? 'fully-private'
    : 'hybrid-private';
};

const assertCompatibleRouteAndAccess = (
  route: OrderRouteV1,
  access: OrderClassificationAccessV1,
  privateLiquidity: boolean,
): void => {
  if (
    route === 'standard-escrow' &&
    (access !== 'public' || privateLiquidity)
  ) {
    throw new Error(
      'Standard escrow orders must use public access and visible liquidity.',
    );
  }
  if (
    route === 'direct-escrow' &&
    (access === 'public' || privateLiquidity)
  ) {
    throw new Error(
      'Direct escrow orders must be unlisted or recipient-bound with non-hidden liquidity.',
    );
  }
  if (
    route === 'private-liquidity-escrow' &&
    !privateLiquidity
  ) {
    throw new Error(
      'Private-liquidity escrow orders must use hidden liquidity.',
    );
  }
  if (
    route === 'recurring-escrow' &&
    access === 'unlisted'
  ) {
    throw new Error(
      'Recurring orders support only public or fixed-recipient access.',
    );
  }
};

const classificationId = (
  cadence: OrderCadenceV1,
  access: OrderClassificationAccessV1,
  privateLiquidity: boolean,
): OrderClassificationIdV1 => {
  if (cadence === 'recurring') {
    if (access === 'unlisted') {
      throw new Error(
        'Recurring orders support only public or fixed-recipient access.',
      );
    }
    return privateLiquidity
      ? `recurring.private-liquidity.${access}`
      : `recurring.${access}`;
  }
  if (privateLiquidity) {
    return `one-off.private-liquidity.${access}`;
  }
  if (access === 'public') return 'one-off.standard-public';
  return access === 'unlisted' ? 'one-off.unlisted' : 'one-off.direct';
};

export const deriveOrderClassificationV1 = (
  input: DeriveOrderClassificationV1Input,
): OrderClassificationV1 => {
  assertCompatibleRouteAndAccess(
    input.route,
    input.access,
    input.privateLiquidity,
  );
  const cadence: OrderCadenceV1 =
    input.route === 'recurring-escrow' ? 'recurring' : 'one-off';
  const privateLiquidity =
    input.privateLiquidity ||
    input.route === 'private-liquidity-escrow';

  return {
    id: classificationId(cadence, input.access, privateLiquidity),
    cadence,
    route: input.route,
    access: input.access,
    termsVisibility: privateLiquidity
      ? 'hidden-liquidity'
      : input.route === 'direct-escrow'
        ? 'direct-private-terms'
        : 'public',
    assetPrivacy: assetPrivacy(input.assets),
    relation: input.relation,
  };
};

const ID_LABELS: Readonly<Record<OrderClassificationIdV1, string>> = {
  'one-off.standard-public': 'One-off · public listing · visible terms',
  'one-off.unlisted': 'One-off · unlisted link · encrypted terms',
  'one-off.direct': 'One-off · direct recipient · encrypted terms',
  'one-off.private-liquidity.public':
    'One-off · public access · hidden private liquidity',
  'one-off.private-liquidity.unlisted':
    'One-off · unlisted link · hidden private liquidity',
  'one-off.private-liquidity.direct':
    'One-off · direct recipient · hidden private liquidity',
  'recurring.public': 'Recurring · public access · visible inventory',
  'recurring.direct': 'Recurring · direct recipient · visible inventory',
  'recurring.private-liquidity.public':
    'Recurring · public access · hidden private inventory',
  'recurring.private-liquidity.direct':
    'Recurring · direct recipient · hidden private inventory',
};

const ASSET_PRIVACY_LABELS: Readonly<
  Record<Exclude<OrderAssetPrivacyV1, null>, string>
> = {
  'public-only': 'public assets',
  'hybrid-private': 'public/private asset pair',
  'fully-private': 'private assets',
};

const RELATION_LABELS: Readonly<Record<OrderRelationV1, string>> = {
  primary: 'primary order',
  counter: 'counterorder',
  replacement: 'replacement order',
};

export const orderClassificationLabel = (
  classification: OrderClassificationV1,
): string =>
  [
    ID_LABELS[classification.id],
    classification.assetPrivacy === null
      ? 'asset privacy pending'
      : ASSET_PRIVACY_LABELS[classification.assetPrivacy],
    RELATION_LABELS[classification.relation],
  ].join(' · ');
