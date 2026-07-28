import { describe, expect, it } from 'vitest';

import {
  ORDER_CLASSIFICATION_IDS_V1,
  deriveOrderClassificationV1,
  orderClassificationLabel,
  type DeriveOrderClassificationV1Input,
  type OrderClassificationIdV1,
} from '../src/shared/index.js';

const PUBLIC_ASSETS = [
  { kind: 'erc20' as const },
  { kind: 'native' as const },
];

describe('OrderClassificationV1', () => {
  it('derives every canonical order type id from route, access, and liquidity privacy', () => {
    const cases: Array<
      [
        OrderClassificationIdV1,
        Omit<
          DeriveOrderClassificationV1Input,
          'assets' | 'relation'
        >,
      ]
    > = [
      [
        'one-off.standard-public',
        {
          route: 'standard-escrow',
          access: 'public',
          privateLiquidity: false,
        },
      ],
      [
        'one-off.unlisted',
        {
          route: 'direct-escrow',
          access: 'unlisted',
          privateLiquidity: false,
        },
      ],
      [
        'one-off.direct',
        {
          route: 'direct-escrow',
          access: 'direct',
          privateLiquidity: false,
        },
      ],
      [
        'one-off.private-liquidity.public',
        {
          route: 'private-liquidity-escrow',
          access: 'public',
          privateLiquidity: true,
        },
      ],
      [
        'one-off.private-liquidity.unlisted',
        {
          route: 'private-liquidity-escrow',
          access: 'unlisted',
          privateLiquidity: true,
        },
      ],
      [
        'one-off.private-liquidity.direct',
        {
          route: 'private-liquidity-escrow',
          access: 'direct',
          privateLiquidity: true,
        },
      ],
      [
        'recurring.public',
        {
          route: 'recurring-escrow',
          access: 'public',
          privateLiquidity: false,
        },
      ],
      [
        'recurring.direct',
        {
          route: 'recurring-escrow',
          access: 'direct',
          privateLiquidity: false,
        },
      ],
      [
        'recurring.private-liquidity.public',
        {
          route: 'recurring-escrow',
          access: 'public',
          privateLiquidity: true,
        },
      ],
      [
        'recurring.private-liquidity.direct',
        {
          route: 'recurring-escrow',
          access: 'direct',
          privateLiquidity: true,
        },
      ],
    ];

    const actual = cases.map(([expectedId, input]) => {
      const classification = deriveOrderClassificationV1({
        ...input,
        assets: PUBLIC_ASSETS,
        relation: 'primary',
      });
      expect(classification.id).toBe(expectedId);
      return classification.id;
    });

    expect(actual).toEqual(ORDER_CLASSIFICATION_IDS_V1);
  });

  it('derives visibility, asset privacy, relation, and a local human label', () => {
    const classification = deriveOrderClassificationV1({
      route: 'recurring-escrow',
      access: 'direct',
      privateLiquidity: true,
      assets: [
        { kind: 'private-erc20' },
        { kind: 'erc20' },
      ],
      relation: 'replacement',
    });

    expect(classification).toEqual({
      id: 'recurring.private-liquidity.direct',
      cadence: 'recurring',
      route: 'recurring-escrow',
      access: 'direct',
      termsVisibility: 'hidden-liquidity',
      assetPrivacy: 'hybrid-private',
      relation: 'replacement',
    });
    expect(orderClassificationLabel(classification)).toBe(
      'Recurring · direct recipient · hidden private inventory · public/private asset pair · replacement order',
    );
  });

  it('uses null until all assets are known and rejects inconsistent direct routes', () => {
    expect(
      deriveOrderClassificationV1({
        route: 'standard-escrow',
        access: 'public',
        privateLiquidity: false,
        assets: [{ kind: 'erc20' }, null],
        relation: 'primary',
      }).assetPrivacy,
    ).toBeNull();

    expect(() =>
      deriveOrderClassificationV1({
        route: 'direct-escrow',
        access: 'public',
        privateLiquidity: false,
        assets: PUBLIC_ASSETS,
        relation: 'primary',
      }),
    ).toThrow(
      'Direct escrow orders must be unlisted or recipient-bound with non-hidden liquidity.',
    );

    expect(() =>
      deriveOrderClassificationV1({
        route: 'recurring-escrow',
        access: 'unlisted',
        privateLiquidity: false,
        assets: PUBLIC_ASSETS,
        relation: 'primary',
      }),
    ).toThrow(
      'Recurring orders support only public or fixed-recipient access.',
    );
  });
});
