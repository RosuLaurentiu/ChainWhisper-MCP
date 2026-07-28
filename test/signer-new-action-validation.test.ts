import { describe, expect, it } from 'vitest';
import {
  encodeFunctionData,
  keccak256,
  parseAbi,
  toFunctionSelector,
  type Abi,
  type Hex,
} from 'viem';

import type {
  ActionStepV1,
  NormalizedAssetV1,
  NormalizedIntentV1,
  OrderClassificationV1,
  SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  StrictMaterializedIntentValidator,
  type MaterializedActionStep,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as const;
const STANDARD =
  '0x2222222222222222222222222222222222222222' as const;
const PRIVATE =
  '0x3333333333333333333333333333333333333333' as const;
const DIRECT =
  '0x4444444444444444444444444444444444444444' as const;
const RECURRING =
  '0x5555555555555555555555555555555555555555' as const;
const WISP_BRIDGE =
  '0x3bCeA2eD4b31107eF877899416dC97213bdc2809' as const;
const TOKEN_A =
  '0x6666666666666666666666666666666666666666' as const;
const TOKEN_B =
  '0x7777777777777777777777777777777777777777' as const;
const RECIPIENT =
  '0x8888888888888888888888888888888888888888' as const;
const FEE_RECIPIENT =
  '0x9999999999999999999999999999999999999999' as const;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as const;
const ZERO_BYTES32 = `0x${'00'.repeat(32)}` as const;
const ACCESS_SECRET = `0x${'ab'.repeat(32)}` as Hex;
const TERMS = '0x123456' as Hex;
const SIGNATURE = `0x${'cd'.repeat(65)}` as Hex;
const ENCRYPTED = [[11n, 12n], SIGNATURE] as const;
const EMPTY_ENCRYPTED = [[0n, 0n], '0x'] as const;
const EXPIRY = '2026-07-29T12:00:00.000Z';
const EXPIRY_SECONDS = BigInt(Date.parse(EXPIRY) / 1_000);
const HASH = `0x${'ee'.repeat(32)}` as const;

const ERC_A: NormalizedAssetV1 = {
  kind: 'erc20',
  reference: TOKEN_A,
  address: TOKEN_A,
  symbol: 'A',
  decimals: 6,
};
const ERC_B: NormalizedAssetV1 = {
  kind: 'erc20',
  reference: TOKEN_B,
  address: TOKEN_B,
  symbol: 'B',
  decimals: 6,
};
const PRIVATE_A: NormalizedAssetV1 = {
  ...ERC_A,
  kind: 'private-erc20',
  symbol: 'p.A',
};
const PRIVATE_B: NormalizedAssetV1 = {
  ...ERC_B,
  kind: 'private-erc20',
  symbol: 'p.B',
};
const NATIVE: NormalizedAssetV1 = {
  kind: 'native',
  reference: 'native:coti',
  symbol: 'COTI',
  decimals: 18,
};

const SIGNATURES = {
  counterPrimary:
    'createDirectCounterTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  counterAndClose:
    'counterTradeAndCloseCounteredTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  counterCross:
    'createDirectCounterTradeForParent(address,uint256,address,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  editStandard:
    'editTradeWithPolicy(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,(bool,uint16,uint256,uint256,bool))',
  editPrivate:
    'cancelAndReplacePrivateOrderWithRecoveryNote(uint256,(uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,bytes32,((uint256,uint256),bytes),((uint256,uint256),bytes),((uint256,uint256),bytes),bytes,((uint256,uint256),bytes),bytes)',
  editDirect:
    'editDirectTrade(uint256,(uint8,address),(uint8,address),(uint256,uint256),((uint256,uint256),bytes),((uint256,uint256),bytes),address,uint64,bytes32,bytes32,((uint256,uint256),bytes),bytes)',
  editRecurring:
    'editOrder(uint256,(uint256,uint256),(uint256,uint256),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes),uint256,uint256,((uint256,uint256),bytes),((uint256,uint256),bytes))',
  settle: 'settleInventory(uint256)',
  bridgeDeposit: 'deposit(uint256,uint256,uint256)',
} as const;

const encode = (
  signature: string,
  args: readonly unknown[],
): Hex => {
  const abi = parseAbi([`function ${signature}`] as never) as Abi;
  return encodeFunctionData({
    abi,
    functionName: signature.slice(0, signature.indexOf('(')),
    args,
  });
};

const classification = (
  input: Partial<OrderClassificationV1> &
    Pick<
      OrderClassificationV1,
      'id' | 'route' | 'access' | 'termsVisibility'
    >,
): OrderClassificationV1 => ({
  cadence:
    input.route === 'recurring-escrow' ? 'recurring' : 'one-off',
  assetPrivacy: 'public-only',
  relation: 'primary',
  ...input,
});

const makeEnvelope = (options: {
  target:
    | typeof STANDARD
    | typeof PRIVATE
    | typeof DIRECT
    | typeof RECURRING
    | typeof WISP_BRIDGE;
  signature: string;
  args: readonly unknown[];
  intent: NormalizedIntentV1;
  value?: string;
  fee?: string;
}): SignedActionEnvelopeV1 => {
  const data = encode(options.signature, options.args);
  const step: ActionStepV1 = {
    id: 'protocol',
    kind: 'protocol',
    to: options.target,
    data,
    value: options.value ?? options.fee ?? '0',
    gasCap: '6000000',
    summary: 'Test protocol action.',
    callTemplate: {
      functionSignature: options.signature,
      arguments: options.args as never,
    },
  };
  const contract = {
    address: options.target,
    bytecodeHash: HASH,
    selectors: { action: toFunctionSelector(options.signature) },
  };
  return {
    version: 'cw.action/1',
    operationId: 'new-action-validation',
    operationHash: HASH,
    wallet: WALLET,
    chainId: 2_632_500,
    registrySnapshot: {
      registryAddress: STANDARD,
      registryBytecodeHash: HASH,
      manifestHash: HASH,
      observedBlock: '10',
      contracts: {
        standardEscrow:
          options.target === STANDARD
            ? contract
            : { ...contract, address: STANDARD, selectors: {} },
        privateEscrow:
          options.target === PRIVATE
            ? contract
            : { ...contract, address: PRIVATE, selectors: {} },
        directEscrow:
          options.target === DIRECT
            ? contract
            : { ...contract, address: DIRECT, selectors: {} },
        recurringEscrow:
          options.target === RECURRING
            ? contract
            : { ...contract, address: RECURRING, selectors: {} },
        privacyBridgeWisp:
          options.target === WISP_BRIDGE
            ? contract
            : { ...contract, address: WISP_BRIDGE, selectors: {} },
      },
      fees: { [options.target.toLowerCase()]: options.fee ?? '0' },
    },
    issuedAt: '2026-07-28T12:00:00.000Z',
    expiresAt: '2026-07-28T12:15:00.000Z',
    intent: options.intent,
    steps: [step],
    exactNativeValue: options.value ?? options.fee ?? '0',
    fee: {
      recipient: FEE_RECIPIENT,
      amount: options.fee ?? '0',
      asset: 'native',
    },
    gasCap: '6000000',
    privateInputs: [],
    secretPolicy: {
      accessMode: options.intent.accessMode ?? 'public',
      generatedLocally: Boolean(
        options.intent.accessMode &&
          options.intent.accessMode !== 'public',
      ),
      mayLeaveSigner: false,
      sharing:
        options.intent.accessMode &&
        options.intent.accessMode !== 'public'
          ? 'coti-private-message-only'
          : 'none',
    },
    simulation: {
      status: 'passed',
      checkedAt: '2026-07-28T12:00:00.000Z',
      blockNumber: '10',
    },
    summary: 'Test action.',
    pairingSignature: {
      algorithm: 'hmac-sha256',
      digest: HASH,
    },
  };
};

const materialized = (
  envelope: SignedActionEnvelopeV1,
  privateValues: Record<string, string> = {},
): MaterializedActionStep => ({
  ...envelope.steps[0]!,
  approval: undefined,
  privateValues,
});

const validate = (
  envelope: SignedActionEnvelopeV1,
  privateValues: Record<string, string> = {},
): Promise<void> =>
  new StrictMaterializedIntentValidator().validate(
    envelope,
    materialized(envelope, privateValues),
    0,
  );

describe('strict validation for newly executable actions', () => {
  it('accepts an exactly bound WISP shield and rejects a changed portal fee', async () => {
    const wisp: NormalizedAssetV1 = {
      kind: 'erc20',
      reference: '0xb70c55bd0823436f44877dc6a9f46e0c55f2c3a8',
      address: '0xb70c55bd0823436F44877DC6A9f46E0C55f2C3A8',
      symbol: 'WISP',
      decimals: 6,
    };
    const privateWisp: NormalizedAssetV1 = {
      kind: 'private-erc20',
      reference: '0x682e3142e62a7ade2a0ca5bdc87b205cade4b17a',
      address: '0x682e3142e62a7aDe2a0CA5bdC87b205CaDe4B17a',
      symbol: 'p.WISP',
      decimals: 6,
    };
    const intent: NormalizedIntentV1 = {
      action: 'privacy_bridge',
      accessMode: 'public',
      amountVisibility: 'visible',
      sellAsset: wisp,
      buyAsset: privateWisp,
      sellAmount: '1',
      buyAmount: '1',
      metadata: {
        bridgePair: 'wisp',
        bridgeProvider: 'chainwhisper',
        bridgeContractName: 'privacyBridgeWisp',
        bridgeKind: 'erc20',
        bridgeDirection: 'public-to-private',
        amountAtomic: '1000000',
        portalFeeAtomic: '9',
        cotiOracleTimestamp: '100',
        tokenOracleTimestamp: '101',
        blockTimestamp: '102',
      },
    };
    const envelope = makeEnvelope({
      target: WISP_BRIDGE,
      signature: SIGNATURES.bridgeDeposit,
      args: [1_000_000n, 100n, 101n],
      intent,
      value: '9',
    });
    await expect(validate(envelope)).resolves.toBeUndefined();

    const tampered = structuredClone(envelope);
    tampered.intent.metadata!.portalFeeAtomic = '10';
    await expect(validate(tampered)).rejects.toMatchObject({
      code: 'ENVELOPE_TAMPERED',
    });
  });

  it.each([
    [
      'primary Direct parent',
      SIGNATURES.counterPrimary,
      false,
      'direct-primary',
      'primary',
    ],
    [
      'Direct counter-of-counter',
      SIGNATURES.counterAndClose,
      false,
      'direct-counter',
      'counter',
    ],
    [
      'cross-escrow parent',
      SIGNATURES.counterCross,
      true,
      'cross-escrow',
      'primary',
    ],
  ] as const)('accepts an exact Direct counter on the %s route', async (
    _label,
    signature,
    cross,
    counterRoute,
    sourceOrderRelation,
  ) => {
    const args = cross
      ? [
          STANDARD,
          5n,
          RECIPIENT,
          [1, TOKEN_A],
          [2, TOKEN_B],
          [1_000_000n, 0n],
          EMPTY_ENCRYPTED,
          ENCRYPTED,
          EXPIRY_SECONDS,
          keccak256(ACCESS_SECRET),
          keccak256(TERMS),
          ENCRYPTED,
          TERMS,
        ]
      : [
          5n,
          [1, TOKEN_A],
          [2, TOKEN_B],
          [1_000_000n, 0n],
          EMPTY_ENCRYPTED,
          ENCRYPTED,
          EXPIRY_SECONDS,
          keccak256(ACCESS_SECRET),
          keccak256(TERMS),
          ENCRYPTED,
          TERMS,
        ];
    const source = cross ? STANDARD : DIRECT;
    const envelope = makeEnvelope({
      target: DIRECT,
      signature,
      args,
      fee: '7',
      intent: {
        action: 'counter',
        orderType: classification({
          id: 'one-off.direct',
          route: 'direct-escrow',
          access: 'direct',
          termsVisibility: 'direct-private-terms',
          assetPrivacy: 'hybrid-private',
          relation: 'counter',
        }),
        accessMode: 'direct',
        amountVisibility: 'visible',
        order: { escrowContract: source, localId: '5' },
        sellAsset: ERC_A,
        buyAsset: PRIVATE_B,
        sellAmount: '1',
        recipient: RECIPIENT,
        expiresAt: EXPIRY,
        metadata: {
          counteredEscrowContract: source,
          counteredTradeId: '5',
          parentEscrowContract:
            counterRoute === 'direct-primary' ? DIRECT : STANDARD,
          parentTradeId: '5',
          counterRoute,
          sourceOrderRelation,
          sourceMaker: RECIPIENT,
          sourceRecipient: cross ? null : WALLET,
        },
      },
    });
    await expect(
      validate(envelope, {
        'order-access-secret': ACCESS_SECRET,
        'request-amount': '2000000',
      }),
    ).resolves.toBeUndefined();
  });

  it('rejects swapping the Direct primary selector to the counter-of-counter route', async () => {
    const envelope = makeEnvelope({
      target: DIRECT,
      signature: SIGNATURES.counterAndClose,
      args: [
        5n,
        [1, TOKEN_A],
        [2, TOKEN_B],
        [1_000_000n, 0n],
        EMPTY_ENCRYPTED,
        ENCRYPTED,
        EXPIRY_SECONDS,
        keccak256(ACCESS_SECRET),
        keccak256(TERMS),
        ENCRYPTED,
        TERMS,
      ],
      fee: '7',
      intent: {
        action: 'counter',
        orderType: classification({
          id: 'one-off.direct',
          route: 'direct-escrow',
          access: 'direct',
          termsVisibility: 'direct-private-terms',
          assetPrivacy: 'hybrid-private',
          relation: 'counter',
        }),
        accessMode: 'direct',
        amountVisibility: 'visible',
        order: { escrowContract: DIRECT, localId: '5' },
        sellAsset: ERC_A,
        buyAsset: PRIVATE_B,
        sellAmount: '1',
        recipient: RECIPIENT,
        expiresAt: EXPIRY,
        metadata: {
          counteredEscrowContract: DIRECT,
          counteredTradeId: '5',
          parentEscrowContract: DIRECT,
          parentTradeId: '5',
          counterRoute: 'direct-primary',
          sourceOrderRelation: 'primary',
          sourceMaker: RECIPIENT,
          sourceRecipient: WALLET,
        },
      },
    });
    await expect(
      validate(envelope, {
        'order-access-secret': ACCESS_SECRET,
        'request-amount': '2000000',
      }),
    ).rejects.toMatchObject({ code: 'ENVELOPE_TAMPERED' });
  });

  it('validates the complete Standard replacement policy', async () => {
    const envelope = makeEnvelope({
      target: STANDARD,
      signature: SIGNATURES.editStandard,
      args: [
        5n,
        [1, TOKEN_A, 1_000_000n],
        [1, TOKEN_B, 2_000_000n],
        ZERO_ADDRESS,
        EXPIRY_SECONDS,
        true,
        ZERO_BYTES32,
        [true, 2500, 100_000n, 500_000n, false],
      ],
      intent: {
        action: 'edit',
        orderType: classification({
          id: 'one-off.standard-public',
          route: 'standard-escrow',
          access: 'public',
          termsVisibility: 'public',
          relation: 'replacement',
        }),
        accessMode: 'public',
        amountVisibility: 'visible',
        order: { escrowContract: STANDARD, localId: '5' },
        sellAsset: ERC_A,
        buyAsset: ERC_B,
        sellAmount: '1',
        buyAmount: '2',
        expiresAt: EXPIRY,
        metadata: {
          orderRelation: 'replacement',
          resultingPartialFillsAllowed: true,
          resultingMinPartialFillBps: 2500,
          resultingMinRequestAmount: '0.1',
          resultingMaxRequestAmountPerWallet: '0.5',
          resultingOneFillPerWallet: false,
        },
      },
    });
    await expect(validate(envelope)).resolves.toBeUndefined();

    const changed = makeEnvelope({
      target: STANDARD,
      signature: SIGNATURES.editStandard,
      args: [
        5n,
        [1, TOKEN_A, 1_000_000n],
        [1, TOKEN_B, 2_000_000n],
        ZERO_ADDRESS,
        EXPIRY_SECONDS,
        true,
        ZERO_BYTES32,
        [true, 2501, 100_000n, 500_000n, false],
      ],
      intent: envelope.intent,
    });
    await expect(validate(changed)).rejects.toMatchObject({
      code: 'ENVELOPE_TAMPERED',
    });
  });

  it('accepts an exact unlisted private-liquidity replacement', async () => {
    const envelope = makeEnvelope({
      target: PRIVATE,
      signature: SIGNATURES.editPrivate,
      args: [
        5n,
        [2, TOKEN_A, 0n],
        [1, TOKEN_B, 0n],
        ZERO_ADDRESS,
        EXPIRY_SECONDS,
        false,
        keccak256(ACCESS_SECRET),
        keccak256(TERMS),
        ENCRYPTED,
        ENCRYPTED,
        ENCRYPTED,
        '0xabcd',
        ENCRYPTED,
        TERMS,
      ],
      fee: '7',
      intent: {
        action: 'edit',
        orderType: classification({
          id: 'one-off.private-liquidity.unlisted',
          route: 'private-liquidity-escrow',
          access: 'unlisted',
          termsVisibility: 'hidden-liquidity',
          assetPrivacy: 'hybrid-private',
          relation: 'replacement',
        }),
        accessMode: 'unlisted',
        amountVisibility: 'private-hidden',
        order: { escrowContract: PRIVATE, localId: '5' },
        sellAsset: PRIVATE_A,
        buyAsset: ERC_B,
        expiresAt: EXPIRY,
        metadata: { orderRelation: 'replacement' },
      },
    });
    await expect(
      validate(envelope, {
        'order-access-secret': ACCESS_SECRET,
        'hidden-offer-amount': '1000000',
        'hidden-request-amount': '2000000',
      }),
    ).resolves.toBeUndefined();
  });

  it('binds a Direct replacement hash and native principal', async () => {
    const value = (10n ** 18n + 7n).toString();
    const envelope = makeEnvelope({
      target: DIRECT,
      signature: SIGNATURES.editDirect,
      args: [
        5n,
        [0, ZERO_ADDRESS],
        [2, TOKEN_B],
        [10n ** 18n, 0n],
        EMPTY_ENCRYPTED,
        ENCRYPTED,
        RECIPIENT,
        EXPIRY_SECONDS,
        keccak256(ACCESS_SECRET),
        keccak256(TERMS),
        ENCRYPTED,
        TERMS,
      ],
      fee: '7',
      value,
      intent: {
        action: 'edit',
        orderType: classification({
          id: 'one-off.direct',
          route: 'direct-escrow',
          access: 'direct',
          termsVisibility: 'direct-private-terms',
          assetPrivacy: 'hybrid-private',
          relation: 'replacement',
        }),
        accessMode: 'direct',
        amountVisibility: 'visible',
        order: { escrowContract: DIRECT, localId: '5' },
        sellAsset: NATIVE,
        buyAsset: PRIVATE_B,
        sellAmount: '1',
        recipient: RECIPIENT,
        expiresAt: EXPIRY,
        metadata: { orderRelation: 'replacement' },
      },
    });
    await expect(
      validate(envelope, {
        'order-access-secret': ACCESS_SECRET,
        'request-amount': '2000000',
      }),
    ).resolves.toBeUndefined();

    const tamperedStep = {
      ...materialized(envelope, {
        'order-access-secret': ACCESS_SECRET,
        'request-amount': '2000000',
      }),
      value: (10n ** 18n + 8n).toString(),
    };
    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        tamperedStep,
        0,
      ),
    ).rejects.toMatchObject({ code: 'ENVELOPE_TAMPERED' });
  });

  it('validates recurring public and private inventory deltas', async () => {
    const envelope = makeEnvelope({
      target: RECURRING,
      signature: SIGNATURES.editRecurring,
      args: [
        5n,
        [1_000_000n, 2_000_000n],
        [1_000_000n, 3_000_000n],
        0n,
        4_000_000n,
        ENCRYPTED,
        EMPTY_ENCRYPTED,
        0n,
        0n,
        ENCRYPTED,
        EMPTY_ENCRYPTED,
      ],
      intent: {
        action: 'edit',
        orderType: classification({
          id: 'recurring.private-liquidity.public',
          route: 'recurring-escrow',
          access: 'public',
          termsVisibility: 'hidden-liquidity',
          assetPrivacy: 'hybrid-private',
        }),
        accessMode: 'public',
        amountVisibility: 'private-hidden',
        order: { escrowContract: RECURRING, localId: '5' },
        sellAsset: PRIVATE_A,
        buyAsset: ERC_B,
        metadata: {
          orderRelation: 'primary',
          trustedBuyBaseAmount: '1',
          trustedBuyQuoteAmount: '2',
          trustedSellBaseAmount: '1',
          trustedSellQuoteAmount: '3',
          trustedBuyPrice: '2',
          trustedSellPrice: '3',
          addBuyQuoteLiquidity: '4',
          adjustPrivateLiquidity: true,
          privateBaseInventory: true,
          privateQuoteInventory: false,
        },
      },
    });
    await expect(
      validate(envelope, {
        'recurring-edit-add-base': '3000000',
        'recurring-edit-remove-base': '0',
      }),
    ).resolves.toBeUndefined();
  });

  it('allows inventory settlement only for a cancelled recurring order', async () => {
    const envelope = makeEnvelope({
      target: RECURRING,
      signature: SIGNATURES.settle,
      args: [5n],
      intent: {
        action: 'order_update',
        orderType: classification({
          id: 'recurring.public',
          route: 'recurring-escrow',
          access: 'public',
          termsVisibility: 'public',
        }),
        accessMode: 'public',
        amountVisibility: 'visible',
        order: { escrowContract: RECURRING, localId: '5' },
        sellAsset: ERC_A,
        buyAsset: ERC_B,
        metadata: {
          update: 'settle_inventory',
          orderStatus: 'cancelled',
          orderRelation: 'primary',
          sourceOrderRelation: 'primary',
          sourceMaker: WALLET,
          sourceRecipient: null,
          sourceOrderType: 'recurring.public',
        },
      },
    });
    await expect(validate(envelope)).resolves.toBeUndefined();

    const invalidStatus = {
      ...envelope,
      intent: {
        ...envelope.intent,
        metadata: {
          ...envelope.intent.metadata,
          orderStatus: 'open',
        },
      },
    } satisfies SignedActionEnvelopeV1;
    await expect(validate(invalidStatus)).rejects.toMatchObject({
      code: 'ENVELOPE_TAMPERED',
    });

    const invalidMaker = {
      ...envelope,
      intent: {
        ...envelope.intent,
        metadata: {
          ...envelope.intent.metadata,
          sourceMaker: RECIPIENT,
        },
      },
    } satisfies SignedActionEnvelopeV1;
    await expect(validate(invalidMaker)).rejects.toMatchObject({
      code: 'ENVELOPE_TAMPERED',
    });
  });

  it('accepts an exact counter token approval before the protocol step', async () => {
    const envelope = makeEnvelope({
      target: DIRECT,
      signature: SIGNATURES.counterAndClose,
      args: [
        5n,
        [1, TOKEN_A],
        [2, TOKEN_B],
        [1_000_000n, 0n],
        EMPTY_ENCRYPTED,
        ENCRYPTED,
        EXPIRY_SECONDS,
        keccak256(ACCESS_SECRET),
        keccak256(TERMS),
        ENCRYPTED,
        TERMS,
      ],
      fee: '7',
      intent: {
        action: 'counter',
        orderType: classification({
          id: 'one-off.direct',
          route: 'direct-escrow',
          access: 'direct',
          termsVisibility: 'direct-private-terms',
          assetPrivacy: 'hybrid-private',
          relation: 'counter',
        }),
        accessMode: 'direct',
        amountVisibility: 'visible',
        order: { escrowContract: DIRECT, localId: '5' },
        sellAsset: ERC_A,
        buyAsset: PRIVATE_B,
        sellAmount: '1',
        recipient: RECIPIENT,
        expiresAt: EXPIRY,
        metadata: {
          counteredEscrowContract: DIRECT,
          counteredTradeId: '5',
          parentEscrowContract: STANDARD,
          parentTradeId: '5',
          counterRoute: 'direct-counter',
          sourceOrderRelation: 'counter',
          sourceMaker: RECIPIENT,
          sourceRecipient: WALLET,
        },
      },
    });
    const approval: ActionStepV1 = {
      id: 'approval',
      kind: 'approval',
      to: TOKEN_A,
      data: '0x',
      value: '0',
      gasCap: '100000',
      summary: 'Approve exact counter offer.',
      allowance: {
        token: TOKEN_A,
        spender: DIRECT,
        amount: '1000000',
        scheme: 'erc20-exact',
      },
    };
    envelope.steps.unshift(approval);
    const materializedApproval: MaterializedActionStep = {
      ...approval,
      approval: {
        token: TOKEN_A,
        spender: DIRECT,
        amount: '1000000',
        scheme: 'erc20-exact',
      },
      privateValues: {
        'order-access-secret': ACCESS_SECRET,
        'request-amount': '2000000',
      },
    };
    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        materializedApproval,
        0,
      ),
    ).resolves.toBeUndefined();
  });
});
