import { describe, expect, it } from 'vitest';
import {
  encodeFunctionData,
  parseAbi,
  toFunctionSelector,
} from 'viem';

import {
  finalizeActionEnvelope,
  signActionEnvelope,
  type OrderClassificationV1,
  type SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  StrictMaterializedIntentValidator,
  type MaterializedActionStep,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as const;
const STANDARD_ESCROW =
  '0x2222222222222222222222222222222222222222' as const;
const DIRECT_ESCROW =
  '0x3333333333333333333333333333333333333333' as const;
const SELL_TOKEN =
  '0x4444444444444444444444444444444444444444' as const;
const BUY_TOKEN =
  '0x5555555555555555555555555555555555555555' as const;
const FEE_RECIPIENT =
  '0x6666666666666666666666666666666666666666' as const;
const HASH = `0x${'77'.repeat(32)}` as const;
const ZERO_BYTES32 = `0x${'00'.repeat(32)}` as const;
const PAIRING = 'classification-test-pairing-secret-is-long-enough';
const CREATE_SIGNATURE =
  'createTradeWithPolicy((uint8,address,uint256),(uint8,address,uint256),address,uint64,bool,bytes32,uint256,(bool,uint16,uint256,uint256,bool))';
const CREATE_ABI = parseAbi([`function ${CREATE_SIGNATURE}`]);
const CREATE_DATA = encodeFunctionData({
  abi: CREATE_ABI,
  functionName: 'createTradeWithPolicy',
  args: [
    [1, SELL_TOKEN, 1_250_000n],
    [1, BUY_TOKEN, 2_500_000n],
    '0x0000000000000000000000000000000000000000',
    1_785_240_000n,
    true,
    ZERO_BYTES32,
    0n,
    [false, 0, 0n, 0n, true],
  ],
});

const VALID_CLASSIFICATION: OrderClassificationV1 = {
  id: 'one-off.standard-public',
  cadence: 'one-off',
  route: 'standard-escrow',
  access: 'public',
  termsVisibility: 'public',
  assetPrivacy: 'public-only',
  relation: 'primary',
};

const createEnvelope = (
  orderType: OrderClassificationV1 | undefined,
): SignedActionEnvelopeV1 =>
  signActionEnvelope(
    finalizeActionEnvelope({
      operationId: 'classification-validation',
      wallet: WALLET,
      registrySnapshot: {
        registryAddress: STANDARD_ESCROW,
        registryBytecodeHash: HASH,
        manifestHash: HASH,
        observedBlock: '10',
        contracts: {
          standardEscrow: {
            address: STANDARD_ESCROW,
            bytecodeHash: HASH,
            selectors: {
              createTradeWithPolicy:
                toFunctionSelector(CREATE_SIGNATURE),
            },
          },
          directEscrow: {
            address: DIRECT_ESCROW,
            bytecodeHash: HASH,
            selectors: {},
          },
        },
        fees: { [STANDARD_ESCROW.toLowerCase()]: '7' },
      },
      issuedAt: '2026-07-28T12:00:00.000Z',
      expiresAt: '2026-07-28T12:15:00.000Z',
      intent: {
        action: 'create_trade',
        ...(orderType ? { orderType } : {}),
        accessMode: 'public',
        amountVisibility: 'visible',
        sellAsset: {
          kind: 'erc20',
          reference: SELL_TOKEN,
          address: SELL_TOKEN,
          symbol: 'SELL',
          decimals: 6,
        },
        buyAsset: {
          kind: 'erc20',
          reference: BUY_TOKEN,
          address: BUY_TOKEN,
          symbol: 'BUY',
          decimals: 6,
        },
        sellAmount: '1.25',
        buyAmount: '2.5',
        expiresAt: '2026-07-28T12:00:00.000Z',
        metadata: {
          partialFillsAllowed: false,
          minPartialFillBps: 0,
          minRequestAmount: null,
          maxRequestAmountPerWallet: null,
          oneFillPerWallet: true,
        },
      },
      steps: [
        {
          id: 'create',
          kind: 'protocol',
          to: STANDARD_ESCROW,
          data: CREATE_DATA,
          value: '7',
          gasCap: '6000000',
          summary: 'Create a public standard order.',
          callTemplate: {
            functionSignature: CREATE_SIGNATURE,
            arguments: [],
          },
        },
      ],
      exactNativeValue: '7',
      fee: {
        recipient: FEE_RECIPIENT,
        amount: '7',
        asset: 'native',
      },
      gasCap: '6000000',
      privateInputs: [],
      secretPolicy: {
        accessMode: 'public',
        generatedLocally: false,
        mayLeaveSigner: false,
        sharing: 'none',
      },
      simulation: {
        status: 'passed',
        checkedAt: '2026-07-28T12:00:00.000Z',
        blockNumber: '10',
      },
      summary: 'Create a public standard order.',
    }),
    PAIRING,
  );

const materializedProtocolStep = (
  envelope: SignedActionEnvelopeV1,
): MaterializedActionStep => ({
  ...envelope.steps[0]!,
  approval: null,
});

describe('signer order-classification validation', () => {
  it('accepts a classification independently supported by the executable action', async () => {
    const envelope = createEnvelope(VALID_CLASSIFICATION);
    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        materializedProtocolStep(envelope),
        0,
      ),
    ).resolves.toBeUndefined();
  });

  it('keeps pre-classification envelopes compatible', async () => {
    const envelope = createEnvelope(undefined);
    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        materializedProtocolStep(envelope),
        0,
      ),
    ).resolves.toBeUndefined();
  });

  it.each([
    [
      'route',
      {
        ...VALID_CLASSIFICATION,
        route: 'direct-escrow',
      } satisfies OrderClassificationV1,
    ],
    [
      'access',
      {
        ...VALID_CLASSIFICATION,
        access: 'direct',
      } satisfies OrderClassificationV1,
    ],
    [
      'asset privacy',
      {
        ...VALID_CLASSIFICATION,
        assetPrivacy: 'hybrid-private',
      } satisfies OrderClassificationV1,
    ],
    [
      'relation',
      {
        ...VALID_CLASSIFICATION,
        relation: 'counter',
      } satisfies OrderClassificationV1,
    ],
  ])('rejects a forged %s before action execution', async (_label, forged) => {
    const envelope = createEnvelope(forged);
    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        materializedProtocolStep(envelope),
        0,
      ),
    ).rejects.toMatchObject({ code: 'ENVELOPE_TAMPERED' });
  });

  it('checks classification before an approval step can be accepted', async () => {
    const envelope = createEnvelope({
      ...VALID_CLASSIFICATION,
      relation: 'replacement',
    });
    const approval = {
      id: 'approval',
      kind: 'approval',
      to: SELL_TOKEN,
      data: '0x',
      value: '0',
      gasCap: '100000',
      summary: 'Approval that must not be reached.',
      approval: null,
    } satisfies MaterializedActionStep;

    await expect(
      new StrictMaterializedIntentValidator().validate(
        envelope,
        approval,
        0,
      ),
    ).rejects.toMatchObject({ code: 'ENVELOPE_TAMPERED' });
  });
});
