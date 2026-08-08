import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  encodeAbiParameters,
  encodeEventTopics,
  parseAbi,
  parseAbiParameters,
} from 'viem';
import { describe, expect, it } from 'vitest';

import {
  deriveOrderClassificationV1,
  type OrderClassificationV1,
  type SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  decodeCreatedOrderReceipt,
  decodeCreatedOrderResult,
  OperationJournal,
  type Address,
  type HexString,
  type TransactionLog,
  type TransactionReceipt,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const OTHER =
  '0x2222222222222222222222222222222222222222' as Address;
const TAKER =
  '0x3333333333333333333333333333333333333333' as Address;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;
const CONTRACTS = {
  standardEscrow:
    '0x4444444444444444444444444444444444444444' as Address,
  privateEscrow:
    '0x5555555555555555555555555555555555555555' as Address,
  directEscrow:
    '0x6666666666666666666666666666666666666666' as Address,
  recurringEscrow:
    '0x7777777777777777777777777777777777777777' as Address,
};
const ZERO_HASH = `0x${'00'.repeat(32)}` as HexString;
const TRANSACTION_HASH = `0x${'88'.repeat(32)}` as HexString;

const EVENT_ABIS = {
  'standard-escrow': parseAbi([
    'event TradeOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, bool isPublic, bytes32 accessHash, uint256 parentTradeId, uint64 createdAt, uint64 expiresAt, uint256 feePaid)',
  ]),
  'private-liquidity-escrow': parseAbi([
    'event PrivateOrderOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, uint8 mode, bool isPublic, bool hasAccessHash, uint64 createdAt, uint64 expiresAt, bytes32 termsHash, uint256 feePaid)',
  ]),
  'direct-escrow': parseAbi([
    'event DirectTradeOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, bool hasAccessHash, uint256 parentTradeId, uint64 createdAt, uint64 expiresAt, bytes32 termsHash, uint256 feePaid)',
  ]),
  'recurring-escrow': parseAbi([
    'event RecurringOrderOpened(uint256 indexed orderId, address indexed maker, address indexed taker, uint8 mode, bool isPublic, bool hasAccessHash, uint64 createdAt, uint256 feePaid)',
  ]),
} as const;

const classification = (
  route: OrderClassificationV1['route'],
  relation: OrderClassificationV1['relation'] = 'primary',
  access: OrderClassificationV1['access'] =
    route === 'direct-escrow' ? 'direct' : 'public',
): OrderClassificationV1 =>
  deriveOrderClassificationV1({
    route,
    access,
    privateLiquidity: route === 'private-liquidity-escrow',
    assets: [{ kind: 'erc20' }, { kind: 'erc20' }],
    relation,
  });

const contractKey = (
  route: OrderClassificationV1['route'],
): keyof typeof CONTRACTS => {
  if (route === 'standard-escrow') return 'standardEscrow';
  if (route === 'private-liquidity-escrow') return 'privateEscrow';
  if (route === 'direct-escrow') return 'directEscrow';
  return 'recurringEscrow';
};

const envelopeFor = (
  route: OrderClassificationV1['route'],
): SignedActionEnvelopeV1 => {
  const contract = CONTRACTS[contractKey(route)];
  const recurring = route === 'recurring-escrow';
  return {
    version: 'cw.action/1',
    operationId: `create-${route}`,
    operationHash: ZERO_HASH,
    wallet: WALLET,
    chainId: 2_632_500,
    registrySnapshot: {
      registryAddress: OTHER,
      registryBytecodeHash: ZERO_HASH,
      manifestHash: ZERO_HASH,
      observedBlock: '1',
      contracts: Object.fromEntries(
        Object.entries(CONTRACTS).map(([name, address]) => [
          name,
          { address, bytecodeHash: ZERO_HASH, selectors: {} },
        ]),
      ),
      fees: {},
    },
    issuedAt: '2026-07-30T00:00:00.000Z',
    expiresAt: '2026-07-30T00:15:00.000Z',
    intent: {
      action: recurring ? 'create_recurring' : 'create_trade',
      orderType: classification(route),
      ...(route === 'direct-escrow' ? { recipient: TAKER } : {}),
    },
    steps: [
      {
        id: 'create',
        kind: 'protocol',
        to: contract,
        data: '0x12345678',
        value: '0',
        gasCap: '1',
        summary: 'Create order.',
      },
    ],
    exactNativeValue: '0',
    fee: { recipient: OTHER, amount: '0', asset: 'native' },
    gasCap: '1',
    privateInputs: [],
    secretPolicy: {
      accessMode: recurring || route === 'standard-escrow' ? 'public' : 'direct',
      generatedLocally: false,
      mayLeaveSigner: false,
      sharing: 'none',
    },
    simulation: {
      status: 'passed',
      checkedAt: '2026-07-30T00:00:00.000Z',
    },
    summary: 'Create order.',
    pairingSignature: { algorithm: 'hmac-sha256', digest: ZERO_HASH },
  };
};

const openedLog = (
  route: OrderClassificationV1['route'],
  orderId: bigint,
  maker: Address = WALLET,
  address = CONTRACTS[contractKey(route)],
  taker: Address = route === 'direct-escrow' ? TAKER : ZERO_ADDRESS,
): TransactionLog => {
  if (route === 'standard-escrow') {
    return {
      address,
      topics: encodeEventTopics({
        abi: EVENT_ABIS[route],
        eventName: 'TradeOpened',
        args: { tradeId: orderId, maker, taker },
      }),
      data: encodeAbiParameters(
        parseAbiParameters(
          'bool, bytes32, uint256, uint64, uint64, uint256',
        ),
        [true, ZERO_HASH, 0n, 1n, 2n, 3n],
      ),
    };
  }
  if (route === 'private-liquidity-escrow') {
    return {
      address,
      topics: encodeEventTopics({
        abi: EVENT_ABIS[route],
        eventName: 'PrivateOrderOpened',
        args: { tradeId: orderId, maker, taker },
      }),
      data: encodeAbiParameters(
        parseAbiParameters(
          'uint8, bool, bool, uint64, uint64, bytes32, uint256',
        ),
        [1, true, false, 1n, 2n, ZERO_HASH, 3n],
      ),
    };
  }
  if (route === 'direct-escrow') {
    return {
      address,
      topics: encodeEventTopics({
        abi: EVENT_ABIS[route],
        eventName: 'DirectTradeOpened',
        args: { tradeId: orderId, maker, taker },
      }),
      data: encodeAbiParameters(
        parseAbiParameters(
          'bool, uint256, uint64, uint64, bytes32, uint256',
        ),
        [true, 0n, 1n, 2n, ZERO_HASH, 3n],
      ),
    };
  }
  return {
    address,
    topics: encodeEventTopics({
      abi: EVENT_ABIS[route],
      eventName: 'RecurringOrderOpened',
      args: { orderId, maker, taker },
    }),
    data: encodeAbiParameters(
      parseAbiParameters('uint8, bool, bool, uint64, uint256'),
      [0, true, false, 1n, 3n],
    ),
  };
};

const receipt = (...logs: TransactionLog[]): TransactionReceipt => ({
  transactionHash: TRANSACTION_HASH,
  status: 'success',
  blockNumber: 12,
  logs,
});

describe('created order semantic results', () => {
  it.each([
    [
      'standard-escrow',
      'https://chainwhisper.chat/otc/order/link/VgAq',
    ],
    [
      'private-liquidity-escrow',
      'https://chainwhisper.chat/otc/order/link/VgAq?escrow=private',
    ],
    [
      'direct-escrow',
      'https://chainwhisper.chat/otc/order/link/VgAq?escrow=direct',
    ],
    [
      'recurring-escrow',
      'https://chainwhisper.chat/otc/order/recurring/42',
    ],
  ] as const)(
    'decodes the exact deployed %s create event',
    (route, appLink) => {
      const envelope = envelopeFor(route);
      expect(
        decodeCreatedOrderReceipt(
          envelope,
          receipt(openedLog(route, 42n)),
        ),
      ).toMatchObject({
        orderBinding: {
          escrowContract: CONTRACTS[contractKey(route)],
          localId: '42',
        },
      });
      expect(
        decodeCreatedOrderResult(
          envelope,
          receipt(openedLog(route, 42n)),
        ),
      ).toEqual({
        action:
          route === 'recurring-escrow'
            ? 'create_recurring'
            : 'create_trade',
        status: 'completed',
        canonicalType: envelope.intent.orderType,
        order: {
          handle: `cw_${CONTRACTS[contractKey(route)]
            .slice(2)
            .toLowerCase()}_42`,
          status: 'open',
          shareableAppLink: appLink,
        },
      });
    },
  );

  it('rejects wrong-target, wrong-maker, ambiguous, and reverted logs', () => {
    const route = 'standard-escrow';
    const envelope = envelopeFor(route);
    expect(
      decodeCreatedOrderResult(
        envelope,
        receipt(openedLog(route, 7n, WALLET, OTHER)),
      ),
    ).toBeNull();
    expect(
      decodeCreatedOrderResult(
        envelope,
        receipt(openedLog(route, 7n, OTHER)),
      ),
    ).toBeNull();
    expect(
      decodeCreatedOrderResult(
        envelope,
        receipt(
          openedLog(
            route,
            7n,
            WALLET,
            CONTRACTS.standardEscrow,
            OTHER,
          ),
        ),
      ),
    ).toBeNull();
    expect(
      decodeCreatedOrderResult(
        envelope,
        receipt(openedLog(route, 7n), openedLog(route, 8n)),
      ),
    ).toBeNull();
    expect(
      decodeCreatedOrderResult(envelope, {
        ...receipt(openedLog(route, 7n)),
        status: 'reverted',
      }),
    ).toBeNull();

    const directEnvelope = envelopeFor('direct-escrow');
    expect(
      decodeCreatedOrderResult(
        directEnvelope,
        receipt(
          openedLog(
            'direct-escrow',
            7n,
            WALLET,
            CONTRACTS.directEscrow,
            OTHER,
          ),
        ),
      ),
    ).toBeNull();
  });

  it('preserves the private-liquidity recurring classification', () => {
    const envelope = envelopeFor('recurring-escrow');
    envelope.intent.orderType = deriveOrderClassificationV1({
      route: 'recurring-escrow',
      access: 'public',
      privateLiquidity: true,
      assets: [
        { kind: 'private-erc20' },
        { kind: 'private-erc20' },
      ],
      relation: 'primary',
    });
    expect(
      decodeCreatedOrderResult(
        envelope,
        receipt(openedLog('recurring-escrow', 10n)),
      ),
    ).toMatchObject({
      canonicalType: {
        id: 'recurring.private-liquidity.public',
        route: 'recurring-escrow',
      },
      order: {
        handle: `cw_${CONTRACTS.recurringEscrow
          .slice(2)
          .toLowerCase()}_10`,
        shareableAppLink:
          'https://chainwhisper.chat/otc/order/recurring/10',
      },
    });
  });

  it.each([
    ['counter', 'direct-escrow', 'counter', 'direct'],
    ['edit', 'direct-escrow', 'replacement', 'direct'],
    [
      'edit',
      'private-liquidity-escrow',
      'replacement',
      'unlisted',
    ],
  ] as const)(
    'decodes the receipt-created identity for a generated-secret %s flow',
    (action, route, relation, access) => {
      const envelope = envelopeFor(route);
      envelope.intent.action = action;
      envelope.intent.orderType = classification(
        route,
        relation,
        access,
      );
      envelope.intent.accessMode = access;
      const decoded = decodeCreatedOrderReceipt(
        envelope,
        receipt(openedLog(route, 57n)),
      );

      expect(decoded).toMatchObject({
        result: {
          action,
          canonicalType: { relation, route, access },
          order: {
            handle: `cw_${CONTRACTS[contractKey(route)]
              .slice(2)
              .toLowerCase()}_57`,
          },
        },
        orderBinding: {
          escrowContract: CONTRACTS[contractKey(route)],
          localId: '57',
        },
      });
      expect(
        decodeCreatedOrderResult(
          envelope,
          receipt(openedLog(route, 57n)),
        ),
      ).toEqual(decoded?.result);
    },
  );

  it('persists the decoded identity atomically with its receipt', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-order-result-'),
    );
    const journal = new OperationJournal(stateDirectory);
    const envelope = envelopeFor('recurring-escrow');
    const semantic = decodeCreatedOrderResult(
      envelope,
      receipt(openedLog('recurring-escrow', 19n)),
    );
    expect(semantic).not.toBeNull();
    await journal.begin(envelope.operationId, envelope.operationHash);
    await journal.recordReceipt(
      envelope.operationId,
      receipt(openedLog('recurring-escrow', 19n)),
      semantic ?? undefined,
    );

    const recovered = await new OperationJournal(stateDirectory).get(
      envelope.operationId,
    );
    expect(recovered).toMatchObject({
      receipts: [{ transactionHash: TRANSACTION_HASH, status: 'success' }],
      semanticResult: {
        action: 'create_recurring',
        order: {
          handle: `cw_${CONTRACTS.recurringEscrow
            .slice(2)
            .toLowerCase()}_19`,
          status: 'open',
          shareableAppLink:
            'https://chainwhisper.chat/otc/order/recurring/19',
        },
      },
    });
    expect(recovered?.receipts[0]).not.toHaveProperty('logs');
  });
});
