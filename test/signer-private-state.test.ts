import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionResult,
  parseAbi,
  parseAbiParameters,
  toFunctionSelector,
  type Hex,
} from 'viem';
import { describe, expect, it, vi } from 'vitest';

import {
  hashRuntimeManifest,
  loadRuntimeManifest,
  type JsonRpcReader,
} from '../src/shared/index.js';
import {
  ConfirmationGate,
  PrivateStateDisclosureService,
  type ActiveAutonomyPolicyV1,
  type Address,
  type AutonomyPolicyManager,
  type ConfirmationRequest,
  type FormElicitor,
  type HexString,
  type WalletTransport,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const OTHER =
  '0x2222222222222222222222222222222222222222' as Address;
const BLOCKED =
  '0x3333333333333333333333333333333333333333' as Address;
const ZERO =
  '0x0000000000000000000000000000000000000000' as Address;
const AES_KEY = '11'.repeat(16);
const ZERO_HASH = `0x${'00'.repeat(32)}` as HexString;
const TRANSACTION_HASH = `0x${'55'.repeat(32)}` as HexString;

const CT = '(uint256 ciphertextHigh,uint256 ciphertextLow)';
const UT = `(${CT} ciphertext,${CT} userCiphertext)`;

const TOKEN_ABI = parseAbi([
  'function balanceOf(address account) view returns ((uint256 ciphertextHigh,uint256 ciphertextLow))',
]);
const PRIVATE_ABI = parseAbi([
  'function getTrade(uint256 tradeId) view returns (address maker,address taker,uint8 status,(uint8 assetType,address token,uint256 amount) offerAsset,(uint8 assetType,address token,uint256 amount) requestAsset,uint64 createdAt,uint64 expiresAt)',
  'function getTradeMetadata(uint256 tradeId) view returns (bool isPublic,bytes32 accessHash,uint256 feePaid,bytes32 termsHash,uint8 mode,bool hasMakerRecoveryNote)',
  `function getPrivateOrderAccountSummary(uint256 tradeId,address account) view returns ((uint256 sequence,bool initialized,${UT} remainingOfferAmount,uint256 fillReceiptTotal) summary)`,
  `event PrivateOrderFillReceipt(uint256 indexed tradeId,address indexed recipient,address indexed filler,uint256 fillIndex,${UT} offerAmount,${UT} requestAmount,${UT} remainingOfferAmount)`,
]);
const RECURRING_ABI = parseAbi([
  'function getOrderView(uint256 orderId) view returns (((address maker,address taker,uint8 status,uint8 mode,(uint8 assetType,address token) baseAsset,(uint8 assetType,address token) quoteAsset,(uint256 baseAmount,uint256 quoteAmount) buyTerms,(uint256 baseAmount,uint256 quoteAmount) sellTerms,bool isPublic,bytes32 accessHash,uint64 createdAt,uint32 executionCount,uint256 publicBaseInventory,uint256 publicQuoteInventory) order,bool buySideOpen,bool sellSideOpen,bool hasPrivateBaseInventory,bool hasPrivateQuoteInventory))',
  `function getRecurringAccountSummary(uint256 orderId,address account) view returns ((uint256 sequence,bool initialized,${UT} baseInventory,${UT} quoteInventory,uint256 privateFillReceiptTotal) summary)`,
  `event PrivateRecurringFillReceipt(uint256 indexed orderId,address indexed recipient,address indexed filler,uint256 fillIndex,uint8 side,${UT} baseAmount,${UT} quoteAmount,${UT} remainingBaseInventory,${UT} remainingQuoteInventory)`,
]);

const ut = (amount: bigint) => ({
  ciphertext: { ciphertextHigh: 0n, ciphertextLow: 0n },
  userCiphertext: { ciphertextHigh: 1n, ciphertextLow: amount },
});

class AcceptingElicitor implements FormElicitor {
  readonly requests: ConfirmationRequest[] = [];
  readonly events: string[];

  constructor(events: string[] = []) {
    this.events = events;
  }

  isSupported(): boolean {
    return true;
  }

  async requestConfirmation(request: ConfirmationRequest) {
    this.events.push('confirm');
    this.requests.push(structuredClone(request));
    return { outcome: 'accepted' as const };
  }
}

class FakeRpc implements JsonRpcReader {
  readonly calls: Array<{ method: string; params: unknown[] }> = [];
  readonly handler: (method: string, params: unknown[]) => unknown;
  readonly blockTag: Hex;

  constructor(
    handler: (method: string, params: unknown[]) => unknown,
    blockTag: Hex = '0x40',
  ) {
    this.handler = handler;
    this.blockTag = blockTag;
  }

  async request<T>(method: string, params: unknown[]): Promise<T> {
    this.calls.push({ method, params: structuredClone(params) });
    if (method === 'eth_blockNumber') return this.blockTag as T;
    return this.handler(method, params) as T;
  }
}

const wallet = {
  getAddress: async () => WALLET,
} as unknown as WalletTransport;

const activeFullPolicy = (
  manifestHash: HexString,
  agentVisiblePrivateAmounts = true,
): ActiveAutonomyPolicyV1 => ({
  id: 'policy-1',
  version: 'cw.autonomy-policy/1',
  wallet: WALLET,
  chainId: 2_632_500,
  manifestHash,
  startsAt: '2026-07-29T00:00:00.000Z',
  expiresAt: '2026-07-31T00:00:00.000Z',
  agentVisiblePrivateAmounts,
  mode: 'full',
  allowlistedEconomicSurface: true,
  activatedAt: '2026-07-29T00:00:00.000Z',
  termsDigest: `0x${'44'.repeat(32)}`,
  lifecycle: {
    state: 'active',
    changedAt: '2026-07-29T00:00:00.000Z',
  },
});

const activeBoundedPolicy = (
  manifestHash: HexString,
): ActiveAutonomyPolicyV1 => ({
  ...activeFullPolicy(manifestHash),
  mode: 'bounded',
  scope: {
    allowedActions: ['fill'],
    allowedAssets: ['p.WISP', 'p.COTI'],
    allowedPairs: [
      { sellAsset: 'p.WISP', buyAsset: 'p.COTI' },
    ],
    allowedOrderTypes: ['recurring.private-liquidity.public'],
    allowedCounterparties: [],
    allowedBridgeRoutes: [],
    messaging: { enabled: false, counterparties: [] },
  },
  limits: {
    perActionSpend: [],
    cumulativeSpend: [],
    maximumNativeValuePerAction: '0',
    maximumNativeValueCumulative: '0',
    maximumNetworkFeePerAction: '0',
    maximumNetworkFeeCumulative: '0',
    maximumActions: 1,
    maximumMessages: 0,
    priceBands: [],
  },
});

const privateStateAuthorizationFor = (
  policy: ActiveAutonomyPolicyV1,
  policyId: string,
): Awaited<
  ReturnType<AutonomyPolicyManager['authorizePrivateStateDisclosure']>
> => {
  if (policy.id !== policyId) {
    return {
      allowed: false,
      denial: {
        code: 'POLICY_NOT_FOUND',
        message: 'Autonomy policy was not found.',
        policyId,
      },
    };
  }
  if (policy.lifecycle.state !== 'active') {
    const code =
      policy.lifecycle.state === 'revoked'
        ? 'POLICY_REVOKED'
        : policy.lifecycle.state === 'expired'
          ? 'POLICY_EXPIRED'
          : 'POLICY_PAUSED';
    return {
      allowed: false,
      denial: {
        code,
        message: `Autonomy policy is ${policy.lifecycle.state}.`,
        policyId,
      },
    };
  }
  if (!policy.agentVisiblePrivateAmounts) {
    return {
      allowed: false,
      denial: {
        code: 'PRIVATE_AMOUNT_DISCLOSURE_NOT_ALLOWED',
        message:
          'The policy does not allow private amounts to be returned to the agent.',
        policyId,
        field: 'agentVisiblePrivateAmounts',
      },
    };
  }
  return { allowed: true, value: policy };
};

const service = async (options: {
  rpc: JsonRpcReader;
  elicitor?: AcceptingElicitor;
  policy?: ActiveAutonomyPolicyV1;
  autonomyAuthorization?: AutonomyPolicyManager['authorizePrivateStateDisclosure'];
  decrypt?: (
    ciphertext: { ciphertextHigh: bigint; ciphertextLow: bigint },
    aesKey: string,
  ) => bigint;
}) => {
  const manifest = await loadRuntimeManifest();
  const manifestHash = hashRuntimeManifest(manifest);
  const elicitor = options.elicitor ?? new AcceptingElicitor();
  const autonomyAuthorization =
    options.autonomyAuthorization ??
    (options.policy
      ? async (policyId: string) =>
          privateStateAuthorizationFor(options.policy!, policyId)
      : undefined);
  return {
    instance: new PrivateStateDisclosureService({
      manifest,
      manifestHash,
      rpc: options.rpc,
      wallet,
      privacyKey: () => AES_KEY,
      confirmation: new ConfirmationGate(elicitor, 1_000),
      ...(autonomyAuthorization
        ? {
            autonomy: {
              authorizePrivateStateDisclosure:
                autonomyAuthorization,
            },
          }
        : {}),
      decrypt:
        options.decrypt ??
        ((ciphertext) => ciphertext.ciphertextLow),
    }),
    manifest,
    manifestHash,
    elicitor,
  };
};

type RuntimeManifest = Awaited<ReturnType<typeof loadRuntimeManifest>>;

const recurringViewResult = (
  manifest: RuntimeManifest,
  options: {
    maker?: Address;
    taker?: Address;
    isPublic?: boolean;
    executionCount?: number;
  } = {},
): Hex => {
  const base = manifest.tokens.find(({ symbol }) => symbol === 'p.WISP')!;
  const quote = manifest.tokens.find(({ symbol }) => symbol === 'p.COTI')!;
  return encodeFunctionResult({
    abi: RECURRING_ABI,
    functionName: 'getOrderView',
    result: {
      order: {
        maker: options.maker ?? WALLET,
        taker: options.taker ?? ZERO,
        status: 1,
        mode: 1,
        baseAsset: {
          assetType: 2,
          token: base.address as Address,
        },
        quoteAsset: {
          assetType: 2,
          token: quote.address as Address,
        },
        buyTerms: { baseAmount: 1n, quoteAmount: 2n },
        sellTerms: { baseAmount: 1n, quoteAmount: 3n },
        isPublic: options.isPublic ?? true,
        accessHash: ZERO_HASH,
        createdAt: 1n,
        executionCount: options.executionCount ?? 2,
        publicBaseInventory: 0n,
        publicQuoteInventory: 0n,
      },
      buySideOpen: true,
      sellSideOpen: true,
      hasPrivateBaseInventory: true,
      hasPrivateQuoteInventory: true,
    },
  });
};

const recurringSummaryResult = (
  receiptTotal: bigint,
): Hex =>
  encodeFunctionResult({
    abi: RECURRING_ABI,
    functionName: 'getRecurringAccountSummary',
    result: {
      sequence: 3n,
      initialized: true,
      baseInventory: ut(8n),
      quoteInventory: ut(6n),
      privateFillReceiptTotal: receiptTotal,
    },
  });

const recurringReceiptLog = (
  manifest: RuntimeManifest,
  options: {
    fillIndex: number;
    filler?: Address;
    blockNumber?: Hex;
    data?: Hex;
  },
) => ({
  address: manifest.contracts.recurringEscrow!.address,
  data:
    options.data ??
    encodeAbiParameters(
      parseAbiParameters(
        `uint256,uint8,${UT},${UT},${UT},${UT}`,
      ),
      [
        BigInt(options.fillIndex),
        1,
        ut(2n),
        ut(4n),
        ut(8n),
        ut(6n),
      ],
    ),
  topics: encodeEventTopics({
    abi: RECURRING_ABI,
    eventName: 'PrivateRecurringFillReceipt',
    args: {
      orderId: 9n,
      recipient: WALLET,
      filler: options.filler ?? OTHER,
    },
  }),
  transactionHash:
    `0x${options.fillIndex.toString(16).padStart(64, '0')}` as HexString,
  blockNumber: options.blockNumber ?? ('0x20' as Hex),
  logIndex: `0x${options.fillIndex.toString(16)}` as Hex,
});

describe('private ChainWhisper state disclosure', () => {
  it('reveals verified balances only after one local approval and never puts values in the confirmation', async () => {
    const events: string[] = [];
    const rpc = new FakeRpc((method) => {
      expect(method).toBe('eth_call');
      events.push('private-read');
      return encodeFunctionResult({
        abi: TOKEN_ABI,
        functionName: 'balanceOf',
        result: {
          ciphertextHigh: 1n,
          ciphertextLow: 42n,
        },
      });
    });
    const elicitor = new AcceptingElicitor(events);
    const { instance } = await service({ rpc, elicitor });

    await expect(
      instance.disclose({
        kind: 'balances',
        assets: ['p.WISP'],
      }),
    ).resolves.toMatchObject({
      allowed: true,
      value: {
        authorization: { mode: 'local-confirmation' },
        data: {
          kind: 'balances',
          balances: [
            {
              symbol: 'p.WISP',
              decimals: 6,
              amountAtomic: '42',
            },
          ],
        },
      },
    });
    expect(events).toEqual(['confirm', 'private-read']);
    expect(elicitor.requests[0]?.amounts).toEqual([]);
    expect(elicitor.requests[0]?.details).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: '42' }),
      ]),
    );
    expect(elicitor.requests[0]).toMatchObject({
      action: 'reveal_private_chainwhisper_state',
      actionButtonLabel: 'Reveal private state to agent',
      fee: 'No transaction or protocol fee',
      nativeValue: '0',
      gasCap: '0',
    });
  });

  it('fails a policy disclosure closed without opening a fallback prompt', async () => {
    const rpc = new FakeRpc(() => {
      throw new Error('private read must not run');
    });
    const { manifestHash } = await service({ rpc });
    const elicitor = new AcceptingElicitor();
    const setup = await service({
      rpc,
      elicitor,
      policy: activeFullPolicy(manifestHash, false),
    });

    await expect(
      setup.instance.disclose(
        { kind: 'balances', assets: ['p.COTI'] },
        'policy-1',
      ),
    ).resolves.toEqual({
      allowed: false,
      denial: {
        code: 'PRIVATE_AMOUNT_DISCLOSURE_NOT_ALLOWED',
        message:
          'The policy does not allow private amounts to be returned to the agent.',
        policyId: 'policy-1',
        field: 'agentVisiblePrivateAmounts',
      },
    });
    expect(elicitor.requests).toHaveLength(0);
    expect(rpc.calls.map(({ method }) => method)).toEqual([
      'eth_blockNumber',
    ]);

    await expect(
      setup.instance.disclose(
        { kind: 'balances', assets: ['p.COTI'] },
        'different-policy',
      ),
    ).resolves.toMatchObject({
      allowed: false,
      denial: {
        code: 'POLICY_NOT_FOUND',
        policyId: 'different-policy',
      },
    });
    expect(elicitor.requests).toHaveLength(0);
    expect(rpc.calls.map(({ method }) => method)).toEqual([
      'eth_blockNumber',
      'eth_blockNumber',
    ]);
  });

  it('returns wallet-scoped one-off participant receipts without exposing maker inventory', async () => {
    const manifest = await loadRuntimeManifest();
    const privateToken = manifest.tokens.find(
      ({ symbol }) => symbol === 'p.WISP',
    )!;
    const publicToken = manifest.tokens.find(
      ({ symbol }) => symbol === 'WISP',
    )!;
    const events: string[] = [];
    const selectors = {
      trade: toFunctionSelector('getTrade(uint256)'),
      metadata: toFunctionSelector('getTradeMetadata(uint256)'),
      summary: toFunctionSelector(
        'getPrivateOrderAccountSummary(uint256,address)',
      ),
    };
    const receiptTopics = encodeEventTopics({
      abi: PRIVATE_ABI,
      eventName: 'PrivateOrderFillReceipt',
      args: { tradeId: 7n, recipient: WALLET, filler: OTHER },
    });
    const receiptData = encodeAbiParameters(
      parseAbiParameters(`uint256,${UT},${UT},${UT}`),
      [1n, ut(3n), ut(5n), ut(7n)],
    );
    const rpc = new FakeRpc((method, params) => {
      if (method === 'eth_getLogs') {
        events.push('private-logs');
        return [
          {
            address: manifest.contracts.privateEscrow!.address,
            data: receiptData,
            topics: receiptTopics,
            transactionHash: TRANSACTION_HASH,
            blockNumber: '0x10',
            logIndex: '0x1',
          },
        ];
      }
      const data = (
        params[0] as { data: Hex }
      ).data.toLowerCase();
      if (data.startsWith(selectors.trade)) {
        events.push('public-trade');
        return encodeFunctionResult({
          abi: PRIVATE_ABI,
          functionName: 'getTrade',
          result: [
            OTHER,
            ZERO,
            1,
            {
              assetType: 2,
              token: privateToken.address as Address,
              amount: 0n,
            },
            {
              assetType: 1,
              token: publicToken.address as Address,
              amount: 0n,
            },
            1n,
            2n,
          ],
        });
      }
      if (data.startsWith(selectors.metadata)) {
        events.push('public-metadata');
        return encodeFunctionResult({
          abi: PRIVATE_ABI,
          functionName: 'getTradeMetadata',
          result: [true, ZERO_HASH, 0n, ZERO_HASH, 1, true],
        });
      }
      if (data.startsWith(selectors.summary)) {
        events.push('private-summary');
        return encodeFunctionResult({
          abi: PRIVATE_ABI,
          functionName: 'getPrivateOrderAccountSummary',
          result: {
            sequence: 2n,
            initialized: false,
            remainingOfferAmount: ut(0n),
            fillReceiptTotal: 1n,
          },
        });
      }
      throw new Error('unexpected RPC call');
    });
    const elicitor = new AcceptingElicitor(events);
    const { instance } = await service({ rpc, elicitor });

    const result = await instance.disclose({
      kind: 'order',
      route: 'one-off',
      orderId: '7',
    });
    expect(result).toMatchObject({
      allowed: true,
      value: {
        data: {
          kind: 'order',
          route: 'one-off',
          role: 'participant',
          offerAsset: 'p.WISP',
          requestAsset: 'WISP',
          privateFillReceiptTotal: 1,
          receipts: [
            {
              fillIndex: 1,
              filler: OTHER,
              offerAmountAtomic: '3',
              requestAmountAtomic: '5',
              remainingOfferAmountAtomic: '7',
              transactionHash: TRANSACTION_HASH,
              blockNumber: 16,
            },
          ],
        },
      },
    });
    expect(
      result.allowed && result.value.data.kind === 'order'
        ? result.value.data
        : null,
    ).not.toHaveProperty('remainingOfferAmountAtomic');
    expect(events).toEqual([
      'public-trade',
      'public-metadata',
      'confirm',
      'private-summary',
      'private-logs',
    ]);
    expect(elicitor.requests[0]?.amounts).toEqual([]);
    expect(elicitor.requests[0]?.details).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: expect.stringMatching(/amount|inventory/iu) }),
      ]),
    );
  });

  it('uses an exact active policy for recurring owned inventory, progress, and receipts', async () => {
    const manifest = await loadRuntimeManifest();
    const base = manifest.tokens.find(({ symbol }) => symbol === 'p.WISP')!;
    const quote = manifest.tokens.find(({ symbol }) => symbol === 'p.COTI')!;
    const manifestHash = hashRuntimeManifest(manifest);
    const selectors = {
      view: toFunctionSelector('getOrderView(uint256)'),
      summary: toFunctionSelector(
        'getRecurringAccountSummary(uint256,address)',
      ),
    };
    const receiptTopics = encodeEventTopics({
      abi: RECURRING_ABI,
      eventName: 'PrivateRecurringFillReceipt',
      args: { orderId: 9n, recipient: WALLET, filler: OTHER },
    });
    const receiptData = encodeAbiParameters(
      parseAbiParameters(
        `uint256,uint8,${UT},${UT},${UT},${UT}`,
      ),
      [2n, 1, ut(2n), ut(4n), ut(8n), ut(6n)],
    );
    const rpc = new FakeRpc((method, params) => {
      if (method === 'eth_getLogs') {
        return [
          {
            address: manifest.contracts.recurringEscrow!.address,
            data: receiptData,
            topics: receiptTopics,
            transactionHash: TRANSACTION_HASH,
            blockNumber: '0x20',
            logIndex: '0x2',
          },
        ];
      }
      const data = (params[0] as { data: Hex }).data.toLowerCase();
      if (data.startsWith(selectors.view)) {
        return encodeFunctionResult({
          abi: RECURRING_ABI,
          functionName: 'getOrderView',
          result: {
            order: {
              maker: WALLET,
              taker: ZERO,
              status: 1,
              mode: 1,
              baseAsset: {
                assetType: 2,
                token: base.address as Address,
              },
              quoteAsset: {
                assetType: 2,
                token: quote.address as Address,
              },
              buyTerms: { baseAmount: 1n, quoteAmount: 2n },
              sellTerms: { baseAmount: 1n, quoteAmount: 3n },
              isPublic: true,
              accessHash: ZERO_HASH,
              createdAt: 1n,
              executionCount: 2,
              publicBaseInventory: 0n,
              publicQuoteInventory: 0n,
            },
            buySideOpen: true,
            sellSideOpen: true,
            hasPrivateBaseInventory: true,
            hasPrivateQuoteInventory: true,
          },
        });
      }
      if (data.startsWith(selectors.summary)) {
        return encodeFunctionResult({
          abi: RECURRING_ABI,
          functionName: 'getRecurringAccountSummary',
          result: {
            sequence: 3n,
            initialized: true,
            baseInventory: ut(8n),
            quoteInventory: ut(6n),
            privateFillReceiptTotal: 2n,
          },
        });
      }
      throw new Error('unexpected RPC call');
    });
    const elicitor = new AcceptingElicitor();
    const { instance } = await service({
      rpc,
      elicitor,
      policy: activeBoundedPolicy(manifestHash),
    });

    await expect(
      instance.disclose(
        {
          kind: 'order',
          route: 'recurring',
          orderId: '9',
        },
        'policy-1',
      ),
    ).resolves.toMatchObject({
      allowed: true,
      value: {
        authorization: {
          mode: 'autonomy-policy',
          policyId: 'policy-1',
        },
        data: {
          route: 'recurring',
          role: 'maker',
          baseAsset: 'p.WISP',
          quoteAsset: 'p.COTI',
          privateBaseInventoryAtomic: '8',
          privateQuoteInventoryAtomic: '6',
          executionCount: 2,
          privateFillReceiptTotal: 2,
          receiptsTruncated: true,
          receipts: [
            {
              fillIndex: 2,
              side: 'sell',
              baseAmountAtomic: '2',
              quoteAmountAtomic: '4',
              remainingBaseInventoryAtomic: '8',
              remainingQuoteInventoryAtomic: '6',
            },
          ],
        },
      },
    });
    expect(elicitor.requests).toHaveLength(0);
  });

  it('rejects direct-recipient recurring disclosure because the app does not expose that route', async () => {
    const manifest = await loadRuntimeManifest();
    const manifestHash = hashRuntimeManifest(manifest);
    const viewSelector = toFunctionSelector('getOrderView(uint256)');
    const rpc = new FakeRpc((method, params) => {
      expect(method).toBe('eth_call');
      const data = (params[0] as { data: Hex }).data.toLowerCase();
      expect(data.startsWith(viewSelector)).toBe(true);
      return recurringViewResult(manifest, {
        taker: BLOCKED,
        isPublic: false,
      });
    });
    const elicitor = new AcceptingElicitor();
    const { instance } = await service({
      rpc,
      elicitor,
      policy: activeBoundedPolicy(manifestHash),
    });

    await expect(
      instance.disclose(
        {
          kind: 'order',
          route: 'recurring',
          orderId: '9',
        },
        'policy-1',
      ),
    ).rejects.toMatchObject({
      code: 'UNSUPPORTED_TOOL',
      message:
        'Private-state disclosure supports only the public-access recurring orders exposed by the ChainWhisper app.',
    });
    expect(elicitor.requests).toHaveLength(0);
    expect(rpc.calls.map(({ method }) => method)).toEqual([
      'eth_blockNumber',
      'eth_call',
    ]);
  });

  it('returns policy-scoped public-order receipts without separately allowlisting every filler', async () => {
    const manifest = await loadRuntimeManifest();
    const manifestHash = hashRuntimeManifest(manifest);
    const selectors = {
      view: toFunctionSelector('getOrderView(uint256)'),
      summary: toFunctionSelector(
        'getRecurringAccountSummary(uint256,address)',
      ),
    };
    const rpc = new FakeRpc((method, params) => {
      if (method === 'eth_getLogs') {
        return [
          recurringReceiptLog(manifest, {
            fillIndex: 1,
            filler: BLOCKED,
          }),
        ];
      }
      const data = (params[0] as { data: Hex }).data.toLowerCase();
      if (data.startsWith(selectors.view)) {
        return recurringViewResult(manifest);
      }
      if (data.startsWith(selectors.summary)) {
        return recurringSummaryResult(1n);
      }
      throw new Error('unexpected RPC call');
    });
    const elicitor = new AcceptingElicitor();
    const decrypt = vi.fn(
      (ciphertext: { ciphertextLow: bigint }) =>
        ciphertext.ciphertextLow,
    );
    const { instance } = await service({
      rpc,
      elicitor,
      policy: activeBoundedPolicy(manifestHash),
      decrypt,
    });

    await expect(
      instance.disclose(
        {
          kind: 'order',
          route: 'recurring',
          orderId: '9',
        },
        'policy-1',
      ),
    ).resolves.toMatchObject({
      allowed: true,
      value: {
        data: {
          receipts: [
            {
              filler: BLOCKED,
              fillIndex: 1,
            },
          ],
        },
      },
    });
    expect(decrypt).toHaveBeenCalled();
    expect(elicitor.requests).toHaveLength(0);
  });

  it.each([
    ['paused', 'POLICY_PAUSED'],
    ['revoked', 'POLICY_REVOKED'],
  ] as const)(
    'does not return plaintext when a policy becomes %s during a disclosure',
    async (lifecycleStateAfterReadStarts, expectedCode) => {
      const manifest = await loadRuntimeManifest();
      const manifestHash = hashRuntimeManifest(manifest);
      const basePolicy = activeFullPolicy(manifestHash);
      let lifecycleState: 'active' | 'paused' | 'revoked' = 'active';
      let statusCalls = 0;
      let markReadStarted = (): void => undefined;
      const readStarted = new Promise<void>((resolve) => {
        markReadStarted = resolve;
      });
      let releaseRead = (): void => undefined;
      const readGate = new Promise<void>((resolve) => {
        releaseRead = resolve;
      });
      const rpc = new FakeRpc((method) => {
        expect(method).toBe('eth_call');
        return (async () => {
          markReadStarted();
          await readGate;
          return encodeFunctionResult({
            abi: TOKEN_ABI,
            functionName: 'balanceOf',
            result: {
              ciphertextHigh: 1n,
              ciphertextLow: 42n,
            },
          });
        })();
      });
      const elicitor = new AcceptingElicitor();
      const { instance } = await service({
        rpc,
        elicitor,
        autonomyAuthorization: async (policyId) => {
          statusCalls += 1;
          const policy: ActiveAutonomyPolicyV1 = {
            ...basePolicy,
            lifecycle: {
              ...basePolicy.lifecycle,
              state: lifecycleState,
            },
          };
          return privateStateAuthorizationFor(policy, policyId);
        },
      });

      const disclosure = instance.disclose(
        { kind: 'balances', assets: ['p.WISP'] },
        'policy-1',
      );
      await readStarted;
      lifecycleState = lifecycleStateAfterReadStarts;
      releaseRead();
      const result = await disclosure;

      expect(result).toMatchObject({
        allowed: false,
        denial: {
          code: expectedCode,
          policyId: 'policy-1',
        },
      });
      expect(JSON.stringify(result)).not.toContain('42');
      expect(statusCalls).toBe(2);
      expect(elicitor.requests).toHaveLength(0);
    },
  );

  it('returns a fixed secret-safe error for malformed private balance data', async () => {
    const secretBearingPayload = '0xdeadbeefcafebabe' as Hex;
    const rpc = new FakeRpc((method) => {
      expect(method).toBe('eth_call');
      return secretBearingPayload;
    });
    const { instance } = await service({ rpc });
    const error = await instance
      .disclose({ kind: 'balances', assets: ['p.WISP'] })
      .then(
        () => null,
        (reason: unknown) => reason,
      );

    expect(error).toMatchObject({
      code: 'PRIVATE_INPUT_UNAVAILABLE',
      message:
        'The signer rejected an invalid private-token balance response.',
    });
    expect(String((error as Error).message)).not.toContain(
      secretBearingPayload.slice(2),
    );
  });

  it('returns a fixed secret-safe error for a malformed wallet-scoped receipt', async () => {
    const manifest = await loadRuntimeManifest();
    const selectors = {
      view: toFunctionSelector('getOrderView(uint256)'),
      summary: toFunctionSelector(
        'getRecurringAccountSummary(uint256,address)',
      ),
    };
    const secretBearingPayload = '0xdeadbeefcafebabe' as Hex;
    const rpc = new FakeRpc((method, params) => {
      if (method === 'eth_getLogs') {
        return [
          recurringReceiptLog(manifest, {
            fillIndex: 1,
            data: secretBearingPayload,
          }),
        ];
      }
      const data = (params[0] as { data: Hex }).data.toLowerCase();
      if (data.startsWith(selectors.view)) {
        return recurringViewResult(manifest);
      }
      if (data.startsWith(selectors.summary)) {
        return recurringSummaryResult(1n);
      }
      throw new Error('unexpected RPC call');
    });
    const { instance } = await service({ rpc });
    const error = await instance
      .disclose({
        kind: 'order',
        route: 'recurring',
        orderId: '9',
      })
      .then(
        () => null,
        (reason: unknown) => reason,
      );

    expect(error).toMatchObject({
      code: 'STALE_STATE',
      message:
        'The signer rejected an invalid wallet-scoped recurring receipt response.',
    });
    expect(String((error as Error).message)).not.toContain(
      secretBearingPayload.slice(2),
    );
  });

  it('pins every read to one block and bounds receipt windows and decrypted output', async () => {
    const manifest = await loadRuntimeManifest();
    const manifestHash = hashRuntimeManifest(manifest);
    const pinnedBlock = 250_000n;
    const blockTag = `0x${pinnedBlock.toString(16)}` as Hex;
    const selectors = {
      view: toFunctionSelector('getOrderView(uint256)'),
      summary: toFunctionSelector(
        'getRecurringAccountSummary(uint256,address)',
      ),
    };
    let logRequestCount = 0;
    const rpc = new FakeRpc((method, params) => {
      if (method === 'eth_getLogs') {
        logRequestCount += 1;
        if (logRequestCount === 1) return [];
        const filter = params[0] as {
          fromBlock: Hex;
          toBlock: Hex;
        };
        const firstLogBlock = BigInt(filter.fromBlock) + 1n;
        return Array.from({ length: 5 }, (_, index) =>
          recurringReceiptLog(manifest, {
            fillIndex: index + 1,
            blockNumber:
              `0x${(firstLogBlock + BigInt(index)).toString(16)}` as Hex,
          }),
        );
      }
      const data = (params[0] as { data: Hex }).data.toLowerCase();
      if (data.startsWith(selectors.view)) {
        return recurringViewResult(manifest);
      }
      if (data.startsWith(selectors.summary)) {
        return recurringSummaryResult(100n);
      }
      throw new Error('unexpected RPC call');
    }, blockTag);
    const decrypt = vi.fn(
      (ciphertext: { ciphertextLow: bigint }) =>
        ciphertext.ciphertextLow,
    );
    const { instance } = await service({
      rpc,
      policy: activeFullPolicy(manifestHash),
      decrypt,
    });

    const result = await instance.disclose(
      {
        kind: 'order',
        route: 'recurring',
        orderId: '9',
        fromBlock: 1,
        receiptLimit: 2,
      },
      'policy-1',
    );

    expect(result).toMatchObject({
      allowed: true,
      value: {
        data: {
          receiptsTruncated: true,
          receipts: [{ fillIndex: 4 }, { fillIndex: 5 }],
        },
      },
    });
    const callBlocks = rpc.calls
      .filter(({ method }) => method === 'eth_call')
      .map(({ params }) => params[1]);
    expect(callBlocks).toEqual([blockTag, blockTag]);
    const logFilters = rpc.calls
      .filter(({ method }) => method === 'eth_getLogs')
      .map(({ params }) => params[0] as {
        fromBlock: Hex;
        toBlock: Hex;
      });
    expect(logFilters).toHaveLength(2);
    expect(logFilters[0]?.toBlock).toBe(blockTag);
    for (const filter of logFilters) {
      expect(
        BigInt(filter.toBlock) - BigInt(filter.fromBlock),
      ).toBeLessThan(100_000n);
    }
    expect(BigInt(logFilters[1]!.toBlock)).toBe(
      BigInt(logFilters[0]!.fromBlock) - 1n,
    );
    expect(decrypt).toHaveBeenCalledTimes(10);
  });
});
