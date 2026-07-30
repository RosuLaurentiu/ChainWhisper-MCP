import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  parseAbi,
  parseAbiParameters,
} from 'viem';

import {
  finalizeActionEnvelope,
  deriveOrderClassificationV1,
  signActionEnvelope,
  type HexString,
  type SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  ActionEnvelopeVerifier,
  AutonomyPolicyManager,
  ConfirmationGate,
  EncryptedSecretVault,
  LoadedSignerConfig,
  OperationJournal,
  PassthroughPrivateInputMaterializer,
  SignerEngine,
  StrictMaterializedIntentValidator,
  loadSignerConfig,
  type Address,
  type AutonomyReservationV1,
  type ConfirmationRequest,
  type FormElicitor,
  type MaterializedActionStep,
  type MaterializedIntentValidator,
  type PolicyExposureV1,
  type RuntimeRegistryState,
  type RuntimeStateReader,
  type TransactionReceipt,
  type TransactionRequest,
  type TransactionSimulator,
  type WalletTransport,
} from '../src/signer/index.js';

const WALLET = '0x1111111111111111111111111111111111111111' as Address;
const CONTRACT = '0x2222222222222222222222222222222222222222' as Address;
const FEE_RECIPIENT = '0x3333333333333333333333333333333333333333' as Address;
const REGISTRY_HASH = `0x${'44'.repeat(32)}` as HexString;
const PAIRING = 'pairing-secret-that-is-longer-than-thirty-two-characters';
const NOW = new Date('2026-07-27T12:05:00.000Z');
const CANCEL_ABI = parseAbi(['function cancelTrade(uint256 tradeId)']);
const TRADE_OPENED_ABI = parseAbi([
  'event TradeOpened(uint256 indexed tradeId, address indexed maker, address indexed taker, bool isPublic, bytes32 accessHash, uint256 parentTradeId, uint64 createdAt, uint64 expiresAt, uint256 feePaid)',
]);
const CANCEL_DATA = encodeFunctionData({
  abi: CANCEL_ABI,
  functionName: 'cancelTrade',
  args: [5n],
});
const FEE_KEY = CONTRACT.toLowerCase();

const createConfig = (stateDirectory: string): LoadedSignerConfig =>
  new LoadedSignerConfig({
    chainId: 2_632_500,
    rpcUrl: 'https://mainnet.coti.io/rpc',
    stateDirectory,
    expectedWallet: WALLET,
    confirmationTimeoutMs: 5_000,
    operationExpirySkewMs: 1_000,
    secrets: {
      privateKey: `0x${'11'.repeat(32)}`,
      aesKey: `0x${'22'.repeat(32)}`,
      pairingSecret: PAIRING,
      vaultPassphrase: 'a-long-test-vault-passphrase',
    },
  });

const createEnvelope = (
  operationId = 'operation-1',
): SignedActionEnvelopeV1 =>
  signActionEnvelope(
    finalizeActionEnvelope({
      operationId,
      wallet: WALLET,
      registrySnapshot: {
        registryAddress: CONTRACT,
        registryBytecodeHash: REGISTRY_HASH,
        manifestHash: REGISTRY_HASH,
        observedBlock: '10',
        contracts: {},
        fees: { [FEE_KEY]: '7' },
      },
      issuedAt: '2026-07-27T12:00:00.000Z',
      expiresAt: '2026-07-27T12:15:00.000Z',
      intent: {
        action: 'order_update',
        order: { escrowContract: CONTRACT, localId: '5' },
        metadata: {
          update: 'cancel',
          orderRelation: 'primary',
          sourceOrderRelation: 'primary',
          sourceMaker: WALLET,
          sourceRecipient: null,
          sourceOrderType: null,
          orderStatus: 'open',
        },
      },
      steps: [
        {
          id: 'cancel',
          kind: 'protocol',
          to: CONTRACT,
          data: CANCEL_DATA,
          value: '0',
          gasCap: '100000',
          summary: 'Cancel order 5.',
          callTemplate: {
            functionSignature: 'cancelTrade(uint256)',
            arguments: ['5'],
          },
        },
      ],
      exactNativeValue: '0',
      fee: { recipient: FEE_RECIPIENT, amount: '0', asset: 'native' },
      gasCap: '100000',
      privateInputs: [],
      secretPolicy: {
        accessMode: 'public',
        generatedLocally: false,
        mayLeaveSigner: false,
        sharing: 'none',
      },
      simulation: {
        status: 'passed',
        checkedAt: '2026-07-27T12:00:00.000Z',
        blockNumber: '10',
      },
      summary: 'Cancel ChainWhisper order 5.',
    }),
    PAIRING,
  );

const resignEnvelope = (
  envelope: SignedActionEnvelopeV1,
  changes: Partial<
    Omit<
      SignedActionEnvelopeV1,
      'pairingSignature' | 'operationHash' | 'version' | 'chainId'
    >
  >,
): SignedActionEnvelopeV1 => {
  const {
    pairingSignature: _pairingSignature,
    operationHash: _operationHash,
    version: _version,
    chainId: _chainId,
    ...draft
  } = envelope;
  return signActionEnvelope(
    finalizeActionEnvelope({ ...draft, ...changes }),
    PAIRING,
  );
};

const createStandardOrderEnvelope = (
  operationId: string,
): {
  envelope: SignedActionEnvelopeV1;
  orderType: ReturnType<typeof deriveOrderClassificationV1>;
} => {
  const orderType = deriveOrderClassificationV1({
    route: 'standard-escrow',
    access: 'public',
    privateLiquidity: false,
    assets: [{ kind: 'erc20' }, { kind: 'erc20' }],
    relation: 'primary',
  });
  const base = createEnvelope(operationId);
  return {
    orderType,
    envelope: resignEnvelope(base, {
      registrySnapshot: {
        ...base.registrySnapshot,
        contracts: {
          standardEscrow: {
            address: CONTRACT,
            bytecodeHash: REGISTRY_HASH,
            selectors: {
              createTradeWithPolicy: CANCEL_DATA.slice(
                0,
                10,
              ) as HexString,
            },
          },
        },
      },
      intent: {
        action: 'create_trade',
        orderType,
        accessMode: 'public',
        amountVisibility: 'visible',
        sellAsset: {
          kind: 'erc20',
          reference: 'WISP',
          address: CONTRACT,
          symbol: 'WISP',
          decimals: 6,
        },
        buyAsset: {
          kind: 'native',
          reference: 'COTI',
          symbol: 'COTI',
          decimals: 18,
        },
        sellAmount: '1',
        buyAmount: '2',
      },
      fee: {
        recipient: FEE_RECIPIENT,
        amount: '7',
        asset: 'native',
      },
      summary: 'Create a public order.',
    }),
  };
};

const tradeOpenedLog = (tradeId: bigint) => ({
  address: CONTRACT,
  topics: encodeEventTopics({
    abi: TRADE_OPENED_ABI,
    eventName: 'TradeOpened',
    args: {
      tradeId,
      maker: WALLET,
      taker: '0x0000000000000000000000000000000000000000',
    },
  }),
  data: encodeAbiParameters(
    parseAbiParameters(
      'bool, bytes32, uint256, uint64, uint64, uint256',
    ),
    [true, `0x${'00'.repeat(32)}`, 0n, 1n, 2n, 7n],
  ),
});

class TestRuntimeState implements RuntimeStateReader {
  reads = 0;
  state: RuntimeRegistryState = {
    chainId: 2_632_500,
    registryHash: REGISTRY_HASH,
    fees: { [FEE_KEY]: '7' },
    trustedFeeRecipients: { [FEE_KEY]: FEE_RECIPIENT },
    allowedContracts: new Set([CONTRACT.toLowerCase()]),
    allowedSelectors: new Map([
      [CONTRACT.toLowerCase(), new Set([CANCEL_DATA.slice(0, 10).toLowerCase()])],
    ]),
  };

  async readRegistryState(): Promise<RuntimeRegistryState> {
    this.reads += 1;
    return this.state;
  }
}

class TestElicitor implements FormElicitor {
  requests: ConfirmationRequest[] = [];

  constructor(
    readonly supported = true,
    readonly outcome: 'accepted' | 'declined' | 'timeout' = 'accepted',
  ) {}

  isSupported(): boolean {
    return this.supported;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<
    | { outcome: 'accepted' }
    | { outcome: 'declined' }
    | { outcome: 'timeout' }
  > {
    this.requests.push(request);
    return { outcome: this.outcome };
  }
}

class DeferredTestElicitor extends TestElicitor {
  release: (() => void) | null = null;

  override async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<{ outcome: 'accepted' }> {
    this.requests.push(request);
    await new Promise<void>((resolve) => {
      this.release = resolve;
    });
    return { outcome: 'accepted' };
  }
}

class BusyDeclinesElicitor extends TestElicitor {
  concurrentDeclines = 0;
  readonly releases: Array<() => void> = [];
  #active = false;

  override async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<{ outcome: 'accepted' } | { outcome: 'declined' }> {
    this.requests.push(request);
    if (this.#active) {
      this.concurrentDeclines += 1;
      return { outcome: 'declined' };
    }
    this.#active = true;
    await new Promise<void>((resolve) => {
      this.releases.push(resolve);
    });
    this.#active = false;
    return { outcome: 'accepted' };
  }
}

class TestWallet implements WalletTransport {
  prepareCount = 0;
  broadcastCount = 0;
  pendingNonce = 4;
  receiptStatus: TransactionReceipt['status'] = 'success';
  receiptLogs: TransactionReceipt['logs'];
  throwAfterAccept = false;
  throwPrepareOnce = false;
  hideTransactions = false;
  readonly transactions = new Map<string, { hash: HexString; nonce: number }>();
  readonly prepared = new Map<string, { hash: HexString; nonce: number }>();

  async getAddress(): Promise<Address> {
    return WALLET;
  }

  async getChainId(): Promise<number> {
    return 2_632_500;
  }

  async getPendingNonce(): Promise<number> {
    return this.pendingNonce;
  }

  async prepareTransaction(
    request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }> {
    this.prepareCount += 1;
    if (this.throwPrepareOnce) {
      this.throwPrepareOnce = false;
      throw new Error('transaction preparation failed');
    }
    const hash = `0x${(request.nonce + 1).toString(16).padStart(64, '0')}` as HexString;
    const signedTransaction = `0x${(request.nonce + 11)
      .toString(16)
      .padStart(64, '0')}` as HexString;
    this.prepared.set(signedTransaction, { hash, nonce: request.nonce });
    return { hash, signedTransaction };
  }

  async broadcastTransaction(
    signedTransaction: HexString,
  ): Promise<{ hash: HexString }> {
    this.broadcastCount += 1;
    const prepared = this.prepared.get(signedTransaction);
    if (!prepared) throw new Error('not prepared');
    this.transactions.set(prepared.hash, prepared);
    if (this.throwAfterAccept) throw new Error('provider response lost');
    return { hash: prepared.hash };
  }

  async getTransaction(
    hash: HexString,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    if (this.hideTransactions) return null;
    return this.transactions.get(hash) ?? null;
  }

  async findTransactionByNonce(
    nonce: number,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    if (this.hideTransactions) return null;
    return (
      [...this.transactions.values()].find(
        (transaction) => transaction.nonce === nonce,
      ) ?? null
    );
  }

  async getTransactionReceipt(
    hash: HexString,
  ): Promise<TransactionReceipt | null> {
    if (this.hideTransactions) return null;
    return this.transactions.has(hash)
      ? {
          transactionHash: hash,
          status: this.receiptStatus,
          ...(this.receiptStatus === 'pending' ? {} : { blockNumber: 20 }),
          ...(this.receiptLogs ? { logs: this.receiptLogs } : {}),
        }
      : null;
  }

  async waitForTransaction(hash: HexString): Promise<TransactionReceipt> {
    return {
      transactionHash: hash,
      status: this.receiptStatus,
      ...(this.receiptStatus === 'pending' ? {} : { blockNumber: 20 }),
      ...(this.receiptLogs ? { logs: this.receiptLogs } : {}),
    };
  }
}

class TestSimulator implements TransactionSimulator {
  calls = 0;
  failOnCall: number | null = null;

  async simulate(): Promise<
    { ok: true } | { ok: false; errorCode: string }
  > {
    this.calls += 1;
    return this.failOnCall === this.calls
      ? { ok: false, errorCode: 'STALE_SIMULATION' }
      : { ok: true };
  }
}

class SequencedFeeSimulator extends TestSimulator {
  constructor(readonly maximumFees: string[]) {
    super();
  }

  override async simulate(): Promise<{
    ok: true;
    feeQuote: {
      model: 'eip1559';
      maximumNetworkFeeWei: string;
      maximumNetworkFeeCoti: string;
      maximumFeePerGasWei: string;
    };
  }> {
    const maximumNetworkFeeWei =
      this.maximumFees[this.calls] ??
      this.maximumFees.at(-1) ??
      '0';
    this.calls += 1;
    return {
      ok: true,
      feeQuote: {
        model: 'eip1559',
        maximumNetworkFeeWei,
        maximumNetworkFeeCoti: '0',
        maximumFeePerGasWei: '1',
      },
    };
  }
}

class DeferredSecondSimulation extends TestSimulator {
  readonly secondCallStarted: Promise<void>;
  #markSecondCallStarted: () => void = () => undefined;
  #releaseSecondCall: () => void = () => undefined;

  constructor() {
    super();
    this.secondCallStarted = new Promise<void>((resolve) => {
      this.#markSecondCallStarted = resolve;
    });
  }

  release(): void {
    this.#releaseSecondCall();
  }

  override async simulate(): Promise<
    { ok: true } | { ok: false; errorCode: string }
  > {
    this.calls += 1;
    if (this.calls === 2) {
      this.#markSecondCallStarted();
      await new Promise<void>((resolve) => {
        this.#releaseSecondCall = resolve;
      });
    }
    return { ok: true };
  }
}

class DeferredPrepareWallet extends TestWallet {
  readonly prepareStarted: Promise<void>;
  #markPrepareStarted: () => void = () => undefined;
  #releasePrepare: () => void = () => undefined;

  constructor() {
    super();
    this.prepareStarted = new Promise<void>((resolve) => {
      this.#markPrepareStarted = resolve;
    });
  }

  release(): void {
    this.#releasePrepare();
  }

  override async prepareTransaction(
    request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }> {
    this.#markPrepareStarted();
    await new Promise<void>((resolve) => {
      this.#releasePrepare = resolve;
    });
    return super.prepareTransaction(request);
  }
}

class DeferredReceiptWallet extends TestWallet {
  readonly waitStarted: Promise<void>;
  receiptReads = 0;
  #markWaitStarted: () => void = () => undefined;
  #releaseWait: () => void = () => undefined;

  constructor() {
    super();
    this.waitStarted = new Promise<void>((resolve) => {
      this.#markWaitStarted = resolve;
    });
  }

  release(): void {
    this.#releaseWait();
  }

  override async getTransactionReceipt(
    hash: HexString,
  ): Promise<TransactionReceipt | null> {
    this.receiptReads += 1;
    return super.getTransactionReceipt(hash);
  }

  override async waitForTransaction(
    hash: HexString,
  ): Promise<TransactionReceipt> {
    this.#markWaitStarted();
    await new Promise<void>((resolve) => {
      this.#releaseWait = resolve;
    });
    return super.waitForTransaction(hash);
  }
}

const createTestAutonomy = () => {
  let paused = false;
  let reservationState: AutonomyReservationV1['state'] = 'reserved';
  const reservation = (): AutonomyReservationV1 =>
    ({
      id: 'reservation-1',
      policyId: 'policy-1',
      operationHash: REGISTRY_HASH,
      state: reservationState,
      signedTransactionHashes: [],
    }) as unknown as AutonomyReservationV1;
  const manager = {
    reserve: async () => ({ allowed: true as const, value: reservation() }),
    authorizeReservedWrite: async () =>
      paused
        ? {
            allowed: false as const,
            denial: {
              code: 'GLOBAL_PAUSED' as const,
              message: 'Autonomy is globally paused.',
              policyId: 'policy-1',
            },
          }
        : { allowed: true as const, value: reservation() },
    markSigned: async () => {
      reservationState = 'signed';
      return { allowed: true as const, value: reservation() };
    },
    markPending: async () => {
      reservationState = 'pending';
      return { allowed: true as const, value: reservation() };
    },
    markUncertain: async () => {
      reservationState = 'uncertain';
      return { allowed: true as const, value: reservation() };
    },
    markSettled: async () => {
      reservationState = 'settled';
      return { allowed: true as const, value: reservation() };
    },
    releaseBeforeSigning: async () => {
      reservationState = 'released';
      return { allowed: true as const, value: reservation() };
    },
    pauseGlobal: async () => {
      paused = true;
      return {
        allowed: true as const,
        value: {
          globalPaused: true,
          policies: [],
          activeReservationCount: 1,
        },
      };
    },
  } as unknown as AutonomyPolicyManager;
  return { manager, isPaused: () => paused };
};

const createEngine = async (options: {
  wallet?: TestWallet;
  elicitor?: TestElicitor;
  simulator?: TestSimulator;
  intentValidator?: MaterializedIntentValidator;
  autonomy?: AutonomyPolicyManager;
}) => {
  const stateDirectory = await mkdtemp(join(tmpdir(), 'cw-signer-core-'));
  const config = createConfig(stateDirectory);
  const runtime = new TestRuntimeState();
  const wallet = options.wallet ?? new TestWallet();
  const elicitor = options.elicitor ?? new TestElicitor();
  const simulator = options.simulator ?? new TestSimulator();
  const journal = new OperationJournal(stateDirectory, () => NOW);
  const vault = new EncryptedSecretVault(
    stateDirectory,
    config.credentialMaterial().vaultPassphrase,
    () => NOW,
  );
  return {
    stateDirectory,
    runtime,
    wallet,
    elicitor,
    simulator,
    journal,
    vault,
    engine: new SignerEngine({
      verifier: new ActionEnvelopeVerifier(config, runtime, () => NOW),
      wallet,
      materializer: new PassthroughPrivateInputMaterializer(),
      confirmation: new ConfirmationGate(elicitor, 5_000),
      simulator,
      intentValidator:
        options.intentValidator ??
        new StrictMaterializedIntentValidator(),
      journal,
      vault,
      ...(options.autonomy ? { autonomy: options.autonomy } : {}),
    }),
  };
};

describe('local ChainWhisper signer core', () => {
  it('returns a structured policy denial without opening a fallback confirmation', async () => {
    const autonomy = {
      reserve: async () => ({
        allowed: false as const,
        denial: {
          code: 'ACTION_NOT_ALLOWED' as const,
          message: 'Action is outside the bounded policy.',
          policyId: 'policy-1',
          field: 'action',
        },
      }),
    } as unknown as AutonomyPolicyManager;
    const setup = await createEngine({ autonomy });

    await expect(
      setup.engine.executeAction(createEnvelope('policy-denial'), 'policy-1'),
    ).resolves.toMatchObject({
      status: 'denied',
      errorCode: 'AUTONOMY_ACTION_NOT_ALLOWED',
      autonomyDenial: {
        code: 'ACTION_NOT_ALLOWED',
        policyId: 'policy-1',
      },
    });
    expect(setup.elicitor.requests).toHaveLength(0);
    expect(setup.wallet.prepared.size).toBe(0);
  });

  it('persists an asynchronous policy denial as a terminal safe status', async () => {
    const autonomy = {
      reserve: async () => ({
        allowed: false as const,
        denial: {
          code: 'ACTION_NOT_ALLOWED' as const,
          message: 'Action is outside the bounded policy.',
          policyId: 'policy-1',
          field: 'action',
        },
      }),
    } as unknown as AutonomyPolicyManager;
    const setup = await createEngine({ autonomy });
    const envelope = createEnvelope('queued-policy-denial');

    await setup.engine.queueAction(envelope, 'policy-1');
    let status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );
    for (
      let attempt = 0;
      status?.status !== 'failed' && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      status = await setup.engine.getOperationStatus(
        envelope.operationId,
      );
    }

    expect(status).toMatchObject({
      status: 'failed',
      errorCode: 'AUTONOMY_ACTION_NOT_ALLOWED',
      userActionRequired: false,
    });
    expect(setup.elicitor.requests).toHaveLength(0);
    expect(
      await setup.vault.get(
        `operation:${envelope.operationId}:request`,
      ),
    ).toBeNull();
  });

  it('does not list, restore, or replay a failed queued operation', async () => {
    const setup = await createEngine({});
    const envelope = createEnvelope('failed-queued-operation');
    await setup.journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );
    await setup.vault.put(
      `operation:${envelope.operationId}:request`,
      JSON.stringify({ version: 1, envelope }),
      { kind: 'recovery-note' },
    );
    await setup.journal.recordError(
      envelope.operationId,
      'STALE_SIMULATION',
      true,
    );

    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({
      status: 'failed',
      errorCode: 'STALE_SIMULATION',
      userActionRequired: false,
      nextPollingIntervalMs: null,
    });
    await expect(
      setup.engine.listPendingOperationIds(),
    ).resolves.not.toContain(envelope.operationId);

    await setup.engine.restorePendingOperations();
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    expect(setup.elicitor.requests).toHaveLength(0);
    expect(setup.simulator.calls).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);

    await expect(
      setup.engine.queueAction(envelope),
    ).resolves.toMatchObject({
      status: 'failed',
      errorCode: 'STALE_SIMULATION',
      nextPollingIntervalMs: null,
    });
    expect(setup.elicitor.requests).toHaveLength(0);
    expect(setup.simulator.calls).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('leaves private-message journal records to the messaging lifecycle owner', async () => {
    const setup = await createEngine({});
    const operationHash = `0x${'7a'.repeat(32)}` as HexString;
    const operationId = `message-${operationHash.slice(2, 18)}`;
    await setup.journal.begin(operationId, operationHash);
    await setup.journal.reserveNonce(operationId, 4, 0);
    await setup.journal.recordBroadcast(
      operationId,
      4,
      `0x${'7b'.repeat(32)}` as HexString,
      0,
    );

    await setup.engine.restorePendingOperations();

    await expect(
      setup.engine.listPendingOperationIds(),
    ).resolves.not.toContain(operationId);
    await expect(setup.journal.get(operationId)).resolves.toMatchObject({
      stage: 'broadcast',
      errorCodes: [],
    });
    expect(setup.simulator.calls).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('does not reopen a confirmation for an already declined operation', async () => {
    const elicitor = new TestElicitor(true, 'declined');
    const setup = await createEngine({ elicitor });
    const envelope = createEnvelope('declined-operation-replay');

    await setup.engine.queueAction(envelope);
    let status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );
    for (
      let attempt = 0;
      status?.status !== 'declined' && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      status = await setup.engine.getOperationStatus(
        envelope.operationId,
      );
    }

    expect(status).toMatchObject({
      status: 'declined',
      errorCode: 'CONFIRMATION_DECLINED',
      userActionRequired: false,
    });
    expect(await setup.journal.get(envelope.operationId)).toMatchObject({
      stage: 'declined',
    });
    expect(await setup.engine.listPendingOperationIds()).not.toContain(
      envelope.operationId,
    );
    expect(elicitor.requests).toHaveLength(1);

    await expect(setup.engine.queueAction(envelope)).resolves.toMatchObject({
      status: 'declined',
      errorCode: 'CONFIRMATION_DECLINED',
    });
    expect(elicitor.requests).toHaveLength(1);
  });

  it('journals confirmation timeout as terminal and excludes it from pending work', async () => {
    const elicitor = new TestElicitor(true, 'timeout');
    const setup = await createEngine({ elicitor });
    const envelope = createEnvelope('timed-out-operation');

    await setup.engine.queueAction(envelope);
    let status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );
    for (
      let attempt = 0;
      status?.status !== 'declined' && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      status = await setup.engine.getOperationStatus(
        envelope.operationId,
      );
    }

    expect(status).toMatchObject({
      status: 'declined',
      errorCode: 'CONFIRMATION_TIMEOUT',
      userActionRequired: false,
    });
    expect(await setup.journal.get(envelope.operationId)).toMatchObject({
      stage: 'declined',
    });
    expect(await setup.engine.listPendingOperationIds()).not.toContain(
      envelope.operationId,
    );
    await expect(setup.engine.queueAction(envelope)).resolves.toMatchObject({
      status: 'declined',
      errorCode: 'CONFIRMATION_TIMEOUT',
    });
    expect(elicitor.requests).toHaveLength(1);
  });

  it('serializes queued manual operations instead of treating a busy prompt as a decline', async () => {
    const elicitor = new BusyDeclinesElicitor();
    const setup = await createEngine({ elicitor });
    const first = createEnvelope('serialized-manual-first');
    const second = createEnvelope('serialized-manual-second');

    await setup.engine.queueAction(first);
    await setup.engine.queueAction(second);
    for (
      let attempt = 0;
      elicitor.requests.length < 1 && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    expect(elicitor.requests).toHaveLength(1);
    expect(
      await setup.engine.getOperationStatus(second.operationId),
    ).toMatchObject({ status: 'queued' });

    elicitor.releases.shift()?.();
    for (
      let attempt = 0;
      elicitor.requests.length < 2 && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    expect(elicitor.requests).toHaveLength(2);
    expect(elicitor.concurrentDeclines).toBe(0);

    elicitor.releases.shift()?.();
    let secondStatus = await setup.engine.getOperationStatus(
      second.operationId,
    );
    for (
      let attempt = 0;
      secondStatus?.status !== 'completed' && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      secondStatus = await setup.engine.getOperationStatus(
        second.operationId,
      );
    }
    expect(secondStatus).toMatchObject({ status: 'completed' });
  });

  it('rechecks runtime around confirmation and confirms every write', async () => {
    const setup = await createEngine({});
    setup.runtime.state.fees[
      '0x9999999999999999999999999999999999999999'
    ] = '11';
    setup.runtime.state.trustedFeeRecipients[
      '0x9999999999999999999999999999999999999999'
    ] = FEE_RECIPIENT;
    const result = await setup.engine.executeAction(createEnvelope());
    expect(result.status).toBe('completed');
    expect(setup.wallet.prepareCount).toBe(1);
    expect(setup.elicitor.requests).toHaveLength(1);
    expect(setup.elicitor.requests[0]).toMatchObject({
      wallet: WALLET,
      contract: CONTRACT,
      action: 'order_update',
      gasCap: '100000',
    });
    expect(setup.runtime.reads).toBeGreaterThanOrEqual(3);
    expect(setup.simulator.calls).toBe(2);
  });

  it('authorizes a complete multi-step action with one confirmation', async () => {
    const setup = await createEngine({});
    const base = createEnvelope('complete-action-confirmation');
    const envelope = resignEnvelope(base, {
      steps: [
        base.steps[0]!,
        {
          ...base.steps[0]!,
          id: 'cancel-confirmed-sequence',
          summary: 'Complete the confirmed sequence.'
        }
      ],
      gasCap: '200000'
    });

    await expect(setup.engine.executeAction(envelope)).resolves.toMatchObject({
      status: 'completed'
    });
    expect(setup.wallet.prepareCount).toBe(2);
    expect(setup.elicitor.requests).toHaveLength(1);
    expect(setup.elicitor.requests[0]).toMatchObject({
      authorizationScope: 'complete-logical-action',
      actionButtonLabel: 'Confirm complete order update',
      stepCount: 2,
      gasCap: '200000',
      technicalDetails: [
        { stepId: 'cancel' },
        { stepId: 'cancel-confirmed-sequence' }
      ]
    });
    expect(setup.elicitor.requests[0]?.stepDigests).toHaveLength(2);
    expect(setup.simulator.calls).toBe(4);
  });

  it('re-simulates after confirmation and never signs changed state', async () => {
    const simulator = new TestSimulator();
    simulator.failOnCall = 2;
    const setup = await createEngine({ simulator });
    const result = await setup.engine.executeAction(
      createEnvelope('post-confirmation-simulation'),
    );
    expect(result).toMatchObject({
      status: 'retryable',
      errorCode: 'STALE_SIMULATION',
    });
    expect(setup.elicitor.requests).toHaveLength(1);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('revalidates live intent facts after confirmation before signing', async () => {
    let validations = 0;
    const setup = await createEngine({
      intentValidator: {
        validate: async () => {
          validations += 1;
          if (validations === 2) {
            throw new Error('Live order facts changed during confirmation.');
          }
        },
      },
    });
    const result = await setup.engine.executeAction(
      createEnvelope('post-confirmation-intent-validation'),
    );
    expect(result.status).toBe('retryable');
    expect(validations).toBe(2);
    expect(setup.elicitor.requests).toHaveLength(1);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('stays read-only when form elicitation is unsupported', async () => {
    const setup = await createEngine({
      elicitor: new TestElicitor(false),
    });
    const result = await setup.engine.executeAction(createEnvelope());
    expect(result).toMatchObject({
      status: 'read-only',
      errorCode: 'ELICITATION_UNSUPPORTED',
    });
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('queues a verified envelope without waiting for Agent Control', async () => {
    const elicitor = new DeferredTestElicitor();
    const setup = await createEngine({ elicitor });
    const envelope = createEnvelope('async-agent-control');

    await expect(setup.engine.queueAction(envelope)).resolves.toMatchObject({
      version: 'cw.operation-status/2',
      operationId: envelope.operationId,
      operationHash: envelope.operationHash,
      status: 'queued',
      userActionRequired: false,
    });
    expect(setup.wallet.prepareCount).toBe(0);
    for (let attempt = 0; !elicitor.release && attempt < 50; attempt += 1) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
    elicitor.release?.();
  });

  it('applies pause before an unsigned autonomous write reaches the wallet', async () => {
    const simulator = new DeferredSecondSimulation();
    const autonomy = createTestAutonomy();
    const setup = await createEngine({
      simulator,
      autonomy: autonomy.manager,
    });
    const envelope = createEnvelope('pause-before-signing');

    await setup.engine.queueAction(envelope, 'policy-1');
    await simulator.secondCallStarted;
    await expect(setup.engine.pauseAutonomy()).resolves.toMatchObject({
      allowed: true,
      value: { globalPaused: true },
    });
    simulator.release();

    await expect
      .poll(
        async () =>
          (await setup.engine.getOperationStatus(envelope.operationId))
            ?.errorCode,
      )
      .toBe('WRITE_UNAVAILABLE');
    expect(autonomy.isPaused()).toBe(true);
    expect(setup.wallet.prepareCount).toBe(0);
    expect(setup.wallet.broadcastCount).toBe(0);
  });

  it('waits for a write already inside the signing queue before pause returns', async () => {
    const wallet = new DeferredPrepareWallet();
    const autonomy = createTestAutonomy();
    const setup = await createEngine({
      wallet,
      autonomy: autonomy.manager,
    });
    const envelope = createEnvelope('pause-waits-for-active-signing');

    await setup.engine.queueAction(envelope, 'policy-1');
    await wallet.prepareStarted;
    let pauseFinished = false;
    const pausing = setup.engine.pauseAutonomy().then((result) => {
      pauseFinished = true;
      return result;
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
    expect(pauseFinished).toBe(false);

    wallet.release();
    await expect(pausing).resolves.toMatchObject({
      allowed: true,
      value: { globalPaused: true },
    });
    expect(wallet.prepareCount).toBe(1);
    expect(wallet.broadcastCount).toBe(1);
  });

  it('does not reconcile while the background worker owns the broadcast lifecycle', async () => {
    const wallet = new DeferredReceiptWallet();
    const setup = await createEngine({ wallet });
    const envelope = createEnvelope('active-worker-owns-recovery');

    await setup.engine.queueAction(envelope);
    await wallet.waitStarted;
    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({ status: 'confirming' });
    expect(wallet.receiptReads).toBe(0);

    wallet.release();
    await setup.engine.executeAction(envelope);
  });

  it('removes the exact envelope after completion and retains only a redacted result', async () => {
    const setup = await createEngine({});
    const envelope = resignEnvelope(
      createEnvelope('async-redacted-result'),
      { summary: 'Cancel using private amount 123456789.' },
    );

    await setup.engine.queueAction(envelope);
    await setup.engine.executeAction(envelope);
    const status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );

    expect(status).toMatchObject({
      status: 'completed',
      summary: 'ChainWhisper order update completed.',
      result: {
        action: 'order_update',
        status: 'completed',
      },
    });
    expect(
      await setup.vault.get(
        `operation:${envelope.operationId}:request`,
      ),
    ).toBeNull();
    expect(JSON.stringify(status)).not.toContain('123456789');
  });

  it('retains a decoded created-order identity through async cleanup', async () => {
    const setup = await createEngine({
      intentValidator: { validate: async () => undefined },
    });
    const { envelope, orderType } = createStandardOrderEnvelope(
      'async-created-order-result',
    );
    setup.wallet.receiptLogs = [tradeOpenedLog(42n)];

    await setup.engine.queueAction(envelope);
    await setup.engine.executeAction(envelope);
    const status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );

    expect(status).toMatchObject({
      status: 'completed',
      result: {
        action: 'create_trade',
        canonicalType: orderType,
        order: {
          handle: `cw_${CONTRACT.slice(2).toLowerCase()}_42`,
          status: 'open',
          shareableAppLink:
            'https://chainwhisper.chat/otc/order/link/VgAq',
        },
      },
    });
    await expect(
      setup.vault.get(`operation:${envelope.operationId}:request`),
    ).resolves.toBeNull();
  });

  it('keeps a completed create envelope until its exact order identity is reconciled', async () => {
    const setup = await createEngine({
      intentValidator: { validate: async () => undefined },
    });
    const { envelope } = createStandardOrderEnvelope(
      'delayed-created-order-result',
    );

    await setup.engine.queueAction(envelope);
    let status = await setup.engine.getOperationStatus(
      envelope.operationId,
    );
    for (
      let attempt = 0;
      status?.status !== 'uncertain' && attempt < 50;
      attempt += 1
    ) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      status = await setup.engine.getOperationStatus(
        envelope.operationId,
      );
    }

    expect(status).toMatchObject({
      status: 'uncertain',
      errorCode: 'ORDER_RESULT_RECONCILIATION_REQUIRED',
      userActionRequired: false,
      nextPollingIntervalMs: 1_000,
    });
    await expect(
      setup.vault.get(`operation:${envelope.operationId}:request`),
    ).resolves.not.toBeNull();
    await expect(setup.engine.listPendingOperationIds()).resolves.toContain(
      envelope.operationId,
    );

    setup.wallet.receiptLogs = [tradeOpenedLog(84n)];
    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({
      status: 'completed',
      result: {
        order: {
          handle: `cw_${CONTRACT.slice(2).toLowerCase()}_84`,
          status: 'open',
        },
      },
    });
    await expect(
      setup.vault.get(`operation:${envelope.operationId}:request`),
    ).resolves.toBeNull();
    await expect(
      setup.engine.listPendingOperationIds(),
    ).resolves.not.toContain(envelope.operationId);
  });

  it('backfills a created-order identity from a successful recovered receipt', async () => {
    const setup = await createEngine({
      intentValidator: { validate: async () => undefined },
    });
    const { envelope } = createStandardOrderEnvelope(
      'recovered-created-order-result',
    );
    const transactionHash = `0x${'99'.repeat(32)}` as HexString;
    setup.wallet.transactions.set(transactionHash, {
      hash: transactionHash,
      nonce: 4,
    });
    setup.wallet.receiptLogs = [tradeOpenedLog(73n)];
    await setup.vault.put(
      `operation:${envelope.operationId}:request`,
      JSON.stringify({ version: 1, envelope }),
      { kind: 'recovery-note' },
    );
    await setup.journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );
    await setup.journal.recordPreparedTransaction(
      envelope.operationId,
      4,
      transactionHash,
      0,
    );
    await setup.journal.recordReceipt(envelope.operationId, {
      transactionHash,
      status: 'success',
      blockNumber: 20,
    });
    await setup.journal.updateStage(
      envelope.operationId,
      'completed',
      1,
    );

    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({
      status: 'completed',
      result: {
        action: 'create_trade',
        order: {
          handle: `cw_${CONTRACT.slice(2).toLowerCase()}_73`,
          status: 'open',
          shareableAppLink:
            'https://chainwhisper.chat/otc/order/link/VgBJ',
        },
      },
    });
    await expect(
      setup.journal.get(envelope.operationId),
    ).resolves.toMatchObject({
      semanticResult: {
        order: {
          handle: `cw_${CONTRACT.slice(2).toLowerCase()}_73`,
        },
      },
    });
  });

  it('requires a fresh envelope after local private setup completes', async () => {
    let reserveCalls = 0;
    const autonomy = {
      reserve: async () => {
        reserveCalls += 1;
        return {
          allowed: false as const,
          denial: {
            code: 'POLICY_NOT_FOUND' as const,
            message: 'The test policy is unavailable.',
          },
        };
      },
    } as unknown as AutonomyPolicyManager;
    const setup = await createEngine({ autonomy });
    const baseEnvelope = createEnvelope('private-setup-reprepare');
    const envelope = resignEnvelope(baseEnvelope, {
      intent: {
        ...baseEnvelope.intent,
        sellAsset: {
          kind: 'private-erc20',
          reference: 'p.WISP',
          symbol: 'p.WISP',
          decimals: 6,
        },
      },
    });
    await setup.journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );
    await setup.vault.put(
      `operation:${envelope.operationId}:request`,
      JSON.stringify({
        version: 1,
        envelope,
        policyId: 'policy-1',
      }),
      { kind: 'recovery-note' },
    );
    await setup.journal.recordError(
      envelope.operationId,
      'PRIVATE_TOKEN_SETUP_REQUIRED',
      true,
    );

    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({
      status: 'needs_setup',
      userActionRequired: true,
      setupRequirement: {
        kind: 'private-token-setup',
        assets: ['p.WISP'],
      },
    });
    await setup.engine.markSetupCompleted();
    await expect(
      setup.engine.getOperationStatus(envelope.operationId),
    ).resolves.toMatchObject({
      status: 'needs_reprepare',
      errorCode: 'OPERATION_REPREPARE_REQUIRED',
    });

    await setup.engine.restorePendingOperations();
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
    expect(reserveCalls).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);

    await expect(
      setup.engine.queueAction(envelope, 'policy-1'),
    ).resolves.toMatchObject({
      status: 'needs_reprepare',
      errorCode: 'OPERATION_REPREPARE_REQUIRED',
    });
    expect(reserveCalls).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('restores a persisted nonterminal envelope after signer restart', async () => {
    const setup = await createEngine({
      elicitor: new TestElicitor(false),
    });
    const envelope = createEnvelope('restart-restoration');
    await expect(setup.engine.queueAction(envelope)).resolves.toMatchObject({
      status: 'needs_confirmation',
      errorCode: 'CONTROL_PANEL_OPEN_REQUIRED',
    });
    const restored = new SignerEngine({
      verifier: new ActionEnvelopeVerifier(
        createConfig(setup.stateDirectory),
        setup.runtime,
        () => NOW,
      ),
      wallet: setup.wallet,
      materializer: new PassthroughPrivateInputMaterializer(),
      confirmation: new ConfirmationGate(new TestElicitor(), 5_000),
      simulator: setup.simulator,
      intentValidator: new StrictMaterializedIntentValidator(),
      journal: setup.journal,
      vault: setup.vault,
    });

    await restored.restorePendingOperations();
    let status = await restored.getOperationStatus(envelope.operationId);
    for (let attempt = 0; status?.status !== 'completed' && attempt < 50; attempt += 1) {
      await new Promise<void>((resolve) => setTimeout(resolve, 5));
      status = await restored.getOperationStatus(envelope.operationId);
    }
    expect(status).toMatchObject({
      status: 'completed',
      result: { action: 'order_update' },
    });
  });

  it('reuses the complete autonomy exposure when resuming a later step after restart', async () => {
    const wallet = new TestWallet();
    wallet.receiptStatus = 'pending';
    let boundExposure: string | null = null;
    const reservation = {
      version: 'cw.autonomy-reservation/1',
      id: 'reservation-1',
      policyId: 'policy-1',
      policyTermsDigest: REGISTRY_HASH,
      operationHash: REGISTRY_HASH,
      exposureDigest: REGISTRY_HASH,
      authorizationBinding: REGISTRY_HASH,
      exposure: null,
      state: 'reserved',
      createdAt: NOW.toISOString(),
      updatedAt: NOW.toISOString(),
      signedTransactionHashes: [],
    } as unknown as AutonomyReservationV1;
    const autonomy = {
      reserve: async (
        _policyId: string,
        exposure: PolicyExposureV1,
      ) => {
        const serialized = JSON.stringify(exposure);
        if (boundExposure === null) boundExposure = serialized;
        if (boundExposure !== serialized) {
          return {
            allowed: false as const,
            denial: {
              code: 'OPERATION_BINDING_MISMATCH' as const,
              message: 'The operation exposure changed during restart.',
              policyId: 'policy-1',
            },
          };
        }
        return {
          allowed: true as const,
          value: { ...reservation, exposure },
        };
      },
      authorizeReservedWrite: async () => ({
        allowed: true as const,
        value: reservation,
      }),
      markSigned: async (
        _id: string,
        transactionHash: HexString,
      ) => ({
        allowed: true as const,
        value: {
          ...reservation,
          state: 'signed' as const,
          signedTransactionHashes: [transactionHash],
        },
      }),
      markPending: async () => ({
        allowed: true as const,
        value: { ...reservation, state: 'pending' as const },
      }),
      markUncertain: async () => ({
        allowed: true as const,
        value: { ...reservation, state: 'uncertain' as const },
      }),
      markSettled: async () => ({
        allowed: true as const,
        value: { ...reservation, state: 'settled' as const },
      }),
      releaseBeforeSigning: async () => ({
        allowed: true as const,
        value: { ...reservation, state: 'released' as const },
      }),
    } as unknown as AutonomyPolicyManager;
    const setup = await createEngine({ wallet, autonomy });
    const base = createEnvelope('autonomy-restart-complete-exposure');
    const envelope = resignEnvelope(base, {
      steps: [
        base.steps[0]!,
        {
          ...base.steps[0]!,
          id: 'cancel-after-restart',
          summary: 'Complete the second bound transaction.',
        },
      ],
      gasCap: '200000',
    });

    await setup.engine.queueAction(envelope, 'policy-1');
    await setup.engine.executeAction(envelope, 'policy-1');
    expect(wallet.broadcastCount).toBe(1);
    expect(await setup.journal.get(envelope.operationId)).toMatchObject({
      stage: 'broadcast',
      nextStepIndex: 0,
    });

    wallet.receiptStatus = 'success';
    wallet.pendingNonce = 5;
    const restored = new SignerEngine({
      verifier: new ActionEnvelopeVerifier(
        createConfig(setup.stateDirectory),
        setup.runtime,
        () => NOW,
      ),
      wallet,
      materializer: new PassthroughPrivateInputMaterializer(),
      confirmation: new ConfirmationGate(new TestElicitor(), 5_000),
      simulator: setup.simulator,
      intentValidator: new StrictMaterializedIntentValidator(),
      journal: setup.journal,
      vault: setup.vault,
      autonomy,
    });

    await restored.restorePendingOperations();
    await restored.executeAction(envelope, 'policy-1');
    const status = await restored.getOperationStatus(envelope.operationId);
    expect(status).toMatchObject({ status: 'completed' });
    expect(wallet.prepareCount).toBe(2);
    expect(wallet.broadcastCount).toBe(2);
  });

  it('enforces each persisted autonomy fee ceiling when a later step resumes', async () => {
    const wallet = new TestWallet();
    wallet.receiptStatus = 'pending';
    const simulator = new SequencedFeeSimulator([
      '10',
      '20',
      '10',
      '21',
    ]);
    const { manager: autonomy } = createTestAutonomy();
    const setup = await createEngine({ wallet, simulator, autonomy });
    const base = createEnvelope('autonomy-restart-fee-ceiling');
    const envelope = resignEnvelope(base, {
      steps: [
        base.steps[0]!,
        {
          ...base.steps[0]!,
          id: 'second-fee-bound-step',
          summary: 'Complete the second fee-bound transaction.',
        },
      ],
      gasCap: '200000',
    });

    await setup.engine.queueAction(envelope, 'policy-1');
    await setup.engine.executeAction(envelope, 'policy-1');
    expect(wallet.broadcastCount).toBe(1);

    const stored = JSON.parse(
      (await setup.vault.get(
        `operation:${envelope.operationId}:request`,
      ))!,
    ) as { policyStepFeeCeilings?: string[] };
    expect(stored.policyStepFeeCeilings).toEqual(['10', '20']);

    wallet.receiptStatus = 'success';
    const restored = new SignerEngine({
      verifier: new ActionEnvelopeVerifier(
        createConfig(setup.stateDirectory),
        setup.runtime,
        () => NOW,
      ),
      wallet,
      materializer: new PassthroughPrivateInputMaterializer(),
      confirmation: new ConfirmationGate(new TestElicitor(), 5_000),
      simulator,
      intentValidator: new StrictMaterializedIntentValidator(),
      journal: setup.journal,
      vault: setup.vault,
      autonomy,
    });

    await restored.restorePendingOperations();
    await restored.executeAction(envelope, 'policy-1');
    expect(
      (await setup.journal.get(envelope.operationId))?.errorCodes.at(-1),
    ).toBe('FEE_CHANGED');
    expect(wallet.prepareCount).toBe(1);
    expect(wallet.broadcastCount).toBe(1);
  });

  it('re-materializes completed steps before resuming an autonomous action', async () => {
    const wallet = new TestWallet();
    wallet.receiptStatus = 'pending';
    const { manager: autonomy } = createTestAutonomy();
    const setup = await createEngine({ wallet, autonomy });
    const base = createEnvelope('autonomy-restart-step-binding');
    const envelope = resignEnvelope(base, {
      steps: [
        base.steps[0]!,
        {
          ...base.steps[0]!,
          id: 'second-digest-bound-step',
          summary: 'Complete the second digest-bound transaction.',
        },
      ],
      gasCap: '200000',
    });

    await setup.engine.queueAction(envelope, 'policy-1');
    await expect
      .poll(() => wallet.broadcastCount, { timeout: 5_000 })
      .toBe(1);
    await expect
      .poll(
        async () =>
          (await setup.journal.get(envelope.operationId))?.stage,
        { timeout: 5_000 },
      )
      .toBe('broadcast');

    wallet.receiptStatus = 'success';
    const restored = new SignerEngine({
      verifier: new ActionEnvelopeVerifier(
        createConfig(setup.stateDirectory),
        setup.runtime,
        () => NOW,
      ),
      wallet,
      materializer: {
        materializeStep: async (
          actionEnvelope: SignedActionEnvelopeV1,
          stepIndex: number,
        ): Promise<MaterializedActionStep> => {
          const step = actionEnvelope.steps[stepIndex]!;
          return {
            ...step,
            data:
              stepIndex === 0
                ? (`${step.data.slice(0, -1)}${
                    step.data.endsWith('0') ? '1' : '0'
                  }` as HexString)
                : step.data,
          };
        },
      },
      confirmation: new ConfirmationGate(new TestElicitor(), 5_000),
      simulator: setup.simulator,
      intentValidator: new StrictMaterializedIntentValidator(),
      journal: setup.journal,
      vault: setup.vault,
      autonomy,
    });

    await restored.restorePendingOperations();
    await expect
      .poll(
        async () =>
          (await setup.journal.get(envelope.operationId))?.errorCodes.at(
            -1,
          ),
        { timeout: 5_000 },
      )
      .toBe('OPERATION_REPREPARE_REQUIRED');
    expect(wallet.prepareCount).toBe(1);
    expect(wallet.broadcastCount).toBe(1);
  });

  it('keeps a pending receipt in processing and does not resubmit it', async () => {
    const wallet = new TestWallet();
    wallet.receiptStatus = 'pending';
    const setup = await createEngine({ wallet });
    const envelope = createEnvelope('pending-operation');
    expect(await setup.engine.executeAction(envelope)).toMatchObject({
      status: 'processing',
    });
    expect(await setup.engine.executeAction(envelope)).toMatchObject({
      status: 'processing',
    });
    expect(wallet.prepareCount).toBe(1);
    expect(wallet.broadcastCount).toBe(1);
  });

  it('keeps a locally prepared hash in processing while RPC visibility is uncertain', async () => {
    const setup = await createEngine({});
    const operationId = 'uncertain-prepared-hash';
    const transactionHash = `0x${'77'.repeat(32)}` as HexString;
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.journal.reserveNonce(operationId, 9, 0);
    await setup.journal.recordPreparedTransaction(
      operationId,
      9,
      transactionHash,
      0,
    );

    await expect(
      setup.engine.recoverOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({
      status: 'processing',
      transactionHashes: [transactionHash],
    });
    await expect(
      setup.engine.recoverOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({ status: 'processing' });
    expect(await setup.journal.get(operationId)).toMatchObject({
      stage: 'prepared-broadcast',
      nextStepIndex: 0,
    });
  });

  it('retries a nonce-only state without adopting another wallet transaction', async () => {
    const setup = await createEngine({});
    const operationId = 'uncertain-reserved-nonce';
    const unrelatedHash = `0x${'99'.repeat(32)}` as HexString;
    setup.wallet.transactions.set(unrelatedHash, {
      hash: unrelatedHash,
      nonce: 9,
    });
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.journal.reserveNonce(operationId, 9, 0);

    await expect(
      setup.engine.recoverOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({
      status: 'retryable',
      transactionHashes: [],
    });
    expect(await setup.journal.get(operationId)).toMatchObject({
      stage: 'validated',
      nextStepIndex: 0,
      transactionHashes: [],
    });
  });

  it('returns a nonce-only preparation failure to a safely retryable stage', async () => {
    const wallet = new TestWallet();
    wallet.throwPrepareOnce = true;
    const setup = await createEngine({ wallet });
    const envelope = createEnvelope('retry-preparation-failure');

    await expect(setup.engine.executeAction(envelope)).resolves.toMatchObject({
      status: 'retryable',
      transactionHashes: [],
    });
    expect(await setup.journal.get(envelope.operationId)).toMatchObject({
      stage: 'validated',
      nonces: [],
      transactionHashes: [],
    });

    await expect(setup.engine.executeAction(envelope)).resolves.toMatchObject({
      status: 'completed',
    });
    expect(wallet.prepareCount).toBe(2);
    expect(wallet.broadcastCount).toBe(1);
    expect(setup.elicitor.requests).toHaveLength(2);
  });

  it('advances a prepared step when its receipt proves a successful broadcast', async () => {
    const setup = await createEngine({});
    const operationId = 'successful-prepared-write';
    const transactionHash = `0x${'88'.repeat(32)}` as HexString;
    setup.wallet.transactions.set(transactionHash, {
      hash: transactionHash,
      nonce: 9,
    });
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.journal.reserveNonce(operationId, 9, 0);
    await setup.journal.recordPreparedTransaction(
      operationId,
      9,
      transactionHash,
      0,
    );

    await expect(
      setup.engine.recoverOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({
      status: 'retryable',
      transactionHashes: [transactionHash],
    });
    expect(await setup.journal.get(operationId)).toMatchObject({
      stage: 'validated',
      nextStepIndex: 1,
      receipts: [
        {
          transactionHash,
          status: 'success',
          blockNumber: 20,
        },
      ],
    });
  });

  it('advances from the latest successful retry without being blocked by an earlier revert', async () => {
    const setup = await createEngine({});
    const operationId = 'successful-retry-after-revert';
    const revertedHash = `0x${'81'.repeat(32)}` as HexString;
    const successfulHash = `0x${'82'.repeat(32)}` as HexString;
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.journal.recordPreparedTransaction(
      operationId,
      9,
      revertedHash,
      0,
    );
    await setup.journal.recordReceipt(operationId, {
      transactionHash: revertedHash,
      status: 'reverted',
      blockNumber: 20,
    });
    await setup.journal.recordPreparedTransaction(
      operationId,
      10,
      successfulHash,
      0,
    );
    await setup.journal.recordReceipt(operationId, {
      transactionHash: successfulHash,
      status: 'success',
      blockNumber: 21,
    });

    await expect(
      setup.engine.recoverOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({
      status: 'retryable',
      transactionHashes: [revertedHash, successfulHash],
    });
    expect(await setup.journal.get(operationId)).toMatchObject({
      stage: 'validated',
      nextStepIndex: 1,
    });
  });

  it('recovers provider acceptance when the broadcast response is lost', async () => {
    const wallet = new TestWallet();
    wallet.throwAfterAccept = true;
    const setup = await createEngine({ wallet });
    const result = await setup.engine.executeAction(
      createEnvelope('lost-response'),
    );
    expect(result.status).toBe('completed');
    expect(wallet.broadcastCount).toBe(1);
    expect((await setup.journal.get('lost-response'))?.stage).toBe(
      'completed',
    );
  });

  it('does not resubmit after a lost response when the prepared hash is not yet visible', async () => {
    const wallet = new TestWallet();
    wallet.throwAfterAccept = true;
    wallet.hideTransactions = true;
    const setup = await createEngine({ wallet });
    const envelope = createEnvelope('lost-response-not-visible');

    await expect(setup.engine.executeAction(envelope)).resolves.toMatchObject({
      status: 'processing',
    });
    await expect(setup.engine.executeAction(envelope)).resolves.toMatchObject({
      status: 'processing',
    });
    expect(wallet.prepareCount).toBe(1);
    expect(wallet.broadcastCount).toBe(1);
    expect(await setup.journal.get(envelope.operationId)).toMatchObject({
      stage: 'broadcast',
      transactionHashes: [expect.any(String)],
    });
  });

  it('rejects a changed fee recipient and non-manifest selector even when re-signed', async () => {
    const setup = await createEngine({});
    const original = createEnvelope('tamper');
    const changedFee = resignEnvelope(original, {
        operationId: 'changed-fee',
        fee: {
          ...original.fee,
          recipient:
            '0x9999999999999999999999999999999999999999',
        },
      });
    await expect(setup.engine.executeAction(changedFee)).rejects.toMatchObject({
      code: 'FEE_CHANGED',
    });

    const chargedLifecycleFee = resignEnvelope(original, {
      operationId: 'charged-lifecycle-fee',
      exactNativeValue: '7',
      fee: {
        ...original.fee,
        amount: '7',
      },
      steps: [
        {
          ...original.steps[0]!,
          value: '7',
        },
      ],
    });
    await expect(
      setup.engine.executeAction(chargedLifecycleFee),
    ).rejects.toMatchObject({ code: 'FEE_CHANGED' });

    const changedSelector = resignEnvelope(original, {
        operationId: 'changed-selector',
        steps: [
          {
            ...original.steps[0]!,
            data: '0xdeadbeef',
            callTemplate: {
              functionSignature: 'cancelTrade(uint256)',
              arguments: ['5'],
            },
          },
        ],
      });
    await expect(
      setup.engine.executeAction(changedSelector),
    ).rejects.toMatchObject({ code: 'REGISTRY_CHANGED' });
  });

  it('encrypts vault contents and keeps the journal free of prompts and secrets', async () => {
    const setup = await createEngine({});
    const secret = `0x${'ab'.repeat(32)}`;
    await setup.vault.put('private:value', secret, {
      kind: 'private-uint256',
    });
    await setup.engine.executeAction(createEnvelope('journal-safety'));
    const vaultFile = await readFile(setup.vault.path, 'utf8');
    const journalFile = await readFile(setup.journal.path, 'utf8');
    expect(vaultFile).not.toContain(secret);
    expect(journalFile).not.toContain(secret);
    expect(journalFile).not.toContain('Cancel ChainWhisper order');
    expect(await setup.vault.get('private:value')).toBe(secret);
  });

  it('creates shared file pairing without serializing credentials', async () => {
    const stateDirectory = await mkdtemp(join(tmpdir(), 'cw-config-'));
    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_PRIVATE_KEY: `0x${'11'.repeat(32)}`,
      CHAINWHISPER_SIGNER_AES_KEY: `0x${'22'.repeat(32)}`,
      CHAINWHISPER_SIGNER_VAULT_PASSPHRASE:
        'a-long-test-vault-passphrase',
      CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL: 'local-web',
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
    });
    const serialized = JSON.stringify(config);
    expect(serialized).toContain('[redacted]');
    expect(serialized).not.toContain('1111111111111111');
    expect(serialized).not.toContain('2222222222222222');
    expect(config.confirmationChannel).toBe('local-web');
    expect(
      (await readFile(join(stateDirectory, 'pairing.key'), 'utf8')).trim(),
    ).toHaveLength(43);
  });

  it('ignores generic credential variables and enters wallet setup mode', async () => {
    const stateDirectory = await mkdtemp(join(tmpdir(), 'cw-config-generic-'));
    const config = await loadSignerConfig({
      PRIVATE_KEY: `0x${'11'.repeat(32)}`,
      AES_KEY: `0x${'22'.repeat(32)}`,
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
    });
    expect(config.walletConfigured).toBe(false);
    expect(config.configurationDiagnostic).toBe('wallet-setup-required');
  });

  it('rejects private artifact recipes before confirmation or signing', async () => {
    const setup = await createEngine({});
    const original = createEnvelope('private-artifact-plan');
    const privateEnvelope = resignEnvelope(original, {
      privateArtifacts: [
        {
          id: 'private-artifact',
          recipe: 'private-fill-v1',
          bindToStepId: 'cancel',
          commitment: `0x${'55'.repeat(32)}`,
          values: [
            {
              id: 'private-value',
              kind: 'uint256',
              source: 'signer-elicitation',
              commitment: `0x${'66'.repeat(32)}`,
            },
          ],
          outputs: [
            {
              kind: 'itUint256',
              valueId: 'private-value',
              jsonPointer: '/arguments/1',
            },
          ],
        },
      ],
    });
    await expect(
      setup.engine.executeAction(privateEnvelope),
    ).rejects.toMatchObject({ code: 'PRIVATE_INPUT_UNAVAILABLE' });
    expect(setup.elicitor.requests).toHaveLength(0);
    expect(setup.wallet.prepareCount).toBe(0);
  });

  it('rejects reserved operation ids and cannot discard an uncertain prepared write', async () => {
    const setup = await createEngine({});
    await expect(
      setup.journal.begin('__proto__', REGISTRY_HASH),
    ).rejects.toMatchObject({ code: 'ENVELOPE_INVALID' });
    await expect(
      setup.journal.begin('constructor', REGISTRY_HASH),
    ).rejects.toMatchObject({ code: 'ENVELOPE_INVALID' });

    const operationId = 'uncertain-prepared-write';
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.journal.reserveNonce(operationId, 9, 0);
    await setup.journal.recordPreparedTransaction(
      operationId,
      9,
      `0x${'77'.repeat(32)}`,
      0,
    );
    await expect(
      setup.engine.discardOperation(operationId, REGISTRY_HASH),
    ).rejects.toMatchObject({ code: 'OPERATION_IN_PROGRESS' });
  });

  it('preserves recovery state when exact operation discard is declined', async () => {
    const elicitor = new TestElicitor(true, 'declined');
    const setup = await createEngine({ elicitor });
    const operationId = 'declined-local-discard';
    const secretReference = `${REGISTRY_HASH}:recovery-secret`;
    const requestReference = `operation:${operationId}:request`;
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.vault.put(secretReference, 'local-recovery-value');
    await setup.vault.put(requestReference, 'durable-operation-request');

    await expect(
      setup.engine.discardOperation(operationId, REGISTRY_HASH),
    ).rejects.toMatchObject({ code: 'CONFIRMATION_DECLINED' });
    expect(elicitor.requests).toHaveLength(1);
    expect(elicitor.requests[0]).toMatchObject({
      operationId,
      operationHash: REGISTRY_HASH,
      action: 'discard_operation',
      actionButtonLabel: 'Confirm discard and delete local data',
      authorizationScope: 'complete-logical-action',
    });
    expect((await setup.journal.get(operationId))?.stage).toBe(
      'validated',
    );
    expect(await setup.vault.get(secretReference)).toBe(
      'local-recovery-value',
    );
    expect(await setup.vault.get(requestReference)).toBe(
      'durable-operation-request',
    );
  });

  it('discards only the locally confirmed exact operation and its secret prefix', async () => {
    const setup = await createEngine({});
    const operationId = 'confirmed-local-discard';
    const secretReference = `${REGISTRY_HASH}:recovery-secret`;
    const requestReference = `operation:${operationId}:request`;
    const resultReference = `operation:${operationId}:result`;
    const unrelatedReference = `0x${'55'.repeat(32)}:recovery-secret`;
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.vault.put(secretReference, 'discard-this-value');
    await setup.vault.put(requestReference, 'discard-this-request');
    await setup.vault.put(resultReference, 'discard-this-result');
    await setup.vault.put(unrelatedReference, 'preserve-this-value');

    await expect(
      setup.engine.discardOperation(operationId, REGISTRY_HASH),
    ).resolves.toMatchObject({
      operationId,
      operationHash: REGISTRY_HASH,
      status: 'discarded',
    });
    expect((await setup.journal.get(operationId))?.stage).toBe(
      'discarded',
    );
    expect(await setup.vault.get(secretReference)).toBeNull();
    expect(await setup.vault.get(requestReference)).toBeNull();
    expect(await setup.vault.get(resultReference)).toBeNull();
    expect(await setup.vault.get(unrelatedReference)).toBe(
      'preserve-this-value',
    );
  });

  it('does not start an operation while its local discard confirmation is open', async () => {
    const elicitor = new DeferredTestElicitor();
    const setup = await createEngine({ elicitor });
    const envelope = createEnvelope('discard-blocks-background-start');
    await setup.journal.begin(
      envelope.operationId,
      envelope.operationHash,
    );

    const discarding = setup.engine.discardOperation(
      envelope.operationId,
      envelope.operationHash,
    );
    await expect
      .poll(() => elicitor.requests.length)
      .toBe(1);
    await expect(
      setup.engine.queueAction(envelope),
    ).rejects.toMatchObject({ code: 'OPERATION_IN_PROGRESS' });
    expect(setup.wallet.prepareCount).toBe(0);
    expect(setup.wallet.broadcastCount).toBe(0);

    elicitor.release?.();
    await expect(discarding).resolves.toMatchObject({
      status: 'discarded',
    });
  });

  it('rejects discard while the same operation has an active background worker', async () => {
    const elicitor = new DeferredTestElicitor();
    const setup = await createEngine({ elicitor });
    const envelope = createEnvelope('active-worker-blocks-discard');

    await setup.engine.queueAction(envelope);
    await expect
      .poll(() => elicitor.requests.length)
      .toBe(1);
    await expect(
      setup.engine.discardOperation(
        envelope.operationId,
        envelope.operationHash,
      ),
    ).rejects.toMatchObject({ code: 'OPERATION_IN_PROGRESS' });

    elicitor.release?.();
  });
});
