import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import { encodeFunctionData, parseAbi } from 'viem';

import {
  finalizeActionEnvelope,
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
  type ConfirmationRequest,
  type FormElicitor,
  type MaterializedIntentValidator,
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
    readonly outcome: 'accepted' | 'declined' = 'accepted',
  ) {}

  isSupported(): boolean {
    return this.supported;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<
    { outcome: 'accepted' } | { outcome: 'declined' }
  > {
    this.requests.push(request);
    return { outcome: this.outcome };
  }
}

class TestWallet implements WalletTransport {
  prepareCount = 0;
  broadcastCount = 0;
  pendingNonce = 4;
  receiptStatus: TransactionReceipt['status'] = 'success';
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
        }
      : null;
  }

  async waitForTransaction(hash: HexString): Promise<TransactionReceipt> {
    return {
      transactionHash: hash,
      status: this.receiptStatus,
      ...(this.receiptStatus === 'pending' ? {} : { blockNumber: 20 }),
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
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.vault.put(secretReference, 'local-recovery-value');

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
  });

  it('discards only the locally confirmed exact operation and its secret prefix', async () => {
    const setup = await createEngine({});
    const operationId = 'confirmed-local-discard';
    const secretReference = `${REGISTRY_HASH}:recovery-secret`;
    const unrelatedReference = `0x${'55'.repeat(32)}:recovery-secret`;
    await setup.journal.begin(operationId, REGISTRY_HASH);
    await setup.vault.put(secretReference, 'discard-this-value');
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
    expect(await setup.vault.get(unrelatedReference)).toBe(
      'preserve-this-value',
    );
  });
});
