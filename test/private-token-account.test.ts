import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';
import {
  encodeFunctionResult,
  parseAbi,
  toFunctionSelector,
} from 'viem';

import {
  loadRuntimeManifest,
  type JsonRpcReader,
} from '../src/shared/index.js';
import {
  ConfirmationGate,
  NonceQueue,
  OperationJournal,
  PrivateTokenAccountService,
  type Address,
  type ConfirmationRequest,
  type FormElicitor,
  type HexString,
  type TransactionReceipt,
  type TransactionRequest,
  type TransactionSimulator,
  type WalletTransport,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000' as Address;
const TRANSACTION_HASH = `0x${'77'.repeat(32)}` as HexString;
const ACCOUNT_ABI = parseAbi([
  'function accountEncryptionAddress(address account) view returns (address)',
]);

class AcceptedElicitor implements FormElicitor {
  readonly requests: ConfirmationRequest[] = [];

  isSupported(): boolean {
    return true;
  }

  async requestConfirmation(
    request: ConfirmationRequest,
  ): Promise<{ outcome: 'accepted' }> {
    this.requests.push(request);
    return { outcome: 'accepted' };
  }
}

class SetupWallet implements WalletTransport {
  readonly visibleAfterBroadcast: boolean;
  ready = false;
  accepted = false;
  prepareCount = 0;
  broadcastCount = 0;
  waitCount = 0;
  findByNonceCount = 0;
  failPrepareOnce = false;
  markReadyOnReceipt = true;

  constructor(visibleAfterBroadcast: boolean) {
    this.visibleAfterBroadcast = visibleAfterBroadcast;
  }

  async getAddress(): Promise<Address> {
    return WALLET;
  }

  async getChainId(): Promise<number> {
    return 2_632_500;
  }

  async getPendingNonce(): Promise<number> {
    return 4;
  }

  async prepareTransaction(
    _request: TransactionRequest,
  ): Promise<{ hash: HexString; signedTransaction: HexString }> {
    this.prepareCount += 1;
    if (this.failPrepareOnce) {
      this.failPrepareOnce = false;
      throw new Error('private-token preparation failed');
    }
    return {
      hash: TRANSACTION_HASH,
      signedTransaction: `0x${'88'.repeat(32)}`,
    };
  }

  async broadcastTransaction(
    _signedTransaction: HexString,
  ): Promise<{ hash: HexString }> {
    this.broadcastCount += 1;
    this.accepted = true;
    throw new Error('provider response lost');
  }

  async getTransaction(
    hash: HexString,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    return this.accepted && this.visibleAfterBroadcast
      ? { hash, nonce: 4 }
      : null;
  }

  async findTransactionByNonce(
    nonce: number,
  ): Promise<{ hash: HexString; nonce: number } | null> {
    this.findByNonceCount += 1;
    return this.accepted && this.visibleAfterBroadcast
      ? { hash: TRANSACTION_HASH, nonce }
      : {
          hash: `0x${'99'.repeat(32)}` as HexString,
          nonce,
        };
  }

  async getTransactionReceipt(
    hash: HexString,
  ): Promise<TransactionReceipt | null> {
    return this.ready
      ? {
          transactionHash: hash,
          status: 'success',
          blockNumber: 20,
        }
      : null;
  }

  async waitForTransaction(
    hash: HexString,
  ): Promise<TransactionReceipt> {
    this.waitCount += 1;
    if (this.markReadyOnReceipt) this.ready = true;
    return {
      transactionHash: hash,
      status: 'success',
      blockNumber: 20,
    };
  }
}

class SuccessfulSimulator implements TransactionSimulator {
  async simulate(): Promise<{ ok: true }> {
    return { ok: true };
  }
}

const createSetup = async (
  visibleAfterBroadcast: boolean,
  options: {
    walletCode?: string;
    initialMapping?: Address;
  } = {},
) => {
  const manifest = await loadRuntimeManifest();
  const privateToken = manifest.tokens.find(
    (token) => token.symbol === 'p.WISP',
  );
  if (!privateToken?.address) throw new Error('missing p.WISP manifest token');
  const operationId = `private-token-${privateToken.address
    .toLowerCase()
    .slice(2, 18)}`;
  const wallet = new SetupWallet(visibleAfterBroadcast);
  const elicitor = new AcceptedElicitor();
  let attestationCount = 0;
  let ethGetCodeCount = 0;
  const rpc: JsonRpcReader = {
    request: async <T>(
      method: string,
      params: unknown[],
    ): Promise<T> => {
      if (method === 'eth_getCode') {
        ethGetCodeCount += 1;
        expect(params).toEqual([WALLET, 'latest']);
        return (options.walletCode ?? '0x6000') as T;
      }
      expect(method).toBe('eth_call');
      const data = (params[0] as { data: HexString }).data;
      expect(data.slice(0, 10).toLowerCase()).toBe(
        toFunctionSelector(
          'accountEncryptionAddress(address)',
        ).toLowerCase(),
      );
      return encodeFunctionResult({
        abi: ACCOUNT_ABI,
        functionName: 'accountEncryptionAddress',
        result:
          wallet.ready
            ? WALLET
            : (options.initialMapping ?? ZERO_ADDRESS),
      }) as T;
    },
  };
  const stateDirectory = await mkdtemp(
    join(tmpdir(), 'cw-private-token-account-'),
  );
  const journal = new OperationJournal(stateDirectory);
  const service = new PrivateTokenAccountService({
    manifest,
    rpc,
    wallet,
    cotiWallet: {
      getUserOnboardInfo: () => ({ aesKey: '55'.repeat(16) }),
    } as never,
    confirmation: new ConfirmationGate(elicitor, 5_000),
    simulator: new SuccessfulSimulator(),
    nonceQueue: new NonceQueue(() => wallet.getPendingNonce()),
    journal,
    assertRuntimeAttested: async () => {
      attestationCount += 1;
    },
  });
  return {
    attestationCount: () => attestationCount,
    elicitor,
    ethGetCodeCount: () => ethGetCodeCount,
    journal,
    operationId,
    service,
    wallet,
  };
};

describe('private-token account setup recovery', () => {
  it('treats a zero owner mapping as ready for an EOA and skips setup', async () => {
    const setup = await createSetup(true, { walletCode: '0x' });

    await expect(setup.service.status('p.WISP')).resolves.toMatchObject({
      accountEncryptionAddress: ZERO_ADDRESS,
      ready: true,
      spenders: {
        standardEscrow: { ready: false },
        privateEscrow: { ready: false },
        directEscrow: { ready: false },
        recurringEscrow: { ready: false },
      },
    });
    await expect(setup.service.enable('p.WISP')).resolves.toMatchObject({
      accountEncryptionAddress: ZERO_ADDRESS,
      ready: true,
      transactionHash: null,
    });

    expect(setup.ethGetCodeCount()).toBe(2);
    expect(setup.attestationCount()).toBe(0);
    expect(setup.wallet.prepareCount).toBe(0);
    expect(setup.wallet.broadcastCount).toBe(0);
    expect(setup.elicitor.requests).toHaveLength(0);
  });

  it('requires setup for a code-bearing wallet with a zero mapping', async () => {
    const setup = await createSetup(true, {
      walletCode: '0x6001600055',
    });

    await expect(setup.service.status('p.WISP')).resolves.toMatchObject({
      accountEncryptionAddress: ZERO_ADDRESS,
      ready: false,
    });
    expect(setup.ethGetCodeCount()).toBe(1);
  });

  it('requires setup for a foreign mapping without classifying the wallet', async () => {
    const foreign =
      '0x2222222222222222222222222222222222222222' as Address;
    const setup = await createSetup(true, {
      walletCode: '0x',
      initialMapping: foreign,
    });

    await expect(setup.service.status('p.WISP')).resolves.toMatchObject({
      accountEncryptionAddress: foreign,
      ready: false,
    });
    expect(setup.ethGetCodeCount()).toBe(0);
  });

  it('reconciles a lost broadcast response against the locally prepared hash', async () => {
    const setup = await createSetup(true);

    await expect(setup.service.enable('p.WISP')).resolves.toMatchObject({
      ready: true,
      transactionHash: TRANSACTION_HASH,
    });
    expect(setup.wallet.prepareCount).toBe(1);
    expect(setup.wallet.broadcastCount).toBe(1);
    expect(setup.wallet.waitCount).toBe(1);
    expect(setup.elicitor.requests).toHaveLength(1);
  });

  it('keeps an unknown prepared hash in processing without confirming or broadcasting again', async () => {
    const setup = await createSetup(false);

    await expect(setup.service.enable('p.WISP')).resolves.toMatchObject({
      ready: false,
      transactionHash: TRANSACTION_HASH,
    });
    await expect(setup.service.enable('p.WISP')).resolves.toMatchObject({
      ready: false,
      transactionHash: TRANSACTION_HASH,
    });
    expect(setup.wallet.prepareCount).toBe(1);
    expect(setup.wallet.broadcastCount).toBe(1);
    expect(setup.wallet.waitCount).toBe(0);
    expect(setup.elicitor.requests).toHaveLength(1);
  });

  it('retries a pre-hash preparation failure without reserving a nonce', async () => {
    const setup = await createSetup(true);
    setup.wallet.failPrepareOnce = true;

    await expect(setup.service.enable('p.WISP')).rejects.toThrow(
      'private-token preparation failed',
    );
    expect(await setup.journal.get(setup.operationId)).toMatchObject({
      nonces: [],
      transactionHashes: [],
    });
    await expect(setup.service.enable('p.WISP')).resolves.toMatchObject({
      ready: true,
      transactionHash: TRANSACTION_HASH,
    });

    expect(setup.wallet.prepareCount).toBe(2);
    expect(setup.wallet.broadcastCount).toBe(1);
    expect(setup.wallet.findByNonceCount).toBe(0);
    expect(setup.elicitor.requests).toHaveLength(2);
  });

  it('does not complete setup until the token reports the expected encryption address', async () => {
    const setup = await createSetup(true);
    setup.wallet.markReadyOnReceipt = false;

    await expect(setup.service.enable('p.WISP')).rejects.toMatchObject({
      code: 'TRANSACTION_FAILED',
    });
    expect(
      await setup.journal.get(setup.operationId),
    ).not.toMatchObject({
      stage: 'completed',
    });
  });
});
