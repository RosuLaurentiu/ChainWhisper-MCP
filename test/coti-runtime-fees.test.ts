import { describe, expect, it, vi } from 'vitest';

import {
  COTI_SIGNER_MAX_FEE_PER_GAS_WEI,
  CotiTransactionSimulator,
  CotiWalletTransport,
  assertCotiSignerTransactionFeePolicy,
  type Address,
  type TransactionRequest,
} from '../src/signer/index.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const CONTRACT =
  '0x2222222222222222222222222222222222222222' as Address;

const request = (): Omit<TransactionRequest, 'nonce'> => ({
  to: CONTRACT,
  data: '0x8269bcc3',
  value: 0n,
  gasLimit: 6_000_000n,
});

const setup = (fees: {
  gasPrice: bigint | null;
  maxFeePerGas: bigint | null;
  maxPriorityFeePerGas: bigint | null;
}) => {
  const provider = {
    estimateGas: vi.fn().mockResolvedValue(233_280n),
    getFeeData: vi.fn().mockResolvedValue(fees),
    getNetwork: vi.fn().mockResolvedValue({ chainId: 2_632_500n }),
  };
  const wallet = {
    getAddress: vi.fn().mockResolvedValue(WALLET),
    populateTransaction: vi.fn(
      async (transaction: Record<string, unknown>) => transaction,
    ),
    signTransaction: vi.fn().mockResolvedValue('0x1234'),
  };
  const transport = new CotiWalletTransport({
    wallet: wallet as never,
    provider: provider as never,
  });
  return {
    provider,
    wallet,
    transport,
    simulator: new CotiTransactionSimulator(transport),
  };
};

describe('COTI signer transaction fee binding', () => {
  it('fixes EIP-1559 fees during pre-confirmation simulation and signs those exact fields', async () => {
    const runtime = setup({
      gasPrice: 13_500_000_000n,
      maxFeePerGas: 14_000_000_000n,
      maxPriorityFeePerGas: 13_000_000_000n,
    });
    const transaction = request();

    await expect(
      runtime.simulator.simulate(transaction, WALLET),
    ).resolves.toMatchObject({
      ok: true,
      feeQuote: {
        model: 'eip1559',
        maximumNetworkFeeWei: '84000000000000000',
        maximumNetworkFeeCoti: '0.084',
        maximumFeePerGasWei: '14000000000',
        maximumPriorityFeePerGasWei: '13000000000',
      },
    });
    runtime.provider.getFeeData.mockResolvedValue({
      gasPrice: COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
      maxFeePerGas: COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
      maxPriorityFeePerGas: COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
    });

    await expect(
      runtime.simulator.simulate(transaction, WALLET),
    ).resolves.toMatchObject({
      ok: true,
      feeQuote: {
        maximumNetworkFeeCoti: '0.084',
      },
    });
    await expect(
      runtime.transport.prepareTransaction({
        ...transaction,
        nonce: 7,
      }),
    ).resolves.toMatchObject({
      signedTransaction: '0x1234',
      hash: expect.stringMatching(/^0x[0-9a-f]{64}$/u),
    });

    expect(runtime.provider.getFeeData).toHaveBeenCalledTimes(1);
    expect(runtime.wallet.populateTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 2,
        maxFeePerGas: 14_000_000_000n,
        maxPriorityFeePerGas: 13_000_000_000n,
      }),
    );
    expect(runtime.wallet.signTransaction).toHaveBeenCalledTimes(1);
  });

  it('fails closed instead of populating fees after confirmation', async () => {
    const runtime = setup({
      gasPrice: 13_500_000_000n,
      maxFeePerGas: 14_000_000_000n,
      maxPriorityFeePerGas: 13_000_000_000n,
    });

    await expect(
      runtime.transport.prepareTransaction({
        ...request(),
        nonce: 7,
      }),
    ).rejects.toMatchObject({
      code: 'FEE_CHANGED',
      message: expect.stringContaining(
        'not fixed before confirmation',
      ),
    });
    expect(runtime.wallet.populateTransaction).not.toHaveBeenCalled();
    expect(runtime.wallet.signTransaction).not.toHaveBeenCalled();
  });

  it('rejects an RPC quote above the signer fee ceiling before confirmation', async () => {
    const runtime = setup({
      gasPrice: COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
      maxFeePerGas: COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
      maxPriorityFeePerGas: 1n,
    });
    const transaction = request();

    await expect(
      runtime.simulator.simulate(transaction, WALLET),
    ).resolves.toEqual({
      ok: false,
      errorCode: 'SIMULATION_FEE_POLICY_REJECTED',
    });
    await expect(
      runtime.transport.prepareTransaction({
        ...transaction,
        nonce: 7,
      }),
    ).rejects.toMatchObject({ code: 'FEE_CHANGED' });
    expect(runtime.wallet.signTransaction).not.toHaveBeenCalled();
  });

  it('binds a legacy gas price and rejects wallet-side fee changes', async () => {
    const runtime = setup({
      gasPrice: 12_000_000_000n,
      maxFeePerGas: null,
      maxPriorityFeePerGas: null,
    });
    const transaction = request();

    await expect(
      runtime.simulator.simulate(transaction, WALLET),
    ).resolves.toMatchObject({
      ok: true,
      feeQuote: {
        model: 'legacy',
        maximumNetworkFeeCoti: '0.072',
        maximumFeePerGasWei: '12000000000',
      },
    });
    runtime.wallet.populateTransaction.mockImplementationOnce(
      async (populated) => ({
        ...populated,
        gasPrice: 12_000_000_001n,
      }),
    );

    await expect(
      runtime.transport.prepareTransaction({
        ...transaction,
        nonce: 7,
      }),
    ).rejects.toMatchObject({
      code: 'FEE_CHANGED',
      message: expect.stringContaining(
        'changed the pre-confirmed fee fields',
      ),
    });
    expect(runtime.wallet.signTransaction).not.toHaveBeenCalled();
  });

  it('applies the same fee and gas ceilings to SDK-managed wallet writes', () => {
    expect(() =>
      assertCotiSignerTransactionFeePolicy({
        gasLimit: 8_000_000n,
        type: 2,
        maxFeePerGas: COTI_SIGNER_MAX_FEE_PER_GAS_WEI,
        maxPriorityFeePerGas: 1n,
      }),
    ).not.toThrow();

    expect(() =>
      assertCotiSignerTransactionFeePolicy({
        gasLimit: 8_000_000n,
        type: 2,
        maxFeePerGas:
          COTI_SIGNER_MAX_FEE_PER_GAS_WEI + 1n,
        maxPriorityFeePerGas: 1n,
      }),
    ).toThrow(expect.objectContaining({ code: 'FEE_CHANGED' }));

    expect(() =>
      assertCotiSignerTransactionFeePolicy({
        gasLimit: 12_000_001n,
        type: 0,
        gasPrice: 1n,
      }),
    ).toThrow(expect.objectContaining({ code: 'FEE_CHANGED' }));
  });
});
