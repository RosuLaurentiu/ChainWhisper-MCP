import {
  encodeFunctionResult,
  parseAbi,
} from 'viem';
import { describe, expect, it, vi } from 'vitest';

import type {
  ChainWhisperRuntimeManifestV1,
  JsonRpcReader,
} from '../src/shared/index.js';
import {
  AgentWalletBalanceReader,
  formatDashboardAmount,
} from '../src/signer/agentWalletBalances.js';
import type {
  Address,
  HexString,
} from '../src/signer/types.js';

const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const WISP =
  '0x2222222222222222222222222222222222222222' as HexString;
const PRIVATE_WISP =
  '0x3333333333333333333333333333333333333333' as HexString;
const PRIVATE_COTI =
  '0x4444444444444444444444444444444444444444' as HexString;
const AES_KEY = `0x${'ab'.repeat(16)}`;
const PUBLIC_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
]);
const PRIVATE_ABI = parseAbi([
  'function accountEncryptionAddress(address account) view returns (address)',
  'function balanceOf(address account) view returns ((uint256 ciphertextHigh,uint256 ciphertextLow))',
]);
const ACCOUNT_SELECTOR = '0x043d2085';

const manifest = {
  tokens: [
    { symbol: 'COTI', kind: 'native', decimals: 18 },
    {
      symbol: 'WISP',
      kind: 'erc20',
      address: WISP,
      decimals: 6,
    },
    {
      symbol: 'p.WISP',
      kind: 'private-erc20',
      address: PRIVATE_WISP,
      decimals: 6,
    },
    {
      symbol: 'p.COTI',
      kind: 'private-erc20',
      address: PRIVATE_COTI,
      decimals: 18,
    },
  ],
} as unknown as ChainWhisperRuntimeManifestV1;

const rpcFixture = () => {
  let failPublicBalance = false;
  let calls = 0;
  const request = vi.fn(
    async <T>(method: string, params: unknown[]): Promise<T> => {
      calls += 1;
      if (method === 'eth_getBalance') {
        return '0x1bc16d674ec80000' as T;
      }
      const transaction = params[0] as {
        to: string;
        data: string;
      };
      if (transaction.to.toLowerCase() === WISP.toLowerCase()) {
        if (failPublicBalance) throw new Error('rpc unavailable');
        return encodeFunctionResult({
          abi: PUBLIC_ABI,
          functionName: 'balanceOf',
          result: 12_500_000n,
        }) as T;
      }
      if (transaction.data.startsWith(ACCOUNT_SELECTOR)) {
        return encodeFunctionResult({
          abi: PRIVATE_ABI,
          functionName: 'accountEncryptionAddress',
          result:
            transaction.to.toLowerCase() ===
            PRIVATE_WISP.toLowerCase()
              ? WALLET
              : ZERO_ADDRESS,
        }) as T;
      }
      return encodeFunctionResult({
        abi: PRIVATE_ABI,
        functionName: 'balanceOf',
        result: {
          ciphertextHigh: 1n,
          ciphertextLow: 2n,
        },
      }) as T;
    },
  );
  return {
    rpc: { request } as JsonRpcReader,
    request,
    calls: () => calls,
    failPublicBalance: () => {
      failPublicBalance = true;
    },
  };
};

describe('AgentWalletBalanceReader', () => {
  it('reads native, public, and prepared private balances with active filtering', async () => {
    const fixture = rpcFixture();
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt: () => 10_000_000n,
    });

    const snapshot = await reader.snapshot(['p.COTI']);

    expect(snapshot.revision).toBe(1);
    expect(snapshot.stale).toBe(false);
    expect(snapshot.rows).toMatchObject([
      {
        symbol: 'COTI',
        displayAmount: '2',
        exactAmount: '2',
        readiness: 'ready',
        defaultVisible: true,
      },
      {
        symbol: 'WISP',
        displayAmount: '12.5',
        exactAmount: '12.5',
        readiness: 'ready',
        defaultVisible: true,
      },
      {
        symbol: 'p.WISP',
        displayAmount: '10',
        exactAmount: '10',
        readiness: 'ready',
        defaultVisible: true,
      },
      {
        symbol: 'p.COTI',
        readiness: 'setup-required',
        defaultVisible: true,
      },
    ]);
    expect(fixture.request).toHaveBeenCalledWith(
      'eth_call',
      expect.arrayContaining([
        expect.objectContaining({ from: WALLET }),
      ]),
    );
  });

  it('uses its cache, deduplicates refreshes, and retains stale successful values', async () => {
    const fixture = rpcFixture();
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt: () => 10_000_000n,
    });
    await reader.snapshot();
    const firstCallCount = fixture.calls();

    await reader.snapshot();
    expect(fixture.calls()).toBe(firstCallCount);

    fixture.failPublicBalance();
    const [first, second] = await Promise.all([
      reader.refresh(),
      reader.refresh(),
    ]);
    expect(first.revision).toBe(2);
    expect(second.revision).toBe(2);
    expect(first.rows.find(({ symbol }) => symbol === 'WISP')).toMatchObject({
      exactAmount: '12.5',
      readiness: 'ready',
      stale: true,
    });
    expect(first.stale).toBe(true);
    expect(fixture.calls() - firstCallCount).toBe(5);
  });

  it('does not query or reveal private balances before privacy onboarding', async () => {
    const fixture = rpcFixture();
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => null,
    });

    const snapshot = await reader.snapshot();

    expect(snapshot.rows.slice(2)).toMatchObject([
      {
        symbol: 'p.WISP',
        readiness: 'privacy-required',
        defaultVisible: false,
      },
      {
        symbol: 'p.COTI',
        readiness: 'privacy-required',
        defaultVisible: false,
      },
    ]);
    expect(fixture.calls()).toBe(2);
  });

  it('limits concurrent RPC work', async () => {
    let active = 0;
    let maximumActive = 0;
    const rpc: JsonRpcReader = {
      request: async <T>(method: string): Promise<T> => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
        active -= 1;
        if (method === 'eth_getBalance') return '0x0' as T;
        return encodeFunctionResult({
          abi: PUBLIC_ABI,
          functionName: 'balanceOf',
          result: 0n,
        }) as T;
      },
    };
    const publicManifest = {
      tokens: [
        { symbol: 'COTI', kind: 'native', decimals: 18 },
        ...Array.from({ length: 5 }, (_, index) => ({
          symbol: `TOKEN${index}`,
          kind: 'erc20',
          address:
            `0x${String(index + 1).padStart(40, '0')}` as HexString,
          decimals: 18,
        })),
      ],
    } as unknown as ChainWhisperRuntimeManifestV1;
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc,
      manifest: publicManifest,
      privacyKey: () => null,
      concurrency: 2,
    });

    await reader.snapshot();

    expect(maximumActive).toBeLessThanOrEqual(2);
  });
});

describe('formatDashboardAmount', () => {
  it.each([
    ['28.871970318561943392', '28.871970'],
    ['12.500000', '12.5'],
    ['0.12345678', '0.123456'],
    ['0.00000042', '<0.000001'],
    ['0', '0'],
  ])('formats %s as %s', (exact, expected) => {
    expect(formatDashboardAmount(exact)).toBe(expected);
  });

  it('trims a large untrusted zero suffix without a regular expression', () => {
    expect(
      formatDashboardAmount(`12.5${'0'.repeat(250_000)}`),
    ).toBe('12.5');
  });
});
