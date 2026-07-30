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

const rpcFixture = (
  options: {
    privateCotiMapping?: string;
    walletCode?: string;
  } = {},
) => {
  let failPublicBalance = false;
  let calls = 0;
  const request = vi.fn(
    async <T>(method: string, params: unknown[]): Promise<T> => {
      calls += 1;
      if (method === 'eth_getBalance') {
        return '0x1bc16d674ec80000' as T;
      }
      if (method === 'eth_getCode') {
        expect(params).toEqual([WALLET, 'latest']);
        return (options.walletCode ?? '0x') as T;
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
              : (options.privateCotiMapping ?? ZERO_ADDRESS),
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
  it('reads explicit and implicit EOA private balances after privacy onboarding', async () => {
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
        displayAmount: '<0.000001',
        exactAmount: '0.00000000001',
        readiness: 'ready',
        defaultVisible: true,
      },
    ]);
    expect(fixture.request).toHaveBeenCalledWith(
      'eth_call',
      expect.arrayContaining([
        expect.objectContaining({ from: WALLET }),
      ]),
    );
    expect(fixture.request).toHaveBeenCalledWith('eth_getCode', [
      WALLET,
      'latest',
    ]);
  });

  it('does not decrypt a zero-mapped private token for a code-bearing wallet', async () => {
    const fixture = rpcFixture({ walletCode: '0x6001600055' });
    const decrypt = vi.fn(() => 10_000_000n);
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt,
    });

    const snapshot = await reader.snapshot();

    expect(
      snapshot.rows.find(({ symbol }) => symbol === 'p.COTI'),
    ).toMatchObject({
      readiness: 'setup-required',
      defaultVisible: false,
    });
    expect(decrypt).toHaveBeenCalledTimes(1);
  });

  it('keeps prepared zero private balances under Show all assets unless required', async () => {
    const fixture = rpcFixture();
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt: () => 0n,
    });

    const ordinary = await reader.snapshot();
    expect(
      ordinary.rows.find(({ symbol }) => symbol === 'p.COTI'),
    ).toMatchObject({
      readiness: 'ready',
      exactAmount: '0',
      defaultVisible: false,
    });

    const required = await reader.snapshot(['p.COTI']);
    expect(
      required.rows.find(({ symbol }) => symbol === 'p.COTI'),
    ).toMatchObject({
      readiness: 'ready',
      exactAmount: '0',
      defaultVisible: true,
    });
  });

  it('does not classify a foreign mapping as ready or query wallet code', async () => {
    const foreign =
      '0x5555555555555555555555555555555555555555';
    const fixture = rpcFixture({ privateCotiMapping: foreign });
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt: () => 10_000_000n,
    });

    const snapshot = await reader.snapshot();

    expect(
      snapshot.rows.find(({ symbol }) => symbol === 'p.COTI'),
    ).toMatchObject({
      readiness: 'setup-required',
      defaultVisible: false,
    });
    expect(
      fixture.request.mock.calls.some(
        ([method]) => method === 'eth_getCode',
      ),
    ).toBe(false);
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
    expect(fixture.calls() - firstCallCount).toBe(6);
  });

  it('invalidates freshness without discarding the last snapshot used for partial-failure fallback', async () => {
    const fixture = rpcFixture();
    const reader = new AgentWalletBalanceReader({
      wallet: WALLET,
      rpc: fixture.rpc,
      manifest,
      privacyKey: () => AES_KEY,
      decrypt: () => 10_000_000n,
    });
    const initial = await reader.snapshot();
    fixture.failPublicBalance();

    reader.invalidate();
    const refreshed = await reader.snapshot();

    expect(refreshed.revision).toBe(initial.revision + 1);
    expect(
      refreshed.rows.find(({ symbol }) => symbol === 'WISP'),
    ).toMatchObject({
      displayAmount: '12.5',
      exactAmount: '12.5',
      readiness: 'ready',
      stale: true,
    });
    expect(
      refreshed.rows.find(({ symbol }) => symbol === 'COTI'),
    ).toMatchObject({
      exactAmount: '2',
      stale: false,
    });
    expect(refreshed.stale).toBe(true);
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
