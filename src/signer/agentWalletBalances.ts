import { decryptUint256 } from '@coti-io/coti-sdk-typescript';
import {
  decodeFunctionResult,
  encodeFunctionData,
  formatUnits,
  parseAbi,
} from 'viem';

import type {
  ChainWhisperRuntimeManifestV1,
  JsonRpcReader,
} from '../shared/index.js';
import { isCotiAesKey, normalizeCotiAesKey } from './cotiAes.js';
import type { Address, HexString } from './types.js';

const PUBLIC_TOKEN_ABI = parseAbi([
  'function balanceOf(address account) view returns (uint256)',
]);
const PRIVATE_TOKEN_ABI = parseAbi([
  'function accountEncryptionAddress(address account) view returns (address)',
  'function balanceOf(address account) view returns ((uint256 ciphertextHigh,uint256 ciphertextLow))',
]);
const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const DEFAULT_CACHE_TTL_MS = 30_000;
const DEFAULT_CONCURRENCY = 4;

export type AgentWalletBalanceReadiness =
  | 'ready'
  | 'privacy-required'
  | 'setup-required'
  | 'unavailable';

export type AgentWalletBalanceRow = {
  symbol: string;
  kind: 'native' | 'erc20' | 'private-erc20';
  token?: HexString;
  displayAmount?: string;
  exactAmount?: string;
  readiness: AgentWalletBalanceReadiness;
  defaultVisible: boolean;
  stale: boolean;
};

export type AgentWalletBalanceSnapshot = {
  rows: AgentWalletBalanceRow[];
  refreshedAt: string;
  stale: boolean;
  revision: number;
};

type RuntimeToken = ChainWhisperRuntimeManifestV1['tokens'][number];
type BaseBalanceRow = Omit<AgentWalletBalanceRow, 'defaultVisible'>;
type Ciphertext = {
  ciphertextHigh: bigint;
  ciphertextLow: bigint;
};
type BaseBalanceSnapshot = Omit<
  AgentWalletBalanceSnapshot,
  'rows'
> & {
  rows: BaseBalanceRow[];
};

const normalizeReference = (value: string): string =>
  value.trim().toLowerCase();

const hasReference = (
  token: RuntimeToken,
  required: ReadonlySet<string>,
): boolean =>
  required.has(normalizeReference(token.symbol)) ||
  Boolean(
    token.address &&
      required.has(normalizeReference(token.address)),
  );

export const formatDashboardAmount = (exact: string): string => {
  const [whole = '0', fraction = ''] = exact.split('.');
  if (!fraction) return whole;
  let trimmedLength = fraction.length;
  while (
    trimmedLength > 0 &&
    fraction.charCodeAt(trimmedLength - 1) === 48
  ) {
    trimmedLength -= 1;
  }
  const trimmed = fraction.slice(0, trimmedLength);
  if (!trimmed) return whole;
  if (trimmed.length <= 6) return `${whole}.${trimmed}`;
  if (whole !== '0') return `${whole}.${trimmed.slice(0, 6)}`;
  const firstNonZero = trimmed.search(/[1-9]/u);
  if (firstNonZero >= 6) return '<0.000001';
  return `${whole}.${trimmed.slice(0, 6)}`;
};

const mapWithConcurrency = async <T, R>(
  values: readonly T[],
  concurrency: number,
  map: (value: T, index: number) => Promise<R>,
): Promise<R[]> => {
  const results = new Array<R>(values.length);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, values.length) },
    async () => {
      while (nextIndex < values.length) {
        const index = nextIndex;
        nextIndex += 1;
        results[index] = await map(values[index]!, index);
      }
    },
  );
  await Promise.all(workers);
  return results;
};

const unavailableRow = (
  token: RuntimeToken,
): BaseBalanceRow => ({
  symbol: token.symbol,
  kind: token.kind,
  ...(token.address ? { token: token.address } : {}),
  readiness: 'unavailable',
  stale: false,
});

export class AgentWalletBalanceReader {
  readonly #wallet: Address;
  readonly #rpc: JsonRpcReader;
  readonly #tokens: readonly RuntimeToken[];
  readonly #privacyKey: () => string | null;
  readonly #decrypt: (ciphertext: Ciphertext, aesKey: string) => bigint;
  readonly #cacheTtlMs: number;
  readonly #concurrency: number;
  #cache: BaseBalanceSnapshot | null = null;
  #refreshing: Promise<BaseBalanceSnapshot> | null = null;
  #walletEoaCheck: Promise<boolean> | null = null;
  #invalidationVersion = 0;
  #cacheVersion = -1;
  #revision = 0;

  constructor(options: {
    wallet: Address;
    rpc: JsonRpcReader;
    manifest: ChainWhisperRuntimeManifestV1;
    privacyKey: () => string | null;
    decrypt?: (ciphertext: Ciphertext, aesKey: string) => bigint;
    cacheTtlMs?: number;
    concurrency?: number;
  }) {
    this.#wallet = options.wallet;
    this.#rpc = options.rpc;
    this.#tokens = options.manifest.tokens;
    this.#privacyKey = options.privacyKey;
    this.#decrypt = options.decrypt ?? decryptUint256;
    this.#cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.#concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  }

  invalidate(): void {
    // Keep the last successful rows available as a stale fallback. The
    // reader instance is wallet-bound, so constructing a new reader is the
    // only wallet-change path that intentionally starts with an empty cache.
    this.#invalidationVersion += 1;
  }

  async snapshot(
    requiredAssets: readonly string[] = [],
    force = false,
  ): Promise<AgentWalletBalanceSnapshot> {
    const cachedAt = this.#cache
      ? Date.parse(this.#cache.refreshedAt)
      : Number.NaN;
    const cacheFresh =
      this.#cache !== null &&
      this.#cacheVersion === this.#invalidationVersion &&
      Number.isFinite(cachedAt) &&
      Date.now() - cachedAt < this.#cacheTtlMs;
    const base =
      !force && cacheFresh
        ? this.#cache!
        : await this.#refresh();
    return this.#withVisibility(base, requiredAssets);
  }

  refresh(
    requiredAssets: readonly string[] = [],
  ): Promise<AgentWalletBalanceSnapshot> {
    return this.snapshot(requiredAssets, true);
  }

  async #refresh(): Promise<BaseBalanceSnapshot> {
    if (this.#refreshing) return this.#refreshing;
    const previous = this.#cache;
    const refreshVersion = this.#invalidationVersion;
    const pending = (async () => {
      const rows = await mapWithConcurrency(
        this.#tokens,
        this.#concurrency,
        async (token) => {
          try {
            return await this.#readToken(token);
          } catch {
            const prior = previous?.rows.find(
              ({ symbol }) =>
                symbol.toLowerCase() === token.symbol.toLowerCase(),
            );
            return prior?.readiness === 'ready'
              ? { ...prior, stale: true }
              : unavailableRow(token);
          }
        },
      );
      this.#revision += 1;
      const snapshot: BaseBalanceSnapshot = {
        rows,
        refreshedAt: new Date().toISOString(),
        stale: rows.some(({ stale }) => stale),
        revision: this.#revision,
      };
      this.#cache = snapshot;
      this.#cacheVersion = refreshVersion;
      return snapshot;
    })();
    this.#refreshing = pending;
    try {
      return await pending;
    } finally {
      if (this.#refreshing === pending) this.#refreshing = null;
    }
  }

  #withVisibility(
    snapshot: BaseBalanceSnapshot,
    requiredAssets: readonly string[],
  ): AgentWalletBalanceSnapshot {
    const required = new Set(requiredAssets.map(normalizeReference));
    return {
      ...snapshot,
      rows: snapshot.rows.map((row, index) => {
        const token = this.#tokens[index]!;
        return {
          ...row,
          defaultVisible:
            row.kind === 'native' ||
            (row.kind === 'erc20' &&
              row.readiness === 'ready' &&
              row.exactAmount !== '0') ||
            (row.kind === 'private-erc20' &&
              row.readiness === 'ready' &&
              row.exactAmount !== '0') ||
            hasReference(token, required),
        };
      }),
    };
  }

  async #readToken(token: RuntimeToken): Promise<BaseBalanceRow> {
    if (token.kind === 'native') {
      const value = await this.#rpc.request<string>('eth_getBalance', [
        this.#wallet,
        'latest',
      ]);
      return this.#readyRow(token, BigInt(value));
    }
    if (!token.address) return unavailableRow(token);
    if (token.kind === 'erc20') {
      const raw = await this.#ethCall(
        token.address,
        encodeFunctionData({
          abi: PUBLIC_TOKEN_ABI,
          functionName: 'balanceOf',
          args: [this.#wallet],
        }),
      );
      const amount = decodeFunctionResult({
        abi: PUBLIC_TOKEN_ABI,
        functionName: 'balanceOf',
        data: raw,
      });
      return this.#readyRow(token, BigInt(amount));
    }
    const privacyKey = this.#privacyKey();
    if (!isCotiAesKey(privacyKey)) {
      return {
        symbol: token.symbol,
        kind: token.kind,
        token: token.address,
        readiness: 'privacy-required',
        stale: false,
      };
    }
    const encryptionRaw = await this.#ethCall(
      token.address,
      encodeFunctionData({
        abi: PRIVATE_TOKEN_ABI,
        functionName: 'accountEncryptionAddress',
        args: [this.#wallet],
      }),
    );
    const encryptionAddress = decodeFunctionResult({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'accountEncryptionAddress',
      data: encryptionRaw,
    });
    const explicitWalletMapping =
      encryptionAddress.toLowerCase() ===
      this.#wallet.toLowerCase();
    const implicitWalletMapping =
      encryptionAddress.toLowerCase() === ZERO_ADDRESS &&
      (await this.#walletIsEoa());
    if (!explicitWalletMapping && !implicitWalletMapping) {
      return {
        symbol: token.symbol,
        kind: token.kind,
        token: token.address,
        readiness: 'setup-required',
        stale: false,
      };
    }
    const balanceRaw = await this.#ethCall(
      token.address,
      encodeFunctionData({
        abi: PRIVATE_TOKEN_ABI,
        functionName: 'balanceOf',
        args: [this.#wallet],
      }),
    );
    const encrypted = decodeFunctionResult({
      abi: PRIVATE_TOKEN_ABI,
      functionName: 'balanceOf',
      data: balanceRaw,
    });
    const amount = this.#decrypt(
      {
        ciphertextHigh: BigInt(encrypted.ciphertextHigh),
        ciphertextLow: BigInt(encrypted.ciphertextLow),
      },
      normalizeCotiAesKey(privacyKey),
    );
    return this.#readyRow(token, amount);
  }

  #readyRow(
    token: RuntimeToken,
    amount: bigint,
  ): BaseBalanceRow {
    const exactAmount = formatUnits(amount, token.decimals);
    return {
      symbol: token.symbol,
      kind: token.kind,
      ...(token.address ? { token: token.address } : {}),
      displayAmount: formatDashboardAmount(exactAmount),
      exactAmount,
      readiness: 'ready',
      stale: false,
    };
  }

  async #walletIsEoa(): Promise<boolean> {
    if (this.#walletEoaCheck) return this.#walletEoaCheck;
    const pending = this.#rpc
      .request<string>('eth_getCode', [this.#wallet, 'latest'])
      .then(
        (code) =>
          typeof code === 'string' &&
          code.toLowerCase() === '0x',
      );
    this.#walletEoaCheck = pending;
    try {
      return await pending;
    } catch (error) {
      if (this.#walletEoaCheck === pending) {
        this.#walletEoaCheck = null;
      }
      throw error;
    }
  }

  #ethCall(to: HexString, data: HexString): Promise<HexString> {
    return this.#rpc.request<HexString>('eth_call', [
      { from: this.#wallet, to, data },
      'latest',
    ]);
  }
}
