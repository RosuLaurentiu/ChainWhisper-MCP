import { afterEach, describe, expect, it, vi } from 'vitest';
import { keccak256, type Hex } from 'viem';

import {
  auditRuntimeManifest,
  type ChainWhisperRuntimeManifestV1,
  type JsonRpcReader,
  type RuntimeContractManifestEntry
} from '../src/shared/runtimeManifest.js';

const BYTECODE = '0x60c3a2a93a00' as const;
const BYTECODE_HASH = keccak256(BYTECODE);
const BLOCK_NUMBER = '0xabc';
const CONTRACT_NAMES = [
  'standardEscrow',
  'privateEscrow',
  'directEscrow',
  'recurringEscrow',
  'reader',
  'historyReader'
] as const;

const address = (index: number): `0x${string}` =>
  `0x${index.toString(16).padStart(40, '0')}`;

const entry = (
  index: number,
  selectors: RuntimeContractManifestEntry['selectors'] = {}
): RuntimeContractManifestEntry => ({
  address: address(index),
  bytecodeHash: BYTECODE_HASH,
  bytecodeBytes: (BYTECODE.length - 2) / 2,
  selectors
});

const createManifest = (): ChainWhisperRuntimeManifestV1 => ({
  schemaVersion: 'chainwhisper.runtime/1',
  network: {
    name: 'test',
    chainId: 2_632_500,
    rpcUrl: 'https://rpc.example',
    explorerUrl: 'https://explorer.example'
  },
  registry: entry(1, { getContracts: '0xc3a2a93a' }),
  contracts: Object.fromEntries(
    CONTRACT_NAMES.map((name, index) => [name, entry(index + 2)])
  ),
  attestations: {
    cotiAccountOnboarding: entry(8),
    cotiPrivateMessaging: entry(9)
  },
  tokens: [],
  audit: {
    capturedAt: '2026-08-08T00:00:00.000Z',
    authority: 'deployed-bytecode',
    recurringWritePolicy: 'enable-only-after-live-bytecode-and-selector-match'
  }
});

const encodeRegistryContracts = (manifest: ChainWhisperRuntimeManifestV1): Hex =>
  `0x${CONTRACT_NAMES.map((name) =>
    manifest.contracts[name]!.address.slice(2).padStart(64, '0')
  ).join('')}`;

const runtimeEntries = (
  manifest: ChainWhisperRuntimeManifestV1
): Array<[string, RuntimeContractManifestEntry]> => [
  ['registry', manifest.registry],
  ...Object.entries(manifest.contracts),
  ...Object.entries(manifest.attestations).map(
    ([name, contractEntry]) =>
      [`attestation.${name}`, contractEntry] as [string, RuntimeContractManifestEntry]
  )
];

const reader = (request: ReturnType<typeof vi.fn>): JsonRpcReader => ({
  request: request as JsonRpcReader['request']
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('auditRuntimeManifest', () => {
  it('limits bytecode concurrency to four, preserves manifest order, and pins every read', async () => {
    const manifest = createManifest();
    const entries = runtimeEntries(manifest);
    const expectedNames = entries.map(([name]) => name);
    const indexByAddress = new Map(
      entries.map(([, contractEntry], index) => [contractEntry.address.toLowerCase(), index])
    );
    const completionOrder: number[] = [];
    const observedPins: unknown[] = [];
    let activeBytecodeReads = 0;
    let maximumBytecodeReads = 0;
    const request = vi.fn(async (method: string, params: unknown[]) => {
      if (method === 'eth_blockNumber') return BLOCK_NUMBER;
      if (method === 'eth_getCode') {
        observedPins.push(params[1]);
        activeBytecodeReads += 1;
        maximumBytecodeReads = Math.max(maximumBytecodeReads, activeBytecodeReads);
        const index = indexByAddress.get(String(params[0]).toLowerCase())!;
        await new Promise((resolve) => setTimeout(resolve, (4 - (index % 4)) * 2));
        completionOrder.push(index);
        activeBytecodeReads -= 1;
        return BYTECODE;
      }
      if (method === 'eth_call') {
        observedPins.push(params[1]);
        return encodeRegistryContracts(manifest);
      }
      throw new Error(`unexpected method: ${method}`);
    });

    const result = await auditRuntimeManifest(manifest, reader(request));

    expect(result.ok).toBe(true);
    expect(result.contracts.map(({ name }) => name)).toEqual(expectedNames);
    expect(maximumBytecodeReads).toBe(4);
    expect(completionOrder).not.toEqual(entries.map((_, index) => index));
    expect(observedPins).toHaveLength(entries.length + 1);
    expect(new Set(observedPins)).toEqual(new Set([BLOCK_NUMBER]));
  });

  it('recovers from transient block, bytecode, and registry RPC failures', async () => {
    vi.useFakeTimers();
    const manifest = createManifest();
    const transientAddress = manifest.contracts.recurringEscrow!.address.toLowerCase();
    let blockAttempts = 0;
    let bytecodeAttempts = 0;
    let registryAttempts = 0;
    const request = vi.fn(async (method: string, params: unknown[]) => {
      if (method === 'eth_blockNumber') {
        blockAttempts += 1;
        if (blockAttempts === 1) throw new Error('transient block failure');
        return BLOCK_NUMBER;
      }
      if (method === 'eth_getCode') {
        if (String(params[0]).toLowerCase() === transientAddress) {
          bytecodeAttempts += 1;
          if (bytecodeAttempts === 1) throw new Error('transient bytecode failure');
        }
        return BYTECODE;
      }
      if (method === 'eth_call') {
        registryAttempts += 1;
        if (registryAttempts === 1) throw new Error('transient registry failure');
        return encodeRegistryContracts(manifest);
      }
      throw new Error(`unexpected method: ${method}`);
    });

    const resultPromise = auditRuntimeManifest(manifest, reader(request));
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(result.ok).toBe(true);
    expect(result.recurringWritesEnabled).toBe(true);
    expect(blockAttempts).toBe(2);
    expect(bytecodeAttempts).toBe(2);
    expect(registryAttempts).toBe(2);
  });

  it('fails closed after four unsuccessful block-pin attempts', async () => {
    vi.useFakeTimers();
    const manifest = createManifest();
    const request = vi.fn(async (method: string) => {
      if (method === 'eth_blockNumber') throw new Error('rpc unavailable');
      throw new Error(`unexpected method: ${method}`);
    });

    const resultPromise = auditRuntimeManifest(manifest, reader(request));
    await vi.runAllTimersAsync();
    const result = await resultPromise;

    expect(request).toHaveBeenCalledTimes(4);
    expect(result).toMatchObject({
      ok: false,
      registryContractsMatch: false,
      registryContractsError: 'block-pin-failed',
      recurringWritesEnabled: false
    });
    expect(result.blockNumber).toBeUndefined();
    expect(result.contracts).toHaveLength(runtimeEntries(manifest).length);
    expect(result.contracts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: 'recurringEscrow',
          bytecodeMatches: false,
          selectorsMatch: false,
          error: 'block-pin-failed'
        })
      ])
    );
  });

  it('does not retry a successful bytecode read whose hash mismatches', async () => {
    const manifest = createManifest();
    const recurringAddress = manifest.contracts.recurringEscrow!.address.toLowerCase();
    let recurringReads = 0;
    const request = vi.fn(async (method: string, params: unknown[]) => {
      if (method === 'eth_blockNumber') return BLOCK_NUMBER;
      if (method === 'eth_getCode') {
        if (String(params[0]).toLowerCase() === recurringAddress) {
          recurringReads += 1;
          return '0x00';
        }
        return BYTECODE;
      }
      if (method === 'eth_call') return encodeRegistryContracts(manifest);
      throw new Error(`unexpected method: ${method}`);
    });

    const result = await auditRuntimeManifest(manifest, reader(request));
    const recurringResult = result.contracts.find(({ name }) => name === 'recurringEscrow');

    expect(recurringReads).toBe(1);
    expect(recurringResult).toMatchObject({
      bytecodeMatches: false,
      selectorsMatch: true
    });
    expect(result.ok).toBe(false);
    expect(result.recurringWritesEnabled).toBe(false);
  });
});
