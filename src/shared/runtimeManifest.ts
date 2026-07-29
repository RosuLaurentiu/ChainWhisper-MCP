import { readFile } from 'node:fs/promises';

import { decodeAbiParameters, keccak256, type Address, type Hex } from 'viem';

import { canonicalize, sha256Hex } from './canonical.js';
import {
  CHAINWHISPER_CHAIN_ID,
  isHexAddress,
  isHexData,
  type HexString,
  type RegistrySnapshotV1,
  type RuntimeContractSnapshotV1
} from './protocol.js';

export interface RuntimeContractManifestEntry {
  address: HexString;
  bytecodeHash: HexString;
  bytecodeBytes: number;
  requiresLiveAudit?: boolean;
  selectorAudit?: 'literal-bytecode' | 'exact-bytecode-hash';
  selectors: Record<string, HexString>;
}

export interface ChainWhisperRuntimeManifestV1 {
  schemaVersion: 'chainwhisper.runtime/1';
  network: {
    name: string;
    chainId: typeof CHAINWHISPER_CHAIN_ID;
    rpcUrl: string;
    explorerUrl: string;
  };
  registry: RuntimeContractManifestEntry;
  contracts: Record<string, RuntimeContractManifestEntry>;
  attestations: Record<string, RuntimeContractManifestEntry>;
  tokens: Array<{
    symbol: string;
    kind: 'native' | 'erc20' | 'private-erc20';
    address?: HexString;
    decimals: number;
    publicCounterpart?: string;
  }>;
  audit: {
    capturedAt: string;
    authority: 'deployed-bytecode';
    recurringWritePolicy: 'enable-only-after-live-bytecode-and-selector-match';
  };
}

export interface JsonRpcReader {
  request<T>(method: string, params: unknown[]): Promise<T>;
}

export interface RuntimeAuditContractResult {
  name: string;
  address: HexString;
  expectedBytecodeHash: HexString;
  observedBytecodeHash?: HexString;
  bytecodeMatches: boolean;
  selectorsMatch: boolean;
  error?: string;
}

export interface RuntimeAuditResult {
  ok: boolean;
  checkedAt: string;
  blockNumber?: string;
  registryContractsMatch: boolean;
  registryContractsError?: string;
  recurringWritesEnabled: boolean;
  contracts: RuntimeAuditContractResult[];
}

const manifestUrl = new URL('../../runtime/coti-mainnet.v1.json', import.meta.url);

const validateEntry = (name: string, value: unknown): RuntimeContractManifestEntry => {
  if (!value || typeof value !== 'object') {
    throw new Error(`Runtime manifest contract ${name} is missing.`);
  }
  const entry = value as Record<string, unknown>;
  if (!isHexAddress(entry.address) || !isHexData(entry.bytecodeHash)) {
    throw new Error(`Runtime manifest contract ${name} has invalid address or bytecode hash.`);
  }
  if (!Number.isSafeInteger(entry.bytecodeBytes) || Number(entry.bytecodeBytes) <= 0) {
    throw new Error(`Runtime manifest contract ${name} has invalid bytecode length.`);
  }
  const selectors = entry.selectors;
  if (
    entry.selectorAudit !== undefined &&
    entry.selectorAudit !== 'literal-bytecode' &&
    entry.selectorAudit !== 'exact-bytecode-hash'
  ) {
    throw new Error(`Runtime manifest contract ${name} has an invalid selector audit mode.`);
  }
  if (!selectors || typeof selectors !== 'object' || Array.isArray(selectors)) {
    throw new Error(`Runtime manifest contract ${name} has invalid selectors.`);
  }
  for (const [selectorName, selector] of Object.entries(selectors)) {
    if (typeof selector !== 'string' || !/^0x[0-9a-fA-F]{8}$/u.test(selector)) {
      throw new Error(`Runtime manifest selector ${name}.${selectorName} is invalid.`);
    }
  }
  return entry as unknown as RuntimeContractManifestEntry;
};

export const loadRuntimeManifest = async (): Promise<ChainWhisperRuntimeManifestV1> => {
  const parsed = JSON.parse(await readFile(manifestUrl, 'utf8')) as Record<string, unknown>;
  if (parsed.schemaVersion !== 'chainwhisper.runtime/1') {
    throw new Error('Unsupported ChainWhisper runtime manifest.');
  }
  const network = parsed.network as Record<string, unknown> | undefined;
  if (network?.chainId !== CHAINWHISPER_CHAIN_ID) {
    throw new Error('Runtime manifest targets an unexpected chain.');
  }
  const registry = validateEntry('registry', parsed.registry);
  const rawContracts = parsed.contracts;
  if (!rawContracts || typeof rawContracts !== 'object' || Array.isArray(rawContracts)) {
    throw new Error('Runtime manifest contracts are missing.');
  }
  const contracts = Object.fromEntries(
    Object.entries(rawContracts).map(([name, entry]) => [name, validateEntry(name, entry)])
  );
  const rawAttestations = parsed.attestations;
  if (
    !rawAttestations ||
    typeof rawAttestations !== 'object' ||
    Array.isArray(rawAttestations)
  ) {
    throw new Error('Runtime manifest contract attestations are missing.');
  }
  const attestations = Object.fromEntries(
    Object.entries(rawAttestations).map(([name, entry]) => [
      name,
      validateEntry(`attestation.${name}`, entry)
    ])
  );
  const rawTokens = parsed.tokens;
  if (!Array.isArray(rawTokens) || rawTokens.length === 0) {
    throw new Error('Runtime manifest verified tokens are missing.');
  }
  const tokens = rawTokens.map((rawToken, index) => {
    if (!rawToken || typeof rawToken !== 'object') {
      throw new Error(`Runtime manifest token ${index} is invalid.`);
    }
    const token = rawToken as Record<string, unknown>;
    if (
      typeof token.symbol !== 'string' ||
      !['native', 'erc20', 'private-erc20'].includes(String(token.kind)) ||
      !Number.isInteger(token.decimals) ||
      Number(token.decimals) < 0 ||
      Number(token.decimals) > 78 ||
      (token.kind !== 'native' && !isHexAddress(token.address))
    ) {
      throw new Error(`Runtime manifest token ${index} is invalid.`);
    }
    return rawToken as ChainWhisperRuntimeManifestV1['tokens'][number];
  });
  for (const required of [
    'cotiAccountOnboarding',
    'cotiPrivateMessaging',
  ]) {
    if (!attestations[required]) {
      throw new Error(
        `Runtime manifest is missing the ${required} write-target attestation.`,
      );
    }
  }
  const attestedAddresses = new Set(
    Object.values(attestations).map(({ address }) =>
      address.toLowerCase(),
    ),
  );
  for (const token of tokens) {
    if (
      token.kind === 'private-erc20' &&
      token.address &&
      !attestedAddresses.has(token.address.toLowerCase())
    ) {
      throw new Error(
        `Private token ${token.symbol} is not covered by a runtime bytecode attestation.`,
      );
    }
  }
  return {
    ...(parsed as unknown as ChainWhisperRuntimeManifestV1),
    registry,
    contracts,
    attestations,
    tokens
  };
};

export const hashRuntimeManifest = (manifest: ChainWhisperRuntimeManifestV1): HexString =>
  sha256Hex(canonicalize(manifest));

const selectorSetMatches = (bytecode: string, selectors: Record<string, HexString>): boolean => {
  const normalizedCode = bytecode.toLowerCase().replace(/^0x/u, '');
  return Object.values(selectors).every((selector) =>
    normalizedCode.includes(selector.toLowerCase().replace(/^0x/u, ''))
  );
};

export const auditRuntimeManifest = async (
  manifest: ChainWhisperRuntimeManifestV1,
  rpc: JsonRpcReader
): Promise<RuntimeAuditResult> => {
  let blockNumber: string | undefined;
  try {
    blockNumber = await rpc.request<string>('eth_blockNumber', []);
  } catch {
    blockNumber = undefined;
  }
  const entries: Array<[string, RuntimeContractManifestEntry]> = [
    ['registry', manifest.registry],
    ...Object.entries(manifest.contracts),
    ...Object.entries(manifest.attestations).map(
      ([name, entry]) =>
        [`attestation.${name}`, entry] as [
          string,
          RuntimeContractManifestEntry
        ]
    )
  ];
  const contracts = await Promise.all(
    entries.map(async ([name, entry]): Promise<RuntimeAuditContractResult> => {
      try {
        const code = await rpc.request<Hex>('eth_getCode', [entry.address, blockNumber ?? 'latest']);
        const observedBytecodeHash = keccak256(code);
        return {
          name,
          address: entry.address,
          expectedBytecodeHash: entry.bytecodeHash,
          observedBytecodeHash,
          bytecodeMatches: observedBytecodeHash.toLowerCase() === entry.bytecodeHash.toLowerCase(),
          selectorsMatch:
            entry.selectorAudit === 'exact-bytecode-hash'
              ? observedBytecodeHash.toLowerCase() ===
                entry.bytecodeHash.toLowerCase()
              : selectorSetMatches(code, entry.selectors)
        };
      } catch (error) {
        return {
          name,
          address: entry.address,
          expectedBytecodeHash: entry.bytecodeHash,
          bytecodeMatches: false,
          selectorsMatch: false,
          error: error instanceof Error ? error.message : 'runtime-audit-failed'
        };
      }
    })
  );
  let registryContractsMatch = false;
  let registryContractsError: string | undefined;
  try {
    const registryResult = await rpc.request<Hex>('eth_call', [
      { to: manifest.registry.address, data: manifest.registry.selectors.getContracts },
      blockNumber ?? 'latest'
    ]);
    const [registryContracts] = decodeAbiParameters(
      [
        {
          type: 'tuple',
          components: [
            { name: 'standardEscrow', type: 'address' },
            { name: 'privateEscrow', type: 'address' },
            { name: 'directEscrow', type: 'address' },
            { name: 'recurringEscrow', type: 'address' },
            { name: 'reader', type: 'address' },
            { name: 'historyReader', type: 'address' }
          ]
        }
      ],
      registryResult
    ) as readonly [
      {
        standardEscrow: Address;
        privateEscrow: Address;
        directEscrow: Address;
        recurringEscrow: Address;
        reader: Address;
        historyReader: Address;
      }
    ];
    registryContractsMatch = (
      ['standardEscrow', 'privateEscrow', 'directEscrow', 'recurringEscrow', 'reader', 'historyReader'] as const
    ).every(
      (name) =>
        registryContracts[name].toLowerCase() === manifest.contracts[name]?.address.toLowerCase()
    );
    if (!registryContractsMatch) {
      registryContractsError = 'registry-contract-address-mismatch';
    }
  } catch (error) {
    registryContractsError = error instanceof Error ? error.message : 'registry-read-failed';
  }
  const recurring = contracts.find((contract) => contract.name === 'recurringEscrow');
  return {
    ok:
      registryContractsMatch &&
      contracts.every((contract) => contract.bytecodeMatches && contract.selectorsMatch),
    checkedAt: new Date().toISOString(),
    blockNumber,
    registryContractsMatch,
    ...(registryContractsError ? { registryContractsError } : {}),
    recurringWritesEnabled: Boolean(
      registryContractsMatch && recurring?.bytecodeMatches && recurring.selectorsMatch
    ),
    contracts
  };
};

export const createRegistrySnapshot = (
  manifest: ChainWhisperRuntimeManifestV1,
  audit: RuntimeAuditResult,
  fees: Record<string, string> = {}
): RegistrySnapshotV1 => {
  const contracts = Object.fromEntries(
    Object.entries(manifest.contracts).map(([name, contract]) => [
      name,
      {
        address: contract.address,
        bytecodeHash: contract.bytecodeHash,
        selectors: contract.selectors
      } satisfies RuntimeContractSnapshotV1
    ])
  );
  return {
    registryAddress: manifest.registry.address,
    registryBytecodeHash: manifest.registry.bytecodeHash,
    manifestHash: hashRuntimeManifest(manifest),
    observedBlock: audit.blockNumber ?? 'latest',
    contracts,
    fees
  };
};

export class HttpJsonRpcReader implements JsonRpcReader {
  readonly #url: string;
  #nextId = 1;

  constructor(url: string) {
    this.#url = url;
  }

  async request<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(this.#url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: this.#nextId++, method, params }),
      signal: AbortSignal.timeout(20_000)
    });
    if (!response.ok) {
      throw new Error(`rpc-http-${response.status}`);
    }
    const payload = (await response.json()) as {
      result?: T;
      error?: { code?: number; message?: string };
    };
    if (payload.error) {
      throw new Error(`rpc-${payload.error.code ?? 'error'}:${payload.error.message ?? 'unknown'}`);
    }
    if (payload.result === undefined) {
      throw new Error('rpc-missing-result');
    }
    return payload.result;
  }
}
