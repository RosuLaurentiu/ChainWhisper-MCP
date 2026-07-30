import { describe, expect, it, vi } from 'vitest';

import {
  createLiveChainWhisperDomainGateway,
  type Address
} from '../src/domain/index.js';
import { loadRuntimeManifest } from '../src/shared/runtimeManifest.js';

const maker = '0x1111111111111111111111111111111111111111' as Address;
const taker = '0x2222222222222222222222222222222222222222' as Address;

describe('LiveChainWhisperDomainGateway', () => {
  it('resolves only manifest-verified native, symbol, address, and private-token references', async () => {
    const manifest = await loadRuntimeManifest();
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client: { readContract: vi.fn() },
      rpc: { request: vi.fn() }
    });
    await expect(gateway.resolveAsset('COTI')).resolves.toMatchObject({
      kind: 'native',
      symbol: 'COTI',
      decimals: 18
    });
    await expect(gateway.resolveAsset('p.gCOTI')).resolves.toMatchObject({
      kind: 'private-erc20',
      decimals: 18,
      publicCounterpart: { symbol: 'gCOTI' }
    });
    await expect(gateway.resolveAsset('p.COTI')).resolves.toMatchObject({
      kind: 'private-erc20',
      decimals: 18,
      publicCounterpart: { symbol: 'COTI', address: null }
    });
    await expect(
      gateway.resolveAsset('0x0000000000000000000000000000000000000001')
    ).resolves.toBeNull();
  });

  it('reads a public standard order with canonical price orientation', async () => {
    const manifest = await loadRuntimeManifest();
    const standard = manifest.contracts.standardEscrow!.address.toLowerCase();
    const wisp = manifest.tokens.find((token) => token.symbol === 'WISP')!;
    const gcoti = manifest.tokens.find((token) => token.symbol === 'gCOTI')!;
    const client = {
      readContract: vi.fn(async ({ address, functionName }: { address: string; functionName: string }) => {
        if (address.toLowerCase() === standard && functionName === 'getTradeView') {
          return {
            trade: {
              maker,
              taker: '0x0000000000000000000000000000000000000000',
              status: 1n,
              offerAsset: { assetType: 1n, token: wisp.address, amount: 5_000_000n },
              requestAsset: { assetType: 1n, token: gcoti.address, amount: 10_000_000_000_000_000_000n },
              createdAt: 1_700_000_000n,
              expiresAt: 0n
            },
            metadata: { isPublic: true, accessHash: `0x${'0'.repeat(64)}` },
            fillState: {
              remainingOfferAmount: 4_000_000n,
              remainingRequestAmount: 8_000_000_000_000_000_000n
            },
            effectiveStatus: 1n
          };
        }
        throw new Error('unexpected read');
      })
    };
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client,
      rpc: { request: vi.fn() }
    });
    const result = await gateway.getOrder({
      escrowContract: manifest.contracts.standardEscrow!.address,
      localId: '7'
    });
    expect(result).toMatchObject({
      kind: 'trade',
      access: 'public',
      amountVisibility: 'visible',
      offerAsset: { symbol: 'WISP' },
      requestAsset: { symbol: 'gCOTI' },
      offerAmount: '5',
      requestAmount: '10',
      remainingOfferAmount: '4',
      remainingRequestAmount: '8',
      price: '2',
      priceBasis: 'quote_per_base'
    });
  });

  it('never returns privacy-only amounts from a private order view', async () => {
    const manifest = await loadRuntimeManifest();
    const privateEscrow = manifest.contracts.privateEscrow!.address.toLowerCase();
    const privateWisp = manifest.tokens.find((token) => token.symbol === 'p.WISP')!;
    const gcoti = manifest.tokens.find((token) => token.symbol === 'gCOTI')!;
    const client = {
      readContract: vi.fn(async ({ address, functionName }: { address: string; functionName: string }) => {
        if (address.toLowerCase() === privateEscrow && functionName === 'getTradeView') {
          return {
            trade: {
              maker,
              taker,
              status: 1n,
              offerAsset: { assetType: 2n, token: privateWisp.address, amount: 999_000_000n },
              requestAsset: { assetType: 1n, token: gcoti.address, amount: 888n },
              createdAt: 1_700_000_000n,
              expiresAt: 0n
            },
            metadata: { isPublic: false, accessHash: `0x${'1'.repeat(64)}` },
            fillState: {
              remainingOfferAmount: 777n,
              remainingRequestAmount: 666n
            },
            effectiveStatus: 1n
          };
        }
        throw new Error('unexpected read');
      })
    };
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client,
      rpc: { request: vi.fn() }
    });
    const result = await gateway.getOrder({
      escrowContract: manifest.contracts.privateEscrow!.address,
      localId: '4'
    });
    expect(result).toMatchObject({
      amountVisibility: 'private',
      offerAmount: null,
      requestAmount: null,
      remainingOfferAmount: null,
      remainingRequestAmount: null,
      price: null
    });
    expect(JSON.stringify(result)).not.toContain('999');
    expect(result?.remainingOfferAmount).toBeNull();
  });

  it('returns Carbon as a reference only and never invents executable liquidity', async () => {
    const manifest = await loadRuntimeManifest();
    const client = {
      readContract: vi.fn(async ({ functionName }: { functionName: string }) => {
        if (functionName === 'getPublicDeskPage') return { items: [], nextOffset: 0n };
        throw new Error('unexpected read');
      })
    };
    const fetcher = vi.fn(async (url: URL | string) => {
      const address = new URL(String(url)).searchParams.get('address');
      return new Response(
        JSON.stringify({
          data: { USD: address?.toLowerCase().includes('7637') ? 0.2 : 0.1 }
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    });
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client,
      rpc: { request: vi.fn() },
      fetcher: fetcher as typeof fetch,
      carbonApiUrl: `https://api.carbondefi.xyz/v1/coti${'/'.repeat(250_000)}`,
      now: () => Date.parse('2026-07-27T00:00:00.000Z')
    });
    const base = (await gateway.resolveAsset('gCOTI'))!;
    const quote = (await gateway.resolveAsset('WISP'))!;
    const references = await gateway.getPriceReferences({
      baseAsset: base,
      quoteAsset: quote,
      side: 'buy',
      amount: null
    });
    expect(references).toEqual([
      expect.objectContaining({
        venue: 'carbon',
        source: 'market',
        executable: false,
        liquidityChecked: false
      })
    ]);
    expect(references[0]).not.toHaveProperty('canExecuteAmount', true);
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const [url] of fetcher.mock.calls) {
      expect(String(url)).toMatch(
        /^https:\/\/api\.carbondefi\.xyz\/v1\/coti\/market-rate\?/u
      );
    }
  });

  it('uses native COTI as the verified public counterpart for p.COTI pricing', async () => {
    const manifest = await loadRuntimeManifest();
    const requestedAddresses: string[] = [];
    const fetcher = vi.fn(async (url: URL | string) => {
      const address = new URL(String(url)).searchParams.get('address')!;
      requestedAddresses.push(address);
      return new Response(
        JSON.stringify({
          data: {
            USD: address.toLowerCase() ===
              '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
              ? 0.2
              : 0.1
          }
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    });
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client: { readContract: vi.fn() },
      rpc: { request: vi.fn() },
      fetcher: fetcher as typeof fetch,
      now: () => Date.parse('2026-07-30T00:00:00.000Z')
    });
    const base = (await gateway.resolveAsset('p.WISP'))!;
    const quote = (await gateway.resolveAsset('p.COTI'))!;

    const references = await gateway.getPriceReferences({
      baseAsset: base,
      quoteAsset: quote,
      side: 'buy',
      amount: null
    });

    expect(references).toEqual([
      expect.objectContaining({
        venue: 'carbon',
        price: '0.5',
        note: 'Public-token counterparts were used for this reference.'
      })
    ]);
    expect(requestedAddresses.map((address) => address.toLowerCase())).toEqual(
      expect.arrayContaining([
        manifest.tokens.find(({ symbol }) => symbol === 'WISP')!.address!.toLowerCase(),
        '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
      ])
    );
  });

  it('fails closed when deployed bytecode does not match the runtime manifest', async () => {
    const manifest = await loadRuntimeManifest();
    const registryContracts = Object.fromEntries(
      Object.entries(manifest.contracts).map(([name, contract]) => [name, contract.address])
    );
    const gateway = await createLiveChainWhisperDomainGateway({
      manifest,
      client: {
        readContract: vi.fn(async ({ functionName }: { functionName: string }) => {
          if (functionName === 'getContracts') return registryContracts;
          throw new Error('unexpected read');
        })
      },
      rpc: {
        request: vi.fn(async (method: string) =>
          method === 'eth_blockNumber' ? '0x64' : '0x6000'
        ) as never
      }
    });
    const status = await gateway.getStatus();
    expect(status.ready).toBe(false);
    expect(status.readOnly).toBe(true);
    expect(status.registry.recurringWritesEnabled).toBe(false);
    expect(status.registry.warnings.length).toBeGreaterThan(0);
  });
});
