import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  ACTION_ENVELOPE_VERSION,
  CHAINWHISPER_CHAIN_ID,
  canonicalize,
  containsSensitiveMaterial,
  finalizeActionEnvelope,
  getOrCreatePairingSecret,
  loadRuntimeManifest,
  signActionEnvelope,
  verifySignedActionEnvelope,
  type ActionEnvelopeV1
} from '../src/shared/index.js';

const ADDRESS = '0x1111111111111111111111111111111111111111' as const;
const HASH = `0x${'22'.repeat(32)}` as const;
const PAIRING_SECRET = 'pairing-secret-that-is-at-least-thirty-two-characters';

const draftEnvelope = (): Omit<
  ActionEnvelopeV1,
  'operationHash' | 'operationId' | 'version' | 'chainId'
> => ({
  wallet: ADDRESS,
  registrySnapshot: {
    registryAddress: ADDRESS,
    registryBytecodeHash: HASH,
    manifestHash: HASH,
    observedBlock: '123',
    contracts: {},
    fees: {}
  },
  issuedAt: '2026-07-27T12:00:00.000Z',
  expiresAt: '2026-07-27T12:15:00.000Z',
  intent: {
    action: 'fill',
    order: { escrowContract: ADDRESS, localId: '5' }
  },
  steps: [],
  exactNativeValue: '0',
  fee: { recipient: ADDRESS, amount: '0', asset: 'native' },
  gasCap: '500000',
  privateInputs: [],
  secretPolicy: {
    accessMode: 'public',
    generatedLocally: false,
    mayLeaveSigner: false,
    sharing: 'none'
  },
  simulation: {
    status: 'passed',
    checkedAt: '2026-07-27T12:00:00.000Z',
    blockNumber: '123'
  },
  summary: 'Fill ChainWhisper order #5.'
});

describe('shared ActionEnvelopeV1 protocol', () => {
  it('canonicalizes object keys deterministically', () => {
    expect(canonicalize({ z: 1, a: { y: 2, x: 3 } })).toBe('{"a":{"x":3,"y":2},"z":1}');
  });

  it('canonicalizes prototype-shaped keys without mutating or omitting them', () => {
    const input = JSON.parse(
      '{"constructor":"safe","__proto__":{"polluted":true}}'
    ) as Record<string, unknown>;

    expect(canonicalize(input)).toBe(
      '{"__proto__":{"polluted":true},"constructor":"safe"}'
    );
    expect(
      (Object.prototype as { polluted?: boolean }).polluted
    ).toBeUndefined();
  });

  it('binds every envelope field to its operation hash and pairing signature', () => {
    const signed = signActionEnvelope(finalizeActionEnvelope(draftEnvelope()), PAIRING_SECRET);
    expect(signed.version).toBe(ACTION_ENVELOPE_VERSION);
    expect(signed.chainId).toBe(CHAINWHISPER_CHAIN_ID);
    expect(
      verifySignedActionEnvelope(signed, PAIRING_SECRET, new Date('2026-07-27T12:05:00.000Z')).ok
    ).toBe(true);

    const tampered = {
      ...signed,
      exactNativeValue: '1'
    };
    expect(
      verifySignedActionEnvelope(tampered, PAIRING_SECRET, new Date('2026-07-27T12:05:00.000Z'))
    ).toEqual({ ok: false, error: 'operation-hash-mismatch' });
  });

  it('rejects expired envelopes and the wrong pairing secret', () => {
    const signed = signActionEnvelope(finalizeActionEnvelope(draftEnvelope()), PAIRING_SECRET);
    expect(
      verifySignedActionEnvelope(signed, 'different-secret-that-is-also-long-enough', new Date('2026-07-27T12:05:00.000Z'))
    ).toEqual({ ok: false, error: 'pairing-signature-invalid' });
    expect(
      verifySignedActionEnvelope(signed, PAIRING_SECRET, new Date('2026-07-27T12:15:00.000Z'))
    ).toEqual({ ok: false, error: 'envelope-expired' });
  });

  it('allows public hashes and configuration flags while rejecting credential fields', () => {
    expect(
      containsSensitiveMaterial({
        operationHash: HASH,
        transactionHash: HASH,
        pairingSignature: { algorithm: 'hmac-sha256', digest: HASH },
        aesConfigured: true,
        pairingConfigured: true,
        secretPolicy: { sharing: 'none' }
      })
    ).toBe(false);
    expect(containsSensitiveMaterial({ privateKey: HASH })).toBe(true);
    expect(containsSensitiveMaterial({ aes_key: HASH })).toBe(true);
    expect(containsSensitiveMaterial({ pairingSecret: 'not-for-output' })).toBe(true);
    expect(containsSensitiveMaterial({ vaultPassphrase: 'not-for-output' })).toBe(true);
    expect(
      containsSensitiveMaterial(
        'test test test test test test test test test test test junk'
      )
    ).toBe(true);
    expect(
      containsSensitiveMaterial(
        'This normal human-readable transaction summary contains more than twelve words and remains safe.'
      )
    ).toBe(false);
  });

  it('creates and reuses one private local pairing secret without returning it in a tool schema', async () => {
    const stateDirectory = await mkdtemp(join(tmpdir(), 'chainwhisper-pairing-'));
    const first = await getOrCreatePairingSecret({ environment: {}, stateDirectory });
    const second = await getOrCreatePairingSecret({ environment: {}, stateDirectory });
    expect(first).toHaveLength(43);
    expect(second).toBe(first);
    expect((await readFile(join(stateDirectory, 'pairing.key'), 'utf8')).trim()).toBe(first);
  });

  it('loads the deployed COTI Mainnet contract and verified-token manifest', async () => {
    const manifest = await loadRuntimeManifest();
    expect(manifest.network.chainId).toBe(CHAINWHISPER_CHAIN_ID);
    expect(manifest.contracts.recurringEscrow?.selectors.fillBuySideWithSecret).toBe('0x451903f0');
    expect(manifest.contracts.recurringEscrow?.selectors.fillPrivateSellSideWithSecret).toBe('0x25c2920e');
    expect(manifest.tokens.find((token) => token.symbol === 'WISP')).toMatchObject({
      kind: 'erc20',
      decimals: 6
    });
    expect(manifest.tokens.find((token) => token.symbol === 'p.WISP')).toMatchObject({
      kind: 'private-erc20',
      decimals: 6,
      publicCounterpart: 'WISP'
    });
  });
});
