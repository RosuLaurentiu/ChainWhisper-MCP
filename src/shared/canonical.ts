import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';

import {
  ACTION_ENVELOPE_VERSION,
  CHAINWHISPER_CHAIN_ID,
  type ActionEnvelopeV1,
  type HexString,
  type PairingSignatureV1,
  type SignedActionEnvelopeV1
} from './protocol.js';

type JsonPrimitive = boolean | null | number | string;
export type CanonicalJsonValue = JsonPrimitive | CanonicalJsonValue[] | { [key: string]: CanonicalJsonValue };

const normalizeJson = (value: unknown): CanonicalJsonValue => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonical JSON cannot contain non-finite numbers.');
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeJson);
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const normalized = Object.create(null) as Record<
      string,
      CanonicalJsonValue
    >;
    return Object.keys(record)
      .sort()
      .reduce<Record<string, CanonicalJsonValue>>((result, key) => {
        const entry = record[key];
        if (entry !== undefined) {
          result[key] = normalizeJson(entry);
        }
        return result;
      }, normalized);
  }
  throw new Error(`Unsupported canonical JSON value: ${typeof value}.`);
};

export const canonicalize = (value: unknown): string => JSON.stringify(normalizeJson(value));

export const sha256Hex = (value: string | Uint8Array): HexString =>
  `0x${createHash('sha256').update(value).digest('hex')}`;

export const hmacSha256Hex = (secret: string | Uint8Array, value: string): HexString =>
  `0x${createHmac('sha256', secret).update(value).digest('hex')}`;

const unsignedEnvelope = (
  envelope: ActionEnvelopeV1 | SignedActionEnvelopeV1
): ActionEnvelopeV1 => {
  const { pairingSignature: _pairingSignature, ...unsigned } = envelope as SignedActionEnvelopeV1;
  return unsigned;
};

const envelopeForHash = (envelope: ActionEnvelopeV1): Omit<ActionEnvelopeV1, 'operationHash'> => {
  const { operationHash: _operationHash, ...hashable } = envelope;
  return hashable;
};

export const computeActionEnvelopeHash = (envelope: ActionEnvelopeV1): HexString =>
  sha256Hex(canonicalize(envelopeForHash(envelope)));

export const finalizeActionEnvelope = (
  draft: Omit<ActionEnvelopeV1, 'operationHash' | 'operationId' | 'version' | 'chainId'> & {
    operationId?: string;
  }
): ActionEnvelopeV1 => {
  const envelope: ActionEnvelopeV1 = {
    ...draft,
    version: ACTION_ENVELOPE_VERSION,
    operationId: draft.operationId ?? randomUUID(),
    operationHash: '0x',
    chainId: CHAINWHISPER_CHAIN_ID
  };
  return {
    ...envelope,
    operationHash: computeActionEnvelopeHash(envelope)
  };
};

export const signActionEnvelope = (
  envelope: ActionEnvelopeV1,
  pairingSecret: string
): SignedActionEnvelopeV1 => {
  if (!pairingSecret || pairingSecret.length < 32) {
    throw new Error('CHAINWHISPER_PAIRING_SECRET must contain at least 32 characters.');
  }
  if (computeActionEnvelopeHash(envelope) !== envelope.operationHash) {
    throw new Error('Cannot sign an action envelope with an invalid operation hash.');
  }
  const pairingSignature: PairingSignatureV1 = {
    algorithm: 'hmac-sha256',
    digest: hmacSha256Hex(pairingSecret, canonicalize(envelope))
  };
  return { ...envelope, pairingSignature };
};

const constantTimeHexEqual = (left: string, right: string): boolean => {
  try {
    const leftBytes = Buffer.from(left.replace(/^0x/u, ''), 'hex');
    const rightBytes = Buffer.from(right.replace(/^0x/u, ''), 'hex');
    return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
  } catch {
    return false;
  }
};

export const verifySignedActionEnvelope = (
  envelope: SignedActionEnvelopeV1,
  pairingSecret: string,
  now = new Date()
): { ok: true; envelope: ActionEnvelopeV1 } | { ok: false; error: string } => {
  if (envelope.version !== ACTION_ENVELOPE_VERSION || envelope.chainId !== CHAINWHISPER_CHAIN_ID) {
    return { ok: false, error: 'unsupported-envelope' };
  }
  const unsigned = unsignedEnvelope(envelope);
  if (computeActionEnvelopeHash(unsigned) !== envelope.operationHash) {
    return { ok: false, error: 'operation-hash-mismatch' };
  }
  if (
    envelope.pairingSignature?.algorithm !== 'hmac-sha256' ||
    !constantTimeHexEqual(
      envelope.pairingSignature.digest,
      hmacSha256Hex(pairingSecret, canonicalize(unsigned))
    )
  ) {
    return { ok: false, error: 'pairing-signature-invalid' };
  }
  const expiry = Date.parse(envelope.expiresAt);
  const issuedAt = Date.parse(envelope.issuedAt);
  if (!Number.isFinite(expiry) || !Number.isFinite(issuedAt) || issuedAt > expiry) {
    return { ok: false, error: 'invalid-envelope-time' };
  }
  if (now.getTime() >= expiry) {
    return { ok: false, error: 'envelope-expired' };
  }
  return { ok: true, envelope: unsigned };
};
