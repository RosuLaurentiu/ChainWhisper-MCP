import type {
  ActionStepV1,
  NormalizedAssetV1,
  PrivateArtifactGroupV1,
  PrivateArtifactValueV1,
  PrivateInputPlaceholderV1,
  SignedActionEnvelopeV1,
} from '../shared/index.js';
import { isHexAddress, isHexData } from '../shared/index.js';
import { prepareIT256, type itUint256 } from '@coti-io/coti-sdk-typescript';
import type { Wallet } from '@coti-io/coti-ethers';
import {
  encodeFunctionData,
  formatUnits,
  keccak256,
  parseUnits,
  parseAbi,
  toFunctionSelector,
  type Abi,
} from 'viem';
import {
  createCipheriv,
  createHash,
  hkdfSync,
  randomBytes,
} from 'node:crypto';

import type {
  Address,
  HexString,
  MaterializedActionStep,
  PrivateInputMaterializer,
  PrivateValueElicitor,
  PrivateValueField,
} from './types.js';
import {
  isCotiAesKey,
  normalizeCotiAesKey,
} from './cotiAes.js';
import { SignerError } from './errors.js';
import { EncryptedSecretVault } from './vault.js';

export type EncodedPrivateUint256 = unknown;

export interface CotiPrivateUint256Encoder {
  encodePrivateUint256(input: {
    decimalValue: string,
    contractAddress: HexString,
    functionSelector: HexString,
  }): Promise<EncodedPrivateUint256>;
}

export type MaterializedPrivateValue =
  | {
      id: string;
      kind: 'itUint256';
      jsonPointer: string;
      encoded: EncodedPrivateUint256;
    }
  | {
      id: string;
      kind: 'access-secret' | 'encrypted-recovery-note';
      jsonPointer: string;
      secret: string;
    }
  | {
      id: string;
      kind: 'raw';
      jsonPointer: string;
      value: string;
    };

export interface StepCalldataMaterializer {
  materialize(
    step: ActionStepV1,
    replacements: MaterializedPrivateValue[],
  ): Promise<HexString>;
}

type CotiPreparedInput = {
  ciphertext: {
    ciphertextHigh: bigint;
    ciphertextLow: bigint;
  };
  signature: string | Uint8Array;
};

const bytesToHex = (value: Uint8Array): HexString =>
  `0x${Buffer.from(value).toString('hex')}`;

const normalizePreparedInput = (
  value: itUint256 | CotiPreparedInput,
): CotiPreparedInput => ({
  ciphertext: {
    ciphertextHigh: BigInt(value.ciphertext.ciphertextHigh),
    ciphertextLow: BigInt(value.ciphertext.ciphertextLow),
  },
  signature:
    typeof value.signature === 'string'
      ? value.signature
      : bytesToHex(value.signature),
});

export class CotiSdkPrivateUint256Encoder
  implements CotiPrivateUint256Encoder
{
  readonly #wallet: Wallet;
  readonly #fallbackAesKey: string;

  constructor(wallet: Wallet, aesKey: string) {
    this.#wallet = wallet;
    this.#fallbackAesKey = aesKey;
  }

  async encodePrivateUint256(input: {
    decimalValue: string;
    contractAddress: HexString;
    functionSelector: HexString;
  }): Promise<CotiPreparedInput> {
    if (
      !/^(?:0|[1-9][0-9]*)$/u.test(input.decimalValue) ||
      !isHexAddress(input.contractAddress) ||
      !/^0x[0-9a-fA-F]{8}$/u.test(input.functionSelector)
    ) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'Private uint256 binding is invalid.',
      );
    }
    const aesKey =
      this.#wallet.getUserOnboardInfo()?.aesKey ??
      this.#fallbackAesKey;
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The official COTI account AES key is unavailable. Run chainwhisper_onboard_privacy first.',
      );
    }
    return normalizePreparedInput(
      prepareIT256(
        BigInt(input.decimalValue),
        {
          wallet: this.#wallet,
          userKey: normalizeCotiAesKey(aesKey),
        },
        input.contractAddress,
        input.functionSelector,
      ),
    );
  }
}

const decodeJsonPointer = (pointer: string): string[] =>
  pointer
    .slice(1)
    .split('/')
    .map((part) => part.replace(/~1/gu, '/').replace(/~0/gu, '~'));

const replaceAtJsonPointer = (
  root: Record<string, unknown>,
  pointer: string,
  value: unknown,
): void => {
  if (!pointer.startsWith('/arguments/')) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Private inputs may only replace signed call-template arguments.',
    );
  }
  const path = decodeJsonPointer(pointer);
  let current: unknown = root;
  for (let index = 0; index < path.length - 1; index += 1) {
    const part = path[index];
    if (part === undefined) {
      throw new SignerError('ENVELOPE_INVALID', 'Invalid JSON pointer.');
    }
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(part)) {
        throw new SignerError('ENVELOPE_INVALID', 'Invalid array JSON pointer.');
      }
      current = current[Number(part)];
    } else if (current && typeof current === 'object') {
      current = (current as Record<string, unknown>)[part];
    } else {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private input JSON pointer does not resolve.',
      );
    }
  }
  const finalPart = path.at(-1);
  if (finalPart === undefined) {
    throw new SignerError('ENVELOPE_INVALID', 'Invalid JSON pointer.');
  }
  if (Array.isArray(current)) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(finalPart)) {
      throw new SignerError('ENVELOPE_INVALID', 'Invalid array JSON pointer.');
    }
    const targetIndex = Number(finalPart);
    if (targetIndex >= current.length) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private input JSON pointer is out of range.',
      );
    }
    current[targetIndex] = value;
    return;
  }
  if (current && typeof current === 'object' && finalPart in current) {
    (current as Record<string, unknown>)[finalPart] = value;
    return;
  }
  throw new SignerError(
    'ENVELOPE_INVALID',
    'Private input JSON pointer does not resolve.',
  );
};

const toAbiReplacement = (replacement: MaterializedPrivateValue): unknown => {
  if (replacement.kind === 'raw') return replacement.value;
  if (replacement.kind !== 'itUint256') return replacement.secret;
  const encoded = replacement.encoded as CotiPreparedInput;
  if (
    !encoded ||
    !encoded.ciphertext ||
    encoded.signature === undefined
  ) {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'COTI private uint256 encoding failed.',
    );
  }
  return [
    [
      BigInt(encoded.ciphertext.ciphertextHigh),
      BigInt(encoded.ciphertext.ciphertextLow),
    ],
    typeof encoded.signature === 'string'
      ? encoded.signature
      : bytesToHex(encoded.signature),
  ];
};

export class AbiCallTemplateMaterializer
  implements StepCalldataMaterializer
{
  async materialize(
    step: ActionStepV1,
    replacements: MaterializedPrivateValue[],
  ): Promise<HexString> {
    const template = step.callTemplate;
    if (!template || !template.functionSignature.trim()) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private action step is missing its signed call template.',
      );
    }
    const expectedSelector = toFunctionSelector(template.functionSignature);
    if (
      step.data.slice(0, 10).toLowerCase() !== expectedSelector.toLowerCase()
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Call template does not match the signed function selector.',
      );
    }
    const materializedTemplate = structuredClone({
      functionSignature: template.functionSignature,
      arguments: template.arguments,
    }) as {
      functionSignature: string;
      arguments: unknown[];
    };
    for (const replacement of replacements) {
      replaceAtJsonPointer(
        materializedTemplate as unknown as Record<string, unknown>,
        replacement.jsonPointer,
        toAbiReplacement(replacement),
      );
    }
    let abi: Abi;
    try {
      const parseRuntimeAbi = parseAbi as unknown as (
        signatures: readonly string[],
      ) => Abi;
      abi = parseRuntimeAbi([
        `function ${materializedTemplate.functionSignature}`,
      ]);
    } catch {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Call template function signature is invalid.',
      );
    }
    const functionName = materializedTemplate.functionSignature.slice(
      0,
      materializedTemplate.functionSignature.indexOf('('),
    );
    const data = encodeFunctionData({
      abi,
      functionName,
      args: materializedTemplate.arguments,
    });
    if (
      !isHexData(data) ||
      data.slice(0, 10).toLowerCase() !== expectedSelector.toLowerCase()
    ) {
      throw new SignerError(
        'ENVELOPE_TAMPERED',
        'Materialized calldata changed the signed function selector.',
      );
    }
    return data;
  }
}

const secretReference = (
  envelope: SignedActionEnvelopeV1,
  placeholder: PrivateInputPlaceholderV1,
): string => `${envelope.operationHash}:${placeholder.id}`;

const ZERO_ADDRESS =
  '0x0000000000000000000000000000000000000000';
const MAX_UINT256 = (1n << 256n) - 1n;
const ARTIFACT_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/u;

type ResolvedArtifactValue = {
  id: string;
  kind: 'uint256' | 'access-secret';
  value: string;
  asset?: NormalizedAssetV1;
  displayAmount?: string;
};

type ResolvedArtifactSet = {
  values: Map<string, ResolvedArtifactValue>;
  displayAmounts: Array<{ id: string; amount: string; symbol: string }>;
};

const artifactReference = (
  envelope: SignedActionEnvelopeV1,
  id: string,
): string => `${envelope.operationHash}:artifact:${id}`;

export const ORDER_ACCESS_SECRET_ID = 'order-access-secret' as const;

export const generatedAccessSecretReference = (
  operationHash: HexString,
  id: string = ORDER_ACCESS_SECRET_ID,
): string => `${operationHash}:${id}`;

export const orderAccessSecretReference = (
  recipient: Address,
  escrowContract: Address,
  localId: string,
  id: string = ORDER_ACCESS_SECRET_ID,
): string =>
  `order:${recipient.toLowerCase()}:${escrowContract.toLowerCase()}:${localId}:${id}`;

const legacyOrderArtifactReference = (
  envelope: SignedActionEnvelopeV1,
  id: string,
): string | null => {
  const order = envelope.intent.order;
  return order
    ? `order:${order.escrowContract.toLowerCase()}:${order.localId}:${id}`
    : null;
};

const sameAsset = (
  left: NormalizedAssetV1 | undefined,
  right: NormalizedAssetV1 | undefined,
): boolean =>
  Boolean(
    left &&
      right &&
      left.kind === right.kind &&
      left.decimals === right.decimals &&
      left.reference === right.reference &&
      (left.address ?? '').toLowerCase() ===
        (right.address ?? '').toLowerCase(),
  );

const atomicAmount = (
  decimalValue: string,
  asset: NormalizedAssetV1,
  allowZero = false,
): string => {
  if (asset.decimals === undefined) {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'Private amount precision is unavailable.',
    );
  }
  try {
    const value = parseUnits(decimalValue, asset.decimals);
    if ((allowZero ? value < 0n : value <= 0n) || value > MAX_UINT256) {
      throw new Error('range');
    }
    return value.toString();
  } catch {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'A signer-local amount cannot be represented exactly as uint256 base units.',
    );
  }
};

const normalizeAccessSecret = (value: string): HexString => {
  const normalized = value.trim();
  if (
    !/^0x[0-9a-fA-F]{64}$/u.test(normalized) ||
    /^0x0{64}$/u.test(normalized)
  ) {
    throw new SignerError(
      'PRIVATE_INPUT_UNAVAILABLE',
      'A private order access secret must be a non-zero 32-byte value.',
    );
  }
  return normalized.toLowerCase() as HexString;
};

export type StoredAccessSecretV1 = {
  version: 1;
  operationHash: HexString;
  recipient: Address | null;
  escrowContract: Address;
  localId: string | null;
  secret: HexString;
};

export const encodeStoredAccessSecret = (
  value: StoredAccessSecretV1,
): string => {
  const normalized: StoredAccessSecretV1 = {
    version: 1,
    operationHash: value.operationHash.toLowerCase() as HexString,
    recipient: value.recipient
      ? (value.recipient.toLowerCase() as Address)
      : null,
    escrowContract: value.escrowContract.toLowerCase() as Address,
    localId: value.localId,
    secret: normalizeAccessSecret(value.secret),
  };
  return JSON.stringify(normalized);
};

export const decodeStoredAccessSecret = (
  value: string,
): StoredAccessSecretV1 | null => {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (
      parsed.version !== 1 ||
      !isHexData(parsed.operationHash) ||
      parsed.operationHash.length !== 66 ||
      (parsed.recipient !== null && !isHexAddress(parsed.recipient)) ||
      !isHexAddress(parsed.escrowContract) ||
      (parsed.localId !== null &&
        (typeof parsed.localId !== 'string' ||
          !/^(?:0|[1-9][0-9]*)$/u.test(parsed.localId))) ||
      typeof parsed.secret !== 'string' ||
      !/^0x[0-9a-fA-F]{64}$/u.test(parsed.secret) ||
      /^0x0{64}$/u.test(parsed.secret)
    ) {
      return null;
    }
    return {
      version: 1,
      operationHash: parsed.operationHash.toLowerCase() as HexString,
      recipient:
        parsed.recipient === null
          ? null
          : (parsed.recipient.toLowerCase() as Address),
      escrowContract: parsed.escrowContract.toLowerCase() as Address,
      localId: parsed.localId as string | null,
      secret: parsed.secret.toLowerCase() as HexString,
    };
  } catch {
    return null;
  }
};

const encryptAesGcm = (
  plaintext: string,
  key: Buffer,
): HexString => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  return `0x${Buffer.concat([
    Buffer.from([1]),
    iv,
    ciphertext,
    cipher.getAuthTag(),
  ]).toString('hex')}`;
};

const tradeAssetPayload = (
  asset: NormalizedAssetV1,
  amount: string,
): Record<string, string> => ({
  kind: asset.kind,
  ...(asset.address ? { tokenAddress: asset.address } : {}),
  amount,
});

const unixExpiry = (envelope: SignedActionEnvelopeV1): number => {
  if (!envelope.intent.expiresAt) return 0;
  const milliseconds = Date.parse(envelope.intent.expiresAt);
  if (!Number.isFinite(milliseconds) || milliseconds <= 0) {
    throw new SignerError(
      'ENVELOPE_INVALID',
      'Private order expiry is invalid.',
    );
  }
  return Math.floor(milliseconds / 1_000);
};

export class VaultBackedPrivateInputMaterializer
  implements PrivateInputMaterializer
{
  static readonly MAX_CACHED_ARTIFACT_RESOLUTIONS = 128;

  readonly #vault: EncryptedSecretVault;
  readonly #privateUint256: CotiPrivateUint256Encoder;
  readonly #calldata: StepCalldataMaterializer;
  readonly #elicitor: PrivateValueElicitor;
  readonly #aesKey: () => string;
  readonly #timeoutMs: number;
  readonly #assertPrivateSpendReady?: (input: {
    token: Address;
    spender: Address;
    amount: string;
  }) => Promise<void>;
  readonly #artifactResolutions = new Map<
    string,
    Promise<ResolvedArtifactSet>
  >();
  readonly #settledArtifactResolutions = new Set<string>();

  constructor(options: {
    vault: EncryptedSecretVault;
    privateUint256: CotiPrivateUint256Encoder;
    calldata: StepCalldataMaterializer;
    elicitor: PrivateValueElicitor;
    aesKey: () => string;
    timeoutMs: number;
    assertPrivateSpendReady?: (input: {
      token: Address;
      spender: Address;
      amount: string;
    }) => Promise<void>;
  }) {
    this.#vault = options.vault;
    this.#privateUint256 = options.privateUint256;
    this.#calldata = options.calldata;
    this.#elicitor = options.elicitor;
    this.#aesKey = options.aesKey;
    this.#timeoutMs = options.timeoutMs;
    this.#assertPrivateSpendReady =
      options.assertPrivateSpendReady;
  }

  async #resolvePlaceholder(
    envelope: SignedActionEnvelopeV1,
    placeholder: PrivateInputPlaceholderV1,
  ): Promise<MaterializedPrivateValue> {
    if (!placeholder.jsonPointer.startsWith('/')) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private input destination must be a JSON pointer.',
      );
    }
    if (placeholder.kind === 'itUint256') {
      let decimalValue = placeholder.decimalValue;
      if (!decimalValue) {
        decimalValue =
          (await this.#vault.get(secretReference(envelope, placeholder))) ??
          undefined;
      }
      if (!decimalValue || !/^(?:0|[1-9][0-9]*)$/u.test(decimalValue)) {
        throw new SignerError(
          'PRIVATE_INPUT_UNAVAILABLE',
          'A private uint256 value is not available in the local signer vault.',
        );
      }
      const step = envelope.steps.find(
        (candidate) => candidate.id === placeholder.bindToStepId,
      );
      const functionSelector = step?.data.slice(0, 10);
      if (
        !step ||
        !isHexAddress(step.to) ||
        !functionSelector ||
        !/^0x[0-9a-fA-F]{8}$/u.test(functionSelector)
      ) {
        throw new SignerError(
          'PRIVATE_INPUT_UNAVAILABLE',
          'Private input is not bound to a valid contract selector.',
        );
      }
      const encoded = await this.#privateUint256.encodePrivateUint256({
        decimalValue,
        contractAddress: step.to,
        functionSelector: functionSelector as HexString,
      });
      return {
        id: placeholder.id,
        kind: 'itUint256',
        jsonPointer: placeholder.jsonPointer,
        encoded,
      };
    }

    const reference = secretReference(envelope, placeholder);
    if (
      placeholder.source === 'generated-local' &&
      !(await this.#vault.has(reference))
    ) {
      const order = envelope.intent.order;
      const recipient = envelope.intent.recipient;
      if (
        placeholder.kind === 'access-secret' &&
        order &&
        recipient
      ) {
        await this.#vault.createAccessSecret(reference, {
          operationHash: envelope.operationHash,
          recipient,
          escrowContract: order.escrowContract,
          localId: order.localId,
        });
      } else if (placeholder.kind === 'access-secret') {
        throw new SignerError(
          'PRIVATE_INPUT_UNAVAILABLE',
          'Generated access secrets require an exact order and recipient binding.',
        );
      } else {
        await this.#vault.put(reference, `0x${randomBytes(32).toString('hex')}`, {
          kind: 'recovery-note',
          binding: { operationHash: envelope.operationHash },
        });
      }
    }
    const secret = await this.#vault.get(reference);
    if (!secret) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The required local secret is unavailable.',
      );
    }
    return {
      id: placeholder.id,
      kind: placeholder.kind,
      jsonPointer: placeholder.jsonPointer,
      secret,
    };
  }

  #valueDefinitions(
    envelope: SignedActionEnvelopeV1,
  ): Map<string, PrivateArtifactValueV1> {
    const definitions = new Map<string, PrivateArtifactValueV1>();
    for (const group of envelope.privateArtifacts ?? []) {
      for (const value of group.values) {
        if (!ARTIFACT_ID_PATTERN.test(value.id)) {
          throw new SignerError(
            'ENVELOPE_INVALID',
            'Private artifact identifiers are invalid.',
          );
        }
        const existing = definitions.get(value.id);
        if (
          existing &&
          (
            existing.kind !== value.kind ||
            existing.source !== value.source ||
            !sameAsset(existing.asset, value.asset) ||
            Boolean(existing.allowZero) !== Boolean(value.allowZero)
          )
        ) {
          throw new SignerError(
            'ENVELOPE_TAMPERED',
            'A shared private artifact has conflicting definitions.',
          );
        }
        definitions.set(value.id, value);
      }
    }
    return definitions;
  }

  #signedDecimal(
    envelope: SignedActionEnvelopeV1,
    value: PrivateArtifactValueV1,
  ): string | null {
    if (value.source === 'intent-sell-amount') {
      return envelope.intent.sellAmount ?? null;
    }
    if (value.source === 'intent-buy-amount') {
      return envelope.intent.buyAmount ?? null;
    }
    if (value.source === 'trusted-order-visible-amount') {
      const trusted = envelope.intent.metadata?.trustedOrderSellAmount;
      return typeof trusted === 'string'
        ? trusted
        : envelope.intent.sellAmount ?? null;
    }
    if (value.source === 'recurring-sell-base-liquidity') {
      const liquidity =
        envelope.intent.metadata?.sellBaseLiquidity;
      return typeof liquidity === 'string' ? liquidity : null;
    }
    if (value.source === 'recurring-buy-quote-liquidity') {
      const liquidity =
        envelope.intent.metadata?.buyQuoteLiquidity;
      return typeof liquidity === 'string' ? liquidity : null;
    }
    return null;
  }

  async #resolveArtifacts(
    envelope: SignedActionEnvelopeV1,
  ): Promise<ResolvedArtifactSet> {
    const definitions = this.#valueDefinitions(envelope);
    const values = new Map<string, ResolvedArtifactValue>();
    const pendingFields: PrivateValueField[] = [];

    for (const definition of definitions.values()) {
      const reference = artifactReference(envelope, definition.id);
      const cached = await this.#vault.get(reference);
      if (cached) {
        values.set(definition.id, {
          id: definition.id,
          kind: definition.kind,
          value: cached,
          ...(definition.asset ? { asset: definition.asset } : {}),
          ...(definition.kind === 'uint256' && definition.asset
            ? {
                displayAmount: formatUnits(
                  BigInt(cached),
                  definition.asset.decimals ?? 0,
                ),
              }
            : {}),
        });
        continue;
      }

      const signedDecimal = this.#signedDecimal(envelope, definition);
      if (signedDecimal !== null) {
        if (!definition.asset || definition.kind !== 'uint256') {
          throw new SignerError(
            'ENVELOPE_INVALID',
            'A signed amount artifact is missing its asset binding.',
          );
        }
        const atomic = atomicAmount(
          signedDecimal,
          definition.asset,
          definition.allowZero,
        );
        await this.#vault.put(reference, atomic, {
          kind: 'private-uint256',
          binding: { operationHash: envelope.operationHash },
        });
        values.set(definition.id, {
          id: definition.id,
          kind: 'uint256',
          value: atomic,
          asset: definition.asset,
          displayAmount: signedDecimal,
        });
        continue;
      }

      if (
        definition.source === 'constant-zero' &&
        definition.kind === 'uint256' &&
        definition.asset
      ) {
        await this.#vault.put(reference, '0', {
          kind: 'private-uint256',
          binding: { operationHash: envelope.operationHash },
        });
        values.set(definition.id, {
          id: definition.id,
          kind: 'uint256',
          value: '0',
          asset: definition.asset,
          displayAmount: '0',
        });
        continue;
      }

      if (
        definition.source === 'generated-local' &&
        definition.kind === 'access-secret'
      ) {
        const secret = `0x${randomBytes(32).toString('hex')}`;
        await this.#vault.put(reference, secret, {
          kind: 'access-secret',
          binding: { operationHash: envelope.operationHash },
        });
        values.set(definition.id, {
          id: definition.id,
          kind: 'access-secret',
          value: secret,
        });
        continue;
      }

      if (
        definition.source === 'local-order-vault' &&
        definition.kind === 'access-secret'
      ) {
        const order = envelope.intent.order;
        const orderReference = order
          ? orderAccessSecretReference(
              envelope.wallet as Address,
              order.escrowContract as Address,
              order.localId,
              definition.id,
            )
          : null;
        const storedOrderSecret = orderReference
          ? await this.#vault.get(orderReference)
          : null;
        const boundOrderSecret = storedOrderSecret
          ? decodeStoredAccessSecret(storedOrderSecret)
          : null;
        if (
          storedOrderSecret &&
          (!boundOrderSecret ||
            !order ||
            boundOrderSecret.recipient?.toLowerCase() !==
              envelope.wallet.toLowerCase() ||
            boundOrderSecret.escrowContract.toLowerCase() !==
              order.escrowContract.toLowerCase() ||
            boundOrderSecret.localId !== order.localId)
        ) {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'The stored order access secret is not bound to this wallet and exact order.',
          );
        }
        const legacyReference = legacyOrderArtifactReference(
          envelope,
          definition.id,
        );
        const legacySecret =
          !storedOrderSecret && legacyReference
            ? await this.#vault.get(legacyReference)
            : null;
        const orderSecret =
          boundOrderSecret?.secret ??
          (legacySecret &&
          /^0x[0-9a-fA-F]{64}$/u.test(legacySecret) &&
          !/^0x0{64}$/u.test(legacySecret)
            ? legacySecret.toLowerCase()
            : null);
        if (orderSecret) {
          values.set(definition.id, {
            id: definition.id,
            kind: 'access-secret',
            value: orderSecret,
          });
          continue;
        }
        pendingFields.push({
          id: definition.id,
          title: 'Private order access secret',
          description:
            'Enter the 32-byte secret from the private order link. It stays inside the local encrypted signer vault.',
          kind: 'access-secret',
        });
        continue;
      }

      if (
        definition.source === 'signer-elicitation' &&
        definition.kind === 'uint256' &&
        definition.asset
      ) {
        pendingFields.push({
          id: definition.id,
          title: `${definition.id.replaceAll('-', ' ')} (${definition.asset.symbol ?? definition.asset.reference})`,
          description:
            definition.allowZero
              ? 'Enter a non-negative decimal amount. It is converted to exact base units only inside the local signer.'
              : 'Enter a positive decimal amount. It is converted to exact base units only inside the local signer.',
          kind: 'decimal-amount',
        });
        continue;
      }

      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'A required private artifact value cannot be resolved safely.',
      );
    }

    if (pendingFields.length) {
      if (!this.#elicitor.isSupported()) {
        throw new SignerError(
          'ELICITATION_UNSUPPORTED',
          'The MCP client cannot collect signer-local private values.',
        );
      }
      const result = await this.#elicitor.requestPrivateValues(
        {
          operationId: envelope.operationId,
          operationHash: envelope.operationHash,
          wallet: envelope.wallet as Address,
          fields: pendingFields,
        },
        this.#timeoutMs,
      );
      if (result.outcome === 'timeout') {
        throw new SignerError(
          'CONFIRMATION_TIMEOUT',
          'Private value entry timed out.',
        );
      }
      if (result.outcome !== 'accepted') {
        throw new SignerError(
          'CONFIRMATION_DECLINED',
          'Private value entry was declined.',
        );
      }
      for (const field of pendingFields) {
        const definition = definitions.get(field.id)!;
        const supplied = result.values[field.id];
        if (!supplied) {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'A signer-local private value was omitted.',
          );
        }
        const resolved =
          definition.kind === 'access-secret'
            ? normalizeAccessSecret(supplied)
            : definition.asset
              ? atomicAmount(
                  supplied,
                  definition.asset,
                  definition.allowZero,
                )
              : null;
        if (!resolved) {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'A signer-local private amount has no asset binding.',
          );
        }
        const reference = artifactReference(envelope, definition.id);
        await this.#vault.put(reference, resolved, {
          kind:
            definition.kind === 'access-secret'
              ? 'access-secret'
              : 'private-uint256',
          binding: { operationHash: envelope.operationHash },
        });
        const order = envelope.intent.order;
        const orderReference =
          definition.kind === 'access-secret' && order
            ? orderAccessSecretReference(
                envelope.wallet as Address,
                order.escrowContract as Address,
                order.localId,
                definition.id,
              )
            : null;
        if (orderReference && order) {
          await this.#vault.put(
            orderReference,
            encodeStoredAccessSecret({
              version: 1,
              operationHash: envelope.operationHash,
              recipient: envelope.wallet as Address,
              escrowContract: order.escrowContract as Address,
              localId: order.localId,
              secret: resolved as HexString,
            }),
            {
              kind: 'access-secret',
              binding: {
                operationHash: envelope.operationHash,
                recipient: envelope.wallet,
                escrowContract: order.escrowContract,
                localId: order.localId,
              },
            },
          );
        }
        values.set(definition.id, {
          id: definition.id,
          kind: definition.kind,
          value: resolved,
          ...(definition.asset ? { asset: definition.asset } : {}),
          ...(definition.kind === 'uint256'
            ? { displayAmount: supplied }
            : {}),
        });
      }
    }

    for (const group of envelope.privateArtifacts ?? []) {
      const required = group.context?.requirePositiveValueIds;
      if (typeof required === 'string' && required.trim()) {
        const ids = required
          .split(',')
          .map((id) => id.trim())
          .filter(Boolean);
        if (
          !ids.length ||
          ids.every((id) => {
            const value = values.get(id);
            return (
              !value ||
              value.kind !== 'uint256' ||
              BigInt(value.value) <= 0n
            );
          })
        ) {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'At least one signer-confirmed recurring inventory side must be positive.',
          );
        }
      }
      const exclusive = group.context?.mutuallyExclusiveValueIds;
      if (typeof exclusive !== 'string' || !exclusive.trim()) continue;
      for (const pair of exclusive.split(',')) {
        const [leftId, rightId, extra] = pair
          .split(':')
          .map((id) => id.trim());
        if (!leftId || !rightId || extra) {
          throw new SignerError(
            'ENVELOPE_INVALID',
            'A recurring edit contains an invalid exclusive-value binding.',
          );
        }
        const left = values.get(leftId);
        const right = values.get(rightId);
        if (
          left?.kind === 'uint256' &&
          right?.kind === 'uint256' &&
          BigInt(left.value) > 0n &&
          BigInt(right.value) > 0n
        ) {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'A recurring edit cannot add and remove the same private inventory side.',
          );
        }
      }
    }

    return {
      values,
      displayAmounts: [...values.values()]
        .filter(
          (
            value,
          ): value is ResolvedArtifactValue & {
            asset: NormalizedAssetV1;
            displayAmount: string;
          } => Boolean(value.asset && value.displayAmount),
        )
        .map((value) => ({
          id: value.id,
          amount: value.displayAmount,
          symbol: value.asset.symbol ?? value.asset.reference,
        })),
    };
  }

  async #persistGeneratedAccessSecretShares(
    envelope: SignedActionEnvelopeV1,
    step: ActionStepV1,
    groups: readonly PrivateArtifactGroupV1[],
    resolved: ResolvedArtifactSet,
  ): Promise<void> {
    for (const group of groups) {
      for (const definition of group.values) {
        if (
          definition.id !== ORDER_ACCESS_SECRET_ID ||
          definition.kind !== 'access-secret' ||
          definition.source !== 'generated-local'
        ) {
          continue;
        }
        const secret = resolved.values.get(definition.id);
        if (!secret || secret.kind !== 'access-secret') {
          throw new SignerError(
            'PRIVATE_INPUT_UNAVAILABLE',
            'The generated order access secret is unavailable.',
          );
        }
        const reference = generatedAccessSecretReference(
          envelope.operationHash,
          definition.id,
        );
        const record: StoredAccessSecretV1 = {
          version: 1,
          operationHash: envelope.operationHash,
          recipient: (envelope.intent.recipient as Address | undefined) ?? null,
          escrowContract: step.to as Address,
          localId: null,
          secret: normalizeAccessSecret(secret.value),
        };
        const existing = await this.#vault.get(reference);
        if (existing) {
          const decoded = decodeStoredAccessSecret(existing);
          if (
            !decoded ||
            decoded.operationHash !== record.operationHash.toLowerCase() ||
            decoded.recipient?.toLowerCase() !==
              record.recipient?.toLowerCase() ||
            decoded.escrowContract.toLowerCase() !==
              record.escrowContract.toLowerCase() ||
            decoded.localId !== null ||
            decoded.secret !== record.secret
          ) {
            throw new SignerError(
              'ENVELOPE_TAMPERED',
              'The generated access-secret share binding changed.',
            );
          }
          continue;
        }
        await this.#vault.put(reference, encodeStoredAccessSecret(record), {
          kind: 'access-secret',
          binding: {
            operationHash: envelope.operationHash,
            ...(record.recipient ? { recipient: record.recipient } : {}),
            escrowContract: step.to,
          },
        });
      }
    }
  }

  #allArtifacts(
    envelope: SignedActionEnvelopeV1,
  ): Promise<ResolvedArtifactSet> {
    const existing = this.#artifactResolutions.get(envelope.operationHash);
    if (existing) return existing;
    this.#pruneArtifactResolutions(
      VaultBackedPrivateInputMaterializer.MAX_CACHED_ARTIFACT_RESOLUTIONS -
        1,
    );
    if (
      this.#artifactResolutions.size >=
      VaultBackedPrivateInputMaterializer.MAX_CACHED_ARTIFACT_RESOLUTIONS
    ) {
      throw new SignerError(
        'WRITE_UNAVAILABLE',
        'Too many private artifact operations are active; wait for an existing operation to finish.',
      );
    }
    const resolution = this.#resolveArtifacts(envelope);
    this.#artifactResolutions.set(envelope.operationHash, resolution);
    void resolution.then(
      () => this.#markArtifactResolutionSettled(envelope.operationHash),
      () => this.#markArtifactResolutionSettled(envelope.operationHash),
    );
    return resolution;
  }

  #markArtifactResolutionSettled(operationHash: string): void {
    this.#settledArtifactResolutions.add(operationHash);
    this.#pruneArtifactResolutions(
      VaultBackedPrivateInputMaterializer.MAX_CACHED_ARTIFACT_RESOLUTIONS,
    );
  }

  #pruneArtifactResolutions(maximum: number): void {
    if (this.#artifactResolutions.size <= maximum) return;
    for (const operationHash of this.#artifactResolutions.keys()) {
      if (!this.#settledArtifactResolutions.has(operationHash)) continue;
      this.#artifactResolutions.delete(operationHash);
      this.#settledArtifactResolutions.delete(operationHash);
      if (this.#artifactResolutions.size <= maximum) return;
    }
  }

  #requiredValue(
    values: Map<string, ResolvedArtifactValue>,
    id: string,
  ): ResolvedArtifactValue {
    const value = values.get(id);
    if (!value) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        `The private artifact ${id} is unavailable.`,
      );
    }
    return value;
  }

  #directTermsPayload(
    envelope: SignedActionEnvelopeV1,
    values: Map<string, ResolvedArtifactValue>,
  ): HexString {
    const secret = normalizeAccessSecret(
      this.#requiredValue(values, 'order-access-secret').value,
    );
    const sellAsset =
      envelope.intent.sellAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private order sell asset is missing.',
        );
      })();
    const buyAsset =
      envelope.intent.buyAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private order buy asset is missing.',
        );
      })();
    const offer =
      values.get('offer-amount') ??
      values.get('hidden-offer-amount');
    const request =
      values.get('request-amount') ??
      values.get('hidden-request-amount');
    if (!offer || !request) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'Private order terms are incomplete.',
      );
    }
    const parentEscrowContract =
      typeof envelope.intent.metadata?.parentEscrowContract === 'string'
        ? envelope.intent.metadata.parentEscrowContract
        : null;
    const parentTradeIdText =
      typeof envelope.intent.metadata?.parentTradeId === 'string'
        ? envelope.intent.metadata.parentTradeId
        : null;
    const parentTradeId =
      parentTradeIdText && /^(?:0|[1-9][0-9]*)$/u.test(parentTradeIdText)
        ? Number(parentTradeIdText)
        : null;
    if (
      parentTradeIdText &&
      (
        !Number.isSafeInteger(parentTradeId) ||
        Number(parentTradeId) <= 0 ||
        !parentEscrowContract
      )
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Private counter parent metadata is invalid.',
      );
    }
    const terms = JSON.stringify({
      version: 1,
      maker: envelope.wallet,
      taker: envelope.intent.recipient ?? ZERO_ADDRESS,
      offer: tradeAssetPayload(sellAsset, offer.value),
      request: tradeAssetPayload(buyAsset, request.value),
      expiresAt: unixExpiry(envelope),
      ...(parentEscrowContract && parentTradeId
        ? { parentEscrowContract, parentTradeId }
        : {}),
    });
    const key = Buffer.from(
      hkdfSync(
        'sha256',
        Buffer.from(secret.slice(2), 'hex'),
        Buffer.from('ChainWhisperDirectTermsV1', 'utf8'),
        Buffer.from('direct-trade-terms', 'utf8'),
        32,
      ),
    );
    return encryptAesGcm(terms, key);
  }

  #tradeRecoveryPayload(
    envelope: SignedActionEnvelopeV1,
    values: Map<string, ResolvedArtifactValue>,
  ): HexString {
    const sellAsset =
      envelope.intent.sellAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private recovery sell asset is missing.',
        );
      })();
    const buyAsset =
      envelope.intent.buyAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Private recovery buy asset is missing.',
        );
      })();
    const offer = this.#requiredValue(values, 'hidden-offer-amount');
    const request = this.#requiredValue(values, 'hidden-request-amount');
    const accessSecret = values.get('order-access-secret')?.value;
    const recovery = JSON.stringify({
      version: 1,
      kind: 'private-order',
      ...(accessSecret
        ? { accessSecret: normalizeAccessSecret(accessSecret) }
        : {}),
      maker: envelope.wallet,
      taker: envelope.intent.recipient ?? ZERO_ADDRESS,
      offer: tradeAssetPayload(sellAsset, offer.value),
      request: tradeAssetPayload(buyAsset, request.value),
      expiresAt: unixExpiry(envelope),
    });
    const aesKey = this.#aesKey().trim();
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The official wallet AES key is unavailable for private order recovery.',
      );
    }
    return encryptAesGcm(
      recovery,
      createHash('sha256')
        .update(
          `ChainWhisperTradeRecoveryV1:${normalizeCotiAesKey(aesKey)}`,
          'utf8',
        )
        .digest(),
    );
  }

  #recurringRecoveryPayload(
    envelope: SignedActionEnvelopeV1,
    values: Map<string, ResolvedArtifactValue>,
  ): HexString {
    const baseAsset =
      envelope.intent.sellAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Recurring recovery base asset is missing.',
        );
      })();
    const quoteAsset =
      envelope.intent.buyAsset ??
      (() => {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'Recurring recovery quote asset is missing.',
        );
      })();
    const buyPrice = envelope.intent.metadata?.buyPrice;
    const sellPrice = envelope.intent.metadata?.sellPrice;
    if (
      typeof buyPrice !== 'string' ||
      typeof sellPrice !== 'string' ||
      baseAsset.decimals === undefined ||
      quoteAsset.decimals === undefined
    ) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Recurring recovery price terms are missing.',
      );
    }
    const baseUnit = 10n ** BigInt(baseAsset.decimals);
    const buyQuote = parseUnits(buyPrice, quoteAsset.decimals);
    const sellQuote = parseUnits(sellPrice, quoteAsset.decimals);
    const baseInventory = this.#requiredValue(
      values,
      'recurring-base-inventory',
    );
    const quoteInventory = this.#requiredValue(
      values,
      'recurring-quote-inventory',
    );
    const recovery = JSON.stringify({
      version: 1,
      kind: 'recurring-order',
      maker: envelope.wallet,
      taker: envelope.intent.recipient ?? ZERO_ADDRESS,
      baseAsset: tradeAssetPayload(baseAsset, '0'),
      quoteAsset: tradeAssetPayload(quoteAsset, '0'),
      buyTerms: {
        baseAmount: baseUnit.toString(),
        quoteAmount: buyQuote.toString(),
      },
      sellTerms: {
        baseAmount: baseUnit.toString(),
        quoteAmount: sellQuote.toString(),
      },
      initialBaseInventory: baseInventory.value,
      initialQuoteInventory: quoteInventory.value,
    });
    const aesKey = this.#aesKey().trim();
    if (!isCotiAesKey(aesKey)) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The official wallet AES key is unavailable for recurring order recovery.',
      );
    }
    return encryptAesGcm(
      recovery,
      createHash('sha256')
        .update(
          `ChainWhisperTradeRecoveryV1:${normalizeCotiAesKey(aesKey)}`,
          'utf8',
        )
        .digest(),
    );
  }

  async #groupReplacements(
    envelope: SignedActionEnvelopeV1,
    step: ActionStepV1,
    group: PrivateArtifactGroupV1,
    resolved: ResolvedArtifactSet,
  ): Promise<{
    replacements: MaterializedPrivateValue[];
    privateAllowance?: string;
  }> {
    let directTerms: HexString | null = null;
    if (
      group.outputs.some(
        (output) =>
          output.kind === 'direct-terms-v1' ||
          output.kind === 'terms-hash-v1',
      )
    ) {
      directTerms = this.#directTermsPayload(envelope, resolved.values);
    }
    let privateAllowance: string | undefined;
    const replacements: MaterializedPrivateValue[] = [];
    for (const output of group.outputs) {
      if (output.kind === 'direct-terms-v1') {
        replacements.push({
          id: `${group.id}:direct-terms`,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: directTerms!,
        });
        continue;
      }
      if (output.kind === 'terms-hash-v1') {
        replacements.push({
          id: `${group.id}:terms-hash`,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: keccak256(directTerms!),
        });
        continue;
      }
      if (output.kind === 'trade-recovery-v1') {
        replacements.push({
          id: `${group.id}:trade-recovery`,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: this.#tradeRecoveryPayload(envelope, resolved.values),
        });
        continue;
      }
      if (output.kind === 'recurring-recovery-v1') {
        replacements.push({
          id: `${group.id}:recurring-recovery`,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: this.#recurringRecoveryPayload(
            envelope,
            resolved.values,
          ),
        });
        continue;
      }
      if (!output.valueId) {
        throw new SignerError(
          'ENVELOPE_INVALID',
          'A private artifact output is missing its value binding.',
        );
      }
      const value = this.#requiredValue(
        resolved.values,
        output.valueId,
      );
      if (output.kind === 'uint256') {
        replacements.push({
          id: output.valueId,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: value.value,
        });
        continue;
      }
      if (output.kind === 'keccak256') {
        replacements.push({
          id: output.valueId,
          kind: 'raw',
          jsonPointer: output.jsonPointer,
          value: keccak256(normalizeAccessSecret(value.value)),
        });
        continue;
      }
      if (
        output.kind === 'itUint256' ||
        output.kind === 'coti-private-exact-allowance'
      ) {
        const decimalValue =
          value.kind === 'access-secret'
            ? BigInt(normalizeAccessSecret(value.value)).toString()
            : value.value;
        const encoded = await this.#privateUint256.encodePrivateUint256({
          decimalValue,
          contractAddress: step.to,
          functionSelector: step.data.slice(0, 10) as HexString,
        });
        replacements.push({
          id: output.valueId,
          kind: 'itUint256',
          jsonPointer: output.jsonPointer,
          encoded,
        });
        if (output.kind === 'coti-private-exact-allowance') {
          privateAllowance = value.value;
        }
        continue;
      }
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'The signer cannot derive this private artifact output.',
      );
    }
    return { replacements, privateAllowance };
  }

  async materializeStep(
    envelope: SignedActionEnvelopeV1,
    stepIndex: number,
  ): Promise<MaterializedActionStep> {
    const step = envelope.steps[stepIndex];
    if (!step) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Action step index is out of range.',
      );
    }
    const placeholders = envelope.privateInputs.filter(
      (placeholder) => placeholder.bindToStepId === step.id,
    );
    const replacements = await Promise.all(
      placeholders.map((placeholder) =>
        this.#resolvePlaceholder(envelope, placeholder),
      ),
    );
    const resolved = await this.#allArtifacts(envelope);
    const artifactGroups = (envelope.privateArtifacts ?? []).filter(
      (group) => group.bindToStepId === step.id,
    );
    let resolvedPrivateAllowance: string | undefined;
    for (const group of artifactGroups) {
      const materialized = await this.#groupReplacements(
        envelope,
        step,
        group,
        resolved,
      );
      replacements.push(...materialized.replacements);
      resolvedPrivateAllowance ??= materialized.privateAllowance;
    }
    if (step.kind === 'protocol') {
      await this.#persistGeneratedAccessSecretShares(
        envelope,
        step,
        artifactGroups,
        resolved,
      );
    }
    if (
      resolvedPrivateAllowance &&
      step.allowance?.scheme === 'coti-private-exact'
    ) {
      if (!this.#assertPrivateSpendReady) {
        throw new SignerError(
          'PRIVATE_INPUT_UNAVAILABLE',
          'Private-token readiness checks are not configured.',
        );
      }
      await this.#assertPrivateSpendReady({
        token: step.allowance.token.toLowerCase() as Address,
        spender: step.allowance.spender.toLowerCase() as Address,
        amount: resolvedPrivateAllowance,
      });
    }
    const data = replacements.length
      ? await this.#calldata.materialize(step, replacements)
      : step.data;
    return {
      ...step,
      data,
      approval: step.allowance
        ? {
            ...step.allowance,
            ...(resolvedPrivateAllowance
              ? { amount: resolvedPrivateAllowance }
              : {}),
          }
        : undefined,
      privateValues: Object.fromEntries(
        [...resolved.values.entries()].map(([id, value]) => [
          id,
          value.value,
        ]),
      ),
      privateDisplayAmounts: resolved.displayAmounts,
    };
  }
}

export class PassthroughPrivateInputMaterializer
  implements PrivateInputMaterializer
{
  async materializeStep(
    envelope: SignedActionEnvelopeV1,
    stepIndex: number,
  ): Promise<MaterializedActionStep> {
    const step = envelope.steps[stepIndex];
    if (!step) {
      throw new SignerError(
        'ENVELOPE_INVALID',
        'Action step index is out of range.',
      );
    }
    if (
      envelope.privateInputs.some(
        (placeholder) => placeholder.bindToStepId === step.id,
      )
    ) {
      throw new SignerError(
        'PRIVATE_INPUT_UNAVAILABLE',
        'Private input support has not been configured.',
      );
    }
    return { ...step, approval: step.allowance };
  }
}
