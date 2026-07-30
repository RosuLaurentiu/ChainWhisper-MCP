import { readFileSync } from 'node:fs';

import { formatUnits, parseUnits } from 'viem';

import { canonicalize, sha256Hex } from '../shared/index.js';

export type PolicyAssetMetadata = {
  symbol: string;
  decimals: number;
};

const manifestUrl = new URL('../../runtime/coti-mainnet.v1.json', import.meta.url);

let installedManifest:
  | {
      hash: string;
      assets: Map<string, PolicyAssetMetadata>;
    }
  | undefined;

const loadInstalledManifest = (): typeof installedManifest => {
  if (installedManifest) return installedManifest;
  try {
    const parsed = JSON.parse(readFileSync(manifestUrl, 'utf8')) as {
      tokens?: Array<{
        symbol?: unknown;
        address?: unknown;
        decimals?: unknown;
        kind?: unknown;
      }>;
    };
    if (!Array.isArray(parsed.tokens)) return undefined;
    const assets = new Map<string, PolicyAssetMetadata>();
    for (const token of parsed.tokens) {
      if (
        typeof token.symbol !== 'string' ||
        !Number.isInteger(token.decimals) ||
        Number(token.decimals) < 0 ||
        Number(token.decimals) > 78
      ) {
        return undefined;
      }
      const metadata = {
        symbol: token.symbol,
        decimals: Number(token.decimals),
      };
      assets.set(token.symbol.toLowerCase(), metadata);
      if (
        typeof token.address === 'string' &&
        /^0x[0-9a-fA-F]{40}$/u.test(token.address)
      ) {
        assets.set(token.address.toLowerCase(), metadata);
      }
      if (token.kind === 'native') assets.set('native', metadata);
    }
    installedManifest = {
      hash: sha256Hex(canonicalize(parsed)).toLowerCase(),
      assets,
    };
    return installedManifest;
  } catch {
    return undefined;
  }
};

export const policyAssetMetadata = (
  manifestHash: string,
  asset: string,
): PolicyAssetMetadata | undefined => {
  const manifest = loadInstalledManifest();
  return manifest?.hash === manifestHash.toLowerCase()
    ? manifest.assets.get(asset.toLowerCase())
    : undefined;
};

export const policyAmountDisplay = (
  amount: string,
  metadata: PolicyAssetMetadata | undefined,
): string | undefined => {
  if (!metadata) return undefined;
  try {
    return formatUnits(BigInt(amount), metadata.decimals);
  } catch {
    return undefined;
  }
};

export const policyAmountFromDisplay = (
  value: string,
  decimals: number | undefined,
): string | undefined => {
  if (decimals === undefined || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(value)) {
    return undefined;
  }
  try {
    return parseUnits(value, decimals).toString();
  } catch {
    return undefined;
  }
};

const gcd = (left: bigint, right: bigint): bigint => {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) {
    [a, b] = [b, a % b];
  }
  return a;
};

const reduced = (
  numerator: bigint,
  denominator: bigint,
): { numerator: bigint; denominator: bigint } => {
  const divisor = gcd(numerator, denominator);
  return {
    numerator: numerator / divisor,
    denominator: denominator / divisor,
  };
};

const rationalFromDisplay = (
  value: string,
): { numerator: bigint; denominator: bigint } | undefined => {
  const fraction = /^([1-9][0-9]*)\/([1-9][0-9]*)$/u.exec(value);
  if (fraction) {
    return reduced(BigInt(fraction[1]!), BigInt(fraction[2]!));
  }
  const decimal = /^(?:([0-9]+))(?:\.([0-9]+))?$/u.exec(value);
  if (!decimal) return undefined;
  const fractionDigits = decimal[2] ?? '';
  const numerator = BigInt(`${decimal[1]}${fractionDigits}`);
  if (numerator === 0n) return undefined;
  return reduced(numerator, 10n ** BigInt(fractionDigits.length));
};

const rationalDisplay = (numerator: bigint, denominator: bigint): string => {
  const value = reduced(numerator, denominator);
  let rest = value.denominator;
  let twos = 0;
  let fives = 0;
  while (rest % 2n === 0n) {
    rest /= 2n;
    twos += 1;
  }
  while (rest % 5n === 0n) {
    rest /= 5n;
    fives += 1;
  }
  const digits = Math.max(twos, fives);
  if (rest !== 1n || digits > 18) {
    return `${value.numerator}/${value.denominator}`;
  }
  const scaled =
    (value.numerator * 10n ** BigInt(digits)) / value.denominator;
  if (digits === 0) return scaled.toString();
  const padded = scaled.toString().padStart(digits + 1, '0');
  const whole = padded.slice(0, -digits);
  const fraction = padded.slice(-digits).replace(/0+$/u, '');
  return fraction ? `${whole}.${fraction}` : whole;
};

export const policyPriceDisplay = (
  numerator: string,
  denominator: string,
  sellDecimals?: number,
  buyDecimals?: number,
): string | undefined => {
  try {
    const scaledNumerator =
      BigInt(numerator) *
      10n ** BigInt(sellDecimals ?? 0);
    const scaledDenominator =
      BigInt(denominator) *
      10n ** BigInt(buyDecimals ?? 0);
    if (scaledNumerator <= 0n || scaledDenominator <= 0n) return undefined;
    return rationalDisplay(scaledNumerator, scaledDenominator);
  } catch {
    return undefined;
  }
};

export const policyPriceFromDisplay = (
  value: string,
  sellDecimals?: number,
  buyDecimals?: number,
): { numerator: string; denominator: string } | undefined => {
  const human = rationalFromDisplay(value);
  if (!human) return undefined;
  const atomic = reduced(
    human.numerator * 10n ** BigInt(buyDecimals ?? 0),
    human.denominator * 10n ** BigInt(sellDecimals ?? 0),
  );
  return {
    numerator: atomic.numerator.toString(),
    denominator: atomic.denominator.toString(),
  };
};

export const localDateTimeValue = (iso: string): string => {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return iso;
  const part = (value: number): string => value.toString().padStart(2, '0');
  return `${date.getFullYear()}-${part(date.getMonth() + 1)}-${part(
    date.getDate(),
  )}T${part(date.getHours())}:${part(date.getMinutes())}`;
};

export const policyDuration = (startsAt: string, expiresAt: string): string => {
  const duration = Date.parse(expiresAt) - Date.parse(startsAt);
  if (!Number.isFinite(duration) || duration <= 0) return 'Invalid duration';
  const hours = duration / (60 * 60 * 1_000);
  if (Number.isInteger(hours / 24)) {
    const days = hours / 24;
    return `${days} ${days === 1 ? 'day' : 'days'}`;
  }
  return `${hours.toFixed(hours < 10 ? 1 : 0)} hours`;
};
