import type { DecimalString } from './types.js';

const DECIMAL_PATTERN = /^(?:0|[1-9]\d*)(?:\.\d+)?$/u;
export const MAX_DECIMAL_INPUT_LENGTH = 160;

export type ParsedDecimal = {
  coefficient: bigint;
  scale: number;
};

export const parseDecimal = (value: unknown): ParsedDecimal | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (
    trimmed.length > MAX_DECIMAL_INPUT_LENGTH ||
    !DECIMAL_PATTERN.test(trimmed)
  ) {
    return null;
  }
  const [whole, fraction = ''] = trimmed.split('.');
  return {
    coefficient: BigInt(`${whole}${fraction}`),
    scale: fraction.length
  };
};

export const isPositiveDecimal = (value: unknown, maxScale = 78): value is DecimalString => {
  const parsed = parseDecimal(value);
  return Boolean(parsed && parsed.coefficient > 0n && parsed.scale <= maxScale);
};

export const isNonNegativeDecimal = (value: unknown, maxScale = 78): value is DecimalString => {
  const parsed = parseDecimal(value);
  return Boolean(parsed && parsed.coefficient >= 0n && parsed.scale <= maxScale);
};

export const canonicalDecimal = (value: string): DecimalString => {
  const parsed = parseDecimal(value);
  if (!parsed) throw new TypeError('Expected a non-negative decimal string.');
  if (parsed.scale === 0) return parsed.coefficient.toString();
  const digits = parsed.coefficient.toString().padStart(parsed.scale + 1, '0');
  const whole = digits.slice(0, -parsed.scale);
  const fraction = digits.slice(-parsed.scale).replace(/0+$/u, '');
  return fraction ? `${whole}.${fraction}` : whole;
};

export const compareDecimals = (left: string, right: string): number => {
  const a = parseDecimal(left);
  const b = parseDecimal(right);
  if (!a || !b) throw new TypeError('Cannot compare invalid decimal strings.');
  const scale = Math.max(a.scale, b.scale);
  const aValue = a.coefficient * 10n ** BigInt(scale - a.scale);
  const bValue = b.coefficient * 10n ** BigInt(scale - b.scale);
  return aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
};

export const invertDecimal = (value: string, precision = 24): DecimalString => {
  const parsed = parseDecimal(value);
  if (!parsed || parsed.coefficient <= 0n) throw new TypeError('Cannot invert a non-positive decimal.');
  const numerator = 10n ** BigInt(precision + parsed.scale);
  const quotient = numerator / parsed.coefficient;
  const digits = quotient.toString().padStart(precision + 1, '0');
  const whole = digits.slice(0, -precision);
  const fraction = digits.slice(-precision).replace(/0+$/u, '');
  return canonicalDecimal(fraction ? `${whole}.${fraction}` : whole);
};

export const multiplyDecimals = (left: string, right: string): DecimalString => {
  const a = parseDecimal(left);
  const b = parseDecimal(right);
  if (!a || !b) throw new TypeError('Cannot multiply invalid decimal strings.');
  const scale = a.scale + b.scale;
  const coefficient = a.coefficient * b.coefficient;
  if (scale === 0) return coefficient.toString();
  const digits = coefficient.toString().padStart(scale + 1, '0');
  return canonicalDecimal(`${digits.slice(0, -scale)}.${digits.slice(-scale)}`);
};

export const divideDecimals = (numerator: string, denominator: string, precision = 24): DecimalString => {
  const a = parseDecimal(numerator);
  const b = parseDecimal(denominator);
  if (!a || !b || b.coefficient <= 0n) throw new TypeError('Cannot divide invalid decimal strings.');
  const scaledNumerator = a.coefficient * 10n ** BigInt(precision + b.scale);
  const scaledDenominator = b.coefficient * 10n ** BigInt(a.scale);
  const quotient = scaledNumerator / scaledDenominator;
  const digits = quotient.toString().padStart(precision + 1, '0');
  return canonicalDecimal(`${digits.slice(0, -precision)}.${digits.slice(-precision)}`);
};
