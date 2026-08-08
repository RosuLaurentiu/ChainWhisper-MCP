import { validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

export const MCP_SAFE_ERROR = Symbol('chainwhisper.mcp-safe-error');

export interface McpSafeError extends Error {
  readonly [MCP_SAFE_ERROR]: true;
}

export const isMcpSafeError = (error: unknown): error is McpSafeError =>
  error instanceof Error &&
  (error as Partial<McpSafeError>)[MCP_SAFE_ERROR] === true;

const normalizeKey = (key: string): string =>
  key.toLowerCase().replace(/[^a-z0-9]/gu, '');

const SENSITIVE_KEYS = new Set([
  'privatekey',
  'signingkey',
  'mnemonic',
  'seed',
  'seedphrase',
  'aeskey',
  'userkey',
  'accesssecret',
  'pairingsecret',
  'rawsecret',
  'vaultpassphrase',
  'password',
  'apikey',
  'authtoken',
  'bearer',
  'credential',
  'signature'
]);

const SENSITIVE_VALUE_PATTERNS = [
  /\b(?:sk|pk)_[a-z0-9_-]{20,}\b/iu
];
const ERROR_SENSITIVE_VALUE_PATTERNS = [
  ...SENSITIVE_VALUE_PATTERNS,
  /\b0x[0-9a-f]{64}\b/iu
];

const isSensitiveKey = (key: string): boolean =>
  SENSITIVE_KEYS.has(normalizeKey(key));

const containsValidMnemonic = (value: string): boolean => {
  const words = value.toLowerCase().match(/[a-z]+/gu) ?? [];
  for (const wordCount of [12, 15, 18, 21, 24]) {
    for (let offset = 0; offset + wordCount <= words.length; offset += 1) {
      if (validateMnemonic(words.slice(offset, offset + wordCount).join(' '), wordlist)) {
        return true;
      }
    }
  }
  return false;
};

export const containsSensitiveMaterial = (value: unknown): boolean => {
  if (typeof value === 'string') {
    return (
      containsValidMnemonic(value) ||
      SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(value))
    );
  }
  if (Array.isArray(value)) {
    return value.some(containsSensitiveMaterial);
  }
  if (value && typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).some(
      ([key, entry]) =>
        (isSensitiveKey(key) && entry !== undefined && entry !== null && entry !== '') ||
        containsSensitiveMaterial(entry)
    );
  }
  return false;
};

export const assertNoSensitiveMaterial = (value: unknown, label = 'output'): void => {
  if (containsSensitiveMaterial(value)) {
    throw new Error(`${label} contains credential or secret material.`);
  }
};

export const redactError = (error: unknown): string => {
  const message = error instanceof Error ? error.message : String(error);
  if (
    containsValidMnemonic(message) ||
    ERROR_SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(message))
  ) {
    return 'redacted-error';
  }
  return message.replace(/[\r\n\t]+/gu, ' ').slice(0, 240);
};
