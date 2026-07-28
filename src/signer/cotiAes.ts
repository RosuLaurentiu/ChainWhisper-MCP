const COTI_AES_PATTERN = /^(?:0x)?[0-9a-fA-F]{32}$/u;

export const isCotiAesKey = (
  value: unknown,
): value is string =>
  typeof value === 'string' && COTI_AES_PATTERN.test(value.trim());

export const normalizeCotiAesKey = (value: string): string => {
  const normalized = value.trim().replace(/^0x/u, '').toLowerCase();
  if (!isCotiAesKey(normalized)) {
    throw new Error('COTI AES keys must be exactly 16 bytes.');
  }
  return normalized;
};
