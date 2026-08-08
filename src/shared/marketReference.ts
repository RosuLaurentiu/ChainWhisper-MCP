export const MARKET_REFERENCE_MAX_AGE_MS = 5 * 60 * 1_000;
export const MARKET_REFERENCE_MAX_FUTURE_SKEW_MS = 30 * 1_000;

export const marketReferenceDeadlineMs = (
  observedAt: string,
  providerExpiresAt?: string | null,
): number | null => {
  const observedAtMs = Date.parse(observedAt);
  if (!Number.isFinite(observedAtMs)) return null;
  let deadline = observedAtMs + MARKET_REFERENCE_MAX_AGE_MS;
  if (providerExpiresAt !== undefined && providerExpiresAt !== null) {
    const providerDeadline = Date.parse(providerExpiresAt);
    if (!Number.isFinite(providerDeadline)) return null;
    deadline = Math.min(deadline, providerDeadline);
  }
  return deadline;
};
