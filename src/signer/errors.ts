export type SignerErrorCode =
  | 'CONFIGURATION_REQUIRED'
  | 'CONFIRMATION_DECLINED'
  | 'CONFIRMATION_TIMEOUT'
  | 'ELICITATION_UNSUPPORTED'
  | 'ENVELOPE_EXPIRED'
  | 'ENVELOPE_INVALID'
  | 'ENVELOPE_TAMPERED'
  | 'EXACT_ALLOWANCE_REQUIRED'
  | 'FEE_CHANGED'
  | 'OPERATION_DISCARDED'
  | 'OPERATION_IN_PROGRESS'
  | 'OPERATION_NOT_FOUND'
  | 'PAIRING_FAILED'
  | 'PRIVATE_INPUT_UNAVAILABLE'
  | 'REGISTRY_CHANGED'
  | 'SIGNER_ALREADY_RUNNING'
  | 'SIGNER_LOCK_OWNERSHIP_LOST'
  | 'STALE_STATE'
  | 'TRANSACTION_FAILED'
  | 'UNSAFE_MESSAGE'
  | 'UNSUPPORTED_TOOL'
  | 'WALLET_MISMATCH'
  | 'WRITE_UNAVAILABLE';

export class SignerError extends Error {
  readonly code: SignerErrorCode;

  constructor(code: SignerErrorCode, message: string) {
    super(message);
    this.name = 'SignerError';
    this.code = code;
  }
}

export const asSignerErrorCode = (error: unknown): SignerErrorCode =>
  error instanceof SignerError ? error.code : 'TRANSACTION_FAILED';
