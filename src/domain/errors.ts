import type { ToolFailureCode, ToolResult } from './types.js';

export class DomainInputError extends Error {
  readonly code: ToolFailureCode;
  readonly details: Array<{ field: string; message: string }>;

  constructor(
    message: string,
    details: Array<{ field: string; message: string }> = [],
    code: ToolFailureCode = 'invalid_input'
  ) {
    super(message);
    this.name = 'DomainInputError';
    this.code = code;
    this.details = details;
  }
}

export const toolFailure = (
  error: unknown,
  fallbackMessage = 'The ChainWhisper request could not be completed.'
): ToolResult<never> => {
  if (error instanceof DomainInputError) {
    return {
      ok: false,
      error: {
        code: error.code,
        message: error.message,
        ...(error.details.length > 0 ? { details: error.details } : {})
      }
    };
  }
  return {
    ok: false,
    error: {
      code: 'provider_error',
      message: error instanceof Error && error.message ? error.message : fallbackMessage
    }
  };
};
