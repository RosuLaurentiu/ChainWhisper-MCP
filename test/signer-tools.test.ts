import { describe, expect, it } from 'vitest';

import type { SignedActionEnvelopeV1 } from '../src/shared/index.js';
import {
  ChainWhisperSignerService,
  createSignerTools,
} from '../src/signer/index.js';

const SIGNED = {
  version: 'cw.action/1',
  operationId: 'operation-1',
  operationHash: `0x${'11'.repeat(32)}`,
  expiresAt: '2026-07-28T13:30:00.000Z',
  summary: 'Create a test order.',
  pairingSignature: {
    algorithm: 'hmac-sha256',
    digest: `0x${'22'.repeat(32)}`,
  },
} as unknown as SignedActionEnvelopeV1;

const executeTool = (
  executeAction: (envelope: SignedActionEnvelopeV1) => Promise<unknown>,
) => {
  const tools = createSignerTools({
    executeAction,
    messaging: { listTools: () => [] },
  } as unknown as ChainWhisperSignerService);
  const tool = tools.find(
    (candidate) => candidate.name === 'chainwhisper_execute_action',
  );
  if (!tool) throw new Error('execute tool missing');
  return tool;
};

describe('signer execute tool envelope handoff', () => {
  it('exposes a read-only confirmation-form diagnostic', async () => {
    const tools = createSignerTools({
      testConfirmationForm: async () => ({
        supported: true,
        outcome: 'accepted',
        writeAttempted: false,
      }),
      messaging: { listTools: () => [] },
    } as unknown as ChainWhisperSignerService);
    const tool = tools.find(
      (candidate) =>
        candidate.name === 'chainwhisper_test_confirmation_form',
    );

    expect(tool?.annotations).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
    });
    await expect(tool?.execute({})).resolves.toEqual({
      supported: true,
      outcome: 'accepted',
      writeAttempted: false,
    });
  });

  it('accepts the exact prepared-envelope wrapper returned by the planner', async () => {
    let received: SignedActionEnvelopeV1 | null = null;
    const tool = executeTool(async (envelope) => {
      received = envelope;
      return { status: 'declined' };
    });

    await expect(
      tool.execute({
        envelope: {
          version: 'ActionEnvelopeV1',
          operationId: SIGNED.operationId,
          operationHash: SIGNED.operationHash,
          expiresAt: SIGNED.expiresAt,
          summary: SIGNED.summary,
          payload: SIGNED,
        },
      }),
    ).resolves.toEqual({ status: 'declined' });
    expect(received).toBe(SIGNED);
  });

  it('continues to accept a raw signed payload', async () => {
    let received: SignedActionEnvelopeV1 | null = null;
    const tool = executeTool(async (envelope) => {
      received = envelope;
      return { status: 'declined' };
    });

    await tool.execute({ envelope: SIGNED });
    expect(received).toBe(SIGNED);
  });

  it('rejects a wrapper whose operation binding differs from its payload', async () => {
    const tool = executeTool(async () => ({ status: 'declined' }));

    await expect(
      tool.execute({
        envelope: {
          version: 'ActionEnvelopeV1',
          operationId: 'different-operation',
          operationHash: SIGNED.operationHash,
          expiresAt: SIGNED.expiresAt,
          summary: SIGNED.summary,
          payload: SIGNED,
        },
      }),
    ).rejects.toMatchObject({
      code: 'ENVELOPE_INVALID',
      message:
        'The prepared envelope wrapper does not match its signed payload.',
    });
  });
});
