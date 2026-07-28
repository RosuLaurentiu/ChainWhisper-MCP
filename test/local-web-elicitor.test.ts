import { describe, expect, it } from 'vitest';

import {
  LocalWebFormElicitor,
  type ConfirmationRequest,
} from '../src/signer/index.js';

const CONFIRMATION: ConfirmationRequest = {
  operationId: 'diagnostic',
  operationHash: `0x${'00'.repeat(32)}`,
  stepId: 'diagnostic',
  stepIndex: 0,
  stepCount: 1,
  wallet: '0x1111111111111111111111111111111111111111',
  contract: '0x0000000000000000000000000000000000000000',
  action: 'confirmation_form_diagnostic',
  orderType: null,
  orderTypeLabel: 'Not applicable',
  assets: [],
  amounts: [],
  counterparty: null,
  fee: '0',
  nativeValue: '0',
  gasCap: '0',
  expectedResult: 'No write.',
  summary: 'Diagnostic.',
};

const postingElicitor = (body: string): LocalWebFormElicitor =>
  new LocalWebFormElicitor({
    openUrl: (url) => {
      setTimeout(() => {
        void fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body,
        });
      }, 0);
    },
  });

describe('local web form elicitor', () => {
  it('accepts an explicitly checked confirmation without writing', async () => {
    await expect(
      postingElicitor('action=confirm&confirm=yes').requestConfirmation(
        CONFIRMATION,
        5_000,
      ),
    ).resolves.toEqual({ outcome: 'accepted' });
  });

  it('collects private decimal values only through the local form', async () => {
    await expect(
      postingElicitor(
        'action=confirm&sellBaseLiquidity=12.5',
      ).requestPrivateValues(
        {
          operationId: 'operation-1',
          operationHash: `0x${'11'.repeat(32)}`,
          wallet: CONFIRMATION.wallet,
          fields: [
            {
              id: 'sellBaseLiquidity',
              title: 'Private p.WISP inventory',
              description: 'Amount available to recurring sells.',
              kind: 'decimal-amount',
            },
          ],
        },
        5_000,
      ),
    ).resolves.toEqual({
      outcome: 'accepted',
      values: { sellBaseLiquidity: '12.5' },
    });
  });

  it('returns an explicit decline without requiring form values', async () => {
    await expect(
      postingElicitor('action=decline').requestConfirmation(
        CONFIRMATION,
        5_000,
      ),
    ).resolves.toMatchObject({
      outcome: 'declined',
      reason: 'client-declined',
    });
  });
});
