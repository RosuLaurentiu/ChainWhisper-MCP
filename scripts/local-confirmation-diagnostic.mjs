import process from 'node:process';

import { LocalWebFormElicitor } from '../dist/signer/index.js';

const elicitor = new LocalWebFormElicitor();
const result = await elicitor.requestConfirmation(
  {
    operationId: 'confirmation-form-diagnostic',
    operationHash: `0x${'00'.repeat(32)}`,
    stepId: 'diagnostic',
    stepIndex: 0,
    stepCount: 1,
    wallet: '0x0000000000000000000000000000000000000000',
    contract: '0x0000000000000000000000000000000000000000',
    action: 'confirmation_form_diagnostic',
    orderType: null,
    orderTypeLabel: 'Not applicable',
    assets: [],
    amounts: [],
    counterparty: null,
    spender: null,
    fee: '0',
    nativeValue: '0',
    gasCap: '0',
    expectedResult: 'No transaction will be prepared, signed, or broadcast.',
    summary: 'Signer-owned local confirmation diagnostic only.',
  },
  120_000,
);

process.stdout.write(`${JSON.stringify(result)}\n`);
