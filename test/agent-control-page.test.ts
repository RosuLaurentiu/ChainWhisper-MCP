import { describe, expect, it } from 'vitest';

import {
  agentControlStateKey,
  renderAgentControlPage,
  type AgentControlPageModel,
} from '../src/signer/localControlPage.js';
import type { ActivityEntryV1 } from '../src/signer/agentActivity.js';

const activityEntry = (
  overrides: Partial<ActivityEntryV1> = {},
): ActivityEntryV1 => ({
  version: 'cw.agent-activity/1',
  id: 'operation:recurring-1',
  source: 'local',
  activityType: 'trade',
  label: 'Create recurring order',
  status: 'confirming',
  updatedAt: '2026-07-30T18:00:00.000Z',
  pair: 'p.WISP / p.COTI',
  orderTypeLabel:
    'Recurring · public access · hidden private inventory',
  access: 'public',
  privacy: 'hidden-liquidity',
  amounts: ['10 p.WISP sell inventory', '10 p.COTI buy budget'],
  prices: [
    '0.0011 p.COTI/p.WISP (+10%)',
    '0.0009 p.COTI/p.WISP (-10%)',
  ],
  fee: '5 COTI + up to 0.48 COTI network',
  operationId: 'recurring-1',
  operationHash: `0x${'33'.repeat(32)}`,
  networkTransactionCount: 3,
  transactionUrls: [
    `https://mainnet.cotiscan.io/tx/0x${'44'.repeat(32)}`,
    `https://mainnet.cotiscan.io/tx/0x${'55'.repeat(32)}`,
  ],
  ...overrides,
});

const model = (
  overrides: Partial<AgentControlPageModel['summary']> = {},
): AgentControlPageModel => ({
  csrfToken: 'csrf-test-token',
  pending: null,
  summary: {
    wallet: '0x1111111111111111111111111111111111111111',
    network: 'COTI Mainnet',
    privacyStatus: 'ready',
    signerStatus: 'ready',
    autonomy: { mode: 'manual' },
    pendingOperations: 1,
    recentOperations: [],
    activity: {
      version: 'cw.agent-activity-page/1',
      recentEntries: [activityEntry()],
      entries: [activityEntry()],
      page: 0,
      pageSize: 20,
      hasPrevious: false,
      hasNext: true,
      refreshedAt: '2026-07-30T18:00:00.000Z',
      revision: 'activity-revision-1',
    },
    walletSetup: {
      required: false,
      environmentFilePath: 'C:\\ChainWhisper\\signer.env',
    },
    ...overrides,
  },
});

describe('Agent Control activity dashboard', () => {
  it('renders merged wallet activity with readable trade terms and paginated history', () => {
    const html = renderAgentControlPage(model(), 'nonce');

    expect(html).toContain('Recent activity');
    expect(html).toContain(
      'Signer actions and wallet-wide ChainWhisper trades',
    );
    expect(html).toContain('p.WISP / p.COTI');
    expect(html).toContain('10 p.WISP sell inventory');
    expect(html).toContain('0.0011 p.COTI/p.WISP (+10%)');
    expect(html).toContain('Full history');
    expect(html).toContain('value="history-next"');
    expect(html).not.toContain(
      activityEntry().operationHash,
    );
  });

  it('keeps order progress beside the dashboard after the single confirmation', () => {
    const html = renderAgentControlPage(
      model({ focusedOperationId: 'recurring-1' }),
      'nonce',
    );

    expect(html).toContain('Order progress');
    expect(html).toContain('Confirming on-chain');
    expect(html).toContain(
      '2 of 3 network transactions submitted',
    );
    expect(html).toContain(
      'One approval authorizes the complete order',
    );
    expect(html).toContain(
      'value="dismiss-focused-operation"',
    );
    expect(html).toContain('Wallet balances');
  });

  it('changes the SSE state key when activity or focus changes', () => {
    const first = model();
    const second = model({
      focusedOperationId: 'recurring-1',
      activity: {
        ...first.summary.activity!,
        revision: 'activity-revision-2',
      },
    });

    expect(agentControlStateKey(first)).not.toBe(
      agentControlStateKey(second),
    );
  });
});
