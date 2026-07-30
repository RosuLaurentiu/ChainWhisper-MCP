import { describe, expect, it, vi } from 'vitest';

import type { SignedActionEnvelopeV1 } from '../src/shared/index.js';
import {
  ChainWhisperSignerService,
  HotSignerToolRouter,
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
  it('keeps one tool catalog while activating a configured signer in memory', async () => {
    const setupStatus = vi.fn(async () => ({
      version: 'cw.signer-status/2' as const,
      configured: false,
    }));
    const activeStatus = vi.fn(async () => ({
      version: 'cw.signer-status/2' as const,
      configured: true,
    }));
    const activeExecute = vi.fn(async () => ({ status: 'queued' }));
    const router = new HotSignerToolRouter({
      getStatus: setupStatus as never,
      openControlPanel: async () => ({
        opened: true,
        ready: true,
        activePrompt: false,
      }),
      autonomyStatus: async () => ({
        allowed: true,
        value: {
          globalPaused: false,
          policies: [],
          activeReservationCount: 0,
        },
      }),
    });
    const tools = router.tools;
    const names = tools.map(({ name }) => name);
    const status = tools.find(
      ({ name }) => name === 'chainwhisper_signer_status',
    )!;
    const execute = tools.find(
      ({ name }) => name === 'chainwhisper_execute_action',
    )!;

    await expect(
      status.execute({ requiredAssets: ['p.WISP'] }),
    ).resolves.toMatchObject({ configured: false });
    await expect(execute.execute({})).resolves.toMatchObject({
      allowed: false,
      denial: {
        code: 'CONFIGURATION_REQUIRED',
        nextAction: { tool: 'chainwhisper_open_control_panel' },
      },
    });

    router.activate({
      getStatus: activeStatus,
      executeAction: activeExecute,
      messaging: {},
    } as unknown as ChainWhisperSignerService);

    expect(router.tools).toBe(tools);
    expect(router.tools.map(({ name }) => name)).toEqual(names);
    await expect(status.execute({})).resolves.toMatchObject({
      configured: true,
    });
    await expect(
      execute.execute({ envelope: SIGNED }),
    ).resolves.toEqual({ status: 'queued' });
    expect(activeExecute).toHaveBeenCalledWith(SIGNED, undefined);
  });

  it('publishes only the beta signer surface without generic COTI, setup, recovery, development, or credential tools', () => {
    const tools = createSignerTools({
      messaging: {
        listTools: () => [
          { name: 'send_private_message' },
          { name: 'get_inbox' },
        ],
      },
    } as unknown as ChainWhisperSignerService);
    expect(tools.map(({ name }) => name)).toEqual([
      'chainwhisper_signer_status',
      'chainwhisper_open_control_panel',
      'chainwhisper_autonomy_status',
      'chainwhisper_private_state',
      'chainwhisper_request_autonomy',
      'chainwhisper_pause_autonomy',
      'chainwhisper_execute_action',
      'chainwhisper_get_operation',
      'chainwhisper_send_order_message',
      'chainwhisper_list_order_messages',
      'chainwhisper_read_order_message',
    ]);
    const schemas = JSON.stringify(
      tools.map(({ name, inputSchema }) => ({ name, inputSchema })),
    );
    expect(schemas).not.toMatch(
      /"privateKey"\s*:|"aesKey"\s*:|"mnemonic"\s*:|"passphrase"\s*:|"accessSecret"\s*:/iu,
    );
    const execute = tools.find(
      ({ name }) => name === 'chainwhisper_execute_action',
    );
    expect(JSON.stringify(execute?.inputSchema)).toContain('policyId');
    const operation = tools.find(
      ({ name }) => name === 'chainwhisper_get_operation',
    );
    expect(operation?.inputSchema).toEqual({
      type: 'object',
      properties: {
        operationId: { type: 'string' },
      },
      required: ['operationId'],
      additionalProperties: false,
    });
    expect(
      tools.find(({ name }) => name === 'chainwhisper_autonomy_status')
        ?.description,
    ).toContain('budgets are intentionally visible');
    expect(tools.map(({ name }) => name)).not.toEqual(
      expect.arrayContaining([
        'send_private_message',
        'get_inbox',
        'chainwhisper_test_confirmation_form',
        'chainwhisper_onboard_privacy',
        'chainwhisper_enable_private_token',
        'chainwhisper_recover_operation',
        'chainwhisper_discard_operation',
        'chainwhisper_resume_autonomy',
        'chainwhisper_revoke_autonomy',
      ]),
    );
  });

  it('forwards one minimal private-state query and optional exact policy id', async () => {
    let received:
      | { query: unknown; policyId?: string }
      | undefined;
    const tools = createSignerTools({
      getPrivateState: async (query: unknown, policyId?: string) => {
        received = {
          query,
          ...(policyId ? { policyId } : {}),
        };
        return { allowed: false, denial: { code: 'POLICY_NOT_FOUND' } };
      },
      messaging: { listTools: () => [] },
    } as unknown as ChainWhisperSignerService);
    const tool = tools.find(
      ({ name }) => name === 'chainwhisper_private_state',
    );

    await expect(
      tool?.execute({
        query: {
          kind: 'order',
          route: 'recurring',
          orderId: '7',
          receiptLimit: 10,
        },
        policyId: 'policy-7',
      }),
    ).resolves.toMatchObject({
      allowed: false,
      denial: { code: 'POLICY_NOT_FOUND' },
    });
    expect(received).toEqual({
      query: {
        kind: 'order',
        route: 'recurring',
        orderId: '7',
        receiptLimit: 10,
      },
      policyId: 'policy-7',
    });
    expect(JSON.stringify(tool?.inputSchema)).not.toMatch(
      /privateKey|aesKey|passphrase|accessSecret|mnemonic/iu,
    );
    await expect(
      Promise.resolve().then(() =>
        tool?.execute({
          query: { kind: 'balances', assets: ['p.WISP'] },
          policyId: '',
        }),
      ),
    ).rejects.toMatchObject({
      code: 'ENVELOPE_INVALID',
    });
  });

  it('preflights required private assets through signer status', async () => {
    let received: string[] = [];
    const tools = createSignerTools({
      getStatus: async (assets: string[]) => {
        received = assets;
        return { version: 'cw.signer-status/2' };
      },
      messaging: { listTools: () => [] },
    } as unknown as ChainWhisperSignerService);
    const tool = tools.find(
      (candidate) =>
        candidate.name === 'chainwhisper_signer_status',
    );

    await expect(
      tool?.execute({ requiredAssets: ['p.WISP', 'p.COTI'] }),
    ).resolves.toEqual({
      version: 'cw.signer-status/2',
    });
    expect(received).toEqual(['p.WISP', 'p.COTI']);
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

describe('signer Agent Control lifecycle', () => {
  it('resumes stored pending operations after Agent Control opens', async () => {
    const restoreEngineOperations = vi.fn(async () => undefined);
    const restoreMessageOperations = vi.fn(async () => undefined);
    const openControlPanel = vi.fn(async () => ({
      opened: true,
      ready: true,
      activePrompt: false,
    }));
    const service = new ChainWhisperSignerService({
      config: {} as never,
      wallet: {} as never,
      confirmation: {} as never,
      engine: {
        restorePendingOperations: restoreEngineOperations,
      } as never,
      messaging: {
        restorePendingOperations: restoreMessageOperations,
      } as never,
      privacyOnboarding: {} as never,
      privateTokens: {} as never,
      control: { openControlPanel } as never,
    });

    await expect(service.openControlPanel()).resolves.toEqual({
      opened: true,
      ready: true,
      activePrompt: false,
    });
    expect(openControlPanel).toHaveBeenCalledOnce();
    expect(restoreMessageOperations).toHaveBeenCalledOnce();
    expect(restoreEngineOperations).toHaveBeenCalledOnce();
  });

  it('routes message polling and local recovery to the messaging lifecycle owner', async () => {
    const messageOperationId = 'message-1111111111111111';
    const engineStatus = vi.fn(async () => null);
    const messageStatus = vi.fn(async () => ({
      version: 'cw.operation-status/2',
      operationId: messageOperationId,
      status: 'uncertain',
    }));
    const engineRecovery = vi.fn(async () => ({
      status: 'processing',
    }));
    const messageRecovery = vi.fn(async () => ({
      status: 'processing',
    }));
    const service = new ChainWhisperSignerService({
      config: {} as never,
      wallet: {} as never,
      confirmation: {} as never,
      engine: {
        getOperationStatus: engineStatus,
        recoverOperation: engineRecovery,
      } as never,
      messaging: {
        getOperationStatus: messageStatus,
        recoverOperation: messageRecovery,
      } as never,
      privacyOnboarding: {} as never,
      privateTokens: {} as never,
    });

    await service.getOperation(messageOperationId);
    await service.recoverOperation(
      messageOperationId,
      SIGNED.operationHash,
    );
    await service.getOperation('operation-1');
    await service.recoverOperation('operation-1', SIGNED.operationHash);

    expect(messageStatus).toHaveBeenCalledWith(messageOperationId);
    expect(messageRecovery).toHaveBeenCalledWith(
      messageOperationId,
      SIGNED.operationHash,
    );
    expect(engineStatus).toHaveBeenCalledWith('operation-1');
    expect(engineRecovery).toHaveBeenCalledWith(
      'operation-1',
      SIGNED.operationHash,
    );
  });
});
