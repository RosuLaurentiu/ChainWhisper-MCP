import { describe, expect, it } from 'vitest';

import {
  buildPublicSignerStatus,
  ChainWhisperSignerService,
} from '../src/signer/index.js';

const WALLET = `0x${'11'.repeat(20)}` as const;

const configured = {
  chainId: 2_632_500,
  walletConfigured: true,
  aesConfigured: true,
} as never;

const statusService = (options: {
  pendingOperations?: string[];
  pendingMessages?: string[];
  privateTokenReady?: boolean;
  writesBlocked?: boolean;
  diagnosticCodes?: string[];
}) =>
  new ChainWhisperSignerService({
    config: configured,
    wallet: {
      getAddress: async () => WALLET,
    } as never,
    confirmation: {
      isWriteAvailable: true,
    } as never,
    engine: {
      listPendingOperationIds: async () =>
        options.pendingOperations ?? [],
    } as never,
    messaging: {
      listPendingOperationIds: async () =>
        options.pendingMessages ?? [],
    } as never,
    privacyOnboarding: {
      isReady: async () => true,
    } as never,
    privateTokens: {
      status: async (asset: string) => ({
        symbol: asset,
        ready: options.privateTokenReady ?? true,
      }),
    } as never,
    control: {
      controlPageReady: true,
    } as never,
    writesBlocked: () => options.writesBlocked ?? false,
    diagnosticCodes: () => options.diagnosticCodes ?? [],
  });

describe('SignerStatusV2 next action', () => {
  it('points wallet setup and asset preflight to the advertised control tool', () => {
    const status = buildPublicSignerStatus(
      {
        chainId: 2_632_500,
        walletConfigured: false,
        aesConfigured: false,
      } as never,
      null,
      null,
      false,
      { requiredAssets: [' p.WISP ', 'p.COTI', 'p.WISP'] },
    );

    expect(status.requiredAssets).toEqual([
      { asset: 'p.WISP', status: 'wallet-setup-required' },
      { asset: 'p.COTI', status: 'wallet-setup-required' },
    ]);
    expect(status.nextAction).toEqual({
      tool: 'chainwhisper_open_control_panel',
      arguments: {},
      reason: 'wallet-setup-required',
    });
  });

  it('returns an exact operation-status tool call for pending work', async () => {
    const status = await statusService({
      pendingOperations: ['operation-1', 'operation-2'],
    }).getStatus();

    expect(status.nextAction).toEqual({
      tool: 'chainwhisper_get_operation',
      arguments: { operationId: 'operation-1' },
      reason: 'pending-operation',
    });
  });

  it('includes pending private-message operations in the same next action', async () => {
    const status = await statusService({
      pendingMessages: ['message-1111111111111111'],
    }).getStatus();

    expect(status.nextAction).toEqual({
      tool: 'chainwhisper_get_operation',
      arguments: { operationId: 'message-1111111111111111' },
      reason: 'pending-operation',
    });
  });

  it('routes missing private-token setup to Agent Control', async () => {
    const status = await statusService({
      privateTokenReady: false,
    }).getStatus(['p.COTI']);

    expect(status.nextAction).toEqual({
      tool: 'chainwhisper_open_control_panel',
      arguments: {},
      reason: 'private-token-setup-required',
    });
  });

  it('does not claim a followable MCP action while restart is required', async () => {
    const status = await statusService({
      writesBlocked: true,
    }).getStatus();

    expect(status.nextAction).toEqual({
      tool: null,
      arguments: {},
      reason: 'signer-restart-required',
    });
  });

  it('includes only secret-safe Agent Control diagnostic codes', async () => {
    const status = await statusService({
      diagnosticCodes: [
        'privacy-onboarding-awaiting-local-confirmation',
        'signer-private-input-unavailable',
        'unsafe diagnostic with spaces',
        `0x${'ab'.repeat(32)}`,
      ],
    }).getStatus();

    expect(status.diagnosticCodes).toContain(
      'privacy-onboarding-awaiting-local-confirmation',
    );
    expect(status.diagnosticCodes).toContain(
      'signer-private-input-unavailable',
    );
    expect(status.diagnosticCodes).not.toContain(
      'unsafe diagnostic with spaces',
    );
    expect(status.diagnosticCodes).not.toContain(
      `0x${'ab'.repeat(32)}`,
    );
  });
});
