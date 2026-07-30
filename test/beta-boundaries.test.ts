import {
  chmod,
  mkdtemp,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { describe, expect, it, vi } from 'vitest';

import {
  MAX_DECIMAL_INPUT_LENGTH,
  parseDecimal,
  rejectSensitiveOrArbitraryInput,
} from '../src/domain/index.js';
import {
  getOrCreatePairingSecret,
  type SignedActionEnvelopeV1,
} from '../src/shared/index.js';
import {
  McpFormElicitor,
  buildActionConfirmation,
  buildConfirmationMessage,
  loadSignerConfig,
  type Address,
  type HexString,
  type MaterializedActionStep,
} from '../src/signer/index.js';

const PRIVATE_KEY = `0x${'11'.repeat(32)}`;
const AES_KEY = `0x${'22'.repeat(32)}`;
const PASSPHRASE = 'a-long-beta-boundary-passphrase';
const WALLET =
  '0x1111111111111111111111111111111111111111' as Address;
const CONTRACT =
  '0x2222222222222222222222222222222222222222' as Address;

describe('public beta input and secret boundaries', () => {
  it('rejects decimal strings before unbounded BigInt conversion', () => {
    expect(parseDecimal('9'.repeat(MAX_DECIMAL_INPUT_LENGTH))).not.toBeNull();
    expect(
      parseDecimal('9'.repeat(MAX_DECIMAL_INPUT_LENGTH + 1)),
    ).toBeNull();
  });

  it('rejects excessively deep planner input without recursive traversal', () => {
    let nested: Record<string, unknown> = {};
    const root = nested;
    for (let index = 0; index < 40; index += 1) {
      const next: Record<string, unknown> = {};
      nested.next = next;
      nested = next;
    }
    expect(() => rejectSensitiveOrArbitraryInput(root)).toThrow(
      'too deeply nested or complex',
    );
  });

  it('defaults confidential signer interaction to local web', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-beta-config-'),
    );
    const config = await loadSignerConfig({
      CHAINWHISPER_SIGNER_PRIVATE_KEY: PRIVATE_KEY,
      CHAINWHISPER_SIGNER_AES_KEY: AES_KEY,
      CHAINWHISPER_SIGNER_VAULT_PASSPHRASE: PASSPHRASE,
      CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
    });
    expect(config.confirmationChannel).toBe('local-web');
  });

  it('does not send confidential values through MCP elicitation', async () => {
    const elicitInput = vi.fn();
    const server = {
      getClientCapabilities: () => ({ elicitation: { form: {} } }),
      elicitInput,
    } as unknown as Server;
    const result = await new McpFormElicitor(server).requestPrivateValues(
      {
        operationId: 'private-value-boundary',
        operationHash: `0x${'33'.repeat(32)}`,
        wallet: WALLET,
        fields: [
          {
            id: 'hidden-amount',
            title: 'Hidden amount',
            description: 'A confidential private-token amount.',
            kind: 'decimal-amount',
          },
        ],
      },
      5_000,
    );
    expect(result).toEqual({ outcome: 'cancelled' });
    expect(elicitInput).not.toHaveBeenCalled();
  });

  it.skipIf(process.platform === 'win32')(
    'rejects a group-readable signer configuration file',
    async () => {
      const stateDirectory = await mkdtemp(
        join(tmpdir(), 'cw-beta-config-mode-'),
      );
      const configPath = join(stateDirectory, 'signer.json');
      await writeFile(
        configPath,
        JSON.stringify({
          privateKey: PRIVATE_KEY,
          aesKey: AES_KEY,
          vaultPassphrase: PASSPHRASE,
          stateDirectory,
        }),
        { mode: 0o600 },
      );
      await chmod(configPath, 0o644);
      await expect(
        loadSignerConfig({
          CHAINWHISPER_SIGNER_CONFIG_FILE: configPath,
        }),
      ).rejects.toMatchObject({ code: 'CONFIGURATION_REQUIRED' });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a symbolic-link signer configuration file',
    async () => {
      const stateDirectory = await mkdtemp(
        join(tmpdir(), 'cw-beta-config-link-'),
      );
      const target = join(stateDirectory, 'target.json');
      const link = join(stateDirectory, 'signer.json');
      await writeFile(
        target,
        JSON.stringify({
          privateKey: PRIVATE_KEY,
          aesKey: AES_KEY,
          vaultPassphrase: PASSPHRASE,
          stateDirectory,
        }),
        { mode: 0o600 },
      );
      await symlink(target, link, 'file');
      await expect(
        loadSignerConfig({
          CHAINWHISPER_SIGNER_CONFIG_FILE: link,
        }),
      ).rejects.toMatchObject({ code: 'CONFIGURATION_REQUIRED' });
    },
  );

  it.skipIf(process.platform === 'win32')(
    'rejects a group-readable existing pairing secret',
    async () => {
      const stateDirectory = await mkdtemp(
        join(tmpdir(), 'cw-beta-pairing-mode-'),
      );
      const pairingPath = join(stateDirectory, 'pairing.key');
      await writeFile(pairingPath, `${'p'.repeat(40)}\n`, {
        mode: 0o600,
      });
      await chmod(pairingPath, 0o644);
      await expect(
        getOrCreatePairingSecret({ stateDirectory }),
      ).rejects.toThrow('must not be accessible');
    },
  );
});

describe('public beta confirmation clarity', () => {
  it('pairs send, receive, and private amounts with explicit labels', () => {
    const envelope = {
      operationId: 'clear-confirmation',
      operationHash: `0x${'44'.repeat(32)}` as HexString,
      wallet: WALLET,
      summary: 'Create an exact private-liquidity order.',
      fee: {
        amount: '1000000000000000000',
        asset: 'native',
        recipient: CONTRACT,
      },
      intent: {
        action: 'create_trade',
        sellAsset: { symbol: 'p.WISP' },
        buyAsset: { symbol: 'p.COTI' },
        sellAmount: '1.25',
        buyAmount: '2.5',
        recipient: null,
      },
      steps: [],
    } as unknown as SignedActionEnvelopeV1;
    const step = {
      id: 'create-private-order',
      kind: 'protocol',
      to: CONTRACT,
      data: '0x12345678' as HexString,
      value: '0',
      gasCap: '8000000',
      summary: 'Create the private order.',
      privateDisplayAmounts: [
        {
          id: 'hidden-offer-amount',
          amount: '1.25',
          symbol: 'p.WISP',
        },
      ],
    } satisfies MaterializedActionStep;

    const confirmation = buildActionConfirmation(envelope, step, 0);
    expect(confirmation.details).toEqual(
      expect.arrayContaining([
        { label: 'You send', value: '1.25 p.WISP' },
        { label: 'You receive', value: '2.5 p.COTI' },
        {
          label: 'Private send amount (hidden-offer-amount)',
          value: '1.25 p.WISP',
        },
      ]),
    );
    const message = buildConfirmationMessage(confirmation);
    expect(message).toContain('Exact transaction terms:');
    expect(message).toContain('- You send: 1.25 p.WISP');
    expect(message).toContain('- You receive: 2.5 p.COTI');
    expect(confirmation.fee).toBe(
      '1 COTI (1000000000000000000 wei)',
    );
  });

  it('formats the signed Privacy Portal fee in COTI and wei', () => {
    const envelope = {
      operationId: 'portal-fee-confirmation',
      operationHash: `0x${'55'.repeat(32)}` as HexString,
      wallet: WALLET,
      summary: 'Convert through the Privacy Portal.',
      fee: {
        amount: '0',
        asset: 'native',
        recipient: CONTRACT,
      },
      intent: {
        action: 'privacy_bridge',
        sellAsset: { symbol: 'WISP' },
        buyAsset: { symbol: 'p.WISP' },
        sellAmount: '1',
        buyAmount: '1',
        recipient: null,
        metadata: { portalFeeAtomic: '9' },
      },
      steps: [],
    } as unknown as SignedActionEnvelopeV1;
    const step = {
      id: 'privacy-portal-deposit',
      kind: 'protocol',
      to: CONTRACT,
      data: '0x12345678' as HexString,
      value: '9',
      gasCap: '8000000',
      summary: 'Convert through the Privacy Portal.',
    } satisfies MaterializedActionStep;

    expect(buildActionConfirmation(envelope, step, 0).fee).toBe(
      '0.000000000000000009 COTI (9 wei); Privacy Portal fee',
    );
  });
});
