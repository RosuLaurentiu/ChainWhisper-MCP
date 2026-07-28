import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from '@modelcontextprotocol/sdk/client/stdio.js';

const REQUEST_TIMEOUT_MS = 30_000;
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRootArgument = process.argv.indexOf('--package-root');
const packageRoot =
  packageRootArgument >= 0 && process.argv[packageRootArgument + 1]
    ? resolve(process.argv[packageRootArgument + 1])
    : resolve(scriptDirectory, '..');
const tokenArgument = process.argv.indexOf('--private-token');
const privateToken =
  tokenArgument >= 0 && process.argv[tokenArgument + 1]
    ? process.argv[tokenArgument + 1]
    : null;
const ordersArgument = process.argv.indexOf('--orders-for-wallet');
const ordersForWallet =
  ordersArgument >= 0 && process.argv[ordersArgument + 1]
    ? process.argv[ordersArgument + 1]
    : null;

const signerEnvironmentNames = [
  'CHAINWHISPER_SIGNER_CONFIG_FILE',
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  'CHAINWHISPER_COTI_RPC_URL',
  'CHAINWHISPER_STATE_DIRECTORY',
  'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
  'CHAINWHISPER_PAIRING_SECRET',
];

const childEnvironment = () => {
  const environment = { ...getDefaultEnvironment() };
  for (const name of signerEnvironmentNames) {
    const value = process.env[name];
    if (value) environment[name] = value;
  }
  return environment;
};

const readToolJson = (result) => {
  const block = result.content?.find((item) => item.type === 'text');
  assert.ok(block && typeof block.text === 'string');
  return JSON.parse(block.text);
};

const withClient = async (name, binaryPath, callback) => {
  let stderr = '';
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [binaryPath],
    cwd: packageRoot,
    env: childEnvironment(),
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (chunk) => {
    stderr += String(chunk);
  });
  const client = new Client(
    { name: 'chainwhisper-live-readonly-smoke', version: '0.1.0' },
    { capabilities: {} },
  );
  try {
    await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
    return await callback(client);
  } catch (error) {
    const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
    throw new Error(`${name} read-only smoke failed: ${String(error)}${detail}`, {
      cause: error,
    });
  } finally {
    await client.close().catch(() => undefined);
  }
};

const callReadOnly = async (client, toolName, args = {}) => {
  const { tools } = await client.listTools(undefined, {
    timeout: REQUEST_TIMEOUT_MS,
  });
  const tool = tools.find((candidate) => candidate.name === toolName);
  assert.ok(tool, `${toolName} is not registered.`);
  assert.equal(
    tool.annotations?.readOnlyHint,
    true,
    `Refusing to invoke ${toolName} because it is not marked read-only.`,
  );
  const result = await client.callTool(
    { name: toolName, arguments: args },
    undefined,
    { timeout: REQUEST_TIMEOUT_MS },
  );
  assert.equal(result.isError, undefined);
  return readToolJson(result);
};

const packageJson = JSON.parse(
  await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
);
const plannerBinary = resolve(
  packageRoot,
  packageJson.bin['chainwhisper-mcp'],
);
const signerBinary = resolve(
  packageRoot,
  packageJson.bin['chainwhisper-coti-signer'],
);

const plannerResult = await withClient(
  'chainwhisper-mcp',
  plannerBinary,
  async (client) => {
    const status = await callReadOnly(client, 'chainwhisper_status');
    const orderTypes = await callReadOnly(
      client,
      'chainwhisper_order_types',
    );
    assert.equal(orderTypes.ok, true);
    assert.equal(orderTypes.data?.version, 'OrderTypeCatalogV1');
    assert.equal(orderTypes.data?.orderTypes?.length, 10);
    assert.equal(
      new Set(orderTypes.data.orderTypes.map(({ id }) => id)).size,
      10,
    );
    for (const orderType of orderTypes.data.orderTypes) {
      assert.equal(typeof orderType.id, 'string');
      assert.equal(typeof orderType.label, 'string');
      assert.equal(typeof orderType.cadence, 'string');
      assert.equal(typeof orderType.access, 'string');
      assert.equal(typeof orderType.terms, 'string');
      assert.equal(typeof orderType.liquidity, 'string');
      assert.equal(typeof orderType.fillStyle, 'string');
      assert.equal(typeof orderType.supported, 'boolean');
    }
    const orders = ordersForWallet
      ? await callReadOnly(client, 'chainwhisper_list_orders', {
          wallet: ordersForWallet,
          role: 'maker',
          kind: 'trade',
          status: 'open',
          limit: 20,
        })
      : null;
    return { status, orderTypes, orders };
  },
);
const signerResult = await withClient(
  'chainwhisper-coti-signer',
  signerBinary,
  async (client) => {
    const signerStatus = await callReadOnly(
      client,
      'chainwhisper_signer_status',
    );
    const tokenStatus =
      privateToken && signerStatus.configured
        ? await callReadOnly(
            client,
            'chainwhisper_private_token_status',
            { token: privateToken },
          )
        : null;
    return { signerStatus, tokenStatus };
  },
);

process.stdout.write(
  `${JSON.stringify(
    {
      planner: plannerResult.status,
      orderTypes: plannerResult.orderTypes,
      ...(plannerResult.orders
        ? { openMakerOrders: plannerResult.orders }
        : {}),
      signer: signerResult.signerStatus,
      ...(signerResult.tokenStatus
        ? { privateToken: signerResult.tokenStatus }
        : {}),
    },
    null,
    2,
  )}\n`,
);
process.stdout.write(
  'ChainWhisper live read-only MCP smoke passed; no write tool was invoked.\n',
);
