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
const publicOrderTypeIds = [
  'one-off.standard-public',
  'one-off.unlisted',
  'one-off.direct',
  'one-off.private-liquidity.public',
  'one-off.private-liquidity.unlisted',
  'one-off.private-liquidity.direct',
  'recurring.public',
  'recurring.private-liquidity.public',
];

const sharedEnvironmentNames = [
  'CHAINWHISPER_STATE_DIRECTORY',
  'CHAINWHISPER_PAIRING_FILE',
  'CHAINWHISPER_PAIRING_SECRET',
];
const signerOnlyEnvironmentNames = [
  'CHAINWHISPER_SIGNER_ENV_FILE',
  'CHAINWHISPER_SIGNER_CONFIG_FILE',
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  'CHAINWHISPER_COTI_RPC_URL',
  'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
  'CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL',
  'CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS',
  'CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS',
];

const childEnvironment = (role, source = process.env) => {
  const environment = { ...getDefaultEnvironment() };
  for (const name of signerOnlyEnvironmentNames) {
    delete environment[name];
  }
  const names =
    role === 'signer'
      ? [...sharedEnvironmentNames, ...signerOnlyEnvironmentNames]
      : sharedEnvironmentNames;
  for (const name of names) {
    const value = source[name];
    if (value) environment[name] = value;
  }
  return environment;
};

const assertEnvironmentSeparation = () => {
  const names = [...sharedEnvironmentNames, ...signerOnlyEnvironmentNames];
  const sentinels = Object.fromEntries(
    names.map((name, index) => [name, `sentinel-${index}`]),
  );
  const planner = childEnvironment('planner', sentinels);
  const signer = childEnvironment('signer', sentinels);
  for (const name of sharedEnvironmentNames) {
    assert.equal(planner[name], sentinels[name]);
    assert.equal(signer[name], sentinels[name]);
  }
  for (const name of signerOnlyEnvironmentNames) {
    assert.equal(
      planner[name],
      undefined,
      `The keyless planner must not receive ${name}.`,
    );
    assert.equal(signer[name], sentinels[name]);
  }
};

const readToolJson = (result) => {
  const block = result.content?.find((item) => item.type === 'text');
  assert.ok(block && typeof block.text === 'string');
  return JSON.parse(block.text);
};

const withClient = async (name, binaryPath, role, callback) => {
  let stderr = '';
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [binaryPath],
    cwd: packageRoot,
    env: childEnvironment(role),
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

const environmentCheckRequested = process.argv.includes(
  '--check-environment-separation',
);
assertEnvironmentSeparation();
if (environmentCheckRequested) {
  process.stdout.write('ChainWhisper child environment separation verified.\n');
  process.exit(0);
}
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
  'planner',
  async (client) => {
    const status = await callReadOnly(client, 'chainwhisper_status');
    const orderTypes = await callReadOnly(
      client,
      'chainwhisper_order_types',
    );
    assert.equal(orderTypes.ok, true);
    assert.equal(orderTypes.data?.version, 'OrderTypeCatalogV1');
    assert.deepEqual(
      orderTypes.data?.orderTypes?.map(({ id }) => id),
      publicOrderTypeIds,
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
  'signer',
  async (client) => {
    const baseSignerStatus = await callReadOnly(
      client,
      'chainwhisper_signer_status',
    );
    const signerStatus =
      privateToken && baseSignerStatus.configured
        ? await callReadOnly(
            client,
            'chainwhisper_signer_status',
            { requiredAssets: [privateToken] },
          )
        : baseSignerStatus;
    const requiredAsset =
      privateToken && signerStatus.configured
        ? signerStatus.requiredAssets?.find(
            ({ asset }) =>
              typeof asset === 'string' &&
              asset.toLowerCase() === privateToken.toLowerCase(),
          ) ?? signerStatus.requiredAssets?.[0] ?? null
        : null;
    if (privateToken && signerStatus.configured) {
      assert.equal(signerStatus.requiredAssets?.length, 1);
      assert.ok(
        requiredAsset &&
          typeof requiredAsset.asset === 'string' &&
          typeof requiredAsset.status === 'string',
        'Signer status must return one required private-asset readiness result.',
      );
    }
    return { signerStatus, requiredAsset };
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
      ...(signerResult.requiredAsset
        ? { requiredPrivateAsset: signerResult.requiredAsset }
        : {}),
    },
    null,
    2,
  )}\n`,
);
process.stdout.write(
  'ChainWhisper live read-only MCP smoke passed; no write tool was invoked.\n',
);
