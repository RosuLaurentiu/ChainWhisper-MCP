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
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const REQUEST_TIMEOUT_MS = 180_000;
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRootArgument = process.argv.indexOf('--package-root');
const packageRoot =
  packageRootArgument >= 0 && process.argv[packageRootArgument + 1]
    ? resolve(process.argv[packageRootArgument + 1])
    : resolve(scriptDirectory, '..');
const toolArgument = process.argv.indexOf('--tool');
const toolName =
  toolArgument >= 0 ? process.argv[toolArgument + 1] : undefined;
const tokenArgument = process.argv.indexOf('--private-token');
const privateToken =
  tokenArgument >= 0 ? process.argv[tokenArgument + 1] : undefined;
const hashArgument = process.argv.indexOf('--accept-operation-hash');
const acceptedOperationHash =
  hashArgument >= 0
    ? process.argv[hashArgument + 1]?.toLowerCase()
    : undefined;

const allowedSetupTools = new Set([
  'chainwhisper_onboard_privacy',
  'chainwhisper_enable_private_token',
]);
assert.ok(
  toolName && allowedSetupTools.has(toolName),
  'Choose --tool chainwhisper_onboard_privacy or chainwhisper_enable_private_token.',
);
if (toolName === 'chainwhisper_enable_private_token') {
  assert.ok(privateToken, '--private-token is required for token setup.');
}
if (acceptedOperationHash) {
  assert.match(
    acceptedOperationHash,
    /^0x[0-9a-f]{64}$/u,
    '--accept-operation-hash must be one exact 32-byte hash.',
  );
}

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

const environment = { ...getDefaultEnvironment() };
for (const name of signerEnvironmentNames) {
  const value = process.env[name];
  if (value) environment[name] = value;
}

const packageJson = JSON.parse(
  await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
);
const signerBinary = resolve(
  packageRoot,
  packageJson.bin['chainwhisper-coti-signer'],
);
let stderr = '';
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [signerBinary],
  cwd: packageRoot,
  env: environment,
  stderr: 'pipe',
});
transport.stderr?.on('data', (chunk) => {
  stderr += String(chunk);
});
const client = new Client(
  { name: 'chainwhisper-live-confirmed-setup', version: '0.1.0' },
  { capabilities: { elicitation: { form: { applyDefaults: true } } } },
);
const confirmationMessages = [];
let acceptedCount = 0;

client.setRequestHandler(ElicitRequestSchema, async (request) => {
  const params = request.params;
  if (params.mode && params.mode !== 'form') {
    return { action: 'cancel' };
  }
  const schema = params.requestedSchema;
  const propertyNames = Object.keys(schema.properties ?? {});
  const confirmationOnly =
    propertyNames.length === 1 &&
    propertyNames[0] === 'confirm' &&
    schema.properties?.confirm?.type === 'boolean';
  assert.ok(
    confirmationOnly,
    'This setup client refuses private-value or credential elicitation.',
  );
  confirmationMessages.push(params.message);
  const hash = params.message
    .match(/Operation hash: (0x[0-9a-fA-F]{64})/u)?.[1]
    ?.toLowerCase();
  if (
    acceptedOperationHash &&
    hash === acceptedOperationHash &&
    acceptedCount === 0
  ) {
    acceptedCount += 1;
    return { action: 'accept', content: { confirm: true } };
  }
  return { action: 'cancel' };
});

try {
  await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
  const { tools } = await client.listTools(undefined, {
    timeout: REQUEST_TIMEOUT_MS,
  });
  const tool = tools.find((candidate) => candidate.name === toolName);
  assert.ok(tool, `${toolName} is not registered.`);
  assert.notEqual(
    tool.annotations?.readOnlyHint,
    true,
    `${toolName} unexpectedly claims to be read-only.`,
  );
  const result = await client.callTool(
    {
      name: toolName,
      arguments:
        toolName === 'chainwhisper_enable_private_token'
          ? { token: privateToken }
          : {},
    },
    undefined,
    { timeout: REQUEST_TIMEOUT_MS },
  );
  process.stdout.write(
    `${JSON.stringify(
      {
        mode: acceptedOperationHash ? 'accept-exact-hash' : 'preview-cancel',
        confirmationMessages,
        result,
      },
      null,
      2,
    )}\n`,
  );
  if (acceptedOperationHash) {
    assert.equal(acceptedCount, 1, 'The exact confirmation was not accepted.');
    assert.equal(result.isError, undefined, 'The accepted setup write failed.');
  } else {
    assert.equal(
      acceptedCount,
      0,
      'Preview mode must never accept a confirmation.',
    );
  }
} catch (error) {
  const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
  throw new Error(`ChainWhisper setup MCP session failed: ${String(error)}${detail}`, {
    cause: error,
  });
} finally {
  await client.close().catch(() => undefined);
}
