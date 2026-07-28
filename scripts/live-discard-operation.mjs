import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import process from 'node:process';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from '@modelcontextprotocol/sdk/client/stdio.js';

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};
const packageRootArgument = argument('--package-root');
const operationId = argument('--operation-id');
const operationHash = argument('--operation-hash');
assert.ok(
  packageRootArgument && isAbsolute(packageRootArgument),
  '--package-root must be an absolute path.',
);
assert.match(
  operationId ?? '',
  /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/u,
  '--operation-id is invalid.',
);
assert.match(
  operationHash ?? '',
  /^0x[0-9a-fA-F]{64}$/u,
  '--operation-hash is invalid.',
);

const packageRoot = resolve(packageRootArgument);
const packageJson = JSON.parse(
  await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
);
const signerBinary = resolve(
  packageRoot,
  packageJson.bin['chainwhisper-coti-signer'],
);
const environment = { ...getDefaultEnvironment() };
for (const name of [
  'CHAINWHISPER_STATE_DIRECTORY',
  'CHAINWHISPER_PAIRING_FILE',
  'CHAINWHISPER_PAIRING_SECRET',
  'CHAINWHISPER_SIGNER_CONFIG_FILE',
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  'CHAINWHISPER_COTI_RPC_URL',
  'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
]) {
  const value = process.env[name];
  if (value) environment[name] = value;
}

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
  { name: 'chainwhisper-live-discard-operation', version: '0.1.0' },
  { capabilities: {} },
);
try {
  await client.connect(transport, { timeout: 30_000 });
  const result = await client.callTool(
    {
      name: 'chainwhisper_discard_operation',
      arguments: { operationId, operationHash },
    },
    undefined,
    { timeout: 30_000 },
  );
  const block = result.content?.find((item) => item.type === 'text');
  assert.ok(block && typeof block.text === 'string');
  process.stdout.write(`${block.text}\n`);
  assert.equal(result.isError, undefined);
} catch (error) {
  const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
  throw new Error(
    `ChainWhisper discard operation failed: ${String(error)}${detail}`,
    { cause: error },
  );
} finally {
  await client.close().catch(() => undefined);
}
