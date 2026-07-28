import assert from 'node:assert/strict';
import { access, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve, sep } from 'node:path';
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
const packageJsonPath = resolve(packageRoot, 'package.json');
const liveStatusRequested = process.argv.includes('--live-status');

const assertFile = async (path) => {
  await access(path);
};

const readToolJson = (result) => {
  const block = result.content?.find((item) => item.type === 'text');
  assert.ok(block && typeof block.text === 'string', 'Tool result must contain JSON text.');
  return JSON.parse(block.text);
};

const sanitizedEnvironment = (stateDirectory) => {
  const environment = {
    ...getDefaultEnvironment(),
    CHAINWHISPER_STATE_DIRECTORY: stateDirectory,
  };
  for (const name of [
    'CHAINWHISPER_SIGNER_CONFIG_FILE',
    'CHAINWHISPER_SIGNER_PRIVATE_KEY',
    'CHAINWHISPER_SIGNER_AES_KEY',
    'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
    'CHAINWHISPER_PAIRING_SECRET',
    'PRIVATE_KEY',
    'AES_KEY',
  ]) {
    delete environment[name];
  }
  return environment;
};

const withStdioClient = async (name, binaryPath, environment, callback) => {
  let stderr = '';
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [binaryPath],
    cwd: packageRoot,
    env: environment,
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (chunk) => {
    stderr += String(chunk);
  });
  const client = new Client(
    { name: 'chainwhisper-package-smoke', version: '0.1.0' },
    { capabilities: {} },
  );
  try {
    await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
    await callback(client);
  } catch (error) {
    const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
    throw new Error(`${name} stdio smoke failed: ${String(error)}${detail}`, {
      cause: error,
    });
  } finally {
    await client.close().catch(() => undefined);
  }
};

const packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'));
assert.equal(packageJson.engines?.node, '>=20');
assert.equal(packageJson.bin?.['chainwhisper-mcp'], './dist/bin/chainwhisper-mcp.js');
assert.equal(
  packageJson.bin?.['chainwhisper-coti-signer'],
  './dist/bin/chainwhisper-coti-signer.js',
);
assert.deepEqual(packageJson.files, ['dist', 'runtime', 'README.md']);

const plannerBinary = resolve(packageRoot, packageJson.bin['chainwhisper-mcp']);
const signerBinary = resolve(
  packageRoot,
  packageJson.bin['chainwhisper-coti-signer'],
);
for (const path of [
  plannerBinary,
  signerBinary,
  resolve(packageRoot, 'runtime/coti-mainnet.v1.json'),
  resolve(packageRoot, 'README.md'),
  ...Object.values(packageJson.exports).map((path) =>
    resolve(packageRoot, path),
  ),
]) {
  await assertFile(path);
}
for (const binary of [plannerBinary, signerBinary]) {
  assert.match(
    await readFile(binary, 'utf8'),
    /^#!\/usr\/bin\/env node\r?\n/u,
    `${binary} must retain its Node.js shebang.`,
  );
}

const stateDirectory = await mkdtemp(
  resolve(tmpdir(), 'chainwhisper-mcp-smoke-'),
);
try {
  const environment = sanitizedEnvironment(stateDirectory);

  await withStdioClient(
    'chainwhisper-coti-signer',
    signerBinary,
    environment,
    async (client) => {
      const { tools } = await client.listTools(undefined, {
        timeout: REQUEST_TIMEOUT_MS,
      });
      assert.deepEqual(
        tools.map((tool) => tool.name),
        ['chainwhisper_signer_status'],
        'An unconfigured signer must expose only its read-only status tool.',
      );
      const result = await client.callTool(
        { name: 'chainwhisper_signer_status', arguments: {} },
        undefined,
        { timeout: REQUEST_TIMEOUT_MS },
      );
      assert.equal(result.isError, undefined);
      const status = readToolJson(result);
      assert.equal(status.chainId, 2_632_500);
      assert.equal(status.configured, false);
      assert.equal(status.mode, 'configuration-required');
    },
  );
  assert.deepEqual(
    await readdir(stateDirectory),
    [],
    'An unconfigured signer must not create pairing, journal, or vault state.',
  );
  process.stdout.write(
    'chainwhisper-coti-signer: unconfigured read-only status verified\n',
  );

  await withStdioClient(
    'chainwhisper-mcp',
    plannerBinary,
    environment,
    async (client) => {
      const { tools } = await client.listTools(undefined, {
        timeout: REQUEST_TIMEOUT_MS,
      });
      assert.ok(
        tools.some((tool) => tool.name === 'chainwhisper_status'),
        'The keyless MCP must expose chainwhisper_status.',
      );
      assert.ok(
        tools.some((tool) => tool.name === 'chainwhisper_prepare_create_trade'),
        'The keyless MCP must expose its planning surface.',
      );

      const { resources } = await client.listResources(undefined, {
        timeout: REQUEST_TIMEOUT_MS,
      });
      assert.ok(
        resources.some(
          (resource) => resource.uri === 'chainwhisper://runtime/coti-mainnet',
        ),
        'The packaged runtime manifest resource must be registered.',
      );

      if (liveStatusRequested) {
        const result = await client.callTool(
          { name: 'chainwhisper_status', arguments: {} },
          undefined,
          { timeout: REQUEST_TIMEOUT_MS },
        );
        assert.equal(result.isError, undefined);
        const response = readToolJson(result);
        assert.equal(response.ok, true);
        assert.equal(response.data?.chainId, 2_632_500);
        assert.equal(response.data?.mode, 'keyless');
      }
    },
  );
  process.stdout.write(
    `chainwhisper-mcp: stdio ready; keyless status ${
      liveStatusRequested ? 'verified live' : 'registered'
    }\n`,
  );
} finally {
  const resolvedTemp = resolve(tmpdir());
  const resolvedState = resolve(stateDirectory);
  assert.ok(
    resolvedState.startsWith(`${resolvedTemp}${sep}`),
    'Refusing to remove a smoke directory outside the system temp directory.',
  );
  await rm(resolvedState, { recursive: true, force: true });
}

process.stdout.write('ChainWhisper MCP package smoke passed.\n');
