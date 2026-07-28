import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import process from 'node:process';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  StdioClientTransport,
  getDefaultEnvironment,
} from '@modelcontextprotocol/sdk/client/stdio.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const REQUEST_TIMEOUT_MS = 180_000;

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const packageRootArgument = argument('--package-root');
const envelopeFileArgument = argument('--envelope-file');
const previewOnly = process.argv.includes('--preview');
const acceptedOperationHash = argument(
  '--accept-operation-hash',
)?.toLowerCase();
const acceptedStepId = argument('--accept-step-id');
assert.ok(
  packageRootArgument && isAbsolute(packageRootArgument),
  '--package-root must be an absolute path.',
);
assert.ok(
  envelopeFileArgument && isAbsolute(envelopeFileArgument),
  '--envelope-file must be an absolute path.',
);
if (!previewOnly) {
  assert.match(
    acceptedOperationHash ?? '',
    /^0x[0-9a-f]{64}$/u,
    '--accept-operation-hash must be one exact 32-byte hash.',
  );
  assert.match(
    acceptedStepId ?? '',
    /^[a-z0-9][a-z0-9._-]{0,99}$/u,
    '--accept-step-id is invalid.',
  );
}

const packageRoot = resolve(packageRootArgument);
const envelopeFile = resolve(envelopeFileArgument);
const envelope = JSON.parse(await readFile(envelopeFile, 'utf8'));
if (!previewOnly) {
  assert.equal(
    String(envelope.operationHash).toLowerCase(),
    acceptedOperationHash,
    'The saved envelope does not match the confirmed operation hash.',
  );
  assert.ok(
    envelope.steps?.some((step) => step.id === acceptedStepId),
    'The confirmed step is not present in the saved envelope.',
  );
}

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
  { name: 'chainwhisper-live-order-execute-step', version: '0.1.0' },
  { capabilities: { elicitation: { form: { applyDefaults: true } } } },
);
const elicitations = [];
let acceptedCount = 0;

client.setRequestHandler(ElicitRequestSchema, async (request) => {
  const params = request.params;
  if (params.mode && params.mode !== 'form') {
    return { action: 'cancel' };
  }
  const properties = Object.keys(
    params.requestedSchema.properties ?? {},
  );
  const confirmationOnly =
    properties.length === 1 &&
    properties[0] === 'confirm' &&
    params.requestedSchema.properties?.confirm?.type === 'boolean';
  const operationHash = params.message
    .match(/Operation hash: (0x[0-9a-fA-F]{64})/u)?.[1]
    ?.toLowerCase();
  const stepId = params.message.match(
    /Step: [0-9]+\/[0-9]+ \(([^)]+)\)/u,
  )?.[1];
  elicitations.push({
    confirmationOnly,
    operationHash: operationHash ?? null,
    stepId: stepId ?? null,
    message: params.message,
  });
  if (
    confirmationOnly &&
    !previewOnly &&
    operationHash === acceptedOperationHash &&
    stepId === acceptedStepId &&
    acceptedCount === 0
  ) {
    acceptedCount += 1;
    return { action: 'accept', content: { confirm: true } };
  }
  return { action: 'cancel' };
});

try {
  await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
  const result = await client.callTool(
    {
      name: 'chainwhisper_execute_action',
      arguments: { envelope },
    },
    undefined,
    { timeout: REQUEST_TIMEOUT_MS },
  );
  const block = result.content?.find((item) => item.type === 'text');
  assert.ok(block && typeof block.text === 'string');
  let response;
  try {
    response = JSON.parse(block.text);
  } catch {
    response = block.text;
  }
  process.stdout.write(
    `${JSON.stringify(
      {
        acceptedOperationHash,
        acceptedStepId,
        acceptedCount,
        elicitations,
        result: {
          isError: result.isError === true,
          response,
        },
      },
      null,
      2,
    )}\n`,
  );
  assert.equal(
    acceptedCount,
    previewOnly ? 0 : 1,
    previewOnly
      ? 'Preview mode must not accept a write.'
      : 'The exact confirmed step was not accepted.',
  );
} catch (error) {
  const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
  throw new Error(
    `ChainWhisper confirmed order step failed: ${String(error)}${detail}`,
    { cause: error },
  );
} finally {
  await client.close().catch(() => undefined);
}
