import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
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

const argument = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
};

const packageRoot = resolve(
  argument('--package-root') ?? resolve(scriptDirectory, '..'),
);
const saveDirectoryArgument = argument('--save-directory');
const saveDirectory = saveDirectoryArgument
  ? resolve(saveDirectoryArgument)
  : null;
if (saveDirectoryArgument) {
  assert.ok(
    isAbsolute(saveDirectoryArgument),
    '--save-directory must be an absolute local path.',
  );
}
const input = {
  wallet: argument('--wallet'),
  offerAsset: argument('--offer-asset'),
  requestAsset: argument('--request-asset'),
  offerAmount: argument('--offer-amount'),
  requestAmount: argument('--request-amount'),
  access: 'public',
  amountVisibility: 'visible',
  expiresAt: argument('--expires-at'),
  fillPolicy: {
    partialFillsAllowed: false,
  },
};
for (const [name, value] of Object.entries(input)) {
  assert.ok(value, `${name} is required.`);
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

const sharedEnvironmentNames = [
  'CHAINWHISPER_STATE_DIRECTORY',
  'CHAINWHISPER_PAIRING_FILE',
  'CHAINWHISPER_PAIRING_SECRET',
];
const signerEnvironmentNames = [
  'CHAINWHISPER_SIGNER_CONFIG_FILE',
  'CHAINWHISPER_SIGNER_PRIVATE_KEY',
  'CHAINWHISPER_SIGNER_AES_KEY',
  'CHAINWHISPER_SIGNER_VAULT_PASSPHRASE',
  'CHAINWHISPER_SIGNER_EXPECTED_WALLET',
  'CHAINWHISPER_COTI_RPC_URL',
  'CHAINWHISPER_SIGNER_STATE_DIRECTORY',
];

const childEnvironment = (names) => {
  const environment = { ...getDefaultEnvironment() };
  for (const name of names) {
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

const withClient = async (
  name,
  binaryPath,
  environment,
  capabilities,
  configure,
  callback,
) => {
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
    { name: 'chainwhisper-live-order-preview', version: '0.1.0' },
    { capabilities },
  );
  try {
    configure?.(client);
    await client.connect(transport, { timeout: REQUEST_TIMEOUT_MS });
    return await callback(client);
  } catch (error) {
    const detail = stderr.trim() ? `\n${stderr.trim()}` : '';
    throw new Error(`${name} preview failed: ${String(error)}${detail}`, {
      cause: error,
    });
  } finally {
    await client.close().catch(() => undefined);
  }
};

const plannerResult = await withClient(
  'chainwhisper-mcp',
  plannerBinary,
  childEnvironment(sharedEnvironmentNames),
  {},
  null,
  async (client) => {
    const { tools } = await client.listTools(undefined, {
      timeout: REQUEST_TIMEOUT_MS,
    });
    const tool = tools.find(
      (candidate) =>
        candidate.name === 'chainwhisper_prepare_create_trade',
    );
    assert.ok(tool);
    assert.equal(tool.annotations?.readOnlyHint, true);
    const result = await client.callTool(
      {
        name: tool.name,
        arguments: input,
      },
      undefined,
      { timeout: REQUEST_TIMEOUT_MS },
    );
    assert.equal(result.isError, undefined);
    return readToolJson(result);
  },
);
assert.equal(
  plannerResult.ok,
  true,
  `Planner rejected the draft: ${JSON.stringify(plannerResult)}`,
);
assert.equal(
  plannerResult.data?.status,
  'ready',
  `Planner did not produce a ready order: ${JSON.stringify(plannerResult)}`,
);
const prepared = plannerResult.data.envelope;
assert.ok(prepared?.payload, 'Planner did not return an executable envelope.');

const elicitations = [];
const signerResult = await withClient(
  'chainwhisper-coti-signer',
  signerBinary,
  childEnvironment([
    ...sharedEnvironmentNames,
    ...signerEnvironmentNames,
  ]),
  { elicitation: { form: { applyDefaults: true } } },
  (client) => {
    client.setRequestHandler(ElicitRequestSchema, async (request) => {
      const params = request.params;
      assert.ok(
        !params.mode || params.mode === 'form',
        'URL elicitation is not allowed in an order preview.',
      );
      const properties = Object.keys(
        params.requestedSchema.properties ?? {},
      );
      const kind =
        properties.length === 1 && properties[0] === 'confirm'
          ? 'confirmation'
          : 'private-values';
      elicitations.push({
        kind,
        message: params.message,
        fields: properties,
      });
      return { action: 'cancel' };
    });
  },
  async (client) => {
    const result = await client.callTool(
      {
        name: 'chainwhisper_execute_action',
        arguments: { envelope: prepared.payload },
      },
      undefined,
      { timeout: REQUEST_TIMEOUT_MS },
    );
    const block = result.content?.find((item) => item.type === 'text');
    assert.ok(block && typeof block.text === 'string');
    try {
      return {
        isError: result.isError === true,
        response: JSON.parse(block.text),
      };
    } catch {
      return {
        isError: result.isError === true,
        response: block.text,
      };
    }
  },
);

const signed = prepared.payload;
let envelopeFile = null;
if (saveDirectory) {
  await mkdir(saveDirectory, { recursive: true, mode: 0o700 });
  envelopeFile = resolve(
    saveDirectory,
    `${prepared.operationId}.json`,
  );
  assert.ok(
    envelopeFile.startsWith(`${saveDirectory}${sep}`),
    'Refusing to save an envelope outside the requested directory.',
  );
  await writeFile(
    envelopeFile,
    `${JSON.stringify(signed, null, 2)}\n`,
    { encoding: 'utf8', mode: 0o600, flag: 'wx' },
  );
}
process.stdout.write(
  `${JSON.stringify(
    {
      plan: {
        status: plannerResult.data.status,
        intent: plannerResult.data.intent,
        warnings: plannerResult.data.warnings,
        operationId: prepared.operationId,
        operationHash: prepared.operationHash,
        envelopeExpiresAt: prepared.expiresAt,
        fee: signed.fee,
        exactNativeValue: signed.exactNativeValue,
        gasCap: signed.gasCap,
        envelopeFile,
        steps: signed.steps.map((step) => ({
          id: step.id,
          kind: step.kind,
          contract: step.to,
          value: step.value,
          gasCap: step.gasCap,
          summary: step.summary,
        })),
      },
      elicitations,
      signerPreview: signerResult,
    },
    null,
    2,
  )}\n`,
);
process.stdout.write(
  'Order preview completed; every elicitation was cancelled and no transaction was signed.\n',
);
