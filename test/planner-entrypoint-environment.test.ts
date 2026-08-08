import { execFile } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);

const signerOnlyEnvironment = {
  CHAINWHISPER_SIGNER_PRIVATE_KEY: 'private-key',
  CHAINWHISPER_SIGNER_AES_KEY: 'privacy-key',
  CHAINWHISPER_SIGNER_VAULT_PASSPHRASE: 'passphrase',
  CHAINWHISPER_SIGNER_ENV_FILE: '/secret/signer.env',
  CHAINWHISPER_SIGNER_CONFIG_FILE: '/secret/legacy.json',
  CHAINWHISPER_SIGNER_EXPECTED_WALLET: '0xwallet',
  CHAINWHISPER_SIGNER_STATE_DIRECTORY: '/secret/signer-state',
  CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL: 'local-web',
  CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS: '60000',
  CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS: '30000',
} as const;

const requiredPlannerEnvironment = {
  CHAINWHISPER_PAIRING_SECRET:
    'planner-pairing-secret-with-at-least-thirty-two-characters',
  CHAINWHISPER_COTI_RPC_URL: 'https://mainnet.coti.io/rpc',
  CHAINWHISPER_STATE_DIRECTORY: '/planner/state',
} as const;

const transpile = (source: string): string =>
  ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ES2022,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;

describe('planner executable environment boundary', () => {
  it('scrubs every signer-only key before broad dependencies evaluate', async () => {
    const root = await mkdtemp(join(tmpdir(), 'cw-planner-bootstrap-'));
    try {
      const binDirectory = join(root, 'bin');
      const plannerDirectory = join(root, 'planner');
      const serverDirectory = join(root, 'server');
      await Promise.all([
        mkdir(binDirectory, { recursive: true }),
        mkdir(plannerDirectory, { recursive: true }),
        mkdir(serverDirectory, { recursive: true }),
      ]);

      const [entrySource, environmentSource] = await Promise.all([
        readFile(
          new URL('../src/bin/chainwhisper-mcp.ts', import.meta.url),
          'utf8',
        ),
        readFile(
          new URL('../src/planner/environment.ts', import.meta.url),
          'utf8',
        ),
      ]);
      const entryPath = join(binDirectory, 'chainwhisper-mcp.js');
      const environmentPath = join(plannerDirectory, 'environment.js');
      const serverProbePath = join(root, 'server-probe.json');
      const plannerProbePath = join(root, 'planner-probe.json');
      const fakeServerPath = join(serverDirectory, 'index.js');
      const fakePlannerPath = join(plannerDirectory, 'server.js');

      await Promise.all([
        writeFile(join(root, 'package.json'), '{"type":"module"}\n'),
        writeFile(entryPath, transpile(entrySource)),
        writeFile(environmentPath, transpile(environmentSource)),
        writeFile(
          fakeServerPath,
          `import { writeFileSync } from 'node:fs';
const keys = JSON.parse(process.env.CHAINWHISPER_TEST_PROBE_KEYS);
writeFileSync(
  process.env.CHAINWHISPER_TEST_SERVER_PROBE_PATH,
  JSON.stringify(Object.fromEntries(keys.map((key) => [key, process.env[key] ?? null])))
);
export const connectStdioMcpServer = async () => {};
export const writeFatalMcpError = () => {};
`,
        ),
        writeFile(
          fakePlannerPath,
          `import { writeFileSync } from 'node:fs';
const keys = JSON.parse(process.env.CHAINWHISPER_TEST_PROBE_KEYS);
writeFileSync(
  process.env.CHAINWHISPER_TEST_PLANNER_PROBE_PATH,
  JSON.stringify(Object.fromEntries(keys.map((key) => [key, process.env[key] ?? null])))
);
export const createChainWhisperPlanningServer = async () => ({});
`,
        ),
      ]);

      const observedKeys = [
        ...Object.keys(signerOnlyEnvironment),
        ...Object.keys(requiredPlannerEnvironment),
      ];
      await execFileAsync(
        process.execPath,
        [entryPath],
        {
          env: {
            ...process.env,
            ...signerOnlyEnvironment,
            ...requiredPlannerEnvironment,
            CHAINWHISPER_TEST_PROBE_KEYS: JSON.stringify(observedKeys),
            CHAINWHISPER_TEST_SERVER_PROBE_PATH: serverProbePath,
            CHAINWHISPER_TEST_PLANNER_PROBE_PATH: plannerProbePath,
          },
          windowsHide: true,
        },
      );

      const [serverObserved, plannerObserved] = await Promise.all(
        [serverProbePath, plannerProbePath].map(async (path) =>
          JSON.parse(await readFile(path, 'utf8')) as Record<
            string,
            string | null
          >,
        ),
      );
      const expected = {
        ...Object.fromEntries(
          Object.keys(signerOnlyEnvironment).map((key) => [key, null]),
        ),
        ...requiredPlannerEnvironment,
      };
      expect(serverObserved).toEqual(expected);
      expect(plannerObserved).toEqual(expected);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
