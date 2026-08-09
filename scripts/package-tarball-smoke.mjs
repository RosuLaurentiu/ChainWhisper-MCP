import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  relative,
  resolve,
  sep,
} from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDirectory, '..');
const repositoryRoot = packageRoot;
const sourcePackageJson = JSON.parse(
  await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
);

const readCliOptions = () => {
  let packDestination;
  for (let index = 2; index < process.argv.length; index += 1) {
    const argument = process.argv[index];
    if (argument === '--pack-destination') {
      const value = process.argv[index + 1];
      if (!value || value.startsWith('--')) {
        throw new Error('--pack-destination requires a directory path.');
      }
      packDestination = resolve(process.cwd(), value);
      index += 1;
      continue;
    }
    throw new Error(`Unknown package-tarball-smoke option: ${argument}`);
  }
  return { packDestination };
};

const isWithin = (parent, child) => {
  const resolvedParent = resolve(parent);
  const resolvedChild = resolve(child);
  const relativePath = relative(resolvedParent, resolvedChild);
  return (
    relativePath === '' ||
    (!isAbsolute(relativePath) &&
      relativePath !== '..' &&
      !relativePath.startsWith(`..${sep}`))
  );
};

const npmInvocation = () => {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && isAbsolute(npmExecPath)) {
    if (basename(npmExecPath).toLowerCase().includes('pnpm')) {
      throw new Error(
        'The tarball smoke requires npm so it can verify npm-created command shims. Run it with npm, not pnpm.',
      );
    }
    return {
      command: process.execPath,
      prefix: [npmExecPath],
    };
  }
  return {
    command: process.platform === 'win32' ? 'npm.cmd' : 'npm',
    prefix: [],
  };
};

const run = async (command, args, options = {}) =>
  new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repositoryRoot,
      env: options.env ?? process.env,
      shell:
        process.platform === 'win32' &&
        /\.(?:cmd|bat)$/iu.test(command),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('error', (error) => {
      rejectPromise(
        new Error(
          `Unable to run ${command}. The package tarball smoke requires npm and tar on PATH.`,
          { cause: error },
        ),
      );
    });
    child.on('close', (code) => {
      if (code === 0) {
        resolvePromise({ stdout, stderr });
        return;
      }
      rejectPromise(
        new Error(
          `${command} exited with code ${String(code)}${
            [stderr.trim(), stdout.trim()].filter(Boolean).length > 0
              ? `\n${[stderr.trim(), stdout.trim()].filter(Boolean).join('\n')}`
              : ''
          }`,
        ),
      );
    });
  });

const withoutWorkspaceContext = () => {
  const environment = { ...process.env };
  for (const name of [
    'INIT_CWD',
    'NODE_PATH',
    'NPM_CONFIG_WORKSPACE',
    'NPM_CONFIG_WORKSPACES',
    'npm_config_workspace',
    'npm_config_workspaces',
  ]) {
    delete environment[name];
  }
  environment.npm_config_ignore_scripts = 'true';
  environment.npm_config_audit = 'false';
  environment.npm_config_fund = 'false';
  return environment;
};

const npm = npmInvocation();
const cliOptions = readCliOptions();
const temporaryRoot = await mkdtemp(
  resolve(tmpdir(), 'chainwhisper-mcp-tarball-'),
);

try {
  assert.equal(
    isWithin(repositoryRoot, temporaryRoot),
    false,
    'The package consumer must be outside the repository.',
  );

  const packDirectory =
    cliOptions.packDestination ?? resolve(temporaryRoot, 'pack');
  const consumerDirectory = resolve(temporaryRoot, 'consumer');
  await mkdir(packDirectory, { recursive: true });
  await mkdir(consumerDirectory, { recursive: true });
  await writeFile(
    resolve(consumerDirectory, 'package.json'),
    `${JSON.stringify(
      {
        name: 'chainwhisper-agent-tools-isolated-smoke',
        private: true,
        type: 'module',
      },
      null,
      2,
    )}\n`,
    'utf8',
  );

  const packResult = await run(
    npm.command,
    [
      ...npm.prefix,
      'pack',
      packageRoot,
      '--json',
      '--ignore-scripts',
      '--pack-destination',
      packDirectory,
    ],
    {
      cwd: repositoryRoot,
      env: withoutWorkspaceContext(),
    },
  );
  const parsedPack = JSON.parse(packResult.stdout.trim());
  const packed = Array.isArray(parsedPack) ? parsedPack : [parsedPack];
  assert.equal(packed.length, 1);
  const entry = packed[0];
  assert.equal(entry.name, '@chainwhisper/agent-tools');
  assert.equal(entry.version, sourcePackageJson.version);
  assert.ok(typeof entry.filename === 'string' && entry.filename.endsWith('.tgz'));

  const packedPaths = new Set(
    (entry.files ?? []).map((file) => String(file.path).replaceAll('\\', '/')),
  );
  for (const required of [
    'README.md',
    'CHANGELOG.md',
    'SECURITY.md',
    'LICENSE',
    'package.json',
    'runtime/coti-mainnet.v1.json',
    'dist/bin/chainwhisper-mcp.js',
    'dist/bin/chainwhisper-coti-signer.js',
    'dist/shared/index.js',
    'dist/domain/index.js',
    'dist/signer/index.js',
  ]) {
    assert.ok(packedPaths.has(required), `Packed file is missing: ${required}`);
  }
  for (const path of packedPaths) {
    assert.ok(
      !/^(?:src|test|scripts)\//u.test(path),
      `Development-only path leaked into the package: ${path}`,
    );
    assert.ok(
      !/(?:^|\/)(?:\.env(?:\.|$)|[^/]*(?:private[-_]?key|mnemonic|secret)[^/]*)/iu.test(
        path,
      ),
      `Potential credential material leaked into the package: ${path}`,
    );
  }

  const tarballPath = resolve(packDirectory, entry.filename);
  assert.ok(
    isWithin(packDirectory, tarballPath),
    'Packed tarball escaped its destination directory.',
  );
  const tarCommand = process.env.TAR ?? 'tar';
  const archiveListing = await run(
    tarCommand,
    ['-tzf', tarballPath],
    { cwd: temporaryRoot },
  );
  const archivePaths = archiveListing.stdout
    .split(/\r?\n/u)
    .map((path) => path.trim().replaceAll('\\', '/'))
    .filter(Boolean);
  for (const path of archivePaths) {
    assert.ok(
      path.startsWith('package/') &&
        !path.startsWith('/') &&
        !path.split('/').includes('..'),
      `Unsafe path in the packed archive: ${path}`,
    );
  }
  for (const required of packedPaths) {
    assert.ok(
      archivePaths.includes(`package/${required}`),
      `npm pack reported a file missing from the archive: ${required}`,
    );
  }

  await run(
    npm.command,
    [
      ...npm.prefix,
      'install',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      tarballPath,
    ],
    {
      cwd: consumerDirectory,
      env: withoutWorkspaceContext(),
    },
  );

  const auditEnvironment = withoutWorkspaceContext();
  auditEnvironment.npm_config_audit = 'true';
  await run(
    npm.command,
    [
      ...npm.prefix,
      'audit',
      '--omit=dev',
      '--audit-level=low',
    ],
    {
      cwd: consumerDirectory,
      env: auditEnvironment,
    },
  );

  const installedPackage = resolve(
    consumerDirectory,
    'node_modules',
    '@chainwhisper',
    'agent-tools',
  );
  await access(installedPackage);
  const installedNodeModulesRealPath = await realpath(
    resolve(consumerDirectory, 'node_modules'),
  );
  const installedPackageRealPath = await realpath(installedPackage);
  assert.ok(
    isWithin(installedNodeModulesRealPath, installedPackageRealPath),
    'npm linked the package from outside the isolated consumer.',
  );

  const installedPackageJson = JSON.parse(
    await readFile(resolve(installedPackage, 'package.json'), 'utf8'),
  );
  assert.equal(installedPackageJson.version, entry.version);
  await run(
    process.execPath,
    [
      resolve(scriptDirectory, 'package-smoke.mjs'),
      '--package-root',
      installedPackage,
      '--via-command-shims',
    ],
    {
      cwd: consumerDirectory,
      env: withoutWorkspaceContext(),
    },
  );

  process.stdout.write(
    `Packed, inspected, production-audited, npm-installed outside the repository, and stdio-smoked ${entry.name}@${entry.version} through npm command shims.\n`,
  );
} finally {
  const resolvedTempDirectory = resolve(tmpdir());
  const resolvedRoot = resolve(temporaryRoot);
  assert.ok(
    resolvedRoot.startsWith(`${resolvedTempDirectory}${sep}`),
    'Refusing to remove a package-smoke directory outside the system temp directory.',
  );
  await rm(resolvedRoot, { recursive: true, force: true });
}
