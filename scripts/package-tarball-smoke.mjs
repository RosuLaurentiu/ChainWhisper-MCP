import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, resolve, sep } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDirectory, '..');
const repositoryRoot = resolve(packageRoot, '..', '..');
const repositoryNodeModules = resolve(repositoryRoot, 'node_modules');

const npmInvocation = () => {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && isAbsolute(npmExecPath)) {
    return {
      command: process.execPath,
      prefix: [npmExecPath],
      flavor: basename(npmExecPath).toLowerCase().startsWith('pnpm')
        ? 'pnpm'
        : 'npm',
    };
  }
  return {
    command: process.platform === 'win32' ? 'npm.cmd' : 'npm',
    prefix: [],
    flavor: 'npm',
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
    child.on('error', rejectPromise);
    child.on('close', (code) => {
      if (code === 0) {
        resolvePromise({ stdout, stderr });
        return;
      }
      rejectPromise(
        new Error(
          `${command} exited with code ${String(code)}${
            stderr.trim() ? `\n${stderr.trim()}` : ''
          }`,
        ),
      );
    });
  });

const npm = npmInvocation();
const temporaryRoot = await mkdtemp(
  resolve(repositoryNodeModules, '.chainwhisper-mcp-tarball-'),
);

try {
  const packDirectory = resolve(temporaryRoot, 'pack');
  const consumerDirectory = resolve(temporaryRoot, 'consumer');
  await mkdir(packDirectory, { recursive: true });
  await mkdir(consumerDirectory, { recursive: true });

  const packResult = await run(
    npm.command,
    npm.flavor === 'pnpm'
      ? [
          ...npm.prefix,
          'pack',
          '--json',
          '--pack-destination',
          packDirectory,
        ]
      : [
          ...npm.prefix,
          'pack',
          packageRoot,
          '--json',
          '--ignore-scripts',
          '--pack-destination',
          packDirectory,
        ],
    {
      cwd: npm.flavor === 'pnpm' ? packageRoot : repositoryRoot,
      env: {
        ...process.env,
        npm_config_ignore_scripts: 'true',
        pnpm_config_ignore_scripts: 'true',
      },
    },
  );
  const parsedPack = JSON.parse(packResult.stdout.trim());
  const packed = Array.isArray(parsedPack) ? parsedPack : [parsedPack];
  assert.ok(Array.isArray(packed) && packed.length === 1);
  const entry = packed[0];
  assert.equal(entry.name, '@chainwhisper/agent-tools');
  assert.equal(entry.version, '0.1.0-beta.0');
  assert.ok(typeof entry.filename === 'string' && entry.filename.endsWith('.tgz'));

  const packedPaths = new Set(
    (entry.files ?? []).map((file) => String(file.path).replaceAll('\\', '/')),
  );
  for (const required of [
    'README.md',
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
    tarballPath.startsWith(`${resolve(temporaryRoot)}${sep}`),
    'Packed tarball escaped the temporary directory.',
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

  const installedPackage = resolve(
    consumerDirectory,
    'node_modules',
    '@chainwhisper',
    'agent-tools',
  );
  await mkdir(installedPackage, { recursive: true });
  await run(
    tarCommand,
    [
      '-xzf',
      tarballPath,
      '-C',
      installedPackage,
      '--strip-components=1',
    ],
    { cwd: temporaryRoot },
  );
  await run(
    process.execPath,
    [
      resolve(scriptDirectory, 'package-smoke.mjs'),
      '--package-root',
      installedPackage,
    ],
    { cwd: consumerDirectory },
  );

  const installedPackageJson = JSON.parse(
    await readFile(resolve(installedPackage, 'package.json'), 'utf8'),
  );
  assert.equal(installedPackageJson.version, entry.version);
  process.stdout.write(
    `Packed, inspected, unpacked into an isolated node_modules layout, and stdio-smoked ${entry.name}@${entry.version}.\n`,
  );
} finally {
  const resolvedNodeModules = resolve(repositoryNodeModules);
  const resolvedRoot = resolve(temporaryRoot);
  assert.ok(
    resolvedRoot.startsWith(`${resolvedNodeModules}${sep}`),
    'Refusing to remove a package-smoke directory outside repository node_modules.',
  );
  await rm(resolvedRoot, { recursive: true, force: true });
}
