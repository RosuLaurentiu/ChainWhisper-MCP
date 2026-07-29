import { randomUUID } from 'node:crypto';
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises';
import {
  basename,
  dirname,
  join,
  parse,
  relative,
  resolve,
  sep,
} from 'node:path';

export type SignerPathDiagnosticCode =
  | 'state-path-invalid'
  | 'state-path-linked'
  | 'state-path-permissions'
  | 'credential-file-invalid'
  | 'credential-file-linked'
  | 'credential-file-permissions';

export class SignerPathSecurityError extends Error {
  readonly diagnosticCode: SignerPathDiagnosticCode;

  constructor(
    diagnosticCode: SignerPathDiagnosticCode,
    message: string,
  ) {
    super(message);
    this.name = 'SignerPathSecurityError';
    this.diagnosticCode = diagnosticCode;
  }
}

const errorCode = (error: unknown): string | undefined =>
  error && typeof error === 'object' && 'code' in error
    ? String((error as { code?: unknown }).code)
    : undefined;

export const isMissingPathError = (error: unknown): boolean =>
  errorCode(error) === 'ENOENT';

// macOS publishes TMPDIR under /var/folders even though /var is an
// OS-managed alias. Only that exact root-owned alias and target are trusted;
// every descendant component still goes through the normal link check.
const isTrustedMacOsVarAlias = async (
  path: string,
  ownerUid: number,
): Promise<boolean> => {
  if (
    process.platform !== 'darwin' ||
    path !== '/var' ||
    ownerUid !== 0
  ) {
    return false;
  }
  try {
    return (await realpath(path)) === '/private/var';
  } catch {
    return false;
  }
};

const assertNoLinkedComponents = async (
  inputPath: string,
  allowMissingTail: boolean,
): Promise<void> => {
  const absolute = resolve(inputPath);
  const root = parse(absolute).root;
  const remainder = relative(root, absolute);
  const segments = remainder ? remainder.split(sep) : [];
  let current = root;

  for (const segment of segments) {
    current = join(current, segment);
    try {
      const details = await lstat(current);
      if (
        details.isSymbolicLink() &&
        !(await isTrustedMacOsVarAlias(current, details.uid))
      ) {
        throw new SignerPathSecurityError(
          'state-path-linked',
          'The signer path must not contain symbolic links or junctions.',
        );
      }
    } catch (error) {
      if (allowMissingTail && isMissingPathError(error)) return;
      throw error;
    }
  }
};

const assertPrivateMode = (
  mode: number,
  diagnosticCode: SignerPathDiagnosticCode,
  message: string,
  mask = 0o077,
): void => {
  if (process.platform !== 'win32' && (mode & mask) !== 0) {
    throw new SignerPathSecurityError(diagnosticCode, message);
  }
};

const validateStateTree = async (directory: string): Promise<void> => {
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(directory, entry.name);
    const details = await lstat(path);
    if (details.isSymbolicLink()) {
      throw new SignerPathSecurityError(
        'state-path-linked',
        'The signer state directory must not contain symbolic links or junctions.',
      );
    }
    if (details.isDirectory()) {
      assertPrivateMode(
        details.mode,
        'state-path-permissions',
        'Signer state directories must be accessible only by the current user.',
      );
      await validateStateTree(path);
      continue;
    }
    if (!details.isFile()) {
      throw new SignerPathSecurityError(
        'state-path-invalid',
        'The signer state directory contains an unsupported filesystem entry.',
      );
    }
    assertPrivateMode(
      details.mode,
      'state-path-permissions',
      'Signer state files must be accessible only by the current user.',
    );
  }
};

/**
 * Creates and validates the signer state boundary before any signer store is
 * opened. Windows symbolic links and junctions are rejected, but Node does not
 * expose a portable same-user ACL check; Windows therefore relies on the
 * current user's profile ACL.
 */
export const ensurePrivateStateDirectory = async (
  stateDirectory: string,
): Promise<string> => {
  const directory = resolve(stateDirectory);
  await assertNoLinkedComponents(directory, true);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await assertNoLinkedComponents(directory, false);

  const details = await lstat(directory);
  if (!details.isDirectory() || details.isSymbolicLink()) {
    throw new SignerPathSecurityError(
      'state-path-invalid',
      'The signer state path must be a regular directory.',
    );
  }
  assertPrivateMode(
    details.mode,
    'state-path-permissions',
    'The signer state directory must be accessible only by the current user.',
  );
  await validateStateTree(directory);
  return directory;
};

const assertCredentialParent = async (filePath: string): Promise<void> => {
  const parent = dirname(resolve(filePath));
  await assertNoLinkedComponents(parent, true);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await assertNoLinkedComponents(parent, false);
  const details = await lstat(parent);
  if (!details.isDirectory() || details.isSymbolicLink()) {
    throw new SignerPathSecurityError(
      'credential-file-invalid',
      'The signer credential file parent must be a regular directory.',
    );
  }
  assertPrivateMode(
    details.mode,
    'credential-file-permissions',
    'The signer credential file parent must not be writable by other users.',
    0o022,
  );
};

export const assertPrivateCredentialFile = async (
  filePath: string,
  options: { allowMissing?: boolean } = {},
): Promise<boolean> => {
  const absolute = resolve(filePath);
  await assertCredentialParent(absolute);
  await assertNoLinkedComponents(absolute, options.allowMissing === true);
  try {
    const details = await lstat(absolute);
    if (!details.isFile() || details.isSymbolicLink()) {
      throw new SignerPathSecurityError(
        'credential-file-invalid',
        'The signer credential path must be a regular file.',
      );
    }
    assertPrivateMode(
      details.mode,
      'credential-file-permissions',
      'The signer credential file must be accessible only by the current user.',
    );
    return true;
  } catch (error) {
    if (options.allowMissing && isMissingPathError(error)) return false;
    throw error;
  }
};

export const readPrivateCredentialFile = async (
  filePath: string,
  options: { allowMissing?: boolean } = {},
): Promise<string | null> => {
  const exists = await assertPrivateCredentialFile(filePath, options);
  if (!exists) return null;
  return readFile(resolve(filePath), 'utf8');
};

export const writePrivateCredentialFileAtomic = async (
  filePath: string,
  contents: string,
): Promise<void> => {
  const absolute = resolve(filePath);
  await assertPrivateCredentialFile(absolute, { allowMissing: true });
  const temporaryPath = join(
    dirname(absolute),
    `.${basename(absolute)}.${process.pid}.${randomUUID()}.tmp`,
  );
  const handle = await open(temporaryPath, 'wx', 0o600);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporaryPath, absolute);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
  await assertPrivateCredentialFile(absolute);
};
