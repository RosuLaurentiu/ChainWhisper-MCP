import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  ensurePrivateStateDirectory,
  writePrivateCredentialFileAtomic,
} from '../src/signer/stateSecurity.js';

describe('signer path security', () => {
  it.skipIf(process.platform !== 'darwin')(
    'allows the root-owned macOS /var alias used by temporary directories',
    async () => {
      const stateDirectory = await mkdtemp(
        '/var/tmp/chainwhisper-state-',
      );
      try {
        await expect(
          ensurePrivateStateDirectory(stateDirectory),
        ).resolves.toBe(resolve(stateDirectory));

        const credentialFile = join(stateDirectory, 'signer.env');
        await expect(
          writePrivateCredentialFileAtomic(
            credentialFile,
            'CHAINWHISPER_SIGNER_PRIVATE_KEY="test"\n',
          ),
        ).resolves.toBeUndefined();
      } finally {
        await rm(stateDirectory, { recursive: true, force: true });
      }
    },
  );

  it.skipIf(process.platform === 'win32')(
    'still rejects a user-controlled symbolic-link path component',
    async () => {
      const root = await mkdtemp(join(tmpdir(), 'cw-linked-state-'));
      const target = join(root, 'target');
      const linked = join(root, 'linked');
      await mkdir(target, { mode: 0o700 });
      await symlink(target, linked, 'dir');

      try {
        await expect(
          ensurePrivateStateDirectory(join(linked, 'state')),
        ).rejects.toMatchObject({
          diagnosticCode: 'state-path-linked',
        });
        await expect(
          writePrivateCredentialFileAtomic(
            join(linked, 'signer.env'),
            '',
          ),
        ).rejects.toMatchObject({
          diagnosticCode: 'state-path-linked',
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
