import {
  mkdtemp,
  readFile,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { acquireSignerInstanceLock } from '../src/signer/index.js';

describe('signer instance lock', () => {
  it('allows only one signer for a state directory and releases normally', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-lock-'),
    );
    const first = await acquireSignerInstanceLock(stateDirectory);

    await expect(
      acquireSignerInstanceLock(stateDirectory),
    ).rejects.toMatchObject({ code: 'SIGNER_ALREADY_RUNNING' });

    await first.release();
    await first.release();

    const next = await acquireSignerInstanceLock(stateDirectory);
    await next.release();
  });

  it('fails closed when a stale lock artifact exists', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-stale-lock-'),
    );
    await writeFile(
      join(stateDirectory, 'signer.instance.lock'),
      JSON.stringify({
        version: 1,
        token: 'stale-token',
        pid: 999_999,
        createdAt: '2026-07-27T12:00:00.000Z',
      }),
      { encoding: 'utf8', mode: 0o600, flag: 'wx' },
    );

    await expect(
      acquireSignerInstanceLock(stateDirectory),
    ).rejects.toMatchObject({ code: 'SIGNER_ALREADY_RUNNING' });
  });

  it('never removes a lock whose ownership token changed', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-owned-lock-'),
    );
    const lock = await acquireSignerInstanceLock(stateDirectory);
    await writeFile(
      lock.path,
      JSON.stringify({
        version: 1,
        token: 'different-token',
        pid: process.pid,
        createdAt: '2026-07-27T12:00:00.000Z',
      }),
      'utf8',
    );

    await expect(lock.release()).rejects.toMatchObject({
      code: 'SIGNER_LOCK_OWNERSHIP_LOST',
    });
    expect(await readFile(lock.path, 'utf8')).toContain(
      'different-token',
    );
  });
});
