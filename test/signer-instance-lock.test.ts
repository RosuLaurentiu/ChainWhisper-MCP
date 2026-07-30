import {
  mkdtemp,
  readFile,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type Server } from 'node:net';

import { describe, expect, it } from 'vitest';

import { acquireSignerInstanceLock } from '../src/signer/index.js';

const listenOnLoopback = async (): Promise<{ port: number; server: Server }> => {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Expected a loopback TCP port.');
  }
  return { port: address.port, server };
};

const closeServer = async (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });

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

  it('does not reclaim a dead owner without a recorded control health port', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-dead-unbound-lock-'),
    );
    await writeFile(
      join(stateDirectory, 'signer.instance.lock'),
      JSON.stringify({
        version: 1,
        token: 'ab'.repeat(32),
        pid: 999_999_999,
        createdAt: '2026-07-27T12:00:00.000Z',
      }),
      { encoding: 'utf8', mode: 0o600, flag: 'wx' },
    );

    await expect(
      acquireSignerInstanceLock(stateDirectory),
    ).rejects.toMatchObject({ code: 'SIGNER_ALREADY_RUNNING' });
  });

  it('does not reclaim a dead owner while its loopback health port responds', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-live-port-lock-'),
    );
    const { port, server } = await listenOnLoopback();
    try {
      await writeFile(
        join(stateDirectory, 'signer.instance.lock'),
        JSON.stringify({
          version: 1,
          token: 'ab'.repeat(32),
          pid: 999_999_999,
          createdAt: '2026-07-27T12:00:00.000Z',
          controlPort: port,
        }),
        { encoding: 'utf8', mode: 0o600, flag: 'wx' },
      );

      await expect(
        acquireSignerInstanceLock(stateDirectory),
      ).rejects.toMatchObject({ code: 'SIGNER_ALREADY_RUNNING' });
    } finally {
      await closeServer(server);
    }
  });

  it('reclaims a well-formed lock only after its process and loopback server are gone', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-dead-lock-'),
    );
    const { port, server } = await listenOnLoopback();
    await closeServer(server);
    await writeFile(
      join(stateDirectory, 'signer.instance.lock'),
      JSON.stringify({
        version: 1,
        token: 'ab'.repeat(32),
        pid: 999_999_999,
        createdAt: '2026-07-27T12:00:00.000Z',
        controlPort: port,
      }),
      { encoding: 'utf8', mode: 0o600, flag: 'wx' },
    );

    const lock = await acquireSignerInstanceLock(stateDirectory);
    await lock.release();
  });

  it('records the active Agent Control port in the owned lock', async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), 'cw-signer-health-lock-'),
    );
    const lock = await acquireSignerInstanceLock(stateDirectory);
    await lock.setControlPort(32_123);

    expect(JSON.parse(await readFile(lock.path, 'utf8'))).toMatchObject({
      pid: process.pid,
      controlPort: 32_123,
    });
    await lock.release();
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
