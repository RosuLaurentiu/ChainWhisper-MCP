import {
  mkdtemp,
  readFile,
  readdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from 'vitest';

const fsMock = vi.hoisted(() => ({
  rename: vi.fn(),
  actualRename: null as
    | typeof import('node:fs/promises').rename
    | null,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('node:fs/promises')>();
  fsMock.actualRename = actual.rename;
  fsMock.rename.mockImplementation(actual.rename);
  return {
    ...actual,
    rename: fsMock.rename,
  };
});

import { AtomicJsonStore } from '../src/signer/atomicStore.js';

type TestState = {
  value: number;
};

const createStore = async (): Promise<{
  directory: string;
  store: AtomicJsonStore<TestState>;
}> => {
  const directory = await mkdtemp(join(tmpdir(), 'cw-atomic-store-'));
  return {
    directory,
    store: new AtomicJsonStore(
      join(directory, 'state.json'),
      () => ({ value: 0 }),
    ),
  };
};

const transientRenameError = (): NodeJS.ErrnoException =>
  Object.assign(new Error('The destination is temporarily locked.'), {
    code: 'EPERM',
  });

describe('AtomicJsonStore', () => {
  beforeEach(() => {
    fsMock.rename.mockReset();
    fsMock.rename.mockImplementation(fsMock.actualRename!);
  });

  it('serializes reads and writes behind an active mutation', async () => {
    const { store } = await createStore();
    await store.write({ value: 1 });
    let releaseMutation: () => void = () => undefined;
    let markMutationStarted: () => void = () => undefined;
    const mutationStarted = new Promise<void>((resolve) => {
      markMutationStarted = resolve;
    });
    const mutationGate = new Promise<void>((resolve) => {
      releaseMutation = resolve;
    });

    const mutation = store.mutate(async (state) => {
      markMutationStarted();
      await mutationGate;
      state.value = 2;
    });
    await mutationStarted;

    let readSettled = false;
    let writeSettled = false;
    const reading = store.read().then((state) => {
      readSettled = true;
      return state;
    });
    const writing = store.write({ value: 3 }).then(() => {
      writeSettled = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));

    expect(readSettled).toBe(false);
    expect(writeSettled).toBe(false);

    releaseMutation();
    await expect(mutation).resolves.toBeUndefined();
    await expect(reading).resolves.toEqual({ value: 2 });
    await expect(writing).resolves.toBeUndefined();
    await expect(store.read()).resolves.toEqual({ value: 3 });
  });

  it('retries transient replacement failures before committing', async () => {
    const { directory, store } = await createStore();
    let attempts = 0;
    fsMock.rename.mockImplementation(async (source, destination) => {
      attempts += 1;
      if (attempts < 3) throw transientRenameError();
      await fsMock.actualRename!(source, destination);
    });

    await expect(store.write({ value: 7 })).resolves.toBeUndefined();

    expect(attempts).toBe(3);
    await expect(store.read()).resolves.toEqual({ value: 7 });
    expect(
      (await readdir(directory)).filter((name) => name.endsWith('.tmp')),
    ).toEqual([]);
  });

  it('removes the temporary file only after retries are exhausted', async () => {
    const { directory, store } = await createStore();
    await store.write({ value: 1 });
    fsMock.rename.mockClear();
    fsMock.rename.mockRejectedValue(transientRenameError());

    await expect(store.write({ value: 9 })).rejects.toMatchObject({
      code: 'EPERM',
    });

    expect(fsMock.rename).toHaveBeenCalledTimes(8);
    expect(JSON.parse(
      await readFile(join(directory, 'state.json'), 'utf8'),
    )).toEqual({ value: 1 });
    expect(
      (await readdir(directory)).filter((name) => name.endsWith('.tmp')),
    ).toEqual([]);
  });
});
