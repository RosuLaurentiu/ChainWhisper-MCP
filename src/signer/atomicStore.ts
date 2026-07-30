import {
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink,
} from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

const isMissing = (error: unknown): boolean =>
  Boolean(
    error &&
      typeof error === 'object' &&
      'code' in error &&
      (error as { code?: string }).code === 'ENOENT',
  );

const isTransientRenameError = (error: unknown): boolean =>
  Boolean(
    error &&
      typeof error === 'object' &&
      'code' in error &&
      ['EACCES', 'EBUSY', 'EPERM'].includes(
        (error as { code?: string }).code ?? '',
      ),
  );

const RENAME_RETRY_LIMIT = 7;

const waitForRenameRetry = async (attempt: number): Promise<void> => {
  await new Promise<void>((resolveWait) => {
    setTimeout(resolveWait, Math.min(5 * 2 ** attempt, 100));
  });
};

const replaceFile = async (
  temporaryPath: string,
  destinationPath: string,
): Promise<void> => {
  for (let attempt = 0; ; attempt += 1) {
    try {
      await rename(temporaryPath, destinationPath);
      return;
    } catch (error) {
      if (
        !isTransientRenameError(error) ||
        attempt >= RENAME_RETRY_LIMIT
      ) {
        throw error;
      }
      await waitForRenameRetry(attempt);
    }
  }
};

export class AtomicJsonStore<T> {
  readonly #path: string;
  readonly #fallback: () => T;
  #operationTail: Promise<void> = Promise.resolve();

  constructor(path: string, fallback: () => T) {
    this.#path = resolve(path);
    this.#fallback = fallback;
  }

  get path(): string {
    return this.#path;
  }

  async #runExclusive<R>(operation: () => Promise<R>): Promise<R> {
    const previous = this.#operationTail;
    let release: () => void = () => undefined;
    this.#operationTail = new Promise<void>((resolveOperation) => {
      release = resolveOperation;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  async #existsUnlocked(): Promise<boolean> {
    try {
      await stat(this.#path);
      return true;
    } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
  }

  async exists(): Promise<boolean> {
    return this.#runExclusive(() => this.#existsUnlocked());
  }

  async #readUnlocked(): Promise<T> {
    try {
      return JSON.parse(await readFile(this.#path, 'utf8')) as T;
    } catch (error) {
      if (isMissing(error)) return this.#fallback();
      throw error;
    }
  }

  async read(): Promise<T> {
    return this.#runExclusive(() => this.#readUnlocked());
  }

  async #writeUnlocked(value: T): Promise<void> {
    await mkdir(dirname(this.#path), { recursive: true, mode: 0o700 });
    const temporaryPath = resolve(
      dirname(this.#path),
      `.${basename(this.#path)}.${process.pid}.${randomUUID()}.tmp`,
    );
    const handle = await open(temporaryPath, 'wx', 0o600);
    try {
      await handle.writeFile(JSON.stringify(value), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await replaceFile(temporaryPath, this.#path);
    } catch (error) {
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }

  async write(value: T): Promise<void> {
    await this.#runExclusive(() => this.#writeUnlocked(value));
  }

  async mutate<R>(mutation: (current: T) => Promise<R> | R): Promise<R> {
    return this.#runExclusive(async () => {
      const current = await this.#readUnlocked();
      const result = await mutation(current);
      await this.#writeUnlocked(current);
      return result;
    });
  }
}
