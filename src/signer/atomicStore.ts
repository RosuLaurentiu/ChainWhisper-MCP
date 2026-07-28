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

export class AtomicJsonStore<T> {
  readonly #path: string;
  readonly #fallback: () => T;
  #mutationTail: Promise<void> = Promise.resolve();

  constructor(path: string, fallback: () => T) {
    this.#path = resolve(path);
    this.#fallback = fallback;
  }

  get path(): string {
    return this.#path;
  }

  async exists(): Promise<boolean> {
    try {
      await stat(this.#path);
      return true;
    } catch (error) {
      if (isMissing(error)) return false;
      throw error;
    }
  }

  async read(): Promise<T> {
    try {
      return JSON.parse(await readFile(this.#path, 'utf8')) as T;
    } catch (error) {
      if (isMissing(error)) return this.#fallback();
      throw error;
    }
  }

  async write(value: T): Promise<void> {
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
      await rename(temporaryPath, this.#path);
    } catch (error) {
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }

  async mutate<R>(mutation: (current: T) => Promise<R> | R): Promise<R> {
    const previous = this.#mutationTail;
    let release: () => void = () => undefined;
    this.#mutationTail = new Promise<void>((resolveMutation) => {
      release = resolveMutation;
    });
    await previous;
    try {
      const current = await this.read();
      const result = await mutation(current);
      await this.write(current);
      return result;
    } finally {
      release();
    }
  }
}
