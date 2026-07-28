export class NonceQueue {
  readonly #getPendingNonce: () => Promise<number>;
  #nextNonce: number | null = null;
  #tail: Promise<void> = Promise.resolve();

  constructor(getPendingNonce: () => Promise<number>) {
    this.#getPendingNonce = getPendingNonce;
  }

  async #exclusive<T>(work: () => Promise<T>): Promise<T> {
    const previous = this.#tail;
    let release: () => void = () => undefined;
    this.#tail = new Promise<void>((resolveWork) => {
      release = resolveWork;
    });
    await previous;
    try {
      return await work();
    } finally {
      release();
    }
  }

  async runTransaction<T>(
    work: (nonce: number) => Promise<T>,
  ): Promise<{ nonce: number; result: T }> {
    return this.#exclusive(async () => {
      const nonce = this.#nextNonce ?? (await this.#getPendingNonce());
      try {
        const result = await work(nonce);
        this.#nextNonce = nonce + 1;
        return { nonce, result };
      } catch (error) {
        this.#nextNonce = null;
        throw error;
      }
    });
  }

  async runExternalWrite<T>(
    work: (pendingNonce: number) => Promise<T>,
  ): Promise<{ nonce: number; result: T }> {
    return this.#exclusive(async () => {
      this.#nextNonce = null;
      try {
        const nonce = await this.#getPendingNonce();
        return { nonce, result: await work(nonce) };
      } finally {
        this.#nextNonce = null;
      }
    });
  }

  invalidate(): void {
    this.#nextNonce = null;
  }
}
