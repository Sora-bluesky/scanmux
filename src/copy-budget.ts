import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat, open, unlink } from 'node:fs/promises';
import { SafeError } from './safety.ts';

export class JobDiskCopyLimitError extends SafeError {
  constructor() { super('job_disk_copy_limit'); }
}
export class CopyCleanupError extends SafeError {
  constructor() { super('copy_cleanup_failed'); }
}

/** Logical copy bytes, independent of retained-record accounting and physical allocation. */
export class CopyBudget {
  readonly limit: number;
  #reservedBytes = 0;
  constructor(limit: number) {
    // Zero is a valid remaining allowance handed from the host to the payload.
    if (!Number.isSafeInteger(limit) || limit < 0) throw new SafeError('invalid_copy_budget');
    this.limit = limit;
  }
  get reservedBytes(): number { return this.#reservedBytes; }
  get remainingBytes(): number { return this.limit - this.#reservedBytes; }

  async copy(source: string, destination: string, options: { maximumBytes?: number; sourceChangedCode?: string; signal?: AbortSignal; mode?: number } = {}) {
    options.signal?.throwIfAborted();
    const before = await stat(source), maximum = options.maximumBytes ?? before.size;
    const changed = () => new SafeError(options.sourceChangedCode ?? 'copy_source_changed');
    if (!before.isFile()) throw new SafeError('invalid_copy_source');
    if (!Number.isSafeInteger(before.size) || before.size < 0 || !Number.isSafeInteger(maximum) || maximum < 0) throw new SafeError('invalid_copy_size');
    if (before.size > maximum) throw changed();
    if (before.size > this.remainingBytes) throw new JobDiskCopyLimitError();
    // No await between admission and reservation: concurrent copies cannot spend the same bytes.
    const reservation = before.size;
    this.#reservedBytes += reservation;
    let output: Awaited<ReturnType<typeof open>> | undefined, created = false, bytes = 0;
    const digest = createHash('sha256');
    try {
      output = await open(destination, 'wx', options.mode ?? 0o600); created = true;
      for await (const chunk of createReadStream(source, { highWaterMark: 65536, signal: options.signal })) {
        options.signal?.throwIfAborted();
        if (chunk.length > reservation - bytes || chunk.length > maximum - bytes) throw changed();
        let offset = 0;
        while (offset < chunk.length) {
          options.signal?.throwIfAborted();
          const written = await output.write(chunk, offset, chunk.length - offset);
          if (written.bytesWritten === 0) throw new SafeError('copy_write_failed');
          offset += written.bytesWritten; bytes += written.bytesWritten;
        }
        digest.update(chunk);
      }
      const after = await stat(source);
      if (bytes !== reservation || after.size !== reservation || !after.isFile()) throw changed();
      await output.close(); output = undefined;
      return { bytes, sha256: digest.digest('hex') };
    } catch (error) {
      let closeError: unknown;
      try { await output?.close(); } catch (failure) { closeError = failure; }
      // Keep charging the reservation if a partial destination cannot be removed.
      if (created) try { await unlink(destination); } catch { throw new CopyCleanupError(); }
      this.#reservedBytes -= reservation;
      throw closeError ?? error;
    }
  }
}

const scope = new AsyncLocalStorage<CopyBudget | undefined>();
export const scopedCopyBudget = (): CopyBudget | undefined => scope.getStore();
export function withCopyBudget<T>(limit: number | CopyBudget | undefined, body: () => Promise<T>): Promise<T> {
  return scope.run(typeof limit === 'number' ? new CopyBudget(limit) : limit, body);
}
