import { AsyncLocalStorage } from 'node:async_hooks';
import { realpathSync, type BigIntStats } from 'node:fs';
import { lstat, readdir, realpath, statfs } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { SafeError } from './safety.ts';

export type JobDiskCause = 'job_disk_measured_limit' | 'job_disk_observation_unverified';
// Directory walks are substantially dearer than the 10 ms process-group probe. 100 ms
// limits the nominal growth window to a tenth of a second without continuously walking.
// Traversal, event-loop scheduling and verified termination add to that window.
export const jobDiskPollMs = 100;
const contains = (parent: string, child: string) => {
  const relative = path.relative(parent, child);
  return relative === '' || relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
};
const samePath = (a: string, b: string) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
const rootKey = (directory: string) => process.platform === 'win32' ? directory.toLowerCase() : directory;
const vanished = (error: unknown) => ['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '');
const sameEntry = (a: BigIntStats, b: BigIntStats) => a.dev === b.dev && a.ino === b.ino
  && a.isDirectory() === b.isDirectory() && a.isSymbolicLink() === b.isSymbolicLink();
// Four attempts per entry bound rename churn, including retries in the final sample.
const entryAttempts = 4;
// Delete-pending metadata gets three confirmations, 10 ms apart; scheduling can add delay.
const deletePendingRetries = 3, deletePendingRetryMs = 10;
const denied = (error: unknown) => ['EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '');

/** A sampled estimate of current regular-file sizes, not allocation or a quota. */
export class JobDisk {
  readonly limit: number;
  readonly #abort = new AbortController();
  readonly #roots = new Map<string, string>();
  #pending: Promise<bigint> | undefined;
  #cause: JobDiskCause | undefined;
  #active = true;
  #localBytes: bigint | undefined;
  #peerBytes = 0n;
  #forceSample = false;
  readonly #onSample: ((bytes: bigint | null, force: boolean) => Promise<void>) | undefined;
  constructor(limit: number, onSample?: (bytes: bigint | null, force: boolean) => Promise<void>) {
    if (!Number.isSafeInteger(limit) || limit <= 0) throw new SafeError('invalid_limit');
    this.limit = limit;
    this.#onSample = onSample;
  }
  get active(): boolean { return this.#active; }
  end(): void { this.#active = false; }
  get signal(): AbortSignal { return this.#abort.signal; }
  get cause(): JobDiskCause | undefined { return this.#cause; }
  register(directory: string): void {
    try {
      const canonical = realpathSync.native(path.resolve(directory));
      this.#roots.set(rootKey(canonical), canonical);
    } catch { this.stop('job_disk_observation_unverified'); }
  }
  release(directory: string): void {
    let canonical = path.resolve(directory);
    try { canonical = realpathSync.native(canonical); } catch { /* A missing root is still removable by its canonical name. */ }
    for (const [key, root] of this.#roots) if (contains(canonical, root)) this.#roots.delete(key);
  }
  /** The peer's latest observation is added once, never charged as a retained write. */
  updatePeerSample(bytes: bigint | null): void {
    if (bytes === null || bytes < 0n) { this.stop('job_disk_observation_unverified'); return; }
    this.#peerBytes = bytes;
    if (this.#localBytes !== undefined && this.#localBytes + bytes > BigInt(this.limit)) this.stop('job_disk_measured_limit');
  }
  check(forceSample = false): Promise<bigint> {
    if (this.#cause) return Promise.reject(new SafeError(this.#cause));
    this.#forceSample ||= forceSample;
    // Concurrent engine observations share a walk; no overlapping directory traversals.
    this.#pending ??= this.#measure().catch(async () => {
      this.stop('job_disk_observation_unverified');
      await this.#onSample?.(null, true).catch(() => {});
      throw new SafeError(this.#cause!);
    }).then(async bytes => {
        this.#localBytes = bytes;
        if (this.#onSample) {
          try {
            do {
              const force = this.#forceSample; this.#forceSample = false;
              await this.#onSample(bytes, force);
            } while (this.#forceSample && !this.#cause);
          }
          catch { this.stop('job_disk_observation_unverified'); }
        }
        if (bytes + this.#peerBytes > BigInt(this.limit)) this.stop('job_disk_measured_limit');
        if (this.#cause) throw new SafeError(this.#cause);
        return bytes;
      }).finally(() => { this.#pending = undefined; });
    return this.#pending;
  }
  stop(cause: JobDiskCause): void {
    this.#cause ??= cause;
    this.#abort.abort(new SafeError(this.#cause));
  }
  async #measure(): Promise<bigint> {
    const roots = [...this.#roots.values()];
    const registered = new Set(roots.map(rootKey));
    async function walk(file: string, registeredRoot = registered.has(rootKey(file))): Promise<Map<string, bigint>> {
      for (let attempt = 0; attempt < entryAttempts; attempt++) {
        try {
          const before = await lstat(file, { bigint: true });
          if (registeredRoot && !before.isDirectory()) throw new SafeError('job_disk_observation_unverified');
          if (before.isSymbolicLink()) return new Map(); // Windows junctions are reported as links too.
          if (!before.isFile() && !before.isDirectory()) return new Map();
          if (!samePath(await realpath(file), file)) {
            // On Windows realpath can return the new name of an entry renamed while
            // it was resolving. Check for redirected ancestors before re-reading it.
            for (let parent = path.dirname(file);; parent = path.dirname(parent)) {
              if ((await lstat(parent)).isSymbolicLink()) return new Map();
              if (registered.has(rootKey(parent)) || parent === path.dirname(parent)) break;
            }
            continue;
          }
          const { bsize } = await statfs(file, { bigint: true });
          if (typeof bsize !== 'bigint' || bsize <= 0n || before.size < 0n) throw new SafeError('job_disk_observation_unverified');
          // Keep identities with the subtotal so a replaced directory discards its
          // entire attempt. A file renamed into another listed path counts only once.
          const files = new Map<string, bigint>();
          if (before.isFile()) files.set(`${before.dev}:${before.ino}`, ((before.size + bsize - 1n) / bsize) * bsize);
          else for (const entry of await readdir(file)) {
            for (const [identity, size] of await walk(path.join(file, entry))) files.set(identity, size);
          }
          const after = await lstat(file, { bigint: true });
          if (sameEntry(after, before)) return files;
          // Rename/replacement invalidates this entry's subtotal, not the whole observation.
        } catch (error) {
          if (registeredRoot) throw error;
          if (vanished(error) || denied(error)) {
            let retry = false;
            for (let confirmation = 0; confirmation < deletePendingRetries; confirmation++) {
              if (denied(error) || confirmation > 0) await delay(deletePendingRetryMs);
              try {
                await lstat(file, { bigint: true });
                // A readable stat cannot establish that the failed operation is still denied.
                retry = true;
                break;
              } catch (confirmationError) {
                if (vanished(confirmationError) || denied(confirmationError)) {
                  // A decoded name that cannot round-trip is not proof of deletion.
                  // Confirm absence even when delete-pending metadata remains denied.
                  try {
                    const name = path.basename(file);
                    const listed = (await readdir(path.dirname(file))).some(entry => entry === name
                      || process.platform === 'win32' && (entry.toUpperCase() === name.toUpperCase()
                        || entry.toLowerCase() === name.toLowerCase()));
                    if (!listed) return new Map();
                  } catch (listingError) {
                    if (vanished(listingError)) return new Map();
                    if (!denied(listingError)) throw listingError;
                    continue;
                  }
                  if (vanished(confirmationError)) { retry = true; break; }
                }
                if (!denied(confirmationError)) throw confirmationError;
              }
            }
            if (retry) continue;
          }
          throw error;
        }
      }
      throw new SafeError('job_disk_observation_unverified');
    }
    const files = new Map<string, bigint>();
    for (const root of roots) {
      if (!roots.some(other => other !== root && contains(other, root))) {
        for (const [identity, size] of await walk(root, true)) files.set(identity, size);
      }
    }
    // Deduplication must not hide a missing nested registration, even if readdir omitted it.
    for (const root of roots) {
      if (!(await lstat(root)).isDirectory() || !samePath(await realpath(root), root)) throw new SafeError('job_disk_observation_unverified');
      const { bsize } = await statfs(root, { bigint: true });
      if (typeof bsize !== 'bigint' || bsize <= 0n) throw new SafeError('job_disk_observation_unverified');
    }
    let bytes = 0n;
    for (const size of files.values()) bytes += size;
    return bytes;
  }
  /** Start after the pre-start check, and finish only after the process tree settles. */
  watch(): () => Promise<void> {
    const timer = setInterval(() => { void this.check().catch(() => {}); }, jobDiskPollMs);
    return async () => {
      clearInterval(timer);
      await this.#pending?.catch(() => {});
      await this.check().catch(() => {});
    };
  }
}

const scope = new AsyncLocalStorage<JobDisk | undefined>();
export const scopedJobDisk = (): JobDisk | undefined => scope.getStore();
export const registerJobDiskRoot = (directory: string): void => scope.getStore()?.register(directory);
export const releaseJobDiskRoot = (directory: string): void => scope.getStore()?.release(directory);
export function withJobDisk<T>(disk: number | JobDisk | undefined, body: () => Promise<T>): Promise<T> {
  return scope.run(typeof disk === 'number' ? new JobDisk(disk) : disk, body);
}
