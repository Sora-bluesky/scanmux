import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { boundedRead, canonical, hash, outside, record, SafeError } from './safety.ts';
import { scopedCopyBudget, type CopyBudget } from './copy-budget.ts';
import { sourceCleanupFor } from './source-cleanup.ts';

export const osvEcosystems = ['npm', 'PyPI', 'Go', 'crates.io'] as const;
export type OsvEcosystem = typeof osvEcosystems[number];
export const receiptName = 'database-receipt.json';
export const markerName = 'acquisition-started';
export const acquisitionMarker = 'scanmux.osv-acquisition/v1\n';
export const acquisitionBasis = 'locally_recorded_https_acquisition_not_authenticated';
export function databaseUrl(ecosystem: OsvEcosystem): string {
  if (!osvEcosystems.includes(ecosystem)) throw new SafeError('invalid_database_ecosystem');
  return `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip`;
}
export interface DatabaseEntry {
  ecosystem: OsvEcosystem; url: string; bytes: number; sha256: string; md5: string;
  generation: string; sourceModifiedAt: string; observedStartedAt: string; observedCompletedAt: string;
}
export interface DatabaseReceipt {
  schema: 'scanmux.osv-database/v1'; basis: typeof acquisitionBasis;
  startedAt: string; completedAt: string; entries: DatabaseEntry[];
}
export type DatabaseProvenance = { state: 'unknown'; reason: 'legacy_acquisition_not_recorded' } | {
  state: 'recorded'; basis: typeof acquisitionBasis; receiptHash: string; acquiredAt: string;
  acquisitionStartedAt: string; sourceModifiedAt: string; generation: string; url: string;
};
export interface DatabaseObservation {
  ecosystem: string; sha256: string; modifiedAt: string; provenance: DatabaseProvenance;
}
function exactKeys(value: Record<string, unknown>, keys: string[]): void {
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw new SafeError('invalid_database_receipt');
}
function utc(value: unknown): number {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)) throw new SafeError('invalid_database_receipt');
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) throw new SafeError('invalid_database_receipt');
  return time;
}
export function validateDatabaseReceipt(value: unknown, now: number): DatabaseReceipt {
  const top = record(value);
  exactKeys(top, ['schema', 'basis', 'startedAt', 'completedAt', 'entries']);
  if (top.schema !== 'scanmux.osv-database/v1' || top.basis !== acquisitionBasis || !Number.isFinite(now)) throw new SafeError('invalid_database_receipt');
  const start = utc(top.startedAt), end = utc(top.completedAt);
  if (start > end || end > now || !Array.isArray(top.entries) || !top.entries.length || top.entries.length > osvEcosystems.length) throw new SafeError('invalid_database_receipt');
  const seen = new Set<string>();
  const entries = top.entries.map(value => {
    const entry = record(value);
    exactKeys(entry, ['ecosystem', 'url', 'bytes', 'sha256', 'md5', 'generation', 'sourceModifiedAt', 'observedStartedAt', 'observedCompletedAt']);
    if (typeof entry.ecosystem !== 'string' || !osvEcosystems.includes(entry.ecosystem as OsvEcosystem) || seen.has(entry.ecosystem)) throw new SafeError('invalid_database_receipt');
    const ecosystem = entry.ecosystem as OsvEcosystem; seen.add(ecosystem);
    if (entry.url !== databaseUrl(ecosystem) || !Number.isSafeInteger(entry.bytes) || Number(entry.bytes) < 1 ||
      typeof entry.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.sha256) ||
      typeof entry.md5 !== 'string' || !/^[A-Za-z0-9+/]{22}==$/.test(entry.md5) || Buffer.from(entry.md5, 'base64').toString('base64') !== entry.md5 ||
      typeof entry.generation !== 'string' || !/^[1-9][0-9]*$/.test(entry.generation)) throw new SafeError('invalid_database_receipt');
    const observedStart = utc(entry.observedStartedAt), observedEnd = utc(entry.observedCompletedAt), modified = utc(entry.sourceModifiedAt);
    if (observedStart < start || observedEnd < observedStart || observedEnd > end || modified > observedEnd) throw new SafeError('invalid_database_receipt');
    return { ecosystem, url: entry.url as string, bytes: Number(entry.bytes), sha256: entry.sha256, md5: entry.md5,
      generation: entry.generation, sourceModifiedAt: entry.sourceModifiedAt as string,
      observedStartedAt: entry.observedStartedAt as string, observedCompletedAt: entry.observedCompletedAt as string };
  });
  return { schema: 'scanmux.osv-database/v1', basis: acquisitionBasis, startedAt: top.startedAt as string, completedAt: top.completedAt as string, entries };
}
async function exists(file: string): Promise<boolean> {
  try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
}
async function regular(file: string, target: string): Promise<string> {
  const full = await outside(file, target);
  if (!(await lstat(full)).isFile()) throw new SafeError('invalid_database');
  return full;
}
async function streamHash(file: string, expectedBytes: number, signal: AbortSignal, destination?: string): Promise<string> {
  const digest = createHash('sha256'); let bytes = 0;
  const observer = new Transform({ transform(chunk: Buffer, _encoding, callback) {
    bytes += chunk.length;
    if (bytes > expectedBytes) { callback(new SafeError('database_size_mismatch')); return; }
    digest.update(chunk); callback(null, destination ? chunk : undefined);
  } });
  if (destination) await pipeline(createReadStream(file), observer, createWriteStream(destination, { flags: 'wx', mode: 0o600 }), { signal });
  else await pipeline(createReadStream(file), observer, { signal });
  if (bytes !== expectedBytes) throw new SafeError('database_size_mismatch');
  return digest.digest('hex');
}
export interface PreparedDatabase {
  directory: string; observations: DatabaseObservation[];
  files: { path: string; bytes: number; sha256: string }[];
}
export async function prepareOfflineDatabase(options: {
  source: string; workspace: string; target: string; ecosystems: OsvEcosystem[];
  maxMetadataBytes: number; timeoutMs: number; signal: AbortSignal; copyBudget?: CopyBudget;
}): Promise<PreparedDatabase> {
  const signal = AbortSignal.any([options.signal, AbortSignal.timeout(options.timeoutMs)]);
  signal.throwIfAborted();
  if (!options.ecosystems.length || new Set(options.ecosystems).size !== options.ecosystems.length || options.ecosystems.some(e => !osvEcosystems.includes(e))) throw new SafeError('invalid_database_ecosystem');
  const source = await outside(options.source, options.target), workspace = await outside(options.workspace, options.target);
  const marker = path.join(source, markerName), receiptFile = path.join(source, receiptName);
  const marked = await exists(marker), receipted = await exists(receiptFile);
  if (marked) {
    const bytes = await boundedRead(await regular(marker, options.target), options.maxMetadataBytes);
    if (!bytes.equals(Buffer.from(acquisitionMarker))) throw new SafeError('invalid_database_acquisition_marker');
    if (!receipted) throw new SafeError('database_acquisition_incomplete');
  }
  let receipt: DatabaseReceipt | undefined, receiptHash: string | undefined;
  if (receipted) {
    const bytes = await boundedRead(await regular(receiptFile, options.target), options.maxMetadataBytes);
    try { receipt = validateDatabaseReceipt(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), Date.now()); }
    catch { throw new SafeError('invalid_database_receipt'); }
    receiptHash = hash(bytes);
  }
  const cleanup = sourceCleanupFor(workspace), directory = cleanup.register(workspace, path.join(workspace, 'osv-database'));
  await mkdir(directory, { mode: 0o700 }); await cleanup.capture(workspace, directory); await canonical(directory);
  await mkdir(path.join(directory, 'osv-scalibr'), { mode: 0o700 });
  const prepared: PreparedDatabase = { directory, observations: [], files: [] };
  for (const ecosystem of options.ecosystems) {
    signal.throwIfAborted();
    const entry = receipt?.entries.find(row => row.ecosystem === ecosystem);
    if (receipt && !entry) throw new SafeError('database_receipt_entry_missing');
    const sourceFile = path.join(source, 'osv-scalibr', ecosystem, 'all.zip');
    if (!await exists(sourceFile)) throw new SafeError('offline_database_unavailable');
    await regular(sourceFile, options.target);
    const stat = await lstat(sourceFile);
    if (!Number.isSafeInteger(stat.size) || stat.size < 1 || (entry && stat.size !== entry.bytes)) throw new SafeError('database_size_mismatch');
    const parent = path.join(directory, 'osv-scalibr', ecosystem);
    await mkdir(parent, { mode: 0o700 }); await canonical(parent);
    const destination = path.join(parent, 'all.zip');
    const budget = options.copyBudget ?? scopedCopyBudget();
    const sha256 = budget ? (await budget.copy(sourceFile, destination, { maximumBytes: stat.size, sourceChangedCode: 'database_size_mismatch', signal })).sha256
      : await streamHash(sourceFile, stat.size, signal, destination);
    const after = await lstat(sourceFile);
    if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || !after.isFile() || after.isSymbolicLink()) throw new SafeError('database_changed_during_copy');
    if (entry && sha256 !== entry.sha256) throw new SafeError('database_digest_mismatch');
    await regular(destination, options.target);
    prepared.files.push({ path: destination, bytes: stat.size, sha256 });
    prepared.observations.push({ ecosystem, sha256, modifiedAt: stat.mtime.toISOString(), provenance: entry ? {
      state: 'recorded', basis: acquisitionBasis, receiptHash: receiptHash!, acquiredAt: entry.observedCompletedAt,
      acquisitionStartedAt: entry.observedStartedAt, sourceModifiedAt: entry.sourceModifiedAt, generation: entry.generation, url: entry.url,
    } : { state: 'unknown', reason: 'legacy_acquisition_not_recorded' } });
  }
  return prepared;
}
export async function verifyPreparedDatabase(prepared: PreparedDatabase, target: string, signal: AbortSignal, timeoutMs: number): Promise<void> {
  const bounded = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]);
  for (const file of prepared.files) {
    bounded.throwIfAborted(); await regular(file.path, target);
    if (await streamHash(file.path, file.bytes, bounded) !== file.sha256) throw new SafeError('database_changed_during_scan');
  }
}
