import { randomUUID } from 'node:crypto';
import { lstat, mkdir, readdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { boundedRead, canonical, hash, hostLocalPath, SafeError } from '../safety.ts';
import { adoptDirectory, verifyPrivateDirectory } from '../private-storage.ts';
import { feedIds, feeds, feedTimeoutMs, type FeedId, type Parsed, type Source } from './feeds.ts';

export type FailReason = 'http_status' | 'network' | 'timeout' | 'byte_limit' | 'url_mismatch' | 'schema_drift';
export type Outcome = { readonly kind: 'stored'; readonly httpStatus: 200; readonly contentType: string | null; readonly bytes: number; readonly sha256: string; readonly source: Source }
  | { readonly kind: 'failed'; readonly reason: FailReason; readonly httpStatus: number | null }
  | { readonly kind: 'unsupported'; readonly httpStatus: number };
export interface Attempt {
  readonly schema: 'scanmux.intel-attempt/v1'; readonly feed: FeedId; readonly url: string; readonly termsUrl: string | null;
  readonly startedAt: string; readonly completedAt: string; readonly outcome: Outcome;
}
export type NoteReason = 'invalid_attempt' | 'clock_unverified' | 'blob_missing' | 'blob_mismatch' | 'schema_drift';
export interface CorruptNote { readonly attempt: string; readonly reason: NoteReason }
export type FeedState = 'never_attempted' | 'unavailable' | 'refresh_failed_previous' | 'fresh' | 'stale' | 'unjudged' | 'corrupt' | 'clock_unknown';
export interface Generation { readonly attempt: Attempt & { readonly outcome: Extract<Outcome, { kind: 'stored' }> }; readonly parsed: Parsed }
export interface LoadedFeed { readonly feed: FeedId; readonly latest: Attempt | null; readonly generation: Generation | null; readonly newest: 'none' | 'attempt' | NoteReason; readonly notes: readonly CorruptNote[] }
export interface LoadedIntel { readonly store: string; readonly storeDigest: string; readonly feeds: Readonly<Record<FeedId, LoadedFeed>> }
export type OpenedStore = string & { readonly __openedStore: true };
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
export interface RefreshDependencies { readonly fetcher?: Fetcher; readonly now?: () => number; readonly uuid?: () => string; readonly timeoutMs?: number }

// Attempt records are a few hundred bytes; anything larger is not one of ours.
const maxAttemptBytes = 64 * 1024;
const attemptName = /^(\d{8}T\d{9}Z)-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.json$/;
const stamp = (iso: string) => iso.replace(/[-:.]/g, '');
const iso = (time: number) => new Date(time).toISOString();
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const sameKeys = (value: Record<string, unknown>, keys: string[]) => Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function parseBody(feed: FeedId, bytes: Buffer): { parsed: Parsed; source: Source } {
  const definition = feeds[feed];
  if (definition.kind !== 'matchable') throw new SafeError('intel_schema_drift');
  return definition.parse(bytes);
}
async function exists(file: string): Promise<boolean> {
  try { await lstat(file); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; }
}
function storePath(input: unknown): string {
  if (typeof input !== 'string' || !hostLocalPath(input) || path.resolve(input) !== input || input === path.parse(input).root) throw new SafeError('invalid_intel_store');
  return input;
}
const layout = ['attempts', 'blobs'];
export async function openStore(input: unknown, create: boolean): Promise<OpenedStore> {
  const requested = storePath(input);
  let created = false;
  if (create && !await exists(requested)) {
    const parent = await canonical(path.dirname(requested));
    if (!(await lstat(parent)).isDirectory()) throw new SafeError('invalid_intel_store');
    created = await mkdir(requested, { mode: 0o700 }).then(() => true, (error: NodeJS.ErrnoException) => { if (error.code !== 'EEXIST') throw error; return false; });
  }
  let store: string;
  try { store = await canonical(requested); } catch (error) { if (error instanceof SafeError) throw error; throw new SafeError('intel_store_unavailable'); }
  if (!(await lstat(store)).isDirectory()) throw new SafeError('invalid_intel_store');
  const names = await readdir(store);
  if (!names.every(name => layout.includes(name))) throw new SafeError('invalid_intel_store');
  if (names.length < layout.length) {
    if (!create) throw new SafeError('invalid_intel_store');
    if (!await adoptDirectory(store, names)) {
      if (!created) throw new SafeError('intel_store_not_private');
      await rm(store, { recursive: true, force: true });
      throw new SafeError('intel_store_owner_not_user');
    }
    for (const name of layout) await mkdir(path.join(store, name), { mode: 0o700, recursive: true });
  }
  for (const name of layout) {
    const directory = path.join(store, name);
    if (await canonical(directory) !== directory || !(await lstat(directory)).isDirectory()) throw new SafeError('invalid_intel_store');
  }
  if (!await verifyPrivateDirectory(store, layout)) throw new SafeError('intel_store_not_private');
  return store as OpenedStore;
}

async function fetchFeed(feed: FeedId, startedAt: string, fetcher: Fetcher, timeoutMs: number): Promise<{ outcome: Outcome; body?: Buffer }> {
  const definition = feeds[feed], url = definition.url(startedAt), signal = AbortSignal.timeout(timeoutMs);
  let response: Response;
  try { response = await fetcher(url, { method: 'GET', redirect: 'error', credentials: 'omit', signal }); }
  catch { return { outcome: { kind: 'failed', reason: signal.aborted ? 'timeout' : 'network', httpStatus: null } }; }
  const status = Number.isSafeInteger(response.status) ? response.status : null;
  const close = async (outcome: Outcome) => { try { await response.body?.cancel(); } catch {} return { outcome }; };
  if (response.url !== url || response.redirected) return close({ kind: 'failed', reason: 'url_mismatch', httpStatus: status });
  if (status !== 200 || !response.body) return close({ kind: 'failed', reason: 'http_status', httpStatus: status });
  if (definition.kind === 'status_only') return close({ kind: 'unsupported', httpStatus: 200 });
  const chunks: Buffer[] = []; let bytes = 0;
  try {
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > definition.maxBytes) return close({ kind: 'failed', reason: 'byte_limit', httpStatus: 200 });
      chunks.push(Buffer.from(chunk));
    }
  } catch { return close({ kind: 'failed', reason: signal.aborted ? 'timeout' : 'network', httpStatus: 200 }); }
  const body = Buffer.concat(chunks);
  let source: Source;
  try { source = parseBody(feed, body).source; } catch { return { outcome: { kind: 'failed', reason: 'schema_drift', httpStatus: 200 } }; }
  const type = response.headers.get('content-type');
  return { body, outcome: { kind: 'stored', httpStatus: 200, contentType: isContentType(type) ? type : null,
    bytes: body.length, sha256: hash(body), source } };
}
async function storeBlob(store: string, body: Buffer, sha256: string, uuid: string): Promise<void> {
  const final = path.join(store, 'blobs', sha256), partial = `${final}.${uuid}.partial`;
  await writeFile(partial, body, { flag: 'wx', mode: 0o600 });
  try {
    try { if (hash(await boundedRead(final, body.length)) === sha256) return; } catch {}
    try { await rename(partial, final); }
    catch (error) { if (hash(await boundedRead(final, body.length)) !== sha256) throw error; }
  } finally { await rm(partial, { force: true }); }
}
export async function refreshIntel(input: unknown, dependencies: RefreshDependencies = {}): Promise<Attempt[]> {
  const store = await openStore(input, true);
  const fetcher = dependencies.fetcher ?? fetch, now = dependencies.now ?? Date.now, uuid = dependencies.uuid ?? randomUUID;
  const attempts: Attempt[] = [];
  for (const feed of feedIds) {
    const startedAt = iso(now()), id = uuid();
    const { outcome, body } = await fetchFeed(feed, startedAt, fetcher, dependencies.timeoutMs ?? feedTimeoutMs);
    if (body && outcome.kind === 'stored') await storeBlob(store, body, outcome.sha256, id);
    const attempt: Attempt = { schema: 'scanmux.intel-attempt/v1', feed, url: feeds[feed].url(startedAt), termsUrl: feeds[feed].termsUrl,
      startedAt, completedAt: iso(now()), outcome };
    const final = path.join(store, 'attempts', `${stamp(startedAt)}-${id}.json`), partial = `${final}.partial`;
    await writeFile(partial, JSON.stringify(attempt, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    await rename(partial, final);
    attempts.push(attempt);
  }
  return attempts;
}

class Note extends Error {
  readonly reason: NoteReason;
  constructor(reason: NoteReason) { super(reason); this.reason = reason; }
}
function time(value: unknown): number {
  const parsed = typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed) || iso(parsed) !== value) throw new Note('clock_unverified');
  return parsed;
}
const stampTime = (name: string) => time(attemptName.exec(name)![1].replace(/^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)(\d{3})Z$/, '$1-$2-$3T$4:$5:$6.$7Z'));
const failReasons = new Set<unknown>(['http_status', 'network', 'timeout', 'byte_limit', 'url_mismatch', 'schema_drift'] satisfies FailReason[]);
const isContentType = (value: unknown) => value === null || (typeof value === 'string' && /^[\x20-\x7e]{1,200}$/.test(value));
const isSource = (value: unknown) => isObject(value) && sameKeys(value, ['version', 'date'])
  && [value.version, value.date].every(item => item === null || (typeof item === 'string' && item.length <= 64));
const isHttpStatus = (value: unknown) => value === null || (Number.isSafeInteger(value) && Number(value) >= 100 && Number(value) <= 599);
function outcomeOf(value: unknown, feed: FeedId): Outcome {
  if (!isObject(value)) throw new Note('invalid_attempt');
  const { kind, maxBytes } = feeds[feed];
  const stored = value.kind === 'stored' && kind === 'matchable' && sameKeys(value, ['kind', 'httpStatus', 'contentType', 'bytes', 'sha256', 'source'])
    && value.httpStatus === 200 && isContentType(value.contentType) && Number.isSafeInteger(value.bytes) && Number(value.bytes) > 0 && Number(value.bytes) <= maxBytes
    && typeof value.sha256 === 'string' && /^[a-f0-9]{64}$/.test(value.sha256) && isSource(value.source);
  const failed = value.kind === 'failed' && sameKeys(value, ['kind', 'reason', 'httpStatus']) && failReasons.has(value.reason) && isHttpStatus(value.httpStatus);
  const unsupported = value.kind === 'unsupported' && kind === 'status_only' && sameKeys(value, ['kind', 'httpStatus']) && value.httpStatus === 200;
  if (!stored && !failed && !unsupported) throw new Note('invalid_attempt');
  return value as Outcome;
}
function attemptOf(bytes: Buffer, name: string, now: number): Attempt {
  if (stampTime(name) > now) throw new Note('clock_unverified');
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new Note('invalid_attempt'); }
  if (!isObject(value) || !sameKeys(value, ['schema', 'feed', 'url', 'termsUrl', 'startedAt', 'completedAt', 'outcome'])
    || value.schema !== 'scanmux.intel-attempt/v1' || !feedIds.includes(value.feed as FeedId)) throw new Note('invalid_attempt');
  const feed = value.feed as FeedId, started = time(value.startedAt), completed = time(value.completedAt);
  if (value.url !== feeds[feed].url(value.startedAt as string) || value.termsUrl !== feeds[feed].termsUrl || attemptName.exec(name)![1] !== stamp(value.startedAt as string)) throw new Note('invalid_attempt');
  outcomeOf(value.outcome, feed);
  if (started > completed || completed > now) throw new Note('clock_unverified');
  return value as unknown as Attempt;
}
async function generationOf(store: string, attempt: Generation['attempt']): Promise<Generation> {
  const outcome = attempt.outcome;
  let body: Buffer;
  try { body = await boundedRead(path.join(store, 'blobs', outcome.sha256), outcome.bytes); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') throw new Note('blob_missing');
    throw new Note('blob_mismatch');
  }
  if (body.length !== outcome.bytes || hash(body) !== outcome.sha256) throw new Note('blob_mismatch');
  let read: { parsed: Parsed; source: Source };
  try { read = parseBody(attempt.feed, body); } catch { throw new Note('schema_drift'); }
  if (JSON.stringify(read.source) !== JSON.stringify(outcome.source)) throw new Note('schema_drift');
  return { attempt, parsed: read.parsed };
}
export async function loadIntel(input: unknown, now: number): Promise<LoadedIntel> {
  return readIntel(await openStore(input, false), now);
}
export async function readIntel(store: OpenedStore, now: number): Promise<LoadedIntel> {
  const directory = path.join(store, 'attempts');
  const names = (await readdir(directory)).filter(name => attemptName.test(name)).sort().reverse();
  const read = new Map<string, Buffer>();
  for (const name of names) {
    try { read.set(name, await boundedRead(path.join(directory, name), maxAttemptBytes)); } catch { read.set(name, Buffer.alloc(0)); }
  }
  const entries = names.map(name => {
    try { const attempt = attemptOf(read.get(name)!, name, now); return { name, attempt, at: Date.parse(attempt.completedAt) }; }
    catch (error) {
      if (!(error instanceof Note)) throw error;
      let feed: unknown, at = -Infinity;
      try { feed = JSON.parse(read.get(name)!.toString('utf8')).feed; } catch {}
      try { at = stampTime(name); } catch {}
      return { name, reason: error.reason, feed: feedIds.includes(feed as FeedId) ? feed as FeedId : null, at };
    }
  });
  const rank = (entry: typeof entries[number]) => 'reason' in entry ? 0 : entry.attempt.outcome.kind === 'stored' ? 2 : 1;
  entries.sort((left, right) => right.at - left.at || rank(left) - rank(right) || (left.name < right.name ? 1 : -1));
  const loaded = {} as Record<FeedId, LoadedFeed>;
  for (const feed of feedIds) {
    const notes: CorruptNote[] = []; let latest: Attempt | null = null, generation: Generation | null = null, newest: LoadedFeed['newest'] = 'none', clockNote = false;
    for (const entry of entries) {
      if ('reason' in entry) {
        if (entry.feed !== null && entry.feed !== feed) continue;
        notes.push({ attempt: entry.name, reason: entry.reason });
        if (entry.feed === null) continue;
        if (entry.reason === 'clock_unverified') clockNote = true;
        else if (newest === 'none') newest = entry.reason;
        continue;
      }
      if (entry.attempt.feed !== feed) continue;
      latest ??= entry.attempt;
      if (newest === 'none') newest = 'attempt';
      if (generation || entry.attempt.outcome.kind !== 'stored') continue;
      try { generation = await generationOf(store, entry.attempt as Generation['attempt']); }
      catch (error) {
        if (!(error instanceof Note)) throw error;
        notes.push({ attempt: entry.name, reason: error.reason });
        if (latest === entry.attempt && newest === 'attempt') newest = error.reason;
      }
    }
    loaded[feed] = { feed, latest, generation, newest: newest === 'none' && clockNote ? 'clock_unverified' : newest, notes };
  }
  const storeDigest = hash(JSON.stringify(names.map(name => [name, hash(read.get(name)!)])));
  return { store, storeDigest, feeds: loaded };
}
