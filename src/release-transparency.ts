import { lstat, readdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import path from 'node:path';
import { execute, verifyVersion } from './process.ts';
import { readGitBlobs } from './git-blobs.ts';
import { canonical, hash, hostLocalPath, SafeError, safeRelative, within } from './safety.ts';
import type { Config } from './model.ts';

export const measurementSchema = 'scanmux.release-measurement/v1';
export const logPath = 'transparency/releases.jsonl';
export const zeroHead = '0'.repeat(64);
const maxLogBytes = 1024 * 1024;
export const releaseScope = Object.freeze({
  measured: 'package_file_set', dependencies: 'lockfile_bound_not_measured', witness: 'none', authenticatedHistory: false,
} as const);

export const outcomes = Object.freeze({
  logged: 0,
  consistent: 0,
  logged_unpinned: 3,
  'not_logged/measurement_absent': 3,
  'not_logged/after_pin': 3,
  'not_logged/version_logged_with_other_measurement': 4,
  'log_tampered/non_canonical': 4,
  'log_tampered/broken_chain': 4,
  'log_tampered/version_conflict': 4,
  'log_tampered/duplicate_commit': 4,
  'log_tampered/pin_mismatch': 4,
  'log_tampered/base_not_prefix': 4,
  'log_tampered/not_reproducible': 4,
  'log_unreadable/log_missing': 3,
  'log_unreadable/over_limit': 3,
  'log_unreadable/git_failed': 3,
  'log_unreadable/not_a_file': 3,
} as const);
export type Outcome = keyof typeof outcomes;
const verdictOf = (outcome: Outcome) => {
  const [verdict, reason = null] = outcome.split('/');
  return { verdict, reason, exitCode: outcomes[outcome] };
};

export type MeasurementRefusalReason = 'link' | 'outside_root' | 'case_collision' | 'not_regular' | 'over_limit'
  | 'listed_path_missing' | 'invalid_package' | 'unsupported_path';
function refuse(reason: MeasurementRefusalReason): never { throw new SafeError(`release_measurement_${reason}`); }

export interface Measurement { schema: typeof measurementSchema; sha256: string; files: number; bytes: number }
export interface Release { version: string; measurement: Measurement }
export interface MeasuredFile { path: string; bytes: number; sha256: string }
export type Listed = { kind: 'file'; bytes: number } | { kind: 'link' } | { kind: 'other' };
export interface Snapshot {
  readonly listing: ReadonlyMap<string, Listed>;
  read(paths: readonly string[]): AsyncIterable<{ path: string; content: Buffer }>;
}
export interface Limits { maxFiles: number; maxFileBytes: number; maxSnapshotBytes: number }

const versionPattern = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/;
// Printable ASCII without quote or backslash keeps canonical JSON identical to plain string joining in any tool.
const pathPattern = /^[\x20-\x21\x23-\x5b\x5d-\x7e]+$/;

function packageEntry(input: unknown): string {
  if (typeof input !== 'string' || !input || /[*?[\]{}!]/.test(input)) return refuse('invalid_package');
  const entry = input.endsWith('/') ? input.slice(0, -1) : input;
  if (entry.startsWith('/') || /^[A-Za-z]:/.test(entry) || entry.split(/[\\/]/).includes('..')) return refuse('outside_root');
  try { safeRelative(entry); } catch { return refuse('unsupported_path'); }
  if (!pathPattern.test(entry)) return refuse('unsupported_path');
  return entry;
}
function parsePackage(bytes: Buffer): { version: string; entries: string[] } {
  let value: unknown;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return refuse('invalid_package'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuse('invalid_package');
  const { version, files } = value as Record<string, unknown>;
  if (typeof version !== 'string' || !versionPattern.test(version) || !Array.isArray(files) || !files.length || files.length > 1000) return refuse('invalid_package');
  return { version, entries: [...new Set([...files.map(packageEntry), 'package.json', 'package-lock.json'])] };
}
function selectPaths(entries: readonly string[], listing: ReadonlyMap<string, Listed>, limits: Limits): string[] {
  const selected = new Set<string>();
  for (const entry of entries) {
    if (listing.has(entry)) { selected.add(entry); continue; }
    const under = [...listing.keys()].filter(name => name.startsWith(entry + '/'));
    if (!under.length) refuse('listed_path_missing');
    for (const name of under) selected.add(name);
  }
  const paths = [...selected].sort(byPath), keys = new Set<string>();
  let total = 0;
  for (const name of paths) {
    const item = listing.get(name)!;
    if (item.kind === 'link') refuse('link');
    if (item.kind === 'other') refuse('not_regular');
    try { safeRelative(name); } catch { refuse('unsupported_path'); }
    if (!pathPattern.test(name)) refuse('unsupported_path');
    const key = name.normalize('NFC').toLowerCase();
    if (keys.has(key)) refuse('case_collision');
    keys.add(key);
    const { bytes } = item as Extract<Listed, { kind: 'file' }>;
    total += bytes;
    if (keys.size > limits.maxFiles || bytes > limits.maxFileBytes || total > limits.maxSnapshotBytes) refuse('over_limit');
  }
  return paths;
}
const byPath = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
export function measurementOf(files: readonly MeasuredFile[]): Measurement {
  const sorted = [...files].sort((left, right) => byPath(left.path, right.path));
  const text = JSON.stringify(sorted.map(({ path: name, bytes, sha256 }) => ({ path: name, bytes, sha256 })));
  return { schema: measurementSchema, sha256: hash(`${measurementSchema}\n${text}`), files: sorted.length, bytes: sorted.reduce((sum, file) => sum + file.bytes, 0) };
}
export async function measureSnapshot(snapshot: Snapshot, limits: Limits): Promise<{ release: Release; files: MeasuredFile[] }> {
  const manifest = snapshot.listing.get('package.json');
  if (!manifest) return refuse('listed_path_missing');
  if (manifest.kind === 'link') return refuse('link');
  if (manifest.kind !== 'file') return refuse('not_regular');
  let packageBytes: Buffer | undefined;
  for await (const item of snapshot.read(['package.json'])) packageBytes = item.content;
  const { version, entries } = parsePackage(packageBytes!);
  const paths = selectPaths(entries, snapshot.listing, limits), files: MeasuredFile[] = [];
  let total = 0;
  for await (const { path: name, content } of snapshot.read(paths)) {
    total += content.length;
    if (content.length > limits.maxFileBytes || total > limits.maxSnapshotBytes) refuse('over_limit');
    files.push({ path: name, bytes: content.length, sha256: hash(content) });
  }
  if (files.length !== paths.length || files.some((file, index) => file.path !== paths[index])) throw new SafeError('release_measurement_incomplete');
  return { release: { version, measurement: measurementOf(files) }, files };
}

async function directorySnapshot(root: string, limits: Limits): Promise<Snapshot> {
  const listing = new Map<string, Listed>(), resolved = new Map<string, string>(), visited = new Set<string>();
  const samePlace = async (file: string) => (await realpath(file)).toLowerCase() === path.resolve(file).toLowerCase();
  async function visit(relative: string): Promise<void> {
    const file = path.join(root, ...relative.split('/'));
    if (listing.has(relative) || visited.has(relative)) return;
    let stat;
    try { stat = await lstat(file); } catch { return; }
    const add = (item: Listed) => { if (listing.size >= limits.maxFiles) refuse('over_limit'); listing.set(relative, item); };
    if (stat.isSymbolicLink() || !await samePlace(file)) { add({ kind: 'link' }); return; }
    if (stat.isFile()) { add({ kind: 'file', bytes: stat.size }); resolved.set(relative, file); return; }
    if (!stat.isDirectory()) { add({ kind: 'other' }); return; }
    visited.add(relative);
    for (const name of (await readdir(file)).sort(byPath)) await visit(`${relative}/${name}`);
  }
  await visit('package.json');
  const manifest = listing.get('package.json');
  if (manifest?.kind === 'file') {
    const { entries } = parsePackage(await readFile(resolved.get('package.json')!));
    for (const entry of entries) await visit(entry);
  }
  return {
    listing,
    async *read(paths) { for (const name of paths) yield { path: name, content: await readFile(resolved.get(name)!) }; },
  };
}
export async function measureDirectory(directory: string, limits: Limits): Promise<{ release: Release; files: MeasuredFile[] }> {
  if (!hostLocalPath(directory)) throw new SafeError('release_installed_path_invalid');
  let root;
  try { root = await canonical(directory); } catch (error) { if (error instanceof SafeError) refuse('link'); throw new SafeError('release_installed_unreadable'); }
  if (!(await lstat(root)).isDirectory()) throw new SafeError('release_installed_unreadable');
  return measureSnapshot(await directorySnapshot(root, limits), limits);
}

export interface LogEntry { seq: number; prev: string; version: string; sourceCommit: string; measurement: Measurement }
export interface ReleaseLog { entries: LogEntry[]; hashes: string[]; head: string }
export type LogDefect = 'non_canonical' | 'broken_chain' | 'version_conflict' | 'duplicate_commit';
export function encodeEntry(entry: LogEntry): string {
  const { schema, sha256, files, bytes } = entry.measurement;
  return JSON.stringify({ seq: entry.seq, prev: entry.prev, version: entry.version, sourceCommit: entry.sourceCommit, measurement: { schema, sha256, files, bytes } });
}
const hex = (value: unknown, length: number): value is string => typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
const count = (value: unknown, minimum: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
function entryShape(value: unknown): LogEntry | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const { seq, prev, version, sourceCommit, measurement } = value as Record<string, unknown>;
  if (!count(seq, 1) || !hex(prev, 64) || typeof version !== 'string' || !versionPattern.test(version) || !hex(sourceCommit, 40)
    || !measurement || typeof measurement !== 'object' || Array.isArray(measurement)) return null;
  const { schema, sha256, files, bytes } = measurement as Record<string, unknown>;
  if (schema !== measurementSchema || !hex(sha256, 64) || !count(files, 1) || !count(bytes, 0)) return null;
  return { seq, prev, version, sourceCommit, measurement: { schema, sha256, files, bytes } };
}
export function parseLog(bytes: Buffer): { ok: true; log: ReleaseLog } | { ok: false; reason: LogDefect } {
  const log: ReleaseLog = { entries: [], hashes: [], head: zeroHead };
  if (!bytes.length) return { ok: true, log };
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { return { ok: false, reason: 'non_canonical' }; }
  if (!text.endsWith('\n')) return { ok: false, reason: 'non_canonical' };
  for (const line of text.slice(0, -1).split('\n')) {
    let entry: LogEntry | null = null;
    try { entry = entryShape(JSON.parse(line)); } catch { /* A line that is not JSON is non-canonical. */ }
    if (!entry || encodeEntry(entry) !== line) return { ok: false, reason: 'non_canonical' };
    if (entry.seq !== log.entries.length + 1 || entry.prev !== log.head) return { ok: false, reason: 'broken_chain' };
    if (log.entries.some(other => other.sourceCommit === entry.sourceCommit)) return { ok: false, reason: 'duplicate_commit' };
    if (log.entries.some(other => other.version === entry.version && JSON.stringify(other.measurement) !== JSON.stringify(entry.measurement))) return { ok: false, reason: 'version_conflict' };
    log.entries.push(entry); log.head = hash(line); log.hashes.push(log.head);
  }
  return { ok: true, log };
}
export interface Pin { entries: number; head: string }
export function parsePin(input: string): Pin {
  const match = /^(0|[1-9][0-9]{0,8}):([0-9a-f]{64})$/.exec(input);
  if (!match) throw new SafeError('invalid_release_pin');
  return { entries: Number(match[1]), head: match[2] };
}
const headAt = (log: ReleaseLog, entries: number) => entries === 0 ? zeroHead : log.hashes[entries - 1];
const sameRelease = (entry: LogEntry, release: Release) => entry.version === release.version && encodeEntry({ ...entry, measurement: release.measurement }) === encodeEntry(entry);

export function matchRelease(log: ReleaseLog, pin: Pin | null, release: Release): { outcome: Outcome; seq: number | null } {
  if (pin && (pin.entries > log.entries.length || headAt(log, pin.entries) !== pin.head)) return { outcome: 'log_tampered/pin_mismatch', seq: null };
  const approved = pin ? pin.entries : log.entries.length;
  const found = log.entries.find(entry => sameRelease(entry, release));
  if (found) return { outcome: found.seq > approved ? 'not_logged/after_pin' : pin ? 'logged' : 'logged_unpinned', seq: found.seq };
  if (log.entries.some(entry => entry.version === release.version)) return { outcome: 'not_logged/version_logged_with_other_measurement', seq: null };
  return { outcome: 'not_logged/measurement_absent', seq: null };
}

export type LogRead = { kind: 'bytes'; bytes: Buffer } | { kind: 'absent' } | { kind: 'unreadable'; reason: 'over_limit' | 'git_failed' | 'not_a_file' };
type ReadLog = { ok: true; log: ReleaseLog } | { ok: false; outcome: Outcome };
function readLog(input: LogRead, absent: 'missing' | 'empty'): ReadLog {
  if (input.kind === 'absent') return absent === 'empty' ? { ok: true, log: { entries: [], hashes: [], head: zeroHead } } : { ok: false, outcome: 'log_unreadable/log_missing' };
  if (input.kind === 'unreadable') return { ok: false, outcome: `log_unreadable/${input.reason}` };
  const parsed = parseLog(input.bytes);
  return parsed.ok ? parsed : { ok: false, outcome: `log_tampered/${parsed.reason}` };
}
const logSummary = (log: ReleaseLog) => ({ entries: log.entries.length, head: log.head });

export async function verifyRelease(input: LogRead, pin: Pin | null, measure: () => Promise<Release>) {
  const read = readLog(input, 'missing');
  if (!read.ok) return { outcome: read.outcome, log: null, release: null, seq: null };
  if (pin && (pin.entries > read.log.entries.length || headAt(read.log, pin.entries) !== pin.head)) {
    return { outcome: 'log_tampered/pin_mismatch' as Outcome, log: logSummary(read.log), release: null, seq: null };
  }
  const release = await measure(), { outcome, seq } = matchRelease(read.log, pin, release);
  return { outcome, log: logSummary(read.log), release, seq };
}

/** Base null means no base was given; an absent base log is the empty prefix of the log being introduced. */
export async function checkReleaseLog(base: LogRead | null, head: LogRead, reproduce: (entry: LogEntry) => Promise<Release | null>) {
  const headLog = readLog(head, 'missing');
  if (!headLog.ok) return { outcome: headLog.outcome, base: null, head: null, reproduced: 0 };
  let baseSummary: { state: 'none' | 'absent' | 'present'; entries: number; head: string } = { state: 'none', entries: 0, head: zeroHead };
  if (base) {
    const baseLog = readLog(base, 'empty');
    if (!baseLog.ok) return { outcome: baseLog.outcome, base: null, head: logSummary(headLog.log), reproduced: 0 };
    baseSummary = { state: base.kind === 'absent' ? 'absent' : 'present', ...logSummary(baseLog.log) };
    const baseBytes = base.kind === 'bytes' ? base.bytes : Buffer.alloc(0), headBytes = (head as Extract<LogRead, { kind: 'bytes' }>).bytes;
    if (!headBytes.subarray(0, baseBytes.length).equals(baseBytes)) return { outcome: 'log_tampered/base_not_prefix' as Outcome, base: baseSummary, head: logSummary(headLog.log), reproduced: 0 };
  }
  let reproduced = 0;
  for (const entry of headLog.log.entries) {
    const release = await reproduce(entry);
    if (!release || !sameRelease(entry, release)) return { outcome: 'log_tampered/not_reproducible' as Outcome, base: baseSummary, head: logSummary(headLog.log), reproduced };
    reproduced++;
  }
  return { outcome: 'consistent' as Outcome, base: baseSummary, head: logSummary(headLog.log), reproduced };
}

export function planRecord(log: ReleaseLog, expectedHead: string, commit: string, release: Release):
  { state: 'existing'; entry: LogEntry } | { state: 'appended'; entry: LogEntry; line: string } {
  const existing = log.entries.find(entry => entry.sourceCommit === commit || sameRelease(entry, release));
  if (existing) {
    if (!sameRelease(existing, release)) throw new SafeError('release_commit_logged_with_other_measurement');
    return { state: 'existing', entry: existing };
  }
  if (log.head !== expectedHead) throw new SafeError('release_log_head_mismatch');
  if (log.entries.some(entry => entry.version === release.version)) throw new SafeError('release_version_logged_with_other_measurement');
  const entry: LogEntry = { seq: log.entries.length + 1, prev: log.head, version: release.version, sourceCommit: commit, measurement: release.measurement };
  return { state: 'appended', entry, line: encodeEntry(entry) + '\n' };
}

interface Repository { root: string; config: Config; workspace: string; signal?: AbortSignal }
class GitFailure extends SafeError { constructor() { super('git_failed'); } }
async function git(repo: Repository, args: string[], batch?: { input: string; maxOutputBytes: number }): Promise<Buffer> {
  const tool = repo.config.tools.git;
  if (!tool) throw new SafeError('git_not_configured');
  const result = await execute(tool, ['--no-optional-locks', '--no-replace-objects', '-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${repo.workspace}`, '-c', 'core.attributesFile=',
    '-c', 'core.excludesFile=', '-c', 'protocol.allow=never', '-C', repo.root, ...args], {
    cwd: repo.workspace, home: repo.workspace, timeoutMs: repo.config.timeoutMs, maxOutputBytes: batch?.maxOutputBytes ?? Math.max(repo.config.maxOutputBytes, repo.config.maxFileBytes),
    target: repo.root, signal: repo.signal, input: batch?.input,
  });
  if (result.reason !== 'exit' || result.code !== 0) throw new GitFailure();
  return result.stdout;
}
async function refuseLinks(directory: string): Promise<void> {
  for (const name of await readdir(directory)) {
    const file = path.join(directory, name), stat = await lstat(file);
    if (stat.isSymbolicLink()) throw new SafeError('linked_git_metadata');
    if (stat.isDirectory()) await refuseLinks(file);
  }
}
const pathSettings = new Set(['core.hookspath', 'core.attributesfile', 'core.excludesfile', 'core.fsmonitor', 'core.sshcommand', 'core.gitproxy',
  'core.askpass', 'core.worktree', 'core.alternaterefscommand']);
const safeExtensions = new Set(['objectformat', 'noop']);
/**
 * Only object reads run here (rev-parse, ls-tree, cat-file), so the config is checked for settings that make Git read another file,
 * path or command instead of against an allow list; a line this reader cannot parse is refused.
 */
async function checkGitConfig(file: string): Promise<void> {
  const stat = await lstat(file).catch(() => null);
  if (!stat?.isFile() || stat.size > 65536) throw new SafeError('unsupported_git_config');
  await canonical(file);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(await readFile(file)); } catch { throw new SafeError('unsupported_git_config'); }
  let section: string | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^[#;]/.test(line)) continue;
    const heading = /^\[([A-Za-z0-9.-]+)(?:\s+"(?:[^"\\]|\\.)*")?\]$/.exec(line);
    if (heading) { section = heading[1].toLowerCase().split('.')[0]; continue; }
    const setting = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=.*)?$/.exec(line);
    if (!setting || section === null || line.endsWith('\\')) throw new SafeError('unsupported_git_config');
    const key = setting[1].toLowerCase();
    if (['include', 'includeif'].includes(section) || pathSettings.has(`${section}.${key}`) || (section === 'extensions' && !safeExtensions.has(key))) {
      throw new SafeError('unsupported_git_config');
    }
  }
}
/** Hooks, fsmonitor and replace objects are switched off, and layouts or config that read from elsewhere are refused before Git runs. */
export async function openRepository(target: string, config: Config, workspace: string, signal?: AbortSignal): Promise<Repository> {
  const root = await canonical(target), gitDir = path.join(root, '.git');
  const stat = await lstat(gitDir).catch(() => null);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) throw new SafeError('ordinary_git_directory_required');
  await canonical(gitDir);
  await refuseLinks(gitDir);
  for (const file of ['commondir', 'config.worktree', 'objects/info/alternates', 'objects/info/http-alternates']) {
    if (await lstat(path.join(gitDir, file)).then(() => true, () => false)) throw new SafeError('unsupported_git_layout');
  }
  await checkGitConfig(path.join(gitDir, 'config'));
  if (!config.tools.git) throw new SafeError('git_not_configured');
  await verifyVersion(config.tools.git, ['--version'], { cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, target: root, signal });
  return { root, config, workspace, signal };
}
interface TreeItem { path: string; mode: string; type: string; oid: string; bytes: number }
function parseTree(output: Buffer): TreeItem[] {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(output); } catch { return refuse('unsupported_path'); }
  return text.split('\0').filter(Boolean).map(line => {
    const match = /^(\d{6}) (blob|tree|commit) ([0-9a-f]{40}) +(\d+|-)\t(.+)$/s.exec(line);
    if (!match) throw new SafeError('invalid_git_tree');
    return { path: match[5], mode: match[1], type: match[2], oid: match[3], bytes: match[4] === '-' ? 0 : Number(match[4]) };
  });
}
async function commitPresent(repo: Repository, commit: string): Promise<boolean> {
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new SafeError('invalid_release_commit');
  try { return (await git(repo, ['rev-parse', '--verify', '--quiet', '--end-of-options', `${commit}^{commit}`])).toString('utf8').trim() === commit; }
  catch (error) { if (error instanceof GitFailure) return false; throw error; }
}
const regular = (item: TreeItem) => item.type === 'blob' && (item.mode === '100644' || item.mode === '100755');
const blobLimit = (repo: Repository) => Math.max(repo.config.maxOutputBytes, repo.config.maxFileBytes);
async function* blobs(repo: Repository, items: readonly TreeItem[]) {
  yield* readGitBlobs(items, (oids, maxOutputBytes) => git(repo, ['cat-file', '--batch'], { input: oids.join('\n') + '\n', maxOutputBytes }), blobLimit(repo), repo.signal);
}
export async function measureCommit(repo: Repository, commit: string): Promise<{ release: Release; files: MeasuredFile[] }> {
  if (!await commitPresent(repo, commit)) throw new SafeError('release_commit_unavailable');
  const items = new Map(parseTree(await git(repo, ['ls-tree', '-r', '-z', '-l', '--full-tree', commit])).map(item => [item.path, item]));
  const listing = new Map<string, Listed>([...items].map(([name, item]) => [name, regular(item) ? { kind: 'file', bytes: item.bytes }
    : item.mode === '120000' ? { kind: 'link' } : { kind: 'other' }]));
  const snapshot: Snapshot = {
    listing,
    async *read(paths) {
      for await (const { entry, content } of blobs(repo, paths.map(name => items.get(name)!))) {
        if (content.length !== entry.bytes) throw new SafeError('blob_size_mismatch');
        yield { path: entry.path, content: Buffer.from(content) };
      }
    },
  };
  return measureSnapshot(snapshot, repo.config);
}
export async function readLogAt(repo: Repository, commit: string): Promise<LogRead> {
  try {
    if (!await commitPresent(repo, commit)) return { kind: 'unreadable', reason: 'git_failed' };
    const items = parseTree(await git(repo, ['ls-tree', '-z', '-l', '--full-tree', commit, '--', logPath])).filter(item => item.path === logPath);
    if (!items.length) {
      const parent = parseTree(await git(repo, ['ls-tree', '-z', '-l', '--full-tree', commit, '--', path.posix.dirname(logPath)]));
      return parent.some(item => item.path === path.posix.dirname(logPath) && item.type !== 'tree') ? { kind: 'unreadable', reason: 'not_a_file' } : { kind: 'absent' };
    }
    const [item] = items;
    if (!regular(item)) return { kind: 'unreadable', reason: 'not_a_file' };
    if (item.bytes > Math.min(maxLogBytes, blobLimit(repo))) return { kind: 'unreadable', reason: 'over_limit' };
    for await (const { content } of blobs(repo, [item])) return { kind: 'bytes', bytes: Buffer.from(content) };
    return { kind: 'unreadable', reason: 'git_failed' };
  } catch (error) {
    if (error instanceof GitFailure || (error instanceof SafeError && ['invalid_git_tree', 'invalid_git_blob_batch'].includes(error.code))) return { kind: 'unreadable', reason: 'git_failed' };
    throw error;
  }
}

const packageRoot = path.resolve(import.meta.dirname, '..');
/** A check run from inside the verified repository, or by the very build being verified, cannot vouch for that build. */
export function independence(runningRoot: string | null, repositoryRoot: string, own: Measurement | null, target: Measurement | null): boolean {
  if (!runningRoot || !own || !target || within(repositoryRoot.toLowerCase(), runningRoot.toLowerCase())) return false;
  return own.sha256 !== target.sha256;
}
async function runningPackage(config: Config): Promise<{ root: string | null; measurement: Measurement | null }> {
  const root = await canonical(packageRoot).catch(() => null);
  if (!root) return { root, measurement: null };
  return { root, measurement: await measureDirectory(root, config).then(measured => measured.release.measurement, () => null) };
}
const sha40 = (value: string | undefined, code: string) => { if (!value || !/^[0-9a-f]{40}$/.test(value)) throw new SafeError(code); return value; };

export async function releaseVerify(repo: Repository, options: { logCommit: string; installed?: string; commit?: string; pin?: string }) {
  const logCommit = sha40(options.logCommit, 'invalid_release_commit');
  if ((options.installed === undefined) === (options.commit === undefined)) throw new SafeError('invalid_command');
  const pin = options.pin === undefined ? null : parsePin(options.pin);
  const target = options.installed !== undefined ? { kind: 'installed' as const } : { kind: 'commit' as const, commit: sha40(options.commit, 'invalid_release_commit') };
  const result = await verifyRelease(await readLogAt(repo, logCommit), pin, async () => (target.kind === 'installed'
    ? await measureDirectory(options.installed!, repo.config) : await measureCommit(repo, target.commit)).release);
  const running = await runningPackage(repo.config);
  const independent = independence(running.root, repo.root, running.measurement, result.release?.measurement ?? null);
  const payload = { schema: 'scanmux.release-verification/v1', ...verdictOf(result.outcome), log: { commit: logCommit, ...(result.log ?? { entries: null, head: null }) },
    pin: pin ?? 'none', target: { ...target, ...(result.release ?? { version: null, measurement: null }) }, match: result.seq === null ? null : { seq: result.seq },
    independent, scope: releaseScope };
  const { measurement } = payload.target;
  const text = `ScanMux release verify: ${result.outcome} (exit ${payload.exitCode}); log=${logCommit} entries=${payload.log.entries ?? 'unread'} head=${payload.log.head ?? 'unread'}; `
    + `pin=${pin ? `${pin.entries}:${pin.head}` : 'none (not owner-approved)'}.\n`
    + `Target: ${target.kind === 'installed' ? 'installed directory' : `commit ${target.commit}`}; version=${payload.target.version ?? 'unmeasured'}; `
    + `measurement=${measurement ? `${measurement.sha256} files=${measurement.files} bytes=${measurement.bytes}` : 'unmeasured'}; match=${result.seq === null ? 'none' : `seq ${result.seq}`}; independent=${independent}.\n`
    + 'A logged release matches the release log; it is not a security PASS. Only the package file set is measured: dependencies are bound by the lockfile and not measured, there is no witness, and the log is not an authenticated history.\n';
  return { payload, text, exitCode: payload.exitCode };
}

export async function releaseLogCheck(repo: Repository, options: { base: string; head: string }) {
  const headCommit = sha40(options.head, 'invalid_release_commit');
  const baseCommit = options.base === 'none' ? null : sha40(options.base, 'invalid_release_commit');
  const reproduce = async (entry: LogEntry) => {
    try { return (await measureCommit(repo, entry.sourceCommit)).release; }
    catch (error) { if (error instanceof SafeError && (error.code.startsWith('release_') || error.code === 'git_failed')) return null; throw error; }
  };
  const result = await checkReleaseLog(baseCommit ? await readLogAt(repo, baseCommit) : null, await readLogAt(repo, headCommit), reproduce);
  const payload = { schema: 'scanmux.release-log-check/v1', ...verdictOf(result.outcome), base: { commit: baseCommit, ...(result.base ?? { state: null, entries: null, head: null }) },
    head: { commit: headCommit, ...(result.head ?? { entries: null, head: null }) }, reproduced: result.reproduced, scope: releaseScope };
  const text = `ScanMux release log check: ${result.outcome} (exit ${payload.exitCode}); base=${baseCommit ?? 'none'} entries=${payload.base.entries ?? 'unread'}; `
    + `head=${headCommit} entries=${payload.head.entries ?? 'unread'} log head=${payload.head.head ?? 'unread'}; reproduced=${result.reproduced}.\n`
    + 'This check runs inside the checked repository and is not a trust anchor; owners verify against their own pin with release-verify.\n';
  return { payload, text, exitCode: payload.exitCode };
}

/** A lock left by a crashed writer is never removed here: the writer waits up to the configured timeout and then refuses. */
async function acquireLock(lock: string, timeoutMs: number, signal?: AbortSignal): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try { await writeFile(lock, String(process.pid), { flag: 'wx' }); return; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
    if (signal?.aborted) throw new SafeError('release_record_cancelled');
    if (Date.now() >= deadline) throw new SafeError('release_log_locked');
    await delay(25);
  }
}
export async function releaseRecord(repo: Repository, options: { commit: string; expectHead: string }) {
  const commit = sha40(options.commit, 'invalid_release_commit');
  const expected = options.expectHead === 'zero' ? zeroHead : options.expectHead;
  if (!/^[0-9a-f]{64}$/.test(expected)) throw new SafeError('invalid_release_head');
  const directory = path.join(repo.root, 'transparency'), file = path.join(directory, 'releases.jsonl');
  const directoryStat = await lstat(directory).catch(() => null), fileStat = await lstat(file).catch(() => null);
  if (!directoryStat || !fileStat) throw new SafeError('release_log_missing');
  if (!directoryStat.isDirectory() || !fileStat.isFile() || directoryStat.isSymbolicLink() || fileStat.isSymbolicLink() || (await canonical(file)) !== file) throw new SafeError('release_log_not_a_file');
  if (fileStat.size > maxLogBytes) throw new SafeError('release_log_over_limit');
  const { release } = await measureCommit(repo, commit);
  const lock = path.join(directory, '.releases.lock');
  await acquireLock(lock, repo.config.timeoutMs, repo.signal);
  let parsed, planned;
  try {
    const current = await readFile(file);
    if (current.length > maxLogBytes) throw new SafeError('release_log_over_limit');
    parsed = parseLog(current);
    if (!parsed.ok) throw new SafeError(`release_log_${parsed.reason}`);
    planned = planRecord(parsed.log, expected, commit, release);
    if (planned.state === 'appended') {
      const temporary = path.join(directory, `.releases-${process.pid}-${Date.now()}.tmp`);
      try {
        await writeFile(temporary, Buffer.concat([current, Buffer.from(planned.line)]), { flag: 'wx' });
        const reread = parseLog(await readFile(temporary));
        if (!reread.ok || reread.log.head !== hash(planned.line.slice(0, -1)) || reread.log.entries.length !== planned.entry.seq) throw new SafeError('release_log_write_unverified');
        await rename(temporary, file);
      } finally { await rm(temporary, { force: true }); }
    }
  } finally { await rm(lock, { force: true }); }
  const entries = parsed.log.entries.length + (planned.state === 'appended' ? 1 : 0);
  const head = planned.state === 'appended' ? hash(planned.line.slice(0, -1)) : parsed.log.head;
  const payload = { schema: 'scanmux.release-record/v1', state: planned.state, entry: planned.entry, log: { entries, head }, pin: `${entries}:${head}`, scope: releaseScope };
  const text = `ScanMux release record: ${planned.state} seq=${planned.entry.seq} version=${planned.entry.version} sourceCommit=${planned.entry.sourceCommit}.\n`
    + `Measurement: ${release.measurement.sha256} files=${release.measurement.files} bytes=${release.measurement.bytes}\n`
    + `Log: entries=${entries} head=${head}\nPin after this log is committed and reviewed: --pin ${entries}:${head}\n`
    + 'Commit the log in a follow-up pull request. The log is tamper-evident against an owner-held pin only; it is not an authenticated history.\n';
  return { payload, text, exitCode: 0 };
}
export function releaseCommandTarget(installed: string | undefined): string[] {
  if (installed === undefined) return [];
  if (!hostLocalPath(installed)) throw new SafeError('release_installed_path_invalid');
  return [installed];
}
