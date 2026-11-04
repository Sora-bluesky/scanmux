import type { BigIntStats } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { SafeError, canonical, hash, safeRelative, within } from './safety.ts';
import { runtimeComponents, zeroHead, type LedgerPin, type RuntimeComponent } from './runtime-policy.ts';

export const ledgerLimit = 1024 * 1024;
export const ledgerPlatforms = ['windows-x64', 'linux-x64'] as const;
export const unpublishedReasons = ['publisher_evidence_unpublished', 'os_signature_not_offline', 'locally_built', 'not_a_file'] as const;

export interface PinnedFile { readonly path: string; readonly sha256: string }
export type LedgerEvidence =
  | { readonly kind: 'sigstore-slsa'; readonly bundle: PinnedFile; readonly trustedRoot: PinnedFile; readonly sourceRef: string; readonly sourceDigest: string }
  | { readonly kind: 'sigstore-slsa-archive'; readonly bundle: PinnedFile; readonly trustedRoot: PinnedFile; readonly sourceRef: string; readonly sourceDigest: string; readonly archive: PinnedFile; readonly member: string }
  | { readonly kind: 'none'; readonly reason: typeof unpublishedReasons[number] };
export interface LedgerEntry {
  readonly seq: number;
  readonly prev: string;
  readonly recordedAt: string;
  readonly component: RuntimeComponent;
  readonly platform: typeof ledgerPlatforms[number];
  readonly version: string;
  readonly sha256: string;
  readonly change: string;
  readonly recordedBy: { readonly scanmux: string; readonly verifier: { readonly sha256: string; readonly version: string } | null };
  readonly evidence: LedgerEvidence;
}
export type LedgerFields = Omit<LedgerEntry, 'seq' | 'prev'>;

const shaPattern = /^[0-9a-f]{64}$/;
const versionPattern = /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/;
const changePattern = /^[\x20-\x7e]{1,200}$/;
const refPattern = /^refs\/(?:tags|heads)\/[A-Za-z0-9._\/-]{1,200}$/;
const sourceDigestPattern = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const timePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function bad(): never { throw new SafeError('engine_ledger_line_invalid'); }
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) bad();
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) bad();
  return value;
}
function text(input: unknown, pattern: RegExp): string {
  if (typeof input !== 'string' || !pattern.test(input)) bad();
  return input;
}
function member<T extends string>(input: unknown, set: readonly T[]): T {
  if (typeof input !== 'string' || !(set as readonly string[]).includes(input)) bad();
  return input as T;
}
function pinnedFile(input: unknown): PinnedFile {
  const value = exact(input, ['path', 'sha256']);
  if (typeof value.path !== 'string' || value.path.length > 4096 || /[\x00-\x1f\x7f]/.test(value.path) || !path.isAbsolute(value.path)) bad();
  return { path: value.path, sha256: text(value.sha256, shaPattern) };
}
function evidence(input: unknown): LedgerEvidence {
  if (!input || typeof input !== 'object' || Array.isArray(input)) bad();
  const kind = (input as Record<string, unknown>).kind;
  if (kind === 'none') return { kind, reason: member(exact(input, ['kind', 'reason']).reason, unpublishedReasons) };
  if (kind !== 'sigstore-slsa' && kind !== 'sigstore-slsa-archive') bad();
  const value = exact(input, ['kind', 'bundle', 'trustedRoot', 'sourceRef', 'sourceDigest', ...(kind === 'sigstore-slsa-archive' ? ['archive', 'member'] : [])]);
  const common = { bundle: pinnedFile(value.bundle), trustedRoot: pinnedFile(value.trustedRoot), sourceRef: text(value.sourceRef, refPattern), sourceDigest: text(value.sourceDigest, sourceDigestPattern) };
  if (kind === 'sigstore-slsa') return { kind, ...common };
  let name: string;
  try { name = safeRelative(value.member); } catch { bad(); }
  return { kind, ...common, archive: pinnedFile(value.archive), member: name };
}
function recordedBy(input: unknown): LedgerEntry['recordedBy'] {
  const value = exact(input, ['scanmux', 'verifier']);
  if (value.verifier === null) return { scanmux: text(value.scanmux, versionPattern), verifier: null };
  const tool = exact(value.verifier, ['sha256', 'version']);
  return { scanmux: text(value.scanmux, versionPattern), verifier: { sha256: text(tool.sha256, shaPattern), version: text(tool.version, versionPattern) } };
}

function encode(entry: LedgerEntry): string {
  const evidenceValue = entry.evidence.kind === 'none'
    ? { kind: entry.evidence.kind, reason: entry.evidence.reason }
    : { kind: entry.evidence.kind, bundle: { path: entry.evidence.bundle.path, sha256: entry.evidence.bundle.sha256 },
      trustedRoot: { path: entry.evidence.trustedRoot.path, sha256: entry.evidence.trustedRoot.sha256 },
      sourceRef: entry.evidence.sourceRef, sourceDigest: entry.evidence.sourceDigest,
      ...(entry.evidence.kind === 'sigstore-slsa-archive' ? { archive: { path: entry.evidence.archive.path, sha256: entry.evidence.archive.sha256 }, member: entry.evidence.member } : {}) };
  const verifier = entry.recordedBy.verifier && { sha256: entry.recordedBy.verifier.sha256, version: entry.recordedBy.verifier.version };
  return JSON.stringify({
    seq: entry.seq, prev: entry.prev, recordedAt: entry.recordedAt, component: entry.component, platform: entry.platform,
    version: entry.version, sha256: entry.sha256, change: entry.change, recordedBy: { scanmux: entry.recordedBy.scanmux, verifier }, evidence: evidenceValue,
  });
}

export function parseLedgerLine(line: Buffer | string): LedgerEntry {
  const bytes = typeof line === 'string' ? Buffer.from(line) : line;
  if (bytes.length > ledgerLimit) bad();
  const source = bytes.toString('utf8');
  let input: unknown;
  try { input = JSON.parse(source); } catch { bad(); }
  const value = exact(input, ['seq', 'prev', 'recordedAt', 'component', 'platform', 'version', 'sha256', 'change', 'recordedBy', 'evidence']);
  if (typeof value.seq !== 'number' || !Number.isSafeInteger(value.seq) || value.seq < 1) bad();
  const recordedAt = text(value.recordedAt, timePattern);
  if (Number.isNaN(Date.parse(recordedAt)) || new Date(recordedAt).toISOString() !== recordedAt) bad();
  const entry: LedgerEntry = {
    seq: value.seq, prev: text(value.prev, shaPattern), recordedAt, component: member(value.component, runtimeComponents),
    platform: member(value.platform, ledgerPlatforms), version: text(value.version, versionPattern), sha256: text(value.sha256, shaPattern),
    change: text(value.change, changePattern), recordedBy: recordedBy(value.recordedBy), evidence: evidence(value.evidence),
  };
  if (!Buffer.from(encode(entry)).equals(bytes)) bad();
  return entry;
}

// Fields are validated by round-tripping through the line parser, so a caller cannot append a line the reader would reject.
export function nextLedgerLine(previous: readonly LedgerEntry[], fields: LedgerFields): { entry: LedgerEntry; bytes: Buffer; head: string } {
  const last = previous.at(-1);
  const entry = parseLedgerLine(encode({ ...fields, seq: previous.length + 1, prev: last ? hash(encode(last)) : zeroHead }));
  const line = encode(entry);
  return { entry, bytes: Buffer.from(line + '\n'), head: hash(line) };
}

function mismatch(): never { throw new SafeError('provenance_ledger_mismatch'); }

/** The writer's view: every line must parse and chain, and the pinned prefix must match. No repair is attempted. */
export function parseWholeLedger(content: Buffer, pin: LedgerPin): { entries: LedgerEntry[]; head: string } {
  if (content.length > ledgerLimit) throw new SafeError('engine_ledger_tail_invalid');
  const entries: LedgerEntry[] = [];
  function broken(): never { if (entries.length < pin.entries) mismatch(); throw new SafeError('engine_ledger_tail_invalid'); }
  let offset = 0, head = zeroHead;
  while (offset < content.length) {
    const end = content.indexOf(0x0a, offset);
    if (end < 0) broken();
    const line = content.subarray(offset, end);
    let entry: LedgerEntry;
    try { entry = parseLedgerLine(line); } catch { broken(); }
    if (entry.seq !== entries.length + 1 || entry.prev !== head) broken();
    head = hash(line);
    entries.push(entry);
    if (entries.length === pin.entries && head !== pin.head) mismatch();
    offset = end + 1;
  }
  if (entries.length < pin.entries) mismatch();
  return { entries, head };
}

/** Reads at most one byte past the limit through one handle. A second hard link would let another ledger path, and so another lock, write the same chain. */
export async function readLedgerFile(physical: string): Promise<{ content: Buffer; stat: BigIntStats }> {
  const handle = await open(physical, 'r');
  try {
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) return { content: Buffer.alloc(0), stat };
    if (stat.nlink !== 1n) throw new SafeError('engine_ledger_linked');
    const buffer = Buffer.alloc(ledgerLimit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    return { content: buffer.subarray(0, length), stat };
  } finally { await handle.close(); }
}

export async function readPinnedLedger(pin: LedgerPin, root?: string): Promise<LedgerEntry[]> {
  if (root && within(root, path.resolve(pin.path))) throw new SafeError('provenance_ledger_inside_target');
  if (pin.entries === 0) return [];
  let physical: string;
  try { physical = await canonical(pin.path); } catch (error) { if (error instanceof SafeError) throw error; mismatch(); }
  if (root && within(root, physical)) throw new SafeError('provenance_ledger_inside_target');
  let content: Buffer;
  try {
    const file = await readLedgerFile(physical);
    if (!file.stat.isFile()) mismatch();
    content = file.content;
  } catch (error) { if (error instanceof SafeError) throw error; mismatch(); }
  const entries: LedgerEntry[] = [];
  let offset = 0, head = zeroHead;
  for (let index = 0; index < pin.entries; index++) {
    const end = content.indexOf(0x0a, offset);
    if (end < 0) mismatch();
    const line = content.subarray(offset, end);
    let entry: LedgerEntry;
    try { entry = parseLedgerLine(line); } catch { mismatch(); }
    if (entry.seq !== index + 1 || entry.prev !== head) mismatch();
    head = hash(line);
    entries.push(entry);
    offset = end + 1;
  }
  if (head !== pin.head) mismatch();
  return entries;
}
