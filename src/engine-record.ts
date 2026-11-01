import type { BigIntStats } from 'node:fs';
import { lstat, open, readFile, unlink } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { boundedRead, canonical, hash, SafeError } from './safety.ts';
import type { Config } from './model.ts';
import {
  ledgerLimit, ledgerPlatforms, nextLedgerLine, parseWholeLedger, readLedgerFile, readPinnedLedger, unpublishedReasons,
  type LedgerEntry, type LedgerEvidence, type LedgerFields,
} from './engine-ledger.ts';
import { admitRuntimePolicy, runtimeComponents, type LedgerPin, type RuntimeComponent, type RuntimePolicy2, type RuntimeSubject } from './runtime-policy.ts';
import { decideProvenance, ProvenanceRefusalError, type PublisherCheck } from './provenance.ts';
import { evidencePath, verifyPublisher, type AdmissionScope } from './runtime-admission.ts';

const scanmuxVersion = '0.1.0';
type RequestEvidence =
  | { kind: 'sigstore-slsa'; bundle: string; trustedRoot: string; sourceRef: string; sourceDigest: string }
  | { kind: 'none'; reason: typeof unpublishedReasons[number] };
interface EngineRecordRequest {
  component: RuntimeComponent; platform: typeof ledgerPlatforms[number]; version: string; change: string; artifact: string; evidence: RequestEvidence;
}
export interface EngineRecordResult {
  schema: 'scanmux.engine-record-result/v1'; state: 'appended' | 'existing'; seq: number;
  paste: { tool: { path: string; sha256: string; version: string }; ledger: LedgerPin };
  authenticatedHistory: false;
}
export type EngineStatus = 'current' | 'superseded' | 'denied';
export interface EngineHistory {
  schema: 'scanmux.engine-history/v1'; ledger: LedgerPin; authenticatedHistory: false;
  entries: { seq: number; component: RuntimeComponent; platform: LedgerEntry['platform']; version: string; sha256: string;
    evidence: LedgerEvidence['kind']; recordedAt: string; change: string; status: EngineStatus }[];
}

export interface UnpinnedTail {
  entries: number; head: string;
  unpinned: { seq: number; component: RuntimeComponent; sha256: string; change: string }[];
}
/** Carries only parsed ledger values, so the operator can check the lines past the pin and paste a pin for them. */
export class EngineLedgerUnpinnedTailError extends SafeError {
  readonly ledger: UnpinnedTail;
  constructor(ledger: UnpinnedTail) { super('engine_ledger_unpinned_tail'); this.ledger = ledger; }
}

function invalid(): never { throw new SafeError('engine_record_request_invalid'); }
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) invalid();
  return value;
}
function absolute(input: unknown): string {
  if (typeof input !== 'string' || input.length > 4096 || /[\x00-\x1f\x7f]/.test(input) || !path.isAbsolute(input)) invalid();
  return input;
}
function bundleFile(input: unknown): string {
  const file = absolute(input);
  if (!['.json', '.jsonl'].includes(path.extname(file).toLowerCase())) invalid();
  return file;
}
function member<T extends string>(input: unknown, set: readonly T[]): T {
  if (typeof input !== 'string' || !(set as readonly string[]).includes(input)) invalid();
  return input as T;
}
function parseRequest(input: unknown): EngineRecordRequest {
  const value = exact(input, ['schema', 'component', 'platform', 'version', 'change', 'artifact', 'evidence']);
  // The version is printed as a config tool pin, so it has the config's Tool.version form.
  if (value.schema !== 'scanmux.engine-record/v1' || typeof value.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(value.version) || typeof value.change !== 'string') invalid();
  const raw = value.evidence;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid();
  const kind = (raw as Record<string, unknown>).kind;
  let evidence: RequestEvidence;
  if (kind === 'none') evidence = { kind, reason: member(exact(raw, ['kind', 'reason']).reason, unpublishedReasons) };
  else if (kind === 'sigstore-slsa') {
    const item = exact(raw, ['kind', 'bundle', 'trustedRoot', 'sourceRef', 'sourceDigest']);
    if (typeof item.sourceRef !== 'string' || typeof item.sourceDigest !== 'string') invalid();
    evidence = { kind, bundle: bundleFile(item.bundle), trustedRoot: absolute(item.trustedRoot), sourceRef: item.sourceRef, sourceDigest: item.sourceDigest };
  } else invalid();
  return { component: member(value.component, runtimeComponents), platform: member(value.platform, ledgerPlatforms), version: value.version,
    change: value.change, artifact: absolute(value.artifact), evidence };
}
function policyTwo(config: Config): RuntimePolicy2 {
  if (config.schema !== 2 || config.runtimePolicy.schema !== 'scanmux.runtime-policy/v2') throw new SafeError('engine_ledger_policy_v2_required');
  return config.runtimePolicy;
}
async function pinned(physical: string): Promise<{ path: string; sha256: string }> {
  return { path: physical, sha256: hash(await readFile(physical)) };
}
// A ledger that does not exist yet is named through its canonical directory; a dangling link is not a missing ledger.
async function ledgerFile(file: string): Promise<string> {
  try { return await canonical(file); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    const present = await lstat(file).then(() => true, (missing: NodeJS.ErrnoException) => { if (missing.code !== 'ENOENT') throw missing; return false; });
    if (present) throw new SafeError('linked_path');
    return path.join(await canonical(path.dirname(file)), path.basename(file));
  }
}
async function readLedger(file: string): Promise<{ content: Buffer; stat: BigIntStats | null }> {
  try {
    const read = await readLedgerFile(file);
    if (!read.stat.isFile()) throw new SafeError('engine_ledger_tail_invalid');
    return read;
  } catch (error) {
    if (error instanceof SafeError) throw error;
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { content: Buffer.alloc(0), stat: null };
    throw new SafeError('engine_ledger_tail_invalid');
  }
}
async function append(file: string, read: BigIntStats | null, bytes: Buffer): Promise<void> {
  let handle;
  try { handle = await open(file, read ? 'a' : 'wx', 0o600); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new SafeError('engine_ledger_changed'); throw error; }
  try {
    const stat = await handle.stat({ bigint: true });
    if (stat.nlink !== 1n || (read ? stat.dev !== read.dev || stat.ino !== read.ino || stat.size !== read.size : stat.size !== 0n)) throw new SafeError('engine_ledger_changed');
    await handle.writeFile(bytes); await handle.sync();
  } finally { await handle.close(); }
}

/** The only ledger writer. Exclusion is a `<physical ledger>.lock` file created with wx; a stale lock stops the writer and is never removed automatically. */
export async function recordEngine(requestFile: string, config: Config, scope: AdmissionScope): Promise<EngineRecordResult> {
  if (!path.isAbsolute(requestFile)) invalid();
  let input: unknown;
  try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await boundedRead(await canonical(requestFile), 65536))); } catch { invalid(); }
  const request = parseRequest(input), policy = policyTwo(config), { ledger: pin, verifier } = policy.provenance;
  const requirement = policy.provenance.require.find(item => item.component === request.component);
  const sigstore = request.evidence.kind === 'sigstore-slsa';
  if (sigstore && requirement?.level !== 'publisher') throw new SafeError('engine_record_publisher_unrequired');
  admitRuntimePolicy(policy, sigstore ? [{ component: 'gh', sha256: verifier.sha256 }] : []);
  const artifact = await pinned(await canonical(request.artifact));
  const evidence: LedgerEvidence = request.evidence.kind === 'none' ? request.evidence : {
    kind: 'sigstore-slsa', bundle: await pinned(await evidencePath(request.evidence.bundle, scope.root)),
    trustedRoot: await pinned(await evidencePath(request.evidence.trustedRoot, scope.root)),
    sourceRef: request.evidence.sourceRef, sourceDigest: request.evidence.sourceDigest,
  };
  const fields: LedgerFields = {
    recordedAt: new Date().toISOString(), component: request.component, platform: request.platform, version: request.version,
    sha256: artifact.sha256, change: request.change,
    recordedBy: { scanmux: scanmuxVersion, verifier: sigstore ? { sha256: verifier.sha256, version: verifier.version } : null }, evidence,
  };
  const paste = (entries: number, head: string) => ({ tool: { path: artifact.path, sha256: artifact.sha256, version: request.version }, ledger: { path: pin.path, entries, head } });
  const ledger = await ledgerFile(pin.path), lockPath = ledger + '.lock';
  let lock;
  try { lock = await open(lockPath, 'wx', 0o600); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new SafeError('engine_ledger_locked'); throw error; }
  try {
    const read = await readLedger(ledger), current = parseWholeLedger(read.content, pin);
    if (current.entries.length > pin.entries) throw new EngineLedgerUnpinnedTailError({ entries: current.entries.length, head: current.head,
      unpinned: current.entries.slice(pin.entries).map(entry => ({ seq: entry.seq, component: entry.component, sha256: entry.sha256, change: entry.change })) });
    const same = current.entries.find(entry => entry.component === fields.component && entry.platform === fields.platform
      && entry.version === fields.version && entry.sha256 === fields.sha256 && isDeepStrictEqual(entry.evidence, evidence));
    if (same) return { schema: 'scanmux.engine-record-result/v1', state: 'existing', seq: same.seq, paste: paste(current.entries.length, current.head), authenticatedHistory: false };
    let next;
    try { next = nextLedgerLine(current.entries, fields); }
    catch (error) { if (error instanceof SafeError && error.code === 'engine_ledger_line_invalid') invalid(); throw error; }
    if (read.content.length + next.bytes.length > ledgerLimit) throw new SafeError('engine_ledger_full');
    if (requirement?.level === 'publisher' && evidence.kind === 'sigstore-slsa') {
      const check: PublisherCheck = { component: request.component, file: artifact.path, ledgerSeq: next.entry.seq, bundle: evidence.bundle, trustedRoot: evidence.trustedRoot,
        expected: { ...requirement.publisher, sha256: artifact.sha256, sourceRef: evidence.sourceRef, sourceDigest: evidence.sourceDigest } };
      const decision = decideProvenance(policy, check, await verifyPublisher(policy, check, scope));
      if (decision.kind === 'refused') throw new ProvenanceRefusalError({ ...decision, engine: { ...decision.engine, ledgerSeq: null } });
    }
    await append(ledger, read.stat, next.bytes);
    return { schema: 'scanmux.engine-record-result/v1', state: 'appended', seq: next.entry.seq, paste: paste(next.entry.seq, next.head), authenticatedHistory: false };
  } finally {
    await lock.close();
    await unlink(lockPath);
  }
}

function denied(policy: RuntimePolicy2, entry: LedgerEntry): boolean {
  return policy.deny.some(rule => rule.component === entry.component && (rule.kind === 'component' || rule.sha256 === entry.sha256));
}
export async function engineHistory(config: Config, configured: readonly RuntimeSubject[]): Promise<EngineHistory> {
  const policy = policyTwo(config), ledger = policy.provenance.ledger;
  const entries = (await readPinnedLedger(ledger)).map(entry => ({
    seq: entry.seq, component: entry.component, platform: entry.platform, version: entry.version, sha256: entry.sha256,
    evidence: entry.evidence.kind, recordedAt: entry.recordedAt, change: entry.change,
    status: denied(policy, entry) ? 'denied' as const
      : configured.some(subject => subject.component === entry.component && subject.sha256 === entry.sha256) ? 'current' as const : 'superseded' as const,
  }));
  return { schema: 'scanmux.engine-history/v1', ledger: { path: ledger.path, entries: ledger.entries, head: ledger.head }, authenticatedHistory: false, entries };
}
