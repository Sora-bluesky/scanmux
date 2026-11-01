import { constants as bufferConstants } from 'node:buffer';
import { spawn, spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import type { Tool } from './model.ts';
import type { HostJobIntent } from './host-job-records.ts';
import { cleanEnvironment } from './process.ts';
import { hash, SafeError } from './safety.ts';

export interface RetainedSlot {
  readonly slot: number;
  readonly name: string;
  readonly maximum: number;
  readonly reserved: boolean;
}
function reject(): never { throw new SafeError('invalid_retained_write'); }
function outputMaximum(maximum: number) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 2147483647) reject();
}

/** Literal data records only. Runtime copies and empty infrastructure are separate. */
export function retainedCatalog(maximum: number): readonly RetainedSlot[] {
  outputMaximum(maximum);
  const records: Omit<RetainedSlot, 'slot'>[] = [
    { name: 'host-job-intent.json', maximum: 65536, reserved: true },
    { name: 'host-job-failure.json', maximum: 4096, reserved: true },
    { name: 'host-job-retained.json', maximum: 4096, reserved: true },
    ...['owner.json', 'report.json', 'delegated-job.json', 'host-job-primary.json', 'host-job-cleanup.json', 'host-job-native.json', 'host-job.json']
      .map(name => ({ name, maximum, reserved: true })),
    { name: 'job-plan.json', maximum, reserved: false },
  ];
  for (let sequence = 1; sequence <= 4; sequence++) {
    for (const kind of ['checkpoint', 'commit']) records.push({ name: `checkpoints/${kind}-${sequence}.json`, maximum, reserved: false });
  }
  return Object.freeze(records.map((record, slot) => Object.freeze({ slot, ...record })));
}

export interface RetainedWritePart { readonly name: string; readonly bytes: Buffer }

function describeRetainedWrite(parts: readonly RetainedWritePart[], maximum: number) {
  const catalog = retainedCatalog(maximum);
  if (!Array.isArray(parts) || parts.length < 1 || parts.length > 2) reject();
  const selected = parts.map(part => {
    if (!part || Object.keys(part).length !== 2 || !Object.hasOwn(part, 'name') || !Object.hasOwn(part, 'bytes')
      || typeof part.name !== 'string' || !Buffer.isBuffer(part.bytes)) reject();
    const entry = catalog.find(entry => entry.name === part.name);
    // Initialization and allocation-stop evidence are owned by the native store.
    if (!entry || ['host-job-intent.json', 'host-job-retained.json'].includes(entry.name) || part.bytes.length < 1 || part.bytes.length > entry.maximum) reject();
    return entry;
  });
  let kind: 'single' | 'checkpoint' = 'single', sequence = 0;
  if (parts.length === 2) {
    const match = /^checkpoints\/checkpoint-([1-4])\.json$/.exec(selected[0].name);
    if (!match || selected[1].name !== `checkpoints/commit-${match[1]}.json`) reject();
    kind = 'checkpoint'; sequence = Number(match[1]);
  } else if (selected[0].name.startsWith('checkpoints/')) reject();
  return { selected, kind, sequence };
}

/** Encodes one native transaction; this function grants no storage admission. */
export function encodeRetainedWrite(parts: readonly RetainedWritePart[], maximum: number): Buffer {
  const { selected, kind, sequence } = describeRetainedWrite(parts, maximum);
  const header = Buffer.from(JSON.stringify({ schema: 'scanmux.retained-write-request/v1', kind, sequence,
    parts: selected.map((entry, index) => ({ slot: entry.slot, bytes: parts[index].bytes.length, sha256: hash(parts[index].bytes) })) }) + '\n', 'ascii');
  if (header.length > 4096) reject();
  const total = header.length + parts.reduce((sum, part) => sum + part.bytes.length, 0);
  if (!Number.isSafeInteger(total) || total > bufferConstants.MAX_LENGTH) reject();
  return Buffer.concat([header, ...parts.map(part => part.bytes)], total);
}

export interface RetainedPolicy {
  jobId: string; intentSha256: string; maximum: number; allocatedBytes: number; clusterBytes: number;
}
export interface RetainedFile { slot: number; bytes: number; allocatedBytes: number }
export interface RetainedSnapshot {
  allocatedBytes: number; reservedBytes: number; allocatedLimit: number; clusterBytes: number; files: RetainedFile[];
}
export interface RetainedWriteResult {
  schema: 'scanmux.retained-write-result/v1'; result: 'committed' | 'retained_allocated_limit'; jobId: string; intentSha256: string;
  slots: number[]; proposedAllocatedBytes: number; availableIntermediateBytes: number; before: RetainedSnapshot; after: RetainedSnapshot;
}
export interface RetainedAllocationStop {
  schema: 'scanmux.retained-allocation-stop/v1'; jobId: string; intentSha256: string;
  parts: { slot: number; bytes: number }[]; proposedAllocatedBytes: number; availableIntermediateBytes: number;
  actualAllocatedBytes: number; reservedBytes: number; allocatedLimit: number; clusterBytes: number;
}
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  const item = value as Record<string, unknown>;
  if (Object.keys(item).length !== keys.length || keys.some(key => !Object.hasOwn(item, key))) reject();
  return item;
}
function count(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) reject();
  return value;
}
function sum(values: readonly number[]) { return values.reduce((total, value) => count(total + count(value)), 0); }
function rounded(value: number, cluster: number) { return count(Math.ceil(count(value) / cluster) * cluster); }
function policyCatalog(policy: RetainedPolicy) {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(policy.jobId) || !/^[a-f0-9]{64}$/.test(policy.intentSha256)) reject();
  count(policy.clusterBytes, 1); count(policy.allocatedBytes, 1);
  const catalog = retainedCatalog(policy.maximum);
  if (policy.allocatedBytes % policy.clusterBytes !== 0 || sum(catalog.filter(item => item.reserved).map(item => rounded(item.maximum, policy.clusterBytes))) > policy.allocatedBytes) reject();
  return catalog;
}

/** Checks recorded native accounting; it never allocates or grants a write. */
export function validateRetainedSnapshot(input: unknown, policy: RetainedPolicy): RetainedSnapshot {
  const catalog = policyCatalog(policy), value = exact(input, ['allocatedBytes', 'reservedBytes', 'allocatedLimit', 'clusterBytes', 'files']);
  if (value.allocatedLimit !== policy.allocatedBytes || value.clusterBytes !== policy.clusterBytes || !Array.isArray(value.files) || value.files.length > catalog.length) reject();
  let previous = -1;
  const files = value.files.map(input => {
    const file = exact(input, ['slot', 'bytes', 'allocatedBytes']), slot = count(file.slot, 0, catalog.length - 1);
    if (slot <= previous) reject(); previous = slot;
    const bytes = count(file.bytes, 0, catalog[slot].maximum), allocatedBytes = count(file.allocatedBytes);
    if (allocatedBytes !== rounded(bytes, policy.clusterBytes)) reject();
    return { slot, bytes, allocatedBytes };
  });
  const allocatedBytes = sum(files.map(file => file.allocatedBytes));
  const reservedBytes = sum(catalog.filter(slot => slot.reserved && !files.some(file => file.slot === slot.slot)).map(slot => rounded(slot.maximum, policy.clusterBytes)));
  if (value.allocatedBytes !== allocatedBytes || value.reservedBytes !== reservedBytes || sum([allocatedBytes, reservedBytes]) > policy.allocatedBytes) reject();
  return { allocatedBytes, reservedBytes, allocatedLimit: policy.allocatedBytes, clusterBytes: policy.clusterBytes, files };
}

/** A historical refusal of record data allocation, distinct from logical length or a directory quota. */
export function validateRetainedAllocationStop(input: unknown, policy: RetainedPolicy, observed?: RetainedSnapshot): RetainedAllocationStop {
  const catalog = policyCatalog(policy), value = exact(input, ['schema', 'jobId', 'intentSha256', 'parts', 'proposedAllocatedBytes',
    'availableIntermediateBytes', 'actualAllocatedBytes', 'reservedBytes', 'allocatedLimit', 'clusterBytes']);
  if (value.schema !== 'scanmux.retained-allocation-stop/v1' || value.jobId !== policy.jobId || value.intentSha256 !== policy.intentSha256
    || value.allocatedLimit !== policy.allocatedBytes || value.clusterBytes !== policy.clusterBytes || !Array.isArray(value.parts)) reject();
  const parts = value.parts.map(input => {
    const part = exact(input, ['slot', 'bytes']), slot = count(part.slot, 10, 18);
    return { slot, bytes: count(part.bytes, 1, catalog[slot].maximum) };
  });
  if (!(parts.length === 1 && parts[0].slot === 10
    || parts.length === 2 && parts[0].slot >= 11 && parts[0].slot % 2 === 1 && parts[1].slot === parts[0].slot + 1)) reject();
  const actualAllocatedBytes = count(value.actualAllocatedBytes, 1), reservedBytes = count(value.reservedBytes, 1);
  const initialReserve = sum(catalog.filter(slot => slot.reserved).map(slot => rounded(slot.maximum, policy.clusterBytes)));
  if (actualAllocatedBytes % policy.clusterBytes !== 0 || reservedBytes % policy.clusterBytes !== 0 || reservedBytes > initialReserve
    || sum([actualAllocatedBytes, reservedBytes]) > policy.allocatedBytes) reject();
  const proposedAllocatedBytes = sum(parts.map(part => rounded(part.bytes, policy.clusterBytes)));
  const availableIntermediateBytes = policy.allocatedBytes - actualAllocatedBytes - reservedBytes;
  if (value.proposedAllocatedBytes !== proposedAllocatedBytes || value.availableIntermediateBytes !== availableIntermediateBytes
    || proposedAllocatedBytes <= availableIntermediateBytes) reject();
  if (observed) {
    const snapshot = validateRetainedSnapshot(observed, policy), witness = snapshot.files.find(file => file.slot === 2);
    if (!witness || witness.bytes === 0 || parts.some(part => snapshot.files.some(file => file.slot === part.slot))
      || snapshot.allocatedBytes < sum([actualAllocatedBytes, witness.allocatedBytes])
      || reservedBytes < sum([snapshot.reservedBytes, rounded(catalog[2].maximum, policy.clusterBytes)])) reject();
  }
  return { schema: 'scanmux.retained-allocation-stop/v1', jobId: policy.jobId, intentSha256: policy.intentSha256, parts,
    proposedAllocatedBytes, availableIntermediateBytes, actualAllocatedBytes, reservedBytes, allocatedLimit: policy.allocatedBytes, clusterBytes: policy.clusterBytes };
}

/** A successful peer exit alone is insufficient: match its exact transaction and counters. */
export function validateRetainedWriteResult(input: unknown, policy: RetainedPolicy, parts: readonly RetainedWritePart[]): RetainedWriteResult {
  const { selected } = describeRetainedWrite(parts, policy.maximum), catalog = policyCatalog(policy);
  const value = exact(input, ['schema', 'result', 'jobId', 'intentSha256', 'slots', 'proposedAllocatedBytes', 'availableIntermediateBytes', 'before', 'after']);
  const slots = value.slots;
  if (value.schema !== 'scanmux.retained-write-result/v1' || !['committed', 'retained_allocated_limit'].includes(String(value.result))
    || value.jobId !== policy.jobId || value.intentSha256 !== policy.intentSha256 || !Array.isArray(slots)
    || slots.length !== selected.length || selected.some((entry, index) => slots[index] !== entry.slot)) reject();
  const before = validateRetainedSnapshot(value.before, policy), after = validateRetainedSnapshot(value.after, policy);
  if (!before.files.some(file => file.slot === 0 && file.bytes > 0) || selected.some(entry => before.files.some(file => file.slot === entry.slot))) reject();
  const proposedAllocatedBytes = sum(parts.map(part => rounded(part.bytes.length, policy.clusterBytes)));
  const released = sum(selected.filter(entry => entry.reserved).map(entry => rounded(entry.maximum, policy.clusterBytes)));
  const availableIntermediateBytes = count(policy.allocatedBytes - before.allocatedBytes - (before.reservedBytes - released));
  if (value.proposedAllocatedBytes !== proposedAllocatedBytes || value.availableIntermediateBytes !== availableIntermediateBytes) reject();
  const additionSlots = value.result === 'committed' ? selected.map(entry => entry.slot) : [2];
  if (value.result === 'committed') {
    if (proposedAllocatedBytes > availableIntermediateBytes || before.files.some(file => file.slot === 2) && selected.some(entry => !entry.reserved)) reject();
    for (let index = 0; index < selected.length; index++) {
      const actual = after.files.find(file => file.slot === selected[index].slot);
      if (!actual || actual.bytes !== parts[index].bytes.length || actual.allocatedBytes !== rounded(parts[index].bytes.length, policy.clusterBytes)) reject();
    }
  } else {
    const witness = after.files.find(file => file.slot === 2);
    if (proposedAllocatedBytes <= availableIntermediateBytes || released !== 0 || before.files.some(file => file.slot === 2)
      || !witness || witness.bytes <= 0 || witness.bytes > catalog[2].maximum) reject();
  }
  if (after.files.length !== before.files.length + additionSlots.length) reject();
  for (const old of before.files) {
    const current = after.files.find(file => file.slot === old.slot);
    if (!current || current.bytes !== old.bytes || current.allocatedBytes !== old.allocatedBytes) reject();
  }
  for (const current of after.files) if (!before.files.some(old => old.slot === current.slot) && !additionSlots.includes(current.slot)) reject();
  return { schema: 'scanmux.retained-write-result/v1', result: value.result as RetainedWriteResult['result'], jobId: policy.jobId, intentSha256: policy.intentSha256,
    slots: selected.map(entry => entry.slot), proposedAllocatedBytes, availableIntermediateBytes, before, after };
}

const replyMaximum = 65536;
type RetainedOperation = '--retained-probe' | '--retained-init' | '--retained-write' | '--retained-inspect';
function nativeError(): never { throw new SafeError('retained_native_unverified'); }
function nativeExecutable(owner: Tool, directory: string) {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new SafeError('unsupported_retained_runtime');
  const local = (value: string) => typeof value === 'string' && /^[A-Za-z]:[\\/][^:]*$/.test(value) && !/[\x00-\x1f\x7f]/.test(value);
  if (owner.version !== '1.1.0' || !local(owner.path) || !local(directory) || !path.isAbsolute(directory)) reject();
  const stat = lstatSync(owner.path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || realpathSync(owner.path) !== owner.path || hash(readFileSync(owner.path)) !== owner.sha256) nativeError();
}
function remaining(deadline: () => number) {
  const milliseconds = Math.floor(deadline() - performance.now());
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 1 || milliseconds > 2147483647) throw new SafeError('retained_write_deadline');
  return milliseconds;
}
function nativeJson(stdout: Buffer, stderr: Buffer, code: number | null, signal: string | null): unknown {
  if (code !== 0 || signal !== null || stderr.length !== 0 || stdout.length === 0 || stdout.length > replyMaximum) nativeError();
  try { return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(stdout)); }
  catch { return nativeError(); }
}
async function invokeNative(owner: Tool, directory: string, operation: RetainedOperation, sha256: string | null, input: Buffer | null, deadline: () => number, signal?: AbortSignal): Promise<unknown> {
  if (signal?.aborted) throw new SafeError('retained_write_cancelled');
  nativeExecutable(owner, directory);
  const timeoutMs = remaining(deadline), args = [operation, directory, ...(sha256 === null ? [] : [sha256])];
  const child = spawn(owner.path, args, { cwd: directory, env: cleanEnvironment(directory), windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'] });
  const output: Buffer[] = [], errors: Buffer[] = []; let size = 0, invalid = false, cancelled = false;
  const stop = () => { cancelled = true; child.kill(); };
  const timer = setTimeout(() => { invalid = true; child.kill(); }, timeoutMs);
  signal?.addEventListener('abort', stop, { once: true });
  child.once('error', () => { invalid = true; }); child.stdin.on('error', () => { invalid = true; child.kill(); });
  for (const [stream, parts] of [[child.stdout, output], [child.stderr, errors]] as const) {
    stream.on('data', (bytes: Buffer) => { size += bytes.length; if (size > replyMaximum) { invalid = true; child.kill(); } else parts.push(Buffer.from(bytes)); });
    stream.on('error', () => { invalid = true; child.kill(); });
  }
  child.stdin.end(input ?? undefined); if (signal?.aborted) stop();
  return new Promise((resolve, rejectPromise) => child.once('close', (code, terminationSignal) => {
    clearTimeout(timer); signal?.removeEventListener('abort', stop);
    try {
      if (cancelled) throw new SafeError('retained_write_cancelled');
      if (invalid || performance.now() >= deadline()) nativeError();
      resolve(nativeJson(Buffer.concat(output), Buffer.concat(errors), code, terminationSignal));
    } catch (error) { rejectPromise(error); }
  }));
}
function invokeNativeSync(owner: Tool, directory: string, operation: '--retained-write', sha256: string, input: Buffer, deadline: () => number): unknown {
  nativeExecutable(owner, directory);
  const result = spawnSync(owner.path, [operation, directory, sha256], { cwd: directory, env: cleanEnvironment(directory), windowsHide: true, shell: false,
    input, timeout: remaining(deadline), maxBuffer: replyMaximum, stdio: ['pipe', 'pipe', 'pipe'] });
  if (result.error || performance.now() >= deadline()) nativeError();
  return nativeJson(result.stdout ?? Buffer.alloc(0), result.stderr ?? Buffer.alloc(0), result.status, result.signal);
}

export async function probeRetainedVolume(owner: Tool, directory: string, deadline: () => number, signal?: AbortSignal) {
  const value = exact(await invokeNative(owner, directory, '--retained-probe', null, null, deadline, signal), ['schema', 'fileSystem', 'clusterBytes']);
  if (value.schema !== 'scanmux.retained-volume/v1' || value.fileSystem !== 'NTFS') reject();
  return { fileSystem: 'NTFS' as const, clusterBytes: count(value.clusterBytes, 1) };
}
export function retainedPolicy(intent: HostJobIntent, intentSha256: string): RetainedPolicy {
  if (intent.schema !== 'scanmux.host-job-intent/v2' || intent.host.owner.version !== '1.1.0') reject();
  const policy = { jobId: intent.jobId, intentSha256, maximum: intent.offline.scan.maxOutputBytes,
    allocatedBytes: intent.storage.allocatedBytes, clusterBytes: intent.storage.clusterBytes };
  policyCatalog(policy); return policy;
}
export async function initializeRetainedStore(intent: HostJobIntent, raw: Buffer, deadline: () => number, signal?: AbortSignal): Promise<RetainedSnapshot> {
  const sha = hash(raw), policy = retainedPolicy(intent, sha), catalog = policyCatalog(policy);
  if (raw.length === 0 || raw.length > catalog[0].maximum) reject();
  const value = exact(await invokeNative(intent.host.owner, intent.directory, '--retained-init', sha, raw, deadline, signal),
    ['schema', 'result', 'jobId', 'intentSha256', 'slots', 'proposedAllocatedBytes', 'availableIntermediateBytes', 'before', 'after']);
  if (value.schema !== 'scanmux.retained-write-result/v1' || value.result !== 'committed' || value.jobId !== policy.jobId || value.intentSha256 !== sha
    || !Array.isArray(value.slots) || value.slots.length !== 1 || value.slots[0] !== 0) reject();
  const before = validateRetainedSnapshot(value.before, policy), after = validateRetainedSnapshot(value.after, policy);
  const proposed = rounded(raw.length, policy.clusterBytes), released = rounded(catalog[0].maximum, policy.clusterBytes);
  if (before.files.length !== 0 || after.files.length !== 1 || after.files[0].slot !== 0 || after.files[0].bytes !== raw.length
    || value.proposedAllocatedBytes !== proposed || value.availableIntermediateBytes !== policy.allocatedBytes - (before.reservedBytes - released)
    || after.allocatedBytes !== proposed || after.reservedBytes !== before.reservedBytes - released) reject();
  return after;
}
export function createRetainedClient(intent: HostJobIntent, intentSha256: string, deadline: () => number, signal?: AbortSignal) {
  const policy = retainedPolicy(intent, intentSha256), owner = { ...intent.host.owner }, directory = intent.directory;
  return Object.freeze({ policy: Object.freeze({ ...policy }),
    async write(parts: readonly RetainedWritePart[]) {
      const input = encodeRetainedWrite(parts, policy.maximum);
      return validateRetainedWriteResult(await invokeNative(owner, directory, '--retained-write', intentSha256, input, deadline, signal), policy, parts);
    },
    writeSync(parts: readonly RetainedWritePart[]) {
      if (signal?.aborted) throw new SafeError('retained_write_cancelled');
      const input = encodeRetainedWrite(parts, policy.maximum);
      return validateRetainedWriteResult(invokeNativeSync(owner, directory, '--retained-write', intentSha256, input, deadline), policy, parts);
    },
    async inspect() {
      const value = exact(await invokeNative(owner, directory, '--retained-inspect', intentSha256, null, deadline, signal), ['schema', 'jobId', 'intentSha256', 'snapshot']);
      if (value.schema !== 'scanmux.retained-inspection/v1' || value.jobId !== policy.jobId || value.intentSha256 !== intentSha256) reject();
      return validateRetainedSnapshot(value.snapshot, policy);
    },
  });
}
export type RetainedClient = ReturnType<typeof createRetainedClient>;
