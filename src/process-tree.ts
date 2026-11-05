import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { privateWorkspace } from './private-storage.ts';
import { canonical, hash, SafeError, within } from './safety.ts';
import type { Tool } from './model.ts';
import type { ProcessResult } from './process.ts';
import { releaseJobDiskRoot } from './job-disk.ts';
import { scopedCopyBudget } from './copy-budget.ts';
import { sourceCleanupFor } from './source-cleanup.ts';

// A stop is confirmed within 5000 ms or reported as unverified.
export const stopBudgetCeilingMs = 5000;
const maxRequestBodyBytes = 16 * 1024 * 1024;
const maxEventBodyBytes = 65536;
const prefixBytes = 5;

const kind = { ready: 1, start: 2, stop: 3, spawned: 4, out: 5, err: 6, result: 7, input: 8, eof: 9, recovery: 10 } as const;
interface Frame { kind: number; id: number; body: Buffer }

export function encodeFrame(type: number, id: number, body: Uint8Array): Buffer {
  const frame = Buffer.allocUnsafe(4 + prefixBytes + body.length);
  frame.writeUInt32LE(prefixBytes + body.length, 0);
  frame.writeUInt8(type, 4);
  frame.writeUInt32LE(id, 5);
  frame.set(body, 9);
  return frame;
}

export class FrameDecoder {
  #pending = Buffer.alloc(0);
  #maxBodyBytes: number;
  constructor(maxBodyBytes: number) { this.#maxBodyBytes = maxBodyBytes; }
  push(chunk: Buffer): Frame[] {
    let buffer = this.#pending.length ? Buffer.concat([this.#pending, chunk]) : chunk;
    const frames: Frame[] = [];
    while (buffer.length >= 4) {
      const length = buffer.readUInt32LE(0);
      if (length < prefixBytes || length > prefixBytes + this.#maxBodyBytes) throw new SafeError('process_owner_frame_invalid');
      if (buffer.length < 4 + length) break;
      frames.push({ kind: buffer.readUInt8(4), id: buffer.readUInt32LE(5), body: Buffer.from(buffer.subarray(9, 4 + length)) });
      buffer = buffer.subarray(4 + length);
    }
    this.#pending = Buffer.from(buffer);
    return frames;
  }
  end(): void { if (this.#pending.length) throw new SafeError('process_owner_frame_truncated'); }
}

const helperReasons = ['exit', 'cancelled', 'timeout', 'output_limit', 'spawn_failed', 'termination_unverified'] as const;
type HelperReason = typeof helperReasons[number];
export type OwnerEvent =
  | { type: 'ready'; version: string }
  | { type: 'recovery'; recovery: OwnerRecovery }
  | { type: 'spawned'; id: number; pid: number }
  | { type: 'out' | 'err'; id: number; bytes: Buffer }
  | { type: 'result'; id: number; reason: HelperReason; code: number | null; operation: string | null };

function json(body: Buffer): Record<string, unknown> {
  const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new SafeError('process_owner_frame_invalid');
  return value as Record<string, unknown>;
}
const uint32 = (value: unknown): value is number => Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 0xffffffff;

export function parseEvent(frame: Frame): OwnerEvent {
  if (frame.kind === kind.ready && frame.id === 0) return { type: 'ready', version: frame.body.toString('ascii') };
  if (frame.kind === kind.recovery && frame.id === 0) {
    const value = json(frame.body);
    if (!uint32(value.recovered) || !uint32(value.kept) || !Array.isArray(value.codes)
      || !value.codes.every(code => typeof code === 'string' && /^appcontainer_[a-z_]{1,64}$/.test(code))) throw new SafeError('process_owner_frame_invalid');
    return { type: 'recovery', recovery: { recovered: value.recovered, kept: value.kept, codes: value.codes.map(code => `process_owner_${code}`) } };
  }
  if (frame.id === 0) throw new SafeError('process_owner_frame_invalid');
  if (frame.kind === kind.out || frame.kind === kind.err) return { type: frame.kind === kind.out ? 'out' : 'err', id: frame.id, bytes: frame.body };
  if (frame.kind === kind.spawned) {
    const value = json(frame.body);
    if (!uint32(value.pid) || value.pid === 0 || typeof value.creationTime !== 'string') throw new SafeError('process_owner_frame_invalid');
    return { type: 'spawned', id: frame.id, pid: value.pid };
  }
  if (frame.kind === kind.result) {
    const value = json(frame.body);
    const reason = helperReasons.find(item => item === value.reason);
    const operation = value.operation === null ? null : typeof value.operation === 'string' && /^[a-z_]{1,64}$/.test(value.operation) ? value.operation : undefined;
    const code = value.code === null ? null : uint32(value.code) ? value.code : undefined;
    const settled = reason === 'exit' || reason === 'cancelled' || reason === 'timeout' || reason === 'output_limit';
    if (!reason || operation === undefined || code === undefined || settled !== (code !== null)) throw new SafeError('process_owner_frame_invalid');
    return { type: 'result', id: frame.id, reason, code, operation };
  }
  throw new SafeError('process_owner_frame_invalid');
}

// One request moves started -> spawned -> finished; a result may also end a request that never spawned.
export type RequestPhase = 'started' | 'spawned' | 'finished';
export function nextPhase(phase: RequestPhase | undefined, event: Exclude<OwnerEvent, { type: 'ready' | 'recovery' }>): RequestPhase {
  if (!phase) throw new SafeError('process_owner_unknown_request');
  if (phase === 'finished') throw new SafeError('process_owner_event_after_result');
  if (event.type === 'spawned') { if (phase !== 'started') throw new SafeError('process_owner_duplicate_spawn'); return 'spawned'; }
  if (event.type === 'result') return 'finished';
  if (phase !== 'spawned') throw new SafeError('process_owner_output_before_spawn');
  return phase;
}

export interface ContainedRequest {
  executable: Tool; args: string[]; cwd: string; environment: Readonly<Record<string, string>>; input?: string;
  maxOutputBytes: number; timeoutMs: number; stopBudgetMs: number; signal?: AbortSignal; onSpawn?: (pid: number) => void;
  appContainer?: { snapshot: string; work: string };
}
export interface ContainedResult { reason: ProcessResult['reason']; code: number | null; stdout: Buffer; stderr: Buffer; diagnostics: string[] }
/** Leftovers of dead owners that this owner reclaimed or had to keep; codes are process_owner_appcontainer_*. */
export interface OwnerRecovery { recovered: number; kept: number; codes: string[] }
export interface ProcessOwner {
  readonly workspace?: string;
  readonly version: string;
  /** Settles once with the owner's reclaim result, or undefined if the owner ended before reporting one. */
  readonly recovery: Promise<OwnerRecovery | undefined>;
  readonly pid: number; runContained(request: ContainedRequest): Promise<ContainedResult>; close(): Promise<void>;
  openRequests(): number;
}

interface Pending {
  phase: RequestPhase; stdout: Buffer[]; stderr: Buffer[]; size: number; max: number; cause?: 'cancelled' | 'output_limit'; stopDeadline: number;
  onSpawn?: (pid: number) => void; stop: (cause: 'cancelled' | 'output_limit') => void;
  settle: (reason: ProcessResult['reason'], code: number | null, diagnostics: string[]) => void;
}

// Node runs a longer setTimeout after 1 ms, so a far deadline is reached through waits no longer than this.
const maxTimerMs = 2 ** 31 - 1;
function deadlineAt(at: number, fire: () => void): { cancel: () => void } {
  let timer: NodeJS.Timeout | undefined;
  const wait = () => { const left = at - performance.now(); if (left <= 0) fire(); else timer = setTimeout(wait, Math.min(left, maxTimerMs)); };
  wait();
  return { cancel: () => clearTimeout(timer) };
}

export async function verifiedImage(tool: Tool, target?: string): Promise<Buffer> {
  const executable = await canonical(tool.path);
  if (target && within(target, executable)) throw new SafeError('tool_inside_target');
  if (!['.exe', ''].includes(path.extname(executable).toLowerCase()) && process.platform === 'win32') throw new SafeError('native_executable_required');
  const bytes = await readFile(executable);
  if (hash(bytes) !== tool.sha256) throw new SafeError('tool_digest_mismatch');
  return bytes;
}

export async function startProcessOwner(helper: Tool, readyTimeoutMs: number, image?: Buffer): Promise<ProcessOwner> {
  if (process.platform !== 'win32') throw new SafeError('process_containment_unavailable');
  const bytes = image ?? await verifiedImage(helper);
  const workspace = await privateWorkspace(undefined, { disposable: true });
  const cleanup = sourceCleanupFor(workspace); cleanup.register(workspace, workspace);
  const copy = path.join(workspace, 'scanmux-windows-process-owner.exe');
  const removeCopy = async () => { releaseJobDiskRoot(workspace); await cleanup.cleanup(workspace); };
  try {
    const budget = scopedCopyBudget();
    if (budget) {
      const copied = await budget.copy(helper.path, copy, { maximumBytes: bytes.length, sourceChangedCode: 'tool_digest_mismatch' });
      if (copied.sha256 !== helper.sha256) throw new SafeError('tool_digest_mismatch');
    } else await writeFile(copy, bytes, { flag: 'wx' });
  } catch (error) { await removeCopy(); throw error; }
  const child = spawn(copy, [], { stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR } });
  const decoder = new FrameDecoder(maxEventBodyBytes);
  const requests = new Map<number, Pending>();
  const abandoned = new Set<number>();
  let state: 'starting' | 'ready' | 'closing' | 'lost' = 'starting';
  let nextId = 1;
  let announce: (version: string | Error) => void = () => {};
  const announced = new Promise<string | Error>(resolve => { announce = resolve; });
  let report: (recovery: OwnerRecovery | undefined) => void = () => {};
  const recovery = new Promise<OwnerRecovery | undefined>(resolve => { report = resolve; });
  const exited = new Promise<void>(resolve => { child.once('exit', () => resolve()); child.once('error', () => { if (child.pid === undefined) resolve(); }); });

  const lose = () => {
    if (state === 'lost') return;
    state = 'lost';
    child.kill();
    announce(new SafeError('process_owner_unavailable'));
    report(undefined);
    for (const pending of requests.values()) pending.settle('termination_unverified', null, ['process_owner_lost']);
    abandoned.clear();
  };
  const send = (frame: Buffer) => { if (state === 'ready') child.stdin.write(frame); };
  const receive = (event: OwnerEvent) => {
    if (event.type === 'ready') {
      if (state !== 'starting') throw new SafeError('process_owner_frame_invalid');
      announce(event.version);
      return;
    }
    if (event.type === 'recovery') { report(event.recovery); return; }
    if (abandoned.has(event.id)) { if (event.type === 'result') abandoned.delete(event.id); return; }
    const pending = requests.get(event.id);
    const phase = nextPhase(pending?.phase, event);
    if (!pending) return;
    pending.phase = phase;
    if (event.type === 'spawned') { try { pending.onSpawn?.(event.pid); } catch { /* Observation cannot change process ownership. */ } }
    else if (event.type === 'result') {
      if (performance.now() >= pending.stopDeadline) { pending.settle('termination_unverified', null, ['process_owner_stop_budget']); return; }
      const reason = event.reason === 'exit' && pending.cause ? pending.cause : event.reason;
      pending.settle(reason, event.code, event.operation ? [`process_owner_${event.operation}`] : []);
    } else {
      pending.size += event.bytes.length;
      if (pending.size > pending.max) pending.stop('output_limit');
      else (event.type === 'out' ? pending.stdout : pending.stderr).push(event.bytes);
    }
  };
  child.stdout.on('data', (chunk: Buffer) => {
    if (state === 'lost') return;
    try { for (const frame of decoder.push(chunk)) receive(parseEvent(frame)); } catch { lose(); }
  });
  child.stdout.once('end', () => { try { decoder.end(); } catch { /* lose() below reports every open request. */ } lose(); });
  child.once('exit', lose);
  child.once('error', lose);
  child.stdin.on('error', lose);

  const version = await Promise.race([announced, new Promise<Error>(resolve => setTimeout(() => resolve(new SafeError('process_owner_start_timeout')), readyTimeoutMs).unref())]);
  if (version instanceof Error || version !== helper.version) { lose(); await exited; await removeCopy(); throw version instanceof Error ? version : new SafeError('tool_version_mismatch'); }
  state = 'ready';

  const runContained = (request: ContainedRequest): Promise<ContainedResult> => {
    const empty = { stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) };
    if (state !== 'ready') return Promise.resolve({ reason: 'spawn_failed', code: null, ...empty, diagnostics: ['process_containment_unavailable'] });
    if (request.appContainer && version !== '1.4.0') return Promise.resolve({ reason: 'spawn_failed', code: null, ...empty, diagnostics: ['process_appcontainer_owner_version_unsupported'] });
    if (request.signal?.aborted) return Promise.resolve({ reason: 'cancelled', code: null, ...empty, diagnostics: [] });
    const stopBudgetMs = Math.min(request.stopBudgetMs, stopBudgetCeilingMs);
    const body = Buffer.from(JSON.stringify({
      path: request.executable.path, sha256: request.executable.sha256, args: request.args, cwd: request.cwd, env: request.environment,
      maxOutputBytes: request.maxOutputBytes, deadlineMs: request.timeoutMs, stopBudgetMs,
      ...(request.appContainer ? { appContainer: request.appContainer } : {}),
    }));
    if (body.length > maxRequestBodyBytes) return Promise.resolve({ reason: 'spawn_failed', code: null, ...empty, diagnostics: ['process_owner_request_too_large'] });
    const id = nextId++;
    return new Promise(resolve => {
      const abort = () => pending.stop('cancelled');
      const expire = () => { abandoned.add(id); pending.settle('termination_unverified', null, ['process_owner_stop_budget']); };
      const pending: Pending = {
        phase: 'started', stdout: [], stderr: [], size: 0, max: request.maxOutputBytes, onSpawn: request.onSpawn,
        stopDeadline: performance.now() + request.timeoutMs + stopBudgetMs,
        stop: cause => {
          if (pending.cause) return;
          pending.cause = cause;
          send(encodeFrame(kind.stop, id, Buffer.from(cause)));
          const at = performance.now() + stopBudgetMs;
          if (at < pending.stopDeadline) { pending.stopDeadline = at; expiry.cancel(); expiry = deadlineAt(at, expire); }
        },
        settle: (reason, code, diagnostics) => {
          requests.delete(id);
          expiry.cancel();
          request.signal?.removeEventListener('abort', abort);
          resolve({ reason, code: reason === 'termination_unverified' || reason === 'spawn_failed' ? null : code, stdout: Buffer.concat(pending.stdout), stderr: Buffer.concat(pending.stderr), diagnostics });
        },
      };
      let expiry = deadlineAt(pending.stopDeadline, expire);
      requests.set(id, pending);
      send(encodeFrame(kind.start, id, body));
      const input = Buffer.from(request.input ?? '');
      for (let offset = 0; offset < input.length; offset += maxEventBodyBytes) send(encodeFrame(kind.input, id, input.subarray(offset, offset + maxEventBodyBytes)));
      send(encodeFrame(kind.eof, id, Buffer.alloc(0)));
      request.signal?.addEventListener('abort', abort, { once: true });
    });
  };
  const close = async () => {
    let timer: NodeJS.Timeout | undefined;
    if (state !== 'lost') {
      state = 'closing';
      child.stdin.end();
      timer = setTimeout(() => child.kill(), stopBudgetCeilingMs);
    }
    await exited;
    clearTimeout(timer);
    await removeCopy();
  };
  return { workspace, pid: child.pid ?? 0, version, recovery, runContained, close, openRequests: () => requests.size + abandoned.size };
}

export interface ProcessRuntimeProfile { readonly helper: Tool | undefined; readonly timeoutMs: number }
const scope = new AsyncLocalStorage<ProcessOwner>();
export const scopedProcessOwner = (): ProcessOwner | undefined => scope.getStore();

export interface RuntimeAdmission { readonly decide: () => void; readonly verify: () => Promise<void> }

/** On Windows the refusals come in order: the policy decision, the helper, then the checks that start processes. Elsewhere only verify runs. */
export async function withProcessRuntime<T>(profile: ProcessRuntimeProfile, admission: RuntimeAdmission, body: () => Promise<T>): Promise<T> {
  if (process.platform !== 'win32') { await admission.verify(); return body(); }
  admission.decide();
  const { helper } = profile;
  if (!helper) throw new SafeError('process_containment_unavailable');
  const image = await verifiedImage(helper);
  await admission.verify();
  // Starting the helper is one process start, so it gets the bound of every configured process.
  const owner = await startProcessOwner(helper, profile.timeoutMs, image);
  try { return await scope.run(owner, body); }
  finally {
    await owner.close();
    // Reclaimed leftovers need no attention; leftovers the owner had to keep are reported once, outside any result.
    const reclaim = await owner.recovery;
    if (reclaim?.codes.length) process.stderr.write(`ScanMux: AppContainer recovery reported ${reclaim.codes.join(', ')}; earlier leftovers kept: ${reclaim.kept}\n`);
  }
}
