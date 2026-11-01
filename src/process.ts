import { scopedJobDisk, type JobDiskCause } from './job-disk.ts';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { SafeError } from './safety.ts';
import { scopedProcessOwner, stopBudgetCeilingMs, verifiedImage } from './process-tree.ts';
import type { Tool } from './model.ts';

export interface ProcessResult { code: number | null; stdout: Buffer; stderr?: Buffer; diagnostics?: string[]; jobDiskStopped?: true; reason: JobDiskCause | 'exit' | 'spawn_failed' | 'cancelled' | 'timeout' | 'output_limit' | 'termination_unverified'; }
export const jobDiskDiagnostic = (result: ProcessResult): JobDiskCause | undefined => result.diagnostics?.find(
  (code): code is JobDiskCause => code === 'job_disk_measured_limit' || code === 'job_disk_observation_unverified');
type ExecuteOptions = {
  cwd: string; home: string; timeoutMs: number; maxOutputBytes: number; signal?: AbortSignal; target?: string;
  input?: string; database?: string; startSignal?: AbortSignal; deadlineAt?: number; onSpawn?: (pid: number) => void; environment?: Readonly<Record<string, string>>;
  appContainer?: { snapshot: string; work: string }; captureStderr?: boolean;
};
// kill(-pgid, 0) is one system call; polling at 10 ms keeps the confirmation delay within 0.2% of the stop budget.
const groupPollMs = 10;
const stderrPatterns = [
  [/no offline version of the OSV database/, 'offline_database_unavailable'],
  [/Access is denied|permission denied/i, 'scanner_permission_denied'],
  [/unknown flag|flag provided but not defined/, 'scanner_argument_rejected'],
  [/Error during extraction/, 'scanner_extraction_failed'],
  [/invalid character|invalid JSON|unexpected end/i, 'scanner_input_invalid'],
] as const;
const diagnose = (stderr: Buffer, into: Set<string>) => { const text = stderr.toString('utf8'); for (const [pattern, code] of stderrPatterns) if (pattern.test(text)) into.add(code); };

export function cleanEnvironment(home: string): NodeJS.ProcessEnv {
  return {
    SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR,
    HOME: home, USERPROFILE: home, TMP: home, TEMP: home, TMPDIR: home,
    XDG_CONFIG_HOME: home, XDG_CACHE_HOME: home, LOCALAPPDATA: home, APPDATA: home,
    LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', NO_COLOR: '1',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(home, 'empty-gitconfig'),
    GIT_NO_LAZY_FETCH: '1', GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0', GIT_ATTR_NOSYSTEM: '1',
  };
}
const environment = (options: ExecuteOptions): NodeJS.ProcessEnv =>
  ({ ...cleanEnvironment(options.home), ...(options.database ? { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: options.database } : {}), ...options.environment });
export async function verifyTool(tool: Tool, target?: string): Promise<void> { await verifiedImage(tool, target); }
export async function verifyVersion(tool: Tool, args: string[], options: ExecuteOptions, run: typeof execute = execute): Promise<void> {
  const result = await run(tool, args, options);
  if (result.reason !== 'exit') throw new SafeError(result.reason);
  const versions: string[] = result.stdout.toString('utf8').match(/\b\d+\.\d+\.\d+\b/g) ?? [];
  if (result.reason !== 'exit' || result.code !== 0 || !versions.includes(tool.version)) throw new SafeError('tool_version_mismatch');
  const diskCause = jobDiskDiagnostic(result);
  if (diskCause) throw new SafeError(diskCause);
}
const notStarted = (reason: 'cancelled' | 'spawn_failed', diagnostics: string[] = []): ProcessResult => ({ code: null, stdout: Buffer.alloc(0), diagnostics, reason });
async function executeContained(tool: Tool, args: string[], options: ExecuteOptions): Promise<ProcessResult> {
  if (options.appContainer && process.platform !== 'win32') return notStarted('spawn_failed', ['process_appcontainer_unsupported_platform']);
  await verifyTool(tool, options.target);
  if (options.signal?.aborted || options.startSignal?.aborted) return notStarted('cancelled');
  if (process.platform !== 'win32') return spawnDirect(tool, args, options);
  const owner = scopedProcessOwner();
  if (!owner) return notStarted('spawn_failed', [options.appContainer ? 'process_appcontainer_owner_unavailable' : 'process_containment_unavailable']);
  const result = await owner.runContained({
    executable: tool, args, cwd: options.cwd, environment: environment(options) as Record<string, string>, input: options.input,
    maxOutputBytes: options.maxOutputBytes, timeoutMs: options.timeoutMs, stopBudgetMs: stopBudgetCeilingMs, signal: options.signal, onSpawn: options.onSpawn,
    ...(options.appContainer ? { appContainer: options.appContainer } : {}),
  });
  const diagnostics = new Set(result.diagnostics);
  diagnose(result.stderr, diagnostics);
  return { code: result.code, stdout: result.stdout, ...(options.captureStderr ? { stderr: result.stderr } : {}), diagnostics: [...diagnostics], reason: result.reason };
}
async function observed(tool: Tool, args: string[], options: ExecuteOptions, run: typeof executeContained): Promise<ProcessResult> {
  const disk = scopedJobDisk();
  if (!disk?.active) return run(tool, args, options);
  const signal = AbortSignal.any([...(options.signal ? [options.signal] : []), disk.signal]);
  if ((signal.aborted && signal.reason !== disk.signal.reason) || options.startSignal?.aborted) return run(tool, args, options);
  try { await disk.check(); }
  catch (error) {
    if (signal.aborted && signal.reason !== disk.signal.reason) return run(tool, args, { ...options, signal });
    throw error;
  }
  const finish = disk.watch();
  let result: ProcessResult;
  try { result = await run(tool, args, { ...options, signal }); }
  finally { await finish(); }
  // Containment, output and process errors retain precedence over the disk stop.
  if (disk.cause && signal.reason === disk.signal.reason) {
    if (result.reason === 'cancelled') return { ...result, reason: disk.cause, jobDiskStopped: true };
    // A completed engine still owns its output, including findings and parse errors.
    if (result.reason === 'exit') return { ...result, diagnostics: [...(result.diagnostics ?? []), disk.cause] };
  }
  return result;
}
export const execute = (tool: Tool, args: string[], options: ExecuteOptions): Promise<ProcessResult> => observed(tool, args, options, executeContained);
/** Only the publisher verifier before admission and the host job owner check start here; on Windows their stop is never verified. */
async function executeUncontained(tool: Tool, args: string[], options: ExecuteOptions): Promise<ProcessResult> {
  if (options.appContainer) return notStarted('spawn_failed', ['process_appcontainer_owner_unavailable']);
  await verifyTool(tool, options.target);
  if (options.signal?.aborted || options.startSignal?.aborted) return notStarted('cancelled');
  if (options.deadlineAt !== undefined) {
    const timeoutMs = Math.min(options.timeoutMs, options.deadlineAt - performance.now());
    if (timeoutMs <= 0) throw new SafeError('process_start_deadline');
    options = { ...options, timeoutMs };
  }
  return spawnDirect(tool, args, options);
}
export const executeDirect = (tool: Tool, args: string[], options: ExecuteOptions): Promise<ProcessResult> => observed(tool, args, options, executeUncontained);
async function groupGone(pid: number, deadline: number): Promise<boolean> {
  for (;;) {
    try { process.kill(-pid, 0); } catch (error) { return (error as NodeJS.ErrnoException).code === 'ESRCH'; }
    if (performance.now() >= deadline) return false;
    await delay(groupPollMs);
  }
}
function spawnDirect(tool: Tool, args: string[], options: ExecuteOptions): Promise<ProcessResult> {
  const disk = scopedJobDisk();
  return new Promise(resolve => {
    const child = spawn(tool.path, args, {
      cwd: options.cwd, env: environment(options), shell: false, windowsHide: true,
      detached: process.platform !== 'win32', stdio: ['pipe', 'pipe', 'pipe'],
    });
    if (child.pid && options.onSpawn) { try { options.onSpawn(child.pid); } catch { /* Observation cannot change process ownership. */ } }
    child.stdin.on('error', () => {});
    child.stdin.end(options.input);
    let reason: ProcessResult['reason'] = 'exit';
    let jobDiskStopped = false;
    let stoppedTree: Promise<boolean> | undefined;
    let size = 0;
    const chunks: Buffer[] = [];
    const stderr: Buffer[] = [];
    const diagnostics = new Set<string>();
    const stop = (why: ProcessResult['reason']) => {
      if (reason !== 'exit') return;
      if (why === 'cancelled' && disk?.signal.aborted && options.signal?.reason === disk.signal.reason) jobDiskStopped = true;
      reason = why;
      const pid = child.pid;
      if (!pid) return;
      if (process.platform === 'win32') { child.kill(); stoppedTree = Promise.resolve(false); return; }
      const deadline = performance.now() + stopBudgetCeilingMs;
      try { process.kill(-pid, 'SIGKILL'); stoppedTree = groupGone(pid, deadline); }
      catch (error) { stoppedTree = Promise.resolve((error as NodeJS.ErrnoException).code === 'ESRCH'); }
    };
    const receive = (buffer: Buffer, keep: boolean) => {
      size += buffer.length;
      if (size > options.maxOutputBytes) { stop('output_limit'); return; }
      if (keep) chunks.push(buffer); else { diagnose(buffer, diagnostics); if (options.captureStderr) stderr.push(buffer); }
    };
    child.stdout.on('data', b => receive(b, true));
    child.stderr.on('data', b => receive(b, false));
    const abort = () => stop('cancelled');
    const timer = setTimeout(() => stop('timeout'), options.timeoutMs);
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();
    child.on('error', () => { reason = 'spawn_failed'; });
    child.on('close', async code => {
      clearTimeout(timer); options.signal?.removeEventListener('abort', abort);
      if (stoppedTree && !await stoppedTree) reason = 'termination_unverified';
      resolve({ code: reason === 'termination_unverified' ? null : code, stdout: Buffer.concat(chunks), ...(options.captureStderr ? { stderr: Buffer.concat(stderr) } : {}), diagnostics: [...diagnostics], ...(jobDiskStopped ? { jobDiskStopped: true as const } : {}), reason });
    });
  });
}
