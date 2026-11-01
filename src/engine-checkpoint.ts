import path from 'node:path';
import { lstat, mkdir, open } from 'node:fs/promises';
import type { Config, Report } from './model.ts';
import { checkedText } from './output.ts';
import { summarizeHistory } from './history.ts';
import { loadConfig } from './config.ts';
import { array, boundedRead, canonical, digest, hash, outside, record, SafeError } from './safety.ts';
import { legacyEngines, requiredEngines, trivyEngines, verifyEngineCatalog } from './engine-catalog.ts';

const provisional = 'controller_completion_unverified';
interface Checkpoint {
  schema: 'scanmux.engine-checkpoint/v1' | 'scanmux.engine-checkpoint/v2'; runId: string; sequence: number;
  planHash: string; previousSha256: string | null; report: Report;
}
interface Commit {
  schema: 'scanmux.engine-checkpoint-commit/v1' | 'scanmux.engine-checkpoint-commit/v2'; runId: string; sequence: number;
  bytes: number; sha256: string; previousSha256: string | null;
}
export type CheckpointFailure = 'engine_execution_failed' | 'controller_integrity_failure' | 'checkpoint_output_rejected';
export interface EngineCheckpointBackend {
  failure(code: CheckpointFailure, signal: AbortSignal): Promise<void>;
  persist(body: Buffer, receipt: Buffer, signal: AbortSignal): Promise<void>;
}
// A runtime-owned admission refusal is distinct from a filesystem/checkpoint failure.
export class CheckpointOwnerStop extends SafeError {
  constructor(code: 'job_retained_limit' | 'job_deadline' | 'job_cancelled') { super(code); }
}
export interface VerifiedCheckpointPair { checkpoint: Checkpoint; sha256: string }
function reject(): never { throw new SafeError('invalid_engine_checkpoint'); }
function exact(input: unknown, keys: string[]): Record<string, unknown> {
  const value = record(input);
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) reject();
  return value;
}
function parse(bytes: Buffer): unknown { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
function bodyName(sequence: number) { return `checkpoint-${sequence}.json`; }
function commitName(sequence: number) { return `commit-${sequence}.json`; }
async function plainDirectory(directory: string): Promise<string> {
  if (!path.isAbsolute(directory)) reject();
  const physical = await canonical(directory);
  if (!(await lstat(physical)).isDirectory()) reject();
  return physical;
}
async function readOptional(file: string, maximum: number): Promise<Buffer | null> {
  const stat = await lstat(file).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (!stat) return null;
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maximum) reject();
  if (await canonical(file) !== file) reject();
  return boundedRead(file, maximum);
}
async function durableWrite(file: string, text: string): Promise<void> {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(text, 'utf8'); await handle.sync(); }
  finally { await handle.close(); }
}
function validateCheckpoint(input: unknown, sequence: number, previous: Checkpoint | null, previousSha256: string | null): Checkpoint {
  const value = exact(input, ['schema', 'runId', 'sequence', 'planHash', 'previousSha256', 'report']);
  const report = record(value.report), plan = record(report.plan), runs = array(report.engines).map(record);
  const engines = plan.schema === 'scanmux.plan/v3' ? requiredEngines(plan.schema) : legacyEngines;
  if (plan.schema === 'scanmux.plan/v3') verifyEngineCatalog(plan);
  if (value.schema !== (plan.schema === 'scanmux.plan/v3' ? 'scanmux.engine-checkpoint/v2' : 'scanmux.engine-checkpoint/v1') || value.sequence !== sequence || value.previousSha256 !== previousSha256
    || value.runId !== report.runId || value.planHash !== plan.planHash || plan.planHash !== digest({ ...plan, planHash: '' })
    || digest(plan.required) !== digest(engines) || runs.length !== sequence || runs.some((run, index) => run.engine !== engines[index])
    || report.executionState !== 'failed' || report.coverageState !== 'incomplete' || report.gate !== 'ERROR' || report.exitCode !== 4
    || !array(report.integrityErrors).includes(provisional) || !array(report.reasons).includes(provisional)) reject();
  const summary = summarizeHistory([Buffer.from(JSON.stringify(report), 'utf8')]).summary.runs[0];
  if (summary.completion !== 'incomplete' || summary.repoId !== hash(String(plan.root))) reject();
  if (previous && (value.runId !== previous.runId || digest(plan) !== digest(previous.report.plan)
    || report.startedAt !== previous.report.startedAt
    || runs.slice(0, sequence - 1).some((run, index) => digest(run) !== digest(previous.report.engines[index]))
    || previous.report.integrityErrors.some(code => !array(report.integrityErrors).includes(code)))) reject();
  return value as unknown as Checkpoint;
}

/** Shared by native recovery and the outside owner; readable bytes alone do not prove ACK. */
export function validateCheckpointPair(body: Buffer, raw: Buffer, sequence: number, previous: VerifiedCheckpointPair | null): VerifiedCheckpointPair {
  const previousSha256 = previous?.sha256 ?? null;
  const receipt = exact(parse(raw), ['schema', 'runId', 'sequence', 'bytes', 'sha256', 'previousSha256']);
  const trivy = receipt.schema === 'scanmux.engine-checkpoint-commit/v2';
  const engines = trivy ? trivyEngines : legacyEngines;
  if (raw.at(-1) !== 10 || sequence < 1 || sequence > engines.length
    || (!trivy && receipt.schema !== 'scanmux.engine-checkpoint-commit/v1') || receipt.sequence !== sequence || receipt.bytes !== body.length
    || receipt.sha256 !== hash(body) || receipt.previousSha256 !== previousSha256) reject();
  let parsed: unknown;
  try { parsed = parse(body); }
  catch (error) { if (trivy) reject(); throw error; }
  const plan = record(record(record(parsed).report).plan);
  if (trivy !== (plan.schema === 'scanmux.plan/v3')) reject();
  const checkpoint = validateCheckpoint(parsed, sequence, previous?.checkpoint ?? null, previousSha256);
  if (receipt.runId !== checkpoint.runId) reject();
  return { checkpoint, sha256: hash(body) };
}

// The private run directory has one writer. All positions are literal catalog slots.
export async function openEngineCheckpoints(workspace: string, config: Config, backend?: EngineCheckpointBackend) {
  const parent = await plainDirectory(workspace), directory = path.join(parent, 'checkpoints');
  if (!backend) await mkdir(directory, { mode: 0o700 });
  let previous: Checkpoint | null = null, previousSha256: string | null = null, sequence = 0;
  return { directory, async save(payload: Report, signal: AbortSignal): Promise<void> {
    if (sequence >= (payload.plan.schema === 'scanmux.plan/v3' ? trivyEngines : legacyEngines).length) reject();
    if (backend && payload.engines.some(run => run.execution === 'failed')) await backend.failure('engine_execution_failed', signal);
    if (backend && payload.integrityErrors.length) await backend.failure('controller_integrity_failure', signal);
    const report: Report = { ...payload, executionState: 'failed', coverageState: 'incomplete', gate: 'ERROR', exitCode: 4,
      integrityErrors: [...new Set([...payload.integrityErrors, provisional])], reasons: [...new Set([...payload.reasons, provisional])] };
    const checkpoint: Checkpoint = { schema: payload.plan.schema === 'scanmux.plan/v3' ? 'scanmux.engine-checkpoint/v2' : 'scanmux.engine-checkpoint/v1', runId: report.runId, sequence: sequence + 1,
      planHash: report.plan.planHash, previousSha256, report };
    validateCheckpoint(checkpoint, sequence + 1, previous, previousSha256);
    const text = JSON.stringify(checkpoint, null, 2) + '\n', bytes = Buffer.byteLength(text);
    if (bytes > config.maxOutputBytes) throw new SafeError('output_size_limit');
    try { if (await checkedText(text, config, parent, signal) !== text) reject(); }
    catch (error) { if (backend) await backend.failure('checkpoint_output_rejected', signal); throw error; }
    const sha256 = hash(text), commit: Commit = { schema: payload.plan.schema === 'scanmux.plan/v3' ? 'scanmux.engine-checkpoint-commit/v2' : 'scanmux.engine-checkpoint-commit/v1', runId: report.runId,
      sequence: sequence + 1, bytes, sha256, previousSha256 };
    const receipt = JSON.stringify(commit, null, 2) + '\n';
    if (Buffer.byteLength(receipt) > config.maxOutputBytes) throw new SafeError('output_size_limit');
    if (backend) await backend.persist(Buffer.from(text, 'utf8'), Buffer.from(receipt, 'utf8'), signal);
    else {
      await durableWrite(path.join(directory, bodyName(sequence + 1)), text);
      await durableWrite(path.join(directory, commitName(sequence + 1)), receipt);
    }
    // Next engine admission depends on both sync/close operations, not readable bytes alone.
    sequence++; previous = JSON.parse(text) as Checkpoint; previousSha256 = sha256;
  } };
}

export async function readEngineCheckpoints(input: string, maximum: number) {
  const directory = await plainDirectory(input);
  if (!Number.isSafeInteger(maximum) || maximum <= 0 || maximum > 2147483647) reject();
  const receipts: (Buffer | null)[] = Array(trivyEngines.length).fill(null);
  // A later published slot implies earlier slots were published already. Reading backwards
  // captures a coherent prefix even while the single writer appends more receipts.
  for (let index = receipts.length - 1; index >= 0; index--) receipts[index] = await readOptional(path.join(directory, commitName(index + 1)), maximum);
  let previous: Checkpoint | null = null, previousSha256: string | null = null, ended = false, ignoredTail = false;
  for (let index = 0; index < receipts.length; index++) {
    const raw = receipts[index], sequence = index + 1;
    const body = await readOptional(path.join(directory, bodyName(sequence)), maximum);
    // A partial final receipt is uncommitted; a complete malformed receipt is corruption.
    const complete = raw !== null && raw.at(-1) === 10;
    if (!complete) {
      if (raw) new TextDecoder('utf-8', { fatal: true }).decode(raw);
      if (raw || body) ignoredTail = true;
      ended = true; continue;
    }
    if (ended || !body) reject();
    const { checkpoint } = validateCheckpointPair(body, raw, sequence, previous ? { checkpoint: previous, sha256: previousSha256 ?? reject() } : null);
    previous = checkpoint; previousSha256 = hash(body);
  }
  if (!previous) throw new SafeError('engine_checkpoint_unavailable');
  return { report: previous.report, sequence: previous.sequence, ignoredTail, directory };
}

export async function recoverEngineCheckpoints(input: string, configPath: string | undefined, config: Config) {
  const recovered = await readEngineCheckpoints(input, config.maxOutputBytes), root = await canonical(recovered.report.plan.root);
  if (!(await lstat(root)).isDirectory() || hash(root) !== recovered.report.plan.repoId) reject();
  await outside(recovered.directory, root);
  await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
  return { ...recovered, root };
}
