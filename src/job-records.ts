import path from 'node:path';
import { lstat, mkdir, open } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import type { CommitPair, Config, Gate, Plan, Report, Tool } from './model.ts';
import { defaults } from './config.ts';
import { catalogIdentity } from './advisory-catalog.ts';
import { comparisonSummary } from './comparison.ts';
import { summarizeHistory } from './history.ts';
import { decide, exitCodes } from './policy.ts';
import { validateCheckpointPair, type VerifiedCheckpointPair } from './engine-checkpoint.ts';
import { jobPayloadResources, type JobProfile } from './job-config.ts';
import { parseAnyRuntimePolicy } from './runtime-policy.ts';
import { array, boundedRead, canonical, digest, hash, record, safeRelative, SafeError } from './safety.ts';
import { jobFailureCodes, type JobFailureCode, type AssembledJobMessage } from '../internal/job-channel.mjs';
import { expectedResourceKernel } from '../internal/worker-resources.mjs';
import type { RetainedClient, RetainedWritePart } from './retained-write.ts';
import { testDirectory, validateTestIdentity, verificationMode, type ReproductionOperation } from './reproduction.ts';

export interface JobAsset { path: string; bytes: number; sha256: string }
export interface JobIdentity {
  nodeVersion: string; python: Tool; git: Tool; tools: Config['tools']; app: JobAsset[];
}
export interface JobPlan {
  schema: 'scanmux.job-plan/v1'; jobId: string; profileSha256: string;
  origin: { root: string; repoId: string }; mappedRoot: string;
  config: Config; configSha256: string; limits: JobProfile['limits']; image: string; runtime: JobIdentity;
  destination: string; requestedComparison: CommitPair | null; plan: Plan;
}
export interface ExpectedJobPlan {
  jobId: string; profileSha256: string; root: string; mappedRoot: string; config: Config; limits: JobProfile['limits'];
  image: string; runtime: JobIdentity; destination: string; comparison: CommitPair | undefined;
}
export interface JobBoundary {
  kernel: { cpuQuota: number; cpuPeriod: number; memoryMax: number; swapMax: number; tmpBytes: number; workBytes: number; shmBytes: number };
  pidsMax: number; uid: 1000; gid: 1000; capabilitiesZero: true; noNewPrivileges: true; seccomp: 2;
  supervisorNonDumpable: true; childSupervisorAccessDenied: true; rootReadonly: true;
  boundedWritableStoresOnly: true; privateNamespaces: true;
  networkCounters: number[]; cpuThrottledPeriods: number; oomKills: number;
}
export type JobStop =
  { kind: 'disk'; tid: number; syscall: 'write' | 'pwrite64'; errno: 28; returned: -28; store: 'tmp' | 'work' | 'shm'; device: number; inode: number; mountId: number; stopBeforeNextInstruction: true }
  | { kind: 'memory'; source: 'memory.events'; before: number; after: number }
  | { kind: 'memory'; source: 'docker-oom-killed' }
  | { kind: 'deadline'; source: 'host' | 'supervisor'; elapsedMs: number }
  | { kind: 'retained'; proposedBytes: number; availableBytes: number }
  | { kind: 'cancelled' };
export const jobHostFailureCodes = [
  'job_protocol_invalid', 'job_asset_changed', 'job_boundary_unverified', 'job_save_failed',
  'job_closure_unverified', 'job_inputs_changed', 'job_daemon_failed', 'job_controller_failed', 'job_admission_failed', 'job_native_observer_failed',
] as const;
const nativeOperations = ['require', 'exact', 'integer', 'read_small', 'file_hash', 'ptrace', 'syscall_info', 'event_message', 'security', 'restrict_child',
  'counters', 'network', 'mount_info', 'safe_root_probe', 'boundary', 'verify_assets', 'verify_source_types', 'emit', 'host_packet', 'service', 'add', 'resume', 'wait',
  'ingest', 'all_stop', 'observe', 'step', 'launch', 'kill_reap', 'close', 'main', 'unknown'] as const;
export interface JobNativeFailure { kind: 'invariant' | 'os' | 'unexpected'; operation: typeof nativeOperations[number]; site: number; errno: number | null }
const observerCountKeys = ['fork', 'vfork', 'clone', 'exec', 'exitEvent', 'signal', 'seccomp', 'interrupt', 'allStop', 'writes', 'execMigrations'] as const;
export interface JobObserverProgress {
  phase: 'starting' | 'waiting_admission' | 'verifying_source' | 'waiting_event' | 'all_stopping' | 'awaiting_write_exit' | 'syscall_exit_observed';
  tid: number | null; store: 'tmp' | 'work' | 'shm' | null; regular: boolean | null; syscall: 'write' | 'pwrite64' | null;
  tracked: number; stopped: number; retiringStopped: number;
  running: { tid: number; kernelState: 'R' | 'S' | 'D' | 'T' | 't' | 'Z' | 'X' | 'I' | 'unknown';
    lastStop: 'new' | 'fork_event' | 'exec_event' | 'exit_event' | 'syscall_entry' | 'event_stop' | 'signal_stop' | 'syscall_exit' | 'vfork_done';
    new: boolean; interrupting: boolean; pendingWrite: boolean } | null;
  lastEvent: { tid: number; signal: number; event: number; previousStop: NonNullable<JobObserverProgress['running']>['lastStop'];
    new: boolean; interrupting: boolean; entryPhase: 'pending' | 'async' | 'held' | null } | null;
}
export interface JobObserver { counts: Record<typeof observerCountKeys[number], number>; interruption: JobObserverProgress | null }
export type JobKnownFailure = JobFailureCode | typeof jobHostFailureCodes[number];
export interface JobClosure {
  startupVerified: boolean; supervisorClosed: boolean; ownedTasksClosure: 'supervisor_final_wait' | 'namespace_terminal_and_absent' | 'unverified';
  controllerCompleted: boolean;
  controllerTerminal: { exitCode: number | null; signal: number | null } | null;
  terminal: { exitCode: number; oomKilled: boolean } | null;
  containerAbsent: boolean; daemonHealthy: boolean; inputsUnchanged: boolean;
}
export interface JobFileReference { bytes: number; sha256: string }
export type JobAnalysisReference =
  { kind: 'report'; file: 'report.json'; bytes: number; sha256: string }
  | { kind: 'checkpoint'; sequence: number; body: JobFileReference; receipt: JobFileReference };
export interface JobReport {
  schema: 'scanmux.job-report/v1'; jobId: string; profileSha256: string; originDigest: string;
  origin: JobPlan['origin'] | null; mappedRoot: string | null;
  plan: JobFileReference | null; analysis: JobAnalysisReference | null;
  basis: 'live_owner_recorded' | 'recovered_saved_checkpoint_without_live_ownership';
  resources: { requested: JobProfile['limits']; startup: JobBoundary | null; ending: JobBoundary | null; stop: JobStop | null; nativeFailure: JobNativeFailure | null; observer: JobObserver | null;
    payloadWallScope: 'linux_payload_and_durable_record_ack_admission'; controlPlaneHardCpuMemoryLimit: false;
    retainedFilesystemPhysicalQuotaEnforced: false; totalCommandWallGuarantee: false };
  closure: JobClosure; knownFailures: JobKnownFailure[];
  failureObservationScope: 'host_accepted_closed_failure_facts'; unobservedInternalErrors: 'unknown';
  inputVerificationScope: 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported';
  infrastructure: { appFiles: number; appBytes: number; emptyConfigurationFiles: 1; ownerIdentityBytes: number };
  retained: { logicalLimit: number; payloadAdmittedBytesBeforeMetadata: number; filesBeforeMetadata: number; metadataBytesMaximum: number; maxFiles: 11 };
  gate: Gate; exitCode: number; reasons: string[];
}

export interface JobCompletionFacts {
  startup: JobBoundary | null; ending: JobBoundary | null; nativeFailure: JobNativeFailure | null;
  stop: JobStop | null; closure: JobClosure; failures: JobKnownFailure[];
}

export function jobFinalAnalysisVerified(facts: JobCompletionFacts): boolean {
  const { closure } = facts;
  return facts.stop === null && facts.nativeFailure === null && facts.startup !== null && facts.ending !== null
    && isDeepStrictEqual(facts.startup.networkCounters, facts.ending.networkCounters)
    && !facts.failures.some(code => jobHostFailureCodes.some(hostCode => hostCode === code))
    && closure.startupVerified && closure.supervisorClosed && closure.ownedTasksClosure === 'supervisor_final_wait'
    && closure.controllerCompleted && closure.controllerTerminal?.exitCode === 0 && closure.controllerTerminal.signal === null
    && closure.terminal?.exitCode === 0 && !closure.terminal.oomKilled && closure.containerAbsent && closure.daemonHealthy && closure.inputsUnchanged;
}

function reject(): never { throw new SafeError('invalid_job_record'); }
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  const value = record(input);
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) reject();
  return value;
}
function count(input: unknown, positive = false): number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < (positive ? 1 : 0)) reject();
  return input;
}
function sha(input: unknown): string {
  if (typeof input !== 'string' || !/^[a-f0-9]{64}$/.test(input)) reject();
  return input;
}
function uuid(input: unknown): string {
  if (typeof input !== 'string' || !/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(input)) reject();
  return input;
}
const eitherAbsolute = (input: string) => path.posix.isAbsolute(input) || path.win32.isAbsolute(input);
function absolute(input: unknown): string {
  if (typeof input !== 'string' || !eitherAbsolute(input) || /[\x00-\x1f\x7f]/.test(input)) reject();
  return input;
}
export function parseJobJson(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
export function jobReference(bytes: Buffer): JobFileReference { return { bytes: bytes.length, sha256: hash(bytes) }; }
function reference(input: unknown): JobFileReference {
  const value = exact(input, ['bytes', 'sha256']); return { bytes: count(value.bytes, true), sha256: sha(value.sha256) };
}
function version(input: unknown): string {
  if (typeof input !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(input)) reject();
  return input;
}
function fixedTool(input: unknown, executable: string): Tool {
  const value = exact(input, ['path', 'sha256', 'version']);
  if (value.path !== executable) reject();
  return { path: executable, sha256: sha(value.sha256), version: version(value.version) };
}
function linuxConfig(input: unknown): Config {
  const two = record(input).schema === 2, value = exact(input, [...Object.keys(defaults), ...(two ? ['runtimePolicy'] : [])]);
  if (!two && value.schema !== defaults.schema) reject();
  for (const key of ['auth', 'model', 'accessProgram', 'runner', 'ai'] as const) if (value[key] !== defaults[key]) reject();
  if (two) try { parseAnyRuntimePolicy(value.runtimePolicy, eitherAbsolute); } catch { reject(); }
  for (const key of ['timeoutMs', 'maxOutputBytes', 'maxFileBytes', 'maxSnapshotBytes', 'maxFiles']) if (count(value[key], true) > 2147483647) reject();
  if (value.osvDatabase !== null && value.osvDatabase !== '/db') reject();
  const tools = record(value.tools);
  if (!Object.hasOwn(tools, 'git') || !Object.hasOwn(tools, 'gitleaks') || Object.keys(tools).some(key => !['git', 'gitleaks', 'osv'].includes(key))) reject();
  fixedTool(tools.git, '/usr/bin/git'); fixedTool(tools.gitleaks, '/tools/gitleaks');
  if (tools.osv !== undefined) fixedTool(tools.osv, '/tools/osv');
  return value as unknown as Config;
}
function identity(input: unknown, config: Config): JobIdentity {
  const value = exact(input, ['nodeVersion', 'python', 'git', 'tools', 'app']);
  version(value.nodeVersion); fixedTool(value.python, '/usr/bin/python3'); fixedTool(value.git, '/usr/bin/git');
  if (!isDeepStrictEqual(value.git, config.tools.git) || !isDeepStrictEqual(value.tools, config.tools)) reject();
  const names = new Set<string>();
  for (const raw of array(value.app)) {
    const asset = exact(raw, ['path', 'bytes', 'sha256']), name = safeRelative(asset.path);
    if (names.has(name)) reject(); names.add(name); count(asset.bytes); sha(asset.sha256);
  }
  if (!names.size || !names.has('internal/linux-job-controller.mjs') || !names.has('internal/linux-job-supervisor.py')) reject();
  return value as unknown as JobIdentity;
}
function planShape(input: unknown, mappedRoot: string, config: Config): Plan {
  const value = record(input), required = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'];
  const keys = ['schema', 'repoId', 'root', 'commit', 'advisoryCatalog', 'treeHash', 'snapshotHash', 'dirty', 'files', 'exclusions',
    'blockers', 'languages', 'lockfiles', 'required', 'policyHash', 'planHash', 'network', 'transmissions', 'constraints', 'cost'];
  if (keys.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => ![...keys, 'configuration', 'comparison'].includes(key))
    || value.schema !== 'scanmux.plan/v2' || value.root !== mappedRoot || value.repoId !== hash(mappedRoot)
    || value.policyHash !== digest(config) || value.planHash !== digest({ ...value, planHash: '' })
    || value.network !== 'offline' || !isDeepStrictEqual(value.required, required) || !isDeepStrictEqual(value.advisoryCatalog, catalogIdentity)
    || !isDeepStrictEqual(value.cost, { kind: 'not_applicable', aiCalls: 0 }) || array(value.transmissions).length !== 0) reject();
  if (sha(value.snapshotHash) !== digest(value.files)) reject();
  for (const key of ['commit', 'treeHash']) if (value[key] !== null && (typeof value[key] !== 'string' || !/^[a-f0-9]{40}$/.test(value[key]))) reject();
  if (value.dirty !== null && typeof value.dirty !== 'boolean') reject();
  let total = 0;
  const names = new Set<string>();
  for (const raw of array(value.files)) {
    const file = exact(raw, ['path', 'oid', 'bytes', 'sha256']), name = safeRelative(file.path), bytes = count(file.bytes);
    const key = name.normalize('NFC').toLowerCase();
    if (names.has(key) || key.split('/').includes('.git') || bytes > config.maxFileBytes || typeof file.oid !== 'string' || !/^[a-f0-9]{40}$/.test(file.oid)) reject();
    names.add(key); total += bytes; sha(file.sha256);
    if (!Number.isSafeInteger(total) || total > config.maxSnapshotBytes || names.size > config.maxFiles) reject();
  }
  for (const raw of array(value.exclusions)) { const row = exact(raw, ['path', 'reason']); safeRelative(row.path); if (typeof row.reason !== 'string' || !/^[a-z0-9_]{1,100}$/.test(row.reason)) reject(); }
  for (const key of ['blockers', 'constraints']) for (const code of array(value[key])) if (typeof code !== 'string' || !/^[A-Za-z0-9_.:-]{1,200}$/.test(code)) reject();
  for (const language of array(value.languages)) if (!['JS/TS', 'Python', 'Go', 'Rust'].includes(String(language))) reject();
  for (const name of array(value.lockfiles)) if (!names.has(safeRelative(name).normalize('NFC').toLowerCase())) reject();
  const plan = value as unknown as Plan;
  comparisonSummary(plan);
  return plan;
}

export function validateJobPlan(input: unknown, expected?: ExpectedJobPlan): JobPlan {
  const value = exact(input, ['schema', 'jobId', 'profileSha256', 'origin', 'mappedRoot', 'config', 'configSha256', 'limits', 'image', 'runtime', 'destination', 'requestedComparison', 'plan']);
  if (value.schema !== 'scanmux.job-plan/v1') reject();
  uuid(value.jobId); sha(value.profileSha256);
  const origin = exact(value.origin, ['root', 'repoId']), root = absolute(origin.root);
  if (origin.repoId !== hash(root) || value.mappedRoot !== '/repo/' + hash(root) || typeof value.image !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value.image)) reject();
  const config = linuxConfig(value.config);
  if (value.configSha256 !== digest(config)) reject();
  if (parseLimits(value.limits).retainedBytes < 2 * config.maxOutputBytes) reject();
  identity(value.runtime, config); absolute(value.destination);
  const plan = planShape(value.plan, String(value.mappedRoot), config);
  if (value.requestedComparison !== null) {
    const comparison = exact(value.requestedComparison, ['base', 'head']);
    if ([comparison.base, comparison.head].some(v => typeof v !== 'string' || !/^[a-f0-9]{40}$/.test(v))) reject();
    if (plan.comparison && (plan.comparison.baseCommit !== comparison.base || plan.comparison.headCommit !== comparison.head)
      || !plan.comparison && !plan.blockers.length) reject();
  } else if (plan.comparison) reject();
  if (expected && (value.jobId !== expected.jobId || value.profileSha256 !== expected.profileSha256 || root !== expected.root
    || value.mappedRoot !== expected.mappedRoot || value.image !== expected.image || value.destination !== expected.destination
    || !isDeepStrictEqual(config, expected.config) || !isDeepStrictEqual(value.limits, expected.limits) || !isDeepStrictEqual(value.runtime, expected.runtime)
    || !isDeepStrictEqual(value.requestedComparison, expected.comparison ?? null))) reject();
  return value as unknown as JobPlan;
}

export function validateJobBootstrap(input: unknown): ExpectedJobPlan {
  const value = exact(input, ['jobId', 'profileSha256', 'root', 'mappedRoot', 'config', 'limits', 'image', 'runtime', 'destination', 'comparison']);
  uuid(value.jobId); sha(value.profileSha256);
  const root = absolute(value.root), config = linuxConfig(value.config);
  if (value.mappedRoot !== '/repo/' + hash(root) || typeof value.image !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value.image)) reject();
  identity(value.runtime, config); absolute(value.destination);
  let comparison: CommitPair | undefined;
  if (value.comparison !== null) {
    const pair = exact(value.comparison, ['base', 'head']);
    if (typeof pair.base !== 'string' || !/^[a-f0-9]{40}$/.test(pair.base) || typeof pair.head !== 'string' || !/^[a-f0-9]{40}$/.test(pair.head)) reject();
    comparison = { base: pair.base, head: pair.head };
  }
  const limits = parseLimits(value.limits);
  if (limits.retainedBytes < 2 * config.maxOutputBytes) reject();
  return { jobId: String(value.jobId), profileSha256: String(value.profileSha256), root, mappedRoot: String(value.mappedRoot), config, limits,
    image: value.image, runtime: identity(value.runtime, config), destination: String(value.destination), comparison };
}

export function validateReproductionOperation(input: unknown, expected?: ExpectedJobPlan): ReproductionOperation {
  const value = exact(input, ['kind', 'side', 'commit', 'sourceSnapshot', 'finding', 'sourceReportSha256', 'testDirectory', 'mode', 'expectedTest']);
  if (value.kind !== 'reproduction' || !['snapshot', 'before', 'after'].includes(String(value.side))) reject();
  const snapshot = exact(value.sourceSnapshot, ['commit', 'tree', 'snapshotHash']), finding = exact(value.finding, ['engine', 'fingerprint']);
  for (const item of [value.commit, snapshot.commit, snapshot.tree]) if (typeof item !== 'string' || !/^[a-f0-9]{40}$/.test(item)) reject();
  sha(snapshot.snapshotHash); sha(value.sourceReportSha256); sha(finding.fingerprint);
  if (!['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].includes(String(finding.engine))) reject();
  testDirectory(value.testDirectory);
  const mode = verificationMode(value.mode);
  if (mode.kind === 'snapshot' ? value.side !== 'snapshot' || value.commit !== snapshot.commit
    : snapshot.commit !== mode.base || value.side === 'snapshot' || value.commit !== (value.side === 'after' ? mode.head : mode.base)) reject();
  if (value.expectedTest !== null) {
    const test = validateTestIdentity(value.expectedTest); if (test.directory !== value.testDirectory) reject();
    if (expected && (test.runtime.imageDigest !== expected.image || test.runtime.profileSha256 !== expected.profileSha256
      || test.runtime.nodeVersion !== expected.runtime.nodeVersion || test.runtime.assetsSha256 !== digest(expected.runtime.app)
      || test.driverSha256 !== expected.runtime.app.find(file => file.path === 'internal/reproduction-driver.mjs')?.sha256)) reject();
  } else if (value.side === 'after') reject();
  if (expected && !isDeepStrictEqual(expected.comparison, { base: value.side === 'after' && mode.kind === 'before_after' ? mode.base : value.commit, head: value.commit })) reject();
  return value as unknown as ReproductionOperation;
}

export function validateReproductionBootstrap(input: unknown) {
  const value = exact(input, ['expected', 'operation']), expected = validateJobBootstrap(value.expected);
  return { expected, operation: validateReproductionOperation(value.operation, expected) };
}

export function validateJobFinalReport(bytes: Buffer, job: JobPlan, prefix: VerifiedCheckpointPair | null): Report {
  const value = exact(parseJobJson(bytes), ['schema', 'runId', 'plan', 'startedAt', 'endedAt', 'engines', 'runner', 'executionState', 'coverageState', 'gate', 'reasons', 'exitCode', 'integrityErrors']);
  if (value.schema !== 'scanmux.report/v2' || !isDeepStrictEqual(value.plan, job.plan)) reject();
  const report = value as unknown as Report;
  const summary = summarizeHistory([bytes]).summary.runs[0], engines = array(value.engines).map(record);
  if (summary.repoId !== hash(job.mappedRoot) || engines.length > job.plan.required.length || engines.some((run, index) => run.engine !== job.plan.required[index])
    || record(value.runner).platform !== 'linux' || record(value.runner).node !== 'v' + job.runtime.nodeVersion
    || array(value.integrityErrors).includes('controller_completion_unverified')) reject();
  const judgment = decide(job.plan, report.engines, report.integrityErrors);
  if (value.gate !== judgment.gate || value.exitCode !== exitCodes[judgment.gate] || !isDeepStrictEqual(value.reasons, judgment.reasons)) reject();
  if (prefix) {
    const previous = prefix.checkpoint.report;
    if (report.runId !== previous.runId || report.startedAt !== previous.startedAt || report.engines.length < previous.engines.length
      || previous.engines.some((run, index) => !isDeepStrictEqual(run, report.engines[index]))
      || previous.integrityErrors.filter(code => code !== 'controller_completion_unverified').some(code => !report.integrityErrors.includes(code))) reject();
  }
  return report;
}

/** Writes are exclusive. Admission accounting includes unaccepted tails and never reuses a final reserve. */
export class JobRecordStore {
  readonly directory: string;
  readonly maximum: number;
  readonly retainedLimit: number;
  readonly expected: ExpectedJobPlan;
  admittedBytes = 0;
  files = 0;
  plan: JobPlan | null = null;
  planReference: JobFileReference | null = null;
  prefix: VerifiedCheckpointPair | null = null;
  analysis: JobAnalysisReference | null = null;
  finalReport: Report | null = null;
  private reportReceipt: { report: Report; reference: JobAnalysisReference } | null = null;
  private finalized = false;
  private pending: { ackSeq: number; commit: () => void } | null = null;
  private failed = false;
  private payloadClosed = false;
  private reportReserved = true;
  private metadataReserved = true;
  private readonly metadataName: 'job.json' | 'delegated-job.json';
  private readonly retained: Pick<RetainedClient, 'write'> | undefined;
  constructor(directory: string, profile: JobProfile, expected: ExpectedJobPlan, metadataName: 'job.json' | 'delegated-job.json' = 'job.json', retained?: Pick<RetainedClient, 'write'>) {
    if (!['job.json', 'delegated-job.json'].includes(metadataName)) reject();
    if (retained && metadataName !== 'delegated-job.json') reject();
    this.retained = retained;
    this.metadataName = metadataName;
    this.directory = directory; this.maximum = profile.scan.maxOutputBytes; this.retainedLimit = profile.limits.retainedBytes; this.expected = expected;
  }
  private async write(file: string, bytes: Buffer) {
    if (bytes.length > this.maximum || this.failed) reject();
    this.admittedBytes += bytes.length; this.files++;
    const handle = await open(file, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); }
    finally { await handle.close(); }
  }
  private async writeBatch(parts: readonly RetainedWritePart[], mayRefuse = false): Promise<{ kind: 'retained'; proposedBytes: number; availableBytes: number } | null> {
    if (this.failed || parts.some(part => part.bytes.length > this.maximum)) reject();
    if (!this.retained) {
      for (const part of parts) await this.write(path.join(this.directory, ...part.name.split('/')), part.bytes);
      return null;
    }
    // Count a possibly created tail even if the native operation fails before replying.
    // Only an authenticated admission refusal proves that no proposed file was created.
    const size = parts.reduce((total, part) => total + part.bytes.length, 0);
    this.admittedBytes += size; this.files += parts.length;
    const result = await this.retained.write(parts);
    if (result.result === 'committed') return null;
    if (!mayRefuse) reject();
    this.admittedBytes -= size; this.files -= parts.length; this.payloadClosed = true;
    return { kind: 'retained', proposedBytes: result.proposedAllocatedBytes, availableBytes: result.availableIntermediateBytes };
  }
  availableIntermediateBytes() {
    return this.retainedLimit - this.admittedBytes - (Number(this.reportReserved) + Number(this.metadataReserved)) * this.maximum;
  }
  async persist(message: Extract<AssembledJobMessage, { type: 'record' }>): Promise<{ kind: 'ready' } | { kind: 'retained'; proposedBytes: number; availableBytes: number }> {
    try { return await this.persistRecord(message); }
    catch (error) { this.failed = true; this.payloadClosed = true; throw error; }
  }
  private async persistRecord(message: Extract<AssembledJobMessage, { type: 'record' }>): Promise<{ kind: 'ready' } | { kind: 'retained'; proposedBytes: number; availableBytes: number }> {
    if (this.pending || this.failed || this.payloadClosed) reject();
    const size = message.parts.reduce((sum, bytes) => sum + bytes.length, 0);
    if (message.parts.some(bytes => bytes.length > this.maximum)) reject();
    // Validate the complete proposed record before classifying its refusal as budget-only.
    if (message.kind === 'plan') {
      if (this.plan || message.slot !== 0 || message.parts.length !== 1) reject();
      const plan = validateJobPlan(parseJobJson(message.parts[0]), this.expected);
      const available = this.availableIntermediateBytes();
      if (size > available) { this.payloadClosed = true; return { kind: 'retained', proposedBytes: size, availableBytes: Math.max(0, available) }; }
      try {
        const refused = await this.writeBatch([{ name: 'job-plan.json', bytes: message.parts[0] }], true);
        if (refused) return refused;
      }
      catch (error) { this.failed = true; throw error; }
      this.pending = { ackSeq: message.ackSeq, commit: () => { this.plan = plan; this.planReference = jobReference(message.parts[0]); } };
    } else if (message.kind === 'checkpoint') {
      if (!this.plan || this.reportReceipt || !this.reportReserved || message.parts.length !== 2 || message.slot !== (this.prefix?.checkpoint.sequence ?? 0) + 1) reject();
      const pair = validateCheckpointPair(message.parts[0], message.parts[1], message.slot, this.prefix);
      if (!isDeepStrictEqual(pair.checkpoint.report.plan, this.plan.plan)) reject();
      const available = this.availableIntermediateBytes();
      if (size > available) { this.payloadClosed = true; return { kind: 'retained', proposedBytes: size, availableBytes: Math.max(0, available) }; }
      try {
        if (!this.retained && !this.prefix) await mkdir(path.join(this.directory, 'checkpoints'), { mode: 0o700 });
        const refused = await this.writeBatch([
          { name: `checkpoints/checkpoint-${message.slot}.json`, bytes: message.parts[0] },
          { name: `checkpoints/commit-${message.slot}.json`, bytes: message.parts[1] },
        ], true);
        if (refused) return refused;
      } catch (error) { this.failed = true; throw error; }
      this.pending = { ackSeq: message.ackSeq, commit: () => {
        this.prefix = pair; this.analysis = { kind: 'checkpoint', sequence: message.slot, body: jobReference(message.parts[0]), receipt: jobReference(message.parts[1]) };
      } };
    } else {
      if (!this.plan || this.reportReceipt || !this.reportReserved || message.parts.length !== 1 || message.slot !== 0) reject();
      const report = validateJobFinalReport(message.parts[0], this.plan, this.prefix);
      this.reportReserved = false;
      try { await this.writeBatch([{ name: 'report.json', bytes: message.parts[0] }]); }
      catch (error) { this.failed = true; throw error; }
      this.pending = { ackSeq: message.ackSeq, commit: () => {
        this.reportReceipt = { report, reference: { kind: 'report', file: 'report.json', ...jobReference(message.parts[0]) } };
      } };
    }
    return { kind: 'ready' };
  }
  acknowledge(sequence: number) {
    if (this.failed || this.payloadClosed || this.pending?.ackSeq !== sequence) reject();
    this.pending.commit(); this.pending = null;
  }
  discardUnacceptedTail() { this.pending = null; this.reportReceipt = null; this.payloadClosed = true; }
  finalize(facts: JobCompletionFacts) {
    if (this.finalized) reject();
    this.finalized = true;
    // ACK records receipt only. Terminal facts are available after the owner closes the payload.
    if (!this.failed && !this.payloadClosed && this.reportReceipt && jobFinalAnalysisVerified(facts)) {
      this.finalReport = this.reportReceipt.report; this.analysis = this.reportReceipt.reference;
    }
    this.discardUnacceptedTail();
  }
  async saveMetadata(bytes: Buffer) {
    if (!this.metadataReserved || bytes.length > this.maximum || this.admittedBytes + bytes.length > this.retainedLimit || this.files >= 11) reject();
    // A failed payload-record write may still leave room for a static ERROR metadata record.
    const wasFailed = this.failed; this.failed = false; this.metadataReserved = false;
    try { await this.writeBatch([{ name: this.metadataName, bytes }]); }
    finally { this.failed = wasFailed; }
  }
}

export function validateJobBoundary(input: unknown, limits: JobProfile['limits']): JobBoundary {
  const value = exact(input, ['kernel', 'pidsMax', 'uid', 'gid', 'capabilitiesZero', 'noNewPrivileges', 'seccomp', 'supervisorNonDumpable',
    'childSupervisorAccessDenied', 'rootReadonly', 'boundedWritableStoresOnly', 'privateNamespaces', 'networkCounters', 'cpuThrottledPeriods', 'oomKills']);
  if (!isDeepStrictEqual(value.kernel, expectedResourceKernel(jobPayloadResources(limits))) || value.pidsMax !== limits.pids || value.uid !== 1000 || value.gid !== 1000
    || value.seccomp !== 2 || ['capabilitiesZero', 'noNewPrivileges', 'supervisorNonDumpable', 'childSupervisorAccessDenied', 'rootReadonly', 'boundedWritableStoresOnly', 'privateNamespaces'].some(key => value[key] !== true)) reject();
  if (!Array.isArray(value.networkCounters) || value.networkCounters.length !== 16) reject();
  value.networkCounters.forEach(counter => count(counter)); count(value.cpuThrottledPeriods); count(value.oomKills);
  return value as unknown as JobBoundary;
}

function parseLimits(input: unknown): JobProfile['limits'] {
  const keys = ['cpuCount', 'memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes', 'pids', 'wallMs', 'cleanupTimeoutMs', 'retainedBytes'];
  const value = exact(input, keys); keys.forEach(key => count(value[key], true));
  try { jobPayloadResources(value as unknown as JobProfile['limits']); } catch { reject(); }
  if (count(value.wallMs) > 2147483647 || count(value.cleanupTimeoutMs) > 2147483647 || count(value.pids) > 2147483647) reject();
  return value as unknown as JobProfile['limits'];
}
export function validateJobStop(input: unknown): JobStop {
  const value = record(input);
  switch (value.kind) {
    case 'disk':
      exact(value, ['kind', 'tid', 'syscall', 'errno', 'returned', 'store', 'device', 'inode', 'mountId', 'stopBeforeNextInstruction']);
      count(value.tid, true); count(value.device); count(value.inode); count(value.mountId, true);
      if (!['write', 'pwrite64'].includes(String(value.syscall)) || value.errno !== 28 || value.returned !== -28
        || !['tmp', 'work', 'shm'].includes(String(value.store)) || value.stopBeforeNextInstruction !== true) reject(); break;
    case 'memory':
      if (value.source === 'memory.events') { exact(value, ['kind', 'source', 'before', 'after']); if (count(value.after) <= count(value.before)) reject(); }
      else { exact(value, ['kind', 'source']); if (value.source !== 'docker-oom-killed') reject(); } break;
    case 'deadline': exact(value, ['kind', 'source', 'elapsedMs']); count(value.elapsedMs); if (!['host', 'supervisor'].includes(String(value.source))) reject(); break;
    case 'retained': exact(value, ['kind', 'proposedBytes', 'availableBytes']); if (count(value.proposedBytes, true) <= count(value.availableBytes)) reject(); break;
    case 'cancelled': exact(value, ['kind']); break;
    default: reject();
  }
  return value as unknown as JobStop;
}

export function validateJobNativeFailure(input: unknown): JobNativeFailure {
  const value = exact(input, ['kind', 'operation', 'site', 'errno']);
  if (!['invariant', 'os', 'unexpected'].includes(String(value.kind)) || !nativeOperations.some(operation => operation === value.operation)) reject();
  count(value.site, true); if (value.errno !== null) count(value.errno);
  return value as unknown as JobNativeFailure;
}
export function validateJobObserver(input: unknown): JobObserver {
  const value = exact(input, ['counts', 'interruption']), counts = exact(value.counts, observerCountKeys);
  Object.values(counts).forEach(value => count(value));
  if (value.interruption !== null) {
    const progress = exact(value.interruption, ['phase', 'tid', 'store', 'regular', 'syscall', 'tracked', 'stopped', 'retiringStopped', 'running', 'lastEvent']);
    if (!['starting', 'waiting_admission', 'verifying_source', 'waiting_event', 'all_stopping', 'awaiting_write_exit', 'syscall_exit_observed'].includes(String(progress.phase))
      || progress.store !== null && !['tmp', 'work', 'shm'].includes(String(progress.store))
      || progress.regular !== null && typeof progress.regular !== 'boolean' || progress.syscall !== null && !['write', 'pwrite64'].includes(String(progress.syscall))) reject();
    if (progress.tid !== null) count(progress.tid, true);
    if (count(progress.stopped) > count(progress.tracked) || progress.store !== null && progress.regular !== true) reject();
    if (count(progress.retiringStopped) > count(progress.stopped)) reject();
    if (progress.lastEvent !== null) {
      const event = exact(progress.lastEvent, ['tid', 'signal', 'event', 'previousStop', 'new', 'interrupting', 'entryPhase']);
      count(event.tid, true);
      if (count(event.signal, true) > 255 || ![0, 1, 2, 3, 4, 5, 6, 7, 128].includes(count(event.event))
        || !['new', 'fork_event', 'exec_event', 'exit_event', 'syscall_entry', 'event_stop', 'signal_stop', 'syscall_exit', 'vfork_done'].includes(String(event.previousStop))
        || typeof event.new !== 'boolean' || typeof event.interrupting !== 'boolean'
        || event.entryPhase !== null && !['pending', 'async', 'held'].includes(String(event.entryPhase))) reject();
    }
    if (progress.running !== null) {
      const running = exact(progress.running, ['tid', 'kernelState', 'lastStop', 'new', 'interrupting', 'pendingWrite']);
      count(running.tid, true);
      if (!['R', 'S', 'D', 'T', 't', 'Z', 'X', 'I', 'unknown'].includes(String(running.kernelState))
        || !['new', 'fork_event', 'exec_event', 'exit_event', 'syscall_entry', 'event_stop', 'signal_stop', 'syscall_exit', 'vfork_done'].includes(String(running.lastStop))
        || ['new', 'interrupting', 'pendingWrite'].some(key => typeof running[key] !== 'boolean')) reject();
    }
  }
  return value as unknown as JobObserver;
}

export function jobOutcome(options: { plan: JobPlan | null; report: Report | null; prefix: VerifiedCheckpointPair | null; stop: JobStop | null; closure: JobClosure; failures: JobKnownFailure[] }) {
  const { plan, report, prefix, stop, closure, failures } = options;
  const closed = closure.startupVerified && closure.supervisorClosed && closure.ownedTasksClosure !== 'unverified' && closure.containerAbsent
    && closure.daemonHealthy && closure.inputsUnchanged && closure.terminal !== null;
  const analysis = report ?? prefix?.checkpoint.report;
  const judgment = plan ? decide(plan.plan, analysis?.engines ?? [], (analysis?.integrityErrors ?? []).filter(code => code !== 'controller_completion_unverified')) : null;
  const reasons: string[] = [...failures, ...(judgment?.reasons ?? []), ...(!analysis ? ['job_analysis_missing'] : [])];
  const causeMismatch = stop?.kind === 'memory' && stop.source === 'docker-oom-killed' && closure.terminal?.oomKilled !== true;
  let gate: Gate;
  if (failures.length || !closed || judgment?.gate === 'ERROR' || causeMismatch) gate = 'ERROR';
  else if (stop) {
    reasons.push('job_' + stop.kind + '_stop');
    gate = stop.kind === 'cancelled' ? 'ERROR' : judgment?.gate === 'FAIL' ? 'FAIL' : 'INCOMPLETE';
  } else if (!report || closure.terminal?.exitCode !== 0 || closure.terminal.oomKilled) { gate = 'ERROR'; reasons.push('job_completion_unverified'); }
  else gate = report.gate;
  if (!closed) reasons.push('job_closure_unverified');
  if (causeMismatch) reasons.push('job_native_cause_unverified');
  return { gate, exitCode: exitCodes[gate], reasons: [...new Set(reasons)] };
}

function validateJobClosure(input: unknown): JobClosure {
  const closure = exact(input, ['startupVerified', 'supervisorClosed', 'ownedTasksClosure', 'controllerCompleted', 'controllerTerminal', 'terminal', 'containerAbsent', 'daemonHealthy', 'inputsUnchanged']);
  for (const key of ['startupVerified', 'supervisorClosed', 'controllerCompleted', 'containerAbsent', 'daemonHealthy', 'inputsUnchanged']) if (typeof closure[key] !== 'boolean') reject();
  if (!['supervisor_final_wait', 'namespace_terminal_and_absent', 'unverified'].includes(String(closure.ownedTasksClosure))) reject();
  if (closure.controllerTerminal !== null) {
    const terminal = exact(closure.controllerTerminal, ['exitCode', 'signal']);
    if ((terminal.exitCode === null) === (terminal.signal === null) || terminal.exitCode !== null && count(terminal.exitCode) > 255
      || terminal.signal !== null && count(terminal.signal, true) > 64) reject();
  }
  if (closure.terminal !== null) { const terminal = exact(closure.terminal, ['exitCode', 'oomKilled']); if (count(terminal.exitCode) > 255 || typeof terminal.oomKilled !== 'boolean') reject(); }
  return closure as unknown as JobClosure;
}

export function validateJobCompletion(input: unknown, requested: JobProfile['limits']): JobCompletionFacts {
  const value = exact(input, ['startup', 'ending', 'nativeFailure', 'stop', 'closure', 'failures']), limits = parseLimits(requested);
  if (value.startup !== null) validateJobBoundary(value.startup, limits);
  if (value.ending !== null) validateJobBoundary(value.ending, limits);
  if (value.nativeFailure !== null) validateJobNativeFailure(value.nativeFailure);
  if (value.stop !== null) validateJobStop(value.stop);
  validateJobClosure(value.closure);
  for (const code of array(value.failures)) if (!jobFailureCodes.includes(code as JobFailureCode) && !jobHostFailureCodes.includes(code as typeof jobHostFailureCodes[number])) reject();
  return value as unknown as JobCompletionFacts;
}

export function validateJobReport(input: unknown): JobReport {
  const value = exact(input, ['schema', 'jobId', 'profileSha256', 'originDigest', 'origin', 'mappedRoot', 'plan', 'analysis', 'basis', 'resources', 'closure',
    'knownFailures', 'failureObservationScope', 'unobservedInternalErrors', 'inputVerificationScope', 'infrastructure', 'retained', 'gate', 'exitCode', 'reasons']);
  if (value.schema !== 'scanmux.job-report/v1' || !['live_owner_recorded', 'recovered_saved_checkpoint_without_live_ownership'].includes(String(value.basis))
    || value.failureObservationScope !== 'host_accepted_closed_failure_facts' || value.unobservedInternalErrors !== 'unknown'
    || value.inputVerificationScope !== 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported') reject();
  uuid(value.jobId); sha(value.profileSha256); sha(value.originDigest);
  if (value.origin === null) { if (value.mappedRoot !== null || value.plan !== null || value.analysis !== null) reject(); }
  else {
    const origin = exact(value.origin, ['root', 'repoId']);
    if (hash(absolute(origin.root)) !== origin.repoId || origin.repoId !== value.originDigest || value.mappedRoot !== '/repo/' + origin.repoId || value.plan === null) reject();
    reference(value.plan);
  }
  if (value.analysis !== null) {
    const analysis = record(value.analysis);
    if (analysis.kind === 'report') { exact(analysis, ['kind', 'file', 'bytes', 'sha256']); if (analysis.file !== 'report.json') reject(); reference({ bytes: analysis.bytes, sha256: analysis.sha256 }); }
    else if (analysis.kind === 'checkpoint') { exact(analysis, ['kind', 'sequence', 'body', 'receipt']); if (count(analysis.sequence, true) > 4) reject(); reference(analysis.body); reference(analysis.receipt); }
    else reject();
  }
  const resources = exact(value.resources, ['requested', 'startup', 'ending', 'stop', 'nativeFailure', 'observer', 'payloadWallScope', 'controlPlaneHardCpuMemoryLimit', 'retainedFilesystemPhysicalQuotaEnforced', 'totalCommandWallGuarantee']);
  const limits = parseLimits(resources.requested);
  if (resources.payloadWallScope !== 'linux_payload_and_durable_record_ack_admission' || resources.controlPlaneHardCpuMemoryLimit !== false
    || resources.retainedFilesystemPhysicalQuotaEnforced !== false || resources.totalCommandWallGuarantee !== false) reject();
  if (resources.startup !== null) validateJobBoundary(resources.startup, limits);
  if (resources.ending !== null) validateJobBoundary(resources.ending, limits);
  if (resources.stop !== null) validateJobStop(resources.stop);
  if (resources.nativeFailure !== null) validateJobNativeFailure(resources.nativeFailure);
  if (resources.observer !== null) validateJobObserver(resources.observer);
  validateJobClosure(value.closure);
  for (const code of array(value.knownFailures)) if (!jobFailureCodes.includes(code as JobFailureCode) && !jobHostFailureCodes.includes(code as typeof jobHostFailureCodes[number])) reject();
  const parsed = value as unknown as JobReport;
  if (parsed.analysis?.kind === 'report' && (parsed.basis !== 'live_owner_recorded' || !jobFinalAnalysisVerified({
    startup: parsed.resources.startup, ending: parsed.resources.ending, nativeFailure: parsed.resources.nativeFailure,
    stop: parsed.resources.stop, closure: parsed.closure, failures: parsed.knownFailures,
  }))) reject();
  const infrastructure = exact(value.infrastructure, ['appFiles', 'appBytes', 'emptyConfigurationFiles', 'ownerIdentityBytes']);
  count(infrastructure.appFiles); count(infrastructure.appBytes); count(infrastructure.ownerIdentityBytes);
  if (infrastructure.emptyConfigurationFiles !== 1) reject();
  const retained = exact(value.retained, ['logicalLimit', 'payloadAdmittedBytesBeforeMetadata', 'filesBeforeMetadata', 'metadataBytesMaximum', 'maxFiles']);
  if (retained.logicalLimit !== limits.retainedBytes || retained.maxFiles !== 11 || count(retained.filesBeforeMetadata) > 10
    || count(retained.payloadAdmittedBytesBeforeMetadata) + count(retained.metadataBytesMaximum, true) > limits.retainedBytes) reject();
  if (!['PASS', 'REVIEW', 'INCOMPLETE', 'FAIL', 'ERROR'].includes(String(value.gate)) || value.exitCode !== exitCodes[value.gate as Gate]) reject();
  for (const code of array(value.reasons)) if (typeof code !== 'string' || !/^[A-Za-z0-9_.:-]{1,200}$/.test(code)) reject();
  return value as unknown as JobReport;
}

export async function readJobRegular(file: string, maximum: number): Promise<Buffer> {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || await canonical(file) !== file) reject();
  return boundedRead(file, maximum);
}
