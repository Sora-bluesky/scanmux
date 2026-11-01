import path from 'node:path';
import { open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type { Comparison, Engine, Report } from './model.ts';
import { catalogIdentity } from './advisory-catalog.ts';
import { summarizeHistory } from './history.ts';
import { renderSarifReports } from './sarif-report.ts';
import { commitPair, comparisonSummary } from './comparison.ts';
import { decide, exitCodes } from './policy.ts';
import { array, digest, hash, record, safeRelative, SafeError } from './safety.ts';
import { jobFinalAnalysisVerified, jobReference, parseJobJson, readJobRegular, validateJobPlan, validateJobCompletion,
  validateJobBootstrap, validateReproductionOperation, type ExpectedJobPlan, type JobCompletionFacts, type JobFileReference, type JobPlan } from './job-records.ts';
import type { JobProfile } from './job-config.ts';
import type { AssembledJobMessage } from '../internal/job-channel.mjs';

export interface FindingSelection { readonly engine: Engine; readonly fingerprint: string }
export type VerificationMode = { readonly kind: 'snapshot'; readonly requirement: 'supporting' | 'required' }
  | { readonly kind: 'before_after'; readonly base: string; readonly head: string };
export interface VerificationRequest { readonly reportPath: string; readonly finding: FindingSelection; readonly testDirectory: string; readonly mode: VerificationMode }
export interface SnapshotIdentity { readonly commit: string; readonly tree: string; readonly snapshotHash: string }
export interface TestFile { readonly path: string; readonly mode: '100644' | '100755'; readonly bytes: number; readonly sha256: string }
export interface TestRuntime { readonly imageDigest: string; readonly profileSha256: string; readonly nodeVersion: string; readonly driverSha256: string; readonly assetsSha256: string }
export interface TestIdentity {
  readonly directory: string; readonly entry: 'test.mjs'; readonly files: readonly TestFile[]; readonly manifestSha256: string;
  readonly driverSha256: string; readonly runtime: TestRuntime; readonly protocol: 'scanmux.probe/v1'; readonly testId: string;
}
export type TestGuard = { readonly kind: 'single_snapshot' | 'unchanged'; readonly test: TestIdentity }
  | { readonly kind: 'not_checked'; readonly reason: 'environment_missing' | 'job_failed' }
  | { readonly kind: 'rejected'; readonly reason: 'test_missing' | 'test_changed' | 'unsafe_test_path' | 'unsupported_test' };
export type ProbeObservation = { kind: 'observed'; problem: 'present' | 'absent' }
  | { kind: 'environment_missing'; reason: 'offline_dependency_missing' | 'fixture_missing' | 'runtime_not_available' };
export type ProbeResult = { readonly kind: 'completed'; readonly outcome: 'reproduced' | 'not_reproduced' }
  | { readonly kind: 'environment_missing'; readonly reason: 'image_not_available' | 'runtime_not_available' | 'offline_dependency_missing' | 'fixture_missing' }
  | { readonly kind: 'failed'; readonly reason: 'test_error' | 'invalid_observation' | 'timeout' | 'resource_limit' | 'cancelled' | 'integrity_error' }
  | { readonly kind: 'not_run'; readonly reason: 'test_guard_rejected' | 'before_unavailable' };
export interface Binding {
  readonly snapshot: SnapshotIdentity; readonly sourceSnapshot: SnapshotIdentity; readonly side: ReproductionOperation['side']; readonly executionPlanHash: string;
  readonly finding: FindingSelection; readonly sourceReportSha256: string; readonly testId: string;
}
export interface FileReference extends JobFileReference { readonly path: string }
export interface AdmittedVerification {
  readonly targetRoot: string; readonly report: Report; readonly selection: FindingSelection; readonly sourceSnapshot: SnapshotIdentity;
  readonly sourceReportSha256: string; readonly sourcePlanHash: string; readonly testDirectory: string; readonly mode: VerificationMode;
}
export interface ReproductionOperation {
  readonly kind: 'reproduction'; readonly side: 'snapshot' | 'before' | 'after'; readonly commit: string; readonly sourceSnapshot: SnapshotIdentity;
  readonly finding: FindingSelection; readonly sourceReportSha256: string; readonly testDirectory: string; readonly mode: VerificationMode; readonly expectedTest: TestIdentity | null;
}
export interface ReproductionPlan {
  readonly schema: 'scanmux.reproduction-plan/v1'; readonly operation: ReproductionOperation; readonly job: JobPlan;
  readonly testModes: Readonly<Record<string, TestFile['mode']>>; readonly testGuard: TestGuard;
}
export interface ReproductionJobReceipt {
  readonly schema: 'scanmux.reproduction-job/v1'; readonly expected: ExpectedJobPlan; readonly operation: ReproductionOperation;
  readonly plan: JobFileReference | null; readonly observation: JobFileReference | null; readonly owner: JobFileReference | null;
  readonly facts: JobCompletionFacts; readonly outcome: ProbeResult; readonly rawOutputRetained: false;
}
declare const recorded: unique symbol;
export type RecordedAttempt = ProbeResult & { readonly commit: string; readonly binding: Binding | null; readonly receipt: FileReference;
  readonly job: { readonly jobId: string; readonly imageDigest: string; readonly profileSha256: string; readonly container: 'verified_removed' } | null; readonly [recorded]: true };
export type Attempts = { readonly kind: 'snapshot'; readonly attempt: RecordedAttempt }
  | { readonly kind: 'before_after'; readonly before: RecordedAttempt; readonly after: RecordedAttempt | { readonly kind: 'not_run'; readonly reason: 'before_unavailable' } };
export type VerificationConclusion = { readonly kind: 'reproduced' | 'not_reproduced' }
  | { readonly kind: 'same_test_no_longer_reproduces'; readonly statement: 'The same test no longer reproduces at head, with the test unchanged.' }
  | { readonly kind: 'not_verified'; readonly reason: 'environment_missing' | 'test_failed' | 'test_guard_rejected' | 'before_not_reproduced' | 'still_reproduces' | 'integrity_error' };
export interface RuntimeEvidence { readonly state: 'runtime_reproduced'; readonly binding: Binding; readonly attemptReceipt: FileReference; readonly [recorded]: true }
export interface VerificationRecord {
  readonly schema: 'scanmux.verification/v1'; readonly verificationId: string; readonly sourceReport: FileReference; readonly finding: FindingSelection;
  readonly mode: VerificationMode; readonly requirement: 'supporting' | 'required'; readonly comparison: Comparison | null; readonly testGuard: TestGuard;
  readonly attempts: Attempts | null; readonly verification: VerificationConclusion; readonly runtimeEvidence: RuntimeEvidence | null;
  readonly assessment: { readonly scope: 'source_report_snapshot'; readonly gate: Report['gate']; readonly exitCode: number; readonly reasons: readonly string[] };
  readonly classification: 'confidential'; readonly rawOutputRetained: false; readonly files: readonly FileReference[];
}
export interface VerificationBundle { readonly verification: VerificationConclusion; readonly assessment: VerificationRecord['assessment']; readonly files: { readonly json: string; readonly html: string; readonly sarif: string } }
const liveAttempts = new WeakMap<object, TestIdentity | null>(), liveEvidence = new WeakMap<object, { report: Report; finding: FindingSelection }>(), admittedSources = new WeakSet<object>();
function frozen<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const item of Object.values(value)) frozen(item); Object.freeze(value); }
  return value;
}
const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
function requireValue(value: unknown): asserts value { if (!value) throw new SafeError('invalid_reproduction_record'); }
function exact(input: unknown, keys: readonly string[]) {
  const value = record(input); requireValue(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))); return value;
}
function text(input: unknown, pattern: RegExp): string { requireValue(typeof input === 'string' && pattern.test(input)); return input; }
const sha = (input: unknown) => text(input, /^[a-f0-9]{64}$/);
const commit = (input: unknown) => text(input, /^[a-f0-9]{40}$/);
export function testDirectory(input: unknown): string {
  const directory = safeRelative(input); requireValue(!directory.split('/').some(part => part.normalize('NFC').toLowerCase() === '.git')); return directory;
}
function selection(input: unknown): FindingSelection {
  const value = exact(input, ['engine', 'fingerprint']);
  if (value.engine === 'trivy') throw new SafeError('reproduction_trivy_unsupported');
  requireValue(['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].includes(String(value.engine)));
  return { engine: value.engine as FindingSelection['engine'], fingerprint: sha(value.fingerprint) };
}
export function verificationMode(input: unknown): VerificationMode {
  const value = record(input);
  if (value.kind === 'snapshot') {
    exact(value, ['kind', 'requirement']); requireValue(value.requirement === 'supporting' || value.requirement === 'required');
    return { kind: 'snapshot', requirement: value.requirement };
  }
  exact(value, ['kind', 'base', 'head']); requireValue(value.kind === 'before_after');
  const pair = commitPair(value.base, value.head)!; requireValue(pair.base !== pair.head); return { kind: 'before_after', ...pair };
}
export function snapshotIdentity(plan: Report['plan']): SnapshotIdentity { return { commit: commit(plan.commit), tree: commit(plan.treeHash), snapshotHash: sha(plan.snapshotHash) }; }
export function admitVerification(targetRoot: string, bytes: Buffer, request: unknown): AdmittedVerification {
  const input = exact(request, ['reportPath', 'finding', 'testDirectory', 'mode']); requireValue(typeof input.reportPath === 'string' && input.reportPath.length > 0);
  const finding = selection(input.finding), directory = testDirectory(input.testDirectory), mode = verificationMode(input.mode);
  const value = exact(parseJobJson(bytes), ['schema', 'runId', 'plan', 'startedAt', 'endedAt', 'engines', 'runner', 'executionState', 'coverageState', 'gate', 'reasons', 'exitCode', 'integrityErrors']);
  summarizeHistory([bytes]);
  const report = value as unknown as Report, plan = report.plan;
  requireValue((plan.root === targetRoot || plan.root === '/repo/' + hash(targetRoot)) && plan.repoId === hash(plan.root)
    && plan.planHash === digest({ ...plan, planHash: '' }) && plan.snapshotHash === digest(plan.files) && isDeepStrictEqual(plan.advisoryCatalog, catalogIdentity));
  sha(plan.policyHash); snapshotIdentity(plan); comparisonSummary(plan);
  const names = new Set<string>();
  for (const file of plan.files) {
    const name = safeRelative(file.path), key = name.normalize('NFC').toLowerCase();
    requireValue(!names.has(key) && !key.split('/').includes('.git') && Number.isSafeInteger(file.bytes) && file.bytes >= 0); names.add(key); sha(file.sha256); commit(file.oid);
  }
  renderSarifReports(report, Math.max(bytes.length * 16, 1048576));
  const selected = report.engines.flatMap(run => run.findings.filter(item => { requireValue(item.engine === run.engine); return item.engine === finding.engine && item.fingerprint === finding.fingerprint; }));
  requireValue(selected.length === 1 && ['candidate', 'source_supported'].includes(selected[0].evidenceState));
  const judgment = decide(plan, report.engines, report.integrityErrors);
  requireValue(report.gate === judgment.gate && report.exitCode === exitCodes[judgment.gate] && isDeepStrictEqual(report.reasons, judgment.reasons));
  if (mode.kind === 'before_after') requireValue(plan.commit === mode.base);
  const source = frozen({ targetRoot, report, selection: finding, sourceSnapshot: snapshotIdentity(plan), sourceReportSha256: hash(bytes), sourcePlanHash: plan.planHash, testDirectory: directory, mode });
  admittedSources.add(source); return source;
}
export function testIdentity(directory: string, input: readonly TestFile[], runtime: TestRuntime): TestIdentity {
  testDirectory(directory); requireValue(input.length > 0 && input.length <= 10000);
  text(runtime.imageDigest, /^sha256:[a-f0-9]{64}$/); sha(runtime.profileSha256); sha(runtime.driverSha256); sha(runtime.assetsSha256); text(runtime.nodeVersion, /^\d+\.\d+\.\d+$/);
  const names = new Map<string, string>(), files = [...input].map(file => {
    exact(file, ['path', 'mode', 'bytes', 'sha256']);
    const name = safeRelative(file.path); requireValue(name.startsWith(directory + '/') && ['100644', '100755'].includes(file.mode) && Number.isSafeInteger(file.bytes) && file.bytes >= 0); sha(file.sha256);
    const parts = name.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const prefix = parts.slice(0, i).join('/'), key = prefix.normalize('NFC').toLowerCase();
      requireValue(!names.has(key) || names.get(key) === prefix && i !== parts.length); names.set(key, prefix);
    }
    return { path: name, mode: file.mode, bytes: file.bytes, sha256: file.sha256 };
  }).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  requireValue(files.some(file => file.path === directory + '/test.mjs'));
  const identity = { directory, entry: 'test.mjs' as const, files, manifestSha256: digest(files), driverSha256: runtime.driverSha256,
    runtime: { imageDigest: runtime.imageDigest, profileSha256: runtime.profileSha256, nodeVersion: runtime.nodeVersion, driverSha256: runtime.driverSha256, assetsSha256: runtime.assetsSha256 }, protocol: 'scanmux.probe/v1' as const };
  return { ...identity, testId: digest({ ...identity, invocation: probeInvocation }) };
}
export const probeInvocation = { executable: '/usr/local/bin/node', driver: '/app/internal/reproduction-driver.mjs', root: '/work/snapshot', cwd: '/work',
  environment: { HOME: '/work', TMPDIR: '/tmp', TMP: '/tmp', TEMP: '/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', NO_COLOR: '1' } } as const;
export function validateTestIdentity(input: unknown): TestIdentity {
  const value = exact(input, ['directory', 'entry', 'files', 'manifestSha256', 'driverSha256', 'runtime', 'protocol', 'testId']);
  const runtime = exact(value.runtime, ['imageDigest', 'profileSha256', 'nodeVersion', 'driverSha256', 'assetsSha256']) as unknown as TestRuntime;
  const identity = testIdentity(testDirectory(value.directory), array(value.files) as unknown as TestFile[], runtime);
  requireValue(isDeepStrictEqual(value, identity)); return identity;
}
export function guardTest(before: TestIdentity, after?: TestIdentity): TestGuard {
  validateTestIdentity(before); if (after) validateTestIdentity(after);
  return after && !isDeepStrictEqual(before, after) ? { kind: 'rejected', reason: 'test_changed' } : { kind: after ? 'unchanged' : 'single_snapshot', test: before };
}
export function matchesBinding(expected: Binding, actual: Binding): boolean {
  return isDeepStrictEqual(expected.snapshot, actual.snapshot) && isDeepStrictEqual(expected.sourceSnapshot, actual.sourceSnapshot) && expected.side === actual.side && isDeepStrictEqual(expected.finding, actual.finding)
    && expected.sourceReportSha256 === actual.sourceReportSha256 && expected.testId === actual.testId;
}
export function verificationDecision(mode: VerificationMode, guard: TestGuard, before?: ProbeResult, after?: ProbeResult): VerificationConclusion {
  const refused = (reason: Extract<VerificationConclusion, { kind: 'not_verified' }>['reason']): VerificationConclusion => ({ kind: 'not_verified', reason });
  if ([before, after].some(attempt => attempt?.kind === 'failed' && attempt.reason === 'integrity_error')) return refused('integrity_error');
  if (guard.kind === 'rejected') return refused('test_guard_rejected');
  if (before?.kind === 'environment_missing' || after?.kind === 'environment_missing') return refused('environment_missing');
  if (before?.kind !== 'completed') return refused('test_failed');
  if (mode.kind === 'snapshot') return { kind: before.outcome === 'reproduced' ? 'reproduced' : 'not_reproduced' };
  if (before.outcome !== 'reproduced') return refused('before_not_reproduced');
  if (after?.kind !== 'completed') return refused('test_failed');
  if (after.outcome === 'reproduced') return refused('still_reproduces');
  if (guard.kind !== 'unchanged') return refused('test_guard_rejected');
  return { kind: 'same_test_no_longer_reproduces', statement: 'The same test no longer reproduces at head, with the test unchanged.' };
}
export function verificationPolicy(report: Report, finding: FindingSelection, evidence: RuntimeEvidence | null, incomplete: boolean, integrityErrors: string[] = []): VerificationRecord['assessment'] {
  const owner = evidence ? liveEvidence.get(evidence) : null, trusted = owner?.report === report && isDeepStrictEqual(owner.finding, finding);
  const engines = report.engines.map(run => ({ ...run, findings: run.findings.map(item => trusted && item.engine === finding.engine && item.fingerprint === finding.fingerprint
    ? { ...item, evidenceState: 'runtime_reproduced' as const } : item) }));
  const judgment = decide({ ...report.plan, blockers: [...report.plan.blockers, ...(incomplete ? ['required_reproduction_incomplete'] : [])] }, engines, [...report.integrityErrors, ...integrityErrors]);
  return { scope: 'source_report_snapshot', ...judgment, exitCode: exitCodes[judgment.gate] };
}

export function validateProbeResult(input: unknown): ProbeResult {
  const value = record(input);
  if (value.kind === 'completed') { exact(value, ['kind', 'outcome']); requireValue(['reproduced', 'not_reproduced'].includes(String(value.outcome))); }
  else {
    exact(value, ['kind', 'reason']);
    requireValue(value.kind === 'environment_missing' ? ['image_not_available', 'runtime_not_available', 'offline_dependency_missing', 'fixture_missing'].includes(String(value.reason))
      : value.kind === 'failed' ? ['test_error', 'invalid_observation', 'timeout', 'resource_limit', 'cancelled', 'integrity_error'].includes(String(value.reason))
        : value.kind === 'not_run' && ['test_guard_rejected', 'before_unavailable'].includes(String(value.reason)));
  }
  return value as unknown as ProbeResult;
}
function validateGuard(input: unknown, operation: ReproductionOperation, expected: ExpectedJobPlan): TestGuard {
  const value = record(input);
  if (value.kind === 'single_snapshot' || value.kind === 'unchanged') {
    exact(value, ['kind', 'test']); const test = validateTestIdentity(value.test);
    requireValue(test.directory === operation.testDirectory && value.kind === (operation.mode.kind === 'snapshot' ? 'single_snapshot' : 'unchanged'));
    const driver = expected.runtime.app.find(file => file.path === 'internal/reproduction-driver.mjs');
    requireValue(test.runtime.imageDigest === expected.image && test.runtime.profileSha256 === expected.profileSha256 && test.runtime.nodeVersion === expected.runtime.nodeVersion
      && test.driverSha256 === driver?.sha256 && test.runtime.assetsSha256 === digest(expected.runtime.app));
    if (operation.expectedTest) requireValue(isDeepStrictEqual(test, operation.expectedTest));
  } else {
    exact(value, ['kind', 'reason']); requireValue(value.kind === 'rejected' ? ['test_missing', 'test_changed', 'unsafe_test_path', 'unsupported_test'].includes(String(value.reason))
      : value.kind === 'not_checked' && value.reason === 'job_failed');
  }
  return value as unknown as TestGuard;
}
export function validateReproductionPlan(input: unknown, expected: ExpectedJobPlan, operation: ReproductionOperation): ReproductionPlan {
  const value = exact(input, ['schema', 'operation', 'job', 'testModes', 'testGuard']);
  requireValue(value.schema === 'scanmux.reproduction-plan/v1' && isDeepStrictEqual(value.operation, operation));
  validateReproductionOperation(operation, expected);
  const job = validateJobPlan(value.job, expected), guard = validateGuard(value.testGuard, operation, expected);
  const inside = (name: string) => name.startsWith(operation.testDirectory + '/');
  const files = new Map(job.plan.files.filter(file => inside(file.path)).map(file => [file.path, file])), modes = record(value.testModes);
  requireValue(Object.keys(modes).length === files.size && Object.entries(modes).every(([name, mode]) => files.has(name) && (mode === '100644' || mode === '100755')));
  if ('test' in guard) {
    requireValue(!job.plan.blockers.length && !job.plan.exclusions.length && job.plan.commit === operation.commit);
    if (operation.side !== 'after') requireValue(isDeepStrictEqual(snapshotIdentity(job.plan), operation.sourceSnapshot));
    requireValue(files.size === guard.test.files.length && !job.plan.comparison?.changes.some(change => inside(change.path)));
    for (const file of guard.test.files) {
      const source = files.get(file.path);
      requireValue(source && modes[file.path] === file.mode && source.bytes === file.bytes && source.sha256 === file.sha256);
    }
  }
  return value as unknown as ReproductionPlan;
}
export function reproductionBinding(plan: ReproductionPlan): Binding | null {
  if (!('test' in plan.testGuard)) return null;
  return { snapshot: snapshotIdentity(plan.job.plan), sourceSnapshot: plan.operation.sourceSnapshot, side: plan.operation.side, executionPlanHash: plan.job.plan.planHash, finding: plan.operation.finding,
    sourceReportSha256: plan.operation.sourceReportSha256, testId: plan.testGuard.test.testId };
}
function validateProvisional(input: unknown, plan: ReproductionPlan) {
  const value = record(input); requireValue(value.schema === 'scanmux.reproduction-result/v1' && value.jobId === plan.job.jobId);
  const binding = reproductionBinding(plan);
  if (value.bindingDigest !== (binding ? digest(binding) : null)) return { kind: 'failed', reason: 'integrity_error' } as const;
  exact(value, ['schema', 'jobId', 'bindingDigest', 'result']);
  const result = validateProbeResult(value.result);
  requireValue(result.kind !== 'not_run' || result.reason === 'test_guard_rejected' && plan.testGuard.kind === 'rejected');
  requireValue(result.kind !== 'completed' && result.kind !== 'environment_missing' || 'test' in plan.testGuard);
  return result;
}
async function exclusive(file: string, bytes: Buffer) {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
function closed(facts: JobCompletionFacts) {
  const c = facts.closure;
  return c.startupVerified && c.supervisorClosed && c.ownedTasksClosure !== 'unverified' && c.containerAbsent && c.daemonHealthy && c.inputsUnchanged && c.terminal !== null;
}
function finalOutcome(facts: JobCompletionFacts, provisional: ProbeResult | null, environment: 'image_not_available' | 'runtime_not_available' | null): ProbeResult {
  if (environment) return facts.failures.length || facts.nativeFailure || !facts.closure.inputsUnchanged || facts.startup || facts.closure.terminal
    ? { kind: 'failed', reason: 'integrity_error' } : { kind: 'environment_missing', reason: environment };
  if (!closed(facts) || facts.failures.length || facts.nativeFailure || facts.startup && facts.ending && !isDeepStrictEqual(facts.startup.networkCounters, facts.ending.networkCounters)) return { kind: 'failed', reason: 'integrity_error' };
  if (facts.stop) return { kind: 'failed', reason: facts.stop.kind === 'cancelled' ? 'cancelled' : facts.stop.kind === 'deadline' ? 'timeout' : 'resource_limit' };
  return jobFinalAnalysisVerified(facts) && provisional ? provisional : { kind: 'failed', reason: 'integrity_error' };
}

/** The existing owner feeds this sink only for its closed reproduction operation. */
export class ReproductionRecordStore {
  readonly directory: string; readonly expected: ExpectedJobPlan; readonly operation: ReproductionOperation; readonly maximum: number; readonly retainedLimit: number;
  admittedBytes = 0; files = 0;
  plan: ReproductionPlan | null = null; planReference: JobFileReference | null = null; observationReference: JobFileReference | null = null;
  private provisional: ProbeResult | null = null;
  private pending: { seq: number; commit: () => void } | null = null;
  private stopped = false;
  private finalized = false;
  constructor(directory: string, profile: JobProfile, expected: ExpectedJobPlan, operation: ReproductionOperation, retainedBytes = profile.limits.retainedBytes) {
    validateReproductionOperation(operation, expected);
    requireValue(Number.isSafeInteger(retainedBytes) && retainedBytes >= 0 && retainedBytes <= profile.limits.retainedBytes);
    this.directory = directory; this.expected = expected; this.operation = operation; this.maximum = profile.scan.maxOutputBytes; this.retainedLimit = retainedBytes;
  }
  admitOwner(bytes: number) { requireValue(bytes <= this.maximum && this.admittedBytes + bytes <= this.retainedLimit); this.admittedBytes += bytes; this.files++; }
  private async save(name: string, bytes: Buffer) {
    requireValue(bytes.length <= this.maximum && this.admittedBytes + bytes.length <= this.retainedLimit);
    this.admittedBytes += bytes.length; this.files++;
    await exclusive(path.join(this.directory, name), bytes);
  }
  async persist(message: Extract<AssembledJobMessage, { type: 'record' }>): Promise<{ kind: 'ready' } | { kind: 'retained'; proposedBytes: number; availableBytes: number }> {
    try {
      requireValue(!this.pending && !this.stopped && !this.finalized && message.slot === 0 && message.parts.length === 1 && message.parts[0].length <= this.maximum);
      const bytes = message.parts[0], input = parseJobJson(bytes);
      let commitRecord: () => void, name: string;
      if (message.kind === 'plan') {
        requireValue(!this.plan); const plan = validateReproductionPlan(input, this.expected, this.operation); name = 'job-plan.json';
        commitRecord = () => { this.plan = plan; this.planReference = jobReference(bytes); };
      } else {
        requireValue(message.kind === 'report' && this.plan && !this.provisional);
        const result = validateProvisional(input, this.plan); name = 'observation.json';
        commitRecord = () => { this.provisional = result; this.observationReference = jobReference(bytes); };
      }
      const available = Math.max(0, this.retainedLimit - this.admittedBytes - this.maximum);
      if (bytes.length > available) { this.discardUnacceptedTail(); return { kind: 'retained', proposedBytes: bytes.length, availableBytes: available }; }
      await this.save(name, bytes); this.pending = { seq: message.ackSeq, commit: commitRecord }; return { kind: 'ready' };
    } catch (error) { this.discardUnacceptedTail(); throw error; }
  }
  acknowledge(sequence: number) { requireValue(!this.stopped && this.pending?.seq === sequence); this.pending.commit(); this.pending = null; }
  discardUnacceptedTail() { this.pending = null; this.provisional = null; this.stopped = true; }
  async complete(input: JobCompletionFacts, environment: 'image_not_available' | 'runtime_not_available' | null, ownerIdentityBytes: number) {
    requireValue(!this.finalized); this.finalized = true;
    const facts = validateJobCompletion(input, this.expected.limits);
    const outcome = finalOutcome(facts, this.stopped ? null : this.provisional, environment);
    const owner = ownerIdentityBytes ? jobReference(await readJobRegular(path.join(this.directory, 'owner.json'), this.maximum)) : null;
    const receipt: ReproductionJobReceipt = { schema: 'scanmux.reproduction-job/v1', expected: this.expected, operation: this.operation,
      plan: this.planReference, observation: this.observationReference, owner, facts, outcome, rawOutputRetained: false };
    const bytes = encode(receipt); await this.save('reproduction-job.json', bytes);
    return readReproductionJob(this.directory, this.maximum);
  }
}

export interface ReproductionJobBundle { readonly directory: string; readonly receipt: ReproductionJobReceipt; readonly attempt: RecordedAttempt; readonly plan: ReproductionPlan | null; readonly files: readonly FileReference[] }
export async function readReproductionJob(directory: string, maximum: number): Promise<ReproductionJobBundle> {
  const bytes = await readJobRegular(path.join(directory, 'reproduction-job.json'), maximum);
  const value = exact(parseJobJson(bytes), ['schema', 'expected', 'operation', 'plan', 'observation', 'owner', 'facts', 'outcome', 'rawOutputRetained']);
  requireValue(value.schema === 'scanmux.reproduction-job/v1' && value.rawOutputRetained === false);
  const rawExpected = record(value.expected), expected = validateJobBootstrap({ ...rawExpected, comparison: rawExpected.comparison ?? null });
  requireValue(bytes.length <= expected.config.maxOutputBytes);
  const operation = validateReproductionOperation(value.operation, expected), facts = validateJobCompletion(value.facts, expected.limits);
  const files: FileReference[] = [], receiptRef = { path: 'reproduction-job.json', ...jobReference(bytes) };
  const read = async (name: string, input: unknown) => {
    const reference = exact(input, ['bytes', 'sha256']);
    const data = await readJobRegular(path.join(directory, name), Math.min(maximum, expected.config.maxOutputBytes)); requireValue(isDeepStrictEqual(jobReference(data), reference));
    files.push({ path: name, ...jobReference(data) }); return parseJobJson(data);
  };
  const plan = value.plan === null ? null : validateReproductionPlan(await read('job-plan.json', value.plan), expected, operation);
  const provisional = value.observation === null ? null : (requireValue(plan), validateProvisional(await read('observation.json', value.observation), plan));
  if (value.owner !== null) {
    const owner = exact(await read('owner.json', value.owner), ['schema', 'jobId', 'containerId', 'name', 'image', 'label']);
    requireValue(owner.schema === 'scanmux.job-owner/v1' && owner.jobId === expected.jobId && owner.image === expected.image && owner.name === 'scanmux-job-' + expected.jobId && owner.label === 'scanmux.job'); sha(owner.containerId);
  }
  const outcome = validateProbeResult(value.outcome), unavailable = outcome.kind === 'environment_missing' && ['runtime_not_available', 'image_not_available'].includes(outcome.reason) && value.owner === null && plan === null;
  requireValue(!unavailable || value.observation === null && facts.startup === null && facts.closure.terminal === null && !facts.closure.startupVerified);
  const environment = unavailable && outcome.kind === 'environment_missing' ? outcome.reason as 'image_not_available' | 'runtime_not_available' : null;
  const final = finalOutcome(facts, provisional, environment);
  if (!isDeepStrictEqual(outcome, final) && final.kind === 'failed' && final.reason === 'integrity_error') throw new SafeError('integrity_error');
  requireValue(isDeepStrictEqual(outcome, final));
  requireValue(outcome.kind !== 'completed' || plan && value.owner !== null && jobFinalAnalysisVerified(facts) && !facts.failures.length);
  const job = closed(facts) && value.owner !== null ? { jobId: expected.jobId, imageDigest: expected.image, profileSha256: expected.profileSha256, container: 'verified_removed' as const } : null;
  const attempt = frozen({ ...outcome, commit: operation.commit, binding: plan ? reproductionBinding(plan) : null, receipt: receiptRef, job }) as RecordedAttempt;
  liveAttempts.set(attempt, plan && 'test' in plan.testGuard ? plan.testGuard.test : null); files.push(receiptRef);
  requireValue(files.reduce((sum, file) => sum + file.bytes, 0) <= expected.limits.retainedBytes);
  return { directory, receipt: value as unknown as ReproductionJobReceipt, attempt, plan, files };
}
function runtimeEvidenceFor(source: AdmittedVerification, attempt?: RecordedAttempt): RuntimeEvidence | null {
  const test = attempt ? liveAttempts.get(attempt) : null;
  if (!attempt || !test || test.directory !== source.testDirectory || attempt.kind !== 'completed' || attempt.outcome !== 'reproduced' || !attempt.job || !attempt.binding) return null;
  const expected: Binding = { snapshot: source.sourceSnapshot, sourceSnapshot: source.sourceSnapshot, side: source.mode.kind === 'snapshot' ? 'snapshot' : 'before',
    executionPlanHash: source.sourcePlanHash, finding: source.selection, sourceReportSha256: source.sourceReportSha256, testId: test.testId };
  if (!matchesBinding(expected, attempt.binding)) return null;
  const evidence = frozen({ state: 'runtime_reproduced', binding: attempt.binding, attemptReceipt: attempt.receipt }) as RuntimeEvidence;
  liveEvidence.set(evidence, { report: source.report, finding: source.selection }); return evidence;
}
export function assessVerification(source: AdmittedVerification, guard: TestGuard, attempts: Attempts | null) {
  requireValue(admittedSources.has(source));
  if ('test' in guard) { validateTestIdentity(guard.test); requireValue(guard.test.directory === source.testDirectory); }
  const before = attempts?.kind === 'snapshot' ? attempts.attempt : attempts?.before, after = attempts?.kind === 'before_after' ? attempts.after : undefined;
  const actual = [before, after].filter((item): item is RecordedAttempt => !!item && 'receipt' in item);
  const invalid = actual.some(item => !liveAttempts.has(item) || !isDeepStrictEqual(item.binding?.finding ?? source.selection, source.selection)
    || item.binding && (!isDeepStrictEqual(item.binding.sourceSnapshot, source.sourceSnapshot) || item.binding.sourceReportSha256 !== source.sourceReportSha256)
    || item.binding && 'test' in guard && item.binding.testId !== guard.test.testId);
  const wrongSource = before?.binding && !isDeepStrictEqual(before.binding.snapshot, source.sourceSnapshot);
  const wrongSide = before?.binding && before.binding.side !== (source.mode.kind === 'snapshot' ? 'snapshot' : 'before') || after && 'binding' in after && after.binding && after.binding.side !== 'after';
  const wrongPair = source.mode.kind === 'before_after' && (before && before.commit !== source.mode.base || after && 'commit' in after && after.commit !== source.mode.head
    || before?.job && after && 'job' in after && after.job && (before.job.imageDigest !== after.job.imageDigest || before.job.profileSha256 !== after.job.profileSha256));
  const verification: VerificationConclusion = invalid || wrongSource || wrongSide || wrongPair ? { kind: 'not_verified', reason: 'integrity_error' } : verificationDecision(source.mode, guard, before, after);
  const runtimeEvidence = verification.kind === 'not_verified' && verification.reason === 'integrity_error' ? null : runtimeEvidenceFor(source, before);
  const incomplete = verification.kind === 'not_verified';
  const assessment = verificationPolicy(source.report, source.selection, runtimeEvidence, incomplete, verification.kind === 'not_verified' && verification.reason === 'integrity_error' ? ['reproduction_integrity_error'] : []);
  const gate = incomplete && (assessment.gate === 'PASS' || assessment.gate === 'REVIEW') ? 'INCOMPLETE' : assessment.gate;
  return { verification, runtimeEvidence, assessment: { ...assessment, gate, exitCode: exitCodes[gate] } };
}

function locatedAttempt(attempt: RecordedAttempt, prefix: string): RecordedAttempt {
  requireValue(liveAttempts.has(attempt));
  const located = frozen({ ...attempt, receipt: { ...attempt.receipt, path: prefix + '/reproduction-job.json' } }) as RecordedAttempt;
  liveAttempts.set(located, liveAttempts.get(attempt)!); return located;
}
function attemptsFor(mode: VerificationMode, jobs: readonly ReproductionJobBundle[]): Attempts {
  requireValue(jobs.length >= 1 && jobs.length <= (mode.kind === 'snapshot' ? 1 : 2));
  const before = locatedAttempt(jobs[0].attempt, mode.kind === 'snapshot' ? 'snapshot' : 'before');
  return mode.kind === 'snapshot' ? { kind: 'snapshot', attempt: before } : { kind: 'before_after', before,
    after: jobs[1] ? locatedAttempt(jobs[1].attempt, 'after') : { kind: 'not_run', reason: 'before_unavailable' } };
}
function guardFor(jobs: readonly ReproductionJobBundle[]): TestGuard {
  const first = jobs[0], second = jobs[1];
  return second?.plan?.testGuard.kind === 'rejected' ? second.plan.testGuard : first.plan?.testGuard
    ?? { kind: 'not_checked', reason: first.attempt.kind === 'environment_missing' ? 'environment_missing' : 'job_failed' };
}
function renderVerification(record: VerificationRecord) {
  const conclusion = record.verification.kind === 'same_test_no_longer_reproduces' ? record.verification.statement : record.verification.kind;
  const escape = (text: string) => text.replace(/[&<>"']/g, value => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[value]!);
  const html = '<!doctype html>\n<html lang="en"><meta charset="utf-8"><title>ScanMux reproduction</title><body><h1>ScanMux reproduction</h1>'
    + '<p>' + escape(conclusion) + '</p><table><tr><th>Verification</th><td>' + escape(record.verificationId) + '</td></tr>'
    + '<tr><th>Finding</th><td>' + escape(record.finding.engine + ':' + record.finding.fingerprint) + '</td></tr><tr><th>Historical source gate</th><td>'
    + escape(record.assessment.gate) + '</td></tr><tr><th>Scope</th><td>The nominated test only; source report snapshot policy.</td></tr></table>'
    + '<p>Confidential local evidence. No raw test output retained.</p><a href="verification.json">Verification manifest</a></body></html>\n';
  const attempts = record.attempts?.kind === 'snapshot' ? [record.attempts.attempt] : record.attempts ? [record.attempts.before, record.attempts.after] : [];
  const sarif = JSON.stringify({ version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json', runs: [{ tool: { driver: { name: 'ScanMux reproduction', rules: [{ id: 'scanmux.reproduction' }] } },
    invocations: [{ executionSuccessful: record.verification.kind !== 'not_verified', properties: { 'scanmux.verificationId': record.verificationId, 'scanmux.manifest': 'verification.json',
      'scanmux.scope': 'nominated_test_only', 'scanmux.historicalSourceGate': record.assessment.gate } }],
    results: [{ ruleId: 'scanmux.reproduction', level: 'note', message: { text: conclusion }, partialFingerprints: { 'scanmux.sourceFingerprint': record.finding.fingerprint },
      properties: { 'scanmux.sourceReport': record.sourceReport, 'scanmux.finding': record.finding, 'scanmux.verification': record.verification,
        'scanmux.attempts': attempts.map(attempt => 'receipt' in attempt ? { receipt: attempt.receipt, binding: attempt.binding, outcome: attempt.kind } : attempt),
        'scanmux.evidence': record.runtimeEvidence, 'scanmux.assessment': record.assessment } }] }] }, null, 2) + '\n';
  return { html: Buffer.from(html), sarif: Buffer.from(sarif) };
}
export async function publishVerification(directory: string, sourceBytes: Buffer, source: AdmittedVerification,
  jobs: readonly ReproductionJobBundle[], profile: JobProfile): Promise<VerificationBundle> {
  const files: FileReference[] = [], maximum = profile.scan.maxOutputBytes;
  const save = async (name: string, bytes: Buffer) => {
    requireValue(bytes.length <= maximum); await exclusive(path.join(directory, ...name.split('/')), bytes); files.push({ path: name, ...jobReference(bytes) });
  };
  requireValue(hash(sourceBytes) === source.sourceReportSha256);
  await save('source-report.json', sourceBytes);
  for (const [index, job] of jobs.entries()) {
    const prefix = index === 0 ? source.mode.kind === 'snapshot' ? 'snapshot' : 'before' : 'after';
    requireValue(job.directory === path.join(directory, prefix));
    for (const reference of job.files) {
      const bytes = await readJobRegular(path.join(job.directory, reference.path), maximum);
      requireValue(isDeepStrictEqual(jobReference(bytes), { bytes: reference.bytes, sha256: reference.sha256 }));
      files.push({ ...reference, path: prefix + '/' + reference.path });
    }
  }
  const attempts = attemptsFor(source.mode, jobs), guard = guardFor(jobs);
  const record: VerificationRecord = { schema: 'scanmux.verification/v1', verificationId: randomUUID(), sourceReport: files[0], finding: source.selection, mode: source.mode,
    requirement: source.mode.kind === 'before_after' ? 'required' : source.mode.requirement, comparison: source.mode.kind === 'before_after' ? jobs[1]?.plan?.job.plan.comparison ?? null : null,
    testGuard: guard, attempts, ...assessVerification(source, guard, attempts), classification: 'confidential', rawOutputRetained: false, files };
  const rendered = renderVerification(record);
  requireValue(rendered.html.length <= maximum && rendered.sarif.length <= maximum);
  files.push({ path: 'verification.html', ...jobReference(rendered.html) }, { path: 'verification.sarif.json', ...jobReference(rendered.sarif) });
  const json = encode(record);
  requireValue(json.length <= maximum && files.reduce((sum, file) => sum + file.bytes, json.length) <= profile.limits.retainedBytes);
  await exclusive(path.join(directory, 'verification.html'), rendered.html); await exclusive(path.join(directory, 'verification.sarif.json'), rendered.sarif);
  // The final manifest is the only completion marker; its own hash is not circular.
  await exclusive(path.join(directory, 'verification.json'), json);
  return { verification: record.verification, assessment: record.assessment,
    files: { json: path.join(directory, 'verification.json'), html: path.join(directory, 'verification.html'), sarif: path.join(directory, 'verification.sarif.json') } };
}
export async function readVerification(directory: string, maximum = 16 * 1024 * 1024): Promise<VerificationRecord> {
  const bytes = await readJobRegular(path.join(directory, 'verification.json'), maximum);
  const value = exact(parseJobJson(bytes), ['schema', 'verificationId', 'sourceReport', 'finding', 'mode', 'requirement', 'comparison', 'testGuard', 'attempts',
    'verification', 'runtimeEvidence', 'assessment', 'classification', 'rawOutputRetained', 'files']);
  requireValue(value.schema === 'scanmux.verification/v1' && value.classification === 'confidential' && value.rawOutputRetained === false);
  text(value.verificationId, /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/);
  const mode = verificationMode(value.mode), finding = selection(value.finding), files = array(value.files), names = new Set<string>();
  requireValue(files.length <= 11);
  for (const raw of files) {
    const file = exact(raw, ['path', 'bytes', 'sha256']), name = safeRelative(file.path);
    requireValue(/^(?:source-report\.json|verification\.(?:html|sarif\.json)|(?:snapshot|before|after)\/(?:job-plan\.json|observation\.json|owner\.json|reproduction-job\.json))$/.test(name) && !names.has(name)); names.add(name);
    const data = await readJobRegular(path.join(directory, ...name.split('/')), maximum);
    requireValue(isDeepStrictEqual(jobReference(data), { bytes: file.bytes, sha256: file.sha256 }));
  }
  const jobs: ReproductionJobBundle[] = [];
  const first = mode.kind === 'snapshot' ? 'snapshot' : 'before';
  jobs.push(await readReproductionJob(path.join(directory, first), maximum));
  if (names.has('after/reproduction-job.json')) { requireValue(mode.kind === 'before_after'); jobs.push(await readReproductionJob(path.join(directory, 'after'), maximum)); }
  const sourceBytes = await readJobRegular(path.join(directory, 'source-report.json'), maximum), initial = jobs[0].receipt;
  const source = admitVerification(initial.expected.root, sourceBytes, { reportPath: 'source-report.json', finding, mode, testDirectory: initial.operation.testDirectory });
  for (const [index, job] of jobs.entries()) {
    const op = job.receipt.operation;
    requireValue(isDeepStrictEqual(op.mode, mode) && isDeepStrictEqual(op.finding, source.selection) && isDeepStrictEqual(op.sourceSnapshot, source.sourceSnapshot)
      && op.sourceReportSha256 === source.sourceReportSha256 && op.testDirectory === source.testDirectory && job.receipt.expected.root === source.targetRoot
      && op.side === (index ? 'after' : mode.kind === 'snapshot' ? 'snapshot' : 'before'));
  }
  if (jobs[1]) requireValue(jobs[0].attempt.kind === 'completed' && jobs[0].plan && 'test' in jobs[0].plan.testGuard
    && isDeepStrictEqual(jobs[1].receipt.operation.expectedTest, jobs[0].plan.testGuard.test));
  const expectedFiles = [{ path: 'source-report.json', ...jobReference(sourceBytes) }, ...jobs.flatMap((job, index) => job.files.map(file => ({ ...file, path: (index ? 'after' : first) + '/' + file.path })))];
  for (const name of ['verification.html', 'verification.sarif.json']) expectedFiles.push({ path: name, ...jobReference(await readJobRegular(path.join(directory, name), maximum)) });
  requireValue(isDeepStrictEqual(files, expectedFiles) && isDeepStrictEqual(value.sourceReport, expectedFiles[0]));
  const guard = guardFor(jobs), attempts = attemptsFor(mode, jobs), assessed = assessVerification(source, guard, attempts);
  const derived = { requirement: mode.kind === 'before_after' ? 'required' : mode.requirement, comparison: mode.kind === 'before_after' ? jobs[1]?.plan?.job.plan.comparison ?? null : null,
    testGuard: guard, attempts, ...assessed };
  for (const [key, expected] of Object.entries(derived)) requireValue(isDeepStrictEqual(value[key], expected));
  const result = value as unknown as VerificationRecord, rendered = renderVerification(result);
  requireValue(isDeepStrictEqual(jobReference(rendered.html), jobReference(await readJobRegular(path.join(directory, 'verification.html'), maximum)))
    && isDeepStrictEqual(jobReference(rendered.sarif), jobReference(await readJobRegular(path.join(directory, 'verification.sarif.json'), maximum))));
  requireValue(bytes.length <= initial.expected.config.maxOutputBytes && expectedFiles.every(file => file.bytes <= initial.expected.config.maxOutputBytes)
    && bytes.length + expectedFiles.reduce((sum, file) => sum + file.bytes, 0) <= initial.expected.limits.retainedBytes);
  return result;
}
