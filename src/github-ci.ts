import path from 'node:path';
import { lstat, mkdir, readdir, writeFile } from 'node:fs/promises';
import type { Config, Gate, Tool } from './model.ts';
import { evaluateCi, parseCiExpectation, parseCiReceipt } from './ci.ts';
import { exitCodes } from './policy.ts';
import { execute, verifyVersion } from './process.ts';
import { checkedJson } from './output.ts';
import { privateWorkspace } from './private-storage.ts';
import { boundedRead, canonical, digest, hash, record, safeRelative, SafeError } from './safety.ts';
import { readZip } from './zip-archive.ts';

export const producerWorkflowPath = '.github/workflows/offline-selfscan.yml';
export const testsWorkflowPath = '.github/workflows/checks.yml';
export const approvedPinsSha256 = '5d0130fe81e12d031c445dddd4ee406d6c88302e16f43744267ea43d52bb1ea1';
export const producerWorkflowSha256 = 'd70603fcdd654ebae1e1ab7f5f1f5934dbc9a86c5cc811ad4985d392e6fb7cc5';
export const producerJob = 'selfscan';
export const testsJob = 'checks';
export const ciScenarios = ['none', 'tool-fetch-fail', 'db-fetch-fail', 'hash-mismatch', 'skip-scan', 'skip-upload', 'cancel-wait'] as const;
export type CiScenario = typeof ciScenarios[number];

export const controllerSteps = ['Use runner temp', 'Configure git line endings', 'Check out controller', 'Set up Node', 'Install controller'] as const;
export const producerStages = [
  { stage: 'target', step: 'Prepare target' }, { stage: 'acquire', step: 'Acquire tools' }, { stage: 'database', step: 'Fetch OSV database' },
  { stage: 'config', step: 'Derive config' }, { stage: 'plan', step: 'Plan' }, { stage: 'wait', step: 'Wait for cancellation' },
  { stage: 'scan', step: 'Scan' }, { stage: 'check', step: 'CI check' },
] as const;
export type ProducerStage = typeof producerStages[number]['stage'];
export const deliverySteps = ['Seal manifest', 'Upload delivery', 'Anchor delivery'] as const;
export const gateStep = 'Gate';
export const failureCodes = ['stage_not_completed', 'target_prepare_failed', 'tool_fetch_failed', 'tool_archive_hash_mismatch', 'tool_extract_failed',
  'tool_hash_mismatch', 'database_fetch_failed', 'config_derive_failed', 'config_git_version_failed', 'process_owner_build_failed',
  'process_owner_receipt_mismatch', 'plan_failed', 'wait_failed', 'scan_failed', 'ci_check_failed'] as const;
export type FailureCode = typeof failureCodes[number];
export const manifestName = 'manifest.json';
export const deliveryFiles = ['ci-receipt.json', 'ci-result.json', 'config.json', 'expected.json', 'osv-database-receipt.json', 'plan.json', 'report.json'] as const;
export const optionalFeatures = { codeScanning: 'not_uploaded', attestation: 'not_attested' } as const;
export const artifactName = (runId: number, attempt: number) => `scanmux-selfscan-${runId}-a${attempt}`;
export const anchorLine = (manifestSha256: string, artifactId: number, runId: number, attempt: number) =>
  `scanmux-anchor v1 manifest=${manifestSha256} artifact=${artifactId} run=${runId} attempt=${attempt}`;

const sha40 = /^[0-9a-f]{40}$/, sha64 = /^[0-9a-f]{64}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.\.?$)[A-Za-z0-9._-]{1,100}$/;
const versionPattern = /^[0-9]+\.[0-9]+\.[0-9]+$/;

function exactKeys(input: unknown, keys: readonly string[], code: string): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new SafeError(code);
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new SafeError(code);
  return value;
}
function textOf(input: unknown, pattern: RegExp, code: string): string {
  if (typeof input !== 'string' || !pattern.test(input)) throw new SafeError(code);
  return input;
}
function idOf(input: unknown, code: string): number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 1) throw new SafeError(code);
  return input;
}
function oneOf<T extends string>(input: unknown, choices: readonly T[], code: string): T {
  if (typeof input !== 'string' || !choices.includes(input as T)) throw new SafeError(code);
  return input as T;
}

export interface DeliveryFile { readonly path: string; readonly bytes: number; readonly sha256: string }
export interface DeliveryManifest {
  readonly schema: 'scanmux.github-delivery/v1';
  readonly github: { readonly repositoryId: number; readonly repository: string; readonly workflowPath: string; readonly runId: number; readonly attempt: number;
    readonly event: 'workflow_run' | 'workflow_dispatch'; readonly runHeadSha: string };
  readonly source: { readonly runId: number; readonly attempt: number; readonly event: 'pull_request' | 'workflow_dispatch'; readonly headSha: string; readonly pr: number | null } | null;
  readonly targetHeadSha: string;
  readonly controllerSha: string;
  readonly pinsSha256: string;
  readonly ciRun: string | null;
  readonly scenario: CiScenario;
  readonly git: Readonly<Tool> | null;
  readonly outcome: { readonly kind: 'produced' } | { readonly kind: 'failed'; readonly stage: ProducerStage; readonly code: FailureCode };
  readonly optional: typeof optionalFeatures;
  readonly files: readonly DeliveryFile[];
}

export function parseDeliveryManifest(input: unknown): DeliveryManifest {
  const bad = 'manifest_invalid';
  const value = exactKeys(input, ['schema', 'github', 'source', 'targetHeadSha', 'controllerSha', 'pinsSha256', 'ciRun', 'scenario', 'git', 'outcome', 'optional', 'files'], bad);
  if (value.schema !== 'scanmux.github-delivery/v1') throw new SafeError(bad);
  const github = exactKeys(value.github, ['repositoryId', 'repository', 'workflowPath', 'runId', 'attempt', 'event', 'runHeadSha'], bad);
  const source = value.source === null ? null : exactKeys(value.source, ['runId', 'attempt', 'event', 'headSha', 'pr'], bad);
  const kind = record(value.outcome).kind;
  let parsedOutcome: DeliveryManifest['outcome'];
  if (kind === 'produced') { exactKeys(value.outcome, ['kind'], bad); parsedOutcome = { kind }; }
  else if (kind === 'failed') {
    const outcome = exactKeys(value.outcome, ['kind', 'stage', 'code'], bad);
    parsedOutcome = { kind, stage: oneOf(outcome.stage, producerStages.map(item => item.stage), bad), code: oneOf(outcome.code, failureCodes, bad) };
  } else throw new SafeError(bad);
  const optional = exactKeys(value.optional, ['codeScanning', 'attestation'], bad);
  if (optional.codeScanning !== optionalFeatures.codeScanning || optional.attestation !== optionalFeatures.attestation) throw new SafeError(bad);
  const git = value.git === null ? null : exactKeys(value.git, ['path', 'sha256', 'version'], bad);
  if (!Array.isArray(value.files) || value.files.length > deliveryFiles.length) throw new SafeError(bad);
  const files = value.files.map(item => {
    const file = exactKeys(item, ['path', 'bytes', 'sha256'], bad);
    if (typeof file.bytes !== 'number' || !Number.isSafeInteger(file.bytes) || file.bytes < 0) throw new SafeError(bad);
    return { path: oneOf(file.path, deliveryFiles, bad), bytes: file.bytes, sha256: textOf(file.sha256, sha64, bad) };
  });
  if (files.some((file, index) => index > 0 && files[index - 1].path >= file.path)) throw new SafeError(bad);
  const ciRun = value.ciRun === null ? null : textOf(value.ciRun, uuidPattern, bad);
  if (parsedOutcome.kind === 'produced' && (ciRun === null || git === null)) throw new SafeError(bad);
  return {
    schema: 'scanmux.github-delivery/v1',
    github: { repositoryId: idOf(github.repositoryId, bad), repository: textOf(github.repository, repositoryPattern, bad),
      workflowPath: textOf(github.workflowPath, /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}$/, bad), runId: idOf(github.runId, bad), attempt: idOf(github.attempt, bad),
      event: oneOf(github.event, ['workflow_run', 'workflow_dispatch'], bad), runHeadSha: textOf(github.runHeadSha, sha40, bad) },
    source: source === null ? null : { runId: idOf(source.runId, bad), attempt: idOf(source.attempt, bad), event: oneOf(source.event, ['pull_request', 'workflow_dispatch'], bad),
      headSha: textOf(source.headSha, sha40, bad), pr: source.pr === null ? null : idOf(source.pr, bad) },
    targetHeadSha: textOf(value.targetHeadSha, sha40, bad), controllerSha: textOf(value.controllerSha, sha40, bad), pinsSha256: textOf(value.pinsSha256, sha64, bad),
    ciRun, scenario: oneOf(value.scenario, ciScenarios, bad),
    git: git === null ? null : { path: textOf(git.path, /^[A-Za-z]:\\[^\x00-\x1f]{1,1000}$/, bad), sha256: textOf(git.sha256, sha64, bad), version: textOf(git.version, versionPattern, bad) },
    outcome: parsedOutcome, optional: optionalFeatures, files,
  };
}

interface Repo { id: number; fullName: string; defaultBranch: string }
interface RunAttempt { id: number; attempt: number; repositoryId: number; path: string; event: string; status: string; conclusion: string | null; headSha: string; title: string | null }
interface Step { name: string; conclusion: string | null }
interface Job { id: number; name: string; attempt: number; status: string; conclusion: string | null; steps: Step[] }
interface Artifact { id: number; name: string; expired: boolean; runId: number }
const apiCode = 'github_response_invalid';
const str = (input: unknown) => { if (typeof input !== 'string' || input.length > 4096) throw new SafeError(apiCode); return input; };
const nullableStr = (input: unknown) => input === null ? null : str(input);
const num = (input: unknown) => idOf(input, apiCode);
function parseRepo(input: unknown): Repo {
  const value = record(input);
  return { id: num(value.id), fullName: textOf(value.full_name, repositoryPattern, apiCode), defaultBranch: textOf(value.default_branch, /^[A-Za-z0-9._/-]{1,255}$/, apiCode) };
}
function parseRun(input: unknown): RunAttempt {
  const value = record(input);
  return { id: num(value.id), attempt: num(value.run_attempt), repositoryId: num(record(value.repository).id), path: str(value.path), event: str(value.event),
    status: str(value.status), conclusion: nullableStr(value.conclusion), headSha: textOf(value.head_sha, sha40, apiCode),
    title: typeof value.display_title === 'string' ? value.display_title : null };
}
function pages<T>(input: unknown, key: string, item: (value: unknown) => T): T[] {
  if (!Array.isArray(input) || !input.length) throw new SafeError(apiCode);
  const items: T[] = [];
  let total = -1;
  for (const page of input) {
    const value = record(page), count = value.total_count;
    if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0 || (total >= 0 && count !== total) || !Array.isArray(value[key])) throw new SafeError(apiCode);
    total = count;
    items.push(...(value[key] as unknown[]).map(item));
  }
  if (items.length !== total) throw new SafeError(apiCode);
  return items;
}
function parseJob(input: unknown): Job {
  const value = record(input);
  if (!Array.isArray(value.steps)) throw new SafeError(apiCode);
  return { id: num(value.id), name: str(value.name), attempt: num(value.run_attempt), status: str(value.status), conclusion: nullableStr(value.conclusion),
    steps: value.steps.map(step => { const item = record(step); return { name: str(item.name), conclusion: nullableStr(item.conclusion) }; }) };
}
function parseArtifact(input: unknown): Artifact {
  const value = record(input);
  if (typeof value.expired !== 'boolean') throw new SafeError(apiCode);
  return { id: num(value.id), name: str(value.name), expired: value.expired, runId: num(record(value.workflow_run).id) };
}
function parseAncestry(input: unknown): string { return str(record(input).status); }

export type Slot<T> = { readonly state: 'fetched'; readonly value: T } | { readonly state: 'failed' } | { readonly state: 'invalid' } | { readonly state: 'not_fetched' };
export interface GithubRequest { readonly repository: string; readonly runId: number; readonly attempt: number }
export interface Evidence {
  readonly request: GithubRequest;
  readonly localCopy: boolean;
  readonly repo: Slot<unknown>;
  readonly run: Slot<unknown>;
  readonly ancestry: Slot<unknown>;
  readonly workflow: Slot<Buffer>;
  readonly jobs: Slot<unknown[]>;
  readonly artifacts: Slot<unknown[]>;
  readonly delivery: Slot<ReadonlyMap<string, Buffer>>;
  readonly log: Slot<string>;
  readonly source: Slot<unknown>;
  readonly sourceJobs: Slot<unknown[]>;
}

const reasonClass = {
  github_fetch_failed: 'error', github_response_invalid: 'error', delivery_archive_invalid: 'error',
  repository_mismatch: 'error', run_mismatch: 'error', run_not_completed: 'incomplete', run_cancelled: 'incomplete',
  run_head_not_on_default_branch: 'error', workflow_content_unapproved: 'error',
  source_run_mismatch: 'error', source_run_not_completed: 'incomplete',
  producer_job_missing: 'incomplete', producer_job_ambiguous: 'error', producer_job_cancelled: 'incomplete',
  producer_step_missing: 'incomplete', producer_step_skipped: 'incomplete', producer_step_cancelled: 'incomplete',
  producer_step_failed: 'error', producer_steps_inconsistent: 'error', delivery_step_incomplete: 'incomplete',
  artifact_missing: 'incomplete', artifact_expired: 'incomplete', artifact_ambiguous: 'error', artifact_run_mismatch: 'error',
  manifest_missing: 'error', anchor_missing: 'error', anchor_ambiguous: 'error', anchor_mismatch: 'error',
  manifest_invalid: 'error', manifest_run_mismatch: 'error', pins_unapproved: 'error', delivery_files_mismatch: 'error', delivery_file_tampered: 'error',
  outcome_step_mismatch: 'error', producer_failed: 'error', scenario_run: 'error',
  expectation_mismatch: 'error', receipt_binding_mismatch: 'error', report_binding_mismatch: 'error',
  result_disagrees: 'error', gate_step_disagrees: 'error',
} as const satisfies Record<string, 'incomplete' | 'error'>;
export type VerificationReason = keyof typeof reasonClass;
export const verificationChecks = ['run', 'workflow_integrity', 'producer_jobs', 'artifact', 'anchor', 'manifest', 'source_run', 'content_binding', 'agreement'] as const;
type Check = typeof verificationChecks[number];
type SourceConclusion = 'passed' | 'failed' | 'skipped' | 'cancelled' | 'unknown' | 'not_applicable';
export interface Verification {
  readonly schema: 'scanmux.github-verification/v1';
  readonly repository: string; readonly runId: number; readonly attempt: number;
  readonly checks: readonly { readonly check: Check; readonly state: 'passed' | 'failed' | 'unknown' }[];
  readonly outcome: 'agreed' | 'incomplete' | 'error';
  readonly reason: VerificationReason | null;
  readonly producer: DeliveryManifest['outcome'] | null;
  readonly scenario: CiScenario | null;
  readonly claimed: { readonly gate: Gate; readonly exitCode: number } | null;
  readonly sourceChecks: { readonly conclusion: SourceConclusion; readonly trusted: false };
  readonly notes: readonly ('local_copy_supplied' | 'failure_scenario')[];
  readonly optional: typeof optionalFeatures;
  readonly gate: Gate;
  readonly exitCode: number;
}

class Stop extends Error {
  readonly reason: VerificationReason;
  constructor(reason: VerificationReason) { super(reason); this.reason = reason; }
}
const stop = (reason: VerificationReason): never => { throw new Stop(reason); };
function take<T>(slot: Slot<T>): T {
  if (slot.state === 'fetched') return slot.value;
  return stop(slot.state === 'invalid' ? 'delivery_archive_invalid' : 'github_fetch_failed');
}
function parsed<T>(slot: Slot<unknown>, parse: (input: unknown) => T): T {
  const value = take(slot);
  try { return parse(value); } catch { return stop('github_response_invalid'); }
}
function json(bytes: Buffer | undefined, reason: VerificationReason): unknown {
  if (!bytes) return stop(reason);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return stop(reason); }
}
function guarded<T>(reason: VerificationReason, read: () => T): T {
  try { return read(); } catch (error) { if (error instanceof Stop) throw error; return stop(reason); }
}
const anchorPattern = /^scanmux-anchor v1 manifest=([0-9a-f]{64}) artifact=([1-9][0-9]{0,15}) run=([1-9][0-9]{0,15}) attempt=([1-9][0-9]{0,5})$/;
function anchors(log: string): { manifest: string; artifact: number; run: number; attempt: number }[] {
  const found = [];
  for (const raw of log.split(/\r?\n/)) {
    const line = raw.replace(/^﻿/, '').replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z /, '');
    if (!line.startsWith('scanmux-anchor')) continue;
    const match = anchorPattern.exec(line);
    if (!match) return stop('anchor_mismatch');
    found.push({ manifest: match[1], artifact: Number(match[2]), run: Number(match[3]), attempt: Number(match[4]) });
  }
  return found;
}
const identityKeys = ['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash'] as const;
function planIdentity(input: unknown) {
  const value = record(input);
  if (typeof value.root !== 'string' || !path.win32.isAbsolute(value.root) && !path.posix.isAbsolute(value.root)) throw new SafeError('invalid');
  return { root: value.root, repoId: textOf(value.repoId, sha64, 'invalid'), commit: textOf(value.commit, sha40, 'invalid'),
    policyHash: textOf(value.policyHash, sha64, 'invalid'), planHash: textOf(value.planHash, sha64, 'invalid'), snapshotHash: textOf(value.snapshotHash, sha64, 'invalid') };
}
function reportClaims(input: unknown) {
  const value = record(input);
  if (!Array.isArray(value.engines)) throw new SafeError('invalid');
  return { runId: value.runId, gate: value.gate, executionState: value.executionState, coverageState: value.coverageState, plan: planIdentity(value.plan),
    engines: value.engines.map(run => { const item = record(run); return { engine: item.engine, execution: item.execution, coverage: item.coverage }; }) };
}
function sourceConclusion(evidence: Evidence, event: string | undefined, sourceMatched: boolean): SourceConclusion {
  if (event === 'workflow_dispatch') return 'not_applicable';
  if (!sourceMatched || evidence.sourceJobs.state !== 'fetched') return 'unknown';
  try {
    const jobs = pages(evidence.sourceJobs.value, 'jobs', parseJob).filter(job => job.name === testsJob);
    if (jobs.length !== 1 || jobs[0].status !== 'completed') return 'unknown';
    const map: Record<string, SourceConclusion> = { success: 'passed', failure: 'failed', skipped: 'skipped', cancelled: 'cancelled' };
    return map[jobs[0].conclusion ?? ''] ?? 'unknown';
  } catch { return 'unknown'; }
}

export function judgeGithubRun(evidence: Evidence): Verification {
  const { request } = evidence;
  const states: Verification['checks'][number][] = verificationChecks.map(check => ({ check, state: 'unknown' as const }));
  let index = 0, claimed: Verification['claimed'] = null, event: string | undefined;
  const pass = () => { states[index] = { check: verificationChecks[index], state: 'passed' }; index++; };
  try {
    const { repo, run } = runIdentity(evidence);
    event = run.event;
    if (run.status !== 'completed') stop('run_not_completed');
    if (run.conclusion === 'cancelled') stop('run_cancelled');
    pass();

    workflowIntegrity(evidence);
    pass();

    const jobs = parsed(evidence.jobs, input => pages(input, 'jobs', parseJob)).filter(job => job.name === producerJob);
    if (!jobs.length) stop('producer_job_missing');
    if (jobs.length > 1) stop('producer_job_ambiguous');
    const [job] = jobs;
    if (job.attempt !== request.attempt) stop('run_mismatch');
    if (job.status !== 'completed') stop('run_not_completed');
    if (job.conclusion === 'cancelled') stop('producer_job_cancelled');
    const conclusion = (name: string) => {
      const steps = job.steps.filter(step => step.name === name);
      return steps.length === 1 ? steps[0].conclusion : stop('producer_step_missing');
    };
    for (const name of controllerSteps) {
      const value = conclusion(name);
      if (value === 'cancelled') stop('producer_step_cancelled');
      if (value === 'skipped') stop('producer_step_skipped');
      if (value !== 'success') stop('producer_step_failed');
    }
    let failedStage: ProducerStage | undefined;
    for (const { stage, step } of producerStages) {
      const value = conclusion(step);
      if (value === 'cancelled') stop('producer_step_cancelled');
      if (value === 'success' && !failedStage) continue;
      if (value === 'failure' && !failedStage) { failedStage = stage; continue; }
      if (value === 'skipped' && failedStage) continue;
      stop(value === 'skipped' ? 'producer_step_skipped' : 'producer_steps_inconsistent');
    }
    for (const name of deliverySteps) if (conclusion(name) !== 'success') stop('delivery_step_incomplete');
    const gateConclusion = conclusion(gateStep);
    if (gateConclusion !== 'success' && gateConclusion !== 'failure') stop('delivery_step_incomplete');
    pass();

    const { artifact, files } = deliveredArtifact(evidence);
    pass();

    const manifestBytes = anchoredBytes(evidence, artifact, files);
    pass();

    const sealed = guarded('manifest_invalid', () => parseDeliveryManifest(json(manifestBytes, 'manifest_missing')));
    const { github } = sealed, titled = titledScenario(run);
    if (github.repositoryId !== repo.id || github.repository !== repo.fullName || github.workflowPath !== run.path || github.runId !== run.id
      || github.attempt !== run.attempt || github.event !== run.event || github.runHeadSha !== run.headSha || sealed.controllerSha !== run.headSha
      || (run.event === 'workflow_dispatch' ? sealed.source !== null || sealed.targetHeadSha !== run.headSha : sealed.source?.headSha !== sealed.targetHeadSha)
      || (titled !== null && titled !== sealed.scenario)) stop('manifest_run_mismatch');
    if (sealed.pinsSha256 !== approvedPinsSha256) stop('pins_unapproved');
    const names = [...files.keys()].filter(name => name !== manifestName).sort();
    if (names.join('\n') !== sealed.files.map(file => file.path).join('\n')) stop('delivery_files_mismatch');
    for (const file of sealed.files) {
      const bytes = files.get(file.path)!;
      if (bytes.length !== file.bytes || hash(bytes) !== file.sha256) stop('delivery_file_tampered');
    }
    if (sealed.outcome.kind === 'failed') stop(sealed.outcome.stage === failedStage ? 'producer_failed' : 'outcome_step_mismatch');
    if (failedStage) stop('outcome_step_mismatch');
    if (names.length !== deliveryFiles.length) stop('delivery_files_mismatch');
    if (sealed.scenario !== 'none') stop('scenario_run');
    pass();

    if (sealed.source) {
      const observed = parsed(evidence.source, parseRun);
      if (observed.id !== sealed.source.runId || observed.attempt !== sealed.source.attempt || observed.repositoryId !== repo.id || observed.path !== testsWorkflowPath
        || observed.event !== sealed.source.event || observed.headSha !== sealed.source.headSha) stop('source_run_mismatch');
      if (observed.status !== 'completed') stop('source_run_not_completed');
    }
    pass();

    const plan = guarded('expectation_mismatch', () => planIdentity(json(files.get('plan.json'), 'expectation_mismatch')));
    if (hash(plan.root) !== plan.repoId || plan.commit !== sealed.targetHeadSha) stop('expectation_mismatch');
    const expected = guarded('expectation_mismatch', () => parseCiExpectation(json(files.get('expected.json'), 'expectation_mismatch')));
    const derived = guarded('expectation_mismatch', () => parseCiExpectation({ schema: 'scanmux.ci-expectation/v1', ciRun: sealed.ciRun,
      jobs: [{ id: producerJob, targetRoot: plan.root, repoId: plan.repoId, commit: plan.commit, policyHash: plan.policyHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash }] }));
    if (digest(expected) !== digest(derived)) stop('expectation_mismatch');
    const reportBytes = files.get('report.json')!;
    const receipt = guarded('receipt_binding_mismatch', () => parseCiReceipt(json(files.get('ci-receipt.json'), 'receipt_binding_mismatch')));
    if (receipt.schema !== 'scanmux.ci-receipt/v1' || receipt.reportHash !== hash(reportBytes) || receipt.ciRun !== sealed.ciRun) stop('receipt_binding_mismatch');
    const report = guarded('report_binding_mismatch', () => reportClaims(json(reportBytes, 'report_binding_mismatch')));
    if (report.runId !== receipt.reportRunId || report.gate !== receipt.gate || report.executionState !== receipt.executionState || report.coverageState !== receipt.coverageState
      || digest(report.engines) !== digest(receipt.engines) || identityKeys.some(key => report.plan[key] !== receipt[key])) stop('report_binding_mismatch');
    pass();

    const result = guarded('result_disagrees', () => evaluateCi(expected, [receipt]));
    if (digest(result) !== digest(json(files.get('ci-result.json'), 'result_disagrees'))) stop('result_disagrees');
    if ((exitCodes[result.gate] === 0) !== (gateConclusion === 'success')) stop('gate_step_disagrees');
    claimed = { gate: result.gate, exitCode: exitCodes[result.gate] };
    pass();
    return finish(evidence, states, null, claimed, sourceConclusion(evidence, event, true));
  } catch (error) {
    if (!(error instanceof Stop)) throw error;
    states[index] = { check: verificationChecks[index], state: 'failed' };
    const sourceMatched = states[verificationChecks.indexOf('source_run')].state === 'passed';
    return finish(evidence, states, error.reason, claimed, sourceConclusion(evidence, event, sourceMatched));
  }
}
function runIdentity(evidence: Evidence) {
  const repo = parsed(evidence.repo, parseRepo), run = parsed(evidence.run, parseRun), { request } = evidence;
  if (repo.fullName.toLowerCase() !== request.repository.toLowerCase()) stop('repository_mismatch');
  if (run.repositoryId !== repo.id || run.id !== request.runId || run.attempt !== request.attempt || run.path !== producerWorkflowPath
    || !['workflow_run', 'workflow_dispatch'].includes(run.event)) stop('run_mismatch');
  return { repo, run };
}
function workflowIntegrity(evidence: Evidence): void {
  if (!['ahead', 'identical'].includes(parsed(evidence.ancestry, parseAncestry))) stop('run_head_not_on_default_branch');
  if (hash(take(evidence.workflow)) !== producerWorkflowSha256) stop('workflow_content_unapproved');
}
function approvedRun(evidence: Evidence): RunAttempt | null {
  try { const { run } = runIdentity(evidence); workflowIntegrity(evidence); return run; } catch { return null; }
}
function deliveredArtifact(evidence: Evidence) {
  const { request } = evidence, expectedName = artifactName(request.runId, request.attempt);
  const artifacts = parsed(evidence.artifacts, input => pages(input, 'artifacts', parseArtifact)).filter(item => item.name === expectedName);
  if (!artifacts.length) stop('artifact_missing');
  if (artifacts.length > 1) stop('artifact_ambiguous');
  const [artifact] = artifacts;
  if (artifact.runId !== request.runId) stop('artifact_run_mismatch');
  if (artifact.expired) stop('artifact_expired');
  return { artifact, files: take(evidence.delivery) };
}
function anchoredBytes(evidence: Evidence, artifact: Artifact, files: ReadonlyMap<string, Buffer>): Buffer {
  const { request } = evidence;
  const manifestBytes = files.get(manifestName) ?? stop('manifest_missing');
  const lines = anchors(take(evidence.log));
  if (!lines.length) stop('anchor_missing');
  if (lines.length > 1) stop('anchor_ambiguous');
  const [anchor] = lines;
  if (anchor.manifest !== hash(manifestBytes) || anchor.artifact !== artifact.id || anchor.run !== request.runId || anchor.attempt !== request.attempt) stop('anchor_mismatch');
  return manifestBytes;
}
const titlePattern = /^offline-selfscan scenario=([a-z-]{1,32})$/;
function titledScenario(run: RunAttempt): CiScenario | null {
  const value = run.title === null ? undefined : titlePattern.exec(run.title)?.[1];
  return ciScenarios.find(scenario => scenario === value) ?? null;
}
function anchoredManifest(evidence: Evidence): DeliveryManifest | null {
  try {
    const { artifact, files } = deliveredArtifact(evidence);
    return parseDeliveryManifest(json(anchoredBytes(evidence, artifact, files), 'manifest_missing'));
  } catch { return null; }
}
function finish(evidence: Evidence, checks: Verification['checks'], reason: VerificationReason | null, claimed: Verification['claimed'], conclusion: SourceConclusion): Verification {
  const outcome = reason === null ? 'agreed' : reasonClass[reason];
  const agreed: Gate = evidence.localCopy && claimed?.gate === 'PASS' ? 'INCOMPLETE' : claimed?.gate ?? 'ERROR';
  const gate: Gate = reason === null ? agreed : outcome === 'incomplete' ? 'INCOMPLETE' : 'ERROR';
  const run = approvedRun(evidence), manifest = run ? anchoredManifest(evidence) : null;
  const known = [manifest?.scenario ?? null, run && titledScenario(run)].filter(value => value !== null);
  const scenario = known.length && known.every(value => value === known[0]) ? known[0] : null;
  const notes: Verification['notes'] = [...(evidence.localCopy ? ['local_copy_supplied' as const] : []), ...(known.some(value => value !== 'none') ? ['failure_scenario' as const] : [])];
  return { schema: 'scanmux.github-verification/v1', repository: evidence.request.repository, runId: evidence.request.runId, attempt: evidence.request.attempt,
    checks, outcome, reason, producer: manifest?.outcome ?? null, scenario, claimed, sourceChecks: { conclusion, trusted: false },
    notes, optional: optionalFeatures, gate, exitCode: exitCodes[gate] };
}

export interface GithubApi {
  json(endpoint: string, jq?: string): Promise<unknown>;
  bytes(endpoint: string, accept: string): Promise<Buffer>;
}
export const deliveryLimits = { maxEntries: deliveryFiles.length + 1, maxBytes: 64 * 1024 * 1024 } as const;
const pageLimit = 20;

const deliveryNames: ReadonlySet<string> = new Set([...deliveryFiles, manifestName]);
function closedDelivery(files: ReadonlyMap<string, Buffer>): Slot<ReadonlyMap<string, Buffer>> {
  return [...files.keys()].every(name => deliveryNames.has(name)) ? { state: 'fetched', value: files } : { state: 'invalid' };
}

async function slot<T>(read: () => Promise<T>): Promise<Slot<T>> {
  try { return { state: 'fetched', value: await read() }; }
  catch (error) {
    if (error instanceof SafeError && (error.code === 'cancelled' || error.code === 'termination_unverified')) throw error;
    return { state: 'failed' };
  }
}
function peek<T>(input: Slot<unknown>, parse: (value: unknown) => T): T | undefined {
  if (input.state !== 'fetched') return undefined;
  try { return parse(input.value); } catch { return undefined; }
}
async function allPages(api: GithubApi, endpoint: string, key: string): Promise<unknown[]> {
  const result: unknown[] = [];
  let seen = 0;
  for (let page = 1; page <= pageLimit; page++) {
    const body = await api.json(`${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    result.push(body);
    const value = record(body), items = value[key];
    if (!Array.isArray(items) || typeof value.total_count !== 'number') return result;
    seen += items.length;
    if (seen >= value.total_count || !items.length) return result;
  }
  throw new SafeError('github_page_limit');
}

export async function collectEvidence(api: GithubApi, request: GithubRequest, localDelivery?: ReadonlyMap<string, Buffer>): Promise<Evidence> {
  const base = `repos/${request.repository}`, runs = `${base}/actions/runs/${request.runId}`;
  const repo = await slot(() => api.json(base));
  const run = await slot(() => api.json(`${runs}/attempts/${request.attempt}`));
  const repoValue = peek(repo, parseRepo), runValue = peek(run, parseRun);
  const notFetched = { state: 'not_fetched' } as const;
  const ancestry = repoValue && runValue ? await slot(() => api.json(`${base}/compare/${runValue.headSha}...${encodeURIComponent(repoValue.defaultBranch)}`, '{status: .status}')) : notFetched;
  const workflow = runValue ? await slot(() => api.bytes(`${base}/contents/${producerWorkflowPath}?ref=${runValue.headSha}`, 'application/vnd.github.raw')) : notFetched;
  const jobs = await slot(() => allPages(api, `${runs}/attempts/${request.attempt}/jobs`, 'jobs'));
  const artifacts = await slot(() => allPages(api, `${runs}/artifacts?name=${artifactName(request.runId, request.attempt)}`, 'artifacts'));
  const matching = peek(artifacts, input => pages(input, 'artifacts', parseArtifact).filter(item => item.name === artifactName(request.runId, request.attempt)));
  let delivery: Slot<ReadonlyMap<string, Buffer>> = notFetched;
  if (localDelivery) delivery = closedDelivery(localDelivery);
  else if (matching?.length === 1) {
    const archive = await slot(() => api.bytes(`${base}/actions/artifacts/${matching[0].id}/zip`, 'application/vnd.github+json'));
    if (archive.state === 'fetched') {
      try { delivery = closedDelivery(readZip(archive.value, deliveryLimits)); } catch { delivery = { state: 'invalid' }; }
    } else delivery = archive;
  }
  const producer = peek(jobs, input => pages(input, 'jobs', parseJob).filter(job => job.name === producerJob));
  const log = producer?.length === 1 ? await slot(async () => (await api.bytes(`${base}/actions/jobs/${producer[0].id}/logs`, 'application/vnd.github+json')).toString('utf8')) : notFetched;
  const manifest = delivery.state === 'fetched' ? (() => { try { return parseDeliveryManifest(JSON.parse(delivery.value.get(manifestName)?.toString('utf8') ?? '')); } catch { return undefined; } })() : undefined;
  let source: Slot<unknown> = notFetched, sourceJobs: Slot<unknown[]> = notFetched;
  if (runValue?.event === 'workflow_run' && manifest?.source) {
    const sourceRun = `${base}/actions/runs/${manifest.source.runId}/attempts/${manifest.source.attempt}`;
    source = await slot(() => api.json(sourceRun));
    sourceJobs = await slot(() => allPages(api, `${sourceRun}/jobs`, 'jobs'));
  }
  return { request, localCopy: Boolean(localDelivery), repo, run, ancestry, workflow, jobs, artifacts, delivery, log, source, sourceJobs };
}

const ghOutputLimit = 96 * 1024 * 1024;
function ghApi(gh: Tool, workspace: string, token: string, config: Config, signal: AbortSignal): GithubApi {
  const call = async (endpoint: string, accept: string, jq?: string) => {
    const result = await execute(gh, ['api', '--method', 'GET', '-H', `Accept: ${accept}`, '-H', 'X-GitHub-Api-Version: 2022-11-28', ...(jq ? ['--jq', jq] : []), endpoint], {
      cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: ghOutputLimit, signal,
      environment: { GH_TOKEN: token, GH_HOST: 'github.com', GH_PROMPT_DISABLED: '1', GH_NO_UPDATE_NOTIFIER: '1', GH_SPINNER_DISABLED: '1' },
    });
    if (result.reason === 'termination_unverified' || result.reason === 'cancelled') throw new SafeError(result.reason);
    if (result.reason !== 'exit' || result.code !== 0) throw new SafeError('github_fetch_failed');
    return result.stdout;
  };
  return {
    json: async (endpoint, jq) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await call(endpoint, 'application/vnd.github+json', jq))),
    bytes: (endpoint, accept) => call(endpoint, accept),
  };
}

async function readLocalCopy(directory: string): Promise<Map<string, Buffer>> {
  if (!path.isAbsolute(directory)) throw new SafeError('local_copy_must_be_absolute');
  const root = await canonical(directory);
  if (!(await lstat(root)).isDirectory()) throw new SafeError('local_copy_invalid');
  const files = new Map<string, Buffer>();
  let remaining = deliveryLimits.maxBytes;
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isFile() || files.size >= deliveryLimits.maxEntries) throw new SafeError('local_copy_invalid');
    const bytes = await boundedRead(path.join(root, safeRelative(entry.name)), remaining);
    remaining -= bytes.length;
    files.set(entry.name, bytes);
  }
  return files;
}

export function parseGithubRequest(repository: unknown, runId: unknown, attempt: unknown): GithubRequest {
  const number = (input: unknown) => {
    if (typeof input !== 'string' || !/^[1-9][0-9]{0,15}$/.test(input) || !Number.isSafeInteger(Number(input))) throw new SafeError('invalid_command');
    return Number(input);
  };
  return { repository: textOf(repository, repositoryPattern, 'invalid_command'), runId: number(runId), attempt: number(attempt) };
}

export async function verifyGithubRun(request: GithubRequest, fromDir: string | undefined, config: Config, signal: AbortSignal) {
  if (config.schema !== 2 || config.runtimePolicy.schema !== 'scanmux.runtime-policy/v2') throw new SafeError('ci_github_gh_unpinned');
  const token = process.env.GH_TOKEN;
  if (!token) throw new SafeError('ci_github_token_required');
  const gh = config.runtimePolicy.provenance.verifier;
  const local = fromDir === undefined ? undefined : await readLocalCopy(fromDir);
  const workspace = await privateWorkspace();
  await verifyVersion(gh, ['--version'], { cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: 65536, signal });
  const evidence = await collectEvidence(ghApi(gh, workspace, token, config, signal), request, local);
  const result = judgeGithubRun(evidence);
  const deliveryDirectory = !local && evidence.delivery.state === 'fetched' ? path.join(workspace, 'delivery') : null;
  const output = await checkedJson(result, config, workspace), destination = path.join(workspace, 'github-verification.json');
  await checkedJson({ destination, deliveryDirectory }, config, workspace);
  await writeFile(destination, output, { mode: 0o600, flag: 'wx' });
  if (deliveryDirectory && evidence.delivery.state === 'fetched') {
    await mkdir(deliveryDirectory, { mode: 0o700 });
    for (const [name, bytes] of evidence.delivery.value) await writeFile(path.join(deliveryDirectory, safeRelative(name)), bytes, { mode: 0o600, flag: 'wx' });
  }
  return { result, json: output, destination, deliveryDirectory };
}
