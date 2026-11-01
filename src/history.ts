import path from 'node:path';
import { lstat, writeFile } from 'node:fs/promises';
import type { Config, TokenObservation } from './model.ts';
import { loadConfig } from './config.ts';
import { checkedJson } from './output.ts';
import { privateWorkspace } from './private-storage.ts';
import { array, boundedRead, canonical, digest, hash, record, SafeError, within } from './safety.ts';
import { workerResourcesComplete } from '../internal/worker-resources.mjs';
import { requiredEngines, trivyCompletion, verifyEngineCatalog } from './engine-catalog.ts';

const executions = ['completed', 'failed', 'cancelled', 'budget_exceeded', 'not_started'] as const;
const coverage = ['analyzed', 'unsupported', 'skipped', 'partial'] as const;
function choice<T extends string>(input: unknown, values: readonly T[]): T {
  if (typeof input !== 'string' || !values.includes(input as T)) throw new SafeError('invalid_history_report');
  return input as T;
}
function text(input: unknown, pattern: RegExp): string {
  if (typeof input !== 'string' || !pattern.test(input)) throw new SafeError('invalid_history_report');
  return input;
}
function count(input: unknown): number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 0) throw new SafeError('invalid_history_usage');
  return input;
}
function timestamp(input: unknown): string {
  const value = text(input, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/), time = new Date(value);
  if (!Number.isFinite(time.valueOf()) || time.toISOString() !== (value.includes('.') ? value : value.replace('Z', '.000Z'))) throw new SafeError('invalid_history_report');
  return value;
}
const digestText = (input: unknown) => text(input, /^[0-9a-f]{64}$/);
const optionalRecord = (input: unknown) => input === undefined || input === null ? null : record(input);
const observedCount = (input: unknown) => typeof input === 'number' && Number.isSafeInteger(input) && input >= 0 ? input : null;
const observedDigest = (input: unknown) => typeof input === 'string' && /^[0-9a-f]{64}$/.test(input) ? input : null;
function aiCompletion(execution: Record<string, unknown>, plan: Record<string, unknown>, engineErrors: unknown) {
  const status = execution.status === undefined ? null : choice(execution.status, ['not_started', 'completed', 'failed', 'canceled', 'budget_exceeded', 'acceptance_unknown']);
  const artifactsAccepted = typeof execution.artifactsAccepted === 'boolean' ? execution.artifactsAccepted : null;
  const programs = execution.programs === undefined ? null : array(execution.programs).map(value => choice(value, ['daybreak_blue', 'standard', 'daybreak_red', 'unknown']));
  const rawCleanup = optionalRecord(execution.cleanup), rawCoverage = optionalRecord(execution.coverage);
  const fact = (input: unknown) => typeof input === 'boolean' ? input : null;
  const cleanup = rawCleanup ? { closed: fact(rawCleanup.closed), quiescent: fact(rawCleanup.quiescent), containerAbsent: fact(rawCleanup.containerAbsent) } : null;
  const coverage = rawCoverage ? { artifactsReviewed: observedCount(rawCoverage.artifactsReviewed), exclusions: observedCount(rawCoverage.exclusions),
    deferred: observedCount(rawCoverage.deferred), openQuestions: observedCount(rawCoverage.openQuestions), limitations: observedCount(rawCoverage.limitations), sha256: observedDigest(rawCoverage.sha256) } : null;
  const aiPlan = optionalRecord(plan.ai), source = optionalRecord(aiPlan?.source), runtime = optionalRecord(execution.runtime), plannedRuntime = optionalRecord(aiPlan?.runtime);
  const resources = optionalRecord(runtime?.resources);
  const current = execution.schema === 'scanmux.ai-execution/v2' && aiPlan?.schema === 'scanmux.ai-plan/v2';
  const legacy = execution.schema === 'scanmux.ai-execution/v1' && aiPlan?.schema === 'scanmux.ai-plan/v1'
    && !Object.hasOwn(aiPlan, 'workerResources') && (!runtime || !Object.hasOwn(runtime, 'resources'));
  const planIdentityVerified = plan.planHash === digest({ ...plan, planHash: '' });
  const resourcesVerified = current && workerResourcesComplete(resources, aiPlan?.workerResources);
  const rawExceeded = resources?.exceeded;
  const exceeded = Array.isArray(rawExceeded) && rawExceeded.every(value => ['memory', 'disk', 'time'].includes(value)) ? rawExceeded as ('memory' | 'disk' | 'time')[] : null;
  const files = Array.isArray(plan.files) ? plan.files.map(record) : [];
  const manifest = files.map(file => ({ path: file.path, bytes: file.bytes, sha256: file.sha256 }));
  const sourceVerified = source !== null && execution.sourcePreflight === 'completed' && typeof plan.commit === 'string' && /^[0-9a-f]{40}$/.test(plan.commit)
    && execution.originalCommit === plan.commit && execution.snapshotHash === plan.snapshotHash && source?.snapshotHash === plan.snapshotHash
    && observedDigest(plan.snapshotHash) !== null && files.length > 0 && source.files === files.length
    && manifest.every(file => typeof file.path === 'string' && file.path.length > 0 && observedCount(file.bytes) !== null && observedDigest(file.sha256) !== null)
    && new Set(manifest.map(file => file.path)).size === files.length && source.manifestSha256 === digest(manifest) && execution.manifestSha256 === source.manifestSha256;
  const runtimeVerified = runtime?.boundaryVerified === true && typeof runtime.imageDigest === 'string' && /^sha256:[0-9a-f]{64}$/.test(runtime.imageDigest)
    && runtime.imageDigest === plannedRuntime?.imageDigest;
  const artifacts = Array.isArray(execution.artifacts) ? execution.artifacts.map(record) : [];
  const artifactRecordsComplete = artifacts.length > 0 && artifacts.every(entry => typeof entry.path === 'string' && observedCount(entry.bytes) !== null && observedDigest(entry.sha256) !== null)
    && new Set(artifacts.map(entry => entry.path)).size === artifacts.length && ['scan-manifest.json', 'findings.json', 'coverage.json'].every(name => artifacts.some(entry => entry.path === name));
  const reasons: string[] = [];
  if (!planIdentityVerified) reasons.push('ai_saved_plan_identity_unverified');
  if (!current && !legacy) reasons.push('ai_resource_schema_inconsistent');
  if (current && !resourcesVerified) reasons.push('ai_worker_resources_unverified');
  if (status !== 'completed') reasons.push('ai_execution_not_completed');
  if (artifactsAccepted !== true || !artifactRecordsComplete) reasons.push('ai_artifact_acceptance_unverified');
  if (!programs?.length || programs.some(program => program !== 'daybreak_blue' && program !== 'standard')) reasons.push('ai_effective_program_unverified');
  if (!cleanup || Object.values(cleanup).some(value => value !== true)) reasons.push('ai_cleanup_unverified');
  if (!sourceVerified) reasons.push('ai_source_evidence_unverified');
  if (!runtimeVerified) reasons.push('ai_boundary_unverified');
  if (!coverage || !sourceVerified || coverage.artifactsReviewed !== files.length || !coverage.sha256
    || [coverage.exclusions, coverage.deferred, coverage.openQuestions, coverage.limitations].some(value => value !== 0)) reasons.push('ai_scope_incomplete');
  if (!Array.isArray(engineErrors) || engineErrors.length > 0) reasons.push('ai_engine_errors_or_missing');
  return { status, artifactsAccepted, programs, cleanup, coverage, sourceVerified, runtimeVerified, artifactRecordsComplete,
    planIdentityVerified, resources: { state: legacy ? 'legacy_unrecorded' as const : resourcesVerified ? 'complete' as const : 'incomplete' as const, exceeded }, reasons };
}
function aiUsage(input: unknown, calls: number, plan: Record<string, unknown>, engineErrors: unknown) {
  if (input === undefined) return undefined;
  const execution = record(input), observation = record(execution.tokens);
  if (!['scanmux.ai-execution/v1', 'scanmux.ai-execution/v2'].includes(String(execution.schema)) || count(execution.submitInvocations) !== calls) throw new SafeError('invalid_history_ai_usage');
  const classification = choice(execution.classification, ['provider', 'synthetic']);
  const connectionAttempts = count(execution.connectionAttempts), sendInvocations = count(execution.sendInvocations);
  if (sendInvocations > connectionAttempts || connectionAttempts > calls) throw new SafeError('invalid_history_ai_usage');
  const kind = choice(observation.kind, ['unknown', 'partial', 'complete']);
  const rows = array(execution.usageRecords).map(input => {
    const row = record(input), usage = record(row.usage), sequence = count(row.sequence);
    const inputTokens = count(usage.inputTokens), outputTokens = count(usage.outputTokens), totalTokens = count(usage.totalTokens);
    if (!sequence || sequence > calls || count(inputTokens + outputTokens) !== totalTokens) throw new SafeError('invalid_history_ai_usage');
    return { sequence, inputTokens, outputTokens, totalTokens };
  });
  if (rows.some((row, i) => i > 0 && row.sequence <= rows[i - 1].sequence)) throw new SafeError('invalid_history_ai_usage');
  let tokens: TokenObservation;
  if (kind === 'unknown') {
    if (observation.observed !== null || rows.length) throw new SafeError('invalid_history_ai_usage');
    tokens = { kind, observed: null };
  } else {
    const observed = record(observation.observed), inputTokens = count(observed.inputTokens), outputTokens = count(observed.outputTokens), totalTokens = count(observed.totalTokens);
    if (!rows.length || count(inputTokens + outputTokens) !== totalTokens || kind === 'complete' && rows.length !== calls
      || count(rows.reduce((n, row) => n + row.inputTokens, 0)) !== inputTokens || count(rows.reduce((n, row) => n + row.outputTokens, 0)) !== outputTokens
      || count(rows.reduce((n, row) => n + row.totalTokens, 0)) !== totalTokens) throw new SafeError('invalid_history_ai_usage');
    tokens = { kind, observed: { inputTokens, outputTokens, totalTokens } };
  }
  const completion = aiCompletion(execution, plan, engineErrors);
  if (classification === 'synthetic') completion.reasons.push('ai_synthetic_evidence');
  if (tokens.kind !== 'complete') completion.reasons.push('ai_usage_incomplete');
  return { classification, tokens, connectionAttempts, sendInvocations, ...completion };
}
function project(bytes: Buffer) {
  const report = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))), plan = record(report.plan);
  if (report.schema !== (plan.schema === 'scanmux.plan/v3' ? 'scanmux.report/v3' : 'scanmux.report/v2')) throw new SafeError('invalid_history_report');
  if (plan.schema !== 'scanmux.plan/v2' && plan.schema !== 'scanmux.plan/v3') throw new SafeError('invalid_history_report');
  const required = requiredEngines(plan.schema);
  if (plan.schema === 'scanmux.plan/v3') verifyEngineCatalog(plan);
  if (typeof plan.root !== 'string' || !path.isAbsolute(plan.root)) throw new SafeError('invalid_history_report');
  const declared = array(plan.required).map(value => choice(value, required));
  if (new Set(declared).size !== declared.length) throw new SafeError('invalid_history_report');
  const recorded = array(report.engines).map(input => {
    const run = record(input), usage = record(run.usage);
    if (usage.cost !== null || usage.allowance !== 'unknown') throw new SafeError('invalid_history_usage');
    const calls = count(usage.calls), ai = aiUsage(run.aiExecution, calls, plan, run.errors), engine = choice(run.engine, required);
    if (ai && engine !== 'codex-security') throw new SafeError('invalid_history_ai_usage');
    const trivyComplete = trivyCompletion(plan, run);
    return { engine, execution: choice(run.execution, executions), coverage: choice(run.coverage, coverage),
      ...(engine === 'trivy' ? { completionVerified: trivyComplete } : {}),
      calls, cost: null, costKind: choice(usage.kind, ['unknown', 'not_applicable']), ...(ai ? { ai } : {}) };
  });
  if (new Set(recorded.map(run => run.engine)).size !== recorded.length) throw new SafeError('invalid_history_report');
  const executionState = choice(report.executionState, executions), coverageState = choice(report.coverageState, ['complete', 'incomplete']);
  const missingEngines = required.filter(engine => !recorded.some(run => run.engine === engine));
  const incomplete = missingEngines.length > 0 || declared.length !== required.length || executionState !== 'completed' || coverageState !== 'complete'
    || recorded.some(run => run.execution !== 'completed' || run.coverage !== 'analyzed')
    || recorded.some(run => run.completionVerified === false)
    || recorded.some(run => run.ai && run.ai.reasons.length > 0)
    || (plan.ai !== undefined || plan.network === 'openai-responses') && !recorded.some(run => run.engine === 'codex-security' && run.ai)
    || array(plan.blockers).length > 0 || array(plan.exclusions).length > 0 || array(report.integrityErrors).length > 0;
  const recordedGate = choice(report.gate, ['PASS', 'FAIL', 'INCOMPLETE', 'REVIEW', 'ERROR']);
  const startedAt = timestamp(report.startedAt), endedAt = timestamp(report.endedAt);
  if (Date.parse(endedAt) < Date.parse(startedAt)) throw new SafeError('invalid_history_report');
  let reportedCalls = 0;
  for (const run of recorded) reportedCalls = count(reportedCalls + run.calls);
  const engines = required.map(engine => {
    const run = recorded.find(value => value.engine === engine);
    return run ? { ...run, recordState: 'recorded' as const } : { engine, recordState: 'missing' as const, execution: null, coverage: null, calls: null, cost: null, costKind: 'unrecorded' as const };
  });
  return { root: plan.root, row: {
    runId: text(report.runId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/), reportHash: hash(bytes),
    repoId: digestText(plan.repoId), commit: plan.commit === null ? null : text(plan.commit, /^[0-9a-f]{40}$/),
    policyHash: digestText(plan.policyHash), planHash: digestText(plan.planHash), snapshotHash: digestText(plan.snapshotHash),
    startedAt, endedAt, recordedGate, executionState, coverageState,
    completion: incomplete ? 'incomplete' as const : 'complete' as const,
    reasons: [...new Set([...(incomplete ? ['required_analysis_incomplete'] : []), ...(incomplete && recordedGate === 'PASS' ? ['recorded_pass_conflicts_with_completion'] : []),
      ...recorded.flatMap(run => run.ai?.reasons ?? [])])],
    engines, reportedCalls, missingEngineRecords: missingEngines.length,
    cost: null, costKind: missingEngines.length || recorded.some(run => run.costKind === 'unknown') ? 'unknown' as const : 'not_applicable' as const,
  } };
}
export function summarizeHistory(inputs: Buffer[]) {
  if (!inputs.length || inputs.length > 10000) throw new SafeError('invalid_history_input');
  const seen = new Map<string, string>(), entries: ReturnType<typeof project>[] = [];
  let duplicateInputs = 0, reportedCalls = 0, missingEngineRecords = 0;
  for (const bytes of inputs) {
    const entry = project(bytes), previous = seen.get(entry.row.runId);
    if (previous !== undefined) {
      if (previous !== entry.row.reportHash) throw new SafeError('history_run_identity_conflict');
      duplicateInputs++; continue;
    }
    seen.set(entry.row.runId, entry.row.reportHash); entries.push(entry);
    reportedCalls = count(reportedCalls + entry.row.reportedCalls); missingEngineRecords = count(missingEngineRecords + entry.row.missingEngineRecords);
  }
  const summary = { schema: 'scanmux.history/v1' as const, operation: 'summarized' as const,
    basis: 'selected_saved_records_not_authenticated' as const, usageScope: 'recorded_calls_in_selected_unique_runs' as const,
    runs: entries.map(entry => entry.row), duplicateInputs, reportedCalls, missingEngineRecords, cost: null,
    costKind: entries.some(entry => entry.row.costKind === 'unknown') ? 'unknown' as const : 'not_applicable' as const };
  return { summary, roots: entries.map(entry => ({ root: entry.root, repoId: entry.row.repoId })) };
}
export async function readHistoryFiles(files: string[], configPath: string | undefined, config: Config) {
  array(files); if (!files.length) throw new SafeError('invalid_history_input');
  const inputs = await Promise.all(files.map(file => canonical(file))), bytes: Buffer[] = [];
  let remaining = config.maxOutputBytes;
  for (const input of inputs) { const value = await boundedRead(input, remaining); remaining -= value.length; bytes.push(value); }
  const projected = summarizeHistory(bytes);
  const roots = await Promise.all(projected.roots.map(async entry => {
    const root = await canonical(entry.root);
    if (!(await lstat(root)).isDirectory() || hash(root) !== entry.repoId) throw new SafeError('history_target_identity_mismatch');
    await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
    if (inputs.some(input => within(root, input))) throw new SafeError('history_input_inside_target');
    return root;
  }));
  const workspace = await privateWorkspace(roots);
  const json = await checkedJson(projected.summary, config, workspace), destination = path.join(workspace, 'history.json');
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, json, { flag: 'wx', mode: 0o600 });
  return { summary: projected.summary, json, destination };
}
