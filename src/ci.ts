import path from 'node:path';
import { lstat, writeFile } from 'node:fs/promises';
import type { Config, Engine, Execution, Gate, Report } from './model.ts';
import { loadConfig } from './config.ts';
import { checkedJson } from './output.ts';
import { privateWorkspace } from './private-storage.ts';
import { exitCodes } from './policy.ts';
import { summarizeHistory } from './history.ts';
import { aiTransportFailures } from './report-language.ts';
import { array, boundedRead, canonical, digest, hash, record, SafeError, within } from './safety.ts';

const engines: readonly Engine[] = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'];
const executions: readonly Execution[] = ['completed', 'failed', 'cancelled', 'budget_exceeded', 'not_started'];
const coverages = ['analyzed', 'unsupported', 'skipped', 'partial'] as const;
const gates: readonly Gate[] = ['PASS', 'REVIEW', 'INCOMPLETE', 'FAIL', 'ERROR'];
interface Identity { repoId: string; commit: string; policyHash: string; planHash: string; snapshotHash: string }
interface ExpectedJob extends Identity { id: string; targetRoot: string }
export type CiExpectation = { schema: 'scanmux.ci-expectation/v1'; ciRun: string; jobs: ExpectedJob[] }
  | { schema: 'scanmux.ci-expectation/v2'; ciRun: string; jobs: (ExpectedJob & { analysis: 'offline' | 'ai' })[] };
interface OfflineCiReceipt extends Identity {
  schema: 'scanmux.ci-receipt/v1'; ciRun: string; jobId: string; reportRunId: string; reportHash: string;
  gate: Gate; executionState: Execution; coverageState: 'complete' | 'incomplete';
  engines: { engine: Engine; execution: Execution; coverage: typeof coverages[number] }[];
}
export type CiReceipt = OfflineCiReceipt | (Omit<OfflineCiReceipt, 'schema'> & { schema: 'scanmux.ci-receipt/v2'; analysis: 'ai' });
const identityKeys = ['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash'] as const;
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  const value = record(input);
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new SafeError('invalid_ci_manifest');
  return value;
}
function text(input: unknown, pattern: RegExp): string {
  if (typeof input !== 'string' || !pattern.test(input)) throw new SafeError('invalid_ci_manifest');
  return input;
}
function choice<T extends string>(input: unknown, choices: readonly T[]): T {
  if (typeof input !== 'string' || !choices.includes(input as T)) throw new SafeError('invalid_ci_manifest');
  return input as T;
}
const uuid = (input: unknown) => text(input, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
const jobId = (input: unknown) => text(input, /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/);
function identity(value: Record<string, unknown>): Identity {
  return { repoId: text(value.repoId, /^[0-9a-f]{64}$/), commit: text(value.commit, /^[0-9a-f]{40}$/),
    policyHash: text(value.policyHash, /^[0-9a-f]{64}$/), planHash: text(value.planHash, /^[0-9a-f]{64}$/), snapshotHash: text(value.snapshotHash, /^[0-9a-f]{64}$/) };
}
export function ciArguments(ciRun: unknown, id: unknown): { ciRun: string; jobId: string } | undefined {
  if (ciRun === undefined && id === undefined) return undefined;
  return { ciRun: uuid(ciRun), jobId: jobId(id) };
}
export function parseCiExpectation(input: unknown): CiExpectation {
  const value = exact(input, ['schema', 'ciRun', 'jobs']);
  const schema = choice(value.schema, ['scanmux.ci-expectation/v1', 'scanmux.ci-expectation/v2']);
  const jobs = array(value.jobs).map(input => {
    const row = exact(input, ['id', 'targetRoot', ...identityKeys, ...(schema === 'scanmux.ci-expectation/v2' ? ['analysis'] : [])]);
    if (typeof row.targetRoot !== 'string' || !path.win32.isAbsolute(row.targetRoot) && !path.posix.isAbsolute(row.targetRoot)) throw new SafeError('invalid_ci_manifest');
    const job = { id: jobId(row.id), targetRoot: row.targetRoot, ...identity(row) };
    return schema === 'scanmux.ci-expectation/v2' ? { ...job, analysis: choice(row.analysis, ['offline', 'ai']) } : job;
  });
  if (!jobs.length || new Set(jobs.map(row => row.id)).size !== jobs.length) throw new SafeError('invalid_ci_manifest');
  if (schema === 'scanmux.ci-expectation/v1') return { schema, ciRun: uuid(value.ciRun), jobs };
  return { schema, ciRun: uuid(value.ciRun), jobs: jobs.map(job => {
    if (!('analysis' in job)) throw new SafeError('invalid_ci_manifest');
    return job;
  }) };
}
export function parseCiReceipt(input: unknown): CiReceipt {
  const schema = choice(record(input).schema, ['scanmux.ci-receipt/v1', 'scanmux.ci-receipt/v2']);
  const value = exact(input, ['schema', 'ciRun', 'jobId', 'reportRunId', 'reportHash', ...identityKeys, 'gate', 'executionState', 'coverageState', 'engines', ...(schema === 'scanmux.ci-receipt/v2' ? ['analysis'] : [])]);
  const runs = array(value.engines).map(input => {
    const run = exact(input, ['engine', 'execution', 'coverage']);
    return { engine: choice(run.engine, engines), execution: choice(run.execution, executions), coverage: choice(run.coverage, coverages) };
  });
  if (new Set(runs.map(run => run.engine)).size !== runs.length) throw new SafeError('invalid_ci_manifest');
  const receipt = { ciRun: uuid(value.ciRun), jobId: jobId(value.jobId), reportRunId: uuid(value.reportRunId),
    reportHash: text(value.reportHash, /^[0-9a-f]{64}$/), ...identity(value), gate: choice(value.gate, gates),
    executionState: choice(value.executionState, executions), coverageState: choice(value.coverageState, ['complete', 'incomplete']), engines: runs };
  return schema === 'scanmux.ci-receipt/v1' ? { schema, ...receipt } : { schema, ...receipt, analysis: choice(value.analysis, ['ai']) };
}
function strongest(values: Gate[]): Gate { return gates[Math.max(...values.map(value => gates.indexOf(value)))]; }
function savedCiReports(inputs: Buffer[]) {
  const reports = inputs.map(bytes => {
    if (!Buffer.isBuffer(bytes)) throw new SafeError('invalid_ci_report');
    const projected = summarizeHistory([bytes]), report = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))), plan = record(report.plan);
    const transportFailures = array(report.engines).flatMap(input => { const run = record(input); return run.engine === 'codex-security' ? aiTransportFailures(run.aiExecution) : []; });
    return { sha256: hash(bytes), row: projected.summary.runs[0], root: projected.roots[0].root, transportFailures,
      ai: plan.network === 'openai-responses' && plan.ai !== undefined && plan.ai !== null };
  });
  if (new Set(reports.map(report => report.sha256)).size !== reports.length || new Set(reports.map(report => report.row.runId)).size !== reports.length) throw new SafeError('invalid_ci_report');
  return new Map(reports.map(report => [report.sha256, report]));
}
function engineIdentity(runs: { engine: Engine; execution: Execution | null; coverage: string | null }[]) {
  return digest(runs.map(({ engine, execution, coverage }) => ({ engine, execution, coverage })).sort((a, b) => a.engine.localeCompare(b.engine)));
}
export function evaluateCi(expectedInput: unknown, receiptInputs: unknown[], reportInputs: Buffer[] = []) {
  const expected = parseCiExpectation(expectedInput), receipts = array(receiptInputs).map(parseCiReceipt);
  array(reportInputs);
  if (expected.schema === 'scanmux.ci-expectation/v1' && (reportInputs.length || receipts.some(receipt => receipt.schema !== 'scanmux.ci-receipt/v1'))) throw new SafeError('invalid_ci_manifest');
  const reports = savedCiReports(reportInputs), usedReports = new Set<string>();
  if (new Set(receipts.map(row => row.jobId)).size !== receipts.length || new Set(receipts.map(row => row.reportRunId)).size !== receipts.length
    || receipts.some(row => !expected.jobs.some(job => job.id === row.jobId))) throw new SafeError('invalid_ci_manifest');
  const jobs = expected.jobs.map(job => {
    const receipt = receipts.find(row => row.jobId === job.id);
    const reasons: string[] = [];
    const analysis = 'analysis' in job ? job.analysis : 'offline';
    let reportState: 'not_required' | 'missing' | 'verified' = analysis === 'ai' ? 'missing' : 'not_required';
    let reportHash: string | null = null;
    let gate: Gate = receipt?.gate ?? 'INCOMPLETE';
    if (!receipt) reasons.push('required_job_missing');
    else {
      if (receipt.ciRun !== expected.ciRun || identityKeys.some(key => receipt[key] !== job[key])) { gate = 'ERROR'; reasons.push('ci_identity_mismatch'); }
      if (receipt.executionState === 'failed' || receipt.engines.some(run => run.execution === 'failed')) { gate = 'ERROR'; reasons.push('ci_execution_failed'); }
      if (receipt.executionState !== 'completed' || receipt.coverageState !== 'complete'
        || engines.some(engine => !receipt.engines.some(run => run.engine === engine && run.execution === 'completed' && run.coverage === 'analyzed'))) {
        gate = strongest([gate, 'INCOMPLETE']); reasons.push('required_analysis_incomplete');
      }
      if (receipt.gate !== 'PASS') reasons.push('report_not_pass');
      const receivedAnalysis = receipt.schema === 'scanmux.ci-receipt/v2' ? 'ai' : 'offline';
      if (receivedAnalysis !== analysis) { gate = 'ERROR'; reasons.push('ci_analysis_mode_mismatch'); }
      if (analysis === 'ai' && receivedAnalysis === 'ai') {
        const saved = reports.get(receipt.reportHash);
        if (!saved) { gate = strongest([gate, 'INCOMPLETE']); reasons.push('required_ai_report_missing'); }
        else {
          if (usedReports.has(saved.sha256)) throw new SafeError('invalid_ci_report');
          usedReports.add(saved.sha256);
          const row = saved.row;
          if (!saved.ai || saved.root !== job.targetRoot || row.runId !== receipt.reportRunId
            || receipt.ciRun !== expected.ciRun || identityKeys.some(key => row[key] !== receipt[key] || row[key] !== job[key]) || row.recordedGate !== receipt.gate
            || row.executionState !== receipt.executionState || row.coverageState !== receipt.coverageState
            || engineIdentity(row.engines.filter(run => run.recordState === 'recorded')) !== engineIdentity(receipt.engines)) {
            gate = 'ERROR'; reasons.push('ci_report_mismatch');
          } else {
            reportState = 'verified'; reportHash = saved.sha256;
            if (row.completion !== 'complete') { gate = strongest([gate, 'INCOMPLETE']); reasons.push('ci_ai_analysis_incomplete'); }
          }
        }
      }
    }
    return expected.schema === 'scanmux.ci-expectation/v1' ? { id: job.id, gate, reasons }
      : { id: job.id, analysis, gate, reasons, reportState, reportHash };
  });
  if (usedReports.size !== reports.size) throw new SafeError('ci_report_unassociated');
  const gate = strongest(jobs.map(job => job.gate));
  return { schema: expected.schema === 'scanmux.ci-expectation/v1' ? 'scanmux.ci-result/v1' as const : 'scanmux.ci-result/v2' as const, ciRun: expected.ciRun, gate, exitCode: exitCodes[gate], jobs };
}

export function ciSummary(result: ReturnType<typeof evaluateCi>, reportInputs: Buffer[] = []): string {
  const reports = savedCiReports(reportInputs);
  const jobs = result.jobs.map(job => {
    let program = '', diagnostics = '';
    if ('analysis' in job && job.analysis === 'ai') {
      const saved = job.reportState === 'verified' && job.reportHash ? reports.get(job.reportHash) : undefined;
      const run = saved?.row.engines.find(run => run.engine === 'codex-security');
      const ai = run?.recordState === 'recorded' ? run.ai : undefined;
      program = `; effective program=${ai?.programs?.length ? ai.programs.join(',') : 'unknown'}`;
      diagnostics = saved?.transportFailures.map(row => `  AI transport diagnostic #${row.sequence}: ${row.failureCode}\n`).join('') ?? '';
    }
    return `${job.id}: ${job.gate}; reasons=${job.reasons.join(',') || 'none'}${program}\n${diagnostics}`;
  });
  return `ScanMux CI: ${result.gate} (exit ${result.exitCode})\n${jobs.join('')}`;
}

// The caller supplies only the result returned after saveReportBundle finished all writes.
// This receipt is a trusted-controller record, not a signature or an import authenticator.
export function ciReceipt(bundle: { report: Report; json: string }, ciRun: string, id: string): CiReceipt {
  const { report, json } = bundle;
  if (digest(JSON.parse(json)) !== digest(report) || report.schema !== 'scanmux.report/v2' || report.exitCode !== exitCodes[report.gate]
    || report.plan.required.length !== engines.length || engines.some(engine => !report.plan.required.includes(engine))) throw new SafeError('invalid_ci_report');
  const ai = report.plan.ai !== undefined || report.plan.network === 'openai-responses';
  if (ai && (report.plan.ai === undefined || report.plan.network !== 'openai-responses')) throw new SafeError('invalid_ci_report');
  return parseCiReceipt({ schema: ai ? 'scanmux.ci-receipt/v2' : 'scanmux.ci-receipt/v1', ...(ai ? { analysis: 'ai' } : {}), ciRun, jobId: id, reportRunId: report.runId, reportHash: hash(Buffer.from(json, 'utf8')),
    repoId: report.plan.repoId, commit: report.plan.commit, policyHash: report.plan.policyHash, planHash: report.plan.planHash, snapshotHash: report.plan.snapshotHash,
    gate: report.gate, executionState: report.executionState, coverageState: report.coverageState,
    engines: report.engines.map(run => ({ engine: run.engine, execution: run.execution, coverage: run.coverage })) });
}
export async function saveCiReceipt(bundle: { report: Report; json: string }, ciRun: string, id: string, config: Config, workspace: string,
  check: typeof checkedJson = checkedJson) {
  const receipt = ciReceipt(bundle, ciRun, id), json = await check(receipt, config, workspace);
  const destination = path.join(workspace, 'ci-receipt.json');
  await check({ destination }, config, workspace);
  await writeFile(destination, json, { mode: 0o600, flag: 'wx' });
  return { receipt, destination };
}
export async function checkCiFiles(expectationPath: string, receiptPaths: string[], configPath: string | undefined, config: Config, reportPaths: string[] = []) {
  const inputs = await Promise.all([expectationPath, ...receiptPaths, ...reportPaths].map(file => canonical(file)));
  if (new Set(inputs).size !== inputs.length) throw new SafeError('invalid_ci_manifest');
  let remaining = config.maxOutputBytes;
  const read = async (file: string) => {
    const bytes = await boundedRead(file, remaining); remaining -= bytes.length;
    return bytes;
  };
  const json = (bytes: Buffer) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  const expected = parseCiExpectation(json(await read(inputs[0])));
  const roots = await Promise.all(expected.jobs.map(async job => {
    const root = await canonical(job.targetRoot);
    if (!(await lstat(root)).isDirectory() || hash(root) !== job.repoId) throw new SafeError('ci_target_identity_mismatch');
    await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
    if (inputs.some(file => within(root, file))) throw new SafeError('ci_input_inside_target');
    return root;
  }));
  const receipts = [];
  for (const file of inputs.slice(1, 1 + receiptPaths.length)) receipts.push(json(await read(file)));
  const reports = [];
  for (const file of inputs.slice(1 + receiptPaths.length)) reports.push(await read(file));
  const result = evaluateCi(expected, receipts, reports);
  const workspace = await privateWorkspace(roots);
  const output = await checkedJson(result, config, workspace), destination = path.join(workspace, 'ci-result.json');
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, output, { mode: 0o600, flag: 'wx' });
  return { result, json: output, destination, summary: ciSummary(result, reports) };
}
