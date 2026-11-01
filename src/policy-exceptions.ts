import path from 'node:path';
import { lstat, writeFile } from 'node:fs/promises';
import type { Config, Engine, Gate } from './model.ts';
import { loadConfig } from './config.ts';
import { evaluateDispositions } from './dispositions.ts';
import { decide, exitCodes } from './policy.ts';
import { checkedJson } from './output.ts';
import { privateWorkspace } from './private-storage.ts';
import { array, boundedRead, canonical, hash, record, SafeError, within } from './safety.ts';

const engines = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const;
const gates: readonly Gate[] = ['PASS', 'REVIEW', 'INCOMPLETE', 'FAIL', 'ERROR'];
function choice<T extends string>(input: unknown, allowed: readonly T[]): T {
  if (typeof input !== 'string' || !allowed.includes(input as T)) throw new SafeError('invalid_policy_report');
  return input as T;
}
function strings(input: unknown): string[] {
  return array(input).map(value => {
    if (typeof value !== 'string') throw new SafeError('invalid_policy_report');
    return value;
  });
}
const key = (item: { engine: Engine; fingerprint: string }) => `${item.engine}:${item.fingerprint}`;
const strongest = (...values: Gate[]): Gate => gates[Math.max(...values.map(value => gates.indexOf(value)))];

export function evaluatePolicyExceptions(reportBytes: Buffer, decisionBytes: Buffer, now = new Date()) {
  const assessed = evaluateDispositions(reportBytes, decisionBytes, now), original = assessed.summary.original;
  const report = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(reportBytes))), rawPlan = record(report.plan);
  const required = array(rawPlan.required).map(value => choice(value, engines));
  if (required.length !== engines.length || new Set(required).size !== engines.length) throw new SafeError('invalid_policy_report');
  const plan = { required, blockers: strings(rawPlan.blockers), exclusions: array(rawPlan.exclusions).map(value => {
    const item = record(value);
    if (typeof item.path !== 'string' || typeof item.reason !== 'string') throw new SafeError('invalid_policy_report');
    return { path: item.path, reason: item.reason };
  }) };
  const runs = array(report.engines).map(value => {
    const run = record(value), engine = choice(run.engine, engines);
    const execution = choice(run.execution, ['completed', 'failed', 'cancelled', 'budget_exceeded', 'not_started'] as const);
    const coverage = choice(run.coverage, ['analyzed', 'unsupported', 'skipped', 'partial'] as const);
    const errors = strings(run.errors), exclusions = strings(run.exclusions);
    if (coverage === 'analyzed' && (execution !== 'completed' || errors.length || exclusions.length)) throw new SafeError('inconsistent_policy_report');
    const findings = array(run.findings).map(value => {
      const item = record(value);
      // Exact engine/fingerprint identity was already validated by evaluateDispositions.
      if (typeof item.fingerprint !== 'string') throw new SafeError('invalid_policy_report');
      return { engine, fingerprint: item.fingerprint,
        category: choice(item.category, ['secret', 'dependency', 'code', 'runtime'] as const),
        severity: choice(item.severity, ['critical', 'high', 'medium', 'low', 'informational', 'unknown'] as const),
        evidenceState: choice(item.evidenceState, ['candidate', 'source_supported', 'runtime_reproduced'] as const) };
    });
    return { engine, execution, coverage, errors, exclusions, findings };
  });
  const integrityErrors = strings(report.integrityErrors), originalReasons = strings(report.reasons);
  const baseline = decide(plan, runs, integrityErrors);
  if (baseline.gate !== original.recordedGate || report.exitCode !== exitCodes[baseline.gate]) throw new SafeError('inconsistent_policy_report');
  const rows = assessed.summary.rows.map(row => ({ ...row, applied: row.source === 'current_finding' && row.state === 'current' }));
  const applied = new Set(rows.filter(row => row.applied).map(key));
  const filtered = runs.map(run => ({ ...run, findings: run.findings.filter(finding => !applied.has(key(finding))) }));
  const judgment = decide(plan, filtered, integrityErrors), reasons = [...judgment.reasons];
  let gate = judgment.gate;
  const terminationUnverified = [...plan.blockers, ...integrityErrors, ...runs.flatMap(run => run.errors)].some(reason => reason.endsWith('termination_unverified'));
  if (terminationUnverified) { gate = 'ERROR'; reasons.push('termination_unverified'); }
  if (original.executionState === 'failed' || original.recordedGate === 'ERROR') { gate = 'ERROR'; reasons.push('original_execution_error'); }
  if (original.completion !== 'complete' || original.recordedGate === 'INCOMPLETE' || runs.some(run => run.errors.length || run.exclusions.length)) {
    gate = strongest(gate, 'INCOMPLETE'); reasons.push('required_analysis_incomplete');
  }
  if (rows.some(row => row.state === 'expired' || row.state === 'reconfirmation_required')) {
    gate = strongest(gate, 'INCOMPLETE'); reasons.push('exception_reconfirmation_required');
  }
  return { root: assessed.root, summary: {
    schema: 'scanmux.policy-result/v1' as const, operation: 'applied_saved_report_exceptions' as const,
    basis: 'exact_saved_report_bytes_not_authenticated' as const, reviewerIdentity: 'declared_not_authenticated' as const,
    evaluatedAt: assessed.summary.evaluatedAt, policyRevision: 'saved-report-exceptions/v1' as const,
    decisionsHash: hash(decisionBytes), original: { ...original, reasons: originalReasons },
    gate, exitCode: exitCodes[gate], reasons: [...new Set(reasons)], rows,
    counts: { ...assessed.summary.counts, applied: applied.size },
    originalReportChanged: false as const, automaticCarryover: false as const,
  } };
}

export async function checkPolicyFiles(reportFile: string, decisionFile: string, configPath: string | undefined, config: Config) {
  if (![reportFile, decisionFile].every(file => typeof file === 'string' && path.isAbsolute(file))) throw new SafeError('invalid_policy_path');
  const inputs = await Promise.all([reportFile, decisionFile].map(file => canonical(file)));
  const reportBytes = await boundedRead(inputs[0], config.maxOutputBytes);
  const decisionBytes = await boundedRead(inputs[1], config.maxOutputBytes - reportBytes.length);
  const evaluated = evaluatePolicyExceptions(reportBytes, decisionBytes), root = await canonical(evaluated.root);
  if (!(await lstat(root)).isDirectory() || hash(root) !== evaluated.summary.original.repoId) throw new SafeError('policy_target_mismatch');
  await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
  if (inputs.some(input => within(root, input))) throw new SafeError('policy_input_inside_target');
  const workspace = await privateWorkspace(root), destination = path.join(workspace, 'policy-result.json');
  const json = await checkedJson(evaluated.summary, config, workspace);
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, json, { flag: 'wx', mode: 0o600 });
  return { summary: evaluated.summary, destination, json };
}
