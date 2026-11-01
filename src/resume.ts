import path from 'node:path';
import { lstat, writeFile } from 'node:fs/promises';
import type { Config, Plan } from './model.ts';
import { summarizeHistory } from './history.ts';
import { checkedJson, type saveReportBundle } from './output.ts';
import { array, boundedRead, canonical, digest, hash, outside, record, SafeError } from './safety.ts';

type SavedRun = ReturnType<typeof summarizeHistory>['summary']['runs'][number];
export interface ResumeSource { previous: SavedRun }

function verifyTermination(input: unknown): void {
  for (const code of array(input)) {
    if (typeof code !== 'string') throw new SafeError('invalid_resume_report');
    if (code.endsWith('termination_unverified')) throw new SafeError('resume_termination_unverified');
  }
}

export function resumeSource(bytes: Buffer, currentRoot: string): ResumeSource {
  const report = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))), plan = record(report.plan);
  const projected = summarizeHistory([bytes]), previous = projected.summary.runs[0];
  if (plan.ai !== undefined || plan.network === 'openai-responses') throw new SafeError('resume_ai_unsupported');
  if (plan.root !== currentRoot || previous.repoId !== hash(currentRoot)) throw new SafeError('resume_target_mismatch');
  if (!['cancelled', 'budget_exceeded'].includes(previous.executionState)) throw new SafeError('resume_requires_stopped_run');
  verifyTermination(plan.blockers); verifyTermination(report.integrityErrors);
  for (const engine of array(report.engines)) verifyTermination(record(engine).errors);
  if (plan.planHash !== digest({ ...plan, planHash: '' })) throw new SafeError('resume_plan_integrity');
  return { previous };
}

export async function readResumeSource(file: string, currentRoot: string, config: Config): Promise<ResumeSource> {
  if (!path.isAbsolute(file)) throw new SafeError('invalid_resume_path');
  const root = await canonical(currentRoot);
  if (!(await lstat(root)).isDirectory()) throw new SafeError('resume_target_mismatch');
  const input = await outside(file, root);
  return resumeSource(await boundedRead(input, config.maxOutputBytes), root);
}

export function verifyResumePlan(source: ResumeSource, plan: Plan): void {
  if (plan.planHash !== digest({ ...plan, planHash: '' })) throw new SafeError('resume_plan_integrity');
  if (plan.blockers.length) throw new SafeError('resume_plan_blocked');
  if (plan.network !== 'offline' || plan.cost.kind !== 'not_applicable' || plan.cost.aiCalls !== 0) throw new SafeError('resume_offline_only');
  for (const field of ['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash'] as const) {
    if (plan[field] !== source.previous[field]) throw new SafeError('resume_identity_mismatch');
  }
  if (plan.commit === null) throw new SafeError('resume_identity_mismatch');
}

function usage(run: SavedRun) {
  return { runId: run.runId, reportHash: run.reportHash, execution: run.executionState, recordedGate: run.recordedGate,
    reportedCalls: run.reportedCalls, missingEngineRecords: run.missingEngineRecords, cost: null, costKind: run.costKind };
}

export function resumeReceipt(source: ResumeSource, bundle: Awaited<ReturnType<typeof saveReportBundle>>) {
  const current = summarizeHistory([Buffer.from(bundle.json, 'utf8')]).summary.runs[0];
  verifyResumePlan(source, bundle.report.plan);
  if (current.runId === source.previous.runId) throw new SafeError('resume_run_identity_conflict');
  return { schema: 'scanmux.resume/v1' as const, operation: 'reexecuted' as const, scope: 'full_scan_new_run' as const,
    basis: 'selected_saved_records_not_authenticated' as const, repoId: current.repoId, commit: current.commit,
    policyHash: current.policyHash, planHash: current.planHash, snapshotHash: current.snapshotHash,
    previous: usage(source.previous), current: usage(current), accountUsage: 'unknown' as const };
}

export async function saveResumeReceipt(source: ResumeSource, bundle: Awaited<ReturnType<typeof saveReportBundle>>, config: Config, workspace: string) {
  const receipt = resumeReceipt(source, bundle), destination = path.join(workspace, 'resume.json');
  const json = await checkedJson(receipt, config, workspace);
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, json, { flag: 'wx', mode: 0o600 });
  return { receipt, destination, json };
}
