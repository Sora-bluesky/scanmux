import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { CommitPair, Config, Gate, Plan, Report } from './model.ts';
import { boundedRead, canonical, digest, hash, record, SafeError, within } from './safety.ts';
import { commitPair } from './comparison.ts';
import { githubUrl } from './github.ts';
import { buildPlan, prepareGitHubPlan } from './repository.ts';
import { loadConfig } from './config.ts';
import { privateWorkspace } from './private-storage.ts';
import { scan } from './controller.ts';
import { checkedJson, saveReportBundle } from './output.ts';
import { parseReportLanguage, type ReportLanguage } from './report-language.ts';
import { exitCodes } from './policy.ts';
import { sourceCleanupFailed, sourceCleanupFor, withSourceCleanup } from './source-cleanup.ts';

export type BatchTarget = { id: string; path: string; comparison?: CommitPair; url?: never }
  | { id: string; url: string; path?: never; comparison?: never };
export type BatchMode = 'plan' | 'scan';
export interface PreparedBatch { targets: BatchTarget[]; manifestHash: string; localRoots: string[]; controlFiles: string[] }
export interface BatchJob {
  id: string; sourceKind: 'local' | 'public-github'; state: 'not_started' | 'finished' | 'failed';
  repoId: string | null; commit: string | null; planHash: string | null; runId: string | null;
  planningComplete: boolean; gate: Gate | null; errors: string[];
  outputs: { plan: string | null; report: string | null; html: string | null; sarif: string[] };
}
export interface BatchSummary {
  schema: 'scanmux.batch/v1'; batchId: string; mode: BatchMode; manifestHash: string; policyHash: string;
  startedAt: string; endedAt: string; stopReason: 'cancelled' | 'time_budget_exceeded' | 'termination_unverified' | null;
  jobs: BatchJob[]; gate: Gate | null; planningComplete: boolean; exitCode: number;
}

export function parseBatchManifest(raw: unknown): BatchTarget[] {
  const document = record(raw);
  if (Object.keys(document).sort().join(',') !== 'repositories,schema' || document.schema !== 1
    || !Array.isArray(document.repositories) || !document.repositories.length) throw new SafeError('invalid_batch_manifest');
  const ids = new Set<string>(), urls = new Set<string>();
  return document.repositories.map(rawTarget => {
    const target = record(rawTarget), id = target.id;
    if (typeof id !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,199}$/i.test(id) || ids.has(id.toLowerCase())) throw new SafeError('invalid_batch_id');
    ids.add(id.toLowerCase());
    if (Object.hasOwn(target, 'url')) {
      if (Object.keys(target).sort().join(',') !== 'id,url' || typeof target.url !== 'string') throw new SafeError('invalid_batch_target');
      const url = githubUrl(target.url);
      if (urls.has(url.toLowerCase())) throw new SafeError('duplicate_batch_target');
      urls.add(url.toLowerCase());
      return { id, url };
    }
    if (Object.keys(target).some(key => !['id', 'path', 'base', 'head'].includes(key))
      || typeof target.path !== 'string' || !path.isAbsolute(target.path)) throw new SafeError('invalid_batch_target');
    const comparison = commitPair(target.base, target.head);
    return { id, path: target.path, ...(comparison ? { comparison } : {}) };
  });
}

async function outsideRoots(candidate: string, roots: string[]): Promise<string> {
  const physical = await canonical(candidate);
  if (roots.some(root => within(root, physical))) throw new SafeError('batch_path_inside_target');
  return physical;
}
async function protectConfiguration(config: Config, roots: string[]): Promise<void> {
  const locations = Object.values(config.tools).map(tool => tool.path);
  if (config.osvDatabase) locations.push(config.osvDatabase);
  if (config.runner) locations.push(config.runner.authHome, config.runner.codex.path, config.runner.linuxCodex.path, config.runner.docker.path);
  for (const location of locations) await outsideRoots(location, roots);
}

export async function prepareBatch(file: string, configFile: string | undefined, config: Config): Promise<PreparedBatch> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  if (!path.isAbsolute(file)) throw new SafeError('batch_manifest_must_be_absolute');
  const manifest = await canonical(file), bytes = await boundedRead(manifest, config.maxOutputBytes);
  const targets = parseBatchManifest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  const localRoots: string[] = [];
  for (const target of targets) {
    if (target.path === undefined) continue;
    target.path = await canonical(target.path);
    if (localRoots.some(root => within(root, target.path!) || within(target.path!, root))) throw new SafeError('overlapping_batch_targets');
    localRoots.push(target.path);
  }
  await outsideRoots(manifest, localRoots);
  if (configFile) {
    await outsideRoots(configFile, localRoots);
    for (const root of localRoots) {
      if (digest(await loadConfig(configFile, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' })) !== digest(config)) throw new SafeError('batch_config_changed');
    }
  }
  await protectConfiguration(config, localRoots);
  return { targets, localRoots, manifestHash: hash(bytes), controlFiles: [manifest, ...(configFile ? [await canonical(configFile)] : [])] };
}

function emptyJob(target: BatchTarget): BatchJob {
  return { id: target.id, sourceKind: target.path === undefined ? 'public-github' : 'local', state: 'not_started',
    repoId: null, commit: null, planHash: null, runId: null, planningComplete: false, gate: null, errors: [],
    outputs: { plan: null, report: null, html: null, sarif: [] } };
}
const errorCode = (error: unknown) => error instanceof SafeError ? error.code : 'batch_job_failed';
const unverified = (errors: string[]) => errors.some(code => code.endsWith('termination_unverified'));

export function aggregateBatch(jobs: BatchJob[], mode: BatchMode): Pick<BatchSummary, 'gate' | 'planningComplete' | 'exitCode'> {
  const planningComplete = jobs.length > 0 && jobs.every(job => job.planningComplete && job.state === 'finished');
  if (sourceCleanupFailed()) return { gate: mode === 'scan' ? 'ERROR' : null, planningComplete, exitCode: 4 };
  if (mode === 'plan') return { gate: null, planningComplete, exitCode: jobs.some(job => job.state === 'failed') ? 4 : planningComplete ? 0 : 3 };
  const observed: Gate[] = jobs.map(job => job.state === 'failed' ? 'ERROR' : job.state !== 'finished' || job.gate === null ? 'INCOMPLETE' : job.gate);
  if (!jobs.length) observed.push('INCOMPLETE');
  const gate = (['ERROR', 'FAIL', 'INCOMPLETE', 'REVIEW', 'PASS'] as const).find(candidate => observed.includes(candidate))!;
  return { gate, planningComplete, exitCode: exitCodes[gate] };
}

type JobRunner = (target: BatchTarget, job: BatchJob, signal: AbortSignal, deadline: AbortSignal) => Promise<void>;

/** Internal orchestration seam; CLI always uses the concrete planner/scanners below. */
export async function runBatchJobs(prepared: PreparedBatch, config: Config, mode: BatchMode, signal: AbortSignal, runJob: JobRunner): Promise<BatchSummary> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const deadline = AbortSignal.timeout(config.timeoutMs);
  const summary: BatchSummary = { schema: 'scanmux.batch/v1', batchId: randomUUID(), mode,
    manifestHash: prepared.manifestHash, policyHash: digest(config), startedAt: new Date().toISOString(), endedAt: '',
    stopReason: null, jobs: prepared.targets.map(emptyJob), gate: null, planningComplete: false, exitCode: 3 };
  for (let index = 0; index < prepared.targets.length; index++) {
    if (!summary.stopReason) summary.stopReason = signal.aborted ? 'cancelled' : deadline.aborted ? 'time_budget_exceeded' : null;
    const job = summary.jobs[index];
    if (summary.stopReason) { job.errors.push(summary.stopReason, ...(sourceCleanupFailed() ? ['source_cleanup_failed'] : [])); continue; }
    try { await runJob(prepared.targets[index], job, signal, deadline); }
    catch (error) { job.state = 'failed'; job.errors.push(errorCode(error)); if (mode === 'scan') job.gate = 'ERROR'; }
    if (sourceCleanupFailed()) {
      if (!job.errors.includes('source_cleanup_failed')) job.errors.push('source_cleanup_failed');
      job.state = 'failed'; if (mode === 'scan') job.gate = 'ERROR';
    }
    if (unverified(job.errors)) summary.stopReason = 'termination_unverified';
  }
  summary.stopReason ??= signal.aborted ? 'cancelled' : deadline.aborted ? 'time_budget_exceeded' : null;
  summary.endedAt = new Date().toISOString();
  Object.assign(summary, aggregateBatch(summary.jobs, mode));
  return summary;
}

function reportErrors(report: Report): string[] {
  return [...new Set([...report.integrityErrors, ...report.plan.blockers, ...report.engines.flatMap(engine => engine.errors)])];
}

export async function executeBatch(prepared: PreparedBatch, config: Config, mode: BatchMode, signal: AbortSignal, inputLanguage: ReportLanguage = 'ja') {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const language = parseReportLanguage(inputLanguage);
  for (const file of prepared.controlFiles) await outsideRoots(file, prepared.localRoots);
  await protectConfiguration(config, prepared.localRoots);
  const workspace = await privateWorkspace(prepared.localRoots);
  const summary = await runBatchJobs(prepared, config, mode, signal, async (target, job, userSignal, deadline) => {
    const combined = AbortSignal.any([userSignal, deadline]);
    const jobWorkspace = await privateWorkspace(prepared.localRoots);
    const cleanup = sourceCleanupFor(jobWorkspace);
    return withSourceCleanup(cleanup, async () => {
    try {
      const plan: Plan = target.path === undefined
        ? await prepareGitHubPlan(target.url, config, jobWorkspace, userSignal, undefined, deadline)
        : await buildPlan(target.path, config, jobWorkspace, combined, target.comparison);
      if (target.path === undefined) {
        if (plan.root !== path.join(jobWorkspace, 'repository')) throw new SafeError('batch_acquisition_mismatch');
        await protectConfiguration(config, [...prepared.localRoots, plan.root]);
        for (const file of prepared.controlFiles) await outsideRoots(file, [plan.root]);
        await outsideRoots(workspace, [plan.root]);
        await outsideRoots(jobWorkspace, [plan.root]);
      }
      job.repoId = plan.repoId; job.commit = plan.commit; job.planHash = plan.planHash;
      job.errors.push(...plan.blockers);
      job.planningComplete = !plan.blockers.length;
      const planPath = path.join(jobWorkspace, 'plan.json');
      const planText = await checkedJson(plan, config, jobWorkspace);
      await checkedJson({ destination: planPath }, config, jobWorkspace);
      await writeFile(planPath, planText, { flag: 'wx', mode: 0o600 });
      job.outputs.plan = planPath;
      if (mode === 'scan') {
        const report = await scan(plan, config, jobWorkspace, combined);
        job.runId = report.runId; job.gate = report.gate;
        job.errors = [...new Set([...job.errors, ...reportErrors(report)])];
        const saved = await saveReportBundle(report, config, jobWorkspace, undefined, undefined, language);
        job.outputs.report = saved.destination; job.outputs.html = saved.htmlDestination;
        job.outputs.sarif = saved.sarif.map(part => part.destination);
      }
      job.state = 'finished';
    } catch (error) {
      job.errors.push(errorCode(error));
      throw error;
    } finally {
      if ((await cleanup.cleanup(jobWorkspace)).status === 'failed') {
        job.errors.push('source_cleanup_failed'); job.gate = mode === 'scan' ? 'ERROR' : null;
        job.state = 'failed';
      }
    }
    });
  });
  const destination = path.join(workspace, 'batch.json');
  const json = await checkedJson(summary, config, workspace);
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, json, { flag: 'wx', mode: 0o600 });
  return { summary, json, destination };
}
