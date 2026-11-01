import { JobDisk, withJobDisk } from './job-disk.ts';
import { scopedProcessOwner } from './process-tree.ts';
import { catalogIdentity } from './advisory-catalog.ts';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import type { Adapter, Config, Plan, Report } from './model.ts';
import { createAdapters, emptyRun } from './adapters.ts';
import { decide, exitCodes } from './policy.ts';
import { materialize, verifySnapshot } from './repository.ts';
import { digest, SafeError } from './safety.ts';
import { comparisonSummary } from './comparison.ts';
import { CheckpointOwnerStop, openEngineCheckpoints, type EngineCheckpointBackend } from './engine-checkpoint.ts';
import { verifyEngineCatalog } from './engine-catalog.ts';
import { CopyBudget, withCopyBudget } from './copy-budget.ts';
import { sourceCleanupFailed, sourceCleanupFor, withSourceCleanup } from './source-cleanup.ts';

// Single-job entry points explicitly share their admission/host budget; other scans start fresh.
export async function scan(plan: Plan, config: Config, workspace: string, signal: AbortSignal,
  adapters: Adapter[] = createAdapters(plan), checkpointBackend?: EngineCheckpointBackend,
  copyBudget: CopyBudget | undefined = config.maxCopyBytes === undefined ? undefined : new CopyBudget(config.maxCopyBytes),
  jobDisk: JobDisk | undefined = config.maxJobDiskBytes === undefined ? undefined : new JobDisk(config.maxJobDiskBytes)): Promise<Report> {
  const cleanup = sourceCleanupFor(workspace);
  return withSourceCleanup(cleanup, () => withJobDisk(jobDisk, () => withCopyBudget(copyBudget, async () => {
  jobDisk?.register(workspace);
  const ownerWorkspace = scopedProcessOwner()?.workspace;
  if (ownerWorkspace) jobDisk?.register(ownerWorkspace);
  const startedAt = new Date().toISOString();
  const runId = randomUUID();
  cleanup.register(workspace, path.join(workspace, 'snapshot'));
  const engines: Report['engines'] = [];
  const integrityErrors: string[] = [];
  let snapshot = '';
  const deadline = AbortSignal.timeout(config.timeoutMs);
  const combined = AbortSignal.any([signal, deadline, ...(jobDisk ? [jobDisk.signal] : [])]);
  let checkpoints: Awaited<ReturnType<typeof openEngineCheckpoints>> | undefined;
  let checkpointFailure: string | undefined;
  let ownerStopped = false;
  const diskStopCause = () => jobDisk?.cause && combined.reason === jobDisk.signal.reason ? jobDisk.cause : undefined;
  const cancelledFirst = () => signal.aborted && (!jobDisk || combined.reason === signal.reason);
  function applyStop(run: Report['engines'][number]): void {
    if (!jobDisk) return;
    const cause = diskStopCause() ?? (combined.aborted ? cancelledFirst() ? 'cancelled' : 'time_budget_exceeded' : undefined);
    if (!cause) return;
    // Preserve execution/integrity errors and all findings (including FAIL).
    if (run.execution !== 'failed') run.execution = cause === 'job_disk_observation_unverified' ? 'failed' : cause === 'cancelled' ? 'cancelled' : 'budget_exceeded';
    if (run.coverage === 'analyzed') run.coverage = 'partial';
    if (!run.errors.includes(cause)) run.errors.push(cause);
  }
  function report(): Report {
    const errors = sourceCleanupFailed() ? [...new Set([...integrityErrors, 'source_cleanup_failed'])] : integrityErrors;
    const judgment = decide(plan, engines, errors);
    const ai = engines.find(engine => engine.engine === 'codex-security')?.aiExecution;
    const isolation: Report['runner']['isolation'] = ai?.runtime.boundaryVerified ? 'host-relay-readonly-linux'
      : ai?.sourcePreflight === 'completed' ? 'host-relay-linux-unverified' : 'local-static-only';
    return {
      schema: plan.schema === 'scanmux.plan/v3' ? 'scanmux.report/v3' : 'scanmux.report/v2', runId, plan, startedAt, endedAt: new Date().toISOString(), engines,
      runner: { platform: process.platform, node: process.version, imageDigest: ai?.runtime.boundaryVerified ? ai.runtime.imageDigest : null, isolation },
      executionState: errors.length ? 'failed' : cancelledFirst() ? 'cancelled' : engines.some(e => e.execution === 'budget_exceeded') ? 'budget_exceeded' : engines.some(e => e.execution === 'failed') ? 'failed' : 'completed',
      coverageState: plan.blockers.length || plan.exclusions.length || engines.length !== plan.required.length || engines.some(e => e.coverage !== 'analyzed') ? 'incomplete' : 'complete',
      ...judgment, exitCode: exitCodes[judgment.gate], integrityErrors: errors,
    };
  }
  try {
    if (plan.policyHash !== digest(config) || plan.planHash !== digest({ ...plan, planHash: '' })) throw new SafeError('plan_integrity');
    comparisonSummary(plan);
    if (!['scanmux.plan/v2', 'scanmux.plan/v3'].includes(plan.schema)
      || plan.schema === 'scanmux.plan/v2' && !plan.required.includes('runtime-advisories')
      || digest(plan.advisoryCatalog) !== digest(catalogIdentity)) throw new SafeError('advisory_plan_mismatch');
    if (plan.schema === 'scanmux.plan/v3') verifyEngineCatalog(plan);
    if (plan.blockers.some(code => code.endsWith('termination_unverified'))) integrityErrors.push('termination_unverified');
    await jobDisk?.check(true);
    if (!plan.blockers.length) snapshot = await materialize(plan, config, workspace, combined);
    for (const adapter of adapters) {
      const context = { plan, config, workspace, snapshot, signal: combined, ...(copyBudget ? { copyBudget } : {}),
        secretScan: engines.find(e => e.engine === 'gitleaks'),
        secretsCleared: engines.some(e => e.engine === 'gitleaks' && e.execution === 'completed' && e.coverage === 'analyzed' && !e.findings.length) };
      if (plan.blockers.length || integrityErrors.length || !snapshot) { engines.push(emptyRun(adapter.capabilities().engine, context, 'plan_blocked')); continue; }
      const diskCause = diskStopCause();
      if (diskCause) {
        const run = emptyRun(adapter.capabilities().engine, context, diskCause);
        run.execution = diskCause === 'job_disk_measured_limit' ? 'budget_exceeded' : 'failed'; engines.push(run); continue;
      }
      if (combined.aborted) {
        const run = emptyRun(adapter.capabilities().engine, context, cancelledFirst() ? 'cancelled_before_start' : 'time_budget_exceeded');
        run.execution = cancelledFirst() ? 'cancelled' : 'budget_exceeded'; engines.push(run); continue;
      }
      engines.push(await adapter.run(context));
      await jobDisk?.check(true).catch(() => {});
      applyStop(engines.at(-1)!);
      if (checkpointBackend && engines.at(-1)!.execution === 'failed') await checkpointBackend.failure('engine_execution_failed', combined);
      if (engines.at(-1)!.errors.some(code => code.endsWith('termination_unverified'))) {
        integrityErrors.push('termination_unverified');
      } else if (!await verifySnapshot(plan, snapshot)) integrityErrors.push('snapshot_changed');
      if (checkpointBackend && integrityErrors.length) await checkpointBackend.failure('controller_integrity_failure', combined);
      if (jobDisk && combined.aborted && !diskStopCause()) continue;
      try {
        checkpoints ??= await openEngineCheckpoints(workspace, config, checkpointBackend);
        try { await checkpoints.save(report(), diskStopCause() ? signal : combined); }
        catch (error) {
          if (!(error instanceof SafeError) || !diskStopCause() || error.code !== diskStopCause()) throw error;
          // A disk stop during the secret check happens before durable checkpoint writes.
          // Save the newly observed cause with observation suspended only for output validation.
          applyStop(engines.at(-1)!);
          await checkpoints.save(report(), signal);
        }
      } catch (error) {
        if (error instanceof CheckpointOwnerStop) { ownerStopped = true; throw error; }
        if (jobDisk && combined.aborted && !diskStopCause() && error instanceof SafeError && error.code === 'cancelled') throw error;
        checkpointFailure = error instanceof SafeError && error.code.endsWith('termination_unverified') ? error.code : 'checkpoint_save_failed';
        throw error;
      }
    }
  } catch (error) {
    const diskCause = diskStopCause();
    if (ownerStopped) {
      // Only the outside owner's accepted prefix is evidence after it refuses admission.
    } else if (checkpointFailure) {
      integrityErrors.push(checkpointFailure);
    } else if (error instanceof SafeError && error.code.endsWith('termination_unverified')) {
      integrityErrors.push('termination_unverified');
    } else if (diskCause && error instanceof SafeError && (error.code === diskCause || error.code === 'git_' + diskCause)) {
      for (const id of plan.required.filter(id => !engines.some(e => e.engine === id))) {
        const run = emptyRun(id, { plan, config, workspace, snapshot, signal: combined, secretsCleared: false }, diskCause);
        run.execution = diskCause === 'job_disk_measured_limit' ? 'budget_exceeded' : 'failed'; engines.push(run);
      }
    } else if (error instanceof SafeError && error.code === 'job_disk_copy_limit') {
      for (const id of plan.required.filter(id => !engines.some(e => e.engine === id))) {
        const run = emptyRun(id, { plan, config, workspace, snapshot, signal: combined, secretsCleared: false }, error.code);
        run.execution = 'budget_exceeded'; engines.push(run);
      }
    } else if (combined.aborted && !diskCause) {
      for (const id of plan.required.filter(id => !engines.some(e => e.engine === id))) {
        const run = emptyRun(id, { plan, config, workspace, snapshot, signal: combined, secretsCleared: false }, cancelledFirst() ? 'cancelled' : 'time_budget_exceeded');
        run.execution = cancelledFirst() ? 'cancelled' : 'budget_exceeded'; engines.push(run);
      }
    } else {
      integrityErrors.push(error instanceof SafeError ? error.code : 'controller_failure');
      if (diskCause) integrityErrors.push(diskCause);
    }
  } finally {
    jobDisk?.end();
    if ((await cleanup.cleanup(workspace)).status === 'failed') integrityErrors.push('source_cleanup_failed');
  }
  return report();
  })));
}
