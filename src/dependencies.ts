import { sourceCleanupFor, withSourceCleanup } from './source-cleanup.ts';
import { createAdapters } from './adapters.ts';
import { assessUpgrades, dependencyInputPath, diffDependencies, type DependencyDiff, type HeadProject, type UpgradeAssessment, type UpgradeFinding } from './dependency-graph.ts';
import { buildPlan, materialize, readCommitFiles, verifySnapshot } from './repository.ts';
import { hash, SafeError } from './safety.ts';
import type { CommitPair, Config, EngineRun, Plan } from './model.ts';

export type MissingItem =
  | { readonly kind: 'plan_blocker'; readonly code: string }
  | { readonly kind: 'input_excluded'; readonly side: 'base' | 'head'; readonly path: string; readonly reason: string }
  | { readonly kind: 'osv'; readonly state: OsvState; readonly reason: string }
  | { readonly kind: 'project_undetermined'; readonly side: 'base' | 'head'; readonly lockfile: string; readonly reason: string }
  | { readonly kind: 'change_limit'; readonly lockfile: string };
export type OsvState = 'completed' | 'partial' | 'failed' | 'not_applicable' | 'not_started';
export interface InputRecord { readonly path: string; readonly bytes: number; readonly sha256: string }
export interface DiffCounts {
  readonly versionChanged: number; readonly added: number; readonly removed: number; readonly relocated: number; readonly metadataOnly: number;
  readonly explained: number; readonly unexplained: number; readonly undeterminedExplanations: number;
}
export interface DependencyReport {
  readonly schema: 'scanmux.dependencies/v1';
  readonly commits: { readonly head: string | null; readonly base: string | null };
  readonly planHash: string;
  readonly inputs: { readonly head: readonly InputRecord[]; readonly base: readonly InputRecord[] | null };
  readonly osv: { readonly state: OsvState; readonly lockfiles: readonly string[]; readonly findings: number; readonly errors: readonly string[] };
  readonly projects: readonly HeadProject[];
  readonly upgrades: readonly UpgradeAssessment[];
  readonly upgradeCounts: { readonly allowed: number; readonly blocked: number; readonly undetermined: number };
  readonly diff: DependencyDiff | null;
  readonly diffCounts: DiffCounts | null;
  readonly missing: readonly MissingItem[];
  readonly notes: readonly string[];
  readonly exitCode: 0 | 3;
}

// The adapter keeps fixed versions but not each range's events, so an advisory without a newer fix is never reported as blocked.
const notes = ['resolver_settings_outside_repository_not_read', 'analysis_completion_is_not_a_security_pass', 'allowed_is_not_a_resolution_or_install_proof',
  'osv_fix_event_completeness_not_observed', 'markers_not_evaluated'] as const;

async function scanLockfiles(plan: Plan, config: Config, workspace: string, signal: AbortSignal): Promise<EngineRun> {
  const osv = createAdapters().find(adapter => adapter.capabilities().engine === 'osv')!;
  const scoped: Plan = { ...plan, files: plan.files.filter(file => plan.lockfiles.includes(file.path)) };
  const cleanup = sourceCleanupFor(workspace);
  let run: EngineRun | undefined, failed = false;
  try {
    const snapshot = await withSourceCleanup(cleanup, () => materialize(scoped, config, workspace, signal));
    run = await osv.run({ plan: scoped, config, workspace, snapshot, signal, secretsCleared: false });
    if (run.errors.some(code => code.endsWith('termination_unverified'))) throw new SafeError('termination_unverified');
    if (!await verifySnapshot(scoped, snapshot)) throw new SafeError('snapshot_changed');
    return run;
  } catch (error) { failed = true; throw error; }
  finally {
    if ((await cleanup.cleanup(workspace)).status === 'failed') {
      if (run) { run.execution = 'failed'; run.errors.push('source_cleanup_failed'); }
      if (!failed) throw new SafeError('source_cleanup_failed');
    }
  }
}

function osvState(run: EngineRun | null, plan: Plan): OsvState {
  if (!plan.lockfiles.length) return 'not_applicable';
  if (!run) return 'not_started';
  if (run.execution !== 'completed') return 'failed';
  return run.coverage === 'analyzed' && !run.errors.length ? 'completed' : 'partial';
}

function counts(diff: DependencyDiff): DiffCounts {
  const changes = diff.projects.flatMap(project => project.changes);
  const explained = changes.flatMap(change => change.kind === 'version_changed' || change.kind === 'added' ? [change.explanation.state] : []);
  const count = (kind: string) => changes.filter(change => change.kind === kind).length;
  return {
    versionChanged: count('version_changed'), added: count('added'), removed: count('removed'), relocated: count('relocated'), metadataOnly: count('metadata_only'),
    explained: explained.filter(state => state === 'explained').length, unexplained: explained.filter(state => state === 'unexplained').length,
    undeterminedExplanations: explained.filter(state => state === 'undetermined').length,
  };
}

const records = (files: ReadonlyMap<string, Buffer>): InputRecord[] =>
  [...files].map(([file, content]) => ({ path: file, bytes: content.length, sha256: hash(content) })).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);

export async function analyzeDependencies(root: string, config: Config, workspace: string, signal: AbortSignal, comparison?: CommitPair): Promise<DependencyReport> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const plan = await buildPlan(root, config, workspace, signal, comparison);
  const missing: MissingItem[] = plan.blockers.map(code => ({ kind: 'plan_blocker', code }));
  const empty = new Map<string, Buffer>();
  const ready = !plan.blockers.length && plan.commit !== null;
  const head = ready ? await readCommitFiles(root, config, workspace, plan.commit!, dependencyInputPath, signal) : { files: empty, exclusions: [] };
  const base = ready && comparison ? await readCommitFiles(root, config, workspace, comparison.base, dependencyInputPath, signal) : null;
  for (const [side, files] of [['head', head], ['base', base]] as const) {
    for (const item of files?.exclusions ?? []) missing.push({ kind: 'input_excluded', side, path: item.path, reason: item.reason });
  }
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(config.timeoutMs)]);
  const run = ready && plan.lockfiles.length ? await scanLockfiles(plan, config, workspace, deadline) : null;
  const state = osvState(run, plan);
  if (state === 'failed' || state === 'partial') for (const reason of run!.errors.length ? run!.errors : ['osv_incomplete']) missing.push({ kind: 'osv', state, reason });
  if (state === 'not_started') missing.push({ kind: 'osv', state, reason: 'plan_blocked' });
  const findings: UpgradeFinding[] = state === 'failed' ? [] : (run?.findings ?? []).flatMap(finding => finding.engine === 'osv' && finding.package ? [{
    lockfile: finding.file, name: finding.package.name, version: finding.package.version, advisories: finding.originIds, fixedVersions: finding.fixedVersions, fixEvents: 'incomplete' as const,
  }] : []);
  const assessed = assessUpgrades(head.files, findings);
  for (const project of assessed.projects) if (project.status !== 'complete') missing.push({ kind: 'project_undetermined', side: 'head', lockfile: project.lockfile, reason: project.reason! });
  const diff = base ? diffDependencies(base.files, head.files) : null;
  for (const project of diff?.projects ?? []) {
    if (project.status.kind === 'undetermined') missing.push({ kind: 'project_undetermined', side: project.status.side, lockfile: project.lockfile, reason: project.status.reason });
    else if (project.status.kind === 'change_limit') missing.push({ kind: 'change_limit', lockfile: project.lockfile });
    else if (project.manifest.base) missing.push({ kind: 'project_undetermined', side: 'base', lockfile: project.lockfile, reason: project.manifest.base });
  }
  const upgradeCount = (value: UpgradeAssessment['state']) => assessed.upgrades.filter(item => item.state === value).length;
  return {
    schema: 'scanmux.dependencies/v1', commits: { head: plan.commit, base: comparison?.base ?? null }, planHash: plan.planHash,
    inputs: { head: records(head.files), base: base ? records(base.files) : null },
    osv: { state, lockfiles: plan.lockfiles, findings: findings.length, errors: run?.errors ?? [] },
    projects: assessed.projects, upgrades: assessed.upgrades,
    upgradeCounts: { allowed: upgradeCount('allowed'), blocked: upgradeCount('blocked'), undetermined: upgradeCount('undetermined') },
    diff, diffCounts: diff ? counts(diff) : null, missing, notes: [...notes], exitCode: missing.length ? 3 : 0,
  };
}

export function dependencyText(report: DependencyReport): string {
  const lines = [`ScanMux dependencies: ${report.exitCode === 0 ? 'analysis completed' : 'analysis incomplete'} (exit ${report.exitCode}); not a security PASS.`,
    `Commits: head=${report.commits.head ?? 'unknown'} base=${report.commits.base ?? 'none'}`,
    `OSV: ${report.osv.state}; lockfiles=${report.osv.lockfiles.length}; findings=${report.osv.findings}`,
    `Upgrades: allowed=${report.upgradeCounts.allowed} blocked=${report.upgradeCounts.blocked} undetermined=${report.upgradeCounts.undetermined}`];
  for (const item of report.upgrades) lines.push(`  ${item.lockfile}  ${item.name}@${item.version}  ${item.state}  ${item.target ?? item.reason ?? ''}  ${item.advisories.join(',')}`);
  if (report.diffCounts) {
    const c = report.diffCounts;
    lines.push(`Diff: version_changed=${c.versionChanged} added=${c.added} removed=${c.removed} relocated=${c.relocated} metadata_only=${c.metadataOnly} explained=${c.explained} unexplained=${c.unexplained} undetermined=${c.undeterminedExplanations}`);
    for (const project of report.diff!.projects) for (const change of project.changes) {
      if ((change.kind === 'version_changed' || change.kind === 'added') && change.explanation.state !== 'explained') lines.push(`  ${project.lockfile}  ${change.key}  ${change.kind}  ${change.explanation.state}:${change.explanation.reason}`);
    }
  }
  for (const item of report.missing) lines.push(`Missing: ${Object.values(item).join(' ')}`);
  lines.push(`Notes: ${report.notes.join(',')}`);
  return lines.join('\n') + '\n';
}
