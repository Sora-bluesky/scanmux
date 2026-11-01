import { sourceCleanupFor, withSourceCleanup } from './source-cleanup.ts';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { createOsvAdapter, type OsvAdvisory, type OsvPackage, type OsvRun } from './adapters.ts';
import { assessUpgrades, dependencyInputPath, diffDependencies, type DependencyDiff, type HeadProject, type UpgradeAssessment, type UpgradeFinding } from './dependency-graph.ts';
import { buildPlan, lockNames, materialize, readCommitFiles, verifySnapshot, type CommitFiles } from './repository.ts';
import { prepareOfflineDatabase, type OsvEcosystem, type PreparedDatabase } from './osv-database.ts';
import { packageVersion } from './package-version.ts';
import { hash, SafeError } from './safety.ts';
import type { CommitPair, Config, Plan } from './model.ts';

export type MissingItem =
  | { readonly kind: 'plan_blocker'; readonly side: 'base' | 'head'; readonly code: string }
  | { readonly kind: 'input_excluded'; readonly side: 'base' | 'head'; readonly path: string; readonly reason: string }
  | { readonly kind: 'osv'; readonly side: 'base' | 'head'; readonly state: OsvState; readonly reason: string }
  | { readonly kind: 'project_undetermined'; readonly side: 'base' | 'head'; readonly lockfile: string; readonly reason: string }
  | { readonly kind: 'change_limit'; readonly lockfile: string };
export type OsvState = 'completed' | 'partial' | 'failed' | 'not_applicable' | 'not_started';
export interface InputRecord { readonly path: string; readonly bytes: number; readonly sha256: string }
export interface DependencyAdvisory extends OsvAdvisory {
  readonly lockfile: string; readonly ecosystem: string; readonly package: string;
  readonly baseVersion: string | null; readonly headVersion: string | null;
  readonly dev: boolean | null; readonly status: 'added' | 'removed' | 'unchanged' | 'present';
}
interface OsvSide { readonly state: OsvState; readonly lockfiles: readonly string[]; readonly findings: number; readonly errors: readonly string[] }
export interface DiffCounts {
  readonly versionChanged: number; readonly added: number; readonly removed: number; readonly relocated: number; readonly metadataOnly: number;
  readonly explained: number; readonly unexplained: number; readonly undeterminedExplanations: number;
}
export interface DependencyReport {
  readonly tool: { readonly name: 'scanmux'; readonly version: string };
  readonly schema: 'scanmux.dependencies/v2';
  readonly commits: { readonly head: string | null; readonly base: string | null };
  readonly planHash: string;
  readonly inputs: { readonly head: readonly InputRecord[]; readonly base: readonly InputRecord[] | null };
  readonly osv: OsvSide & { readonly database: PreparedDatabase['observations']; readonly sides: { readonly head: OsvSide; readonly base: OsvSide | null } };
  readonly advisories: readonly DependencyAdvisory[];
  readonly advisoryCounts: { readonly added: number; readonly removed: number; readonly unchanged: number; readonly present: number };
  readonly projects: readonly HeadProject[];
  readonly upgrades: readonly UpgradeAssessment[];
  readonly upgradeCounts: { readonly allowed: number; readonly blocked: number; readonly undetermined: number };
  readonly diff: DependencyDiff | null;
  readonly diffCounts: DiffCounts | null;
  readonly missing: readonly MissingItem[];
  readonly notes: readonly string[];
  readonly exitCode: 0 | 10 | 2;
}

// The adapter keeps fixed versions but not each range's events, so an advisory without a newer fix is never reported as blocked.
const notes = ['resolver_settings_outside_repository_not_read', 'analysis_completion_is_not_a_security_pass', 'allowed_is_not_a_resolution_or_install_proof',
  'osv_fix_event_completeness_not_observed', 'markers_not_evaluated'] as const;

async function scanLockfiles(plan: Plan, config: Config, workspace: string, signal: AbortSignal, database?: PreparedDatabase): Promise<OsvRun> {
  const osv = createOsvAdapter(database);
  const scoped: Plan = { ...plan, files: plan.files.filter(file => plan.lockfiles.includes(file.path)) };
  const cleanup = sourceCleanupFor(workspace);
  let run: OsvRun | undefined, failed = false;
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

function osvState(run: OsvRun | null, plan: Plan): OsvState {
  if (plan.blockers.length) return 'not_started';
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

function compareAdvisories(base: readonly OsvPackage[] | null, head: readonly OsvPackage[]): DependencyAdvisory[] {
  const packageKey = (pkg: OsvPackage) => JSON.stringify([pkg.lockfile, pkg.ecosystem, pkg.name]);
  const index = (packages: readonly OsvPackage[]) => {
    const result = new Map<string, { pkg: OsvPackage; advisory: OsvAdvisory }>();
    const byPackage = new Map<string, OsvPackage[]>();
    for (const pkg of packages) {
      const identity = packageKey(pkg), instances = byPackage.get(identity) ?? [];
      instances.push(pkg); byPackage.set(identity, instances);
      for (const advisory of pkg.advisories) {
        const key = JSON.stringify([pkg.lockfile, pkg.ecosystem, pkg.name, advisory.id]), previous = result.get(key);
        result.set(key, { pkg, advisory: previous ? { ...advisory,
          aliases: [...new Set([...previous.advisory.aliases, ...advisory.aliases])].sort(),
          fixedVersions: [...new Set([...previous.advisory.fixedVersions, ...advisory.fixedVersions])].sort(),
        } : advisory });
      }
    }
    return { advisories: result, packages: byPackage };
  };
  const before = index(base ?? []), after = index(head);
  return [...new Set([...before.advisories.keys(), ...after.advisories.keys()])].sort().map(key => {
    const left = before.advisories.get(key), right = after.advisories.get(key), { pkg, advisory } = (right ?? left)!;
    const basePackages = before.packages.get(packageKey(pkg)) ?? [], headPackages = after.packages.get(packageKey(pkg)) ?? [];
    const versions = (packages: readonly OsvPackage[]) => [...new Set(packages.flatMap(item => item.version === null ? [] : [item.version]))].sort().join(', ') || null;
    const current = headPackages.length ? headPackages : basePackages;
    return { lockfile: pkg.lockfile, ecosystem: pkg.ecosystem, package: pkg.name, baseVersion: versions(basePackages), headVersion: versions(headPackages),
      ...advisory, dev: pkg.ecosystem === 'npm' ? current.every(item => item.dev === true) : null,
      status: base === null ? 'present' : left && right ? 'unchanged' : right ? 'added' : 'removed' };
  });
}

export async function analyzeDependencies(root: string, config: Config, workspace: string, signal: AbortSignal, comparison?: CommitPair): Promise<DependencyReport> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const plan = await buildPlan(root, config, workspace, signal, comparison);
  const basePlan = comparison ? await buildPlan(root, config, workspace, signal, { base: comparison.base, head: comparison.base }) : null;
  const missing: MissingItem[] = [];
  const isLockfile = (file: string) => lockNames.includes(path.posix.basename(file));
  const load = async (plan: Plan, side: 'base' | 'head'): Promise<CommitFiles> => {
    for (const code of plan.blockers) missing.push({ kind: 'plan_blocker', side, code });
    if (plan.blockers.length || !plan.commit) return { files: new Map(), exclusions: [] };
    try {
      const files = await readCommitFiles(root, config, workspace, plan.commit, file => dependencyInputPath(file) || isLockfile(file), signal);
      for (const item of [...files.exclusions, ...plan.exclusions.filter(item => isLockfile(item.path))]) {
        if (!missing.some(existing => existing.kind === 'input_excluded' && existing.side === side && existing.path === item.path)) {
          missing.push({ kind: 'input_excluded', side, path: item.path, reason: item.reason });
        }
      }
      return files;
    } catch (error) {
      missing.push({ kind: 'plan_blocker', side, code: error instanceof SafeError ? error.code : 'dependency_inputs_unavailable' });
      return { files: new Map(), exclusions: [] };
    }
  };
  const head = await load(plan, 'head'), base = basePlan ? await load(basePlan, 'base') : null;
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(config.timeoutMs)]);
  const lockfiles = [...new Set([...plan.lockfiles, ...basePlan?.lockfiles ?? []])].sort();
  let database: PreparedDatabase | undefined, databaseError: string | undefined;
  if (lockfiles.length) try {
    if (!config.osvDatabase) throw new SafeError('offline_database_not_configured');
    const ecosystems: OsvEcosystem[] = [...new Set(lockfiles.map(file => /(?:package-lock.json|pnpm-lock.yaml|yarn.lock)$/.test(file) ? 'npm' : /go\.(mod|sum)$/.test(file) ? 'Go' : /Cargo.lock$/.test(file) ? 'crates.io' : 'PyPI'))];
    database = await prepareOfflineDatabase({ source: config.osvDatabase, workspace, target: root, ecosystems,
      maxMetadataBytes: config.maxOutputBytes, timeoutMs: config.timeoutMs, signal: deadline });
  } catch (error) { databaseError = error instanceof SafeError ? error.code : 'offline_database_unavailable'; }
  const check = async (plan: Plan, side: 'base' | 'head'): Promise<{ summary: OsvSide; run: OsvRun | null }> => {
    const inputError = missing.some(item => item.kind === 'input_excluded' && item.side === side && isLockfile(item.path)) ? 'lockfile_unavailable' : undefined;
    let run: OsvRun | null = null, error = inputError ?? databaseError;
    const blocked = plan.blockers.length || missing.some(item => item.kind === 'plan_blocker' && item.side === side);
    if (!blocked && plan.lockfiles.length && !error) try {
      const directory = path.join(workspace, side); await mkdir(directory, { mode: 0o700 });
      run = await scanLockfiles(plan, config, directory, deadline, database);
    } catch (failure) { error = failure instanceof SafeError ? failure.code : 'osv_unavailable'; }
    const state = blocked ? 'not_started' : error && (plan.lockfiles.length || inputError) ? 'failed' : osvState(run, plan);
    const errors = state === 'not_started' ? ['plan_blocked'] : state === 'failed' || state === 'partial' ? error ? [error] : run?.errors.length ? run.errors : ['osv_incomplete'] : [];
    for (const reason of errors) missing.push({ kind: 'osv', side, state, reason });
    return { summary: { state, lockfiles: plan.lockfiles, findings: run?.findings.length ?? 0, errors }, run };
  };
  const headCheck = await check(plan, 'head'), baseCheck = basePlan ? await check(basePlan, 'base') : null;
  const checked = (side: OsvSide) => side.state === 'completed' || side.state === 'not_applicable';
  const complete = checked(headCheck.summary) && (!baseCheck || checked(baseCheck.summary));
  const state: OsvState = complete ? lockfiles.length ? 'completed' : 'not_applicable'
    : [headCheck.summary, baseCheck?.summary].some(side => side?.state === 'failed') ? 'failed'
      : [headCheck.summary, baseCheck?.summary].some(side => side?.state === 'partial') ? 'partial' : 'not_started';
  const advisories = complete ? compareAdvisories(baseCheck ? baseCheck.run?.packages ?? [] : null, headCheck.run?.packages ?? []) : [];
  const advisoryCount = (status: DependencyAdvisory['status']) => advisories.filter(item => item.status === status).length;
  const advisoryCounts = { added: advisoryCount('added'), removed: advisoryCount('removed'), unchanged: advisoryCount('unchanged'), present: advisoryCount('present') };
  const findings: UpgradeFinding[] = headCheck.summary.state === 'failed' ? [] : (headCheck.run?.findings ?? []).flatMap(finding => finding.engine === 'osv' && finding.package ? [{
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
  const failed = !complete || missing.some(item => item.kind === 'plan_blocker' || item.kind === 'input_excluded' && isLockfile(item.path));
  return {
    tool: { name: 'scanmux', version: packageVersion }, schema: 'scanmux.dependencies/v2', commits: { head: plan.commit, base: comparison?.base ?? null }, planHash: plan.planHash,
    inputs: { head: records(head.files), base: base ? records(base.files) : null },
    osv: { state, lockfiles, findings: findings.length, errors: [...new Set([...headCheck.summary.errors, ...baseCheck?.summary.errors ?? []])],
      database: database?.observations ?? [], sides: { head: headCheck.summary, base: baseCheck?.summary ?? null } },
    advisories, advisoryCounts,
    projects: assessed.projects, upgrades: assessed.upgrades,
    upgradeCounts: { allowed: upgradeCount('allowed'), blocked: upgradeCount('blocked'), undetermined: upgradeCount('undetermined') },
    diff, diffCounts: diff ? counts(diff) : null, missing, notes: [...notes], exitCode: failed ? 2 : (comparison ? advisoryCounts.added : advisoryCounts.present) > 0 ? 10 : 0,
  };
}

export function dependencyText(report: DependencyReport): string {
  const lines = [`ScanMux dependencies: ${report.exitCode === 2 ? 'analysis incomplete' : 'analysis completed'} (exit ${report.exitCode}); not a security PASS.`,
    `Commits: head=${report.commits.head ?? 'unknown'} base=${report.commits.base ?? 'none'}`,
    `OSV: ${report.osv.state}; lockfiles=${report.osv.lockfiles.length}; findings=${report.osv.findings}`,
    `Advisories: added=${report.advisoryCounts.added} removed=${report.advisoryCounts.removed} unchanged=${report.advisoryCounts.unchanged} present=${report.advisoryCounts.present}`];
  const order = { added: 0, present: 1, unchanged: 2, removed: 3 };
  for (const item of [...report.advisories].sort((left, right) => order[left.status] - order[right.status])) {
    lines.push(`  ${item.status}  ${item.lockfile}  ${item.ecosystem}  ${item.package}  ${item.baseVersion ?? '-'} -> ${item.headVersion ?? '-'}  ${item.id}  ${item.severity ?? 'unknown'}  dev=${item.dev ?? 'unknown'}  fixes=${item.fixedVersions.join(',') || 'none'}`);
  }
  lines.push(`Upgrades: allowed=${report.upgradeCounts.allowed} blocked=${report.upgradeCounts.blocked} undetermined=${report.upgradeCounts.undetermined}`);
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
