import { emptyRun } from './engine-run.ts';
export { emptyRun } from './engine-run.ts';
import { RuntimeAdvisoryAdapter } from './runtime-advisories.ts';
import { TrivyAdapter } from './trivy-adapter.ts';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { array, digest, hash, identifier, record, SafeError, safeRelative } from './safety.ts';
import { execute, verifyVersion } from './process.ts';
import { prepareOfflineDatabase, verifyPreparedDatabase } from './osv-database.ts';
import { JobDiskCopyLimitError } from './copy-budget.ts';
import { matchingNpmPackages, npmLockfilePackages, type NpmPackage } from './npm-lockfile.ts';
import type { OsvEcosystem, PreparedDatabase } from './osv-database.ts';
import type { Adapter, AdapterContext, Capability, CodexFinding, ProcessEngine, EngineRun, Finding, LegacyFinding, Plan, Severity } from './model.ts';

const versions: Record<ProcessEngine, string> = { gitleaks: '8.30.1', osv: '2.7.0', 'codex-security': '0.5.1' };
export const gitleaksConfig = '[extend]\nuseDefault = true\n';

// Gitleaks 8.30.1 global path allowlist, recorded as coverage exclusions rather than silently accepted.
const defaultExcludedPaths = [
  /gitleaks\.toml/, /\.(?:bmp|gif|jpe?g|png|svg|tiff?|eot|[ot]tf|woff2?|docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$/i,
  /go\.(?:mod|sum|work(?:\.sum)?)$/, /(?:^|\/)vendor\/modules\.txt$/,
  /(?:^|\/)vendor\/(?:github\.com|golang\.org\/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:\/.*)?$/,
  /(?:^|\/)gradlew(?:\.bat)?$/, /(?:^|\/)gradle\.lockfile$/, /(?:^|\/)mvnw(?:\.cmd)?$/,
  /(?:^|\/)\.mvn\/wrapper\/MavenWrapperDownloader\.java$/, /(?:^|\/)node_modules(?:\/.*)?$/,
  /(?:^|\/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/,
  /(?:^|\/)bower_components(?:\/.*)?$/, /(?:^|\/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$/,
  /(?:^|\/)javascript\.json$/, /(?:^|\/)(?:Pipfile|poetry)\.lock$/,
  /(?:^|\/)(?:v?env|virtualenv)\/lib(?:64)?(?:\/.*)?$/i,
  /(?:^|\/)(?:lib(?:64)?\/python[23](?:\.\d{1,2})+|python\/[23](?:\.\d{1,2})+\/lib(?:64)?)(?:\/.*)?$/i,
  /(?:^|\/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:\/.+)?$/i, /(?:^|\/)vendor\/(?:bundle|ruby)(?:\/.*?)?$/,
  /\.gem$/, /verification-metadata\.xml/, /Database.refactorlog/, /(?:^|\/)\.git$/,
  /\.(?:zip|tar|gz|7z|rar)$/i,
];
export function secretExclusions(plan: Plan): string[] {
  return plan.files.filter(file => defaultExcludedPaths.some(pattern => pattern.test(file.path))).map(file => file.path);
}
type CodexContext = Pick<AdapterContext, 'plan'> & Partial<Pick<AdapterContext, 'snapshot'>>;
function location(raw: unknown, context: CodexContext): string {
  if (typeof raw !== 'string') throw new SafeError('invalid_location');
  let relative = raw.replaceAll('\\', '/');
  if (path.isAbsolute(raw)) {
    if (!context.snapshot || !path.isAbsolute(context.snapshot)) throw new SafeError('location_outside_snapshot');
    relative = path.relative(context.snapshot, raw).split(path.sep).join('/');
  }
  const name = safeRelative(relative);
  if (!context.plan.files.some(f => f.path === name)) throw new SafeError('location_outside_snapshot');
  return name;
}
function severity(input: unknown): Severity {
  if (typeof input !== 'string') return 'unknown';
  const normalized = input.toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'informational'].includes(normalized) ? normalized as Severity : 'unknown';
}
function makeFinding<T extends Omit<LegacyFinding | CodexFinding, 'fingerprint' | 'disposition' | 'reachability' | 'knownExploited'>>(fields: T) {
  return { ...fields, fingerprint: digest([fields.engine, fields.originIds, fields.file, fields.line, fields.package]), disposition: 'open' as const, reachability: 'unknown' as const, knownExploited: 'unknown' as const };
}
export function normalizeGitleaks(raw: unknown, context: AdapterContext): LegacyFinding[] {
  return array(raw).map(item => {
    const row = record(item);
    if (!Number.isSafeInteger(row.StartLine) || Number(row.StartLine) < 1) throw new SafeError('invalid_line');
    // Match, Secret, commit author and arbitrary descriptions never cross this boundary.
    return makeFinding({
      engine: 'gitleaks', originIds: [identifier(row.RuleID)], category: 'secret', severity: 'high', confidence: 'unknown',
      evidenceState: 'source_supported', file: location(row.File, context), line: Number(row.StartLine),
      title: 'Potential credential detected; validity and revocation are unverified', fixedVersions: [],
    });
  });
}
export interface OsvAdvisory {
  readonly id: string; readonly aliases: string[]; readonly severity: string | null; readonly fixedVersions: string[];
}
export interface OsvPackage {
  readonly lockfile: string; readonly ecosystem: string; readonly name: string; readonly version: string | null;
  readonly dev: boolean | null; readonly matchingIncomplete: boolean; readonly advisories: OsvAdvisory[];
}
export interface OsvRun extends EngineRun { packages?: OsvPackage[] }

function osvPackages(raw: unknown, context: AdapterContext, locks: ReadonlyMap<string, ReadonlyMap<string, readonly NpmPackage[]>> = new Map()): OsvPackage[] {
  const packages: OsvPackage[] = [];
  for (const item of array(record(raw).results)) {
    const group = record(item);
    const file = location(record(group.source).path, context);
    if (!context.plan.lockfiles.includes(file)) throw new SafeError('unexpected_dependency_source');
    for (const packageItem of array(group.packages)) {
      const entry = record(packageItem);
      const pkg = record(entry.package);
      const name = identifier(pkg.name), ecosystem = identifier(pkg.ecosystem);
      const version = typeof pkg.version === 'string' && pkg.version ? identifier(pkg.version) : null;
      const entries = ecosystem === 'npm' ? matchingNpmPackages(locks.get(file)?.get(name) ?? [], name, version) : [];
      const localSource = typeof pkg.purl === 'string' && /[?&]source=LOCAL(?:&|$)/.test(pkg.purl);
      if (entries.some(entry => entry.local) && (localSource || entries.every(entry => entry.local))) continue;
      const registryEntries = entries.filter(entry => !entry.local);
      const advisories: OsvAdvisory[] = [];
      for (const vulnerability of array(entry.vulnerabilities ?? [])) {
        const advisory = record(vulnerability);
        const id = identifier(advisory.id), aliases = [...new Set(array(advisory.aliases ?? []).map(identifier))].sort();
        const level = record(advisory.database_specific ?? {}).severity;
        const fixed = new Set<string>();
        for (const affectedItem of array(advisory.affected ?? [])) {
          const affected = record(affectedItem);
          const affectedPackage = record(affected.package);
          if (affectedPackage.name !== pkg.name || affectedPackage.ecosystem !== pkg.ecosystem) continue;
          for (const range of array(affected.ranges ?? [])) for (const event of array(record(range).events)) {
            const value = record(event).fixed;
            if (value !== undefined) fixed.add(identifier(value));
          }
        }
        advisories.push({ id, aliases, severity: typeof level === 'string' && /^[A-Za-z_-]{1,200}$/.test(level) ? level : null, fixedVersions: [...fixed].sort() });
      }
      packages.push({ lockfile: file, name, ecosystem, version, dev: ecosystem === 'npm' ? registryEntries.length > 0 && registryEntries.every(entry => entry.dev) : null,
        matchingIncomplete: version === null || (typeof pkg.purl === 'string' && pkg.purl.includes('source=LOCAL')), advisories });
    }
  }
  return packages;
}
function osvFindings(packages: readonly OsvPackage[]): LegacyFinding[] {
  const findings = packages.flatMap(pkg => pkg.version === null ? [] : pkg.advisories.map(advisory => makeFinding({
    engine: 'osv', originIds: [...new Set([advisory.id, ...advisory.aliases])].sort(), category: 'dependency', severity: severity(advisory.severity),
    confidence: 'unknown', evidenceState: 'candidate', file: pkg.lockfile, line: null, title: 'Advisory matches a declared dependency; applicability requires review',
    package: { name: pkg.name, version: pkg.version!, ecosystem: pkg.ecosystem, direct: 'unknown' }, fixedVersions: advisory.fixedVersions,
  })));
  return [...new Map(findings.map(f => [f.fingerprint, f])).values()];
}
export function normalizeOsv(raw: unknown, context: AdapterContext): LegacyFinding[] { return osvFindings(osvPackages(raw, context)); }
export function normalizeCodex(raw: unknown, context: CodexContext): CodexFinding[] {
  const result = record(raw);
  const manifest = record(record(result.manifest).scan);
  const target = record(manifest.target);
  if (target.revision !== context.plan.commit) throw new SafeError('codex_revision_mismatch');
  return codexFindings(result.findings, manifest.id, context);
}
/** Mapping comes from this invocation's completed projection, never a saved report. */
export function normalizeProjectedCodex(raw: unknown, mappingInput: unknown, context: CodexContext): CodexFinding[] {
  const mapping = record(mappingInput), result = record(raw), manifest = record(record(result.manifest).scan), target = record(manifest.target);
  if (mapping.schema !== 'scanmux.sdk-projection/v1' || mapping.originalCommit !== context.plan.commit || mapping.originalTree !== context.plan.treeHash
    || mapping.planHash !== context.plan.planHash || mapping.snapshotHash !== context.plan.snapshotHash || mapping.projectionScope !== 'accepted_files_only'
    || mapping.projectedMode !== '100644' || typeof mapping.derivedRevision !== 'string' || !/^[a-f0-9]{40}$/.test(mapping.derivedRevision)
    || digest(mapping.manifest) !== digest(context.plan.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })))
    || target.revision !== mapping.derivedRevision) throw new SafeError('codex_projection_mismatch');
  return codexFindings(result.findings, manifest.id, context);
}
function codexFindings(input: unknown, scanId: unknown, context: CodexContext): CodexFinding[] {
  const document = record(input);
  if (document.documentType !== 'codex-security.findings' || document.schemaVersion !== '1.0' || document.scanId !== scanId) throw new SafeError('invalid_codex_report');
  return array(document.findings).flatMap(item => {
    const row = record(item);
    return array(row.locations).map(loc => {
      const position = record(loc);
      const line = position.startLine, endLine = position.endLine ?? null;
      if (!Number.isSafeInteger(line) || Number(line) < 1
        || (endLine !== null && (!Number.isSafeInteger(endLine) || Number(endLine) < Number(line)))) throw new SafeError('invalid_line');
      const file = location(position.path, context);
      const confidence = record(row.confidence).level;
      if (!['high', 'medium', 'low'].includes(String(confidence))) throw new SafeError('invalid_confidence');
      return makeFinding({ engine: 'codex-security', originIds: [identifier(row.findingId), identifier(row.ruleId)],
        category: 'code', severity: severity(record(row.severity).level), confidence: confidence as 'high' | 'medium' | 'low',
        evidenceState: 'candidate', file, line: Number(line), ...(endLine === null ? {} : { endLine: Number(endLine) }),
        title: 'AI candidate; human confirmation required', fixedVersions: [],
      });
    });
  });
}
class ScannerAdapter implements Adapter {
  private controller = new AbortController();
  readonly engine: ProcessEngine;
  private database?: PreparedDatabase;
  private retainPackages: boolean;
  constructor(engine: ProcessEngine, database?: PreparedDatabase, retainPackages = false) {
    this.engine = engine; this.database = database; this.retainPackages = retainPackages;
  }
  capabilities(): Capability {
    return { engine: this.engine, category: this.engine === 'gitleaks' ? 'secrets' : this.engine === 'osv' ? 'dependencies' : 'code',
      inputs: this.engine === 'osv' ? ['JS/TS lockfiles', 'Python lockfiles', 'Go modules', 'Rust Cargo.lock'] : ['tracked text snapshot'],
      operatingSystems: this.engine === 'codex-security' ? ['linux (required; unverified)'] : ['windows', 'linux', 'darwin'],
      permissions: this.engine === 'codex-security' ? ['isolated credential relay; not implemented'] : ['snapshot read', 'private temporary write'],
      buildRequired: false, transmission: 'none; offline PoC', license: this.engine === 'gitleaks' ? 'MIT CLI; builtin rules' : 'Apache-2.0; service/database terms separate',
    };
  }
  plan(plan: Plan) { return { applicable: this.engine !== 'codex-security' && (this.engine !== 'osv' || plan.lockfiles.length > 0), targets: this.engine === 'osv' ? plan.lockfiles : plan.files.map(f => f.path), constraints: this.engine === 'codex-security' ? ['isolation_unverified'] : ['offline_static_only'] }; }
  cancel(): void { this.controller.abort(); }
  validate(): 'unsupported' { return 'unsupported'; }
  patch(): 'unsupported' { return 'unsupported'; }
  normalize(raw: unknown, context: AdapterContext): Finding[] {
    return this.engine === 'gitleaks' ? normalizeGitleaks(raw, context) : this.engine === 'osv' ? normalizeOsv(raw, context) : normalizeCodex(raw, context);
  }
  async run(context: AdapterContext): Promise<OsvRun> {
    const run: OsvRun = emptyRun(this.engine, context);
    const tool = context.config.tools[this.engine];
    const signal = AbortSignal.any([context.signal, this.controller.signal]);
    if (signal.aborted) { run.execution = 'cancelled'; run.errors.push('cancelled_before_start'); return run; }
    // No configuration flag can turn an unverified AI boundary into a verified one.
    if (this.engine === 'codex-security') { run.errors.push('isolation_unverified', 'runner_auth_unverified', 'daybreak_effective_unknown'); run.coverage = 'unsupported'; return run; }
    if (!tool) { run.errors.push('tool_not_configured'); return run; }
    if (tool.version !== versions[this.engine]) { run.errors.push('unsupported_tool_version'); run.coverage = 'unsupported'; return run; }
    if (this.engine === 'osv' && !context.plan.lockfiles.length) { run.errors.push('no_supported_lockfile'); run.coverage = 'unsupported'; return run; }
    try {
      await verifyVersion(tool, [this.engine === 'gitleaks' ? 'version' : '--version'], {
        cwd: context.workspace, home: context.workspace, timeoutMs: context.config.timeoutMs,
        maxOutputBytes: context.config.maxOutputBytes, signal, target: context.plan.root,
      });
      const locks = new Map<string, Map<string, NpmPackage[]>>();
      if (this.engine === 'osv') for (const file of context.plan.lockfiles) if (path.posix.basename(file) === 'package-lock.json') {
        const packages = new Map<string, NpmPackage[]>();
        for (const entry of npmLockfilePackages(await readFile(path.join(context.snapshot, file)))) {
          const instances = packages.get(entry.name) ?? []; instances.push(entry); packages.set(entry.name, instances);
        }
        locks.set(file, packages);
      }
      const prepared = await this.arguments(context, run, signal);
      const invocation = await execute(tool, prepared.args, { cwd: context.workspace, home: context.workspace,
        timeoutMs: context.config.timeoutMs, maxOutputBytes: context.config.maxOutputBytes,
        signal, target: context.plan.root, database: prepared.database?.directory,
      });
      run.exitCode = invocation.code;
      run.errors.push(...(invocation.diagnostics ?? []));
      if (invocation.reason !== 'exit' || ![0, 1].includes(invocation.code ?? -1)) {
        run.execution = invocation.reason === 'cancelled' ? 'cancelled' : ['timeout', 'job_disk_measured_limit'].includes(invocation.reason) ? 'budget_exceeded' : 'failed';
        run.errors.push(invocation.reason === 'exit' ? 'scanner_exit_failure' : invocation.reason);
        return run;
      }
      if (prepared.database) await verifyPreparedDatabase(prepared.database, context.plan.root, signal, context.config.timeoutMs);
      if (!invocation.stdout.length) throw new SafeError('scanner_json_missing');
      let raw: unknown;
      try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(invocation.stdout)); }
      catch { throw new SafeError('scanner_json_invalid'); }
      const packages = this.engine === 'osv' ? osvPackages(raw, context, locks) : null;
      run.findings = packages ? osvFindings(packages) : this.normalize(raw, context);
      if (this.retainPackages && packages) run.packages = packages;
      const reportedFindings = this.engine === 'osv' ? array(record(raw).results).some(r => array(record(r).packages).some(p => array(record(p).vulnerabilities ?? []).length)) : run.findings.length > 0;
      if ((invocation.code === 1) !== reportedFindings) throw new SafeError('exit_report_disagreement');
      if (this.engine === 'osv') {
        if (packages!.some(pkg => pkg.matchingIncomplete)) run.errors.push('offline_package_matching_incomplete');
        const sources = array(record(raw).results).map(r => location(record(record(r).source).path, context));
        run.exclusions = context.plan.lockfiles.filter(file => !sources.includes(file));
        if (!sources.length) run.errors.push('no_dependency_coverage_receipt');
      } else { run.exclusions = secretExclusions(context.plan); }
      run.execution = 'completed';
      run.coverage = run.exclusions.length || run.errors.length ? 'partial' : 'analyzed';
      run.evidence = [{ kind: 'scanner_observation', snapshotHash: context.plan.snapshotHash,
        reportHash: hash(invocation.stdout), classification: 'confidential', rawRetained: false }];
      if (run.exclusions.length) run.errors.push(this.engine === 'gitleaks' ? 'builtin_rules_exclude_paths' : 'dependency_sources_not_reported');
      return run;
    } catch (error) {
      run.execution = error instanceof JobDiskCopyLimitError || error instanceof SafeError && error.code === 'job_disk_measured_limit' ? 'budget_exceeded' : 'failed';
      run.errors.push(error instanceof SafeError ? error.code : 'invalid_or_unavailable_report'); return run;
    } finally { run.endedAt = new Date().toISOString(); }
  }
  private async arguments(context: AdapterContext, run: EngineRun, signal: AbortSignal): Promise<{ args: string[]; database?: PreparedDatabase }> {
    if (this.engine === 'gitleaks') {
      const config = path.join(context.workspace, 'gitleaks-config.toml');
      const ignore = path.join(context.workspace, 'gitleaks.ignore');
      await writeFile(config, gitleaksConfig, { flag: 'wx', mode: 0o600 });
      await writeFile(ignore, '', { flag: 'wx', mode: 0o600 });
      return { args: ['dir', context.snapshot, '--config', config, '--gitleaks-ignore-path', ignore,
        '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--no-color', '--log-level', 'error', '--max-decode-depth=0',
        '--report-format', 'json', '--report-path', '-'] };
    }
    if (!context.config.osvDatabase) throw new SafeError('offline_database_not_configured');
    const config = path.join(context.workspace, 'osv-config.toml');
    await writeFile(config, '', { flag: 'wx', mode: 0o600 });
    const ecosystems: OsvEcosystem[] = [...new Set(context.plan.lockfiles.map(file => /(?:package-lock.json|pnpm-lock.yaml|yarn.lock)$/.test(file) ? 'npm' : /go\.(mod|sum)$/.test(file) ? 'Go' : /Cargo.lock$/.test(file) ? 'crates.io' : 'PyPI'))];
    const database = this.database ?? await prepareOfflineDatabase({ source: context.config.osvDatabase, workspace: context.workspace, target: context.plan.root,
      ecosystems, maxMetadataBytes: context.config.maxOutputBytes, timeoutMs: context.config.timeoutMs, signal, copyBudget: context.copyBudget });
    if (this.database) await verifyPreparedDatabase(database, context.plan.root, signal, context.config.timeoutMs);
    run.database.push(...database.observations);
    return { database, args: ['scan', 'source', '--offline', '--offline-vulnerabilities', '--no-resolve', '--no-call-analysis=all', '--config', config, '--format', 'json', '--all-packages', '--all-vulns',
      ...context.plan.lockfiles.flatMap(file => ['--lockfile', ':' + path.join(context.snapshot, file)])] };
  }
}
export function createAdapters(plan?: Plan): Adapter[] { return [new ScannerAdapter('gitleaks'), new ScannerAdapter('osv'), new ScannerAdapter('codex-security'), new RuntimeAdvisoryAdapter(), ...(plan?.schema === 'scanmux.plan/v3' ? [new TrivyAdapter()] : [])]; }
export function createOsvAdapter(database?: PreparedDatabase): ScannerAdapter { return new ScannerAdapter('osv', database, true); }
