import { readFileSync } from 'node:fs';
import { registerJobDiskRoot, releaseJobDiskRoot } from './job-disk.ts';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { emptyRun } from './engine-run.ts';
import type { Adapter, AdapterContext, Capability, EngineRun, IaCKind, InputUnit, NonEmpty, Plan, TrivyCoverage, TrivyFinding, TrivyReceipt, Tool } from './model.ts';
import { execute, jobDiskDiagnostic } from './process.ts';
import type { ProcessResult } from './process.ts';
import { scopedProcessOwner, verifiedImage } from './process-tree.ts';
import { array, digest, hash, identifier, record, SafeError, safeRelative } from './safety.ts';
import { inventoryTrivy } from './trivy-plan.ts';
import { JobDiskCopyLimitError, scopedCopyBudget } from './copy-budget.ts';
import { sourceCleanupFor } from './source-cleanup.ts';

export const trivyVersion = '0.76.1';
const scannerTypes: Record<IaCKind, string> = {
  dockerfile: 'Dockerfile Security Check', kubernetes: 'Kubernetes Security Check', terraform: 'Terraform Security Check',
  cloudformation: 'CloudFormation Security Check', helm: 'Helm Security Check',
};

/** Rebuild the inventory from exactly the accepted bytes, including files with no scanner response. */
function acceptedInputs(context: AdapterContext): { units: readonly InputUnit[]; lines: Map<string, number> } {
  if (context.plan.schema !== 'scanmux.plan/v3') throw new SafeError('trivy_plan_missing');
  const files = new Map<string, Buffer>(), lines = new Map<string, number>();
  for (const entry of context.plan.files) {
    const name = safeRelative(entry.path);
    if (files.has(name)) throw new SafeError('trivy_plan_mismatch');
    const bytes = readFileSync(path.join(context.snapshot, name));
    if (bytes.length !== entry.bytes || hash(bytes) !== entry.sha256) throw new SafeError('snapshot_changed');
    files.set(name, bytes);
    lines.set(name, bytes.length ? bytes.toString('utf8').split('\n').length - (bytes.at(-1) === 10 ? 1 : 0) : 0);
  }
  const inventory = inventoryTrivy(files);
  if (digest(inventory) !== digest(context.plan.trivy)) throw new SafeError('trivy_plan_mismatch');
  return { units: inventory.inputs, lines };
}

function targetName(input: unknown, snapshot: string): string {
  if (typeof input !== 'string' || !input || /[\x00-\x1f\x7f]/.test(input)) throw new SafeError('trivy_invalid_target');
  let target = input.replaceAll('\\', '/');
  if (/^[A-Za-z]:\//.test(target) || target.startsWith('/')) {
    // Relative reduction is permitted only for this invocation's own snapshot.
    const base = snapshot.replaceAll('\\', '/').replace(/\/$/, '');
    if (!target.startsWith(base + '/')) throw new SafeError('location_outside_snapshot');
    target = target.slice(base.length + 1);
  }
  return target === '.' ? target : safeRelative(target);
}
function integer(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new SafeError('trivy_invalid_summary');
  return Number(value);
}
function opaque(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > 8192 || /[\x00-\x1f\x7f]/.test(value)) throw new SafeError('trivy_invalid_resource');
  return value;
}
function lineRange(cause: Record<string, unknown>, file: string | null, lines: Map<string, number>): { line: number | null; endLine: number | null } {
  const line = cause.StartLine === undefined || cause.StartLine === null ? null : cause.StartLine;
  const endLine = cause.EndLine === undefined || cause.EndLine === null ? null : cause.EndLine;
  if ((line !== null && (!Number.isSafeInteger(line) || Number(line) < 1))
    || (endLine !== null && (!Number.isSafeInteger(endLine) || Number(endLine) < 1))
    || (line === null && endLine !== null) || (line !== null && endLine !== null && Number(endLine) < Number(line))) throw new SafeError('invalid_line');
  if (file && ((line !== null && Number(line) > (lines.get(file) ?? 0)) || (endLine !== null && Number(endLine) > (lines.get(file) ?? 0)))) throw new SafeError('invalid_line');
  // An aggregate result cannot prove which source file owns its reported line.
  return file ? { line: line as number | null, endLine: endLine as number | null } : { line: null, endLine: null };
}
function diagnosticReasons(stderr?: Buffer): string[] {
  if (!stderr?.length) return [];
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(stderr); } catch { throw new SafeError('trivy_diagnostics_invalid'); }
  const unsafe = text.split(/\r?\n/).some(line => /\b(?:WARN|ERROR|FATAL)\b/.test(line)
    && !/\[misconfig\]\s+Falling back to embedded checks\b/.test(line));
  return unsafe ? ['trivy_scanner_diagnostics'] : [];
}

export function normalizeTrivy(raw: unknown, context: AdapterContext, diagnostics?: Buffer): { findings: TrivyFinding[]; coverage: TrivyCoverage } {
  const { units, lines } = acceptedInputs(context), document = record(raw);
  if (document.SchemaVersion !== 2 || record(document.Trivy).Version !== trivyVersion || document.ArtifactType !== 'filesystem') throw new SafeError('trivy_report_schema_mismatch');
  const results = document.Results === undefined ? [] : array(document.Results);
  const reasons = new Set(diagnosticReasons(diagnostics)), seen = new Map<string, string>(), findings: TrivyFinding[] = [];
  const observed = new Map<string, Map<string, boolean>>(), excluded = new Set<string>(), parseFailures = new Set<string>();
  if (document.Errors !== undefined && array(document.Errors).length) reasons.add('trivy_reported_parse_error');
  for (const value of results) {
    const result = record(value);
    const kind = typeof result.Type === 'string' && Object.hasOwn(scannerTypes, result.Type) ? result.Type as IaCKind : null;
    if (result.Class !== 'config' || !kind) throw new SafeError('trivy_unsupported_result_type');
    const target = targetName(result.Target, context.snapshot);
    const matching = units.filter(unit => unit.kind === kind && (unit.files.includes(target)
      || ((kind === 'terraform' || kind === 'helm') && unit.key === `${kind}:${target}`)));
    // A result for an unplanned target cannot be attributed to a planned unit. It makes the run partial;
    // its rows are not reported, because their file and lines were never accepted from the snapshot.
    // More than one match means the plan itself is inconsistent, which stays an error.
    if (matching.length > 1) throw new SafeError('trivy_target_ambiguous');
    if (!matching.length) { reasons.add('trivy_target_not_planned'); continue; }
    const unit = matching[0], file = lines.has(target) ? target : null;
    const summary = record(result.MisconfSummary), counts = { PASS: 0, FAIL: 0, EXCEPTION: 0 };
    const rows = array(result.Misconfigurations ?? []);
    if (!rows.length) reasons.add('trivy_empty_result_receipt');
    const parseFailed = result.Errors !== undefined && array(result.Errors).length > 0;
    if (parseFailed) { reasons.add('trivy_reported_parse_error'); parseFailures.add(unit.key); }
    for (const item of rows) {
      const row = record(item), status = row.Status;
      if (status !== 'PASS' && status !== 'FAIL' && status !== 'EXCEPTION') throw new SafeError('trivy_invalid_status');
      counts[status]++;
      if (row.Type !== scannerTypes[kind]) throw new SafeError('trivy_unsupported_check_type');
      const id = identifier(row.ID), namespace = identifier(row.Namespace), cause = record(row.CauseMetadata ?? {});
      // Helm locations refer to rendered YAML, whose lines do not map to template lines.
      // Validate their shape and preserve them only in the hashed observation identity.
      const position = lineRange(cause, kind === 'helm' ? null : file, lines);
      const identityPosition = kind === 'helm' ? [cause.StartLine ?? null, cause.EndLine ?? null] : position;
      const identity = [kind, namespace, id, target, identityPosition, opaque(cause.Resource), opaque(cause.Provider), opaque(cause.Service)];
      const fingerprint = digest(['trivy', identity]), content = digest(row);
      if (seen.has(fingerprint)) {
        if (seen.get(fingerprint) !== content) throw new SafeError('trivy_conflicting_observation');
        continue;
      }
      seen.set(fingerprint, content);
      if (status === 'EXCEPTION') { excluded.add(unit.key); reasons.add('trivy_checks_excluded'); }
      if (status !== 'FAIL') continue;
      const severity = typeof row.Severity === 'string' ? row.Severity.toLowerCase() : 'unknown';
      findings.push({ fingerprint, engine: 'trivy', originIds: [id], category: 'misconfiguration',
        severity: severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low' ? severity : 'unknown',
        confidence: 'unknown', evidenceState: 'candidate', file, ...position,
        title: 'Configuration check candidate; applicability requires review', fixedVersions: [],
        disposition: 'open', reachability: 'unknown', knownExploited: 'unknown' });
    }
    if (integer(summary.Successes ?? 0) !== counts.PASS || integer(summary.Failures ?? 0) !== counts.FAIL || integer(summary.Exceptions ?? 0) !== counts.EXCEPTION) throw new SafeError('trivy_summary_mismatch');
    const targets = observed.get(unit.key) ?? new Map<string, boolean>();
    targets.set(target, (targets.get(target) ?? true) && rows.length > 0 && !parseFailed);
    observed.set(unit.key, targets);
  }
  if (!units.length) return { findings, coverage: { state: 'unsupported', reason: 'no_recognized_config' } };
  const receipts: TrivyReceipt[] = units.map(unit => {
    const targets = observed.get(unit.key);
    if (parseFailures.has(unit.key)) return { unit: unit.key, state: 'parse_failed' };
    if (unit.kind === 'unresolved' || unit.unresolved) { reasons.add('trivy_input_unresolved'); return { unit: unit.key, state: 'unresolved' }; }
    if (targets && [...targets.values()].some(complete => !complete)) return { unit: unit.key, state: 'unresolved' };
    if (excluded.has(unit.key)) return { unit: unit.key, state: 'excluded' };
    // Aggregate checks are additional evidence, not an acknowledgement of every candidate file.
    // Trivy can silently omit malformed siblings while still producing a directory result.
    if (!targets || !unit.files.every(file => targets.get(file) === true)) {
      reasons.add('trivy_input_result_missing'); return { unit: unit.key, state: 'unresolved' };
    }
    return { unit: unit.key, state: 'analyzed' };
  });
  if (reasons.size) return { findings, coverage: { state: 'partial', receipts, reasons: [...reasons].sort() as unknown as NonEmpty<string> } };
  return { findings, coverage: { state: 'analyzed', receipts: receipts as unknown as NonEmpty<TrivyReceipt & { state: 'analyzed' }> } };
}

/** All credential, proxy and TRIVY_* settings are absent; process.ts supplies only its clean base. */
export function trivyEnvironment(work: string): Record<string, string> {
  return { HOME: work, USERPROFILE: work, TEMP: work, TMP: work, TMPDIR: work,
    XDG_CONFIG_HOME: path.join(work, 'config'), XDG_CACHE_HOME: path.join(work, 'cache'), XDG_DATA_HOME: path.join(work, 'data'),
    APPDATA: path.join(work, 'roaming'), LOCALAPPDATA: path.join(work, 'local') };
}
export function trivyArguments(snapshot: string, work: string): string[] {
  return ['config', '--config', path.join(work, 'trivy.yaml'), '--ignorefile', path.join(work, 'empty.ignore'), '--cache-dir', path.join(work, 'cache'),
    '--skip-check-update', '--skip-version-check', '--disable-telemetry', '--misconfig-scanners', 'dockerfile,kubernetes,terraform,cloudformation,helm',
    '--include-non-failures', '--exit-code', '0', '--format', 'json', snapshot];
}
function resultFailure(result: ProcessResult, run: EngineRun, scanning = false): boolean {
  run.exitCode = result.code; run.errors.push(...result.diagnostics ?? []);
  const boundaryError = run.errors.some(code => code.startsWith('process_'));
  // A zero-exit scanner diagnostic belongs to coverage analysis; containment errors never do.
  const onlyDiskDiagnostics = run.errors.every(code => code === 'job_disk_measured_limit' || code === 'job_disk_observation_unverified');
  if (result.reason === 'exit' && result.code === 0 && (onlyDiskDiagnostics || (scanning && !boundaryError))) return false;
  const unavailable = result.reason === 'spawn_failed' && run.errors.some(code => [
    'process_appcontainer_unsupported_platform', 'process_appcontainer_owner_unavailable', 'process_appcontainer_owner_version_unsupported',
    'process_owner_appcontainer_elevated_owner', 'process_owner_appcontainer_profile_unavailable', 'process_containment_unavailable',
  ].includes(code));
  run.execution = unavailable ? 'not_started' : result.reason === 'cancelled' ? 'cancelled' : ['timeout', 'job_disk_measured_limit'].includes(result.reason) ? 'budget_exceeded' : 'failed';
  run.errors.push(result.reason === 'exit' ? 'scanner_exit_failure' : result.reason);
  return true;
}
async function invoke(context: AdapterContext, signal: AbortSignal, probe: boolean): Promise<EngineRun> {
  const run = emptyRun('trivy', context), tool = context.config.tools.trivy;
  run.coverage = 'unsupported'; run.trivyCoverage = { state: 'unsupported', reason: 'offline_scope_unavailable' };
  run.rulesVersion = 'embedded-0.76.1';
  const cleanup = sourceCleanupFor(context.workspace);
  let root: string | undefined;
  try {
    if (signal.aborted) { run.execution = 'cancelled'; run.errors.push('cancelled_before_start'); return run; }
    if (!tool) { run.errors.push('tool_not_configured'); return run; }
    if (tool.version !== trivyVersion) { run.errors.push('unsupported_tool_version'); return run; }
    if (process.platform !== 'win32') { run.errors.push('process_appcontainer_unsupported_platform'); return run; }
    if (!scopedProcessOwner()) { run.errors.push('process_appcontainer_owner_unavailable'); return run; }
    if (!probe) {
      const inputs = acceptedInputs(context).units;
      run.targets = inputs.map(unit => unit.key);
      if (!inputs.length) { run.trivyCoverage = { state: 'unsupported', reason: 'no_recognized_config' }; run.errors.push('no_recognized_config'); return run; }
    }
    const bytes = await verifiedImage(tool, context.plan.root);
    root = await cleanup.directory(context.workspace, 'trivy-');
    registerJobDiskRoot(root);
    const bin = path.join(root, 'bin'), work = path.join(root, 'W');
    await mkdir(bin); registerJobDiskRoot(bin);
    await mkdir(work); registerJobDiskRoot(work);
    for (const name of ['cache', 'config', 'data', 'roaming', 'local']) await mkdir(path.join(work, name));
    const copy: Tool = { ...tool, path: path.join(bin, 'trivy.exe') };
    const budget = context.copyBudget ?? scopedCopyBudget();
    if (budget) {
      try {
        const copied = await budget.copy(tool.path, copy.path, { maximumBytes: bytes.length, sourceChangedCode: 'tool_digest_mismatch', signal, mode: 0o500 });
        if (copied.sha256 !== tool.sha256) throw new SafeError('tool_digest_mismatch');
      } catch (error) {
        // execute() reports an already-aborted signal as cancelled, including a scan timeout.
        if (signal.aborted && !(error instanceof SafeError) && (error === signal.reason
          || (error instanceof Error && ['AbortError', 'TimeoutError'].includes(error.name)))) {
          resultFailure({ code: null, stdout: Buffer.alloc(0), reason: 'cancelled' }, run); return run;
        }
        throw error;
      }
    } else await writeFile(copy.path, bytes, { flag: 'wx', mode: 0o500 });
    await writeFile(path.join(work, 'trivy.yaml'), '{}\n', { flag: 'wx', mode: 0o600 });
    await writeFile(path.join(work, 'empty.ignore'), '', { flag: 'wx', mode: 0o600 });
    const options = { cwd: work, home: work, timeoutMs: context.config.timeoutMs, maxOutputBytes: context.config.maxOutputBytes,
      signal, target: context.plan.root, environment: trivyEnvironment(work), captureStderr: true, appContainer: { snapshot: context.snapshot, work } };
    const version = await execute(copy, ['--version'], options);
    if (resultFailure(version, run)) return run;
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(version.stdout); } catch { throw new SafeError('tool_version_mismatch'); }
    if (!/^Version: 0\.76\.1\r?\n?$/.test(text)) throw new SafeError('tool_version_mismatch');
    const diskCause = jobDiskDiagnostic(version);
    if (diskCause) throw new SafeError(diskCause);
    if (probe) { run.execution = 'completed'; return run; }
    const result = await execute(copy, trivyArguments(context.snapshot, work), options);
    if (resultFailure(result, run, true)) return run;
    let raw: unknown;
    try { raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout)); } catch { throw new SafeError('scanner_json_invalid'); }
    const normalized = normalizeTrivy(raw, context, result.stderr);
    run.findings = normalized.findings; run.trivyCoverage = normalized.coverage; run.coverage = normalized.coverage.state;
    if (run.errors.length && normalized.coverage.state === 'analyzed') {
      run.coverage = 'partial'; run.trivyCoverage = { state: 'partial', receipts: normalized.coverage.receipts, reasons: ['trivy_scanner_diagnostics'] };
    }
    if (normalized.coverage.state === 'partial') run.errors.push(...normalized.coverage.reasons);
    run.errors = [...new Set(run.errors)];
    run.execution = 'completed';
    run.evidence = [{ kind: 'scanner_observation', snapshotHash: context.plan.snapshotHash,
      reportHash: hash(Buffer.concat([result.stdout, Buffer.from([0]), result.stderr ?? Buffer.alloc(0)])), classification: 'confidential', rawRetained: false }];
    return run;
  } catch (error) {
    run.execution = error instanceof JobDiskCopyLimitError || error instanceof SafeError && error.code === 'job_disk_measured_limit' ? 'budget_exceeded' : 'failed';
    run.errors.push(error instanceof SafeError ? error.code : 'invalid_or_unavailable_report'); return run;
  } finally {
    if (root) {
      releaseJobDiskRoot(root);
      if ((await cleanup.cleanup(context.workspace, [root])).status === 'failed') { run.execution = 'failed'; run.errors.push('source_cleanup_failed'); }
    }
    run.endedAt = new Date().toISOString();
  }
}

export const probeTrivy = (context: AdapterContext): Promise<EngineRun> => invoke(context, context.signal, true);
export class TrivyAdapter implements Adapter {
  private controller = new AbortController();
  capabilities(): Capability {
    return { engine: 'trivy', category: 'misconfiguration', inputs: Object.keys(scannerTypes), operatingSystems: ['windows'],
      permissions: ['AppContainer with zero capabilities', 'snapshot and private binary read', 'private working area write'],
      buildRequired: false, transmission: 'none intended; offline embedded checks; UDP denial unverified', license: 'Apache-2.0 CLI and embedded checks' };
  }
  plan(plan: Plan) { return { applicable: plan.schema === 'scanmux.plan/v3' && plan.trivy.inputs.length > 0,
    targets: plan.schema === 'scanmux.plan/v3' ? plan.trivy.inputs.map(unit => unit.key) : [], constraints: ['windows_appcontainer_required', 'offline_embedded_checks_only'] }; }
  cancel(): void { this.controller.abort(); }
  validate(): 'unsupported' { return 'unsupported'; }
  patch(): 'unsupported' { return 'unsupported'; }
  normalize(raw: unknown, context: AdapterContext): TrivyFinding[] { return normalizeTrivy(raw, context).findings; }
  run(context: AdapterContext): Promise<EngineRun> { return invoke(context, AbortSignal.any([context.signal, this.controller.signal]), false); }
}
