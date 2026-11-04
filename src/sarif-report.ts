import { gzipSync } from 'node:zlib';
import type { Finding, Report, TrivyCoverage } from './model.ts';
import { SafeError, safeRelative } from './safety.ts';
import { comparisonSummary } from './comparison.ts';

const engines = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories', 'trivy'] as const;
const categories = ['secret', 'dependency', 'code', 'runtime', 'misconfiguration'] as const;
const executions = ['completed', 'failed', 'cancelled', 'budget_exceeded', 'not_started'] as const;
const coverages = ['analyzed', 'unsupported', 'skipped', 'partial'] as const;
const severities = ['critical', 'high', 'medium', 'low', 'informational', 'unknown'] as const;
const gates = ['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'] as const;
const maximumResults = 5000;
const maximumGzipBytes = 10 * 1024 * 1024;
function member<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw new SafeError('invalid_sarif_report');
  return value as T;
}
function requiredText(value: unknown, pattern: RegExp): string {
  if (!supported(value, pattern)) throw new SafeError('invalid_sarif_report');
  return value;
}
const originPattern = /^[a-z][a-z0-9_.-]{0,127}$/i;
const versionPattern = /^[a-z0-9][a-z0-9.+_~-]{0,199}$/i;
const ecosystemPattern = /^[a-z][a-z0-9._+-]{0,39}$/i;
function packageName(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 200) return false;
  return supported(value, /^(?:@[a-z0-9][a-z0-9._+-]*\/)?[a-z0-9][a-z0-9._+-]*(?:\/[a-z0-9][a-z0-9._+-]*)*$/i);
}
function supported(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && !/[\x00-\x1f\x7f\u2028\u2029]/.test(value) && pattern.test(value);
}
function result(finding: Finding) {
  const engine = member(finding.engine, engines), category = member(finding.category, categories);
  const severity = member(finding.severity, severities);
  const confidence = member(finding.confidence, ['high', 'medium', 'low', 'unknown']);
  const evidenceState = member(finding.evidenceState, ['candidate', 'source_supported', 'runtime_reproduced']);
  member(finding.disposition, ['open']); member(finding.reachability, ['unknown']); member(finding.knownExploited, ['unknown']);
  const fingerprint = requiredText(finding.fingerprint, /^[a-f0-9]{64}$/);
  const originIds = finding.originIds.filter(value => supported(value, originPattern));
  const fixedVersions = finding.fixedVersions.filter(value => supported(value, versionPattern));
  const pkg = finding.package;
  const name = pkg && packageName(pkg.name) ? pkg.name : undefined;
  const version = pkg && supported(pkg.version, versionPattern) ? pkg.version : undefined;
  const ecosystem = pkg && supported(pkg.ecosystem, ecosystemPattern) ? pkg.ecosystem : undefined;
  let uri: string | undefined;
  try { if (finding.file !== null) uri = safeRelative(finding.file).split('/').map(segment => encodeURIComponent(segment)).join('/'); } catch { /* Omit unsupported locations, never the finding. */ }
  const line = Number.isSafeInteger(finding.line) && finding.line! > 0 ? finding.line! : undefined;
  const endLine = (finding.engine === 'trivy' || finding.engine === 'codex-security') && line !== undefined && Number.isSafeInteger(finding.endLine) && finding.endLine! >= line ? finding.endLine! : undefined;
  if ((engine === 'trivy') !== (category === 'misconfiguration') || engine === 'trivy' && evidenceState !== 'candidate') throw new SafeError('invalid_sarif_report');
  return {
    ruleId: `scanmux/${engine}/${category}`,
    level: severity === 'critical' || severity === 'high' ? 'error' : severity === 'medium' || severity === 'low' ? 'warning' : 'note',
    message: { text: 'ScanMux finding' + (originIds.length ? ': ' + originIds.join(', ') : '.') },
    partialFingerprints: { 'scanmux/v1': fingerprint },
    ...(uri === undefined ? {} : { locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: 'SRCROOT' }, ...(line === undefined ? {} : { region: { startLine: line, ...(endLine === undefined ? {} : { endLine }) } }) } }] }),
    properties: { fingerprint, engine, category, severity, confidence, evidenceState, originIds, fixedVersions,
      ...(name === undefined ? {} : { packageName: name }), ...(version === undefined ? {} : { packageVersion: version }),
      ...(ecosystem === undefined ? {} : { ecosystem }), locationUnavailable: uri === undefined,
      metadataOmitted: { originIds: originIds.length !== finding.originIds.length, fixedVersions: fixedVersions.length !== finding.fixedVersions.length,
        packageName: Boolean(pkg && name === undefined), packageVersion: Boolean(pkg && version === undefined), ecosystem: Boolean(pkg && ecosystem === undefined) } },
  };
}

function coverageEvidence(coverage: TrivyCoverage, report: Report) {
  const state = member(coverage.state, ['analyzed', 'unsupported', 'partial']);
  if (coverage.state === 'unsupported') return { state, reason: member(coverage.reason, ['no_recognized_config', 'offline_scope_unavailable']) };
  const units = new Map(report.plan.trivy?.inputs.map(unit => [unit.key, unit]) ?? []);
  const receipts = coverage.receipts.map(receipt => {
    const unit = units.get(receipt.unit);
    if (!unit) throw new SafeError('invalid_sarif_report');
    // A unit key has a controlled kind and a repository-relative root; never copy host paths.
    const root = unit.key.slice(unit.key.indexOf(':') + 1);
    if (unit.key !== `${member(unit.kind, ['dockerfile', 'kubernetes', 'terraform', 'cloudformation', 'helm', 'unresolved'])}:${root}`) throw new SafeError('invalid_sarif_report');
    if (root !== '.') safeRelative(root);
    return { unit: unit.key, state: member(receipt.state, ['analyzed', 'unsupported', 'parse_failed', 'excluded', 'unresolved']) };
  });
  if (new Set(receipts.map(receipt => receipt.unit)).size !== receipts.length) throw new SafeError('invalid_sarif_report');
  if (state === 'analyzed' && (!receipts.length || receipts.length !== units.size || receipts.some(receipt => receipt.state !== 'analyzed' || units.get(receipt.unit)!.unresolved))) throw new SafeError('invalid_sarif_report');
  return { state, receipts, ...(coverage.state === 'partial' ? { reasonCount: coverage.reasons.length } : {}) };
}

/** Pure, closed projection of Report v2/v3. JSON remains the decision record. */
export function renderSarifReports(report: Report, maxOutputBytes: number): { name: string; text: string; findings: number }[] {
  if (!['scanmux.report/v2', 'scanmux.report/v3'].includes(report.schema) || !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0) throw new SafeError('invalid_sarif_report');
  const v3 = report.schema === 'scanmux.report/v3';
  if (v3 !== (report.plan.schema === 'scanmux.plan/v3')) throw new SafeError('invalid_sarif_report');
  const allowedEngines = v3 ? engines : engines.filter(engine => engine !== 'trivy');
  const gate = member(report.gate, gates);
  const executionState = member(report.executionState, executions), coverageState = member(report.coverageState, ['complete', 'incomplete']);
  if (report.exitCode !== gates.indexOf(gate)) throw new SafeError('invalid_sarif_report');
  const runId = requiredText(report.runId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
  const snapshotHash = requiredText(report.plan.snapshotHash, /^[a-f0-9]{64}$/);
  const commit = report.plan.commit === null ? null : requiredText(report.plan.commit, /^[a-f0-9]{40,64}$/);
  const comparison = comparisonSummary(report.plan);
  const required = report.plan.required.map(engine => member(engine, allowedEngines));
  if (v3 && (JSON.stringify(required) !== JSON.stringify(engines) || !report.plan.trivy)) throw new SafeError('invalid_sarif_report');
  const engineRuns = report.engines.map(run => ({ engine: member(run.engine, allowedEngines), execution: member(run.execution, executions),
    coverage: member(run.coverage, coverages), findings: run.findings.length, required: required.includes(run.engine),
    ...(v3 && run.engine === 'trivy' && run.trivyCoverage ? { trivyCoverage: coverageEvidence(run.trivyCoverage, report) } : {}) }));
  const requiredEngines = required.map(engine => ({ engine, records: engineRuns.filter(run => run.engine === engine) }));
  const executionSuccessful = executionState === 'completed' && coverageState === 'complete' && report.integrityErrors.length === 0 && required.length > 0
    && new Set(required).size === required.length && requiredEngines.every(({ records }) => records.length === 1 && records[0].execution === 'completed' && records[0].coverage === 'analyzed')
    && (!v3 || report.engines.some(run => run.engine === 'trivy' && run.trivyCoverage?.state === 'analyzed'));
  if (gate === 'PASS' && !executionSuccessful) throw new SafeError('invalid_sarif_report');
  const results = report.engines.flatMap(run => run.findings.map(finding => {
    if (finding.engine !== run.engine) throw new SafeError('invalid_sarif_report');
    return result(finding);
  }));
  const rules = [...new Set(results.map(item => item.ruleId))].map(id => ({ id }));
  const serialize = (items: typeof results, part: number, parts: number) => JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
      tool: { driver: { name: 'ScanMux', version: '0.2.1', rules } },
      originalUriBaseIds: { SRCROOT: { description: { text: 'Repository root; absolute location intentionally omitted.' } } },
      invocations: [{ executionSuccessful, ...(executionSuccessful ? {} : { toolExecutionNotifications: [{ level: 'warning', message: { text: 'ScanMux required analysis is incomplete or failed. Consult execution and coverage properties.' } }] }) }],
      properties: { runId, commit, snapshotHash, ...(comparison ? { comparison } : {}), gate, exitCode: report.exitCode, executionState, coverageState,
        integrityErrorCount: report.integrityErrors.length, engineRuns, requiredEngines, part, parts, totalFindings: results.length },
      results: items,
    }],
  }, null, 2) + '\n';
  const fits = (text: string) => Buffer.byteLength(text) <= maxOutputBytes && gzipSync(text).length <= maximumGzipBytes;
  // Conservative part numbers make the final serialization no larger than the sizes tested here.
  const bound = Math.max(1, results.length), chunks: (typeof results)[] = [];
  if (!results.length) {
    if (!fits(serialize([], 1, 1))) throw new SafeError('sarif_output_size_limit');
    chunks.push([]);
  }
  for (let offset = 0; offset < results.length;) {
    let low = 1, high = Math.min(maximumResults, results.length - offset), accepted = 0;
    while (low <= high) {
      const count = Math.floor((low + high) / 2);
      if (fits(serialize(results.slice(offset, offset + count), bound, bound))) { accepted = count; low = count + 1; } else high = count - 1;
    }
    if (!accepted) throw new SafeError('sarif_output_size_limit');
    chunks.push(results.slice(offset, offset + accepted)); offset += accepted;
  }
  return chunks.map((items, index) => {
    const text = serialize(items, index + 1, chunks.length);
    if (!fits(text)) throw new SafeError('sarif_output_size_limit');
    return { name: chunks.length === 1 ? 'report.sarif' : `report-${String(index + 1).padStart(4, '0')}.sarif`, text, findings: items.length };
  });
}
