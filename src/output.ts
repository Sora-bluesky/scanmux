import { scopedJobDisk, withJobDisk } from './job-disk.ts';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Config, Report } from './model.ts';
import { array, SafeError } from './safety.ts';
import { execute, jobDiskDiagnostic, verifyVersion } from './process.ts';
import { gitleaksConfig } from './adapters.ts';
import { renderHtmlReport } from './html-report.ts';
import { renderSarifReports } from './sarif-report.ts';
import { parseReportLanguage, type ReportLanguage } from './report-language.ts';
import type { PolicyRef } from './runtime-policy.ts';
import type { EngineDetail } from './provenance.ts';
import type { UnpinnedTail } from './engine-record.ts';
import { sourceCleanupFailed, sourceCleanupFor } from './source-cleanup.ts';
import { decide, exitCodes } from './policy.ts';

export async function checkedJson(payload: unknown, config: Config, workspace: string): Promise<string> {
  const serialized = JSON.stringify(payload, null, 2) + '\n';
  return checkedText(serialized, config, workspace);
}
export async function checkedText(serialized: string, config: Config, workspace: string, signal?: AbortSignal): Promise<string> {
  // After a disk stop, the bounded secret check must still publish the stop cause.
  // It is output validation, not a continuation of the stopped analysis.
  const disk = scopedJobDisk();
  return withJobDisk(disk?.cause ? undefined : disk, () => checkText(serialized, config, workspace, signal));
}
async function checkText(serialized: string, config: Config, workspace: string, signal?: AbortSignal): Promise<string> {
  if (Buffer.byteLength(serialized) > config.maxOutputBytes) throw new SafeError('output_size_limit');
  const tool = config.tools.gitleaks;
  if (!tool || tool.version !== '8.30.1') throw new SafeError('output_secret_check_unavailable');
  await verifyVersion(tool, ['version'], { cwd: workspace, home: workspace,
    timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, signal });
  const cleanup = sourceCleanupFor(workspace);
  const checkDirectory = await cleanup.directory(workspace, 'output-check-');
  const rulePath = path.join(checkDirectory, 'rules.toml');
  let failed = false;
  try {
    await writeFile(rulePath, gitleaksConfig, { flag: 'wx', mode: 0o600 });
    const check = await execute(tool, ['stdin', '--config', rulePath, '--redact=100', '--no-banner', '--no-color', '--log-level', 'error', '--ignore-gitleaks-allow', '--report-format', 'json', '--report-path', '-'], {
      cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, input: serialized, signal,
    });
    if (check.reason === 'termination_unverified') throw new SafeError('termination_unverified');
    if (check.reason.startsWith('job_disk_')) throw new SafeError(check.reason);
    if (check.reason !== 'exit' || check.code !== 0) throw new SafeError('output_secret_check_failed');
    try { if (array(JSON.parse(check.stdout.toString('utf8'))).length !== 0) throw new Error(); }
    catch { throw new SafeError('output_secret_check_failed'); }
    const diskCause = jobDiskDiagnostic(check);
    if (diskCause) throw new SafeError(diskCause);
    return serialized;
  } catch (error) { failed = true; throw error; }
  finally {
    if ((await cleanup.cleanup(workspace, [checkDirectory])).status === 'failed' && !failed) throw new SafeError('source_cleanup_failed');
  }
}
export async function saveReportBundle(payload: Report, config: Config, workspace: string,
  check: typeof checkedJson = checkedJson, checkText: typeof checkedText = checkedText, inputLanguage: ReportLanguage = 'ja') {
  const language = parseReportLanguage(inputLanguage);
  if (sourceCleanupFailed()) {
    payload.integrityErrors = [...new Set([...payload.integrityErrors, 'source_cleanup_failed'])];
    const judgment = decide(payload.plan, payload.engines, payload.integrityErrors);
    Object.assign(payload, judgment, { executionState: 'failed', exitCode: exitCodes[judgment.gate] });
  }
  const destination = path.join(workspace, 'report.json');
  const htmlDestination = path.join(workspace, 'report.html');
  const json = await check(payload, config, workspace);
  const report = JSON.parse(json) as Report;
  const html = renderHtmlReport(report, language);
  if (Buffer.byteLength(json) > config.maxOutputBytes || Buffer.byteLength(html) > config.maxOutputBytes) throw new SafeError('output_size_limit');
  await checkText(html, config, workspace);
  const sarif = renderSarifReports(report, config.maxOutputBytes).map(part => ({ ...part, destination: path.join(workspace, part.name) }));
  for (const part of sarif) await checkText(part.text, config, workspace);
  await check({ destination, htmlDestination, sarifDestinations: sarif.map(part => part.destination) }, config, workspace);
  await writeFile(destination, json, { mode: 0o600, flag: 'wx' });
  await writeFile(htmlDestination, html, { mode: 0o600, flag: 'wx' });
  for (const part of sarif) await writeFile(part.destination, part.text, { mode: 0o600, flag: 'wx' });
  return { destination, htmlDestination, json, html, report, sarif };
}
export async function saveReport(payload: Report, config: Config, workspace: string): Promise<string> {
  const { destination } = await saveReportBundle(payload, config, workspace);
  return destination;
}
export function staticError(code: string, policy?: PolicyRef, engine?: EngineDetail, ledger?: UnpinnedTail): string {
  // Callers only pass application-owned codes, never exception messages.
  return JSON.stringify({ schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: code,
    ...(policy ? { policy: { id: policy.id, revision: policy.revision, state: policy.state, sha256: policy.sha256 } } : {}),
    ...(engine ? { engine: { component: engine.component, state: engine.state, reason: engine.reason, ledgerSeq: engine.ledgerSeq } } : {}),
    ...(ledger ? { ledger: { entries: ledger.entries, head: ledger.head,
      unpinned: ledger.unpinned.map(line => ({ seq: line.seq, component: line.component, sha256: line.sha256, change: line.change })) } } : {}) });
}
