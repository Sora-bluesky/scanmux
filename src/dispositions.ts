import path from 'node:path';
import { lstat, writeFile } from 'node:fs/promises';
import type { Config, Engine } from './model.ts';
import { loadConfig } from './config.ts';
import { summarizeHistory } from './history.ts';
import { checkedJson } from './output.ts';
import { privateWorkspace } from './private-storage.ts';
import { array, boundedRead, canonical, hash, record, SafeError, within } from './safety.ts';

const engines = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const;
const decisions = ['false_positive', 'risk_accepted', 'out_of_scope'] as const;
type State = 'open' | 'current' | 'expired' | 'reconfirmation_required';
type Reason = 'report_changed' | 'finding_missing' | 'expired';
interface Decision {
  reportHash: string; engine: Engine; fingerprint: string; decision: typeof decisions[number];
  reason: string; reviewer: string; reviewedAt: string; expiresAt: string;
}
interface Row {
  source: 'current_finding' | 'unmatched_decision'; engine: Engine; fingerprint: string;
  state: State; reasons: Reason[]; decision: Decision | null;
}
function text(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new SafeError('invalid_disposition');
  return value;
}
function digestText(value: unknown): string {
  const result = text(value); if (!/^[0-9a-f]{64}$/.test(result)) throw new SafeError('invalid_disposition');
  return result;
}
function choice<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw new SafeError('invalid_disposition');
  return value as T;
}
function timestamp(value: unknown): string {
  const result = text(value), date = new Date(result);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(result) || !Number.isFinite(date.valueOf())
    || date.toISOString() !== (result.includes('.') ? result : result.replace('Z', '.000Z'))) throw new SafeError('invalid_disposition_time');
  return result;
}
const key = (value: { engine: Engine; fingerprint: string }) => `${value.engine}:${value.fingerprint}`;
const json = (bytes: Buffer) => record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));

export function evaluateDispositions(reportBytes: Buffer, decisionBytes?: Buffer, now = new Date()) {
  const evaluatedAt = now.toISOString(), currentTime = now.valueOf();
  const projected = summarizeHistory([reportBytes]), original = projected.summary.runs[0], report = json(reportBytes);
  if (report.schema === 'scanmux.report/v3') throw new SafeError('unsupported_report_schema');
  const findings = new Map<string, { engine: Engine; fingerprint: string }>();
  for (const input of array(report.engines)) {
    const run = record(input), engine = choice(run.engine, engines);
    for (const item of array(run.findings)) {
      const finding = record(item), identity = { engine: choice(finding.engine, engines), fingerprint: digestText(finding.fingerprint) };
      if (identity.engine !== engine || findings.has(key(identity))) throw new SafeError('invalid_disposition_finding');
      findings.set(key(identity), identity);
    }
  }
  const entries = new Map<string, Decision>();
  if (decisionBytes !== undefined) {
    const manifest = json(decisionBytes);
    if (manifest.schema !== 'scanmux.dispositions/v1') throw new SafeError('invalid_disposition');
    for (const input of array(manifest.entries)) {
      const item = record(input), entry: Decision = {
        reportHash: digestText(item.reportHash), engine: choice(item.engine, engines), fingerprint: digestText(item.fingerprint),
        decision: choice(item.decision, decisions), reason: text(item.reason), reviewer: text(item.reviewer),
        reviewedAt: timestamp(item.reviewedAt), expiresAt: timestamp(item.expiresAt),
      };
      if (Date.parse(entry.reviewedAt) > currentTime || Date.parse(entry.expiresAt) <= Date.parse(entry.reviewedAt)) throw new SafeError('invalid_disposition_time');
      if (entries.has(key(entry))) throw new SafeError('duplicate_disposition');
      entries.set(key(entry), entry);
    }
  }
  function assessed(entry: Decision): Row {
    const reasons: Reason[] = [];
    if (entry.reportHash !== original.reportHash) reasons.push('report_changed');
    if (!findings.has(key(entry))) reasons.push('finding_missing');
    if (Date.parse(entry.expiresAt) <= currentTime) reasons.push('expired');
    const unmatched = reasons.includes('report_changed') || reasons.includes('finding_missing');
    return { source: unmatched ? 'unmatched_decision' : 'current_finding', engine: entry.engine, fingerprint: entry.fingerprint,
      state: unmatched ? 'reconfirmation_required' : reasons.length ? 'expired' : 'current', reasons, decision: entry };
  }
  const rows: Row[] = [];
  for (const identity of findings.values()) {
    const entry = entries.get(key(identity));
    rows.push(entry?.reportHash === original.reportHash ? assessed(entry)
      : { source: 'current_finding', ...identity, state: 'open', reasons: [], decision: null });
  }
  for (const entry of entries.values()) if (entry.reportHash !== original.reportHash || !findings.has(key(entry))) rows.push(assessed(entry));
  return { root: projected.roots[0].root, summary: {
    schema: 'scanmux.disposition-summary/v1' as const, operation: 'assessed_saved_records' as const, evaluatedAt,
    basis: 'exact_saved_report_bytes_not_authenticated' as const, reviewerIdentity: 'declared_not_authenticated' as const,
    original: { runId: original.runId, reportHash: original.reportHash, repoId: original.repoId, commit: original.commit,
      policyHash: original.policyHash, planHash: original.planHash, snapshotHash: original.snapshotHash,
      recordedGate: original.recordedGate, executionState: original.executionState, coverageState: original.coverageState,
      completion: original.completion, reasons: original.reasons }, rows,
    counts: { current: rows.filter(row => row.state === 'current').length, expired: rows.filter(row => row.state === 'expired').length,
      reconfirmationRequired: rows.filter(row => row.state === 'reconfirmation_required').length, open: rows.filter(row => row.state === 'open').length },
    gateChanged: false as const, automaticCarryover: false as const,
  } };
}

export async function readDispositions(reportFile: string, decisionFile: string | undefined, configPath: string | undefined, config: Config) {
  const files = [reportFile, ...(decisionFile === undefined ? [] : [decisionFile])];
  if (files.some(file => !path.isAbsolute(file))) throw new SafeError('invalid_disposition_path');
  const inputs = await Promise.all(files.map(file => canonical(file)));
  const reportBytes = await boundedRead(inputs[0], config.maxOutputBytes);
  const decisionBytes = inputs.length === 2 ? await boundedRead(inputs[1], config.maxOutputBytes - reportBytes.length) : undefined;
  const evaluated = evaluateDispositions(reportBytes, decisionBytes), root = await canonical(evaluated.root);
  if (!(await lstat(root)).isDirectory() || hash(root) !== evaluated.summary.original.repoId) throw new SafeError('disposition_target_mismatch');
  await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
  if (inputs.some(input => within(root, input))) throw new SafeError('disposition_input_inside_target');
  const workspace = await privateWorkspace(root), destination = path.join(workspace, 'dispositions.json');
  const output = await checkedJson(evaluated.summary, config, workspace);
  await checkedJson({ destination }, config, workspace);
  await writeFile(destination, output, { flag: 'wx', mode: 0o600 });
  return { summary: evaluated.summary, destination, json: output };
}
