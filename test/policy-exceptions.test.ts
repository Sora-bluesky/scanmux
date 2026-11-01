import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, mkdir, readFile, writeFile, symlink } from 'node:fs/promises';
import type { Report, Finding } from '../src/model.ts';
import { defaults } from '../src/config.ts';
import { emptyRun } from '../src/engine-run.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { hash, digest } from '../src/safety.ts';
import { evaluatePolicyExceptions, checkPolicyFiles } from '../src/policy-exceptions.ts';

const now = new Date('2026-10-23T12:00:00.000Z');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const manifest = (entries: unknown[]) => bytes({ schema: 'scanmux.dispositions/v1', entries });
function finding(fingerprint = 'e'.repeat(64)): Finding {
  return { engine: 'osv', fingerprint, originIds: ['synthetic'], category: 'dependency', severity: 'high', confidence: 'high',
    evidenceState: 'source_supported', disposition: 'open', file: 'private-source.ts', line: 1, title: 'Private finding title',
    fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' };
}
function fixture(root = path.resolve('test')): Report {
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), treeHash: 'b'.repeat(40),
    advisoryCatalog: { ...catalogIdentity }, snapshotHash: 'c'.repeat(64), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: 'd'.repeat(64),
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  const report: Report = { schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555', plan,
    startedAt: '2026-10-23T00:00:00Z', endedAt: '2026-10-23T00:00:01Z',
    runner: { platform: 'synthetic', node: 'synthetic', imageDigest: null, isolation: 'local-static-only' },
    executionState: 'completed', coverageState: 'complete', gate: 'FAIL', exitCode: 1, reasons: [], integrityErrors: [],
    engines: plan.required.map(engine => ({ ...emptyRun(engine, { plan, config: defaults, workspace: '', snapshot: '', signal: new AbortController().signal, secretsCleared: true }), execution: 'completed', coverage: 'analyzed' })) };
  report.engines[1].findings = [finding()]; return settled(report);
}
function settled(report: Report): Report {
  const result = decide(report.plan, report.engines, report.integrityErrors);
  return Object.assign(report, result, { exitCode: exitCodes[result.gate] });
}
function decision(report: Report, fingerprint = 'e'.repeat(64)) {
  return { reportHash: hash(bytes(report)), engine: 'osv', fingerprint, decision: 'risk_accepted',
    reason: 'Synthetic policy test only; no actual human risk acceptance.', reviewer: 'Fixture reviewer',
    reviewedAt: '2026-10-23T01:00:00Z', expiresAt: '2026-10-24T00:00:00Z' };
}
const evaluate = (report: Report, entries: unknown[]) => evaluatePolicyExceptions(bytes(report), manifest(entries), now).summary;

test('each explicit current exception affects only a separate gate and retains every original identity and reason', () => {
  for (const kind of ['false_positive', 'risk_accepted', 'out_of_scope']) {
    const report = fixture(), entry = { ...decision(report), decision: kind }, before = bytes(report);
    const result = evaluate(report, [entry]);
    assert.equal(result.original.recordedGate, 'FAIL'); assert.deepEqual(result.original.reasons, report.reasons);
    assert.equal(result.gate, 'PASS'); assert.equal(result.exitCode, 0); assert.equal(result.counts.applied, 1);
    assert.equal(result.rows[0].applied, true); assert.deepEqual(result.rows[0].decision, entry);
    assert.equal(result.originalReportChanged, false); assert.equal(result.automaticCarryover, false);
    assert.equal(result.basis, 'exact_saved_report_bytes_not_authenticated'); assert.equal(result.reviewerIdentity, 'declared_not_authenticated');
    assert.equal(result.decisionsHash, hash(manifest([entry]))); assert.deepEqual(bytes(report), before);
    assert.ok(!JSON.stringify(result).includes('private-source.ts')); assert.ok(!JSON.stringify(result).includes('Private finding title'));
  }
});

test('remaining findings keep FAIL or REVIEW and empty decisions preserve the original decision', () => {
  const report = fixture(); report.engines[1].findings.push(finding('f'.repeat(64))); settled(report);
  assert.equal(evaluate(report, []).gate, 'FAIL'); assert.equal(evaluate(report, [decision(report)]).gate, 'FAIL');
  report.engines[1].findings[1].evidenceState = 'candidate'; settled(report);
  const partial = evaluate(report, [decision(report)]); assert.equal(partial.gate, 'REVIEW'); assert.equal(partial.counts.open, 1);
  report.engines[1].findings = [finding()]; report.engines[1].findings[0].evidenceState = 'candidate'; settled(report);
  assert.equal(report.gate, 'REVIEW'); assert.equal(evaluate(report, [decision(report)]).gate, 'PASS');
});

test('expiry is inclusive, and stale or unmatched expired records prevent PASS even with no current finding', () => {
  for (const [expiresAt, expected] of [['2026-10-23T12:00:00.001Z', 'PASS'], ['2026-10-23T12:00:00.000Z', 'FAIL'], ['2026-10-23T11:59:59.999Z', 'FAIL']]) {
    const report = fixture(), entry = { ...decision(report), expiresAt }, result = evaluate(report, [entry]);
    assert.equal(result.gate, expected); assert.equal(result.rows[0].applied, expected === 'PASS');
  }
  const report = fixture(), old = decision(report); old.expiresAt = now.toISOString();
  report.engines[1].findings = []; settled(report);
  const result = evaluate(report, [old]); assert.equal(result.original.recordedGate, 'PASS'); assert.equal(result.gate, 'INCOMPLETE');
  assert.equal(result.counts.applied, 0); assert.deepEqual(result.rows[0].reasons, ['report_changed', 'finding_missing', 'expired']);
  assert.ok(result.reasons.includes('exception_reconfirmation_required'));
});

test('changes to code, policy, database evidence and serialization cannot carry an exception forward', () => {
  const original = fixture(), entry = decision(original);
  for (const mutate of [
    (r: Report) => { r.plan.commit = 'f'.repeat(40); }, (r: Report) => { r.plan.policyHash = 'f'.repeat(64); },
    (r: Report) => { r.engines[1].database = [{ ecosystem: 'npm', sha256: 'f'.repeat(64), modifiedAt: now.toISOString() }]; },
    (r: Report) => { r.engines[1].findings[0].title = 'Different evidence'; },
  ]) { const changed = structuredClone(original); mutate(changed); const result = evaluate(changed, [entry]); assert.equal(result.gate, 'FAIL'); assert.equal(result.counts.applied, 0); assert.equal(result.counts.reconfirmationRequired, 1); }
  const formatted = evaluatePolicyExceptions(Buffer.from(JSON.stringify(original, null, 2)), manifest([entry]), now).summary;
  assert.equal(formatted.counts.applied, 0); assert.equal(formatted.gate, 'FAIL');
});

test('all incomplete execution and coverage paths remain non-waivable after removing every finding cause', () => {
  const mutations: ((r: Report) => void)[] = [
    r => { r.engines.pop(); r.coverageState = 'incomplete'; },
    ...(['not_started', 'cancelled', 'budget_exceeded'] as const).map(execution => (r: Report) => { r.engines[2].execution = execution; r.engines[2].coverage = 'skipped'; }),
    ...(['partial', 'unsupported', 'skipped'] as const).map(coverage => (r: Report) => { r.engines[2].coverage = coverage; }),
    r => { r.plan.blockers = ['unverified_condition']; }, r => { r.plan.exclusions = [{ path: 'binary', reason: 'binary' }]; },
    r => { r.executionState = 'cancelled'; }, r => { r.executionState = 'budget_exceeded'; }, r => { r.executionState = 'not_started'; },
    r => { r.coverageState = 'incomplete'; },
    r => { r.engines[0].coverage = 'partial'; r.engines[0].errors = ['builtin_rules_exclude_paths']; r.engines[0].exclusions = ['package-lock.json']; },
  ];
  for (const mutate of mutations) {
    const report = fixture(); mutate(report); settled(report);
    const result = evaluate(report, [decision(report)]); assert.equal(result.gate, 'INCOMPLETE'); assert.equal(result.exitCode, 3);
    assert.equal(result.counts.applied, 1); assert.ok(result.reasons.includes('required_analysis_incomplete'));
  }
});

test('all failure and uncertain termination paths remain ERROR regardless of eligible exceptions', () => {
  const mutations: ((r: Report) => void)[] = [
    r => { r.engines[2].execution = 'failed'; r.engines[2].coverage = 'skipped'; },
    r => { r.executionState = 'failed'; }, r => { r.integrityErrors = ['snapshot_changed']; },
    r => { r.plan.blockers = ['git_termination_unverified']; }, r => { r.integrityErrors = ['termination_unverified']; },
    r => { r.engines[0].coverage = 'partial'; r.engines[0].errors = ['termination_unverified']; },
  ];
  for (const mutate of mutations) {
    const report = fixture(); mutate(report); settled(report);
    const result = evaluate(report, [decision(report)]); assert.equal(result.gate, 'ERROR'); assert.equal(result.exitCode, 4);
  }
});

test('malformed and internally contradictory policy state is rejected rather than treated as clean analysis', () => {
  const mutations: ((r: any) => void)[] = [
    r => { r.engines[0].errors = ['termination_unverified']; }, r => { r.engines[0].exclusions = ['hidden']; },
    r => { r.engines[0].execution = 'not_started'; }, r => { r.engines[0].coverage = 'new_unknown_state'; },
    r => { r.engines[0].errors = [null]; }, r => { delete r.engines[0].exclusions; },
    r => { r.engines[1].findings[0].category = 'other'; }, r => { r.engines[1].findings[0].severity = null; },
    r => { delete r.engines[1].findings[0].evidenceState; }, r => { r.engines[1].findings[0].engine = 'gitleaks'; },
    r => { r.engines[1].findings.push(r.engines[1].findings[0]); }, r => { r.engines.push(r.engines[0]); },
    r => { r.plan.required.pop(); }, r => { r.plan.required[1] = 'gitleaks'; },
    r => { r.plan.exclusions = [{ path: 'x', reason: null }]; }, r => { r.plan.blockers = [5]; },
    r => { r.integrityErrors = [null]; }, r => { r.reasons = 'missing array'; },
    r => { r.gate = 'PASS'; r.exitCode = 0; }, r => { r.exitCode = 0; },
  ];
  for (const mutate of mutations) { const report = fixture(); mutate(report); assert.throws(() => evaluate(report, [])); }
  assert.throws(() => evaluatePolicyExceptions(Buffer.from([0xff]), manifest([]), now));
  assert.throws(() => evaluatePolicyExceptions(bytes(fixture()), Buffer.from([0xff]), now));
});

test('invalid or duplicate human decisions cannot be applied', () => {
  const report = fixture(), valid = decision(report);
  for (const field of Object.keys(valid)) { const entry: any = { ...valid }; delete entry[field]; assert.throws(() => evaluate(report, [entry])); }
  for (const entry of [
    { ...valid, reason: ' ' }, { ...valid, reviewer: '\n' }, { ...valid, decision: 'fixed' },
    { ...valid, reviewedAt: '2026-10-23T13:00:00Z' }, { ...valid, expiresAt: valid.reviewedAt },
    { ...valid, expiresAt: '2026-02-29T00:00:00Z' }, { ...valid, expiresAt: '2026-10-24T09:00:00+09:00' },
  ]) assert.throws(() => evaluate(report, [entry]));
  assert.throws(() => evaluate(report, [valid, valid]));
});

test('input size, canonical file and target boundaries are enforced before saving', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-policy-test-'));
  test.after(() => removeTempDir(workspace));
  const root = path.join(workspace, 'repo'); await mkdir(root);
  const report = fixture(root), original = bytes(report), entries = manifest([]);
  const reportFile = path.join(workspace, 'report.json'), decisionFile = path.join(workspace, 'decisions.json'), inside = path.join(root, 'decisions.json');
  await writeFile(reportFile, original); await writeFile(decisionFile, entries); await writeFile(inside, entries);
  await assert.rejects(checkPolicyFiles('report.json', decisionFile, undefined, defaults), /invalid_policy_path/);
  await assert.rejects(checkPolicyFiles(reportFile, inside, undefined, defaults), /policy_input_inside_target/);
  await assert.rejects(checkPolicyFiles(reportFile, decisionFile, undefined, { ...defaults, maxOutputBytes: original.length + entries.length - 1 }), /file_limit/);
  const alias = path.join(workspace, 'alias'); await symlink(root, alias, 'junction');
  await assert.rejects(checkPolicyFiles(reportFile, path.join(alias, 'decisions.json'), undefined, defaults), /linked_path/);
  assert.deepEqual(await readFile(reportFile), original); assert.deepEqual(await readFile(decisionFile), entries);
});
