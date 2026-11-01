import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, mkdir, writeFile, readFile, symlink } from 'node:fs/promises';
import { resumeSource, readResumeSource, verifyResumePlan, resumeReceipt } from '../src/resume.ts';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { emptyRun } from '../src/engine-run.ts';
import { digest, hash } from '../src/safety.ts';
import type { Report } from '../src/model.ts';

function fixture(root = path.resolve('test')): Report {
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: hash(root),
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 'c'.repeat(64), dirty: false,
    files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '',
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  return { schema: 'scanmux.report/v2', runId: 'aaaaaaaa-1111-2222-3333-444444444444', plan,
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z',
    runner: { platform: 'fixture', node: 'fixture', isolation: 'local-static-only', imageDigest: null },
    executionState: 'cancelled', coverageState: 'incomplete', gate: 'INCOMPLETE', exitCode: 3, reasons: [], integrityErrors: [],
    engines: plan.required.map(engine => emptyRun(engine, { plan, config: defaults, workspace: '', snapshot: '',
      signal: new AbortController().signal, secretsCleared: false })) };
}
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
const source = (report: Report) => resumeSource(bytes(report), report.plan.root);
const rehash = (plan: Report['plan']) => { plan.planHash = digest({ ...plan, planHash: '' }); };
const bundle = (report: Report) => ({ report, json: bytes(report).toString(), destination: '', htmlDestination: '', html: '', sarif: [] });

test('resume accepts only explicitly stopped runs and preserves unknown/missing recorded usage', () => {
  const report = fixture(); report.engines[2].usage = { calls: 5, cost: null, kind: 'unknown', allowance: 'unknown' };
  report.engines.pop();
  for (const state of ['cancelled', 'budget_exceeded'] as const) {
    report.executionState = state;
    const selected = source(report); verifyResumePlan(selected, report.plan);
    assert.equal(selected.previous.reportedCalls, 5); assert.equal(selected.previous.missingEngineRecords, 1);
    assert.equal(selected.previous.costKind, 'unknown'); assert.equal(selected.previous.recordedGate, 'INCOMPLETE');
  }
  for (const state of ['completed', 'failed', 'not_started'] as const) {
    report.executionState = state; assert.throws(() => source(report), /resume_requires_stopped_run/);
  }
});

test('resume rejects termination uncertainty and malformed errors in every saved location', () => {
  const locations = [
    (r: Report, value: any) => { r.plan.blockers = value; },
    (r: Report, value: any) => { r.integrityErrors = value; },
    ...fixture().engines.map((_, index) => (r: Report, value: any) => { r.engines[index].errors = value; }),
  ];
  for (const set of locations) {
    for (const value of [['termination_unverified'], ['git_termination_unverified'], null, {}, [7]]) {
      const report = fixture(); set(report, value); rehash(report.plan);
      assert.throws(() => source(report), /resume_termination_unverified|invalid_resume_report|invalid_report/);
    }
  }
});

test('resume checks old plan integrity and current target before accepting a saved source', () => {
  const report = fixture();
  assert.throws(() => resumeSource(bytes(report), path.resolve('different-target')), /resume_target_mismatch/);
  report.plan.repoId = 'f'.repeat(64); rehash(report.plan); assert.throws(() => source(report), /resume_target_mismatch/);
  const changed = fixture(); changed.plan.constraints.push('edited'); assert.throws(() => source(changed), /resume_plan_integrity/);
  const invalid: any = fixture(); invalid.engines[0].usage.calls = -1; assert.throws(() => source(invalid), /invalid_history_usage/);
  assert.throws(() => resumeSource(Buffer.from([0xff]), report.plan.root));
});

test('resume binds every fresh plan identity, requires a runnable offline plan, and never repairs mismatches', () => {
  const report = fixture(), selected = source(report);
  for (const field of ['repoId', 'commit', 'policyHash', 'snapshotHash'] as const) {
    const changed = structuredClone(report.plan); changed[field] = 'f'.repeat(field === 'commit' ? 40 : 64); rehash(changed);
    assert.throws(() => verifyResumePlan(selected, changed), /resume_identity_mismatch/);
  }
  const changed = structuredClone(report.plan); changed.constraints.push('new'); rehash(changed);
  assert.throws(() => verifyResumePlan(selected, changed), /resume_identity_mismatch/);
  changed.planHash = 'e'.repeat(64); assert.throws(() => verifyResumePlan(selected, changed), /resume_plan_integrity/);
  const blocked = structuredClone(report.plan); blocked.blockers.push('missing'); rehash(blocked);
  assert.throws(() => verifyResumePlan(selected, blocked), /resume_plan_blocked/);
  const online = structuredClone(report.plan); online.network = 'osv'; rehash(online);
  assert.throws(() => verifyResumePlan(selected, online), /resume_offline_only/);
});

test('resume receipt links exact saved bytes and separate usages without an aggregate security decision', () => {
  const previous = fixture(); previous.engines[2].usage.calls = 5; previous.engines[2].usage.kind = 'unknown';
  const current = fixture(); current.runId = 'bbbbbbbb-1111-2222-3333-444444444444'; current.executionState = 'completed';
  const previousBytes = bytes(previous), currentBundle = bundle(current);
  const receipt = resumeReceipt(source(previous), currentBundle);
  assert.equal(receipt.previous.reportHash, hash(previousBytes)); assert.equal(receipt.current.reportHash, hash(currentBundle.json));
  assert.equal(receipt.previous.reportedCalls, 5); assert.equal(receipt.current.reportedCalls, 0);
  assert.equal(receipt.previous.costKind, 'unknown'); assert.equal(receipt.current.costKind, 'not_applicable');
  assert.ok(!Object.hasOwn(receipt, 'gate')); assert.ok(!Object.hasOwn(receipt, 'reportedCalls'));
  assert.deepEqual(bytes(previous), previousBytes);
  assert.throws(() => resumeReceipt(source(previous), bundle(previous)), /resume_run_identity_conflict/);
});

test('resume source I/O rejects in-target paths, links, non-files, oversized bytes, and relative inputs', async () => {
  const base = await mkdtemp(path.join(tmpdir(), 'scanmux-resume-test-'));
  test.after(() => removeTempDir(base));
  const root = path.join(base, 'repo'); await mkdir(root);
  const report = fixture(root), original = bytes(report), input = path.join(base, 'report.json'), inside = path.join(root, 'report.json');
  await writeFile(input, original); await writeFile(inside, original);
  assert.equal((await readResumeSource(input, root, defaults)).previous.runId, report.runId);
  await assert.rejects(readResumeSource(inside, root, defaults), /path_inside_target/);
  await assert.rejects(readResumeSource(base, root, defaults), /file_limit/);
  await assert.rejects(readResumeSource(input, root, { ...defaults, maxOutputBytes: original.length - 1 }), /file_limit/);
  await assert.rejects(readResumeSource('report.json', root, defaults), /invalid_resume_path/);
  const alias = path.join(base, 'alias'); await symlink(root, alias, 'junction');
  await assert.rejects(readResumeSource(path.join(alias, 'report.json'), root, defaults), /linked_path/);
  assert.deepEqual(await readFile(input), original);
});

test('v3 resume keeps Trivy mandatory and reexecutes the full same plan in a new run', () => {
  const previous = fixture();
  previous.schema = 'scanmux.report/v3';
  previous.plan = { ...previous.plan, schema: 'scanmux.plan/v3', required: [...previous.plan.required, 'trivy'],
    trivy: { schema: 'scanmux.trivy-plan/v1', profile: 'embedded-config-v1', inputs: [] } };
  rehash(previous.plan);
  const selected = source(previous); verifyResumePlan(selected, previous.plan);
  assert.equal(selected.previous.missingEngineRecords, 1);
  const current = structuredClone(previous); current.runId = 'bbbbbbbb-1111-2222-3333-444444444444'; current.executionState = 'completed';
  current.engines.push({ ...emptyRun('trivy', { plan: current.plan, config: defaults, workspace: '', snapshot: '', signal: new AbortController().signal, secretsCleared: false }),
    coverage: 'unsupported', trivyCoverage: { state: 'unsupported', reason: 'no_recognized_config' } });
  const receipt = resumeReceipt(selected, bundle(current));
  assert.equal(receipt.scope, 'full_scan_new_run'); assert.equal(receipt.current.missingEngineRecords, 0);
  assert.equal(receipt.previous.missingEngineRecords, 1);
  const disabled = structuredClone(previous.plan); disabled.required.pop(); rehash(disabled);
  assert.throws(() => verifyResumePlan(selected, disabled), /resume_identity_mismatch/);
});
