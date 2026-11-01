import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, mkdir, writeFile, readFile, symlink } from 'node:fs/promises';
import { evaluateDispositions, readDispositions } from '../src/dispositions.ts';
import { defaults } from '../src/config.ts';
import { hash } from '../src/safety.ts';

const now = new Date('2026-10-23T00:00:00.000Z');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value));
function fixture(root = path.resolve('test')) {
  return { schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555',
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', gate: 'INCOMPLETE',
    executionState: 'completed', coverageState: 'incomplete', integrityErrors: [],
    plan: { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64),
      planHash: 'c'.repeat(64), snapshotHash: 'd'.repeat(64), required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], blockers: [], exclusions: [] },
    engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed',
      findings: engine === 'osv' ? [{ engine, fingerprint: 'e'.repeat(64), title: 'private-source-title', file: 'private-path' }] : [],
      usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) };
}
function entry(report = fixture()) {
  return { reportHash: hash(bytes(report)), engine: 'osv', fingerprint: 'e'.repeat(64), decision: 'risk_accepted',
    reason: 'Synthetic test only; not an actual risk acceptance.', reviewer: 'Fixture reviewer',
    reviewedAt: '2026-10-22T10:00:00Z', expiresAt: '2026-10-24T00:00:00Z' };
}
const manifest = (entries: unknown[]) => bytes({ schema: 'scanmux.dispositions/v1', entries });
const summary = (report: unknown, entries?: unknown[]) => evaluateDispositions(bytes(report), entries === undefined ? undefined : manifest(entries), now).summary;

test('dispositions lists all current findings as open without exposing source text or changing the gate', () => {
  const report = fixture(), result = summary(report);
  assert.equal(result.rows.length, 1); assert.equal(result.rows[0].state, 'open'); assert.equal(result.rows[0].decision, null);
  assert.equal(result.original.recordedGate, 'INCOMPLETE'); assert.equal(result.original.completion, 'incomplete');
  assert.equal(result.gateChanged, false); assert.equal(result.automaticCarryover, false); assert.ok(!Object.hasOwn(result, 'gate'));
  assert.ok(!JSON.stringify(result).includes('private-source-title')); assert.ok(!JSON.stringify(result).includes('private-path'));
  assert.equal(result.original.reportHash, hash(bytes(report)));
});

test('all human decision kinds remain data and preserve FAIL and incomplete coverage', () => {
  for (const kind of ['false_positive', 'risk_accepted', 'out_of_scope']) {
    const report = fixture(); report.gate = 'FAIL'; const decision = entry(report); decision.decision = kind;
    const before = bytes(report), result = summary(report, [decision]);
    assert.equal(result.rows[0].state, 'current'); assert.deepEqual(result.rows[0].decision, decision);
    assert.equal(result.original.recordedGate, 'FAIL'); assert.equal(result.original.completion, 'incomplete');
    assert.deepEqual(bytes(report), before); assert.equal(result.reviewerIdentity, 'declared_not_authenticated');
  }
});

test('expiry uses one host time and expires at the exact boundary', () => {
  for (const [expiresAt, state] of [['2026-10-23T00:00:00.001Z', 'current'], ['2026-10-23T00:00:00Z', 'expired'], ['2026-10-22T23:59:59.999Z', 'expired']]) {
    const decision = entry(); decision.expiresAt = expiresAt;
    const result = summary(fixture(), [decision]); assert.equal(result.rows[0].state, state);
    assert.deepEqual(result.rows[0].reasons, state === 'expired' ? ['expired'] : []); assert.equal(result.evaluatedAt, now.toISOString());
  }
});

test('changed bytes and missing findings retain all reasons and never carry a decision to the current finding', () => {
  const report = fixture(), decision = entry(report); decision.reportHash = 'f'.repeat(64); decision.expiresAt = now.toISOString();
  let result = summary(report, [decision]);
  assert.deepEqual(result.rows.map(row => row.state), ['open', 'reconfirmation_required']);
  assert.deepEqual(result.rows[1].reasons, ['report_changed', 'expired']);
  decision.fingerprint = 'a'.repeat(64); result = summary(report, [decision]);
  assert.deepEqual(result.rows[1].reasons, ['report_changed', 'finding_missing', 'expired']);
  decision.reportHash = hash(bytes(report)); result = summary(report, [decision]);
  assert.deepEqual(result.rows[1].reasons, ['finding_missing', 'expired']);
  const fresh = entry(report), formatted = Buffer.from(JSON.stringify(report, null, 2));
  const reformatted = evaluateDispositions(formatted, manifest([fresh]), now).summary;
  assert.deepEqual(reformatted.rows.map(row => row.state), ['open', 'reconfirmation_required']);
  for (const mutate of [
    (r: ReturnType<typeof fixture>) => { r.plan.commit = 'f'.repeat(40); },
    (r: ReturnType<typeof fixture>) => { r.engines[1].findings[0].title = 'changed evidence'; },
    (r: ReturnType<typeof fixture>) => { r.plan.policyHash = 'f'.repeat(64); },
  ]) { const changed = fixture(); mutate(changed); assert.equal(summary(changed, [fresh]).rows[1].state, 'reconfirmation_required'); }
});

test('dispositions rejects missing fields, blank free text, invalid times, and duplicate finding keys', () => {
  for (const field of Object.keys(entry())) { const decision: any = entry(); delete decision[field]; assert.throws(() => summary(fixture(), [decision])); }
  for (const field of ['reason', 'reviewer']) { const decision: any = entry(); decision[field] = ' \r\n\t '; assert.throws(() => summary(fixture(), [decision]), /invalid_disposition/); }
  for (const value of ['2026-02-29T00:00:00Z', '2026-10-24', '2026-10-24T09:00:00+09:00']) {
    const decision = entry(); decision.expiresAt = value; assert.throws(() => summary(fixture(), [decision]), /invalid_disposition_time/);
  }
  const future = entry(); future.reviewedAt = '2026-10-23T00:00:00.001Z'; assert.throws(() => summary(fixture(), [future]), /invalid_disposition_time/);
  const reversed = entry(); reversed.expiresAt = reversed.reviewedAt; assert.throws(() => summary(fixture(), [reversed]), /invalid_disposition_time/);
  assert.throws(() => summary(fixture(), [entry(), entry()]), /duplicate_disposition/);
  const wrong: any = entry(); wrong.decision = 'fixed_verified'; assert.throws(() => summary(fixture(), [wrong]), /invalid_disposition/);
});

test('dispositions rejects malformed finding collections, mismatched engines, duplicate identities and invalid UTF-8', () => {
  for (const value of [null, {}, 'findings']) { const report: any = fixture(); report.engines[1].findings = value; assert.throws(() => summary(report), /invalid_report/); }
  const wrong = fixture(); wrong.engines[1].findings[0].engine = 'gitleaks'; assert.throws(() => summary(wrong), /invalid_disposition_finding/);
  const duplicate = fixture(); duplicate.engines[1].findings.push(duplicate.engines[1].findings[0]); assert.throws(() => summary(duplicate), /invalid_disposition_finding/);
  assert.throws(() => evaluateDispositions(bytes(fixture()), Buffer.from([0xff]), now));
});

test('disposition file reads enforce combined input size, canonical paths, and target boundaries before output', async () => {
  const base = await mkdtemp(path.join(tmpdir(), 'scanmux-disposition-test-'));
  test.after(() => removeTempDir(base));
  const root = path.join(base, 'repo'); await mkdir(root);
  const report = fixture(root), original = bytes(report), decisions = manifest([entry(report)]);
  const input = path.join(base, 'report.json'), inside = path.join(root, 'decisions.json'), outside = path.join(base, 'decisions.json');
  await writeFile(input, original); await writeFile(inside, decisions); await writeFile(outside, decisions);
  await assert.rejects(readDispositions(input, inside, undefined, defaults), /disposition_input_inside_target/);
  await assert.rejects(readDispositions(input, outside, undefined, { ...defaults, maxOutputBytes: original.length + decisions.length - 1 }), /file_limit/);
  await assert.rejects(readDispositions('report.json', undefined, undefined, defaults), /invalid_disposition_path/);
  const alias = path.join(base, 'alias'); await symlink(root, alias, 'junction');
  await assert.rejects(readDispositions(input, path.join(alias, 'decisions.json'), undefined, defaults), /linked_path/);
  assert.deepEqual(await readFile(input), original); assert.deepEqual(await readFile(inside), decisions);
});
