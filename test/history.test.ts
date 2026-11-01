import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { summarizeHistory, readHistoryFiles } from '../src/history.ts';
import { hash } from '../src/safety.ts';
import { defaults } from '../src/config.ts';

function fixture(root = path.resolve('test')) {
  return { schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555', startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01.000Z',
    gate: 'PASS', executionState: 'completed', coverageState: 'complete', integrityErrors: [],
    plan: { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64), planHash: 'c'.repeat(64), snapshotHash: 'd'.repeat(64),
      required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], blockers: [], exclusions: [] },
    engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed',
      usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) };
}
const bytes = (input: unknown) => Buffer.from(JSON.stringify(input));
const summary = (input: unknown) => summarizeHistory([bytes(input)]).summary;

test('history keeps separate runs/SHA/policy and deduplicates only exact saved bytes', () => {
  const a = fixture(), b = fixture(); b.runId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; b.plan.commit = 'f'.repeat(40); b.plan.policyHash = 'e'.repeat(64);
  a.engines[2].usage.calls = 3; a.engines[2].usage.kind = 'unknown'; b.engines[2].usage.calls = 5;
  const before = bytes(a), result = summarizeHistory([before, bytes(b), before]).summary;
  assert.equal(result.runs.length, 2); assert.equal(result.duplicateInputs, 1); assert.equal(result.reportedCalls, 8);
  assert.equal(result.runs[0].commit, a.plan.commit); assert.equal(result.runs[1].policyHash, b.plan.policyHash);
  assert.equal(result.cost, null); assert.equal(result.costKind, 'unknown'); assert.ok(!Object.hasOwn(result, 'gate')); assert.deepEqual(bytes(a), before);
  assert.throws(() => summarizeHistory([before, Buffer.from(JSON.stringify(a, null, 2))]), /history_run_identity_conflict/);
  const changed = structuredClone(a); changed.gate = 'FAIL'; assert.throws(() => summarizeHistory([before, bytes(changed)]), /history_run_identity_conflict/);
});
test('history preserves unknown cost and recorded zero separately from missing engine records', () => {
  const input = fixture(); input.engines[2].usage.kind = 'unknown';
  assert.equal(summary(input).reportedCalls, 0); assert.equal(summary(input).costKind, 'unknown'); assert.equal(summary(input).runs[0].engines[2].recordState, 'recorded');
  input.engines.splice(2, 1);
  const result = summary(input), missing = result.runs[0].engines[2];
  assert.equal(result.reportedCalls, 0); assert.equal(result.missingEngineRecords, 1); assert.equal(missing.calls, null); assert.equal(missing.recordState, 'missing');
  assert.equal(missing.costKind, 'unrecorded'); assert.equal(result.runs[0].recordedGate, 'PASS'); assert.equal(result.runs[0].completion, 'incomplete');
  assert.ok(result.runs[0].reasons.includes('recorded_pass_conflicts_with_completion'));
});
test('history never changes recorded gates and exposes every incomplete completion sibling', () => {
  for (const gate of ['PASS', 'FAIL', 'INCOMPLETE', 'REVIEW', 'ERROR']) { const input = fixture(); input.gate = gate; assert.equal(summary(input).runs[0].recordedGate, gate); }
  const mutations = [
    (r: any) => { r.executionState = 'cancelled'; }, (r: any) => { r.coverageState = 'incomplete'; },
    (r: any) => { r.plan.required.pop(); }, (r: any) => { r.plan.blockers = ['private-canary']; },
    (r: any) => { r.plan.exclusions = [{ path: 'private-canary' }]; }, (r: any) => { r.integrityErrors = ['private-canary']; },
  ];
  for (let i = 0; i < 4; i++) {
    mutations.push(r => { r.engines.splice(i, 1); });
    for (const execution of ['failed', 'not_started', 'cancelled', 'budget_exceeded']) mutations.push(r => { r.engines[i].execution = execution; });
    for (const coverage of ['partial', 'unsupported', 'skipped']) mutations.push(r => { r.engines[i].coverage = coverage; });
  }
  for (const mutate of mutations) {
    const input = fixture(); mutate(input); const result = summary(input);
    assert.equal(result.runs[0].recordedGate, 'PASS'); assert.equal(result.runs[0].completion, 'incomplete');
    assert.ok(!JSON.stringify(result).includes('private-canary'));
  }
});
test('history rejects absent, malformed, duplicate and overflowing usage rather than inventing zero', () => {
  for (const value of [undefined, null, '0', -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    const input: any = fixture(); input.engines[0].usage.calls = value; assert.throws(() => summary(input), /invalid_history_usage/);
  }
  const duplicate = fixture(); duplicate.engines.push(structuredClone(duplicate.engines[0])); assert.throws(() => summary(duplicate));
  const overflow = fixture(); overflow.engines[0].usage.calls = Number.MAX_SAFE_INTEGER; overflow.engines[1].usage.calls = 1; assert.throws(() => summary(overflow));
  overflow.engines[1].usage.calls = 0; const other = fixture(); other.runId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'; other.engines[0].usage.calls = 1;
  assert.throws(() => summarizeHistory([bytes(overflow), bytes(other)]));
  for (const mutation of [(r: any) => { r.engines[0].usage.cost = 0; }, (r: any) => { r.engines[0].usage.kind = 'free'; }, (r: any) => { r.engines[0].usage.allowance = 'available'; }]) {
    const input = fixture(); mutation(input); assert.throws(() => summary(input));
  }
});
test('history rejects invalid schema, identity, timestamp, enum and UTF-8 fields', () => {
  const mutations = [(r: any) => { r.schema = 'other'; }, (r: any) => { r.runId = 'arbitrary-text'; }, (r: any) => { r.plan.repoId = 'invalid'; },
    (r: any) => { r.plan.commit = 'main'; }, (r: any) => { r.plan.required.push('other'); }, (r: any) => { r.plan.required.push('osv'); },
    (r: any) => { r.gate = 'unknown'; }, (r: any) => { r.engines[0].coverage = 'unknown'; }, (r: any) => { r.plan.root = 'relative'; },
    (r: any) => { r.startedAt = '2026-02-29T00:00:00Z'; }, (r: any) => { r.endedAt = '2026-10-21T00:00:00Z'; }, (r: any) => { r.startedAt = 'not-time'; }];
  for (const mutate of mutations) { const input = fixture(); mutate(input); assert.throws(() => summary(input)); }
  assert.throws(() => summarizeHistory([Buffer.from([0xc0, 0xaf])])); assert.throws(() => summarizeHistory([]));
  const blocked: any = fixture(); blocked.plan.commit = null; blocked.gate = 'INCOMPLETE'; blocked.coverageState = 'incomplete';
  assert.equal(summary(blocked).runs[0].commit, null);
});
test('history projects no raw source, finding, arbitrary text or local root', () => {
  const input: any = fixture(); input.untrusted = 'private-canary'; input.engines[0].findings = [{ title: 'private-canary', file: 'private-canary' }];
  input.engines[0].errors = ['private-canary'];
  const output = JSON.stringify(summary(input)); assert.ok(!output.includes('private-canary')); assert.ok(!output.includes(input.plan.root));
  assert.equal(summary(input).runs[0].reportHash, hash(bytes(input)));
});
test('history file admission enforces target boundary, physical identity and aggregate bytes', async () => {
  const folder = await mkdtemp(path.join(tmpdir(), 'scanmux-history-test-'));
  test.after(() => removeTempDir(folder));
  const target = path.join(folder, 'target'); await mkdir(target);
  const input = fixture(target), inside = path.join(target, 'report.json'), outside = path.join(folder, 'report.json'), raw = bytes(input);
  await writeFile(inside, raw); await writeFile(outside, raw);
  await assert.rejects(readHistoryFiles([inside], undefined, defaults), /history_input_inside_target/);
  await assert.rejects(readHistoryFiles([outside, outside], undefined, { ...defaults, maxOutputBytes: raw.length * 2 - 1 }), /file_limit/);
  input.plan.repoId = 'f'.repeat(64); await writeFile(outside, bytes(input));
  await assert.rejects(readHistoryFiles([outside], undefined, defaults), /history_target_identity_mismatch/);
  assert.deepEqual(await readFile(inside), raw);
});
