import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { commitPair, treeEntries, changedEntries, comparisonSummary } from '../src/comparison.ts';
import { defaults } from '../src/config.ts';
import { buildPlan } from '../src/repository.ts';
import { scan } from '../src/controller.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { digest } from '../src/safety.ts';
import { renderHtmlReport } from '../src/html-report.ts';
import { renderSarifReports } from '../src/sarif-report.ts';
import type { Comparison, Plan, Report } from '../src/model.ts';

const base = 'a'.repeat(40), head = 'b'.repeat(40), tree = 'c'.repeat(40);
const row = (name: string, oid = base, mode = '100644', bytes = 1) => `${mode} ${mode === '160000' ? 'commit' : 'blob'} ${oid} ${mode === '160000' ? '-' : bytes}\t${name}\0`;
const entries = (text: string) => [...treeEntries(Buffer.from(text), defaults)];
const comparison = (): Comparison => ({ schema: 'scanmux.comparison/v1', baseCommit: base, headCommit: head,
  baseTree: base, headTree: tree, scope: 'full_head', baseline: 'not_compared', changes: [] });
function plan(): Plan {
  const result: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, repoId: 'fixture', root: '/synthetic',
    commit: head, treeHash: tree, snapshotHash: 'd'.repeat(64), dirty: false, files: [], exclusions: [], blockers: [],
    languages: [], lockfiles: ['package-lock.json'], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'],
    policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [],
    cost: { kind: 'not_applicable', aiCalls: 0 }, comparison: comparison() };
  result.planHash = digest({ ...result, planHash: '' }); return result;
}

test('comparison requires both complete commit SHAs, never refs or Git options', async () => {
  assert.deepEqual(commitPair(base, head), { base, head });
  assert.equal(commitPair(undefined, undefined), undefined);
  for (const pair of [[base, undefined], [undefined, head], ['', head], ['HEAD', head], [base.slice(0, 8), head], ['--all', head],
    [base.toUpperCase(), head], [base + '\n', head], [base, head + '^{tree}'], [null, head]]) assert.throws(() => commitPair(pair[0], pair[1]));
  await assert.rejects(buildPlan('/not-read', defaults, '/not-used', undefined, { base: 'HEAD', head }), { code: 'invalid_comparison_sha' });
});

test('tree comparison retains add/delete/modify/mode and records rename as deletion plus addition', () => {
  const before = entries(row('delete.ts') + row('old-name.ts') + row('modify.ts') + row('mode.sh') + row('unchanged.ts'));
  const after = entries(row('add.ts') + row('new-name.ts') + row('modify.ts', head) + row('mode.sh', base, '100755') + row('unchanged.ts'));
  assert.deepEqual(changedEntries(before, after), [
    { path: 'add.ts', kind: 'added' }, { path: 'delete.ts', kind: 'deleted' }, { path: 'mode.sh', kind: 'mode_changed' },
    { path: 'modify.ts', kind: 'modified' }, { path: 'new-name.ts', kind: 'added' }, { path: 'old-name.ts', kind: 'deleted' },
  ]);
  assert.deepEqual(changedEntries(before, before), []);
  assert.deepEqual(changedEntries(entries(row('link', base, '120000')), entries(row('link'))), [{ path: 'link', kind: 'mode_changed' }]);
  assert.deepEqual(changedEntries(entries(row('submodule', base, '160000')), []), [{ path: 'submodule', kind: 'deleted' }]);
});

test('both tree inputs reject ambiguous paths and preserve bounds for excluded files', () => {
  for (const name of ['../outside', '.git/config', 'x\\y', 'aux', 'file:stream', 'a/../b', 'path\nline']) assert.throws(() => entries(row(name)));
  for (const text of [row('A.ts') + row('a.ts'), row('Dir/a.ts') + row('dir/b.ts'), row('é.ts') + row('e\u0301.ts'), 'malformed\0']) assert.throws(() => entries(text));
  assert.throws(() => [...treeEntries(Buffer.from([0xff]), defaults)]);
  const iterator = treeEntries(Buffer.from(row('first.ts') + row('second.ts')), { ...defaults, maxFiles: 1 });
  assert.equal(iterator.next().value?.path, 'first.ts'); assert.throws(() => iterator.next(), { code: 'snapshot_file_limit' });
  assert.throws(() => [...treeEntries(Buffer.from(row('large.ts', base, '100644', 2)), { ...defaults, maxFileBytes: 1 })], { code: 'snapshot_byte_limit' });
  assert.throws(() => [...treeEntries(Buffer.from(row('a.ts') + row('b.ts')), { ...defaults, maxSnapshotBytes: 1 })], { code: 'snapshot_byte_limit' });
  assert.throws(() => [...treeEntries(Buffer.from(row('link1', base, '120000') + row('link2', base, '120000')), { ...defaults, maxFiles: 1 })], { code: 'snapshot_file_limit' });
});

test('comparison binds the head and tree; an empty change list does not erase dependency scope', () => {
  const accepted = plan();
  assert.equal(comparisonSummary(accepted)?.changedPaths, 0);
  assert.deepEqual(accepted.lockfiles, ['package-lock.json']);
  assert.ok(accepted.required.includes('osv'));
  const old = { ...accepted }; delete old.comparison;
  assert.equal(comparisonSummary(old), null);
  for (const change of [{ headCommit: base }, { headTree: base }, { baseCommit: 'HEAD' }, { baseTree: 'invalid' },
    { baseline: 'clean' }, { scope: 'changed_lines' }, { changes: [{ path: '../escape', kind: 'added' }] },
    { changes: [{ path: 'a.ts', kind: 'deleted' }, { path: 'a.ts', kind: 'added' }] }]) {
    assert.throws(() => comparisonSummary({ ...accepted, comparison: { ...accepted.comparison, ...change } as Comparison }));
  }
});

test('controller rejects changed comparison bytes and a rehashed mixed-head plan before invoking adapters', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-comparison-test-'));
  try {
    const changed = plan(); changed.comparison!.baseCommit = head;
    const tampered = await scan(changed, defaults, workspace, new AbortController().signal, []);
    assert.equal(tampered.gate, 'ERROR'); assert.ok(tampered.integrityErrors.includes('plan_integrity'));
    changed.comparison!.headCommit = base; changed.planHash = digest({ ...changed, planHash: '' });
    const mixed = await scan(changed, defaults, workspace, new AbortController().signal, []);
    assert.equal(mixed.gate, 'ERROR'); assert.ok(mixed.integrityErrors.includes('comparison_plan_mismatch'));
  } finally { await rm(workspace, { recursive: true, force: true }); }
});

test('JSON, HTML and SARIF identify fixed SHAs, full-head coverage and no baseline comparison', () => {
  const report: Report = { schema: 'scanmux.report/v2', runId: '12345678-1234-1234-1234-123456789012', plan: plan(),
    runner: { platform: 'synthetic', node: '24.0.0', imageDigest: null, isolation: 'local-static-only' },
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', engines: [],
    executionState: 'completed', coverageState: 'incomplete', gate: 'INCOMPLETE', exitCode: 3, reasons: [], integrityErrors: [] };
  const html = renderHtmlReport(report);
  assert.ok(html.includes(base) && html.includes(head)); assert.ok(html.includes('head全体'));
  assert.ok(html.includes('修正済み判定は行っていません')); assert.ok(!html.includes('/synthetic'));
  const sarif = JSON.parse(renderSarifReports(report, defaults.maxOutputBytes)[0].text);
  assert.deepEqual(sarif.runs[0].properties.comparison, comparisonSummary(report.plan));
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, false);
  assert.deepEqual(JSON.parse(JSON.stringify(report)).plan.comparison, report.plan.comparison);
});
