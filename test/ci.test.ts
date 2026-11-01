import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { ciArguments, ciReceipt, evaluateCi, parseCiExpectation, parseCiReceipt, saveCiReceipt, checkCiFiles } from '../src/ci.ts';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { emptyRun } from '../src/engine-run.ts';
import { digest, hash } from '../src/safety.ts';
import { exitCodes } from '../src/policy.ts';
import type { Gate, Report } from '../src/model.ts';

const ciRun = '11111111-2222-3333-4444-555555555555';
function fixture(id = 'first') {
  const root = path.resolve('test', id);
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: hash(root), commit: 'a'.repeat(40), treeHash: 'b'.repeat(40),
    snapshotHash: 'c'.repeat(64), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: 'd'.repeat(64), network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  const report: Report = { schema: 'scanmux.report/v2', runId: id === 'first' ? 'aaaaaaaa-1111-2222-3333-444444444444' : 'bbbbbbbb-1111-2222-3333-444444444444', plan,
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', runner: { platform: 'fixture', node: 'fixture', isolation: 'local-static-only', imageDigest: null },
    executionState: 'completed', coverageState: 'complete', gate: 'PASS', exitCode: 0, reasons: [], integrityErrors: [],
    engines: plan.required.map(engine => ({ ...emptyRun(engine, { plan, config: defaults, workspace: '', snapshot: '', signal: new AbortController().signal, secretsCleared: true }), execution: 'completed', coverage: 'analyzed' })) };
  const expected = { id, targetRoot: root, repoId: plan.repoId, commit: plan.commit, policyHash: plan.policyHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash };
  const makeReceipt = () => ciReceipt({ report, json: JSON.stringify(report, null, 2) + '\n' }, ciRun, id);
  return { report, expected, makeReceipt };
}
function expectation(...jobs: ReturnType<typeof fixture>['expected'][]) { return { schema: 'scanmux.ci-expectation/v1', ciRun, jobs }; }

test('CI synthetic completion: two independent jobs with every fixed engine; no live AI claim', () => {
  const a = fixture(), b = fixture('second'), expected = expectation(a.expected, b.expected);
  const result = evaluateCi(expected, [b.makeReceipt(), a.makeReceipt()]);
  assert.equal(result.gate, 'PASS'); assert.equal(result.exitCode, 0);
  assert.deepEqual(result.jobs.map(row => row.id), ['first', 'second']);
  assert.ok(!JSON.stringify(result).includes(a.expected.targetRoot));
});
test('CI gate precedence preserves each original non-PASS and missing job cannot disappear', () => {
  const a = fixture(), b = fixture('second'), expected = expectation(a.expected, b.expected);
  const gates: Gate[] = ['PASS', 'REVIEW', 'INCOMPLETE', 'FAIL', 'ERROR'];
  for (const [i, left] of gates.entries()) for (const [j, right] of gates.entries()) {
    const x = a.makeReceipt(), y = b.makeReceipt(); x.gate = left; y.gate = right;
    const result = evaluateCi(expected, [x, y]); assert.equal(result.gate, gates[Math.max(i, j)]); assert.equal(result.exitCode, exitCodes[result.gate]);
  }
  assert.equal(evaluateCi(expected, []).gate, 'INCOMPLETE');
  for (const gate of gates) { const receipt = a.makeReceipt(); receipt.gate = gate; assert.equal(evaluateCi(expected, [receipt]).gate, gates[Math.max(gates.indexOf(gate), 2)]); }
});
test('CI all sibling engine omissions, states and coverage values refuse success', () => {
  const a = fixture(), expected = expectation(a.expected);
  for (let index = 0; index < 4; index++) {
    const missing = a.makeReceipt(); missing.engines.splice(index, 1); assert.equal(evaluateCi(expected, [missing]).gate, 'INCOMPLETE');
    for (const execution of ['not_started', 'cancelled', 'budget_exceeded', 'failed'] as const) {
      const receipt = a.makeReceipt(); receipt.engines[index].execution = execution;
      assert.equal(evaluateCi(expected, [receipt]).gate, execution === 'failed' ? 'ERROR' : 'INCOMPLETE');
    }
    for (const coverage of ['skipped', 'partial', 'unsupported'] as const) {
      const receipt = a.makeReceipt(); receipt.engines[index].coverage = coverage; assert.equal(evaluateCi(expected, [receipt]).gate, 'INCOMPLETE');
    }
  }
  for (const execution of ['not_started', 'cancelled', 'budget_exceeded', 'failed'] as const) {
    const receipt = a.makeReceipt(); receipt.executionState = execution; assert.notEqual(evaluateCi(expected, [receipt]).exitCode, 0);
  }
  const receipt = a.makeReceipt(); receipt.coverageState = 'incomplete'; assert.equal(evaluateCi(expected, [receipt]).gate, 'INCOMPLETE');
});
test('CI every run, commit, policy, scope and snapshot identity is matched to expectations', () => {
  const a = fixture(), expected = expectation(a.expected);
  for (const key of ['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash', 'ciRun'] as const) {
    const receipt = a.makeReceipt(); receipt[key] = receipt[key].replace(/[a-f0-9]/g, 'f');
    assert.equal(evaluateCi(expected, [receipt]).gate, 'ERROR', key);
  }
});
test('CI duplicate or excess jobs, repeated report identity and duplicate engines reject', () => {
  const a = fixture(), b = fixture('second'), x = a.makeReceipt(), y = b.makeReceipt();
  assert.throws(() => evaluateCi(expectation(a.expected), [x, x]));
  assert.throws(() => evaluateCi(expectation(a.expected), [x, y]));
  y.reportRunId = x.reportRunId; assert.throws(() => evaluateCi(expectation(a.expected, b.expected), [x, y]));
  x.engines.push({ ...x.engines[0] }); assert.throws(() => evaluateCi(expectation(a.expected), [x]));
  assert.throws(() => parseCiExpectation(expectation(a.expected, a.expected)));
  assert.throws(() => parseCiExpectation(expectation()));
});
test('CI closed schemas reject unknown fields, types, enums and identifiers', () => {
  const a = fixture();
  for (const field of ['schema', 'ciRun', 'jobId', 'reportRunId', 'reportHash', 'gate', 'executionState', 'coverageState', 'repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash']) {
    for (const bad of [null, {}, [], true, 0, '<private canary>']) assert.throws(() => parseCiReceipt({ ...a.makeReceipt(), [field]: bad }), field);
  }
  assert.throws(() => parseCiReceipt({ ...a.makeReceipt(), extra: 'private-canary-text' }));
  for (const key of ['engine', 'execution', 'coverage']) { const receipt: any = a.makeReceipt(); receipt.engines[0][key] = 'private-canary-text'; assert.throws(() => parseCiReceipt(receipt)); }
  for (const missing of ['planHash', 'snapshotHash', 'targetRoot']) { const expected: any = expectation(a.expected); delete expected.jobs[0][missing]; assert.throws(() => parseCiExpectation(expected)); }
  assert.throws(() => parseCiExpectation({ ...expectation(a.expected), extra: true }));
  assert.throws(() => parseCiExpectation(expectation({ ...a.expected, targetRoot: 'relative/target' })));
});
test('CI tags are all-or-none, closed and independent from source strings', () => {
  assert.equal(ciArguments(undefined, undefined), undefined); assert.deepEqual(ciArguments(ciRun, 'first'), { ciRun, jobId: 'first' });
  for (const pair of [[ciRun, undefined], [undefined, 'first'], [ciRun, '<script>'], ['anything', 'first']]) assert.throws(() => ciArguments(pair[0], pair[1]));
});
test('CI receipt hashes exact saved JSON bytes and excludes arbitrary report content', () => {
  const a = fixture(); a.report.reasons = ['private-canary-text'];
  const json = JSON.stringify(a.report, null, 2) + '\n', receipt = ciReceipt({ report: a.report, json }, ciRun, 'first');
  assert.equal(receipt.reportHash, hash(Buffer.from(json))); assert.ok(!JSON.stringify(receipt).includes('private-canary-text'));
  assert.ok(!JSON.stringify(receipt).includes(a.report.plan.root));
  assert.throws(() => ciReceipt({ report: a.report, json: '{}' }, ciRun, 'first'));
  a.report.plan.required.pop(); assert.throws(() => a.makeReceipt());
});
test('CI receipt saves exclusively after output check, preserves existing results on failure', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-ci-test-'));
  test.after(() => removeTempDir(root));
  const a = fixture();
  const json = JSON.stringify(a.report) + '\n', bundle = { report: a.report, json };
  await writeFile(path.join(root, 'report.json'), json);
  await assert.rejects(saveCiReceipt(bundle, ciRun, 'first', defaults, root, async () => { throw new Error('blocked'); }));
  await assert.rejects(readFile(path.join(root, 'ci-receipt.json')));
  const saved = await saveCiReceipt(bundle, ciRun, 'first', defaults, root, async payload => JSON.stringify(payload) + '\n');
  assert.deepEqual(JSON.parse(await readFile(saved.destination, 'utf8')), saved.receipt);
  await assert.rejects(saveCiReceipt(bundle, ciRun, 'first', defaults, root, async payload => JSON.stringify(payload)));
  assert.equal(await readFile(path.join(root, 'report.json'), 'utf8'), json);
});
test('CI file boundary rejects target-contained expectations and identity aliases before output tooling', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-ci-boundary-'));
  test.after(() => removeTempDir(root));
  const a = fixture();
  a.expected.targetRoot = root; a.expected.repoId = hash(root);
  const file = path.join(root, 'expected.json'); await writeFile(file, JSON.stringify(expectation(a.expected)));
  await assert.rejects(checkCiFiles(file, [], undefined, defaults), /ci_input_inside_target/);
  a.expected.repoId = 'f'.repeat(64); await writeFile(file, JSON.stringify(expectation(a.expected)));
  await assert.rejects(checkCiFiles(file, [], undefined, defaults), /ci_target_identity_mismatch/);
  await assert.rejects(checkCiFiles(file, [file], undefined, defaults), /invalid_ci_manifest/);
});
test('CI input budget applies to the whole collection and rejects invalid UTF-8 before output', async () => {
  const folder = await mkdtemp(path.join(tmpdir(), 'scanmux-ci-limit-'));
  test.after(() => removeTempDir(folder));
  const a = fixture();
  a.expected.targetRoot = path.join(folder, 'target');
  const { mkdir } = await import('node:fs/promises'); await mkdir(a.expected.targetRoot);
  a.expected.repoId = hash(a.expected.targetRoot);
  const expectedFile = path.join(folder, 'expected.json'), receiptFile = path.join(folder, 'receipt.json');
  const expected = JSON.stringify(expectation(a.expected)), receipt = JSON.stringify(a.makeReceipt());
  await writeFile(expectedFile, expected); await writeFile(receiptFile, receipt);
  await assert.rejects(checkCiFiles(expectedFile, [receiptFile], undefined, { ...defaults, maxOutputBytes: Buffer.byteLength(expected) + Buffer.byteLength(receipt) - 1 }), /file_limit/);
  await writeFile(receiptFile, Buffer.from([0xc0, 0xaf]));
  await assert.rejects(checkCiFiles(expectedFile, [receiptFile], undefined, defaults), /encoded data/);
});
