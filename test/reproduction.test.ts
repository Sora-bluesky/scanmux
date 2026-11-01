import test from 'node:test';
import assert from 'node:assert/strict';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { emptyRun } from '../src/engine-run.ts';
import { digest, hash } from '../src/safety.ts';
import type { Finding, Report } from '../src/model.ts';
import { admitVerification, assessVerification, guardTest, testIdentity, verificationDecision, verificationPolicy, matchesBinding,
  type Binding, type ProbeResult, type VerificationMode } from '../src/reproduction.ts';

const selection = { engine: 'codex-security' as const, fingerprint: 'f'.repeat(64) };
const runtime = { imageDigest: 'sha256:' + 'a'.repeat(64), profileSha256: 'b'.repeat(64), nodeVersion: '24.22.1', driverSha256: 'c'.repeat(64), assetsSha256: 'd'.repeat(64) };
const files = ['test.mjs', 'helper.mjs', 'fixture.json'].map(path => ({ path: 'tests/repro/' + path, mode: '100644' as const, bytes: 10, sha256: hash(path) }));
const identity = () => testIdentity('tests/repro', files, runtime);
const pair: VerificationMode = { kind: 'before_after', base: 'a'.repeat(40), head: 'b'.repeat(40) };
const present: ProbeResult = { kind: 'completed', outcome: 'reproduced' }, absent: ProbeResult = { kind: 'completed', outcome: 'not_reproduced' };
const missing: ProbeResult = { kind: 'environment_missing', reason: 'offline_dependency_missing' };
function report(evidenceState: 'candidate' | 'source_supported' = 'candidate', complete = true): Report {
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: '/repo/test', repoId: hash('/repo/test'),
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), files: [], snapshotHash: digest([]), dirty: false, exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest({ ...plan, planHash: '' });
  const finding: Finding = { ...selection, category: 'code', severity: 'critical', confidence: 'high', evidenceState, disposition: 'open', file: 'app.mjs', line: 1,
    title: 'Synthetic finding', originIds: [], fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' };
  const engines = plan.required.map(engine => {
    const run = emptyRun(engine, { plan, config: defaults, workspace: '/work', snapshot: '/work/snapshot', secretsCleared: true, signal: new AbortController().signal });
    run.execution = 'completed'; run.coverage = 'analyzed'; if (engine === selection.engine) run.findings.push(finding); return run;
  });
  if (!complete) engines.pop();
  const value: Report = { schema: 'scanmux.report/v2', runId: '11111111-1111-4111-8111-111111111111', plan, engines,
    startedAt: '2026-10-31T00:00:00.000Z', endedAt: '2026-10-31T00:00:00.000Z', runner: { platform: 'linux', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' },
    executionState: 'completed', coverageState: complete ? 'complete' : 'incomplete', gate: 'REVIEW', exitCode: 2, reasons: [], integrityErrors: [] };
  const { scope: _scope, ...assessment } = verificationPolicy(value, selection, null, false); Object.assign(value, assessment); return value;
}

test('missing environment preserves source evidence and all required checks and gate order', () => {
  for (const evidence of ['candidate', 'source_supported'] as const) for (const complete of [true, false]) for (const required of [true, false]) {
    const source = report(evidence, complete), original = JSON.stringify(source);
    const decision = verificationDecision({ kind: 'snapshot', requirement: required ? 'required' : 'supporting' }, { kind: 'not_checked', reason: 'environment_missing' }, missing);
    assert.equal(decision.kind, 'not_verified');
    const assessment = verificationPolicy(source, selection, null, required);
    const gate = evidence === 'source_supported' ? 'FAIL' : !complete || required ? 'INCOMPLETE' : 'REVIEW';
    assert.equal(assessment.gate, gate); assert.equal(assessment.exitCode, { FAIL: 1, REVIEW: 2, INCOMPLETE: 3 }[gate]);
    assert.equal(verificationPolicy(source, selection, null, required, ['integrity_error']).gate, 'ERROR');
    assert.equal(JSON.stringify(source), original);
  }
});

test('unchanged oracle and a positive before control are required for the exact scoped statement', () => {
  const guard = guardTest(identity(), identity());
  assert.deepEqual(verificationDecision(pair, guard, present, absent), { kind: 'same_test_no_longer_reproduces', statement: 'The same test no longer reproduces at head, with the test unchanged.' });
  for (const [before, after, reason] of [[absent, absent, 'before_not_reproduced'], [present, present, 'still_reproduces'], [present, missing, 'environment_missing'],
    [missing, undefined, 'environment_missing'], [present, { kind: 'failed', reason: 'invalid_observation' }, 'test_failed']] as const) {
    assert.deepEqual(verificationDecision(pair, guard, before, after), { kind: 'not_verified', reason });
  }
  for (const requirement of ['supporting', 'required'] as const) {
    assert.deepEqual(verificationDecision({ kind: 'snapshot', requirement }, guardTest(identity()), absent), { kind: 'not_reproduced' });
  }
});

test('a verification with no attempt cannot inherit a passing source gate in any mode', () => {
  const original = report(); original.engines[2].findings[0].severity = 'medium';
  const { scope: _scope, ...assessment } = verificationPolicy(original, selection, null, false); Object.assign(original, assessment);
  assert.equal(original.gate, 'PASS');
  const bytes = Buffer.from(JSON.stringify(original));
  for (const mode of [{ kind: 'snapshot', requirement: 'supporting' }, { kind: 'snapshot', requirement: 'required' }, pair] as const) {
    const source = admitVerification(original.plan.root, bytes, { reportPath: '/saved/report.json', finding: selection, testDirectory: 'tests/repro', mode });
    const result = assessVerification(source, { kind: 'not_checked', reason: 'job_failed' }, null);
    assert.deepEqual(result.verification, { kind: 'not_verified', reason: 'test_failed' });
    assert.equal(result.assessment.gate, 'INCOMPLETE'); assert.equal(result.assessment.exitCode, 3);
    assert.equal(JSON.stringify(source.report), bytes.toString());
  }
});

test('directory identity covers every path, mode, byte, helper, fixture and pinned runtime, independent of commit', () => {
  assert.deepEqual(identity(), testIdentity('tests/repro', [...files].reverse(), runtime));
  const changes = [files.slice(1), [...files, { ...files[0], path: 'tests/repro/extra.mjs' }], files.map((f, i) => i ? f : { ...f, mode: '100755' as const }),
    files.map((f, i) => i === 1 ? { ...f, sha256: hash('weakened helper') } : f), files.map((f, i) => i === 2 ? { ...f, bytes: 11 } : f),
    files.map((f, i) => i === 1 ? { ...f, path: 'tests/repro/moved.mjs' } : f)];
  for (const changed of changes) {
    let guard; try { guard = guardTest(identity(), testIdentity('tests/repro', changed, runtime)); } catch { continue; }
    assert.equal(guard.kind, 'rejected'); assert.equal(verificationDecision(pair, guard, present, absent).kind, 'not_verified');
  }
  for (const key of ['imageDigest', 'profileSha256', 'nodeVersion', 'driverSha256', 'assetsSha256'] as const) {
    const changed = { ...runtime, [key]: key === 'nodeVersion' ? '24.23.0' : key === 'imageDigest' ? 'sha256:' + 'e'.repeat(64) : 'e'.repeat(64) };
    assert.equal(guardTest(identity(), testIdentity('tests/repro', files, changed)).kind, 'rejected');
  }
  for (const directory of ['../tests', '/tests', 'tests\\repro', 'tests/.git', 'tests//repro']) assert.throws(() => testIdentity(directory, files, runtime));
  assert.throws(() => testIdentity('tests/repro', [...files, { ...files[0], path: 'tests/repro/TEST.mjs' }], runtime));
});

test('binding rejects cross-snapshot replay, wrong finding/report/test; execution plan context may differ', () => {
  const binding: Binding = { snapshot: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), snapshotHash: 'c'.repeat(64) }, executionPlanHash: 'd'.repeat(64),
    sourceSnapshot: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), snapshotHash: 'c'.repeat(64) }, side: 'before', finding: selection, sourceReportSha256: 'e'.repeat(64), testId: identity().testId };
  assert.equal(matchesBinding(binding, { ...binding, executionPlanHash: '9'.repeat(64) }), true);
  for (const changed of [{ ...binding, snapshot: { ...binding.snapshot, commit: 'f'.repeat(40) } }, { ...binding, snapshot: { ...binding.snapshot, tree: 'f'.repeat(40) } },
    { ...binding, snapshot: { ...binding.snapshot, snapshotHash: 'f'.repeat(64) } }, { ...binding, finding: { ...selection, fingerprint: 'e'.repeat(64) } },
    { ...binding, finding: { ...selection, engine: 'gitleaks' as const } }, { ...binding, sourceReportSha256: 'f'.repeat(64) }, { ...binding, testId: 'f'.repeat(64) },
    { ...binding, side: 'after' as const }, { ...binding, sourceSnapshot: { ...binding.sourceSnapshot, tree: 'f'.repeat(40) } }]) {
    assert.equal(matchesBinding(binding, changed), false);
  }
});

test('admission binds original report, full commits, original root and one non-Trivy finding', () => {
  const source = report(), bytes = Buffer.from(JSON.stringify(source)), request = { reportPath: '/saved/report.json', finding: selection, testDirectory: 'tests/repro', mode: pair };
  assert.equal(admitVerification(source.plan.root, bytes, request).sourceReportSha256, hash(bytes));
  for (const changed of [{ ...request, finding: { ...selection, fingerprint: 'a'.repeat(64) } }, { ...request, testDirectory: '../test' },
    { ...request, mode: { ...pair, base: 'short' } }, { ...request, mode: { ...pair, head: pair.base } }]) assert.throws(() => admitVerification(source.plan.root, bytes, changed));
  assert.throws(() => admitVerification('/other', bytes, request));
  for (const modify of [(r: Report) => { r.engines[2].findings.push(r.engines[2].findings[0]); }, (r: Report) => { r.plan.snapshotHash = 'a'.repeat(64); },
    (r: Report) => { r.engines[2].findings[0].evidenceState = 'runtime_reproduced'; }, (r: Report) => { r.plan.planHash = 'b'.repeat(64); }]) {
    const altered = structuredClone(source); modify(altered); assert.throws(() => admitVerification(source.plan.root, Buffer.from(JSON.stringify(altered)), request));
  }
});
