import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { parseBatchManifest, prepareBatch, runBatchJobs, aggregateBatch, type BatchJob, type PreparedBatch } from '../src/batch.ts';
import { defaults } from '../src/config.ts';
import { SafeError } from '../src/safety.ts';
import type { Gate } from '../src/model.ts';
import { prepareGitHubPlan } from '../src/repository.ts';

const root = path.resolve('.local/synthetic-one'), other = path.resolve('.local/synthetic-two');
const prepared = (): PreparedBatch => ({ manifestHash: 'a'.repeat(64), localRoots: [root, other], controlFiles: [], targets: [{ id: 'one', path: root }, { id: 'two', path: other }, { id: 'three', url: 'https://github.com/example/fixture' }] });
function finish(job: BatchJob, gate: Gate = 'INCOMPLETE') {
  job.state = 'finished'; job.planningComplete = true; job.gate = gate;
  job.repoId = job.id; job.commit = 'a'.repeat(40); job.planHash = 'b'.repeat(64);
  job.outputs.report = '/synthetic/' + job.id + '/report.json';
}

test('manifest accepts only explicit local or public GitHub targets and paired local SHAs', () => {
  const targets = parseBatchManifest({ schema: 1, repositories: [{ id: 'one', path: root, base: 'a'.repeat(40), head: 'b'.repeat(40) }, { id: 'two', url: 'https://github.com/example/fixture.git' }] });
  assert.deepEqual(targets[0].comparison, { base: 'a'.repeat(40), head: 'b'.repeat(40) });
  assert.equal(targets[1].url, 'https://github.com/example/fixture');
  for (const raw of [null, {}, { schema: 1, repositories: [] }, { schema: 1, repositories: [], extra: true },
    ...[{ id: 'bad/id', path: root }, { id: 'one', path: 'relative' }, { id: 'one', path: root, base: 'a'.repeat(40) },
      { id: 'one', url: 'https://github.com/example/fixture', head: 'b'.repeat(40) }, { id: 'one', url: 'https://example.invalid/repo' },
      { id: 'one', url: 'https://github.com/example/fixture?secret=value' }, { id: 'one', path: root, command: 'execute' },
      { id: 'one', path: root, url: 'https://github.com/example/fixture' }].map(target => ({ schema: 1, repositories: [target] }))]) assert.throws(() => parseBatchManifest(raw));
  for (const repositories of [[{ id: 'one', path: root }, { id: 'ONE', path: other }],
    [{ id: 'one', url: 'https://github.com/example/fixture.git' }, { id: 'two', url: 'https://github.com/EXAMPLE/FIXTURE' }]]) assert.throws(() => parseBatchManifest({ schema: 1, repositories }));
});

test('preflight validates every root and control path before any job can start', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-batch-test-'));
  test.after(() => removeTempDir(workspace));
  const a = path.join(workspace, 'one'), b = path.join(workspace, 'two'), manifest = path.join(workspace, 'list.json');
  await mkdir(a); await mkdir(b); await mkdir(path.join(a, 'nested'));
  const write = (repositories: unknown[], destination = manifest) => writeFile(destination, JSON.stringify({ schema: 1, repositories }));
  try {
    await write([{ id: 'one', path: a }, { id: 'two', path: b }]);
    const accepted = await prepareBatch(manifest, undefined, defaults);
    assert.deepEqual(accepted.localRoots, [a, b]); assert.match(accepted.manifestHash, /^[a-f0-9]{64}$/);
    for (const target of [a, path.join(a, 'nested')]) {
      await write([{ id: 'one', path: a }, { id: 'two', path: target }]);
      await assert.rejects(prepareBatch(manifest, undefined, defaults), { code: 'overlapping_batch_targets' });
    }
    await write([{ id: 'one', path: a }], path.join(a, 'manifest.json'));
    await assert.rejects(prepareBatch(path.join(a, 'manifest.json'), undefined, defaults), { code: 'batch_path_inside_target' });
    await write([{ id: 'one', path: a }, { id: 'two', path: b }]);
    const executable = path.join(b, 'fake-engine.exe'); await writeFile(executable, 'not executable');
    const unsafe = { ...defaults, tools: { git: { path: executable, sha256: '0'.repeat(64), version: '1.0.0' } } };
    await assert.rejects(prepareBatch(manifest, undefined, unsafe), { code: 'batch_path_inside_target' });
    await assert.rejects(prepareBatch(manifest, undefined, { ...defaults, osvDatabase: b }), { code: 'batch_path_inside_target' });
    const config = path.join(a, 'config.json'); await writeFile(config, '{"schema":1}');
    await assert.rejects(prepareBatch(manifest, config, defaults), { code: 'batch_path_inside_target' });
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('jobs execute serially, preserve each result identity and retain earlier output across a later failure', async () => {
  let active = 0, maximum = 0;
  const order: string[] = [];
  const summary = await runBatchJobs(prepared(), defaults, 'scan', new AbortController().signal, async (target, job) => {
    active++; maximum = Math.max(maximum, active); order.push(target.id);
    await setTimeout(1); active--;
    if (target.id === 'two') throw new SafeError('scanner_exit_failure');
    finish(job);
  });
  assert.equal(maximum, 1); assert.deepEqual(order, ['one', 'two', 'three']);
  assert.deepEqual(summary.jobs.map(job => job.state), ['finished', 'failed', 'finished']);
  assert.equal(summary.jobs[0].outputs.report, '/synthetic/one/report.json');
  assert.equal(summary.jobs[2].outputs.report, '/synthetic/three/report.json');
  assert.equal(summary.gate, 'ERROR'); assert.equal(summary.exitCode, 4);
});

test('cancelled or expired batches retain unstarted rows and never call their runner', async () => {
  for (const preCancelled of [true, false]) {
    const controller = new AbortController(); if (preCancelled) controller.abort();
    const calls: string[] = [];
    const summary = await runBatchJobs(prepared(), defaults, 'scan', controller.signal, async (target, job) => {
      calls.push(target.id); finish(job); controller.abort();
    });
    assert.deepEqual(calls, preCancelled ? [] : ['one']);
    assert.equal(summary.jobs.length, 3); assert.equal(summary.stopReason, 'cancelled');
    assert.equal(summary.jobs[2].state, 'not_started'); assert.equal(summary.gate, 'INCOMPLETE');
  }
  let calls = 0;
  const timed = await runBatchJobs(prepared(), { ...defaults, timeoutMs: 10 }, 'scan', new AbortController().signal, async (_target, job, user, deadline) => {
    calls++; assert.equal(user.aborted, false); await setTimeout(25); assert.equal(deadline.aborted, true); finish(job);
  });
  assert.equal(calls, 1); assert.equal(timed.stopReason, 'time_budget_exceeded');
  assert.equal(timed.jobs[1].state, 'not_started'); assert.equal(timed.gate, 'INCOMPLETE');
});

test('unknown termination stops siblings whether returned in a report or thrown during output checking', async () => {
  for (const thrown of [true, false]) {
    let calls = 0;
    const summary = await runBatchJobs(prepared(), defaults, 'scan', new AbortController().signal, async (_target, job) => {
      calls++;
      if (thrown) throw new SafeError('git_termination_unverified');
      finish(job, 'ERROR'); job.errors.push('termination_unverified');
    });
    assert.equal(calls, 1); assert.equal(summary.stopReason, 'termination_unverified');
    assert.deepEqual(summary.jobs.slice(1).map(job => job.state), ['not_started', 'not_started']);
    assert.equal(summary.gate, 'ERROR');
  }
});

test('GitHub acquisition receives the batch deadline separately and stops before any transport', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-batch-deadline-test-'));
  test.after(() => removeTempDir(workspace));
  const config = { ...defaults, tools: { git: { path: path.join(workspace, 'never-execute'), sha256: '0'.repeat(64), version: '1.0.0' } } };
  try {
    await assert.rejects(prepareGitHubPlan('https://github.com/example/fixture', config, workspace, undefined, undefined, AbortSignal.abort()), { code: 'git_timeout' });
    await assert.rejects(prepareGitHubPlan('https://github.com/example/fixture', config, workspace, AbortSignal.abort()), { code: 'git_cancelled' });
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('aggregate respects all gate combinations, and plan success is never a security PASS', async () => {
  const empty = await runBatchJobs(prepared(), defaults, 'scan', AbortSignal.abort(), async () => assert.fail('must not start'));
  const priority: Gate[] = ['ERROR', 'FAIL', 'INCOMPLETE', 'REVIEW', 'PASS'];
  for (const first of priority) for (const second of priority) {
    const jobs = structuredClone(empty.jobs.slice(0, 2)); finish(jobs[0], first); finish(jobs[1], second);
    assert.equal(aggregateBatch(jobs, 'scan').gate, priority[Math.min(priority.indexOf(first), priority.indexOf(second))]);
  }
  const planned = await runBatchJobs(prepared(), defaults, 'plan', new AbortController().signal, async (_target, job) => { finish(job); job.gate = null; });
  assert.equal(planned.gate, null); assert.equal(planned.exitCode, 0); assert.equal(planned.planningComplete, true);
  planned.jobs[1].planningComplete = false;
  assert.equal(aggregateBatch(planned.jobs, 'plan').exitCode, 3);
  assert.equal(aggregateBatch([], 'scan').gate, 'INCOMPLETE'); assert.equal(aggregateBatch([], 'plan').exitCode, 3);
  const missing = structuredClone(empty.jobs); finish(missing[0], 'PASS');
  assert.equal(aggregateBatch(missing, 'scan').gate, 'INCOMPLETE');
});
