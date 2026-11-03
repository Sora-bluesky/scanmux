import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, lstat, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { execute, executeDirect, verifyVersion } from '../src/process.ts';
import { scopedProcessOwner } from '../src/process-tree.ts';
import { contained } from './process-owner.ts';
import { digest, hash } from '../src/safety.ts';
import { scan } from '../src/controller.ts';
import { defaults } from '../src/config.ts';
import { sourceCleanupFor } from '../src/source-cleanup.ts';
import type { Plan } from '../src/model.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();

test('start cancellation during tool verification prevents process creation', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-start-'));
  test.after(() => removeTempDir(workspace));
  const marker = path.join(workspace, 'started');
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const abort = new AbortController();
  let spawned = false;
  try {
    const running = execute(tool, ['-e', 'require("node:fs").writeFileSync(process.argv[1],"started")', marker], {
      cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024,
      startSignal: abort.signal, onSpawn: () => { spawned = true; },
    });
    abort.abort();
    assert.equal((await running).reason, 'cancelled');
    assert.equal(spawned, false);
    assert.equal(await lstat(marker).catch(() => null), null);
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('start cancellation allows an existing command to settle but does not suppress a deadline', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-settle-'));
  test.after(() => removeTempDir(workspace));
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  try {
    await contained(async () => {
      const abort = new AbortController();
      const natural = await execute(tool, ['-e', 'setTimeout(()=>process.exit(7),30)'], {
        cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024,
        startSignal: abort.signal, onSpawn: () => abort.abort(),
      });
      assert.equal(natural.reason, 'exit');
      assert.equal(natural.code, 7);
      const another = new AbortController();
      const timed = await execute(tool, ['-e', 'setInterval(()=>{},1000)'], {
        cwd: workspace, home: workspace, timeoutMs: 300, maxOutputBytes: 1024,
        startSignal: another.signal, onSpawn: () => another.abort(),
      });
      assert.equal(timed.reason, 'timeout');
    });
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('cancellation waits for a real parent and descendant to terminate', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-process-'));
  test.after(() => removeTempDir(workspace));
  const pidFile = path.join(workspace, 'child.pid');
  const parentFile = path.join(workspace, 'parent.cjs');
  await writeFile(parentFile, `const {spawn}=require('node:child_process');const fs=require('node:fs');const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[2],String(child.pid));setInterval(()=>{},1000);`);
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const abort = new AbortController();
  try {
    await contained(async () => {
      const running = execute(tool, [parentFile, pidFile], { cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024, signal: abort.signal });
      let childPid = 0;
      try {
        const deadline = Date.now() + 5000;
        while (!childPid && Date.now() < deadline) {
          childPid = Number(await readFile(pidFile, 'utf8').catch(() => '0'));
          if (!childPid) await delay(20);
        }
        assert.ok(childPid, 'Child started');
        abort.abort();
        assert.equal((await running).reason, 'cancelled');
        assert.throws(() => process.kill(childPid, 0), { code: 'ESRCH' });
      } finally { abort.abort(); await running; }
    });
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('a lost process owner stays explicit through version verification', { skip: process.platform !== 'win32' }, async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-stop-failure-'));
  test.after(() => removeTempDir(workspace));
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const ready = path.join(workspace, 'ready');
  const fixture = path.join(workspace, 'fixture.cjs');
  await writeFile(fixture, `require('node:fs').writeFileSync(process.argv[2],'ready');setInterval(()=>{},1000);`);
  try {
    await contained(async () => {
      const version = assert.rejects(verifyVersion(tool, [fixture, ready], { cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024 }), /termination_unverified/);
      const deadline = Date.now() + 5000;
      while (!await lstat(ready).catch(() => null)) {
        assert.ok(Date.now() < deadline, 'Fixture started');
        await delay(20);
      }
      process.kill(scopedProcessOwner()!.pid);
      await version;
    });
  } finally {
    // The owner died, so nothing confirms when Windows releases the tree's handle on the workspace.
    await removeTempDirStrict(workspace, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
});

test('off Windows a process group already gone at SIGKILL counts as stopped', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-gone-'));
  test.after(() => removeTempDir(workspace));
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const platform = Object.getOwnPropertyDescriptor(process, 'platform')!, kill = process.kill.bind(process), abort = new AbortController();
  Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
  process.kill = (pid: number, signal?: string | number) => {
    if (signal !== 'SIGKILL') return kill(pid, signal);
    kill(-pid);
    throw Object.assign(new Error('kill ESRCH'), { code: 'ESRCH' });
  };
  try {
    const result = await execute(tool, ['-e', 'setInterval(()=>{},1000)'], { cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024, signal: abort.signal, onSpawn: () => abort.abort() });
    assert.deepEqual([result.reason, result.diagnostics], ['cancelled', []]);
  } finally {
    Object.defineProperty(process, 'platform', platform);
    process.kill = kill;
    await removeTempDirStrict(workspace, { recursive: true, force: true });
  }
});

for (const atSignal of [false, true]) for (const probe of ['transient', 'denied', 'other'] as const)
  test('process group permission errors require a later ESRCH: ' + (atSignal ? 'signal ' : 'probe ') + probe, async t => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-group-'));
    const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
    const platform = Object.getOwnPropertyDescriptor(process, 'platform')!, kill = process.kill.bind(process), abort = new AbortController();
    let now = 0, probes = 0;
    Object.defineProperty(process, 'platform', { ...platform, value: 'linux' });
    t.mock.method(performance, 'now', () => now);
    process.kill = (pid: number, signal?: string | number) => {
      if (signal === 'SIGKILL') {
        kill(-pid);
        if (atSignal) throw Object.assign(new Error('kill EPERM'), { code: 'EPERM' });
        return true;
      }
      assert.equal(signal, 0); assert.ok(pid < 0); probes++; now += 1000;
      throw Object.assign(new Error('group probe'), { code: probe === 'other' ? 'EIO' : probe === 'transient' && probes > 1 ? 'ESRCH' : 'EPERM' });
    };
    try {
      const result = await executeDirect(tool, ['-e', 'setInterval(()=>{},1000)'], { cwd: workspace, home: workspace, timeoutMs: 10000,
        maxOutputBytes: 1024, signal: abort.signal, onSpawn: () => abort.abort() });
      assert.equal(result.reason, probe === 'transient' ? 'cancelled' : 'termination_unverified');
      assert.equal(probes, probe === 'transient' ? 2 : probe === 'denied' ? 5 : 1);
    } finally {
      Object.defineProperty(process, 'platform', platform); process.kill = kill; t.mock.restoreAll();
      await removeTempDirStrict(workspace, { recursive: true, force: true });
    }
  });

test('the direct verifier path never reports a verified stop on Windows', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-direct-'));
  test.after(() => removeTempDir(workspace));
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  try {
    const result = await executeDirect(tool, ['-e', 'setInterval(()=>{},1000)'], { cwd: workspace, home: workspace, timeoutMs: 200, maxOutputBytes: 1024 });
    assert.deepEqual([result.reason, result.code], [process.platform === 'win32' ? 'termination_unverified' : 'timeout', null]);
    const natural = await executeDirect(tool, ['-e', 'process.exit(5)'], { cwd: workspace, home: workspace, timeoutMs: 10000, maxOutputBytes: 1024 });
    assert.deepEqual([natural.reason, natural.code], ['exit', 5]);
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});

test('unverified plan termination prevents scan and removes the owned snapshot', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-retain-'));
  test.after(() => removeTempDir(workspace));
  const owner = sourceCleanupFor(workspace), snapshot = owner.register(workspace, path.join(workspace, 'snapshot'));
  await mkdir(snapshot); await owner.capture(workspace, snapshot);
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: workspace, repoId: 'test', commit: null, treeHash: null,
    snapshotHash: digest([]), dirty: null, files: [], exclusions: [], blockers: ['git_termination_unverified'], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  try {
    const report = await scan(plan, defaults, workspace, AbortSignal.abort());
    assert.equal(report.gate, 'ERROR');
    assert.deepEqual(report.integrityErrors, ['termination_unverified']);
    assert.ok(report.engines.every(engine => engine.execution === 'not_started'));
    assert.equal(await lstat(path.join(workspace, 'snapshot')).catch(() => null), null);
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});
