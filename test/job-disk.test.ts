import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { defaults, loadConfig } from '../src/config.ts';
import { parseJobProfile } from '../src/job-config.ts';
import { scan } from '../src/controller.ts';
import { createAdapters, emptyRun, normalizeGitleaks } from '../src/adapters.ts';
import { decide } from '../src/policy.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { digest, hash, SafeError } from '../src/safety.ts';
import { execute, verifyVersion } from '../src/process.ts';
import { stopBudgetCeilingMs } from '../src/process-tree.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import { contained, testProcessOwner } from './process-owner.ts';
import type { Adapter, Config, Plan } from '../src/model.ts';

async function api() {
  const name = '../src/job-disk.ts';
  const module = await import(name).catch(() => undefined);
  assert.ok(module?.JobDisk, 'per-scan measured disk observation must exist');
  return module as typeof import('../src/job-disk.ts');
}
async function fixture(t: test.TestContext) {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-job-disk-test-'));
  t.after(() => removeTempDirStrict(directory, { recursive: true, force: true }));
  return { directory, cluster: (await fs.statfs(directory)).bsize };
}
async function outputConfig(workspace: string): Promise<Config> {
  await fs.writeFile(path.join(workspace, 'version'), "console.log('8.30.1');");
  await fs.writeFile(path.join(workspace, 'stdin'), "process.stdin.resume();process.stdin.on('end',()=>console.log('[]'));");
  return { ...defaults, tools: { gitleaks: { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: '8.30.1' } } };
}
function planFor(config: Config, root: string): Plan {
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: hash(root),
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest([]), dirty: false, files: [], exclusions: [], blockers: [],
    languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '',
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest({ ...plan, planHash: '' }); return plan;
}
function adapters(action?: (context: Parameters<Adapter['run']>[0], index: number) => Promise<void>): Adapter[] {
  return (['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const).map((engine, index) => ({
    capabilities: () => ({ engine }) as ReturnType<Adapter['capabilities']>, plan: () => ({ applicable: true, targets: [], constraints: [] }), cancel() {}, validate: () => 'unsupported', patch: () => 'unsupported',
    normalize: () => [], async run(context) {
      await action?.(context, index);
      return { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
    },
  }));
}

test('job disk: optional config accepts positive safe integers and preserves absent bytes', async t => {
  const f = await fixture(t), file = path.join(f.directory, 'config.json');
  await fs.writeFile(file, JSON.stringify({ schema: 1, maxJobDiskBytes: Number.MAX_SAFE_INTEGER }));
  assert.equal((await loadConfig(file)).maxJobDiskBytes, Number.MAX_SAFE_INTEGER);
  for (const maxJobDiskBytes of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, null, '4']) {
    await fs.writeFile(file, JSON.stringify({ schema: 1, maxJobDiskBytes }));
    await assert.rejects(loadConfig(file), { code: 'invalid_limit' });
  }
  await fs.writeFile(file, '{"schema":1}');
  assert.equal(digest(await loadConfig(file)), 'fa29e80009c28284ec2ec41b0ba6b71f215f2962e32791b521d3daf8c1a69f26');
  assert.equal(Object.hasOwn(defaults, 'maxJobDiskBytes'), false);
  const tool = { path: process.execPath, sha256: hash('fixture'), version: '1.2.3' };
  const profile = { schema: 'scanmux.job-profile/v1', name: 'disk_test', scope: 'offline-local',
    docker: { tool, endpoint: process.platform === 'win32' ? 'npipe:////./pipe/docker' : 'unix:///var/run/docker.sock' }, image: 'sha256:' + 'a'.repeat(64),
    runtime: { nodeVersion: process.versions.node, python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } },
    tools: { gitleaks: tool }, osvDatabase: null,
    scan: { timeoutMs: 10000, maxOutputBytes: 1048576, maxFileBytes: 1048576, maxSnapshotBytes: 8388608, maxFiles: 1000 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576,
      pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 16777216 } };
  assert.equal(parseJobProfile(profile).name, 'disk_test');
  assert.equal(parseJobProfile({ ...profile, maxJobDiskBytes: 1 }).maxJobDiskBytes, 1);
  for (const maxJobDiskBytes of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, null, '4']) {
    assert.throws(() => parseJobProfile({ ...profile, maxJobDiskBytes }), { code: 'invalid_job_profile' });
  }
  assert.throws(() => parseJobProfile({ ...profile, scan: { ...profile.scan, maxJobDiskBytes: 1 } }), { code: 'invalid_job_profile' });
});
test('job disk: exact cluster limit passes and one cluster over stops', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  disk.register(f.directory); disk.register(f.directory); // Duplicate roots cannot double count.
  await fs.mkdir(path.join(f.directory, 'nested')); disk.register(path.join(f.directory, 'nested'));
  await fs.writeFile(path.join(f.directory, 'small'), 'x');
  assert.equal(await disk.check(), BigInt(f.cluster)); assert.equal(disk.signal.aborted, false);
  await fs.writeFile(path.join(f.directory, 'nested', 'second'), 'x');
  await assert.rejects(disk.check(), { code: 'job_disk_measured_limit' });
  assert.equal(disk.signal.aborted, true);
});

test('job disk: peer observations replace the latest sample and share the exact combined limit', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(3 * f.cluster);
  disk.register(f.directory); await fs.writeFile(path.join(f.directory, 'host'), 'x');
  assert.equal(await disk.check(), BigInt(f.cluster));
  for (const bytes of [2 * f.cluster, f.cluster, f.cluster, 2 * f.cluster]) {
    disk.updatePeerSample(BigInt(bytes)); await disk.check(); assert.equal(disk.cause, undefined);
  }
  disk.updatePeerSample(BigInt(2 * f.cluster) + 1n);
  await assert.rejects(disk.check(), { code: 'job_disk_measured_limit' });
});

test('job disk: a failed walk reports an unknown sample and a failed peer never becomes zero', async t => {
  const f = await fixture(t), { JobDisk } = await api(), root = path.join(f.directory, 'root'), samples: (bigint | null)[] = [];
  await fs.mkdir(root);
  const disk = new JobDisk(f.cluster, async bytes => { samples.push(bytes); }); disk.register(root);
  await fs.rmdir(root);
  await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' }); assert.deepEqual(samples, [null]);
  const peer = new JobDisk(f.cluster); peer.register(f.directory); await peer.check(); peer.updatePeerSample(null);
  await assert.rejects(peer.check(), { code: 'job_disk_observation_unverified' });
});
test('job disk: outside junctions or symlinks are not followed, directories and empty files count zero', async t => {
  const f = await fixture(t), { JobDisk } = await api(), root = path.join(f.directory, 'root'), outside = path.join(f.directory, 'outside');
  await fs.mkdir(root); await fs.mkdir(outside); await fs.writeFile(path.join(outside, 'large'), Buffer.alloc(f.cluster * 4));
  await fs.writeFile(path.join(root, 'empty'), ''); await fs.symlink(outside, path.join(root, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
  const disk = new JobDisk(1); disk.register(root);
  assert.equal(await disk.check(), 0n);
});
test('job disk: unknown cluster size and failed reads are observation errors, never zero', async t => {
  const f = await fixture(t), { JobDisk } = await api();
  for (const failure of ['statfs', 'readdir', 'lstat'] as const) {
    const disk = new JobDisk(f.cluster); disk.register(f.directory);
    t.mock.method(fs, failure, async () => { throw Object.assign(new Error('fixture'), { code: 'EACCES' }); }); syncBuiltinESMExports();
    try { await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' }); }
    finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
    assert.equal(disk.signal.aborted, true);
  }
  const disk = new JobDisk(f.cluster); disk.register(f.directory);
  t.mock.method(fs, 'statfs', async () => ({ bsize: 0n })); syncBuiltinESMExports();
  try { await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});
test('job disk: engine end is sampled, prior FAIL and ERROR keep precedence', async t => {
  const f = await fixture(t), { JobDisk } = await api();
  for (const prior of ['none', 'FAIL', 'ERROR'] as const) {
    const workspace = path.join(f.directory, prior); await fs.mkdir(workspace);
    const ownerBytes = testProcessOwner ? Math.ceil((await fs.stat(testProcessOwner.path)).size / f.cluster) * f.cluster : 0;
    const limit = ownerBytes + f.cluster * 128, config = { ...await outputConfig(workspace), maxJobDiskBytes: limit }, disk = new JobDisk(limit);
    const runs = adapters(async (context, index) => { if (index === 1) await fs.writeFile(path.join(context.workspace, 'growth'), Buffer.alloc(limit + 1)); });
    const original = runs[0].run;
    runs[0].run = async context => {
      const run = await original(context);
      if (prior === 'ERROR') { run.execution = 'failed'; run.errors.push('earlier_error'); }
      if (prior === 'FAIL') run.findings = normalizeGitleaks([{ RuleID: 'fixture', File: 'source.ts', StartLine: 1 }], { ...context, plan: { ...context.plan, files: [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 0, sha256: hash('') }] } });
      return run;
    };
    const report = await contained(() => scan(planFor(config, f.directory), config, workspace, new AbortController().signal, runs, undefined, undefined, disk));
    assert.equal(report.gate, prior === 'none' ? 'INCOMPLETE' : prior, JSON.stringify(report.reasons));
    assert.ok(report.reasons.includes('job_disk_measured_limit'));
  }
});
test('job disk: measurement failure gives ERROR in the real controller', async t => {
  const f = await fixture(t), { JobDisk } = await api(), config = { ...defaults, maxJobDiskBytes: f.cluster };
  const disk = new JobDisk(f.cluster); disk.register(f.directory + '-missing');
  const report = await scan(planFor(config, f.directory), config, f.directory, new AbortController().signal, adapters(), undefined, undefined, disk);
  assert.equal(report.gate, 'ERROR'); assert.ok(report.reasons.includes('job_disk_observation_unverified'), JSON.stringify(report.reasons));
});
test('job disk: an integrity exception concurrent with a measured stop stays ERROR', async t => {
  const f = await fixture(t), { JobDisk } = await api(), config = { ...defaults, maxJobDiskBytes: f.cluster };
  const disk = new JobDisk(f.cluster);
  const report = await scan(planFor(config, f.directory), config, f.directory, new AbortController().signal,
    adapters(async () => {
      await fs.writeFile(path.join(f.directory, 'growth'), Buffer.alloc(f.cluster + 1));
      await disk.check().catch(() => {});
      throw new SafeError('snapshot_integrity');
    }), undefined, undefined, disk);
  assert.equal(report.gate, 'ERROR', JSON.stringify(report.reasons));
  assert.ok(report.reasons.includes('snapshot_integrity'));
});
test('job disk: a stop during checkpoint secret checking saves the disk cause', async t => {
  const f = await fixture(t), { JobDisk } = await api();
  const ownerBytes = testProcessOwner ? Math.ceil((await fs.stat(testProcessOwner.path)).size / f.cluster) * f.cluster : 0;
  const limit = ownerBytes + 12 * f.cluster, config = { ...await outputConfig(f.directory), maxJobDiskBytes: limit };
  await fs.writeFile(path.join(f.directory, 'stdin'), `process.stdin.resume();process.stdin.on('end',()=>{require('fs').writeFileSync('growth',Buffer.alloc(${limit + 1}));console.log('[]')});`);
  const report = await contained(() => scan(planFor(config, f.directory), config, f.directory, new AbortController().signal, adapters(), undefined, undefined, new JobDisk(limit)));
  assert.equal(report.gate, 'INCOMPLETE', JSON.stringify(report.reasons));
  assert.ok(report.reasons.includes('job_disk_measured_limit'));
  const checkpoint = JSON.parse(await fs.readFile(path.join(f.directory, 'checkpoints', 'checkpoint-1.json'), 'utf8'));
  assert.ok(checkpoint.report.reasons.includes('job_disk_measured_limit'));
});
test('job disk: a TEMP writer and its child stop within the rate-based overshoot bound', async t => {
  const f = await fixture(t), { JobDisk, jobDiskPollMs } = await api();
  const ownerBytes = testProcessOwner ? Math.ceil((await fs.stat(testProcessOwner.path)).size / f.cluster) * f.cluster : 0;
  const limit = ownerBytes + 16 * f.cluster, config = { ...await outputConfig(f.directory), timeoutMs: 15000, maxJobDiskBytes: limit };
  const disk = new JobDisk(limit), durations: number[] = [], check = disk.check.bind(disk);
  t.mock.method(disk, 'check', async () => { const start = performance.now(); try { return await check(); } finally { durations.push(performance.now() - start); } });
  const tool = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
  const childCode = `const fs=require('fs'),p=require('path');fs.writeFileSync(p.join(process.env.TEMP,'child.pid'),String(process.pid));setInterval(()=>fs.appendFileSync(p.join(process.env.TEMP,'growth'),Buffer.alloc(${f.cluster})),40);`;
  const code = `require('child_process').spawn(process.execPath,['-e',${JSON.stringify(childCode)}],{stdio:'inherit',windowsHide:true});setInterval(()=>{},1000);`;
  let result: Awaited<ReturnType<typeof execute>> | undefined, parentPid = 0;
  const report = await contained(() => scan(planFor(config, f.directory), config, f.directory, new AbortController().signal,
    adapters(async (context, index) => { if (!index) result = await execute(tool, ['-e', code], { cwd: f.directory, home: f.directory, timeoutMs: 12000,
      maxOutputBytes: 4096, signal: context.signal, onSpawn: pid => { parentPid = pid; } }); }), undefined, undefined, disk));
  assert.equal(report.gate, 'INCOMPLETE', JSON.stringify(report.reasons)); assert.ok(report.reasons.includes('job_disk_measured_limit'));
  assert.equal(result?.reason, 'job_disk_measured_limit');
  const childPid = Number(await fs.readFile(path.join(f.directory, 'child.pid'), 'utf8'));
  for (const pid of [parentPid, childPid]) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  const peak = ownerBytes + 2 * f.cluster + Math.ceil((await fs.stat(path.join(f.directory, 'growth'))).size / f.cluster) * f.cluster + f.cluster;
  // Monotonic writer: final size is the peak. Allow one write per 40 ms through polling,
  // the measured traversal delay and the existing verified tree-stop budget, plus one burst.
  const bound = f.cluster * (Math.ceil((jobDiskPollMs + Math.max(...durations) + stopBudgetCeilingMs) / 40) + 1);
  assert.ok(peak <= limit + bound, `${peak} > ${limit} + ${bound}`);
  t.diagnostic(`peak=${peak}; limit=${limit}; overshootBound=${bound}; parent and child absent`);
});
test('job disk: workspace creation registers roots and retired roots are released', async t => {
  const f = await fixture(t), { JobDisk, withJobDisk, releaseJobDiskRoot } = await api(), disk = new JobDisk(f.cluster);
  await withJobDisk(disk, async () => {
    const workspace = await privateWorkspace();
    try { await fs.writeFile(path.join(workspace, 'data'), 'x'); assert.equal(await disk.check(), BigInt(f.cluster)); }
    finally { releaseJobDiskRoot(workspace); await removeTempDirStrict(workspace, { recursive: true, force: true }); }
    assert.equal(await disk.check(), 0n);
  });
});
test('job disk: each scan is independent and absent config does no observation or format change', async t => {
  const f = await fixture(t), { JobDisk, withJobDisk } = await api();
  const outer = new JobDisk(1); outer.register(path.join(f.directory, 'missing'));
  t.mock.method(fs, 'statfs', async () => { throw new Error('absent config must never measure'); }); syncBuiltinESMExports();
  try {
    const legacy = await outputConfig(f.directory);
    const report = await contained(() => withJobDisk(outer, () => scan(planFor(legacy, f.directory), legacy, f.directory, new AbortController().signal, adapters())));
    assert.equal(report.gate, 'PASS', JSON.stringify(report.reasons)); assert.ok(!JSON.stringify(report).includes('job_disk'));
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  for (const name of ['one', 'two']) {
    const workspace = path.join(f.directory, name); await fs.mkdir(workspace);
    const config = { ...await outputConfig(workspace), maxJobDiskBytes: f.cluster * 128 + (testProcessOwner ? (await fs.stat(testProcessOwner.path)).size : 0) };
    const report = await contained(() => scan(planFor(config, f.directory), config, workspace, new AbortController().signal, adapters()));
    assert.equal(report.gate, 'PASS', JSON.stringify(report.reasons));
  }
});

test('job disk review: concurrent entry deletion and replacement are observable churn', async t => {
  const { JobDisk } = await api();
  for (const phase of ['readdir', 'realpath', 'statfs', 'final-lstat', 'rename', 'rename-realpath', 'delete-pending', 'delete-pending-replaced'] as const) {
    await t.test(phase, async t => {
      const f = await fixture(t), root = path.join(f.directory, 'root'), file = path.join(root, 'entry');
      await fs.mkdir(root); await fs.writeFile(file, 'x');
      const disk = new JobDisk(f.cluster * 4); disk.register(root);
      const method = phase === 'rename-realpath' ? 'realpath' : phase === 'final-lstat' || phase === 'rename' || phase === 'delete-pending' || phase === 'delete-pending-replaced' ? 'lstat' : phase;
      const original = fs[method].bind(fs) as (...args: any[]) => Promise<any>;
      let calls = 0, changed = false;
      t.mock.method(fs, method, async (...args: any[]) => {
        const matches = String(args[0]) === (method === 'readdir' ? root : file);
        if (matches) calls++;
        const change = matches && !changed && (phase === 'final-lstat' || phase === 'rename' ? calls === 2 : true);
        if (method === 'readdir') {
          const entries = await original(...args);
          if (change) { changed = true; await fs.unlink(file); }
          return entries;
        }
        if (change) {
          changed = true;
          if (phase === 'rename' || phase === 'delete-pending-replaced') {
            const replacement = path.join(f.directory, 'replacement');
            await fs.writeFile(replacement, Buffer.alloc(f.cluster + 1)); await fs.rename(replacement, file);
          } else if (phase === 'rename-realpath') {
            const moved = path.join(root, 'moved'); await fs.rename(file, moved);
            // Windows may resolve an opened entry to its new name during rename.
            return original(moved);
          } else await fs.unlink(file);
          if (phase.startsWith('delete-pending')) throw Object.assign(new Error('delete pending'), { code: 'EPERM' });
        }
        return original(...args);
      });
      syncBuiltinESMExports();
      try {
        assert.equal(await disk.check(), phase === 'rename' || phase === 'delete-pending-replaced' ? BigInt(f.cluster * 2) : 0n);
        assert.equal(changed, true); assert.equal(disk.signal.aborted, false);
      } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
    });
  }
  for (const code of ['EPERM', 'EACCES', 'EIO']) await t.test(`persistent entry ${code} stays an observation error`, async t => {
    const f = await fixture(t), file = path.join(f.directory, 'entry'), disk = new JobDisk(f.cluster * 4);
    await fs.writeFile(file, 'x'); disk.register(f.directory);
    const original = fs.lstat;
    t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
      if (String(args[0]) === file) throw Object.assign(new Error('fixture'), { code });
      return original(...args);
    }); syncBuiltinESMExports();
    try { await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' }); }
    finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  });
  for (const nested of [false, true]) await t.test(`missing registered root stays an observation error, nested=${nested}`, async t => {
    const f = await fixture(t), root = path.join(f.directory, 'root'), disk = new JobDisk(f.cluster * 4);
    await fs.mkdir(root);
    if (nested) disk.register(f.directory);
    disk.register(root); await fs.rmdir(root);
    await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
  });
  await t.test('TEMP writer alongside periodic sampler preserves the scan verdict', async t => {
    const f = await fixture(t);
    const ownerBytes = testProcessOwner ? (await fs.stat(testProcessOwner.path)).size : 0;
    const limit = ownerBytes + f.cluster * 1024, config = { ...await outputConfig(f.directory), maxJobDiskBytes: limit };
    const tool = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
    // Keep deletion concurrent without recreating a listed name during the sampler's bounded retries.
    const code = `const fs=require('fs'),p=require('path');const dir=p.join(process.env.TEMP,'churn');fs.mkdirSync(dir);const end=Date.now()+3000;let i=0;while(Date.now()<end){const a=p.join(dir,'a'+i),b=p.join(dir,'b'+i);fs.writeFileSync(a,'x');fs.renameSync(a,b);fs.unlinkSync(b);i++}console.log(i);`;
    let result: Awaited<ReturnType<typeof execute>> | undefined;
    const report = await contained(() => scan(planFor(config, f.directory), config, f.directory, new AbortController().signal,
      adapters(async (context, index) => { if (!index) result = await execute(tool, ['-e', code], {
        cwd: f.directory, home: f.directory, timeoutMs: 10000, maxOutputBytes: 4096, signal: context.signal,
      }); })));
    assert.equal(result?.reason, 'exit'); assert.equal(result?.code, 0); assert.ok(Number(result?.stdout.toString()) > 0);
    assert.equal(report.gate, 'PASS', JSON.stringify(report.reasons));
    assert.ok(!report.reasons.some(reason => reason.startsWith('job_disk_')));
  });
});

test('job disk review: Windows case-variant duplicate roots count once and detect growth', { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  disk.register(f.directory); disk.register(f.directory.toUpperCase()); disk.register(f.directory.toLowerCase());
  await fs.writeFile(path.join(f.directory, 'one'), 'x');
  assert.equal(await disk.check(), BigInt(f.cluster));
  await fs.writeFile(path.join(f.directory, 'two'), 'x');
  await assert.rejects(disk.check(), { code: 'job_disk_measured_limit' });
});

test('job disk review: cancellation before final disk sampling keeps the first cause', async t => {
  const { JobDisk, withJobDisk } = await api();
  for (const failure of ['limit', 'observation'] as const) {
    await t.test(`execute cancellation then ${failure}`, async t => {
      const f = await fixture(t), disk = new JobDisk(f.cluster), abort = new AbortController(); disk.register(f.directory);
      const tool = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
      const result = await contained(() => withJobDisk(disk, () => execute(tool, ['-e', 'setInterval(()=>{},1000)'], {
        cwd: f.directory, home: f.directory, timeoutMs: 10000, maxOutputBytes: 4096, signal: abort.signal,
        onSpawn: () => {
          abort.abort();
          if (failure === 'limit') writeFileSync(path.join(f.directory, 'growth'), Buffer.alloc(f.cluster + 1));
          else { t.mock.method(fs, 'statfs', async () => { throw Object.assign(new Error('fixture'), { code: 'EACCES' }); }); syncBuiltinESMExports(); }
        },
      })));
      t.mock.restoreAll(); syncBuiltinESMExports();
      assert.equal(disk.cause, failure === 'limit' ? 'job_disk_measured_limit' : 'job_disk_observation_unverified');
      assert.equal(result.reason, 'cancelled');
    });
    for (const throws of [false, true]) await t.test(`controller cancellation then ${failure}, throws=${throws}`, async t => {
      const f = await fixture(t), abort = new AbortController();
      const limit = f.cluster * 1024 + (testProcessOwner ? (await fs.stat(testProcessOwner.path)).size : 0);
      const disk = new JobDisk(limit), config = { ...await outputConfig(f.directory), maxJobDiskBytes: limit };
      try {
        const report = await contained(() => scan(planFor(config, f.directory), config, f.directory, abort.signal,
          adapters(async (_context, index) => {
            if (index) return;
            abort.abort();
            if (failure === 'limit') await fs.writeFile(path.join(f.directory, 'growth'), Buffer.alloc(limit + 1));
            else { t.mock.method(fs, 'statfs', async () => { throw Object.assign(new Error('fixture'), { code: 'EACCES' }); }); syncBuiltinESMExports(); }
            if (throws) { await disk.check().catch(() => {}); throw new SafeError('cancelled'); }
          }), undefined, undefined, disk));
        assert.equal(report.executionState, 'cancelled'); assert.equal(report.gate, 'INCOMPLETE', JSON.stringify(report.reasons));
        assert.ok(report.engines.some(run => run.errors.some(reason => reason.startsWith('cancelled'))), JSON.stringify(report.engines));
        assert.ok(!report.reasons.some(reason => reason.startsWith('job_disk_')), JSON.stringify(report.reasons));
      } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
    });
  }
  for (const failure of ['limit', 'observation'] as const) for (const throws of [false, true]) await t.test(`controller deadline then ${failure}, throws=${throws}`, async t => {
    const f = await fixture(t), deadline = new AbortController();
    const limit = f.cluster * 1024 + (testProcessOwner ? (await fs.stat(testProcessOwner.path)).size : 0);
    const disk = new JobDisk(limit), config = { ...await outputConfig(f.directory), maxJobDiskBytes: limit };
    try {
      const report = await contained(async () => {
        t.mock.method(AbortSignal, 'timeout', () => deadline.signal);
        return scan(planFor(config, f.directory), config, f.directory, new AbortController().signal,
          adapters(async (_context, index) => {
            if (index) return;
            deadline.abort(new DOMException('fixture deadline', 'TimeoutError'));
            if (failure === 'limit') await fs.writeFile(path.join(f.directory, 'growth'), Buffer.alloc(limit + 1));
            else { t.mock.method(fs, 'statfs', async () => { throw Object.assign(new Error('fixture'), { code: 'EACCES' }); }); syncBuiltinESMExports(); }
            if (throws) { await disk.check().catch(() => {}); throw new SafeError('cancelled'); }
          }), undefined, undefined, disk);
      });
      assert.equal(report.executionState, 'budget_exceeded'); assert.equal(report.gate, 'INCOMPLETE', JSON.stringify(report.reasons));
      assert.ok(report.engines.some(run => run.errors.includes('time_budget_exceeded')), JSON.stringify(report.engines));
      assert.ok(!report.reasons.some(reason => reason.startsWith('job_disk_')), JSON.stringify(report.reasons));
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  });
});

test('job disk review: registering through a non-canonical ancestor alias measures and releases the canonical root', async t => {
  const f = await fixture(t), { JobDisk } = await api(), actual = path.join(f.directory, 'actual'), alias = path.join(f.directory, 'alias');
  await fs.mkdir(actual); await fs.mkdir(path.join(actual, 'job'));
  await fs.symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir');
  await fs.writeFile(path.join(actual, 'job', 'entry'), 'x');
  const disk = new JobDisk(f.cluster); disk.register(path.join(alias, 'job')); disk.register(path.join(actual, 'job'));
  assert.equal(await disk.check(), BigInt(f.cluster));
  disk.release(path.join(alias, 'job')); assert.equal(await disk.check(), 0n);
});

test('job disk final: a file renamed over a listed empty entry counts only once per sample', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  const a = path.join(f.directory, 'a'), b = path.join(f.directory, 'b');
  await fs.writeFile(a, 'x'); await fs.writeFile(b, ''); disk.register(f.directory);
  const original = fs.lstat, list = fs.readdir;
  let reads = 0, lists = 0;
  t.mock.method(fs, 'readdir', async (...args: Parameters<typeof fs.readdir>) =>
    String(args[0]) === f.directory && lists++ === 0 ? ['a', 'b'] : list(...args));
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await original(...args);
    if (String(args[0]) === a && ++reads === 2) await fs.rename(a, b);
    return stat;
  }); syncBuiltinESMExports();
  try {
    assert.equal(await disk.check(), BigInt(f.cluster));
    assert.equal(reads, 2); assert.equal(disk.cause, undefined);
    assert.equal(await disk.check(), BigInt(f.cluster), 'identities reset for each sample');
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

for (const finding of [false, true]) test(`job disk final: final observation failure preserves output and stays ERROR, finding=${finding}`, async t => {
  const f = await fixture(t), { JobDisk, withJobDisk } = await api(), disk = new JobDisk(f.cluster * 128);
  const config = { ...await outputConfig(f.directory), maxJobDiskBytes: disk.limit };
  const json = finding ? JSON.stringify([{ RuleID: 'fixture', File: 'source.ts', StartLine: 1 }]) : '[]';
  await fs.writeFile(path.join(f.directory, 'dir'), `console.log(${JSON.stringify(json)});process.exitCode=${finding ? 1 : 0};`);
  const plan = planFor(config, f.directory); plan.required = ['gitleaks'];
  plan.files = [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 0, sha256: hash('') }];
  disk.register(f.directory);
  let finishes = 0;
  t.mock.method(disk, 'watch', () => async () => {
    if (++finishes === 2) disk.register(path.join(f.directory, 'missing'));
    await disk.check().catch(() => {});
  });
  const run = await contained(() => withJobDisk(disk, () => createAdapters()[0].run({
    plan, config, workspace: f.directory, snapshot: f.directory, signal: new AbortController().signal, secretsCleared: false,
  })));
  assert.equal(run.findings.length, finding ? 1 : 0);
  assert.ok(run.errors.includes('job_disk_observation_unverified'));
  assert.equal(decide(plan, [run]).gate, 'ERROR');
});

test('job disk final: repeated replacement cannot keep a sample or finish pending', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster * 4);
  const file = path.join(f.directory, 'entry'); await fs.writeFile(file, 'x'); disk.register(f.directory);
  const original = fs.lstat;
  let reads = 0;
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await original(...args);
    // Twenty replacements would eventually settle on HEAD; the sample must refuse earlier.
    if (String(args[0]) === file && ++reads <= 40) return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { ino: BigInt(reads) });
    return stat;
  }); syncBuiltinESMExports();
  try {
    const finish = disk.watch(); t.after(finish);
    await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
    await finish(); assert.ok(reads < 40, `entry read ${reads} times`);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

for (const code of ['EPERM', 'EACCES']) test(`job disk: deleted names are absent while delete-pending stats remain ${code}`, async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  const file = path.join(f.directory, 'entry'), retained = path.join(f.directory, 'retained');
  await fs.writeFile(file, 'x'); await fs.writeFile(retained, 'x'); disk.register(f.directory);
  const original = fs.lstat, list = fs.readdir;
  let reads = 0, confirmations = 0;
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    if (String(args[0]) === file) {
      if (++reads === 1) await fs.unlink(file);
      throw Object.assign(new Error('delete-pending metadata'), { code });
    }
    return original(...args);
  });
  t.mock.method(fs, 'readdir', async (...args: Parameters<typeof fs.readdir>) => {
    if (String(args[0]) === f.directory && reads) confirmations++;
    return list(...args);
  }); syncBuiltinESMExports();
  try {
    assert.equal(await disk.check(), BigInt(f.cluster));
    assert.ok(confirmations > 0, 'absence must be confirmed by a fresh parent listing');
    assert.equal(disk.cause, undefined);
  } finally {
    t.diagnostic(`entry stats=${reads}; parent listings after failure=${confirmations}`);
    t.mock.restoreAll(); syncBuiltinESMExports();
  }
});

for (const persistent of [false, true]) test(`job disk: ${persistent ? 'persistent' : 'transient'} parent listing permission errors`, async t => {
  for (const code of ['EACCES', 'EPERM']) await t.test(code, async t => {
    const f = await fixture(t), { JobDisk } = await api(), samples: (bigint | null)[] = [];
    const disk = new JobDisk(f.cluster, async bytes => { samples.push(bytes); });
    const file = path.join(f.directory, 'entry'); await fs.writeFile(file, 'x'); disk.register(f.directory);
    const original = fs.lstat, list = fs.readdir;
    let reads = 0, lists = 0;
    t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
      if (String(args[0]) === file && (++reads <= 2 || persistent)) {
        throw Object.assign(new Error('delete-pending metadata'), { code: 'EPERM' });
      }
      return original(...args);
    });
    t.mock.method(fs, 'readdir', async (...args: Parameters<typeof fs.readdir>) => {
      if (String(args[0]) === f.directory && ++lists > 1 && (persistent || lists === 2)) {
        throw Object.assign(new Error('parent listing denied'), { code });
      }
      return list(...args);
    }); syncBuiltinESMExports();
    try {
      if (persistent) {
        await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
        assert.equal(disk.cause, 'job_disk_observation_unverified');
        assert.deepEqual(samples, [null]);
        assert.equal(reads, 4); assert.equal(lists, 4);
      } else {
        assert.equal(await disk.check(), BigInt(f.cluster));
        assert.equal(disk.cause, undefined); assert.deepEqual(samples, [BigInt(f.cluster)]);
        assert.equal(reads, 5); assert.equal(lists, 2);
      }
    } finally {
      t.diagnostic(`entry stats=${reads}; parent listings=${lists}`);
      t.mock.restoreAll(); syncBuiltinESMExports();
    }
  });
});

for (const code of ['EPERM', 'EACCES']) for (const method of ['realpath', 'statfs', 'readdir', 'final-lstat'] as const) for (const persistent of [false, true]) {
  test(`job disk: ${persistent ? 'persistent' : 'transient'} ${code} at ${method} verifies a readable entry`, async t => {
    const f = await fixture(t), { JobDisk } = await api(), samples: (bigint | null)[] = [];
    const disk = new JobDisk(f.cluster, async bytes => { samples.push(bytes); });
    const root = path.join(f.directory, 'root'), entry = path.join(root, 'entry');
    await fs.mkdir(root);
    if (method === 'readdir') { await fs.mkdir(entry); await fs.writeFile(path.join(entry, 'retained'), 'x'); }
    else await fs.writeFile(entry, 'x');
    disk.register(root);
    const operation = method === 'final-lstat' ? 'lstat' : method;
    const original = fs[operation].bind(fs) as (...args: any[]) => Promise<any>;
    let calls = 0, failures = 0;
    t.mock.method(fs, operation, async (...args: any[]) => {
      if (String(args[0]) === entry && ++calls >= (method === 'final-lstat' ? 2 : 1) && (persistent || failures === 0)) {
        failures++;
        throw Object.assign(new Error('transient sharing failure'), { code });
      }
      return original(...args);
    }); syncBuiltinESMExports();
    try {
      if (persistent) {
        await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
        assert.deepEqual(samples, [null]);
      } else {
        assert.equal(await disk.check(), BigInt(f.cluster));
        assert.equal(failures, 1); assert.equal(disk.cause, undefined);
        assert.deepEqual(samples, [BigInt(f.cluster)]);
      }
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  });
}

for (const code of ['EPERM', 'EACCES']) test(`job disk: case-only renamed names with persistent ${code} remain unverified`, { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(t), { JobDisk } = await api(), samples: (bigint | null)[] = [];
  const disk = new JobDisk(f.cluster, async bytes => { samples.push(bytes); });
  const file = path.join(f.directory, 'entry'); await fs.writeFile(file, 'x'); disk.register(f.directory);
  const original = fs.lstat, list = fs.readdir;
  let lists = 0;
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    if (String(args[0]) === file) throw Object.assign(new Error('sharing failure after case-only rename'), { code });
    return original(...args);
  });
  t.mock.method(fs, 'readdir', async (...args: Parameters<typeof fs.readdir>) =>
    String(args[0]) === f.directory ? (lists++ === 0 ? ['entry'] : ['ENTRY']) : list(...args));
  syncBuiltinESMExports();
  try {
    await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
    assert.equal(disk.cause, 'job_disk_observation_unverified');
    assert.deepEqual(samples, [null]);
    assert.ok(lists > 1, 'the parent listing must be checked again after the failed stat');
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

for (const code of ['EPERM', 'EACCES']) for (const [name, relistedName] of [['ΟΣ', 'οσ'], ['ος', 'οσ']]) {
  test(`job disk: Greek sigma names ${name} to ${relistedName} with persistent ${code} remain unverified`, { skip: process.platform !== 'win32' }, async t => {
    const f = await fixture(t), { JobDisk } = await api(), samples: (bigint | null)[] = [];
    const disk = new JobDisk(f.cluster, async bytes => { samples.push(bytes); });
    const file = path.join(f.directory, name); await fs.writeFile(file, 'x'); disk.register(f.directory);
    const original = fs.lstat, list = fs.readdir;
    let lists = 0;
    t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
      if (String(args[0]) === file) throw Object.assign(new Error('sharing failure after case-only rename'), { code });
      return original(...args);
    });
    t.mock.method(fs, 'readdir', async (...args: Parameters<typeof fs.readdir>) =>
      String(args[0]) === f.directory ? (lists++ === 0 ? [name] : [relistedName]) : list(...args));
    syncBuiltinESMExports();
    try {
      await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' });
      assert.equal(disk.cause, 'job_disk_observation_unverified');
      assert.deepEqual(samples, [null]);
      assert.ok(lists > 1, 'the parent listing must be checked again after the failed stat');
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  });
}

test('job disk: replacement after a confirmation stat is measured on the next attempt', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster * 2);
  const root = path.join(f.directory, 'root'), file = path.join(root, 'entry'), replacement = path.join(f.directory, 'replacement');
  await fs.mkdir(root); await fs.writeFile(file, 'x'); await fs.writeFile(replacement, Buffer.alloc(f.cluster + 1)); disk.register(root);
  const original = fs.lstat, resolve = fs.realpath;
  let reads = 0, failures = 0;
  t.mock.method(fs, 'realpath', async (...args: Parameters<typeof fs.realpath>) => {
    if (String(args[0]) === file && failures++ === 0) throw Object.assign(new Error('transient sharing failure'), { code: 'EPERM' });
    return resolve(...args);
  });
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await original(...args);
    if (String(args[0]) === file && ++reads === 2) await fs.rename(replacement, file);
    return stat;
  }); syncBuiltinESMExports();
  try {
    assert.equal(await disk.check(), BigInt(f.cluster * 2));
    assert.ok(reads > 2); assert.equal(disk.cause, undefined);
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

for (const code of ['EPERM', 'EACCES']) test(`job disk final: transient ${code} delete-pending clears before refusal`, async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  const file = path.join(f.directory, 'entry'); await fs.writeFile(file, 'x'); disk.register(f.directory);
  const original = fs.lstat;
  let reads = 0;
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    if (String(args[0]) === file) {
      if (++reads <= 3) throw Object.assign(new Error('delete pending'), { code });
      if (reads === 4) await fs.unlink(file);
    }
    return original(...args);
  }); syncBuiltinESMExports();
  try { assert.equal(await disk.check(), 0n); assert.equal(reads, 4); assert.equal(disk.cause, undefined); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('job disk final: a persistently listed but unaddressable name is an observation error', async t => {
  const f = await fixture(t), { JobDisk } = await api(), disk = new JobDisk(f.cluster);
  const file = path.join(f.directory, 'unaddressable'); await fs.writeFile(file, 'x'); disk.register(f.directory);
  const original = fs.lstat;
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    if (String(args[0]) === file) throw Object.assign(new Error('name cannot round trip'), { code: 'ENOENT' });
    return original(...args);
  }); syncBuiltinESMExports();
  try { await assert.rejects(disk.check(), { code: 'job_disk_observation_unverified' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

for (const output of ['finding', 'empty', 'invalid'] as const) test(`job disk final: final-sample limit preserves normal scanner output: ${output}`, async t => {
  const f = await fixture(t), { JobDisk, withJobDisk } = await api();
  const limit = f.cluster * 128, disk = new JobDisk(limit), config = { ...await outputConfig(f.directory), maxJobDiskBytes: limit };
  const json = output === 'finding' ? JSON.stringify([{ RuleID: 'fixture', File: 'source.ts', StartLine: 1 }]) : output === 'empty' ? '[]' : 'invalid JSON';
  await fs.writeFile(path.join(f.directory, 'dir'), `require('fs').writeFileSync('growth',Buffer.alloc(${limit + 1}));console.log(${JSON.stringify(json)});process.exitCode=${output === 'empty' ? 0 : 1};`);
  const plan = planFor(config, f.directory); plan.required = ['gitleaks'];
  plan.files = [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 0, sha256: hash('') }];
  disk.register(f.directory);
  // Sample only at process completion to make the final-sample boundary deterministic.
  t.mock.method(disk, 'watch', () => async () => { await disk.check().catch(() => {}); });
  const run = await contained(() => withJobDisk(disk, () => createAdapters()[0].run({
    plan, config, workspace: f.directory, snapshot: f.directory, signal: new AbortController().signal, secretsCleared: false,
  })));
  assert.equal(run.exitCode, output === 'empty' ? 0 : 1);
  assert.equal(run.findings.length, output === 'finding' ? 1 : 0);
  assert.ok(run.errors.includes('job_disk_measured_limit'), JSON.stringify(run.errors));
  assert.equal(decide(plan, [run]).gate, output === 'finding' ? 'FAIL' : output === 'empty' ? 'INCOMPLETE' : 'ERROR');
  if (output === 'invalid') assert.ok(run.errors.includes('scanner_json_invalid'));
});

test('job disk final: docs disclose renamed directories beside short-lived files', async () => {
  for (const file of ['docs/getting-started.md', 'docs/getting-started.ja.md', 'docs/assumptions.md', 'docs/assumptions.ja.md']) {
    const text = await fs.readFile(file, 'utf8');
    assert.match(text, file.includes('.ja.')
      ? /短命なファイル[^。]*。[^。]*ディレクトリ[^。]*次の計測/
      : /files created and removed between observations[^.]*\.[^.]*director[^.]*renamed[^.]*next sample/i, file);
  }
});

for (const cause of ['job_disk_measured_limit', 'job_disk_observation_unverified'] as const) test(`job disk final: version validation retains ${cause} after parsing`, async () => {
  const tool = { path: process.execPath, sha256: '', version: '8.30.1' };
  const options = { cwd: '.', home: '.', timeoutMs: 1000, maxOutputBytes: 4096 };
  for (const valid of [true, false]) {
    await assert.rejects(verifyVersion(tool, [], options, async () => ({ code: 0, reason: 'exit', diagnostics: [cause], stdout: Buffer.from(valid ? '8.30.1' : 'invalid') })),
      { code: valid ? cause : 'tool_version_mismatch' });
  }
});
