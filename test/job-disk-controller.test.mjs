import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { defaults } from '../src/config.ts';
import { scan } from '../src/controller.ts';
import { JobDisk, jobDiskPollMs, scopedJobDisk, withJobDisk } from '../src/job-disk.ts';
import { scopedCopyBudget, withCopyBudget } from '../src/copy-budget.ts';
import { execute } from '../src/process.ts';
import { emptyRun, normalizeGitleaks } from '../src/adapters.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { CheckpointOwnerStop } from '../src/engine-checkpoint.ts';
import { digest, hash, record } from '../src/safety.ts';
import * as channel from '../internal/job-channel.mjs';
import { contained } from './process-owner.ts';

// Run the controller's real input loop and scan on Windows, replacing only Linux
// paths/platform admission and the already-tested repository/tool boundary.
const source = (await fs.readFile('internal/linux-job-controller.mjs', 'utf8')).replace(/^import .*;\n/gm, '');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
async function runController(t, scenario, prior) {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-disk-controller-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const roots = Object.fromEntries(['work', 'tmp', 'shm', 'app', 'host'].map(name => [name, path.join(directory, name)]));
  await Promise.all(Object.values(roots).map(root => fs.mkdir(root)));
  const maximum = 8 * 1024 * 1024, enabled = scenario !== 'absent';
  await fs.writeFile(path.join(roots.app, 'readonly-copy'), Buffer.alloc(maximum + 1));
  await fs.writeFile(path.join(roots.work, 'version'), "console.log('8.30.1');");
  await fs.writeFile(path.join(roots.work, 'stdin'), "process.stdin.resume();process.stdin.on('end',()=>console.log('[]'));");
  const tool = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: '8.30.1' };
  const config = { ...defaults, timeoutMs: 15000, maxOutputBytes: 1048576, tools: { gitleaks: tool } };
  const plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: directory, repoId: hash(directory),
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest([]), dirty: false, files: [], exclusions: [], blockers: [],
    languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '',
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  const limits = { wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 8 * 1048576 };
  const expected = { jobId: randomUUID(), config, limits, root: directory, mappedRoot: '/repo/fixture', runtime: { nodeVersion: process.versions.node } };
  const registration = [], processes = [], records = [], samples = [];
  class MappedDisk extends JobDisk {
    register(root) {
      registration.push(root);
      const mapped = { '/work': roots.work, '/tmp': roots.tmp, '/dev/shm': scenario === 'unmeasurable' ? path.join(directory, 'missing') : roots.shm };
      super.register(mapped[root] ?? root);
    }
  }
  const hostDisk = new JobDisk(Number.MAX_SAFE_INTEGER); hostDisk.register(roots.host);
  const proc = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(),
    platform: 'linux', version: process.version, exitCode: undefined });
  const options = { nonce: expected.jobId, maxOutputBytes: config.maxOutputBytes, retainedBytes: limits.retainedBytes,
    ...(enabled && channel.jobDiskSampleLimit ? { diskSampleLimit: channel.jobDiskSampleLimit(limits) } : {}) };
  const decoder = new channel.JobFrameDecoder({ ...options, sender: 'controller' });
  const writer = channel.createJobFrameWriter({ ...options, sender: 'host' }), assembler = new channel.JobRecordAssembler(config.maxOutputBytes);
  let incoming = Promise.resolve(), report, driverError;
  const reply = fields => proc.stdin.write(writer.encode(fields).bytes);
  proc.stdout.on('data', bytes => {
    incoming = incoming.then(async () => {
      for (const frame of decoder.push(bytes)) {
        if (frame.type === 'disk-sample') {
          samples.push(frame.bytes);
          const local = await hostDisk.check();
          reply({ type: 'disk-ack', sampleSeq: frame.seq, cause: frame.bytes === null ? 'job_disk_observation_unverified'
            : local + BigInt(frame.bytes) > BigInt(maximum) ? 'job_disk_measured_limit' : null });
          continue;
        }
        const message = assembler.accept(frame);
        if (!message) continue;
        if (message.type === 'record') {
          records.push(message.kind);
          if (message.kind === 'report') report = JSON.parse(message.parts[0]);
        }
        reply({ type: 'ack', ackSeq: message.ackSeq, disposition: 'accepted' }); assembler.acknowledged(message.ackSeq);
      }
    }).catch(error => { driverError = error; proc.stdin.destroy(); });
  });
  const adapters = plan.required.map((engine, index) => ({ capabilities: () => ({ engine }), async run(context) {
    if (index === (prior ? 1 : 0) && ['host', 'work', 'tmp', 'shm', 'sum', 'engine-end'].includes(scenario)) {
      const file = path.join(scenario === 'host' || scenario === 'sum' ? roots.host : scenario === 'engine-end' ? roots.work : roots[scenario], 'growth');
      if (scenario === 'sum') await fs.writeFile(path.join(roots.work, 'sum'), Buffer.alloc(maximum / 2));
      if (scenario === 'engine-end') await fs.writeFile(file, Buffer.alloc(maximum + 1));
      else {
        const marker = path.join(directory, 'child.pid');
        const code = `require('fs').writeFileSync(${JSON.stringify(marker)},String(process.pid));setTimeout(()=>require('fs').writeFileSync(${JSON.stringify(file)},Buffer.alloc(${scenario === 'sum' ? maximum / 2 : maximum + 1})),200);setTimeout(()=>process.exit(0),1000);`;
        const parent = `require('child_process').spawn(process.execPath,['-e',${JSON.stringify(code)}],{stdio:'inherit',windowsHide:true});setTimeout(()=>process.exit(0),1200);`;
        const result = await execute({ ...tool, version: process.versions.node }, ['-e', parent], { cwd: roots.work, home: roots.work,
          timeoutMs: 12000, maxOutputBytes: 4096, signal: context.signal, onSpawn: pid => processes.push(pid) });
        processes.push(Number(await fs.readFile(marker, 'utf8')));
        assert.equal(result.reason, 'job_disk_measured_limit');
      }
    }
    const run = { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
    if (index === 0 && prior === 'ERROR') { run.execution = 'failed'; run.errors.push('earlier_error'); }
    if (index === 0 && prior === 'FAIL') run.findings = normalizeGitleaks([{ RuleID: 'fixture', File: 'source.ts', StartLine: 1 }],
      { ...context, plan: { ...context.plan, files: [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 0, sha256: hash('') }] } });
    return run;
  } }));
  const dependencies = { process: proc, buildPlan: async () => plan,
    scan: (p, c, _work, signal, _adapters, backend, budget, disk) => scan(p, c, roots.work, signal, adapters, backend, budget, disk),
    checkedText: async text => text, CheckpointOwnerStop, digest, hash, record,
    validateJobBootstrap: value => value, validateJobPlan: value => value,
    createJobFrameWriter: channel.createJobFrameWriter, JobFrameDecoder: channel.JobFrameDecoder,
    jobFailureCodes: channel.jobFailureCodes, jobRecordFrames: channel.jobRecordFrames,
    scopedCopyBudget, withCopyBudget, JobDisk: MappedDisk, jobDiskPollMs, scopedJobDisk, withJobDisk,
    jobDiskSampleLimit: channel.jobDiskSampleLimit };
  const running = contained(() => new AsyncFunction(...Object.keys(dependencies), source)(...Object.values(dependencies)));
  proc.stdin.write(JSON.stringify({ schema: 'scanmux.job-controller-init/v1', nonce: expected.jobId, expected, limits,
    ...(enabled ? { maxJobDiskBytes: maximum } : {}) }) + '\n');
  await running; await incoming;
  if (driverError) throw driverError;
  assert.equal(proc.exitCode, 0); assert.ok(report, 'the controller must finish its normal report');
  assert.equal(Object.hasOwn(report.plan, 'maxJobDiskBytes'), false);
  assert.equal(Object.hasOwn(config, 'maxJobDiskBytes'), false);
  assert.equal(records.at(-1), 'report');
  if (enabled) for (const root of ['/work', '/tmp', '/dev/shm']) assert.ok(registration.includes(root), root);
  else { assert.deepEqual(registration, []); assert.deepEqual(samples, []); }
  assert.ok(!registration.includes('/app'));
  for (const pid of processes) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  return { report, samples };
}

for (const scenario of ['host', 'work', 'tmp', 'shm', 'sum', 'engine-end', 'under', 'unmeasurable', 'absent']) {
  test('Linux controller measured disk: ' + scenario, { timeout: 25000 }, async t => {
    const { report } = await runController(t, scenario);
    const stopped = !['under', 'absent'].includes(scenario), cause = scenario === 'unmeasurable' ? 'job_disk_observation_unverified' : 'job_disk_measured_limit';
    assert.equal(report.gate, !stopped ? 'PASS' : scenario === 'unmeasurable' ? 'ERROR' : 'INCOMPLETE', JSON.stringify(report.reasons));
    if (stopped) assert.ok(report.engines.some(engine => engine.errors.includes(cause)), JSON.stringify(report.reasons));
  });
}

for (const prior of ['FAIL', 'ERROR']) test('Linux controller measured disk preserves earlier ' + prior, { timeout: 25000 }, async t => {
  const { report } = await runController(t, 'engine-end', prior);
  assert.equal(report.gate, prior, JSON.stringify(report.reasons));
  assert.ok(report.reasons.includes('job_disk_measured_limit'));
});
