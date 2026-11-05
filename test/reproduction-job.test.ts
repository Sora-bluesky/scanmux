import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { defaults } from '../src/config.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { digest, hash } from '../src/safety.ts';
import { jobPayloadResources, type JobProfile } from '../src/job-config.ts';
import { verifyFinding } from '../src/job-runner.ts';
import { main } from '../src/cli.ts';
import { readVerification, testIdentity, assessVerification, admitVerification, verificationPolicy, validateReproductionPlan, reproductionBinding, type ProbeResult, type ReproductionOperation, type ReproductionPlan, type VerificationRecord } from '../src/reproduction.ts';
import { expectedResourceKernel } from '../internal/worker-resources.mjs';
import { createJobFrameWriter, jobRecordFrames, JobFrameDecoder } from '../internal/job-channel.mjs';
import { jobReference, type ExpectedJobPlan, type JobPlan } from '../src/job-records.ts';
import type { Report } from '../src/model.ts';

// Synthetic native owner: actual lifecycle/admission/record code, no Docker or target
// executable. These tests establish coordination and fail-closed evidence, not Linux isolation.
const fixtureMaxOutputBytes = 1048576;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const base = 'a'.repeat(40), head = 'b'.repeat(40), selection = { engine: 'codex-security' as const, fingerprint: 'f'.repeat(64) };
const testFile = { path: 'tests/repro/test.mjs', mode: '100644' as const, bytes: 30, sha256: hash('user nominated regression oracle') };
const sourceFiles = [{ path: 'app.mjs', oid: '1'.repeat(40), bytes: 20, sha256: hash('vulnerable') },
  { path: testFile.path, oid: '2'.repeat(40), bytes: testFile.bytes, sha256: testFile.sha256 }];
class FakeProcess extends EventEmitter {
  stdin = new PassThrough(); stdout = new PassThrough(); stderr = new PassThrough(); pid = undefined;
  kill() { this.stdout.end(); this.stderr.end(); setImmediate(() => this.emit('close', 0)); return true; }
}
type Scenario = 'pair' | 'base_negative' | 'still' | 'missing' | 'image' | 'head_missing' | 'head_changed' | 'failed' | 'changed' | 'cleanup' | 'mutated' | 'binding_changed' | 'binding_missing';
async function fixture(t: import('node:test').TestContext, scenario: Scenario, retainedBytes = 16 * fixtureMaxOutputBytes, severity: 'critical' | 'medium' = 'critical', twoFindings = false) {
  const directory = await mkdtemp(path.join(tmpdir(), 'repro-')), target = path.join(directory, 'target'); await mkdir(target);
  const controllerTemp = path.join(directory, 'tmp'); await mkdir(controllerTemp);
  const previousTemp = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  process.env.TEMP = controllerTemp; process.env.TMP = controllerTemp; process.env.TMPDIR = controllerTemp;
  const dockerPath = path.join(directory, 'synthetic-docker.exe'), leakPath = path.join(directory, 'synthetic-gitleaks');
  await writeFile(dockerPath, 'synthetic docker'); await writeFile(leakPath, 'synthetic gitleaks');
  const tool = { path: dockerPath, version: '27.1.2', sha256: hash('synthetic docker') };
  const profile: JobProfile = { schema: 'scanmux.job-profile/v1', name: 'synthetic_reproduction_owner', scope: 'offline-local',
    docker: { tool, endpoint: process.platform === 'win32' ? 'npipe:////./pipe/dockerDesktopLinuxEngine' : 'unix:///var/run/docker.sock' }, image: 'sha256:' + 'd'.repeat(64),
    runtime: { nodeVersion: '24.22.1', python: { path: '/usr/bin/python3', version: '3.11.2', sha256: 'e'.repeat(64) }, git: { path: '/usr/bin/git', version: '2.54.0', sha256: 'e'.repeat(64) } },
    tools: { gitleaks: { path: leakPath, sha256: hash('synthetic gitleaks'), version: '8.30.1' } }, osvDatabase: null,
    scan: { timeoutMs: 1000, maxOutputBytes: fixtureMaxOutputBytes, maxFileBytes: 65536, maxSnapshotBytes: 1048576, maxFiles: 100 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 10000, cleanupTimeoutMs: 10000, retainedBytes } };
  const profilePath = path.join(directory, 'profile.json'); await writeFile(profilePath, encode(profile));
  const mappedRoot = '/repo/' + hash(target);
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: mappedRoot, repoId: hash(mappedRoot), commit: base, treeHash: 'c'.repeat(40),
    files: sourceFiles, snapshotHash: digest(sourceFiles), dirty: false, exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'],
    policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  const engines = plan.required.map(engine => {
    const run = emptyRun(engine, { plan, config: defaults, workspace: '/work', snapshot: '/work/snapshot', secretsCleared: true, signal: new AbortController().signal });
    run.execution = 'completed'; run.coverage = 'analyzed';
    if (engine === selection.engine) run.findings.push({ ...selection, category: 'code', severity, confidence: 'high', evidenceState: 'candidate', disposition: 'open', file: 'app.mjs', line: 1,
      title: 'Synthetic finding', originIds: [], fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' });
    return run;
  });
  if (twoFindings) engines[2].findings.push({ ...engines[2].findings[0], fingerprint: '7'.repeat(64) });
  const judgment = decide(plan, engines);
  const source: Report = { schema: 'scanmux.report/v2', runId: '11111111-1111-4111-8111-111111111111', plan, engines, startedAt: '2026-10-31T00:00:00.000Z', endedAt: '2026-10-31T00:00:00.000Z',
    runner: { platform: 'linux', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' }, executionState: 'completed', coverageState: 'complete', ...judgment, exitCode: exitCodes[judgment.gate], integrityErrors: [] };
  const sourceBytes = encode(source), reportPath = path.join(directory, 'original.json'); await writeFile(reportPath, sourceBytes);
  const launches: string[] = [], calls: string[][] = [], jobs: { id: string; name: string; args: string[]; removed: boolean; running: boolean; expected?: ExpectedJobPlan; operation?: ReproductionOperation }[] = [];
  const originalSpawn = childProcess.spawn;
  childProcess.spawn = ((file: string, args: string[], options: unknown) => {
    launches.push(file);
    if (file !== dockerPath) {
      assert.match(file, /powershell(?:\.exe)?$/i, 'no host project/test/tool/provider executable');
      return originalSpawn(file, args, options as childProcess.SpawnOptions);
    }
    const tail = args.slice(4); calls.push(tail);
    const child = new FakeProcess();
    const finish = (code: number, value = '') => setImmediate(() => { child.stdout.end(value); child.stderr.end(); setImmediate(() => child.emit('close', code)); });
    if (tail[0] === 'version') {
      if (scenario === 'missing') finish(1);
      else finish(0, JSON.stringify(tail.at(-1) === '{{json .Server}}' ? { Os: 'linux' } : { Client: { Version: tool.version }, Server: { Os: 'linux', Arch: 'amd64' } }));
    } else if (tail[0] === 'image') finish(scenario === 'image' ? 1 : 0, scenario === 'image' ? '' : JSON.stringify([{ Id: profile.image, Os: 'linux', Architecture: 'amd64', Config: { Volumes: {}, Env: [], Labels: {} } }]));
    else if (tail[0] === 'create') {
      assert.ok(jobs.every(job => job.removed), 'previous container must be removed before the next create');
      assert.ok(tail.includes('--pull=never') && tail.includes('--read-only') && tail.includes('1000:1000') && tail.includes('ALL') && tail.includes('no-new-privileges'));
      const id = String(jobs.length + 1).repeat(64), name = tail[tail.indexOf('--name') + 1]; jobs.push({ id, name, args: tail, removed: false, running: false }); finish(0, id + '\n');
    } else if (tail[0] === 'start') {
      const job = jobs.find(job => job.id === tail.at(-1))!; job.running = true;
      let seq = 0, stage = 0, expected: ExpectedJobPlan, operation: ReproductionOperation;
      let writer: ReturnType<typeof createJobFrameWriter>, decoder: JobFrameDecoder;
      const outer = (type: string, fields: Record<string, unknown>) => child.stdout.write(JSON.stringify({ v: 1, nonce: expected.jobId, seq: ++seq, type, ...fields }) + '\n');
      const boundary = () => ({ kernel: expectedResourceKernel(jobPayloadResources(profile.limits)), pidsMax: profile.limits.pids, uid: 1000, gid: 1000,
        capabilitiesZero: true, noNewPrivileges: true, seccomp: 2, supervisorNonDumpable: true, childSupervisorAccessDenied: true, rootReadonly: true,
        boundedWritableStoresOnly: true, privateNamespaces: true, networkCounters: Array(16).fill(0), cpuThrottledPeriods: 0, oomKills: 0 });
      const sendRecord = (kind: 'plan' | 'report', payload: unknown) => {
        for (const frame of jobRecordFrames(writer, ++stage, kind, 0, [encode(payload)])) {
          for (let offset = 0; offset < frame.bytes.length; offset += 16384) outer('data', { data: frame.bytes.subarray(offset, offset + 16384).toString('base64') });
        }
      };
      let guard: ReturnType<typeof import('../src/reproduction.ts').guardTest>;
      let reproductionPlan: ReproductionPlan;
      const sendPlan = () => {
        const p = structuredClone(plan);
        if (operation.side === 'after') { p.commit = head; p.treeHash = '9'.repeat(40); p.files[0].sha256 = hash('corrected'); p.files[0].oid = '3'.repeat(40); p.snapshotHash = digest(p.files); }
        p.policyHash = digest(expected.config); p.comparison = { schema: 'scanmux.comparison/v1', baseCommit: expected.comparison!.base, headCommit: operation.commit,
          baseTree: plan.treeHash!, headTree: p.treeHash!, scope: 'full_head', baseline: 'not_compared', changes: operation.side === 'after' ? [{ path: 'app.mjs', kind: 'modified' }] : [] };
        p.planHash = digest({ ...p, planHash: '' });
        const test = testIdentity('tests/repro', [testFile], { imageDigest: expected.image, profileSha256: expected.profileSha256, nodeVersion: expected.runtime.nodeVersion,
          driverSha256: expected.runtime.app.find(file => file.path === 'internal/reproduction-driver.mjs')!.sha256, assetsSha256: digest(expected.runtime.app) });
        guard = scenario === 'changed' || scenario === 'head_changed' && operation.side === 'after' ? { kind: 'rejected', reason: 'test_changed' } : { kind: operation.mode.kind === 'snapshot' ? 'single_snapshot' : 'unchanged', test };
        const jobPlan: JobPlan = { schema: 'scanmux.job-plan/v1', jobId: expected.jobId, profileSha256: expected.profileSha256, origin: { root: target, repoId: hash(target) },
          mappedRoot, config: expected.config, configSha256: digest(expected.config), limits: profile.limits, image: profile.image, runtime: expected.runtime, destination: expected.destination,
          requestedComparison: expected.comparison!, plan: p };
        sendRecord('plan', reproductionPlan = { schema: 'scanmux.reproduction-plan/v1', operation, job: jobPlan, testModes: { [testFile.path]: testFile.mode }, testGuard: guard });
      };
      const sendResult = () => {
        const result: ProbeResult = scenario === 'changed' || scenario === 'head_changed' && operation.side === 'after' ? { kind: 'not_run', reason: 'test_guard_rejected' }
          : scenario === 'failed' ? { kind: 'failed', reason: 'invalid_observation' } : scenario === 'mutated' ? { kind: 'failed', reason: 'integrity_error' }
            : scenario === 'head_missing' && operation.side === 'after' ? { kind: 'environment_missing', reason: 'fixture_missing' }
              : { kind: 'completed', outcome: scenario === 'base_negative' || operation.side === 'after' && scenario !== 'still' ? 'not_reproduced' : 'reproduced' };
        const binding = reproductionBinding(reproductionPlan);
        sendRecord('report', { schema: 'scanmux.reproduction-result/v1', jobId: expected.jobId,
          ...(scenario === 'binding_missing' ? {} : { bindingDigest: scenario === 'binding_changed' ? '0'.repeat(64) : binding ? digest(binding) : null }), result });
      };
      child.stdin.on('data', bytes => {
        const packet = JSON.parse(bytes.toString());
        if (packet.type === 'init') {
          expected = packet.payload.expected; operation = packet.payload.operation; job.expected = expected; job.operation = operation;
          writer = createJobFrameWriter({ nonce: expected.jobId, sender: 'controller', maxOutputBytes: profile.scan.maxOutputBytes, retainedBytes: profile.limits.retainedBytes });
          decoder = new JobFrameDecoder({ nonce: expected.jobId, sender: 'host', maxOutputBytes: profile.scan.maxOutputBytes, retainedBytes: profile.limits.retainedBytes });
          setImmediate(() => outer('ready', { sampleNs: '1234', boundary: boundary() }));
        } else if (packet.type === 'start') setImmediate(sendPlan);
        else if (packet.type === 'input') {
          for (const frame of decoder.push(Buffer.from(packet.data, 'base64'))) {
            assert.equal(frame.type, 'ack');
            if (stage === 1) setImmediate(sendResult);
            else setImmediate(() => {
              job.running = false;
              outer('closed', { boundary: boundary(), rootTerminal: { exitCode: 0, signal: null }, allOwnedTasksReaped: true,
                counts: Object.fromEntries(['fork', 'vfork', 'clone', 'exec', 'exitEvent', 'signal', 'seccomp', 'interrupt', 'allStop', 'writes', 'execMigrations'].map(key => [key, 0])),
                stopReason: null, controllerCompleted: true, interruption: null });
              child.stdout.end(); child.stderr.end(); setImmediate(() => child.emit('close', 0));
            });
          }
        } else if (packet.type === 'stop') child.kill();
      });
    } else if (tail[0] === 'inspect') {
      const job = jobs.find(job => job.id === tail[1] || job.name === tail[1]);
      if (!job || job.removed) finish(1);
      else {
        const create = job.args, mounts = create.flatMap((arg, i) => arg === '--mount' ? [Object.fromEntries(create[i + 1].split(',').map(part => part.split('=')))] : []);
        finish(0, JSON.stringify([{ Id: job.id, Name: '/' + job.name, Image: profile.image,
          Config: { Labels: { 'scanmux.job': job.name.slice('scanmux-job-'.length) }, User: '1000:1000', Tty: false, OpenStdin: true, WorkingDir: '/work', Env: [],
            Entrypoint: ['/usr/bin/python3'], Cmd: ['-I', '-B', '/app/internal/linux-job-supervisor.py', job.name.slice('scanmux-job-'.length), '10000', String(profile.scan.maxOutputBytes)], Healthcheck: { Test: ['NONE'] } },
          HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, AutoRemove: false, PidMode: '', IpcMode: 'private', CgroupnsMode: 'private', UTSMode: '', CapAdd: [], CapDrop: ['ALL'],
            SecurityOpt: ['no-new-privileges'], PortBindings: {}, LogConfig: { Type: 'none' }, Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=8388608,mode=1777', '/work': 'rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=1000,gid=1000' },
            PidsLimit: 64, NanoCpus: 1000000000, Memory: 268435456, MemorySwap: 268435456, ShmSize: 1048576,
            Mounts: mounts.map(m => ({ Type: 'bind', Source: m.source, Target: m.target, ReadOnly: true })) },
          Mounts: mounts.map(m => ({ Type: 'bind', Destination: m.target, RW: false })), State: { Running: job.running, ExitCode: 0, OOMKilled: false } }]));
      }
    } else if (tail[0] === 'rm') {
      const job = jobs.find(job => job.id === tail[1])!;
      if (scenario === 'cleanup') finish(1); else { job.removed = true; finish(0); }
    } else if (tail[0] === 'ps') finish(0, jobs.filter(job => !job.removed).map(job => job.id).join('\n'));
    else if (tail[0] === 'kill') { const job = jobs.find(job => job.id === tail.at(-1))!; job.running = false; finish(0); }
    else if (tail[0] === 'wait') finish(0, '0\n');
    else throw Error('unexpected synthetic docker operation');
    return child as unknown as childProcess.ChildProcess;
  }) as typeof childProcess.spawn;
  syncBuiltinESMExports();
  t.after(async () => {
    childProcess.spawn = originalSpawn; syncBuiltinESMExports();
    for (const [key, value] of Object.entries(previousTemp)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    await rm(directory, { recursive: true, force: true });
  });
  return { directory, target, source, sourceBytes, reportPath, profilePath, profile, calls, launches, jobs,
    cli: async (snapshot = false) => {
      const originalWrite = process.stdout.write; let output = '';
      process.stdout.write = ((bytes: string | Uint8Array) => { output += typeof bytes === 'string' ? bytes : Buffer.from(bytes).toString(); return true; }) as typeof process.stdout.write;
      try {
        const code = await main(['reproduce', target, '--job-profile', profilePath, '--from', reportPath, '--finding', selection.engine + ':' + selection.fingerprint,
          '--test', 'tests/repro', '--json', ...(snapshot ? [] : ['--base', base, '--head', head])]);
        return { code, record: JSON.parse(output) as VerificationRecord };
      } finally { process.stdout.write = originalWrite; }
    },
    run: (snapshot = false) => verifyFinding(target, profilePath, { reportPath, finding: selection, testDirectory: 'tests/repro',
      mode: snapshot ? { kind: 'snapshot', requirement: 'supporting' } : { kind: 'before_after', base, head } }, new AbortController().signal) };
}

test('reproduction refuses macOS hosts before reading job inputs', { skip: process.platform !== 'darwin' }, async () => {
  await assert.rejects(verifyFinding(path.resolve('target'), path.resolve('profile.json'), {
    reportPath: path.resolve('report.json'), finding: selection, testDirectory: 'tests/repro', mode: { kind: 'snapshot', requirement: 'supporting' },
  }, new AbortController().signal), { code: 'unsupported_job_host' });
});

test('synthetic owner: same committed oracle, two fresh removed jobs, immutable source and three validated projections', { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'pair'), result = await f.run(), directory = path.dirname(result.files.json);
  const firstReceipt = JSON.parse(await readFile(path.join(directory, 'before', 'reproduction-job.json'), 'utf8'));
  assert.equal(result.verification.kind, 'same_test_no_longer_reproduces', JSON.stringify({ facts: firstReceipt.facts, outcome: firstReceipt.outcome, plan: firstReceipt.plan, observation: firstReceipt.observation })); assert.equal(result.assessment.gate, 'FAIL'); assert.equal(result.assessment.exitCode, 1);
  const saved = await readVerification(directory, f.profile.scan.maxOutputBytes);
  assert.equal(saved.runtimeEvidence?.state, 'runtime_reproduced'); assert.equal(saved.runtimeEvidence?.binding.snapshot.commit, base);
  assert.equal(saved.comparison?.baseline, 'not_compared'); assert.equal(saved.comparison?.scope, 'full_head');
  assert.equal(f.jobs.length, 2); assert.ok(f.jobs.every(job => job.removed));
  assert.notEqual(f.jobs[0].id, f.jobs[1].id); assert.notEqual(f.jobs[0].expected!.destination, f.jobs[1].expected!.destination);
  assert.deepEqual(await readFile(f.reportPath), f.sourceBytes); assert.deepEqual(await readFile(path.join(directory, 'source-report.json')), f.sourceBytes);
  assert.equal(saved.attempts?.kind, 'before_after');
  if (saved.attempts?.kind !== 'before_after' || !('binding' in saved.attempts.after)) throw Error('pair missing');
  assert.equal(saved.attempts.before.binding?.testId, saved.attempts.after.binding?.testId);
  for (const side of ['before', 'after']) {
    const plan = JSON.parse(await readFile(path.join(directory, side, 'job-plan.json'), 'utf8'));
    const observation = JSON.parse(await readFile(path.join(directory, side, 'observation.json'), 'utf8'));
    assert.equal(observation.bindingDigest, digest(reproductionBinding(plan)));
  }
  assert.deepEqual(f.jobs[1].operation!.expectedTest?.files, [testFile]);
  const html = await readFile(result.files.html, 'utf8'), sarif = JSON.parse(await readFile(result.files.sarif, 'utf8'));
  assert.match(html, /The same test no longer reproduces at head, with the test unchanged\./);
  assert.equal(sarif.runs[0].tool.driver.name, 'ScanMux reproduction'); assert.equal(sarif.runs[0].results[0].properties['scanmux.assessment'].gate, 'FAIL');
  assert.doesNotMatch(html + JSON.stringify(sarif), /Synthetic finding|stdout|stderr|suppression|baselineState|false_positive/);
  assert.deepEqual(await readdir(f.target), []);
  for (const job of f.jobs) await assert.rejects(readdir(path.join(job.expected!.destination, 'app')));
  assert.notEqual(saved.attempts.before.binding?.executionPlanHash, f.source.plan.planHash, 'a different execution plan context must not reject the same snapshot');
  const source = admitVerification(f.target, f.sourceBytes, { reportPath: f.reportPath, finding: selection, testDirectory: 'tests/repro', mode: { kind: 'before_after', base, head } });
  assert.equal(assessVerification(source, saved.testGuard, saved.attempts).runtimeEvidence, null, 'serialized attempts do not create live evidence');
  assert.equal(verificationPolicy(f.source, selection, saved.runtimeEvidence, false).gate, 'REVIEW', 'saved booleans cannot import runtime promotion');
  const receiptPath = path.join(directory, 'before', 'reproduction-job.json'), receipt = await readFile(receiptPath);
  await writeFile(receiptPath, Buffer.concat([receipt, Buffer.from(' ')])); await assert.rejects(readVerification(directory, f.profile.scan.maxOutputBytes));
  await rm(directory, { recursive: true, force: true });
});

for (const [evidenceState, integrityErrors, sourceGate, gate, code] of [
  ['source_supported', [], 'FAIL', 'FAIL', 1], ['candidate', [], 'REVIEW', 'INCOMPLETE', 3],
  ['source_supported', ['source_integrity_error'], 'ERROR', 'ERROR', 4],
] as const) test('missing environment preserves verification gate order from ' + sourceGate, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'missing'), original = structuredClone(f.source);
  original.engines[2].findings[0].evidenceState = evidenceState; original.integrityErrors = [...integrityErrors];
  const judgment = decide(original.plan, original.engines, original.integrityErrors);
  Object.assign(original, judgment, { exitCode: exitCodes[judgment.gate] }); assert.equal(original.gate, sourceGate);
  const bytes = encode(original); await writeFile(f.reportPath, bytes);
  const result = await f.cli(true);
  assert.deepEqual(result.record.verification, { kind: 'not_verified', reason: 'environment_missing' });
  assert.equal(result.code, code); assert.equal(result.record.assessment.gate, gate); assert.equal(result.record.assessment.exitCode, code);
  assert.deepEqual(await readFile(f.reportPath), bytes);
});

for (const [scenario, snapshot, reason, gate, code] of [
  ['missing', true, 'environment_missing', 'INCOMPLETE', 3], ['image', true, 'environment_missing', 'INCOMPLETE', 3],
  ['failed', true, 'test_failed', 'INCOMPLETE', 3], ['changed', true, 'test_guard_rejected', 'INCOMPLETE', 3],
  ['base_negative', false, 'before_not_reproduced', 'INCOMPLETE', 3], ['still', false, 'still_reproduces', 'INCOMPLETE', 3],
  ['head_missing', false, 'environment_missing', 'INCOMPLETE', 3], ['head_changed', false, 'test_guard_rejected', 'INCOMPLETE', 3],
  ['mutated', true, 'integrity_error', 'ERROR', 4], ['cleanup', true, 'integrity_error', 'ERROR', 4],
  ['binding_changed', true, 'integrity_error', 'ERROR', 4], ['binding_missing', true, 'integrity_error', 'ERROR', 4],
] as const) test('reproduction CLI cannot pass an unverified PASS source: ' + scenario, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, scenario, 16 * fixtureMaxOutputBytes, 'medium');
  assert.equal(f.source.gate, 'PASS'); assert.equal(f.source.exitCode, 0);
  const result = await f.cli(snapshot);
  assert.deepEqual(result.record.verification, { kind: 'not_verified', reason });
  assert.equal(result.code, code); assert.equal(result.record.assessment.gate, gate); assert.equal(result.record.assessment.exitCode, code);
  if (reason === 'integrity_error') assert.equal(result.record.runtimeEvidence, null);
  assert.deepEqual(await readFile(f.reportPath), f.sourceBytes);
});

for (const [scenario, snapshot, kind] of [['pair', false, 'same_test_no_longer_reproduces'], ['pair', true, 'reproduced'], ['base_negative', true, 'not_reproduced']] as const)
  test('reproduction CLI preserves a held PASS result: ' + kind, { skip: process.platform === 'darwin' }, async t => {
    const f = await fixture(t, scenario, 16 * fixtureMaxOutputBytes, 'medium'), result = await f.cli(snapshot);
    assert.equal(result.record.verification.kind, kind); assert.equal(result.record.assessment.gate, 'PASS'); assert.equal(result.code, 0);
    assert.deepEqual(await readFile(f.reportPath), f.sourceBytes);
  });

for (const mutation of ['added', 'removed', 'mode_changed', 'modified'] as const) test('saved and live head plans refuse a test identity mismatch: ' + mutation, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'pair'), result = await f.run(), directory = path.dirname(result.files.json), filename = path.join(directory, 'after', 'job-plan.json');
  const plan = JSON.parse(await readFile(filename, 'utf8')) as ReproductionPlan, headPlan = plan.job.plan;
  if (mutation === 'added') headPlan.files.push({ ...headPlan.files[1], path: 'tests/repro/nested/helper.mjs' });
  else if (mutation === 'removed') headPlan.files = headPlan.files.filter(file => file.path !== testFile.path);
  else if (mutation === 'modified') headPlan.files[1].sha256 = hash('changed oracle');
  if (mutation === 'mode_changed') headPlan.comparison!.changes.push({ path: testFile.path, kind: mutation });
  headPlan.snapshotHash = digest(headPlan.files); headPlan.planHash = digest({ ...headPlan, planHash: '' });
  const record = JSON.parse(await readFile(result.files.json, 'utf8')), receiptPath = path.join(directory, 'after', 'reproduction-job.json');
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8')), planBytes = encode(plan);
  receipt.plan = jobReference(planBytes);
  const receiptBytes = encode(receipt);
  record.attempts.after.binding.snapshot.snapshotHash = headPlan.snapshotHash; record.attempts.after.binding.executionPlanHash = headPlan.planHash;
  Object.assign(record.attempts.after.receipt, jobReference(receiptBytes)); record.comparison = headPlan.comparison;
  const sarif = JSON.parse(await readFile(result.files.sarif, 'utf8')), attempt = sarif.runs[0].results[0].properties['scanmux.attempts'][1];
  attempt.binding = record.attempts.after.binding; attempt.receipt = record.attempts.after.receipt;
  const sarifBytes = encode(sarif);
  for (const [name, bytes] of [['after/job-plan.json', planBytes], ['after/reproduction-job.json', receiptBytes], ['verification.sarif.json', sarifBytes]] as const) {
    await writeFile(path.join(directory, ...name.split('/')), bytes);
    Object.assign(record.files.find((file: { path: string }) => file.path === name), jobReference(bytes));
  }
  await writeFile(result.files.json, encode(record));
  await assert.rejects(readVerification(directory, f.profile.scan.maxOutputBytes), { code: 'invalid_reproduction_record' });
  assert.throws(() => validateReproductionPlan(plan, f.jobs[1].expected!, f.jobs[1].operation!), { code: 'invalid_reproduction_record' });
  assert.deepEqual(await readFile(f.reportPath), f.sourceBytes);
});

test('separate Git modes constrain an otherwise consistently retagged live test identity', { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'pair'), result = await f.run(), directory = path.dirname(result.files.json);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const plan = JSON.parse(await readFile(path.join(directory, 'after', 'job-plan.json'), 'utf8'));
  plan.testGuard.test.files[0].mode = '100755';
  plan.operation.expectedTest = plan.testGuard.test = testIdentity(plan.testGuard.test.directory, plan.testGuard.test.files, plan.testGuard.test.runtime);
  assert.throws(() => validateReproductionPlan(plan, f.jobs[1].expected!, plan.operation), { code: 'invalid_reproduction_record' });
});

test('reproduction mode records must exactly cover the planned test directory with regular Git modes', { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'pair'), result = await f.run(), directory = path.dirname(result.files.json);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const plan = JSON.parse(await readFile(path.join(directory, 'after', 'job-plan.json'), 'utf8'));
  for (const testModes of [{}, { [testFile.path]: '120000' }, { 'app.mjs': '100644' }, { [testFile.path]: '100644', 'tests/repro/extra.mjs': '100644' }]) {
    assert.throws(() => validateReproductionPlan({ ...plan, testModes }, f.jobs[1].expected!, f.jobs[1].operation!), { code: 'invalid_reproduction_record' });
  }
  assert.deepEqual(validateReproductionPlan(plan, f.jobs[1].expected!, f.jobs[1].operation!), plan);
});

for (const snapshot of [false, true]) for (const mutation of ['finding', 'test_id', 'test_mode', 'observation_digest'] as const)
  test('saved observations reject metadata inconsistent with their binding digest: ' + (snapshot ? 'snapshot ' : 'pair ') + mutation, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, 'pair', 16 * fixtureMaxOutputBytes, 'critical', true), result = await f.run(snapshot), directory = path.dirname(result.files.json);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const record = JSON.parse(await readFile(result.files.json, 'utf8')), observations = [];
  const save = async (name: string, bytes: Buffer) => {
    await writeFile(path.join(directory, ...name.split('/')), bytes);
    Object.assign(record.files.find((file: { path: string }) => file.path === name), jobReference(bytes));
  };
  if (mutation === 'finding') record.finding.fingerprint = '7'.repeat(64);
  const sides = snapshot ? ['snapshot'] : ['before', 'after'], attempts = snapshot ? [record.attempts.attempt] : [record.attempts.before, record.attempts.after];
  for (const [index, side] of sides.entries()) {
    const plan = JSON.parse(await readFile(path.join(directory, side, 'job-plan.json'), 'utf8'));
    const receipt = JSON.parse(await readFile(path.join(directory, side, 'reproduction-job.json'), 'utf8'));
    observations.push(await readFile(path.join(directory, side, 'observation.json')));
    plan.operation.finding = record.finding;
    if (mutation === 'test_id') {
      plan.job.runtime.nodeVersion = receipt.expected.runtime.nodeVersion = '24.23.0';
      plan.testGuard.test.runtime.nodeVersion = '24.23.0';
    }
    if (mutation === 'test_mode') plan.testGuard.test.files[0].mode = '100755';
    const test = plan.testGuard.test = testIdentity(plan.testGuard.test.directory, plan.testGuard.test.files, plan.testGuard.test.runtime);
    if (side === 'after') plan.operation.expectedTest = test;
    receipt.operation = plan.operation;
    if (mutation === 'observation_digest') {
      const observation = JSON.parse(observations.at(-1)!.toString()); observation.bindingDigest = '0'.repeat(64);
      const bytes = encode(observation); receipt.observation = jobReference(bytes); await save(side + '/observation.json', bytes);
    }
    const planBytes = encode(plan); receipt.plan = jobReference(planBytes);
    const receiptBytes = encode(receipt), attempt = attempts[index];
    attempt.binding.finding = record.finding; attempt.binding.testId = test.testId;
    Object.assign(attempt.receipt, jobReference(receiptBytes));
    if (index === 0) record.testGuard = plan.testGuard;
    await save(side + '/job-plan.json', planBytes); await save(side + '/reproduction-job.json', receiptBytes);
  }
  record.runtimeEvidence.binding = attempts[0].binding; record.runtimeEvidence.attemptReceipt = attempts[0].receipt;
  const html = (await readFile(result.files.html, 'utf8')).replace(selection.engine + ':' + selection.fingerprint, record.finding.engine + ':' + record.finding.fingerprint);
  await save('verification.html', Buffer.from(html));
  const sarif = JSON.parse(await readFile(result.files.sarif, 'utf8')), finding = sarif.runs[0].results[0], properties = finding.properties;
  finding.partialFingerprints['scanmux.sourceFingerprint'] = record.finding.fingerprint; properties['scanmux.finding'] = record.finding;
  properties['scanmux.attempts'] = attempts.map(attempt => ({ receipt: attempt.receipt, binding: attempt.binding, outcome: attempt.kind }));
  properties['scanmux.evidence'] = record.runtimeEvidence; await save('verification.sarif.json', encode(sarif));
  await writeFile(result.files.json, encode(record));
  await assert.rejects(readVerification(directory, f.profile.scan.maxOutputBytes), { code: mutation === 'test_mode' ? 'invalid_reproduction_record' : 'integrity_error' });
  assert.deepEqual(await readFile(path.join(directory, 'source-report.json')), f.sourceBytes);
  assert.deepEqual(await readFile(f.reportPath), f.sourceBytes);
  if (mutation !== 'observation_digest') for (const [index, side] of sides.entries()) assert.deepEqual(await readFile(path.join(directory, side, 'observation.json')), observations[index]);
});

for (const scenario of ['base_negative', 'still', 'head_missing', 'head_changed', 'failed', 'changed', 'cleanup', 'mutated'] as const) test('synthetic owner rejects an unproven pair: ' + scenario, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, scenario), result = await f.run(), directory = path.dirname(result.files.json), saved = await readVerification(directory, f.profile.scan.maxOutputBytes);
  assert.equal(result.verification.kind, 'not_verified');
  assert.equal(result.assessment.gate, ['cleanup', 'mutated'].includes(scenario) ? 'ERROR' : ['still', 'head_missing', 'head_changed'].includes(scenario) ? 'FAIL' : 'INCOMPLETE');
  if (['still', 'head_missing', 'head_changed'].includes(scenario)) assert.equal(saved.runtimeEvidence?.state, 'runtime_reproduced'); else assert.equal(saved.runtimeEvidence, null);
  assert.equal(f.jobs.length, ['failed', 'changed', 'cleanup', 'mutated'].includes(scenario) ? 1 : 2);
  assert.deepEqual(await readFile(f.reportPath), f.sourceBytes); assert.deepEqual(await readdir(f.target), []);
  await rm(directory, { recursive: true, force: true });
});

for (const scenario of ['missing', 'image'] as const) test('synthetic owner: unavailable environment never creates a container or invents a test manifest: ' + scenario, { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t, scenario, 2 * fixtureMaxOutputBytes), result = await f.run(true), directory = path.dirname(result.files.json), saved = await readVerification(directory, f.profile.scan.maxOutputBytes);
  assert.equal(result.assessment.gate, 'INCOMPLETE'); assert.equal(result.assessment.exitCode, 3); assert.equal(saved.runtimeEvidence, null);
  assert.deepEqual(saved.testGuard, { kind: 'not_checked', reason: 'environment_missing' }); assert.equal(f.jobs.length, 0);
  assert.ok(!f.calls.some(args => args[0] === 'create')); assert.equal(saved.attempts?.kind, 'snapshot');
  if (saved.attempts?.kind === 'snapshot') { assert.equal(saved.attempts.attempt.kind, 'environment_missing'); assert.equal(saved.attempts.attempt.job, null); assert.equal(saved.attempts.attempt.binding, null); }
  await rm(directory, { recursive: true, force: true });
});
