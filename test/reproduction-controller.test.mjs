import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { digest, hash, record, SafeError } from '../src/safety.ts';
import { CheckpointOwnerStop } from '../src/engine-checkpoint.ts';
import { validateJobBootstrap, validateJobPlan, validateReproductionBootstrap } from '../src/job-records.ts';
import { guardTest, testIdentity, snapshotIdentity, probeInvocation, validateProbeResult, validateReproductionPlan, reproductionBinding } from '../src/reproduction.ts';
import { isDeepStrictEqual } from 'node:util';
import { scopedCopyBudget, withCopyBudget } from '../src/copy-budget.ts';
import { JobDisk, jobDiskPollMs, withJobDisk } from '../src/job-disk.ts';
import * as channel from '../internal/job-channel.mjs';

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const driver = (await readFile('internal/reproduction-driver.mjs', 'utf8')).replace(/^import .*;\n|^const \{.*\} = await import\('.*'\);\n/gm, '')
  .replace('await import(pathToFileURL(path.join(process.argv[2], directory, \'test.mjs\')).href)', 'await loadProbe()');
for (const [name, observation, expected] of [
  ['positive', { kind: 'observed', problem: 'present' }, { kind: 'completed', outcome: 'reproduced' }],
  ['negative', { kind: 'observed', problem: 'absent' }, { kind: 'completed', outcome: 'not_reproduced' }],
  ['missing prerequisite', { kind: 'environment_missing', reason: 'fixture_missing' }, { kind: 'environment_missing', reason: 'fixture_missing' }],
  ['empty', undefined, { kind: 'failed', reason: 'invalid_observation' }], ['skip', { skipped: true }, { kind: 'failed', reason: 'invalid_observation' }],
  ['unbounded prose', { kind: 'environment_missing', reason: 'arbitrary private prose' }, { kind: 'failed', reason: 'invalid_observation' }],
  ['extra keys', { kind: 'observed', problem: 'absent', skipped: true }, { kind: 'failed', reason: 'invalid_observation' }],
  ['exception', 'throw', { kind: 'failed', reason: 'test_error' }],
]) test('probe driver unit contract: ' + name, async () => {
  // A stub oracle models a return value. No scanned-project code is imported on the host.
  const bindingDigest = '8'.repeat(64), writes = [], proc = { platform: 'linux', getuid: () => 1000, argv: ['node', '/app/internal/reproduction-driver.mjs', '/work/snapshot', 'tests/repro', bindingDigest], exitCode: undefined };
  await new AsyncFunction('process', 'writeSync', 'path', 'pathToFileURL', 'loadProbe', driver)(proc, (fd, bytes) => { assert.equal(fd, 3); writes.push(bytes); }, path, pathToFileURL,
    async () => ({ default: async () => { if (observation === 'throw') throw Error('discarded secret diagnostic'); return observation; } }));
  assert.equal(writes.length, 1); assert.deepEqual(JSON.parse(writes[0]), { schema: 'scanmux.probe-completion/v1', bindingDigest, result: expected });
  assert.doesNotMatch(writes[0], /discarded secret|arbitrary private/);
});

test('probe driver echoes the admitted digest even if the oracle edits its arguments', async () => {
  const bindingDigest = '8'.repeat(64), writes = [], proc = { platform: 'linux', getuid: () => 1000,
    argv: ['node', '/app/internal/reproduction-driver.mjs', '/work/snapshot', 'tests/repro', bindingDigest] };
  await new AsyncFunction('process', 'writeSync', 'path', 'pathToFileURL', 'loadProbe', driver)(proc, (_fd, bytes) => writes.push(bytes), path, pathToFileURL,
    async () => ({ default: async () => { proc.argv[4] = '0'.repeat(64); return { kind: 'observed', problem: 'present' }; } }));
  assert.deepEqual(JSON.parse(writes[0]), { schema: 'scanmux.probe-completion/v1', bindingDigest, result: { kind: 'completed', outcome: 'reproduced' } });
});

const controller = (await readFile('internal/linux-job-controller.mjs', 'utf8')).replace(/^import .*;\n|^const \{.*\} = await import\('.*'\);\n/gm, '');
async function runController(scenario, copyBudgetBytes) {
  const commit = 'a'.repeat(40), head = 'b'.repeat(40), root = '/source', mappedRoot = '/repo/' + hash(root), file = { path: 'tests/repro/test.mjs', mode: ['executable', 'mode_missing_execute', 'mode_mutation'].includes(scenario) ? '100755' : '100644', bytes: 10, sha256: hash('oracle') };
  const config = { ...structuredClone(defaults), maxOutputBytes: 65536, tools: { git: { path: '/usr/bin/git', version: '2.54.0', sha256: 'c'.repeat(64) }, gitleaks: { path: '/tools/gitleaks', version: '8.30.1', sha256: 'd'.repeat(64) } } };
  const limits = { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 10000, cleanupTimeoutMs: 10000, retainedBytes: 1048576 };
  const plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: mappedRoot, repoId: hash(mappedRoot), commit, treeHash: 'c'.repeat(40),
    files: [{ path: file.path, oid: 'd'.repeat(40), bytes: file.bytes, sha256: file.sha256 }], snapshotHash: '', dirty: false, exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 },
    comparison: { schema: 'scanmux.comparison/v1', baseCommit: commit, headCommit: commit, baseTree: 'c'.repeat(40), headTree: 'c'.repeat(40), scope: 'full_head', baseline: 'not_compared', changes: [] } };
  if (scenario === 'excluded') plan.exclusions.push({ path: 'fixture.bin', reason: 'binary_content_unsupported' });
  plan.snapshotHash = digest(plan.files); plan.planHash = digest(plan);
  const expected = { jobId: '11111111-1111-4111-8111-111111111111', profileSha256: 'e'.repeat(64), root, mappedRoot, config, limits, image: 'sha256:' + 'f'.repeat(64), destination: '/retained', comparison: { base: commit, head: commit },
    runtime: { nodeVersion: '24.22.1', python: { path: '/usr/bin/python3', sha256: 'c'.repeat(64), version: '3.11.2' }, git: config.tools.git, tools: config.tools,
      app: ['internal/linux-job-controller.mjs', 'internal/linux-job-supervisor.py', 'internal/reproduction-driver.mjs'].map(path => ({ path, bytes: 1, sha256: 'c'.repeat(64) })) } };
  const operation = { kind: 'reproduction', side: 'before', commit, sourceSnapshot: snapshotIdentity(plan), finding: { engine: 'codex-security', fingerprint: 'f'.repeat(64) }, sourceReportSha256: 'a'.repeat(64),
    testDirectory: 'tests/repro', mode: { kind: 'before_after', base: commit, head }, expectedTest: null };
  const proc = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), platform: 'linux', version: 'v24.22.1', ppid: 1, getuid: () => 1000,
    argv: ['/usr/local/bin/node', '/app/internal/linux-job-controller.mjs'], exitCode: undefined });
  const options = { nonce: expected.jobId, maxOutputBytes: config.maxOutputBytes, retainedBytes: limits.retainedBytes };
  const decoder = new channel.JobFrameDecoder({ ...options, sender: 'controller' }), assembler = new channel.JobRecordAssembler(config.maxOutputBytes), writer = channel.createJobFrameWriter({ ...options, sender: 'host' });
  const records = [], launches = [], commits = [], checks = [], materializations = [], verifications = [];
  let incoming = Promise.resolve(), result, verificationCount = 0;
  proc.stdout.on('data', bytes => {
    incoming = incoming.then(() => {
      for (const frame of decoder.push(bytes)) {
        const message = assembler.accept(frame); if (!message) continue;
        if (message.type === 'record') { const record = JSON.parse(message.parts[0]); records.push(record); if (message.kind === 'report') result = record.result; }
        proc.stdin.write(writer.encode({ type: 'ack', ackSeq: message.ackSeq, disposition: 'accepted' }).bytes); assembler.acknowledged(message.ackSeq);
      }
    });
  });
  const spawn = (file, args, opts) => {
    assert.equal(scopedCopyBudget()?.remainingBytes, copyBudgetBytes);
    assert.equal(records.length, 1, 'plan/test guard must be durably ACKed before a probe launch');
    assert.equal(file, '/usr/local/bin/node'); assert.deepEqual(args.slice(0, 3), ['/app/internal/reproduction-driver.mjs', '/work/snapshot', 'tests/repro']);
    assert.match(args[3], /^[a-f0-9]{64}$/);
    assert.equal(args[3], digest({ snapshot: snapshotIdentity(records[0].job.plan), sourceSnapshot: operation.sourceSnapshot, side: operation.side,
      executionPlanHash: records[0].job.plan.planHash, finding: operation.finding, sourceReportSha256: operation.sourceReportSha256, testId: records[0].testGuard.test.testId }));
    assert.equal(opts.shell, false); assert.deepEqual(opts.env, probeInvocation.environment); assert.deepEqual(opts.stdio, ['ignore', 'pipe', 'pipe', 'pipe']);
    launches.push({ file, args, opts });
    const child = Object.assign(new EventEmitter(), { stdout: new PassThrough(), stderr: new PassThrough(), stdio: [null, null, null, new PassThrough()], kill: () => true });
    setImmediate(() => {
      child.stdout.end('raw target stdout'); child.stderr.end('raw target stderr');
      const observation = { schema: 'scanmux.probe-completion/v1', bindingDigest: scenario === 'binding_changed' ? '0'.repeat(64) : args[3],
        result: { kind: 'completed', outcome: ['positive', 'executable', 'binding_changed', 'binding_missing'].includes(scenario) || scenario.startsWith('mode_') ? 'reproduced' : 'not_reproduced' } };
      if (scenario === 'binding_missing') delete observation.bindingDigest;
      child.stdio[3].end(scenario === 'empty' ? '' : scenario === 'malformed' ? '{}\n' : JSON.stringify(observation) + (scenario === 'duplicate' ? JSON.stringify(observation) : '\n'));
      setImmediate(() => child.emit('close', scenario === 'nonzero' ? 1 : 0, null));
    });
    return child;
  };
  const dependencies = { process: proc, buildPlan: async (_root, _config, _work, _signal, _comparison, capture) => {
    assert.equal(capture.directory, operation.testDirectory); capture.modes.set(file.path, file.mode); return plan;
  }, scan: () => { throw Error('scan/AI engines cannot run during reproduction'); }, checkedText: async text => { checks.push(text); return text; },
    CheckpointOwnerStop, digest, hash, record, validateJobBootstrap, validateJobPlan, validateReproductionBootstrap, guardTest, testIdentity, snapshotIdentity, probeInvocation, validateProbeResult, validateReproductionPlan, reproductionBinding,
    isDeepStrictEqual, spawn, materialize: async (_plan, _config, _work, _signal, modes) => {
      assert.equal(scopedCopyBudget()?.remainingBytes, copyBudgetBytes); materializations.push(modes); return '/work/snapshot';
    }, verifySnapshot: async (_plan, _snapshot, modes) => {
      verifications.push(modes); verificationCount++;
      return !(scenario === 'mutation' && verificationCount > 1 || modes && (['mode_missing_execute', 'mode_unexpected_execute'].includes(scenario) || scenario === 'mode_mutation' && verificationCount > 1));
    },
    readTestFiles: async (_root, _config, _work, sha) => {
      commits.push(sha); if (scenario === 'missing') throw new SafeError('test_missing');
      return [{ ...file, ...(scenario === 'changed' && sha === head ? { sha256: hash('weak oracle') } : {}) }];
    }, createJobFrameWriter: channel.createJobFrameWriter, JobFrameDecoder: channel.JobFrameDecoder, jobFailureCodes: channel.jobFailureCodes, jobRecordFrames: channel.jobRecordFrames,
    jobDiskSampleLimit: channel.jobDiskSampleLimit, scopedCopyBudget, withCopyBudget, JobDisk, jobDiskPollMs, withJobDisk };
  const running = new AsyncFunction(...Object.keys(dependencies), controller)(...Object.values(dependencies));
  proc.stdin.write(JSON.stringify({ schema: 'scanmux.reproduction-controller-init/v1', nonce: expected.jobId, expected, operation, limits,
    ...(copyBudgetBytes === undefined ? {} : { copyBudgetBytes }) }) + '\n');
  await running; await incoming; decoder.finish(); assembler.finish();
  assert.equal(proc.exitCode, 0); assert.doesNotMatch(JSON.stringify(records) + checks.join(''), /raw target stdout|raw target stderr/);
  return { result, launches, commits, records, materializations, verifications };
}
for (const [scenario, expected] of [
  ['positive', { kind: 'completed', outcome: 'reproduced' }], ['negative', { kind: 'completed', outcome: 'not_reproduced' }],
  ['executable', { kind: 'completed', outcome: 'reproduced' }],
  ['mode_missing_execute', { kind: 'failed', reason: 'integrity_error' }], ['mode_unexpected_execute', { kind: 'failed', reason: 'integrity_error' }],
  ['mode_mutation', { kind: 'failed', reason: 'integrity_error' }],
  ['empty', { kind: 'failed', reason: 'invalid_observation' }], ['malformed', { kind: 'failed', reason: 'invalid_observation' }],
  ['duplicate', { kind: 'failed', reason: 'invalid_observation' }], ['nonzero', { kind: 'failed', reason: 'test_error' }],
  ['mutation', { kind: 'failed', reason: 'integrity_error' }], ['changed', { kind: 'not_run', reason: 'test_guard_rejected' }],
  ['binding_changed', { kind: 'failed', reason: 'integrity_error' }], ['binding_missing', { kind: 'failed', reason: 'integrity_error' }],
  ['missing', { kind: 'not_run', reason: 'test_guard_rejected' }], ['excluded', { kind: 'failed', reason: 'integrity_error' }],
]) test('controller synthetic probe protocol: ' + scenario, async () => {
  const actual = await runController(scenario); assert.deepEqual(actual.result, expected);
  assert.equal(actual.launches.length, ['changed', 'missing', 'excluded', 'mode_missing_execute', 'mode_unexpected_execute'].includes(scenario) ? 0 : 1);
  if (actual.launches.length) assert.deepEqual(actual.commits, ['a'.repeat(40), 'b'.repeat(40), 'a'.repeat(40)]);
  const observation = actual.records.at(-1);
  assert.equal(observation.bindingDigest, scenario === 'binding_changed' ? '0'.repeat(64) : scenario === 'binding_missing' || !actual.launches.length ? null : actual.launches[0].args[3]);
});

test('reproduction controller passes recorded test modes to materialization and both integrity checks', async () => {
  for (const scenario of ['positive', 'executable']) {
    const actual = await runController(scenario), modes = actual.records[0].testModes;
    assert.deepEqual(actual.materializations, [modes]); assert.deepEqual(actual.verifications, [modes, modes]);
  }
});

test('reproduction controller preserves zero and safe remaining copy budgets through materialization and probe launch', async () => {
  for (const remaining of [0, 4, Number.MAX_SAFE_INTEGER]) {
    const actual = await runController('positive', remaining);
    assert.deepEqual(actual.result, { kind: 'completed', outcome: 'reproduced' }); assert.equal(actual.launches.length, 1);
  }
});
