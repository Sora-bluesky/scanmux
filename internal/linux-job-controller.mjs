import '../bin/typescript-bootstrap.mjs';
import { spawn } from 'node:child_process';
import { isDeepStrictEqual } from 'node:util';
import { createJobFrameWriter, JobFrameDecoder, jobFailureCodes, jobRecordFrames, jobDiskSampleLimit } from './job-channel.mjs';
const { buildPlan, materialize, readTestFiles, verifySnapshot } = await import('../src/repository.ts');
const { scan } = await import('../src/controller.ts');
const { checkedText } = await import('../src/output.ts');
const { CheckpointOwnerStop } = await import('../src/engine-checkpoint.ts');
const { digest, hash, record } = await import('../src/safety.ts');
const { validateJobBootstrap, validateJobPlan, validateReproductionBootstrap } = await import('../src/job-records.ts');
const { guardTest, testIdentity, snapshotIdentity, probeInvocation, validateProbeResult, validateReproductionPlan, reproductionBinding } = await import('../src/reproduction.ts');
const { scopedCopyBudget, withCopyBudget } = await import('../src/copy-budget.ts');
const { JobDisk, jobDiskPollMs, withJobDisk } = await import('../src/job-disk.ts');

const abort = new AbortController();
const stop = () => abort.abort();
process.on('SIGTERM', stop); process.on('SIGINT', stop);
let decoder, writer, expected, operation, outstanding, copyBudgetBytes, maxJobDiskBytes, disk, diskOutstanding, pendingDiskCause;
let rejected = false, outputStopped = false, recordId = 0, lastDiskSample = -Infinity;
let bootstrap = Buffer.alloc(0), resolveBootstrap, rejectBootstrap;
const initialized = new Promise((resolve, reject) => { resolveBootstrap = resolve; rejectBootstrap = reject; });
const failures = new Set();
function protocolFailure() {
  if (rejected) return;
  rejected = true; abort.abort(); rejectBootstrap(Error('job_protocol_invalid'));
  if (outstanding) { outstanding.reject(Error('job_protocol_invalid')); outstanding = null; }
  if (diskOutstanding) { diskOutstanding.reject(Error('job_protocol_invalid')); diskOutstanding = null; }
}
process.stdin.on('data', bytes => {
  try {
    if (rejected) throw Error();
    if (!decoder) {
      const newline = bytes.indexOf(10), end = newline === -1 ? bytes.length : newline + 1;
      if (bootstrap.length + end > 65536) throw Error();
      bootstrap = Buffer.concat([bootstrap, bytes.subarray(0, end)]);
      if (newline === -1) return;
      const input = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bootstrap)));
      const hasCopyBudget = Object.hasOwn(input, 'copyBudgetBytes');
      const hasJobDisk = Object.hasOwn(input, 'maxJobDiskBytes');
      const reproduction = input.schema === 'scanmux.reproduction-controller-init/v1';
      const keys = ['expected', 'limits', 'nonce', 'schema', ...(reproduction ? ['operation'] : []), ...(hasCopyBudget ? ['copyBudgetBytes'] : []), ...(hasJobDisk ? ['maxJobDiskBytes'] : [])];
      if (Object.keys(input).sort().join(',') !== keys.sort().join(',') || !reproduction && input.schema !== 'scanmux.job-controller-init/v1') throw Error();
      if (hasCopyBudget) {
        if (!Number.isSafeInteger(input.copyBudgetBytes) || input.copyBudgetBytes < 0) throw Error();
        copyBudgetBytes = input.copyBudgetBytes;
      }
      if (hasJobDisk) {
        if (!Number.isSafeInteger(input.maxJobDiskBytes) || input.maxJobDiskBytes <= 0) throw Error();
        maxJobDiskBytes = input.maxJobDiskBytes;
      }
      if (reproduction) ({ expected, operation } = validateReproductionBootstrap({ expected: input.expected, operation: input.operation }));
      else expected = validateJobBootstrap(input.expected);
      if (input.nonce !== expected.jobId || process.platform !== 'linux' || process.version !== 'v' + expected.runtime.nodeVersion) throw Error();
      const limits = record(input.limits);
      if (digest(limits) !== digest(expected.limits)) throw Error();
      const options = { nonce: expected.jobId, maxOutputBytes: expected.config.maxOutputBytes, retainedBytes: limits.retainedBytes,
        ...(hasJobDisk ? { diskSampleLimit: jobDiskSampleLimit(limits) } : {}) };
      decoder = new JobFrameDecoder({ ...options, sender: 'host' }); writer = createJobFrameWriter({ ...options, sender: 'controller' });
      bootstrap = Buffer.alloc(0); resolveBootstrap(); bytes = bytes.subarray(end);
    }
    for (const frame of decoder.push(bytes)) {
      if (frame.type === 'disk-stop') {
        pendingDiskCause ??= frame.cause; disk?.stop(frame.cause); continue;
      }
      if (frame.type === 'disk-ack') {
        if (!diskOutstanding || diskOutstanding.seq !== frame.sampleSeq) throw Error();
        if (frame.cause) { pendingDiskCause ??= frame.cause; disk?.stop(frame.cause); }
        const current = diskOutstanding; diskOutstanding = null; current.resolve(); continue;
      }
      if (!outstanding || frame.type !== 'ack' || frame.ackSeq !== outstanding.seq) throw Error();
      const current = outstanding; outstanding = null;
      if (frame.disposition === 'accepted') current.resolve();
      else {
        outputStopped = true;
        current.reject(new CheckpointOwnerStop(frame.disposition === 'retained' ? 'job_retained_limit' : frame.disposition === 'deadline' ? 'job_deadline' : 'job_cancelled'));
      }
    }
  } catch { protocolFailure(); }
});
process.stdin.on('end', () => { try { decoder?.finish(false); } catch {} protocolFailure(); });
process.stdin.on('error', protocolFailure);
process.stdout.on('error', protocolFailure);
process.stdin.resume();

async function write(bytes) {
  if (rejected || outputStopped || abort.signal.aborted) throw Error('job_protocol_invalid');
  await new Promise((resolve, reject) => process.stdout.write(bytes, error => error ? reject(error) : resolve()));
}
async function writeAndWait(encoded) {
  if (outstanding) throw Error('job_protocol_invalid');
  const acknowledged = new Promise((resolve, reject) => { outstanding = { seq: encoded.seq, resolve, reject }; });
  acknowledged.catch(() => {});
  // Register before writing: an immediate ACK must not race its waiter.
  try { await write(encoded.bytes); await acknowledged; }
  catch (error) { outstanding = null; throw error; }
}
async function failure(code) {
  if (failures.has(code)) return;
  if (!jobFailureCodes.includes(code)) throw Error('job_protocol_invalid');
  await writeAndWait(writer.encode({ type: 'failure', code })); failures.add(code);
}
async function sendRecord(kind, slot, parts) {
  const frames = jobRecordFrames(writer, recordId + 1, kind, slot, parts);
  for (const encoded of frames) {
    // Only the complete record receives an ACK; no chunk can release another engine.
    const frame = JSON.parse(encoded.bytes);
    if (frame.type === 'end') await writeAndWait(encoded); else await write(encoded.bytes);
  }
  recordId++;
}
async function sampleDisk(bytes, force) {
  const now = performance.now();
  // Pre/post-process checks reuse the latest remote sample between periodic ticks;
  // engine-end checks always wait for a fresh combined observation.
  if (bytes !== null && !force && bytes <= BigInt(maxJobDiskBytes) && now - lastDiskSample < jobDiskPollMs) return;
  if (diskOutstanding) throw Error('job_protocol_invalid');
  const encoded = writer.encode({ type: 'disk-sample', bytes: bytes === null ? null : String(bytes) });
  const acknowledged = new Promise((resolve, reject) => { diskOutstanding = { seq: encoded.seq, resolve, reject }; });
  acknowledged.catch(() => {}); lastDiskSample = now;
  try { await write(encoded.bytes); await acknowledged; }
  catch (error) { diskOutstanding = null; throw error; }
}
async function checked(payload, rejectionCode) {
  const text = JSON.stringify(payload, null, 2) + '\n';
  try {
    if (await checkedText(text, expected.config, '/work', abort.signal) !== text) throw Error();
    return Buffer.from(text);
  } catch (error) { await failure(rejectionCode); throw error; }
}
async function executeProbeInJob(admission, test, binding) {
  if (admission !== expected || process.platform !== 'linux' || process.getuid() !== 1000 || process.ppid !== 1
    || process.argv[1] !== '/app/internal/linux-job-controller.mjs' || test.directory !== operation.testDirectory) throw Error('job_boundary_unverified');
  await disk?.check(true);
  const endDisk = disk?.watch();
  const diskStop = () => abort.abort(disk.signal.reason);
  disk?.signal.addEventListener('abort', diskStop, { once: true });
  const expectedDigest = digest(binding);
  let bindingDigest = expectedDigest;
  try { const result = await new Promise(resolve => {
    let size = 0, resultBytes = Buffer.alloc(0), resultSize = 0, forced = null, spawnFailed = false;
    const child = spawn(probeInvocation.executable, [probeInvocation.driver, probeInvocation.root, test.directory, expectedDigest], {
      shell: false, cwd: probeInvocation.cwd, env: { ...probeInvocation.environment }, stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    });
    const stopChild = () => { forced ??= { kind: 'failed', reason: 'cancelled' }; child.kill('SIGKILL'); };
    abort.signal.addEventListener('abort', stopChild, { once: true });
    if (abort.signal.aborted) stopChild();
    for (const stream of [child.stdout, child.stderr]) {
      stream.on('data', bytes => { size += bytes.length; if (size > expected.config.maxOutputBytes) { forced = { kind: 'failed', reason: 'resource_limit' }; child.kill('SIGKILL'); } });
      stream.on('error', () => { forced = { kind: 'failed', reason: 'test_error' }; child.kill('SIGKILL'); });
    }
    child.stdio[3].on('data', bytes => {
      resultSize += bytes.length;
      if (resultSize > 1024) { forced = { kind: 'failed', reason: 'invalid_observation' }; child.kill('SIGKILL'); }
      else resultBytes = Buffer.concat([resultBytes, bytes]);
    });
    child.stdio[3].on('error', () => { forced = { kind: 'failed', reason: 'invalid_observation' }; child.kill('SIGKILL'); });
    child.on('error', () => { spawnFailed = true; });
    child.once('close', (code, signal) => {
      abort.signal.removeEventListener('abort', stopChild);
      if (forced) return resolve(forced);
      if (spawnFailed || code !== 0 || signal !== null) return resolve({ kind: 'failed', reason: 'test_error' });
      try {
        const envelope = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(resultBytes)));
        if (envelope.schema !== 'scanmux.probe-completion/v1') throw Error();
        bindingDigest = typeof envelope.bindingDigest === 'string' && /^[a-f0-9]{64}$/.test(envelope.bindingDigest) ? envelope.bindingDigest : null;
        if (bindingDigest !== expectedDigest) return resolve({ kind: 'failed', reason: 'integrity_error' });
        if (Object.keys(envelope).sort().join(',') !== 'bindingDigest,result,schema') throw Error();
        const result = validateProbeResult(envelope.result);
        if (result.kind === 'not_run' || result.kind === 'environment_missing' && result.reason === 'image_not_available') throw Error();
        resolve(result);
      } catch { resolve({ kind: 'failed', reason: 'invalid_observation' }); }
    });
  }); return { bindingDigest, result }; } finally { disk?.signal.removeEventListener('abort', diskStop); await endDisk?.(); }
}
async function reproduceInJob(job, testModes) {
  let guard = { kind: 'not_checked', reason: 'job_failed' }, result = { kind: 'failed', reason: 'integrity_error' };
  if (!job.plan.blockers.length && !job.plan.exclusions.length) {
    if (job.plan.commit !== operation.commit || operation.side !== 'after' && !isDeepStrictEqual(snapshotIdentity(job.plan), operation.sourceSnapshot)) throw Error('snapshot_integrity');
    const driver = expected.runtime.app.find(file => file.path === 'internal/reproduction-driver.mjs');
    if (!driver) throw Error('job_asset_changed');
    const runtime = { imageDigest: expected.image, profileSha256: expected.profileSha256, nodeVersion: expected.runtime.nodeVersion, driverSha256: driver.sha256, assetsSha256: digest(expected.runtime.app) };
    try {
      const test = testIdentity(operation.testDirectory, await readTestFiles(expected.mappedRoot, expected.config, '/work', operation.commit, operation.testDirectory, abort.signal), runtime);
      if (operation.expectedTest) guard = guardTest(operation.expectedTest, test);
      else if (operation.mode.kind === 'before_after') {
        const other = testIdentity(operation.testDirectory, await readTestFiles(expected.mappedRoot, expected.config, '/work', operation.mode.head, operation.testDirectory, abort.signal), runtime);
        guard = guardTest(test, other);
      } else guard = guardTest(test);
    } catch (error) {
      const reason = ['test_missing', 'unsupported_test', 'unsafe_test_path'].includes(error?.code) ? error.code : 'unsupported_test';
      guard = { kind: 'rejected', reason };
    }
    if (guard.kind === 'rejected') result = { kind: 'not_run', reason: 'test_guard_rejected' };
  }
  const plan = validateReproductionPlan({ schema: 'scanmux.reproduction-plan/v1', operation, job, testModes, testGuard: guard }, expected, operation);
  let bindingDigest = null;
  await sendRecord('plan', 0, [await checked(plan, 'plan_output_rejected')]);
  if ('test' in guard) {
    const snapshot = await materialize(job.plan, expected.config, '/work', abort.signal, plan.testModes);
    if (await verifySnapshot(job.plan, snapshot, plan.testModes)) {
      ({ bindingDigest, result } = await executeProbeInJob(expected, guard.test, reproductionBinding(plan)));
      if (!await verifySnapshot(job.plan, snapshot, plan.testModes)) result = { kind: 'failed', reason: 'integrity_error' };
      const after = testIdentity(operation.testDirectory, await readTestFiles(expected.mappedRoot, expected.config, '/work', operation.commit, operation.testDirectory, abort.signal), guard.test.runtime);
      if (!isDeepStrictEqual(after, guard.test)) result = { kind: 'failed', reason: 'integrity_error' };
    }
  }
  await sendRecord('report', 0, [await checked({ schema: 'scanmux.reproduction-result/v1', jobId: expected.jobId, bindingDigest, result }, 'final_output_rejected')]);
  return 0;
}
async function run() {
  await initialized;
  let plan; const testModes = new Map();
  try { plan = await buildPlan(expected.mappedRoot, expected.config, '/work', abort.signal, expected.comparison, operation ? { directory: operation.testDirectory, modes: testModes } : undefined); }
  catch (error) { await failure('plan_failed'); throw error; }
  const job = validateJobPlan({ schema: 'scanmux.job-plan/v1', jobId: expected.jobId, profileSha256: expected.profileSha256,
    origin: { root: expected.root, repoId: hash(expected.root) }, mappedRoot: expected.mappedRoot,
    config: expected.config, configSha256: digest(expected.config), limits: expected.limits, image: expected.image, runtime: expected.runtime,
    destination: expected.destination, requestedComparison: expected.comparison ?? null, plan }, expected);
  if (!operation) await sendRecord('plan', 0, [await checked(job, 'plan_output_rejected')]);
  if (maxJobDiskBytes !== undefined) {
    // The host owns the combined threshold. This side uses the same regular-file
    // walker, without counting the read-only application bind a second time.
    disk = new JobDisk(Number.MAX_SAFE_INTEGER, sampleDisk);
    for (const root of ['/work', '/tmp', '/dev/shm']) disk.register(root);
    if (pendingDiskCause) disk.stop(pendingDiskCause);
  }
  if (operation) return withJobDisk(disk, () => reproduceInJob(job, Object.fromEntries(testModes)));
  let sequence = 0;
  const backend = { failure: code => failure(code), persist: async (body, receipt) => { await sendRecord('checkpoint', sequence + 1, [body, receipt]); sequence++; } };
  const report = await scan(plan, expected.config, '/work', abort.signal, undefined, backend, scopedCopyBudget(), disk);
  if (outputStopped) return 3;
  if (report.gate === 'ERROR') await failure('controller_integrity_failure');
  await sendRecord('report', 0, [await checked(report, 'final_output_rejected')]);
  return 0;
}
try { await initialized; process.exitCode = await withCopyBudget(copyBudgetBytes, run); }
catch (error) {
  if (!(error instanceof CheckpointOwnerStop) && !outputStopped && !rejected && writer) {
    try { await failure('controller_failed'); } catch {}
  }
  process.exitCode = outputStopped ? 3 : 4;
} finally {
  process.stdin.pause(); process.stdin.destroy();
  process.removeListener('SIGTERM', stop); process.removeListener('SIGINT', stop);
}
