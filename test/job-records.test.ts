import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import * as fs from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { stripTypeScriptTypes } from 'node:module';
import { isDeepStrictEqual } from 'node:util';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { comparisonSummary } from '../src/comparison.ts';
import { summarizeHistory } from '../src/history.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import * as safety from '../src/safety.ts';
import { validateCheckpointPair } from '../src/engine-checkpoint.ts';
import type { RetainedWritePart, RetainedWriteResult } from '../src/retained-write.ts';
import { jobLinuxConfig, jobPayloadResources, type JobProfile } from '../src/job-config.ts';
import * as records from '../src/job-records.ts';
import { jobFailureCodes } from '../internal/job-channel.mjs';
import { parseWorkerResources, expectedResourceKernel } from '../internal/worker-resources.mjs';
import type { Report } from '../src/model.ts';
import { renderJobHtml } from '../src/job-view.ts';

const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
async function fixture() {
  const parent = tmpdir(), directory = await fs.mkdtemp(path.join(parent, 'bounded-job-records-test-'));
  test.after(() => removeTempDir(directory));
  const root = path.join(directory, 'source'); await fs.mkdir(root);
  const destination = path.join(directory, 'retained'); await fs.mkdir(destination);
  const tool = { path: path.join(directory, 'fixture'), version: '1.2.3', sha256: 'c'.repeat(64) };
  const profile: JobProfile = { schema: 'scanmux.job-profile/v1', name: 'synthetic_record_fixture', scope: 'offline-local', docker: { tool, endpoint: 'unix:///var/run/docker.sock' },
    image: 'sha256:' + 'd'.repeat(64), runtime: { nodeVersion: '24.22.1', python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } },
    tools: { gitleaks: { ...tool, version: '8.30.1' } }, osvDatabase: null,
    scan: { timeoutMs: 10000, maxOutputBytes: 65536, maxFileBytes: 65536, maxSnapshotBytes: 1024 * 1024, maxFiles: 100 },
    limits: { cpuCount: 1, memoryBytes: 256 * 1024 * 1024, tmpBytes: 8 * 1024 * 1024, workBytes: 8 * 1024 * 1024, shmBytes: 1024 * 1024,
      pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 16 * 65536 } };
  const config = jobLinuxConfig(profile), mappedRoot = '/repo/' + safety.hash(root);
  const job: records.JobPlan = { schema: 'scanmux.job-plan/v1', jobId: randomUUID(), profileSha256: safety.digest(profile), origin: { root, repoId: safety.hash(root) }, mappedRoot,
    config, configSha256: safety.digest(config), limits: profile.limits, image: profile.image, runtime: { ...profile.runtime, tools: config.tools,
      app: ['internal/linux-job-controller.mjs', 'internal/linux-job-supervisor.py'].map(path => ({ path, bytes: 1, sha256: 'e'.repeat(64) })) },
    destination, requestedComparison: null, plan: { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: mappedRoot, repoId: safety.hash(mappedRoot),
      commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: safety.digest([]), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
      required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: safety.digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } } };
  job.plan.planHash = safety.digest(job.plan);
  const expected: records.ExpectedJobPlan = { jobId: job.jobId, profileSha256: job.profileSha256, root, mappedRoot, config, limits: profile.limits, image: profile.image, runtime: job.runtime, destination, comparison: undefined };
  const time = new Date().toISOString();
  const report: Report = { schema: 'scanmux.report/v2', runId: randomUUID(), plan: job.plan, startedAt: time, endedAt: time, engines: [],
    runner: { platform: 'linux', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' }, executionState: 'completed', coverageState: 'incomplete',
    gate: 'INCOMPLETE', exitCode: 3, reasons: [], integrityErrors: [] };
  const add = () => {
    const engine = job.plan.required[report.engines.length], run = emptyRun(engine, { plan: job.plan, config, workspace: '/work', snapshot: '/work/snapshot', signal: new AbortController().signal, secretsCleared: false });
    run.execution = 'completed'; run.coverage = 'analyzed'; report.engines.push(run);
    Object.assign(report, decide(job.plan, report.engines)); report.exitCode = exitCodes[report.gate]; return run;
  };
  const checkpoint = (previous: string | null = null) => {
    const marker = 'controller_completion_unverified';
    const provisional: Report = { ...structuredClone(report), executionState: 'failed', coverageState: 'incomplete', gate: 'ERROR', exitCode: 4,
      reasons: [...report.reasons, marker], integrityErrors: [...report.integrityErrors, marker] };
    const body = encode({ schema: 'scanmux.engine-checkpoint/v1', runId: report.runId, sequence: report.engines.length, planHash: job.plan.planHash, previousSha256: previous, report: provisional });
    const receipt = encode({ schema: 'scanmux.engine-checkpoint-commit/v1', runId: report.runId, sequence: report.engines.length, bytes: body.length, sha256: safety.hash(body), previousSha256: previous });
    return [body, receipt];
  };
  const store = new records.JobRecordStore(destination, profile, expected);
  const planMessage = { type: 'record' as const, kind: 'plan' as const, slot: 0, parts: [encode(job)], ackSeq: 1 };
  return { parent, directory, root, destination, profile, config, job, expected, report, add, checkpoint, store, planMessage,
    async close() { assert.ok(safety.within(parent, directory)); await removeTempDirStrict(directory, { recursive: true }); } };
}

test('host delegation never publishes the old metadata name; the default writer remains compatible', async () => {
  for (const delegated of [false, true]) {
    const f = await fixture();
    try {
      const store = delegated ? new records.JobRecordStore(f.destination, f.profile, f.expected, 'delegated-job.json') : f.store;
      const metadata = encode({ fixture: 'metadata_filename_only' });
      await store.saveMetadata(metadata);
      assert.deepEqual(await fs.readdir(f.destination), [delegated ? 'delegated-job.json' : 'job.json']);
      assert.deepEqual(await fs.readFile(path.join(f.destination, delegated ? 'delegated-job.json' : 'job.json')), metadata);
      assert.equal(store.files, 1);
      assert.equal(store.admittedBytes, metadata.length);
      await assert.rejects(store.saveMetadata(metadata));
    } finally { await f.close(); }
  }
});

test('delegated native storage validates before admission, submits whole pairs and commits only after ACK', async () => {
  const f = await fixture();
  const calls: (readonly RetainedWritePart[])[] = [];
  // This adapter test supplies already trusted replies. Native accounting/transport
  // have separate tests; these counters are not measurement evidence.
  const reply = (denied = false): RetainedWriteResult => ({ schema: 'scanmux.retained-write-result/v1', result: denied ? 'retained_allocated_limit' : 'committed',
    jobId: f.job.jobId, intentSha256: 'a'.repeat(64), slots: [], proposedAllocatedBytes: 8192, availableIntermediateBytes: 4096,
    before: { allocatedBytes: 0, reservedBytes: 0, allocatedLimit: 1048576, clusterBytes: 4096, files: [] },
    after: { allocatedBytes: 0, reservedBytes: 0, allocatedLimit: 1048576, clusterBytes: 4096, files: [] } });
  let denied = false;
  const backend = { async write(parts: readonly RetainedWritePart[]) { calls.push(parts); return reply(denied); } };
  try {
    assert.throws(() => new records.JobRecordStore(f.destination, f.profile, f.expected, 'job.json', backend));
    const invalid = new records.JobRecordStore(f.destination, f.profile, f.expected, 'delegated-job.json', backend);
    await assert.rejects(invalid.persist({ ...f.planMessage, parts: [encode({ invalid: true })] })); assert.equal(calls.length, 0);
    const small = new records.JobRecordStore(f.destination, { ...f.profile, limits: { ...f.profile.limits, retainedBytes: 2 * f.profile.scan.maxOutputBytes + 1 } }, f.expected, 'delegated-job.json', backend);
    assert.equal((await small.persist(f.planMessage)).kind, 'retained'); assert.equal(calls.length, 0);
    const store = new records.JobRecordStore(f.destination, f.profile, f.expected, 'delegated-job.json', backend);
    assert.deepEqual(await store.persist(f.planMessage), { kind: 'ready' }); assert.equal(store.plan, null);
    assert.deepEqual(calls[0], [{ name: 'job-plan.json', bytes: f.planMessage.parts[0] }]);
    store.acknowledge(1); f.add(); const pair = f.checkpoint();
    await store.persist({ type: 'record', kind: 'checkpoint', slot: 1, parts: pair, ackSeq: 2 });
    assert.equal(store.prefix, null); assert.equal(calls.length, 2);
    assert.deepEqual(calls[1], [{ name: 'checkpoints/checkpoint-1.json', bytes: pair[0] }, { name: 'checkpoints/commit-1.json', bytes: pair[1] }]);
    store.acknowledge(2); assert.equal(store.prefix!.checkpoint.sequence, 1);
    const acceptedBytes = store.admittedBytes, acceptedFiles = store.files;
    f.add(); const next = f.checkpoint(safety.hash(pair[0])); denied = true;
    assert.deepEqual(await store.persist({ type: 'record', kind: 'checkpoint', slot: 2, parts: next, ackSeq: 3 }),
      { kind: 'retained', proposedBytes: 8192, availableBytes: 4096 });
    assert.equal(store.admittedBytes, acceptedBytes); assert.equal(store.files, acceptedFiles);
    assert.throws(() => store.acknowledge(3)); assert.equal(store.prefix!.checkpoint.sequence, 1);
    await assert.rejects(store.persist(f.planMessage));
    denied = false; const metadata = encode({ synthetic: 'reserved_after_stop' }); await store.saveMetadata(metadata);
    assert.deepEqual(calls.at(-1), [{ name: 'delegated-job.json', bytes: metadata }]);
    assert.equal(store.admittedBytes, acceptedBytes + metadata.length); assert.equal(store.files, acceptedFiles + 1);
    assert.deepEqual(await fs.readdir(f.destination), []); // No ordinary writer fallback.
  } finally { await f.close(); }
});

test('uncertain native batch failure counts every possible tail and never retries or ACKs it', async () => {
  const f = await fixture(); let calls = 0;
  try {
    const backend = { async write(): Promise<RetainedWriteResult> { calls++; throw new Error('synthetic_transport_loss'); } };
    const store = new records.JobRecordStore(f.destination, f.profile, f.expected, 'delegated-job.json', backend);
    await assert.rejects(store.persist(f.planMessage), /synthetic_transport_loss/);
    assert.equal(store.admittedBytes, f.planMessage.parts[0].length); assert.equal(store.files, 1); assert.throws(() => store.acknowledge(1));
    await assert.rejects(store.persist(f.planMessage)); assert.equal(calls, 1);
    assert.deepEqual(await fs.readdir(f.destination), []);
  } finally { await f.close(); }
});

test('outer origin and real mapped Plan/config remain distinct; full identity and sibling routes cannot be rewritten', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(records.validateJobPlan(f.job, f.expected), f.job);
    const changes: ((job: records.JobPlan) => void)[] = [
      job => job.jobId = randomUUID(), job => job.origin.root += '/other', job => job.plan.root = f.root,
      job => job.plan.repoId = job.origin.repoId, job => Object.assign(job.config, { ai: {} }),
      job => job.config.tools.git!.path = '/host/git', job => job.destination += 'changed',
      job => job.plan.transmissions.push('outbound'), job => job.plan.required.reverse(),
      job => Object.assign(job.plan, { ai: { schema: 'forbidden' } }), job => Object.assign(job, { path: '/arbitrary' }),
    ];
    for (const change of changes) { const input = structuredClone(f.job); change(input); assert.throws(() => records.validateJobPlan(input, f.expected)); }
    assert.notEqual(f.job.origin.repoId, f.job.plan.repoId); assert.equal(f.job.plan.root, f.job.mappedRoot);
  } finally { await f.close(); }
});

test('job plans preserve the four-field file shape and reject modes in scan entries', async () => {
  const f = await fixture();
  try {
    for (const mode of [undefined, '100644', '100755', '120000', '100600', ['100644'], null]) {
      const job = structuredClone(f.job), file = { path: 'test.mjs', oid: 'a'.repeat(40), bytes: 1, sha256: safety.hash('x'), ...(mode === undefined ? {} : { mode }) };
      job.plan.files = [file as Report['plan']['files'][number]]; job.plan.snapshotHash = safety.digest(job.plan.files); job.plan.planHash = safety.digest({ ...job.plan, planHash: '' });
      if (mode === undefined) assert.deepEqual(records.validateJobPlan(job, f.expected), job);
      else assert.throws(() => records.validateJobPlan(job, f.expected));
    }
  } finally { await f.close(); }
});

function completionFacts(f: Awaited<ReturnType<typeof fixture>>): records.JobCompletionFacts {
  const boundary: records.JobBoundary = { kernel: expectedResourceKernel(jobPayloadResources(f.profile.limits)), pidsMax: f.profile.limits.pids,
    uid: 1000, gid: 1000, capabilitiesZero: true, noNewPrivileges: true, seccomp: 2, supervisorNonDumpable: true,
    childSupervisorAccessDenied: true, rootReadonly: true, boundedWritableStoresOnly: true, privateNamespaces: true,
    networkCounters: Array(16).fill(0), cpuThrottledPeriods: 0, oomKills: 0 };
  return { startup: boundary, ending: structuredClone(boundary), nativeFailure: null, stop: null, failures: [],
    closure: { startupVerified: true, supervisorClosed: true, ownedTasksClosure: 'supervisor_final_wait', controllerCompleted: true,
      controllerTerminal: { exitCode: 0, signal: null }, terminal: { exitCode: 0, oomKilled: false }, containerAbsent: true, daemonHealthy: true, inputsUnchanged: true } };
}

function jobEnvelope(f: Awaited<ReturnType<typeof fixture>>, facts: records.JobCompletionFacts): records.JobReport {
  return { schema: 'scanmux.job-report/v1', jobId: f.job.jobId, profileSha256: f.job.profileSha256, originDigest: f.job.origin.repoId,
    origin: f.job.origin, mappedRoot: f.job.mappedRoot, plan: f.store.planReference, analysis: f.store.analysis, basis: 'live_owner_recorded',
    resources: { requested: f.profile.limits, startup: facts.startup, ending: facts.ending, nativeFailure: facts.nativeFailure, observer: null, stop: facts.stop,
      payloadWallScope: 'linux_payload_and_durable_record_ack_admission', controlPlaneHardCpuMemoryLimit: false, retainedFilesystemPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false },
    closure: facts.closure, knownFailures: facts.failures, failureObservationScope: 'host_accepted_closed_failure_facts', unobservedInternalErrors: 'unknown',
    inputVerificationScope: 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported',
    infrastructure: { appFiles: 2, appBytes: 2, emptyConfigurationFiles: 1, ownerIdentityBytes: 0 },
    retained: { logicalLimit: f.profile.limits.retainedBytes, payloadAdmittedBytesBeforeMetadata: f.store.admittedBytes, filesBeforeMetadata: f.store.files,
      metadataBytesMaximum: f.profile.scan.maxOutputBytes, maxFiles: 11 },
    ...records.jobOutcome({ plan: f.store.plan, report: f.store.finalReport, prefix: f.store.prefix, stop: facts.stop, closure: facts.closure, failures: facts.failures }) };
}

test('final ACK is only a receipt; additional writes poison final selection while preserving the entire prefix', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(await f.store.persist(f.planMessage), { kind: 'ready' });
    assert.equal(f.store.plan, null); assert.deepEqual(records.parseJobJson(await fs.readFile(path.join(f.destination, 'job-plan.json'))), f.job);
    f.store.acknowledge(1); f.add();
    const parts = f.checkpoint(), next = { type: 'record' as const, kind: 'checkpoint' as const, slot: 1, parts, ackSeq: 2 };
    await f.store.persist(next); assert.equal(f.store.prefix, null); f.store.acknowledge(2);
    assert.deepEqual(f.store.prefix, validateCheckpointPair(parts[0], parts[1], 1, null));
    assert.deepEqual(records.validateJobFinalReport(encode(f.report), f.job, f.store.prefix).engines, f.report.engines);
    const changed = structuredClone(f.report); changed.engines[0].coverage = 'skipped'; Object.assign(changed, decide(changed.plan, changed.engines));
    assert.throws(() => records.validateJobFinalReport(encode(changed), f.job, f.store.prefix));
    await f.store.persist({ type: 'record', kind: 'report', slot: 0, parts: [encode(f.report)], ackSeq: 3 });
    assert.equal(f.store.finalReport, null); f.store.acknowledge(3);
    assert.equal(f.store.finalReport, null); assert.equal(f.store.analysis?.kind, 'checkpoint');
    await assert.rejects(f.store.persist({ ...next, slot: 2 }));
    // A rejected further write must not turn this failed store into a final result.
    f.store.finalize(completionFacts(f)); assert.equal(f.store.analysis?.kind, 'checkpoint');
    assert.equal(f.store.files, 4); assert.ok(f.store.admittedBytes + f.profile.scan.maxOutputBytes <= f.profile.limits.retainedBytes);
  } finally { await f.close(); }
});

test('final receipt selection covers stop, disappearance, every closure axis and saved-reader contradictions as one state family', async () => {
  const negatives: [string, (facts: records.JobCompletionFacts) => void][] = [
    ['deadline after ACK', facts => { facts.stop = { kind: 'deadline', source: 'supervisor', elapsedMs: 20000 }; }],
    ['cancel after ACK', facts => { facts.stop = { kind: 'cancelled' }; }],
    ['disk after ACK', facts => { facts.stop = { kind: 'disk', tid: 2, syscall: 'write', errno: 28, returned: -28, store: 'work', device: 1, inode: 2, mountId: 3, stopBeforeNextInstruction: true }; }],
    ['memory after ACK', facts => { facts.stop = { kind: 'memory', source: 'memory.events', before: 0, after: 1 }; }],
    ['retained after ACK', facts => { facts.stop = { kind: 'retained', proposedBytes: 2, availableBytes: 1 }; }],
    ['controller incomplete', facts => { facts.closure.controllerCompleted = false; }],
    ['controller missing', facts => { facts.closure.controllerTerminal = null; }],
    ['controller signalled', facts => { facts.closure.controllerTerminal = { exitCode: null, signal: 9 }; }],
    ['controller nonzero', facts => { facts.closure.controllerTerminal = { exitCode: 4, signal: null }; }],
    ['supervisor open', facts => { facts.closure.supervisorClosed = false; }],
    ['namespace fallback', facts => { facts.closure.ownedTasksClosure = 'namespace_terminal_and_absent'; }],
    ['tasks unverified', facts => { facts.closure.ownedTasksClosure = 'unverified'; }],
    ['terminal missing', facts => { facts.closure.terminal = null; }],
    ['terminal nonzero', facts => { facts.closure.terminal = { exitCode: 4, oomKilled: false }; }],
    ['terminal OOM', facts => { facts.closure.terminal = { exitCode: 0, oomKilled: true }; }],
    ['startup unverified', facts => { facts.closure.startupVerified = false; }],
    ['container present', facts => { facts.closure.containerAbsent = false; }],
    ['daemon unhealthy', facts => { facts.closure.daemonHealthy = false; }],
    ['inputs changed', facts => { facts.closure.inputsUnchanged = false; }],
    ['startup missing', facts => { facts.startup = null; }],
    ['ending missing', facts => { facts.ending = null; }],
    ['network changed', facts => { facts.ending!.networkCounters[0]++; }],
    ['native failure', facts => { facts.nativeFailure = { kind: 'invariant', operation: 'require', site: 1, errno: null }; }],
    ...records.jobHostFailureCodes.map(code => [code, (facts: records.JobCompletionFacts) => { facts.failures.push(code); }] as [string, (facts: records.JobCompletionFacts) => void]),
  ];
  for (const [label, change] of [['normal', null], ['known analysis error', (facts: records.JobCompletionFacts) => { facts.failures.push('engine_execution_failed'); }], ...negatives] as [string, ((facts: records.JobCompletionFacts) => void) | null][]) {
    const f = await fixture();
    try {
      await f.store.persist(f.planMessage); f.store.acknowledge(1); f.add();
      const parts = f.checkpoint(); await f.store.persist({ type: 'record', kind: 'checkpoint', slot: 1, parts, ackSeq: 2 }); f.store.acknowledge(2);
      const finalBytes = encode(f.report); await f.store.persist({ type: 'record', kind: 'report', slot: 0, parts: [finalBytes], ackSeq: 3 }); f.store.acknowledge(3);
      assert.equal(f.store.finalReport, null, label); assert.equal(f.store.analysis?.kind, 'checkpoint', label);
      const facts = completionFacts(f); change?.(facts); f.store.finalize(facts);
      const eligible = label === 'normal' || label === 'known analysis error';
      assert.equal(f.store.analysis?.kind, eligible ? 'report' : 'checkpoint', label);
      assert.deepEqual(await fs.readFile(path.join(f.destination, 'report.json')), finalBytes, label);
      const saved = jobEnvelope(f, facts); records.validateJobReport(saved);
      if (eligible) {
        assert.deepEqual(f.store.finalReport, f.report);
        const recovered = structuredClone(saved); recovered.basis = 'recovered_saved_checkpoint_without_live_ownership';
        assert.throws(() => records.validateJobReport(recovered), label);
      } else {
        assert.equal(f.store.finalReport, null, label);
        assert.deepEqual(f.store.prefix!.checkpoint.report.engines, f.report.engines, label);
        assert.ok(f.store.prefix!.checkpoint.report.integrityErrors.includes('controller_completion_unverified'), label);
        assert.match(renderJobHtml(f.store.prefix!.checkpoint.report, saved, 'en'), /provisional; completion unverified/);
        assert.match(renderJobHtml(f.store.prefix!.checkpoint.report, saved, 'ja'), /途中保存・完了未確認/);
        const contradictory = structuredClone(saved); contradictory.analysis = { kind: 'report', file: 'report.json', ...records.jobReference(finalBytes) };
        assert.throws(() => records.validateJobReport(contradictory), label);
      }
      assert.throws(() => f.store.finalize(completionFacts(f)), label);
    } finally { await f.close(); }
  }
});

test('missing, unacknowledged and discarded final tails never promote even with later normal terminal facts', async () => {
  for (const state of ['missing', 'unacknowledged', 'discarded']) {
    const f = await fixture();
    try {
      await f.store.persist(f.planMessage); f.store.acknowledge(1); f.add();
      const parts = f.checkpoint(); await f.store.persist({ type: 'record', kind: 'checkpoint', slot: 1, parts, ackSeq: 2 }); f.store.acknowledge(2);
      if (state !== 'missing') await f.store.persist({ type: 'record', kind: 'report', slot: 0, parts: [encode(f.report)], ackSeq: 3 });
      if (state === 'discarded') f.store.discardUnacceptedTail();
      f.store.finalize(completionFacts(f));
      assert.equal(f.store.finalReport, null, state); assert.equal(f.store.analysis?.kind, 'checkpoint', state);
      assert.throws(() => f.store.acknowledge(3), state);
    } finally { await f.close(); }
  }
});

test('retained logical refusal happens before any write; final reserves and unaccepted late tails cannot admit more work', async () => {
  const f = await fixture();
  try {
    const small = { ...f.profile, limits: { ...f.profile.limits, retainedBytes: 2 * f.profile.scan.maxOutputBytes + 1 } };
    const store = new records.JobRecordStore(f.destination, small, f.expected);
    const result = await store.persist(f.planMessage);
    assert.equal(result.kind, 'retained'); assert.deepEqual(await fs.readdir(f.destination), []); assert.equal(store.plan, null);
    await assert.rejects(store.persist(f.planMessage));
    const other = path.join(f.directory, 'late'); await fs.mkdir(other);
    const late = new records.JobRecordStore(other, f.profile, { ...f.expected, destination: other });
    const job = { ...f.job, destination: other };
    await late.persist({ ...f.planMessage, parts: [encode(job)] }); late.discardUnacceptedTail();
    assert.equal(late.plan, null); assert.ok(late.admittedBytes > 0);
    assert.throws(() => late.acknowledge(1)); await assert.rejects(late.persist({ ...f.planMessage, parts: [encode(job)] }));
  } finally { await f.close(); }
});

test('actual host open/write/sync/close faults remain errors and never ACK or promote a record', async () => {
  for (const kind of ['open', 'write', 'sync', 'close']) {
    const f = await fixture();
    try {
      const customOpen = async (...args: Parameters<typeof fs.open>) => {
        if (kind === 'open') throw Error('fixture open failure');
        const handle = await fs.open(...args);
        if (kind === 'write') handle.writeFile = async () => { throw Error('fixture write failure'); };
        if (kind === 'sync') handle.sync = async () => { throw Error('fixture sync failure'); };
        if (kind === 'close') { const close = handle.close.bind(handle); handle.close = async () => { await close(); throw Error('fixture close failure'); }; }
        return handle;
      };
      const source = stripTypeScriptTypes(await fs.readFile('src/job-records.ts', 'utf8')).replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
      const dependencies = { path, lstat: fs.lstat, mkdir: fs.mkdir, open: customOpen, isDeepStrictEqual, defaults, catalogIdentity, comparisonSummary, summarizeHistory, decide, exitCodes,
        validateCheckpointPair, ...safety, jobFailureCodes, jobPayloadResources, parseWorkerResources, expectedResourceKernel };
      const module = Function(...Object.keys(dependencies), source + '\nreturn {JobRecordStore};')(...Object.values(dependencies)) as typeof records;
      const store = new module.JobRecordStore(f.destination, f.profile, f.expected);
      await assert.rejects(store.persist(f.planMessage)); assert.equal(store.plan, null); assert.throws(() => store.acknowledge(1));
      await assert.rejects(store.persist(f.planMessage));
    } finally { await f.close(); }
  }
});

test('native stop facts require their exact source; known failures and missing closure always outrank budget stops', async () => {
  const f = await fixture();
  try {
    const closure: records.JobClosure = { startupVerified: true, supervisorClosed: true, ownedTasksClosure: 'supervisor_final_wait', controllerCompleted: true,
      controllerTerminal: { exitCode: 0, signal: null }, terminal: { exitCode: 0, oomKilled: false }, containerAbsent: true, daemonHealthy: true, inputsUnchanged: true };
    const stops: records.JobStop[] = [
      { kind: 'disk', tid: 2, syscall: 'write', errno: 28, returned: -28, store: 'work', device: 1, inode: 2, mountId: 3, stopBeforeNextInstruction: true },
      { kind: 'memory', source: 'memory.events', before: 0, after: 1 }, { kind: 'memory', source: 'docker-oom-killed' },
      { kind: 'deadline', source: 'host', elapsedMs: 20000 }, { kind: 'retained', proposedBytes: 200, availableBytes: 100 },
    ];
    for (const stop of stops) {
      const actualClosure = stop.kind === 'memory' && stop.source === 'docker-oom-killed' ? { ...closure, terminal: { exitCode: 137, oomKilled: true } } : closure;
      assert.deepEqual(records.validateJobStop(stop), stop);
      assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix: null, stop, closure: actualClosure, failures: [] }).gate, 'INCOMPLETE');
      assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix: null, stop, closure, failures: ['engine_execution_failed'] }).gate, 'ERROR');
      assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix: null, stop, closure: { ...closure, containerAbsent: false }, failures: [] }).gate, 'ERROR');
    }
    assert.throws(() => records.validateJobStop({ kind: 'memory', source: 'stderr' }));
    assert.throws(() => records.validateJobStop({ kind: 'memory', source: 'memory.events', before: 1, after: 1 }));
    assert.throws(() => records.validateJobStop({ ...stops[0], returned: -9 }));
    assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix: null, stop: { kind: 'memory', source: 'docker-oom-killed' }, closure, failures: [] }).gate, 'ERROR');
    assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix: null, stop: null, closure, failures: [] }).gate, 'ERROR');
    f.add().execution = 'failed'; const parts = f.checkpoint(), prefix = validateCheckpointPair(parts[0], parts[1], 1, null);
    assert.equal(records.jobOutcome({ plan: f.job, report: null, prefix, stop: stops[0], closure, failures: [] }).gate, 'ERROR');
  } finally { await f.close(); }
});

test('composite job limits project onto exact kernel resource keys while all other boundary axes remain checked', async () => {
  const f = await fixture();
  try {
    const snapshot = { kernel: { cpuQuota: 100000, cpuPeriod: 100000, memoryMax: 268435456, swapMax: 0, tmpBytes: 8388608, workBytes: 8388608, shmBytes: 1048576 },
      pidsMax: 64, uid: 1000, gid: 1000, capabilitiesZero: true, noNewPrivileges: true, seccomp: 2, supervisorNonDumpable: true,
      childSupervisorAccessDenied: true, rootReadonly: true, boundedWritableStoresOnly: true, privateNamespaces: true,
      networkCounters: Array(16).fill(0), cpuThrottledPeriods: 0, oomKills: 0 };
    assert.deepEqual(records.validateJobBoundary(snapshot, f.profile.limits), snapshot);
    const changes: ((input: typeof snapshot) => void)[] = [
      input => input.kernel.cpuQuota++, input => input.kernel.cpuPeriod++, input => input.kernel.memoryMax++, input => input.kernel.swapMax++,
      input => input.kernel.tmpBytes++, input => input.kernel.workBytes++, input => input.kernel.shmBytes++, input => input.pidsMax++,
      input => input.uid = 0, input => input.gid = 0, input => input.capabilitiesZero = false, input => input.noNewPrivileges = false,
      input => input.seccomp = 0, input => input.supervisorNonDumpable = false, input => input.childSupervisorAccessDenied = false,
      input => input.rootReadonly = false, input => input.boundedWritableStoresOnly = false, input => input.privateNamespaces = false,
      input => input.networkCounters.pop(), input => Object.assign(input.kernel, { unbounded: true }),
    ];
    for (const change of changes) { const input = structuredClone(snapshot); change(input); assert.throws(() => records.validateJobBoundary(input, f.profile.limits)); }
    // Duration and retention do not silently become kernel resource keys or relax its limits.
    assert.deepEqual(records.validateJobBoundary(snapshot, { ...f.profile.limits, wallMs: 1, cleanupTimeoutMs: 1, retainedBytes: 131072 }), snapshot);
  } finally { await f.close(); }
});

test('job plans stay offline: the offline plan has no destinations and a plan carrying AI destinations is refused', async () => {
  const f = await fixture();
  try {
    assert.equal(Object.hasOwn(f.job.plan, 'destinations'), false);
    records.validateJobPlan(structuredClone(f.job), f.expected);
    const disclosed = structuredClone(f.job);
    Reflect.set(disclosed.plan, 'destinations', { schema: 'scanmux.destinations/v1', rule: 'send_only_to_validated_software', ruleMet: false, destinations: [] });
    disclosed.plan.planHash = safety.digest({ ...disclosed.plan, planHash: '' });
    assert.throws(() => records.validateJobPlan(disclosed, f.expected));
  } finally { await f.close(); }
});

test('copy budget cause survives the standalone job policy re-evaluation and prior FAIL/ERROR', async () => {
  const f = await fixture();
  try {
    const first = f.add(), osv = f.add(); f.add(); f.add();
    osv.execution = 'budget_exceeded'; osv.errors.push('job_disk_copy_limit');
    const closure: records.JobClosure = { startupVerified: true, supervisorClosed: true, ownedTasksClosure: 'supervisor_final_wait', controllerCompleted: true,
      controllerTerminal: { exitCode: 0, signal: null }, terminal: { exitCode: 0, oomKilled: false }, containerAbsent: true, daemonHealthy: true, inputsUnchanged: true };
    for (const earlier of ['none', 'FAIL', 'ERROR'] as const) {
      if (earlier === 'FAIL') first.findings.push({ fingerprint: 'a'.repeat(64), engine: 'gitleaks', originIds: ['fixture'], severity: 'high', confidence: 'high',
        evidenceState: 'source_supported', disposition: 'open', category: 'secret', file: 'fixture.ts', line: 1,
        title: 'Fixture secret', fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' });
      if (earlier === 'ERROR') first.execution = 'failed';
      Object.assign(f.report, decide(f.job.plan, f.report.engines));
      f.report.exitCode = exitCodes[f.report.gate];
      assert.deepEqual(records.validateJobFinalReport(encode(f.report), f.job, null), f.report);
      const result = records.jobOutcome({ plan: f.job, report: f.report, prefix: null, stop: null, closure, failures: [] });
      assert.equal(result.gate, earlier === 'none' ? 'INCOMPLETE' : earlier);
      assert.equal(result.exitCode, exitCodes[result.gate]);
      assert.ok(result.reasons.includes('job_disk_copy_limit'));
    }
  } finally { await f.close(); }
});
