import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import * as fs from 'node:fs/promises';
import { digest, within } from '../src/safety.ts';
import { retainedCatalog, type RetainedWritePart, type RetainedWriteResult, type RetainedAllocationStop } from '../src/retained-write.ts';
import { hostFailureRecorder, hostJobCompletion, hostJobOutcome, hostNativeClosed, nativePrimaryNormal, nativeProcessCapacity, parseHostJobProfile, windowsOwnerForcedExit,
  validateHostJobFailure, validateHostJobIntent, validateHostJobReport, validateHostNativeReceipt,
  type HostCompletionInput, type HostJobIntent, type HostNativeReceipt, type HostNativePhase } from '../src/host-job-records.ts';

function intentFixture(): HostJobIntent {
  const tool = { path: path.resolve('.local/synthetic-host-tool.exe'), sha256: 'a'.repeat(64), version: '1.0.0' };
  const profile = { schema: 'scanmux.host-job-profile/v1', name: 'synthetic_host_boundary', scope: 'windows-offline-local', offlineProfile: path.resolve('.local/synthetic-offline-profile.json'),
    owner: tool, node: { ...tool, version: '24.22.1' }, limits: { cpuRate: 2500, memoryBytes: 536870912, wallMs: 20000, cleanupTimeoutMs: 10000 } };
  return validateHostJobIntent({ schema: 'scanmux.host-job-intent/v1', mode: 'scan', jobId: '11111111-1111-4111-8111-111111111111', root: path.resolve('.local/synthetic-host-source'),
    directory: path.resolve('.local/synthetic-host-output'), comparison: null, rootIdentity: { device: '1', inode: '2', modifiedNs: '3' }, host: profile,
    hostSource: { path: path.resolve('.local/synthetic-host-profile.json'), identity: { bytes: 1, sha256: 'b'.repeat(64) } },
    offline: { schema: 'scanmux.job-profile/v1', name: 'synthetic_offline_boundary', scope: 'offline-local', docker: { tool, endpoint: 'npipe:////./pipe/dockerDesktopLinuxEngine' }, image: 'sha256:' + 'c'.repeat(64),
      runtime: { nodeVersion: '24.22.1', python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } }, tools: { gitleaks: tool }, osvDatabase: null,
      scan: { timeoutMs: 10000, maxOutputBytes: 65536, maxFileBytes: 65536, maxSnapshotBytes: 1048576, maxFiles: 100 },
      limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 1048576 } },
    offlineSource: { bytes: 1, sha256: 'd'.repeat(64) }, application: path.resolve('.local/synthetic-host-app'),
    assets: [{ path: 'internal/windows-job-worker.mjs', bytes: 1, sha256: 'e'.repeat(64) }], nodeIdentity: { bytes: 1, sha256: tool.sha256 }, ownerIdentity: { bytes: 1, sha256: tool.sha256 }, maxProcesses: nativeProcessCapacity(65536) });
}
function nativeFixture(intent = intentFixture()): HostNativeReceipt {
  const phase = (name: HostNativePhase['phase'], start: number, pid: number): HostNativePhase => ({ phase: name, reason: 'completed', configured: true, memberBeforeResume: true,
    cpuFlags: 5, cpuRate: intent.host.limits.cpuRate, memoryBytes: intent.host.limits.memoryBytes, limitFlags: 0x2200,
    root: { pid, creationFileTime: String(pid) }, processes: [{ pid, creationFileTime: String(pid), memberVerified: true, signaled: true, exitCode: 0 }],
    totalProcesses: 1, maximumTotalProcesses: 1, accountingSamples: 2, accountingMonotonic: true, coverageComplete: true, startedMs: start, endedMs: start + 1, closingStartedMs: 2, error: null });
  return { schema: 'scanmux.windows-job-owner/v1', version: '1.0.0', intentSha256: 'f'.repeat(64), jobId: intent.jobId, mode: 'scan', phases: [phase('primary', 1, 1000), phase('cleanup', 2, 1004)],
    state: 'closed', closingStartedMs: 2, endedMs: 4, owner: { pid: 996, creationFileTime: '996' } };
}
function completionFixture(native = nativeFixture()): HostCompletionInput {
  return { native, ownerTerminal: { code: 0, signal: null, protocolValid: true }, inputsUnchanged: true, containerAbsent: true, daemonHealthy: true,
    cancelled: false, recovered: false, normalInner: true, hasFinal: true, hasPrefix: true, failures: [] };
}

test('native first-error persistence must finish before acceptance and never falls back to an ordinary write', async () => {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'native-failure-adapter-'));
  try {
    const replies = JSON.parse(await fs.readFile(path.resolve('test/fixtures/retained-replies.json'), 'utf8'));
    const reply = replies.cases[0].result as RetainedWriteResult; let calls = 0, committed = false;
    const intent = intentFixture(), recorder = hostFailureRecorder(directory, intent.jobId, digest(intent.offline), {
      writeSync(parts: readonly RetainedWritePart[]) {
        calls++; assert.equal(parts.length, 1); assert.equal(parts[0].name, 'host-job-failure.json');
        const value = validateHostJobFailure(JSON.parse(parts[0].bytes.toString('utf8')), intent.jobId, digest(intent.offline));
        assert.equal(value.code, 'job_protocol_invalid');
        if (!committed) throw new Error('synthetic_native_flush_failed');
        return reply;
      },
    });
    assert.throws(() => recorder('job_protocol_invalid'), /synthetic_native_flush_failed/); assert.equal(calls, 1);
    committed = true; recorder('job_protocol_invalid'); recorder('job_controller_failed'); assert.equal(calls, 2);
    assert.deepEqual(await fs.readdir(directory), []);
  } finally { assert.ok(within(tmpdir(), directory)); await fs.rm(directory, { recursive: true }); }
});

function allocationFixture() {
  const old = intentFixture(), host = { ...old.host, schema: 'scanmux.host-job-profile/v2', owner: { ...old.host.owner, version: '1.1.0' }, retained: { allocatedBytes: 532480 } };
  const intent = validateHostJobIntent({ ...old, schema: 'scanmux.host-job-intent/v2', host, storage: { fileSystem: 'NTFS', clusterBytes: 4096, allocatedBytes: 532480 } });
  const reserved = retainedCatalog(65536).filter(slot => slot.reserved && slot.slot !== 0 && slot.slot !== 2).reduce((total, slot) => total + Math.ceil(slot.maximum / 4096) * 4096, 0);
  const stop: RetainedAllocationStop = { schema: 'scanmux.retained-allocation-stop/v1', jobId: intent.jobId, intentSha256: 'f'.repeat(64),
    parts: [{ slot: 10, bytes: 65536 }], proposedAllocatedBytes: 65536, availableIntermediateBytes: 61440, actualAllocatedBytes: 4096,
    reservedBytes: reserved + 4096, allocatedLimit: 532480, clusterBytes: 4096 };
  const snapshot = { allocatedBytes: 8192, reservedBytes: reserved, allocatedLimit: 532480, clusterBytes: 4096,
    files: [{ slot: 0, bytes: 2000, allocatedBytes: 4096 }, { slot: 2, bytes: 500, allocatedBytes: 4096 }] };
  return { intent, stop, snapshot };
}

test('allocation refusal cannot promote final analysis or hide an independent error or missing closure fact', () => {
  const { stop } = allocationFixture();
  const completed = completionFixture(); completed.retainedStop = stop;
  const selected = hostJobCompletion(completed); assert.equal(selected.analysisKind, 'checkpoint'); assert.equal(selected.finalAllowed, false);
  assert.equal(hostJobOutcome({ plan: null, analysis: null, completion: selected }).gate, 'INCOMPLETE');
  for (const change of [
    (value: HostCompletionInput) => { value.failures.push('engine_execution_failed'); },
    (value: HostCompletionInput) => { value.ownerTerminal = null; },
    (value: HostCompletionInput) => { value.native = null; },
    (value: HostCompletionInput) => { value.inputsUnchanged = false; },
    (value: HostCompletionInput) => { value.containerAbsent = false; },
    (value: HostCompletionInput) => { value.daemonHealthy = false; },
    (value: HostCompletionInput) => { value.recovered = true; },
    (value: HostCompletionInput) => { value.cancelled = true; },
  ]) { const input = structuredClone(completed); change(input); const result = hostJobCompletion(input); assert.equal(result.finalAllowed, false); assert.equal(hostJobOutcome({ plan: null, analysis: null, completion: result }).gate, 'ERROR'); }
});

test('v2 saved storage facts require recorded geometry and an explicit original observation scope; unverified storage stays ERROR', () => {
  const { intent, stop, snapshot } = allocationFixture();
  const report = { schema: 'scanmux.host-job-report/v2', jobId: intent.jobId, hostProfileSha256: digest(intent.host), offlineProfileSha256: digest(intent.offline), originDigest: 'a'.repeat(64),
    intent: { bytes: 2000, sha256: stop.intentSha256 }, native: null, delegated: null, acceptedFailure: null, primary: null, cleanup: null, plan: null, analysis: null,
    basis: 'live_owner_recorded', ownerTerminal: { code: 0, signal: null, protocolValid: true }, closure: { windowsProcessTreeVerified: true, containerAbsent: true, daemonHealthy: true, inputsUnchanged: true },
    resources: { host: intent.host.limits, linux: intent.offline.limits, trustedOwnerAndAdmissionExcluded: true, retainedPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false, aggregateHostLinuxBudget: false },
    infrastructure: { maximumMetadataFiles: 7, maximumMetadataBytes: 65536 + 4 * 65536 + 1024 + 4096, filesBeforeEnvelope: 2, bytesBeforeEnvelope: 2500 },
    knownFailures: [], unobservedInternalErrors: 'unknown', gate: 'INCOMPLETE', exitCode: 3, reasons: ['host_job_retained_allocated_stop'],
    retained: { scope: 'recorded_original_before_envelope_not_copy_quota', snapshot, stop, witness: { bytes: 500, sha256: 'b'.repeat(64) } } };
  assert.deepEqual(validateHostJobReport(report, intent), report);
  for (const change of [
    (value: typeof report) => { value.schema = 'scanmux.host-job-report/v1'; },
    (value: typeof report) => { value.retained.scope = 'directory_quota'; },
    (value: typeof report) => { value.retained.snapshot.files[0].bytes++; },
    (value: typeof report) => { value.retained.snapshot.files.push({ slot: 9, bytes: 1, allocatedBytes: 4096 }); },
    (value: typeof report) => { value.retained.witness.bytes++; },
    (value: typeof report) => { value.retained.stop.availableIntermediateBytes++; },
    (value: typeof report) => { value.resources.retainedPhysicalQuotaEnforced = true; },
  ]) { const copy = structuredClone(report); change(copy); assert.throws(() => validateHostJobReport(copy, intent)); }
  assert.throws(() => validateHostJobReport(report, intentFixture()));
  const unknown = { ...report, gate: 'ERROR', exitCode: 4, knownFailures: ['host_job_retained_unverified'], retained: { ...report.retained, snapshot: null } };
  assert.deepEqual(validateHostJobReport(unknown, intent), unknown);
  assert.throws(() => validateHostJobReport({ ...unknown, gate: 'INCOMPLETE', exitCode: 3 }, intent));
  assert.throws(() => validateHostJobReport({ ...unknown, knownFailures: [] }, intent));
});

test('host profile has explicit Windows units and finite limits; old schemas and alternative launch authority are rejected', () => {
  const intent = intentFixture(); assert.deepEqual(parseHostJobProfile(intent.host), intent.host);
  for (const change of [
    (value: typeof intent.host) => value.limits.cpuRate = 0,
    (value: typeof intent.host) => value.limits.cpuRate = 10001,
    (value: typeof intent.host) => value.limits.memoryBytes++,
    (value: typeof intent.host) => value.limits.wallMs = Infinity,
    (value: typeof intent.host) => value.limits.cleanupTimeoutMs = 2147483648,
    (value: typeof intent.host) => value.limits.wallMs = 2147483647,
    (value: typeof intent.host) => Object.assign(value, { commands: ['untrusted'] }),
    (value: typeof intent.host) => Object.assign(value.limits, { unlimited: true }),
    (value: typeof intent.host) => value.offlineProfile = '\\\\untrusted.invalid\\share\\profile.json',
    (value: typeof intent.host) => value.owner.path = '\\\\?\\C:\\owner.exe',
  ]) { const copy = structuredClone(intent.host); change(copy); assert.throws(() => parseHostJobProfile(copy)); }
  assert.throws(() => validateHostJobIntent({ ...intent, mode: 'cleanup' }));
  assert.throws(() => validateHostJobIntent({ ...intent, originalPrimary: {} }));
  assert.throws(() => nativeProcessCapacity(8192));
});

test('whole-tree closure needs every exact generation terminal plus complete accounting and the shared bounded closing interval', () => {
  const intent = intentFixture(), input = nativeFixture(intent);
  const accepted = validateHostNativeReceipt(input, intent, input.intentSha256); assert.equal(hostNativeClosed(accepted), true); assert.equal(nativePrimaryNormal(accepted), true);
  const changes: ((native: HostNativeReceipt) => void)[] = [
    value => { value.phases[0].processes[0].signaled = false; value.phases[0].processes[0].exitCode = null; },
    value => value.phases[0].totalProcesses = 2,
    value => value.phases[0].maximumTotalProcesses = 2,
    value => value.phases[0].processes.push(structuredClone(value.phases[0].processes[0])),
    value => value.phases[0].root!.creationFileTime = '99999',
    value => value.phases[0].accountingMonotonic = false,
    value => value.phases[0].accountingSamples = 0,
    value => value.phases[0].cpuFlags = 0,
    value => value.phases[0].cpuRate++,
    value => value.phases[1].startedMs = 0,
    value => value.phases[1].closingStartedMs = 3,
    value => value.endedMs = value.closingStartedMs! + intent.host.limits.cleanupTimeoutMs + 1,
  ];
  for (const change of changes) { const copy = structuredClone(input); change(copy); assert.throws(() => validateHostNativeReceipt(copy, intent, input.intentSha256)); }
  const stopped = structuredClone(input); stopped.phases[0].reason = 'deadline';
  assert.equal(nativePrimaryNormal(validateHostNativeReceipt(stopped, intent, input.intentSha256)), false);
});

test('explicit retained v2 requires the new owner and matching geometry without changing v1', () => {
  const original = intentFixture();
  assert.deepEqual(validateHostJobIntent(original), original);
  const profile = { ...structuredClone(original.host), schema: 'scanmux.host-job-profile/v2', owner: { ...original.host.owner, version: '1.1.0' }, retained: { allocatedBytes: 1048576 } };
  assert.equal(parseHostJobProfile(profile).schema, 'scanmux.host-job-profile/v2');
  const input = { ...structuredClone(original), schema: 'scanmux.host-job-intent/v2', host: profile, storage: { fileSystem: 'NTFS', clusterBytes: 4096, allocatedBytes: 1048576 } };
  const accepted = validateHostJobIntent(input); assert.equal(accepted.schema, 'scanmux.host-job-intent/v2');
  const native = { ...nativeFixture(accepted), version: '1.1.0' };
  assert.equal(validateHostNativeReceipt(native, accepted, native.intentSha256).version, '1.1.0');
  assert.throws(() => validateHostNativeReceipt({ ...native, version: '1.0.0' }, accepted, native.intentSha256));
  for (const mutation of [
    { ...input, schema: 'scanmux.host-job-intent/v1' },
    { ...input, storage: { ...input.storage, allocatedBytes: input.storage.allocatedBytes + 4096 } },
    { ...input, storage: { ...input.storage, fileSystem: 'unverified' } },
    { ...input, storage: { ...input.storage, clusterBytes: 0 } },
    { ...input, host: { ...profile, owner: original.host.owner } },
    { ...input, host: { ...profile, retained: { allocatedBytes: 1 } }, storage: { ...input.storage, allocatedBytes: 1 } },
    { ...input, host: { ...profile, retained: { allocatedBytes: 1048577 } }, storage: { ...input.storage, allocatedBytes: 1048577 } },
  ]) assert.throws(() => validateHostJobIntent(mutation));
  assert.throws(() => parseHostJobProfile({ ...original.host, retained: profile.retained }));
  const compatible = parseHostJobProfile({ ...original.host, owner: { ...original.host.owner, version: '1.1.0' } });
  assert.equal(compatible.schema, 'scanmux.host-job-profile/v1');
});

test('first independent ERROR is durable before return, survives loss of worker state, and is never replaced by a later deadline', async () => {
  const intent = intentFixture(), parent = tmpdir(), directory = await fs.mkdtemp(path.join(parent, 'host-job-records-'));
  try {
    const retain = hostFailureRecorder(directory, intent.jobId, digest(intent.offline));
    retain('controller_integrity_failure');
    const first = await fs.readFile(path.join(directory, 'host-job-failure.json'));
    const accepted = validateHostJobFailure(JSON.parse(first.toString('utf8')), intent.jobId, digest(intent.offline));
    retain('job_closure_unverified'); assert.deepEqual(await fs.readFile(path.join(directory, 'host-job-failure.json')), first);
    const native = nativeFixture(intent); native.phases[0].reason = 'deadline';
    const completion = hostJobCompletion({ ...completionFixture(native), failures: [accepted.code] });
    const result = hostJobOutcome({ plan: null, analysis: null, completion });
    assert.equal(result.gate, 'ERROR'); assert.ok(result.reasons.includes('controller_integrity_failure'));
    assert.throws(() => validateHostJobFailure({ ...accepted, jobId: '22222222-2222-4222-8222-222222222222' }, intent.jobId, digest(intent.offline)));
    assert.throws(() => validateHostJobFailure({ ...accepted, code: 'OOM prose' }, intent.jobId, digest(intent.offline)));
    assert.throws(() => hostFailureRecorder(directory, intent.jobId, digest(intent.offline))('job_daemon_failed'));
  } finally { assert.ok(within(parent, directory)); await fs.rm(directory, { recursive: true }); }
});

test('an independently observed natural worker failure cannot become a deadline incomplete result', () => {
  const intent = intentFixture(), native = nativeFixture(intent);
  native.phases[0].reason = 'deadline'; native.phases[0].processes[0].exitCode = 1;
  validateHostNativeReceipt(native, intent, native.intentSha256);
  const completion = hostJobCompletion(completionFixture(native));
  assert.equal(completion.analysisKind, 'checkpoint');
  const result = hostJobOutcome({ plan: null, analysis: null, completion });
  assert.equal(result.gate, 'ERROR');
  assert.ok(result.reasons.includes('host_job_worker_failed'));
});

test('the one completion decision selects final only after every outer and inner prerequisite, across all readers', () => {
  const accepted = completionFixture();
  const completed = hostJobCompletion(accepted); assert.equal(completed.analysisKind, 'report'); assert.equal(completed.finalAllowed, true);
  const changes: ((input: HostCompletionInput) => void)[] = [
    input => input.ownerTerminal = null,
    input => input.ownerTerminal!.code = 1,
    input => input.ownerTerminal!.signal = 'SIGKILL',
    input => input.ownerTerminal!.protocolValid = false,
    input => input.inputsUnchanged = false,
    input => input.containerAbsent = false,
    input => input.daemonHealthy = false,
    input => input.cancelled = true,
    input => input.recovered = true,
    input => input.native = null,
    input => input.native!.phases[1].processes[0].exitCode = 1,
    input => input.native!.phases[0].processes[0].exitCode = 1,
    input => input.failures.push('host_job_failure_unverified'),
    input => input.failures.push('job_protocol_invalid'),
    input => input.normalInner = false,
    input => input.hasFinal = false,
  ];
  for (const change of changes) {
    const input = structuredClone(accepted); change(input);
    const prefix = hostJobCompletion(input); assert.equal(prefix.analysisKind, 'checkpoint'); assert.equal(prefix.finalAllowed, false);
    assert.equal(hostJobOutcome({ plan: null, analysis: null, completion: prefix }).gate, 'ERROR');
    input.hasPrefix = false; assert.equal(hostJobCompletion(input).analysisKind, null);
  }
  const analysisFailure = hostJobCompletion({ ...accepted, failures: ['controller_integrity_failure'] });
  assert.equal(analysisFailure.analysisKind, 'report'); assert.equal(hostJobOutcome({ plan: null, analysis: null, completion: analysisFailure }).gate, 'ERROR');
});

test('deadline priority distinguishes natural terminals from the exact accounted owner stop code', () => {
  for (const [reason, code, expected] of [
    ['deadline', 1, 'ERROR'], ['deadline', 2, 'ERROR'], ['deadline', windowsOwnerForcedExit - 1, 'ERROR'],
    ['deadline', windowsOwnerForcedExit, 'INCOMPLETE'], ['deadline', 0, 'INCOMPLETE'],
    ['cancelled', windowsOwnerForcedExit, 'ERROR'], ['completed', windowsOwnerForcedExit, 'ERROR'], ['failed', 0, 'ERROR'],
  ] as const) {
    const native = nativeFixture(); native.phases[0].reason = reason; native.phases[0].processes[0].exitCode = code;
    const completion = hostJobCompletion(completionFixture(native)); assert.equal(completion.analysisKind, 'checkpoint');
    assert.equal(hostJobOutcome({ plan: null, analysis: null, completion }).gate, expected, reason + ':' + code);
  }
});

test('a delegated copy refusal uses existing reasons only after verified closure and keeps error, cancel and deadline precedence', () => {
  const input = { ...completionFixture(), hasFinal: false, hasPrefix: false, normalInner: false };
  const outcome = (value: HostCompletionInput) => hostJobOutcome({ plan: null, analysis: null, completion: hostJobCompletion(value), copyBudgetStopped: true });
  assert.deepEqual(outcome(input), { gate: 'INCOMPLETE', exitCode: 3, reasons: ['job_disk_copy_limit', 'job_analysis_missing'] });
  for (const change of [
    (value: HostCompletionInput) => { value.failures.push('job_asset_changed'); },
    (value: HostCompletionInput) => { value.cancelled = true; },
    (value: HostCompletionInput) => { value.inputsUnchanged = false; },
    (value: HostCompletionInput) => { value.containerAbsent = false; },
    (value: HostCompletionInput) => { value.recovered = true; },
    (value: HostCompletionInput) => { value.native!.phases[0].reason = 'deadline'; },
  ]) {
    const changed = structuredClone(input); change(changed); assert.equal(outcome(changed).gate, 'ERROR');
    assert.equal(outcome(changed).reasons.includes('job_disk_copy_limit'), false);
  }
});
