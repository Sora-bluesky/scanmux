import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { parseWorkerResources, expectedResourceKernel, parseResourceSnapshot, buildWorkerResourceReport, workerResourcesComplete, classifyResourceStop, probeWorkerDisk } from '../internal/worker-resources.mjs';
import { summarizeHistory } from '../src/history.ts';
import { ciReceipt, evaluateCi } from '../src/ci.ts';
import { digest, hash, SafeError } from '../src/safety.ts';

const limits = { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 };
const kernel = { cpuQuota: 100000, cpuPeriod: 100000, memoryMax: 268435456, swapMax: 0, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 };
const events = { cpuThrottledPeriods: 0, oom: 0, oomKill: 0 };
const completeResources = () => ({ schema: 'scanmux.worker-resources/v1', state: 'verified', requested: structuredClone(limits), kernel: structuredClone(kernel), events: structuredClone(events), terminal: { exitCode: 0, oomKilled: false }, exceeded: [] });

test('resource profiles are explicit, closed and exactly representable by the Linux boundary', () => {
  assert.deepEqual(parseWorkerResources(limits), limits); assert.deepEqual(expectedResourceKernel(limits), kernel);
  const cases = [undefined, null, {}, { ...limits, extra: 1 }];
  for (const field of Object.keys(limits)) for (const value of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', null]) cases.push({ ...limits, [field]: value });
  for (const field of ['memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes']) cases.push({ ...limits, [field]: limits[field] + 1 });
  cases.push({ ...limits, cpuCount: Number.MAX_SAFE_INTEGER }, { ...limits, memoryBytes: 5 * 1024 * 1024 });
  for (const input of cases) assert.throws(() => parseWorkerResources(input), /invalid_worker_resources/);
  assert.deepEqual(parseWorkerResources({ ...limits, memoryBytes: 6 * 1024 * 1024, tmpBytes: 4096, workBytes: 4096, shmBytes: 4096 }), { ...limits, memoryBytes: 6 * 1024 * 1024, tmpBytes: 4096, workBytes: 4096, shmBytes: 4096 });
});

test('each requested kernel cap and the closed observation must match; throttling is a normal observation', () => {
  const input = { kernel: structuredClone(kernel), events: { ...events, cpuThrottledPeriods: 17 } };
  assert.deepEqual(parseResourceSnapshot(input, limits), input);
  for (const field of Object.keys(kernel)) for (const value of [undefined, kernel[field] + 1, -1, '0']) {
    const changed = structuredClone(input); changed.kernel[field] = value; assert.throws(() => parseResourceSnapshot(changed, limits), /resource_boundary_unverified/);
  }
  for (const field of Object.keys(events)) for (const value of [undefined, -1, 1.1, '0']) {
    const changed = structuredClone(input); changed.events[field] = value; assert.throws(() => parseResourceSnapshot(changed, limits), /resource_boundary_unverified/);
  }
  for (const mutate of [x => { x.extra = 1; }, x => { x.kernel.extra = 1; }, x => { x.events.extra = 1; }]) {
    const changed = structuredClone(input); mutate(changed); assert.throws(() => parseResourceSnapshot(changed, limits));
  }
  const resource = completeResources(); resource.events.cpuThrottledPeriods = 17; assert.equal(workerResourcesComplete(resource, limits), true);
});

test('missing, partial, OOM and altered records never become complete resource evidence', () => {
  const valid = completeResources(); assert.equal(workerResourcesComplete(valid, limits), true);
  for (const field of Object.keys(valid)) {
    const missing = structuredClone(valid); delete missing[field]; assert.equal(workerResourcesComplete(missing, limits), false, field);
    const nulled = structuredClone(valid); nulled[field] = null; assert.equal(workerResourcesComplete(nulled, limits), false, field);
  }
  for (const mutate of [x => { x.events.oom = 1; }, x => { x.events.oomKill = 1; }, x => { x.terminal.oomKilled = true; }, x => { x.terminal.exitCode = 137; },
    x => { x.exceeded = ['memory']; }, x => { x.state = 'not_verified'; }, x => { x.requested.memoryBytes *= 2; }, x => { x.kernel.memoryMax *= 2; }, x => { x.extra = 'private-canary'; }]) {
    const changed = structuredClone(valid); mutate(changed); assert.equal(workerResourcesComplete(changed, limits), false);
  }
});

test('host termination preserves known OOM when PID 1 cannot produce a final observation', () => {
  const report = buildWorkerResourceReport({ requested: limits, boundaryVerified: true, startupVerified: true, snapshot: null, terminal: { exitCode: 137, oomKilled: true } });
  assert.equal(report.state, 'not_verified'); assert.equal(report.events, null); assert.deepEqual(report.terminal, { exitCode: 137, oomKilled: true }); assert.deepEqual(report.exceeded, ['memory']);
  assert.equal(workerResourcesComplete(report, limits), false);
  const absent = buildWorkerResourceReport({ requested: limits, boundaryVerified: true, startupVerified: true, snapshot: { kernel, events }, terminal: undefined });
  assert.equal(absent.state, 'not_verified'); assert.equal(absent.terminal, null);
  const startedWithOom = buildWorkerResourceReport({ requested: limits, boundaryVerified: true, startupVerified: true, snapshot: { kernel, events: { ...events, oom: 1 } }, terminal: { exitCode: 0, oomKilled: false } });
  assert.equal(startedWithOom.state, 'verified'); assert.deepEqual(startedWithOom.exceeded, ['memory']); assert.equal(workerResourcesComplete(startedWithOom, limits), false);
  const disk = buildWorkerResourceReport({ requested: limits, boundaryVerified: true, failureCode: 'resource_disk_exceeded', terminal: { exitCode: 1, oomKilled: false } });
  assert.deepEqual(disk.exceeded, ['disk']);
  const unknown = buildWorkerResourceReport({ requested: limits, boundaryVerified: true, failureCode: 'arbitrary private-canary', terminal: { exitCode: 1, oomKilled: false } });
  assert.deepEqual(unknown.exceeded, []); assert.ok(!JSON.stringify(unknown).includes('private-canary'));
});

const stopOptions = () => ({ resources: { ...completeResources(), exceeded: ['memory'] }, reason: 'bridge_early_eof', boundaryVerified: true, inputsUnchanged: true,
  workerClosed: true, containerAbsent: true, transportClosed: true, independentFailure: false, mcpEvidence: 'not_started', artifactEvidence: 'none', calls: 0, tokensComplete: false, executionStatus: undefined });

test('the predeclared decision table distinguishes known limits from independent evidence failures', () => {
  const base = stopOptions(); assert.equal(classifyResourceStop(base), 'resource_memory_exceeded');
  for (const field of ['boundaryVerified', 'inputsUnchanged', 'workerClosed', 'containerAbsent', 'transportClosed']) for (const value of [false, undefined]) assert.equal(classifyResourceStop({ ...base, [field]: value }), null, field);
  assert.equal(classifyResourceStop({ ...base, independentFailure: true }), null);
  for (const [field, values] of [['mcpEvidence', ['unverified', undefined, null, true, 'unknown']], ['artifactEvidence', ['unverified', undefined, null, true, 'unknown']]])
    for (const value of values) assert.equal(classifyResourceStop({ ...base, [field]: value }), null, field + ':' + value);
  for (const mcpEvidence of ['not_started', 'closed']) for (const artifactEvidence of ['none', 'verified'])
    assert.equal(classifyResourceStop({ ...base, mcpEvidence, artifactEvidence }), 'resource_memory_exceeded');
  assert.equal(classifyResourceStop({ ...base, reason: 'bridge_inputs_changed' }), null);
  assert.equal(classifyResourceStop({ ...base, reason: 'worker_sdk_initialization_failed', resources: { ...completeResources(), exceeded: ['disk'] } }), null);
  assert.equal(classifyResourceStop({ ...base, calls: 1 }), null);
  assert.equal(classifyResourceStop({ ...base, calls: 1, tokensComplete: true, executionStatus: 'acceptance_unknown' }), null);
  assert.equal(classifyResourceStop({ ...base, calls: 1, tokensComplete: true, executionStatus: 'completed' }), 'resource_memory_exceeded');
  assert.equal(classifyResourceStop({ ...base, resources: { ...completeResources(), exceeded: ['disk'] } }), 'resource_disk_exceeded');
  assert.equal(classifyResourceStop({ ...base, resources: { ...completeResources(), exceeded: ['time'] }, reason: 'ipc_deadline' }), 'time_budget_exceeded');
  assert.equal(classifyResourceStop({ ...base, resources: { ...completeResources(), events: { ...events, cpuThrottledPeriods: 50 } } }), null);
});

test('bounded disk observation requires a full page or actual ENOSPC and known close/removal', async () => {
  for (const fault of ['none', 'full', 'short', 'unknown', 'close', 'unlink']) {
    const paths = [], removed = [];
    const io = { async open(name, flag, mode) {
      paths.push(name); assert.equal(flag, 'wx'); assert.equal(mode, 0o600);
      return { async write(bytes) { assert.equal(bytes.length, 4096); if (fault === 'full' || fault === 'unknown') throw Object.assign(Error('private'), { code: fault === 'full' ? 'ENOSPC' : 'EIO' }); return { bytesWritten: fault === 'short' ? 2 : 4096 }; }, async close() { if (fault === 'close') throw Error('private'); } };
    }, async unlink(name) { removed.push(name); if (fault === 'unlink') throw Error('private'); } };
    const result = await probeWorkerDisk(io);
    assert.equal(paths.length, 3); assert.deepEqual(removed, paths);
    for (const [index, folder] of ['/tmp/', '/work/', '/dev/shm/'].entries()) assert.ok(paths[index].startsWith(folder + '.scanmux-resource-'));
    assert.equal(result.observationComplete, ['none', 'full'].includes(fault)); assert.deepEqual(result.fullStores, fault === 'full' ? ['tmp', 'work', 'shm'] : []);
  }
});

test('every SDK failure reason remains an independent error even alongside known memory, disk or time exhaustion', () => {
  for (const reason of ['worker_sdk_initialization_failed', 'worker_sdk_finalization_failed', 'worker_mcp_failed', 'bridge_sdk_failed']) {
    for (const exceeded of [['memory'], ['disk'], ['time']]) {
      for (const calls of [0, 1]) assert.equal(classifyResourceStop({ ...stopOptions(), reason, calls, tokensComplete: true, executionStatus: 'completed', resources: { ...completeResources(), exceeded } }), null);
    }
  }
});

function providerShape() {
  const root = path.resolve('test'), files = [{ path: 'source.ts', bytes: 1, sha256: 'a'.repeat(64) }], snapshotHash = digest(files);
  const report = { schema: 'scanmux.report/v2', runId: 'abcdefab-1111-2222-3333-444444444444', startedAt: '2026-10-23T00:00:00Z', endedAt: '2026-10-23T00:00:01Z', gate: 'PASS', exitCode: 0, executionState: 'completed', coverageState: 'complete', integrityErrors: [],
    plan: { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64), planHash: '', snapshotHash, files, required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], blockers: [], exclusions: [], network: 'openai-responses',
      ai: { schema: 'scanmux.ai-plan/v2', workerResources: structuredClone(limits), source: { files: 1, snapshotHash, manifestSha256: snapshotHash }, runtime: { imageDigest: 'sha256:' + 'd'.repeat(64) } } },
    engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed', errors: [], usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) };
  report.engines[2].usage.calls = 1;
  report.engines[2].aiExecution = { schema: 'scanmux.ai-execution/v2', classification: 'provider', status: 'completed', artifactsAccepted: true, originalCommit: report.plan.commit, snapshotHash, manifestSha256: snapshotHash, sourcePreflight: 'completed',
    submitInvocations: 1, connectionAttempts: 1, sendInvocations: 1, tokens: { kind: 'complete', observed: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } }, usageRecords: [{ sequence: 1, usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } }], programs: ['daybreak_blue'], cleanup: { closed: true, quiescent: true, containerAbsent: true },
    runtime: { imageDigest: report.plan.ai.runtime.imageDigest, boundaryVerified: true, resources: completeResources() }, coverage: { artifactsReviewed: 1, exclusions: 0, deferred: 0, openQuestions: 0, limitations: 0, sha256: 'e'.repeat(64) },
    artifacts: ['scan-manifest.json', 'findings.json', 'coverage.json'].map(path => ({ path, bytes: 1, sha256: 'f'.repeat(64) })) };
  report.plan.planHash = digest({ ...report.plan, planHash: '' }); return report;
}
const bytes = report => Buffer.from(JSON.stringify(report, null, 2) + '\n');
const ciRun = '11111111-2222-3333-4444-555555555555';
const expected = report => ({ schema: 'scanmux.ci-expectation/v2', ciRun, jobs: [{ id: 'ai', analysis: 'ai', targetRoot: report.plan.root,
  ...Object.fromEntries(['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash'].map(key => [key, report.plan[key]])) }] });
const evaluate = (report, expectation = expected(report)) => evaluateCi(expectation, [ciReceipt({ report, json: bytes(report).toString('utf8') }, ciRun, 'ai')], [bytes(report)]);
const history = report => summarizeHistory([bytes(report)]).summary.runs[0];

test('a complete current resource record can finish shared history and CI; this is provider-shaped structural evidence only', () => {
  const report = providerShape(); assert.equal(history(report).completion, 'complete'); assert.equal(history(report).engines[2].ai.resources.state, 'complete'); assert.equal(evaluate(report).gate, 'PASS');
  report.engines[2].aiExecution.runtime.resources.events.cpuThrottledPeriods = 23;
  assert.equal(history(report).completion, 'complete'); assert.equal(evaluate(report).gate, 'PASS');
});

test('all current resource deletions, nulls, mismatches and actual exceedance refuse completion', () => {
  const cases = [r => { delete r.plan.ai.workerResources; }, r => { r.plan.ai.workerResources = null; }, r => { delete r.engines[2].aiExecution.runtime.resources; }, r => { r.engines[2].aiExecution.runtime.resources = null; },
    r => { r.plan.ai.schema = 'scanmux.ai-plan/v1'; }, r => { r.engines[2].aiExecution.schema = 'scanmux.ai-execution/v1'; }, r => { delete r.plan.ai.workerResources; delete r.engines[2].aiExecution.runtime.resources; }];
  for (const field of Object.keys(limits)) cases.push(r => { r.plan.ai.workerResources[field] += field === 'cpuCount' ? 1 : 4096; }, r => { r.engines[2].aiExecution.runtime.resources.requested[field] += field === 'cpuCount' ? 1 : 4096; });
  for (const field of Object.keys(kernel)) cases.push(r => { r.engines[2].aiExecution.runtime.resources.kernel[field]++; });
  for (const cause of ['memory', 'disk', 'time']) cases.push(r => { r.engines[2].aiExecution.runtime.resources.exceeded = [cause]; });
  cases.push(r => { r.engines[2].aiExecution.runtime.resources.events.oom = 1; }, r => { r.engines[2].aiExecution.runtime.resources.events.oomKill = 1; },
    r => { r.engines[2].aiExecution.runtime.resources.terminal.oomKilled = true; }, r => { r.engines[2].aiExecution.runtime.resources.terminal = null; });
  for (const mutate of cases) {
    const report = providerShape(), expectation = expected(report); mutate(report);
    assert.equal(history(report).completion, 'incomplete'); assert.notEqual(evaluate(report, expectation).gate, 'PASS');
    assert.equal(history(report).reportedCalls, 1); assert.deepEqual(history(report).engines[2].ai.tokens.observed, { inputTokens: 3, outputTokens: 2, totalTokens: 5 });
  }
});

test('dropping both new schemas and resource fields cannot retain the originally accepted CI identity', () => {
  for (const rehash of [false, true]) {
    const report = providerShape(), expectation = expected(report);
    report.plan.ai.schema = 'scanmux.ai-plan/v1'; report.engines[2].aiExecution.schema = 'scanmux.ai-execution/v1';
    delete report.plan.ai.workerResources; delete report.engines[2].aiExecution.runtime.resources;
    if (rehash) report.plan.planHash = digest({ ...report.plan, planHash: '' });
    const row = history(report); assert.equal(row.engines[2].ai.resources.state, 'legacy_unrecorded'); assert.notEqual(evaluate(report, expectation).gate, 'PASS');
    if (!rehash) assert.equal(row.completion, 'incomplete');
  }
});

test('altering a requested cap and self-rehashing cannot authorize the original expected job', () => {
  const report = providerShape(), expectation = expected(report);
  report.plan.ai.workerResources.memoryBytes *= 2;
  report.engines[2].aiExecution.runtime.resources.requested.memoryBytes *= 2;
  report.engines[2].aiExecution.runtime.resources.kernel.memoryMax *= 2;
  report.plan.planHash = digest({ ...report.plan, planHash: '' });
  assert.equal(history(report).completion, 'complete'); assert.equal(evaluate(report, expectation).gate, 'ERROR');
});

test('legacy records remain readable without being converted into resource assurance', () => {
  const report = providerShape(); report.plan.ai.schema = 'scanmux.ai-plan/v1'; report.engines[2].aiExecution.schema = 'scanmux.ai-execution/v1';
  delete report.plan.ai.workerResources; delete report.engines[2].aiExecution.runtime.resources; report.plan.planHash = digest({ ...report.plan, planHash: '' });
  const row = history(report); assert.equal(row.completion, 'complete'); assert.equal(row.engines[2].ai.resources.state, 'legacy_unrecorded'); assert.equal(row.engines[2].ai.resources.exceeded, null); assert.equal(row.reportedCalls, 1);
});

test('resource defects preserve stronger FAIL and ERROR CI results and never emit private text', () => {
  for (const gate of ['PASS', 'REVIEW', 'INCOMPLETE', 'FAIL', 'ERROR']) {
    const report = providerShape(); report.gate = gate; report.exitCode = { PASS: 0, REVIEW: 2, INCOMPLETE: 3, FAIL: 1, ERROR: 4 }[gate];
    report.engines[2].aiExecution.runtime.resources.exceeded = ['memory']; report.engines[2].aiExecution.runtime.resources.private = 'private-canary';
    const result = evaluate(report); assert.equal(result.gate, ['FAIL', 'ERROR'].includes(gate) ? gate : 'INCOMPLETE'); assert.ok(!JSON.stringify(result).includes('private-canary'));
  }
  const malformed = providerShape(); malformed.engines[2].aiExecution.schema = 'unknown';
  assert.throws(() => history(malformed), error => error instanceof SafeError && error.code === 'invalid_history_ai_usage');
});
