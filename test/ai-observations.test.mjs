import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { hostUsage, readHostTerminals, readAiArtifacts } from '../src/ai-observations.mjs';
import { hash, digest } from '../src/safety.ts';
import { summarizeHistory } from '../src/history.ts';
import { resumeSource } from '../src/resume.ts';
import { publicPackageFiles, verifyPackagePaths } from '../scripts/verify-public.ts';

const control = () => ({ expiresAt: performance.now() + 30000 });
const usageValue = { inputTokens: 3, outputTokens: 2, totalTokens: 5 };
const identity = { runId: 'fixture-run', attemptId: 'fixture-attempt', buildId: 'fixture-build' }, snapshotHash = 'a'.repeat(64);
const result = () => ({ providerSubmitInvocations: 1, scanId: 'fixture-scan', execution: { requestId: 'fixture-request' }, usage: { complete: true, observed: { ...usageValue }, requests: [{ sequence: 1, callId: 'fixture-call', usage: { ...usageValue } }] } });
const terminal = () => ({ version: 1, identity: { ...identity, requestId: 'fixture-request', scanId: 'fixture-scan', snapshotHash }, sequence: 1, sessionId: 'fixture-session', callId: 'fixture-call', submitInvoked: true, state: 'completed', closed: true, effectiveProgram: 'daybreak_blue', actualModel: 'gpt-6-sol', usage: { ...usageValue } });
async function directory() { const root = await fs.mkdtemp(path.join(tmpdir(), 'ai-observation-test-')); test.after(() => removeTempDir(root)); return root; }
async function terminals(record = terminal(), input = result()) {
  const root = await directory(); await fs.mkdir(path.join(root, 'ai')); await fs.writeFile(path.join(root, 'ai/1.terminal.json'), JSON.stringify(record));
  return readHostTerminals({ result: input, usage: hostUsage(input, 5), directory: root, identity, snapshotHash, maximumBytes: 10000, control: control() });
}
test('observed token totals remain partial until matching host terminal records prove completeness', async () => {
  const input = result(), observed = hostUsage(input, 5); assert.deepEqual(observed.tokens, { kind: 'partial', observed: usageValue });
  const accepted = await terminals(); assert.deepEqual(accepted.tokens, { kind: 'complete', observed: usageValue });
  assert.deepEqual(accepted.programs, ['daybreak_blue']); assert.deepEqual(accepted.models, ['gpt-6-sol']);
});
test('standard and failed response observations retain numeric usage without inventing Blue', async () => {
  for (const state of ['failed', 'acceptance_unknown']) {
    const record = terminal(); record.state = state; record.effectiveProgram = 'standard';
    const observed = await terminals(record); assert.deepEqual(observed.programs, ['standard']); assert.deepEqual(observed.models, ['gpt-6-sol']); assert.deepEqual(observed.tokens.observed, usageValue);
  }
});
test('absent usage stays unknown, including zero submits and a send with no trustworthy terminal response', async () => {
  for (const calls of [0, 1]) assert.deepEqual(hostUsage({ providerSubmitInvocations: calls, usage: null }, 5).tokens, { kind: 'unknown', observed: null });
  const record = terminal(); record.usage = null; record.actualModel = null; record.effectiveProgram = 'unknown'; record.state = 'acceptance_unknown';
  const input = result(); input.usage = { complete: false, observed: null, requests: [] };
  assert.deepEqual((await terminals(record, input)).tokens, { kind: 'unknown', observed: null });
});
test('missing or cross-attempt terminal records cannot certify complete usage', async () => {
  const root = await directory(), input = result(), usage = hostUsage(input, 5);
  await assert.rejects(readHostTerminals({ result: input, usage, directory: root, identity, snapshotHash, maximumBytes: 10000, control: control() }));
  for (const mutate of [r => { r.identity.attemptId = 'other'; }, r => { r.callId = 'other'; }, r => { r.sequence = 2; }, r => { r.usage.totalTokens = 6; }, r => { r.actualModel = 'arbitrary-model'; }]) {
    const record = terminal(); mutate(record); await assert.rejects(terminals(record));
  }
  assert.deepEqual(usage.tokens, { kind: 'partial', observed: usageValue });
});
test('invalid counters, sums, repeated sequences and overflowing totals are rejected', () => {
  for (const calls of [-1, NaN, 1.5, 6]) assert.throws(() => hostUsage({ providerSubmitInvocations: calls, usage: null }, 5), /ai_usage_invalid/);
  for (const mutate of [r => { r.usage.observed.totalTokens = 6; }, r => { r.usage.requests[0].sequence = 2; }, r => { r.usage.requests.push(r.usage.requests[0]); }, r => { r.usage.requests[0].usage.inputTokens = Number.MAX_SAFE_INTEGER; }]) {
    const input = result(); mutate(input); assert.throws(() => hostUsage(input, 5), /ai_usage_invalid/);
  }
});
async function artifacts(mutate = () => {}) {
  const root = await directory(); await fs.mkdir(path.join(root, 'artifacts'));
  const plan = { commit: 'b'.repeat(40), snapshotHash, files: [{ path: 'source.ts' }, { path: '日本語.ts' }] };
  const value = { artifactsAccepted: true, originalCommit: plan.commit, snapshotHash, derivedRevision: 'c'.repeat(40), scanId: 'fixture-scan', artifacts: [] };
  const documents = {
    'scan-manifest.json': { documentType: 'codex-security.scan-manifest', schemaVersion: '1.0', scan: { id: value.scanId, status: 'completed', target: { revision: value.derivedRevision }, scope: { includePaths: ['.'], excludePaths: [], artifactsReviewed: plan.files.map(file => file.path), limitations: [] } } },
    'findings.json': { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: value.scanId, findings: [] },
    'coverage.json': { documentType: 'codex-security.coverage', schemaVersion: '1.0', scanId: value.scanId, mode: 'repository', inventoryStrategy: 'repository', includePaths: ['.'], excludePaths: [], surfaces: [{ id: 'surface-1', label: 'Synthetic surface', disposition: 'no_issue_found', receiptRefs: ['receipt.json'] }], explicitExclusions: [], deferred: [], openQuestions: [] },
    'receipt.json': { synthetic: true },
  };
  mutate({ documents, result: value, plan });
  for (const [name, document] of Object.entries(documents)) { const bytes = Buffer.from(JSON.stringify(document)); await fs.writeFile(path.join(root, 'artifacts', name), bytes); value.artifacts.push({ path: name, bytes: bytes.length, sha256: hash(bytes) }); }
  return { root, plan, result: value, read: () => readAiArtifacts(value, root, plan, control(), 100000) };
}
test('accepted artifacts bind exact original and derived identities and include every reviewed source', async () => {
  const fixture = await artifacts(), observed = await fixture.read(); assert.deepEqual(observed.reasons, []); assert.equal(observed.observation.artifactsReviewed, 2);
  assert.equal(observed.manifest.scan.target.revision, fixture.result.derivedRevision); assert.notEqual(observed.manifest.scan.target.revision, fixture.plan.commit);
});
test('scope exclusions, deferred work, open questions and limitations remain visible as partial reasons', async () => {
  const fixture = await artifacts(({ documents }) => {
    documents['coverage.json'].explicitExclusions = [{ pattern: 'ignored', reason: 'private-canary' }];
    documents['coverage.json'].deferred = [{ id: 'deferred-1', reason: 'private-canary' }];
    documents['coverage.json'].openQuestions = [{ question: 'private-canary' }]; documents['coverage.json'].surfaces[0].disposition = 'needs_follow_up';
    documents['scan-manifest.json'].scan.scope.limitations = ['private-canary'];
  });
  const observed = await fixture.read(); assert.deepEqual(observed.reasons.sort(), ['ai_scope_incomplete','ai_scope_exclusions','ai_scope_deferred','ai_scope_open_questions','ai_scope_limitations'].sort());
  assert.equal(observed.observation.exclusions, 1); assert.equal(observed.observation.deferred, 1); assert.equal(observed.observation.openQuestions, 1); assert.equal(observed.observation.limitations, 1);
  assert.equal(JSON.stringify({ reasons: observed.reasons, observation: observed.observation, descriptors: observed.descriptors }).includes('private-canary'), false);
});
test('unknown coverage shape, omitted or duplicated source and invalid receipt references reject artifact acceptance', async () => {
  for (const mutate of [d => { d['coverage.json'].other = true; }, d => { d['coverage.json'].includePaths = ['other']; }, d => { d['coverage.json'].surfaces[0].receiptRefs = ['absent']; },
    d => { d['scan-manifest.json'].scan.scope.artifactsReviewed.pop(); }, d => { d['scan-manifest.json'].scan.scope.artifactsReviewed.push('source.ts'); }, d => { d['scan-manifest.json'].scan.target.revision = 'd'.repeat(40); }]) {
    const fixture = await artifacts(({ documents }) => mutate(documents)); await assert.rejects(fixture.read(), /ai_(scope|artifact)_identity/);
  }
});
test('artifact content changes and hardlinks cannot pass saved size and hash checks', async () => {
  for (const kind of ['changed', 'hardlink']) {
    const fixture = await artifacts(), file = path.join(fixture.root, 'artifacts/receipt.json');
    if (kind === 'changed') await fs.writeFile(file, '{}'); else await fs.link(file, path.join(fixture.root, 'other.json'));
    await assert.rejects(fixture.read());
  }
});
function historyReport() {
  const root = path.resolve('test');
  return { schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555', startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', gate: 'PASS', executionState: 'completed', coverageState: 'complete', integrityErrors: [],
    plan: { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64), planHash: 'c'.repeat(64), snapshotHash: 'd'.repeat(64), required: ['gitleaks','osv','codex-security','runtime-advisories'], blockers: [], exclusions: [] },
    engines: ['gitleaks','osv','codex-security','runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed', errors: [], usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) };
}
const history = report => summarizeHistory([Buffer.from(JSON.stringify(report))]).summary.runs[0];
function completedProviderHistory() {
  const report = historyReport(), files = [{ path: 'source.ts', bytes: 1, sha256: '1'.repeat(64) }];
  report.plan.files = files;
  report.plan.network = 'openai-responses';
  report.plan.ai = { schema: 'scanmux.ai-plan/v1', source: { files: files.length, snapshotHash: report.plan.snapshotHash, manifestSha256: digest(files) }, runtime: { imageDigest: 'sha256:' + '2'.repeat(64) } };
  const run = report.engines[2]; run.usage.calls = 1;
  run.aiExecution = {
    schema: 'scanmux.ai-execution/v1', classification: 'provider', status: 'completed', artifactsAccepted: true,
    originalCommit: report.plan.commit, snapshotHash: report.plan.snapshotHash, manifestSha256: digest(files), sourcePreflight: 'completed',
    submitInvocations: 1, connectionAttempts: 1, sendInvocations: 1, tokens: { kind: 'complete', observed: usageValue }, usageRecords: [{ sequence: 1, usage: usageValue }],
    programs: ['daybreak_blue'], cleanup: { closed: true, quiescent: true, containerAbsent: true },
    runtime: { imageDigest: report.plan.ai.runtime.imageDigest, boundaryVerified: true },
    coverage: { artifactsReviewed: 1, exclusions: 0, deferred: 0, openQuestions: 0, limitations: 0, sha256: '3'.repeat(64) },
    artifacts: ['scan-manifest.json', 'findings.json', 'coverage.json'].map(path => ({ path, bytes: 1, sha256: '4'.repeat(64) }))
  };
  report.plan.planHash = digest({ ...report.plan, planHash: '' });
  return report;
}
test('saved provider completion requires acceptance, a verified program, cleanup, scope and source evidence together', () => {
  const positive = history(completedProviderHistory());
  assert.equal(positive.completion, 'complete'); assert.deepEqual(positive.reasons, []);
  assert.deepEqual(positive.engines[2].ai.tokens.observed, usageValue);
  const cases = [];
  for (const status of ['not_started', 'failed', 'canceled', 'budget_exceeded', 'acceptance_unknown', undefined]) cases.push(['status ' + status, r => { r.engines[2].aiExecution.status = status; }]);
  for (const accepted of [false, undefined]) cases.push(['acceptance ' + accepted, r => { r.engines[2].aiExecution.artifactsAccepted = accepted; }]);
  for (const programs of [[], ['unknown'], ['daybreak_red'], ['standard', 'unknown'], ['daybreak_blue', 'daybreak_red'], undefined]) cases.push(['programs ' + programs, r => { r.engines[2].aiExecution.programs = programs; }]);
  for (const field of ['closed', 'quiescent', 'containerAbsent']) for (const value of [false, undefined]) cases.push(['cleanup ' + field + value, r => { r.engines[2].aiExecution.cleanup[field] = value; }]);
  for (const field of ['exclusions', 'deferred', 'openQuestions', 'limitations']) for (const value of [1, undefined]) cases.push(['scope ' + field + value, r => { r.engines[2].aiExecution.coverage[field] = value; }]);
  for (const reviewed of [0, 2, undefined]) cases.push(['reviewed ' + reviewed, r => { r.engines[2].aiExecution.coverage.artifactsReviewed = reviewed; }]);
  for (const field of ['status', 'artifactsAccepted', 'programs', 'cleanup', 'coverage', 'runtime', 'sourcePreflight', 'originalCommit', 'snapshotHash', 'manifestSha256', 'artifacts']) cases.push(['missing ' + field, r => { delete r.engines[2].aiExecution[field]; }]);
  cases.push(['synthetic inference', r => { r.engines[2].aiExecution.classification = 'synthetic'; }],
    ['partial token observation', r => { r.engines[2].aiExecution.tokens.kind = 'partial'; }],
    ['scope digest absent', r => { delete r.engines[2].aiExecution.coverage.sha256; }],
    ['source count absent', r => { delete r.plan.ai.source.files; }], ['source count mismatch', r => { r.plan.ai.source.files = 2; }],
    ['source manifest mismatch', r => { r.engines[2].aiExecution.manifestSha256 = '5'.repeat(64); }],
    ['source revision mismatch', r => { r.engines[2].aiExecution.originalCommit = '5'.repeat(40); }],
    ['snapshot mismatch', r => { r.engines[2].aiExecution.snapshotHash = '5'.repeat(64); }],
    ['preflight absent', r => { r.engines[2].aiExecution.sourcePreflight = 'not_completed'; }],
    ['boundary unverified', r => { r.engines[2].aiExecution.runtime.boundaryVerified = false; }],
    ['image mismatch', r => { r.engines[2].aiExecution.runtime.imageDigest = 'sha256:' + '5'.repeat(64); }],
    ['missing artifact', r => { r.engines[2].aiExecution.artifacts.pop(); }],
    ['empty artifact set', r => { r.engines[2].aiExecution.artifacts = []; }],
    ['AI errors', r => { r.engines[2].errors = ['private-canary']; }], ['AI errors missing', r => { delete r.engines[2].errors; }]);
  for (const [name, mutate] of cases) {
    const report = completedProviderHistory(); mutate(report); const before = JSON.stringify(report), row = history(report);
    assert.equal(row.completion, 'incomplete', name); assert.equal(row.recordedGate, 'PASS', name);
    assert.ok(row.reasons.some(reason => reason.startsWith('ai_')), name);
    assert.ok(row.reasons.includes('recorded_pass_conflicts_with_completion'), name);
    assert.deepEqual(row.engines[2].ai.tokens.observed, usageValue, name); assert.equal(row.reportedCalls, 1, name);
    assert.equal(JSON.stringify(report), before, name); assert.ok(!JSON.stringify(row).includes('private-canary'), name);
  }
});

for (const programs of [['standard'], ['daybreak_blue'], ['daybreak_blue', 'standard']]) test(`saved ${programs} satisfies the AI program gate without changing recorded values`, () => {
  const report = completedProviderHistory(), run = report.engines[2];
  run.accessProgramRequested = 'daybreak_blue'; run.accessProgramEffective = programs.length === 1 ? programs[0] : 'unknown'; run.aiExecution.programs = programs;
  const before = JSON.stringify(report), row = history(report);
  assert.equal(row.completion, 'complete'); assert.deepEqual(row.reasons, []); assert.deepEqual(row.engines[2].ai.programs, programs); assert.equal(JSON.stringify(report), before);
});

for (const [name, change, reason] of [
  ['synthetic', ai => { ai.classification = 'synthetic'; }, 'ai_synthetic_evidence'],
  ['unknown usage', ai => { ai.tokens = { kind: 'unknown', observed: null }; ai.usageRecords = []; }, 'ai_usage_incomplete'],
  ['unverified interruption', ai => { ai.status = 'acceptance_unknown'; ai.cleanup.quiescent = false; }, 'ai_cleanup_unverified'],
  ['missing artifacts', ai => { ai.artifacts = []; }, 'ai_artifact_acceptance_unverified'],
]) test(`standard still refuses saved ${name}`, () => {
  const report = completedProviderHistory(), ai = report.engines[2].aiExecution; ai.programs = ['standard']; change(ai);
  const row = history(report); assert.equal(row.completion, 'incomplete'); assert.ok(row.reasons.includes(reason)); assert.ok(!row.reasons.includes('ai_effective_program_unverified'));
});
test('saved AI evidence retains failed acceptance, program and cleanup beside observed usage', () => {
  const report = completedProviderHistory(), ai = report.engines[2].aiExecution;
  ai.status = 'acceptance_unknown'; ai.artifactsAccepted = false; ai.programs = ['standard']; ai.cleanup.quiescent = false;
  const row = history(report), saved = row.engines[2].ai;
  assert.equal(row.completion, 'incomplete'); assert.equal(saved.status, 'acceptance_unknown'); assert.equal(saved.artifactsAccepted, false);
  assert.deepEqual(saved.programs, ['standard']); assert.equal(saved.cleanup.quiescent, false);
  assert.deepEqual(saved.coverage, ai.coverage); assert.deepEqual(saved.tokens.observed, usageValue);
});
test('old history remains readable while synthetic, partial and absent AI observations prevent a completion claim', () => {
  assert.equal(history(historyReport()).completion, 'complete');
  const report = historyReport(); report.plan.ai = {}; report.plan.network = 'openai-responses'; assert.equal(history(report).completion, 'incomplete');
  const ai = report.engines[2]; ai.usage.calls = 1; ai.aiExecution = { schema: 'scanmux.ai-execution/v1', classification: 'synthetic', submitInvocations: 1, connectionAttempts: 1, sendInvocations: 1, tokens: { kind: 'complete', observed: usageValue }, usageRecords: [{ sequence: 1, usage: usageValue }] };
  assert.equal(history(report).completion, 'incomplete'); ai.aiExecution.classification = 'provider'; ai.aiExecution.tokens.kind = 'partial';
  const partial = history(report); assert.equal(partial.completion, 'incomplete'); assert.deepEqual(partial.engines[2].ai.tokens, { kind: 'partial', observed: usageValue }); assert.equal(partial.recordedGate, 'PASS');
});
test('history rejects corrupt AI usage and AI reports cannot authorize resume', () => {
  const report = historyReport(); report.plan.ai = {}; report.plan.network = 'openai-responses'; report.executionState = 'cancelled';
  assert.throws(() => resumeSource(Buffer.from(JSON.stringify(report)), report.plan.root), /resume_ai_unsupported/);
  const ai = report.engines[2]; ai.usage.calls = 1; ai.aiExecution = { schema: 'scanmux.ai-execution/v1', classification: 'provider', submitInvocations: 1, connectionAttempts: 1, sendInvocations: 1, tokens: { kind: 'complete', observed: usageValue }, usageRecords: [{ sequence: 1, usage: usageValue }] };
  for (const mutate of [x => { x.tokens.observed.totalTokens = 7; }, x => { x.connectionAttempts = 2; }, x => { x.usageRecords = []; }, x => { x.tokens.kind = 'unknown'; }]) {
    const input = structuredClone(report); mutate(input.engines[2].aiExecution); assert.throws(() => history(input), /invalid_history_ai_usage/);
  }
});
test('package admission rejects stray internal files and includes canonical runtime and resource contract modules', async () => {
  verifyPackagePaths(publicPackageFiles);
  const internal = publicPackageFiles.filter(name => name.startsWith('internal/')), manifest = JSON.parse(await fs.readFile('package.json', 'utf8'));
  assert.equal(internal.length, 23); assert.deepEqual(manifest.files.filter(name => name.startsWith('internal/')).sort(), internal);
  for (const name of ['internal/job-channel.mjs', 'internal/job-channel.d.mts', 'internal/linux-job-controller.mjs', 'internal/reproduction-driver.mjs', 'internal/linux-job-supervisor.py', 'internal/windows-job-owner.cs', 'internal/windows-retained-store.cs', 'internal/windows-job-worker.mjs', 'scripts/build-windows-job-owner.ps1', 'src/retained-write.ts', 'internal/windows-process-owner.cs', 'scripts/build-windows-process-owner.ps1', 'src/process-tree.ts']) assert.ok(publicPackageFiles.includes(name));
  assert.ok(publicPackageFiles.includes('internal/sdk-initialization-observer.mjs'));
  assert.ok(publicPackageFiles.includes('internal/sdk-native-observer.py'));
  assert.ok(publicPackageFiles.includes('internal/worker-resources.mjs')); assert.ok(publicPackageFiles.includes('internal/worker-resources.d.mts'));
  for (const name of ['internal/extra.mjs', 'internal/scanmux-windows-job-owner.exe', 'internal/scanmux-windows-process-owner.exe', '.local/config.json', 'docs/private-plan.md', 'src/stray.ts']) assert.throws(() => verifyPackagePaths([...publicPackageFiles, name]));
  assert.throws(() => verifyPackagePaths(publicPackageFiles.filter(name => name !== 'internal/reproduction-driver.mjs')));
  assert.equal(digest(publicPackageFiles).length, 64);
});
