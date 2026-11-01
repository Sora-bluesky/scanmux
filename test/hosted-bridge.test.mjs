import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { EventEmitter } from 'node:events';
import { registerHooks } from 'node:module';
import { runInNewContext } from 'node:vm';
import { privateWorkspace } from '../src/private-storage.ts';
import { createHostedChannel } from '../internal/hosted-channel.mjs';
import { runHostedBridge, validateBridgeArtifacts } from '../internal/hosted-bridge.mjs';
import { validateLinuxHostedBoundary } from '../internal/linux-hosted-runner.mjs';
import { validateAiArtifactDocuments } from '../src/ai-observations.mjs';
import { normalizeProjectedCodex } from '../src/adapters.ts';
import { classifyResourceStop } from '../internal/worker-resources.mjs';
import { expectedResourceKernel } from '../internal/worker-resources.mjs';
import { defaults } from '../src/config.ts';
import { aiRuntime } from '../src/ai-plan.ts';
import { toolFailureCodes } from '../internal/ai-session.mjs';

const root = await privateWorkspace(process.cwd());
test.after(() => removeTempDir(root));
const schema = JSON.parse(await fs.readFile(new URL('./fixtures/codex-security-draft-input-schema.json', import.meta.url)));
const hash = bytes => createHash('sha256').update(bytes).digest('hex'), digest = value => hash(JSON.stringify(value));
const content = 'export const value = 1;\n';
const certificate = bytes => ({ bytes: bytes.length, sha256: hash(bytes) });
function deferred() { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; }
function data() {
  const files = [{ path: 'source.ts', bytes: Buffer.byteLength(content), sha256: hash(content) }], config = {};
  const plan = { schema: 'scanmux.plan/v2', root: 'synthetic', files, commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), exclusions: [], blockers: [], dirty: false, policyHash: digest(config), snapshotHash: digest(files), planHash: '' }; plan.planHash = digest(plan);
  const mapping = { schema: 'scanmux.sdk-projection/v1', originalCommit: plan.commit, originalTree: plan.treeHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash, projectionScope: 'accepted_files_only', projectedMode: '100644', manifest: files, originalExclusions: [], derivedRevision: 'd'.repeat(40) };
  const identity = { runId: randomUUID(), attemptId: randomUUID(), buildId: 'build' }, scope = { paths: ['source.ts'] };
  const input = { plan, config, projection: { status: 'completed', mapping, scope } };
  const binding = { repository: '/handoff', revision: mapping.derivedRevision, originalCommit: plan.commit, snapshotHash: plan.snapshotHash, scope, identity, reasoningEffort: 'high', manifest: files };
  const runtime = { pluginRoot: '/assets/node_modules/@openai/codex-security/_bundled_plugin', pluginVersion: '0.1.95', stateDirectory: '/work/state', outputDirectory: '/work/outputs', environment: { PATH: '/usr/local/bin:/usr/bin:/bin', CODEX_SECURITY_SCAN_ID: 'scan', CODEX_SECURITY_REPOSITORY: '/handoff', CODEX_SECURITY_STATE_DIR: '/work/state', CODEX_SECURITY_SCAN_DIR: '/work/outputs', CODEX_SECURITY_PLUGIN_ROOT: '/assets/node_modules/@openai/codex-security/_bundled_plugin', CODEX_SECURITY_TARGET_REVISION: mapping.derivedRevision, CODEX_SECURITY_SURFACE: 'sdk' } };
  const request = { version: 2, requestId: 'request', scanId: 'scan', repository: '/handoff', revision: binding.revision, scope, identity, prompt: 'Synthetic SDK prompt.', model: 'gpt-6-sol', reasoningEffort: 'high', runtime };
  const expectedStartup = { sourceReceiptsSha256: 'f'.repeat(64), uid: 1000 };
  return { input, binding, request, expectedStartup, sources: new Map([['source.ts', content]]) };
}
const draft = complete => ({ complete, scope: { artifactsReviewed: ['source.ts'] }, threatModel: { summary: 'Synthetic fixture.' }, findings: [], coverage: { surfaces: [{ label: 'Synthetic source', disposition: 'no_issue_found' }], explicitExclusions: [], deferred: [] } });
function response(context) {
  const calls = context.sequence === 1 ? [{ id: 'read_1', name: 'scanmux_read_source', arguments: { path: 'source.ts' } }] : context.sequence === 2 || context.sequence === 3 ? [{ id: 'draft_' + context.sequence, name: 'record_codex_security_scan_draft', arguments: draft(context.sequence === 3) }] : [];
  return { sessionId: context.sessionId, callId: context.callId, requestId: context.identity.requestId, responseId: 'response_' + context.sequence, status: 'completed', model: 'gpt-6-sol', effectiveProgram: 'daybreak_blue', usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 }, output: [{ type: 'message', id: 'message_' + context.sequence, role: 'assistant', phase: calls.length ? 'commentary' : 'final_answer', status: 'completed', content: [{ type: 'output_text', text: 'Synthetic only.', annotations: [] }] }, ...calls.map((call, index) => ({ type: 'function_call', id: 'function_' + context.sequence + '_' + index, call_id: call.id, name: call.name, arguments: JSON.stringify(call.arguments), status: 'completed' }))] };
}
function artifactPayload(f, execution = { requestId: 'request', status: 'completed', sessionId: 'session', finalResponse: 'Synthetic only.', usage: { observed: { inputTokens: 12, outputTokens: 8, totalTokens: 20 }, complete: true, requests: [] } }) {
  const status = execution.status === 'completed' ? 'completed' : ['canceled', 'acceptance_unknown'].includes(execution.status) ? execution.status : 'failed';
  const findings = { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'scan', findings: [] }, coverage = { documentType: 'codex-security.coverage', schemaVersion: '1.0', scanId: 'scan', mode: 'repository', inventoryStrategy: 'repository', includePaths: ['.'], excludePaths: [], surfaces: [{ id: 'surface-1', label: 'Synthetic source', disposition: 'no_issue_found', receiptRefs: [] }], explicitExclusions: [], deferred: [], openQuestions: [] };
  const json = value => JSON.stringify(value) + '\n';
  const make = (name, text) => ({ path: name, bytes: Buffer.byteLength(text), sha256: hash(text), content: text });
  const artifacts = status !== 'completed' ? [] : [make('findings.json', json(findings)), make('coverage.json', json(coverage)), make('report.md', '# Synthetic report\n')];
  if (status === 'completed') artifacts.push(make('scan-manifest.json', json({ documentType: 'codex-security.scan-manifest', schemaVersion: '1.0', scan: { id: 'scan', status: 'completed', sealedAt: '2026-10-23T00:00:00.000Z', target: { revision: f.binding.revision }, scope: { includePaths: f.binding.scope.paths, excludePaths: [], artifactsReviewed: f.binding.manifest.map(item => item.path), limitations: [] }, artifacts: artifacts.filter(a => a.path.endsWith('.json')).map(a => ({ path: a.path, sha256: a.sha256, mediaType: 'application/json' })) } })));
  artifacts.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const result = { version: 2, repository: '/handoff', revision: f.binding.revision, scope: f.binding.scope, identity: f.binding.identity, outputDirectory: '/work/outputs', scanId: 'scan', pluginVersion: '0.1.95', provenance: { cliVersion: '0.5.1', pluginVersion: '0.1.95', buildId: f.binding.identity.buildId }, execution: structuredClone(execution), status, artifacts: artifacts.map(({ content, ...entry }) => entry) };
  const attestation = { sdkCleanupFailures: 0, mcp: { closed: true, quiescent: true, clean: true }, pids: [1], sourceReceiptsSha256: f.expectedStartup.sourceReceiptsSha256, networkBefore: { lo: Array(16).fill('0') }, networkAfter: { lo: Array(16).fill('0') } };
  return { result, artifacts, attestation };
}
function pure(f, payload, execution = payload.result.execution) { return validateBridgeArtifacts({ payload, execution, request: f.request, binding: f.binding, sources: f.sources, expectedStartup: f.expectedStartup, maxBytes: 1024 * 1024 }); }
function rewriteArtifact(payload, name, edit) {
  const item = payload.artifacts.find(a => a.path === name), value = JSON.parse(item.content); edit(value); item.content = JSON.stringify(value) + '\n'; item.bytes = Buffer.byteLength(item.content); item.sha256 = hash(item.content);
  Object.assign(payload.result.artifacts.find(a => a.path === name), { bytes: item.bytes, sha256: item.sha256 });
  if (name !== 'scan-manifest.json') rewriteArtifact(payload, 'scan-manifest.json', manifest => { const entry = manifest.scan.artifacts.find(a => a.path === name); if (entry) entry.sha256 = item.sha256; });
}
async function fixture(t) {
  const f = data(), base = path.join(root, randomUUID()), directory = path.join(base, 'attempt'), repo = path.join(base, 'source');
  await fs.mkdir(directory, { recursive: true }); await fs.mkdir(repo); await fs.writeFile(path.join(repo, 'source.ts'), content);
  Object.assign(f, { base, directory, repo, controller: new AbortController(), behavior: {}, rawHost: [], rawChild: [], calls: { opens: 0, submits: 0, transportCloses: 0, closes: 0, drafts: [], commands: [], verifies: [] } });
  const active = [];
  f.options = { directory, sourceRoot: repo, input: f.input, binding: f.binding, signal: f.controller.signal, timeoutMs: 10000, cleanupTimeoutMs: 500,
    limits: { maxRequests: 5, maxTotalOutputTokens: 20, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 262144, maxResponseBytesPerRequest: 131072, maxToolCalls: 6, maxToolResultBytes: 131072, timeoutMs: 5000 }, ipc: { maxFrameBytes: 1024 * 1024, maxBytes: 4 * 1024 * 1024, maxFrames: 32 },
    check: async bytes => certificate(bytes), verifyInputs: async ({ phase, inputHash }) => { f.calls.verifies.push(phase); return { inputHash }; },
    submit: async (bytes, context) => { f.calls.submits++; return response(context); }, closeTransport: async () => { f.calls.transportCloses++; return { closed: true, quiescent: true }; },
    async openWorker(control) {
      f.calls.opens++; const input = new PassThrough(), output = new PassThrough(), ending = deferred(); let phase = 'initial', closePromise;
      const originalWrite = input.write.bind(input); input.write = (bytes, ...args) => { f.rawChild.push(Buffer.from(bytes)); return originalWrite(bytes, ...args); };
      output.on('data', bytes => f.rawHost.push(Buffer.from(bytes)));
      async function sendFailure(failureStage) {
        phase = 'final_sent';
        let payload = { code: failureStage === 'mcp' ? 'worker_mcp_failed' : failureStage === 'sdk_initialization' ? 'worker_sdk_initialization_failed' : 'worker_sdk_finalization_failed', stage: failureStage, startup: structuredClone(f.expectedStartup), resources: { kernel: structuredClone(f.expectedStartup.resources), events: { cpuThrottledPeriods: 0, oom: 0, oomKill: 0 } }, diskFullStores: [], diskObservationComplete: true };
        await f.behavior.failure?.(payload);
        await peer.send('worker.failure', payload);
        if (f.behavior.extraFailure) await peer.send('worker.failure', payload);
        if (f.behavior.trailingFailure) input.write(Buffer.from(JSON.stringify({ version: 1, runId: 'foreign', sequence: 99, type: 'sdk.result', payload: {} }) + '\n'));
        if (f.behavior.hangFailure) return;
        await peer.end(); await peer.ended; ending.resolve({ code: f.behavior.failureExit ?? 1, signal: null });
      }
      const peer = createHostedChannel({ input: output, output: input, runId: control.runId, signal: control.signal, expiresAt: control.expiresAt, ...control.ipc, incomingTypes: ['mcp.start', 'mcp.listTools', 'mcp.recordDraft', 'mcp.close', 'execution.result'], outgoingTypes: ['execution.request', 'mcp.result', 'mcp.error', 'sdk.result', 'worker.failure'], onFailure() {}, onEnd() { assert.equal(phase, 'final_sent'); },
        onFrame(type, payload) {
          if (type === 'execution.result') {
            if (f.behavior.failureStage === 'sdk_finalization') { void sendFailure('sdk_finalization').catch(() => ending.resolve({ code: 1, signal: null })); return; }
            phase = 'final_sent'; let result = artifactPayload(f, payload.result); if (f.behavior.final) result = f.behavior.final(result) ?? result;
            void (async () => { await peer.send('sdk.result', result); if (f.behavior.extraAfterResult) input.write(Buffer.from('invalid trailing data\n')); await peer.end(); await peer.ended; ending.resolve({ code: f.behavior.exitCode ?? (result.result.status === 'completed' ? 0 : 1), signal: null }); })().catch(() => ending.resolve({ code: 1, signal: null })); return;
          }
          f.calls.commands.push(type); let result = null;
          if (f.behavior.eofCommand === type) { phase = 'final_sent'; input.end(); ending.resolve({ code: 137, signal: null }); return; }
          if (f.behavior.errorCommand === type) { input.destroy(Error('synthetic stream error')); ending.resolve({ code: 137, signal: null }); return; }
          if (f.behavior.failureStage === 'mcp' && (!f.behavior.failureCommand || f.behavior.failureCommand === type)) { void sendFailure('mcp').catch(() => ending.resolve({ code: 1, signal: null })); return; }
          if (f.behavior.hangCommand === type) { f.behavior.onCommand?.(); return; }
          if (type === 'mcp.listTools') result = { tools: [{ name: 'record_codex_security_scan_draft', inputSchema: structuredClone(schema) }] };
          if (type === 'mcp.recordDraft') { f.calls.drafts.push(structuredClone(payload.draft)); if (f.behavior.hangDraft) { f.behavior.onDraft?.(); return; } result = { content: [{ type: 'text', text: JSON.stringify({ scanId: payload.draft.scanId, status: 'draft_written', operation: 'replace', findingCount: payload.draft.findings.length, surfaceCount: payload.draft.coverage.surfaces.length, coverage: payload.draft.coverage }) }] }; if (f.behavior.draftResult) result = f.behavior.draftResult(payload.draft, result); }
          if (type === 'mcp.close') result = f.behavior.mcpClosure ?? { closed: true, quiescent: true, clean: true };
          if (f.behavior.mcpError === type) { void peer.send('mcp.error', { commandId: payload.commandId, code: 'worker_mcp_failed' }).catch(() => {}); return; }
          void peer.send('mcp.result', { commandId: payload.commandId + (f.behavior.wrongCommandId ? 1 : 0), result }).catch(() => {});
        },
      }); active.push(peer);
      if (f.behavior.onOpen) await f.behavior.onOpen();
      queueMicrotask(() => {
        if (f.behavior.hangStartup) return;
        if (f.behavior.failureStage === 'sdk_initialization') { void sendFailure('sdk_initialization').catch(() => ending.resolve({ code: 1, signal: null })); return; }
        if (f.behavior.earlyEof) { input.end(); ending.resolve({ code: 1, signal: null }); return; }
        const startup = structuredClone(f.expectedStartup), request = structuredClone(f.request); f.behavior.request?.(request); f.behavior.startup?.(startup);
        void peer.send('execution.request', { request, startup }).catch(() => {});
      });
      return { input, output, closed: ending.promise, expectedStartup: f.expectedStartup, close() { if (!closePromise) closePromise = (async () => { f.calls.closes++; if (phase !== 'final_sent') { peer.fail('peer_shutdown'); input.end(); output.end(); ending.resolve({ code: 1, signal: null }); } return f.behavior.cleanup ?? { closed: true, quiescent: phase === 'final_sent', containerAbsent: true }; })(); return closePromise; } };
    },
  };
  t.after(() => { for (const peer of active) peer.dispose(); }); f.run = () => runHostedBridge(f.options); return f;
}

test('one host attempt binds real journal, complete semantic conversation and durable artifacts', async t => {
  const f = await fixture(t), result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.artifactsAccepted, true); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.providerSubmitInvocations, 4); assert.deepEqual(f.calls.drafts.map(d => d.complete), [false, true]); assert.equal(f.calls.closes, 1); assert.deepEqual(f.calls.verifies, ['before', 'after']);
  assert.deepEqual(f.calls.commands, ['mcp.start', 'mcp.listTools', 'mcp.recordDraft', 'mcp.recordDraft', 'mcp.close']);
  const stored = JSON.parse(await fs.readFile(path.join(f.directory, 'attempt.result.json'))), ai = JSON.parse(await fs.readFile(path.join(f.directory, 'ai/session.result.json')));
  assert.equal(stored.status, 'completed'); assert.equal(stored.execution.finalResponse, undefined); assert.equal(ai.submitInvocations, 4); assert.equal(ai.usage.totalTokens, 20);
  for (const artifact of result.artifacts) assert.equal(hash(await fs.readFile(path.join(f.directory, 'artifacts', artifact.path))), artifact.sha256);
});
test('any existing attempt directory is not resumed or overwritten', async t => {
  const f = await fixture(t); await f.run(); const before = await fs.readFile(path.join(f.directory, 'attempt.result.json')), result = await f.run(); assert.equal(result.reason, 'ownership_unavailable'); assert.equal(f.calls.opens, 1); assert.equal(f.calls.submits, 4); assert.deepEqual(await fs.readFile(path.join(f.directory, 'attempt.result.json')), before);
  const g = await fixture(t); await fs.writeFile(path.join(g.directory, 'attempt.result.json'), 'user-owned'); assert.equal((await g.run()).reason, 'ownership_unavailable'); assert.equal(g.calls.opens, 0); assert.equal(await fs.readFile(path.join(g.directory, 'attempt.result.json'), 'utf8'), 'user-owned');
});
test('preabort never creates a worker or provider submission', async t => { const f = await fixture(t); f.controller.abort(); const result = await f.run(); assert.equal(result.status, 'canceled'); assert.equal(f.calls.opens, 0); assert.equal(f.calls.submits, 0); });
test('secret checker failure precedes Linux exposure', async t => { const f = await fixture(t); f.options.check = async () => { throw Error('private raw secret'); }; const result = await f.run(); assert.equal(result.status, 'failed'); assert.equal(f.calls.opens, 0); assert.equal(f.calls.submits, 0); assert.equal(JSON.stringify(result).includes('private raw secret'), false); });
test('wrong input certificate stops before worker', async t => { const f = await fixture(t); f.options.verifyInputs = async () => ({ inputHash: 'wrong' }); const result = await f.run(); assert.equal(result.reason, 'bridge_inputs_changed'); assert.equal(f.calls.opens, 0); });
for (const [name, edit] of [['zero IPC budget', o => { o.ipc.maxBytes = 0; }], ['inconsistent frame budget', o => { o.ipc.maxFrameBytes = o.ipc.maxBytes + 1; }], ['unknown IPC option', o => { o.ipc.extra = 1; }], ['zero AI request budget', o => { o.limits.maxRequests = 0; }]]) test(`invalid host limits reject ${name} before lock and worker`, async t => { const f = await fixture(t); edit(f.options); await assert.rejects(f.run(), /bridge_(ipc|ai)_limits/); assert.equal(f.calls.opens, 0); assert.equal(f.calls.submits, 0); assert.equal(await fs.stat(path.join(f.directory, 'attempt.lock')).catch(() => null), null); });
// The deadline passes only once the hung command arrives, so a slow host cannot spend it in setup.
function hangUntilDeadline(t, f, command, ms) {
  let clock = 0;
  t.mock.method(performance, 'now', () => clock);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  f.behavior.hangCommand = command; f.behavior.onCommand = () => { clock += ms; t.mock.timers.tick(ms); };
}
test('the tighter executor budget stops a blocked MCP start within the overall attempt', async t => { const f = await fixture(t); f.options.limits.timeoutMs = 50; hangUntilDeadline(t, f, 'mcp.start', 50); const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 0); assert.deepEqual(f.calls.commands, ['mcp.start']); assert.equal(result.cleanup.containerAbsent, true); });
test('deadline owner captures worker returned after synchronous starvation', async t => {
  const f = await fixture(t), original = f.options.openWorker; f.options.timeoutMs = 500;
  f.options.openWorker = async control => { const owner = await original(control), until = performance.now() + 600; while (performance.now() < until) {} return owner; };
  const result = await f.run(); assert.equal(f.calls.opens, 1); assert.equal(f.calls.submits, 0); assert.equal(f.calls.closes, 1); assert.equal(result.cleanup.containerAbsent, true); assert.equal(result.artifactsAccepted, false);
});
test('deadline owner closes a later asynchronous return without promoting unknown cleanup', async t => {
  const f = await fixture(t), original = f.options.openWorker, started = deferred(), release = deferred();
  f.options.openWorker = async control => { const owner = await original(control); started.resolve(); await release.promise; return owner; };
  const running = f.run(); await started.promise; f.controller.abort(); const result = await running; assert.equal(result.cleanup.containerAbsent, false); release.resolve(); await new Promise(resolve => setImmediate(resolve)); assert.equal(f.calls.closes, 1); assert.equal(f.calls.submits, 0); assert.equal(result.artifactsAccepted, false);
});
test('deadline owner never infers absent resources from a constructor exception', async t => {
  const f = await fixture(t); f.options.openWorker = () => { f.calls.opens++; throw Error('constructor_failed'); };
  const result = await f.run(); assert.equal(result.cleanup.containerAbsent, false); assert.equal(result.status, 'acceptance_unknown'); assert.equal(f.calls.opens, 1); assert.equal(f.calls.submits, 0);
});
test('startup identity mismatch stops before MCP or provider', async t => { const f = await fixture(t); f.behavior.startup = startup => { startup.uid = 0; }; const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 0); assert.equal(f.calls.commands.length, 0); });
for (const [name, edit] of [['repository', r => { r.repository = '/other'; }], ['revision', r => { r.revision = 'e'.repeat(40); }], ['scope', r => { r.scope = { paths: ['other.ts'] }; }], ['model', r => { r.model = 'foreign'; }], ['identity', r => { r.identity.runId = 'foreign'; }], ['runtime', r => { r.runtime.pluginRoot = '/assets/foreign'; }]]) test(`child cannot alter ${name}`, async t => { const f = await fixture(t); f.behavior.request = edit; const result = await f.run(); assert.notEqual(result.status, 'completed'); assert.equal(f.calls.submits, 0); assert.equal(f.calls.drafts.length, 0); });
test('early EOF never becomes an empty successful scan', async t => { const f = await fixture(t); f.behavior.earlyEof = true; const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 0); });
test('MCP reply identity mismatch cannot dispatch a provider call', async t => { const f = await fixture(t); f.behavior.wrongCommandId = true; const result = await f.run(); assert.notEqual(result.status, 'completed'); assert.equal(f.calls.submits, 0); });
test('MCP error preserves already observed host usage and blocks artifacts', async t => { const f = await fixture(t); f.behavior.mcpError = 'mcp.recordDraft'; const result = await f.run(); assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage.observed.totalTokens, 10); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 2); });
test('standard response completes semantic drafts and accepts artifacts', async t => {
  const f = await fixture(t), submit = f.options.submit;
  f.options.submit = async (bytes, context) => ({ ...await submit(bytes, context), effectiveProgram: 'standard' });
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.usage.complete, true); assert.equal(result.providerSubmitInvocations, 4);
  assert.deepEqual(f.calls.drafts.map(d => d.complete), [false, true]); assert.equal(result.artifactsAccepted, true);
  for (const artifact of result.artifacts) assert.equal(hash(await fs.readFile(path.join(f.directory, 'artifacts', artifact.path))), artifact.sha256);
});
for (const program of ['unknown', 'daybreak_red']) test(`${program} response records usage but dispatches zero semantic drafts`, async t => {
  const f = await fixture(t), submit = f.options.submit;
  f.options.submit = async (bytes, context) => ({ ...await submit(bytes, context), effectiveProgram: program });
  const result = await f.run(); assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage.observed.totalTokens, 5); assert.equal(result.usage.complete, true); assert.equal(result.providerSubmitInvocations, 1); assert.equal(f.calls.drafts.length, 0); assert.equal(result.artifactsAccepted, false);
});
test('abnormal provider close preserves observed usage without tool execution', async t => { const f = await fixture(t); f.options.closeTransport = async () => ({ closed: true, quiescent: false }); const result = await f.run(); assert.equal(result.usage.observed.totalTokens, 5); assert.equal(result.usage.complete, true); assert.equal(f.calls.drafts.length, 0); assert.equal(result.artifactsAccepted, false); });
test('corrupt provider stream leaves usage unknown rather than zero', async t => { const f = await fixture(t); f.options.submit = async () => { f.calls.submits++; throw Error('transport_stream'); }; const result = await f.run(); assert.equal(result.usage.observed, null); assert.equal(result.usage.complete, false); assert.equal(f.calls.drafts.length, 0); assert.equal(result.providerSubmitInvocations, 1); });
test('abort while provider is pending settles and never resends', async t => { const f = await fixture(t), started = deferred(); f.options.submit = async () => { f.calls.submits++; started.resolve(); return new Promise(() => {}); }; const running = f.run(); await started.promise; f.controller.abort(); const result = await running; assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage.observed, null); assert.equal(result.providerSubmitInvocations, 1); assert.equal(f.calls.drafts.length, 0); });
test('abort during draft preserves prior usage and makes draft acceptance unknown', async t => { const f = await fixture(t), started = deferred(); f.behavior.hangDraft = true; f.behavior.onDraft = () => started.resolve(); const running = f.run(); await started.promise; f.controller.abort(); const result = await running; assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage.observed.totalTokens, 10); assert.equal(f.calls.drafts.length, 1); assert.equal(f.calls.submits, 2); assert.equal(result.artifactsAccepted, false); });
test('terminal payload cannot replace host usage', async t => { const f = await fixture(t); f.behavior.final = payload => { payload.result.execution.usage.observed.totalTokens = 0; }; const result = await f.run(); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.artifactsAccepted, false); });
test('SDK asynchronous cleanup failure blocks otherwise completed result', async t => { const f = await fixture(t); f.behavior.final = payload => { payload.attestation.sdkCleanupFailures = 1; }; const result = await f.run(); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.artifactsAccepted, false); });
test('trailing malformed frame after SDK result prevents persistence acceptance', async t => { const f = await fixture(t); f.behavior.extraAfterResult = true; const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(result.artifacts.length, 0); });
test('attach exit and owned-container absence are both required', async t => { const f = await fixture(t); f.behavior.exitCode = 1; assert.equal((await f.run()).artifactsAccepted, false); const g = await fixture(t); g.behavior.cleanup = { closed: true, quiescent: true, containerAbsent: false }; assert.equal((await g.run()).artifactsAccepted, false); });
test('input change during execution invalidates sealed artifacts and keeps usage', async t => { const f = await fixture(t); f.options.verifyInputs = async ({ phase, inputHash }) => phase === 'after' ? { inputHash: 'changed' } : { inputHash }; const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(result.inputsUnchanged, false); assert.equal(result.usage.observed.totalTokens, 20); });
test('artifact write is exclusive and preserves an occupied output', async t => { const f = await fixture(t); f.behavior.onOpen = () => fs.writeFile(path.join(f.directory, 'artifacts/report.md'), 'held output', { flag: 'wx' }); const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(await fs.readFile(path.join(f.directory, 'artifacts/report.md'), 'utf8'), 'held output'); });
test('a host credential canary never enters worker frames or saved journals/artifacts', async t => {
  const f = await fixture(t), canary = 'synthetic-bearer-' + randomUUID(), original = f.options.submit; f.options.submit = (bytes, context) => { assert.ok(canary.length); return original(bytes, context); };
  assert.equal((await f.run()).status, 'completed'); assert.equal(Buffer.concat([...f.rawHost, ...f.rawChild]).includes(Buffer.from(canary)), false);
  async function visit(directory) { for (const name of await fs.readdir(directory, { withFileTypes: true })) { const full = path.join(directory, name.name); if (name.isDirectory()) await visit(full); else assert.equal((await fs.readFile(full)).includes(Buffer.from(canary)), false); } } await visit(f.directory);
});

const invalidArtifacts = [
  ['stray undeclared artifact', p => p.artifacts.push({ ...p.artifacts[0], path: 'extra.json' })],
  ['path escape', p => { p.artifacts[0].path = '../outside.json'; p.result.artifacts[0].path = '../outside.json'; }],
  ['Windows drive', p => { p.artifacts[0].path = 'C:/outside.json'; p.result.artifacts[0].path = 'C:/outside.json'; }],
  ['Windows device', p => { p.artifacts[0].path = 'con.json'; p.result.artifacts[0].path = 'con.json'; }],
  ['case alias', p => { p.artifacts[1].path = p.artifacts[0].path.toUpperCase(); p.result.artifacts[1].path = p.artifacts[1].path; }],
  ['wrong bytes', p => { p.artifacts[0].bytes++; p.result.artifacts[0].bytes++; }],
  ['wrong hash', p => { p.artifacts[0].sha256 = '0'.repeat(64); p.result.artifacts[0].sha256 = '0'.repeat(64); }],
  ['wrong scan', p => { p.result.scanId = 'foreign'; }], ['wrong revision', p => { p.result.revision = 'e'.repeat(40); }],
  ['wrong scope', p => { p.result.scope = { paths: ['foreign'] }; }], ['wrong version', p => { p.result.version = 1; }],
  ['wrong plugin', p => { p.result.provenance.pluginVersion = '0.5.1'; }], ['invented model field', p => { p.result.model = 'gpt-6-sol'; }],
  ['unknown cleanup', p => { p.attestation.mcp.quiescent = false; }], ['SDK cleanup failure', p => { p.attestation.sdkCleanupFailures = 1; }],
  ['extra process', p => { p.attestation.pids.push(2); }], ['changed source', p => { p.attestation.sourceReceiptsSha256 = '0'.repeat(64); }],
  ['network change', p => { p.attestation.networkAfter.lo[0] = '1'; }],
  ['unsealed manifest', p => rewriteArtifact(p, 'scan-manifest.json', m => { delete m.scan.sealedAt; })],
  ['wrong sealed scan', p => rewriteArtifact(p, 'scan-manifest.json', m => { m.scan.id = 'foreign'; })],
  ['wrong sealed revision', p => rewriteArtifact(p, 'scan-manifest.json', m => { m.scan.target.revision = 'e'.repeat(40); })],
  ['wrong sealed hash', p => rewriteArtifact(p, 'scan-manifest.json', m => { m.scan.artifacts[0].sha256 = '0'.repeat(64); })],
  ['wrong finding identity', p => rewriteArtifact(p, 'findings.json', m => { m.scanId = 'foreign'; })],
  ['finding outside source', p => rewriteArtifact(p, 'findings.json', m => { m.findings = [{ locations: [{ path: '../outside.ts', startLine: 1 }] }]; })],
  ['finding outside lines', p => rewriteArtifact(p, 'findings.json', m => { m.findings = [{ locations: [{ path: 'source.ts', startLine: 2 }] }]; })],
  ['wrong coverage identity', p => rewriteArtifact(p, 'coverage.json', m => { m.scanId = 'foreign'; })],
];
for (const [name, edit] of invalidArtifacts) test(`artifact acceptance rejects ${name}`, () => { const f = data(), payload = artifactPayload(f); edit(payload); assert.throws(() => pure(f, payload)); });
test('artifact positive runs only after negative families and respects aggregate bound', () => { const f = data(), payload = artifactPayload(f); assert.equal(pure(f, payload).length, 4); assert.throws(() => validateBridgeArtifacts({ payload, execution: payload.result.execution, request: f.request, binding: f.binding, sources: f.sources, expectedStartup: f.expectedStartup, maxBytes: 1 }), /bridge_artifact_bytes/); });

function boundary() {
  const mounts = ['/assets', '/etc/gitconfig', '/handoff', '/verify'].map((target, i) => ({ source: 'C:\\owned\\' + i, target })), id = 'a'.repeat(64), env = ['PATH=/usr/bin', 'HOME=/work/home', 'TMPDIR=/tmp'];
  const workerResources = { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 };
  const expected = { id, runId: 'run', mounts, env, workerResources }, info = { Id: id, Image: 'sha256:f9b3548b20b15b705b66aeecaeac7dd690c73d5e4661357aac02e60e3d38c88a', State: { Status: 'created', Running: false }, Config: { Labels: { 'scanmux.hosted-bridge': 'run' }, User: '1000:1000', Tty: false, OpenStdin: true, Entrypoint: ['/usr/local/bin/node'], Cmd: ['/verify/linux-hosted-worker.mjs'], WorkingDir: '/work', Env: env }, HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], CapAdd: [], SecurityOpt: ['no-new-privileges'], PidMode: '', IpcMode: 'private', CgroupnsMode: 'private', AutoRemove: false, PidsLimit: 64, LogConfig: { Type: 'none' }, PortBindings: {}, Devices: [], DeviceRequests: [], Binds: [], NanoCpus: 1000000000, Memory: 268435456, MemorySwap: 268435456, ShmSize: 4194304, Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=33554432,mode=1777', '/work': 'rw,noexec,nosuid,nodev,size=16777216,uid=1000,gid=1000,mode=0700' }, Mounts: mounts.map(m => ({ Type: 'bind', Source: m.source, Target: m.target, ReadOnly: true })) }, Mounts: mounts.map(m => ({ Type: 'bind', Destination: m.target, RW: false })) }; return { info, expected };
}
for (const [name, edit] of [
  ['network', i => { i.HostConfig.NetworkMode = 'default'; }], ['root user', i => { i.Config.User = '0'; }], ['writable root', i => { i.HostConfig.ReadonlyRootfs = false; }],
  ['capability', i => { i.HostConfig.CapAdd = ['NET_ADMIN']; }], ['host namespace', i => { i.HostConfig.PidMode = 'host'; }], ['TTY', i => { i.Config.Tty = true; }],
  ['credentials env', i => { i.Config.Env = [...i.Config.Env, 'TOKEN=synthetic']; }], ['writable source', i => { i.Mounts[2].RW = true; }],
  ['extra mount', i => { i.HostConfig.Mounts.push({ Type: 'bind', Source: 'C:\\secret', Target: '/extra', ReadOnly: true }); }], ['early start', i => { i.State.Running = true; }],
  ['foreign identity', i => { i.Config.Labels['scanmux.hosted-bridge'] = 'foreign'; }], ['different command', i => { i.Config.Cmd = ['/bin/sh']; }],
  ['unbounded CPU', i => { i.HostConfig.NanoCpus = 0; }], ['larger CPU', i => { i.HostConfig.NanoCpus *= 2; }], ['unbounded memory', i => { i.HostConfig.Memory = 0; }],
  ['swap allowed', i => { i.HostConfig.MemorySwap *= 2; }], ['larger shm', i => { i.HostConfig.ShmSize *= 2; }], ['automatic removal hides terminal', i => { i.HostConfig.AutoRemove = true; }],
  ['unbounded tmp', i => { i.HostConfig.Tmpfs['/tmp'] = 'rw,noexec,nosuid,nodev,mode=1777'; }], ['different work quota', i => { i.HostConfig.Tmpfs['/work'] = i.HostConfig.Tmpfs['/work'].replace('16777216', '33554432'); }],
]) test(`prestart runner boundary rejects ${name}`, () => { const { info, expected } = boundary(); edit(info); assert.throws(() => validateLinuxHostedBoundary(info, expected)); });
test('prestart boundary accepts only the exact fixed created instance', () => { const { info, expected } = boundary(); assert.doesNotThrow(() => validateLinuxHostedBoundary(info, expected)); });

async function resourceFixture(t) {
  const f = await fixture(t), workerResources = { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 };
  f.input.config.ai = { workerResources }; f.input.plan.ai = { schema: 'scanmux.ai-plan/v2', workerResources };
  f.input.plan.policyHash = digest(f.input.config); f.input.plan.planHash = digest({ ...f.input.plan, planHash: '' }); f.input.projection.mapping.planHash = f.input.plan.planHash;
  f.binding.scope.paths = ['.'];
  f.options.validateArtifacts = (copies, metadata) => {
    const artifacts = validateAiArtifactDocuments(copies, metadata, f.input.plan, f.options.ipc.maxBytes);
    normalizeProjectedCodex({ manifest: artifacts.manifest, findings: artifacts.findings }, f.input.projection.mapping, { plan: f.input.plan, snapshot: f.repo });
  };
  f.options.workerResources = workerResources; f.expectedStartup.resources = expectedResourceKernel(workerResources);
  f.behavior.final = payload => { payload.attestation.resources = { kernel: structuredClone(f.expectedStartup.resources), events: { cpuThrottledPeriods: 0, oom: 0, oomKill: 0 } }; f.behavior.resourceFinal?.(payload); return payload; };
  const open = f.options.openWorker;
  f.options.openWorker = async control => { const owner = await open(control); owner.diagnostics = () => ({ boundaryVerifiedBeforeStart: true, terminal: f.behavior.terminal === undefined ? { exitCode: 0, oomKilled: false } : f.behavior.terminal }); return owner; };
  return f;
}

function transportPackets(sequence, status = 'completed', details = {}) {
  const receipt = response({ sequence, identity: { requestId: 'request' } });
  const terminal = { id: receipt.responseId, model: receipt.model, status, access_programs: null,
    usage: status === 'completed' ? { input_tokens: 3, output_tokens: 2, total_tokens: 5 } : null,
    output: status === 'completed' ? receipt.output : [], ...details };
  return [{ type: 'response.created', response: { id: terminal.id, model: terminal.model, status: 'in_progress', output: [] } },
    { type: `response.${status}`, response: terminal }].map((event, sequence_number) => Buffer.from(JSON.stringify({ sequence_number, ...event })));
}

class HostedSocket extends EventEmitter {
  send(bytes, options, callback) { callback(); }
  close() { queueMicrotask(() => this.emit('close', 1000)); }
  terminate() { queueMicrotask(() => this.emit('close', 1006)); }
}

async function savedHostedTransport(t, { stream, cap = 131072, credentialsFail = false, complete = false, setup, toolError, toolCheckFailure = false, outcomeChange, outcomeOmit = 'toolFailureCode', outcomeValid = false } = {}) {
  const f = await resourceFixture(t); setup?.(f); const workspace = path.join(f.base, 'workspace'); await fs.mkdir(workspace);
  const config = { ...structuredClone(defaults), ai: { assetsRoot: path.join(f.base, 'assets'), credentialStore: path.join(f.base, 'credentials'),
    reasoningEffort: 'high', commandTimeoutMs: 10000, cleanupTimeoutMs: 500, workerResources: f.options.workerResources,
    limits: { ...f.options.limits, maxResponseBytesPerRequest: cap }, ipc: f.options.ipc } };
  const plan = f.input.plan; plan.root = f.repo; plan.ai.source = { manifestSha256: digest(plan.files) };
  plan.policyHash = digest(config); plan.planHash = digest({ ...plan, planHash: '' }); f.input.projection.mapping.planHash = plan.planHash;
  const projection = { ...f.input.projection, repository: f.repo, mappingFile: path.join(f.base, 'mapping.json') };
  await fs.writeFile(projection.mappingFile, JSON.stringify(projection.mapping));
  const assets = Array.from({ length: 10805 }, (_, index) => ({ path: `asset-${index}`, bytes: 0, sha256: 'a'.repeat(64) }));
  const adapterUrl = new URL(`../src/ai-runner.mjs?hosted-transport-${randomUUID()}`, import.meta.url).href;
  const bridgeUrl = new URL(`../internal/hosted-bridge.mjs?hosted-outcome-${randomUUID()}`, import.meta.url).href;
  const stub = (file, source) => `export * from ${JSON.stringify(new URL(file, import.meta.url).href)}; ${source}`;
  const modules = new Map([
    ['./ai-plan.ts', stub('../src/ai-plan.ts', `export const verifyAiPlan = () => {}; export const buildAiPlan = () => (${JSON.stringify(plan)}); export const aiRuntime = ${JSON.stringify({ ...aiRuntime, assetManifestSha256: digest(assets) })};`)],
    ['./ai-files.mjs', stub('../src/ai-files.mjs', `export const canonicalAiPath = async value => value; export const inventoryAiDirectory = async (directory, control, options) => options.order === 'sdk-assets' ? ${JSON.stringify(assets)} : [];`)],
    ['./repository.ts', stub('../src/repository.ts', `export const verifySnapshot = async () => true; export const buildPlan = async () => (${JSON.stringify(plan)});`)],
    ['./output.ts', stub('../src/output.ts', 'export const checkedText = async value => value;')],
    ['./siwc-credentials.mjs', `import { SafeError } from ${JSON.stringify(new URL('../src/safety.ts', import.meta.url).href)};
      export const readSiwcCredentials = async () => { ${credentialsFail ? "throw new SafeError('ai_credentials_permissions');" : "return { accessToken: 'private-credential-canary', expiresAt: Date.now() + 60000 };"} };`],
    ['../internal/projected-repository.mjs', stub('../internal/projected-repository.mjs', `export const projectRepository = async () => (${JSON.stringify(projection)});`)],
  ]);
  const executorStub = `import { createHostedExecutor as create } from ${JSON.stringify(new URL('../internal/hosted-executor.mjs', import.meta.url).href)};
    export const createHostedExecutor = options => {
      const toolError = ${JSON.stringify(toolError ?? null)}, change = JSON.parse(${JSON.stringify(JSON.stringify(outcomeChange ?? null))});
      const implementation = create({ ...options,
        check: async (bytes, signal) => ${toolCheckFailure} && bytes.toString().startsWith('{"complete":') ? null : options.check(bytes, signal),
        createMcp(...args) { const mcp = options.createMcp(...args); return toolError ? { ...mcp, async recordDraft() { throw Object.assign(Error(toolError.message), toolError); } } : mcp; },
      });
      return change ? { ...implementation, outcome() { const value = implementation.outcome(); if (value) { delete value[${JSON.stringify(outcomeOmit)}]; Object.assign(value, change); } return value; } } : implementation;
    };`;
  if (toolError || toolCheckFailure || outcomeChange) modules.set('../internal/hosted-bridge.mjs', `export * from ${JSON.stringify(bridgeUrl)};`);
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (context.parentURL === adapterUrl && modules.has(specifier)) return { url: 'data:text/javascript,' + encodeURIComponent(modules.get(specifier)), shortCircuit: true };
    if (context.parentURL === bridgeUrl && specifier === './hosted-executor.mjs') return { url: 'data:text/javascript,' + encodeURIComponent(executorStub), shortCircuit: true };
    return nextResolve(specifier, context);
  } });
  let createAdapter;
  try { ({ createAiAdapter: createAdapter } = await import(adapterUrl)); } finally { hooks.deregister(); }
  if (!complete) f.behavior.failureStage = 'sdk_finalization';
  const streams = []; let connections = 0;
  const runtime = {
    async openWorker(control) {
      f.binding.identity = control.identity; f.request.identity = control.identity;
      const owner = await f.options.openWorker(control), diagnostics = owner.diagnostics;
      owner.diagnostics = () => ({ ...diagnostics(), imageId: aiRuntime.imageDigest }); return owner;
    },
    createSocket() {
      const socket = new HostedSocket(), received = stream ? stream(++connections) : transportPackets(++connections); streams.push(received);
      queueMicrotask(() => { socket.emit('upgrade', { statusCode: 101 }); socket.emit('open');
        for (const bytes of received) socket.emit('message', bytes, false);
        if (received.length === 1) socket.emit('close', 1000);
      }); return socket;
    },
  };
  const run = await createAdapter({ acceptedPlanHash: plan.planHash, expiresAt: performance.now() + 10000, runtime }).run({ plan, config, workspace, snapshot: '',
    signal: new AbortController().signal, secretScan: { execution: 'completed', coverage: 'analyzed', findings: [], errors: [] } });
  const destination = path.join(workspace, 'saved-ai.json'); await fs.writeFile(destination, JSON.stringify(run));
  const saved = JSON.parse(await fs.readFile(destination, 'utf8')), directory = path.join(workspace, 'ai-attempt');
  assert.ok(saved.aiExecution.submitInvocations > 0, saved.aiExecution.reason);
  const session = JSON.parse(await fs.readFile(path.join(directory, 'ai', 'session.result.json')));
  const terminals = await Promise.all(Array.from({ length: session.submitInvocations }, (_, index) => fs.readFile(path.join(directory, 'ai', `${index + 1}.terminal.json`), 'utf8').then(JSON.parse)));
  for (const canary of ['private-credential-canary', 'private-provider-canary', 'Synthetic SDK prompt.', 'Synthetic only.']) assert.ok(!JSON.stringify(saved).includes(canary));
  assert.equal(saved.aiExecution.submitInvocations, session.submitInvocations); assert.equal(saved.aiExecution.artifactsAccepted, complete && (!outcomeChange || outcomeValid));
  if (outcomeChange && !outcomeValid || !complete) { assert.equal(saved.aiExecution.reason, outcomeChange ? 'bridge_sdk_outcome' : 'worker_sdk_finalization_failed'); assert.equal(saved.aiExecution.status, 'acceptance_unknown'); }
  return { saved, streams, session, terminals, attempt: await fs.readFile(path.join(directory, 'attempt.result.json'), 'utf8') };
}

const failedPackets = code => transportPackets(1, 'failed', { error: { code, message: 'private-provider-canary' } });
const incompletePackets = reason => transportPackets(1, 'incomplete', { incomplete_details: { reason, detail: 'private-provider-canary' } });
const cappedPackets = failedPackets('server_error'), responseCap = Math.max(...cappedPackets.map(bytes => bytes.length));
const createdFirstEvent = { kind: 'object', type: 'response.created', keys: ['response', 'sequence_number', 'type'], otherKeys: 0,
  sequenceNumber: 'integer', sequence: 'absent', streamId: 'absent' };
for (const [name, packets, cap, terminalKind, closeCode, failureCode, provider, rejectedEvent = null, rejectedAt = null] of [
  ['normal close without completion', transportPackets(1).slice(0, 1), 131072, 'none', 1000, 'early_eof', {}],
  ['failed response code', failedPackets('server_error'), 131072, 'failed', 1000, null, { providerErrorCode: 'server_error' }],
  ['incomplete response reason', incompletePackets('max_output_tokens'), 131072, 'incomplete', 1000, null, { incompleteReason: 'max_output_tokens' }],
  ['cumulative byte cap', cappedPackets, responseCap, 'none', 1006, 'response_limit', {}, { ...createdFirstEvent, type: 'response.failed', valueShapes: {
    response: { type: 'object', size: 7, output: { type: 'array', size: 0 }, statusType: 'string' }, sequence_number: { type: 'number', size: null }, type: { type: 'string', size: 15 },
  } }, 2],
  ['unknown provider error code', failedPackets('private-provider-canary'), 131072, 'failed', 1000, null, { providerErrorCode: 'other' }],
  ['unknown incomplete reason', incompletePackets('private-provider-canary'), 131072, 'incomplete', 1000, null, {}],
]) test(`hosted transport diagnostics: ${name}`, async t => {
  const { saved, session, terminals } = await savedHostedTransport(t, { stream: () => packets, cap });
  assert.deepEqual(saved.aiExecution.transportRequests, [{ sequence: 1, receivedBytes: packets.reduce((sum, bytes) => sum + bytes.length, 0),
    receivedMessages: packets.length, terminal: terminalKind !== 'none', terminalKind, closeCode, sendOk: true, failureCode, firstEvent: createdFirstEvent, rejectedEvent, rejectedAt, ...provider }]);
  assert.equal(saved.aiExecution.connectionAttempts, 1); assert.equal(saved.aiExecution.sendInvocations, 1);
  assert.equal(session.completedResponses, 0); assert.equal(session.toolInvocations, 0); assert.deepEqual(session.observedUsage, []);
  assert.deepEqual(session.responseTools, []); assert.deepEqual(saved.aiExecution.sdkOutcome.responses, []);
  assert.equal(terminals[0].reason, terminalKind === 'failed' ? 'provider_failed' : terminalKind === 'incomplete' ? 'invalid_response_status' : 'close_unverified');
});

test('hosted first WebSocket message shape survives into the saved report on rejection', async t => {
  const packets = [Buffer.from(JSON.stringify({ type: 'codex.rate_limits', rate_limits: { detail: 'private-provider-canary', remaining: 8675309 } }))];
  const { saved, session } = await savedHostedTransport(t, { stream: () => packets });
  const row = saved.aiExecution.transportRequests[0]; assert.equal(row.failureCode, 'sequence_mismatch'); assert.equal(row.terminalKind, 'none');
  assert.deepEqual(row.firstEvent, { kind: 'object', type: 'codex.rate_limits', keys: ['rate_limits', 'type'], otherKeys: 0,
    sequenceNumber: 'absent', sequence: 'absent', streamId: 'absent' });
  assert.equal(row.rejectedAt, 1); assert.deepEqual(row.rejectedEvent, { ...row.firstEvent, valueShapes: {
    rate_limits: { type: 'object', size: 2 }, type: { type: 'string', size: 17 },
  } });
  assert.equal(session.completedResponses, 0); assert.equal(session.toolInvocations, 0); assert.deepEqual(session.observedUsage, []);
  assert.ok(!JSON.stringify(saved).includes('8675309'));
});

test('hosted rejected WebSocket event shape and index survive into the saved report', async t => {
  const packets = [transportPackets(1)[0], Buffer.from(JSON.stringify({ type: 'response.something_new', sequence_number: 1, text: 'private-provider-canary' }))];
  const { saved, session } = await savedHostedTransport(t, { stream: () => packets });
  const row = saved.aiExecution.transportRequests[0]; assert.equal(row.failureCode, 'unexpected_event'); assert.equal(row.rejectedAt, 2);
  assert.deepEqual(row.firstEvent, createdFirstEvent);
  assert.deepEqual(row.rejectedEvent, { ...createdFirstEvent, type: 'response.something_new', keys: ['sequence_number', 'text', 'type'], valueShapes: {
    sequence_number: { type: 'number', size: null }, text: { type: 'string', size: 23 }, type: { type: 'string', size: 22 },
  } });
  assert.equal(session.completedResponses, 0); assert.equal(session.toolInvocations, 0); assert.deepEqual(session.observedUsage, []);
});

test('hosted transport diagnostics: credential failure before transport creation', async t => {
  const { saved, session, terminals } = await savedHostedTransport(t, { credentialsFail: true });
  assert.equal(saved.aiExecution.connectionAttempts, 0); assert.equal(saved.aiExecution.sendInvocations, 0); assert.equal(session.submitInvocations, 1);
  assert.equal(terminals[0].closed, true); assert.equal(terminals[0].reason, 'acceptance_unknown');
  assert.deepEqual(saved.aiExecution.transportRequests, [{ sequence: 1, receivedBytes: 0, receivedMessages: 0, terminal: false, terminalKind: 'none',
    closeCode: null, sendOk: false, failureCode: 'ai_credentials_permissions', firstEvent: null, rejectedEvent: null, rejectedAt: null }]);
});

test('hosted transport diagnostics: standard responses preserve every request and acceptance', async t => {
  const { saved, session, streams } = await savedHostedTransport(t, { complete: true });
  assert.equal(saved.execution, 'completed'); assert.equal(saved.aiExecution.status, 'completed'); assert.deepEqual(saved.aiExecution.programs, ['standard']);
  assert.equal(session.completedResponses, 4); assert.equal(saved.aiExecution.tokens.kind, 'complete');
  assert.deepEqual(saved.aiExecution.transportRequests, streams.map((packets, index) => ({ sequence: index + 1, receivedBytes: packets.reduce((sum, bytes) => sum + bytes.length, 0),
    receivedMessages: packets.length, terminal: true, terminalKind: 'completed', closeCode: 1000, sendOk: true, failureCode: null, firstEvent: createdFirstEvent, rejectedEvent: null, rejectedAt: null })));
});

test('bounded worker startup, attestation and host terminal all bind before artifact acceptance', async t => {
  const f = await resourceFixture(t); f.behavior.resourceFinal = payload => { payload.attestation.resources.events.cpuThrottledPeriods = 9; };
  const result = await f.run(); assert.equal(result.artifactsAccepted, true); assert.equal(result.workerResources.state, 'verified');
  assert.equal(result.workerResources.events.cpuThrottledPeriods, 9); assert.deepEqual(result.workerResources.exceeded, []); assert.equal(f.calls.submits, 4);
});

test('resource caps in host options, accepted plan and configuration cannot differ', async t => {
  for (const target of ['plan', 'config', 'options']) {
    const f = await resourceFixture(t);
    if (target === 'options') f.options.workerResources = { ...f.options.workerResources, cpuCount: 2 };
    else {
      const selected = target === 'plan' ? f.input.plan.ai : f.input.config.ai; selected.workerResources = { ...selected.workerResources, cpuCount: 2 };
      f.input.plan.policyHash = digest(f.input.config); f.input.plan.planHash = digest({ ...f.input.plan, planHash: '' }); f.input.projection.mapping.planHash = f.input.plan.planHash;
    }
    await assert.rejects(f.run(), /bridge_worker_resource_binding/); assert.equal(f.calls.opens, 0); assert.equal(f.calls.submits, 0);
  }
});

test('missing terminal, omitted resources and OOM observation cannot yield accepted artifacts', async t => {
  for (const kind of ['terminal', 'attestation', 'oom']) {
    const f = await resourceFixture(t);
    if (kind === 'terminal') f.behavior.terminal = null;
    else f.behavior.resourceFinal = payload => { if (kind === 'attestation') delete payload.attestation.resources; else payload.attestation.resources.events.oom = 1; };
    const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.deepEqual(result.artifacts, []);
    if (kind === 'oom') { assert.equal(result.reason, 'resource_memory_exceeded'); assert.deepEqual(result.workerResources.exceeded, ['memory']); }
    else assert.equal(result.workerResources.state, 'not_verified');
  }
});

test('a changed kernel startup stops before any provider submission', async t => {
  const f = await resourceFixture(t); f.behavior.startup = startup => { startup.resources.memoryMax *= 2; };
  const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 0); assert.equal(result.workerResources.state, 'not_verified');
});

test('cleanup notifications preserve the first resource, SDK and artifact failure as one causal family', async t => {
  for (const [expectedReason, change] of [
    ['resource_memory_exceeded', payload => { payload.attestation.resources.events.oom = 1; }],
    ['bridge_sdk_binding', payload => { payload.result.revision = '0'.repeat(40); }],
    ['bridge_artifact_bytes', payload => { payload.artifacts[0].content += 'changed'; }],
  ]) {
    const f = await resourceFixture(t); f.behavior.resourceFinal = change;
    const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.equal(result.reason, expectedReason); assert.deepEqual(result.artifacts, []); assert.equal(f.calls.closes, 1);
  }
});

for (const failureStage of ['sdk_initialization', 'mcp', 'sdk_finalization']) test(`legal ${failureStage} failure drains once and retains the explicit terminal cause`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = failureStage; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run();
  assert.equal(result.reason, failureStage === 'mcp' ? 'worker_mcp_failed' : failureStage === 'sdk_initialization' ? 'worker_sdk_initialization_failed' : 'worker_sdk_finalization_failed');
  assert.equal(result.artifactsAccepted, false); assert.equal(result.cleanup.quiescent, true); assert.deepEqual(result.independentFailures, []);
  assert.equal(result.mcpEvidence, failureStage === 'mcp' ? 'unverified' : failureStage === 'sdk_initialization' ? 'not_started' : 'closed'); assert.equal(result.artifactEvidence, 'none'); assert.equal(f.calls.submits, failureStage === 'sdk_finalization' ? 4 : 0);
});

for (const [name, edit] of [
  ['unknown code', p => { p.code = 'foreign'; }], ['unknown stage', p => { p.stage = 'foreign'; }], ['extra field', p => { p.extra = true; }],
  ['foreign startup', p => { p.startup.uid = 0; }], ['late phase', p => { p.stage = 'sdk_finalization'; p.code = 'worker_sdk_finalization_failed'; }],
  ['missing snapshot', p => { p.code = 'resource_disk_exceeded'; p.resources = null; p.diskFullStores = ['work']; }],
  ['changed snapshot', p => { p.resources.kernel.memoryMax *= 2; }], ['unobserved disk', p => { p.code = 'resource_disk_exceeded'; }],
  ['duplicate store', p => { p.code = 'resource_disk_exceeded'; p.diskFullStores = ['work', 'work']; }],
]) test(`terminal failure refuses ${name}`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior.failure = edit;
  const result = await f.run(); assert.equal(result.artifactsAccepted, false); assert.notEqual(result.reason, 'resource_disk_exceeded'); assert.equal(f.calls.submits, 0);
});

for (const behavior of ['extraFailure', 'trailingFailure', 'hangFailure', 'failureExit']) test(`a resource terminal cannot hide independent ${behavior}`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior[behavior] = behavior === 'failureExit' ? 0 : true;
  f.behavior.failure = p => { p.code = 'resource_disk_exceeded'; p.diskFullStores = ['work']; }; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run(); assert.equal(result.reason, 'resource_disk_exceeded'); assert.equal(result.artifactsAccepted, false);
  assert.ok(result.independentFailures.length > 0); assert.deepEqual(result.workerResources.exceeded, ['disk']); assert.equal(f.calls.submits, 0);
});

test('a generic SDK failure retains concurrent ENOSPC without converting its cause or weakening ERROR', async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior.failure = p => { p.diskFullStores = ['work']; };
  f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run(); assert.equal(result.reason, 'worker_sdk_initialization_failed'); assert.deepEqual(result.workerResources.exceeded, ['disk']); assert.equal(result.artifactsAccepted, false);
});

const nativeRegistrationReceipt = () => ({ schema: 'scanmux.sdk-initialization-observation/v2', state: 'observed', helperInvocations: 1, closedInvocations: 1, sqliteFullObserved: true, otherSqliteErrorObserved: false, terminal: 'sqlite_full' });
test('a bound native registration terminal supplies disk cause independently of a later full-store probe', async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  f.behavior.failure = p => { p.code = 'resource_disk_exceeded'; p.diskObservationComplete = false; p.sdkInitializationObservation = nativeRegistrationReceipt(); };
  const result = await f.run(); assert.equal(result.reason, 'resource_disk_exceeded'); assert.deepEqual(result.workerResources.exceeded, ['disk']);
  assert.deepEqual(result.sdkInitializationObservation, nativeRegistrationReceipt()); assert.deepEqual(result.independentFailures, []); assert.equal(f.calls.submits, 0);
  const saved = JSON.parse(await fs.readFile(path.join(f.directory, 'attempt.result.json'))); assert.deepEqual(saved.sdkInitializationObservation, result.sdkInitializationObservation);
});
for (const terminal of ['none', 'other', 'sqlite_full']) test(`a generic SDK error with native ${terminal} observation keeps its original cause`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  f.behavior.failure = p => { p.sdkInitializationObservation = { ...nativeRegistrationReceipt(), terminal, otherSqliteErrorObserved: terminal === 'other' }; };
  const result = await f.run(); assert.equal(result.reason, 'worker_sdk_initialization_failed'); assert.deepEqual(result.workerResources.exceeded, []); assert.equal(result.artifactsAccepted, false);
});
for (const [name, edit] of [
  ['unavailable', p => { p.sdkInitializationObservation = { ...nativeRegistrationReceipt(), state: 'unavailable', terminal: 'none', sqliteFullObserved: false }; }],
  ['mixed SQLite errors', p => { p.sdkInitializationObservation.otherSqliteErrorObserved = true; p.sdkInitializationObservation.terminal = 'other'; }],
  ['different terminal exception', p => { p.sdkInitializationObservation.terminal = 'other'; }],
  ['multiple helpers', p => { p.sdkInitializationObservation.helperInvocations = 2; p.sdkInitializationObservation.closedInvocations = 2; }],
  ['foreign schema', p => { p.sdkInitializationObservation.schema = 'foreign'; }],
  ['missing snapshot', p => { p.resources = null; }],
]) test(`native terminal refuses cause promotion with ${name}`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  f.behavior.failure = p => { p.code = 'resource_disk_exceeded'; p.sdkInitializationObservation = nativeRegistrationReceipt(); edit(p); };
  const result = await f.run(); assert.notEqual(result.reason, 'resource_disk_exceeded'); assert.equal(result.artifactsAccepted, false); assert.equal(f.calls.submits, 0);
});
for (const behavior of ['extraFailure', 'trailingFailure', 'hangFailure', 'failureExit']) test(`native terminal retains independent ${behavior}`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_initialization'; f.behavior[behavior] = behavior === 'failureExit' ? 0 : true;
  f.behavior.failure = p => { p.code = 'resource_disk_exceeded'; p.sdkInitializationObservation = nativeRegistrationReceipt(); }; f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run(); assert.equal(result.reason, 'resource_disk_exceeded'); assert.ok(result.independentFailures.length > 0); assert.equal(result.artifactsAccepted, false);
});
test('a native initialization receipt cannot be supplied by finalization', async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = 'sdk_finalization'; f.behavior.failure = p => { p.sdkInitializationObservation = nativeRegistrationReceipt(); };
  const result = await f.run(); assert.equal(result.reason, 'bridge_failure_observation_phase'); assert.equal(result.artifactsAccepted, false);
});

test('legacy SDK failure with ENOSPC text and concurrent OOM stays a SDK error', async t => {
  const f = await resourceFixture(t);
  f.behavior.resourceFinal = p => { p.result.status = 'failed'; p.result.error = 'ENOSPC: no space left on device, write'; p.result.artifacts = []; p.artifacts = []; p.attestation.resources.events.oom = 1; };
  f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run(); assert.equal(result.reason, 'bridge_sdk_failed'); assert.equal(result.artifactsAccepted, false); assert.deepEqual(result.workerResources.exceeded, ['memory']);
});

test('OOM never bypasses independent artifact integrity checks', async t => {
  for (const [reason, edit] of [
    ['bridge_artifact_bytes', p => { p.artifacts[0].content += 'changed'; }],
    ['bridge_finding_lines', p => rewriteArtifact(p, 'findings.json', v => { v.findings.push({ locations: [{ path: 'source.ts', startLine: 999 }] }); })],
  ]) {
    const f = await resourceFixture(t); f.behavior.resourceFinal = p => { p.attestation.resources.events.oom = 1; edit(p); };
    const result = await f.run(); assert.equal(result.reason, reason); assert.equal(result.artifactsAccepted, false); assert.deepEqual(result.workerResources.exceeded, ['memory']);
  }
});

const resourceClassification = result => classifyResourceStop({ resources: result.workerResources, reason: result.reason, boundaryVerified: true,
  inputsUnchanged: result.inputsUnchanged, workerClosed: result.cleanup.closed, containerAbsent: result.cleanup.containerAbsent, transportClosed: true,
  calls: result.providerSubmitInvocations, tokensComplete: result.usage?.complete === true, executionStatus: result.execution?.status,
  mcpEvidence: result.mcpEvidence, artifactEvidence: result.artifactEvidence, independentFailure: (result.independentFailures?.length ?? 0) > 0 });

for (const command of ['mcp.start', 'mcp.listTools', 'mcp.recordDraft', 'mcp.close']) for (const terminal of ['eof', 'communication', 'deadline', 'failure'])
test('MCP closure evidence survives ' + command + ' / ' + terminal, async t => {
  const f = await resourceFixture(t);
  f.behavior.terminal = { exitCode: terminal === 'deadline' ? 1 : 137, oomKilled: terminal !== 'deadline' };
  if (terminal === 'eof') f.behavior.eofCommand = command;
  if (terminal === 'communication') f.behavior.errorCommand = command;
  // Keep the MCP deadline distinct from the worker's wall deadline: the former
  // expires first and must not manufacture an observation of the latter.
  if (terminal === 'deadline') { f.options.limits.timeoutMs = 50; hangUntilDeadline(t, f, command, 50); }
  if (terminal === 'failure') { f.behavior.failureStage = 'mcp'; f.behavior.failureCommand = command; }
  const result = await f.run();
  assert.equal(result.mcpEvidence, 'unverified'); assert.equal(result.artifactEvidence, 'none');
  assert.equal(resourceClassification(result), null); assert.equal(result.artifactsAccepted, false);
  const saved = JSON.parse(await fs.readFile(path.join(f.directory, 'attempt.result.json')));
  assert.equal(saved.mcpEvidence, 'unverified'); assert.equal(saved.artifactEvidence, 'none');
  if (terminal === 'deadline') {
    assert.equal(result.reason, 'bridge_mcp_stopped');
    assert.deepEqual(result.workerResources.exceeded, []);
  } else assert.ok(result.workerResources.exceeded.includes('memory'));
  if (command === 'mcp.start' || command === 'mcp.listTools') assert.equal(result.providerSubmitInvocations, 0);
  else assert.ok(result.providerSubmitInvocations > 0);
  assert.deepEqual(await fs.readdir(path.join(f.directory, 'artifacts')), []);
});

test('the worker wall deadline is observed before cleanup and remains separate from a MCP deadline', async t => {
  const f = await resourceFixture(t); f.behavior.hangStartup = true; f.options.timeoutMs = 150;
  f.behavior.terminal = { exitCode: 1, oomKilled: false };
  const result = await f.run();
  assert.equal(result.providerSubmitInvocations, 0); assert.equal(result.mcpEvidence, 'not_started'); assert.equal(result.artifactEvidence, 'none');
  assert.deepEqual(result.workerResources.exceeded, ['time']); assert.equal(resourceClassification(result), 'time_budget_exceeded');
  assert.equal(result.artifactsAccepted, false); assert.deepEqual(await fs.readdir(path.join(f.directory, 'artifacts')), []);
});

test('resource-only OOM before MCP and after complete artifact proof remains distinguishable', async t => {
  const before = await resourceFixture(t); before.behavior.earlyEof = true; before.behavior.terminal = { exitCode: 137, oomKilled: true };
  const a = await before.run(); assert.equal(a.mcpEvidence, 'not_started'); assert.equal(a.artifactEvidence, 'none'); assert.equal(resourceClassification(a), 'resource_memory_exceeded');
  const after = await resourceFixture(t); const checked = [], validator = after.options.validateArtifacts;
  after.options.check = async bytes => { checked.push(hash(bytes)); return certificate(bytes); };
  after.options.validateArtifacts = (copies, metadata) => { for (const copy of copies) assert.equal(checked.filter(value => value === copy.sha256).length, 1); return validator(copies, metadata); };
  after.behavior.resourceFinal = p => { p.attestation.resources.events.oom = 1; };
  const b = await after.run(); assert.equal(b.mcpEvidence, 'closed'); assert.equal(b.artifactEvidence, 'verified');
  assert.equal(resourceClassification(b), 'resource_memory_exceeded'); assert.equal(b.artifactsAccepted, false); assert.equal(b.usage.observed.totalTokens, 20);
  assert.deepEqual(await fs.readdir(path.join(after.directory, 'artifacts')), []);
});

test('missing or invalid product validator rejects before ownership, worker and provider', async t => {
  for (const value of [undefined, null, true, {}]) {
    const f = await resourceFixture(t); f.options.validateArtifacts = value;
    await assert.rejects(f.run(), /bridge_artifact_validator/); assert.equal(f.calls.opens, 0); assert.equal(f.calls.submits, 0);
    assert.equal(await fs.stat(path.join(f.directory, 'attempt.lock')).catch(() => null), null);
  }
});

test('an unclean MCP close cannot be certified even beside a clean worker attestation', async t => {
  for (const mcpClosure of [{ closed: true, quiescent: false, clean: true }, { closed: true, quiescent: true, clean: false }, { closed: true, quiescent: true }]) {
    const f = await resourceFixture(t); f.behavior.mcpClosure = mcpClosure; f.behavior.terminal = { exitCode: 137, oomKilled: true };
    const result = await f.run(); assert.equal(result.mcpEvidence, 'unverified'); assert.equal(resourceClassification(result), null); assert.equal(result.artifactsAccepted, false);
  }
});

const productArtifactDefects = [
  ['unknown coverage key', 'coverage.json', d => { d.extra = true; }],
  ['include scope', 'coverage.json', d => { d.includePaths = ['other']; }],
  ['exclude scope', 'coverage.json', d => { d.excludePaths = ['source.ts']; }],
  ['duplicate surface', 'coverage.json', d => { d.surfaces.push(structuredClone(d.surfaces[0])); }],
  ['missing receipt', 'coverage.json', d => { d.surfaces[0].receiptRefs = ['absent.json']; }],
  ['invalid disposition', 'coverage.json', d => { d.surfaces[0].disposition = 'unknown'; }],
  ['invalid exclusion', 'coverage.json', d => { d.explicitExclusions = [{ pattern: 'x' }]; }],
  ['invalid deferred', 'coverage.json', d => { d.deferred = [{ id: 'x' }]; }],
  ['invalid question', 'coverage.json', d => { d.openQuestions = [{}]; }],
  ['missing source', 'scan-manifest.json', d => { d.scan.scope.artifactsReviewed = []; }],
  ['duplicate source', 'scan-manifest.json', d => { d.scan.scope.artifactsReviewed.push('source.ts'); }],
  ['invalid limitation', 'scan-manifest.json', d => { d.scan.scope.limitations = [false]; }],
  ['derived identity', 'scan-manifest.json', d => { d.scan.target.revision = 'e'.repeat(40); }],
  ['finding confidence', 'findings.json', d => { d.findings = [{ findingId: 'finding', ruleId: 'rule', confidence: { level: 'unknown' }, severity: { level: 'high' }, locations: [{ path: 'source.ts', startLine: 1 }] }]; }],
  ['finding severity shape', 'findings.json', d => { d.findings = [{ findingId: 'finding', ruleId: 'rule', confidence: { level: 'high' }, severity: null, locations: [{ path: 'source.ts', startLine: 1 }] }]; }],
  ['finding identifier', 'findings.json', d => { d.findings = [{ findingId: 'private invalid identifier', ruleId: 'rule', confidence: { level: 'high' }, severity: { level: 'high' }, locations: [{ path: 'source.ts', startLine: 1 }] }]; }],
  ['finding source', 'findings.json', d => { d.findings = [{ locations: [{ path: 'other.ts', startLine: 1 }] }]; }],
  ['finding line', 'findings.json', d => { d.findings = [{ locations: [{ path: 'source.ts', startLine: 2 }] }]; }],
];
for (const [name, file, change] of productArtifactDefects) test('OOM retains independent product rejection: ' + name, async t => {
  const f = await resourceFixture(t); f.behavior.resourceFinal = p => { rewriteArtifact(p, file, change); p.attestation.resources.events.oom = 1; };
  const result = await f.run(); assert.equal(result.artifactEvidence, 'unverified'); assert.equal(resourceClassification(result), null);
  assert.notEqual(result.reason, 'resource_memory_exceeded'); assert.equal(result.artifactsAccepted, false); assert.deepEqual(result.workerResources.exceeded, ['memory']);
  assert.equal(result.usage.observed.totalTokens, 20); assert.deepEqual(await fs.readdir(path.join(f.directory, 'artifacts')), []);
});

test('OOM cannot bypass artifact secret certification or live projection normalization', async t => {
  for (const kind of ['secret', 'projection']) {
    const f = await resourceFixture(t); f.behavior.resourceFinal = p => { p.attestation.resources.events.oom = 1; if (kind === 'projection') f.input.projection.mapping.originalCommit = '0'.repeat(40); };
    if (kind === 'secret') f.options.check = async bytes => bytes.includes(Buffer.from('"documentType":"codex-security.coverage"')) ? { bytes: 0, sha256: hash('') } : certificate(bytes);
    const result = await f.run(); assert.equal(result.artifactEvidence, 'unverified'); assert.equal(result.reason, kind === 'secret' ? 'bridge_secret_check' : 'codex_projection_mismatch');
    assert.equal(resourceClassification(result), null); assert.deepEqual(result.workerResources.exceeded, ['memory']); assert.equal(result.usage.observed.totalTokens, 20);
  }
});

const sdkdiagCanary = 'synthetic-sdkdiag-canary';
// Puts the canary into provider text and tool arguments; `calls` decides which tool calls a response keeps.
const canaryPackets = (sequence, calls = output => output) => transportPackets(sequence).map(bytes => {
  const event = JSON.parse(bytes);
  if (event.type === 'response.completed') event.response.output = calls(event.response.output.map(item => item.type === 'function_call' ? { ...item, arguments: item.arguments.replace('Synthetic fixture.', sdkdiagCanary) } : { ...item, content: [{ ...item.content[0], text: sdkdiagCanary }] }));
  return Buffer.from(JSON.stringify(event));
});
const site = (name, errorCode = null) => f => { f.behavior.failure = p => { p.sdkOutcome = { site: name, errorCode }; }; };
const firstTwo = [{ sequence: 1, toolCalls: 1, tools: ['scanmux_read_source'] }, { sequence: 2, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }];
for (const [name, options, expected, requests] of [
  ['A: a tool fails after the third response', { setup: f => { site('result_not_completed')(f); f.behavior.draftResult = (d, r) => d.complete ? { content: [{ type: 'text', text: JSON.stringify({ status: sdkdiagCanary }) }] } : r; } },
    { executorStatus: 'acceptance_unknown', executorMessage: 'tool_acceptance_unknown', sessionStatus: 'acceptance_unknown', sessionReason: 'tool_acceptance_unknown', finalDraft: false, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: 'draft_receipt',
      responses: [...firstTwo, { sequence: 3, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }], workerSite: 'result_not_completed', workerErrorCode: null }, 3],
  ['B: a response without tool calls ends the conversation before a final draft', { setup: site('result_not_completed'), stream: n => canaryPackets(n, output => n === 3 ? output.filter(item => item.type !== 'function_call').map(item => ({ ...item, phase: 'final_answer' })) : output) },
    { executorStatus: 'failed', executorMessage: 'final_draft_missing', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: false, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 2, toolFailureCode: null,
      responses: [...firstTwo, { sequence: 3, toolCalls: 0, tools: [] }], workerSite: 'result_not_completed', workerErrorCode: null }, 3],
  ['C: MCP close is unverified', { setup: f => { site('worker_threw', 'other')(f); f.behavior.mcpClosure = { closed: false, quiescent: false, clean: false }; } },
    { executorStatus: 'acceptance_unknown', executorMessage: 'mcp_close_unverified', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null, workerSite: 'worker_threw', workerErrorCode: 'other' }, 4],
  ['C: the executor throws after the session', { setup: f => { site('result_not_completed')(f); f.behavior.draftResult = (d, r) => { if (d.complete) writeFileSync(path.join(f.repo, 'source.ts'), sdkdiagCanary + '\n'); return r; }; } },
    { executorStatus: 'acceptance_unknown', executorMessage: 'executor_not_completed', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null, workerSite: 'result_not_completed', workerErrorCode: null }, 4],
]) test(`saved SDK outcome distinguishes ${name}`, async t => {
  const { saved, attempt, session } = await savedHostedTransport(t, { stream: n => canaryPackets(n), ...options });
  const outcome = saved.aiExecution.sdkOutcome; assert.equal(session.submitInvocations, requests);
  assert.deepEqual(expected.responses ? outcome : { ...outcome, responses: undefined }, { responses: undefined, ...expected });
  assert.deepEqual(JSON.parse(attempt).sdkOutcome, outcome);
  assert.ok(!JSON.stringify(saved).includes(sdkdiagCanary)); assert.ok(!attempt.includes(sdkdiagCanary));
});
test('saved SDK outcome on success has no worker site', async t => {
  const { saved, attempt } = await savedHostedTransport(t, { complete: true });
  assert.deepEqual(saved.aiExecution.sdkOutcome, { executorStatus: 'completed', executorMessage: null, sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null,
    responses: [...firstTwo, { sequence: 3, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }, { sequence: 4, toolCalls: 0, tools: [] }], workerSite: null, workerErrorCode: null });
  assert.deepEqual(JSON.parse(attempt).sdkOutcome, saved.aiExecution.sdkOutcome);
});
test('saved SDK outcome separates the two worker failure sites', async t => {
  const first = await savedHostedTransport(t, { setup: site('result_not_completed') }), second = await savedHostedTransport(t, { setup: site('worker_threw', 'worker_artifact_path') });
  assert.deepEqual([first, second].map(({ saved }) => [saved.aiExecution.sdkOutcome.workerSite, saved.aiExecution.sdkOutcome.workerErrorCode]), [['result_not_completed', null], ['worker_threw', 'worker_artifact_path']]);
  assert.deepEqual({ ...first.saved.aiExecution.sdkOutcome, workerSite: null, workerErrorCode: null }, { ...second.saved.aiExecution.sdkOutcome, workerSite: null, workerErrorCode: null });
});
async function workerFailureFrame(error, payload) {
  const source = await fs.readFile(new URL('../internal/linux-hosted-worker.mjs', import.meta.url), 'utf8');
  const start = source.indexOf('function terminalFailure('), end = source.indexOf('\nasync function main()'); assert.ok(start >= 0 && end > start);
  let frame;
  const context = { error, phase: 'sealing', failurePromise: null, mcp: null, rejectExecution() {}, startup: payload.startup, input: {}, requestSeen: {}, stage: 'artifacts', process: {},
    probeWorkerDisk: async () => ({ fullStores: [], observationComplete: true }), readWorkerResourceSnapshot: async () => payload.resources,
    pids: async () => { throw Error('synthetic unavailable'); }, requireValue: value => assert.ok(value),
    channel: { async send(type, value) { assert.equal(type, 'worker.failure'); frame = JSON.parse(JSON.stringify(value)); }, async end() {}, ended: Promise.resolve(), inspect: () => ({ failure: null, pendingWrites: 0 }) } };
  await runInNewContext(source.slice(start, end) + "\nterminalFailure('sdk_finalization', { error, site: 'worker_threw' });", context);
  assert.equal(context.process.exitCode, 1); return frame;
}
for (const [name, code, expected] of [['absent', undefined, 'other'], ['nonstring', 5, 'other'], ['invalid', 'worker-error', 'other'], ['oversize', 'a'.repeat(65), 'other'], ['valid', 'worker_artifact_path', 'worker_artifact_path']]) test(`worker error ${name} code never falls back to its message`, async t => {
  const canary = 'synthetic_sdkdiag_canary', error = Error(canary); if (code !== undefined) error.code = code;
  let frame;
  const { saved, attempt } = await savedHostedTransport(t, { setup: f => { f.behavior.failure = async payload => { frame = await workerFailureFrame(error, payload); Object.assign(payload, frame); }; } });
  assert.deepEqual(frame.sdkOutcome, { site: 'worker_threw', errorCode: expected });
  assert.equal(saved.aiExecution.sdkOutcome.workerErrorCode, expected); assert.equal(JSON.parse(attempt).sdkOutcome.workerErrorCode, expected);
  for (const text of [JSON.stringify(frame), JSON.stringify(saved), attempt]) assert.ok(!text.includes(canary));
});
const unknownTool = 'synthetic_sdkdiag_tool_canary';
for (const [name, change, reason, responses] of [
  ['unknown tool', response => response.output.find(item => item.type === 'function_call').name = unknownTool, 'invalid_tool', [{ sequence: 1, toolCalls: 1, tools: ['other'] }]],
  ['unknown usage', response => response.usage = null, 'usage_unknown', []],
]) test(`saved SDK outcome counts projected responses on ${name}`, async t => {
  const stream = n => transportPackets(n).map(bytes => { const event = JSON.parse(bytes); if (event.type === 'response.completed') change(event.response); return Buffer.from(JSON.stringify(event)); });
  const { saved, attempt, session } = await savedHostedTransport(t, { stream });
  assert.equal(session.status, 'acceptance_unknown'); assert.equal(session.reason, reason); assert.equal(session.toolInvocations, 0); assert.equal(session.submitInvocations, 1);
  const outcome = saved.aiExecution.sdkOutcome; assert.equal(outcome.sessionReason, reason); assert.deepEqual(outcome.responses, responses); assert.deepEqual(JSON.parse(attempt).sdkOutcome, outcome);
  for (const text of [JSON.stringify(session), JSON.stringify(saved), attempt]) assert.ok(!text.includes(unknownTool));
});
for (const [name, value, stage = 'sdk_finalization'] of [
  ['unknown key', { site: 'result_not_completed', errorCode: null, extra: 1 }], ['missing key', { site: 'worker_threw' }], ['unknown site', { site: 'foreign', errorCode: null }],
  ['wrong type', { site: 'worker_threw', errorCode: 5 }], ['array value', []], ['oversize code', { site: 'worker_threw', errorCode: 'a'.repeat(65) }],
  ['free text code', { site: 'worker_threw', errorCode: sdkdiagCanary }], ['code on the result site', { site: 'result_not_completed', errorCode: 'worker_failed' }],
  ['MCP stage', { site: 'worker_threw', errorCode: 'other' }, 'mcp'],
  ['host-owned tool failure code', { site: 'result_not_completed', errorCode: null, toolFailureCode: 'draft_source' }],
]) test(`terminal failure refuses SDK outcome with ${name}`, async t => {
  const f = await resourceFixture(t); f.behavior.failureStage = stage; f.behavior.failure = p => { p.sdkOutcome = value; };
  const result = await f.run(), attempt = await fs.readFile(path.join(f.directory, 'attempt.result.json'), 'utf8');
  assert.equal(result.reason, 'bridge_failure_shape'); assert.equal(result.artifactsAccepted, false); assert.equal(result.sdkOutcome?.workerSite ?? null, null); assert.ok(!attempt.includes(sdkdiagCanary));
});
const changePackets = change => n => transportPackets(n).map(bytes => {
  const event = JSON.parse(bytes); if (event.type === 'response.completed') change(event.response, n); return Buffer.from(JSON.stringify(event));
});
const repeatedRejections = (at, change) => changePackets((response, n) => {
  if (n !== at) return;
  const first = response.output.find(item => item.type === 'function_call'), value = JSON.parse(first.arguments); change(value); first.arguments = JSON.stringify(value);
  for (let i = 1; i < 3; i++) response.output.push({ ...first, id: `${first.id}_${i}`, call_id: `${first.call_id}_${i}` });
});
for (const [code, options, expected = code] of [
  ['draft_source', { stream: repeatedRejections(2, draft => { draft.scope.artifactsReviewed = ['foreign.ts']; }) }],
  ['draft_receipt', { setup: f => { f.behavior.draftResult = () => ({ content: [{ type: 'text', text: JSON.stringify({ status: sdkdiagCanary }) }] }); } }],
  ['draft_result_limit', { setup: f => { f.behavior.draftResult = () => ({ content: [{ type: 'text', text: 'x'.repeat(f.options.limits.maxToolResultBytes + 1) }] }); } }],
  ['secret_check_failed', { toolCheckFailure: true }],
  ['draft_owned_field', { stream: repeatedRejections(3, draft => { draft.coverage.scanId = sdkdiagCanary; }) }],
  ['mcp_unsettled', { toolError: { code: 'mcp_unsettled', message: sdkdiagCanary } }],
  ['synthetic_mcp_failure', { toolError: { code: 'synthetic_mcp_failure', message: sdkdiagCanary } }, 'other'],
  ['unknown message', { toolError: { message: sdkdiagCanary } }, 'other'],
]) test(`saved SDK outcome identifies tool failure ${code} without error text`, async t => {
  const { saved, attempt, session } = await savedHostedTransport(t, options);
  assert.equal(saved.aiExecution.sdkOutcome.toolFailureCode, expected); assert.equal(JSON.parse(attempt).sdkOutcome.toolFailureCode, expected); assert.equal(session.toolFailureCode, expected);
  assert.equal(saved.aiExecution.sdkOutcome.sessionReason, 'tool_acceptance_unknown');
  for (const text of [JSON.stringify(saved), attempt, JSON.stringify(session)]) assert.ok(!text.includes(sdkdiagCanary));
});
for (const [name, change] of [
  ['missing', {}], ['nonstring', { toolFailureCode: 5 }], ['array', { toolFailureCode: ['draft_source'] }], ['object', { toolFailureCode: { code: 'draft_source' } }],
  ['unknown code', { toolFailureCode: 'synthetic_mcp_failure' }], ['free text', { toolFailureCode: sdkdiagCanary }],
]) test(`bridge refuses SDK outcome tool failure code with ${name}`, async t => {
  const { saved, attempt } = await savedHostedTransport(t, { complete: true, outcomeChange: change });
  assert.equal(saved.aiExecution.sdkOutcome, undefined); assert.equal(JSON.parse(attempt).sdkOutcome, undefined);
  assert.equal(JSON.parse(attempt).reason, 'bridge_sdk_outcome'); assert.equal(JSON.parse(attempt).artifactsAccepted, false); assert.ok(!JSON.stringify(saved).includes(sdkdiagCanary)); assert.ok(!attempt.includes(sdkdiagCanary));
});
for (const [name, batches, expected] of [
  ['one in the same response', [1], 1], ['one in the next response', [0, 1], 1],
  ['several in one response', [3], 3], ['several across responses', [1, 2], 3],
]) test(`saved SDK outcome counts ignored post-final drafts: ${name}`, async t => {
  let calls;
  const stream = changePackets((response, n) => {
    const count = batches[n - 3] ?? 0;
    for (let i = 0; i < count; i++) response.output.push({ type: 'function_call', id: `ignored_function_${n}_${i}`, call_id: `ignored_draft_${n}_${i}`, name: 'record_codex_security_scan_draft', arguments: JSON.stringify(draft(true)), status: 'completed' });
    if (count) response.output[0].phase = 'commentary';
  });
  const { saved, attempt } = await savedHostedTransport(t, { complete: true, stream, setup: f => { calls = f.calls; } }), outcome = saved.aiExecution.sdkOutcome;
  assert.equal(outcome.ignoredAfterFinal, expected); assert.equal(outcome.toolInvocations, 3 + expected); assert.equal(outcome.toolFailureCode, null); assert.equal(calls.drafts.length, 2);
  assert.deepEqual(calls.drafts.map(d => d.complete), [false, true]); assert.deepEqual(JSON.parse(attempt).sdkOutcome, outcome);
});
for (const [name, change] of [
  ['missing', {}], ['negative', { ignoredAfterFinal: -1 }], ['non-integer', { ignoredAfterFinal: 1.5 }], ['string', { ignoredAfterFinal: '1' }],
  ['unsafe integer', { ignoredAfterFinal: Number.MAX_SAFE_INTEGER + 1 }], ['null', { ignoredAfterFinal: null }], ['boolean', { ignoredAfterFinal: true }],
]) test(`bridge refuses SDK outcome ignoredAfterFinal with ${name}`, async t => {
  const { saved, attempt } = await savedHostedTransport(t, { complete: true, outcomeChange: change, outcomeOmit: 'ignoredAfterFinal' }), result = JSON.parse(attempt);
  assert.equal(saved.aiExecution.sdkOutcome, undefined); assert.equal(result.sdkOutcome, undefined); assert.equal(result.reason, 'bridge_sdk_outcome'); assert.equal(result.artifactsAccepted, false);
});

const rejectionCanary = 'synthetic-draft-rejection-source-canary';
for (const codes of [['draft_owned_field'], ['draft_owned_field', 'draft_owned_field'], ['draft_owned_field', 'draft_code'], ['draft_owned_field', 'draft_code', 'draft_code']]) test(`saved SDK outcome counts draft rejections ${codes.join(',')}`, async t => {
  const sent = []; let calls;
  t.mock.method(HostedSocket.prototype, 'send', (bytes, options, callback) => { sent.push(JSON.parse(bytes)); callback(); });
  const stream = changePackets((response, n) => {
    if (n !== 2) return;
    const original = response.output.find(item => item.type === 'function_call');
    const rejected = codes.map((code, i) => {
      const value = draft(true); value.threatModel.summary = rejectionCanary;
      if (code === 'draft_owned_field') value.coverage.scanId = rejectionCanary;
      else value.findings = [{ locations: [{ path: 'source.ts', startLine: 1 }], codeEvidence: [{ path: 'source.ts', startLine: 1, code: rejectionCanary }] }];
      return { ...original, id: `rejected_function_${i}`, call_id: `rejected_draft_${i}`, arguments: JSON.stringify(value) };
    });
    response.output.splice(response.output.indexOf(original), 0, ...rejected);
  });
  const complete = codes.length < 3, { saved, attempt, session } = await savedHostedTransport(t, { complete, stream, setup: f => {
    calls = f.calls; const source = `// ${rejectionCanary}\n`; writeFileSync(path.join(f.repo, 'source.ts'), source); f.sources.set('source.ts', source);
    Object.assign(f.binding.manifest[0], { bytes: Buffer.byteLength(source), sha256: hash(source) });
    f.input.plan.snapshotHash = f.input.projection.mapping.snapshotHash = f.binding.snapshotHash = digest(f.binding.manifest);
  } });
  const expected = {}; for (const code of codes) expected[code] = (expected[code] ?? 0) + 1;
  const outcome = saved.aiExecution.sdkOutcome; assert.deepEqual(outcome.draftRejections, expected); assert.equal(outcome.toolFailureCode, complete ? null : codes.at(-1)); assert.equal(outcome.finalDraft, complete);
  assert.deepEqual(JSON.parse(attempt).sdkOutcome, outcome); assert.equal(calls.drafts.length, complete ? 2 : 0); assert.deepEqual(calls.drafts.map(d => d.complete), complete ? [false, true] : []);
  if (complete) for (let i = 0; i < codes.length; i++) {
    const output = sent.at(-1).input.find(item => item.type === 'function_call_output' && item.call_id === `rejected_draft_${i}`), feedback = JSON.parse(output.output);
    assert.equal(feedback.isError, true); assert.match(feedback.content[0].text, /^Input validation error\n/); assert.ok(!output.output.includes(rejectionCanary));
  }
  for (const text of [JSON.stringify(saved), attempt, JSON.stringify(session), JSON.stringify(calls.drafts)]) assert.ok(!text.includes(rejectionCanary));
});

for (const [name, value] of [
  ['missing', undefined], ['null', null], ['array', []], ['scalar', 1], ['negative', { draft_code: -1 }], ['fraction', { draft_code: 0.5 }],
  ['unsafe integer', { draft_code: Number.MAX_SAFE_INTEGER + 1 }], ['string count', { draft_code: '1' }], ['null count', { draft_code: null }], ['boolean count', { draft_code: true }],
  ['unknown code', { [rejectionCanary]: 1 }], ['fallback code', { other: 1 }], ['prototype key', JSON.parse('{"__proto__":1}')],
]) test(`bridge refuses SDK draft rejection counts with ${name}`, async t => {
  const { saved, attempt } = await savedHostedTransport(t, { complete: true, outcomeChange: value === undefined ? {} : { draftRejections: value }, outcomeOmit: 'draftRejections' }), result = JSON.parse(attempt);
  assert.equal(saved.aiExecution.sdkOutcome, undefined); assert.equal(result.sdkOutcome, undefined); assert.equal(result.reason, 'bridge_sdk_outcome'); assert.equal(result.artifactsAccepted, false);
  assert.ok(!attempt.includes(rejectionCanary)); assert.ok(!JSON.stringify(saved).includes(rejectionCanary));
});

test('bridge permits only fixed tool failure keys with non-negative integer rejection counts', async t => {
  const draftRejections = Object.fromEntries(toolFailureCodes.map(code => [code, code === 'draft_code' ? Number.MAX_SAFE_INTEGER : 0]));
  const { saved, attempt } = await savedHostedTransport(t, { complete: true, outcomeChange: { toolFailureCode: null, draftRejections }, outcomeValid: true });
  assert.deepEqual(saved.aiExecution.sdkOutcome.draftRejections, draftRejections); assert.deepEqual(JSON.parse(attempt).sdkOutcome.draftRejections, draftRejections);
});
