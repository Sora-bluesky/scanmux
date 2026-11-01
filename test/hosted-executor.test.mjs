import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { privateWorkspace } from '../src/private-storage.ts';
import { createHostedExecutor } from '../internal/hosted-executor.mjs';
import { createResponseDecoder } from '../internal/response-protocol.mjs';

const root = await privateWorkspace(process.cwd());
test.after(() => removeTempDir(root));
const schema = JSON.parse(await fs.readFile(new URL('./fixtures/codex-security-draft-input-schema.json', import.meta.url)));
const sha = b => createHash('sha256').update(b).digest('hex');
const certificate = b => ({ bytes: b.length, sha256: sha(b) });
const content = 'export const value = 1;\n';
const draft = complete => ({ complete, scope: { artifactsReviewed: ['source.ts'] }, threatModel: { summary: 'Synthetic fixture.' }, findings: [], coverage: { surfaces: [{ label: 'Fixture source', disposition: 'no_issue_found' }], explicitExclusions: [], deferred: [] } });
const tool = (id, name, args) => ({ id, name, arguments: args });
const read = () => tool('read_1', 'scanmux_read_source', { path: 'source.ts' });
const save = (complete = true, id = 'draft_1') => tool(id, 'record_codex_security_scan_draft', draft(complete));
function response(c, tools = []) {
  return { sessionId: c.sessionId, callId: c.callId, requestId: c.identity.requestId, responseId: `response_${c.sequence}`, status: 'completed', model: 'gpt-6-sol', effectiveProgram: 'daybreak_blue', usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 }, output: [{ type: 'message', id: `message_${c.sequence}`, role: 'assistant', phase: tools.length ? 'commentary' : 'final_answer', status: 'completed', content: [{ type: 'output_text', text: '', annotations: [] }] }, ...tools.map((tool, index) => ({ type: 'function_call', id: `function_${c.sequence}_${index}`, call_id: tool.id, name: tool.name, arguments: JSON.stringify(tool.arguments), status: 'completed' }))] };
}

async function fixture() {
  const base = path.join(root, randomUUID()), repo = path.join(base, 'repository'), directory = path.join(base, 'session');
  await fs.mkdir(repo, { recursive: true }); await fs.mkdir(directory); await fs.writeFile(path.join(repo, 'source.ts'), content);
  const identity = { runId: 'run', attemptId: 'attempt', buildId: 'build' };
  const runtime = { pluginRoot: path.join(base, 'plugin'), pluginVersion: '0.1.161', stateDirectory: path.join(base, 'state'), outputDirectory: path.join(base, 'out'), environment: {} };
  runtime.environment = { CODEX_SECURITY_SCAN_ID: 'scan', CODEX_SECURITY_REPOSITORY: repo, CODEX_SECURITY_STATE_DIR: runtime.stateDirectory, CODEX_SECURITY_SCAN_DIR: runtime.outputDirectory, CODEX_SECURITY_PLUGIN_ROOT: runtime.pluginRoot, CODEX_SECURITY_TARGET_REVISION: 'b'.repeat(40), CODEX_SECURITY_SURFACE: 'sdk' };
  const binding = { repository: repo, revision: 'b'.repeat(40), originalCommit: 'a'.repeat(40), snapshotHash: 'c'.repeat(64), scope: { paths: ['source.ts'] }, identity, runtime, reasoningEffort: 'high', manifest: [{ path: 'source.ts', bytes: Buffer.byteLength(content), sha256: sha(content) }] };
  const request = { version: 2, requestId: 'request', scanId: 'scan', repository: repo, revision: binding.revision, scope: structuredClone(binding.scope), identity: { ...identity }, runtime: structuredClone(runtime), prompt: 'Synthetic SDK prompt.', model: 'gpt-6-sol', reasoningEffort: 'high' };
  const calls = { submit: 0, drafts: [], close: 0, start: 0, transportClose: 0 }, abort = new AbortController(), bodies = [];
  const mcp = {
    async start() { calls.start++; },
    async listTools() { return { tools: [{ name: 'record_codex_security_scan_draft', inputSchema: structuredClone(schema) }] }; },
    async recordDraft(value) { calls.drafts.push(value); return { content: [{ type: 'text', text: JSON.stringify({ scanId: value.scanId, status: 'draft_written', operation: 'replace', findingCount: value.findings.length, surfaceCount: value.coverage.surfaces.length, coverage: value.coverage }) }] }; },
    async close() { calls.close++; return { closed: true, quiescent: true, clean: true }; },
  };
  const options = { binding, directory, limits: { maxRequests: 5, maxTotalOutputTokens: 20, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 262144, maxResponseBytesPerRequest: 131072, maxToolCalls: 6, maxToolResultBytes: 131072, timeoutMs: 10000 }, check: async b => certificate(b), createMcp: () => mcp,
    submit: async (bytes, c) => { calls.submit++; bodies.push(JSON.parse(bytes)); return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(false, 'checkpoint')] : c.sequence === 3 ? [save()] : []); },
    closeTransport: async () => { calls.transportClose++; return { closed: true, quiescent: true }; },
  };
  return { base, repo, binding, request, options, calls, mcp, abort, bodies, run: () => createHostedExecutor(options).run(request, { signal: abort.signal }) };
}

function logicalLinuxBinding(f) {
  f.options.sourceRoot = f.repo;
  f.binding.repository = '/handoff';
  f.binding.runtime.environment.CODEX_SECURITY_REPOSITORY = '/handoff';
  f.request.repository = '/handoff';
  f.request.runtime.environment.CODEX_SECURITY_REPOSITORY = '/handoff';
}
test('trusted physical sourceRoot preserves logical Linux request and real host journal', async () => {
  const f = await fixture(); logicalLinuxBinding(f);
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(f.calls.submit, 4);
  const journal = JSON.parse(await fs.readFile(path.join(f.options.directory, 'session.result.json'))); assert.equal(journal.status, 'completed'); assert.equal(journal.submitInvocations, 4); assert.equal(f.request.repository, '/handoff');
});
test('physical sourceRoot does not relax logical request binding', async () => {
  const f = await fixture(); logicalLinuxBinding(f); f.request.repository = f.repo;
  assert.equal((await f.run()).status, 'failed'); assert.equal(f.calls.start, 0); assert.equal(f.calls.submit, 0);
});
for (const [name, source] of [['relative', () => 'relative'], ['noncanonical', f => f.repo + path.sep + '..' + path.sep + 'repository'], ['nonstring', () => ({ repository: '/handoff' })]]) test(`physical sourceRoot rejects ${name}`, async () => {
  const f = await fixture(); logicalLinuxBinding(f); f.options.sourceRoot = source(f); assert.equal((await f.run()).status, 'failed'); assert.equal(f.calls.start, 0); assert.equal(f.calls.submit, 0);
});
test('logical Linux binding cannot hide a journal inside physical sourceRoot', async () => {
  const f = await fixture(); logicalLinuxBinding(f); f.options.directory = path.join(f.repo, 'journal'); await fs.mkdir(f.options.directory);
  assert.equal((await f.run()).status, 'failed'); assert.equal(f.calls.submit, 0); assert.equal(await fs.stat(path.join(f.options.directory, 'session.lock')).catch(() => null), null);
});
test('final integrity check reads physical sourceRoot after all semantic drafts', async () => {
  const f = await fixture(); logicalLinuxBinding(f); const original = f.options.submit;
  f.options.submit = async (bytes, context) => { const result = await original(bytes, context); if (context.sequence === 4) await fs.writeFile(path.join(f.repo, 'source.ts'), 'changed\n'); return result; };
  const result = await f.run(); assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(f.calls.drafts.length, 2);
});

test('SDK receipt requires actual final draft and complete conversation; full history retained', async () => {
  const f = await fixture(), result = await f.run();
  assert.equal(result.status, 'completed'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.usage.complete, true);
  assert.equal(f.calls.submit, 4); assert.equal(f.calls.transportClose, 4); assert.equal(f.calls.close, 1); assert.deepEqual(f.calls.drafts.map(d => d.complete), [false, true]);
  assert.ok(f.calls.drafts.every(d => d.scanId === 'scan'));
  assert.equal(f.bodies[3].input.filter(x => x.type === 'function_call_output').length, 3);
  assert.equal(f.bodies[0].tools[1].parameters.properties.scanId, undefined);
  assert.equal(f.bodies[0].tools[1].parameters.properties.handoffClaimToken, undefined);
  assert.ok(f.bodies[0].tools[1].parameters.required.includes('complete'));
  assert.match(f.bodies[0].input[0].content, /After complete:true succeeds, do not call the draft tool again; return the final answer\./);
  assert.match(f.bodies[0].tools[1].description, /After complete:true succeeds, do not call this tool again; return the final answer\./);
});

for (const timing of ['same response', 'next response']) for (const change of ['identical', 'changed final', 'invalid checkpoint']) test(`accepted final ignores ${change} in ${timing} and completes`, async () => {
  const f = await fixture(), accepted = draft(true), ignored = structuredClone(accepted), checked = [];
  const expected = Buffer.from(JSON.stringify({ ...accepted, scanId: 'scan' }));
  if (change === 'changed final') ignored.threatModel.summary = 'Changed after final acceptance.';
  if (change === 'invalid checkpoint') { ignored.complete = false; ignored.scope.artifactsReviewed = ['other.ts']; }
  f.options.check = async b => { checked.push(Buffer.from(b)); return certificate(b); };
  f.options.submit = async (bytes, c) => {
    f.calls.submit++; f.bodies.push(JSON.parse(bytes));
    return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('draft_1', 'record_codex_security_scan_draft', accepted), ...(timing === 'same response' ? [tool('draft_2', 'record_codex_security_scan_draft', ignored)] : [])] : c.sequence === 3 && timing === 'next response' ? [tool('draft_2', 'record_codex_security_scan_draft', ignored)] : []);
  };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed'); assert.equal(f.calls.drafts.length, 1); assert.equal(outcome.ignoredAfterFinal, 1);
  assert.deepEqual(Buffer.from(JSON.stringify(f.calls.drafts[0])), expected);
  assert.equal(checked.filter(b => b.equals(expected)).length, 1);
  if (change !== 'identical') assert.equal(checked.some(b => b.equals(Buffer.from(JSON.stringify({ ...ignored, scanId: 'scan' })))), false);
  const output = f.bodies.at(-1).input.find(item => item.type === 'function_call_output' && item.call_id === 'draft_2');
  assert.equal(output.output, 'final draft already accepted; do not call this tool again; finish with your final answer');
  assert.equal(checked.filter(b => b.toString() === output.output).length, 1);
  assert.equal(f.calls.submit, timing === 'same response' ? 3 : 4); assert.equal(f.calls.transportClose, f.calls.submit); assert.equal(f.calls.close, 1);
});

for (const [budget, maximum, submits, invocations] of [['maxRequests', 5, 5, 4], ['maxToolCalls', 3, 4, 3]]) test(`post-final repetition stops at existing ${budget} budget`, async () => {
  const f = await fixture(), expected = Buffer.from(JSON.stringify({ ...draft(true), scanId: 'scan' })); f.options.limits[budget] = maximum;
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, c.sequence === 1 ? [read()] : [save(true, `draft_${c.sequence}`)]); };
  const result = await f.run(); assert.equal(result.message, 'budget_exceeded'); assert.notEqual(result.status, 'completed');
  assert.equal(f.calls.submit, submits); assert.equal(f.calls.transportClose, submits); assert.equal(f.calls.drafts.length, 1); assert.equal(f.calls.close, 1);
  assert.deepEqual(Buffer.from(JSON.stringify(f.calls.drafts[0])), expected);
  const journal = JSON.parse(await fs.readFile(path.join(f.options.directory, 'session.result.json')));
  assert.equal(journal.reason, 'budget_exceeded'); assert.equal(journal.reservedCalls, submits); assert.equal(journal.toolInvocations, invocations);
});
test('ignored post-final result still requires the session secret certificate', async () => {
  const f = await fixture(); let rejected = 0;
  f.options.check = async b => { if (b.toString() === 'final draft already accepted; do not call this tool again; finish with your final answer') { rejected++; return null; } return certificate(b); };
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(), save(true, 'draft_2')] : []); };
  const result = await f.run(); assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.message, 'secret_check_failed');
  assert.equal(rejected, 1); assert.equal(f.calls.submit, 2); assert.deepEqual(f.calls.drafts, [{ ...draft(true), scanId: 'scan' }]);
});
for (const [name, next, reason] of [
  ['source read', tool('read_2', 'scanmux_read_source', { path: 'source.ts' }), undefined],
  ['invalid source read', tool('read_2', 'scanmux_read_source', { path: 'other.ts' }), 'tool_acceptance_unknown'],
  ['unknown tool', tool('other', 'other_tool', {}), 'invalid_tool'],
]) test(`post-final ${name} keeps normal handling`, async () => {
  const f = await fixture();
  f.options.submit = async (bytes, c) => { f.calls.submit++; f.bodies.push(JSON.parse(bytes)); return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save()] : c.sequence === 3 ? [next] : []); };
  const result = await f.run(); assert.equal(result.status, reason ? 'acceptance_unknown' : 'completed'); assert.equal(result.message, reason);
  assert.deepEqual(f.calls.drafts, [{ ...draft(true), scanId: 'scan' }]);
  if (!reason) assert.equal(JSON.parse(f.bodies.at(-1).input.find(item => item.type === 'function_call_output' && item.call_id === 'read_2').output).content, content);
});

test('raw events reach SDK with complete reasoning, assistant phase and original function arguments', async () => {
  const f = await fixture(), history = [], outputsByCall = [];
  f.options.submit = async (bytes, c) => {
    f.calls.submit++; const body = JSON.parse(bytes); assert.deepEqual(body.input.slice(2), history);
    const tools = c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(false, 'checkpoint')] : c.sequence === 3 ? [save()] : [];
    const output = [
      { type: 'reasoning', id: `reason_${c.sequence}`, status: 'completed', summary: [], encrypted_content: `synthetic-reasoning-${c.sequence}` },
      ...response(c, tools).output,
    ];
    for (const item of output.filter(item => item.type === 'function_call')) item.arguments = ` ${item.arguments} `;
    const final = { id: `raw_${c.sequence}`, model: 'gpt-6-sol', status: 'completed', access_programs: { cyber: 'daybreak_blue' }, usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 }, output };
    const decoder = createResponseDecoder({ context: { sessionId: c.sessionId, callId: c.callId, requestId: c.identity.requestId }, maxBytes: f.options.limits.maxResponseBytesPerRequest, maxEvents: 32 });
    const events = [{ type: 'response.created', response: { id: final.id, model: final.model, status: 'in_progress', output: [] } }, ...output.flatMap((item, output_index) => [{ type: 'response.output_item.added', output_index, item: { ...item, status: 'in_progress' } }, { type: 'response.output_item.done', output_index, item }]), { type: 'response.completed', response: { ...final, output: null } }];
    for (const [sequence_number, event] of events.entries()) decoder.push(Buffer.from(JSON.stringify({ sequence_number, ...event })));
    outputsByCall.push(structuredClone(output)); history.push(...structuredClone(output));
    return decoder.finish();
  };
  const submit = f.options.submit;
  f.options.submit = async (bytes, c) => {
    const body = JSON.parse(bytes);
    if (c.sequence > 1) {
      const prior = outputsByCall.at(-1).filter(item => item.type === 'function_call');
      const additions = body.input.slice(2 + history.length);
      assert.deepEqual(additions.map(item => item.call_id), prior.map(item => item.call_id));
      assert.ok(additions.every(item => item.type === 'function_call_output'));
      history.push(...structuredClone(additions));
    }
    return submit(bytes, c);
  };
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(outputsByCall.length, 4); assert.equal(f.calls.drafts.length, 2);
});
for (const key of ['version', 'requestId', 'scanId', 'repository', 'revision', 'scope', 'identity', 'model', 'reasoningEffort', 'runtime']) test(`reject foreign ${key} before MCP and submit`, async () => {
  const f = await fixture(); f.request[key] = key === 'requestId' ? '' : key === 'version' ? 1 : 'foreign';
  assert.equal((await f.run()).status, 'failed'); assert.equal(f.calls.start, 0); assert.equal(f.calls.submit, 0);
});
test('one executor owns one invocation even after rejection', async () => {
  const f = await fixture(), executor = createHostedExecutor(f.options); f.request.model = 'other';
  assert.equal((await executor.run(f.request)).status, 'failed'); f.request.model = 'gpt-6-sol';
  assert.equal((await executor.run(f.request)).message, 'executor_already_used'); assert.equal(f.calls.submit, 0);
});
for (const [name, mutate] of [
  ['extra file', f => fs.writeFile(path.join(f.repo, 'extra.ts'), 'extra')],
  ['missing file', f => fs.rename(path.join(f.repo, 'source.ts'), path.join(f.base, 'held.ts'))],
  ['changed source', f => fs.writeFile(path.join(f.repo, 'source.ts'), 'export const value = 2;\n')],
  ['traversal', async f => { f.binding.manifest[0].path = '../source.ts'; }],
  ['alias', async f => { f.binding.manifest.push({ ...f.binding.manifest[0], path: 'SOURCE.ts' }); }],
  ['invalid UTF8', async f => { const bytes = Buffer.from([0xff]); await fs.writeFile(path.join(f.repo, 'source.ts'), bytes); Object.assign(f.binding.manifest[0], { bytes: 1, sha256: sha(bytes) }); }],
  ['hardlink', async f => { await fs.link(path.join(f.repo, 'source.ts'), path.join(f.base, 'linked.ts')); }],
  ['oversize source', async f => { f.options.limits.maxToolResultBytes = 3; }],
]) test(`manifest rejects ${name} before inference`, async () => {
  const f = await fixture(); await mutate(f); assert.equal((await f.run()).status, 'failed'); assert.equal(f.calls.submit, 0);
});
const rejectionCanary = 'synthetic-draft-rejection-canary';
for (const [name, mutate, code, at] of [
  ['foreign scan', d => { d.scanId = rejectionCanary; }, 'draft_shape', '$'], ['claim token', d => { d.handoffClaimToken = rejectionCanary; }, 'draft_shape', '$'],
  ['unknown key', d => { d[rejectionCanary] = rejectionCanary; }, 'draft_shape', '$'],
  ['scope container', d => { d.scope = 42; }, 'draft_shape', 'scope'],
  ['findings container', d => { d.findings = {}; }, 'draft_shape', 'findings'],
  ['finding container', d => { d.findings[0] = null; }, 'draft_shape', 'findings[0]'],
  ['coverage container', d => { d.coverage = []; }, 'draft_shape', 'coverage'],
  ['provenance container', d => { d.findings[0].provenance = false; }, 'draft_shape', 'findings[0].provenance'],
  ['scope override', d => { d.scope.includePaths = [rejectionCanary]; }, 'draft_owned_field', 'scope.includePaths'],
  ['coverage override', d => { d.coverage.mode = rejectionCanary; }, 'draft_owned_field', 'coverage.mode'],
  ['foreign reviewed path', d => { d.scope.artifactsReviewed = [rejectionCanary]; }, 'draft_source', 'scope.artifactsReviewed[0]'],
  ['foreign deferred path', d => { d.coverage.deferred = [{ reason: 'later', paths: [rejectionCanary] }]; }, 'draft_source', 'coverage.deferred[0].paths[0]'],
  ...[['number', 1], ['repro number', 42], ['boolean', false], ['object', {}]].flatMap(([name, value]) => [
    [`reviewed ${name}`, d => { d.scope.artifactsReviewed = value; }, 'draft_shape', 'scope.artifactsReviewed'],
    [`deferred ${name}`, d => { d.coverage.deferred = value; }, 'draft_shape', 'coverage.deferred'],
    [`deferred paths ${name}`, d => { d.coverage.deferred = [{ paths: value }]; }, 'draft_shape', 'coverage.deferred[0].paths'],
    [`evidence ${name}`, d => { d.findings[0].codeEvidence = value; }, 'draft_shape', 'findings[0].codeEvidence'],
  ]),
  ['null deferred item', d => { d.coverage.deferred = [null]; }, 'draft_shape', 'coverage.deferred[0]'],
  ['missing complete', d => { delete d.complete; }, 'draft_shape', 'complete'],
  ['fake code', d => { d.findings[0].codeEvidence[1].code = rejectionCanary; }, 'draft_code', 'findings[0].codeEvidence[1].code'],
  ['out of range lines', d => { d.findings[0].locations[0].startLine = 2; }, 'draft_lines', 'findings[0].locations[0].startLine'],
  ['reversed lines', d => { d.findings[0].locations[0].endLine = 0; }, 'draft_lines', 'findings[0].locations[0].endLine'],
  ['canonical metadata', d => { d.findings[0].findingId = rejectionCanary; }, 'draft_owned_field', 'findings[0].findingId'],
  ['invalid location', d => { d.findings[0].locations[0] = rejectionCanary; }, 'draft_location', 'findings[0].locations[0]'],
  ['empty locations', d => { d.findings[0].locations = []; }, 'draft_locations', 'findings[0].locations'],
  ['root cause metadata', d => { d.findings[0].rootCause = { code: rejectionCanary }; }, 'draft_owned_field', 'findings[0].rootCause.code'],
  ['writeup path', d => { d.findings[0].writeup = { reportPath: rejectionCanary }; }, 'draft_writeup', 'findings[0].writeup.reportPath'],
  ...[['missing', undefined], ['null', null], ['number', 1], ['boolean', false], ['array', []], ['object', {}], ['noncallable toString', { toString: rejectionCanary }]].map(([name, value]) =>
    [`writeup path ${name}`, d => { d.findings[0].writeup = { reportPath: value }; }, 'draft_writeup', 'findings[0].writeup.reportPath']),
  ['provenance metadata', d => { d.findings[0].provenance = { sourceFindingIds: [rejectionCanary] }; }, 'draft_owned_field', 'findings[0].provenance.sourceFindingIds'],
]) test(`draft rejection returns a safe path for ${name}, then accepts the corrected final`, async () => {
  const f = await fixture(), accepted = anchoredDraft(), rejected = structuredClone(accepted); mutate(rejected);
  f.options.submit = async (bytes, c) => { f.calls.submit++; f.bodies.push(JSON.parse(bytes)); return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('rejected', 'record_codex_security_scan_draft', rejected)] : c.sequence === 3 ? [tool('corrected', 'record_codex_security_scan_draft', accepted)] : []); };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed'); assert.equal(outcome.toolFailureCode, null); assert.deepEqual(outcome.draftRejections, { [code]: 1 });
  assert.deepEqual(f.calls.drafts, [{ ...accepted, scanId: 'scan' }]); assert.equal(f.calls.submit, 4);
  const feedback = draftFeedback(f, 'rejected'); assert.equal(feedback.isError, true); assert.equal(feedback.content.length, 1); assert.equal(feedback.content[0].type, 'text');
  const lines = feedback.content[0].text.split('\n'); assert.deepEqual(lines.slice(0, 3), ['Input validation error', code, at]); assert.equal(lines.length, 4); assert.match(lines[3], /^[A-Z].*\.$/);
  assert.ok(!JSON.stringify(feedback).includes(rejectionCanary)); assert.ok(!JSON.stringify(outcome).includes(rejectionCanary));
});
for (const [name, mutate] of [
  ...[['missing', undefined], ['null', null], ['empty string', '']].flatMap(([name, value]) => [
    [`reviewed ${name}`, d => { d.scope.artifactsReviewed = value; }],
    [`deferred ${name}`, d => { d.coverage.deferred = value; }],
    [`deferred paths ${name}`, d => { d.coverage.deferred = [{ paths: value }]; }],
    [`evidence ${name}`, d => { d.findings[0].codeEvidence = value; }],
  ]),
  ['non-object deferred entries', d => { d.coverage.deferred = [false, 42, 'legacy', []]; }],
  ['string deferred entries', d => { d.coverage.deferred = 'legacy'; }],
]) test(`draft validation preserves acceptance of ${name}`, async () => {
  const f = await fixture(), accepted = anchoredDraft(); mutate(accepted);
  f.options.submit = async (bytes, c) => { f.calls.submit++; f.bodies.push(JSON.parse(bytes)); return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('accepted', 'record_codex_security_scan_draft', accepted)] : []); };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed'); assert.equal(outcome.toolFailureCode, null); assert.deepEqual(outcome.draftRejections, {});
  assert.deepEqual(f.calls.drafts, [{ ...JSON.parse(JSON.stringify(accepted)), scanId: 'scan' }]); assert.equal(f.calls.submit, 3);
});
test('standard response completes semantic drafts with observed usage', async () => {
  const f = await fixture(), submit = f.options.submit;
  f.options.submit = async (bytes, context) => ({ ...await submit(bytes, context), effectiveProgram: 'standard' });
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.usage.observed.totalTokens, 20); assert.equal(result.usage.complete, true); assert.equal(f.calls.submit, 4);
  assert.deepEqual(f.calls.drafts.map(d => d.complete), [false, true]);
});
for (const kind of ['text only', 'checkpoint only', 'unknown', 'daybreak_red', 'unknown usage', 'same batch unread', 'unknown source', 'unknown schema', 'missing schema', 'duplicate schema']) test(`${kind} cannot complete`, async () => {
  const f = await fixture();
  if (kind.includes('schema')) f.mcp.listTools = async () => ({ tools: kind === 'missing schema' ? [] : kind === 'duplicate schema' ? [1,2].map(() => ({ name: 'record_codex_security_scan_draft', inputSchema: schema })) : [{ name: 'record_codex_security_scan_draft', inputSchema: {} }] });
  f.options.submit = async (_, c) => {
    f.calls.submit++; const r = response(c, kind === 'text only' ? [] : c.sequence === 1 ? kind === 'same batch unread' ? [read(), save()] : kind === 'unknown source' ? [tool('read', 'scanmux_read_source', { path: '.git/config' })] : [read()] : c.sequence === 2 ? [save(kind !== 'checkpoint only')] : []);
    if (['unknown', 'daybreak_red'].includes(kind)) r.effectiveProgram = kind; if (kind === 'unknown usage') delete r.usage;
    return r;
  };
  const result = await f.run(); assert.notEqual(result.status, 'completed');
  if (['unknown', 'daybreak_red'].includes(kind)) assert.equal(result.status, 'acceptance_unknown');
  if (['unknown', 'daybreak_red', 'unknown usage', 'same batch unread', 'unknown source'].includes(kind)) assert.equal(f.calls.drafts.length, 0);
});
test('fixed bytes are delivered despite transient source mutation, and final mutation cannot complete', async () => {
  const f = await fixture(); let supplied;
  f.options.submit = async (bytes, c) => {
    f.calls.submit++; const b = JSON.parse(bytes);
    if (c.sequence === 1) await fs.writeFile(path.join(f.repo, 'source.ts'), 'temporary untrusted content');
    if (c.sequence === 2) { supplied = b.input.find(x => x.type === 'function_call_output').output; await fs.writeFile(path.join(f.repo, 'source.ts'), content); }
    if (c.sequence === 3) await fs.writeFile(path.join(f.repo, 'source.ts'), 'changed after draft');
    return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save()] : []);
  };
  const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.equal(JSON.parse(supplied).content, content); assert.equal(r.usage.observed.totalTokens, 15);
});
for (const failure of ['isError', 'foreign scan', 'wrong status', 'conflict', 'oversize', 'pending cancel', 'close', 'throw']) test(`MCP ${failure} never yields completed`, async () => {
  const f = await fixture(), original = f.mcp.recordDraft;
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(), save(true, 'draft_2')] : []); };
  f.mcp.recordDraft = async d => {
    if (failure === 'pending cancel') { f.calls.drafts.push(d); f.abort.abort(); return new Promise(() => {}); }
    const r = await original(d);
    if (failure === 'throw') throw Error('synthetic_mcp');
    if (failure === 'isError') r.isError = true;
    if (failure === 'conflict') r.structuredContent = { scanId: 'other' };
    if (failure === 'oversize') r.content[0].text = 'x'.repeat(131073);
    if (['foreign scan', 'wrong status'].includes(failure)) { const value = JSON.parse(r.content[0].text); value[failure === 'foreign scan' ? 'scanId' : 'status'] = 'other'; r.content[0].text = JSON.stringify(value); }
    return r;
  };
  if (failure === 'close') f.mcp.close = async () => { f.calls.close++; return { closed: true, quiescent: true, clean: false }; };
  const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.equal(r.usage.observed.totalTokens >= 10, true); assert.equal(f.calls.drafts.length, 1); assert.equal(f.calls.close, 1);
});
for (const phase of ['source', 'inventory', 'request', 'tool result', 'draft', 'draft result']) test(`secret checker rejects ${phase}`, async () => {
  const f = await fixture();
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(), save(true, 'draft_2')] : []); };
  f.options.check = async b => { const t = b.toString(); if (phase === 'source' && t === content || phase === 'inventory' && t.startsWith('[{"path"') || phase === 'request' && t.includes('response.create') || phase === 'tool result' && t.includes('"content":"export') || phase === 'draft' && t === JSON.stringify({ ...draft(true), scanId: 'scan' }) || phase === 'draft result' && t.startsWith('{"content":')) throw Error('synthetic_secret'); return certificate(b); };
  assert.notEqual((await f.run()).status, 'completed'); assert.equal(f.calls.drafts.length, phase === 'draft result' ? 1 : 0);
});
for (const phase of ['start', 'listTools']) test(`pre-session ${phase} consumes same deadline`, async () => {
  const f = await fixture(); f.options.limits.timeoutMs = 80; const original = f.mcp[phase];
  f.mcp[phase] = async () => { const until = performance.now() + 100; while (performance.now() < until) {} return original(); };
  assert.notEqual((await f.run()).status, 'completed'); assert.equal(f.calls.submit, 0); assert.equal(f.calls.close, 1);
});

test('genuine source anchors reach only the bound draft tool without rewriting semantic data', async () => {
  const f = await fixture(); const final = draft(true);
  final.findings = [{ locations: [{ path: 'source.ts', startLine: 1, endLine: 1 }], codeEvidence: [{ path: 'source.ts', startLine: 1, endLine: 1, code: content.trimEnd() }] }];
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('draft', 'record_codex_security_scan_draft', final)] : []); };
  assert.equal((await f.run()).status, 'completed'); assert.deepEqual(f.calls.drafts, [{ ...final, scanId: 'scan' }]);
});
test('source result bound includes metadata and escaping; no truncation is sent', async () => {
  const f = await fixture(); f.options.limits.maxToolResultBytes = Buffer.byteLength(content);
  assert.notEqual((await f.run()).status, 'completed'); assert.equal(f.calls.submit, 1); assert.equal(f.calls.drafts.length, 0);
});
test('constructor freezes binding and limits before caller mutation', async () => {
  const f = await fixture(); const executor = createHostedExecutor(f.options);
  f.binding.repository = path.join(f.base, 'foreign'); f.binding.manifest[0].sha256 = 'f'.repeat(64); f.options.limits.maxRequests = 1;
  assert.equal((await executor.run(f.request)).status, 'completed'); assert.equal(f.calls.submit, 4);
});
test('SDK abort before initialization performs no MCP or provider work', async () => {
  const f = await fixture(); f.abort.abort(); assert.equal((await f.run()).status, 'canceled'); assert.equal(f.calls.start, 0); assert.equal(f.calls.submit, 0); assert.equal(f.calls.close, 0);
});
test('host callback allocation does not reset the deadline or start MCP after expiry', async t => {
  const f = await fixture(); f.options.limits.timeoutMs = 80;
  // Only the blocking callback moves the executor clock, so a slow host cannot spend the deadline before it.
  let clock = 0;
  t.mock.method(performance, 'now', () => clock);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  f.options.createMcp = () => { clock += 100; return f.mcp; };
  assert.notEqual((await f.run()).status, 'completed'); assert.equal(f.calls.start, 0); assert.equal(f.calls.submit, 0); assert.equal(f.calls.close, 1);
});

for (const [name, value] of [
  ['ASCII', 'export const value = 1;\n'], ['leading UTF8 BOM', '\ufeffexport const value = 1;\n'],
  ['internal U+FEFF', 'a\ufeffb\n'], ['CRLF', 'const a = 1;\r\nconst b = 2;\r\n'],
  ['nonASCII', 'const 名前 = "é";\n'], ['empty', ''],
]) test(`complete source bytes and evidence survive ${name}`, async () => {
  const f = await fixture(); await fs.writeFile(path.join(f.repo, 'source.ts'), value);
  Object.assign(f.binding.manifest[0], { bytes: Buffer.byteLength(value), sha256: sha(value) });
  let delivered;
  const final = draft(true);
  if (value) final.findings = [{ locations: [{ path: 'source.ts', startLine: 1 }], codeEvidence: [{ path: 'source.ts', startLine: 1, code: value.split('\n')[0] }] }];
  f.options.submit = async (bytes, c) => {
    f.calls.submit++;
    if (c.sequence === 2) {
      const body = JSON.parse(bytes), output = body.input.find(x => x.type === 'function_call_output');
      delivered = JSON.parse(output.output);
    }
    return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('draft', 'record_codex_security_scan_draft', final)] : []);
  };
  const result = await f.run();
  assert.deepEqual(Buffer.from(delivered.content), Buffer.from(value));
  assert.equal(delivered.bytes, Buffer.byteLength(delivered.content)); assert.equal(delivered.sha256, sha(delivered.content));
  assert.equal(result.status, 'completed'); assert.deepEqual(f.calls.drafts, [{ ...final, scanId: 'scan' }]);
});

const canary = 'synthetic-sdkdiag-canary';
async function outcomeOf(f) { const executor = createHostedExecutor(f.options), result = await executor.run(f.request, { signal: f.abort.signal }); return { result, outcome: executor.outcome() }; }
const threeResponses = [{ sequence: 1, toolCalls: 1, tools: ['scanmux_read_source'] }, { sequence: 2, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }];
test('SDK outcome summarizes a completed run with fixed codes and counts only', async () => {
  const f = await fixture(), { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed');
  assert.deepEqual(outcome, { executorStatus: 'completed', executorMessage: null, sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null,
    responses: [...threeResponses, { sequence: 3, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }, { sequence: 4, toolCalls: 0, tools: [] }] });
});
for (const [name, edit, expected] of [
  ['A: final draft tool fails after the third response', f => {
    const submit = f.options.submit, original = f.mcp.recordDraft;
    f.options.submit = async (bytes, c) => { const r = await submit(bytes, c); for (const item of r.output) if (item.type === 'function_call') item.arguments = item.arguments.replace('Synthetic fixture.', canary); else item.content[0].text = canary; return r; };
    f.mcp.recordDraft = async d => { const r = await original(d); if (d.complete) r.content[0].text = JSON.stringify({ status: canary }); return r; };
  }, { executorStatus: 'acceptance_unknown', executorMessage: 'tool_acceptance_unknown', sessionStatus: 'acceptance_unknown', sessionReason: 'tool_acceptance_unknown', finalDraft: false, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: 'draft_receipt',
    responses: [...threeResponses, { sequence: 3, toolCalls: 1, tools: ['record_codex_security_scan_draft'] }] }],
  ['B: third response ends the conversation before a final draft', f => {
    f.options.submit = async (_, c) => { f.calls.submit++; const r = response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [save(false, 'checkpoint')] : []); r.output[0].content[0].text = canary; return r; };
  }, { executorStatus: 'failed', executorMessage: 'final_draft_missing', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: false, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 2, toolFailureCode: null,
    responses: [...threeResponses, { sequence: 3, toolCalls: 0, tools: [] }] }],
  ['C: MCP close is unverified', f => { f.mcp.close = async () => ({ closed: true, quiescent: true, clean: false }); },
    { executorStatus: 'acceptance_unknown', executorMessage: 'mcp_close_unverified', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null }],
  ['C: the executor throws after the session', f => {
    let late = false; const check = f.options.check, closeTransport = f.options.closeTransport;
    f.options.closeTransport = async c => { if (c.sequence === 4) late = true; return closeTransport(c); };
    f.options.check = async b => { if (late) throw Error(canary); return check(b); };
  }, { executorStatus: 'acceptance_unknown', executorMessage: 'executor_not_completed', sessionStatus: 'completed', sessionReason: 'conversation_completed', finalDraft: true, writeStarted: true, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 3, toolFailureCode: null }],
]) test(`SDK outcome distinguishes ${name}`, async () => {
  const f = await fixture(); edit(f); const { result, outcome } = await outcomeOf(f);
  assert.notEqual(result.status, 'completed'); assert.deepEqual(expected.responses ? outcome : { ...outcome, responses: undefined }, { responses: undefined, ...expected });
  assert.equal(JSON.stringify(outcome).includes(canary), false);
});
test('SDK outcome is null before any run and unchanged by a second invocation', async () => {
  const f = await fixture(), executor = createHostedExecutor(f.options); assert.equal(executor.outcome(), null);
  await executor.run(f.request); const first = executor.outcome(); assert.equal((await executor.run(f.request)).message, 'executor_already_used'); assert.deepEqual(executor.outcome(), first);
});
for (const [code, expected] of [['mcp_unsettled', 'mcp_unsettled'], ['mcp_unavailable', 'mcp_unavailable'], ['mcp_input_limit', 'mcp_input_limit'], ['mcp_response_error', 'mcp_response_error'], ['synthetic_mcp_failure', 'other']]) test(`SDK outcome retains only the fixed MCP failure ${code}`, async () => {
  const f = await fixture(); f.mcp.recordDraft = async () => { throw Object.assign(Error(canary), { code }); };
  const { result, outcome } = await outcomeOf(f), saved = await fs.readFile(path.join(f.options.directory, 'session.result.json'), 'utf8');
  assert.equal(result.status, 'acceptance_unknown'); assert.equal(outcome.toolFailureCode, expected); assert.equal(JSON.parse(saved).toolFailureCode, expected);
  assert.ok(!JSON.stringify(outcome).includes(canary)); assert.ok(!saved.includes(canary));
});
test('SDK outcome identifies a tool certificate refusal before MCP dispatch', async () => {
  const f = await fixture(); f.options.check = async bytes => bytes.toString().startsWith('{"complete":') ? null : certificate(bytes);
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'acceptance_unknown'); assert.equal(outcome.toolFailureCode, 'secret_check_failed'); assert.equal(f.calls.drafts.length, 0);
});

function anchoredDraft() {
  const value = draft(true), evidence = { path: 'source.ts', startLine: 1, code: content.trimEnd() };
  value.findings = [{ locations: [{ path: 'source.ts', startLine: 1 }], codeEvidence: [structuredClone(evidence), structuredClone(evidence)] }]; return value;
}
const draftFeedback = (f, id) => JSON.parse(f.bodies.at(-1).input.find(item => item.type === 'function_call_output' && item.call_id === id).output);
for (const count of [1, 2]) for (const batch of [false, true]) test(`${count} draft rejections ${batch ? 'in one response' : 'across responses'} preserve the corrected draft`, async () => {
  const f = await fixture(), accepted = anchoredDraft(), rejected = structuredClone(accepted); rejected.coverage.mode = rejectionCanary;
  f.options.submit = async (bytes, c) => {
    f.calls.submit++; f.bodies.push(JSON.parse(bytes));
    const calls = c.sequence === 1 ? [read()] : batch ? c.sequence === 2 ? [...Array.from({ length: count }, (_, i) => tool(`rejected_${i}`, 'record_codex_security_scan_draft', rejected)), tool('corrected', 'record_codex_security_scan_draft', accepted)] : []
      : c.sequence < count + 2 ? [tool(`rejected_${c.sequence}`, 'record_codex_security_scan_draft', rejected)] : c.sequence === count + 2 ? [tool('corrected', 'record_codex_security_scan_draft', accepted)] : [];
    return response(c, calls);
  };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed'); assert.deepEqual(outcome.draftRejections, { draft_owned_field: count });
  assert.deepEqual(f.calls.drafts, [{ ...accepted, scanId: 'scan' }]); assert.equal(outcome.toolInvocations, count + 2); assert.equal(outcome.finalDraft, true);
  const feedback = draftFeedback(f, batch ? 'rejected_0' : 'rejected_2');
  assert.deepEqual(feedback, { isError: true, content: [{ type: 'text', text: 'Input validation error\ndraft_owned_field\ncoverage.mode\nRemove the SDK-owned field at the named path.' }] });
});

test('the third draft rejection keeps its code and stops before any draft write', async () => {
  const f = await fixture();
  f.options.submit = async (_, c) => {
    f.calls.submit++; const rejected = draft(true); if (c.sequence < 4) rejected.coverage.scanId = rejectionCanary;
    else rejected.findings = [{ locations: [{ path: 'source.ts', startLine: 1 }], codeEvidence: [{ path: 'source.ts', startLine: 1, code: rejectionCanary }] }];
    return response(c, c.sequence === 1 ? [read()] : [tool(`rejected_${c.sequence}`, 'record_codex_security_scan_draft', rejected), ...(c.sequence === 4 ? [save()] : [])]);
  };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.message, 'tool_acceptance_unknown'); assert.equal(outcome.toolFailureCode, 'draft_code');
  assert.deepEqual(outcome.draftRejections, { draft_owned_field: 2, draft_code: 1 }); assert.equal(f.calls.submit, 4); assert.equal(outcome.toolInvocations, 4); assert.equal(outcome.writeStarted, false); assert.deepEqual(f.calls.drafts, []);
});

for (const corrected of [false, true]) test(`accepted checkpoint survives a rejected final${corrected ? ' and is replaced only by the corrected final' : ''}`, async () => {
  const f = await fixture(), checkpoint = draft(false), accepted = anchoredDraft(), rejected = structuredClone(accepted); rejected.coverage.scanId = rejectionCanary;
  f.options.limits.maxRequests = 6;
  f.options.submit = async (bytes, c) => {
    f.calls.submit++; f.bodies.push(JSON.parse(bytes));
    if (c.sequence === 4) assert.deepEqual(f.calls.drafts, [{ ...checkpoint, scanId: 'scan' }]);
    return response(c, c.sequence === 1 ? [read()] : c.sequence === 2 ? [tool('checkpoint', 'record_codex_security_scan_draft', checkpoint)] : c.sequence === 3 ? [tool('rejected', 'record_codex_security_scan_draft', rejected)] : c.sequence === 4 && corrected ? [tool('corrected', 'record_codex_security_scan_draft', accepted)] : []);
  };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, corrected ? 'completed' : 'failed'); assert.equal(result.message, corrected ? undefined : 'final_draft_missing');
  assert.deepEqual(f.calls.drafts, [{ ...checkpoint, scanId: 'scan' }, ...(corrected ? [{ ...accepted, scanId: 'scan' }] : [])]); assert.deepEqual(outcome.draftRejections, { draft_owned_field: 1 }); assert.equal(outcome.finalDraft, corrected);
});

test('an unread source rejection points only to its draft path and can be corrected by a source read', async () => {
  const f = await fixture();
  f.options.submit = async (bytes, c) => { f.calls.submit++; f.bodies.push(JSON.parse(bytes)); return response(c, c.sequence === 1 ? [save(true, 'rejected')] : c.sequence === 2 ? [read()] : c.sequence === 3 ? [save()] : []); };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.status, 'completed'); assert.deepEqual(outcome.draftRejections, { draft_unread_source: 1 });
  assert.match(draftFeedback(f, 'rejected').content[0].text, /^Input validation error\ndraft_unread_source\nscope.artifactsReviewed\[0\]\n/); assert.equal(f.calls.drafts.length, 1);
});

for (const [budget, maximum, submits, rejections] of [['maxRequests', 3, 3, 1], ['maxToolCalls', 2, 3, 1], ['maxTotalOutputTokens', 6, 3, 1]]) test(`repeated draft rejections stay inside ${budget}`, async () => {
  const f = await fixture(); f.options.limits[budget] = maximum;
  f.options.submit = async (_, c) => { f.calls.submit++; const rejected = draft(true); rejected.coverage.mode = rejectionCanary; return response(c, c.sequence === 1 ? [read()] : [tool(`rejected_${c.sequence}`, 'record_codex_security_scan_draft', rejected)]); };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.message, 'budget_exceeded'); assert.equal(outcome.sessionStatus, budget === 'maxToolCalls' ? 'acceptance_unknown' : 'budget_exceeded'); assert.equal(outcome.toolFailureCode, null);
  assert.equal(f.calls.submit, submits); assert.deepEqual(outcome.draftRejections, { draft_owned_field: rejections }); assert.equal(outcome.finalDraft, false); assert.deepEqual(f.calls.drafts, []);
});

for (const failure of ['size', 'secret']) test(`draft rejection feedback requires the existing ${failure} check`, async () => {
  const f = await fixture(); if (failure === 'size') f.options.limits.maxToolResultBytes = 180;
  let checked = 0;
  f.options.check = async bytes => { if (bytes.toString().startsWith('{"isError":true,')) { checked++; return null; } return certificate(bytes); };
  f.options.submit = async (_, c) => { f.calls.submit++; const rejected = anchoredDraft(); rejected.findings[0].codeEvidence[1].code = rejectionCanary; return response(c, c.sequence === 1 ? [read()] : [tool('rejected', 'record_codex_security_scan_draft', rejected)]); };
  const { result, outcome } = await outcomeOf(f); assert.equal(result.message, failure === 'size' ? 'tool_acceptance_unknown' : 'secret_check_failed');
  assert.equal(outcome.toolFailureCode, failure === 'size' ? 'invalid_bytes' : 'secret_check_failed'); assert.equal(checked, failure === 'size' ? 0 : 1); assert.deepEqual(f.calls.drafts, []); assert.equal(f.calls.submit, 2);
});
