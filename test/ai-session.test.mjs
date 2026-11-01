import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { privateWorkspace } from '../src/private-storage.ts';
import { runAiSession, toolFailureCodes, validToolFailureCode } from '../internal/ai-session.mjs';
import { request as verifiedProbeRequest } from '../scripts/verify-daybreak-ws.mjs';
import { createResponseDecoder } from '../internal/response-protocol.mjs';

const target = process.cwd();
const root = await privateWorkspace(target);
test.after(() => removeTempDir(root));
const certificate = async b => ({ bytes: b.length, sha256: createHash('sha256').update(b).digest('hex') });
const sampleTool = { id: 'call_1', name: 'read', arguments: { file: 'fixed-fixture' } };
async function fixture(overrides = {}) {
  const directory = path.join(root, randomUUID()); await fs.mkdir(directory);
  const calls = { prepare: 0, submit: 0, tool: 0, close: 0 };
  const controller = new AbortController();
  const options = {
    directory, targetRoots: [target], identity: { runId: 'run', attemptId: 'attempt', buildId: 'build', requestId: 'request', scanId: 'scan', snapshotHash: 'a'.repeat(64) },
    limits: { maxRequests: 3, maxTotalOutputTokens: 12, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 8192, maxResponseBytesPerRequest: 8192, maxToolCalls: 3, maxToolResultBytes: 1024, timeoutMs: 10000 },
    toolNames: ['read'], signal: controller.signal,
    prepare: async context => { calls.prepare++; return Buffer.from(JSON.stringify({ type: 'response.create', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, store: false, input: [], tools: [{ type: 'function', name: 'read', parameters: {} }], max_output_tokens: context.outputCap })); },
    checkRequest: certificate, checkOutput: certificate,
    submit: async (body, context) => {
      calls.submit++;
      const reservation = JSON.parse(await fs.readFile(path.join(directory, `${context.sequence}.reserved.json`)));
      assert.equal(reservation.requestSha256, (await certificate(body)).sha256);
      assert.equal(reservation.callId, context.callId);
      return response(context);
    },
    executeAllowedTool: async () => { calls.tool++; return Buffer.from('fixed public fixture'); },
    close: async () => { calls.close++; return { closed: true, quiescent: true }; },
  };
  Object.assign(options, overrides);
  return { options, calls, controller, run: () => runAiSession(options) };
}
const functionItem = (tool, index = 0) => ({ type: 'function_call', id: `function_${index}`, call_id: tool.id, name: tool.name, arguments: JSON.stringify(tool.arguments), status: 'completed' });
function response(c, { tools = [], text = 'synthetic only', ...override } = {}) {
  return { sessionId: c.sessionId, callId: c.callId, requestId: c.identity.requestId, responseId: `response_${c.sequence}`, status: 'completed', model: 'gpt-6-sol-2026-10-01', effectiveProgram: 'daybreak_blue', usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5 }, output: [{ type: 'message', id: `message_${c.sequence}`, role: 'assistant', status: 'completed', content: [{ type: 'output_text', text, annotations: [] }] }, ...tools.map(functionItem)], ...override };
}

function decoded(c, output, change = () => {}) {
  const final = { id: `raw_${c.sequence}`, status: 'completed', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5 }, output };
  const events = [{ type: 'response.created', response: { id: final.id, model: final.model, status: 'in_progress', output: [] } }, { type: 'response.completed', response: final }]; change(events);
  const decoder = createResponseDecoder({ context: { sessionId: c.sessionId, callId: c.callId, requestId: c.identity.requestId }, maxBytes: 8192, maxEvents: 8 });
  for (const [sequence_number, event] of events.entries()) decoder.push(Buffer.from(JSON.stringify({ sequence_number, ...event })));
  return decoder.finish();
}

for (const [name, change, usageKnown] of [
  ['unrequested program', events => events[1].response.access_programs = { cyber: 'daybreak_red' }, true],
  ['unsupported output', events => events[1].response.output.push({ id: 'builtin', type: 'web_search_call' }), true],
  ['refusal', events => events[1].response.output.unshift({ id: 'refusal', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'refusal', refusal: 'Synthetic refusal.' }] }), true],
  ['incomplete', events => { events[1].type = 'response.incomplete'; events[1].response.status = 'incomplete'; }, true],
  ['invalid usage', events => events[1].response.usage.total_tokens = 4, false],
  ['missing usage', events => delete events[1].response.usage, false],
  ['duplicate terminal', events => events.push(structuredClone(events[1])), false],
  ['truncated stream', events => events.pop(), false],
]) test(`raw ${name} cannot dispatch tools even when transport close succeeds`, async () => {
  const f = await fixture(); f.options.submit = (_, c) => { f.calls.submit++; return decoded(c, [functionItem(sampleTool)], change); };
  const result = await f.run(); assert.notEqual(result.status, 'completed'); assert.equal(f.calls.tool, 0); assert.equal(f.calls.submit, 1); assert.equal(f.calls.close, 1);
  assert.equal(result.usageComplete, usageKnown); assert.equal(result.observedUsage.length, usageKnown ? 1 : 0);
  assert.deepEqual(result.responseTools, []);
});

test('raw completed output waits for certified transport close before the first tool', async () => {
  const f = await fixture(); let closing = false;
  f.options.submit = (_, c) => { f.calls.submit++; closing = false; return decoded(c, response(c, { tools: c.sequence === 1 ? [sampleTool] : [] }).output); };
  f.options.close = async () => { f.calls.close++; assert.equal(f.calls.tool, f.calls.submit === 1 ? 0 : 1); closing = true; return { closed: true, quiescent: true }; };
  f.options.executeAllowedTool = async () => { assert.equal(closing, true); f.calls.tool++; return Buffer.from('fixture'); };
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(f.calls.tool, 1); assert.equal(result.usage.totalTokens, 10);
});

for (const access of [null, { cyber: 'standard' }, { cyber: 'daybreak_blue' }]) test(`effective ${JSON.stringify(access)} completes a Blue request and retains its actual program`, async () => {
  const f = await fixture(), effective = access?.cyber ?? 'standard';
  f.options.submit = (_, c) => {
    f.calls.submit++;
    return decoded(c, response(c, { tools: c.sequence === 1 ? [sampleTool] : [] }).output, events => { events[1].response.access_programs = access; });
  };
  const result = await f.run();
  assert.equal(result.status, 'completed'); assert.equal(result.usageComplete, true); assert.equal(f.calls.tool, 1); assert.equal(f.calls.close, 2);
  for (const sequence of [1, 2]) {
    const reserved = JSON.parse(await fs.readFile(path.join(f.options.directory, `${sequence}.reserved.json`)));
    const terminal = JSON.parse(await fs.readFile(path.join(f.options.directory, `${sequence}.terminal.json`)));
    assert.equal(reserved.requestedProgram, 'daybreak_blue'); assert.equal(terminal.effectiveProgram, effective); assert.equal(terminal.state, 'completed');
  }
});

test('final response at exact call/output limit succeeds only as conversation; immutable records contain metadata', async () => {
  const f = await fixture(); f.options.limits.maxRequests = 1; f.options.limits.maxTotalOutputTokens = 2;
  const result = await f.run(); assert.equal(result.status, 'completed'); assert.equal(result.scanArtifactsAccepted, false); assert.equal(result.usageComplete, true);
  assert.deepEqual(f.calls, { prepare: 1, submit: 1, tool: 0, close: 1 });
  assert.equal(result.reservedCalls, 1); assert.equal(result.cost.value, null); assert.equal(result.accountAllowance, 'unknown');
  for (const name of await fs.readdir(f.options.directory)) assert.equal((await fs.readFile(path.join(f.options.directory, name), 'utf8')).includes('synthetic only'), false);
  const again = await f.run(); assert.equal(again.reason, 'ownership_unavailable'); assert.equal(f.calls.submit, 1);
});
test('two contenders have a single owner', async () => {
  const f = await fixture(); const results = await Promise.all([f.run(), f.run()]);
  assert.equal(results.filter(r => r.status === 'completed').length, 1); assert.equal(f.calls.submit, 1);
});
test('finite tool continuation consumes actual output, reserves each request and executes tools once', async () => {
  const f = await fixture(); const caps = []; const originalPrepare = f.options.prepare;
  f.options.limits.maxTotalOutputTokens = 6;
  f.options.prepare = async (c, previous) => { caps.push(c.outputCap); if (c.sequence > 1) assert.equal(previous.results[0].id, 'call_1'); return originalPrepare(c); };
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: c.sequence === 1 ? [sampleTool] : [] }); };
  const r = await f.run(); assert.equal(r.status, 'completed'); assert.deepEqual(caps, [5, 4]); assert.equal(r.toolInvocations, 1); assert.equal(f.calls.tool, 1); assert.equal(r.usage.outputTokens, 4);
  assert.deepEqual(r.responseTools, [{ sequence: 1, tools: ['read'] }, { sequence: 2, tools: [] }]);
  assert.equal(r.toolFailureCode, null); assert.equal(JSON.parse(await fs.readFile(path.join(f.options.directory, 'session.result.json'))).toolFailureCode, null);
});
for (const [name, change, reason] of [
  ['unknown program', r => r.effectiveProgram = 'unknown', 'effective_program_unverified'],
  ['red', r => r.effectiveProgram = 'daybreak_red', 'effective_program_unverified'],
  ['invalid model date', r => r.model = 'gpt-6-sol-2026-02-30', 'effective_program_unverified'],
  ['missing program', r => delete r.effectiveProgram, 'effective_program_unverified'],
  ['missing model', r => delete r.model, 'effective_program_unverified'],
  ['missing usage', r => delete r.usage, 'usage_unknown'],
  ['negative usage', r => r.usage.inputTokens = -1, 'usage_unknown'],
  ['unsafe usage', r => r.usage.totalTokens = Number.MAX_SAFE_INTEGER + 1, 'usage_unknown'],
  ['wrong total', r => r.usage.totalTokens = 4, 'usage_unknown'],
  ['cache exceeds input', r => r.usage.cachedInputTokens = 4, 'usage_unknown'],
  ['reasoning exceeds output', r => r.usage.reasoningTokens = 3, 'usage_unknown'],
  ['output exceeds cap', r => r.usage = { inputTokens: 0, outputTokens: 6, totalTokens: 6 }, 'output_cap_exceeded'],
  ['wrong association', r => r.callId = 'other', 'response_association'],
  ['extra receipt field', r => r.url = 'unsupported', 'invalid_response'],
  ['unknown tool', r => r.output.push(functionItem({ ...sampleTool, name: 'shell' })), 'invalid_tool'],
  ['duplicate tools', r => r.output.push(functionItem(sampleTool, 1), functionItem(sampleTool, 2)), 'invalid_output'],
  ['nonobject arguments', r => r.output.push(functionItem({ ...sampleTool, arguments: 'code' })), 'invalid_output'],
  ['missing text', r => delete r.output[0].content[0].text, 'invalid_output'],
  ['legacy text receipt', r => r.text = 'unsupported', 'invalid_response'],
  ['legacy tools receipt', r => r.tools = [], 'invalid_response'],
]) test(`reject ${name} before effects`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; const r = response(c); change(r); return r; };
  const r = await f.run(); assert.equal(r.status, 'acceptance_unknown'); assert.equal(r.reason, reason); assert.equal(f.calls.submit, 1); assert.equal(f.calls.close, 1); assert.equal(f.calls.tool, 0);
  assert.deepEqual(r.responseTools, name === 'unknown tool' ? [{ sequence: 1, tools: ['other'] }] : []);
  if (['red', 'unknown program', 'missing program', 'missing model', 'output exceeds cap'].includes(name)) assert.equal(r.observedUsage.length, 1);
});
// The deadline passes only inside the callback under test, so a slow host cannot spend it in an earlier phase.
function sessionClock(t) {
  let clock = 0;
  t.mock.method(performance, 'now', () => clock);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  // A synchronous callback blocks the timer, so it only moves the clock; an awaited one lets the timer fire.
  return (ms, { awaited }) => { clock += ms; if (awaited) t.mock.timers.tick(ms); };
}
for (const kind of ['sync', 'reject', 'cancel', 'timeout']) test(`${kind} submit settles unknown and closes once without replay`, async t => {
  const f = await fixture(), advance = sessionClock(t); if (kind === 'timeout') f.options.limits.timeoutMs = 40;
  f.options.submit = () => { f.calls.submit++; if (kind === 'sync') throw Error('private detail'); if (kind === 'reject') return Promise.reject(Error('private detail')); if (kind === 'cancel') f.controller.abort(); if (kind === 'timeout') advance(40, { awaited: true }); return new Promise(() => {}); };
  const r = await f.run(); assert.equal(r.status, 'acceptance_unknown'); assert.equal(f.calls.submit, 1); assert.equal(f.calls.close, 1); assert.equal(JSON.stringify(r).includes('private detail'), false);
});
for (const kind of ['false', 'throw', 'timeout', 'cancel']) test(`close ${kind} retains observed usage and cannot complete`, async t => {
  const f = await fixture(), advance = sessionClock(t); if (kind === 'timeout') f.options.limits.timeoutMs = 40;
  f.options.close = () => { f.calls.close++; if (kind === 'throw') throw Error(); if (kind === 'cancel') f.controller.abort(); if (kind === 'timeout') { advance(40, { awaited: true }); return new Promise(() => {}); } return { closed: false, quiescent: false }; };
  const r = await f.run(); assert.equal(r.status, 'acceptance_unknown'); assert.equal(r.reason, 'close_unverified'); assert.equal(r.observedUsage.length, 1); assert.equal(r.usage.totalTokens, 5); assert.equal(f.calls.close, 1);
});
test('pre-abort and abort during prepare send nothing', async () => {
  for (const during of [false, true]) { const f = await fixture(); if (during) f.options.prepare = () => { f.controller.abort(); return new Promise(() => {}); }; else f.controller.abort(); const r = await f.run(); assert.equal(r.submitInvocations, 0); assert.equal(f.calls.close, 0); }
});
test('late submit completion after cancellation cannot execute tools or another call', async () => {
  const f = await fixture(); let resolve, context;
  f.options.submit = (_, c) => { f.calls.submit++; context = c; f.controller.abort(); return new Promise(r => resolve = r); };
  const r = await f.run(); resolve(response(context, { tools: [sampleTool] })); await new Promise(r => setImmediate(r));
  assert.equal(r.status, 'acceptance_unknown'); assert.equal(f.calls.tool, 0); assert.equal(f.calls.submit, 1);
});
for (const kind of ['request', 'output', 'tool']) test(`secret check refusal for ${kind} stops continuation`, async () => {
  const f = await fixture();
  if (kind === 'request') f.options.checkRequest = async () => null;
  else { f.options.checkOutput = async b => kind === 'tool' && b.toString().startsWith('{') ? certificate(b) : null; f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: kind === 'tool' ? [sampleTool] : [] }); }; }
  const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.equal(f.calls.submit, kind === 'request' ? 0 : 1); assert.equal(f.calls.tool, kind === 'tool' ? 1 : 0);
  assert.equal(r.toolFailureCode, kind === 'tool' ? 'secret_check_failed' : null);
});
for (const [name, change] of [
  ['model', b => b.model = 'other'], ['program', b => b.access_programs = { cyber: 'standard' }], ['storage', b => b.store = true],
  ['old program array', b => b.access_programs = ['daybreak_blue']], ['missing event type', b => delete b.type], ['wrong event type', b => b.type = 'response.cancel'], ['extra program', b => b.access_programs.other = 'daybreak_blue'],
  ['cap', b => b.max_output_tokens++], ['endpoint', b => b.url = 'elsewhere'], ['builtin tool', b => b.tools = [{ type: 'web_search' }]],
]) test(`prepared ${name} change cannot dispatch`, async () => {
  const f = await fixture(); const original = f.options.prepare; f.options.prepare = async c => { const b = JSON.parse((await original(c)).toString()); change(b); return Buffer.from(JSON.stringify(b)); };
  const r = await f.run(); assert.equal(r.reservedCalls, 0); assert.equal(f.calls.submit, 0);
});
test('checker cannot mutate request bytes between validation and dispatch', async () => {
  const f = await fixture(); f.options.checkRequest = async b => { const result = await certificate(b); b.fill(0); return result; }; assert.equal((await f.run()).status, 'completed');
});
for (const boundary of ['calls', 'tokens', 'tools']) test(`${boundary} boundary forbids tool effects and another send`, async () => {
  const f = await fixture(); if (boundary === 'calls') f.options.limits.maxRequests = 1; if (boundary === 'tokens') f.options.limits.maxTotalOutputTokens = 2; if (boundary === 'tools') f.options.limits.maxToolCalls = 1;
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: boundary === 'tools' ? [sampleTool, { ...sampleTool, id: 'second' }] : [sampleTool] }); };
  const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.equal(r.reason, 'budget_exceeded'); assert.equal(f.calls.tool, 0); assert.equal(f.calls.submit, 1);
});
test('duplicate response and tool identifiers across turns cannot execute again', async () => {
  for (const duplicate of ['response', 'tool']) { const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { responseId: duplicate === 'response' ? 'same' : `r${c.sequence}`, tools: [sampleTool] }); }; const r = await f.run(); assert.equal(r.status, 'acceptance_unknown'); assert.equal(f.calls.tool, 1); assert.equal(f.calls.submit, 2); }
});
test('aggregate overflow retains individual usage and stops', async () => {
  const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { usage: { inputTokens: Number.MAX_SAFE_INTEGER - 2, outputTokens: 2, totalTokens: Number.MAX_SAFE_INTEGER }, tools: [sampleTool] }); };
  const r = await f.run(); assert.equal(r.reason, 'usage_overflow'); assert.equal(r.observedUsage.length, 2); assert.equal(r.usageComplete, false); assert.equal(f.calls.tool, 1);
});
for (const kind of ['throw', 'cancel', 'oversize', 'utf8']) test(`tool ${kind} cannot be replayed or continued`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: [sampleTool] }); };
  f.options.executeAllowedTool = () => { f.calls.tool++; if (kind === 'throw') throw Error(); if (kind === 'cancel') { f.controller.abort(); return new Promise(() => {}); } return kind === 'oversize' ? Buffer.alloc(1025) : Buffer.from([0xff]); };
  const r = await f.run(); assert.equal(r.status, 'acceptance_unknown'); assert.equal(f.calls.tool, 1); assert.equal(f.calls.submit, 1); assert.equal(JSON.parse(await fs.readFile(path.join(f.options.directory, 'session.result.json'))).status, 'acceptance_unknown');
  assert.equal(r.toolFailureCode, { throw: 'other', cancel: 'canceled', oversize: 'invalid_bytes', utf8: 'invalid_utf8' }[kind]);
});
for (const check of ['valid', 'oversize', 'secret']) test(`MCP-shaped input validation error uses the normal ${check} tool result path`, async () => {
  const f = await fixture(), feedback = Buffer.from(JSON.stringify({ isError: true, content: [{ type: 'text', text: 'Input validation error\ndraft_owned_field\ncoverage.mode\nRemove the SDK-owned field at the named path.' }] }));
  const prepare = f.options.prepare; let delivered = false, certified = false;
  f.options.prepare = async (context, previous) => { if (previous) { delivered = true; assert.equal(previous.results[0].content, feedback.toString()); assert.equal(JSON.parse(previous.results[0].content).isError, true); } return prepare(context); };
  f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: c.sequence === 1 ? [sampleTool] : [] }); };
  f.options.executeAllowedTool = async () => { f.calls.tool++; return feedback; };
  if (check === 'oversize') f.options.limits.maxToolResultBytes = feedback.length - 1;
  f.options.checkOutput = async bytes => { if (bytes.equals(feedback)) { certified = true; if (check === 'secret') return null; } return certificate(bytes); };
  const result = await f.run(); assert.equal(result.status, check === 'valid' ? 'completed' : 'acceptance_unknown'); assert.equal(result.toolFailureCode, check === 'valid' ? null : check === 'secret' ? 'secret_check_failed' : 'invalid_bytes');
  assert.equal(delivered, check === 'valid'); assert.equal(certified, check !== 'oversize'); assert.equal(result.toolInvocations, 1); assert.equal(f.calls.submit, check === 'valid' ? 2 : 1);
});
const toolErrorCanary = 'synthetic_tool_error_message_canary';
for (const code of toolFailureCodes) test(`tool failure keeps only the fixed code ${code}`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => response(c, { tools: [sampleTool] });
  f.options.executeAllowedTool = () => { throw Object.assign(Error(toolErrorCanary), { code }); };
  const result = await f.run(), saved = await fs.readFile(path.join(f.options.directory, 'session.result.json'), 'utf8');
  assert.equal(result.reason, 'tool_acceptance_unknown'); assert.equal(result.toolFailureCode, code); assert.equal(JSON.parse(saved).toolFailureCode, code); assert.ok(!saved.includes(toolErrorCanary));
});
for (const [name, error, expected] of [
  ['own message code', Error('draft_source'), 'draft_source'], ['own MCP message code', Error('mcp_unsettled'), 'mcp_unsettled'],
  ['unknown code', Object.assign(Error(toolErrorCanary), { code: 'synthetic_unknown_code' }), 'other'], ['message only', Error(toolErrorCanary), 'other'],
  ['nonstring code', Object.assign(Error('draft_source'), { code: 5 }), 'other'], ['null code', Object.assign(Error('draft_source'), { code: null }), 'other'],
  ['unknown code with a known message', Object.assign(Error('draft_source'), { code: toolErrorCanary }), 'other'], ['null throw', null, 'other'],
]) test(`tool failure classifies ${name} without retaining its message`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => response(c, { tools: [sampleTool] }); f.options.executeAllowedTool = () => { throw error; };
  const result = await f.run(), saved = await fs.readFile(path.join(f.options.directory, 'session.result.json'), 'utf8');
  assert.equal(result.toolFailureCode, expected); assert.equal(JSON.parse(saved).toolFailureCode, expected); assert.ok(!JSON.stringify(result).includes(toolErrorCanary)); assert.ok(!saved.includes(toolErrorCanary));
});
for (const [name, createError] of [
  ['throwing code getter', () => Object.defineProperty(Error(toolErrorCanary), 'code', { get() { throw Error(toolErrorCanary); } })],
  ['throwing message getter', () => Object.defineProperty(Error(), 'message', { get() { throw Error(toolErrorCanary); } })],
  ['revoked Proxy', () => { const { proxy, revoke } = Proxy.revocable({}, {}); revoke(); return proxy; }],
]) test(`tool failure classifies ${name} without changing the outcome`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { tools: [sampleTool] }); };
  f.options.executeAllowedTool = () => { f.calls.tool++; throw createError(); };
  const result = await f.run(), saved = await fs.readFile(path.join(f.options.directory, 'session.result.json'), 'utf8');
  for (const state of [result, JSON.parse(saved)]) assert.deepEqual({ status: state.status, reason: state.reason, toolFailureCode: state.toolFailureCode }, { status: 'acceptance_unknown', reason: 'tool_acceptance_unknown', toolFailureCode: 'other' });
  assert.equal(f.calls.tool, 1); assert.equal(f.calls.submit, 1); assert.equal(f.calls.close, 1); assert.ok(!JSON.stringify(result).includes(toolErrorCanary)); assert.ok(!saved.includes(toolErrorCanary));
});
test('tool failure code validation requires null or a fixed string', () => {
  for (const value of [null, 'other', ...toolFailureCodes]) assert.equal(validToolFailureCode(value), true);
  for (const value of [undefined, false, 0, {}, [], ['draft_source'], '', 'DRAFT_SOURCE', 'draft_source\n', toolErrorCanary]) assert.equal(validToolFailureCode(value), false);
});
// Fault injection is confined to fs.open in each sequential test; there is no
// production persistence override or model-controlled storage capability.
for (const step of ['open', 'writeFile', 'sync', 'close']) test(`reservation ${step} failure has zero submit`, async t => {
  const f = await fixture(); const open = fs.open.bind(fs);
  t.mock.method(fs, 'open', async (file, ...args) => {
    if (!file.endsWith('1.reserved.json')) return open(file, ...args);
    if (step === 'open') throw Error();
    const h = await open(file, ...args); const original = h[step].bind(h);
    h[step] = async (...values) => { if (step === 'close') await original(...values); throw Error(); }; return h;
  });
  const r = await f.run(); assert.equal(f.calls.submit, 0); assert.notEqual(r.status, 'completed');
});
test('terminal persistence failure stops after first send and preserves reservation', async t => {
  const f = await fixture(); const open = fs.open.bind(fs);
  t.mock.method(fs, 'open', async (file, ...args) => { if (file.endsWith('1.terminal.json')) throw Error(); return open(file, ...args); });
  const r = await f.run(); assert.equal(r.reason, 'persistence_failed'); assert.equal(f.calls.submit, 1); assert.equal(r.observedUsage.length, 1); assert.equal(JSON.parse(await fs.readFile(path.join(f.options.directory, '1.reserved.json'))).state, 'reserved');
});
test('abort after durable reservation before submit preserves canceled-not-sent evidence', async t => {
  const f = await fixture(); const open = fs.open.bind(fs);
  t.mock.method(fs, 'open', async (file, ...args) => { const h = await open(file, ...args); if (file.endsWith('1.reserved.json')) { const close = h.close.bind(h); h.close = async () => { await close(); f.controller.abort(); }; } return h; });
  const r = await f.run(); assert.equal(r.status, 'canceled'); assert.equal(r.reservedCalls, 1); assert.equal(r.submitInvocations, 0); assert.equal(JSON.parse(await fs.readFile(path.join(f.options.directory, '1.terminal.json'))).state, 'canceled_not_sent');
});
test('truncated existing ownership and terminal records are not repaired or resumed', async () => {
  const f = await fixture(); await fs.writeFile(path.join(f.options.directory, 'session.lock'), '{'); await fs.writeFile(path.join(f.options.directory, '1.terminal.json'), '{');
  assert.equal((await f.run()).reason, 'ownership_unavailable'); assert.equal(f.calls.prepare, 0); assert.equal(await fs.readFile(path.join(f.options.directory, 'session.lock'), 'utf8'), '{');
});
test('adapter cannot change accepted response while close is pending', async () => {
  const f = await fixture(); let supplied;
  f.options.submit = async (_, c) => { f.calls.submit++; supplied = response(c); return supplied; };
  f.options.close = async () => { f.calls.close++; supplied.output.push(functionItem({ ...sampleTool, name: 'shell' })); supplied.output[0].content[0].text = 'changed after verification'; return { closed: true, quiescent: true }; };
  const r = await f.run(); assert.equal(r.status, 'completed'); assert.equal(r.finalText, 'synthetic only'); assert.equal(f.calls.tool, 0);
});
for (const providerStatus of ['failed', 'canceled']) test(`definitive provider ${providerStatus} is preserved with observed usage`, async () => {
  const f = await fixture(); f.options.submit = async (_, c) => { f.calls.submit++; return response(c, { status: providerStatus }); };
  const r = await f.run(); assert.equal(r.status, providerStatus); assert.equal(r.observedUsage.length, 1); assert.equal(f.calls.tool, 0); assert.equal(f.calls.close, 1);
});
test('response and request byte limits reject before continuation', async () => {
  for (const which of ['request', 'response']) { const f = await fixture(); f.options.limits[which === 'request' ? 'maxInputBytesPerRequest' : 'maxResponseBytesPerRequest'] = 1; const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.equal(f.calls.submit, which === 'request' ? 0 : 1); assert.equal(f.calls.tool, 0); }
});
test('unknown usage remains null rather than zero', async () => {
  const f = await fixture(); f.options.submit = async (_, c) => response(c, { usage: undefined }); const r = await f.run(); assert.equal(r.usage, null); assert.equal(r.usageComplete, false); assert.deepEqual(r.observedUsage, []);
});
test('exact cache and reasoning boundaries are accepted', async () => {
  const f = await fixture(); f.options.submit = async (_, c) => response(c, { usage: { inputTokens: 3, outputTokens: 2, totalTokens: 5, cachedInputTokens: 3, reasoningTokens: 2 } }); assert.equal((await f.run()).status, 'completed');
});
test('directory within any target fails before ownership or callbacks', async () => {
  const f = await fixture(); f.options.targetRoots.push(root); await assert.rejects(f.run, /invalid_directory/); assert.deepEqual(await fs.readdir(f.options.directory), []); assert.equal(f.calls.prepare, 0);
});
test('final result persistence failure cannot return completed', async t => {
  const f = await fixture(); const open = fs.open.bind(fs);
  t.mock.method(fs, 'open', async (file, ...args) => { if (file.endsWith('session.result.json')) throw Error(); return open(file, ...args); });
  const r = await f.run(); assert.equal(r.reason, 'persistence_failed'); assert.equal(r.status, 'acceptance_unknown'); assert.equal(r.finalText, undefined); assert.equal(r.observedUsage.length, 1);
});
test('prepared protocol fields match the retained actual WebSocket probe contract', async () => {
  const f = await fixture(); const original = f.options.prepare;
  f.options.prepare = async (context, previous) => { const body = await original(context, previous); const parsed = JSON.parse(body); for (const key of ['type', 'model', 'access_programs', 'store']) assert.deepEqual(parsed[key], verifiedProbeRequest[key]); return body; };
  assert.equal((await f.run()).status, 'completed');
});
for (const phase of ['prepare', 'requestCheck', 'submit', 'responseCheck', 'tool', 'toolCheck', 'close']) test(`absolute deadline stops successors after slow synchronous ${phase}`, async t => {
  const f = await fixture(), advance = sessionClock(t); f.options.limits.timeoutMs = 100;
  const counts = { requestChecks: 0, responseChecks: 0, toolChecks: 0 };
  const block = () => advance(150, { awaited: false });
  const originalPrepare = f.options.prepare;
  f.options.prepare = async c => { const body = await originalPrepare(c); if (phase === 'prepare') block(); return body; };
  f.options.checkRequest = async b => { counts.requestChecks++; if (phase === 'requestCheck') block(); return certificate(b); };
  f.options.submit = (_, c) => { f.calls.submit++; if (phase === 'submit') block(); return response(c, { tools: [sampleTool, { ...sampleTool, id: 'call_2' }] }); };
  f.options.checkOutput = async b => { const kind = b.toString().startsWith('{') ? 'responseChecks' : 'toolChecks'; counts[kind]++; if (phase === 'responseCheck' && kind === 'responseChecks' || phase === 'toolCheck' && kind === 'toolChecks') block(); return certificate(b); };
  f.options.executeAllowedTool = () => { f.calls.tool++; if (phase === 'tool') block(); return Buffer.from('fixed fixture'); };
  f.options.close = () => { f.calls.close++; if (phase === 'close') block(); return { closed: true, quiescent: true }; };
  const r = await f.run(); assert.notEqual(r.status, 'completed'); assert.ok(f.calls.submit <= 1);
  if (phase === 'prepare') { assert.equal(counts.requestChecks, 0); assert.equal(f.calls.submit, 0); }
  if (phase === 'requestCheck') { assert.equal(r.reservedCalls, 0); assert.equal(f.calls.submit, 0); }
  if (phase === 'submit') { assert.equal(counts.responseChecks, 0); assert.equal(r.observedUsage.length, 1); }
  if (['tool', 'toolCheck'].includes(phase)) { assert.equal(f.calls.tool, 1); assert.equal(r.toolInvocations, 1); }
  else assert.equal(f.calls.tool, 0);
  if (!['prepare', 'requestCheck'].includes(phase)) { assert.equal(f.calls.close, 1); assert.equal(r.observedUsage.length, 1); }
});
