import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { createServer } from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { registerHooks } from 'node:module';
import WebSocket, { WebSocketServer } from 'ws';
import { createResponsesTransport } from '../internal/responses-transport.mjs';
import { runAiSession } from '../internal/ai-session.mjs';
import { privateWorkspace } from '../src/private-storage.ts';
import { defaults as configDefaults } from '../src/config.ts';
import { aiRuntime } from '../src/ai-plan.ts';
import { digest } from '../src/safety.ts';

const hash = b => createHash('sha256').update(b).digest('hex');
const root = await privateWorkspace(process.cwd());
test.after(async () => { try { await saveProof(); } finally { await removeTempDir(root); } });
const evidence = [];
const token = 'synthetic-transport-fixture';
const defaults = { bearerToken: token, maxRequests: 3, maxRequestBytes: 8192, maxResponseBytes: 16384, maxEvents: 32, timeoutMs: 2000 };
const identity = Object.freeze({ runId: 'run', attemptId: 'attempt', buildId: 'build', requestId: 'request', scanId: 'scan', snapshotHash: 'a'.repeat(64) });
function context(sequence = 1, changes = {}) { return Object.freeze({ identity, sessionId: 'session', callId: `call_${sequence}`, sequence, outputCap: 5, signal: new AbortController().signal, ...changes }); }
function body(c) { return Buffer.from(JSON.stringify({ type: 'response.create', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, store: false, input: [], tools: [], max_output_tokens: c.outputCap })); }
const message = n => ({ type: 'message', id: `message_${n}`, role: 'assistant', status: 'completed', phase: 'final_answer', content: [{ type: 'output_text', text: 'synthetic complete', annotations: [] }] });
const functionItem = { type: 'function_call', id: 'function_1', call_id: 'tool_1', name: 'read', arguments: ' { "file": "fixed" } \n', status: 'completed' };
const richOutput = [{ type: 'reasoning', id: 'reasoning_1', summary: [], encrypted_content: 'synthetic-encrypted-only', status: 'completed' }, { ...message(1), phase: 'commentary' }, functionItem];
function packets(n = 1, { output = [message(n)], status = 'completed', access = { cyber: 'daybreak_blue' }, fallback = false } = {}) {
  const response = { id: `resp_fixture_${n}`, model: 'gpt-6-sol', status, access_programs: access, usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5, input_tokens_details: { cached_tokens: 1 }, output_tokens_details: { reasoning_tokens: 1 } }, output };
  const events = [{ type: 'response.created', response: { id: response.id, model: response.model, status: 'in_progress', output: [] } }];
  if (fallback) { for (const [output_index, item] of output.entries()) { events.push({ type: 'response.output_item.added', output_index, item }); events.push({ type: 'response.output_item.done', output_index, item }); } delete response.output; }
  events.push({ type: `response.${status}`, response });
  return events.map((event, sequence_number) => Buffer.from(JSON.stringify({ sequence_number, ...event })));
}
function deliver(socket, bytes) { for (const b of bytes) socket.emit('message', b, false); }
class FakeSocket extends EventEmitter {
  constructor({ autoAck = true, neverClose = false, closeCode = 1000 } = {}) { super(); this.autoAck = autoAck; this.neverClose = neverClose; this.closeCode = closeCode; this.sends = []; this.terminations = 0; this.closes = 0; }
  open() { this.emit('upgrade', { statusCode: 101 }); this.emit('open'); }
  send(bytes, options, callback) { this.sends.push({ bytes: Buffer.from(bytes), options }); this.callback = callback; if (this.autoAck) callback(); }
  close() { this.closes++; if (!this.neverClose) queueMicrotask(() => this.emit('close', this.closeCode)); }
  terminate() { this.terminations++; if (!this.neverClose) queueMicrotask(() => this.emit('close', 1006)); }
}
function fake(overrides = {}, socketOptions = {}) {
  const socket = new FakeSocket(socketOptions), constructions = [];
  const adapter = createResponsesTransport({ ...defaults, createSocket: (url, settings) => { constructions.push({ url, settings }); return socket; }, ...overrides });
  return { adapter, socket, constructions, begin(c = context(), bytes = body(c)) { const promise = adapter.submit(bytes, c); promise.catch(() => {}); return { promise, c }; } };
}
const rejected = promise => assert.rejects(promise, error => /^transport_|^invalid_transport_/.test(error.message) && !error.message.includes(token));

const emptyFirstEvent = { type: 'absent', keys: [], otherKeys: 0, sequenceNumber: 'absent', sequence: 'absent', streamId: 'absent' };
const createdFirstEvent = { ...emptyFirstEvent, kind: 'object', type: 'response.created', keys: ['response', 'sequence_number', 'type'], sequenceNumber: 'integer' };
const rateLimitMessage = Buffer.from(JSON.stringify({ type: 'codex.rate_limits', rate_limits: { remaining: 8675309, detail: 'private-response-canary' } }));
const rateLimitFirstEvent = { ...emptyFirstEvent, kind: 'object', type: 'codex.rate_limits', keys: ['rate_limits', 'type'] };
const rateLimitRejectedEvent = { ...rateLimitFirstEvent, valueShapes: { rate_limits: { type: 'object', size: 2 }, type: { type: 'string', size: 17 } } };

for (const [type, reportedType] of [['response.something_new', 'response.something_new'], ['private-response-canary', 'other']]) test(`decoder rejection records the first bounded ${reportedType} shape at message two`, async () => {
  const bytes = Buffer.from(JSON.stringify({ type, sequence_number: 1, text: 'private-response-canary', UpperKey: 'private-response-canary' }));
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [packets()[0], bytes, packets()[1]]); await rejected(promise);
  const row = f.adapter.inspect().calls[0], shape = { ...emptyFirstEvent, kind: 'object', type: reportedType,
    keys: ['sequence_number', 'text', 'type'], otherKeys: 1, sequenceNumber: 'integer', valueShapes: {
      sequence_number: { type: 'number', size: null }, text: { type: 'string', size: 23 }, type: { type: 'string', size: type.length },
    } };
  assert.equal(row.failureCode, 'unexpected_event'); assert.equal(row.outputIdentityMismatch, null); assert.equal(row.rejectedAt, 2); assert.deepEqual(row.rejectedEvent, shape);
  assert.deepEqual(row.firstEvent, createdFirstEvent); assert.equal(row.receivedMessages, 2);
  assert.ok(!JSON.stringify(row).includes('private-response-canary')); assert.ok(!JSON.stringify(row).includes('UpperKey'));
  row.rejectedEvent.type = 'private-response-canary'; row.rejectedEvent.keys.push('private-response-canary'); row.rejectedAt = 99;
  assert.deepEqual(f.adapter.inspect().calls[0].rejectedEvent, shape); assert.equal(f.adapter.inspect().calls[0].rejectedAt, 2);
});

const shapeCanary = 'synthetic-shape-canary';
for (const safety_buffering of [false, { use_cases: [shapeCanary], reasons: [shapeCanary], retry_model: shapeCanary }])
test(`rejected completed event describes ${typeof safety_buffering} safety buffering and JSON value shapes without content`, async () => {
  const received = packets(1, { output: [functionItem, message(1)], fallback: true }), ending = JSON.parse(received.at(-1));
  ending.response.output = [functionItem]; ending.response.note = shapeCanary;
  Object.assign(ending, { safety_buffering, text: shapeCanary, array: [shapeCanary], number: 8675309, flag: true, nothing: null, extra: { detail: shapeCanary } });
  received[received.length - 1] = Buffer.from(JSON.stringify(ending));
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, received); await rejected(promise);
  const row = f.adapter.inspect().calls[0], expected = {
    array: { type: 'array', size: 1 }, extra: { type: 'object', size: 1 }, flag: { type: 'boolean', size: null }, nothing: { type: 'null', size: null }, number: { type: 'number', size: null },
    response: { type: 'object', size: 7, output: { type: 'array', size: 1 }, statusType: 'string' },
    safety_buffering: safety_buffering === false ? { type: 'boolean', size: null } : { type: 'object', size: 3, keys: ['reasons', 'retry_model', 'use_cases'], otherKeys: 0 },
    sequence_number: { type: 'number', size: null }, text: { type: 'string', size: shapeCanary.length }, type: { type: 'string', size: 18 },
  };
  assert.equal(row.failureCode, 'output_identity'); assert.deepEqual(row.rejectedEvent.valueShapes, expected);
  assert.ok(!JSON.stringify(f.adapter.inspect()).includes(shapeCanary)); assert.ok(!JSON.stringify(f.adapter.inspect()).includes('8675309'));
  row.rejectedEvent.valueShapes.response.output.size = 99;
  if (safety_buffering !== false) row.rejectedEvent.valueShapes.safety_buffering.keys.push(shapeCanary);
  assert.deepEqual(f.adapter.inspect().calls[0].rejectedEvent.valueShapes, expected);
});

for (const [output, type, size] of [[undefined, 'absent', null], [null, 'null', null], [[], 'array', 0], [{}, 'object', 0],
  [shapeCanary, 'string', shapeCanary.length], [8675309, 'number', null], [false, 'boolean', null]])
test(`rejected response describes ${type} output without assuming an array`, async () => {
  const received = packets(), ending = JSON.parse(received[1]); ending.response.status = false; ending.response.output = output;
  received[1] = Buffer.from(JSON.stringify(ending));
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, received); await rejected(promise);
  const row = f.adapter.inspect().calls[0]; assert.equal(row.failureCode, 'response_status'); assert.equal(row.outputIdentityMismatch, null);
  assert.deepEqual(row.rejectedEvent.valueShapes.response, { type: 'object', size: output === undefined ? 5 : 6, output: { type, size }, statusType: 'boolean' });
  assert.ok(!JSON.stringify(f.adapter.inspect()).includes(shapeCanary)); assert.ok(!JSON.stringify(f.adapter.inspect()).includes('8675309'));
});

for (const [kind, output, index, terminalType] of [
  ['missing_index', [message(1)], 1, null],
  ['type', [functionItem, message(1), message(2)], 0, 'function_call'],
  ['id', [message(2)], 0, 'message'],
]) test(`20th completed event with safety buffering explains shifted terminal output: ${kind}`, async () => {
  const events = packets(1, { output: [message(1), message(2)], fallback: true }).map(bytes => JSON.parse(bytes)), ending = events.pop();
  for (let index = 0; index < 14; index++) events.push({ type: 'response.metadata', response_id: ending.response.id, metadata: { detail: shapeCanary } });
  ending.response.output = output; ending.safety_buffering = { use_cases: ['cyber'], reasons: ['user_risk'] }; events.push(ending);
  const received = events.map((event, sequence_number) => Buffer.from(JSON.stringify({ ...event, sequence_number }))), f = fake(), { promise } = f.begin();
  f.socket.open(); deliver(f.socket, received); await rejected(promise);
  const row = f.adapter.inspect().calls[0], expected = { streamedItemCount: 2, terminalOutputLength: output.length, index, kind, streamedType: 'message', terminalType };
  assert.equal(row.receivedMessages, 20); assert.equal(row.rejectedAt, 20); assert.equal(row.failureCode, 'output_identity'); assert.equal(row.terminalKind, 'completed');
  assert.deepEqual(row.outputIdentityMismatch, expected);
  assert.deepEqual(row.rejectedEvent, { ...createdFirstEvent, type: 'response.completed', keys: ['response', 'safety_buffering', 'sequence_number', 'type'], valueShapes: {
    response: { type: 'object', size: 6, output: { type: 'array', size: output.length }, statusType: 'string' },
    safety_buffering: { type: 'object', size: 2, keys: ['reasons', 'use_cases'], otherKeys: 0 }, sequence_number: { type: 'number', size: null }, type: { type: 'string', size: 18 },
  } });
  row.outputIdentityMismatch.kind = shapeCanary; assert.deepEqual(f.adapter.inspect().calls[0].outputIdentityMismatch, expected);
  for (const value of [shapeCanary, 'cyber', 'user_risk', 'message_1', 'message_2', 'synthetic complete']) assert.ok(!JSON.stringify(f.adapter.inspect()).includes(value));
});

for (const fields of [{ headers: { 'x-example': 'synthetic-metadata-canary' } }, { metadata: { etag: 'synthetic-metadata-canary' } }, { headers: {}, metadata: { etag: 'synthetic-metadata-canary' } }]) test(`transport accepts and discards out-of-band ${Object.keys(fields).join('/')} metadata`, async () => {
  const baseline = fake(), first = baseline.begin(); baseline.socket.open(); deliver(baseline.socket, packets());
  const expected = await first.promise; assert.deepEqual(baseline.adapter.close(first.c), { closed: true, quiescent: true });
  const metadata = Buffer.from(JSON.stringify({ type: 'codex.response.metadata', ...fields }));
  const received = packets(); received.splice(1, 0, metadata); received.unshift(metadata);
  const f = fake(), { promise, c } = f.begin(); f.socket.open(); deliver(f.socket, received);
  assert.deepEqual(await promise, expected); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, null); assert.equal(row.terminalKind, 'completed');
  assert.equal(row.receivedBytes, received.reduce((sum, bytes) => sum + bytes.length, 0)); assert.equal(row.receivedMessages, received.length);
  assert.deepEqual(row.firstEvent, { ...emptyFirstEvent, kind: 'object', type: 'codex.response.metadata', keys: [...Object.keys(fields), 'type'].sort() });
  assert.ok(!JSON.stringify(f.adapter.inspect()).includes('synthetic-metadata-canary'));
});

test('transport reconstructs empty terminal output from four completed streamed items', async () => {
  const output = [...richOutput, message(2)], original = packets(1, { output, fallback: true }), ending = JSON.parse(original.at(-1));
  ending.response.output = null; original[original.length - 1] = Buffer.from(JSON.stringify(ending));
  const baseline = fake(), first = baseline.begin(); baseline.socket.open(); deliver(baseline.socket, original);
  const expected = await first.promise; assert.deepEqual(baseline.adapter.close(first.c), { closed: true, quiescent: true });
  ending.response.output = [];
  const received = [...original.slice(0, -1), Buffer.from(JSON.stringify(ending))], f = fake(), { promise, c } = f.begin();
  f.socket.open(); deliver(f.socket, received);
  const result = await promise; assert.deepEqual(result, expected); assert.equal(result.status, 'completed'); assert.deepEqual(result.output, output);
  assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, null); assert.equal(row.outputIdentityMismatch, null); assert.equal(row.terminalKind, 'completed');
  assert.equal(row.rejectedEvent, null); assert.equal(row.rejectedAt, null);
});

for (const fallback of [false, true]) test(`transport accepts and discards WebSocket timing with ${fallback ? 'reconstructed' : 'terminal'} output`, async () => {
  const original = packets(1, { output: richOutput, fallback }), baseline = fake(), first = baseline.begin();
  baseline.socket.open(); deliver(baseline.socket, original);
  const expected = await first.promise; assert.deepEqual(baseline.adapter.close(first.c), { closed: true, quiescent: true });
  const timing = Buffer.from(JSON.stringify({ type: 'responsesapi.websocket_timing', timing_metrics: { latency_ms: 8675309 } }));
  const received = [...original.slice(0, -1), timing, original.at(-1)]; received.splice(1, 0, timing); received.unshift(timing);
  const f = fake(), { promise, c } = f.begin(); f.socket.open(); deliver(f.socket, received);
  assert.deepEqual(await promise, expected); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, null); assert.equal(row.terminalKind, 'completed');
  assert.equal(row.rejectedEvent, null); assert.equal(row.rejectedAt, null);
  assert.equal(row.receivedBytes, received.reduce((sum, bytes) => sum + bytes.length, 0)); assert.equal(row.receivedMessages, received.length);
  assert.deepEqual(row.firstEvent, { ...emptyFirstEvent, kind: 'object', type: 'responsesapi.websocket_timing', keys: ['timing_metrics', 'type'] });
  assert.ok(!JSON.stringify(f.adapter.inspect()).includes('8675309'));
});

test('transport accepts and discards in-stream metadata after output events', async () => {
  const original = packets(1, { output: richOutput, fallback: true }), baseline = fake(), first = baseline.begin();
  baseline.socket.open(); deliver(baseline.socket, original);
  const expected = await first.promise; assert.deepEqual(baseline.adapter.close(first.c), { closed: true, quiescent: true });
  const leading = Buffer.from(JSON.stringify({ type: 'codex.response.metadata', headers: {} }));
  const metadata = Buffer.from(JSON.stringify({ type: 'response.metadata', response_id: 'resp_fixture_1', sequence_number: original.length - 1, metadata: { etag: 'synthetic-in-stream-metadata-canary' } }));
  const ending = Buffer.from(JSON.stringify({ ...JSON.parse(original.at(-1)), sequence_number: original.length }));
  const received = [leading, ...original.slice(0, -1), metadata, ending], f = fake(), { promise, c } = f.begin();
  f.socket.open(); deliver(f.socket, received);
  assert.deepEqual(await promise, expected); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, null); assert.equal(row.terminalKind, 'completed');
  assert.equal(row.rejectedEvent, null); assert.equal(row.rejectedAt, null);
  assert.equal(row.receivedMessages, received.length); assert.equal(row.receivedBytes, received.reduce((sum, bytes) => sum + bytes.length, 0));
  assert.ok(!JSON.stringify(f.adapter.inspect()).includes('synthetic-in-stream-metadata-canary'));
});

test('first WebSocket message is recorded after the deadline before the timer fires', async t => {
  let clock = 0;
  t.mock.method(performance, 'now', () => clock);
  const f = fake(), { promise } = f.begin(); f.socket.open();
  clock = defaults.timeoutMs + 1;
  deliver(f.socket, [Buffer.from(JSON.stringify({ type: 'codex.rate_limits', rate_limits: {} }))]);
  await assert.rejects(promise, { message: 'transport_deadline' });
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, 'transport_deadline'); assert.deepEqual(row.firstEvent, rateLimitFirstEvent);
  assert.equal(row.rejectedEvent, null); assert.equal(row.rejectedAt, null);
  assert.equal(row.receivedMessages, 0); assert.equal(row.receivedBytes, 0); assert.equal(row.terminalKind, 'none');
});

for (const [mode, failureCode] of [['abort', 'transport_canceled'], ['close', 'transport_closed_early'], ['socket-error', 'socket_error']]) test(`first WebSocket message is recorded after ${mode} before socket closure`, async () => {
  const controller = new AbortController(), f = fake(), { c, promise } = f.begin(context(1, { signal: controller.signal }));
  f.socket.open();
  if (mode === 'abort') controller.abort();
  else if (mode === 'close') f.adapter.close(c);
  else f.socket.emit('error', new Error('synthetic socket error'));
  deliver(f.socket, [rateLimitMessage]); await rejected(promise);
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, failureCode); assert.deepEqual(row.firstEvent, rateLimitFirstEvent);
  assert.equal(row.receivedMessages, 0); assert.equal(row.receivedBytes, 0); assert.equal(row.terminalKind, 'none');
});

test('first WebSocket message records a rejected rate-limit event without accepting it', async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [rateLimitMessage, ...packets()]); await rejected(promise);
  const row = f.adapter.inspect().calls[0];
  assert.equal(row.failureCode, 'sequence_mismatch'); assert.equal(row.terminalKind, 'none');
  assert.deepEqual(row.firstEvent, rateLimitFirstEvent);
  assert.equal(row.rejectedAt, 1); assert.deepEqual(row.rejectedEvent, rateLimitRejectedEvent);
  assert.ok(!JSON.stringify(row).includes('private-response-canary')); assert.ok(!JSON.stringify(row).includes('8675309'));
});

test('first WebSocket message excludes unallowlisted type and key names and all payload values', async () => {
  const bytes = Buffer.from(JSON.stringify({ type: 'private-response-canary', rate_limits: { detail: 'private-response-canary' },
    sequence_number: 'private-response-canary', sequence: 8675309.5, stream_id: 'private-response-canary', UpperKey: 'private-response-canary', ['x'.repeat(50)]: 'private-response-canary' }));
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [bytes]); await rejected(promise);
  const row = f.adapter.inspect().calls[0]; assert.equal(row.failureCode, 'sequence_mismatch');
  assert.deepEqual(row.firstEvent, { kind: 'object', type: 'other', keys: ['rate_limits', 'sequence', 'sequence_number', 'stream_id', 'type'],
    otherKeys: 2, sequenceNumber: 'string', sequence: 'number', streamId: 'present' });
  assert.equal(row.rejectedAt, 1); assert.deepEqual(row.rejectedEvent, { ...row.firstEvent, valueShapes: {
    rate_limits: { type: 'object', size: 1 }, sequence: { type: 'number', size: null }, sequence_number: { type: 'string', size: 23 },
    stream_id: { type: 'string', size: 23 }, type: { type: 'string', size: 23 },
  } });
  for (const value of ['private-response-canary', 'UpperKey', 'x'.repeat(50), '8675309']) assert.ok(!JSON.stringify(row).includes(value));
});

test('first WebSocket message sorts and caps keys and counts rejected and excess names', async () => {
  const payload = { type: 'a'.repeat(64), ['b'.repeat(41)]: 'private-response-canary', UpperKey: 'private-response-canary',
    ...Object.fromEntries(Array.from({ length: 18 }, (_, index) => [`key${String(17 - index).padStart(2, '0')}`, 'private-response-canary'])), ['a'.repeat(40)]: 'private-response-canary' };
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [Buffer.from(JSON.stringify(payload))]); await rejected(promise);
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, { ...emptyFirstEvent, kind: 'object', type: 'a'.repeat(64),
    keys: ['a'.repeat(40), ...Array.from({ length: 15 }, (_, index) => `key${String(index).padStart(2, '0')}`)], otherKeys: 6 });
  const row = f.adapter.inspect().calls[0];
  assert.deepEqual(Object.keys(row.rejectedEvent.valueShapes), row.firstEvent.keys);
  assert.equal(Object.keys(row.rejectedEvent.valueShapes).length, 16);
  assert.ok(Object.values(row.rejectedEvent.valueShapes).every(value => value.type === 'string' && value.size === 23));
  assert.ok(!JSON.stringify(row).includes('private-response-canary'));
});

test('rejected safety buffering object sorts and caps key names without their values', async () => {
  const safety_buffering = { ...Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`key${String(19 - index).padStart(2, '0')}`, shapeCanary])),
    UpperKey: shapeCanary, ['x'.repeat(41)]: shapeCanary };
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [packets()[0], Buffer.from(JSON.stringify({ type: 'response.something_new', sequence_number: 1, safety_buffering }))]);
  await rejected(promise);
  const row = f.adapter.inspect().calls[0];
  assert.deepEqual(row.rejectedEvent.valueShapes.safety_buffering, { type: 'object', size: 22, keys: Array.from({ length: 16 }, (_, index) => `key${String(index).padStart(2, '0')}`), otherKeys: 6 });
  for (const value of [shapeCanary, 'UpperKey', 'x'.repeat(41)]) assert.ok(!JSON.stringify(f.adapter.inspect()).includes(value));
});

for (const [value, classification] of [[42, 'integer'], [-1, 'integer'], [1.5, 'number'], ['private-response-canary', 'string'],
  [null, 'object'], [true, 'boolean'], [{ detail: 'private-response-canary' }, 'object'], [[], 'object']]) test(`first WebSocket message classifies sequence fields as ${classification}: ${JSON.stringify(value)}`, async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open();
  deliver(f.socket, [Buffer.from(JSON.stringify({ sequence_number: value, sequence: value, stream_id: null }))]); await rejected(promise);
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, { kind: 'object', type: 'absent', keys: ['sequence', 'sequence_number', 'stream_id'],
    otherKeys: 0, sequenceNumber: classification, sequence: classification, streamId: 'null' });
});

for (const type of [null, 42, true, {}, [], '', 'A.event', 'a'.repeat(65), 'event\n']) test(`first WebSocket message classifies invalid type ${JSON.stringify(type)} as other`, async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [Buffer.from(JSON.stringify({ type }))]); await rejected(promise);
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, { ...emptyFirstEvent, kind: 'object', type: 'other', keys: ['type'] });
});

for (const value of [null, [], ['private-response-canary'], 'private-response-canary', 8675309, true]) test(`first WebSocket message records non-object JSON: ${JSON.stringify(value)}`, async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [Buffer.from(JSON.stringify(value))]); await rejected(promise);
  assert.equal(f.adapter.inspect().calls[0].failureCode, 'sequence_mismatch');
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, { ...emptyFirstEvent, kind: 'non_object' });
});

for (const [name, bytes] of [['JSON', Buffer.from('{"private-response-canary":')], ['UTF-8', Buffer.from([255])]]) test(`first WebSocket message records invalid ${name} without content`, async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open(); deliver(f.socket, [bytes]); await rejected(promise);
  assert.equal(f.adapter.inspect().calls[0].failureCode, 'invalid_event_bytes');
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, { ...emptyFirstEvent, kind: 'invalid_json' });
});

test('first WebSocket message is null until receipt and stays fixed after later messages and inspection', async () => {
  const f = fake(), { promise } = f.begin(); assert.equal(f.adapter.inspect().calls[0].firstEvent, null);
  assert.equal(f.adapter.inspect().calls[0].rejectedEvent, null); assert.equal(f.adapter.inspect().calls[0].rejectedAt, null);
  f.socket.open(); const received = packets(); deliver(f.socket, [received[0]]);
  const snapshot = f.adapter.inspect(); assert.deepEqual(snapshot.calls[0].firstEvent, createdFirstEvent);
  snapshot.calls[0].firstEvent.type = 'private-response-canary'; snapshot.calls[0].firstEvent.keys.push('private-response-canary');
  deliver(f.socket, [received[1]]); assert.equal((await promise).status, 'completed');
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, createdFirstEvent);
  assert.equal(f.adapter.inspect().calls[0].rejectedEvent, null); assert.equal(f.adapter.inspect().calls[0].rejectedAt, null);
});

test('first WebSocket message is still recorded when binary transport validation rejects it', async () => {
  const f = fake(), { promise } = f.begin(); f.socket.open(); f.socket.emit('message', rateLimitMessage, true); await rejected(promise);
  assert.equal(f.adapter.inspect().calls[0].failureCode, 'transport_protocol');
  assert.deepEqual(f.adapter.inspect().calls[0].firstEvent, rateLimitFirstEvent);
  assert.equal(f.adapter.inspect().calls[0].rejectedEvent, null); assert.equal(f.adapter.inspect().calls[0].rejectedAt, null);
});

async function saveTransportExecution(mode, received, maxResponseBytes) {
  const workspace = path.join(root, randomUUID()); await fs.mkdir(workspace);
  const config = { ...structuredClone(configDefaults), ai: { assetsRoot: path.join(root, 'assets'), credentialStore: path.join(root, 'credentials'),
    reasoningEffort: 'high', commandTimeoutMs: 10000, cleanupTimeoutMs: 10000,
    workerResources: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 33554432, workBytes: 16777216, shmBytes: 4194304 },
    limits: { maxRequests: 3, maxTotalOutputTokens: 12, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 8192, maxResponseBytesPerRequest: maxResponseBytes,
      maxToolCalls: 2, maxToolResultBytes: 1024, timeoutMs: 5000 }, ipc: { maxBytes: 1048576 } } };
  const plan = { root: process.cwd(), commit: 'b'.repeat(40), snapshotHash: identity.snapshotHash, files: [], ai: { source: { manifestSha256: 'c'.repeat(64) } } };
  const manifest = Array.from({ length: 10805 }, (_, index) => ({ path: `asset-${index}`, bytes: 0, sha256: 'a'.repeat(64) }));
  const adapterUrl = new URL(`../src/ai-runner.mjs?transport-${randomUUID()}`, import.meta.url).href;
  const stub = (file, source) => `export * from ${JSON.stringify(new URL(file, import.meta.url).href)}; ${source}`;
  const modules = new Map([
    ['./ai-plan.ts', stub('../src/ai-plan.ts', `export const verifyAiPlan = () => {}; export const aiRuntime = ${JSON.stringify({ ...aiRuntime, assetManifestSha256: digest(manifest) })};`)],
    ['./ai-files.mjs', stub('../src/ai-files.mjs', `export const canonicalAiPath = async value => value; export const inventoryAiDirectory = async (directory, control, options) => options.order === 'sdk-assets' ? Array.from({ length: 10805 }, (_, index) => ({ path: 'asset-' + index, bytes: 0, sha256: 'a'.repeat(64) })) : [];`)],
    ['./repository.ts', stub('../src/repository.ts', 'export const verifySnapshot = async () => true;')],
    ['./siwc-credentials.mjs', stub('../src/siwc-credentials.mjs', `export const readSiwcCredentials = async () => ({ accessToken: ${JSON.stringify(token)}, expiresAt: Date.now() + 60000 });`)],
    ['./ai-observations.mjs', stub('../src/ai-observations.mjs', 'export const readHostTerminals = async ({ usage }) => ({ tokens: usage.tokens, programs: [], models: [] });')],
    ['../internal/projected-repository.mjs', stub('../internal/projected-repository.mjs', `export const projectRepository = async () => (${JSON.stringify({ status: 'completed', repository: path.join(root, 'projection'), mapping: { derivedRevision: 'f'.repeat(40) }, scope: { paths: [] } })});`)],
    ['../internal/hosted-bridge.mjs', `import { createHash } from 'node:crypto'; import { mkdir } from 'node:fs/promises'; import { runAiSession } from ${JSON.stringify(new URL('../internal/ai-session.mjs', import.meta.url).href)};
      export async function runHostedBridge(options) {
        const check = async bytes => ({ bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
        await mkdir(options.directory + '/ai');
        const session = await runAiSession({ directory: options.directory + '/ai', targetRoots: [${JSON.stringify(process.cwd())}],
          identity: { ...options.binding.identity, requestId: 'request', scanId: 'scan', snapshotHash: options.binding.snapshotHash }, limits: options.limits,
          toolNames: ['read'], checkRequest: check, checkOutput: check, submit: options.submit, close: options.closeTransport,
          prepare: async c => Buffer.from(JSON.stringify({ type: 'response.create', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, store: false,
            input: [{ role: 'user', content: 'private-prompt-canary' }], tools: [{ type: 'function', name: 'read', parameters: {} }], max_output_tokens: c.outputCap })), executeAllowedTool: async () => Buffer.from('fixed tool result') });
        return { status: 'failed', reason: 'worker_sdk_finalization_failed', artifactsAccepted: false, providerSubmitInvocations: session.submitInvocations,
          usage: { complete: session.usageComplete, requests: session.observedUsage, observed: session.usage }, scanId: 'scan', execution: { requestId: 'request' },
          cleanup: { closed: true, quiescent: session.reason !== 'close_unverified', containerAbsent: true } };
      }`],
  ]);
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (context.parentURL === adapterUrl && modules.has(specifier)) return { url: 'data:text/javascript,' + encodeURIComponent(modules.get(specifier)), shortCircuit: true };
    return nextResolve(specifier, context);
  } });
  let createAiAdapter;
  try { ({ createAiAdapter } = await import(adapterUrl)); } finally { hooks.deregister(); }
  const streams = Array.isArray(received[0]) ? received : [received]; let connections = 0;
  const runtime = { createSocket() { const socket = new FakeSocket(), stream = streams[connections++]; queueMicrotask(() => {
    socket.open(); deliver(socket, stream);
    if (mode === 'early-eof') socket.emit('close', 1000);
    if (mode === 'socket-error') socket.emit('error', new Error('private-socket-canary'));
    if (mode === 'native-message-cap') socket.emit('error', Object.assign(new Error('private-socket-canary'), { code: 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' }));
  }); return socket; } };
  const run = await createAiAdapter({ acceptedPlanHash: 'd'.repeat(64), expiresAt: performance.now() + 10000, runtime }).run({ plan, config, workspace, snapshot: '',
    signal: new AbortController().signal, secretScan: { execution: 'completed', coverage: 'analyzed', findings: [], errors: [] } });
  const destination = path.join(workspace, 'saved-ai.json'); await fs.writeFile(destination, JSON.stringify(run));
  const saved = JSON.parse(await fs.readFile(destination, 'utf8'));
  assert.equal(saved.aiExecution.reason, 'worker_sdk_finalization_failed'); assert.equal(saved.execution, 'failed'); assert.equal(saved.aiExecution.artifactsAccepted, false);
  for (const value of [token, 'private-response-canary', 'private-prompt-canary', 'private-socket-canary', 'synthetic-error-canary', 'resp_fixture_1', 'synthetic complete']) assert.ok(!JSON.stringify(saved).includes(value));
  return saved.aiExecution;
}

const diagnosticPackets = packets();
const completedRejectedEvent = { ...createdFirstEvent, type: 'response.completed', valueShapes: {
  response: { type: 'object', size: 6, output: { type: 'array', size: 1 }, statusType: 'string' }, sequence_number: { type: 'number', size: null }, type: { type: 'string', size: 18 },
} };
const unknownPacket = type => Buffer.from(JSON.stringify({ sequence_number: 1, type, text: 'private-response-canary' }));
const unknownEventShape = (type, size = type.length) => ({ ...emptyFirstEvent, kind: 'object', type, keys: ['sequence_number', 'text', 'type'], sequenceNumber: 'integer', valueShapes: {
  sequence_number: { type: 'number', size: null }, text: { type: 'string', size: 23 }, type: { type: 'string', size },
} });
for (const [mode, received, cap, failureCode, terminalKind, closeCode, firstEvent = createdFirstEvent, rejectedEvent = null, rejectedAt = null] of [
  ['cumulative-cap', diagnosticPackets, Math.max(...diagnosticPackets.map(b => b.length)), 'response_limit', 'none', 1006, createdFirstEvent, completedRejectedEvent, 2],
  ['single-message-cap', [Buffer.alloc(257, 120)], 256, 'message_too_large', 'none', 1006, { ...emptyFirstEvent, kind: 'invalid_json' }, { ...emptyFirstEvent, kind: 'invalid_json', valueShapes: {} }, 1],
  ['unknown-event', [diagnosticPackets[0], unknownPacket('response.something_new')], defaults.maxResponseBytes, 'unexpected_event', 'none', 1006, createdFirstEvent, unknownEventShape('response.something_new'), 2],
  ['private-event-name', [diagnosticPackets[0], unknownPacket('private-response-canary')], defaults.maxResponseBytes, 'unexpected_event', 'none', 1006, createdFirstEvent, unknownEventShape('other', 23), 2],
  ['sequence-mismatch', [diagnosticPackets[0], Buffer.from(JSON.stringify({ ...JSON.parse(diagnosticPackets[1]), sequence_number: 0 }))], defaults.maxResponseBytes, 'sequence_mismatch', 'completed', 1006, createdFirstEvent, completedRejectedEvent, 2],
  ['early-eof', [diagnosticPackets[0]], defaults.maxResponseBytes, 'early_eof', 'none', 1000],
  ['socket-error', [diagnosticPackets[0]], defaults.maxResponseBytes, 'socket_error', 'none', 1006],
  ['native-message-cap', [], defaults.maxResponseBytes, 'message_too_large', 'none', 1006, null],
  ['incomplete', packets(1, { status: 'incomplete' }), defaults.maxResponseBytes, null, 'incomplete', 1000],
  ['failed', packets(1, { status: 'failed' }), defaults.maxResponseBytes, null, 'failed', 1000],
  ['terminal-error', [diagnosticPackets[0], Buffer.from(JSON.stringify({ type: 'error', sequence_number: 1, code: null, message: 'private-response-canary', param: null }))], defaults.maxResponseBytes, null, 'failed', 1000],
  ['completed', diagnosticPackets, defaults.maxResponseBytes, null, 'completed', 1000],
]) test(`saved AI transport diagnostics: ${mode}`, async () => {
  const saved = await saveTransportExecution(mode, received, cap);
  assert.deepEqual(saved.transportRequests, [{ sequence: 1, receivedBytes: received.reduce((sum, b) => sum + b.length, 0), receivedMessages: received.length,
    terminal: terminalKind !== 'none', terminalKind, closeCode, sendOk: true, failureCode, firstEvent, rejectedEvent, rejectedAt }]);
  assert.equal(Object.hasOwn(saved.transportRequests[0], 'outputIdentityMismatch'), false);
  assert.equal(saved.connectionAttempts, 1); assert.equal(saved.sendInvocations, 1); assert.equal(saved.submitInvocations, 1);
});

const errorCanary = 'synthetic-error-canary';
for (const [name, code, expected] of [['policy', 'cyber_policy', 'cyber_policy'], ['quota', 'insufficient_quota', 'insufficient_quota'],
  ['rate limit', 'rate_limit_exceeded', 'rate_limit_exceeded'], ['unknown', errorCanary, 'other'], ['empty', '', 'other'], ['null', null, undefined]])
for (const shape of ['flat', 'nested', 'response.failed']) test(`${shape} ${name} error keeps only the fixed code in transport and saved records`, async () => {
  const error = { code, message: errorCanary, param: errorCanary, type: errorCanary }, ending = shape === 'response.failed' ? JSON.parse(packets(1, { status: 'failed' })[1]) :
    { type: 'error', sequence_number: 1, ...(shape === 'nested' ? { error } : { code, message: errorCanary, param: errorCanary }) };
  if (shape === 'response.failed') ending.response.error = error;
  const received = [packets()[0], Buffer.from(JSON.stringify(ending))], f = fake(), { promise, c } = f.begin();
  f.socket.open(); deliver(f.socket, received); assert.equal((await promise).status, shape === 'response.failed' ? 'failed' : 'error');
  assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  const observed = f.adapter.inspect(), row = observed.calls[0];
  assert.equal(row.terminalKind, 'failed'); assert.equal(row.failureCode, null); assert.equal(row.providerErrorCode, expected);
  assert.equal(Object.hasOwn(row, 'providerErrorCode'), expected !== undefined); assert.ok(!JSON.stringify(observed).includes(errorCanary));
  const saved = await saveTransportExecution('provider-error', received, defaults.maxResponseBytes);
  assert.deepEqual(saved.transportRequests, [{ sequence: 1, receivedBytes: received.reduce((sum, b) => sum + b.length, 0), receivedMessages: 2,
    terminal: true, terminalKind: 'failed', closeCode: 1000, sendOk: true, failureCode: null, firstEvent: createdFirstEvent, rejectedEvent: null, rejectedAt: null,
    ...(expected === undefined ? {} : { providerErrorCode: expected }) }]);
  assert.equal(saved.connectionAttempts, 1); assert.equal(saved.sendInvocations, 1); assert.equal(saved.submitInvocations, 1);
});

for (const [name, error] of [['non-object', errorCanary], ['invalid message', { code: errorCanary, message: {}, param: errorCanary, type: errorCanary }],
  ['unknown key', { code: errorCanary, message: errorCanary, param: errorCanary, type: errorCanary, detail: errorCanary }]])
test(`malformed nested ${name} error keeps the failure code and discards values in transport and saved records`, async () => {
  const received = [packets()[0], Buffer.from(JSON.stringify({ type: 'error', sequence_number: 1, error }))], f = fake(), { promise } = f.begin();
  f.socket.open(); deliver(f.socket, received); await rejected(promise);
  const observed = f.adapter.inspect(); assert.equal(observed.calls[0].terminalKind, 'failed'); assert.equal(observed.calls[0].failureCode, 'error_event');
  assert.equal(observed.calls[0].rejectedAt, 2); assert.ok(!JSON.stringify(observed).includes(errorCanary));
  const saved = await saveTransportExecution('malformed-provider-error', received, defaults.maxResponseBytes);
  assert.equal(saved.transportRequests[0].terminalKind, 'failed'); assert.equal(saved.transportRequests[0].failureCode, 'error_event');
  assert.equal(saved.transportRequests[0].rejectedAt, 2); assert.ok(!JSON.stringify(saved).includes(errorCanary));
});

test('saved AI transport diagnostics preserve output identity mismatch detail', async () => {
  const received = packets(1, { output: [message(1), message(2)], fallback: true }), ending = JSON.parse(received.at(-1));
  ending.response.output = [message(1)]; received[received.length - 1] = Buffer.from(JSON.stringify(ending));
  const saved = await saveTransportExecution('output-identity-mismatch', received, defaults.maxResponseBytes);
  assert.equal(saved.transportRequests[0].failureCode, 'output_identity');
  assert.deepEqual(saved.transportRequests[0].outputIdentityMismatch, {
    streamedItemCount: 2, terminalOutputLength: 1, index: 1, kind: 'missing_index', streamedType: 'message', terminalType: null,
  });
});

test('saved first WebSocket message shape survives the AI runner report on rejection', async () => {
  const saved = await saveTransportExecution('rate-limits', [rateLimitMessage], defaults.maxResponseBytes);
  assert.equal(saved.transportRequests[0].failureCode, 'sequence_mismatch');
  assert.deepEqual(saved.transportRequests[0].firstEvent, rateLimitFirstEvent);
  assert.deepEqual(saved.transportRequests[0].rejectedEvent, rateLimitRejectedEvent); assert.equal(saved.transportRequests[0].rejectedAt, 1);
});

test('saved AI transport diagnostics keep separate observations for every request', async () => {
  const streams = [packets(1, { output: [functionItem] }), packets(2, { status: 'incomplete' })];
  const saved = await saveTransportExecution('two-requests', streams, defaults.maxResponseBytes);
  assert.deepEqual(saved.transportRequests, streams.map((received, index) => ({ sequence: index + 1, receivedBytes: received.reduce((sum, b) => sum + b.length, 0),
    receivedMessages: received.length, terminal: true, terminalKind: index === 0 ? 'completed' : 'incomplete', closeCode: 1000, sendOk: true, failureCode: null, firstEvent: createdFirstEvent, rejectedEvent: null, rejectedAt: null })));
  assert.equal(saved.submitInvocations, 2); assert.equal(saved.connectionAttempts, 2); assert.equal(saved.sendInvocations, 2);
});

for (const [name, change] of [
  ['zero request bound', { maxRequests: 0 }], ['fractional byte bound', { maxRequestBytes: 1.5 }], ['disabled payload overflow', { maxResponseBytes: 2 ** 31 }], ['timer overflow', { timeoutMs: 2 ** 31 }], ['event bound', { maxEvents: 0 }], ['empty bearer', { bearerToken: '' }], ['header injection', { bearerToken: 'fixture\r\nother' }], ['token whitespace', { bearerToken: 'fixture token' }], ['unknown option', { endpoint: 'ws://127.0.0.1' }], ['nonfunction seam', { createSocket: 1 }],
]) test(`factory refuses ${name} before creating any socket`, () => assert.throws(() => createResponsesTransport({ ...defaults, ...change }), /invalid_transport_options/));

test('fixed endpoint/options and exact copied bytes use one text send', async () => {
  const f = fake(), c = context(), original = body(c), expected = Buffer.from(original), { promise } = f.begin(c, original); original.fill(0);
  f.socket.open(); deliver(f.socket, packets()); const receipt = await promise;
  assert.equal(receipt.status, 'completed'); assert.deepEqual(f.socket.sends, [{ bytes: expected, options: { binary: false, compress: false } }]);
  const [{ url, settings }] = f.constructions; assert.equal(url, 'wss://api.openai.com/v1/responses');
  assert.deepEqual(Object.keys(settings).sort(), ['headers', 'followRedirects', 'perMessageDeflate', 'rejectUnauthorized', 'skipUTF8Validation', 'maxPayload', 'handshakeTimeout', 'closeTimeout'].sort());
  assert.deepEqual(settings.headers, { authorization: `Bearer ${token}` });
  assert.equal(settings.followRedirects, false); assert.equal(settings.perMessageDeflate, false); assert.equal(settings.rejectUnauthorized, true); assert.equal(settings.skipUTF8Validation, false); assert.equal(settings.maxPayload, defaults.maxResponseBytes);
  assert.ok(settings.handshakeTimeout > 0 && settings.handshakeTimeout <= defaults.timeoutMs); assert.equal(settings.closeTimeout, settings.handshakeTimeout);
  assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true }); assert.deepEqual(f.adapter.close(c), { closed: false, quiescent: false });
  const snapshot = f.adapter.inspect(); assert.equal(snapshot.connectionAttempts, 1); assert.equal(snapshot.sendInvocations, 1); assert.equal(snapshot.calls[0].requestSha256, hash(expected));
  snapshot.calls[0].quiescent = false; assert.equal(f.adapter.inspect().calls[0].quiescent, true); assert.equal(JSON.stringify(snapshot).includes(token), false);
});

for (const [name, change] of [
  ['mutable context', c => ({ ...c })], ['mutable identity', c => Object.freeze({ ...c, identity: { ...identity } })], ['invalid id', c => Object.freeze({ ...c, callId: '../bad' })], ['invalid signal', c => Object.freeze({ ...c, signal: {} })], ['sequence jump', c => Object.freeze({ ...c, sequence: 2 })],
]) test(`admission rejects ${name} without connection`, async () => { const f = fake(); await rejected(f.adapter.submit(body(context()), change(context()))); assert.equal(f.constructions.length, 0); });

for (const [name, change] of [
  ['empty bytes', () => Buffer.alloc(0)], ['nonbytes', () => '{}'], ['invalid utf8', () => Buffer.from([255])], ['invalid json', () => Buffer.from('{')], ['wrong type', c => Buffer.from(JSON.stringify({ ...JSON.parse(body(c)), type: 'response.cancel' }))], ['wrong model', c => Buffer.from(JSON.stringify({ ...JSON.parse(body(c)), model: 'other' }))], ['stored request', c => Buffer.from(JSON.stringify({ ...JSON.parse(body(c)), store: true }))], ['standard request', c => Buffer.from(JSON.stringify({ ...JSON.parse(body(c)), access_programs: { cyber: 'standard' } }))], ['wrong cap', c => Buffer.from(JSON.stringify({ ...JSON.parse(body(c)), max_output_tokens: 6 }))], ['oversize request', () => Buffer.alloc(defaults.maxRequestBytes + 1)],
]) test(`invalid ${name} has no effects and a known empty resource set`, async () => { const f = fake(), c = context(); await rejected(f.adapter.submit(change(c), c)); assert.equal(f.constructions.length, 0); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true }); });

test('preabort has no connection; constructor throw remains closure-unverified and sanitized', async () => {
  const controller = new AbortController(); controller.abort(); const f = fake(), c = context(1, { signal: controller.signal }); await rejected(f.adapter.submit(body(c), c)); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true }); assert.equal(f.constructions.length, 0);
  const a = createResponsesTransport({ ...defaults, createSocket: () => { throw new Error(token); } }), d = context(); await rejected(a.submit(body(d), d)); assert.equal(a.inspect().connectionAttempts, 1); assert.deepEqual(a.close(d), { closed: false, quiescent: false }); assert.equal(JSON.stringify(a.inspect()).includes(token), false); await rejected(a.submit(body(context(2)), context(2))); assert.equal(a.inspect().connectionAttempts, 1);
});

test('duplicate, concurrent and foreign close contexts cannot dispatch or close another call', async () => {
  const f = fake(), { c, promise } = f.begin(); await rejected(f.adapter.submit(body(c), c)); await rejected(f.adapter.submit(body(context(2)), context(2))); assert.deepEqual(f.adapter.close(Object.freeze({ ...c })), { closed: false, quiescent: false }); assert.equal(f.socket.terminations, 0);
  f.socket.open(); deliver(f.socket, packets()); await promise;
  await rejected(f.adapter.submit(body(context(2)), context(2))); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: true });
  await rejected(f.adapter.submit(body(context(2)), context(2, { sessionId: 'foreign' }))); assert.equal(f.constructions.length, 1);
});

test('send callback must succeed before close; late success never promotes evidence', async () => {
  const f = fake({}, { autoAck: false }), { c, promise } = f.begin(); f.socket.open(); deliver(f.socket, packets()); const receipt = await promise; assert.equal(receipt.usage.totalTokens, 5);
  assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: false }); f.socket.callback(); assert.equal(f.adapter.inspect().calls[0].quiescent, false);
});

test('normal closure permits one next sequence and enforces the request limit', async () => {
  const sockets = [], a = createResponsesTransport({ ...defaults, maxRequests: 2, createSocket: () => { const socket = new FakeSocket(); sockets.push(socket); return socket; } });
  for (let n = 1; n <= 2; n++) { const c = context(n), promise = a.submit(body(c), c); sockets[n-1].open(); deliver(sockets[n-1], packets(n)); await promise; assert.deepEqual(a.close(c), { closed: true, quiescent: true }); }
  await rejected(a.submit(body(context(3)), context(3))); assert.equal(a.inspect().connectionAttempts, 2); assert.equal(a.inspect().sendInvocations, 2);
});

test('duplicate open, duplicate send callback and thrown send never send twice', async () => {
  for (const mode of ['open', 'callback', 'throw', 'unverified-upgrade']) {
    const f = fake({}, { autoAck: mode !== 'callback' });
    if (mode === 'throw') f.socket.send = () => { throw new Error(token); };
    const { c, promise } = f.begin();
    if (mode === 'unverified-upgrade') f.socket.emit('open');
    else { f.socket.open(); if (mode === 'open') f.socket.emit('open'); if (mode === 'callback') { f.socket.callback(); f.socket.callback(); } }
    await rejected(promise); assert.equal(f.adapter.inspect().sendInvocations, mode === 'unverified-upgrade' ? 0 : 1); assert.equal(f.adapter.close(c).quiescent, mode === 'unverified-upgrade');
  }
});

test('send failure is not retried; a valid terminal on abnormal close preserves usage only', async () => {
  const f = fake({}, { closeCode: 1006 }), { c, promise } = f.begin(); f.socket.open(); deliver(f.socket, packets()); assert.equal((await promise).usage.totalTokens, 5); assert.deepEqual(f.adapter.close(c), { closed: true, quiescent: false }); await rejected(f.adapter.submit(body(context(2)), context(2))); assert.equal(f.socket.sends.length, 1);
  const g = fake({}, { autoAck: false }), start = g.begin(); g.socket.open(); g.socket.callback(new Error(token)); await rejected(start.promise); assert.equal(g.adapter.inspect().sendInvocations, 1); assert.equal(g.socket.terminations, 1);
});

test('all packets before close are checked; a terminal followed by another terminal fails', async () => {
  const f = fake(), { c, promise } = f.begin(); f.socket.open(); const bytes = packets(); deliver(f.socket, [...bytes, bytes[1]]); await rejected(promise); assert.equal(f.adapter.close(c).quiescent, false); assert.equal(f.socket.sends.length, 1);
});

test('monotonic deadline catches a blocked constructor before open can send', async () => {
  const socket = new FakeSocket(), a = createResponsesTransport({ ...defaults, timeoutMs: 10, createSocket: () => { const until = performance.now() + 30; while (performance.now() < until) {} return socket; } }), c = context(); const promise = a.submit(body(c), c); promise.catch(() => {}); socket.open(); await rejected(promise); assert.equal(socket.sends.length, 0); assert.equal(a.inspect().connectionAttempts, 1); assert.equal(a.close(c).quiescent, false);
});

test('abort/deadline/early close do not await an uncooperative socket or allow late send', async () => {
  for (const mode of ['abort', 'deadline', 'close']) {
    const controller = new AbortController(), f = fake({ timeoutMs: 25 }, { neverClose: true }), { c, promise } = f.begin(context(1, { signal: controller.signal }));
    if (mode === 'abort') controller.abort(); if (mode === 'close') assert.deepEqual(f.adapter.close(c), { closed: false, quiescent: false });
    await rejected(promise); f.socket.open(); deliver(f.socket, packets()); f.socket.emit('close', 1000); assert.equal(f.adapter.inspect().sendInvocations, 0); assert.equal(f.adapter.inspect().calls[0].quiescent, false); assert.equal(f.adapter.inspect().calls[0].closed, true); await rejected(f.adapter.submit(body(context(2)), context(2))); assert.equal(f.constructions.length, 1);
  }
});

async function loopback(t, onRequest, status = null) {
  const peers = new Set(), clients = new Set(), tcp = new Set(), counts = { upgrades: 0, requests: 0, ordinaryHttp: 0, requestHashes: [], binary: [], activePeers: 0, activeClients: 0, destroyedTcp: false, clientsBeforeCleanup: null };
  const server = createServer((request, response) => { counts.ordinaryHttp++; response.writeHead(400).end(); });
  const wss = new WebSocketServer({ noServer: true });
  server.on('connection', socket => { tcp.add(socket); socket.on('close', () => tcp.delete(socket)); });
  server.on('upgrade', (request, socket, head) => {
    counts.upgrades++; assert.equal(request.headers.authorization, `Bearer ${token}`);
    if (status) { socket.end(`HTTP/1.1 ${status} Synthetic\r\n${status === 302 ? 'Location: /redirected\r\n' : ''}Content-Length: 0\r\nConnection: close\r\n\r\n`); return; }
    wss.handleUpgrade(request, socket, head, ws => wss.emit('connection', ws, socket));
  });
  wss.on('connection', (ws, rawSocket) => { peers.add(ws); counts.activePeers = peers.size; ws.on('error', () => {}); ws.on('close', () => { peers.delete(ws); counts.activePeers = peers.size; }); ws.on('message', (data, binary) => { counts.requests++; counts.requestHashes.push(hash(data)); counts.binary.push(binary); onRequest(ws, Buffer.from(data), counts.requests, rawSocket); }); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  let cleaned = false;
  const cleanup = async () => {
    if (cleaned) return; cleaned = true; counts.clientsBeforeCleanup = clients.size;
    const clientEnds = [...clients].map(ws => new Promise(resolve => ws.once('close', resolve))), tcpEnds = [...tcp].map(socket => new Promise(resolve => socket.once('close', resolve)));
    const serverEnd = new Promise(resolve => server.close(resolve));
    for (const ws of clients) ws.terminate(); for (const ws of peers) ws.terminate(); for (const socket of tcp) socket.destroy();
    await Promise.all([serverEnd, new Promise(resolve => wss.close(resolve)), ...clientEnds, ...tcpEnds]);
    counts.destroyedTcp = tcp.size === 0; assert.equal(counts.destroyedTcp, true); assert.equal(counts.activePeers, 0); assert.equal(counts.activeClients, 0);
  };
  t.after(cleanup);
  return { counts, cleanup, createSocket: (url, settings) => { assert.equal(url, 'wss://api.openai.com/v1/responses'); assert.equal(settings.followRedirects, false); assert.equal(settings.rejectUnauthorized, true); const client = new WebSocket(`ws://127.0.0.1:${server.address().port}`, settings); clients.add(client); counts.activeClients = clients.size; client.on('close', () => { clients.delete(client); counts.activeClients = clients.size; }); return client; } };
}
const sendPackets = (ws, bytes) => { for (const b of bytes) ws.send(b, { binary: false }); };

for (const fallback of [false, true]) test(`actual ws loopback preserves full canonical ${fallback ? 'done fallback' : 'terminal'} output`, async t => {
  const local = await loopback(t, ws => sendPackets(ws, packets(1, { output: richOutput, fallback }))), a = createResponsesTransport({ ...defaults, createSocket: local.createSocket }), c = context();
  const receipt = await a.submit(body(c), c); assert.deepEqual(receipt.output, richOutput); assert.deepEqual(a.close(c), { closed: true, quiescent: true }); assert.equal(local.counts.upgrades, 1); assert.equal(local.counts.requests, 1); assert.deepEqual(local.counts.binary, [false]); assert.equal(local.counts.requestHashes[0], hash(body(c))); await local.cleanup(); evidence.push({ case: fallback ? 'canonical-fallback' : 'canonical-full', counts: local.counts, transport: a.inspect(), preservedOutput: true });
});

for (const status of [401, 429, 302]) test(`actual HTTP ${status} handshake rejection is one attempt, zero send, no fallback`, async t => {
  const local = await loopback(t, () => assert.fail('No WebSocket request permitted'), status), a = createResponsesTransport({ ...defaults, createSocket: local.createSocket }), c = context(); await rejected(a.submit(body(c), c)); assert.deepEqual(a.close(c), { closed: true, quiescent: true }); assert.equal(a.inspect().connectionAttempts, 1); assert.equal(a.inspect().sendInvocations, 0); assert.equal(a.inspect().calls[0].httpStatus, status); await rejected(a.submit(body(context(2)), context(2))); assert.equal(local.counts.upgrades, 1); assert.equal(local.counts.ordinaryHttp, 0); await local.cleanup(); evidence.push({ case: `http-${status}`, counts: local.counts, transport: a.inspect() });
});

for (const mode of ['cutoff', 'binary', 'utf8', 'payload', 'aggregate', 'events', 'extra-terminal', 'identity']) test(`actual ws ${mode} cannot produce accepted close evidence or retry`, async t => {
  const normal = packets(), aggregatePackets = [normal[0], Buffer.from(JSON.stringify({ type: 'response.in_progress', sequence_number: 1, response: { id: 'resp_fixture_1', status: 'in_progress', output: [] } })), Buffer.from(JSON.stringify({ ...JSON.parse(normal[1]), sequence_number: 2 }))];
  const aggregateBound = Math.max(...aggregatePackets.map(b => b.length)); assert.ok(aggregatePackets.reduce((n,b) => n+b.length, 0) > aggregateBound);
  const limits = mode === 'payload' ? { maxResponseBytes: 256 } : mode === 'aggregate' ? { maxResponseBytes: aggregateBound } : mode === 'events' ? { maxEvents: 1 } : {};
  const local = await loopback(t, ws => {
    if (mode === 'cutoff') { sendPackets(ws, packets().slice(0, 1)); ws.terminate(); }
    else if (mode === 'binary') ws.send(packets()[0], { binary: true });
    else if (mode === 'utf8') ws.send(Buffer.from([255]), { binary: false });
    else if (mode === 'payload') ws.send('x'.repeat(257));
    else if (mode === 'aggregate') sendPackets(ws, aggregatePackets);
    else if (mode === 'identity') { const changed = JSON.parse(normal[1]); changed.response.id = 'resp_foreign'; sendPackets(ws, [normal[0], Buffer.from(JSON.stringify(changed))]); }
    else if (mode === 'extra-terminal') { const bytes = packets(); sendPackets(ws, [...bytes, bytes[1]]); }
    else sendPackets(ws, packets());
  });
  const a = createResponsesTransport({ ...defaults, ...limits, createSocket: local.createSocket }), c = context(); await rejected(a.submit(body(c), c)); assert.equal(a.close(c).quiescent, false); await rejected(a.submit(body(context(2)), context(2))); assert.equal(local.counts.requests, 1); assert.equal(local.counts.upgrades, 1); await local.cleanup(); evidence.push({ case: mode, counts: local.counts, transport: a.inspect() });
});

for (const mode of ['deadline', 'abort-before-open', 'slow-close']) test(`actual ws ${mode} releases local sockets without claiming quiescence or retry`, async t => {
  const controller = new AbortController(), local = await loopback(t, (ws, bytes, n, rawSocket) => { if (mode === 'slow-close') { rawSocket.pause(); sendPackets(ws, packets(n)); } });
  const a = createResponsesTransport({ ...defaults, timeoutMs: 50, createSocket: (url, settings) => { const ws = local.createSocket(url, settings); if (mode === 'abort-before-open') controller.abort(); return ws; } }), c = context(1, { signal: controller.signal });
  await rejected(a.submit(body(c), c)); assert.equal(a.close(c).quiescent, false); assert.equal(local.counts.requests, mode === 'abort-before-open' ? 0 : 1); if (mode === 'slow-close') assert.equal(a.inspect().calls[0].terminal, true); await rejected(a.submit(body(context(2)), context(2))); await local.cleanup(); evidence.push({ case: mode, counts: local.counts, transport: a.inspect() });
});

const certificate = async bytes => ({ bytes: bytes.length, sha256: hash(bytes) });
for (const mode of ['tool-final', 'standard', 'failed', 'incomplete', 'abnormal-close', 'abort']) test(`actual AI loop plus ws ${mode} preserves accounting and prevents unsafe tools/resend`, async t => {
  const controller = new AbortController();
  const local = await loopback(t, (ws, bytes, n) => {
    if (mode === 'abort') { sendPackets(ws, packets(n).slice(0, 1)); controller.abort(); return; }
    const output = mode === 'tool-final' && n === 1 ? richOutput : [message(n)];
    if (mode === 'abnormal-close') { sendPackets(ws, packets(n, { output: [functionItem] })); ws.close(1001); return; }
    sendPackets(ws, packets(n, { output, access: mode === 'standard' ? null : { cyber: 'daybreak_blue' }, status: ['failed', 'incomplete'].includes(mode) ? mode : 'completed' }));
  });
  const adapter = createResponsesTransport({ ...defaults, createSocket: local.createSocket }), directory = path.join(root, randomUUID()); await fs.mkdir(directory); let tools = 0;
  const options = { directory, targetRoots: [process.cwd()], identity, limits: { maxRequests: 3, maxTotalOutputTokens: 12, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 8192, maxResponseBytesPerRequest: 16384, maxToolCalls: 2, maxToolResultBytes: 1024, timeoutMs: 5000 }, toolNames: ['read'], signal: controller.signal, checkRequest: certificate, checkOutput: certificate, submit: adapter.submit, close: adapter.close,
    prepare: async (c, previous) => { const request = JSON.parse(body(c)); request.tools = [{ type: 'function', name: 'read', parameters: {} }]; if (previous) { assert.deepEqual(previous.response.output, richOutput); request.input = [...previous.response.output, { type: 'function_call_output', call_id: previous.results[0].id, output: previous.results[0].content }]; } return Buffer.from(JSON.stringify(request)); },
    executeAllowedTool: async () => { assert.equal(adapter.inspect().calls[0].quiescent, true); tools++; return Buffer.from('fixed fixture result'); } };
  const result = await runAiSession(options), expectedCalls = mode === 'tool-final' ? 2 : 1;
  assert.equal(result.status === 'completed', ['tool-final', 'standard'].includes(mode)); assert.equal(tools, mode === 'tool-final' ? 1 : 0); assert.equal(result.submitInvocations, expectedCalls); assert.equal(local.counts.requests, expectedCalls);
  if (mode === 'standard') assert.equal(JSON.parse(await fs.readFile(path.join(directory, '1.terminal.json'))).effectiveProgram, 'standard');
  assert.equal(result.usageComplete, mode !== 'abort'); assert.equal(result.usage?.totalTokens ?? null, mode === 'abort' ? null : expectedCalls * 5); if (mode === 'abnormal-close') assert.equal(result.reason, 'close_unverified');
  const before = adapter.inspect().sendInvocations, replay = await runAiSession(options); assert.equal(replay.reason, 'ownership_unavailable'); assert.equal(adapter.inspect().sendInvocations, before);
  const saved = JSON.parse(await fs.readFile(path.join(directory, 'session.result.json'))); assert.equal(saved.status, result.status); assert.equal(saved.usageComplete, result.usageComplete);
  for (let n = 1; n <= expectedCalls; n++) { const reservation = JSON.parse(await fs.readFile(path.join(directory, `${n}.reserved.json`))), terminal = JSON.parse(await fs.readFile(path.join(directory, `${n}.terminal.json`))); assert.equal(reservation.requestSha256, local.counts.requestHashes[n-1]); assert.equal(terminal.callId, reservation.callId); assert.equal(terminal.usage?.totalTokens ?? null, mode === 'abort' ? null : 5); }
  await local.cleanup(); evidence.push({ case: `ai-${mode}`, counts: local.counts, transport: adapter.inspect(), result, directory, originalLockPreventsReplay: true });
});

for (const stage of ['before', 'after']) for (const fault of ['utf8', 'payload', 'framing', 'binary', 'json', 'identity']) test(`actual AI stream corruption ${stage} terminal ${fault} leaves usage unknown and tools disabled`, async t => {
  const nativeErrorCodes = [];
  const local = await loopback(t, (ws, bytes, n, rawSocket) => {
    const valid = packets(n, { output: [functionItem] }); sendPackets(ws, stage === 'after' ? valid : valid.slice(0, 1));
    if (fault === 'utf8') ws.send(Buffer.from([255]), { binary: false });
    else if (fault === 'payload') ws.send('x'.repeat(defaults.maxResponseBytes + 1));
    else if (fault === 'framing') rawSocket.write(Buffer.from([0xc1, 0]));
    else if (fault === 'binary') ws.send(Buffer.from('{}'), { binary: true });
    else if (fault === 'json') ws.send('{');
    else ws.send(JSON.stringify({ type: 'response.in_progress', sequence_number: 2, response: { id: 'resp_foreign', status: 'in_progress', output: [] } }));
  });
  const adapter = createResponsesTransport({ ...defaults, createSocket: (url, settings) => { const socket = local.createSocket(url, settings); socket.on('error', error => { nativeErrorCodes.push(typeof error.code === 'string' && /^WS_ERR_[A-Z0-9_]+$/.test(error.code) ? error.code : 'unclassified_socket_error'); }); return socket; } });
  const directory = path.join(root, randomUUID()); await fs.mkdir(directory); let tools = 0;
  const options = { directory, targetRoots: [process.cwd()], identity, limits: { maxRequests: 3, maxTotalOutputTokens: 12, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 8192, maxResponseBytesPerRequest: 16384, maxToolCalls: 2, maxToolResultBytes: 1024, timeoutMs: 5000 }, toolNames: ['read'], checkRequest: certificate, checkOutput: certificate, submit: adapter.submit, close: adapter.close,
    prepare: async c => { const request = JSON.parse(body(c)); request.tools = [{ type: 'function', name: 'read', parameters: {} }]; return Buffer.from(JSON.stringify(request)); }, executeAllowedTool: async () => { tools++; return Buffer.from('must not execute'); } };
  const result = await runAiSession(options), replay = await runAiSession(options); await local.cleanup();
  evidence.push({ case: `ai-corrupt-${stage}-${fault}`, counts: local.counts, transport: adapter.inspect(), result, directory, originalLockPreventsReplay: replay.reason === 'ownership_unavailable', nativeErrorCodes });
  assert.equal(result.status, 'acceptance_unknown'); assert.equal(result.usage, null); assert.equal(result.usageComplete, false); assert.deepEqual(result.observedUsage, []); assert.equal(tools, 0); assert.equal(result.submitInvocations, 1); assert.equal(local.counts.requests, 1); assert.equal(adapter.inspect().connectionAttempts, 1); assert.equal(adapter.inspect().sendInvocations, 1); assert.equal(adapter.inspect().calls[0].quiescent, false); assert.equal(replay.reason, 'ownership_unavailable');
  const terminal = JSON.parse(await fs.readFile(path.join(directory, '1.terminal.json'))), saved = JSON.parse(await fs.readFile(path.join(directory, 'session.result.json'))); assert.equal(terminal.usage, null); assert.equal(terminal.state, 'acceptance_unknown'); assert.equal(saved.usage, null); assert.equal(saved.usageComplete, false);
  const codes = { utf8: 'WS_ERR_INVALID_UTF8', payload: 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH', framing: 'WS_ERR_UNEXPECTED_RSV_1' }; if (codes[fault]) assert.deepEqual(nativeErrorCodes, [codes[fault]]); else assert.deepEqual(nativeErrorCodes, []);
});

async function saveProof() {
  if (process.env.SCANMUX_TRANSPORT_MUTANT === '1') return;
  const sources = [];
  for (const name of ['internal/responses-transport.mjs', 'test/responses-transport.test.mjs', 'internal/ai-session.mjs', 'internal/response-protocol.mjs', 'src/private-storage.ts', 'node_modules/ws/package.json', 'node_modules/ws/lib/websocket.js', 'node_modules/ws/lib/receiver.js']) { const bytes = await fs.readFile(name); sources.push({ path: name, bytes: bytes.length, sha256: hash(bytes) }); }
  const proof = path.join(root, 'transport-proof.json'); await fs.writeFile(proof, JSON.stringify({ schema: 'scanmux.responses-transport-test-observations/v1', classification: 'synthetic_loopback_only', platform: process.platform, node: process.version, actualProviderCalls: 0, sources, cases: evidence }, null, 2) + '\n', { flag: 'wx' });
}
