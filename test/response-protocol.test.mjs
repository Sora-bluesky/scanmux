import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createResponseDecoder, projectResponseOutput } from '../internal/response-protocol.mjs';
import { createResponsesTransport } from '../internal/responses-transport.mjs';

const context = { sessionId: 'session', callId: 'call', requestId: 'request' };
const message = (phase = 'final_answer') => ({ id: 'message_1', type: 'message', role: 'assistant', status: 'completed', phase, content: [{ type: 'output_text', text: 'Synthetic final.', annotations: [] }] });
const reasoning = () => ({ id: 'reasoning_1', type: 'reasoning', status: 'completed', summary: [{ type: 'summary_text', text: 'Synthetic summary.' }], content: [{ type: 'reasoning_text', text: 'Synthetic test text.' }], encrypted_content: 'synthetic-opaque-content-only' });
const call = () => ({ id: 'function_1', type: 'function_call', call_id: 'tool_1', name: 'read', arguments: '{ "path" : "source.ts" }', status: 'completed', async: false, caller: { type: 'direct' } });
const created = () => ({ type: 'response.created', response: { id: 'response_1', object: 'response', status: 'in_progress', model: 'gpt-6-sol', output: [] } });
const terminal = output => ({ type: 'response.completed', response: { id: 'response_1', object: 'response', status: 'completed', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, usage: { input_tokens: 3, output_tokens: 2, total_tokens: 5, input_tokens_details: { cached_tokens: 1, cache_write_tokens: 0 }, output_tokens_details: { reasoning_tokens: 1 } }, output, error: null, incomplete_details: null } });
const wire = events => events.map((event, index) => Buffer.from(JSON.stringify({ sequence_number: index, ...event })));
function decodePackets(packets, limits = {}) {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64, ...limits });
  for (const bytes of packets) decoder.push(bytes);
  return decoder.finish();
}
const decode = (events, limits = {}) => decodePackets(wire(events), limits);
const added = (item, output_index = 0) => ({ type: 'response.output_item.added', item, output_index });
const done = (item, output_index = 0) => ({ type: 'response.output_item.done', item, output_index });
const metadataPacket = fields => Buffer.from(JSON.stringify({ type: 'codex.response.metadata', ...fields }));
const metadataVariants = [
  ['headers', { headers: { 'x-example': '1' } }],
  ['metadata', { metadata: { etag: 'synthetic-metadata-canary' } }],
  ['both', { headers: {}, metadata: { etag: 'synthetic-metadata-canary' } }],
];
const inStreamMetadata = fields => ({ type: 'response.metadata', response_id: 'response_1', metadata: { etag: 'synthetic-in-stream-metadata-canary' }, ...fields });
const timingPacket = (fields = {}) => Buffer.from(JSON.stringify({ type: 'responsesapi.websocket_timing', timing_metrics: { latency_ms: 8675309 }, ...fields }));

for (const fallback of [false, true]) for (const position of [0, 1, 2, 3]) test(`WebSocket timing at position ${position} preserves the ${fallback ? 'reconstructed' : 'terminal'} response`, () => {
  const packets = wire([created(), added(call()), done(call()), terminal(fallback ? null : [call()])]), expected = decodePackets(packets);
  packets.splice(position, 0, timingPacket());
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  for (const [index, packet] of packets.entries()) {
    const before = decoder.inspect(); decoder.push(packet);
    if (index === position) assert.deepEqual(decoder.inspect(), before);
  }
  assert.deepEqual(decoder.finish(), expected);
  assert.deepEqual(decoder.inspect(), { terminalKind: 'completed', failureCode: null });
});

for (const [name, timing_metrics] of [['empty', {}], ['unexamined', { future_field: { detail: 'synthetic-timing-canary' } }]]) test(`WebSocket timing with ${name} metrics discards their values`, () => {
  const packets = wire([created(), terminal([message()])]), expected = decodePackets(packets);
  packets.splice(1, 0, timingPacket({ timing_metrics }));
  assert.deepEqual(decodePackets(packets), expected);
});

for (const [name, fields, code, failureCode] of [
  ['unknown field', { future_field: true }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['missing timing metrics', { timing_metrics: undefined }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['null timing metrics', { timing_metrics: null }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['array timing metrics', { timing_metrics: [] }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['string timing metrics', { timing_metrics: 'text' }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['numeric timing metrics', { timing_metrics: 1 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['boolean timing metrics', { timing_metrics: false }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['sequence number', { sequence_number: 1 }, 'unsupported_event', 'unexpected_event'],
  ['duplicate sequence', { sequence_number: 0 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['null sequence', { sequence_number: null }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['stream id', { stream_id: 'named' }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['sequence alias', { sequence: 1 }, 'event_sequence_or_stream', 'sequence_mismatch'],
]) test(`WebSocket timing rejects ${name} with the original failure code`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  decoder.push(wire([created()])[0]);
  assert.throws(() => decoder.push(timingPacket(fields)), { code });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'none', failureCode });
});

for (const type of ['response.future', 'response.metadata', 'codex.rate_limits']) test(`${type} with timing metrics retains the sequence failure code`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  assert.throws(() => decoder.push(timingPacket({ type })), { code: 'event_sequence_or_stream' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'none', failureCode: 'sequence_mismatch' });
});

test('WebSocket timing cannot create a response or reset its sequence', () => {
  assert.throws(() => decodePackets([timingPacket(), ...wire([terminal([message()])])]), { code: 'event_before_created' });
  const packets = wire([created(), { ...terminal([message()]), sequence_number: 0 }]);
  assert.throws(() => decodePackets([packets[0], timingPacket(), packets[1]]), { code: 'event_sequence_or_stream' });
});

test('WebSocket timing after terminal is rejected', () => {
  assert.throws(() => decodePackets([...wire([created(), terminal([message()])]), timingPacket()]), { code: 'event_after_terminal' });
});

test('WebSocket timing counts toward byte and event limits', () => {
  const packets = wire([created(), terminal([message()])]); packets.splice(1, 0, timingPacket());
  const maxBytes = packets.reduce((sum, packet) => sum + packet.length, 0);
  assert.equal(decodePackets(packets, { maxBytes, maxEvents: packets.length }).status, 'completed');
  assert.throws(() => decodePackets(packets, { maxBytes: maxBytes - 1 }), { code: 'response_limit' });
  assert.throws(() => decodePackets(packets, { maxEvents: packets.length - 1 }), { code: 'response_limit' });
  assert.throws(() => decodePackets([timingPacket()], { maxBytes: timingPacket().length - 1 }), { code: 'response_limit' });
});

for (const fallback of [false, true]) for (const position of [2, 3]) test(`in-stream metadata at position ${position} preserves the ${fallback ? 'reconstructed' : 'terminal'} response`, () => {
  const events = [created(), added(call()), done(call()), terminal(fallback ? null : [call()])], expected = decode(events);
  events.splice(position, 0, inStreamMetadata());
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  for (const [index, packet] of wire(events).entries()) {
    const before = decoder.inspect(); decoder.push(packet);
    if (index === position) assert.deepEqual(decoder.inspect(), before);
  }
  assert.deepEqual(decoder.finish(), expected);
  assert.deepEqual(decoder.inspect(), { terminalKind: 'completed', failureCode: null });
});

for (const [name, fields, code, failureCode] of [
  ['different response id', { response_id: 'response_other' }, 'response_identity', 'response_identity'],
  ['missing sequence', { sequence_number: undefined }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['duplicate sequence', { sequence_number: 1 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['decreasing sequence', { sequence_number: 0 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['negative sequence', { sequence_number: -1 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['fractional sequence', { sequence_number: 2.5 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['string sequence', { sequence_number: '2' }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['null sequence', { sequence_number: null }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['unsafe sequence', { sequence_number: Number.MAX_SAFE_INTEGER + 1 }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['stream id', { stream_id: 'named' }, 'event_sequence_or_stream', 'sequence_mismatch'],
  ['null stream id', { stream_id: null }, 'event_sequence_or_stream', 'sequence_mismatch'],
]) test(`in-stream metadata rejects ${name} through the common checks`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), added(call()), inStreamMetadata(fields)]);
  for (const packet of packets.slice(0, -1)) decoder.push(packet);
  assert.throws(() => decoder.push(packets.at(-1)), { code });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'none', failureCode });
});

for (const [name, fields] of [
  ['missing response id', { response_id: undefined }],
  ['missing metadata', { metadata: undefined }],
  ['null metadata', { metadata: null }],
  ['array metadata', { metadata: [] }],
  ['string metadata', { metadata: 'text' }],
  ['numeric metadata', { metadata: 1 }],
  ['boolean metadata', { metadata: false }],
  ['headers', { headers: {} }],
  ['response body', { response: created().response }],
  ['unknown field', { future_field: true }],
]) test(`in-stream metadata rejects ${name} as an unsupported shape`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), inStreamMetadata(fields)]);
  decoder.push(packets[0]);
  assert.throws(() => decoder.push(packets[1]), { code: 'unsupported_event' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'none', failureCode: 'unexpected_event' });
});

for (const [name, events, code] of [
  ['before created', [inStreamMetadata(), created(), terminal([message()])], 'response_identity'],
  ['before created without response id', [inStreamMetadata({ response_id: undefined }), created(), terminal([message()])], 'event_before_created'],
  ['after terminal', [created(), terminal([message()]), inStreamMetadata()], 'event_after_terminal'],
  ['followed by repeated sequence', [created(), inStreamMetadata(), { ...terminal([message()]), sequence_number: 1 }], 'event_sequence_or_stream'],
  ['followed by lifecycle regression', [created(), inStreamMetadata(), { type: 'response.queued', response: { ...created().response, status: 'queued' } }], 'response_regressed'],
]) test(`in-stream metadata ${name} retains the protocol failure`, () => {
  assert.throws(() => decode(events), { code });
});

test('in-stream metadata counts toward byte and event limits', () => {
  const packets = wire([created(), inStreamMetadata(), terminal([message()])]), maxBytes = packets.reduce((sum, packet) => sum + packet.length, 0);
  assert.equal(decodePackets(packets, { maxBytes, maxEvents: packets.length }).status, 'completed');
  assert.throws(() => decodePackets(packets, { maxBytes: maxBytes - 1 }), { code: 'response_limit' });
  assert.throws(() => decodePackets(packets, { maxEvents: packets.length - 1 }), { code: 'response_limit' });
});

for (const [name, fields] of metadataVariants) for (const position of [0, 2]) test(`out-of-band ${name} metadata at position ${position} leaves the response unchanged`, () => {
  const packets = wire([created(), added(call()), done(call()), terminal(null)]), expected = decodePackets(packets);
  packets.splice(position, 0, metadataPacket(fields));
  assert.deepEqual(decodePackets(packets), expected);
});

for (const [name, fields] of metadataVariants) test(`out-of-band ${name} metadata after terminal is rejected`, () => {
  assert.throws(() => decodePackets([...wire([created(), terminal([message()])]), metadataPacket(fields)]), { code: 'event_after_terminal' });
});

for (const field of ['headers', 'metadata']) for (const value of [null, [], 'text', 1, false]) for (const companion of [false, true]) test(`out-of-band ${field} metadata rejects ${JSON.stringify(value)} with companion ${companion}`, () => {
  const fields = { [field]: value, ...(companion ? { [field === 'headers' ? 'metadata' : 'headers']: {} } : {}) };
  assert.throws(() => decodePackets([metadataPacket(fields), ...wire([created(), terminal([message()])])]));
});

for (const [name, fields] of [
  ['missing object', {}],
  ['stream id', { headers: {}, stream_id: 'named' }],
  ['null stream id', { headers: {}, stream_id: null }],
  ['sequence number', { headers: {}, sequence_number: 0 }],
  ['sequence alias', { headers: {}, sequence: 0 }],
  ['response id', { metadata: {}, response_id: 'response_1' }],
  ['response body', { metadata: {}, response: created().response }],
  ['unknown field', { headers: {}, future_field: true }],
]) test(`out-of-band metadata rejects ${name}`, () => {
  assert.throws(() => decodePackets([metadataPacket(fields), ...wire([created(), terminal([message()])])]));
});

for (const type of ['response.future', 'response.metadata']) test(`${type} without sequence retains the sequence failure code`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  assert.throws(() => decoder.push(Buffer.from(JSON.stringify({ type, metadata: {} }))), { code: 'event_sequence_or_stream' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'none', failureCode: 'sequence_mismatch' });
});

test('out-of-band metadata cannot create a response or reset its sequence', () => {
  const metadata = metadataPacket({ headers: {} });
  assert.throws(() => decodePackets([metadata, ...wire([terminal([message()])])]), { code: 'event_before_created' });
  const packets = wire([created(), { ...terminal([message()]), sequence_number: 0 }]);
  assert.throws(() => decodePackets([packets[0], metadata, packets[1]]), { code: 'event_sequence_or_stream' });
});

for (const [name, fields] of metadataVariants) test(`out-of-band ${name} metadata counts toward byte and event limits`, () => {
  const packets = [metadataPacket(fields), ...wire([created(), terminal([message()])])];
  const maxBytes = packets.reduce((sum, bytes) => sum + bytes.length, 0);
  assert.equal(decodePackets(packets, { maxBytes, maxEvents: packets.length }).status, 'completed');
  assert.throws(() => decodePackets(packets, { maxBytes: maxBytes - 1 }), { code: 'response_limit' });
  assert.throws(() => decodePackets(packets, { maxEvents: packets.length - 1 }), { code: 'response_limit' });
  assert.throws(() => decodePackets([packets[0]], { maxBytes: packets[0].length - 1 }), { code: 'response_limit' });
});

test('complete canonical output retains order, phase, reasoning and original argument spelling', () => {
  const output = [reasoning(), message('commentary'), call()], result = decode([created(), terminal(output)]);
  assert.deepEqual(result.output, output); assert.deepEqual(projectResponseOutput(result.output), { text: '', tools: [{ id: 'tool_1', name: 'read', arguments: { path: 'source.ts' } }] });
  assert.deepEqual(result.usage, { inputTokens: 3, outputTokens: 2, totalTokens: 5, cachedInputTokens: 1, reasoningTokens: 1 });
  assert.equal(result.effectiveProgram, 'daybreak_blue'); assert.deepEqual(Object.fromEntries(Object.keys(context).map(key => [key, result[key]])), context);
  output[0].encrypted_content = 'changed'; assert.equal(result.output[0].encrypted_content, 'synthetic-opaque-content-only');
});

for (const omitted of ['absent', 'null']) test(`reconstruct ${omitted} terminal output from completed wire indexes`, () => {
  const output = [reasoning(), call()], ending = terminal(output);
  if (omitted === 'absent') delete ending.response.output; else ending.response.output = null;
  const result = decode([created(), added(output[1], 1), added(output[0], 0), done(output[0], 0), done(output[1], 1), ending]);
  assert.equal(result.status, 'completed'); assert.deepEqual(result.output, output);
});

test('empty terminal output reconstructs four completed streamed items exactly like null', () => {
  const output = [reasoning(), message('commentary'), call(), { ...message(), id: 'message_2' }];
  const events = [created(), ...[0, 2, 1, 3].flatMap(index => [added(output[index], index), done(output[index], index)])];
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  for (const packet of wire([...events, terminal([])])) decoder.push(packet);
  const result = decoder.finish();
  assert.deepEqual(result, decode([...events, terminal(null)])); assert.equal(result.status, 'completed'); assert.deepEqual(result.output, output);
  assert.deepEqual(decoder.inspect(), { terminalKind: 'completed', failureCode: null });
});

for (const output of [null, []]) for (const [name, events] of [
  ['unfinished item', [added(call())]], ['index gap', [added(call(), 1), done(call(), 1)]],
]) test(`${output === null ? 'null' : 'empty'} terminal output rejects ${name} with unfinished_output`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), ...events, terminal(output)]);
  for (const packet of packets.slice(0, -1)) decoder.push(packet);
  assert.throws(() => decoder.push(packets.at(-1)), { code: 'unfinished_output' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'completed', failureCode: 'unfinished_output' });
});

test('empty terminal output without streamed items has the same result as null', () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  for (const packet of wire([created(), terminal([])])) decoder.push(packet);
  const result = decoder.finish();
  assert.deepEqual(result, decode([created(), terminal(null)])); assert.equal(result.status, 'invalid');
  assert.deepEqual(decoder.inspect(), { terminalKind: 'completed', failureCode: 'invalid_output' });
});

test('full terminal output replaces unfinished additions without treating partial encrypted content as final', () => {
  const r = reasoning(), f = call(), partial = { ...r, status: 'in_progress', encrypted_content: 'partial' };
  const result = decode([created(), added(partial), added({ ...f, arguments: '{', status: 'in_progress' }, 1), terminal([r, f])]);
  assert.equal(result.status, 'completed'); assert.deepEqual(result.output, [r, f]);
});

const identityCanary = 'synthetic-shape-canary';
const identityItem = { ...call(), id: identityCanary, call_id: `${identityCanary}-call`, name: identityCanary, arguments: JSON.stringify({ text: identityCanary }) };
for (const [kind, output, index, terminalType] of [
  ['missing_index', [identityItem], 1, null],
  ['type', [message()], 0, 'message'],
  ['id', [{ ...identityItem, id: 'other' }], 0, 'function_call'],
  ['call', [{ ...identityItem, call_id: 'other' }], 0, 'function_call'],
  ['name', [{ ...identityItem, name: 'other' }], 0, 'function_call'],
]) test(`output identity diagnostics explain ${kind} without changing the rejection`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), added(identityItem), ...(index === 1 ? [added(call(), 1)] : []), terminal(output)]);
  for (const packet of packets.slice(0, -1)) decoder.push(packet);
  assert.throws(() => decoder.push(packets.at(-1)), { code: 'output_identity' });
  const expected = { terminalKind: 'completed', failureCode: 'output_identity', outputIdentityMismatch: {
    streamedItemCount: index + 1, terminalOutputLength: output.length, index, kind, streamedType: 'function_call', terminalType,
  } };
  assert.deepEqual(decoder.inspect(), expected); assert.ok(!JSON.stringify(decoder.inspect()).includes(identityCanary));
  const snapshot = decoder.inspect(); snapshot.outputIdentityMismatch.kind = identityCanary;
  assert.deepEqual(decoder.inspect(), expected);
});

for (const [item, kind, terminalType] of [[null, 'type', null], [{ ...identityItem, type: 42 }, 'type', null],
  [{ ...identityItem, type: identityCanary.repeat(5) }, 'type', 'other'], [{ ...identityItem, id: null }, 'id', 'function_call'],
  [{ ...identityItem, call_id: null }, 'call', 'function_call'], [{ ...identityItem, name: null }, 'name', 'function_call'],
  [(({ id, ...item }) => item)(message()), 'type', 'message'], [(({ id, ...item }) => item)(reasoning()), 'type', 'reasoning']])
test(`output identity diagnostics keep malformed ${kind} identities content-free: ${terminalType}`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), added(identityItem), terminal([item])]);
  for (const packet of packets.slice(0, -1)) decoder.push(packet);
  assert.throws(() => decoder.push(packets.at(-1)), { code: 'output_identity' });
  assert.deepEqual(decoder.inspect().outputIdentityMismatch, { streamedItemCount: 1, terminalOutputLength: 1, index: 0, kind, streamedType: 'function_call', terminalType });
  assert.ok(!JSON.stringify(decoder.inspect()).includes(identityCanary));
});

test('output identity diagnostics name the first checked failing wire index after matching items', () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), output = [message(), { ...message(), id: 'message_2' }, call()];
  const packets = wire([created(), added(output[0]), added(output[2], 2), added(output[1], 1), terminal([output[0]])]);
  for (const packet of packets.slice(0, -1)) decoder.push(packet);
  assert.throws(() => decoder.push(packets.at(-1)), { code: 'output_identity' });
  assert.deepEqual(decoder.inspect().outputIdentityMismatch, { streamedItemCount: 3, terminalOutputLength: 1, index: 2, kind: 'missing_index', streamedType: 'function_call', terminalType: null });
});

test('known progress binds item identity while terminal output owns text and arguments', () => {
  const item = { ...call(), arguments: '', status: 'in_progress' };
  const result = decode([created(), added(item), { type: 'response.function_call_arguments.delta', item_id: item.id, output_index: 0, delta: 'unusable partial' }, done(call()), terminal([call()])]);
  assert.equal(result.status, 'completed'); assert.deepEqual(projectResponseOutput(result.output).tools[0].arguments, { path: 'source.ts' });
});

test('function optional item id is distinct from its required call id', () => {
  const f = call(); delete f.id;
  const result = decode([created(), added({ ...f, arguments: '' }), done(f), terminal([f])]);
  assert.equal(result.status, 'completed'); assert.equal(result.output[0].id, undefined); assert.equal(projectResponseOutput(result.output).tools[0].id, 'tool_1');
});

test('queued lifecycle can advance once and complete with phase-less messages', () => {
  const first = created(); first.response.status = 'queued';
  const last = message(); delete last.phase;
  assert.equal(decode([first, { type: 'response.queued', response: first.response }, { type: 'response.in_progress', response: created().response }, terminal([last])]).status, 'completed');
});

for (const [name, alter] of [
  ['refusal', output => output[1].content.push({ type: 'refusal', refusal: 'Synthetic refusal.' })],
  ['unknown builtin', output => output.push({ id: 'other', type: 'web_search_call', status: 'completed' })],
  ['unknown field', output => output[1].future_field = 'unsupported'],
  ['unknown annotation', output => output[1].content[0].annotations.push({ type: 'url_citation', url: 'https://example.invalid' })],
  ['nonempty logprobs', output => output[1].content[0].logprobs = [{}]],
  ['asynchronous tool', output => output[2].async = true],
  ['program caller', output => output[2].caller = { type: 'program', caller_id: 'program_1' }],
  ['string direct caller', output => output[2].caller = 'direct'],
  ['namespace', output => output[2].namespace = 'other'],
  ['array arguments', output => output[2].arguments = '[]'],
  ['malformed arguments', output => output[2].arguments = '{'],
  ['duplicate call', output => output.push({ ...call(), id: 'function_2' })],
  ['duplicate item id', output => output[2].id = output[0].id],
  ['incomplete message', output => output[1].status = 'incomplete'],
  ['incomplete function', output => output[2].status = 'incomplete'],
  ['missing reasoning continuation', output => delete output[0].encrypted_content],
  ['null reasoning continuation', output => output[0].encrypted_content = null],
  ['unknown reasoning field', output => output[0].future_field = true],
]) test(`unsupported ${name} preserves associated usage without executable output`, () => {
  const output = [reasoning(), message('commentary'), call()]; alter(output);
  const result = decode([created(), terminal(output)]);
  assert.equal(result.status, 'invalid'); assert.deepEqual(result.output, []); assert.equal(result.usage.totalTokens, 5);
});

for (const [name, output] of [['commentary only', [message('commentary')]], ['reasoning only', [reasoning()]], ['empty output', []]]) test(`${name} cannot finish a conversation`, () => {
  assert.equal(decode([created(), terminal(output)]).status, 'invalid');
});

for (const phase of [undefined, null, 'final_answer']) test(`final message phase ${phase} retains final text`, () => {
  const m = message(); if (phase === undefined) delete m.phase; else m.phase = phase;
  const r = reasoning(); delete r.encrypted_content;
  assert.equal(projectResponseOutput(decode([created(), terminal([r, m])]).output).text, 'Synthetic final.');
});

for (const status of ['failed', 'incomplete']) test(`provider ${status} preserves observed usage and exposes no tool`, () => {
  const e = terminal([call()]); e.type = `response.${status}`; e.response.status = status;
  const result = decode([created(), e]); assert.equal(result.status, status); assert.equal(result.usage.totalTokens, 5); assert.deepEqual(result.output, []);
});

for (const [status, details, diagnostic] of [
  ['failed', { error: { code: 'server_error', message: 'private-provider-canary' } }, { providerErrorCode: 'server_error' }],
  ['failed', { error: { code: 'private-provider-canary', message: 'private-provider-canary' } }, { providerErrorCode: 'other' }],
  ['incomplete', { incomplete_details: { reason: 'max_output_tokens', message: 'private-provider-canary' } }, { incompleteReason: 'max_output_tokens' }],
  ['incomplete', { incomplete_details: { reason: 'content_filter' } }, { incompleteReason: 'content_filter' }],
  ['incomplete', { incomplete_details: { reason: 'private-provider-canary' } }, {}],
]) test(`terminal diagnostics allow only fixed ${status} tokens ${JSON.stringify(diagnostic)}`, async () => {
  const ending = terminal([]); ending.type = `response.${status}`; ending.response.status = status; Object.assign(ending.response, details);
  const packets = wire([created(), ending]);
  class Socket extends EventEmitter {
    send(bytes, options, callback) { callback(); }
    close() { queueMicrotask(() => this.emit('close', 1000)); }
    terminate() { queueMicrotask(() => this.emit('close', 1006)); }
  }
  const transport = createResponsesTransport({ bearerToken: 'synthetic-credential', maxRequests: 1, maxRequestBytes: 8192, maxResponseBytes: 65536, maxEvents: 64, timeoutMs: 2000,
    createSocket() { const socket = new Socket(); queueMicrotask(() => { socket.emit('upgrade', { statusCode: 101 }); socket.emit('open'); for (const bytes of packets) socket.emit('message', bytes, false); }); return socket; } });
  const request = Object.freeze({ identity: Object.freeze({ runId: 'run', attemptId: 'attempt', buildId: 'build', requestId: 'request', scanId: 'scan', snapshotHash: 'a'.repeat(64) }),
    sessionId: context.sessionId, callId: context.callId, sequence: 1, outputCap: 5, signal: new AbortController().signal });
  const result = await transport.submit(Buffer.from(JSON.stringify({ type: 'response.create', model: 'gpt-6-sol', store: false, access_programs: { cyber: 'daybreak_blue' }, max_output_tokens: 5 })), request);
  assert.equal(result.status, status); assert.deepEqual(transport.close(request), { closed: true, quiescent: true });
  const { receivedBytes, receivedMessages, terminalKind, closeCode, sendOk, failureCode, providerErrorCode, incompleteReason } = transport.inspect().calls[0];
  assert.deepEqual({ receivedBytes, receivedMessages, terminalKind, closeCode, sendOk, failureCode,
    ...(providerErrorCode === undefined ? {} : { providerErrorCode }), ...(incompleteReason === undefined ? {} : { incompleteReason }) },
  { receivedBytes: packets.reduce((sum, bytes) => sum + bytes.length, 0), receivedMessages: 2, terminalKind: status, closeCode: 1000, sendOk: true, failureCode: null, ...diagnostic });
  assert.ok(!JSON.stringify(transport.inspect()).includes('private-provider-canary'));
});

test('error event without response carries no invented status or usage', () => {
  const result = decode([created(), { type: 'error', code: 'synthetic', message: 'No real provider called.', param: null }]);
  assert.equal(result.status, 'error'); assert.equal(result.usage, null); assert.equal(result.effectiveProgram, 'unknown'); assert.deepEqual(result.output, []);
});

test('nested error event records a known provider code without retaining details', () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), canary = 'synthetic-error-canary';
  for (const packet of wire([created(), { type: 'error', error: { code: 'cyber_policy', message: canary, param: canary, type: canary } }])) decoder.push(packet);
  const result = decoder.finish(); assert.equal(result.status, 'error'); assert.equal(result.usage, null); assert.deepEqual(result.output, []);
  assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: null, providerErrorCode: 'cyber_policy' });
  assert.ok(!JSON.stringify({ result, diagnostic: decoder.inspect() }).includes(canary));
});

const errorCanary = 'synthetic-error-canary';
const providerErrorEvents = error => [
  ['flat', { type: 'error', code: error.code, message: error.message, param: error.param }],
  ['nested', { type: 'error', error }],
  ['response.failed', { type: 'response.failed', response: { ...terminal([]).response, status: 'failed', error } }],
];
for (const [name, code, expected] of [
  ...['server_error', 'flex_unavailable', 'model_not_found', 'context_length_exceeded', 'insufficient_quota', 'credit_balance_exhausted',
    'organization_spend_limit_exceeded', 'project_spend_limit_exceeded', 'usage_not_included', 'cyber_policy', 'bio_policy', 'misalignment_policy_violation',
    'invalid_prompt', 'policy_capacity_unavailable', 'server_is_overloaded', 'rate_limit_exceeded', 'slow_down'].map(code => [code, code, code]),
  ['unknown', errorCanary, 'other'], ['empty', '', 'other'], ['null', null, undefined],
]) for (const [shape, ending] of providerErrorEvents({ code, message: errorCanary, param: errorCanary, type: errorCanary }))
test(`${shape} provider error ${name} records only fixed diagnostics`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 });
  for (const packet of wire([created(), ending])) decoder.push(packet);
  const result = decoder.finish(); assert.equal(result.status, shape === 'response.failed' ? 'failed' : 'error'); assert.deepEqual(result.output, []);
  assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: null, ...(expected === undefined ? {} : { providerErrorCode: expected }) });
  assert.ok(!JSON.stringify({ result, diagnostic: decoder.inspect() }).includes(errorCanary));
});

for (const error of [undefined, null, {}, { message: errorCanary }, { code: null, message: errorCanary }]) test(`failed response without a string code records no provider code: ${JSON.stringify(error)}`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), ending = providerErrorEvents(error ?? {})[2][1];
  ending.response.error = error;
  for (const packet of wire([created(), ending])) decoder.push(packet);
  assert.equal(decoder.finish().status, 'failed'); assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: null });
  assert.ok(!JSON.stringify(decoder.inspect()).includes(errorCanary));
});

for (const fields of [{}, { message: null, param: null, type: null }, { message: errorCanary }, { param: errorCanary }, { type: errorCanary }])
test(`nested error accepts optional string or null details: ${JSON.stringify(fields)}`, () => {
  assert.equal(decode([created(), { type: 'error', error: { code: null, ...fields } }]).status, 'error');
});

for (const [name, error] of [
  ['missing', undefined], ['null', null], ['array', []], ['string', errorCanary], ['number', 1], ['boolean', false],
  ['missing code', { message: errorCanary }], ['unknown key', { code: null, detail: errorCanary }],
  ...['code', 'message', 'param', 'type'].flatMap(key => [0, false, [], {}].map((value, index) => [`${key} type ${index}`, { code: null, [key]: value }])),
]) test(`malformed nested error rejects ${name} with the existing failure code`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), { type: 'error', error }]);
  decoder.push(packets[0]); assert.throws(() => decoder.push(packets[1]), { code: 'error_event' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: 'error_event' });
  assert.ok(!JSON.stringify(decoder.inspect()).includes(errorCanary)); assert.throws(() => decoder.finish(), { code: 'response_unfinished' });
});

for (const fields of [{ code: null }, { message: errorCanary }, { param: null }, { code: null, message: errorCanary, param: null },
  { code: 1, message: errorCanary, param: null }]) test(`mixed error shapes are rejected: ${Object.keys(fields).join('/')}`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), { type: 'error', error: { code: null }, ...fields }]);
  decoder.push(packets[0]); assert.throws(() => decoder.push(packets[1]), { code: 'error_event' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: 'error_event' });
});

for (const fields of [{ code: undefined }, { code: 1 }, { message: undefined }, { message: null }, { message: {} }, { param: undefined }, { param: false }])
test(`malformed flat error retains its existing failure code: ${JSON.stringify(fields)}`, () => {
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }), packets = wire([created(), { type: 'error', code: null, message: errorCanary, param: null, ...fields }]);
  decoder.push(packets[0]); assert.throws(() => decoder.push(packets[1]), { code: 'error_event' });
  assert.deepEqual(decoder.inspect(), { terminalKind: 'failed', failureCode: 'error_event' });
});

test('flat error still permits unexamined extra fields', () => {
  assert.equal(decode([created(), { type: 'error', code: null, message: errorCanary, param: errorCanary, detail: { value: errorCanary } }]).status, 'error');
});

for (const [shape, ending] of providerErrorEvents({ code: null, message: errorCanary, param: null }).slice(0, 2))
test(`${shape} error remains terminal and requires a created response`, () => {
  assert.throws(() => decode([ending]), { code: 'event_before_created' });
  assert.throws(() => decode([created(), ending, terminal([message()])]), { code: 'event_after_terminal' });
});

for (const [value, expected] of [[null, 'standard'], [{ cyber: 'standard' }, 'standard'], [{ cyber: 'daybreak_red' }, 'daybreak_red'], [undefined, 'unknown'], [{ cyber: 'other' }, 'unknown'], [{ cyber: 'daybreak_blue', extra: true }, 'unknown']]) test(`effective access program ${JSON.stringify(value)} is never inferred from requested Blue`, () => {
  const e = terminal([message()]); if (value === undefined) delete e.response.access_programs; else e.response.access_programs = value;
  assert.equal(decode([created(), e]).effectiveProgram, expected);
});

for (const [name, events] of [
  ['before created', [terminal([message()])]],
  ['duplicate created', [created(), created(), terminal([message()])]],
  ['different response id', [created(), { ...terminal([message()]), response: { ...terminal([message()]).response, id: 'different' } }]],
  ['model changed', [created(), { ...terminal([message()]), response: { ...terminal([message()]).response, model: 'other' } }]],
  ['named stream', [created(), { ...terminal([message()]), stream_id: 'named' }]],
  ['null stream', [created(), { ...terminal([message()]), stream_id: null }]],
  ['duplicate sequence', [created(), { ...terminal([message()]), sequence_number: 0 }]],
  ['unsafe sequence', [created(), { ...terminal([message()]), sequence_number: Number.MAX_SAFE_INTEGER + 1 }]],
  ['unknown event', [created(), { type: 'response.future' }, terminal([message()])]],
  ['duplicate terminal', [created(), terminal([call()]), terminal([call()])]],
  ['event after terminal', [created(), terminal([call()]), added(call())]],
  ['status mismatch', [created(), { ...terminal([message()]), response: { ...terminal([message()]).response, status: 'incomplete' } }]],
  ['completed error', [created(), { ...terminal([message()]), response: { ...terminal([message()]).response, error: { code: 'error' } } }]],
  ['completed incomplete details', [created(), { ...terminal([message()]), response: { ...terminal([message()]).response, incomplete_details: { reason: 'max_output_tokens' } } }]],
  ['duplicate index', [created(), added(call()), added(message()), terminal([call()])]],
  ['duplicate added id', [created(), added(call()), added(call(), 1), terminal([call()])]],
  ['duplicate added call', [created(), added(call()), added({ ...call(), id: 'other' }, 1), terminal([call()])]],
  ['done without added', [created(), done(call()), terminal([call()])]],
  ['duplicate done', [created(), added(call()), done(call()), done(call()), terminal([call()])]],
  ['done identity changed', [created(), added(call()), done({ ...call(), call_id: 'other' }), terminal([call()])]],
  ['terminal name changed', [created(), added(call()), terminal([{ ...call(), name: 'other' }])]],
  ['terminal dropped item', [created(), added(call()), terminal([message()])]],
  ['done terminal conflict', [created(), added(call()), done(call()), terminal([{ ...call(), arguments: '{}' }])]],
  ['progress unknown item', [created(), { type: 'response.output_text.delta', item_id: 'unknown', output_index: 0, delta: 'text' }, terminal([message()])]],
  ['progress after done', [created(), added(call()), done(call()), { type: 'response.function_call_arguments.delta', item_id: 'function_1', output_index: 0, delta: '{}' }, terminal([call()])]],
  ['unfinished fallback', [created(), added(call()), terminal(null)]],
  ['fallback index gap', [created(), added(call(), 1), done(call(), 1), terminal(null)]],
  ['interim inline output', [created(), { type: 'response.in_progress', response: { ...created().response, output: [call()] } }, terminal([call()])]],
]) test(`protocol rejects ${name} for the entire event list`, () => { assert.throws(() => decode(events)); });

test('byte and event bounds include exactly the complete wire sequence', () => {
  const events = [created(), terminal([message()])], count = wire(events).reduce((sum, bytes) => sum + bytes.length, 0);
  assert.equal(decode(events, { maxBytes: count, maxEvents: 2 }).status, 'completed');
  assert.throws(() => decode(events, { maxBytes: count - 1 })); assert.throws(() => decode(events, { maxEvents: 1 }));
});

test('malformed bytes, unfinished stream and finished decoder cannot recover into a usable response', () => {
  for (const invalid of [Buffer.from([0xff]), Buffer.from('{'), Buffer.from('null')]) {
    const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }); decoder.push(wire([created()])[0]);
    assert.throws(() => decoder.push(invalid)); assert.throws(() => decoder.finish()); assert.throws(() => decoder.push(wire([terminal([call()])])[0]));
  }
  const unfinished = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }); unfinished.push(wire([created()])[0]); assert.throws(() => unfinished.finish());
  const decoder = createResponseDecoder({ context, maxBytes: 65536, maxEvents: 64 }); for (const bytes of wire([created(), terminal([message()])])) decoder.push(bytes);
  assert.equal(decoder.finish().status, 'completed'); assert.throws(() => decoder.finish());
});

test('decoder owns context and parsed bytes after each push', () => {
  const host = { ...context }, decoder = createResponseDecoder({ context: host, maxBytes: 65536, maxEvents: 64 }), events = wire([created(), terminal([message()])]);
  decoder.push(events[0]); events[0].fill(0); host.callId = 'changed'; decoder.push(events[1]); events[1].fill(0);
  const result = decoder.finish(); assert.equal(result.callId, context.callId); assert.equal(projectResponseOutput(result.output).text, 'Synthetic final.');
});

for (const limits of [{ maxBytes: 0, maxEvents: 1 }, { maxBytes: 1, maxEvents: 0 }, { maxBytes: 1, maxEvents: -1 }]) test(`invalid decoder limits ${JSON.stringify(limits)}`, () => {
  assert.throws(() => createResponseDecoder({ context, ...limits }));
});
