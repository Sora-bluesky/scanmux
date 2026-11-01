import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import { performance } from 'node:perf_hooks';
import { createHostedChannel } from '../internal/hosted-channel.mjs';

const frame = (sequence = 1, type = 'execution.request', payload = { text: '日本語\nline' }) => ({ version: 1, runId: 'run', sequence, type, payload });
const wire = value => Buffer.from(JSON.stringify(value) + '\n');
function fixture(t, changes = {}) {
  const input = new PassThrough(), writes = [], frames = [], failures = [], controller = new AbortController();
  const output = new Writable({ highWaterMark: 1, write(bytes, encoding, callback) { writes.push(Buffer.from(bytes)); callback(); } });
  const channel = createHostedChannel({ input, output, runId: 'run', signal: controller.signal, expiresAt: performance.now() + 10000, maxFrameBytes: 4096, maxBytes: 16384, maxFrames: 16, incomingTypes: ['execution.request', 'mcp.result', 'sdk.result'], outgoingTypes: ['mcp.start', 'mcp.recordDraft', 'execution.result'], onFrame: (type, payload) => frames.push({ type, payload }), onFailure: code => failures.push(code), onEnd: () => {}, ...changes });
  t.after(() => channel.dispose()); return { channel, input, output, writes, frames, failures, controller };
}

test('split UTF-8, escaped newline and multiple frames survive one bounded pipe', async t => {
  const f = fixture(t), packet = Buffer.concat([wire(frame()), wire(frame(2, 'mcp.result', { commandId: 1, result: {} }))]);
  for (const byte of packet) f.input.write(Buffer.from([byte]));
  f.input.end(); await f.channel.ended; await f.channel.end();
  assert.equal(f.failures.length, 0); assert.equal(f.frames.length, 2); assert.equal(f.frames[0].payload.text, '日本語\nline'); assert.equal(f.channel.inspect().inputEnded, true); assert.equal(f.channel.inspect().outputEnded, true);
});
test('single chunk may contain multiple frames larger than the individual frame cap', t => {
  const packet = wire(frame()), f = fixture(t, { maxFrameBytes: packet.length, maxBytes: packet.length * 2 });
  f.input.write(Buffer.concat([packet, wire(frame(2))])); assert.equal(f.frames.length, 2); assert.equal(f.channel.inspect().failure, null);
});
for (const [name, mutate] of [
  ['wrong version', x => { x.version = 2; }], ['wrong identity', x => { x.runId = 'other'; }],
  ['zero sequence', x => { x.sequence = 0; }], ['future sequence', x => { x.sequence = 2; }],
  ['unknown direction', x => { x.type = 'mcp.start'; }], ['extra envelope key', x => { x.extra = 1; }],
  ['missing payload', x => { delete x.payload; }], ['missing identity', x => { delete x.runId; }],
]) test(`reject ${name} before owner callback`, t => {
  const f = fixture(t), value = frame(); mutate(value); f.input.write(wire(value)); f.input.write(wire(frame())); assert.equal(f.frames.length, 0); assert.equal(f.failures.length, 1);
});
for (const [name, bytes] of [
  ['array', Buffer.from('[]\n')], ['null', Buffer.from('null\n')], ['blank', Buffer.from('\n')],
  ['invalid JSON', Buffer.from('{\n')], ['invalid UTF8', Buffer.from([0xff, 10])], ['BOM', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), wire(frame())])],
]) test(`reject raw ${name}`, t => { const f = fixture(t); f.input.write(bytes); assert.equal(f.frames.length, 0); assert.equal(f.failures.length, 1); });
test('duplicate frame poisons the channel and suppresses later valid frames', t => {
  const f = fixture(t); f.input.write(Buffer.concat([wire(frame()), wire(frame()), wire(frame(2))])); assert.equal(f.frames.length, 1); assert.equal(f.failures.length, 1);
});
test('owner rejects extra data after apparent terminal before EOF', async t => {
  let terminal = false;
  const f = fixture(t, { onFrame(type) { if (terminal) throw Error('ipc_after_terminal'); terminal = type === 'sdk.result'; } });
  f.input.write(Buffer.concat([wire(frame(1, 'sdk.result')), wire(frame(2, 'mcp.result'))])); f.input.end(); await f.channel.ended; assert.equal(f.channel.inspect().failure, 'ipc_after_terminal');
});
test('trailing partial frame is not a clean EOF', async t => { const f = fixture(t); f.input.end(wire(frame()).subarray(0, -1)); await f.channel.ended; assert.equal(f.channel.inspect().failure, 'ipc_truncated'); assert.equal(f.frames.length, 0); });
test('owner rejects early EOF even at frame boundary', async t => { const f = fixture(t, { onEnd() { throw Error('ipc_early_eof'); } }); f.input.end(); await f.channel.ended; assert.equal(f.channel.inspect().failure, 'ipc_early_eof'); });
test('close without end is not clean EOF', async t => { const f = fixture(t); f.input.emit('close'); await f.channel.ended; assert.equal(f.channel.inspect().failure, 'ipc_input_closed'); });
test('per-frame limit applies while a peer withholds newline', t => { const f = fixture(t, { maxFrameBytes: 10 }); f.input.write(Buffer.alloc(10, 32)); assert.equal(f.channel.inspect().failure, 'ipc_frame_limit'); assert.equal(f.frames.length, 0); });
test('aggregate byte limit applies across frames and chunks', t => { const packet = wire(frame()), f = fixture(t, { maxFrameBytes: packet.length, maxBytes: packet.length }); f.input.write(packet); f.input.write(wire(frame(2))); assert.equal(f.frames.length, 1); assert.equal(f.channel.inspect().failure, 'ipc_byte_limit'); });
test('frame-count limit stops before another owner callback', t => { const f = fixture(t, { maxFrames: 1 }); f.input.write(Buffer.concat([wire(frame()), wire(frame(2))])); assert.equal(f.frames.length, 1); assert.equal(f.channel.inspect().failure, 'ipc_frame_count'); });
test('backpressure causes one write and retains exact copied bytes', async t => {
  const f = fixture(t), payload = { text: '日本語' }; await f.channel.send('mcp.recordDraft', payload); payload.text = 'changed'; await f.channel.end(); await f.channel.end();
  assert.equal(f.writes.length, 1); assert.equal(f.channel.inspect().writes, 1); assert.deepEqual(JSON.parse(f.writes[0]), { version: 1, runId: 'run', sequence: 1, type: 'mcp.recordDraft', payload: { text: '日本語' } });
});
test('outgoing type, size and frame limits cause zero extra writes', async t => {
  const f = fixture(t, { maxFrames: 1 }); await f.channel.send('mcp.start', {}); await assert.rejects(f.channel.send('mcp.start', {}), /ipc_send_limit/); assert.equal(f.writes.length, 1);
  const g = fixture(t); await assert.rejects(g.channel.send('sdk.result', {}), /ipc_send_state/); assert.equal(g.writes.length, 0);
  const h = fixture(t, { maxFrameBytes: 10 }); await assert.rejects(h.channel.send('mcp.start', {}), /ipc_send_limit/); assert.equal(h.writes.length, 0);
});
test('preabort sends nothing', async t => { const f = fixture(t); f.controller.abort(); await assert.rejects(f.channel.send('mcp.start', {}), /ipc_stopped/); assert.equal(f.writes.length, 0); });
test('abort rejects a blocked write once and late callback cannot revive it', async t => {
  let callback, actual = 0;
  const output = new Writable({ write(bytes, encoding, done) { actual++; callback = done; } });
  const f = fixture(t, { output }), pending = f.channel.send('mcp.start', {}); f.controller.abort(); await assert.rejects(pending, /ipc_stopped/); callback(); await assert.rejects(f.channel.send('mcp.start', {}), /ipc_stopped/); assert.equal(actual, 1); assert.equal(f.channel.inspect().pendingWrites, 0);
});
test('write error and synchronous write throw never retry', async t => {
  let count = 0; const f = fixture(t, { output: new Writable({ write(bytes, encoding, callback) { count++; callback(Error('private raw error')); } }) });
  await assert.rejects(f.channel.send('mcp.start', {}), /ipc_write_failed/); assert.equal(count, 1); assert.deepEqual(f.failures, ['ipc_write_failed']);
  const g = fixture(t); g.output.write = () => { throw Error('private exception'); }; await assert.rejects(g.channel.send('mcp.start', {}), /ipc_write_failed/); assert.equal(g.channel.inspect().writes, 1);
});
test('synchronous serialization cannot send after the absolute deadline', async t => {
  const f = fixture(t, { expiresAt: performance.now() + 15 });
  await assert.rejects(f.channel.send('mcp.start', { get field() { const until = performance.now() + 25; while (performance.now() < until) {} return 1; } }), /ipc_deadline/); assert.equal(f.writes.length, 0);
});
test('narrower deadline also prevents a write after synchronous serialization', async t => {
  const f = fixture(t), expiresAt = performance.now() + 15;
  await assert.rejects(f.channel.send('mcp.start', { get field() { const until = performance.now() + 25; while (performance.now() < until) {} return 1; } }, { expiresAt }), /ipc_deadline/); assert.equal(f.writes.length, 0);
});
test('narrower deadline settles a blocked write even while the overall budget remains', async t => {
  let callback, count = 0; const output = new Writable({ write(bytes, encoding, done) { count++; callback = done; } });
  const f = fixture(t, { output }); await assert.rejects(f.channel.send('mcp.start', {}, { expiresAt: performance.now() + 15 }), /ipc_deadline/); callback(); assert.equal(count, 1); assert.equal(f.channel.inspect().pendingWrites, 0); await assert.rejects(f.channel.send('mcp.start', {}), /ipc_deadline/);
});
test('a wider local deadline cannot extend the overall deadline', async t => {
  const f = fixture(t, { expiresAt: performance.now() + 15 }); await assert.rejects(f.channel.send('mcp.start', { get value() { const until = performance.now() + 25; while (performance.now() < until) {} return 1; } }, { expiresAt: performance.now() + 1000 }), /ipc_deadline/); assert.equal(f.writes.length, 0);
});
for (const value of [NaN, Infinity]) test(`invalid local deadline ${value} sends nothing`, async t => { const f = fixture(t); await assert.rejects(f.channel.send('mcp.start', {}, { expiresAt: value }), /ipc_send_deadline/); assert.equal(f.writes.length, 0); });
test('synchronous owner work cannot deliver the next frame past deadline', t => {
  let received = 0;
  const f = fixture(t, { expiresAt: performance.now() + 15, onFrame() { received++; const until = performance.now() + 25; while (performance.now() < until) {} } });
  f.input.write(Buffer.concat([wire(frame()), wire(frame(2))])); assert.equal(received, 1); assert.equal(f.channel.inspect().failure, 'ipc_deadline');
});
for (const key of ['maxFrameBytes', 'maxBytes', 'maxFrames']) for (const value of [0, -1, Infinity, 0.5]) test(`reject invalid ${key}=${value}`, t => { assert.throws(() => fixture(t, { [key]: value }), /ipc_options/); });
