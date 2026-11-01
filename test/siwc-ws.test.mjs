import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { once } from 'node:events';
import WebSocket, { WebSocketServer } from 'ws';
import { request, runWsProbe } from '../scripts/verify-daybreak-ws.mjs';
import { issuer, scopes } from '../scripts/siwc-auth.mjs';
import { SiwcError } from '../scripts/siwc-storage.mjs';

const registration = { clientId: 'oaiapp_synthetic' };
const credentials = () => ({ schema: 1, state: 'active', issuer, clientId: registration.clientId, subject: 'synthetic', accessToken: 'synthetic-access', refreshToken: 'synthetic-refresh', idToken: 'synthetic-id', scopes, expiresAt: Date.now() + 3600000 });
const limits = { timeoutMs: 1000, maxOutputBytes: 8192 };
const terminal = (change = {}) => ({ type: 'response.completed', response: { id: 'resp_synthetic', status: 'completed', model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, usage: { input_tokens: 17, output_tokens: 11, total_tokens: 28 }, ...change } });
class Store {
  constructor(files = {}) { this.files = structuredClone(files); }
  async read(name) { return this.files[name] ?? null; }
  async write(name, value, exclusive) {
    if (exclusive && Object.hasOwn(this.files, name)) throw new SiwcError('operation_already_recorded');
    this.files[name] = structuredClone(value);
  }
}
function mock(onSend, options = {}) {
  const calls = { connect: 0, send: 0, close: 0, terminate: 0, requestDestroyed: false, responseDestroyed: false };
  class Socket extends EventEmitter {
    constructor(url, opts) {
      super(); calls.connect++; calls.url = url; calls.options = opts;
      queueMicrotask(() => {
        if (options.handshake) this.emit('unexpected-response', { destroy() { calls.requestDestroyed = true; } }, { statusCode: options.handshake, headers: {}, destroy() { calls.responseDestroyed = true; } });
        else { this.emit('upgrade', { statusCode: 101, headers: { 'x-request-id': 'req_fixture' } }); if (!options.neverOpen) this.emit('open'); }
      });
    }
    send(body, callback) {
      calls.send++; assert.deepEqual(JSON.parse(body), request);
      callback(options.sendError ? new Error('synthetic') : undefined);
      if (!options.sendError) queueMicrotask(() => onSend?.(this));
    }
    event(value) { this.emit('message', Buffer.from(JSON.stringify(value)), false); }
    close(code) { calls.close++; if (options.lateEvent) this.event({ type: 'response.output_text.delta', delta: 'synthetic' }); if (!options.neverClose) queueMicrotask(() => this.emit('close', options.closeCode ?? code)); }
    terminate() { calls.terminate++; queueMicrotask(() => this.emit('close', 1006)); }
  }
  return { Socket, calls };
}
async function run(onSend, socketOptions = {}, probeOptions = {}) {
  const m = mock(onSend, socketOptions), store = new Store();
  const proof = await runWsProbe(store, credentials(), registration, { Socket: m.Socket, limits, ...probeOptions });
  return { proof, store, ...m };
}

test('one fixed request waits for successful terminal and client-initiated normal close', async () => {
  const result = await run(socket => { socket.event({ type: 'response.created', response: { id: 'resp_synthetic' } }); socket.event({ type: 'response.output_text.delta', item_id: 'msg_fixture', delta: 'synthetic' }); socket.event(terminal()); });
  assert.equal(result.proof.state, 'BLUE_VERIFIED');
  assert.deepEqual(result.proof.usage, { input: 17, output: 11, total: 28, cachedInput: null, reasoningOutput: null });
  assert.equal(result.calls.connect, 1); assert.equal(result.calls.send, 1); assert.equal(result.calls.close, 1); assert.equal(result.calls.terminate, 0);
  assert.equal(result.calls.url, 'wss://api.openai.com/v1/responses');
  assert.deepEqual(result.calls.options, { headers: { authorization: 'Bearer synthetic-access' }, followRedirects: false, perMessageDeflate: false, maxPayload: limits.maxOutputBytes, handshakeTimeout: limits.timeoutMs });
  assert.equal(result.store.files['probe-attempt.json'].state, 'finished');
  await assert.rejects(runWsProbe(result.store, credentials(), registration, { Socket: result.Socket }), { code: 'probe_already_attempted' });
  assert.equal(result.calls.connect, 1);
});

test('standard, missing program, model mismatch and invalid usage never pass', async () => {
  for (const [change, code] of [
    [{ access_programs: { cyber: 'standard' } }, 'effective_blue_unverified'],
    [{ access_programs: null }, 'effective_blue_unverified'],
    [{ model: 'gpt-6-astra' }, 'effective_model_mismatch'],
    [{ model: 'gpt-6-sol-2026-02-30' }, 'effective_model_mismatch'],
    [{ usage: { input_tokens: 1, output_tokens: 1, total_tokens: 3 } }, 'response_usage_unverified'],
    [{ usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2, input_tokens_details: { cached_tokens: 2 } } }, 'response_usage_unverified'],
  ]) {
    const { proof } = await run(socket => socket.event(terminal(change)));
    assert.equal(proof.state, 'INCOMPLETE'); assert.equal(proof.error, code); assert.equal(proof.closed, true);
  }
});

test('mismatched identities, malformed/binary/oversize messages and failed events close without retry', async () => {
  const cases = [
    [s => { s.event({ type: 'response.created', response: { id: 'resp_other' } }); s.event(terminal()); }, 'response_identity_mismatch'],
    [s => s.emit('message', Buffer.from([0xff]), false), 'invalid_websocket_event'],
    [s => s.emit('message', Buffer.from('{}'), true), 'binary_websocket_message'],
    [s => s.emit('message', Buffer.alloc(8193, 32), false), 'websocket_output_limit'],
    [s => s.event({ type: 'response.failed', response: { id: 'resp_synthetic', error: { code: 'subscription_sharing_usage_limit_exceeded' } } }), 'subscription_sharing_usage_limit_exceeded'],
    [s => s.emit('close', 1000), 'response_not_completed'],
  ];
  for (const [operation, code] of cases) {
    const { proof, calls } = await run(operation);
    assert.equal(proof.state, 'INCOMPLETE'); assert.equal(proof.error, code); assert.equal(proof.closed, true); assert.equal(calls.send, 1); assert.equal(calls.connect, 1);
  }
  const { proof } = await run(s => { s.event({ type: 'response.output_text.delta', delta: 'x'.repeat(5000) }); s.event({ type: 'response.output_text.delta', delta: 'x'.repeat(5000) }); });
  assert.equal(proof.error, 'websocket_output_limit');
});

test('terminal is provisional until close; late events and abnormal close preserve usage but reject success', async () => {
  for (const options of [{ lateEvent: true }, { closeCode: 1006 }, { neverClose: true }]) {
    const { proof } = await run(s => s.event(terminal()), options, { limits: { ...limits, timeoutMs: 10 } });
    assert.equal(proof.state, 'INCOMPLETE'); assert.equal(proof.completedEvent, true); assert.equal(proof.accessProgramEffective, 'daybreak_blue'); assert.equal(proof.usage.total, 28); assert.equal(proof.closed, true);
    assert.ok(proof.error);
  }
});

test('pre-connect/handshake/in-flight abort, timeout and send failure do not resend', async () => {
  const aborted = AbortSignal.abort(); const m = mock();
  const proof = await runWsProbe(new Store(), credentials(), registration, { signal: aborted, Socket: m.Socket, limits });
  assert.equal(proof.error, 'operation_aborted'); assert.equal(m.calls.connect, 0);
  for (const socketOptions of [{ neverOpen: true }, {}, { sendError: true }, { handshake: 401 }, { handshake: 302 }]) {
    const { proof, calls } = await run(undefined, socketOptions, { limits: { ...limits, timeoutMs: 10 } });
    assert.equal(proof.state, 'INCOMPLETE'); assert.equal(proof.closed, true); assert.equal(calls.connect, 1); assert.ok(calls.send <= 1); assert.ok(calls.terminate > 0);
    if (socketOptions.handshake) { assert.equal(calls.requestDestroyed, true); assert.equal(calls.responseDestroyed, true); assert.equal(calls.send, 0); }
  }
  const controller = new AbortController();
  const result = await run(() => controller.abort(), {}, { signal: controller.signal });
  assert.equal(result.proof.error, 'operation_aborted'); assert.equal(result.proof.closed, true);
});

test('existing or partial markers and invalid credentials prevent connection', async () => {
  for (const marker of [{ state: 'dispatch_pending' }, { state: 'finished' }, null]) {
    const m = mock();
    await assert.rejects(runWsProbe(new Store({ 'probe-attempt.json': marker }), credentials(), registration, { Socket: m.Socket }));
    assert.equal(m.calls.connect, 0);
  }
  const m = mock();
  await assert.rejects(runWsProbe(new Store(), { ...credentials(), expiresAt: 0 }, registration, { Socket: m.Socket }), { code: 'credentials_expired' });
  assert.equal(m.calls.connect, 0);
});

test('real loopback WebSocket normal completion and timeout both observe socket closure', async () => {
  for (const respond of [true, false]) {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening'); let count = 0; let peerClosed;
    server.on('connection', socket => {
      peerClosed = once(socket, 'close');
      socket.on('message', data => { count++; assert.deepEqual(JSON.parse(data.toString()), request); if (respond) socket.send(JSON.stringify(terminal())); });
    });
    class LocalSocket extends WebSocket { constructor(_url, opts) { super(`ws://127.0.0.1:${server.address().port}`, opts); } }
    try {
      const proof = await runWsProbe(new Store(), credentials(), registration, { Socket: LocalSocket, limits: { ...limits, timeoutMs: respond ? 1000 : 100 } });
      assert.equal(proof.state, respond ? 'BLUE_VERIFIED' : 'INCOMPLETE', JSON.stringify(proof)); assert.equal(proof.closed, true); assert.equal(count, 1);
    } finally { await new Promise(resolve => server.close(resolve)); }
    assert.ok(peerClosed); await peerClosed;
  }
});
