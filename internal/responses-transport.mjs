import WebSocket from 'ws';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createResponseDecoder } from './response-protocol.mjs';

const endpoint = 'wss://api.openai.com/v1/responses';
const identityKeys = ['runId', 'attemptId', 'buildId', 'requestId', 'scanId', 'snapshotHash'];
const optionKeys = ['bearerToken', 'maxRequests', 'maxRequestBytes', 'maxResponseBytes', 'maxEvents', 'timeoutMs', 'createSocket'];
const object = v => v !== null && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
const exact = (v, keys) => object(v) && Object.keys(v).every(k => keys.includes(k));
const positive = v => Number.isSafeInteger(v) && v > 0;
const id = v => typeof v === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(v);
const terminalTypes = new Set(['response.completed', 'response.failed', 'response.incomplete', 'error']);
class TransportError extends Error { constructor(code) { super(code); this.code = code; } }
const fail = code => { throw new TransportError(code); };

function describeKeys(value) {
  const names = Object.keys(value), keys = names.filter(key => /^[a-z][a-z0-9_]{0,39}$/.test(key)).sort().slice(0, 16);
  return { keys, otherKeys: names.length - keys.length };
}
function describeValue(value) {
  const type = value === undefined ? 'absent' : value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
  return { type, size: type === 'string' || type === 'array' ? value.length : type === 'object' ? Object.keys(value).length : null };
}
function describeEvent(data, values = false) {
  const shape = { kind: 'invalid_json', type: 'absent', keys: [], otherKeys: 0, sequenceNumber: 'absent', sequence: 'absent', streamId: 'absent', ...(values ? { valueShapes: {} } : {}) };
  let event;
  try { event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); } catch { return shape; }
  if (!object(event)) return { ...shape, kind: 'non_object' };
  const { keys, otherKeys } = describeKeys(event);
  const sequenceKind = key => !Object.hasOwn(event, key) ? 'absent' : Number.isInteger(event[key]) ? 'integer' : typeof event[key];
  return { kind: 'object', type: !Object.hasOwn(event, 'type') ? 'absent' : typeof event.type === 'string' && /^[a-z][a-z0-9_.]{0,63}$/.test(event.type) ? event.type : 'other',
    keys, otherKeys, sequenceNumber: sequenceKind('sequence_number'), sequence: sequenceKind('sequence'),
    streamId: !Object.hasOwn(event, 'stream_id') ? 'absent' : event.stream_id === null ? 'null' : 'present',
    ...(values ? { valueShapes: Object.fromEntries(keys.map(key => [key, { ...describeValue(event[key]),
      ...(key === 'response' && object(event[key]) ? { output: describeValue(event[key].output), statusType: describeValue(event[key].status).type } : {}),
      ...(key === 'safety_buffering' && object(event[key]) ? describeKeys(event[key]) : {}) }])) } : {}) };
}

/** Trusted host adapter. No credential loading, retry, persistence or CLI activation. */
export function createResponsesTransport(options) {
  if (!exact(options, optionKeys) || !['maxRequests', 'maxRequestBytes', 'maxResponseBytes', 'maxEvents', 'timeoutMs'].every(k => positive(options[k])) || options.timeoutMs > 2 ** 31 - 1 || options.maxResponseBytes > 2 ** 31 - 1) fail('invalid_transport_options');
  const { bearerToken, maxRequests, maxRequestBytes, maxResponseBytes, maxEvents, timeoutMs } = options;
  if (typeof bearerToken !== 'string' || !/^[\x21-\x7e]+$/.test(bearerToken) || Buffer.byteLength(bearerToken) > maxRequestBytes || options.createSocket !== undefined && typeof options.createSocket !== 'function') fail('invalid_transport_options');
  const createSocket = options.createSocket ?? ((url, settings) => new WebSocket(url, settings));
  const entries = new Map();
  let namespace = null, poisoned = false, active = null, connectionAttempts = 0, sendInvocations = 0, closeInvocations = 0;

  function validateContext(context) {
    if (!exact(context, ['identity', 'sessionId', 'callId', 'sequence', 'outputCap', 'signal']) || !Object.isFrozen(context) || !exact(context.identity, identityKeys) || !Object.isFrozen(context.identity) || identityKeys.some(k => !id(context.identity[k])) || !/^[a-f0-9]{64}$/.test(context.identity.snapshotHash) || !id(context.sessionId) || !id(context.callId) || !positive(context.sequence) || !positive(context.outputCap) || !(context.signal instanceof AbortSignal)) fail('invalid_transport_context');
    const key = [context.sessionId, ...identityKeys.map(k => context.identity[k])];
    if (namespace && key.some((part, i) => part !== namespace[i])) fail('transport_association');
    if (entries.has(context.callId)) fail('transport_replay');
    if (poisoned || active || context.sequence !== entries.size + 1 || entries.size >= maxRequests) fail('transport_unavailable');
    const previous = [...entries.values()].at(-1);
    if (previous && (!previous.closeTaken || !previous.quiescent)) fail('transport_unavailable');
    namespace ??= key;
  }

  async function submit(buffer, context) {
    const expiresAt = performance.now() + timeoutMs;
    try { validateContext(context); } catch (error) { throw new TransportError(error instanceof TransportError ? error.code : 'invalid_transport_context'); }
    const entry = { context, sequence: context.sequence, requestBytes: 0, requestSha256: null, connectionInvoked: false, sent: false, sendOk: false, closed: false, quiescent: false, closeCode: null, httpStatus: null, receivedBytes: 0, receivedMessages: 0, firstEvent: null, rejectedEvent: null, rejectedAt: null, terminal: false, terminalKind: 'none', failure: null, failureCode: null, outputIdentityMismatch: null, settled: false, stopped: false, forced: false, closeTaken: false };
    entries.set(context.callId, entry); active = entry;
    let copy;
    try {
      if (!Buffer.isBuffer(buffer) || !buffer.length || buffer.length > maxRequestBytes) fail('invalid_transport_request');
      copy = Buffer.from(buffer);
      const request = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(copy));
      if (!object(request) || request.type !== 'response.create' || request.model !== 'gpt-6-sol' || request.store !== false || !exact(request.access_programs, ['cyber']) || request.access_programs.cyber !== 'daybreak_blue' || request.max_output_tokens !== context.outputCap) fail('invalid_transport_request');
      entry.requestBytes = copy.length; entry.requestSha256 = createHash('sha256').update(copy).digest('hex');
      if (context.signal.aborted || performance.now() >= expiresAt) fail(context.signal.aborted ? 'transport_canceled' : 'transport_deadline');
    } catch (error) {
      entry.failure = error instanceof TransportError ? error.code : 'invalid_transport_request'; entry.closed = true; entry.quiescent = true; entry.stopped = true; entry.settled = true; active = null; poisoned = true;
      entry.failureCode = entry.failure;
      throw new TransportError(entry.failure);
    }
    const decoder = createResponseDecoder({ context: { sessionId: context.sessionId, callId: context.callId, requestId: context.identity.requestId }, maxBytes: maxResponseBytes, maxEvents });
    return new Promise((resolve, reject) => {
      let socket, timer, opened = false, closeRequested = false, sendCallbackSeen = false, protocolBroken = false, abandoned = false;
      const settle = (code, receipt) => {
        if (entry.settled) return;
        entry.settled = true; clearTimeout(timer); context.signal.removeEventListener('abort', onAbort);
        if (receipt) resolve(receipt); else reject(new TransportError(code ?? 'transport_incomplete'));
      };
      const stop = (code, immediately = false) => {
        if (entry.settled) return;
        entry.stopped = true; entry.failure ??= code; entry.failureCode ??= code; poisoned = true;
        if (immediately) abandoned = true;
        if (socket) { entry.forced = true; try { socket.terminate(); } catch {} }
        else if (!entry.connectionInvoked) { entry.closed = true; entry.quiescent = true; active = null; }
        if (immediately) settle(entry.failure);
      };
      const invalidateStream = code => { if (entry.settled) return; protocolBroken = true; stop(code); };
      entry.stop = stop;
      function onAbort() { stop('transport_canceled', true); }
      const withinDeadline = () => {
        if (entry.settled || entry.stopped) return false;
        if (context.signal.aborted || performance.now() >= expiresAt) { stop(context.signal.aborted ? 'transport_canceled' : 'transport_deadline', true); return false; }
        return true;
      };
      function onUpgrade(response) {
        if (!withinDeadline()) return;
        if (entry.httpStatus !== null || response.statusCode !== 101) { stop('transport_handshake'); return; }
        entry.httpStatus = 101;
      }
      function onOpen() {
        if (!withinDeadline()) return;
        if (opened || entry.sent || entry.httpStatus !== 101) { stop('transport_dispatch'); return; }
        opened = true;
        if (!withinDeadline()) return;
        entry.sent = true; sendInvocations++;
        try {
          socket.send(copy, { binary: false, compress: false }, error => {
            if (entry.settled) return;
            if (sendCallbackSeen || error != null) { stop('transport_send'); return; }
            sendCallbackSeen = true; entry.sendOk = true;
          });
        } catch { stop('transport_send'); }
      }
      function onMessage(data, binary) {
        entry.firstEvent ??= describeEvent(data);
        if (!withinDeadline()) return;
        try {
          if (!entry.sent || binary || !Buffer.isBuffer(data)) fail('transport_protocol');
          entry.receivedBytes += data.length; entry.receivedMessages++;
          try { decoder.push(data); } catch (error) {
            if (entry.rejectedEvent === null) { entry.rejectedEvent = describeEvent(data, true); entry.rejectedAt = entry.receivedMessages; }
            throw error;
          }
          const type = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)).type;
          if (terminalTypes.has(type)) { entry.terminal = true; closeRequested = true; socket.close(1000); }
        } catch {
          entry.failureCode ??= decoder.inspect().failureCode ?? 'transport_protocol';
          invalidateStream('transport_protocol');
        } finally {
          const { terminalKind, providerErrorCode, incompleteReason, outputIdentityMismatch } = decoder.inspect(); entry.terminalKind = terminalKind;
          entry.outputIdentityMismatch = outputIdentityMismatch ?? null;
          if (providerErrorCode !== undefined) entry.providerErrorCode = providerErrorCode;
          if (incompleteReason !== undefined) entry.incompleteReason = incompleteReason;
        }
      }
      function onError(error) {
        if (entry.settled) return;
        entry.failureCode ??= error?.code === 'WS_ERR_UNSUPPORTED_MESSAGE_LENGTH' ? 'message_too_large' : 'socket_error';
        invalidateStream('transport_socket');
      }
      function onUnexpected(request, response) {
        if (entry.settled) return;
        entry.httpStatus = Number.isInteger(response.statusCode) && response.statusCode >= 100 && response.statusCode <= 599 ? response.statusCode : null;
        try { request.destroy(); } catch {} try { response.destroy(); } catch {}
        stop('transport_handshake');
      }
      const detach = () => {
        socket.removeListener('upgrade', onUpgrade); socket.removeListener('open', onOpen); socket.removeListener('message', onMessage); socket.removeListener('unexpected-response', onUnexpected); socket.removeListener('close', onClose);
        // Keep the bounded error listener for late native cleanup errors.
      };
      function onClose(code) {
        if (entry.closed) return;
        entry.closed = true; entry.closeCode = Number.isInteger(code) && code >= 1000 && code <= 4999 ? code : null; active = null;
        detach();
        if (entry.settled) return;
        if (context.signal.aborted || performance.now() >= expiresAt) { entry.failure ??= context.signal.aborted ? 'transport_canceled' : 'transport_deadline'; abandoned = true; }
        let receipt;
        if (!abandoned && !protocolBroken && entry.terminal) { try { receipt = decoder.finish(); } catch { entry.failure ??= 'transport_protocol'; } }
        entry.failureCode ??= decoder.inspect().failureCode;
        entry.quiescent = !entry.sent || Boolean(receipt && !entry.failure && !entry.forced && entry.sendOk && closeRequested && entry.httpStatus === 101 && code === 1000);
        if (!receipt) entry.failure ??= 'transport_incomplete';
        if (entry.failure) entry.failureCode ??= entry.failure === 'transport_incomplete' ? 'early_eof' : entry.failure;
        else if (!entry.quiescent) entry.failureCode ??= !entry.sendOk ? 'send_unverified' : 'abnormal_close';
        if (entry.failure || !entry.quiescent) poisoned = true;
        settle(entry.failure, receipt);
      }
      context.signal.addEventListener('abort', onAbort, { once: true });
      timer = setTimeout(() => stop('transport_deadline', true), Math.max(1, Math.ceil(expiresAt - performance.now())));
      if (!withinDeadline()) return;
      const remaining = Math.max(1, Math.ceil(expiresAt - performance.now()));
      try {
        entry.connectionInvoked = true; connectionAttempts++;
        socket = createSocket(endpoint, { headers: { authorization: `Bearer ${bearerToken}` }, followRedirects: false, perMessageDeflate: false, rejectUnauthorized: true, skipUTF8Validation: false, maxPayload: maxResponseBytes, handshakeTimeout: remaining, closeTimeout: remaining });
        socket.on('error', onError); socket.on('close', onClose); socket.on('upgrade', onUpgrade); socket.on('open', onOpen); socket.on('message', onMessage); socket.on('unexpected-response', onUnexpected);
        if (entry.stopped || entry.settled) { entry.forced = true; try { socket.terminate(); } catch {} return; }
        withinDeadline();
      } catch { entry.failure ??= 'transport_setup'; entry.failureCode ??= entry.failure; poisoned = true; entry.stopped = true; abandoned = true; if (socket) { entry.forced = true; try { socket.terminate(); } catch {} } settle(entry.failure); }
    });
  }

  function close(context) {
    closeInvocations++;
    const entry = [...entries.values()].find(value => value.context === context);
    if (!entry || entry.closeTaken) return { closed: false, quiescent: false };
    entry.closeTaken = true;
    if (!entry.closed && !entry.settled) entry.stop?.('transport_closed_early', true);
    return { closed: entry.closed, quiescent: entry.quiescent };
  }

  function inspect() {
    return { connectionAttempts, sendInvocations, closeInvocations, automaticRetries: 0, httpFallbacks: 0, calls: [...entries.values()].map(e => ({ sequence: e.sequence, requestBytes: e.requestBytes, requestSha256: e.requestSha256, sent: e.sent, sendOk: e.sendOk, closed: e.closed, quiescent: e.quiescent, closeCode: e.closeCode, httpStatus: e.httpStatus, receivedBytes: e.receivedBytes, receivedMessages: e.receivedMessages, firstEvent: structuredClone(e.firstEvent),
      rejectedEvent: structuredClone(e.rejectedEvent), rejectedAt: e.rejectedAt, terminal: e.terminal, terminalKind: e.terminalKind, failure: e.failure, failureCode: e.failureCode, outputIdentityMismatch: e.outputIdentityMismatch === null ? null : { ...e.outputIdentityMismatch },
      ...(e.providerErrorCode === undefined ? {} : { providerErrorCode: e.providerErrorCode }), ...(e.incompleteReason === undefined ? {} : { incompleteReason: e.incompleteReason }) })) };
  }
  return Object.freeze({ submit, close, inspect });
}
