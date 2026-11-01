import { performance } from 'node:perf_hooks';

const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const keys = ['version', 'runId', 'sequence', 'type', 'payload'];
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;

/** One bounded duplex pipe. Its owner, rather than peer text, chooses legal states. */
export function createHostedChannel(options) {
  const { input, output, runId, signal, expiresAt, onFrame, onFailure, onEnd } = options;
  const { maxFrameBytes, maxBytes, maxFrames } = options;
  if (!identifier(runId) || ![maxFrameBytes, maxBytes, maxFrames].every(positive) || maxFrameBytes > maxBytes || !Number.isFinite(expiresAt) || expiresAt - performance.now() > 2 ** 31 - 1 || ![onFrame, onFailure, onEnd].every(f => typeof f === 'function') || !signal || !input?.on || !output?.write) throw Error('ipc_options');
  const incoming = new Set(options.incomingTypes), outgoing = new Set(options.outgoingTypes);
  if (!incoming.size || !outgoing.size || [...incoming, ...outgoing].some(t => typeof t !== 'string' || !/^[a-z]+\.[A-Za-z]+$/.test(t))) throw Error('ipc_types');
  let failure, inputEnded = false, outputEnding = false, outputEnded = false;
  let inboundBytes = 0, outboundBytes = 0, inboundFrames = 0, outboundFrames = 0, writes = 0;
  let prefix = Buffer.alloc(0), resolveEnded, endingPromise;
  const pendingWrites = new Set(), ended = new Promise(resolve => { resolveEnded = resolve; });
  const rejectWrites = () => { for (const reject of pendingWrites) reject(Error(failure)); pendingWrites.clear(); };
  const fail = code => {
    if (!failure) {
      failure = /^[a-z_]+$/.test(code) ? code : 'ipc_failed'; rejectWrites();
      try { onFailure(failure); } catch {}
    }
  };
  const stop = () => {
    if (signal.aborted) fail('ipc_stopped');
    else if (performance.now() >= expiresAt) fail('ipc_deadline');
    if (failure) throw Error(failure);
  };
  const abort = () => fail('ipc_stopped');
  const timer = setTimeout(() => fail('ipc_deadline'), Math.max(1, Math.ceil(expiresAt - performance.now())));
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  input.on('data', chunk => {
    if (failure) return;
    try {
      stop();
      if (inputEnded || !Buffer.isBuffer(chunk)) throw Error('ipc_input');
      const copied = Buffer.from(chunk); inboundBytes += copied.length;
      if (!Number.isSafeInteger(inboundBytes) || inboundBytes > maxBytes) throw Error('ipc_byte_limit');
      let offset = 0;
      while (offset < copied.length) {
        stop();
        const end = copied.indexOf(10, offset), next = end < 0 ? copied.length : end;
        const part = copied.subarray(offset, next);
        if (prefix.length + part.length + 1 > maxFrameBytes) throw Error('ipc_frame_limit');
        prefix = Buffer.concat([prefix, part]);
        if (end < 0) break;
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(prefix); prefix = Buffer.alloc(0);
        const frame = JSON.parse(text);
        if (!plain(frame) || Object.keys(frame).length !== keys.length || keys.some(k => !Object.hasOwn(frame, k)) || frame.version !== 1 || frame.runId !== runId || !Number.isSafeInteger(frame.sequence) || frame.sequence !== inboundFrames + 1 || !incoming.has(frame.type)) throw Error('ipc_frame');
        if (++inboundFrames > maxFrames) throw Error('ipc_frame_count');
        stop(); onFrame(frame.type, frame.payload); stop(); offset = end + 1;
      }
    } catch (error) { fail(/^[a-z_]+$/.test(error.message) ? error.message : 'ipc_invalid'); }
  });
  input.on('error', () => fail('ipc_input_error'));
  input.on('close', () => { if (!inputEnded) { fail('ipc_input_closed'); resolveEnded(); } });
  input.on('end', () => {
    if (inputEnded) { fail('ipc_duplicate_end'); return; }
    inputEnded = true;
    if (prefix.length) fail('ipc_truncated');
    try { stop(); onEnd(); stop(); } catch (error) { fail(/^[a-z_]+$/.test(error.message) ? error.message : 'ipc_end'); }
    resolveEnded();
  });
  output.on('error', () => fail('ipc_output_error'));
  output.on('finish', () => { outputEnded = true; });
  output.on('close', () => { if (!outputEnded) fail('ipc_output_closed'); });
  return {
    fail,
    ended,
    async send(type, payload, control = {}) {
      stop(); if (outputEnding || !outgoing.has(type)) { fail('ipc_send_state'); throw Error(failure); }
      if (!plain(control) || Object.keys(control).some(k => k !== 'expiresAt') || Object.hasOwn(control, 'expiresAt') && !Number.isFinite(control.expiresAt)) { fail('ipc_send_deadline'); throw Error(failure); }
      const sendExpiresAt = Math.min(expiresAt, control.expiresAt ?? expiresAt);
      const sendStop = () => { stop(); if (performance.now() >= sendExpiresAt) { fail('ipc_deadline'); throw Error(failure); } };
      sendStop();
      let bytes;
      try { bytes = Buffer.from(JSON.stringify({ version: 1, runId, sequence: outboundFrames + 1, type, payload }) + '\n'); }
      catch { fail('ipc_serialize'); throw Error(failure); }
      if (payload === undefined || bytes.length > maxFrameBytes || outboundBytes + bytes.length > maxBytes || outboundFrames >= maxFrames) { fail('ipc_send_limit'); throw Error(failure); }
      sendStop(); outboundFrames++; outboundBytes += bytes.length; writes++;
      await new Promise((resolve, reject) => {
        let settled = false, writeTimer;
        const rejected = error => { if (!settled) { settled = true; clearTimeout(writeTimer); pendingWrites.delete(rejected); reject(error); } };
        pendingWrites.add(rejected);
        if (sendExpiresAt < expiresAt) writeTimer = setTimeout(() => fail('ipc_deadline'), Math.max(1, Math.ceil(sendExpiresAt - performance.now())));
        try {
          // A false return is backpressure. This exact write still owns its callback.
          output.write(bytes, error => {
            if (settled) return;
            if (error) { fail('ipc_write_failed'); return; }
            try { sendStop(); settled = true; clearTimeout(writeTimer); pendingWrites.delete(rejected); resolve(); }
            catch (error) { rejected(error); }
          });
        } catch { fail('ipc_write_failed'); }
      });
      sendStop();
    },
    async end() {
      stop();
      if (!outputEnding) {
        outputEnding = true;
        endingPromise = new Promise((resolve, reject) => {
          const rejected = error => { pendingWrites.delete(rejected); reject(error); };
          pendingWrites.add(rejected);
          try { output.end(error => { pendingWrites.delete(rejected); if (error) { fail('ipc_end_failed'); reject(Error('ipc_end_failed')); } else resolve(); }); }
          catch { fail('ipc_end_failed'); }
        });
      }
      await endingPromise; stop();
    },
    inspect: () => ({ failure: failure ?? null, inputEnded, outputEnded, inboundBytes, outboundBytes, inboundFrames, outboundFrames, writes, pendingWrites: pendingWrites.size }),
    dispose() { clearTimeout(timer); signal.removeEventListener('abort', abort); },
  };
}
