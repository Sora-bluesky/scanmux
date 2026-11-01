import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import WebSocket from 'ws';
import { openStore, repositoryRoot, SiwcError, errorCode } from './siwc-storage.mjs';
import { usableCredentials, defaultLimits } from './siwc-auth.mjs';

export const request = Object.freeze({
  type: 'response.create', model: 'gpt-6-sol', access_programs: Object.freeze({ cyber: 'daybreak_blue' }),
  store: false, input: Object.freeze([Object.freeze({ role: 'user', content: 'Reply exactly: SCANMUX_DAYBREAK_PROBE_OK' })]),
});
const endpoint = 'wss://api.openai.com/v1/responses';
const responseId = value => typeof value === 'string' && /^resp_[A-Za-z0-9_-]{1,160}$/u.test(value);
const safeRequestId = value => typeof value === 'string' && /^(?:req_[A-Za-z0-9_-]{1,160}|[0-9a-f]{8}-[0-9a-f-]{27})$/iu.test(value) ? value : null;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const knownCodes = new Set(['invalid_access_program', 'unsupported_access_program', 'access_program_not_enabled', 'subscription_sharing_user_not_eligible', 'subscription_sharing_usage_limit_exceeded', 'subscription_sharing_usage_unavailable', 'subscription_sharing_unsupported_capability', 'subscription_sharing_route_not_supported', 'model_not_found', 'rate_limit_exceeded']);

function acceptCompleted(terminal, proof) {
  if (terminal.status !== 'completed' || terminal.error != null) throw new SiwcError('response_not_completed');
  proof.completedEvent = true; proof.responseId = terminal.id;
  const model = terminal.model;
  const dated = typeof model === 'string' && /^gpt-6-sol-\d{4}-\d{2}-\d{2}$/u.test(model);
  const validDate = dated && Number.isFinite(Date.parse(model.slice(-10))) && new Date(model.slice(-10)).toISOString().slice(0, 10) === model.slice(-10);
  proof.modelActual = model === 'gpt-6-sol' || validDate ? model : 'unexpected';
  const program = terminal.access_programs?.cyber;
  proof.accessProgramEffective = ['standard', 'daybreak_blue', 'daybreak_red'].includes(program) ? program : 'unknown';
  const usage = terminal.usage;
  if (!usage || !['input_tokens', 'output_tokens', 'total_tokens'].every(k => Number.isSafeInteger(usage[k]) && usage[k] >= 0)
    || usage.total_tokens !== usage.input_tokens + usage.output_tokens) throw new SiwcError('response_usage_unverified');
  const cached = usage.input_tokens_details?.cached_tokens;
  const reasoning = usage.output_tokens_details?.reasoning_tokens;
  if ((cached !== undefined && (!Number.isSafeInteger(cached) || cached < 0 || cached > usage.input_tokens))
    || (reasoning !== undefined && (!Number.isSafeInteger(reasoning) || reasoning < 0 || reasoning > usage.output_tokens))) throw new SiwcError('response_usage_unverified');
  proof.usage = { input: usage.input_tokens, output: usage.output_tokens, total: usage.total_tokens, cachedInput: cached ?? null, reasoningOutput: reasoning ?? null };
  if (proof.modelActual === 'unexpected') throw new SiwcError('effective_model_mismatch');
  if (proof.accessProgramEffective !== 'daybreak_blue') throw new SiwcError('effective_blue_unverified');
}

export async function runWsProbe(store, credentials, registration, { signal, limits = defaultLimits, sources = [], Socket = WebSocket } = {}) {
  usableCredentials(credentials, registration);
  if (await store.read('probe-attempt.json')) throw new SiwcError('probe_already_attempted');
  const attemptId = randomUUID();
  await store.write('probe-attempt.json', { schema: 1, attemptId, state: 'dispatch_pending', createdAt: new Date().toISOString(), sources }, true);
  const proof = {
    schema: 'scanmux.daybreak-websocket-proof/v1', attemptId, state: 'INCOMPLETE', authentication: 'chatgpt_plan_oauth',
    modelRequested: request.model, modelActual: 'unknown', accessProgramRequested: 'daybreak_blue', accessProgramEffective: 'unknown',
    requestBodyHash: hash(JSON.stringify(request)), requestId: null, responseId: null, usage: null,
    connections: 0, inferenceRequests: 0, automaticRetries: 0, httpFallbacks: 0, handshakeStatus: null, receivedBytes: 0,
    completedEvent: false, closeRequested: false, closed: false, closeCode: null, terminated: false,
    verificationRecommendationPresent: false, moderationMetadataPresent: false, responseModelHeaderPresent: false,
    codeExecution: 'not_checked', productionIntegration: 'not_started', cost: 'N/A', allowance: 'unknown', error: null, sources,
  };
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), limits.timeoutMs);
  const combined = signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal;
  let socket, terminal = false, identity;
  const fail = code => { proof.error ??= code; };
  try {
    if (combined.aborted) throw new SiwcError('operation_aborted');
    await new Promise(resolve => {
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true; combined.removeEventListener('abort', stop); resolve();
      };
      const terminate = code => {
        fail(code); proof.terminated = true;
        if (socket) socket.terminate(); else finish();
      };
      const stop = () => terminate('operation_aborted');
      combined.addEventListener('abort', stop, { once: true });
      try {
        proof.connections = 1;
        socket = new Socket(endpoint, { headers: { authorization: `Bearer ${credentials.accessToken}` },
          followRedirects: false, perMessageDeflate: false, maxPayload: limits.maxOutputBytes, handshakeTimeout: limits.timeoutMs });
      } catch { fail('websocket_setup_failed'); finish(); return; }
      socket.on('upgrade', response => {
        proof.handshakeStatus = response.statusCode === 101 ? 101 : null;
        proof.requestId = safeRequestId(response.headers['x-request-id'] ?? response.headers['openai-request-id']);
      });
      socket.on('unexpected-response', (req, response) => {
        proof.handshakeStatus = Number.isInteger(response.statusCode) && response.statusCode >= 100 && response.statusCode <= 599 ? response.statusCode : null;
        proof.requestId = safeRequestId(response.headers['x-request-id'] ?? response.headers['openai-request-id']);
        fail('websocket_handshake_rejected'); req.destroy(); response.destroy(); terminate('websocket_handshake_rejected');
      });
      socket.on('open', () => {
        if (combined.aborted || proof.error || proof.inferenceRequests) { terminate('websocket_dispatch_rejected'); return; }
        proof.inferenceRequests = 1;
        try { socket.send(JSON.stringify(request), error => { if (error) terminate('websocket_send_failed'); }); }
        catch { terminate('websocket_send_failed'); }
      });
      socket.on('message', (data, binary) => {
        if (proof.error && !terminal) return;
        try {
          if (combined.aborted) throw new SiwcError('operation_aborted');
          if (terminal) throw new SiwcError('event_after_completion');
          if (binary) throw new SiwcError('binary_websocket_message');
          const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
          proof.receivedBytes += bytes.length;
          if (proof.receivedBytes > limits.maxOutputBytes) throw new SiwcError('websocket_output_limit');
          const event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          if (!event || typeof event !== 'object' || typeof event.type !== 'string') throw new SiwcError('invalid_websocket_event');
          for (const value of [event.response?.id, event.response_id]) {
            if (value !== undefined) {
              if (!responseId(value) || identity && value !== identity) throw new SiwcError('response_identity_mismatch');
              identity = value;
            }
          }
          const metadata = event.response?.metadata?.metadata;
          proof.verificationRecommendationPresent ||= metadata?.openai_verification_recommendation != null;
          proof.moderationMetadataPresent ||= metadata?.openai_chatgpt_moderation_metadata != null;
          for (const headers of [event.headers, event.response?.headers]) {
            if (headers && typeof headers === 'object') proof.responseModelHeaderPresent ||= Object.keys(headers).some(key => key.toLowerCase() === 'openai-model');
          }
          if (['error', 'response.failed', 'response.incomplete'].includes(event.type)) {
            const code = event.response?.error?.code ?? event.error?.code ?? event.code;
            throw new SiwcError(knownCodes.has(code) ? code : 'response_not_completed');
          }
          if (event.type === 'response.completed') {
            if (!responseId(event.response?.id) || identity !== event.response.id) throw new SiwcError('response_identity_mismatch');
            terminal = true;
            try { acceptCompleted(event.response, proof); } catch (error) { fail(errorCode(error)); }
            proof.closeRequested = true; socket.close(1000);
          }
        } catch (error) { terminate(errorCode(error) === 'operation_failed' ? 'invalid_websocket_event' : errorCode(error)); }
      });
      socket.on('error', () => terminate('websocket_transport_failed'));
      socket.on('close', code => {
        proof.closed = true; proof.closeCode = Number.isInteger(code) && code >= 1000 && code <= 4999 ? code : null;
        if (!terminal) fail('response_not_completed');
        if (!proof.closeRequested || code !== 1000 || proof.terminated) fail('websocket_close_unverified');
        finish();
      });
      if (combined.aborted) stop();
    });
    if (combined.aborted) fail('operation_aborted');
    if (!proof.closed || !proof.closeRequested || proof.closeCode !== 1000 || proof.terminated) fail('websocket_close_unverified');
    if (!proof.error && proof.completedEvent && proof.inferenceRequests === 1 && proof.handshakeStatus === 101) proof.state = 'BLUE_VERIFIED';
  } catch (error) { fail(errorCode(error)); }
  finally { clearTimeout(timer); }
  proof.finishedAt = new Date().toISOString();
  await store.write('probe-result.json', proof);
  await store.write('probe-attempt.json', { schema: 1, attemptId, state: 'finished', result: proof.state, finishedAt: proof.finishedAt, sources });
  return proof;
}

async function main() {
  if (process.argv.length !== 2) throw new SiwcError('invalid_probe_command');
  const controller = new AbortController(), stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  const credentialsStore = await openStore();
  let store, output;
  try {
    const sources = [];
    for (const file of ['scripts/verify-daybreak-ws.mjs', 'scripts/siwc-auth.mjs', 'scripts/siwc-storage.mjs', 'package.json', 'package-lock.json', 'node_modules/ws/package.json']) {
      const bytes = await fs.readFile(path.join(repositoryRoot, file)); sources.push({ path: file, bytes: bytes.length, sha256: hash(bytes) });
    }
    const ws = JSON.parse(await fs.readFile(path.join(repositoryRoot, 'node_modules/ws/package.json'), 'utf8'));
    if (ws.name !== 'ws' || ws.version !== '8.22.0') throw new SiwcError('dependency_pin_mismatch');
    const registration = await credentialsStore.read('registration.json');
    const credentials = usableCredentials(await credentialsStore.read('credentials.json'), registration);
    store = await openStore(path.join(repositoryRoot, '.local', 'siwc-ws-private'));
    output = await runWsProbe(store, credentials, registration, { signal: controller.signal, sources });
  } finally {
    await store?.close(); await credentialsStore.close();
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  }
  process.stdout.write(JSON.stringify(output) + '\n');
  process.exitCode = output.state === 'BLUE_VERIFIED' ? 0 : 3;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => { process.stderr.write(JSON.stringify({ state: 'ERROR', error: errorCode(error) }) + '\n'); process.exitCode = 4; });
}
