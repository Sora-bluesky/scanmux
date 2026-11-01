import fs from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import OpenAI from 'openai';
import { openStore, repositoryRoot, SiwcError, errorCode } from './siwc-storage.mjs';
import { authenticate, usableCredentials, discover, endpoints, publicJson, defaultLimits, readBounded, abortable } from './siwc-auth.mjs';

export const probeRequest = Object.freeze({
  model: 'gpt-6-sol', access_programs: Object.freeze({ cyber: 'daybreak_blue' }), store: false, stream: true,
  input: Object.freeze([Object.freeze({ role: 'user', content: 'Reply exactly: SCANMUX_DAYBREAK_PROBE_OK' })]),
});
const endpoint = 'https://api.openai.com/v1/responses';
const knownErrors = new Set([
  'invalid_access_program', 'unsupported_access_program', 'access_program_not_enabled',
  'subscription_sharing_user_not_eligible', 'subscription_sharing_usage_limit_exceeded',
  'subscription_sharing_usage_unavailable', 'subscription_sharing_unsupported_capability',
  'subscription_sharing_route_not_supported', 'subscription_sharing_invalid_user',
  'chatpass_v2_scope_not_authorized', 'chatpass_v2_invalid_authorization_context',
  'subscription_sharing_user_unavailable', 'model_not_found', 'rate_limit_exceeded',
]);
const responseId = value => typeof value === 'string' && /^resp_[A-Za-z0-9_-]{1,160}$/u.test(value);
const safeRequestId = value => typeof value === 'string' && /^(?:req_[A-Za-z0-9_-]{1,160}|[0-9a-f]{8}-[0-9a-f-]{27})$/iu.test(value) ? value : null;
const compatibleModel = value => {
  if (value === 'gpt-6-sol') return true;
  if (typeof value !== 'string' || !/^gpt-6-sol-\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const day = value.slice(-10); const date = new Date(day);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === day;
};

export function validateSseEnvelope(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\r\n/gu, '\n');
  if (text.includes('\r') || !text.endsWith('\n\n')) throw new SiwcError('sse_incomplete_frame');
  let done = false;
  for (const frame of text.split('\n\n')) {
    if (!frame) continue;
    const data = [];
    for (const line of frame.split('\n')) {
      if (!line || line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const key = colon < 0 ? line : line.slice(0, colon);
      const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /u, '');
      if (!['data', 'event', 'id', 'retry'].includes(key) || done) throw new SiwcError('sse_trailing_or_invalid_frame');
      if (key === 'data') data.push(value);
    }
    const payload = data.join('\n');
    if (payload.startsWith('[DONE]')) {
      if (payload !== '[DONE]') throw new SiwcError('sse_trailing_or_invalid_frame');
      done = true;
    }
  }
}

function normalizedUsage(raw) {
  if (!raw || !['input_tokens', 'output_tokens', 'total_tokens'].every(k => Number.isSafeInteger(raw[k]) && raw[k] >= 0) || raw.total_tokens !== raw.input_tokens + raw.output_tokens) throw new SiwcError('response_usage_unverified');
  const cached = raw.input_tokens_details?.cached_tokens;
  const reasoning = raw.output_tokens_details?.reasoning_tokens;
  if ((cached !== undefined && (!Number.isSafeInteger(cached) || cached < 0 || cached > raw.input_tokens)) || (reasoning !== undefined && (!Number.isSafeInteger(reasoning) || reasoning < 0 || reasoning > raw.output_tokens))) throw new SiwcError('response_usage_unverified');
  return { input: raw.input_tokens, output: raw.output_tokens, total: raw.total_tokens, cachedInput: cached ?? null, reasoningOutput: reasoning ?? null };
}

export async function sourceIdentity() {
  const files = ['scripts/siwc-auth.mjs', 'scripts/siwc-storage.mjs', 'scripts/verify-daybreak-direct.mjs', 'package.json', 'package-lock.json'];
  const sources = [];
  for (const file of files) {
    const bytes = await fs.readFile(path.join(repositoryRoot, file));
    sources.push({ path: file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
  }
  for (const [name, version] of [['openai', '7.42.0'], ['jose', '6.2.13']]) {
    const manifest = JSON.parse(await fs.readFile(path.join(repositoryRoot, 'node_modules', name, 'package.json'), 'utf8'));
    if (manifest.name !== name || manifest.version !== version) throw new SiwcError('dependency_pin_mismatch');
  }
  return sources;
}

export async function runProbe(store, credentials, { fetcher = globalThis.fetch, signal, limits = defaultLimits, sources = [], predecessorAttemptId = null } = {}) {
  usableCredentials(credentials, await store.read('registration.json'));
  if (await store.read('probe-attempt.json')) throw new SiwcError('probe_already_attempted');
  const attemptId = randomUUID();
  await store.write('probe-attempt.json', { schema: 1, attemptId, predecessorAttemptId, state: 'dispatch_pending', createdAt: new Date().toISOString(), sources }, true);
  const proof = {
    schema: 'scanmux.daybreak-direct-proof/v1', attemptId, predecessorAttemptId, state: 'INCOMPLETE',
    authentication: 'chatgpt_plan_oauth', modelRequested: probeRequest.model, modelActual: 'unknown',
    accessProgramRequested: 'daybreak_blue', accessProgramEffective: 'unknown',
    requestId: null, responseId: null, usage: null, inferenceRequests: 0, automaticRetries: 0,
    httpBodyEnded: false, completedEvent: false, codeExecution: 'not_checked',
    httpStatus: null, mediaType: null, httpBodyBytes: null, providerErrorCode: null,
    productionIntegration: 'not_started', cost: 'N/A', allowance: 'unknown', error: null, sources,
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), limits.timeoutMs);
  const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  let dispatched = false;
  const guardedFetch = async (url, options) => {
    if (dispatched || String(url) !== endpoint || options?.method !== 'POST') throw new SiwcError('inference_destination_or_retry_rejected');
    try { assert.deepEqual(JSON.parse(options.body), probeRequest); }
    catch { throw new SiwcError('inference_body_rejected'); }
    if (combined.aborted) throw new SiwcError('operation_aborted');
    dispatched = true; proof.inferenceRequests = 1;
    const response = await abortable(fetcher(endpoint, {
      method: 'POST', signal: combined, redirect: 'error', credentials: 'omit',
      headers: { authorization: `Bearer ${credentials.accessToken}`, 'content-type': 'application/json', accept: 'text/event-stream' },
      body: JSON.stringify(probeRequest),
    }), combined);
    if (response.redirected || (response.url && response.url !== endpoint)) throw new SiwcError('inference_redirect_rejected');
    proof.httpStatus = response.status;
    const mediaType = (response.headers.get('content-type') ?? '').split(';', 1)[0].trim().toLowerCase();
    proof.mediaType = !mediaType ? 'missing' : mediaType === 'text/event-stream' ? 'event_stream' : mediaType === 'application/json' ? 'json' : mediaType === 'text/html' ? 'html' : 'other';
    proof.requestId = safeRequestId(response.headers.get('x-request-id') ?? response.headers.get('openai-request-id'));
    const bytes = await readBounded(response, limits.maxOutputBytes, combined);
    proof.httpBodyEnded = true;
    proof.httpBodyBytes = bytes.length;
    let providerCode;
    try { const value = JSON.parse(bytes.toString('utf8')); providerCode = typeof value.error === 'string' ? value.error : value.error?.code; } catch { /* SSE and other bodies are not retained. */ }
    if (knownErrors.has(providerCode)) proof.providerErrorCode = providerCode;
    if (!response.ok) {
      throw new SiwcError(proof.providerErrorCode ?? `inference_http_${response.status}`);
    }
    // Official direct-plan transport may omit this header; the full SSE proof is still required.
    if (mediaType && mediaType !== 'text/event-stream') throw new SiwcError('inference_content_type');
    validateSseEnvelope(bytes);
    return new Response(bytes, { status: response.status, headers: { 'content-type': 'text/event-stream' } });
  };
  try {
    const client = new OpenAI({
      apiKey: credentials.accessToken, baseURL: 'https://api.openai.com/v1', organization: null, project: null,
      maxRetries: 0, timeout: limits.timeoutMs, logLevel: 'off',
      logger: { debug() {}, info() {}, warn() {}, error() {} }, fetch: guardedFetch,
    });
    const stream = await client.responses.create(probeRequest, { signal: combined });
    let identity; let terminal;
    for await (const event of stream) {
      if (terminal) throw new SiwcError('event_after_completion');
      if (event.response?.id !== undefined) {
        if (!responseId(event.response.id) || (identity && identity !== event.response.id)) throw new SiwcError('response_identity_mismatch');
        identity = event.response.id;
      }
      if (event.response_id !== undefined) {
        if (!responseId(event.response_id) || (identity && identity !== event.response_id)) throw new SiwcError('response_identity_mismatch');
        identity = event.response_id;
      }
      if (['response.failed', 'response.incomplete', 'error'].includes(event.type)) {
        const code = event.response?.error?.code ?? event.code;
        throw new SiwcError(knownErrors.has(code) ? code : 'response_not_completed');
      }
      if (event.type === 'response.completed') terminal = event.response;
    }
    if (!terminal || terminal.status !== 'completed' || terminal.error != null || !responseId(terminal.id) || identity !== terminal.id) throw new SiwcError('response_not_completed');
    proof.completedEvent = true; proof.responseId = terminal.id;
    proof.modelActual = compatibleModel(terminal.model) ? terminal.model : 'unexpected';
    const program = terminal.access_programs?.cyber;
    proof.accessProgramEffective = ['standard', 'daybreak_blue', 'daybreak_red'].includes(program) ? program : 'unknown';
    proof.usage = normalizedUsage(terminal.usage);
    if (!compatibleModel(terminal.model)) throw new SiwcError('effective_model_mismatch');
    if (program !== 'daybreak_blue') throw new SiwcError('effective_blue_unverified');
    if (combined.aborted) throw new SiwcError('operation_aborted');
    proof.state = 'BLUE_VERIFIED';
  } catch (error) {
    proof.error = errorCode(error);
    // The SDK may wrap transport failures; preserve only our fixed safe error code.
    if (proof.error === 'operation_failed' && error?.cause instanceof SiwcError) proof.error = error.cause.code;
    if (proof.error === 'operation_failed' && combined.aborted) proof.error = 'operation_aborted';
  } finally { clearTimeout(timer); controller.abort(); }
  proof.finishedAt = new Date().toISOString();
  await store.write('probe-result.json', proof);
  await store.write('probe-attempt.json', { schema: 1, attemptId, predecessorAttemptId, state: 'finished', result: proof.state, finishedAt: proof.finishedAt, sources });
  return proof;
}

export async function runCompatibilityProbe(store, options = {}) {
  const previous = await store.read('probe-result.json');
  const marker = await store.read('probe-attempt.json');
  const originalVerifier = 'dc5c01b5a2ada3c03b01d13bc32ac5e577052fd0d25a42049e08bb0107d53462';
  if (previous?.schema !== 'scanmux.daybreak-direct-proof/v1' || marker?.schema !== 1 || marker.state !== 'finished' || marker.result !== 'INCOMPLETE'
      || previous.state !== 'INCOMPLETE' || previous.error !== 'inference_content_type' || previous.attemptId !== marker.attemptId
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(previous.attemptId ?? '')
      || previous.inferenceRequests !== 1 || previous.automaticRetries !== 0 || previous.httpBodyEnded !== true || previous.completedEvent !== false
      || previous.modelRequested !== probeRequest.model || previous.accessProgramRequested !== 'daybreak_blue'
      || !Array.isArray(previous.sources) || !previous.sources.some(source => source.path === 'scripts/verify-daybreak-direct.mjs' && source.sha256 === originalVerifier)) throw new SiwcError('compatibility_predecessor_rejected');
  try { assert.deepEqual(previous.sources, marker.sources); }
  catch { throw new SiwcError('compatibility_predecessor_rejected'); }
  const mapping = { 'probe-attempt.json': 'probe-compat-attempt.json', 'probe-result.json': 'probe-compat-result.json' };
  const compatStore = {
    read(name) {
      if (name === 'registration.json') return store.read(name);
      if (!Object.hasOwn(mapping, name)) throw new SiwcError('invalid_state_operation');
      return store.read(mapping[name]);
    },
    write(name, value, exclusive) {
      if (!Object.hasOwn(mapping, name)) throw new SiwcError('invalid_state_operation');
      return store.write(mapping[name], value, exclusive);
    },
  };
  // This separate fixed experiment cannot register, refresh, reset, or overwrite the first attempt.
  const credentials = usableCredentials(await store.read('credentials.json'), await store.read('registration.json'));
  return runProbe(compatStore, credentials, { ...options, predecessorAttemptId: previous.attemptId });
}

async function main() {
  const mode = process.argv[2];
  if (process.argv.length !== 3 || !['prepare', 'authorize-probe', 'compatibility-probe'].includes(mode)) throw new SiwcError('invalid_probe_command');
  const sources = await sourceIdentity();
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  const store = await openStore();
  let output;
  try {
    if (mode === 'prepare') {
      await discover({ signal: controller.signal });
      const jwks = await publicJson(endpoints.jwks, { signal: controller.signal });
      if (!Array.isArray(jwks.keys) || !jwks.keys.some(key => key.kty === 'RSA')) throw new SiwcError('jwks_unavailable');
      output = { prepared: true, privateStorageVerified: true, officialDiscoveryVerified: true, publicJwksAvailable: true, oauthStarted: false, inferenceRequests: 0, sources };
    } else if (mode === 'compatibility-probe') {
      output = await runCompatibilityProbe(store, { signal: controller.signal, sources });
      process.exitCode = output.state === 'BLUE_VERIFIED' ? 0 : 3;
    } else {
    if (await store.read('probe-attempt.json')) throw new SiwcError('probe_already_attempted');
    let credentials = await store.read('credentials.json');
    if (credentials) {
      try { usableCredentials(credentials, await store.read('registration.json')); }
      catch (error) { if (error.code !== 'credentials_expired') throw error; credentials = null; }
    }
    if (!credentials) credentials = await authenticate(store, {
      signal: controller.signal,
      onReady: ({ url, expiresAt }) => { process.stdout.write(JSON.stringify({ event: 'oauth_consent_required', authorizationUrl: url, expiresAt }) + '\n'); },
    });
    const proof = await runProbe(store, credentials, { signal: controller.signal, sources });
    output = proof;
    process.exitCode = proof.state === 'BLUE_VERIFIED' ? 0 : 3;
    }
  } finally {
    await store.close();
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
  }
  process.stdout.write(JSON.stringify(output) + '\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => { process.stderr.write(JSON.stringify({ state: 'ERROR', error: errorCode(error) }) + '\n'); process.exitCode = 4; });
}
