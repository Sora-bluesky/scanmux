import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import http from 'node:http';
import { randomUUID, createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { openStore, verifyPrivate, repositoryRoot, SiwcError } from '../scripts/siwc-storage.mjs';
import { issuer, endpoints, scopes, discover, publicJson, parseCallback, validateTokens, usableCredentials, authenticate } from '../scripts/siwc-auth.mjs';
import { probeRequest, runProbe, runCompatibilityProbe, validateSseEnvelope } from '../scripts/verify-daybreak-direct.mjs';

const clientId = 'oaiapp_synthetic';
const subject = 'synthetic-subject';
const keyPair = await generateKeyPair('RS256');
const publicKey = { ...(await exportJWK(keyPair.publicKey)), kid: 'synthetic', alg: 'RS256', use: 'sig' };
const jwks = { keys: [publicKey] };
const discovery = { issuer, authorization_endpoint: endpoints.authorization, token_endpoint: endpoints.token, jwks_uri: endpoints.jwks, id_token_signing_alg_values_supported: ['RS256'] };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const hostId = 'urn:uuid:11111111-1111-4111-8111-111111111111';
const registration = { schema: 1, state: 'registered_unverified', hostId, clientId };
const credential = () => ({ schema: 1, state: 'active', issuer, clientId, subject, accessToken: 'synthetic-access', refreshToken: 'synthetic-refresh', idToken: 'synthetic-id', scopes: [...scopes], expiresAt: Date.now() + 3600000 });
class MemoryStore {
  constructor(initial = {}) { this.files = structuredClone(initial); this.writes = []; }
  async read(name) { return structuredClone(this.files[name] ?? null); }
  async write(name, value, exclusive = false) {
    if (exclusive && Object.hasOwn(this.files, name)) throw new SiwcError('operation_already_recorded');
    this.files[name] = structuredClone(value); this.writes.push(name);
  }
}
async function tokens(nonce, overrides = {}, claims = {}, key = keyPair.privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const id = await new SignJWT({ iss: issuer, aud: clientId, sub: subject, iat: now, exp: now + 3600, nonce, ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'synthetic' }).sign(key);
  const tok = 'synthetic-access';
  return { id_token: id, access_token: tok, refresh_token: 'synthetic-refresh', token_type: 'Bearer', expires_in: 3600, scope: scopes.join(' '), ...overrides };
}
const rejectsCode = (promise, code) => assert.rejects(promise, error => error.code === code);
const terminal = (overrides = {}) => ({ id: 'resp_synthetic', status: 'completed', error: null, model: 'gpt-6-sol', access_programs: { cyber: 'daybreak_blue' }, usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 }, ...overrides });
const eventFrame = event => `data: ${JSON.stringify(event)}\n\n`;
const completion = value => eventFrame({ type: 'response.created', response: { id: 'resp_synthetic' } }) + eventFrame({ type: 'response.completed', response: value ?? terminal() });
const sse = text => new Response(text, { headers: { 'content-type': 'text/event-stream', 'x-request-id': 'req_synthetic' } });

test('JWT signature, issuer, audience, nonce, subject, expiry and exact plan permissions are required', async () => {
  const valid = await tokens('nonce');
  assert.equal((await validateTokens(valid, { clientId, nonce: 'nonce', jwks })).subject, subject);
  const otherKey = await generateKeyPair('RS256');
  const cases = [
    [await tokens('nonce', {}, {}, otherKey.privateKey), {}, 'id_token_invalid'],
    [await tokens('nonce', {}, { iss: 'https://example.invalid' }), {}, 'id_token_invalid'],
    [await tokens('nonce', {}, { aud: 'oaiapp_other' }), {}, 'id_token_invalid'],
    [await tokens('other'), {}, 'id_token_binding_invalid'],
    [await tokens('nonce', {}, { exp: 1 }), {}, 'id_token_invalid'],
    [await tokens('nonce', {}, { iat: Math.floor(Date.now() / 1000) + 100 }), {}, 'id_token_binding_invalid'],
    [await tokens('nonce', {}, { sub: '' }), {}, 'id_token_binding_invalid'],
    [valid, { expectedSubject: 'different-subject' }, 'account_change_rejected'],
    [await tokens('nonce', {}, { aud: [clientId, 'other'] }), {}, 'id_token_binding_invalid'],
    [await tokens('nonce', {}, { azp: 'other' }), {}, 'id_token_binding_invalid'],
    [await tokens('nonce', { scope: 'openid profile email offline_access resource.invoke' }), {}, 'plan_permission_missing'],
    [await tokens('nonce', { refresh_token: null }), {}, 'token_response_invalid'],
    [await tokens('nonce', { expires_in: 0 }), {}, 'token_response_invalid'],
  ];
  for (const [value, options, code] of cases) await rejectsCode(validateTokens(value, { clientId, nonce: 'nonce', jwks, ...options }), code);
});

test('callback rejects sibling origins, parameter pollution, replay and expired transactions', () => {
  const tx = { host: '127.0.0.1:12345', redirectUri: 'http://127.0.0.1:12345/auth/callback', state: 'synthetic-state', expiresAt: Date.now() + 10000, claimed: false };
  const raw = `/auth/callback?state=${tx.state}&code=synthetic-code&client_id=${clientId}`;
  assert.equal(parseCallback(raw, tx.host, tx).clientId, clientId);
  for (const [url, host, override] of [
    [raw, 'localhost:12345', {}], [raw, 'evil.invalid', {}],
    [raw + '&state=synthetic-state', tx.host, {}], [raw + '&unknown=x', tx.host, {}],
    [raw + '&iss=https%3A%2F%2Fevil.invalid', tx.host, {}], [raw + '#fragment', tx.host, {}],
    [raw.replace('synthetic-state', 'other'), tx.host, {}], [raw.replace('synthetic-code', '%xx'), tx.host, {}],
    [raw, tx.host, { claimed: true }], [raw, tx.host, { expiresAt: 0 }],
    [raw, tx.host, { clientId: 'oaiapp_other' }], [raw + '&error=access_denied', tx.host, {}],
  ]) assert.throws(() => parseCallback(url, host, { ...tx, ...override }), SiwcError);
  assert.deepEqual(parseCallback(`/auth/callback?state=${tx.state}&error=access_denied`, tx.host, tx), { denied: true });
});

function localRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request(url, options, response => {
      response.resume(); response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject); request.end();
  });
}

test('real loopback OAuth binds PKCE and persists client before exchange; duplicate callbacks cannot exchange twice', async () => {
  const store = new MemoryStore(); let authorization; let exchanges = 0; let releaseToken;
  const tokenReady = new Promise(resolve => { releaseToken = resolve; });
  let exchangeEntered; const entered = new Promise(resolve => { exchangeEntered = resolve; });
  let firstRequest;
  const result = await authenticate(store, {
    fetcher: async (url, options) => {
      assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
      if (url === endpoints.discovery) return json(discovery);
      if (url === endpoints.jwks) return json(jwks);
      assert.equal(url, endpoints.token); exchanges++;
      assert.equal(store.files['registration.json'].clientId, clientId);
      assert.equal(store.files['registration.json'].state, 'registered_unverified');
      assert.equal(store.files['credentials.json'], undefined);
      const form = new URLSearchParams(options.body);
      assert.equal(form.get('client_id'), clientId);
      assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'), authorization.searchParams.get('code_challenge'));
      exchangeEntered(); await tokenReady;
      return json(await tokens(authorization.searchParams.get('nonce')));
    },
    onReady: async ({ url }) => {
      authorization = new URL(url);
      assert.equal(authorization.origin, issuer);
      assert.equal(authorization.searchParams.get('client_id'), 'dynamic_agent_client');
      assert.equal(store.files['registration.json'].state, 'authorizing');
      const callback = new URL(authorization.searchParams.get('redirect_uri'));
      callback.search = new URLSearchParams({ state: authorization.searchParams.get('state'), code: 'synthetic-code', client_id: clientId });
      assert.equal(await localRequest(callback, { method: 'POST' }), 400);
      assert.equal(await localRequest(callback, { headers: { host: 'evil.invalid' } }), 400);
      firstRequest = localRequest(callback);
      await entered;
      assert.equal(await localRequest(callback), 400);
      releaseToken();
    },
  });
  assert.equal(await firstRequest, 200); assert.equal(exchanges, 1);
  assert.equal(result.state, 'active'); assert.equal(store.files['credentials.json'].subject, subject);
  await assert.rejects(localRequest(authorization.searchParams.get('redirect_uri')), { code: 'ECONNREFUSED' });
});

test('exchange or validation failures retain issued registration and any previous credential; reauth reuses client', async () => {
  for (const reauth of [false, true]) {
    const previous = credential();
    const store = new MemoryStore(reauth ? { 'host.json': { schema: 1, hostId }, 'registration.json': registration, 'credentials.json': previous } : {});
    let authorization; let exchanges = 0;
    await rejectsCode(authenticate(store, {
      fetcher: async url => {
        if (url === endpoints.discovery) return json(discovery);
        if (url === endpoints.jwks) return json(jwks);
        exchanges++;
        if (!reauth) return json({ error: 'synthetic' }, 400);
        return json(await tokens(authorization.searchParams.get('nonce'), {}, { sub: 'different-subject' }));
      },
      onReady: async ({ url }) => {
        authorization = new URL(url);
        assert.equal(authorization.searchParams.get('client_id'), reauth ? clientId : 'dynamic_agent_client');
        assert.equal(authorization.searchParams.has('agent_name_hint'), !reauth);
        const callback = new URL(authorization.searchParams.get('redirect_uri'));
        callback.search = new URLSearchParams({ state: authorization.searchParams.get('state'), code: 'synthetic-code', client_id: clientId });
        assert.equal(await localRequest(callback), 400);
      },
    }), reauth ? 'account_change_rejected' : 'auth_http_400');
    assert.equal(exchanges, 1); assert.equal(store.files['registration.json'].clientId, clientId);
    assert.deepEqual(store.files['credentials.json'], reauth ? previous : undefined);
    await assert.rejects(localRequest(authorization.searchParams.get('redirect_uri')), { code: 'ECONNREFUSED' });
  }
});

test('denied or interrupted new registration stays unknown and cannot dynamically register again', async () => {
  for (const denied of [false, true]) {
    const store = new MemoryStore(); const controller = new AbortController(); let exchanges = 0; let callback;
    const fetcher = async url => { if (url !== endpoints.discovery) exchanges++; return json(discovery); };
    await rejectsCode(authenticate(store, {
      fetcher, signal: controller.signal,
      onReady: async ({ url }) => {
        const auth = new URL(url); callback = new URL(auth.searchParams.get('redirect_uri'));
        if (!denied) { controller.abort(); return; }
        callback.search = new URLSearchParams({ state: auth.searchParams.get('state'), error: 'access_denied' });
        assert.equal(await localRequest(callback), 400);
      },
    }), denied ? 'oauth_denied' : 'oauth_aborted');
    assert.equal(exchanges, 0); assert.equal(store.files['registration.json'].state, 'authorizing');
    await rejectsCode(authenticate(store, { fetcher }), 'registration_outcome_unknown');
    await assert.rejects(localRequest(callback), { code: 'ECONNREFUSED' });
  }
});

test('auth destination and discovery are fixed; malformed, redirected and oversized HTTP bodies fail', async () => {
  await rejectsCode(publicJson('https://example.invalid'), 'auth_destination_rejected');
  await rejectsCode(discover({ fetcher: async () => json({ ...discovery, token_endpoint: 'https://example.invalid' }) }), 'discovery_mismatch');
  await rejectsCode(publicJson(endpoints.jwks, { fetcher: async () => json(jwks), limits: { timeoutMs: 1000, maxOutputBytes: 1 } }), 'http_body_limit');
  await assert.rejects(publicJson(endpoints.jwks, { fetcher: async () => new Response(new Uint8Array([0xff])) }));
  const redirected = json(jwks); Object.defineProperty(redirected, 'redirected', { value: true });
  await rejectsCode(publicJson(endpoints.jwks, { fetcher: async () => redirected }), 'auth_redirect_rejected');
  await rejectsCode(publicJson(endpoints.jwks, { fetcher: () => new Promise(() => {}), limits: { timeoutMs: 25, maxOutputBytes: 1024 } }), 'operation_aborted');
});

test('successful probe uses only fixed synthetic request and OAuth bearer once, records measured fields without secrets', async () => {
  const store = new MemoryStore({ 'registration.json': registration }); let calls = 0;
  const proof = await runProbe(store, credential(), { fetcher: async (url, options) => {
    calls++; assert.equal(url, 'https://api.openai.com/v1/responses');
    assert.deepEqual(JSON.parse(options.body), probeRequest);
    assert.deepEqual(Object.keys(options.headers).sort(), ['accept', 'authorization', 'content-type']);
    assert.equal(options.headers.authorization, 'Bearer synthetic-access');
    assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit');
    return sse(completion() + 'data: [DONE]\n\n');
  } });
  assert.equal(proof.state, 'BLUE_VERIFIED'); assert.equal(calls, 1); assert.equal(proof.inferenceRequests, 1);
  assert.equal(proof.httpBodyEnded, true); assert.equal(proof.completedEvent, true);
  assert.equal(proof.accessProgramEffective, 'daybreak_blue'); assert.equal(proof.modelActual, 'gpt-6-sol');
  assert.equal(proof.responseId, 'resp_synthetic'); assert.equal(proof.requestId, 'req_synthetic');
  assert.deepEqual(proof.usage, { input: 9, output: 1, total: 10, cachedInput: null, reasoningOutput: null });
  assert.equal(proof.codeExecution, 'not_checked'); assert.equal(proof.productionIntegration, 'not_started');
  assert.doesNotMatch(JSON.stringify(proof), /synthetic-access|synthetic-refresh|synthetic-id|synthetic-subject|oaiapp_synthetic|SCANMUX_DAYBREAK_PROBE_OK/u);
  await rejectsCode(runProbe(store, credential(), { fetcher: () => { calls++; } }), 'probe_already_attempted');
  assert.equal(calls, 1);
});

test('completion requires effective Blue, expected model, matching identity, valid usage and complete stream', async () => {
  const variants = [
    [completion(terminal({ access_programs: null })), 'effective_blue_unverified'],
    [completion(terminal({ access_programs: { cyber: 'standard' } })), 'effective_blue_unverified'],
    [completion(terminal({ access_programs: { cyber: 'daybreak_red' } })), 'effective_blue_unverified'],
    [completion(terminal({ model: 'other' })), 'effective_model_mismatch'],
    [completion(terminal({ model: 'gpt-6-sol-2026-02-30' })), 'effective_model_mismatch'],
    [completion(terminal({ id: 'resp_other' })), 'response_identity_mismatch'],
    [completion(terminal({ usage: { input_tokens: 9, output_tokens: 1, total_tokens: 11 } })), 'response_usage_unverified'],
    [completion(terminal({ usage: null })), 'response_usage_unverified'],
    [completion(terminal({ usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10, output_tokens_details: { reasoning_tokens: 2 } } })), 'response_usage_unverified'],
    [completion(terminal({ status: 'incomplete' })), 'response_not_completed'],
    [eventFrame({ type: 'response.failed', response: { id: 'resp_synthetic', error: { code: 'synthetic-secret' } } }), 'response_not_completed'],
    [completion() + eventFrame({ type: 'response.output_text.delta', delta: 'synthetic-secret' }), 'event_after_completion'],
    [completion() + eventFrame({ type: 'response.completed', response: terminal() }), 'event_after_completion'],
    [completion() + 'data: [DONE]\n\ndata: {}\n\n', 'sse_trailing_or_invalid_frame'],
    [completion() + 'data: [DONE]junk\n\n', 'sse_trailing_or_invalid_frame'],
    [completion() + 'data: {', 'sse_incomplete_frame'],
    [completion().slice(0, -1), 'sse_incomplete_frame'],
    [eventFrame({ type: 'response.created', response: { id: 'resp_synthetic' } }), 'response_not_completed'],
  ];
  for (const [body, error] of variants) {
    const store = new MemoryStore({ 'registration.json': registration });
    const proof = await runProbe(store, credential(), { fetcher: async () => sse(body) });
    assert.equal(proof.state, 'INCOMPLETE', error); assert.equal(proof.error, error);
    assert.equal(proof.inferenceRequests, 1); assert.equal(store.files['probe-attempt.json'].state, 'finished');
    assert.doesNotMatch(JSON.stringify(proof), /synthetic-secret/u);
  }
  const dated = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { fetcher: async () => sse(completion(terminal({ model: 'gpt-6-sol-2026-10-22' }))) });
  assert.equal(dated.state, 'BLUE_VERIFIED');
  const splitBytes = Buffer.from(eventFrame({ type: 'response.output_text.delta', response_id: 'resp_synthetic', delta: '合成データ' }) + completion());
  const splitProof = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { fetcher: async () => sse(new ReadableStream({ start(c) {
    for (const byte of splitBytes) c.enqueue(Uint8Array.of(byte));
    c.close();
  } })) });
  assert.equal(splitProof.state, 'BLUE_VERIFIED');
  assert.doesNotThrow(() => validateSseEnvelope(Buffer.from((completion() + 'data: [DONE]\n\n: comment\n\n').replace(/\n/gu, '\r\n'))));
});

test('HTTP errors, body limits, bad UTF-8, missing EOF, disconnect and abort never retry or pass', async () => {
  const variants = [
    [() => json({ error: { code: 'subscription_sharing_route_not_supported', message: 'synthetic-secret' } }, 403), {}, 'subscription_sharing_route_not_supported'],
    [() => json({ error: { code: 'synthetic-secret' } }, 500), {}, 'inference_http_500'],
    [() => sse(completion()), { maxOutputBytes: 1, timeoutMs: 1000 }, 'http_body_limit'],
    [() => sse(new Uint8Array([0xff])), {}, 'operation_failed'],
    [() => sse(new ReadableStream({ start(c) { c.enqueue(Buffer.from(completion())); } })), { timeoutMs: 25, maxOutputBytes: 8192 }, 'operation_aborted'],
    [() => sse(new ReadableStream({ start(c) { c.enqueue(Buffer.from(completion())); c.error(new Error('synthetic-secret')); } })), {}, 'operation_failed'],
    [() => new Promise(() => {}), { timeoutMs: 25, maxOutputBytes: 8192 }, 'operation_aborted'],
  ];
  for (const [response, limits, error] of variants) {
    let calls = 0; const store = new MemoryStore({ 'registration.json': registration });
    const proof = await runProbe(store, credential(), { fetcher: async () => { calls++; return response(); }, limits: { timeoutMs: 1000, maxOutputBytes: 8192, ...limits } });
    assert.equal(proof.state, 'INCOMPLETE'); assert.equal(proof.error, error); assert.equal(calls, 1);
    assert.doesNotMatch(JSON.stringify(proof), /synthetic-secret/u);
    await rejectsCode(runProbe(store, credential()), 'probe_already_attempted');
  }
  const controller = new AbortController(); controller.abort(); let calls = 0;
  const proof = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { signal: controller.signal, fetcher: async () => { calls++; } });
  assert.equal(proof.state, 'INCOMPLETE'); assert.equal(calls, 0);
});

test('unverified or expired credentials cannot dispatch', async () => {
  for (const change of [{ expiresAt: 0 }, { clientId: 'oaiapp_other' }, { subject: '' }, { scopes: [] }, { state: 'unverified' }]) {
    let calls = 0;
    await assert.rejects(runProbe(new MemoryStore({ 'registration.json': registration }), { ...credential(), ...change }, { fetcher: () => { calls++; } }), SiwcError);
    assert.equal(calls, 0);
  }
  assert.throws(() => usableCredentials(credential(), { clientId: 'oaiapp_other' }), SiwcError);
});

test('official missing media type compatibility still requires complete valid SSE and effective Blue', async () => {
  for (const type of [null, '', 'text/event-stream', 'Text/Event-Stream; charset=utf-8']) {
    const proof = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { fetcher: async () => new Response(Buffer.from(completion()), { headers: type === null ? {} : { 'content-type': type } }) });
    assert.equal(proof.state, 'BLUE_VERIFIED'); assert.equal(proof.httpStatus, 200);
    assert.equal(proof.mediaType, type ? 'event_stream' : 'missing'); assert.equal(proof.httpBodyBytes, Buffer.byteLength(completion()));
  }
  for (const [body, type] of [
    [completion(), 'application/json'], [completion(), 'text/html'], [completion(), 'text/event-stream-invalid'], [completion(), '__proto__'],
    [JSON.stringify(terminal()), null], [completion().slice(0, -1), null], [Buffer.from([0xff]), null],
    [completion(terminal({ access_programs: null })), null], [completion() + 'data: [DONE]\n\ndata: {}\n\n', null],
  ]) {
    const proof = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { fetcher: async () => new Response(Buffer.from(body), { headers: type === null ? {} : { 'content-type': type } }) });
    assert.equal(proof.state, 'INCOMPLETE');
    assert(['event_stream', 'json', 'html', 'missing', 'other'].includes(proof.mediaType));
    if (type) assert.equal(proof.error, 'inference_content_type');
  }
  const error = await runProbe(new MemoryStore({ 'registration.json': registration }), credential(), { fetcher: async () => json({ error: 'subscription_sharing_route_not_supported', message: 'synthetic-secret' }, 200) });
  assert.equal(error.state, 'INCOMPLETE'); assert.equal(error.providerErrorCode, 'subscription_sharing_route_not_supported');
  assert.doesNotMatch(JSON.stringify(error), /synthetic-secret/u);
});

function predecessorFiles() {
  const sources = [{ path: 'scripts/verify-daybreak-direct.mjs', bytes: 12559, sha256: 'dc5c01b5a2ada3c03b01d13bc32ac5e577052fd0d25a42049e08bb0107d53462' }];
  const attemptId = '11111111-1111-4111-8111-111111111111';
  return {
    'registration.json': registration, 'credentials.json': credential(),
    'probe-attempt.json': { schema: 1, attemptId, state: 'finished', result: 'INCOMPLETE', sources },
    'probe-result.json': { schema: 'scanmux.daybreak-direct-proof/v1', attemptId, state: 'INCOMPLETE', error: 'inference_content_type', inferenceRequests: 1, automaticRetries: 0, httpBodyEnded: true, completedEvent: false, modelRequested: 'gpt-6-sol', accessProgramRequested: 'daybreak_blue', sources },
  };
}

test('separate compatibility experiment preserves first attempt and sends at most one additional request', async () => {
  for (const success of [false, true]) {
    const initial = predecessorFiles(); const store = new MemoryStore(initial); let calls = 0;
    const fetcher = async (url, options) => {
      calls++; assert.equal(url, 'https://api.openai.com/v1/responses'); assert.deepEqual(JSON.parse(options.body), probeRequest);
      assert.equal(store.files['probe-compat-attempt.json'].state, 'dispatch_pending');
      assert.equal(store.files['probe-compat-attempt.json'].predecessorAttemptId, initial['probe-result.json'].attemptId);
      assert.deepEqual(store.files['probe-attempt.json'], initial['probe-attempt.json']);
      assert.deepEqual(store.files['probe-result.json'], initial['probe-result.json']);
      return success ? new Response(Buffer.from(completion())) : json({ error: 'synthetic-secret' }, 500);
    };
    const proof = await runCompatibilityProbe(store, { fetcher });
    assert.equal(proof.state, success ? 'BLUE_VERIFIED' : 'INCOMPLETE'); assert.equal(calls, 1);
    assert.equal(proof.predecessorAttemptId, initial['probe-result.json'].attemptId);
    assert.equal(store.files['probe-compat-attempt.json'].state, 'finished');
    assert.deepEqual(store.files['probe-attempt.json'], initial['probe-attempt.json']);
    assert.deepEqual(store.files['probe-result.json'], initial['probe-result.json']);
    await rejectsCode(runCompatibilityProbe(store, { fetcher }), 'probe_already_attempted'); assert.equal(calls, 1);
    assert(store.writes.every(name => ['probe-compat-attempt.json', 'probe-compat-result.json'].includes(name)));
  }
});

test('compatibility entry rejects wrong predecessor, partial or existing marker, expired credentials and persistence failure without sending', async () => {
  const mutations = [
    files => { delete files['probe-result.json']; },
    files => { files['probe-attempt.json'].state = 'dispatch_pending'; },
    files => { files['probe-attempt.json'].attemptId = 'other'; },
    files => { files['probe-result.json'].state = 'BLUE_VERIFIED'; },
    files => { files['probe-result.json'].error = 'operation_aborted'; },
    files => { files['probe-result.json'].inferenceRequests = 0; },
    files => { files['probe-result.json'].completedEvent = true; },
    files => { files['probe-result.json'].httpBodyEnded = false; },
    files => { files['probe-result.json'].modelRequested = 'other'; },
    files => { files['probe-result.json'].sources = [{ path: 'scripts/verify-daybreak-direct.mjs', sha256: 'other' }]; },
    files => { files['probe-attempt.json'].sources = []; },
    files => { files['probe-compat-attempt.json'] = { state: 'dispatch_pending' }; },
    files => { files['probe-compat-attempt.json'] = null; },
    files => { files['probe-compat-attempt.json'] = { malformed: true }; },
    files => { files['credentials.json'].expiresAt = 0; },
    files => { delete files['credentials.json']; },
  ];
  for (const mutate of mutations) {
    const initial = predecessorFiles(); mutate(initial); const store = new MemoryStore(initial); let calls = 0;
    await assert.rejects(runCompatibilityProbe(store, { fetcher: async () => { calls++; } })); assert.equal(calls, 0);
    assert.deepEqual(store.files['probe-attempt.json'], initial['probe-attempt.json']);
  }
  const store = new MemoryStore(predecessorFiles()); let calls = 0;
  store.write = async () => { throw new SiwcError('synthetic_storage_failure'); };
  await rejectsCode(runCompatibilityProbe(store, { fetcher: async () => { calls++; } }), 'synthetic_storage_failure'); assert.equal(calls, 0);
});

test('real private store enforces owner ACL, exclusive lock, atomic replacement, name allowlist and hardlink rejection', async () => {
  const base = path.join(tmpdir(), 'siwc-tests-' + randomUUID());
  await fs.mkdir(base);
  test.after(() => removeTempDir(base));
  const directory = path.join(base, 'private');
  const inherited = path.join(base, 'inherited');
  await fs.mkdir(inherited, { mode: 0o755 });
  await rejectsCode(openStore(inherited), 'private_permissions_unverified');
  const store = await openStore(directory);
  try {
    await verifyPrivate(directory);
    await rejectsCode(openStore(directory), 'state_locked');
    await store.write('host.json', { schema: 1, synthetic: true }, true);
    await rejectsCode(store.write('host.json', {}, true), 'operation_already_recorded');
    await store.write('host.json', { schema: 2, synthetic: true });
    assert.deepEqual(await store.read('host.json'), { schema: 2, synthetic: true });
    await rejectsCode(store.read('../outside'), 'invalid_state_operation');
    await fs.link(path.join(directory, 'host.json'), path.join(directory, 'linked.json'));
    await rejectsCode(store.read('host.json'), 'invalid_state_file');
  } finally { await store.close(); }
  const reopened = await openStore(directory); await reopened.close();
  await rejectsCode(store.read('credentials.json'), 'invalid_state_operation');
  const linked = path.join(base, 'junction');
  await fs.symlink(directory, linked, process.platform === 'win32' ? 'junction' : 'dir');
  await rejectsCode(openStore(linked), 'linked_state_path');
});
