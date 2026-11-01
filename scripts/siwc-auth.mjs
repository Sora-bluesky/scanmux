import http from 'node:http';
import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { SiwcError } from './siwc-storage.mjs';

export const issuer = 'https://auth.openai.com';
export const resource = 'https://api.openai.com/v1';
export const endpoints = Object.freeze({
  discovery: issuer + '/.well-known/openid-configuration',
  authorization: issuer + '/api/accounts/authorize',
  token: issuer + '/api/accounts/oauth/token',
  jwks: issuer + '/.well-known/jwks.json',
});
export const scopes = ['openid', 'profile', 'email', 'offline_access', 'resource.invoke', 'chatgpt.tokens.use.direct'];
export const defaultLimits = Object.freeze({ timeoutMs: 120000, maxOutputBytes: 8 * 1024 * 1024 });
const clientPattern = /^oaiapp_[A-Za-z0-9_-]{1,200}$/;
const opaque = value => typeof value === 'string' && value.length > 0 && value.length <= 16384 && !/[\x00-\x20\x7f]/u.test(value);
const secureEqual = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const randomValue = () => randomBytes(32).toString('base64url');

export async function abortable(promise, signal) {
  if (signal?.aborted) throw new SiwcError('operation_aborted');
  let stop;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      stop = () => reject(new SiwcError('operation_aborted'));
      signal?.addEventListener('abort', stop, { once: true });
    })]);
  } finally { if (stop) signal?.removeEventListener('abort', stop); }
}

export async function readBounded(response, maximum, signal) {
  if (!response.body) throw new SiwcError('empty_http_body');
  const reader = response.body.getReader();
  const chunks = []; let size = 0; let ended = false;
  try {
    for (;;) {
      const chunk = await abortable(reader.read(), signal);
      if (chunk.done) { ended = true; break; }
      size += chunk.value.length;
      if (size > maximum) throw new SiwcError('http_body_limit');
      chunks.push(Buffer.from(chunk.value));
    }
    const bytes = Buffer.concat(chunks);
    new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return bytes;
  } finally {
    if (!ended) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function publicJson(url, { fetcher = globalThis.fetch, signal, limits = defaultLimits, body } = {}) {
  if (![endpoints.discovery, endpoints.jwks, endpoints.token].includes(url) || (url === endpoints.token) !== (body !== undefined)) throw new SiwcError('auth_destination_rejected');
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), limits.timeoutMs);
  const combined = signal ? AbortSignal.any([signal, timeout.signal]) : timeout.signal;
  try {
    const response = await abortable(fetcher(url, {
      method: body === undefined ? 'GET' : 'POST', signal: combined, redirect: 'error', credentials: 'omit',
      headers: body === undefined ? { accept: 'application/json' } : { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
      ...(body === undefined ? {} : { body: body.toString() }),
    }), combined);
    if (response.redirected || (response.url && response.url !== url)) throw new SiwcError('auth_redirect_rejected');
    const bytes = await readBounded(response, limits.maxOutputBytes, combined);
    if (!response.ok) throw new SiwcError(`auth_http_${response.status}`);
    if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) throw new SiwcError('auth_content_type');
    return JSON.parse(bytes.toString('utf8'));
  } finally { clearTimeout(timer); timeout.abort(); }
}

export async function discover(options = {}) {
  const value = await publicJson(endpoints.discovery, options);
  if (value.issuer !== issuer || value.authorization_endpoint !== endpoints.authorization || value.token_endpoint !== endpoints.token || value.jwks_uri !== endpoints.jwks || !value.id_token_signing_alg_values_supported?.includes('RS256')) throw new SiwcError('discovery_mismatch');
  return value;
}

export function parseCallback(rawUrl, host, transaction, now = Date.now()) {
  if (!transaction || transaction.claimed || now >= transaction.expiresAt) throw new SiwcError('oauth_transaction_unavailable');
  if (host !== transaction.host || !rawUrl.startsWith('/auth/callback?') || /%(?![0-9a-f]{2})/iu.test(rawUrl)) throw new SiwcError('oauth_callback_rejected');
  const url = new URL(rawUrl, transaction.redirectUri);
  if (url.origin !== new URL(transaction.redirectUri).origin || url.pathname !== '/auth/callback' || url.hash) throw new SiwcError('oauth_callback_rejected');
  const allowed = new Set(['code', 'state', 'client_id', 'scope', 'error', 'error_description', 'error_uri', 'iss']);
  for (const key of url.searchParams.keys()) if (!allowed.has(key) || url.searchParams.getAll(key).length !== 1) throw new SiwcError('oauth_callback_rejected');
  if (!secureEqual(url.searchParams.get('state'), transaction.state)) throw new SiwcError('oauth_state_mismatch');
  if (url.searchParams.has('iss') && url.searchParams.get('iss') !== issuer) throw new SiwcError('oauth_issuer_mismatch');
  if (url.searchParams.has('error')) {
    if (url.searchParams.has('code')) throw new SiwcError('oauth_callback_rejected');
    return { denied: true };
  }
  if (url.searchParams.has('error_description') || url.searchParams.has('error_uri')) throw new SiwcError('oauth_callback_rejected');
  const code = url.searchParams.get('code');
  const suppliedClient = url.searchParams.get('client_id');
  const clientId = suppliedClient ?? transaction.clientId;
  if (!opaque(code) || !clientPattern.test(clientId ?? '') || (transaction.clientId && clientId !== transaction.clientId)) throw new SiwcError('oauth_client_mismatch');
  return { code, clientId };
}

export async function validateTokens(tokens, { clientId, nonce, expectedSubject, jwks, now = Date.now() }) {
  if (!clientPattern.test(clientId) || !opaque(tokens?.id_token) || !opaque(tokens?.access_token) || !opaque(tokens?.refresh_token) || tokens.token_type?.toLowerCase() !== 'bearer' || !Number.isSafeInteger(tokens.expires_in) || tokens.expires_in <= 0 || typeof tokens.scope !== 'string') throw new SiwcError('token_response_invalid');
  let payload;
  try {
    ({ payload } = await jwtVerify(tokens.id_token, createLocalJWKSet(jwks), {
      issuer, audience: clientId, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'nonce'],
      clockTolerance: 5, currentDate: new Date(now),
    }));
  } catch { throw new SiwcError('id_token_invalid'); }
  if (!opaque(payload.sub) || !secureEqual(payload.nonce, nonce) || typeof payload.iat !== 'number' || payload.iat > now / 1000 + 5 || (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== clientId) || (payload.azp !== undefined && payload.azp !== clientId)) throw new SiwcError('id_token_binding_invalid');
  if (expectedSubject && payload.sub !== expectedSubject) throw new SiwcError('account_change_rejected');
  const granted = [...new Set(tokens.scope.split(/\s+/u).filter(Boolean))];
  if (!scopes.every(scope => granted.includes(scope))) throw new SiwcError('plan_permission_missing');
  return {
    schema: 1, state: 'active', issuer, clientId, subject: payload.sub,
    accessToken: tokens.access_token, refreshToken: tokens.refresh_token, idToken: tokens.id_token,
    scopes: granted, expiresAt: now + tokens.expires_in * 1000, savedAt: new Date(now).toISOString(),
  };
}

export function usableCredentials(record, registration, now = Date.now()) {
  if (!record || record.schema !== 1 || record.state !== 'active' || record.issuer !== issuer || !clientPattern.test(record.clientId ?? '') || record.clientId !== registration?.clientId || !opaque(record.subject) || !opaque(record.accessToken) || !opaque(record.refreshToken) || !opaque(record.idToken) || !Array.isArray(record.scopes) || !scopes.every(scope => record.scopes.includes(scope))) throw new SiwcError('credentials_unverified');
  if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt <= now) throw new SiwcError('credentials_expired');
  return record;
}

export async function authenticate(store, { fetcher = globalThis.fetch, signal, limits = defaultLimits, onReady, lifetimeMs = 600000 } = {}) {
  await discover({ fetcher, signal, limits });
  let hostRecord = await store.read('host.json');
  if (!hostRecord) { hostRecord = { schema: 1, hostId: 'urn:uuid:' + randomUUID() }; await store.write('host.json', hostRecord, true); }
  if (hostRecord.schema !== 1 || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(hostRecord.hostId)) throw new SiwcError('host_identity_invalid');
  const registration = await store.read('registration.json');
  const previous = await store.read('credentials.json');
  if (registration && (registration.schema !== 1 || registration.hostId !== hostRecord.hostId || !['authorizing', 'registered_unverified'].includes(registration.state))) throw new SiwcError('registration_identity_invalid');
  if (registration && !clientPattern.test(registration.clientId ?? '')) throw new SiwcError('registration_outcome_unknown');
  if (previous && (previous.clientId !== registration?.clientId || !opaque(previous.subject))) throw new SiwcError('registration_identity_invalid');
  const controller = new AbortController();
  const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
  const server = http.createServer();
  let transaction; let timer; let callbackTask; let settled = false;
  let resolveResult; let rejectResult;
  const result = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  // Install the rejection observer before any abort, listener or callback can fire.
  result.catch(() => {});
  const finish = (error, value) => {
    if (settled) return;
    settled = true;
    if (error) rejectResult(error); else resolveResult(value);
  };
  const onAbort = () => finish(new SiwcError('oauth_aborted'));
  combined.addEventListener('abort', onAbort, { once: true });
  const reply = (response, status, text) => {
    response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'", connection: 'close' });
    response.end(text);
  };
  server.on('clientError', (_, socket) => socket.destroy());
  server.on('error', () => finish(new SiwcError('oauth_listener_failed')));
  server.on('request', (request, response) => {
    request.on('error', () => request.destroy());
    response.on('error', () => response.destroy());
    if (request.method !== 'GET' || settled) { reply(response, 400, 'Request rejected.'); return; }
    let callback;
    try { callback = parseCallback(request.url ?? '', request.headers.host, transaction); }
    catch { reply(response, 400, 'Request rejected.'); return; }
    transaction.claimed = true;
    callbackTask = (async () => {
      if (callback.denied) throw new SiwcError('oauth_denied');
      const pendingRegistration = { schema: 1, state: 'registered_unverified', hostId: hostRecord.hostId, clientId: callback.clientId, attemptId: transaction.attemptId };
      // A remote registration already exists now. Preserve its ID before exchange.
      if (!registration) await store.write('registration.json', pendingRegistration);
      await store.write('oauth-pending.json', pendingRegistration);
      if (combined.aborted) throw new SiwcError('oauth_aborted');
      const tokens = await publicJson(endpoints.token, { fetcher, signal: combined, limits, body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: callback.clientId, code: callback.code,
        code_verifier: transaction.verifier, redirect_uri: transaction.redirectUri, resource,
      }) });
      const jwks = await publicJson(endpoints.jwks, { fetcher, signal: combined, limits });
      const credentials = await validateTokens(tokens, { clientId: callback.clientId, nonce: transaction.nonce, expectedSubject: previous?.subject, jwks });
      if (combined.aborted) throw new SiwcError('oauth_aborted');
      await store.write('credentials.json', credentials);
      reply(response, 200, 'ScanMux sign-in completed. You can return to Codex.');
      finish(null, credentials);
    })().catch(error => { reply(response, 400, 'ScanMux sign-in did not complete. Return to Codex.'); finish(error); });
  });
  try {
    if (combined.aborted) throw new SiwcError('oauth_aborted');
    await abortable(new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
    }), combined);
    const port = server.address().port;
    const host = `127.0.0.1:${port}`;
    transaction = {
      attemptId: randomUUID(), host, redirectUri: `http://${host}/auth/callback`, clientId: registration?.clientId,
      state: randomValue(), nonce: randomValue(), verifier: randomValue(), expiresAt: Date.now() + lifetimeMs, claimed: false,
    };
    const pending = { schema: 1, state: 'authorizing', hostId: hostRecord.hostId, clientId: registration?.clientId ?? null, attemptId: transaction.attemptId };
    if (!registration) await store.write('registration.json', pending, true);
    await store.write('oauth-pending.json', pending);
    const url = new URL(endpoints.authorization);
    url.search = new URLSearchParams({
      client_id: transaction.clientId ?? 'dynamic_agent_client',
      ...(!transaction.clientId ? { agent_name_hint: 'ScanMux' } : {}),
      ext_agent_host_id: hostRecord.hostId, response_type: 'code', redirect_uri: transaction.redirectUri,
      scope: scopes.join(' '), resource, state: transaction.state, nonce: transaction.nonce,
      code_challenge_method: 'S256', code_challenge: createHash('sha256').update(transaction.verifier).digest('base64url'),
    });
    timer = setTimeout(() => controller.abort(), lifetimeMs);
    if (combined.aborted) throw new SiwcError('oauth_aborted');
    await onReady?.({ url: url.href, expiresAt: new Date(transaction.expiresAt).toISOString() });
    return await result;
  } finally {
    clearTimeout(timer); controller.abort(); combined.removeEventListener('abort', onAbort);
    await new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections(); });
    await callbackTask;
    transaction = undefined;
  }
}
