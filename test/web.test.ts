import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, lstat, writeFile } from 'node:fs/promises';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { request as httpRequest } from 'node:http';
import { stripTypeScriptTypes } from 'node:module';
import { setTimeout as delay } from 'node:timers/promises';
import { startWeb, type WebServices, type WebOptions } from '../src/web.ts';
import { defaults } from '../src/config.ts';
import { digest, SafeError } from '../src/safety.ts';
import type { Plan, Report } from '../src/model.ts';
import type { WebObservation } from '../src/web-connection.ts';
import { isolateStorage } from './isolated-storage.ts';
import { sourceCleanupFailed, sourceCleanupFor, sourceCleanupState } from '../src/source-cleanup.ts';
isolateStorage();

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
async function serveExit(web: Awaited<ReturnType<typeof startWeb>>) {
  const source = stripTypeScriptTypes(await readFile('src/cli.ts', 'utf8'));
  const end = 'return stopped.retained || sourceCleanupFailed() ? 4 : 0;';
  const body = source.slice(source.indexOf('const web = await startWeb(config,'), source.indexOf(end) + end.length);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const run = AsyncFunction('config', 'startWeb', 'values', 'abort', 'sourceCleanupFailed', body);
  const stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = process.stderr.write = () => true;
  try { return await run(defaults, async () => web, {}, new AbortController(), sourceCleanupFailed); }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
function plan(root: string): Plan {
  const value: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: 'fixture', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40),
    snapshotHash: digest([]), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [],
    constraints: ['offline_only'], cost: { kind: 'not_applicable', aiCalls: 0 }, source: { kind: 'public-github', url: 'https://github.com/octocat/Hello-World', commit: 'a'.repeat(40) } };
  value.planHash = digest(value);
  return value;
}
function report(value: Plan, cancelled = false): Report {
  return { schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', plan: value, startedAt: '2026-01-01T00:00:00Z', endedAt: '2026-01-01T00:00:01Z',
    engines: [], runner: { platform: process.platform, node: process.version, imageDigest: null, isolation: 'local-static-only' },
    executionState: cancelled ? 'cancelled' : 'completed', coverageState: 'incomplete', gate: 'INCOMPLETE', exitCode: 3,
    reasons: ['missing_required_engines'], integrityErrors: [] };
}
async function fixture(overrides: Partial<WebServices> = {}, options: WebOptions = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-web-test-'));
  test.after(() => removeTempDir(root));
  const workspaces: string[] = [];
  const counts = { prepare: 0, scan: 0, check: 0 };
  const config = { ...structuredClone(defaults), maxOutputBytes: 65536 };
  const operations: WebServices = {
    workspace: async () => { const w = await mkdtemp(path.join(root, 'job-')); workspaces.push(w); return w; },
    prepare: async (_url, _config, workspace) => { counts.prepare++; const cleanup = sourceCleanupFor(workspace), root = cleanup.register(workspace, path.join(workspace, 'repository')); await mkdir(root); await cleanup.capture(workspace, root); return plan(root); },
    scan: async value => { counts.scan++; return report(value); },
    check: async value => { counts.check++; return JSON.stringify(value); },
    checkText: async value => value,
    ...overrides,
  };
  const web = await startWeb(config, operations, options);
  const endpoint = new URL(web.url), token = endpoint.hash.slice(1), origin = endpoint.origin;
  async function request(route: string, data?: unknown, headers: Record<string, string> = {}) {
    return fetch(origin + route, { method: data === undefined ? 'GET' : 'POST',
      headers: { 'x-scanmux-token': token, ...(data === undefined ? {} : { origin, 'content-type': 'application/json' }), ...headers },
      body: data === undefined ? undefined : JSON.stringify(data) });
  }
  async function state() { return (await request('/api/state')).json(); }
  async function settled() {
    const limit = Date.now() + 5000;
    while (Date.now() < limit) {
      const value = await state();
      if (!['preparing', 'running', 'cancelling'].includes(value.state)) return value;
      await delay(5);
    }
    assert.fail('Job did not settle');
  }
  return { web, root, workspaces, counts, request, state, settled, token, origin,
    close: async () => { await web.close(); await removeTempDirStrict(root, { recursive: true, force: true }); } };
}

test('loopback API enforces Host, Origin, token, JSON and exact input shape before acquisition', async () => {
  const f = await fixture();
  try {
    const page = await fetch(f.origin);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.ok(!html.includes(f.token));
    assert.match(page.headers.get('content-security-policy')!, /frame-ancestors 'none'/);
    const launch = await fetch(f.origin, { headers: { 'sec-fetch-site': 'cross-site' } });
    assert.equal(launch.status, 200, 'Public static shell can be opened from an external application');
    assert.equal(await launch.text(), html);
    // Node fetch normalizes Host; use the HTTP client to actually send an adversarial Host.
    const hostStatus = await new Promise<number | undefined>((resolve, reject) => {
      const req = httpRequest(f.origin + '/api/state', { headers: { host: 'evil.example', 'x-scanmux-token': f.token } }, res => { res.resume(); resolve(res.statusCode); });
      req.on('error', reject); req.end();
    });
    assert.equal(hostStatus, 403);
    const invalidHeaders: Record<string, string>[] = [{ origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }, { 'x-scanmux-token': '' }];
    for (const headers of invalidHeaders) {
      assert.equal((await f.request('/api/state', undefined, headers)).status, 403);
      assert.equal((await f.request('/api/prepare', { url: 'https://github.com/octocat/Hello-World' }, headers)).status, 403);
    }
    const invalidPostHeaders: Record<string, string>[] = [{ origin: '' }, { 'content-type': 'text/plain' }];
    for (const headers of invalidPostHeaders) assert.equal((await f.request('/api/prepare', {}, headers)).status, 403);
    for (const value of [{ url: 'https://example.com/owner/repo' }, { url: 'https://github.com/a/b?token=secret' }, { url: 'https://github.com/a/b', config: {} }, { url: 'https://github.com/a/b', path: '/tmp' }]) {
      assert.equal((await f.request('/api/prepare', value)).status, 400);
    }
    assert.equal((await f.request('/api/prepare', { url: 'a'.repeat(70000) })).status, 400);
    assert.equal((await f.request('/api/unknown')).status, 404);
    assert.equal((await f.request('/api/report/old')).status, 404);
    assert.equal(f.counts.prepare, 0);
  } finally { await f.close(); }
});

test('one owned job, explicit execution, idempotent replay, stale cancellation and exact checked download', async () => {
  const scanGate = deferred();
  let calls = 0;
  const f = await fixture({ scan: async (value, _config, _workspace, signal) => { calls++; await scanGate.promise; return report(value, signal.aborted); } });
  try {
    const prepared = await f.request('/api/prepare', { url: 'https://github.com/octocat/Hello-World' });
    assert.equal(prepared.status, 202);
    const state = await f.settled();
    assert.equal(state.state, 'planned');
    assert.equal(calls, 0);
    assert.ok(!JSON.stringify(state).includes(f.root));
    assert.equal((await f.request('/api/run', { id: 'stale' })).status, 409);
    assert.equal((await f.request('/api/run', { id: state.id })).status, 202);
    assert.equal((await f.request('/api/run', { id: state.id })).status, 200);
    assert.equal(calls, 1);
    assert.equal((await f.request('/api/prepare', { url: 'https://github.com/a/b' })).status, 409);
    assert.equal((await f.request('/api/cancel', { id: 'stale' })).status, 409);
    assert.equal((await f.state()).state, 'running');
    assert.equal((await f.request('/api/report/' + state.id + '/html')).status, 404);
    await f.request('/api/cancel', { id: state.id });
    assert.equal((await f.state()).state, 'cancelling');
    assert.ok(await lstat(path.join(f.workspaces[0], 'repository')));
    scanGate.resolve();
    const done = await f.settled();
    assert.equal(done.state, 'cancelled');
    assert.equal(done.result.gate, 'INCOMPLETE');
    assert.equal(await lstat(path.join(f.workspaces[0], 'repository')).catch(() => null), null);
    const download = await (await f.request('/api/report/' + state.id)).text();
    assert.equal(download, await readFile(path.join(f.workspaces[0], 'report.json'), 'utf8'));
    assert.equal(JSON.parse(download).executionState, 'cancelled');
    const htmlResponse = await f.request('/api/report/' + state.id + '/html');
    assert.equal(htmlResponse.status, 200);
    assert.match(htmlResponse.headers.get('content-security-policy')!, /script-src 'none'/);
    assert.equal(await htmlResponse.text(), await readFile(path.join(f.workspaces[0], 'report.html'), 'utf8'));
    assert.equal(done.capabilities.htmlReport, true);
    assert.equal((await f.request('/api/report/' + state.id + '/html', undefined, { 'x-scanmux-token': '' })).status, 403);
    assert.equal((await f.request('/api/report/00000000-0000-0000-0000-000000000000/html')).status, 404);
    await f.request('/api/run', { id: state.id });
    assert.equal(calls, 1);
    const checks = f.counts.check;
    await f.state(); await f.request('/api/report/' + state.id);
    assert.equal(f.counts.check, checks, 'Read requests never spawn output checks');
  } finally { scanGate.resolve(); await f.close(); }
});

test('HTML save failure publishes neither format and preserves pre-existing bytes', async () => {
  const f = await fixture({ scan: async (value, _config, workspace) => { await writeFile(path.join(workspace, 'report.html'), 'existing'); return report(value); } });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    const planned = await f.settled();
    await f.request('/api/run', { id: planned.id });
    const state = await f.settled();
    assert.equal(state.state, 'error');
    assert.equal(state.reportAvailable, false);
    assert.equal((await f.request('/api/report/' + planned.id)).status, 404);
    assert.equal((await f.request('/api/report/' + planned.id + '/html')).status, 404);
    assert.equal(await readFile(path.join(f.workspaces[0], 'report.html'), 'utf8'), 'existing');
  } finally { await f.close(); }
});

test('preparation cancellation waits for owned work and prevents plan adoption and scan', async () => {
  const gate = deferred();
  const f = await fixture({ prepare: async (_url, _config, workspace) => {
    const cleanup = sourceCleanupFor(workspace), root = cleanup.register(workspace, path.join(workspace, 'repository'));
    await mkdir(root); await cleanup.capture(workspace, root); await gate.promise; return plan(root);
  } });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    const state = await f.state();
    await f.request('/api/cancel', { id: state.id });
    assert.equal((await f.state()).state, 'cancelling');
    assert.equal((await f.request('/api/prepare', { url: 'https://github.com/a/c' })).status, 409);
    gate.resolve();
    const done = await f.settled();
    assert.equal(done.state, 'cancelled');
    assert.equal(done.plan, undefined);
    assert.equal(f.counts.scan, 0);
    assert.equal(f.counts.check, 0);
    assert.equal(await lstat(path.join(f.workspaces[0], 'repository')).catch(() => null), null);
  } finally { gate.resolve(); await f.close(); }
});

test('unverified termination outranks cancellation and removes source while retaining the stop decision', async () => {
  const gate = deferred();
  const f = await fixture({ scan: async value => {
    await gate.promise;
    return { ...report(value), gate: 'ERROR', executionState: 'failed', integrityErrors: ['termination_unverified'], exitCode: 4 };
  } });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    const state = await f.settled();
    await f.request('/api/run', { id: state.id });
    await f.request('/api/cancel', { id: state.id });
    gate.resolve();
    const done = await f.settled();
    assert.equal(done.state, 'error');
    assert.equal(done.retained, true);
    assert.equal(done.canReplace, false);
    assert.equal(done.result.gate, 'ERROR');
    assert.equal(await lstat(path.join(f.workspaces[0], 'repository')).catch(() => null), null);
    assert.equal((await f.request('/api/prepare', { url: 'https://github.com/a/c' })).status, 409);
    assert.equal((await f.web.close()).retained, true);
    assert.equal(await serveExit(f.web), 4, 'web-exit-probe: removed source does not prove termination');
  } finally { gate.resolve(); await f.close(); }
});

test('serve retains a source removal failure from before the current web job', async () => {
  const f = await fixture();
  try {
    sourceCleanupState.failed = true;
    assert.equal((await f.web.close()).retained, true);
    assert.equal(await serveExit(f.web), 4);
  } finally { await f.close(); }
});

test('output rejection never exposes target data and output-check uncertainty still removes source', async () => {
  for (const code of ['output_secret_check_failed', 'termination_unverified']) {
    const f = await fixture({ check: async () => { throw new SafeError(code); } });
    try {
      await f.request('/api/prepare', { url: 'https://github.com/a/b' });
      const state = await f.settled();
      assert.equal(state.state, 'error');
      assert.equal(state.plan, undefined);
      assert.equal(state.result, undefined);
      assert.equal(state.reportAvailable, false);
      assert.equal((await f.request('/api/report/' + state.id)).status, 404);
      assert.equal(state.retained, code === 'termination_unverified');
      assert.equal(await lstat(path.join(f.workspaces[0], 'repository')).catch(() => null), null);
    } finally { await f.close(); }
  }
});

test('planned cancellation blocks subsequent run and replacing a plan invalidates its ID', async () => {
  const f = await fixture();
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    const old = await f.settled();
    await f.request('/api/cancel', { id: old.id });
    assert.equal((await f.settled()).state, 'cancelled');
    assert.equal((await f.request('/api/run', { id: old.id })).status, 409);
    await f.request('/api/prepare', { url: 'https://github.com/a/c' });
    const next = await f.settled();
    assert.notEqual(next.id, old.id);
    assert.equal((await f.request('/api/cancel', { id: old.id })).status, 409);
    assert.equal((await f.state()).state, 'planned');
    assert.equal(f.counts.scan, 0);
  } finally { await f.close(); }
});

test('Sites authority is paired to its origin and cannot obtain local credentials or shutdown', async () => {
  const siteOrigin = 'https://scanner.example';
  const f = await fixture({}, { siteOrigin });
  try {
    const connection = await (await f.request('/api/site-connection')).json();
    assert.notEqual(connection.token, f.token);
    const site = { origin: siteOrigin, 'x-scanmux-token': connection.token };
    assert.equal((await f.request('/api/state', undefined, site)).status, 200);
    assert.equal((await f.request('/api/site-connection', undefined, site)).status, 403);
    assert.equal((await f.request('/api/shutdown', {}, site)).status, 403);
    const wrongPairs: Record<string, string>[] = [{ origin: siteOrigin }, { origin: f.origin, 'x-scanmux-token': connection.token },
      { 'x-scanmux-token': connection.token }, { ...site, origin: 'null' }, { ...site, origin: siteOrigin + '.evil' }];
    for (const headers of wrongPairs) {
      assert.equal((await f.request('/api/state', undefined, headers)).status, 403);
      assert.equal((await f.request('/api/prepare', { url: 'https://github.com/a/b' }, headers)).status, 403);
    }
    for (const [route, method, requestHeaders, expected] of [
      ['/api/state', 'GET', 'x-scanmux-token', 204], ['/api/prepare', 'POST', 'content-type,x-scanmux-token', 204],
      ['/api/shutdown', 'POST', 'content-type,x-scanmux-token', 403], ['/api/site-connection', 'GET', 'x-scanmux-token', 403],
      ['/api/run', 'DELETE', 'content-type,x-scanmux-token', 403], ['/api/state', 'GET', 'authorization,x-scanmux-token', 403],
      ['/api/report/00000000-0000-0000-0000-000000000000/html', 'GET', 'x-scanmux-token', 204],
      ['/api/report/00000000-0000-0000-0000-000000000000/html/extra', 'GET', 'x-scanmux-token', 403],
    ] as const) {
      const response = await fetch(f.origin + route, { method: 'OPTIONS', headers: { origin: siteOrigin,
        'access-control-request-method': method, 'access-control-request-headers': requestHeaders } });
      assert.equal(response.status, expected);
      assert.equal(response.headers.get('access-control-allow-origin'), expected === 204 ? siteOrigin : null);
    }
    assert.equal(f.counts.prepare, 0);
    await f.request('/api/prepare', { url: 'https://github.com/a/b' }, site);
    const planned = await f.settled();
    await f.request('/api/run', { id: planned.id }, site);
    const done = await f.settled();
    assert.equal(done.state, 'completed');
    assert.equal(done.contract, 'scanmux.web/v2');
    assert.equal(await (await f.request('/api/report/' + done.id, undefined, site)).text(),
      await (await f.request('/api/report/' + done.id)).text());
    assert.equal(await (await f.request('/api/report/' + done.id + '/html', undefined, site)).text(),
      await (await f.request('/api/report/' + done.id + '/html')).text());
    for (const headers of wrongPairs) assert.equal((await f.request('/api/report/' + done.id + '/html', undefined, headers)).status, 403);
  } finally { await f.close(); }
});

test('normal update shutdown refuses active, planned and retained jobs and settles once', async () => {
  const gate = deferred();
  const f = await fixture({ prepare: async (_url, _config, workspace) => { await gate.promise; return plan(workspace); } });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    assert.equal((await f.request('/api/shutdown', {})).status, 409);
    gate.resolve();
    const p = await f.settled();
    assert.equal((await f.request('/api/shutdown', {})).status, 409);
    await f.request('/api/cancel', { id: p.id });
    await f.settled();
    assert.equal((await f.request('/api/shutdown', { extra: true })).status, 400);
    assert.equal((await f.request('/api/shutdown', {})).status, 202);
    assert.equal((await f.web.closed).retained, false);
    assert.deepEqual(await f.web.close(), await f.web.closed);
  } finally { gate.resolve(); await f.close(); }
  const retained = await fixture({ prepare: async () => { throw new SafeError('termination_unverified'); } });
  try {
    await retained.request('/api/prepare', { url: 'https://github.com/a/b' });
    await retained.settled();
    assert.equal((await retained.request('/api/shutdown', {})).status, 409);
  } finally { await retained.close(); }
});

for (const termination of [false, true]) test(`failed web source removal is saved as ERROR and preserves termination=${termination}`, async t => {
  const f = await fixture({ scan: async value => termination
    ? { ...report(value), gate: 'ERROR', exitCode: 4, executionState: 'failed', integrityErrors: ['termination_unverified'] } : report(value) });
  const rmdir = fs.rmdir;
  let locked = true;
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (locked && args[0] === path.join(f.workspaces[0], 'repository')) throw Object.assign(new Error(), { code: 'EBUSY' });
    return rmdir(...args);
  });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/a/b' });
    const planned = await f.settled(); await f.request('/api/run', { id: planned.id });
    const state = await f.settled();
    assert.equal(state.state, 'error'); assert.equal(state.result.gate, 'ERROR'); assert.equal(state.retained, true);
    assert.ok(state.result.integrityErrors.includes('source_cleanup_failed'));
    assert.equal(state.result.integrityErrors.includes('termination_unverified'), termination);
    assert.equal(state.error, termination ? 'termination_unverified' : 'source_cleanup_failed');
    const saved = await (await f.request('/api/report/' + state.id)).json();
    assert.equal(saved.exitCode, 4); assert.equal(saved.gate, 'ERROR'); assert.ok(saved.integrityErrors.includes('source_cleanup_failed'));
    locked = false;
    assert.equal((await f.web.close()).retained, true); assert.equal(await serveExit(f.web), 4);
    assert.equal(await lstat(path.join(f.workspaces[0], 'repository')).catch(() => null), null);
  } finally { locked = false; await f.close(); }
});

test('improvement observations contain only closed fields and observer failures cannot change scan judgment', async () => {
  const events: WebObservation[] = [];
  const f = await fixture({}, { observe: async event => { events.push(event); if (event.operation === 'scan') throw new Error('synthetic'); } });
  try {
    await f.request('/api/prepare', { url: 'https://github.com/private-canary/do-not-copy' });
    const p = await f.settled();
    await f.request('/api/run', { id: p.id });
    const done = await f.settled();
    assert.equal(done.result.gate, 'INCOMPLETE');
    assert.equal(done.observation, 'write_failed');
    assert.equal(events.length, 2);
    assert.ok(!JSON.stringify(events).includes('canary'));
    assert.ok(!JSON.stringify(events).includes(f.root));
    assert.deepEqual(Object.keys(events[1]).sort(), ['schema','eventId','at','operation','outcome','gate','reason','files','findings'].sort());
  } finally { await f.close(); }
});
