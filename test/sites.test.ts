import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { checkedObservation, observationWriter } from '../src/observations.ts';
import type { WebObservation } from '../src/web-connection.ts';
import { verifySiteFiles, siteFiles, siteAssets } from '../scripts/build-site.ts';
import { runInNewContext } from 'node:vm';
import { siteJavascript } from '../src/web-ui.ts';

test('Sites CSP precedes scripts and authorizes only the exact emitted application bytes', () => {
  const assets = siteAssets();
  const document = assets['index.html'];
  const hash = `sha256-${createHash('sha256').update(assets['app.js']).digest('base64')}`;
  const meta = document.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)!;
  assert.ok(meta);
  assert.ok(document.includes(`<meta charset="utf-8">${meta[0]}`));
  assert.ok(document.indexOf(meta[0]) < document.indexOf('<script'));
  assert.equal(document.match(/<script\b/g)?.length, 1);
  assert.ok(document.includes(`<script defer src="/app.js" integrity="${hash}"></script>`));
  assert.equal(meta[1].split('; ').find(value => value.startsWith('script-src ')), `script-src '${hash}'`);
  assert.ok(meta[1].includes("worker-src 'none'"));
  assert.ok(meta[1].includes('connect-src http://127.0.0.1:*'));
  assert.ok(!meta[1].includes('frame-ancestors'));
  assert.ok(assets._headers.includes(`Content-Security-Policy: ${meta[1]}; frame-ancestors 'none'`));
  for (const untrusted of ['alert(1)', assets['app.js'].toString('utf8') + '\n// changed']) {
    assert.ok(!meta[1].includes(createHash('sha256').update(untrusted).digest('base64')));
  }
});

test('observation storage rejects unknown text before writing and serializes concurrent counters', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-observation-test-'));
  const event: WebObservation = { schema: 'scanmux.observation/v1', eventId: randomUUID(), at: new Date().toISOString(),
    operation: 'scan', outcome: 'completed', gate: 'INCOMPLETE', reason: 'none', files: 1, findings: 0 };
  try {
    for (const bad of [{ ...event, url: 'private-canary' }, { ...event, reason: 'private-canary' }, { ...event, files: -1 },
      { ...event, at: 'private-canary' }, { ...event, eventId: 'private-canary' }, { ...event, findings: Infinity }]) {
      assert.throws(() => checkedObservation(bad as WebObservation));
    }
    const writer = observationWriter(root);
    await Promise.all([writer.observe(event), writer.observe({ ...event, eventId: randomUUID() })]);
    const saved = JSON.parse(await readFile(writer.destination, 'utf8'));
    assert.equal(saved.counts['scan:completed:INCOMPLETE:none'], 2);
    assert.equal(saved.latest.files, 1);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Sites publication allowlist rejects stray inputs including nested internal files', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-site-test-'));
  try {
    for (const name of siteFiles) { await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), 'fixture'); }
    await verifySiteFiles(root);
    await writeFile(path.join(root, 'dist', 'internal.json'), 'private-canary');
    await assert.rejects(verifySiteFiles(root), /Unexpected or missing site source/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Sites accepts only its opener and loopback pair; mismatch and connection loss block mutations', async () => {
  function node(): any { return { append() {}, replaceChildren() {}, addEventListener() {}, setAttribute() {}, querySelector() { return null; }, focus() {}, dataset: {} }; }
  for (const contract of ['scanmux.web/v2', 'unsupported']) {
    const messages: unknown[] = [], requests: { url: string; options: any }[] = [];
    let listener!: (event: any) => void;
    const opener = { postMessage: (data: unknown) => messages.push(data), focus() {} };
    const context: any = { URL, location: { origin: 'https://scanner.example', hash: '#must-not-be-used' },
      history: { replaceState() {} }, sessionStorage: { getItem() { assert.fail('Sites storage read'); }, setItem() { assert.fail('Sites storage write'); } },
      window: { opener, addEventListener: (_name: string, fn: typeof listener) => { listener = fn; } },
      document: { getElementById: node, createElement: node, createTextNode: node }, setTimeout() {},
      fetch: async (url: string, options: any) => { requests.push({ url, options }); return { ok: true, json: async () => ({ contract, state: 'idle' }) }; },
    };
    runInNewContext(siteJavascript + '\nglobalThis.check = { api, refresh };', context);
    assert.deepEqual(JSON.parse(JSON.stringify(messages)), [{ type: 'scanmux-site-ready', contract: 'scanmux.web/v2' }]);
    const data = { type: 'scanmux-local-session', contract: 'scanmux.web/v2', endpoint: 'http://127.0.0.1:12345', token: 'a'.repeat(64) };
    for (const event of [{ data, source: {}, origin: data.endpoint }, { data, source: opener, origin: 'https://evil.example' },
      { data: { ...data, endpoint: 'http://localhost:12345' }, source: opener, origin: 'http://localhost:12345' },
      { data: { ...data, extra: 'canary' }, source: opener, origin: data.endpoint }]) listener(event);
    assert.equal(requests.length, 0);
    listener({ data, source: opener, origin: data.endpoint });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, data.endpoint + '/api/state');
    assert.equal(requests[0].options.credentials, 'omit');
    assert.equal(requests[0].options.redirect, 'error');
    listener({ data: { ...data, endpoint: 'http://127.0.0.1:54321' }, source: opener, origin: 'http://127.0.0.1:54321' });
    assert.equal(requests.length, 1);
    if (contract === 'unsupported') await assert.rejects(context.check.api('/api/run', { id: 'fixture' }));
    else {
      context.fetch = async () => { throw new Error('PC stopped or browser denied'); };
      await context.check.refresh();
      await assert.rejects(context.check.api('/api/run', { id: 'fixture' }));
    }
    assert.equal(requests.filter(value => value.options.method === 'POST').length, 0);
  }
});
