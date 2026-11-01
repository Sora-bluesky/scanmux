import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile, lstat, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { acquireDatabase, parseAcquisitionArgs } from '../scripts/fetch-osv-db.mjs';
import { databaseUrl, markerName, receiptName } from '../src/osv-database.ts';

const bytes = Buffer.from('synthetic download');
const now = () => Date.parse('2026-01-02T00:00:00.000Z');
async function options() {
  const parent = await mkdtemp(path.join(tmpdir(), 'scanmux-acquire-test-'));
  test.after(() => removeTempDir(parent));
  return { destination: path.join(parent, 'dataset'), ecosystems: ['npm'], maxBytes: 1024, timeoutMs: 10000 };
}
function response(url, change = {}) {
  const headers = { 'content-length': String(bytes.length), 'x-goog-generation': '123',
    'last-modified': 'Thu, 01 Jan 2026 00:00:00 GMT', 'x-goog-hash': `md5=${createHash('md5').update(bytes).digest('base64')}`, ...change.headers };
  const r = new Response(change.body ?? bytes, { status: change.status ?? 200, headers });
  Object.defineProperty(r, 'url', { value: change.url ?? url });
  if (change.redirected) Object.defineProperty(r, 'redirected', { value: true });
  return r;
}
test('explicit budgets and fixed ecosystem arguments reject alternatives before mutation', async () => {
  const o = await options();
  const args = ['--destination', o.destination, '--ecosystems', 'npm,Go', '--max-bytes', '1024', '--timeout-ms', '10000'];
  assert.deepEqual(parseAcquisitionArgs(args), { ...o, ecosystems: ['npm', 'Go'] });
  for (const bad of [[], args.slice(0, -2), [...args, '--url', 'https://attacker.invalid'], [...args, '--ecosystems', 'npm'],
    args.map(v => v === 'npm,Go' ? 'npm,npm' : v), args.map(v => v === 'npm,Go' ? 'unknown' : v),
    args.map(v => v === '1024' ? '0' : v), args.map(v => v === '10000' ? '2147483648' : v),
    args.map(v => v === o.destination ? 'relative' : v)]) assert.throws(() => parseAcquisitionArgs(bad));
  let calls = 0;
  await assert.rejects(acquireDatabase({ ...o, ecosystems: ['unknown'] }, { fetcher: () => { calls++; } }));
  assert.equal(calls, 0); await assert.rejects(lstat(o.destination), { code: 'ENOENT' });
});
test('complete multiple-ecosystem acquisition preserves exact bytes and publishes receipt last', async () => {
  const o = await options(), calls = [];
  const receipt = await acquireDatabase({ ...o, ecosystems: ['npm', 'Go'] }, { now, fetcher: async (url, init) => {
    calls.push(url); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit'); assert.equal(init.method, 'GET'); assert.equal(init.headers, undefined);
    await assert.rejects(lstat(path.join(o.destination, receiptName)), { code: 'ENOENT' }); return response(url);
  } });
  assert.deepEqual(calls, [databaseUrl('npm'), databaseUrl('Go')]);
  assert.deepEqual(JSON.parse(await readFile(path.join(o.destination, receiptName), 'utf8')), receipt);
  for (const e of receipt.entries) {
    assert.deepEqual(await readFile(path.join(o.destination, 'osv-scalibr', e.ecosystem, 'all.zip')), bytes);
    assert.equal(e.sha256, createHash('sha256').update(bytes).digest('hex'));
    assert.ok(e.sourceModifiedAt < e.observedStartedAt);
  }
});
test('response and streaming failures keep managed incomplete state without a success receipt', async () => {
  const cases = [ { status: 302 }, { status: 500 }, { redirected: true }, { url: 'https://attacker.invalid/' },
    { headers: { 'content-length': '0' } }, { headers: { 'content-length': '99999' } }, { headers: { 'content-length': String(bytes.length + 1) } },
    { headers: { 'content-length': String(bytes.length - 1) } }, { headers: { 'x-goog-generation': 'unknown' } },
    { headers: { 'content-encoding': 'gzip' } }, { headers: { 'x-goog-hash': 'crc32c=abc' } },
    { headers: { 'x-goog-hash': 'md5=AAAAAAAAAAAAAAAAAAAAAA==' } },
    { headers: { 'last-modified': 'Sat, 03 Jan 2026 00:00:00 GMT' } },
    { body: new ReadableStream({ start(controller) { controller.enqueue(bytes.subarray(0, 1)); controller.error(new Error('synthetic disconnect')); } }) },
  ];
  for (const value of cases) {
    const o = await options(); await assert.rejects(acquireDatabase(o, { now, fetcher: async url => response(url, value) }));
    assert.ok((await lstat(path.join(o.destination, markerName))).isFile());
    await assert.rejects(lstat(path.join(o.destination, receiptName)), { code: 'ENOENT' });
  }
});
test('aggregate byte budget and deadline fail closed without retries', async () => {
  const o = await options(); let calls = 0;
  await assert.rejects(acquireDatabase({ ...o, ecosystems: ['npm', 'Go'], maxBytes: bytes.length }, { now, fetcher: async url => { calls++; return response(url); } }), { code: 'database_download_byte_budget' });
  assert.equal(calls, 2); await assert.rejects(lstat(path.join(o.destination, receiptName)), { code: 'ENOENT' });
  const timeout = await options(); let timeoutCalls = 0;
  const keeper = setInterval(() => {}, 1000);
  try {
    await assert.rejects(acquireDatabase({ ...timeout, timeoutMs: 10 }, { now, fetcher: async (_url, init) => {
      timeoutCalls++; return new Promise((_resolve, reject) => { if (init.signal.aborted) reject(init.signal.reason); else init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true }); });
    } }));
  } finally { clearInterval(keeper); }
  assert.ok(timeoutCalls <= 1); await assert.rejects(lstat(path.join(timeout.destination, receiptName)), { code: 'ENOENT' });
});
test('existing destination and old dataset are never overwritten or fetched again', async () => {
  const o = await options(); await mkdir(o.destination); await writeFile(path.join(o.destination, 'keep'), 'original'); let calls = 0;
  await assert.rejects(acquireDatabase(o, { fetcher: async () => { calls++; } }), { code: 'EEXIST' });
  assert.equal(calls, 0); assert.equal(await readFile(path.join(o.destination, 'keep'), 'utf8'), 'original');
});
