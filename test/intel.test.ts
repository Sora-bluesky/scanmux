import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { watch } from 'node:fs';
import fsPromises, { chmod, mkdtemp, mkdir, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { feeds } from '../src/intel/feeds.ts';
import { toCveId } from '../src/intel/syntax.ts';
import { parseKev } from '../src/intel/kev.ts';
import { parseJvnRss } from '../src/intel/jvn-rss.ts';
import { loadIntel, openStore, refreshIntel, type Fetcher } from '../src/intel/store.ts';
import { intelExitCode, matchIntel, readSource } from '../src/intel/match.ts';
import { intelDictionary, renderIntelHtml, renderIntelSarif, renderIntelText } from '../src/intel/render.ts';
import { matchIntelFiles, parseMaxAgeHours, writeIntelBundle } from '../src/intel/index.ts';
import { main } from '../src/cli.ts';
import { defaults } from '../src/config.ts';
import { canonical, digest, hash } from '../src/safety.ts';
import { realConfigPath, realConfigSkip } from './real-config.ts';
import { withTestProcessOwner } from './process-owner.ts';

const t0 = Date.parse('2026-10-26T00:00:00.000Z'), hour = 3600000;
const kevUrl = feeds.kev.url(''), jvnUrl = feeds.jvn.url(''), jvndbUrl = feeds.jvndb.url('2026-10-26T00:00:00.000Z');
function kevBody(entries: Record<string, unknown>[] = [kevEntry('CVE-2026-0001')], change: Record<string, unknown> = {}): Buffer {
  return Buffer.from(JSON.stringify({ title: 'CISA Catalog', catalogVersion: '2026.10.23', dateReleased: '2026-10-23T19:30:18.9209Z', count: entries.length, vulnerabilities: entries, ...change }));
}
function kevEntry(cveID: string, change: Record<string, unknown> = {}): Record<string, unknown> {
  return { cveID, vendorProject: 'Vendor', product: 'Product', vulnerabilityName: 'Vendor Product Flaw', dateAdded: '2026-10-01', shortDescription: 'Synthetic.',
    requiredAction: 'Apply updates.', dueDate: '2026-10-22', knownRansomwareCampaignUse: 'Unknown', notes: '', cwes: [], forensicTriage: 'new key', ...change };
}
function item(identifier: string | null, title: string, description: string, modified = '2026-10-24T10:00:00+09:00'): string {
  return `<item rdf:about="https://jvn.jp/vu/X/"><title>${title}</title><link>https://jvn.jp/vu/${identifier ?? 'none'}/</link><description>${description}</description>`
    + `${identifier === null ? '' : `<dc:identifier>${identifier}</dc:identifier>`}<dc:date>${modified}</dc:date><dcterms:modified>${modified}</dcterms:modified></item>`;
}
function rss(items = [item('JVNVU#1', 'CVE-2026-0001 issue', '&lt;p&gt;Fixes cve-2026-0002 &amp;amp; CVE-2026-0001&lt;/p&gt;'), item('JVNVU#2', 'Other', 'CVE-2026-0002', '2026-10-25T10:00:00+09:00')]): Buffer {
  return Buffer.from(`<?xml version="1.0" encoding="utf-8"?>\n<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><channel rdf:about="https://jvn.jp/"><title>JVN</title><dc:date>2026-10-25T11:00:00+09:00</dc:date><dcterms:modified>2026-10-25T11:00:00+09:00</dcterms:modified><items><rdf:Seq><rdf:li rdf:resource="x"/></rdf:Seq></items></channel>${items.join('')}</rdf:RDF>`);
}
function respond(url: string, body: Buffer | null, status = 200, change: { url?: string } = {}): Response {
  const response = new Response(body === null ? null : new Uint8Array(body), { status, headers: { 'content-type': 'application/json' } });
  Object.defineProperty(response, 'url', { value: change.url ?? url });
  return response;
}
type Plan = Partial<Record<'kev' | 'jvn' | 'jvndb', () => Response | Promise<Response>>>;
function fetcher(plan: Plan = {}, calls: { url: string; init: RequestInit }[] = []): Fetcher {
  return async (url, init) => {
    calls.push({ url, init });
    if (url === kevUrl) return plan.kev ? plan.kev() : respond(url, kevBody());
    if (url === jvnUrl) return plan.jvn ? plan.jvn() : respond(url, rss());
    return plan.jvndb ? plan.jvndb() : respond(url, Buffer.from('<html>stopped</html>'), 503);
  };
}
const clock = (start = t0) => { let now = start; return () => now++; };
async function tempDirectory(prefix: string): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), prefix));
  test.after(() => removeTempDir(directory));
  return directory;
}
async function store(): Promise<string> { return path.join(await tempDirectory('scanmux-intel-test-'), 'store'); }
async function commandTemp() {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-intel-command-'));
  test.after(async () => {
    for (const name of await readdir(directory).catch(() => [])) if (name.startsWith('scanmux-')) await removeTempDir(path.join(directory, name));
    await removeTempDir(directory);
  });
  const saved = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  test.after(() => { for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value; });
  Object.assign(process.env, { TEMP: directory, TMP: directory, TMPDIR: directory });
}

test('KEV parses with unknown keys and keeps seven fractional digits as text', () => {
  const catalog = parseKev(kevBody([kevEntry('CVE-2026-0001'), kevEntry('CVE-2026-0001')], { extra: true }));
  assert.equal(catalog.dateReleased, '2026-10-23T19:30:18.9209Z'); assert.equal(catalog.entries.size, 1);
  assert.equal(catalog.entries.get(toCveId('CVE-2026-0001')!)?.knownRansomwareCampaignUse, 'Unknown');
});
test('KEV drift is all or nothing', () => {
  for (const body of [kevBody(undefined, { count: 2 }), kevBody([kevEntry('CVE-2026-0001', { dueDate: undefined })]), kevBody([kevEntry('cve-2026-0001')]),
    kevBody([kevEntry('CVE-2026-0001'), kevEntry('CVE-2026-0001', { product: 'Other' })]), kevBody(undefined, { dateReleased: '2026-10-23' }), Buffer.from('{'),
    kevBody([kevEntry('CVE-2026-0001', { shortDescription: undefined })]), kevBody([kevEntry('CVE-2026-0001', { requiredAction: undefined })])])
    assert.throws(() => parseKev(body), /intel_schema_drift/);
});
test('KEV refuses duplicates that differ in any known field and calendar dates that do not exist', () => {
  for (const change of [{ requiredAction: 'Do not patch.' }, { shortDescription: 'Different.' }])
    assert.throws(() => parseKev(kevBody([kevEntry('CVE-2026-0001'), kevEntry('CVE-2026-0001', change)])), /intel_schema_drift/, JSON.stringify(change));
  for (const body of [kevBody([kevEntry('CVE-2026-0001', { dateAdded: '2026-02-31' })]), kevBody([kevEntry('CVE-2026-0001', { dueDate: '2026-13-01' })]),
    kevBody(undefined, { dateReleased: '2026-02-31T00:00:00Z' }), kevBody(undefined, { dateReleased: '2026-10-23T24:00:00Z' })])
    assert.throws(() => parseKev(body), /intel_schema_drift/);
  assert.throws(() => parseJvnRss(rss([item('JVNVU#1', 'x', 'y', '2026-02-30T10:00:00+09:00')])), /intel_schema_drift/);
});
test('toCveId accepts only exact CVE identifiers and never guesses', () => {
  for (const [input, expected] of [[' cve-2026-12345 ', 'CVE-2026-12345'], ['CVE-2026-0001', 'CVE-2026-0001'], ['CVE-2026-001', null], ['GHSA-xxxx-yyyy-zzzz', null],
    ['CVE-26-0001', null], ['CVE-2026-0001x', null], [42, null], ['', null]] as const) assert.equal(toCveId(input), expected);
});
test('JVN RSS decodes escaped descriptions and collects CVEs per item and across items', () => {
  const window = parseJvnRss(rss());
  assert.deepEqual(window.items.map(entry => [entry.identifier, entry.cves]), [['JVNVU#1', ['CVE-2026-0001', 'CVE-2026-0002']], ['JVNVU#2', ['CVE-2026-0002']]]);
  assert.equal(window.oldest, '2026-10-24T10:00:00+09:00'); assert.equal(window.newest, '2026-10-25T10:00:00+09:00'); assert.equal(window.modified, '2026-10-25T11:00:00+09:00');
});
test('JVN RSS rejects a missing identifier, DTDs, unknown entities and duplicate elements', () => {
  for (const body of [rss([item(null, 'x', 'y')]), Buffer.from(`<!DOCTYPE x [<!ENTITY a "b">]>${rss().toString()}`), rss([item('JVNVU#1', 'x', '&nbsp;')]),
    rss([item('JVNVU#1', 'x', 'a & b')]), rss([item('JVNVU#1', 'x', 'y').replace('</title>', '</title><title>again</title>')]), Buffer.from([0xff])])
    assert.throws(() => parseJvnRss(body), /intel_schema_drift/);
});

test('JVN RSS reads only real items: comments are skipped and CDATA may be mixed with text', () => {
  const hidden = `<!--${item('JVNVU#9', 'CVE-2026-0009 hidden', 'x')}-->`;
  const window = parseJvnRss(rss([hidden, item('JVNVU#1', 'Plain', '  <![CDATA[ <b>CVE-2026-0005</b> ]]> and CVE-2026-0007  '), item('JVNVU#2', 'Other', 'none')]));
  assert.deepEqual(window.items.map(entry => [entry.identifier, entry.cves]), [['JVNVU#1', ['CVE-2026-0005', 'CVE-2026-0007']], ['JVNVU#2', []]]);
});
test('JVN RSS rejects an unclosed root, a processing instruction and an item field it cannot read', () => {
  for (const body of [Buffer.from(rss().toString().replace('</rdf:RDF>', '')), Buffer.from(rss().toString().replace('?>', '?><?xml-stylesheet href="x"?>')),
    rss([item('JVNVU#1', 'x', '<p>CVE-2026-0001</p>')]), Buffer.from(`${rss().toString()}<rdf:RDF></rdf:RDF>`), Buffer.from(rss().toString().replace('</channel>', '</channel></x>'))])
    assert.throws(() => parseJvnRss(body), /intel_schema_drift/);
});
test('JVN RSS takes a CVE only as a whole token', () => {
  const window = parseJvnRss(rss([item('JVNVU#3', 'CVE-2026-0001x XCVE-2026-0003 CVE-2026-0004-1 _CVE-2026-0008', 'CVE-2026-00051 と CVE-2026-0006の対策')]));
  assert.deepEqual(window.items[0].cves, ['CVE-2026-00051', 'CVE-2026-0006']);
});
test('JVN RSS refuses duplicate or undefined attributes, malformed comments and characters XML does not allow', () => {
  const control = String.fromCharCode(1), nonCharacter = String.fromCharCode(0xfffe);
  for (const body of [rss([item('JVNVU#1', 'x', 'y').replace('<item ', '<item rdf:about="a" ')]), rss([item('JVNVU#1', 'x', 'y').replace('rdf:about="https://jvn.jp/vu/X/"', 'rdf:about="&unknown;"')]),
    rss(['<!-- a -- b -->', item('JVNVU#1', 'x', 'y')]), rss(['<!-- a --->', item('JVNVU#1', 'x', 'y')]), rss([item('JVNVU#1', `x${control}`, 'y')]),
    rss([item('JVNVU#1', 'x', '&#1;')]), rss([item('JVNVU#1', 'x', nonCharacter)])])
    assert.throws(() => parseJvnRss(body), /intel_schema_drift/, body.toString().slice(380, 460));
  assert.equal(parseJvnRss(rss(['<!-- a - b -->', item('JVNVU#1', 'x&#9;', 'y')])).items.length, 1);
});
test('refresh fetches exactly the fixed URLs with nothing derived from local data', async () => {
  const calls: { url: string; init: RequestInit }[] = [], location = await store();
  const attempts = await refreshIntel(location, { fetcher: fetcher({}, calls), now: clock() });
  assert.deepEqual(calls.map(call => call.url), [kevUrl, jvnUrl, jvndbUrl]);
  for (const { init } of calls) assert.deepEqual(Object.keys(init).sort(), ['credentials', 'method', 'redirect', 'signal']);
  assert.ok(calls.every(({ init }) => init.method === 'GET' && init.redirect === 'error' && init.credentials === 'omit'));
  assert.deepEqual(attempts.map(attempt => attempt.outcome.kind), ['stored', 'stored', 'failed']);
  assert.deepEqual(attempts[2].outcome, { kind: 'failed', reason: 'http_status', httpStatus: 503 });
  assert.equal(attempts[0].termsUrl, feeds.kev.termsUrl); assert.equal(attempts[1].termsUrl, null);
});
test('JVNDB 200 is recorded as unsupported and never parsed', async () => {
  const location = await store();
  const attempts = await refreshIntel(location, { fetcher: fetcher({ jvndb: () => respond(jvndbUrl, Buffer.from('<rdf/>')) }), now: clock() });
  assert.deepEqual(attempts[2].outcome, { kind: 'unsupported', httpStatus: 200 });
  assert.equal((await loadIntel(location, t0 + hour)).feeds.jvndb.generation, null);
});
test('a network error and a timeout are recorded as failed attempts', async () => {
  const location = await store(), waiting: Fetcher = (_url, init) => new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)));
  const attempts = await refreshIntel(location, { fetcher: async (url, init) => url === kevUrl ? Promise.reject(new TypeError('fetch failed')) : url === jvnUrl ? waiting(url, init) : fetcher()(url, init), now: clock(), timeoutMs: 1 });
  assert.deepEqual(attempts.map(attempt => attempt.outcome), [{ kind: 'failed', reason: 'network', httpStatus: null }, { kind: 'failed', reason: 'timeout', httpStatus: null }, { kind: 'failed', reason: 'http_status', httpStatus: 503 }]);
});
test('byte limit, redirect mismatch and schema drift fail without leaving visible blobs', async () => {
  const location = await store();
  const endless = () => Object.defineProperty(new Response(new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); } }), { status: 200 }), 'url', { value: kevUrl }) as Response;
  let attempts = await refreshIntel(location, { fetcher: fetcher({ kev: endless, jvn: () => respond(jvnUrl, rss(), 200, { url: 'https://jvn.jp/other' }) }), now: clock() });
  assert.deepEqual(attempts.map(attempt => attempt.outcome.kind === 'failed' ? attempt.outcome.reason : attempt.outcome.kind), ['byte_limit', 'url_mismatch', 'http_status']);
  attempts = await refreshIntel(location, { fetcher: fetcher({ kev: () => respond(kevUrl, kevBody(undefined, { count: 9 })), jvn: () => respond(jvnUrl, Buffer.from('<rdf:RDF>no items</rdf:RDF>')) }), now: clock(t0 + 10) });
  assert.deepEqual(attempts.map(attempt => attempt.outcome.kind === 'failed' ? attempt.outcome.reason : attempt.outcome.kind), ['schema_drift', 'schema_drift', 'http_status']);
  assert.deepEqual(await readdir(path.join(location, 'blobs')), []);
  await writeFile(path.join(location, 'blobs', 'a'.repeat(64) + '.x.partial'), 'partial');
  await writeFile(path.join(location, 'attempts', '20990101T000000000Z-00000000-0000-0000-0000-000000000000.json.partial'), '{');
  const loaded = await loadIntel(location, t0 + hour);
  assert.equal(loaded.feeds.kev.notes.length, 0); assert.equal(loaded.feeds.kev.generation, null);
});

async function broaden(directory: string): Promise<void> {
  if (process.platform !== 'win32') return chmod(directory, 0o755);
  const icacls = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'icacls.exe');
  assert.equal(spawnSync(icacls, [directory, '/grant', '*S-1-1-0:(OI)(CI)(R)'], { windowsHide: true, stdio: 'ignore' }).status, 0, 'fixture grants Everyone read');
}
test('an existing store is used only when it and both children are private to the current user', async () => {
  const manual = await store();
  await mkdir(manual); await mkdir(path.join(manual, 'attempts')); await mkdir(path.join(manual, 'blobs'));
  if (process.platform !== 'win32') await chmod(manual, 0o755);
  await assert.rejects(loadIntel(manual, t0), /intel_store_not_private/);
  await assert.rejects(refreshIntel(manual, { fetcher: fetcher(), now: clock() }), /intel_store_not_private/);
  for (const child of ['attempts', 'blobs']) {
    const location = await store();
    await refreshIntel(location, { fetcher: fetcher(), now: clock() });
    await broaden(path.join(location, child));
    await assert.rejects(loadIntel(location, t0 + hour), /intel_store_not_private/, child);
  }
});
test('an interrupted initialisation is completed on the next refresh', async () => {
  const location = await store();
  await mkdir(location); await mkdir(path.join(location, 'attempts'));
  if (process.platform !== 'win32') for (const directory of [location, path.join(location, 'attempts')]) await chmod(directory, 0o755);
  assert.deepEqual((await refreshIntel(location, { fetcher: fetcher(), now: clock() })).map(attempt => attempt.outcome.kind), ['stored', 'stored', 'failed']);
  assert.deepEqual((await readdir(location)).sort(), ['attempts', 'blobs']);
  assert.equal((await loadIntel(location, t0 + hour)).feeds.kev.generation?.attempt.startedAt, '2026-10-26T00:00:00.000Z');
});
test('completing an interrupted initialisation makes an existing broader child private', async () => {
  const location = await store(), attempts = path.join(location, 'attempts');
  await mkdir(location); await mkdir(attempts); await broaden(attempts);
  await refreshIntel(location, { fetcher: fetcher(), now: clock() });
  if (process.platform !== 'win32') return assert.equal((await fsPromises.lstat(attempts)).mode & 0o777, 0o700);
  const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const script = `"$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) Allow"
[IO.DirectoryInfo]::new($env:ATTEMPTS).GetAccessControl().GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { "$($_.IdentityReference.Value) $($_.AccessControlType)" }`;
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot, ATTEMPTS: attempts } });
  const [user, ...rules] = result.stdout.trim().split(/\r?\n/);
  assert.deepEqual(rules, [user]);
});
test('adopting a store refuses a child junction and leaves the ACLs of the junction and its target unchanged', { skip: process.platform !== 'win32' }, async () => {
  const location = await store(), link = path.join(location, 'attempts'), target = await tempDirectory('scanmux-intel-junction-target-');
  await broaden(target); await mkdir(location); await symlink(target, link, 'junction');
  const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  // GetAccessControl on the junction path reads the junction's own ACL, not its target's.
  const sddl = (directory: string) => spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', '[IO.DirectoryInfo]::new($env:TARGET).GetAccessControl().GetSecurityDescriptorSddlForm(\'All\')'],
    { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot, TARGET: directory } }).stdout.trim();
  const acls = () => [sddl(target), sddl(link)];
  const before = acls();
  for (const acl of before) assert.match(acl, /^O:/);
  const error = await refreshIntel(location, { fetcher: fetcher(), now: clock() }).then(() => null, (failure: unknown) => failure);
  assert.deepEqual(acls(), before);
  assert.match(String(error), /intel_store_not_private/);
});

async function seeded() {
  const location = await store();
  await refreshIntel(location, { fetcher: fetcher(), now: clock() });
  return location;
}
const status = async (location: string, now: number, maxAgeMs: number | null) => matchIntel(Buffer.from('{}'), { kind: 'import', repoId: 'f'.repeat(64), root: null, subjects: [], noCve: 0 },
  await loadIntel(location, now), { now, maxAgeMs }).feeds;
test('freshness is decided per feed with an exact boundary and no default limit', async () => {
  const location = await seeded(), completed = Date.parse((await loadIntel(location, t0 + hour)).feeds.kev.generation!.attempt.completedAt);
  assert.equal((await status(location, completed + hour, hour)).kev.state, 'fresh');
  assert.equal((await status(location, completed + hour + 1, hour)).kev.state, 'stale');
  const unjudged = await status(location, completed + hour, null);
  assert.equal(unjudged.kev.state, 'unjudged'); assert.equal(unjudged.jvndb.state, 'unavailable'); assert.equal(unjudged.jvndb.usable, false);
});
test('a store this run created but cannot own is removed and reported as not owned by the user', async t => {
  const location = await store(), refresh = () => assert.rejects(refreshIntel(location, { fetcher: fetcher(), now: clock() }), /intel_store_owner_not_user/);
  if (process.platform === 'win32') {
    const saved = process.env.SystemRoot;
    process.env.SystemRoot = path.join(path.dirname(location), 'missing-windows');
    try { await refresh(); } finally { process.env.SystemRoot = saved; }
  } else { t.mock.method(process as unknown as { getuid(): number }, 'getuid', () => -1); await refresh(); }
  assert.deepEqual(await readdir(path.dirname(location)), []);
});
test('a store with no attempts reports every feed as never attempted', async () => {
  const location = await store();
  await openStore(location, true);
  assert.deepEqual(Object.values(await status(location, t0, hour)).map(feed => [feed.state, feed.usable]), [['never_attempted', false], ['never_attempted', false], ['never_attempted', false]]);
});
test('records dated after now or with an impossible time never decide the newest state', async () => {
  const location = await seeded();
  await writeFile(path.join(location, 'attempts', '20990101T000000000Z-00000000-0000-4000-8000-000000000000.json'), '{');
  let feedsNow = await status(location, t0 + hour, null);
  assert.deepEqual(Object.values(feedsNow).map(feed => feed.state), ['unjudged', 'unjudged', 'unavailable']);
  assert.deepEqual(feedsNow.kev.notes, [{ attempt: '20990101T000000000Z-00000000-0000-4000-8000-000000000000.json', reason: 'clock_unverified' }]);
  await refreshIntel(location, { fetcher: fetcher(), now: clock(t0 + 100) });
  const newer = (await readdir(path.join(location, 'attempts'))).filter(name => name.startsWith('20261026T000000100Z'));
  assert.equal(newer.length, 1);
  const file = path.join(location, 'attempts', newer[0]);
  await writeFile(file, JSON.stringify({ ...JSON.parse(await readFile(file, 'utf8')), completedAt: '2026-13-26T00:00:00.000Z' }));
  feedsNow = await status(location, t0 + 200, hour);
  assert.equal(feedsNow.kev.state, 'fresh'); assert.equal(feedsNow.kev.generation?.startedAt, '2026-10-26T00:00:00.000Z');
  assert.ok(feedsNow.kev.notes.some(note => note.attempt === newer[0] && note.reason === 'clock_unverified'));
});
test('a record whose feed cannot be identified is listed for every feed and decides none', async () => {
  const location = await store(), name = '20990101T000000000Z-00000000-0000-4000-8000-000000000000.json';
  await openStore(location, true);
  await writeFile(path.join(location, 'attempts', name), '{');
  const feedsNow = await status(location, t0, hour);
  assert.deepEqual(Object.values(feedsNow).map(feed => [feed.state, feed.notes]), Array(3).fill(['never_attempted', [{ attempt: name, reason: 'clock_unverified' }]]));
});
test('attempts are ordered by completion time and a failure wins a tie', async () => {
  const location = await seeded();
  await refreshIntel(location, { fetcher: fetcher({ kev: () => respond(kevUrl, null, 500) }), now: clock(), uuid: () => '00000000-0000-4000-8000-000000000000' });
  const feedsNow = await status(location, t0 + hour, 10 * hour);
  assert.equal(feedsNow.kev.state, 'refresh_failed_previous'); assert.equal(feedsNow.kev.latestAttempt?.httpStatus, 500);
});
test('a failed refresh after a success is shown first and is never fresh', async () => {
  const location = await seeded();
  await refreshIntel(location, { fetcher: fetcher({ kev: () => respond(kevUrl, null, 500) }), now: clock(t0 + 100) });
  const feedsNow = await status(location, t0 + 200, 10 * hour);
  assert.equal(feedsNow.kev.state, 'refresh_failed_previous'); assert.equal(feedsNow.kev.usable, true);
  assert.equal(feedsNow.kev.latestAttempt?.httpStatus, 500); assert.equal(feedsNow.kev.generation?.startedAt, '2026-10-26T00:00:00.000Z');
  const match = matchIntel(Buffer.from('{}'), { kind: 'import', repoId: 'f'.repeat(64), root: null, subjects: [], noCve: 0 }, await loadIntel(location, t0 + 200), { now: t0 + 200, maxAgeMs: 10 * hour });
  assert.match(renderIntelText(match, 'en'), /latest refresh failed \(reason http_status, HTTP 500/);
  assert.equal(intelExitCode(match, true), 3); assert.equal(intelExitCode(match, false), 0);
});
test('corrupt, missing or drifted blobs and clock reversal fall back or become unavailable', async () => {
  const location = await seeded();
  await refreshIntel(location, { fetcher: fetcher({ kev: () => respond(kevUrl, kevBody([kevEntry('CVE-2026-0009')])) }), now: clock(t0 + 100) });
  const loaded = await loadIntel(location, t0 + 200), newest = loaded.feeds.kev.generation!.attempt.outcome.sha256;
  await writeFile(path.join(location, 'blobs', newest), kevBody([kevEntry('CVE-2026-0008')]));
  let feedsNow = await status(location, t0 + 200, hour);
  assert.equal(feedsNow.kev.state, 'corrupt'); assert.equal(feedsNow.kev.generation?.startedAt, '2026-10-26T00:00:00.000Z');
  assert.deepEqual(feedsNow.kev.notes.map(note => note.reason), ['blob_mismatch']);
  await rm(path.join(location, 'blobs', newest));
  assert.deepEqual((await status(location, t0 + 200, hour)).kev.notes.map(note => note.reason), ['blob_missing']);
  for (const name of await readdir(path.join(location, 'blobs'))) await rm(path.join(location, 'blobs', name));
  feedsNow = await status(location, t0 + 200, hour);
  assert.equal(feedsNow.kev.state, 'corrupt'); assert.equal(feedsNow.kev.usable, false);
  const reversed = await seeded();
  feedsNow = await status(reversed, t0 - 1, null);
  assert.equal(feedsNow.kev.state, 'clock_unknown'); assert.equal(feedsNow.kev.usable, false);
  const drifted = await seeded(), names = (await readdir(path.join(drifted, 'attempts'))).sort();
  const first = path.join(drifted, 'attempts', names[0]), value = JSON.parse(await readFile(first, 'utf8'));
  await writeFile(first, JSON.stringify({ ...value, extra: 1 }));
  feedsNow = await status(drifted, t0 + hour, null);
  assert.equal(feedsNow.kev.state, 'corrupt'); assert.deepEqual(feedsNow.kev.notes.map(note => note.reason), ['invalid_attempt']);
});
test('concurrent refreshes append separate attempts and share one blob per body', async () => {
  const location = await seeded();
  await Promise.all([refreshIntel(location, { fetcher: fetcher(), now: clock(t0 + 50) }), refreshIntel(location, { fetcher: fetcher(), now: clock(t0 + 50) })]);
  assert.equal((await readdir(path.join(location, 'attempts'))).length, 9);
  assert.equal((await readdir(path.join(location, 'blobs'))).length, 2);
  assert.equal((await loadIntel(location, t0 + hour)).feeds.kev.notes.length, 0);
});

function report(root: string) {
  const findings = [{ engine: 'osv', fingerprint: 'a'.repeat(64), originIds: ['GHSA-1111-2222-3333', 'CVE-2026-0001'], file: 'package-lock.json', line: 3 },
    { engine: 'osv', fingerprint: 'b'.repeat(64), originIds: ['CVE-2026-0003'], file: 'package-lock.json', line: null },
    { engine: 'osv', fingerprint: 'c'.repeat(64), originIds: ['GHSA-4444-5555-6666'], file: 'package-lock.json', line: null }];
  return { schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555', startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', gate: 'FAIL',
    executionState: 'completed', coverageState: 'complete', integrityErrors: [],
    plan: { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64), planHash: 'c'.repeat(64), snapshotHash: 'd'.repeat(64),
      required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], blockers: [], exclusions: [] },
    engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed',
      findings: engine === 'osv' ? findings : [], usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) };
}
function importRecord(repoId: string) {
  const facts = { repoId, observations: [], rejected: [], findings: [{ findingId: 'e'.repeat(64), tool: 'osv-scanner', ruleId: 'CVE-2026-0002', path: 'a/b.txt', startLine: 2, package: null, occurrences: [] },
    { findingId: 'f'.repeat(64), tool: 'gitleaks', ruleId: 'generic-api-key', path: 'c.txt', startLine: 1, package: null, occurrences: [] }] };
  return { schema: 'scanmux.import/v2', effect: { gate: 'unchanged', substitutesEngine: false, scanVerified: false }, rawRetained: false, facts, factsDigest: digest(facts), view: {} };
}
test('report and import findings match KEV and the JVN window without guessing', async () => {
  const location = await seeded(), loaded = await loadIntel(location, t0 + hour), root = await tempDirectory('scanmux-intel-root-');
  const bytes = Buffer.from(JSON.stringify(report(root))), source = readSource(bytes);
  assert.equal(source.noCve, 1);
  const match = matchIntel(bytes, source, loaded, { now: t0 + hour, maxAgeMs: null });
  assert.equal(match.sourceSha256, hash(bytes));
  assert.deepEqual(match.findings.map(finding => finding.cves.map(entry => [entry.cve, entry.kev.state, entry.jvn.state])),
    [[['CVE-2026-0001', 'listed', 'observed']], [['CVE-2026-0003', 'not_listed', 'not_observed_in_window']]]);
  const imported = readSource(Buffer.from(JSON.stringify(importRecord('9'.repeat(64)))));
  assert.equal(imported.noCve, 1); assert.equal(imported.root, null);
  const importMatch = matchIntel(Buffer.from('x'), imported, loaded, { now: t0 + hour, maxAgeMs: null });
  assert.deepEqual(importMatch.findings[0].cves.map(entry => [entry.kev.state, entry.jvn.state]), [['not_listed', 'observed']]);
  const empty = matchIntel(Buffer.from('x'), imported, await loadIntel(await seeded().then(async s => { await rm(path.join(s, 'blobs'), { recursive: true }); await mkdir(path.join(s, 'blobs'), { mode: 0o700 }); return s; }), t0 + hour), { now: t0 + hour, maxAgeMs: null });
  assert.deepEqual(empty.findings[0].cves.map(entry => [entry.kev, entry.jvn]), [[{ state: 'not_evaluated', reason: 'corrupt' }, { state: 'not_evaluated', reason: 'corrupt' }]]);
  const sarif = JSON.parse(renderIntelSarif(match));
  assert.ok(sarif.runs[0].results.every((result: { level: string }) => result.level === 'note'));
  assert.deepEqual(sarif.runs[0].invocations[0].toolExecutionNotifications.map((note: { properties: Record<string, { feed: string }> }) => note.properties['scanmux/intel/v1'].feed), ['jvndb']);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
  const none = JSON.parse(renderIntelSarif(matchIntel(Buffer.from('x'), { ...imported, subjects: [] }, await loadIntel(await store().then(async s => { await refreshIntel(s, { fetcher: fetcher({ kev: () => respond(kevUrl, null, 500), jvn: () => respond(jvnUrl, null, 500) }), now: clock() }); return s; }), t0 + hour), { now: t0 + hour, maxAgeMs: null })));
  assert.equal(none.runs[0].results.length, 0); assert.equal(none.runs[0].invocations[0].toolExecutionNotifications.length, 3);
  assert.equal(none.runs[0].invocations[0].executionSuccessful, false);
});
test('the bundle is bound to the exact input bytes, leaves the input unchanged and refuses a store inside the target', async () => {
  await commandTemp();
  const location = await seeded(), root = await tempDirectory('scanmux-intel-root-'), outside = await tempDirectory('scanmux-intel-input-');
  const input = path.join(outside, 'report.json'), bytes = Buffer.from(JSON.stringify(report(root)));
  await writeFile(input, bytes);
  const result = await matchIntelFiles(input, location, undefined, defaults, { maxAgeMs: null, requireFresh: true, language: 'en', now: t0 + hour, checkText: async text => text });
  assert.equal(result.exitCode, 3); assert.equal(result.match.sourceSha256, hash(bytes));
  const fresh = await matchIntelFiles(input, location, undefined, defaults, { maxAgeMs: hour, requireFresh: true, language: 'en', now: t0 + hour, checkText: async text => text });
  assert.deepEqual([fresh.exitCode, fresh.match.feeds.kev.state, fresh.match.feeds.jvn.state, fresh.match.feeds.jvndb.state], [0, 'fresh', 'fresh', 'unavailable']);
  assert.equal(JSON.parse(await readFile(fresh.sarifDestination, 'utf8')).runs[0].invocations[0].executionSuccessful, true);
  assert.deepEqual(await readFile(input), bytes);
  assert.deepEqual((await readdir(path.dirname(result.destination))).filter(name => name.startsWith('intel-')).sort(), ['intel-match.html', 'intel-match.json', 'intel-match.sarif', 'intel-match.txt']);
  assert.deepEqual(JSON.parse(await readFile(result.destination, 'utf8')), result.match);
  const workspace = await tempDirectory('scanmux-intel-out-');
  await assert.rejects(writeIntelBundle(result.match, input, defaults, workspace, 'ja', async text => { await writeFile(input, 'changed'); return text; }), /intel_source_binding_mismatch/);
  assert.deepEqual(await readdir(workspace), []);
  await writeFile(input, bytes); await writeFile(path.join(workspace, 'intel-match.txt'), 'earlier');
  await assert.rejects(writeIntelBundle(result.match, input, defaults, workspace, 'en', async text => text), /EEXIST/);
  assert.deepEqual(await readdir(workspace), ['intel-match.txt']);
  assert.equal(await readFile(path.join(workspace, 'intel-match.txt'), 'utf8'), 'earlier');
  const inner = path.join(root, 'intel');
  await refreshIntel(inner, { fetcher: fetcher(), now: clock() });
  await writeFile(input, bytes);
  await assert.rejects(matchIntelFiles(input, inner, undefined, defaults, { maxAgeMs: null, requireFresh: false, language: 'ja', checkText: async text => text }), /intel_store_inside_target/);
  const record = path.join(outside, 'import.json');
  await writeFile(record, JSON.stringify(importRecord(hash(root))));
  await assert.rejects(matchIntelFiles(record, inner, undefined, defaults, { maxAgeMs: null, requireFresh: false, language: 'ja', checkText: async text => text }), /intel_store_inside_target/);
  const temporary = path.join(root, '.tmp'), saved = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  await mkdir(temporary);
  const created: string[] = [], watcher = watch(temporary, (_event, name) => { if (name?.startsWith('scanmux-')) created.push(name); });
  await writeFile(record, JSON.stringify(importRecord(hash(await canonical(root)))));
  Object.assign(process.env, { TEMP: temporary, TMP: temporary, TMPDIR: temporary });
  try { await assert.rejects(matchIntelFiles(record, location, undefined, defaults, { maxAgeMs: null, requireFresh: false, language: 'en', now: t0 + hour, checkText: async text => text }), /intel_output_inside_target/); }
  finally { for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  await new Promise(resolve => setImmediate(resolve)); watcher.close();
  assert.deepEqual(await readdir(temporary), []); assert.deepEqual(created, [], 'no output directory was created inside the target');
  await writeFile(record, JSON.stringify(importRecord(hash(root))));
  const imported = await matchIntelFiles(record, location, undefined, defaults, { maxAgeMs: null, requireFresh: false, language: 'ja', now: t0 + hour, checkText: async text => text });
  assert.equal(imported.exitCode, 0); assert.equal(imported.match.sourceKind, 'import');
});
test('a bundle file that fails part-way is removed with the files written before it', async () => {
  const location = await seeded(), root = await tempDirectory('scanmux-intel-root-'), outside = await tempDirectory('scanmux-intel-input-');
  const input = path.join(outside, 'report.json'), bytes = Buffer.from(JSON.stringify(report(root))), workspace = await tempDirectory('scanmux-intel-out-');
  await writeFile(input, bytes);
  const match = matchIntel(bytes, readSource(bytes), await loadIntel(location, t0 + hour), { now: t0 + hour, maxAgeMs: null });
  const original = { open: fsPromises.open, writeFile: fsPromises.writeFile }, failing = (file: unknown) => path.basename(String(file)) === 'intel-match.html';
  const partial = async (handle: fsPromises.FileHandle, data: unknown) => { await handle.write(String(data).slice(0, 10)); throw Object.assign(new Error('no space left on device'), { code: 'ENOSPC' }); };
  fsPromises.open = (async (file: string, flags?: string, mode?: number) => {
    const handle = await original.open(file, flags, mode);
    if (failing(file)) handle.writeFile = (data: unknown) => partial(handle, data);
    return handle;
  }) as typeof fsPromises.open;
  fsPromises.writeFile = (async (file: string, data: string, options?: object) => {
    if (!failing(file)) return original.writeFile(file, data, options);
    const handle = await original.open(file, 'wx', 0o600);
    try { await partial(handle, data); } finally { await handle.close(); }
  }) as typeof fsPromises.writeFile;
  syncBuiltinESMExports();
  try { await assert.rejects(writeIntelBundle(match, input, defaults, workspace, 'en', async text => text), { code: 'ENOSPC' }); }
  finally { Object.assign(fsPromises, original); syncBuiltinESMExports(); }
  assert.deepEqual(await readdir(workspace), []);
});
test('Japanese and English texts are complete and the English outputs carry no Japanese', async () => {
  for (const [key, value] of Object.entries(intelDictionary)) {
    assert.ok(value.length > 0);
    assert.deepEqual([...value.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort(), [...key.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort(), key);
    assert.doesNotMatch(value, /[\u3040-\u30ff\u4e00-\u9fff\uff08-\uff1a]/, key);
  }
  const location = await seeded(), root = await tempDirectory('scanmux-intel-root-'), bytes = Buffer.from(JSON.stringify(report(root)));
  const match = matchIntel(bytes, readSource(bytes), await loadIntel(location, t0 + hour), { now: t0 + hour, maxAgeMs: hour });
  for (const text of [renderIntelText(match, 'en'), renderIntelHtml(match, 'en'), renderIntelSarif(match)]) assert.doesNotMatch(text, /[\u3040-\u30ff\u4e00-\u9fff]/);
  assert.match(renderIntelText(match, 'ja'), /最近の更新RSSの範囲（2件/);
  assert.match(renderIntelHtml(match, 'en'), /not the full database/);
  assert.doesNotMatch(renderIntelHtml(match, 'en'), /<script|https?:\/\/[^"<]*\.(?:css|js)/);
});
test('the JVN window line appears only when a JVN copy exists', async () => {
  const location = await store();
  await refreshIntel(location, { fetcher: fetcher({ jvn: () => respond(jvnUrl, null, 500) }), now: clock() });
  const match = matchIntel(Buffer.from('{}'), { kind: 'import', repoId: 'f'.repeat(64), root: null, subjects: [], noCve: 0 }, await loadIntel(location, t0 + hour), { now: t0 + hour, maxAgeMs: null });
  for (const text of [renderIntelText(match, 'en'), renderIntelHtml(match, 'en')]) assert.doesNotMatch(text, /RSS window/);
});
test('intel commands reject misplaced options before any network or file access', async () => {
  for (const argv of [['intel-refresh'], ['intel-refresh', '--store', 'C:\\x', '--config', 'C:\\c.json'], ['intel-refresh', '--store', 'C:\\x', '--require-fresh'],
    ['intel-match', 'C:\\r.json', '--store', 'C:\\x'], ['scan', 'C:\\r', '--store', 'C:\\x'], ['intel-match', 'C:\\r.json', '--config', 'C:\\c.json']]) assert.equal(await main(argv), 4);
});
async function invoke(argv: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (output.push(chunk), true) : out.call(process.stdout, chunk, ...rest)) as typeof out;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (errors.push(chunk), true) : err.call(process.stderr, chunk, ...rest)) as typeof err;
  try { return { exitCode: await main(argv), output: output.join(''), error: errors.join('') }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
test('--require-fresh without --max-age-hours is an invalid command', async () => {
  const result = await invoke(['intel-match', 'C:\\r.json', '--store', 'C:\\x', '--config', 'C:\\c.json', '--require-fresh']);
  assert.equal(result.exitCode, 4); assert.equal(JSON.parse(result.error).error, 'invalid_command');
});
test('--max-age-hours accepts 1 to 9999999 hours without a leading zero', () => {
  assert.equal(parseMaxAgeHours(undefined), null); assert.equal(parseMaxAgeHours('24'), 24 * hour); assert.equal(parseMaxAgeHours('9999999'), 9999999 * hour);
  for (const value of ['0', '01', '10000000', '1.5', '-1', '', ' 1']) assert.throws(() => parseMaxAgeHours(value), /invalid_intel_max_age/, value);
});
test('the commands run end to end with the real secret check: refresh, then match exits 0, 3 or 4', { skip: realConfigSkip }, async t => {
  await commandTemp();
  const now = t.mock.method(Date, 'now', () => t0);
  t.mock.method(globalThis, 'fetch', fetcher());
  const location = await store(), root = await tempDirectory('scanmux-intel-root-'), outside = await tempDirectory('scanmux-intel-input-');
  const input = path.join(outside, 'report.json'), configFile = path.join(outside, 'config.json');
  await writeFile(input, JSON.stringify(report(root)));
  await writeFile(configFile, JSON.stringify(withTestProcessOwner(JSON.parse(await readFile(realConfigPath!, 'utf8')))));
  assert.equal((await invoke(['intel-refresh', '--store', location])).exitCode, 0);
  now.mock.mockImplementation(() => t0 + hour);
  const match = (...extra: string[]) => invoke(['intel-match', input, '--store', location, '--config', configFile, '--json', ...extra]);
  const fresh = await match('--max-age-hours', '24', '--require-fresh');
  assert.equal(fresh.exitCode, 0, fresh.error);
  assert.deepEqual([JSON.parse(fresh.output).feeds.kev.state, JSON.parse(fresh.output).feeds.jvn.state], ['fresh', 'fresh']);
  now.mock.mockImplementation(() => t0 + 2 * hour);
  assert.equal((await match('--max-age-hours', '1', '--require-fresh')).exitCode, 3);
  const refused = await match('--require-fresh');
  assert.equal(refused.exitCode, 4); assert.equal(JSON.parse(refused.error).error, 'invalid_command');
});
