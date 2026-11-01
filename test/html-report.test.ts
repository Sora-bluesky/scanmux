import { catalogIdentity } from '../src/advisory-catalog.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Report, Gate, LegacyFinding } from '../src/model.ts';
import { renderHtmlReport, reportCsp, groupFindings } from '../src/html-report.ts';
import { saveReportBundle } from '../src/output.ts';
import { defaults } from '../src/config.ts';
import { SafeError } from '../src/safety.ts';

function fixture(gate: Gate = 'INCOMPLETE'): Report {
  return { schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', gate, exitCode: 3,
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', executionState: 'completed', coverageState: 'incomplete', reasons: ['required_codex-security_incomplete'], integrityErrors: [],
    runner: { platform: 'win32', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' },
    plan: { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: 'C:\\private-host\\secret-target', repoId: 'fixture', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 'c'.repeat(64), dirty: false,
      files: [], exclusions: [], blockers: [], languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: 'd'.repeat(64), planHash: 'e'.repeat(64), network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } }, engines: [] };
}
function addFinding(report: Report): LegacyFinding {
  const finding: LegacyFinding = { fingerprint: 'f'.repeat(64), engine: 'osv', originIds: ['CVE-2026-12345'], category: 'dependency', severity: 'high', confidence: 'high', evidenceState: 'candidate', disposition: 'open', file: 'package-lock.json', line: null, title: 'arbitrary title', package: { name: '@example/package', version: '1.0.0', ecosystem: 'npm', direct: 'unknown' }, fixedVersions: ['1.0.1'], reachability: 'unknown', knownExploited: 'unknown' };
  report.engines.push({ engine: 'osv', execution: 'completed', coverage: 'analyzed', targets: ['package-lock.json'], exclusions: [], findings: [finding], evidence: [], errors: [], version: '2.7.0', executableHash: 'f'.repeat(64), rulesVersion: null, dbAsOf: null, database: [], startedAt: report.startedAt, endedAt: report.endedAt, exitCode: 1, auth: 'none', modelRequested: null, modelActual: null, accessProgramRequested: null, accessProgramEffective: null, usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } });
  return finding;
}
test('all five decisions are preserved; absent required engines and zero findings never imply safety', () => {
  for (const gate of ['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'] as const) {
    const report = fixture(gate), before = structuredClone(report), html = renderHtmlReport(report);
    assert.ok(html.includes(`（${gate}）`));
    assert.ok(html.includes('AIコード検査（Codex Security）'));
    assert.equal((html.match(/<td>実行記録なし<\/td>/g) ?? []).length, 4);
    assert.match(html, /指摘の記録は0件/);
    assert.ok(!html.includes(report.plan.root));
    assert.deepEqual(report, before);
  }
});

test('display groups preserve raw identity, occurrences, stable order and separate print records', () => {
  const report = fixture(), original = addFinding(report);
  original.fingerprint = 'a1'.repeat(32);
  const copy = (change: Partial<LegacyFinding>) => ({ ...structuredClone(original), ...change });
  const values = [original, copy({ severity: 'unknown' }), copy({ package: { ...original.package!, version: '2.0.0' } }),
    copy({ engine: 'runtime-advisories' }), copy({ package: { ...original.package!, ecosystem: 'other' } }),
    copy({ package: { ...original.package!, name: '/hidden-one' } }), copy({ package: { ...original.package!, name: '/hidden-two' } }),
    copy({ package: undefined, file: '/host/one', severity: 'low' }), copy({ package: undefined, file: '/host/two', severity: 'low' }),
    copy({ file: 'other.json', line: 2 })];
  report.engines[0].findings = values;
  const before = structuredClone(report), groups = groupFindings(values), html = renderHtmlReport(report);
  assert.equal(groups.length, 8); assert.equal(groups[0].items.length, 3); assert.equal(groups[0].unknownCount, 1); assert.equal(groups[0].knownSeverity, 'high'); assert.equal(groups[0].places, 2);
  assert.deepEqual(groups.flatMap(group => group.items.map(item => item.index)).sort((a, b) => a - b), values.map((_, i) => i));
  assert.deepEqual(groups.filter(group => group.knownSeverity === 'high').map(group => group.items[0].index), [0, 2, 3, 4, 5, 6]);
  for (const mode of ['screen', 'print']) assert.deepEqual([...html.matchAll(new RegExp(`id="${mode}-finding-([0-9]+)"`, 'g'))].map(match => Number(match[1])).sort((a, b) => a - b), values.map((_, i) => i + 1));
  const ids = [...html.matchAll(/ id="([^"]+)"/g)].map(match => match[1]); assert.equal(new Set(ids).size, ids.length);
  assert.ok(!html.includes('/hidden-one')); assert.ok(!html.includes('/hidden-two')); assert.ok(!html.includes('/host/one')); assert.ok(!html.includes('/host/two')); assert.ok(!html.includes(original.fingerprint));
  assert.ok(html.includes('重要度不明 1件')); assert.equal((html.match(/修正版は通知ごとの候補です/g) ?? []).length, 1);
  assert.deepEqual(report, before);
});
test('closed HTML projection rejects host paths and arbitrary fields, escapes location markup, and has no active content', () => {
  const report = fixture('FAIL'), finding = addFinding(report);
  const hostile = '</style><script>alert(1)</script><img src="https://evil.example">';
  finding.title = hostile;
  finding.file = 'src/<img src="evil">.ts';
  finding.originIds.push(hostile);
  report.plan.exclusions = [{ path: '/home/private-host/data', reason: hostile }, { path: 'C:\\private-host\\data', reason: 'binary' }, { path: '../private-host/data', reason: 'unknown' }];
  report.engines[0].errors = [hostile, 'C:\\private-host\\error'];
  report.engines[0].targets.push('/home/private-host/target');
  const html = renderHtmlReport(report);
  assert.ok(!html.includes('private-host'));
  assert.ok(!html.includes('<script'));
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('evil.example'));
  assert.ok(html.includes('&lt;img src=&quot;evil&quot;&gt;'));
  assert.ok(html.includes('CVE-2026-12345'));
  assert.ok(html.includes('@example/package'));
  assert.ok(html.includes('1.0.1'));
  assert.ok(html.includes('重要度：高'));
  const style = html.match(/<style>([\s\S]*?)<\/style>/)![1];
  assert.ok(reportCsp.includes(`'sha256-${createHash('sha256').update(style).digest('base64')}'`));
  assert.equal((html.match(/href="/g) ?? []).length, (html.match(/href="#/g) ?? []).length);
  assert.ok(!/<[^>]+\s(?:src|onload|onclick)=/i.test(html));
});
test('bundle checks exact HTML, JSON and SARIF before saving, preserves existing output, and enforces UTF-8 size', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-html-test-'));
  const report = fixture(), checked: string[] = [], config = { ...defaults, maxOutputBytes: 100000 };
  const check = async (value: unknown) => { assert.deepEqual(await readdir(directory), []); checked.push('json'); return JSON.stringify(value); };
  const checkText = async (value: string) => { assert.deepEqual(await readdir(directory), []); checked.push(value); return value; };
  try {
    const bundle = await saveReportBundle(report, config, directory, check, checkText);
    assert.equal(await readFile(bundle.htmlDestination, 'utf8'), renderHtmlReport(report));
    assert.equal(await readFile(bundle.destination, 'utf8'), JSON.stringify(report));
    assert.equal(checked[1], bundle.html);
    assert.equal(checked[2], bundle.sarif[0].text);
    assert.equal(await readFile(bundle.sarif[0].destination, 'utf8'), bundle.sarif[0].text);
    await assert.rejects(saveReportBundle(report, config, directory, async value => JSON.stringify(value), async value => value), { code: 'EEXIST' });
    assert.equal(await readFile(bundle.htmlDestination, 'utf8'), bundle.html);
  } finally { await rm(directory, { recursive: true, force: true }); }
  const second = await mkdtemp(path.join(tmpdir(), 'scanmux-html-test-'));
  try {
    const html = renderHtmlReport(report);
    assert.ok(Buffer.byteLength(html) > html.length);
    await assert.rejects(saveReportBundle(report, { ...config, maxOutputBytes: html.length }, second, async value => JSON.stringify(value), async value => value), (error: unknown) => error instanceof SafeError && error.code === 'output_size_limit');
    assert.deepEqual(await readdir(second), []);
    await assert.rejects(saveReportBundle(report, config, second, async value => JSON.stringify(value), async () => { throw new SafeError('output_secret_check_failed'); }));
    assert.deepEqual(await readdir(second), []);
    await writeFile(path.join(second, 'report.html'), 'existing');
    await assert.rejects(saveReportBundle(report, config, second, async value => JSON.stringify(value), async value => value), { code: 'EEXIST' });
    assert.equal(await readFile(path.join(second, 'report.html'), 'utf8'), 'existing');
  } finally { await rm(second, { recursive: true, force: true }); }
});

test('AI destinations render in an amber disclosure, with the provider as unverifiable and unknown codes hidden', () => {
  const report = fixture('PASS');
  report.plan.destinations = { schema: 'scanmux.destinations/v1', rule: 'send_only_to_validated_software', ruleMet: false, destinations: [
    { side: 'local', component: 'linux-image', sha256: 'a'.repeat(64), level: 'digest_pinned_only' },
    { side: 'local', component: 'docker', sha256: null, level: 'unidentified' },
    { side: 'provider', component: 'openai-responses', attestation: 'unattestable', reason: 'provider_offers_no_software_attestation' },
  ] };
  const html = renderHtmlReport(report), english = renderHtmlReport(report, 'en');
  const box = html.slice(html.indexOf('<div class="disclosure">'), html.indexOf('</table></div></div>', html.indexOf('<div class="disclosure">')));
  assert.ok(box.length > 0);
  assert.match(box, /「検証済みのソフトウェアにだけ送る」条件は満たしていません/);
  assert.match(box, /<td>プロバイダー<\/td><td>OpenAI Responses API<\/td><td>検証できません（プロバイダーがソフトウェアの証明を提供していません）<\/td>/);
  assert.match(box, /<td>Linux作業イメージ<\/td><td>ハッシュの固定のみ<\/td>/);
  assert.ok(!box.includes('PASS'));
  assert.match(english, /The rule "send only to verified software" is not met\./);
  assert.match(english, /Cannot be verified \(the provider offers no software attestation\)/);
  assert.match(html, /\.disclosure\{border-left:6px solid #9c6d15;background:#fff8e8;/);
  Reflect.set(report.plan.destinations.destinations[0], 'level', '<b>verified</b>');
  assert.ok(!renderHtmlReport(report).includes('<b>verified</b>'));
  assert.ok(!renderHtmlReport(fixture()).includes('class="disclosure"'), 'an offline report has no destination section');
});
