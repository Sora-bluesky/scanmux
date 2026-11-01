import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Report, LegacyFinding } from '../src/model.ts';
import { renderSarifReports } from '../src/sarif-report.ts';
import { saveReportBundle } from '../src/output.ts';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';

export function fixture(): Report {
  const report: Report = { schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', gate: 'PASS', exitCode: 0,
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', executionState: 'completed', coverageState: 'complete', reasons: [], integrityErrors: [],
    runner: { platform: 'win32', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' },
    plan: { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: 'C:\\private-host\\secret-target', repoId: 'fixture', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 'c'.repeat(64), dirty: false,
      files: [], exclusions: [], blockers: [], languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: 'd'.repeat(64), planHash: 'e'.repeat(64), network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } }, engines: [] };
  report.engines = report.plan.required.map(engine => ({ engine, execution: 'completed', coverage: 'analyzed', targets: [], exclusions: [], findings: [], evidence: [], errors: [], version: null, executableHash: null, rulesVersion: null, dbAsOf: null, database: [], startedAt: report.startedAt, endedAt: report.endedAt, exitCode: 0, auth: 'none', modelRequested: null, modelActual: null, accessProgramRequested: null, accessProgramEffective: null, usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } }));
  return report;
}
function finding(change: Partial<LegacyFinding> = {}): LegacyFinding {
  return { fingerprint: 'f'.repeat(64), engine: 'osv', originIds: ['CVE-2026-12345'], category: 'dependency', severity: 'high', confidence: 'high', evidenceState: 'candidate', disposition: 'open', file: 'package-lock.json', line: null, title: 'arbitrary private text', package: { name: '@example/package', version: '1.0.0', ecosystem: 'npm', direct: 'unknown' }, fixedVersions: ['1.0.1'], reachability: 'unknown', knownExploited: 'unknown', ...change };
}
function render(report: Report) { return JSON.parse(renderSarifReports(report, 8 * 1024 * 1024)[0].text).runs[0]; }

test('all gates, categories, severities and repeated advisory occurrences preserve identity and order', () => {
  for (const [exitCode, gate] of (['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'] as const).entries()) {
    const report = fixture(); report.gate = gate; report.exitCode = exitCode;
    report.engines.forEach((run, index) => { run.findings = [finding({ engine: run.engine as LegacyFinding['engine'], category: (['secret', 'dependency', 'code', 'runtime'] as const)[index] })]; });
    for (const [index, severity] of (['critical', 'high', 'medium', 'low', 'informational', 'unknown'] as const).entries()) report.engines[1].findings.push(finding({ severity, fingerprint: index.toString(16).repeat(64), file: `位置/空 白%#${index}.json`, line: index + 1, package: { name: `example.com/package${index}`, version: 'v1.0.0+meta', ecosystem: 'Go', direct: 'unknown' } }));
    const before = structuredClone(report), run = render(report), original = report.engines.flatMap(run => run.findings);
    assert.equal(run.properties.gate, gate); assert.equal(run.properties.exitCode, exitCode);
    assert.equal(run.invocations[0].executionSuccessful, true);
    assert.deepEqual(run.results.map((value: any) => value.properties.fingerprint), original.map(value => value.fingerprint));
    assert.deepEqual(run.results.map((value: any) => value.ruleId), original.map(value => `scanmux/${value.engine}/${value.category}`));
    assert.deepEqual(run.results.map((value: any) => value.level), original.map(value => ['critical', 'high'].includes(value.severity) ? 'error' : ['medium', 'low'].includes(value.severity) ? 'warning' : 'note'));
    assert.equal(run.results[1].locations[0].physicalLocation.region, undefined);
    assert.equal(run.results[2].locations[0].physicalLocation.artifactLocation.uri, '%E4%BD%8D%E7%BD%AE/%E7%A9%BA%20%E7%99%BD%25%230.json');
    assert.equal(run.results[2].locations[0].physicalLocation.region.startLine, 1);
    assert.deepEqual(report, before);
  }
});

test('incomplete, missing, duplicate, partial and failed analysis never become success with zero findings', () => {
  const mutations: ((report: Report) => void)[] = [r => { r.coverageState = 'incomplete'; }, r => { r.executionState = 'not_started'; }, r => { r.engines.pop(); }, r => { r.engines.push(structuredClone(r.engines[0])); }, r => { r.engines[0].execution = 'failed'; }, r => { r.engines[0].coverage = 'partial'; }, r => { r.integrityErrors = ['arbitrary-private-error']; }, r => { r.plan.required = []; }, r => { r.engines[2].execution = 'not_started'; r.engines[2].coverage = 'skipped'; }];
  for (const mutate of mutations) {
    const report = fixture(); mutate(report);
    assert.throws(() => render(report), /invalid_sarif_report/);
    report.gate = 'INCOMPLETE'; report.exitCode = 3;
    const run = render(report);
    assert.equal(run.invocations[0].executionSuccessful, false); assert.equal(run.results.length, 0);
    assert.equal(run.invocations[0].toolExecutionNotifications.length, 1);
    assert.ok(!JSON.stringify(run).includes('arbitrary-private-error'));
    assert.deepEqual(run.properties.requiredEngines.map((item: any) => item.records.length), report.plan.required.map(engine => report.engines.filter(run => run.engine === engine).length));
  }
});

test('closed metadata family omits URL and absolute paths in every field while preserving supported values', () => {
  const unsafe = ['https://private-host.example/value', '/home/private-host/value', 'C:\\private-host\\value'];
  for (const value of unsafe) {
    const report = fixture(); report.plan.source = { kind: 'public-github', url: value, commit: value }; report.reasons = [value]; report.engines[1].errors = [value];
    report.engines[1].findings = [finding({ title: value, originIds: ['CVE-2026-12345', value], fixedVersions: ['1.0.1', value], file: value, package: { name: value, version: value, ecosystem: value, direct: 'unknown' } })];
    const run = render(report), output = JSON.stringify(run), result = run.results[0];
    assert.ok(!output.includes('private-host')); assert.ok(!output.includes(report.plan.root));
    assert.equal(result.locations, undefined); assert.equal(result.properties.locationUnavailable, true);
    assert.deepEqual(result.properties.metadataOmitted, { originIds: true, fixedVersions: true, packageName: true, packageVersion: true, ecosystem: true });
    assert.deepEqual(result.properties.originIds, ['CVE-2026-12345']); assert.deepEqual(result.properties.fixedVersions, ['1.0.1']);
    assert.equal(result.properties.fingerprint, 'f'.repeat(64));
    assert.equal(run.originalUriBaseIds.SRCROOT.uri, undefined);
  }
  for (const name of ['lodash', '@scope/package', 'example.com/module/path', 'lib+name']) {
    const report = fixture(); report.engines[1].findings = [finding({ package: { name, version: 'v1.2.3+meta_~x-1', ecosystem: 'crates.io', direct: 'unknown' }, originIds: ['GHSA-abcd-1234-xxxx', 'PYSEC_2026.1'] })];
    const properties = render(report).results[0].properties;
    assert.equal(properties.packageName, name); assert.equal(properties.packageVersion, 'v1.2.3+meta_~x-1'); assert.equal(properties.ecosystem, 'crates.io');
    assert.ok(Object.values(properties.metadataOmitted).every(value => value === false));
  }
});

test('invalid location segments, lines and unknown enums cannot escape projection', () => {
  for (const file of ['', '../value', 'a/../value', './value', '//server/value', 'a//value', 'con.txt', 'space /x', 'a\u0000b', '\\server\\share', 'C:/value']) {
    const report = fixture(); report.engines[1].findings = [finding({ file })];
    assert.equal(render(report).results[0].locations, undefined);
  }
  for (const line of [null, 0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const report = fixture(); report.engines[1].findings = [finding({ line })];
    assert.equal(render(report).results[0].locations[0].physicalLocation.region, undefined);
  }
  for (const key of ['engine', 'category', 'severity', 'confidence', 'evidenceState', 'disposition', 'reachability', 'knownExploited']) {
    const report = fixture(); report.engines[1].findings = [finding({ [key]: 'https://private-host' })];
    assert.throws(() => render(report), /invalid_sarif_report/);
  }
  for (const key of ['execution', 'coverage']) { const report = fixture(); (report.engines[0] as any)[key] = 'unknown'; assert.throws(() => render(report), /invalid_sarif_report/); }
  for (const name of ['@scope', '../value', 'a/./b', 'a/../b', '/root', 'a//b', 'a:b', 'a\\b', 'x'.repeat(201)]) {
    const report = fixture(); report.engines[1].findings = [finding({ package: { name, version: '1', ecosystem: 'npm', direct: 'unknown' } })];
    assert.equal(render(report).results[0].properties.packageName, undefined);
  }
});

test('metadata grammar lengths and trailing line terminators are enforced for the whole identifier family', () => {
  for (const suffix of ['\n', '\r', '\u2028', '\u2029', '\u0000', '/value', ':value']) {
    const report = fixture(); report.engines[1].findings = [finding({ originIds: ['CVE-2026-12345' + suffix], fixedVersions: ['1.0.0' + suffix], package: { name: 'package' + suffix, version: '1.0.0' + suffix, ecosystem: 'npm' + suffix, direct: 'unknown' } })];
    const projected = render(report).results[0];
    // A relative package segment list is supported; the other identifier grammars never accept slashes.
    assert.equal(projected.properties.metadataOmitted.packageName, suffix !== '/value');
    for (const key of ['originIds', 'fixedVersions', 'packageVersion', 'ecosystem']) assert.equal(projected.properties.metadataOmitted[key], true);
    report.runId += suffix; assert.throws(() => render(report), /invalid_sarif_report/);
  }
  for (const extra of [0, 1]) {
    const report = fixture(); report.engines[1].findings = [finding({ originIds: ['X'.repeat(128 + extra)], fixedVersions: ['1'.repeat(200 + extra)], package: { name: 'x'.repeat(200 + extra), version: '1'.repeat(200 + extra), ecosystem: 'x'.repeat(40 + extra), direct: 'unknown' } })];
    assert.ok(Object.values(render(report).results[0].properties.metadataOmitted).every(value => value === Boolean(extra)));
  }
});

test('split limits retain every finding in order with exact numbering and UTF-8 limits', () => {
  const report = fixture(); report.engines[1].findings = Array.from({ length: 5001 }, (_, index) => finding({ fingerprint: index.toString(16).padStart(64, '0') }));
  const parts = renderSarifReports(report, 20 * 1024 * 1024);
  assert.deepEqual(parts.map(part => part.name), ['report-0001.sarif', 'report-0002.sarif']);
  assert.deepEqual(parts.map(part => part.findings), [5000, 1]);
  assert.deepEqual(parts.flatMap(part => JSON.parse(part.text).runs[0].results.map((item: any) => item.properties.fingerprint)), report.engines[1].findings.map(item => item.fingerprint));
  const sample = fixture(); sample.engines[1].findings = Array.from({ length: 10 }, () => finding({ file: '日本語/ファイル.json' }));
  const single = renderSarifReports(sample, 100000)[0];
  const split = renderSarifReports(sample, Math.floor(Buffer.byteLength(single.text) / 2));
  assert.ok(split.length > 1); assert.equal(split.reduce((n, p) => n + p.findings, 0), 10);
  split.forEach((part, i) => { assert.ok(Buffer.byteLength(part.text) <= Math.floor(Buffer.byteLength(single.text) / 2)); const run = JSON.parse(part.text).runs[0]; assert.equal(run.properties.part, i + 1); assert.equal(run.properties.parts, split.length); assert.equal(run.properties.totalFindings, 10); });
  assert.throws(() => renderSarifReports(sample, 1), /sarif_output_size_limit/);
  assert.throws(() => renderSarifReports(fixture(), 1), /sarif_output_size_limit/);
  const oversized = fixture(); oversized.engines[1].findings = [finding({ originIds: Array.from({ length: 1000 }, () => 'X'.repeat(128)) })];
  assert.doesNotThrow(() => renderSarifReports(fixture(), 15000));
  assert.throws(() => renderSarifReports(oversized, 15000), /sarif_output_size_limit/);
});

test('gzip limit also splits without loss when uncompressed limit is larger', () => {
  const report = fixture();
  report.engines[1].findings = Array.from({ length: 30 }, (_, index) => finding({ fingerprint: index.toString(16).padStart(64, '0'), originIds: Array.from({ length: 4000 }, () => 'X' + randomBytes(63).toString('hex')) }));
  const parts = renderSarifReports(report, 100 * 1024 * 1024);
  assert.ok(parts.length > 1); assert.equal(parts.reduce((count, part) => count + part.findings, 0), 30);
  for (const part of parts) assert.ok(gzipSync(part.text).length <= 10 * 1024 * 1024);
});

test('all SARIF content and destination checks precede any bundle write; existing SARIF is preserved', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-sarif-test-'));
  const config = { ...defaults, maxOutputBytes: 100000 }, report = fixture(), checks: string[] = [];
  const json = async (value: unknown) => { assert.deepEqual(await readdir(directory), []); checks.push(JSON.stringify(value)); return JSON.stringify(value); };
  try {
    await assert.rejects(saveReportBundle(report, config, directory, json, async text => { assert.deepEqual(await readdir(directory), []); if (text.includes('"version": "2.1.0"')) throw new Error('synthetic secret check failure'); return text; }));
    assert.deepEqual(await readdir(directory), []);
    await assert.rejects(saveReportBundle(report, config, directory, async value => {
      if (value && typeof value === 'object' && 'sarifDestinations' in value) throw new Error('synthetic destination check failure');
      return JSON.stringify(value);
    }, async text => text));
    assert.deepEqual(await readdir(directory), []);
    const bundle = await saveReportBundle(report, config, directory, json, async text => { assert.deepEqual(await readdir(directory), []); checks.push(text); return text; });
    assert.equal(bundle.sarif.length, 1); assert.equal(await readFile(bundle.sarif[0].destination, 'utf8'), bundle.sarif[0].text);
    assert.equal(JSON.parse(checks.at(-1)!).sarifDestinations[0], bundle.sarif[0].destination);
    await assert.rejects(saveReportBundle(report, config, directory, async value => JSON.stringify(value), async value => value), { code: 'EEXIST' });
    assert.equal(await readFile(bundle.sarif[0].destination, 'utf8'), bundle.sarif[0].text);
  } finally { await rm(directory, { recursive: true, force: true }); }
  const existing = await mkdtemp(path.join(tmpdir(), 'scanmux-sarif-existing-test-'));
  try {
    await writeFile(path.join(existing, 'report.sarif'), 'existing sarif');
    await assert.rejects(saveReportBundle(report, config, existing, async value => JSON.stringify(value), async value => value), { code: 'EEXIST' });
    assert.equal(await readFile(path.join(existing, 'report.sarif'), 'utf8'), 'existing sarif');
    assert.deepEqual((await readdir(existing)).sort(), ['report.html', 'report.json', 'report.sarif']);
  } finally { await rm(existing, { recursive: true, force: true }); }
});
