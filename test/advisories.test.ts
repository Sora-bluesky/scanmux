import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { catalog, catalogIdentity, parseVersion } from '../src/advisory-catalog.ts';
import { extractDeclarations } from '../src/runtime-declarations.ts';
import { assessDeclaration, RuntimeAdvisoryAdapter } from '../src/runtime-advisories.ts';
import { advisoryText, advisoryView } from '../src/advisory-display.ts';
import { defaults } from '../src/config.ts';
import { digest } from '../src/safety.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide } from '../src/policy.ts';
import { scan } from '../src/controller.ts';
import { renderHtmlReport } from '../src/html-report.ts';
import type { AdapterContext, Declaration, Plan } from '../src/model.ts';

function assess(product: Declaration['product'], version: string | null, id: string) {
  const row = assessDeclaration({ product, version, file: 'Dockerfile', line: 1, selector: null, edition: null, reason: version ? 'exact_declaration' : 'invalid_version', assessments: [] });
  return row.assessments.find(value => value.id === id)?.state;
}
function plan(root: string): Plan {
  const value: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: 'fixture', commit: null, treeHash: null, snapshotHash: digest([]), dirty: false, files: [], exclusions: [], blockers: ['test_plan_blocked'], languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  value.planHash = digest({ ...value, planHash: '' }); return value;
}
test('all 26 advisories retain attributed facts and independent series boundaries', () => {
  assert.equal(catalog.records.length, 26); assert.equal(new Set(catalog.records.map(row => row.id)).size, 26);
  assert.equal(catalogIdentity.sha256, digest(catalog)); assert.ok(Object.isFrozen(catalog.records[0].affected[0]));
  for (const row of catalog.records) {
    assert.equal(row.confirmedAt, '2026-10-22'); assert.ok(row.sources.every(url => url.startsWith('https://')));
    for (const value of [...row.domains, ...row.affected, ...row.excluded]) { assert.ok(parseVersion(value.from)); assert.ok(parseVersion(value.to)); }
    assert.equal(assess(row.product, null, row.id), 'unknown');
    assert.equal(assess(row.product, '999.0.0', row.id), 'unknown');
  }
  for (const id of ['CVE-2026-109618', 'CVE-2026-109619']) {
    for (const [last, fixed] of [['8.2.34', '8.2.35'], ['8.3.35', '8.3.36'], ['8.4.26', '8.4.27'], ['8.5.11', '8.5.12']]) { assert.equal(assess('php', last, id), 'matched'); assert.equal(assess('php', fixed, id), 'outside_recorded_ranges'); }
    for (const version of ['7.4.33', '8.0.30', '8.1.0', '8.6.0']) assert.equal(assess('php', version, id), 'unknown');
  }
  const nodeDomains = { '105482': [22, 24, 26], '105483': [24, 26], '106069': [22, 24, 26], '111497': [22, 24, 26], '105481': [22, 24, 26], '106072': [22, 24, 26], '106074': [22, 24, 26], '106070': [26], '106071': [26], '106073': [22, 24, 26] };
  for (const [id, majors] of Object.entries(nodeDomains)) for (const [last, fixed] of [['22.23.3', '22.23.4'], ['24.22.0', '24.22.1'], ['26.12.0', '26.12.1']]) {
    const supported = majors.includes(Number(last.split('.')[0])); assert.equal(assess('node', last, 'CVE-2026-' + id), supported ? 'matched' : 'unknown'); assert.equal(assess('node', fixed, 'CVE-2026-' + id), supported ? 'outside_recorded_ranges' : 'unknown');
  }
  for (const row of catalog.records.filter(row => row.product === 'node')) assert.equal(assess('node', '20.0.0', row.id), 'unknown');
});
test('Next exclusive lower bound and separate domains are not flattened', () => {
  const cases: [string, string, string][] = [
    ['GHSA-673q-mjm6-r5xr', '15.5.27', 'unknown'], ['GHSA-673q-mjm6-r5xr', '16.0.0', 'matched'], ['GHSA-673q-mjm6-r5xr', '16.4.0', 'matched'], ['GHSA-673q-mjm6-r5xr', '16.4.1', 'outside_recorded_ranges'],
    ['GHSA-2464-fhr4-w9xw', '9.9.9', 'unknown'], ['GHSA-2464-fhr4-w9xw', '10.0.0', 'matched'], ['GHSA-2464-fhr4-w9xw', '15.5.27', 'matched'], ['GHSA-2464-fhr4-w9xw', '15.5.28', 'outside_recorded_ranges'], ['GHSA-2464-fhr4-w9xw', '16.0.0', 'outside_recorded_ranges'], ['GHSA-2464-fhr4-w9xw', '16.0.1', 'matched'], ['GHSA-2464-fhr4-w9xw', '16.4.0', 'matched'], ['GHSA-2464-fhr4-w9xw', '16.4.1', 'outside_recorded_ranges'],
    ['GHSA-p3m5-59mp-jv5r', '12.3.0', 'unknown'], ['GHSA-p3m5-59mp-jv5r', '13.0.0', 'matched'], ['GHSA-p3m5-59mp-jv5r', '15.5.27', 'matched'], ['GHSA-p3m5-59mp-jv5r', '15.5.28', 'outside_recorded_ranges'], ['GHSA-p3m5-59mp-jv5r', '16.0.0', 'matched'], ['GHSA-p3m5-59mp-jv5r', '16.4.0', 'matched'], ['GHSA-p3m5-59mp-jv5r', '16.4.1', 'outside_recorded_ranges'],
  ];
  for (const [id, version, state] of cases) assert.equal(assess('next', version, id), state, `${id}/${version}`);
});
test('NGINX fixed stable branch never clears vulnerable mainline; all lower bounds', () => {
  for (const [id, before, first] of [['15176', '0.1.28', '0.1.29'], ['93479', '1.31.1', '1.31.2'], ['95101', '1.24.9', '1.25.0'], ['97629', '1.23.1', '1.23.2'], ['97205', '0.8.10', '0.8.11']]) {
    const cve = 'CVE-2026-' + id;
    assert.equal(assess('nginx', before, cve), 'outside_recorded_ranges');
    for (const version of [first, '1.30.0', '1.30.5', '1.31.6']) assert.equal(assess('nginx', version, cve), 'matched');
    for (const version of ['1.30.6', '1.30.9', '1.31.7']) assert.equal(assess('nginx', version, cve), 'outside_recorded_ranges');
    assert.equal(assess('nginx', '1.32.0', cve), 'unknown');
  }
});
test('GitLab seven release intervals and Tomcat advisory-specific starts and domains', () => {
  for (const [first, last, fixed] of [['7.0.0', '18.11.12', '18.11.13'], ['19.0.0', '19.0.9', '19.0.10'], ['19.1.0', '19.1.8', '19.1.9'], ['19.2.0', '19.2.8', '19.2.9'], ['19.3.0', '19.3.5', '19.3.6'], ['19.4.0', '19.4.2', '19.4.3'], ['19.5.0', '19.5.0', '19.5.1']]) {
    for (const version of [first, last]) assert.equal(assess('gitlab', version, 'CVE-2026-110264'), 'matched');
    assert.equal(assess('gitlab', fixed, 'CVE-2026-110264'), 'outside_recorded_ranges');
  }
  for (const version of ['6.9.0', '19.6.0']) assert.equal(assess('gitlab', version, 'CVE-2026-110264'), 'unknown');
  for (const [id, starts] of Object.entries({ '103119': ['11.0.0'], '101356': ['11.0.22', '10.1.55', '9.0.118'], '101296': ['11.0.0', '10.1.0', '9.0.0'], '93446': ['11.0.0', '10.1.25', '9.0.90'], '88041': ['11.0.0', '10.1.27', '9.0.92'] })) {
    const cve = 'CVE-2026-' + id;
    for (const [i, first] of starts.entries()) {
      assert.equal(assess('tomcat', first, cve), 'matched');
      const [major, minor, patch] = first.split('.').map(Number);
      if (patch) assert.equal(assess('tomcat', `${major}.${minor}.${patch - 1}`, cve), 'outside_recorded_ranges');
      assert.equal(assess('tomcat', ['11.0.26', '10.1.60', '9.0.122'][i], cve), 'matched');
      assert.equal(assess('tomcat', ['11.0.27', '10.1.61', '9.0.123'][i], cve), 'outside_recorded_ranges');
    }
    for (const version of ['10.0.1', '11.0.0-M25', '8.5.0']) assert.equal(assess('tomcat', version, cve), 'unknown');
  }
  for (const version of ['10.1.59', '9.0.120']) assert.equal(assess('tomcat', version, 'CVE-2026-103119'), 'unknown');
  assert.equal(catalog.records.find(row => row.id === 'CVE-2026-103119')?.severity, 'unknown');
});
test('version declaration grammar rejects ambiguity without retaining original text', () => {
  for (const file of ['.nvmrc', '.node-version', 'nested/.nvmrc']) assert.equal(extractDeclarations(file, '# comment\n v24.22.0\n')[0].version, '24.22.0');
  assert.equal(extractDeclarations('.php-version', '8.5.11')[0].version, '8.5.11');
  for (const value of ['v8.5.11', '8.05.11', '8.5', '^8.5.11', '8.5.11-alpha', '8.5.11+vendor', '8.5.11\n8.4.26', '9007199254740992.0.0', '', 'secret payload']) {
    const rows = extractDeclarations('.php-version', value); assert.equal(rows[0].version, null); assert.ok(!JSON.stringify(rows).includes('secret payload'));
  }
  const tools = extractDeclarations('.tool-versions', 'python 3.13.0\nnodejs 24.22.0\nphp 8.5.11 8.4.26\nphp 8.4.26\n');
  assert.deepEqual(tools.map(row => [row.line, row.product, row.version]), [[2, 'node', '24.22.0'], [3, 'php', null], [4, 'php', '8.4.26']]);
});
test('Docker identities, suffix families, stages and unsupported syntax are explicit', () => {
  for (const [product, version, variants] of [
    ['node', '24.22.0', ['', '-slim', '-alpine', '-alpine3.22', '-bookworm', '-bookworm-slim', '-bullseye', '-bullseye-slim', '-trixie', '-trixie-slim']],
    ['php', '8.5.11', ['', '-cli', '-fpm', '-apache', '-zts', '-alpine', '-alpine3.22', '-bookworm', '-bullseye', '-trixie', ...['cli', 'fpm', 'apache', 'zts'].flatMap(sapi => ['alpine', 'alpine3.22', 'bookworm', 'bullseye', 'trixie'].map(os => `-${sapi}-${os}`))]],
    ['nginx', '1.31.6', ['', '-alpine', '-alpine3.22', '-bookworm', '-trixie']],
    ['tomcat', '11.0.26', ['', ...[8, 11, 17, 21, 25].flatMap(jdk => ['temurin', 'corretto'].flatMap(vendor => ['', '-jammy', '-noble', '-alpine'].map(os => `-jdk${jdk}-${vendor}${os}`)))]]
  ] as [string, string, string[]][]) for (const identity of [product, 'library/' + product, 'docker.io/library/' + product]) for (const suffix of variants) {
    const row = extractDeclarations('nested/Dockerfile.prod', `FROM --platform=linux/amd64 ${identity}:${version}${suffix} AS build`)[0];
    assert.equal(row.product, product); assert.equal(row.version, version, identity + suffix);
  }
  for (const edition of ['ce', 'ee']) for (const identity of [`gitlab/gitlab-${edition}`, `docker.io/gitlab/gitlab-${edition}`]) {
    const row = extractDeclarations('Dockerfile', `FROM ${identity}:19.5.0-${edition}.0`)[0]; assert.equal(row.product, 'gitlab'); assert.equal(row.version, '19.5.0'); assert.equal(row.edition, edition);
  }
  for (const text of ['FROM node:latest', 'FROM node:24', 'FROM node:24.22.0-vendor', 'FROM node:24.22.0@sha256:abcd', 'FROM $IMAGE', 'FROM "node:24.22.0"', 'FROM node:24.22.0 extra', 'FROM build', 'FROM evil/node:24.22.0', 'FROM docker.io/evil/node:24.22.0', 'FROM gitlab/gitlab-ce:19.5.0', 'FROM gitlab/gitlab-ce:19.5.0-ee.0', 'FROM --platform=Linux/AMD64 node:24.22.0', 'FROM --PLATFORM=linux/amd64 node:24.22.0']) assert.equal(extractDeclarations('Dockerfile', text)[0].version, null, text);
  for (const text of ['FROM node:24.22.0\nRUN echo \\\nhello', 'FROM node:24.22.0\nRUN <<EOF\nx\nEOF', '# escape=`\nFROM node:24.22.0']) assert.deepEqual(extractDeclarations('Dockerfile', text).map(row => row.reason), ['unsupported_docker_syntax']);
  const multi = extractDeclarations('Dockerfile', 'FROM node:24.22.0 AS build\nFROM php:8.5.12\nFROM build'); assert.deepEqual(multi.map(row => row.version), ['24.22.0', '8.5.12', null]); assert.deepEqual(multi.map(row => row.line), [1, 2, 3]);
  assert.deepEqual(extractDeclarations('.dockerignore', 'FROM node:24.22.0'), []);
});
test('npm v1/v2/v3 traversal, aliases, links, source and malformed required objects', () => {
  const v1 = extractDeclarations('package-lock.json', JSON.stringify({ lockfileVersion: 1, dependencies: { next: { version: '16.4.0' }, parent: { version: '1.0.0', dependencies: { next: { version: '15.5.27' } } }, alias: { version: 'npm:next@16.4.0' } } }));
  assert.equal(v1.length, 3); assert.ok(v1.some(row => row.selector === 'node_modules/parent/node_modules/next' && row.version === '15.5.27')); assert.ok(v1.some(row => row.reason === 'npm_alias'));
  for (const lockfileVersion of [2, 3]) {
    const rows = extractDeclarations('npm-shrinkwrap.json', JSON.stringify({ lockfileVersion, packages: { '': { name: 'next', version: '16.4.0' }, 'node_modules/next': { version: '16.4.0' }, 'node_modules/a/node_modules/next': { name: 'next', version: '15.5.27' }, 'node_modules/alias': { name: 'next', version: '16.4.0' } }, dependencies: { next: { version: '16.4.0' } } }));
    assert.equal(rows.length, 3); assert.equal(rows.filter(row => row.version).length, 2); assert.equal(rows[2].reason, 'npm_alias');
  }
  for (const entry of [{ name: 'other', version: '16.4.0' }, { link: true, version: '16.4.0' }, { version: '^16.4.0' }, { version: 'npm:next@16.4.0' }, {}, null, ...['file:../next', 'link:../next', 'workspace:*', 'git+https://example.test/a.git', 'https://github.com/vercel/next.js/archive/main.tar.gz', 'https://example.test/a.git'].map(resolved => ({ version: '16.4.0', resolved }))]) {
    const rows = extractDeclarations('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/next': entry } })); assert.equal(rows[0].version, null);
  }
  for (const value of ['{', '{}', '{"lockfileVersion":"3","packages":{}}', '{"lockfileVersion":4,"packages":{}}', '{"lockfileVersion":3,"packages":[]}', '{"lockfileVersion":1,"dependencies":{"x":{"dependencies":[]}}}']) assert.throws(() => extractDeclarations('package-lock.json', value), /advisory_input_invalid/);
});
test('adapter preserves mixed matched/unknown, no declaration, failure and cancellation without PASS', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-advisory-test-'));
  try {
    const value = plan(workspace); value.files = [{ path: '.node-version', oid: 'a'.repeat(40), sha256: 'b'.repeat(64), bytes: 7 }];
    const context: AdapterContext = { plan: value, config: defaults, workspace, snapshot: workspace, signal: new AbortController().signal, secretsCleared: false };
    await writeFile(path.join(workspace, '.node-version'), '22.23.3');
    const run = await new RuntimeAdvisoryAdapter().run(context);
    assert.equal(run.execution, 'completed'); assert.equal(run.coverage, 'partial'); assert.equal(run.findings.length, 7);
    assert.equal(run.advisoryDetails!.declarations[0].assessments.filter(row => row.state === 'unknown').length, 3);
    const text = advisoryText(run.advisoryDetails!); const view = advisoryView(run.advisoryDetails!);
    assert.match(text, /CVE-2026-105482: 影響版に一致/); assert.match(text, /CVE-2026-105483: 未確認/); assert.match(text, /SHA-256/); assert.match(text, /nodejs.org/); assert.equal(view.declarations[0].assessments.length, 10);
    const html = renderHtmlReport({ schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', plan: value, startedAt: run.startedAt, endedAt: run.endedAt, engines: [run], gate: 'INCOMPLETE', exitCode: 3, reasons: ['required_runtime-advisories_incomplete'], integrityErrors: [], executionState: 'completed', coverageState: 'incomplete', runner: { platform: 'test', node: '24.22.1', imageDigest: null, isolation: 'local-static-only' } });
    assert.match(html, /CVE-2026-105482：影響版に一致/); assert.match(html, /CVE-2026-105483：未確認/); assert.match(html, /影響版に一致 7件.*未確認 3件/); assert.ok(html.includes(catalogIdentity.sha256)); assert.ok(html.includes('nodejs.org')); assert.ok(!html.includes(workspace));
    const others = value.required.filter(id => id !== 'runtime-advisories').map(id => ({ ...emptyRun(id, context), execution: 'completed' as const, coverage: 'analyzed' as const }));
    assert.equal(decide(value, [...others, run]).gate, 'INCOMPLETE');
    const cleanPlan = { ...value, blockers: [] };
    for (const coverage of ['partial', 'unsupported'] as const) assert.equal(decide(cleanPlan, [...others, { ...run, coverage }]).gate, 'INCOMPLETE');
    assert.equal(decide(cleanPlan, others).gate, 'INCOMPLETE');
    const none = await new RuntimeAdvisoryAdapter().run({ ...context, plan: { ...value, files: [] } }); assert.equal(none.coverage, 'unsupported'); assert.match(advisoryText(none.advisoryDetails!), /版宣言なし・実環境は未確認/);
    await writeFile(path.join(workspace, '.node-version'), 'secret payload\n'); const unknown = await new RuntimeAdvisoryAdapter().run(context); assert.equal(unknown.findings.length, 0); assert.ok(!JSON.stringify(unknown).includes('secret payload'));
    const cancelled = await new RuntimeAdvisoryAdapter().run({ ...context, signal: AbortSignal.abort() }); assert.equal(cancelled.execution, 'cancelled');
    await writeFile(path.join(workspace, 'package-lock.json'), '{'); const failed = await new RuntimeAdvisoryAdapter().run({ ...context, plan: { ...value, files: [{ ...value.files[0], path: 'package-lock.json' }] } }); assert.equal(failed.execution, 'failed'); assert.equal(decide(cleanPlan, [...others, failed]).gate, 'ERROR');
    await writeFile(path.join(workspace, '.node-version'), '22.23.3');
    const partial = await new RuntimeAdvisoryAdapter().run({ ...context, plan: { ...value, files: [value.files[0], { ...value.files[0], path: 'package-lock.json' }] } }); assert.equal(partial.execution, 'failed'); assert.equal(partial.findings.length, 7);
  } finally { await rm(workspace, { recursive: true, force: true }); }
});
test('old schema, missing required adapter and changed catalog reject before execution', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-advisory-plan-'));
  try {
    for (const change of [{ schema: 'scanmux.plan/v1' }, { required: ['gitleaks'] }, { advisoryCatalog: { ...catalogIdentity, sha256: '0'.repeat(64) } }]) {
      const value = { ...plan(workspace), ...change } as Plan; value.planHash = digest({ ...value, planHash: '' });
      const report = await scan(value, defaults, workspace, new AbortController().signal); assert.equal(report.gate, 'ERROR'); assert.deepEqual(report.engines, []); assert.deepEqual(report.integrityErrors, ['advisory_plan_mismatch']);
    }
  } finally { await rm(workspace, { recursive: true, force: true }); }
});
