import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import type { EngineRun, Report, TrivyFinding } from '../src/model.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { renderHtmlReport, groupFindings } from '../src/html-report.ts';
import { renderSarifReports } from '../src/sarif-report.ts';
import { trivyCoverageText } from '../src/report-language.ts';

function fixture(): Report {
  const finding: TrivyFinding = { fingerprint: 'f'.repeat(64), engine: 'trivy', originIds: ['AVD-DS-0002'], category: 'misconfiguration', severity: 'high', confidence: 'unknown', evidenceState: 'candidate', disposition: 'open', file: 'Dockerfile', line: 2, endLine: 5, title: 'private scanner prose', fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' };
  const run: EngineRun = { engine: 'trivy', execution: 'completed', coverage: 'partial', targets: ['Dockerfile', 'broken.yaml'], exclusions: [], findings: [finding, { ...finding, fingerprint: '0'.repeat(64), file: null, line: null, endLine: null }], evidence: [], errors: [], version: '0.76.1', executableHash: 'a'.repeat(64), rulesVersion: null, dbAsOf: null, database: [], startedAt: '2026-10-26T00:00:00Z', endedAt: '2026-10-26T00:00:01Z', exitCode: 0, auth: 'none', modelRequested: null, modelActual: null, accessProgramRequested: null, accessProgramEffective: null, usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' }, trivyCoverage: { state: 'partial', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }, { unit: 'kubernetes:broken.yaml', state: 'parse_failed' }], reasons: ['private diagnostic must not leak'] } };
  return { schema: 'scanmux.report/v3', runId: '11111111-1111-1111-1111-111111111111', gate: 'INCOMPLETE', exitCode: 3, startedAt: run.startedAt, endedAt: run.endedAt, executionState: 'completed', coverageState: 'incomplete', reasons: ['required_trivy_incomplete'], integrityErrors: [], runner: { platform: 'win32', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' }, plan: { schema: 'scanmux.plan/v3', root: 'C:/private-host/source', repoId: 'fixture', advisoryCatalog: { ...catalogIdentity }, commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 'c'.repeat(64), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories', 'trivy'], policyHash: 'd'.repeat(64), planHash: 'e'.repeat(64), network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 }, trivy: { schema: 'scanmux.trivy-plan/v1', profile: 'embedded-config-v1', inputs: [{ key: 'dockerfile:Dockerfile', kind: 'dockerfile', files: ['Dockerfile'], unresolved: false }, { key: 'kubernetes:broken.yaml', kind: 'kubernetes', files: ['broken.yaml'], unresolved: false }] } }, engines: [run] };
}
const sarif = (report: Report) => JSON.parse(renderSarifReports(report, 100000)[0].text).runs[0];

test('Trivy candidates retain range, unknown location and coverage evidence in both display languages and SARIF', () => {
  const report = fixture(), before = structuredClone(report);
  for (const language of ['ja', 'en'] as const) {
    const html = renderHtmlReport(report, language), summary = trivyCoverageText(report.engines[0], language);
    for (const value of [html, summary]) { assert.ok(!value.includes('private diagnostic')); assert.ok(!value.includes('private-host')); assert.ok(!value.includes('private scanner prose')); }
    assert.ok(html.includes('AVD-DS-0002')); assert.ok(html.includes('Dockerfile')); assert.ok(html.includes('2–5'));
    assert.ok(html.includes(language === 'ja' ? '場所は不明です' : 'Location unavailable'));
    assert.ok(html.includes(language === 'ja' ? '検出候補' : 'Candidate finding'));
    assert.ok(html.includes(language === 'ja' ? '構文解析失敗' : 'Parse failed'));
    assert.ok(html.includes('scanmux.report/v3')); assert.ok(summary.includes('2'));
  }
  const output = sarif(report);
  assert.equal(output.invocations[0].executionSuccessful, false);
  assert.deepEqual(output.results[0].locations[0].physicalLocation.region, { startLine: 2, endLine: 5 });
  assert.equal(output.results[1].locations, undefined); assert.equal(output.results[1].properties.locationUnavailable, true);
  assert.equal(output.results[0].properties.evidenceState, 'candidate');
  assert.deepEqual(output.properties.engineRuns[0].trivyCoverage, { state: 'partial', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }, { unit: 'kubernetes:broken.yaml', state: 'parse_failed' }], reasonCount: 1 });
  assert.ok(!JSON.stringify(output).includes('private diagnostic')); assert.deepEqual(report, before);
});

test('every owner AppContainer operation has a specific explanation in both report languages', () => {
  const labels = [
    ['elevated_owner', '所有者が昇格しているため、TrivyのAppContainerを起動できません。', 'The Trivy AppContainer cannot start because its owner is elevated.'],
    ['profile_unavailable', 'TrivyのAppContainerプロファイルAPIを利用できません。', 'The Trivy AppContainer profile API is unavailable.'],
    ['profile_failed', 'TrivyのAppContainerプロファイルの作成に失敗しました。', 'The Trivy AppContainer profile could not be created.'],
    ['owner_token_invalid', 'TrivyのAppContainer所有者のトークンを確認できません。', 'The Trivy AppContainer owner token could not be verified.'],
    ['roots_invalid', 'TrivyのAppContainerの対象ディレクトリが要件を満たしていません。', 'The Trivy AppContainer directories do not meet the required layout and path constraints.'],
    ['grant_failed', 'TrivyのAppContainerへのアクセス権付与に失敗しました。', 'Access permissions could not be granted to the Trivy AppContainer.'],
    ['create_failed', 'TrivyのAppContainerプロセスの作成または属性の設定に失敗しました。', 'The Trivy AppContainer process could not be created or its attributes could not be set.'],
    ['token_mismatch', 'TrivyのAppContainer子プロセスのトークンが要件を満たしていません。', 'The Trivy AppContainer child token does not meet the required constraints.'],
    ['setup_failed', 'TrivyのAppContainerの準備中に予期しないエラーが発生しました。', 'An unexpected error occurred while preparing the Trivy AppContainer.'],
    ['cleanup_failed', 'TrivyのAppContainerの後始末に失敗しました。', 'The Trivy AppContainer cleanup failed.'],
    ['unavailable', 'TrivyのAppContainerを利用できません。', 'The Trivy AppContainer is unavailable.'],
  ];
  for (const [operation, ja, en] of labels) {
    const report = fixture();
    report.reasons = report.engines[0].errors = [`process_owner_appcontainer_${operation}`];
    const coverage = report.engines[0].trivyCoverage!;
    if (coverage.state === 'partial') coverage.reasons = [`process_owner_appcontainer_${operation}`];
    for (const language of ['ja', 'en'] as const) {
      const html = renderHtmlReport(report, language);
      assert.ok(html.includes(language === 'ja' ? ja : en), `${operation}: ${language}`);
      assert.ok(!html.includes(language === 'ja' ? '自動説明に未対応' : 'Some reasons do not have'));
    }
  }
});

test('unknown and invalid Trivy locations never fabricate ranges or expose absolute paths', () => {
  for (const file of [null, 'C:/private-host/path', '../private-host/path']) {
    const report = fixture(); const finding = report.engines[0].findings[0] as TrivyFinding; finding.file = file;
    assert.equal(sarif(report).results[0].locations, undefined);
    for (const language of ['ja', 'en'] as const) assert.ok(!renderHtmlReport(report, language).includes('private-host'));
  }
  for (const endLine of [null, 0, 1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const report = fixture(); (report.engines[0].findings[0] as TrivyFinding).endLine = endLine;
    assert.deepEqual(sarif(report).results[0].locations[0].physicalLocation.region, { startLine: 2 });
  }
  const report = fixture(); (report.engines[0].findings[0] as TrivyFinding).line = null;
  assert.equal(sarif(report).results[0].locations[0].physicalLocation.region, undefined);
});

test('coverage receipts stay tied to planned units and arbitrary receipt paths cannot enter SARIF', () => {
  const report = fixture(); const coverage = report.engines[0].trivyCoverage!;
  assert.equal(coverage.state, 'partial'); if (coverage.state !== 'partial') return;
  coverage.receipts = [{ unit: 'C:/private-host/receipt', state: 'analyzed' }];
  assert.throws(() => sarif(report), /invalid_sarif_report/);
  assert.ok(!renderHtmlReport(report, 'en').includes('private-host'));
  assert.ok(!trivyCoverageText(report.engines[0], 'en').includes('private-host'));
});

test('v3 SARIF success requires all five required records and complete nonempty Trivy receipts', () => {
  const report = fixture(), original = report.engines[0];
  original.findings = []; original.coverage = 'analyzed'; original.trivyCoverage = { state: 'analyzed', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }, { unit: 'kubernetes:broken.yaml', state: 'analyzed' }] };
  report.engines = report.plan.required.map(engine => ({ ...structuredClone(original), engine, ...(engine === 'trivy' ? {} : { trivyCoverage: undefined }) }));
  report.gate = 'PASS'; report.exitCode = 0; report.coverageState = 'complete';
  assert.equal(sarif(report).invocations[0].executionSuccessful, true);
  const absent = structuredClone(report); delete absent.engines[4].trivyCoverage;
  assert.throws(() => sarif(absent), /invalid_sarif_report/);
  const missing = structuredClone(report); missing.engines.pop();
  assert.throws(() => sarif(missing), /invalid_sarif_report/);
  const incomplete = structuredClone(report); incomplete.engines[4].trivyCoverage = { state: 'analyzed', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }] };
  assert.throws(() => sarif(incomplete), /invalid_sarif_report/);
  const empty = structuredClone(report); Reflect.set(empty.engines[4], 'trivyCoverage', { state: 'analyzed', receipts: [] });
  assert.throws(() => sarif(empty), /invalid_sarif_report/);
  const duplicates = structuredClone(report); duplicates.engines[4].trivyCoverage = { state: 'analyzed', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }, { unit: 'dockerfile:Dockerfile', state: 'analyzed' }] };
  assert.throws(() => sarif(duplicates), /invalid_sarif_report/);
  const unresolved = structuredClone(report); unresolved.plan.trivy!.inputs[0].unresolved = true;
  assert.throws(() => sarif(unresolved), /invalid_sarif_report/);
});

test('Trivy display grouping distinguishes unknown locations and does not mutate finding identity', () => {
  const report = fixture(), findings = report.engines[0].findings;
  assert.equal(groupFindings(findings).length, 2);
  assert.deepEqual(groupFindings(findings).flatMap(group => group.items.map(item => item.value.fingerprint)), findings.map(finding => finding.fingerprint));
});

test('Trivy guides share structure, fixed acquisition values and measured limitations', async () => {
  const en = await readFile('docs/trivy.md', 'utf8'), ja = await readFile('docs/trivy.ja.md', 'utf8');
  const headings = (value: string) => value.split('\n').filter(line => /^#+ /.test(line)).map(line => line.split(' ')[0]);
  assert.deepEqual(headings(en), headings(ja));
  for (const text of [en, ja]) {
    for (const value of ['0.76.1', '94618922c9eb324d7099bf217b01504bfc1f87a0d46d6008cb24ec89b1d1a4bb', '1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf', 'Apache-2.0', '--skip-version-check', '--disable-telemetry', '--skip-check-update', '11001', '10013', 'SendTo', 'All Application Packages']) assert.ok(text.includes(value), value);
    assert.ok(text.includes('trivy.exe --version')); assert.ok(!text.includes('trivy.exe --skip-version-check --disable-telemetry --version'));
    assert.ok(!text.includes('\r'));
    for (const value of ['engine-record', 'engine-history', 'GitHub', 'SCANMUX_REQUIRE_APPCONTAINER=1']) assert.ok(text.includes(value), value);
  }
  assert.match(en, /configured version other than.*0\.76\.1.*INCOMPLETE/);
  assert.match(ja, /設定.*0\.76\.1.*INCOMPLETE/);
  const owner = await readFile('docs/windows-process-termination.md', 'utf8');
  for (const value of ['appcontainer_elevated_owner', 'appcontainer_profile_unavailable', 'appcontainer_grant_failed', 'appcontainer_create_failed', 'appcontainer_token_mismatch', 'tool_digest_mismatch', 'descriptor', 'appcontainer_cleanup_failed']) assert.ok(owner.includes(value), value);
});

test('Trivy and owner guides state the two AppContainer exceptions to ERROR', async () => {
  for (const file of ['docs/trivy.md', 'docs/windows-process-termination.md']) {
    assert.match(await readFile(file, 'utf8'), /Every `process_owner_appcontainer_\*` code except `process_owner_appcontainer_elevated_owner` and `process_owner_appcontainer_profile_unavailable` yields `ERROR`\./, file);
  }
  assert.match(await readFile('docs/trivy.ja.md', 'utf8'), /`process_owner_appcontainer_elevated_owner` と `process_owner_appcontainer_profile_unavailable` を除くすべての `process_owner_appcontainer_\*` コードは `ERROR` になります。/);
});

test('owner guide identifies the .NET exception HRESULT for missing DLLs and entry points', async () => {
  assert.match(await readFile('docs/windows-process-termination.md', 'utf8'), /When the DLL or entry point is missing, the native error field holds the \.NET exception HRESULT\./);
});
