import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { AdvisoryDetails, AiTransportRejectedEvent, EngineRun, Finding, Gate, Report } from '../src/model.ts';
import { catalog, catalogIdentity } from '../src/advisory-catalog.ts';
import { extractDeclarations } from '../src/runtime-declarations.ts';
import { assessDeclaration } from '../src/runtime-advisories.ts';
import { advisoryInfo, advisoryReason, advisoryView, declarationPlace } from '../src/advisory-display.ts';
import { displayValue, parseReportLanguage, reportText } from '../src/report-language.ts';
import { renderHtmlReport, reportCsp } from '../src/html-report.ts';
import { renderSarifReports } from '../src/sarif-report.ts';
import { saveReportBundle } from '../src/output.ts';
import { defaults } from '../src/config.ts';
import { main } from '../src/cli.ts';
import { SafeError } from '../src/safety.ts';

const languages = ['ja', 'en'] as const;
function fixture(gate: Gate = 'INCOMPLETE'): Report {
  return { schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', gate,
    exitCode: ({ PASS: 0, FAIL: 1, REVIEW: 2, INCOMPLETE: 3, ERROR: 4 })[gate],
    startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z', executionState: 'completed', coverageState: 'incomplete',
    reasons: ['required_codex-security_incomplete'], integrityErrors: [],
    runner: { platform: 'win32', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' },
    plan: { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: 'C:\\private-host\\target', repoId: 'fixture',
      commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 'c'.repeat(64), dirty: false, files: [], exclusions: [], blockers: [],
      languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: 'd'.repeat(64), planHash: 'e'.repeat(64),
      network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } }, engines: [] };
}
function engine(): EngineRun {
  return { engine: 'osv', execution: 'completed', coverage: 'analyzed', targets: ['package-lock.json'], exclusions: [], findings: [], evidence: [], errors: [],
    version: '2.7.0', executableHash: 'f'.repeat(64), rulesVersion: null, dbAsOf: null, database: [], startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01Z',
    exitCode: 0, auth: 'none', modelRequested: null, modelActual: null, accessProgramRequested: null, accessProgramEffective: null,
    usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } };
}
function finding(): Finding {
  return { fingerprint: '1'.repeat(64), engine: 'osv', originIds: ['CVE-2026-12345'], category: 'dependency', severity: 'high', confidence: 'unknown',
    evidenceState: 'candidate', disposition: 'open', file: '日本語/é-source.ts', line: 7, title: '<script>untrusted</script>',
    package: { name: '@example/package', version: '1.0.0', ecosystem: 'npm', direct: 'unknown' }, fixedVersions: ['1.0.1'], reachability: 'unknown', knownExploited: 'unknown' };
}
function advisoryDetails(): AdvisoryDetails {
  return { catalog: { ...catalogIdentity }, environment: 'unverified', vendorPatches: 'unverified', advisories: structuredClone(catalog.records),
    declarations: extractDeclarations('.node-version', '24.16.0\n').map(assessDeclaration) };
}
async function removeOwned(folder: string) {
  const parent = path.resolve(tmpdir());
  assert.equal(path.dirname(path.resolve(folder)), parent); assert.ok(path.basename(folder).startsWith('scanmux-language-'));
  await rm(folder, { recursive: true, force: true });
}

test('language admission is a closed choice without locale or path interpretation', () => {
  assert.equal(parseReportLanguage(undefined), 'ja'); assert.equal(parseReportLanguage('ja'), 'ja'); assert.equal(parseReportLanguage('en'), 'en');
  for (const value of ['', 'JA', 'EN', 'en-US', '../en', '<script>', null, 0, {}, []]) assert.throws(() => parseReportLanguage(value), { code: 'invalid_report_language' });
  assert.equal(reportText('ja', '未確認'), '未確認'); assert.equal(reportText('en', '未確認'), 'Unverified');
  assert.throws(() => Reflect.apply(reportText, null, ['en', 'untrusted prose']), { code: 'invalid_report_text' });
});

for (const code of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'unknown_code']) test(`display codes do not inherit object properties: ${code}`, () => {
  const values = Object.create({ [code]: 'inherited must not be displayed' }); values.known = 'own';
  assert.equal(displayValue(values, code, 'fallback'), 'fallback'); assert.equal(displayValue(values, 'known', 'fallback'), 'own');
  assert.equal(advisoryReason(code, 'en'), 'Unrecognized reason'); assert.equal(advisoryReason(code), '未解釈の理由');
  const advisory = structuredClone(catalog.records[0]); Reflect.set(advisory, 'conditions', [code]);
  assert.deepEqual(advisoryInfo(advisory, 'en').conditions, ['Conditions unverified']);
  const details = advisoryDetails(); assert.ok(details.declarations.length); const row = details.declarations[0];
  Reflect.set(row, 'product', code); row.assessments = [{ id: 'CVE-2026-12345', state: 'unknown', reason: 'declaration_unknown' }]; Reflect.set(row.assessments[0], 'state', code);
  const view = advisoryView(details, 'en'); assert.equal(view.declarations[0].product, 'Product unverified'); assert.equal(view.declarations[0].assessments[0].state, 'Unverified');
  const report = fixture(); Reflect.apply(report.plan.required.push, report.plan.required, [code]); const run = engine(); run.engine = 'runtime-advisories'; run.advisoryDetails = details; report.engines.push(run);
  const html = renderHtmlReport(report, 'en'); assert.ok(html.includes('Affected-version matches 0 / Outside recorded ranges 0 / Unverified 1'));
  for (const value of ['inherited must not be displayed', 'function Object', '[object Object]', 'function toString']) assert.ok(!html.includes(value));
});

for (const gate of ['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'] as const) test(`both languages preserve ${gate}, missing engines and zero findings`, () => {
  const report = fixture(gate), before = structuredClone(report);
  const ja = renderHtmlReport(report), en = renderHtmlReport(report, 'en');
  assert.equal(renderHtmlReport(report, 'ja'), ja); assert.ok(ja.includes(`（${gate}）`)); assert.ok(en.includes(`(${gate})`));
  assert.equal((ja.match(/<td>実行記録なし<\/td>/g) ?? []).length, 4); assert.equal((en.match(/<td>No execution record<\/td>/g) ?? []).length, 4);
  assert.ok(en.includes('No findings were recorded. Also check for unscanned or excluded areas.')); assert.ok(en.includes('Incomplete'));
  assert.equal(/[\u3000-\u30ff\u3400-\u9fff\uff00-\uffef]/.test(en), false); assert.ok(!en.includes(report.plan.root)); assert.deepEqual(report, before);
});

test('grouping, CVE, version, Unicode locations, IDs and print records retain their meaning', () => {
  const report = fixture(), run = engine(), first = finding(); run.findings.push(first, { ...structuredClone(first), fingerprint: '2'.repeat(64), severity: 'unknown', line: 9 }); report.engines.push(run);
  const before = structuredClone(report), sarif = renderSarifReports(report, defaults.maxOutputBytes);
  const html = languages.map(language => renderHtmlReport(report, language));
  for (const value of html) {
    for (const identity of ['CVE-2026-12345', '@example/package', '1.0.0', '1.0.1', '日本語/é-source.ts', 'screen-finding-1', 'print-finding-1', 'screen-finding-2', 'print-finding-2']) assert.ok(value.includes(identity), identity);
    assert.equal((value.match(/id="target-/g) ?? []).length, 1); assert.ok(!value.includes('<script>')); assert.ok(!value.includes(first.title));
    assert.ok(!value.includes(report.plan.root)); assert.ok(!value.includes(first.fingerprint));
  }
  assert.ok(html[1].includes('Highest known severity: High / Unknown severity 1')); assert.deepEqual(report, before); assert.deepEqual(renderSarifReports(report, defaults.maxOutputBytes), sarif);
});

test('both locales retain escaping, concealment and generic unknown-reason fallback', () => {
  const report = fixture(), run = engine(), value = finding(); value.file = 'source<svg onload=bad>.ts'; value.originIds.push('<script>bad</script>'); run.findings.push(value); run.errors.push('<script>arbitrary reason</script>'); report.engines.push(run);
  for (const language of languages) {
    const html = renderHtmlReport(report, language); assert.ok(html.includes('source&lt;svg onload=bad&gt;.ts')); assert.ok(!html.includes('<svg')); assert.ok(!html.includes('<script>')); assert.ok(!html.includes('arbitrary reason'));
    assert.ok(html.includes(language === 'en' ? 'Identifier hidden' : '識別子は非表示')); assert.ok(html.includes(language === 'en' ? 'Some reasons have no display explanation.' : '自動説明に未対応の理由があります。'));
  }
  value.file = 'C:\\private-host\\secret.ts'; value.fixedVersions = ['javascript:bad'];
  for (const language of languages) { const html = renderHtmlReport(report, language); assert.ok(!html.includes(value.file)); assert.ok(!html.includes('javascript:bad')); }
});

test('advisory facts and location selectors stay fixed while only controlled labels change', () => {
  const details = advisoryDetails(), before = structuredClone(details), ja = advisoryView(details), en = advisoryView(details, 'en');
  assert.equal(en.hash, ja.hash); assert.equal(en.confirmedAt, ja.confirmedAt); assert.equal(en.declarations.length, ja.declarations.length);
  for (let index = 0; index < en.declarations.length; index++) { const old = ja.declarations[index], current = en.declarations[index];
    assert.deepEqual([current.product, current.version, current.place, current.edition], [old.product, old.version, old.place, old.edition]); assert.deepEqual(current.assessments.map(x => x.id), old.assessments.map(x => x.id));
  }
  for (let index = 0; index < en.advisories.length; index++) assert.deepEqual([en.advisories[index].id, en.advisories[index].severity, en.advisories[index].sources, en.advisories[index].fixed], [ja.advisories[index].id, ja.advisories[index].severity, ja.advisories[index].sources, ja.advisories[index].fixed]);
  assert.equal(declarationPlace(details.declarations[0], 'en'), declarationPlace(details.declarations[0])); assert.deepEqual(details, before);
});

test('invalid locale is rejected by rendering and advisory entry points', () => {
  const report = fixture(), details = advisoryDetails();
  for (const value of ['', 'EN', null, '<script>']) {
    for (const [fn, input] of [[renderHtmlReport, report], [advisoryView, details], [advisoryInfo, catalog.records[0]], [advisoryReason, 'unknown'], [declarationPlace, details.declarations[0]]] as const) {
      assert.throws(() => Reflect.apply(fn, null, [input, value]), { code: 'invalid_report_language' });
    }
  }
});

test('bundle locale changes HTML only, with identical JSON and SARIF and unchanged report', async () => {
  const report = fixture(), before = structuredClone(report), roots: string[] = [], outputs = [];
  const check = async (payload: unknown) => JSON.stringify(payload, null, 2) + '\n', checkText = async (value: string) => value;
  try { for (const language of languages) { const root = await mkdtemp(path.join(tmpdir(), 'scanmux-language-')); roots.push(root);
    const saved = await saveReportBundle(report, defaults, root, check, checkText, language); assert.equal(saved.html, renderHtmlReport(saved.report, language)); assert.ok(saved.html.includes(`<html lang="${language}">`)); outputs.push(saved);
  }
  assert.equal(outputs[0].json, outputs[1].json); assert.deepEqual(outputs[0].sarif.map(x => x.text), outputs[1].sarif.map(x => x.text)); assert.deepEqual(report, before);
  } finally { for (const root of roots) await removeOwned(root); }
});

function aiEngine(): EngineRun {
  const run = engine(); run.engine = 'codex-security'; run.auth = 'chatgpt'; run.modelRequested = run.modelActual = 'gpt-6-sol';
  run.accessProgramRequested = 'daybreak_blue'; run.accessProgramEffective = 'standard';
  Reflect.set(run, 'aiExecution', { schema: 'scanmux.ai-execution/v1', classification: 'provider', status: 'completed',
    tokens: { kind: 'complete', observed: { inputTokens: 3, outputTokens: 2, totalTokens: 5 } }, programs: ['standard'],
    submitInvocations: 1, connectionAttempts: 1, sendInvocations: 1, runtime: { boundaryVerified: true },
    cleanup: { closed: true, quiescent: true, containerAbsent: true }, originalCommit: 'a'.repeat(40), derivedRevision: 'b'.repeat(40),
    sourcePreflight: 'completed', artifactsAccepted: true, artifacts: [], coverage: { openQuestions: 0, deferred: 0, exclusions: 0, limitations: 0 } });
  return run;
}

for (const language of languages) test(`saved AI transport failures have a short controlled diagnostic in ${language} HTML`, async () => {
  const report = fixture(), run = aiEngine(); report.engines.push(run); assert.ok(run.aiExecution);
  run.aiExecution.transportRequests = [{ sequence: 1, receivedBytes: 648, receivedMessages: 2, terminal: false, terminalKind: 'none', closeCode: 1006, sendOk: true, failureCode: 'response_limit' }];
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-language-'));
  try {
    const bundle = await saveReportBundle(report, defaults, root, async value => JSON.stringify(value), async value => value, language);
    const saved = JSON.parse(await readFile(bundle.destination, 'utf8'));
    assert.deepEqual(saved.engines[0].aiExecution.transportRequests, run.aiExecution.transportRequests);
    assert.ok(bundle.html.includes(`${language === 'ja' ? 'AI通信の診断' : 'AI transport diagnostic'} #1: response_limit`));
    assert.equal(saved.gate, report.gate); assert.equal(saved.engines[0].aiExecution.schema, 'scanmux.ai-execution/v1');
    Reflect.set(run.aiExecution, 'transportRequests', [{ sequence: 1, failureCode: 'private-canary<script>' }, { sequence: 'private-canary', failureCode: 'response_limit' }, null]);
    const html = renderHtmlReport(report, language); assert.ok(!html.includes('private-canary')); assert.ok(!html.includes('AI transport diagnostic #'));
  } finally { await removeOwned(root); }
});

for (const language of languages) test(`saved first and rejected WebSocket message shapes survive ${language} report serialization`, async () => {
  const report = fixture(), run = aiEngine(); report.engines.push(run); assert.ok(run.aiExecution);
  const firstEvent = { kind: 'object' as const, type: 'codex.rate_limits', keys: ['rate_limits', 'type'], otherKeys: 0,
    sequenceNumber: 'absent' as const, sequence: 'absent' as const, streamId: 'absent' as const };
  const rejectedEvent: AiTransportRejectedEvent = { ...firstEvent, type: 'response.completed', keys: ['response', 'safety_buffering', 'sequence_number', 'type'], sequenceNumber: 'integer',
    valueShapes: { response: { type: 'object', size: 7, output: { type: 'array', size: 1 }, statusType: 'string' },
      safety_buffering: { type: 'object', size: 3, keys: ['reasons', 'retry_model', 'use_cases'], otherKeys: 0 }, sequence_number: { type: 'number', size: null }, type: { type: 'string', size: 18 } } };
  // @ts-expect-error valueShapes carries shapes only, never a value.
  const valueLeak: AiTransportRejectedEvent = { ...firstEvent, valueShapes: { type: { type: 'string', size: 17, value: 'codex.rate_limits' } } }; assert.ok(valueLeak);
  run.aiExecution.transportRequests = [{ sequence: 1, receivedBytes: 1002, receivedMessages: 1, terminal: false, terminalKind: 'none', closeCode: 1006,
    sendOk: true, failureCode: 'sequence_mismatch', firstEvent, rejectedEvent, rejectedAt: 1 }];
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-language-'));
  try {
    const bundle = await saveReportBundle(report, defaults, root, async value => JSON.stringify(value), async value => value, language);
    const saved = JSON.parse(await readFile(bundle.destination, 'utf8'));
    assert.deepEqual(saved.engines[0].aiExecution.transportRequests[0].firstEvent, firstEvent);
    assert.deepEqual(saved.engines[0].aiExecution.transportRequests[0].rejectedEvent, rejectedEvent);
    assert.equal(saved.engines[0].aiExecution.transportRequests[0].rejectedAt, 1);
    assert.ok(bundle.html.includes(`${language === 'ja' ? 'AI通信の診断' : 'AI transport diagnostic'} #1: sequence_mismatch`));
    Reflect.set(run.aiExecution.transportRequests[0], 'firstEvent', { type: 'private-canary<script>', keys: ['private-canary<script>'] });
    assert.ok(!renderHtmlReport(report, language).includes('private-canary'));
  } finally { await removeOwned(root); }
});

for (const language of languages) test(`Blue requested with standard effective stays standard in saved JSON and ${language} HTML`, async () => {
  const report = fixture(), run = aiEngine(); report.engines.push(run);
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-language-'));
  try {
    const bundle = await saveReportBundle(report, defaults, root, async value => JSON.stringify(value), async value => value, language);
    const saved = JSON.parse(bundle.json).engines[0]; assert.equal(saved.accessProgramRequested, 'daybreak_blue'); assert.equal(saved.accessProgramEffective, 'standard'); assert.deepEqual(saved.aiExecution.programs, ['standard']);
    const label = language === 'ja' ? '実効プログラム' : 'Effective access program', value = language === 'ja' ? '通常（standard）' : 'Standard (standard)';
    assert.ok(bundle.html.includes(`<dt>${label}</dt><dd>${value}</dd>`)); assert.ok(!bundle.html.includes(`<dt>${label}</dt><dd>Blue</dd>`));
    assert.ok(!/Blue\s*(?:vs\.?|versus|対)\s*standard/i.test(bundle.html));
  } finally { await removeOwned(root); }
});

for (const language of languages) test(`unverified AI program is explained without requiring Blue in ${language}`, () => {
  const report = fixture(), run = aiEngine(); run.accessProgramEffective = 'unknown'; run.errors.push('ai_effective_program_unverified'); report.engines.push(run);
  const html = renderHtmlReport(report, language);
  assert.ok(html.includes(language === 'ja' ? '実効プログラムを確認できず' : 'effective access program could not be verified'));
  assert.ok(!html.includes(language === 'ja' ? '要求したBlueの実効適用' : 'Effective Blue access could not be verified'));
});

test('bundle refuses invalid locale before checks or persistence, and refuses English secret-check failures', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-language-')); let checks = 0;
  const check = async (payload: unknown) => { checks++; return JSON.stringify(payload); }, checkText = async (value: string) => { checks++; return value; };
  try {
    await assert.rejects(Reflect.apply(saveReportBundle, null, [fixture(), defaults, root, check, checkText, 'unsupported']), { code: 'invalid_report_language' });
    assert.equal(checks, 0); assert.deepEqual(await readdir(root), []);
    await assert.rejects(saveReportBundle(fixture(), defaults, root, check, async () => { throw new SafeError('output_secret_check_failed'); }, 'en'), { code: 'output_secret_check_failed' });
    assert.deepEqual(await readdir(root), []);
  } finally { await removeOwned(root); }
});

test('simultaneous language requests do not share mutable locale state or CSP', async () => {
  const report = fixture(), expected = languages.map(language => renderHtmlReport(report, language));
  const outputs = await Promise.all(Array.from({ length: 20 }, async (_, index) => renderHtmlReport(report, languages[index % 2])));
  outputs.forEach((value, index) => { assert.equal(value, expected[index % 2]); const csp = value.match(/http-equiv="Content-Security-Policy" content="([^"]*)"/); assert.ok(csp); assert.equal(csp[1], reportCsp.replaceAll("'", '&#39;')); });
});

test('CLI language validation rejects every unsupported command and invalid scan choice before input/runtime work', async () => {
  const config = path.resolve('.local/never-read-language-config.json'), target = path.resolve('.local/never-read-language-target'), file = path.resolve('.local/never-read-language-report.json');
  const unsupported = ['doctor', 'serve', 'runner-check', 'plan', 'ai-plan', 'plan-list', 'history', 'ci-check', 'dispositions', 'policy-check'];
  const supported = ['scan', 'ai-scan', 'resume', 'scan-list']; let runtimeReads = 0;
  const runtime = new Proxy({}, { get() { runtimeReads++; throw Error('runtime must not be read'); } });
  const invoke = async (args: string[]) => {
    const out: string[] = [], err: string[] = [], stdout = process.stdout.write, stderr = process.stderr.write;
    process.stdout.write = (value: string | Uint8Array) => { out.push(String(value)); return true; };
    process.stderr.write = (value: string | Uint8Array) => { err.push(String(value)); return true; };
    try { const exit = await Reflect.apply(main, null, [args, { ai: runtime }]); return { exit, stdout: out.join(''), error: JSON.parse(err.join('')).error }; }
    finally { process.stdout.write = stdout; process.stderr.write = stderr; }
  };
  for (const command of unsupported) { const args = [command, ...(['doctor', 'serve', 'runner-check'].includes(command) ? [] : [target]), '--config', config, '--report-language', 'en']; if (command === 'policy-check') args.push('--decisions', file);
    assert.deepEqual(await invoke(args), { exit: 4, stdout: '', error: 'invalid_command' }); }
  for (const command of supported) for (const value of ['', 'EN', '../en', '<script>']) {
    const args = [command, target, '--config', config, '--report-language', value]; if (command === 'ai-scan') args.push('--accept-plan', 'a'.repeat(64)); if (command === 'resume') args.push('--from', file);
    assert.deepEqual(await invoke(args), { exit: 4, stdout: '', error: 'invalid_report_language' });
  }
  assert.equal(runtimeReads, 0);
});
