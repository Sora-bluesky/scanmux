import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { normalizeCodex, normalizeProjectedCodex, emptyRun } from '../src/adapters.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { defaults } from '../src/config.ts';
import { groupFindings, renderHtmlReport } from '../src/html-report.ts';
import type { AdapterContext, CodexFinding, Plan, Report } from '../src/model.ts';
import { saveReportBundle } from '../src/output.ts';
import { renderSarifReports } from '../src/sarif-report.ts';
import { digest, hash, SafeError } from '../src/safety.ts';

const source = [
  'const prefix = "echo ";',
  '',
  'function commandFor(input) {',
  '  return prefix + input;',
  '}',
  'function handler(input) {',
  '  const command = commandFor(input);',
  '  execute(command);',
  '}',
].join('\n');
const commit = 'a'.repeat(40);

async function fixture(t: TestContext, content = source + '\n'): Promise<AdapterContext> {
  const directory = await mkdtemp(path.join(process.cwd(), 'codex-line-range-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, 'source.ts'), content);
  const files = [{ path: 'source.ts', oid: 'b'.repeat(40), bytes: Buffer.byteLength(content), sha256: hash(content) }];
  const plan: Plan = {
    schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: directory, repoId: 'fixture', commit,
    treeHash: 'c'.repeat(40), snapshotHash: digest(files), dirty: false, files, exclusions: [], blockers: [],
    languages: ['JS/TS'], lockfiles: [], required: ['codex-security'], policyHash: digest(defaults), planHash: '',
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 },
  };
  plan.planHash = digest({ ...plan, planHash: '' });
  return { plan, config: defaults, snapshot: directory, workspace: directory, signal: new AbortController().signal, secretsCleared: true };
}

function raw(position: Record<string, unknown> = { path: 'source.ts', startLine: 6 }) {
  return { manifest: { scan: { id: 'example-scan', target: { revision: commit } } }, findings: {
    documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'example-scan', findings: [{
      findingId: 'finding-one', ruleId: 'command-injection', severity: { level: 'high' }, confidence: { level: 'medium' }, locations: [position],
    }],
  } };
}

function reportFor(context: AdapterContext, findings: CodexFinding[]): Report {
  const run = emptyRun('codex-security', context);
  Object.assign(run, { execution: 'completed', coverage: 'analyzed', findings, exitCode: 1 });
  return {
    schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', plan: context.plan,
    runner: { platform: 'win32', node: 'v24.16.0', imageDigest: null, isolation: 'local-static-only' },
    startedAt: run.startedAt, endedAt: run.endedAt, engines: [run], executionState: 'completed', coverageState: 'complete',
    gate: 'REVIEW', exitCode: 2, reasons: [], integrityErrors: [],
  };
}

const sarifResult = (report: Report) => JSON.parse(renderSarifReports(report, defaults.maxOutputBytes)[0].text).runs[0].results[0];
const invalidLine = (error: unknown) => error instanceof SafeError && error.code === 'invalid_line';

test('Codex reported range survives saved JSON, SARIF and screen/print HTML without moving its start', async t => {
  const context = await fixture(t), input = raw({ path: 'source.ts', startLine: 6, endLine: 8 }), before = structuredClone(input);
  const findings = normalizeCodex(input, context), report = reportFor(context, findings);
  const bundle = await saveReportBundle(report, defaults, context.workspace, async value => JSON.stringify(value), async value => value);
  const saved = JSON.parse(await readFile(bundle.destination, 'utf8')).engines[0].findings[0];
  assert.equal(saved.line, 6); assert.equal(saved.endLine, 8);
  const sarif = JSON.parse(await readFile(bundle.sarif[0].destination, 'utf8')).runs[0].results[0];
  assert.deepEqual(sarif.locations[0].physicalLocation.region, { startLine: 6, endLine: 8 });
  assert.equal(sarif.partialFingerprints['scanmux/v1'], findings[0].fingerprint);
  assert.equal(await readFile(bundle.htmlDestination, 'utf8'), bundle.html);
  for (const language of ['ja', 'en'] as const) assert.equal(renderHtmlReport(report, language).match(/source\.ts[^<]*6–8/g)?.length, 2);
  assert.deepEqual(input, before);
});

test('missing and null Codex end lines keep the previous JSON and single-line display', async t => {
  const context = await fixture(t), missing = normalizeCodex(raw(), context);
  for (const position of [{ path: 'source.ts', startLine: 6 }, { path: 'source.ts', startLine: 6, endLine: null }]) {
    const findings = normalizeCodex(raw(position), context), report = reportFor(context, findings);
    assert.deepEqual(findings, missing);
    assert.equal(findings[0].endLine ?? null, null);
    assert.equal(Object.hasOwn(JSON.parse(JSON.stringify(report)).engines[0].findings[0], 'endLine'), false);
    assert.deepEqual(sarifResult(report).locations[0].physicalLocation.region, { startLine: 6 });
    for (const language of ['ja', 'en'] as const) {
      const html = renderHtmlReport(report, language);
      assert.equal(html.match(/source\.ts[^<]*6/g)?.length, 2);
      assert.ok(!html.includes('6–'));
    }
  }
});

test('Codex rejects reversed, nonpositive, noninteger and unsafe end lines', async t => {
  const context = await fixture(t);
  for (const endLine of [5, 0, -1, 6.5, Number.MAX_SAFE_INTEGER + 1, '8', true]) {
    assert.throws(() => normalizeCodex(raw({ path: 'source.ts', startLine: 6, endLine }), context), invalidLine, String(endLine));
  }
  for (const startLine of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '6']) {
    assert.throws(() => normalizeCodex(raw({ path: 'source.ts', startLine, endLine: 8 }), context), invalidLine);
  }
});

test('Codex preserves reported lines beyond file content, including empty files', async t => {
  for (const content of [source + '\n', '']) {
    const context = await fixture(t, content);
    for (const position of [
      { path: 'source.ts', startLine: 6, endLine: 10 },
      { path: 'source.ts', startLine: 10 },
      { path: 'source.ts', startLine: 10, endLine: Number.MAX_SAFE_INTEGER },
    ]) {
      const finding = normalizeCodex(raw(position), context)[0];
      assert.equal(finding.line, position.startLine); assert.equal(finding.endLine, position.endLine);
    }
  }
});

test('Codex keeps valid ranges without a local snapshot', async t => {
  const context = await fixture(t);
  for (const snapshot of [undefined, '', path.join(context.workspace, 'missing-snapshot')]) {
    const input = { plan: context.plan, snapshot };
    const finding = normalizeCodex(raw({ path: 'source.ts', startLine: 6, endLine: 8 }), input)[0];
    assert.equal(finding.line, 6); assert.equal(finding.endLine, 8);
    assert.throws(() => normalizeCodex(raw({ path: 'source.ts', startLine: 6, endLine: 5 }), input), invalidLine);
  }
});

test('Codex finding identity ignores endLine while display place counts distinguish ranges', async t => {
  const context = await fixture(t), original = normalizeCodex(raw(), context)[0];
  const findings = [6, 8, 9].map(endLine => normalizeCodex(raw({ path: 'source.ts', startLine: 6, endLine }), context)[0]);
  for (const finding of findings) {
    const { endLine, ...unchanged } = finding;
    assert.deepEqual(unchanged, original);
    assert.equal(sarifResult(reportFor(context, [finding])).partialFingerprints['scanmux/v1'], original.fingerprint);
  }
  const group = groupFindings([findings[1], findings[1], findings[2]])[0];
  assert.equal(group.items.length, 3); assert.equal(group.places, 2);
});

test('projected Codex normalization retains and validates the same reported range', async t => {
  const context = await fixture(t), input = raw({ path: 'source.ts', startLine: 6, endLine: 10 });
  const mapping = {
    schema: 'scanmux.sdk-projection/v1', originalCommit: context.plan.commit, originalTree: context.plan.treeHash,
    planHash: context.plan.planHash, snapshotHash: context.plan.snapshotHash, projectionScope: 'accepted_files_only', projectedMode: '100644',
    derivedRevision: 'd'.repeat(40), manifest: context.plan.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })),
  };
  const expected = normalizeCodex(input, context);
  input.manifest.scan.target.revision = mapping.derivedRevision;
  assert.deepEqual(normalizeProjectedCodex(input, mapping, context), expected);
  for (const endLine of [5, 0, 6.5, Number.MAX_SAFE_INTEGER + 1]) {
    input.findings.findings[0].locations[0].endLine = endLine;
    assert.throws(() => normalizeProjectedCodex(input, mapping, context), invalidLine);
  }
});
