import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { defaults } from '../src/config.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { createAdapters, emptyRun, normalizeCodex, normalizeGitleaks, normalizeOsv } from '../src/adapters.ts';
import { digest, hash, safeRelative } from '../src/safety.ts';
import { cleanEnvironment, execute } from '../src/process.ts';
import type { AdapterContext, EngineRun, Plan } from '../src/model.ts';
import { publicPackageFiles, verifyPackagePaths } from '../scripts/verify-public.ts';
import { scan } from '../src/controller.ts';
import { githubUrl } from '../src/github.ts';
import { contained } from './process-owner.ts';

const plan: Plan = {
  schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: path.resolve('test'), repoId: 'r', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 's', dirty: false,
  files: [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 10, sha256: 'c'.repeat(64) }, { path: 'package-lock.json', oid: 'b'.repeat(40), bytes: 20, sha256: 'd'.repeat(64) }],
  exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: ['package-lock.json'], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 },
};
const context: AdapterContext = { plan, config: defaults, snapshot: path.resolve('snapshot'), workspace: path.resolve('.'), signal: new AbortController().signal, secretsCleared: false };
function completed(): EngineRun[] { return plan.required.map(id => ({ ...emptyRun(id, context), execution: 'completed', coverage: 'analyzed' })); }
const secret = () => normalizeGitleaks([{ RuleID: 'test-rule', File: 'source.ts', StartLine: 1, Secret: 'never emit this', Match: 'nor this' }], context)[0];

test('decision table: all gates and precedence, never pass missing evidence', () => {
  assert.equal(decide(plan, completed()).gate, 'PASS');
  const omitted = { ...plan, exclusions: [{ path: 'image.png', reason: 'binary_content_unsupported' }] };
  assert.equal(decide(omitted, completed()).gate, 'INCOMPLETE');
  const omittedSecret = completed(); omittedSecret[0].findings.push(secret());
  assert.equal(decide(omitted, omittedSecret).gate, 'FAIL');
  assert.equal(decide(omitted, omittedSecret, ['unsafe_tree_path']).gate, 'ERROR');
  assert.equal(decide(plan, []).gate, 'INCOMPLETE');
  for (const execution of ['failed', 'cancelled', 'budget_exceeded', 'not_started'] as const) {
    const runs = completed(); runs[0].execution = execution;
    assert.equal(decide(plan, runs).gate, execution === 'failed' ? 'ERROR' : 'INCOMPLETE');
  }
  for (const coverage of ['unsupported', 'skipped', 'partial'] as const) {
    const runs = completed(); runs[0].coverage = coverage; assert.equal(decide(plan, runs).gate, 'INCOMPLETE');
  }
  const runs = completed(); runs[0].findings.push(secret());
  assert.equal(decide(plan, runs).gate, 'FAIL');
  assert.equal(decide(plan, runs, ['snapshot_changed']).gate, 'ERROR');
  runs[1].execution = 'failed'; assert.equal(decide(plan, runs).gate, 'ERROR');
  runs[1].execution = 'completed'; runs[0].findings[0] = { ...secret(), category: 'code', evidenceState: 'candidate' };
  assert.equal(decide(plan, runs).gate, 'REVIEW');
  runs[2].coverage = 'unsupported'; assert.equal(decide(plan, runs).gate, 'INCOMPLETE');
  assert.deepEqual(exitCodes, { PASS: 0, FAIL: 1, REVIEW: 2, INCOMPLETE: 3, ERROR: 4 });
});
test('normalization discards scanner free text and rejects unsafe locations', () => {
  assert.ok(!JSON.stringify(secret()).includes('never emit'));
  for (const File of ['../escape', '/etc/passwd', 'C:\\secret', 'unknown.ts']) assert.throws(() => normalizeGitleaks([{RuleID:'test', File, StartLine:1}], context));
  assert.throws(() => normalizeGitleaks({}, context));
  assert.throws(() => normalizeOsv({ results: [{ source: {path:'source.ts'}, packages:[] }] }, context));
});
test('OSV retains advisory identity and fixes without claiming exploitability', () => {
  const advisory = { id:'GHSA-test', aliases:['CVE-2026-12345'], database_specific:{severity:'HIGH'}, summary:'untrusted free text', affected:[{package:{name:'fixture',ecosystem:'npm'},ranges:[{events:[{introduced:'0'},{fixed:'2.0.0'}]}]}] };
  const findings = normalizeOsv({ results:[{ source:{path:'package-lock.json'}, packages:[{package:{name:'fixture',version:'1.0.0',ecosystem:'npm'},vulnerabilities:[advisory]}] }] }, context);
  assert.equal(findings.length, 1); assert.equal(findings[0].evidenceState, 'candidate');
  assert.deepEqual(findings[0].fixedVersions, ['2.0.0']); assert.equal(findings[0].reachability, 'unknown');
  assert.ok(!JSON.stringify(findings).includes('untrusted free text'));
});
test('Codex 0.5.1 document projection binds revision and scan ID; mock only', () => {
  const raw = { manifest:{scan:{id:'scan-one',target:{revision:plan.commit}}},findings:{documentType:'codex-security.findings',schemaVersion:'1.0',scanId:'scan-one',findings:[{findingId:'f1',ruleId:'cwe-79',severity:{level:'high'},confidence:{level:'medium'},locations:[{path:'source.ts',startLine:1}],summary:'untrusted model prose'}]} };
  assert.equal(normalizeCodex(raw, context)[0].confidence, 'medium');
  assert.ok(!JSON.stringify(normalizeCodex(raw, context)).includes('untrusted model prose'));
  raw.findings.scanId = 'different'; assert.throws(() => normalizeCodex(raw, context));
  raw.findings.scanId = 'scan-one'; raw.manifest.scan.target.revision = 'b'.repeat(40); assert.throws(() => normalizeCodex(raw, context));
});
test('path canonicalization rejects traversal, ADS, devices and ambiguous components', () => {
  for (const name of ['../x', 'a/../x', '/x', 'a\\b', 'x:y', 'CON', 'a/NUL.txt', 'x.', 'x ', 'a//b', 'a\u0000b']) assert.throws(() => safeRelative(name));
  assert.equal(safeRelative('日本語/a.ts'), '日本語/a.ts');
});
test('AI is impossible to activate by configured executable or secrets-cleared flag', async () => {
  const input = { ...context, secretsCleared: true, config: { ...defaults, tools: {'codex-security': {path:'/does-not-exist', sha256:'0'.repeat(64), version:'0.5.1'}} } };
  const run = await createAdapters()[2].run(input);
  assert.equal(run.execution, 'not_started'); assert.equal(run.usage.calls, 0); assert.ok(run.errors.includes('isolation_unverified'));
  assert.equal((await createAdapters()[0].run(context)).execution, 'not_started');
});
test('process environment drops credentials and enforces timeout/output/cancellation/hash', async () => {
  assert.equal(cleanEnvironment('/private').OPENAI_API_KEY, undefined);
  assert.equal(cleanEnvironment('/private').PATH, undefined);
  const home = await mkdtemp(path.join(tmpdir(), 'scanmux-test-'));
  test.after(() => removeTempDir(home));
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const options = { cwd: home, home, timeoutMs: 1000, maxOutputBytes: 1024 };
  try {
    await contained(async () => {
      assert.equal((await execute(tool, ['-e', 'console.log("ok")'], options)).code, 0);
      assert.equal((await execute(tool, ['-e', 'setInterval(()=>{},1000)'], { ...options, timeoutMs: 100 })).reason, 'timeout');
      assert.equal((await execute(tool, ['-e', 'console.log("x".repeat(2048));setInterval(()=>{},1000)'], options)).reason, 'output_limit');
      assert.equal((await execute(tool, [], { ...options, signal: AbortSignal.abort() })).reason, 'cancelled');
      await assert.rejects(execute({ ...tool, sha256: '0'.repeat(64) }, [], options), /tool_digest_mismatch/);
    });
  } finally { await removeTempDirStrict(home, { recursive: true, force: true }); }
});
test('GitHub URL admission rejects alternate destinations, credentials, refs and ambiguous encodings', () => {
  assert.equal(githubUrl('https://github.com/octocat/Hello-World.git/'), 'https://github.com/octocat/Hello-World');
  for (const url of ['http://github.com/o/r', 'https://github.com.evil/o/r', 'https://evil/github.com/o/r',
    'https://u:p@github.com/o/r', 'https://github.com:443/o/r', 'https://github.com/o/r?x=1',
    'https://github.com/o/r#main', 'https://github.com/o/r/tree/main', 'https://github.com/o/%2e%2e',
    'https://github.com/o/..', 'file:///repo', 'git@github.com:o/r', ' https://github.com/o/r']) {
    assert.throws(() => githubUrl(url), /public_github_url_required/);
  }
});
test('public package gate rejects stray and internal files, including under src', () => {
  verifyPackagePaths(publicPackageFiles);
  for (const extra of ['src/private-notes.md', 'private/spec.docx', '.local/config.json', 'docs/private-plan.md']) assert.throws(() => verifyPackagePaths([...publicPackageFiles, extra]));
});
test('controller rejects modified plan or policy before starting any adapter', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-test-'));
  test.after(() => removeTempDir(workspace));
  try {
    const original = { ...plan, planHash: digest({ ...plan, planHash: '' }) };
    const changed = { ...original, blockers: ['changed'] };
    const result = await scan(changed, defaults, workspace, new AbortController().signal);
    assert.equal(result.gate, 'ERROR'); assert.deepEqual(result.engines, []); assert.deepEqual(result.integrityErrors, ['plan_integrity']);
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
});
