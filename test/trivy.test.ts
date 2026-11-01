import { registerJobDiskRoot, releaseJobDiskRoot } from '../src/job-disk.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { stripTypeScriptTypes, syncBuiltinESMExports } from 'node:module';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { defaults, loadConfig } from '../src/config.ts';
import { inventoryTrivy } from '../src/trivy-plan.ts';
import { normalizeTrivy, probeTrivy, TrivyAdapter, trivyArguments, trivyEnvironment } from '../src/trivy-adapter.ts';
import type { AdapterContext, Config, PlanV3 } from '../src/model.ts';
import { digest, hash, SafeError } from '../src/safety.ts';
import { CopyBudget, JobDiskCopyLimitError, scopedCopyBudget } from '../src/copy-budget.ts';
import { contained, testProcessOwner } from './process-owner.ts';
import { sourceCleanupFor } from '../src/source-cleanup.ts';

const fixtureRoot = path.resolve('test/fixtures/trivy-input');
const fixture = JSON.parse(await readFile('test/fixtures/trivy-offline.json', 'utf8'));
async function fileMap(directory: string): Promise<Map<string, Buffer>> {
  const files = new Map<string, Buffer>();
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) if (entry.isFile()) {
    const full = path.join(entry.parentPath, entry.name), name = path.relative(directory, full).split(path.sep).join('/');
    files.set(name, await readFile(full));
  }
  return files;
}
async function contextFor(snapshot = fixtureRoot, config: Config = defaults): Promise<AdapterContext> {
  const files = await fileMap(snapshot);
  const plan: PlanV3 = { schema: 'scanmux.plan/v3', advisoryCatalog: { ...catalogIdentity }, root: snapshot, repoId: 'fixture',
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest([...files]), dirty: false,
    files: [...files].map(([name, bytes]) => ({ path: name, oid: 'c'.repeat(40), bytes: bytes.length, sha256: hash(bytes) })),
    exclusions: [], blockers: [], languages: [], lockfiles: [], trivy: inventoryTrivy(files),
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories', 'trivy'], policyHash: digest(config), planHash: '',
    network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest({ ...plan, planHash: '' });
  return { plan, config, snapshot, workspace: path.resolve('.local'), signal: new AbortController().signal, secretsCleared: false };
}
const context = await contextFor();
const copy = () => structuredClone(fixture);
function firstFail(raw: any) { return raw.Results.find((result: any) => result.Type === 'dockerfile').Misconfigurations.find((row: any) => row.Status === 'FAIL'); }

test('full sanitized offline report retains 52 candidates and missing Kubernetes input is partial', () => {
  const normalized = normalizeTrivy(fixture, context);
  assert.equal(normalized.findings.length, 52);
  assert.deepEqual(Object.fromEntries(['docker', 'kubernetes', 'terraform', 'cloudformation', 'helm'].map(prefix =>
    [prefix, normalized.findings.filter(finding => finding.file?.startsWith(prefix + '/')).length])),
  { docker: 2, kubernetes: 17, terraform: 8, cloudformation: 8, helm: 17 });
  assert.equal(normalized.coverage.state, 'partial');
  assert.ok(normalized.coverage.state === 'partial' && normalized.coverage.receipts.some(receipt => receipt.unit === 'kubernetes:kubernetes/broken.yaml' && receipt.state === 'unresolved'));
  const text = JSON.stringify(normalized);
  for (const secret of ['C:\\Users\\', 'No public access block', 'BucketName:', 'trivy-sandbox-unencrypted-demo', 'References', 'Highlighted']) assert.ok(!text.includes(secret));
  assert.ok(normalized.findings.every(finding => finding.evidenceState === 'candidate' && finding.confidence === 'unknown'));
  assert.ok(normalized.findings.filter(finding => finding.file?.startsWith('helm/')).every(finding => finding.line === null && finding.endLine === null), 'rendered Helm lines are never presented as template lines');
});

test('all planned file receipts, including non-failures, are required for analyzed coverage', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'trivy-parser-'));
  try {
    for (const [name, bytes] of await fileMap(fixtureRoot)) if (name !== 'kubernetes/broken.yaml') {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), bytes);
    }
    const clean = await contextFor(root);
    assert.equal(normalizeTrivy(fixture, clean).coverage.state, 'analyzed');
    const noFailures = copy();
    for (const result of noFailures.Results) {
      result.MisconfSummary.Successes += result.MisconfSummary.Failures; result.MisconfSummary.Failures = 0;
      for (const row of result.Misconfigurations) row.Status = 'PASS';
    }
    assert.deepEqual(normalizeTrivy(noFailures, clean).findings, []);
    assert.equal(normalizeTrivy(noFailures, clean).coverage.state, 'analyzed');
    for (const name of ['terraform/broken.tf', 'helm/demo/templates/broken.yaml']) {
      await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), 'broken: [\n');
    }
    const siblings = normalizeTrivy(fixture, await contextFor(root));
    assert.equal(siblings.coverage.state, 'partial');
    assert.ok(siblings.coverage.state === 'partial' && ['terraform:terraform', 'helm:helm/demo'].every(unit =>
      siblings.coverage.state === 'partial' && siblings.coverage.receipts.some(receipt => receipt.unit === unit && receipt.state === 'unresolved')));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('inventory recognizes five formats from accepted bytes and marks unknown and external inputs unresolved', () => {
  assert.deepEqual([...new Set(context.plan.trivy!.inputs.map(unit => unit.kind))].sort(), ['cloudformation', 'dockerfile', 'helm', 'kubernetes', 'terraform']);
  const inventory = inventoryTrivy(new Map([
    ['Dockerfile', Buffer.from('FROM alpine\n')], ['main.tf', Buffer.from('module "external" { source = "https://example.invalid" }')],
    ['unknown.yaml', Buffer.from('broken: [')], ['invalid.json', Buffer.from([0xff])],
  ]));
  assert.ok(inventory.inputs.find(unit => unit.kind === 'terraform')?.unresolved);
  assert.equal(inventory.inputs.filter(unit => unit.kind === 'unresolved').length, 2);
  assert.equal(inventoryTrivy(new Map([['package.json', Buffer.from('{"name":"fixture"}')]])).inputs.length, 0);
});

test('inventory plans Containerfiles and leaves compose and CI pipelines out, but not lookalikes', () => {
  const services = Buffer.from('services:\n  web:\n    image: nginx\n'), pipeline = Buffer.from('on: push\njobs: {}\n');
  const inventory = inventoryTrivy(new Map([
    ['Containerfile', Buffer.from('FROM alpine\n')], ['build/Containerfile.dev', Buffer.from('FROM alpine\n')], ['build/app.containerfile', Buffer.from('FROM alpine\n')],
    ['docker-compose.yml', services], ['deploy/compose.prod.yaml', services], ['.github/workflows/ci.yml', pipeline], ['.gitlab-ci.yml', Buffer.from('build:\n  script: make\n')],
    ['.circleci/config.yml', pipeline], ['azure-pipelines.yml', pipeline],
    // A compose name without services, a workflow outside .github/workflows and a broken compose stay unresolved.
    ['compose.yaml', Buffer.from('volumes: {}\n')], ['ci/workflows/ci.yml', pipeline], ['docker-compose.override.yml', Buffer.from([0xff])],
  ]));
  assert.deepEqual(inventory.inputs.map(unit => unit.key), ['dockerfile:Containerfile', 'dockerfile:build/Containerfile.dev', 'dockerfile:build/app.containerfile',
    'unresolved:ci/workflows/ci.yml', 'unresolved:compose.yaml', 'unresolved:docker-compose.override.yml']);
  // Kubernetes manifests named like compose files keep their own kind.
  assert.equal(inventoryTrivy(new Map([['compose.yaml', Buffer.from('apiVersion: v1\nkind: Pod\nservices: []\n')]])).inputs[0].kind, 'kubernetes');
});

test('undecodable template candidates cannot disappear behind a successful Dockerfile', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'trivy-template-'));
  try {
    await writeFile(path.join(root, 'Dockerfile'), await readFile(path.join(fixtureRoot, 'docker/Dockerfile')));
    await writeFile(path.join(root, 'bad.template'), Buffer.concat([Buffer.from('Resources:\n# '), Buffer.from([0xff])]));
    const raw = copy(); raw.Results = raw.Results.filter((result: any) => result.Type === 'dockerfile');
    raw.Results[0].Target = 'Dockerfile';
    const coverage = normalizeTrivy(raw, await contextFor(root)).coverage;
    assert.equal(coverage.state, 'partial');
    assert.ok(coverage.state === 'partial' && coverage.receipts.some(receipt => receipt.unit === 'unresolved:bad.template' && receipt.state === 'unresolved'));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('unit ordering uses code units for stable inventory hashes across ICU implementations', () => {
  const inventory = inventoryTrivy(new Map(['z', 'a', 'A', 'é', '_'].map(name => [name + '.tf', Buffer.from('resource "x" "y" {}\n')])));
  assert.deepEqual(inventory.inputs[0].files, ['A.tf', '_.tf', 'a.tf', 'z.tf', 'é.tf']);
  const dockerfiles = inventoryTrivy(new Map(['z', 'a', 'A', 'é', '_'].map(name => [name + '/Dockerfile', Buffer.from('FROM alpine\n')])));
  assert.deepEqual(dockerfiles.inputs.map(unit => unit.key), ['A', '_', 'a', 'z', 'é'].map(name => `dockerfile:${name}/Dockerfile`));
});

for (const failure of ['empty', 'parse-error', 'empty-parse-error'] as const) test(`${failure} results retain their incomplete receipt even beside completed targets`, () => {
  for (const duplicateFirst of [null, true, false]) {
    const raw = copy(), result = raw.Results.find((result: any) => result.Type === 'dockerfile');
    const good = structuredClone(result);
    if (failure !== 'parse-error') { result.Misconfigurations = []; result.MisconfSummary = { Successes: 0, Failures: 0, Exceptions: 0 }; }
    if (failure !== 'empty') result.Errors = ['synthetic parse failure'];
    if (duplicateFirst !== null) raw.Results.splice(duplicateFirst ? 0 : raw.Results.length, 0, good);
    const coverage = normalizeTrivy(raw, context).coverage;
    assert.equal(coverage.state, 'partial');
    assert.ok(coverage.state === 'partial');
    assert.equal(coverage.receipts.find(receipt => receipt.unit === 'dockerfile:docker/Dockerfile')?.state, failure === 'empty' ? 'unresolved' : 'parse_failed');
    assert.equal(coverage.receipts.find(receipt => receipt.unit === 'terraform:terraform')?.state, 'analyzed');
  }
});

test('a successful Terraform file cannot complete an empty or parse-failed sibling in its module', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'trivy-receipts-'));
  try {
    await mkdir(path.join(root, 'terraform'));
    const bytes = await readFile(path.join(fixtureRoot, 'terraform/main.tf'));
    for (const name of ['main.tf', 'sibling.tf']) await writeFile(path.join(root, 'terraform', name), bytes);
    const module = await contextFor(root);
    for (const failure of ['empty', 'parse-error']) {
      const raw = copy(); raw.Results = raw.Results.filter((result: any) => result.Type === 'terraform');
      const sibling = structuredClone(raw.Results[0]); sibling.Target = 'terraform/sibling.tf';
      raw.Results.push(sibling);
      assert.equal(normalizeTrivy(raw, module).coverage.state, 'analyzed');
      if (failure === 'empty') { sibling.Misconfigurations = []; sibling.MisconfSummary = { Successes: 0, Failures: 0, Exceptions: 0 }; }
      else sibling.Errors = ['synthetic parse error'];
      const coverage = normalizeTrivy(raw, module).coverage;
      assert.ok(coverage.state === 'partial');
      assert.deepEqual(coverage.receipts, [{ unit: 'terraform:terraform', state: failure === 'empty' ? 'unresolved' : 'parse_failed' }]);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('ordinary config candidates retain their classification inside root and nested Helm charts', async () => {
  const candidates = new Map([...await fileMap(fixtureRoot)].filter(([name]) => !name.startsWith('helm/')));
  candidates.set('unknown.yaml', Buffer.from('broken: [\n'));
  candidates.set('external/main.tf', Buffer.from('module "external" { source = "./other" }\n'));
  candidates.set('unknown.hcl', Buffer.from('broken {\n'));
  candidates.set('invalid.yaml', Buffer.from([0xff]));
  const outside = inventoryTrivy(candidates);
  for (const charts of [['.'], ['.', 'charts/nested']]) {
    const deepest = charts.at(-1)!, prefix = deepest === '.' ? '' : deepest + '/';
    const files = new Map([...candidates].map(([name, bytes]) => [prefix + name, bytes]));
    for (const chart of charts) {
      const root = chart === '.' ? '' : chart + '/';
      files.set(root + 'Chart.yaml', Buffer.from('apiVersion: v2\nname: demo\nversion: 0.1.0\n'));
      files.set(root + 'values.yaml', Buffer.from('kind: configuration-value\n'));
      files.set(root + 'values.schema.json', Buffer.from('{"properties":{"Resources":{}}}\n'));
      files.set(root + 'templates/deployment.yaml', Buffer.from('kind: Deployment\n'));
    }
    const inside = inventoryTrivy(files);
    assert.equal(inside.inputs.length, outside.inputs.length + charts.length);
    for (const unit of outside.inputs) {
      const names = unit.files.map(file => prefix + file);
      const relocated = inside.inputs.find(input => input.files.includes(names[0]));
      assert.ok(relocated, `${deepest}: ${unit.key} must not disappear`);
      assert.deepEqual([relocated.kind, relocated.unresolved, relocated.files], [unit.kind, unit.unresolved, names]);
    }
  }
});

test('successful Helm receipts cannot complete omitted sibling configs under root or nested charts', async () => {
  const sources = await fileMap(fixtureRoot);
  for (const charts of [['.'], ['.', 'charts/nested']]) {
    const root = await mkdtemp(path.join(tmpdir(), 'trivy-chart-'));
    try {
      const raw = copy(); raw.Results = [];
      for (const chart of charts) {
        const prefix = chart === '.' ? '' : chart + '/';
        for (const [source, target] of [['Chart.yaml', 'Chart.yaml'], ['values.yaml', 'values.yaml'], ['templates/deployment.yaml', 'templates/deployment.yaml']]) {
          const destination = path.join(root, prefix + target);
          await mkdir(path.dirname(destination), { recursive: true });
          await writeFile(destination, sources.get('helm/demo/' + source)!);
        }
        const result = structuredClone(fixture.Results.find((result: any) => result.Type === 'helm'));
        result.Target = prefix + 'templates/deployment.yaml'; raw.Results.push(result);
      }
      assert.equal(normalizeTrivy(raw, await contextFor(root)).coverage.state, 'analyzed', 'ordinary chart metadata needs no independent Result');
      const deepest = charts.at(-1)!, prefix = deepest === '.' ? '' : deepest + '/';
      for (const [name, bytes] of sources) if (!name.startsWith('helm/')) {
        const destination = path.join(root, prefix + name);
        await mkdir(path.dirname(destination), { recursive: true }); await writeFile(destination, bytes);
      }
      const missing = await contextFor(root), coverage = normalizeTrivy(raw, missing).coverage;
      assert.equal(coverage.state, 'partial');
      assert.ok(coverage.state === 'partial' && coverage.reasons.includes('trivy_input_result_missing'));
      for (const unit of missing.plan.trivy!.inputs.filter(unit => unit.kind !== 'helm')) {
        assert.ok(coverage.state === 'partial' && coverage.receipts.some(receipt => receipt.unit === unit.key && receipt.state === 'unresolved'), unit.key);
      }
      assert.ok(coverage.state === 'partial' && coverage.receipts.some(receipt => receipt.unit === `kubernetes:${prefix}kubernetes/broken.yaml` && receipt.state === 'unresolved'));
    } finally { await rm(root, { recursive: true, force: true }); }
  }
});

test('parser rejects schema, version, result type, status, summary and conflicting observations', () => {
  for (const mutate of [
    (raw: any) => { raw.SchemaVersion = 3; }, (raw: any) => { raw.Trivy.Version = '9.0.0'; },
    (raw: any) => { raw.ArtifactType = 'container_image'; }, (raw: any) => { raw.Results[0].Class = 'os-pkgs'; },
    (raw: any) => { raw.Results[0].Type = 'unknown'; }, (raw: any) => { firstFail(raw).Status = 'SKIP'; },
    (raw: any) => { delete firstFail(raw).Status; }, (raw: any) => { raw.Results[0].MisconfSummary.Failures++; },
    (raw: any) => { firstFail(raw).ID = 'secret\nvalue'; }, (raw: any) => { firstFail(raw).Namespace = '../bad value'; },
    (raw: any) => { const row = structuredClone(firstFail(raw)); row.Severity = 'LOW'; raw.Results.find((r: any) => r.Type === 'dockerfile').Misconfigurations.push(row); },
  ]) { const raw = copy(); mutate(raw); assert.throws(() => normalizeTrivy(raw, context)); }
  const duplicate = copy(); duplicate.Results.push(structuredClone(duplicate.Results[0]));
  assert.equal(normalizeTrivy(duplicate, context).findings.length, 52);
  const rendered = copy(), helm = rendered.Results.find((result: any) => result.Type === 'helm');
  const sibling = structuredClone(helm.Misconfigurations.find((row: any) => row.Status === 'FAIL'));
  sibling.CauseMetadata.StartLine += 20; sibling.CauseMetadata.EndLine += 20;
  helm.Misconfigurations.push(sibling); helm.MisconfSummary.Failures++;
  assert.equal(normalizeTrivy(rendered, context).findings.length, 53, 'distinct rendered resources retain distinct identities despite unknown source lines');
  sibling.CauseMetadata.StartLine = -1;
  assert.throws(() => normalizeTrivy(rendered, context), /invalid_line/);
});

test('parser rejects every target escape and invalid actual source line range', () => {
  for (const target of ['../escape', 'C:/elsewhere/private', '/etc/passwd', 'a/../docker/Dockerfile', 'docker/Dockerfile:stream', '\\\\server\\file']) {
    const raw = copy(); raw.Results[0].Target = target; assert.throws(() => normalizeTrivy(raw, context));
  }
  // An in-snapshot target outside the plan makes the run partial instead of failing it, and its rows are not reported.
  const unplanned = copy(); unplanned.Results[0].Target = 'unknown.yaml';
  const dropped = unplanned.Results[0].Misconfigurations.filter((row: any) => row.Status === 'FAIL').length;
  const partial = normalizeTrivy(unplanned, context);
  assert.equal(partial.findings.length, 52 - dropped);
  assert.ok(partial.coverage.state === 'partial' && partial.coverage.reasons.includes('trivy_target_not_planned') && partial.coverage.reasons.includes('trivy_input_result_missing'));
  assert.ok(partial.findings.every(finding => finding.file !== 'unknown.yaml'));
  for (const cause of [{ StartLine: 0 }, { StartLine: -1 }, { StartLine: 2.5 }, { StartLine: 3, EndLine: 2 }, { StartLine: 1000000, EndLine: 1000000 }, { EndLine: 2 }]) {
    const raw = copy(); firstFail(raw).CauseMetadata = cause; assert.throws(() => normalizeTrivy(raw, context));
  }
  const absolute = copy(); absolute.Results[0].Target = path.join(context.snapshot, absolute.Results[0].Target);
  assert.equal(normalizeTrivy(absolute, context).findings.length, 52);
});

test('unknown positions and severities remain explicit; exceptions and diagnostics prevent analyzed', () => {
  for (const [input, expected] of [['LOW', 'low'], ['MEDIUM', 'medium'], ['HIGH', 'high'], ['CRITICAL', 'critical'], ['UNKNOWN', 'unknown'], [undefined, 'unknown']]) {
    const sample = copy(); firstFail(sample).Severity = input;
    assert.equal(normalizeTrivy(sample, context).findings.find(finding => finding.file === 'docker/Dockerfile' && finding.originIds[0] === firstFail(sample).ID)?.severity, expected);
  }
  const raw = copy(), row = firstFail(raw); delete row.CauseMetadata; row.Severity = 'NEW-SEVERITY';
  const finding = normalizeTrivy(raw, context).findings.find(finding => finding.originIds[0] === row.ID && finding.file === 'docker/Dockerfile')!;
  assert.equal(finding.line, null); assert.equal(finding.endLine, null); assert.equal(finding.severity, 'unknown');
  row.Status = 'EXCEPTION'; const summary = raw.Results.find((r: any) => r.Type === 'dockerfile').MisconfSummary; summary.Failures--; summary.Exceptions = 1;
  const excluded = normalizeTrivy(raw, context);
  assert.equal(excluded.findings.length, 51);
  assert.ok(excluded.coverage.state === 'partial' && excluded.coverage.receipts.some(receipt => receipt.state === 'excluded'));
  assert.throws(() => normalizeTrivy(fixture, context, Buffer.from([0xff])));
  const diagnosed = normalizeTrivy(fixture, context, Buffer.from('ERROR failed to parse synthetic input\n'));
  assert.ok(diagnosed.coverage.state === 'partial' && diagnosed.coverage.reasons.includes('trivy_scanner_diagnostics'));
  const embedded = normalizeTrivy(fixture, context, Buffer.from('ERROR\t[misconfig] Falling back to embedded checks\terr="cache does not exist"\n'));
  assert.ok(embedded.coverage.state === 'partial' && !embedded.coverage.reasons.includes('trivy_scanner_diagnostics'));
});

test('plan bytes and inventory cannot be replaced with scanner output', () => {
  const changed = { ...context, plan: structuredClone(context.plan) };
  changed.plan.files[0].sha256 = '0'.repeat(64);
  assert.throws(() => normalizeTrivy(fixture, changed), /snapshot_changed/);
  const omitted = { ...context, plan: { ...context.plan, trivy: { ...context.plan.trivy!, inputs: context.plan.trivy!.inputs.slice(1) } } as PlanV3 };
  assert.throws(() => normalizeTrivy(fixture, omitted), /trivy_plan_mismatch/);
  const emptyReport = copy(); delete emptyReport.Results;
  assert.equal(normalizeTrivy(emptyReport, context).coverage.state, 'partial');
});

test('fixed argv and clean environment select only the five embedded scanners', () => {
  const work = path.resolve('private/W'), args = trivyArguments(context.snapshot, work), env = trivyEnvironment(work);
  assert.deepEqual(args, ['config', '--config', path.join(work, 'trivy.yaml'), '--ignorefile', path.join(work, 'empty.ignore'), '--cache-dir', path.join(work, 'cache'),
    '--skip-check-update', '--skip-version-check', '--disable-telemetry', '--misconfig-scanners', 'dockerfile,kubernetes,terraform,cloudformation,helm',
    '--include-non-failures', '--exit-code', '0', '--format', 'json', context.snapshot]);
  for (const key of ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TMP', 'TEMP', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME']) assert.ok(env[key].startsWith(work));
  assert.ok(!Object.keys(env).some(key => /proxy|token|trivy_/i.test(key)));
});

test('missing boundary and incompatible pin never fall back to ordinary execution', async () => {
  const config = { ...defaults, tools: { trivy: { path: 'nonexistent.exe', sha256: '0'.repeat(64), version: '0.76.1' } } };
  const run = await new TrivyAdapter().run({ ...context, config });
  assert.equal(run.execution, 'not_started'); assert.equal(run.coverage, 'unsupported');
  assert.ok(run.errors.includes(process.platform === 'win32' ? 'process_appcontainer_owner_unavailable' : 'process_appcontainer_unsupported_platform'));
  const wrong = await new TrivyAdapter().run({ ...context, config: { ...config, tools: { trivy: { ...config.tools.trivy, version: '0.1.0' } } } });
  assert.ok(wrong.errors.includes('unsupported_tool_version'));
  const adapter = new TrivyAdapter(); adapter.cancel(); assert.equal((await adapter.run(context)).execution, 'cancelled');
});

for (const reason of ['AbortError', 'TimeoutError']) test(`copy budget: ${reason} during Trivy copy matches unkeyed cancellation`, { skip: process.platform !== 'win32' }, async t => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'trivy-copy-cancel-'));
  const write = fsPromises.writeFile, stream = fs.createReadStream;
  let controller: AbortController, interrupted = false;
  try {
    const file = path.join(workspace, 'tool.exe'), bytes = Buffer.alloc(128 * 1024, 1);
    await writeFile(file, bytes);
    const config: Config = { ...defaults, tools: { trivy: { path: file, sha256: hash(bytes), version: '0.76.1' } } };
    const base = { ...await contextFor(fixtureRoot, config), workspace };
    const abort = () => { interrupted = true; controller.abort(new DOMException('scan interrupted', reason)); };
    t.mock.method(fsPromises, 'writeFile', async (...args: Parameters<typeof write>) => {
      await write(...args);
      if (String(args[0]).endsWith(`${path.sep}trivy.exe`)) abort();
    });
    t.mock.method(fs, 'createReadStream', (...args: Parameters<typeof stream>) => {
      const input = stream(...args);
      if (args[0] === file) input.once('data', abort);
      return input;
    });
    syncBuiltinESMExports();
    await contained(async () => {
      for (const invoke of [probeTrivy, (ctx: AdapterContext) => new TrivyAdapter().run(ctx)]) {
        const results = [];
        for (const budgeted of [false, true]) {
          controller = new AbortController(); interrupted = false;
          const budget = new CopyBudget(bytes.length);
          const ctx = { ...base, signal: controller.signal,
            config: { ...config, ...(budgeted ? { maxCopyBytes: bytes.length } : {}) },
            ...(budgeted ? { copyBudget: budget } : {}) };
          const run = await invoke(ctx), decision = decide(ctx.plan, [run]);
          assert.equal(interrupted, true, 'abort occurs during the executable copy');
          assert.equal(budget.reservedBytes, 0, 'an interrupted copy releases its reservation');
          assert.deepEqual(await readdir(workspace), ['tool.exe'], 'private copy workspace is removed');
          results.push({ execution: run.execution, errors: run.errors, exitCode: run.exitCode, decision, exit: exitCodes[decision.gate] });
        }
        assert.equal(results[0].execution, 'cancelled'); assert.deepEqual(results[0].errors, ['cancelled']);
        assert.equal(results[0].decision.gate, 'INCOMPLETE'); assert.equal(results[0].exit, 3);
        assert.deepEqual(results[1], results[0]);
      }
    });
  } finally {
    t.mock.restoreAll(); syncBuiltinESMExports();
    await rm(workspace, { recursive: true, force: true });
  }
});

test('copy budget: a larger replacement Trivy binary stays an integrity ERROR', { skip: process.platform !== 'win32' }, async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'trivy-copy-integrity-'));
  try {
    const file = path.join(workspace, 'tool.exe'); await writeFile(file, '12345');
    const config: Config = { ...defaults, tools: { trivy: { path: file, sha256: hash('1234'), version: '0.76.1' } } };
    const ctx = { ...await contextFor(fixtureRoot, config), workspace, copyBudget: new CopyBudget(100) };
    const source = stripTypeScriptTypes(await readFile('src/trivy-adapter.ts', 'utf8'));
    // Pin the race between verifiedImage and the copy; execute() must never be reached.
    const invoke = Function('emptyRun', 'scopedProcessOwner', 'verifiedImage', 'path', 'mkdtemp', 'mkdir', 'rm', 'writeFile',
      'SafeError', 'JobDiskCopyLimitError', 'scopedCopyBudget', 'trivyVersion', 'registerJobDiskRoot', 'releaseJobDiskRoot', 'sourceCleanupFor',
      source.slice(source.indexOf('async function invoke('), source.indexOf('export const probeTrivy')) + '\nreturn invoke;')(
      emptyRun, () => ({}), async () => Buffer.from('1234'), path, mkdtemp, mkdir, rm, writeFile,
      SafeError, JobDiskCopyLimitError, scopedCopyBudget, '0.76.1', registerJobDiskRoot, releaseJobDiskRoot, sourceCleanupFor);
    const run = await invoke(ctx, ctx.signal, true);
    assert.equal(run.execution, 'failed'); assert.deepEqual(run.errors, ['tool_digest_mismatch']);
    assert.equal(decide(ctx.plan, [run]).gate, 'ERROR');
  } finally { await rm(workspace, { recursive: true, force: true }); }
});

test('owner environment limitations are unstarted while token and setup failures are errors', async () => {
  const source = stripTypeScriptTypes(await readFile('src/trivy-adapter.ts', 'utf8'));
  const start = source.indexOf('function resultFailure('), end = source.indexOf('async function invoke(', start);
  const classify = Function(source.slice(start, end) + '\nreturn resultFailure;')();
  for (const operation of ['elevated_owner', 'profile_unavailable', 'token_mismatch', 'grant_failed', 'create_failed', 'roots_invalid', 'cleanup_failed']) {
    const run = emptyRun('trivy', context);
    const result = { reason: 'spawn_failed', code: null, diagnostics: [`process_owner_appcontainer_${operation}`] };
    assert.equal(classify(result, run), true);
    assert.equal(run.execution, ['elevated_owner', 'profile_unavailable'].includes(operation) ? 'not_started' : 'failed', operation);
    if (operation === 'token_mismatch') assert.equal(decide(context.plan, [run]).gate, 'ERROR');
  }
});

test('real offline AppContainer run (explicit local config required)', { skip: !process.env.SCANMUX_TRIVY_REAL_CONFIG }, async t => {
  assert.equal(process.platform, 'win32'); assert.ok(testProcessOwner);
  const loaded = await loadConfig(path.resolve(process.env.SCANMUX_TRIVY_REAL_CONFIG!));
  const config: Config = { ...loaded, tools: { ...loaded.tools, 'windows-process-owner': testProcessOwner } };
  const real = await contextFor(fixtureRoot, config);
  const workspace = await mkdtemp(path.resolve('.local/trivy-real-'));
  real.workspace = workspace;
  let retain = false;
  try {
    const probe = await contained(() => probeTrivy(real));
    retain ||= probe.errors.some(code => code.endsWith('termination_unverified') || code === 'process_owner_appcontainer_cleanup_failed');
    assert.equal(probe.execution, 'completed', JSON.stringify(probe.errors));
    const run = await contained(() => new TrivyAdapter().run(real));
    retain ||= run.errors.some(code => code.endsWith('termination_unverified') || code === 'process_owner_appcontainer_cleanup_failed');
    t.diagnostic(JSON.stringify({ exit: run.exitCode, execution: run.execution, findings: run.findings.length,
      counts: Object.fromEntries(['docker', 'kubernetes', 'terraform', 'cloudformation', 'helm'].map(kind => [kind, run.findings.filter(finding => finding.file?.startsWith(kind + '/')).length])),
      coverage: run.coverage, reasons: run.errors }));
    assert.equal(run.execution, 'completed', JSON.stringify(run.errors)); assert.equal(run.exitCode, 0); assert.equal(run.findings.length, 52); assert.equal(run.coverage, 'partial');
    assert.ok(run.trivyCoverage?.state === 'partial' && run.trivyCoverage.receipts.some(receipt => receipt.unit === 'kubernetes:kubernetes/broken.yaml' && receipt.state === 'unresolved'));
    assert.deepEqual(await readdir(workspace), []);
  } finally { if (!retain) await rm(workspace, { recursive: true, force: true }); }
});

test('real offline run plans Containerfiles and does not fail on compose or CI YAML (explicit local config required)', { skip: !process.env.SCANMUX_TRIVY_REAL_CONFIG }, async t => {
  const loaded = await loadConfig(path.resolve(process.env.SCANMUX_TRIVY_REAL_CONFIG!));
  const config: Config = { ...loaded, tools: { ...loaded.tools, 'windows-process-owner': testProcessOwner } };
  const real = await contextFor(path.resolve('test/fixtures/trivy-container-ci'), config);
  const workspace = await mkdtemp(path.resolve('.local/trivy-real-'));
  real.workspace = workspace;
  let retain = false;
  try {
    const run = await contained(() => new TrivyAdapter().run(real));
    retain ||= run.errors.some(code => code.endsWith('termination_unverified') || code === 'process_owner_appcontainer_cleanup_failed');
    t.diagnostic(JSON.stringify({ execution: run.execution, findings: run.findings.map(finding => finding.file), coverage: run.trivyCoverage, reasons: run.errors, targets: run.targets }));
    assert.equal(run.execution, 'completed', JSON.stringify(run.errors));
    // Measured with Trivy 0.76.1: all three Containerfile spellings are scanned; compose and CI YAML give no result.
    assert.deepEqual(run.targets, ['dockerfile:Containerfile', 'dockerfile:build/Containerfile.dev', 'dockerfile:build/app.containerfile']);
    assert.deepEqual([run.coverage, run.errors], ['analyzed', []]);
    assert.deepEqual(new Set(run.findings.map(finding => finding.file)), new Set(['Containerfile', 'build/Containerfile.dev', 'build/app.containerfile']));
    assert.deepEqual(await readdir(workspace), []);
  } finally { if (!retain) await rm(workspace, { recursive: true, force: true }); }
});
