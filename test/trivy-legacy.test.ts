import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import { randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Adapter, AdapterContext, Plan, Report } from '../src/model.ts';

const base = '4e00c54881bb907e6783011847ae7cd6b85a6b27';
const goldenPath = new URL('./fixtures/trivy-legacy-golden.json', import.meta.url);

/** Both capture and verification call exactly the same deterministic public projections. */
async function observations(root: string) {
  const module = <T>(name: string) => import(pathToFileURL(path.join(root, 'src', name)).href) as Promise<T>;
  const [configModule, adapters, safety, catalog, html, sarif, configuration, policy, history, dispositions, checkpoint] = await Promise.all([
    module<typeof import('../src/config.ts')>('config.ts'),
    module<typeof import('../src/adapters.ts')>('adapters.ts'),
    module<typeof import('../src/safety.ts')>('safety.ts'),
    module<typeof import('../src/advisory-catalog.ts')>('advisory-catalog.ts'),
    module<typeof import('../src/html-report.ts')>('html-report.ts'),
    module<typeof import('../src/sarif-report.ts')>('sarif-report.ts'),
    module<typeof import('../src/configuration.ts')>('configuration.ts'),
    module<typeof import('../src/policy.ts')>('policy.ts'),
    module<typeof import('../src/history.ts')>('history.ts'),
    module<typeof import('../src/dispositions.ts')>('dispositions.ts'),
    module<typeof import('../src/engine-checkpoint.ts')>('engine-checkpoint.ts'),
  ]);
  const { hash, digest } = safety, config = await configModule.loadConfig();
  assert.equal(Object.hasOwn(config.tools, 'trivy'), false);
  const source = new Map([
    ['source.ts', Buffer.from('export const example = 1;\n')],
    ['package-lock.json', Buffer.from('{"name":"example","lockfileVersion":3,"packages":{}}\n')],
    ['Dockerfile', Buffer.from('FROM node:24\nUSER root\n')],
  ]);
  const files = [...source].map(([name, bytes], index) => ({ path: name, oid: String(index + 1).repeat(40), bytes: bytes.length, sha256: hash(bytes) }));
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalog.catalogIdentity }, root: 'C:/scanmux-legacy-fixture', repoId: 'legacy-fixture', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest(files), dirty: false, files, exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: ['package-lock.json'], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [], constraints: ['tracked_files_only', 'offline_only'], cost: { kind: 'not_applicable', aiCalls: 0 }, configuration: configuration.summarizeConfiguration([...source].map(([name, bytes]) => configuration.observeConfiguration(name, bytes))) };
  plan.planHash = digest({ ...plan, planHash: '' });
  const context: AdapterContext = { plan, config, snapshot: 'C:/scanmux-legacy-snapshot', workspace: 'C:/scanmux-legacy-work', signal: new AbortController().signal, secretsCleared: true };
  const instances = Reflect.apply(adapters.createAdapters, null, [plan]) as Adapter[];
  const runs = instances.map(adapter => ({ ...adapters.emptyRun(adapter.capabilities().engine, context), execution: 'completed' as const, coverage: 'analyzed' as const, startedAt: '2026-10-26T00:00:00.000Z', endedAt: '2026-10-26T00:00:01.000Z', exitCode: 0 }));
  runs[0].findings = adapters.normalizeGitleaks([{ RuleID: 'example-rule', File: 'source.ts', StartLine: 1, Secret: 'omitted scanner field', Match: 'omitted scanner field' }], context);
  runs[1].findings = adapters.normalizeOsv({ results: [{ source: { path: 'package-lock.json' }, packages: [{ package: { name: 'example', version: '1.0.0', ecosystem: 'npm' }, vulnerabilities: [{ id: 'GHSA-example-1234', aliases: ['CVE-2026-12345'], database_specific: { severity: 'HIGH' }, affected: [{ package: { name: 'example', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '1.0.1' }] }] }] }] }] }] }, context);
  runs[2].findings = adapters.normalizeCodex({ manifest: { scan: { id: 'legacy-scan', target: { revision: plan.commit } } }, findings: { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'legacy-scan', findings: [{ findingId: 'f1', ruleId: 'cwe-79', severity: { level: 'high' }, confidence: { level: 'medium' }, locations: [{ path: 'source.ts', startLine: 1 }], summary: 'omitted model field' }] } }, context);
  // The catalog remains incomplete today; a successful synthetic fixture must not imply runtime coverage.
  const engines: Report['engines'] = runs;
  engines[3].coverage = 'partial'; engines[3].errors = ['runtime_environment_unverified'];
  const decision = policy.decide(plan, engines);
  const report: Report = { schema: 'scanmux.report/v2', runId: '11111111-1111-1111-1111-111111111111', plan, runner: { platform: 'win32', node: 'v24.16.0', imageDigest: null, isolation: 'local-static-only' }, startedAt: '2026-10-26T00:00:00.000Z', endedAt: '2026-10-26T00:00:01.000Z', engines, executionState: 'completed', coverageState: 'incomplete', gate: decision.gate, exitCode: policy.exitCodes[decision.gate], reasons: decision.reasons, integrityErrors: [] };
  const bytes = (value: string | Buffer) => ({ bytes: Buffer.byteLength(value), sha256: hash(value) });
  const sarifParts = sarif.renderSarifReports(report, config.maxOutputBytes);
  const { version: packageVersion } = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const error = (action: () => unknown) => {
    try { action(); return 'accepted'; } catch (failure) { return failure instanceof safety.SafeError ? failure.code : (failure as Error).name; }
  };
  const encoded = (value: unknown) => Buffer.from(JSON.stringify(value));
  const invalidPlan = structuredClone(report); Reflect.set(invalidPlan.plan, 'schema', 'scanmux.plan/v1');
  const oldReport = structuredClone(report); Reflect.set(oldReport, 'schema', 'scanmux.report/v1');
  const changedCheckpoint = (change: (plan: Plan) => void, rehash = true, corrupt?: (body: Buffer) => Buffer) => {
    const saved = structuredClone(report);
    saved.plan.repoId = hash(saved.plan.root); saved.plan.planHash = digest({ ...saved.plan, planHash: '' });
    change(saved.plan); if (rehash) saved.plan.planHash = digest({ ...saved.plan, planHash: '' });
    Object.assign(saved, { engines: saved.engines.slice(0, 1), executionState: 'failed', gate: 'ERROR', exitCode: 4,
      integrityErrors: ['controller_completion_unverified'], reasons: ['controller_completion_unverified'] });
    const body = encoded({ schema: 'scanmux.engine-checkpoint/v1', runId: saved.runId, sequence: 1, planHash: saved.plan.planHash, previousSha256: null, report: saved });
    const receipt = Buffer.from(JSON.stringify({ schema: 'scanmux.engine-checkpoint-commit/v1', runId: saved.runId, sequence: 1, bytes: body.length, sha256: hash(body), previousSha256: null }) + '\n');
    return error(() => checkpoint.validateCheckpointPair(corrupt ? corrupt(body) : body, receipt, 1, null));
  };
  const errors = {
    dispositionOldReport: error(() => dispositions.evaluateDispositions(encoded(oldReport))),
    dispositionMalformed: error(() => dispositions.evaluateDispositions(Buffer.from('{'))),
    dispositionInvalidUtf8: error(() => dispositions.evaluateDispositions(Buffer.from([0xff]))),
    historyOldPlan: error(() => history.summarizeHistory([encoded(invalidPlan)])),
    checkpointOrder: changedCheckpoint(plan => { plan.required.reverse(); }),
    checkpointOldPlan: changedCheckpoint(plan => { Reflect.set(plan, 'schema', 'scanmux.plan/v1'); }, false),
    checkpointRehashedOldPlan: changedCheckpoint(plan => { Reflect.set(plan, 'schema', 'scanmux.plan/v1'); }),
    checkpointTruncated: changedCheckpoint(() => {}, true, body => body.subarray(0, -1)),
    checkpointHashMismatch: changedCheckpoint(() => {}, true, body => Buffer.from('{'.repeat(body.length))),
  };
  assert.deepEqual(errors, { dispositionOldReport: 'invalid_history_report', dispositionMalformed: 'SyntaxError', dispositionInvalidUtf8: 'TypeError',
    historyOldPlan: 'invalid_history_report', checkpointOrder: 'invalid_engine_checkpoint', checkpointOldPlan: 'invalid_engine_checkpoint', checkpointRehashedOldPlan: 'invalid_history_report',
    checkpointTruncated: 'invalid_engine_checkpoint', checkpointHashMismatch: 'invalid_engine_checkpoint' });
  // Exercise the controller's real admission/order logic with IO confined to this test's scratch.
  const workspace = await mkdtemp(path.join(tmpdir(), 'trivy-legacy-controller-'));
  try {
    const source = stripTypeScriptTypes(await readFile(path.join(root, 'src/controller.ts'), 'utf8')).replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
    const copyBudget = root === path.resolve('.') ? await module<typeof import('../src/copy-budget.ts')>('copy-budget.ts') : undefined;
    const disk = root === path.resolve('.') ? await module<typeof import('../src/job-disk.ts')>('job-disk.ts') : undefined;
    const processTree = root === path.resolve('.') ? await module<typeof import('../src/process-tree.ts')>('process-tree.ts') : undefined;
    const cleanup = root === path.resolve('.') ? await module<typeof import('../src/source-cleanup.ts')>('source-cleanup.ts') : undefined;
    const imports = { ...safety, path, randomUUID, rm, catalogIdentity: catalog.catalogIdentity, ...policy, ...adapters,
      ...(cleanup ? { sourceCleanupFor: cleanup.sourceCleanupFor, sourceCleanupFailed: cleanup.sourceCleanupFailed, withSourceCleanup: cleanup.withSourceCleanup } : {}),
      ...(disk && processTree ? { JobDisk: disk.JobDisk, withJobDisk: disk.withJobDisk, scopedProcessOwner: processTree.scopedProcessOwner } : {}),
      ...(copyBudget ? { CopyBudget: copyBudget.CopyBudget, withCopyBudget: copyBudget.withCopyBudget } : {}),
      comparisonSummary: () => undefined, verifyEngineCatalog: (_input: unknown): void => { throw Error('replaced below'); },
      materialize: async () => path.join(workspace, 'snapshot'), verifySnapshot: async () => true,
      openEngineCheckpoints: async () => ({ async save() { throw new safety.SafeError('invalid_engine_checkpoint'); } }),
      CheckpointOwnerStop: checkpoint.CheckpointOwnerStop };
    if (root === path.resolve('.')) imports.verifyEngineCatalog = (await module<typeof import('../src/engine-catalog.ts')>('engine-catalog.ts')).verifyEngineCatalog;
    const controller = Function(...Object.keys(imports), source + '\nreturn scan;')(...Object.values(imports));
    const reordered = structuredClone(plan); reordered.required.reverse(); reordered.planHash = digest({ ...reordered, planHash: '' });
    const visited: string[] = [];
    const run = await controller(reordered, config, workspace, context.signal, instances.map(adapter => ({
      capabilities: () => adapter.capabilities(), async run(input: AdapterContext) { const engine = adapter.capabilities().engine; visited.push(engine); return adapters.emptyRun(engine, input); },
    })));
    assert.deepEqual({ visited, integrityErrors: run.integrityErrors }, { visited: ['gitleaks'], integrityErrors: ['checkpoint_save_failed'] });
  } finally { await rm(workspace, { recursive: true, force: true }); }
  return { base, config: bytes(JSON.stringify(config)), policyHash: plan.policyHash, plan: bytes(JSON.stringify(plan, null, 2) + '\n'), planHash: plan.planHash, snapshotHash: plan.snapshotHash,
    adapterOrder: instances.map(adapter => adapter.capabilities().engine), requiredOrder: plan.required, engineOrder: engines.map(run => run.engine), findingOrder: engines.flatMap(run => run.findings.map(finding => ({ engine: finding.engine, fingerprint: finding.fingerprint, originIds: finding.originIds }))),
    report: bytes(JSON.stringify(report, null, 2) + '\n'), html: { ja: bytes(html.renderHtmlReport(report, 'ja')), en: bytes(html.renderHtmlReport(report, 'en')) },
    sarif: sarifParts.map(part => {
      const parsed = JSON.parse(part.text);
      assert.equal(JSON.stringify(parsed, null, 2) + '\n', part.text);
      // Compare against the immutable capture's package version.
      for (const run of parsed.runs) {
        assert.equal(run.tool.driver.version, packageVersion);
        run.tool.driver.version = '0.1.0-poc.1';
      }
      const text = JSON.stringify(parsed, null, 2) + '\n';
      return { name: part.name, findings: part.findings, text: bytes(text), gzip: bytes(gzipSync(text)) };
    }) };
}

function verifyCaptureBaseline(root: string): void {
  const git = (args: string[]) => {
    const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
  };
  assert.equal(path.resolve(git(['rev-parse', '--show-toplevel'])), root, 'capture requires an independent baseline checkout');
  assert.equal(git(['rev-parse', 'HEAD']), base, 'capture requires the immutable baseline commit');
  assert.equal(git(['status', '--porcelain', '--untracked-files=all']), '', 'capture requires a clean baseline tree');
}

test('legacy capture refuses the current feature checkout before producing output', t => {
  const checkout = spawnSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8', windowsHide: true });
  if (checkout.error || checkout.status !== 0) {
    const reason = 'legacy capture requires git and a checkout';
    assert.notEqual(process.env.SCANMUX_REQUIRE_TRIVY_LEGACY_GIT, '1', reason);
    t.skip(reason); return;
  }
  assert.throws(() => verifyCaptureBaseline(path.resolve('.')), /immutable baseline commit/);
});

test('legacy checkout guard skips without git or a checkout unless explicitly required', () => {
  for (const unavailable of ['git', 'checkout']) for (const required of [false, true]) {
    const env: NodeJS.ProcessEnv = { ...process.env, SCANMUX_REQUIRE_TRIVY_LEGACY_GIT: required ? '1' : '0' };
    delete env.NODE_TEST_CONTEXT;
    if (unavailable === 'git') env.PATH = path.dirname(process.execPath);
    else env.GIT_DIR = path.join(tmpdir(), `nonexistent-legacy-checkout-${randomUUID()}`);
    const run: SpawnSyncReturns<string> = spawnSync(process.execPath, [path.resolve('scripts/run-tests.mjs'),
      '--test-name-pattern=^legacy capture refuses the current feature checkout before producing output$', 'test/trivy-legacy.test.ts'],
    { env, encoding: 'utf8', windowsHide: true });
    assert.equal(run.error, undefined);
    const output = run.stdout + run.stderr;
    assert.equal(run.status, required ? 1 : 0, `${unavailable}, required=${required}: ${output}`);
    assert.match(output, required ? /legacy capture requires git and a checkout/ : /skip(?:ped)?\s+1|# SKIP/);
  }
});

test('without tools.trivy all v2 bytes, hashes, engine order, fingerprints and error paths match the immutable original', async () => {
  if (process.env.SCANMUX_CAPTURE_TRIVY_LEGACY === base) {
    const root = path.resolve('.local/legacy-baseline');
    verifyCaptureBaseline(root);
    const captured = await observations(root);
    // Capture is an explicit one-time authoring action into ignored storage, never golden regeneration.
    await writeFile(path.join(root, 'captured.json'), JSON.stringify(captured, null, 2) + '\n', { flag: 'wx' });
    assert.equal(captured.base, base);
    return;
  }
  const golden = JSON.parse(await readFile(goldenPath, 'utf8'));
  assert.equal(golden.base, base);
  assert.deepEqual(await observations(path.resolve('.')), golden);
});
