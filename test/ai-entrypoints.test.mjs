import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { registerHooks } from 'node:module';
import { main } from '../src/cli.ts';
import { loadConfig, defaults } from '../src/config.ts';
import { createAdapters, normalizeCodex, normalizeProjectedCodex } from '../src/adapters.ts';
import { createAiAdapter } from '../src/ai-runner.mjs';
import { aiRuntime, buildAiPlan } from '../src/ai-plan.ts';
import { digest } from '../src/safety.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { buildWorkerResourceReport } from '../internal/worker-resources.mjs';

const aiConfig = (assetsRoot, credentialStore) => ({ assetsRoot, credentialStore, reasoningEffort: 'high', commandTimeoutMs: 10000, cleanupTimeoutMs: 10000,
  workerResources: { cpuCount: 1, memoryBytes: 256 * 1024 * 1024, tmpBytes: 32 * 1024 * 1024, workBytes: 16 * 1024 * 1024, shmBytes: 4 * 1024 * 1024 },
  limits: { maxRequests: 5, maxTotalOutputTokens: 20, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 1024, maxResponseBytesPerRequest: 1024, maxToolCalls: 3, maxToolResultBytes: 1024, timeoutMs: 30000 },
  ipc: { maxFrameBytes: 1024, maxBytes: 8192, maxFrames: 20 } });
function source(config) {
  const plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: path.resolve('test'), repoId: 'a'.repeat(64), commit: 'b'.repeat(40), treeHash: 'c'.repeat(40), files: [{ path: 'source.ts', oid: 'd'.repeat(40), bytes: 2, sha256: 'e'.repeat(64) }], dirty: false, exclusions: [], blockers: [], languages: [], lockfiles: [], required: ['gitleaks','osv','codex-security','runtime-advisories'], policyHash: digest(config), network: 'offline', transmissions: [], constraints: ['offline_only','ai_isolation_unverified'], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.snapshotHash = digest(plan.files); plan.planHash = digest({ ...plan, planHash: '' }); return plan;
}
async function invoke(argv) {
  const errors = [], saved = process.stderr.write;
  process.stderr.write = chunk => { errors.push(String(chunk)); return true; };
  try { return { exitCode: await main(argv, { ai: { openWorker() { throw Error('unexpected_worker'); }, createSocket() { throw Error('unexpected_socket'); } } }), error: errors.join('') }; }
  finally { process.stderr.write = saved; }
}
test('AI acceptance options are rejected on every offline sibling before reading configuration', async () => {
  for (const command of ['doctor','plan','scan','plan-list','scan-list','serve','runner-check','ci-check','history','resume','dispositions','policy-check','ai-plan']) {
    const args = [command, ...(['doctor','serve','runner-check'].includes(command) ? [] : ['synthetic-target']), '--config', 'missing-config', '--accept-plan', '0'.repeat(64)];
    const result = await invoke(args); assert.equal(result.exitCode, 4); assert.equal(JSON.parse(result.error).error, 'invalid_command');
  }
  for (const args of [['ai-scan','synthetic-target'], ['ai-plan','synthetic-target']]) {
    const result = await invoke(args); assert.equal(result.exitCode, 4); assert.ok(['invalid_command','ai_config_required'].includes(JSON.parse(result.error).error));
  }
  const unpairedCi = await invoke(['ai-scan','synthetic-target','--accept-plan','0'.repeat(64),'--ci-run','synthetic','--config','missing']);
  assert.equal(unpairedCi.exitCode, 4); assert.equal(JSON.parse(unpairedCi.error).error, 'invalid_ci_manifest');
});
test('AI configuration validates exact shape, path separation and finite bounds without requiring credential records', async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'ai-config-test-'));
  test.after(() => removeTempDir(root));
  const target = path.join(root, 'target'), assets = path.join(root, 'assets'), store = path.join(root, 'store'), file = path.join(root, 'config.json');
  for (const directory of [target, assets, store]) await fs.mkdir(directory);
  const valid = { ...structuredClone(defaults), ai: aiConfig(assets, store) };
  await fs.writeFile(file, JSON.stringify(valid)); const loaded = await loadConfig(file, target); assert.deepEqual(loaded.ai, valid.ai); assert.deepEqual(await fs.readdir(store), []);
  const mutations = [c => { c.ai.extra = true; }, c => { c.ai.limits.extra = 1; }, c => { c.ai.limits.maxRequests = 0; }, c => { c.ai.limits.maxRequests = 1.5; },
    c => { c.ai.limits.timeoutMs = 2147483648; }, c => { c.ai.commandTimeoutMs = 0; }, c => { c.ai.ipc.maxFrameBytes = c.ai.ipc.maxBytes + 1; },
    c => { c.ai.credentialStore = assets; }, c => { c.ai.assetsRoot = target; }, c => { c.ai.assetsRoot = root; }, c => { c.ai.credentialStore = 'relative'; }, c => { c.ai.reasoningEffort = 'low'; },
    c => { delete c.ai.workerResources; }, c => { c.ai.workerResources = null; }, c => { c.ai.workerResources.extra = 1; },
    c => { c.ai.workerResources.memoryBytes = 0; }, c => { c.ai.workerResources.workBytes = 4097; }];
  for (const mutate of mutations) { const input = structuredClone(valid); mutate(input); await fs.writeFile(file, JSON.stringify(input)); await assert.rejects(loadConfig(file, target)); }
  assert.deepEqual(await fs.readdir(store), []);
});
test('the ordinary adapter remains blocked even with AI configuration and an AI plan', async () => {
  const config = { ...structuredClone(defaults), ai: aiConfig(path.resolve('.local'), path.resolve('test')) }, plan = buildAiPlan(source(config), config);
  const adapter = createAdapters().find(adapter => adapter.capabilities().engine === 'codex-security');
  const run = await adapter.run({ plan, config, workspace: process.cwd(), snapshot: '', signal: new AbortController().signal, secretsCleared: true });
  assert.equal(run.execution, 'not_started'); assert.equal(run.usage.calls, 0); assert.equal(run.aiExecution, undefined); assert.ok(run.errors.includes('isolation_unverified'));
});
test('a wrong acceptance and a missing completed secret scan stop the AI adapter before runtime factories', async () => {
  const config = { ...structuredClone(defaults), ai: aiConfig(path.resolve('.local'), path.resolve('test')) }, plan = buildAiPlan(source(config), config);
  let effects = 0; const runtime = { openWorker() { effects++; throw Error('unexpected'); }, createSocket() { effects++; throw Error('unexpected'); } };
  for (const acceptedPlanHash of ['0'.repeat(64), plan.planHash]) {
    const run = await createAiAdapter({ acceptedPlanHash, expiresAt: performance.now() + 10000, runtime }).run({ plan, config, workspace: process.cwd(), snapshot: '', signal: new AbortController().signal });
    assert.equal(run.execution, 'failed'); assert.equal(run.usage.calls, 0); assert.equal(run.aiExecution.connectionAttempts, 0); assert.ok(run.errors.includes(acceptedPlanHash === plan.planHash ? 'ai_source_secret_scan_missing' : 'ai_plan_not_accepted'));
  }
  assert.equal(effects, 0);
});
test('a verified resource stop before the first submit retains its final adapter state and reason', { skip: process.platform !== 'win32' }, async t => {
  const root = await fs.mkdtemp(path.join(process.cwd(), '.ai-adapter-test-'));
  test.after(() => removeTempDirStrict(root, { recursive: true, force: true }));
  const workspace = path.join(root, 'workspace');
  await fs.mkdir(workspace);
  const config = { ...structuredClone(defaults), ai: aiConfig(path.join(root, 'assets'), path.join(root, 'store')) }, plan = buildAiPlan(source(config), config);
  const assets = "Array.from({ length: 10805 }, (_, index) => ({ path: 'asset-' + index, bytes: 0, sha256: 'a'.repeat(64) }))";
  const manifest = Array.from({ length: 10805 }, (_, index) => ({ path: 'asset-' + index, bytes: 0, sha256: 'a'.repeat(64) }));
  const result = { status: 'failed', reason: 'bridge_early_eof', artifactsAccepted: false, providerSubmitInvocations: 0, usage: null,
    mcpEvidence: 'not_started', artifactEvidence: 'none', inputsUnchanged: true, workerAttempted: true, independentFailures: [],
    workerResources: buildWorkerResourceReport({ requested: config.ai.workerResources, boundaryVerified: true, startupVerified: true, terminal: { exitCode: 137, oomKilled: true } }) };
  const adapterUrl = new URL('../src/ai-runner.mjs?resource-stop', import.meta.url).href;
  const stub = (file, body) => `export * from ${JSON.stringify(new URL(file, import.meta.url).href)}; ${body}`;
  const modules = new Map([
    ['./ai-plan.ts', stub('../src/ai-plan.ts', `export const aiRuntime = ${JSON.stringify({ ...aiRuntime, assetManifestSha256: digest(manifest) })};`)],
    ['./ai-files.mjs', stub('../src/ai-files.mjs', `export const canonicalAiPath = async value => value; export const inventoryAiDirectory = async (directory, control, options) => options.order === 'sdk-assets' ? ${assets} : [];`)],
    ['./repository.ts', stub('../src/repository.ts', 'export const verifySnapshot = async () => true;')],
    ['../internal/projected-repository.mjs', stub('../internal/projected-repository.mjs', `export const projectRepository = async () => (${JSON.stringify({ status: 'completed', repository: path.join(root, 'projection'), mapping: { derivedRevision: 'f'.repeat(40) }, scope: { paths: ['source.ts'] } })});`)],
    ['../internal/hosted-bridge.mjs', stub('../internal/hosted-bridge.mjs', `export async function runHostedBridge(options) { await options.openWorker({}); const cleanup = await options.closeTransport({}); return { ...${JSON.stringify(result)}, cleanup: { ...cleanup, containerAbsent: true } }; }`)],
  ]);
  const hooks = registerHooks({ resolve(specifier, context, nextResolve) {
    if (context.parentURL === adapterUrl && modules.has(specifier)) return { url: 'data:text/javascript,' + encodeURIComponent(modules.get(specifier)), shortCircuit: true };
    return nextResolve(specifier, context);
  } });
  let createAdapter;
  try { ({ createAiAdapter: createAdapter } = await import(adapterUrl)); } finally { hooks.deregister(); }
  let opens = 0, connections = 0;
  const runtime = { async openWorker() { opens++; return { diagnostics: () => ({ boundaryVerifiedBeforeStart: true, imageId: aiRuntime.imageDigest }) }; }, createSocket() { connections++; throw Error('unexpected_socket'); } };
  const run = await createAdapter({ acceptedPlanHash: plan.planHash, expiresAt: performance.now() + 10000, runtime }).run({ plan, config, workspace, snapshot: '', signal: new AbortController().signal,
    secretScan: { execution: 'completed', coverage: 'analyzed', findings: [], errors: [] } });
  assert.equal(opens, 1); assert.equal(connections, 0); assert.equal(run.usage.calls, 0);
  assert.equal(run.aiExecution.submitInvocations, 0); assert.equal(run.aiExecution.connectionAttempts, 0); assert.equal(run.aiExecution.sendInvocations, 0); assert.deepEqual(run.aiExecution.programs, []);
  assert.equal(run.execution, 'budget_exceeded'); assert.equal(run.aiExecution.status, 'budget_exceeded'); assert.equal(run.aiExecution.reason, 'resource_memory_exceeded');
  assert.ok(run.errors.includes('resource_memory_exceeded')); assert.ok(!run.errors.includes('ai_effective_program_unverified'));
  assert.equal(run.aiExecution.artifactsAccepted, false); assert.equal(run.coverage, 'partial'); assert.deepEqual(run.findings, []);
});
test('mapping-aware normalization preserves the original plan and rejects every cross-source identity sibling', () => {
  const config = structuredClone(defaults), plan = source(config), context = { plan, config };
  const mapping = { schema: 'scanmux.sdk-projection/v1', originalCommit: plan.commit, originalTree: plan.treeHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash, projectionScope: 'accepted_files_only', projectedMode: '100644', derivedRevision: 'f'.repeat(40), manifest: plan.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })) };
  const raw = { manifest: { scan: { id: 'fixture-scan', target: { revision: mapping.derivedRevision } } }, findings: { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'fixture-scan', findings: [{ findingId: 'fixture-finding', ruleId: 'fixture-rule', severity: { level: 'high' }, confidence: { level: 'high' }, locations: [{ path: 'source.ts', startLine: 1 }] }] } };
  const before = structuredClone({ plan, raw, mapping }), findings = normalizeProjectedCodex(raw, mapping, context);
  assert.equal(findings.length, 1); assert.equal(findings[0].file, 'source.ts'); assert.equal(findings[0].evidenceState, 'candidate'); assert.deepEqual({ plan, raw, mapping }, before);
  assert.throws(() => normalizeCodex(raw, context), /codex_revision_mismatch/);
  for (const key of ['originalCommit','originalTree','planHash','snapshotHash','derivedRevision']) { const changed = structuredClone(mapping); changed[key] = '0'.repeat(changed[key].length); assert.throws(() => normalizeProjectedCodex(raw, changed, context), /codex_projection_mismatch/); }
  const changed = structuredClone(mapping); changed.manifest[0].sha256 = '0'.repeat(64); assert.throws(() => normalizeProjectedCodex(raw, changed, context), /codex_projection_mismatch/);
});

test('projected Codex ranges need no local snapshot and retain all structural checks', () => {
  const config = structuredClone(defaults), plan = source(config);
  const mapping = { schema: 'scanmux.sdk-projection/v1', originalCommit: plan.commit, originalTree: plan.treeHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash, projectionScope: 'accepted_files_only', projectedMode: '100644', derivedRevision: 'f'.repeat(40), manifest: plan.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 })) };
  const position = { path: 'source.ts', startLine: 1, endLine: 2 };
  const raw = { manifest: { scan: { id: 'fixture-scan', target: { revision: mapping.derivedRevision } } }, findings: { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'fixture-scan', findings: [{ findingId: 'fixture-finding', ruleId: 'fixture-rule', severity: { level: 'high' }, confidence: { level: 'high' }, locations: [position] }] } };
  for (const context of [{ plan, config }, { plan, config, snapshot: '' }]) {
    const before = structuredClone({ plan, raw, mapping });
    const finding = normalizeProjectedCodex(raw, mapping, context)[0];
    assert.equal(finding.line, 1); assert.equal(finding.endLine, 2);
    assert.deepEqual({ plan, raw, mapping }, before);
    for (const endLine of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, '2', true]) {
      const changed = structuredClone(raw); changed.findings.findings[0].locations[0].endLine = endLine;
      assert.throws(() => normalizeProjectedCodex(changed, mapping, context), /invalid_line/);
    }
    for (const location of [{ ...position, startLine: 3 }, { ...position, startLine: 0 }, { ...position, path: '../source.ts' }, { ...position, path: path.resolve('source.ts') }]) {
      const changed = structuredClone(raw); changed.findings.findings[0].locations = [location];
      assert.throws(() => normalizeProjectedCodex(changed, mapping, context));
    }
  }
});
