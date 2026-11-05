import test, { afterEach, mock, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash, randomUUID } from 'node:crypto';
import { stripTypeScriptTypes, syncBuiltinESMExports } from 'node:module';
import childProcess, { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { defaults } from '../src/config.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { legacyEngines, verifyEngineCatalog } from '../src/engine-catalog.ts';
import { emptyRun } from '../src/engine-run.ts';
import { gitleaksConfig } from '../src/adapters.ts';
import { prepareOfflineDatabase, verifyPreparedDatabase } from '../src/osv-database.ts';
import { privateAclRule } from '../src/private-acl.ts';
import { privateWorkspace, protectDirectory, verifyPrivateDirectory } from '../src/private-storage.ts';
import { verifySnapshot } from '../src/repository.ts';
import { comparisonSummary, treeEntries } from '../src/comparison.ts';
import { CheckpointOwnerStop } from '../src/engine-checkpoint.ts';
import { decide, exitCodes } from '../src/policy.ts';
import * as safety from '../src/safety.ts';
import * as copyBudget from '../src/copy-budget.ts';
import * as jobDisk from '../src/job-disk.ts';
import * as provenance from '../src/provenance.ts';
import * as cleanupModule from '../src/source-cleanup.ts';
import { safeRemove } from '../src/safe-remove.ts';
import { main } from '../src/cli.ts';
import { runBatchJobs } from '../src/batch.ts';
import { staticError } from '../src/output.ts';
import { parseReportLanguage } from '../src/report-language.ts';
import type { Adapter, Config, Plan, Report } from '../src/model.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); });

const { SourceCleanupOwner, sourceCleanupFor, withSourceCleanup } = cleanupModule;
const body = 'export const value = 1;\n', name = 'source.ts';
const oid = createHash('sha1').update(`blob ${Buffer.byteLength(body)}\0${body}`).digest('hex');
const absent = async (directory: string) => assert.equal(await fs.lstat(directory).catch(() => null), null, directory);
async function loaded(file: string, imports: Record<string, unknown>, names: string[]) {
  const source = stripTypeScriptTypes(await fs.readFile(file, 'utf8')).replace(/^import [\s\S]*?;\r?\n/gm, '').replace(/^export \{.*\} from .*;\r?\n/gm, '').replace(/^export /gm, '');
  return Function(...Object.keys(imports), source + `\nreturn {${names.join(',')}};`)(...Object.values(imports));
}
async function fixture() {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'original-')), workspace = await privateWorkspace(root);
  await fs.writeFile(path.join(root, name), body);
  await fs.writeFile(path.join(workspace, 'report.json'), 'retained report');
  const config: Config = { ...structuredClone(defaults), maxOutputBytes: 1024 * 1024, timeoutMs: 10000,
    tools: { git: { path: process.execPath, sha256: 'a'.repeat(64), version: process.versions.node }, gitleaks: { path: process.execPath, sha256: 'b'.repeat(64), version: '8.30.1' } } };
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: safety.hash(root), commit: 'c'.repeat(40), treeHash: 'd'.repeat(40),
    snapshotHash: '', dirty: false, files: [{ path: name, oid, bytes: Buffer.byteLength(body), sha256: safety.hash(body) }], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: [...legacyEngines], policyHash: safety.digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.snapshotHash = safety.digest(plan.files); plan.planHash = safety.digest(plan);
  return { root, workspace, config, plan, abort: new AbortController() };
}
async function projection(f: Awaited<ReturnType<typeof fixture>>, mode = 'success', spawnChild: typeof spawn = spawn, timing: Record<string, unknown> = {}) {
  let copied = false;
  const diagnostics: { code: string; syscall: string }[] = [];
  const observedFs = { ...fs, realpath: async (...args: Parameters<typeof fs.realpath>) => {
    try { return await fs.realpath(...args); }
    catch (error) { const failure = error as NodeJS.ErrnoException; diagnostics.push({ code: failure.code!, syscall: failure.syscall! }); throw error; }
  } };
  const execute = async (tool: { version: string }, args: string[], options: { input?: string }) => {
    const result = (text = '', reason = 'exit', code: number | null = 0) => ({ stdout: Buffer.from(text), reason, code });
    if (tool.version === '8.30.1') return result(args[0] === 'version' ? '8.30.1' : '[]');
    const repository = path.join(f.workspace, 'sdk-repository'), git = path.join(repository, '.git');
    if (args.includes('init')) { await fs.mkdir(git); return result(); }
    if (args.includes('hash-object')) {
      assert.equal(await fs.readFile(path.join(repository, name), 'utf8'), body); copied = true;
      await fs.mkdir(path.join(git, 'objects'), { recursive: true }); await fs.writeFile(path.join(git, 'objects', oid), body);
      if (mode === 'partial_projection') return result('', 'exit', 1);
      if (mode === 'projection_cancelled') f.abort.abort();
      if (mode === 'projection_termination_unverified') return result('', 'termination_unverified', null);
      return result(oid + '\n');
    }
    if (args.includes('write-tree')) return result('e'.repeat(40) + '\n');
    if (args.includes('commit-tree') || args.includes('rev-parse')) return result('f'.repeat(40) + '\n');
    if (args.includes('cat-file')) return args.includes('commit') ? result('tree ' + 'e'.repeat(40) + '\n') : result(body);
    if (args.includes('ls-tree')) return result(`100644 blob ${oid} ${Buffer.byteLength(body)}\t${name}\0`);
    if (args.includes('check-attr')) return result(args.slice(args.indexOf('-z') + 1, args.indexOf('--stdin')).map(attribute => `${name}\0${attribute}\0unset\0`).join(''));
    if (args.includes('--index-info')) await fs.writeFile(path.join(git, 'index'), options.input ?? '');
    return result();
  };
  const module = await loaded('internal/projected-repository.mjs', { fs: observedFs, path, performance, spawn: spawnChild, ...safety, execute, treeEntries, gitleaksConfig, privateAclRule, sourceCleanupFor, ...timing }, ['projectRepository']);
  const result = await module.projectRepository({ ...f, snapshot: path.join(f.workspace, 'snapshot'), signal: f.abort.signal });
  if (diagnostics.length) result.diagnostics = diagnostics;
  return { result, copied };
}
async function controller(f: Awaited<ReturnType<typeof fixture>>, mode: string) {
  let verified = 0, saved = 0;
  const module = await loaded('src/controller.ts', { ...safety, ...copyBudget, ...jobDisk, ...cleanupModule, path, randomUUID, catalogIdentity, emptyRun,
    createAdapters: () => [], decide, exitCodes, scopedProcessOwner: () => undefined, verifyEngineCatalog, comparisonSummary, CheckpointOwnerStop,
    materialize: async () => {
      const snapshot = sourceCleanupFor(f.workspace).register(f.workspace, path.join(f.workspace, 'snapshot'));
      await fs.mkdir(snapshot); await sourceCleanupFor(f.workspace).capture(f.workspace, snapshot); await fs.writeFile(path.join(snapshot, name), body);
      if (mode === 'materialization_failure') throw new safety.SafeError('snapshot_integrity');
      return snapshot;
    },
    verifySnapshot: async (plan: Plan, snapshot: string) => { verified++; assert.equal(await fs.readFile(path.join(snapshot, name), 'utf8'), body); return verifySnapshot(plan, snapshot); },
    openEngineCheckpoints: async () => ({ save: async (report: Report) => {
      const directory = path.join(f.workspace, 'checkpoints'); await fs.mkdir(directory, { recursive: true });
      await fs.writeFile(path.join(directory, `checkpoint-${++saved}.json`), JSON.stringify(report));
    } }),
  }, ['scan']);
  const adapters: Adapter[] = legacyEngines.map(engine => ({ capabilities: () => ({ engine }), async run(context: Parameters<Adapter['run']>[0]) {
    const run = { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
    if (engine === 'gitleaks') {
      const acquisition = sourceCleanupFor(f.workspace).register(f.workspace, path.join(f.workspace, 'repository'));
      await fs.mkdir(acquisition); await sourceCleanupFor(f.workspace).capture(f.workspace, acquisition);
      await fs.mkdir(path.join(acquisition, '.git'), { recursive: true }); await fs.writeFile(path.join(acquisition, '.git', 'original'), body);
      const { result, copied } = await projection(f, mode);
      assert.equal(copied, true, JSON.stringify(result));
      if (mode === 'partial_projection') { assert.notEqual(result.status, 'completed'); throw new safety.SafeError('ai_projection_failed'); }
      assert.equal(result.status, 'completed', result.reason);
      if (mode === 'engine_failure') { run.execution = 'failed'; run.errors.push('scanner_exit_failure'); }
      if (mode === 'cancellation') { f.abort.abort(); run.execution = 'cancelled'; run.errors.push('cancelled'); }
      if (mode === 'termination_unverified') { run.execution = 'failed'; run.errors.push('worker_termination_unverified'); }
    }
    return run;
  } } as Adapter));
  return { scan: () => module.scan(f.plan, f.config, f.workspace, f.abort.signal, adapters) as Promise<Report>, verified: () => verified };
}
async function cleanupScan(f: Awaited<ReturnType<typeof fixture>>, duringScan = async () => {}) {
  const module = await loaded('src/controller.ts', { ...safety, ...copyBudget, ...jobDisk, ...cleanupModule, path, randomUUID, catalogIdentity, emptyRun,
    createAdapters: () => [], decide, exitCodes, scopedProcessOwner: () => undefined, verifyEngineCatalog, comparisonSummary, CheckpointOwnerStop, verifySnapshot,
    materialize: async () => { const owner = sourceCleanupFor(f.workspace), snapshot = owner.register(f.workspace, path.join(f.workspace, 'snapshot')); await fs.mkdir(snapshot); await owner.capture(f.workspace, snapshot); await fs.writeFile(path.join(snapshot, name), body); return snapshot; },
    openEngineCheckpoints: async () => ({ save: async () => {} }),
  }, ['scan']);
  const adapters: Adapter[] = legacyEngines.map(engine => ({ capabilities: () => ({ engine }), run: async context => {
    await duringScan(); await fs.readFile(path.join(context.snapshot, name)); return { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
  } } as Adapter));
  return module.scan(f.plan, f.config, f.workspace, f.abort.signal, adapters) as Promise<Report>;
}

for (const mode of ['success', 'scanner_failure', 'copy_failure']) test(`scan removes its offline database after ${mode} and keeps its report`, async () => {
  const f = await fixture(), source = await fs.mkdtemp(path.join(tmpdir(), 'database-'));
  await fs.mkdir(path.join(source, 'osv-scalibr', 'PyPI'), { recursive: true });
  if (mode !== 'copy_failure') await fs.writeFile(path.join(source, 'osv-scalibr', 'PyPI', 'all.zip'), 'offline fixture');
  f.config.osvDatabase = source;
  f.config.tools.osv = { path: process.execPath, version: '2.7.0', sha256: 'a'.repeat(64) };
  f.plan.lockfiles = [name]; f.plan.policyHash = safety.digest(f.config); f.plan.planHash = safety.digest({ ...f.plan, planHash: '' });
  let invoked = false, prepared = false;
  const module = await loaded('src/adapters.ts', { ...safety, ...copyBudget, path, readFile: fs.readFile, writeFile: fs.writeFile, emptyRun,
    prepareOfflineDatabase, verifyPreparedDatabase, verifyVersion: async () => {},
    execute: async () => {
      invoked = true;
      assert.equal(await fs.readFile(path.join(f.workspace, 'osv-database', 'osv-scalibr', 'PyPI', 'all.zip'), 'utf8'), 'offline fixture');
      return { reason: 'exit', code: mode === 'scanner_failure' ? 2 : 0, stdout: Buffer.from(JSON.stringify({ results: [{ source: { path: name }, packages: [] }] })) };
    },
  }, ['createOsvAdapter']);
  const report = await cleanupScan(f, async () => {
    if (prepared) return; prepared = true;
    const run = await module.createOsvAdapter().run({ plan: f.plan, config: f.config, workspace: f.workspace,
      snapshot: path.join(f.workspace, 'snapshot'), signal: f.abort.signal, secretsCleared: false });
    assert.equal(run.execution, mode === 'success' ? 'completed' : 'failed');
    if (mode !== 'success') throw new safety.SafeError(run.errors[0]);
  });
  assert.equal(prepared, true); assert.equal(invoked, mode !== 'copy_failure');
  assert.equal(report.gate, mode === 'success' ? 'PASS' : 'ERROR');
  await absent(path.join(f.workspace, 'osv-database'));
  assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
  if (mode !== 'copy_failure') assert.equal(await fs.readFile(path.join(source, 'osv-scalibr', 'PyPI', 'all.zip'), 'utf8'), 'offline fixture');
});


for (const replacement of ['workspace', 'recorded-copy']) test(`live cleanup preserves a replacement ${replacement} and reports failure`, async () => {
  const workspace = await privateWorkspace(), owner = sourceCleanupFor(workspace);
  const copy = replacement === 'workspace' ? owner.register(workspace, path.join(workspace, 'snapshot')) : await owner.directory(workspace, 'trivy-');
  if (replacement === 'workspace') await fs.mkdir(copy);
  await fs.writeFile(path.join(copy, name), body);
  const moved = replacement === 'workspace' ? workspace : copy, held = moved + '-held';
  await fs.rename(moved, held); await fs.mkdir(copy, { recursive: true }); await fs.writeFile(path.join(copy, 'unrelated'), 'replacement');
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'replacement');
  assert.equal(await fs.readFile(path.join(held, ...(replacement === 'workspace' ? ['snapshot'] : []), name), 'utf8'), body);
});

async function copiedSnapshot(f: Awaited<ReturnType<typeof fixture>>) {
  const module = await loaded('src/repository.ts', { ...safety, path, ...fs, sourceCleanupFor, legacyEngines,
    readGitBlobs: async function* () { yield { entry: f.plan.files[0], content: Buffer.from(body) }; },
  }, ['materialize']);
  return module.materialize(f.plan, f.config, f.workspace, f.abort.signal) as Promise<string>;
}

for (const copyName of ['snapshot', 'repository', 'sdk-repository', 'sdk-projection-control', 'osv-database', 'trivy-unused', 'trivy-probe-snapshot-unused', 'output-check-unused']) test(`a registered but never created ${copyName} is forgotten without a cleanup failure`, async t => {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace), copy = owner.register(f.workspace, path.join(f.workspace, copyName)); let stderr = '';
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  assert.deepEqual(await owner.cleanup(), { status: 'removed' }); assert.equal(cleanupModule.sourceCleanupFailed(), false); assert.equal(stderr, '');
  await fs.mkdir(copy); await fs.writeFile(path.join(copy, 'unrelated'), 'later directory');
  assert.deepEqual(await owner.cleanup(), { status: 'removed' }); assert.equal(cleanupModule.sourceCleanupFailed(), false); assert.equal(stderr, '');
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'later directory');
});

test('a never created copy does not prevent removal of its disposable workspace', async t => {
  const workspace = await privateWorkspace(undefined, { disposable: true }), owner = sourceCleanupFor(workspace); let stderr = '';
  owner.register(workspace, workspace); owner.register(workspace, path.join(workspace, 'snapshot'));
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  assert.deepEqual(await owner.cleanup(), { status: 'removed' }); await absent(workspace);
  assert.equal(cleanupModule.sourceCleanupFailed(), false); assert.equal(stderr, '');
});

test('disposable cleanup preserves a replacement inside a nested workspace', async () => {
  const workspace = await privateWorkspace(undefined, { disposable: true }), owner = sourceCleanupFor(workspace), head = path.join(workspace, 'head');
  owner.register(workspace, workspace); await fs.mkdir(head);
  const snapshot = owner.register(head, path.join(head, 'snapshot'));
  await fs.mkdir(snapshot); await owner.capture(head, snapshot); await fs.writeFile(path.join(snapshot, name), body);
  await fs.rename(snapshot, snapshot + '-held'); await fs.mkdir(snapshot); await fs.writeFile(path.join(snapshot, 'unrelated'), 'replacement');
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.equal(await fs.readFile(path.join(snapshot, 'unrelated'), 'utf8'), 'replacement');
  assert.equal(await fs.readFile(path.join(snapshot + '-held', name), 'utf8'), body);
});

test('an unrecorded copy whose existence cannot be checked still fails cleanup', async t => {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace), copy = owner.register(f.workspace, path.join(f.workspace, 'snapshot')), lstat = fs.lstat; let stderr = '';
  const read = t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    if (args[0] === copy) throw Object.assign(new Error('identity read failed'), { code: 'EIO' }); return lstat(...args);
  });
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  assert.deepEqual(await owner.cleanup(), { status: 'failed', code: 'source_cleanup_failed' }); assert.equal(cleanupModule.sourceCleanupFailed(), true); assert.equal(stderr, '');
  read.mock.restore(); await fs.mkdir(copy); await fs.writeFile(path.join(copy, 'unrelated'), 'unrecorded');
  assert.deepEqual(await owner.cleanup(), { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'unrecorded');
  assert.equal(stderr, `ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(copy)}\n`);
});

for (const copyName of ['snapshot', 'repository', 'sdk-repository', 'sdk-projection-control', 'osv-database', 'trivy-', 'trivy-probe-snapshot-', 'output-check-']) test(`unrecorded ${copyName} identity preserves a replacement after a creation read failure`, async t => {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace), lstat = fs.lstat, failure = Object.assign(new Error('identity read failed'), { code: 'EIO' });
  let copy = '', held = '', stderr = '';
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    const file = String(args[0]);
    if (!copy && path.dirname(file) === f.workspace && path.basename(file).startsWith(copyName) && args[1]?.bigint) {
      copy = file; held = file + '-held'; await fs.writeFile(path.join(file, 'created'), body);
      await fs.rename(file, held); await fs.mkdir(file); await fs.writeFile(path.join(file, 'unrelated'), 'replacement');
      throw failure;
    }
    return lstat(...args);
  });
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  const create = async () => {
    if (copyName.endsWith('-')) return owner.directory(f.workspace, copyName);
    const directory = owner.register(f.workspace, path.join(f.workspace, copyName)); await fs.mkdir(directory);
    await owner.capture(f.workspace, directory); return directory;
  };
  await assert.rejects(create(), error => error === failure);
  assert.notEqual(copy, ''); assert.deepEqual(await owner.cleanup(), { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'replacement'); assert.equal(await fs.readFile(path.join(held, 'created'), 'utf8'), body);
  assert.equal(cleanupModule.sourceCleanupFailed(), true);
  assert.equal(stderr, `ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(copy)}\n`);
  assert.deepEqual(await owner.cleanup(), { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'replacement');
  const later = await command(async () => 0);
  assert.equal(later.code, 4); assert.deepEqual(JSON.parse(later.stderr), JSON.parse(staticError('source_cleanup_failed')));
});

test('a pre-existing fixed snapshot is never adopted or removed after materialization fails', async t => {
  const f = await fixture(), snapshot = path.join(f.workspace, 'snapshot'); let stderr = '';
  await fs.mkdir(snapshot); await fs.writeFile(path.join(snapshot, 'unrelated'), 'pre-existing');
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  await assert.rejects(copiedSnapshot(f), { code: 'EEXIST' });
  assert.deepEqual(await sourceCleanupFor(f.workspace).cleanup(), { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(snapshot, 'unrelated'), 'utf8'), 'pre-existing'); await absent(path.join(snapshot, name));
  assert.equal(cleanupModule.sourceCleanupFailed(), true);
  assert.equal(stderr, `ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(snapshot)}\n`);
  const later = await command(async () => 0);
  assert.equal(later.code, 4); assert.deepEqual(JSON.parse(later.stderr), JSON.parse(staticError('source_cleanup_failed')));
});

test('fixed snapshot identity survives final checkpoint replacement and makes the scan ERROR', async () => {
  const f = await fixture(), snapshot = path.join(f.workspace, 'snapshot'), held = snapshot + '-held';
  let saves = 0;
  const module = await loaded('src/controller.ts', { ...safety, ...copyBudget, ...jobDisk, ...cleanupModule, path, randomUUID, catalogIdentity, emptyRun,
    createAdapters: () => [], decide, exitCodes, scopedProcessOwner: () => undefined, verifyEngineCatalog, comparisonSummary, CheckpointOwnerStop, verifySnapshot,
    materialize: () => copiedSnapshot(f), openEngineCheckpoints: async () => ({ save: async () => {
      if (++saves !== legacyEngines.length) return;
      await fs.rename(snapshot, held); await fs.mkdir(snapshot); await fs.writeFile(path.join(snapshot, 'unrelated'), 'replacement');
    } }),
  }, ['scan']);
  const adapters: Adapter[] = legacyEngines.map(engine => ({ capabilities: () => ({ engine }), run: async context => ({ ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' }) } as Adapter));
  const report: Report = await module.scan(f.plan, f.config, f.workspace, f.abort.signal, adapters);
  assert.equal(report.gate, 'ERROR'); assert.equal(report.exitCode, 4); assert.deepEqual(report.integrityErrors, ['source_cleanup_failed']);
  assert.equal(await fs.readFile(path.join(snapshot, 'unrelated'), 'utf8'), 'replacement'); assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
});

test('fixed acquisition identity preserves a replacement repository', async () => {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace), root = path.join(f.workspace, 'repository'), held = root + '-held';
  const execute = async (_tool: unknown, args: string[]) => {
    let stdout = '';
    if (args.includes('--version')) stdout = process.versions.node;
    if (args.includes('ls-remote')) stdout = 'a'.repeat(40) + '\tHEAD\n';
    if (args.includes('fetch')) await fs.writeFile(path.join(root, name), body);
    if (args.includes('update-ref')) { await fs.rename(root, held); await fs.mkdir(root); await fs.writeFile(path.join(root, 'unrelated'), 'replacement'); }
    return { reason: 'exit', code: 0, stdout: Buffer.from(stdout) };
  };
  const module = await loaded('src/github.ts', { ...safety, path, ...fs, sourceCleanupFor, execute }, ['fetchGitHub']);
  await module.fetchGitHub('https://github.com/example/fixture', f.config, f.workspace, f.abort.signal, f.abort.signal);
  assert.equal((await owner.cleanup()).status, 'failed'); assert.equal(cleanupModule.sourceCleanupFailed(), true);
  assert.equal(await fs.readFile(path.join(root, 'unrelated'), 'utf8'), 'replacement'); assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
});

for (const name of ['sdk-repository', 'sdk-projection-control']) test(`fixed projection identity preserves a replacement ${name}`, async () => {
  const f = await fixture(); await copiedSnapshot(f);
  const { result } = await projection(f); assert.equal(result.status, 'completed', JSON.stringify(result));
  const copy = path.join(f.workspace, name), held = copy + '-held';
  await fs.writeFile(path.join(copy, 'owned'), body); await fs.rename(copy, held); await fs.mkdir(copy); await fs.writeFile(path.join(copy, 'unrelated'), 'replacement');
  assert.equal((await sourceCleanupFor(f.workspace).cleanup()).status, 'failed'); assert.equal(cleanupModule.sourceCleanupFailed(), true);
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'replacement'); assert.equal(await fs.readFile(path.join(held, 'owned'), 'utf8'), body);
});

test('disposable workspace cleanup also preserves a replaced recorded copy', async () => {
  const f = await fixture(), workspace = await privateWorkspace(f.root, { disposable: true }), owner = sourceCleanupFor(workspace);
  const copy = await copiedSnapshot({ ...f, workspace }), held = copy + '-held'; owner.register(workspace, workspace);
  await fs.rename(copy, held); await fs.mkdir(copy); await fs.writeFile(path.join(copy, 'unrelated'), 'replacement');
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.equal(await fs.readFile(path.join(copy, 'unrelated'), 'utf8'), 'replacement'); assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
});

for (const blocked of [false, true]) test(`projection timeout returns before an unclosed ACL child, cleanup blocked=${blocked}`, { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(), children: EventEmitter[] = []; f.config.timeoutMs = 100;
  let now = 0, closed = false, expire: () => void = () => assert.fail('projection must arm its timeout');
  f.plan.policyHash = safety.digest(f.config); f.plan.planHash = safety.digest({ ...f.plan, planHash: '' }); await copiedSnapshot(f);
  const spawnChild = (() => {
    const child = Object.assign(new EventEmitter(), { kill: () => false }); children.push(child);
    if (children.length === 1) queueMicrotask(() => child.emit('close', 0));
    else { child.once('close', () => { closed = true; }); queueMicrotask(() => { now = f.config.timeoutMs; expire(); }); }
    return child;
  }) as unknown as typeof spawn;
  const copy = path.join(f.workspace, 'sdk-repository'), rmdir = fs.rmdir;
  if (blocked) t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (args[0] === copy) throw Object.assign(new Error('locked'), { code: 'EBUSY' }); return rmdir(...args);
  });
  // Freeze the projection clock during setup, then expire only once the second ACL child exists.
  const deadline = new AbortController(), operation = projection(f, 'success', spawnChild, {
    performance: { now: () => now },
    setTimeout: (callback: () => void, timeoutMs: number) => { assert.equal(timeoutMs, f.config.timeoutMs); expire = callback; }, clearTimeout: () => {},
  });
  try {
    const observed = await Promise.race([operation, delay(10000, null, { signal: deadline.signal })]);
    assert.notEqual(observed, null, 'projection must return without the ACL close event');
    assert.equal(observed!.copied, true, JSON.stringify(observed!.result)); assert.equal(children.length, 2); assert.equal(observed!.result.status, 'termination_unverified');
    assert.equal(observed!.result.reason, 'projection_stopped'); assert.equal(closed, false, 'projection returned before the second ACL child closed');
    assert.equal(cleanupModule.sourceCleanupFailed(), blocked);
    if (blocked) assert.ok(observed!.result.errors.includes('source_cleanup_failed')); else await absent(copy);
    await absent(path.join(f.workspace, 'sdk-projection-control')); await absent(path.join(f.workspace, 'sdk-projection.json'));
  } finally { deadline.abort(); for (const child of children) child.emit('close', 1); await operation; }
});

for (const reason of ['artifact_changed', 'evidence_changed'] as const) test(`publisher cleanup failure preserves ${reason} and both command diagnostics`, async t => {
  const f = await fixture(), workspaces: string[] = [], file = path.join(f.root, name), rmdir = fs.rmdir;
  const module = await loaded('src/runtime-admission.ts', { ...safety, ...copyBudget, ...jobDisk, ...provenance, path, ...fs, constants: { COPYFILE_EXCL: 1 }, sourceCleanupFor,
    privateWorkspace: async (...args: Parameters<typeof privateWorkspace>) => { const workspace = await privateWorkspace(...args); workspaces.push(workspace); return workspace; },
    executeDirect: () => assert.fail('changed artifact or evidence cannot reach the verifier'),
  }, ['verifyPublisher']);
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (workspaces.includes(String(args[0]))) throw Object.assign(new Error('locked'), { code: 'EBUSY' }); return rmdir(...args);
  });
  const check: provenance.PublisherCheck = { component: 'osv', file, ledgerSeq: 1,
    expected: { sha256: reason === 'artifact_changed' ? 'a'.repeat(64) : safety.hash(body), repository: 'example/fixture', certIdentity: 'https://example.invalid/cert', oidcIssuer: 'https://example.invalid/issuer', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted', sourceRef: 'refs/tags/v1', sourceDigest: 'b'.repeat(40) },
    bundle: { path: file, sha256: 'a'.repeat(64) }, trustedRoot: { path: file, sha256: safety.hash(body) } };
  const policy: Parameters<typeof provenance.decideProvenance>[0] = { schema: 'scanmux.runtime-policy/v2', id: '0f8e2c4a-6b1d-4e3f-9a7c-5d2b8e1f0a63', revision: 1, state: 'active', deny: [],
    provenance: { verifier: f.config.tools.git!, ledger: { path: file, entries: 1, head: 'c'.repeat(64) }, require: [] } };
  const result = await command(async () => {
    const outcome = await module.verifyPublisher(policy, check, { timeoutMs: 10000 }); assert.equal(outcome, reason);
    const decision = provenance.decideProvenance(policy, check, outcome); assert.equal(decision.kind, 'refused');
    const error = new provenance.ProvenanceRefusalError(decision as provenance.ProvenanceRefusal);
    process.stderr.write(staticError(error.code, error.policy, error.engine) + '\n'); return 4;
  });
  const errors = result.stderr.trim().split('\n').map(line => JSON.parse(line)); assert.equal(result.code, 4);
  assert.equal(errors[0].error, 'provenance_unverifiable_osv'); assert.equal(errors[0].engine.reason, reason); assert.equal(errors[1].error, 'source_cleanup_failed');
});

for (const replaced of [false, true]) test(`first registration records an existing workspace identity, replaced=${replaced}`, async () => {
  const workspace = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-')), owner = new SourceCleanupOwner(), copy = owner.register(workspace, path.join(workspace, 'snapshot'));
  await fs.mkdir(copy); await owner.capture(workspace, copy); await fs.writeFile(path.join(copy, name), body);
  if (replaced) { await fs.rename(workspace, workspace + '-held'); await fs.mkdir(copy, { recursive: true }); await fs.writeFile(path.join(copy, name), 'replacement'); }
  assert.equal((await owner.cleanup()).status, replaced ? 'failed' : 'removed');
  if (replaced) assert.equal(await fs.readFile(path.join(copy, name), 'utf8'), 'replacement'); else await absent(copy);
});

test('live cleanup refuses a nondisposable workspace and preserves its report', async () => {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace); owner.register(f.workspace, f.workspace);
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
});

test('a replaced workspace makes an otherwise successful scan ERROR with a nonzero exit code', async () => {
  const f = await fixture(), snapshot = path.join(f.workspace, 'snapshot'), held = f.workspace + '-held';
  let saves = 0;
  const module = await loaded('src/controller.ts', { ...safety, ...copyBudget, ...jobDisk, ...cleanupModule, path, randomUUID, catalogIdentity, emptyRun,
    createAdapters: () => [], decide, exitCodes, scopedProcessOwner: () => undefined, verifyEngineCatalog, comparisonSummary, CheckpointOwnerStop, verifySnapshot,
    materialize: async () => { const owner = sourceCleanupFor(f.workspace); owner.register(f.workspace, snapshot); await fs.mkdir(snapshot); await owner.capture(f.workspace, snapshot); await fs.writeFile(path.join(snapshot, name), body); return snapshot; },
    openEngineCheckpoints: async () => ({ save: async () => {
      if (++saves !== legacyEngines.length) return;
      await fs.rename(f.workspace, held); await fs.mkdir(snapshot, { recursive: true }); await fs.writeFile(path.join(snapshot, 'unrelated'), 'replacement');
    } }),
  }, ['scan']);
  const adapters: Adapter[] = legacyEngines.map(engine => ({ capabilities: () => ({ engine }), run: async context => ({ ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' }) } as Adapter));
  const report: Report = await module.scan(f.plan, f.config, f.workspace, f.abort.signal, adapters);
  assert.equal(saves, legacyEngines.length); assert.equal(report.gate, 'ERROR'); assert.notEqual(report.exitCode, 0);
  assert.ok(report.integrityErrors.includes('source_cleanup_failed'));
  assert.equal(await fs.readFile(path.join(snapshot, 'unrelated'), 'utf8'), 'replacement');
  assert.equal(await fs.readFile(path.join(held, 'snapshot', name), 'utf8'), body);
});


for (const mode of ['success', 'engine_failure', 'cancellation', 'partial_projection', 'termination_unverified', 'materialization_failure']) {
  test(`${mode} removes every registered source copy and preserves reports, checkpoints and the original`, async () => {
    const f = await fixture(), scan = await controller(f, mode), report = await scan.scan();
    assert.equal(report.gate === 'PASS', mode === 'success', JSON.stringify(report.integrityErrors));
    for (const directory of ['snapshot', 'sdk-repository', 'sdk-projection-control', 'repository']) await absent(path.join(f.workspace, directory));
    assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
    assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body);
    if (!['partial_projection', 'materialization_failure'].includes(mode)) assert.ok((await fs.readdir(path.join(f.workspace, 'checkpoints'))).length);
    if (mode === 'success') assert.equal(scan.verified(), legacyEngines.length);
    if (mode === 'termination_unverified') assert.ok(report.integrityErrors.includes('termination_unverified'));
  });
}

for (const mode of ['partial_projection', 'projection_cancelled', 'projection_termination_unverified']) test(`${mode} cleans a half-written projection before returning`, async () => {
  const f = await fixture(), owner = new SourceCleanupOwner();
  await fs.mkdir(path.join(f.workspace, 'snapshot')); await fs.writeFile(path.join(f.workspace, 'snapshot', name), body);
  const { result, copied } = await withSourceCleanup(owner, () => projection(f, mode));
  assert.equal(copied, true, JSON.stringify(result)); assert.notEqual(result.status, 'completed');
  for (const directory of ['sdk-repository', 'sdk-projection-control']) await absent(path.join(f.workspace, directory));
  assert.equal(await fs.readFile(path.join(f.workspace, 'snapshot', name), 'utf8'), body);
});


for (const type of ['junction', 'dir'] as const) test(`${type} links inside a copy are removed without touching their target; root and ancestor links are refused`, async () => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'), link = path.join(copy, 'link'), alias = path.join(f.workspace, 'alias');
  await fs.mkdir(copy); await fs.symlink(f.root, link, type);
  assert.deepEqual(await safeRemove(copy), { status: 'removed' });
  assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body);
  await fs.symlink(f.root, alias, type);
  assert.deepEqual(await safeRemove(alias), { status: 'failed', code: 'source_cleanup_failed' });
  assert.deepEqual(await safeRemove(path.join(alias, 'nested')), { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body);
  await fs.unlink(alias);
});

for (const operation of ['unlink', 'rmdir'] as const) test(`a parent junction swap just before ${operation} stops removal without touching the outside target`, async () => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'), parent = path.join(copy, 'parent'), held = path.join(copy, 'held');
  const target = path.join(parent, operation === 'unlink' ? name : 'empty');
  await fs.mkdir(parent, { recursive: true });
  if (operation === 'unlink') await fs.writeFile(target, body);
  else { await fs.mkdir(target); await fs.mkdir(path.join(f.root, 'empty')); }
  const module = await loaded('src/safe-remove.ts', { fs, path, delay }, ['removeDirectory']);
  let swapped = false;
  const result = await module.removeDirectory(copy, { beforeDelete: async (file: string) => {
    if (file !== target || swapped) return;
    swapped = true; await fs.rename(parent, held); await fs.symlink(f.root, parent, 'junction');
  } });
  assert.equal(swapped, true); assert.deepEqual(result, { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body);
  if (operation === 'unlink') assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
  else { assert.ok((await fs.lstat(path.join(f.root, 'empty'))).isDirectory()); assert.ok((await fs.lstat(path.join(held, 'empty'))).isDirectory()); }
  await fs.unlink(parent);
});

test('a copy root replaced by a real directory before deletion is refused', async () => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'), held = path.join(f.workspace, 'held'), file = path.join(copy, name);
  await fs.mkdir(copy); await fs.writeFile(file, body);
  const module = await loaded('src/safe-remove.ts', { fs, path, delay }, ['removeDirectory']);
  const result = await module.removeDirectory(copy, { beforeDelete: async (target: string) => {
    if (target !== file) return;
    await fs.rename(copy, held); await fs.mkdir(copy); await fs.writeFile(file, 'new data');
  } });
  assert.deepEqual(result, { status: 'failed', code: 'source_cleanup_failed' });
  assert.equal(await fs.readFile(file, 'utf8'), 'new data'); assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
});

test('sharing violations are retried briefly and a later successful unlink is reported as removed', async t => {
  const f = await fixture(), directory = path.join(f.workspace, 'snapshot'), file = path.join(directory, name), unlink = fs.unlink;
  await fs.mkdir(directory); await fs.writeFile(file, body);
  let attempts = 0;
  t.mock.method(fs, 'unlink', async (...args: Parameters<typeof fs.unlink>) => {
    if (args[0] === file && ++attempts < 3) throw Object.assign(new Error(), { code: 'EBUSY' });
    return unlink(...args);
  });
  assert.deepEqual(await safeRemove(directory), { status: 'removed' }); assert.equal(attempts, 3);
});

for (const replacement of ['junction', 'file'] as const) test(`directory identity remains fixed across retries when a child becomes a ${replacement}`, async t => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'), child = path.join(copy, 'child'), held = path.join(f.workspace, 'held'), unlink = fs.unlink;
  const file = path.join(child, name);
  await fs.mkdir(child, { recursive: true }); await fs.writeFile(file, body);
  let swapped = false;
  t.mock.method(fs, 'unlink', async (...args: Parameters<typeof fs.unlink>) => {
    if (args[0] === file && !swapped) {
      swapped = true; await fs.rename(child, held);
      if (replacement === 'junction') await fs.symlink(f.root, child, 'junction'); else await fs.writeFile(child, 'new data');
      throw Object.assign(new Error(), { code: 'EBUSY' });
    }
    return unlink(...args);
  });
  assert.deepEqual(await safeRemove(copy), { status: 'failed', code: 'source_cleanup_failed' }); assert.equal(swapped, true);
  assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body); assert.equal(await fs.readFile(path.join(held, name), 'utf8'), body);
  if (replacement === 'junction') { assert.equal((await fs.lstat(child)).isSymbolicLink(), true); await fs.unlink(child); }
  else assert.equal(await fs.readFile(child, 'utf8'), 'new data');
});


for (const mode of ['success', 'failed', 'cancelled', 'termination_unverified']) test(`GitHub acquisition ${mode} is removed at command exit, including partial fetch objects`, async () => {
  const f = await fixture(), owner = new SourceCleanupOwner(), root = path.join(f.workspace, 'repository');
  let copied = false;
  const execute = async (_tool: unknown, args: string[]) => {
    const result = { reason: 'exit', code: 0 as number | null, stdout: Buffer.alloc(0) };
    if (args.includes('--version')) result.stdout = Buffer.from(process.versions.node);
    if (args.includes('ls-remote')) result.stdout = Buffer.from('a'.repeat(40) + '\tHEAD\n');
    if (args.includes('init')) await fs.mkdir(path.join(root, '.git'));
    if (args.includes('fetch')) {
      await fs.writeFile(path.join(root, '.git', 'objects'), body); copied = true;
      if (mode === 'failed') result.code = 1;
      if (mode === 'cancelled') f.abort.abort();
      if (mode === 'termination_unverified') { result.reason = mode; result.code = null; }
    }
    return result;
  };
  const module = await loaded('src/github.ts', { mkdir: fs.mkdir, readdir: fs.readdir, lstat: fs.lstat, path, ...safety, execute, sourceCleanupFor }, ['fetchGitHub']);
  await withSourceCleanup(owner, async () => {
    try {
      const call = module.fetchGitHub('https://github.com/example/fixture', f.config, f.workspace, f.abort.signal, new AbortController().signal);
      if (mode === 'success') { await call; assert.ok(await fs.lstat(root)); }
      else { await assert.rejects(call); await absent(root); }
    } finally { assert.equal((await owner.cleanup()).status, 'removed'); }
  });
  assert.equal(copied, true); await absent(root);
  assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
});

for (const mode of ['success', 'materialization_failure', 'termination_unverified']) test(`dependency snapshot ${mode} is removed after verification or partial failure`, async () => {
  const f = await fixture(), owner = new SourceCleanupOwner(), snapshot = path.join(f.workspace, 'snapshot');
  f.plan.lockfiles = [name];
  const module = await loaded('src/dependencies.ts', { ...safety, sourceCleanupFor, withSourceCleanup, verifySnapshot,
    createOsvAdapter: () => ({ run: async (context: Parameters<Adapter['run']>[0]) => ({ ...emptyRun('osv', context),
      execution: mode === 'success' ? 'completed' : 'failed', coverage: 'analyzed', errors: mode === 'termination_unverified' ? ['termination_unverified'] : [] }) }),
    materialize: async () => {
      const owner = sourceCleanupFor(f.workspace); owner.register(f.workspace, snapshot); await fs.mkdir(snapshot); await owner.capture(f.workspace, snapshot); await fs.writeFile(path.join(snapshot, name), body);
      if (mode === 'materialization_failure') throw new safety.SafeError('snapshot_integrity');
      return snapshot;
    },
  }, ['scanLockfiles']);
  await withSourceCleanup(owner, async () => {
    const call = module.scanLockfiles(f.plan, f.config, f.workspace, f.abort.signal);
    if (mode === 'success') await call; else await assert.rejects(call);
  });
  await absent(snapshot);
});

for (const mode of ['success', 'termination_unverified']) test(`output validation ${mode} removes its scratch directory`, async () => {
  const f = await fixture();
  const module = await loaded('src/output.ts', { ...safety, ...jobDisk, path, writeFile: fs.writeFile, sourceCleanupFor, gitleaksConfig, verifyVersion: async () => {},
    execute: async () => ({ reason: mode === 'success' ? 'exit' : mode, code: mode === 'success' ? 0 : null, stdout: Buffer.from('[]') }), jobDiskDiagnostic: () => undefined,
  }, ['checkedText']);
  const call = module.checkedText('retained report', f.config, f.workspace);
  if (mode === 'success') assert.equal(await call, 'retained report'); else await assert.rejects(call, /termination_unverified/);
  assert.deepEqual((await fs.readdir(f.workspace)).filter(file => file.startsWith('output-check-')), []);
});

for (const mode of ['success', 'termination_unverified']) test(`Trivy probe ${mode} removes its private work tree`, { skip: process.platform !== 'win32' && 'Trivy AppContainer is Windows-only' }, async () => {
  const f = await fixture();
  f.config.tools.trivy = { path: path.join(f.root, name), sha256: safety.hash(body), version: '0.76.1' };
  const module = await loaded('src/trivy-adapter.ts', { ...safety, ...copyBudget, ...jobDisk, path, mkdir: fs.mkdir, writeFile: fs.writeFile, sourceCleanupFor, emptyRun,
    scopedProcessOwner: () => ({}), verifiedImage: async () => Buffer.from(body), jobDiskDiagnostic: () => undefined,
    execute: async () => ({ reason: mode === 'success' ? 'exit' : mode, code: mode === 'success' ? 0 : null, stdout: Buffer.from('Version: 0.76.1\n') }),
  }, ['probeTrivy']);
  const run = await module.probeTrivy({ ...f, snapshot: f.root, signal: f.abort.signal, secretsCleared: false });
  assert.equal(run.execution, mode === 'success' ? 'completed' : 'failed');
  if (mode !== 'success') assert.ok(run.errors.includes(mode));
  assert.deepEqual((await fs.readdir(f.workspace)).filter(file => file.startsWith('trivy-')), []);
});

test('Trivy probe refuses non-Windows hosts before creating its private work tree', { skip: process.platform === 'win32' && 'requires a non-Windows host' }, async () => {
  const f = await fixture();
  f.config.tools.trivy = { path: path.join(f.root, name), sha256: safety.hash(body), version: '0.76.1' };
  const { probeTrivy } = await import('../src/trivy-adapter.ts');
  const run = await probeTrivy({ ...f, snapshot: f.root, signal: f.abort.signal, secretsCleared: false });
  assert.equal(run.execution, 'not_started'); assert.deepEqual(run.errors, ['process_appcontainer_unsupported_platform']);
  assert.deepEqual((await fs.readdir(f.workspace)).filter(file => file.startsWith('trivy-')), []);
  assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
});

for (const mode of ['success', 'termination_unverified']) test(`publisher admission ${mode} removes all copied artifacts`, async () => {
  const f = await fixture(), workspaces: string[] = [], original = path.join(f.root, name);
  const module = await loaded('src/runtime-admission.ts', { ...safety, ...copyBudget, ...jobDisk, ...provenance, path, copyFile: fs.copyFile, readFile: fs.readFile, constants: { COPYFILE_EXCL: 1 }, sourceCleanupFor,
    privateWorkspace: async (...args: Parameters<typeof privateWorkspace>) => { const workspace = await privateWorkspace(...args); workspaces.push(workspace); return workspace; },
    verifyVersion: async () => {}, evaluateGhVerification: () => 'verified', jobDiskDiagnostic: () => undefined,
    executeDirect: async () => ({ reason: mode === 'success' ? 'exit' : mode, code: mode === 'success' ? 0 : null, jobDiskStopped: mode !== 'success', stdout: Buffer.from('{}') }),
  }, ['verifyPublisher']);
  const check = { file: original, expected: { sha256: safety.hash(body) }, bundle: { path: original, sha256: safety.hash(body) }, trustedRoot: { path: original, sha256: safety.hash(body) } };
  const call = module.verifyPublisher({ provenance: { verifier: {} } }, check, { timeoutMs: 10000 });
  if (mode === 'success') assert.equal(await call, 'verified'); else await assert.rejects(call, /termination_unverified/);
  assert.equal(workspaces.length, 1); for (const workspace of workspaces) await absent(workspace);
});

test('workspace-creation-swap: creation identity precedes ACL and rejects the replacement before adoption', async t => {
  const lstat = fs.lstat;
  let swapped = false, held = '', replacement = '';
  t.mock.method(fs, 'lstat', async (...args: Parameters<typeof fs.lstat>) => {
    const file = String(args[0]);
    if (!swapped && path.dirname(file) === path.join(tmpdir(), 'scanmux-private') && path.basename(file).startsWith('scanmux-') && args[1]?.bigint) {
      swapped = true; held = file + '-held'; replacement = file;
      await fs.rename(file, held); await fs.mkdir(file); await fs.writeFile(path.join(file, 'unrelated'), 'replacement');
    }
    return lstat(...args);
  });
  await assert.rejects(privateWorkspace(undefined, { disposable: true }), /source_cleanup_failed/);
  assert.equal(swapped, true); assert.ok(await fs.lstat(held));
  const owner = sourceCleanupFor(replacement); owner.register(replacement, replacement);
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.equal(await fs.readFile(path.join(replacement, 'unrelated'), 'utf8'), 'replacement');
  await absent(path.join(replacement, 'empty-gitconfig'));
});

for (const field of ['dev', 'ino', 'birthtimeNs'] as const) for (const root of ['copy', 'workspace']) test(`removal checks the recorded ${root} ${field} before touching source`, async () => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'); await fs.mkdir(copy); await fs.writeFile(path.join(copy, name), body);
  const identity = await fs.lstat(copy, { bigint: true }), workspace = await fs.lstat(f.workspace, { bigint: true });
  const mismatch = (stat: typeof identity) => ({ dev: stat.dev, ino: stat.ino, birthtimeNs: stat.birthtimeNs, [field]: stat[field] + 1n });
  assert.equal((await safeRemove(copy, root === 'copy' ? mismatch(identity) : identity,
    { directory: f.workspace, identity: root === 'workspace' ? mismatch(workspace) : workspace })).status, 'failed');
  assert.equal(await fs.readFile(path.join(copy, name), 'utf8'), body);
});

async function blockedSource(t: TestContext) {
  const f = await fixture(), owner = sourceCleanupFor(f.workspace), copy = owner.register(f.workspace, path.join(f.workspace, 'snapshot'));
  await fs.mkdir(copy); await owner.capture(f.workspace, copy); await fs.writeFile(path.join(copy, name), body);
  const rmdir = fs.rmdir;
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (args[0] === copy) throw Object.assign(new Error('locked'), { code: 'EBUSY' }); return rmdir(...args);
  });
  assert.equal((await owner.cleanup()).status, 'failed');
  return { ...f, owner, copy };
}

async function command(runMain: () => Promise<number>) {
  const source = stripTypeScriptTypes(await fs.readFile('src/cli.ts', 'utf8'));
  const wrapper = source.slice(source.indexOf('export async function main('), source.indexOf('async function runMain(')).replace(/^export /, '');
  const main = Function('SourceCleanupOwner', 'withSourceCleanup', 'sourceCleanupFailed', 'staticError', 'runMain', wrapper + '\nreturn main;')(
    SourceCleanupOwner, withSourceCleanup, cleanupModule.sourceCleanupFailed, staticError, runMain);
  let stderr = '';
  const write = process.stderr.write;
  process.stderr.write = ((chunk: string) => { stderr += chunk; return true; }) as typeof write;
  try { return { code: await main([]), stderr }; } finally { process.stderr.write = write; }
}

for (const site of ['workspace', 'sibling']) test(`${site} creation cleanup failure keeps the ACL error, reports its path only to stderr and poisons later exits`, { skip: process.platform !== 'win32' }, async t => {
  const parent = path.join(tmpdir(), 'scanmux-private'), held = path.join(tmpdir(), 'held'), rmdir = fs.rmdir;
  let retained = '', stdout = '', stderr = '';
  if (site === 'workspace') { await fs.mkdir(parent, { mode: 0o700 }); await protectDirectory(parent); }
  t.mock.method(childProcess, 'spawn', (_file: string, _args: string[], options: { env: NodeJS.ProcessEnv }) => {
    retained = options.env.SCANMUX_PRIVATE_DIR!;
    const child = new EventEmitter();
    void (async () => {
      if (site === 'workspace') { await fs.rename(retained, held); await fs.mkdir(retained); await fs.writeFile(path.join(retained, 'canary'), 'unchanged'); }
    })().then(() => child.emit('close', 1), error => child.emit('error', error));
    return child;
  });
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (site === 'sibling' && String(args[0]).startsWith(parent + '.')) throw Object.assign(new Error('locked'), { code: 'EBUSY' }); return rmdir(...args);
  });
  t.mock.method(process.stdout, 'write', (chunk: string) => { stdout += chunk; return true; });
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  syncBuiltinESMExports();
  const code = await main(['doctor', '--json']);
  t.mock.restoreAll(); syncBuiltinESMExports();
  assert.equal(code, 4); assert.equal(stdout, ''); assert.equal(cleanupModule.sourceCleanupFailed(), true);
  const lines = stderr.trim().split('\n'), errors = lines.filter(line => line.startsWith('{')).map(line => JSON.parse(line));
  assert.deepEqual(errors, [JSON.parse(staticError('private_acl_unverified')), JSON.parse(staticError('source_cleanup_failed'))]);
  assert.equal(lines.filter(line => !line.startsWith('{')).length, 1); assert.ok(stderr.includes(JSON.stringify(retained)));
  assert.equal(JSON.stringify(errors).includes(JSON.stringify(retained).slice(1, -1)), false);
  if (site === 'workspace') { assert.deepEqual(await fs.readdir(held), []); assert.equal(await fs.readFile(path.join(retained, 'canary'), 'utf8'), 'unchanged'); }
  else assert.deepEqual(await fs.readdir(retained), []);
  const later = await command(async () => 0);
  assert.equal(later.code, 4); assert.deepEqual(JSON.parse(later.stderr), JSON.parse(staticError('source_cleanup_failed')));
  const report = await cleanupScan(await fixture());
  assert.equal(report.gate, 'ERROR'); assert.equal(report.exitCode, 4); assert.deepEqual(report.integrityErrors, ['source_cleanup_failed']);
  assert.equal(JSON.stringify(report).includes(JSON.stringify(retained).slice(1, -1)), false);
});

test('earlier-workspace-failure: a later successful scan and command both retain source_cleanup_failed', async t => {
  const old = await blockedSource(t), f = await fixture();
  const report = await cleanupScan(f);
  assert.equal(report.gate, 'ERROR'); assert.equal(report.exitCode, 4); assert.equal(report.executionState, 'failed');
  assert.deepEqual(report.integrityErrors, ['source_cleanup_failed']);
  assert.equal(Object.hasOwn(report, 'sourceCleanup'), false);
  const result = await command(async () => 0);
  assert.equal(result.code, 4); assert.equal(JSON.parse(result.stderr).error, 'source_cleanup_failed');
  const stopped = await runBatchJobs({ targets: [{ id: 'not-started', path: f.root }], localRoots: [], controlFiles: [], manifestHash: 'a'.repeat(64) }, f.config, 'scan', AbortSignal.abort(), async () => assert.fail('canceled batch must not start'));
  assert.equal(stopped.exitCode, 4); assert.equal(stopped.gate, 'ERROR');
  assert.deepEqual(stopped.jobs[0].errors, ['cancelled', 'source_cleanup_failed']);
  assert.ok(await fs.lstat(old.copy)); await absent(path.join(f.workspace, 'snapshot'));
  t.mock.restoreAll();
  assert.equal((await old.owner.cleanup()).status, 'removed');
  assert.equal((await command(async () => 0)).code, 4, 'successful removal cannot erase an earlier failure');
});

test('batch-startup: an earlier removal failure reaches the returned report and saved batch.json', async t => {
  const old = await blockedSource(t), f = await fixture(), reports: Report[] = [];
  const module = await loaded('src/batch.ts', { ...safety, ...cleanupModule, path, randomUUID, exitCodes, parseReportLanguage,
    writeFile: fs.writeFile, privateWorkspace, buildPlan: async () => f.plan,
    checkedJson: async (value: unknown) => JSON.stringify(value),
    scan: async (_plan: Plan, _config: Config, workspace: string) => { const report = await cleanupScan({ ...f, workspace }); reports.push(report); return report; },
    saveReportBundle: async (report: Report, _config: Config, workspace: string) => {
      const destination = path.join(workspace, 'report.json'); await fs.writeFile(destination, JSON.stringify(report));
      return { destination, htmlDestination: null, sarif: [] };
    },
  }, ['executeBatch']);
  const config = { ...f.config, tools: {} };
  let result: Awaited<ReturnType<typeof import('../src/batch.ts')['executeBatch']>> | undefined;
  const executed = await command(async () => {
    result = await module.executeBatch({ targets: [{ id: 'target', path: f.root }], localRoots: [f.root], controlFiles: [], manifestHash: 'a'.repeat(64) }, config, 'scan', f.abort.signal);
    return result!.summary.exitCode;
  });
  const saved = JSON.parse(await fs.readFile(result!.destination, 'utf8'));
  assert.equal(executed.code, 4); assert.equal(result!.summary.exitCode, 4); assert.equal(saved.exitCode, 4);
  assert.equal(result!.summary.gate, 'ERROR'); assert.equal(saved.gate, 'ERROR');
  assert.ok(saved.jobs[0].errors.includes('source_cleanup_failed')); assert.equal(reports[0].gate, 'ERROR');
  assert.equal(JSON.parse(await fs.readFile(saved.jobs[0].outputs.report, 'utf8')).gate, 'ERROR');
  assert.ok(await fs.lstat(old.copy));
});

for (const reason of ['termination_unverified', 'exit']) test(`error-overwrite: failed GitHub cleanup preserves ${reason} and the batch stop decision`, async t => {
  const f = await fixture(), copy = path.join(f.workspace, 'repository'), rmdir = fs.rmdir;
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (args[0] === copy) throw Object.assign(new Error(), { code: 'EBUSY' }); return rmdir(...args);
  });
  const execute = async (_tool: unknown, args: string[]) => {
    if (args.includes('--version')) return { reason: 'exit', code: 0, stdout: Buffer.from(process.versions.node) };
    if (args.includes('ls-remote')) return { reason: 'exit', code: 0, stdout: Buffer.from('a'.repeat(40) + '\tHEAD\n') };
    if (args.includes('fetch')) { await fs.writeFile(path.join(copy, name), body); return { reason, code: reason === 'exit' ? 1 : null, stdout: Buffer.alloc(0) }; }
    return { reason: 'exit', code: 0, stdout: Buffer.alloc(0) };
  };
  const module = await loaded('src/github.ts', { ...safety, path, sourceCleanupFor, execute, mkdir: fs.mkdir, readdir: fs.readdir, lstat: fs.lstat }, ['fetchGitHub']);
  const visited: string[] = [];
  const summary = await runBatchJobs({ targets: [{ id: 'first', path: f.root }, { id: 'second', path: f.root }], localRoots: [], controlFiles: [], manifestHash: 'a'.repeat(64) }, f.config, 'scan', f.abort.signal,
    async (target, job, signal, deadline) => { visited.push(target.id); if (target.id === 'first') await module.fetchGitHub('https://github.com/example/fixture', f.config, f.workspace, signal, deadline); else { job.state = 'finished'; job.gate = 'PASS'; } });
  assert.equal(summary.exitCode, 4); assert.equal(summary.gate, 'ERROR');
  assert.ok(summary.jobs[0].errors.includes(reason === 'exit' ? 'public_github_fetch_failed' : 'git_termination_unverified'));
  assert.ok(summary.jobs[0].errors.includes('source_cleanup_failed'));
  assert.equal(summary.stopReason, reason === 'exit' ? null : 'termination_unverified');
  assert.deepEqual(visited, reason === 'exit' ? ['first', 'second'] : ['first']);
  if (reason !== 'exit') assert.deepEqual(summary.jobs[1].errors, ['termination_unverified', 'source_cleanup_failed']);
});

test('leaf-link-chmod: read-only recovery never changes the target of a swapped file link', async t => {
  const f = await fixture(), copy = path.join(f.workspace, 'snapshot'), leaf = path.join(copy, name), held = path.join(f.workspace, 'held');
  const target = path.join(f.root, 'unrelated'); await fs.mkdir(copy); await fs.writeFile(leaf, body); await fs.writeFile(target, 'unrelated'); await fs.chmod(target, 0o444);
  const open = fs.open, unlink = fs.unlink;
  let denied = false, swapped = false;
  t.mock.method(fs, 'unlink', async (...args: Parameters<typeof fs.unlink>) => {
    if (args[0] === leaf && !denied) { denied = true; throw Object.assign(new Error(), { code: 'EPERM' }); } return unlink(...args);
  });
  t.mock.method(fs, 'open', async (...args: Parameters<typeof fs.open>) => {
    if (args[0] === leaf && !swapped) { swapped = true; await fs.rename(leaf, held); await fs.symlink(target, leaf, 'file'); }
    return open(...args);
  });
  try {
    const before = (await fs.stat(target)).mode & 0o222;
    await safeRemove(copy);
    assert.equal(swapped, process.platform === 'win32');
    assert.equal((await fs.stat(target)).mode & 0o222, before); assert.equal(await fs.readFile(target, 'utf8'), 'unrelated');
  } finally { await fs.chmod(target, 0o600); }
});

test('disposable cleanup failure writes neither an ownership file nor a pending journal', async t => {
  const workspace = await privateWorkspace(undefined, { disposable: true }), owner = sourceCleanupFor(workspace), rmdir = fs.rmdir;
  owner.register(workspace, workspace);
  await fs.writeFile(path.join(workspace, 'artifact'), body);
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (args[0] === workspace) throw Object.assign(new Error(), { code: 'EBUSY' }); return rmdir(...args);
  });
  assert.equal((await owner.cleanup()).status, 'failed');
  assert.deepEqual(await fs.readdir(workspace), []);
  assert.deepEqual(await fs.readdir(process.env.LOCALAPPDATA!), []);
  assert.equal(cleanupModule.sourceCleanupFailed(), true);
});

for (const partial of [false, true]) test(`${partial ? 'partial-materialization' : 'verification-order'}: actual materialization registers before copying and keeps source through verification`, async () => {
  const f = await fixture(), snapshot = path.join(f.workspace, 'snapshot'), events: string[] = [];
  const source = stripTypeScriptTypes(await fs.readFile('src/repository.ts', 'utf8'));
  const bodySource = source.slice(source.indexOf('export async function materialize('), source.indexOf('export async function verifySnapshot(')).replace(/^export /, '');
  const materialize = Function('sourceCleanupFor', 'path', 'mkdir', 'readGitBlobs', 'git', 'hash', 'SafeError', 'writeFile', bodySource + '\nreturn materialize;')(
    (workspace: string) => ({ register: (...args: Parameters<typeof SourceCleanupOwner.prototype.register>) => { events.push('registered'); return sourceCleanupFor(workspace).register(...args); },
      capture: (...args: Parameters<typeof SourceCleanupOwner.prototype.capture>) => sourceCleanupFor(workspace).capture(...args) }), path,
    async (...args: Parameters<typeof fs.mkdir>) => { const result = await fs.mkdir(...args); if (args[0] === snapshot && !(typeof args[1] === 'object' && args[1]?.recursive)) events.push('created'); return result; },
    async function* () { yield { entry: f.plan.files[0], content: Buffer.from(body) }; if (partial) throw new safety.SafeError('injected_blob_read_failure'); },
    () => assert.fail('no Git process is needed'), safety.hash, safety.SafeError,
    async (...args: Parameters<typeof fs.writeFile>) => { await fs.writeFile(...args); events.push('copied'); });
  const module = await loaded('src/controller.ts', { ...safety, ...copyBudget, ...jobDisk, ...cleanupModule, path, randomUUID, catalogIdentity, emptyRun, decide, exitCodes,
    createAdapters: () => [], scopedProcessOwner: () => undefined, verifyEngineCatalog, comparisonSummary, CheckpointOwnerStop, materialize,
    verifySnapshot: async (...args: Parameters<typeof verifySnapshot>) => { events.push('post_scan_verified'); assert.equal(await fs.readFile(path.join(snapshot, name), 'utf8'), body); return verifySnapshot(...args); },
    openEngineCheckpoints: async () => ({ save: async () => {} }),
  }, ['scan']);
  const adapters: Adapter[] = legacyEngines.map(engine => ({ capabilities: () => ({ engine }), run: async context => {
    assert.equal(await fs.readFile(path.join(context.snapshot, name), 'utf8'), body); events.push('engine_read_source');
    return { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
  } } as Adapter));
  const report: Report = await module.scan(f.plan, f.config, f.workspace, f.abort.signal, adapters);
  assert.deepEqual(events.slice(0, 3), ['registered', 'created', 'copied']);
  assert.equal(report.gate, partial ? 'ERROR' : 'PASS');
  assert.equal(events.filter(event => event === 'post_scan_verified').length, partial ? 0 : legacyEngines.length);
  if (partial) assert.ok(report.integrityErrors.includes('injected_blob_read_failure'));
  await absent(snapshot); assert.equal(await fs.readFile(path.join(f.workspace, 'report.json'), 'utf8'), 'retained report');
  assert.equal(await fs.readFile(path.join(f.root, name), 'utf8'), body);
});
