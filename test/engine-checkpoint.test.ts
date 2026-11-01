import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import * as fs from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { randomUUID } from 'node:crypto';
import { defaults } from '../src/config.ts';
import { legacyEngines, requiredEngines, trivyEngines, verifyEngineCatalog } from '../src/engine-catalog.ts';
import * as safety from '../src/safety.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { summarizeHistory } from '../src/history.ts';
import { resumeSource } from '../src/resume.ts';
import { ciReceipt, evaluateCi } from '../src/ci.ts';
import type { Adapter, Config, Plan, Report } from '../src/model.ts';
import type * as checkpointModule from '../src/engine-checkpoint.ts';
import type * as controllerModule from '../src/controller.ts';
import * as copyBudgets from '../src/copy-budget.ts';
import * as jobDisk from '../src/job-disk.ts';
import { scopedProcessOwner } from '../src/process-tree.ts';
import * as sourceCleanup from '../src/source-cleanup.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();

const order = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const;
// Execute current source in this realm with test-owned IO/check dependencies. The shipped
// functions have no caller option to bypass persistence, secret checking or sync/close.
async function fixtureModule(file: string, imports: Record<string, unknown>, exports: string[]) {
  const source = stripTypeScriptTypes(await fs.readFile(file, 'utf8'))
    .replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
  return Function(...Object.keys(imports), source + `\nreturn {${exports.join(',')}};`)(...Object.values(imports));
}
async function fixture(options: { open?: typeof fs.open; lstat?: typeof fs.lstat; check?: (text: string) => Promise<string>; trivy?: boolean } = {}) {
  const order = options.trivy ? trivyEngines : legacyEngines;
  const home = await fs.mkdtemp(path.join(tmpdir(), 'engine-checkpoint-test-'));
  test.after(() => removeTempDir(home));
  const root = path.join(home, 'source'), workspace = path.join(home, 'run');
  await fs.mkdir(root); await fs.mkdir(workspace);
  const config: Config = { ...structuredClone(defaults), maxOutputBytes: 1024 * 1024 };
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: safety.hash(root), commit: 'a'.repeat(40), treeHash: 'b'.repeat(40),
    snapshotHash: safety.digest([]), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [], required: [...order],
    policyHash: safety.digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  if (options.trivy) {
    Object.assign(plan, { schema: 'scanmux.plan/v3', files: [{ path: 'Dockerfile', oid: 'c'.repeat(40), bytes: 12, sha256: safety.hash('FROM alpine\n') }],
      trivy: { schema: 'scanmux.trivy-plan/v1', profile: 'embedded-config-v1', inputs: [{ key: 'dockerfile:Dockerfile', kind: 'dockerfile', files: ['Dockerfile'], unresolved: false }] } });
  }
  plan.planHash = safety.digest(plan);
  const now = new Date().toISOString();
  const report: Report = { schema: options.trivy ? 'scanmux.report/v3' : 'scanmux.report/v2', runId: randomUUID(), plan, startedAt: now, endedAt: now, engines: [],
    runner: { platform: process.platform, node: process.version, imageDigest: null, isolation: 'local-static-only' }, executionState: 'completed', coverageState: 'incomplete',
    gate: 'INCOMPLETE', exitCode: 3, reasons: [], integrityErrors: [] };
  const checked: string[] = [];
  const imports = { path, lstat: options.lstat ?? fs.lstat, mkdir: fs.mkdir, open: options.open ?? fs.open,
    checkedText: async (text: string) => { checked.push(text); return options.check ? options.check(text) : text; }, summarizeHistory,
    loadConfig: async () => config, legacyEngines, requiredEngines, trivyEngines, verifyEngineCatalog, ...safety };
  const module = await fixtureModule('src/engine-checkpoint.ts', imports, ['CheckpointOwnerStop', 'validateCheckpointPair', 'openEngineCheckpoints', 'readEngineCheckpoints', 'recoverEngineCheckpoints']) as typeof checkpointModule;
  const add = () => {
    const engine = order[report.engines.length];
    const run = emptyRun(engine, { plan, config, workspace, snapshot: '', signal: new AbortController().signal, secretsCleared: false });
    run.execution = 'completed'; run.coverage = 'analyzed';
    if (engine === 'trivy') run.trivyCoverage = { state: 'analyzed', receipts: [{ unit: 'dockerfile:Dockerfile', state: 'analyzed' }] };
    run.targets = ['日本語/é.ts'];
    report.engines.push(run); return run;
  };
  return { home, root, workspace, config, plan, report, module, checked, add, order, close: () => removeTempDirStrict(home, { recursive: true, force: true }) };
}
async function controller(f: Awaited<ReturnType<typeof fixture>>) {
  return (await fixtureModule('src/controller.ts', { catalogIdentity, randomUUID, rm: fs.rm, path, emptyRun, createAdapters: () => [], decide, exitCodes,
    materialize: async () => { const owner = sourceCleanup.sourceCleanupFor(f.workspace), folder = owner.register(f.workspace, path.join(f.workspace, 'snapshot')); await fs.mkdir(folder); await owner.capture(f.workspace, folder); return folder; }, verifySnapshot: async () => true,
    ...safety, ...copyBudgets, ...jobDisk, ...sourceCleanup, scopedProcessOwner, verifyEngineCatalog, comparisonSummary: () => undefined, openEngineCheckpoints: f.module.openEngineCheckpoints, CheckpointOwnerStop: f.module.CheckpointOwnerStop }, ['scan'])) as typeof controllerModule;
}
function adapters(f: Awaited<ReturnType<typeof fixture>>, visited: string[], before?: (engine: string) => Promise<void>): Adapter[] {
  return f.order.map(engine => ({ capabilities: () => ({ engine }), async run(context: Parameters<Adapter['run']>[0]) {
    visited.push(engine); await before?.(engine);
    return { ...emptyRun(engine, context), execution: 'completed', coverage: 'analyzed' };
  } } as Adapter));
}

test('one through four cumulative checkpoints retain exact engines, usage and Unicode; all remain provisional', async () => {
  const f = await fixture();
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config);
    for (let n = 1; n <= 4; n++) {
      f.add(); await writer.save(f.report, new AbortController().signal);
      const read = await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes);
      assert.equal(read.sequence, n); assert.equal(read.ignoredTail, false);
      assert.deepEqual(read.report.engines, f.report.engines); assert.equal(read.report.runId, f.report.runId);
      assert.equal(read.report.gate, 'ERROR'); assert.equal(read.report.executionState, 'failed'); assert.equal(read.report.coverageState, 'incomplete');
      const bytes = Buffer.from(JSON.stringify(read.report));
      assert.equal(summarizeHistory([bytes]).summary.runs[0].completion, 'incomplete');
      assert.throws(() => resumeSource(bytes, f.root), /resume_requires_stopped_run/);
      const receipt = ciReceipt({ report: read.report, json: bytes.toString() }, randomUUID(), 'checkpoint');
      const expected = { schema: 'scanmux.ci-expectation/v1', ciRun: receipt.ciRun, jobs: [{ id: 'checkpoint', targetRoot: f.root,
        ...Object.fromEntries(['repoId', 'commit', 'policyHash', 'planHash', 'snapshotHash'].map(key => [key, f.plan[key as keyof Plan]])) }] };
      assert.notEqual(evaluateCi(expected, [receipt]).gate, 'PASS');
    }
    const files = await fs.readdir(writer.directory); assert.equal(files.length, 8);
    assert.equal(f.checked.length, 4);
    assert.deepEqual(f.report.integrityErrors, []); assert.equal(f.report.gate, 'INCOMPLETE');
    await assert.rejects(writer.save(f.report, new AbortController().signal), /invalid_engine_checkpoint/);
  } finally { await f.close(); }
});

test('uncommitted body and truncated final receipt preserve prefix; no complete record is unavailable', async () => {
  const f = await fixture();
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config);
    await assert.rejects(f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes), /engine_checkpoint_unavailable/);
    f.add(); await writer.save(f.report, new AbortController().signal);
    const before = await fs.readFile(path.join(writer.directory, 'checkpoint-1.json'));
    await fs.writeFile(path.join(writer.directory, 'checkpoint-2.json'), '{"partial":');
    let read = await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes);
    assert.equal(read.sequence, 1); assert.equal(read.ignoredTail, true);
    await fs.writeFile(path.join(writer.directory, 'commit-2.json'), '{"schema":"scanmux.engine');
    read = await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes);
    assert.equal(read.sequence, 1); assert.equal(read.ignoredTail, true);
    assert.deepEqual(await fs.readFile(path.join(writer.directory, 'checkpoint-1.json')), before);
    await fs.writeFile(path.join(writer.directory, 'commit-2.json'), 'malformed\n');
    await assert.rejects(f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes));
  } finally { await f.close(); }
});

test('complete receipt can be recovered before sync/close/ACK but next engine must wait', async () => {
  const ready = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
  let blocked = false;
  const customOpen = (async (...args: Parameters<typeof fs.open>) => {
    const handle = await fs.open(...args);
    if (String(args[0]).endsWith('commit-1.json')) {
      const sync = handle.sync.bind(handle);
      handle.sync = async () => { blocked = true; ready.resolve(); await release.promise; await sync(); };
    }
    return handle;
  }) as typeof fs.open;
  const f = await fixture({ open: customOpen }); const visited: string[] = [];
  try {
    const c = await controller(f), work = c.scan(f.plan, f.config, f.workspace, new AbortController().signal, adapters(f, visited));
    await ready.promise; assert.equal(blocked, true); assert.deepEqual(visited, ['gitleaks']);
    const saved = await f.module.readEngineCheckpoints(path.join(f.workspace, 'checkpoints'), f.config.maxOutputBytes);
    assert.equal(saved.sequence, 1); assert.equal(saved.report.gate, 'ERROR');
    release.resolve(); const final = await work;
    assert.equal(final.gate, 'PASS'); assert.equal(final.runId, saved.report.runId); assert.deepEqual(visited, order);
    assert.deepEqual(final.integrityErrors, []);
    assert.equal((await f.module.readEngineCheckpoints(path.join(f.workspace, 'checkpoints'), f.config.maxOutputBytes)).report.gate, 'ERROR');
  } finally { release.resolve(); await f.close(); }
});

test('descending receipt observation tolerates live appends but rejects a real gap', async () => {
  let append: (() => Promise<void>) | undefined, triggered = false;
  const customStat = (async (...args: Parameters<typeof fs.lstat>) => {
    try { return await fs.lstat(...args); }
    catch (error) {
      if (!triggered && String(args[0]).endsWith('commit-3.json') && append) { triggered = true; await append(); }
      throw error;
    }
  }) as typeof fs.lstat;
  const f = await fixture({ lstat: customStat });
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config); f.add(); await writer.save(f.report, new AbortController().signal);
    append = async () => { for (let i = 0; i < 2; i++) { f.add(); await writer.save(f.report, new AbortController().signal); } };
    const read = await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes);
    assert.equal(triggered, true); assert.equal(read.sequence, 2);
    assert.equal((await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes)).sequence, 3);
    await fs.unlink(path.join(writer.directory, 'commit-2.json'));
    await assert.rejects(f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes), /invalid_engine_checkpoint/);
  } finally { await f.close(); }
});

test('tampered body, receipt, identity, prefix, UTF8 and size cannot discard evidence into a successful recovery', async () => {
  const cases = ['body', 'receipt', 'run', 'plan', 'prefix', 'sequence', 'predecessor', 'utf8', 'missing-body', 'size'] as const;
  for (const kind of cases) {
    const f = await fixture();
    try {
      const writer = await f.module.openEngineCheckpoints(f.workspace, f.config);
      for (let i = 0; i < 2; i++) { f.add(); await writer.save(f.report, new AbortController().signal); }
      const bodyFile = path.join(writer.directory, 'checkpoint-2.json'), receiptFile = path.join(writer.directory, 'commit-2.json');
      const body = JSON.parse(await fs.readFile(bodyFile, 'utf8')), receipt = JSON.parse(await fs.readFile(receiptFile, 'utf8'));
      if (kind === 'body') await fs.appendFile(bodyFile, ' ');
      else if (kind === 'receipt') { receipt.bytes++; await fs.writeFile(receiptFile, JSON.stringify(receipt) + '\n'); }
      else if (kind === 'utf8') await fs.writeFile(receiptFile, Buffer.from([0xff]));
      else if (kind === 'missing-body') await fs.unlink(bodyFile);
      else if (kind === 'size') await fs.writeFile(bodyFile, Buffer.alloc(f.config.maxOutputBytes + 1));
      else {
        if (kind === 'run') { body.runId = randomUUID(); body.report.runId = body.runId; receipt.runId = body.runId; }
        if (kind === 'plan') body.report.plan.commit = 'c'.repeat(40);
        if (kind === 'prefix') body.report.engines[0].usage.calls = 99;
        if (kind === 'sequence') body.sequence = 4;
        if (kind === 'predecessor') { body.previousSha256 = null; receipt.previousSha256 = null; }
        const text = JSON.stringify(body) + '\n'; receipt.bytes = Buffer.byteLength(text); receipt.sha256 = safety.hash(text);
        await fs.writeFile(bodyFile, text); await fs.writeFile(receiptFile, JSON.stringify(receipt) + '\n');
      }
      await assert.rejects(f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes), kind);
    } finally { await f.close(); }
  }
});

test('existing directory, secret refusal, changed checker bytes, size and file collision fail without overwriting prior data', async () => {
  for (const kind of ['directory', 'secret', 'changed-check', 'size', 'collision']) {
    const f = await fixture({ check: async text => { if (kind === 'secret') throw new safety.SafeError('output_secret_check_failed'); return kind === 'changed-check' ? text + ' ' : text; } });
    try {
      if (kind === 'directory') {
        await fs.mkdir(path.join(f.workspace, 'checkpoints'));
        await assert.rejects(f.module.openEngineCheckpoints(f.workspace, f.config)); continue;
      }
      const writer = await f.module.openEngineCheckpoints(f.workspace, f.config); f.add();
      const collision = path.join(writer.directory, 'checkpoint-1.json');
      if (kind === 'collision') await fs.writeFile(collision, 'preserved');
      if (kind === 'size') f.config.maxOutputBytes = 1;
      await assert.rejects(writer.save(f.report, new AbortController().signal));
      assert.equal(await fs.stat(path.join(writer.directory, 'commit-1.json')).catch(() => null), null);
      if (kind === 'collision') assert.equal(await fs.readFile(collision, 'utf8'), 'preserved');
    } finally { await f.close(); }
  }
});

test('checkpoint sync/close/secret failures outrank simultaneous cancel; completed result and prior prefix remain', async () => {
  for (const kind of ['sync', 'close', 'secret', 'termination_unverified']) {
    const abort = new AbortController();
    const customOpen = (async (...args: Parameters<typeof fs.open>) => {
      const handle = await fs.open(...args);
      if (String(args[0]).endsWith('checkpoint-2.json')) {
        if (kind === 'sync') handle.sync = async () => { abort.abort(); throw new Error('fixture sync failure'); };
        if (kind === 'close') { const close = handle.close.bind(handle); handle.close = async () => { await close(); abort.abort(); throw new Error('fixture close failure'); }; }
      }
      return handle;
    }) as typeof fs.open;
    let checks = 0;
    const f = await fixture({ open: customOpen, check: async text => {
      if (++checks === 2 && ['secret', 'termination_unverified'].includes(kind)) { abort.abort(); throw new safety.SafeError(kind === 'secret' ? 'output_secret_check_failed' : kind); } return text;
    } });
    try {
      const visited: string[] = [], c = await controller(f);
      const result = await c.scan(f.plan, f.config, f.workspace, abort.signal, adapters(f, visited));
      assert.deepEqual(visited, order.slice(0, 2)); assert.equal(result.engines.length, 2);
      assert.equal(result.engines[1].execution, 'completed'); assert.equal(result.gate, 'ERROR'); assert.equal(result.executionState, 'failed');
      assert.ok(result.integrityErrors.includes(kind === 'termination_unverified' ? kind : 'checkpoint_save_failed'));
      const saved = await f.module.readEngineCheckpoints(path.join(f.workspace, 'checkpoints'), f.config.maxOutputBytes);
      assert.equal(saved.sequence, 1); assert.deepEqual(saved.report.engines[0], result.engines[0]);
      assert.equal(Boolean(await fs.stat(path.join(f.workspace, 'snapshot')).catch(() => null)), false);
    } finally { await f.close(); }
  }
});

test('returned termination-unverified result still reaches persistence and removes snapshot', async () => {
  const f = await fixture();
  try {
    const visited: string[] = [], list = adapters(f, visited), first = list[0].run;
    list[0].run = async context => { const run = await first(context); run.execution = 'failed'; run.errors.push('worker_termination_unverified'); return run; };
    const result = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, list);
    assert.deepEqual(visited, ['gitleaks']); assert.equal(result.gate, 'ERROR');
    const saved = await f.module.readEngineCheckpoints(path.join(f.workspace, 'checkpoints'), f.config.maxOutputBytes);
    assert.equal(saved.sequence, 1); assert.deepEqual(saved.report.engines, result.engines.slice(0, 1));
    assert.ok(saved.report.integrityErrors.includes('termination_unverified'));
    assert.equal(await fs.stat(path.join(f.workspace, 'snapshot')).catch(() => null), null);
  } finally { await f.close(); }
});

test('exact serialized byte limit is accepted, one byte less refused; linked parents and inside-target recovery are rejected', async () => {
  const f = await fixture();
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config); f.add(); await writer.save(f.report, new AbortController().signal);
    const size = (await fs.stat(path.join(writer.directory, 'checkpoint-1.json'))).size;
    for (const delta of [0, -1]) {
      const next = path.join(f.home, `boundary-${delta}`); await fs.mkdir(next);
      const config = { ...f.config, maxOutputBytes: size + delta }, bounded = await f.module.openEngineCheckpoints(next, config);
      if (delta === 0) { await bounded.save(f.report, new AbortController().signal); assert.equal((await f.module.readEngineCheckpoints(bounded.directory, size)).sequence, 1); }
      else { await assert.rejects(bounded.save(f.report, new AbortController().signal), /output_size_limit/); assert.deepEqual(await fs.readdir(bounded.directory), []); }
    }
    const linked = path.join(f.home, 'linked'); await fs.symlink(f.workspace, linked, 'junction');
    await assert.rejects(f.module.openEngineCheckpoints(linked, f.config), /linked_path/);
    const inside = path.join(f.root, 'copied-checkpoints'); await fs.cp(writer.directory, inside, { recursive: true });
    await assert.rejects(f.module.recoverEngineCheckpoints(inside, undefined, f.config), /path_inside_target/);
    assert.equal((await f.module.recoverEngineCheckpoints(writer.directory, undefined, f.config)).root, f.root);
  } finally { await f.close(); }
});

test('runtime checkpoint backend preserves exact validated bytes without creating a local durable substitute', async () => {
  const f = await fixture();
  try {
    const pairs: Buffer[][] = [];
    const backend: checkpointModule.EngineCheckpointBackend = { failure: async () => {}, persist: async (body, receipt) => { pairs.push([body, receipt]); } };
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config, backend);
    f.add(); await writer.save(f.report, new AbortController().signal);
    let previous = f.module.validateCheckpointPair(pairs[0][0], pairs[0][1], 1, null);
    assert.deepEqual(previous.checkpoint.report.engines, f.report.engines);
    assert.equal(await fs.stat(writer.directory).catch(() => null), null);
    f.add(); await writer.save(f.report, new AbortController().signal);
    const next = f.module.validateCheckpointPair(pairs[1][0], pairs[1][1], 2, previous);
    assert.deepEqual(next.checkpoint.report.engines, f.report.engines);
    const bad = JSON.parse(pairs[1][1].toString()); bad.runId = randomUUID();
    assert.throws(() => f.module.validateCheckpointPair(pairs[1][0], Buffer.from(JSON.stringify(bad) + '\n'), 2, previous));
    assert.throws(() => f.module.validateCheckpointPair(pairs[1][0], pairs[1][1], 2, null));
  } finally { await f.close(); }
});

test('outside persistence ACK blocks the next adapter; owner budget refusal preserves the last prefix without fabricating IO failure', async () => {
  const f = await fixture();
  try {
    let release!: () => void, entered!: () => void;
    const ready = new Promise<void>(resolve => { entered = resolve; });
    const ack = new Promise<void>(resolve => { release = resolve; });
    let writes = 0;
    const backend: checkpointModule.EngineCheckpointBackend = { failure: async () => {}, persist: async () => {
      if (++writes === 1) { entered(); await ack; }
      else throw new f.module.CheckpointOwnerStop('job_retained_limit');
    } };
    const visited: string[] = [], work = (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, adapters(f, visited), backend);
    await ready; assert.deepEqual(visited, ['gitleaks']); release();
    const result = await work;
    assert.deepEqual(visited, ['gitleaks', 'osv']); assert.equal(result.engines.length, 2);
    assert.equal(result.integrityErrors.includes('checkpoint_save_failed'), false);
    assert.equal(writes, 2);
  } finally { await f.close(); }
});

test('known returned engine failure reaches the outside owner before the next secret/output check', async () => {
  const events: string[] = [], f = await fixture({ check: async text => { events.push('secret-check'); return text; } });
  try {
    const visited: string[] = [], list = adapters(f, visited), first = list[0].run;
    list[0].run = async context => ({ ...await first(context), execution: 'failed' });
    const backend: checkpointModule.EngineCheckpointBackend = { failure: async code => { events.push(code); }, persist: async () => { events.push('persist'); } };
    const result = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, list, backend);
    assert.equal(events[0], 'engine_execution_failed'); assert.ok(events.indexOf('secret-check') > 0);
    assert.equal(result.gate, 'ERROR'); assert.equal(result.engines[0].execution, 'failed');
  } finally { await f.close(); }
});

test('actual outside IO rejection remains an ERROR and blocks subsequent adapters', async () => {
  const f = await fixture();
  try {
    const visited: string[] = [], backend: checkpointModule.EngineCheckpointBackend = {
      failure: async () => {}, persist: async () => { throw Error('fixture actual outside fsync failure'); },
    };
    const result = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, adapters(f, visited), backend);
    assert.deepEqual(visited, ['gitleaks']); assert.equal(result.gate, 'ERROR'); assert.ok(result.integrityErrors.includes('checkpoint_save_failed'));
  } finally { await f.close(); }
});

test('v3 checkpoints recover each of five exact prefixes, reject changed schemas and preserve a truncated tail', async () => {
  const f = await fixture({ trivy: true });
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config);
    for (let sequence = 1; sequence <= 5; sequence++) {
      f.add(); await writer.save(f.report, new AbortController().signal);
      const recovered = await f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes);
      assert.equal(recovered.sequence, sequence); assert.equal(recovered.report.schema, 'scanmux.report/v3');
      assert.deepEqual(recovered.report.engines.map(run => run.engine), trivyEngines.slice(0, sequence));
      assert.equal(recovered.report.gate, 'ERROR');
      const body = await fs.readFile(path.join(writer.directory, `checkpoint-${sequence}.json`));
      const receipt = await fs.readFile(path.join(writer.directory, `commit-${sequence}.json`));
      assert.equal(JSON.parse(body.toString()).schema, 'scanmux.engine-checkpoint/v2');
      assert.equal(JSON.parse(receipt.toString()).schema, 'scanmux.engine-checkpoint-commit/v2');
    }
    await fs.writeFile(path.join(writer.directory, 'commit-5.json'), '{"schema":');
    const prefix = await f.module.recoverEngineCheckpoints(writer.directory, undefined, f.config);
    assert.equal(prefix.sequence, 4); assert.equal(prefix.ignoredTail, true);
    const bodyFile = path.join(writer.directory, 'checkpoint-4.json'), receiptFile = path.join(writer.directory, 'commit-4.json');
    const body = JSON.parse(await fs.readFile(bodyFile, 'utf8')); body.schema = 'scanmux.engine-checkpoint/v1';
    const text = JSON.stringify(body) + '\n'; const receipt = JSON.parse(await fs.readFile(receiptFile, 'utf8'));
    receipt.bytes = Buffer.byteLength(text); receipt.sha256 = safety.hash(text);
    await fs.writeFile(bodyFile, text); await fs.writeFile(receiptFile, JSON.stringify(receipt) + '\n');
    await assert.rejects(f.module.readEngineCheckpoints(writer.directory, f.config.maxOutputBytes), /invalid_engine_checkpoint/);
  } finally { await f.close(); }
});

test('v3 malformed checkpoint bodies return the documented code with stale or matching receipts', async () => {
  const f = await fixture({ trivy: true });
  try {
    const writer = await f.module.openEngineCheckpoints(f.workspace, f.config);
    f.add(); await writer.save(f.report, new AbortController().signal);
    const body = await fs.readFile(path.join(writer.directory, 'checkpoint-1.json'));
    const raw = await fs.readFile(path.join(writer.directory, 'commit-1.json'));
    assert.equal(f.module.validateCheckpointPair(body, raw, 1, null).checkpoint.report.schema, 'scanmux.report/v3');
    for (const malformed of [body.subarray(0, -2), Buffer.from('{'.repeat(body.length))]) {
      for (const rehash of [false, true]) {
        const receipt = JSON.parse(raw.toString());
        if (rehash) { receipt.bytes = malformed.length; receipt.sha256 = safety.hash(malformed); }
        assert.throws(() => f.module.validateCheckpointPair(malformed, Buffer.from(JSON.stringify(receipt) + '\n'), 1, null),
          (error: unknown) => error instanceof safety.SafeError && error.code === 'invalid_engine_checkpoint');
      }
    }
  } finally { await f.close(); }
});

test('v3 saved completion cannot trust a reduced required set or missing, empty or mismatched Trivy receipts', async () => {
  const f = await fixture({ trivy: true });
  try {
    for (let i = 0; i < 5; i++) f.add();
    const bytes = () => Buffer.from(JSON.stringify(f.report));
    f.report.coverageState = 'complete'; f.report.gate = 'PASS';
    assert.equal(summarizeHistory([bytes()]).summary.runs[0].completion, 'complete');
    const run = f.report.engines[4];
    delete run.trivyCoverage;
    assert.equal(summarizeHistory([bytes()]).summary.runs[0].completion, 'incomplete');
    run.trivyCoverage = { state: 'analyzed', receipts: [] as any };
    assert.throws(() => summarizeHistory([bytes()]), /invalid_trivy_coverage/);
    run.trivyCoverage = { state: 'analyzed', receipts: [{ unit: 'dockerfile:unplanned', state: 'analyzed' }] };
    assert.throws(() => summarizeHistory([bytes()]), /invalid_trivy_coverage/);
    f.plan.required.pop();
    assert.throws(() => summarizeHistory([bytes()]), /engine_plan_mismatch/);
  } finally { await f.close(); }
});

test('v3 controller refuses post-plan pin changes and reduced engine catalog before any adapter starts', async () => {
  for (const mutation of ['pin', 'catalog']) {
    const f = await fixture({ trivy: true });
    try {
      const visited: string[] = [], c = await controller(f);
      if (mutation === 'pin') f.config.tools.trivy = { path: process.execPath, sha256: 'f'.repeat(64), version: '0.76.1' };
      else { f.plan.required.pop(); f.plan.planHash = safety.digest({ ...f.plan, planHash: '' }); }
      const result = await c.scan(f.plan, f.config, f.workspace, new AbortController().signal, adapters(f, visited));
      assert.equal(result.schema, 'scanmux.report/v3'); assert.equal(result.gate, 'ERROR'); assert.deepEqual(visited, []);
      assert.deepEqual(result.integrityErrors, [mutation === 'pin' ? 'plan_integrity' : 'engine_plan_mismatch']);
    } finally { await f.close(); }
  }
});


test('copy budget: scan report carries the cause and preserves prior FAIL and ERROR', async () => {
  for (const earlier of ['none', 'FAIL', 'ERROR'] as const) {
    const f = await fixture();
    try {
      const instances = adapters(f, []).map(adapter => ({ ...adapter, async run(context: Parameters<Adapter['run']>[0]) {
        const run = await adapter.run(context);
        if (run.engine === 'osv') { run.execution = 'budget_exceeded'; run.errors.push('job_disk_copy_limit'); }
        if (run.engine === 'gitleaks' && earlier === 'ERROR') run.execution = 'failed';
        if (run.engine === 'gitleaks' && earlier === 'FAIL') run.findings.push({
          fingerprint: 'a'.repeat(64), engine: 'gitleaks', originIds: ['fixture'], severity: 'high', confidence: 'high',
          evidenceState: 'source_supported', disposition: 'open', category: 'secret', file: 'fixture.ts', line: 1,
          title: 'Fixture secret', fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown',
        });
        return run;
      } }));
      const report = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, instances);
      assert.equal(report.gate, earlier === 'none' ? 'INCOMPLETE' : earlier);
      assert.ok(report.reasons.includes('job_disk_copy_limit')); assert.equal(report.executionState, 'budget_exceeded');
    } finally { await f.close(); }
  }
});

for (const command of ['serve', 'scan-list']) test(`copy budget: two ${command} scans each receive their own configured allowance`, async () => {
  const first = await fixture(), second = await fixture();
  try {
    const source = path.join(first.home, 'command-owner'); await fs.writeFile(source, '12');
    const commandConfig = { ...first.config, maxCopyBytes: 3 };
    const code = await fs.readFile('src/cli.ts', 'utf8');
    const withConfig = Function('loadConfig', 'runtimeSubjects', 'startsProcesses', 'withProcessRuntime', 'withCopyBudget', 'SafeError', 'withJobDisk',
      stripTypeScriptTypes(code.slice(code.indexOf('async function withConfig'), code.indexOf('const releaseOnlyOptions'))) + '\nreturn withConfig;')(
      async () => commandConfig, {}, () => true,
      async (_options: unknown, admission: { verify(): Promise<void> }, body: () => Promise<unknown>) => {
        await admission.verify(); await copyBudgets.scopedCopyBudget()!.copy(source, source + '-copy'); return body();
      }, copyBudgets.withCopyBudget, safety.SafeError, jobDisk.withJobDisk);
    await withConfig(command, undefined, new AbortController().signal, undefined, async () => {
      const ownerBudget = copyBudgets.scopedCopyBudget()!;
      for (const [index, f] of [first, second].entries()) {
        f.config.maxCopyBytes = index ? 8 : 4;
        f.plan.policyHash = safety.digest(f.config); f.plan.planHash = safety.digest({ ...f.plan, planHash: '' });
        const source = path.join(f.home, 'asset'); await fs.writeFile(source, '1234'.repeat(index + 1));
        const list = adapters(f, []).map(adapter => ({ ...adapter, async run(context: Parameters<Adapter['run']>[0]) {
          if (adapter.capabilities().engine === 'gitleaks') {
            assert.equal(context.copyBudget?.limit, f.config.maxCopyBytes);
            await context.copyBudget!.copy(source, path.join(f.workspace, 'asset'));
          }
          return adapter.run(context);
        } }));
        const report = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, list);
        assert.equal(report.gate, 'PASS', JSON.stringify(report.integrityErrors));
      }
      assert.equal(ownerBudget.reservedBytes, 2); assert.equal(ownerBudget.remainingBytes, 1);
    });
  } finally { await first.close(); await second.close(); }
});

test('copy budget: a scan without the key does not inherit the command allowance', async () => {
  const f = await fixture();
  try {
    await copyBudgets.withCopyBudget(0, async () => {
      const list = adapters(f, []).map(adapter => ({ ...adapter, async run(context: Parameters<Adapter['run']>[0]) {
        assert.equal(context.copyBudget, undefined); assert.equal(copyBudgets.scopedCopyBudget(), undefined);
        return adapter.run(context);
      } }));
      const report = await (await controller(f)).scan(f.plan, f.config, f.workspace, new AbortController().signal, list);
      assert.equal(report.gate, 'PASS', JSON.stringify(report.integrityErrors));
    });
  } finally { await f.close(); }
});
