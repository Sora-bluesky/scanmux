import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import promises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { defaults, loadConfig } from '../src/config.ts';
import { parseJobProfile, jobLinuxConfig } from '../src/job-config.ts';
import { prepareOfflineDatabase } from '../src/osv-database.ts';
import { main } from '../src/cli.ts';
import { scan } from '../src/controller.ts';
import { emptyRun } from '../src/adapters.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { digest, hash, SafeError } from '../src/safety.ts';
import type { Adapter, Config, Plan } from '../src/model.ts';
import { testProcessOwner, withTestProcessOwner } from './process-owner.ts';
import { startProcessOwner } from '../src/process-tree.ts';
import { sourceCleanupFor } from '../src/source-cleanup.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();

async function api() {
  const name = '../src/copy-budget.ts';
  const module = await import(name).catch(() => undefined);
  assert.ok(module?.CopyBudget, 'the shared pre-write copy budget must exist');
  return module as typeof import('../src/copy-budget.ts');
}
async function fixture(t: test.TestContext) {
  const directory = await promises.mkdtemp(path.join(tmpdir(), 'scanmux-copy-budget-test-'));
  t.after(() => removeTempDirStrict(directory, { recursive: true, force: true }));
  const source = path.join(directory, 'source'); await promises.writeFile(source, '1234');
  const destination = path.join(directory, 'copy');
  return { directory, source, destination };
}
const absent = (file: string) => assert.rejects(promises.lstat(file), { code: 'ENOENT' });
async function invoke(args: string[]) {
  const out: string[] = [], err: string[] = [], stdout = process.stdout.write, stderr = process.stderr.write;
  process.stdout.write = chunk => { out.push(String(chunk)); return true; };
  process.stderr.write = chunk => { err.push(String(chunk)); return true; };
  try { return { code: await main(args), out: out.join(''), err: err.join('') }; }
  finally { process.stdout.write = stdout; process.stderr.write = stderr; }
}
function jobProfile(executable: string) {
  const tool = { path: executable, sha256: hash('1234'), version: '1.2.3' };
  return { schema: 'scanmux.job-profile/v1', name: 'copy_budget', scope: 'offline-local',
    docker: { tool, endpoint: process.platform === 'win32' ? 'npipe:////./pipe/docker' : 'unix:///var/run/docker.sock' }, image: 'sha256:' + 'a'.repeat(64),
    runtime: { nodeVersion: process.versions.node, python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } },
    tools: { gitleaks: tool }, osvDatabase: null,
    scan: { timeoutMs: 10000, maxOutputBytes: 1048576, maxFileBytes: 1048576, maxSnapshotBytes: 8388608, maxFiles: 1000 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576,
      pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 16777216 } };
}

test('copy budget: exact limit copies and accounts every byte', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), budget = new CopyBudget(4);
  assert.deepEqual(await budget.copy(f.source, f.destination), { bytes: 4, sha256: hash('1234') });
  assert.equal(await promises.readFile(f.destination, 'utf8'), '1234'); assert.equal(budget.reservedBytes, 4);
});
test('copy budget: one byte over refuses before creating a destination with the typed cause', async t => {
  const f = await fixture(t), { CopyBudget, JobDiskCopyLimitError } = await api(), budget = new CopyBudget(3);
  await assert.rejects(budget.copy(f.source, f.destination), error => error instanceof JobDiskCopyLimitError && error.code === 'job_disk_copy_limit');
  await absent(f.destination); assert.equal(budget.reservedBytes, 0);
});
test('copy budget: a verified size mismatch is integrity failure even when the job has space', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), budget = new CopyBudget(100);
  await assert.rejects(budget.copy(f.source, f.destination, { maximumBytes: 3 }), { code: 'copy_source_changed' });
  await absent(f.destination);
});
test('copy budget: two concurrent copies share one job reservation', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), budget = new CopyBudget(7), second = f.destination + '-2';
  const results = await Promise.allSettled([budget.copy(f.source, f.destination), budget.copy(f.source, second)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const rejected = results.find(r => r.status === 'rejected'); assert.equal(rejected?.reason.code, 'job_disk_copy_limit');
  assert.equal(budget.reservedBytes, 4);
  assert.equal((await promises.readdir(f.directory)).filter(name => name.startsWith('copy')).length, 1);
});
test('copy budget: source growing during streaming cannot exceed its original reservation', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), size = 131072, budget = new CopyBudget(size + 1);
  await promises.writeFile(f.source, Buffer.alloc(size));
  const original = fs.createReadStream; let grew = false;
  t.mock.method(fs, 'createReadStream', (...args: Parameters<typeof original>) => {
    const stream = original(...args);
    stream.once('data', () => { fs.appendFileSync(f.source, 'x'); grew = true; }); return stream;
  }); syncBuiltinESMExports();
  try { await assert.rejects(budget.copy(f.source, f.destination), { code: 'copy_source_changed' }); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.equal(grew, true); assert.equal((await promises.stat(f.source)).size, size + 1);
  await absent(f.destination); assert.equal(budget.reservedBytes, 0);
});
test('copy budget: failed cleanup keeps the partial output reservation charged', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), size = 131072, budget = new CopyBudget(size);
  await promises.writeFile(f.source, Buffer.alloc(size));
  const original = fs.createReadStream;
  t.mock.method(fs, 'createReadStream', (...args: Parameters<typeof original>) => {
    const stream = original(...args); stream.once('data', () => fs.appendFileSync(f.source, 'x')); return stream;
  });
  t.mock.method(promises, 'unlink', async () => { throw Object.assign(new Error('fixture cleanup refusal'), { code: 'EACCES' }); });
  syncBuiltinESMExports();
  try { await assert.rejects(budget.copy(f.source, f.destination), error => error instanceof SafeError && error.constructor.name === 'CopyCleanupError' && error.code === 'copy_cleanup_failed'); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  assert.equal(budget.reservedBytes, size); assert.ok((await promises.stat(f.destination)).size <= size);
  await promises.writeFile(f.source, Buffer.alloc(size));
  await assert.rejects(budget.copy(f.source, f.destination + '-2'), { code: 'job_disk_copy_limit' });
});
test('copy budget: exclusive destination conflicts never delete the existing file', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), budget = new CopyBudget(4);
  await promises.writeFile(f.destination, 'keep');
  await assert.rejects(budget.copy(f.source, f.destination), { code: 'EEXIST' });
  assert.equal(await promises.readFile(f.destination, 'utf8'), 'keep'); assert.equal(budget.reservedBytes, 0);
});
test('copy budget: interrupted streams remove partial files and release only after cleanup', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), budget = new CopyBudget(131072);
  await promises.writeFile(f.source, Buffer.alloc(131072));
  const abort = new AbortController(), original = fs.createReadStream;
  t.mock.method(fs, 'createReadStream', (...args: Parameters<typeof original>) => {
    const stream = original(...args); stream.once('data', () => abort.abort()); return stream;
  }); syncBuiltinESMExports();
  try { await assert.rejects(budget.copy(f.source, f.destination, { signal: abort.signal })); }
  finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  await absent(f.destination); assert.equal(budget.reservedBytes, 0);
});
test('copy budget: optional config is a positive safe integer without a schema/default change', async t => {
  const f = await fixture(t), file = path.join(f.directory, 'config.json');
  await promises.writeFile(file, JSON.stringify({ schema: 1, maxCopyBytes: Number.MAX_SAFE_INTEGER }));
  assert.equal((await loadConfig(file)).maxCopyBytes, Number.MAX_SAFE_INTEGER);
  for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, null, '4']) {
    await promises.writeFile(file, JSON.stringify({ schema: 1, maxCopyBytes: value }));
    await assert.rejects(loadConfig(file), { code: 'invalid_limit' });
  }
  assert.equal(Object.hasOwn(defaults, 'maxCopyBytes'), false);
  assert.equal(digest(defaults), 'fa29e80009c28284ec2ec41b0ba6b71f215f2962e32791b521d3daf8c1a69f26');
});
test('copy budget: job profile accepts the optional key without changing the saved Linux config', async t => {
  const f = await fixture(t), original = jobProfile(f.source), legacy = jobLinuxConfig(parseJobProfile(original));
  const parsed = parseJobProfile({ ...original, maxCopyBytes: Number.MAX_SAFE_INTEGER });
  assert.equal(parsed.maxCopyBytes, Number.MAX_SAFE_INTEGER); assert.deepEqual(jobLinuxConfig(parsed), legacy);
  for (const maxCopyBytes of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, null, '4']) {
    assert.throws(() => parseJobProfile({ ...original, maxCopyBytes }), { code: 'invalid_job_profile' });
  }
});
test('copy budget: OSV ZIP copies use the shared budget and retain their hash identity', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), source = path.join(f.directory, 'db'), workspace = path.join(f.directory, 'work'), target = path.join(f.directory, 'target');
  await promises.mkdir(path.join(source, 'osv-scalibr', 'npm'), { recursive: true }); await promises.mkdir(workspace); await promises.mkdir(target);
  await promises.writeFile(path.join(source, 'osv-scalibr', 'npm', 'all.zip'), '1234');
  const input = { source, workspace, target, ecosystems: ['npm'] as ['npm'], maxMetadataBytes: 1024, timeoutMs: 10000, signal: new AbortController().signal };
  const budget = new CopyBudget(3);
  await assert.rejects(prepareOfflineDatabase({ ...input, copyBudget: budget }), { code: 'job_disk_copy_limit' });
  await absent(path.join(workspace, 'osv-database', 'osv-scalibr', 'npm', 'all.zip'));
  assert.deepEqual(await sourceCleanupFor(workspace).cleanup(workspace), { status: 'removed' });
  const exact = new CopyBudget(4), prepared = await prepareOfflineDatabase({ ...input, copyBudget: exact });
  assert.equal(prepared.files[0].sha256, hash('1234')); assert.equal(exact.reservedBytes, 4);
});
test('copy budget: plain scan refuses the process-owner copy as INCOMPLETE with its own cause', { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(t), file = path.join(f.directory, 'config.json'), root = path.join(f.directory, 'target');
  await promises.mkdir(root); assert.ok(testProcessOwner);
  await promises.writeFile(file, JSON.stringify(withTestProcessOwner({ schema: 1, maxCopyBytes: 1 })));
  const result = await invoke(['scan', root, '--config', file, '--json']);
  assert.equal(result.code, 3); assert.equal(result.out, '');
  assert.deepEqual(JSON.parse(result.err), { schema: 'scanmux.error/v1', gate: 'INCOMPLETE', exitCode: 3, error: 'job_disk_copy_limit' });
});
test('copy budget: job-scan runtime bundle refusal is INCOMPLETE before Docker starts', { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t), root = path.join(f.directory, 'target'), file = path.join(f.directory, 'profile.json'); await promises.mkdir(root);
  await promises.writeFile(file, JSON.stringify({ ...jobProfile(f.source), maxCopyBytes: 1 }));
  const result = await invoke(['job-scan', root, '--job-profile', file, '--json']);
  assert.equal(result.code, 3); assert.equal(result.out, '');
  assert.deepEqual(JSON.parse(result.err), { schema: 'scanmux.error/v1', gate: 'INCOMPLETE', exitCode: 3, error: 'job_disk_copy_limit' });
});

test('copy budget: follows a symlink to a regular source like copyFile', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), link = path.join(f.directory, 'link');
  await promises.symlink(f.source, link, 'file');
  assert.equal((await new CopyBudget(4).copy(link, f.destination)).sha256, hash('1234'));
  assert.equal(await promises.readFile(f.destination, 'utf8'), '1234');
});

test('copy budget: a replaced process owner keeps tool_digest_mismatch', { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(t), { withCopyBudget } = await api();
  await promises.writeFile(f.source, '12345');
  await assert.rejects(withCopyBudget(100, () => startProcessOwner(
    { path: f.source, sha256: hash('1234'), version: '1' }, 1000, Buffer.from('1234'))), { code: 'tool_digest_mismatch' });
});

test('copy budget: a replaced runtime asset keeps the integrity ERROR envelope', { skip: process.platform === 'darwin' }, async t => {
  const f = await fixture(t), { CopyBudget } = await api(), root = path.join(f.directory, 'target'), file = path.join(f.directory, 'profile.json');
  const replacement = path.join(f.directory, 'replacement');
  await promises.mkdir(root); await promises.writeFile(replacement, Buffer.alloc(1048576));
  await promises.writeFile(file, JSON.stringify({ ...jobProfile(f.source), maxCopyBytes: 16777216 }));
  const original = CopyBudget.prototype.copy;
  t.mock.method(CopyBudget.prototype, 'copy', function (this: InstanceType<typeof CopyBudget>, source: string, destination: string, options: Parameters<typeof original>[2]) {
    return original.call(this, destination.includes(path.sep + 'app' + path.sep) ? replacement : source, destination, options);
  });
  const result = await invoke(['job-scan', root, '--job-profile', file, '--json']);
  assert.equal(result.code, 4);
  assert.deepEqual(JSON.parse(result.err), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'job_asset_changed' });
});

test('copy budget: growing OSV ZIP retains database_size_mismatch and removes partial output', async t => {
  const f = await fixture(t), { CopyBudget } = await api(), source = path.join(f.directory, 'db'), workspace = path.join(f.directory, 'work'), target = path.join(f.directory, 'target');
  await promises.mkdir(path.join(source, 'osv-scalibr', 'npm'), { recursive: true }); await promises.mkdir(workspace); await promises.mkdir(target);
  const zip = path.join(source, 'osv-scalibr', 'npm', 'all.zip'); await promises.writeFile(zip, Buffer.alloc(131072));
  const original = fs.createReadStream;
  t.mock.method(fs, 'createReadStream', (...args: Parameters<typeof original>) => {
    const stream = original(...args); stream.once('data', () => fs.appendFileSync(zip, 'x')); return stream;
  }); syncBuiltinESMExports();
  try {
    await assert.rejects(prepareOfflineDatabase({ source, workspace, target, ecosystems: ['npm'], maxMetadataBytes: 1024,
      timeoutMs: 10000, signal: new AbortController().signal, copyBudget: new CopyBudget(262144) }), { code: 'database_size_mismatch' });
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
  await absent(path.join(workspace, 'osv-database', 'osv-scalibr', 'npm', 'all.zip'));
});
