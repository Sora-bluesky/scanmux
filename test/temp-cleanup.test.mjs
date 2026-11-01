import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';

test('temp cleanup removes nested junctions without deleting their target contents', async t => {
  const target = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-target-'));
  t.after(() => removeTempDir(target));
  await fs.writeFile(path.join(target, 'keep'), 'unchanged');
  const holder = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-holder-'));
  t.after(() => removeTempDir(holder));
  const nested = path.join(holder, 'nested'); await fs.mkdir(nested);
  await fs.writeFile(path.join(nested, 'owned'), 'fixture');
  await fs.symlink(target, path.join(nested, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  await removeTempDir(holder);
  await assert.rejects(fs.lstat(holder), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(target, 'keep'), 'utf8'), 'unchanged');
});

test('temp cleanup removes a linked root without entering the target', async t => {
  const target = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-root-'));
  t.after(() => removeTempDir(target));
  const holder = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-link-'));
  t.after(() => removeTempDir(holder));
  await fs.writeFile(path.join(target, 'keep'), 'unchanged');
  const link = path.join(holder, 'linked'); await fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  await removeTempDir(link);
  await assert.rejects(fs.lstat(link), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(target, 'keep'), 'utf8'), 'unchanged');
});

test('temp cleanup ignores missing paths and filesystem failures', async t => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-errors-'));
  t.after(() => removeTempDir(root));
  await assert.doesNotReject(removeTempDir(path.join(root, 'missing')));
  const lstat = fs.lstat, rm = fs.rm;
  try {
    fs.lstat = async () => { throw Error('synthetic lstat failure'); };
    fs.rm = async () => { throw Error('synthetic rm failure'); };
    await assert.doesNotReject(removeTempDir(root));
  } finally { fs.lstat = lstat; fs.rm = rm; }
});

test('strict temp cleanup rejects EBUSY without retries for a directory held by a live child', { skip: process.platform !== 'win32' }, async t => {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-held-'));
  const child = spawn(process.execPath, ['-e', 'process.send("ready");process.on("message", () => process.exit(0));'], { cwd: directory, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true });
  const closed = once(child, 'close');
  try {
    await once(child, 'message');
    const started = performance.now();
    await assert.rejects(removeTempDirStrict(directory, { recursive: true, maxRetries: 0 }), { code: 'EBUSY' });
    t.diagnostic(`EBUSY without retries after ${(performance.now() - started).toFixed(1)} ms`);
  } finally {
    child.kill(); await closed;
    await removeTempDirStrict(directory);
  }
});

test('strict temp cleanup preserves force and no-force behavior for a missing directory', async t => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-missing-'));
  t.after(() => removeTempDir(root));
  await removeTempDirStrict(root);
  await assert.doesNotReject(removeTempDirStrict(root));
  await assert.rejects(removeTempDirStrict(root, { recursive: true, maxRetries: 0 }), { code: 'ENOENT' });
  await assert.rejects(removeTempDirStrict(root, { recursive: true }), { code: 'ENOENT' });
});

test('strict temp cleanup retries until a child releases its directory after 1.5 seconds', { skip: process.platform !== 'win32' }, async t => {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-release-'));
  const child = spawn(process.execPath, ['-e', 'process.send("ready");process.on("message", () => setTimeout(() => process.exit(0), 1500));'], { cwd: directory, stdio: ['ignore', 'ignore', 'ignore', 'ipc'], windowsHide: true });
  const closed = once(child, 'close');
  try {
    await once(child, 'message');
    child.send('release'); const started = performance.now();
    await removeTempDirStrict(directory, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    await assert.rejects(fs.lstat(directory), { code: 'ENOENT' });
    t.diagnostic(`removed after delayed child release in ${(performance.now() - started).toFixed(1)} ms`);
  } finally {
    child.kill(); await closed;
    await removeTempDirStrict(directory);
  }
});

test('strict temp cleanup removes nested junctions and a linked root without entering their target', async t => {
  const target = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-strict-target-'));
  t.after(() => removeTempDir(target));
  const holder = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-strict-holder-'));
  t.after(() => removeTempDir(holder));
  await fs.writeFile(path.join(target, 'keep'), 'unchanged');
  const link = path.join(holder, 'linked'); await fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  await removeTempDirStrict(link);
  await assert.rejects(fs.lstat(link), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(target, 'keep'), 'utf8'), 'unchanged');
  const nested = path.join(holder, 'nested'); await fs.mkdir(nested);
  await fs.symlink(target, path.join(nested, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
  await removeTempDirStrict(holder);
  await assert.rejects(fs.lstat(holder), { code: 'ENOENT' });
  assert.equal(await fs.readFile(path.join(target, 'keep'), 'utf8'), 'unchanged');
});

test('strict temp cleanup forwards the exact removal options and propagates the original error', async t => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-strict-error-'));
  t.after(() => removeTempDir(root));
  const rm = fs.rm, rmOptions = { recursive: true, maxRetries: 0 };
  const failure = Object.assign(Error('synthetic removal failure'), { code: 'EPERM' });
  try {
    fs.rm = async (directory, options) => { assert.equal(directory, root); assert.equal(options, rmOptions); throw failure; };
    await assert.rejects(removeTempDirStrict(root, rmOptions), error => error === failure);
  } finally { fs.rm = rm; }
});

test('strict temp cleanup rejects a directory left behind after a successful removal', async t => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-cleanup-strict-remains-'));
  t.after(() => removeTempDir(root));
  const rm = fs.rm;
  try {
    fs.rm = async () => {};
    await assert.rejects(removeTempDirStrict(root), { message: `Temporary directory remains: ${root}` });
  } finally { fs.rm = rm; }
});
