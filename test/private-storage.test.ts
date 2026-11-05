import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { registerJobDiskRoot, releaseJobDiskRoot } from '../src/job-disk.ts';
import { privateAclRule } from '../src/private-acl.ts';
import { privateWorkspace, protectDirectory, verifyPrivateDirectory } from '../src/private-storage.ts';
import { unlinkedDirectory } from '../src/safe-remove.ts';
import { canonical, SafeError, within } from '../src/safety.ts';
import { initializeSourceWorkspace, sourceCleanupFor, sourceCleanupState, verifySourceWorkspace } from '../src/source-cleanup.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();
let previous: string | undefined;
beforeEach(() => { previous = process.env.TMPDIR; process.env.TMPDIR = process.env.TEMP; });
afterEach(() => { if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous; });

async function storage(overrides: Record<string, unknown> = {}) {
  let workspaces = 0, protections = 0, processes = 0;
  const parentAcl: string[] = [];
  const parent = path.join(tmpdir(), 'scanmux-private');
  const imports = { ...fs, tmpdir, path, process, randomUUID, privateAclRule, canonical, SafeError, within, registerJobDiskRoot, releaseJobDiskRoot, initializeSourceWorkspace, sourceCleanupState, unlinkedDirectory, verifySourceWorkspace, ...overrides,
    mkdtemp: async (...args: Parameters<typeof fs.mkdtemp>) => { workspaces++; return fs.mkdtemp(...args); },
    spawn: ((...args: Parameters<typeof spawn>) => {
      const env = args[2]?.env;
      processes++;
      if (env?.SCANMUX_PRIVATE_PARENT === parent) parentAcl.push('verify');
      if (env?.SCANMUX_PRIVATE_DIR === parent || env?.SCANMUX_PRIVATE_DIR?.startsWith(parent + '.')) {
        parentAcl.push(env.SCANMUX_PRIVATE_MODE!); if (env.SCANMUX_PRIVATE_MODE === 'protect') protections++;
      }
      return (overrides.spawn as typeof spawn ?? spawn)(...args);
    }) as typeof spawn };
  const source = stripTypeScriptTypes(await fs.readFile('src/private-storage.ts', 'utf8')).replace(/^import [\s\S]*?;\r?\n/gm, '').replace(/^export /gm, '');
  const module = Function(...Object.keys(imports), source + '\nreturn { privateWorkspace };')(...Object.values(imports)) as { privateWorkspace: typeof privateWorkspace };
  return { ...module, parent, counts: () => ({ workspaces, protections }), processes: () => processes, parentAcl: () => [...parentAcl] };
}
async function refused(module: Awaited<ReturnType<typeof storage>>, workspaces = 0, protections = 0) {
  await assert.rejects(module.privateWorkspace(), { code: 'private_acl_unverified' });
  assert.deepEqual(module.counts(), { workspaces, protections });
}
async function permissions(directory: string): Promise<string> {
  if (process.platform !== 'win32') { const stat = await fs.lstat(directory); return `${stat.uid}:${stat.mode}`; }
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command',
      "$ErrorActionPreference='Stop'; [IO.DirectoryInfo]::new($env:SCANMUX_PRIVATE_DIR).GetAccessControl().GetSecurityDescriptorSddlForm('Access,Owner,Group')"],
    { env: { SystemRoot: process.env.SystemRoot, SCANMUX_PRIVATE_DIR: directory }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', stderr = ''; child.stdout.on('data', chunk => { output += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject); child.once('close', code => code === 0 && output.trim() ? resolve(output.trim()) : reject(new Error(`ACL read failed: ${code} ${stderr}`)));
  });
}

test('workspace lives inside a protected parent that survives disposable cleanup', async () => {
  const workspace = await privateWorkspace(undefined, { disposable: true }), parent = path.join(tmpdir(), 'scanmux-private');
  assert.equal(path.dirname(workspace), parent);
  assert.equal(await verifyPrivateDirectory(parent), true); assert.equal(await verifyPrivateDirectory(workspace), true);
  if (process.platform !== 'win32') assert.equal((await fs.lstat(parent)).mode & 0o777, 0o700);
  assert.equal(await fs.readFile(path.join(workspace, 'empty-gitconfig'), 'utf8'), '');
  const owner = sourceCleanupFor(workspace); owner.register(workspace, workspace);
  assert.equal((await owner.cleanup()).status, 'removed');
  assert.equal(await fs.lstat(workspace).catch(() => null), null); assert.equal(await verifyPrivateDirectory(parent), true);
});

for (const disposable of [false, true]) for (const partial of [false, true]) test(`a failed gitconfig write removes its workspace and releases its disk root, disposable=${disposable}, partial=${partial}`, async () => {
  const failure = Object.assign(new Error('disk full'), { code: 'ENOSPC' }); let directory = '', registered = '', released = '';
  const module = await storage({
    registerJobDiskRoot: (root: string) => { registered = root; registerJobDiskRoot(root); },
    releaseJobDiskRoot: (root: string) => { released = root; releaseJobDiskRoot(root); },
    writeFile: async (...args: Parameters<typeof fs.writeFile>) => {
      directory = path.dirname(String(args[0])); assert.equal(path.basename(String(args[0])), 'empty-gitconfig');
      if (partial) await fs.writeFile(args[0], 'partial'); throw failure;
    },
  });
  await assert.rejects(module.privateWorkspace(undefined, { disposable }), error => error === failure);
  assert.equal(path.dirname(directory), module.parent); assert.deepEqual(await fs.readdir(module.parent), []);
  assert.equal(await fs.lstat(directory).catch(() => null), null); assert.equal(registered, directory); assert.equal(released, directory);
  assert.equal(sourceCleanupState.failed, false);
});

for (const mode of ['replacement', 'junction', 'nonempty', 'rmdir', 'unlink']) test(`gitconfig write failure preserves and reports ${mode} without replacing the original error`, async t => {
  const failure = Object.assign(new Error('disk full'), { code: 'ENOSPC' }), held = path.join(tmpdir(), 'held'); let directory = '', released = '', stderr = '';
  const module = await storage({
    releaseJobDiskRoot: (root: string) => { released = root; releaseJobDiskRoot(root); },
    rmdir: async (...args: Parameters<typeof fs.rmdir>) => { if (mode === 'rmdir') throw new Error('locked'); return fs.rmdir(...args); },
    unlink: async (...args: Parameters<typeof fs.unlink>) => { if (mode === 'unlink') throw new Error('locked'); return fs.unlink(...args); },
    writeFile: async (...args: Parameters<typeof fs.writeFile>) => {
      directory = path.dirname(String(args[0])); await fs.writeFile(args[0], 'partial');
      if (mode === 'replacement' || mode === 'junction') {
        await fs.rename(directory, held);
        if (mode === 'replacement') await fs.mkdir(directory); else await fs.symlink(held, directory, process.platform === 'win32' ? 'junction' : 'dir');
        await fs.writeFile(path.join(directory, 'empty-gitconfig'), 'unchanged');
      }
      if (['replacement', 'junction', 'nonempty'].includes(mode)) await fs.writeFile(path.join(directory, 'canary'), 'unchanged');
      throw failure;
    },
  });
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  await assert.rejects(module.privateWorkspace(), error => error === failure);
  assert.equal(released, directory); assert.ok(await fs.lstat(directory));
  if (['replacement', 'junction', 'nonempty'].includes(mode)) assert.equal(await fs.readFile(path.join(directory, 'canary'), 'utf8'), 'unchanged');
  if (mode === 'replacement' || mode === 'junction') assert.equal(await fs.readFile(path.join(directory, 'empty-gitconfig'), 'utf8'), 'unchanged');
  if (mode === 'unlink') assert.equal(await fs.readFile(path.join(directory, 'empty-gitconfig'), 'utf8'), 'partial');
  if (mode === 'junction') assert.equal((await fs.lstat(directory)).isSymbolicLink(), true);
  assert.equal(sourceCleanupState.failed, true); assert.ok(stderr.includes('source_cleanup_failed'));
});

test('an existing protected parent is reused without changing its ACL', async () => {
  const first = await privateWorkspace(), module = await storage(), before = await fs.lstat(module.parent, { bigint: true });
  await fs.writeFile(path.join(module.parent, 'retained'), 'unchanged');
  const second = await module.privateWorkspace(), after = await fs.lstat(module.parent, { bigint: true });
  assert.equal(path.dirname(first), module.parent); assert.equal(path.dirname(second), module.parent); assert.notEqual(first, second);
  assert.deepEqual([after.dev, after.ino, after.birthtimeNs], [before.dev, before.ino, before.birthtimeNs]);
  assert.equal(await fs.readFile(path.join(module.parent, 'retained'), 'utf8'), 'unchanged');
  assert.deepEqual(module.counts(), { workspaces: 1, protections: 0 });
});

for (const existing of [false, true]) test(`the second Windows workspace spawns no parent ACL child, existing=${existing}`, { skip: process.platform !== 'win32' }, async () => {
  const module = await storage();
  if (existing) { await fs.mkdir(module.parent, { mode: 0o700 }); await protectDirectory(module.parent); }
  const first = await module.privateWorkspace(), expected = existing ? ['verify'] : ['protect', 'verify'];
  assert.deepEqual(module.parentAcl(), expected);
  assert.equal(module.processes(), existing ? 1 : 3);
  const second = await module.privateWorkspace();
  assert.equal(module.processes(), existing ? 2 : 4);
  assert.notEqual(first, second); assert.equal(await verifyPrivateDirectory(second), true);
  assert.deepEqual(module.parentAcl(), expected); assert.deepEqual(module.counts(), { workspaces: 2, protections: existing ? 0 : 1 });
});

test('concurrent Windows workspaces each verify the parent in their own protection run', { skip: process.platform !== 'win32' }, async () => {
  const module = await storage(); await fs.mkdir(module.parent, { mode: 0o700 }); await protectDirectory(module.parent);
  const workspaces = await Promise.all([module.privateWorkspace(), module.privateWorkspace()]);
  assert.equal(new Set(workspaces).size, 2); assert.deepEqual(module.parentAcl(), ['verify', 'verify']); assert.equal(module.processes(), 2);
  assert.deepEqual(module.counts(), { workspaces: 2, protections: 0 });
});

test('two processes publish concurrent first parents without exposing an unprotected parent or leaving a sibling', { skip: process.platform !== 'win32' }, async () => {
  const parent = path.join(tmpdir(), 'scanmux-private');
  const source = `import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { once } from 'node:events';
import { privateWorkspace } from './src/private-storage.ts';
const rename = fs.rename;
fs.rename = async (...args) => { process.send('prepared'); await once(process, 'message'); return rename(...args); };
syncBuiltinESMExports();
try { process.send({ workspace: await privateWorkspace() }); } catch (error) { console.error(error); process.exitCode = 1; }
process.disconnect();`;
  const children = [0, 1].map(() => spawn(process.execPath, ['--input-type=module', '--eval', source], { env: process.env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] }));
  const runs = children.map(child => {
    let workspace = '', stderr = '', ready = false;
    child.stdout!.resume(); child.stderr!.on('data', chunk => { stderr += chunk; });
    let prepared!: () => void, failed!: (error: Error) => void;
    const preparation = new Promise<void>((resolve, reject) => { prepared = resolve; failed = reject; });
    child.on('message', message => { if (message === 'prepared') { ready = true; prepared(); } else workspace = (message as { workspace: string }).workspace; });
    const done = new Promise<string>((resolve, reject) => {
      child.once('error', error => { failed(error); reject(error); });
      child.once('close', code => {
        if (!ready) failed(new Error(`child exited before publishing: ${code} ${stderr}`));
        if (code !== 0 || !workspace) reject(new Error(`workspace child failed: ${code} ${stderr}`)); else resolve(workspace);
      });
    });
    void done.catch(() => {}); return { preparation, done };
  });
  try {
    await Promise.all(runs.map(run => run.preparation));
    assert.equal(await fs.lstat(parent).catch(() => null), null, 'the fixed name is absent until protection succeeds');
    const siblings = (await fs.readdir(tmpdir())).filter(name => name.startsWith('scanmux-private.'));
    assert.equal(siblings.length, 2);
    for (const sibling of siblings) assert.equal(await verifyPrivateDirectory(path.join(tmpdir(), sibling)), true);
    for (const child of children) child.send('publish');
    const workspaces = await Promise.all(runs.map(run => run.done));
    assert.equal(new Set(workspaces).size, 2); assert.deepEqual(await fs.readdir(tmpdir()), ['scanmux-private']);
    assert.equal(await verifyPrivateDirectory(parent), true);
    for (const workspace of workspaces) { assert.equal(path.dirname(workspace), parent); assert.equal(await verifyPrivateDirectory(workspace), true); }
    assert.deepEqual((await fs.readdir(parent)).sort(), workspaces.map(workspace => path.basename(workspace)).sort());
  } finally { for (const child of children) if (child.exitCode === null) child.kill(); await Promise.allSettled(runs.map(run => run.done)); }
});

for (const replacement of ['private', 'broad', 'junction']) test(`a cached Windows parent replaced by ${replacement} stops and invalidates its verification`, { skip: process.platform !== 'win32' }, async () => {
  const module = await storage(), held = path.join(tmpdir(), 'held'), target = path.join(tmpdir(), 'unrelated');
  await fs.mkdir(module.parent, { mode: 0o700 }); await protectDirectory(module.parent); await module.privateWorkspace();
  await fs.rename(module.parent, held);
  if (replacement === 'junction') { await fs.mkdir(target); await fs.symlink(target, module.parent, 'junction'); }
  else { await fs.mkdir(module.parent); if (replacement === 'private') await protectDirectory(module.parent); }
  await fs.writeFile(path.join(module.parent, 'canary'), 'unchanged');
  await assert.rejects(module.privateWorkspace(), { code: 'private_acl_unverified' });
  assert.deepEqual(module.parentAcl(), ['verify']); assert.deepEqual(module.counts(), { workspaces: 1, protections: 0 });
  assert.deepEqual(await fs.readdir(module.parent), ['canary']); assert.equal(await fs.readFile(path.join(module.parent, 'canary'), 'utf8'), 'unchanged');
  if (replacement === 'private') {
    assert.equal(path.dirname(await module.privateWorkspace()), module.parent);
    assert.deepEqual(module.parentAcl(), ['verify', 'verify']); assert.deepEqual(module.counts(), { workspaces: 2, protections: 0 });
  } else {
    await assert.rejects(module.privateWorkspace(), { code: 'private_acl_unverified' });
    assert.deepEqual(module.parentAcl(), replacement === 'broad' ? ['verify', 'verify'] : ['verify']);
    assert.deepEqual(module.counts(), { workspaces: replacement === 'broad' ? 2 : 1, protections: 0 });
  }
});

for (const field of ['dev', 'ino', 'birthtimeNs'] as const) test(`a cached Windows parent ${field} mismatch stops before workspace creation`, { skip: process.platform !== 'win32' }, async () => {
  const parent = path.join(tmpdir(), 'scanmux-private'); let changed = false;
  const module = await storage({ lstat: async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await fs.lstat(...args);
    if (changed && String(args[0]) === parent && args[1]?.bigint) {
      const identity = stat as unknown as { dev: bigint; ino: bigint; birthtimeNs: bigint };
      return Object.assign(Object.create(stat), { [field]: identity[field] + 1n });
    }
    return stat;
  } });
  await fs.mkdir(parent, { mode: 0o700 }); await protectDirectory(parent); await module.privateWorkspace(); changed = true;
  await assert.rejects(module.privateWorkspace(), { code: 'private_acl_unverified' });
  assert.deepEqual(module.parentAcl(), ['verify']); assert.deepEqual(module.counts(), { workspaces: 1, protections: 0 });
});

test('a pre-existing junction or symlink parent is refused without touching its target', async () => {
  const module = await storage(), target = path.join(tmpdir(), 'unrelated');
  await fs.mkdir(target); await fs.writeFile(path.join(target, 'canary'), 'unchanged');
  await fs.symlink(target, module.parent, process.platform === 'win32' ? 'junction' : 'dir');
  await refused(module); assert.deepEqual(await fs.readdir(target), ['canary']);
  assert.equal(await fs.readFile(path.join(target, 'canary'), 'utf8'), 'unchanged');
});

test('a pre-existing file parent is refused', async () => {
  const module = await storage(); await fs.writeFile(module.parent, 'unchanged');
  await refused(module); assert.equal(await fs.readFile(module.parent, 'utf8'), 'unchanged');
});

test('a pre-existing parent with a broader ACL or mode is refused without repair', async () => {
  let writes = 0;
  const module = await storage({ writeFile: async () => { writes++; throw new Error('unexpected workspace write'); } }); await fs.mkdir(module.parent, { mode: 0o755 });
  if (process.platform !== 'win32') await fs.chmod(module.parent, 0o755);
  const before = await permissions(module.parent);
  assert.equal(await verifyPrivateDirectory(module.parent), false);
  await refused(module, process.platform === 'win32' ? 1 : 0); assert.deepEqual(await fs.readdir(module.parent), []);
  assert.equal(writes, 0); assert.equal(await permissions(module.parent), before);
  assert.equal(await verifyPrivateDirectory(module.parent), false);
});

test('a pre-existing parent with a simulated foreign owner is refused without changing its ACL', async () => {
  const parent = path.join(tmpdir(), 'scanmux-private'); await fs.mkdir(parent, { mode: 0o700 }); await protectDirectory(parent);
  const before = await permissions(parent); let writes = 0;
  const module = await storage(process.platform === 'win32' ? {
    privateAclRule: privateAclRule.replace('return $null -ne $owner', 'return $false -and $null -ne $owner'),
    writeFile: async () => { writes++; throw new Error('unexpected workspace write'); },
  } : { lstat: async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await fs.lstat(...args);
    return String(args[0]) === parent && !args[1]?.bigint ? Object.assign(Object.create(stat), { uid: (process.getuid?.() ?? 0) + 1 }) : stat;
  } });
  await refused(module, process.platform === 'win32' ? 1 : 0); assert.deepEqual(await fs.readdir(parent), []);
  assert.equal(writes, 0); assert.equal(await permissions(parent), before);
});

test('a failed combined parent check leaves no workspace and is not cached', { skip: process.platform !== 'win32' }, async () => {
  let first = true;
  const module = await storage({ spawn: ((...args: Parameters<typeof spawn>) => {
    if (!first) return spawn(...args);
    first = false; const child = new EventEmitter(); queueMicrotask(() => child.emit('close', 1)); return child;
  }) as typeof spawn });
  await fs.mkdir(module.parent, { mode: 0o700 }); await protectDirectory(module.parent);
  await refused(module, 1); assert.deepEqual(await fs.readdir(module.parent), []); assert.equal(sourceCleanupState.failed, false);
  const workspace = await module.privateWorkspace();
  assert.deepEqual(module.parentAcl(), ['verify', 'verify']); assert.equal(module.processes(), 2);
  assert.deepEqual(await fs.readdir(module.parent), [path.basename(workspace)]);
});

for (const site of ['workspace', 'sibling']) for (const mode of ['replacement', 'junction', 'ancestor-junction', 'nonempty', 'rmdir']) test(`${site} cleanup preserves and reports ${mode} after ACL refusal`, { skip: process.platform !== 'win32' }, async t => {
  const held = path.join(mode === 'ancestor-junction' ? path.dirname(tmpdir()) : tmpdir(), 'held'), target = path.join(tmpdir(), 'unrelated'); let retained = '', removals = 0, stderr = '';
  const module = await storage({
    rmdir: async (...args: Parameters<typeof fs.rmdir>) => {
      removals++; if (mode === 'rmdir') throw Object.assign(new Error('locked'), { code: 'EBUSY' }); return fs.rmdir(...args);
    },
    spawn: ((_file: string, _args: string[], options: { env: NodeJS.ProcessEnv }) => {
      retained = options.env.SCANMUX_PRIVATE_DIR!;
      if (site === 'workspace') assert.equal(options.env.SCANMUX_PRIVATE_PARENT, path.dirname(retained));
      else assert.ok(retained.startsWith(module.parent + '.'));
      const child = new EventEmitter();
      void (async () => {
        if (mode === 'replacement' || mode === 'junction') {
          await fs.rename(retained, held);
          if (mode === 'replacement') await fs.mkdir(retained);
          else { await fs.mkdir(target); await fs.writeFile(path.join(target, 'canary'), 'unchanged'); await fs.symlink(target, retained, 'junction'); }
        } else if (mode === 'ancestor-junction') {
          const ancestor = site === 'workspace' ? module.parent : tmpdir(); await fs.rename(ancestor, held); await fs.symlink(held, ancestor, 'junction');
        } else if (mode === 'nonempty') await fs.writeFile(path.join(retained, 'canary'), 'unchanged');
      })().then(() => child.emit('close', 1), error => child.emit('error', error));
      return child;
    }) as unknown as typeof spawn,
  });
  if (site === 'workspace') { await fs.mkdir(module.parent, { mode: 0o700 }); await protectDirectory(module.parent); }
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  await refused(module, site === 'workspace' ? 1 : 0, site === 'sibling' ? 1 : 0);
  assert.equal(removals, ['replacement', 'junction', 'ancestor-junction'].includes(mode) ? 0 : 1);
  if (mode === 'replacement' || mode === 'junction') assert.deepEqual(await fs.readdir(held), []);
  if (mode === 'junction') { assert.equal((await fs.lstat(retained)).isSymbolicLink(), true); assert.equal(await fs.readFile(path.join(target, 'canary'), 'utf8'), 'unchanged'); }
  else if (mode === 'nonempty') { assert.deepEqual(await fs.readdir(retained), ['canary']); assert.equal(await fs.readFile(path.join(retained, 'canary'), 'utf8'), 'unchanged'); }
  else assert.deepEqual(await fs.readdir(retained), []);
  if (mode === 'ancestor-junction') assert.equal((await fs.lstat(site === 'workspace' ? module.parent : tmpdir())).isSymbolicLink(), true);
  assert.equal(sourceCleanupState.failed, true);
  assert.ok(stderr.includes('source_cleanup_failed')); assert.ok(stderr.includes(JSON.stringify(retained))); assert.equal(stderr.trim().split('\n').length, 1);
});

for (const valid of [false, true]) test(`a competing Windows parent is verified without repair after a lost rename, private=${valid}`, { skip: process.platform !== 'win32' }, async () => {
  const parent = path.join(tmpdir(), 'scanmux-private');
  let before = '';
  const module = await storage({ rename: async (sibling: string, destination: string) => {
    assert.equal(destination, parent); assert.ok(sibling.startsWith(parent + '.')); assert.equal(await verifyPrivateDirectory(sibling), true);
    await fs.mkdir(parent, { mode: valid ? 0o700 : 0o755 });
    if (valid) await protectDirectory(parent); before = await permissions(parent);
    throw Object.assign(new Error('concurrent create'), { code: 'EPERM' });
  } });
  if (valid) { assert.equal(path.dirname(await module.privateWorkspace()), parent); assert.deepEqual(module.counts(), { workspaces: 1, protections: 1 }); }
  else { await refused(module, 1, 1); assert.deepEqual(await fs.readdir(parent), []); }
  assert.equal(await permissions(parent), before); assert.deepEqual(await fs.readdir(tmpdir()), ['scanmux-private']);
});

test('a sibling swapped after its creation identity is read is refused before its ACL is changed', { skip: process.platform !== 'win32' }, async t => {
  const parent = path.join(tmpdir(), 'scanmux-private'), held = path.join(tmpdir(), 'held');
  let replacement = '', stderr = '';
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  const module = await storage({ lstat: async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await fs.lstat(...args);
    if (!replacement && String(args[0]).startsWith(parent + '.') && args[1]?.bigint) {
      replacement = String(args[0]); await fs.rename(replacement, held); await fs.mkdir(replacement); await fs.writeFile(path.join(replacement, 'canary'), 'unchanged');
    }
    return stat;
  } });
  await refused(module); assert.ok(replacement); assert.deepEqual(await fs.readdir(held), []);
  assert.equal(await fs.readFile(path.join(replacement, 'canary'), 'utf8'), 'unchanged');
  assert.equal(await fs.lstat(parent).catch(() => null), null);
  assert.equal(sourceCleanupState.failed, true);
  assert.equal(stderr, `ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(replacement)}\n`);
});

for (const mode of ['protect', 'verify']) test(`a sibling swapped during ACL ${mode} is refused before publication`, { skip: process.platform !== 'win32' }, async t => {
  const parent = path.join(tmpdir(), 'scanmux-private'), held = path.join(tmpdir(), 'held');
  let replacement = '', stderr = '';
  t.mock.method(process.stderr, 'write', (chunk: string) => { stderr += chunk; return true; });
  const module = await storage({ spawn: ((file: string, args: string[], options: { env: NodeJS.ProcessEnv }) => {
    if (options.env.SCANMUX_PRIVATE_MODE !== mode) return spawn(file, args, options);
    replacement = options.env.SCANMUX_PRIVATE_DIR!; assert.ok(replacement.startsWith(parent + '.'));
    const child = new EventEmitter();
    void (async () => {
      await fs.rename(replacement, held); await fs.mkdir(replacement); await fs.writeFile(path.join(replacement, 'canary'), 'unchanged');
    })().then(() => child.emit('close', 0), error => child.emit('error', error));
    return child;
  }) as unknown as typeof spawn });
  await refused(module, 0, 1); assert.ok(replacement); assert.deepEqual(await fs.readdir(held), []);
  assert.deepEqual(await fs.readdir(replacement), ['canary']); assert.equal(await fs.readFile(path.join(replacement, 'canary'), 'utf8'), 'unchanged');
  assert.equal(await fs.lstat(parent).catch(() => null), null);
  assert.equal(sourceCleanupState.failed, true);
  assert.equal(stderr, `ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(replacement)}\n`);
});

for (const permission of ['private', 'other-owner', 'broad-mode']) test(`POSIX parent verification enforces ownership and permissions: ${permission}`, async () => {
  const parent = path.join(tmpdir(), 'scanmux-private'); await fs.mkdir(parent, { mode: 0o700 });
  const module = await storage({ process: { platform: 'linux', getuid: () => 1234 }, lstat: async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await fs.lstat(...args);
    return String(args[0]) === parent && !args[1]?.bigint
      ? Object.assign(Object.create(stat), { uid: permission === 'other-owner' ? 1235 : 1234, mode: permission === 'broad-mode' ? 0o40755 : 0o40700 }) : stat;
  } });
  if (permission === 'private') { assert.equal(path.dirname(await module.privateWorkspace()), parent); assert.deepEqual(module.counts(), { workspaces: 1, protections: 0 }); }
  else { await refused(module); assert.deepEqual(await fs.readdir(parent), []); }
});

for (const field of ['dev', 'ino', 'birthtimeNs'] as const) test(`parent ${field} mismatch is refused before workspace creation`, async () => {
  const parent = path.join(tmpdir(), 'scanmux-private'); await fs.mkdir(parent, { mode: 0o700 }); await protectDirectory(parent);
  let reads = 0;
  const module = await storage({ lstat: async (...args: Parameters<typeof fs.lstat>) => {
    const stat = await fs.lstat(...args);
    if (String(args[0]) === parent && args[1]?.bigint && ++reads > 1) {
      const identity = stat as unknown as { dev: bigint; ino: bigint; birthtimeNs: bigint };
      return Object.assign(Object.create(stat), { [field]: identity[field] + 1n });
    }
    return stat;
  } });
  await refused(module); assert.deepEqual(await fs.readdir(parent), []);
});

test('parent ACL failure after creation prevents workspace creation', { skip: process.platform !== 'win32' }, async () => {
  const module = await storage({ spawn: (() => { const child = new EventEmitter(); queueMicrotask(() => child.emit('close', 1)); return child; }) as unknown as typeof spawn });
  await refused(module, 0, 1); assert.deepEqual(await fs.readdir(tmpdir()), []); assert.equal(sourceCleanupState.failed, false);
});

test('a parent filesystem failure becomes a SafeError without workspace creation', async () => {
  const module = await storage({ mkdir: async () => { throw Object.assign(new Error('refused'), { code: 'EACCES' }); } });
  await refused(module);
});

for (const privateParent of [false, true]) test(`TEMP inside the target is refused before mutation, private parent=${privateParent}`, async () => {
  const module = await storage();
  if (privateParent) await fs.mkdir(module.parent, { mode: 0o700 });
  const before = await fs.readdir(tmpdir());
  await assert.rejects(module.privateWorkspace(privateParent ? module.parent : tmpdir()), { code: 'temp_inside_target' });
  assert.deepEqual(await fs.readdir(tmpdir()), before); assert.deepEqual(module.counts(), { workspaces: 0, protections: 0 });
});
