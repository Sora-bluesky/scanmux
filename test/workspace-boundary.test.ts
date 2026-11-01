import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, readdir, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { hash } from '../src/safety.ts';

const moduleUrl = pathToFileURL(path.resolve('src/private-storage.ts')).href;
async function tree(root: string): Promise<string[]> {
  const rows: string[] = [];
  async function walk(folder: string) {
    for (const item of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(folder, item.name), relative = path.relative(root, full);
      if (item.isSymbolicLink()) rows.push(`link:${relative}`);
      else if (item.isDirectory()) { rows.push(`dir:${relative}`); await walk(full); }
      else rows.push(`file:${relative}:${hash(await readFile(full))}`);
    }
  }
  await walk(root); return rows;
}
function child(parent: string, argument: unknown, omitted = false) {
  const source = `import { privateWorkspace } from ${JSON.stringify(moduleUrl)}; try { const value=await privateWorkspace(${omitted ? '' : JSON.stringify(argument)}); console.log(JSON.stringify({value})); } catch(error) { console.log(JSON.stringify({error:error.code??error.message})); process.exitCode=4; }`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', source], { windowsHide: true, encoding: 'utf8',
    env: { ...process.env, TEMP: parent, TMP: parent, TMPDIR: parent }, maxBuffer: 1024 * 1024 });
  assert.ok(Number.isInteger(result.status)); return { status: result.status, output: JSON.parse(result.stdout.trim()) };
}
test('workspace family rejects every target and child TEMP before any file-system mutation', async () => {
  const folder = await mkdtemp(path.join(tmpdir(), 'scanmux-workspace-boundary-'));
  test.after(() => removeTempDir(folder));
  const roots = [path.join(folder, 'first'), path.join(folder, 'second')];
  for (const root of roots) { await mkdir(path.join(root, 'nested'), { recursive: true }); await writeFile(path.join(root, 'canary.txt'), 'unchanged\n'); }
  const before = await tree(folder);
  for (const root of roots) for (const parent of [root, path.join(root, 'nested')]) {
    const result = child(parent, roots); assert.equal(result.status, 4); assert.equal(result.output.error, 'temp_inside_target');
    assert.deepEqual(await tree(folder), before);
  }
  const single = child(roots[0], roots[0]); assert.equal(single.status, 4); assert.deepEqual(await tree(folder), before);
});
test('workspace validates all roots and parent aliases before writing; undefined and empty sets stay supported', async () => {
  const folder = await mkdtemp(path.join(tmpdir(), 'scanmux-workspace-valid-'));
  test.after(() => removeTempDir(folder));
  const root = path.join(folder, 'target'), outside = path.join(folder, 'outside');
  await mkdir(root); await mkdir(outside); const file = path.join(root, 'file'); await writeFile(file, 'not a directory\n');
  const link = path.join(folder, 'alias'); await symlink(root, link, process.platform === 'win32' ? 'junction' : 'dir');
  const before = await tree(folder);
  for (const argument of [null, {}, ['', root], [root, null], [root, 'relative'], [root, file], [root, path.join(folder, 'missing')], [root, link]]) {
    assert.equal(child(outside, argument).status, 4); assert.deepEqual(await tree(folder), before);
  }
  assert.equal(child(link, [root]).status, 4); assert.deepEqual(await tree(folder), before);
  for (const argument of [[root], [], undefined]) {
    const result = child(outside, argument, argument === undefined); assert.equal(result.status, 0);
    assert.ok(result.output.value.startsWith(outside + path.sep)); assert.equal(await readFile(path.join(result.output.value, 'empty-gitconfig'), 'utf8'), '');
  }
  assert.deepEqual(await tree(root), ['file:file:' + hash('not a directory\n')]);
});
test('workspace directory is protected and grants FullControl only to the current user', { skip: process.platform !== 'win32' && 'the private ACL is applied only on Windows' }, async () => {
  const outside = await mkdtemp(path.join(tmpdir(), 'scanmux-workspace-acl-'));
  test.after(() => removeTempDir(outside));
  const result = child(outside, []); assert.equal(result.status, 0);
  const probe = spawnSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoProfile', '-NonInteractive', '-Command', "$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $sid; [System.IO.DirectoryInfo]::new($env:SCANMUX_PROBE_DIR).GetAccessControl().Sddl; [Security.AccessControl.RawSecurityDescriptor]::new('D:PAI(A;OICI;FA;;;' + $sid + ')').GetSddlForm('Access')"],
    { windowsHide: true, encoding: 'utf8', env: { ...process.env, SCANMUX_PROBE_DIR: result.output.value } });
  assert.equal(probe.status, 0);
  const [sid, sddl, expected] = probe.stdout.trim().split(/\r?\n/);
  assert.match(sid, /^S-1-\d/);
  // SDDL output abbreviates well-known accounts (the built-in Administrator becomes LA), so the expected DACL goes through the same conversion.
  assert.equal(sddl.slice(sddl.indexOf('D:')), expected);
});
