import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rename, rmdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { registerJobDiskRoot } from './job-disk.ts';
import { privateAclRule } from './private-acl.ts';
import { unlinkedDirectory, type DirectoryIdentity } from './safe-remove.ts';
import { canonical, SafeError, within } from './safety.ts';
import { initializeSourceWorkspace, sourceCleanupState, verifySourceWorkspace } from './source-cleanup.ts';

// This ACL applies only to newly created private directories, never the user's settings.
// .NET calls instead of Set-Acl/Get-Acl: cmdlet autoloading scans every installed module, which can take seconds per launch without LOCALAPPDATA.
const windowsAcl = `${privateAclRule}
$owned = { param($item) Test-PrivateOwner ($item.GetAccessControl('Owner').GetOwner([Security.Principal.SecurityIdentifier])) $sid $elevated }
$only = { param($security) @($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ne $sid.Value -or $_.AccessControlType -ne 'Allow' }).Count -eq 0 }
if ($env:SCANMUX_PRIVATE_PARENT) {
  $parent = [System.IO.DirectoryInfo]::new($env:SCANMUX_PRIVATE_PARENT)
  if (!$parent.Exists -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 1 }
  $security = $parent.GetAccessControl()
  if (!(Test-PrivateAcl $security $sid $elevated $true)) { exit 1 }
  $parentRule = @($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))[0]
  if ($parentRule.IsInherited -or $parentRule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit' -or $parentRule.PropagationFlags -ne 'None') { exit 1 }
}
$directory = [System.IO.DirectoryInfo]::new($env:SCANMUX_PRIVATE_DIR)
$children = @($env:SCANMUX_PRIVATE_CHILDREN -split '\\|' | Where-Object { $_ } | ForEach-Object { [System.IO.DirectoryInfo]::new([System.IO.Path]::Combine($directory.FullName, $_)) })
if (@(@($directory) + $children | Where-Object { $_.Exists -and ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }).Count -ne 0) { exit 1 }
if ($env:SCANMUX_PRIVATE_MODE -ne 'protect' -and !(& $owned $directory)) { exit 1 }
if ($env:SCANMUX_PRIVATE_MODE -eq 'adopt' -and @($children | Where-Object { !(& $owned $_) }).Count -ne 0) { exit 1 }
if ($env:SCANMUX_PRIVATE_MODE -ne 'verify') {
  # A security object is written only once: SetAccessControl clears its modified flags, so each directory gets its own.
  foreach ($item in @($directory) + $children) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    $item.SetAccessControl($acl)
  }
}
$check = $directory.GetAccessControl()
$rules = @($check.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
if (!$check.AreAccessRulesProtected -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') { exit 1 }
foreach ($child in $children) { if (!(& $owned $child) -or !(& $only $child.GetAccessControl())) { exit 1 } }
`;

type Mode = 'protect' | 'adopt' | 'verify';
async function windowsPrivate(directory: string, mode: Mode, children: readonly string[], parent?: string): Promise<boolean> {
  const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const code = await new Promise<number | null>(resolve => {
    const child = spawn(powershell, ['-NoProfile', '-NonInteractive', '-Command', windowsAcl], {
      env: { SystemRoot: process.env.SystemRoot, SCANMUX_PRIVATE_DIR: directory, SCANMUX_PRIVATE_MODE: mode, SCANMUX_PRIVATE_CHILDREN: children.join('|'), SCANMUX_PRIVATE_PARENT: parent }, windowsHide: true, stdio: 'ignore',
    });
    child.on('error', () => resolve(null)); child.on('close', resolve);
  });
  return code === 0;
}
async function ownedPrivately(directory: string): Promise<boolean> {
  const stat = await lstat(directory);
  return stat.isDirectory() && stat.uid === process.getuid?.() && (stat.mode & 0o077) === 0;
}

export async function protectDirectory(directory: string): Promise<void> {
  if (process.platform !== 'win32') return;
  if (!await windowsPrivate(directory, 'protect', [])) throw new SafeError('private_acl_unverified');
}
export async function adoptDirectory(directory: string, children: readonly string[]): Promise<boolean> {
  if (process.platform === 'win32') return windowsPrivate(directory, 'adopt', children);
  const items = [directory, ...children.map(name => path.join(directory, name))];
  for (const item of items) {
    const stat = await lstat(item);
    if (!stat.isDirectory() || stat.uid !== process.getuid?.()) return false;
  }
  for (const item of items) await chmod(item, 0o700);
  return true;
}
export async function verifyPrivateDirectory(directory: string, children: readonly string[] = []): Promise<boolean> {
  if (process.platform === 'win32') return windowsPrivate(directory, 'verify', children);
  for (const item of [directory, ...children.map(name => path.join(directory, name))]) if (!await ownedPrivately(item)) return false;
  return true;
}
async function verifyParentIdentity(directory: string, identity: DirectoryIdentity): Promise<void> {
  const stat = await parentIdentity(directory);
  if (stat.dev !== identity.dev || stat.ino !== identity.ino || stat.birthtimeNs !== identity.birthtimeNs) throw new SafeError('private_acl_unverified');
}
async function parentIdentity(directory: string): Promise<DirectoryIdentity> {
  const stat = await lstat(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new SafeError('private_acl_unverified');
  return { dev: stat.dev, ino: stat.ino, birthtimeNs: stat.birthtimeNs };
}
async function removeEmptyDirectory(directory: string, identity: DirectoryIdentity): Promise<void> {
  try { await unlinkedDirectory(directory); await verifyParentIdentity(directory, identity); await rmdir(directory); }
  catch (error) {
    sourceCleanupState.failed = true;
    process.stderr.write(`ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(directory)}\n`);
    throw error;
  }
}
// Windows cannot set the protected ACL at mkdir. Publish only a fully verified sibling; POSIX mkdir
// applies 0700 atomically. Cache only successful checks, then check identity before every mkdtemp.
const verifiedParents = new Map<string, DirectoryIdentity>();
async function prepareWorkspaceParent(directory: string): Promise<{ identity: DirectoryIdentity; verify: boolean }> {
  try {
    const cached = process.platform === 'win32' ? verifiedParents.get(directory) : undefined;
    if (cached) { await verifyParentIdentity(directory, cached); return { identity: cached, verify: false }; }
    if (process.platform !== 'win32') {
      try { await mkdir(directory, { mode: 0o700 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error; }
      const identity = await parentIdentity(directory);
      if (!await verifyPrivateDirectory(directory)) throw new SafeError('private_acl_unverified');
      await verifyParentIdentity(directory, identity); return { identity, verify: false };
    }
    try { return { identity: await parentIdentity(directory), verify: true }; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const sibling = directory + '.' + randomUUID();
    await mkdir(sibling, { mode: 0o700 });
    const identity = await parentIdentity(sibling);
    let published = false;
    try {
      await verifyParentIdentity(sibling, identity); await protectDirectory(sibling);
      await verifyParentIdentity(sibling, identity);
      if (!await verifyPrivateDirectory(sibling)) throw new SafeError('private_acl_unverified');
      await verifyParentIdentity(sibling, identity);
      try { await rename(sibling, directory); published = true; return { identity, verify: false }; }
      catch (error) {
        if (!['EEXIST', 'ENOTEMPTY', 'EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
        return { identity: await parentIdentity(directory), verify: true };
      }
    } finally { if (!published) await removeEmptyDirectory(sibling, identity); }
  } catch {
    verifiedParents.delete(directory);
    throw new SafeError('private_acl_unverified');
  }
}
export async function privateWorkspace(target?: string | readonly string[], options: { disposable?: boolean } = {}): Promise<string> {
  const requested = target === undefined ? [] : typeof target === 'string' ? [target] : target;
  if (!Array.isArray(requested) || Array.from(requested).some(root => typeof root !== 'string' || !path.isAbsolute(root))) throw new SafeError('invalid_workspace_target');
  const roots = await Promise.all(requested.map(root => canonical(root)));
  for (const root of roots) if (!(await lstat(root)).isDirectory()) throw new SafeError('invalid_workspace_target');
  const base = await canonical(tmpdir()), parent = path.join(base, 'scanmux-private');
  if (!(await lstat(base)).isDirectory()) throw new SafeError('invalid_workspace_parent');
  if (roots.some(root => within(root, base) || within(root, parent))) throw new SafeError('temp_inside_target');
  const prepared = await prepareWorkspaceParent(parent);
  try { await verifyParentIdentity(parent, prepared.identity); }
  catch { verifiedParents.delete(parent); throw new SafeError('private_acl_unverified'); }
  const directory = await mkdtemp(path.join(parent, 'scanmux-'));
  const identity = initializeSourceWorkspace(directory, options.disposable === true);
  try {
    if (process.platform === 'win32' && !await windowsPrivate(directory, 'protect', [], prepared.verify ? parent : undefined)) throw new SafeError('private_acl_unverified');
    await verifyParentIdentity(parent, prepared.identity);
  } catch {
    verifiedParents.delete(parent);
    try { await removeEmptyDirectory(directory, identity); } catch { /* Never remove a replacement or a nonempty workspace. */ }
    throw new SafeError('private_acl_unverified');
  }
  await verifySourceWorkspace(directory, identity);
  if (process.platform === 'win32') verifiedParents.set(parent, prepared.identity);
  registerJobDiskRoot(directory);
  await writeFile(path.join(directory, 'empty-gitconfig'), '', { flag: 'wx', mode: 0o600 });
  return directory;
}
