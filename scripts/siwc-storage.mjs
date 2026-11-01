import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
export const stateDirectory = path.join(repositoryRoot, '.local', 'siwc-private');
const names = new Set(['host.json', 'registration.json', 'credentials.json', 'oauth-pending.json', 'probe-attempt.json', 'probe-result.json', 'probe-compat-attempt.json', 'probe-compat-result.json']);
export class SiwcError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const errorCode = error => error instanceof SiwcError ? error.code : 'operation_failed';

// A copy of src/private-acl.ts (equality is tested): the probe records hash only this script's own files, so an import would leave the rule out.
export const privateAclRule = `
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User
$elevated=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function Test-PrivateOwner($owner, $user, $elevatedToken) {
  return $null -ne $owner -and ($owner.Value -eq $user.Value -or ($elevatedToken -and $owner.Value -eq 'S-1-5-32-544'))
}
function Test-PrivateAcl($security, $user, $elevatedToken, $requireProtected) {
  if (!(Test-PrivateOwner ($security.GetOwner([Security.Principal.SecurityIdentifier])) $user $elevatedToken)) { return $false }
  if ($requireProtected -and !$security.AreAccessRulesProtected) { return $false }
  $rules=@($security.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  return $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $user.Value -and $rules[0].AccessControlType -eq 'Allow' -and $rules[0].FileSystemRights -eq 'FullControl'
}
`;

export const aclScript = `${privateAclRule}
$attributes=[System.IO.File]::GetAttributes($env:SCANMUX_SIWC_PATH)
if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 1 }
$container=($attributes -band [IO.FileAttributes]::Directory) -ne 0
$item=if ($container) { [System.IO.DirectoryInfo]::new($env:SCANMUX_SIWC_PATH) } else { [System.IO.FileInfo]::new($env:SCANMUX_SIWC_PATH) }
if ($env:SCANMUX_SIWC_CREATE -eq '1') {
  $acl=[Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true,$false)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  $item.SetAccessControl($acl)
}
if (!(Test-PrivateAcl $item.GetAccessControl() $sid $elevated $container)) { exit 1 }
`;

export async function canonicalUnlinked(file) {
  const absolute = path.resolve(file);
  let current = absolute;
  for (;;) {
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink()) throw new SiwcError('linked_state_path');
    if (path.dirname(current) === current) break;
    current = path.dirname(current);
  }
  if ((await fs.realpath(absolute)).toLowerCase() !== absolute.toLowerCase()) throw new SiwcError('linked_state_path');
  return absolute;
}

export async function verifyPrivate(file, create = false) {
  await canonicalUnlinked(file);
  const stat = await fs.lstat(file);
  if (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1)) throw new SiwcError('invalid_state_file');
  if (process.platform !== 'win32') {
    if (stat.uid !== process.getuid() || (stat.mode & 0o077)) throw new SiwcError('private_permissions_unverified');
    return;
  }
  const binary = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const code = await new Promise(resolve => {
    const child = spawn(binary, ['-NoProfile', '-NonInteractive', '-Command', aclScript], {
      env: { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows', SCANMUX_SIWC_PATH: file, SCANMUX_SIWC_CREATE: create ? '1' : '0' },
      windowsHide: true, stdio: 'ignore',
    });
    const timer = setTimeout(() => { child.kill(); }, 120000);
    child.once('error', () => { clearTimeout(timer); resolve(null); });
    child.once('close', value => { clearTimeout(timer); resolve(value); });
  });
  if (code !== 0) throw new SiwcError('private_permissions_unverified');
}

export async function openStore(directory = stateDirectory) {
  const root = path.resolve(directory);
  if (path.dirname(root) === path.dirname(stateDirectory)) await fs.mkdir(path.dirname(root), { recursive: true });
  await canonicalUnlinked(path.dirname(root));
  let created = false;
  try { await fs.mkdir(root, { mode: 0o700 }); created = true; }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  await verifyPrivate(root, created);
  if (!(await fs.lstat(root)).isDirectory()) throw new SiwcError('invalid_state_directory');
  const lockPath = path.join(root, 'operation.lock');
  let lock;
  try { lock = await fs.open(lockPath, 'wx', 0o600); }
  catch (error) { if (error.code === 'EEXIST') throw new SiwcError('state_locked'); throw error; }
  const lockId = randomUUID();
  try { await lock.writeFile(lockId); await lock.sync(); }
  catch (error) { await lock.close().catch(() => {}); throw error; }
  let closed = false;
  const namePath = name => {
    if (closed || !names.has(name)) throw new SiwcError('invalid_state_operation');
    return path.join(root, name);
  };
  const read = async name => {
    const file = namePath(name);
    try { await verifyPrivate(file); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    const handle = await fs.open(file, 'r');
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 8 * 1024 * 1024) throw new SiwcError('invalid_state_file');
      const buffer = await handle.readFile();
      if (buffer.length > 8 * 1024 * 1024) throw new SiwcError('invalid_state_file');
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    } finally { await handle.close(); }
  };
  const write = async (name, value, exclusive = false) => {
    const destination = namePath(name);
    await verifyPrivate(root);
    if (!exclusive) await read(name);
    const temporary = exclusive ? destination : path.join(root, `.${name}.${randomUUID()}.tmp`);
    let handle;
    try {
      handle = await fs.open(temporary, 'wx', 0o600);
      await handle.writeFile(JSON.stringify(value) + '\n', 'utf8'); await handle.sync(); await handle.close(); handle = undefined;
      await verifyPrivate(temporary);
      if (!exclusive) await fs.rename(temporary, destination);
      await verifyPrivate(destination);
    } catch (error) {
      await handle?.close().catch(() => {});
      // Preserve a partial exclusive marker: an uncertain operation must not be retried.
      if (!exclusive) await fs.unlink(temporary).catch(() => {});
      if (exclusive && error.code === 'EEXIST') throw new SiwcError('operation_already_recorded');
      throw error;
    }
  };
  return {
    read, write,
    async close() {
      if (closed) return;
      closed = true;
      await lock.close();
      await verifyPrivate(lockPath);
      if (await fs.readFile(lockPath, 'utf8') !== lockId) throw new SiwcError('lock_identity_changed');
      await fs.unlink(lockPath);
    },
  };
}
