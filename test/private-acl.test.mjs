import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { privateWorkspace } from '../src/private-storage.ts';
import { privateAcl } from '../src/siwc-credentials.mjs';
import { inspectPrivateAcl } from '../internal/projected-repository.mjs';
import { aclScript, privateAclRule as storageRule } from '../scripts/siwc-storage.mjs';
import { administratorsSid, privateAclRule } from '../src/private-acl.ts';

const windows = { skip: process.platform !== 'win32' && 'the private ACL check runs only on Windows' };
const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
function run(script, env) {
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', `$PSModuleAutoLoadingPreference='None'\n${script}`],
    { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot, ...env } });
  return result.status;
}

test('module autoloading off makes a cmdlet ACL read fail', windows, async () => {
  const directory = await privateWorkspace();
  test.after(() => removeTempDir(directory));
  assert.notEqual(run("$ErrorActionPreference='Stop'\nGet-Acl -LiteralPath $env:SCANMUX_PROBE", { SCANMUX_PROBE: directory }), 0);
});

test('every private ACL check passes with module autoloading off', windows, async () => {
  const directory = await privateWorkspace();
  test.after(() => removeTempDir(directory));
  const file = path.join(directory, 'record.json');
  await fs.writeFile(file, '{}', { flag: 'wx', mode: 0o600 });
  assert.equal(run(inspectPrivateAcl, { SCANMUX_PROJECTION_WORKSPACE: directory }), 0, 'projection workspace');
  for (const target of [directory, file]) assert.equal(run(privateAcl, { SCANMUX_AI_CREDENTIAL_PATH: target }), 0, `credentials ${target}`);
  const store = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-siwc-acl-'));
  test.after(() => removeTempDir(store));
  const stored = path.join(store, 'record.json');
  assert.equal(run(aclScript, { SCANMUX_SIWC_PATH: store, SCANMUX_SIWC_CREATE: '1' }), 0, 'store created');
  await fs.writeFile(stored, '{}', { flag: 'wx', mode: 0o600 });
  for (const target of [store, stored]) assert.equal(run(aclScript, { SCANMUX_SIWC_PATH: target, SCANMUX_SIWC_CREATE: '0' }), 0, `store ${target}`);
});

const user = 'S-1-5-21-1000-1000-1000-1001', other = 'S-1-5-21-1000-1000-1000-1002', system = 'S-1-5-18';
const only = (sid, flags = 'P', ace = 'A', rights = 'FA') => `D:${flags}(${ace};OICI;${rights};;;${sid})`;
const owned = [
  ['user, not elevated', user, false, true], ['user, elevated', user, true, true],
  ['Administrators, elevated', administratorsSid, true, true], ['Administrators, not elevated', administratorsSid, false, false],
  ['third party, not elevated', other, false, false], ['third party, elevated', other, true, false],
  ['SYSTEM, elevated', system, true, false], ['no owner, elevated', null, true, false],
].map(([name, owner, elevated, expected]) => ({ name, owner, elevated, protect: true, dacl: only(user), expected }));
const dacls = [
  ['unprotected directory', only(user, ''), true, false], ['unprotected file', only(user, ''), false, true],
  ['second allow rule', `${only(user)}(A;OICI;FA;;;${administratorsSid})`, true, false], ['rule for Administrators only', only(administratorsSid), true, false],
  ['deny rule', only(user, 'P', 'D'), true, false], ['read only', only(user, 'P', 'A', 'FR'), true, false], ['empty DACL', 'D:P', true, false],
].flatMap(([name, dacl, protect, expected]) => [user, administratorsSid].map(owner => ({ name: `${name}, owner ${owner}`, owner, elevated: true, protect, dacl, expected })));

test('the private owner rule accepts the user, and Administrators only for an elevated token', windows, () => {
  const cases = [...owned, ...dacls];
  const script = `${privateAclRule}
function Get-Security($sddl) { $security=[Security.AccessControl.DirectorySecurity]::new(); $security.SetSecurityDescriptorSddlForm($sddl); $security }
${cases.map(c => `[string](Test-PrivateAcl (Get-Security '${c.owner ? `O:${c.owner}` : ''}${c.dacl}') ([Security.Principal.SecurityIdentifier]::new('${user}')) $${c.elevated} $${c.protect})`).join('\n')}`;
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot } });
  assert.equal(result.status, 0, result.stderr);
  const actual = result.stdout.trim().split(/\r?\n/);
  assert.deepEqual(cases.map((c, i) => `${c.name}: ${actual[i]}`), cases.map(c => `${c.name}: ${c.expected ? 'True' : 'False'}`));
});

test('the private storage script judges owners by the shared owner rule', windows, () => {
  const source = readFileSync(new URL('../src/private-storage.ts', import.meta.url), 'utf8');
  assert.match(source, /const windowsAcl = `\$\{privateAclRule\}\n\$owned = \{ param\(\$item\) Test-PrivateOwner \(.*\) \$sid \$elevated \}\n/, 'storage $owned delegates to Test-PrivateOwner');
  const script = `${privateAclRule}
${owned.map(c => `[string](Test-PrivateOwner ${c.owner ? `([Security.Principal.SecurityIdentifier]::new('${c.owner}'))` : '$null'} ([Security.Principal.SecurityIdentifier]::new('${user}')) $${c.elevated})`).join('\n')}`;
  const actual = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot } }).stdout.trim().split(/\r?\n/);
  assert.deepEqual(owned.map((c, i) => `${c.name}: ${actual[i]}`), owned.map(c => `${c.name}: ${c.expected ? 'True' : 'False'}`));
});

// WindowsIdentity.Groups comes from TokenGroups and leaves out deny-only entries, so Administrators appears there
// only while the token is elevated. It reads the token apart from the IsInRole check the shared rule uses.
function powershellLines(script) {
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, encoding: 'utf8', env: { SystemRoot: process.env.SystemRoot } });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim().split(/\r?\n/);
}

test('the elevated flag the shared rule computes matches the enabled token groups', windows, () => {
  const [enabled] = powershellLines(`[string](@([Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -eq '${administratorsSid}' }).Count -eq 1)`);
  assert.match(enabled, /^(True|False)$/, 'the token groups were read');
  assert.deepEqual(powershellLines(`${privateAclRule}
[string]$elevated
$security=[Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm("O:${administratorsSid}D:P(A;OICI;FA;;;$($sid.Value))")
[string](Test-PrivateAcl $security $sid $elevated $true)`), [enabled, enabled], `Administrators enabled in the token: ${enabled}; elevated, then an Administrators-owned private ACL`);
});

// The ACL calls read and write the junction's own security descriptor, not its target's. Giving the junction a
// private ACL of its own leaves the reparse attribute as the only reason left to reject it.
async function privateJunction(t) {
  const parent = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-junction-'));
  test.after(() => removeTempDirStrict(parent, { recursive: true, force: true }));
  const target = path.join(parent, 'target'), link = path.join(parent, 'link');
  await fs.mkdir(target);
  try { await fs.symlink(target, link, 'junction'); } catch (error) { t.skip(`a junction could not be created: ${error.code}`); return null; }
  assert.ok((await fs.lstat(link)).isSymbolicLink(), 'the link is a reparse point');
  assert.equal(run(`${privateAclRule}
$item=[System.IO.DirectoryInfo]::new($env:SCANMUX_PROBE)
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
$item.SetAccessControl($acl)
if (!(Test-PrivateAcl $item.GetAccessControl() $sid $elevated $true)) { exit 1 }`, { SCANMUX_PROBE: link }), 0, 'the junction carries a private ACL of its own');
  return link;
}

test('the credential ACL script rejects a junction that carries a private ACL', windows, async t => {
  const link = await privateJunction(t);
  if (link) assert.notEqual(run(privateAcl, { SCANMUX_AI_CREDENTIAL_PATH: link }), 0);
});

test('the SIWC store ACL script rejects a junction that carries a private ACL', windows, async t => {
  const link = await privateJunction(t);
  if (link) assert.notEqual(run(aclScript, { SCANMUX_SIWC_PATH: link, SCANMUX_SIWC_CREATE: '0' }), 0);
});

test('the SIWC store carries the same owner rule as the shared module', () => {
  assert.equal(storageRule, privateAclRule);
});
