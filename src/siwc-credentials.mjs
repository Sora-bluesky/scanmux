import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { SafeError } from './safety.ts';
import { active, canonicalAiPath, readAiJson } from './ai-files.mjs';
import { privateAclRule } from './private-acl.ts';

const scopes = ['openid', 'profile', 'email', 'offline_access', 'resource.invoke', 'chatgpt.tokens.use.direct'];
const opaque = value => typeof value === 'string' && value.length > 0 && value.length <= 16384 && !/[\x00-\x20\x7f]/u.test(value);
export const privateAcl = `${privateAclRule}
$attributes=[System.IO.File]::GetAttributes($env:SCANMUX_AI_CREDENTIAL_PATH)
if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 1 }
$container=($attributes -band [IO.FileAttributes]::Directory) -ne 0
$item=if ($container) { [System.IO.DirectoryInfo]::new($env:SCANMUX_AI_CREDENTIAL_PATH) } else { [System.IO.FileInfo]::new($env:SCANMUX_AI_CREDENTIAL_PATH) }
if (!(Test-PrivateAcl $item.GetAccessControl() $sid $elevated $container)) { exit 1 }
`;
async function permissions(file, control, kind) {
  await canonicalAiPath(file, control, kind); const stat = await fs.lstat(file); active(control);
  if (process.platform !== 'win32') {
    if (stat.uid !== process.getuid() || stat.mode & 0o077) throw new SafeError('ai_credentials_permissions');
    return;
  }
  const binary = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
  await new Promise((resolve, reject) => {
    active(control); let failure, timer, cleanupTimer, settled = false;
    const child = spawn(binary, ['-NoProfile', '-NonInteractive', '-Command', privateAcl], {
      env: { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows', SCANMUX_AI_CREDENTIAL_PATH: file }, windowsHide: true, shell: false, stdio: 'ignore',
    });
    const finish = error => { if (settled) return; settled = true; clearTimeout(timer); clearTimeout(cleanupTimer); control.signal?.removeEventListener('abort', stop); error ? reject(error) : resolve(); };
    const stop = () => {
      if (failure) return;
      failure = 'ai_credentials_stopped'; try { child.kill(); } catch {}
      cleanupTimer = setTimeout(() => finish(new SafeError('ai_credentials_termination_unverified')), control.cleanupTimeoutMs);
    };
    child.once('error', () => { failure = 'ai_credentials_permissions'; });
    child.once('close', code => finish(failure || code !== 0 ? new SafeError(failure ?? 'ai_credentials_permissions') : undefined));
    control.signal?.addEventListener('abort', stop, { once: true });
    timer = setTimeout(stop, Math.max(1, Math.min(control.commandTimeoutMs, Math.ceil(control.expiresAt - performance.now()))));
    if (control.signal?.aborted) stop();
  }); active(control);
}
async function unlocked(directory) {
  try { await fs.lstat(path.join(directory, 'operation.lock')); }
  catch (error) { if (error.code === 'ENOENT') return; throw new SafeError('ai_credentials_unavailable'); }
  throw new SafeError('ai_credentials_locked');
}
/** Reads an already authenticated dedicated store. It never logs in, refreshes or writes. */
export async function readSiwcCredentials(directory, control) {
  try {
    if (![control?.commandTimeoutMs, control?.cleanupTimeoutMs].every(value => Number.isSafeInteger(value) && value > 0 && value <= 2147483647)) throw new SafeError('ai_credentials_control');
    active(control); await permissions(directory, control, 'directory'); await unlocked(directory); active(control);
    const read = async name => {
      const file = path.join(directory, name); await permissions(file, control, 'file');
      const record = await readAiJson(file, 8 * 1024 * 1024, control); await permissions(file, control, 'file'); return record;
    };
    const registration = await read('registration.json'), record = await read('credentials.json');
    await unlocked(directory); await permissions(directory, control, 'directory'); active(control);
    if (!registration || registration.schema !== 1 || !['authorizing', 'registered_unverified'].includes(registration.state)
      || !/^oaiapp_[A-Za-z0-9_-]{1,200}$/.test(registration.clientId ?? '')
      || !record || record.schema !== 1 || record.state !== 'active' || record.issuer !== 'https://auth.openai.com'
      || record.clientId !== registration.clientId || ![record.subject, record.accessToken].every(opaque)
      || !Array.isArray(record.scopes) || !scopes.every(scope => record.scopes.includes(scope)) || !/^[\x21-\x7e]+$/.test(record.accessToken)) throw new SafeError('ai_credentials_unverified');
    if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt <= Date.now()) throw new SafeError('ai_credentials_expired');
    return Object.freeze({ accessToken: record.accessToken, expiresAt: record.expiresAt });
  } catch (error) {
    if (error instanceof SafeError) throw error;
    throw new SafeError('ai_credentials_unavailable');
  }
}
