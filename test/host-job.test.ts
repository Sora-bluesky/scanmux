import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawn } from 'node:child_process';

async function cli(args: string[]) {
  const child = spawn(process.execPath, ['bin/scanmux.mjs', ...args], {
    windowsHide: true, shell: false, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout: Buffer[] = [], stderr: Buffer[] = [];
  let bytes = 0;
  for (const [stream, parts] of [[child.stdout, stdout], [child.stderr, stderr]] as const) stream.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > 65536) child.kill(); else parts.push(Buffer.from(chunk));
  });
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

test('Windows host job requires its explicit profile before any target work', async () => {
  const result = await cli(['host-job-scan', path.resolve('.local/absent-host-job-target')]);
  assert.equal(result.code, 4);
  assert.equal(result.stdout, '');
  assert.equal(JSON.parse(result.stderr).error, 'host_job_profile_required');
});

test('host profile authority cannot reach an old command and unrelated flags cannot reach host work', async () => {
  const root = path.resolve('.local/absent-host-target'), profile = path.resolve('.local/absent-host-profile.json');
  for (const command of ['doctor', 'plan', 'scan', 'ai-plan', 'ai-scan', 'plan-list', 'scan-list', 'serve', 'runner-check', 'ci-check', 'history', 'recover', 'resume', 'dispositions', 'policy-check', 'job-scan', 'job-export', 'job-recover']) {
    const result = await cli([command, ...(['doctor', 'serve', 'runner-check'].includes(command) ? [] : [root]), '--host-job-profile', profile]);
    assert.equal(result.code, 4); assert.equal(result.stdout, ''); assert.equal(JSON.parse(result.stderr).error, 'invalid_command');
  }
  for (const flags of [['--job-profile', profile], ['--config', profile], ['--report-language', 'en'], ['--accept-plan', 'a'.repeat(64)], ['--from', profile], ['--ci-run', '11111111-1111-4111-8111-111111111111']]) {
    const result = await cli(['host-job-scan', root, '--host-job-profile', profile, ...flags]);
    assert.equal(result.code, 4); assert.equal(result.stdout, ''); assert.equal(JSON.parse(result.stderr).error, 'invalid_command');
  }
});
