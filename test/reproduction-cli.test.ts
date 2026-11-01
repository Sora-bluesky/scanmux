import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';

async function cli(args: string[]) {
  return new Promise<{ code: number | null; out: string; err: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ['bin/scanmux.mjs', ...args], { env: { ...process.env }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    child.stdout.on('data', bytes => { out += bytes; }); child.stderr.on('data', bytes => { err += bytes; });
    child.on('error', reject); child.once('close', code => resolve({ code, out, err }));
  });
}
test('reproduction CLI admits only the closed caller choices, and new flags cannot enter old commands', async () => {
  const nowhere = path.resolve('test/nonexistent-reproduction-input'), selection = 'codex-security:' + 'a'.repeat(64);
  const base = ['reproduce', nowhere, '--job-profile', nowhere, '--from', nowhere, '--finding', selection, '--test', 'tests/repro'];
  for (const extra of [['--config', nowhere], ['--host-job-profile', nowhere], ['--report-language', 'en'], ['--accept-plan', 'a'.repeat(64)], ['--ci-run', '11111111-1111-4111-8111-111111111111']]) {
    const result = await cli([...base, ...extra]); assert.equal(result.code, 4); assert.equal(result.out, ''); assert.equal(JSON.parse(result.err).error, 'invalid_command');
  }
  for (const command of ['plan', 'scan', 'job-scan', 'ai-plan']) for (const option of ['--finding', '--test', '--required']) {
    const result = await cli([command, nowhere, option, ...(option === '--required' ? [] : ['value'])]);
    assert.equal(result.code, 4); assert.equal(result.out, ''); assert.equal(JSON.parse(result.err).error, 'invalid_command');
  }
  for (const sha of ['abc123', 'A'.repeat(40), 'refs/heads/main']) {
    const result = await cli([...base, '--base', sha, '--head', 'b'.repeat(40)]); assert.equal(result.code, 4); assert.equal(JSON.parse(result.err).error, 'invalid_comparison_sha');
  }
  for (const finding of ['codex-security:short', 'trivy:' + 'a'.repeat(64), 'unknown:' + 'a'.repeat(64)]) {
    const args = [...base]; args[args.indexOf('--finding') + 1] = finding;
    const result = await cli(args); assert.equal(result.code, 4); assert.equal(JSON.parse(result.err).error, 'invalid_reproduction_selection');
  }
});
