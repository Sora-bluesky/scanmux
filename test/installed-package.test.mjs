import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { command, installPackage, verifyDependencies } from '../scripts/ci-installed-package.mjs';
import { removeTempDir } from './temp-cleanup.mjs';

test('a real packed package starts through the installed npm bin under node_modules', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'scanmux-installed-'));
  try {
    const installed = await installPackage(directory);
    const result = await command(installed.bin, ['--version'], { cwd: installed.consumer });
    assert.equal(result.code, 0, result.stderr);
    const { version } = JSON.parse(await readFile('package.json', 'utf8'));
    assert.equal(result.stdout.toString('utf8'), version + '\n');
    assert.equal(result.stderr, '');
    for (const entry of ['internal/windows-job-worker.mjs', 'internal/linux-job-controller.mjs']) {
      const worker = await command(process.execPath, [path.join(installed.app, entry)], { cwd: installed.consumer });
      assert.equal(worker.code, entry.includes('windows') ? 1 : 4, worker.stderr);
      assert.equal(worker.stdout.length, 0); assert.equal(worker.stderr, '');
    }
  } finally { await removeTempDir(directory); }
});
test('installed deps gate rejects help, missing prerequisites, incomplete analysis and mismatched identity', () => {
  const input = [{ path: 'package-lock.json', bytes: 5, sha256: 'a'.repeat(64) }];
  const report = { schema: 'scanmux.dependencies/v2', tool: { name: 'scanmux', version: '0.2.0' }, commits: { head: 'b'.repeat(40), base: null },
    exitCode: 0, osv: { state: 'completed', errors: [], sides: { head: { state: 'completed' } } }, missing: [], inputs: { head: input } };
  const result = value => ({ code: 0, signal: null, overflow: false, stderr: '', stdout: Buffer.from(JSON.stringify(value)) });
  const check = value => verifyDependencies(value, '0.2.0', 'b'.repeat(40), input);
  assert.equal(check(result(report)).schema, report.schema);
  for (const mutate of [r => { r.schema = 'help'; }, r => { r.tool.version = '0.1.0'; }, r => { r.commits.head = 'c'.repeat(40); },
    r => { r.exitCode = 2; }, r => { r.osv.state = 'failed'; }, r => { r.osv.sides.head.state = 'not_started'; },
    r => { r.missing = [{ kind: 'plan_blocker' }]; }, r => { r.inputs.head = []; }, r => { r.osv.errors = ['tool_missing']; }]) {
    const copy = structuredClone(report); mutate(copy); assert.throws(() => check(result(copy)));
  }
  for (const changes of [{ code: 2 }, { signal: 'SIGTERM' }, { overflow: true }, { stdout: Buffer.from('Usage: scanmux') },
    { stdout: Buffer.from(JSON.stringify(report) + JSON.stringify(report)) }, { stderr: 'ExperimentalWarning: stripTypeScriptTypes is an experimental feature and might change at any time' }]) {
    assert.throws(() => check({ ...result(report), ...changes }));
  }
  assert.doesNotThrow(() => check({ ...result(report), stderr: 'An unrelated warning\n' }));
});
