import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

test('a CLI that cannot load its modules exits with a fixed error, 2 for deps and 4 otherwise', async () => {
  // Only the bin directory is copied, so loading ../src fails as it would with a broken install.
  const home = await mkdtemp(path.resolve('test/cli-startup-'));
  test.after(() => rm(home, { recursive: true, force: true }));
  await mkdir(path.join(home, 'bin'));
  for (const file of ['scanmux.mjs', 'typescript-bootstrap.mjs']) await copyFile(path.join('bin', file), path.join(home, 'bin', file));
  for (const [command, code] of [['deps', 2], ['scan', 4], ['doctor', 4]] as const) {
    const result = spawnSync(process.execPath, [path.join(home, 'bin', 'scanmux.mjs'), command, home], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, code, command);
    assert.deepEqual(JSON.parse(result.stderr), { schema: 'scanmux.error/v1', ...(command === 'deps' ? {} : { gate: 'ERROR' }), exitCode: code, error: 'startup_failed' });
    assert.equal(result.stdout, '');
  }
});
