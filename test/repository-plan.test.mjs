import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import path from 'node:path';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { defaults } from '../src/config.ts';
import { commitPair, treeEntries } from '../src/comparison.ts';
import { readGitBlobs } from '../src/git-blobs.ts';
import { legacyEngines } from '../src/engine-catalog.ts';
import { observeConfiguration, summarizeConfiguration } from '../src/configuration.ts';
import { digest, hash, SafeError, safeRelative } from '../src/safety.ts';

const source = stripTypeScriptTypes(await readFile('src/repository.ts', 'utf8')).replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
async function repository(testMode = '100755') {
  const commit = 'a'.repeat(40), tree = 'b'.repeat(40), oid = 'c'.repeat(40), content = Buffer.from('export const fixture = 1;\n'), calls = [];
  const entries = [['app.mjs', '100755'], ['tests/repro/test.mjs', testMode], ['tests/repro/nested/helper.mjs', '100644'], ['tests/reproduction/test.mjs', '100755']];
  const dependencies = { catalogIdentity, path, digest, hash, SafeError, safeRelative, commitPair, treeEntries, readGitBlobs, legacyEngines, observeConfiguration, summarizeConfiguration,
    canonical: async value => value, lstat: async name => {
      if (name.endsWith('.git')) return { isDirectory: () => true, isSymbolicLink: () => false };
      if (!name.endsWith('.git/config')) throw Error('missing');
      return { isSymbolicLink: () => false };
    }, readdir: async () => [], readFile: async () => '[core]\nrepositoryformatversion = 0\nbare = false\n', verifyVersion: async () => {}, jobDiskDiagnostic: () => null,
    execute: async (_tool, args, options) => {
      const command = args.slice(args.indexOf('-C') + 2); calls.push(command);
      const text = command[0] === 'status' ? '' : command[0] === 'ls-tree' ? entries.map(([name, mode]) => `${mode} blob ${oid} ${content.length}\t${name}\0`).join('')
        : command[0] === 'cat-file' ? Buffer.concat(options.input.trimEnd().split('\n').flatMap(oid => [Buffer.from(`${oid} blob ${content.length}\n`), content, Buffer.from('\n')]))
          : command.at(-1).endsWith('^{tree}') ? tree + '\n' : commit + '\n';
      return { reason: 'exit', code: 0, stdout: Buffer.from(text) };
    } };
  const buildPlan = new AsyncFunction(...Object.keys(dependencies), source + '\nreturn buildPlan;')(...Object.values(dependencies));
  return { buildPlan: await buildPlan, calls, config: { ...defaults, tools: { git: { path: '/fixture/git', sha256: 'd'.repeat(64), version: '2.54.0' } } } };
}

test('ordinary buildPlan preserves the origin/main file shape and plan hash', async () => {
  const { buildPlan, config } = await repository(), plan = await buildPlan('/fixture/repository', config, '/fixture/work');
  assert.deepEqual(plan.blockers, []); assert.equal(plan.files.length, 4);
  for (const file of plan.files) assert.deepEqual(Object.keys(file), ['path', 'oid', 'bytes', 'sha256']);
  const files = plan.files.map(({ path, oid, bytes, sha256 }) => ({ path, oid, bytes, sha256 }));
  const legacy = { ...plan, files, snapshotHash: digest(files), planHash: '' };
  assert.equal(plan.snapshotHash, legacy.snapshotHash); assert.equal(plan.planHash, digest(legacy));
  assert.equal(JSON.stringify(plan), JSON.stringify({ ...legacy, planHash: digest(legacy) }));
});

test('reproduction captures only its test directory modes from the same tree without changing the plan', async () => {
  for (const mode of ['100644', '100755']) {
    const { buildPlan, config, calls } = await repository(mode), ordinary = await buildPlan('/fixture/repository', config, '/fixture/work');
    const capture = { directory: 'tests/repro', modes: new Map([['stale.mjs', '100644']]) };
    const reproduction = await buildPlan('/fixture/repository', config, '/fixture/work', undefined, undefined, capture);
    assert.deepEqual(capture.modes, new Map([['tests/repro/test.mjs', mode], ['tests/repro/nested/helper.mjs', '100644']]));
    assert.equal(JSON.stringify(reproduction), JSON.stringify(ordinary));
    assert.deepEqual(calls.filter(args => args[0] === 'ls-tree'), Array(2).fill(['ls-tree', '-r', '-z', '-l', ordinary.commit]));
  }
});
