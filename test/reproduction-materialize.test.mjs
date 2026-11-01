import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import path from 'node:path';
import { defaults } from '../src/config.ts';
import { legacyEngines } from '../src/engine-catalog.ts';
import { hash, SafeError } from '../src/safety.ts';

const source = stripTypeScriptTypes(await readFile('src/repository.ts', 'utf8')).replace(/^import .*;\r?\n/gm, '').replace(/^export /gm, '');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
async function fixture(mode = '100755') {
  const names = ['app.mjs', 'tests/repro/test.mjs', 'tests/repro/nested/helper.mjs', 'tests/repro/nested/fixture.txt', 'tests/reproduction/test.mjs'];
  const content = Buffer.from('fixture\n'), files = new Map(), writes = [], stats = [];
  const plan = { root: '/fixture/repository', files: names.map(name => ({ path: name, oid: 'a'.repeat(40), bytes: content.length, sha256: hash(content) })) };
  const modes = { 'tests/repro/test.mjs': mode, 'tests/repro/nested/helper.mjs': '100755', 'tests/repro/nested/fixture.txt': '100644' };
  const dependencies = { path, hash, SafeError, legacyEngines, sourceCleanupFor: () => ({ register: (_workspace, snapshot) => snapshot, capture: async () => {} }),
    mkdir: async () => {}, writeFile: async (name, bytes, options) => {
      assert.equal(options.flag, 'wx'); assert.equal(files.has(name), false); writes.push(options.mode); files.set(name, { bytes: Buffer.from(bytes), mode: 0o100000 | options.mode });
    }, readFile: async name => files.get(name).bytes, lstat: async name => { stats.push(name); return { mode: files.get(name).mode, isFile: () => true, isSymbolicLink: () => false }; },
    readdir: async folder => {
      const entries = new Map();
      for (const name of files.keys()) {
        if (!name.startsWith(folder + path.sep)) continue;
        const [entry, ...rest] = name.slice(folder.length + 1).split(path.sep);
        entries.set(entry, { name: entry, isSymbolicLink: () => false, isDirectory: () => rest.length > 0, isFile: () => rest.length === 0 });
      }
      return [...entries.values()];
    }, readGitBlobs: async function* (entries) { for (const entry of entries) yield { entry, content }; } };
  const { materialize, verifySnapshot } = await new AsyncFunction(...Object.keys(dependencies), source + '\nreturn { materialize, verifySnapshot };')(...Object.values(dependencies));
  return { materialize, verifySnapshot, plan, modes, files, writes, stats };
}

for (const mode of ['100755', '100644']) test('reproduction materializes recorded test modes, including nested files: ' + mode, async () => {
  const f = await fixture(mode), snapshot = await f.materialize(f.plan, defaults, '/fixture/work', new AbortController().signal, f.modes);
  for (const file of f.plan.files) assert.equal(f.files.get(path.join(snapshot, file.path)).mode & 0o7777, f.modes[file.path] === '100755' ? 0o700 : 0o600, file.path);
  assert.equal(await f.verifySnapshot(f.plan, snapshot, f.modes), true);
  assert.deepEqual(f.stats, Object.keys(f.modes).map(name => path.join(snapshot, name)));
});

for (const [recorded, actual] of [['100755', 0o600], ['100644', 0o700], ['100755', 0o710], ['100644', 0o640], ['100755', 0o4700]]) {
  test(`reproduction refuses materialized test mode ${actual.toString(8)} for ${recorded} with unchanged content`, async () => {
    const f = await fixture(recorded), snapshot = await f.materialize(f.plan, defaults, '/fixture/work', new AbortController().signal, f.modes);
    f.files.get(path.join(snapshot, 'tests/repro/test.mjs')).mode = 0o100000 | actual;
    assert.equal(await f.verifySnapshot(f.plan, snapshot, f.modes), false);
  });
}

test('ordinary materialize keeps every file at 0600 and ordinary verification remains content-only', async () => {
  const f = await fixture(), snapshot = await f.materialize(f.plan, defaults, '/fixture/work', new AbortController().signal);
  assert.deepEqual(f.writes, Array(f.plan.files.length).fill(0o600)); assert.equal(await f.verifySnapshot(f.plan, snapshot), true);
  f.files.get(path.join(snapshot, 'tests/repro/test.mjs')).mode = 0o100700;
  assert.equal(await f.verifySnapshot(f.plan, snapshot), true); assert.deepEqual(f.stats, []);
});
