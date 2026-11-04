import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import childProcess from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { languages, materializePair, lockedVersion, vendoredVersion, totalBytes, buildRepo } from '../scripts/eval-pairs.mjs';
import jsProbe from '../eval/pairs/js/test/test.mjs';
import pythonProbe from '../eval/pairs/python/test/test.mjs';

const manifestNames = new Set(['package.json', 'package-lock.json', 'requirements.txt', 'go.mod']);
const differing = pair => [...pair.base.keys()].filter(name => {
  const a = pair.base.get(name), b = pair.head.get(name);
  return a === undefined || b === undefined || !a.equals(b);
});

function writeTree(root, files) {
  for (const [name, bytes] of files) {
    const target = path.join(root, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
}

test('the JS oracle observes base and head but propagates unexpected template errors', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'scanmux-eval-js-'));
  const pair = materializePair('js');
  try {
    for (const [revision, problem] of [['base', 'present'], ['head', 'absent']]) {
      const projectRoot = path.join(root, revision);
      writeTree(projectRoot, pair[revision]);
      assert.deepEqual(await jsProbe({ projectRoot }), { kind: 'observed', problem });
    }
    const invalidVariable = 'Invalid `variable` option passed into `_.template`';
    for (const [index, statement] of [
      "throw new RangeError('unexpected template failure')",
      `throw new TypeError(${JSON.stringify(invalidVariable)})`,
      `throw new Error(${JSON.stringify(invalidVariable + ' unexpectedly')})`,
    ].entries()) {
      const projectRoot = path.join(root, `broken-${index}`);
      writeTree(projectRoot, pair.head);
      writeFileSync(path.join(projectRoot, 'vendor/lodash/template.js'), `module.exports = () => { ${statement}; };\n`);
      await assert.rejects(() => jsProbe({ projectRoot }), /unexpected|Invalid/);
    }
    const projectRoot = path.join(root, 'no-marker');
    writeTree(projectRoot, pair.head);
    writeFileSync(path.join(projectRoot, 'vendor/lodash/template.js'), 'module.exports = () => () => {};\n');
    await assert.rejects(() => jsProbe({ projectRoot }), /completed without the expected marker/);
  } finally { delete globalThis.__scanmux_lodash_template_marker; rmSync(root, { recursive: true, force: true }); }
});

test('the Python harness and oracle distinguish base, head, import failure and a broken loader', async t => {
  const run = childProcess.spawnSync;
  let python;
  for (const candidate of process.platform === 'win32' ? ['python3', 'python'] : ['python3']) {
    const result = run(candidate, ['-I', '-B', '-c', 'import sys; print(sys.version_info.major)'], { encoding: 'utf8', windowsHide: true });
    if (result.error?.code === 'ENOENT') continue;
    assert.ifError(result.error);
    assert.equal(result.status, 0, 'python3 must start successfully');
    assert.equal(result.stdout.trim(), '3', 'the harness requires Python 3');
    python = candidate; break;
  }
  if (!python) { t.skip('python3 is missing (including the Windows python executable)'); return; }
  const root = mkdtempSync(path.join(tmpdir(), 'scanmux-eval-python-'));
  const pair = materializePair('python');
  try {
    t.mock.method(childProcess, 'spawnSync', (executable, args, options) => {
      assert.equal(executable, '/usr/bin/python3');
      return run(python, args, { ...options, env: { ...process.env, SCANMUX_MARKER_PATH: options.env.SCANMUX_MARKER_PATH } });
    }); syncBuiltinESMExports();
    for (const [revision, token, problem] of [['base', 'MARKER_WRITTEN', 'present'], ['head', 'CONSTRUCTOR_ERROR', 'absent'], ['broken', '', null], ['import', 'IMPORT_FAIL', null]]) {
      const projectRoot = path.join(root, revision), marker = path.join(projectRoot, 'marker');
      writeTree(projectRoot, pair[revision === 'base' ? 'base' : 'head']);
      if (revision === 'broken') writeFileSync(path.join(projectRoot, 'vendor/pyyaml/yaml/__init__.py'),
        'class constructor:\n    class ConstructorError(Exception): pass\ndef full_load(document):\n    raise RuntimeError("broken loader")\n');
      if (revision === 'import') writeFileSync(path.join(projectRoot, 'vendor/pyyaml/yaml/__init__.py'), 'raise ImportError("broken import")\n');
      const result = run(python, ['-I', '-B', path.join(projectRoot, pair.testDirectory, 'run_yaml.py'), path.join(projectRoot, 'vendor/pyyaml'), path.join(projectRoot, pair.testDirectory, 'payload.yaml')],
        { encoding: 'utf8', windowsHide: true, env: { ...process.env, SCANMUX_MARKER_PATH: marker } });
      assert.ifError(result.error);
      assert.equal(result.signal, null);
      assert.equal(result.stdout.trim(), token, `${revision}: harness result`);
      assert.equal(existsSync(marker), revision === 'base', `${revision}: marker presence`);
      if (revision === 'broken') {
        assert.notEqual(result.status, 0, 'an unexpected loader exception must fail the child');
        await assert.rejects(() => pythonProbe({ projectRoot }));
      } else {
        assert.equal(result.status, 0, `${revision}: clean exit`);
        if (problem) assert.deepEqual(await pythonProbe({ projectRoot }), { kind: 'observed', problem });
        else assert.deepEqual(await pythonProbe({ projectRoot }), { kind: 'environment_missing', reason: 'fixture_missing' });
      }
    }
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); rmSync(root, { recursive: true, force: true }); }
});

test('the Python oracle requires a clean child and a consistent result token and marker', async t => {
  const projectRoot = fileURLToPath(new URL('../eval/pairs/python/base/', import.meta.url));
  const failures = [
    { status: 1 }, { status: 1, stdout: 'CONSTRUCTOR_ERROR\n' }, { status: 1, stdout: 'IMPORT_FAIL\n' },
    { status: null, signal: 'SIGTERM' }, { error: Object.assign(new Error('spawn refused'), { code: 'EACCES' }) },
    { stdout: '' }, { stdout: 'LOAD_ERROR\n' }, { stdout: 'noise CONSTRUCTOR_ERROR\n' },
    { stdout: 'MARKER_WRITTEN\n' }, { stdout: 'MARKER_WRITTEN\n', marker: 'wrong' },
    { stdout: 'CONSTRUCTOR_ERROR\n', marker: '' }, { stdout: 'CONSTRUCTOR_ERROR\n', marker: '73' },
    { status: 1, stdout: 'MARKER_WRITTEN\n', marker: '73' },
  ];
  let child;
  try {
    t.mock.method(childProcess, 'spawnSync', (_executable, _args, options) => {
      if (child.marker !== undefined) writeFileSync(options.env.SCANMUX_MARKER_PATH, child.marker);
      return { status: 0, signal: null, stdout: '', ...child };
    }); syncBuiltinESMExports();
    for (const failure of failures) {
      child = failure;
      await assert.rejects(() => pythonProbe({ projectRoot }), `must reject ${JSON.stringify(failure)}`);
    }
    for (const [result, observation] of [
      [{ stdout: 'MARKER_WRITTEN\n', marker: '73' }, { kind: 'observed', problem: 'present' }],
      [{ stdout: 'CONSTRUCTOR_ERROR\n' }, { kind: 'observed', problem: 'absent' }],
      [{ stdout: 'IMPORT_FAIL\n' }, { kind: 'environment_missing', reason: 'fixture_missing' }],
      [{ error: Object.assign(new Error('missing python'), { code: 'ENOENT' }) }, { kind: 'environment_missing', reason: 'runtime_not_available' }],
    ]) {
      child = result;
      assert.deepEqual(await pythonProbe({ projectRoot }), observation);
    }
  } finally { t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('every pair keeps the same file set at base and head', () => {
  for (const lang of languages) {
    const pair = materializePair(lang);
    assert.deepEqual([...pair.base.keys()].sort(), [...pair.head.keys()].sort(), `${lang}: base and head name the same files`);
  }
});

test('lockfiles name the vulnerable and fixed versions, and vendored code matches', () => {
  for (const lang of languages) {
    const pair = materializePair(lang), lockfile = pair.meta.lockfile;
    assert.equal(lockedVersion(lang, pair.base.get(lockfile)), pair.meta.base.version, `${lang}: base lockfile version`);
    assert.equal(lockedVersion(lang, pair.head.get(lockfile)), pair.meta.head.version, `${lang}: head lockfile version`);
    const vb = vendoredVersion(lang, pair.base), vh = vendoredVersion(lang, pair.head);
    if (vb !== null) {
      assert.equal(vb, pair.meta.base.version, `${lang}: base vendored version matches lockfile`);
      assert.equal(vh, pair.meta.head.version, `${lang}: head vendored version matches lockfile`);
    } else assert.equal(pair.meta.scannerOnly, true, `${lang}: only a scanner-only pair may skip vendored code`);
  }
});

test('the only base/head differences are the dependency files, never the test directory', () => {
  for (const lang of languages) {
    const pair = materializePair(lang), changed = differing(pair);
    assert.ok(changed.length > 0, `${lang}: base and head must differ by the upgrade`);
    for (const name of changed) {
      if (pair.testDirectory) assert.ok(!name.startsWith(pair.testDirectory + '/'), `${lang}: ${name} must not change inside the test directory`);
      const isDependencyFile = manifestNames.has(path.posix.basename(name)) || name.startsWith('vendor/');
      assert.ok(isDependencyFile, `${lang}: unexpected non-dependency change ${name}`);
    }
  }
});

test('the shared test directory is byte-identical at base and head', () => {
  for (const lang of languages) {
    const pair = materializePair(lang);
    if (!pair.testDirectory) { assert.equal(pair.meta.reproduces, false, `${lang}: a pair without a test directory cannot reproduce`); continue; }
    const testKeys = [...pair.base.keys()].filter(name => name.startsWith(pair.testDirectory + '/'));
    assert.ok(testKeys.length > 0, `${lang}: the test directory must hold files`);
    for (const name of testKeys) assert.ok(pair.base.get(name).equals(pair.head.get(name)), `${lang}: ${name} identical`);
  }
});

test('each pair stays under its size limit at both commits', () => {
  for (const lang of languages) {
    const pair = materializePair(lang);
    assert.ok(totalBytes(pair.base) < pair.sizeLimitBytes, `${lang}: base under ${pair.sizeLimitBytes}`);
    assert.ok(totalBytes(pair.head) < pair.sizeLimitBytes, `${lang}: head under ${pair.sizeLimitBytes}`);
  }
});

test('building a pair commits identical test trees and distinct 40-character commits', t => {
  if (spawnSync('git', ['--version'], { windowsHide: true }).status !== 0) { t.skip('git not available'); return; }
  const root = mkdtempSync(path.join(tmpdir(), 'scanmux-eval-build-'));
  try {
    for (const lang of languages) {
      const out = path.join(root, lang), result = buildRepo(lang, out);
      assert.match(result.base, /^[a-f0-9]{40}$/, `${lang}: base commit`);
      assert.match(result.head, /^[a-f0-9]{40}$/, `${lang}: head commit`);
      assert.notEqual(result.base, result.head, `${lang}: commits differ`);
      if (!result.testDirectory) continue;
      const tree = commit => spawnSync('git', ['-C', out, 'ls-tree', '-r', commit, result.testDirectory], { encoding: 'utf8', windowsHide: true }).stdout;
      assert.equal(tree(result.base), tree(result.head), `${lang}: test tree unchanged between commits`);
      assert.ok(tree(result.base).length > 0, `${lang}: test tree present`);
    }
  } finally { rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
});

// The README's checkout lines, with the git options they pass before `-C`.
const checkoutOptions = () => {
  const readme = readFileSync(fileURLToPath(new URL('../eval/README.md', import.meta.url)), 'utf8');
  const lines = [...readme.matchAll(/^git ((?:-c \S+ )*)-C \S+ checkout <(BASE|HEAD)_40>$/gm)];
  assert.deepEqual(lines.map(m => m[2]), ['BASE', 'HEAD'], 'eval/README.md documents one checkout of base and one of head');
  assert.equal(lines[0][1], lines[1][1], 'both checkouts pass the same git options');
  return lines[0][1].trim().split(/\s+/).filter(Boolean);
};
// Same allowlist as `job-scan` applies to .git/config (src/repository.ts).
const allowedConfig = { core: ['repositoryformatversion', 'filemode', 'bare', 'logallrefupdates', 'symlinks', 'ignorecase'], remote: ['url', 'fetch'], branch: ['remote', 'merge'] };

test('with a global core.autocrlf=true, the documented checkouts leave working files byte-identical to the commits', t => {
  if (spawnSync('git', ['--version'], { windowsHide: true }).status !== 0) { t.skip('git not available'); return; }
  const root = mkdtempSync(path.join(tmpdir(), 'scanmux-eval-crlf-'));
  const globalConfig = path.join(root, 'global.gitconfig');
  writeFileSync(globalConfig, '[core]\n\tautocrlf = true\n');
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig };
  const userGit = (out, args, encoding = 'utf8') => {
    const result = spawnSync('git', ['-C', out, ...args], { encoding, windowsHide: true, env, maxBuffer: 64 * 1024 * 1024 });
    assert.equal(result.status, 0, `git ${args.join(' ')}: ${result.stderr}`);
    return result.stdout;
  };
  const saved = process.env.GIT_CONFIG_GLOBAL;
  try {
    process.env.GIT_CONFIG_GLOBAL = globalConfig;
    const options = checkoutOptions();
    for (const lang of languages) {
      const out = path.join(root, lang), result = buildRepo(lang, out);
      let section = '';
      for (const line of readFileSync(path.join(out, '.git', 'config'), 'utf8').split(/\r?\n/).map(text => text.trim()).filter(Boolean)) {
        const heading = /^\[([a-z]+)(?: "[^"]+")?\]$/i.exec(line);
        if (heading) { section = heading[1].toLowerCase(); continue; }
        const key = (/^([a-z]+)\s*=/i.exec(line) ?? [])[1]?.toLowerCase();
        assert.ok(allowedConfig[section]?.includes(key) || process.platform === 'darwin' && section === 'core' && key === 'precomposeunicode',
          `${lang}: .git/config key ${section}.${key} is outside the job-scan allowlist`);
      }
      for (const commit of [result.base, result.head]) {
        const checkout = spawnSync('git', [...options, '-C', out, 'checkout', '-q', commit], { encoding: 'utf8', windowsHide: true, env });
        assert.equal(checkout.status, 0, `${lang}: checkout ${commit}: ${checkout.stderr}`);
        for (const entry of userGit(out, ['ls-tree', '-r', '-z', commit]).split('\0').filter(Boolean)) {
          const [meta, name] = entry.split('\t'), blob = meta.split(' ')[2];
          const committed = userGit(out, ['cat-file', 'blob', blob], 'buffer');
          assert.ok(readFileSync(path.join(out, name)).equals(committed), `${lang}: ${name} at ${commit.slice(0, 7)} matches the committed blob`);
        }
      }
    }
  } finally {
    if (saved === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = saved;
    rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
