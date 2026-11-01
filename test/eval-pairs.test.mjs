import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { languages, materializePair, lockedVersion, vendoredVersion, totalBytes, buildRepo } from '../scripts/eval-pairs.mjs';

const manifestNames = new Set(['package.json', 'package-lock.json', 'requirements.txt', 'go.mod']);
const differing = pair => [...pair.base.keys()].filter(name => {
  const a = pair.base.get(name), b = pair.head.get(name);
  return a === undefined || b === undefined || !a.equals(b);
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
        assert.ok(allowedConfig[section]?.includes(key), `${lang}: .git/config key ${section}.${key} is outside the job-scan allowlist`);
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
