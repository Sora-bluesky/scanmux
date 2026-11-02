import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { main } from '../src/cli.ts';
import { loadConfig } from '../src/config.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import type { Config } from '../src/model.ts';
import { realConfigPath, realConfigSkip } from './real-config.ts';

const configPath = realConfigPath ?? '';
let config!: Config, fixtureRoot!: string, repo!: string, hooks!: string;
function git(args: string[]): string {
  const result = spawnSync(config.tools.git!.path, ['--no-optional-locks', '-c', `core.hooksPath=${hooks}`, '-c', 'core.autocrlf=false', '-c', 'protocol.allow=never', '-C', repo, ...args], {
    encoding: 'utf8', windowsHide: true, env: { SystemRoot: process.env.SystemRoot, HOME: fixtureRoot, USERPROFILE: fixtureRoot, GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: path.join(fixtureRoot, 'empty-gitconfig'), GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  });
  assert.equal(result.status, 0, 'trusted fixture Git command');
  return result.stdout.trim();
}
const pkg = (name: string, version: string, extra: Record<string, unknown> = {}) => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`, integrity: 'sha512-' + version, ...extra });
function npmFiles(head: boolean) {
  const dependencies = { lodash: '^4.17.0', ...(head ? { 'left-pad': '^1.3.0' } : {}) };
  const packages: Record<string, unknown> = { '': { name: 'app', version: '1.0.0', dependencies }, 'node_modules/lodash': pkg('lodash', head ? '4.17.20' : '4.17.19') };
  if (head) packages['node_modules/left-pad'] = pkg('left-pad', '1.3.0');
  return { 'package.json': JSON.stringify({ name: 'app', version: '1.0.0', dependencies }, null, 2), 'package-lock.json': JSON.stringify({ name: 'app', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2) };
}
function uvFiles(head: boolean) {
  const requests = head ? '2.30.0' : '2.29.0';
  return {
    'py/pyproject.toml': ['[project]', 'name = "app"', 'version = "0.1.0"', 'dependencies = ["requests>=2.0,<3"]', ''].join('\n'),
    'py/uv.lock': ['version = 1', 'revision = 2', 'requires-python = ">=3.12"', '',
      '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }', 'dependencies = [', '    { name = "requests" },', ']', '',
      '[package.metadata]', 'requires-dist = [{ name = "requests", specifier = ">=2.0,<3" }]', '',
      '[[package]]', 'name = "requests"', `version = "${requests}"`, 'source = { registry = "https://pypi.org/simple" }', ''].join('\n'),
  };
}
async function commit(files: Record<string, string>, message: string): Promise<string> {
  for (const [name, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(repo, name)), { recursive: true });
    await fs.writeFile(path.join(repo, name), text);
  }
  git(['add', '-A']); git(['commit', '-q', '-m', message]);
  return git(['rev-parse', 'HEAD']);
}
let base = '', head = '';
if (realConfigPath) {
  config = await loadConfig(configPath);
  fixtureRoot = await privateWorkspace(process.cwd());
  test.after(() => removeTempDirStrict(fixtureRoot, { recursive: true, force: true }));
  repo = path.join(fixtureRoot, 'repository'); hooks = path.join(fixtureRoot, 'hooks');
  await fs.mkdir(repo); await fs.mkdir(hooks);
  git(['init', '-q', '--initial-branch=main', `--template=${hooks}`]);
  base = await commit({ ...npmFiles(false), ...uvFiles(false), 'README.md': 'fixture\n' }, 'base');
  head = await commit({ ...npmFiles(true), ...uvFiles(true) }, 'head');
}

async function invoke(args: string[]) {
  const temporary = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-dependencies-cli-'));
  test.after(async () => {
    for (const name of await fs.readdir(temporary).catch(() => [])) if (name.startsWith('scanmux-')) await removeTempDir(path.join(temporary, name));
    await removeTempDir(temporary);
  });
  const saved = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  Object.assign(process.env, { TEMP: temporary, TMP: temporary, TMPDIR: temporary });
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  // The test runner reports through the same stream with binary frames; only the CLI's text is captured.
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (output.push(chunk), true) : out.call(process.stdout, chunk, ...rest)) as typeof out;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (errors.push(chunk), true) : err.call(process.stderr, chunk, ...rest)) as typeof err;
  try { return { exitCode: await main(args), output: output.join(''), error: errors.join('') }; }
  finally {
    process.stdout.write = out; process.stderr.write = err;
    for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
}

test('deps argument failures use exit 2 when options precede the command', async () => {
  for (const args of [
    ['deps', '.', '--unknown-option'],
    ['--json', 'deps', '.', '--unknown-option'],
    ['--config', 'unused.json', '--json', 'deps', '.', '--unknown-option'],
    ['--config=unused.json', 'deps', '.', '--unknown-option'],
    ['--json', '--', 'deps', '.', 'extra'],
  ]) {
    const result = await invoke(args);
    assert.equal(result.exitCode, 2, args.join(' ')); assert.equal(result.output, '');
    assert.equal(JSON.parse(result.error).exitCode, 2, args.join(' '));
  }
});

test('deps in an option value or later positional does not change other commands failure exits', async () => {
  for (const args of [
    ['--json', 'scan', 'deps', '--unknown-option'],
    ['--config', 'deps', 'scan', '.', '--unknown-option'],
    ['--config=deps', 'scan', '.', '--unknown-option'],
    ['--json', 'import', 'deps', '--unknown-option'],
  ]) {
    const result = await invoke(args);
    assert.equal(result.exitCode, 4, args.join(' ')); assert.equal(result.output, '');
    assert.equal(JSON.parse(result.error).exitCode, 4, args.join(' '));
  }
});

test('deps --json on a base/head pair reports the diff, OSV-based upgrades, the closed schema and exit 0', { skip: realConfigSkip }, async () => {
  const beforeStatus = git(['status', '--porcelain']);
  const beforeMetadata = (await fs.readdir(path.join(repo, '.git'), { recursive: true })).sort();
  const result = await invoke(['deps', repo, '--config', configPath, '--base', base, '--head', head, '--json']);
  const report = JSON.parse(result.output);
  assert.equal(result.exitCode, 0, JSON.stringify(report.missing));
  assert.deepEqual(Object.keys(report), ['tool', 'schema', 'commits', 'planHash', 'inputs', 'osv', 'advisories', 'advisoryCounts', 'projects', 'upgrades', 'upgradeCounts', 'diff', 'diffCounts', 'missing', 'notes', 'exitCode']);
  assert.equal(report.schema, 'scanmux.dependencies/v2');
  assert.deepEqual(report.tool, { name: 'scanmux', version: JSON.parse(await fs.readFile('package.json', 'utf8')).version });
  assert.deepEqual(report.commits, { head, base });
  assert.ok(report.notes.includes('resolver_settings_outside_repository_not_read'));
  assert.equal(report.osv.state, 'completed');
  assert.deepEqual(report.osv.lockfiles, ['package-lock.json', 'py/uv.lock']);
  assert.deepEqual(report.inputs.head.map((item: { path: string }) => item.path), ['package-lock.json', 'package.json', 'py/pyproject.toml', 'py/uv.lock']);
  assert.deepEqual(report.projects.map((item: { lockfile: string; status: string }) => [item.lockfile, item.status]), [['package-lock.json', 'complete'], ['py/uv.lock', 'complete']]);
  assert.deepEqual(report.diffCounts, { versionChanged: 2, added: 1, removed: 0, relocated: 0, metadataOnly: 0, explained: 1, unexplained: 2, undeterminedExplanations: 0 });
  const lodash = report.upgrades.filter((item: { name: string }) => item.name === 'lodash');
  const requests = report.upgrades.filter((item: { name: string }) => item.name === 'requests');
  assert.ok(lodash.length > 0 && requests.length > 0, 'the offline OSV database matches both fixture advisories');
  for (const item of [...lodash, ...requests]) assert.ok(['allowed', 'undetermined'].includes(item.state), `${item.name} ${item.state} ${item.reason}`);
  assert.ok(lodash.some((item: { state: string; target: string }) => item.state === 'allowed' && item.target === '4.17.21'));
  assert.equal(JSON.stringify(report).includes('registry.npmjs.org'), false);
  assert.equal(report.osv.sides.base.state, 'completed');
  assert.equal(git(['status', '--porcelain']), beforeStatus);
  assert.deepEqual((await fs.readdir(path.join(repo, '.git'), { recursive: true })).sort(), beforeMetadata);
});

test('deps without a comparison assesses HEAD only, and the text output is a short table', { skip: realConfigSkip }, async () => {
  const json = JSON.parse((await invoke(['deps', repo, '--config', configPath, '--json'])).output);
  assert.equal(json.diff, null); assert.equal(json.diffCounts, null); assert.equal(json.inputs.base, null); assert.deepEqual(json.commits, { head, base: null });
  const text = await invoke(['deps', repo, '--config', configPath]);
  assert.equal(text.exitCode, 10);
  assert.match(text.output, /^ScanMux dependencies: analysis completed \(exit 10\); not a security PASS\./);
  assert.match(text.output, /package-lock\.json {2}lodash@4\.17\.20 {2}allowed {2}4\.17\.21/);
});

test('a missing OSV database is listed for both sides and exits 2 instead of reporting no findings', { skip: realConfigSkip }, async () => {
  const raw = JSON.parse(await fs.readFile(configPath, 'utf8'));
  const without = path.join(fixtureRoot, 'config-without-osv.json');
  await fs.writeFile(without, JSON.stringify({ ...raw, osvDatabase: null }));
  const result = await invoke(['deps', repo, '--config', without, '--base', base, '--head', head, '--json']);
  const report = JSON.parse(result.output);
  assert.equal(result.exitCode, 2);
  assert.equal(report.osv.state, 'failed');
  assert.deepEqual(report.missing, ['head', 'base'].map(side => ({ kind: 'osv', side, state: 'failed', reason: 'offline_database_not_configured' })));
  assert.deepEqual(report.upgrades, []);
  assert.equal(report.diffCounts.versionChanged, 2);
});

test('deps requires a config and rejects options of other commands', { skip: realConfigSkip }, async () => {
  for (const args of [['deps', repo], ['deps', repo, '--config', configPath, '--base', base], ['deps', repo, '--config', configPath, '--report-language', 'en']]) {
    const result = await invoke(args);
    assert.equal(result.exitCode, 2, args.join(' '));
    assert.equal(result.output, '');
  }
});
