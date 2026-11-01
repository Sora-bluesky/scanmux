import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { main } from '../src/cli.ts';
import { loadConfig } from '../src/config.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import { measureCommit, measureDirectory, openRepository, parseLog, releaseLogCheck, releaseRecord, releaseVerify } from '../src/release-transparency.ts';
import type { Config } from '../src/model.ts';
import { realConfigPath, realConfigSkip } from './real-config.ts';
import { contained } from './process-owner.ts';
import { prepareReleaseLogRepository } from '../scripts/ci-release-log.ts';

const configPath = realConfigPath ?? '';
let config!: Config, fixtureRoot!: string, repo!: string, hooks!: string;
const gitEnvironment = () => ({ SystemRoot: process.env.SystemRoot, HOME: fixtureRoot, USERPROFILE: fixtureRoot, GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: path.join(fixtureRoot, 'empty-gitconfig'), GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' });
function git(args: string[]): string {
  const result = spawnSync(config.tools.git!.path, ['-c', `core.hooksPath=${hooks}`, '-c', 'core.autocrlf=false', '-c', 'protocol.allow=never', '-C', repo, ...args], {
    encoding: 'utf8', windowsHide: true, env: gitEnvironment() });
  assert.equal(result.status, 0, 'trusted fixture Git command');
  return result.stdout.trim();
}
async function write(files: Record<string, string>) {
  for (const [name, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(repo, name)), { recursive: true });
    await fs.writeFile(path.join(repo, name), text);
  }
}
async function commit(files: Record<string, string>, message: string): Promise<string> {
  await write(files); git(['add', '-A']); git(['commit', '-q', '--allow-empty', '-m', message]);
  return git(['rev-parse', 'HEAD']);
}
const manifest = (version: string) => JSON.stringify({ name: 'demo', version, files: ['bin', 'src', 'README.md'] }, null, 2) + '\n';
let initial = '', c1 = '', c2 = '', c3 = '', l1 = '', pin1 = '';
if (realConfigPath) {
  config = await loadConfig(configPath);
  fixtureRoot = await privateWorkspace(process.cwd());
  test.after(() => removeTempDirStrict(fixtureRoot, { recursive: true, force: true }));
  repo = path.join(fixtureRoot, 'repository'); hooks = path.join(fixtureRoot, 'hooks');
  await fs.mkdir(repo); await fs.mkdir(hooks);
  git(['init', '-q', '--initial-branch=main', `--template=${hooks}`]);
  initial = await commit({ 'README.md': 'before transparency\n' }, 'initial');
  c1 = await commit({ 'package.json': manifest('1.0.0'), 'package-lock.json': '{"lockfileVersion":3}\n', 'README.md': 'demo\r\n', 'bin/demo.mjs': 'run();\n',
    'src/a.ts': 'export const a = 1;\r\n', 'src/deep/b.ts': 'export const b = 2;\n', 'test/a.test.ts': 'outside the package\n', 'transparency/releases.jsonl': '' }, 'release 1.0.0');
}

async function invoke(args: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (output.push(chunk), true) : out.call(process.stdout, chunk, ...rest)) as typeof out;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (errors.push(chunk), true) : err.call(process.stderr, chunk, ...rest)) as typeof err;
  try { return { exitCode: await main(args), output: output.join(''), error: errors.join('') }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
const json = async (args: string[]) => {
  const result = await invoke([...args, '--config', configPath, '--json']);
  return { exitCode: result.exitCode, value: result.output ? JSON.parse(result.output) : null, error: result.error ? JSON.parse(result.error) : null };
};
async function withRepository<T>(run: (repository: Awaited<ReturnType<typeof openRepository>>) => Promise<T>): Promise<T> {
  const workspace = await privateWorkspace(repo);
  test.after(() => removeTempDir(workspace));
  try { return await run(await openRepository(repo, config, workspace)); } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
}

test('one commit measured from Git blobs equals the same files measured from an installed directory, CRLF bytes included', { skip: realConfigSkip }, async () => contained(async () => {
  const fromGit = await withRepository(repository => measureCommit(repository, c1));
  const fromDirectory = await measureDirectory(repo, config);
  assert.deepEqual(fromDirectory, fromGit);
  assert.deepEqual(fromGit.files.map(file => file.path), ['README.md', 'bin/demo.mjs', 'package-lock.json', 'package.json', 'src/a.ts', 'src/deep/b.ts']);
  assert.equal(fromGit.files.find(file => file.path === 'src/a.ts')?.bytes, Buffer.byteLength('export const a = 1;\r\n'));
}));

test('the docs recipes reproduce the measurement and the log head with Git and Node only', { skip: realConfigSkip }, async () => contained(async () => {
  const blocks = [...(await fs.readFile('docs/transparency.md', 'utf8')).matchAll(/```js\n([\s\S]*?)```/g)].map(match => match[1]);
  assert.equal(blocks.length, 2, 'docs carry the measurement and head recipes');
  const env = { ...gitEnvironment(), PATH: path.dirname(config.tools.git!.path) };
  const attempt = async (script: string, args: string[]) => {
    const file = path.join(fixtureRoot, `recipe-${Math.random().toString(36).slice(2)}.mjs`);
    await fs.writeFile(file, script);
    return spawnSync(process.execPath, [file, ...args], { encoding: 'utf8', windowsHide: true, env, cwd: fixtureRoot });
  };
  const run = async (script: string, args: string[]) => {
    const result = await attempt(script, args);
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  try {
    const measured = await withRepository(repository => measureCommit(repository, c1));
    const { sha256, files, bytes } = measured.release.measurement;
    assert.deepEqual(JSON.parse(await run(blocks[0], [repo, c1])), { version: '1.0.0', sha256, files, bytes });
    const recorded = await json(['release-record', repo, '--commit', c1, '--expect-head', 'zero']);
    const logCommit = await commit({}, 'log 1.0.0');
    assert.equal(await run(blocks[1], [repo, logCommit]), recorded.value.pin);

    const bom = await commit({ 'package.json': '﻿' + manifest('1.0.1') }, 'manifest with a BOM');
    const bomMeasured = (await withRepository(repository => measureCommit(repository, bom))).release;
    assert.deepEqual(JSON.parse(await run(blocks[0], [repo, bom])), { version: '1.0.1', ...(({ schema, ...rest }) => rest)(bomMeasured.measurement) });

    const log = await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl'), 'utf8');
    const unterminated = await commit({ 'transparency/releases.jsonl': log.slice(0, -1) }, 'log without a final LF');
    const unterminatedRecipe = await attempt(blocks[1], [repo, unterminated]);
    assert.notEqual(unterminatedRecipe.status, 0, 'the head recipe refuses what the code refuses');
    const unterminatedVerify = await json(['release-verify', repo, '--log-commit', unterminated, '--commit', c1]);
    assert.deepEqual([unterminatedVerify.exitCode, unterminatedVerify.value.reason], [4, 'non_canonical']);
    const spaced = await commit({ 'transparency/releases.jsonl': log.replace('{"seq":1,', '{"seq": 1,') }, 'non-canonical log');
    assert.notEqual((await attempt(blocks[1], [repo, spaced])).status, 0, 'the head recipe checks the canonical encoding');

    const docs = await fs.readFile('docs/transparency.md', 'utf8');
    for (const refused of ['`"`', '`\\`', '`:`']) assert.ok(docs.includes(refused), `docs list the refused path character ${refused}`);
  } finally { git(['reset', '-q', '--hard', c1]); }
}));

test('record, verify and log-check follow the decision table on a real repository', { skip: realConfigSkip }, async () => contained(async () => {
  const empty = await json(['release-record', repo, '--commit', initial, '--expect-head', 'zero']);
  assert.equal(empty.exitCode, 4); assert.equal(empty.error.error, 'release_measurement_listed_path_missing');

  const first = await json(['release-record', repo, '--commit', c1, '--expect-head', 'zero']);
  assert.equal(first.exitCode, 0); assert.equal(first.value.state, 'appended'); assert.equal(first.value.entry.seq, 1);
  assert.deepEqual(first.value.scope, { measured: 'package_file_set', dependencies: 'lockfile_bound_not_measured', witness: 'none', authenticatedHistory: false });
  const bytes = await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl'));
  const again = await json(['release-record', repo, '--commit', c1, '--expect-head', 'zero']);
  assert.equal(again.value.state, 'existing'); assert.deepEqual(await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl')), bytes, 'idempotent');
  l1 = await commit({}, 'log 1.0.0'); pin1 = first.value.pin;

  const verifyCommit = (target: string, pin?: string, logCommit = l1) => json(['release-verify', repo, '--log-commit', logCommit, '--commit', target, ...(pin ? ['--pin', pin] : [])]);
  const logged = await verifyCommit(c1, pin1);
  assert.deepEqual([logged.exitCode, logged.value.verdict, logged.value.reason, logged.value.match, logged.value.independent], [0, 'logged', null, { seq: 1 }, true]);
  const installed = await json(['release-verify', repo, '--log-commit', l1, '--installed', repo, '--pin', pin1]);
  assert.deepEqual([installed.exitCode, installed.value.verdict, installed.value.target.kind, installed.value.independent], [0, 'logged', 'installed', true]);
  const unpinned = await verifyCommit(c1);
  assert.deepEqual([unpinned.exitCode, unpinned.value.verdict, unpinned.value.pin, unpinned.value.match], [3, 'logged_unpinned', 'none', { seq: 1 }]);

  c2 = await commit({ 'src/a.ts': 'export const a = 3;\n' }, 'same version, other bytes');
  const other = await verifyCommit(c2, pin1);
  assert.deepEqual([other.exitCode, other.value.verdict, other.value.reason], [4, 'not_logged', 'version_logged_with_other_measurement']);
  c3 = await commit({ 'package.json': manifest('1.1.0') }, 'release 1.1.0');
  const absent = await verifyCommit(c3, pin1);
  assert.deepEqual([absent.exitCode, absent.value.reason], [3, 'measurement_absent']);
  const stale = await json(['release-record', repo, '--commit', c3, '--expect-head', 'zero']);
  assert.deepEqual([stale.exitCode, stale.error.error], [4, 'release_log_head_mismatch']);
  const conflict = await json(['release-record', repo, '--commit', c2, '--expect-head', pin1.split(':')[1]]);
  assert.deepEqual([conflict.exitCode, conflict.error.error], [4, 'release_version_logged_with_other_measurement']);
  const second = await json(['release-record', repo, '--commit', c3, '--expect-head', pin1.split(':')[1]]);
  assert.equal(second.value.entry.seq, 2);
  const l2 = await commit({}, 'log 1.1.0'), pin2 = second.value.pin;
  const afterPin = await verifyCommit(c3, pin1, l2);
  assert.deepEqual([afterPin.exitCode, afterPin.value.reason], [3, 'after_pin']);
  assert.equal((await verifyCommit(c3, pin2, l2)).exitCode, 0);
  const mismatch = await verifyCommit(c3, `1:${'e'.repeat(64)}`, l2);
  assert.deepEqual([mismatch.exitCode, mismatch.value.verdict, mismatch.value.reason], [4, 'log_tampered', 'pin_mismatch']);
  const missing = await verifyCommit(c1, undefined, initial);
  assert.deepEqual([missing.exitCode, missing.value.verdict, missing.value.reason], [3, 'log_unreadable', 'log_missing']);

  const check = (base: string, headCommit: string) => json(['release-log-check', repo, '--base', base, '--head', headCommit]);
  const consistent = await check(l1, l2);
  assert.deepEqual([consistent.exitCode, consistent.value.verdict, consistent.value.reproduced, consistent.value.base.entries], [0, 'consistent', 2, 1]);
  assert.equal((await check('none', l2)).exitCode, 0);
  assert.deepEqual([(await check(initial, l2)).value.base.state, (await check(c1, l2)).value.base.state], ['absent', 'present']);
  const shrunk = await check(l2, l1);
  assert.deepEqual([shrunk.exitCode, shrunk.value.reason], [4, 'base_not_prefix']);
  const log = (await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl'), 'utf8')).replace(/"bytes":(\d+)}}\n$/, (_, n) => `"bytes":${Number(n) + 1}}}\n`);
  const forged = await commit({ 'transparency/releases.jsonl': log }, 'forged last entry');
  const unreproducible = await check(l1, forged);
  assert.deepEqual([unreproducible.exitCode, unreproducible.value.reason], [4, 'not_reproducible']);

  git(['reset', '-q', '--hard', l2]);
  const lines = (await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl'), 'utf8')).split('\n');
  const appended = JSON.stringify({ ...JSON.parse(lines[1]), seq: 3, prev: createHash('sha256').update(lines[1]).digest('hex'), version: '1.0.0', sourceCommit: c2 });
  const conflicting = await commit({ 'transparency/releases.jsonl': lines.slice(0, 2).join('\n') + '\n' + appended + '\n' }, 'hand-appended version conflict');
  const conflictCheck = await check(l2, conflicting), conflictVerify = await verifyCommit(c1, pin2, conflicting);
  assert.deepEqual([conflictCheck.exitCode, conflictCheck.value.verdict, conflictCheck.value.reason], [4, 'log_tampered', 'version_conflict']);
  assert.deepEqual([conflictVerify.exitCode, conflictVerify.value.verdict, conflictVerify.value.reason], [4, 'log_tampered', 'version_conflict']);

  const text = await invoke(['release-verify', repo, '--log-commit', l2, '--commit', c3, '--config', configPath]);
  assert.equal(text.exitCode, 3);
  assert.match(text.output, /^ScanMux release verify: logged_unpinned \(exit 3\); .*pin=none \(not owner-approved\)\.\n/);
  assert.match(text.output, /not a security PASS/);
  const self = await json(['release-verify', repo, '--log-commit', l2, '--installed', process.cwd()]);
  assert.deepEqual([self.value.independent, self.value.target.kind, self.value.verdict], [false, 'installed', 'not_logged']);
}));

function checkout(commit: string, autocrlf: boolean): string {
  const destination = path.join(fixtureRoot, `checkout-${Math.random().toString(36).slice(2)}`);
  for (const args of [['clone', '-q', '--no-checkout', '-c', `core.autocrlf=${autocrlf}`, repo, destination], ['-C', destination, 'checkout', '-q', commit]]) {
    const result = spawnSync(config.tools.git!.path, ['-c', `core.hooksPath=${hooks}`, '-c', `core.autocrlf=${autocrlf}`, ...args], { encoding: 'utf8', windowsHide: true, env: gitEnvironment() });
    assert.equal(result.status, 0, 'trusted fixture Git checkout');
  }
  return destination;
}

test('a CRLF-converted checkout is never logged, and the repository attributes keep checkouts byte-identical', { skip: realConfigSkip }, async () => contained(async () => {
  git(['reset', '-q', '--hard', c1]);
  const verifyInstalled = (directory: string) => json(['release-verify', repo, '--log-commit', l1, '--installed', directory, '--pin', pin1]);
  const converted = await verifyInstalled(checkout(c1, true));
  assert.deepEqual([converted.exitCode, converted.value.verdict, converted.value.reason], [4, 'not_logged', 'version_logged_with_other_measurement']);
  assert.equal((await verifyInstalled(checkout(c1, false))).value.verdict, 'logged');
  const attributed = await commit({ '.gitattributes': await fs.readFile('.gitattributes', 'utf8') }, 'repository attributes');
  const kept = await verifyInstalled(checkout(attributed, true));
  assert.deepEqual([kept.exitCode, kept.value.verdict, kept.value.match], [0, 'logged', { seq: 1 }]);
}));

test('a commit that measures the same as the running ScanMux is not an independent check', { skip: realConfigSkip }, async () => contained(async () => {
  const own = await measureDirectory(process.cwd(), config);
  git(['reset', '-q', '--hard', c1]); git(['rm', '-r', '-q', '--', '.']);
  for (const file of own.files) {
    const destination = path.join(repo, ...file.path.split('/'));
    await fs.mkdir(path.dirname(destination), { recursive: true }); await fs.copyFile(path.join(process.cwd(), ...file.path.split('/')), destination);
  }
  git(['add', '-A']); git(['commit', '-q', '-m', 'same package as the running ScanMux']);
  const same = await json(['release-verify', repo, '--log-commit', l1, '--commit', git(['rev-parse', 'HEAD']), '--pin', pin1]);
  assert.deepEqual([same.value.independent, same.value.target.measurement], [false, own.release.measurement]);
  const other = await json(['release-verify', repo, '--log-commit', l1, '--commit', c1, '--pin', pin1]);
  assert.deepEqual([other.value.verdict, other.value.independent], ['logged', true]);
  git(['reset', '-q', '--hard', c1]);
}));

test('Git config that reads other files, and a linked objects directory, are refused before Git reads the repository', { skip: realConfigSkip }, async () => contained(async () => {
  const outside = path.join(fixtureRoot, 'outside-gitconfig');
  await fs.writeFile(outside, '[broken\n');
  const cases: [string, string][] = [
    [`[include]\n\tpath = ${outside.replaceAll('\\', '/')}\n`, 'include'],
    [`[includeIf "gitdir:${fixtureRoot.replaceAll('\\', '/')}/"]\n\tpath = ${outside.replaceAll('\\', '/')}\n`, 'includeIf'],
    ['[core]\n\thooksPath = elsewhere\n', 'core.hooksPath'],
    ['[core]\n\tfsmonitor = true\n', 'core.fsmonitor'],
    ['[core]\n\tsshCommand = ssh\n', 'core.sshCommand'],
    ['[extensions]\n\tworktreeConfig = true\n', 'extensions.worktreeConfig'],
    ['[include] path = x\n', 'a setting on the section line'],
    ['[core]\n\tbare = false \\\n', 'a continued line'],
  ];
  for (const [text, name] of cases) {
    const copy = path.join(fixtureRoot, `config-${Math.random().toString(36).slice(2)}`);
    await fs.cp(repo, copy, { recursive: true });
    await fs.appendFile(path.join(copy, '.git', 'config'), text);
    const result = await json(['release-verify', copy, '--log-commit', l1, '--commit', c1, '--pin', pin1]);
    assert.deepEqual([result.exitCode, result.error?.error], [4, 'unsupported_git_config'], name);
  }
  const linked = path.join(fixtureRoot, `linked-${Math.random().toString(36).slice(2)}`), moved = path.join(fixtureRoot, `objects-${Math.random().toString(36).slice(2)}`);
  await fs.cp(repo, linked, { recursive: true });
  await fs.rename(path.join(linked, '.git', 'objects'), moved);
  await fs.symlink(moved, path.join(linked, '.git', 'objects'), 'junction');
  const junction = await json(['release-verify', linked, '--log-commit', l1, '--commit', c1, '--pin', pin1]);
  assert.deepEqual([junction.exitCode, junction.error?.error], [4, 'linked_git_metadata']);
  const plain = await json(['release-verify', repo, '--log-commit', l1, '--commit', c1, '--pin', pin1]);
  assert.equal(plain.value.verdict, 'logged', 'the fixture config itself is accepted');
}));

test('CI checks the release log in a fresh repository, because the actions/checkout layout is refused', { skip: realConfigSkip }, async () => contained(async () => {
  const workspace = path.join(fixtureRoot, `workspace-${Math.random().toString(36).slice(2)}`);
  const inWorkspace = (args: string[]) => {
    const result = spawnSync(config.tools.git!.path, ['-c', `core.hooksPath=${hooks}`, '-c', 'core.autocrlf=false', ...args], { encoding: 'utf8', windowsHide: true, env: gitEnvironment() });
    assert.equal(result.status, 0, `checkout replay: git ${args[2] ?? args[0]}`);
  };
  for (const args of [['init', '-q', workspace], ['-C', workspace, 'remote', 'add', 'origin', repo], ['-C', workspace, 'config', '--local', 'gc.auto', '0'],
    ['-C', workspace, 'fetch', '-q', '--no-tags', '--prune', '--no-recurse-submodules', 'origin', '+refs/heads/*:refs/remotes/origin/*', `+${l1}:refs/remotes/pull/1/merge`],
    ['-C', workspace, 'sparse-checkout', 'disable'], ['-C', workspace, 'config', '--local', '--unset-all', 'extensions.worktreeConfig'],
    ['-C', workspace, 'checkout', '-q', '--force', 'refs/remotes/pull/1/merge']]) inWorkspace(args);
  assert.ok(await fs.lstat(path.join(workspace, '.git', 'config.worktree')), 'sparse-checkout disable leaves config.worktree behind');
  const refused = await json(['release-log-check', workspace, '--base', c1, '--head', l1]);
  assert.deepEqual([refused.exitCode, refused.error?.error], [4, 'unsupported_git_layout']);

  const fresh = path.join(fixtureRoot, `release-log-${Math.random().toString(36).slice(2)}`);
  await prepareReleaseLogRepository({ git: config.tools.git!.path, source: workspace, destination: fresh, base: c1, head: l1 });
  const checked = await json(['release-log-check', fresh, '--base', c1, '--head', l1]);
  assert.deepEqual([checked.exitCode, checked.value.verdict, checked.value.reproduced], [0, 'consistent', 1]);
  await assert.rejects(prepareReleaseLogRepository({ git: config.tools.git!.path, source: workspace, destination: fresh, base: c1, head: l1 }), { code: 'release_log_repository_exists' });

  const dispatch = path.join(fixtureRoot, `release-log-${Math.random().toString(36).slice(2)}`);
  await prepareReleaseLogRepository({ git: config.tools.git!.path, source: workspace, destination: dispatch, base: null, head: l1 });
  assert.equal((await json(['release-log-check', dispatch, '--base', 'none', '--head', l1])).exitCode, 0);
  const absent = path.join(fixtureRoot, `release-log-${Math.random().toString(36).slice(2)}`);
  await assert.rejects(prepareReleaseLogRepository({ git: config.tools.git!.path, source: workspace, destination: absent, base: 'f'.repeat(40), head: l1 }),
    { code: 'release_log_repository_failed' });
}));

test('a log over the Git output limit is unreadable, and an over-limit reproduction is not reproducible', { skip: realConfigSkip }, async () => contained(async () => {
  const workspace = await privateWorkspace(repo);
  test.after(() => removeTempDir(workspace));
  try {
    const small = await openRepository(repo, { ...config, maxOutputBytes: 200, maxFileBytes: 200 }, workspace);
    const verified = await releaseVerify(small, { logCommit: l1, commit: c1, pin: pin1 });
    assert.deepEqual([verified.exitCode, verified.payload.verdict, verified.payload.reason], [3, 'log_unreadable', 'over_limit']);
    const checked = await releaseLogCheck(small, { base: 'none', head: l1 });
    assert.deepEqual([checked.exitCode, checked.payload.reason], [3, 'over_limit']);
    const few = await openRepository(repo, { ...config, maxFiles: 2 }, workspace);
    const reproduced = await releaseLogCheck(few, { base: 'none', head: l1 });
    assert.deepEqual([reproduced.exitCode, reproduced.payload.verdict, reproduced.payload.reason], [4, 'log_tampered', 'not_reproducible']);
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); }
}));

test('two interleaved records never lose an appended line: the second writer gets a head mismatch', { skip: realConfigSkip }, async () => contained(async () => {
  git(['reset', '-q', '--hard', c1]);
  const next = await commit({ 'package.json': manifest('2.0.0') }, 'release 2.0.0');
  git(['reset', '-q', '--hard', c1]);
  const results = await Promise.allSettled([c1, next].map(target => withRepository(repository => releaseRecord(repository, { commit: target, expectHead: 'zero' }))));
  const appended = results.filter(result => result.status === 'fulfilled'), refused = results.filter(result => result.status === 'rejected');
  assert.deepEqual([appended.length, refused.length], [1, 1]);
  assert.equal((refused[0] as PromiseRejectedResult).reason.code, 'release_log_head_mismatch');
  const parsed = parseLog(await fs.readFile(path.join(repo, 'transparency', 'releases.jsonl')));
  assert.ok(parsed.ok);
  assert.deepEqual(parsed.log.entries, [(appended[0] as PromiseFulfilledResult<Awaited<ReturnType<typeof releaseRecord>>>).value.payload.entry]);
  assert.deepEqual((await fs.readdir(path.join(repo, 'transparency'))).sort(), ['releases.jsonl'], 'the lock and temporary files are gone');
  const lock = path.join(repo, 'transparency', '.releases.lock');
  await fs.writeFile(lock, 'left by a crashed writer');
  const workspace = await privateWorkspace(repo);
  test.after(() => removeTempDir(workspace));
  try {
    const waiting = await openRepository(repo, { ...config, timeoutMs: 200 }, workspace);
    await assert.rejects(releaseRecord(waiting, { commit: next, expectHead: parsed.log.head }), { code: 'release_log_locked' });
    assert.equal(await fs.readFile(lock, 'utf8'), 'left by a crashed writer', 'a stale lock is refused, never removed');
  } finally { await removeTempDirStrict(workspace, { recursive: true, force: true }); await fs.rm(lock, { force: true }); }
  git(['reset', '-q', '--hard', c1]);
}));

test('release commands reject options that belong to other commands', { skip: realConfigSkip }, async () => contained(async () => {
  for (const args of [
    ['release-record', repo, '--commit', c1],
    ['release-verify', repo, '--log-commit', c1],
    ['release-verify', repo, '--log-commit', c1, '--commit', c1, '--installed', repo],
    ['release-log-check', repo, '--base', 'none'],
    ['release-log-check', repo, '--base', 'none', '--head', c1, '--pin', `0:${'0'.repeat(64)}`],
    ['scan', repo, '--log-commit', c1],
  ]) {
    const result = await invoke([...args, '--config', configPath]);
    assert.equal(result.exitCode, 4, args.join(' ')); assert.equal(JSON.parse(result.error).error, 'invalid_command');
  }
  const unconfigured = await invoke(['release-verify', repo, '--log-commit', c1, '--commit', c1]);
  assert.equal(JSON.parse(unconfigured.error).error, 'release_config_required');
}));

test('help lists the release commands', async () => {
  const result = await invoke(['--help']);
  for (const command of ['release-record', 'release-verify', 'release-log-check']) assert.match(result.output, new RegExp(`scanmux ${command} <local-git-root>`));
  assert.match(result.output, /never a security PASS/);
});
