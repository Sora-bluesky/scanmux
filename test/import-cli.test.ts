import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { main } from '../src/cli.ts';
import { loadConfig } from '../src/config.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import { commitFacts } from '../src/repository.ts';
import { hash } from '../src/safety.ts';
import type { Config } from '../src/model.ts';
import { realConfigPath, realConfigSkip } from './real-config.ts';
import { contained, withTestProcessOwner } from './process-owner.ts';

const launches: string[] = [];
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) { launches.push(name); return Reflect.apply(original, this, args); };
}
syncBuiltinESMExports();

const configPath = realConfigPath ?? '';
let config!: Config, fixtureRoot!: string, repo!: string, hooks!: string;
function git(args: string[]): string {
  const result = childProcess.spawnSync(config.tools.git!.path, ['-c', `core.hooksPath=${hooks}`, '-c', 'core.autocrlf=false', '-c', 'protocol.allow=never', '-C', repo, ...args], {
    encoding: 'utf8', windowsHide: true, env: { SystemRoot: process.env.SystemRoot, HOME: fixtureRoot, USERPROFILE: fixtureRoot, GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_GLOBAL: path.join(fixtureRoot, 'empty-gitconfig'), GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  });
  assert.equal(result.status, 0, 'trusted fixture Git command');
  return result.stdout.trim();
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
  base = await commit({ 'README.md': 'fixture\n' }, 'base');
  head = await commit({ 'config/settings.env': 'NAME=value\n' }, 'head');
}

let written = 0;
async function input(value: unknown): Promise<string> {
  const file = path.join(fixtureRoot, `input-${written++}.json`);
  await fs.writeFile(file, typeof value === 'string' ? value : JSON.stringify(value));
  return file;
}
const leak = (revisions: string[] = [head]) => ({
  version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'gitleaks', semanticVersion: 'v8.0.0' } },
    ...(revisions.length ? { versionControlProvenance: revisions.map(revisionId => ({ revisionId, repositoryUri: 'https://example.invalid/private.git' })) } : {}),
    invocations: [{ executionSuccessful: true }],
    results: [{
      ruleId: 'generic-api-key', level: 'error', message: { text: 'found in C:/Users/someone/project by person.name@example.invalid' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'config/settings.env' }, region: { startLine: 1, snippet: { text: 'NAME=value' } } } }],
      partialFingerprints: { commitSha: base, email: 'person.name@example.invalid', author: 'Taro Example', commitMessage: 'rotate the key' },
    }],
  }],
});
async function invoke(args: string[]) {
  const temporary = await fs.mkdtemp(path.join(tmpdir(), 'scanmux-import-cli-'));
  test.after(async () => {
    for (const name of await fs.readdir(temporary).catch(() => [])) if (name.startsWith('scanmux-')) await removeTempDir(path.join(temporary, name));
    await removeTempDir(temporary);
  });
  const saved = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  Object.assign(process.env, { TEMP: temporary, TMP: temporary, TMPDIR: temporary });
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  launches.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (output.push(chunk), true) : out.call(process.stdout, chunk, ...rest)) as typeof out;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (errors.push(chunk), true) : err.call(process.stderr, chunk, ...rest)) as typeof err;
  try { return { exitCode: await main(args), output: output.join(''), error: errors.join(''), launches: [...launches] }; }
  finally {
    process.stdout.write = out; process.stderr.write = err;
    for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
}
const forbidden = ['person.name@example.invalid', 'Taro Example', 'rotate the key', 'C:/Users/someone', 'file:///', 'NAME=value', 'example.invalid'];
test('import --json of a recorded HEAD SARIF exits 0, writes the checked record and leaks no personal or path values', { skip: realConfigSkip }, async () => contained(async () => {
  const result = await invoke(['import', repo, await input(leak()), '--config', configPath, '--json']);
  assert.equal(result.exitCode, 0, result.output + result.error);
  const record = JSON.parse(result.output);
  assert.equal(record.schema, 'scanmux.import/v2');
  assert.deepEqual(record.view.observations.map((item: { relation: string }) => item.relation), ['head']);
  assert.equal(record.view.head, head);
  assert.equal(record.facts.repoId, hash(await fs.realpath(repo)));
  for (const value of [...forbidden, JSON.stringify(repo).slice(1, -1), JSON.stringify(fixtureRoot).slice(1, -1)]) assert.equal(result.output.includes(value), false, value);
  const text = await invoke(['import', repo, await input(leak()), '--config', configPath]);
  assert.equal(text.exitCode, 0);
  assert.match(text.output, /^ScanMux import: read and recorded, not a security decision; gate unchanged \(exit 0\)\./);
  const destination = /^JSON: (.+)$/m.exec(text.output)![1];
  assert.equal(path.basename(destination), 'import.json');
  assert.equal(JSON.parse(await fs.readFile(destination, 'utf8')).schema, 'scanmux.import/v2');
  assert.deepEqual((await fs.readdir(path.dirname(destination))).filter(name => name.startsWith('import')), ['import.json'], 'no temporary file is left');
}));

test('import binds a declared commit against the real repository: stale, unavailable and missing', { skip: realConfigSkip }, async () => contained(async () => {
  const unrecorded = await input(leak([]));
  const cases: [string[], string | null, string][] = [
    [[], null, 'sha_missing'], [['--scanned-commit', base], 'stale_commit', 'stale_commit'], [['--scanned-commit', '0'.repeat(40)], 'commit_unavailable', 'commit_unavailable'],
  ];
  for (const [extra, relation, reason] of cases) {
    const result = await invoke(['import', repo, unrecorded, '--config', configPath, '--json', ...extra]);
    assert.equal(result.exitCode, 3, reason);
    const record = JSON.parse(result.output);
    assert.equal(record.view.observations[0].relation, relation, reason);
    assert.ok(record.view.observations[0].reasons.includes(reason), reason);
  }
  const stale = JSON.parse((await invoke(['import', repo, unrecorded, '--config', configPath, '--json', '--scanned-commit', base])).output);
  assert.ok(stale.view.observations[0].reasons.includes('referenced_paths_absent'), 'config/settings.env did not exist at the base commit');
}));

test('a saved record re-imported with its SARIF adds nothing; a truncated SARIF is a rejected row, not an error', { skip: realConfigSkip }, async () => contained(async () => {
  const sarif = await input(leak());
  const first = JSON.parse((await invoke(['import', repo, sarif, '--config', configPath, '--json'])).output);
  const again = await invoke(['import', repo, await input(first), sarif, (await input(JSON.stringify(leak()).slice(0, 50))), '--config', configPath, '--json']);
  assert.equal(again.exitCode, 3);
  const record = JSON.parse(again.output);
  assert.deepEqual(record.view.inputs.map((row: { state: string; reasons: string[] }) => [row.state, row.reasons]),
    [['accepted', []], ['duplicate', ['duplicate_input']], ['rejected', ['invalid_json']]]);
  assert.deepEqual(record.facts.findings, first.facts.findings);
}));

test('one advisory in two packages and two pathless secrets of one rule stay four findings through import and re-import', { skip: realConfigSkip }, async () => contained(async () => {
  const lockfile = pathToFileURL(path.join(repo, 'package-lock.json')).href;
  const vulnerable = (pkg: string) => ({ ruleId: 'GHSA-aaaa-bbbb-cccc', message: { text: `Package '${pkg}' is vulnerable to 'GHSA-aaaa-bbbb-cccc' (also known as 'CVE-2020-11111').` },
    locations: [{ physicalLocation: { artifactLocation: { uri: lockfile } } }] });
  const osv = { version: '2.1.0', runs: [{ tool: { driver: { name: 'osv-scanner', version: '2.7.0' } }, results: [vulnerable('lodash@4.17.20'), vulnerable('minimist@1.2.5')] }] };
  const secrets = { ...leak(), runs: [{ ...leak().runs[0], results: ['first NAME=value', 'second NAME=value'].map(text => ({ ruleId: 'generic-api-key', message: { text } })) }] };
  const inputs = [await input(osv), await input(secrets)];
  const first = await invoke(['import', repo, ...inputs, '--config', configPath, '--json', '--scanned-commit', head]);
  const record = JSON.parse(first.output);
  assert.equal(record.facts.findings.length, 4, first.error);
  assert.deepEqual(record.facts.findings.flatMap((item: { package: { name: string } | null }) => item.package ? [item.package.name] : []).sort(), ['lodash', 'minimist']);
  for (const value of [...forbidden, 'CVE-2020-11111', JSON.stringify(repo).slice(1, -1)]) assert.equal(first.output.includes(value), false, value);
  const again = JSON.parse((await invoke(['import', repo, await input(record), ...inputs, '--config', configPath, '--json', '--scanned-commit', head])).output);
  assert.deepEqual(again.view.inputs.map((row: { state: string }) => row.state), ['accepted', 'duplicate', 'duplicate']);
  assert.deepEqual(again.facts.findings, record.facts.findings);
}));

test('operator errors exit 4 with no output', { skip: realConfigSkip }, async () => contained(async () => {
  const sarif = await input(leak());
  const inside = path.join(repo, 'result.sarif');
  await fs.writeFile(inside, JSON.stringify(leak()));
  const cases: [string[], string][] = [
    [['import', repo, sarif], 'import_config_required'],
    [['import', repo, '--config', configPath], 'invalid_command'],
    [['import', repo, inside, '--config', configPath], 'import_input_inside_target'],
    [['import', repo, 'relative.sarif', '--config', configPath], 'import_input_not_absolute'],
    [['import', repo, sarif, '--config', configPath, '--scanned-commit', head.toUpperCase()], 'invalid_scanned_commit'],
    [['import', repo, sarif, '--config', configPath, '--base', base, '--head', head], 'invalid_command'],
    [['deps', repo, '--config', configPath, '--scanned-commit', head], 'invalid_command'],
  ];
  for (const [args, code] of cases) {
    const result = await invoke(args);
    assert.equal(result.exitCode, 4, args.join(' '));
    assert.equal(result.output, '', args.join(' '));
    assert.equal(JSON.parse(result.error).error, code, args.join(' '));
  }
  await fs.rm(inside);
}));

test('runtime admission refuses import before the first process; an osv deny is outside its closure', { skip: realConfigSkip }, async () => contained(async () => {
  const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
  const tools = { git: node, gitleaks: { ...node, version: '8.30.1' }, osv: node };
  const policy = (state: 'active' | 'stopped', deny: unknown[]) => ({ schema: 'scanmux.runtime-policy/v1', id: '6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b', revision: 3, state, deny });
  const sarif = await input(leak());
  const cases: [ReturnType<typeof policy>, string | null][] = [
    [policy('stopped', []), 'runtime_policy_stopped'],
    [policy('active', [{ kind: 'component', component: 'gitleaks' }]), 'runtime_policy_denied_gitleaks_component'],
    [policy('active', [{ kind: 'digest', component: 'git', sha256: node.sha256 }]), 'runtime_policy_denied_git_digest'],
    [policy('active', [{ kind: 'component', component: 'osv' }]), null],
  ];
  for (const [runtimePolicy, code] of cases) {
    const file = await input(withTestProcessOwner({ schema: 2, runtimePolicy, tools }));
    const result = await invoke(['import', repo, sarif, '--config', file, '--json']);
    assert.equal(result.exitCode, 4);
    if (code) {
      assert.equal(JSON.parse(result.error).error, code);
      assert.deepEqual(result.launches, [], code);
      assert.equal(result.output, '');
    } else {
      assert.doesNotMatch(result.error, /runtime_policy/);
      assert.ok(result.launches.length > 0, 'the admitted closure continued to its first process');
    }
  }
}));

test('help states that the record digest detects corruption only and is not an authentication', async () => {
  const result = await invoke(['--help']);
  assert.match(result.output, /factsDigest detects corruption only; it is not an authentication/);
  assert.match(result.output, /earlier scanmux\.import\/v1 record is refused as unsupported_schema, so import its original SARIF again/);
});

test('commitFacts checks only the wanted paths, so a tree larger than the output limit still binds', { skip: realConfigSkip }, async () => contained(async () => {
  const files = Object.fromEntries(Array.from({ length: 120 }, (_, index) => [`bulk/file-with-a-long-name-${String(index).padStart(4, '0')}.txt`, 'x'+String.fromCharCode(10)]));
  const bulk = await commit(files, 'bulk');
  const small = { ...config, maxOutputBytes: 2048, maxFileBytes: 2048 };
  const asked = ['config/settings.env', 'bulk/file-with-a-long-name-0001.txt', 'bulk', 'missing.txt'];
  const facts = await commitFacts(repo, small, hooks, new Map([[bulk, asked], [base, asked]]));
  assert.deepEqual([...facts.commits.get(bulk)!.paths].sort(), ['bulk/file-with-a-long-name-0001.txt', 'config/settings.env']);
  assert.deepEqual(facts.commits.get(base)!.paths, []);
  assert.equal(facts.commits.get(base)!.ancestor, true);
  const none = await commitFacts(repo, small, hooks, new Map([[bulk, []]]));
  assert.deepEqual(none.commits.get(bulk), { exists: true, ancestor: false, paths: [] });
}));

test('recheck 7: each commit is asked only for its own paths, so many commits with one path each stay under the output limit', { skip: realConfigSkip }, async () => contained(async () => {
  const limit = 65536, limited = await input({ ...JSON.parse(await fs.readFile(configPath, 'utf8')), maxOutputBytes: limit });
  const far = (index: number) => `absent/${'p'.repeat(900)}-${String(index).padStart(2, '0')}.txt`;
  const commits: string[] = [];
  for (let index = 0; index < 12; index++) commits.push(await commit({ [`many/${index}.txt`]: `${index}\n` }, `many ${index}`));
  assert.ok(commits.length ** 2 * (41 + far(0).length + ' missing\n'.length) > limit, 'asking every commit for every path would pass the limit');
  const sarifs: string[] = [];
  for (const [index, revisionId] of commits.entries()) {
    sarifs.push(await input({ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks', semanticVersion: 'v8.0.0' } }, versionControlProvenance: [{ revisionId }],
      invocations: [{ executionSuccessful: true }], results: [{ ruleId: 'generic-api-key', level: 'error', locations: [{ physicalLocation: { artifactLocation: { uri: far(index) }, region: { startLine: 1 } } }] }] }] }));
  }
  const result = await invoke(['import', repo, ...sarifs, '--config', limited, '--json']);
  assert.equal(result.exitCode, 3, result.error);
  const record = JSON.parse(result.output);
  assert.equal(record.view.observations.length, 12);
  for (const item of record.view.observations) assert.ok(item.absentPaths === 1 && item.reasons.includes('referenced_paths_absent'), JSON.stringify(item));
}));

test('recheck 7: commitFacts splits the path queries into batches whose answers stay under the output limit', { skip: realConfigSkip }, async () => contained(async () => {
  const current = git(['rev-parse', 'HEAD']);
  const small = { ...config, maxOutputBytes: 2048, maxFileBytes: 2048 };
  const names = Array.from({ length: 40 }, (_, index) => `absent/${'q'.repeat(60)}-${index}.txt`);
  assert.ok(names.reduce((total, name) => total + 41 + name.length + ' missing\n'.length, 0) > small.maxOutputBytes, 'one batch would pass the limit');
  const facts = await commitFacts(repo, small, hooks, new Map([[current, [...names, 'config/settings.env']]]));
  assert.deepEqual(facts.commits.get(current)!.paths, ['config/settings.env']);
}));
