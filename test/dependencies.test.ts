import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import { defaults } from '../src/config.ts';
import * as safety from '../src/safety.ts';
import * as repository from '../src/repository.ts';
import * as graph from '../src/dependency-graph.ts';
import * as databases from '../src/osv-database.ts';
import * as cleanup from '../src/source-cleanup.ts';
import * as npm from '../src/npm-lockfile.ts';
import { packageVersion } from '../src/package-version.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { legacyEngines } from '../src/engine-catalog.ts';
import { observeConfiguration, summarizeConfiguration } from '../src/configuration.ts';
import { changedEntries, commitPair, treeEntries } from '../src/comparison.ts';
import { readGitBlobs } from '../src/git-blobs.ts';
import { emptyRun } from '../src/engine-run.ts';
import { JobDiskCopyLimitError } from '../src/copy-budget.ts';
import { main } from '../src/cli.ts';
import type { CommitPair, Config, Plan } from '../src/model.ts';
import type { OsvRun } from '../src/adapters.ts';
import type { DependencyReport } from '../src/dependencies.ts';

async function loaded(file: string, imports: Record<string, unknown>, names: string[]) {
  const source = stripTypeScriptTypes(await fs.readFile(file, 'utf8'))
    .replace(/^import [\s\S]*?;\r?\n/gm, '').replace(/^export \{[^\n]*\n/gm, '').replace(/^export /gm, '');
  return Function(...Object.keys(imports), source + `\nreturn {${names.join(',')}};`)(...Object.values(imports));
}

const lock = (version: string, packages: Record<string, unknown> = {}, root: Record<string, unknown> = {}) => JSON.stringify({
  name: 'app', lockfileVersion: 3, packages: { '': { name: 'app', dependencies: { example: '^1.0.0' }, ...root },
    'node_modules/example': { version, dev: true }, ...packages },
});
const files = (version: string) => ({ 'README.md': 'fixture\n', 'package.json': '{"name":"app","dependencies":{"example":"^1.0.0"}}', 'package-lock.json': lock(version) });
function advisory(id: string, severity: string | null = 'MODERATE', fixed: string[] = ['1.2.0']) {
  return { id, aliases: ['CVE-2026-12345'], database_specific: severity === null ? {} : { severity },
    affected: [{ package: { name: 'example', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, ...fixed.map(version => ({ fixed: version }))] }] }],
    severity: [{ type: 'CVSS_V3', score: '9.8' }], summary: 'scanner prose must not be retained' };
}
interface Options {
  baseFiles?: Record<string, string | Buffer>; headFiles?: Record<string, string | Buffer>;
  advisories?: (version: string) => unknown[];
  extraPackages?: Record<string, unknown>[];
  failureSide?: 'base' | 'head'; failureReason?: string;
  worktreeConfig?: string; mainConfig?: string;
}
async function fixture(options: Options = {}) {
  const home = await fs.mkdtemp(path.resolve('test/deps-fixture-'));
  test.after(() => fs.rm(home, { recursive: true, force: true }));
  const root = path.join(home, 'repository'), workspace = path.join(home, 'run'), db = path.join(home, 'database');
  await fs.mkdir(path.join(root, '.git', 'objects'), { recursive: true });
  await fs.mkdir(path.join(root, '.git', 'refs')); await fs.mkdir(workspace);
  await fs.writeFile(path.join(root, '.git', 'config'), options.mainConfig ?? '[core]\nrepositoryformatversion = 0\nbare = false\n');
  if (options.worktreeConfig !== undefined) await fs.writeFile(path.join(root, '.git', 'config.worktree'), options.worktreeConfig);
  // Write synthetic loose objects directly; fixture setup uses no commit or branch commands.
  const object = async (kind: string, bytes: Buffer) => {
    const content = Buffer.concat([Buffer.from(`${kind} ${bytes.length}\0`), bytes]);
    const oid = createHash('sha1').update(content).digest('hex'), directory = path.join(root, '.git', 'objects', oid.slice(0, 2));
    await fs.mkdir(directory, { recursive: true }); await fs.writeFile(path.join(directory, oid.slice(2)), deflateSync(content)); return oid;
  };
  const tree = async (entries: Record<string, string | Buffer>): Promise<string> => {
    const groups = new Map<string, Record<string, string | Buffer>>(), result: Buffer[] = [];
    for (const name of Object.keys(entries).sort()) {
      const slash = name.indexOf('/');
      if (slash >= 0) {
        const directory = name.slice(0, slash), group = groups.get(directory) ?? {};
        group[name.slice(slash + 1)] = entries[name]!; groups.set(directory, group);
      } else result.push(Buffer.concat([Buffer.from(`100644 ${name}\0`), Buffer.from(await object('blob', Buffer.from(entries[name]!)), 'hex')]));
    }
    for (const [name, children] of groups) result.push(Buffer.concat([Buffer.from(`40000 ${name}\0`), Buffer.from(await tree(children), 'hex')]));
    return object('tree', Buffer.concat(result));
  };
  const revision = async (entries: Record<string, string | Buffer>, parent?: string) => object('commit', Buffer.from(
    `tree ${await tree(entries)}\n${parent ? `parent ${parent}\n` : ''}author Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\nfixture\n`));
  const baseFiles = options.baseFiles ?? files('1.0.0'), headFiles = options.headFiles ?? files('1.1.0');
  const base = await revision(baseFiles), head = await revision(headFiles, base);
  await fs.writeFile(path.join(root, '.git', 'HEAD'), head + '\n');
  for (const [name, content] of Object.entries(headFiles)) { await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true }); await fs.writeFile(path.join(root, name), content); }
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, HOME: home, USERPROFILE: home, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(home, 'empty-config') };
  const gitResult = (args: string[], input?: string) => spawnSync('git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${workspace}`, '-C', root, ...args], { env, input, windowsHide: true });
  const git = (args: string[], input?: string) => {
    const result = gitResult(args, input);
    assert.equal(result.status, 0, result.stderr?.toString()); return result.stdout;
  };
  git(['read-tree', head]);
  await fs.mkdir(path.join(db, 'osv-scalibr', 'npm'), { recursive: true });
  await fs.writeFile(path.join(db, 'osv-scalibr', 'npm', 'all.zip'), 'synthetic database');
  const config: Config = { ...structuredClone(defaults), osvDatabase: db,
    tools: { git: { path: 'synthetic-git', sha256: 'a'.repeat(64), version: '2.54.0' }, osv: { path: 'synthetic-osv', sha256: 'b'.repeat(64), version: '2.7.0' } } };
  const repo = await loaded('src/repository.ts', { ...fs, path, ...safety, catalogIdentity, legacyEngines, changedEntries, commitPair, treeEntries, readGitBlobs,
    observeConfiguration, summarizeConfiguration, ...cleanup, verifyVersion: async () => {}, jobDiskDiagnostic: () => undefined,
    execute: async (_tool: unknown, args: string[], execution: { input?: string }) => {
      const command = args.slice(args.indexOf('-C') + 2);
      assert.ok(['rev-parse', 'status', 'ls-tree', 'cat-file'].includes(command[0]!));
      const result = gitResult(command, execution.input);
      return { reason: 'exit', code: result.status, stdout: result.stdout };
    },
  }, ['buildPlan', 'readCommitFiles', 'materialize']);
  const calls: { database: string; config: string; snapshot: string; toolVersion: string }[] = [];
  const adapters = await loaded('src/adapters.ts', { ...fs, path, ...safety, ...databases, ...npm, emptyRun, JobDiskCopyLimitError,
    RuntimeAdvisoryAdapter: class {}, TrivyAdapter: class {},
    verifyVersion: async (tool: { version: string }) => assert.equal(tool.version, '2.7.0'),
    execute: async (tool: { version: string }, args: string[], execution: { database: string }) => {
      assert.ok(['--offline', '--offline-vulnerabilities', '--no-resolve', '--all-packages', '--all-vulns'].every(flag => args.includes(flag)));
      const sources: { source: { path: string }; packages: unknown[] }[] = [];
      for (let index = 0; index < args.length; index++) if (args[index] === '--lockfile') {
        const file = args[++index]!.slice(1), snapshot = path.dirname(file);
        calls.push({ database: execution.database, config: await fs.readFile(args[args.indexOf('--config') + 1]!, 'utf8'), snapshot, toolVersion: tool.version });
        if (path.basename(path.dirname(snapshot)) === options.failureSide) return { reason: options.failureReason ?? 'exit', code: 2, stdout: Buffer.alloc(0) };
        const content = JSON.parse(await fs.readFile(file, 'utf8'));
        const version = content.packages['node_modules/example']?.version ?? '1.0.0';
        sources.push({ source: { path: file }, packages: [{ package: { name: 'example', ecosystem: 'npm', version },
          vulnerabilities: options.advisories?.(version) ?? [] }, ...options.extraPackages ?? []] });
      }
      const vulnerable = sources.some(source => source.packages.some(item => ((item as { vulnerabilities?: unknown[] }).vulnerabilities?.length ?? 0) > 0));
      return { reason: 'exit', code: vulnerable ? 1 : 0, stdout: Buffer.from(JSON.stringify({ results: sources })) };
    },
  }, ['createOsvAdapter', 'createAdapters']);
  const dependencies = await loaded('src/dependencies.ts', { ...fs, path, ...safety, ...cleanup, ...graph, ...databases, packageVersion,
    ...repository, ...repo, ...adapters,
  }, ['analyzeDependencies', 'dependencyText']);
  const analyze = (comparison: boolean | CommitPair = true): Promise<DependencyReport> => dependencies.analyzeDependencies(root, config, workspace, new AbortController().signal,
    comparison === false ? undefined : comparison === true ? { base, head } : comparison);
  return { root, workspace, config, base, head, calls, git, analyze, text: dependencies.dependencyText as (report: DependencyReport) => string, adapters, repo };
}

test('compares removed, added and unchanged advisories across versions with v2 metadata and one database', async () => {
  const f = await fixture({ advisories: version => version === '1.0.0' ? [advisory('GHSA-removed'), advisory('GHSA-kept')] : [advisory('GHSA-added', 'HIGH'), advisory('GHSA-kept')] });
  const beforeStatus = f.git(['status', '--porcelain']);
  const beforeMetadata = (await fs.readdir(path.join(f.root, '.git'), { recursive: true })).sort();
  const report = await f.analyze();
  assert.equal(report.exitCode, 10, JSON.stringify(report.missing)); assert.equal(report.schema, 'scanmux.dependencies/v2');
  assert.deepEqual(report.tool, { name: 'scanmux', version: packageVersion });
  assert.deepEqual(report.advisoryCounts, { added: 1, removed: 1, unchanged: 1, present: 0 });
  assert.deepEqual(report.advisories.map(item => [item.id, item.status, item.baseVersion, item.headVersion]), [
    ['GHSA-added', 'added', '1.0.0', '1.1.0'], ['GHSA-kept', 'unchanged', '1.0.0', '1.1.0'], ['GHSA-removed', 'removed', '1.0.0', '1.1.0'],
  ]);
  assert.deepEqual(report.advisories[0], { lockfile: 'package-lock.json', ecosystem: 'npm', package: 'example', baseVersion: '1.0.0', headVersion: '1.1.0',
    id: 'GHSA-added', aliases: ['CVE-2026-12345'], severity: 'HIGH', fixedVersions: ['1.2.0'], dev: true, status: 'added' });
  assert.equal(report.osv.database.length, 1); assert.equal(report.osv.database[0]!.sha256, safety.hash('synthetic database'));
  assert.equal(report.osv.sides.base?.state, 'completed'); assert.equal(report.osv.sides.head.state, 'completed');
  assert.equal(new Set(f.calls.map(call => call.database)).size, 1); assert.equal(new Set(f.calls.map(call => call.snapshot)).size, 2);
  assert.deepEqual(f.calls.map(call => [call.config, call.toolVersion]), [['', '2.7.0'], ['', '2.7.0']]);
  assert.deepEqual(f.git(['status', '--porcelain']), beforeStatus);
  assert.deepEqual((await fs.readdir(path.join(f.root, '.git'), { recursive: true })).sort(), beforeMetadata);
  assert.equal(JSON.stringify(report).includes('scanner prose'), false);
  const text = f.text(report); assert.match(text, /Advisories: added=1 removed=1 unchanged=1 present=0/);
  const reversed = f.text({ ...report, advisories: [...report.advisories].reverse() });
  assert.ok(reversed.indexOf('  added  ') < reversed.indexOf('  removed  '));
});

test('removed or unchanged advisories give exit 0, even when upgrade analysis is undetermined', async () => {
  const f = await fixture({ advisories: version => version === '1.0.0' ? [advisory('GHSA-removed'), advisory('GHSA-kept', null, [])] : [advisory('GHSA-kept', null, [])] });
  const report = await f.analyze();
  assert.equal(report.exitCode, 0); assert.equal(report.upgradeCounts.undetermined, 1);
  assert.deepEqual(report.advisoryCounts, { added: 0, removed: 1, unchanged: 1, present: 0 });
  assert.equal(report.advisories[0]!.severity, null); assert.deepEqual(report.advisories[0]!.fixedVersions, []);
});

test('without a base, advisories are present and exit 10; clean head exits 0', async () => {
  const vulnerable = await fixture({ advisories: () => [advisory('GHSA-present', 'LOW')] }), report = await vulnerable.analyze(false);
  assert.equal(report.exitCode, 10); assert.equal(report.advisories[0]!.status, 'present'); assert.equal(report.advisories[0]!.baseVersion, null);
  assert.equal(report.osv.sides.base, null); assert.equal(vulnerable.calls.length, 1);
  assert.deepEqual(report.advisoryCounts, { added: 0, removed: 0, unchanged: 0, present: 1 });
  assert.equal((await (await fixture()).analyze(false)).exitCode, 0);
});

test('duplicate advisory instances aggregate versions and retain non-development usage', async () => {
  const extra = { 'node_modules/parent/node_modules/example': { version: '1.0.0' } };
  const f = await fixture({ baseFiles: { ...files('1.0.0'), 'package-lock.json': lock('1.0.0', extra) },
    headFiles: { ...files('1.1.0'), 'package-lock.json': lock('1.1.0', extra) }, advisories: () => [advisory('GHSA-kept')],
    extraPackages: [{ package: { name: 'example', ecosystem: 'npm', version: '1.0.0' }, vulnerabilities: [advisory('GHSA-kept')] }],
  });
  const report = await f.analyze();
  assert.equal(report.exitCode, 0); assert.equal(report.advisories.length, 1);
  assert.deepEqual([report.advisories[0]!.baseVersion, report.advisories[0]!.headVersion, report.advisories[0]!.dev, report.advisories[0]!.severity], ['1.0.0', '1.0.0, 1.1.0', false, 'MODERATE']);
  assert.deepEqual(report.advisoryCounts, { added: 0, removed: 0, unchanged: 1, present: 0 });
});

for (const side of ['base', 'head'] as const) for (const reason of ['exit', 'timeout', 'cancelled']) test(`OSV ${reason} on ${side} exits 2, never a clean comparison`, async () => {
  const f = await fixture({ failureSide: side, failureReason: reason }), report = await f.analyze();
  assert.equal(report.exitCode, 2); assert.equal(report.osv.sides[side]!.state, 'failed'); assert.deepEqual(report.advisories, []);
  assert.ok(report.missing.some(item => item.kind === 'osv' && item.side === side));
});

test('base-only and head-only lockfiles use their own plans and absent versions are null', async () => {
  const noLock = { 'README.md': 'fixture\n' };
  for (const side of ['base', 'head'] as const) {
    const f = await fixture({ ...(side === 'base' ? { headFiles: noLock } : { baseFiles: noLock }), advisories: () => [advisory('GHSA-one-side')] });
    const report = await f.analyze(), row = report.advisories[0]!;
    assert.equal(report.exitCode, side === 'base' ? 0 : 10); assert.equal(f.calls.length, 1);
    assert.equal(row.status, side === 'base' ? 'removed' : 'added');
    assert.equal(side === 'base' ? row.headVersion : row.baseVersion, null);
  }
});

test('malformed or excluded lockfiles and an unresolved commit exit 2', async () => {
  for (const body of ['{', Buffer.from([0]), 'version https://git-lfs.github.com/spec/v1\n']) {
    const f = await fixture({ baseFiles: { ...files('1.0.0'), 'package-lock.json': body } });
    assert.equal((await f.analyze()).exitCode, 2);
  }
  const f = await fixture();
  const report = await f.analyze({ base: 'f'.repeat(40), head: f.head });
  assert.equal(report.exitCode, 2); assert.ok(report.missing.some(item => item.kind === 'plan_blocker' && item.code === 'git_failed'));
  // An invalid comparison remains a CLI failure even before scanner execution.
  const write = process.stderr.write; let output = '';
  process.stderr.write = ((chunk: string) => { output += chunk; return true; }) as typeof write;
  try { assert.equal(await main(['deps', f.root, '--config', 'relative.json', '--base', 'not-a-commit', '--head', f.head]), 2); }
  finally { process.stderr.write = write; }
  assert.equal(JSON.parse(output).exitCode, 2);
});

test('workspace links and declared workspace paths do not make OSV incomplete, including scan', async () => {
  const content = lock('1.1.0', { 'node_modules/local-link': { link: true, resolved: 'packages/local-link' },
    'packages/local-link': { name: 'local-link', version: '1.0.0' }, 'packages/local-workspace': { name: 'local-workspace' } }, { workspaces: ['packages/*'] });
  const f = await fixture({ baseFiles: { ...files('1.0.0'), 'package-lock.json': content }, headFiles: { ...files('1.1.0'), 'package-lock.json': content }, extraPackages: [
    { package: { name: 'local-link', ecosystem: 'npm', purl: 'pkg:npm/local-link?source=LOCAL' }, vulnerabilities: [advisory('GHSA-local')] },
    { package: { name: 'local-workspace', ecosystem: 'npm' } },
  ] });
  const report = await f.analyze(); assert.equal(report.exitCode, 0); assert.equal(report.osv.state, 'completed');
  assert.ok(report.missing.some(item => item.kind === 'project_undetermined' && item.reason === 'workspaces_outside_subset'));
  const scanWorkspace = path.join(path.dirname(f.root), 'scan'); await fs.mkdir(scanWorkspace);
  const plan = await f.repo.buildPlan(f.root, f.config, scanWorkspace), snapshot = await f.repo.materialize(plan, f.config, scanWorkspace, new AbortController().signal);
  const run: OsvRun = await f.adapters.createAdapters()[1].run({ plan, config: f.config, workspace: scanWorkspace, snapshot, signal: new AbortController().signal, secretsCleared: false });
  assert.equal(run.execution, 'completed'); assert.equal(run.coverage, 'analyzed'); assert.deepEqual(run.findings, []);
  assert.equal(run.packages, undefined, 'scan retains its existing finding shape');
  await cleanup.sourceCleanupFor(scanWorkspace).cleanup(scanWorkspace);
});

test('scoped registry advisories retain their names and development flags alongside local packages', async () => {
  const name = '@example-node_modules/shared';
  const vulnerability = { ...advisory('GHSA-registry'), affected: [{ package: { name, ecosystem: 'npm' },
    ranges: [{ events: [{ introduced: '0' }, { fixed: '2.1.0' }] }] }] };
  for (const local of [false, true]) {
    const content = lock('1.1.0', local ? {
      'packages/local': { name },
      [`node_modules/${name}`]: { link: true, resolved: 'packages/local' },
      'node_modules/parent': { version: '1.0.0', dev: true, dependencies: { [name]: '^2.0.0' } },
      [`node_modules/parent/node_modules/${name}`]: { version: '2.0.0', dev: true },
    } : { [`node_modules/${name}`]: { version: '2.0.0', dev: true } }, { workspaces: ['packages/*'] });
    const f = await fixture({ headFiles: { ...files('1.1.0'), 'package-lock.json': content }, extraPackages: [
      ...(local ? [{ package: { name, ecosystem: 'npm', purl: `pkg:npm/${name}?source=LOCAL` } },
        { package: { name: 'parent', version: '1.0.0', ecosystem: 'npm' } }] : []),
      { package: { name, version: '2.0.0', ecosystem: 'npm' }, vulnerabilities: [vulnerability] },
    ] });
    const report = await f.analyze(false);
    assert.equal(report.exitCode, 10); assert.equal(report.osv.state, 'completed');
    assert.deepEqual(report.advisories.map(item => [item.package, item.id, item.headVersion, item.dev, item.status]),
      [[name, 'GHSA-registry', '2.0.0', true, 'present']]);
  }
});

test('declared file links and their targets remain local without workspace declarations on both sides', async () => {
  for (const version of [null, '1.0.0']) {
    const content = lock('1.1.0', {
      'node_modules/local': { link: true, resolved: 'packages/local' },
      'packages/local': version === null ? {} : { version },
    }, { dependencies: { example: '^1.0.0', local: 'file:packages/local' } });
    const manifest = JSON.stringify({ name: 'app', dependencies: { example: '^1.0.0', local: 'file:packages/local' } });
    const committed = { ...files('1.1.0'), 'package.json': manifest, 'package-lock.json': content };
    const f = await fixture({ baseFiles: committed, headFiles: committed, extraPackages: [{ package: { name: 'local', ecosystem: 'npm' } }] });
    const report = await f.analyze();
    assert.equal(report.exitCode, 0); assert.equal(report.osv.state, 'completed');
    assert.equal(report.osv.sides.base?.state, 'completed'); assert.equal(report.osv.sides.head.state, 'completed');
    assert.equal(report.missing.some(item => item.kind === 'osv'), false); assert.deepEqual(report.advisories, []);
  }
});

test('local packages with matching names and versions do not change registry advisory development flags', async () => {
  const content = lock('1.1.0', {
    'node_modules/local-alias': { link: true, resolved: 'packages/local' },
    'packages/local': { name: 'example', version: '1.1.0' },
  }, { workspaces: ['packages/*'] });
  const f = await fixture({ headFiles: { ...files('1.1.0'), 'package-lock.json': content }, advisories: () => [advisory('GHSA-registry')],
    extraPackages: [{ package: { name: 'example', ecosystem: 'npm', version: '1.1.0', purl: 'pkg:npm/example@1.1.0?source=LOCAL' } }],
  });
  const report = await f.analyze(false);
  assert.equal(report.exitCode, 10); assert.equal(report.osv.state, 'completed');
  assert.deepEqual(report.advisories.map(item => [item.package, item.id, item.dev]), [['example', 'GHSA-registry', true]]);
});

for (const pkg of [{ name: 'unknown', ecosystem: 'npm' }, { name: 'example', ecosystem: 'npm', version: '1.1.0', purl: 'pkg:npm/example?source=LOCAL' }]) test(`unproven local package ${pkg.name} still makes offline matching incomplete`, async () => {
  const f = await fixture({ extraPackages: [{ package: pkg }] }), report = await f.analyze();
  assert.equal(report.exitCode, 2); assert.equal(report.osv.state, 'partial');
  assert.ok(report.missing.some(item => item.kind === 'osv' && item.reason === 'offline_package_matching_incomplete'));
});

test('a local source receipt disambiguates workspace and registry packages with the same name', async () => {
  const content = lock('1.1.0', { 'packages/shared': { name: 'shared', version: '1.0.0' }, 'node_modules/shared': { version: '2.0.0' } }, { workspaces: ['packages/*'] });
  for (const localSource of [false, true]) {
    const f = await fixture({ baseFiles: { ...files('1.0.0'), 'package-lock.json': content }, headFiles: { ...files('1.1.0'), 'package-lock.json': content },
      extraPackages: [{ package: { name: 'shared', ecosystem: 'npm', ...(localSource ? { purl: 'pkg:npm/shared?source=LOCAL' } : {}) } },
        { package: { name: 'shared', ecosystem: 'npm', version: '2.0.0' } }],
    });
    assert.equal((await f.analyze()).exitCode, localSource ? 0 : 2);
  }
});

test('config.worktree is accepted with the safe main-config allowlist', async () => {
  const f = await fixture({ mainConfig: '[core]\nrepositoryformatversion = 0\nbare = false\n[extensions]\nworktreeConfig = true\n', worktreeConfig: '[core]\nfilemode = false\nbare = false\n' });
  assert.equal((await f.analyze()).exitCode, 0);
});

test('worktree and main configs reject the same includes, execution keys, extensions and continuations', async () => {
  const f = await fixture();
  for (const value of ['[include]\npath = unsafe\n', '[includeIf "gitdir:*"]\npath = unsafe\n', '[core]\nhooksPath = unsafe\n', '[core]\nfsmonitor = unsafe\n',
    '[filter "test"]\nsmudge = unsafe\n', '[extensions]\nunknown = true\n', '[core]\nfilemode = false\\\n', '[core]\nbare = true\n', '[core]\nrepositoryformatversion = 1\n']) {
    const errors: string[][] = [];
    for (const file of ['config', 'config.worktree']) {
      await fs.writeFile(path.join(f.root, '.git', file), value);
      const plan: Plan = await f.repo.buildPlan(f.root, f.config, f.workspace);
      errors.push(plan.blockers); await fs.writeFile(path.join(f.root, '.git', file), '[core]\nrepositoryformatversion = 0\nbare = false\n');
    }
    assert.deepEqual(errors[1], errors[0], value); assert.ok(errors[0]!.length, value);
  }
});
