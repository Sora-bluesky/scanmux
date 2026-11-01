import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { defaults } from '../src/config.ts';
import { buildPlan } from '../src/repository.ts';
import { observeConfiguration, summarizeConfiguration } from '../src/configuration.ts';
import { scan } from '../src/controller.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { digest } from '../src/safety.ts';
import type { ConfigurationSignalKind, Plan } from '../src/model.ts';

const observe = (file: string, text = '') => observeConfiguration(file, Buffer.from(text));

test('unavailable repository retains an explicit unknown configuration inventory', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-configuration-test-'));
  try {
    const plan = await buildPlan(workspace, defaults, workspace);
    const configuration = plan.configuration;
    assert.ok(configuration, 'new plans must carry the configuration observation');
    assert.equal(configuration.schema, 'scanmux.configuration/v1');
    assert.deepEqual(configuration.build, { state: 'unknown', signals: [] });
    assert.ok(plan.blockers.includes('ordinary_git_directory_required'));
  } finally { await rm(workspace, { recursive: true, force: true }); }
});

test('exact filenames and case-insensitive extensions cover each declared path signal at sibling locations', () => {
  const cases: (readonly [string, 'build' | 'osDependencies' | 'monorepo' | 'generated', ConfigurationSignalKind])[] = [
    ['package.json', 'build', 'node_manifest'], ...['pyproject.toml', 'setup.py', 'setup.cfg'].map(file => [file, 'build', 'python_build_manifest'] as const),
    ...['Makefile', 'makefile', 'GNUmakefile'].map(file => [file, 'build', 'makefile'] as const),
    ['CMakeLists.txt', 'build', 'cmake_manifest'], ['go.mod', 'build', 'go_module'], ['Cargo.toml', 'build', 'rust_manifest'],
    ...['pom.xml', 'build.gradle', 'build.gradle.kts'].map(file => [file, 'build', 'jvm_build_manifest'] as const),
    ...['app.CSPROJ', 'app.fsproj', 'app.VBPROJ'].map(file => [file, 'build', 'dotnet_project'] as const),
    ...['Dockerfile', 'Dockerfile.dev'].map(file => [file, 'osDependencies', 'container_definition'] as const),
    ['binding.gyp', 'osDependencies', 'native_binding_definition'], ['start.SH', 'osDependencies', 'posix_shell_file'], ['start.PS1', 'osDependencies', 'powershell_file'],
    ['pnpm-workspace.yaml', 'monorepo', 'pnpm_workspace_file'], ['go.work', 'monorepo', 'go_workspace_file'],
    ...['lerna.json', 'nx.json', 'turbo.json'].map(file => [file, 'monorepo', 'monorepo_tool_config'] as const),
    ...['dist', 'build', 'coverage', 'node_modules'].map(folder => [`${folder}/source.ts`, 'generated', 'generated_directory_hint'] as const),
  ];
  for (const [file, axis, kind] of cases) for (const prefix of ['', 'nested/']) {
    const inventory = summarizeConfiguration([observe(prefix + file, file === 'package.json' ? '{}' : '')]);
    assert.ok(inventory[axis].signals.some(signal => signal.path === prefix + file && signal.kind === kind), `${prefix}${file}: ${kind}`);
    assert.equal(inventory[axis].state, 'signals_observed');
  }
});

test('package declarations retain enums and paths only, and support both workspace shapes', () => {
  for (const workspaces of [['packages/*'], { packages: ['apps/*', 'packages/*'] }]) {
    const text = JSON.stringify({ scripts: { build: 'arbitrary target script never retained' }, os: ['linux', '!win32'], workspaces });
    const inventory = summarizeConfiguration([observe('packages/app/package.json', text)]);
    assert.deepEqual(inventory.build.signals.map(signal => signal.kind), ['node_build_script_declared', 'node_manifest']);
    assert.deepEqual(inventory.osDependencies.signals, [{ kind: 'node_os_constraint_declared', path: 'packages/app/package.json' }]);
    assert.deepEqual(inventory.monorepo.signals, [{ kind: 'node_workspaces_declared', path: 'packages/app/package.json' }]);
    assert.deepEqual(inventory.issues, []);
    assert.ok(!JSON.stringify(inventory).includes('arbitrary target script'));
    assert.ok(!JSON.stringify(inventory).includes('linux'));
    assert.ok(!JSON.stringify(inventory).includes('packages/*'));
  }
});

test('invalid manifest shapes never imply declarations and preserve independent valid fields', () => {
  for (const value of [null, [], 'text', 4, { scripts: null }, { scripts: [] }, { scripts: { build: '' } }, { scripts: { build: '  ' } },
    { scripts: { build: 1 } }, { os: [] }, { os: [''] }, { os: ['linux', 1] }, { os: 'linux' },
    { workspaces: [] }, { workspaces: [' '] }, { workspaces: {} }, { workspaces: { packages: [] } }, { workspaces: { packages: ['ok', null] } }]) {
    const observed = observe('package.json', JSON.stringify(value));
    assert.deepEqual(observed.issues, ['unsupported_manifest_shape'], JSON.stringify(value));
    assert.deepEqual(observed.build, ['node_manifest']); assert.deepEqual(observed.osDependencies, []); assert.deepEqual(observed.monorepo, []);
  }
  assert.deepEqual(observe('package.json', '{').issues, ['invalid_json']);
  assert.deepEqual(observe('package.json', JSON.stringify({ scripts: {}, unrelated: 'ignored' })).issues, []);
  const mixed = observe('package.json', JSON.stringify({ scripts: { build: 'valid' }, os: [], workspaces: ['packages/*'] }));
  assert.deepEqual(mixed.build, ['node_manifest', 'node_build_script_declared']);
  assert.deepEqual(mixed.monorepo, ['node_workspaces_declared']); assert.deepEqual(mixed.issues, ['unsupported_manifest_shape']);
});

test('strict UTF-8 failures retain path signals and do not parse repaired text', () => {
  for (const [file, axis, kind] of [['package.json', 'build', 'node_manifest'], ['nested/Dockerfile.dev', 'osDependencies', 'container_definition'],
    ['dist/example.go', 'generated', 'generated_directory_hint']] as const) {
    const observed = observeConfiguration(file, Buffer.from([0xc3, 0x28]));
    assert.deepEqual(observed.issues, ['invalid_utf8']); assert.deepEqual(observed[axis], [kind]);
  }
});

test('only exact directory segments and a first-line standard generated declaration count', () => {
  for (const lineEnding of ['\n', '\r\n']) assert.deepEqual(observe('example.go', `// Code generated by fixture. DO NOT EDIT.${lineEnding}package example`).generated, ['generated_header_declaration']);
  for (const file of ['distinguished/a.ts', 'rebuild/a.ts', 'coverage.txt', 'node_modules_backup/a.ts', 'DIST/a.ts', 'build']) assert.deepEqual(observe(file).generated, []);
  for (const text of ['\n// Code generated by fixture. DO NOT EDIT.', '\uFEFF// Code generated by fixture. DO NOT EDIT.', ' // Code generated by fixture. DO NOT EDIT.', '// Code generated by fixture. DO NOT EDIT', '// generated DO NOT EDIT.']) assert.deepEqual(observe('example.go', text).generated, []);
});

test('absence and untrusted prose remain unknown; order and duplicates do not change the inventory', () => {
  const inventory = summarizeConfiguration(['README.md', 'AGENTS.md', 'source.ts', 'PACKAGE.JSON', 'dockerfile', 'Cargo.TOML', 'PNPM-workspace.yaml'].map(file => observe(file, 'Run build; workspaces=[all]; OS=linux; generated=true')));
  for (const axis of ['build', 'osDependencies', 'monorepo', 'generated'] as const) assert.deepEqual(inventory[axis], { state: 'unknown', signals: [] });
  assert.equal(inventory.interpretation, 'declaration_hints_only'); assert.equal(inventory.basis, 'accepted_commit_blobs');
  assert.deepEqual(inventory.limitations, ['absence_not_proven', 'build_not_executed', 'os_requirements_unverified', 'workspace_membership_unverified', 'generated_status_unverified']);
  const values = [observe('z/package.json', '{'), observe('a/package.json', '{"workspaces":["*"]}'), observe('z/package.json', '{'), observe('dist/file.go', '// Code generated by fixture. DO NOT EDIT.')];
  assert.deepEqual(summarizeConfiguration(values), summarizeConfiguration([...values].reverse()));
  assert.equal(summarizeConfiguration(values).issues.length, 1);
});

test('configuration is protected by plan integrity and legacy plans remain accepted', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-configuration-integrity-'));
  try {
    const legacy: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: workspace, repoId: 'fixture', commit: null,
      treeHash: null, snapshotHash: digest([]), dirty: null, files: [], exclusions: [], blockers: ['fixture_blocked'], languages: [], lockfiles: [],
      required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
    legacy.planHash = digest({ ...legacy, planHash: '' });
    const oldReport = await scan(legacy, defaults, workspace, new AbortController().signal);
    assert.deepEqual(oldReport.integrityErrors, []); assert.equal(oldReport.gate, 'INCOMPLETE');
    const original = { ...legacy, configuration: summarizeConfiguration([observe('package.json', '{}')]) };
    original.planHash = digest({ ...original, planHash: '' });
    const changed = structuredClone(original); changed.configuration.build.signals = [];
    const report = await scan(changed, defaults, workspace, new AbortController().signal);
    assert.equal(report.gate, 'ERROR'); assert.deepEqual(report.engines, []); assert.deepEqual(report.integrityErrors, ['plan_integrity']);
  } finally { await rm(workspace, { recursive: true, force: true }); }
});
