import test from 'node:test';
import assert from 'node:assert/strict';
import { assessUpgrades, type UpgradeAssessment, type UpgradeFinding } from '../src/dependency-graph.ts';

const bytes = (value: unknown) => value instanceof Uint8Array ? value : new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value, null, 2));
const inputs = (files: Record<string, unknown>) => new Map(Object.entries(files).map(([file, value]) => [file, bytes(value)]));
const pkg = (version: string, extra: Record<string, unknown> = {}) => ({ version, resolved: `https://registry.npmjs.org/x/-/x-${version}.tgz`, integrity: 'sha512-' + version, ...extra });
function npm(options: { root?: Record<string, string>; packages?: Record<string, unknown>; manifest?: Record<string, unknown>; files?: Record<string, unknown> } = {}) {
  const root = options.root ?? { lodash: '^4.17.0' };
  return {
    'package.json': { name: 'app', dependencies: root, ...options.manifest },
    'package-lock.json': { name: 'app', lockfileVersion: 3, packages: { '': { name: 'app', dependencies: root }, 'node_modules/lodash': pkg('4.17.20'), ...options.packages } },
    ...options.files,
  };
}
const finding = (fields: Partial<UpgradeFinding> = {}): UpgradeFinding => ({
  lockfile: 'package-lock.json', name: 'lodash', version: '4.17.20', advisories: ['GHSA-test'], fixedVersions: ['4.17.21'], fixEvents: 'incomplete', ...fields,
});
const assess = (files: Record<string, unknown>, fields: Partial<UpgradeFinding> = {}): UpgradeAssessment => {
  const { upgrades } = assessUpgrades(inputs(files), [finding(fields)]);
  assert.equal(upgrades.length, 1);
  return upgrades[0]!;
};
const verdict = (row: UpgradeAssessment) => [row.state, row.reason];

test('row 1: a lockfile outside npm v2/v3 and uv.lock v1 is ecosystem_not_supported', () => {
  assert.deepEqual(verdict(assess(npm(), { lockfile: 'yarn.lock' })), ['undetermined', 'ecosystem_not_supported']);
  const v1 = { ...npm(), 'package-lock.json': { name: 'app', lockfileVersion: 1, dependencies: {} } };
  assert.deepEqual(verdict(assess(v1)), ['undetermined', 'ecosystem_not_supported']);
});

test('row 2: a missing manifest, invalid lockfile or workspaces make the project undetermined', () => {
  const { 'package.json': _manifest, ...lockOnly } = npm();
  const missing = assessUpgrades(inputs(lockOnly), [finding()]);
  assert.deepEqual(verdict(missing.upgrades[0]!), ['undetermined', 'project_undetermined']);
  assert.deepEqual(missing.projects, [{ lockfile: 'package-lock.json', ecosystem: 'npm', status: 'undetermined', reason: 'manifest_missing' }]);
  assert.deepEqual(verdict(assess({ ...npm(), 'package-lock.json': '{' })), ['undetermined', 'project_undetermined']);
  assert.deepEqual(verdict(assess(npm({ manifest: { workspaces: ['packages/*'] } }))), ['undetermined', 'project_undetermined']);
  assert.deepEqual(verdict(assess(npm(), { lockfile: 'web/package-lock.json' })), ['undetermined', 'project_undetermined']);
});

test('row 3: a finding whose name@version has no instance is package_not_in_lockfile', () => {
  assert.deepEqual(verdict(assess(npm(), { version: '4.17.19' })), ['undetermined', 'package_not_in_lockfile']);
  assert.deepEqual(verdict(assess(npm(), { name: 'react' })), ['undetermined', 'package_not_in_lockfile']);
});

test('row 4: link, git and file sources are non_registry_source', () => {
  for (const extra of [{ resolved: 'git+ssh://git@example.invalid/lodash.git#abc' }, { resolved: 'file:../lodash' }]) {
    assert.deepEqual(verdict(assess(npm({ packages: { 'node_modules/lodash': pkg('4.17.20', extra) } }))), ['undetermined', 'non_registry_source']);
  }
});

test('row 5: a current or fixed version outside the subset is version_outside_subset', () => {
  assert.deepEqual(verdict(assess(npm(), { fixedVersions: ['4.17.21-beta.1'] })), ['undetermined', 'version_outside_subset']);
  const prerelease = npm({ packages: { 'node_modules/lodash': pkg('4.17.20-rc.1') } });
  assert.deepEqual(verdict(assess(prerelease, { version: '4.17.20-rc.1' })), ['undetermined', 'version_outside_subset']);
});

test('row 6: no recorded fixed version is no_recorded_fix, never unpublished', () => {
  assert.deepEqual(verdict(assess(npm(), { fixedVersions: [] })), ['undetermined', 'no_recorded_fix']);
});

test('row 7: no newer fixed version is blocked only when the fix events are complete', () => {
  assert.deepEqual(verdict(assess(npm(), { fixedVersions: ['4.17.20', '4.0.0'] })), ['undetermined', 'fix_events_incomplete']);
  assert.deepEqual(verdict(assess(npm(), { fixedVersions: ['4.17.20'], fixEvents: 'complete' })), ['blocked', 'no_newer_fixed_version']);
});

test('row 8: an instance bundled by its parent is blocked', () => {
  assert.deepEqual(verdict(assess(npm({ packages: { 'node_modules/lodash': pkg('4.17.20', { inBundle: true }) } }))), ['blocked', 'bundled_by_parent']);
});

test('row 9: declared overrides make the result undetermined', () => {
  assert.deepEqual(verdict(assess(npm({ manifest: { overrides: { lodash: '4.17.21' } } }))), ['undetermined', 'overrides_declared']);
  const uv = uvProject({ manifestTail: '[tool.uv]\noverride-dependencies = ["requests==2.31.0"]\n' });
  assert.deepEqual(verdict(assess(uv, uvFinding())), ['undetermined', 'overrides_declared']);
});

test('row 10: unconditional exclusions block with manifest exact > manifest range > transitive priority and listed blockers', () => {
  const exact = assess(npm({ root: { lodash: '4.17.20', a: '^1.0.0' }, packages: { 'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '~4.17.0' } }) } }));
  assert.deepEqual(verdict(exact), ['blocked', 'exact_pin']);
  assert.deepEqual(exact.instances[0]!.blockers, [{ from: 'app', kind: 'manifest_exact', spec: '4.17.20' }]);
  assert.deepEqual(verdict(assess(npm(), { fixedVersions: ['5.0.0'] })), ['blocked', 'range_excludes_fixed']);
  const transitive = assess(npm({ root: { lodash: '^4.17.0', a: '^1.0.0' }, packages: { 'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '4.17.20' } }) } }));
  assert.deepEqual(verdict(transitive), ['blocked', 'transitive_constraint']);
  assert.deepEqual(transitive.instances[0]!.blockers, [{ from: 'a@1.0.0', kind: 'transitive', spec: '4.17.20' }]);
  const both = assess(npm({ root: { lodash: '4.17.20', a: '^1.0.0' }, packages: { 'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '4.17.20' } }) } }));
  assert.deepEqual(both.instances[0]!.blockers.map(item => item.kind), ['manifest_exact', 'transitive']);
  const many = Object.fromEntries(Array.from({ length: 10 }, (_, index) => [`node_modules/p${index}`, pkg('1.0.0', { dependencies: { lodash: '4.17.20' } })]));
  assert.equal(assess(npm({ packages: many }), { fixedVersions: ['4.17.21'] }).instances[0]!.blockers.length, 8);
});

test('row 10: exclusions only through markers, unrecorded specs or specs outside the subset stay undetermined', () => {
  assert.deepEqual(verdict(assess(uvProject({ marker: true }), uvFinding())), ['undetermined', 'conditional_requirement']);
  assert.deepEqual(verdict(assess(uvProject(), uvFinding({ name: 'urllib3', version: '2.0.0', fixedVersions: ['2.2.2'] }))), ['undetermined', 'transitive_spec_not_recorded']);
  assert.deepEqual(verdict(assess(npm({ root: { lodash: 'latest' } }))), ['undetermined', 'constraint_outside_subset']);
});

test('row 11: a cutoff declared in the repository or an unreadable .npmrc is cutoff_declared', () => {
  assert.deepEqual(verdict(assess(npm({ files: { '.npmrc': 'before=2024-01-01\n' } }))), ['undetermined', 'cutoff_declared']);
  assert.deepEqual(verdict(assess(npm({ files: { '.npmrc': new Uint8Array([0xff]) } }))), ['undetermined', 'cutoff_declared']);
  assert.deepEqual(verdict(assess(npm({ files: { '.npmrc': 'registry=https://registry.npmjs.org/\n' } }))), ['allowed', null]);
  for (const files of [uvProject({ lockOptions: '[options]\nexclude-newer = "2024-01-01T00:00:00Z"\n' }), uvProject({ manifestTail: '[tool.uv]\nexclude-newer = "2024-01-01"\n' }),
    { ...uvProject(), 'uv.toml': 'exclude-newer = "2024-01-01"\n' }]) {
    assert.deepEqual(verdict(assess(files, uvFinding({ fixedVersions: ['2.31.0'] }))), ['undetermined', 'cutoff_declared']);
  }
});

test('row 12: otherwise allowed with the smallest fixed version every edge admits', () => {
  const allowed = assess(npm(), { fixedVersions: ['5.0.0', '4.17.21', '4.17.19', '4.17.22'] });
  assert.deepEqual([allowed.state, allowed.reason, allowed.target], ['allowed', null, '4.17.21']);
  assert.deepEqual(verdict(assess(uvProject(), uvFinding({ fixedVersions: ['2.31.0'] }))), ['allowed', null]);
});

test('instances of one name@version combine as blocked > undetermined > allowed', () => {
  const files = npm({ root: { lodash: '^4.17.0', a: '^1.0.0' }, packages: {
    'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '4.17.20' } }), 'node_modules/a/node_modules/lodash': pkg('4.17.20'),
    'node_modules/b': pkg('1.0.0', { dependencies: { lodash: '~4.17.0' } }),
  } });
  const combined = assess(files);
  assert.deepEqual(combined.instances.map(item => [item.key, item.state]), [['node_modules/a/node_modules/lodash', 'blocked'], ['node_modules/lodash', 'allowed']]);
  assert.deepEqual([combined.state, combined.reason, combined.target], ['blocked', 'transitive_constraint', null]);
  const mixed = assess({ ...files, 'package-lock.json': { name: 'app', lockfileVersion: 3, packages: {
    '': { name: 'app', dependencies: { lodash: '^4.17.0' } }, 'node_modules/lodash': pkg('4.17.20'),
    'node_modules/x/node_modules/lodash': pkg('4.17.20', { resolved: 'git+ssh://git@example.invalid/l.git' }) } } });
  assert.deepEqual(verdict(mixed), ['undetermined', 'non_registry_source']);
});

function uvProject(options: { marker?: boolean; manifestTail?: string; lockOptions?: string } = {}) {
  const marker = options.marker ? ', marker = "sys_platform == \'win32\'"' : '', spec = options.marker ? '>=2.0,<2.31' : '>=2.0,<3';
  const pyproject = ['[project]', 'name = "app"', 'version = "0.1.0"', `dependencies = ["requests${spec}${options.marker ? '; sys_platform == \'win32\'' : ''}"]`, ''].join('\n')
    + (options.manifestTail ?? '');
  const lock = ['version = 1', 'revision = 2', 'requires-python = ">=3.12"', '', options.lockOptions ?? '',
    '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }', 'dependencies = [', `    { name = "requests"${marker} },`, ']', '',
    '[package.metadata]', `requires-dist = [{ name = "requests"${marker}, specifier = "${spec}" }]`, '',
    '[[package]]', 'name = "requests"', 'version = "2.30.0"', 'source = { registry = "https://pypi.org/simple" }', 'dependencies = [', '    { name = "urllib3" },', ']', '',
    '[[package]]', 'name = "urllib3"', 'version = "2.0.0"', 'source = { registry = "https://pypi.org/simple" }', ''].join('\n');
  return { 'pyproject.toml': pyproject, 'uv.lock': lock };
}
const uvFinding = (fields: Partial<UpgradeFinding> = {}) => ({ lockfile: 'uv.lock', name: 'requests', version: '2.30.0', fixedVersions: ['2.31.0'], ...fields });

const npmRoot = (root: Record<string, unknown>, packages: Record<string, unknown> = { 'node_modules/lodash': pkg('4.17.20') }) => ({
  'package.json': { name: 'app', ...root }, 'package-lock.json': { name: 'app', lockfileVersion: 3, packages: { '': { name: 'app', ...root }, ...packages } },
});
const registry = 'source = { registry = "https://pypi.org/simple" }';
function uvRaw(project: string[], root: string[], options: { lockHead?: string[]; tail?: string; packages?: string[] } = {}) {
  return {
    'pyproject.toml': ['[project]', 'name = "app"', 'version = "0.1.0"', ...project, ''].join('\n') + (options.tail ?? ''),
    'uv.lock': ['version = 1', 'revision = 2', ...options.lockHead ?? [], '', '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }', ...root, '',
      ...options.packages ?? ['[[package]]', 'name = "requests"', 'version = "2.30.0"', registry, '']].join('\n'),
  };
}
const requestsRoot = (requiresDist: string, dependencies = '{ name = "requests" }') => [`dependencies = [${dependencies}]`, '', '[package.metadata]', `requires-dist = [${requiresDist}]`];

test('direct requirements come from the manifest; a manifest that disagrees with the lockfile root is manifest_lock_mismatch', () => {
  const mismatch = ['undetermined', 'manifest_lock_mismatch'];
  for (const spec of ['latest', '4.17.20']) assert.deepEqual(verdict(assess(npm({ manifest: { dependencies: { lodash: spec } } }))), mismatch, spec);
  assert.deepEqual(verdict(assess(npm({ root: { lodash: '4.17.20' }, manifest: { dependencies: { lodash: '^4.17.0' } } }))), mismatch);
  const unlocked = npm({ root: { a: '^1.0.0' }, manifest: { dependencies: { a: '^1.0.0', lodash: '4.17.20' } }, packages: { 'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '^4.17.0' } }) } });
  assert.deepEqual(verdict(assess(unlocked)), mismatch);
  const uv = uvProject();
  const files = { ...uv, 'pyproject.toml': uv['pyproject.toml'].replace('<3', '<2.32') };
  assert.deepEqual(assessUpgrades(inputs(files), [finding(uvFinding())]).projects, [{ lockfile: 'uv.lock', ecosystem: 'uv', status: 'complete', reason: null }]);
  assert.deepEqual(verdict(assess(files, uvFinding())), mismatch);
});

test('repository uv constraints, overrides and dependency metadata are declared overrides', () => {
  const declared = ['undetermined', 'overrides_declared'];
  const cases: Record<string, unknown>[] = [
    uvProject({ manifestTail: '[tool.uv]\nconstraint-dependencies = ["requests<2.31"]\n' }),
    uvProject({ manifestTail: '[[tool.uv.dependency-metadata]]\nname = "requests"\nversion = "2.31.0"\n' }),
    { ...uvProject(), 'uv.toml': 'override-dependencies = ["requests==2.30.0"]\n' },
    { ...uvProject(), 'uv.toml': 'constraint-dependencies = ["requests<2.31"]\n' },
    { ...uvProject(), 'uv.toml': '[[dependency-metadata]]\nname = "requests"\n' },
    { ...uvProject(), 'uv.toml': new Uint8Array([0xff]) },
    uvProject({ lockOptions: '[manifest]\nconstraints = [{ name = "requests", specifier = "<2.31" }]\n' }),
    uvProject({ lockOptions: '[[manifest.dependency-metadata]]\nname = "requests"\n' }),
  ];
  for (const files of cases) assert.deepEqual(verdict(assess(files, uvFinding())), declared);
});

test('uv same-name requirements keep every entry with its marker, dev groups read requires-dev, and a non-string specifier is never unconstrained', () => {
  const split = uvRaw(['dependencies = ["requests>=2.0; sys_platform == \'win32\'", "requests<2.31; sys_platform != \'win32\'"]'],
    requestsRoot('{ name = "requests", marker = "sys_platform == \'win32\'", specifier = ">=2.0" }, { name = "requests", marker = "sys_platform != \'win32\'", specifier = "<2.31" }'));
  assert.deepEqual(verdict(assess(split, uvFinding())), ['undetermined', 'conditional_requirement']);
  const typed = uvRaw(['dependencies = ["requests"]'], requestsRoot('{ name = "requests", specifier = 42 }'));
  assert.deepEqual(verdict(assess(typed, uvFinding())), ['undetermined', 'manifest_lock_mismatch']);
  const dev = uvRaw(['dependencies = []', '', '[dependency-groups]', 'dev = ["requests>=2.0,<2.31"]'],
    ['[package.dev-dependencies]', 'dev = [{ name = "requests" }]', '', '[package.metadata]', 'requires-dist = []', '', '[package.metadata.requires-dev]', 'dev = [{ name = "requests", specifier = ">=2.0,<2.31" }]']);
  assert.deepEqual(verdict(assess(dev, uvFinding())), ['blocked', 'range_excludes_fixed']);
  const extra = uvRaw(['dependencies = []', '', '[project.optional-dependencies]', 'dev = ["requests>=2.0,<3"]'],
    ['[package.optional-dependencies]', 'dev = [{ name = "requests" }]', '', '[package.metadata]', 'requires-dist = [{ name = "requests", marker = "extra == \'dev\'", specifier = ">=2.0,<3" }]']);
  assert.deepEqual(verdict(assess(extra, uvFinding())), ['allowed', null]);
});

test('a conditional or repeated uv requirement is conditional_requirement even when its spec admits the fix', () => {
  const conditional = ['undetermined', 'conditional_requirement'];
  const marker = '{ name = "requests", marker = "sys_platform == \'win32\'" }';
  const single = uvRaw(['dependencies = ["requests>=2.0; sys_platform == \'win32\'"]'], requestsRoot('{ name = "requests", marker = "sys_platform == \'win32\'", specifier = ">=2.0" }', marker));
  assert.deepEqual(verdict(assess(single, uvFinding())), conditional);
  const repeated = uvRaw(['dependencies = ["requests>=2.0", "requests<3"]'], requestsRoot('{ name = "requests", specifier = ">=2.0" }, { name = "requests", specifier = "<3" }'));
  assert.deepEqual(verdict(assess(repeated, uvFinding())), conditional);
  const lockMarkerOnly = uvRaw(['dependencies = ["requests>=2.0"]'], requestsRoot('{ name = "requests", specifier = ">=2.0" }', marker));
  assert.deepEqual(verdict(assess(lockMarkerOnly, uvFinding())), conditional);
});

test('manifest and lockfile requirements are compared with their marker contents', () => {
  const mismatch = ['undetermined', 'manifest_lock_mismatch'];
  for (const [manifest, lock] of [["sys_platform == 'win32'", "sys_platform == 'linux'"], ["platform_version == 'a  b'", "platform_version == 'a b'"]]) {
    const files = uvRaw([`dependencies = ["requests>=2.0; ${manifest}"]`], requestsRoot(`{ name = "requests", marker = "${lock}", specifier = ">=2.0" }`));
    assert.deepEqual(verdict(assess(files, uvFinding())), mismatch, manifest);
  }
});

test('a uv version that fails validation keeps the finding on the instance as version_outside_subset', () => {
  const files = uvRaw(['dependencies = ["requests>=2.0"]'], requestsRoot('{ name = "requests", specifier = ">=2.0" }'),
    { packages: ['[[package]]', 'name = "requests"', 'version = "2.30.0rc1"', registry, ''] });
  assert.deepEqual(verdict(assess(files, uvFinding({ version: '2.30.0rc1' }))), ['undetermined', 'version_outside_subset']);
});

test('an instance without resolved incoming edges, or with an unresolved edge of the same name, is incoming_edges_incomplete', () => {
  const incomplete = ['undetermined', 'incoming_edges_incomplete'];
  assert.deepEqual(verdict(assess(npm({ root: { a: '^1.0.0' }, packages: { 'node_modules/a': pkg('1.0.0') } }))), incomplete);
  const nested = npmRoot({ dependencies: { lodash: '^4.17.0', x: '^1.0.0' } },
    { 'node_modules/x': pkg('1.0.0', { dependencies: { lodash: '^4.17.0' } }), 'node_modules/x/node_modules/lodash': pkg('4.17.20') });
  assert.deepEqual(verdict(assess(nested)), incomplete);
});

test('pyproject dynamic dependencies are outside the subset', () => {
  const dynamic = assessUpgrades(inputs(uvProject({ manifestTail: 'dynamic = ["dependencies"]\n' })), [{ ...finding(), ...uvFinding() }]);
  assert.deepEqual(verdict(dynamic.upgrades[0]!), ['undetermined', 'project_undetermined']);
  assert.equal(dynamic.projects[0]!.reason, 'dynamic_dependencies_outside_subset');
  assert.deepEqual(verdict(assess(uvProject({ manifestTail: 'dynamic = ["version"]\n' }), uvFinding())), ['allowed', null]);
});

test('a manifest nested beyond the depth limit is a closed reason, not an error', () => {
  const depth = 20_000;
  const text = '{"name":"app","dependencies":{"lodash":"^4.17.0"},"overrides":' + '{"a":'.repeat(depth) + '"1"' + '}'.repeat(depth) + '}';
  const report = assessUpgrades(inputs({ ...npm(), 'package.json': text }), [finding()]);
  assert.deepEqual(verdict(report.upgrades[0]!), ['undetermined', 'project_undetermined']);
  assert.equal(report.projects[0]!.reason, 'manifest_depth_limit');
});

test('npm optionalDependencies take precedence over dependencies; other cross-section duplicates are duplicate_requirement', () => {
  const optional = assess(npmRoot({ dependencies: { lodash: '4.17.20' }, optionalDependencies: { lodash: '^4.17.0' } }));
  assert.deepEqual([optional.state, optional.reason, optional.target], ['allowed', null, '4.17.21']);
  assert.deepEqual(verdict(assess(npmRoot({ dependencies: { lodash: '^4.17.0' }, devDependencies: { lodash: '4.17.20' } }))), ['undetermined', 'duplicate_requirement']);
  const peer = npmRoot({ dependencies: { a: '^1.0.0' } }, {
    'node_modules/a': pkg('1.0.0', { dependencies: { lodash: '^4.17.0' }, peerDependencies: { lodash: '4.17.20' } }), 'node_modules/lodash': pkg('4.17.20'),
  });
  assert.deepEqual(verdict(assess(peer)), ['undetermined', 'duplicate_requirement']);
});
