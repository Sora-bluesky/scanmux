import test from 'node:test';
import assert from 'node:assert/strict';
import { assessUpgrades, dependencyInputPath, diffDependencies, type DependencyChange, type ProjectDiff } from '../src/dependency-graph.ts';

const bytes = (value: unknown) => value instanceof Uint8Array ? value : new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value, null, 2));
const inputs = (files: Record<string, unknown>) => new Map(Object.entries(files).map(([file, value]) => [file, bytes(value)]));
const only = (base: Record<string, unknown>, head: Record<string, unknown>): ProjectDiff => {
  const { projects } = diffDependencies(inputs(base), inputs(head));
  assert.equal(projects.length, 1);
  return projects[0]!;
};
const byKey = (project: ProjectDiff) => new Map(project.changes.map(change => [change.kind === 'relocated' ? change.to : change.key, change]));
const explanation = (change: DependencyChange | undefined) => {
  assert.ok(change && (change.kind === 'version_changed' || change.kind === 'added'), 'change carries an explanation');
  return change.explanation;
};

const pkg = (version: string, extra: Record<string, unknown> = {}) => ({ version, resolved: `https://registry.npmjs.org/x/-/x-${version}.tgz`, integrity: 'sha512-' + version, ...extra });
function nextAppWithOptionalDependencies(side: 'base' | 'head') {
  const head = side === 'head';
  const next = head ? '15.5.28' : '15.5.12';
  const rootDependencies = { next: head ? '^15.5.28' : '^15.5.12', lodash: '^4.17.0', react: '^19.0.0' };
  const manifest = head
    ? { devDependencies: { typescript: '^5.0.0' }, name: 'app', dependencies: { react: '^19.0.0', next: '^15.5.28', lodash: '^4.17.0' } }
    : { name: 'app', dependencies: rootDependencies, devDependencies: { typescript: '^5.0.0' } };
  const packages: Record<string, unknown> = {
    '': { name: 'app', dependencies: rootDependencies, devDependencies: { typescript: '^5.0.0' } },
    'node_modules/next': pkg(next, {
      dependencies: { 'styled-jsx': '5.1.6' },
      optionalDependencies: { '@next/swc-linux-x64-gnu': next, sharp: head ? '^0.34.3 || ^0.35.5' : '^0.34.3' },
      peerDependencies: { react: '^18.2.0 || ^19.0.0' },
    }),
    'node_modules/@next/swc-linux-x64-gnu': pkg(next, { optional: true }),
    'node_modules/sharp': pkg(head ? '0.35.5' : '0.34.5', {
      optional: true, hasInstallScript: true, dependencies: { semver: head ? '^7.8.5' : '^7.7.3' },
      optionalDependencies: head
        ? { '@img/sharp-wasm32': '0.35.5', '@img/sharp-linux-x64': '0.35.5', '@img/sharp-libvips-linux-x64': '1.3.0' }
        : { '@img/sharp-wasm32': '0.34.5' },
    }),
    'node_modules/semver': pkg(head ? '7.8.5' : '7.7.4', { optional: true }),
    'node_modules/@img/sharp-wasm32': pkg(head ? '0.35.5' : '0.34.5', { optional: true, dependencies: { '@emnapi/runtime': head ? '^1.8.0' : '^1.7.0' } }),
    'node_modules/@emnapi/runtime': pkg(head ? '1.8.0' : '1.7.0', { optional: true }),
    'node_modules/styled-jsx': pkg('5.1.6', { dependencies: { 'client-only': '0.0.1 || 0.0.2' } }),
    'node_modules/client-only': pkg(head ? '0.0.2' : '0.0.1'),
    'node_modules/lodash': pkg(head ? '4.17.21' : '4.17.20'),
    'node_modules/react': pkg('19.0.0'),
    'node_modules/typescript': pkg('5.0.0', head ? { devOptional: true } : { dev: true }),
  };
  if (head) {
    packages['node_modules/@img/sharp-linux-x64'] = pkg('0.35.5', { optional: true, optionalDependencies: { '@img/sharp-libvips-linux-x64': '1.3.0' } });
    packages['node_modules/@img/sharp-libvips-linux-x64'] = pkg('1.3.0', { optional: true });
  }
  return { 'web/package.json': manifest, 'web/package-lock.json': { name: 'app', lockfileVersion: 3, requires: true, packages } };
}

test('dependency inputs are recognized by basename only for safe repository paths', () => {
  for (const file of ['package.json', 'web/package-lock.json', 'a/b/.npmrc', 'pyproject.toml', 'py/servers/member/pyproject.toml', 'py/uv.lock', 'uv.toml']) assert.equal(dependencyInputPath(file), true, file);
  for (const file of ['README.md', 'package.json.bak', '../package.json', '/package.json', 'a\\package.json', 'a//uv.lock']) assert.equal(dependencyInputPath(file), false, file);
});

test('Next.js app with optional dependencies: only next is a changed requirement and every lockfile change is classified', () => {
  const project = only(nextAppWithOptionalDependencies('base'), nextAppWithOptionalDependencies('head'));
  assert.equal(project.lockfile, 'web/package-lock.json');
  assert.deepEqual(project.status, { kind: 'complete' });
  assert.deepEqual(project.requirements.map(item => [item.section, item.name, item.base?.[0]?.spec, item.head?.[0]?.spec]),
    [['dependencies', 'next', '>=15.5.12 <16.0.0', '>=15.5.28 <16.0.0']]);
  const changes = byKey(project);
  const via = (key: string) => {
    const result = explanation(changes.get(key));
    assert.equal(result.state, 'explained', key);
    return result.state === 'explained' ? result.via : [];
  };
  assert.deepEqual(via('node_modules/next'), ['next@15.5.28']);
  assert.deepEqual(via('node_modules/@next/swc-linux-x64-gnu'), ['next@15.5.28', '@next/swc-linux-x64-gnu@15.5.28']);
  assert.deepEqual(via('node_modules/sharp'), ['next@15.5.28', 'sharp@0.35.5']);
  assert.deepEqual(via('node_modules/semver'), ['next@15.5.28', 'sharp@0.35.5', 'semver@7.8.5']);
  assert.deepEqual(via('node_modules/@emnapi/runtime'), ['next@15.5.28', 'sharp@0.35.5', '@img/sharp-wasm32@0.35.5', '@emnapi/runtime@1.8.0']);
  assert.deepEqual(via('node_modules/@img/sharp-libvips-linux-x64'), ['next@15.5.28', 'sharp@0.35.5', '@img/sharp-libvips-linux-x64@1.3.0']);
  assert.deepEqual(via('node_modules/@img/sharp-linux-x64'), ['next@15.5.28', 'sharp@0.35.5', '@img/sharp-linux-x64@0.35.5']);
  assert.equal(changes.get('node_modules/@img/sharp-linux-x64')?.kind, 'added');
  assert.equal(changes.get('node_modules/@img/sharp-libvips-linux-x64')?.kind, 'added');
  assert.deepEqual(changes.get('node_modules/semver'), {
    kind: 'version_changed', key: 'node_modules/semver', name: 'semver', from: '7.7.4', to: '7.8.5',
    explanation: { state: 'explained', via: ['next@15.5.28', 'sharp@0.35.5', 'semver@7.8.5'] },
  });
  assert.deepEqual(explanation(changes.get('node_modules/client-only')), { state: 'unexplained', reason: 'reachable_only_via_unchanged' });
  assert.deepEqual(explanation(changes.get('node_modules/lodash')), { state: 'unexplained', reason: 'not_reachable' });
  assert.deepEqual(changes.get('node_modules/typescript'), { kind: 'metadata_only', key: 'node_modules/typescript', name: 'typescript', version: '5.0.0', fields: ['flags'] });
  assert.equal(changes.has('node_modules/react'), false);
  assert.equal(changes.has('node_modules/styled-jsx'), false);
  assert.equal(changes.has(''), false);
  assert.equal(project.changes.length, 11);
});

test('a manifest that only reorders keys is not a requirement change', () => {
  const base = nextAppWithOptionalDependencies('base');
  const reordered = { ...base, 'web/package.json': { devDependencies: { typescript: '^5.0.0' }, dependencies: { react: '^19.0.0', lodash: '^4.17.0', next: '^15.5.12' }, name: 'app' } };
  const project = only(base, reordered);
  assert.deepEqual(project.requirements, []);
  assert.deepEqual(project.changes, []);
});

test('npm hoisting of the same name@version is relocated, not removed and added', () => {
  const lock = (packages: Record<string, unknown>) => ({ 'package.json': { dependencies: { a: '^1.0.0' } }, 'package-lock.json': { lockfileVersion: 2, packages: { '': { dependencies: { a: '^1.0.0' } }, ...packages } } });
  const project = only(
    lock({ 'node_modules/a': pkg('1.0.0', { dependencies: { b: '^2.0.0' } }), 'node_modules/a/node_modules/b': pkg('2.1.0') }),
    lock({ 'node_modules/a': pkg('1.0.0', { dependencies: { b: '^2.0.0' } }), 'node_modules/b': pkg('2.1.0') }),
  );
  assert.deepEqual(project.changes, [{ kind: 'relocated', from: 'node_modules/a/node_modules/b', to: 'node_modules/b', name: 'b', version: '2.1.0' }]);
});

test('an undetermined manifest or changed overrides makes explanations undetermined instead of guessed', () => {
  const head = nextAppWithOptionalDependencies('head');
  const broken = only(nextAppWithOptionalDependencies('base'), { ...head, 'web/package.json': '{ not json' });
  assert.equal(broken.manifest.head, 'manifest_invalid');
  assert.deepEqual(explanation(byKey(broken).get('node_modules/semver')), { state: 'undetermined', reason: 'manifest_undetermined' });
  const missing = only(nextAppWithOptionalDependencies('base'), { 'web/package-lock.json': head['web/package-lock.json'] });
  assert.equal(missing.manifest.head, 'manifest_missing');
  assert.deepEqual(explanation(byKey(missing).get('node_modules/lodash')), { state: 'undetermined', reason: 'manifest_undetermined' });
  const overrides = only(nextAppWithOptionalDependencies('base'), { ...head, 'web/package.json': { ...head['web/package.json'], overrides: { semver: '7.8.5' } } });
  assert.deepEqual(explanation(byKey(overrides).get('node_modules/semver')), { state: 'undetermined', reason: 'overrides_changed' });
});

test('lockfiles outside the subset or over the limits emit no rows and a closed reason', () => {
  const v1 = only({}, { 'package.json': {}, 'package-lock.json': { lockfileVersion: 1, dependencies: {} } });
  assert.deepEqual([v1.status, v1.changes], [{ kind: 'undetermined', side: 'head', reason: 'lockfile_version_unsupported' }, []]);
  const encoding = diffDependencies(new Map(), new Map([['package-lock.json', new Uint8Array([0xff, 0xfe, 0x00])]])).projects[0]!;
  assert.deepEqual(encoding.status, { kind: 'undetermined', side: 'head', reason: 'lockfile_encoding' });
  const many = (prefix: string, count: number) => Object.fromEntries(Array.from({ length: count }, (_, index) => [`node_modules/${prefix}${index}`, pkg('1.0.0')]));
  const instances = only({}, { 'package.json': {}, 'package-lock.json': { lockfileVersion: 3, packages: many('p', 20_001) } });
  assert.deepEqual(instances.status, { kind: 'undetermined', side: 'head', reason: 'instance_limit' });
  const changes = only({ 'package.json': {}, 'package-lock.json': { lockfileVersion: 3, packages: many('a', 12_000) } }, { 'package.json': {}, 'package-lock.json': { lockfileVersion: 3, packages: many('b', 12_000) } });
  assert.deepEqual([changes.status, changes.changes, changes.requirements], [{ kind: 'change_limit' }, [], []]);
  const uv = only({}, { 'pyproject.toml': '[project]\nname = "x"\n', 'uv.lock': 'version = 2\n' });
  assert.deepEqual(uv.status, { kind: 'undetermined', side: 'head', reason: 'lockfile_version_unsupported' });
  const toml = only({}, { 'pyproject.toml': '[project]\nname = "x"\n', 'uv.lock': 'version = 1\nversion = 1\n' });
  assert.deepEqual(toml.status, { kind: 'undetermined', side: 'head', reason: 'toml_duplicate_key' });
});

test('output carries hashes and validated identifiers only, never raw source text or URLs', () => {
  const project = only(nextAppWithOptionalDependencies('base'), nextAppWithOptionalDependencies('head'));
  const text = JSON.stringify(project);
  assert.equal(text.includes('registry.npmjs.org'), false);
  assert.equal(text.includes('sha512-'), false);
  assert.match(project.inputs.head.lockfileSha256 ?? '', /^[0-9a-f]{64}$/);
  assert.equal(project.inputs.base.manifestSha256 === project.inputs.head.manifestSha256, false);
});

const uvPackage = (name: string, version: string, body: string[] = []) => [
  '[[package]]', `name = "${name}"`, `version = "${version}"`, 'source = { registry = "https://pypi.org/simple" }', ...body,
  `sdist = { url = "https://files.example.invalid/${name}-${version}.tar.gz", hash = "sha256:${'0'.repeat(64)}", size = 1 }`, '',
];
function uvShaped(side: 'base' | 'head') {
  const head = side === 'head';
  const httpx = head ? '0.28' : '0.27';
  const pyproject = ['[project]', 'name = "app"', 'version = "0.1.0"', 'dependencies = [', `    "httpx>=${httpx}",`, '    "rich>=13",', ']', ''].join('\n');
  const lock = [
    'version = 1', 'revision = 3', 'requires-python = ">=3.12"', '',
    '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }',
    'dependencies = [', '    { name = "httpx" },', '    { name = "rich" },', ']', '',
    '[package.metadata]', 'requires-dist = [', `    { name = "httpx", specifier = ">=${httpx}" },`, '    { name = "rich", specifier = ">=13" },', ']', '',
    ...uvPackage('anyio', head ? '4.4.0' : '4.0.0'),
    ...uvPackage('colorama', '0.4.6'),
    ...uvPackage('httpx', head ? '0.28.1' : '0.27.0', ['dependencies = [', '    { name = "anyio" },',
      ...(head
        ? ['    { name = "numpy", version = "1.26.4", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < \'3.13\'" },',
          '    { name = "numpy", version = "2.1.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= \'3.13\'" },']
        : ['    { name = "numpy" },']),
      ']']),
    ...uvPackage('numpy', '1.26.4', head ? ['resolution-markers = ["python_full_version < \'3.13\'"]'] : []),
    ...(head ? uvPackage('numpy', '2.1.0', ['resolution-markers = ["python_full_version >= \'3.13\'"]']) : []),
    ...uvPackage('rich', '13.0.0', ['dependencies = [', `    { name = "colorama", marker = "sys_platform ${head ? '!=' : '=='} 'win32'" },`, ']']),
  ].join('\n');
  return { 'py/pyproject.toml': pyproject, 'py/uv.lock': lock };
}

test('uv diff: a direct constraint change explains the transitive version change; markers only are flags; one name with several versions is keyed by version', () => {
  const project = only(uvShaped('base'), uvShaped('head'));
  assert.equal(project.ecosystem, 'uv');
  assert.deepEqual(project.status, { kind: 'complete' });
  assert.deepEqual(project.requirements.map(item => [item.section, item.name, item.base?.[0]?.spec, item.head?.[0]?.spec]),
    [['project.dependencies', 'httpx', '>=0.27', '>=0.28']]);
  const changes = byKey(project);
  assert.deepEqual(explanation(changes.get('httpx')), { state: 'explained', via: ['httpx@0.28.1'] });
  assert.deepEqual(explanation(changes.get('anyio')), { state: 'explained', via: ['httpx@0.28.1', 'anyio@4.4.0'] });
  assert.deepEqual(changes.get('numpy@1.26.4'), { kind: 'relocated', from: 'numpy', to: 'numpy@1.26.4', name: 'numpy', version: '1.26.4' });
  assert.equal(changes.get('numpy@2.1.0')?.kind, 'added');
  assert.deepEqual(explanation(changes.get('numpy@2.1.0')), { state: 'explained', via: ['httpx@0.28.1', 'numpy@2.1.0'] });
  assert.deepEqual(changes.get('rich'), { kind: 'metadata_only', key: 'rich', name: 'rich', version: '13.0.0', fields: ['flags'] });
  assert.equal(changes.has('colorama'), false);
  assert.equal(changes.has('app'), false);
  assert.equal(project.changes.length, 5);
  assert.equal(JSON.stringify(project).includes('pypi.org'), false);
});

test('uv root-only workspaces are accepted and post releases remain outside the subset', () => {
  const head = uvShaped('head');
  const workspace = only(uvShaped('base'), { ...head, 'py/pyproject.toml': head['py/pyproject.toml'] + '[tool.uv.workspace]\nmembers = ["libs/*"]\n' });
  assert.equal(workspace.manifest.head, null);
  assert.deepEqual(explanation(byKey(workspace).get('anyio')), { state: 'explained', via: ['httpx@0.28.1', 'anyio@4.4.0'] });
  const sources = '[tool.uv.sources]\nhttpx = { index = "private-index-value" }\n';
  const sourced = only({ ...uvShaped('base'), 'py/pyproject.toml': uvShaped('base')['py/pyproject.toml'] + sources },
    { ...head, 'py/pyproject.toml': head['py/pyproject.toml'] + sources + '[tool.uv.workspace]\nmembers = []\n' });
  assert.equal(explanation(byKey(sourced).get('anyio')).state, 'explained');
  const post = only({}, { ...head, 'py/uv.lock': head['py/uv.lock'] + '\n' + uvPackage('python-dateutil', '2.9.0.post0').join('\n') });
  assert.deepEqual(post.graph.head?.outside, [{ key: 'python-dateutil', field: 'version', dependency: null, reason: 'post_release_outside_subset' }]);
  assert.deepEqual(post.graph.head?.outsideByReason, [{ field: 'version', reason: 'post_release_outside_subset', count: 1 }]);
});

function uvWorkspace(version = '1.0', spec = '>=1', virtual = false): Record<string, string> {
  return {
    'py/pyproject.toml': (virtual ? '[dependency-groups]\ndev = ["example>=1"]\n' : '[project]\nname = "root-name"\ndependencies = []\n')
      + '[tool.uv.workspace]\nmembers = ["servers/*"]\n',
    'py/servers/member/pyproject.toml': `[project]\nname = "Member_Name"\ndependencies = ["root-name", "example${spec}"]\n[tool.uv.sources]\nroot-name = { workspace = true }\n`,
    'py/uv.lock': ['version = 1', '[manifest]', 'members = ["root-name", "member-name"]', '',
      '[[package]]', 'name = "root-name"', 'source = { ' + (virtual ? 'virtual' : 'editable') + ' = "." }',
      ...(virtual ? ['[package.dev-dependencies]', 'dev = [{ name = "example" }]', '[package.metadata.requires-dev]', 'dev = [{ name = "example", specifier = ">=1" }]'] : []),
      '', '[[package]]', 'name = "member-name"', 'source = { editable = "servers/member" }',
      'dependencies = [{ name = "root-name" }, { name = "example" }]', '[package.metadata]',
      `requires-dist = [{ name = "root-name", editable = "." }, { name = "example", specifier = "${spec}" }]`, '',
      ...uvPackage('example', version),
    ].join('\n'),
  };
}
const workspaceAssessment = (files: Record<string, unknown>) => assessUpgrades(inputs(files), [{
  lockfile: 'py/uv.lock', name: 'example', version: '1.1', advisories: ['GHSA-test'], fixedVersions: ['1.2'], fixEvents: 'complete',
}]);

test('uv workspace members share comparison and upgrade analysis with path-labelled requirements', () => {
  const base = uvWorkspace(), head = uvWorkspace('1.1', '>=1.1'), project = only(base, head);
  assert.deepEqual(project.status, { kind: 'complete' }); assert.deepEqual(project.manifest, { base: null, head: null });
  assert.deepEqual(project.requirements.map(item => [item.section, item.name]), [['servers/member:project.dependencies', 'example']]);
  assert.deepEqual(explanation(byKey(project).get('example')), { state: 'explained', via: ['example@1.1'] });
  const assessed = workspaceAssessment(head);
  assert.equal(assessed.projects[0]?.status, 'complete'); assert.equal(assessed.upgrades[0]?.state, 'allowed');
  for (const [left, right] of [[{}, head], [head, {}], [uvShaped('base'), head]]) {
    const diff = only(left!, right!); assert.deepEqual(diff.manifest, { base: null, head: null });
  }
});

test('uv explanations can pass through a workspace package whose version changed', () => {
  const side = (head: boolean) => {
    const files = uvWorkspace(head ? '1.1' : '1.0'), version = head ? '0.2' : '0.1';
    files['py/pyproject.toml'] = files['py/pyproject.toml']!.replace('dependencies = []', 'dependencies = ["example>=1"]');
    files['py/servers/member/pyproject.toml'] = files['py/servers/member/pyproject.toml']!.replace('"root-name", "example>=1"', `"root-name>=${version}"`);
    files['py/uv.lock'] = files['py/uv.lock']!.replace('source = { editable = "." }', `version = "${version}"\nsource = { editable = "." }\ndependencies = [{ name = "example" }]\n[package.metadata]\nrequires-dist = [{ name = "example", specifier = ">=1" }]`)
      .replace('dependencies = [{ name = "root-name" }, { name = "example" }]', 'dependencies = [{ name = "root-name" }]')
      .replace('requires-dist = [{ name = "root-name", editable = "." }, { name = "example", specifier = ">=1" }]', `requires-dist = [{ name = "root-name", specifier = ">=${version}", editable = "." }]`);
    return files;
  };
  const project = only(side(false), side(true));
  assert.equal(project.manifest.head, null);
  assert.deepEqual(explanation(byKey(project).get('example')), { state: 'explained', via: ['root-name@0.2', 'example@1.1'] });
  const unchangedRoot = side(true);
  unchangedRoot['py/uv.lock'] = unchangedRoot['py/uv.lock']!.replace('version = "0.2"', 'version = "0.1"').replace('specifier = ">=0.2"', 'specifier = ">=0.0"');
  unchangedRoot['py/servers/member/pyproject.toml'] = unchangedRoot['py/servers/member/pyproject.toml']!.replace('root-name>=0.2', 'root-name>=0.0');
  assert.deepEqual(explanation(byKey(only(side(false), unchangedRoot)).get('example')), { state: 'unexplained', reason: 'reachable_only_via_unchanged' });
});

test('uv workspace completeness refuses each unsupported membership boundary', () => {
  const original = uvWorkspace('1.1'), root = 'py/pyproject.toml', member = 'py/servers/member/pyproject.toml', lock = 'py/uv.lock';
  const cases: Record<string, Record<string, string>> = {
    missing: Object.fromEntries(Object.entries(original).filter(([file]) => file !== member)),
    missingRoot: Object.fromEntries(Object.entries(original).filter(([file]) => file !== root)),
    name: { ...original, [member]: original[member]!.replace('Member_Name', 'other') },
    manifest: { ...original, [lock]: original[lock]!.replace('["root-name", "member-name"]', '["root-name"]') },
    extraManifestMember: { ...original, [lock]: original[lock]!.replace('["root-name", "member-name"]', '["root-name", "member-name", "other"]') },
    absentManifest: { ...original, [lock]: original[lock]!.replace('[manifest]\nmembers = ["root-name", "member-name"]\n', '') },
    stale: { ...original, 'py/servers/stale/pyproject.toml': '[project]\nname = "stale"\n' },
    nested: { ...original, [member]: original[member]! + '[tool.uv.workspace]\nmembers = []\n' },
    excluded: { ...original, [root]: original[root]! + 'exclude = ["servers/member"]\n' },
    duplicatePath: { ...original, [lock]: original[lock]!.replace('editable = "servers/member"', 'editable = "."') },
    duplicateName: { ...original, [lock]: original[lock]!.replace('name = "member-name"\nsource', 'name = "root-name"\nversion = "0.1"\nsource') },
    invalidMembers: { ...original, [root]: original[root]!.replace('["servers/*"]', '42') },
    invalidExclude: { ...original, [root]: original[root]! + 'exclude = 42\n' },
    invalidWorkspace: { ...original, [root]: original[root]!.replace('[tool.uv.workspace]\nmembers = ["servers/*"]', '[tool.uv]\nworkspace = false') },
    invalidLockMembers: { ...original, [lock]: original[lock]!.replace('["root-name", "member-name"]', '42') },
    duplicateLockMember: { ...original, [lock]: original[lock]!.replace('["root-name", "member-name"]', '["root-name", "root-name"]') },
  };
  for (const value of ['../member', '/member', 'C:/member', 'servers\\member', 'servers/../member', 'servers//member']) {
    cases['path:' + value] = { ...original, [lock]: original[lock]!.replace('editable = "servers/member"', 'editable = ' + JSON.stringify(value)) };
  }
  for (const key of ['members', 'exclude']) for (const value of ['servers/**', 'servers/*/nested', 'servers/mem?er', '../servers', 'servers/[ab]']) {
    cases[key + ':' + value] = { ...original, [root]: original[root]!.replace('members = ["servers/*"]', `${key} = [${JSON.stringify(value)}]`) };
  }
  for (const [label, files] of Object.entries(cases)) {
    assert.equal(only({}, files).manifest.head, 'workspaces_outside_subset', label);
    assert.equal(workspaceAssessment(files).projects[0]?.reason, 'workspaces_outside_subset', label);
  }
});

test('uv workspace patterns select literals or immediate children and respect exclusions', () => {
  const files = uvWorkspace('1.1');
  files['py/pyproject.toml'] = files['py/pyproject.toml']!.replace('"servers/*"', '"servers/member"') + 'exclude = ["servers/excluded/*", "servers/stale"]\n';
  files['py/servers/stale/pyproject.toml'] = '[project]\nname = "stale"\n';
  files['py/servers/member/nested/pyproject.toml'] = '[project]\nname = "nested"\n';
  assert.equal(workspaceAssessment(files).projects[0]?.status, 'complete');
  files['py/pyproject.toml'] = files['py/pyproject.toml']!.replace('"servers/member"', '"servers/*"');
  assert.equal(workspaceAssessment(files).projects[0]?.status, 'complete');
});

test('uv virtual workspace roots contribute groups and member failures keep their own reason', () => {
  const files = uvWorkspace('1.1', '>=1', true);
  assert.equal(workspaceAssessment(files).projects[0]?.status, 'complete');
  assert.equal(workspaceAssessment(files).upgrades[0]?.state, 'allowed');
  const member = 'py/servers/member/pyproject.toml';
  for (const [text, reason] of [['[project]\nname = "member-name"\ndynamic = ["dependencies"]\n', 'dynamic_dependencies_outside_subset'],
    ['[project]\nname = "member-name"\ndependencies = 42\n', 'requirement_outside_subset'], ['invalid', 'toml_outside_subset']]) {
    const broken = { ...files, [member]: text! };
    assert.equal(only({}, broken).manifest.head, reason); assert.equal(workspaceAssessment(broken).projects[0]?.reason, reason);
  }
  assert.equal(only({}, { 'py/pyproject.toml': '[dependency-groups]\ndev = []\n', 'py/uv.lock': files['py/uv.lock']! }).manifest.head, 'manifest_invalid');
});

test('uv virtual roots without a lock package use the manifest dependency groups', () => {
  const files = uvWorkspace('1.1', '>=1', true), lock = 'py/uv.lock', member = 'py/servers/member/pyproject.toml';
  files[lock] = files[lock]!.replace('members = ["root-name", "member-name"]', 'members = ["member-name"]\n[manifest.dependency-groups]\ndev = [{ name = "example", specifier = ">=1" }]')
    .replace(/\[\[package\]\]\nname = "root-name"[\s\S]*?(?=\[\[package\]\])/, '')
    .replace('{ name = "root-name" }, ', '').replace('{ name = "root-name", editable = "." }, ', '');
  files[member] = '[project]\nname = "member-name"\ndependencies = ["example>=1"]\n';
  assert.equal(workspaceAssessment(files).projects[0]?.status, 'complete');
  assert.equal(workspaceAssessment(files).upgrades[0]?.state, 'allowed');
  files['py/pyproject.toml'] = files['py/pyproject.toml']!.replace('example>=1', 'example>=1.1');
  assert.equal(workspaceAssessment(files).upgrades[0]?.reason, 'manifest_lock_mismatch');
});

test('uv workspace resolution settings come only from the root and sources cover every member', () => {
  const base = uvWorkspace(), head = uvWorkspace('1.1', '>=1.1'), member = 'py/servers/member/pyproject.toml';
  head[member] += '[tool.uv]\noverride-dependencies = ["example==1.1"]\nconstraint-dependencies = ["example<2"]\nexclude-newer = "2020-01-01"\n';
  assert.equal(workspaceAssessment(head).upgrades[0]?.state, 'allowed');
  assert.equal(explanation(byKey(only(base, head)).get('example')).state, 'explained');
  const sources = { ...head, [member]: head[member]!.replace('root-name = { workspace = true }', 'root-name = { path = "private-source-value" }') };
  assert.deepEqual(explanation(byKey(only(base, sources)).get('example')), { state: 'undetermined', reason: 'overrides_changed' });
  assert.equal(JSON.stringify(only(base, sources)).includes('private-source-value'), false);
  const overridden = { ...head, 'py/pyproject.toml': '[tool.uv]\noverride-dependencies = ["example==1.1"]\n' + head['py/pyproject.toml']! };
  assert.equal(workspaceAssessment(overridden).upgrades[0]?.reason, 'overrides_declared');
});

test('uv member groups stay distinct even when two members declare the same package', () => {
  const base = uvWorkspace('1.1'), member = 'py/servers/member/pyproject.toml';
  base['py/pyproject.toml'] = base['py/pyproject.toml']!.replace('dependencies = []', 'dependencies = ["example>=1"]');
  base['py/uv.lock'] = base['py/uv.lock']!.replace('source = { editable = "." }', 'source = { editable = "." }\ndependencies = [{ name = "example" }]\n[package.metadata]\nrequires-dist = [{ name = "example", specifier = ">=1" }]');
  const head = { ...base, 'py/pyproject.toml': base['py/pyproject.toml']!.replace('example>=1', 'example>=1.1'),
    [member]: base[member]!.replace('example>=1', 'example>=1.2') };
  assert.deepEqual(only(base, head).requirements.map(item => item.section), ['project.dependencies', 'servers/member:project.dependencies']);
  assert.equal(workspaceAssessment(head).upgrades[0]?.reason, 'manifest_lock_mismatch');
});

test('uv member-only changes affect the manifest digest, declarations and lock agreement', () => {
  const base = uvWorkspace('1.1'), member = 'py/servers/member/pyproject.toml';
  const head = { ...base, [member]: base[member]!.replace('example>=1', 'example>=1.1') }, diff = only(base, head);
  assert.notEqual(diff.inputs.base.manifestSha256, diff.inputs.head.manifestSha256);
  assert.deepEqual(diff.requirements.map(item => [item.section, item.name]), [['servers/member:project.dependencies', 'example']]);
  assert.equal(workspaceAssessment(head).upgrades[0]?.reason, 'manifest_lock_mismatch');
  const comment = only(base, { ...base, [member]: base[member]! + '# change\n' });
  assert.notEqual(comment.inputs.base.manifestSha256, comment.inputs.head.manifestSha256);
  const unsupported = { ...base, 'py/pyproject.toml': base['py/pyproject.toml']!.replace('servers/*', 'servers/**') };
  const outside = only(unsupported, { ...unsupported, [member]: base[member]! + '# change\n' });
  assert.equal(outside.manifest.head, 'workspaces_outside_subset');
  assert.notEqual(outside.inputs.base.manifestSha256, outside.inputs.head.manifestSha256);
});

test('uv keys of a name with several versions use the validated version or a hash, never the raw version text', () => {
  const pyproject = '[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["foo"]\n';
  const lock = (second: string) => ['version = 1', '', '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }',
    'dependencies = [{ name = "foo", version = "1.0.0" }]', '', '[package.metadata]', 'requires-dist = [{ name = "foo" }]', '',
    ...uvPackage('foo', '1.0.0'), ...uvPackage('foo', second)].join('\n');
  for (const raw of ['PRIVATE DOCUMENT CONTENT', 'PRIVATE_DOCUMENT_CONTENT']) {
    const project = only({ 'pyproject.toml': pyproject, 'uv.lock': lock('0.9.0') }, { 'pyproject.toml': pyproject, 'uv.lock': lock(raw) });
    assert.equal(JSON.stringify(project).includes('PRIVATE'), false, raw);
    const added = project.changes.find(change => change.kind === 'added');
    assert.match(added?.kind === 'added' ? added.key : '', /^foo@sha256:[0-9a-f]{64}$/, raw);
    assert.equal(added?.kind === 'added' ? added.version : 'missing', null, raw);
    assert.deepEqual(project.graph.head?.outside.map(item => item.key), [added?.kind === 'added' ? added.key : ''], raw);
  }
  const single = (version: string) => ({ 'pyproject.toml': pyproject, 'uv.lock': ['version = 1', '', '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }',
    'dependencies = [{ name = "foo" }]', '', '[package.metadata]', 'requires-dist = [{ name = "foo" }]', '', ...uvPackage('foo', version)].join('\n') });
  const renamed = only(single('PRIVATE_A'), single('PRIVATE_B'));
  assert.equal(JSON.stringify(renamed).includes('PRIVATE'), false);
  assert.deepEqual(renamed.changes.map(change => [change.kind, change.kind === 'version_changed' ? [change.from, change.to] : null]), [['version_changed', [null, null]]]);
});

test('an unreadable uv.toml on either side makes explanations settings_unreadable, never unchanged', () => {
  const base = uvShaped('base'), head = uvShaped('head');
  for (const unreadable of [new Uint8Array([0xff]), 'override-dependencies = [\n']) {
    for (const [left, right] of [[unreadable, unreadable], [unreadable, undefined], [undefined, unreadable]]) {
      const files = (side: Record<string, unknown>, settings: unknown) => settings === undefined ? side : { ...side, 'py/uv.toml': settings };
      assert.deepEqual(explanation(byKey(only(files(base, left), files(head, right))).get('anyio')), { state: 'undetermined', reason: 'settings_unreadable' });
    }
  }
});

test('only edges of the changed requirement group start an explanation', () => {
  const pyproject = (dev: string) => ['[project]', 'name = "app"', 'version = "0.1.0"', 'dependencies = ["foo>=1,<2"]', '', '[dependency-groups]', `dev = ["foo${dev}"]`, ''].join('\n');
  const side = (main: string, dev: string) => ({ 'pyproject.toml': pyproject(dev), 'uv.lock': ['version = 1', '', '[[package]]', 'name = "app"', 'version = "0.1.0"', 'source = { editable = "." }',
    `dependencies = [{ name = "foo", version = "${main}" }]`, '', '[package.dev-dependencies]', 'dev = [{ name = "foo", version = "2.0.0" }]', '',
    '[package.metadata]', 'requires-dist = [{ name = "foo", specifier = ">=1,<2" }]', '', '[package.metadata.requires-dev]', `dev = [{ name = "foo", specifier = "${dev}" }]`, '',
    ...uvPackage('foo', main), ...uvPackage('foo', '2.0.0')].join('\n') });
  const project = only(side('1.0.0', '>=2,<3'), side('1.1.0', '>=2,<4'));
  assert.deepEqual(project.requirements.map(item => [item.section, item.name]), [['dependency-groups.dev', 'foo']]);
  assert.deepEqual(explanation(byKey(project).get('foo@1.1.0')), { state: 'unexplained', reason: 'not_reachable' });
});

test('a path through a direct dependency whose version did not change is not an explanation', () => {
  const side = (range: string, b: string) => ({ 'package.json': { dependencies: { a: range } }, 'package-lock.json': { lockfileVersion: 3, packages: {
    '': { dependencies: { a: range } }, 'node_modules/a': pkg('1.0.0', { dependencies: { b: '>=1.0.0' } }), 'node_modules/b': pkg(b) } } });
  const project = only(side('~1.0.0', '1.0.0'), side('>=1.0.0 <2.0.0', '2.0.0'));
  assert.deepEqual(project.requirements.map(item => item.name), ['a']);
  assert.deepEqual(explanation(byKey(project).get('node_modules/b')), { state: 'unexplained', reason: 'reachable_only_via_unchanged' });
});

test('changed uv.toml, pyproject or uv.lock constraints and sources make explanations overrides_changed', () => {
  const base = uvShaped('base'), head = uvShaped('head');
  const lockManifest = '\n[manifest]\nconstraints = [{ name = "anyio", specifier = "<5" }]\n';
  const cases: [Record<string, unknown>, Record<string, unknown>][] = [
    [{ ...base, 'py/uv.toml': 'override-dependencies = ["anyio==4.0.0"]\n' }, { ...head, 'py/uv.toml': 'override-dependencies = ["anyio==4.4.0"]\n' }],
    [base, { ...head, 'py/pyproject.toml': head['py/pyproject.toml'] + '[tool.uv]\nconstraint-dependencies = ["anyio<5"]\n' }],
    [base, { ...head, 'py/pyproject.toml': head['py/pyproject.toml'] + '[tool.uv.sources]\nanyio = { index = "internal" }\n' }],
    [base, { ...head, 'py/uv.lock': head['py/uv.lock'].replace('requires-python = ">=3.12"\n', 'requires-python = ">=3.12"\n' + lockManifest) }],
  ];
  for (const [left, right] of cases) assert.deepEqual(explanation(byKey(only(left, right)).get('anyio')), { state: 'undetermined', reason: 'overrides_changed' });
  assert.deepEqual(explanation(byKey(only({ ...base, 'py/uv.toml': 'native-tls = true\n' }, { ...head, 'py/uv.toml': 'native-tls = true\n' })).get('anyio')),
    { state: 'explained', via: ['httpx@0.28.1', 'anyio@4.4.0'] });
});

test('tool.uv.dev-dependencies is a requirement section', () => {
  const head = uvShaped('head');
  const project = only(uvShaped('base'), { ...head, 'py/pyproject.toml': head['py/pyproject.toml'] + '[tool.uv]\ndev-dependencies = ["pytest>=8"]\n' });
  assert.deepEqual(project.requirements.map(item => [item.section, item.name, item.head?.[0]?.spec]),
    [['project.dependencies', 'httpx', '>=0.28'], ['tool.uv.dev-dependencies', 'pytest', '>=8']]);
});
