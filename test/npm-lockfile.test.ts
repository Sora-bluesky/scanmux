import test from 'node:test';
import assert from 'node:assert/strict';
import { matchingNpmPackages, npmLockfilePackages } from '../src/npm-lockfile.ts';

test('npm v2 and v3 local declarations preserve scoped names and do not exempt workspace registry dependencies', () => {
  for (const lockfileVersion of [2, 3]) {
    const packages = npmLockfilePackages(Buffer.from(JSON.stringify({ lockfileVersion, packages: {
      '': { workspaces: ['packages/**'] },
      'node_modules/@example/local': { link: true, resolved: 'packages/local' }, 'packages/local': { version: '1.0.0' },
      'packages/other': { name: 'other' },
      'packages/local/node_modules/registry': { version: '2.0.0', devOptional: true },
      'node_modules/regular': { version: '1.0.0' },
      'node_modules/dev-only': { version: '1.0.0', dev: true },
    } })));
    assert.ok(matchingNpmPackages(packages, '@example/local', null).every(pkg => pkg.local));
    assert.equal(matchingNpmPackages(packages, '@example/local', '1.0.0').length, 2);
    assert.deepEqual(matchingNpmPackages(packages, 'other', null).map(pkg => [pkg.version, pkg.local]), [[null, true]]);
    assert.deepEqual(matchingNpmPackages(packages, 'registry', '2.0.0').map(pkg => [pkg.local, pkg.dev]), [[false, true]]);
    assert.equal(matchingNpmPackages(packages, 'regular', '1.0.0')[0]!.dev, false);
    assert.equal(matchingNpmPackages(packages, 'dev-only', '1.0.0')[0]!.dev, true);
  }
});

test('local evidence cannot exempt a versionless registry instance with the same name', () => {
  const packages = npmLockfilePackages(Buffer.from(JSON.stringify({ lockfileVersion: 3, packages: {
    '': { workspaces: { packages: ['packages/*'] } },
    'packages/shared': { name: 'shared', version: '1.0.0' }, 'node_modules/shared': { version: '2.0.0' },
  } })));
  assert.equal(matchingNpmPackages(packages, 'shared', null).every(pkg => pkg.local), false);
  assert.deepEqual(matchingNpmPackages(packages, 'shared', '2.0.0').map(pkg => pkg.local), [false]);
});

test('excluded workspace paths are not proof of local packages', () => {
  const packages = npmLockfilePackages(Buffer.from(JSON.stringify({ lockfileVersion: 3, packages: {
    '': { workspaces: ['packages/*', '!packages/external'] }, 'packages/local': { name: 'local' }, 'packages/external': { name: 'external' },
  } })));
  assert.equal(matchingNpmPackages(packages, 'local', null)[0]!.local, true);
  assert.equal(matchingNpmPackages(packages, 'external', null)[0]!.local, false);
});

test('npm v1 development flags remain available without inferring local packages', () => {
  const packages = npmLockfilePackages(Buffer.from(JSON.stringify({ lockfileVersion: 1, dependencies: {
    regular: { version: '1.0.0', dependencies: { child: { version: '2.0.0', devOptional: true } } },
  } })));
  assert.deepEqual(packages, [{ name: 'regular', version: '1.0.0', local: false, dev: false }, { name: 'child', version: '2.0.0', local: false, dev: true }]);
});

test('invalid UTF-8, JSON and npm v2/v3 package maps cannot be treated as an empty successful scan', () => {
  for (const value of [Buffer.from([255]), Buffer.from('{'), Buffer.from('{"lockfileVersion":3,"packages":[]}'), Buffer.from('{"lockfileVersion":2,"packages":{"node_modules/example":null}}')]) {
    assert.throws(() => npmLockfilePackages(value), /lockfile_invalid/);
  }
});
