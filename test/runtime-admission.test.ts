import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.ts';
import { defaults, loadConfig } from '../src/config.ts';
import { digest, hash } from '../src/safety.ts';
import { decideRuntimePolicy, parseRuntimePolicy, runtimePolicyCode, type RuntimeRefusal } from '../src/runtime-policy.ts';
import { withTestProcessOwner } from './process-owner.ts';
import { privateWorkspace } from '../src/private-storage.ts';

const launches: string[] = [];
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) { launches.push(name); return Reflect.apply(original, this, args); };
}
syncBuiltinESMExports();

const fixture = await fs.mkdtemp(path.join(tmpdir(), 'runtime-admission-test-'));
test.after(() => removeTempDirStrict(fixture, { recursive: true, force: true }));
const temporary = path.join(fixture, 'tmp'); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;
const target = path.join(fixture, 'target');
await fs.mkdir(target);
const manifest = path.join(fixture, 'repositories.json');
await fs.writeFile(manifest, JSON.stringify({ schema: 1, repositories: [{ id: 'one', path: target }] }));
const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
const tools = { git: node, gitleaks: { ...node, version: '8.30.1' }, osv: node };
const id = '6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b';
const policy = (state: 'active' | 'stopped', deny: unknown[] = []) => ({ schema: 'scanmux.runtime-policy/v1', id, revision: 3, state, deny });
let files = 0;
async function configFile(value: unknown): Promise<string> {
  const file = path.join(fixture, `config-${files++}.json`);
  await fs.writeFile(file, JSON.stringify(value));
  return file;
}
const commands = ['plan', 'scan', 'deps', 'resume', 'doctor', 'plan-list', 'scan-list'] as const;
function argv(command: string, config: string): string[] {
  if (command === 'doctor') return [command, '--config', config];
  if (command === 'resume') return [command, target, '--from', path.join(fixture, 'absent-report.json'), '--config', config];
  return [command, command.endsWith('-list') ? manifest : target, '--config', config];
}
async function invoke(args: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  launches.length = 0;
  process.stdout.write = (chunk: string | Uint8Array) => { output.push(String(chunk)); return true; };
  process.stderr.write = (chunk: string | Uint8Array) => { errors.push(String(chunk)); return true; };
  try { const exitCode = await main(args); return { exitCode, output: output.join(''), error: errors.join(''), launches: [...launches] }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
const errorCode = (text: string) => JSON.parse(text).error;


test('Config1 identity is unchanged for defaults and existing schema 1 files', async () => {
  assert.equal(digest(defaults), 'fa29e80009c28284ec2ec41b0ba6b71f215f2962e32791b521d3daf8c1a69f26');
  assert.equal(Object.hasOwn(defaults, 'runtimePolicy'), false);
  assert.equal(digest(await loadConfig(await configFile({ schema: 1 }))), 'fa29e80009c28284ec2ec41b0ba6b71f215f2962e32791b521d3daf8c1a69f26');
  const pinned = { schema: 1, timeoutMs: 5000, maxOutputBytes: 4096, maxFiles: 10, tools: {
    git: { path: '/opt/scanmux/git.exe', sha256: 'a'.repeat(64), version: '2.50.1' },
    gitleaks: { path: '/opt/scanmux/gitleaks.exe', sha256: 'b'.repeat(64), version: '8.30.1' } } };
  for (const entry of [undefined, { runtimePolicy: 'accept' as const }]) {
    assert.equal(digest(await loadConfig(await configFile(pinned), undefined, entry)), '6c4961e16692abc864271c78ee58fdbae09ee6f15376fe60d5a8c67c67419e27');
  }
});

test('Trivy runtime denial stops doctor, scan and resume before any process, and unsupported entries reject before admission', async () => {
  const config = await configFile(withTestProcessOwner({ schema: 2, runtimePolicy: policy('active', [{ kind: 'component', component: 'trivy' }]),
    tools: { ...tools, trivy: { ...node, version: '0.76.1' } } }));
  for (const command of ['doctor', 'scan', 'resume']) {
    const result = await invoke(argv(command, config));
    assert.equal(result.exitCode, 4); assert.deepEqual(result.launches, []);
    assert.match(errorCode(result.error), /runtime_policy_denied_trivy/);
  }
  for (const command of ['deps', 'plan-list', 'scan-list']) {
    const result = await invoke(argv(command, config));
    assert.equal(errorCode(result.error), 'trivy_entry_unsupported'); assert.deepEqual(result.launches, []);
  }
});

test('schema and runtime policy presence must agree, and schema 2 needs an accepting entry', async () => {
  const valid = policy('active');
  await assert.rejects(loadConfig(await configFile({ schema: 1, runtimePolicy: valid }), undefined, { runtimePolicy: 'accept' }), { code: 'invalid_config' });
  await assert.rejects(loadConfig(await configFile({ schema: 1, runtimePolicy: valid })), { code: 'invalid_config' });
  await assert.rejects(loadConfig(await configFile({ schema: 2 }), undefined, { runtimePolicy: 'accept' }), { code: 'runtime_policy_required' });
  await assert.rejects(loadConfig(await configFile({ schema: 2, runtimePolicy: valid })), { code: 'runtime_policy_entry_unsupported' });
  await assert.rejects(loadConfig(await configFile({ schema: 2 })), { code: 'runtime_policy_entry_unsupported' });
  await assert.rejects(loadConfig(await configFile({ schema: 2, runtimePolicy: { ...valid, revision: 0 } }), undefined, { runtimePolicy: 'accept' }), { code: 'runtime_policy_invalid' });
  await assert.rejects(loadConfig(await configFile({ schema: 2, runtimePolicy: valid, maxFiles: 0 }), undefined, { runtimePolicy: 'accept' }), { code: 'invalid_limit' });
  await assert.rejects(loadConfig(await configFile({ schema: 2, runtimePolicy: valid, extra: true }), undefined, { runtimePolicy: 'accept' }), { code: 'invalid_config' });
  const loaded = await loadConfig(await configFile({ schema: 2, runtimePolicy: valid, tools }), undefined, { runtimePolicy: 'accept' });
  assert.equal(loaded.schema, 2);
  assert.deepEqual(loaded.runtimePolicy, parseRuntimePolicy(valid));
  const { runtimePolicy: _policy, ...fields } = loaded;
  assert.deepEqual({ ...fields, schema: 1 }, await loadConfig(await configFile({ schema: 1, tools })));
});

test('serve rejects Config2 before any process starts', async () => {
  const result = await invoke(['serve', '--config', await configFile({ schema: 2, runtimePolicy: policy('active'), tools })]);
  assert.equal(result.exitCode, 4);
  assert.equal(errorCode(result.error), 'runtime_policy_entry_unsupported');
  assert.deepEqual(result.launches, []);
});

const refusals: { name: string; deny: unknown[]; state: 'active' | 'stopped'; code: string }[] = [
  { name: 'stopped', state: 'stopped', deny: [{ kind: 'component', component: 'gitleaks' }], code: 'runtime_policy_stopped' },
  { name: 'component', state: 'active', deny: [{ kind: 'component', component: 'gitleaks' }], code: 'runtime_policy_denied_gitleaks_component' },
  { name: 'digest', state: 'active', deny: [{ kind: 'digest', component: 'git', sha256: node.sha256 }], code: 'runtime_policy_denied_git_digest' },
];
for (const refusal of refusals) {
  test(`${refusal.name} policy refuses all seven admitted entries with zero process launches`, async () => {
    const raw = policy(refusal.state, refusal.deny);
    const decision = decideRuntimePolicy(parseRuntimePolicy(raw), Object.entries(tools).map(([component, tool]) => ({ component: component as 'git', sha256: tool.sha256 })));
    assert.notEqual(decision.kind, 'continue');
    assert.equal(runtimePolicyCode(decision as RuntimeRefusal), refusal.code);
    const config = await configFile({ schema: 2, runtimePolicy: raw, tools });
    for (const command of commands) {
      const result = await invoke(argv(command, config));
      assert.equal(result.exitCode, command === 'deps' ? 2 : 4, command);
      assert.equal(errorCode(result.error), refusal.code, command);
      assert.deepEqual(result.launches, [], command);
      assert.equal(result.output, '', command);
    }
  });
}

test('a component deny applies only to entries whose closure uses that tool', async () => {
  const config = await configFile(withTestProcessOwner({ schema: 2, runtimePolicy: policy('active', [{ kind: 'component', component: 'osv' }]), tools }));
  const baseline = await configFile(withTestProcessOwner({ schema: 1, tools }));
  await privateWorkspace(); // Both policies start with the same already-protected parent.
  for (const command of ['scan', 'deps', 'resume', 'doctor', 'scan-list']) {
    const result = await invoke(argv(command, config));
    assert.equal(result.exitCode, command === 'deps' ? 2 : 4, command);
    assert.equal(errorCode(result.error), 'runtime_policy_denied_osv_component', command);
    assert.deepEqual(result.launches, [], command);
  }
  for (const command of ['plan', 'plan-list']) {
    const expected = await invoke(argv(command, baseline)), actual = await invoke(argv(command, config));
    assert.ok(expected.launches.length > 0, command);
    assert.deepEqual({ exitCode: actual.exitCode, error: actual.error, launches: actual.launches }, { exitCode: expected.exitCode, error: expected.error, launches: expected.launches }, command);
  }
});

test('an active policy without a matching rule continues to the same Config1 behavior', async () => {
  const deny = [{ kind: 'digest', component: 'git', sha256: 'c'.repeat(64) }, { kind: 'component', component: 'docker' }, { kind: 'digest', component: 'node', sha256: node.sha256 }];
  const config = await configFile(withTestProcessOwner({ schema: 2, runtimePolicy: policy('active', deny), tools }));
  const baseline = await configFile(withTestProcessOwner({ schema: 1, tools }));
  for (const command of commands) {
    const expected = await invoke(argv(command, baseline)), actual = await invoke(argv(command, config));
    assert.doesNotMatch(actual.error, /runtime_policy/, command);
    assert.deepEqual({ exitCode: actual.exitCode, error: actual.error, launches: actual.launches }, { exitCode: expected.exitCode, error: expected.error, launches: expected.launches }, command);
  }
  const probes = { git: node, osv: node };
  const expected = await invoke(['doctor', '--config', await configFile(withTestProcessOwner({ schema: 1, tools: probes }))]);
  const actual = await invoke(['doctor', '--config', await configFile(withTestProcessOwner({ schema: 2, runtimePolicy: policy('active', deny), tools: probes }))]);
  assert.equal(actual.exitCode, 3);
  assert.ok(actual.launches.includes('spawn'));
  assert.deepEqual(JSON.parse(actual.output).tools.slice(0, 3), [{ engine: 'git', state: 'verified' }, { engine: 'gitleaks', state: 'not_configured' }, { engine: 'osv', state: 'verified' }]);
  assert.deepEqual(actual, expected);
});
