import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fsSync from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.ts';
import { aiRuntime } from '../src/ai-plan.ts';
import { hash } from '../src/safety.ts';
import { parseRuntimePolicy, runtimePolicyRef } from '../src/runtime-policy.ts';
import { withTestProcessOwner } from './process-owner.ts';
import { protectDirectory } from '../src/private-storage.ts';

const launches: string[] = [];
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) { launches.push(name); return Reflect.apply(original, this, args); };
}
const opened: string[] = [];
const promises = fs as unknown as Record<string, (...args: unknown[]) => unknown>;
for (const name of ['open', 'readFile', 'readdir', 'opendir', 'access'] as const) {
  const original = promises[name];
  promises[name] = function (this: unknown, ...args: unknown[]) { if (typeof args[0] === 'string') opened.push(path.resolve(args[0])); return Reflect.apply(original, this, args); };
}
const sync = fsSync as unknown as Record<string, (...args: unknown[]) => unknown>;
for (const name of ['openSync', 'readFileSync', 'readdirSync', 'createReadStream'] as const) {
  const original = sync[name];
  sync[name] = function (this: unknown, ...args: unknown[]) { if (typeof args[0] === 'string') opened.push(path.resolve(args[0])); return Reflect.apply(original, this, args); };
}
syncBuiltinESMExports();

const fixture = await fs.mkdtemp(path.join(tmpdir(), 'runtime-admission-ai-test-'));
test.after(() => removeTempDirStrict(fixture, { recursive: true, force: true }));
const temporary = path.join(fixture, 'tmp'); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;
const workspaceParent = path.join(temporary, 'scanmux-private');
await fs.mkdir(workspaceParent, { mode: 0o700 }); await protectDirectory(workspaceParent);
const target = path.join(fixture, 'target'), assets = path.join(fixture, 'assets'), store = path.join(fixture, 'store'), authHome = path.join(fixture, 'auth');
for (const directory of [target, assets, store, authHome]) await fs.mkdir(directory);
await fs.writeFile(path.join(store, 'credentials.json'), '{}');
const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
const tools = { git: node, gitleaks: { ...node, version: '8.30.1' }, osv: node };
async function fakeTool(name: string, version: string) {
  const file = path.join(fixture, `${name}.exe`), bytes = Buffer.from(`synthetic ${name}`);
  await fs.writeFile(file, bytes);
  return { path: file, sha256: hash(bytes), version };
}
const runner = { codex: await fakeTool('codex', '0.0.1'), linuxCodex: await fakeTool('linux-codex', '0.0.1'), docker: await fakeTool('docker', '1.0.0'),
  image: 'sha256:' + '7'.repeat(64), authHome, disabledMcpServers: [], disabledPlugins: [] };
const ai = { assetsRoot: assets, credentialStore: store, reasoningEffort: 'high', commandTimeoutMs: 10000, cleanupTimeoutMs: 10000,
  workerResources: { cpuCount: 1, memoryBytes: 256 * 1024 * 1024, tmpBytes: 32 * 1024 * 1024, workBytes: 16 * 1024 * 1024, shmBytes: 4 * 1024 * 1024 },
  limits: { maxRequests: 5, maxTotalOutputTokens: 20, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 1024, maxResponseBytesPerRequest: 1024, maxToolCalls: 3, maxToolResultBytes: 1024, timeoutMs: 30000 },
  ipc: { maxFrameBytes: 1024, maxBytes: 8192, maxFrames: 20 } };
const id = '0b6d2f4e-8a1c-4d3e-9f5a-7c2b1e0d9a8f';
const policy = (state: 'active' | 'stopped', deny: unknown[] = []) => ({ schema: 'scanmux.runtime-policy/v1', id, revision: 7, state, deny });
const report = path.join(fixture, 'report.json');
const canonicalTarget = await fs.realpath(target);
await fs.writeFile(report, JSON.stringify({ schema: 'scanmux.report/v2', runId: '11111111-2222-3333-4444-555555555555', startedAt: '2026-10-22T00:00:00Z', endedAt: '2026-10-22T00:00:01.000Z',
  gate: 'PASS', executionState: 'completed', coverageState: 'complete', integrityErrors: [],
  plan: { schema: 'scanmux.plan/v2', root: canonicalTarget, repoId: hash(canonicalTarget), commit: 'a'.repeat(40), policyHash: 'b'.repeat(64), planHash: 'c'.repeat(64), snapshotHash: 'd'.repeat(64),
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], blockers: [], exclusions: [] },
  engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: 'completed', coverage: 'analyzed',
    usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' } })) }));
let files = 0;
async function configFile(value: object): Promise<string> {
  const file = path.join(fixture, `config-${files++}.json`);
  await fs.writeFile(file, JSON.stringify(withTestProcessOwner(value)));
  return file;
}
const unexpected = { openWorker() { throw new Error('unexpected_worker'); }, createSocket() { throw new Error('unexpected_socket'); } };
async function invoke(args: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  launches.length = 0; opened.length = 0;
  process.stdout.write = (chunk: string | Uint8Array) => { output.push(String(chunk)); return true; };
  process.stderr.write = (chunk: string | Uint8Array) => { errors.push(String(chunk)); return true; };
  try { const exitCode = await main(args, { ai: unexpected }); return { exitCode, output: output.join(''), error: errors.join(''), launches: [...launches], opened: [...opened] }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
const inside = (files: string[], directories: string[]) => files.filter(file => directories.some(directory => file === directory || file.startsWith(directory + path.sep)));
const ref = (raw: unknown) => { const value = runtimePolicyRef(parseRuntimePolicy(raw)); return { id: value.id, revision: value.revision, state: value.state, sha256: value.sha256 }; };
const comparable = (result: Awaited<ReturnType<typeof invoke>>) => ({ exitCode: result.exitCode, error: result.error, launches: result.launches });


const aiEntries = [['ai-plan', target], ['ai-scan', target, '--accept-plan', '0'.repeat(64)]];
const aiRefusals: [unknown, string][] = [
  [policy('stopped'), 'runtime_policy_stopped'],
  [policy('active', [{ kind: 'digest', component: 'codex-security-sdk', sha256: aiRuntime.assetManifestSha256 }]), 'runtime_policy_denied_codex_security_sdk_digest'],
  [policy('active', [{ kind: 'digest', component: 'linux-image', sha256: aiRuntime.imageDigest.slice('sha256:'.length) }]), 'runtime_policy_denied_linux_image_digest'],
  [policy('active', [{ kind: 'digest', component: 'docker', sha256: 'f'.repeat(64) }]), 'runtime_policy_unidentified_docker'],
  [policy('active', [{ kind: 'digest', component: 'git', sha256: 'f'.repeat(64) }]), 'runtime_policy_unidentified_git'],
  [policy('active', [{ kind: 'component', component: 'node' }]), 'runtime_policy_denied_node_component'],
  [policy('active', [{ kind: 'digest', component: 'node', sha256: 'f'.repeat(64) }]), 'runtime_policy_unidentified_node'],
];
test('AI entries refuse stopped, AI digest and unidentified docker, git and node policies before any process or credential read', async () => {
  for (const [raw, code] of aiRefusals) {
    const config = await configFile({ schema: 2, runtimePolicy: raw, tools, ai });
    for (const args of aiEntries) {
      const result = await invoke([...args, '--config', config]);
      assert.equal(result.exitCode, 4, `${args[0]} ${code}`);
      assert.deepEqual(JSON.parse(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: code, policy: ref(raw) }, `${args[0]} ${code}`);
      assert.deepEqual(result.launches, [], `${args[0]} ${code}`);
      assert.deepEqual(inside(result.opened, [store, assets]), [], `${args[0]} ${code}`);
      assert.equal(result.output, '', `${args[0]} ${code}`);
    }
  }
});

test('AI entries with a non-matching policy, or without AI configuration, reach the same point as Config1', { skip: process.platform !== 'win32' && 'AI host is Windows-only' }, async () => {
  const unmatched = policy('active', [{ kind: 'digest', component: 'linux-image', sha256: '1'.repeat(64) }, { kind: 'component', component: 'windows-owner' }, { kind: 'component', component: 'codex-cli' }]);
  const cases = [{ fields: { tools, ai }, raw: unmatched }, { fields: { tools }, raw: policy('active', [{ kind: 'digest', component: 'docker', sha256: 'f'.repeat(64) }]) }];
  for (const { fields, raw } of cases) for (const args of aiEntries) {
    const expected = await invoke([...args, '--config', await configFile({ schema: 1, ...fields })]);
    const actual = await invoke([...args, '--config', await configFile({ schema: 2, runtimePolicy: raw, ...fields })]);
    assert.ok(expected.launches.length > 0, args[0]);
    assert.doesNotMatch(actual.error, /runtime_policy/, args[0]);
    assert.deepEqual(comparable(actual), comparable(expected), args[0]);
  }
});

const runnerRefusals: [unknown, string][] = [
  [policy('stopped'), 'runtime_policy_stopped'],
  [policy('active', [{ kind: 'component', component: 'codex-cli' }]), 'runtime_policy_denied_codex_cli_component'],
  [policy('active', [{ kind: 'digest', component: 'codex-cli', sha256: runner.linuxCodex.sha256 }]), 'runtime_policy_denied_codex_cli_digest'],
  [policy('active', [{ kind: 'digest', component: 'docker', sha256: runner.docker.sha256 }]), 'runtime_policy_denied_docker_digest'],
  [policy('active', [{ kind: 'digest', component: 'linux-image', sha256: '7'.repeat(64) }]), 'runtime_policy_denied_linux_image_digest'],
  [policy('active', [{ kind: 'component', component: 'gitleaks' }]), 'runtime_policy_denied_gitleaks_component'],
];
test('runner-check refuses before hashing runner tools, reading the auth home or starting a process', { skip: process.platform !== 'win32' && 'runner-check host is Windows-only' }, async () => {
  const runnerFiles = [runner.codex.path, runner.linuxCodex.path, runner.docker.path];
  for (const [raw, code] of runnerRefusals) {
    const result = await invoke(['runner-check', '--config', await configFile({ schema: 2, runtimePolicy: raw, tools: { gitleaks: tools.gitleaks }, runner })]);
    assert.equal(result.exitCode, 4, code);
    assert.deepEqual(JSON.parse(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: code, policy: ref(raw) }, code);
    assert.deepEqual(result.launches, [], code);
    assert.deepEqual(inside(result.opened, [authHome, ...runnerFiles]), [], code);
    assert.equal(result.output, '', code);
  }
  const unmatched = policy('active', [{ kind: 'digest', component: 'codex-cli', sha256: '2'.repeat(64) }, { kind: 'component', component: 'osv' }]);
  const expected = await invoke(['runner-check', '--config', await configFile({ schema: 1, runner })]);
  const actual = await invoke(['runner-check', '--config', await configFile({ schema: 2, runtimePolicy: unmatched, runner })]);
  assert.deepEqual(inside(actual.opened, runnerFiles), runnerFiles, 'positive control hashed the runner tools');
  const state = (text: string) => { const { runId: _run, createdAt: _created, ...rest } = JSON.parse(text); return rest; };
  assert.deepEqual({ ...comparable(actual), state: state(actual.output) }, { ...comparable(expected), state: state(expected.output) });
});

test('runner-check refuses non-Windows hosts before reading runner inputs or starting a process', { skip: process.platform === 'win32' && 'requires a non-Windows host' }, async () => {
  const result = await invoke(['runner-check', '--config', await configFile({ schema: 1, runner })]);
  assert.equal(result.exitCode, 3); assert.equal(result.error, '');
  const state = JSON.parse(result.output);
  assert.equal(state.state, 'INCOMPLETE'); assert.ok(state.blockers.includes('runner_host_unsupported'));
  assert.deepEqual(result.launches, []);
  assert.deepEqual(inside(result.opened, [authHome, runner.codex.path, runner.linuxCodex.path, runner.docker.path]), []);
});

const readers = [['history', report], ['ci-check', report], ['recover', report], ['dispositions', report], ['policy-check', report, '--decisions', report],
  ['job-export', report], ['job-export', path.join(fixture, 'host-job.json')], ['job-recover', report]];
test('reader entries refuse stopped and gitleaks-denied policies before reading inputs or starting a process', async () => {
  for (const raw of [policy('stopped', [{ kind: 'component', component: 'osv' }]), policy('active', [{ kind: 'component', component: 'gitleaks' }])]) {
    const config = await configFile({ schema: 2, runtimePolicy: raw, tools });
    for (const args of readers) {
      const result = await invoke([...args, '--config', config]);
      assert.equal(result.exitCode, 4, args[0]);
      assert.deepEqual(JSON.parse(result.error).policy, ref(raw), args[0]);
      assert.equal(JSON.parse(result.error).error, raw.state === 'stopped' ? 'runtime_policy_stopped' : 'runtime_policy_denied_gitleaks_component', args[0]);
      assert.deepEqual(result.launches, [], args[0]);
      assert.deepEqual(inside(result.opened, [report]), [], args[0]);
    }
  }
});

test('reader entries with a non-matching policy produce the Config1 output', async () => {
  const unmatched = policy('active', [{ kind: 'component', component: 'osv' }, { kind: 'digest', component: 'gitleaks', sha256: '3'.repeat(64) }, { kind: 'component', component: 'docker' }]);
  const expectedConfig = await configFile({ schema: 1, tools }), actualConfig = await configFile({ schema: 2, runtimePolicy: unmatched, tools });
  for (const args of readers) {
    const expected = await invoke([...args, '--config', expectedConfig]), actual = await invoke([...args, '--config', actualConfig]);
    assert.doesNotMatch(actual.error, /runtime_policy/, args[0]);
    assert.deepEqual({ ...comparable(actual), output: actual.output }, { ...comparable(expected), output: expected.output }, args.join(' '));
  }
  const history = await invoke(['history', report, '--config', actualConfig]);
  assert.ok(history.launches.includes('spawn'), 'history reached the gitleaks output check under Config2');
});

test('serve still rejects Config2 and refusals without an identified policy carry no policy fields', async () => {
  const serve = await invoke(['serve', '--config', await configFile({ schema: 2, runtimePolicy: policy('active'), tools })]);
  assert.deepEqual(JSON.parse(serve.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'runtime_policy_entry_unsupported' });
  assert.deepEqual(serve.launches, []);
  for (const [value, code] of [[{ schema: 2, tools }, 'runtime_policy_required'], [{ schema: 2, runtimePolicy: { ...policy('active'), revision: 0 }, tools }, 'runtime_policy_invalid']] as const) {
    const result = await invoke(['history', report, '--config', await configFile(value)]);
    assert.deepEqual(JSON.parse(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: code });
  }
});
