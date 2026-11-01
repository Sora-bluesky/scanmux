import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { canonical, digest, hash, within } from '../src/safety.ts';
import { admitJobRuntime, jobFileIdentity, jobLinuxConfig, loadJobProfile, parseJobProfile, type JobProfile2 } from '../src/job-config.ts';
import { validateJobBootstrap, validateJobPlan } from '../src/job-records.ts';
import { nativeProcessCapacity, validateHostJobIntent } from '../src/host-job-records.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { scanJob } from '../src/job-runner.ts';
import { cleanupHostContainer, readHostJobIntent, scanHostJob, verifyHostJobInputs } from '../src/host-job.ts';
import { decideRuntimePolicy, parseRuntimePolicy, parseRuntimePolicy2, runtimePolicyRef } from '../src/runtime-policy.ts';
import { nextLedgerLine, type LedgerEntry, type LedgerFields } from '../src/engine-ledger.ts';
import { JobFrameDecoder } from '../internal/job-channel.mjs';
import { protectDirectory } from '../src/private-storage.ts';

type GhBehavior = { kind: 'exit'; code: number; stdout: string } | { kind: 'spawn_error' };
let gh: GhBehavior = { kind: 'exit', code: 1, stdout: '' };
function fakeChild(behavior: GhBehavior) {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), pid: behavior.kind === 'exit' ? 4242 : undefined, kill: () => true });
  setImmediate(() => {
    if (behavior.kind === 'spawn_error') { child.emit('error', Object.assign(new Error('spawn failed'), { code: 'ENOENT' })); child.emit('close', -4058); return; }
    child.stdout.end(behavior.stdout); child.stderr.end();
    child.stdout.on('end', () => setImmediate(() => child.emit('close', behavior.code)));
    child.stdout.resume();
  });
  return child;
}
const launches: string[] = [];
let dockerPath = '', ownerPath = '', ghPath = '';
const ghVersion: GhBehavior = { kind: 'exit', code: 0, stdout: 'gh version 2.94.0 (2026-09-01)' };
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) {
    launches.push(String(args[0]));
    if (name === 'spawn' && args[0] === ghPath) return fakeChild(Array.isArray(args[1]) && args[1][0] === '--version' ? ghVersion : gh);
    if (args[0] === dockerPath) throw new Error('synthetic docker canary was started');
    if (args[0] === ownerPath) throw new Error('synthetic owner canary was started');
    return Reflect.apply(original, this, args);
  };
}
syncBuiltinESMExports();

const parent = tmpdir(), fixture = await fs.mkdtemp(path.join(parent, 'job-admission-test-'));
test.after(async () => { try { assert.ok(within(parent, fixture)); } finally { await removeTempDirStrict(fixture, { recursive: true, force: true }); } });
const target = path.join(fixture, 'target'), temporary = path.join(fixture, 'tmp'), workspaceParent = path.join(temporary, 'scanmux-private');
await fs.mkdir(target); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;
await fs.mkdir(workspaceParent, { mode: 0o700 }); await protectDirectory(workspaceParent);

const tool = (name: string, version = '1.2.3') => ({ path: '/opt/scanmux/' + name, sha256: '0'.repeat(63) + name.length, version });
const pinned = () => ({ schema: 'scanmux.job-profile/v1', name: 'pinned_v1', scope: 'offline-local', docker: { tool: tool('docker'), endpoint: 'npipe:////./pipe/dockerDesktopLinuxEngine' },
  image: 'sha256:' + '1'.repeat(64), runtime: { nodeVersion: '24.22.1', python: { ...tool('p'), path: '/usr/bin/python3' }, git: { ...tool('g'), path: '/usr/bin/git' } },
  tools: { gitleaks: tool('gitleaks', '8.30.1'), osv: tool('osv', '2.3.0') } as Record<string, ReturnType<typeof tool>>, osvDatabase: null as string | null,
  scan: { timeoutMs: 10000, maxOutputBytes: 1048576, maxFileBytes: 1048576, maxSnapshotBytes: 8388608, maxFiles: 1000 },
  limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 4194304 } });
const policy = (state: 'active' | 'stopped', deny: unknown[] = []) => ({ schema: 'scanmux.runtime-policy/v1', id: '6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b', revision: 2, state, deny });
const two = (value: ReturnType<typeof pinned>, runtimePolicy: unknown) => ({ ...value, schema: 'scanmux.job-profile/v2', runtimePolicy });
const accept = { runtimePolicy: 'accept' as const };

test('v1 job profile parse result and digests are unchanged', () => {
  for (const entry of [undefined, accept]) {
    const parsed = parseJobProfile(pinned(), entry);
    assert.equal(JSON.stringify(parsed), JSON.stringify(pinned()));
    assert.equal(digest(parsed), '8d24d3e08e1d456708af5faa73fb53bfbe2210563ea248be9f2ba9a0b6c30140');
    assert.equal(digest(jobLinuxConfig(parsed)), '4774598408fff3419e21728f593c9aadd70eb5a14e3a704a2b6cd01be64fcfc5');
    assert.equal(Object.hasOwn(parsed, 'runtimePolicy'), false);
  }
});

test('schema and runtime policy presence must agree, and v2 needs an accepting entry', () => {
  const valid = policy('active');
  for (const entry of [undefined, accept]) assert.throws(() => parseJobProfile({ ...pinned(), runtimePolicy: valid }, entry), { code: 'invalid_job_profile' });
  const { runtimePolicy: _policy, ...missing } = two(pinned(), valid);
  assert.throws(() => parseJobProfile(missing, accept), { code: 'runtime_policy_required' });
  assert.throws(() => parseJobProfile(two(pinned(), valid)), { code: 'runtime_policy_entry_unsupported' });
  assert.throws(() => parseJobProfile(missing), { code: 'runtime_policy_entry_unsupported' });
  assert.throws(() => parseJobProfile(two(pinned(), { ...valid, revision: 0 }), accept), { code: 'runtime_policy_invalid' });
  assert.throws(() => parseJobProfile({ ...two(pinned(), valid), scope: 'ai' }, accept), { code: 'invalid_job_profile' });
  const parsed = parseJobProfile(two(pinned(), valid), accept);
  assert.equal(parsed.schema, 'scanmux.job-profile/v2');
  assert.deepEqual(parsed.runtimePolicy, parseRuntimePolicy(valid));
  const { runtimePolicy: _parsed, ...fields } = parsed;
  assert.deepEqual({ ...fields, schema: 'scanmux.job-profile/v1' }, parseJobProfile(pinned()));
});

let files = 0;
async function writeJson(value: unknown): Promise<string> {
  const file = path.join(fixture, `input-${files++}.json`);
  await fs.writeFile(file, JSON.stringify(value));
  return file;
}
const dockerBytes = 'synthetic docker canary bytes', gitleaksBytes = 'synthetic gitleaks bytes';
async function disk() {
  const directory = await fs.mkdtemp(path.join(fixture, 'assets-'));
  dockerPath = path.join(directory, 'docker.exe');
  const gitleaksPath = path.join(directory, 'gitleaks.exe');
  await fs.writeFile(dockerPath, dockerBytes); await fs.writeFile(gitleaksPath, gitleaksBytes);
  const value = pinned();
  value.docker.tool = { path: dockerPath, sha256: hash(dockerBytes), version: '28.1.1' };
  value.tools = { gitleaks: { path: gitleaksPath, sha256: hash(gitleaksBytes), version: '8.30.1' } };
  return value;
}
async function workspaces() {
  assert.deepEqual(await fs.readdir(temporary), ['scanmux-private'], 'only the protected parent may remain in TEMP');
  return fs.readdir(workspaceParent);
}
async function clearWorkspaces() { for (const name of await workspaces()) await removeTempDirStrict(path.join(workspaceParent, name), { recursive: true, force: true }); }

test('the default reader refuses v2; the delegated host scan admits it again before any process', async () => {
  const value = await disk();
  await assert.rejects(loadJobProfile(await writeJson(two(value, policy('active'))), target), { code: 'runtime_policy_entry_unsupported' });
  const directory = await fs.mkdtemp(path.join(fixture, 'delegated-'));
  const delegated = async (runtimePolicy: unknown) => scanJob(target, await writeJson(two(value, runtimePolicy)), new AbortController().signal, undefined,
    { jobId: randomUUID(), directory, metadataName: 'delegated-job.json' });
  launches.length = 0;
  await assert.rejects(delegated(policy('stopped')), { code: 'runtime_policy_stopped' });
  await assert.rejects(delegated(policy('active', [{ kind: 'component', component: 'docker' }])), { code: 'runtime_policy_denied_docker_component' });
  await assert.rejects(delegated(policy('active')), (error: { code?: unknown }) => !String(error.code).startsWith('runtime_policy'));
  assert.deepEqual(launches, []); assert.deepEqual(await fs.readdir(directory), []); assert.deepEqual(await workspaces(), []);
});

const ownerBytes = 'synthetic owner canary bytes';
async function hostInputs(offline: unknown) {
  ownerPath = path.join(await canonical(fixture), 'owner.exe'); await fs.writeFile(ownerPath, ownerBytes);
  const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
  const host = { schema: 'scanmux.host-job-profile/v1', name: 'synthetic_host', scope: 'windows-offline-local', offlineProfile: await canonical(await writeJson(offline)),
    owner: { path: ownerPath, sha256: hash(ownerBytes), version: '1.0.0' }, node, limits: { cpuRate: 2500, memoryBytes: 536870912, wallMs: 20000, cleanupTimeoutMs: 10000 } };
  return { host, hostPath: await canonical(await writeJson(host)) };
}
const windowsOnly = { skip: process.platform === 'win32' ? false : 'host job is Windows-only' };

test('stopped and denied v2 host jobs start no process and create no workspace; v1 and non-matching v2 reach the owner', windowsOnly, async () => {
  const value = await disk(), { host } = await hostInputs(value);
  const refusals: [unknown, string][] = [
    [policy('stopped'), 'runtime_policy_stopped'],
    [policy('active', [{ kind: 'digest', component: 'windows-owner', sha256: host.owner.sha256 }]), 'runtime_policy_denied_windows_owner_digest'],
    [policy('active', [{ kind: 'digest', component: 'node', sha256: host.node.sha256 }]), 'runtime_policy_denied_node_digest'],
    [policy('active', [{ kind: 'component', component: 'docker' }]), 'runtime_policy_denied_docker_component'],
    [policy('active', [{ kind: 'component', component: 'node' }]), 'runtime_policy_denied_node_component'],
    [policy('active', [{ kind: 'digest', component: 'node', sha256: 'f'.repeat(64) }]), 'runtime_policy_unidentified_node'],
  ];
  for (const [runtimePolicy, code] of refusals) {
    const { hostPath } = await hostInputs(two(value, runtimePolicy));
    launches.length = 0;
    await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), { code });
    assert.deepEqual(launches, [], code); assert.deepEqual(await workspaces(), [], code);
  }
  const unmatched = policy('active', [{ kind: 'digest', component: 'windows-owner', sha256: 'f'.repeat(64) }, { kind: 'component', component: 'codex-cli' }]);
  const observed: string[][] = [];
  for (const offline of [value, two(value, unmatched)]) {
    const { hostPath } = await hostInputs(offline);
    launches.length = 0;
    await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), /synthetic owner canary was started/);
    assert.equal(launches.at(-1), ownerPath, 'positive control reached the owner');
    assert.equal((await workspaces()).length, 1, 'positive control created its workspace');
    observed.push([...launches]); await clearWorkspaces();
  }
  assert.deepEqual(observed[1], observed[0]);
});

async function hostIntent(runtimePolicy: unknown) {
  const value = await disk(), offline = two(value, runtimePolicy), { host, hostPath } = await hostInputs(offline);
  const directory = await canonical(await fs.mkdtemp(path.join(fixture, 'intent-'))), application = await canonical(await fs.mkdtemp(path.join(fixture, 'app-')));
  await fs.mkdir(path.join(directory, 'AppData', 'Roaming'), { recursive: true });
  const worker = path.join(application, 'internal', 'windows-job-worker.mjs');
  await fs.mkdir(path.dirname(worker)); await fs.writeFile(worker, 'synthetic worker');
  const root = await canonical(target), stat = await fs.lstat(root, { bigint: true });
  const intent = { schema: 'scanmux.host-job-intent/v1', mode: 'scan', jobId: randomUUID(), root, directory, comparison: null,
    rootIdentity: { device: stat.dev.toString(), inode: stat.ino.toString(), modifiedNs: stat.mtimeNs.toString() }, host,
    hostSource: { path: hostPath, identity: await jobFileIdentity(hostPath) }, offline: parseJobProfile(offline, accept), offlineSource: await jobFileIdentity(host.offlineProfile),
    application, assets: [{ path: 'internal/windows-job-worker.mjs', ...await jobFileIdentity(worker) }],
    nodeIdentity: await jobFileIdentity(host.node.path), ownerIdentity: await jobFileIdentity(host.owner.path), maxProcesses: nativeProcessCapacity(1048576) };
  const bytes = Buffer.from(JSON.stringify(intent, null, 2) + '\n');
  await fs.writeFile(path.join(directory, 'host-job-intent.json'), bytes);
  return { intent, directory, sha256: hash(bytes) };
}

test('a v2 host intent is accepted and keeps the v2 profile to Config2 plan mapping', windowsOnly, async () => {
  const unmatched = policy('active', [{ kind: 'digest', component: 'gitleaks', sha256: 'f'.repeat(64) }]);
  const { intent, directory, sha256 } = await hostIntent(unmatched), loaded = await readHostJobIntent(directory, sha256);
  assert.deepEqual(loaded.intent, intent);
  assert.equal(loaded.intent.offline.schema, 'scanmux.job-profile/v2');
  const config = jobLinuxConfig(loaded.intent.offline);
  assert.equal(config.schema, 2); assert.deepEqual(config.runtimePolicy, parseRuntimePolicy(unmatched));
  const bootstrap = bootstrapFor(loaded.intent.offline), expected = { ...validateJobBootstrap(bootstrap), comparison: undefined };
  assert.deepEqual(expected.config, config);
  assert.equal(validateJobPlan(planFor(bootstrap), expected).config.schema, 2);
  assert.throws(() => validateJobPlan(planFor({ ...bootstrap, config: jobLinuxConfig(parseJobProfile(pinned())) }), expected), { code: 'invalid_job_record' });
  await verifyHostJobInputs(loaded.intent);
});

test('a stored v2 host intent keeps its rule order, so its recorded plan still matches', windowsOnly, async () => {
  const rules = [{ kind: 'digest', component: 'osv', sha256: 'f'.repeat(64) }, { kind: 'digest', component: 'gitleaks', sha256: 'e'.repeat(64) }, { kind: 'component', component: 'codex-cli' }];
  const { intent, directory } = await hostIntent(policy('active', rules));
  const linux = ['internal/linux-job-controller.mjs', 'internal/linux-job-supervisor.py'].map(name => ({ path: name, bytes: 1, sha256: 'e'.repeat(64) }));
  const stored = { ...intent, assets: [...linux, ...intent.assets], offline: { ...intent.offline, runtimePolicy: policy('active', rules) } };
  const bytes = Buffer.from(JSON.stringify(stored, null, 2) + '\n');
  await fs.writeFile(path.join(directory, 'host-job-intent.json'), bytes);
  const loaded = await readHostJobIntent(directory, hash(bytes));
  const offline = loaded.intent.offline, config = jobLinuxConfig(offline);
  const expected = { jobId: loaded.intent.jobId, profileSha256: digest(offline), root: loaded.intent.root, mappedRoot: '/repo/' + hash(loaded.intent.root), config,
    limits: offline.limits, image: offline.image, runtime: { ...offline.runtime, tools: config.tools, app: loaded.intent.assets }, destination: loaded.intent.directory, comparison: undefined };
  const recorded = stored.offline as unknown as ReturnType<typeof parseJobProfile>, recordedConfig = jobLinuxConfig(recorded);
  const bootstrap = { ...expected, jobId: loaded.intent.jobId as ReturnType<typeof randomUUID>, profileSha256: digest(recorded), config: recordedConfig, comparison: null,
    runtime: { ...recorded.runtime, tools: recordedConfig.tools, app: loaded.intent.assets } };
  assert.equal(validateJobPlan(planFor(bootstrap), expected).profileSha256, digest(recorded));
  assert.deepEqual((offline as JobProfile2).runtimePolicy.deny, rules);
});

test('the v1 host intent shape and digest are unchanged', { skip: process.platform === 'win32' ? false : 'host paths are Windows drive paths' }, () => {
  const tool = { path: 'C:\\scanmux\\owner.exe', sha256: 'a'.repeat(64), version: '1.0.0' };
  const input = { schema: 'scanmux.host-job-intent/v1', mode: 'scan', jobId: '11111111-1111-4111-8111-111111111111', root: 'C:\\scanmux\\source', directory: 'C:\\scanmux\\output',
    comparison: null, rootIdentity: { device: '1', inode: '2', modifiedNs: '3' },
    host: { schema: 'scanmux.host-job-profile/v1', name: 'pinned_host', scope: 'windows-offline-local', offlineProfile: 'C:\\scanmux\\offline.json', owner: tool,
      node: { ...tool, path: 'C:\\scanmux\\node.exe', version: '24.22.1' }, limits: { cpuRate: 2500, memoryBytes: 536870912, wallMs: 20000, cleanupTimeoutMs: 10000 } },
    hostSource: { path: 'C:\\scanmux\\host.json', identity: { bytes: 1, sha256: 'b'.repeat(64) } },
    offline: { ...pinned(), docker: { ...pinned().docker, tool: { ...tool, path: 'C:\\scanmux\\docker.exe' } }, tools: { gitleaks: { ...tool, path: 'C:\\scanmux\\gitleaks.exe' } } },
    offlineSource: { bytes: 1, sha256: 'd'.repeat(64) }, application: 'C:\\scanmux\\app', assets: [{ path: 'internal/windows-job-worker.mjs', bytes: 1, sha256: 'e'.repeat(64) }],
    nodeIdentity: { bytes: 1, sha256: tool.sha256 }, ownerIdentity: { bytes: 1, sha256: tool.sha256 }, maxProcesses: nativeProcessCapacity(1048576) };
  const intent = validateHostJobIntent(input);
  assert.deepEqual(intent, input);
  assert.equal(hash(Buffer.from(JSON.stringify(intent, null, 2) + '\n')), 'bfa4a361beb668e79bf4a8540e39b2efed37e94e8dd448d49daa018b4ddd34db');
  assert.equal(digest(intent), '638b77a6bb92cc7356469a7c017ab12709c8bb273835b168b99ddf298854749f');
  assert.equal(digest(jobLinuxConfig(intent.offline)), '7bf99434450f359a383c5f1dd4c14b8541b40fe7c2eb0dfb0706220cde15fc92');
});

test('cleanup input checks never consult the policy, and a rewritten profile still fails them as before', windowsOnly, async () => {
  const stopped = await hostIntent(policy('stopped')), loaded = await readHostJobIntent(stopped.directory, stopped.sha256);
  launches.length = 0;
  await verifyHostJobInputs(loaded.intent);
  await assert.rejects(cleanupHostContainer(loaded.intent, stopped.sha256), /synthetic docker canary was started/);
  assert.deepEqual(launches, [dockerPath], 'cleanup reached docker under a stopped policy');
  const active = await hostIntent(policy('active')), recorded = await readHostJobIntent(active.directory, active.sha256);
  await fs.writeFile(recorded.intent.host.offlineProfile, JSON.stringify(two(await disk(), policy('stopped'))));
  launches.length = 0;
  await assert.rejects(verifyHostJobInputs(recorded.intent), { code: 'job_asset_changed' });
  assert.deepEqual(launches, []);
});

test('stopped and denied v2 job profiles never start docker or create a workspace; v1 and non-matching v2 do', { skip: process.platform === 'win32' ? false : 'npipe fixture profile is Windows-only' }, async () => {
  const value = await disk();
  const refusals: [unknown, string][] = [
    [policy('stopped'), 'runtime_policy_stopped'],
    [policy('active', [{ kind: 'digest', component: 'docker', sha256: hash(dockerBytes) }]), 'runtime_policy_denied_docker_digest'],
    [policy('active', [{ kind: 'digest', component: 'linux-image', sha256: '1'.repeat(64) }]), 'runtime_policy_denied_linux_image_digest'],
    [policy('active', [{ kind: 'component', component: 'gitleaks' }]), 'runtime_policy_denied_gitleaks_component'],
    [policy('active', [{ kind: 'component', component: 'node' }]), 'runtime_policy_denied_node_component'],
    [policy('active', [{ kind: 'digest', component: 'node', sha256: 'f'.repeat(64) }]), 'runtime_policy_unidentified_node'],
  ];
  for (const [runtimePolicy, code] of refusals) {
    const file = await writeJson(two(value, runtimePolicy));
    launches.length = 0;
    await assert.rejects(scanJob(target, file, new AbortController().signal), { code, policy: runtimePolicyRef(parseRuntimePolicy(runtimePolicy)) });
    assert.deepEqual(launches, [], code); assert.deepEqual(await workspaces(), [], code);
  }
  const unmatched = policy('active', [{ kind: 'digest', component: 'docker', sha256: 'f'.repeat(64) }, { kind: 'component', component: 'codex-cli' }]);
  for (const profile of [value, two(value, unmatched)]) {
    launches.length = 0;
    await scanJob(target, await writeJson(profile), new AbortController().signal).catch(() => null);
    assert.ok(launches.includes(dockerPath), 'positive control reached docker');
    assert.equal((await workspaces()).length, 1, 'positive control created its workspace');
    await clearWorkspaces();
  }
});

function bootstrapFor(profile: ReturnType<typeof parseJobProfile>) {
  const config = jobLinuxConfig(profile), root = target, mappedRoot = '/repo/' + hash(root);
  const runtime = { ...profile.runtime, tools: config.tools, app: ['internal/linux-job-controller.mjs', 'internal/linux-job-supervisor.py'].map(name => ({ path: name, bytes: 1, sha256: 'e'.repeat(64) })) };
  return { jobId: randomUUID(), profileSha256: digest(profile), root, mappedRoot, config, limits: profile.limits, image: profile.image, runtime, destination: fixture, comparison: null };
}
function planFor(bootstrap: ReturnType<typeof bootstrapFor>) {
  const { mappedRoot, config } = bootstrap;
  const plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: mappedRoot, repoId: hash(mappedRoot),
    commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest([]), dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  return { schema: 'scanmux.job-plan/v1', jobId: bootstrap.jobId, profileSha256: bootstrap.profileSha256, origin: { root: bootstrap.root, repoId: hash(bootstrap.root) }, mappedRoot,
    config, configSha256: digest(config), limits: bootstrap.limits, image: bootstrap.image, runtime: bootstrap.runtime, destination: bootstrap.destination, requestedComparison: null, plan };
}

test('active non-matching v2 continues, emits Config2 and the records accept only the matching closed config kind', async () => {
  const unmatched = policy('active', [{ kind: 'digest', component: 'gitleaks', sha256: 'f'.repeat(64) }]);
  const profile = parseJobProfile(two(pinned(), unmatched), accept) as JobProfile2;
  assert.deepEqual(decideRuntimePolicy(profile.runtimePolicy, [{ component: 'gitleaks', sha256: profile.tools.gitleaks.sha256 }]), { kind: 'continue' });
  launches.length = 0;
  await admitJobRuntime(profile, target, new AbortController().signal);
  assert.deepEqual(launches, []);
  const config = jobLinuxConfig(profile);
  assert.equal(config.schema, 2); assert.deepEqual(config.runtimePolicy, parseRuntimePolicy(unmatched));
  const bootstrap = bootstrapFor(profile);
  assert.deepEqual(validateJobBootstrap(bootstrap).config, config);
  const changes: ((input: ReturnType<typeof bootstrapFor>) => void)[] = [
    input => { (input.config as { schema: number }).schema = 1; },
    input => { delete (input.config as { runtimePolicy?: unknown }).runtimePolicy; },
    input => { (input.config as { runtimePolicy: { revision: number } }).runtimePolicy.revision = 0; },
  ];
  for (const change of changes) { const input = structuredClone(bootstrap); change(input); assert.throws(() => validateJobBootstrap(input), { code: 'invalid_job_record' }); }
  const v1 = bootstrapFor(parseJobProfile(pinned()));
  assert.equal(validateJobBootstrap(v1).config.schema, 1);
  assert.throws(() => validateJobBootstrap({ ...v1, config: { ...v1.config, runtimePolicy: unmatched } }), { code: 'invalid_job_record' });
  const expected = { ...validateJobBootstrap(bootstrap), comparison: undefined }, expectedOne = { ...validateJobBootstrap(v1), comparison: undefined };
  assert.equal(validateJobPlan(planFor(bootstrap), expected).config.schema, 2);
  assert.throws(() => validateJobPlan(planFor({ ...bootstrap, config: jobLinuxConfig(parseJobProfile(pinned())) }), expected), { code: 'invalid_job_record' });
  assert.throws(() => validateJobPlan(planFor({ ...v1, config: config }), expectedOne), { code: 'invalid_job_record' });
});

async function controller(runtimePolicy: unknown) {
  const profile = parseJobProfile({ ...two(pinned(), runtimePolicy), runtime: { ...pinned().runtime, nodeVersion: process.versions.node } }, accept);
  const bootstrap = bootstrapFor(profile);
  const preload = path.join(fixture, 'controller-preload.mjs');
  await fs.writeFile(preload, [
    "import childProcess from 'node:child_process'; import { syncBuiltinESMExports } from 'node:module';",
    "for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork']) {",
    "  const original = childProcess[name]; childProcess[name] = function (...args) { process.stderr.write('LAUNCH ' + String(args[0]) + '\\n'); return Reflect.apply(original, this, args); };",
    '}',
    "syncBuiltinESMExports(); Object.defineProperty(process, 'platform', { value: 'linux' });",
  ].join('\n'));
  const child = childProcess.spawn(process.execPath, ['--import', 'file:///' + preload.split(path.sep).join('/'), 'internal/linux-job-controller.mjs'],
    { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const decoder = new JobFrameDecoder({ nonce: bootstrap.jobId, maxOutputBytes: profile.scan.maxOutputBytes, retainedBytes: profile.limits.retainedBytes, sender: 'controller' });
  const frames: Record<string, unknown>[] = [], errors: Buffer[] = [];
  child.stderr.on('data', bytes => errors.push(bytes));
  const timer = setTimeout(() => child.kill(), 20000);
  child.stdout.on('data', bytes => { frames.push(...decoder.push(Buffer.from(bytes))); if (frames.length) child.stdin.end(); });
  const closed = new Promise<number | null>(resolve => child.once('close', resolve));
  child.stdin.write(JSON.stringify({ schema: 'scanmux.job-controller-init/v1', nonce: bootstrap.jobId, expected: bootstrap, limits: profile.limits }) + '\n');
  const code = await closed; clearTimeout(timer);
  return { code, frames, launches: Buffer.concat(errors).toString('utf8').split('\n').filter(line => line.startsWith('LAUNCH ')) };
}

test('linux job controller accepts a Config2 bootstrap and reaches planning without deciding the policy itself', async () => {
  for (const runtimePolicy of [policy('stopped'), policy('active', [{ kind: 'component', component: 'git' }])]) {
    const result = await controller(runtimePolicy);
    assert.equal(result.code, 4);
    assert.deepEqual(result.frames.map(frame => [frame.type, frame.code]), [['failure', 'plan_failed']], JSON.stringify(runtimePolicy));
  }
});

const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
ghPath = path.join(fixture, 'gh.exe');
await fs.writeFile(ghPath, 'synthetic gh');
const nodeTool = { path: ghPath, sha256: hash('synthetic gh'), version: '2.94.0' };
const osvBytes = 'synthetic linux osv artifact bytes', bundleBytes = 'synthetic bundle', rootBytes = 'synthetic trusted root';
const publisher = {
  repository: 'google/osv-scanner',
  certIdentity: 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0',
  oidcIssuer: 'https://token.actions.githubusercontent.com', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted',
};
const sourceRef = 'refs/tags/v2.3.0', sourceDigest = 'a'.repeat(40);
const osvPath = path.join(fixture, 'osv-linux'), bundlePath = path.join(fixture, 'osv.intoto.jsonl'), trustedRootPath = path.join(fixture, 'trusted-root.jsonl');
await fs.writeFile(osvPath, osvBytes); await fs.writeFile(bundlePath, bundleBytes); await fs.writeFile(trustedRootPath, rootBytes);
const sigstore = { kind: 'sigstore-slsa' as const, bundle: { path: bundlePath, sha256: hash(bundleBytes) }, trustedRoot: { path: trustedRootPath, sha256: hash(rootBytes) }, sourceRef, sourceDigest };
async function ledgerFile(items: LedgerFields[]) {
  const file = path.join(fixture, `ledger-${files++}.jsonl`), entries: LedgerEntry[] = [], chunks: Buffer[] = [];
  let head = '0'.repeat(64);
  for (const item of items) { const next = nextLedgerLine(entries, item); entries.push(next.entry); chunks.push(next.bytes); head = next.head; }
  await fs.writeFile(file, Buffer.concat(chunks));
  return { path: file, entries: entries.length, head };
}
const signedLedger = await ledgerFile([{ recordedAt: '2026-10-25T00:00:00.000Z', component: 'osv', platform: 'linux-x64', version: '2.3.0', sha256: hash(osvBytes),
  change: 'synthetic', recordedBy: { scanmux: '0.1.0-poc.1', verifier: null }, evidence: sigstore }]);
const policyTwo = (ledger: { path: string; entries: number; head: string } = signedLedger) => ({ schema: 'scanmux.runtime-policy/v2', id: '6f1c2a8e-3b4d-4e5f-8a9b-0c1d2e3f4a5b', revision: 2, state: 'active', deny: [],
  provenance: { verifier: nodeTool, ledger, require: [{ component: 'osv', level: 'publisher', publisher }] } });
function verifiedJson(sha256 = hash(osvBytes)) {
  return JSON.stringify([{ verificationResult: {
    statement: { predicateType: publisher.predicateType, subject: [{ name: 'osv-scanner_linux_amd64', digest: { sha256 } }] },
    signature: { certificate: { subjectAlternativeName: publisher.certIdentity, issuer: publisher.oidcIssuer, sourceRepositoryURI: 'https://github.com/google/osv-scanner',
      sourceRepositoryRef: sourceRef, sourceRepositoryDigest: sourceDigest, runnerEnvironment: 'github-hosted' } } } }]);
}
async function withOsv() {
  const value = await disk();
  value.tools = { ...value.tools, osv: { path: osvPath, sha256: hash(osvBytes), version: '2.3.0' } };
  return value;
}
const verifying = [powershell, ghPath, ghPath];
const gated: [string, GhBehavior | null, () => unknown, string, string[]][] = [
  ['rejected', { kind: 'exit', code: 1, stdout: '' }, () => policyTwo(), 'provenance_invalid_osv', verifying],
  ['mismatching verifier output', { kind: 'exit', code: 0, stdout: verifiedJson('e'.repeat(64)) }, () => policyTwo(), 'provenance_unverifiable_osv', verifying],
  ['verifier spawn failure', { kind: 'spawn_error' }, () => policyTwo(), 'provenance_unverifiable_osv', verifying],
  ['ledger mismatch', null, () => policyTwo({ ...signedLedger, head: 'c'.repeat(64) }), 'provenance_ledger_mismatch', []],
  ['unrecorded', null, () => policyTwo({ path: path.join(fixture, 'empty-ledger.jsonl'), entries: 0, head: '0'.repeat(64) }), 'provenance_unrecorded_osv', []],
];

test('job-scan verifies the host copy of the Linux OSV binary before docker or its workspace', windowsOnly, async () => {
  const value = await withOsv();
  for (const [label, behavior, raw, code, expected] of gated) {
    if (behavior) gh = behavior;
    launches.length = 0;
    await assert.rejects(scanJob(target, await writeJson(two(value, raw())), new AbortController().signal), { code }, label);
    assert.deepEqual(launches, expected, label); assert.deepEqual(await workspaces(), [], label);
  }
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  launches.length = 0;
  await scanJob(target, await writeJson(two(value, policyTwo())), new AbortController().signal).catch(() => null);
  assert.deepEqual(launches.slice(0, verifying.length), verifying, 'verification ran first');
  assert.ok(launches.includes(dockerPath), 'a verified binary reaches docker');
  assert.equal((await workspaces()).length, 1, 'only the scan workspace remains');
  await clearWorkspaces();
});

test('host-job-scan verifies before its workspace and the owner; v2 offline profiles are accepted', windowsOnly, async () => {
  const value = await withOsv();
  for (const [label, behavior, raw, code, expected] of gated) {
    if (behavior) gh = behavior;
    const { hostPath } = await hostInputs(two(value, raw()));
    launches.length = 0;
    await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), { code }, label);
    assert.deepEqual(launches, expected, label); assert.deepEqual(await workspaces(), [], label);
  }
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  const { hostPath } = await hostInputs(two(value, policyTwo()));
  launches.length = 0;
  await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), /synthetic owner canary was started/);
  assert.deepEqual(launches.slice(0, verifying.length), verifying, 'verification ran first');
  assert.equal(launches.at(-1), ownerPath, 'a verified binary reaches the owner');
  assert.equal((await workspaces()).length, 1, 'only the host job workspace remains');
  await clearWorkspaces();
});

test('a v2 profile cannot pin its verifier or ledger inside the target or on a non-local host path', windowsOnly, async () => {
  const value = await withOsv(), inside = policyTwo({ ...signedLedger, path: path.join(target, 'ledger.jsonl') });
  launches.length = 0;
  await assert.rejects(scanJob(target, await writeJson(two(value, inside)), new AbortController().signal), { code: 'provenance_ledger_inside_target' });
  const verifier = { ...policyTwo(), provenance: { ...policyTwo().provenance, verifier: { ...nodeTool, path: path.join(target, 'gh.exe') } } };
  await assert.rejects(scanJob(target, await writeJson(two(value, verifier)), new AbortController().signal), { code: 'provenance_verifier_inside_target' });
  const remote = { ...policyTwo(), provenance: { ...policyTwo().provenance, verifier: { ...nodeTool, path: '\\\\server\\share\\gh.exe' } } };
  const { hostPath } = await hostInputs(two(value, remote));
  await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), { code: 'invalid_host_job_record' });
  assert.deepEqual(launches, []); assert.deepEqual(await workspaces(), []);
});

test('a delegated scanJob decides a v2 policy again, verifier included; cleanup still never consults it', windowsOnly, async () => {
  const value = await withOsv(), directory = await fs.mkdtemp(path.join(fixture, 'delegated-v2-'));
  const delegated = async () => scanJob(target, await writeJson(two(value, policyTwo())), new AbortController().signal, undefined,
    { jobId: randomUUID(), directory, metadataName: 'delegated-job.json' });
  gh = { kind: 'exit', code: 1, stdout: '' };
  launches.length = 0;
  await assert.rejects(delegated(), { code: 'provenance_invalid_osv' });
  assert.deepEqual(launches, verifying); assert.deepEqual(await fs.readdir(directory), []); assert.deepEqual(await workspaces(), []);
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  launches.length = 0;
  await assert.rejects(delegated(), (error: { code?: unknown }) => !/^(runtime_policy|provenance)/.test(String(error.code)));
  assert.deepEqual(launches, verifying, 'the verified delegate ran gh again and then stopped at its own record checks');

  gh = { kind: 'exit', code: 1, stdout: '' };
  const { intent, directory: intentDirectory, sha256 } = await hostIntent(policyTwo());
  const loaded = await readHostJobIntent(intentDirectory, sha256);
  assert.deepEqual(loaded.intent, intent);
  launches.length = 0;
  await verifyHostJobInputs(loaded.intent);
  await assert.rejects(cleanupHostContainer(loaded.intent, sha256), /synthetic docker canary was started/);
  assert.deepEqual(launches, [dockerPath], 'cleanup reached docker without running the verifier');
});

test('a v2 host intent and its Linux bootstrap and plan records accept runtime policy v2', windowsOnly, async () => {
  const { intent } = await hostIntent(policyTwo());
  assert.deepEqual(validateHostJobIntent(intent), intent);
  const offline = intent.offline as JobProfile2;
  assert.deepEqual(offline.runtimePolicy, parseRuntimePolicy2(policyTwo()));
  const config = jobLinuxConfig(offline);
  assert.equal(config.schema, 2); assert.deepEqual(config.runtimePolicy, parseRuntimePolicy2(policyTwo()));
  const bootstrap = bootstrapFor(offline), expected = { ...validateJobBootstrap(bootstrap), comparison: undefined };
  assert.deepEqual(expected.config, config);
  assert.equal(validateJobPlan(planFor(bootstrap), expected).config.schema, 2);
  const broken = structuredClone(bootstrap) as unknown as { config: { runtimePolicy: { provenance: { ledger: { entries: number } } } } };
  broken.config.runtimePolicy.provenance.ledger.entries = -1;
  assert.throws(() => validateJobBootstrap(broken), { code: 'invalid_job_record' });
});

test('the Linux controller takes a v2 Config2 bootstrap to planning without deciding the policy or running the verifier', async () => {
  const result = await controller(policyTwo());
  assert.equal(result.code, 4);
  assert.deepEqual(result.frames.map(frame => [frame.type, frame.code]), [['failure', 'plan_failed']]);
  assert.ok(!result.launches.some(line => line.includes(ghPath)), 'the controller never ran the verifier');
});

test('host admission copy exhaustion keeps its budget code before the owner; delegation requires a remainder', windowsOnly, async () => {
  const value = { ...two(await withOsv(), policyTwo()), maxCopyBytes: 1 }, { hostPath } = await hostInputs(value);
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  launches.length = 0;
  await assert.rejects(scanHostJob(target, hostPath, new AbortController().signal), { code: 'job_disk_copy_limit' });
  const directory = await fs.mkdtemp(path.join(fixture, 'missing-copy-remainder-'));
  await assert.rejects(scanJob(target, await writeJson(value), new AbortController().signal, undefined,
    { jobId: randomUUID(), directory, metadataName: 'delegated-job.json' }), { code: 'invalid_host_job_record' });
  assert.deepEqual(launches, [powershell]); assert.deepEqual(await fs.readdir(directory), []);
});
