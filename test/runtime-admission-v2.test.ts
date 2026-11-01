import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import fs from 'node:fs/promises';
import { renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { main } from '../src/cli.ts';
import { loadConfig } from '../src/config.ts';
import { hash, within } from '../src/safety.ts';
import { nextLedgerLine, type LedgerEntry, type LedgerFields } from '../src/engine-ledger.ts';
import { parseRuntimePolicy, parseRuntimePolicy2, runtimePolicyRef } from '../src/runtime-policy.ts';
import { admitRuntime, verifyPublisher } from '../src/runtime-admission.ts';
import { JobDisk, withJobDisk } from '../src/job-disk.ts';
import { testProcessOwner, withTestProcessOwner } from './process-owner.ts';
import { CopyBudget, withCopyBudget } from '../src/copy-budget.ts';

type GhBehavior = { kind: 'exit'; code: number; stdout: string } | { kind: 'spawn_error' } | { kind: 'wait'; started?: () => void };
interface Launch { file: string; args: string[]; cwd?: string; env?: NodeJS.ProcessEnv }
const launches: Launch[] = [];
let gh: GhBehavior = { kind: 'exit', code: 1, stdout: '' };
let ghCopies: string[] = [];
let duringVerification: (() => void) | null = null;
let osvPath = '', ghPath = '';
let ghVersion: GhBehavior = { kind: 'exit', code: 0, stdout: 'gh version 2.94.0 (2026-09-01)' };
function fakeChild(behavior: GhBehavior) {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), pid: behavior.kind !== 'spawn_error' ? 4242 : undefined,
    kill: () => { if (behavior.kind === 'wait') setImmediate(() => child.emit('close', null)); return true; } });
  setImmediate(() => {
    if (behavior.kind === 'spawn_error') { child.emit('error', Object.assign(new Error('spawn failed'), { code: 'ENOENT' })); child.emit('close', -4058); return; }
    if (behavior.kind === 'wait') { behavior.started?.(); return; }
    child.stdout.end(behavior.stdout); child.stderr.end();
    child.stdout.on('end', () => setImmediate(() => child.emit('close', behavior.code)));
    child.stdout.resume();
  });
  return child;
}
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) {
    const argv = Array.isArray(args[1]) ? (args[1] as string[]) : [], options = (args[2] ?? {}) as { cwd?: string; env?: NodeJS.ProcessEnv };
    launches.push({ file: String(args[0]), args: argv, cwd: options.cwd, env: options.env });
    if (name === 'spawn' && args[0] === ghPath && argv[0] === '--version') return fakeChild(ghVersion);
    if (name === 'spawn' && argv[0] === 'attestation') { ghCopies = [argv[2], argv[4], argv[6]]; duringVerification?.(); return fakeChild(gh); }
    if (name === 'spawn' && args[0] === osvPath) return fakeChild({ kind: 'exit', code: 0, stdout: 'osv-scanner version: 2.3.0' });
    return Reflect.apply(original, this, args);
  };
}
syncBuiltinESMExports();

const parent = tmpdir(), fixture = await fs.mkdtemp(path.join(parent, 'runtime-admission-v2-test-'));
test.after(async () => { try { assert.ok(within(parent, fixture)); } finally { await removeTempDirStrict(fixture, { recursive: true, force: true }); } });
const target = path.join(fixture, 'target'), temporary = path.join(fixture, 'tmp');
await fs.mkdir(target); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;

const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
ghPath = path.join(fixture, 'gh.exe');
await fs.writeFile(ghPath, 'synthetic gh');
const ghTool = { path: ghPath, sha256: hash('synthetic gh'), version: '2.94.0' };
osvPath = path.join(fixture, 'osv.exe');
const osvBytes = 'synthetic osv artifact bytes';
await fs.writeFile(osvPath, osvBytes);
const osv = { path: osvPath, sha256: hash(osvBytes), version: '2.3.0' };
const tools = { git: node, gitleaks: { ...node, version: '8.30.1' }, osv };
const bundlePath = path.join(fixture, 'osv.intoto.jsonl'), rootPath = path.join(fixture, 'trusted-root.jsonl');
await fs.writeFile(bundlePath, 'synthetic bundle'); await fs.writeFile(rootPath, 'synthetic trusted root');
const publisher = {
  repository: 'google/osv-scanner',
  certIdentity: 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0',
  oidcIssuer: 'https://token.actions.githubusercontent.com', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted',
};
const sourceRef = 'refs/tags/v2.3.0', sourceDigest = 'a'.repeat(40);
const sigstore = { kind: 'sigstore-slsa' as const, bundle: { path: bundlePath, sha256: hash('synthetic bundle') }, trustedRoot: { path: rootPath, sha256: hash('synthetic trusted root') }, sourceRef, sourceDigest };
const id = '3c9a7e21-4b5d-4f6a-8b7c-9d0e1f2a3b4c';
let files = 0;
const fresh = (name: string) => path.join(fixture, `${files++}-${name}`);
function fields(component: LedgerFields['component'], sha256: string, evidence: LedgerFields['evidence']): LedgerFields {
  return { recordedAt: '2026-10-25T00:00:00.000Z', component, platform: 'windows-x64', version: '2.3.0', sha256, change: 'synthetic',
    recordedBy: { scanmux: '0.1.0-poc.1', verifier: null }, evidence };
}
async function ledgerFile(items: LedgerFields[]) {
  const file = fresh('ledger.jsonl'), entries: LedgerEntry[] = [], chunks: Buffer[] = [];
  let head = '0'.repeat(64);
  for (const item of items) { const next = nextLedgerLine(entries, item); entries.push(next.entry); chunks.push(next.bytes); head = next.head; }
  await fs.writeFile(file, Buffer.concat(chunks));
  return { path: file, entries: entries.length, head };
}
const policy2 = (ledger: { path: string; entries: number; head: string }, overrides: Record<string, unknown> = {}, require: unknown[] = [{ component: 'osv', level: 'publisher', publisher }]) => ({
  schema: 'scanmux.runtime-policy/v2', id, revision: 4, state: 'active', deny: [], provenance: { verifier: ghTool, ledger, require }, ...overrides,
});
async function configFile(runtimePolicy: unknown, toolSet: unknown = tools): Promise<string> {
  const file = fresh('config.json');
  await fs.writeFile(file, JSON.stringify(withTestProcessOwner({ schema: 2, runtimePolicy, tools: toolSet })));
  return file;
}
async function invoke(args: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  launches.length = 0; ghCopies = [];
  process.stdout.write = (chunk: string | Uint8Array) => { output.push(String(chunk)); return true; };
  process.stderr.write = (chunk: string | Uint8Array) => { errors.push(String(chunk)); return true; };
  try { const exitCode = await main(args); return { exitCode, output: output.join(''), error: errors.join(''), launches: [...launches] }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
const ghLaunches = (result: { launches: Launch[] }) => result.launches.filter(launch => launch.args[0] === 'attestation');
// On Windows every engine starts inside the process owner, so its launch stands for the first engine start.
const engineLaunches = (result: { launches: Launch[] }) => result.launches.filter(launch =>
  ([osvPath, node.path].includes(launch.file) || path.basename(launch.file) === 'scanmux-windows-process-owner.exe') && launch.args[0] !== 'attestation');
const failure = (text: string) => JSON.parse(text);
function verifiedJson(sha256 = osv.sha256) {
  return JSON.stringify([{ verificationResult: {
    statement: { predicateType: publisher.predicateType, subject: [{ name: 'osv-scanner_windows_amd64.exe', digest: { sha256 } }] },
    signature: { certificate: { subjectAlternativeName: publisher.certIdentity, issuer: publisher.oidcIssuer, sourceRepositoryURI: 'https://github.com/google/osv-scanner',
      sourceRepositoryRef: sourceRef, sourceRepositoryDigest: sourceDigest, runnerEnvironment: 'github-hosted' } } } }]);
}
const ref = (raw: unknown) => runtimePolicyRef(parseRuntimePolicy2(raw));

for (const stage of ['version', 'attestation'] as const) for (const stop of ['timeout', 'cancelled'] as const) {
  test(`job disk final: Windows provenance ${stage} ${stop} keeps the unkeyed outcome`, { skip: process.platform !== 'win32' }, async () => {
    const policy = parseRuntimePolicy2(policy2({ path: fresh('unused-ledger'), entries: 0, head: '0'.repeat(64) }));
    const check = { component: 'osv' as const, file: osv.path, ledgerSeq: 1, bundle: sigstore.bundle, trustedRoot: sigstore.trustedRoot,
      expected: { ...publisher, runner: 'github-hosted' as const, sha256: osv.sha256, sourceRef, sourceDigest } };
    try {
      for (const keyed of [false, true]) {
        const abort = new AbortController(), waiting: GhBehavior = { kind: 'wait', started: stop === 'cancelled' ? () => abort.abort() : undefined };
        ghVersion = stage === 'version' ? waiting : { kind: 'exit', code: 0, stdout: 'gh version 2.94.0' };
        gh = stage === 'attestation' ? waiting : { kind: 'exit', code: 0, stdout: verifiedJson() };
        const disk = keyed ? new JobDisk(1024 * 1024) : undefined;
        assert.equal(await withJobDisk(disk, () => verifyPublisher(policy, check, { root: target, timeoutMs: 50, signal: abort.signal })), 'failed', `keyed=${keyed}`);
        assert.equal(disk?.cause, undefined);
      }
    } finally { ghVersion = { kind: 'exit', code: 0, stdout: 'gh version 2.94.0' }; gh = { kind: 'exit', code: 0, stdout: verifiedJson() }; }
  });
}

for (const stage of ['version', 'attestation'] as const) for (const diskStop of [false, true]) {
  test(`job disk final: Windows provenance ${stage} propagates only a disk-initiated stop, diskStop=${diskStop}`, { skip: process.platform !== 'win32' }, async t => {
    const policy = parseRuntimePolicy2(policy2({ path: fresh('unused-ledger'), entries: 0, head: '0'.repeat(64) }));
    const check = { component: 'osv' as const, file: osv.path, ledgerSeq: 1, bundle: sigstore.bundle, trustedRoot: sigstore.trustedRoot,
      expected: { ...publisher, runner: 'github-hosted' as const, sha256: osv.sha256, sourceRef, sourceDigest } };
    const abort = new AbortController(), disk = new JobDisk(1024 * 1024), missing = fresh('missing-root');
    const waiting: GhBehavior = { kind: 'wait', started: () => diskStop ? disk.register(missing) : abort.abort() };
    let finishes = 0;
    t.mock.method(disk, 'watch', () => async () => {
      if (!diskStop && ++finishes === (stage === 'version' ? 1 : 2)) disk.register(missing);
      await disk.check().catch(() => {});
    });
    ghVersion = stage === 'version' ? waiting : { kind: 'exit', code: 0, stdout: 'gh version 2.94.0' };
    gh = stage === 'attestation' ? waiting : { kind: 'exit', code: 0, stdout: verifiedJson() };
    try {
      const result = withJobDisk(disk, () => verifyPublisher(policy, check, { root: target, timeoutMs: 1000, signal: abort.signal }));
      if (diskStop) await assert.rejects(result, { code: 'termination_unverified' });
      else assert.equal(await result, 'failed');
      assert.equal(disk.cause, 'job_disk_observation_unverified');
    } finally { ghVersion = { kind: 'exit', code: 0, stdout: 'gh version 2.94.0' }; gh = { kind: 'exit', code: 0, stdout: verifiedJson() }; }
  });
}

test('a v1 policy through admitRuntime keeps the stop/deny decision and starts no process', async () => {
  const v1 = (state: 'active' | 'stopped') => parseRuntimePolicy({ schema: 'scanmux.runtime-policy/v1', id, revision: 1, state, deny: [] });
  launches.length = 0;
  await assert.rejects(admitRuntime(v1('stopped'), [{ component: 'osv', sha256: osv.sha256, file: osv.path }], { timeoutMs: 1000 }), { code: 'runtime_policy_stopped' });
  await admitRuntime(v1('active'), [{ component: 'osv', sha256: osv.sha256, file: osv.path }], { timeoutMs: 1000 });
  assert.deepEqual(launches, []);
});

test('Config2 accepts policy v2 and refuses a verifier or ledger inside the target', async () => {
  const pin = { path: path.join(fixture, 'absent-ledger.jsonl'), entries: 0, head: '0'.repeat(64) };
  const loaded = await loadConfig(await configFile(policy2(pin)), undefined, { runtimePolicy: 'accept' });
  assert.equal(loaded.schema, 2);
  assert.deepEqual(loaded.schema === 2 && loaded.runtimePolicy, parseRuntimePolicy2(policy2(pin)));
  await assert.rejects(loadConfig(await configFile(policy2(pin))), { code: 'runtime_policy_entry_unsupported' });
  await assert.rejects(loadConfig(await configFile(policy2({ ...pin, path: path.join(target, 'ledger.jsonl') })), target, { runtimePolicy: 'accept' }), { code: 'provenance_ledger_inside_target' });
  const inside = { ...policy2(pin), provenance: { ...policy2(pin).provenance, verifier: { path: path.join(target, 'gh.exe'), sha256: node.sha256, version: '2.94.0' } } };
  await assert.rejects(loadConfig(await configFile(inside), target, { runtimePolicy: 'accept' }), { code: 'provenance_verifier_inside_target' });
});

test('ledger mismatch, unrecorded, unverifiable, stopped and gh deny refuse before gh or any engine starts', async () => {
  const none = await ledgerFile([fields('osv', osv.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' })]);
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]);
  const empty = { path: fresh('empty.jsonl'), entries: 0, head: '0'.repeat(64) };
  const cases: [unknown, string, unknown][] = [
    [policy2({ ...none, head: 'c'.repeat(64) }), 'provenance_ledger_mismatch', undefined],
    [policy2(empty), 'provenance_unrecorded_osv', { component: 'osv', state: 'unrecorded', reason: 'not_in_ledger', ledgerSeq: null }],
    [policy2(none), 'provenance_unverifiable_osv', { component: 'osv', state: 'unverifiable', reason: 'publisher_evidence_unpublished', ledgerSeq: 1 }],
    [policy2(empty, {}, [{ component: 'gitleaks', level: 'recorded' }]), 'provenance_unrecorded_gitleaks', { component: 'gitleaks', state: 'unrecorded', reason: 'not_in_ledger', ledgerSeq: null }],
    [policy2(signed, { state: 'stopped' }), 'runtime_policy_stopped', undefined],
    [policy2(signed, { deny: [{ kind: 'component', component: 'gh' }] }), 'runtime_policy_denied_gh_component', undefined],
  ];
  for (const [raw, code, engine] of cases) {
    const result = await invoke(['doctor', '--config', await configFile(raw)]);
    assert.equal(result.exitCode, 4, code);
    const error = failure(result.error);
    assert.equal(error.error, code);
    assert.deepEqual(error.engine, engine, code);
    if (code !== 'provenance_ledger_mismatch') assert.deepEqual(error.policy, ref(raw), code);
    assert.deepEqual(result.launches, [], code);
  }
});

test('on Windows a missing process owner refuses before gh starts, after a policy refusal', { skip: process.platform !== 'win32' }, async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]);
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  for (const [raw, code] of [[policy2(signed), 'process_containment_unavailable'], [policy2(signed, { state: 'stopped' }), 'runtime_policy_stopped']] as const) {
    const file = fresh('config.json');
    await fs.writeFile(file, JSON.stringify({ schema: 2, runtimePolicy: raw, tools }));
    const result = await invoke(['doctor', '--config', file]);
    assert.equal(result.exitCode, 4, code);
    assert.equal(failure(result.error).error, code);
    assert.deepEqual(result.launches, [], code);
  }
});

test('gh outcomes decide admission: only a matching structured result on exit 0 lets the engines start', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]), raw = policy2(signed), config = await configFile(raw);
  process.env.GH_TOKEN = 'synthetic-token-that-must-not-reach-gh';
  try {
    gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
    const verified = await invoke(['doctor', '--config', config]);
    assert.doesNotMatch(verified.error, /provenance|tool_digest/);
    const [call] = ghLaunches(verified);
    assert.equal(ghLaunches(verified).length, 1);
    assert.equal(call.file, ghPath);
    const workspace = path.dirname(call.args[2]);
    assert.deepEqual(call.args, ['attestation', 'verify', path.join(workspace, 'artifact'), '--bundle', path.join(workspace, 'bundle.jsonl'),
      '--custom-trusted-root', path.join(workspace, 'trusted-root.jsonl'), '--repo', 'google/osv-scanner', '--source-ref', sourceRef, '--source-digest', sourceDigest,
      '--cert-identity', publisher.certIdentity, '--cert-oidc-issuer', publisher.oidcIssuer, '--predicate-type', publisher.predicateType,
      '--deny-self-hosted-runners', '--format', 'json']);
    assert.equal(call.cwd, workspace); assert.equal(call.env?.HOME, workspace); assert.equal(call.env?.USERPROFILE, workspace);
    assert.ok(!Object.keys(call.env ?? {}).some(key => /TOKEN|GH_|GITHUB/i.test(key)), 'no token or gh variables reach the verifier');
    assert.ok(within(temporary, workspace) && !within(target, workspace));
    for (const copy of ghCopies) await assert.rejects(fs.access(copy), 'verification copies are removed');
    const [engine] = engineLaunches(verified);
    assert.ok(engine && verified.launches.indexOf(engine) > verified.launches.indexOf(call), 'engines started after verification');

    const refusals: [GhBehavior, string, string][] = [
      [{ kind: 'exit', code: 0, stdout: verifiedJson('e'.repeat(64)) }, 'provenance_unverifiable_osv', 'verifier_failed'],
      [{ kind: 'exit', code: 0, stdout: 'not json' }, 'provenance_unverifiable_osv', 'verifier_failed'],
      [{ kind: 'exit', code: 1, stdout: '' }, 'provenance_invalid_osv', 'signature_rejected'],
      [{ kind: 'spawn_error' }, 'provenance_unverifiable_osv', 'verifier_failed'],
    ];
    for (const [behavior, code, reason] of refusals) {
      gh = behavior;
      const result = await invoke(['doctor', '--config', config]);
      assert.equal(result.exitCode, 4, code);
      assert.deepEqual(failure(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: code, policy: ref(raw),
        engine: { component: 'osv', state: code === 'provenance_invalid_osv' ? 'invalid' : 'unverifiable', reason, ledgerSeq: 1 } }, code);
      assert.equal(ghLaunches(result).length, 1, code);
      assert.deepEqual(engineLaunches(result), [], code);
      for (const copy of ghCopies) await assert.rejects(fs.access(copy), code);
    }
  } finally { delete process.env.GH_TOKEN; }
});

test('a replaced artifact or changed evidence refuses before gh and before any engine', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]), raw = policy2(signed), config = await configFile(raw);
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  await fs.writeFile(osvPath, 'replaced osv artifact bytes');
  try {
    const replaced = await invoke(['doctor', '--config', config]);
    assert.deepEqual(failure(replaced.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'provenance_unverifiable_osv', policy: ref(raw),
      engine: { component: 'osv', state: 'unverifiable', reason: 'artifact_changed', ledgerSeq: 1 } });
    assert.ok(!replaced.launches.some(launch => launch.file === ghPath)); assert.deepEqual(engineLaunches(replaced), []);
  } finally { await fs.writeFile(osvPath, osvBytes); }
  await fs.writeFile(bundlePath, 'tampered bundle');
  try {
    const changed = await invoke(['doctor', '--config', config]);
    assert.deepEqual(failure(changed.error).engine, { component: 'osv', state: 'unverifiable', reason: 'evidence_changed', ledgerSeq: 1 });
    assert.equal(failure(changed.error).error, 'provenance_unverifiable_osv');
    assert.deepEqual(ghLaunches(changed), []); assert.deepEqual(engineLaunches(changed), []);
  } finally { await fs.writeFile(bundlePath, 'synthetic bundle'); }
});

async function request(value: Record<string, unknown>) {
  const file = fresh('request.json');
  await fs.writeFile(file, JSON.stringify({ schema: 'scanmux.engine-record/v1', platform: 'windows-x64', change: 'upgrade', ...value }));
  return file;
}
const none = { kind: 'none', reason: 'publisher_evidence_unpublished' };
const signedRequest = { component: 'osv', version: '2.3.0', artifact: osvPath, evidence: { kind: 'sigstore-slsa', bundle: bundlePath, trustedRoot: rootPath, sourceRef, sourceDigest } };

test('engine-record appends once, is idempotent, and its paste values admit the recorded engine', async () => {
  const pin = { path: fresh('ledger.jsonl'), entries: 0, head: '0'.repeat(64) };
  const require = [{ component: 'osv', level: 'publisher', publisher }, { component: 'gitleaks', level: 'recorded' }];
  const first = await invoke(['engine-record', await request({ component: 'gitleaks', version: '8.30.1', artifact: node.path, evidence: none }), '--config', await configFile(policy2(pin, {}, require)), '--json']);
  assert.equal(first.exitCode, 0, first.error);
  const appended = JSON.parse(first.output);
  const bytes = await fs.readFile(pin.path), line = bytes.toString('utf8').trimEnd();
  assert.deepEqual(appended, { schema: 'scanmux.engine-record-result/v1', state: 'appended', seq: 1,
    paste: { tool: { path: node.path, sha256: node.sha256, version: '8.30.1' }, ledger: { path: pin.path, entries: 1, head: hash(line) } }, authenticatedHistory: false });
  assert.equal(JSON.parse(line).recordedBy.verifier, null);
  assert.deepEqual(first.launches, []);

  const again = await invoke(['engine-record', await request({ component: 'gitleaks', version: '8.30.1', artifact: node.path, evidence: none, change: 'rerun' }), '--config', await configFile(policy2(appended.paste.ledger, {}, require)), '--json']);
  assert.equal(JSON.parse(again.output).state, 'existing'); assert.equal(JSON.parse(again.output).seq, 1);
  assert.deepEqual(await fs.readFile(pin.path), bytes);

  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  const signed = await invoke(['engine-record', await request(signedRequest), '--config', await configFile(policy2(appended.paste.ledger, {}, require)), '--json']);
  assert.equal(signed.exitCode, 0, signed.error);
  const second = JSON.parse(signed.output);
  assert.equal(second.seq, 2); assert.equal(ghLaunches(signed).length, 1);
  assert.deepEqual(second.paste.tool, { path: osvPath, sha256: osv.sha256, version: '2.3.0' });
  const stored = JSON.parse((await fs.readFile(pin.path, 'utf8')).trimEnd().split('\n')[1]);
  assert.deepEqual(stored.evidence, sigstore);
  assert.deepEqual(stored.recordedBy.verifier, { sha256: ghTool.sha256, version: '2.94.0' });

  const admitted = await invoke(['doctor', '--config', await configFile(policy2(second.paste.ledger, {}, require))]);
  assert.doesNotMatch(admitted.error, /provenance/);
  assert.ok(engineLaunches(admitted).length > 0, 'the pasted pins admit osv');

  const text = await invoke(['engine-record', await request(signedRequest), '--config', await configFile(policy2(second.paste.ledger, {}, require))]);
  assert.match(text.output, /existing seq=2/); assert.match(text.output, /not an authenticated history/);
  assert.deepEqual(ghLaunches(text), [], 'an idempotent rerun does not verify again');
});

test('engine-record refuses without changing the ledger on failed verification, damaged tails, mismatched pins, locks and stop', async () => {
  const pin = await ledgerFile([fields('gitleaks', node.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' })]);
  const before = await fs.readFile(pin.path);
  const record = async (raw: unknown, value: Record<string, unknown> = signedRequest) => invoke(['engine-record', await request(value), '--config', await configFile(raw)]);
  const unchanged = async (label: string) => assert.deepEqual(await fs.readFile(pin.path), before, label);

  gh = { kind: 'exit', code: 1, stdout: '' };
  const rejected = await record(policy2(pin));
  assert.deepEqual(failure(rejected.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'provenance_invalid_osv', policy: ref(policy2(pin)),
    engine: { component: 'osv', state: 'invalid', reason: 'signature_rejected', ledgerSeq: null } });
  await unchanged('rejected signature');
  gh = { kind: 'exit', code: 0, stdout: verifiedJson('e'.repeat(64)) };
  assert.equal(failure((await record(policy2(pin))).error).error, 'provenance_unverifiable_osv');
  await unchanged('mismatching verifier output');

  assert.equal(failure((await record(policy2(pin, {}, [{ component: 'gitleaks', level: 'recorded' }]))).error).error, 'engine_record_publisher_unrequired');
  assert.equal(failure((await record(policy2(pin, { state: 'stopped' }), { component: 'gitleaks', version: '8.30.1', artifact: node.path, evidence: none })).error).error, 'runtime_policy_stopped');
  assert.equal(failure((await record(policy2({ ...pin, head: 'c'.repeat(64) }), { component: 'gitleaks', version: '8.30.1', artifact: node.path, evidence: none })).error).error, 'provenance_ledger_mismatch');
  await unchanged('policy refusals');

  await fs.writeFile(pin.path + '.lock', '');
  assert.equal(failure((await record(policy2(pin), { component: 'osv', version: '2.3.0', artifact: osvPath, evidence: none })).error).error, 'engine_ledger_locked');
  await fs.rm(pin.path + '.lock');
  await unchanged('held lock');

  for (const tail of ['{"seq":2', '{"seq":2}\n', 'x\n']) {
    await fs.writeFile(pin.path, Buffer.concat([before, Buffer.from(tail)]));
    const torn = await record(policy2(pin), { component: 'osv', version: '2.3.0', artifact: osvPath, evidence: none });
    assert.equal(failure(torn.error).error, 'engine_ledger_tail_invalid', JSON.stringify(tail));
    assert.deepEqual(await fs.readFile(pin.path), Buffer.concat([before, Buffer.from(tail)]), 'no automatic repair');
    await assert.rejects(fs.access(pin.path + '.lock'), 'the lock is released');
  }
  await fs.writeFile(pin.path, before);
  assert.equal(failure((await record(policy2(pin), { component: 'osv', version: '2.3.0', artifact: osvPath, evidence: none, schema: 'other' })).error).error, 'engine_record_request_invalid');
  assert.equal(failure((await invoke(['engine-record', await request({ component: 'osv', version: '2.3.0', artifact: osvPath, evidence: none }), '--config', await (async () => {
    const file = fresh('v1.json'); await fs.writeFile(file, JSON.stringify(withTestProcessOwner({ schema: 2, runtimePolicy: { schema: 'scanmux.runtime-policy/v1', id, revision: 1, state: 'active', deny: [] }, tools }))); return file;
  })()])).error).error, 'engine_ledger_policy_v2_required');
  await unchanged('request refusals');
});

test('engine-history reads the pinned prefix and derives current, superseded and denied', async () => {
  const old = 'b'.repeat(64);
  const pin = await ledgerFile([
    fields('gitleaks', old, { kind: 'none', reason: 'publisher_evidence_unpublished' }),
    fields('gitleaks', node.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' }),
    fields('osv', osv.sha256, sigstore),
  ]);
  await fs.appendFile(pin.path, 'unpinned torn tail');
  const raw = policy2(pin, { deny: [{ kind: 'digest', component: 'osv', sha256: osv.sha256 }] });
  const result = await invoke(['engine-history', '--config', await configFile(raw), '--json']);
  assert.equal(result.exitCode, 0, result.error);
  const history = JSON.parse(result.output);
  assert.deepEqual(history.ledger, pin); assert.equal(history.authenticatedHistory, false);
  assert.deepEqual(history.entries.map((entry: { seq: number; component: string; evidence: string; status: string }) => [entry.seq, entry.component, entry.evidence, entry.status]),
    [[1, 'gitleaks', 'none', 'superseded'], [2, 'gitleaks', 'none', 'current'], [3, 'osv', 'sigstore-slsa', 'denied']]);
  assert.deepEqual(result.launches, []);
  const text = await invoke(['engine-history', '--config', await configFile(raw)]);
  assert.match(text.output, /3 pinned entries/); assert.match(text.output, /status=denied/);
  const mismatched = await invoke(['engine-history', '--config', await configFile(policy2({ ...pin, head: 'c'.repeat(64) }))]);
  assert.equal(mismatched.exitCode, 4); assert.equal(failure(mismatched.error).error, 'provenance_ledger_mismatch');
});

test('a missing, replaced or wrong-version gh and unreadable copies refuse with the engine, before any engine starts', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]);
  const otherGh = fresh('gh.exe');
  await fs.writeFile(otherGh, 'another gh');
  const withVerifier = (verifier: unknown) => ({ ...policy2(signed), provenance: { ...policy2(signed).provenance, verifier } });
  const unverifiable = (reason: string, ledgerSeq: number | null = 1) => ({ component: 'osv', state: 'unverifiable', reason, ledgerSeq });
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  const cases: [string, unknown, unknown, string][] = [
    ['gh absent', withVerifier({ ...ghTool, path: fresh('absent-gh.exe') }), tools, 'verifier_failed'],
    ['gh replaced', withVerifier({ ...ghTool, path: otherGh }), tools, 'verifier_failed'],
    ['artifact unreadable', policy2(signed), { ...tools, osv: { ...osv, path: fresh('absent-osv.exe') } }, 'artifact_unreadable'],
  ];
  for (const [label, raw, toolSet, reason] of cases) {
    const result = await invoke(['doctor', '--config', await configFile(raw, toolSet)]);
    assert.deepEqual(failure(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'provenance_unverifiable_osv', policy: ref(raw), engine: unverifiable(reason) }, label);
    assert.deepEqual(ghLaunches(result), [], label); assert.deepEqual(engineLaunches(result), [], label);
  }
  ghVersion = { kind: 'exit', code: 0, stdout: 'gh version 2.93.0 (2026-08-01)' };
  try {
    const old = await invoke(['doctor', '--config', await configFile(policy2(signed))]);
    assert.deepEqual(failure(old.error).engine, unverifiable('verifier_failed'));
    assert.equal(old.launches.filter(launch => launch.file === ghPath).length, 1, 'only the version probe ran');
    assert.deepEqual(engineLaunches(old), []);
  } finally { ghVersion = { kind: 'exit', code: 0, stdout: 'gh version 2.94.0 (2026-09-01)' }; }

  const lost = fresh('lost.intoto.jsonl');
  await fs.writeFile(lost, 'synthetic bundle');
  const lostLedger = await ledgerFile([fields('osv', osv.sha256, { ...sigstore, bundle: { path: lost, sha256: hash('synthetic bundle') } })]);
  await fs.rm(lost);
  const missing = await invoke(['doctor', '--config', await configFile(policy2(lostLedger))]);
  assert.deepEqual(failure(missing.error).engine, unverifiable('evidence_unreadable'));
  assert.deepEqual(ghLaunches(missing), []); assert.deepEqual(engineLaunches(missing), []);
});

test('evidence paths must be host-local for admission and for engine-record, even without a target root', async () => {
  const remotes = process.platform === 'win32' ? ['\\\\server\\share\\osv.intoto.jsonl', '\\\\?\\' + bundlePath] : ['//server/share/osv.intoto.jsonl'];
  for (const bundle of remotes) {
    const remote = await ledgerFile([fields('osv', osv.sha256, { ...sigstore, bundle: { path: bundle, sha256: sigstore.bundle.sha256 } })]);
    const admitted = await invoke(['doctor', '--config', await configFile(policy2(remote))]);
    assert.equal(failure(admitted.error).error, 'provenance_evidence_not_local', bundle);
    assert.deepEqual(admitted.launches, [], bundle);

    const pin = await ledgerFile([fields('gitleaks', node.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' })]), before = await fs.readFile(pin.path);
    const recorded = await invoke(['engine-record', await request({ ...signedRequest, evidence: { ...signedRequest.evidence, bundle } }), '--config', await configFile(policy2(pin))]);
    assert.equal(failure(recorded.error).error, 'provenance_evidence_not_local', bundle);
    assert.deepEqual(await fs.readFile(pin.path), before, bundle); assert.deepEqual(recorded.launches, [], bundle);
  }
});

test('the bundle copy is bundle.json for a .json bundle in any case and bundle.jsonl for any other', async () => {
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  for (const [name, copy] of [['osv.sigstore.json', 'bundle.json'], ['osv.sigstore.JSON', 'bundle.json'], ['osv.intoto.JSONL', 'bundle.jsonl'], ['osv.sigstore', 'bundle.jsonl'], ['osv.bundle', 'bundle.jsonl']]) {
    const file = fresh(name);
    await fs.writeFile(file, 'synthetic bundle');
    const signed = await ledgerFile([fields('osv', osv.sha256, { ...sigstore, bundle: { path: file, sha256: hash('synthetic bundle') } })]);
    const result = await invoke(['doctor', '--config', await configFile(policy2(signed))]);
    assert.doesNotMatch(result.error, /provenance/, name);
    assert.equal(path.basename(ghCopies[1]), copy, name);
  }
});

test('engine-record takes a bundle path only with a .json or .jsonl extension, in any case', async () => {
  const pin = await pinFor(), before = await fs.readFile(pin.path);
  for (const name of ['osv.sigstore', 'osv.bundle', 'osv', 'osv.json.txt']) {
    const file = fresh(name);
    await fs.writeFile(file, 'synthetic bundle');
    const refused = await record(pin, { ...signedRequest, evidence: { ...signedRequest.evidence, bundle: file } });
    assert.equal(failure(refused.error).error, 'engine_record_request_invalid', name);
    assert.deepEqual(refused.launches, [], name);
  }
  assert.deepEqual(await fs.readFile(pin.path), before);
  gh = { kind: 'exit', code: 1, stdout: '' };
  const upper = fresh('osv.sigstore.JSON');
  await fs.writeFile(upper, 'synthetic bundle');
  const accepted = await record(pin, { ...signedRequest, evidence: { ...signedRequest.evidence, bundle: upper } });
  assert.notEqual(failure(accepted.error).error, 'engine_record_request_invalid');
  assert.equal(ghLaunches(accepted).length, 1);
  assert.equal(path.basename(ghCopies[1]), 'bundle.json');
  assert.deepEqual(await fs.readFile(pin.path), before);
});

const pinFor = async () => ledgerFile([fields('gitleaks', node.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' })]);
const unsigned = { component: 'osv', version: '2.3.0', artifact: osvPath, evidence: none };
const record = async (ledger: { path: string; entries: number; head: string }, value: Record<string, unknown> = unsigned) =>
  invoke(['engine-record', await request(value), '--config', await configFile(policy2(ledger))]);

test('engine-record takes only the config tool version form', async () => {
  const pin = await pinFor(), before = await fs.readFile(pin.path);
  for (const version of ['v2.3.0', '2.3', '2.3.0-rc.1']) assert.equal(failure((await record(pin, { ...unsigned, version })).error).error, 'engine_record_request_invalid', version);
  assert.deepEqual(await fs.readFile(pin.path), before);
});

test('engine-record refuses valid lines after the pinned ones and leaves the ledger unchanged', async () => {
  const longer = await ledgerFile([fields('gitleaks', node.sha256, { kind: 'none', reason: 'publisher_evidence_unpublished' }), fields('gitleaks', 'b'.repeat(64), { kind: 'none', reason: 'publisher_evidence_unpublished' })]);
  const longerBytes = await fs.readFile(longer.path), firstHead = hash(longerBytes.toString('utf8').split('\n')[0]);
  const wholeHead = hash(longerBytes.toString('utf8').trimEnd().split('\n')[1]), stale = { path: longer.path, entries: 1, head: firstHead };
  const expected = { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'engine_ledger_unpinned_tail',
    ledger: { entries: 2, head: wholeHead, unpinned: [{ seq: 2, component: 'gitleaks', sha256: 'b'.repeat(64), change: 'synthetic' }] } };
  const json = await invoke(['engine-record', await request(unsigned), '--config', await configFile(policy2(stale)), '--json']);
  assert.equal(json.exitCode, 4); assert.equal(json.output, '');
  assert.deepEqual(failure(json.error), expected);
  const text = await record(stale), lines = text.error.trimEnd().split('\n');
  assert.equal(text.exitCode, 4);
  assert.match(lines[0], /refused; the ledger has 1 valid lines after the pin and was not changed/);
  assert.equal(lines[1], `Unpinned line: seq=2 component=gitleaks sha256=${'b'.repeat(64)} change=synthetic`);
  assert.equal(lines[2], `Whole ledger: entries=2 head=${wholeHead}`);
  assert.deepEqual(failure(lines[3]), expected);
  assert.deepEqual(await fs.readFile(longer.path), longerBytes); await assert.rejects(fs.access(longer.path + '.lock'));
  const repinned = await invoke(['engine-record', await request(unsigned), '--config', await configFile(policy2({ path: longer.path, entries: 2, head: wholeHead })), '--json']);
  assert.equal(repinned.exitCode, 0, repinned.error);
  assert.equal(JSON.parse(repinned.output).paste.ledger.entries, 3, 'the printed pin is accepted once pasted');
});

test('a hard-linked ledger is refused by the writer under either name and by the reader', async () => {
  const linked = await pinFor(), linkedBytes = await fs.readFile(linked.path), alias = fresh('alias.jsonl');
  await fs.link(linked.path, alias);
  for (const spelled of [linked.path, alias]) assert.equal(failure((await record({ ...linked, path: spelled })).error).error, 'engine_ledger_linked', spelled);
  assert.equal(failure((await invoke(['doctor', '--config', await configFile(policy2(linked, {}, [{ component: 'gitleaks', level: 'recorded' }]))])).error).error, 'engine_ledger_linked');
  assert.deepEqual(await fs.readFile(linked.path), linkedBytes);
});

test('engine-record refuses a junction spelling', async () => {
  const directory = fresh('ledger-directory'), junction = fresh('ledger-junction');
  await fs.mkdir(directory);
  const inner = await pinFor(), innerPath = path.join(directory, 'ledger.jsonl');
  await fs.rename(inner.path, innerPath);
  const innerBytes = await fs.readFile(innerPath);
  await fs.symlink(directory, junction, 'junction');
  assert.equal(failure((await record({ ...inner, path: path.join(junction, 'ledger.jsonl') })).error).error, 'linked_path');
  assert.deepEqual(await fs.readFile(innerPath), innerBytes);
});

test('engine-record locks the physical ledger under another case spelling', { skip: process.platform === 'win32' ? false : 'case-insensitive paths are Windows-only' }, async () => {
  const inner = await pinFor();
  await fs.writeFile(inner.path + '.lock', '');
  try { assert.equal(failure((await record({ ...inner, path: inner.path.toUpperCase() })).error).error, 'engine_ledger_locked'); }
  finally { await fs.rm(inner.path + '.lock'); }
});

test('engine-record refuses a ledger replaced while gh verifies', async () => {
  const swapped = await pinFor(), swappedBytes = await fs.readFile(swapped.path);
  gh = { kind: 'exit', code: 0, stdout: verifiedJson() };
  duringVerification = () => { writeFileSync(swapped.path + '.new', swappedBytes); renameSync(swapped.path + '.new', swapped.path); };
  try {
    const raced = await invoke(['engine-record', await request(signedRequest), '--config', await configFile(policy2(swapped))]);
    assert.equal(failure(raced.error).error, 'engine_ledger_changed');
    assert.equal(ghLaunches(raced).length, 1, 'the ledger was replaced while gh verified');
  } finally { duringVerification = null; }
  assert.deepEqual(await fs.readFile(swapped.path), swappedBytes); await assert.rejects(fs.access(swapped.path + '.lock'));
});
test('serve refuses a policy v2 Config2 before any process starts', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]);
  const result = await invoke(['serve', '--config', await configFile(policy2(signed))]);
  assert.deepEqual(failure(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4, error: 'runtime_policy_entry_unsupported' });
  assert.deepEqual(result.launches, []);
});

test('configured copy refusal escapes publisher admission with the disk cause before gh starts', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]);
  const file = await configFile(policy2(signed));
  const config = JSON.parse(await fs.readFile(file, 'utf8')); config.maxCopyBytes = 1;
  await fs.writeFile(file, JSON.stringify(config));
  const result = await invoke(['scan', target, '--config', file, '--json']);
  assert.equal(result.exitCode, 3);
  assert.deepEqual(failure(result.error), { schema: 'scanmux.error/v1', gate: 'INCOMPLETE', exitCode: 3, error: 'job_disk_copy_limit' });
  assert.deepEqual(ghLaunches(result), []); assert.deepEqual(engineLaunches(result), []);
});

test('copy budget: missing provenance artifact keeps artifact_unreadable refusal', async () => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]), raw = policy2(signed);
  const file = await configFile(raw, { ...tools, osv: { ...osv, path: fresh('absent-budget-osv.exe') } });
  const config = JSON.parse(await fs.readFile(file, 'utf8')); config.maxCopyBytes = 10485760;
  await fs.writeFile(file, JSON.stringify(config));
  const result = await invoke(['doctor', '--config', file]);
  assert.equal(result.exitCode, 4);
  assert.deepEqual(failure(result.error), { schema: 'scanmux.error/v1', gate: 'ERROR', exitCode: 4,
    error: 'provenance_unverifiable_osv', policy: ref(raw),
    engine: { component: 'osv', state: 'unverifiable', reason: 'artifact_unreadable', ledgerSeq: 1 } });
  assert.deepEqual(ghLaunches(result), []); assert.deepEqual(engineLaunches(result), []);
});

test('copy budget: provenance evidence lost during copying keeps evidence_unreadable', async t => {
  const signed = await ledgerFile([fields('osv', osv.sha256, sigstore)]), policy = parseRuntimePolicy2(policy2(signed));
  const original = CopyBudget.prototype.copy;
  t.mock.method(CopyBudget.prototype, 'copy', function (this: CopyBudget, source: string, destination: string, options: Parameters<typeof original>[2]) {
    if (source === bundlePath) throw Object.assign(new Error('fixture unreadable bundle'), { code: 'EACCES' });
    return original.call(this, source, destination, options);
  });
  await assert.rejects(withCopyBudget(1048576, () => admitRuntime(policy, [{ component: 'osv', sha256: osv.sha256, file: osv.path }], { timeoutMs: 1000 })),
    error => error instanceof Error && 'engine' in error && (error.engine as { reason: string }).reason === 'evidence_unreadable');
});
