import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { canonical, hash, SafeError, within } from '../src/safety.ts';
import { hostCommandPlan, scanHostJob } from '../src/host-job.ts';
import { loadJobProfile } from '../src/job-config.ts';
import { nextLedgerLine, type LedgerEntry, type LedgerFields } from '../src/engine-ledger.ts';

// The owner is a fake: spawn() of its path answers --version and the job launch from in-process streams.
let ownerPath = '', launchDelayMs = 0, launched = 0;
let ghPath = '', ghDelayMs = 0, ghDeadlineAt = 0, ghStallAfterCall = 2;
let ghAbortAfterStall: AbortController | undefined;
const ghCalls: { startedAt: number; elapsedMs?: number }[] = [];
const publisher = { repository: 'scanmux/fixture', certIdentity: 'https://github.com/scanmux/fixture/.github/workflows/release.yml@refs/tags/v1.0.0',
  oidcIssuer: 'https://token.actions.githubusercontent.com', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted' };
const sourceRef = 'refs/tags/v1.0.0', sourceDigest = 'a'.repeat(40);
function fakeGh(args: readonly string[]) {
  const call = { startedAt: performance.now(), elapsedMs: undefined as number | undefined };
  ghCalls.push(call);
  const callNumber = ghCalls.length;
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), pid: 4243 });
  let done = false;
  const close = (code: number | null, signal: string | null) => {
    if (done) return; done = true;
    call.elapsedMs = performance.now() - call.startedAt;
    child.stdout.end(); child.stderr.end();
    setImmediate(() => {
      child.emit('exit', code, signal); child.emit('close', code, signal);
      // Model scheduling/I/O between successful calls: the process has closed and its timeout is cleared.
      // Expire the window here so this case tests a refusal to START gh, rather than an in-flight provenance refusal.
      if (code === 0 && callNumber === ghStallAfterCall && ghDeadlineAt) {
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, ghDeadlineAt + 25 - performance.now()));
        ghAbortAfterStall?.abort();
      }
    });
  };
  const timer = setTimeout(() => {
    child.stdout.write(args[0] === '--version' ? 'gh version 2.94.0\n' : JSON.stringify([{ verificationResult: {
      statement: { predicateType: publisher.predicateType, subject: [{ digest: { sha256: hash(readFileSync(args[2])) } }] },
      signature: { certificate: { subjectAlternativeName: publisher.certIdentity, issuer: publisher.oidcIssuer,
        sourceRepositoryURI: `https://github.com/${publisher.repository}`, sourceRepositoryRef: sourceRef,
        sourceRepositoryDigest: sourceDigest, runnerEnvironment: publisher.runner } },
    } }]));
    close(0, null);
  }, ghDelayMs);
  Object.assign(child, { kill: () => { clearTimeout(timer); close(null, 'SIGTERM'); return true; } });
  child.stdin.resume();
  return child;
}
function fakeOwner(args: readonly string[]) {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), pid: 4242,
    exitCode: null as number | null, signalCode: null as string | null });
  let done = false;
  const close = (code: number | null, signal: string | null) => {
    if (done) return; done = true;
    child.stdout.end(); child.stderr.end();
    setImmediate(() => { child.emit('exit', code, signal); child.emit('close', code, signal); });
  };
  let timer: NodeJS.Timeout | undefined;
  Object.assign(child, { kill: () => { clearTimeout(timer); close(null, 'SIGTERM'); return true; } });
  if (args[0] === '--version') setImmediate(() => { child.stdout.write('1.0.0\n'); close(0, null); });
  else { launched++; timer = setTimeout(() => { child.stdout.write('closed'); close(0, null); }, launchDelayMs); }
  child.stdin.resume();
  return child;
}
const original = childProcess.spawn;
(childProcess as unknown as Record<string, unknown>).spawn = function (this: unknown, ...args: unknown[]) {
  if (ownerPath && args[0] === ownerPath) return fakeOwner(args[1] as string[]);
  if (ghPath && args[0] === ghPath) return fakeGh(args[1] as string[]);
  return Reflect.apply(original, this, args);
};
syncBuiltinESMExports();

const windowsOnly = { skip: process.platform === 'win32' ? false : 'host job is Windows-only' };
const parent = tmpdir(), fixture = await fs.mkdtemp(path.join(parent, 'host-job-deadline-test-'));
test.after(async () => { try { assert.ok(within(parent, fixture)); } finally { await removeTempDirStrict(fixture, { recursive: true, force: true }); } });
const target = path.join(fixture, 'target'), temporary = path.join(fixture, 'tmp'), workspaceParent = path.join(temporary, 'scanmux-private');
await fs.mkdir(target); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;

let files = 0;
async function writeJson(value: unknown): Promise<string> {
  const file = path.join(fixture, `input-${files++}.json`);
  await fs.writeFile(file, JSON.stringify(value));
  return canonical(file);
}
async function offlineProfile() {
  const directory = await fs.mkdtemp(path.join(fixture, 'assets-'));
  const docker = path.join(directory, 'docker.exe'), gitleaks = path.join(directory, 'gitleaks.exe');
  await fs.writeFile(docker, 'synthetic docker bytes'); await fs.writeFile(gitleaks, 'synthetic gitleaks bytes');
  const tool = (name: string) => ({ path: '/opt/scanmux/' + name, sha256: '0'.repeat(63) + name.length, version: '1.2.3' });
  return writeJson({ schema: 'scanmux.job-profile/v1', name: 'deadline_v1', scope: 'offline-local',
    docker: { tool: { path: docker, sha256: hash('synthetic docker bytes'), version: '28.1.1' }, endpoint: 'npipe:////./pipe/dockerDesktopLinuxEngine' },
    image: 'sha256:' + '1'.repeat(64), runtime: { nodeVersion: '24.22.1', python: { ...tool('p'), path: '/usr/bin/python3' }, git: { ...tool('g'), path: '/usr/bin/git' } },
    tools: { gitleaks: { path: gitleaks, sha256: hash('synthetic gitleaks bytes'), version: '8.30.1' } }, osvDatabase: null,
    scan: { timeoutMs: 10000, maxOutputBytes: 1048576, maxFileBytes: 1048576, maxSnapshotBytes: 8388608, maxFiles: 1000 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 4194304 } });
}
async function owner() {
  ownerPath = path.join(await canonical(fixture), `owner-${files++}.exe`);
  await fs.writeFile(ownerPath, 'synthetic owner', { flag: 'wx' });
  return { path: ownerPath, sha256: hash('synthetic owner'), version: '1.0.0' };
}
async function hostProfile(limits: { wallMs: number; cleanupTimeoutMs: number }) {
  const node = { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node };
  return writeJson({ schema: 'scanmux.host-job-profile/v1', name: 'deadline_host', scope: 'windows-offline-local', offlineProfile: await offlineProfile(),
    owner: await owner(), node, limits: { cpuRate: 2500, memoryBytes: 536870912, ...limits } });
}
async function writtenReports(): Promise<string[]> {
  const found: string[] = [];
  for (const name of await workspaceNames()) if (name.startsWith('scanmux-')) {
    if (await fs.stat(path.join(workspaceParent, name, 'host-job.json')).then(() => true, () => false)) found.push(name);
  }
  return found;
}
async function workspaceNames(): Promise<string[]> {
  const entries = await fs.readdir(temporary);
  assert.deepEqual(entries, entries.includes('scanmux-private') ? ['scanmux-private'] : [], 'only the protected parent may remain in TEMP');
  return entries.length ? fs.readdir(workspaceParent) : [];
}
async function reset() { for (const name of await workspaceNames()) await removeTempDirStrict(path.join(workspaceParent, name), { recursive: true, force: true }); launched = 0; }
async function publisherProfile(limits: { wallMs: number; cleanupTimeoutMs: number }) {
  const profile = await hostProfile(limits), host = JSON.parse(await fs.readFile(profile, 'utf8'));
  const offline = JSON.parse(await fs.readFile(host.offlineProfile, 'utf8'));
  ghPath = path.join(await canonical(fixture), `gh-${files++}.exe`);
  await fs.writeFile(ghPath, 'synthetic gh');
  const bundle = { path: await writeJson('synthetic bundle'), sha256: hash(JSON.stringify('synthetic bundle')) };
  const trustedRoot = { path: await writeJson('synthetic root'), sha256: hash(JSON.stringify('synthetic root')) };
  const entries: LedgerEntry[] = [], chunks: Buffer[] = [];
  let head = '0'.repeat(64);
  for (const [component, tool] of [['docker', offline.docker.tool], ['gitleaks', offline.tools.gitleaks]] as const) {
    const fields: LedgerFields = { recordedAt: '2026-10-25T00:00:00.000Z', component, platform: 'windows-x64', version: tool.version,
      sha256: tool.sha256, change: 'synthetic', recordedBy: { scanmux: '0.1.0-poc.1', verifier: null },
      evidence: { kind: 'sigstore-slsa', bundle, trustedRoot, sourceRef, sourceDigest } };
    const next = nextLedgerLine(entries, fields); entries.push(next.entry); chunks.push(next.bytes); head = next.head;
  }
  const ledger = path.join(fixture, `ledger-${files++}.jsonl`);
  await fs.writeFile(ledger, Buffer.concat(chunks));
  await fs.writeFile(host.offlineProfile, JSON.stringify({ ...offline, schema: 'scanmux.job-profile/v2', runtimePolicy: {
    schema: 'scanmux.runtime-policy/v2', id: '3c9a7e21-4b5d-4f6a-8b7c-9d0e1f2a3b4c', revision: 1, state: 'active', deny: [],
    provenance: { verifier: { path: ghPath, sha256: hash(await fs.readFile(ghPath)), version: '2.94.0' },
      ledger: { path: ledger, entries: entries.length, head }, require: ['docker', 'gitleaks'].map(component => ({ component, level: 'publisher', publisher })) },
  } }));
  return profile;
}
// Milliseconds for one whole read and hash of node.exe on this machine, now.
async function nodeHashMs(): Promise<number> {
  const started = performance.now();
  createHash('sha256').update(await fs.readFile(process.execPath)).digest();
  return Math.max(1, performance.now() - started);
}

test('the command bound is the owner window plus a shared admission window', () => {
  assert.deepEqual(hostCommandPlan({ wallMs: 1000, cleanupTimeoutMs: 300 }), { admissionMs: 900, boundMs: 2200 });
  assert.deepEqual(hostCommandPlan({ wallMs: 1, cleanupTimeoutMs: 1 }), { admissionMs: 3, boundMs: 5 });
});

test('publisher checks share the admission deadline and never start gh after it', windowsOnly, async t => {
  await reset(); ghCalls.length = 0;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 2500 }, admissionMs = hostCommandPlan(limits).admissionMs;
  // Four successful gh calls would take 8000 ms, beyond the 7500 ms window; each needs only 2000 ms.
  ghDelayMs = 2000;
  const slackMs = 750, profile = await publisherProfile(limits), started = performance.now();
  ghDeadlineAt = started + admissionMs;
  let failure: unknown;
  try { await scanHostJob(target, profile, new AbortController().signal); } catch (error) { failure = error; }
  finally { ghDeadlineAt = 0; }
  const elapsed = performance.now() - started, late = ghCalls.filter(call => call.startedAt >= started + admissionMs);
  t.diagnostic(JSON.stringify({ admissionMs, slackMs, elapsedMs: elapsed, ghStartsMs: ghCalls.map(call => call.startedAt - started),
    ghDurationsMs: ghCalls.map(call => call.elapsedMs), lateStarts: late.length, ownerLaunches: launched, code: failure instanceof SafeError ? failure.code : null }));
  assert.ok(elapsed < admissionMs + slackMs, `elapsed ${elapsed} ms exceeds admission ${admissionMs} + slack ${slackMs}`);
  assert.ok(failure instanceof SafeError);
  assert.equal(failure.code, 'host_job_admission_deadline');
  assert.equal(launched, 0, 'the owner job was not launched');
  assert.equal(late.length, 0, 'no gh process starts after the deadline');
  assert.equal(ghCalls.length, 2, 'the first publisher verified before the window expired between calls');
  assert.ok(ghCalls.every(call => call.elapsedMs! < limits.cleanupTimeoutMs));
  assert.deepEqual(await workspaceNames(), [], 'publisher workspaces are removed');
});

test('expiry after gh version prevents the attestation call for the same publisher', windowsOnly, async () => {
  await reset(); ghCalls.length = 0; ghDelayMs = 0; ghStallAfterCall = 1;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 1000 }, profile = await publisherProfile(limits);
  const started = performance.now(), admissionMs = hostCommandPlan(limits).admissionMs;
  ghDeadlineAt = started + admissionMs;
  try {
    await assert.rejects(scanHostJob(target, profile, new AbortController().signal), { code: 'host_job_admission_deadline' });
  } finally { ghDeadlineAt = 0; ghStallAfterCall = 2; }
  assert.ok(performance.now() - started < admissionMs + 750);
  assert.equal(ghCalls.length, 1);
  assert.equal(launched, 0);
  assert.deepEqual(await workspaceNames(), []);
});

test('abort during publisher cleanup keeps a gh start deadline mapped to admission', windowsOnly, async t => {
  await reset(); ghCalls.length = 0; ghDelayMs = 0; ghStallAfterCall = 1;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 1000 }, profile = await publisherProfile(limits);
  const controller = new AbortController(), started = performance.now();
  ghDeadlineAt = started + hostCommandPlan(limits).admissionMs;
  const rmdir = fs.rmdir;
  let cleanups = 0;
  fs.rmdir = (async (...args: Parameters<typeof fs.rmdir>) => {
    if (typeof args[0] === 'string' && path.dirname(args[0]) === workspaceParent) {
      assert.equal(controller.signal.aborted, false, 'gh start refusal precedes cancellation');
      assert.ok(performance.now() >= ghDeadlineAt, 'the start window has expired before cleanup');
      assert.equal(ghCalls.length, 1, 'only the version call started');
      cleanups++;
      // Yield in verifyPublisher's finally before cancelling; executeDirect has already refused to start.
      await Reflect.apply(rmdir, fs, args);
      controller.abort();
      return;
    }
    return Reflect.apply(rmdir, fs, args);
  }) as typeof fs.rmdir;
  syncBuiltinESMExports();
  let failure: unknown;
  try { await scanHostJob(target, profile, controller.signal); } catch (error) { failure = error; }
  finally { fs.rmdir = rmdir; syncBuiltinESMExports(); ghDeadlineAt = 0; ghStallAfterCall = 2; }
  t.diagnostic(JSON.stringify({ cleanups, aborted: controller.signal.aborted, ghStarts: ghCalls.length,
    ownerLaunches: launched, code: failure instanceof SafeError ? failure.code : null }));
  assert.equal(cleanups, 1);
  assert.equal(controller.signal.aborted, true);
  assert.equal(launched, 0);
  assert.deepEqual(await workspaceNames(), [], 'the publisher workspace was removed before returning');
  assert.ok(failure instanceof SafeError);
  assert.equal(failure.code, 'host_job_admission_deadline');
});

test('a gh verification cut short by the remaining window keeps its provenance refusal', windowsOnly, async t => {
  await reset(); ghCalls.length = 0; ghDelayMs = 2000;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 2500 }, profile = await publisherProfile(limits);
  const started = performance.now(), admissionMs = hostCommandPlan(limits).admissionMs;
  await assert.rejects(scanHostJob(target, profile, new AbortController().signal), { code: 'provenance_unverifiable_gitleaks' });
  const elapsed = performance.now() - started;
  t.diagnostic(JSON.stringify({ admissionMs, slackMs: 750, elapsedMs: elapsed, ghStartsMs: ghCalls.map(call => call.startedAt - started),
    ghDurationsMs: ghCalls.map(call => call.elapsedMs) }));
  assert.ok(elapsed < admissionMs + 750, `elapsed ${elapsed}`);
  assert.equal(ghCalls.length, 4);
  assert.ok(ghCalls.every(call => call.startedAt < started + admissionMs));
  assert.ok(ghCalls.at(-1)!.elapsedMs! < ghDelayMs, 'the attestation call was cut to the remaining time');
  assert.equal(launched, 0);
  assert.deepEqual(await workspaceNames(), [], 'publisher workspaces are removed after a timeout too');
});

test('expiry during gh executable verification prevents either publisher call from starting', windowsOnly, async t => {
  for (const callNumber of [1, 2]) await t.test(callNumber === 1 ? 'version' : 'attestation', async () => {
    await reset(); ghCalls.length = 0; ghDelayMs = 0;
    const limits = { wallMs: 1000, cleanupTimeoutMs: 1000 }, profile = await publisherProfile(limits);
    const started = performance.now(), deadlineAt = started + hostCommandPlan(limits).admissionMs;
    const readFile = fs.readFile;
    let verified = 0, stalledAt = 0;
    // Use the existing builtin-I/O interception pattern; no production test hook is needed.
    fs.readFile = (async (...args: Parameters<typeof fs.readFile>) => {
      const bytes = await Reflect.apply(readFile, fs, args);
      if (args[0] === ghPath && ++verified === callNumber) {
        stalledAt = performance.now();
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, deadlineAt + 25 - stalledAt));
      }
      return bytes;
    }) as typeof fs.readFile;
    syncBuiltinESMExports();
    let failure: unknown;
    try { await scanHostJob(target, profile, new AbortController().signal); } catch (error) { failure = error; }
    finally { fs.readFile = readFile; syncBuiltinESMExports(); }
    t.diagnostic(JSON.stringify({ callNumber, stalledAtMs: stalledAt - started, ghStartsMs: ghCalls.map(call => call.startedAt - started),
      lateStarts: ghCalls.filter(call => call.startedAt >= deadlineAt).length, code: failure instanceof SafeError ? failure.code : null }));
    assert.ok(stalledAt > started && stalledAt < deadlineAt, 'tool verification began within the admission window');
    assert.equal(ghCalls.filter(call => call.startedAt >= deadlineAt).length, 0, 'no gh process starts after executable verification crosses the deadline');
    assert.ok(failure instanceof SafeError);
    assert.equal(failure.code, 'host_job_admission_deadline');
    assert.equal(ghCalls.length, callNumber - 1);
    assert.equal(launched, 0);
    assert.deepEqual(await workspaceNames(), []);
  });
});

test('abort and expiry between gh calls keep the provenance cancellation refusal', windowsOnly, async t => {
  await reset(); ghCalls.length = 0; ghDelayMs = 0; ghStallAfterCall = 1;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 1000 }, profile = await publisherProfile(limits);
  const controller = new AbortController(), started = performance.now();
  ghDeadlineAt = started + hostCommandPlan(limits).admissionMs;
  ghAbortAfterStall = controller;
  let failure: unknown;
  try { await scanHostJob(target, profile, controller.signal); } catch (error) { failure = error; }
  finally { ghDeadlineAt = 0; ghStallAfterCall = 2; ghAbortAfterStall = undefined; }
  t.diagnostic(JSON.stringify({ aborted: controller.signal.aborted, elapsedMs: performance.now() - started,
    ghStarts: ghCalls.length, code: failure instanceof SafeError ? failure.code : null }));
  assert.equal(controller.signal.aborted, true);
  assert.ok(performance.now() - started >= hostCommandPlan(limits).admissionMs);
  assert.ok(failure instanceof SafeError);
  assert.equal(failure.code, 'provenance_unverifiable_docker');
  assert.equal(ghCalls.length, 1);
  assert.equal(launched, 0);
  assert.deepEqual(await workspaceNames(), []);
});

test('gh timeout uses the time left after executable verification', windowsOnly, async t => {
  await reset(); ghCalls.length = 0; ghDelayMs = 500;
  const limits = { wallMs: 1000, cleanupTimeoutMs: 1500 }, profile = await publisherProfile(limits);
  const started = performance.now(), deadlineAt = started + hostCommandPlan(limits).admissionMs;
  const readFile = fs.readFile;
  let verified = 0, stalledAt = 0;
  fs.readFile = (async (...args: Parameters<typeof fs.readFile>) => {
    const bytes = await Reflect.apply(readFile, fs, args);
    if (args[0] === ghPath && ++verified === 4) {
      stalledAt = performance.now();
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, deadlineAt - 150 - stalledAt));
    }
    return bytes;
  }) as typeof fs.readFile;
  syncBuiltinESMExports();
  let failure: unknown;
  try { await scanHostJob(target, profile, new AbortController().signal); } catch (error) { failure = error; }
  finally { fs.readFile = readFile; syncBuiltinESMExports(); }
  t.diagnostic(JSON.stringify({ stalledAtMs: stalledAt - started, ghStartsMs: ghCalls.map(call => call.startedAt - started),
    ghDurationsMs: ghCalls.map(call => call.elapsedMs), code: failure instanceof SafeError ? failure.code : null }));
  assert.ok(stalledAt > started && stalledAt < deadlineAt - 150);
  assert.equal(ghCalls.length, 4);
  assert.ok(ghCalls.every(call => call.startedAt < deadlineAt));
  assert.ok(ghCalls.at(-1)!.elapsedMs! < ghDelayMs, 'the last call cannot use time spent verifying its executable');
  assert.ok(failure instanceof SafeError);
  assert.equal(failure.code, 'provenance_unverifiable_gitleaks');
  assert.equal(launched, 0);
  assert.deepEqual(await workspaceNames(), []);
});

test('slow work before the owner stops with host_job_admission_deadline and never launches the owner', windowsOnly, async () => {
  await reset();
  // node.exe is hashed at least three times before launch, which already takes longer than this window.
  const cleanupTimeoutMs = Math.max(5, Math.floor(await nodeHashMs() / 2));
  const profile = await hostProfile({ wallMs: 1000, cleanupTimeoutMs });
  const started = performance.now();
  await assert.rejects(scanHostJob(target, profile, new AbortController().signal), { code: 'host_job_admission_deadline' });
  const elapsed = performance.now() - started;
  assert.equal(launched, 0, 'the owner job was not launched');
  assert.deepEqual(await writtenReports(), []);
  // verifyTool reads node.exe whole without stopping (measured now, under the same load), and creating the private
  // workspace runs PowerShell once; neither can stop midway.
  const fullRead = await nodeHashMs();
  assert.ok(elapsed < hostCommandPlan({ wallMs: 1000, cleanupTimeoutMs }).admissionMs + 2 * fullRead + 3000, `elapsed ${elapsed}, full read ${fullRead}`);
});

test('an owner that outlives its window ends the command with host_job_command_deadline and writes no record', windowsOnly, async () => {
  await reset();
  const limits = { wallMs: 300, cleanupTimeoutMs: 5000 }, profile = await hostProfile(limits);
  launchDelayMs = 60000;
  const started = performance.now();
  try {
    await assert.rejects(scanHostJob(target, profile, new AbortController().signal), { code: 'host_job_command_deadline' });
  } finally { launchDelayMs = 0; }
  const elapsed = performance.now() - started;
  assert.equal(launched, 1);
  assert.deepEqual(await writtenReports(), []);
  assert.ok(elapsed < hostCommandPlan(limits).boundMs + 1000, `elapsed ${elapsed}`);
});

test('normal timing still writes the report and keeps the whole-command guarantee false', windowsOnly, async () => {
  await reset();
  const limits = { wallMs: 2000, cleanupTimeoutMs: 5000 }, profile = await hostProfile(limits);
  const started = performance.now();
  const result = await scanHostJob(target, profile, new AbortController().signal);
  assert.ok(performance.now() - started < hostCommandPlan(limits).boundMs);
  assert.equal(launched, 1);
  assert.equal(result.job.resources.totalCommandWallGuarantee, false);
  assert.equal((await writtenReports()).length, 1);
});

test('loading the offline profile stops its tool hashes at the given expiry', windowsOnly, async () => {
  const profile = await offlineProfile();
  await assert.rejects(loadJobProfile(profile, target, { runtimePolicy: 'accept' }, { expiresAt: performance.now() - 1 }), { code: 'job_asset_verification_stopped' });
  assert.equal((await loadJobProfile(profile, target, { runtimePolicy: 'accept' })).profile.name, 'deadline_v1');
});

test('a cancellation before the owner yields host_job_cancelled', windowsOnly, async () => {
  await reset();
  const profile = await hostProfile({ wallMs: 2000, cleanupTimeoutMs: 5000 }), controller = new AbortController();
  controller.abort();
  await assert.rejects(scanHostJob(target, profile, controller.signal), { code: 'host_job_cancelled' });
  assert.equal(launched, 0);
});
