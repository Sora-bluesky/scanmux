import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { EventEmitter } from 'node:events';
import { syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { canonical, digest, hash, within } from '../src/safety.ts';
import { CopyBudget, withCopyBudget } from '../src/copy-budget.ts';
import { jobRuntimeFiles, scanJob } from '../src/job-runner.ts';
import { JobDisk, scopedJobDisk } from '../src/job-disk.ts';
import { jobPayloadResources } from '../src/job-config.ts';
import { readHostJobIntent, scanHostJob } from '../src/host-job.ts';
import { validateHostJobIntent, validateHostJobReport, type HostJobIntent, type HostNativePhase } from '../src/host-job-records.ts';
import { type ExpectedJobPlan, type JobBoundary, validateJobReport } from '../src/job-records.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { main } from '../src/cli.ts';
import { cleanEnvironment } from '../src/process.ts';
import { nextLedgerLine } from '../src/engine-ledger.ts';
import { createJobFrameWriter, jobRecordFrames } from '../internal/job-channel.mjs';
import { expectedResourceKernel } from '../internal/worker-resources.mjs';

// The same in-process owner/spawn boundary as host-job-deadline.test.ts. The worker,
// admission copies, app copies, framing and Linux database preparation are real.
const windowsOnly = { skip: process.platform !== 'win32' };
const parent = tmpdir(), fixture = await fs.mkdtemp(path.join(parent, 'host-job-copy-budget-'));
test.after(async () => { try { assert.ok(within(parent, fixture)); } finally { await removeTempDirStrict(fixture, { recursive: true, force: true }); } });
const target = path.join(fixture, 'target'), temporary = path.join(fixture, 'tmp');
await fs.mkdir(target); await fs.mkdir(temporary);
process.env.TEMP = temporary; process.env.TMP = temporary; process.env.TMPDIR = temporary;
const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
let ownerPath = '', dockerPath = '', ghPath = '', database = '', ownerVersion = '1.1.0', workerExit = 0;
let stage = 'outer', omitRemainder = false;
let diskScenario: 'host' | 'container' | 'sum' | 'under' | 'unmeasurable' | undefined;
let bootstrap: (Record<string, unknown> & { expected: ExpectedJobPlan }) | undefined;
let ownerArgs: string[] = [], ownerError: unknown, workerArgs: string[] = [];
const charges: { stage: string; limit: number; before: number; bytes: number }[] = [];
const trace: string[] = [];
const publisher = { repository: 'scanmux/fixture', certIdentity: 'https://github.com/scanmux/fixture/.github/workflows/release.yml@refs/tags/v1.0.0',
  oidcIssuer: 'https://token.actions.githubusercontent.com', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted' };

function child() {
  const process = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(),
    pid: 4242, kill: () => true });
  return Object.assign(process, { close(code = 0) { process.stdout.end(); process.stderr.end(); setImmediate(() => { process.emit('exit', code, null); process.emit('close', code, null); }); } });
}
function reply(value: unknown, code = 0) {
  const result = child(); result.stdin.resume();
  setImmediate(() => { result.stdout.write(typeof value === 'string' ? value : JSON.stringify(value)); result.close(code); }); return result;
}
async function worker(intent: HostJobIntent, sha: string, extra: string[]) {
  const savedArgv = process.argv, savedExit = process.exitCode;
  workerArgs = ['run', intent.directory, sha, ...extra];
  process.argv = [process.execPath, path.resolve('internal/windows-job-worker.mjs'), ...workerArgs]; process.exitCode = 0;
  stage = 'worker';
  try {
    // A real process does not inherit the outer parent's AsyncLocalStorage.
    await withCopyBudget(undefined, () => import(pathToFileURL(path.resolve('internal/windows-job-worker.mjs')).href + '?' + randomUUID()));
    workerExit = Number(process.exitCode);
  } finally { stage = 'outer'; process.argv = savedArgv; process.exitCode = savedExit; }
}
async function savedOwner(args: string[]) {
  ownerArgs = args;
  const { intent, sha256 } = await readHostJobIntent(args[0], args[1]);
  await worker(intent, sha256, omitRemainder ? [] : args.slice(2));
  const phase = (name: HostNativePhase['phase'], pid: number, start: number): HostNativePhase => ({ phase: name,
    reason: name === 'primary' && workerExit ? 'failed' : 'completed', configured: true, memberBeforeResume: true,
    cpuFlags: 5, cpuRate: intent.host.limits.cpuRate, memoryBytes: intent.host.limits.memoryBytes, limitFlags: 0x2200,
    root: { pid, creationFileTime: String(pid) }, processes: [{ pid, creationFileTime: String(pid), memberVerified: true, signaled: true,
      exitCode: name === 'primary' ? workerExit : 0 }], totalProcesses: 1, maximumTotalProcesses: 1, accountingSamples: 2,
    accountingMonotonic: true, coverageComplete: true, startedMs: start, endedMs: start + 1, closingStartedMs: 2, error: null });
  const native = { schema: 'scanmux.windows-job-owner/v1', version: intent.host.owner.version, intentSha256: sha256, jobId: intent.jobId,
    mode: 'scan', phases: [phase('primary', 1000, 1), phase('cleanup', 1004, 2)], state: 'closed', closingStartedMs: 2, endedMs: 4,
    owner: { pid: 996, creationFileTime: '996' } };
  const files = { 'host-job-primary.json': { schema: 'scanmux.windows-job-primary/v1', jobId: intent.jobId, intentSha256: sha256,
    owner: native.owner, phase: native.phases[0] }, 'host-job-native.json': native,
    'host-job-cleanup.json': { schema: 'scanmux.host-job-cleanup/v1', jobId: intent.jobId, intentSha256: sha256, containerId: null,
      terminal: null, containerAbsent: true, daemonHealthy: true } };
  if (intent.schema === 'scanmux.host-job-intent/v2') {
    const { createRetainedClient } = await import('../src/retained-write.ts');
    const retained = createRetainedClient(intent, sha256, () => performance.now() + 10000);
    for (const [name, value] of Object.entries(files)) assert.equal((await retained.write([{ name, bytes: encode(value) }])).result, 'committed');
  } else for (const [name, value] of Object.entries(files)) await fs.writeFile(path.join(intent.directory, name), encode(value));
}
function attached() {
  const result = child(); let sequence = 0, record = 0, report: Buffer, writer: ReturnType<typeof createJobFrameWriter>, boundary: JobBoundary;
  const hostDisk = scopedJobDisk();
  let diskCause: string | undefined;
  const send = (type: string, fields: Record<string, unknown>) => { trace.push('send ' + type); return result.stdout.write(JSON.stringify({ v: 1, nonce: bootstrap!.expected.jobId, seq: ++sequence, type, ...fields }) + '\n'); };
  const sendRecord = (kind: 'plan' | 'report', body: Buffer) => {
    for (const frame of jobRecordFrames(writer, ++record, kind, 0, [body])) for (let offset = 0; offset < frame.bytes.length; offset += 16384) {
      send('data', { data: frame.bytes.subarray(offset, offset + 16384).toString('base64') });
    }
  };
  result.stdin.on('data', raw => {
    try {
    const packet = JSON.parse(raw.toString());
    trace.push('receive ' + packet.type);
    if (packet.type === 'init') {
      bootstrap = packet.payload; const expected = bootstrap!.expected, limits = expected.limits;
      boundary = { kernel: expectedResourceKernel(jobPayloadResources(limits)), pidsMax: limits.pids, uid: 1000, gid: 1000,
        capabilitiesZero: true, noNewPrivileges: true, seccomp: 2, supervisorNonDumpable: true, childSupervisorAccessDenied: true,
        rootReadonly: true, boundedWritableStoresOnly: true, privateNamespaces: true, networkCounters: Array(16).fill(0), cpuThrottledPeriods: 0, oomKills: 0 };
      writer = createJobFrameWriter({ nonce: expected.jobId, maxOutputBytes: expected.config.maxOutputBytes, retainedBytes: limits.retainedBytes,
        ...(diskScenario ? { diskSampleLimit: Math.ceil((limits.wallMs + limits.cleanupTimeoutMs) / 100) + 8 } : {}), sender: 'controller' });
      if (diskScenario === 'unmeasurable') hostDisk?.register(path.join(expected.destination, 'missing'));
      setImmediate(() => send('ready', { sampleNs: '1', boundary }));
    } else if (packet.type === 'start') {
      const expected = bootstrap!.expected, workspace = path.join(fixture, randomUUID());
      mkdirSync(workspace);
      const { database: _database, ...init } = bootstrap!;
      // Test fixture runs the production Linux init parser and prepareOfflineDatabase.
      const prepared = childProcess.spawnSync(process.execPath, ['test/fixtures/copy-budget-payload.mjs'], { encoding: 'utf8', windowsHide: true,
        input: JSON.stringify({ init: { schema: 'scanmux.job-controller-init/v1', nonce: expected.jobId, ...init }, options: { source: database, workspace, target } }) });
      assert.ok([0, 3].includes(prepared.status!), JSON.stringify({ code: prepared.status, out: prepared.stdout, err: prepared.stderr }));
      const output = JSON.parse(prepared.stdout), plan = { schema: 'scanmux.plan/v2' as const, advisoryCatalog: { ...catalogIdentity },
        root: expected.mappedRoot, repoId: hash(expected.mappedRoot), commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: digest([]),
        dirty: false, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const,
        policyHash: digest(expected.config), planHash: '', network: 'offline' as const, transmissions: [], constraints: [], cost: { kind: 'not_applicable' as const, aiCalls: 0 as const } };
      plan.planHash = digest(plan);
      const typedPlan = { ...plan, required: [...plan.required] };
      const engines = typedPlan.required.map(engine => { const run = emptyRun(engine, { plan: typedPlan, config: expected.config,
        workspace: '/work', snapshot: '/work/snapshot', signal: new AbortController().signal, secretsCleared: false });
        run.execution = 'completed'; run.coverage = 'analyzed';
        if (engine === 'osv' && prepared.status === 3) { run.execution = 'not_started'; run.coverage = 'skipped'; run.errors = [output.error]; }
        return run; });
      const judgment = decide(typedPlan, engines), now = new Date().toISOString();
      report = encode({ schema: 'scanmux.report/v2', runId: randomUUID(), plan: typedPlan, startedAt: now, endedAt: now, engines,
        runner: { platform: 'linux', node: 'v' + expected.runtime.nodeVersion, imageDigest: null, isolation: 'local-static-only' },
        executionState: 'completed', coverageState: prepared.status === 0 ? 'complete' : 'incomplete', ...judgment, exitCode: exitCodes[judgment.gate], integrityErrors: [] });
      sendRecord('plan', encode({ schema: 'scanmux.job-plan/v1', jobId: expected.jobId, profileSha256: expected.profileSha256,
        origin: { root: expected.root, repoId: hash(expected.root) }, mappedRoot: expected.mappedRoot, config: expected.config, configSha256: digest(expected.config),
        limits: expected.limits, image: expected.image, runtime: expected.runtime, destination: expected.destination, requestedComparison: null, plan: typedPlan }));
    } else if (packet.type === 'input') {
      const frame = JSON.parse(Buffer.from(packet.data, 'base64').toString('utf8'));
      if (frame.type === 'disk-stop') { diskCause = frame.cause; return; }
      if (frame.type === 'disk-ack') {
        diskCause ??= frame.cause ?? undefined;
        if (diskCause) {
          const value = JSON.parse(report.toString('utf8'));
          value.engines[0].errors.push(diskCause); value.engines[0].coverage = 'partial';
          value.engines[0].execution = diskCause === 'job_disk_measured_limit' ? 'budget_exceeded' : 'failed';
          Object.assign(value, decide(value.plan, value.engines)); value.exitCode = exitCodes[value.gate as keyof typeof exitCodes];
          value.coverageState = 'incomplete'; report = encode(value);
        }
        sendRecord('report', report); return;
      }
      if (record === 1 && diskScenario) {
        void (async () => {
          const expected = bootstrap!.expected, limit = Number(bootstrap!.maxJobDiskBytes), root = path.join(fixture, randomUUID());
          await fs.mkdir(root);
          const probe = new JobDisk(Number.MAX_SAFE_INTEGER); probe.register(expected.destination);
          const hostBytes = await probe.check(), cluster = (await fs.statfs(root)).bsize;
          if (diskScenario === 'container' || diskScenario === 'sum') await fs.writeFile(path.join(root, 'growth'),
            Buffer.alloc(diskScenario === 'container' ? limit + 1 : Math.max(1, limit - Number(hostBytes) + cluster)));
          const containerDisk = new JobDisk(Number.MAX_SAFE_INTEGER); containerDisk.register(root);
          const sample = await containerDisk.check();
          send('data', { data: writer.encode({ type: 'disk-sample', bytes: String(sample) }).bytes.toString('base64') });
        })().catch(error => { ownerError = error; result.close(1); });
      } else if (record === 1) sendRecord('report', report);
      else { send('closed', { boundary, rootTerminal: { exitCode: 0, signal: null }, allOwnedTasksReaped: true, counts: null,
        stopReason: null, controllerCompleted: true, interruption: null }); result.close(); }
    }
    } catch (error) { ownerError = error; result.close(1); throw error; }
  });
  return result;
}
let container: Record<string, unknown> | undefined;
function docker(args: string[]) {
  const tail = args.slice(4), command = tail[0];
  if (command === 'version') return reply(tail[2] === '{{json .Server}}' ? { Os: 'linux' } : { Client: { Version: '28.1.1' }, Server: { Os: 'linux', Arch: 'amd64' } });
  if (command === 'image') return reply([{ Id: 'sha256:' + '1'.repeat(64), Os: 'linux', Architecture: 'amd64', Config: { Env: [], Labels: {}, Volumes: {} } }]);
  if (command === 'create') {
    const at = (key: string) => tail[tail.indexOf(key) + 1], mounts = tail.flatMap((value, i) => value === '--mount' ? [tail[i + 1]] : []).map(value => {
      const parts = Object.fromEntries(value.split(',').map(part => part.split('='))); return { source: parts.source, target: parts.target }; });
    const offline = JSON.parse(readFileSync(activeOffline, 'utf8')), limits = offline.limits;
    container = { Id: 'c'.repeat(64), Name: '/' + at('--name'), Image: offline.image,
      Config: { Labels: { 'scanmux.job': at('--label').split('=')[1] }, User: '1000:1000', Tty: false, OpenStdin: true, WorkingDir: '/work', Env: [],
        Entrypoint: ['/usr/bin/python3'], Cmd: ['-I', '-B', '/app/internal/linux-job-supervisor.py', at('--label').split('=')[1], String(limits.wallMs), String(offline.scan.maxOutputBytes)], Healthcheck: { Test: ['NONE'] } },
      HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, AutoRemove: false, PidMode: '', IpcMode: 'private', CgroupnsMode: 'private', UTSMode: '',
        CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], LogConfig: { Type: 'none' }, Tmpfs: Object.fromEntries(['tmp', 'work', 'shm'].filter(k => k !== 'shm').map(k => ['/' + k,
          `rw,noexec,nosuid,nodev,size=${limits[k + 'Bytes']},mode=${k === 'tmp' ? '1777' : '0700,uid=1000,gid=1000'}`])),
        PidsLimit: limits.pids, NanoCpus: limits.cpuCount * 1e9, Memory: limits.memoryBytes, MemorySwap: limits.memoryBytes, ShmSize: limits.shmBytes,
        Mounts: mounts.map(m => ({ Type: 'bind', Source: m.source, Target: m.target, ReadOnly: true })) },
      Mounts: mounts.map(m => ({ Type: 'bind', Source: m.source, Destination: m.target, RW: false })), State: { Running: false, ExitCode: 0, OOMKilled: false } };
    return reply('c'.repeat(64));
  }
  if (command === 'inspect') return container ? reply([container]) : reply('', 1);
  if (command === 'start') return attached();
  if (command === 'rm') { container = undefined; return reply(''); }
  if (command === 'ps') return reply('');
  throw Error('unexpected Docker call: ' + command);
}
const originalSpawn = childProcess.spawn;
(childProcess as unknown as Record<string, unknown>).spawn = function (this: unknown, ...args: unknown[]) {
  const tail = args[1] as string[];
  if (args[0] === ownerPath && !tail[0]?.startsWith('--retained-')) {
    if (tail[0] === '--version') return reply(ownerVersion);
    const result = child(); result.stdin.resume();
    setImmediate(() => { savedOwner(tail).then(() => { result.stdout.write('closed'); result.close(); }, error => { ownerError = error; result.stdout.write('failed'); result.close(1); }); }); return result;
  }
  if (args[0] === dockerPath) return docker(tail);
  if (args[0] === ghPath) return reply(tail[0] === '--version' ? 'gh version 2.94.0' : [{ verificationResult: {
    statement: { predicateType: publisher.predicateType, subject: [{ digest: { sha256: hash(readFileSync(tail[2])) } }] },
    signature: { certificate: { subjectAlternativeName: publisher.certIdentity, issuer: publisher.oidcIssuer, sourceRepositoryURI: 'https://github.com/' + publisher.repository,
      sourceRepositoryRef: 'refs/tags/v1.0.0', sourceRepositoryDigest: 'a'.repeat(40), runnerEnvironment: publisher.runner } } } }]);
  return Reflect.apply(originalSpawn, this, args);
};
syncBuiltinESMExports();

let activeOffline = '', H = 0;
test.before(async () => {
  if (process.platform !== 'win32') return;
  const powershell = path.join(process.env.SystemRoot!, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const built = childProcess.spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    "& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SCANMUX_TEST_BUILD).Replace('$PSScriptRoot','$env:SCANMUX_TEST_SCRIPTS'))) -OutputDirectory $env:SCANMUX_TEST_OWNER"],
    { encoding: 'utf8', windowsHide: true, env: { ...process.env, SCANMUX_TEST_SCRIPTS: path.resolve('scripts'),
      SCANMUX_TEST_BUILD: path.resolve('scripts/build-windows-job-owner.ps1'), SCANMUX_TEST_OWNER: path.join(fixture, 'owner') } });
  assert.equal(built.status, 0, built.stderr); const receipt = JSON.parse(built.stdout.trim().split(/\r?\n/).at(-1)!);
  ownerPath = path.join(fixture, 'owner/scanmux-windows-job-owner.exe'); assert.equal(hash(await fs.readFile(ownerPath)), receipt.assemblySha256);
  dockerPath = path.join(fixture, 'docker.exe'); ghPath = path.join(fixture, 'gh.exe');
  const osv = path.join(fixture, 'osv.exe'), gitleaks = path.join(fixture, 'gitleaks.exe');
  for (const file of [dockerPath, ghPath, osv, gitleaks]) await fs.writeFile(file, path.basename(file));
  const bundle = path.join(fixture, 'bundle.json'), trustedRoot = path.join(fixture, 'root.jsonl');
  await fs.writeFile(bundle, 'bundle'); await fs.writeFile(trustedRoot, 'root'); H = (await fs.stat(osv)).size + 10;
  const ledger = nextLedgerLine([], { recordedAt: '2026-10-25T00:00:00.000Z', component: 'osv', platform: 'linux-x64', version: '2.3.0', sha256: hash(await fs.readFile(osv)),
    change: 'synthetic', recordedBy: { scanmux: '0.1.0-poc.1', verifier: null }, evidence: { kind: 'sigstore-slsa', bundle: { path: bundle, sha256: hash('bundle') },
      trustedRoot: { path: trustedRoot, sha256: hash('root') }, sourceRef: 'refs/tags/v1.0.0', sourceDigest: 'a'.repeat(40) } });
  const ledgerPath = path.join(fixture, 'ledger.jsonl'); await fs.writeFile(ledgerPath, ledger.bytes);
  database = path.join(fixture, 'db'); await fs.mkdir(path.join(database, 'osv-scalibr/npm'), { recursive: true }); await fs.writeFile(path.join(database, 'osv-scalibr/npm/all.zip'), 'zip!');
  const tool = async (file: string, version: string) => ({ path: file, version, sha256: hash(await fs.readFile(file)) });
  const fixed = { sha256: '0'.repeat(64), version: '1.2.3' };
  activeOffline = path.join(fixture, 'offline.json');
  await fs.writeFile(activeOffline, encode({ schema: 'scanmux.job-profile/v2', name: 'copy_budget', scope: 'offline-local',
    docker: { tool: await tool(dockerPath, '28.1.1'), endpoint: 'npipe:////./pipe/dockerDesktopLinuxEngine' }, image: 'sha256:' + '1'.repeat(64),
    runtime: { nodeVersion: process.versions.node, python: { ...fixed, path: '/usr/bin/python3' }, git: { ...fixed, path: '/usr/bin/git' } },
    tools: { gitleaks: await tool(gitleaks, '8.30.1'), osv: await tool(osv, '2.3.0') }, osvDatabase: database,
    scan: { timeoutMs: 10000, maxOutputBytes: 1048576, maxFileBytes: 1048576, maxSnapshotBytes: 8388608, maxFiles: 1000 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 4194304 },
    runtimePolicy: { schema: 'scanmux.runtime-policy/v2', id: randomUUID(), revision: 1, state: 'active', deny: [], provenance: {
      verifier: await tool(ghPath, '2.94.0'), ledger: { path: ledgerPath, entries: 1, head: ledger.head }, require: [{ component: 'osv', level: 'publisher', publisher }] } } }));
});
async function run(limit?: number, retained = false, disk?: typeof diskScenario) {
  charges.length = 0; trace.length = 0; ownerArgs = []; bootstrap = undefined; ownerError = undefined; workerExit = 0; container = undefined;
  const offline = JSON.parse(await fs.readFile(activeOffline, 'utf8')); delete offline.maxCopyBytes;
  delete offline.maxJobDiskBytes; diskScenario = disk;
  if (disk) offline.maxJobDiskBytes = disk === 'host' ? 1 : 8 * 1048576;
  if (limit !== undefined) offline.maxCopyBytes = limit;
  await fs.writeFile(activeOffline, encode(offline));
  const host = { schema: retained ? 'scanmux.host-job-profile/v2' : 'scanmux.host-job-profile/v1', name: 'copy_budget_host', scope: 'windows-offline-local',
    offlineProfile: await canonical(activeOffline), owner: { path: ownerPath, sha256: hash(await fs.readFile(ownerPath)), version: ownerVersion },
    node: { path: process.execPath, sha256: hash(await fs.readFile(process.execPath)), version: process.versions.node },
    // The simulated owner closes at 2 ms, so disk cases need a window for the real worker and record verification.
    limits: { cpuRate: 2500, memoryBytes: 536870912, wallMs: disk ? 120000 : 20000, cleanupTimeoutMs: disk ? 60000 : 10000 }, ...(retained ? { retained: { allocatedBytes: 16777216 } } : {}) };
  const hostPath = path.join(fixture, 'host.json'); await fs.writeFile(hostPath, encode(host));
  const original = CopyBudget.prototype.copy;
  CopyBudget.prototype.copy = async function (source, destination, options) {
    const before = this.remainingBytes, copied = await original.call(this, source, destination, options);
    charges.push({ stage, limit: this.limit, before, bytes: copied.bytes }); return copied;
  };
  try { return await scanHostJob(target, hostPath, new AbortController().signal); }
  finally { CopyBudget.prototype.copy = original; }
}
const appBytes = async () => (await Promise.all(jobRuntimeFiles.map(file => fs.stat(file)))).reduce((sum, stat) => sum + stat.size, 0);

for (const scenario of ['host', 'container', 'sum', 'under', 'unmeasurable'] as const) {
  test('host measured disk: ' + scenario + ' uses engine reasons with unchanged record schemas', windowsOnly, async () => {
    for (const retained of [false, true]) {
      const result = await run(undefined, retained, scenario);
      assert.equal(ownerError, undefined); assert.equal(workerExit, 0);
      const cause = scenario === 'unmeasurable' ? 'job_disk_observation_unverified' : 'job_disk_measured_limit';
      assert.equal(result.job.gate, scenario === 'under' ? 'PASS' : scenario === 'unmeasurable' ? 'ERROR' : 'INCOMPLETE', result.json);
      if (scenario !== 'under') assert.ok(result.job.reasons.includes(cause), result.json);
      assert.equal(bootstrap?.maxJobDiskBytes, scenario === 'host' ? 1 : 8 * 1048576);
      assert.equal(Object.hasOwn(bootstrap!.expected.config, 'maxJobDiskBytes'), false);
      assert.equal(ownerArgs.length, 2); assert.equal(workerArgs.length, 3);
      const delegated = validateJobReport(JSON.parse(await fs.readFile(path.join(result.directory, 'delegated-job.json'), 'utf8')));
      assert.equal(delegated.resources.stop, null); assert.equal(delegated.gate, result.job.gate);
      validateHostJobReport(result.job, (await readHostJobIntent(result.directory)).intent);
      if (scenario !== 'unmeasurable') await assert.rejects(fs.stat(path.join(result.directory, 'host-job-failure.json')), { code: 'ENOENT' });
    }
  });
}

test('job measured disk: direct scanJob uses the profile limit without a host owner', windowsOnly, async () => {
  await run(undefined, false);
  const offline = JSON.parse(await fs.readFile(activeOffline, 'utf8'));
  offline.maxJobDiskBytes = 1; delete offline.maxCopyBytes; await fs.writeFile(activeOffline, encode(offline));
  diskScenario = 'host'; bootstrap = undefined; ownerError = undefined;
  const result = await scanJob(target, activeOffline, new AbortController().signal);
  assert.equal(ownerError, undefined); assert.equal(result.job.gate, 'INCOMPLETE', result.json);
  assert.ok(result.job.reasons.includes('job_disk_measured_limit'));
  assert.equal(result.job.resources.stop, null);
});

test('host copy budget: exact outer + worker + app + Linux ZIP succeeds; one byte less is INCOMPLETE', windowsOnly, async () => {
  for (const retained of [false, true]) for (const shortfall of [0, 1]) {
    const A = await appBytes(), maximum = H + H + A + 4 - shortfall, result = await run(maximum, retained);
    assert.equal(ownerError, undefined); assert.equal(workerExit, 0);
    assert.equal(result.job.gate, shortfall ? 'INCOMPLETE' : 'PASS', result.json);
    assert.equal(result.job.reasons.includes('job_disk_copy_limit'), !!shortfall);
    assert.equal(bootstrap?.copyBudgetBytes, 4 - shortfall);
    assert.equal(Number(ownerArgs[2]), maximum - H);
    assert.equal(charges.filter(c => c.stage === 'outer').reduce((sum, c) => sum + c.bytes, 0), H);
    assert.equal(charges.filter(c => c.stage === 'worker').reduce((sum, c) => sum + c.bytes, 0), H + A);
    assert.ok(charges.filter(c => c.stage === 'worker').every(c => c.limit === maximum - H));
    const intent = (await readHostJobIntent(result.directory)).intent; validateHostJobReport(result.job, intent);
    await assert.rejects(fs.stat(path.join(result.directory, 'host-job-failure.json')), { code: 'ENOENT' });
  }
});
test('host copy budget: admission/app shortfall writes the existing reason and never creates a partial app', windowsOnly, async () => {
  for (const retained of [false, true]) for (const maximum of [H, H + H + await appBytes() - 1]) {
    const result = await run(maximum, retained);
    assert.equal(ownerError, undefined); assert.equal(workerExit, 0);
    assert.equal(result.job.gate, 'INCOMPLETE', result.json); assert.ok(result.job.reasons.includes('job_disk_copy_limit'));
    const delegated = validateJobReport(JSON.parse(await fs.readFile(path.join(result.directory, 'delegated-job.json'), 'utf8')));
    assert.deepEqual(delegated.knownFailures, []); assert.equal(delegated.gate, 'INCOMPLETE');
    await assert.rejects(fs.stat(path.join(result.directory, 'app')), { code: 'ENOENT' });
    await assert.rejects(fs.stat(path.join(result.directory, 'host-job-failure.json')), { code: 'ENOENT' });
  }
});
test('host copy budget: a missing worker remainder never restarts the full profile budget', windowsOnly, async () => {
  omitRemainder = true;
  try { const result = await run(2 * H + await appBytes() + 4); assert.equal(workerExit, 1); assert.equal(result.job.gate, 'ERROR');
    assert.equal(bootstrap, undefined); await assert.rejects(fs.stat(path.join(result.directory, 'app')), { code: 'ENOENT' });
  } finally { omitRemainder = false; }
});
test('host copy budget: offline v1 profiles also hand the remaining app/ZIP allowance forward', windowsOnly, async () => {
  const saved = await fs.readFile(activeOffline), offline = JSON.parse(saved.toString('utf8'));
  offline.schema = 'scanmux.job-profile/v1'; delete offline.runtimePolicy;
  await fs.writeFile(activeOffline, encode(offline));
  try {
    for (const retained of [false, true]) for (const shortfall of [0, 1]) {
      const A = await appBytes(), result = await run(A + 4 - shortfall, retained);
      assert.equal(ownerError, undefined); assert.equal(workerExit, 0);
      assert.equal(result.job.gate, shortfall ? 'INCOMPLETE' : 'PASS', result.json);
      assert.equal(Number(ownerArgs[2]), A + 4 - shortfall); assert.equal(bootstrap?.copyBudgetBytes, 4 - shortfall);
      assert.equal(charges.filter(c => c.stage === 'outer').length, 0);
    }
  } finally { await fs.writeFile(activeOffline, saved); }
});
test('host copy budget: changed app size/hash remains ERROR instead of a copy-limit reason', windowsOnly, async t => {
  const copy = CopyBudget.prototype.copy, replacement = path.join(fixture, 'changed-app');
  try {
    for (const grow of [false, true]) {
      await fs.writeFile(replacement, Buffer.alloc((await fs.stat('LICENSE')).size + Number(grow)));
      t.mock.method(CopyBudget.prototype, 'copy', function (this: CopyBudget, source: string, destination: string, options: Parameters<typeof copy>[2]) {
        return copy.call(this, destination.endsWith(path.join('app', 'LICENSE')) ? replacement : source, destination, options);
      });
      const result = await run(2 * H + await appBytes() + 4);
      assert.equal(workerExit, 1); assert.equal(result.job.gate, 'ERROR', result.json);
      assert.equal(result.job.reasons.includes('job_disk_copy_limit'), false);
      t.mock.restoreAll();
    }
  } finally { t.mock.restoreAll(); }
});
test('host copy budget: no key preserves owner/worker arguments, intent and saved record formats', windowsOnly, async () => {
  for (const retained of [false, true]) {
    const result = await run(undefined, retained); assert.equal(ownerError, undefined); assert.equal(workerExit, 0, result.json + JSON.stringify(trace)); assert.equal(result.job.gate, 'PASS', result.json);
    const { intent, bytes, sha256 } = await readHostJobIntent(result.directory);
    assert.deepEqual(ownerArgs, [intent.directory, sha256]); assert.deepEqual(workerArgs, ['run', intent.directory, sha256]);
    assert.deepEqual(encode(validateHostJobIntent(JSON.parse(bytes.toString('utf8')))), bytes);
    assert.equal(Object.hasOwn(intent.offline, 'maxCopyBytes'), false); assert.equal(Object.hasOwn(bootstrap!, 'copyBudgetBytes'), false);
    assert.equal(Object.hasOwn(intent.offline, 'maxJobDiskBytes'), false); assert.equal(Object.hasOwn(bootstrap!, 'maxJobDiskBytes'), false);
    assert.deepEqual(encode(validateHostJobReport(JSON.parse(result.json), intent)), Buffer.from(result.json));
    for (const name of ['host-job-intent.json', 'host-job.json', 'delegated-job.json']) assert.doesNotMatch(await fs.readFile(path.join(result.directory, name), 'utf8'), /copyBudgetBytes|maxCopyBytes|maxJobDiskBytes|disk-sample|disk-stop|disk-ack/);
    assert.deepEqual(charges, []);
  }
});

test('host copy budget: pre-owner refusal keeps the CLI error envelope and exit 3', windowsOnly, async t => {
  await assert.rejects(run(1), { code: 'job_disk_copy_limit' });
  const errors: string[] = [], output: string[] = [];
  t.mock.method(process.stderr, 'write', (chunk: string | Buffer) => { errors.push(chunk.toString()); return true; });
  t.mock.method(process.stdout, 'write', (chunk: string | Buffer) => { output.push(chunk.toString()); return true; });
  let code: number;
  try { code = await main(['host-job-scan', target, '--host-job-profile', path.join(fixture, 'host.json'), '--json']); }
  finally { t.mock.restoreAll(); }
  assert.equal(code, 3); assert.deepEqual(output, []);
  assert.deepEqual(JSON.parse(errors.join('')), { schema: 'scanmux.error/v1', gate: 'INCOMPLETE', exitCode: 3, error: 'job_disk_copy_limit' });
  assert.deepEqual(ownerArgs, []);
});

test('host copy budget: the real native owner forwards only the run remainder and preserves cleanup arguments', windowsOnly, async () => {
  const template = (await readHostJobIntent((await run()).directory)).intent;
  const application = path.join(fixture, 'channel-app'), file = path.join(application, 'internal/windows-job-worker.mjs');
  await fs.mkdir(path.dirname(file), { recursive: true });
  for (const remaining of [undefined, '0', '4']) {
    const directory = await canonical(await fs.mkdtemp(path.join(temporary, 'native-channel-'))), log = path.join(fixture, randomUUID());
    await fs.writeFile(file, `import {writeFile} from 'node:fs/promises'; await writeFile(${JSON.stringify(log)} + '-' + process.argv[2], JSON.stringify(process.argv.slice(2)));`);
    const offline = { ...template.offline }; if (remaining === undefined) delete offline.maxCopyBytes; else offline.maxCopyBytes = 4;
    const intent = validateHostJobIntent({ ...template, directory, application, offline, jobId: randomUUID(),
      assets: [{ path: 'internal/windows-job-worker.mjs', bytes: (await fs.stat(file)).size, sha256: hash(await fs.readFile(file)) }] });
    const bytes = encode(intent), sha = hash(bytes); await fs.writeFile(path.join(directory, 'host-job-intent.json'), bytes);
    const invoke = async (extra: string[]) => {
      const result = originalSpawn(ownerPath, [directory, sha, ...extra], { cwd: directory, env: cleanEnvironment(directory), windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      const output: Buffer[] = [], errors: Buffer[] = [];
      result.stdout.on('data', chunk => output.push(chunk)); result.stderr.on('data', chunk => errors.push(chunk));
      const code = await new Promise<number | null>((resolve, reject) => { result.once('error', reject); result.once('close', resolve); });
      result.stdin.destroy(); return { code, out: Buffer.concat(output).toString('utf8').trim(), err: Buffer.concat(errors).toString('utf8') };
    };
    if (remaining !== undefined) for (const invalid of [[], ['-1'], ['04'], ['1.5'], ['5'], ['9007199254740992']]) {
      assert.equal((await invoke(invalid)).code, 1);
      await assert.rejects(fs.stat(log + '-run'), { code: 'ENOENT' });
    }
    const result = await invoke(remaining === undefined ? [] : [remaining]);
    assert.deepEqual(result, { code: 0, out: 'closed', err: '' });
    assert.deepEqual(JSON.parse(await fs.readFile(log + '-run', 'utf8')), ['run', directory, sha, ...(remaining === undefined ? [] : [remaining])]);
    assert.deepEqual(JSON.parse(await fs.readFile(log + '-cleanup', 'utf8')), ['cleanup', directory, sha]);
  }
});
