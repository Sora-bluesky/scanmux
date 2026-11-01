import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { copyFile, lstat, mkdir, open, readdir, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import type { CommitPair } from './model.ts';
import { cleanEnvironment } from './process.ts';
import { privateWorkspace } from './private-storage.ts';
import { admitJobRuntime, jobDatabaseMounts, jobFileIdentity, jobLinuxConfig, loadJobProfile, type JobProfile } from './job-config.ts';
import { JobRecordStore, jobHostFailureCodes, jobOutcome, readJobRegular, validateJobBoundary, validateJobReport, validateJobStop, validateJobNativeFailure, validateJobObserver,
  type ExpectedJobPlan, type JobAsset, type JobBoundary, type JobClosure, type JobKnownFailure, type JobReport, type JobStop, type JobNativeFailure, type JobObserver } from './job-records.ts';
import { canonical, hash, record, SafeError, within } from './safety.ts';
import { boundedRead, digest } from './safety.ts';
import { hostFailureRecorder, validateHostJobIntent, type HostJobIntent } from './host-job-records.ts';
import { createRetainedClient } from './retained-write.ts';
import { createJobFrameWriter, JobFrameDecoder, JobRecordAssembler, jobChannelLimits, jobDiskSampleLimit } from '../internal/job-channel.mjs';
import { JobDiskCopyLimitError, scopedCopyBudget, withCopyBudget } from './copy-budget.ts';
import { scopedJobDisk, withJobDisk } from './job-disk.ts';
import { ReproductionRecordStore, admitVerification, publishVerification, readVerification,
  type ReproductionJobBundle, type ReproductionOperation, type VerificationRequest, type VerificationBundle } from './reproduction.ts';

// One runtime/package inventory. A directory glob never grants application-mount authority.
export const jobRuntimeFiles = [
  'LICENSE', 'NOTICE', 'README.ja.md', 'README.md', 'bin/scanmux.mjs', 'package.json',
  'src/adapters.ts', 'src/cli.ts', 'src/config.ts', 'src/controller.ts', 'src/copy-budget.ts', 'src/job-disk.ts', 'src/github.ts', 'src/model.ts',
  'src/engine-catalog.ts', 'src/trivy-adapter.ts', 'src/trivy-plan.ts', 'src/safe-remove.ts', 'src/source-cleanup.ts',
  'src/output.ts', 'src/report-language.ts', 'src/policy.ts', 'src/private-acl.ts', 'src/private-storage.ts', 'src/process.ts', 'src/process-tree.ts', 'src/repository.ts', 'src/safety.ts', 'src/engine-checkpoint.ts',
  'src/web.ts', 'src/web-ui.ts', 'src/web-connection.ts', 'src/observations.ts', 'src/html-report.ts',
  'src/engine-run.ts', 'src/advisory-catalog.ts', 'src/runtime-declarations.ts', 'src/runtime-advisories.ts', 'src/advisory-display.ts', 'src/runtime-policy.ts', 'src/engine-ledger.ts', 'src/provenance.ts', 'src/runtime-admission.ts', 'src/engine-record.ts',
  'src/sarif-report.ts', 'src/osv-database.ts', 'src/configuration.ts', 'src/dependency-syntax.ts', 'src/dependency-graph.ts', 'src/dependencies.ts', 'src/import.ts',
  'src/comparison.ts', 'src/git-blobs.ts', 'src/release-transparency.ts', 'src/batch.ts', 'src/ci.ts', 'src/github-ci.ts', 'src/zip-archive.ts', 'src/history.ts', 'src/resume.ts', 'src/dispositions.ts', 'src/policy-exceptions.ts',
  'src/intel/feeds.ts', 'src/intel/index.ts', 'src/intel/jvn-rss.ts', 'src/intel/kev.ts', 'src/intel/match.ts', 'src/intel/render.ts', 'src/intel/store.ts', 'src/intel/syntax.ts',
  'src/runner-check.mjs', 'src/runner-check.d.mts', 'src/runner-lifecycle.mjs', 'src/runner-policy.mjs',
  'src/ai-plan.ts', 'src/ai-files.mjs', 'src/siwc-credentials.mjs', 'src/ai-observations.mjs', 'src/ai-runner.mjs', 'src/ai-runner.d.mts',
  'src/job-config.ts', 'src/job-records.ts', 'src/job-runner.ts', 'src/job-view.ts', 'src/reproduction.ts',
  'internal/ai-session.mjs', 'internal/response-protocol.mjs', 'internal/responses-transport.mjs', 'internal/projected-repository.mjs',
  'internal/hosted-channel.mjs', 'internal/hosted-mcp.mjs', 'internal/hosted-executor.mjs', 'internal/hosted-bridge.mjs',
  'internal/linux-hosted-runner.mjs', 'internal/linux-hosted-worker.mjs', 'internal/worker-resources.mjs', 'internal/worker-resources.d.mts',
  'internal/sdk-initialization-observer.mjs', 'internal/sdk-native-observer.py',
  'internal/job-channel.mjs', 'internal/job-channel.d.mts', 'internal/linux-job-controller.mjs', 'internal/linux-job-supervisor.py', 'internal/reproduction-driver.mjs',
  'src/host-job.ts', 'src/host-job-records.ts', 'src/retained-write.ts', 'internal/windows-job-owner.cs', 'internal/windows-retained-store.cs', 'internal/windows-job-worker.mjs', 'scripts/build-windows-job-owner.ps1',
  'internal/windows-process-owner.cs', 'scripts/build-windows-process-owner.ps1',
].sort();

interface JobMount { source: string; target: string }
interface ContainerExpected { id: string; name: string; jobId: string; profile: JobProfile; mounts: JobMount[]; imageEnvironment: unknown; imageLabels: unknown }
function requireValue(value: unknown, code = 'job_boundary_unverified'): asserts value {
  if (!value) throw new SafeError(code);
}
function exact(input: unknown, keys: string[]): Record<string, unknown> {
  const value = record(input);
  requireValue(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), 'job_protocol_invalid');
  return value;
}
function temporaryStores(profile: JobProfile) {
  return {
    '/tmp': `rw,noexec,nosuid,nodev,size=${profile.limits.tmpBytes},mode=1777`,
    '/work': `rw,noexec,nosuid,nodev,size=${profile.limits.workBytes},mode=0700,uid=1000,gid=1000`,
  };
}
export function validateJobContainer(input: unknown, expected: ContainerExpected) {
  const value = record(input), config = record(value.Config), host = record(value.HostConfig), state = record(value.State), limits = expected.profile.limits;
  requireValue(value.Id === expected.id && value.Name === '/' + expected.name && value.Image === expected.profile.image);
  requireValue(isDeepStrictEqual(config.Labels, { ...record(expected.imageLabels ?? {}), 'scanmux.job': expected.jobId }));
  requireValue(config.User === '1000:1000' && config.Tty === false && config.OpenStdin === true && config.WorkingDir === '/work'
    && isDeepStrictEqual(config.Env, expected.imageEnvironment) && isDeepStrictEqual(config.Entrypoint, ['/usr/bin/python3'])
    && isDeepStrictEqual(config.Cmd, ['-I', '-B', '/app/internal/linux-job-supervisor.py', expected.jobId, String(limits.wallMs), String(expected.profile.scan.maxOutputBytes)])
    && isDeepStrictEqual(record(config.Healthcheck).Test, ['NONE']));
  requireValue(host.NetworkMode === 'none' && host.ReadonlyRootfs === true && host.Privileged === false && host.AutoRemove === false
    && host.PidMode === '' && host.IpcMode === 'private' && host.CgroupnsMode === 'private' && (host.UTSMode === '' || host.UTSMode === undefined)
    && host.Init !== true && host.OomKillDisable !== true && isDeepStrictEqual(host.CapAdd ?? [], [])
    && isDeepStrictEqual(host.CapDrop, ['ALL']) && isDeepStrictEqual(host.SecurityOpt, ['no-new-privileges']));
  for (const key of ['Binds', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'ExtraHosts', 'Links', 'VolumesFrom', 'GroupAdd']) requireValue(isDeepStrictEqual(host[key] ?? [], []));
  requireValue(isDeepStrictEqual(host.PortBindings ?? {}, {}) && host.PublishAllPorts !== true && record(host.LogConfig).Type === 'none'
    && isDeepStrictEqual(host.Tmpfs, temporaryStores(expected.profile)) && host.PidsLimit === limits.pids
    && host.NanoCpus === limits.cpuCount * 1000000000 && host.Memory === limits.memoryBytes && host.MemorySwap === limits.memoryBytes && host.ShmSize === limits.shmBytes);
  requireValue(Array.isArray(host.Mounts) && Array.isArray(value.Mounts));
  requireValue(isDeepStrictEqual(host.Mounts.map(raw => { const mount = record(raw); return [mount.Type, mount.Source, mount.Target, mount.ReadOnly]; }).sort(),
    expected.mounts.map(mount => ['bind', mount.source, mount.target, true]).sort()));
  requireValue(isDeepStrictEqual(value.Mounts.map(raw => { const mount = record(raw); return [mount.Type, mount.Destination, mount.RW]; }).sort(),
    expected.mounts.map(mount => ['bind', mount.target, false]).sort()));
  requireValue(typeof state.Running === 'boolean' && typeof state.OOMKilled === 'boolean' && Number.isInteger(state.ExitCode)
    && Number(state.ExitCode) >= 0 && Number(state.ExitCode) <= 255);
  return { running: state.Running, terminal: state.Running ? null : { exitCode: Number(state.ExitCode), oomKilled: state.OOMKilled } };
}

async function bundleRuntime(directory: string, maximum: number, expectedAssets?: JobAsset[]) {
  const application = path.dirname(path.dirname(fileURLToPath(import.meta.url))), bundle = path.join(directory, 'app');
  const budget = scopedCopyBudget(), manifest: JobAsset[] = [];
  if (budget) {
    let bytes = 0;
    for (const relative of jobRuntimeFiles) {
      const source = await canonical(path.join(application, ...relative.split('/')));
      requireValue(within(application, source) && source === path.join(application, ...relative.split('/')), 'job_asset_changed');
      const identity = await jobFileIdentity(source);
      requireValue(identity.bytes <= maximum, 'job_runtime_size_limit');
      bytes += identity.bytes; requireValue(Number.isSafeInteger(bytes), 'job_runtime_size_limit');
      manifest.push({ path: relative, ...identity });
    }
    if (expectedAssets) requireValue(isDeepStrictEqual(manifest, expectedAssets), 'job_asset_changed');
    // The v2 retained store accepts app only as a complete manifest. Refuse before mkdir.
    if (bytes > budget.remainingBytes) throw new JobDiskCopyLimitError();
  }
  await mkdir(bundle, { mode: 0o700 });
  const assets: JobAsset[] = [];
  for (const relative of jobRuntimeFiles) {
    const source = await canonical(path.join(application, ...relative.split('/'))), destination = path.join(bundle, ...relative.split('/'));
    requireValue(within(application, source) && source === path.join(application, ...relative.split('/')), 'job_asset_changed');
    const { path: _path, ...identity } = manifest[assets.length] ?? { path: relative, ...await jobFileIdentity(source) };
    requireValue(identity.bytes <= maximum, 'job_runtime_size_limit');
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    if (budget) requireValue(isDeepStrictEqual(await budget.copy(source, destination, { maximumBytes: identity.bytes, sourceChangedCode: 'job_asset_changed' }), identity), 'job_asset_changed');
    else await copyFile(source, destination, 1);
    requireValue(isDeepStrictEqual(await jobFileIdentity(destination), identity), 'job_asset_changed');
    assets.push({ path: relative, ...identity });
  }
  return { application, bundle, assets };
}

interface DockerResult { code: number | null; stdout: Buffer; stderrBytes: number; reason: 'exit' | 'timeout' | 'output_limit' | 'spawn_failed' }
function dockerControl(profile: JobProfile, home: string) {
  const args = (tail: string[]) => ['--host', profile.docker.endpoint, '--config', path.join(home, 'docker-config'), ...tail];
  const options = { windowsHide: true, shell: false as const, env: cleanEnvironment(home) };
  return {
    attached(id: string): ChildProcessWithoutNullStreams { return spawn(profile.docker.tool.path, args(['start', '--attach', '--interactive', id]), { ...options, stdio: ['pipe', 'pipe', 'pipe'] }); },
    async run(tail: string[], expiresAt: number): Promise<DockerResult> {
      if (performance.now() >= expiresAt) throw new SafeError('job_control_deadline');
      return new Promise(resolve => {
        const child = spawn(profile.docker.tool.path, args(tail), { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
        const chunks: Buffer[] = []; let size = 0, stderrBytes = 0, reason: DockerResult['reason'] = 'exit';
        const timer = setTimeout(() => { reason = 'timeout'; child.kill(); }, Math.max(1, Math.floor(expiresAt - performance.now())));
        const receive = (bytes: Buffer, keep: boolean) => {
          size += bytes.length; if (!keep) stderrBytes += bytes.length;
          if (size > profile.scan.maxOutputBytes) { reason = 'output_limit'; child.kill(); }
          else if (keep) chunks.push(bytes);
        };
        child.stdout.on('data', bytes => receive(bytes, true)); child.stderr.on('data', bytes => receive(bytes, false));
        child.stdout.on('error', () => { reason = 'spawn_failed'; child.kill(); }); child.stderr.on('error', () => { reason = 'spawn_failed'; child.kill(); });
        child.on('error', () => { reason = 'spawn_failed'; });
        child.once('close', code => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(chunks), stderrBytes, reason }); });
      });
    },
  };
}
function successful(value: DockerResult) {
  requireValue(value.reason === 'exit' && value.code === 0, 'job_daemon_failed'); return value.stdout;
}
function parseDocker(value: DockerResult): unknown { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(successful(value))); }
async function exclusive(file: string, value: Buffer) {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(value); await handle.sync(); }
  finally { await handle.close(); }
}
const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');

export interface HostJobInvocation { jobId: string; directory: string; metadataName: 'delegated-job.json'; copyBudgetBytes?: number }

async function copyBudgetRefusal(intent: HostJobIntent, intentSha256: string) {
  const profile = intent.offline, directory = intent.directory, config = jobLinuxConfig(profile), deadline = performance.now() + profile.limits.cleanupTimeoutMs;
  const expected: ExpectedJobPlan = { jobId: intent.jobId, profileSha256: digest(profile), root: intent.root, mappedRoot: '/repo/' + hash(intent.root),
    config, limits: profile.limits, image: profile.image, runtime: { ...profile.runtime, tools: config.tools, app: intent.assets }, destination: directory,
    comparison: intent.comparison ?? undefined };
  const retained = intent.schema === 'scanmux.host-job-intent/v2' ? createRetainedClient(intent, intentSha256, () => deadline) : undefined;
  const store = new JobRecordStore(directory, profile, expected, 'delegated-job.json', retained);
  const job: JobReport = { schema: 'scanmux.job-report/v1', jobId: intent.jobId, profileSha256: expected.profileSha256, originDigest: hash(intent.root),
    origin: null, mappedRoot: null, plan: null, analysis: null, basis: 'live_owner_recorded',
    resources: { requested: profile.limits, startup: null, ending: null, stop: null, nativeFailure: null, observer: null,
      payloadWallScope: 'linux_payload_and_durable_record_ack_admission', controlPlaneHardCpuMemoryLimit: false,
      retainedFilesystemPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false },
    closure: { startupVerified: false, supervisorClosed: false, ownedTasksClosure: 'unverified', controllerCompleted: false, controllerTerminal: null,
      terminal: null, containerAbsent: false, daemonHealthy: false, inputsUnchanged: false }, knownFailures: [],
    failureObservationScope: 'host_accepted_closed_failure_facts', unobservedInternalErrors: 'unknown',
    inputVerificationScope: 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported',
    infrastructure: { appFiles: 0, appBytes: 0, emptyConfigurationFiles: 1, ownerIdentityBytes: 0 },
    retained: { logicalLimit: profile.limits.retainedBytes, payloadAdmittedBytesBeforeMetadata: 0, filesBeforeMetadata: 0, metadataBytesMaximum: profile.scan.maxOutputBytes, maxFiles: 11 },
    gate: 'INCOMPLETE', exitCode: 3, reasons: ['job_disk_copy_limit'] };
  validateJobReport(job);
  const json = encode(job); await store.saveMetadata(json);
  return { job, json: json.toString('utf8'), directory, destination: path.join(directory, 'delegated-job.json') };
}

interface ScanJobBundle { job: JobReport; json: string; directory: string; destination: string }
export async function scanJob(target: string, profilePath: string, signal: AbortSignal, comparison?: CommitPair, hostInvocation?: HostJobInvocation): Promise<ScanJobBundle> {
  const result = await runOwnedJob(target, profilePath, signal, comparison, hostInvocation);
  requireValue('job' in result); return result;
}

// Only these two fixed operations share the owner; callers cannot supply commands,
// executors, mounts, environment, transport parsers or lifecycle callbacks.
async function runOwnedJob(target: string, profilePath: string, signal: AbortSignal, comparison?: CommitPair, hostInvocation?: HostJobInvocation,
  operation?: ReproductionOperation, reproductionStorage?: { directory: string; root: string; retainedBytes: number }): Promise<ScanJobBundle | ReproductionJobBundle> {
  requireValue(!target.includes('://'), 'job_local_root_required');
  const loaded = await loadJobProfile(profilePath, path.resolve(target), { runtimePolicy: 'accept' }), { profile, root } = loaded;
  if (hostInvocation) {
    requireValue(Object.hasOwn(hostInvocation, 'copyBudgetBytes') === (profile.maxCopyBytes !== undefined), 'invalid_host_job_record');
    if (profile.maxCopyBytes !== undefined) requireValue(Number.isSafeInteger(hostInvocation.copyBudgetBytes) && hostInvocation.copyBudgetBytes! >= 0
      && hostInvocation.copyBudgetBytes! <= profile.maxCopyBytes, 'invalid_host_job_record');
  }
  return withCopyBudget(hostInvocation ? hostInvocation.copyBudgetBytes : profile.maxCopyBytes, async () => {
  const readInvocation = async () => {
    requireValue(hostInvocation, 'invalid_host_job_record');
    exact(hostInvocation, ['jobId', 'directory', 'metadataName', ...(profile.maxCopyBytes !== undefined ? ['copyBudgetBytes'] : [])]);
    requireValue(hostInvocation.metadataName === 'delegated-job.json' && await canonical(hostInvocation.directory) === hostInvocation.directory && !within(root, hostInvocation.directory), 'invalid_host_job_record');
    const rawIntent = await boundedRead(path.join(hostInvocation.directory, 'host-job-intent.json'), 65536);
    const intent = validateHostJobIntent(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(rawIntent)));
    requireValue(intent.mode === 'scan' && intent.jobId === hostInvocation.jobId && intent.directory === hostInvocation.directory && intent.root === root
      && intent.host.offlineProfile === loaded.source && intent.offlineSource.sha256 === loaded.sourceSha256 && digest(intent.offline) === loaded.profileSha256
      && isDeepStrictEqual(intent.comparison, comparison ?? null), 'invalid_host_job_record');
    requireValue(isDeepStrictEqual((await readdir(hostInvocation.directory)).sort(), ['AppData', 'empty-gitconfig', 'host-job-intent.json',
      ...(intent.schema === 'scanmux.host-job-intent/v2' ? ['retained-write.lock'] : [])]), 'invalid_host_job_record');
    return { intent, sha256: hash(rawIntent) };
  };
  // A budget refusal in admission still needs the verified intent to save a normal reason record.
  let hostInput = hostInvocation && profile.maxCopyBytes !== undefined ? await readInvocation() : null;
  try {
  await admitJobRuntime(profile, root, signal);
  if (signal.aborted) throw new SafeError('job_cancelled');
  return await withJobDisk(profile.maxJobDiskBytes, async () => {
  const disk = scopedJobDisk();
  if (hostInvocation && !hostInput) hostInput = await readInvocation();
  const hostIntent = hostInput?.intent ?? null, intentSha256 = hostInput?.sha256 ?? null;
  requireValue(!reproductionStorage || operation && !hostInvocation, 'job_admission_failed');
  const directory = hostInvocation?.directory ?? reproductionStorage?.directory ?? await privateWorkspace(root);
  disk?.register(reproductionStorage?.root ?? directory);
  const runtime = await bundleRuntime(directory, profile.scan.maxOutputBytes, hostIntent?.assets).catch(async error => {
    if ((operation || profile.maxCopyBytes !== undefined) && !hostInvocation) await rm(directory, { recursive: true, force: true });
    throw error;
  });
  try {
  await mkdir(path.join(directory, 'docker-config'), { mode: 0o700 });
  const database = await jobDatabaseMounts(profile, root);
  for (const file of database) requireValue(!within(directory, file.source), 'invalid_job_asset');
  const jobId = hostInvocation?.jobId ?? randomUUID(), name = 'scanmux-job-' + jobId, config = jobLinuxConfig(profile);
  const expected: ExpectedJobPlan = { jobId, profileSha256: loaded.profileSha256, root, mappedRoot: loaded.mappedRoot, config, limits: profile.limits,
    image: profile.image, runtime: { ...profile.runtime, tools: config.tools, app: runtime.assets }, destination: directory, comparison };
  const metadataName = hostInvocation?.metadataName ?? 'job.json';
  // Select this fixed backend only from the verified immutable host intent.
  const retained = hostIntent?.schema === 'scanmux.host-job-intent/v2'
    ? createRetainedClient(hostIntent, intentSha256!, () => controlDeadline()) : undefined;
  const store = operation ? new ReproductionRecordStore(directory, profile, expected, operation, reproductionStorage?.retainedBytes) : new JobRecordStore(directory, profile, expected, metadataName, retained);
  const docker = dockerControl(profile, directory);
  const mounts = [{ source: root, target: loaded.mappedRoot }, { source: runtime.bundle, target: '/app' },
    { source: profile.tools.gitleaks.path, target: '/tools/gitleaks' }, ...(profile.tools.osv ? [{ source: profile.tools.osv.path, target: '/tools/osv' }] : []),
    ...database.map(file => ({ source: file.source, target: file.destination }))];
  for (const mount of mounts) requireValue(!/[,\r\n]/.test(mount.source), 'invalid_job_asset');
  const bootstrap = { expected: { ...expected, comparison: comparison ?? null }, limits: profile.limits,
    ...(operation ? { operation } : {}),
    ...(scopedCopyBudget() ? { copyBudgetBytes: scopedCopyBudget()!.remainingBytes } : {}),
    ...(profile.maxJobDiskBytes === undefined ? {} : { maxJobDiskBytes: profile.maxJobDiskBytes }),
    database: database.map(({ destination, bytes, sha256 }) => ({ destination, bytes, sha256 })) };
  requireValue(Buffer.byteLength(JSON.stringify(bootstrap)) + 256 <= 65536, 'job_bootstrap_size_limit');
  const rootBefore = await lstat(root);
  const failures = new Set<JobKnownFailure>();
  const retainFailure = hostInvocation ? hostFailureRecorder(directory, jobId, loaded.profileSha256, retained) : null;
  const acceptFailure = (code: JobKnownFailure) => { retainFailure?.(code); failures.add(code); };
  let id: string | null = null, imageEnvironment: unknown, imageLabels: unknown, attached: ChildProcessWithoutNullStreams | null = null;
  let hostSequence = 0, outerSequence = 0, ownerIdentityBytes = 0;
  const facts: { startup: JobBoundary | null; ending: JobBoundary | null; controllerTerminal: JobClosure['controllerTerminal']; nativeFailure: JobNativeFailure | null; observer: JobObserver | null } = { startup: null, ending: null, controllerTerminal: null, nativeFailure: null, observer: null };
  let stop: JobStop | null = null, supervisorClosed = false, reaped = false;
  let cleanupExpiresAt: number | null = null, terminationRequest: Promise<void> | null = null, controllerCompleted = false;
  let partialOuter = false, closedFact = false, outerPending = Buffer.alloc(0), supervisorBytes = 0, supervisorFrames = 0;
  let environment: 'runtime_not_available' | 'image_not_available' | null = null;
  const closure: JobClosure = { startupVerified: false, supervisorClosed: false, ownedTasksClosure: 'unverified', controllerCompleted: false, controllerTerminal: null,
    terminal: null, containerAbsent: false, daemonHealthy: false, inputsUnchanged: false };
  const diskSamples = disk ? jobDiskSampleLimit(profile.limits) : 0;
  const channelOptions = { nonce: jobId, maxOutputBytes: profile.scan.maxOutputBytes, retainedBytes: profile.limits.retainedBytes,
    ...(disk ? { diskSampleLimit: diskSamples } : {}) };
  const decoder = new JobFrameDecoder({ ...channelOptions, sender: 'controller' }), assembler = new JobRecordAssembler(profile.scan.maxOutputBytes);
  const acknowledgements = createJobFrameWriter({ ...channelOptions, sender: 'host' });
  const bounds = jobChannelLimits(profile.scan.maxOutputBytes, profile.limits.retainedBytes, diskSamples);
  let diskStopSent = false;
  const started = performance.now(), expiresAt = started + profile.limits.wallMs;
  const cleanupDeadline = () => cleanupExpiresAt ??= performance.now() + profile.limits.cleanupTimeoutMs;
  const controlDeadline = () => cleanupExpiresAt ?? expiresAt;
  const containerExpected = (): ContainerExpected => {
    requireValue(id !== null, 'job_closure_unverified'); return { id, name, jobId, profile, mounts, imageEnvironment, imageLabels };
  };
  async function inspect() {
    requireValue(id !== null, 'job_closure_unverified');
    const values = parseDocker(await docker.run(['inspect', id], controlDeadline()));
    requireValue(Array.isArray(values) && values.length === 1, 'job_closure_unverified');
    return validateJobContainer(values[0], containerExpected());
  }
  async function send(type: 'init' | 'start' | 'input' | 'stop', fields: Record<string, unknown>) {
    requireValue(attached && !attached.stdin.destroyed && hostSequence < 16 + (diskSamples ? diskSamples + 1 : 0), 'job_protocol_invalid');
    const bytes = Buffer.from(JSON.stringify({ v: 1, nonce: jobId, seq: ++hostSequence, type, ...fields }) + '\n');
    requireValue(bytes.length <= 65536, 'job_protocol_invalid');
    return new Promise<boolean>((resolve, reject) => attached!.stdin.write(bytes, error => {
      if (!error) resolve(true);
      else if (cleanupExpiresAt !== null && ['EPIPE', 'ERR_STREAM_DESTROYED', 'ERR_STREAM_WRITE_AFTER_END'].includes((error as NodeJS.ErrnoException).code ?? '')) resolve(false);
      else reject(error);
    }));
  }
  async function terminateOwned() {
    if (id === null) return;
    const observed = await inspect();
    if (observed.running) {
      successful(await docker.run(['kill', '--signal', 'KILL', id], cleanupDeadline()));
      successful(await docker.run(['wait', id], cleanupDeadline()));
    }
  }
  function requestStop(event: JobStop | null, reason: 'retained' | 'deadline' | 'cancelled' | 'error') {
    if (stop === null && event) stop = event;
    if (cleanupExpiresAt !== null) return;
    cleanupDeadline(); store.discardUnacceptedTail();
    // The native owner stops immediately too. The outside owner independently closes
    // the exact container if it remains live, without relying on stderr or pipe EOF.
    if (attached) send('stop', { reason }).catch(() => {});
    terminationRequest = terminateOwned().catch(() => { acceptFailure('job_closure_unverified'); });
  }
  const cancel = () => requestStop({ kind: 'cancelled' }, 'cancelled');
  const timer = setTimeout(() => requestStop({ kind: 'deadline', source: 'host', elapsedMs: Math.floor(performance.now() - started) }, 'deadline'), profile.limits.wallMs);
  signal.addEventListener('abort', cancel, { once: true });
  try {
    if (signal.aborted) cancel();
    const versionResult = await docker.run(['version', '--format', '{{json .}}'], expiresAt);
    if (operation && versionResult.reason === 'exit' && versionResult.code !== 0) { environment = 'runtime_not_available'; throw new SafeError('reproduction_environment_missing'); }
    const version = record(parseDocker(versionResult));
    requireValue(record(version.Client).Version === profile.docker.tool.version && record(version.Server).Os === 'linux' && record(version.Server).Arch === 'amd64');
    const imageResult = await docker.run(['image', 'inspect', profile.image], expiresAt);
    if (operation && imageResult.reason === 'exit' && imageResult.code !== 0) {
      const health = record(parseDocker(await docker.run(['version', '--format', '{{json .Server}}'], expiresAt)));
      requireValue(health.Os === 'linux', 'job_daemon_failed'); environment = 'image_not_available'; throw new SafeError('reproduction_environment_missing');
    }
    const images = parseDocker(imageResult);
    requireValue(Array.isArray(images) && images.length === 1);
    const image = record(images[0]), imageConfig = record(image.Config);
    requireValue(image.Id === profile.image && image.Os === 'linux' && image.Architecture === 'amd64' && Object.keys(record(imageConfig.Volumes ?? {})).length === 0);
    imageEnvironment = imageConfig.Env; imageLabels = imageConfig.Labels;
    const created = successful(await docker.run(['create', '--pull=never', '--interactive', '--name', name, '--label', 'scanmux.job=' + jobId,
      '--network', 'none', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--ipc', 'private', '--cgroupns', 'private', '--init=false', '--no-healthcheck', '--pids-limit', String(profile.limits.pids), '--log-driver', 'none',
      '--cpus', String(profile.limits.cpuCount), '--memory', String(profile.limits.memoryBytes), '--memory-swap', String(profile.limits.memoryBytes), '--shm-size', String(profile.limits.shmBytes),
      ...Object.entries(temporaryStores(profile)).flatMap(([destination, settings]) => ['--tmpfs', destination + ':' + settings]),
      ...mounts.flatMap(mount => ['--mount', 'type=bind,source=' + mount.source + ',target=' + mount.target + ',readonly']),
      '--workdir', '/work', '--entrypoint', '/usr/bin/python3', profile.image, '-I', '-B', '/app/internal/linux-job-supervisor.py', jobId, String(profile.limits.wallMs), String(profile.scan.maxOutputBytes)], expiresAt));
    id = new TextDecoder('utf-8', { fatal: true }).decode(created).trim(); requireValue(/^[a-f0-9]{64}$/.test(id));
    await inspect();
    const identity = encode({ schema: 'scanmux.job-owner/v1', jobId, containerId: id, name, image: profile.image, label: 'scanmux.job' });
    requireValue(identity.length <= profile.scan.maxOutputBytes);
    if (store instanceof ReproductionRecordStore) store.admitOwner(identity.length);
    if (retained) requireValue((await retained.write([{ name: 'owner.json', bytes: identity }])).result === 'committed', 'job_save_failed');
    else await exclusive(path.join(directory, 'owner.json'), identity);
    ownerIdentityBytes = identity.length;
    requireValue(cleanupExpiresAt === null && performance.now() < expiresAt, 'job_admission_failed');
    attached = docker.attached(id);
    const processClosed = new Promise<void>(resolve => { attached!.once('close', () => resolve()); });
    let stderrBytes = 0;
    attached.on('error', () => { acceptFailure('job_daemon_failed'); requestStop(null, 'error'); });
    attached.stdin.on('error', () => { if (cleanupExpiresAt === null && !closedFact) { acceptFailure('job_protocol_invalid'); requestStop(null, 'error'); } });
    attached.stderr.on('data', (bytes: Buffer) => { stderrBytes += bytes.length; if (stderrBytes > profile.scan.maxOutputBytes) { acceptFailure('job_protocol_invalid'); requestStop(null, 'error'); } });
    attached.stderr.on('error', () => { acceptFailure('job_protocol_invalid'); requestStop(null, 'error'); });
    await send('init', { payload: bootstrap });
    const parsePacket = async (raw: Buffer) => {
      const packet = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)));
      requireValue(packet.v === 1 && packet.nonce === jobId && packet.seq === ++outerSequence && !closedFact, 'job_protocol_invalid');
      switch (packet.type) {
        case 'ready': {
          exact(packet, ['v', 'nonce', 'seq', 'type', 'sampleNs', 'boundary']);
          requireValue(facts.startup === null && typeof packet.sampleNs === 'string' && /^[0-9]{1,30}$/.test(packet.sampleNs), 'job_protocol_invalid');
          facts.startup = validateJobBoundary(packet.boundary, profile.limits); closure.startupVerified = true;
          requireValue(facts.startup.oomKills === 0, 'job_boundary_unverified');
          if (cleanupExpiresAt === null) {
            const remainingMs = Math.floor(expiresAt - performance.now());
            if (remainingMs <= 0) requestStop({ kind: 'deadline', source: 'host', elapsedMs: Math.floor(performance.now() - started) }, 'deadline');
            else await send('start', { remainingMs });
          }
          break;
        }
        case 'data': {
          exact(packet, ['v', 'nonce', 'seq', 'type', 'data']);
          requireValue(facts.startup !== null && typeof packet.data === 'string' && packet.data.length <= 4 * Math.ceil(Math.min(16384, profile.scan.maxOutputBytes) / 3), 'job_protocol_invalid');
          const bytes = Buffer.from(packet.data, 'base64'); requireValue(bytes.toString('base64') === packet.data, 'job_protocol_invalid');
          for (const frame of decoder.push(bytes)) {
            requireValue(frame.type !== 'ack' && frame.type !== 'disk-ack' && frame.type !== 'disk-stop', 'job_protocol_invalid');
            if (frame.type === 'disk-sample') {
              requireValue(disk, 'job_protocol_invalid');
              if (cleanupExpiresAt !== null) continue;
              disk.updatePeerSample(frame.bytes === null ? null : BigInt(frame.bytes));
              // The controller waits for this response at engine boundaries. The two
              // walks are not simultaneous; neither copy nor retained counters change.
              await disk.check().catch(() => {});
              if (disk.cause && !diskStopSent) {
                diskStopSent = true;
                await send('input', { data: acknowledgements.encode({ type: 'disk-stop', cause: disk.cause }).bytes.toString('base64') });
              }
              await send('input', { data: acknowledgements.encode({ type: 'disk-ack', sampleSeq: frame.seq, cause: disk.cause ?? null }).bytes.toString('base64') });
              continue;
            }
            const message = assembler.accept(frame);
            if (message?.type === 'failure') {
              acceptFailure(message.code);
              if (cleanupExpiresAt === null) {
                const ack = acknowledgements.encode({ type: 'ack', ackSeq: message.ackSeq, disposition: 'accepted' });
                if (await send('input', { data: ack.bytes.toString('base64') })) assembler.acknowledged(message.ackSeq);
              }
            } else if (message?.type === 'record') {
              if (cleanupExpiresAt !== null) continue;
              const persisted = await store.persist(message);
              if (persisted.kind === 'retained') { requestStop({ ...persisted, kind: 'retained' }, 'retained'); continue; }
              if (performance.now() >= expiresAt || cleanupExpiresAt !== null) {
                requestStop({ kind: 'deadline', source: 'host', elapsedMs: Math.floor(performance.now() - started) }, 'deadline'); continue;
              }
              const ack = acknowledgements.encode({ type: 'ack', ackSeq: message.ackSeq, disposition: 'accepted' });
              const delivered = await send('input', { data: ack.bytes.toString('base64') });
              if (!delivered || performance.now() >= expiresAt || cleanupExpiresAt !== null) {
                requestStop({ kind: 'deadline', source: 'host', elapsedMs: Math.floor(performance.now() - started) }, 'deadline'); continue;
              }
              store.acknowledge(message.ackSeq); assembler.acknowledged(message.ackSeq);
            }
          }
          break;
        }
        case 'stop': {
          exact(packet, ['v', 'nonce', 'seq', 'type', 'event']);
          const event = validateJobStop(packet.event);
          requireValue(event.kind === 'disk' || event.kind === 'memory' && event.source === 'memory.events' || event.kind === 'deadline' && event.source === 'supervisor', 'job_protocol_invalid');
          requestStop(event, event.kind === 'deadline' ? 'deadline' : 'error'); break;
        }
        case 'failure': {
          exact(packet, ['v', 'nonce', 'seq', 'type', 'code', 'detail']);
          facts.nativeFailure ??= validateJobNativeFailure(packet.detail);
          const code = jobHostFailureCodes.find(code => code === packet.code);
          requireValue(code !== undefined, 'job_protocol_invalid');
          acceptFailure(code); requestStop(null, 'error'); break;
        }
        case 'closed': {
          exact(packet, ['v', 'nonce', 'seq', 'type', 'boundary', 'rootTerminal', 'allOwnedTasksReaped', 'counts', 'stopReason', 'controllerCompleted', 'interruption']);
          requireValue(packet.allOwnedTasksReaped === true && typeof packet.controllerCompleted === 'boolean'
            && (packet.stopReason === null || ['disk', 'memory', 'deadline', 'retained', 'cancelled', 'error'].includes(String(packet.stopReason))), 'job_protocol_invalid');
          if (packet.boundary !== null) facts.ending = validateJobBoundary(packet.boundary, profile.limits);
          if (packet.rootTerminal !== null) {
            const terminal = exact(packet.rootTerminal, ['exitCode', 'signal']);
            requireValue((terminal.exitCode === null) !== (terminal.signal === null)
              && (terminal.exitCode === null || Number.isSafeInteger(terminal.exitCode) && Number(terminal.exitCode) >= 0 && Number(terminal.exitCode) <= 255)
              && (terminal.signal === null || Number.isSafeInteger(terminal.signal) && Number(terminal.signal) > 0 && Number(terminal.signal) <= 64), 'job_protocol_invalid');
            facts.controllerTerminal = { exitCode: terminal.exitCode === null ? null : Number(terminal.exitCode), signal: terminal.signal === null ? null : Number(terminal.signal) };
          }
          if (packet.counts !== null) {
            facts.observer = validateJobObserver({ counts: packet.counts, interruption: packet.interruption });
          } else requireValue(packet.interruption === null, 'job_protocol_invalid');
          closedFact = true; reaped = true; controllerCompleted = packet.controllerCompleted;
          clearTimeout(timer);
          attached!.stdin.end(); break;
        }
        default: throw new SafeError('job_protocol_invalid');
      }
    };
    try {
      for await (const chunk of attached.stdout) {
        const bytes = Buffer.from(chunk); supervisorBytes += bytes.length;
        requireValue(supervisorBytes <= bounds.maxBytes * 256 + 4 * 65536, 'job_protocol_invalid');
        let offset = 0;
        while (offset < bytes.length) {
          const newline = bytes.indexOf(10, offset), end = newline === -1 ? bytes.length : newline + 1;
          requireValue(outerPending.length + end - offset <= 65536, 'job_protocol_invalid');
          outerPending = Buffer.concat([outerPending, bytes.subarray(offset, end)]); offset = end;
          if (newline === -1) break;
          requireValue(++supervisorFrames <= bounds.maxBytes + 4, 'job_protocol_invalid');
          await parsePacket(outerPending); outerPending = Buffer.alloc(0);
        }
      }
      partialOuter = outerPending.length !== 0;
    } catch (error) {
      acceptFailure(error instanceof SafeError && error.code === 'job_admission_failed' ? 'job_closure_unverified' : 'job_protocol_invalid'); requestStop(null, 'error');
    }
    cleanupDeadline();
    const remaining = Math.max(1, Math.floor(cleanupDeadline() - performance.now()));
    let closeTimer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([processClosed.then(() => { supervisorClosed = true; }), new Promise<void>(resolve => { closeTimer = setTimeout(resolve, remaining); })]);
    if (closeTimer) clearTimeout(closeTimer);
    if (!supervisorClosed) { acceptFailure('job_closure_unverified'); attached.kill(); }
  } catch (error) {
    if (!(environment && error instanceof SafeError && error.code === 'reproduction_environment_missing')) {
      const code = error instanceof SafeError ? jobHostFailureCodes.find(code => code === error.code) : undefined;
      acceptFailure(code ?? 'job_admission_failed'); requestStop(null, 'error');
    }
  } finally {
    clearTimeout(timer); signal.removeEventListener('abort', cancel); cleanupDeadline();
    if (terminationRequest) await terminationRequest;
    if (!environment) try {
      if (id === null) {
        // A create response can be lost. Reconcile the unique owned name before cleanup.
        const lookup = await docker.run(['inspect', name], cleanupDeadline());
        if (lookup.code === 0 && lookup.reason === 'exit') {
          const values = parseDocker(lookup); requireValue(Array.isArray(values) && values.length === 1);
          const found = record(values[0]), configuration = record(found.Config);
          requireValue(found.Image === profile.image && record(configuration.Labels)['scanmux.job'] === jobId && found.Name === '/' + name && typeof found.Id === 'string' && /^[a-f0-9]{64}$/.test(found.Id));
          id = found.Id;
          const candidate = validateJobContainer(found, containerExpected());
          if (candidate.running) await terminateOwned();
        }
      }
      if (id !== null) {
        let observed = await inspect();
        if (observed.running) { await terminateOwned(); observed = await inspect(); }
        requireValue(!observed.running && observed.terminal !== null, 'job_closure_unverified'); closure.terminal = observed.terminal;
        if (observed.terminal.oomKilled && facts.startup) stop ??= { kind: 'memory', source: 'docker-oom-killed' };
        successful(await docker.run(['rm', id], cleanupDeadline()));
      }
      const health = parseDocker(await docker.run(['version', '--format', '{{json .Server}}'], cleanupDeadline())); requireValue(record(health).Os === 'linux', 'job_daemon_failed'); closure.daemonHealthy = true;
      const absent = await docker.run(['inspect', id ?? name], cleanupDeadline());
      const listed = successful(await docker.run(['ps', '-a', '--no-trunc', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], cleanupDeadline()));
      requireValue(absent.reason === 'exit' && absent.code !== 0 && listed.toString('utf8').trim() === '', 'job_closure_unverified'); closure.containerAbsent = true;
    } catch { acceptFailure('job_closure_unverified'); }
    try {
      const ensureTime = () => requireValue(performance.now() < cleanupDeadline(), 'job_closure_unverified');
      ensureTime(); requireValue((await jobFileIdentity(loaded.source, { expiresAt: cleanupDeadline(), maximumBytes: 65536 })).sha256 === loaded.sourceSha256, 'job_inputs_changed');
      for (const tool of [profile.docker.tool, profile.tools.gitleaks, ...(profile.tools.osv ? [profile.tools.osv] : [])]) {
        ensureTime(); requireValue((await jobFileIdentity(tool.path, { expiresAt: cleanupDeadline() })).sha256 === tool.sha256, 'job_asset_changed');
      }
      for (const asset of runtime.assets) for (const base of [runtime.application, runtime.bundle]) {
        ensureTime(); requireValue(isDeepStrictEqual(await jobFileIdentity(path.join(base, ...asset.path.split('/')), { expiresAt: cleanupDeadline(), maximumBytes: asset.bytes }), { bytes: asset.bytes, sha256: asset.sha256 }), 'job_asset_changed');
      }
      for (const asset of database) { ensureTime(); requireValue(isDeepStrictEqual(await jobFileIdentity(asset.source, { expiresAt: cleanupDeadline(), maximumBytes: asset.bytes }), { bytes: asset.bytes, sha256: asset.sha256 }), 'job_asset_changed'); }
      const rootAfter = await lstat(root);
      requireValue((await readdir(path.join(directory, 'docker-config'))).length === 0, 'job_inputs_changed');
      requireValue(await canonical(root) === root && rootBefore.dev === rootAfter.dev && rootBefore.ino === rootAfter.ino && rootBefore.mtimeMs === rootAfter.mtimeMs, 'job_inputs_changed');
      ensureTime(); closure.inputsUnchanged = true;
    } catch { acceptFailure('job_inputs_changed'); }
  }
  closure.supervisorClosed = supervisorClosed || closure.containerAbsent && closure.terminal !== null;
  closure.ownedTasksClosure = reaped ? 'supervisor_final_wait' : closure.containerAbsent && closure.terminal ? 'namespace_terminal_and_absent' : 'unverified';
  closure.controllerTerminal = facts.controllerTerminal;
  closure.controllerCompleted = controllerCompleted;
  const verifiedStop = stop !== null && closure.startupVerified && closure.containerAbsent && closure.supervisorClosed;
  try { decoder.finish(verifiedStop); assembler.finish(verifiedStop); if (partialOuter && !verifiedStop) throw Error(); }
  catch { acceptFailure('job_protocol_invalid'); }
  if (!environment && (!closedFact && !verifiedStop || stop === null && (!controllerCompleted || facts.controllerTerminal?.exitCode !== 0 || !facts.ending))) acceptFailure('job_controller_failed');
  if (facts.startup && facts.ending && !isDeepStrictEqual(facts.startup.networkCounters, facts.ending.networkCounters)) acceptFailure('job_boundary_unverified');
  if (store instanceof ReproductionRecordStore) {
    requireValue(performance.now() < cleanupDeadline(), 'job_metadata_deadline');
    return await store.complete({ startup: facts.startup, ending: facts.ending, nativeFailure: facts.nativeFailure, stop, closure, failures: [...failures] }, environment, ownerIdentityBytes);
  }
  store.finalize({ startup: facts.startup, ending: facts.ending, nativeFailure: facts.nativeFailure, stop, closure, failures: [...failures] });
  const outcome = jobOutcome({ plan: store.plan, report: store.finalReport, prefix: store.prefix, stop, closure, failures: [...failures] });
  const job: JobReport = { schema: 'scanmux.job-report/v1', jobId, profileSha256: loaded.profileSha256, originDigest: hash(root),
    origin: store.plan?.origin ?? null, mappedRoot: store.plan?.mappedRoot ?? null, plan: store.planReference, analysis: store.analysis, basis: 'live_owner_recorded',
    resources: { requested: profile.limits, startup: facts.startup, ending: facts.ending, stop, nativeFailure: facts.nativeFailure, observer: facts.observer, payloadWallScope: 'linux_payload_and_durable_record_ack_admission',
      controlPlaneHardCpuMemoryLimit: false, retainedFilesystemPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false },
    closure, knownFailures: [...failures], failureObservationScope: 'host_accepted_closed_failure_facts', unobservedInternalErrors: 'unknown',
    inputVerificationScope: 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported',
    infrastructure: { appFiles: runtime.assets.length, appBytes: runtime.assets.reduce((sum, asset) => sum + asset.bytes, 0), emptyConfigurationFiles: 1, ownerIdentityBytes },
    retained: { logicalLimit: profile.limits.retainedBytes, payloadAdmittedBytesBeforeMetadata: store.admittedBytes, filesBeforeMetadata: store.files, metadataBytesMaximum: profile.scan.maxOutputBytes, maxFiles: 11 }, ...outcome };
  validateJobReport(job);
  requireValue(performance.now() < cleanupDeadline(), 'job_metadata_deadline');
  const json = encode(job); await store.saveMetadata(json);
  requireValue(performance.now() < cleanupDeadline(), 'job_metadata_deadline');
  return { job, json: json.toString('utf8'), directory, destination: path.join(directory, metadataName) };
  } finally { if (operation) await rm(runtime.bundle, { recursive: true, force: true }); }
  });
  } catch (error) {
    if (error instanceof JobDiskCopyLimitError && hostInput) {
      if (signal.aborted) throw new SafeError('job_cancelled');
      return copyBudgetRefusal(hostInput.intent, hostInput.sha256);
    }
    throw error;
  }
  });
}

export async function verifyFinding(target: string, offlineProfilePath: string, request: VerificationRequest, signal: AbortSignal): Promise<VerificationBundle> {
  requireValue(!target.includes('://'), 'job_local_root_required');
  const loaded = await loadJobProfile(offlineProfilePath, path.resolve(target), { runtimePolicy: 'accept' }), { profile, root } = loaded;
  const reportPath = await canonical(path.resolve(request.reportPath));
  requireValue(!within(root, reportPath), 'reproduction_report_inside_target');
  const sourceBytes = await readJobRegular(reportPath, profile.scan.maxOutputBytes), source = admitVerification(root, sourceBytes, request);
  const directory = await privateWorkspace(root), jobs: ReproductionJobBundle[] = [];
    const operation = (side: ReproductionOperation['side'], commit: string, expectedTest: ReproductionOperation['expectedTest']): ReproductionOperation => ({ kind: 'reproduction', side, commit,
      sourceSnapshot: source.sourceSnapshot, finding: source.selection, sourceReportSha256: source.sourceReportSha256, testDirectory: source.testDirectory, mode: source.mode, expectedTest });
    const execute = async (op: ReproductionOperation) => {
      requireValue((await loadJobProfile(offlineProfilePath, root, { runtimePolicy: 'accept' })).profileSha256 === loaded.profileSha256, 'job_inputs_changed');
      const comparison = { base: op.side === 'after' && source.mode.kind === 'before_after' ? source.mode.base : op.commit, head: op.commit };
      const phase = path.join(directory, op.side); await mkdir(phase, { mode: 0o700 }); await exclusive(path.join(phase, 'empty-gitconfig'), Buffer.alloc(0));
      const retainedBytes = profile.limits.retainedBytes - sourceBytes.length - jobs.flatMap(job => job.files).reduce((sum, file) => sum + file.bytes, 0);
      const job = await runOwnedJob(root, offlineProfilePath, signal, comparison, undefined, op, { directory: phase, root: directory, retainedBytes });
      requireValue('receipt' in job); jobs.push(job); return job;
    };
    const before = await execute(operation(source.mode.kind === 'snapshot' ? 'snapshot' : 'before', source.sourceSnapshot.commit, null));
    const guard = before.plan?.testGuard;
    if (source.mode.kind === 'before_after' && before.attempt.kind === 'completed' && guard && 'test' in guard) await execute(operation('after', source.mode.head, guard.test));
    requireValue((await jobFileIdentity(reportPath, { maximumBytes: sourceBytes.length })).sha256 === source.sourceReportSha256, 'job_inputs_changed');
    const bundle = await publishVerification(directory, sourceBytes, source, jobs, profile);
    await readVerification(directory, profile.scan.maxOutputBytes);
    return bundle;
}
