import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { lstat, mkdir, open, readdir } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import type { CommitPair, Config, Report } from './model.ts';
import { loadConfig } from './config.ts';
import { privateWorkspace } from './private-storage.ts';
import { cleanEnvironment, executeDirect, verifyTool, verifyVersion } from './process.ts';
import { boundedRead, canonical, digest, hash, hostLocalPath, record, SafeError, within } from './safety.ts';
import { jobFileIdentity, jobLinuxConfig, jobRuntimeSubjects, loadJobProfile, parseJobProfile, regularJobFile } from './job-config.ts';
import { admitRuntime } from './runtime-admission.ts';
import { jobRuntimeFiles } from './job-runner.ts';
import { readEngineCheckpoints, type VerifiedCheckpointPair } from './engine-checkpoint.ts';
import { jobReference, parseJobJson, readJobRegular, validateJobPlan, type ExpectedJobPlan, type JobFileReference, type JobPlan } from './job-records.ts';
import { fixedPrefix, readSavedJobRecord } from './job-view.ts';
import { checkedText } from './output.ts';
import { renderHtmlReport } from './html-report.ts';
import { renderSarifReports } from './sarif-report.ts';
import { parseReportLanguage, type ReportLanguage } from './report-language.ts';
import { createRetainedClient, initializeRetainedStore, probeRetainedVolume, retainedCatalog, retainedPolicy, validateRetainedSnapshot,
  validateRetainedAllocationStop, type RetainedSnapshot } from './retained-write.ts';
import { hostControlMaximum, hostFailureMaximum, hostJobCompletion, hostJobOutcome, hostNativeClosed, hostRequire, nativeProcessCapacity, validateHostOfflinePaths,
  parseHostJobProfile, validateHostJobFailure, validateHostJobIntent, validateHostJobReport, validateHostNativeReceipt,
  type HostJobIntent, type HostJobReport, type HostNativeReceipt, type HostCompletionInput, type HostRetainedEvidence } from './host-job-records.ts';
import { jobOutcome, validateJobReport } from './job-records.ts';
import { scopedCopyBudget, withCopyBudget } from './copy-budget.ts';

const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const acceptPolicy = { runtimePolicy: 'accept' } as const;
const application = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
interface SavedFile { name: string; bytes: Buffer }
async function exclusive(file: string, bytes: Buffer, maximum: number) {
  hostRequire(bytes.length <= maximum);
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
}
async function optional(directory: string, name: string, maximum: number): Promise<Buffer | null> {
  const file = path.join(directory, ...name.split('/'));
  const exists = await lstat(file).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  return exists ? readJobRegular(file, maximum) : null;
}
async function rootIdentity(root: string): Promise<HostJobIntent['rootIdentity']> {
  const stat = await lstat(root, { bigint: true }); hostRequire(stat.isDirectory() && !stat.isSymbolicLink());
  return { device: stat.dev.toString(), inode: stat.ino.toString(), modifiedNs: stat.mtimeNs.toString() };
}
async function verifyRuntimeDirectories(directory: string) {
  // Windows/.NET initializes this empty profile namespace even with a clean env.
  // It grants no cache-file exception or access to the real user's profile.
  for (const relative of ['AppData', 'AppData/Roaming']) {
    const folder = path.join(directory, ...relative.split('/')), stat = await lstat(folder);
    hostRequire(stat.isDirectory() && !stat.isSymbolicLink() && await canonical(folder) === folder);
  }
  hostRequire(isDeepStrictEqual(await readdir(path.join(directory, 'AppData')), ['Roaming']) && (await readdir(path.join(directory, 'AppData', 'Roaming'))).length === 0);
}
export async function readHostJobIntent(directory: string, expectedSha256?: string) {
  const physical = await canonical(directory);
  const bytes = await readJobRegular(path.join(physical, 'host-job-intent.json'), hostControlMaximum), sha256 = hash(bytes);
  if (expectedSha256 !== undefined) hostRequire(sha256 === expectedSha256);
  return { intent: validateHostJobIntent(parseJobJson(bytes)), bytes, sha256 };
}
/** A point in performance.now() time after which a step stops with its own error code. */
export interface HostDeadline { at: number; code: 'host_job_admission_deadline' | 'host_job_command_deadline' }
const checkDeadline = (deadline?: HostDeadline) => { if (deadline && performance.now() >= deadline.at) throw new SafeError(deadline.code); };
// jobFileIdentity checks its expiry between read chunks, so a hash stops within one chunk of the deadline.
async function boundedIdentity(file: string, deadline: HostDeadline | undefined, options: { maximumBytes?: number } = {}) {
  try { return await jobFileIdentity(file, deadline ? { ...options, expiresAt: deadline.at } : options); }
  catch (error) { if (deadline && error instanceof SafeError && error.code === 'job_asset_verification_stopped') throw new SafeError(deadline.code); throw error; }
}
/**
 * The whole host-job-scan command is bounded by wallMs + 4·cleanupTimeoutMs from its start: work before the
 * owner shares 3·cleanupTimeoutMs, the owner and its closing keep their wallMs + cleanupTimeoutMs.
 * Steps that cannot stop midway can overrun it: a whole-image read when a tool is verified, reading the saved
 * records after the owner, one record write, or the gap between killing the owner and its exit.
 */
export function hostCommandPlan(limits: { wallMs: number; cleanupTimeoutMs: number }): { admissionMs: number; boundMs: number } {
  return { admissionMs: 3 * limits.cleanupTimeoutMs, boundMs: limits.wallMs + 4 * limits.cleanupTimeoutMs };
}

async function boundedProfile(file: string, root: string, deadline: HostDeadline | undefined) {
  try { return await loadJobProfile(file, root, acceptPolicy, deadline ? { expiresAt: deadline.at } : {}); }
  catch (error) { if (deadline && error instanceof SafeError && error.code === 'job_asset_verification_stopped') throw new SafeError(deadline.code); throw error; }
}

/** Fixed trusted assets only. Source traversal remains inside the Linux payload. */
export async function verifyHostJobInputs(intent: HostJobIntent, deadline?: HostDeadline) {
  await verifyRuntimeDirectories(intent.directory);
  hostRequire(await canonical(intent.root) === intent.root && isDeepStrictEqual(await rootIdentity(intent.root), intent.rootIdentity));
  const identities = [
    { path: intent.hostSource.path, ...intent.hostSource.identity }, { path: intent.host.offlineProfile, ...intent.offlineSource },
    { path: intent.host.node.path, ...intent.nodeIdentity }, { path: intent.host.owner.path, ...intent.ownerIdentity },
    ...intent.assets.map(asset => ({ path: path.join(intent.application, ...asset.path.split('/')), bytes: asset.bytes, sha256: asset.sha256 })),
  ];
  for (const asset of identities) {
    checkDeadline(deadline);
    hostRequire(await regularJobFile(asset.path, intent.root) === asset.path);
    hostRequire(isDeepStrictEqual(await boundedIdentity(asset.path, deadline, { maximumBytes: asset.bytes }), { bytes: asset.bytes, sha256: asset.sha256 }));
  }
  hostRequire(intent.nodeIdentity.sha256 === intent.host.node.sha256 && intent.ownerIdentity.sha256 === intent.host.owner.sha256);
  const offline = await boundedProfile(intent.host.offlineProfile, intent.root, deadline);
  hostRequire(offline.sourceSha256 === intent.offlineSource.sha256 && isDeepStrictEqual(offline.profile, intent.offline));
}
function expectedPlan(intent: HostJobIntent): ExpectedJobPlan {
  const config = jobLinuxConfig(intent.offline);
  return { jobId: intent.jobId, profileSha256: digest(intent.offline), root: intent.root, mappedRoot: '/repo/' + hash(intent.root), config,
    limits: intent.offline.limits, image: intent.offline.image, runtime: { ...intent.offline.runtime, tools: config.tools, app: intent.assets },
    destination: intent.directory, comparison: intent.comparison ?? undefined };
}

export interface HostCleanupRecord {
  schema: 'scanmux.host-job-cleanup/v1'; jobId: string; intentSha256: string; containerId: string | null;
  terminal: { exitCode: number; oomKilled: boolean } | null; containerAbsent: true; daemonHealthy: true;
}
function validateCleanup(input: unknown, intent: HostJobIntent, intentSha256: string): HostCleanupRecord {
  const value = record(input), keys = ['schema', 'jobId', 'intentSha256', 'containerId', 'terminal', 'containerAbsent', 'daemonHealthy'];
  hostRequire(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) && value.schema === 'scanmux.host-job-cleanup/v1'
    && value.jobId === intent.jobId && value.intentSha256 === intentSha256 && value.containerAbsent === true && value.daemonHealthy === true);
  hostRequire(value.containerId === null || typeof value.containerId === 'string' && /^[a-f0-9]{64}$/.test(value.containerId));
  if (value.terminal !== null) {
    const terminal = record(value.terminal);
    hostRequire(Object.keys(terminal).length === 2 && Number.isInteger(terminal.exitCode) && Number(terminal.exitCode) >= 0 && Number(terminal.exitCode) <= 255 && typeof terminal.oomKilled === 'boolean');
  }
  hostRequire((value.containerId === null) === (value.terminal === null));
  return value as unknown as HostCleanupRecord;
}
export async function cleanupHostContainer(intent: HostJobIntent, intentSha256: string) {
  // This helper is called only by the live owner after a proven primary drain.
  const home = path.join(intent.directory, 'host-cleanup-docker-config'); await mkdir(home, { mode: 0o700 });
  const profile = intent.offline, name = 'scanmux-job-' + intent.jobId;
  const expiresAt = performance.now() + intent.host.limits.cleanupTimeoutMs;
  async function control(args: string[]) {
    hostRequire(performance.now() < expiresAt);
    const child = spawn(profile.docker.tool.path, ['--host', profile.docker.endpoint, '--config', home, ...args], {
      windowsHide: true, shell: false, env: cleanEnvironment(intent.directory), stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks: Buffer[] = []; let size = 0, failed = false;
    const timer = setTimeout(() => { failed = true; child.kill(); }, Math.max(1, Math.floor(expiresAt - performance.now())));
    for (const [stream, keep] of [[child.stdout, true], [child.stderr, false]] as const) {
      stream.on('data', bytes => { size += bytes.length; if (size > profile.scan.maxOutputBytes) { failed = true; child.kill(); } else if (keep) chunks.push(Buffer.from(bytes)); });
      stream.on('error', () => { failed = true; child.kill(); });
    }
    child.once('error', () => { failed = true; });
    return new Promise<{ code: number | null; bytes: Buffer }>((resolve, reject) => child.once('close', code => {
      clearTimeout(timer); if (failed) reject(new SafeError('host_job_cleanup_unverified')); else resolve({ code, bytes: Buffer.concat(chunks) });
    }));
  }
  const good = (value: Awaited<ReturnType<typeof control>>) => { hostRequire(value.code === 0); return value.bytes; };
  const parse = (bytes: Buffer): unknown => JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  const version = record(parse(good(await control(['version', '--format', '{{json .}}']))));
  hostRequire(record(version.Client).Version === profile.docker.tool.version && record(version.Server).Os === 'linux' && record(version.Server).Arch === 'amd64');
  let containerId: string | null = null, terminal: HostCleanupRecord['terminal'] = null;
  const inspected = await control(['inspect', name]);
  if (inspected.code === 0) {
    const values = parse(inspected.bytes); hostRequire(Array.isArray(values) && values.length === 1);
    const value = record(values[0]), configuration = record(value.Config), state = record(value.State);
    hostRequire(value.Name === '/' + name && value.Image === profile.image && record(configuration.Labels)['scanmux.job'] === intent.jobId
      && typeof value.Id === 'string' && /^[a-f0-9]{64}$/.test(value.Id) && typeof state.Running === 'boolean');
    containerId = value.Id;
    const ownerBytes = await optional(intent.directory, 'owner.json', profile.scan.maxOutputBytes);
    if (ownerBytes) {
      const owner = record(parse(ownerBytes));
      hostRequire(owner.containerId === containerId && owner.jobId === intent.jobId && owner.name === name && owner.image === profile.image && owner.label === 'scanmux.job');
    }
    if (state.Running) { good(await control(['kill', '--signal', 'KILL', containerId])); good(await control(['wait', containerId])); }
    const ended = parse(good(await control(['inspect', containerId]))); hostRequire(Array.isArray(ended) && ended.length === 1);
    const actual = record(ended[0]), last = record(actual.State);
    hostRequire(actual.Id === containerId && actual.Name === '/' + name && actual.Image === profile.image && record(record(actual.Config).Labels)['scanmux.job'] === intent.jobId
      && last.Running === false && Number.isInteger(last.ExitCode) && Number(last.ExitCode) >= 0 && Number(last.ExitCode) <= 255 && typeof last.OOMKilled === 'boolean');
    terminal = { exitCode: Number(last.ExitCode), oomKilled: last.OOMKilled };
    good(await control(['rm', containerId]));
  }
  const health = record(parse(good(await control(['version', '--format', '{{json .Server}}'])))); hostRequire(health.Os === 'linux' && health.Arch === 'amd64');
  const absent = await control(['inspect', containerId ?? name]);
  const listed = good(await control(['ps', '-a', '--no-trunc', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']));
  hostRequire(absent.code !== 0 && listed.toString('utf8').trim() === '' && (await readdir(home)).length === 0);
  const cleanup: HostCleanupRecord = { schema: 'scanmux.host-job-cleanup/v1', jobId: intent.jobId, intentSha256, containerId, terminal, containerAbsent: true, daemonHealthy: true };
  validateCleanup(cleanup, intent, intentSha256);
  const bytes = encode(cleanup);
  if (intent.schema === 'scanmux.host-job-intent/v2') {
    const retained = createRetainedClient(intent, intentSha256, () => expiresAt);
    hostRequire((await retained.write([{ name: 'host-job-cleanup.json', bytes }])).result === 'committed');
  } else await exclusive(path.join(intent.directory, 'host-job-cleanup.json'), bytes, profile.scan.maxOutputBytes);
}

async function launchOwner(intent: HostJobIntent, intentSha256: string, signal: AbortSignal): Promise<NonNullable<HostJobReport['ownerTerminal']>> {
  const budget = scopedCopyBudget();
  const child = spawn(intent.host.owner.path, [intent.directory, intentSha256, ...(budget ? [String(budget.remainingBytes)] : [])], {
    windowsHide: true, shell: false, cwd: intent.directory, env: cleanEnvironment(intent.directory), stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stdout: Buffer[] = []; let size = 0, stderrBytes = 0, valid = true;
  const cancel = () => { if (!child.stdin.destroyed) child.stdin.write('CANCEL\n', () => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  child.stdin.on('error', () => {});
  child.once('error', () => { valid = false; });
  for (const [stream, keep] of [[child.stdout, true], [child.stderr, false]] as const) {
    stream.on('data', bytes => { size += bytes.length; if (!keep) stderrBytes += bytes.length; if (size > hostControlMaximum) { valid = false; child.kill(); } else if (keep) stdout.push(Buffer.from(bytes)); });
    stream.on('error', () => { valid = false; child.kill(); });
  }
  const timer = setTimeout(() => { valid = false; child.kill(); }, intent.host.limits.wallMs + intent.host.limits.cleanupTimeoutMs);
  if (signal.aborted) cancel();
  return new Promise(resolve => child.once('close', (code, terminationSignal) => {
    clearTimeout(timer); signal.removeEventListener('abort', cancel); child.stdin.destroy();
    const text = Buffer.concat(stdout).toString('utf8').trim();
    valid &&= stderrBytes === 0 && (code === 0 && text === 'closed' || code === 1 && text === 'failed');
    resolve({ code: code !== null && code >= 0 ? code : null, signal: terminationSignal === 'SIGTERM' || terminationSignal === 'SIGKILL' ? terminationSignal : null,
      protocolValid: valid && terminationSignal === null });
  }));
}

interface HostAnalysisCandidate {
  report: Report; pair: VerifiedCheckpointPair | null; analysis: NonNullable<HostJobReport['analysis']>; files: SavedFile[];
}
interface HostEvidence {
  files: SavedFile[]; native: HostNativeReceipt | null; plan: JobPlan | null; planBytes: Buffer | null;
  report: Report | null; pair: VerifiedCheckpointPair | null; analysis: HostJobReport['analysis']; normalInner: boolean;
  finalCandidate: HostAnalysisCandidate | null; prefixCandidate: HostAnalysisCandidate | null;
  refs: Pick<HostJobReport, 'native' | 'primary' | 'cleanup' | 'delegated' | 'acceptedFailure'>;
  failures: string[]; containerAbsent: boolean; daemonHealthy: boolean;
  retained: HostRetainedEvidence | null;
  copyBudgetStopped: boolean;
}
type CompletionContext = Pick<HostCompletionInput, 'ownerTerminal' | 'inputsUnchanged' | 'cancelled' | 'recovered'>;
async function evidence(directory: string, intent: HostJobIntent, intentSha256: string, context: CompletionContext, snapshot: RetainedSnapshot | null = null): Promise<HostEvidence> {
  const maximum = intent.offline.scan.maxOutputBytes;
  const result: HostEvidence = { files: [], native: null, plan: null, planBytes: null, report: null, pair: null, analysis: null, normalInner: false,
    finalCandidate: null, prefixCandidate: null, copyBudgetStopped: false,
    refs: { native: null, primary: null, cleanup: null, delegated: null, acceptedFailure: null }, failures: [], containerAbsent: false, daemonHealthy: false, retained: null };
  const files = new Map<string, Buffer>();
  for (const name of ['host-job-native.json', 'host-job-primary.json', 'host-job-cleanup.json', 'host-job-failure.json', 'delegated-job.json']) {
    const bytes = await optional(directory, name, name === 'host-job-failure.json' ? hostFailureMaximum : maximum);
    if (bytes) { files.set(name, bytes); result.files.push({ name, bytes }); }
  }
  const ref = (name: string) => { const bytes = files.get(name); return bytes ? jobReference(bytes) : null; };
  result.refs = { native: ref('host-job-native.json'), primary: ref('host-job-primary.json'), cleanup: ref('host-job-cleanup.json'), delegated: ref('delegated-job.json'), acceptedFailure: ref('host-job-failure.json') };
  try {
    const bytes = files.get('host-job-native.json');
    if (!bytes) throw new SafeError('host_job_native_unverified');
    result.native = validateHostNativeReceipt(parseJobJson(bytes), intent, intentSha256);
    if (!hostNativeClosed(result.native)) result.failures.push('host_job_native_unverified');
    const primary = files.get('host-job-primary.json');
    hostRequire(primary);
    const proof = record(parseJobJson(primary));
    hostRequire(Object.keys(proof).length === 5 && proof.schema === 'scanmux.windows-job-primary/v1' && proof.jobId === intent.jobId && proof.intentSha256 === intentSha256
      && isDeepStrictEqual(proof.owner, result.native.owner) && isDeepStrictEqual(proof.phase, result.native.phases[0]));
  } catch { result.failures.push('host_job_native_unverified'); result.native = null; }
  try {
    const bytes = files.get('host-job-cleanup.json'); if (!bytes) throw new SafeError('host_job_cleanup_unverified');
    const cleanup = validateCleanup(parseJobJson(bytes), intent, intentSha256);
    result.containerAbsent = cleanup.containerAbsent; result.daemonHealthy = cleanup.daemonHealthy;
  } catch { result.failures.push('host_job_cleanup_unverified'); }
  const failureBytes = files.get('host-job-failure.json');
  if (failureBytes) {
    try { result.failures.push(validateHostJobFailure(parseJobJson(failureBytes), intent.jobId, digest(intent.offline)).code); }
    catch { result.failures.push('host_job_failure_unverified'); }
  }
  if (intent.schema === 'scanmux.host-job-intent/v2') {
    const policy = retainedPolicy(intent, intentSha256), bytes = await optional(directory, 'host-job-retained.json', 4096);
    result.retained = { scope: 'recorded_original_before_envelope_not_copy_quota', snapshot, stop: null, witness: bytes ? jobReference(bytes) : null };
    if (bytes) result.files.push({ name: 'host-job-retained.json', bytes });
    try {
      if (snapshot) validateRetainedSnapshot(snapshot, policy);
      else result.failures.push('host_job_retained_unverified');
      if (bytes) {
        result.retained.stop = validateRetainedAllocationStop(parseJobJson(bytes), policy, snapshot ?? undefined);
        const metadata = files.get('delegated-job.json'); hostRequire(metadata);
        const delegated = validateJobReport(parseJobJson(metadata)), stop = delegated.resources.stop;
        hostRequire(delegated.jobId === intent.jobId && delegated.profileSha256 === digest(intent.offline)
          && stop?.kind === 'retained' && stop.proposedBytes === result.retained.stop.proposedAllocatedBytes
          && stop.availableBytes === result.retained.stop.availableIntermediateBytes && delegated.analysis?.kind !== 'report');
        result.failures.push(...delegated.knownFailures);
      } else if (snapshot) hostRequire(!snapshot.files.some(file => file.slot === 2));
      if (snapshot) {
        for (const file of result.files) {
          const slot = retainedCatalog(maximum).find(slot => slot.name === file.name); hostRequire(slot);
          hostRequire(snapshot.files.some(measured => measured.slot === slot.slot && measured.bytes === file.bytes.length));
        }
      }
    } catch { result.failures.push('host_job_retained_unverified'); }
  }
  const planBytes = await optional(directory, 'job-plan.json', maximum);
  async function checkStoppedDelegate() {
    if (!result.retained?.stop) return;
    try {
      const metadata = files.get('delegated-job.json'); hostRequire(metadata);
      const delegated = validateJobReport(parseJobJson(metadata));
      hostRequire(isDeepStrictEqual(delegated.plan, result.planBytes ? jobReference(result.planBytes) : null)
        && isDeepStrictEqual(delegated.origin, result.plan?.origin ?? null));
      if (result.prefixCandidate) {
        const saved = await readSavedJobRecord(path.join(directory, 'delegated-job.json'), maximum, 'delegated-job.json');
        hostRequire(saved.job.analysis?.kind === 'checkpoint' && result.prefixCandidate.analysis.kind === 'checkpoint'
          && saved.job.analysis.sequence === result.prefixCandidate.analysis.sequence && isDeepStrictEqual(saved.plan, result.plan)
          && isDeepStrictEqual(saved.report, result.prefixCandidate.report));
      } else hostRequire(delegated.analysis === null);
      const checked = jobOutcome({ plan: result.plan, report: null, prefix: result.prefixCandidate?.pair ?? null,
        stop: delegated.resources.stop, closure: delegated.closure, failures: delegated.knownFailures });
      hostRequire(checked.gate === delegated.gate && checked.exitCode === delegated.exitCode);
      if (checked.gate === 'ERROR') result.failures.push('host_job_worker_failed');
    } catch { result.failures.push('host_job_retained_unverified'); }
  }
  if (!planBytes) {
    if (intent.offline.maxCopyBytes !== undefined && files.has('delegated-job.json')) {
      try {
        const delegated = validateJobReport(parseJobJson(files.get('delegated-job.json')!));
        hostRequire(delegated.jobId === intent.jobId && delegated.profileSha256 === digest(intent.offline) && delegated.originDigest === hash(intent.root)
          && delegated.basis === 'live_owner_recorded' && delegated.plan === null && delegated.analysis === null
          && delegated.gate === 'INCOMPLETE' && delegated.exitCode === 3 && delegated.knownFailures.length === 0
          && isDeepStrictEqual(delegated.reasons, ['job_disk_copy_limit']) && isDeepStrictEqual(delegated.resources.requested, intent.offline.limits)
          && ['startup', 'ending', 'stop', 'nativeFailure', 'observer'].every(key => delegated.resources[key as keyof typeof delegated.resources] === null)
          && delegated.closure.startupVerified === false && delegated.closure.supervisorClosed === false
          && delegated.closure.ownedTasksClosure === 'unverified' && delegated.closure.controllerCompleted === false
          && delegated.closure.controllerTerminal === null && delegated.closure.terminal === null && delegated.closure.containerAbsent === false
          && delegated.closure.daemonHealthy === false && delegated.closure.inputsUnchanged === false
          && delegated.infrastructure.appFiles === 0 && delegated.infrastructure.appBytes === 0);
        hostRequire(!await lstat(path.join(directory, 'app')).catch(error => { if (error.code === 'ENOENT') return null; throw error; }));
        result.copyBudgetStopped = true;
      } catch { result.failures.push('host_job_worker_failed'); }
    }
    await checkStoppedDelegate(); return result;
  }
  try {
    result.plan = validateJobPlan(parseJobJson(planBytes), expectedPlan(intent)); result.planBytes = planBytes; result.files.push({ name: 'job-plan.json', bytes: planBytes });
  } catch { result.failures.push('host_job_worker_failed'); return result; }
  // Collect independent candidates first. Outer completion facts choose exactly
  // one later; a failed final candidate must not discard a valid committed prefix.
  try {
    const checkpointDirectory = path.join(directory, 'checkpoints'), exists = await lstat(checkpointDirectory).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (exists) {
      const recovered = await readEngineCheckpoints(checkpointDirectory, maximum), prefix = await fixedPrefix(directory, recovered.sequence, maximum, result.plan);
      hostRequire(prefix.pair && isDeepStrictEqual(prefix.pair.checkpoint.report, recovered.report));
      result.prefixCandidate = { pair: prefix.pair, report: recovered.report,
        analysis: { kind: 'checkpoint', sequence: recovered.sequence, body: jobReference(prefix.files.at(-2)!.bytes), receipt: jobReference(prefix.files.at(-1)!.bytes) }, files: prefix.files };
    }
  } catch { result.failures.push('host_job_worker_failed'); }
  await checkStoppedDelegate();
  try {
    const outer = hostJobCompletion({ ...context, native: result.native, containerAbsent: result.containerAbsent, daemonHealthy: result.daemonHealthy,
      normalInner: false, hasFinal: false, hasPrefix: result.prefixCandidate !== null, failures: result.failures, retainedStop: result.retained?.stop });
    if (outer.outerFinalEligible && files.has('delegated-job.json')) {
      const saved = await readSavedJobRecord(path.join(directory, 'delegated-job.json'), maximum, 'delegated-job.json');
      hostRequire(isDeepStrictEqual(saved.plan, result.plan));
      result.failures.push(...saved.job.knownFailures);
      if (saved.job.analysis?.kind === 'report') {
        const reportBytes = await readJobRegular(path.join(directory, 'report.json'), maximum);
        result.normalInner = true;
        result.finalCandidate = { report: saved.report, pair: saved.pair, analysis: { kind: 'report', reference: jobReference(reportBytes) },
          files: saved.files.filter(file => file.name !== 'job-plan.json') };
      }
    }
  } catch { result.failures.push('host_job_worker_failed'); }
  return result;
}
function makeReport(intent: HostJobIntent, intentBytes: Buffer, collected: HostEvidence, ownerTerminal: HostJobReport['ownerTerminal'], inputsUnchanged: boolean, cancelled: boolean, recovered: boolean) {
  const completion = hostJobCompletion({ native: collected.native, ownerTerminal, inputsUnchanged, cancelled, recovered,
    containerAbsent: collected.containerAbsent, daemonHealthy: collected.daemonHealthy, normalInner: collected.normalInner,
    hasFinal: collected.finalCandidate !== null, hasPrefix: collected.prefixCandidate !== null, failures: collected.failures, retainedStop: collected.retained?.stop });
  const selected = completion.analysisKind === 'report' ? collected.finalCandidate : completion.analysisKind === 'checkpoint' ? collected.prefixCandidate : null;
  const facts: HostEvidence = { ...collected, files: [...collected.files, ...(selected?.files ?? [])],
    report: selected?.report ?? null, pair: selected?.pair ?? null, analysis: selected?.analysis ?? null };
  const outcome = hostJobOutcome({ plan: facts.plan, analysis: facts.report, completion, copyBudgetStopped: facts.copyBudgetStopped });
  if (collected.retained?.snapshot) {
    const snapshot = collected.retained.snapshot, catalog = retainedCatalog(intent.offline.scan.maxOutputBytes);
    hostRequire(snapshot.files.some(file => file.slot === 0 && file.bytes === intentBytes.length));
    for (const file of facts.files) {
      const slot = catalog.find(slot => slot.name === file.name); hostRequire(slot);
      hostRequire(snapshot.files.some(measured => measured.slot === slot.slot && measured.bytes === file.bytes.length));
    }
  }
  const v2 = intent.schema === 'scanmux.host-job-intent/v2';
  const report = validateHostJobReport({ schema: v2 ? 'scanmux.host-job-report/v2' : 'scanmux.host-job-report/v1',
    ...(v2 ? { retained: facts.retained } : {}), jobId: intent.jobId, hostProfileSha256: digest(intent.host), offlineProfileSha256: digest(intent.offline), originDigest: hash(intent.root),
    intent: jobReference(intentBytes), ...facts.refs, plan: facts.planBytes ? jobReference(facts.planBytes) : null, analysis: facts.analysis,
    basis: recovered ? 'recovered_saved_checkpoint_without_original_live_ownership' : 'live_owner_recorded', ownerTerminal,
    closure: completion.closure, resources: { host: intent.host.limits, linux: intent.offline.limits, trustedOwnerAndAdmissionExcluded: true, retainedPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false, aggregateHostLinuxBudget: false },
    infrastructure: { maximumMetadataFiles: v2 ? 7 : 6, maximumMetadataBytes: hostControlMaximum + 4 * intent.offline.scan.maxOutputBytes + hostFailureMaximum + (v2 ? 4096 : 0),
      filesBeforeEnvelope: 1 + facts.files.filter(file => file.name.startsWith('host-job-')).length,
      bytesBeforeEnvelope: intentBytes.length + facts.files.filter(file => file.name.startsWith('host-job-')).reduce((sum, file) => sum + file.bytes.length, 0) },
    knownFailures: completion.failures, unobservedInternalErrors: 'unknown', ...outcome }, intent);
  return { job: report, facts };
}

export async function scanHostJob(target: string, profilePath: string, signal: AbortSignal, comparison?: CommitPair) {
  if (process.platform !== 'win32' || process.arch !== 'x64' || !/^v24\./.test(process.version)) throw new SafeError('unsupported_host_job_runtime');
  if (!hostLocalPath(target) || target.includes('://')) throw new SafeError('host_job_local_root_required');
  if (!hostLocalPath(profilePath)) throw new SafeError('invalid_host_job_record');
  const started = performance.now();
  const root = await canonical(target), source = await regularJobFile(profilePath, root), raw = await boundedRead(source, hostControlMaximum);
  const host = parseHostJobProfile(parseJobJson(raw));
  // Everything before the owner shares one admission window, so separate step clocks cannot add up past the bound.
  // Runtime-policy and provenance refusals keep their own codes, including a gh check cut short by the window.
  const admission: HostDeadline = { at: started + hostCommandPlan(host.limits).admissionMs, code: 'host_job_admission_deadline' };
  const admit = () => { if (signal.aborted) throw new SafeError('host_job_cancelled'); checkDeadline(admission); };
  // A step whose own timeout was cut to the window reports the window, not its own timeout code.
  const withinAdmission = async <T>(step: (timeoutMs: number) => Promise<T>): Promise<T> => {
    admit();
    const left = Math.floor(admission.at - performance.now()), timeoutMs = Math.max(1, Math.min(host.limits.cleanupTimeoutMs, left));
    try { return await step(timeoutMs); }
    catch (error) {
      if (error instanceof SafeError && error.code === 'process_start_deadline') throw new SafeError(admission.code);
      // A runtime-policy or provenance refusal keeps its documented code even when it arrives late.
      const refusal = error instanceof SafeError && /^(?:runtime_policy|provenance)_/.test(error.code);
      if (!signal.aborted && !refusal && performance.now() >= admission.at) throw new SafeError(admission.code);
      throw error;
    }
  };
  const offlineProfile = parseJobProfile(parseJobJson(await readJobRegular(host.offlineProfile, hostControlMaximum)), acceptPolicy);
  validateHostOfflinePaths(offlineProfile);
  hostRequire(host.node.path === process.execPath && host.node.version === process.version.slice(1));
  for (const tool of [host.node, host.owner]) { admit(); hostRequire(await regularJobFile(tool.path, root) === tool.path); await verifyTool(tool, root); }
  admit();
  const offline = await boundedProfile(host.offlineProfile, root, admission);
  return withCopyBudget(offline.profile.maxCopyBytes, async () => {
  if (offline.profile.schema === 'scanmux.job-profile/v2') {
    const runtimePolicy = offline.profile.runtimePolicy, subjects = [{ component: 'windows-owner' as const, sha256: host.owner.sha256, file: host.owner.path },
      { component: 'node' as const, sha256: host.node.sha256, file: host.node.path }, ...jobRuntimeSubjects(offline.profile)];
    await withinAdmission(timeoutMs => admitRuntime(runtimePolicy, subjects, { root, timeoutMs, signal, deadlineAt: admission.at }));
  }
  const directory = await privateWorkspace(root);
  await mkdir(path.join(directory, 'AppData', 'Roaming'), { recursive: true, mode: 0o700 });
  await withinAdmission(timeoutMs => verifyVersion(host.owner, ['--version'], { cwd: directory, home: directory, timeoutMs, maxOutputBytes: hostControlMaximum, signal }, executeDirect));
  const assets = [];
  for (const file of jobRuntimeFiles) { admit(); assets.push({ path: file, ...await boundedIdentity(path.join(application, ...file.split('/')), admission) }); }
  const admissionDeadline = Math.min(performance.now() + host.limits.cleanupTimeoutMs, admission.at);
  const storage = host.schema === 'scanmux.host-job-profile/v2'
    ? { ...await withinAdmission(() => probeRetainedVolume(host.owner, directory, () => admissionDeadline, signal)), allocatedBytes: host.retained.allocatedBytes } : null;
  admit();
  const offlineSource = await boundedIdentity(offline.source, admission), rootIdentityNow = await rootIdentity(root);
  admit();
  const nodeIdentity = await boundedIdentity(host.node.path, admission);
  admit();
  const ownerIdentity = await boundedIdentity(host.owner.path, admission);
  const intent = validateHostJobIntent({ schema: storage ? 'scanmux.host-job-intent/v2' : 'scanmux.host-job-intent/v1', ...(storage ? { storage } : {}),
    mode: 'scan', jobId: randomUUID(), root, directory, comparison: comparison ?? null,
    rootIdentity: rootIdentityNow, host, hostSource: { path: source, identity: jobReference(raw) }, offline: offline.profile,
    offlineSource, application, assets, nodeIdentity, ownerIdentity,
    maxProcesses: nativeProcessCapacity(offline.profile.scan.maxOutputBytes) });
  validateHostJobIntent(intent); const intentBytes = encode(intent); hostRequire(intentBytes.length <= hostControlMaximum);
  admit();
  if (intent.schema === 'scanmux.host-job-intent/v2') await withinAdmission(() => initializeRetainedStore(intent, intentBytes, () => admissionDeadline, signal));
  else await exclusive(path.join(directory, 'host-job-intent.json'), intentBytes, hostControlMaximum);
  await verifyHostJobInputs(intent, admission);
  admit();
  const ownerStarted = performance.now(), ownerTerminal = await launchOwner(intent, hash(intentBytes), signal);
  let closingDeadline = ownerStarted + intent.host.limits.wallMs + intent.host.limits.cleanupTimeoutMs;
  if (intent.schema === 'scanmux.host-job-intent/v2') {
    try {
      const bytes = await optional(directory, 'host-job-native.json', intent.offline.scan.maxOutputBytes); hostRequire(bytes);
      const native = validateHostNativeReceipt(parseJobJson(bytes), intent, hash(intentBytes));
      if (native.closingStartedMs !== null) closingDeadline = Math.min(closingDeadline, ownerStarted + native.closingStartedMs + intent.host.limits.cleanupTimeoutMs);
    } catch {}
  }
  const retained = intent.schema === 'scanmux.host-job-intent/v2' ? createRetainedClient(intent, hash(intentBytes), () => closingDeadline) : null;
  let snapshot: RetainedSnapshot | null = null;
  if (retained) { try { snapshot = await retained.inspect(); } catch {} }
  // After the owner, the closing deadline bounds both record versions; past it no host-job.json is written.
  const closing: HostDeadline = { at: closingDeadline, code: 'host_job_command_deadline' };
  let inputsUnchanged = false;
  try { await verifyHostJobInputs(intent, closing); inputsUnchanged = true; }
  catch (error) { if (error instanceof SafeError && error.code === closing.code) throw error; }
  checkDeadline(closing);
  const cancelled = signal.aborted;
  const facts = await evidence(directory, intent, hash(intentBytes), { ownerTerminal, inputsUnchanged, cancelled, recovered: false }, snapshot);
  const report = makeReport(intent, intentBytes, facts, ownerTerminal, inputsUnchanged, cancelled, false).job;
  const json = encode(report);
  checkDeadline(closing);
  if (retained) {
    let committed: boolean;
    try { committed = (await retained.write([{ name: 'host-job.json', bytes: json }])).result === 'committed'; }
    catch (error) { if (performance.now() >= closing.at) throw new SafeError(closing.code); throw error; }
    hostRequire(committed);
  } else await exclusive(path.join(directory, 'host-job.json'), json, intent.offline.scan.maxOutputBytes);
  return { job: report, json: json.toString('utf8'), directory, destination: path.join(directory, 'host-job.json') };
  });
}

export async function isHostJobRecovery(directory: string): Promise<boolean> {
  return !!await lstat(path.join(directory, 'host-job-intent.json')).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
}
async function checkSavedOriginalCatalog(directory: string, intent: HostJobIntent, snapshot: RetainedSnapshot | null) {
  // Copies may omit unselected tails or add derived report formats. Their filesystem
  // is outside the recorded origin guarantee; only selected references are checked.
  if (intent.schema !== 'scanmux.host-job-intent/v2' || directory !== intent.directory || !snapshot) return;
  const catalog = retainedCatalog(intent.offline.scan.maxOutputBytes);
  const allowed = new Set([...catalog.filter(slot => !slot.name.includes('/')).map(slot => slot.name),
    'checkpoints', 'AppData', 'app', 'docker-config', 'host-cleanup-docker-config', 'empty-gitconfig', 'retained-write.lock']);
  hostRequire((await readdir(directory)).every(name => allowed.has(name)));
  const checkpointDirectory = path.join(directory, 'checkpoints'), checkpoints = await lstat(checkpointDirectory).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
  if (checkpoints) {
    hostRequire(checkpoints.isDirectory() && !checkpoints.isSymbolicLink() && await canonical(checkpointDirectory) === checkpointDirectory);
    const names = new Set(catalog.filter(slot => slot.name.startsWith('checkpoints/')).map(slot => slot.name.slice('checkpoints/'.length)));
    hostRequire((await readdir(checkpointDirectory)).every(name => names.has(name)));
  }
  for (const slot of catalog) {
    if (slot.slot === 9) continue; // The recorded observation precedes this envelope.
    const bytes = await optional(directory, slot.name, slot.maximum), measured = snapshot.files.find(file => file.slot === slot.slot);
    hostRequire(bytes === null ? measured === undefined : measured !== undefined && measured.bytes === bytes.length);
  }
}
async function savedHostJob(input: string, configPath: string, config: Config, recover: boolean) {
  if (!path.isAbsolute(input) || !recover && path.basename(input) !== 'host-job.json') throw new SafeError('invalid_host_job_record');
  const directory = await canonical(recover ? input : path.dirname(input)), loaded = await readHostJobIntent(directory), { intent } = loaded;
  let raw: Buffer | null = null, recorded: HostJobReport | null = null;
  if (!recover) { raw = await readJobRegular(path.join(directory, 'host-job.json'), config.maxOutputBytes); recorded = validateHostJobReport(parseJobJson(raw), intent); }
  const recoveredBasis = recover || recorded?.basis === 'recovered_saved_checkpoint_without_original_live_ownership';
  const context: CompletionContext = { ownerTerminal: recorded?.ownerTerminal ?? null, inputsUnchanged: recorded?.closure.inputsUnchanged ?? false,
    cancelled: recorded?.knownFailures.includes('host_job_cancelled') ?? false, recovered: recoveredBasis };
  const snapshot = recorded?.schema === 'scanmux.host-job-report/v2' ? recorded.retained.snapshot : null;
  await checkSavedOriginalCatalog(directory, intent, snapshot);
  const collected = await evidence(directory, intent, loaded.sha256, context, snapshot);
  const finalized = makeReport(intent, loaded.bytes, collected, context.ownerTerminal, context.inputsUnchanged, context.cancelled, context.recovered), facts = finalized.facts, rebuilt = finalized.job;
  if (!facts.plan || !facts.report) throw new SafeError('job_analysis_unavailable');
  const root = await canonical(facts.plan.origin.root); hostRequire(root === intent.root && !within(root, directory));
  await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
  if (!config.tools.gitleaks) throw new SafeError('output_secret_check_unavailable');
  await regularJobFile(config.tools.gitleaks.path, root);
  if (recorded) hostRequire(isDeepStrictEqual(recorded, rebuilt));
  return { directory, loaded, facts, job: recorded ?? rebuilt, raw: raw ?? encode(rebuilt), root };
}
function escape(text: string) { return text.replace(/[&<>"']/g, value => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[value]!); }
async function exportHostSaved(saved: Awaited<ReturnType<typeof savedHostJob>>, config: Config, inputLanguage: ReportLanguage) {
  const language = parseReportLanguage(inputLanguage), report = saved.facts.report; hostRequire(report);
  const provisional = saved.job.analysis?.kind === 'checkpoint';
  const physicalExclusion = saved.job.schema === 'scanmux.host-job-report/v2'
    ? language === 'ja' ? 'ディレクトリ全体の物理容量' : 'whole-directory physical storage'
    : language === 'ja' ? '保持出力の物理容量' : 'retained physical storage';
  const text = language === 'ja'
    ? `保存されたホスト実行判定: ${saved.job.gate}。解析記録: ${report.gate}${provisional ? '（途中保存・完了未確認）' : ''}。WindowsのCPU・コミット済みメモリとLinux処理には別々の上限があります。管理役と受入・出力処理、${physicalExclusion}、コマンド全体時間は保証範囲外です。保存済みの終了情報は現在の所有権や耐久性を再認証しません。`
    : `Recorded host-job outcome: ${saved.job.gate}. Analysis: ${report.gate}${provisional ? ' (provisional; completion unverified)' : ''}. Windows CPU/committed memory and the Linux payload have separate limits. Trusted owner/admission/export, ${physicalExclusion} and total command time are excluded. Saved termination facts do not authenticate current ownership or durability.`;
  const retainedText = saved.job.schema !== 'scanmux.host-job-report/v2' ? '' : language === 'ja'
    ? `固定保持ファイルのデータ割当上限: ${saved.loaded.intent.schema === 'scanmux.host-job-intent/v2' ? saved.loaded.intent.storage.allocatedBytes : ''} bytes。外側記録の保存前に観測した割当: ${saved.job.retained.snapshot?.allocatedBytes ?? '未確認'} bytes、未使用の管理情報予約: ${saved.job.retained.snapshot?.reservedBytes ?? '未確認'} bytes。${saved.job.retained.stop ? 'データ割当量の上限による受付停止を記録。' : ''}これは元の実行の保存事実で、この出力先の容量制限を保証しません。ディレクトリ全体・実行用コピー・ファイルシステム管理情報・OS/Docker等は対象外です。`
    : `Controlled record data allocation limit: ${saved.loaded.intent.schema === 'scanmux.host-job-intent/v2' ? saved.loaded.intent.storage.allocatedBytes : ''} bytes. Recorded allocation before the outer envelope: ${saved.job.retained.snapshot?.allocatedBytes ?? 'unverified'} bytes; outstanding metadata reservations: ${saved.job.retained.snapshot?.reservedBytes ?? 'unverified'} bytes. ${saved.job.retained.stop ? 'Record admission stopped at the allocated data limit. ' : ''}These are original run facts, not a quota on this export destination. The whole directory, runtime copy, filesystem metadata and OS/Docker stores are excluded.`;
  const origin = language === 'ja' ? '元のホストパス' : 'Recorded host origin', mapped = language === 'ja' ? '解析時のLinuxパス' : 'Actual Linux analysis root';
  const html = renderHtmlReport(report, language).replace(/<body(?:\s[^>]*)?>/, body => body + `<aside role="note"><p>${escape(text)}</p>${retainedText ? `<p>${escape(retainedText)}</p>` : ''}<p>${origin}: <code>${escape(saved.facts.plan?.origin.root ?? '')}</code><br>${mapped}: <code>${escape(report.plan.root)}</code></p></aside>`);
  const sarif = renderSarifReports(report, config.maxOutputBytes).map(part => {
    const value = record(JSON.parse(part.text)); hostRequire(Array.isArray(value.runs));
    for (const raw of value.runs) {
      const run = record(raw);
      run.properties = { ...record(run.properties ?? {}), scanmuxHostJob: { jobId: saved.job.jobId, gate: saved.job.gate, analysisGate: report.gate, provisional,
        basis: saved.job.basis, resources: saved.job.resources,
        ...(saved.job.schema === 'scanmux.host-job-report/v2' ? { retained: saved.job.retained } : {}), savedOwnershipNotReauthenticated: true } };
    }
    return { name: part.name, bytes: encode(value) };
  });
  const files = [{ name: 'host-job-intent.json', bytes: saved.loaded.bytes }, ...saved.facts.files,
    { name: 'host-job.json', bytes: saved.raw }, { name: 'report.html', bytes: Buffer.from(html) },
    ...sarif];
  if (!files.some(file => file.name === 'report.json')) files.push({ name: 'report.json', bytes: encode(report) });
  hostRequire(new Set(files.map(file => file.name)).size === files.length && !files.some(file => file.name === 'job.json'));
  const destination = await privateWorkspace(saved.root);
  for (const file of files) {
    hostRequire(file.bytes.length <= config.maxOutputBytes);
    const value = new TextDecoder('utf8', { fatal: true }).decode(file.bytes);
    hostRequire(await checkedText(value, config, destination) === value);
  }
  await checkedText(JSON.stringify({ destination, job: path.join(destination, 'host-job.json'), html: path.join(destination, 'report.html') }), config, destination);
  if (files.some(file => file.name.startsWith('checkpoints/'))) await mkdir(path.join(destination, 'checkpoints'), { mode: 0o700 });
  for (const file of files) await exclusive(path.join(destination, ...file.name.split('/')), file.bytes, config.maxOutputBytes);
  return { job: saved.job, json: saved.raw.toString('utf8'), directory: destination, destination: path.join(destination, 'host-job.json'), htmlDestination: path.join(destination, 'report.html'), report };
}
export async function exportHostJob(input: string, configPath: string, config: Config, language: ReportLanguage) {
  return exportHostSaved(await savedHostJob(input, configPath, config, false), config, language);
}
export async function recoverHostJob(input: string, configPath: string, config: Config, language: ReportLanguage) {
  // Saved bytes never authorize Docker operations or a new native owner.
  return exportHostSaved(await savedHostJob(input, configPath, config, true), config, language);
}
