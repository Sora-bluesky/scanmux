import path from 'node:path';
import { closeSync, fsyncSync, openSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import type { CommitPair, Gate, Report, Tool } from './model.ts';
import { parseJobProfile, type JobProfile } from './job-config.ts';
import { jobHostFailureCodes, type JobAsset, type JobFileReference, type JobKnownFailure, type JobPlan } from './job-records.ts';
import { decide, exitCodes } from './policy.ts';
import { digest, hostLocalPath, record, safeRelative, SafeError } from './safety.ts';
import { jobFailureCodes } from '../internal/job-channel.mjs';
import { retainedCatalog, retainedPolicy, validateRetainedSnapshot, validateRetainedAllocationStop,
  type RetainedClient, type RetainedSnapshot, type RetainedAllocationStop } from './retained-write.ts';

export const windowsOwnerVersion = '1.0.0';
export const windowsRetainedOwnerVersion = '1.1.0';
export const windowsOwnerForcedExit = 0xe1000001;
export const hostControlMaximum = 65536;
// Bounds for the fixed native schema (no path/text fields), including two phases.
export const nativeFixedBytes = 8192, nativeProcessBytes = 2 * 512, hostFailureMaximum = 1024;
export const hostFailureCodes = [
  'host_job_native_unverified', 'host_job_inputs_changed', 'host_job_worker_failed', 'host_job_cleanup_unverified',
  'host_job_failure_unverified', 'host_job_cancelled', 'host_job_recovered_without_original_ownership',
  'host_job_retained_unverified',
] as const;
export type HostFailureCode = typeof hostFailureCodes[number];
const allJobFailures: readonly string[] = [...jobFailureCodes, ...jobHostFailureCodes];
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const shaPattern = /^[a-f0-9]{64}$/;
export function hostRequire(value: unknown): asserts value { if (!value) throw new SafeError('invalid_host_job_record'); }
function exact(input: unknown, keys: readonly string[]) {
  const value = record(input);
  hostRequire(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
  return value;
}
function integer(input: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  hostRequire(typeof input === 'number' && Number.isSafeInteger(input) && input >= minimum && input <= maximum);
  return input;
}
function elapsed(input: unknown): number { hostRequire(typeof input === 'number' && Number.isFinite(input) && input >= 0); return input; }
function text(input: unknown, pattern: RegExp): string { hostRequire(typeof input === 'string' && pattern.test(input)); return input; }
function absolute(input: unknown): string { hostRequire(typeof input === 'string' && hostLocalPath(input)); return input; }
function tool(input: unknown): Tool {
  const value = exact(input, ['path', 'sha256', 'version']);
  return { path: absolute(value.path), sha256: text(value.sha256, shaPattern), version: text(value.version, /^\d+\.\d+\.\d+$/) };
}
function reference(input: unknown): JobFileReference {
  const value = exact(input, ['bytes', 'sha256']);
  return { bytes: integer(value.bytes, 1), sha256: text(value.sha256, shaPattern) };
}
interface HostJobProfileBase {
  name: string; scope: 'windows-offline-local'; offlineProfile: string; owner: Tool; node: Tool;
  limits: { cpuRate: number; memoryBytes: number; wallMs: number; cleanupTimeoutMs: number };
}
export type HostJobProfile = HostJobProfileBase & (
  { schema: 'scanmux.host-job-profile/v1' } | { schema: 'scanmux.host-job-profile/v2'; retained: { allocatedBytes: number } }
);
export function parseHostJobProfile(input: unknown): HostJobProfile {
  const schema = record(input).schema;
  const value = exact(input, ['schema', 'name', 'scope', 'offlineProfile', 'owner', 'node', 'limits', ...(schema === 'scanmux.host-job-profile/v2' ? ['retained'] : [])]);
  hostRequire(['scanmux.host-job-profile/v1', 'scanmux.host-job-profile/v2'].includes(String(schema)) && value.scope === 'windows-offline-local');
  const limits = exact(value.limits, ['cpuRate', 'memoryBytes', 'wallMs', 'cleanupTimeoutMs']);
  const memoryBytes = integer(limits.memoryBytes, 4096); hostRequire(memoryBytes % 4096 === 0);
  const wallMs = integer(limits.wallMs, 1, 2147483647), cleanupTimeoutMs = integer(limits.cleanupTimeoutMs, 1, 2147483647);
  hostRequire(wallMs + cleanupTimeoutMs <= 2147483647);
  const owner = tool(value.owner); hostRequire(owner.version === windowsOwnerVersion || owner.version === windowsRetainedOwnerVersion);
  const common: HostJobProfileBase = { name: text(value.name, /^[A-Za-z0-9_-]{1,64}$/), scope: 'windows-offline-local',
    offlineProfile: absolute(value.offlineProfile), owner, node: tool(value.node),
    limits: { cpuRate: integer(limits.cpuRate, 1, 10000), memoryBytes, wallMs, cleanupTimeoutMs } };
  if (schema === 'scanmux.host-job-profile/v1') return { ...common, schema };
  hostRequire(owner.version === windowsRetainedOwnerVersion);
  const retained = exact(value.retained, ['allocatedBytes']);
  return { ...common, schema: 'scanmux.host-job-profile/v2', retained: { allocatedBytes: integer(retained.allocatedBytes, 1) } };
}
export function validateHostOfflinePaths(profile: JobProfile) {
  hostRequire(profile.docker.endpoint.startsWith('npipe:'));
  const provenance = profile.schema === 'scanmux.job-profile/v2' && profile.runtimePolicy.schema === 'scanmux.runtime-policy/v2' ? profile.runtimePolicy.provenance : null;
  for (const file of [profile.docker.tool.path, profile.tools.gitleaks.path, ...(profile.tools.osv ? [profile.tools.osv.path] : []), ...(profile.osvDatabase ? [profile.osvDatabase] : []),
    ...(provenance ? [provenance.verifier.path, provenance.ledger.path] : [])]) hostRequire(hostLocalPath(file));
}
export function nativeProcessCapacity(maximum: number): number {
  integer(maximum, 1, 2147483647);
  const capacity = Math.floor((maximum - nativeFixedBytes) / nativeProcessBytes);
  hostRequire(capacity >= 2);
  return capacity;
}
interface HostJobIntentBase {
  mode: 'scan'; jobId: string; root: string; directory: string; comparison: CommitPair | null;
  rootIdentity: { device: string; inode: string; modifiedNs: string };
  host: HostJobProfile; hostSource: { path: string; identity: JobFileReference }; offline: JobProfile; offlineSource: JobFileReference;
  application: string; assets: JobAsset[]; nodeIdentity: JobFileReference; ownerIdentity: JobFileReference;
  maxProcesses: number;
}
export type HostJobIntent = HostJobIntentBase & (
  { schema: 'scanmux.host-job-intent/v1'; host: Extract<HostJobProfile, { schema: 'scanmux.host-job-profile/v1' }> }
  | { schema: 'scanmux.host-job-intent/v2'; host: Extract<HostJobProfile, { schema: 'scanmux.host-job-profile/v2' }>; storage: { fileSystem: 'NTFS'; clusterBytes: number; allocatedBytes: number } }
);
export function validateHostJobIntent(input: unknown): HostJobIntent {
  const schema = record(input).schema;
  const value = exact(input, ['schema', 'mode', 'jobId', 'root', 'directory', 'comparison', 'rootIdentity', 'host', 'hostSource', 'offline', 'offlineSource', 'application', 'assets', 'nodeIdentity', 'ownerIdentity', 'maxProcesses', ...(schema === 'scanmux.host-job-intent/v2' ? ['storage'] : [])]);
  hostRequire(['scanmux.host-job-intent/v1', 'scanmux.host-job-intent/v2'].includes(String(schema)) && value.mode === 'scan');
  const host = parseHostJobProfile(value.host), offline = parseJobProfile(value.offline, { runtimePolicy: 'accept' });
  validateHostOfflinePaths(offline);
  const hostSource = exact(value.hostSource, ['path', 'identity']), rootIdentity = exact(value.rootIdentity, ['device', 'inode', 'modifiedNs']);
  let comparison: CommitPair | null = null;
  if (value.comparison !== null) { const pair = exact(value.comparison, ['base', 'head']); comparison = { base: text(pair.base, /^[a-f0-9]{40,64}$/), head: text(pair.head, /^[a-f0-9]{40,64}$/) }; hostRequire(comparison.base.length === comparison.head.length); }
  hostRequire(Array.isArray(value.assets) && value.assets.length > 0 && value.assets.length <= 10000);
  const assets = value.assets.map(input => { const asset = exact(input, ['path', 'bytes', 'sha256']); return { path: safeRelative(asset.path), bytes: integer(asset.bytes, 1), sha256: text(asset.sha256, shaPattern) }; });
  hostRequire(new Set(assets.map(asset => asset.path)).size === assets.length && assets.every((asset, index) => index === 0 || assets[index - 1].path < asset.path));
  const maxProcesses = integer(value.maxProcesses, 2, 0xffffffff);
  hostRequire(maxProcesses === nativeProcessCapacity(offline.scan.maxOutputBytes));
  const common: HostJobIntentBase = { mode: value.mode as HostJobIntent['mode'], jobId: text(value.jobId, uuidPattern), root: absolute(value.root), directory: absolute(value.directory), comparison,
    rootIdentity: { device: text(rootIdentity.device, /^\d+$/), inode: text(rootIdentity.inode, /^\d+$/), modifiedNs: text(rootIdentity.modifiedNs, /^\d+$/) },
    host, hostSource: { path: absolute(hostSource.path), identity: reference(hostSource.identity) }, offline, offlineSource: reference(value.offlineSource),
    application: absolute(value.application), assets, nodeIdentity: reference(value.nodeIdentity), ownerIdentity: reference(value.ownerIdentity), maxProcesses };
  if (schema === 'scanmux.host-job-intent/v1') { hostRequire(host.schema === 'scanmux.host-job-profile/v1'); return { ...common, schema, host }; }
  hostRequire(host.schema === 'scanmux.host-job-profile/v2');
  const storage = exact(value.storage, ['fileSystem', 'clusterBytes', 'allocatedBytes']);
  const clusterBytes = integer(storage.clusterBytes, 1), allocatedBytes = integer(storage.allocatedBytes, 1);
  hostRequire(storage.fileSystem === 'NTFS' && allocatedBytes === host.retained.allocatedBytes && allocatedBytes % clusterBytes === 0);
  let reserved = 0;
  for (const slot of retainedCatalog(offline.scan.maxOutputBytes).filter(slot => slot.reserved)) reserved = integer(reserved + integer(Math.ceil(slot.maximum / clusterBytes) * clusterBytes));
  hostRequire(reserved <= allocatedBytes);
  return { ...common, schema: 'scanmux.host-job-intent/v2', host, storage: { fileSystem: 'NTFS', clusterBytes, allocatedBytes } };
}
export interface HostJobFailure {
  schema: 'scanmux.host-job-failure/v1'; jobId: string; profileSha256: string; code: JobKnownFailure;
}
export function validateHostJobFailure(input: unknown, jobId: string, profileSha256: string): HostJobFailure {
  const value = exact(input, ['schema', 'jobId', 'profileSha256', 'code']);
  hostRequire(value.schema === 'scanmux.host-job-failure/v1' && value.jobId === jobId && value.profileSha256 === profileSha256 && allJobFailures.includes(String(value.code)));
  return value as unknown as HostJobFailure;
}
/** Durably accept the first independent ERROR before any failure ACK. */
export function hostFailureRecorder(directory: string, jobId: string, profileSha256: string, retained?: Pick<RetainedClient, 'writeSync'>) {
  let first: HostJobFailure | null = null;
  return (code: JobKnownFailure) => {
    hostRequire(allJobFailures.includes(code));
    if (first) return;
    const failure: HostJobFailure = { schema: 'scanmux.host-job-failure/v1', jobId, profileSha256, code };
    const bytes = Buffer.from(JSON.stringify(failure) + '\n'); hostRequire(bytes.length <= hostFailureMaximum);
    if (retained) hostRequire(retained.writeSync([{ name: 'host-job-failure.json', bytes }]).result === 'committed');
    else {
      const handle = openSync(path.join(directory, 'host-job-failure.json'), 'wx', 0o600);
      try { writeFileSync(handle, bytes); fsyncSync(handle); }
      finally { closeSync(handle); }
    }
    first = failure;
  };
}

export interface HostProcessTerminal { pid: number; creationFileTime: string; memberVerified: true; signaled: boolean; exitCode: number | null }
export interface HostNativePhase {
  phase: 'primary' | 'cleanup'; reason: 'completed' | 'deadline' | 'cancelled' | 'failed'; configured: boolean; memberBeforeResume: boolean;
  cpuFlags: number; cpuRate: number; memoryBytes: number; limitFlags: number;
  root: { pid: number; creationFileTime: string } | null; processes: HostProcessTerminal[];
  totalProcesses: number; maximumTotalProcesses: number; accountingSamples: number; accountingMonotonic: boolean; coverageComplete: boolean;
  startedMs: number; endedMs: number; closingStartedMs: number | null; error: { operation: string; win32: number } | null;
}
const nativeOperations = ['descriptor', 'hash', 'create_job', 'set_limits', 'query_limits', 'create_port', 'associate_port', 'attributes', 'create_process', 'membership',
  'resume', 'accounting', 'counter_range', 'capture', 'capacity', 'identity', 'wait', 'terminate_job', 'drain', 'save', 'unexpected'] as const;
function validatePhase(input: unknown, intent: HostJobIntent): HostNativePhase {
  const value = exact(input, ['phase', 'reason', 'configured', 'memberBeforeResume', 'cpuFlags', 'cpuRate', 'memoryBytes', 'limitFlags', 'root', 'processes', 'totalProcesses', 'maximumTotalProcesses', 'accountingSamples', 'accountingMonotonic', 'coverageComplete', 'startedMs', 'endedMs', 'closingStartedMs', 'error']);
  hostRequire(['primary', 'cleanup'].includes(String(value.phase)) && ['completed', 'deadline', 'cancelled', 'failed'].includes(String(value.reason)));
  for (const key of ['configured', 'memberBeforeResume', 'accountingMonotonic', 'coverageComplete']) hostRequire(typeof value[key] === 'boolean');
  integer(value.cpuFlags); integer(value.cpuRate); integer(value.memoryBytes); integer(value.limitFlags);
  if (value.configured) hostRequire(value.cpuFlags === 5 && value.cpuRate === intent.host.limits.cpuRate && value.memoryBytes === intent.host.limits.memoryBytes && value.limitFlags === 0x2200);
  let root: HostNativePhase['root'] = null;
  if (value.root !== null) { const process = exact(value.root, ['pid', 'creationFileTime']); root = { pid: integer(process.pid, 1, 0xffffffff), creationFileTime: text(process.creationFileTime, /^[1-9]\d{0,19}$/) }; }
  hostRequire(Array.isArray(value.processes) && value.processes.length <= intent.maxProcesses);
  const processes = value.processes.map(input => {
    const process = exact(input, ['pid', 'creationFileTime', 'memberVerified', 'signaled', 'exitCode']);
    hostRequire(process.memberVerified === true && typeof process.signaled === 'boolean' && (process.exitCode === null || Number.isSafeInteger(process.exitCode)));
    hostRequire(process.signaled === (process.exitCode !== null));
    return { pid: integer(process.pid, 1, 0xffffffff), creationFileTime: text(process.creationFileTime, /^[1-9]\d{0,19}$/), memberVerified: true as const, signaled: process.signaled, exitCode: process.exitCode === null ? null : integer(process.exitCode, 0, 0xffffffff) };
  });
  hostRequire(new Set(processes.map(process => process.pid + ':' + process.creationFileTime)).size === processes.length);
  const totalProcesses = integer(value.totalProcesses, 0, 0xffffffff), maximumTotalProcesses = integer(value.maximumTotalProcesses, totalProcesses, 0xffffffff);
  integer(value.accountingSamples, 0, 0xffffffff);
  const startedMs = elapsed(value.startedMs), endedMs = elapsed(value.endedMs), closingStartedMs = value.closingStartedMs === null ? null : elapsed(value.closingStartedMs);
  hostRequire(endedMs >= startedMs && (closingStartedMs === null || closingStartedMs <= endedMs));
  let error: HostNativePhase['error'] = null;
  if (value.error !== null) { const failure = exact(value.error, ['operation', 'win32']); hostRequire(nativeOperations.includes(failure.operation as typeof nativeOperations[number])); error = { operation: String(failure.operation), win32: integer(failure.win32, 0, 0xffffffff) }; }
  if (value.coverageComplete) hostRequire(root && value.configured && value.memberBeforeResume && value.accountingMonotonic && Number(value.accountingSamples) >= 2 && !error && processes.length === totalProcesses
    && totalProcesses === maximumTotalProcesses && processes.every(process => process.signaled) && processes.some(process => process.pid === root.pid && process.creationFileTime === root.creationFileTime));
  hostRequire(value.reason !== 'completed' || value.coverageComplete === true);
  return { phase: value.phase as HostNativePhase['phase'], reason: value.reason as HostNativePhase['reason'], configured: Boolean(value.configured), memberBeforeResume: Boolean(value.memberBeforeResume),
    cpuFlags: Number(value.cpuFlags), cpuRate: Number(value.cpuRate), memoryBytes: Number(value.memoryBytes), limitFlags: Number(value.limitFlags), root, processes,
    totalProcesses, maximumTotalProcesses, accountingSamples: Number(value.accountingSamples), accountingMonotonic: Boolean(value.accountingMonotonic), coverageComplete: Boolean(value.coverageComplete), startedMs, endedMs, closingStartedMs, error };
}
export interface HostNativeReceipt {
  schema: 'scanmux.windows-job-owner/v1'; version: typeof windowsOwnerVersion | typeof windowsRetainedOwnerVersion; intentSha256: string; jobId: string; mode: HostJobIntent['mode'];
  phases: HostNativePhase[]; state: 'closed' | 'failed'; closingStartedMs: number | null; endedMs: number; owner: { pid: number; creationFileTime: string };
}
export function validateHostNativeReceipt(input: unknown, intent: HostJobIntent, intentSha256: string): HostNativeReceipt {
  const value = exact(input, ['schema', 'version', 'intentSha256', 'jobId', 'mode', 'phases', 'state', 'closingStartedMs', 'endedMs', 'owner']);
  hostRequire(value.schema === 'scanmux.windows-job-owner/v1' && value.version === intent.host.owner.version && value.intentSha256 === intentSha256 && value.jobId === intent.jobId && value.mode === intent.mode && ['closed', 'failed'].includes(String(value.state)));
  hostRequire(Array.isArray(value.phases) && value.phases.length >= 1 && value.phases.length <= 2);
  const phases = value.phases.map(phase => validatePhase(phase, intent));
  hostRequire(phases[0].phase === 'primary');
  if (phases.length === 2) hostRequire(intent.mode === 'scan' && phases[1].phase === 'cleanup' && phases[0].coverageComplete && phases[1].startedMs >= phases[0].endedMs);
  const closingStartedMs = value.closingStartedMs === null ? null : elapsed(value.closingStartedMs), endedMs = elapsed(value.endedMs);
  hostRequire(endedMs >= phases.at(-1)!.endedMs);
  if (closingStartedMs !== null) hostRequire(phases.every(phase => phase.closingStartedMs === closingStartedMs) && endedMs <= closingStartedMs + intent.host.limits.cleanupTimeoutMs || value.state === 'failed');
  if (value.state === 'closed') hostRequire(closingStartedMs !== null && phases.at(-1)!.phase === 'cleanup' && phases.every(phase => phase.coverageComplete && !phase.error));
  const owner = exact(value.owner, ['pid', 'creationFileTime']);
  return { schema: 'scanmux.windows-job-owner/v1', version: value.version as HostNativeReceipt['version'], intentSha256, jobId: intent.jobId, mode: intent.mode, phases,
    state: value.state as HostNativeReceipt['state'], closingStartedMs, endedMs, owner: { pid: integer(owner.pid, 1, 0xffffffff), creationFileTime: text(owner.creationFileTime, /^[1-9]\d{0,19}$/) } };
}
export function hostNativeClosed(native: HostNativeReceipt | null): boolean {
  return native?.state === 'closed' && native.phases.every(phase => phase.coverageComplete && phase.processes.every(process => process.signaled))
    && native.phases.at(-1)?.phase === 'cleanup' && native.phases.at(-1)?.reason === 'completed'
    && native.phases.at(-1)?.processes.find(process => process.pid === native.phases.at(-1)?.root?.pid && process.creationFileTime === native.phases.at(-1)?.root?.creationFileTime)?.exitCode === 0;
}
export function nativePrimaryNormal(native: HostNativeReceipt | null): boolean {
  const primary = native?.phases.find(phase => phase.phase === 'primary');
  return !!primary && hostNativeClosed(native) && primary.reason === 'completed' && primary.processes.find(process => process.pid === primary.root?.pid && process.creationFileTime === primary.root?.creationFileTime)?.exitCode === 0;
}
interface HostJobReportBase {
  jobId: string; hostProfileSha256: string; offlineProfileSha256: string; originDigest: string;
  intent: JobFileReference; native: JobFileReference | null; delegated: JobFileReference | null; acceptedFailure: JobFileReference | null;
  primary: JobFileReference | null; cleanup: JobFileReference | null;
  plan: JobFileReference | null; analysis: { kind: 'report'; reference: JobFileReference } | { kind: 'checkpoint'; sequence: number; body: JobFileReference; receipt: JobFileReference } | null;
  basis: 'live_owner_recorded' | 'recovered_saved_checkpoint_without_original_live_ownership';
  ownerTerminal: { code: number | null; signal: 'SIGTERM' | 'SIGKILL' | null; protocolValid: boolean } | null;
  closure: { windowsProcessTreeVerified: boolean; containerAbsent: boolean; daemonHealthy: boolean; inputsUnchanged: boolean };
  resources: { host: HostJobProfile['limits']; linux: JobProfile['limits']; trustedOwnerAndAdmissionExcluded: true; retainedPhysicalQuotaEnforced: false; totalCommandWallGuarantee: false; aggregateHostLinuxBudget: false };
  infrastructure: { maximumMetadataFiles: 6 | 7; maximumMetadataBytes: number; filesBeforeEnvelope: number; bytesBeforeEnvelope: number };
  knownFailures: string[]; unobservedInternalErrors: 'unknown'; gate: Gate; exitCode: number; reasons: string[];
}
export interface HostRetainedEvidence {
  scope: 'recorded_original_before_envelope_not_copy_quota';
  snapshot: RetainedSnapshot | null; stop: RetainedAllocationStop | null; witness: JobFileReference | null;
}
export type HostJobReport = HostJobReportBase & (
  { schema: 'scanmux.host-job-report/v1' } | { schema: 'scanmux.host-job-report/v2'; retained: HostRetainedEvidence }
);
export interface HostCompletionInput {
  native: HostNativeReceipt | null; ownerTerminal: HostJobReport['ownerTerminal']; inputsUnchanged: boolean;
  containerAbsent: boolean; daemonHealthy: boolean; cancelled: boolean; recovered: boolean;
  normalInner: boolean; hasFinal: boolean; hasPrefix: boolean; failures: string[];
  retainedStop?: RetainedAllocationStop | null;
}
export function hostJobCompletion(input: HostCompletionInput) {
  const failures = [...input.failures], native = input.native, primary = native?.phases[0];
  const ownerNormal = input.ownerTerminal?.code === 0 && input.ownerTerminal.signal === null && input.ownerTerminal.protocolValid;
  if (!ownerNormal || !hostNativeClosed(native)) failures.push('host_job_native_unverified');
  if (!input.inputsUnchanged && !input.recovered) failures.push('host_job_inputs_changed');
  if (!input.containerAbsent || !input.daemonHealthy) failures.push('host_job_cleanup_unverified');
  if (input.recovered) failures.push('host_job_recovered_without_original_ownership');
  if (input.cancelled || primary?.reason === 'cancelled') failures.push('host_job_cancelled');
  const root = primary?.processes.find(process => process.pid === primary.root?.pid && process.creationFileTime === primary.root?.creationFileTime);
  const accountedOwnerStop = root?.exitCode === windowsOwnerForcedExit && primary && ['deadline', 'cancelled', 'failed'].includes(primary.reason);
  const independentWorkerFailure = !!root?.signaled && root.exitCode !== null && root.exitCode !== 0 && !accountedOwnerStop;
  if (independentWorkerFailure || primary?.reason === 'failed' || primary?.reason === 'completed' && !nativePrimaryNormal(native)) failures.push('host_job_worker_failed');
  const unique = [...new Set(failures)];
  const closure = { windowsProcessTreeVerified: !input.recovered && ownerNormal && hostNativeClosed(native), containerAbsent: !input.recovered && input.containerAbsent,
    daemonHealthy: !input.recovered && input.daemonHealthy, inputsUnchanged: !input.recovered && input.inputsUnchanged };
  const closed = Object.values(closure).every(Boolean);
  const hostFailure = unique.some(code => hostFailureCodes.some(hostCode => hostCode === code) || jobHostFailureCodes.some(hostCode => hostCode === code));
  const outerFinalEligible = closed && !hostFailure && !input.cancelled && !input.recovered && !input.retainedStop && nativePrimaryNormal(native);
  const finalAllowed = outerFinalEligible && input.normalInner && input.hasFinal;
  const analysisKind: 'report' | 'checkpoint' | null = finalAllowed ? 'report' : input.hasPrefix ? 'checkpoint' : null;
  return { closure, closed, failures: unique, analysisKind, finalAllowed, outerFinalEligible,
    deadline: primary?.reason === 'deadline' && !independentWorkerFailure, allocationStopped: !!input.retainedStop, recovered: input.recovered };
}
export function hostJobOutcome(options: { plan: JobPlan | null; analysis: Report | null; completion: ReturnType<typeof hostJobCompletion>; copyBudgetStopped?: boolean }) {
  const completion = options.completion;
  const judgment = options.plan ? decide(options.plan.plan, options.analysis?.engines ?? [], (options.analysis?.integrityErrors ?? []).filter(code => code !== 'controller_completion_unverified')) : null;
  const reasons = [...completion.failures, ...(judgment?.reasons ?? [])];
  let gate: Gate;
  if (completion.recovered || !completion.closed || completion.failures.length || judgment?.gate === 'ERROR') gate = 'ERROR';
  else if (completion.allocationStopped) { gate = judgment?.gate === 'FAIL' ? 'FAIL' : 'INCOMPLETE'; reasons.push('host_job_retained_allocated_stop'); }
  else if (completion.deadline && completion.analysisKind === 'checkpoint') { gate = judgment?.gate === 'FAIL' ? 'FAIL' : 'INCOMPLETE'; reasons.push('host_job_deadline_stop'); }
  else if (options.copyBudgetStopped && !completion.deadline) { gate = judgment?.gate === 'FAIL' ? 'FAIL' : 'INCOMPLETE'; reasons.push('job_disk_copy_limit'); }
  else if (completion.finalAllowed && completion.analysisKind === 'report' && options.analysis) gate = options.analysis.gate;
  else { gate = 'ERROR'; reasons.push('host_job_completion_unverified'); }
  if (!options.analysis) reasons.push('job_analysis_missing');
  return { gate, exitCode: exitCodes[gate], reasons: [...new Set(reasons)] };
}
export function validateHostJobReport(input: unknown, intent: HostJobIntent): HostJobReport {
  const v2 = intent.schema === 'scanmux.host-job-intent/v2';
  const value = exact(input, ['schema', 'jobId', 'hostProfileSha256', 'offlineProfileSha256', 'originDigest', 'intent', 'native', 'primary', 'cleanup', 'delegated', 'acceptedFailure', 'plan', 'analysis', 'basis', 'ownerTerminal', 'closure', 'resources', 'infrastructure', 'knownFailures', 'unobservedInternalErrors', 'gate', 'exitCode', 'reasons', ...(v2 ? ['retained'] : [])]);
  hostRequire(value.schema === (v2 ? 'scanmux.host-job-report/v2' : 'scanmux.host-job-report/v1') && value.jobId === intent.jobId && value.hostProfileSha256 === digest(intent.host) && value.offlineProfileSha256 === digest(intent.offline));
  text(value.originDigest, shaPattern); reference(value.intent);
  for (const key of ['native', 'primary', 'cleanup', 'delegated', 'acceptedFailure', 'plan']) if (value[key] !== null) reference(value[key]);
  hostRequire(['live_owner_recorded', 'recovered_saved_checkpoint_without_original_live_ownership'].includes(String(value.basis)));
  if (value.ownerTerminal !== null) {
    const terminal = exact(value.ownerTerminal, ['code', 'signal', 'protocolValid']);
    if (terminal.code !== null) integer(terminal.code, 0, 0xffffffff);
    hostRequire([null, 'SIGTERM', 'SIGKILL'].includes(terminal.signal as null | string) && typeof terminal.protocolValid === 'boolean');
  }
  const infrastructure = exact(value.infrastructure, ['maximumMetadataFiles', 'maximumMetadataBytes', 'filesBeforeEnvelope', 'bytesBeforeEnvelope']);
  const witnessMaximum = v2 ? 4096 : 0;
  hostRequire(infrastructure.maximumMetadataFiles === (v2 ? 7 : 6) && infrastructure.maximumMetadataBytes === hostControlMaximum + 4 * intent.offline.scan.maxOutputBytes + hostFailureMaximum + witnessMaximum);
  integer(infrastructure.filesBeforeEnvelope, 1, v2 ? 6 : 5); integer(infrastructure.bytesBeforeEnvelope, 1, hostControlMaximum + 3 * intent.offline.scan.maxOutputBytes + hostFailureMaximum + witnessMaximum);
  const closure = exact(value.closure, ['windowsProcessTreeVerified', 'containerAbsent', 'daemonHealthy', 'inputsUnchanged']);
  for (const fact of Object.values(closure)) hostRequire(typeof fact === 'boolean');
  const resources = exact(value.resources, ['host', 'linux', 'trustedOwnerAndAdmissionExcluded', 'retainedPhysicalQuotaEnforced', 'totalCommandWallGuarantee', 'aggregateHostLinuxBudget']);
  hostRequire(isDeepStrictEqual(resources.host, intent.host.limits) && isDeepStrictEqual(resources.linux, intent.offline.limits) && resources.trustedOwnerAndAdmissionExcluded === true
    && resources.retainedPhysicalQuotaEnforced === false && resources.totalCommandWallGuarantee === false && resources.aggregateHostLinuxBudget === false && value.unobservedInternalErrors === 'unknown');
  if (value.analysis !== null) {
    const analysis = record(value.analysis);
    if (analysis.kind === 'report') { exact(analysis, ['kind', 'reference']); reference(analysis.reference); }
    else { exact(analysis, ['kind', 'sequence', 'body', 'receipt']); hostRequire(analysis.kind === 'checkpoint'); integer(analysis.sequence, 1, 4); reference(analysis.body); reference(analysis.receipt); }
    hostRequire(value.plan !== null);
  }
  hostRequire(Array.isArray(value.knownFailures) && value.knownFailures.length <= allJobFailures.length + hostFailureCodes.length && value.knownFailures.every(code => allJobFailures.includes(code) || hostFailureCodes.some(hostCode => hostCode === code)));
  hostRequire(new Set(value.knownFailures).size === value.knownFailures.length && Array.isArray(value.reasons) && value.reasons.length <= 10000 && value.reasons.every(reason => typeof reason === 'string' && reason.length <= 256 && /^[a-z0-9_:.-]+$/.test(reason)));
  hostRequire(['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR'].includes(String(value.gate)) && value.exitCode === exitCodes[value.gate as Gate]);
  if (v2) {
    const retained = exact(value.retained, ['scope', 'snapshot', 'stop', 'witness']);
    hostRequire(retained.scope === 'recorded_original_before_envelope_not_copy_quota');
    const policy = retainedPolicy(intent, reference(value.intent).sha256);
    const snapshot = retained.snapshot === null ? null : validateRetainedSnapshot(retained.snapshot, policy);
    if (snapshot) hostRequire(snapshot.files.some(file => file.slot === 0 && file.bytes === reference(value.intent).bytes) && !snapshot.files.some(file => file.slot === 9));
    if (retained.witness !== null) reference(retained.witness);
    if (retained.stop !== null) {
      hostRequire(retained.witness !== null && record(value.analysis ?? {}).kind !== 'report');
      validateRetainedAllocationStop(retained.stop, policy, snapshot ?? undefined);
    }
    const unverified = retained.snapshot === null || retained.witness !== null && retained.stop === null;
    if (unverified) hostRequire(value.gate === 'ERROR' && (value.knownFailures as string[]).includes('host_job_retained_unverified') && record(value.analysis ?? {}).kind !== 'report');
    if (snapshot) {
      const witness = snapshot.files.find(file => file.slot === 2);
      hostRequire((retained.witness === null) === (witness === undefined));
      if (witness) hostRequire(witness.bytes === reference(retained.witness).bytes);
    }
  }
  return value as unknown as HostJobReport;
}
