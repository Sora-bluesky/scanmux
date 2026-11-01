import path from 'node:path';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { lstat } from 'node:fs/promises';
import { defaults } from './config.ts';
import type { Config, Config1, Config2, Tool } from './model.ts';
import { boundedRead, canonical, digest, hash, outside, record, SafeError, within } from './safety.ts';
import { parseAnyRuntimePolicy, type RuntimePolicy } from './runtime-policy.ts';
import { admitRuntime } from './runtime-admission.ts';
import type { ProvenanceSubject } from './provenance.ts';
import { parseWorkerResources } from '../internal/worker-resources.mjs';

interface JobProfileFields {
  maxCopyBytes?: number;
  maxJobDiskBytes?: number;
  name: string; scope: 'offline-local';
  docker: { tool: Tool; endpoint: string }; image: string;
  runtime: { nodeVersion: string; python: Tool; git: Tool };
  tools: { gitleaks: Tool; osv?: Tool }; osvDatabase: string | null;
  scan: Pick<Config, 'timeoutMs' | 'maxOutputBytes' | 'maxFileBytes' | 'maxSnapshotBytes' | 'maxFiles'>;
  limits: { cpuCount: number; memoryBytes: number; tmpBytes: number; workBytes: number; shmBytes: number;
    pids: number; wallMs: number; cleanupTimeoutMs: number; retainedBytes: number };
}
export interface JobProfile1 extends JobProfileFields { schema: 'scanmux.job-profile/v1'; runtimePolicy?: never }
export interface JobProfile2 extends JobProfileFields { schema: 'scanmux.job-profile/v2'; runtimePolicy: RuntimePolicy }
export type JobProfile = JobProfile1 | JobProfile2;
export interface JobProfileEntry { runtimePolicy: 'reject' | 'accept' }
const scanKeys = ['timeoutMs', 'maxOutputBytes', 'maxFileBytes', 'maxSnapshotBytes', 'maxFiles'] as const;
const limitKeys = ['cpuCount', 'memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes', 'pids', 'wallMs', 'cleanupTimeoutMs', 'retainedBytes'] as const;
const versionPattern = /^[0-9]+\.[0-9]+\.[0-9]+$/;
export function jobPayloadResources(limits: Pick<JobProfile['limits'], 'cpuCount' | 'memoryBytes' | 'tmpBytes' | 'workBytes' | 'shmBytes'>) {
  return parseWorkerResources({ cpuCount: limits.cpuCount, memoryBytes: limits.memoryBytes,
    tmpBytes: limits.tmpBytes, workBytes: limits.workBytes, shmBytes: limits.shmBytes });
}
function reject(): never { throw new SafeError('invalid_job_profile'); }
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  const value = record(input);
  if (Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) reject();
  return value;
}
function positive(input: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input <= 0 || input > maximum) reject();
  return input;
}
function version(input: unknown): string {
  if (typeof input !== 'string' || !versionPattern.test(input)) reject();
  return input;
}
function absolute(input: unknown): string {
  if (typeof input !== 'string' || !path.isAbsolute(input) || /[,\x00-\x1f\x7f]/.test(input)) reject();
  return input;
}
function tool(input: unknown, fixedPath?: string): Tool {
  const value = exact(input, ['path', 'sha256', 'version']);
  const executable = fixedPath === undefined ? absolute(value.path) : value.path;
  if (typeof executable !== 'string' || fixedPath !== undefined && executable !== fixedPath
    || typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256)) reject();
  return { path: executable, sha256: value.sha256, version: version(value.version) };
}

/** This sidecar never becomes a Config default or changes an existing Plan digest. */
export function parseJobProfile(input: unknown, entry: JobProfileEntry = { runtimePolicy: 'reject' }): JobProfile {
  if (record(input).schema !== 'scanmux.job-profile/v2') return jobProfileOne(input);
  if (entry.runtimePolicy !== 'accept') throw new SafeError('runtime_policy_entry_unsupported');
  if (!Object.hasOwn(record(input), 'runtimePolicy')) throw new SafeError('runtime_policy_required');
  const { runtimePolicy, ...fields } = record(input);
  const policy = parseAnyRuntimePolicy(runtimePolicy);
  return { ...jobProfileOne({ ...fields, schema: 'scanmux.job-profile/v1' }), schema: 'scanmux.job-profile/v2', runtimePolicy: policy };
}
function jobProfileOne(input: unknown): JobProfile1 {
  const value = exact(input, ['schema', 'name', 'scope', 'docker', 'image', 'runtime', 'tools', 'osvDatabase', 'scan', 'limits',
    ...(Object.hasOwn(record(input), 'maxCopyBytes') ? ['maxCopyBytes'] : []),
    ...(Object.hasOwn(record(input), 'maxJobDiskBytes') ? ['maxJobDiskBytes'] : [])]);
  if (value.schema !== 'scanmux.job-profile/v1' || value.scope !== 'offline-local'
    || typeof value.name !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value.name)
    || typeof value.image !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value.image)) reject();
  const docker = exact(value.docker, ['tool', 'endpoint']), runtime = exact(value.runtime, ['nodeVersion', 'python', 'git']);
  if (typeof docker.endpoint !== 'string' || !(
    /^npipe:\/\/\/\/\.\/pipe\/[A-Za-z0-9_-]{1,100}$/.test(docker.endpoint)
    || /^unix:\/\/\/[A-Za-z0-9_./-]+$/.test(docker.endpoint) && !docker.endpoint.split('/').some(piece => piece === '..' || piece === '.')
  )) reject();
  const tools = record(value.tools);
  if (!Object.hasOwn(tools, 'gitleaks') || Object.keys(tools).some(key => !['gitleaks', 'osv'].includes(key))) reject();
  const scan = exact(value.scan, scanKeys), limits = exact(value.limits, limitKeys);
  const parsedScan = {
    timeoutMs: positive(scan.timeoutMs, 2147483647), maxOutputBytes: positive(scan.maxOutputBytes, 2147483647),
    maxFileBytes: positive(scan.maxFileBytes, 2147483647), maxSnapshotBytes: positive(scan.maxSnapshotBytes, 2147483647), maxFiles: positive(scan.maxFiles, 2147483647),
  };
  for (const key of limitKeys) positive(limits[key]);
  const requested = { cpuCount: positive(limits.cpuCount), memoryBytes: positive(limits.memoryBytes),
    tmpBytes: positive(limits.tmpBytes), workBytes: positive(limits.workBytes), shmBytes: positive(limits.shmBytes) };
  try { jobPayloadResources(requested); } catch { reject(); }
  if (!Number.isSafeInteger(requested.cpuCount * 100000) || !Number.isSafeInteger(2 * parsedScan.maxOutputBytes)
    || positive(limits.retainedBytes) < 2 * parsedScan.maxOutputBytes) reject();
  return {
    schema: 'scanmux.job-profile/v1', name: value.name, scope: 'offline-local',
    ...(Object.hasOwn(value, 'maxCopyBytes') ? { maxCopyBytes: positive(value.maxCopyBytes) } : {}),
    ...(Object.hasOwn(value, 'maxJobDiskBytes') ? { maxJobDiskBytes: positive(value.maxJobDiskBytes) } : {}),
    docker: { tool: tool(docker.tool), endpoint: docker.endpoint }, image: value.image,
    runtime: { nodeVersion: version(runtime.nodeVersion), python: tool(runtime.python, '/usr/bin/python3'), git: tool(runtime.git, '/usr/bin/git') },
    tools: { gitleaks: tool(tools.gitleaks), ...(tools.osv === undefined ? {} : { osv: tool(tools.osv) }) },
    osvDatabase: value.osvDatabase === null ? null : absolute(value.osvDatabase), scan: parsedScan,
    limits: { ...requested, pids: positive(limits.pids, 2147483647), wallMs: positive(limits.wallMs, 2147483647),
      cleanupTimeoutMs: positive(limits.cleanupTimeoutMs, 2147483647), retainedBytes: positive(limits.retainedBytes) },
  };
}

export async function regularJobFile(file: string, target: string): Promise<string> {
  const physical = await outside(absolute(file), target), stat = await lstat(physical);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new SafeError('invalid_job_asset');
  return physical;
}

/** Stream hashing does not put executable or database bytes into the host result buffer. */
export async function jobFileIdentity(file: string, options: { expiresAt?: number; maximumBytes?: number } = {}) {
  const admitted = () => {
    if (options.expiresAt !== undefined && performance.now() >= options.expiresAt) throw new SafeError('job_asset_verification_stopped');
  };
  admitted();
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || await canonical(file) !== file) throw new SafeError('invalid_job_asset');
  if (options.maximumBytes !== undefined && before.size > options.maximumBytes) throw new SafeError('job_asset_changed');
  const state = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(file, { highWaterMark: 65536 })) {
    admitted(); bytes += chunk.length;
    if (options.maximumBytes !== undefined && bytes > options.maximumBytes) throw new SafeError('job_asset_changed');
    state.update(chunk);
  }
  const after = await lstat(file);
  if (bytes !== before.size || before.size !== after.size || before.dev !== after.dev || before.ino !== after.ino
    || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || after.nlink !== 1) throw new SafeError('job_asset_changed');
  admitted(); return { bytes, sha256: state.digest('hex') };
}

export async function loadJobProfile(file: string, target: string, entry: JobProfileEntry = { runtimePolicy: 'reject' }, options: { expiresAt?: number } = {}) {
  if (!['win32', 'linux'].includes(process.platform)) throw new SafeError('unsupported_job_host');
  const root = await canonical(absolute(target));
  if (!(await lstat(root)).isDirectory()) throw new SafeError('invalid_job_target');
  const source = await regularJobFile(file, root), raw = await boundedRead(source, 65536);
  const profile = parseJobProfile(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)), entry);
  if (process.platform === 'win32' ? !profile.docker.endpoint.startsWith('npipe:') : !profile.docker.endpoint.startsWith('unix:')) reject();
  if (profile.schema === 'scanmux.job-profile/v2' && profile.runtimePolicy.schema === 'scanmux.runtime-policy/v2') {
    if (within(root, path.resolve(profile.runtimePolicy.provenance.verifier.path))) throw new SafeError('provenance_verifier_inside_target');
    if (within(root, path.resolve(profile.runtimePolicy.provenance.ledger.path))) throw new SafeError('provenance_ledger_inside_target');
  }
  for (const item of [profile.docker.tool, profile.tools.gitleaks, ...(profile.tools.osv ? [profile.tools.osv] : [])]) {
    const physical = await regularJobFile(item.path, root);
    if (physical !== item.path || (await jobFileIdentity(physical, options)).sha256 !== item.sha256) throw new SafeError('job_asset_mismatch');
  }
  if (profile.osvDatabase !== null) {
    const directory = await outside(profile.osvDatabase, root);
    if (!(await lstat(directory)).isDirectory()) throw new SafeError('invalid_job_database');
    profile.osvDatabase = directory;
  }
  return { profile, root, source, profileSha256: digest(profile), sourceSha256: hash(raw), mappedRoot: '/repo/' + hash(root) };
}

// The Linux tools are checked as the host files that are mounted; image and container actors have no host file.
export function jobRuntimeSubjects(profile: JobProfile2): ProvenanceSubject[] {
  return [{ component: 'docker', sha256: profile.docker.tool.sha256, file: profile.docker.tool.path },
    { component: 'gitleaks', sha256: profile.tools.gitleaks.sha256, file: profile.tools.gitleaks.path },
    ...(profile.tools.osv ? [{ component: 'osv' as const, sha256: profile.tools.osv.sha256, file: profile.tools.osv.path }] : []),
    { component: 'linux-image', sha256: profile.image.slice('sha256:'.length), file: null }, { component: 'git', sha256: profile.runtime.git.sha256, file: null },
    // The container's /usr/local/bin/node runs the controller but is never hashed.
    { component: 'node', sha256: null, file: null }];
}
export async function admitJobRuntime(profile: JobProfile, root: string, signal: AbortSignal): Promise<void> {
  if (profile.schema === 'scanmux.job-profile/v1') return;
  await admitRuntime(profile.runtimePolicy, jobRuntimeSubjects(profile), { root, timeoutMs: profile.scan.timeoutMs, signal });
}

export function jobLinuxConfig(profile: JobProfile1): Config1;
export function jobLinuxConfig(profile: JobProfile2): Config2;
export function jobLinuxConfig(profile: JobProfile): Config;
export function jobLinuxConfig(profile: JobProfile): Config {
  const config: Config1 = { ...structuredClone(defaults), ...profile.scan,
    tools: { git: { ...profile.runtime.git }, gitleaks: { ...profile.tools.gitleaks, path: '/tools/gitleaks' },
      ...(profile.tools.osv ? { osv: { ...profile.tools.osv, path: '/tools/osv' } } : {}) },
    osvDatabase: profile.osvDatabase === null ? null : '/db',
  };
  return profile.schema === 'scanmux.job-profile/v1' ? config : { ...config, schema: 2, runtimePolicy: structuredClone(profile.runtimePolicy) };
}

export const jobDatabaseCandidates = [
  'osv-scalibr/npm/all.zip', 'osv-scalibr/PyPI/all.zip', 'osv-scalibr/Go/all.zip', 'osv-scalibr/crates.io/all.zip',
  'database-receipt.json', 'acquisition-started',
] as const;

export async function jobDatabaseMounts(profile: JobProfile, root: string) {
  const admitted: { source: string; destination: string; bytes: number; sha256: string }[] = [];
  if (profile.osvDatabase === null) return admitted;
  for (const candidate of jobDatabaseCandidates) {
    const file = path.join(profile.osvDatabase, ...candidate.split('/'));
    const present = await lstat(file).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (!present) continue;
    const source = await regularJobFile(file, root);
    admitted.push({ source, destination: '/db/' + candidate, ...await jobFileIdentity(source) });
  }
  return admitted;
}
