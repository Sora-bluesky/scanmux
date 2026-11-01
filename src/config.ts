import path from 'node:path';
import { lstat, realpath } from 'node:fs/promises';
import { boundedRead, canonical, outside, record, SafeError, within } from './safety.ts';
import type { AiConfig, Config, Config1, Tool, RunnerConfig } from './model.ts';
import { parseAnyRuntimePolicy } from './runtime-policy.ts';
import { parseWorkerResources } from '../internal/worker-resources.mjs';

export const defaults: Config1 = {
  schema: 1, timeoutMs: 120000, maxOutputBytes: 8 * 1024 * 1024,
  maxFileBytes: 8 * 1024 * 1024, maxSnapshotBytes: 64 * 1024 * 1024, maxFiles: 10000,
  tools: {}, osvDatabase: null, auth: 'chatgpt', model: 'gpt-6-sol', accessProgram: 'daybreak_blue',
  runner: null, ai: null,
};
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) throw new SafeError('invalid_ai_limit');
  return value;
}
function duration(value: unknown): number {
  const number = positive(value);
  if (number > 2147483647) throw new SafeError('invalid_ai_limit');
  return number;
}
function exact(input: unknown, keys: string[]): Record<string, unknown> {
  const object = record(input);
  if (Object.keys(object).sort().join(',') !== [...keys].sort().join(',')) throw new SafeError('invalid_ai_config');
  return object;
}
async function aiConfig(input: unknown, root?: string): Promise<AiConfig> {
  const value = exact(input, ['assetsRoot', 'credentialStore', 'limits', 'ipc', 'workerResources', 'cleanupTimeoutMs', 'commandTimeoutMs', 'reasoningEffort']);
  let workerResources;
  try { workerResources = parseWorkerResources(value.workerResources); } catch { throw new SafeError('invalid_worker_resources'); }
  const limits = exact(value.limits, ['maxRequests', 'maxTotalOutputTokens', 'maxOutputTokensPerRequest', 'maxInputBytesPerRequest', 'maxResponseBytesPerRequest', 'maxToolCalls', 'maxToolResultBytes', 'timeoutMs']);
  const ipc = exact(value.ipc, ['maxFrameBytes', 'maxBytes', 'maxFrames']);
  if (value.reasoningEffort !== 'high') throw new SafeError('unsupported_ai_reasoning');
  const paths: string[] = [];
  for (const candidate of [value.assetsRoot, value.credentialStore]) {
    if (typeof candidate !== 'string' || !path.isAbsolute(candidate)) throw new SafeError('invalid_ai_path');
    const physical = root ? await outside(candidate, root) : await canonical(candidate);
    if (root && within(physical, root)) throw new SafeError('ai_path_contains_target');
    let current = physical;
    for (;;) {
      if ((await lstat(current)).isSymbolicLink() || await realpath(current) !== current) throw new SafeError('invalid_ai_path');
      if (path.dirname(current) === current) break;
      current = path.dirname(current);
    }
    paths.push(physical);
  }
  const [assetsRoot, credentialStore] = paths;
  if (!(await lstat(assetsRoot)).isDirectory() || !(await lstat(credentialStore)).isDirectory()) throw new SafeError('invalid_ai_path');
  if (within(assetsRoot, credentialStore) || within(credentialStore, assetsRoot)) throw new SafeError('ai_credentials_in_runtime');
  const maxFrameBytes = positive(ipc.maxFrameBytes), maxBytes = positive(ipc.maxBytes);
  if (maxFrameBytes > maxBytes) throw new SafeError('invalid_ai_limit');
  return { assetsRoot, credentialStore, workerResources, reasoningEffort: 'high', cleanupTimeoutMs: duration(value.cleanupTimeoutMs), commandTimeoutMs: duration(value.commandTimeoutMs),
    limits: { maxRequests: positive(limits.maxRequests), maxTotalOutputTokens: positive(limits.maxTotalOutputTokens), maxOutputTokensPerRequest: positive(limits.maxOutputTokensPerRequest), maxInputBytesPerRequest: positive(limits.maxInputBytesPerRequest), maxResponseBytesPerRequest: positive(limits.maxResponseBytesPerRequest), maxToolCalls: positive(limits.maxToolCalls), maxToolResultBytes: positive(limits.maxToolResultBytes), timeoutMs: duration(limits.timeoutMs) },
    ipc: { maxFrameBytes, maxBytes, maxFrames: positive(ipc.maxFrames) } };
}
export interface ConfigEntry { runtimePolicy: 'reject' | 'accept' }
export async function loadConfig(file?: string, target?: string, entry: ConfigEntry = { runtimePolicy: 'reject' }): Promise<Config> {
  if (!file) return structuredClone(defaults);
  if (!path.isAbsolute(file)) throw new SafeError('config_must_be_absolute');
  const root = target ? await canonical(target) : undefined;
  const trusted = root ? await outside(file, root) : await canonical(file);
  const parsed = record(JSON.parse((await boundedRead(trusted, 65536)).toString('utf8')));
  if (parsed.schema !== 2) return configOne(parsed, root);
  if (entry.runtimePolicy !== 'accept') throw new SafeError('runtime_policy_entry_unsupported');
  if (!Object.hasOwn(parsed, 'runtimePolicy')) throw new SafeError('runtime_policy_required');
  const { runtimePolicy, ...fields } = parsed;
  const policy = parseAnyRuntimePolicy(runtimePolicy);
  if (root && policy.schema === 'scanmux.runtime-policy/v2') {
    if (within(root, path.resolve(policy.provenance.verifier.path))) throw new SafeError('provenance_verifier_inside_target');
    if (within(root, path.resolve(policy.provenance.ledger.path))) throw new SafeError('provenance_ledger_inside_target');
  }
  return { ...await configOne({ ...fields, schema: 1 }, root), schema: 2, runtimePolicy: policy };
}
async function configOne(parsed: Record<string, unknown>, root: string | undefined): Promise<Config1> {
  if (Object.keys(parsed).some(k => !Object.hasOwn(defaults, k) && !['maxCopyBytes', 'maxJobDiskBytes'].includes(k)) || parsed.schema !== 1) throw new SafeError('invalid_config');
  const config = { ...defaults, ...parsed, tools: {} } as Config1;
  for (const key of ['maxCopyBytes', 'maxJobDiskBytes']) {
    if (Object.hasOwn(parsed, key) && (typeof parsed[key] !== 'number' || !Number.isSafeInteger(parsed[key]) || parsed[key] <= 0)) throw new SafeError('invalid_limit');
  }
  for (const key of ['timeoutMs', 'maxOutputBytes', 'maxFileBytes', 'maxSnapshotBytes', 'maxFiles'] as const) {
    if (!Number.isSafeInteger(config[key]) || config[key] <= 0 || config[key] > 2147483647) throw new SafeError('invalid_limit');
  }
  if (config.auth !== 'chatgpt' || config.accessProgram !== 'daybreak_blue' || config.model !== 'gpt-6-sol') throw new SafeError('unsupported_auth_or_model');
  if (config.ai !== null) config.ai = await aiConfig(config.ai, root);
  if (config.runner !== null) {
    const runner = record(config.runner);
    if (Object.keys(runner).sort().join(',') !== 'authHome,codex,disabledMcpServers,disabledPlugins,docker,image,linuxCodex') throw new SafeError('invalid_runner_config');
    if (typeof runner.image !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(runner.image)) throw new SafeError('invalid_runner_image');
    if (typeof runner.authHome !== 'string' || !path.isAbsolute(runner.authHome)) throw new SafeError('invalid_runner_auth_home');
    runner.authHome = root ? await outside(runner.authHome, root) : await canonical(runner.authHome);
    for (const name of ['codex', 'linuxCodex', 'docker']) {
      const tool = record(runner[name]);
      if (Object.keys(tool).sort().join(',') !== 'path,sha256,version' || typeof tool.path !== 'string' || !path.isAbsolute(tool.path) || typeof tool.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(tool.sha256) || typeof tool.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(tool.version)) throw new SafeError('invalid_runner_tool');
      if (root && within(root, path.resolve(tool.path))) throw new SafeError('runner_tool_inside_target');
    }
    for (const key of ['disabledMcpServers', 'disabledPlugins']) {
      const names = runner[key];
      if (!Array.isArray(names) || names.length > 1000 || names.some(n => typeof n !== 'string' || !/^[A-Za-z0-9_@.-]{1,200}$/.test(n)) || new Set(names).size !== names.length) throw new SafeError('invalid_runner_connections');
    }
    config.runner = runner as unknown as RunnerConfig;
  }
  if (config.osvDatabase !== null) {
    if (typeof config.osvDatabase !== 'string' || !path.isAbsolute(config.osvDatabase)) throw new SafeError('invalid_database_path');
    config.osvDatabase = root ? await outside(config.osvDatabase, root) : await canonical(config.osvDatabase);
  }
  for (const [key, value] of Object.entries(record(parsed.tools ?? {}))) {
    if (!['git', 'gitleaks', 'osv', 'codex-security', 'windows-process-owner', 'trivy'].includes(key)) throw new SafeError('invalid_tool');
    const tool = record(value);
    if (Object.keys(tool).sort().join(',') !== 'path,sha256,version' || typeof tool.path !== 'string' || !path.isAbsolute(tool.path) || typeof tool.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(tool.sha256) || typeof tool.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(tool.version)) throw new SafeError('invalid_tool');
    if (root && within(root, path.resolve(tool.path))) throw new SafeError('tool_inside_target');
    config.tools[key as keyof Config['tools']] = tool as unknown as Tool;
  }
  return config;
}
