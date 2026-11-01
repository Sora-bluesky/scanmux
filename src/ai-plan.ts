import type { AiLocalComponent, AiPlan, Config, Destination, Destinations, Plan } from './model.ts';
import { digest, SafeError } from './safety.ts';
import type { ProvenanceSubject } from './provenance.ts';
import { parseWorkerResources } from '../internal/worker-resources.mjs';

export const aiRuntime = Object.freeze({
  host: 'win32', worker: 'linux', sdkVersion: '0.5.1', pluginVersion: '0.1.95',
  imageDigest: 'sha256:f9b3548b20b15b705b66aeecaeac7dd690c73d5e4661357aac02e60e3d38c88a',
  assetManifestSha256: 'a8d9e7ec6006b43bd296a3beaf618a43818731ae75f5847f214324d0b2d2308c',
} satisfies AiPlan['runtime']);
export function aiSubjects(config: Config): (ProvenanceSubject & { component: AiLocalComponent })[] {
  if (!config.ai) return [];
  // Host docker and the container's /usr/bin/git and node run from fixed paths without hashing, so their identities are unknown here.
  return [{ component: 'codex-security-sdk', sha256: aiRuntime.assetManifestSha256, file: null },
    { component: 'linux-image', sha256: aiRuntime.imageDigest.slice('sha256:'.length), file: null }, { component: 'docker', sha256: null, file: null },
    { component: 'git', sha256: null, file: null }, { component: 'node', sha256: null, file: null }];
}
function destinations(config: Config): Destinations {
  const required = config.schema === 2 && config.runtimePolicy.schema === 'scanmux.runtime-policy/v2' ? config.runtimePolicy.provenance.require : [];
  const local = aiSubjects(config).map(({ component, sha256 }): Destination => {
    const level = required.find(item => item.component === component)?.level;
    return { side: 'local', component, sha256, level: sha256 === null ? 'unidentified'
      : level === 'publisher' ? 'publisher_verified_at_admission' : level === 'recorded' ? 'ledger_recorded_at_admission' : 'digest_pinned_only' };
  });
  return { schema: 'scanmux.destinations/v1', rule: 'send_only_to_validated_software', ruleMet: false, destinations: [...local,
    { side: 'provider', component: 'openai-responses', attestation: 'unattestable', reason: 'provider_offers_no_software_attestation' }] };
}
export function destinationsText(value: Destinations): string {
  const local = value.destinations.flatMap(item => item.side === 'local' ? [`${item.component}=${item.level}`] : []);
  const provider = value.destinations.flatMap(item => item.side === 'provider' ? [`${item.component}=${item.attestation} (${item.reason})`] : []);
  return `AI destinations: rule ${value.rule} not met; local ${local.join(', ')}; provider ${provider.join(', ')}.\n`;
}
const transmissions = ['accepted_snapshot_text', 'fixed_sdk_instructions', 'bounded_conversation_and_tool_results'];
const aiConstraints = ['ai_boundary_verification_required', 'fixed_openai_responses_only', 'exact_ai_plan_acceptance_required', 'no_automatic_retry_or_refresh'];
function disclosure(source: Plan, config: Config): AiPlan {
  if (!config.ai) throw new SafeError('ai_not_configured');
  const options = config.ai;
  return { schema: 'scanmux.ai-plan/v2', provider: 'openai', endpoint: 'wss://api.openai.com/v1/responses',
    authentication: 'chatgpt', model: 'gpt-6-sol', accessProgram: 'daybreak_blue', reasoningEffort: options.reasoningEffort,
    source: { snapshotHash: source.snapshotHash, manifestSha256: digest(source.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 }))), files: source.files.length, bytes: source.files.reduce((sum, file) => sum + file.bytes, 0) },
    runtime: { ...aiRuntime }, limits: structuredClone(options.limits), ipc: structuredClone(options.ipc), workerResources: parseWorkerResources(options.workerResources), executionTimeoutMs: config.timeoutMs,
    cleanupTimeoutMs: options.cleanupTimeoutMs, commandTimeoutMs: options.commandTimeoutMs, parallelism: 1, automaticRetries: 0, automaticRefresh: false,
    retention: { store: false, providerRetention: 'unverified', trainingPolicy: 'unverified' }, cost: { amount: null, kind: 'not_applicable', allowance: 'unknown' } };
}
export function buildAiPlan(source: Plan, config: Config): Plan {
  if (source.schema === 'scanmux.plan/v3' || config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  if (source.planHash !== digest({ ...source, planHash: '' }) || source.policyHash !== digest(config)
    || source.network !== 'offline' || source.ai || source.source || source.destinations) throw new SafeError('invalid_ai_source_plan');
  const plan = structuredClone(source);
  plan.ai = disclosure(source, config);
  plan.destinations = destinations(config);
  plan.network = 'openai-responses'; plan.cost = { kind: 'not_applicable', aiCalls: plan.ai.limits.maxRequests };
  plan.transmissions = [...transmissions];
  plan.constraints = [...plan.constraints.filter(value => !['ai_isolation_unverified', 'offline_only'].includes(value)),
    ...aiConstraints];
  plan.planHash = digest({ ...plan, planHash: '' });
  return plan;
}
export function verifyAiPlan(plan: Plan, config: Config, acceptedHash: string): void {
  if (!config.ai) throw new SafeError('ai_not_configured');
  if (!/^[a-f0-9]{64}$/.test(acceptedHash) || acceptedHash !== plan.planHash) throw new SafeError('ai_plan_not_accepted');
  if (plan.planHash !== digest({ ...plan, planHash: '' }) || plan.policyHash !== digest(config) || plan.snapshotHash !== digest(plan.files)
    || plan.network !== 'openai-responses' || plan.source || digest(plan.ai) !== digest(disclosure(plan, config)) || digest(plan.destinations ?? null) !== digest(destinations(config))
    || digest(plan.transmissions) !== digest(transmissions) || digest(plan.cost) !== digest({ kind: 'not_applicable', aiCalls: config.ai.limits.maxRequests })
    || aiConstraints.some(value => !plan.constraints.includes(value)) || plan.constraints.some(value => ['offline_only', 'ai_isolation_unverified'].includes(value))) throw new SafeError('ai_plan_integrity');
  if (plan.blockers.length || !plan.commit || plan.dirty !== false || !plan.files.length) throw new SafeError('ai_plan_blocked');
}
