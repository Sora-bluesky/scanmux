import test from 'node:test';
import assert from 'node:assert/strict';
import { defaults } from '../src/config.ts';
import { buildAiPlan, destinationsText, verifyAiPlan, aiRuntime } from '../src/ai-plan.ts';
import { digest } from '../src/safety.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import type { AiConfig, Config, Plan } from '../src/model.ts';

export const aiOptions: AiConfig = {
  assetsRoot: 'C:\\operator-assets', credentialStore: 'C:\\private-store', reasoningEffort: 'high', cleanupTimeoutMs: 10000, commandTimeoutMs: 10000,
  workerResources: { cpuCount: 1, memoryBytes: 256 * 1024 * 1024, tmpBytes: 32 * 1024 * 1024, workBytes: 16 * 1024 * 1024, shmBytes: 4 * 1024 * 1024 },
  limits: { maxRequests: 5, maxTotalOutputTokens: 20, maxOutputTokensPerRequest: 5, maxInputBytesPerRequest: 1024 * 1024, maxResponseBytesPerRequest: 1024 * 1024, maxToolCalls: 13, maxToolResultBytes: 256 * 1024, timeoutMs: 120000 },
  ipc: { maxFrameBytes: 8 * 1024 * 1024, maxBytes: 8 * 1024 * 1024, maxFrames: 30 },
};
function fixture(config: Config): Plan {
  const plan: Plan = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root: 'C:\\synthetic-target', repoId: 'a'.repeat(64), commit: 'b'.repeat(40), treeHash: 'c'.repeat(40),
    files: [{ path: 'source.ts', oid: 'd'.repeat(40), bytes: 2, sha256: 'e'.repeat(64) }], snapshotHash: '', dirty: false, exclusions: [], blockers: [], languages: ['TypeScript'], lockfiles: [],
    required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [],
    constraints: ['clean_committed_git_only', 'tracked_files_only', 'git_history_not_scanned', 'no_build_or_scripts', 'ai_isolation_unverified', 'offline_only', 'same_user_concurrent_mutation_not_supported'], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.snapshotHash = digest(plan.files); plan.planHash = digest({ ...plan, planHash: '' }); return plan;
}
const configured = () => ({ ...structuredClone(defaults), ai: structuredClone(aiOptions) } satisfies Config);
test('AI planning discloses exact accepted source and finite limits without altering the offline plan', () => {
  const config = configured(), source = fixture(config), before = structuredClone(source), planned = buildAiPlan(source, config);
  assert.deepEqual(source, before); assert.equal(source.network, 'offline'); assert.equal(source.cost.aiCalls, 0); assert.equal(source.ai, undefined);
  assert.equal(planned.network, 'openai-responses'); assert.equal(planned.cost.aiCalls, 5); assert.equal(planned.ai?.runtime.imageDigest, aiRuntime.imageDigest);
  assert.deepEqual(planned.ai?.source, { snapshotHash: source.snapshotHash, manifestSha256: digest(source.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 }))), files: 1, bytes: 2 });
  assert.equal(planned.ai?.retention.providerRetention, 'unverified'); assert.equal(planned.ai?.cost.amount, null); assert.equal(planned.ai?.cost.allowance, 'unknown');
  assert.equal(JSON.stringify(planned).includes(aiOptions.credentialStore), false); assert.equal(JSON.stringify(planned).includes(aiOptions.assetsRoot), false);
  assert.equal(planned.constraints.includes('offline_only'), false); assert.ok(planned.constraints.includes('no_build_or_scripts')); verifyAiPlan(planned, config, planned.planHash);
});
test('AI config alone does not select online planning and missing config cannot create an AI plan', () => {
  const config = configured(); assert.equal(fixture(config).ai, undefined); assert.equal(fixture(config).network, 'offline');
  const offline = structuredClone(defaults); assert.throws(() => buildAiPlan(fixture(offline), offline), /ai_not_configured/);
});
test('exact plan acceptance is required; wrong and absent hashes cannot authorize execution', () => {
  const config = configured(), planned = buildAiPlan(fixture(config), config);
  for (const value of ['', '0'.repeat(64), planned.planHash.toUpperCase()]) assert.throws(() => verifyAiPlan(planned, config, value), /ai_plan_not_accepted/);
});
test('source, limits and config policy changes create distinct disclosed plans', () => {
  const config = configured(), source = fixture(config), first = buildAiPlan(source, config);
  const other = structuredClone(source); other.files[0].sha256 = 'f'.repeat(64); other.snapshotHash = digest(other.files); other.planHash = digest({ ...other, planHash: '' });
  assert.notEqual(buildAiPlan(other, config).planHash, first.planHash);
  const changed = configured(); changed.timeoutMs++; assert.notEqual(buildAiPlan(fixture(changed), changed).planHash, first.planHash);
  const changedLimit = configured(); changedLimit.ai.limits.maxRequests++; assert.notEqual(buildAiPlan(fixture(changedLimit), changedLimit).planHash, first.planHash);
  for (const key of ['cpuCount', 'memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes'] as const) {
    const changedResources = configured(); changedResources.ai.workerResources[key] += key === 'cpuCount' ? 1 : 4096;
    const planned = buildAiPlan(fixture(changedResources), changedResources); assert.notEqual(planned.planHash, first.planHash);
    assert.deepEqual(planned.ai?.workerResources, changedResources.ai.workerResources);
  }
});
test('self-rehashed metadata cannot change the fixed disclosure or execution requirements', () => {
  const config = configured(), planned = buildAiPlan(fixture(config), config);
  const mutations: ((p: Plan) => void)[] = [p => { p.network = 'offline'; }, p => { p.transmissions = []; }, p => { p.cost.aiCalls = 0; },
    p => { Reflect.set(p.ai ?? {}, 'model', 'other'); }, p => { Reflect.set(p.ai?.runtime ?? {}, 'imageDigest', 'sha256:' + '0'.repeat(64)); }, p => { if (p.ai) p.ai.limits.maxRequests++; },
    p => { Reflect.set(p.ai?.retention ?? {}, 'providerRetention', 'none'); }, p => { p.constraints = ['offline_only']; }, p => { Reflect.set(p.ai ?? {}, 'extra', true); },
    p => { Reflect.set(p.ai?.workerResources ?? {}, 'memoryBytes', 536870912); }, p => { Reflect.deleteProperty(p.ai ?? {}, 'workerResources'); }, p => { Reflect.set(p.ai ?? {}, 'schema', 'scanmux.ai-plan/v1'); }];
  for (const mutate of mutations) { const broken = structuredClone(planned); mutate(broken); broken.planHash = digest({ ...broken, planHash: '' }); assert.throws(() => verifyAiPlan(broken, config, broken.planHash), /ai_plan_integrity/); }
});
test('blocked, dirty and empty plans are disclosure only, never execution authority', () => {
  const config = configured();
  for (const mutate of [(p: Plan) => { p.blockers = ['fixture_blocked']; }, (p: Plan) => { p.dirty = true; }, (p: Plan) => { p.files = []; p.snapshotHash = digest([]); }]) {
    const source = fixture(config); mutate(source); source.planHash = digest({ ...source, planHash: '' }); const planned = buildAiPlan(source, config);
    assert.throws(() => verifyAiPlan(planned, config, planned.planHash), /ai_plan_blocked/);
  }
});
test('an AI plan discloses its destinations: local sides with their admission level, the provider as unattestable, and the rule as not met', () => {
  const config = configured(), source = fixture(config), planned = buildAiPlan(source, config);
  assert.equal(Object.hasOwn(source, 'destinations'), false, 'the offline plan carries no destinations');
  assert.deepEqual(planned.destinations, { schema: 'scanmux.destinations/v1', rule: 'send_only_to_validated_software', ruleMet: false, destinations: [
    { side: 'local', component: 'codex-security-sdk', sha256: aiRuntime.assetManifestSha256, level: 'digest_pinned_only' },
    { side: 'local', component: 'linux-image', sha256: aiRuntime.imageDigest.slice('sha256:'.length), level: 'digest_pinned_only' },
    { side: 'local', component: 'docker', sha256: null, level: 'unidentified' },
    { side: 'local', component: 'git', sha256: null, level: 'unidentified' },
    { side: 'local', component: 'node', sha256: null, level: 'unidentified' },
    { side: 'provider', component: 'openai-responses', attestation: 'unattestable', reason: 'provider_offers_no_software_attestation' },
  ] });
  assert.equal(planned.planHash, digest({ ...planned, planHash: '' }));
  assert.equal(destinationsText(planned.destinations!), 'AI destinations: rule send_only_to_validated_software not met; local codex-security-sdk=digest_pinned_only, linux-image=digest_pinned_only, '
    + 'docker=unidentified, git=unidentified, node=unidentified; provider openai-responses=unattestable (provider_offers_no_software_attestation).\n');
  const policy = { schema: 'scanmux.runtime-policy/v2', provenance: { require: [{ component: 'linux-image', level: 'publisher' }, { component: 'codex-security-sdk', level: 'recorded' }, { component: 'docker', level: 'publisher' }] } };
  const strict = { ...configured(), schema: 2, runtimePolicy: policy } as unknown as Config;
  const levels = buildAiPlan(fixture(strict), strict).destinations!.destinations.map(item => item.side === 'local' ? item.level : item.attestation);
  assert.deepEqual(levels, ['ledger_recorded_at_admission', 'publisher_verified_at_admission', 'unidentified', 'unidentified', 'unidentified', 'unattestable']);
});
test('destinations are bound into the plan hash and plan acceptance; an altered or missing disclosure is ai_plan_integrity', () => {
  const config = configured(), planned = buildAiPlan(fixture(config), config);
  const mutations: ((p: Plan) => void)[] = [p => { Reflect.set(p.destinations ?? {}, 'ruleMet', true); }, p => { Reflect.deleteProperty(p, 'destinations'); },
    p => { p.destinations?.destinations.pop(); }, p => { Reflect.set(p.destinations?.destinations[2] ?? {}, 'level', 'publisher_verified_at_admission'); },
    p => { Reflect.set(p.destinations?.destinations[5] ?? {}, 'attestation', 'attested'); }];
  for (const mutate of mutations) {
    const broken = structuredClone(planned); mutate(broken);
    assert.throws(() => verifyAiPlan(broken, config, planned.planHash), /ai_plan_integrity/, 'the accepted hash no longer matches the plan');
    broken.planHash = digest({ ...broken, planHash: '' });
    assert.notEqual(broken.planHash, planned.planHash);
    assert.throws(() => verifyAiPlan(broken, config, broken.planHash), /ai_plan_integrity/);
  }
  const offline = fixture(config); Reflect.set(offline, 'destinations', planned.destinations); offline.planHash = digest({ ...offline, planHash: '' });
  assert.throws(() => buildAiPlan(offline, config), /invalid_ai_source_plan/);
});
