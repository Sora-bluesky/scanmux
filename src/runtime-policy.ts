import path from 'node:path';
import { SafeError, digest } from './safety.ts';
import type { Tool } from './model.ts';

export const runtimeComponents = ['git', 'gitleaks', 'osv', 'docker', 'codex-cli', 'codex-security-sdk', 'linux-image', 'windows-owner', 'node', 'trivy'] as const;
export type RuntimeComponent = typeof runtimeComponents[number];
export const runtimeComponents2 = [...runtimeComponents, 'gh', 'windows-process-owner'] as const;
export type RuntimeComponent2 = typeof runtimeComponents2[number];

export type RuntimeRule<C extends RuntimeComponent2 = RuntimeComponent> =
  | { readonly kind: 'component'; readonly component: C }
  | { readonly kind: 'digest'; readonly component: C; readonly sha256: string };
interface RuntimePolicyFields {
  readonly id: string;
  readonly revision: number;
  readonly state: 'active' | 'stopped';
}
export interface RuntimePolicy1 extends RuntimePolicyFields {
  readonly schema: 'scanmux.runtime-policy/v1';
  readonly deny: readonly RuntimeRule[];
}
export interface PublisherIdentity {
  readonly repository: string;
  readonly certIdentity: string;
  readonly oidcIssuer: string;
  readonly predicateType: string;
  readonly runner: 'github-hosted';
}
export type ProvenanceRequirement =
  | { readonly component: RuntimeComponent; readonly level: 'recorded' }
  | { readonly component: RuntimeComponent; readonly level: 'publisher'; readonly publisher: PublisherIdentity };
export interface LedgerPin { readonly path: string; readonly entries: number; readonly head: string }
export interface RuntimePolicy2 extends RuntimePolicyFields {
  readonly schema: 'scanmux.runtime-policy/v2';
  readonly deny: readonly RuntimeRule<RuntimeComponent2>[];
  readonly provenance: {
    readonly verifier: Readonly<Tool>;
    readonly ledger: LedgerPin;
    readonly require: readonly ProvenanceRequirement[];
  };
}
export type RuntimePolicy = RuntimePolicy1 | RuntimePolicy2;
export interface RuntimeSubject { readonly component: RuntimeComponent2; readonly sha256: string | null }
export interface PolicyRef { readonly id: string; readonly revision: number; readonly state: RuntimePolicy['state']; readonly sha256: string }
export type RuntimeDecision =
  | { readonly kind: 'continue' }
  | { readonly kind: 'stopped'; readonly policy: PolicyRef }
  | { readonly kind: 'denied'; readonly policy: PolicyRef; readonly component: RuntimeComponent2; readonly rule: RuntimeRule['kind'] }
  | { readonly kind: 'unidentified'; readonly policy: PolicyRef; readonly component: RuntimeComponent2 };
export type RuntimeRefusal = Exclude<RuntimeDecision, { kind: 'continue' }>;

const schema = 'scanmux.runtime-policy/v1';
const schema2 = 'scanmux.runtime-policy/v2';
export const zeroHead = '0'.repeat(64);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const shaPattern = /^[0-9a-f]{64}$/;
const httpsPattern = /^https:\/\/[\x21-\x7e]{1,1000}$/;
const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.\.?$)[A-Za-z0-9._-]{1,100}$/;
const versionPattern = /^[0-9]+\.[0-9]+\.[0-9]+$/;

function invalid(): never { throw new SafeError('runtime_policy_invalid'); }
function exact(input: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>;
  if (Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key))) invalid();
  return value;
}
function component(input: unknown): RuntimeComponent;
function component<C extends RuntimeComponent2>(input: unknown, set: readonly C[]): C;
function component(input: unknown, set: readonly string[] = runtimeComponents): string {
  if (typeof input !== 'string' || !set.includes(input)) invalid();
  return input;
}
function sha256(input: unknown): string {
  if (typeof input !== 'string' || !shaPattern.test(input)) invalid();
  return input;
}
function text(input: unknown, pattern: RegExp): string {
  if (typeof input !== 'string' || !pattern.test(input)) invalid();
  return input;
}
type Absolute = (input: string) => boolean;
function absolutePath(input: unknown, absolute: Absolute): string {
  if (typeof input !== 'string' || input.length > 4096 || /[\x00-\x1f\x7f]/.test(input) || !absolute(input)) invalid();
  return input;
}
function rule<C extends RuntimeComponent2>(input: unknown, set: readonly C[]): RuntimeRule<C> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const kind = (input as Record<string, unknown>).kind;
  if (kind === 'component') return { kind, component: component(exact(input, ['kind', 'component']).component, set) };
  if (kind === 'digest') { const value = exact(input, ['kind', 'component', 'sha256']); return { kind, component: component(value.component, set), sha256: sha256(value.sha256) }; }
  return invalid();
}
function ruleKey(value: RuntimeRule<RuntimeComponent2>): [string, string, string] {
  return [value.component, value.kind, value.kind === 'digest' ? value.sha256 : ''];
}
function compareRules(left: RuntimeRule<RuntimeComponent2>, right: RuntimeRule<RuntimeComponent2>): number {
  const a = ruleKey(left), b = ruleKey(right);
  for (let index = 0; index < a.length; index++) if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  return 0;
}
function fields<C extends RuntimeComponent2>(value: Record<string, unknown>, set: readonly C[]): RuntimePolicyFields & { deny: RuntimeRule<C>[] } {
  if (typeof value.id !== 'string' || !uuidPattern.test(value.id)) invalid();
  if (typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < 1) invalid();
  if (value.state !== 'active' && value.state !== 'stopped') invalid();
  if (!Array.isArray(value.deny)) invalid();
  const deny = value.deny.map(item => rule(item, set));
  const sorted = [...deny].sort(compareRules);
  if (sorted.some((item, index) => index > 0 && compareRules(sorted[index - 1], item) === 0)) invalid();
  return { id: value.id, revision: value.revision, state: value.state, deny };
}

export function parseRuntimePolicy(input: unknown): RuntimePolicy1 {
  const value = exact(input, ['schema', 'id', 'revision', 'state', 'deny']);
  if (value.schema !== schema) invalid();
  const { id, revision, state, deny } = fields(value, runtimeComponents);
  return { schema, id, revision, state, deny };
}

function publisher(input: unknown): PublisherIdentity {
  const value = exact(input, ['repository', 'certIdentity', 'oidcIssuer', 'predicateType', 'runner']);
  if (value.runner !== 'github-hosted') invalid();
  return {
    repository: text(value.repository, repositoryPattern), certIdentity: text(value.certIdentity, httpsPattern),
    oidcIssuer: text(value.oidcIssuer, httpsPattern), predicateType: text(value.predicateType, httpsPattern), runner: value.runner,
  };
}
function requirement(input: unknown): ProvenanceRequirement {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const level = (input as Record<string, unknown>).level;
  if (level === 'recorded') return { component: component(exact(input, ['component', 'level']).component), level };
  if (level === 'publisher') { const value = exact(input, ['component', 'level', 'publisher']); return { component: component(value.component), level, publisher: publisher(value.publisher) }; }
  return invalid();
}
function verifier(input: unknown, absolute: Absolute): Tool {
  const value = exact(input, ['path', 'sha256', 'version']);
  return { path: absolutePath(value.path, absolute), sha256: sha256(value.sha256), version: text(value.version, versionPattern) };
}
function ledgerPin(input: unknown, absolute: Absolute): LedgerPin {
  const value = exact(input, ['path', 'entries', 'head']);
  if (typeof value.entries !== 'number' || !Number.isSafeInteger(value.entries) || value.entries < 0) invalid();
  const head = sha256(value.head);
  if (value.entries === 0 && head !== zeroHead) invalid();
  return { path: absolutePath(value.path, absolute), entries: value.entries, head };
}

/** `absolute` is widened only where the pinned paths are carried but never opened, such as the Linux job records. */
export function parseRuntimePolicy2(input: unknown, absolute: Absolute = path.isAbsolute): RuntimePolicy2 {
  const value = exact(input, ['schema', 'id', 'revision', 'state', 'deny', 'provenance']);
  if (value.schema !== schema2) invalid();
  const { id, revision, state, deny } = fields(value, runtimeComponents2);
  const provenance = exact(value.provenance, ['verifier', 'ledger', 'require']);
  if (!Array.isArray(provenance.require)) invalid();
  const require = provenance.require.map(requirement);
  if (new Set(require.map(item => item.component)).size !== require.length) invalid();
  return { schema: schema2, id, revision, state, deny, provenance: { verifier: verifier(provenance.verifier, absolute), ledger: ledgerPin(provenance.ledger, absolute), require } };
}

export function declaresRuntimePolicy2(input: unknown): boolean {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input) && (input as Record<string, unknown>).schema === schema2;
}
export function parseAnyRuntimePolicy(input: unknown, absolute: Absolute = path.isAbsolute): RuntimePolicy {
  return declaresRuntimePolicy2(input) ? parseRuntimePolicy2(input, absolute) : parseRuntimePolicy(input);
}

function canonicalProvenance({ verifier: tool, ledger, require }: RuntimePolicy2['provenance']): unknown {
  return {
    verifier: { path: tool.path, sha256: tool.sha256, version: tool.version },
    ledger: { path: ledger.path, entries: ledger.entries, head: ledger.head },
    require: [...require].sort((left, right) => left.component < right.component ? -1 : 1).map(item => item.level === 'recorded'
      ? { component: item.component, level: item.level }
      : { component: item.component, level: item.level, publisher: {
        repository: item.publisher.repository, certIdentity: item.publisher.certIdentity, oidcIssuer: item.publisher.oidcIssuer,
        predicateType: item.publisher.predicateType, runner: item.publisher.runner } }),
  };
}

export function runtimePolicyRef(policy: RuntimePolicy): PolicyRef {
  const deny = [...policy.deny].sort(compareRules)
    .map(item => item.kind === 'digest' ? { kind: item.kind, component: item.component, sha256: item.sha256 } : { kind: item.kind, component: item.component });
  const canonical = policy.schema === schema
    ? { schema: policy.schema, id: policy.id, revision: policy.revision, state: policy.state, deny }
    : { schema: policy.schema, id: policy.id, revision: policy.revision, state: policy.state, deny, provenance: canonicalProvenance(policy.provenance) };
  return { id: policy.id, revision: policy.revision, state: policy.state, sha256: digest(canonical) };
}

export function decideRuntimePolicy(policy: RuntimePolicy, subjects: readonly RuntimeSubject[]): RuntimeDecision {
  const set: readonly RuntimeComponent2[] = policy.schema === schema ? runtimeComponents : runtimeComponents2;
  for (const subject of subjects) { component(subject.component, set); if (subject.sha256 !== null) sha256(subject.sha256); }
  const ref = runtimePolicyRef(policy);
  if (policy.state === 'stopped') return { kind: 'stopped', policy: ref };
  const deny: readonly RuntimeRule<RuntimeComponent2>[] = policy.deny;
  for (const subject of subjects) {
    const rules = deny.filter(item => item.component === subject.component);
    if (rules.some(item => item.kind === 'component')) return { kind: 'denied', policy: ref, component: subject.component, rule: 'component' };
    const digests = rules.flatMap(item => item.kind === 'digest' ? [item.sha256] : []);
    if (digests.length === 0) continue;
    if (subject.sha256 === null) return { kind: 'unidentified', policy: ref, component: subject.component };
    if (digests.includes(subject.sha256)) return { kind: 'denied', policy: ref, component: subject.component, rule: 'digest' };
  }
  return { kind: 'continue' };
}

// Downstream channels keep only /^[a-z_]+$/ codes, so component hyphens become underscores.
export function runtimePolicyCode(decision: RuntimeRefusal): string {
  if (decision.kind === 'stopped') return 'runtime_policy_stopped';
  const name = decision.component.replaceAll('-', '_');
  return decision.kind === 'denied' ? `runtime_policy_denied_${name}_${decision.rule}` : `runtime_policy_unidentified_${name}`;
}

export class RuntimePolicyRefusalError extends SafeError {
  readonly policy: PolicyRef;
  constructor(decision: RuntimeRefusal) { super(runtimePolicyCode(decision)); this.policy = decision.policy; }
}

export function admitRuntimePolicy(policy: RuntimePolicy, subjects: readonly RuntimeSubject[]): void {
  const decision = decideRuntimePolicy(policy, subjects);
  if (decision.kind !== 'continue') throw new RuntimePolicyRefusalError(decision);
}
