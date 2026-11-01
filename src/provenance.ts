import { SafeError } from './safety.ts';
import type { LedgerEntry, PinnedFile, unpublishedReasons } from './engine-ledger.ts';
import { runtimePolicyRef, type PolicyRef, type PublisherIdentity, type RuntimeComponent, type RuntimePolicy2, type RuntimeSubject } from './runtime-policy.ts';

export interface ProvenanceSubject extends RuntimeSubject { readonly file: string | null }
export type EngineState = 'invalid' | 'unverifiable' | 'unrecorded';
export type EngineReason =
  | 'unhashed' | 'not_in_ledger' | typeof unpublishedReasons[number]
  | 'signature_rejected' | 'verifier_failed' | 'evidence_changed' | 'evidence_unreadable' | 'artifact_changed' | 'artifact_unreadable';
export interface EngineDetail {
  readonly component: RuntimeComponent;
  readonly state: EngineState;
  readonly reason: EngineReason;
  readonly ledgerSeq: number | null;
}
export interface GhExpectation extends PublisherIdentity { readonly sha256: string; readonly sourceRef: string; readonly sourceDigest: string }
export interface PublisherCheck {
  readonly component: RuntimeComponent;
  readonly file: string;
  readonly ledgerSeq: number;
  readonly bundle: PinnedFile;
  readonly trustedRoot: PinnedFile;
  readonly expected: GhExpectation;
}
export type ProvenancePlan =
  | { readonly kind: 'ready'; readonly checks: readonly PublisherCheck[] }
  | { readonly kind: 'refused'; readonly policy: PolicyRef; readonly engine: EngineDetail };
export type VerifierOutcome = 'verified' | 'rejected' | 'failed' | 'evidence_changed' | 'evidence_unreadable' | 'artifact_changed' | 'artifact_unreadable';
export type ProvenanceDecision =
  | { readonly kind: 'verified' }
  | { readonly kind: 'refused'; readonly policy: PolicyRef; readonly engine: EngineDetail };
export type ProvenanceRefusal = Extract<ProvenanceDecision, { kind: 'refused' }>;

// Downstream channels keep only /^[a-z_]+$/ codes, so component hyphens become underscores.
export function provenanceCode(engine: EngineDetail): string {
  return `provenance_${engine.state}_${engine.component.replaceAll('-', '_')}`;
}

export class ProvenanceRefusalError extends SafeError {
  readonly policy: PolicyRef;
  readonly engine: EngineDetail;
  constructor(refusal: ProvenanceRefusal) { super(provenanceCode(refusal.engine)); this.policy = refusal.policy; this.engine = refusal.engine; }
}

export function provenanceSubjects(policy: RuntimePolicy2, subjects: readonly ProvenanceSubject[]): ProvenanceSubject[] {
  const publishers = new Set(policy.provenance.require.flatMap(item => item.level === 'publisher' ? [item.component] : []));
  if (!subjects.some(subject => publishers.has(subject.component as RuntimeComponent))) return [...subjects];
  const { verifier } = policy.provenance;
  return [...subjects, { component: 'gh', sha256: verifier.sha256, file: verifier.path }];
}

function latest(ledger: readonly LedgerEntry[], component: RuntimeComponent, sha256: string, kind?: 'sigstore-slsa'): LedgerEntry | undefined {
  return ledger.findLast(entry => entry.component === component && entry.sha256 === sha256 && (!kind || entry.evidence.kind === kind));
}

export function planProvenance(policy: RuntimePolicy2, ledger: readonly LedgerEntry[], subjects: readonly ProvenanceSubject[]): ProvenancePlan {
  const refuse = (component: RuntimeComponent, state: EngineState, reason: EngineReason, ledgerSeq: number | null): ProvenancePlan =>
    ({ kind: 'refused', policy: runtimePolicyRef(policy), engine: { component, state, reason, ledgerSeq } });
  const checks: PublisherCheck[] = [];
  for (const subject of subjects) {
    const requirement = policy.provenance.require.find(item => item.component === subject.component);
    if (!requirement) continue;
    const { component } = requirement;
    if (requirement.level === 'recorded') {
      if (subject.sha256 === null) return refuse(component, 'unrecorded', 'unhashed', null);
      if (!latest(ledger, component, subject.sha256)) return refuse(component, 'unrecorded', 'not_in_ledger', null);
      continue;
    }
    if (subject.sha256 === null) return refuse(component, 'unverifiable', 'unhashed', null);
    if (subject.file === null) return refuse(component, 'unverifiable', 'not_a_file', null);
    const entry = latest(ledger, component, subject.sha256, 'sigstore-slsa') ?? latest(ledger, component, subject.sha256);
    if (!entry) return refuse(component, 'unrecorded', 'not_in_ledger', null);
    if (entry.evidence.kind === 'none') return refuse(component, 'unverifiable', entry.evidence.reason, entry.seq);
    const { bundle, trustedRoot, sourceRef, sourceDigest } = entry.evidence;
    checks.push({ component, file: subject.file, ledgerSeq: entry.seq, bundle, trustedRoot, expected: { ...requirement.publisher, sha256: subject.sha256, sourceRef, sourceDigest } });
  }
  return { kind: 'ready', checks };
}

const refusals: Record<Exclude<VerifierOutcome, 'verified'>, readonly [EngineState, EngineReason]> = {
  rejected: ['invalid', 'signature_rejected'], failed: ['unverifiable', 'verifier_failed'],
  evidence_changed: ['unverifiable', 'evidence_changed'], evidence_unreadable: ['unverifiable', 'evidence_unreadable'],
  artifact_changed: ['unverifiable', 'artifact_changed'], artifact_unreadable: ['unverifiable', 'artifact_unreadable'],
};

export function decideProvenance(policy: RuntimePolicy2, check: PublisherCheck, outcome: VerifierOutcome): ProvenanceDecision {
  if (outcome === 'verified') return { kind: 'verified' };
  const [state, reason] = refusals[outcome];
  return { kind: 'refused', policy: runtimePolicyRef(policy), engine: { component: check.component, state, reason, ledgerSeq: check.ledgerSeq } };
}

export const ghOutputLimit = 4 * 1024 * 1024;
const elementLimit = 64, subjectLimit = 4096;

function field(input: unknown, ...keys: string[]): unknown {
  let value = input;
  for (const key of keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, key)) return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}
function matches(element: unknown, expected: GhExpectation): boolean {
  const statement = field(element, 'verificationResult', 'statement');
  const certificate = field(element, 'verificationResult', 'signature', 'certificate');
  const subjects = field(statement, 'subject');
  if (!Array.isArray(subjects) || subjects.length > subjectLimit) return false;
  return field(statement, 'predicateType') === expected.predicateType
    && subjects.some(subject => field(subject, 'digest', 'sha256') === expected.sha256)
    && field(certificate, 'subjectAlternativeName') === expected.certIdentity
    && field(certificate, 'issuer') === expected.oidcIssuer
    && field(certificate, 'sourceRepositoryURI') === `https://github.com/${expected.repository}`
    && field(certificate, 'sourceRepositoryRef') === expected.sourceRef
    && field(certificate, 'sourceRepositoryDigest') === expected.sourceDigest
    && field(certificate, 'runnerEnvironment') === expected.runner;
}

// Exit 0 alone is not trusted: the structured result must also name the pinned artifact and identity.
export function evaluateGhVerification(code: number | null, stdout: Buffer | string, expected: GhExpectation): 'verified' | 'rejected' | 'failed' {
  if (code === 1) return 'rejected';
  if (code !== 0) return 'failed';
  const bytes = typeof stdout === 'string' ? Buffer.from(stdout) : stdout;
  if (bytes.length > ghOutputLimit) return 'failed';
  let parsed: unknown;
  try { parsed = JSON.parse(bytes.toString('utf8')); } catch { return 'failed'; }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > elementLimit) return 'failed';
  return parsed.some(element => matches(element, expected)) ? 'verified' : 'failed';
}
