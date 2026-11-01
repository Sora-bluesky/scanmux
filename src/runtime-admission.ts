import { copyFile, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { releaseJobDiskRoot } from './job-disk.ts';
import { privateWorkspace } from './private-storage.ts';
import { executeDirect, jobDiskDiagnostic, verifyVersion } from './process.ts';
import { canonical, hash, hostLocalPath, SafeError, within } from './safety.ts';
import { readPinnedLedger } from './engine-ledger.ts';
import { admitRuntimePolicy, type RuntimePolicy, type RuntimePolicy2 } from './runtime-policy.ts';
import { CopyCleanupError, JobDiskCopyLimitError, scopedCopyBudget } from './copy-budget.ts';
import { sourceCleanupFor } from './source-cleanup.ts';
import {
  decideProvenance, evaluateGhVerification, ghOutputLimit, planProvenance, provenanceSubjects, ProvenanceRefusalError,
  type ProvenanceSubject, type PublisherCheck, type VerifierOutcome,
} from './provenance.ts';

/** deadlineAt, when supplied, is an absolute performance.now() deadline shared by every publisher check. */
export interface AdmissionScope { readonly root?: string; readonly timeoutMs: number; readonly signal?: AbortSignal; readonly deadlineAt?: number }

export function ghVerifyArguments(check: PublisherCheck, copies: { artifact: string; bundle: string; trustedRoot: string }): string[] {
  const { expected } = check;
  return ['attestation', 'verify', copies.artifact, '--bundle', copies.bundle, '--custom-trusted-root', copies.trustedRoot,
    '--repo', expected.repository, '--source-ref', expected.sourceRef, '--source-digest', expected.sourceDigest,
    '--cert-identity', expected.certIdentity, '--cert-oidc-issuer', expected.oidcIssuer, '--predicate-type', expected.predicateType,
    '--deny-self-hosted-runners', '--format', 'json'];
}

/** Bundle and trusted root paths, for the recorder and for admission alike. I/O errors from resolving the file are left to the caller. */
export async function evidencePath(file: string, root?: string): Promise<string> {
  if (!hostLocalPath(file)) throw new SafeError('provenance_evidence_not_local');
  if (root && within(root, path.resolve(file))) throw new SafeError('provenance_evidence_inside_target');
  const physical = await canonical(file);
  if (root && within(root, physical)) throw new SafeError('provenance_evidence_inside_target');
  return physical;
}

async function copied(source: string, destination: string): Promise<string | null> {
  try {
    const budget = scopedCopyBudget();
    if (budget) await budget.copy(source, destination);
    else await copyFile(source, destination, constants.COPYFILE_EXCL);
    return hash(await readFile(destination));
  } catch (error) {
    if (error instanceof JobDiskCopyLimitError || error instanceof CopyCleanupError) throw error;
    return null;
  }
}

async function verifyIn(workspace: string, policy: RuntimePolicy2, check: PublisherCheck, scope: AdmissionScope): Promise<VerifierOutcome> {
  // gh chooses how to parse a bundle by its extension and reads only .json and .jsonl.
  const bundleName = path.extname(check.bundle.path).toLowerCase() === '.json' ? 'bundle.json' : 'bundle.jsonl';
  const copies = { artifact: path.join(workspace, 'artifact'), bundle: path.join(workspace, bundleName), trustedRoot: path.join(workspace, 'trusted-root.jsonl') };
  const artifact = await copied(check.file, copies.artifact);
  if (artifact === null) return 'artifact_unreadable';
  if (artifact !== check.expected.sha256) return 'artifact_changed';
  const bundle = await copied(check.bundle.path, copies.bundle), trustedRoot = await copied(check.trustedRoot.path, copies.trustedRoot);
  if (bundle === null || trustedRoot === null) return 'evidence_unreadable';
  if (bundle !== check.bundle.sha256 || trustedRoot !== check.trustedRoot.sha256) return 'evidence_changed';
  const { verifier } = policy.provenance;
  const options = { cwd: workspace, home: workspace, timeoutMs: scope.timeoutMs, deadlineAt: scope.deadlineAt,
    maxOutputBytes: ghOutputLimit, signal: scope.signal, target: scope.root };
  let diskStopped = false;
  const run: typeof executeDirect = async (...args) => {
    const result = await executeDirect(...args);
    diskStopped ||= result.jobDiskStopped === true;
    return result;
  };
  try {
    await verifyVersion(verifier, ['--version'], options, run);
    const result = await run(verifier, ghVerifyArguments(check, copies), options);
    if (result.reason.startsWith('job_disk_') || result.reason === 'termination_unverified' && diskStopped) throw new SafeError(result.reason);
    const diskCause = jobDiskDiagnostic(result);
    if (diskCause) throw new SafeError(diskCause);
    return evaluateGhVerification(result.reason === 'exit' ? result.code : null, result.stdout, check.expected);
  } catch (error) {
    // A refusal to start escapes to the shared admission window; attempted or cancelled checks keep their provenance outcome.
    if (error instanceof SafeError && (error.code === 'process_start_deadline' || error.code === 'termination_unverified' && diskStopped || error.code.startsWith('job_disk_'))) throw error;
    return 'failed';
  }
}

/** Steps 3 and 4 for one publisher check; the copies live only in a private workspace removed before returning. */
export async function verifyPublisher(policy: RuntimePolicy2, check: PublisherCheck, scope: AdmissionScope): Promise<VerifierOutcome> {
  for (const file of [check.bundle.path, check.trustedRoot.path]) {
    try { await evidencePath(file, scope.root); }
    catch (error) { if (error instanceof SafeError) throw error; return 'evidence_unreadable'; }
  }
  const workspace = await privateWorkspace(scope.root, { disposable: true });
  const cleanup = sourceCleanupFor(workspace); cleanup.register(workspace, workspace);
  let failed = false, outcome: VerifierOutcome | undefined;
  try { return outcome = await verifyIn(workspace, policy, check, scope); }
  catch (error) { failed = true; throw error; }
  finally {
    releaseJobDiskRoot(workspace);
    if ((await cleanup.cleanup(workspace)).status === 'failed' && !failed && outcome === 'verified') throw new SafeError('source_cleanup_failed');
  }
}

export function decideRuntime(policy: RuntimePolicy, subjects: readonly ProvenanceSubject[]): void {
  admitRuntimePolicy(policy, policy.schema === 'scanmux.runtime-policy/v1' ? subjects : provenanceSubjects(policy, subjects));
}

export async function admitRuntime(policy: RuntimePolicy, subjects: readonly ProvenanceSubject[], scope: AdmissionScope): Promise<void> {
  decideRuntime(policy, subjects);
  if (policy.schema === 'scanmux.runtime-policy/v1') return;
  const all = provenanceSubjects(policy, subjects);
  const plan = planProvenance(policy, await readPinnedLedger(policy.provenance.ledger, scope.root), all);
  if (plan.kind === 'refused') throw new ProvenanceRefusalError(plan);
  for (const check of plan.checks) {
    const decision = decideProvenance(policy, check, await verifyPublisher(policy, check, scope));
    if (decision.kind === 'refused') throw new ProvenanceRefusalError(decision);
  }
}
