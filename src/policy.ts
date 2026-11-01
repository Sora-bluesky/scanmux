import type { EngineRun, Finding, Gate, Plan } from './model.ts';

export const exitCodes: Record<Gate, number> = { PASS: 0, FAIL: 1, REVIEW: 2, INCOMPLETE: 3, ERROR: 4 };
export type PolicyPlan = Pick<Plan, 'blockers' | 'exclusions' | 'required'>;
export type PolicyFinding = Pick<Finding, 'category' | 'severity' | 'evidenceState'>;
export type PolicyEngine = Pick<EngineRun, 'engine' | 'execution' | 'coverage'> & { findings: PolicyFinding[]; errors?: string[] };
export function decide(plan: PolicyPlan, engines: PolicyEngine[], integrityErrors: string[] = []): { gate: Gate; reasons: string[] } {
  const reasons = [...integrityErrors, ...plan.blockers];
  if (plan.exclusions.length) reasons.push('snapshot_entries_excluded');
  const findings = engines.flatMap(e => e.findings);
  const fail = findings.some(f => f.category === 'secret' || (['critical', 'high'].includes(f.severity) && f.evidenceState !== 'candidate'));
  const missing = plan.required.filter(id => !engines.some(e => e.engine === id && e.execution === 'completed' && e.coverage === 'analyzed'));
  if (fail) reasons.push('blocking_finding');
  if (missing.length) reasons.push(...missing.map(e => `required_${e}_incomplete`));
  const review = findings.some(f => f.severity === 'unknown' || (['critical', 'high'].includes(f.severity) && f.evidenceState === 'candidate'));
  if (review) reasons.push('finding_requires_review');
  const failed = engines.filter(e => e.execution === 'failed');
  reasons.push(...failed.map(e => `${e.engine}_execution_failed`));
  for (const cause of ['job_disk_copy_limit', 'job_disk_measured_limit', 'job_disk_observation_unverified']) {
    if (engines.some(e => e.errors?.includes(cause))) reasons.push(cause);
  }
  const gate: Gate = integrityErrors.length || failed.length || reasons.includes('job_disk_observation_unverified') ? 'ERROR' : fail ? 'FAIL' : plan.blockers.length || plan.exclusions.length || missing.length || reasons.includes('job_disk_measured_limit') ? 'INCOMPLETE' : review ? 'REVIEW' : 'PASS';
  return { gate, reasons: [...new Set(reasons)] };
}
