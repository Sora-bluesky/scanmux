import type { Engine, Plan } from './model.ts';
import { array, digest, record, safeRelative, SafeError } from './safety.ts';

export const legacyEngines = ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'] as const;
export const trivyEngines = [...legacyEngines, 'trivy'] as const;
export function requiredEngines(schema: unknown): readonly Engine[] {
  if (schema === 'scanmux.plan/v2') return legacyEngines;
  if (schema === 'scanmux.plan/v3') return trivyEngines;
  throw new SafeError('unsupported_plan_schema');
}
export function verifyEngineCatalog(input: unknown): void {
  const plan = record(input);
  if (digest(plan.required) !== digest(requiredEngines(plan.schema))
    || (plan.schema === 'scanmux.plan/v3') !== (plan.trivy !== undefined)) throw new SafeError('engine_plan_mismatch');
  if (plan.schema !== 'scanmux.plan/v3') return;
  if (plan.ai !== undefined || plan.source !== undefined || plan.network !== 'offline') throw new SafeError('trivy_entry_unsupported');
  const trivy = record(plan.trivy), units = array(trivy.inputs).map(record);
  if (trivy.schema !== 'scanmux.trivy-plan/v1' || trivy.profile !== 'embedded-config-v1') throw new SafeError('engine_plan_mismatch');
  const files = new Set(array(plan.files).map(file => record(file).path));
  for (const unit of units) {
    if (!['dockerfile', 'kubernetes', 'terraform', 'cloudformation', 'helm', 'unresolved'].includes(String(unit.kind))
      || typeof unit.key !== 'string' || !unit.key.startsWith(unit.kind + ':') || typeof unit.unresolved !== 'boolean') throw new SafeError('engine_plan_mismatch');
    const paths = array(unit.files);
    if (!paths.length || new Set(paths).size !== paths.length || paths.some(file => typeof file !== 'string' || !files.has(safeRelative(file)))) throw new SafeError('engine_plan_mismatch');
  }
  if (new Set(units.map(unit => unit.key)).size !== units.length) throw new SafeError('engine_plan_mismatch');
}

/** Saved completion claims must carry the same inventory receipts as live execution. */
export function trivyCompletion(planInput: unknown, runInput: unknown): boolean {
  const plan = record(planInput), run = record(runInput);
  if (run.engine !== 'trivy') return true;
  const units = array(record(plan.trivy).inputs).map(record);
  if (run.trivyCoverage === undefined) return false;
  const coverage = record(run.trivyCoverage);
  if (coverage.state === 'unsupported') {
    if (!['no_recognized_config', 'offline_scope_unavailable'].includes(String(coverage.reason)) || run.coverage !== 'unsupported') throw new SafeError('invalid_trivy_coverage');
    return false;
  }
  if (!['analyzed', 'partial'].includes(String(coverage.state)) || run.coverage !== coverage.state) throw new SafeError('invalid_trivy_coverage');
  const receipts = array(coverage.receipts).map(record), byKey = new Map(units.map(unit => [unit.key, unit]));
  if (new Set(receipts.map(receipt => receipt.unit)).size !== receipts.length || receipts.some(receipt => !byKey.has(receipt.unit)
    || !['analyzed', 'unsupported', 'parse_failed', 'excluded', 'unresolved'].includes(String(receipt.state)))) throw new SafeError('invalid_trivy_coverage');
  const complete = units.length > 0 && receipts.length === units.length && receipts.every(receipt => receipt.state === 'analyzed' && !byKey.get(receipt.unit)!.unresolved);
  if (coverage.state === 'analyzed' && !complete) throw new SafeError('invalid_trivy_coverage');
  if (coverage.state === 'partial' && (!array(coverage.reasons).length || array(coverage.reasons).some(reason => typeof reason !== 'string'))) throw new SafeError('invalid_trivy_coverage');
  return coverage.state === 'analyzed' && complete;
}
