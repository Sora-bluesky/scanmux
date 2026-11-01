import type { Engine, EngineRun, AdapterContext } from './model.ts';
export function emptyRun(engine: Engine, context: AdapterContext, reason?: string): EngineRun {
  const tool = engine === 'runtime-advisories' ? undefined : context.config.tools[engine];
  const now = new Date().toISOString();
  return {
    engine, execution: 'not_started', coverage: 'skipped', targets: engine === 'osv' ? context.plan.lockfiles : context.plan.files.map(f => f.path),
    exclusions: [], findings: [], evidence: [], errors: reason ? [reason] : [],
    version: tool?.version ?? null, executableHash: tool?.sha256 ?? null, rulesVersion: engine === 'gitleaks' ? 'builtin-8.30.1' : null,
    dbAsOf: null, database: [], startedAt: now, endedAt: now, exitCode: null,
    auth: engine === 'codex-security' ? 'chatgpt' : 'none', modelRequested: engine === 'codex-security' ? context.config.model : null,
    modelActual: null, accessProgramRequested: engine === 'codex-security' ? 'daybreak_blue' : null,
    accessProgramEffective: engine === 'codex-security' ? 'unknown' : null,
    usage: { calls: 0, cost: null, kind: 'not_applicable', allowance: 'unknown' },
  };
}
