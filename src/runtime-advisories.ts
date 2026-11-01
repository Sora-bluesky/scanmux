import path from 'node:path';
import { catalog, catalogIdentity, contains, parseVersion } from './advisory-catalog.ts';
import { declarationInput, extractDeclarations } from './runtime-declarations.ts';
import { emptyRun } from './engine-run.ts';
import { boundedRead, digest, SafeError } from './safety.ts';
import type { Adapter, AdapterContext, AdvisoryDetails, Capability, Declaration, EngineRun, Finding, Plan } from './model.ts';

export function assessDeclaration(input: Declaration): Declaration {
  const version = input.version ? parseVersion(input.version) : null;
  return { ...input, assessments: catalog.records.filter(row => row.product === input.product).map(row => {
    if (!version) return { id: row.id, state: 'unknown', reason: 'declaration_unknown' };
    if (!row.domains.some(range => contains(version, range))) return { id: row.id, state: 'unknown', reason: 'comparison_domain_unknown' };
    const matched = row.affected.some(range => contains(version, range)) && !row.excluded.some(range => contains(version, range));
    return { id: row.id, state: matched ? 'matched' : 'outside_recorded_ranges', reason: matched ? 'affected_version' : 'outside_recorded_ranges' };
  }) };
}
function findings(declarations: Declaration[]): Finding[] {
  return declarations.flatMap(declaration => declaration.assessments.filter(value => value.state === 'matched').map(value => {
    const advisory = catalog.records.find(row => row.id === value.id)!;
    return { fingerprint: digest(['runtime-advisories', advisory.id, declaration]), engine: 'runtime-advisories', originIds: [advisory.id, ...advisory.aliases],
      category: 'runtime', severity: advisory.severity, confidence: 'unknown', evidenceState: 'candidate', disposition: 'open',
      file: declaration.file, line: declaration.line, title: 'Declared version matches an advisory; deployed environment is unverified',
      package: { name: declaration.product!, version: declaration.version!, ecosystem: 'runtime-declaration', direct: 'unknown' },
      fixedVersions: [...advisory.fixed], reachability: 'unknown', knownExploited: 'unknown', advisory };
  }));
}
export class RuntimeAdvisoryAdapter implements Adapter {
  private controller = new AbortController();
  capabilities(): Capability { return { engine: 'runtime-advisories', category: 'runtime-version-declarations', inputs: ['version files', 'Dockerfile FROM', 'npm lockfiles'], operatingSystems: ['windows', 'linux', 'darwin'], permissions: ['read-fixed-snapshot'], buildRequired: false, transmission: 'none', license: 'MIT (adapter); advisory facts retain source attribution' }; }
  plan(plan: Plan) { return { applicable: true, targets: plan.files.filter(file => declarationInput(file.path)).map(file => file.path), constraints: ['declared_versions_only', 'runtime_environment_unverified', 'vendor_patches_unverified'] }; }
  cancel(): void { this.controller.abort(); }
  validate(): 'unsupported' { return 'unsupported'; }
  patch(): 'unsupported' { return 'unsupported'; }
  normalize(): Finding[] { throw new SafeError('builtin_advisory_input_only'); }
  async run(context: AdapterContext): Promise<EngineRun> {
    const run = emptyRun('runtime-advisories', context);
    run.targets = this.plan(context.plan).targets; run.version = '1.0.0'; run.rulesVersion = catalogIdentity.sha256;
    const details: AdvisoryDetails = { catalog: { ...catalogIdentity }, declarations: [], advisories: structuredClone(catalog.records), environment: 'unverified', vendorPatches: 'unverified' };
    run.advisoryDetails = details;
    const signal = AbortSignal.any([context.signal, this.controller.signal]);
    try {
      if (digest(context.plan.advisoryCatalog) !== digest(catalogIdentity)) throw new SafeError('advisory_plan_mismatch');
      for (const file of run.targets) {
        if (signal.aborted) break;
        const bytes = await boundedRead(path.join(context.snapshot, file), context.config.maxFileBytes);
        let text: string;
        try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new SafeError('advisory_input_invalid'); }
        details.declarations.push(...extractDeclarations(file, text).map(assessDeclaration));
      }
      if (signal.aborted) { run.execution = 'cancelled'; run.errors.push('cancelled'); run.coverage = 'partial'; return run; }
      run.execution = 'completed'; run.coverage = details.declarations.length ? 'partial' : 'unsupported'; run.exitCode = 0;
      run.errors.push('runtime_environment_unverified', 'vendor_patches_unverified');
      if (!details.declarations.length) run.errors.push('no_runtime_declarations');
      run.evidence = [{ kind: 'scanner_observation', snapshotHash: context.plan.snapshotHash, reportHash: digest(details), classification: 'confidential', rawRetained: false }];
    } catch (error) {
      run.execution = 'failed'; run.coverage = 'partial';
      run.errors.push(error instanceof SafeError ? error.code : 'advisory_input_invalid');
    } finally { run.findings = findings(details.declarations); run.endedAt = new Date().toISOString(); }
    return run;
  }
}
