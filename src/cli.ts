import { parseArgs } from 'node:util';
import { packageVersion } from './package-version.ts';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { scopedJobDisk, withJobDisk } from './job-disk.ts';
import { loadConfig } from './config.ts';
import { JobDiskCopyLimitError, scopedCopyBudget, withCopyBudget } from './copy-budget.ts';
import { privateWorkspace } from './private-storage.ts';
import { buildPlan } from './repository.ts';
import { scan } from './controller.ts';
import { createAdapters } from './adapters.ts';
import { checkedJson, checkedText, saveReportBundle, staticError } from './output.ts';
import { analyzeDependencies, dependencyText } from './dependencies.ts';
import { importResults, importText } from './import.ts';
import { canonical, SafeError } from './safety.ts';
import { execute } from './process.ts';
import { withProcessRuntime } from './process-tree.ts';
import type { Config, Engine } from './model.ts';
import { startWeb } from './web.ts';
import { advisoryText } from './advisory-display.ts';
import { commitPair } from './comparison.ts';
import { executeBatch, prepareBatch } from './batch.ts';
import { ciArguments, checkCiFiles, saveCiReceipt } from './ci.ts';
import { parseGithubRequest, verifyGithubRun } from './github-ci.ts';
import { readHistoryFiles } from './history.ts';
import { readResumeSource, verifyResumePlan, saveResumeReceipt } from './resume.ts';
import { readDispositions } from './dispositions.ts';
import { checkPolicyFiles } from './policy-exceptions.ts';
import { aiSubjects, buildAiPlan, destinationsText, verifyAiPlan } from './ai-plan.ts';
import { createAiAdapter, type SyntheticAiRuntime } from './ai-runner.mjs';
import { parseReportLanguage, trivyCoverageText } from './report-language.ts';
import { probeTrivy, TrivyAdapter } from './trivy-adapter.ts';
import { legacyEngines } from './engine-catalog.ts';
import { recoverEngineCheckpoints } from './engine-checkpoint.ts';
import { scanJob, verifyFinding } from './job-runner.ts';
import { scanHostJob, exportHostJob, recoverHostJob, isHostJobRecovery } from './host-job.ts';
import { exportJob, recoverJob } from './job-view.ts';
import { RuntimePolicyRefusalError } from './runtime-policy.ts';
import { ProvenanceRefusalError, type ProvenanceSubject } from './provenance.ts';
import { admitRuntime, decideRuntime } from './runtime-admission.ts';
import { EngineLedgerUnpinnedTailError, engineHistory, recordEngine } from './engine-record.ts';
import { openRepository, releaseCommandTarget, releaseLogCheck, releaseRecord, releaseVerify } from './release-transparency.ts';
import { matchIntelFiles, parseMaxAgeHours, refreshIntel } from './intel/index.ts';
import { SourceCleanupOwner, sourceCleanupFailed, sourceCleanupFor, withSourceCleanup } from './source-cleanup.ts';

const help = `ScanMux 0.2.3
Usage: scanmux doctor [--config /absolute/config.json] [--json]
       scanmux plan <local-git-root> --config /absolute/config.json [--base SHA --head SHA] [--json]
       scanmux scan <local-git-root> --config /absolute/config.json [--base SHA --head SHA] [--json]
       scanmux deps <local-git-root> --config /absolute/config.json [--base SHA --head SHA] [--json]
       scanmux import <local-git-root> /absolute/result.sarif [/absolute/import.json ...] --config /absolute/config.json [--scanned-commit SHA] [--json]
       scanmux ai-plan <local-git-root> --config /absolute/config.json [--base SHA --head SHA] [--json]
       scanmux ai-scan <local-git-root> --config /absolute/config.json --accept-plan SHA256 [--base SHA --head SHA] [--json]
       scanmux plan-list /absolute/repositories.json --config /absolute/config.json [--json]
       scanmux scan-list /absolute/repositories.json --config /absolute/config.json [--json]
       scanmux scan <local-git-root> --config /absolute/config.json --ci-run UUID --ci-job ID [--base SHA --head SHA] [--json]
       scanmux ci-check /absolute/expected.json [/absolute/ci-receipt.json ...] --config /absolute/config.json [--ci-report /absolute/report.json ...] [--json]
       scanmux ci-github --repo OWNER/NAME --run ID --attempt N --config /absolute/config.json [--from-dir /absolute/delivery] [--json]
       scanmux history /absolute/report.json [/absolute/report.json ...] --config /absolute/config.json [--json]
       scanmux recover /absolute/private-run/checkpoints --config /absolute/config.json [--json] [--report-language ja|en]
       scanmux job-scan <local-git-root> --job-profile /absolute/profile.json [--base SHA --head SHA] [--json]
       scanmux reproduce <local-git-root> --job-profile /absolute/profile.json --from /absolute/report.json --finding ENGINE:FINGERPRINT --test tests/repro [--required] [--base SHA --head SHA] [--json]
       scanmux host-job-scan <absolute-local-git-root> --host-job-profile /absolute/profile.json [--base SHA --head SHA] [--json]
       scanmux job-export /absolute/private-job/job.json --config /absolute/config.json [--report-language ja|en] [--json]
       scanmux job-recover /absolute/private-job --config /absolute/config.json [--report-language ja|en] [--json]
       scanmux resume <local-git-root> --from /absolute/report.json --config /absolute/config.json [--base SHA --head SHA] [--json]
       scanmux dispositions /absolute/report.json [--decisions /absolute/decisions.json] --config /absolute/config.json [--json]
       scanmux policy-check /absolute/report.json --decisions /absolute/decisions.json --config /absolute/config.json [--json]
       scanmux serve --config /absolute/config.json [--site-origin https://your-site.example]
       scanmux runner-check --config /absolute/config.json [--json]
       scanmux engine-record /absolute/request.json --config /absolute/config.json [--json]
       scanmux engine-history --config /absolute/config.json [--json]
       scanmux release-record <local-git-root> --commit SHA --expect-head SHA256|zero --config /absolute/config.json [--json]
       scanmux release-verify <local-git-root> --log-commit SHA (--installed /absolute/dir | --commit SHA) [--pin ENTRIES:SHA256] --config /absolute/config.json [--json]
       scanmux release-log-check <local-git-root> --base SHA|none --head SHA --config /absolute/config.json [--json]
       scanmux intel-refresh --store /absolute/intel-store [--json]
       scanmux intel-match /absolute/report.json|/absolute/import.json --store /absolute/intel-store --config /absolute/config.json [--max-age-hours N] [--require-fresh] [--report-language ja|en] [--json]

Default commands remain offline. AI requires an explicit AI Plan and fixed isolated Linux runner.
On Windows, a command that would start a configured tool needs the process owner pinned as tools["windows-process-owner"] (build it with scripts/build-windows-process-owner.ps1); without it the command fails with process_containment_unavailable before any tool starts (deps exits 2; other commands exit 4). Each tool then runs in its own Job Object, and a stop is reported only after the whole process tree is gone, or as termination_unverified.
Scan gate exit codes: PASS=0 FAIL=1 REVIEW=2 INCOMPLETE=3 ERROR=4. deps has separate exit codes below.
Reports are private, outside the target. No source build/install, push or upload.
runner-check is an explicit model-free ChatGPT/Linux connection diagnostic; it cannot enable AI scans.
ai-plan discloses the fixed OpenAI source scope and finite limits without reading credentials or starting a worker.
ai-scan requires the exact current AI Plan hash; dedicated SIWC credentials stay in host memory. No automatic retry, refresh or API-key fallback.
AI is limited to one local repository; Web, batch and resume remain offline-only.
ai-scan accepts paired --ci-run UUID --ci-job ID; its v2 CI check requires the exact saved report via --ci-report.
Diff requests scan the full head snapshot; empty diffs do not skip dependencies.
plan-list success means planning completed, never a security PASS.
deps checks base/head lockfiles with the same offline OSV database and reports added/removed/unchanged advisories (present without a base).
Since 0.2.0, deps uses scanmux.dependencies/v2 and exits 0 for no added/present advisory, 10 for added/present advisories, or 2 for a failed/incomplete check. Upgrade undetermined results do not change this exit code; 0 is never a security PASS.
import reads OSV-Scanner or Gitleaks SARIF 2.1.0 and earlier import records, bound to the commit they record or --scanned-commit; exit 0 means read and recorded, never a security PASS. The gate is unchanged and imported findings stay separate; any rejected input, unbound or non-HEAD commit, dirty worktree or missing value exits 3. An import record's factsDigest detects corruption only; it is not an authentication. Import records are scanmux.import/v2; an earlier scanmux.import/v1 record is refused as unsupported_schema, so import its original SARIF again.
ci-check requires a trusted, pre-scan expectation and all four engines; missing jobs cannot pass.
ci-github verifies one offline-selfscan GitHub Actions run with the runtime policy v2 gh and GH_TOKEN: run, workflow content, jobs, artifact, log anchor, manifest and a local re-evaluation. It exits with the claimed gate only when all agree; missing, cancelled or skipped exits 3; tampering, mismatch, failed acquisition, disagreement or a failure scenario exits 4. --from-dir checks a downloaded copy, still requires every API check, and turns a PASS claim into INCOMPLETE (exit 3).
history exit 0 means records were read and summarized, never a security PASS.
dispositions exit 0 means saved judgments were assessed, never a security PASS or a gate override.
policy-check returns a separate gate for exact saved records with explicit exceptions; original scan and CI records remain unchanged.
resume reruns all engines once in a new run; only a matching cancelled or time-limited run can be used.
scan, ai-scan, resume and scan-list accept --report-language ja|en for HTML reports (default: ja).
Report language changes HTML display only; canonical JSON, SARIF, decisions and identifiers stay unchanged.
recover exports the latest verified engine checkpoint as ERROR: controller completion and process termination remain unverified. It never reruns a scan.
job-scan is an explicit single-local offline Linux payload; it never selects AI or falls back to native scanning.
host-job-scan adds explicit Windows coordinator CPU/committed-memory containment; trusted admission/owner and physical output quota remain excluded.
Its operator profile sets finite CPU rate, memory, transient stores, PIDs, payload wall time and logical retained bytes.
Host control-plane CPU/memory, retained physical filesystem capacity and whole-command duration are not guaranteed.
job-export renders actual saved analysis; without a report/checkpoint it returns an analysis-unavailable error.
job-recover exports only a verified checkpoint prefix as ERROR; it never starts Docker or trusts saved closure claims.
Job viewers show the recorded outer job outcome separately from the analysis outcome; viewing does not authenticate current ownership.
engine-record is the only engine ledger writer; it needs a runtime policy v2 config and verifies publisher evidence before appending.
engine-history exit 0 means the pinned ledger was read, never a security PASS. The ledger is not an authenticated history.
Runtime policy v2 verifies publisher-required engines offline with the pinned gh before any engine starts, including job-scan and host-job-scan; refusals exit 2 for deps (failure), or 4 for other commands.
serve refuses runtime policy v2.
release-record measures the package file set (package.json files, package.json and package-lock.json) of one commit from Git blobs and appends one line to transparency/releases.jsonl when the log head equals --expect-head; recording the same release again appends nothing. It is the only log writer.
release-verify reads the log from --log-commit's Git blob, never the worktree, and measures --installed or --commit. Exit 0 means a logged release match inside the --pin prefix, never a security PASS; without --pin a match is logged_unpinned, not owner-approved, and exits 3. Not logged exits 3, or 4 when the version is logged with another measurement; a tampered log exits 4 and an unreadable log 3.
intel-refresh is the only command that contacts CISA KEV and JVN; it GETs fixed public feed URLs only, sends nothing from any target, and appends one attempt per feed to the store. JVN iPedia (JVNDB) is recorded but not parsed. Exit 0 means the attempts were recorded, including failed ones.
intel-match matches CVE IDs of a saved report or import record against the stored feeds offline and saves JSON, HTML, text and SARIF bound to the exact input bytes. The gate and the input are unchanged; KEV listing never changes the exit code. No freshness limit applies unless --max-age-hours is given; --require-fresh needs --max-age-hours and exits 3 unless KEV and the JVN RSS are both usable and fresh. JVNDB is shown as a status only and never decides the exit code. The JVN feed is a recent-update window, never the full database.
release-log-check requires the base log to be a byte prefix of the head log, a valid chain, one measurement per version, one entry per source commit and every entry reproducible from its source commit. Dependencies are lockfile-bound and not measured; there is no witness and the log is not an authenticated history.
`;
type AdmittedTool = 'git' | 'gitleaks' | 'osv' | 'trivy';
const scanTools = ['git', 'gitleaks', 'osv'] as const, planTools = ['git', 'gitleaks'] as const;
function toolSubjects(config: Config, names: readonly AdmittedTool[]): ProvenanceSubject[] {
  return names.flatMap(component => {
    const tool = config.tools[component];
    return tool ? [{ component, sha256: tool.sha256, file: tool.path }] : [];
  });
}
const localScanSubjects = (config: Config) => toolSubjects(config, [...scanTools, ...(config.tools.trivy ? ['trivy' as const] : [])]);
function runnerSubjects(config: Config): ProvenanceSubject[] {
  const runner = config.runner;
  return [...(runner ? [{ component: 'codex-cli' as const, sha256: runner.codex.sha256, file: runner.codex.path }, { component: 'codex-cli' as const, sha256: runner.linuxCodex.sha256, file: runner.linuxCodex.path },
    { component: 'docker' as const, sha256: runner.docker.sha256, file: runner.docker.path }, { component: 'linux-image' as const, sha256: runner.image.slice('sha256:'.length), file: null }] : []),
    ...toolSubjects(config, ['gitleaks'])];
}
const readerSubjects = (config: Config) => toolSubjects(config, ['gitleaks']);
function ghSubjects(config: Config): ProvenanceSubject[] {
  if (config.schema !== 2 || config.runtimePolicy.schema !== 'scanmux.runtime-policy/v2') return [];
  const { verifier } = config.runtimePolicy.provenance;
  return [{ component: 'gh', sha256: verifier.sha256, file: verifier.path }];
}
const runtimeSubjects: Readonly<Record<string, (config: Config) => ProvenanceSubject[]>> = Object.freeze({
  doctor: localScanSubjects, plan: config => toolSubjects(config, planTools), scan: localScanSubjects,
  deps: config => toolSubjects(config, scanTools), import: config => toolSubjects(config, planTools),
  resume: localScanSubjects, 'plan-list': config => toolSubjects(config, planTools), 'scan-list': config => toolSubjects(config, scanTools),
  'ai-plan': config => [...toolSubjects(config, planTools), ...aiSubjects(config)], 'ai-scan': config => [...toolSubjects(config, scanTools), ...aiSubjects(config)],
  'runner-check': runnerSubjects,
  'job-export': readerSubjects, 'job-recover': readerSubjects, recover: readerSubjects, history: readerSubjects,
  'ci-check': readerSubjects, 'policy-check': readerSubjects, dispositions: readerSubjects,
  'ci-github': config => [...ghSubjects(config), ...readerSubjects(config)],
  'intel-match': readerSubjects,
  'release-record': config => toolSubjects(config, ['git']), 'release-verify': config => toolSubjects(config, ['git']), 'release-log-check': config => toolSubjects(config, ['git']),
});
// A v1 runtime policy cannot name the helper, so only v2 decides on it.
function processOwnerSubjects(config: Config): ProvenanceSubject[] {
  const helper = config.tools['windows-process-owner'];
  return process.platform === 'win32' && helper && config.schema === 2 && config.runtimePolicy.schema === 'scanmux.runtime-policy/v2'
    ? [{ component: 'windows-process-owner', sha256: helper.sha256, file: helper.path }] : [];
}
function startsProcesses(command: string, config: Config): boolean {
  if (command === 'doctor') return Boolean(config.tools.git || config.tools.gitleaks || config.tools.osv || config.tools.trivy);
  if (command === 'runner-check') return Boolean(config.tools.gitleaks);
  return true;
}
async function withConfig<T>(command: string, file: string | undefined, signal: AbortSignal, root: string | undefined, body: (config: Config) => Promise<T>): Promise<T> {
  const admitted = Object.hasOwn(runtimeSubjects, command);
  const config = await loadConfig(file, root, { runtimePolicy: admitted ? 'accept' : 'reject' });
  if (config.tools.trivy && !['plan', 'scan', 'resume', 'doctor', 'history', 'recover', 'engine-record', 'engine-history'].includes(command)) throw new SafeError('trivy_entry_unsupported');
  const contained = startsProcesses(command, config);
  const subjects = () => [...runtimeSubjects[command](config), ...(contained ? processOwnerSubjects(config) : [])];
  const admission = {
    decide: () => { if (config.schema === 2) decideRuntime(config.runtimePolicy, subjects()); },
    verify: async () => { if (config.schema === 2) await admitRuntime(config.runtimePolicy, subjects(), { root, timeoutMs: config.timeoutMs, signal }); },
  };
  const singleScan = ['scan', 'ai-scan', 'resume'].includes(command);
  return withJobDisk(singleScan ? config.maxJobDiskBytes : undefined, () => withCopyBudget(config.maxCopyBytes, async () => {
    if (!contained) { await admission.verify(); return body(config); }
    return withProcessRuntime({ helper: config.tools['windows-process-owner'], timeoutMs: config.timeoutMs }, admission, () => body(config));
  }));
}
const releaseOnlyOptions = ['commit', 'expect-head', 'log-commit', 'installed', 'pin'] as const;
const releaseCommandOptions: Readonly<Record<string, { required: readonly string[]; optional: readonly string[] }>> = Object.freeze({
  'release-record': { required: ['commit', 'expect-head'], optional: [] },
  'release-verify': { required: ['log-commit'], optional: ['installed', 'commit', 'pin'] },
  'release-log-check': { required: ['base', 'head'], optional: [] },
});
const configuredSubjects = (config: Config) => [...localScanSubjects(config), ...aiSubjects(config), ...runnerSubjects(config)];
async function doctor(config: Config, workspace: string) {
  const tools: { engine: string; state: string }[] = [];
  for (const name of ['git', 'gitleaks', 'osv', 'codex-security'] as const) {
    const tool = config.tools[name];
    let state = tool ? 'configured_not_verified' : 'not_configured';
    if (tool && name !== 'codex-security') {
      try {
        const check = await execute(tool, [name === 'gitleaks' ? 'version' : '--version'], {
          cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes,
        });
        state = check.reason === 'exit' && check.code === 0 && check.stdout.toString().includes(tool.version) ? 'verified' : 'version_or_execution_failure';
      } catch { state = 'digest_or_path_failure'; }
    }
    tools.push({ engine: name, state });
  }
  if (config.tools.trivy) {
    const cleanup = sourceCleanupFor(workspace);
    const snapshot = await cleanup.directory(workspace, 'trivy-probe-snapshot-');
    const plan = { schema: 'scanmux.plan/v2' as const, root: snapshot, required: [...legacyEngines] } as import('./model.ts').Plan;
    let run;
    try { run = await probeTrivy({ plan, config, workspace, snapshot, signal: new AbortController().signal, secretsCleared: false }); }
    finally { await cleanup.cleanup(workspace, [snapshot]); }
    if (sourceCleanupFailed()) throw new SafeError('source_cleanup_failed');
    tools.push({ engine: 'trivy', state: run.execution === 'completed' ? 'verified' : run.execution === 'not_started' ? 'unsupported' : 'version_or_execution_failure' });
  }
  return {
    schema: 'scanmux.doctor/v1', platform: process.platform, node: process.version,
    tools, capabilities: [...createAdapters(), ...(config.tools.trivy ? [new TrivyAdapter()] : [])].map(a => a.capabilities()),
    runnerDiagnostic: { configured: config.runner !== null, state: 'not_checked', command: 'runner-check', inference: false },
    authentication: { requested: 'chatgpt', provider: 'openai', apiProject: null,
      ambientApiKeyPresent: Boolean(process.env.OPENAI_API_KEY || process.env.CODEX_API_KEY), ambientKeysIgnored: true,
      runnerLogin: 'unverified', modelRequested: 'gpt-6-sol', modelActual: 'unknown',
      accessProgramRequested: 'daybreak_blue', accessProgramEffective: 'unknown', allowance: 'unknown',
    },
    blockers: ['ai_isolation_unverified', 'linux_runner_unverified', ...(config.osvDatabase ? [] : ['offline_database_not_configured'])],
    output: { privateDirectoryVerified: true, secretCheckConfigured: Boolean(config.tools.gitleaks) },
    state: 'INCOMPLETE',
  };
}
export async function main(argv: string[], dependencies?: { ai?: SyntheticAiRuntime }): Promise<number> {
  const cleanup = new SourceCleanupOwner();
  const invocation: { command?: string } = {};
  return withSourceCleanup(cleanup, async () => {
    let code = 4;
    try { code = await runMain(argv, dependencies, invocation); }
    finally {
      await cleanup.cleanup();
      if (sourceCleanupFailed()) {
        code = invocation.command === 'deps' ? 2 : 4;
        process.stderr.write(JSON.stringify({ ...JSON.parse(staticError('source_cleanup_failed')), exitCode: code }) + '\n');
      }
    }
    return code;
  });
}
async function runMain(argv: string[], dependencies: { ai?: SyntheticAiRuntime } | undefined, invocation: { command?: string }): Promise<number> {
  const commandStarted = performance.now();
  const abort = new AbortController();
  const stop = () => abort.abort();
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let command: string | undefined;
  try {
    if (argv.length === 1 && argv[0] === '--version') { process.stdout.write(packageVersion + '\n'); return 0; }
    const options = {
      config: { type: 'string' }, json: { type: 'boolean' }, help: { type: 'boolean' }, 'site-origin': { type: 'string' },
      base: { type: 'string' }, head: { type: 'string' },
      'ci-run': { type: 'string' }, 'ci-job': { type: 'string' },
      'ci-report': { type: 'string', multiple: true },
      from: { type: 'string' },
      finding: { type: 'string' }, test: { type: 'string' }, required: { type: 'boolean' },
      decisions: { type: 'string' },
      'accept-plan': { type: 'string' },
      'report-language': { type: 'string' },
      'job-profile': { type: 'string' },
      'host-job-profile': { type: 'string' },
      'scanned-commit': { type: 'string' },
      repo: { type: 'string' }, run: { type: 'string' }, attempt: { type: 'string' }, 'from-dir': { type: 'string' },
      commit: { type: 'string' }, 'expect-head': { type: 'string' }, 'log-commit': { type: 'string' }, installed: { type: 'string' }, pin: { type: 'string' },
      store: { type: 'string' }, 'max-age-hours': { type: 'string' }, 'require-fresh': { type: 'boolean' },
    } as const;
    command = parseArgs({ args: argv, allowPositionals: true, options, strict: false }).positionals[0];
    invocation.command = command;
    const { positionals, values } = parseArgs({ args: argv, allowPositionals: true, options });
    if (values.help || !positionals.length) { process.stdout.write(help); return 0; }
    const target = positionals[1];
    command = positionals[0];
    if (!['doctor', 'plan', 'scan', 'deps', 'import', 'ai-plan', 'ai-scan', 'plan-list', 'scan-list', 'serve', 'runner-check', 'ci-check', 'history', 'recover', 'resume', 'dispositions', 'policy-check', 'job-scan', 'reproduce', 'host-job-scan', 'job-export', 'job-recover', 'engine-record', 'engine-history', 'ci-github', 'release-record', 'release-verify', 'release-log-check', 'intel-refresh', 'intel-match'].includes(command)
      || (['ci-check', 'history'].includes(command) ? positionals.length < 2 : command === 'import' ? positionals.length < 3 : positionals.length !== (['doctor', 'serve', 'runner-check', 'engine-history', 'ci-github', 'intel-refresh'].includes(command) ? 1 : 2))) throw new SafeError('invalid_command');
    if ((command === 'ci-github') !== (values.repo !== undefined && values.run !== undefined && values.attempt !== undefined)
      || (command !== 'ci-github' && values['from-dir'] !== undefined)) throw new SafeError('invalid_command');
    if (command === 'ci-github' && !values.config) throw new SafeError('ci_github_config_required');
    if (['engine-record', 'engine-history'].includes(command) && !values.config) throw new SafeError('engine_ledger_config_required');
    if (command === 'reproduce') {
      const allowed = ['job-profile', 'from', 'finding', 'test', 'required', 'base', 'head', 'json'];
      if (Object.keys(values).some(key => !allowed.includes(key)) || ['job-profile', 'from', 'finding', 'test'].some(key => values[key as keyof typeof values] === undefined)) throw new SafeError('invalid_command');
    } else if (values.finding !== undefined || values.test !== undefined || values.required !== undefined) throw new SafeError('invalid_command');
    if (values['job-profile'] !== undefined && !['job-scan', 'reproduce'].includes(command)) throw new SafeError('invalid_command');
    if (values['host-job-profile'] !== undefined && command !== 'host-job-scan') throw new SafeError('invalid_command');
    if (command === 'host-job-scan' && values['host-job-profile'] === undefined) throw new SafeError('host_job_profile_required');
    if (command === 'job-scan' && values['job-profile'] === undefined) throw new SafeError('job_profile_required');
    if (['job-scan', 'host-job-scan'].includes(command) && (values.config !== undefined || values['report-language'] !== undefined)) throw new SafeError('invalid_command');
    if (['job-export', 'job-recover'].includes(command) && !values.config) throw new SafeError('job_reader_config_required');
    if (values['site-origin'] !== undefined && command !== 'serve') throw new SafeError('invalid_command');
    if (command.startsWith('intel-') !== (values.store !== undefined) || (command === 'intel-refresh' && values.config !== undefined)
      || (command !== 'intel-match' && (values['max-age-hours'] !== undefined || values['require-fresh'] !== undefined))
      || (values['require-fresh'] === true && values['max-age-hours'] === undefined)) throw new SafeError('invalid_command');
    if (command === 'intel-match' && !values.config) throw new SafeError('intel_config_required');
    const release = command.startsWith('release-');
    if (release && !values.config) throw new SafeError('release_config_required');
    const releaseOptions = release ? releaseCommandOptions[command] : { required: [], optional: [] };
    if (releaseOnlyOptions.some(name => values[name] !== undefined && ![...releaseOptions.required, ...releaseOptions.optional].includes(name))
      || releaseOptions.required.some(name => values[name as keyof typeof values] === undefined)
      || (command === 'release-verify' && (values.installed === undefined) === (values.commit === undefined))) throw new SafeError('invalid_command');
    if (command === 'deps' && !values.config) throw new SafeError('deps_config_required');
    if (command === 'import' && !values.config) throw new SafeError('import_config_required');
    if (values['scanned-commit'] !== undefined && command !== 'import') throw new SafeError('invalid_command');
    if ((values.base !== undefined || values.head !== undefined) && !['plan', 'scan', 'deps', 'resume', 'ai-plan', 'ai-scan', 'job-scan', 'reproduce', 'host-job-scan', 'release-log-check'].includes(command)) throw new SafeError('invalid_command');
    if ((command === 'ai-scan') !== (values['accept-plan'] !== undefined)) throw new SafeError('invalid_command');
    if (['ai-plan', 'ai-scan'].includes(command) && !values.config) throw new SafeError('ai_config_required');
    if ((values['ci-run'] !== undefined || values['ci-job'] !== undefined) && !['scan', 'ai-scan'].includes(command)) throw new SafeError('invalid_command');
    if (values['ci-report'] !== undefined && command !== 'ci-check') throw new SafeError('invalid_command');
    if (['resume', 'reproduce'].includes(command) !== (values.from !== undefined)) throw new SafeError('invalid_command');
    if (values.decisions !== undefined && !['dispositions', 'policy-check'].includes(command)) throw new SafeError('invalid_command');
    if (command === 'policy-check' && values.decisions === undefined) throw new SafeError('invalid_command');
    if (values['report-language'] !== undefined && !['scan', 'ai-scan', 'resume', 'scan-list', 'recover', 'job-export', 'job-recover', 'intel-match'].includes(command)) throw new SafeError('invalid_command');
    const reportLanguage = parseReportLanguage(values['report-language']);
    const ci = ciArguments(values['ci-run'], values['ci-job']);
    const comparison = command === 'release-log-check' ? undefined : commitPair(values.base, values.head);
    if (command === 'reproduce') {
      const match = /^(gitleaks|osv|codex-security|runtime-advisories):([a-f0-9]{64})$/.exec(values.finding!);
      if (!match) throw new SafeError('invalid_reproduction_selection');
      const result = await verifyFinding(target, path.resolve(values['job-profile']!), { reportPath: path.resolve(values.from!),
        finding: { engine: match[1] as Engine, fingerprint: match[2] }, testDirectory: values.test!,
        mode: comparison ? { kind: 'before_after', ...comparison } : { kind: 'snapshot', requirement: values.required ? 'required' : 'supporting' } }, abort.signal);
      if (values.json) process.stdout.write(await readFile(result.files.json));
      else process.stdout.write(`ScanMux reproduction: ${result.verification.kind}; source report snapshot: ${result.assessment.gate} (exit ${result.assessment.exitCode}).\n`
        + (result.verification.kind === 'same_test_no_longer_reproduces' ? result.verification.statement + '\n' : '')
        + `JSON: ${result.files.json}\nHTML: ${result.files.html}\nSARIF: ${result.files.sarif}\n`);
      return result.assessment.exitCode;
    }
    if (command === 'intel-refresh') {
      const attempts = await refreshIntel(values.store);
      if (values.json) process.stdout.write(JSON.stringify({ schema: 'scanmux.intel-refresh/v1', attempts }, null, 2) + '\n');
      else {
        process.stdout.write('ScanMux intel refresh: one attempt per feed recorded. Only fixed public feed URLs were fetched; nothing from any target was sent.\n');
        for (const { feed, outcome, completedAt } of attempts) process.stdout.write(`${feed}: ${outcome.kind}; http=${outcome.httpStatus ?? 'none'}${outcome.kind === 'failed' ? `; reason=${outcome.reason}` : ''}${outcome.kind === 'stored' ? `; bytes=${outcome.bytes}; version=${outcome.source.version ?? 'none'}` : ''}; at=${completedAt}\n`);
      }
      return 0;
    }
    if (command === 'intel-match') {
      const maxAgeMs = parseMaxAgeHours(values['max-age-hours']);
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const matched = await matchIntelFiles(target, values.store!, values.config, config, { maxAgeMs, requireFresh: values['require-fresh'] === true, language: reportLanguage });
        if (values.json) process.stdout.write(matched.json);
        else process.stdout.write(`${matched.text}JSON: ${matched.destination}\nHTML: ${matched.htmlDestination}\nText: ${matched.textDestination}\nSARIF: ${matched.sarifDestination}\n`);
        return matched.exitCode;
      });
    }
    if (release) {
      const root = await canonical(target);
      return await withConfig(command, values.config, abort.signal, root, async config => {
        const workspace = await privateWorkspace([root, ...releaseCommandTarget(values.installed)], { disposable: true });
        const cleanup = sourceCleanupFor(workspace); cleanup.register(workspace, workspace);
        try {
          const repo = await openRepository(root, config, workspace, abort.signal);
          const result = command === 'release-record' ? await releaseRecord(repo, { commit: values.commit!, expectHead: values['expect-head']! })
            : command === 'release-verify' ? await releaseVerify(repo, { logCommit: values['log-commit']!, installed: values.installed, commit: values.commit, pin: values.pin })
              : await releaseLogCheck(repo, { base: values.base!, head: values.head! });
          const output = values.json ? await checkedJson(result.payload, config, workspace) : await checkedText(result.text, config, workspace);
          await cleanup.cleanup(workspace);
          if (sourceCleanupFailed()) throw new SafeError('source_cleanup_failed');
          process.stdout.write(output);
          return result.exitCode;
        } finally { await cleanup.cleanup(workspace); }
      });
    }
    if (command === 'host-job-scan') {
      const result = await scanHostJob(target, values['host-job-profile']!, abort.signal, comparison);
      if (values.json) process.stdout.write(result.json);
      else process.stdout.write(`ScanMux Windows-owned offline job: ${result.job.gate} (exit ${result.job.exitCode}); job=${result.job.jobId}.\nWindows CPU/committed-memory and Linux limits are separate. Trusted owner/admission, physical retained storage and total command time are excluded.\nSaved host job: ${result.destination}\nUse job-export for the selected retained analysis.\n`);
      return result.job.exitCode;
    }
    if (command === 'job-scan') {
      const result = await scanJob(target, values['job-profile']!, abort.signal, comparison);
      if (values.json) {
        process.stdout.write(result.json);
        if (result.job.origin) process.stderr.write(`Saved job: ${result.destination}\n`);
      }
      else {
        process.stdout.write(`ScanMux bounded offline job: ${result.job.gate} (exit ${result.job.exitCode}); job=${result.job.jobId}.\n`);
        process.stdout.write('Limits apply to the Linux payload and durable-record ACK admission. Host control-plane CPU/memory, retained physical storage and whole-command time are not guaranteed.\n');
        if (result.job.origin) process.stdout.write(`Saved job: ${result.destination}\nUse job-export to view actual retained analysis.\n`);
        else process.stdout.write('No plan was accepted; private metadata was retained without fabricating analysis.\n');
      }
      return result.job.exitCode;
    }
    if (command === 'engine-record') {
      const config = await loadConfig(values.config, undefined, { runtimePolicy: 'accept' });
      let result;
      try { result = await recordEngine(target, config, { timeoutMs: config.timeoutMs, signal: abort.signal }); }
      catch (error) {
        if (!values.json && error instanceof EngineLedgerUnpinnedTailError) {
          const { ledger } = error;
          process.stderr.write(`ScanMux engine record: refused; the ledger has ${ledger.unpinned.length} valid lines after the pin and was not changed. Check them, then paste a ledger pin yourself.\n`);
          for (const line of ledger.unpinned) process.stderr.write(`Unpinned line: seq=${line.seq} component=${line.component} sha256=${line.sha256} change=${line.change}\n`);
          process.stderr.write(`Whole ledger: entries=${ledger.entries} head=${ledger.head}\n`);
        }
        throw error;
      }
      if (values.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      else {
        const { tool, ledger } = result.paste;
        process.stdout.write(`ScanMux engine record: ${result.state} seq=${result.seq}.\nTool pin: path=${tool.path} sha256=${tool.sha256} version=${tool.version}\nLedger pin: path=${ledger.path} entries=${ledger.entries} head=${ledger.head}\n`);
        process.stdout.write('This ledger is tamper-evident only against the pinned config; it is not an authenticated history.\n');
      }
      return 0;
    }
    if (command === 'engine-history') {
      const config = await loadConfig(values.config, undefined, { runtimePolicy: 'accept' });
      const history = await engineHistory(config, configuredSubjects(config));
      if (values.json) process.stdout.write(JSON.stringify(history, null, 2) + '\n');
      else {
        process.stdout.write(`ScanMux engine history: ${history.entries.length} pinned entries. Reading completed, not a security decision; not an authenticated history.\n`);
        for (const entry of history.entries) process.stdout.write(`${entry.seq}: ${entry.component} ${entry.platform} ${entry.version} sha256=${entry.sha256} evidence=${entry.evidence} recordedAt=${entry.recordedAt} status=${entry.status} change=${entry.change}\n`);
      }
      return 0;
    }
    if (command === 'job-export' || command === 'job-recover') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const viewed = command === 'job-export'
          ? path.basename(target) === 'host-job.json' ? await exportHostJob(target, values.config!, config, reportLanguage) : await exportJob(target, values.config!, config, reportLanguage)
          : await isHostJobRecovery(target) ? await recoverHostJob(target, values.config!, config, reportLanguage) : await recoverJob(target, values.config!, config, reportLanguage);
        if (values.json) process.stdout.write(viewed.json);
        else process.stdout.write(`ScanMux saved job: recorded=${viewed.job.gate}; analysis=${viewed.report.gate}${viewed.job.analysis?.kind === 'checkpoint' ? ' (provisional; completion unverified)' : ''}. Current ownership and metadata durability are not authenticated by saved bytes.\nJSON: ${viewed.destination}\nHTML: ${viewed.htmlDestination}\n`);
        return viewed.job.exitCode;
      });
    }
    if (command === 'recover') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const recovered = await recoverEngineCheckpoints(target, values.config, config);
        const workspace = await privateWorkspace(recovered.root);
        const bundle = await saveReportBundle(recovered.report, config, workspace, undefined, undefined, reportLanguage);
        if (values.json) process.stdout.write(bundle.json);
        else process.stdout.write(`ScanMux recovered checkpoint ${recovered.sequence}: ERROR (exit 4); controller completion and process termination are unverified.\nJSON: ${bundle.destination}\nHTML: ${bundle.htmlDestination}\n`);
        if (recovered.ignoredTail) process.stderr.write('ScanMux: uncommitted checkpoint tail ignored; it is not accepted as engine evidence.\n');
        return 4;
      });
    }
    if (command === 'policy-check') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const checked = await checkPolicyFiles(target, values.decisions!, values.config, config);
        if (values.json) process.stdout.write(checked.json);
        else {
          const summary = checked.summary;
          process.stdout.write(`ScanMux saved-report policy: ${summary.gate} (exit ${summary.exitCode}); original=${summary.original.recordedGate}; applied exceptions=${summary.counts.applied}.\n`);
          process.stdout.write(`Reasons: ${summary.reasons.join(',') || 'none'}. Original scan and CI records are unchanged; current repository state and reviewer identity are not authenticated.\nJSON: ${checked.destination}\n`);
        }
        return checked.summary.exitCode;
      });
    }
    if (command === 'dispositions') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const assessed = await readDispositions(target, values.decisions, values.config, config);
        if (values.json) process.stdout.write(assessed.json);
        else {
          const counts = assessed.summary.counts, original = assessed.summary.original;
          process.stdout.write(`ScanMux saved judgments: current=${counts.current}; expired=${counts.expired}; reconfirmation=${counts.reconfirmationRequired}; open=${counts.open}.\n`);
          process.stdout.write(`Recorded decision: ${original.recordedGate}; completion=${original.completion}. Reading and saving completed; no security decision or gate change.\nJSON: ${assessed.destination}\n`);
        }
        return 0;
      });
    }
    if (command === 'history') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const viewed = await readHistoryFiles(positionals.slice(1), values.config, config);
        if (values.json) process.stdout.write(viewed.json);
        else {
          process.stdout.write(`ScanMux history: ${viewed.summary.runs.length} saved runs; ${viewed.summary.duplicateInputs} duplicate inputs ignored. Reading completed, not a security decision.\n`);
          for (const run of viewed.summary.runs) process.stdout.write(`${run.runId}: commit=${run.commit ?? 'unknown'} recorded=${run.recordedGate}; completion=${run.completion}; recorded calls=${run.reportedCalls}; missing engine records=${run.missingEngineRecords}; reasons=${run.reasons.join(',') || 'none'}\n`);
          process.stdout.write(`Recorded calls in selected unique runs: ${viewed.summary.reportedCalls}; missing engine records: ${viewed.summary.missingEngineRecords}; cost: ${viewed.summary.costKind}; account usage/allowance: unknown.\nJSON: ${viewed.destination}\n`);
        }
        return 0;
      });
    }
    if (command === 'ci-check') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const checked = await checkCiFiles(target, positionals.slice(2), values.config, config, values['ci-report']);
        if (values.json) process.stdout.write(checked.json);
        else {
          process.stdout.write(checked.summary);
          process.stdout.write(`JSON: ${checked.destination}\n`);
        }
        return checked.result.exitCode;
      });
    }
    if (command === 'ci-github') {
      const request = parseGithubRequest(values.repo, values.run, values.attempt);
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const verified = await verifyGithubRun(request, values['from-dir'], config, abort.signal);
        const { result } = verified;
        if (values.json) process.stdout.write(verified.json);
        else {
          process.stdout.write(`ScanMux GitHub run ${result.runId} attempt ${result.attempt}: ${result.gate} (exit ${result.exitCode}); outcome=${result.outcome}; reason=${result.reason ?? 'none'}; scenario=${result.scenario ?? 'unknown'}${result.notes.length ? '; ' + result.notes.join(',') : ''}.
`);
          process.stdout.write(`Checks: ${result.checks.map(item => `${item.check}=${item.state}`).join(' ')}
Source checks job, reported by the source run and not verified: ${result.sourceChecks.conclusion}
JSON: ${verified.destination}
`);
          if (verified.deliveryDirectory) process.stdout.write(`Delivery copy: ${verified.deliveryDirectory}
`);
        }
        return result.exitCode;
      });
    }
    if (command === 'plan-list' || command === 'scan-list') {
      return await withConfig(command, values.config, abort.signal, undefined, async config => {
        const prepared = await prepareBatch(target, values.config, config);
        const batch = await executeBatch(prepared, config, command === 'plan-list' ? 'plan' : 'scan', abort.signal, reportLanguage);
        if (values.json) process.stdout.write(batch.json);
        else {
          process.stdout.write(`ScanMux ${batch.summary.mode}: ${batch.summary.mode === 'plan' ? (batch.summary.planningComplete ? 'planning completed' : 'planning incomplete') : batch.summary.gate} (exit ${batch.summary.exitCode})\n`);
          for (const job of batch.summary.jobs) process.stdout.write(`${job.id}: ${job.state}; ${job.gate ?? (job.planningComplete ? 'planned, not scanned' : 'not planned')}; reasons=${job.errors.join(',') || 'none'}\n`);
          process.stdout.write(`JSON: ${batch.destination}\n`);
        }
        return batch.summary.exitCode;
      });
    }
    const root = target ? await canonical(target) : undefined;
    return await withConfig(command, values.config, abort.signal, root, async config => {
      if (ci && config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
      const aiCommand = command === 'ai-plan' || command === 'ai-scan', aiExpiresAt = commandStarted + config.timeoutMs;
      if (aiCommand && performance.now() >= aiExpiresAt) throw new SafeError('ai_stopped');
      const executionSignal = aiCommand ? AbortSignal.any([abort.signal, AbortSignal.timeout(Math.max(1, Math.ceil(aiExpiresAt - performance.now())))]) : abort.signal;
      if (command === 'serve') {
        const web = await startWeb(config, undefined, { siteOrigin: values['site-origin'] });
        process.stdout.write(`ScanMux: open this private local session URL in your browser:\n${web.url}\nKeep this URL private. Press Ctrl+C to stop.\n`);
        await Promise.race([web.closed, new Promise<void>(resolve => { if (abort.signal.aborted) resolve(); else abort.signal.addEventListener('abort', () => resolve(), { once: true }); })]);
        const stopped = await web.close();
        if (stopped.retained) process.stderr.write('ScanMux: process termination or source cleanup is unverified; the private workspace was retained.\n');
        return stopped.retained || sourceCleanupFailed() ? 4 : 0;
      }
      const resuming = command === 'resume' ? await readResumeSource(values.from!, root!, config) : undefined;
      const disposable = ['deps', 'doctor', 'runner-check', 'plan', 'ai-plan'].some(name => name === command);
      const workspace = await privateWorkspace(root, { disposable });
      if (disposable) sourceCleanupFor(workspace).register(workspace, workspace);
      if (command === 'deps') {
        const report = await analyzeDependencies(root!, config, workspace, executionSignal, comparison);
        process.stdout.write(values.json ? await checkedJson(report, config, workspace) : await checkedText(dependencyText(report), config, workspace));
        return report.exitCode;
      }
      if (command === 'import') {
        const imported = await importResults({ root: root!, inputs: positionals.slice(2), scannedCommit: values['scanned-commit'] ?? null, workspace }, config, executionSignal);
        process.stdout.write(values.json ? imported.json : await checkedText(importText(imported.record, imported.destination), config, workspace));
        return imported.record.view.exitCode;
      }
      if (command === 'runner-check') {
        const { checkRunner } = await import('./runner-check.mjs');
        const state = await checkRunner(config, workspace, abort.signal);
        const output = config.tools.gitleaks ? await checkedJson(state, config, workspace) : JSON.stringify(state, null, 2) + '\n';
        process.stdout.write(output);
        return state.state === 'ERROR' ? 4 : 3;
      }
      if (command === 'doctor') {
        // All doctor fields are closed enums, booleans or runtime-owned strings; no target/config text is emitted.
        const state = await doctor(config, workspace);
        const output = config.tools.gitleaks ? await checkedJson(state, config, workspace) : JSON.stringify(state, null, 2) + '\n';
        process.stdout.write(output); return 3;
      }
      const offlinePlan = await buildPlan(root!, config, workspace, executionSignal, comparison);
      const plan = aiCommand ? buildAiPlan(offlinePlan, config) : offlinePlan;
      if (command === 'plan' || command === 'ai-plan') {
        const output = await checkedJson(plan, config, workspace);
        process.stdout.write(output);
        if (!values.json) process.stderr.write(`ScanMux plan: ${plan.files.length} files; ${plan.lockfiles.length} dependency inputs; ${plan.blockers.length} blockers; ${command === 'ai-plan' ? 'AI source disclosure only; not executed' : 'offline; AI not selected'}.\n`);
        if (!values.json && plan.destinations) process.stderr.write(destinationsText(plan.destinations));
        return plan.blockers.length ? 3 : 0;
      }
      if (resuming) {
        verifyResumePlan(resuming, plan);
        const notice = await checkedJson({ schema: 'scanmux.resume-plan/v1', operation: 'full_scan_new_run',
          previousRunId: resuming.previous.runId, previousRecordedCalls: resuming.previous.reportedCalls,
          previousMissingEngineRecords: resuming.previous.missingEngineRecords, previousCostKind: resuming.previous.costKind,
          newScanTimeoutMs: config.timeoutMs, additionalAiCallsPlanned: 0, additionalCostKind: 'not_applicable',
          automaticRetries: 0 }, config, workspace);
        process.stderr.write(notice);
      }
      let adapters;
      if (command === 'ai-scan') {
        verifyAiPlan(plan, config, values['accept-plan']!);
        const ai = createAiAdapter({ acceptedPlanHash: values['accept-plan']!, expiresAt: aiExpiresAt, runtime: dependencies?.ai });
        adapters = createAdapters().map(adapter => adapter.capabilities().engine === 'codex-security' ? ai : adapter);
      }
      const report = await scan(plan, config, workspace, executionSignal, adapters, undefined, scopedCopyBudget(), scopedJobDisk());
      const bundle = await saveReportBundle(report, config, workspace, undefined, undefined, reportLanguage);
      let resumed;
      if (resuming) {
        try { resumed = await saveResumeReceipt(resuming, bundle, config, workspace); }
        catch {
          // The bundle and its paths already passed the output secret check. Never repeat the scan here.
          process.stderr.write(`ScanMux: scan already ran; resume record could not be saved. Run: ${bundle.report.runId}; JSON: ${bundle.destination}\n`);
          throw new SafeError('resume_record_save_failed');
        }
      }
      let receipt;
      if (ci) {
        try { receipt = await saveCiReceipt(bundle, ci.ciRun, ci.jobId, config, workspace); }
        catch {
          process.stderr.write(`ScanMux: scan already ran; CI receipt could not be saved. Run: ${bundle.report.runId}; JSON: ${bundle.destination}\n`);
          throw new SafeError('ci_receipt_save_failed');
        }
      }
      if (values.json) process.stdout.write(bundle.json);
      else {
        process.stdout.write(`ScanMux: ${report.gate} (exit ${report.exitCode})\n`);
        for (const run of report.engines) process.stdout.write(`${run.engine}: ${run.execution}, ${run.coverage}, findings=${run.findings.length}, reasons=${run.errors.join(',') || 'none'}\n`);
        for (const run of report.engines) if (run.engine === 'trivy') process.stdout.write(trivyCoverageText(run, reportLanguage) + '\n');
        for (const run of report.engines) if (run.aiExecution) {
          const ai = run.aiExecution;
          process.stdout.write(`AI evidence=${ai.classification}; submit invocations=${ai.submitInvocations}; connection attempts=${ai.connectionAttempts}; send attempts=${ai.sendInvocations}; observed tokens=${ai.tokens.kind === 'unknown' ? 'unknown' : ai.tokens.observed.totalTokens + ' (' + ai.tokens.kind + ')'}; cost=N/A; account allowance=unknown; effective program=${run.accessProgramEffective ?? 'unknown'}.\n`);
        }
        for (const run of report.engines) if (run.advisoryDetails) process.stdout.write(advisoryText(run.advisoryDetails));
        if (report.plan.destinations) process.stdout.write(destinationsText(report.plan.destinations));
        process.stdout.write(`HTML: ${bundle.htmlDestination}\nJSON: ${bundle.destination}\n`);
        for (const [index, part] of bundle.sarif.entries()) process.stdout.write(`SARIF (${index + 1}/${bundle.sarif.length}, findings=${part.findings}/${report.engines.reduce((count, run) => count + run.findings.length, 0)}): ${part.destination}\n`);
      }
      if (receipt) (values.json ? process.stderr : process.stdout).write(`CI receipt: ${receipt.destination}\n`);
      if (resumed) (values.json ? process.stderr : process.stdout).write(`Resume record: ${resumed.destination}\n`);
      return report.exitCode;
    });
  } catch (error) {
    if (command === 'deps') {
      process.stderr.write(JSON.stringify({ schema: 'scanmux.error/v1', exitCode: 2,
        error: error instanceof SafeError ? error.code : 'invalid_input_or_io_failure' }) + '\n');
      return 2;
    }
    if (error instanceof JobDiskCopyLimitError || error instanceof SafeError && error.code === 'job_disk_measured_limit') {
      process.stderr.write(JSON.stringify({ schema: 'scanmux.error/v1', gate: 'INCOMPLETE', exitCode: 3, error: error.code }) + '\n');
      return 3;
    }
    const policy = error instanceof RuntimePolicyRefusalError || error instanceof ProvenanceRefusalError ? error.policy : undefined;
    const engine = error instanceof ProvenanceRefusalError ? error.engine : undefined;
    const ledger = error instanceof EngineLedgerUnpinnedTailError ? error.ledger : undefined;
    process.stderr.write(staticError(error instanceof SafeError ? error.code : 'invalid_input_or_io_failure', policy, engine, ledger) + '\n'); return 4;
  } finally { process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop); }
}
