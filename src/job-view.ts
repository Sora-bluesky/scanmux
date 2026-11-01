import path from 'node:path';
import { lstat, mkdir, open } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import type { Config, Report } from './model.ts';
import { loadConfig } from './config.ts';
import { privateWorkspace } from './private-storage.ts';
import { checkedText } from './output.ts';
import { renderHtmlReport } from './html-report.ts';
import { renderSarifReports } from './sarif-report.ts';
import { parseReportLanguage, type ReportLanguage } from './report-language.ts';
import { readEngineCheckpoints, validateCheckpointPair, type VerifiedCheckpointPair } from './engine-checkpoint.ts';
import { regularJobFile } from './job-config.ts';
import { jobOutcome, jobReference, parseJobJson, readJobRegular, validateJobFinalReport, validateJobPlan, validateJobReport,
  type JobPlan, type JobReport, type JobFileReference, type JobClosure } from './job-records.ts';
import { canonical, hash, outside, SafeError } from './safety.ts';

const encode = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');
const requireValue = (value: unknown): void => { if (!value) throw new SafeError('invalid_job_record'); };
interface SavedFile { name: string; bytes: Buffer }
function checkReference(bytes: Buffer, reference: JobFileReference) { requireValue(isDeepStrictEqual(jobReference(bytes), reference)); }

export async function fixedPrefix(directory: string, sequence: number, maximum: number, job: JobPlan) {
  let previous: VerifiedCheckpointPair | null = null;
  const files: SavedFile[] = [];
  for (let slot = 1; slot <= sequence; slot++) {
    const bodyName = `checkpoints/checkpoint-${slot}.json`, receiptName = `checkpoints/commit-${slot}.json`;
    const body = await readJobRegular(path.join(directory, ...bodyName.split('/')), maximum);
    const receipt = await readJobRegular(path.join(directory, ...receiptName.split('/')), maximum);
    previous = validateCheckpointPair(body, receipt, slot, previous);
    requireValue(isDeepStrictEqual(previous.checkpoint.report.plan, job.plan));
    files.push({ name: bodyName, bytes: body }, { name: receiptName, bytes: receipt });
  }
  return { pair: previous, files };
}

async function nativeReader(directory: string, job: JobPlan, configPath: string, config: Config) {
  const root = await canonical(job.origin.root);
  requireValue(root === job.origin.root && (await lstat(root)).isDirectory() && hash(root) === job.origin.repoId);
  await outside(directory, root);
  await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
  if (!config.tools.gitleaks) throw new SafeError('output_secret_check_unavailable');
  await regularJobFile(config.tools.gitleaks.path, root);
  return root;
}

export async function readSavedJobRecord(input: string, maximum: number, metadataName: 'job.json' | 'delegated-job.json' = 'job.json') {
  if (!['job.json', 'delegated-job.json'].includes(metadataName) || !path.isAbsolute(input) || path.basename(input) !== metadataName) throw new SafeError('invalid_job_input');
  const file = await canonical(input), directory = await canonical(path.dirname(file));
  const raw = await readJobRegular(file, maximum), job = validateJobReport(parseJobJson(raw));
  if (!job.plan || !job.analysis) throw new SafeError('job_analysis_unavailable');
  const planBytes = await readJobRegular(path.join(directory, 'job-plan.json'), maximum);
  checkReference(planBytes, job.plan);
  const plan = validateJobPlan(parseJobJson(planBytes));
  requireValue(plan.jobId === job.jobId && plan.profileSha256 === job.profileSha256 && plan.origin.repoId === job.originDigest
    && isDeepStrictEqual(plan.origin, job.origin) && plan.mappedRoot === job.mappedRoot && isDeepStrictEqual(plan.limits, job.resources.requested));
  const root = plan.origin.root;
  const files: SavedFile[] = [{ name: 'job-plan.json', bytes: planBytes }];
  let report: Report, pair: VerifiedCheckpointPair | null = null;
  if (job.analysis.kind === 'checkpoint') {
    const prefix = await fixedPrefix(directory, job.analysis.sequence, maximum, plan);
    if (!prefix.pair) throw new SafeError('job_analysis_unavailable');
    checkReference(prefix.files.at(-2)!.bytes, job.analysis.body); checkReference(prefix.files.at(-1)!.bytes, job.analysis.receipt);
    pair = prefix.pair; report = pair.checkpoint.report; files.push(...prefix.files);
  } else {
    const checkpointDirectory = path.join(directory, 'checkpoints');
    const exists = await lstat(checkpointDirectory).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (exists) {
      const verified = await readEngineCheckpoints(checkpointDirectory, maximum);
      const prefix = await fixedPrefix(directory, verified.sequence, maximum, plan);
      requireValue(isDeepStrictEqual(prefix.pair?.checkpoint.report, verified.report)); pair = prefix.pair; files.push(...prefix.files);
    }
    const reportBytes = await readJobRegular(path.join(directory, 'report.json'), maximum);
    checkReference(reportBytes, { bytes: job.analysis.bytes, sha256: job.analysis.sha256 });
    report = validateJobFinalReport(reportBytes, plan, pair); files.push({ name: 'report.json', bytes: reportBytes });
  }
  const recorded = jobOutcome({ plan, report: job.analysis.kind === 'report' ? report : null, prefix: pair,
    stop: job.resources.stop, closure: job.closure, failures: job.knownFailures });
  requireValue(job.gate === recorded.gate && job.exitCode === recorded.exitCode);
  return { job, raw, plan, root, files, report, pair };
}

export async function readSavedJob(input: string, configPath: string, config: Config) {
  const saved = await readSavedJobRecord(input, config.maxOutputBytes);
  const root = await nativeReader(path.dirname(input), saved.plan, configPath, config);
  return { ...saved, root };
}

function escape(text: string) { return text.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!); }
export function renderJobHtml(report: Report, job: JobReport, language: ReportLanguage) {
  const heading = language === 'ja'
    ? `保存された実行判定: ${job.gate}。解析記録: ${report.gate}${job.analysis?.kind === 'checkpoint' ? '（途中保存・完了未確認）' : ''}。現在の終了状態や保存の耐久性を再認証した結果ではありません。`
    : `Recorded job outcome: ${job.gate}. Analysis record: ${report.gate}${job.analysis?.kind === 'checkpoint' ? ' (provisional; completion unverified)' : ''}. Saved records do not authenticate current termination or metadata durability.`;
  const scope = language === 'ja'
    ? '資源上限は当時のLinux検査処理と保存確認応答への入場に適用。ホスト制御面のCPU・メモリ上限、保持出力の物理容量、コマンド全体の時間保証はありません。この閲覧・出力処理は検査jobの外です。'
    : 'Limits cover the original Linux payload and durable-record ACK admission. Host control-plane CPU/memory, retained physical filesystem capacity, and total command duration are not guaranteed. This export runs outside the scan job.';
  const banner = `<aside role="note"><p>${escape(heading)}</p><p>${escape(scope)}</p><p>${language === 'ja' ? '元のホストパス' : 'Recorded host origin'}: <code>${escape(job.origin?.root ?? '')}</code><br>${language === 'ja' ? '解析時のLinuxパス' : 'Actual Linux analysis root'}: <code>${escape(report.plan.root)}</code></p></aside>`;
  return renderHtmlReport(report, language).replace(/<body(?:\s[^>]*)?>/, body => body + banner);
}

async function writeSaved(file: string, bytes: Buffer) {
  const handle = await open(file, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); }
  finally { await handle.close(); }
}

async function exportFiles(options: { job: JobReport; raw: Buffer; report: Report; files: SavedFile[]; root: string }, config: Config, inputLanguage: ReportLanguage) {
  const language = parseReportLanguage(inputLanguage), directory = await privateWorkspace(options.root);
  const files = [...options.files];
  if (!files.some(file => file.name === 'report.json')) files.push({ name: 'report.json', bytes: encode(options.report) });
  const html = renderJobHtml(options.report, options.job, language);
  const sarif = renderSarifReports(options.report, config.maxOutputBytes);
  files.push({ name: 'job.json', bytes: options.raw }, { name: 'report.html', bytes: Buffer.from(html) }, ...sarif.map(part => ({ name: part.name, bytes: Buffer.from(part.text) })));
  // Validate only this export's fixed artifact list, before publishing any of it.
  if (new Set(files.map(file => file.name)).size !== files.length) throw new SafeError('invalid_job_record');
  for (const file of files) {
    if (file.bytes.length > config.maxOutputBytes) throw new SafeError('output_size_limit');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(file.bytes);
    if (await checkedText(text, config, directory) !== text) throw new SafeError('invalid_job_record');
  }
  const destination = path.join(directory, 'job.json'), htmlDestination = path.join(directory, 'report.html');
  await checkedText(JSON.stringify({ destination, htmlDestination, reportDestination: path.join(directory, 'report.json'), sarifDestinations: sarif.map(part => path.join(directory, part.name)) }), config, directory);
  if (files.some(file => file.name.startsWith('checkpoints/'))) await mkdir(path.join(directory, 'checkpoints'), { mode: 0o700 });
  for (const file of files) await writeSaved(path.join(directory, ...file.name.split('/')), file.bytes);
  return { directory, destination, htmlDestination, json: options.raw.toString('utf8'), job: options.job, report: options.report };
}

export async function exportJob(input: string, configPath: string, config: Config, language: ReportLanguage) {
  return exportFiles(await readSavedJob(input, configPath, config), config, language);
}

export async function recoverJob(input: string, configPath: string, config: Config, language: ReportLanguage) {
  if (!path.isAbsolute(input)) throw new SafeError('invalid_job_input');
  const directory = await canonical(input);
  if (!(await lstat(directory)).isDirectory()) throw new SafeError('invalid_job_input');
  const planBytes = await readJobRegular(path.join(directory, 'job-plan.json'), config.maxOutputBytes), plan = validateJobPlan(parseJobJson(planBytes));
  const root = await nativeReader(directory, plan, configPath, config);
  // Explicit recovery never reads final report or trusts a saved job's closure/resource claims.
  const recovered = await readEngineCheckpoints(path.join(directory, 'checkpoints'), config.maxOutputBytes);
  const prefix = await fixedPrefix(directory, recovered.sequence, config.maxOutputBytes, plan);
  if (!prefix.pair || !isDeepStrictEqual(prefix.pair.checkpoint.report, recovered.report)) throw new SafeError('invalid_job_record');
  const files = [{ name: 'job-plan.json', bytes: planBytes }, ...prefix.files];
  const closure: JobClosure = { startupVerified: false, supervisorClosed: false, ownedTasksClosure: 'unverified', controllerCompleted: false, controllerTerminal: null,
    terminal: null, containerAbsent: false, daemonHealthy: false, inputsUnchanged: false };
  const outcome = jobOutcome({ plan, report: null, prefix: prefix.pair, stop: null, closure, failures: ['job_closure_unverified'] });
  const body = prefix.files.at(-2)!.bytes, receipt = prefix.files.at(-1)!.bytes;
  const job: JobReport = { schema: 'scanmux.job-report/v1', jobId: plan.jobId, profileSha256: plan.profileSha256, originDigest: plan.origin.repoId,
    origin: plan.origin, mappedRoot: plan.mappedRoot, plan: jobReference(planBytes), analysis: { kind: 'checkpoint', sequence: recovered.sequence, body: jobReference(body), receipt: jobReference(receipt) },
    basis: 'recovered_saved_checkpoint_without_live_ownership', resources: { requested: plan.limits, startup: null, ending: null, stop: null, nativeFailure: null, observer: null,
      payloadWallScope: 'linux_payload_and_durable_record_ack_admission', controlPlaneHardCpuMemoryLimit: false, retainedFilesystemPhysicalQuotaEnforced: false, totalCommandWallGuarantee: false },
    closure, knownFailures: ['job_closure_unverified'], failureObservationScope: 'host_accepted_closed_failure_facts', unobservedInternalErrors: 'unknown',
    inputVerificationScope: 'declared_assets_and_readonly_source_identity_concurrent_host_mutation_unsupported',
    infrastructure: { appFiles: 0, appBytes: 0, emptyConfigurationFiles: 1, ownerIdentityBytes: 0 },
    retained: { logicalLimit: plan.limits.retainedBytes, payloadAdmittedBytesBeforeMetadata: files.reduce((sum, file) => sum + file.bytes.length, 0), filesBeforeMetadata: files.length,
      metadataBytesMaximum: plan.config.maxOutputBytes, maxFiles: 11 }, ...outcome };
  validateJobReport(job);
  return exportFiles({ job, raw: encode(job), report: recovered.report, files, root }, config, language);
}
