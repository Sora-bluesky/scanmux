import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { copyFile, lstat, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { acquireDatabase } from './fetch-osv-db.mjs';
import { osvEcosystems, receiptName } from '../src/osv-database.ts';
import { parseRuntimePolicy } from '../src/runtime-policy.ts';
import { SafeError } from '../src/safety.ts';
import { readZip } from '../src/zip-archive.ts';
import {
  anchorLine, ciScenarios, deliveryFiles, failureCodes, manifestName, matchesOfflineOutcome, optionalFeatures, parseDeliveryManifest, producerJob, producerStages, testsWorkflowPath,
} from '../src/github-ci.ts';

const repository = path.resolve(import.meta.dirname, '..');
const pinsPath = path.join(repository, '.github', 'scanmux', 'pins.json');
const runnerGit = 'C:\\Program Files\\Git\\cmd\\git.exe';
const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const toolBudget = 256 * 1024 * 1024, outputLimit = 96 * 1024 * 1024, waitMs = 10 * 60 * 1000;
const stageDefaults = { target: 'target_prepare_failed', acquire: 'tool_fetch_failed', database: 'database_fetch_failed', config: 'config_derive_failed',
  plan: 'plan_failed', wait: 'wait_failed', scan: 'scan_failed', check: 'ci_check_failed' };
const prerequisites = { target: [], acquire: [], database: [], config: ['acquire', 'database'], plan: ['target', 'config'], wait: [], scan: ['plan'], check: ['scan'] };

class StageFailure extends Error { constructor(code) { super(code); this.code = code; } }
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function exact(input, keys) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== keys.length || keys.some(key => !Object.hasOwn(input, key))) throw new SafeError('invalid_pins');
  return input;
}

export function parsePins(input) {
  const value = exact(input, ['schema', 'tools', 'database', 'runtimePolicy']);
  if (value.schema !== 'scanmux.ci-pins/v1') throw new SafeError('invalid_pins');
  const tools = exact(value.tools, ['gitleaks', 'osv']);
  const releases = { gitleaks: 'gitleaks/gitleaks', osv: 'google/osv-scanner' };
  for (const [name, release] of Object.entries(releases)) {
    const tool = exact(tools[name], ['version', 'url', 'archiveSha256', 'exeSha256']);
    if (typeof tool.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(tool.version)
      || typeof tool.url !== 'string' || !tool.url.startsWith(`https://github.com/${release}/releases/download/v${tool.version}/`) || !/\.(?:zip|exe)$/.test(tool.url)
      || ![tool.archiveSha256, tool.exeSha256].every(digest => typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest))) throw new SafeError('invalid_pins');
  }
  const database = exact(value.database, ['ecosystems', 'maxBytes', 'timeoutMs']);
  if (!Array.isArray(database.ecosystems) || !database.ecosystems.length || new Set(database.ecosystems).size !== database.ecosystems.length
    || database.ecosystems.some(item => !osvEcosystems.includes(item))
    || ![database.maxBytes, database.timeoutMs].every(number => Number.isSafeInteger(number) && number > 0 && number <= 2147483647)) throw new SafeError('invalid_pins');
  return { tools, database, runtimePolicy: parseRuntimePolicy(value.runtimePolicy) };
}

export function scenarioOf(eventName, event) {
  if (eventName !== 'workflow_dispatch' || event?.inputs?.scenario === undefined) return 'none';
  if (!ciScenarios.includes(event.inputs.scenario)) throw new SafeError('invalid_scenario');
  return event.inputs.scenario;
}

export function targetOf(eventName, event, githubSha) {
  const commit = eventName === 'workflow_run' ? event?.workflow_run?.head_sha : eventName === 'workflow_dispatch' ? githubSha : undefined;
  if (typeof commit !== 'string' || !/^[0-9a-f]{40}$/.test(commit)) throw new SafeError('invalid_target');
  if (eventName === 'workflow_run' && event.workflow_run.path !== testsWorkflowPath) throw new SafeError('invalid_target');
  return commit;
}

export function sourceOf(eventName, event) {
  if (eventName !== 'workflow_run') return null;
  const run = event.workflow_run, pr = run.pull_requests?.[0]?.number ?? null;
  return { runId: run.id, attempt: run.run_attempt, event: run.event, headSha: run.head_sha, pr };
}

function layout() {
  const temp = process.env.RUNNER_TEMP;
  if (!temp || !path.isAbsolute(temp)) throw new SafeError('runner_temp_required');
  const work = path.join(temp, 'scanmux');
  return { work, state: path.join(work, 'state'), delivery: path.join(work, 'delivery'), tools: path.join(work, 'tools'),
    database: path.join(work, 'osv-db'), target: path.join(work, 'target'), home: path.join(work, 'home') };
}
async function readJson(file) { return JSON.parse(await readFile(file, 'utf8')); }
async function exists(file) { return Boolean(await lstat(file).catch(() => null)); }
async function event() {
  const file = process.env.GITHUB_EVENT_PATH;
  return file ? readJson(file) : {};
}

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: options.cwd ?? repository, env: { ...process.env, ...options.env }, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = [];
    let size = 0;
    const take = (list, chunk) => { size += chunk.length; if (size > outputLimit) child.kill(); else list.push(chunk); };
    child.stdout.on('data', chunk => take(out, chunk));
    child.stderr.on('data', chunk => take(err, chunk));
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString('utf8') }));
  });
}
const gitEnvironment = dirs => ({ GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(dirs.home, 'empty-gitconfig'), GIT_TERMINAL_PROMPT: '0' });
const scanmux = (args, dirs) => run(process.execPath, [path.join(repository, 'bin', 'scanmux.mjs'), ...args], { cwd: dirs.work });

async function download(url, budget) {
  let response;
  try { response = await fetch(url, { redirect: 'follow', credentials: 'omit', signal: AbortSignal.timeout(300000) }); }
  catch { throw new StageFailure('tool_fetch_failed'); }
  if (!response.ok || !response.body) throw new StageFailure('tool_fetch_failed');
  const chunks = [];
  let bytes = 0;
  try {
    for await (const chunk of response.body) {
      bytes += chunk.length;
      if (bytes > budget) throw new StageFailure('tool_fetch_failed');
      chunks.push(chunk);
    }
  } catch { await response.body.cancel().catch(() => {}); throw new StageFailure('tool_fetch_failed'); }
  return Buffer.concat(chunks);
}

const stages = {
  async target(dirs, context) {
    const commit = targetOf(context.eventName, context.event, process.env.GITHUB_SHA);
    const git = (args, cwd) => run(runnerGit, args, { cwd, env: gitEnvironment(dirs) });
    if ((await git(['clone', '--quiet', '--no-hardlinks', '--no-checkout', repository, dirs.target], dirs.work)).code !== 0) throw new StageFailure('target_prepare_failed');
    if ((await git(['-C', dirs.target, 'checkout', '--quiet', '--detach', commit], dirs.work)).code !== 0) throw new StageFailure('target_prepare_failed');
    const head = await git(['-C', dirs.target, 'rev-parse', 'HEAD'], dirs.work), status = await git(['-C', dirs.target, 'status', '--porcelain', '--untracked-files=all'], dirs.work);
    if (head.code !== 0 || head.stdout.toString('utf8').trim() !== commit || status.code !== 0 || status.stdout.length) throw new StageFailure('target_prepare_failed');
  },
  async acquire(dirs, context) {
    const { tools } = context.pins;
    let altered = false;
    for (const name of ['gitleaks', 'osv']) {
      const pin = tools[name];
      const archive = await download(pin.url, context.scenario === 'tool-fetch-fail' ? 1 : toolBudget);
      if (sha256(archive) !== pin.archiveSha256) throw new StageFailure('tool_archive_hash_mismatch');
      let executable = archive;
      if (pin.url.endsWith('.zip')) {
        try { executable = readZip(archive, { maxEntries: 16, maxBytes: toolBudget }).get(`${name}.exe`); } catch { executable = undefined; }
        if (!executable) throw new StageFailure('tool_extract_failed');
      }
      if (context.scenario === 'hash-mismatch' && !altered) { executable = Buffer.from(executable); executable[executable.length - 1] ^= 0xff; altered = true; }
      if (sha256(executable) !== pin.exeSha256) throw new StageFailure('tool_hash_mismatch');
      await writeFile(path.join(dirs.tools, `${name}.exe`), executable, { flag: 'wx' });
    }
  },
  async database(dirs, context) {
    const { ecosystems, maxBytes, timeoutMs } = context.pins.database;
    try { await acquireDatabase({ destination: dirs.database, ecosystems, maxBytes: context.scenario === 'db-fetch-fail' ? 1 : maxBytes, timeoutMs }); }
    catch { throw new StageFailure('database_fetch_failed'); }
    await copyFile(path.join(dirs.database, receiptName), path.join(dirs.delivery, 'osv-database-receipt.json'));
  },
  async config(dirs, context) {
    const version = await run(runnerGit, ['--version'], { cwd: dirs.work, env: gitEnvironment(dirs) });
    const match = /\b(\d+\.\d+\.\d+)/.exec(version.stdout.toString('utf8'));
    if (version.code !== 0 || !match) throw new StageFailure('config_git_version_failed');
    const tool = name => ({ path: path.join(dirs.tools, `${name}.exe`), sha256: context.pins.tools[name].exeSha256, version: context.pins.tools[name].version });
    const ownerDirectory = path.join(dirs.tools, 'process-owner'), owner = path.join(ownerDirectory, 'scanmux-windows-process-owner.exe');
    const built = await run(powershell, ['-NoProfile', '-NonInteractive', '-File', path.join(repository, 'scripts', 'build-windows-process-owner.ps1'), '-OutputDirectory', ownerDirectory], { cwd: dirs.work });
    let receipt = null;
    try { receipt = JSON.parse(built.stdout.toString('utf8').trim().split(/\r?\n/).at(-1)); } catch { /* Refused below. */ }
    if (built.code !== 0 || receipt?.schema !== 'scanmux.windows-process-owner-build/v1') {
      const tail = text => text.split(/\r?\n/).slice(-40).join('\n');
      process.stderr.write(`Process owner build exited ${built.code}.\n--- stderr ---\n${tail(built.stderr)}\n--- stdout ---\n${tail(built.stdout.toString('utf8'))}\n`);
      throw new StageFailure('process_owner_build_failed');
    }
    if (receipt.assemblySha256 !== sha256(await readFile(owner).catch(() => Buffer.alloc(0)))) throw new StageFailure('process_owner_receipt_mismatch');
    const fields = { osvDatabase: dirs.database, tools: { git: { path: runnerGit, sha256: sha256(await readFile(runnerGit)), version: match[1] }, gitleaks: tool('gitleaks'), osv: tool('osv'),
      'windows-process-owner': { path: owner, sha256: receipt.assemblySha256, version: receipt.version } } };
    const config = JSON.stringify({ schema: 2, ...fields, runtimePolicy: context.pins.runtimePolicy }, null, 2) + '\n';
    await writeFile(path.join(dirs.state, 'config.json'), config, { flag: 'wx' });
    await writeFile(path.join(dirs.state, 'test-config.json'), JSON.stringify({ schema: 1, ...fields }, null, 2) + '\n', { flag: 'wx' });
    await writeFile(path.join(dirs.delivery, 'config.json'), config, { flag: 'wx' });
  },
  async plan(dirs) {
    const result = await scanmux(['plan', dirs.target, '--config', path.join(dirs.state, 'config.json'), '--json'], dirs);
    if (result.code !== 0 && result.code !== 3) throw new StageFailure('plan_failed');
    const plan = JSON.parse(result.stdout.toString('utf8'));
    const ciRun = randomUUID();
    const expected = { schema: 'scanmux.ci-expectation/v1', ciRun, jobs: [{ id: producerJob, targetRoot: plan.root, repoId: plan.repoId, commit: plan.commit,
      policyHash: plan.policyHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash }] };
    await writeFile(path.join(dirs.delivery, 'plan.json'), result.stdout, { flag: 'wx' });
    await writeFile(path.join(dirs.delivery, 'expected.json'), JSON.stringify(expected, null, 2) + '\n', { flag: 'wx' });
    await writeFile(path.join(dirs.state, 'run.json'), JSON.stringify({ ciRun }) + '\n', { flag: 'wx' });
  },
  async wait(_dirs, context) {
    if (context.scenario !== 'cancel-wait') return;
    process.stdout.write('ScanMux: waiting for a cancellation request.\n');
    await delay(waitMs);
    throw new StageFailure('wait_failed');
  },
  async scan(dirs) {
    const { ciRun } = await readJson(path.join(dirs.state, 'run.json'));
    const result = await scanmux(['scan', dirs.target, '--config', path.join(dirs.state, 'config.json'), '--ci-run', ciRun, '--ci-job', producerJob, '--json'], dirs);
    const receipt = /^CI receipt: (.+)$/m.exec(result.stderr)?.[1]?.trim();
    if (result.code === null || !receipt || !path.isAbsolute(receipt)) throw new StageFailure('scan_failed');
    const receiptBytes = await readFile(receipt);
    if (JSON.parse(receiptBytes.toString('utf8')).reportHash !== sha256(result.stdout)) throw new StageFailure('scan_failed');
    await writeFile(path.join(dirs.delivery, 'report.json'), result.stdout, { flag: 'wx' });
    await writeFile(path.join(dirs.delivery, 'ci-receipt.json'), receiptBytes, { flag: 'wx' });
  },
  async check(dirs) {
    const result = await scanmux(['ci-check', path.join(dirs.delivery, 'expected.json'), path.join(dirs.delivery, 'ci-receipt.json'),
      '--config', path.join(dirs.state, 'config.json'), '--json'], dirs);
    let claim;
    try { claim = JSON.parse(result.stdout.toString('utf8')); } catch { throw new StageFailure('ci_check_failed'); }
    if (claim?.schema !== 'scanmux.ci-result/v1' || claim.exitCode !== result.code) throw new StageFailure('ci_check_failed');
    await writeFile(path.join(dirs.delivery, 'ci-result.json'), result.stdout, { flag: 'wx' });
  },
};

async function outcomeOf(dirs) {
  const file = path.join(dirs.state, 'outcome.json');
  if (await exists(file)) return readJson(file);
  for (const { stage } of producerStages) if (!(await exists(path.join(dirs.state, `${stage}.done`)))) return { kind: 'failed', stage, code: 'stage_not_completed' };
  return { kind: 'produced' };
}

async function seal(dirs, context) {
  const names = (await readdir(dirs.delivery, { withFileTypes: true })).map(entry => {
    if (!entry.isFile() || !deliveryFiles.includes(entry.name)) throw new SafeError('unexpected_delivery_file');
    return entry.name;
  }).sort();
  const files = [];
  for (const name of names) {
    const bytes = await readFile(path.join(dirs.delivery, name));
    files.push({ path: name, bytes: bytes.length, sha256: sha256(bytes) });
  }
  const env = process.env, repositoryName = env.GITHUB_REPOSITORY;
  const workflowRef = env.GITHUB_WORKFLOW_REF ?? '';
  const workflowPath = workflowRef.startsWith(`${repositoryName}/`) ? workflowRef.slice(repositoryName.length + 1).replace(/@.*$/, '') : '';
  const controller = await run(runnerGit, ['-C', repository, 'rev-parse', 'HEAD'], { cwd: dirs.work, env: gitEnvironment(dirs) });
  const configFile = path.join(dirs.state, 'config.json'), runFile = path.join(dirs.state, 'run.json');
  const manifest = parseDeliveryManifest({
    schema: 'scanmux.github-delivery/v1',
    github: { repositoryId: Number(env.GITHUB_REPOSITORY_ID), repository: repositoryName, workflowPath, runId: Number(env.GITHUB_RUN_ID),
      attempt: Number(env.GITHUB_RUN_ATTEMPT), event: context.eventName, runHeadSha: env.GITHUB_SHA },
    source: sourceOf(context.eventName, context.event),
    targetHeadSha: targetOf(context.eventName, context.event, env.GITHUB_SHA),
    controllerSha: controller.stdout.toString('utf8').trim(),
    pinsSha256: sha256(await readFile(pinsPath)),
    ciRun: await exists(runFile) ? (await readJson(runFile)).ciRun : null,
    scenario: context.scenario,
    git: await exists(configFile) ? (await readJson(configFile)).tools.git : null,
    outcome: await outcomeOf(dirs),
    optional: optionalFeatures,
    files,
  });
  await writeFile(path.join(dirs.delivery, manifestName), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' });
}

async function anchor(dirs) {
  const id = process.env.SCANMUX_ARTIFACT_ID;
  if (!id || !/^[1-9][0-9]{0,15}$/.test(id)) throw new SafeError('artifact_id_missing');
  const bytes = await readFile(path.join(dirs.delivery, manifestName));
  parseDeliveryManifest(JSON.parse(bytes.toString('utf8')));
  process.stdout.write(anchorLine(sha256(bytes), Number(id), Number(process.env.GITHUB_RUN_ID), Number(process.env.GITHUB_RUN_ATTEMPT)) + '\n');
}

async function gate(dirs) {
  const manifest = parseDeliveryManifest(await readJson(path.join(dirs.delivery, manifestName)));
  if (manifest.outcome.kind === 'failed') {
    process.stdout.write(`ScanMux self-scan: producer failed at ${manifest.outcome.stage} (${manifest.outcome.code}); exit 4.\n`);
    process.stdout.write('ScanMux self-scan documented offline outcome: did not match.\n');
    return 4;
  }
  const claim = await readJson(path.join(dirs.delivery, 'ci-result.json'));
  if (![0, 1, 2, 3, 4].includes(claim.exitCode)) return 4;
  process.stdout.write(`ScanMux self-scan claim: ${claim.gate} (exit ${claim.exitCode}).\n`);
  const files = await Promise.all(manifest.files.map(async file => {
    const bytes = await readFile(path.join(dirs.delivery, file.path)).catch(() => null);
    return bytes !== null && bytes.length === file.bytes && sha256(bytes) === file.sha256;
  }));
  const matched = files.every(Boolean) && matchesOfflineOutcome(manifest, claim, await readJson(path.join(dirs.delivery, 'report.json')).catch(() => null));
  process.stdout.write(`ScanMux self-scan documented offline outcome: ${matched ? 'matched' : 'did not match'}${claim.gate === 'PASS' ? ' (unexpected PASS)' : ''}.\n`);
  return matched ? 0 : claim.exitCode || 1;
}

async function main(command) {
  const dirs = layout();
  for (const directory of [dirs.work, dirs.state, dirs.delivery, dirs.tools, dirs.home]) await mkdir(directory, { recursive: true });
  await writeFile(path.join(dirs.home, 'empty-gitconfig'), '', { flag: 'a' });
  const eventName = process.env.GITHUB_EVENT_NAME, payload = await event();
  const context = { eventName, event: payload, scenario: scenarioOf(eventName, payload), pins: parsePins(await readJson(pinsPath)) };
  if (command === 'seal') { await seal(dirs, context); return 0; }
  if (command === 'anchor') { await anchor(dirs); return 0; }
  if (command === 'gate') return gate(dirs);
  if (!Object.hasOwn(stages, command)) throw new SafeError('invalid_command');
  try {
    for (const required of prerequisites[command]) if (!(await exists(path.join(dirs.state, `${required}.done`)))) throw new StageFailure('stage_not_completed');
    await stages[command](dirs, context);
  } catch (error) {
    const code = error instanceof StageFailure && failureCodes.includes(error.code) ? error.code : stageDefaults[command];
    await writeFile(path.join(dirs.state, 'outcome.json'), JSON.stringify({ kind: 'failed', stage: command, code }) + '\n', { flag: 'wx' }).catch(() => {});
    process.stderr.write(JSON.stringify({ state: 'failed', stage: command, code }) + '\n');
    return 1;
  }
  await writeFile(path.join(dirs.state, `${command}.done`), '', { flag: 'wx' });
  return 0;
}

if (import.meta.main) {
  try { process.exitCode = await main(process.argv[2]); }
  catch (error) {
    process.stderr.write(JSON.stringify({ state: 'failed', code: error instanceof SafeError ? error.code : 'ci_produce_failed' }) + '\n');
    process.exitCode = 4;
  }
}
