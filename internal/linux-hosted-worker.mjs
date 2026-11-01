import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { createHostedChannel } from './hosted-channel.mjs';
import { createStdioMcp } from './hosted-mcp.mjs';
import { parseWorkerResources, readWorkerResourceSnapshot, probeWorkerDisk } from './worker-resources.mjs';

const sdkRoot = '/assets/node_modules/@openai/codex-security';
const pluginRoot = sdkRoot + '/_bundled_plugin';
const gitTrust = '[safe]\ndirectory =\ndirectory = /handoff\n';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => hash(JSON.stringify(value));
const requireValue = (value, code) => { if (!value) throw Error(code); };
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
const positive = value => Number.isSafeInteger(value) && value > 0;
const safePath = value => typeof value === 'string' && value.length > 0 && !value.startsWith('/') && !/[\\\x00-\x1f\x7f]/.test(value) && value.split('/').every(p => p && p !== '.' && p !== '..');
const environment = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/work/home', TMPDIR: '/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', GIT_CONFIG_GLOBAL: '/work/empty-gitconfig', GIT_TERMINAL_PROMPT: '0', GIT_ATTR_NOSYSTEM: '1', GIT_NO_LAZY_FETCH: '1', GIT_NO_REPLACE_OBJECTS: '1', GIT_OPTIONAL_LOCKS: '0' };
let stage = 'input', channel, mcp, input, expiresAt, commandTimer;
let startup, failurePromise, executionReceived, initializationObserver, initializationObservation;
let sourceReceipts, networkBefore;
let phase = 'preflight', busy = false, commandId = 0, requestSeen, resolveExecution, rejectExecution, mcpState = 'unused', mcpClosure = { closed: true, quiescent: true, clean: true };
const controller = new AbortController();
const abort = () => { controller.abort(); rejectExecution?.(Error('worker_stopped')); };
const stop = () => { if (performance.now() >= expiresAt) abort(); requireValue(!controller.signal.aborted, 'worker_stopped'); };
const executionWait = new Promise((resolve, reject) => { resolveExecution = resolve; rejectExecution = reject; }); executionWait.catch(() => {});

async function inventory(root, { directories = false, contents = false } = {}) {
  const entries = [];
  async function visit(folder) {
    stop();
    for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
      stop(); const full = path.join(folder, entry.name), name = path.relative(root, full);
      const stat = await fs.lstat(full); requireValue(!stat.isSymbolicLink() && await fs.realpath(full) === full, 'worker_alias');
      if (stat.isDirectory()) { if (directories) entries.push({ path: name, kind: 'directory' }); await visit(full); }
      else {
        requireValue(stat.isFile() && stat.nlink === 1, 'worker_file');
        if (contents) { const bytes = await fs.readFile(full); stop(); entries.push({ path: name, bytes: bytes.length, sha256: hash(bytes) }); }
        else entries.push(name);
      }
    }
  }
  await visit(root); return entries.sort((a, b) => { const x = typeof a === 'string' ? a : a.path, y = typeof b === 'string' ? b : b.path; return x < y ? -1 : x > y ? 1 : 0; });
}
async function verifyFile(root, entry) {
  requireValue(exact(entry, ['path', 'bytes', 'sha256']) && safePath(entry.path) && Number.isSafeInteger(entry.bytes) && entry.bytes >= 0 && /^[a-f0-9]{64}$/.test(entry.sha256), 'worker_manifest');
  const full = path.join(root, entry.path), stat = await fs.lstat(full); requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && await fs.realpath(full) === full, 'worker_file');
  const bytes = await fs.readFile(full); stop(); requireValue(bytes.length === entry.bytes && hash(bytes) === entry.sha256, 'worker_changed'); return bytes;
}
async function network() {
  const text = await fs.readFile('/proc/net/dev', 'utf8'), value = {};
  for (const line of text.split('\n').slice(2)) {
    if (!line.trim()) continue;
    const [name, fields] = line.trim().split(':'); requireValue(name && fields, 'worker_network');
    const counters = fields.trim().split(/\s+/); requireValue(counters.length === 16 && counters.every(c => /^\d+$/.test(c)), 'worker_network'); value[name] = counters;
  }
  return value;
}
async function pids() { return (await fs.readdir('/proc')).filter(name => /^\d+$/.test(name)).map(Number).sort((a, b) => a - b); }
async function git(args, selectedEnvironment = environment) {
  stop();
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/work/empty-hooks', '-c', 'protocol.allow=never', '-C', '/handoff', ...args], { cwd: '/work', env: selectedEnvironment, detached: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let count = 0, stdout = Buffer.alloc(0), failure;
    const kill = () => { failure ??= 'worker_git_stopped'; try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const timer = setTimeout(kill, Math.max(1, Math.min(input.commandTimeoutMs, Math.ceil(expiresAt - performance.now()))));
    controller.signal.addEventListener('abort', kill, { once: true });
    child.on('error', () => { failure ??= 'worker_git_start'; });
    child.stdout.on('data', bytes => { count += bytes.length; if (count > input.ipc.maxBytes) kill(); else stdout = Buffer.concat([stdout, bytes]); });
    child.stderr.on('data', bytes => { count += bytes.length; if (count > input.ipc.maxBytes) kill(); });
    child.on('close', (code, signal) => { clearTimeout(timer); controller.signal.removeEventListener('abort', kill); failure || code !== 0 || signal !== null ? reject(Error(failure ?? 'worker_git_failed')) : resolve(stdout); });
  });
}
async function dispatch(type, payload) {
  stop();
  if (type === 'mcp.start') {
    requireValue(mcpState === 'unused' && positive(payload.budgetMs) && payload.budgetMs <= input.budgetMs, 'worker_mcp_state');
    mcpState = 'starting';
    mcp = createStdioMcp({ command: '/usr/local/bin/node', args: [pluginRoot + '/mcp/server.mjs'], cwd: '/work', environment: requestSeen.runtime.environment, signal: controller.signal, expiresAt: Math.min(expiresAt, performance.now() + payload.budgetMs), maxBytes: input.ipc.maxBytes });
    mcpClosure = { closed: false, quiescent: false, clean: false }; await mcp.start(); stop(); mcpState = 'started'; return null;
  }
  if (type === 'mcp.listTools') { requireValue(mcpState === 'started', 'worker_mcp_state'); mcpState = 'listed'; return mcp.listTools(); }
  if (type === 'mcp.recordDraft') { requireValue(mcpState === 'listed' && plain(payload.draft) && payload.draft.scanId === requestSeen.scanId, 'worker_mcp_state'); return mcp.recordDraft(payload.draft); }
  requireValue(type === 'mcp.close' && ['starting', 'started', 'listed'].includes(mcpState), 'worker_mcp_state');
  mcpState = 'closing'; mcpClosure = await mcp.close(); mcpState = 'closed'; return mcpClosure;
}
function receive(type, payload) {
  stop(); requireValue(phase === 'awaiting_execution' && requestSeen && !busy, 'worker_protocol_state');
  if (type === 'execution.result') {
    requireValue(exact(payload, ['result']) && plain(payload.result) && payload.result.requestId === requestSeen.requestId && ['unused', 'closed'].includes(mcpState), 'worker_execution_result');
    phase = 'sealing'; executionReceived = structuredClone(payload.result); resolveExecution(executionReceived); return;
  }
  const expectedKeys = type === 'mcp.start' ? ['commandId', 'budgetMs'] : type === 'mcp.recordDraft' ? ['commandId', 'draft'] : ['commandId'];
  requireValue(exact(payload, expectedKeys) && Number.isSafeInteger(payload.commandId) && payload.commandId === commandId + 1, 'worker_command_id');
  const id = ++commandId; busy = true;
  void dispatch(type, payload).then(async result => { stop(); busy = false; await channel.send('mcp.result', { commandId: id, result }); }).catch(error => { void terminalFailure('mcp', { error }).catch(abort); });
}

async function finishInitializationObservation() {
  if (!initializationObserver) return;
  try { initializationObservation = await initializationObserver?.finish() ?? null; }
  catch { initializationObservation = { schema: 'scanmux.sdk-initialization-observation/v2', state: 'unavailable', helperInvocations: 0, closedInvocations: 0, sqliteFullObserved: false, otherSqliteErrorObserved: false, terminal: 'none' }; }
}
function terminalFailure(failureStage, { error, result, sdkCleanupFailures, site } = {}) {
  if (failurePromise) return failurePromise;
  failurePromise = (async () => {
    phase = 'failure_sent'; rejectExecution(Error('worker_terminal_failure'));
    if (mcp) try { mcpClosure = await mcp.close(); } catch { mcpClosure = { closed: false, quiescent: false, clean: false }; }
    const disk = await probeWorkerDisk();
    let resources = null; try { resources = await readWorkerResourceSnapshot(input.workerResources); } catch {}
    let integrity = false;
    try { integrity = isDeepStrictEqual(await pids(), [1]) && isDeepStrictEqual(await inventory('/handoff', { directories: true, contents: true }), sourceReceipts) && isDeepStrictEqual(await network(), networkBefore); } catch {}
    const directDisk = !result && !requestSeen && stage === 'sdk' && error?.code === 'ENOSPC' && isDeepStrictEqual(mcpClosure, { closed: true, quiescent: true, clean: true });
    const nativeDisk = failureStage === 'sdk_initialization' && stage === 'sdk' && !error && !requestSeen && !executionReceived && !mcp && mcpState === 'unused' && commandId === 0
      && !controller.signal.aborted && performance.now() < expiresAt && sdkCleanupFailures === 0
      && result?.status === 'failed' && !Object.hasOwn(result, 'scanId') && !Object.hasOwn(result, 'execution') && Array.isArray(result.artifacts) && result.artifacts.length === 0
      && initializationObservation?.state === 'observed' && initializationObservation.terminal === 'sqlite_full'
      && resources?.events.oom === 0 && resources.events.oomKill === 0 && isDeepStrictEqual(mcpClosure, { closed: true, quiescent: true, clean: true });
    const code = failureStage !== 'mcp' && integrity && resources && (disk.observationComplete && disk.fullStores.length && directDisk || nativeDisk)
      ? 'resource_disk_exceeded' : failureStage === 'mcp' ? 'worker_mcp_failed' : failureStage === 'sdk_initialization' ? 'worker_sdk_initialization_failed' : 'worker_sdk_finalization_failed';
    let errorCode = null;
    if (site === 'worker_threw') {
      try { const value = error?.code; errorCode = typeof value === 'string' && /^[a-z_]{1,64}$/.test(value) ? value : 'other'; }
      catch { errorCode = 'other'; }
    }
    await channel.send('worker.failure', { code, stage: failureStage, startup, resources, diskFullStores: disk.fullStores, diskObservationComplete: disk.observationComplete,
      ...(failureStage === 'sdk_initialization' && initializationObservation ? { sdkInitializationObservation: initializationObservation } : {}),
      ...(site ? { sdkOutcome: { site, errorCode } } : {}) });
    await channel.end(); await channel.ended;
    requireValue(channel.inspect().failure === null && channel.inspect().pendingWrites === 0, 'worker_channel_close');
    process.exitCode = 1;
  })();
  return failurePromise;
}

async function main() {
  requireValue(process.platform === 'linux' && process.version === 'v24.22.1' && process.getuid() === 1000, 'worker_runtime');
  const inputBytes = await fs.readFile('/verify/input.json'); requireValue(inputBytes.length <= 8 * 1024 * 1024, 'worker_input_limit'); input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(inputBytes));
  requireValue(input.version === 1 && positive(input.budgetMs) && input.budgetMs <= 2 ** 31 - 1 && positive(input.commandTimeoutMs) && input.commandTimeoutMs <= 2 ** 31 - 1, 'worker_input');
  expiresAt = performance.now() + input.budgetMs; commandTimer = setTimeout(abort, input.budgetMs);
  stage = 'resources'; parseWorkerResources(input.workerResources);
  const initialResources = await readWorkerResourceSnapshot(input.workerResources);
  requireValue(initialResources.events.oom === 0 && initialResources.events.oomKill === 0, 'resource_memory_exceeded');
  requireValue(isDeepStrictEqual(await pids(), [1]), 'worker_initial_processes');
  for (const folder of ['/work/home', '/work/empty-hooks']) await fs.mkdir(folder);
  await fs.writeFile('/work/empty-gitconfig', '', { flag: 'wx' });
  for (const key of Object.keys(process.env)) delete process.env[key]; Object.assign(process.env, environment);
  stage = 'modules';
  requireValue(Array.isArray(input.modules) && input.modules.length === 7 && digest(input.modules) === input.modulesManifestSha256, 'worker_modules');
  for (const entry of input.modules) await verifyFile('/verify', entry);
  requireValue(isDeepStrictEqual(await inventory('/verify'), [...input.modules.map(e => e.path), 'input.json'].sort()), 'worker_module_inventory');
  stage = 'assets';
  requireValue(Array.isArray(input.assets) && input.assets.length === 10805 && digest(input.assets) === input.assetManifestSha256, 'worker_assets');
  for (const entry of input.assets) await verifyFile('/assets', entry);
  requireValue(isDeepStrictEqual(await inventory('/assets'), input.assets.map(e => e.path).sort()), 'worker_asset_inventory');
  requireValue(JSON.parse(await fs.readFile(sdkRoot + '/package.json')).version === '0.5.1' && JSON.parse(await fs.readFile(pluginRoot + '/.codex-plugin/plugin.json')).version === '0.1.95', 'worker_sdk_version');
  stage = 'source';
  requireValue((await fs.readFile('/etc/gitconfig', 'utf8')) === gitTrust && (await fs.readFile('/verify/git-trust.config', 'utf8')) === gitTrust, 'worker_git_trust');
  let trustWrite; try { const handle = await fs.open('/etc/gitconfig', 'a'); await handle.close(); } catch (error) { trustWrite = error.code; } requireValue(trustWrite === 'EROFS', 'worker_git_trust_write');
  const readOnlyChecks = [];
  for (const name of ['.scanmux-readonly-canary', '.git/.scanmux-readonly-canary']) {
    let code; try { const handle = await fs.open('/handoff/' + name, 'wx'); await handle.close(); } catch (error) { code = error.code; }
    requireValue(code === 'EROFS', 'worker_source_write'); readOnlyChecks.push({ path: name, code });
  }
  sourceReceipts = await inventory('/handoff', { directories: true, contents: true }); requireValue(digest(sourceReceipts) === input.sourceReceiptsSha256, 'worker_source_changed');
  requireValue((await git(['rev-parse', '--verify', 'HEAD^{commit}'])).toString().trim() === input.revision, 'worker_revision');
  requireValue((await git(['config', '--system', '--get-all', 'safe.directory'])).toString() === '\n/handoff\n', 'worker_git_scope');
  for (const entry of input.manifest) { await verifyFile('/handoff', entry); const blob = await git(['cat-file', 'blob', input.revision + ':' + entry.path]); requireValue(blob.length === entry.bytes && hash(blob) === entry.sha256, 'worker_source_blob'); }
  stage = 'sdk';
  networkBefore = await network(); startup = { platform: 'linux', node: process.version, uid: process.getuid(), sdkVersion: '0.5.1', pluginVersion: '0.1.95', assetManifestSha256: input.assetManifestSha256, modulesManifestSha256: input.modulesManifestSha256, revision: input.revision, manifestSha256: digest(input.manifest), sourceReceiptsSha256: input.sourceReceiptsSha256, readOnlyChecks, resources: initialResources.kernel };
  requireValue(isDeepStrictEqual(startup, input.expectedStartup), 'worker_startup');
  channel = createHostedChannel({ input: process.stdin, output: process.stdout, runId: input.identity.runId, signal: controller.signal, expiresAt, ...input.ipc, incomingTypes: ['mcp.start', 'mcp.listTools', 'mcp.recordDraft', 'mcp.close', 'execution.result'], outgoingTypes: ['execution.request', 'mcp.result', 'mcp.error', 'sdk.result', 'worker.failure'], onFrame: receive, onFailure: abort, onEnd() { requireValue(['final_sent', 'failure_sent'].includes(phase), 'worker_early_eof'); } });
  try { const { observeSdkInitialization } = await import('./sdk-initialization-observer.mjs'); initializationObserver = observeSdkInitialization({ ipc: input.ipc, signal: controller.signal, expiresAt }); }
  catch { initializationObservation = { schema: 'scanmux.sdk-initialization-observation/v2', state: 'unavailable', helperInvocations: 0, closedInvocations: 0, sqliteFullObserved: false, otherSqliteErrorObserved: false, terminal: 'none' }; }
  const { runHostedScan } = await import(sdkRoot + '/dist/hosted-scan.js'); stop();
  let sdkCleanupFailures = 0;
  const value = { version: 2, repository: '/handoff', revision: input.revision, scope: input.scope, outputDirectory: '/work/outputs', stateDirectory: '/work/state', model: 'gpt-6-sol', reasoningEffort: input.reasoningEffort, identity: input.identity };
  const result = await runHostedScan(value, { signal: controller.signal, onEvent(event) { if (event.type === 'activity' && event.activity.id === 'runtime.cleanup' && event.activity.status === 'failed') sdkCleanupFailures++; }, executor: { async run(request) {
    try { initializationObserver?.disarm(); } catch {}
    stop(); requireValue(!requestSeen && request.repository === value.repository && request.revision === value.revision && isDeepStrictEqual(request.scope, value.scope) && isDeepStrictEqual(request.identity, value.identity) && request.runtime.pluginRoot === pluginRoot && request.runtime.pluginVersion === '0.1.95', 'worker_request_binding');
    requireValue(request.runtime.stateDirectory === '/work/state' && request.runtime.outputDirectory === '/work/outputs' && plain(request.runtime.environment) && Object.keys(request.runtime.environment).every(k => !/TOKEN|SECRET|PASSWORD|API_KEY|AUTH/i.test(k)) && Object.values(request.runtime.environment).every(v => typeof v === 'string'), 'worker_runtime_binding');
    requestSeen = structuredClone(request); phase = 'awaiting_execution';
    await channel.send('execution.request', { request: requestSeen, startup }); return executionWait;
  } } });
  await finishInitializationObservation();
  // The SDK reports its own close failures through queued activity notifications.
  if (failurePromise) { await failurePromise; return; }
  if (!requestSeen || result.status !== 'completed') {
    await new Promise(resolve => setImmediate(resolve));
    await terminalFailure(requestSeen ? 'sdk_finalization' : 'sdk_initialization', { result, sdkCleanupFailures, site: 'result_not_completed' }); return;
  }
  await new Promise(resolve => setImmediate(resolve)); stop(); stage = 'artifacts';
  const artifacts = [], names = new Set(); let total = 0;
  for (const item of result.artifacts) {
    requireValue(safePath(item.path) && !names.has(item.path), 'worker_artifact_path'); names.add(item.path);
    const bytes = await verifyFile(result.outputDirectory, item); total += bytes.length; requireValue(total <= input.ipc.maxBytes, 'worker_artifact_limit');
    const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); requireValue(Buffer.from(content).equals(bytes), 'worker_artifact_utf8'); artifacts.push({ ...item, content });
  }
  const afterReceipts = await inventory('/handoff', { directories: true, contents: true }); requireValue(isDeepStrictEqual(afterReceipts, sourceReceipts), 'worker_source_changed');
  const attestation = { sdkCleanupFailures, mcp: mcpClosure, pids: await pids(), sourceReceiptsSha256: digest(afterReceipts), networkBefore, networkAfter: await network(), resources: await readWorkerResourceSnapshot(input.workerResources) };
  phase = 'final_sent'; await channel.send('sdk.result', { result, artifacts, attestation }); await channel.end(); await channel.ended;
  requireValue(channel.inspect().failure === null && channel.inspect().pendingWrites === 0, 'worker_channel_close');
  process.exitCode = result.status === 'completed' && sdkCleanupFailures === 0 && mcpClosure.clean ? 0 : 1;
}

try { await main(); }
catch (error) {
  await finishInitializationObservation();
  if (channel && startup && !controller.signal.aborted && channel.inspect().failure === null) {
    try { await terminalFailure(requestSeen ? 'sdk_finalization' : 'sdk_initialization', { error, site: 'worker_threw' }); }
    catch { abort(); channel.fail('worker_failed'); process.exitCode = 1; }
  } else { abort(); channel?.fail('worker_failed'); process.stderr.write(JSON.stringify({ code: error.code === 'ENOSPC' ? 'resource_disk_exceeded' : /^[a-z_]+$/.test(error.message) ? error.message : 'worker_failed', stage }) + '\n'); process.exitCode = 1; }
}
finally { try { initializationObserver?.disarm(); } catch {} if (mcp) try { await mcp.close(); } catch {} clearTimeout(commandTimer); channel?.dispose(); }
