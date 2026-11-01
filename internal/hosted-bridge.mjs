import fs from 'node:fs/promises';
import { parseSdkInitializationObservation } from './sdk-initialization-observer.mjs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { createHostedChannel } from './hosted-channel.mjs';
import { createHostedExecutor } from './hosted-executor.mjs';
import { toolFailureCodes, validToolFailureCode } from './ai-session.mjs';
import { parseWorkerResources, expectedResourceKernel, parseResourceSnapshot, buildWorkerResourceReport, workerResourcesComplete } from './worker-resources.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => hash(JSON.stringify(value));
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
const requireValue = (value, code) => { if (!value) throw Error(code); };
const positive = value => Number.isSafeInteger(value) && value > 0;
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const relative = value => typeof value === 'string' && value.length > 0 && value.length <= 1024 && !/[\\:<>"|?*\x00-\x1f\x7f]/.test(value) && value.split('/').every(p => p && p !== '.' && p !== '..' && !/[. ]$/.test(p) && p.toLowerCase() !== '.git' && !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p));
const inside = (root, target) => { const value = path.relative(root, target); return value === '' || value !== '..' && !value.startsWith('..' + path.sep) && !path.isAbsolute(value); };
const pluginRoot = '/assets/node_modules/@openai/codex-security/_bundled_plugin';
const incomingTypes = ['execution.request', 'mcp.result', 'mcp.error', 'sdk.result', 'worker.failure'];
const outgoingTypes = ['mcp.start', 'mcp.listTools', 'mcp.recordDraft', 'mcp.close', 'execution.result'];

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  promise.catch(() => {});
  return { promise, resolve, reject };
}
async function persist(directory, name, bytes) {
  const handle = await fs.open(path.join(directory, name), 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function canonicalDirectory(directory) {
  requireValue(typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) === directory, 'bridge_directory');
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const stat = await fs.lstat(current);
    requireValue(stat.isDirectory() && !stat.isSymbolicLink() && await fs.realpath(current) === current, 'bridge_directory_alias');
  }
}
function validateOrigin(input, binding) {
  const { plan, config, projection } = input, mapping = projection?.mapping;
  requireValue(plan?.schema === 'scanmux.plan/v2' && plan.planHash === digest({ ...plan, planHash: '' }) && plan.policyHash === digest(config) && plan.snapshotHash === digest(plan.files), 'bridge_plan');
  requireValue(plan.dirty === false && Array.isArray(plan.blockers) && plan.blockers.length === 0 && projection.status === 'completed', 'bridge_plan_blocked');
  requireValue(mapping?.schema === 'scanmux.sdk-projection/v1' && mapping.originalCommit === plan.commit && mapping.originalTree === plan.treeHash && mapping.planHash === plan.planHash && mapping.snapshotHash === plan.snapshotHash && mapping.projectionScope === 'accepted_files_only' && mapping.projectedMode === '100644', 'bridge_mapping');
  requireValue(isDeepStrictEqual(mapping.manifest, plan.files.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256 }))) && isDeepStrictEqual(mapping.originalExclusions, plan.exclusions), 'bridge_manifest');
  requireValue(binding.repository === '/handoff' && binding.originalCommit === plan.commit && binding.snapshotHash === plan.snapshotHash && binding.revision === mapping.derivedRevision && isDeepStrictEqual(binding.manifest, mapping.manifest) && isDeepStrictEqual(binding.scope, projection.scope), 'bridge_binding');
  requireValue(exact(binding.identity, ['runId', 'attemptId', 'buildId']) && Object.values(binding.identity).every(identifier), 'bridge_identity');
}
async function sourceFiles(root, manifest, stop) {
  const sources = new Map(), folded = new Set(); await canonicalDirectory(root); stop();
  for (const entry of manifest) {
    requireValue(exact(entry, ['path', 'bytes', 'sha256']) && relative(entry.path) && Number.isSafeInteger(entry.bytes) && entry.bytes >= 0 && /^[a-f0-9]{64}$/.test(entry.sha256) && !folded.has(entry.path.toLowerCase()), 'bridge_source_manifest');
    const file = path.join(root, entry.path); await canonicalDirectory(path.dirname(file));
    const stat = await fs.lstat(file); requireValue(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && await fs.realpath(file) === file, 'bridge_source_alias');
    const bytes = await fs.readFile(file); stop(); requireValue(bytes.length === entry.bytes && hash(bytes) === entry.sha256, 'bridge_source_changed');
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); requireValue(Buffer.from(text).equals(bytes), 'bridge_source_utf8');
    sources.set(entry.path, text); folded.add(entry.path.toLowerCase());
  }
  requireValue(sources.size > 0, 'bridge_source_empty'); return sources;
}
function unchangedTraffic(before, after) {
  requireValue(plain(before) && plain(after) && isDeepStrictEqual(Object.keys(before).sort(), Object.keys(after).sort()) && Object.keys(before).length > 0, 'bridge_network');
  for (const key of Object.keys(before)) {
    requireValue(Array.isArray(before[key]) && before[key].length === 16 && Array.isArray(after[key]) && after[key].length === 16, 'bridge_network');
    for (let i = 0; i < 16; i++) requireValue(typeof before[key][i] === 'string' && /^\d+$/.test(before[key][i]) && before[key][i] === after[key][i], 'bridge_network');
  }
}

/** Validate copied data only. The Linux worker cannot select a host path or usage. */
export function validateBridgeArtifacts({ payload, execution, request, binding, sources, expectedStartup, maxBytes, workerResources }) {
  requireValue(exact(payload, ['result', 'artifacts', 'attestation']), 'bridge_final_shape');
  const { result, artifacts, attestation } = payload;
  const resultKeys = ['version', 'repository', 'revision', 'scope', 'identity', 'outputDirectory', 'scanId', 'pluginVersion', 'provenance', 'execution', 'status', 'error', 'artifacts'];
  requireValue(plain(result) && Object.keys(result).every(k => resultKeys.includes(k)) && result.version === 2 && ['completed', 'failed', 'canceled', 'acceptance_unknown'].includes(result.status), 'bridge_sdk_result');
  requireValue(result.repository === '/handoff' && result.revision === binding.revision && isDeepStrictEqual(result.scope, binding.scope) && isDeepStrictEqual(result.identity, binding.identity) && result.scanId === request.scanId && result.outputDirectory === '/work/outputs', 'bridge_sdk_binding');
  requireValue(result.pluginVersion === '0.1.95' && exact(result.provenance, ['cliVersion', 'buildId', 'pluginVersion']) && result.provenance.cliVersion === '0.5.1' && result.provenance.pluginVersion === '0.1.95' && result.provenance.buildId === binding.identity.buildId, 'bridge_sdk_version');
  requireValue(isDeepStrictEqual(result.execution, execution), 'bridge_execution_changed');
  const attestationKeys = ['sdkCleanupFailures', 'mcp', 'pids', 'sourceReceiptsSha256', 'networkBefore', 'networkAfter'];
  if (workerResources !== undefined) attestationKeys.push('resources');
  requireValue(exact(attestation, attestationKeys) && attestation.sdkCleanupFailures === 0 && isDeepStrictEqual(attestation.mcp, { closed: true, quiescent: true, clean: true }) && isDeepStrictEqual(attestation.pids, [1]) && attestation.sourceReceiptsSha256 === expectedStartup.sourceReceiptsSha256, 'bridge_worker_cleanup');
  if (workerResources !== undefined) {
    requireValue(isDeepStrictEqual(expectedStartup.resources, expectedResourceKernel(workerResources)), 'resource_boundary_unverified');
    parseResourceSnapshot(attestation.resources, workerResources);
  } else requireValue(expectedStartup.resources === undefined, 'resource_boundary_unverified');
  unchangedTraffic(attestation.networkBefore, attestation.networkAfter);
  requireValue(Array.isArray(artifacts) && Array.isArray(result.artifacts) && artifacts.length === result.artifacts.length, 'bridge_artifacts');
  if (result.status !== 'completed') { requireValue(artifacts.length === 0, 'bridge_failed_artifacts'); return []; }
  requireValue(execution.status === 'completed' && execution.usage?.complete === true, 'bridge_execution_incomplete');
  const copies = [], names = new Set(); let bytesTotal = 0;
  for (let i = 0; i < artifacts.length; i++) {
    const item = artifacts[i], declared = result.artifacts[i];
    requireValue(exact(item, ['path', 'bytes', 'sha256', 'content']) && exact(declared, ['path', 'bytes', 'sha256']) && relative(item.path) && !names.has(item.path.toLowerCase()), 'bridge_artifact_path');
    requireValue(Number.isSafeInteger(item.bytes) && item.bytes >= 0 && /^[a-f0-9]{64}$/.test(item.sha256) && typeof item.content === 'string' && isDeepStrictEqual(declared, { path: item.path, bytes: item.bytes, sha256: item.sha256 }), 'bridge_artifact_declaration');
    const bytes = Buffer.from(item.content); bytesTotal += bytes.length;
    requireValue(bytes.length === item.bytes && hash(bytes) === item.sha256 && Number.isSafeInteger(bytesTotal) && bytesTotal <= maxBytes && new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes) === item.content, 'bridge_artifact_bytes');
    names.add(item.path.toLowerCase()); copies.push({ path: item.path, bytes, sha256: item.sha256 });
  }
  for (const name of names) requireValue(![...names].some(other => other !== name && other.startsWith(name + '/')), 'bridge_artifact_collision');
  const json = name => { const item = copies.find(c => c.path === name); requireValue(item, 'bridge_canonical_missing'); return JSON.parse(item.bytes); };
  const manifest = json('scan-manifest.json'), findings = json('findings.json'), coverage = json('coverage.json');
  requireValue(copies.some(c => c.path === 'report.md'), 'bridge_canonical_missing');
  requireValue(manifest.documentType === 'codex-security.scan-manifest' && manifest.schemaVersion === '1.0' && manifest.scan?.id === request.scanId && manifest.scan.status === 'completed' && typeof manifest.scan.sealedAt === 'string' && Number.isFinite(Date.parse(manifest.scan.sealedAt)), 'bridge_seal');
  requireValue(manifest.scan.target?.revision === binding.revision && isDeepStrictEqual(manifest.scan.scope?.includePaths, binding.scope.paths) && isDeepStrictEqual(manifest.scan.scope?.excludePaths, []), 'bridge_artifact_scope');
  requireValue(Array.isArray(manifest.scan.artifacts) && manifest.scan.artifacts.length > 0, 'bridge_seal_artifacts');
  const sealedNames = new Set();
  for (const entry of manifest.scan.artifacts) { requireValue(plain(entry) && relative(entry.path) && !sealedNames.has(entry.path) && copies.some(c => c.path === entry.path && c.sha256 === entry.sha256), 'bridge_seal_hash'); sealedNames.add(entry.path); }
  requireValue(sealedNames.has('findings.json') && sealedNames.has('coverage.json'), 'bridge_seal_artifacts');
  requireValue(findings.documentType === 'codex-security.findings' && findings.schemaVersion === '1.0' && findings.scanId === request.scanId && Array.isArray(findings.findings), 'bridge_findings');
  requireValue(coverage.documentType === 'codex-security.coverage' && coverage.schemaVersion === '1.0' && coverage.scanId === request.scanId, 'bridge_coverage');
  for (const finding of findings.findings) {
    requireValue(plain(finding) && Array.isArray(finding.locations) && finding.locations.length > 0, 'bridge_finding_location');
    for (const location of [...finding.locations, ...(finding.codeEvidence ?? [])]) {
      requireValue(plain(location) && sources.has(location.path), 'bridge_finding_source');
      const lines = sources.get(location.path).split('\n'); if (lines.at(-1) === '') lines.pop();
      requireValue(Number.isSafeInteger(location.startLine) && location.startLine >= 1 && Number.isSafeInteger(location.endLine ?? location.startLine) && (location.endLine ?? location.startLine) >= location.startLine && (location.endLine ?? location.startLine) <= lines.length, 'bridge_finding_lines');
    }
  }
  return copies;
}

/** One host-owned attempt. openWorker and check are trusted host adapters. */
export async function runHostedBridge(options) {
  const { directory, sourceRoot, check, submit, closeTransport, openWorker, verifyInputs, signal } = options;
  const binding = structuredClone(options.binding), input = structuredClone(options.input), limits = structuredClone(options.limits), ipc = structuredClone(options.ipc);
  const workerResources = options.workerResources === undefined ? undefined : parseWorkerResources(options.workerResources);
  requireValue([check, submit, closeTransport, openWorker, verifyInputs].every(f => typeof f === 'function') && positive(options.timeoutMs) && options.timeoutMs <= 2 ** 31 - 1 && positive(options.cleanupTimeoutMs) && options.cleanupTimeoutMs <= 2 ** 31 - 1, 'bridge_options');
  requireValue(workerResources === undefined || typeof options.validateArtifacts === 'function', 'bridge_artifact_validator');
  requireValue(exact(ipc, ['maxFrameBytes', 'maxBytes', 'maxFrames']) && Object.values(ipc).every(positive) && ipc.maxFrameBytes <= ipc.maxBytes, 'bridge_ipc_limits');
  requireValue(exact(limits, ['maxRequests', 'maxTotalOutputTokens', 'maxOutputTokensPerRequest', 'maxInputBytesPerRequest', 'maxResponseBytesPerRequest', 'maxToolCalls', 'maxToolResultBytes', 'timeoutMs']) && Object.values(limits).every(positive) && limits.timeoutMs <= 2 ** 31 - 1, 'bridge_ai_limits');
  validateOrigin(input, binding);
  if (input.plan.ai?.schema === 'scanmux.ai-plan/v2' || workerResources !== undefined) requireValue(workerResources !== undefined && isDeepStrictEqual(workerResources, input.plan.ai?.workerResources) && isDeepStrictEqual(workerResources, input.config.ai?.workerResources), 'bridge_worker_resource_binding');
  const expiresAt = performance.now() + options.timeoutMs, controller = new AbortController(), initial = deferred(), final = deferred();
  const inputHash = digest({ input, binding, sourceRoot }), runId = binding.identity.runId;
  let reason = 'bridge_not_started', phase = 'before_worker', worker, channel, pending, commandId = 0, request, execution, executionPromise, sources, finalPayload, implementation;
  let workerAttempted = false, providerSubmitInvocations = 0, mcpPhase = 'unused', closingMcp, removeMcpAbort, mcpControl, startupVerified = false, deadlineExceeded = false;
  let cleanup = { closed: true, quiescent: true, containerAbsent: true }, inputsUnchanged = false, accepted = false, artifacts = [], lockWritten = false;
  let failurePayload, failureDrained = false, mcpEvidence = 'not_started', artifactEvidence = 'none';
  const independentFailures = new Set();
  const abort = () => controller.abort(); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
  const expire = () => { if (!controller.signal.aborted) { deadlineExceeded = true; abort(); } };
  const timer = setTimeout(expire, options.timeoutMs);
  const stop = () => { if (performance.now() >= expiresAt) expire(); requireValue(!controller.signal.aborted, 'bridge_stopped'); };
  const breakChannel = code => {
    if (reason === 'bridge_not_started') reason = code;
    else if (failurePayload && code !== reason) independentFailures.add(code);
    initial.reject(Error(code)); final.reject(Error(code)); pending?.reject(Error(code)); pending = undefined; abort();
  };
  async function guarded(callback) {
    stop(); let listener;
    const stopped = new Promise((_, reject) => { listener = () => reject(Error('bridge_stopped')); controller.signal.addEventListener('abort', listener, { once: true }); });
    try { const result = await Promise.race([Promise.resolve().then(() => { stop(); return callback(); }), stopped]); stop(); return result; }
    finally { controller.signal.removeEventListener('abort', listener); }
  }
  const certify = async bytes => { const copied = Buffer.from(bytes), expected = { bytes: copied.length, sha256: hash(copied) }; requireValue(isDeepStrictEqual(await guarded(() => check(Buffer.from(copied), controller.signal)), expected), 'bridge_secret_check'); };
  const verifyHost = async at => { const run = () => verifyInputs({ phase: at, inputHash }); requireValue(isDeepStrictEqual(await (at === 'after' ? boundedCleanup(run) : guarded(run)), { inputHash }), 'bridge_inputs_changed'); };
  async function boundedCleanup(callback) {
    let cleanupTimer;
    try { return await Promise.race([Promise.resolve().then(callback), new Promise((_, reject) => { cleanupTimer = setTimeout(() => reject(Error('bridge_cleanup_timeout')), options.cleanupTimeoutMs); })]); }
    finally { clearTimeout(cleanupTimer); }
  }
  async function rpc(type, payload) {
    const stopMcp = () => { stop(); if (mcpControl?.signal.aborted || performance.now() >= (mcpControl?.expiresAt ?? expiresAt)) { channel.fail('bridge_mcp_stopped'); throw Error('bridge_mcp_stopped'); } };
    stopMcp(); requireValue(phase === 'executing' && !pending, 'bridge_mcp_overlap');
    mcpEvidence = 'unverified';
    const waiting = deferred(), id = ++commandId; pending = { id, ...waiting };
    await channel.send(type, { commandId: id, ...payload }, { expiresAt: Math.min(expiresAt, mcpControl?.expiresAt ?? expiresAt) });
    const result = await guarded(() => waiting.promise); stopMcp(); return result;
  }
  function receive(type, payload) {
    if (type === 'sdk.result') artifactEvidence = 'unverified';
    if (type === 'worker.failure') {
      const failureKeys = ['code', 'stage', 'startup', 'resources', 'diskFullStores', 'diskObservationComplete'];
      const optionalKeys = ['sdkInitializationObservation', 'sdkOutcome'].filter(key => plain(payload) && Object.hasOwn(payload, key));
      requireValue(workerResources !== undefined && exact(payload, [...failureKeys, ...optionalKeys])
        && isDeepStrictEqual(payload.startup, worker.expectedStartup) && isDeepStrictEqual(payload.startup.resources, expectedResourceKernel(workerResources)), 'bridge_failure_shape');
      const stageCodes = { sdk_initialization: 'worker_sdk_initialization_failed', sdk_finalization: 'worker_sdk_finalization_failed', mcp: 'worker_mcp_failed' };
      requireValue(Object.hasOwn(stageCodes, payload.stage) && [stageCodes[payload.stage], 'resource_disk_exceeded'].includes(payload.code)
        && Array.isArray(payload.diskFullStores) && payload.diskFullStores.every(store => ['tmp', 'work', 'shm'].includes(store))
        && new Set(payload.diskFullStores).size === payload.diskFullStores.length && typeof payload.diskObservationComplete === 'boolean', 'bridge_failure_shape');
      const legal = phase === 'waiting_request' && payload.stage === 'sdk_initialization' && !request && !pending && commandId === 0 && providerSubmitInvocations === 0
        || phase === 'executing' && payload.stage === 'mcp' && pending
        || phase === 'waiting_result' && payload.stage === 'sdk_finalization' && execution && !pending;
      requireValue(legal, 'bridge_failure_order');
      if (Object.hasOwn(payload, 'sdkOutcome')) { const site = payload.sdkOutcome; requireValue(payload.stage !== 'mcp' && exact(site, ['site', 'errorCode'])
        && (site.site === 'result_not_completed' && site.errorCode === null || site.site === 'worker_threw' && typeof site.errorCode === 'string' && /^[a-z_]{1,64}$/.test(site.errorCode)), 'bridge_failure_shape'); }
      if (payload.resources !== null) parseResourceSnapshot(payload.resources, workerResources);
      let nativeDisk = false;
      if (Object.hasOwn(payload, 'sdkInitializationObservation')) {
        requireValue(payload.stage === 'sdk_initialization', 'bridge_failure_observation_phase');
        const observation = parseSdkInitializationObservation(payload.sdkInitializationObservation, ipc.maxFrames);
        nativeDisk = observation.state === 'observed' && observation.terminal === 'sqlite_full';
      }
      if (payload.code === 'resource_disk_exceeded') requireValue(payload.stage !== 'mcp' && payload.resources !== null && (payload.diskObservationComplete && payload.diskFullStores.length > 0 || nativeDisk), 'bridge_failure_resource');
      failurePayload = structuredClone(payload); startupVerified = true; reason = payload.code; phase = 'worker_failure_received';
      initial.reject(Error(reason)); final.reject(Error(reason)); pending?.reject(Error(reason)); pending = undefined; return;
    }
    if (type === 'execution.request') {
      requireValue(phase === 'waiting_request' && exact(payload, ['request', 'startup']) && isDeepStrictEqual(payload.startup, worker.expectedStartup), 'bridge_startup');
      if (workerResources !== undefined) requireValue(isDeepStrictEqual(payload.startup.resources, expectedResourceKernel(workerResources)), 'resource_boundary_unverified');
      startupVerified = true;
      const candidate = payload.request;
      requireValue(plain(candidate) && identifier(candidate.requestId) && identifier(candidate.scanId) && candidate.runtime?.pluginRoot === pluginRoot && candidate.runtime.pluginVersion === '0.1.95' && candidate.runtime.stateDirectory === '/work/state' && candidate.runtime.outputDirectory === '/work/outputs', 'bridge_runtime');
      request = structuredClone(candidate); phase = 'executing'; initial.resolve(request); return;
    }
    if (type === 'mcp.result' || type === 'mcp.error') {
      requireValue(phase === 'executing' && pending && exact(payload, type === 'mcp.result' ? ['commandId', 'result'] : ['commandId', 'code']) && payload.commandId === pending.id, 'bridge_mcp_reply');
      const waiting = pending; pending = undefined;
      if (type === 'mcp.error') { waiting.reject(Error('bridge_mcp_failed')); throw Error('bridge_mcp_failed'); }
      waiting.resolve(payload.result); return;
    }
    requireValue(type === 'sdk.result' && phase === 'waiting_result' && !pending, 'bridge_result_order');
    finalPayload = structuredClone(payload); phase = 'final_received'; final.resolve(finalPayload);
  }
  try {
    await canonicalDirectory(directory); await canonicalDirectory(sourceRoot); stop(); requireValue(!inside(sourceRoot, directory), 'bridge_journal_in_source');
    requireValue((await fs.readdir(directory)).length === 0, 'ownership_unavailable'); stop();
    try { await persist(directory, 'attempt.lock', Buffer.from(JSON.stringify({ version: 1, identity: binding.identity, inputHash }) + '\n')); lockWritten = true; }
    catch { throw Error('ownership_unavailable'); }
    await fs.mkdir(path.join(directory, 'ai')); await fs.mkdir(path.join(directory, 'artifacts')); stop();
    sources = await sourceFiles(sourceRoot, binding.manifest, stop); await verifyHost('before');
    for (const text of sources.values()) await certify(Buffer.from(text));
    phase = 'waiting_request';
    worker = await guarded(async () => {
      workerAttempted = true;
      const owner = await openWorker({ runId, identity: structuredClone(binding.identity), revision: binding.revision, scope: structuredClone(binding.scope), manifest: structuredClone(binding.manifest), reasoningEffort: binding.reasoningEffort, signal: controller.signal, expiresAt, ipc: structuredClone(ipc) });
      worker = owner;
      if (controller.signal.aborted || performance.now() >= expiresAt) { abort(); try { await owner.close(); } catch {} throw Error('bridge_stopped'); }
      return owner;
    });
    requireValue(worker && !worker.failure && worker.input && worker.output && worker.closed && typeof worker.close === 'function' && plain(worker.expectedStartup), 'bridge_worker');
    channel = createHostedChannel({ input: worker.input, output: worker.output, runId, signal: controller.signal, expiresAt, ...ipc, incomingTypes, outgoingTypes, onFrame: receive, onFailure: breakChannel, onEnd() { requireValue(['final_received', 'worker_failure_received'].includes(phase), 'bridge_early_eof'); } });
    await guarded(() => initial.promise);
    implementation = createHostedExecutor({ binding: { ...binding, runtime: structuredClone(request.runtime) }, sourceRoot, directory: path.join(directory, 'ai'), limits: { ...limits, timeoutMs: Math.max(1, Math.min(limits.timeoutMs, Math.floor(expiresAt - performance.now()))) }, check,
      submit(bytes, context) { stop(); requireValue(!failurePayload, 'bridge_terminal_failure'); providerSubmitInvocations++; return submit(bytes, context); }, closeTransport,
      createMcp(runtime, control) {
        requireValue(mcpPhase === 'unused' && isDeepStrictEqual(runtime, request.runtime), 'bridge_mcp_binding');
        mcpControl = control;
        const mcpAbort = () => { if (!failurePayload) channel.fail('bridge_mcp_stopped'); }; control.signal.addEventListener('abort', mcpAbort, { once: true }); removeMcpAbort = () => control.signal.removeEventListener('abort', mcpAbort);
        return {
          async start() { requireValue(mcpPhase === 'unused', 'bridge_mcp_state'); mcpPhase = 'starting'; const result = await rpc('mcp.start', { budgetMs: Math.max(1, Math.floor(Math.min(expiresAt, control.expiresAt) - performance.now())) }); requireValue(result === null, 'bridge_mcp_start'); mcpPhase = 'started'; },
          async listTools() { requireValue(mcpPhase === 'started', 'bridge_mcp_state'); mcpPhase = 'listed'; return rpc('mcp.listTools', {}); },
          recordDraft(draft) { requireValue(mcpPhase === 'listed', 'bridge_mcp_state'); return rpc('mcp.recordDraft', { draft }); },
          close() {
            if (!closingMcp) closingMcp = (async () => { if (mcpPhase === 'unused') return { closed: true, quiescent: true, clean: true }; mcpPhase = 'closing'; try { const result = await rpc('mcp.close', {}); if (isDeepStrictEqual(result, { closed: true, quiescent: true, clean: true })) mcpEvidence = 'closed'; mcpPhase = 'closed'; return result; } catch { return { closed: false, quiescent: false, clean: false }; } })();
            return closingMcp;
          },
        };
      },
    });
    executionPromise = implementation.run(request, { signal: controller.signal }); executionPromise.then(value => { execution = structuredClone(value); }).catch(() => {});
    await guarded(() => executionPromise); stop(); requireValue(execution, 'bridge_execution_missing');
    requireValue(!failurePayload, 'bridge_terminal_failure'); phase = 'waiting_result'; await channel.send('execution.result', { result: execution });
    await guarded(() => final.promise); await channel.end(); await guarded(() => channel.ended);
    const ending = await guarded(() => worker.closed); requireValue(ending.code === (finalPayload.result?.status === 'completed' ? 0 : 1) && ending.signal === null, 'bridge_worker_exit');
    requireValue(channel.inspect().failure === null && channel.inspect().inputEnded && channel.inspect().outputEnded && channel.inspect().pendingWrites === 0, 'bridge_channel_close');
    artifacts = validateBridgeArtifacts({ payload: finalPayload, execution, request, binding, sources, expectedStartup: worker.expectedStartup, maxBytes: ipc.maxBytes, workerResources });
    if (finalPayload.result.status === 'completed') {
      for (const item of artifacts) await certify(item.bytes);
      if (typeof options.validateArtifacts === 'function') {
        const metadata = { originalCommit: binding.originalCommit, snapshotHash: binding.snapshotHash, derivedRevision: binding.revision, scanId: request.scanId };
        await guarded(() => options.validateArtifacts(artifacts.map(item => ({ ...item, bytes: Buffer.from(item.bytes) })), metadata));
        artifactEvidence = 'verified';
      }
      if (workerResources !== undefined) {
        const observed = parseResourceSnapshot(finalPayload.attestation.resources, workerResources);
        requireValue(observed.events.oom === 0 && observed.events.oomKill === 0, 'resource_memory_exceeded');
      }
    }
    reason = finalPayload.result.status === 'completed' ? 'bridge_completed' : 'bridge_sdk_failed';
  } catch (error) { if (reason === 'bridge_not_started') reason = /^[a-z_]+$/.test(error.message) ? error.message : 'bridge_failed'; }
  finally {
    if (failurePayload && !controller.signal.aborted) {
      try {
        await boundedCleanup(async () => {
          await channel.end(); await channel.ended;
          const ending = await worker.closed;
          requireValue(ending.code === 1 && ending.signal === null, 'bridge_worker_exit');
          const closed = channel.inspect(); requireValue(closed.failure === null && closed.inputEnded && closed.outputEnded && closed.pendingWrites === 0, 'bridge_channel_close');
        }); failureDrained = true;
      } catch (error) { independentFailures.add(/^[a-z_]+$/.test(error.message) ? error.message : 'bridge_failure_drain'); }
    }
    if (reason !== 'bridge_completed' && reason !== 'bridge_sdk_failed' && !failureDrained) { abort(); channel?.fail(reason); }
    try { cleanup = worker ? await boundedCleanup(() => worker.close()) : workerAttempted ? { closed: false, quiescent: false, containerAbsent: false } : cleanup; }
    catch { cleanup = { closed: false, quiescent: false, containerAbsent: false }; }
    if (executionPromise && !execution) try { execution = structuredClone(await boundedCleanup(() => executionPromise)); } catch {}
    if (lockWritten) try { await verifyHost('after'); inputsUnchanged = true; } catch { inputsUnchanged = false; }
    removeMcpAbort?.();
  }
  if (!lockWritten) { clearTimeout(timer); signal?.removeEventListener('abort', abort); return { status: signal?.aborted || performance.now() >= expiresAt ? 'canceled' : 'failed', reason, artifactsAccepted: false, providerSubmitInvocations, workerAttempted, mcpEvidence, artifactEvidence }; }
  let resourceReport;
  if (workerResources !== undefined) {
    const diagnostics = worker?.diagnostics?.();
    resourceReport = buildWorkerResourceReport({ requested: workerResources, boundaryVerified: diagnostics?.boundaryVerifiedBeforeStart,
      startupVerified, snapshot: failurePayload?.resources ?? finalPayload?.attestation?.resources, terminal: diagnostics?.terminal, failureCode: failurePayload?.code ?? diagnostics?.failureCode,
      diskObserved: failurePayload?.diskObservationComplete === true && failurePayload.diskFullStores.length > 0, deadlineExceeded });
  }
  try {
    stop(); requireValue(isDeepStrictEqual(cleanup, { closed: true, quiescent: true, containerAbsent: true }) && inputsUnchanged && reason === 'bridge_completed', 'bridge_not_accepted');
    requireValue(workerResources === undefined || workerResourcesComplete(resourceReport, workerResources), 'resource_boundary_unverified');
    for (const item of artifacts) { stop(); const target = path.join(directory, 'artifacts', item.path); await fs.mkdir(path.dirname(target), { recursive: true }); await canonicalDirectory(path.dirname(target)); stop(); await persist(path.dirname(target), path.basename(target), item.bytes); stop(); }
    accepted = true;
  } catch { accepted = false; }
  const observed = execution?.usage ?? null;
  const status = accepted ? 'completed' : reason === 'bridge_sdk_failed' && inputsUnchanged && cleanup.containerAbsent && !controller.signal.aborted ? execution?.status === 'canceled' ? 'canceled' : execution?.status === 'acceptance_unknown' ? 'acceptance_unknown' : 'failed' : providerSubmitInvocations > 0 || commandId > 0 || !cleanup.containerAbsent ? 'acceptance_unknown' : signal?.aborted || performance.now() >= expiresAt ? 'canceled' : 'failed';
  const result = { version: 1, identity: binding.identity, inputHash, status, reason: accepted ? 'bridge_completed' : reason === 'bridge_completed' ? 'bridge_acceptance_failed' : reason, artifactsAccepted: accepted, originalCommit: binding.originalCommit, derivedRevision: binding.revision, snapshotHash: binding.snapshotHash, scanId: request?.scanId ?? null, execution: execution ?? null, usage: observed, providerSubmitInvocations, workerAttempted, mcpEvidence, artifactEvidence, cleanup, inputsUnchanged, artifacts: accepted ? artifacts.map(a => ({ path: a.path, bytes: a.bytes.length, sha256: a.sha256 })) : [] };
  if (resourceReport) result.workerResources = resourceReport;
  if (failurePayload?.sdkInitializationObservation) result.sdkInitializationObservation = structuredClone(failurePayload.sdkInitializationObservation);
  if (failurePayload) result.independentFailures = [...independentFailures];
  const executorOutcome = implementation?.outcome() ?? null;
  if (executorOutcome && (!validToolFailureCode(executorOutcome.toolFailureCode) || !Number.isSafeInteger(executorOutcome.ignoredAfterFinal) || executorOutcome.ignoredAfterFinal < 0
    || !plain(executorOutcome.draftRejections) || !Object.entries(executorOutcome.draftRejections).every(([code, count]) => toolFailureCodes.includes(code) && Number.isSafeInteger(count) && count >= 0))) { result.status = 'acceptance_unknown'; result.reason = 'bridge_sdk_outcome'; result.artifactsAccepted = false; result.artifacts = []; }
  else if (executorOutcome || failurePayload?.sdkOutcome) result.sdkOutcome = { ...(executorOutcome ?? { executorStatus: null, executorMessage: null, sessionStatus: null, sessionReason: null, finalDraft: false, writeStarted: false, ignoredAfterFinal: 0, draftRejections: {}, toolInvocations: 0, toolFailureCode: null, responses: [] }),
    workerSite: failurePayload?.sdkOutcome?.site ?? null, workerErrorCode: failurePayload?.sdkOutcome?.errorCode ?? null };
  const durable = { ...result, execution: execution ? { requestId: execution.requestId, status: execution.status, usage: observed } : null };
  try { await persist(directory, 'attempt.result.json', Buffer.from(JSON.stringify(durable) + '\n')); }
  catch { result.status = 'acceptance_unknown'; result.reason = 'bridge_result_persistence'; result.artifactsAccepted = false; result.artifacts = []; }
  clearTimeout(timer); signal?.removeEventListener('abort', abort); channel?.dispose(); return result;
}
