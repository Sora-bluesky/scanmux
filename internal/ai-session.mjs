import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { projectResponseOutput } from './response-protocol.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const record = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => record(value) && Object.keys(value).every(key => keys.includes(key));
const integer = n => Number.isSafeInteger(n) && n >= 0;
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const fail = code => { throw new SessionError(code); };
class SessionError extends Error { constructor(code) { super(code); this.code = code; } }
// Fixed failures from tool checks, result bounds and the MCP adapters; never retain free text.
export const toolFailureCodes = Object.freeze(['source_request', 'source_result_limit', 'draft_after_final', 'draft_shape', 'draft_owned_field', 'draft_source', 'draft_unread_source',
  'draft_location', 'draft_lines', 'draft_code', 'draft_locations', 'draft_writeup', 'draft_result', 'draft_result_conflict', 'draft_receipt', 'draft_result_limit', 'secret_check_failed',
  'executor_stopped', 'deadline', 'canceled', 'invalid_bytes', 'invalid_utf8', 'mcp_unsettled', 'mcp_unavailable', 'mcp_input_limit', 'mcp_response_error',
  'bridge_stopped', 'bridge_mcp_stopped', 'bridge_mcp_overlap', 'bridge_mcp_state', 'bridge_mcp_failed', 'worker_mcp_failed']);
export const validToolFailureCode = value => value === null || value === 'other' || toolFailureCodes.includes(value);
function toolFailureCode(error) {
  try {
    const code = error?.code === undefined && error instanceof Error ? error.message : error?.code;
    return toolFailureCodes.includes(code) ? code : 'other';
  } catch { return 'other'; }
}
const limitKeys = ['maxRequests', 'maxTotalOutputTokens', 'maxOutputTokensPerRequest', 'maxInputBytesPerRequest', 'maxResponseBytesPerRequest', 'maxToolCalls', 'maxToolResultBytes', 'timeoutMs'];
const identityKeys = ['runId', 'attemptId', 'buildId', 'requestId', 'scanId', 'snapshotHash'];
const inside = (root, child) => { const relative = path.relative(root, child); return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)); };

async function persist(directory, name, value) {
  const handle = await fs.open(path.join(directory, name), 'wx', 0o600);
  try { await handle.writeFile(`${JSON.stringify(value)}\n`, 'utf8'); await handle.sync(); }
  finally { await handle.close(); }
}

function bytes(value, maximum) {
  if (!Buffer.isBuffer(value) || value.length > maximum) fail('invalid_bytes');
  const copy = Buffer.from(value);
  try { new TextDecoder('utf-8', { fatal: true }).decode(copy); } catch { fail('invalid_utf8'); }
  return copy;
}

function usage(value) {
  if (!exact(value, ['inputTokens', 'outputTokens', 'totalTokens', 'cachedInputTokens', 'reasoningTokens'])) return null;
  const { inputTokens, outputTokens, totalTokens, cachedInputTokens, reasoningTokens } = value;
  if (![inputTokens, outputTokens, totalTokens].every(integer) || !Number.isSafeInteger(inputTokens + outputTokens) || totalTokens !== inputTokens + outputTokens) return null;
  if (cachedInputTokens !== undefined && (!integer(cachedInputTokens) || cachedInputTokens > inputTokens)) return null;
  if (reasoningTokens !== undefined && (!integer(reasoningTokens) || reasoningTokens > outputTokens)) return null;
  return { inputTokens, outputTokens, totalTokens, ...(cachedInputTokens === undefined ? {} : { cachedInputTokens }), ...(reasoningTokens === undefined ? {} : { reasoningTokens }) };
}

function requestBody(buffer, cap, names) {
  let body;
  try { body = JSON.parse(buffer.toString('utf8')); } catch { fail('invalid_request'); }
  if (!exact(body, ['type', 'model', 'access_programs', 'store', 'input', 'tools', 'max_output_tokens', 'reasoning']) || body.type !== 'response.create' || body.model !== 'gpt-6-sol' || body.store !== false || body.max_output_tokens !== cap || !exact(body.access_programs, ['cyber']) || body.access_programs.cyber !== 'daybreak_blue' || !Array.isArray(body.input) || !Array.isArray(body.tools)) fail('invalid_request');
  const seen = new Set();
  for (const tool of body.tools) {
    if (!exact(tool, ['type', 'name', 'description', 'parameters', 'strict']) || tool.type !== 'function' || !names.has(tool.name) || seen.has(tool.name) || !record(tool.parameters)) fail('invalid_request_tools');
    seen.add(tool.name);
  }
}

/** Host-only accounting loop. The host supplies an owner-private directory and trusted adapters.
 * This module performs no network I/O and does not accept scan artifacts or resume an attempt.
 */
export async function runAiSession(options) {
  const { directory, targetRoots, prepare, checkRequest, checkOutput, submit, executeAllowedTool, close, signal } = options;
  if (!exact(options.identity, identityKeys) || identityKeys.some(key => !id(options.identity[key])) || !/^[a-f0-9]{64}$/.test(options.identity.snapshotHash)) fail('invalid_identity');
  if (!exact(options.limits, limitKeys) || limitKeys.some(key => !integer(options.limits[key]) || options.limits[key] === 0) || options.limits.timeoutMs > 2 ** 31 - 1) fail('invalid_limits');
  if (!Array.isArray(options.toolNames) || options.toolNames.some(name => !id(name)) || new Set(options.toolNames).size !== options.toolNames.length) fail('invalid_tools');
  if ([prepare, checkRequest, checkOutput, submit, executeAllowedTool, close].some(callback => typeof callback !== 'function')) fail('invalid_callbacks');
  const identity = Object.freeze({ ...options.identity });
  const limits = Object.freeze({ ...options.limits });
  const names = new Set(options.toolNames);
  if (typeof directory !== 'string' || !path.isAbsolute(directory) || !Array.isArray(targetRoots) || !targetRoots.length || targetRoots.some(root => typeof root !== 'string' || !path.isAbsolute(root))) fail('invalid_directory');
  const canonical = await fs.realpath(directory);
  const roots = await Promise.all(targetRoots.map(root => fs.realpath(root)));
  if (!(await fs.lstat(directory)).isDirectory() || (await Promise.all(roots.map(root => fs.lstat(root)))).some(stat => !stat.isDirectory()) || roots.some(root => inside(root, canonical))) fail('invalid_directory');
  const sessionId = randomUUID();
  const state = { version: 1, identity, sessionId, status: 'failed', reason: 'not_started', reservedCalls: 0, submitInvocations: 0, completedResponses: 0, toolInvocations: 0, toolFailureCode: null, responseTools: [], observedUsage: [], usage: null, usageComplete: false, cost: { kind: 'not_applicable', value: null }, accountAllowance: 'unknown', scanArtifactsAccepted: false };
  // Never remove or steal this lock, even on a pre-dispatch error.
  try { await persist(canonical, 'session.lock', { version: 1, identity, sessionId }); }
  catch { return { ...state, reason: 'ownership_unavailable' }; }
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) abort();
  let timedOut = false;
  const expiresAt = performance.now() + limits.timeoutMs;
  const timer = setTimeout(() => { timedOut = true; abort(); }, limits.timeoutMs);
  const refreshStop = () => { if (performance.now() >= expiresAt) { timedOut = true; abort(); } };
  const stopCheck = () => { refreshStop(); if (controller.signal.aborted) fail(timedOut ? 'deadline' : 'canceled'); };
  // Late callback settlement cannot advance this loop. The host close adapter must
  // separately prove quiescence; an abort signal alone is never such evidence.
  async function guarded(callback) {
    stopCheck();
    let listener;
    const stopped = new Promise((_, reject) => {
      listener = () => reject(new SessionError(timedOut ? 'deadline' : 'canceled'));
      controller.signal.addEventListener('abort', listener, { once: true });
    });
    try { return await Promise.race([Promise.resolve().then(() => { stopCheck(); return callback(); }), stopped]); }
    finally { controller.signal.removeEventListener('abort', listener); }
  }
  async function certify(buffer, checker) {
    const expected = { bytes: buffer.length, sha256: sha(buffer) };
    const certificate = await guarded(() => { const copy = Buffer.from(buffer); stopCheck(); return checker(copy, controller.signal); });
    if (!exact(certificate, ['bytes', 'sha256']) || certificate.bytes !== expected.bytes || certificate.sha256 !== expected.sha256) fail('secret_check_failed');
    stopCheck();
  }
  let totalInput = 0, totalOutput = 0, totalTokens = 0;
  let previous = null;
  const responseIds = new Set(), toolIds = new Set();
  let finalText;
  try {
    await persist(canonical, 'session.json', { version: 1, identity, sessionId, limits, toolNames: [...names], createdAt: new Date().toISOString() });
    stopCheck();
    while (true) {
      if (state.reservedCalls >= limits.maxRequests || totalOutput >= limits.maxTotalOutputTokens) fail('budget_exceeded');
      const cap = Math.min(limits.maxOutputTokensPerRequest, limits.maxTotalOutputTokens - totalOutput);
      const sequence = state.reservedCalls + 1;
      const callId = randomUUID();
      const context = Object.freeze({ identity, sessionId, callId, sequence, outputCap: cap, signal: controller.signal });
      const prepared = bytes(await guarded(() => prepare(context, previous)), limits.maxInputBytesPerRequest);
      requestBody(prepared, cap, names);
      await certify(prepared, checkRequest);
      stopCheck();
      const reservation = { version: 1, identity, sessionId, callId, sequence, state: 'reserved', requestBytes: prepared.length, requestSha256: sha(prepared), model: 'gpt-6-sol', requestedProgram: 'daybreak_blue', outputCap: cap, reservedAt: new Date().toISOString() };
      await persist(canonical, `${sequence}.reserved.json`, reservation);
      state.reservedCalls++;
      let invoked = false, closed = false, accepted = false, response, projection, observed = null;
      let reason = 'acceptance_unknown';
      let effectiveProgram = 'unknown', actualModel = null;
      try {
        stopCheck();
        // Count immediately before calling, including synchronous throws.
        response = await guarded(() => { const copy = Buffer.from(prepared); stopCheck(); invoked = true; state.submitInvocations++; return submit(copy, context); });
        // The trusted adapter bounds transport data before parsing; bound the
        // structured receipt here as well, before it can drive any tool.
        const encoded = Buffer.from(JSON.stringify(response));
        response = JSON.parse(encoded.toString('utf8'));
        if (encoded.length > limits.maxResponseBytesPerRequest || !exact(response, ['sessionId', 'callId', 'requestId', 'responseId', 'status', 'model', 'effectiveProgram', 'usage', 'output'])) fail('invalid_response');
        if (response.sessionId !== sessionId || response.callId !== callId || response.requestId !== identity.requestId || !id(response.responseId) || responseIds.has(response.responseId)) fail('response_association');
        responseIds.add(response.responseId);
        observed = usage(response.usage);
        effectiveProgram = ['daybreak_blue', 'standard', 'daybreak_red', 'unknown'].includes(response.effectiveProgram) ? response.effectiveProgram : 'unknown';
        const modelDate = typeof response.model === 'string' && /^gpt-6-sol-\d{4}-\d{2}-\d{2}$/.test(response.model) ? response.model.slice(-10) : null;
        actualModel = response.model === 'gpt-6-sol' || modelDate && Number.isFinite(Date.parse(modelDate)) && new Date(modelDate).toISOString().slice(0, 10) === modelDate ? response.model : null;
        if (observed) {
          state.observedUsage.push({ sequence, callId, usage: observed });
          if (![totalInput + observed.inputTokens, totalOutput + observed.outputTokens, totalTokens + observed.totalTokens].every(Number.isSafeInteger)) fail('usage_overflow');
          totalInput += observed.inputTokens; totalOutput += observed.outputTokens; totalTokens += observed.totalTokens;
          state.usage = { inputTokens: totalInput, outputTokens: totalOutput, totalTokens };
        }
        if (response.status !== 'completed') fail(['failed', 'canceled'].includes(response.status) ? `provider_${response.status}` : 'invalid_response_status');
        state.completedResponses++;
        if (!actualModel || effectiveProgram !== 'daybreak_blue' && effectiveProgram !== 'standard') fail('effective_program_unverified');
        if (!observed) fail('usage_unknown');
        if (observed.outputTokens > cap) fail('output_cap_exceeded');
        try { projection = projectResponseOutput(response.output); } catch { fail('invalid_output'); }
        state.responseTools.push({ sequence, tools: projection.tools.map(tool => names.has(tool.name) ? tool.name : 'other') });
        const batchIds = new Set();
        for (const tool of projection.tools) {
          if (!exact(tool, ['id', 'name', 'arguments']) || !id(tool.id) || !names.has(tool.name) || batchIds.has(tool.id) || toolIds.has(tool.id) || !record(tool.arguments)) fail('invalid_tool');
          batchIds.add(tool.id);
        }
        if (state.toolInvocations + projection.tools.length > limits.maxToolCalls) fail('budget_exceeded');
        await certify(encoded, checkOutput);
        accepted = true; reason = 'response_completed';
      } catch (error) { reason = error instanceof SessionError ? error.code : 'acceptance_unknown'; }
      finally {
        refreshStop();
        if (invoked) {
          // Every submit invocation owns exactly one close, even on sync throw,
          // rejected promise or cancellation. Never wait past the session deadline.
          const closing = Promise.resolve().then(() => close(context));
          try {
            const evidence = controller.signal.aborted ? await Promise.race([closing, Promise.resolve(null)]) : await guarded(() => closing);
            closed = exact(evidence, ['closed', 'quiescent']) && evidence.closed === true && evidence.quiescent === true;
          } catch { closed = false; }
          closing.catch(() => {});
        }
      }
      refreshStop();
      if (controller.signal.aborted) { accepted = false; reason = timedOut ? 'deadline' : 'canceled'; }
      if (invoked && !closed) { accepted = false; reason = 'close_unverified'; }
      const definitiveFailure = closed && ['provider_failed', 'provider_canceled'].includes(reason);
      const terminalState = accepted ? 'completed' : !invoked ? 'canceled_not_sent' : definitiveFailure ? reason.slice(9) : 'acceptance_unknown';
      await persist(canonical, `${sequence}.terminal.json`, { version: 1, identity, sessionId, callId, sequence, state: terminalState, reason, submitInvoked: invoked, closed, effectiveProgram, actualModel, usage: observed, endedAt: new Date().toISOString() });
      if (!accepted) { state.status = terminalState === 'canceled_not_sent' ? 'canceled' : terminalState; state.reason = reason; break; }
      stopCheck();
      if (projection.tools.length === 0) {
        finalText = projection.text; state.status = 'completed'; state.reason = 'conversation_completed'; break;
      }
      // Do not invoke tools if their results cannot be consumed by a next call.
      if (state.reservedCalls >= limits.maxRequests || totalOutput >= limits.maxTotalOutputTokens) fail('budget_exceeded');
      const results = [];
      for (const tool of projection.tools) {
        stopCheck();
        let result;
        try { result = bytes(await guarded(() => { const copy = structuredClone(tool); stopCheck(); toolIds.add(tool.id); state.toolInvocations++; return executeAllowedTool(copy, context); }), limits.maxToolResultBytes); }
        catch (error) { state.toolFailureCode = toolFailureCode(error); fail('tool_acceptance_unknown'); }
        try { await certify(result, checkOutput); }
        catch (error) { state.toolFailureCode = toolFailureCode(error); throw error; }
        results.push({ id: tool.id, content: result.toString('utf8') });
      }
      previous = { response: structuredClone(response), results };
    }
  } catch (error) {
    state.reason = error instanceof SessionError ? error.code : 'persistence_failed';
    state.status = state.reason === 'budget_exceeded' ? 'budget_exceeded' : state.reason === 'canceled' && state.submitInvocations === 0 ? 'canceled' : state.submitInvocations > 0 ? 'acceptance_unknown' : 'failed';
  } finally {
    clearTimeout(timer); signal?.removeEventListener('abort', abort);
    state.usageComplete = state.submitInvocations > 0 && state.observedUsage.length === state.submitInvocations && state.reason !== 'usage_overflow';
  }
  try { await persist(canonical, 'session.result.json', state); }
  catch { state.status = 'acceptance_unknown'; state.reason = 'persistence_failed'; }
  return { ...state, ...(state.status === 'completed' ? { finalText } : {}) };
}
