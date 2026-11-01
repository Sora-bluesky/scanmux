import { isDeepStrictEqual } from 'node:util';

const object = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => object(value) && Object.keys(value).every(key => keys.includes(key));
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
class ProtocolError extends Error { constructor(code) { super(code); this.code = code; } }
const requireValue = (condition, code) => { if (!condition) throw new ProtocolError(code); };
const completed = item => item.status === undefined || item.status === 'completed';

export function projectResponseOutput(output) {
  requireValue(Array.isArray(output) && output.length > 0, 'invalid_output');
  const tools = [], ids = new Set(), calls = new Set(), reasoning = [];
  let text = '', hasFinal = false;
  for (const item of output) {
    requireValue(object(item) && typeof item.type === 'string', 'invalid_output');
    if (item.id !== undefined) {
      requireValue(identifier(item.id) && !ids.has(item.id), 'invalid_output'); ids.add(item.id);
    }
    if (item.type === 'message') {
      requireValue(exact(item, ['id', 'type', 'role', 'status', 'phase', 'content']) && identifier(item.id) && item.role === 'assistant' && item.status === 'completed' && Array.isArray(item.content), 'invalid_output');
      requireValue(item.phase === undefined || item.phase === null || ['commentary', 'final_answer'].includes(item.phase), 'invalid_output');
      const final = item.phase !== 'commentary';
      for (const part of item.content) {
        requireValue(exact(part, ['type', 'text', 'annotations', 'logprobs']) && part.type === 'output_text' && typeof part.text === 'string' && Array.isArray(part.annotations) && part.annotations.length === 0 && (part.logprobs === undefined || Array.isArray(part.logprobs) && part.logprobs.length === 0), 'invalid_output');
        if (final) text += part.text;
      }
      if (final) hasFinal = true;
    } else if (item.type === 'reasoning') {
      requireValue(exact(item, ['id', 'type', 'summary', 'content', 'encrypted_content', 'status']) && identifier(item.id) && completed(item) && Array.isArray(item.summary), 'invalid_output');
      requireValue(item.summary.every(part => exact(part, ['type', 'text']) && part.type === 'summary_text' && typeof part.text === 'string'), 'invalid_output');
      requireValue(item.content === undefined || Array.isArray(item.content) && item.content.every(part => exact(part, ['type', 'text']) && part.type === 'reasoning_text' && typeof part.text === 'string'), 'invalid_output');
      requireValue(item.encrypted_content === undefined || item.encrypted_content === null || typeof item.encrypted_content === 'string', 'invalid_output');
      reasoning.push(item);
    } else if (item.type === 'function_call') {
      requireValue(exact(item, ['type', 'id', 'call_id', 'name', 'arguments', 'status', 'async', 'caller', 'namespace']) && identifier(item.call_id) && identifier(item.name) && typeof item.arguments === 'string' && completed(item), 'invalid_output');
      requireValue((item.async === undefined || item.async === false) && item.namespace === undefined && (item.caller === undefined || item.caller === null || exact(item.caller, ['type']) && item.caller.type === 'direct'), 'invalid_output');
      let argumentsObject;
      try { argumentsObject = JSON.parse(item.arguments); } catch { throw new ProtocolError('invalid_output'); }
      requireValue(object(argumentsObject) && !calls.has(item.call_id), 'invalid_output'); calls.add(item.call_id);
      tools.push({ id: item.call_id, name: item.name, arguments: argumentsObject });
    } else throw new ProtocolError('invalid_output');
  }
  requireValue(tools.length > 0 || hasFinal, 'final_response_missing');
  if (tools.length) requireValue(reasoning.every(item => typeof item.encrypted_content === 'string' && item.encrypted_content.length > 0), 'reasoning_continuation_missing');
  return { text, tools };
}

const progressEvents = new Set([
  'response.content_part.added', 'response.content_part.done',
  'response.output_text.delta', 'response.output_text.done',
  'response.refusal.delta', 'response.refusal.done',
  'response.function_call_arguments.delta', 'response.function_call_arguments.done',
  'response.reasoning_summary_part.added', 'response.reasoning_summary_part.done',
  'response.reasoning_summary_text.delta', 'response.reasoning_summary_text.done',
  'response.reasoning_text.delta', 'response.reasoning_text.done',
]);
const lifecycle = new Map([
  ['response.queued', 'queued'], ['response.in_progress', 'in_progress'],
  ['response.completed', 'completed'], ['response.failed', 'failed'], ['response.incomplete', 'incomplete'],
]);
const providerErrorCodes = new Set([
  'server_error', 'rate_limit_exceeded', 'invalid_prompt', 'data_residency_mismatch', 'bio_policy', 'misalignment_policy_violation', 'vector_store_timeout',
  'flex_unavailable', 'model_not_found', 'context_length_exceeded', 'insufficient_quota', 'credit_balance_exhausted', 'organization_spend_limit_exceeded',
  'project_spend_limit_exceeded', 'usage_not_included', 'cyber_policy', 'policy_capacity_unavailable', 'server_is_overloaded', 'slow_down',
  'invalid_image', 'invalid_image_format', 'invalid_base64_image', 'invalid_image_url', 'image_too_large', 'image_too_small', 'image_parse_error',
  'image_content_policy_violation', 'invalid_image_mode', 'image_file_too_large', 'unsupported_image_media_type', 'empty_image_file', 'failed_to_download_image', 'image_file_not_found',
]);
const incompleteReasons = new Set(['max_output_tokens', 'max_messages', 'content_filter', 'steered']);

function itemIdentity(item) {
  requireValue(object(item) && typeof item.type === 'string', 'output_identity');
  if (item.type === 'function_call') {
    requireValue(identifier(item.call_id) && identifier(item.name) && (item.id === undefined || identifier(item.id)), 'output_identity');
    return { type: item.type, id: item.id, call: item.call_id, name: item.name };
  }
  requireValue(identifier(item.id), 'output_identity');
  return { type: item.type, id: item.id };
}

function sameIdentity(before, after) {
  const a = itemIdentity(before), b = itemIdentity(after);
  return a.type === b.type && (a.id === undefined || a.id === b.id) && a.call === b.call && a.name === b.name;
}

function identityMismatch(before, after) {
  if (object(before) && object(after) && typeof before.type === 'string' && typeof after.type === 'string' && before.type !== after.type) return 'type';
  for (const item of [before, after]) {
    if (!object(item) || typeof item.type !== 'string') return 'type';
    if (item.type === 'function_call') {
      if (!identifier(item.call_id)) return 'call';
      if (!identifier(item.name)) return 'name';
      if (item.id !== undefined && !identifier(item.id)) return 'id';
    } else if (!identifier(item.id)) return 'id';
  }
  const a = itemIdentity(before), b = itemIdentity(after);
  return a.type !== b.type ? 'type' : a.id !== undefined && a.id !== b.id ? 'id' : a.call !== b.call ? 'call' : 'name';
}
const diagnosticItemType = item => !object(item) || typeof item.type !== 'string' ? null : ['message', 'function_call', 'reasoning'].includes(item.type) ? item.type.slice(0, 64) : 'other';

function program(access) {
  if (access === null) return 'standard';
  return exact(access, ['cyber']) && ['daybreak_blue', 'standard', 'daybreak_red'].includes(access.cyber) ? access.cyber : 'unknown';
}

function usage(usage) {
  if (!object(usage)) return null;
  return {
    inputTokens: usage.input_tokens, outputTokens: usage.output_tokens, totalTokens: usage.total_tokens,
    ...(usage.input_tokens_details?.cached_tokens === undefined ? {} : { cachedInputTokens: usage.input_tokens_details.cached_tokens }),
    ...(usage.output_tokens_details?.reasoning_tokens === undefined ? {} : { reasoningTokens: usage.output_tokens_details.reasoning_tokens }),
  };
}

/** One implicit Responses stream. The caller owns transport, its deadline and close evidence. */
export function createResponseDecoder({ context, maxBytes, maxEvents }) {
  requireValue(exact(context, ['sessionId', 'callId', 'requestId']) && Object.values(context).length === 3 && Object.values(context).every(identifier), 'decoder_context');
  requireValue(integer(maxBytes) && maxBytes > 0 && integer(maxEvents) && maxEvents > 0, 'decoder_limits');
  const association = { ...context }, items = new Map(), itemIds = new Set(), callIds = new Set();
  let state = 'new', responseId, initialModel, terminal, lastSequence = -1, count = 0, bytes = 0, finished = false;
  let terminalKind = 'none', failureCode = null, outputIdentityMismatch = null;
  const providerDetails = {};
  function diagnose(error) {
    const code = error instanceof ProtocolError ? error.code : 'protocol_error';
    failureCode ??= code === 'event_sequence_or_stream' ? 'sequence_mismatch' : code === 'unsupported_event' ? 'unexpected_event' : code;
  }

  function checkResponse(response) {
    requireValue(object(response) && identifier(response.id) && (response.object === undefined || response.object === 'response'), 'response_identity');
    requireValue(responseId === undefined || response.id === responseId, 'response_identity');
    requireValue(initialModel === undefined || response.model === undefined || response.model === initialModel, 'response_model_changed');
  }

  function indexOf(event) {
    requireValue(integer(event.output_index), 'output_index'); return event.output_index;
  }

  function push(buffer) {
    try {
      requireValue(!finished && !['terminal', 'broken'].includes(state), 'event_after_terminal');
      if (Buffer.isBuffer(buffer) && buffer.length > maxBytes) failureCode ??= 'message_too_large';
      requireValue(Buffer.isBuffer(buffer) && buffer.length <= maxBytes - bytes && count < maxEvents, 'response_limit');
      bytes += buffer.length; count++;
      let event;
      try { event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer)); } catch { throw new ProtocolError('invalid_event_bytes'); }
      if (object(event)) {
        if (event.type === 'codex.response.metadata' && exact(event, ['type', 'headers', 'metadata']) &&
            Object.keys(event).length > 1 && Object.entries(event).every(([key, value]) => key === 'type' || object(value))) return;
        if (event.type === 'responsesapi.websocket_timing' && exact(event, ['type', 'timing_metrics']) && Object.keys(event).length === 2 && object(event.timing_metrics)) return;
        if (event.type === 'response.completed') terminalKind = 'completed';
        else if (event.type === 'response.incomplete') terminalKind = 'incomplete';
        else if (event.type === 'response.failed' || event.type === 'error') terminalKind = 'failed';
        const code = event.type === 'error' ? (Object.hasOwn(event, 'error') ? event.error?.code : event.code) : event.type === 'response.failed' ? event.response?.error?.code : undefined;
        if (typeof code === 'string') providerDetails.providerErrorCode = providerErrorCodes.has(code) ? code : 'other';
        const reason = event.type === 'response.incomplete' ? event.response?.incomplete_details?.reason : undefined;
        if (incompleteReasons.has(reason)) providerDetails.incompleteReason = reason;
      }
      requireValue(object(event) && !Object.hasOwn(event, 'stream_id') && integer(event.sequence_number) && event.sequence_number > lastSequence, 'event_sequence_or_stream');
      lastSequence = event.sequence_number;
      if (event.response_id !== undefined) requireValue(responseId !== undefined && event.response_id === responseId, 'response_identity');
      if (event.type === 'response.created') {
        requireValue(state === 'new', 'duplicate_created'); checkResponse(event.response);
        requireValue(['queued', 'in_progress'].includes(event.response.status), 'response_status');
        requireValue(event.response.output == null || Array.isArray(event.response.output) && event.response.output.length === 0, 'initial_output_unsupported');
        responseId = event.response.id; initialModel = event.response.model; state = event.response.status;
        return;
      }
      requireValue(state !== 'new', 'event_before_created');
      if (event.type === 'response.metadata') {
        requireValue(exact(event, ['type', 'sequence_number', 'response_id', 'metadata']) && Object.keys(event).length === 4 && object(event.metadata), 'unsupported_event');
        return;
      }
      if (event.type === 'error') {
        if (Object.hasOwn(event, 'error')) {
          const error = event.error;
          requireValue(exact(error, ['code', 'message', 'param', 'type']) && (error.code === null || typeof error.code === 'string') &&
            ['message', 'param', 'type'].every(key => !Object.hasOwn(error, key) || error[key] === null || typeof error[key] === 'string') &&
            !['code', 'message', 'param'].some(key => Object.hasOwn(event, key)), 'error_event');
        } else requireValue((event.code === null || typeof event.code === 'string') && typeof event.message === 'string' && (event.param === null || typeof event.param === 'string'), 'error_event');
        terminal = { status: 'error' }; state = 'terminal'; return;
      }
      if (lifecycle.has(event.type)) {
        checkResponse(event.response);
        const status = lifecycle.get(event.type);
        requireValue(event.response.status === status, 'response_status');
        if (status === 'queued' || status === 'in_progress') {
          requireValue(!(state === 'in_progress' && status === 'queued'), 'response_regressed');
          requireValue(event.response.output == null || Array.isArray(event.response.output) && event.response.output.length === 0, 'interim_output_unsupported');
          state = status; return;
        }
        if (status === 'completed') {
          requireValue(event.response.error == null && event.response.incomplete_details == null, 'completion_error');
          let output = Array.isArray(event.response.output) && event.response.output.length === 0 ? null : event.response.output;
          if (output == null) {
            const ordered = [...items].sort(([a], [b]) => a - b);
            requireValue(ordered.every(([index, entry], position) => index === position && entry.done), 'unfinished_output');
            output = ordered.map(([, entry]) => entry.item);
          }
          requireValue(Array.isArray(output), 'terminal_output');
          for (const [index, entry] of items) {
            try { requireValue(output[index] !== undefined && sameIdentity(entry.item, output[index]), 'output_identity'); }
            catch (error) {
              if (error instanceof ProtocolError && error.code === 'output_identity') outputIdentityMismatch ??= {
                streamedItemCount: items.size, terminalOutputLength: output.length, index, kind: output[index] === undefined ? 'missing_index' : identityMismatch(entry.item, output[index]),
                streamedType: diagnosticItemType(entry.item), terminalType: diagnosticItemType(output[index]),
              };
              throw error;
            }
            if (entry.done) requireValue(isDeepStrictEqual(entry.item, output[index]), 'completed_output_changed');
          }
          terminal = { ...event.response, output };
        } else terminal = event.response;
        state = 'terminal'; return;
      }
      if (event.type === 'response.output_item.added') {
        const index = indexOf(event), identity = itemIdentity(event.item);
        requireValue(!items.has(index) && (identity.id === undefined || !itemIds.has(identity.id)) && (identity.call === undefined || !callIds.has(identity.call)), 'duplicate_output');
        if (identity.id !== undefined) itemIds.add(identity.id);
        if (identity.call !== undefined) callIds.add(identity.call);
        items.set(index, { item: event.item, done: false }); return;
      }
      if (event.type === 'response.output_item.done') {
        const index = indexOf(event), entry = items.get(index);
        requireValue(entry && !entry.done && sameIdentity(entry.item, event.item), 'output_identity');
        const identity = itemIdentity(event.item);
        if (entry.item.id === undefined && identity.id !== undefined) {
          requireValue(!itemIds.has(identity.id), 'duplicate_output'); itemIds.add(identity.id);
        }
        items.set(index, { item: event.item, done: true }); return;
      }
      requireValue(progressEvents.has(event.type), 'unsupported_event');
      const entry = items.get(indexOf(event));
      requireValue(entry && !entry.done && identifier(event.item_id) && event.item_id === entry.item.id, 'progress_identity');
      if (event.content_index !== undefined) requireValue(integer(event.content_index), 'content_index');
      if (event.summary_index !== undefined) requireValue(integer(event.summary_index), 'summary_index');
    } catch (error) { state = 'broken'; diagnose(error); throw error; }
  }

  function finish() {
    requireValue(!finished, 'decoder_finished'); finished = true;
    requireValue(state === 'terminal', 'response_unfinished');
    const receipt = { ...association, responseId, status: terminal.status, model: terminal.model ?? initialModel ?? null, effectiveProgram: program(terminal.access_programs), usage: usage(terminal.usage), output: [] };
    if (terminal.status === 'completed') {
      try { projectResponseOutput(terminal.output); receipt.output = terminal.output; }
      catch (error) { diagnose(error); receipt.status = 'invalid'; }
    }
    return structuredClone(receipt);
  }
  return Object.freeze({ push, finish, inspect: () => ({ terminalKind, failureCode, ...providerDetails,
    ...(outputIdentityMismatch === null ? {} : { outputIdentityMismatch: { ...outputIdentityMismatch } }) }) });
}
