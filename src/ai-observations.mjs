import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { array, digest, hash, record, safeRelative, SafeError } from './safety.ts';
import { readAiFile, readAiJson } from './ai-files.mjs';

const requireValue = (value, code) => { if (!value) throw new SafeError(code); };
const count = value => Number.isSafeInteger(value) && value >= 0;
const programs = ['daybreak_blue', 'standard', 'daybreak_red', 'unknown'];
function tokens(input) {
  const value = record(input), { inputTokens, outputTokens, totalTokens } = value;
  requireValue([inputTokens, outputTokens, totalTokens].every(count) && Number.isSafeInteger(inputTokens + outputTokens) && inputTokens + outputTokens === totalTokens, 'ai_usage_invalid');
  return { inputTokens, outputTokens, totalTokens };
}
export function hostUsage(result, maximumCalls) {
  const calls = result.providerSubmitInvocations;
  requireValue(count(calls) && calls <= maximumCalls, 'ai_usage_invalid');
  const value = result.usage;
  if (value === null || value === undefined) return { calls, tokens: { kind: 'unknown', observed: null }, records: [], declaredComplete: false };
  const usage = record(value), requests = array(usage.requests);
  requireValue(typeof usage.complete === 'boolean' && requests.length <= calls, 'ai_usage_invalid');
  let last = 0; const ids = new Set(), total = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };
  const records = requests.map(input => {
    const row = record(input), value = tokens(row.usage);
    requireValue(count(row.sequence) && row.sequence > last && row.sequence <= calls && typeof row.callId === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(row.callId) && !ids.has(row.callId), 'ai_usage_invalid');
    last = row.sequence; ids.add(row.callId);
    for (const key of Object.keys(total)) { total[key] += value[key]; requireValue(count(total[key]), 'ai_usage_invalid'); }
    return { sequence: row.sequence, usage: value, callId: row.callId };
  });
  if (usage.observed === null) requireValue(records.length === 0, 'ai_usage_invalid');
  else requireValue(isDeepStrictEqual(tokens(usage.observed), total) && records.length > 0, 'ai_usage_invalid');
  return { calls, tokens: records.length ? { kind: 'partial', observed: total } : { kind: 'unknown', observed: null }, records, declaredComplete: usage.complete };
}
export async function readHostTerminals({ result, usage, directory, identity, snapshotHash, maximumBytes, control }) {
  if (usage.calls === 0) return { tokens: usage.tokens, programs: [], models: [] };
  const expected = { ...identity, requestId: result.execution?.requestId, scanId: result.scanId, snapshotHash };
  requireValue(typeof expected.requestId === 'string' && typeof expected.scanId === 'string', 'ai_usage_records_incomplete');
  let sessionId; const observedPrograms = [], models = [], callIds = new Set(); let observed = 0;
  for (let sequence = 1; sequence <= usage.calls; sequence++) {
    const terminal = record(await readAiJson(path.join(directory, 'ai', sequence + '.terminal.json'), maximumBytes, control));
    requireValue(terminal.version === 1 && isDeepStrictEqual(terminal.identity, expected) && terminal.sequence === sequence && terminal.submitInvoked === true
      && typeof terminal.sessionId === 'string' && typeof terminal.callId === 'string' && !callIds.has(terminal.callId) && typeof terminal.closed === 'boolean'
      && ['completed','acceptance_unknown','failed','canceled'].includes(terminal.state) && programs.includes(terminal.effectiveProgram), 'ai_usage_records_incomplete');
    sessionId ??= terminal.sessionId; requireValue(terminal.sessionId === sessionId, 'ai_usage_records_incomplete'); callIds.add(terminal.callId);
    observedPrograms.push(terminal.effectiveProgram);
    if (terminal.actualModel !== null) {
      requireValue(typeof terminal.actualModel === 'string' && /^gpt-6-sol(?:-\d{4}-\d{2}-\d{2})?$/.test(terminal.actualModel), 'ai_usage_records_incomplete'); models.push(terminal.actualModel);
    }
    const row = usage.records.find(row => row.sequence === sequence);
    if (terminal.usage !== null) { requireValue(row && row.callId === terminal.callId && isDeepStrictEqual(tokens(terminal.usage), row.usage), 'ai_usage_records_incomplete'); observed++; }
    else requireValue(row === undefined, 'ai_usage_records_incomplete');
  }
  requireValue(observed === usage.records.length, 'ai_usage_records_incomplete');
  const observation = usage.tokens.kind === 'unknown' ? usage.tokens : { kind: usage.declaredComplete && observed === usage.calls ? 'complete' : 'partial', observed: usage.tokens.observed };
  return { tokens: observation, programs: [...new Set(observedPrograms)], models: [...new Set(models)] };
}
/** Read only the bridge's checked, sealed artifact allowlist in this fresh attempt. */
export async function readAiArtifacts(result, directory, plan, control, maxBytes) {
  requireValue(result.artifactsAccepted === true && result.originalCommit === plan.commit && result.snapshotHash === plan.snapshotHash, 'ai_artifacts_not_accepted');
  const copies = []; let total = 0;
  for (const input of array(result.artifacts)) {
    const entry = record(input), name = safeRelative(entry.path);
    requireValue(count(entry.bytes) && /^[a-f0-9]{64}$/.test(entry.sha256) && !copies.some(copy => copy.path === name), 'ai_artifact_identity');
    total += entry.bytes; requireValue(count(total) && total <= maxBytes, 'ai_artifact_limit');
    const bytes = await readAiFile(path.join(directory, 'artifacts', ...name.split('/')), entry.bytes, control);
    requireValue(bytes.length === entry.bytes && hash(bytes) === entry.sha256, 'ai_artifact_identity');
    copies.push({ path: name, bytes, sha256: entry.sha256 });
  }
  return validateAiArtifactDocuments(copies, result, plan, maxBytes);
}
/** Validate copied documents before acceptance, using identities owned by the host. */
export function validateAiArtifactDocuments(copies, result, plan, maxBytes) {
  requireValue(result.originalCommit === plan.commit && result.snapshotHash === plan.snapshotHash, 'ai_artifact_identity');
  const documents = new Map(), descriptors = []; let total = 0;
  for (const input of array(copies)) {
    const entry = record(input), name = safeRelative(entry.path);
    requireValue(Buffer.isBuffer(entry.bytes) && /^[a-f0-9]{64}$/.test(entry.sha256) && !documents.has(name) && hash(entry.bytes) === entry.sha256, 'ai_artifact_identity');
    total += entry.bytes.length; requireValue(count(total) && total <= maxBytes, 'ai_artifact_limit');
    documents.set(name, entry.bytes); descriptors.push({ path: name, bytes: entry.bytes.length, sha256: entry.sha256 });
  }
  const json = name => { const bytes = documents.get(name); requireValue(bytes, 'ai_artifact_missing'); try { return record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); } catch { throw new SafeError('ai_artifact_json'); } };
  const manifest = json('scan-manifest.json'), findings = json('findings.json'), coverage = json('coverage.json'), scan = record(manifest.scan), scope = record(scan.scope);
  requireValue(manifest.documentType === 'codex-security.scan-manifest' && manifest.schemaVersion === '1.0' && scan.id === result.scanId && scan.status === 'completed'
    && record(scan.target).revision === result.derivedRevision && findings.documentType === 'codex-security.findings' && findings.schemaVersion === '1.0' && findings.scanId === result.scanId, 'ai_artifact_identity');
  const reviewed = array(scope.artifactsReviewed).map(safeRelative), wanted = plan.files.map(file => file.path).sort();
  requireValue(reviewed.length === new Set(reviewed).size && isDeepStrictEqual([...reviewed].sort(), wanted)
    && isDeepStrictEqual(scope.includePaths, ['.']) && isDeepStrictEqual(scope.excludePaths, []), 'ai_scope_identity');
  const allowedKeys = ['documentType','schemaVersion','scanId','mode','inventoryStrategy','includePaths','excludePaths','surfaces','explicitExclusions','deferred','resolvedDeferred','openQuestions'];
  requireValue(Object.keys(coverage).every(key => allowedKeys.includes(key)) && coverage.documentType === 'codex-security.coverage' && coverage.schemaVersion === '1.0' && coverage.scanId === result.scanId
    && coverage.mode === 'repository' && coverage.inventoryStrategy === 'repository' && isDeepStrictEqual(coverage.includePaths, ['.']) && isDeepStrictEqual(coverage.excludePaths, []), 'ai_scope_identity');
  const surfaces = array(coverage.surfaces).map(record), ids = new Set();
  for (const surface of surfaces) {
    requireValue(typeof surface.id === 'string' && surface.id.length > 0 && !ids.has(surface.id) && typeof surface.label === 'string' && surface.label.length > 0
      && ['reported','no_issue_found','rejected','not_applicable','needs_follow_up'].includes(surface.disposition), 'ai_scope_identity'); ids.add(surface.id);
    for (const reference of array(surface.receiptRefs)) requireValue(typeof reference === 'string' && documents.has(safeRelative(reference)), 'ai_scope_identity');
  }
  const exclusions = array(coverage.explicitExclusions), deferred = array(coverage.deferred), questions = array(coverage.openQuestions ?? []), limitations = array(scope.limitations);
  for (const value of exclusions) { const item = record(value); requireValue(typeof item.pattern === 'string' && item.pattern.length > 0 && typeof item.reason === 'string' && item.reason.length > 0, 'ai_scope_identity'); }
  for (const value of deferred) { const item = record(value); requireValue(typeof item.id === 'string' && item.id.length > 0 && typeof item.reason === 'string' && item.reason.length > 0, 'ai_scope_identity'); }
  for (const value of questions) requireValue(typeof record(value).question === 'string' && value.question.length > 0, 'ai_scope_identity');
  requireValue(limitations.every(value => typeof value === 'string' && value.length > 0), 'ai_scope_identity');
  const reasons = [];
  if (!surfaces.length || surfaces.some(surface => surface.disposition === 'needs_follow_up')) reasons.push('ai_scope_incomplete');
  if (exclusions.length) reasons.push('ai_scope_exclusions'); if (deferred.length) reasons.push('ai_scope_deferred'); if (questions.length) reasons.push('ai_scope_open_questions'); if (limitations.length) reasons.push('ai_scope_limitations');
  return { manifest, findings, descriptors, reasons, observation: { artifactsReviewed: reviewed.length, exclusions: exclusions.length, deferred: deferred.length, openQuestions: questions.length, limitations: limitations.length, sha256: digest({ coverage, scope }) } };
}
