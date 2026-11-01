import { randomBytes } from 'node:crypto';
import { lstat, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Config } from './model.ts';
import { checkedJson } from './output.ts';
import { commitFacts, type CommitFacts } from './repository.ts';
import { boundedRead, canonical, digest, hash, SafeError, safeRelative, within } from './safety.ts';

export type { CommitFacts } from './repository.ts';
export type ImportTool = 'osv-scanner' | 'gitleaks';
export type RejectReason = 'over_limit' | 'results_over_limit' | 'invalid_utf8' | 'invalid_json' | 'unsupported_schema' | 'record_digest_mismatch' | 'record_repository_mismatch'
  | 'record_inconsistent' | 'record_empty' | 'unsupported_tool' | 'invalid_shape';
export type FieldReason = 'level_unavailable' | 'line_unavailable' | 'location_base_unresolved' | 'location_outside_repository' | 'location_unavailable' | 'multiple_locations'
  | 'package_unavailable' | 'rule_unavailable';
export type Relation = 'head' | 'stale_commit' | 'sha_mismatch' | 'commit_unavailable';
export type ObservationReason = FieldReason | Relation | 'tool_version_unrecorded' | 'tool_reported_incomplete' | 'execution_unrecorded'
  | 'sha_missing' | 'mixed_sha' | 'recorded_sha_unreadable' | 'declaration_conflict' | 'input_rebound' | 'referenced_paths_absent' | 'worktree_dirty_at_import';
export type RecordReason = 'record_carries_rejected';
export type ImportInput = { readonly kind: 'bytes'; readonly bytes: Buffer } | { readonly kind: 'over_limit'; readonly bytes: number };
export type Level = 'error' | 'warning' | 'note' | 'none';
export interface Basis { readonly kind: 'recorded' | 'declared' | 'unbound'; readonly commit: string | null }
export interface Execution { readonly successful: number; readonly failed: number; readonly unrecorded: number; readonly notifications: number }
export interface LevelSources { readonly explicit: number; readonly ruleDefault: number; readonly sarifDefault: number }
export interface Observation {
  readonly importId: string; readonly tool: ImportTool; readonly recordedToolVersion: string | null;
  readonly inputSha256: string; readonly inputBytes: number;
  readonly recordedCommits: readonly string[]; readonly unreadableRevisions: number; readonly declaredCommits: readonly string[]; readonly basis: Basis;
  readonly importedAt: string; readonly headAtImport: string; readonly dirtyAtImport: boolean;
  readonly execution: Execution;
  readonly results: number; readonly levelSources: LevelSources; readonly fieldReasons: readonly { readonly reason: FieldReason; readonly count: number }[];
}
export interface PackageIdentity { readonly ecosystem: 'npm' | 'PyPI'; readonly name: string; readonly version: string }
export interface LevelCount { readonly level: Level | null; readonly count: number }
export interface OccurrenceImport { readonly importId: string; readonly count: number; readonly levels: readonly LevelCount[] }
export interface Occurrence { readonly commit: string | null; readonly count: number; readonly imports: readonly OccurrenceImport[] }
export interface Finding {
  readonly findingId: string; readonly tool: ImportTool; readonly ruleId: string | null;
  readonly path: string | null; readonly startLine: number | null; readonly package: PackageIdentity | null; readonly occurrences: readonly Occurrence[];
}
/** An input refused before it was read has no content hash; unreadId tells such inputs apart by the run and position that refused them. */
export interface Rejection { readonly sha256: string | null; readonly bytes: number; readonly reason: RejectReason; readonly unreadId: string | null }
export interface InputRow {
  readonly input: number; readonly kind: 'sarif' | 'record' | null; readonly sha256: string | null; readonly bytes: number;
  readonly state: 'accepted' | 'rejected' | 'duplicate';
  readonly reasons: readonly (RejectReason | ObservationReason | RecordReason | 'duplicate_input')[]; readonly importIds: readonly string[];
}
export interface ObservationView { readonly importId: string; readonly relation: Relation | null; readonly reasons: readonly ObservationReason[]; readonly absentPaths: number }
export interface ImportRecord {
  readonly schema: typeof recordSchema;
  readonly effect: { readonly gate: 'unchanged'; readonly substitutesEngine: false; readonly scanVerified: false };
  readonly rawRetained: false;
  readonly facts: { readonly repoId: string; readonly observations: readonly Observation[]; readonly findings: readonly Finding[]; readonly rejected: readonly Rejection[] };
  readonly factsDigest: string;
  readonly view: {
    readonly head: string; readonly dirty: boolean; readonly importedAt: string; readonly inputs: readonly InputRow[]; readonly observations: readonly ObservationView[];
    readonly counts: { readonly inputs: number; readonly accepted: number; readonly duplicate: number; readonly rejected: number; readonly observations: number; readonly findings: number; readonly occurrences: number };
    readonly exitCode: 0 | 3;
  };
}
type Pending = Omit<Observation, 'importedAt' | 'headAtImport' | 'dirtyAtImport'> & Partial<Pick<Observation, 'importedAt' | 'headAtImport' | 'dirtyAtImport'>>;
type FindingCore = Omit<Finding, 'occurrences'>;
type Owned = { readonly count: number; readonly levels: readonly LevelCount[] };
interface ParsedRow {
  readonly input: number; readonly kind: InputRow['kind']; readonly sha256: string | null; readonly bytes: number; readonly reasons: readonly RejectReason[];
  readonly importIds: readonly string[]; readonly duplicates: number; readonly recordReasons: readonly RecordReason[];
}
export interface ParsedImports {
  readonly repoId: string; readonly rows: readonly ParsedRow[]; readonly observations: readonly Pending[];
  readonly findings: ReadonlyMap<string, { readonly core: FindingCore; readonly counts: ReadonlyMap<string, Owned> }>;
  readonly rejected: readonly Rejection[];
  /** Per basis commit, the paths that its own observations reference. */
  readonly wanted: ReadonlyMap<string, readonly string[]>;
}

const recordSchema = 'scanmux.import/v2';
const tools: readonly ImportTool[] = ['osv-scanner', 'gitleaks'];
const levels: readonly Level[] = ['error', 'warning', 'note', 'none'];
const fieldReasons: readonly FieldReason[] = ['level_unavailable', 'line_unavailable', 'location_base_unresolved', 'location_outside_repository', 'location_unavailable', 'multiple_locations',
  'package_unavailable', 'rule_unavailable'];
const locationReasons: readonly FieldReason[] = ['location_base_unresolved', 'location_outside_repository', 'location_unavailable', 'multiple_locations'];
const rejectReasons: readonly RejectReason[] = ['over_limit', 'results_over_limit', 'invalid_utf8', 'invalid_json', 'unsupported_schema', 'record_digest_mismatch', 'record_repository_mismatch',
  'record_inconsistent', 'record_empty', 'unsupported_tool', 'invalid_shape'];
const effect = { gate: 'unchanged', substitutesEngine: false, scanVerified: false } as const;
const sha40 = /^[a-f0-9]{40}$/, sha64 = /^[a-f0-9]{64}$/, versionPattern = /^v?\d{1,9}(?:\.\d{1,9}){1,3}(?:[-+][0-9A-Za-z.-]{1,64})?$/;
const timestampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ruleGrammar: Readonly<Record<ImportTool, RegExp>> = {
  'osv-scanner': /^[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9._]+)+$/,
  gitleaks: /^[A-Za-z0-9][A-Za-z0-9._-]*$/,
};
const maxDepth = 64;

class Rejected extends Error {
  readonly reason: RejectReason;
  constructor(reason: RejectReason) { super(reason); this.reason = reason; }
}
function reject(reason: RejectReason): never { throw new Rejected(reason); }
function shape(condition: unknown): asserts condition { if (!condition) reject('invalid_shape'); }
function consistent(condition: unknown): asserts condition { if (!condition) reject('record_inconsistent'); }
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const optionalArray = (value: unknown): unknown[] => { if (value === undefined) return []; shape(Array.isArray(value)); return value as unknown[]; };
const sameJson = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right);
const order = (left: string | null, right: string | null) => left === right ? 0 : left === null ? 1 : right === null ? -1 : left < right ? -1 : 1;
const importIdOf = (inputSha256: string, basis: Basis) => digest(['import/v1', inputSha256, basis.kind, basis.commit]);
const ruleOf = (tool: ImportTool, value: unknown): string | null => typeof value === 'string' && value.length <= 200 && ruleGrammar[tool].test(value) ? value : null;
type Identity = Omit<FindingCore, 'findingId'>;
const identityComplete = (identity: Identity) => identity.ruleId !== null
  && (identity.tool === 'osv-scanner' ? identity.package !== null : identity.path !== null && identity.startLine !== null);
const findingIdOf = (identity: Identity, resultDigest: string | null) =>
  digest(['import/v1', identity.tool, identity.ruleId, identity.path, identity.startLine, identity.package, ...resultDigest === null ? [] : [resultDigest]]);
const keysSorted = (value: unknown): unknown => Array.isArray(value) ? value.map(keysSorted)
  : isObject(value) ? Object.fromEntries(Object.keys(value).sort().map(key => [key, keysSorted(value[key])])) : value;
const levelRank = (level: Level | null) => level === null ? levels.length : levels.indexOf(level);
const levelCounts = (counts: ReadonlyMap<Level | null, number>): LevelCount[] =>
  [...counts].sort(([left], [right]) => levelRank(left) - levelRank(right)).map(([level, count]) => ({ level, count }));

const lockfileEcosystems = new Map<string, PackageIdentity['ecosystem']>([['package-lock.json', 'npm'], ['uv.lock', 'PyPI']]);
// dependency-syntax.ts stays private to dependency-graph.ts, and its version subsets refuse prereleases that advisories name.
const packageGrammar = {
  npm: {
    name: /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9_~-][a-z0-9._~-]*$/i,
    version: /^(?:0|[1-9]\d{0,14})\.(?:0|[1-9]\d{0,14})\.(?:0|[1-9]\d{0,14})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
  },
  PyPI: {
    name: /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/,
    version: /^\d{1,15}(?:\.\d{1,15}){0,5}(?:(?:a|b|rc)\d{1,15})?(?:\.post\d{1,15})?(?:\.dev\d{1,15})?(?:\+[a-z0-9]+(?:\.[a-z0-9]+)*)?$/,
  },
} as const;
function packageOf(ecosystem: PackageIdentity['ecosystem'], name: string, version: string): PackageIdentity | null {
  const grammar = packageGrammar[ecosystem];
  return name.length <= 214 && version.length <= 128 && grammar.name.test(name) && grammar.version.test(version) ? { ecosystem, name, version } : null;
}
const osvMessage = /^Package '((?:@[^'@/]+\/)?[^'@/]+)@([^'@]+)' is vulnerable to '([A-Za-z0-9._:-]{1,200})'(?: \(also known as '[A-Za-z0-9._:-]{1,200}'\))?\.$/;
function osvPackage(message: unknown, ruleId: string | null, location: string | null): PackageIdentity | null {
  const ecosystem = location === null ? undefined : lockfileEcosystems.get(path.posix.basename(location));
  const text = isObject(message) ? message.text : undefined;
  const match = ecosystem && ruleId !== null && typeof text === 'string' ? osvMessage.exec(text) : null;
  return match && match[3] === ruleId ? packageOf(ecosystem!, match[1], match[2]) : null;
}

// JSON.parse keeps the last of duplicate keys and has no depth bound, so the input grammar is parsed here.
function parseJson(text: string): unknown {
  let at = 0;
  const token = /"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/y;
  const space = () => { while (at < text.length && ' \t\n\r'.includes(text[at])) at++; };
  const literal = (): unknown => {
    token.lastIndex = at;
    const match = token.exec(text);
    if (!match) reject('invalid_json');
    at = token.lastIndex;
    return JSON.parse(match![0]);
  };
  const expect = (char: string) => { space(); if (text[at++] !== char) reject('invalid_json'); };
  function value(depth: number): unknown {
    if (depth > maxDepth) reject('invalid_json');
    space();
    if (text[at] === '[') {
      at++; const items: unknown[] = []; space();
      if (text[at] === ']') { at++; return items; }
      for (;;) { items.push(value(depth + 1)); space(); const next = text[at++]; if (next === ']') return items; if (next !== ',') reject('invalid_json'); }
    }
    if (text[at] !== '{') return literal();
    at++; const object: Record<string, unknown> = Object.create(null); space();
    if (text[at] === '}') { at++; return object; }
    for (;;) {
      space(); if (text[at] !== '"') reject('invalid_json');
      const key = literal() as string;
      if (Object.hasOwn(object, key)) reject('invalid_json');
      expect(':'); object[key] = value(depth + 1); space();
      const next = text[at++]; if (next === '}') return object; if (next !== ',') reject('invalid_json');
    }
  }
  const result = value(0); space();
  if (at !== text.length) reject('invalid_json');
  return result;
}

type Located = { readonly path: string | null; readonly reason: FieldReason | null };
function repositoryPath(uri: unknown, root: string): Located {
  const unavailable = { path: null, reason: 'location_unavailable' } as const;
  if (typeof uri !== 'string' || !uri || uri.length > 4096) return unavailable;
  const contained = (absolute: string): Located => {
    if (!path.isAbsolute(absolute)) return unavailable;
    const resolved = path.resolve(absolute);
    if (!within(root, resolved)) return { path: null, reason: 'location_outside_repository' };
    const relative = path.relative(root, resolved).split(path.sep).join('/');
    try { return { path: safeRelative(relative), reason: null }; } catch { return unavailable; }
  };
  if (/^file:/i.test(uri)) { try { return contained(fileURLToPath(uri)); } catch { return unavailable; } }
  if (/^(?:\\\\|\/\/)/.test(uri)) return unavailable;
  // Gitleaks writes local absolute paths where SARIF expects a URI.
  if (/^[A-Za-z]:[\\/]/.test(uri) || uri.startsWith('/')) return contained(uri);
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) || uri.startsWith('\\')) return unavailable;
  let decoded: string;
  try { decoded = decodeURIComponent(uri.split(/[?#]/)[0]); } catch { return unavailable; }
  return contained(path.resolve(root, decoded.replace(/\\/g, '/')));
}

type LevelSource = keyof LevelSources;
/** 'absent' is a readable rule list without the rule; 'unreadable' is a reference or rule entry that cannot be read, so the rule may exist. */
type RuleLookup = { readonly rule: Record<string, unknown> } | 'absent' | 'unreadable';
type RuleOf = (index: unknown, id: unknown) => RuleLookup;
const closedLevel = (value: unknown): Level | null => levels.find(item => item === value) ?? null;
const levelUnknown = { level: null, source: null } as const;
/** SARIF 2.1.0 §3.27.10: an absent level is the rule's defaultConfiguration.level, else warning; a present but unreadable value or rule is unknown. */
function levelOf(result: Record<string, unknown>, ruleAt: RuleOf): { level: Level | null; source: LevelSource | null } {
  if (result.level !== undefined) { const level = closedLevel(result.level); return { level, source: level === null ? null : 'explicit' }; }
  if (result.rule !== undefined && !isObject(result.rule)) return levelUnknown;
  const reference = isObject(result.rule) ? result.rule : {};
  // A reference into an extension's rules cannot be resolved against the driver's rules.
  const index = result.ruleIndex ?? (reference.toolComponent === undefined ? reference.index : undefined);
  const found = ruleAt(index, result.ruleId ?? reference.id);
  if (found === 'unreadable') return levelUnknown;
  const configuration = found === 'absent' ? undefined : found.rule.defaultConfiguration;
  const configured = configuration === undefined ? undefined : isObject(configuration) ? configuration.level : null;
  if (configured === undefined) return { level: 'warning', source: 'sarifDefault' };
  const level = closedLevel(configured);
  return { level, source: level === null ? null : 'ruleDefault' };
}
function rulesOf(driver: Record<string, unknown>): RuleOf {
  const rules = optionalArray(driver.rules), byId = new Map<string, Record<string, unknown>>();
  let unreadable = false;
  for (const rule of rules) {
    if (isObject(rule) && typeof rule.id === 'string') { if (!byId.has(rule.id)) byId.set(rule.id, rule); } else unreadable = true;
  }
  return (index, id) => {
    // SARIF 2.1.0 §3.27.6: -1 means no index; an index past the list falls back to the ruleId.
    if (index !== undefined && index !== -1) {
      if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 0) return 'unreadable';
      if (index < rules.length) return isObject(rules[index]) ? { rule: rules[index] as Record<string, unknown> } : 'unreadable';
    }
    const rule = typeof id === 'string' ? byId.get(id) : undefined;
    return rule ? { rule } : unreadable ? 'unreadable' : 'absent';
  };
}

function readResult(input: unknown, tool: ImportTool, root: string, ruleAt: RuleOf): { core: FindingCore; level: Level | null; source: LevelSource | null; reasons: FieldReason[] } {
  shape(isObject(input));
  const result = input as Record<string, unknown>, reasons: FieldReason[] = [];
  const ruleId = ruleOf(tool, result.ruleId);
  if (ruleId === null) reasons.push('rule_unavailable');
  const { level, source } = levelOf(result, ruleAt);
  if (level === null) reasons.push('level_unavailable');
  const locations = Array.isArray(result.locations) ? result.locations : [];
  let located: Located = { path: null, reason: 'location_unavailable' }, startLine: number | null = null;
  if (locations.length > 1) located = { path: null, reason: 'multiple_locations' };
  else if (locations.length === 1 && isObject(locations[0]) && isObject(locations[0].physicalLocation)) {
    const physical = locations[0].physicalLocation, artifact = isObject(physical.artifactLocation) ? physical.artifactLocation : {};
    located = artifact.uriBaseId !== undefined ? { path: null, reason: 'location_base_unresolved' } : repositoryPath(artifact.uri, root);
    const line = isObject(physical.region) ? physical.region.startLine : undefined;
    if (typeof line === 'number' && Number.isSafeInteger(line) && line > 0) startLine = line;
  }
  if (located.reason) reasons.push(located.reason);
  if (startLine === null) reasons.push('line_unavailable');
  // OSV-Scanner SARIF carries the package only inside a fixed message sentence; nothing else of the message is kept.
  const found = tool === 'osv-scanner' ? osvPackage(result.message, ruleId, located.path) : null;
  if (tool === 'osv-scanner' && !found) reasons.push('package_unavailable');
  const identity: Identity = { tool, ruleId, path: located.path, startLine, package: found };
  const findingId = findingIdOf(identity, identityComplete(identity) ? null : hash(JSON.stringify(keysSorted(result))));
  return { core: { findingId, ...identity }, level, source, reasons };
}

interface Read { readonly observation: Pending; readonly findings: readonly { readonly core: FindingCore; readonly owned: Owned }[] }
/** Null when the declared and recorded commits cannot come from one import, which only a saved record can present. */
function basisOf(recorded: readonly string[], declared: readonly string[]): { basis: Basis; reasons: ObservationReason[] } | null {
  const reasons: ObservationReason[] = declared.some(commit => recorded.some(other => other !== commit)) ? ['declaration_conflict'] : [];
  if (recorded.length > 1) return { basis: { kind: 'unbound', commit: null }, reasons: ['mixed_sha', ...reasons] };
  if (recorded.length === 1) return { basis: { kind: 'recorded', commit: recorded[0] }, reasons };
  if (declared.length === 1) return { basis: { kind: 'declared', commit: declared[0] }, reasons };
  return declared.length ? null : { basis: { kind: 'unbound', commit: null }, reasons: ['sha_missing'] };
}
function readSarif(top: Record<string, unknown>, bytes: Buffer, root: string, declared: string | null, maxFiles: number): Read {
  if (top.version !== '2.1.0' || !Array.isArray(top.runs) || top.runs.length !== 1) reject('unsupported_schema');
  const run = (top.runs as unknown[])[0];
  shape(isObject(run) && isObject(run.tool) && isObject(run.tool.driver) && typeof run.tool.driver.name === 'string');
  const { tool: toolBlock, results, versionControlProvenance, invocations } = run as Record<string, unknown>;
  const driver = (toolBlock as Record<string, Record<string, unknown>>).driver;
  const tool = tools.find(value => value === driver.name) ?? reject('unsupported_tool');
  shape(Array.isArray(results));
  if ((results as unknown[]).length > maxFiles) reject('results_over_limit');
  const readable = new Set<string>();
  let unreadableRevisions = 0;
  for (const entry of optionalArray(versionControlProvenance)) {
    shape(isObject(entry));
    const revision = (entry as Record<string, unknown>).revisionId;
    if (typeof revision === 'string' && sha40.test(revision)) readable.add(revision);
    else if (revision !== undefined) unreadableRevisions++;
  }
  const recorded = [...readable].sort();
  const execution = { successful: 0, failed: 0, unrecorded: 0, notifications: 0 };
  for (const entry of optionalArray(invocations)) {
    shape(isObject(entry));
    const invocation = entry as Record<string, unknown>;
    shape(invocation.executionSuccessful === undefined || typeof invocation.executionSuccessful === 'boolean');
    if (invocation.executionSuccessful === true) execution.successful++;
    else if (invocation.executionSuccessful === false) execution.failed++;
    else execution.unrecorded++;
    execution.notifications += optionalArray(invocation.toolExecutionNotifications).length + optionalArray(invocation.toolConfigurationNotifications).length;
  }
  const version = [driver.version, driver.semanticVersion].find(value => typeof value === 'string' && versionPattern.test(value)) as string | undefined;
  const declaredCommits = declared ? [declared] : [];
  const { basis } = basisOf(recorded, declaredCommits)!;
  const inputSha256 = hash(bytes), importId = importIdOf(inputSha256, basis);
  const counts = new Map<FieldReason, number>(), findings = new Map<string, { core: FindingCore; count: number; levels: Map<Level | null, number> }>();
  const ruleAt = rulesOf(driver), levelSources = { explicit: 0, ruleDefault: 0, sarifDefault: 0 };
  for (const entry of results as unknown[]) {
    const { core, level, source, reasons } = readResult(entry, tool, root, ruleAt);
    if (source) levelSources[source]++;
    for (const reason of reasons) counts.set(reason, (counts.get(reason) ?? 0) + 1);
    const existing = findings.get(core.findingId) ?? { core, count: 0, levels: new Map<Level | null, number>() };
    existing.count++;
    existing.levels.set(level, (existing.levels.get(level) ?? 0) + 1);
    findings.set(core.findingId, existing);
  }
  const observation: Pending = {
    importId, tool, recordedToolVersion: version ?? null, inputSha256, inputBytes: bytes.length, recordedCommits: recorded, unreadableRevisions, declaredCommits, basis,
    execution, results: (results as unknown[]).length, levelSources,
    fieldReasons: fieldReasons.filter(reason => counts.has(reason)).map(reason => ({ reason, count: counts.get(reason)! })),
  };
  return { observation, findings: [...findings.values()].map(({ core, count, levels: seen }) => ({ core, owned: { count, levels: levelCounts(seen) } })) };
}

const optional = <T>(value: unknown, check: (input: unknown) => T): T | null => value === null ? null : check(value);
const text = (pattern: RegExp) => (value: unknown): string => { shape(typeof value === 'string' && pattern.test(value)); return value as string; };
const positive = (value: unknown): number => { shape(typeof value === 'number' && Number.isSafeInteger(value) && value > 0); return value as number; };
const count = (value: unknown): number => { shape(typeof value === 'number' && Number.isSafeInteger(value) && value >= 0); return value as number; };
const member = <T extends string>(values: readonly T[]) => (value: unknown): T => { shape(values.includes(value as T)); return value as T; };
const list = (value: unknown): unknown[] => { shape(Array.isArray(value) && value.length <= 100000); return value as unknown[]; };
const bool = (value: unknown): boolean => { shape(typeof value === 'boolean'); return value; };
const fields = (value: unknown): Record<string, unknown> => { shape(isObject(value)); return value as Record<string, unknown>; };
const sortedUnique = (values: readonly string[]) => sameJson(values, [...new Set(values)].sort());
function savedObservation(value: unknown, maxFiles: number): Observation {
  const input = fields(value), basis = fields(input.basis), execution = fields(input.execution), sources = fields(input.levelSources);
  const recordedCommits = list(input.recordedCommits).map(text(sha40)), declaredCommits = list(input.declaredCommits).map(text(sha40));
  shape(sortedUnique(recordedCommits) && sortedUnique(declaredCommits));
  const observation: Observation = {
    importId: text(sha64)(input.importId), tool: member(tools)(input.tool), recordedToolVersion: optional(input.recordedToolVersion, text(versionPattern)),
    inputSha256: text(sha64)(input.inputSha256), inputBytes: positive(input.inputBytes), recordedCommits, unreadableRevisions: count(input.unreadableRevisions), declaredCommits,
    basis: { kind: member(['recorded', 'declared', 'unbound'] as const)(basis.kind), commit: optional(basis.commit, text(sha40)) },
    importedAt: text(timestampPattern)(input.importedAt), headAtImport: text(sha40)(input.headAtImport), dirtyAtImport: bool(input.dirtyAtImport),
    execution: { successful: count(execution.successful), failed: count(execution.failed), unrecorded: count(execution.unrecorded), notifications: count(execution.notifications) },
    results: count(input.results),
    levelSources: { explicit: count(sources.explicit), ruleDefault: count(sources.ruleDefault), sarifDefault: count(sources.sarifDefault) },
    fieldReasons: list(input.fieldReasons).map(entry => { const item = fields(entry); return { reason: member(fieldReasons)(item.reason), count: positive(item.count) }; }),
  };
  shape(sameJson(observation, input));
  shape(sameJson(observation.fieldReasons.map(item => item.reason), fieldReasons.filter(reason => observation.fieldReasons.some(item => item.reason === reason))));
  if (observation.results > maxFiles) reject('results_over_limit');
  const derived = basisOf(recordedCommits, declaredCommits);
  consistent(derived && sameJson(observation.basis, derived.basis) && observation.importId === importIdOf(observation.inputSha256, observation.basis));
  consistent(observation.fieldReasons.every(item => item.count <= observation.results));
  const { explicit, ruleDefault, sarifDefault } = observation.levelSources;
  const unknownLevels = observation.fieldReasons.find(item => item.reason === 'level_unavailable')?.count ?? 0;
  consistent(explicit + ruleDefault + sarifDefault + unknownLevels === observation.results);
  return observation;
}
function savedFinding(value: unknown): Finding {
  const input = fields(value);
  const tool = member(tools)(input.tool);
  const identity: Identity = {
    tool, ruleId: optional(input.ruleId, value => ruleOf(tool, value) ?? reject('invalid_shape')),
    path: optional(input.path, value => { shape(typeof value === 'string'); try { return safeRelative(value); } catch { return reject('invalid_shape'); } }),
    startLine: optional(input.startLine, positive), package: optional(input.package, value => {
      const item = fields(value), ecosystem = member(['npm', 'PyPI'] as const)(item.ecosystem);
      shape(typeof item.name === 'string' && typeof item.version === 'string');
      return packageOf(ecosystem, item.name as string, item.version as string) ?? reject('invalid_shape');
    }),
  };
  shape(identity.tool === 'osv-scanner' || identity.package === null);
  // A package is only ever read together with its advisory id from a lockfile of the package's ecosystem.
  consistent(identity.package === null || (identity.ruleId !== null && identity.path !== null
    && lockfileEcosystems.get(path.posix.basename(identity.path)) === identity.package.ecosystem));
  const finding: Finding = {
    findingId: text(sha64)(input.findingId), ...identity,
    occurrences: list(input.occurrences).map(entry => {
      const item = fields(entry);
      const imports = list(item.imports).map(entry => {
        const value = fields(entry);
        const seen = list(value.levels).map(entry => { const level = fields(entry); return { level: optional(level.level, member(levels)), count: positive(level.count) }; });
        shape(seen.length > 0 && sameJson(seen.map(item => levelRank(item.level)), [...new Set(seen.map(item => levelRank(item.level)))].sort((left, right) => left - right)));
        return { importId: text(sha64)(value.importId), count: positive(value.count), levels: seen };
      });
      return { commit: optional(item.commit, text(sha40)), count: positive(item.count), imports };
    }),
  };
  shape(sameJson(finding, input) && finding.occurrences.length > 0 && finding.occurrences.every(item => item.imports.length > 0));
  // The digest of an incomplete identity covers the raw result, which is not retained, so only a complete identity is recomputed.
  consistent(!identityComplete(identity) || finding.findingId === findingIdOf(identity, null));
  for (const item of finding.occurrences) {
    consistent(item.count === item.imports.reduce((total, entry) => total + entry.count, 0));
    for (const entry of item.imports) consistent(entry.count === entry.levels.reduce((total, level) => total + level.count, 0));
  }
  return finding;
}
function savedRejection(value: unknown): Rejection {
  const input = fields(value);
  const rejection: Rejection = {
    sha256: optional(input.sha256, text(sha64)), bytes: count(input.bytes), reason: member(rejectReasons)(input.reason), unreadId: optional(input.unreadId, text(sha64)),
  };
  shape(sameJson(rejection, input));
  // Only the byte limit refuses an input before it is read; the result-count limit and every other reason come after reading it.
  consistent((rejection.sha256 === null) === (rejection.reason === 'over_limit') && (rejection.unreadId === null) === (rejection.sha256 !== null));
  return rejection;
}
/** Field reasons follow from the findings an observation owns: null rule, line, level and package one-to-one, and one location reason per null path. */
function expectedFieldCounts(tool: ImportTool, owned: readonly { core: FindingCore; owned: Owned }[]): { exact: Map<FieldReason, number>; locations: number } {
  const exact = new Map<FieldReason, number>();
  let locations = 0;
  const add = (reason: FieldReason, amount: number) => { if (amount) exact.set(reason, (exact.get(reason) ?? 0) + amount); };
  for (const { core, owned: { count, levels: seen } } of owned) {
    if (core.ruleId === null) add('rule_unavailable', count);
    if (core.startLine === null) add('line_unavailable', count);
    if (tool === 'osv-scanner' && core.package === null) add('package_unavailable', count);
    add('level_unavailable', seen.find(item => item.level === null)?.count ?? 0);
    if (core.path === null) locations += count;
  }
  return { exact, locations };
}
function readRecord(top: Record<string, unknown>, repoId: string, maxFiles: number): { reads: Read[]; rejected: Rejection[] } {
  if (top.schema !== recordSchema) reject('unsupported_schema');
  shape(sameJson(Object.keys(top), ['schema', 'effect', 'rawRetained', 'facts', 'factsDigest', 'view']) && sameJson(top.effect, effect) && top.rawRetained === false && isObject(top.view));
  if (top.factsDigest !== digest(top.facts)) reject('record_digest_mismatch');
  const facts = fields(top.facts);
  shape(sameJson(Object.keys(facts), ['repoId', 'observations', 'findings', 'rejected']));
  if (facts.repoId !== repoId) reject('record_repository_mismatch');
  const observations = list(facts.observations).map(entry => savedObservation(entry, maxFiles)), findings = list(facts.findings).map(savedFinding);
  const rejected = list(facts.rejected).map(savedRejection);
  shape(sameJson(rejected, canonicalRejections(rejected)));
  // importResults always records at least one input, so a record without observations or rejections cannot come from it.
  if (!observations.length && !rejected.length) reject('record_empty');
  consistent(new Set(observations.map(item => item.importId)).size === observations.length && new Set(findings.map(item => item.findingId)).size === findings.length);
  const byImport = new Map(observations.map(item => [item.importId, { observation: item, findings: [] as { core: FindingCore; owned: Owned }[] }]));
  for (const { occurrences, ...core } of findings) {
    for (const occurrence of occurrences) for (const { importId, ...owned } of occurrence.imports) {
      const owner = byImport.get(importId);
      consistent(owner && owner.observation.basis.commit === occurrence.commit && owner.observation.tool === core.tool && !owner.findings.some(item => item.core.findingId === core.findingId));
      owner!.findings.push({ core, owned });
    }
  }
  for (const { observation, findings: owned } of byImport.values()) {
    consistent(owned.reduce((total, item) => total + item.owned.count, 0) === observation.results);
    const { exact, locations } = expectedFieldCounts(observation.tool, owned);
    const stored = new Map(observation.fieldReasons.map(item => [item.reason, item.count]));
    consistent(fieldReasons.filter(reason => !locationReasons.includes(reason)).every(reason => (stored.get(reason) ?? 0) === (exact.get(reason) ?? 0)));
    consistent(locationReasons.reduce((total, reason) => total + (stored.get(reason) ?? 0), 0) === locations);
    const warnings = owned.reduce((total, item) => total + (item.owned.levels.find(entry => entry.level === 'warning')?.count ?? 0), 0);
    consistent(observation.levelSources.sarifDefault <= warnings);
  }
  return { reads: [...byImport.values()].map(({ observation, findings: owned }) => ({ observation, findings: owned })), rejected };
}
const rejectionOrder = (left: Rejection, right: Rejection) => order(left.sha256, right.sha256) || left.bytes - right.bytes || order(left.reason, right.reason)
  || order(left.unreadId, right.unreadId);
function canonicalRejections(values: readonly Rejection[]): Rejection[] {
  return [...new Map(values.map(item => [JSON.stringify(item), item])).values()].sort(rejectionOrder);
}
/** Everything an import's bytes determine, so two reads of one importId can be compared apart from declarations and import-time stamps. */
function contentKey({ observation, findings }: Read): string {
  const { importId, tool, recordedToolVersion, inputSha256, inputBytes, recordedCommits, unreadableRevisions, basis, execution, results, levelSources, fieldReasons: reasons } = observation;
  return digest([[importId, tool, recordedToolVersion, inputSha256, inputBytes, recordedCommits, unreadableRevisions, basis, execution, results, levelSources, reasons],
    [...findings].sort((left, right) => order(left.core.findingId, right.core.findingId))]);
}
/** Reads of one importId agree on content; declarations are united and the earliest stamp is kept, so input order changes no fact. */
function mergeReads(reads: readonly Read[]): Read {
  const stamped = reads.map(item => item.observation).filter(item => item.importedAt !== undefined)
    .sort((left, right) => order(left.importedAt!, right.importedAt!) || order(left.headAtImport!, right.headAtImport!));
  const first = reads[0].observation;
  const declaredCommits = [...new Set(reads.flatMap(item => item.observation.declaredCommits))].sort();
  const stamp = stamped.length ? { importedAt: stamped[0].importedAt, headAtImport: stamped[0].headAtImport, dirtyAtImport: stamped.some(item => item.dirtyAtImport) } : {};
  return { observation: { ...first, declaredCommits, ...stamp }, findings: reads[0].findings };
}

type Parsed = { readonly input: number; readonly kind: InputRow['kind']; readonly sha256: string | null; readonly bytes: number }
  & ({ readonly reason: RejectReason } | { readonly reason: null; readonly reads: readonly Read[]; readonly carried: readonly Rejection[] });
/**
 * Inputs whose reads give one group key different content keys disagree. A SARIF read is re-derived from its bytes and is the truth,
 * so the records that differ from it disagree; without one, no record can be preferred and every record in the group disagrees.
 */
function disagreeing(parsed: readonly Parsed[], keysOf: (read: Read) => readonly (readonly [string, string])[]): Set<number> {
  const groups = new Map<string, { kind: InputRow['kind']; input: number; key: string }[]>();
  for (const item of parsed) if (item.reason === null) for (const read of item.reads) for (const [group, key] of keysOf(read)) {
    groups.set(group, [...groups.get(group) ?? [], { kind: item.kind, input: item.input, key }]);
  }
  const found = new Set<number>();
  for (const members of groups.values()) {
    if (new Set(members.map(item => item.key)).size === 1) continue;
    const truth = members.find(item => item.kind === 'sarif')?.key;
    for (const item of members) if (item.kind === 'record' && item.key !== truth) found.add(item.input);
  }
  return found;
}
const inconsistentWhere = (parsed: readonly Parsed[], keysOf: (read: Read) => readonly (readonly [string, string])[]): Parsed[] => {
  const found = disagreeing(parsed, keysOf);
  return parsed.map(item => found.has(item.input) ? { input: item.input, kind: item.kind, sha256: item.sha256, bytes: item.bytes, reason: 'record_inconsistent' } : item);
};
export interface ParseContext { readonly root: string; readonly repoId: string; readonly declared: string | null; readonly maxFiles: number; readonly runId: string }
/** Parses each input on its own; a structural failure rejects only that input, which stays listed with its hash and is carried into the facts. */
export function parseInputs(inputs: readonly ImportInput[], context: ParseContext): ParsedImports {
  let parsed: Parsed[] = inputs.map((item, index): Parsed => {
    const input = index + 1;
    if (item.kind === 'over_limit') return { input, kind: null, sha256: null, bytes: item.bytes, reason: 'over_limit' };
    const sha256 = hash(item.bytes), bytes = item.bytes.length;
    let kind: InputRow['kind'] = null;
    try {
      let decoded: string;
      try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(item.bytes); } catch { reject('invalid_utf8'); }
      const top = parseJson(decoded);
      if (!isObject(top)) reject('unsupported_schema');
      const object = top as Record<string, unknown>;
      kind = typeof object.schema === 'string' && object.schema.startsWith('scanmux.') ? 'record' : 'sarif';
      if (kind === 'record' && !/^scanmux\.import\/v\d+$/.test(object.schema as string)) reject('unsupported_schema');
      if (kind === 'record') { const { reads, rejected } = readRecord(object, context.repoId, context.maxFiles); return { input, kind, sha256, bytes, reason: null, reads, carried: rejected }; }
      return { input, kind, sha256, bytes, reason: null, reads: [readSarif(object, item.bytes, context.root, context.declared, context.maxFiles)], carried: [] };
    } catch (error) {
      if (!(error instanceof Rejected)) throw error;
      return { input, kind, sha256, bytes, reason: error.reason };
    }
  });
  // Imports are settled first, so a record already refused for its imports does not also decide a finding's core.
  parsed = inconsistentWhere(parsed, read => [[read.observation.importId, contentKey(read)]]);
  parsed = inconsistentWhere(parsed, read => read.findings.map(({ core }) => [core.findingId, JSON.stringify(keysSorted(core))] as const));
  const readsById = new Map<string, Read[]>(), rows: ParsedRow[] = [], rejected: Rejection[] = [];
  for (const item of parsed) {
    const { input, kind, sha256, bytes } = item;
    if (item.reason !== null) {
      rows.push({ input, kind, sha256, bytes, reasons: [item.reason], importIds: [], duplicates: 0, recordReasons: [] });
      rejected.push({ sha256, bytes, reason: item.reason, unreadId: sha256 === null ? digest(['unread/v2', context.runId, input]) : null });
      continue;
    }
    const importIds = item.reads.map(read => read.observation.importId);
    const duplicates = importIds.filter(importId => readsById.has(importId)).length;
    for (const read of item.reads) readsById.set(read.observation.importId, [...readsById.get(read.observation.importId) ?? [], read]);
    rejected.push(...item.carried);
    rows.push({ input, kind, sha256, bytes, reasons: [], importIds, duplicates, recordReasons: item.carried.length ? ['record_carries_rejected'] : [] });
  }
  const merged = [...readsById.values()].map(mergeReads);
  const findings = new Map<string, { core: FindingCore; counts: Map<string, Owned> }>();
  for (const { observation, findings: owned } of merged) for (const { core, owned: entry } of owned) {
    const known = findings.get(core.findingId) ?? { core, counts: new Map<string, Owned>() };
    known.counts.set(observation.importId, entry);
    findings.set(core.findingId, known);
  }
  const pending = merged.map(item => item.observation);
  const commitOf = new Map(pending.map(item => [item.importId, item.basis.commit]));
  const wanted = new Map<string, Set<string>>(pending.flatMap(item => item.basis.commit ? [[item.basis.commit, new Set<string>()] as const] : []));
  for (const { core, counts } of findings.values()) if (core.path) for (const importId of counts.keys()) {
    const commit = commitOf.get(importId);
    if (commit) wanted.get(commit)!.add(core.path);
  }
  return {
    repoId: context.repoId, rows, observations: pending, findings, rejected: canonicalRejections(rejected),
    wanted: new Map([...wanted].sort(([left], [right]) => order(left, right)).map(([commit, paths]) => [commit, [...paths].sort()])),
  };
}

/** Stamps new observations with the import-time facts and re-derives every relation to the current HEAD; nothing stored is trusted for that. */
export function assessImports(parsed: ParsedImports, facts: CommitFacts, importedAt: string): ImportRecord {
  const observations: Observation[] = parsed.observations.map(item => ({ ...item, importedAt: item.importedAt ?? importedAt, headAtImport: item.headAtImport ?? facts.head, dirtyAtImport: item.dirtyAtImport ?? facts.dirty }))
    .map(({ importId, tool, recordedToolVersion, inputSha256, inputBytes, recordedCommits, unreadableRevisions, declaredCommits, basis, importedAt, headAtImport, dirtyAtImport, execution, results, levelSources, fieldReasons }) =>
      ({ importId, tool, recordedToolVersion, inputSha256, inputBytes, recordedCommits, unreadableRevisions, declaredCommits, basis, importedAt, headAtImport, dirtyAtImport,
        execution: { successful: execution.successful, failed: execution.failed, unrecorded: execution.unrecorded, notifications: execution.notifications }, results,
        levelSources: { explicit: levelSources.explicit, ruleDefault: levelSources.ruleDefault, sarifDefault: levelSources.sarifDefault }, fieldReasons }))
    .sort((left, right) => order(left.importId, right.importId));
  const byImport = new Map(observations.map(item => [item.importId, item]));
  const findings: Finding[] = [...parsed.findings.values()].map(({ core, counts }) => {
    const commits = new Map<string | null, OccurrenceImport[]>();
    for (const [importId, { count, levels: seen }] of counts) {
      const commit = byImport.get(importId)!.basis.commit;
      commits.set(commit, [...commits.get(commit) ?? [], { importId, count, levels: seen }]);
    }
    const occurrences = [...commits].sort(([left], [right]) => order(left, right)).map(([commit, imports]) => {
      const sorted = imports.sort((left, right) => order(left.importId, right.importId));
      return { commit, count: sorted.reduce((total, entry) => total + entry.count, 0), imports: sorted };
    });
    return { ...core, occurrences };
  }).sort((left, right) => order(left.findingId, right.findingId));
  const bindings = new Map<string, number>();
  for (const item of observations) bindings.set(item.inputSha256, (bindings.get(item.inputSha256) ?? 0) + 1);
  const views: ObservationView[] = observations.map(observation => {
    const reasons: ObservationReason[] = [...basisOf(observation.recordedCommits, observation.declaredCommits)!.reasons];
    if (observation.unreadableRevisions) reasons.push('recorded_sha_unreadable');
    if (bindings.get(observation.inputSha256)! > 1) reasons.push('input_rebound');
    if (!observation.recordedToolVersion) reasons.push('tool_version_unrecorded');
    const { execution } = observation;
    if (execution.failed > 0 || execution.notifications > 0) reasons.push('tool_reported_incomplete');
    if (execution.unrecorded > 0 || execution.successful + execution.failed === 0) reasons.push('execution_unrecorded');
    let relation: Relation | null = null, absentPaths = 0;
    if (observation.basis.commit) {
      const fact = facts.commits.get(observation.basis.commit);
      if (!fact) throw new SafeError('commit_facts_missing');
      relation = observation.basis.commit === facts.head ? 'head' : !fact.exists ? 'commit_unavailable' : fact.ancestor ? 'stale_commit' : 'sha_mismatch';
      if (relation !== 'head') reasons.push(relation);
      if (fact.exists) {
        const present = new Set(fact.paths);
        absentPaths = findings.filter(item => item.path && !present.has(item.path) && item.occurrences.some(entry => entry.imports.some(owned => owned.importId === observation.importId))).length;
        if (absentPaths) reasons.push('referenced_paths_absent');
      }
    }
    if (observation.dirtyAtImport) reasons.push('worktree_dirty_at_import');
    reasons.push(...observation.fieldReasons.map(item => item.reason));
    return { importId: observation.importId, relation, reasons, absentPaths };
  });
  const viewOf = new Map(views.map(item => [item.importId, item]));
  const inputs: InputRow[] = parsed.rows.map(({ duplicates, recordReasons, ...row }) => {
    if (row.reasons.length) return { ...row, state: 'rejected', reasons: [...row.reasons] };
    const fresh = row.importIds.length - duplicates;
    const reasons = [...recordReasons, ...new Set(row.importIds.flatMap(importId => viewOf.get(importId)!.reasons))];
    return { ...row, state: fresh === 0 && duplicates > 0 ? 'duplicate' : 'accepted', reasons: duplicates ? [...reasons, 'duplicate_input'] : reasons };
  });
  const factsBlock = { repoId: parsed.repoId, observations, findings, rejected: parsed.rejected };
  const incomplete = facts.dirty || parsed.rejected.length > 0 || inputs.some(row => row.reasons.some(reason => reason !== 'duplicate_input')) || views.some(item => item.reasons.length > 0);
  return {
    schema: recordSchema, effect: { ...effect }, rawRetained: false, facts: factsBlock, factsDigest: digest(factsBlock),
    view: {
      head: facts.head, dirty: facts.dirty, importedAt, inputs, observations: views,
      counts: {
        inputs: inputs.length, accepted: inputs.filter(row => row.state === 'accepted').length, duplicate: inputs.filter(row => row.state === 'duplicate').length,
        rejected: inputs.filter(row => row.state === 'rejected').length, observations: observations.length, findings: findings.length,
        occurrences: findings.reduce((total, item) => total + item.occurrences.reduce((sum, entry) => sum + entry.count, 0), 0),
      },
      exitCode: incomplete ? 3 : 0,
    },
  };
}

export interface ImportRequest { readonly root: string; readonly inputs: readonly string[]; readonly scannedCommit: string | null; readonly workspace: string }
export async function importResults(request: ImportRequest, config: Config, signal: AbortSignal): Promise<{ record: ImportRecord; json: string; destination: string }> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  if (request.scannedCommit !== null && !sha40.test(request.scannedCommit)) throw new SafeError('invalid_scanned_commit');
  const root = await canonical(request.root);
  if (!request.inputs.length) throw new SafeError('invalid_command');
  const files: string[] = [];
  for (const file of request.inputs) {
    if (!path.isAbsolute(file)) throw new SafeError('import_input_not_absolute');
    const physical = await canonical(file);
    if (within(root, physical)) throw new SafeError('import_input_inside_target');
    files.push(physical);
  }
  let remaining = config.maxOutputBytes;
  const inputs: ImportInput[] = [];
  for (const file of files) {
    const stat = await lstat(file);
    if (!stat.isFile()) throw new SafeError('import_input_not_file');
    if (stat.size > remaining) { inputs.push({ kind: 'over_limit', bytes: stat.size }); continue; }
    const bytes = await boundedRead(file, remaining);
    remaining -= bytes.length;
    inputs.push({ kind: 'bytes', bytes });
  }
  const parsed = parseInputs(inputs, { root, repoId: hash(root), declared: request.scannedCommit, maxFiles: config.maxFiles, runId: hash(randomBytes(32)) });
  const facts = await commitFacts(root, config, request.workspace, parsed.wanted, signal);
  const record = assessImports(parsed, facts, new Date().toISOString());
  const json = await checkedJson(record, config, request.workspace), destination = path.join(request.workspace, 'import.json');
  await checkedJson({ destination }, config, request.workspace);
  const partial = path.join(request.workspace, 'import.json.partial');
  await writeFile(partial, json, { flag: 'wx', mode: 0o600 });
  await rename(partial, destination);
  return { record, json, destination };
}

export function importText(record: ImportRecord, destination: string): string {
  const { view } = record;
  const lines = [`ScanMux import: read and recorded, not a security decision; gate unchanged (exit ${view.exitCode}).`,
    `HEAD=${view.head} dirty=${view.dirty}; inputs=${view.counts.inputs} accepted=${view.counts.accepted} duplicate=${view.counts.duplicate} rejected=${view.counts.rejected}`];
  for (const row of view.inputs) {
    lines.push(`Input ${row.input}: ${row.state} sha256=${row.sha256 ?? 'unread'} reasons=${row.reasons.join(',') || 'none'}`);
    if (row.kind === 'record' && row.reasons.includes('unsupported_schema')) lines.push(`Input ${row.input}: only ${recordSchema} records are read; import the original SARIF again.`);
  }
  for (const item of record.facts.rejected) lines.push(`Rejected input kept: sha256=${item.sha256 ?? 'unread'} bytes=${item.bytes} reason=${item.reason}`);
  for (const [index, item] of view.observations.entries()) {
    const fact = record.facts.observations[index];
    lines.push(`Import ${item.importId}: tool=${fact.tool} version=${fact.recordedToolVersion ?? 'unrecorded'} basis=${fact.basis.kind}:${fact.basis.commit ?? 'none'} relation=${item.relation ?? 'unbound'} results=${fact.results} reasons=${item.reasons.join(',') || 'none'}`);
  }
  lines.push(`Findings: ${view.counts.findings}; occurrences: ${view.counts.occurrences}. Imported findings are separate from ScanMux findings; scanVerified=false.`, `JSON: ${destination}`);
  return lines.join('\n') + '\n';
}
