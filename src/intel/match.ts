import { summarizeHistory } from '../history.ts';
import { array, digest, hash, record, SafeError } from '../safety.ts';
import { feedIds, feeds, isMatchable, type FeedId } from './feeds.ts';
import { toCveId, type CveId } from './syntax.ts';
import type { KevEntry } from './kev.ts';
import type { CorruptNote, FailReason, FeedState, LoadedFeed, LoadedIntel } from './store.ts';

export type SourceKind = 'report' | 'import';
export type FindingRef = { readonly kind: 'report'; readonly engine: string; readonly fingerprint: string } | { readonly kind: 'import'; readonly tool: string; readonly findingId: string };
export interface Subject { readonly ref: FindingRef; readonly path: string | null; readonly line: number | null; readonly cves: readonly CveId[] }
export interface IntelSource { readonly kind: SourceKind; readonly repoId: string; readonly root: string | null; readonly subjects: readonly Subject[]; readonly noCve: number }
export interface FeedStatus {
  readonly feed: FeedId; readonly state: FeedState; readonly usable: boolean; readonly termsUrl: string | null;
  readonly latestAttempt: { readonly url: string; readonly startedAt: string; readonly completedAt: string; readonly outcome: 'stored' | 'failed' | 'unsupported'; readonly reason: FailReason | null; readonly httpStatus: number | null } | null;
  readonly generation: { readonly url: string; readonly startedAt: string; readonly completedAt: string; readonly sha256: string; readonly bytes: number; readonly ageMs: number; readonly sourceVersion: string | null; readonly sourceDate: string | null } | null;
  readonly window: { readonly items: number; readonly oldest: string; readonly newest: string } | null;
  readonly notes: readonly CorruptNote[];
}
export type KevMatch = { readonly state: 'listed'; readonly catalogVersion: string; readonly entry: KevEntry } | { readonly state: 'not_listed'; readonly catalogVersion: string } | { readonly state: 'not_evaluated'; readonly reason: FeedState };
export type JvnMatch = { readonly state: 'observed'; readonly items: readonly { readonly identifier: string; readonly link: string; readonly modified: string }[] }
  | { readonly state: 'not_observed_in_window'; readonly oldest: string; readonly newest: string; readonly items: number } | { readonly state: 'not_evaluated'; readonly reason: FeedState };
export interface IntelMatch {
  readonly schema: 'scanmux.intel-match/v1'; readonly sourceSha256: string; readonly sourceKind: SourceKind; readonly matchedAt: string; readonly maxAgeMs: number | null;
  readonly storeDigest: string; readonly feeds: Readonly<Record<FeedId, FeedStatus>>;
  readonly findings: readonly (FindingRef & { readonly path: string | null; readonly line: number | null; readonly cves: readonly { readonly cve: CveId; readonly kev: KevMatch; readonly jvn: JvnMatch }[] })[];
  readonly skipped: { readonly noCve: number };
}

const sha64 = /^[a-f0-9]{64}$/;
function invalid(condition: unknown): asserts condition { if (!condition) throw new SafeError('invalid_intel_source'); }
const cvesOf = (values: readonly (string | null)[]) => [...new Set(values.map(toCveId).filter(id => id !== null))].sort();
const optionalText = (value: unknown) => { invalid(value === null || (typeof value === 'string' && value.length <= 1024)); return value as string | null; };
const optionalLine = (value: unknown) => { invalid(value === null || (Number.isSafeInteger(value) && Number(value) > 0)); return value as number | null; };

export function readSource(bytes: Buffer): IntelSource {
  let top: Record<string, unknown>;
  try { top = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))); } catch { throw new SafeError('invalid_intel_source'); }
  const subjects: Subject[] = []; let noCve = 0;
  const add = (subject: Subject) => { if (subject.cves.length) subjects.push(subject); else noCve++; };
  if (top.schema === 'scanmux.report/v2') {
    let projected: ReturnType<typeof summarizeHistory>;
    try { projected = summarizeHistory([bytes]); } catch { throw new SafeError('invalid_intel_source'); }
    for (const run of array(top.engines)) for (const item of array(record(run).findings)) {
      const finding = record(item), originIds = array(finding.originIds);
      invalid(typeof finding.engine === 'string' && /^[a-z-]{1,64}$/.test(finding.engine) && typeof finding.fingerprint === 'string' && sha64.test(finding.fingerprint)
        && originIds.every(id => typeof id === 'string' && id.length <= 200));
      add({ ref: { kind: 'report', engine: finding.engine, fingerprint: finding.fingerprint }, path: optionalText(finding.file ?? null), line: optionalLine(finding.line ?? null), cves: cvesOf(originIds as string[]) });
    }
    return { kind: 'report', repoId: projected.roots[0].repoId, root: projected.roots[0].root, subjects, noCve };
  }
  invalid(top.schema === 'scanmux.import/v2' && top.factsDigest === digest(top.facts));
  const facts = record(top.facts);
  invalid(typeof facts.repoId === 'string' && sha64.test(facts.repoId));
  for (const item of array(facts.findings)) {
    const finding = record(item);
    invalid(typeof finding.findingId === 'string' && sha64.test(finding.findingId) && ['osv-scanner', 'gitleaks'].includes(finding.tool as string));
    add({ ref: { kind: 'import', tool: finding.tool as string, findingId: finding.findingId }, path: optionalText(finding.path), line: optionalLine(finding.startLine),
      cves: cvesOf([optionalText(finding.ruleId)]) });
  }
  return { kind: 'import', repoId: facts.repoId, root: null, subjects, noCve };
}

function feedStatus(loaded: LoadedFeed, now: number, maxAgeMs: number | null): FeedStatus {
  const { generation, latest } = loaded;
  const ageMs = generation ? now - Date.parse(generation.attempt.completedAt) : 0;
  const state: FeedState = loaded.newest === 'none' ? 'never_attempted' : loaded.newest === 'clock_unverified' ? 'clock_unknown' : loaded.newest !== 'attempt' ? 'corrupt'
    : latest!.outcome.kind !== 'stored' ? generation ? 'refresh_failed_previous' : 'unavailable'
      : maxAgeMs === null ? 'unjudged' : ageMs <= maxAgeMs ? 'fresh' : 'stale';
  const outcome = latest?.outcome, parsed = generation?.parsed;
  return { feed: loaded.feed, state, usable: generation !== null, termsUrl: feeds[loaded.feed].termsUrl,
    latestAttempt: latest && outcome ? { url: latest.url, startedAt: latest.startedAt, completedAt: latest.completedAt, outcome: outcome.kind,
      reason: outcome.kind === 'failed' ? outcome.reason : null, httpStatus: outcome.httpStatus } : null,
    generation: generation ? { url: generation.attempt.url, startedAt: generation.attempt.startedAt, completedAt: generation.attempt.completedAt,
      sha256: generation.attempt.outcome.sha256, bytes: generation.attempt.outcome.bytes, ageMs,
      sourceVersion: generation.attempt.outcome.source.version, sourceDate: generation.attempt.outcome.source.date } : null,
    window: parsed?.feed === 'jvn' ? { items: parsed.data.items.length, oldest: parsed.data.oldest, newest: parsed.data.newest } : null,
    notes: loaded.notes };
}
export function matchIntel(sourceBytes: Buffer, source: IntelSource, intel: LoadedIntel, options: { readonly now: number; readonly maxAgeMs: number | null }): IntelMatch {
  if (options.maxAgeMs !== null && (!Number.isSafeInteger(options.maxAgeMs) || options.maxAgeMs < 1)) throw new SafeError('invalid_intel_max_age');
  const status = Object.fromEntries(feedIds.map(feed => [feed, feedStatus(intel.feeds[feed], options.now, options.maxAgeMs)])) as Record<FeedId, FeedStatus>;
  const kev = intel.feeds.kev.generation?.parsed, jvn = intel.feeds.jvn.generation?.parsed;
  const observed = new Map<CveId, { identifier: string; link: string; modified: string }[]>();
  if (jvn?.feed === 'jvn') for (const item of jvn.data.items) for (const cve of item.cves) observed.set(cve, [...observed.get(cve) ?? [], { identifier: item.identifier, link: item.link, modified: item.modified }]);
  const findings = source.subjects.map(subject => ({ ...subject.ref, path: subject.path, line: subject.line, cves: subject.cves.map(cve => {
    const listed = kev?.feed === 'kev' ? kev.data.entries.get(cve) : undefined;
    const kevMatch: KevMatch = kev?.feed !== 'kev' ? { state: 'not_evaluated', reason: status.kev.state }
      : listed ? { state: 'listed', catalogVersion: kev.data.catalogVersion, entry: listed } : { state: 'not_listed', catalogVersion: kev.data.catalogVersion };
    const items = observed.get(cve);
    const jvnMatch: JvnMatch = jvn?.feed !== 'jvn' ? { state: 'not_evaluated', reason: status.jvn.state }
      : items ? { state: 'observed', items } : { state: 'not_observed_in_window', oldest: jvn.data.oldest, newest: jvn.data.newest, items: jvn.data.items.length };
    return { cve, kev: kevMatch, jvn: jvnMatch };
  }) }));
  return { schema: 'scanmux.intel-match/v1', sourceSha256: hash(sourceBytes), sourceKind: source.kind, matchedAt: new Date(options.now).toISOString(),
    maxAgeMs: options.maxAgeMs, storeDigest: intel.storeDigest, feeds: status, findings, skipped: { noCve: source.noCve } };
}
export function intelExitCode(match: IntelMatch, requireFresh: boolean): 0 | 3 {
  return requireFresh && feedIds.some(feed => isMatchable(feed) && (!match.feeds[feed].usable || match.feeds[feed].state !== 'fresh')) ? 3 : 0;
}
