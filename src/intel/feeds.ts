import { parseJvnRss, type JvnWindow } from './jvn-rss.ts';
import { parseKev, type KevCatalog } from './kev.ts';

export const feedIds = ['kev', 'jvn', 'jvndb'] as const;
export type FeedId = typeof feedIds[number];
export type Parsed = { readonly feed: 'kev'; readonly data: KevCatalog } | { readonly feed: 'jvn'; readonly data: JvnWindow };
export type Source = { readonly version: string | null; readonly date: string | null };
interface Common { readonly id: FeedId; readonly termsUrl: string | null; readonly maxBytes: number; url(startedAt: string): string }
export type Feed = Common & ({ readonly kind: 'matchable'; parse(bytes: Buffer): { readonly parsed: Parsed; readonly source: Source } } | { readonly kind: 'status_only' });
const mib = 1024 * 1024;
// Bounds one stalled server per feed; the largest measured body (1.8 MB) arrives in seconds.
export const feedTimeoutMs = 60_000;
export const feeds: Readonly<Record<FeedId, Feed>> = Object.freeze({
  // About 9x the 1.8 MB catalog measured on 2026-10-26; a stop-the-download limit, not a semantic threshold.
  kev: { id: 'kev', kind: 'matchable', termsUrl: 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt', maxBytes: 16 * mib,
    url: () => 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    parse: bytes => { const data = parseKev(bytes); return { parsed: { feed: 'kev', data }, source: { version: data.catalogVersion, date: data.dateReleased } }; } },
  // About 60x the 17 KB recent-window RSS measured on 2026-10-26.
  jvn: { id: 'jvn', kind: 'matchable', termsUrl: null, maxBytes: mib, url: () => 'https://jvn.jp/rss/jvn.rdf',
    parse: bytes => { const data = parseJvnRss(bytes); return { parsed: { feed: 'jvn', data }, source: { version: null, date: data.modified } }; } },
  // Room for a yearly detail feed; the body is never kept until a parser for it is verified.
  jvndb: { id: 'jvndb', kind: 'status_only', termsUrl: null, maxBytes: 64 * mib, url: startedAt => `https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_${startedAt.slice(0, 4)}.rdf` },
});
export const isMatchable = (feed: FeedId) => feeds[feed].kind === 'matchable';
