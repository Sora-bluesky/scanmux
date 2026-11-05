import { createHash } from 'node:crypto';
import { hash, safeRelative, SafeError } from '../safety.ts';
import { parseReportLanguage, type ReportLanguage } from '../report-language.ts';
import { feedIds, isMatchable, type FeedId } from './feeds.ts';
import type { FeedStatus, IntelMatch, JvnMatch, KevMatch } from './match.ts';

const english = {
  "ScanMux 公開情報照合": "ScanMux public feed match",
  "この照合は判定（ゲート）を変えません。KEV掲載の有無も終了コードを変えません。": "This match never changes the gate. A KEV listing never changes the exit code.",
  "照合元": "Source",
  "照合元のSHA-256": "Source SHA-256",
  "照合時刻": "Matched at",
  "鮮度の上限": "Freshness limit",
  "指定なし": "not set",
  "情報源": "Feeds",
  "状態": "State",
  "説明": "Details",
  "検出": "Finding",
  "CVEのない検出": "Findings without a CVE",
  "CVEを含む検出はありません。": "No finding carries a CVE.",
  "保存データの破損": "Corrupt stored data",
  "CISA KEV（悪用が確認された脆弱性）": "CISA KEV (Known Exploited Vulnerabilities)",
  "JVN 更新RSS": "JVN update RSS",
  "JVN iPedia（JVNDB）": "JVN iPedia (JVNDB)",
  "未取得です。intel-refresh を実行してください。": "Not acquired. Run intel-refresh.",
  "取得に失敗しました（理由 {reason}、HTTP {status}、{at}）。照合していません。": "Fetch failed (reason {reason}, HTTP {status}, at {at}). Not matched.",
  "最新の取得に失敗しました（理由 {reason}、HTTP {status}、{at}）。{age}前に取得したコピーと照合しています。最新とは判定しません。": "The latest refresh failed (reason {reason}, HTTP {status}, at {at}). Matched against the copy fetched {age} ago; it is not judged current.",
  "{age}前に取得しました（版 {version}）。上限 {limit} 以内です。": "Fetched {age} ago (version {version}); within the {limit} limit.",
  "{age}前のデータと照合しています（上限 {limit} を超過）。": "Matched against data {age} old; older than the {limit} limit.",
  "{age}前に取得しました（版 {version}）。鮮度の上限が指定されていないため、最新とは判定していません。": "Fetched {age} ago (version {version}). No freshness limit was set, so it is not judged current.",
  "最新の保存データが破損しています。": "The latest stored data is corrupt.",
  "取得時刻を検証できません。最新とは判定しません。": "The fetch time cannot be verified; it is never judged current.",
  "{age}前の正常なコピーと照合しています。": "Matched against the valid copy from {age} ago.",
  "照合していません。": "Not matched.",
  "最近の更新RSSの範囲（{items}件、{oldest}～{newest}）であり、データベース全体ではありません。": "Recent-update RSS window ({items} items, {oldest} to {newest}); not the full database.",
  "情報源の公開日時：{date}": "Source release time: {date}",
  "利用条件：{url}": "Terms: {url}",
  "利用条件：未確認": "Terms: not verified",
  "KEV掲載（追加 {added}、期限 {due}、ランサムウェアでの利用 {ransomware}）：{name}": "Listed in KEV (added {added}, due {due}, ransomware use {ransomware}): {name}",
  "KEV未掲載（版 {version}）": "Not listed in KEV (version {version})",
  "KEV未評価（{reason}）": "KEV not evaluated ({reason})",
  "JVN更新RSSに掲載：{ids}": "In the JVN update RSS: {ids}",
  "JVN更新RSSの範囲内には見当たりません（データベース全体は未確認）": "Not seen in the JVN update RSS window (full database not checked)",
  "JVN未評価（{reason}）": "JVN not evaluated ({reason})",
  "{hours}時間{minutes}分": "{hours} h {minutes} min",
  "{count}件": "{count}",
} as const;
export type IntelText = keyof typeof english;
export const intelDictionary: Readonly<Record<IntelText, string>> = english;
export function intelText(language: ReportLanguage, key: IntelText, values: Readonly<Record<string, string | number>> = {}): string {
  const template = parseReportLanguage(language) === 'ja' ? key : english[key];
  return template.replace(/\{(\w+)\}/g, (_match, name: string) => {
    if (!Object.hasOwn(values, name)) throw new SafeError('invalid_report_text');
    return String(values[name]);
  });
}
const feedNames: Readonly<Record<FeedId, IntelText>> = { kev: 'CISA KEV（悪用が確認された脆弱性）', jvn: 'JVN 更新RSS', jvndb: 'JVN iPedia（JVNDB）' };
const age = (language: ReportLanguage, ms: number) => intelText(language, '{hours}時間{minutes}分', { hours: Math.floor(ms / 3600000), minutes: Math.floor(ms % 3600000 / 60000) });
const plain = (value: string) => value.replace(/[\x00-\x1f\x7f\u2028\u2029]/g, ' ');

export function feedSentences(status: FeedStatus, match: IntelMatch, language: ReportLanguage): string[] {
  const t = (key: IntelText, values?: Record<string, string | number>) => intelText(language, key, values);
  const generation = status.generation, latest = status.latestAttempt;
  const since = generation ? age(language, generation.ageMs) : '', version = generation?.sourceVersion ?? '-';
  const limit = match.maxAgeMs === null ? '' : age(language, match.maxAgeMs);
  const failure = { reason: latest?.reason ?? latest?.outcome ?? '-', status: latest?.httpStatus ?? '-', at: latest?.completedAt ?? '-' };
  const fallback = generation ? t('{age}前の正常なコピーと照合しています。', { age: since }) : t('照合していません。');
  const lines = [{
    never_attempted: () => t('未取得です。intel-refresh を実行してください。'),
    unavailable: () => t('取得に失敗しました（理由 {reason}、HTTP {status}、{at}）。照合していません。', failure),
    refresh_failed_previous: () => t('最新の取得に失敗しました（理由 {reason}、HTTP {status}、{at}）。{age}前に取得したコピーと照合しています。最新とは判定しません。', { ...failure, age: since }),
    fresh: () => t('{age}前に取得しました（版 {version}）。上限 {limit} 以内です。', { age: since, version, limit }),
    stale: () => t('{age}前のデータと照合しています（上限 {limit} を超過）。', { age: since, limit }),
    unjudged: () => t('{age}前に取得しました（版 {version}）。鮮度の上限が指定されていないため、最新とは判定していません。', { age: since, version }),
    corrupt: () => `${t('最新の保存データが破損しています。')} ${fallback}`,
    clock_unknown: () => `${t('取得時刻を検証できません。最新とは判定しません。')} ${fallback}`,
  }[status.state]()];
  if (status.window) lines.push(t('最近の更新RSSの範囲（{items}件、{oldest}～{newest}）であり、データベース全体ではありません。', status.window));
  if (generation?.sourceDate) lines.push(t('情報源の公開日時：{date}', { date: generation.sourceDate }));
  lines.push(status.termsUrl ? t('利用条件：{url}', { url: status.termsUrl }) : t('利用条件：未確認'));
  return lines;
}
export function kevSentence(value: KevMatch, language: ReportLanguage): string {
  if (value.state === 'listed') return intelText(language, 'KEV掲載（追加 {added}、期限 {due}、ランサムウェアでの利用 {ransomware}）：{name}', { added: value.entry.dateAdded,
    due: value.entry.dueDate, ransomware: plain(value.entry.knownRansomwareCampaignUse ?? '-'), name: plain(value.entry.vulnerabilityName) });
  return value.state === 'not_listed' ? intelText(language, 'KEV未掲載（版 {version}）', { version: value.catalogVersion }) : intelText(language, 'KEV未評価（{reason}）', { reason: value.reason });
}
export function jvnSentence(value: JvnMatch, language: ReportLanguage): string {
  if (value.state === 'observed') return intelText(language, 'JVN更新RSSに掲載：{ids}', { ids: value.items.map(item => `${item.identifier} ${item.link}`).join(', ') });
  return value.state === 'not_observed_in_window' ? intelText(language, 'JVN更新RSSの範囲内には見当たりません（データベース全体は未確認）') : intelText(language, 'JVN未評価（{reason}）', { reason: value.reason });
}
const findingName = (finding: IntelMatch['findings'][number]) => finding.kind === 'report' ? `${finding.engine} ${finding.fingerprint.slice(0, 12)}` : `${finding.tool} ${finding.findingId.slice(0, 12)}`;

export function renderIntelText(match: IntelMatch, language: ReportLanguage): string {
  const t = (key: IntelText) => intelText(language, key);
  const lines = [t('ScanMux 公開情報照合'), t('この照合は判定（ゲート）を変えません。KEV掲載の有無も終了コードを変えません。'),
    `${t('照合元')}: ${match.sourceKind}; ${t('照合元のSHA-256')}: ${match.sourceSha256}; ${t('照合時刻')}: ${match.matchedAt}; ${t('鮮度の上限')}: ${match.maxAgeMs === null ? t('指定なし') : age(language, match.maxAgeMs)}`];
  for (const feed of feedIds) {
    const status = match.feeds[feed];
    lines.push(`${t(feedNames[feed])} [${status.state}]: ${feedSentences(status, match, language).join(' ')}`);
    for (const note of status.notes) lines.push(`  ${t('保存データの破損')}: ${note.attempt} ${note.reason}`);
  }
  if (!match.findings.length) lines.push(t('CVEを含む検出はありません。'));
  for (const finding of match.findings) for (const item of finding.cves) lines.push(`${findingName(finding)} ${item.cve}: ${kevSentence(item.kev, language)}; ${jvnSentence(item.jvn, language)}`);
  lines.push(`${t('CVEのない検出')}: ${intelText(language, '{count}件', { count: match.skipped.noCve })}`);
  return lines.map(plain).join('\n') + '\n';
}

const style = `body{margin:0;font-family:system-ui,"Yu Gothic",Meiryo,sans-serif;color:#172a3e;background:#edf1f5;line-height:1.6}main{max-width:1120px;margin:24px auto;background:#fff;padding:32px}h1{font-size:1.6rem}h2{font-size:1.2rem;border-bottom:2px solid #dce4ec;padding-bottom:6px;margin-top:28px}.notice{border-left:6px solid #9c6d15;background:#fff8e8;padding:12px 18px}table{width:100%;border-collapse:collapse;font-size:.9rem}th{text-align:left;background:#edf2f7}th,td{padding:9px;border-bottom:1px solid #dfe6ed;vertical-align:top;overflow-wrap:anywhere}code{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere}@media(max-width:600px){main{margin:0;padding:18px 16px}}`;
const csp = `default-src 'none'; script-src 'none'; style-src 'sha256-${createHash('sha256').update(style).digest('base64')}'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
const e = (value: string | number) => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);

export function renderIntelHtml(match: IntelMatch, language: ReportLanguage): string {
  const lang = parseReportLanguage(language), t = (key: IntelText) => e(intelText(lang, key));
  const feedRows = feedIds.map(feed => {
    const status = match.feeds[feed], notes = status.notes.map(note => `<br><small>${t('保存データの破損')}: <code>${e(note.attempt)}</code> ${e(note.reason)}</small>`).join('');
    return `<tr><td>${t(feedNames[feed])}</td><td><code>${e(status.state)}</code></td><td>${feedSentences(status, match, lang).map(e).join('<br>')}${notes}</td></tr>`;
  }).join('');
  const findingRows = match.findings.flatMap(finding => finding.cves.map(item =>
    `<tr><td><code>${e(findingName(finding))}</code></td><td><code>${e(item.cve)}</code></td><td>${e(kevSentence(item.kev, lang))}</td><td>${e(jvnSentence(item.jvn, lang))}</td></tr>`)).join('');
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${e(csp)}"><meta name="referrer" content="no-referrer"><title>${t('ScanMux 公開情報照合')}</title><style>${style}</style></head><body><main>
<h1>${t('ScanMux 公開情報照合')}</h1><p class="notice">${t('この照合は判定（ゲート）を変えません。KEV掲載の有無も終了コードを変えません。')}</p>
<p>${t('照合元')}: <code>${e(match.sourceKind)}</code><br>${t('照合元のSHA-256')}: <code>${e(match.sourceSha256)}</code><br>${t('照合時刻')}: <code>${e(match.matchedAt)}</code><br>${t('鮮度の上限')}: ${match.maxAgeMs === null ? t('指定なし') : e(age(lang, match.maxAgeMs))}</p>
<h2>${t('情報源')}</h2><table><thead><tr><th>${t('情報源')}</th><th>${t('状態')}</th><th>${t('説明')}</th></tr></thead><tbody>${feedRows}</tbody></table>
<h2>${t('検出')}</h2>${findingRows ? `<table><thead><tr><th>${t('検出')}</th><th>CVE</th><th>KEV</th><th>JVN</th></tr></thead><tbody>${findingRows}</tbody></table>` : `<p>${t('CVEを含む検出はありません。')}</p>`}
<p>${t('CVEのない検出')}: ${e(intelText(lang, '{count}件', { count: match.skipped.noCve }))}</p>
</main></body></html>
`;
}

export function renderIntelSarif(match: IntelMatch): string {
  const raised = feedIds.filter(feed => !['fresh', 'stale', 'unjudged'].includes(match.feeds[feed].state));
  const notifications = raised.map(feed => match.feeds[feed]).map(status => ({
    level: 'warning', message: { text: `${status.feed}: ${feedSentences(status, match, 'en')[0]}` }, properties: { 'scanmux/intel/v1': { feed: status.feed, state: status.state } } }));
  const results = match.findings.flatMap(finding => finding.cves.map(item => {
    let uri: string | undefined;
    try { uri = finding.path === null ? undefined : safeRelative(finding.path).split('/').map(segment => encodeURIComponent(segment)).join('/'); } catch { uri = undefined; }
    const ref = finding.kind === 'report' ? { kind: finding.kind, engine: finding.engine, fingerprint: finding.fingerprint } : { kind: finding.kind, tool: finding.tool, findingId: finding.findingId };
    return { ruleId: 'scanmux/intel/cve', level: 'note', message: { text: `${item.cve}: ${kevSentence(item.kev, 'en')}; ${jvnSentence(item.jvn, 'en')}` },
      partialFingerprints: { 'scanmux/intel/v1': hash(JSON.stringify([ref, item.cve])) },
      ...(uri === undefined ? {} : { locations: [{ physicalLocation: { artifactLocation: { uri, uriBaseId: 'SRCROOT' }, ...(finding.line === null ? {} : { region: { startLine: finding.line } }) } }] }),
      properties: { 'scanmux/intel/v1': { cve: item.cve, kev: item.kev.state, jvn: item.jvn.state, finding: ref } } };
  }));
  return JSON.stringify({ $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs: [{
    tool: { driver: { name: 'ScanMux', version: '0.2.4', rules: [{ id: 'scanmux/intel/cve' }] } },
    originalUriBaseIds: { SRCROOT: { description: { text: 'Repository root; absolute location intentionally omitted.' } } },
    invocations: [{ executionSuccessful: !raised.some(isMatchable), ...(notifications.length ? { toolExecutionNotifications: notifications } : {}) }],
    properties: { 'scanmux/intel/v1': { sourceSha256: match.sourceSha256, sourceKind: match.sourceKind, matchedAt: match.matchedAt, maxAgeMs: match.maxAgeMs, storeDigest: match.storeDigest,
      feeds: Object.fromEntries(feedIds.map(feed => [feed, match.feeds[feed].state])), skippedNoCve: match.skipped.noCve } },
    results,
  }] }, null, 2) + '\n';
}
