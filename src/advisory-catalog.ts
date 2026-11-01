import { digest } from './safety.ts';
import type { Severity } from './model.ts';

export type Product = 'php' | 'node' | 'next' | 'nginx' | 'gitlab' | 'tomcat';
export type Version = readonly [number, number, number];
export interface Interval { from: string; to: string; excludeFrom?: true; includeTo?: true }
export type Condition = 'web_sapi' | 'node_features' | 'cache_components_typed_arrays' | 'linux_glibc_image_optimizer'
  | 'app_router_server_actions' | 'nginx_configuration' | 'gitlab_regex' | 'ajp' | 'http2_async' | 'jndi_realm' | 'tls13' | 'http2_trailers';
export interface Advisory {
  id: string; aliases: string[]; product: Product; severity: Severity; officialSeverity: string;
  domains: Interval[]; affected: Interval[]; excluded: Interval[]; fixed: string[];
  conditions: Condition[]; sources: string[]; publishedAt: string | null; confirmedAt: string;
}
export function parseVersion(value: string): Version | null {
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  return parts.every(Number.isSafeInteger) ? parts as unknown as Version : null;
}
export function compare(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; }
  return 0;
}
export function contains(version: Version, range: Interval): boolean {
  const lower = compare(version, parseVersion(range.from)!); const upper = compare(version, parseVersion(range.to)!);
  return (lower > 0 || lower === 0 && !range.excludeFrom) && (upper < 0 || upper === 0 && Boolean(range.includeTo));
}
const interval = (from: string, to: string): Interval => ({ from, to });
const branch = (value: string): Interval => { const [major, minor] = value.split('.').map(Number); return interval(`${major}.${minor}.0`, `${major}.${minor + 1}.0`); };
const major = (value: number): Interval => interval(`${value}.0.0`, `${value + 1}.0.0`);
const confirmedAt = '2026-10-22';
const advisory = (value: Omit<Advisory, 'confirmedAt' | 'publishedAt' | 'excluded' | 'aliases'> & Partial<Pick<Advisory, 'publishedAt' | 'excluded' | 'aliases'>>): Advisory =>
  ({ confirmedAt, publishedAt: null, excluded: [], aliases: [], ...value });
const phpFixes = ['8.2.35', '8.3.36', '8.4.27', '8.5.12'];
const nodeFixes = ['22.23.4', '24.22.1', '26.12.1'];
const tomcatFixes = ['11.0.27', '10.1.61', '9.0.123'];
const records: Advisory[] = [
  ...(['109618', '109619'] as const).map((id, i) => advisory({ id: `CVE-2026-${id}`, aliases: [i ? 'GHSA-6wmf-4rv5-p3rp' : 'GHSA-w8hw-w9fx-j79w'], product: 'php', severity: 'critical', officialSeverity: 'Critical',
    domains: ['8.2', '8.3', '8.4', '8.5'].map(branch), affected: phpFixes.map(fix => interval(fix.replace(/\.[0-9]+$/, '.0'), fix)), fixed: phpFixes,
    conditions: ['web_sapi'], sources: ['https://www.php.net/archive/2026.php', `https://github.com/php/php-src/security/advisories/${i ? 'GHSA-6wmf-4rv5-p3rp' : 'GHSA-w8hw-w9fx-j79w'}`], publishedAt: '2026-10-21' })),
  ...(['105482', '105483', '106069', '111497', '105481', '106072', '106074', '106070', '106071', '106073'] as const).map((id, i) => {
    const majors = id === '105483' ? [24, 26] : ['106070', '106071'].includes(id) ? [26] : [22, 24, 26];
    const fixed = nodeFixes.filter(fix => majors.includes(Number(fix.split('.')[0])));
    return advisory({ id: `CVE-2026-${id}`, product: 'node', severity: i < 4 ? 'high' : i < 7 ? 'medium' : 'low', officialSeverity: i < 4 ? 'High' : i < 7 ? 'Medium' : 'Low',
      domains: majors.map(major), affected: fixed.map(fix => interval(`${fix.split('.')[0]}.0.0`, fix)), fixed,
      conditions: ['node_features'], sources: ['https://nodejs.org/en/blog/vulnerability/october-2026-security-releases'] });
  }),
  advisory({ id: 'GHSA-673q-mjm6-r5xr', product: 'next', severity: 'critical', officialSeverity: 'Critical', domains: [major(16)], affected: [interval('16.0.0', '16.4.1')], fixed: ['16.4.1'], conditions: ['cache_components_typed_arrays'], sources: ['https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr'] }),
  advisory({ id: 'GHSA-2464-fhr4-w9xw', aliases: ['CVE-2026-96889'], publishedAt: '2026-10-14', product: 'next', severity: 'critical', officialSeverity: 'Critical', domains: [interval('10.0.0', '17.0.0')], affected: [{ from: '10.0.0', to: '15.5.27', includeTo: true }, { from: '16.0.0', excludeFrom: true, to: '16.4.0', includeTo: true }], fixed: ['15.5.28', '16.4.1'], conditions: ['linux_glibc_image_optimizer'], sources: ['https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw'] }),
  advisory({ id: 'GHSA-p3m5-59mp-jv5r', product: 'next', severity: 'high', officialSeverity: 'High', domains: [interval('13.0.0', '17.0.0')], affected: [{ from: '13.0.0', to: '15.5.27', includeTo: true }, { from: '16.0.0', to: '16.4.0', includeTo: true }], fixed: ['15.5.28', '16.4.1'], conditions: ['app_router_server_actions'], sources: ['https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r'] }),
  ...(['15176', '93479', '95101', '97629', '97205'] as const).map((id, i) => advisory({ id: `CVE-2026-${id}`, product: 'nginx', severity: 'medium', officialSeverity: 'Medium', domains: [interval('0.1.0', '1.32.0')],
    affected: id === '93479' ? [interval('1.31.2', '1.31.7'), interval('1.30.0', '1.30.6')] : [interval(['0.1.29', '', '1.25.0', '1.23.2', '0.8.11'][i], '1.31.7')],
    excluded: [interval('1.30.6', '1.31.0')], fixed: ['1.30.6', '1.31.7'], conditions: ['nginx_configuration'], sources: ['https://nginx.org/en/security_advisories.html'] })),
  advisory({ id: 'CVE-2026-110264', product: 'gitlab', severity: 'critical', officialSeverity: 'Critical', domains: [interval('7.0.0', '19.6.0')],
    affected: [['7.0.0', '18.11.13'], ['19.0.0', '19.0.10'], ['19.1.0', '19.1.9'], ['19.2.0', '19.2.9'], ['19.3.0', '19.3.6'], ['19.4.0', '19.4.3'], ['19.5.0', '19.5.1']].map(([from, to]) => interval(from, to)),
    fixed: ['18.11.13', '19.0.10', '19.1.9', '19.2.9', '19.3.6', '19.4.3', '19.5.1'], conditions: ['gitlab_regex'], sources: ['https://docs.gitlab.com/ja-jp/releases/patches/patch-release-gitlab-19-5-1-released/'] }),
  ...(['103119', '101356', '101296', '93446', '88041'] as const).map((id, i) => {
    const from = [['11.0.0'], ['11.0.22', '10.1.55', '9.0.118'], ['11.0.0', '10.1.0', '9.0.0'], ['11.0.0', '10.1.25', '9.0.90'], ['11.0.0', '10.1.27', '9.0.92']][i];
    return advisory({ id: `CVE-2026-${id}`, product: 'tomcat', severity: i < 3 ? 'unknown' : 'low', officialSeverity: i < 3 ? 'Important' : 'Low',
      domains: from.map(version => branch(version.split('.').slice(0, 2).join('.'))), affected: from.map((version, j) => interval(version, tomcatFixes[j])), fixed: tomcatFixes.slice(0, from.length),
      conditions: [(['ajp', 'http2_async', 'jndi_realm', 'tls13', 'http2_trailers'] as const)[i]], sources: (i ? [11, 10, 9] : [11]).map(series => `https://tomcat.apache.org/security-${series}.html`), publishedAt: '2026-10-20' });
  }),
];
// Freeze every nested value: a plan and its run must refer to identical catalog semantics.
function freeze<T>(value: T): T { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
export const catalog = freeze({ schema: 'scanmux.advisories/v1' as const, asOf: confirmedAt, records });
export const catalogIdentity = freeze({ schema: catalog.schema, asOf: catalog.asOf, sha256: digest(catalog) });
