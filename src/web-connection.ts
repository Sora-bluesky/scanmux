import { timingSafeEqual } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { SafeError } from './safety.ts';

export const webContract = 'scanmux.web/v2';

export function checkedSiteOrigin(value?: string): string | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol === 'https:' && url.origin === value && !url.username && !url.password) return value;
  } catch { /* Invalid operator configuration is never adopted. */ }
  throw new SafeError('invalid_site_origin');
}

function tokenMatches(supplied: string | string[] | undefined, expected?: string): boolean {
  return Boolean(expected && typeof supplied === 'string' && /^[a-f0-9]{64}$/.test(supplied)
    && timingSafeEqual(Buffer.from(supplied), Buffer.from(expected)));
}

export function siteApi(method?: string, route?: string): boolean {
  return method === 'GET' && (route === '/api/state' || /^\/api\/report\/[a-f0-9-]{36}(?:\/html)?$/.test(route ?? ''))
    || method === 'POST' && ['/api/prepare', '/api/run', '/api/cancel'].includes(route ?? '');
}

export function webAuthority(headers: IncomingHttpHeaders, localOrigin: string, localToken: string,
  siteOrigin?: string, siteToken?: string): 'local' | 'site' | undefined {
  const requestOrigin = headers.origin;
  if (headers.host !== new URL(localOrigin).host) return;
  if ((!requestOrigin || requestOrigin === localOrigin)
    && (!headers['sec-fetch-site'] || ['same-origin', 'none'].includes(String(headers['sec-fetch-site'])))
    && tokenMatches(headers['x-scanmux-token'], localToken)) return 'local';
  if (siteOrigin && requestOrigin === siteOrigin && tokenMatches(headers['x-scanmux-token'], siteToken)) return 'site';
}

export function sitePreflight(headers: IncomingHttpHeaders, route: string | undefined, localOrigin: string, siteOrigin?: string): boolean {
  const method = headers['access-control-request-method'];
  const requested = headers['access-control-request-headers'];
  if (!siteOrigin || headers.host !== new URL(localOrigin).host || headers.origin !== siteOrigin
    || typeof method !== 'string' || !siteApi(method, route) || typeof requested !== 'string') return false;
  const names = requested.toLowerCase().split(',').map(value => value.trim()).sort().join(',');
  return names === (method === 'POST' ? 'content-type,x-scanmux-token' : 'x-scanmux-token')
    && (!headers['access-control-request-private-network'] || headers['access-control-request-private-network'] === 'true');
}

export interface WebObservation {
  schema: 'scanmux.observation/v1';
  eventId: string;
  at: string;
  operation: 'prepare' | 'scan';
  outcome: 'planned' | 'blocked' | 'completed' | 'cancelled' | 'error';
  gate: 'PASS' | 'FAIL' | 'REVIEW' | 'INCOMPLETE' | 'ERROR' | 'not_available';
  reason: 'none' | 'operation_failed' | 'termination_unverified' | 'source_cleanup_failed' | 'public_github_fetch_failed'
    | 'public_github_head_unavailable' | 'git_timeout' | 'git_output_limit' | 'fetch_byte_limit'
    | 'git_not_configured' | 'tool_digest_mismatch' | 'tool_version_mismatch' | 'output_secret_check_unavailable'
    | 'output_secret_check_failed' | 'output_size_limit' | 'private_acl_unverified';
  files: number;
  findings: number;
}
