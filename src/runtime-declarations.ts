import path from 'node:path';
import { parseVersion, type Product } from './advisory-catalog.ts';
import { SafeError, safeRelative } from './safety.ts';
import type { Declaration, DeclarationReason } from './model.ts';

export function declarationInput(file: string): boolean {
  const name = path.posix.basename(file);
  return ['.nvmrc', '.node-version', '.php-version', '.tool-versions', 'package-lock.json', 'npm-shrinkwrap.json'].includes(name) || /^Dockerfile(?:\..+)?$/.test(name);
}
function declaration(file: string, product: Product | null, line: number | null, reason: DeclarationReason, version: string | null = null, selector: string | null = null, edition: 'ce' | 'ee' | null = null): Declaration {
  return { file, product, line, version, selector, edition, reason, assessments: [] };
}
const variants: Record<Exclude<Product, 'next' | 'gitlab'>, RegExp> = {
  node: /^(?:|-(?:slim|alpine(?:[0-9]+\.[0-9]+)?|(?:bookworm|bullseye|trixie)(?:-slim)?))$/,
  php: /^(?:|-(?:cli|fpm|apache|zts)(?:-(?:alpine(?:[0-9]+\.[0-9]+)?|bookworm|bullseye|trixie))?|-(?:alpine(?:[0-9]+\.[0-9]+)?|bookworm|bullseye|trixie))$/,
  nginx: /^(?:|-(?:alpine(?:[0-9]+\.[0-9]+)?|bookworm|trixie))$/,
  tomcat: /^(?:|-jdk(?:8|11|17|21|25)-(?:temurin|corretto)(?:-(?:jammy|noble|alpine))?)$/,
};
function docker(file: string, lines: string[]): Declaration[] {
  if (lines.some(line => /^\s*#\s*escape\s*=/i.test(line) || !/^\s*#/.test(line) && (/\\\s*$/.test(line) || line.includes('<<')))) return [declaration(file, null, null, 'unsupported_docker_syntax')];
  const result: Declaration[] = [];
  for (const [index, raw] of lines.entries()) {
    if (!/^\s*FROM(?:\s|$)/i.test(raw)) continue;
    const option = raw.trim().split(/\s+/)[1];
    if (option?.startsWith('--') && !/^--platform=[a-z0-9/]+$/.test(option)) { result.push(declaration(file, null, index + 1, 'unsupported_docker_syntax')); continue; }
    const match = /^\s*FROM\s+(?:--platform=[a-z0-9/]+\s+)?([^\s]+)(?:\s+AS\s+[a-z0-9._-]+)?\s*$/i.exec(raw);
    if (!match || /["'$`]/.test(match[1]) || /--platform=[^\s]*[A-Z]/.test(raw)) { result.push(declaration(file, null, index + 1, 'unsupported_docker_syntax')); continue; }
    const image = match[1];
    const identity = image.split(/[:@]/)[0];
    let product: Product | null = null; let edition: 'ce' | 'ee' | null = null;
    for (const candidate of ['node', 'php', 'nginx', 'tomcat'] as const) {
      if ([candidate, `library/${candidate}`, `docker.io/library/${candidate}`].includes(identity)) product = candidate;
    }
    const gitlab = /^(?:docker\.io\/)?gitlab\/gitlab-(ce|ee)$/.exec(identity);
    if (gitlab) { product = 'gitlab'; edition = gitlab[1] as 'ce' | 'ee'; }
    if (!product) { result.push(declaration(file, null, index + 1, 'unsupported_image')); continue; }
    if (image.includes('@') || !image.startsWith(identity + ':')) { result.push(declaration(file, product, index + 1, 'dynamic_image', null, null, edition)); continue; }
    const tag = image.slice(identity.length + 1);
    const parsed = /^([0-9]+\.[0-9]+\.[0-9]+)(.*)$/.exec(tag);
    if (!parsed || !parseVersion(parsed[1])) { result.push(declaration(file, product, index + 1, 'invalid_version', null, null, edition)); continue; }
    const valid = product === 'gitlab' ? new RegExp(`^-${edition}\\.(0|[1-9][0-9]*)$`).test(parsed[2]) : variants[product].test(parsed[2]);
    result.push(declaration(file, product, index + 1, valid ? 'exact_declaration' : 'unsupported_image_variant', valid ? parsed[1] : null, null, edition));
  }
  return result;
}
function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function dependencyPath(value: string): string | null {
  try { const clean = safeRelative(value); return /^[a-zA-Z0-9@._/-]+$/.test(clean) ? clean : null; } catch { return null; }
}
function registrySource(value: unknown): boolean {
  if (value === undefined) return true;
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password
      && !/(^|\.)(github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org)$/.test(url.hostname)
      && !/\.git(?:\/|$)|\/(?:tarball|archive)\//.test(url.pathname);
  } catch { return false; }
}
function npm(file: string, text: string): Declaration[] {
  let lock: unknown;
  try { lock = JSON.parse(text); } catch { throw new SafeError('advisory_input_invalid'); }
  if (!object(lock) || ![1, 2, 3].includes(Number(lock.lockfileVersion)) || !Number.isInteger(lock.lockfileVersion)) throw new SafeError('advisory_input_invalid');
  const result: Declaration[] = [];
  function add(entry: unknown, selector: string, alias: boolean) {
    let reason: DeclarationReason = 'exact_declaration'; let version: string | null = null;
    const clean = dependencyPath(selector);
    if (alias) reason = 'npm_alias';
    else if (!object(entry) || !clean || entry.name !== undefined && entry.name !== 'next') reason = 'npm_entry_ambiguous';
    else if (entry.link === true) reason = 'npm_link';
    else if (entry.link !== undefined && entry.link !== false) reason = 'npm_entry_ambiguous';
    else if (!registrySource(entry.resolved)) reason = 'npm_source';
    else if (typeof entry.version !== 'string' || !parseVersion(entry.version)) reason = 'invalid_version';
    else version = entry.version;
    result.push(declaration(file, 'next', null, reason, version, clean));
  }
  if (lock.lockfileVersion === 1) {
    if (!object(lock.dependencies)) throw new SafeError('advisory_input_invalid');
    const pending: { entries: Record<string, unknown>; prefix: string }[] = [{ entries: lock.dependencies, prefix: '' }];
    while (pending.length) {
      const { entries, prefix } = pending.pop()!;
      for (const [name, entry] of Object.entries(entries)) {
        const selector = `${prefix}node_modules/${name}`;
        const alias = name !== 'next' && object(entry) && (entry.name === 'next' || typeof entry.version === 'string' && entry.version.startsWith('npm:next@'));
        if (name === 'next' || alias) add(entry, selector, alias);
        if (object(entry) && entry.dependencies !== undefined) {
          if (!object(entry.dependencies)) throw new SafeError('advisory_input_invalid');
          pending.push({ entries: entry.dependencies, prefix: selector + '/' });
        }
      }
    }
  } else {
    if (!object(lock.packages)) throw new SafeError('advisory_input_invalid');
    for (const [selector, entry] of Object.entries(lock.packages)) {
      if (!selector) continue;
      const named = /(?:^|\/)node_modules\/next$/.test(selector);
      const alias = !named && object(entry) && (entry.name === 'next' || typeof entry.version === 'string' && entry.version.startsWith('npm:next@'));
      if (named || alias) add(entry, selector, alias);
    }
  }
  return result;
}
export function extractDeclarations(file: string, text: string): Declaration[] {
  safeRelative(file);
  const name = path.posix.basename(file); const lines = text.split(/\r?\n/);
  if (/^Dockerfile(?:\..+)?$/.test(name)) return docker(file, lines);
  if (['package-lock.json', 'npm-shrinkwrap.json'].includes(name)) return npm(file, text);
  const payload = lines.map((value, index) => ({ value: value.trim(), line: index + 1 })).filter(row => row.value && !row.value.startsWith('#'));
  if (name === '.tool-versions') return payload.flatMap(({ value, line }) => {
    const tokens = value.split(/\s+/); const product = tokens[0] === 'nodejs' ? 'node' : tokens[0] === 'php' ? 'php' : null;
    if (!product) return [];
    const exact = tokens.length === 2 && parseVersion(tokens[1]);
    return [declaration(file, product, line, exact ? 'exact_declaration' : 'ambiguous_declaration', exact ? tokens[1] : null)];
  });
  if (!['.nvmrc', '.node-version', '.php-version'].includes(name)) return [];
  const product = name === '.php-version' ? 'php' : 'node';
  const value = payload.length === 1 ? payload[0].value.replace(product === 'node' ? /^v/ : /$^/, '') : '';
  const exact = parseVersion(value);
  return [declaration(file, product, payload[0]?.line ?? null, exact ? 'exact_declaration' : payload.length === 1 ? 'invalid_version' : 'ambiguous_declaration', exact ? value : null)];
}
