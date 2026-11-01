import path from 'node:path';
import { record, SafeError } from './safety.ts';

export interface NpmPackage {
  readonly name: string;
  readonly version: string | null;
  readonly local: boolean;
  readonly dev: boolean;
}

/** Only committed lockfile declarations can establish that an npm package is local. */
export function npmLockfilePackages(bytes: Uint8Array): NpmPackage[] {
  try {
    const lock = record(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    const result: NpmPackage[] = [];
    const version = (entry: Record<string, unknown>) => typeof entry.version === 'string' && entry.version ? entry.version : null;
    const dev = (entry: Record<string, unknown>) => entry.dev === true || entry.devOptional === true;
    if (lock.lockfileVersion === 2 || lock.lockfileVersion === 3) {
      const packages = record(lock.packages), root = record(packages[''] ?? {});
      const workspaces = Array.isArray(root.workspaces) ? root.workspaces
        : root.workspaces && typeof root.workspaces === 'object' ? record(root.workspaces).packages : [];
      const patterns = Array.isArray(workspaces) ? workspaces.filter((value): value is string => typeof value === 'string') : [];
      const linkNames = new Map<string, string>();
      for (const [key, value] of Object.entries(packages)) {
        const entry = record(value);
        if (entry.link === true && typeof entry.resolved === 'string') linkNames.set(entry.resolved, key.split('node_modules/').at(-1)!);
      }
      for (const [key, value] of Object.entries(packages)) {
        const entry = record(value);
        if (!key) continue;
        const target = entry.link === true && typeof entry.resolved === 'string' ? packages[entry.resolved] : undefined;
        const linked = target === undefined ? {} : record(target);
        const name = typeof entry.name === 'string' ? entry.name : typeof linked.name === 'string' ? linked.name
          : linkNames.get(key) ?? (key.includes('node_modules/') ? key.split('node_modules/').at(-1)! : path.posix.basename(key));
        // Installed dependencies inside a workspace are still registry packages.
        const matches = (pattern: string) => path.posix.matchesGlob(key, pattern.replace(/^\.\//, '').replace(/\/$/, ''));
        const workspace = !key.split('/').includes('node_modules') && patterns.some(pattern => !pattern.startsWith('!') && matches(pattern))
          && !patterns.some(pattern => pattern.startsWith('!') && matches(pattern.slice(1)));
        result.push({ name, version: version(entry) ?? version(linked), local: entry.link === true || workspace, dev: dev(entry) });
      }
    } else if (lock.lockfileVersion === 1) {
      const walk = (dependencies: unknown) => {
        for (const [name, value] of Object.entries(record(dependencies ?? {}))) {
          const entry = record(value);
          result.push({ name, version: version(entry), local: false, dev: dev(entry) });
          walk(entry.dependencies);
        }
      };
      walk(lock.dependencies);
    }
    return result;
  } catch { throw new SafeError('lockfile_invalid'); }
}

export function matchingNpmPackages(packages: readonly NpmPackage[], name: string, version: string | null): readonly NpmPackage[] {
  return packages.filter(entry => entry.name === name && (version === null || entry.version === null || entry.version === version));
}
