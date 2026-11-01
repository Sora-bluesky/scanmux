import type { CommitPair, Comparison, Config, Plan } from './model.ts';
import { SafeError, safeRelative } from './safety.ts';

const sha = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
export function commitPair(base: unknown, head: unknown): CommitPair | undefined {
  if (base === undefined && head === undefined) return undefined;
  if (!sha(base) || !sha(head)) throw new SafeError('invalid_comparison_sha');
  return { base, head };
}

export interface TreeEntry { path: string; mode: string; oid: string; bytes: number }
// Yield in Git's order so a bounded plan retains only observations made before a limit.
export function* treeEntries(tree: Buffer, config: Pick<Config, 'maxFiles' | 'maxFileBytes' | 'maxSnapshotBytes'>): Generator<TreeEntry> {
  const names = new Set<string>(), prefixes = new Map<string, string>();
  let total = 0;
  for (const entry of new TextDecoder('utf-8', { fatal: true }).decode(tree).split('\0').filter(Boolean)) {
    const match = /^(\d+) (blob|commit) ([a-f0-9]{40})\s+(\d+|-)\t(.+)$/.exec(entry);
    if (!match) throw new SafeError('invalid_git_tree');
    const name = safeRelative(match[5]), key = name.normalize('NFC').toLowerCase();
    if (name.split('/').some(p => p.toLowerCase() === '.git') || names.has(key)) throw new SafeError('unsafe_tree_path');
    names.add(key);
    const parts = name.split('/');
    for (let i = 1; i <= parts.length; i++) {
      const prefix = parts.slice(0, i).join('/'), prefixKey = prefix.normalize('NFC').toLowerCase();
      if (prefixes.has(prefixKey) && prefixes.get(prefixKey) !== prefix) throw new SafeError('unsafe_tree_path');
      prefixes.set(prefixKey, prefix);
    }
    if (names.size > config.maxFiles) throw new SafeError('snapshot_file_limit');
    const bytes = match[4] === '-' ? 0 : Number(match[4]);
    if (['100644', '100755'].includes(match[1])) {
      total += bytes;
      if (!Number.isSafeInteger(bytes) || bytes > config.maxFileBytes || total > config.maxSnapshotBytes) throw new SafeError('snapshot_byte_limit');
    }
    yield { path: name, mode: match[1], oid: match[3], bytes };
  }
}

export function changedEntries(base: TreeEntry[], head: TreeEntry[]): Comparison['changes'] {
  const before = new Map(base.map(entry => [entry.path, entry]));
  const after = new Map(head.map(entry => [entry.path, entry]));
  return [...new Set([...before.keys(), ...after.keys()])].sort().flatMap(name => {
    const old = before.get(name), current = after.get(name);
    if (old?.oid === current?.oid && old?.mode === current?.mode) return [];
    const kind = !old ? 'added' : !current ? 'deleted' : old.oid !== current.oid ? 'modified' : 'mode_changed';
    return [{ path: name, kind } as Comparison['changes'][number]];
  });
}

export function comparisonSummary(plan: Pick<Plan, 'comparison' | 'commit' | 'treeHash'>) {
  const comparison = plan.comparison;
  if (comparison === undefined) return null;
  if (!comparison || comparison.schema !== 'scanmux.comparison/v1' || comparison.scope !== 'full_head'
    || comparison.baseline !== 'not_compared' || !sha(comparison.baseCommit) || !sha(comparison.headCommit)
    || !sha(comparison.baseTree) || !sha(comparison.headTree) || comparison.headCommit !== plan.commit
    || comparison.headTree !== plan.treeHash || !Array.isArray(comparison.changes)) throw new SafeError('comparison_plan_mismatch');
  const paths = new Set<string>();
  for (const change of comparison.changes) {
    const name = safeRelative(change.path);
    if (!['added', 'deleted', 'modified', 'mode_changed'].includes(change.kind) || paths.has(name)) throw new SafeError('comparison_plan_mismatch');
    paths.add(name);
  }
  return { schema: comparison.schema, baseCommit: comparison.baseCommit, headCommit: comparison.headCommit,
    baseTree: comparison.baseTree, headTree: comparison.headTree, scope: comparison.scope,
    baseline: comparison.baseline, changedPaths: comparison.changes.length };
}
