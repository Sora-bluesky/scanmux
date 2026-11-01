import { mkdir, readdir, lstat } from 'node:fs/promises';
import path from 'node:path';
import type { Config } from './model.ts';
import { canonical, SafeError } from './safety.ts';
import { execute } from './process.ts';
import { sourceCleanupFor } from './source-cleanup.ts';

export type AcquisitionPhase = 'version' | 'resolve' | 'init' | 'fetch' | 'bind';
export type AcquisitionObserver = (phase: AcquisitionPhase, state: 'running' | 'settled', pid?: number) => void;

export function githubUrl(input: string): string {
  const match = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9_.-]{1,100})\/?$/.exec(input);
  if (!match) throw new SafeError('public_github_url_required');
  const repository = match[2].replace(/\.git$/, '');
  if (!repository || repository === '.' || repository === '..') throw new SafeError('public_github_url_required');
  return `https://github.com/${match[1]}/${repository}`;
}

// Only this acquisition path supplies the planner's private no-worktree receipt.
export async function fetchGitHub(input: string, config: Config, workspace: string, signal: AbortSignal, deadline: AbortSignal, observe?: AcquisitionObserver): Promise<{ root: string; url: string; commit: string }> {
  const url = githubUrl(input);
  const tool = config.tools.git;
  if (!tool) throw new SafeError('git_not_configured');
  const cleanup = sourceCleanupFor(workspace);
  const root = cleanup.register(workspace, path.join(await canonical(workspace), 'repository'));
  const template = path.join(workspace, 'git-empty-template');
  const settings = [
    'core.fsmonitor=false', `core.hooksPath=${template}`, 'core.attributesFile=', 'core.excludesFile=',
    'credential.helper=', 'credential.interactive=false', 'protocol.allow=never', 'protocol.https.allow=always',
    'http.followRedirects=false', 'http.proxy=', 'http.sslVerify=true', 'http.emptyAuth=false',
    'http.proactiveAuth=none', 'http.delegation=none', 'http.extraHeader=', 'maintenance.auto=false', 'gc.auto=0',
  ].flatMap(value => ['-c', value]);
  const guard = () => {
    if (deadline.aborted) throw new SafeError('git_timeout');
    if (signal.aborted) throw new SafeError('git_cancelled');
  };
  const notify = (phase: AcquisitionPhase, state: 'running' | 'settled', pid?: number) => { try { observe?.(phase, state, pid); } catch { /* Progress is observational. */ } };
  const options = { cwd: workspace, home: workspace, timeoutMs: config.timeoutMs,
    maxOutputBytes: config.maxOutputBytes, signal: deadline, startSignal: AbortSignal.any([signal, deadline]) };
  const run = async (phase: AcquisitionPhase, args: string[]): Promise<string> => {
    guard();
    const result = await execute(tool, [...settings, ...args], { ...options, onSpawn: pid => notify(phase, 'running', pid) });
    notify(phase, 'settled');
    if (result.reason === 'cancelled' && deadline.aborted) throw new SafeError('git_timeout');
    if (result.reason !== 'exit') throw new SafeError('git_' + result.reason);
    if (result.code === null) throw new SafeError('git_termination_unverified');
    guard();
    if (result.code !== 0) throw new SafeError('public_github_fetch_failed');
    return result.stdout.toString('utf8');
  };
  const version = await run('version', ['--version']);
  const versions: string[] = version.match(/\b\d+\.\d+\.\d+\b/g) ?? [];
  if (!versions.includes(tool.version)) throw new SafeError('tool_version_mismatch');
  await mkdir(root, { mode: 0o700 });
  try {
    await cleanup.capture(workspace, root);
    await mkdir(template, { mode: 0o700 });
    const head = await run('resolve', ['ls-remote', '--exit-code', url, 'HEAD']);
    const match = /^([a-f0-9]{40})\s+HEAD\s*$/.exec(head);
    if (!match) throw new SafeError('public_github_head_unavailable');
    const commit = match[1];
    await run('init', ['init', `--template=${template}`, root]);
    await run('fetch', ['-C', root, 'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules', '--no-auto-maintenance', '--no-write-commit-graph', url, commit]);
    let bytes = 0;
    async function measure(folder: string): Promise<void> {
      for (const entry of await readdir(folder, { withFileTypes: true })) {
        guard();
        const file = path.join(folder, entry.name);
        if (entry.isSymbolicLink()) throw new SafeError('linked_git_metadata');
        if (entry.isDirectory()) await measure(file);
        else bytes += (await lstat(file)).size;
        if (bytes > config.maxSnapshotBytes) throw new SafeError('fetch_byte_limit');
      }
    }
    await measure(root);
    await run('bind', ['-C', root, 'update-ref', 'HEAD', commit]);
    const canonicalRoot = await canonical(root);
    guard();
    return { root: canonicalRoot, url, commit };
  } catch (error) {
    await cleanup.cleanup(workspace, [root]);
    throw error;
  }
}
