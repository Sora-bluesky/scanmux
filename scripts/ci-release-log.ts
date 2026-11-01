import { spawnSync } from 'node:child_process';
import { lstat, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { SafeError } from '../src/safety.ts';

const repository = path.resolve(import.meta.dirname, '..');
const runnerGit = 'C:\\Program Files\\Git\\cmd\\git.exe';
const commitPattern = /^[0-9a-f]{40}$/;

/**
 * actions/checkout runs `git sparse-checkout disable`, which leaves `.git/config.worktree` behind, so release-log-check
 * refuses the checkout itself. The check runs on a fresh repository that holds only the two commits' objects:
 * no hooks, no worktree config and none of the workspace's config.
 */
export async function prepareReleaseLogRepository({ git, source, destination, base, head }:
  { git: string; source: string; destination: string; base: string | null; head: string }): Promise<void> {
  if (!commitPattern.test(head) || (base !== null && !commitPattern.test(base))) throw new SafeError('invalid_release_commit');
  if (await lstat(destination).then(() => true, () => false)) throw new SafeError('release_log_repository_exists');
  const home = `${destination}-home`, globalConfig = path.join(home, 'empty-gitconfig');
  await mkdir(home); await writeFile(globalConfig, '', { flag: 'wx' });
  const run = (args: string[]) => {
    const result = spawnSync(git, args, { encoding: 'utf8', windowsHide: true, shell: false,
      env: { SystemRoot: process.env.SystemRoot, PATH: process.env.PATH, HOME: home, USERPROFILE: home, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: globalConfig, GIT_TERMINAL_PROMPT: '0' } });
    if (result.status !== 0) throw new SafeError('release_log_repository_failed');
    return result.stdout.trim();
  };
  run(['init', '--quiet', '--template=', destination]);
  run(['-C', destination, 'config', 'core.autocrlf', 'false']);
  const refspecs = [`${head}:refs/scanmux/head`, ...(base === null ? [] : [`${base}:refs/scanmux/base`])];
  run(['-C', destination, 'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--no-recurse-submodules', source, ...refspecs]);
  for (const [ref, commit] of [['refs/scanmux/head', head], ...(base === null ? [] : [['refs/scanmux/base', base]])] as const) {
    if (run(['-C', destination, 'rev-parse', '--verify', '--quiet', `${ref}^{commit}`]) !== commit) throw new SafeError('release_log_repository_failed');
  }
}

async function main(): Promise<number> {
  const temp = process.env.RUNNER_TEMP, workspace = process.env.GITHUB_WORKSPACE;
  if (!temp || !path.isAbsolute(temp) || !workspace || !path.isAbsolute(workspace)) throw new SafeError('runner_temp_required');
  const head = spawnSync(runnerGit, ['-C', workspace, 'rev-parse', '--verify', 'HEAD^{commit}'], { encoding: 'utf8', windowsHide: true });
  if (head.status !== 0) throw new SafeError('release_log_repository_failed');
  const base = process.env.BASE_SHA ? process.env.BASE_SHA : null, destination = path.join(temp, 'scanmux', 'release-log');
  await prepareReleaseLogRepository({ git: runnerGit, source: workspace, destination, base, head: head.stdout.trim() });
  const check = spawnSync(process.execPath, [path.join(repository, 'bin', 'scanmux.mjs'), 'release-log-check', destination, '--base', base ?? 'none',
    '--head', head.stdout.trim(), '--config', path.join(temp, 'scanmux', 'state', 'config.json')], { stdio: 'inherit', windowsHide: true });
  return check.status ?? 1;
}

if (import.meta.main) {
  try { process.exitCode = await main(); }
  catch (error) {
    process.stderr.write(`${JSON.stringify({ error: error instanceof SafeError ? error.code : 'release_log_repository_failed' })}\n`);
    process.exitCode = 4;
  }
}
