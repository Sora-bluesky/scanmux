import { catalogIdentity } from './advisory-catalog.ts';
import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { canonical, digest, hash, SafeError, safeRelative } from './safety.ts';
import { execute, jobDiskDiagnostic, verifyVersion } from './process.ts';
import type { CommitPair, Config, Plan } from './model.ts';
import { changedEntries, commitPair, treeEntries, type TreeEntry } from './comparison.ts';
import { fetchGitHub, type AcquisitionObserver } from './github.ts';
import { observeConfiguration, summarizeConfiguration, type ConfigurationObservation } from './configuration.ts';
import { readGitBlobs } from './git-blobs.ts';
import { legacyEngines, trivyEngines } from './engine-catalog.ts';
import { inventoryTrivy } from './trivy-plan.ts';
import { sourceCleanupFor } from './source-cleanup.ts';

export const lockNames = ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'requirements.txt', 'poetry.lock', 'uv.lock', 'go.mod', 'go.sum', 'Cargo.lock'];
const required = legacyEngines;
async function exists(file: string): Promise<boolean> { try { await lstat(file); return true; } catch { return false; } }

async function checkMetadata(root: string, acquiredCommit?: string): Promise<void> {
  const gitDir = path.join(root, '.git');
  const stat = await lstat(gitDir).catch(() => null);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) throw new SafeError('ordinary_git_directory_required');
  await canonical(gitDir);
  // Reject linked object/ref/index metadata before Git can read outside this repository.
  async function checkLinks(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) throw new SafeError('linked_git_metadata');
      if (entry.isDirectory()) await checkLinks(path.join(directory, entry.name));
    }
  }
  await checkLinks(gitDir);
  for (const file of ['commondir', 'objects/info/alternates', 'objects/info/http-alternates']) {
    if (await exists(path.join(gitDir, file))) throw new SafeError('unsupported_git_layout');
  }
  if (await exists(path.join(gitDir, 'shallow'))) {
    if (!acquiredCommit || (await readFile(path.join(gitDir, 'shallow'), 'utf8')).trim() !== acquiredCommit) throw new SafeError('unsupported_git_layout');
  }
  await checkGitConfig(path.join(gitDir, 'config'));
  const worktreeConfig = path.join(gitDir, 'config.worktree');
  if (await exists(worktreeConfig)) await checkGitConfig(worktreeConfig);
}
// These identity, push and branch-management keys are inert for rev-parse, status,
// ls-tree, cat-file and merge-base. Recheck this policy when adding Git commands.
const gitConfigPolicy: Record<string, RegExp | null> = {
  'core.repositoryformatversion': /^0$/, 'core.bare': /^false$/i,
  'core.filemode': null, 'core.logallrefupdates': null, 'core.symlinks': null, 'core.ignorecase': null,
  'remote.url': null, 'remote.fetch': null, 'branch.remote': null, 'branch.merge': null,
  'extensions.worktreeconfig': /^(true|false)$/i,
  'user.name': null, 'user.email': null, 'user.signingkey': null, 'user.useconfigonly': null,
  'push.default': null, 'push.followtags': null, 'push.autosetupremote': null,
  'branch.description': null, 'branch.rebase': null, 'branch.pushremote': null, 'branch.vscode-merge-base': null,
  // Every target invocation through gitExit overrides these four settings.
  'core.hookspath': null, 'core.fsmonitor': null, 'core.attributesfile': null, 'core.excludesfile': null,
  // Keep conversion settings effective for status; snapshots read committed blobs.
  'core.autocrlf': /^(false|true|input)$/i, 'core.safecrlf': /^(false|true|warn)$/i, 'core.eol': /^(lf|crlf|native)$/i,
};
async function checkGitConfig(file: string): Promise<void> {
  const configPath = await canonical(file);
  const raw = await readFile(configPath, 'utf8');
  if (raw.length > 65536) throw new SafeError('unsupported_git_config');
  let section = '';
  for (const line of raw.split(/\r?\n/)) {
    const text = line.trim();
    if (!text || /^[#;]/.test(text)) continue;
    const heading = /^\[([a-z0-9-]+)(?: "[^"\r\n]+")?\]$/i.exec(text);
    if (heading) { section = heading[1].toLowerCase(); continue; }
    const setting = /^([a-z][a-z0-9-]*)\s*=\s*([^\r\n]*)$/i.exec(text);
    if (!section || !setting) throw new SafeError('unsupported_git_config');
    const variable = setting[1].toLowerCase(), key = `${section}.${variable}`;
    const code = section.length <= 64 && variable.length <= 64 ? `unsupported_git_config:${key}` : 'unsupported_git_config';
    if (!Object.hasOwn(gitConfigPolicy, key) || /\\$/.test(text) || gitConfigPolicy[key] && !gitConfigPolicy[key]!.test(setting[2])) throw new SafeError(code);
  }
}
async function gitExit(root: string, config: Config, workspace: string, args: string[], signal?: AbortSignal,
  batch?: { input: string; maxOutputBytes: number }) {
  const tool = config.tools.git;
  if (!tool) throw new SafeError('git_not_configured');
  const invocation = await execute(tool, ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${workspace}`, '-c', 'core.attributesFile=', '-c', 'core.excludesFile=', '-c', 'protocol.allow=never', '-C', root, ...args], {
    cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: batch?.maxOutputBytes ?? Math.max(config.maxOutputBytes, config.maxFileBytes), target: root, signal, input: batch?.input,
  });
  if (invocation.reason !== 'exit') throw new SafeError(invocation.reason.startsWith('job_disk_') ? invocation.reason : 'git_' + invocation.reason);
  const diskCause = jobDiskDiagnostic(invocation);
  if (diskCause && [0, 1].includes(invocation.code ?? -1)) throw new SafeError(diskCause);
  return invocation;
}
async function git(root: string, config: Config, workspace: string, args: string[], signal?: AbortSignal,
  batch?: { input: string; maxOutputBytes: number }): Promise<Buffer> {
  const invocation = await gitExit(root, config, workspace, args, signal, batch);
  if (invocation.code !== 0) throw new SafeError('git_failed');
  return invocation.stdout;
}
export interface CommitFact { readonly exists: boolean; readonly ancestor: boolean; readonly paths: readonly string[] }
export interface CommitFacts { readonly head: string; readonly dirty: boolean; readonly commits: ReadonlyMap<string, CommitFact> }
// An answer is "<oid> <type> <size>" (oid 40, type at most 6, size at most 20 digits) or the query echoed with " missing".
const foundAnswerBytes = 40 + 1 + 6 + 1 + 20 + 1;
/** Asks cat-file --batch-check one line per query, in batches whose longest possible answers fit the output limit. */
async function batchCheck(root: string, config: Config, workspace: string, queries: readonly string[], signal?: AbortSignal): Promise<string[]> {
  const answers: string[] = [];
  let batch: string[] = [], bound = 0;
  const flush = async () => {
    const lines = (await git(root, config, workspace, ['cat-file', '--batch-check'], signal, { input: batch.join('\n') + '\n', maxOutputBytes: config.maxOutputBytes })).toString('utf8').split('\n');
    if (lines.pop() !== '' || lines.length !== batch.length) throw new SafeError('invalid_git_batch');
    answers.push(...lines); batch = []; bound = 0;
  };
  for (const query of queries) {
    const most = Math.max(foundAnswerBytes, Buffer.byteLength(query) + ' missing\n'.length);
    if (most > config.maxOutputBytes) throw new SafeError('git_output_limit');
    if (bound + most > config.maxOutputBytes) await flush();
    batch.push(query); bound += most;
  }
  if (batch.length) await flush();
  return answers;
}
/** Observes HEAD, worktree dirtiness and, per wanted commit, existence, strict ancestry of HEAD and which of that commit's wanted paths its tree holds. */
export async function commitFacts(target: string, config: Config, workspace: string, wanted: ReadonlyMap<string, readonly string[]>, signal?: AbortSignal): Promise<CommitFacts> {
  const unique = [...wanted.keys()].sort();
  if (unique.some(commit => !/^[a-f0-9]{40}$/.test(commit))) throw new SafeError('invalid_comparison_sha');
  for (const names of wanted.values()) for (const name of names) safeRelative(name);
  const root = await canonical(target);
  await checkMetadata(root);
  if (!config.tools.git) throw new SafeError('git_not_configured');
  await verifyVersion(config.tools.git, ['--version'], { cwd: workspace, home: workspace, timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, target: root, signal });
  const head = (await git(root, config, workspace, ['rev-parse', '--verify', 'HEAD^{commit}'], signal)).toString().trim();
  if (!/^[a-f0-9]{40}$/.test(head)) throw new SafeError('unsupported_git_format');
  const dirty = (await git(root, config, workspace, ['status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=all'], signal)).length > 0;
  const result = new Map<string, CommitFact>(), types = new Map<string, string>();
  for (const [index, answer] of (await batchCheck(root, config, workspace, unique, signal)).entries()) {
    const commit = unique[index], found = /^([a-f0-9]{40}) ([a-z]+) \d+$/.exec(answer);
    if (found ? found[1] !== commit : answer !== `${commit} missing`) throw new SafeError('invalid_git_batch');
    types.set(commit, found?.[2] ?? 'missing');
  }
  const present = unique.filter(commit => types.get(commit) === 'commit');
  const queries = present.flatMap(commit => [...new Set(wanted.get(commit))].sort().map(name => ({ commit, name, line: `${commit}:${name}` })));
  const held = new Map<string, string[]>(present.map(commit => [commit, []]));
  for (const [index, answer] of (await batchCheck(root, config, workspace, queries.map(item => item.line), signal)).entries()) {
    const query = queries[index], found = /^[a-f0-9]{40} (blob|commit|tree) \d+$/.exec(answer);
    if (!found && answer !== `${query.line} missing`) throw new SafeError('invalid_git_batch');
    if (found && found[1] !== 'tree') held.get(query.commit)!.push(query.name);
  }
  for (const commit of unique) {
    if (types.get(commit) !== 'commit') { result.set(commit, { exists: false, ancestor: false, paths: [] }); continue; }
    const ancestry = commit === head ? null : await gitExit(root, config, workspace, ['merge-base', '--is-ancestor', commit, head], signal);
    if (ancestry && ancestry.code !== 0 && ancestry.code !== 1) throw new SafeError('git_failed');
    result.set(commit, { exists: true, ancestor: ancestry?.code === 0, paths: held.get(commit)! });
  }
  return { head, dirty, commits: result };
}
function contentExclusion(content: Buffer): 'lfs_pointer' | 'binary_content_unsupported' | null {
  if (content.subarray(0, 128).toString().startsWith('version https://git-lfs.github.com/spec/v1')) return 'lfs_pointer';
  return content.includes(0) ? 'binary_content_unsupported' : null;
}
export interface CommitFiles { readonly files: Map<string, Buffer>; readonly exclusions: { path: string; reason: string }[] }
/** Reads only the selected tracked blobs of one verified commit, with the Plan's tree limits and LFS/binary exclusions. */
export async function readCommitFiles(root: string, config: Config, workspace: string, commit: string, select: (file: string) => boolean, signal?: AbortSignal): Promise<CommitFiles> {
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new SafeError('invalid_comparison_sha');
  const result: CommitFiles = { files: new Map(), exclusions: [] };
  const selected = [...treeEntries(await git(root, config, workspace, ['ls-tree', '-r', '-z', '-l', commit], signal), config)].filter(entry => select(entry.path));
  const regular = selected.filter(entry => ['100644', '100755'].includes(entry.mode));
  for (const entry of selected) if (!regular.includes(entry)) result.exclusions.push({ path: entry.path, reason: 'symlink_or_submodule' });
  const blobs = readGitBlobs(regular, (oids, maxOutputBytes) => git(root, config, workspace, ['cat-file', '--batch'], signal, { input: oids.join('\n') + '\n', maxOutputBytes }),
    Math.max(config.maxOutputBytes, config.maxFileBytes), signal);
  for await (const { entry, content } of blobs) {
    if (content.length !== entry.bytes) throw new SafeError('blob_size_mismatch');
    const excluded = contentExclusion(content);
    if (excluded) result.exclusions.push({ path: entry.path, reason: excluded });
    else result.files.set(entry.path, Buffer.from(content));
  }
  return result;
}
/** Complete, accepted committed directory identity; callable as data plumbing, never an executor. */
export async function readTestFiles(root: string, config: Config, workspace: string, commit: string, directory: string, signal: AbortSignal) {
  safeRelative(directory);
  const selected = (name: string) => name.startsWith(directory + '/');
  const entries = [...treeEntries(await git(root, config, workspace, ['ls-tree', '-r', '-z', '-l', commit], signal), config)].filter(entry => selected(entry.path));
  if (!entries.some(entry => entry.path === directory + '/test.mjs')) throw new SafeError('test_missing');
  if (entries.some(entry => !['100644', '100755'].includes(entry.mode))) throw new SafeError('unsupported_test');
  const accepted = await readCommitFiles(root, config, workspace, commit, selected, signal);
  if (accepted.exclusions.length || accepted.files.size !== entries.length) throw new SafeError('unsupported_test');
  return entries.map(entry => ({ path: entry.path, mode: entry.mode as '100644' | '100755', bytes: entry.bytes, sha256: hash(accepted.files.get(entry.path)!) }));
}
export interface TestModeCapture { readonly directory: string; readonly modes: Map<string, '100644' | '100755'> }
type TestModes = Readonly<Record<string, '100644' | '100755'>>;
export async function buildPlan(target: string, config: Config, workspace: string, signal?: AbortSignal, comparison?: CommitPair, testModes?: TestModeCapture): Promise<Plan> {
  const pair = comparison === undefined ? undefined : commitPair(comparison.base, comparison.head);
  if (testModes) { safeRelative(testModes.directory); testModes.modes.clear(); }
  return buildPlanCore(target, config, workspace, signal, undefined, pair, testModes);
}
export async function prepareGitHubPlan(url: string, config: Config, workspace: string, signal?: AbortSignal, observe?: AcquisitionObserver, batchDeadline?: AbortSignal): Promise<Plan> {
  if (config.tools.trivy) throw new SafeError('trivy_entry_unsupported');
  const deadline = batchDeadline ? AbortSignal.any([AbortSignal.timeout(config.timeoutMs), batchDeadline]) : AbortSignal.timeout(config.timeoutMs);
  const userSignal = signal ?? new AbortController().signal;
  const combined = AbortSignal.any([deadline, userSignal]);
  const receipt = await fetchGitHub(url, config, workspace, userSignal, deadline, observe);
  if (deadline.aborted) throw new SafeError('git_timeout');
  if (userSignal.aborted) throw new SafeError('git_cancelled');
  return buildPlanCore(receipt.root, config, workspace, combined, receipt);
}
async function buildPlanCore(target: string, config: Config, workspace: string, signal?: AbortSignal,
  acquired?: { root: string; commit: string; url: string }, comparison?: CommitPair, testModes?: TestModeCapture): Promise<Plan> {
  const root = await canonical(target);
  const configurationObservations: ConfigurationObservation[] = [];
  const trivyFiles = new Map<string, Buffer>();
  const plan: Plan = {
    schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, repoId: hash(root), root, commit: null, treeHash: null,
    snapshotHash: '', dirty: null, files: [], exclusions: [], blockers: [], languages: [], lockfiles: [],
    required: [...required], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [],
    constraints: ['clean_committed_git_only', 'tracked_files_only', 'git_history_not_scanned', 'no_build_or_scripts', 'ai_isolation_unverified', 'offline_only', 'same_user_concurrent_mutation_not_supported'],
    cost: { kind: 'not_applicable', aiCalls: 0 },
  };
  try {
    await checkMetadata(root, acquired?.commit);
    if (!config.tools.git) throw new SafeError('git_not_configured');
    await verifyVersion(config.tools.git, ['--version'], { cwd: workspace, home: workspace,
      timeoutMs: config.timeoutMs, maxOutputBytes: config.maxOutputBytes, target: root, signal });
    plan.commit = (await git(root, config, workspace, ['rev-parse', '--verify', `${comparison?.head ?? 'HEAD'}^{commit}`], signal)).toString().trim();
    if (!/^[a-f0-9]{40}$/.test(plan.commit)) throw new SafeError('unsupported_git_format');
    if (comparison && plan.commit !== comparison.head) throw new SafeError('comparison_commit_mismatch');
    if (acquired && (root !== acquired.root || plan.commit !== acquired.commit)) throw new SafeError('acquired_commit_mismatch');
    plan.treeHash = (await git(root, config, workspace, ['rev-parse', `${plan.commit}^{tree}`], signal)).toString().trim();
    plan.dirty = acquired ? false : (await git(root, config, workspace, ['status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=all'], signal)).length > 0;
    if (plan.dirty) plan.blockers.push('dirty_worktree_unsupported');
    const tree = await git(root, config, workspace, ['ls-tree', '-r', '-z', '-l', plan.commit], signal);
    const headEntries: TreeEntry[] = [];
    let treeError: unknown;
    try { for (const entry of treeEntries(tree, config)) headEntries.push(entry); }
    catch (error) { treeError = error; }
    const blobs = readGitBlobs(headEntries.filter(entry => ['100644', '100755'].includes(entry.mode)),
      (oids, maxOutputBytes) => git(root, config, workspace, ['cat-file', '--batch'], signal, { input: oids.join('\n') + '\n', maxOutputBytes }),
      Math.max(config.maxOutputBytes, config.maxFileBytes), signal);
    for (const entry of headEntries) {
      const { path: name, bytes, oid, mode } = entry;
      if (!['100644', '100755'].includes(mode)) { plan.exclusions.push({ path: name, reason: 'symlink_or_submodule' }); continue; }
      const next = await blobs.next();
      if (next.done || next.value.entry !== entry) throw new SafeError('invalid_git_blob_batch');
      const { content } = next.value;
      if (content.length !== bytes) throw new SafeError('blob_size_mismatch');
      const excluded = contentExclusion(content);
      if (excluded) { plan.exclusions.push({ path: name, reason: excluded }); continue; }
      plan.files.push({ path: name, oid, bytes, sha256: hash(content) });
      if (testModes && name.startsWith(testModes.directory + '/')) testModes.modes.set(name, mode as '100644' | '100755');
      if (config.tools.trivy) trivyFiles.set(name, content);
      configurationObservations.push(observeConfiguration(name, content));
    }
    if (treeError !== undefined) throw treeError;
    if (comparison) {
      const baseCommit = (await git(root, config, workspace, ['rev-parse', '--verify', `${comparison.base}^{commit}`], signal)).toString().trim();
      if (baseCommit !== comparison.base) throw new SafeError('comparison_commit_mismatch');
      const baseTree = (await git(root, config, workspace, ['rev-parse', `${baseCommit}^{tree}`], signal)).toString().trim();
      const baseEntries = [...treeEntries(await git(root, config, workspace, ['ls-tree', '-r', '-z', '-l', baseCommit], signal), config)];
      plan.comparison = { schema: 'scanmux.comparison/v1', baseCommit, headCommit: plan.commit,
        baseTree, headTree: plan.treeHash, scope: 'full_head', baseline: 'not_compared', changes: changedEntries(baseEntries, headEntries) };
      plan.constraints.push('diff_context_full_head_scanned', 'base_findings_not_compared', 'renames_recorded_as_delete_add');
    }
    plan.lockfiles = plan.files.filter(f => lockNames.includes(path.posix.basename(f.path))).map(f => f.path);
    plan.languages = [...new Set(plan.files.flatMap(f => /\.(?:[cm]?[jt]sx?)$/.test(f.path) || /(?:package-lock.json|pnpm-lock.yaml|yarn.lock)$/.test(f.path) ? ['JS/TS'] : /(?:\.py|requirements.txt|poetry.lock|uv.lock)$/.test(f.path) ? ['Python'] : /(?:\.go|go.mod|go.sum)$/.test(f.path) ? ['Go'] : /(?:\.rs|Cargo.toml|Cargo.lock)$/.test(f.path) ? ['Rust'] : []))];
    if (!plan.files.length) plan.blockers.push('empty_snapshot');
  } catch (error) { plan.blockers.push(error instanceof SafeError ? error.code : 'repository_unavailable'); }
  if (acquired) {
    plan.source = { kind: 'public-github', url: acquired.url, commit: acquired.commit };
    plan.constraints = plan.constraints.filter(c => c !== 'clean_committed_git_only');
    plan.constraints.push('fixed_public_commit', 'fetch_size_checked_after_transfer');
  }
  plan.configuration = summarizeConfiguration(configurationObservations);
  plan.snapshotHash = digest(plan.files);
  if (config.tools.trivy) {
    const enabled: Plan = { ...plan, schema: 'scanmux.plan/v3', required: [...trivyEngines], trivy: inventoryTrivy(trivyFiles) };
    enabled.planHash = digest({ ...enabled, planHash: '' });
    return enabled;
  }
  plan.planHash = digest({ ...plan, planHash: '' });
  return plan;
}
export async function materialize(plan: Plan, config: Config, workspace: string, signal: AbortSignal, testModes?: TestModes): Promise<string> {
  const cleanup = sourceCleanupFor(workspace), snapshot = cleanup.register(workspace, path.join(workspace, 'snapshot'));
  await mkdir(snapshot, { mode: 0o700 });
  await cleanup.capture(workspace, snapshot);
  const blobs = readGitBlobs(plan.files,
    (oids, maxOutputBytes) => git(plan.root, config, workspace, ['cat-file', '--batch'], signal, { input: oids.join('\n') + '\n', maxOutputBytes }),
    Math.max(config.maxOutputBytes, config.maxFileBytes), signal);
  for await (const { entry: file, content } of blobs) {
    if (signal.aborted) throw new SafeError('cancelled');
    if (content.length !== file.bytes || hash(content) !== file.sha256) throw new SafeError('snapshot_integrity');
    const destination = path.join(snapshot, file.path);
    await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await writeFile(destination, content, { flag: 'wx', mode: testModes?.[file.path] === '100755' ? 0o700 : 0o600 });
  }
  return snapshot;
}
export async function verifySnapshot(plan: Plan, snapshot: string, testModes?: TestModes): Promise<boolean> {
  const found: string[] = [];
  async function walk(folder: string): Promise<void> {
    for (const entry of await readdir(folder, { withFileTypes: true })) {
      const absolute = path.join(folder, entry.name);
      if (entry.isSymbolicLink()) throw new SafeError('snapshot_integrity');
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile()) found.push(path.relative(snapshot, absolute).split(path.sep).join('/'));
      else throw new SafeError('snapshot_integrity');
    }
  }
  try {
    await walk(snapshot);
    if (found.length !== plan.files.length) return false;
    for (const file of plan.files) if (!found.includes(file.path) || hash(await readFile(path.join(snapshot, file.path))) !== file.sha256) return false;
    if (testModes) for (const [name, mode] of Object.entries(testModes)) {
      const stat = await lstat(path.join(snapshot, name));
      if (!stat.isFile() || (stat.mode & 0o7777) !== (mode === '100755' ? 0o700 : 0o600)) return false;
    }
    return true;
  } catch { return false; }
}
