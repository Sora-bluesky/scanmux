import fs from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { spawn } from 'node:child_process';
import { digest, hash, safeRelative, within, SafeError } from '../src/safety.ts';
import { execute } from '../src/process.ts';
import { treeEntries } from '../src/comparison.ts';
import { gitleaksConfig } from '../src/adapters.ts';
import { privateAclRule } from '../src/private-acl.ts';
import { sourceCleanupFor } from '../src/source-cleanup.ts';

const object = x => x !== null && typeof x === 'object' && Object.getPrototypeOf(x) === Object.prototype;
const sha1 = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);
const requireValue = (value, code) => { if (!value) throw new SafeError(code); };
const attributes = ['text', 'filter', 'ident', 'working-tree-encoding', 'export-ignore', 'export-subst', 'eol'];
export const inspectPrivateAcl = `${privateAclRule}
$acl=[System.IO.DirectoryInfo]::new($env:SCANMUX_PROJECTION_WORKSPACE).GetAccessControl()
if (!(Test-PrivateAcl $acl $sid $elevated $true)) { exit 1 }
`;

async function directory(directory, step) {
  requireValue(typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) === directory, 'projection_directory');
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await step(() => fs.lstat(current));
    requireValue(stat.isDirectory() && !stat.isSymbolicLink(), 'projection_directory_link');
    requireValue(await step(() => fs.realpath(current)) === current, 'projection_directory_alias');
  }
}

function acceptedManifest(plan, config) {
  requireValue(object(plan) && plan.schema === 'scanmux.plan/v2' && sha1(plan.commit) && sha1(plan.treeHash) && plan.dirty === false && Array.isArray(plan.blockers) && plan.blockers.length === 0 && Array.isArray(plan.exclusions), 'projection_plan');
  requireValue(plan.planHash === digest({ ...plan, planHash: '' }) && plan.policyHash === digest(config) && plan.snapshotHash === digest(plan.files), 'projection_plan_hash');
  requireValue(Array.isArray(plan.files) && plan.files.length > 0, 'projection_empty');
  for (const key of ['timeoutMs', 'maxFiles', 'maxFileBytes', 'maxSnapshotBytes', 'maxOutputBytes']) requireValue(Number.isSafeInteger(config[key]) && config[key] > 0 && config[key] <= 2147483647, 'projection_limits');
  for (const file of plan.files) {
    requireValue(object(file) && Object.keys(file).sort().join(',') === 'bytes,oid,path,sha256' && sha1(file.oid) && /^[a-f0-9]{64}$/.test(file.sha256) && Number.isSafeInteger(file.bytes) && file.bytes >= 0, 'projection_manifest');
    safeRelative(file.path);
  }
  // Reuse the accepted path/prefix/NFC collision and aggregate limit contract.
  const encoded = plan.files.map(f => `100644 blob ${f.oid} ${f.bytes}\t${f.path}\0`).join('');
  const entries = [...treeEntries(Buffer.from(encoded), config)];
  requireValue(entries.length === plan.files.length, 'projection_manifest');
  return plan.files;
}

async function sourceFiles(root, manifest, step) {
  await directory(root, step);
  const expected = new Map(manifest.map(f => [f.path, f])), found = new Map();
  async function visit(folder, prefix = '') {
    for (const entry of await step(() => fs.readdir(folder, { withFileTypes: true }))) {
      const name = prefix + entry.name, full = path.join(folder, entry.name);
      safeRelative(name);
      requireValue(!entry.isSymbolicLink() && !name.split('/').some(p => p.toLowerCase() === '.git'), 'projection_source_link');
      const stat = await step(() => fs.lstat(full));
      requireValue(!stat.isSymbolicLink() && await step(() => fs.realpath(full)) === full, 'projection_source_alias');
      if (stat.isDirectory()) await visit(full, name + '/');
      else {
        const file = expected.get(name);
        requireValue(stat.isFile() && stat.nlink === 1 && file && stat.size === file.bytes, 'projection_source_inventory');
        const bytes = await step(() => fs.readFile(full));
        requireValue(bytes.length === file.bytes && hash(bytes) === file.sha256, 'projection_source_changed');
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        requireValue(Buffer.from(text, 'utf8').equals(bytes), 'projection_source_encoding');
        found.set(name, bytes);
      }
    }
  }
  await visit(root); requireValue(found.size === expected.size, 'projection_source_missing');
  return found;
}

/** Host-only one-shot analysis projection. A retained directory or mapping file
 * never authorizes an SDK run; only this invocation's completed return does.
 */
export async function projectRepository(options) {
  let plan, config;
  try { plan = structuredClone(options.plan); config = structuredClone(options.config); }
  catch { return { status: 'failed', reason: 'projection_input' }; }
  let pendingChildren = 0, active = true, outcome, cleanup;
  const created = [], operations = new Set();
  const track = operation => { operations.add(operation); operation.then(() => operations.delete(operation), () => operations.delete(operation)); return operation; };
  const controller = new AbortController(), originalSignal = options.signal;
  const abort = () => { active = false; controller.abort(); };
  const timeout = config?.timeoutMs;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 2147483647) return { status: 'failed', reason: 'projection_limits' };
  const expiresAt = performance.now() + timeout, timer = setTimeout(abort, timeout);
  originalSignal?.addEventListener('abort', abort, { once: true }); if (originalSignal?.aborted) abort();
  const check = () => { if (performance.now() >= expiresAt) abort(); requireValue(active && !controller.signal.aborted, 'projection_stopped'); };
  async function step(callback, child = false) {
    check(); let listener;
    const stopped = new Promise((_, reject) => { listener = () => reject(new SafeError('projection_stopped')); controller.signal.addEventListener('abort', listener, { once: true }); });
    try {
      const operation = Promise.resolve().then(() => { check(); return callback(); });
      const value = await Promise.race([child ? operation : track(operation), stopped]); check(); return value;
    }
    finally { controller.signal.removeEventListener('abort', listener); }
  }
  async function privateWorkspace(directory) {
    const stat = await step(() => fs.lstat(directory));
    if (process.platform !== 'win32') {
      requireValue(stat.uid === process.getuid() && (stat.mode & 0o077) === 0, 'projection_workspace_permissions');
      return;
    }
    check(); pendingChildren++;
    const operation = new Promise(resolve => {
      const child = spawn(path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', inspectPrivateAcl], {
        env: { SystemRoot: process.env.SystemRoot, SCANMUX_PROJECTION_WORKSPACE: directory }, windowsHide: true, stdio: 'ignore',
      });
      const abortChild = () => { child.kill(); };
      let failed = false;
      child.on('error', () => { failed = true; });
      controller.signal.addEventListener('abort', abortChild, { once: true });
      if (controller.signal.aborted) abortChild();
      child.on('close', code => { controller.signal.removeEventListener('abort', abortChild); resolve(!failed && code === 0); });
    });
    operation.then(() => pendingChildren--, () => pendingChildren--);
    requireValue(await step(() => operation, true), 'projection_workspace_permissions');
  }
  try {
    const manifest = acceptedManifest(plan, config), { snapshot, workspace } = options;
    await directory(plan.root, step); await directory(snapshot, step); await directory(workspace, step);
    cleanup = sourceCleanupFor(workspace);
    requireValue(!within(plan.root, workspace) && !within(snapshot, workspace), 'projection_workspace');
    await privateWorkspace(workspace);
    requireValue(object(config.tools?.git), 'projection_git');
    const bytes = await sourceFiles(snapshot, manifest, step);
    const repository = path.join(workspace, 'sdk-repository'), control = path.join(workspace, 'sdk-projection-control');
    for (const directory of [repository, control]) {
      const existing = await step(() => fs.lstat(directory).catch(error => { if (error.code === 'ENOENT') return null; throw error; }));
      requireValue(!existing, 'projection_output_exists');
      cleanup.register(workspace, directory); created.push(directory);
      await step(async () => { await fs.mkdir(directory, { mode: 0o700 }); await cleanup.capture(workspace, directory); });
    }
    const template = path.join(control, 'template'), hooks = path.join(control, 'hooks'), empty = path.join(control, 'empty');
    await step(() => fs.mkdir(template, { mode: 0o700 })); await step(() => fs.mkdir(hooks, { mode: 0o700 }));
    await step(() => fs.writeFile(empty, '', { flag: 'wx', mode: 0o600 }));
    async function toolCall(tool, args, input) {
      check(); pendingChildren++;
      const operation = execute(tool, args, {
        cwd: control, home: workspace, timeoutMs: Math.max(1, Math.ceil(expiresAt - performance.now())), maxOutputBytes: Math.max(config.maxOutputBytes, config.maxFileBytes), input, signal: controller.signal, target: plan.root,
      });
      operation.then(() => pendingChildren--, () => pendingChildren--);
      const result = await step(() => operation, true);
      requireValue(result.reason !== 'termination_unverified', 'projection_termination_unverified');
      requireValue(result.reason === 'exit' && result.code === 0, 'projection_tool_failed');
      return result.stdout;
    }
    const git = (args, input) => toolCall(config.tools.git, ['--no-optional-locks', '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false', '-c', `core.hooksPath=${hooks}`, '-c', `core.attributesFile=${empty}`, '-c', `core.excludesFile=${empty}`, '-C', repository, ...args], input);
    await git(['init', '--object-format=sha1', '--initial-branch=scanmux', `--template=${template}`]);
    await directory(path.join(repository, '.git'), step);
    await step(() => fs.mkdir(path.join(repository, '.git/info'), { mode: 0o700 }).catch(e => { if (e.code !== 'EEXIST') throw e; }));
    await directory(path.join(repository, '.git/info'), step);
    const quote = p => JSON.stringify(p.split(path.sep).join('/'));
    const gitConfig = `[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = false\nlogallrefupdates = false\nautocrlf = false\nsafecrlf = false\nfsmonitor = false\nhooksPath = ${quote(hooks)}\nattributesFile = ${quote(empty)}\nexcludesFile = ${quote(empty)}\n[protocol]\nallow = never\n[user]\nname = ScanMux snapshot\nemail = snapshot@example.invalid\n`;
    await step(() => fs.writeFile(path.join(repository, '.git/config'), gitConfig, { mode: 0o600 }));
    await step(() => fs.writeFile(path.join(repository, '.git/info/attributes'), '* ' + attributes.map(a => '-' + a).join(' ') + '\n', { flag: 'wx', mode: 0o600 }));
    const index = [];
    for (const file of manifest) {
      const destination = path.join(repository, file.path);
      const parts = file.path.split('/'); let parent = repository;
      for (const part of parts.slice(0, -1)) {
        parent = path.join(parent, part); await step(() => fs.mkdir(parent, { mode: 0o700 }).catch(e => { if (e.code !== 'EEXIST') throw e; })); await directory(parent, step);
      }
      await directory(path.dirname(destination), step);
      const content = bytes.get(file.path), text = content.toString('utf8');
      requireValue(Buffer.from(text).equals(content), 'projection_source_encoding');
      await step(() => fs.writeFile(destination, content, { flag: 'wx', mode: 0o600 }));
      const stat = await step(() => fs.lstat(destination));
      requireValue(stat.isFile() && stat.nlink === 1 && !stat.isSymbolicLink() && await step(() => fs.realpath(destination)) === destination, 'projection_destination_alias');
      const oid = (await git(['hash-object', '--no-filters', '-w', '--stdin'], text)).toString('utf8').trim();
      requireValue(oid === file.oid, 'projection_blob_identity'); index.push(`100644 ${oid}\t${file.path}\0`);
    }
    await git(['update-index', '-z', '--index-info'], index.join(''));
    const tree = (await git(['write-tree'])).toString('utf8').trim(); requireValue(sha1(tree), 'projection_tree');
    const derivedRevision = (await git(['commit-tree', tree], 'ScanMux analysis snapshot\n')).toString('utf8').trim(); requireValue(sha1(derivedRevision), 'projection_commit');
    await git(['update-ref', 'refs/heads/scanmux', derivedRevision]);
    requireValue((await git(['rev-parse', 'HEAD'])).toString().trim() === derivedRevision, 'projection_head');
    const commit = (await git(['cat-file', 'commit', derivedRevision])).toString('utf8'); requireValue(!/^parent /m.test(commit) && commit.startsWith(`tree ${tree}\n`), 'projection_history');
    await git(['update-index', '--refresh']);
    const listed = [...treeEntries(await git(['ls-tree', '-r', '-z', '-l', derivedRevision]), config)];
    requireValue(listed.length === manifest.length && listed.every(e => e.mode === '100644' && manifest.some(f => f.path === e.path && f.oid === e.oid && f.bytes === e.bytes)), 'projection_tree_inventory');
    const attr = (await git(['check-attr', '-z', ...attributes, '--stdin'], manifest.map(f => f.path + '\0').join(''))).toString('utf8').split('\0'); attr.pop();
    requireValue(attr.length === manifest.length * attributes.length * 3, 'projection_attributes');
    for (let i = 0; i < attr.length; i += 3) requireValue(bytes.has(attr[i]) && attributes.includes(attr[i + 1]) && attr[i + 2] === 'unset', 'projection_attributes');
    for (const file of manifest) requireValue((await git(['cat-file', 'blob', file.oid])).equals(bytes.get(file.path)), 'projection_blob_changed');
    requireValue((await git(['status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=all'])).length === 0, 'projection_dirty');
    requireValue((await git(['remote'])).length === 0, 'projection_remote');
    await sourceFiles(snapshot, manifest, step);
    for (const file of manifest) requireValue((await step(() => fs.readFile(path.join(repository, file.path)))).equals(bytes.get(file.path)), 'projection_destination_changed');
    const mapping = { schema: 'scanmux.sdk-projection/v1', usableOnlyFromCompletedInvocation: true, originalCommit: plan.commit, originalTree: plan.treeHash, derivedRevision, derivedTree: tree, planHash: plan.planHash, snapshotHash: plan.snapshotHash, projectionScope: 'accepted_files_only', originalExclusions: plan.exclusions, projectedMode: '100644', manifest: manifest.map(({ path: name, bytes: size, sha256 }) => ({ path: name, bytes: size, sha256 })) };
    await privateWorkspace(workspace);
    const encoded = JSON.stringify(mapping, null, 2) + '\n', mappingFile = path.join(workspace, 'sdk-projection.json');
    requireValue(Buffer.byteLength(encoded) <= config.maxOutputBytes, 'projection_output_limit');
    const gitleaks = config.tools.gitleaks;
    requireValue(object(gitleaks) && gitleaks.version === '8.30.1', 'projection_secret_check_unavailable');
    const version = (await toolCall(gitleaks, ['version'])).toString('utf8').match(/\b\d+\.\d+\.\d+\b/g) ?? [];
    requireValue(version.includes('8.30.1'), 'projection_secret_check_version');
    const rules = path.join(control, 'gitleaks.toml');
    await step(() => fs.writeFile(rules, gitleaksConfig, { flag: 'wx', mode: 0o600 }));
    const checked = await toolCall(gitleaks, ['stdin', '--config', rules, '--redact=100', '--no-banner', '--no-color', '--log-level', 'error', '--ignore-gitleaks-allow', '--report-format', 'json', '--report-path', '-'], encoded);
    const leaks = JSON.parse(checked.toString('utf8'));
    requireValue(Array.isArray(leaks) && leaks.length === 0, 'projection_secret_check_failed');
    await step(() => fs.writeFile(mappingFile, encoded, { flag: 'wx', mode: 0o600 }));
    requireValue(await step(() => fs.readFile(mappingFile, 'utf8')) === encoded, 'projection_mapping_changed');
    check(); active = false; return outcome = { status: 'completed', repository, mappingFile, mapping, scope: { paths: ['.'] } };
  } catch (error) {
    active = false; controller.abort();
    return outcome = { status: pendingChildren > 0 || error?.code === 'projection_termination_unverified' ? 'termination_unverified' : originalSignal?.aborted ? 'canceled' : 'failed', reason: error instanceof SafeError ? error.code : 'projection_failed' };
  } finally {
    clearTimeout(timer); originalSignal?.removeEventListener('abort', abort);
    // Settle filesystem steps before removal; an aborted child may never close.
    await Promise.allSettled([...operations]);
    if (outcome?.status !== 'completed' && created.length && (await cleanup.cleanup(options.workspace, created)).status === 'failed') outcome.errors = [...new Set([...(outcome.errors ?? []), 'source_cleanup_failed'])];
  }
}
