import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { parseWorkerResources, expectedResourceKernel } from './worker-resources.mjs';

const docker = 'C:/Program Files/Docker/Docker/resources/bin/docker.exe';
const endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine';
const imageId = 'sha256:f9b3548b20b15b705b66aeecaeac7dd690c73d5e4661357aac02e60e3d38c88a';
const imageReference = 'node@' + imageId;
const assetManifestSha256 = 'a8d9e7ec6006b43bd296a3beaf618a43818731ae75f5847f214324d0b2d2308c';
const gitTrust = '[safe]\ndirectory =\ndirectory = /handoff\n';
const temporaryStores = limits => ({ '/tmp': 'rw,noexec,nosuid,nodev,size=' + limits.tmpBytes + ',mode=1777', '/work': 'rw,noexec,nosuid,nodev,size=' + limits.workBytes + ',uid=1000,gid=1000,mode=0700' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => hash(JSON.stringify(value));
const requireValue = (value, code) => { if (!value) throw Error(code); };
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const positive = value => Number.isSafeInteger(value) && value > 0;

/** Reject extra mounts/capabilities and verify the exact instance before start. */
export function validateLinuxHostedBoundary(info, expected) {
  const limits = parseWorkerResources(expected.workerResources);
  requireValue(info && info.Id === expected.id && info.Image === imageId && info.Config?.Labels?.['scanmux.hosted-bridge'] === expected.runId && info.State?.Status === 'created' && info.State.Running === false, 'runner_identity');
  const host = info.HostConfig, config = info.Config;
  requireValue(host.NetworkMode === 'none' && host.ReadonlyRootfs === true && config.User === '1000:1000' && host.Privileged === false && config.Tty === false && config.OpenStdin === true, 'runner_isolation');
  requireValue(isDeepStrictEqual(host.CapDrop?.map(s => s.toUpperCase()), ['ALL']) && isDeepStrictEqual(host.CapAdd ?? [], []) && isDeepStrictEqual(host.SecurityOpt, ['no-new-privileges']) && ['', 'private'].includes(host.PidMode) && host.IpcMode === 'private' && host.CgroupnsMode === 'private', 'runner_privileges');
  requireValue(host.AutoRemove === false && host.PidsLimit === 64 && host.LogConfig?.Type === 'none' && isDeepStrictEqual(host.PortBindings ?? {}, {}) && isDeepStrictEqual(host.Devices ?? [], []) && isDeepStrictEqual(host.DeviceRequests ?? [], []) && isDeepStrictEqual(host.Binds ?? [], []) && isDeepStrictEqual(host.Tmpfs, temporaryStores(limits)), 'runner_host_access');
  requireValue(host.NanoCpus === limits.cpuCount * 1000000000 && host.Memory === limits.memoryBytes && host.MemorySwap === limits.memoryBytes && host.ShmSize === limits.shmBytes, 'runner_resource_boundary');
  requireValue(isDeepStrictEqual(config.Entrypoint, ['/usr/local/bin/node']) && isDeepStrictEqual(config.Cmd, ['/verify/linux-hosted-worker.mjs']) && config.WorkingDir === '/work' && isDeepStrictEqual([...config.Env].sort(), [...expected.env].sort()), 'runner_command');
  requireValue(isDeepStrictEqual(expected.mounts.map(m => m.target).sort(), ['/assets', '/etc/gitconfig', '/handoff', '/verify']), 'runner_mount_inventory');
  requireValue(isDeepStrictEqual(host.Mounts.map(m => [m.Type, m.Source, m.Target, m.ReadOnly]).sort(), expected.mounts.map(m => ['bind', m.source, m.target, true]).sort()) && isDeepStrictEqual(info.Mounts.map(m => [m.Type, m.Destination, m.RW]).sort(), expected.mounts.map(m => ['bind', m.target, false]).sort()), 'runner_mounts');
}
async function canonical(directory) {
  requireValue(typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) === directory, 'runner_directory');
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) { current = path.join(current, part); const stat = await fs.lstat(current); requireValue(stat.isDirectory() && !stat.isSymbolicLink() && await fs.realpath(current) === current, 'runner_directory_alias'); }
}

/** Owns one container and attach client. No target value chooses a command. */
export async function openLinuxHostedWorker(options) {
  const { directory, sourceRoot, signal, expiresAt, identity, runId, revision, scope, manifest, ipc, reasoningEffort } = options;
  const assets = structuredClone(options.assets), sourceReceipts = structuredClone(options.sourceReceipts), commandTimeoutMs = options.commandTimeoutMs;
  const workerResources = parseWorkerResources(options.workerResources);
  requireValue(process.platform === 'win32' && identifier(runId) && identity?.runId === runId && typeof directory === 'string' && path.isAbsolute(directory) && path.resolve(directory) === directory && /^[a-f0-9]{40}$/.test(revision) && Number.isFinite(expiresAt) && positive(commandTimeoutMs) && commandTimeoutMs <= 2 ** 31 - 1 && signal && positive(ipc.maxBytes), 'runner_options');
  const name = 'scanmux-hosted-' + runId, verify = path.join(directory, 'verify'), configDirectory = path.join(directory, 'docker-config');
  const env = Object.fromEntries(Object.entries({ SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, TEMP: directory, TMP: directory, DOCKER_CONFIG: configDirectory }).filter(([, value]) => value !== undefined));
  let id, createInvoked = false, createCompleted = false, attach, attachEnded = false, attachStarted = false, forced = false, closePromise, resolveClosed, failure, expectedStartup, boundary;
  let stderrBytes = 0, structuredStderr = Buffer.alloc(0), terminal = null, failureCode = null;
  const stderrDigest = createHash('sha256'), closed = new Promise(resolve => { resolveClosed = resolve; });
  const stop = () => { requireValue(!signal.aborted && performance.now() < expiresAt, 'runner_stopped'); };
  const stopClient = () => { forced = true; try { attach?.kill(); } catch {} };
  const diagnostics = () => ({ failure: failure ?? null, imageId, id: id ?? null, createInvoked, createCompleted, attachStarted, attachEnded, forced, stderrBytes, stderrSha256: stderrDigest.copy().digest('hex'), boundaryVerifiedBeforeStart: Boolean(boundary), boundary, terminal: terminal ? structuredClone(terminal) : null, failureCode });
  async function command(args, cleanup = false) {
    if (!cleanup) stop();
    const budget = cleanup ? commandTimeoutMs : Math.max(1, Math.min(commandTimeoutMs, Math.ceil(expiresAt - performance.now())));
    return new Promise((resolve, reject) => {
      const child = spawn(docker, ['--host', endpoint, '--config', configDirectory, ...args], { env, windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
      let total = 0, stdout = Buffer.alloc(0), settled = false;
      const rejectOnce = code => { if (!settled) { settled = true; try { child.kill(); } catch {} reject(Error(code)); } };
      const abort = () => rejectOnce('runner_command_stopped'), timer = setTimeout(() => rejectOnce('runner_command_timeout'), budget);
      if (!cleanup) signal.addEventListener('abort', abort, { once: true });
      child.on('error', () => rejectOnce('runner_command_start'));
      child.stdout.on('data', bytes => { total += bytes.length; if (total > ipc.maxBytes) rejectOnce('runner_command_limit'); else if (!settled) stdout = Buffer.concat([stdout, bytes]); });
      child.stderr.on('data', bytes => { total += bytes.length; if (total > ipc.maxBytes) rejectOnce('runner_command_limit'); });
      child.on('close', (code, endSignal) => { clearTimeout(timer); signal.removeEventListener('abort', abort); if (!settled) { settled = true; resolve({ code, signal: endSignal, stdout }); } });
    });
  }
  async function success(args, cleanup = false) { const result = await command(args, cleanup); requireValue(result.code === 0 && result.signal === null, 'runner_command_failed'); return new TextDecoder('utf-8', { fatal: true }).decode(result.stdout); }
  async function inspect(cleanup = true) {
    const result = await command(['inspect', id ?? name], cleanup);
    if (result.code === 0) { const rows = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout)); requireValue(Array.isArray(rows) && rows.length === 1, 'runner_inspect'); return rows[0]; }
    const health = await success(['version', '--format', '{{.Server.Version}}'], cleanup); requireValue(/^\d+\.\d+/.test(health.trim()), 'runner_daemon');
    const found = (await success(['ps', '-a', '--no-trunc', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'], cleanup)).trim(); requireValue(found === '', 'runner_absence_unknown'); return null;
  }
  const owned = info => requireValue(info && info.Config?.Labels?.['scanmux.hosted-bridge'] === runId && info.Image === imageId && (!id || info.Id === id), 'runner_cleanup_identity');
  async function close() {
    if (!closePromise) closePromise = (async () => {
      let containerAbsent = !createInvoked;
      try {
        if (createInvoked) {
          const info = await inspect();
          if (info) {
            owned(info); id ??= info.Id;
            if (info.State.Running) { forced = true; await success(['stop', '--time', '1', id], true); }
            const ending = await inspect(); owned(ending); requireValue(ending.State?.Running === false, 'runner_still_running');
            if (ending.State.Status === 'exited') {
              requireValue(Number.isSafeInteger(ending.State.ExitCode) && ending.State.ExitCode >= 0 && ending.State.ExitCode <= 255 && typeof ending.State.OOMKilled === 'boolean', 'runner_terminal_observation');
              terminal = { exitCode: ending.State.ExitCode, oomKilled: ending.State.OOMKilled };
            } else requireValue(ending.State.Status === 'created', 'runner_terminal_observation');
            await success(['rm', id], true);
          }
          containerAbsent = await inspect() === null && createCompleted;
        }
        if (attachStarted && !attachEnded) {
          let timer; try { await Promise.race([closed, new Promise((_, reject) => { timer = setTimeout(() => { stopClient(); reject(Error('runner_attach_unclosed')); }, commandTimeoutMs); })]); } finally { clearTimeout(timer); }
        }
        if (stderrBytes > 0 && stderrBytes <= 1024) {
          try {
            const record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(structuredStderr));
            if (record && Object.keys(record).sort().join(',') === 'code,stage' && ['input', 'resources', 'modules', 'assets', 'source', 'sdk', 'artifacts'].includes(record.stage) && ['resource_disk_exceeded', 'resource_memory_exceeded', 'resource_boundary_unverified', 'resource_observation_invalid'].includes(record.code)) failureCode = record.code;
          } catch {}
        }
        return { closed: !attachStarted || attachEnded, quiescent: (!attachStarted || attachEnded) && !forced && containerAbsent, containerAbsent };
      } catch { stopClient(); return { closed: !attachStarted || attachEnded, quiescent: false, containerAbsent: false }; }
      finally { signal.removeEventListener('abort', abortOwner); }
    })();
    return closePromise;
  }
  const abortOwner = () => { void close().catch(() => {}); };
  const owner = { input: null, output: null, closed, close, diagnostics, get expectedStartup() { return expectedStartup; }, get failure() { return failure; } };
  try {
    stop(); await canonical(path.dirname(directory)); await canonical(sourceRoot); await canonical(assets.root); stop();
    requireValue(!directory.startsWith(sourceRoot + path.sep) && directory !== sourceRoot && Array.isArray(assets.manifest) && assets.manifest.length === 10805 && assets.manifestSha256 === assetManifestSha256 && digest(assets.manifest) === assetManifestSha256 && Array.isArray(sourceReceipts), 'runner_binding');
    await fs.mkdir(directory); await fs.mkdir(verify); await fs.mkdir(configDirectory); await fs.writeFile(path.join(configDirectory, 'config.json'), '{}\n', { flag: 'wx' }); stop();
    const modules = [];
    for (const file of ['hosted-channel.mjs', 'hosted-mcp.mjs', 'linux-hosted-worker.mjs', 'worker-resources.mjs', 'sdk-initialization-observer.mjs', 'sdk-native-observer.py']) { const bytes = await fs.readFile(path.join(import.meta.dirname, file)); await fs.writeFile(path.join(verify, file), bytes, { flag: 'wx' }); modules.push({ path: file, bytes: bytes.length, sha256: hash(bytes) }); stop(); }
    const trustBytes = Buffer.from(gitTrust); await fs.writeFile(path.join(verify, 'git-trust.config'), trustBytes, { flag: 'wx' }); modules.push({ path: 'git-trust.config', bytes: trustBytes.length, sha256: hash(trustBytes) }); modules.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
    expectedStartup = { platform: 'linux', node: 'v24.22.1', uid: 1000, sdkVersion: '0.5.1', pluginVersion: '0.1.95', assetManifestSha256: assets.manifestSha256, modulesManifestSha256: digest(modules), revision, manifestSha256: digest(manifest), sourceReceiptsSha256: digest(sourceReceipts), readOnlyChecks: [{ path: '.scanmux-readonly-canary', code: 'EROFS' }, { path: '.git/.scanmux-readonly-canary', code: 'EROFS' }], resources: expectedResourceKernel(workerResources) };
    const value = { version: 1, identity, revision, scope, manifest, reasoningEffort, workerResources, budgetMs: Math.max(1, Math.floor(expiresAt - performance.now())), commandTimeoutMs, ipc, assets: assets.manifest, assetManifestSha256: assets.manifestSha256, modules, modulesManifestSha256: digest(modules), sourceReceiptsSha256: digest(sourceReceipts), expectedStartup };
    const bytes = Buffer.from(JSON.stringify(value)); requireValue(bytes.length <= 8 * 1024 * 1024, 'runner_input_limit'); stop(); await fs.writeFile(path.join(verify, 'input.json'), bytes, { flag: 'wx' }); stop();
    const image = JSON.parse(await success(['image', 'inspect', imageReference]))[0]; requireValue(image.Id === imageId && image.Os === 'linux' && image.Architecture === 'amd64' && image.RepoDigests?.includes(imageReference), 'runner_image');
    const imageEnvironment = image.Config.Env.filter(entry => !/^(HOME|TMPDIR)=/.test(entry)); requireValue(imageEnvironment.every(entry => /^(PATH|NODE_VERSION|YARN_VERSION)=/.test(entry)), 'runner_image_environment');
    const expectedEnvironment = [...imageEnvironment, 'HOME=/work/home', 'TMPDIR=/tmp'];
    const mounts = [{ source: assets.root, target: '/assets' }, { source: verify, target: '/verify' }, { source: sourceRoot, target: '/handoff' }, { source: path.join(verify, 'git-trust.config'), target: '/etc/gitconfig' }];
    for (const mount of mounts) requireValue(!/[\r\n,]/.test(mount.source), 'runner_mount_path');
    stop(); createInvoked = true;
    id = (await success(['create', '--pull=never', '--interactive', '--name', name, '--label', 'scanmux.hosted-bridge=' + runId, '--network', 'none', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--ipc', 'private', '--cgroupns', 'private', '--pids-limit', '64', '--log-driver', 'none', '--cpus', String(workerResources.cpuCount), '--memory', String(workerResources.memoryBytes), '--memory-swap', String(workerResources.memoryBytes), '--shm-size', String(workerResources.shmBytes), ...Object.entries(temporaryStores(workerResources)).flatMap(([target, settings]) => ['--tmpfs', target + ':' + settings]), ...mounts.flatMap(m => ['--mount', 'type=bind,source=' + m.source + ',target=' + m.target + ',readonly']), '--env', 'HOME=/work/home', '--env', 'TMPDIR=/tmp', '--workdir', '/work', '--entrypoint', '/usr/local/bin/node', imageReference, '/verify/linux-hosted-worker.mjs'])).trim();
    requireValue(/^[a-f0-9]{64}$/.test(id), 'runner_create_identity'); createCompleted = true; stop();
    const info = await inspect(false); validateLinuxHostedBoundary(info, { id, runId, env: expectedEnvironment, mounts, workerResources }); boundary = { info, expected: { id, runId, env: expectedEnvironment, mounts, workerResources } }; stop();
    attach = spawn(docker, ['--host', endpoint, '--config', configDirectory, 'start', '--attach', '--interactive', id], { env, windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'pipe'] }); attachStarted = true;
    attach.on('error', () => { failure ??= 'runner_attach_start'; }); attach.stdin.on('error', () => {});
    attach.stderr.on('data', bytes => { stderrBytes += bytes.length; stderrDigest.update(bytes); if (stderrBytes <= 1024) structuredStderr = Buffer.concat([structuredStderr, bytes]); else structuredStderr = Buffer.alloc(0); if (stderrBytes > ipc.maxBytes) { failure ??= 'runner_stderr_limit'; abortOwner(); } });
    attach.once('close', (code, endSignal) => { attachEnded = true; resolveClosed({ code, signal: endSignal }); });
    owner.input = attach.stdout; owner.output = attach.stdin; signal.addEventListener('abort', abortOwner, { once: true }); stop(); return owner;
  } catch (error) {
    failure = /^[a-z_]+$/.test(error.message) ? error.message : 'runner_failed'; if (!attachStarted) resolveClosed({ code: null, signal: null }); await close(); return owner;
  }
}
