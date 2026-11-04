import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, chmod, readdir, open, lstat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { generateFixture } from './ci-linux-job-fixture.mjs';
import { nativeSuitePassed } from './ci-linux-job-native.mjs';

const run = path.resolve(process.argv[2]);
const source = path.join(run, 'src'), out = path.join(run, 'out');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const fields = ['startupVerified', 'supervisorClosed', 'containerAbsent', 'daemonHealthy', 'terminal', 'ownedTasksClosure'];
const criteria = [
  'SETUP approved pins and real Linux environment', 'SOURCE unchanged product files',
  'NATIVE suite passes without skipped tests',
  'LIMIT measured reason', 'LIMIT gate INCOMPLETE', 'LIMIT exit 3',
  ...fields.map(f => `LIMIT closure.${f}`),
  'LIMIT independent label listing empty', 'LIMIT independent daemon answers',
  'LIMIT container started before limit', 'LIMIT copy budget did not win',
  'CONTROL valid completed job', 'CONTROL no measured reason', 'CONTROL gitleaks completed',
  ...fields.map(f => `STOP closure.${f}`),
  'STOP independent label listing empty', 'STOP independent daemon answers',
  'STOP scanner seen before interrupt', 'STOP supported interrupt recorded', 'STOP scanner gone',
  'STOP no job_closure_unverified',
  'HARNESS all CLI children exited normally', 'HARNESS no owned containers remain',
];
const verdicts = new Map(criteria.map(name => [name, { pass: false, detail: 'not reached' }]));
const set = (name, pass, detail = '') => verdicts.set(name, { pass: pass === true, detail });
const assert = (yes, message) => { if (!yes) throw Error(message); };
const environment = {
  PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
  HOME: path.join(run, 'home'), GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(run, 'home', 'empty-gitconfig'),
  GIT_TERMINAL_PROMPT: '0', NPM_CONFIG_CACHE: path.join(run, 'npm-cache'),
  NPM_CONFIG_USERCONFIG: path.join(run, 'home', 'empty-npmrc'),
};
let commandNumber = 0, dockerTool, image, validateJobReport, installedApp;
const owned = new Map(), cliChildren = new Set();
let forced = false;
async function jsonFile(file, value) {
  await writeFile(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
async function command(file, args, options = {}) {
  const prefix = path.join(out, `command-${String(++commandNumber).padStart(5, '0')}`);
  const result = await new Promise(resolve => {
    const child = spawn(file, args, { cwd: options.cwd ?? run, env: { ...environment, ...options.env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = [], stderr = [], count = 0, launchError = null, overflow = false;
    child.on('error', e => { launchError = e.message; });
    const take = (list, bytes) => {
      count += bytes.length;
      if (count > (options.maxBytes ?? 256 * 1024 * 1024)) { overflow = true; child.kill('SIGKILL'); }
      else list.push(bytes);
    };
    child.stdout.on('data', b => take(stdout, b)); child.stderr.on('data', b => take(stderr, b));
    // This bounds observer commands, not the product's resource-stop policy.
    const timer = setTimeout(() => child.kill('SIGKILL'), options.timeoutMs ?? 60000);
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, launchError, overflow, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr) }); });
  });
  if (options.recordStdout !== false) await writeFile(prefix + '.stdout', result.stdout);
  await writeFile(prefix + '.stderr', result.stderr);
  await jsonFile(prefix + '.json', { file, args, code: result.code, signal: result.signal, launchError: result.launchError, overflow: result.overflow });
  return result;
}
function good(r) { assert(r.code === 0 && r.signal === null && !r.launchError && !r.overflow, `command failed: exit=${r.code} signal=${r.signal}`); return r.stdout; }
const text = r => good(r).toString('utf8').trim();
const docker = args => command(dockerTool, ['--host', 'unix:///var/run/docker.sock', '--config', path.join(run, 'docker-config'), ...args],
  { recordStdout: !['inspect', 'image'].includes(args[0]) });

async function inventory(directory, relative = '') {
  const result = [];
  for (const entry of await readdir(path.join(directory, relative), { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const name = path.posix.join(relative, entry.name);
    if (entry.isDirectory()) result.push(...await inventory(directory, name));
    else if (entry.isFile()) result.push({ path: name, sha256: hash(await readFile(path.join(directory, name))) });
    else throw Error('unexpected source link: ' + name);
  }
  return result.sort((a, b) => a.path.localeCompare(b.path));
}
async function acquire(name, pin) {
  assert(/^\d+\.\d+\.\d+$/.test(pin?.version), 'invalid version pin');
  for (const key of ['archiveSha256', 'exeSha256']) assert(/^[a-f0-9]{64}$/.test(pin[key]), 'missing approved ' + name + ' ' + key);
  const expectedUrl = name === 'docker'
    ? `https://download.docker.com/linux/static/stable/x86_64/docker-${pin.version}.tgz`
    : 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz';
  assert(pin.url === expectedUrl && (name !== 'gitleaks' || pin.version === '8.30.1'), 'unexpected tool URL/version');
  const response = await fetch(pin.url, { credentials: 'omit', redirect: 'follow', signal: AbortSignal.timeout(300000) });
  assert(response.ok && response.body, 'tool download failed');
  const chunks = []; let bytes = 0;
  for await (const chunk of response.body) {
    bytes += chunk.length; assert(bytes <= 256 * 1024 * 1024, 'tool archive too large'); chunks.push(chunk);
  }
  const archive = Buffer.concat(chunks);
  assert(hash(archive) === pin.archiveSha256, name + ' archive hash mismatch');
  const tar = path.join(run, 'tools', name + '.tar.gz');
  await writeFile(tar, archive, { flag: 'wx' });
  const member = name === 'docker' ? 'docker/docker' : 'gitleaks';
  // Extract exactly one member to stdout; never let archive paths create host files.
  const executable = good(await command('/bin/tar', ['-xOzf', tar, '--', member]));
  assert(hash(executable) === pin.exeSha256, name + ' executable hash mismatch');
  const destination = path.join(run, 'tools', name);
  await writeFile(destination, executable, { flag: 'wx', mode: 0o755 });
  await chmod(destination, 0o755);
  return { path: destination, version: pin.version, sha256: pin.exeSha256 };
}

async function ownerIn(tmp, fixture) {
  const parent = path.join(tmp, 'scanmux-private');
  for (const dir of await readdir(parent).catch(() => [])) {
    if (!/^scanmux-[A-Za-z0-9]+$/.test(dir)) continue;
    const directory = path.join(parent, dir);
    let owner;
    try { owner = JSON.parse(await readFile(path.join(directory, 'owner.json'), 'utf8')); } catch { continue; }
    assert(owner.schema === 'scanmux.job-owner/v1' && uuid.test(owner.jobId)
      && /^[a-f0-9]{64}$/.test(owner.containerId) && owner.name === 'scanmux-job-' + owner.jobId
      && owner.label === 'scanmux.job' && owner.image === image, 'invalid owned identity');
    const item = { ...owner, directory, fixture };
    owned.set(owner.containerId, item);
    return item;
  }
  return null;
}
async function checkClosure(name, job) {
  for (const field of fields) {
    const value = job?.closure?.[field];
    const pass = field === 'terminal' ? value != null
      : field === 'ownedTasksClosure' ? ['supervisor_final_wait', 'namespace_terminal_and_absent'].includes(value) : value === true;
    set(`${name} closure.${field}`, pass, JSON.stringify(value) ?? 'missing result closure');
  }
}
async function independentChecks(name, owner, job) {
  const jobId = owner?.jobId;
  let absent = false, healthy = false;
  if (jobId && (!job || job.jobId === jobId)) {
    const listing = await docker(['ps', '-a', '--no-trunc', '--filter', 'label=scanmux.job=' + jobId, '--format', '{{.ID}}']);
    absent = listing.code === 0 && listing.signal === null && listing.stdout.toString('utf8').trim() === '';
    await writeFile(path.join(out, name, 'post-label-listing.txt'), listing.stdout);
    // This is deliberately before any harness cleanup.
    await jsonFile(path.join(out, name, 'post-label-listing.json'), { jobId, code: listing.code, signal: listing.signal, absent });
    if (name === 'STOP') {
      const top = await docker(['top', owner.containerId, '-eo', 'pid,args']);
      await jsonFile(path.join(out, name, 'post-top.json'), { code: top.code, signal: top.signal, stdout: top.stdout.toString('utf8'), stderr: top.stderr.toString('utf8') });
      set('STOP scanner gone', absent && top.code !== 0 && top.signal === null && job?.closure?.terminal != null
        && job?.closure?.ownedTasksClosure !== 'unverified' && job?.closure?.startupVerified === true,
      'namespace terminal/absent plus independent label absence and failed top; no host PID reuse assumption');
    }
  }
  const health = await docker(['version', '--format', '{{json .Server}}']);
  try { healthy = health.code === 0 && health.signal === null && JSON.parse(health.stdout).Os === 'linux'; } catch {}
  await jsonFile(path.join(out, name, 'post-daemon.json'), { code: health.code, signal: health.signal, healthy, stdout: health.stdout.toString('utf8') });
  set(`${name} independent label listing empty`, absent, jobId ?? 'no owned job identity');
  set(`${name} independent daemon answers`, healthy);
}

async function scenario(name, profile, fixture) {
  const directory = path.join(out, name), tmp = path.join(run, 'tmp', name);
  await mkdir(directory); await mkdir(tmp, { recursive: true });
  const profilePath = path.join(directory, 'profile.json'); await jsonFile(profilePath, profile);
  const stdout = await open(path.join(directory, 'stdout.json'), 'wx', 0o600);
  const stderr = await open(path.join(directory, 'stderr.txt'), 'wx', 0o600);
  const child = spawn(process.execPath, [path.join(installedApp, 'bin/scanmux.mjs'), 'job-scan', fixture, '--job-profile', profilePath, '--json'], {
    cwd: source, env: { ...environment, TMPDIR: tmp }, stdio: ['ignore', stdout.fd, stderr.fd],
  });
  cliChildren.add(child);
  let done = false, launchError = null, exit, owner = null, interrupt = null, observedScanner = null;
  child.on('error', error => { launchError = error.message; });
  const closed = new Promise(resolve => child.on('close', (code, signal) => { done = true; cliChildren.delete(child); exit = { code, signal, launchError }; resolve(); }));
  const watchdog = setTimeout(() => {
    forced = true; child.kill('SIGTERM');
  }, profile.limits.wallMs + 2 * profile.limits.cleanupTimeoutMs);
  const hardWatchdog = setTimeout(() => {
    forced = true; child.kill('SIGKILL');
  }, profile.limits.wallMs + 3 * profile.limits.cleanupTimeoutMs);
  const observations = [];
  let pollingError;
  try {
    while (!done) {
      owner ??= await ownerIn(tmp, fixture);
      if (owner) {
        if (name === 'STOP' && !interrupt) {
          const r = await docker(['top', owner.containerId, '-eo', 'pid,args']);
          const output = r.stdout.toString('utf8');
          // Match the real directory scan, not a version or output-secret-check process.
          const scannerLine = output.split('\n').find(line => /(?:^|\s)\/tools\/gitleaks\s+dir\s+\/work\/snapshot(?:\s|$)/.test(line));
          observations.push({ at: new Date().toISOString(), code: r.code, signal: r.signal, top: output });
          if (r.code === 0 && r.signal === null && scannerLine && !done) {
            observedScanner = { containerId: owner.containerId, jobId: owner.jobId, scannerLine, top: output, observedAt: new Date().toISOString() };
            await jsonFile(path.join(directory, 'scanner-seen.json'), observedScanner);
            // Product SIGTERM -> abort -> job-runner cancellation/owned-container closure.
            const sent = child.kill('SIGTERM');
            interrupt = { signal: 'SIGTERM', sent, sentAt: new Date().toISOString(), pid: child.pid };
            await jsonFile(path.join(directory, 'interrupt.json'), interrupt);
          }
        }
      }
      await delay(50);
    }
    await closed;
  } catch (error) {
    pollingError = error;
    // Preserve the product's supported stop path even if observation fails.
    child.kill('SIGTERM');
    await closed;
  } finally {
    clearTimeout(watchdog); clearTimeout(hardWatchdog);
    await stdout.close(); await stderr.close();
  }
  owner ??= await ownerIn(tmp, fixture);
  await jsonFile(path.join(directory, 'exit.json'), exit);
  await jsonFile(path.join(directory, 'observations.json'), observations);
  if (pollingError) {
    forced = true;
    await writeFile(path.join(directory, 'polling-error.txt'), String(pollingError.stack ?? pollingError) + '\n');
  }
  let job = null;
  try {
    job = validateJobReport(JSON.parse(await readFile(path.join(directory, 'stdout.json'), 'utf8')));
    assert(owner && job.jobId === owner.jobId, 'result/owner mismatch');
  } catch (error) { await writeFile(path.join(directory, 'result-error.txt'), String(error) + '\n'); job = null; }
  const reasons = job?.reasons ?? [];
  if (name === 'LIMIT') {
    set('LIMIT measured reason', reasons.includes('job_disk_measured_limit'), JSON.stringify(reasons));
    set('LIMIT gate INCOMPLETE', job?.gate === 'INCOMPLETE', job?.gate ?? 'no valid job report');
    set('LIMIT exit 3', exit.code === 3 && exit.signal === null && job?.exitCode === 3, JSON.stringify(exit));
    // The verified ready packet precedes controller start.
    set('LIMIT container started before limit', job?.closure.startupVerified === true && job.resources.startup !== null
      && reasons.includes('job_disk_measured_limit'), 'verified supervisor ready before controller start');
    const allOutput = await readFile(path.join(directory, 'stdout.json'), 'utf8') + await readFile(path.join(directory, 'stderr.txt'), 'utf8');
    const copyWon = allOutput.includes('job_disk_copy_limit');
    set('LIMIT copy budget did not win', job !== null && !copyWon, copyWon ? 'FINDING: copy budget won despite omitted maxCopyBytes' : 'maxCopyBytes omitted');
  } else if (name === 'CONTROL') {
    set('CONTROL valid completed job', job !== null && job.closure.startupVerified && job.closure.controllerCompleted
      && job.closure.containerAbsent && job.closure.inputsUnchanged && job.closure.terminal?.exitCode === 0
      && job.knownFailures.length === 0 && job.resources.stop === null && job.analysis?.kind === 'report'
      && exit.code === job.exitCode && exit.signal === null && job.gate !== 'ERROR', 'prevents vacuous success on admission failure');
    set('CONTROL no measured reason', job !== null && !reasons.includes('job_disk_measured_limit'), JSON.stringify(reasons));
    set('CONTROL gitleaks completed', job !== null && !reasons.includes('required_gitleaks_incomplete'), JSON.stringify(reasons));
  } else {
    set('STOP scanner seen before interrupt', observedScanner !== null && interrupt?.sent === true);
    set('STOP no job_closure_unverified', job !== null && !reasons.includes('job_closure_unverified'), JSON.stringify(reasons));
    set('STOP supported interrupt recorded', interrupt?.sent === true && job?.resources.stop?.kind === 'cancelled'
      && exit.signal === null && exit.code === job?.exitCode, 'SIGTERM; job.resources.stop.kind must be cancelled');
  }
  if (name !== 'CONTROL') { await checkClosure(name, job); await independentChecks(name, owner, job); }
}

async function cleanupOwned() {
  // Run AFTER recording all independent post-run checks. Cleanup never repairs a FAIL.
  let clean = true;
  for (const owner of owned.values()) {
    const listing = await docker(['ps', '-a', '--no-trunc', '--filter', 'label=scanmux.job=' + owner.jobId, '--format', '{{.ID}}']);
    if (listing.code !== 0 || listing.signal !== null) { clean = false; continue; }
    const ids = listing.stdout.toString('utf8').trim().split('\n').filter(Boolean);
    for (const id of ids) {
      if (id !== owner.containerId) { clean = false; continue; }
      const inspected = await docker(['inspect', id]); let value;
      try { [value] = JSON.parse(good(inspected)); } catch { clean = false; continue; }
      if (value.Id !== id || value.Name !== '/' + owner.name || value.Image !== owner.image
        || value.Config?.Labels?.['scanmux.job'] !== owner.jobId
        || !value.Mounts?.some(m => m.Type === 'bind' && m.Source === owner.fixture)) { clean = false; continue; }
      const removed = await docker(['rm', '--force', id]);
      if (removed.code !== 0 || removed.signal !== null) clean = false;
    }
    const after = await docker(['ps', '-a', '--no-trunc', '--filter', 'label=scanmux.job=' + owner.jobId, '--format', '{{.ID}}']);
    if (after.code !== 0 || after.signal !== null || after.stdout.toString('utf8').trim()) clean = false;
  }
  set('HARNESS no owned containers remain', clean, `${owned.size} exact owned identities checked; no images or volumes created`);
}

let before;
try {
  assert(/^run-[a-f0-9]{32}$/.test(path.basename(run)), 'fresh dedicated daemon-host run directory required');
  await mkdir(out, { recursive: true });
  assert(process.platform === 'linux' && process.arch === 'x64' && process.versions.node === '24.22.1' && process.getuid() === 1000, 'Linux/x64 Node 24.22.1 UID 1000 required');
  const mib = 128;
  assert(Number.isSafeInteger(mib) && mib >= 64 && mib <= 512, 'fixture MiB must be 64..512');
  image = process.argv[3]; assert(/^sha256:[a-f0-9]{64}$/.test(image), 'exact preloaded image ID required');
  for (const folder of ['tools', 'home', 'docker-config']) await mkdir(path.join(run, folder));
  for (const file of ['empty-gitconfig', 'empty-npmrc']) await writeFile(path.join(run, 'home', file), '', { flag: 'wx' });
  const pinsBytes = await readFile(path.join(source, '.github/scanmux/linux-job-pins.json')), pins = JSON.parse(pinsBytes);
  assert(pins.schema === 'scanmux.ci-linux-job-pins/v1', 'Linux pins schema required');
  const dockerPin = await acquire('docker', pins.docker), gitleaks = await acquire('gitleaks', pins.gitleaks);
  dockerTool = dockerPin.path;
  const version = JSON.parse(good(await docker(['version', '--format', '{{json .}}'])));
  assert(version.Client.Version === dockerPin.version && version.Server.Os === 'linux' && version.Server.Arch === 'amd64', 'daemon/client mismatch');
  const imageInfo = JSON.parse(good(await docker(['image', 'inspect', '--format',
    '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Volumes":{{json .Config.Volumes}}}', image])));
  assert(imageInfo.Id === image && imageInfo.Os === 'linux' && imageInfo.Architecture === 'amd64'
    && !Object.keys(imageInfo.Volumes ?? {}).length, 'image must be Linux amd64 without volumes');
  assert(text(await command(gitleaks.path, ['version'])) === '8.30.1', 'Gitleaks version mismatch');
  const runtimeTool = async (file, args) => ({ path: file, sha256: hash(await readFile(file)), version: /\b(\d+\.\d+\.\d+)/.exec(text(await command(file, args)))?.[1] });
  const python = await runtimeTool('/usr/bin/python3', ['--version']), git = await runtimeTool('/usr/bin/git', ['--version']);
  assert(python.version && git.version && (await lstat('/var/run/docker.sock')).isSocket(), 'runtime identities/socket unavailable');
  before = await inventory(source);
  await jsonFile(path.join(out, 'source-before.json'), before);
  good(await command('/usr/local/bin/npm', ['ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: source, timeoutMs: 300000 }));
  const { installPackage } = await import(pathToFileURL(path.join(source, 'scripts/ci-installed-package.mjs')));
  const packageDirectory = path.join(run, 'installed-package'); await mkdir(packageDirectory);
  ({ app: installedApp } = await installPackage(packageDirectory));
  await import(pathToFileURL(path.join(installedApp, 'bin/typescript-bootstrap.mjs')));
  ({ validateJobReport } = await import(pathToFileURL(path.join(installedApp, 'src/job-records.ts'))));
  await jsonFile(path.join(out, 'preparation.json'), { pinsSha256: hash(pinsBytes), docker: dockerPin, gitleaks, image, runtime: { nodeVersion: process.versions.node, python, git }, daemon: version.Server, fixtureMiB: mib });
  set('SETUP approved pins and real Linux environment', true);
  const fixture = path.join(run, 'fixture'); await generateFixture(fixture, mib);
  for (const args of [['init', '--quiet', '--template=', fixture], ['-C', fixture, 'add', '--all'],
    ['-C', fixture, '-c', 'user.name=ScanMux Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Public non-secret text fixture']]) good(await command('/usr/bin/git', args));
  assert(text(await command('/usr/bin/git', ['-C', fixture, 'status', '--porcelain'])) === '', 'fixture must be clean');
  const fixtureHead = text(await command('/usr/bin/git', ['-C', fixture, 'rev-parse', 'HEAD']));
  const MiB = 1048576;
  const profile = { schema: 'scanmux.job-profile/v1', name: 'ci-linux-job', scope: 'offline-local', docker: { tool: dockerPin, endpoint: 'unix:///var/run/docker.sock' },
    image, runtime: { nodeVersion: '24.22.1', python, git }, tools: { gitleaks }, osvDatabase: null,
    scan: { timeoutMs: 300000, maxOutputBytes: 8 * MiB, maxFileBytes: 2 * MiB, maxSnapshotBytes: (mib + 16) * MiB, maxFiles: mib + 16 },
    limits: { cpuCount: 2, memoryBytes: 3 * 1024 * MiB, tmpBytes: 256 * MiB, workBytes: 1024 * MiB, shmBytes: 64 * MiB,
      pids: 256, wallMs: 300000, cleanupTimeoutMs: 60000, retainedBytes: 128 * MiB } };
  await jsonFile(path.join(out, 'fixture.json'), { root: fixture, commit: fixtureHead, files: mib, bytes: mib * MiB, fileBytes: MiB,
    limitBytes: mib / 4 * MiB, controlBytes: 4 * 1024 * MiB, maxCopyBytes: 'omitted', note: 'Snapshot growth, not scanner writes; STOP requires observed real gitleaks dir.' });
  const nativeProfile = path.join(run, 'native-profile.json'), nativeTmp = path.join(run, 'tmp', 'native');
  await jsonFile(nativeProfile, profile); await mkdir(nativeTmp, { recursive: true });
  const native = await command(process.execPath, ['--test', '--test-reporter=tap', 'test/linux-job-supervisor.test.mjs'], {
    cwd: source, timeoutMs: 600000, env: { SCANMUX_NATIVE_JOB_PROFILE: nativeProfile, TMPDIR: nativeTmp },
  });
  set('NATIVE suite passes without skipped tests', nativeSuitePassed(native), native.stdout.toString('utf8').split('\n').filter(line => /^# (tests|pass|fail|cancelled|skipped|todo) /.test(line)).join('; '));
  for (const name of ['LIMIT', 'CONTROL', 'STOP']) {
    try { await scenario(name, { ...profile, maxJobDiskBytes: (name === 'LIMIT' ? mib / 4 : 4 * 1024) * MiB }, fixture); }
    catch (error) { await writeFile(path.join(out, name + '-harness-error.txt'), String(error.stack ?? error) + '\n'); }
  }
} catch (error) {
  await writeFile(path.join(out, 'setup-error.txt'), String(error.stack ?? error) + '\n').catch(() => {});
} finally {
  for (const child of cliChildren) { forced = true; child.kill('SIGTERM'); }
  set('HARNESS all CLI children exited normally', cliChildren.size === 0 && !forced);
  if (dockerTool) {
    try { await cleanupOwned(); } catch (error) { set('HARNESS no owned containers remain', false, String(error)); }
  }
  if (before) {
    try {
      const after = await inventory(source); await jsonFile(path.join(out, 'source-after.json'), after);
      set('SOURCE unchanged product files', JSON.stringify(before) === JSON.stringify(after));
    } catch (error) { set('SOURCE unchanged product files', false, String(error)); }
  }
  const results = [...verdicts].map(([criterion, result]) => ({ criterion, ...result }));
  await jsonFile(path.join(out, 'criteria.json'), results).catch(() => {});
  for (const result of results) console.log(`${result.pass ? 'PASS' : 'FAIL'} ${result.criterion}${result.detail ? ' | ' + result.detail.replace(/[\r\n]+/g, ' ') : ''}`);
  process.exitCode = results.every(r => r.pass) ? 0 : 1;
}
