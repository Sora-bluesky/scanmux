import '../bin/typescript-bootstrap.mjs';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const { acquireDatabase } = await import('./fetch-osv-db.mjs');
const { readZip } = await import('../src/zip-archive.ts');

const repository = path.resolve(import.meta.dirname, '..');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const windows = process.platform === 'win32';
const env = { ...process.env, NODE_OPTIONS: '', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };

export async function command(file, args, options = {}) {
  if (windows && file.endsWith('.cmd')) {
    assert.ok([file, ...args].every(value => !/["%\r\n]/.test(value)), 'unsupported cmd argument');
    args = ['/d', '/s', '/c', `"${[file, ...args].map(value => `"${value}"`).join(' ')}"`];
    file = process.env.ComSpec;
    options = { ...options, windowsVerbatimArguments: true };
  }
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: repository, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], ...options });
    const out = [], err = []; let bytes = 0, overflow = false;
    const take = (list, chunk) => { bytes += chunk.length; if (bytes > 256 * 1024 * 1024) { overflow = true; child.kill(); } else list.push(chunk); };
    child.stdout.on('data', chunk => take(out, chunk)); child.stderr.on('data', chunk => take(err, chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, overflow, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString('utf8') }));
  });
}
function successful(result) {
  assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); assert.equal(result.overflow, false);
  return result.stdout;
}
export async function installPackage(directory, archive) {
  const npm = path.join(path.dirname(process.execPath), windows ? 'node_modules/npm/bin/npm-cli.js' : '../lib/node_modules/npm/bin/npm-cli.js');
  const environment = { ...env, NPM_CONFIG_CACHE: path.join(directory, 'npm-cache') };
  if (!archive) {
    const packed = JSON.parse(successful(await command(process.execPath, [npm, 'pack', '--ignore-scripts', '--json', '--pack-destination', directory], { env: environment })));
    assert.equal(packed.length, 1); archive = path.join(directory, packed[0].filename);
  }
  const consumer = path.join(directory, 'consumer'); await mkdir(consumer);
  successful(await command(process.execPath, [npm, 'install', '--prefix', consumer, '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', path.resolve(archive)], { env: environment }));
  return { consumer, app: path.join(consumer, 'node_modules/scanmux'), bin: path.join(consumer, 'node_modules/.bin/scanmux' + (windows ? '.cmd' : '')) };
}
async function acquireTool(directory, name, pin) {
  const response = await fetch(pin.url, { credentials: 'omit', redirect: 'follow', signal: AbortSignal.timeout(300000) });
  assert.ok(response.ok && response.body, name + ' download failed');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; assert.ok(size <= 256 * 1024 * 1024); chunks.push(chunk); }
  const archive = Buffer.concat(chunks); assert.equal(hash(archive), pin.archiveSha256, name + ' archive hash');
  let executable = archive;
  if (name === 'gitleaks') {
    if (windows) executable = readZip(archive, { maxEntries: 100, maxBytes: 256 * 1024 * 1024 }).get('gitleaks.exe');
    else {
      const tar = path.join(directory, 'gitleaks.tar.gz'); await writeFile(tar, archive, { flag: 'wx' });
      executable = successful(await command('/bin/tar', ['-xOzf', tar, '--', 'gitleaks']));
    }
  }
  assert.equal(hash(executable), pin.exeSha256, name + ' executable hash');
  const destination = path.join(directory, name + (windows ? '.exe' : ''));
  await writeFile(destination, executable, { flag: 'wx', mode: 0o755 });
  const version = successful(await command(destination, [name === 'gitleaks' ? 'version' : '--version'])).toString('utf8');
  assert.ok(version.includes(pin.version), name + ' version');
  return { path: destination, sha256: pin.exeSha256, version: pin.version };
}
async function provision(directory) {
  assert.ok((windows || process.platform === 'linux') && process.arch === 'x64', 'automatic provisioning requires Windows/Linux x64; supply --config elsewhere');
  const pins = JSON.parse(await readFile(path.join(repository, '.github/scanmux/pins.json'), 'utf8'));
  const linux = JSON.parse(await readFile(path.join(repository, '.github/scanmux/linux-job-pins.json'), 'utf8'));
  const tools = {};
  const git = windows ? successful(await command('where.exe', ['git'])).toString('utf8').trim().split(/\r?\n/)[0] : '/usr/bin/git';
  const gitPath = await realpath(git), version = /\b(\d+\.\d+\.\d+)/.exec(successful(await command(gitPath, ['--version'])).toString('utf8'))?.[1];
  assert.ok(version, 'Git version required');
  // Like ci-linux-job, bind the runner Git's actual bytes and version in the config.
  tools.git = { path: gitPath, sha256: hash(await readFile(gitPath)), version };
  tools.gitleaks = await acquireTool(directory, 'gitleaks', windows ? pins.tools.gitleaks : linux.gitleaks);
  const osvSha256 = '160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b';
  tools.osv = await acquireTool(directory, 'osv', windows ? pins.tools.osv : {
    version: '2.7.0', url: 'https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64', archiveSha256: osvSha256, exeSha256: osvSha256,
  });
  if (windows) {
    const ownerDirectory = path.join(directory, 'owner');
    const powershell = path.join(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
    const built = successful(await command(powershell, ['-NoProfile', '-NonInteractive', '-Command', '& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SCANMUX_OWNER_SOURCE))) -OutputDirectory $env:SCANMUX_OWNER_DESTINATION -SourcePath $env:SCANMUX_OWNER_CS'],
      { env: { ...env, SCANMUX_OWNER_SOURCE: path.join(repository, 'scripts/build-windows-process-owner.ps1'), SCANMUX_OWNER_DESTINATION: ownerDirectory, SCANMUX_OWNER_CS: path.join(repository, 'internal/windows-process-owner.cs') } }));
    const receipt = JSON.parse(built.toString('utf8').trim().split(/\r?\n/).at(-1)), owner = path.join(ownerDirectory, 'scanmux-windows-process-owner.exe');
    assert.equal(receipt.schema, 'scanmux.windows-process-owner-build/v1'); assert.equal(hash(await readFile(owner)), receipt.assemblySha256);
    tools['windows-process-owner'] = { path: owner, sha256: receipt.assemblySha256, version: receipt.version };
  }
  const osvDatabase = path.join(directory, 'database');
  await acquireDatabase({ destination: osvDatabase, ecosystems: ['npm'], maxBytes: pins.database.maxBytes, timeoutMs: pins.database.timeoutMs });
  return { schema: 1, timeoutMs: 120000, tools, osvDatabase };
}
export function verifyDependencies(result, version, commit, inputs) {
  successful(result); assert.doesNotMatch(result.stderr, /stripTypeScriptTypes|ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING/, 'installed deps must not emit a loader warning');
  const report = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.stdout));
  assert.equal(report.schema, 'scanmux.dependencies/v2'); assert.deepEqual(report.tool, { name: 'scanmux', version });
  assert.deepEqual(report.commits, { head: commit, base: null }); assert.equal(report.exitCode, 0);
  assert.equal(report.osv.state, 'completed'); assert.equal(report.osv.sides.head.state, 'completed');
  assert.deepEqual(report.osv.errors, []); assert.deepEqual(report.missing, []);
  assert.deepEqual(report.inputs.head, inputs);
  return report;
}
export async function gate(args) {
  const options = new Map();
  for (let i = 0; i < args.length; i += 2) {
    assert.ok(['--tgz', '--config'].includes(args[i]) && args[i + 1] && !options.has(args[i]), 'use --tgz <archive> --config <config>');
    options.set(args[i], path.resolve(args[i + 1]));
  }
  const directory = await mkdtemp(path.join(await realpath(process.env.RUNNER_TEMP ?? tmpdir()), 'scanmux-installed-'));
  // Keep the dedicated directory for failed-gate diagnosis.
  console.log('Installed-package work directory: ' + directory);
  const emptyGitConfig = path.join(directory, 'empty-gitconfig'); await writeFile(emptyGitConfig, ''); env.GIT_CONFIG_GLOBAL = emptyGitConfig;
  const installed = await installPackage(directory, options.get('--tgz'));
  const { version } = JSON.parse(await readFile(path.join(repository, 'package.json'), 'utf8'));
  const printed = await command(installed.bin, ['--version'], { cwd: installed.consumer });
  assert.equal(successful(printed).toString('utf8'), version + '\n'); assert.equal(printed.stderr, '');
  console.log('Installed --version passed: ' + version);
  const config = options.has('--config') ? JSON.parse(await readFile(options.get('--config'), 'utf8')) : await provision(directory);
  const configPath = path.join(directory, 'config.json'); await writeFile(configPath, JSON.stringify(config) + '\n');
  const fixture = path.join(directory, 'fixture');
  await cp(path.join(repository, 'test/fixtures/installed-package'), fixture, { recursive: true });
  const git = args => command(config.tools.git.path, args, { cwd: fixture });
  for (const args of [['init', '--quiet', '--template='], ['add', '--all'], ['-c', 'user.name=ScanMux Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Installed package fixture']]) successful(await git(args));
  assert.equal(successful(await git(['status', '--porcelain'])).toString('utf8'), '');
  const commit = successful(await git(['rev-parse', 'HEAD'])).toString('utf8').trim();
  const inputs = await Promise.all(['package-lock.json', 'package.json'].map(async name => {
    const bytes = await readFile(path.join(fixture, name)); return { path: name, bytes: bytes.length, sha256: hash(bytes) };
  }));
  const result = await command(installed.bin, ['deps', fixture, '--config', configPath, '--json'], { cwd: installed.consumer });
  verifyDependencies(result, version, commit, inputs);
  if (result.stderr) process.stderr.write(result.stderr);
  console.log('Installed deps passed: exit 0, one v2 document, expected version/commit/inputs, completed OSV, no missing items or loader warning.');
  console.log('Job execution is covered separately by ci-linux-job using an installed runtime; this gate did not run job-scan.');
}
if (import.meta.main) await gate(process.argv.slice(2));
