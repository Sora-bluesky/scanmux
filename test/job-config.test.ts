import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import * as fs from 'node:fs/promises';
import { defaults } from '../src/config.ts';
import { digest, hash, within } from '../src/safety.ts';
import { jobDatabaseMounts, jobFileIdentity, jobLinuxConfig, loadJobProfile, parseJobProfile } from '../src/job-config.ts';

// Explicit fixture capacities, not application defaults or performance recommendations.
function profile(file: string) {
  const tool = { path: file, version: '1.2.3', sha256: hash('owned fixture executable bytes') };
  return { schema: 'scanmux.job-profile/v1', name: 'fixture', scope: 'offline-local', docker: { tool, endpoint: process.platform === 'win32' ? 'npipe:////./pipe/dockerDesktopLinuxEngine' : 'unix:///var/run/docker.sock' },
    image: 'sha256:' + 'a'.repeat(64), runtime: { nodeVersion: '24.22.1', python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } },
    tools: { gitleaks: tool, osv: tool }, osvDatabase: null as string | null,
    scan: { timeoutMs: 10000, maxOutputBytes: 1024 * 1024, maxFileBytes: 1024 * 1024, maxSnapshotBytes: 8 * 1024 * 1024, maxFiles: 1000 },
    limits: { cpuCount: 1, memoryBytes: 256 * 1024 * 1024, tmpBytes: 8 * 1024 * 1024, workBytes: 16 * 1024 * 1024, shmBytes: 1024 * 1024,
      pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 16 * 1024 * 1024 } };
}
async function fixture() {
  const parent = tmpdir(), directory = await fs.mkdtemp(path.join(parent, 'bounded-job-config-test-'));
  test.after(() => removeTempDir(directory));
  const root = path.join(directory, 'source'), executable = path.join(directory, 'fixture.exe');
  await fs.mkdir(root); await fs.writeFile(executable, 'owned fixture executable bytes');
  return { directory, root, executable, async close() { assert.ok(within(parent, directory)); await removeTempDirStrict(directory, { recursive: true }); } };
}

test('job profile constructs an offline Linux policy without changing existing Config defaults/digest', () => {
  const input = profile(path.resolve('.local/fixture.exe')), parsed = parseJobProfile(input), config = jobLinuxConfig(parsed);
  assert.deepEqual(parsed, input);
  assert.equal(config.tools.git?.path, '/usr/bin/git'); assert.equal(config.tools.gitleaks?.path, '/tools/gitleaks'); assert.equal(config.tools.osv?.path, '/tools/osv');
  assert.equal(config.runner, null); assert.equal(config.ai, null); assert.equal(config.osvDatabase, null);
  assert.equal(digest(defaults), 'fa29e80009c28284ec2ec41b0ba6b71f215f2962e32791b521d3daf8c1a69f26');
  config.tools.git!.path = '/changed'; assert.equal(parsed.runtime.git.path, '/usr/bin/git');
});

test('job profile rejects unknown authority, nonlocal endpoints, unbounded/rounded/overflow limits and unsupported runtime paths', () => {
  const original = profile(path.resolve('.local/fixture.exe'));
  const changes: ((value: ReturnType<typeof profile>) => void)[] = [
    value => Object.assign(value, { auth: 'ambient' }), value => value.scope = 'ai', value => Object.assign(value.tools, { 'codex-security': value.tools.gitleaks }),
    value => value.runtime.python.path = '/bin/python3', value => value.runtime.git.path = '/host/git',
    value => value.docker.endpoint = 'tcp://127.0.0.1:2375', value => value.docker.endpoint = 'ssh://localhost',
    value => value.docker.endpoint = 'unix:///var/../docker.sock', value => value.tools.gitleaks.path = 'relative',
    value => value.tools.gitleaks.path += ',readonly=false', value => value.image = 'node:latest',
    value => value.limits.cpuCount = 0.5, value => value.limits.memoryBytes = 4096,
    value => value.limits.tmpBytes++, value => value.limits.workBytes = Number.MAX_SAFE_INTEGER,
    value => value.limits.cpuCount = Number.MAX_SAFE_INTEGER, value => value.limits.pids = Infinity,
    value => value.limits.wallMs = 2147483648, value => value.limits.cleanupTimeoutMs = 0,
    value => value.limits.retainedBytes = 2 * value.scan.maxOutputBytes - 1, value => value.scan.maxFiles = NaN,
    value => value.scan.maxOutputBytes = 2147483648, value => Object.assign(value.runtime, { extra: 'arbitrary command' }),
  ];
  for (const change of changes) { const input = structuredClone(original); change(input); assert.throws(() => parseJobProfile(input)); }
});

test('job profile validates exact regular pinned host files and refuses target-owned/invalid UTF8/oversized profiles', { skip: process.platform === 'darwin' }, async () => {
  const f = await fixture();
  try {
    const source = path.join(f.directory, 'profile.json'), input = profile(f.executable);
    await fs.writeFile(source, JSON.stringify(input));
    const loaded = await loadJobProfile(source, f.root);
    assert.equal(loaded.mappedRoot, '/repo/' + hash(f.root)); assert.equal(loaded.profileSha256, digest(parseJobProfile(input)));
    assert.deepEqual(await jobFileIdentity(f.executable), { bytes: Buffer.byteLength('owned fixture executable bytes'), sha256: input.tools.gitleaks.sha256 });
    const inside = path.join(f.root, 'profile.json'); await fs.copyFile(source, inside);
    await assert.rejects(loadJobProfile(inside, f.root), /path_inside_target/);
    await fs.writeFile(source, Buffer.from([255])); await assert.rejects(loadJobProfile(source, f.root));
    await fs.writeFile(source, ' '.repeat(65537)); await assert.rejects(loadJobProfile(source, f.root), /file_limit/);
    await fs.writeFile(source, JSON.stringify(input)); await fs.appendFile(f.executable, 'changed');
    await assert.rejects(loadJobProfile(source, f.root), /job_asset_mismatch/);
  } finally { await f.close(); }
});

test('database admission selects only six literal regular files; parent directories and sibling credentials are absent', { skip: process.platform === 'darwin' }, async () => {
  const f = await fixture();
  try {
    const input = profile(f.executable); input.osvDatabase = f.directory;
    const zip = path.join(f.directory, 'osv-scalibr', 'npm', 'all.zip'); await fs.mkdir(path.dirname(zip), { recursive: true });
    await fs.writeFile(zip, 'owned ZIP placeholder, not executed');
    await fs.writeFile(path.join(f.directory, 'database-receipt.json'), '{}');
    await fs.writeFile(path.join(f.directory, 'synthetic-credential-marker'), 'never admitted');
    const mounts = await jobDatabaseMounts(parseJobProfile(input), f.root);
    assert.deepEqual(mounts.map(mount => mount.destination), ['/db/osv-scalibr/npm/all.zip', '/db/database-receipt.json']);
    assert.ok(mounts.every(mount => mount.source !== f.directory && !mount.source.endsWith('synthetic-credential-marker')));
    const source = path.join(f.directory, 'profile.json'); await fs.writeFile(source, JSON.stringify(input));
    // The DB root may be an ancestor of the target: only the fixed files become mounts.
    assert.equal((await loadJobProfile(source, f.root)).profile.osvDatabase, f.directory);
    await fs.mkdir(path.join(f.directory, 'acquisition-started')); await assert.rejects(jobDatabaseMounts(parseJobProfile(input), f.root), /invalid_job_asset/);
    await fs.rmdir(path.join(f.directory, 'acquisition-started'));
    await fs.link(zip, path.join(f.directory, 'second-link'));
    await assert.rejects(jobDatabaseMounts(parseJobProfile(input), f.root), /invalid_job_asset/);
  } finally { await f.close(); }
});
