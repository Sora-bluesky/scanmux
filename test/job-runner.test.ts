import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { validateJobContainer, jobRuntimeFiles } from '../src/job-runner.ts';
import type { JobProfile } from '../src/job-config.ts';
import { verifyPackagePaths } from '../scripts/verify-public.ts';

function fixture() {
  const tool = { path: path.resolve('.local/fixture.exe'), sha256: 'a'.repeat(64), version: '1.2.3' };
  const profile: JobProfile = { schema: 'scanmux.job-profile/v1', name: 'synthetic_boundary_fixture', scope: 'offline-local', docker: { tool, endpoint: 'unix:///var/run/docker.sock' }, image: 'sha256:' + 'b'.repeat(64),
    runtime: { nodeVersion: '24.22.1', python: { ...tool, path: '/usr/bin/python3' }, git: { ...tool, path: '/usr/bin/git' } }, tools: { gitleaks: tool }, osvDatabase: null,
    scan: { timeoutMs: 10000, maxOutputBytes: 65536, maxFileBytes: 65536, maxSnapshotBytes: 1048576, maxFiles: 100 },
    limits: { cpuCount: 1, memoryBytes: 268435456, tmpBytes: 8388608, workBytes: 16777216, shmBytes: 1048576, pids: 64, wallMs: 20000, cleanupTimeoutMs: 10000, retainedBytes: 1048576 } };
  const jobId = '11111111-1111-4111-8111-111111111111', name = 'scanmux-job-' + jobId, id = 'c'.repeat(64);
  const mounts = [{ source: path.resolve('.local/owned-source'), target: '/repo/' + 'd'.repeat(64) }, { source: path.resolve('.local/owned-app'), target: '/app' },
    { source: path.resolve('.local/owned-gitleaks'), target: '/tools/gitleaks' }, { source: path.resolve('.local/owned-db/database-receipt.json'), target: '/db/database-receipt.json' }];
  const expected = { id, jobId, name, profile, mounts, imageEnvironment: ['PATH=trusted_image_value'], imageLabels: {} };
  const value = { Id: id, Name: '/' + name, Image: profile.image,
    Config: { Labels: { 'scanmux.job': jobId }, User: '1000:1000', Tty: false, OpenStdin: true, WorkingDir: '/work', Env: expected.imageEnvironment,
      Entrypoint: ['/usr/bin/python3'], Cmd: ['-I', '-B', '/app/internal/linux-job-supervisor.py', jobId, '20000', '65536'], Healthcheck: { Test: ['NONE'] } },
    HostConfig: { NetworkMode: 'none', ReadonlyRootfs: true, Privileged: false, AutoRemove: false, PidMode: '', IpcMode: 'private', CgroupnsMode: 'private', UTSMode: '',
      Init: false, OomKillDisable: false, CapAdd: Array<string>(), CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges'], Binds: [], Devices: [], DeviceRequests: [], DeviceCgroupRules: [],
      ExtraHosts: [], Links: [], VolumesFrom: [], GroupAdd: [], PortBindings: {}, PublishAllPorts: false, LogConfig: { Type: 'none' },
      Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=8388608,mode=1777', '/work': 'rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=1000,gid=1000' },
      PidsLimit: 64, NanoCpus: 1000000000, Memory: 268435456, MemorySwap: 268435456, ShmSize: 1048576,
      Mounts: mounts.map(mount => ({ Type: 'bind', Source: mount.source, Target: mount.target, ReadOnly: true })) },
    Mounts: mounts.map(mount => ({ Type: 'bind', Source: mount.source, Destination: mount.target, RW: false })),
    State: { Running: false, ExitCode: 0, OOMKilled: false } };
  return { expected, value };
}

test('container inventory binds exact identities and files; privileges, networks, uncapped stores and alternate sources cannot enter', () => {
  const { expected, value } = fixture();
  assert.deepEqual(validateJobContainer(value, expected), { running: false, terminal: { exitCode: 0, oomKilled: false } });
  const changes: ((input: typeof value) => void)[] = [
    input => input.Id = 'f'.repeat(64), input => input.Image = 'sha256:' + 'e'.repeat(64), input => input.Config.Labels['scanmux.job'] = 'foreign',
    input => input.Config.User = '0:0', input => input.Config.Env.push('AMBIENT_CREDENTIAL=forbidden'), input => input.Config.Cmd.push('--untrusted'),
    input => input.Config.Healthcheck.Test = ['CMD', 'target-script'], input => input.HostConfig.Privileged = true,
    input => input.HostConfig.ReadonlyRootfs = false, input => input.HostConfig.SecurityOpt = ['seccomp=unconfined'], input => input.HostConfig.CapAdd = ['SYS_PTRACE'],
    input => input.HostConfig.PidMode = 'host', input => input.HostConfig.IpcMode = 'host', input => input.HostConfig.CgroupnsMode = 'host', input => input.HostConfig.NetworkMode = 'bridge',
    input => input.HostConfig.NanoCpus = 0, input => input.HostConfig.MemorySwap = -1, input => input.HostConfig.PidsLimit = 0, input => input.HostConfig.ShmSize++,
    input => input.HostConfig.Tmpfs['/work'] = 'rw,size=unbounded', input => input.HostConfig.Mounts[0].ReadOnly = false,
    input => input.HostConfig.Mounts[0].Source += '/alternate', input => input.Mounts[0].RW = true,
    input => input.HostConfig.Mounts.push({ Type: 'bind', Source: '/var/run/docker.sock', Target: '/var/run/docker.sock', ReadOnly: true }),
    input => input.HostConfig.Mounts[3].Source = path.resolve('.local/owned-db'),
    input => input.Mounts.push({ Type: 'volume', Source: 'implicit', Destination: '/uncapped', RW: true }),
  ];
  for (const change of changes) { const input = structuredClone(value); change(input); assert.throws(() => validateJobContainer(input, expected)); }
});

test('runtime and package share one exact file inventory; stray src files and private records are refused', () => {
  verifyPackagePaths([...jobRuntimeFiles]);
  assert.throws(() => verifyPackagePaths([...jobRuntimeFiles, 'src/stray-private.ts']));
  assert.throws(() => verifyPackagePaths([...jobRuntimeFiles, '.local/private-record.json']));
  assert.throws(() => verifyPackagePaths(jobRuntimeFiles.filter(file => file !== 'internal/linux-job-supervisor.py')));
});

test('the job runtime bundle contains every file in the static import closure of src/cli.ts', async () => {
  const specifiers = /(?:^|\n)\s*(?:import|export)\b[^;'"]*?\bfrom\s*'(\.{1,2}\/[^']+)'|(?:^|\n)\s*import\s*'(\.{1,2}\/[^']+)'/g;
  const seen = new Set<string>(), pending = ['src/cli.ts'];
  while (pending.length) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const match of (await readFile(file, 'utf8')).matchAll(specifiers)) {
      pending.push(path.posix.normalize(path.posix.join(path.posix.dirname(file), match[1] ?? match[2])));
    }
  }
  assert.ok(seen.size > 40 && seen.has('src/dependencies.ts') && seen.has('src/import.ts'), 'closure walk reached the command modules');
  assert.deepEqual([...seen].filter(file => !jobRuntimeFiles.includes(file)).sort(), []);
});

async function cli(args: string[]) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ['bin/scanmux.mjs', ...args], { windowsHide: true, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR }, stdio: ['ignore', 'pipe', 'pipe'] });
    const output: Buffer[] = [], errors: Buffer[] = []; let size = 0;
    const timer = setTimeout(() => { child.kill(); reject(Error('fixture CLI timeout')); }, 10000);
    child.stdout.on('data', bytes => { size += bytes.length; if (size > 65536) child.kill(); else output.push(bytes); });
    child.stderr.on('data', bytes => { size += bytes.length; if (size > 65536) child.kill(); else errors.push(bytes); });
    child.once('error', reject); child.once('close', code => { clearTimeout(timer); resolve({ code, stdout: Buffer.concat(output).toString('utf8'), stderr: Buffer.concat(errors).toString('utf8') }); });
  });
}
test('new profile cannot fall through any old command; incompatible job flags fail before preparation', async () => {
  const root = path.resolve('.local/does-not-exist-target'), profile = path.resolve('.local/does-not-exist-profile.json');
  for (const command of ['doctor', 'plan', 'scan', 'ai-plan', 'ai-scan', 'plan-list', 'scan-list', 'serve', 'runner-check', 'ci-check', 'history', 'recover', 'resume', 'dispositions', 'policy-check']) {
    const args = [command, ...(['doctor', 'serve', 'runner-check'].includes(command) ? [] : [root]), '--job-profile', profile];
    const result = await cli(args); assert.equal(result.code, 4); assert.equal(result.stdout, ''); assert.equal(JSON.parse(result.stderr).error, 'invalid_command');
  }
  for (const extra of [['--config', profile], ['--report-language', 'en'], ['--accept-plan', 'a'.repeat(64)], ['--ci-run', '11111111-1111-4111-8111-111111111111'], ['--from', profile], ['--site-origin', 'https://example.invalid']]) {
    const result = await cli(['job-scan', root, '--job-profile', profile, ...extra]); assert.equal(result.code, 4); assert.equal(result.stdout, ''); assert.equal(JSON.parse(result.stderr).error, 'invalid_command');
  }
  const url = await cli(['job-scan', 'https://example.invalid/repository', '--job-profile', profile]);
  assert.equal(url.code, 4); assert.equal(JSON.parse(url.stderr).error, 'job_local_root_required');
  const missing = await cli(['job-export', profile]); assert.equal(JSON.parse(missing.stderr).error, 'job_reader_config_required');
});
