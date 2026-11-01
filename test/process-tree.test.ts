import { removeTempDir, removeTempDirStrict } from './temp-cleanup.mjs';
import test, { after, before, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import childProcess, { spawn, spawnSync } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { PassThrough } from 'node:stream';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { hash } from '../src/safety.ts';
import type { Tool } from '../src/model.ts';
import { encodeFrame, FrameDecoder, nextPhase, parseEvent, startProcessOwner, withProcessRuntime, type ProcessOwner } from '../src/process-tree.ts';
import { execute } from '../src/process.ts';
import { main } from '../src/cli.ts';
import { loadConfig } from '../src/config.ts';

let spawns = 0;
let fakeOwner: (() => FakeOwner) | undefined;
const originalSpawn = childProcess.spawn;
(childProcess as unknown as Record<string, unknown>).spawn = function (this: unknown, ...args: unknown[]) {
  spawns++;
  if (fakeOwner && path.basename(String(args[0])) === 'scanmux-windows-process-owner.exe') return fakeOwner();
  return Reflect.apply(originalSpawn, this, args);
};
syncBuiltinESMExports();

class FakeOwner extends EventEmitter {
  readonly pid = 4242;
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly #frames: { kind: number; id: number; body: Buffer }[] = [];
  readonly #decoder = new FrameDecoder(64 << 20);
  constructor(version: string) {
    super();
    this.stdin.on('data', (chunk: Buffer) => { this.#frames.push(...this.#decoder.push(chunk)); this.emit('frame'); });
    this.stdin.on('finish', () => this.kill());
    setImmediate(() => this.stdout.write(encodeFrame(1, 0, Buffer.from(version))));
  }
  kill(): boolean {
    if (!this.stdout.writableEnded) { this.stdout.end(); setImmediate(() => this.emit('exit', 0, null)); }
    return true;
  }
  async next(kind: number): Promise<{ id: number; body: Buffer }> {
    for (;;) {
      const index = this.#frames.findIndex(frame => frame.kind === kind);
      if (index >= 0) return this.#frames.splice(index, 1)[0];
      await once(this, 'frame');
    }
  }
  send(kind: number, id: number, body: string | object): void {
    this.stdout.write(encodeFrame(kind, id, Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))));
  }
}
const frame = { start: 2, stop: 3, spawned: 4, out: 5, result: 7 } as const;
const turns = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };
function controlledClock(t: TestContext): void {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 0 });
  t.mock.method(performance, 'now', () => Date.now());
}
async function withFakeOwner(t: TestContext, body: (owner: ProcessOwner, fake: FakeOwner) => Promise<void>, version?: string): Promise<void> {
  if (unavailable) { t.skip(unavailable); return; }
  let fake: FakeOwner | undefined;
  const descriptor = version ? { ...helper!, version } : helper!;
  fakeOwner = () => (fake = new FakeOwner(descriptor.version));
  let owner: ProcessOwner;
  try { owner = await startProcessOwner(descriptor, 10000); } finally { fakeOwner = undefined; }
  try { await body(owner, fake!); } finally { t.mock.timers.reset(); t.mock.restoreAll(); await owner.close(); }
}
const fakeRequest = (timeoutMs: number, signal?: AbortSignal) =>
  ({ executable: helper!, args: [], cwd: tmpdir(), environment, maxOutputBytes: 1 << 20, timeoutMs, stopBudgetMs: 5000, signal });

test('AppContainer requests require owner 1.4.0 before a start frame is sent', async t => withFakeOwner(t, async (owner, fake) => {
  const result = await owner.runContained({ ...fakeRequest(10000), appContainer: { snapshot: 'C:\\S', work: 'C:\\W' } });
  assert.deepEqual([result.reason, result.diagnostics, owner.openRequests()], ['spawn_failed', ['process_appcontainer_owner_version_unsupported'], 0]);
  const ordinary = owner.runContained(fakeRequest(10000));
  const started = await fake.next(frame.start);
  assert.equal(Object.hasOwn(JSON.parse(started.body.toString()), 'appContainer'), false, 'legacy request bytes have no new option');
  fake.send(frame.result, started.id, { reason: 'exit', code: 0, operation: null, win32: 0 });
  assert.equal((await ordinary).reason, 'exit');
}, '1.3.0'));

test('owner recovery frames are validated and exposed with owner-prefixed codes', async t => withFakeOwner(t, async (owner, fake) => {
  const valid = { recovered: 1, kept: 1, codes: ['appcontainer_recovery_root_invalid'] };
  assert.deepEqual(parseEvent({ kind: 10, id: 0, body: Buffer.from(JSON.stringify(valid)) }),
    { type: 'recovery', recovery: { recovered: 1, kept: 1, codes: ['process_owner_appcontainer_recovery_root_invalid'] } });
  for (const [id, body] of [[3, valid], [0, { ...valid, codes: ['not_appcontainer'] }], [0, { ...valid, kept: -1 }], [0, { recovered: 0, kept: 0 }]] as const)
    assert.throws(() => parseEvent({ kind: 10, id, body: Buffer.from(JSON.stringify(body)) }), /process_owner_frame_invalid/);
  fake.send(10, 0, valid);
  assert.deepEqual(await owner.recovery, { recovered: 1, kept: 1, codes: ['process_owner_appcontainer_recovery_root_invalid'] });
}));

test('owner 1.4.0 sends the exact AppContainer roots without changing ordinary request fields', async t => withFakeOwner(t, async (owner, fake) => {
  const appContainer = { snapshot: 'C:\\S', work: 'C:\\W' };
  const running = owner.runContained({ ...fakeRequest(10000), appContainer });
  const started = await fake.next(frame.start);
  assert.deepEqual(JSON.parse(started.body.toString()).appContainer, appContainer);
  fake.send(frame.result, started.id, { reason: 'spawn_failed', code: null, operation: 'appcontainer_unavailable', win32: 0 });
  assert.deepEqual((await running).diagnostics, ['process_owner_appcontainer_unavailable']);
}));

const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const environment = { SystemRoot: process.env.SystemRoot ?? '', WINDIR: process.env.WINDIR ?? '' };
let scratch = '';
let helper: Tool | undefined;
let probe: Tool | undefined;
let unavailable = process.platform === 'win32' ? '' : 'the process owner is Windows-only';

const probeSource = `using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Probe {
 public static int Main(string[] args){
  if(args.Length>0 && args[0]=="argv"){int count;IntPtr list=CommandLineToArgvW(GetCommandLineW(),out count);for(int i=2;i<count;i++)Console.Out.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(Marshal.PtrToStringUni(Marshal.ReadIntPtr(list,i*IntPtr.Size)))));LocalFree(list);return 0;}
  if(args.Length==3 && args[0]=="wait"){IntPtr process=OpenProcess(0x100000,false,uint.Parse(args[1]));if(process==IntPtr.Zero){Console.Out.WriteLine("missing");return 1;}Console.Out.WriteLine("opened");Console.Out.WriteLine(WaitForSingleObject(process,uint.Parse(args[2]))==0?"exited":"alive");return 0;}
  return 2;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr GetCommandLineW();
 [DllImport("shell32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CommandLineToArgvW(IntPtr line,out int count);
 [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
}
`;
const probeBuild = `param([string]$Source,[string]$Output)
$ErrorActionPreference = 'Stop'
$compiler = [System.CodeDom.Compiler.CompilerParameters]::new()
$compiler.CompilerOptions = '/platform:x64'
$compiler.GenerateExecutable = $true
$compiler.OutputAssembly = $Output
[void]$compiler.ReferencedAssemblies.Add('System.dll')
Add-Type -Path $Source -CompilerParameters $compiler
`;
const treeScript = `import { spawn } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
const self = process.argv[1], mode = process.argv[2];
const keep = () => setInterval(() => {}, 1 << 30);
const orphan = stdio => { const c = spawn(process.execPath, [self, 'c'], { detached: true, stdio }); c.unref(); writeFileSync('c.pid', String(c.pid)); };
if (mode === 'a') { const b = spawn(process.execPath, [self, 'b'], { stdio: 'ignore' }); b.on('exit', () => writeFileSync('orphaned', '')); keep(); }
else if (mode === 'b') { orphan('ignore'); process.exit(0); }
else if (mode === 'c') keep();
else if (mode === 'leave') { orphan('ignore'); writeFileSync('orphaned', ''); process.exit(0); }
else if (mode === 'hold') { orphan(['ignore', 'inherit', 'ignore']); writeFileSync('orphaned', ''); process.exit(0); }
else if (mode === 'flood') { orphan('ignore'); writeFileSync('orphaned', ''); const go = setInterval(() => { if (existsSync('go')) { clearInterval(go); process.stdout.write('x'.repeat(4096)); keep(); } }, 20); }
`;

before(async () => {
  if (unavailable) return;
  scratch = await mkdtemp(path.join(tmpdir(), 'scanmux-process-tree-'));
  const built = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', '& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SCANMUX_OWNER_SOURCE))) -OutputDirectory $env:SCANMUX_OWNER_DESTINATION -SourcePath $env:SCANMUX_OWNER_CS'],
    { encoding: 'utf8', windowsHide: true, env: { ...environment, SCANMUX_OWNER_SOURCE: path.resolve('scripts/build-windows-process-owner.ps1'), SCANMUX_OWNER_CS: path.resolve('internal/windows-process-owner.cs'), SCANMUX_OWNER_DESTINATION: path.join(scratch, 'owner') } });
  const receipt = built.status === 0 ? JSON.parse(built.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') : undefined;
  const ownerPath = path.join(scratch, 'owner', 'scanmux-windows-process-owner.exe');
  if (!receipt || receipt.schema !== 'scanmux.windows-process-owner-build/v1' || receipt.assemblySha256 !== hash(await readFile(ownerPath))) {
    unavailable = `process owner build failed: ${built.status} ${built.stderr.slice(0, 400)}`;
    return;
  }
  helper = { path: ownerPath, sha256: receipt.assemblySha256, version: receipt.version };
  await writeFile(path.join(scratch, 'probe.cs'), probeSource);
  await writeFile(path.join(scratch, 'build-probe.ps1'), probeBuild);
  const probePath = path.join(scratch, 'probe.exe');
  const compiled = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', '& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SCANMUX_PROBE_BUILD))) -Source $env:SCANMUX_PROBE_SOURCE -Output $env:SCANMUX_PROBE_DESTINATION'],
    { encoding: 'utf8', windowsHide: true, env: { ...environment, SCANMUX_PROBE_BUILD: path.join(scratch, 'build-probe.ps1'), SCANMUX_PROBE_SOURCE: path.join(scratch, 'probe.cs'), SCANMUX_PROBE_DESTINATION: probePath } });
  if (compiled.status !== 0) { unavailable = `probe build failed: ${compiled.stderr.slice(0, 400)}`; return; }
  probe = { path: probePath, sha256: hash(await readFile(probePath)), version: '0' };
});
after(async () => { if (scratch) await removeTempDirStrict(scratch, { recursive: true, force: true }); });

const node = async (): Promise<Tool> => ({ path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node });
async function workspace(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-tree-'));
  test.after(() => removeTempDir(directory));
  await writeFile(path.join(directory, 'tree.mjs'), treeScript);
  return directory;
}
async function appears(file: string, ms = 10000): Promise<void> {
  for (const started = Date.now(); Date.now() - started < ms;) {
    if (await stat(file).then(() => true, () => false)) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error(`${path.basename(file)} never appeared`);
}
// The handle is opened before the stop, so a reused PID cannot pass for the orphan.
async function watch(pid: number): Promise<{ verdict: Promise<string> }> {
  const child = spawn(probe!.path, ['wait', String(pid), '15000'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'], cwd: tmpdir() });
  let output = '';
  const opened = new Promise<void>((resolve, reject) => {
    child.stdout.on('data', bytes => { output += bytes; if (output.includes('opened')) resolve(); if (output.includes('missing')) reject(Error('orphan was not running')); });
  });
  const verdict = new Promise<string>(resolve => child.once('close', () => resolve(output.trim().split(/\r?\n/).at(-1) ?? '')));
  await opened;
  return { verdict };
}
async function orphanPid(directory: string): Promise<number> {
  await appears(path.join(directory, 'orphaned'));
  return Number(await readFile(path.join(directory, 'c.pid'), 'utf8'));
}
async function withOwner(t: { skip: (message: string) => void }, body: (owner: ProcessOwner) => Promise<void>): Promise<void> {
  if (unavailable) { t.skip(unavailable); return; }
  const owner = await startProcessOwner(helper!, 10000);
  try { await body(owner); } finally { await owner.close(); }
}
const request = async (directory: string, mode: string, timeoutMs: number, signal?: AbortSignal) => ({
  executable: await node(), args: [path.join(directory, 'tree.mjs'), mode], cwd: directory, environment, maxOutputBytes: 1 << 20, timeoutMs, stopBudgetMs: 5000, signal,
});

test('a cancelled tree drains its orphaned grandchild and frees the workspace', async t => withOwner(t, async owner => {
  const directory = await workspace(), controller = new AbortController();
  const running = owner.runContained(await request(directory, 'a', 60000, controller.signal));
  const { verdict } = await watch(await orphanPid(directory));
  controller.abort();
  const result = await running;
  assert.equal(result.reason, 'cancelled');
  assert.equal(await verdict, 'exited');
  await removeTempDirStrict(directory, { recursive: true, maxRetries: 0 });
}));

test('a natural exit that leaves an orphan is held until the deadline and stopped as timeout', async t => withOwner(t, async owner => {
  const directory = await workspace(), started = Date.now();
  const running = owner.runContained(await request(directory, 'leave', 3000));
  const { verdict } = await watch(await orphanPid(directory));
  const result = await running;
  assert.equal(result.reason, 'timeout');
  assert.ok(Date.now() - started >= 3000, 'held until the deadline');
  assert.equal(await verdict, 'exited');
  await removeTempDirStrict(directory, { recursive: true, maxRetries: 0 });
}));

test('an orphan holding the inherited stdout does not delay the result past the stop budget', async t => withOwner(t, async owner => {
  const directory = await workspace(), started = Date.now();
  const running = owner.runContained(await request(directory, 'hold', 3000));
  const { verdict } = await watch(await orphanPid(directory));
  const result = await running;
  assert.equal(result.reason, 'timeout');
  assert.ok(Date.now() - started < 3000 + 5000, `result within the deadline plus the stop budget: ${Date.now() - started} ms`);
  assert.equal(await verdict, 'exited');
  await removeTempDirStrict(directory, { recursive: true, maxRetries: 0 });
}));

test('killing the helper mid-run reports termination_unverified and refuses later starts', async t => withOwner(t, async owner => {
  const directory = await workspace();
  const running = owner.runContained(await request(directory, 'a', 60000));
  const { verdict } = await watch(await orphanPid(directory));
  process.kill(owner.pid);
  const result = await running;
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['termination_unverified', null, ['process_owner_lost']]);
  assert.equal(await verdict, 'exited', 'KILL_ON_JOB_CLOSE still removed the tree');
  const later = await owner.runContained(await request(directory, 'c', 1000));
  assert.deepEqual([later.reason, later.diagnostics], ['spawn_failed', ['process_containment_unavailable']]);
  await removeTempDirStrict(directory, { recursive: true, maxRetries: 0 });
}));

test('arguments with special characters round-trip through CommandLineToArgvW', async t => withOwner(t, async owner => {
  const table = ['', 'plain', 'with space', 'tab\there', 'quote"inside', '"', '""', 'trailing\\', 'trailing\\\\', 'back\\"slash', '\\\\server\\share',
    'a\\\\\\"b', '日本語 テキスト', '&|<>^%!', "single'quote", 'new\nline', ' leading', '{"json": true}', 'C:\\Program Files\\x\\', '*?', '\\', '\\"'];
  const result = await owner.runContained({ executable: probe!, args: ['argv', ...table], cwd: tmpdir(), environment, maxOutputBytes: 1 << 20, timeoutMs: 10000, stopBudgetMs: 5000 });
  assert.deepEqual([result.reason, result.code], ['exit', 0]);
  const lines = result.stdout.toString('utf8').split('\r\n');
  assert.equal(lines.pop(), '');
  assert.deepEqual(lines.map(line => Buffer.from(line, 'base64').toString('utf8')), table);
}));

test('standard input keeps NUL separators', async t => withOwner(t, async owner => {
  const result = await owner.runContained({ executable: await node(), args: ['-e', "process.stdin.on('data',d=>process.stdout.write(d.toString('hex')))"], cwd: tmpdir(), environment, input: 'a b ', maxOutputBytes: 1024, timeoutMs: 10000, stopBudgetMs: 5000 });
  assert.deepEqual([result.reason, result.code, result.stdout.toString()], ['exit', 0, '61006200']);
}));

test('standard input larger than one request frame arrives whole, NUL bytes included', async t => withOwner(t, async owner => {
  const input = 'a\0b'.repeat(6 << 20);
  const count = "const h=require('node:crypto').createHash('sha256');let n=0;process.stdin.on('data',d=>{n+=d.length;h.update(d);}).on('end',()=>process.stdout.write(n+' '+h.digest('hex')))";
  const result = await owner.runContained({ executable: await node(), args: ['-e', count], cwd: tmpdir(), environment, input, maxOutputBytes: 1024, timeoutMs: 60000, stopBudgetMs: 5000 });
  assert.deepEqual([result.reason, result.code, result.stdout.toString()], ['exit', 0, `${input.length} ${hash(input)}`]);
}));

test('a digest mismatch starts nothing and reports spawn_failed', async t => withOwner(t, async owner => {
  const result = await owner.runContained({ executable: { ...probe!, sha256: '0'.repeat(64) }, args: ['argv'], cwd: tmpdir(), environment, maxOutputBytes: 1024, timeoutMs: 10000, stopBudgetMs: 5000 });
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['spawn_failed', null, ['process_owner_tool_digest_mismatch']]);
}));

test('the longest allowed timeout does not overflow the stop deadline timer', async t => withFakeOwner(t, async (owner, fake) => {
  const warnings: string[] = [], listen = (warning: Error) => { warnings.push(warning.name); };
  process.on('warning', listen);
  try {
    const running = owner.runContained(fakeRequest(2147483647));
    const { id } = await fake.next(frame.start);
    await turns();
    fake.send(frame.result, id, { reason: 'exit', code: 0, operation: null, win32: 0 });
    assert.deepEqual([(await running).reason, warnings], ['exit', []]);
  } finally { process.off('warning', listen); }
}));

test('a stop deadline beyond the timer limit fires at its absolute deadline', async t => withFakeOwner(t, async (owner, fake) => {
  controlledClock(t);
  let settled = false;
  const running = owner.runContained(fakeRequest(2147483647)).finally(() => { settled = true; });
  await fake.next(frame.start);
  t.mock.timers.tick(2147483647 + 5000 - 1); await turns();
  assert.equal(settled, false, 'not before the deadline');
  t.mock.timers.tick(1); await turns();
  assert.equal(settled, true, 'at the deadline');
  assert.deepEqual((await running).diagnostics, ['process_owner_stop_budget']);
}));

test('a timeout the helper never reports is termination_unverified one stop budget after the deadline', async t => withFakeOwner(t, async (owner, fake) => {
  controlledClock(t);
  let settled = false;
  const running = owner.runContained(fakeRequest(10000)).finally(() => { settled = true; });
  const { id } = await fake.next(frame.start);
  t.mock.timers.tick(14999); await turns();
  assert.equal(settled, false, 'the helper still has budget');
  t.mock.timers.tick(1); await turns();
  assert.equal(settled, true, 'settled when the stop budget ends');
  const result = await running;
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['termination_unverified', null, ['process_owner_stop_budget']]);
  fake.send(frame.result, id, { reason: 'timeout', code: 1, operation: null, win32: 0 });
  await turns();
  assert.equal(owner.openRequests(), 0);
}));

test('a timeout result that arrives after the stop deadline is termination_unverified before its timer runs', async t => withFakeOwner(t, async (owner, fake) => {
  controlledClock(t);
  const running = owner.runContained(fakeRequest(10000));
  const { id } = await fake.next(frame.start);
  t.mock.timers.setTime(16000);
  fake.send(frame.result, id, { reason: 'timeout', code: 1, operation: null, win32: 0 });
  const result = await running;
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['termination_unverified', null, ['process_owner_stop_budget']]);
}));

test('a cancelled result after the stop deadline is termination_unverified for that request alone', async t => withFakeOwner(t, async (owner, fake) => {
  controlledClock(t);
  const controller = new AbortController();
  const cancelled = owner.runContained(fakeRequest(60000, controller.signal));
  const first = await fake.next(frame.start);
  const other = owner.runContained(fakeRequest(60000));
  const second = await fake.next(frame.start);
  controller.abort();
  await fake.next(frame.stop);
  t.mock.timers.setTime(5000);
  fake.send(frame.result, first.id, { reason: 'cancelled', code: 1, operation: null, win32: 0 });
  const result = await cancelled;
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['termination_unverified', null, ['process_owner_stop_budget']]);
  fake.send(frame.result, second.id, { reason: 'exit', code: 0, operation: null, win32: 0 });
  assert.deepEqual([(await other).reason, owner.openRequests()], ['exit', 0]);
}));

test('a stop the helper never confirms is termination_unverified at the stop budget, and its late result is dropped', async t => withFakeOwner(t, async (owner, fake) => {
  controlledClock(t);
  const controller = new AbortController();
  let settled = false;
  const running = owner.runContained(fakeRequest(60000, controller.signal)).finally(() => { settled = true; });
  const { id } = await fake.next(frame.start);
  fake.send(frame.spawned, id, { pid: 7, creationTime: '1' });
  await turns();
  controller.abort();
  await fake.next(frame.stop);
  t.mock.timers.tick(4999); await turns();
  assert.equal(settled, false, 'the helper still has budget');
  t.mock.timers.tick(1); await turns();
  assert.equal(settled, true, 'settled when the stop budget ends');
  const result = await running;
  assert.deepEqual([result.reason, result.code, result.diagnostics], ['termination_unverified', null, ['process_owner_stop_budget']]);
  fake.send(frame.result, id, { reason: 'cancelled', code: 1, operation: null, win32: 0 });
  await turns();
  assert.equal(owner.openRequests(), 0);
  const later = owner.runContained(fakeRequest(60000));
  const next = await fake.next(frame.start);
  fake.send(frame.result, next.id, { reason: 'exit', code: 0, operation: null, win32: 0 });
  assert.equal((await later).reason, 'exit', 'the late result did not break the owner');
}));

test('settled requests leave the owner with their output', async t => withFakeOwner(t, async (owner, fake) => {
  for (let i = 0; i < 3; i++) {
    const running = owner.runContained(fakeRequest(60000));
    const { id } = await fake.next(frame.start);
    fake.send(frame.spawned, id, { pid: 7, creationTime: '1' });
    fake.send(frame.out, id, 'x'.repeat(1000));
    fake.send(frame.result, id, { reason: 'exit', code: 0, operation: null, win32: 0 });
    assert.equal((await running).stdout.length, 1000);
  }
  assert.equal(owner.openRequests(), 0);
}));

test('the helper runs from a private copy, so the configured file can change while it runs', async t => {
  if (unavailable) { t.skip(unavailable); return; }
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-owner-copy-'));
  test.after(() => removeTempDir(directory));
  const configured = path.join(directory, 'scanmux-windows-process-owner.exe');
  await writeFile(configured, await readFile(helper!.path));
  try {
    await withProcessRuntime({ helper: { ...helper!, path: configured }, timeoutMs: 10000 }, { decide: () => {}, verify: async () => {} }, async () => {
      await writeFile(configured, 'replaced while the helper runs');
      const result = await execute(probe!, ['argv', 'x'], { cwd: directory, home: directory, timeoutMs: 10000, maxOutputBytes: 1024 });
      assert.deepEqual([result.reason, result.code], ['exit', 0]);
    });
  } finally { await removeTempDirStrict(directory, { recursive: true, force: true }); }
});

test('a schema 1 config may pin the process owner', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-owner-pin-'));
  test.after(() => removeTempDir(directory));
  const file = path.join(directory, 'config.json'), owner = { path: process.execPath, sha256: '0'.repeat(64), version: '1.1.0' };
  try {
    await writeFile(file, JSON.stringify({ schema: 1, tools: { 'windows-process-owner': owner } }));
    assert.deepEqual((await loadConfig(file)).tools['windows-process-owner'], owner);
  } finally { await removeTempDirStrict(directory, { recursive: true, force: true }); }
});

test('frame decoder rejects truncated and oversize frames and reassembles split ones', () => {
  const frames = Buffer.concat([encodeFrame(1, 0, Buffer.from('1.0.0')), encodeFrame(5, 7, Buffer.from('abc'))]);
  const decoder = new FrameDecoder(16);
  const decoded = [...frames].flatMap(byte => decoder.push(Buffer.of(byte)));
  decoder.end();
  assert.deepEqual(decoded.map(frame => [frame.kind, frame.id, frame.body.toString()]), [[1, 0, '1.0.0'], [5, 7, 'abc']]);

  const truncated = new FrameDecoder(16);
  assert.deepEqual(truncated.push(frames.subarray(0, frames.length - 1)), [{ kind: 1, id: 0, body: Buffer.from('1.0.0') }]);
  assert.throws(() => truncated.end(), /process_owner_frame_truncated/);
  assert.throws(() => new FrameDecoder(2).push(encodeFrame(5, 7, Buffer.from('abc'))), /process_owner_frame_invalid/);
  const short = Buffer.alloc(9); short.writeUInt32LE(4, 0);
  assert.throws(() => new FrameDecoder(16).push(short), /process_owner_frame_invalid/);
});

test('request events follow started, spawned, finished and a duplicate result is a protocol violation', () => {
  const result = (reason: string, code: number | null) => parseEvent({ kind: 7, id: 3, body: Buffer.from(JSON.stringify({ reason, code, operation: null, win32: 0 })) });
  const spawned = parseEvent({ kind: 4, id: 3, body: Buffer.from(JSON.stringify({ pid: 10, creationTime: '1' })) });
  const output = parseEvent({ kind: 5, id: 3, body: Buffer.from('x') });
  if (spawned.type === 'ready' || spawned.type === 'recovery' || output.type === 'ready' || output.type === 'recovery') throw Error('unexpected owner event');
  const done = result('exit', 0);
  if (done.type === 'ready' || done.type === 'recovery') throw Error('unexpected owner event');
  assert.equal(nextPhase(nextPhase(nextPhase('started', spawned), output), done), 'finished');
  assert.throws(() => nextPhase('finished', done), /process_owner_event_after_result/);
  assert.throws(() => nextPhase(undefined, done), /process_owner_unknown_request/);
  assert.throws(() => nextPhase('started', output), /process_owner_output_before_spawn/);
  assert.throws(() => nextPhase('spawned', spawned), /process_owner_duplicate_spawn/);
  assert.throws(() => result('exit', null), /process_owner_frame_invalid/);
  assert.throws(() => result('termination_unverified', 0), /process_owner_frame_invalid/);
  assert.throws(() => result('done', 0), /process_owner_frame_invalid/);
  assert.throws(() => parseEvent({ kind: 9, id: 3, body: Buffer.alloc(0) }), /process_owner_frame_invalid/);
});

const run = async (directory: string, mode: string, options: { timeoutMs: number; maxOutputBytes: number }) =>
  execute(await node(), [path.join(directory, 'tree.mjs'), mode], { cwd: directory, home: directory, ...options });
test('timeout and output limit keep their own reasons after the Job drains', async t => {
  if (unavailable) { t.skip(unavailable); return; }
  await withProcessRuntime({ helper, timeoutMs: 10000 }, { decide: () => {}, verify: async () => {} }, async () => {
    const timed = await workspace();
    const timing = run(timed, 'a', { timeoutMs: 3000, maxOutputBytes: 1 << 20 });
    const late = await watch(await orphanPid(timed));
    assert.equal((await timing).reason, 'timeout');
    assert.equal(await late.verdict, 'exited');
    await removeTempDirStrict(timed, { recursive: true, maxRetries: 0 });

    const flooded = await workspace();
    const flooding = run(flooded, 'flood', { timeoutMs: 60000, maxOutputBytes: 1024 });
    const loud = await watch(await orphanPid(flooded));
    await writeFile(path.join(flooded, 'go'), '');
    assert.equal((await flooding).reason, 'output_limit');
    assert.equal(await loud.verdict, 'exited');
    await removeTempDirStrict(flooded, { recursive: true, maxRetries: 0 });
  });
});

test('without an admitted process owner nothing starts and the refusal is explicit', { skip: process.platform !== 'win32' }, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-uncontained-'));
  test.after(() => removeTempDir(directory));
  const saved = { TEMP: process.env.TEMP, TMP: process.env.TMP, TMPDIR: process.env.TMPDIR };
  test.after(() => { for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value; });
  Object.assign(process.env, { TEMP: directory, TMP: directory, TMPDIR: directory });
  const marker = path.join(directory, 'started'), tool = await node();
  try {
    spawns = 0;
    const loose = await execute(tool, ['-e', 'require("node:fs").writeFileSync(process.argv[1],"")', marker], { cwd: directory, home: directory, timeoutMs: 10000, maxOutputBytes: 1024, onSpawn: () => assert.fail('spawned') });
    assert.deepEqual([loose.reason, loose.code, loose.diagnostics], ['spawn_failed', null, ['process_containment_unavailable']]);

    let decided = 0, verified = 0, entered = 0;
    const counted = { decide: () => { decided++; }, verify: async () => { verified++; } };
    await assert.rejects(withProcessRuntime({ helper: undefined, timeoutMs: 10000 }, counted, async () => { entered++; }), /process_containment_unavailable/);
    assert.deepEqual([decided, verified, entered], [1, 0, 0], 'the policy decision refuses first, then the missing owner refuses before any check that starts a process');
    const stopped = { decide: () => { throw new Error('runtime_policy_stopped'); }, verify: async () => { verified++; } };
    await assert.rejects(withProcessRuntime({ helper: undefined, timeoutMs: 10000 }, stopped, async () => { entered++; }), /runtime_policy_stopped/);
    if (helper) {
      await assert.rejects(withProcessRuntime({ helper, timeoutMs: 10000 }, { decide: () => {}, verify: async () => { throw new Error('runtime_policy_stopped'); } }, async () => { entered++; }), /runtime_policy_stopped/);
      await assert.rejects(withProcessRuntime({ helper: { ...helper, sha256: '0'.repeat(64) }, timeoutMs: 10000 }, counted, async () => { entered++; }), /tool_digest_mismatch/);
      assert.deepEqual([verified, entered], [0, 0], 'an unadmitted or replaced owner never runs the body');
    }

    const config = path.join(directory, 'config.json');
    await writeFile(config, JSON.stringify({ schema: 1, tools: { git: tool } }));
    const errors: string[] = [], write = process.stderr.write;
    process.stderr.write = (chunk: string | Uint8Array) => { errors.push(String(chunk)); return true; };
    let code;
    try { code = await main(['doctor', '--config', config]); } finally { process.stderr.write = write; }
    assert.equal(code, 4);
    assert.equal(JSON.parse(errors.join('')).error, 'process_containment_unavailable');
    assert.equal(spawns, 0, 'no process started');
    assert.equal(await stat(marker).then(() => true, () => false), false);

    await writeFile(config, JSON.stringify({ schema: 1 }));
    const out = process.stdout.write;
    process.stdout.write = () => true;
    try { assert.equal(await main(['doctor', '--config', config]), 3, 'a command that starts no tool still runs'); } finally { process.stdout.write = out; }
  } finally { await removeTempDirStrict(directory, { recursive: true, force: true }); }
});
