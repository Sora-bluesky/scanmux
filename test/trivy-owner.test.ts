import test, { after, before, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { copyFile, link, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { hash } from '../src/safety.ts';
import type { Tool } from '../src/model.ts';
import { protectDirectory, verifyPrivateDirectory } from '../src/private-storage.ts';
import { execute, executeDirect } from '../src/process.ts';
import { startProcessOwner, withProcessRuntime, type ProcessOwner } from '../src/process-tree.ts';

const windows = process.platform === 'win32';
const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const environment = { SystemRoot: process.env.SystemRoot ?? '', WINDIR: process.env.WINDIR ?? '' };
let scratch = '', binary = '', helper: Tool;
const source = `using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
public static class Probe {
 static int Number(IntPtr token,int kind){int n;GetTokenInformation(token,kind,IntPtr.Zero,0,out n);IntPtr p=Marshal.AllocHGlobal(n);try{if(!GetTokenInformation(token,kind,p,n,out n))throw new Exception("token");return Marshal.ReadInt32(p);}finally{Marshal.FreeHGlobal(p);}}
 static bool Read(string p){try{File.ReadAllBytes(p);return true;}catch(UnauthorizedAccessException){return false;}}
 static bool Write(string p){try{File.WriteAllText(p,"test");return true;}catch(UnauthorizedAccessException){return false;}}
 public static int Main(string[] a){
  if(a[0]=="wait"){IntPtr h=OpenProcess(0x100000,false,uint.Parse(a[1]));if(h==IntPtr.Zero)return 2;Console.WriteLine("opened");Console.WriteLine(WaitForSingleObject(h,15000)==0?"exited":"alive");return 0;}
  if(a[0]=="child"){Thread.Sleep(Timeout.Infinite);return 0;}
  IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),8,out token))return 3;
  int ac=Number(token,29), caps=Number(token,30), elevated=Number(token,20);if(ac!=1||caps!=0||elevated!=0)return 4;
  int bytes;GetTokenInformation(token,31,IntPtr.Zero,0,out bytes);IntPtr data=Marshal.AllocHGlobal(bytes);string sid;try{if(!GetTokenInformation(token,31,data,bytes,out bytes))return 5;sid=new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value;}finally{Marshal.FreeHGlobal(data);}
  IntPtr folder;if(GetAppContainerFolderPath(sid,out folder)!=0)return 6;string storage;try{storage=Marshal.PtrToStringUni(folder);}finally{Marshal.FreeCoTaskMem(folder);}
  string root=a[1], work=Path.Combine(root,"W");
  string profile=Directory.GetDirectories(Path.Combine(work,"local","Packages"))[0];
  if(a[0]=="probe"){
   int tcp=0,udp=0;
   try{using(var s=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)){var pending=s.BeginConnect(IPAddress.Loopback,int.Parse(a[2]),null,null);if(pending.AsyncWaitHandle.WaitOne(2000))s.EndConnect(pending);else tcp=10060;}}catch(SocketException e){tcp=e.NativeErrorCode;}
   try{using(var s=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp)){s.SendTo(new byte[]{0},new IPEndPoint(IPAddress.Loopback,9));}}catch(SocketException e){udp=e.NativeErrorCode;}
   Console.Error.Write("bounded diagnostic");
   Console.WriteLine(new JavaScriptSerializer().Serialize(new { appContainer=ac, capabilities=caps, elevated=elevated, sid=sid, storage=storage, profile=Path.GetFileName(profile), tcpError=tcp, udpError=udp,
    snapshotRead=Read(Path.Combine(root,"S","input")), binRead=Read(Path.Combine(root,"bin","probe.exe")), workWrite=Write(Path.Combine(work,"ok")),
    privateRead=Read(Path.Combine(root,"private")), aapRead=Read(Path.Combine(root,"aap")), snapshotWrite=Write(Path.Combine(root,"S","denied")), binWrite=Write(Path.Combine(root,"bin","denied")) }));return 0;
  }
  if(a[0]=="mark"){File.WriteAllText(Path.Combine(work,"started"),"");return 0;}
  if(a[0]=="emptyw"){
   // Leave W first: a current directory cannot be deleted, which would hide a missing ACL denial.
   Directory.SetCurrentDirectory(Path.Combine(root,"S"));int removed=0;
   foreach(string e in Directory.GetFileSystemEntries(work)){try{if(Directory.Exists(e))Directory.Delete(e,true);else File.Delete(e);removed++;}catch(Exception){}}
   int denial=RemoveDirectory(work)?0:Marshal.GetLastWin32Error();
   int rename=MoveFile(work,work+"-moved")?0:Marshal.GetLastWin32Error();
   // Try to grant itself DELETE on W and delete W again, which would defeat the non-delete grant.
   string permission="none";try{var acl=Directory.GetAccessControl(work,AccessControlSections.Access);acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,AccessControlType.Allow));Directory.SetAccessControl(work,acl);}catch(Exception e){permission=e.GetType().Name;}
   int second=RemoveDirectory(work)?0:Marshal.GetLastWin32Error();
   Console.WriteLine(new JavaScriptSerializer().Serialize(new { removed=removed, denial=denial, rename=rename, permission=permission, second=second, exists=Directory.Exists(work) }));return 0;
  }
  File.WriteAllText(Path.Combine(work,"sid"),sid);
  var start=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"child");start.UseShellExecute=false;start.CreateNoWindow=true;var child=Process.Start(start);
  File.WriteAllText(Path.Combine(work,"pid"),child.Id.ToString());
  while(!File.Exists(Path.Combine(work,"go")))Thread.Sleep(10);
  if(a[0]=="flood")Console.Write(new string('x',65536));
  Thread.Sleep(Timeout.Infinite);return 0;
 }
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="RemoveDirectoryW")] static extern bool RemoveDirectory(string path);
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode,EntryPoint="MoveFileW")] static extern bool MoveFile(string from,string to);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr p,int size,out int n);
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("userenv.dll",CharSet=CharSet.Unicode)] static extern int GetAppContainerFolderPath(string sid,out IntPtr path);
}
`;

before(async () => {
  if (!windows) return;
  helper = JSON.parse(process.env.SCANMUX_TEST_PROCESS_OWNER ?? '{}') as Tool;
  assert.equal(helper.version, '1.4.0', 'the npm test runner builds the current owner');
  scratch = await mkdtemp(path.join(tmpdir(), 'trivy-owner-'));
  await writeFile(path.join(scratch, 'probe.cs'), source);
  binary = path.join(scratch, 'probe.exe');
  const compile = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    '$ErrorActionPreference="Stop"; $p=New-Object System.CodeDom.Compiler.CompilerParameters; $p.CompilerOptions="/platform:x64"; $p.GenerateExecutable=$true; $p.OutputAssembly=$env:PROBE_OUT; [void]$p.ReferencedAssemblies.Add("System.dll"); [void]$p.ReferencedAssemblies.Add("System.Web.Extensions.dll"); Add-Type -Path $env:PROBE_SRC -CompilerParameters $p'],
  { windowsHide: true, encoding: 'utf8', env: { ...environment, PROBE_SRC: path.join(scratch, 'probe.cs'), PROBE_OUT: binary } });
  assert.equal(compile.status, 0, compile.stderr);
});
after(async () => { if (scratch) await rm(scratch, { recursive: true, force: true }); });

async function fixture(): Promise<{ root: string; tool: Tool; request: Parameters<ProcessOwner['runContained']>[0] }> {
  const root = await mkdtemp(path.join(scratch, 'run-'));
  await protectDirectory(root);
  for (const dir of ['S', 'W', 'bin']) await mkdir(path.join(root, dir));
  await copyFile(binary, path.join(root, 'bin', 'probe.exe'));
  await writeFile(path.join(root, 'S', 'input'), 'snapshot');
  await writeFile(path.join(root, 'private'), 'synthetic private');
  await writeFile(path.join(root, 'aap'), 'synthetic AAP-readable');
  const grant = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    '$f=[IO.FileInfo]::new($env:AAP_FILE); $a=$f.GetAccessControl(); $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new("S-1-15-2-1"),"ReadAndExecute","Allow")); $f.SetAccessControl($a)'],
  { windowsHide: true, encoding: 'utf8', env: { ...environment, AAP_FILE: path.join(root, 'aap') } });
  assert.equal(grant.status, 0, grant.stderr);
  const tool = { path: path.join(root, 'bin', 'probe.exe'), sha256: hash(await readFile(binary)), version: '0' };
  return { root, tool, request: { executable: tool, args: ['probe', root, '9'], cwd: path.join(root, 'W'), environment, appContainer: { snapshot: path.join(root, 'S'), work: path.join(root, 'W') }, timeoutMs: 15000, maxOutputBytes: 8192, stopBudgetMs: 5000 } };
}
const exists = async (file: string): Promise<boolean> => stat(file).then(() => true, () => false);
function unavailable(t: Pick<TestContext, 'skip'>, result: { reason: string; diagnostics?: string[] }, required = process.env.SCANMUX_REQUIRE_APPCONTAINER === '1'): boolean {
  if (result.reason !== 'spawn_failed' || result.diagnostics?.length !== 1
    || !['process_owner_appcontainer_elevated_owner', 'process_owner_appcontainer_profile_unavailable'].includes(result.diagnostics[0])) return false;
  assert.equal(required, false, `AppContainer execution required: ${result.diagnostics[0]}`);
  t.skip(result.diagnostics[0]); return true;
}
test('AppContainer skips only explicit environment limitations and required mode forbids every skip', () => {
  for (const operation of ['elevated_owner', 'profile_unavailable', 'grant_failed', 'create_failed', 'token_mismatch', 'roots_invalid', 'unavailable']) {
    const result = { reason: 'spawn_failed', diagnostics: [`process_owner_appcontainer_${operation}`] };
    let skipped = false;
    const t = { skip() { skipped = true; } };
    const allowed = ['elevated_owner', 'profile_unavailable'].includes(operation);
    assert.equal(unavailable(t, result, false), allowed); assert.equal(skipped, allowed);
    if (allowed) assert.throws(() => unavailable(t, result, true), /AppContainer execution required/);
    else assert.equal(unavailable(t, result, true), false);
  }
});
async function appears(file: string, finished: () => boolean): Promise<boolean> {
  for (const started = Date.now(); Date.now() - started < 10000;) {
    if (await exists(file)) return true;
    if (finished()) return false;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('contained probe did not create readiness marker');
}

test('AppContainer has zero capabilities, read-only inputs, private sibling denial and cleanup', { skip: !windows }, async t => {
  const f = await fixture();
  const owner = await startProcessOwner(helper, 10000);
  let connections = 0;
  const listener = createServer(socket => { connections++; socket.destroy(); });
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
  try {
    const address = listener.address();
    assert.ok(address && typeof address !== 'string');
    const result = await owner.runContained({ ...f.request, args: ['probe', f.root, String(address.port)] });
    if (unavailable(t, result)) {
      assert.equal(await exists(path.join(f.root, 'W', 'ok')), false);
      assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true);
      return;
    }
    assert.deepEqual([result.reason, result.code, result.diagnostics], ['exit', 0, []]);
    const data = JSON.parse(result.stdout.toString());
    assert.deepEqual([data.appContainer, data.capabilities, data.elevated], [1, 0, 0]);
    assert.deepEqual([data.snapshotRead, data.binRead, data.workWrite, data.privateRead, data.aapRead, data.snapshotWrite, data.binWrite], [true, true, true, false, true, false, false]);
    assert.ok([10013, 10060].includes(data.tcpError), 'loopback TCP is denied or times out against a listening socket');
    assert.equal(connections, 0, 'no TCP connection reached the loopback listener');
    assert.equal(result.stderr.toString(), 'bounded diagnostic');
    assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true, 'profile SID ACEs removed from all roots');
    assert.ok(path.isAbsolute(data.storage));
    assert.equal(await exists(data.storage), false, 'disposable profile storage removed');
    const residual = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
      '$n=0; foreach($r in @("S","bin","W")){ $d=[IO.DirectoryInfo]::new([IO.Path]::Combine($env:PROBE_ROOT,$r)); foreach($f in @($d)+@($d.GetFileSystemInfos("*",[IO.SearchOption]::AllDirectories))){foreach($a in $f.GetAccessControl().GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($a.IdentityReference.Value -eq $env:PROBE_SID){$n++}}}}; [Console]::Write($n)'],
    { windowsHide: true, encoding: 'utf8', env: { ...environment, PROBE_ROOT: f.root, PROBE_SID: data.sid } });
    assert.deepEqual([residual.status, residual.stdout], [0, '0'], residual.stderr);
    t.diagnostic(`loopback TCP: ${data.tcpError}; UDP send error: ${data.udpError}; UDP delivery remains unverified`);
  } finally { await new Promise<void>(resolve => listener.close(() => resolve())); await owner.close(); }
});

test('AppContainer rejects overlapping roots before a tool starts', { skip: !windows }, async t => {
  const f = await fixture(), owner = await startProcessOwner(helper, 10000);
  try {
    for (const appContainer of [{ snapshot: f.root, work: f.request.cwd }, { snapshot: path.join(f.root, 'S'), work: path.join(f.root, 'bin') }]) {
      const result = await owner.runContained({ ...f.request, args: ['mark', f.root], appContainer });
      if (unavailable(t, result)) return;
      assert.deepEqual([result.reason, result.diagnostics], ['spawn_failed', ['process_owner_appcontainer_roots_invalid']]);
      assert.equal(await exists(path.join(f.root, 'W', 'started')), false);
    }
  } finally { await owner.close(); }
});

test('AppContainer can empty W but cannot delete W itself, and cleanup still succeeds', { skip: !windows }, async t => {
  const f = await fixture(), owner = await startProcessOwner(helper, 10000);
  try {
    await writeFile(path.join(f.root, 'W', 'seed'), 'synthetic');
    const result = await owner.runContained({ ...f.request, args: ['emptyw', f.root] });
    if (unavailable(t, result)) return;
    assert.deepEqual([result.reason, result.code, result.diagnostics], ['exit', 0, []]);
    const data = JSON.parse(result.stdout.toString());
    assert.ok(data.removed >= 2, 'the tool may remove the contents of W');
    assert.deepEqual([data.denial, data.rename, data.exists], [5, 5, true], 'deleting or renaming W fails with ERROR_ACCESS_DENIED');
    // Writing an unchanged ACL is skipped by .NET, so the probe adds a real ACE before writing it.
    assert.deepEqual([data.permission, data.second], ['UnauthorizedAccessException', 5], 'the tool cannot grant itself DELETE on W');
    assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true);
  } finally { await owner.close(); }
});

test('AppContainer refuses a hardlinked file in any granted root before granting', { skip: !windows }, async t => {
  const owner = await startProcessOwner(helper, 10000);
  try {
    for (const dir of ['S', 'bin', 'W']) {
      const f = await fixture();
      await link(path.join(f.root, 'private'), path.join(f.root, dir, 'linked'));
      const result = await owner.runContained({ ...f.request, args: ['mark', f.root] });
      if (unavailable(t, result)) return;
      assert.deepEqual([result.reason, result.diagnostics], ['spawn_failed', ['process_owner_appcontainer_hardlink_present']], dir);
      assert.equal(await exists(path.join(f.root, 'W', 'started')), false);
      assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true);
    }
  } finally { await owner.close(); }
});

test('AppContainer timeout, cancellation and output limit stop descendants and remove grants', { skip: !windows }, async t => {
  const owner = await startProcessOwner(helper, 10000);
  try {
    for (const mode of ['timeout', 'cancelled', 'output_limit'] as const) {
      const f = await fixture(), controller = new AbortController();
      const running = owner.runContained({ ...f.request, args: [mode === 'output_limit' ? 'flood' : 'tree', f.root], timeoutMs: mode === 'timeout' ? 3000 : 30000, maxOutputBytes: 1024, signal: controller.signal });
      let finished = false;
      void running.then(() => { finished = true; });
      if (!await appears(path.join(f.root, 'W', 'pid'), () => finished)) {
        const result = await running;
        if (unavailable(t, result)) return;
        assert.fail(`AppContainer setup failed: ${JSON.stringify(result.diagnostics)}`);
      }
      const pid = (await readFile(path.join(f.root, 'W', 'pid'), 'utf8')).trim();
      const watcher = spawn(binary, ['wait', pid], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'], env: environment });
      let output = '';
      await new Promise<void>((resolve, reject) => { watcher.stdout.on('data', chunk => { output += chunk; if (output.includes('opened')) resolve(); }); watcher.on('error', reject); watcher.on('exit', code => { if (code !== 0) reject(Error('descendant not running')); }); });
      const exited = new Promise<void>(resolve => watcher.on('close', () => resolve()));
      if (mode === 'cancelled') controller.abort();
      else if (mode === 'output_limit') await writeFile(path.join(f.root, 'W', 'go'), '');
      assert.equal((await running).reason, mode);
      await exited;
      assert.equal(output.trim().split(/\r?\n/).at(-1), 'exited');
      assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true);
    }
  } finally { await owner.close(); }
});

function leftovers(root: string, sid: string): { aces: number; mapped: boolean } {
  const checked = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command',
    '$n=0; foreach($r in @("S","bin","W")){ $d=[IO.DirectoryInfo]::new([IO.Path]::Combine($env:PROBE_ROOT,$r)); if(!$d.Exists){continue}; foreach($f in @($d)+@($d.GetFileSystemInfos("*",[IO.SearchOption]::AllDirectories))){foreach($a in $f.GetAccessControl().GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($a.IdentityReference.Value -eq $env:PROBE_SID){$n++}}}}; $m=Test-Path -LiteralPath ("HKCU:\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings\\"+$env:PROBE_SID); [Console]::Write("$n $m")'],
  { windowsHide: true, encoding: 'utf8', env: { ...environment, PROBE_ROOT: root, PROBE_SID: sid } });
  assert.equal(checked.status, 0, checked.stderr);
  const [aces, mapped] = checked.stdout.trim().split(' ');
  return { aces: Number(aces), mapped: mapped === 'True' };
}

test('a new owner reclaims the grants and profile of an owner killed during a request', { skip: !windows }, async t => {
  const f = await fixture(), first = await startProcessOwner(helper, 10000);
  let finished = false;
  const running = first.runContained({ ...f.request, args: ['tree', f.root], timeoutMs: 60000 });
  void running.then(() => { finished = true; });
  if (!await appears(path.join(f.root, 'W', 'pid'), () => finished)) {
    const result = await running;
    if (unavailable(t, result)) { await first.close(); return; }
    assert.fail(`AppContainer setup failed: ${JSON.stringify(result.diagnostics)}`);
  }
  const sid = (await readFile(path.join(f.root, 'W', 'sid'), 'utf8')).trim();
  // While the first owner lives it holds its journal exclusively, so no other owner can reclaim yet.
  const before = leftovers(f.root, sid);
  assert.ok(before.aces > 0 && before.mapped, 'the running request has grants and a profile');
  const killed = spawnSync(path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'), ['/F', '/PID', String(first.pid)], { windowsHide: true, encoding: 'utf8' });
  assert.equal(killed.status, 0, killed.stderr);
  assert.equal((await running).reason, 'termination_unverified');
  await first.close();
  // An owner started by a parallel test file may already have reclaimed them, so this is a diagnostic, not an assertion.
  t.diagnostic(`left by the killed owner: ${JSON.stringify(leftovers(f.root, sid))}`);
  const second = await startProcessOwner(helper, 10000);
  try {
    await second.recovery;
    // Another test file's owner may be reclaiming the same journal; wait for whichever owner does it.
    let now = leftovers(f.root, sid);
    for (const started = Date.now(); (now.aces || now.mapped) && Date.now() - started < 15000; now = leftovers(f.root, sid)) await new Promise(resolve => setTimeout(resolve, 200));
    assert.deepEqual(now, { aces: 0, mapped: false });
  } finally { await second.close(); }
});

test('AppContainer execute refuses unsupported platforms or missing owner with no fallback', async () => {
  const tool = { path: process.execPath, sha256: hash(await readFile(process.execPath)), version: process.versions.node };
  const options = { cwd: process.cwd(), home: process.cwd(), appContainer: { snapshot: process.cwd(), work: process.cwd() }, timeoutMs: 1000, maxOutputBytes: 1024, onSpawn: () => assert.fail('tool started') };
  const result = await execute(tool, ['--version'], options);
  assert.deepEqual([result.reason, result.diagnostics], ['spawn_failed', [windows ? 'process_appcontainer_owner_unavailable' : 'process_appcontainer_unsupported_platform']]);
  assert.equal((await executeDirect(tool, ['--version'], options)).reason, 'spawn_failed');
});

test('AppContainer execute exposes stderr only when requested and applies a combined output bound', { skip: !windows }, async t => {
  const f = await fixture();
  await withProcessRuntime({ helper, timeoutMs: 10000 }, { decide() {}, async verify() {} }, async () => {
    const options = { cwd: f.request.cwd, home: f.request.cwd, appContainer: f.request.appContainer, timeoutMs: 15000, maxOutputBytes: 8192 };
    const result = await execute(f.tool, f.request.args, { ...options, captureStderr: true });
    if (unavailable(t, result)) return;
    assert.equal(result.reason, 'exit', JSON.stringify(result.diagnostics));
    assert.equal(result.stderr?.toString(), 'bounded diagnostic');
    const hidden = await execute(f.tool, f.request.args, options);
    assert.equal(Object.hasOwn(hidden, 'stderr'), false);
    const bounded = await execute(f.tool, f.request.args, { ...options, captureStderr: true, maxOutputBytes: 8 });
    assert.equal(bounded.reason, 'output_limit');
    assert.ok(bounded.stdout.length + (bounded.stderr?.length ?? 0) <= 8);
  });
});

test('AppContainer create failures preserve their operation instead of becoming unavailable', { skip: !windows }, async t => {
  const f = await fixture(), owner = await startProcessOwner(helper, 10000);
  try {
    const bytes = Buffer.from('synthetic invalid executable');
    await writeFile(f.tool.path, bytes);
    const result = await owner.runContained({ ...f.request, executable: { ...f.tool, sha256: hash(bytes) } });
    if (unavailable(t, result)) return;
    assert.deepEqual([result.reason, result.diagnostics], ['spawn_failed', ['process_owner_appcontainer_create_failed']]);
    assert.equal(await verifyPrivateDirectory(f.root, ['S', 'bin', 'W']), true);
  } finally { await owner.close(); }
});

test('owner distinguishes child token mismatch and grant failure at their source', { skip: !windows }, () => {
  const checked = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', `
    $ErrorActionPreference='Stop'
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    $assembly=[Reflection.Assembly]::LoadFile($env:OWNER_EXE)
    $owner=$assembly.GetType('ScanMuxWindowsProcessOwner')
    $flags=[Reflection.BindingFlags]'NonPublic,Static'
    $sid=[Security.Principal.SecurityIdentifier]::new('S-1-15-2-12345')
    try { $owner.GetMethod('VerifyToken',$flags).Invoke($null,@([Diagnostics.Process]::GetCurrentProcess().Handle,$sid)); throw 'expected mismatch' }
    catch { $failure=$_.Exception; while($failure.InnerException){$failure=$failure.InnerException}; [Console]::WriteLine($failure.operation) }
    $container=$owner.GetNestedType('Container',[Reflection.BindingFlags]'NonPublic')
    $instance=[Activator]::CreateInstance($container,$true)
    $container.GetField('identity').SetValue($instance,$sid)
    try { $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'ReadAndExecute','Allow'); $container.GetMethod('Add',[Reflection.BindingFlags]'NonPublic,Instance').Invoke($instance,@($env:MISSING_ROOT,[Security.AccessControl.FileSystemAccessRule[]]@($rule))); throw 'expected grant failure' }
    catch { $failure=$_.Exception; while($failure.InnerException){$failure=$failure.InnerException}; [Console]::WriteLine($failure.operation) }
  `], { windowsHide: true, encoding: 'utf8', env: { ...environment, OWNER_EXE: helper.path, MISSING_ROOT: path.join(scratch, 'absent') } });
  assert.equal(checked.status, 0, checked.stderr);
  assert.deepEqual(checked.stdout.trim().split(/\r?\n/), ['appcontainer_token_mismatch', 'appcontainer_grant_failed']);
});
