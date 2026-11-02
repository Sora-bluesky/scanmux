import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { cleanEnvironment } from '../src/process.ts';
import { loadJobProfile, parseJobProfile, jobFileIdentity, jobLinuxConfig } from '../src/job-config.ts';
import { jobRuntimeFiles, validateJobContainer } from '../src/job-runner.ts';
import { validateJobBoundary, validateJobNativeFailure, validateJobObserver } from '../src/job-records.ts';
import { digest, hash } from '../src/safety.ts';

const profileInput = process.env.SCANMUX_NATIVE_JOB_PROFILE;
const fixturePrefix = `
import {spawn} from 'node:child_process';
let initBuffer=Buffer.alloc(0);
await new Promise((resolve,reject)=>{
 const receive=bytes=>{initBuffer=Buffer.concat([initBuffer,bytes]);if(initBuffer.length>65536)reject(Error('fixture_init_limit'));const end=initBuffer.indexOf(10);if(end>=0){JSON.parse(initBuffer.subarray(0,end));process.stdin.removeListener('data',receive);process.stdin.pause();resolve();}};
 process.stdin.on('data',receive);process.stdin.once('error',reject);process.stdin.once('end',()=>reject(Error('fixture_init_eof')));
});
function run(file,args){return new Promise((resolve,reject)=>{
 const child=spawn(file,args,{env:{HOME:'/work',TMPDIR:'/tmp',LANG:'C.UTF-8',LC_ALL:'C.UTF-8'},stdio:['ignore','pipe','pipe']});
 let bytes=0;const out=[],err=[];child.stdout.on('data',b=>{bytes+=b.length;if(bytes>8388608)reject(Error('fixture_output_limit'));else out.push(b);});child.stderr.on('data',b=>{if(b.length>65536)reject(Error('fixture_stderr_limit'));else err.push(b);});
 child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal,bytes,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8')}));
});}
`;
const pipePython = [
  'import os,fcntl', 'r,w=os.pipe()', 'size=fcntl.fcntl(w,fcntl.F_GETPIPE_SZ)+4096', 'pid=os.fork()',
  'if pid==0:', ' os.close(w)', ' total=0', ' while True:', '  b=os.read(r,4096)', '  if not b: break', '  total+=len(b)',
  ' os._exit(0 if total==size else 9)', 'os.close(r)', "written=os.write(w,b'X'*size)", 'os.close(w)',
  'child,status=os.waitpid(pid,0)', "os.write(1,b'X'*written)", 'os.write(2,str(size).encode())', 'os._exit(0 if written==size and status==0 else 9)',
].join('\n');
const scenarios = {
  'controller-disappearance': fixturePrefix + "process.kill(process.pid,'SIGKILL');await new Promise(()=>{});\n",
  'spawn-exit': fixturePrefix + String.raw`
const versions=[];for(let i=0;i<2;i++){const value=await run('/tools/gitleaks',['version']);if(value.code!==0||value.signal||value.stdout.trim()!=='8.30.1')throw Error('fixture_version_failure');versions.push(value.stdout.trim());}
process.stdout.write(JSON.stringify({scenario:'spawn-exit',versions})+'\n',()=>process.stdin.destroy());
`,
  'internal-pipe': fixturePrefix + String.raw`
const script=${JSON.stringify(pipePython)};
const result=await run('/usr/bin/python3',['-I','-B','-c',script]);
if(result.code!==0||result.signal||result.bytes!==Number(result.stderr)||!/^X+$/.test(result.stdout))throw Error('fixture_pipe_failure');
process.stdout.write(JSON.stringify({scenario:'internal-pipe',bytes:result.bytes,expectedBytes:Number(result.stderr),code:result.code})+'\n',()=>process.stdin.destroy());
`,
};
const pythonScenario = (name, code, inherited = false) => fixturePrefix + String.raw`
const script=${JSON.stringify(code)};
${inherited ? "const child=spawn('/usr/bin/python3',['-I','-B','-c',script],{env:{HOME:'/work',TMPDIR:'/tmp',LANG:'C.UTF-8',LC_ALL:'C.UTF-8'},stdio:['ignore','inherit','pipe']}); child.stderr.resume(); await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});" : "const value=await run('/usr/bin/python3',['-I','-B','-c',script]);if(value.code!==0||value.signal)throw Error('fixture_python_failure');const result=JSON.parse(value.stdout);process.stdout.write(JSON.stringify({scenario:" + JSON.stringify(name) + ",...result})+String.fromCharCode(10),()=>process.stdin.destroy());"}
`;
for (const [name, store, syscall, high] of [
  ['disk-work', '/work', 'write', false], ['disk-tmp', '/tmp', 'pwrite64', false], ['disk-shm-high-fd', '/dev/shm', 'write', true],
]) {
  const code = ['import os,ctypes', 'lib=ctypes.CDLL(None,use_errno=True)', `fd=os.open('${store}/quota',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)`,
    "b=ctypes.create_string_buffer(b'X'*65536)", 'offset=0', 'while True:',
    ` result=lib.syscall(ctypes.c_long(${syscall === 'write' ? 1 : 18}),ctypes.c_ulong(fd${high ? '+(1<<32)' : ''}),ctypes.cast(b,ctypes.c_void_p),ctypes.c_size_t(65536)${syscall === 'pwrite64' ? ',ctypes.c_longlong(offset)' : ''})`,
    ' if result<0: break', ' offset+=result',
    "os.write(1,b'WRITER_CONTINUED_AFTER_ENOSPC')", 'os._exit(9)',
  ].join('\n');
  scenarios[name] = pythonScenario(name, code, true);
}
scenarios['partial-write'] = pythonScenario('partial-write', [
  'import os,json', "fd=os.open('/work/partial',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)",
  'space=os.fstatvfs(fd)', 'left=space.f_bavail*space.f_frsize-4096', 'while left:',
  " n=os.write(fd,b'X'*min(65536,left))", ' left-=n', "written=os.write(fd,b'Y'*8192)",
  'assert written==4096', 'os.close(fd)', "os.write(1,json.dumps({'written':written,'requested':8192}).encode())",
].join('\n'));
scenarios['nonquota-negative'] = pythonScenario('nonquota-negative', [
  'import os,errno,json,ctypes', "fd=os.open('/dev/null',os.O_WRONLY)", 'assert os.write(fd,b"X"*8192)==8192', 'os.close(fd)',
  'lib=ctypes.CDLL(None,use_errno=True)', 'assert lib.syscall(ctypes.c_long(1),ctypes.c_int(-1),ctypes.c_char_p(b"X"),ctypes.c_size_t(1))==-1',
  'assert ctypes.get_errno()==errno.EBADF', "os.write(1,json.dumps({'missingErrno':errno.EBADF,'fakeMessage':'ENOSPC errno 28; not a native fact'}).encode())",
].join('\n'));
scenarios['population-filter'] = pythonScenario('population-filter', [
  'import os,ctypes,errno,json', 'lib=ctypes.CDLL(None,use_errno=True)', 'results={}',
  'for nr in [101,310,311,272,308,319,447,425,426,427]:',
  ' ctypes.set_errno(0)', ' result=lib.syscall(ctypes.c_long(nr),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))',
  ' assert result==-1 and ctypes.get_errno()==errno.EPERM', " results[str(nr)]=ctypes.get_errno()",
  'assert lib.syscall(ctypes.c_long(435),ctypes.c_ulong(0),ctypes.c_ulong(0))==-1 and ctypes.get_errno()==errno.ENOSYS',
  'for flag in [0x00800000,0x00020000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000]:',
  ' result=lib.syscall(ctypes.c_long(56),ctypes.c_ulong(flag|17),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))',
  ' if result==0: os._exit(91)', ' assert result==-1 and ctypes.get_errno()==errno.EPERM',
  "os.write(1,json.dumps({'denied':results,'clone3Errno':errno.ENOSYS,'legacyDeniedFlags':8}).encode())",
].join('\n'));
scenarios['nonleader-exec'] = pythonScenario('nonleader-exec', [
  'import os,threading', "thread=threading.Thread(target=lambda:os.execv('/usr/bin/python3',['python3','-I','-B','-c',\"import os;os.write(1,b'{}')\"]))",
  'thread.start()', 'thread.join()', 'os._exit(92)',
].join('\n'));
scenarios['concurrent-writers'] = pythonScenario('concurrent-writers', [
  'import os,threading,json', 'def write(name):', " fd=os.open('/work/'+name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)",
  ' for i in range(8):', "  assert os.write(fd,b'X'*16384)==16384", ' os.close(fd)',
  'pid=os.fork()', "if pid==0: write('forked');os._exit(0)",
  "threads=[threading.Thread(target=write,args=(name,)) for name in ['thread-a','thread-b']]",
  'for thread in threads: thread.start()', 'for thread in threads: thread.join()', 'child,status=os.waitpid(pid,0)', 'assert status==0',
  "sizes=[os.stat('/work/'+name).st_size for name in ['forked','thread-a','thread-b']]", 'assert sizes==[131072]*3',
  "os.write(1,json.dumps({'sizes':sizes}).encode())",
].join('\n'));
scenarios['vfork-exec'] = pythonScenario('vfork-exec', [
  'import os,json', "code=\"import os;fd=os.open('/work/vfork-output',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);assert os.write(fd,b'X'*8192)==8192;os.close(fd)\"",
  "pid=os.posix_spawn('/usr/bin/python3',['python3','-I','-B','-c',code],{'HOME':'/work','TMPDIR':'/tmp','LANG':'C.UTF-8'})",
  'child,status=os.waitpid(pid,0)', "assert status==0 and os.stat('/work/vfork-output').st_size==8192", "os.write(1,json.dumps({'childStatus':status,'bytes':8192}).encode())",
].join('\n'));
scenarios['fd-reuse'] = pythonScenario('fd-reuse', [
  'import os,threading,ctypes,errno,json', "quota=os.open('/work/reused',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)", "null=os.open('/dev/null',os.O_WRONLY)",
  'target=200', 'os.dup2(null,target)', 'changes=[]', 'def mutate():', ' for i in range(64):',
  '  os.dup2(quota,target)', "  changes.append('quota')", '  os.close(target)', "  changes.append('missing')", '  os.dup2(null,target)', "  changes.append('nonquota')",
  'thread=threading.Thread(target=mutate)', 'thread.start()', 'lib=ctypes.CDLL(None,use_errno=True)', 'success=missing=0', 'for i in range(256):',
  ' result=lib.syscall(ctypes.c_long(1),ctypes.c_int(target),ctypes.c_char_p(b"X"),ctypes.c_size_t(1))',
  ' if result==1: success+=1', ' else:', '  assert result==-1 and ctypes.get_errno()==errno.EBADF', '  missing+=1',
  'thread.join()', 'assert len(changes)==192 and success+missing==256', "os.write(1,json.dumps({'success':success,'missing':missing,'fdTransitions':len(changes)}).encode())",
].join('\n'));
const observerErrorScenarios = new Set(['nonquota-enospc', 'payload-sigtrap', 'payload-group-stop']);
scenarios['nonquota-enospc'] = pythonScenario('nonquota-enospc', [
  'import os', "fd=os.open('/dev/full',os.O_WRONLY)", 'try:', " os.write(fd,b'X')", 'except OSError: pass', "os.write(1,b'WRITER_CONTINUED_AFTER_UNCORRELATED_ENOSPC')",
].join('\n'),true);
for(const[name,sig]of[['payload-sigtrap','SIGTRAP'],['payload-group-stop','SIGSTOP']])scenarios[name]=pythonScenario(name,
  `import os,signal\nos.kill(os.getpid(),signal.${sig})\nos.write(1,b'UNSUPPORTED_STOP_CONTINUED')`,true);
for (const name of ['restart-write', 'signal-restart-write']) scenarios[name] = pythonScenario(name, [
  'import os,fcntl,threading,time,signal,json', 'r,w=os.pipe()', 'size=fcntl.fcntl(w,fcntl.F_GETPIPE_SZ)',
  "assert os.write(w,b'X'*size)==size", 'ready=threading.Event()', 'received=bytearray()', 'signals=[]',
  'signal.signal(signal.SIGUSR1,lambda sig,frame:signals.append(sig))', 'signal.siginterrupt(signal.SIGUSR1,False)',
  'def trigger():', ' ready.wait()', ' time.sleep(0.02)',
  ...(name === 'signal-restart-write' ? [' os.kill(os.getpid(),signal.SIGUSR1)'] : []),
  // The measured-store write interrupts the blocked pipe writer at the all-stop barrier.
  " fd=os.open('/work/trigger',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)", " assert os.write(fd,b'X')==1", ' os.close(fd)',
  ' while True:', '  data=os.read(r,4096)', '  if not data: break', '  received.extend(data)', ' os.close(r)',
  'thread=threading.Thread(target=trigger)', 'thread.start()', 'ready.set()', "assert os.write(w,b'Y')==1", 'os.close(w)', 'thread.join()',
  "assert received==b'X'*size+b'Y'", `assert len(signals)==${name === 'signal-restart-write' ? 1 : 0}`,
  "os.write(1,json.dumps({'bytes':len(received),'expectedBytes':size+1,'signals':len(signals)}).encode())",
].join('\n'));

export async function runNativeSupervisorFixture(profilePath, scenario) {
  assert.ok(Object.hasOwn(scenarios, scenario));
  const runId = randomUUID(), directory = path.join(tmpdir(), 'bounded-job-native-' + scenario + '-' + runId), source = path.join(directory, 'source'), app = path.join(directory, 'app');
  await fs.mkdir(directory);
  test.after(() => removeTempDir(directory));
  await fs.mkdir(source); await fs.writeFile(path.join(source, 'owned.txt'), 'self-authored; never executed\n');
  await fs.mkdir(app); await fs.mkdir(path.join(directory, 'docker-config')); await fs.writeFile(path.join(directory, 'empty-gitconfig'), '');
  const loaded = await loadJobProfile(profilePath, source), value = structuredClone(loaded.profile);
  value.osvDatabase = null; delete value.tools.osv;
  // Explicit native-fixture values, separate from application defaults/production evidence.
  Object.assign(value.limits, { memoryBytes: 536870912, tmpBytes: 8388608, workBytes: 8388608, shmBytes: 1048576, pids: 64, wallMs: 15000 });
  const profile = parseJobProfile(value), config = jobLinuxConfig(profile), assets = [], publicState = [];
  for (const relative of jobRuntimeFiles) {
    const original = path.resolve(...relative.split('/')), destination = path.join(app, ...relative.split('/'));
    publicState.push({ path: relative, ...await jobFileIdentity(original) });
    await fs.mkdir(path.dirname(destination), { recursive: true }); await fs.copyFile(original, destination, 1);
  }
  // This is a private test controller. The public CLI/profile provides no command/module override.
  await fs.writeFile(path.join(app, 'internal/linux-job-controller.mjs'), scenarios[scenario]);
  for (const relative of jobRuntimeFiles) assets.push({ path: relative, ...await jobFileIdentity(path.join(app, ...relative.split('/'))) });
  const expected = { jobId: runId, profileSha256: digest(profile), root: source, mappedRoot: '/repo/' + hash(source), config, limits: profile.limits,
    image: profile.image, runtime: { ...profile.runtime, tools: config.tools, app: assets }, destination: directory, comparison: null };
  const mounts = [{ source, target: expected.mappedRoot }, { source: app, target: '/app' }, { source: profile.tools.gitleaks.path, target: '/tools/gitleaks' }];
  const name = 'scanmux-job-native-' + runId;
  const proof = { schema: 'scanmux.native-job-supervisor-fixture/v1', state: 'failed', scenario, runId,
    classification: 'test-owned controller with the exact production supervisor; not a real scan/provider result', actualProviderCalls: 0, credentialsAccessed: false,
    directory, profileSha256: digest(profile), publicState, assets, packets: [], containerAbsent: false, sourceUnchanged: false };
  const env = cleanEnvironment(directory), dockerArguments = args => ['--host', profile.docker.endpoint, '--config', path.join(directory, 'docker-config'), ...args];
  const syntax = spawnSync(process.execPath, ['--input-type=module', '--check'], { input: scenarios[scenario], env, windowsHide: true, encoding: 'utf8' });
  assert.equal(syntax.status, 0, 'self-authored fixture must parse before creating a container');
  const call = args => new Promise((resolve, reject) => {
    const child = spawn(profile.docker.tool.path, dockerArguments(args), { windowsHide: true, shell: false, env, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = []; let bytes = 0, stderrBytes = 0, limited = false, timeout = false;
    const timer = setTimeout(() => { timeout = true; child.kill(); }, profile.limits.cleanupTimeoutMs);
    child.stdout.on('data', data => { bytes += data.length; if (bytes > profile.scan.maxOutputBytes) { limited = true; child.kill(); } else out.push(data); });
    child.stderr.on('data', data => { stderrBytes += data.length; if (stderrBytes > profile.scan.maxOutputBytes) { limited = true; child.kill(); } });
    child.once('error', reject); child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, limited, timeout, stdout: Buffer.concat(out), stderrBytes }); });
  });
  const good = result => { assert.equal(result.code, 0); assert.equal(result.signal, null); assert.equal(result.limited, false); assert.equal(result.timeout, false); return result.stdout; };
  const json = result => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(good(result)));
  let id, imageEnvironment, imageLabels, child, outerSequence = 0, hostSequence = 0, timer, closedProcess, start = performance.now();
  const bound = () => ({ id, name, jobId: runId, profile, mounts, imageEnvironment, imageLabels });
  const inspect = async () => { const list = json(await call(['inspect', id])); assert.equal(list.length, 1); return validateJobContainer(list[0], bound()); };
  const send = (type, fields) => { const line = Buffer.from(JSON.stringify({ v: 1, nonce: runId, seq: ++hostSequence, type, ...fields }) + '\n'); assert.ok(line.length <= 65536); child.stdin.write(line); };
  try {
    const [image] = json(await call(['image', 'inspect', profile.image])); assert.equal(image.Id, profile.image);
    imageEnvironment = image.Config.Env; imageLabels = image.Config.Labels;
    id = good(await call(['create', '--pull=never', '--interactive', '--name', name, '--label', 'scanmux.job=' + runId, '--network', 'none', '--read-only', '--user', '1000:1000',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--ipc', 'private', '--cgroupns', 'private', '--init=false', '--no-healthcheck', '--pids-limit', '64', '--log-driver', 'none',
      '--cpus', String(profile.limits.cpuCount), '--memory', String(profile.limits.memoryBytes), '--memory-swap', String(profile.limits.memoryBytes), '--shm-size', String(profile.limits.shmBytes),
      '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=8388608,mode=1777', '--tmpfs', '/work:rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=1000,gid=1000',
      ...mounts.flatMap(mount => ['--mount', 'type=bind,source=' + mount.source + ',target=' + mount.target + ',readonly']), '--workdir', '/work', '--entrypoint', '/usr/bin/python3', profile.image,
      '-I', '-B', '/app/internal/linux-job-supervisor.py', runId, String(profile.limits.wallMs), String(profile.scan.maxOutputBytes)])).toString().trim();
    assert.match(id, /^[a-f0-9]{64}$/); await inspect(); proof.id = id;
    child = spawn(profile.docker.tool.path, dockerArguments(['start', '--attach', '--interactive', id]), { windowsHide: true, shell: false, env, stdio: ['pipe', 'pipe', 'pipe'] });
    closedProcess = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); }); closedProcess.catch(() => {});
    child.stdin.on('error', () => {}); let errors = 0;
    child.stderr.on('data', bytes => { errors += bytes.length; if (errors > profile.scan.maxOutputBytes) child.kill(); });
    send('init', { payload: { expected, limits: profile.limits, database: [] } });
    timer = setTimeout(() => { try { send('stop', { reason: 'deadline' }); } catch {} }, Math.max(1, profile.limits.wallMs - (performance.now() - start)));
    let pending = Buffer.alloc(0), total = 0;
    for await (const bytes of child.stdout) {
      total += bytes.length; assert.ok(total <= profile.scan.maxOutputBytes);
      pending = Buffer.concat([pending, bytes]); assert.ok(pending.length <= 2 * 65536);
      let end;
      while ((end = pending.indexOf(10)) !== -1) {
        assert.ok(end < 65536);
        const packet = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(pending.subarray(0, end))); pending = pending.subarray(end + 1);
        assert.equal(packet.v, 1); assert.equal(packet.nonce, runId); assert.equal(packet.seq, ++outerSequence); proof.packets.push(packet);
        if (packet.type === 'ready') { validateJobBoundary(packet.boundary, profile.limits); send('start', { remainingMs: Math.max(1, Math.floor(profile.limits.wallMs - (performance.now() - start))) }); }
        else if (packet.type === 'failure') validateJobNativeFailure(packet.detail);
        else if (packet.type === 'closed') { if (packet.counts) validateJobObserver({ counts: packet.counts, interruption: packet.interruption }); clearTimeout(timer); child.stdin.end(); }
        else assert.ok(['data', 'stop'].includes(packet.type));
      }
    }
    assert.equal(pending.length, 0); proof.process = await closedProcess; proof.stderrBytes = errors;
    proof.terminal = (await inspect()).terminal;
    const closed = proof.packets.find(packet => packet.type === 'closed'), startup = proof.packets.find(packet => packet.type === 'ready');
    assert.ok(startup); assert.ok(closed); assert.equal(closed.allOwnedTasksReaped, true);
    validateJobBoundary(closed.boundary, profile.limits); assert.deepEqual(closed.boundary.networkCounters, startup.boundary.networkCounters);
    const body = Buffer.concat(proof.packets.filter(packet => packet.type === 'data').map(packet => Buffer.from(packet.data, 'base64')));
    if (scenario === 'controller-disappearance') {
      assert.equal(closed.controllerCompleted,true);assert.deepEqual(closed.rootTerminal,{exitCode:null,signal:9});
      assert.equal(closed.stopReason,null);assert.equal(proof.packets.some(packet=>packet.type==='stop'||packet.type==='failure'),false);
      assert.equal(body.length,0);proof.result={rootTerminal:closed.rootTerminal,resourceCause:null,analysisProduced:false};
    } else if (observerErrorScenarios.has(scenario)) {
      const failure = proof.packets.find(packet=>packet.type==='failure');assert.ok(failure);assert.equal(failure.code,'job_native_observer_failed');assert.equal(failure.detail.operation,'ingest');
      assert.equal(closed.controllerCompleted,false);assert.equal(closed.stopReason,null);assert.equal(proof.packets.some(packet=>packet.type==='stop'),false);
      assert.equal(body.length,0,'unsupported observation must not resume the writer to its marker');assert.equal(closed.rootTerminal.signal,9);
      const last=closed.interruption.lastEvent;assert.equal(last.event,0);
      if(scenario==='nonquota-enospc'){assert.equal(last.signal,133);assert.equal(last.entryPhase,'async');}
      else assert.equal(last.signal,scenario==='payload-sigtrap'?5:19);
      proof.result={failure:failure.detail,lastEvent:last};
    } else if (scenario.startsWith('disk-')) {
      const stop = proof.packets.find(packet => packet.type === 'stop');
      assert.equal(closed.controllerCompleted, false); assert.equal(closed.stopReason, 'disk'); assert.ok(stop);
      assert.equal(proof.packets.some(packet => packet.type === 'failure'), false);
      assert.equal(stop.event.kind, 'disk'); assert.equal(stop.event.returned, -28); assert.equal(stop.event.errno, 28); assert.equal(stop.event.stopBeforeNextInstruction, true);
      assert.equal(stop.event.store, scenario === 'disk-work' ? 'work' : scenario === 'disk-tmp' ? 'tmp' : 'shm');
      assert.equal(stop.event.syscall, scenario === 'disk-tmp' ? 'pwrite64' : 'write');
      assert.ok(stop.event.inode > 0 && stop.event.device > 0 && stop.event.mountId > 0);
      assert.equal(body.length, 0, 'writer continuation marker must never reach its nonquota output');
      assert.equal(closed.rootTerminal.signal, 9); proof.result = stop.event;
    } else {
      assert.equal(closed.controllerCompleted, true); assert.deepEqual(closed.rootTerminal, { exitCode: 0, signal: null });
      assert.equal(proof.packets.some(packet => packet.type === 'failure' || packet.type === 'stop'), false);
      proof.result = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)); assert.equal(proof.result.scenario, scenario);
      if (scenario === 'nonleader-exec') assert.ok(closed.counts.execMigrations > 0);
      if (scenario === 'concurrent-writers') assert.ok(closed.counts.fork > 0 && closed.counts.clone > 0);
      if (scenario === 'vfork-exec') assert.ok(closed.counts.vfork > 0 && closed.counts.exec >= 3);
      if (scenario === 'restart-write' || scenario === 'signal-restart-write') {
        assert.equal(proof.result.bytes, proof.result.expectedBytes); assert.ok(closed.counts.interrupt > 0);
        assert.ok(closed.counts.seccomp > closed.counts.writes, 'a restart must re-enter seccomp without counting a completed write');
        assert.equal(proof.result.signals, scenario === 'signal-restart-write' ? 1 : 0);
        if (scenario === 'signal-restart-write') assert.ok(closed.counts.signal > 0);
      }
    }
    proof.state = 'passed';
  } finally {
    if (timer) clearTimeout(timer);
    if (id) { const state = await inspect(); if (state.running) { good(await call(['kill', '--signal', 'KILL', id])); good(await call(['wait', id])); } good(await call(['rm', id]));
      good(await call(['version', '--format', '{{.Server.Version}}'])); assert.notEqual((await call(['inspect', id])).code, 0);
      assert.equal(good(await call(['ps', '-a', '--no-trunc', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}'])).toString().trim(), ''); proof.containerAbsent = true; }
    if (child && child.exitCode === null) child.kill();
    assert.equal(await fs.readFile(path.join(source, 'owned.txt'), 'utf8'), 'self-authored; never executed\n'); proof.sourceUnchanged = true;
    for (const item of publicState) assert.deepEqual(await jobFileIdentity(path.resolve(item.path)), { bytes: item.bytes, sha256: item.sha256 });
    for (const item of assets) assert.deepEqual(await jobFileIdentity(path.join(app, ...item.path.split('/'))), { bytes: item.bytes, sha256: item.sha256 });
    await fs.writeFile(path.join(directory, 'proof.json'), JSON.stringify(proof, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ nativeFixture: scenario, state: proof.state, proof: path.join(directory, 'proof.json'), containerAbsent: proof.containerAbsent }));
  }
  return proof;
}

test('native supervisor: real pinned Go process completion and group exit through Node', { skip: profileInput ? false : 'requires explicit local native-fixture profile; not counted as PASS' }, async () => {
  await runNativeSupervisorFixture(profileInput, 'spawn-exit');
});
test('native supervisor: internal blocking pipe keeps its tracee consumer runnable', { skip: profileInput ? false : 'requires explicit local native-fixture profile; not counted as PASS' }, async () => {
  await runNativeSupervisorFixture(profileInput, 'internal-pipe');
});
for (const name of ['controller-disappearance', 'disk-work', 'disk-tmp', 'disk-shm-high-fd', 'partial-write', 'nonquota-negative', 'population-filter', 'nonleader-exec', 'concurrent-writers', 'vfork-exec', 'fd-reuse', 'restart-write', 'signal-restart-write', ...observerErrorScenarios]) {
  test('native supervisor: ' + name, { skip: profileInput ? false : 'requires explicit local native-fixture profile; not counted as PASS' }, async () => {
    await runNativeSupervisorFixture(profileInput, name);
  });
}
