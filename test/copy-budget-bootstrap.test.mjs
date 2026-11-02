import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { withCopyBudget, scopedCopyBudget } from '../src/copy-budget.ts';
import { hash } from '../src/safety.ts';
import { stripTypeScriptTypes } from 'node:module';

// Run the actual init parser on Windows too, without loading Linux ptrace or starting a child.
const parser = String.raw`
import ast,base64,json,sys
source=ast.parse(open('internal/linux-job-supervisor.py',encoding='utf-8').read())
names={'require','exact','integer'}
nodes=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name in names]
pump=next(n for n in source.body if isinstance(n,ast.ClassDef) and n.name=='Pump')
pump.body=[n for n in pump.body if isinstance(n,ast.FunctionDef) and n.name=='host_packet']
nodes.append(pump)
namespace={'json':json,'base64':base64,'MAX_INTEGER':9007199254740991}
exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-init-parser>','exec'),namespace)
value=json.loads(sys.argv[1]); obj=namespace['Pump'].__new__(namespace['Pump'])
obj.nonce='fixture'; obj.host_sequence=0; obj.initialized=False; obj.maximum=1024
obj.host_packet(json.dumps({'v':1,'nonce':'fixture','seq':1,'type':'init','payload':value}).encode())
for _ in range(int(sys.argv[2])):
 obj.admitted=True; obj.cleanup=False; obj.max_control_line=65536; obj.child_input=bytearray()
 obj.host_packet(json.dumps({'v':1,'nonce':'fixture','seq':obj.host_sequence+1,'type':'input','data':'eA=='}).encode())
if sys.argv[3]=='forward':
 from types import SimpleNamespace
 tracer=next(n for n in source.body if isinstance(n,ast.ClassDef) and n.name=='Tracer')
 launch=next(n for n in tracer.body if isinstance(n,ast.FunctionDef) and n.name=='launch')
 first=next(i for i,n in enumerate(launch.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='initial' for t in n.targets))
 last=next(i for i,n in enumerate(launch.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='encoded' for t in n.targets))
 namespace['self']=SimpleNamespace(pump=SimpleNamespace(init=obj.init,nonce='fixture'))
 exec(compile(ast.Module(body=launch.body[first:last+1],type_ignores=[]),'<actual-launch-payload>','exec'),namespace)
 print(namespace['encoded'].decode().strip())
else:
 print(json.dumps(obj.init))
`;
function parse(remaining, maximum, packets = 0, forward = false) {
  const input = { expected: { jobId: 'fixture', config: { maxOutputBytes: 1024 } }, database: [],
    limits: { ...Object.fromEntries(['cpuCount','memoryBytes','tmpBytes','workBytes','shmBytes','pids','wallMs','cleanupTimeoutMs','retainedBytes'].map(k => [k, 1])), wallMs: 20000, cleanupTimeoutMs: 10000 } };
  if (remaining !== undefined) input.copyBudgetBytes = remaining;
  if (maximum !== undefined) input.maxJobDiskBytes = maximum;
  return spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-B', '-c', parser, JSON.stringify(input), String(packets), forward ? 'forward' : 'init'], { encoding: 'utf8', windowsHide: true });
}
test('copy budget bootstrap: accepts zero and safe remaining bytes without changing absent-key packets', () => {
  for (const remaining of [undefined, 0, 1, Number.MAX_SAFE_INTEGER]) {
    const result = parse(remaining); assert.equal(result.status, 0, result.stderr);
    const value = JSON.parse(result.stdout);
    assert.equal(Object.hasOwn(value, 'copyBudgetBytes'), remaining !== undefined);
    assert.equal(value.copyBudgetBytes, remaining);
  }
});
test('copy budget bootstrap: rejects negative, fractional, unsafe and nonnumeric allowances', () => {
  // Positive control prevents parser/setup errors from masquerading as validation.
  assert.equal(parse(0).status, 0);
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, '4', true]) assert.notEqual(parse(value).status, 0);
});

const controllerPacket = (remaining, maximum, operation) => ({ schema: operation ? 'scanmux.reproduction-controller-init/v1' : 'scanmux.job-controller-init/v1', nonce: 'fixture', expected: {}, limits: {},
  ...(operation ? { operation } : {}),
  ...(remaining === undefined ? {} : { copyBudgetBytes: remaining }), ...(maximum === undefined ? {} : { maxJobDiskBytes: maximum }) });
function controller(input, parseOnly = false) {
  return spawnSync(process.execPath, ['test/fixtures/copy-budget-payload.mjs', ...(parseOnly ? ['--parse'] : [])],
    { input: JSON.stringify(input), encoding: 'utf8', windowsHide: true });
}
test('copy budget controller init: absent, zero and valid safe allowances', () => {
  for (const value of [undefined, 0, 4, Number.MAX_SAFE_INTEGER]) {
    const result = controller({ init: controllerPacket(value) }, true);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { present: value !== undefined, ...(value === undefined ? {} : { remaining: value }) });
  }
});
test('copy budget controller init: invalid allowances are refused', () => {
  assert.equal(controller({ init: controllerPacket(0) }, true).status, 0);
  for (const value of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, '4', true]) {
    const result = controller({ init: controllerPacket(value) }, true);
    assert.equal(result.status, 4, result.stderr); assert.deepEqual(JSON.parse(result.stdout), { error: 'invalid_init' });
  }
});

test('measured disk bootstrap: the supervisor and controller accept only positive safe top-level limits', () => {
  for (const maximum of [1, Number.MAX_SAFE_INTEGER]) {
    const supervisor = parse(0, maximum); assert.equal(supervisor.status, 0, supervisor.stderr);
    assert.equal(JSON.parse(supervisor.stdout).maxJobDiskBytes, maximum);
    const result = controller({ init: controllerPacket(0, maximum) }, true);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { present: true, remaining: 0, maxJobDiskBytes: maximum });
  }
  for (const maximum of [0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, '4', true]) {
    assert.notEqual(parse(0, maximum).status, 0);
    assert.equal(controller({ init: controllerPacket(0, maximum) }, true).status, 4);
  }
});

test('measured disk framing: telemetry crosses record ACK waits and has a wall-time-derived bound', async () => {
  const channel = await import('../internal/job-channel.mjs');
  assert.equal(typeof channel.jobDiskSampleLimit, 'function');
  const samples = channel.jobDiskSampleLimit({ wallMs: 20000, cleanupTimeoutMs: 10000 });
  const options = { nonce: '11111111-1111-4111-8111-111111111111', maxOutputBytes: 1, retainedBytes: 2, diskSampleLimit: samples };
  const writer = channel.createJobFrameWriter({ ...options, sender: 'controller' });
  const decoder = new channel.JobFrameDecoder({ ...options, sender: 'controller' });
  for (let i = 0; i < samples; i++) {
    const frame = decoder.push(writer.encode({ type: 'disk-sample', bytes: i === 0 ? null : String(i) }).bytes)[0];
    assert.equal(frame.type, 'disk-sample');
  }
  assert.throws(() => writer.encode({ type: 'disk-sample', bytes: '1' }));
  const oldWriter = channel.createJobFrameWriter({ ...options, diskSampleLimit: undefined, sender: 'controller' });
  assert.throws(() => oldWriter.encode({ type: 'disk-sample', bytes: '0' }));
  const host = channel.createJobFrameWriter({ ...options, sender: 'host' });
  const incoming = new channel.JobFrameDecoder({ ...options, sender: 'host' });
  assert.equal(incoming.push(host.encode({ type: 'disk-stop', cause: 'job_disk_measured_limit' }).bytes)[0].cause, 'job_disk_measured_limit');
  assert.equal(incoming.push(host.encode({ type: 'disk-ack', sampleSeq: 1, cause: null }).bytes)[0].type, 'disk-ack');
  for (const bytes of ['-1', '01', '1.1', 1, '', '9'.repeat(41)]) {
    const invalid = channel.createJobFrameWriter({ ...options, sender: 'controller' });
    assert.throws(() => invalid.encode({ type: 'disk-sample', bytes }));
  }
  assert.deepEqual(channel.jobChannelLimits(1, 2), channel.jobChannelLimits(1, 2, undefined));
});

test('measured disk supervisor: launch forwards only runtime fields and admits bounded sample replies beyond sixteen packets', async () => {
  const { jobDiskSampleLimit } = await import('../internal/job-channel.mjs');
  const samples = jobDiskSampleLimit({ wallMs: 20000, cleanupTimeoutMs: 10000 });
  assert.equal(parse(undefined, undefined, 15).status, 0);
  assert.notEqual(parse(undefined, undefined, 16).status, 0);
  assert.equal(parse(0, 1, 15 + samples + 1).status, 0);
  assert.notEqual(parse(0, 1, 16 + samples + 1).status, 0);
  for (const maximum of [undefined, 1]) {
    const result = parse(0, maximum, 0, true); assert.equal(result.status, 0, result.stderr);
    const packet = JSON.parse(result.stdout);
    assert.equal(packet.schema, 'scanmux.job-controller-init/v1');
    assert.equal(packet.copyBudgetBytes, 0); assert.equal(packet.maxJobDiskBytes, maximum);
    assert.equal(Object.hasOwn(packet.expected.config, 'maxJobDiskBytes'), false);
    if (maximum === undefined) assert.equal(Object.hasOwn(packet, 'maxJobDiskBytes'), false);
  }
});

const reproduction = { kind: 'reproduction', side: 'snapshot', commit: 'a'.repeat(40), sourceSnapshot: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), snapshotHash: 'c'.repeat(64) },
  finding: { engine: 'codex-security', fingerprint: 'd'.repeat(64) }, sourceReportSha256: 'e'.repeat(64), testDirectory: 'tests/repro', mode: { kind: 'snapshot', requirement: 'supporting' }, expectedTest: null };
for (const operation of [undefined, reproduction]) test(`copy budget bootstrap (${operation ? 'reproduce' : 'scan'}): H + Z copies across processes; H + Z - 1 refuses in the payload`, async t => {
  const directory = await fs.mkdtemp(path.join(tmpdir(), 'copy-budget-process-boundary-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const host = path.join(directory, 'host'), source = path.join(directory, 'db'), target = path.join(directory, 'target');
  await fs.writeFile(host, 'host'); await fs.mkdir(target); await fs.mkdir(path.join(source, 'osv-scalibr', 'npm'), { recursive: true });
  await fs.writeFile(path.join(source, 'osv-scalibr', 'npm', 'all.zip'), 'zip!');
  const H = (await fs.stat(host)).size, Z = 4;
  // Use the actual host bootstrap producer, including its remainingBytes expression.
  const code = await fs.readFile('src/job-runner.ts', 'utf8'), start = code.indexOf('const bootstrap = { expected:');
  const producer = Function('expected', 'comparison', 'profile', 'database', 'scopedCopyBudget', 'operation',
    stripTypeScriptTypes(code.slice(start, code.indexOf('requireValue(Buffer.byteLength(JSON.stringify(bootstrap))', start))) + '\nreturn bootstrap;');
  for (const maximum of [H + Z, H + Z - 1]) await withCopyBudget(maximum, async () => {
    await scopedCopyBudget().copy(host, host + maximum);
    const payload = producer({}, undefined, { limits: {} }, [], scopedCopyBudget, operation);
    assert.equal(Object.hasOwn(payload, 'operation'), operation !== undefined); assert.deepEqual(payload.operation, operation);
    assert.equal(payload.copyBudgetBytes, maximum - H);
    const workspace = path.join(directory, 'work-' + maximum); await fs.mkdir(workspace);
    const result = controller({ init: { ...controllerPacket(payload.copyBudgetBytes, undefined, payload.operation), expected: payload.expected, limits: payload.limits },
      options: { source, workspace, target } });
    assert.equal(result.status, maximum === H + Z ? 0 : 3, result.stderr);
    const output = JSON.parse(result.stdout), destination = path.join(workspace, 'osv-database', 'osv-scalibr', 'npm', 'all.zip');
    if (maximum === H + Z) {
      assert.deepEqual(output, { bytes: Z, sha256: hash('zip!'), reserved: Z }); assert.equal(await fs.readFile(destination, 'utf8'), 'zip!');
    } else {
      assert.deepEqual(output, { error: 'job_disk_copy_limit' }); await assert.rejects(fs.stat(destination), { code: 'ENOENT' });
    }
    assert.equal(scopedCopyBudget().reservedBytes, H);
  });
});
