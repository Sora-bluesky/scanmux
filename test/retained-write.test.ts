import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { retainedCatalog, encodeRetainedWrite, validateRetainedWriteResult, validateRetainedAllocationStop,
  type RetainedPolicy, type RetainedWriteResult, type RetainedAllocationStop } from '../src/retained-write.ts';

test('retained data catalog closes every supported record and reserves terminal evidence', () => {
  const catalog = retainedCatalog(8193);
  assert.equal(catalog.length, 19);
  assert.equal(new Set(catalog.map(item => item.name)).size, 19);
  assert.equal(catalog.filter(item => item.reserved).length, 10);
  assert.equal(catalog.find(item => item.name === 'host-job-intent.json')?.maximum, 65536);
  for (const name of ['host-job-failure.json', 'host-job-retained.json']) assert.equal(catalog.find(item => item.name === name)?.maximum, 4096);
  for (const name of ['report.json', 'delegated-job.json', 'host-job.json', 'owner.json']) assert.equal(catalog.find(item => item.name === name)?.reserved, true);
  assert.equal(catalog.find(item => item.name === 'job-plan.json')?.reserved, false);
  for (let n = 1; n <= 4; n++) for (const kind of ['checkpoint', 'commit']) assert.equal(catalog.find(item => item.name === `checkpoints/${kind}-${n}.json`)?.reserved, false);
});

test('retained request preserves exact bytes and describes a whole checkpoint pair', () => {
  const body = Buffer.from('{"body":"é"}\n', 'utf8'), receipt = Buffer.from('{"receipt":true}\n');
  const encoded = encodeRetainedWrite([{ name: 'checkpoints/checkpoint-2.json', bytes: body }, { name: 'checkpoints/commit-2.json', bytes: receipt }], 8193);
  const newline = encoded.indexOf(10), header = JSON.parse(encoded.subarray(0, newline).toString('ascii'));
  assert.equal(header.schema, 'scanmux.retained-write-request/v1');
  assert.equal(header.kind, 'checkpoint'); assert.equal(header.sequence, 2);
  assert.deepEqual(header.parts.map((part: { bytes: number; sha256: string }) => [part.bytes, part.sha256]), [body, receipt].map(bytes => [bytes.length, createHash('sha256').update(bytes).digest('hex')]));
  assert.deepEqual(encoded.subarray(newline + 1), Buffer.concat([body, receipt]));
  assert.equal(header.parts[0].slot, retainedCatalog(8193).find(item => item.name === 'checkpoints/checkpoint-2.json')?.slot);
  assert.equal(header.parts[1].slot, retainedCatalog(8193).find(item => item.name === 'checkpoints/commit-2.json')?.slot);
});

test('native write framing rejects alternate names, broken pairs, duplicate and excess records before transport', () => {
  const bytes = Buffer.from('{}\n'), part = (name: string) => ({ name, bytes });
  for (const parts of [[], [part('../report.json')], [part('report.json:alternate')], [part('job.json')], [part('host-job-intent.json')], [part('host-job-retained.json')],
    [part('checkpoints/checkpoint-1.json')], [part('checkpoints/commit-1.json')],
    [part('checkpoints/checkpoint-1.json'), part('checkpoints/commit-2.json')],
    [part('checkpoints/commit-1.json'), part('checkpoints/checkpoint-1.json')],
    [part('report.json'), part('report.json')], [part('report.json'), part('host-job.json')],
    [part('checkpoints/checkpoint-5.json'), part('checkpoints/commit-5.json')]]) assert.throws(() => encodeRetainedWrite(parts, 8193));
  assert.throws(() => encodeRetainedWrite([{ name: 'report.json', bytes: Buffer.alloc(8194) }], 8193));
  assert.throws(() => encodeRetainedWrite([{ name: 'host-job-failure.json', bytes: Buffer.alloc(4097) }], 8193));
  assert.throws(() => encodeRetainedWrite([{ name: 'report.json', bytes: Buffer.alloc(0) }], 8193));
  for (const maximum of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER]) assert.throws(() => retainedCatalog(maximum));
});

test('client-owned single-record slots carry literal numeric identities; native stop witnesses stay native-owned', () => {
  for (const item of retainedCatalog(8193).filter(item => !['host-job-intent.json', 'host-job-retained.json'].includes(item.name) && !item.name.startsWith('checkpoints/'))) {
    const encoded = encodeRetainedWrite([{ name: item.name, bytes: Buffer.from('{}\n') }], 8193), header = JSON.parse(encoded.subarray(0, encoded.indexOf(10)).toString('ascii'));
    assert.equal(header.kind, 'single'); assert.equal(header.sequence, 0); assert.equal(header.parts.length, 1); assert.equal(header.parts[0].slot, item.slot);
  }
});

interface ReplyFixture { name: string; policy: RetainedPolicy; result: RetainedWriteResult; parts: { name: string; text?: string; zeroBytes?: number }[] }
async function replies(): Promise<ReplyFixture[]> { return JSON.parse(await readFile(new URL('./fixtures/retained-replies.json', import.meta.url), 'utf8')).cases; }
const buffers = (fixture: ReplyFixture) => fixture.parts.map(part => ({ name: part.name, bytes: part.text === undefined ? Buffer.alloc(part.zeroBytes!) : Buffer.from(part.text, 'utf8') }));

test('native replies must match measured allocation, whole transaction, immutable prior files and separate witness', async () => {
  for (const fixture of await replies()) assert.deepEqual(validateRetainedWriteResult(fixture.result, fixture.policy, buffers(fixture)), fixture.result);
});

test('forged native success, omitted counters, unit confusion, wrong ownership and record substitution never validate', async () => {
  for (const fixture of await replies()) {
    const changes: ((result: RetainedWriteResult) => void)[] = [
      value => value.jobId = '22222222-2222-4222-8222-222222222222',
      value => value.intentSha256 = 'b'.repeat(64),
      value => value.slots[0] = 18,
      value => value.proposedAllocatedBytes++,
      value => value.availableIntermediateBytes++,
      value => value.before.allocatedBytes++,
      value => value.after.reservedBytes++,
      value => value.after.files[0].bytes++,
      value => value.after.files[0].allocatedBytes++,
      value => value.after.files.reverse(),
      value => value.after.files.push(structuredClone(value.after.files[0])),
      value => value.after.files.shift(),
      value => Object.assign(value, { unexpected: true }),
      value => { delete (value.before as Partial<RetainedWriteResult['before']>).allocatedBytes; },
      value => { value.result = value.result === 'committed' ? 'retained_allocated_limit' : 'committed'; },
    ];
    for (const change of changes) { const copy = structuredClone(fixture.result); change(copy); assert.throws(() => validateRetainedWriteResult(copy, fixture.policy, buffers(fixture))); }
  }
});

test('replies cannot substitute logical lengths for physical bytes or create refused payload slots', async () => {
  const fixture = (await replies()).find(item => item.name === 'allocation-refusal')!;
  const logical = structuredClone(fixture.result); logical.proposedAllocatedBytes = buffers(fixture).reduce((sum, part) => sum + part.bytes.length, 0);
  assert.throws(() => validateRetainedWriteResult(logical, fixture.policy, buffers(fixture)));
  const missing = structuredClone(fixture.result); missing.after.files = missing.after.files.filter(file => file.slot !== 2);
  assert.throws(() => validateRetainedWriteResult(missing, fixture.policy, buffers(fixture)));
  const substituted = structuredClone(fixture.result); substituted.after.files.find(file => file.slot === 2)!.slot = fixture.result.slots[0];
  assert.throws(() => validateRetainedWriteResult(substituted, fixture.policy, buffers(fixture)));
  for (const policy of [{ ...fixture.policy, allocatedBytes: 1 }, { ...fixture.policy, clusterBytes: 0 }, { ...fixture.policy, allocatedBytes: Number.MAX_SAFE_INTEGER }]) {
    assert.throws(() => validateRetainedWriteResult(fixture.result, policy, buffers(fixture)));
  }
});

test('saved allocation stops preserve physical units, complete refused pairs and the independently reserved witness', async () => {
  const fixture = (await replies()).find(item => item.name === 'allocation-refusal')!;
  const stop: RetainedAllocationStop = { schema: 'scanmux.retained-allocation-stop/v1', jobId: fixture.policy.jobId, intentSha256: fixture.policy.intentSha256,
    parts: buffers(fixture).map((part, index) => ({ slot: fixture.result.slots[index], bytes: part.bytes.length })),
    proposedAllocatedBytes: fixture.result.proposedAllocatedBytes, availableIntermediateBytes: fixture.result.availableIntermediateBytes,
    actualAllocatedBytes: fixture.result.before.allocatedBytes, reservedBytes: fixture.result.before.reservedBytes,
    allocatedLimit: fixture.policy.allocatedBytes, clusterBytes: fixture.policy.clusterBytes };
  assert.deepEqual(validateRetainedAllocationStop(stop, fixture.policy, fixture.result.after), stop);
  for (const change of [
    (value: RetainedAllocationStop) => { value.jobId = '22222222-2222-4222-8222-222222222222'; },
    (value: RetainedAllocationStop) => { value.intentSha256 = 'b'.repeat(64); },
    (value: RetainedAllocationStop) => { value.parts[0].slot = 9; },
    (value: RetainedAllocationStop) => { value.parts.pop(); },
    (value: RetainedAllocationStop) => { value.parts.reverse(); },
    (value: RetainedAllocationStop) => { value.parts[0].bytes = 0; },
    (value: RetainedAllocationStop) => { value.proposedAllocatedBytes = value.parts.reduce((sum, part) => sum + part.bytes, 0); },
    (value: RetainedAllocationStop) => { value.availableIntermediateBytes++; },
    (value: RetainedAllocationStop) => { value.actualAllocatedBytes++; },
    (value: RetainedAllocationStop) => { value.reservedBytes++; },
    (value: RetainedAllocationStop) => { value.allocatedLimit += 4096; },
    (value: RetainedAllocationStop) => { value.clusterBytes *= 2; },
    (value: RetainedAllocationStop) => { Object.assign(value, { directoryQuotaEnforced: true }); },
  ]) { const copy = structuredClone(stop); change(copy); assert.throws(() => validateRetainedAllocationStop(copy, fixture.policy, fixture.result.after)); }
  const missing = structuredClone(fixture.result.after); missing.files = missing.files.filter(file => file.slot !== 2);
  assert.throws(() => validateRetainedAllocationStop(stop, fixture.policy, missing));
  const admitted = structuredClone(fixture.result.after); admitted.files.find(file => file.slot === 2)!.slot = stop.parts[0].slot;
  assert.throws(() => validateRetainedAllocationStop(stop, fixture.policy, admitted));
});
