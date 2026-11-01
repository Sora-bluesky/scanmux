import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { createJobFrameWriter, JobFrameDecoder, JobRecordAssembler, jobRecordFrames, jobChannelLimits } from '../internal/job-channel.mjs';

const maximum = 65536, retained = maximum * 16;
function channel(sender = 'controller') {
  const options = { nonce: randomUUID(), maxOutputBytes: maximum, retainedBytes: retained, sender };
  return { options, writer: createJobFrameWriter(options), decoder: new JobFrameDecoder(options), assembler: new JobRecordAssembler(maximum) };
}
const hash = input => createHash('sha256').update(input).digest('hex');
function decoded(c, frame) { return c.decoder.push(c.writer.encode(frame).bytes)[0]; }

test('chunked Unicode checkpoint bytes remain exact; no subsequent record is accepted before durable ACK', () => {
  const c = channel(), parts = [Buffer.from('\ufeff日本語🔥\r\n'.repeat(1500)), Buffer.from('{"receipt":true}\n')];
  let accepted;
  for (const frame of jobRecordFrames(c.writer, 1, 'checkpoint', 1, parts)) {
    // Split every encoded frame into small fragments, including multibyte boundaries.
    for (let offset = 0; offset < frame.bytes.length; offset += 127)
      for (const value of c.decoder.push(frame.bytes.subarray(offset, offset + 127))) accepted = c.assembler.accept(value) ?? accepted;
  }
  assert.equal(accepted.type, 'record'); assert.deepEqual(accepted.parts, parts);
  const pending = decoded(c, { type: 'begin', recordId: 2, kind: 'report', slot: 0, sizes: [2], hashes: [hash('{}')] });
  assert.throws(() => c.assembler.accept(pending), /job_protocol_invalid/);
  const valid = channel();
  for (const frame of jobRecordFrames(valid.writer, 1, 'plan', 0, [Buffer.from('{}')]))
    for (const value of valid.decoder.push(frame.bytes)) { const result = valid.assembler.accept(value); if (result) valid.assembler.acknowledged(result.ackSeq); }
  assert.deepEqual(valid.decoder.finish(), { discardedBytes: 0 }); assert.deepEqual(valid.assembler.finish(), { discardedRecord: false });
});

test('nonce/type/extra keys/replay/order/UTF8/base64/size violations latch errors and cannot become an expected stop', () => {
  const mutations = [
    frame => frame.nonce = randomUUID(), frame => frame.type = 'native-event', frame => frame.extra = 'forbidden',
    frame => frame.seq = 2, frame => frame.code = 'ENOSPC untrusted',
  ];
  for (const change of mutations) {
    const c = channel(), frame = { v: 1, nonce: c.options.nonce, seq: 1, type: 'failure', code: 'engine_execution_failed' };
    change(frame); assert.throws(() => c.decoder.push(Buffer.from(JSON.stringify(frame) + '\n')));
    assert.throws(() => c.decoder.finish(true));
  }
  for (const payload of [Buffer.from([255,10]), Buffer.alloc(jobChannelLimits(maximum, retained).maxFrameBytes + 1, 32)]) {
    const c = channel(); assert.throws(() => c.decoder.push(payload)); assert.throws(() => c.decoder.finish(true));
  }
  const repeated = channel(), raw = repeated.writer.encode({ type: 'failure', code: 'engine_execution_failed' }).bytes;
  repeated.decoder.push(raw); assert.throws(() => repeated.decoder.push(raw));
  for (const data of ['Zg=', 'Zh==', '', '!!!!', 'a'.repeat(4 * Math.ceil(maximum / 3))]) {
    const c = channel(); assert.throws(() => c.writer.encode({ type: 'chunk', recordId: 1, data }));
  }
});

test('only an owner-proven stop may discard partial JSON or a partial record; malformed complete records still fail', () => {
  const unknown = channel(); unknown.decoder.push(Buffer.from('{'));
  assert.throws(() => unknown.decoder.finish(false)); assert.throws(() => unknown.decoder.finish(true));
  const expected = channel(); expected.decoder.push(Buffer.from('{'));
  assert.deepEqual(expected.decoder.finish(true), { discardedBytes: 1 });
  assert.throws(() => expected.decoder.push(Buffer.from('}')));
  const partial = channel();
  partial.assembler.accept(decoded(partial, { type: 'begin', recordId: 1, kind: 'plan', slot: 0, sizes: [10], hashes: ['a'.repeat(64)] }));
  assert.deepEqual(partial.assembler.finish(true), { discardedRecord: true });
  const malformed = channel();
  malformed.assembler.accept(decoded(malformed, { type: 'begin', recordId: 1, kind: 'plan', slot: 0, sizes: [2], hashes: [hash('{}')] }));
  malformed.assembler.accept(decoded(malformed, { type: 'chunk', recordId: 1, data: Buffer.from('[]').toString('base64') }));
  assert.throws(() => malformed.assembler.accept(decoded(malformed, { type: 'end', recordId: 1 })));
  assert.throws(() => malformed.assembler.finish(true));
});

test('closed failure facts require their own ACK before further output; native causes cannot enter the controller channel', () => {
  const c = channel(), failure = c.assembler.accept(decoded(c, { type: 'failure', code: 'engine_execution_failed' }));
  assert.deepEqual(failure, { type: 'failure', code: 'engine_execution_failed', ackSeq: 1 });
  c.assembler.acknowledged(1);
  const second = c.assembler.accept(decoded(c, { type: 'failure', code: 'final_output_rejected' }));
  assert.equal(second.ackSeq, 2); c.assembler.acknowledged(2); c.assembler.finish();
  assert.throws(() => c.writer.encode({ type: 'native-event', kind: 'disk' }));
  const host = channel('host');
  const frame = decoded(host, { type: 'ack', ackSeq: 100, disposition: 'retained' }); assert.equal(frame.disposition, 'retained');
  assert.throws(() => host.writer.encode({ type: 'failure', code: 'engine_execution_failed' }));
});
