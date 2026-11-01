import { createHash } from 'node:crypto';

export const jobFailureCodes = Object.freeze([
  'engine_execution_failed', 'controller_integrity_failure', 'checkpoint_output_rejected',
  'plan_failed', 'plan_output_rejected', 'final_output_rejected', 'controller_failed',
]);
const positive = value => Number.isSafeInteger(value) && value > 0;
const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const requireValue = value => { if (!value) throw Error('job_protocol_invalid'); };
const sha256 = value => createHash('sha256').update(value).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const common = ['v', 'nonce', 'seq', 'type'];
const diskCause = value => ['job_disk_measured_limit', 'job_disk_observation_unverified'].includes(value);

export function jobDiskSampleLimit({ wallMs, cleanupTimeoutMs }) {
  requireValue(positive(wallMs) && wallMs <= 2147483647 && positive(cleanupTimeoutMs) && cleanupTimeoutMs <= 2147483647);
  // Periodic samples plus the initial/four engine-end observations and failure slack.
  return Math.ceil((wallMs + cleanupTimeoutMs) / 100) + 8;
}

export function jobChannelLimits(maxOutputBytes, retainedBytes, diskSampleLimit = 0) {
  requireValue(positive(maxOutputBytes) && maxOutputBytes <= 2147483647 && positive(retainedBytes) && retainedBytes >= 2 * maxOutputBytes);
  requireValue(Number.isSafeInteger(diskSampleLimit) && diskSampleLimit >= 0);
  // Ten payload files: one plan, four body/receipt pairs, and one final report.
  const files = 10, records = 6, chunkBytes = Math.min(16384, maxOutputBytes);
  const payloadFrames = files * Math.ceil(maxOutputBytes / chunkBytes) + 2 * records + jobFailureCodes.length;
  const maxFrames = payloadFrames + diskSampleLimit + (diskSampleLimit ? 1 : 0);
  // The longest fixed schema fits in 1024 bytes excluding a canonical base64 chunk.
  const maxFrameBytes = 1024 + 4 * Math.ceil(chunkBytes / 3);
  const maxBytes = maxFrameBytes * payloadFrames + (diskSampleLimit ? 1024 * (diskSampleLimit + 1) : 0);
  requireValue(positive(maxFrames) && positive(maxBytes));
  return { chunkBytes, maxFrameBytes, maxFrames, maxBytes };
}

function validateFrame(frame, nonce, sender, maximum, chunkBytes, diskSampleLimit) {
  requireValue(plain(frame) && frame.v === 1 && frame.nonce === nonce && positive(frame.seq));
  if (sender === 'host') {
    if (diskSampleLimit && frame.type === 'disk-stop') {
      requireValue(exact(frame, [...common, 'cause']) && diskCause(frame.cause)); return;
    }
    if (diskSampleLimit && frame.type === 'disk-ack') {
      requireValue(exact(frame, [...common, 'sampleSeq', 'cause']) && positive(frame.sampleSeq)
        && (frame.cause === null || diskCause(frame.cause))); return;
    }
    requireValue(exact(frame, [...common, 'ackSeq', 'disposition']) && frame.type === 'ack' && positive(frame.ackSeq)
      && ['accepted', 'retained', 'deadline', 'cancelled'].includes(frame.disposition));
    return;
  }
  switch (frame.type) {
    case 'disk-sample':
      requireValue(diskSampleLimit > 0 && exact(frame, [...common, 'bytes'])
        && (frame.bytes === null || typeof frame.bytes === 'string' && /^(0|[1-9][0-9]{0,39})$/.test(frame.bytes))); return;
    case 'begin':
      requireValue(exact(frame, [...common, 'recordId', 'kind', 'slot', 'sizes', 'hashes']) && positive(frame.recordId)
        && ['plan', 'checkpoint', 'report'].includes(frame.kind) && Number.isSafeInteger(frame.slot)
        && (frame.kind === 'checkpoint' ? frame.slot >= 1 && frame.slot <= 4 : frame.slot === 0)
        && Array.isArray(frame.sizes) && frame.sizes.length === (frame.kind === 'checkpoint' ? 2 : 1)
        && frame.sizes.every(size => positive(size) && size <= maximum)
        && Array.isArray(frame.hashes) && frame.hashes.length === frame.sizes.length && frame.hashes.every(digest));
      return;
    case 'chunk':
      requireValue(exact(frame, [...common, 'recordId', 'data']) && positive(frame.recordId) && typeof frame.data === 'string'
        && frame.data.length <= 4 * Math.ceil(chunkBytes / 3) && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(frame.data)
        && frame.data.length > 0 && Buffer.from(frame.data, 'base64').toString('base64') === frame.data
        && Buffer.from(frame.data, 'base64').length <= chunkBytes);
      return;
    case 'end': requireValue(exact(frame, [...common, 'recordId']) && positive(frame.recordId)); return;
    case 'failure': requireValue(exact(frame, [...common, 'code']) && jobFailureCodes.includes(frame.code)); return;
    default: throw Error('job_protocol_invalid');
  }
}

export function createJobFrameWriter({ nonce, maxOutputBytes, retainedBytes, sender, diskSampleLimit = 0 }) {
  requireValue(typeof nonce === 'string' && /^[a-f0-9-]{36}$/.test(nonce) && ['controller', 'host'].includes(sender));
  const limits = jobChannelLimits(maxOutputBytes, retainedBytes, diskSampleLimit);
  let sequence = 0, total = 0, samples = 0, stops = 0;
  return { limits, encode(fields) {
    const frame = { v: 1, nonce, seq: sequence + 1, ...fields };
    validateFrame(frame, nonce, sender, maxOutputBytes, limits.chunkBytes, diskSampleLimit);
    if (frame.type === 'disk-sample' || frame.type === 'disk-ack') requireValue(++samples <= diskSampleLimit);
    if (frame.type === 'disk-stop') requireValue(++stops <= 1);
    requireValue(frame.seq === sequence + 1);
    const bytes = Buffer.from(JSON.stringify(frame) + '\n');
    requireValue(bytes.length <= limits.maxFrameBytes && sequence < limits.maxFrames && total + bytes.length <= limits.maxBytes);
    sequence++; total += bytes.length;
    return { bytes, seq: sequence };
  } };
}

/** A bounded incremental parser. Its uncompleted tail can only be discarded by an owner-proven stop. */
export class JobFrameDecoder {
  constructor({ nonce, maxOutputBytes, retainedBytes, sender, diskSampleLimit = 0 }) {
    requireValue(typeof nonce === 'string' && /^[a-f0-9-]{36}$/.test(nonce) && ['controller', 'host'].includes(sender));
    this.nonce = nonce; this.maximum = maxOutputBytes; this.sender = sender;
    this.diskSampleLimit = diskSampleLimit; this.samples = 0; this.stops = 0;
    this.limits = jobChannelLimits(maxOutputBytes, retainedBytes, diskSampleLimit);
    this.pending = Buffer.alloc(0); this.sequence = 0; this.total = 0; this.failed = false; this.ended = false;
  }
  push(input) {
    try {
      requireValue(!this.failed && !this.ended && Buffer.isBuffer(input));
      this.total += input.length;
      requireValue(this.total <= this.limits.maxBytes);
      const frames = [];
      let offset = 0;
      while (offset < input.length) {
        const newline = input.indexOf(10, offset), end = newline === -1 ? input.length : newline + 1;
        requireValue(this.pending.length + end - offset <= this.limits.maxFrameBytes);
        this.pending = Buffer.concat([this.pending, input.subarray(offset, end)]);
        offset = end;
        if (newline === -1) break;
        const frame = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(this.pending));
        validateFrame(frame, this.nonce, this.sender, this.maximum, this.limits.chunkBytes, this.diskSampleLimit);
        if (frame.type === 'disk-sample' || frame.type === 'disk-ack') requireValue(++this.samples <= this.diskSampleLimit);
        if (frame.type === 'disk-stop') requireValue(++this.stops <= 1);
        requireValue(frame.seq === this.sequence + 1 && frame.seq <= this.limits.maxFrames);
        this.sequence++; this.pending = Buffer.alloc(0); frames.push(frame);
      }
      return frames;
    } catch { this.failed = true; throw Error('job_protocol_invalid'); }
  }
  finish(expectedOwnerStop = false) {
    this.ended = true;
    if (this.failed || this.pending.length !== 0 && expectedOwnerStop !== true) { this.failed = true; throw Error('job_protocol_invalid'); }
    const discardedBytes = this.pending.length;
    this.pending = Buffer.alloc(0);
    return { discardedBytes };
  }
}

export function* jobRecordFrames(writer, recordId, kind, slot, parts) {
  requireValue(positive(recordId) && Array.isArray(parts) && parts.every(Buffer.isBuffer));
  yield writer.encode({ type: 'begin', recordId, kind, slot, sizes: parts.map(part => part.length), hashes: parts.map(sha256) });
  // Parts remain distinct; a checkpoint receipt is not spliced into report JSON.
  for (const part of parts) for (let offset = 0; offset < part.length; offset += writer.limits.chunkBytes)
    yield writer.encode({ type: 'chunk', recordId, data: part.subarray(offset, offset + writer.limits.chunkBytes).toString('base64') });
  yield writer.encode({ type: 'end', recordId });
}

export class JobRecordAssembler {
  constructor(maxOutputBytes) {
    requireValue(positive(maxOutputBytes));
    this.maximum = maxOutputBytes; this.active = null; this.pendingAck = null; this.lastRecord = 0; this.failed = false; this.ended = false;
  }
  accept(frame) {
    try {
      requireValue(!this.failed && !this.ended && this.pendingAck === null);
      if (frame.type === 'failure') {
        requireValue(this.active === null && jobFailureCodes.includes(frame.code));
        this.pendingAck = frame.seq;
        return { type: 'failure', code: frame.code, ackSeq: frame.seq };
      }
      if (frame.type === 'begin') {
        requireValue(this.active === null && frame.recordId === this.lastRecord + 1);
        this.active = { ...frame, chunks: [], received: 0 };
        return null;
      }
      const active = this.active;
      requireValue(active !== null && frame.recordId === active.recordId);
      if (frame.type === 'chunk') {
        const chunk = Buffer.from(frame.data, 'base64');
        requireValue(active.received + chunk.length <= active.sizes.reduce((a, b) => a + b, 0));
        active.received += chunk.length; active.chunks.push(chunk);
        return null;
      }
      requireValue(frame.type === 'end' && active.received === active.sizes.reduce((a, b) => a + b, 0));
      const joined = Buffer.concat(active.chunks, active.received), parts = [];
      let offset = 0;
      for (let i = 0; i < active.sizes.length; i++) {
        const part = joined.subarray(offset, offset + active.sizes[i]); offset += active.sizes[i];
        requireValue(part.length <= this.maximum && sha256(part) === active.hashes[i]);
        new TextDecoder('utf-8', { fatal: true }).decode(part);
        parts.push(part);
      }
      this.active = null; this.pendingAck = frame.seq; this.lastRecord = active.recordId;
      return { type: 'record', kind: active.kind, slot: active.slot, parts, ackSeq: frame.seq };
    } catch { this.failed = true; throw Error('job_protocol_invalid'); }
  }
  acknowledged(sequence) {
    if (this.failed || this.ended || this.pendingAck !== sequence) { this.failed = true; throw Error('job_protocol_invalid'); }
    this.pendingAck = null;
  }
  finish(expectedOwnerStop = false) {
    this.ended = true;
    if (this.failed || expectedOwnerStop !== true && (this.active !== null || this.pendingAck !== null)) { this.failed = true; throw Error('job_protocol_invalid'); }
    const discardedRecord = this.active !== null || this.pendingAck !== null;
    this.active = null; this.pendingAck = null;
    return { discardedRecord };
  }
}
