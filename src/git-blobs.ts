import { SafeError } from './safety.ts';
import type { TreeEntry } from './comparison.ts';

type BlobReference = Pick<TreeEntry, 'oid' | 'bytes'>;
type ReadBatch = (oids: string[], maxOutputBytes: number) => Promise<Buffer>;
// Full SHA1 + " blob " + largest safe integer + two LF bytes.
const framingBytes = 64;

function header(entry: BlobReference): Buffer {
  if (!/^[a-f0-9]{40}$/.test(entry.oid) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0) {
    throw new SafeError('invalid_git_blob_input');
  }
  return Buffer.from(`${entry.oid} blob ${entry.bytes}\n`, 'ascii');
}

function parseBatch<T extends BlobReference>(entries: readonly T[], output: Buffer): { entry: T; content: Buffer }[] {
  const result: { entry: T; content: Buffer }[] = [];
  let offset = 0;
  for (const entry of entries) {
    const expected = header(entry), start = offset + expected.length, end = start + entry.bytes;
    if (!output.subarray(offset, start).equals(expected) || end >= output.length || output[end] !== 10) {
      throw new SafeError('invalid_git_blob_batch');
    }
    result.push({ entry, content: output.subarray(start, end) });
    offset = end + 1;
  }
  if (offset !== output.length) throw new SafeError('invalid_git_blob_batch');
  return result;
}

/** Only complete, ordered, size-bound batches expose raw object bytes. */
export async function* readGitBlobs<T extends BlobReference>(entries: readonly T[], read: ReadBatch,
  maxContentOutputBytes: number, signal?: AbortSignal): AsyncGenerator<{ entry: T; content: Buffer }, void> {
  const maxOutputBytes = maxContentOutputBytes + framingBytes;
  if (!Number.isSafeInteger(maxContentOutputBytes) || maxContentOutputBytes < 1 || !Number.isSafeInteger(maxOutputBytes)) {
    throw new SafeError('invalid_git_blob_input');
  }
  let pending: T[] = [], expectedBytes = 0;
  async function* flush(): AsyncGenerator<{ entry: T; content: Buffer }, void> {
    if (signal?.aborted) throw new SafeError('git_cancelled');
    const verified = parseBatch(pending, await read(pending.map(entry => entry.oid), maxOutputBytes));
    for (const item of verified) {
      if (signal?.aborted) throw new SafeError('git_cancelled');
      yield item;
    }
  }
  for (const entry of entries) {
    const recordBytes = header(entry).length + entry.bytes + 1;
    if (!Number.isSafeInteger(recordBytes) || recordBytes > maxOutputBytes) throw new SafeError('invalid_git_blob_input');
    if (recordBytes > maxOutputBytes - expectedBytes) {
      yield* flush(); pending = []; expectedBytes = 0;
    }
    pending.push(entry); expectedBytes += recordBytes;
  }
  if (pending.length) yield* flush();
}
