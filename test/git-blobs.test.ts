import test from 'node:test';
import assert from 'node:assert/strict';
import { readGitBlobs } from '../src/git-blobs.ts';
import { SafeError } from '../src/safety.ts';

const one = { oid: '1'.repeat(40), bytes: 1 }, two = { oid: '2'.repeat(40), bytes: 1 };
const first = Buffer.from(`${one.oid} blob 1\nx\n`), second = Buffer.from(`${two.oid} blob 1\ny\n`);
async function collect(entries: Parameters<typeof readGitBlobs>[0], output: Buffer, limit = 1024) {
  const accepted: Buffer[] = [];
  for await (const item of readGitBlobs(entries, async () => output, limit)) accepted.push(item.content);
  return accepted;
}

test('raw Git batch preserves empty, newline, NUL, non-UTF8 and repeated objects in order', async () => {
  const empty = { oid: '0'.repeat(40), bytes: 0 }, body = Buffer.from([0xc3, 0xa9, 10, 0, 0xff]), rich = { oid: 'a'.repeat(40), bytes: body.length };
  const output = Buffer.concat([Buffer.from(`${empty.oid} blob 0\n\n${rich.oid} blob 5\n`), body, Buffer.from(`\n${rich.oid} blob 5\n`), body, Buffer.from('\n')]);
  const entries = [empty, rich, rich], observed = [];
  for await (const item of readGitBlobs(entries, async (oids, bound) => {
    assert.deepEqual(oids, entries.map(e => e.oid)); assert.equal(bound, 1088); return output;
  }, 1024)) observed.push(item);
  assert.deepEqual(observed.map(x => x.content), [Buffer.alloc(0), body, body]);
  assert.deepEqual(observed.map(x => x.entry), entries);
  let calls = 0; for await (const ignored of readGitBlobs([], async () => { calls++; return Buffer.alloc(0); }, 1)) assert.fail(String(ignored));
  assert.equal(calls, 0);
});

test('batch framing is bounded at the exact sum and admits a max-size source blob', async () => {
  const entries = [one, two, one], calls: string[][] = [], observed = [];
  for await (const item of readGitBlobs(entries, async (oids, bound) => {
    calls.push(oids); assert.equal(bound, 100);
    return Buffer.concat(oids.map(oid => oid === one.oid ? first : second));
  }, 36)) observed.push(item.content.toString());
  assert.deepEqual(calls, [[one.oid, two.oid], [one.oid]]); assert.deepEqual(observed, ['x', 'y', 'x']);
  const body = Buffer.alloc(8192, 120), large = { oid: '3'.repeat(40), bytes: body.length };
  assert.deepEqual(await collect([large], Buffer.concat([Buffer.from(`${large.oid} blob 8192\n`), body, Buffer.from('\n')]), body.length), [body]);
});

const invalidWire = new Map<string, Buffer>([
  ['wrong object', Buffer.from(`${two.oid} blob 1\nx\n`)],
  ['wrong type', Buffer.from(`${one.oid} tree 1\nx\n`)],
  ['wrong size', Buffer.from(`${one.oid} blob 2\nx\n`)],
  ['leading zero', Buffer.from(`${one.oid} blob 01\nx\n`)],
  ['signed size', Buffer.from(`${one.oid} blob +1\nx\n`)],
  ['CRLF header', Buffer.from(`${one.oid} blob 1\r\nx\n`)],
  ['missing trailer', first.subarray(0, -1)],
  ['wrong trailer', Buffer.from(`${one.oid} blob 1\nx\r`)],
  ['trailing byte', Buffer.concat([first, Buffer.from('x')])],
  ['extra record', Buffer.concat([first, second])],
  ...['missing', 'excluded', 'ambiguous', 'submodule'].map(value => [value, Buffer.from(`${one.oid} ${value}\n`)] satisfies [string, Buffer]),
]);
for (const [name, output] of invalidWire) test(`reject ${name} before any bytes are exposed`, async () => {
  const accepted: unknown[] = [];
  await assert.rejects(async () => { for await (const item of readGitBlobs([one], async () => output, 1024)) accepted.push(item); }, { code: 'invalid_git_blob_batch' });
  assert.deepEqual(accepted, []);
});

test('every truncated prefix and wrong ordering reject the whole current batch', async () => {
  const wire = Buffer.concat([first, second]);
  for (let end = 0; end < wire.length; end++) {
    const accepted: unknown[] = [];
    await assert.rejects(async () => { for await (const item of readGitBlobs([one, two], async () => wire.subarray(0, end), 1024)) accepted.push(item); }, { code: 'invalid_git_blob_batch' });
    assert.deepEqual(accepted, [], 'truncated at byte ' + end);
  }
  await assert.rejects(collect([one, two], Buffer.concat([second, first])), { code: 'invalid_git_blob_batch' });
  await assert.rejects(collect([one, two], Buffer.concat([first, first])), { code: 'invalid_git_blob_batch' });
});

test('a malformed later record cannot expose an earlier record in that batch', async () => {
  const accepted: unknown[] = [];
  await assert.rejects(async () => { for await (const item of readGitBlobs([one, two], async () => Buffer.concat([first, second.subarray(0, -1)]), 1024)) accepted.push(item); }, { code: 'invalid_git_blob_batch' });
  assert.deepEqual(accepted, []);
});

test('only complete earlier batches can remain when a later batch fails', async () => {
  const accepted: string[] = []; let calls = 0;
  await assert.rejects(async () => { for await (const item of readGitBlobs([one, two], async () => ++calls === 1 ? first : Buffer.alloc(0), 1)) accepted.push(item.content.toString()); }, { code: 'invalid_git_blob_batch' });
  assert.deepEqual(accepted, ['x']); assert.equal(calls, 2);
});

test('invalid OID, sizes and envelope bounds fail before invoking Git', async () => {
  let calls = 0; const read = async () => { calls++; return first; };
  for (const oid of ['HEAD', one.oid + '\n', '../source', '--batch', one.oid.toUpperCase().replace('1', 'A'), 'g'.repeat(40)]) {
    await assert.rejects(async () => { for await (const ignored of readGitBlobs([{ ...one, oid }], read, 1024)) assert.fail(String(ignored)); }, { code: 'invalid_git_blob_input' });
  }
  for (const bytes of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER, 1024]) {
    await assert.rejects(async () => { for await (const ignored of readGitBlobs([{ ...one, bytes }], read, 1)) assert.fail(String(ignored)); }, { code: 'invalid_git_blob_input' });
  }
  for (const limit of [0, -1, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(async () => { for await (const ignored of readGitBlobs([one], read, limit)) assert.fail(String(ignored)); }, { code: 'invalid_git_blob_input' });
  }
  assert.equal(calls, 0);
});

test('process failure and cancellation never create an accepted batch', async () => {
  for (const code of ['git_failed', 'git_timeout', 'git_output_limit', 'git_termination_unverified']) {
    const accepted: unknown[] = [];
    await assert.rejects(async () => { for await (const item of readGitBlobs([one], async () => { throw new SafeError(code); }, 1024)) accepted.push(item); }, { code });
    assert.deepEqual(accepted, []);
  }
  let calls = 0;
  await assert.rejects(async () => { for await (const ignored of readGitBlobs([one], async () => { calls++; return first; }, 1024, AbortSignal.abort())) assert.fail(String(ignored)); }, { code: 'git_cancelled' });
  assert.equal(calls, 0);
  const aborted = new AbortController();
  await assert.rejects(async () => { for await (const ignored of readGitBlobs([one], async () => { aborted.abort(); return first; }, 1024, aborted.signal)) assert.fail(String(ignored)); }, { code: 'git_cancelled' });
  const stopBetween = new AbortController(), reader = readGitBlobs([one, two], async () => Buffer.concat([first, second]), 1024, stopBetween.signal);
  assert.equal((await reader.next()).value?.content.toString(), 'x'); stopBetween.abort();
  await assert.rejects(reader.next(), { code: 'git_cancelled' });
});
