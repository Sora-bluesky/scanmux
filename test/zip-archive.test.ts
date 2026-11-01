import test from 'node:test';
import assert from 'node:assert/strict';
import { readZip } from '../src/zip-archive.ts';
import { localHeader, zip } from './zip-fixture.ts';

const limits = { maxEntries: 4, maxBytes: 1024 };

test('zip reader: stored and deflated entries round-trip; corruption, duplicates, unsafe names and trailing bytes are refused', () => {
  const entries: [string, Buffer][] = [['a.json', Buffer.from('{"a":1}\n')], ['b.json', Buffer.alloc(0)]];
  for (const deflate of [true, false]) assert.deepEqual([...readZip(zip(entries, deflate), { maxEntries: 4, maxBytes: 1024 })], entries);
  const corrupt = zip(entries, false); corrupt[30 + 6] ^= 1;
  for (const bad of [corrupt, zip([...entries, entries[0]]), zip([['../x', Buffer.from('x')]]), zip([['d/', Buffer.alloc(0)]]), Buffer.concat([zip(entries), Buffer.from('x')])]) {
    assert.throws(() => readZip(bad, limits), /zip_archive_invalid/);
  }
  assert.throws(() => readZip(zip(entries), { maxEntries: 1, maxBytes: 1024 }), /zip_archive_invalid/);
  assert.throws(() => readZip(zip([['big', Buffer.alloc(2048)]]), limits), /zip_archive_invalid/);
});

test('zip reader: the local header must agree with the central directory on flags, method, CRC and sizes', () => {
  const entries: [string, Buffer][] = [['a.json', Buffer.from('{"a":1}\n')]];
  for (const deflate of [true, false]) assert.deepEqual([...readZip(zip(entries, deflate, true), limits)], entries, 'a data descriptor carries the CRC and sizes');
  const changed = (descriptor: boolean, edit: (archive: Buffer) => void) => { const archive = zip(entries, true, descriptor); edit(archive); return archive; };
  const cases: [string, Buffer][] = [
    ['local encryption flag', changed(false, archive => archive.writeUInt16LE(1, localHeader.flags))],
    ['local unsupported method', changed(false, archive => archive.writeUInt16LE(99, localHeader.method))],
    ['local stored method', changed(false, archive => archive.writeUInt16LE(0, localHeader.method))],
    ['local CRC', changed(false, archive => { archive[localHeader.crc] ^= 1; })],
    ['local compressed size', changed(false, archive => archive.writeUInt32LE(archive.readUInt32LE(localHeader.compressed) + 1, localHeader.compressed))],
    ['local size', changed(false, archive => archive.writeUInt32LE(archive.readUInt32LE(localHeader.size) + 1, localHeader.size))],
    ['descriptor flag only in the local header', changed(false, archive => archive.writeUInt16LE(0x8, localHeader.flags))],
    ['descriptor with a stray local CRC', changed(true, archive => archive.writeUInt32LE(1, localHeader.crc))],
  ];
  const descriptorAt = (archive: Buffer) => 30 + entries[0][0].length + archive.readUInt32LE(archive.length - 22 - 46 - entries[0][0].length + 20);
  for (const field of [4, 8, 12]) cases.push([`descriptor field ${field}`, changed(true, archive => { archive[descriptorAt(archive) + field] ^= 1; })]);
  const strongEncryption = zip(entries);
  strongEncryption.writeUInt16LE(0x40, localHeader.flags); strongEncryption.writeUInt16LE(0x40, strongEncryption.length - 22 - 46 - entries[0][0].length + 8);
  cases.push(['strong encryption flag in both headers', strongEncryption]);
  for (const [name, archive] of cases) assert.throws(() => readZip(archive, limits), /zip_archive_invalid/, name);
});
