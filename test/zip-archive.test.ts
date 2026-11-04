import test from 'node:test';
import assert from 'node:assert/strict';
import { readZip } from '../src/zip-archive.ts';
import { localHeader, zip } from './zip-fixture.ts';

const limits = { maxEntries: 4, maxBytes: 1024 };

test('zip reader: non-ASCII names require the UTF-8 flag', () => {
  const entries: [string, Buffer][] = [['caf\u00e9.txt', Buffer.from('content')]];
  const archive = zip(entries), central = archive.readUInt32LE(archive.length - 6);
  assert.throws(() => readZip(archive, limits), /zip_archive_invalid/);
  assert.throws(() => readZip(archive, limits, 'other'), /zip_archive_invalid/);
  archive.writeUInt16LE(0x800, localHeader.flags); archive.writeUInt16LE(0x800, central + 8);
  assert.deepEqual([...readZip(archive, limits)], entries);
  assert.deepEqual([...readZip(archive, limits, entries[0][0])], entries);
});

test('zip reader: only the exact selected member is inflated and charged to the byte limit', () => {
  const selected: [string, Buffer] = ['engine.exe', Buffer.from('engine')];
  for (const descriptor of [false, true]) {
    const archive = zip([['other', Buffer.alloc(2048)], selected], true, descriptor);
    archive[30 + 'other'.length] = 0x07;
    assert.throws(() => readZip(archive, { ...limits, maxBytes: 4096 }), /zip_archive_invalid/);
    assert.deepEqual([...readZip(archive, { ...limits, maxBytes: selected[1].length }, selected[0])], [selected]);
    assert.deepEqual([...readZip(archive, { ...limits, maxBytes: 0 }, 'ENGINE.EXE')], []);
    assert.throws(() => readZip(archive, { ...limits, maxBytes: selected[1].length - 1 }, selected[0]), /zip_archive_invalid/);
    assert.throws(() => readZip(archive, { ...limits, maxEntries: 1 }, selected[0]), /zip_archive_invalid/);
  }
});

test('zip reader: selecting a member still refuses unrelated duplicates and bad headers', () => {
  const selected: [string, Buffer] = ['engine.exe', Buffer.from('engine')], other: [string, Buffer] = ['other', Buffer.from('other')];
  const duplicate = zip([other, selected, other]);
  const local = zip([other, selected]); local.writeUInt16LE(1, localHeader.flags);
  const central = zip([selected, other]), directory = central.readUInt32LE(central.length - 6);
  central.writeUInt16LE(99, directory + 46 + selected[0].length + 10);
  const descriptor = zip([other, selected], true, true);
  descriptor[30 + other[0].length + descriptor.readUInt32LE(descriptor.readUInt32LE(descriptor.length - 6) + 20) + 4] ^= 1;
  for (const bad of [duplicate, local, central, descriptor]) assert.throws(() => readZip(bad, limits, selected[0]), /zip_archive_invalid/);
});

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
