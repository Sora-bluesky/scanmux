import { crc32, inflateRawSync } from 'node:zlib';
import { safeRelative, SafeError } from './safety.ts';

export interface ZipLimits { readonly maxEntries: number; readonly maxBytes: number }

const eocdSignature = 0x06054b50, centralSignature = 0x02014b50, localSignature = 0x04034b50, descriptorSignature = 0x08074b50;
const wide16 = 0xffff, wide32 = 0xffffffff;
const descriptorFlag = 0x8, allowedFlags = 0x2 | 0x4 | descriptorFlag | 0x800;

function invalid(): never { throw new SafeError('zip_archive_invalid'); }
function u16(bytes: Buffer, offset: number): number { if (offset < 0 || offset + 2 > bytes.length) invalid(); return bytes.readUInt16LE(offset); }
function u32(bytes: Buffer, offset: number): number { if (offset < 0 || offset + 4 > bytes.length) invalid(); return bytes.readUInt32LE(offset); }
function slice(bytes: Buffer, start: number, length: number): Buffer {
  if (start < 0 || length < 0 || start + length > bytes.length) invalid();
  return bytes.subarray(start, start + length);
}
const utf8 = new TextDecoder('utf-8', { fatal: true });

export function readZip(archive: Buffer, limits: ZipLimits, only?: string): Map<string, Buffer> {
  let end = -1;
  for (let offset = archive.length - 22; offset >= Math.max(0, archive.length - 22 - wide16); offset--) {
    if (archive.readUInt32LE(offset) === eocdSignature && offset + 22 + archive.readUInt16LE(offset + 20) === archive.length) { end = offset; break; }
  }
  if (end < 0) invalid();
  const disk = u16(archive, end + 4), directoryDisk = u16(archive, end + 6), onDisk = u16(archive, end + 8), entries = u16(archive, end + 10);
  const directorySize = u32(archive, end + 12), directoryOffset = u32(archive, end + 16);
  if (disk !== 0 || directoryDisk !== 0 || onDisk !== entries || entries === wide16 || directorySize === wide32 || directoryOffset === wide32) invalid();
  if (entries > limits.maxEntries || directoryOffset + directorySize !== end) invalid();
  const files = new Map<string, Buffer>();
  const seen = new Set<string>();
  let cursor = directoryOffset, total = 0;
  for (let index = 0; index < entries; index++) {
    if (u32(archive, cursor) !== centralSignature) invalid();
    const flags = u16(archive, cursor + 8), method = u16(archive, cursor + 10), checksum = u32(archive, cursor + 16);
    const compressed = u32(archive, cursor + 20), size = u32(archive, cursor + 24);
    const nameLength = u16(archive, cursor + 28), extraLength = u16(archive, cursor + 30), commentLength = u16(archive, cursor + 32);
    const startDisk = u16(archive, cursor + 34), localOffset = u32(archive, cursor + 42);
    if ((flags & ~allowedFlags) || (method !== 0 && method !== 8) || startDisk !== 0 || compressed === wide32 || size === wide32 || localOffset === wide32) invalid();
    const rawName = slice(archive, cursor + 46, nameLength);
    if (!(flags & 0x800) && rawName.some(byte => byte >= 0x80)) invalid();
    let name: string;
    try { name = safeRelative(utf8.decode(rawName)); } catch { invalid(); }
    if (seen.has(name)) invalid();
    seen.add(name);
    if (u32(archive, localOffset) !== localSignature || !slice(archive, localOffset + 30, u16(archive, localOffset + 26)).equals(rawName)) invalid();
    if (u16(archive, localOffset + 6) !== flags || u16(archive, localOffset + 8) !== method) invalid();
    const dataOffset = localOffset + 30 + u16(archive, localOffset + 26) + u16(archive, localOffset + 28);
    const data = slice(archive, dataOffset, compressed);
    const sizes = (at: number) => [u32(archive, at), u32(archive, at + 4), u32(archive, at + 8)];
    const declared = [checksum, compressed, size], local = sizes(localOffset + 14);
    if (flags & descriptorFlag) {
      const after = dataOffset + compressed, signed = u32(archive, after) === descriptorSignature;
      if (local.some(value => value !== 0) || sizes(after + (signed ? 4 : 0)).some((value, at) => value !== declared[at])) invalid();
    } else if (local.some((value, at) => value !== declared[at])) invalid();
    if (only === undefined || name === only) {
      total += size;
      if (total > limits.maxBytes) invalid();
      let content: Buffer;
      if (method === 0) content = Buffer.from(data);
      else { try { content = inflateRawSync(data, { maxOutputLength: Math.max(1, size) }); } catch { invalid(); } }
      if (content.length !== size || crc32(content) !== checksum) invalid();
      files.set(name, content);
    }
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  if (cursor !== end) invalid();
  return files;
}
