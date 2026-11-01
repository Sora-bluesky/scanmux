import { crc32, deflateRawSync } from 'node:zlib';

export const localHeader = { flags: 6, method: 8, crc: 14, compressed: 18, size: 22 } as const;

export function zip(entries: [string, Buffer][], deflate = true, descriptor = false): Buffer {
  const locals: Buffer[] = [], centrals: Buffer[] = [];
  const flags = descriptor ? 0x8 : 0;
  let offset = 0;
  for (const [name, content] of entries) {
    const nameBytes = Buffer.from(name), data = deflate ? deflateRawSync(content) : content, method = deflate ? 8 : 0;
    const local = Buffer.alloc(30), central = Buffer.alloc(46), trailer = Buffer.alloc(descriptor ? 16 : 0);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(flags, 6); local.writeUInt16LE(method, 8);
    if (!descriptor) { local.writeUInt32LE(crc32(content), 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(content.length, 22); }
    else { trailer.writeUInt32LE(0x08074b50, 0); trailer.writeUInt32LE(crc32(content), 4); trailer.writeUInt32LE(data.length, 8); trailer.writeUInt32LE(content.length, 12); }
    local.writeUInt16LE(nameBytes.length, 26);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(flags, 8); central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc32(content), 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(nameBytes.length, 28); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data, trailer); centrals.push(central, nameBytes);
    offset += 30 + nameBytes.length + data.length + trailer.length;
  }
  const directory = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
