import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { SafeError, safeRelative } from './safety.ts';

export function active(control) {
  if (!control || !Number.isFinite(control.expiresAt) || control.signal?.aborted || performance.now() >= control.expiresAt) throw new SafeError('ai_stopped');
}
export async function canonicalAiPath(file, control, kind = 'file') {
  active(control);
  if (typeof file !== 'string' || !path.isAbsolute(file) || path.resolve(file) !== file) throw new SafeError('ai_file_path');
  let current = path.parse(file).root;
  for (const part of file.slice(current.length).split(path.sep).filter(Boolean)) {
    active(control); current = path.join(current, part);
    const stat = await fs.lstat(current); active(control);
    if (stat.isSymbolicLink() || await fs.realpath(current) !== current) throw new SafeError('ai_file_alias');
  }
  const stat = await fs.lstat(file); active(control);
  if (kind === 'directory' ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1) throw new SafeError('ai_file_kind');
  return file;
}
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
export async function readAiFile(file, maximum, control) {
  if (!Number.isSafeInteger(maximum) || maximum < 0) throw new SafeError('ai_file_limit');
  await canonicalAiPath(file, control);
  const before = await fs.lstat(file, { bigint: true });
  if (before.size > BigInt(maximum)) throw new SafeError('ai_file_limit');
  const handle = await fs.open(file, 'r');
  try {
    active(control); const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameFile(before, opened)) throw new SafeError('ai_file_changed');
    const chunks = [], chunk = Buffer.alloc(Math.min(maximum + 1, 64 * 1024)); let count = 0;
    for (;;) {
      active(control); const { bytesRead } = await handle.read(chunk, 0, chunk.length, count); active(control);
      if (!bytesRead) break;
      count += bytesRead; if (count > maximum) throw new SafeError('ai_file_limit');
      chunks.push(Buffer.from(chunk.subarray(0, bytesRead)));
    }
    const bytes = Buffer.concat(chunks, count); active(control);
    const after = await handle.stat({ bigint: true }), current = await fs.lstat(file, { bigint: true });
    await canonicalAiPath(file, control);
    if (bytes.length > maximum || !sameFile(opened, after) || !sameFile(after, current)) throw new SafeError('ai_file_changed');
    return bytes;
  } finally { await handle.close(); }
}
export async function readAiJson(file, maximum, control) {
  const bytes = await readAiFile(file, maximum, control);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw new SafeError('ai_file_json'); }
}
/** Bounded memory hashing of operator assets and freshly created projection files. */
export async function inventoryAiDirectory(root, control, { directories = false, maxReceiptBytes, order = 'path' } = {}) {
  await canonicalAiPath(root, control, 'directory');
  if (!Number.isSafeInteger(maxReceiptBytes) || maxReceiptBytes < 2 || !['path', 'sdk-assets'].includes(order)) throw new SafeError('ai_inventory_limit');
  const entries = []; let encodedBytes = 2;
  const add = entry => {
    encodedBytes += Buffer.byteLength(JSON.stringify(entry)) + (entries.length ? 1 : 0);
    if (encodedBytes > maxReceiptBytes) throw new SafeError('ai_inventory_limit');
    entries.push(entry);
  };
  async function visit(folder) {
    active(control);
    for (const entry of await fs.readdir(folder, { withFileTypes: true })) {
      active(control); const full = path.join(folder, entry.name), name = path.relative(root, full).split(path.sep).join('/'); safeRelative(name);
      const stat = await fs.lstat(full, { bigint: true });
      if (stat.isSymbolicLink() || await fs.realpath(full) !== full) throw new SafeError('ai_file_alias');
      if (stat.isDirectory()) { if (directories) add({ path: name, kind: 'directory' }); await visit(full); }
      else {
        if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new SafeError('ai_file_kind');
        const hash = createHash('sha256'), stream = createReadStream(full); let count = 0;
        const cancel = () => stream.destroy(new SafeError('ai_stopped'));
        control.signal?.addEventListener('abort', cancel, { once: true });
        try { for await (const bytes of stream) { active(control); count += bytes.length; hash.update(bytes); } }
        finally { control.signal?.removeEventListener('abort', cancel); stream.destroy(); }
        active(control); const after = await fs.lstat(full, { bigint: true });
        if (!sameFile(stat, after) || count !== Number(stat.size)) throw new SafeError('ai_file_changed');
        add({ path: name, bytes: count, sha256: hash.digest('hex') });
      }
    }
  }
  await visit(root); active(control);
  return entries.sort((a, b) => {
    if (order === 'path') return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
    // The adopted SDK manifest orders each directory in English before descending.
    const left = a.path.split('/'), right = b.path.split('/');
    for (let index = 0; index < Math.min(left.length, right.length); index++) {
      const compared = left[index].localeCompare(right[index], 'en');
      if (compared) return compared;
    }
    return left.length - right.length;
  });
}
