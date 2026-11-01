import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

export class SafeError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.code = code; }
}
export function hash(input: string | Buffer): string { return createHash('sha256').update(input).digest('hex'); }
export function digest(input: unknown): string { return hash(JSON.stringify(input)); }
export function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}
export function safeRelative(input: unknown): string {
  if (typeof input !== 'string' || !input || input.length > 1024 || /[\\:\x00-\x1f\x7f]/.test(input) || input.startsWith('/')) throw new SafeError('unsafe_path');
  const parts = input.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p))) throw new SafeError('unsafe_path');
  return input;
}
export async function canonical(input: string): Promise<string> {
  const resolved = path.resolve(input);
  const physical = await realpath(resolved);
  // Do not silently follow junctions, symlinks or alternate spellings.
  if (physical.toLowerCase() !== resolved.toLowerCase() || (await lstat(resolved)).isSymbolicLink()) throw new SafeError('linked_path');
  return physical;
}
export function hostLocalPath(input: string): boolean {
  return path.isAbsolute(input) && !/^(?:\\\\|\/\/)/.test(input) && !/[\x00-\x1f\x7f]/.test(input)
    && (process.platform !== 'win32' || /^[A-Za-z]:[\\/][^:]*$/.test(input));
}
export async function outside(input: string, root: string): Promise<string> {
  const physical = await canonical(input);
  if (within(root, physical)) throw new SafeError('path_inside_target');
  return physical;
}
export function record(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new SafeError('invalid_report');
  return input as Record<string, unknown>;
}
export function array(input: unknown): unknown[] {
  if (!Array.isArray(input) || input.length > 10000) throw new SafeError('invalid_report');
  return input;
}
export function identifier(input: unknown): string {
  if (typeof input !== 'string' || !/^[A-Za-z0-9@_./+:-]{1,200}$/.test(input)) throw new SafeError('invalid_identifier');
  return input;
}
export async function boundedRead(file: string, maximum: number): Promise<Buffer> {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maximum) throw new SafeError('file_limit');
  const content = await readFile(file);
  if (content.length > maximum) throw new SafeError('file_limit');
  return content;
}
