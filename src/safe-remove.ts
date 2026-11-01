import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export type RemovalResult = { status: 'removed' } | { status: 'failed'; code: 'source_cleanup_failed' };
export interface DirectoryIdentity { dev: bigint; ino: bigint; birthtimeNs: bigint }
interface WorkspaceIdentity { directory: string; identity: DirectoryIdentity }
const missing = (error: unknown) => (error as NodeJS.ErrnoException).code === 'ENOENT';

export async function unlinkedDirectory(directory: string): Promise<void> {
  const absolute = path.resolve(directory);
  let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = await fs.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('linked_directory');
  }
}

async function removeDirectory(directory: string, options: { beforeDelete?: (file: string) => Promise<void>; identity?: DirectoryIdentity; workspace?: WorkspaceIdentity } = {}): Promise<RemovalResult> {
  if (!path.isAbsolute(directory) || path.resolve(directory) === path.parse(directory).root) return { status: 'failed', code: 'source_cleanup_failed' };
  const identities = new Map<string, DirectoryIdentity>();
  const same = (left: DirectoryIdentity, right: DirectoryIdentity) => left.dev === right.dev && left.ino === right.ino && left.birthtimeNs === right.birthtimeNs;
  function remember(file: string, stat: DirectoryIdentity & { isDirectory(): boolean; isSymbolicLink(): boolean }): void {
    const previous = identities.get(file), expected = file === path.resolve(directory) ? options.identity : undefined;
    if (!stat.isDirectory() || stat.isSymbolicLink() || previous && !same(previous, stat) || expected && !same(expected, stat)
      || file === options.workspace?.directory && !same(options.workspace.identity, stat)) throw new Error('changed_directory');
    identities.set(file, { dev: stat.dev, ino: stat.ino, birthtimeNs: stat.birthtimeNs });
  }
  async function checkParent(file: string): Promise<void> {
    const stat = await fs.lstat(file, { bigint: true }).catch(error => { if (identities.has(file)) throw new Error('changed_directory'); throw error; });
    remember(file, stat);
  }
  async function checkDirectory(file: string): Promise<void> {
    const absolute = path.resolve(file);
    let current = path.parse(absolute).root;
    for (const part of ['', ...absolute.slice(current.length).split(path.sep).filter(Boolean)]) {
      current = path.join(current, part);
      await checkParent(current);
    }
  }
  async function beforeDelete(file: string, directory = false): Promise<void> {
    await options.beforeDelete?.(file);
    if (directory) await checkParent(file);
    await checkDirectory(path.dirname(file));
  }
  async function visit(file: string, root = false): Promise<void> {
    if (root) await checkDirectory(path.dirname(file));
    const stat = await fs.lstat(file, { bigint: true });
    if (root && options.identity && !same(options.identity, stat)) throw new Error('changed_directory');
    if (identities.has(file)) remember(file, stat);
    if (stat.isSymbolicLink()) {
      if (root) throw new Error('linked_root');
      await beforeDelete(file); await fs.unlink(file); return;
    }
    if (root && !stat.isDirectory()) throw new Error('directory_required');
    if (!stat.isDirectory()) {
      try { await beforeDelete(file); await fs.unlink(file); }
      catch (error) {
        if (process.platform !== 'win32' || (error as NodeJS.ErrnoException).code !== 'EPERM' || !stat.isFile() || stat.nlink !== 1n) throw error;
        await checkParent(path.dirname(file));
        const current = await fs.lstat(file, { bigint: true });
        if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1n || current.ino !== stat.ino || current.dev !== stat.dev) throw error;
        const handle = await fs.open(file, 'r');
        try {
          const opened = await handle.stat({ bigint: true });
          if (!opened.isFile() || opened.nlink !== 1n || !same(opened, stat)) throw error;
          await handle.chmod(0o600);
        } finally { await handle.close(); }
        await beforeDelete(file); await fs.unlink(file);
      }
      return;
    }
    remember(file, stat); await checkDirectory(file);
    const entries = await fs.readdir(file);
    const links: string[] = [], rest: string[] = [];
    for (const name of entries) {
      const child = path.join(file, name);
      const childStat = await fs.lstat(child).catch(error => { if (missing(error)) return null; throw error; });
      if (childStat) (childStat.isSymbolicLink() ? links : rest).push(child);
    }
    for (const child of [...links, ...rest]) await visit(child).catch(error => { if (!missing(error)) throw error; });
    await beforeDelete(file, true); await fs.rmdir(file);
  }
  for (let attempt = 0; attempt < 4; attempt++) {
    try { await visit(path.resolve(directory), true); return { status: 'removed' }; }
    catch (error) {
      if (missing(error)) {
        try { await fs.lstat(directory); } catch (absent) { if (missing(absent)) return { status: 'removed' }; }
      }
      if (!['EBUSY', 'EPERM', 'EACCES', 'ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code ?? '') || attempt === 3) break;
      await delay(25 * (attempt + 1));
    }
  }
  return { status: 'failed', code: 'source_cleanup_failed' };
}

export async function safeRemove(directory: string, identity?: DirectoryIdentity, workspace?: WorkspaceIdentity): Promise<RemovalResult> { return removeDirectory(directory, { identity, workspace }); }
