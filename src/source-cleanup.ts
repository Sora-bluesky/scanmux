import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { lstatSync } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { safeRemove, unlinkedDirectory, type DirectoryIdentity, type RemovalResult } from './safe-remove.ts';
import { SafeError, within } from './safety.ts';

interface OwnedCopy { workspace: string; identity?: DirectoryIdentity }
interface WorkspaceOwnership { disposable: boolean; identity: DirectoryIdentity }
const scope = new AsyncLocalStorage<SourceCleanupOwner>();
const standalone = new Map<string, SourceCleanupOwner>();
export const sourceCleanupState = { failed: false };
export const sourceCleanupFailed = (): boolean => sourceCleanupState.failed;
const failed = (): RemovalResult => { sourceCleanupState.failed = true; return { status: 'failed', code: 'source_cleanup_failed' }; };
const absent = (error: unknown) => (error as NodeJS.ErrnoException).code === 'ENOENT';
const identityOf = ({ dev, ino, birthtimeNs }: DirectoryIdentity): DirectoryIdentity => ({ dev, ino, birthtimeNs });
const sameIdentity = (left: DirectoryIdentity, right: DirectoryIdentity) => left.dev === right.dev && left.ino === right.ino && left.birthtimeNs === right.birthtimeNs;
const copyName = /^(?:snapshot|repository|sdk-repository|sdk-projection-control|(?:trivy|trivy-probe-snapshot|output-check)-[a-zA-Z0-9-]+)$/;

export function initializeSourceWorkspace(workspace: string, disposable: boolean): DirectoryIdentity {
  return sourceCleanupFor(workspace).initialize(workspace, disposable);
}
export async function verifySourceWorkspace(workspace: string, identity: DirectoryIdentity): Promise<void> {
  const stat = await fs.lstat(workspace, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() || !sameIdentity(stat, identity)) { failed(); throw new SafeError('source_cleanup_failed'); }
}

export class SourceCleanupOwner {
  #paths = new Map<string, OwnedCopy>();
  #workspaces = new Map<string, WorkspaceOwnership>();
  initialize(workspace: string, disposable: boolean): DirectoryIdentity {
    const key = path.resolve(workspace), stat = lstatSync(key, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || this.#workspaces.has(key)) { failed(); throw new SafeError('source_cleanup_failed'); }
    const identity = identityOf(stat);
    this.#workspaces.set(key, { disposable, identity }); standalone.set(key, this);
    return identity;
  }
  register(workspace: string, directory: string): string {
    const key = path.resolve(workspace), absolute = path.resolve(directory);
    if (!path.isAbsolute(workspace) || !path.isAbsolute(directory) || key === path.parse(key).root || !within(key, absolute)
      || absolute !== key && (path.dirname(absolute) !== key || !copyName.test(path.basename(absolute)))) { failed(); throw new SafeError('source_cleanup_failed'); }
    const previous = standalone.get(key);
    let ownership = this.#workspaces.get(key) ?? (previous && previous.#workspaces.get(key));
    if (!ownership) {
      const stat = lstatSync(key, { bigint: true });
      if (!stat.isDirectory() || stat.isSymbolicLink()) { failed(); throw new SafeError('source_cleanup_failed'); }
      ownership = { disposable: false, identity: identityOf(stat) };
    }
    this.#workspaces.set(key, ownership);
    if (!this.#paths.has(absolute)) this.#paths.set(absolute, { workspace: key, identity: absolute === key ? ownership.identity : undefined });
    return absolute;
  }
  async capture(workspace: string, directory: string): Promise<void> {
    const absolute = this.register(workspace, directory), stat = await fs.lstat(absolute, { bigint: true }), copy = this.#paths.get(absolute)!;
    if (!stat.isDirectory() || stat.isSymbolicLink() || copy.identity && !sameIdentity(copy.identity, stat)) { failed(); throw new SafeError('source_cleanup_failed'); }
    copy.identity ??= identityOf(stat);
  }
  async directory(workspace: string, prefix: string): Promise<string> {
    if (!/^(?:trivy|trivy-probe-snapshot|output-check)-$/.test(prefix)) { failed(); throw new SafeError('source_cleanup_failed'); }
    const directory = this.register(workspace, path.join(workspace, prefix + randomUUID()));
    await fs.mkdir(directory, { mode: 0o700 });
    await this.capture(workspace, directory);
    return directory;
  }
  async cleanup(workspace?: string, only?: readonly string[]): Promise<RemovalResult> {
    let result: RemovalResult = { status: 'removed' };
    const paths = [...this.#paths].reverse().sort(([a, left], [b, right]) => Number(a === left.workspace) - Number(b === right.workspace));
    for (const [directory, copy] of paths) {
      if (workspace && copy.workspace !== path.resolve(workspace) || only && !only.includes(directory)) continue;
      if (!copy.identity) {
        try { await fs.lstat(directory); }
        catch (error) {
          if (absent(error)) this.#paths.delete(directory);
          else result = failed();
          continue;
        }
        result = failed();
        process.stderr.write(`ScanMux: source_cleanup_failed; private directory retained: ${JSON.stringify(directory)}\n`);
        continue;
      }
      const ownership = this.#workspaces.get(copy.workspace);
      try {
        if (!ownership || directory === copy.workspace && !ownership.disposable) throw new SafeError('source_cleanup_failed');
        if (directory === copy.workspace && [...this.#paths].some(([child, owned]) => child !== directory && owned.workspace === copy.workspace)) throw new SafeError('source_cleanup_failed');
        await unlinkedDirectory(copy.workspace);
        await verifySourceWorkspace(copy.workspace, ownership.identity);
        const stat = await fs.lstat(directory, { bigint: true }).catch(error => { if (absent(error)) return undefined; throw error; });
        if (stat && !sameIdentity(stat, copy.identity)) throw new SafeError('source_cleanup_failed');
        const removed = await safeRemove(directory, copy.identity, { directory: copy.workspace, identity: ownership.identity });
        if (removed.status === 'failed') result = failed();
        else this.#paths.delete(directory);
      } catch { result = failed(); }
    }
    return result;
  }
}
export function sourceCleanupFor(workspace: string): SourceCleanupOwner {
  const owner = scope.getStore(); if (owner) return owner;
  const key = path.resolve(workspace);
  if (!standalone.has(key)) standalone.set(key, new SourceCleanupOwner());
  return standalone.get(key)!;
}
export const withSourceCleanup = <T>(owner: SourceCleanupOwner, body: () => Promise<T>): Promise<T> => scope.run(owner, body);
