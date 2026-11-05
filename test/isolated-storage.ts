import { beforeEach, afterEach } from 'node:test';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { sourceCleanupState } from '../src/source-cleanup.ts';

export function isolateStorage(): void {
  let root: string, previous: Record<string, string | undefined>;
  beforeEach(async () => {
    sourceCleanupState.failed = false;
    previous = Object.fromEntries(['TEMP', 'TMP', 'TMPDIR', 'LOCALAPPDATA'].map(key => [key, process.env[key]]));
    root = await mkdtemp(path.join(process.cwd(), 'test', '.p1-storage-'));
    const temp = path.join(root, 'temp'), local = path.join(root, 'local');
    await mkdir(temp); await mkdir(local);
    process.env.TEMP = temp; process.env.TMP = temp; process.env.TMPDIR = temp; process.env.LOCALAPPDATA = local;
  });
  afterEach(async () => {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
}
