import fs from 'node:fs/promises';
import path from 'node:path';

async function removeLinks(directory) {
  try {
    const stat = await fs.lstat(directory);
    if (stat.isSymbolicLink()) {
      try { await fs.unlink(directory); } catch { await fs.rmdir(directory); }
    } else if (stat.isDirectory()) {
      for (const name of await fs.readdir(directory)) await removeLinks(path.join(directory, name));
    }
  } catch {}
}

export async function removeTempDir(directory) {
  try {
    await removeLinks(directory);
    await fs.rm(directory, { recursive: true, force: true, maxRetries: 3 });
  } catch {}
}

export async function removeTempDirStrict(directory, rmOptions = { recursive: true, force: true }) {
  await removeLinks(directory);
  await fs.rm(directory, rmOptions);
  try { await fs.lstat(directory); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  throw Error(`Temporary directory remains: ${directory}`);
}
