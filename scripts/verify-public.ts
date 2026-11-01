import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { jobRuntimeFiles } from '../src/job-runner.ts';

// Explicit package allowlist: a stray file under src/ must fail this check too.
export const publicPackageFiles = [...jobRuntimeFiles];
export function verifyPackagePaths(paths: string[]): void {
  assert.deepEqual([...paths].sort(), publicPackageFiles, 'Unexpected or missing package file');
}
if (import.meta.main && process.argv[2]) {
  const raw = JSON.parse(await readFile(process.argv[2], 'utf8'));
  const pack = Array.isArray(raw) ? raw : Object.values(raw);
  assert.equal(pack.length, 1);
  verifyPackagePaths(pack[0].files.map((f: { path: string }) => f.path));
  console.log(`PUBLIC_PACKAGE_VERIFIED: ${publicPackageFiles.length} explicitly allowed files; no internal documents or tools.`);
}
