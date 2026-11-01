import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { inventoryAiDirectory, readAiFile } from '../src/ai-files.mjs';

const control = () => ({ expiresAt: performance.now() + 30000 });
test('SDK asset ordering matches the adopted per-directory English ordering while source receipts keep path ordering', async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'ai-files-test-'));
  test.after(() => removeTempDir(root));
  const files = ['LICENSE', 'build/Z.js', 'build/a.js', 'build/workbench_target.py', 'build/workbench_target_state.py'];
  for (const name of files) { await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true }); await fs.writeFile(path.join(root, name), name); }
  const lexical = await inventoryAiDirectory(root, control(), { maxReceiptBytes: 10000 });
  assert.deepEqual(lexical.map(entry => entry.path), [...files].sort());
  const assets = await inventoryAiDirectory(root, control(), { maxReceiptBytes: 10000, order: 'sdk-assets' });
  assert.deepEqual(assets.map(entry => entry.path), ['build/a.js', 'build/workbench_target_state.py', 'build/workbench_target.py', 'build/Z.js', 'LICENSE']);
  assert.deepEqual([...assets].sort((a, b) => a.path < b.path ? -1 : 1), lexical);
});

test('file and inventory byte limits reject their own output boundary and aborts stay effective', async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'ai-files-test-'));
  test.after(() => removeTempDir(root));
  const file = path.join(root, 'source.txt'); await fs.writeFile(file, 'abcdef');
  assert.equal((await readAiFile(file, 6, control())).toString(), 'abcdef');
  await assert.rejects(readAiFile(file, 5, control()), /ai_file_limit/);
  const entries = await inventoryAiDirectory(root, control(), { maxReceiptBytes: 10000 }), bytes = Buffer.byteLength(JSON.stringify(entries));
  assert.deepEqual(await inventoryAiDirectory(root, control(), { maxReceiptBytes: bytes }), entries);
  await assert.rejects(inventoryAiDirectory(root, control(), { maxReceiptBytes: bytes - 1 }), /ai_inventory_limit/);
  const abort = new AbortController(); abort.abort();
  await assert.rejects(inventoryAiDirectory(root, { ...control(), signal: abort.signal }, { maxReceiptBytes: 10000 }), /ai_stopped/);
});
