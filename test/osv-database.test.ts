import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, symlink } from 'node:fs/promises';
import { acquisitionBasis, acquisitionMarker, databaseUrl, markerName, receiptName, prepareOfflineDatabase, verifyPreparedDatabase, validateDatabaseReceipt } from '../src/osv-database.ts';
import type { DatabaseReceipt } from '../src/osv-database.ts';
import { hash } from '../src/safety.ts';

const data = Buffer.from('synthetic database bytes, not an actual archive');
function receipt(): DatabaseReceipt {
  return { schema: 'scanmux.osv-database/v1', basis: acquisitionBasis, startedAt: '2026-01-02T00:00:00.000Z', completedAt: '2026-01-02T00:00:02.000Z', entries: [{
    ecosystem: 'npm', url: databaseUrl('npm'), bytes: data.length, sha256: hash(data), md5: createHash('md5').update(data).digest('base64'), generation: '123456',
    sourceModifiedAt: '2026-01-01T00:00:00.000Z', observedStartedAt: '2026-01-02T00:00:00.000Z', observedCompletedAt: '2026-01-02T00:00:01.000Z',
  }] };
}
async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'scanmux-db-test-'));
  test.after(() => removeTempDir(root));
  const source = path.join(root, 'source'), workspace = path.join(root, 'workspace'), target = path.join(root, 'target');
  await mkdir(path.join(source, 'osv-scalibr', 'npm'), { recursive: true }); await mkdir(workspace); await mkdir(target);
  const file = path.join(source, 'osv-scalibr', 'npm', 'all.zip'); await writeFile(file, data);
  return { file, source, workspace, target, ecosystems: ['npm'] as ['npm'], maxMetadataBytes: 8192, timeoutMs: 10000, signal: new AbortController().signal };
}
test('receipt timestamps separate acquisition, object update and unknown advisory cutoff', () => {
  const good = receipt(); assert.deepEqual(validateDatabaseReceipt(good, Date.parse(good.completedAt)), good);
  const invalid: ((value: any) => void)[] = [
    r => { r.extra = true; }, r => { r.schema = 'other'; }, r => { r.basis = 'signed'; }, r => { r.entries = []; },
    r => { r.entries.push(r.entries[0]); }, r => { r.entries[0].ecosystem = 'RubyGems'; }, r => { r.entries[0].url = 'https://attacker.invalid/'; },
    r => { r.entries[0].bytes = 0; }, r => { r.entries[0].bytes = Number.MAX_SAFE_INTEGER + 1; },
    r => { r.entries[0].sha256 = 'A'.repeat(64); }, r => { r.entries[0].md5 = 'invalid'; }, r => { r.entries[0].generation = '0123'; },
    r => { r.entries[0].sourceModifiedAt = '2026-01-02T00:00:02.000Z'; },
    r => { r.entries[0].observedStartedAt = '2026-01-01T23:59:59.000Z'; },
    r => { r.entries[0].observedCompletedAt = '2026-01-02T00:00:03.000Z'; },
    r => { r.completedAt = '2026-01-01T00:00:00.000Z'; }, r => { r.startedAt = '2026-02-30T00:00:00.000Z'; },
    r => { r.entries[0].observedStartedAt = '2026-01-02T00:00:00Z'; }, r => { r.entries[0].extra = true; },
  ];
  for (const mutate of invalid) { const value = structuredClone(good); mutate(value); assert.throws(() => validateDatabaseReceipt(value, Date.parse(good.completedAt))); }
  assert.throws(() => validateDatabaseReceipt(good, Date.parse(good.completedAt) - 1));
});
test('legacy bytes consumed from private copy retain unknown provenance and survive source replacement', async () => {
  const input = await fixture(), prepared = await prepareOfflineDatabase(input);
  assert.equal(prepared.observations[0]!.sha256, hash(data));
  assert.deepEqual(prepared.observations[0]!.provenance, { state: 'unknown', reason: 'legacy_acquisition_not_recorded' });
  assert.deepEqual(await readFile(prepared.files[0]!.path), data);
  await writeFile(input.file, 'different source');
  await verifyPreparedDatabase(prepared, input.target, input.signal, input.timeoutMs);
  await writeFile(prepared.files[0]!.path, Buffer.alloc(data.length, 65));
  await assert.rejects(verifyPreparedDatabase(prepared, input.target, input.signal, input.timeoutMs), { code: 'database_changed_during_scan' });
});
test('managed receipt binds recorded times and receipt hash to the copied bytes', async () => {
  const input = await fixture(), bytes = JSON.stringify(receipt());
  await writeFile(path.join(input.source, markerName), acquisitionMarker);
  await writeFile(path.join(input.source, receiptName), bytes);
  const prepared = await prepareOfflineDatabase(input), provenance = prepared.observations[0]!.provenance;
  assert.equal(provenance.state, 'recorded');
  if (provenance.state === 'recorded') {
    assert.equal(provenance.receiptHash, hash(bytes)); assert.equal(provenance.acquiredAt, receipt().entries[0]!.observedCompletedAt);
    assert.equal(provenance.sourceModifiedAt, receipt().entries[0]!.sourceModifiedAt); assert.equal(provenance.basis, acquisitionBasis);
  }
  await verifyPreparedDatabase(prepared, input.target, input.signal, input.timeoutMs);
});
test('incomplete acquisition, malformed metadata, size and digest mismatches are refused', async () => {
  for (const kind of ['incomplete', 'marker', 'json', 'utf8', 'large', 'missing-entry', 'digest', 'size', 'missing-db']) {
    const input = await fixture();
    if (kind === 'incomplete') await writeFile(path.join(input.source, markerName), acquisitionMarker);
    else if (kind === 'marker') await writeFile(path.join(input.source, markerName), 'other');
    else if (kind === 'missing-db') input.ecosystems = ['Go'] as any;
    else {
      const value = receipt();
      if (kind === 'digest') value.entries[0]!.sha256 = 'a'.repeat(64);
      if (kind === 'size') value.entries[0]!.bytes++;
      if (kind === 'missing-entry') { value.entries[0]!.ecosystem = 'Go'; value.entries[0]!.url = databaseUrl('Go'); }
      const bytes = kind === 'json' ? Buffer.from('{') : kind === 'utf8' ? Buffer.from([255]) : kind === 'large' ? Buffer.alloc(8193, 32) : Buffer.from(JSON.stringify(value));
      await writeFile(path.join(input.source, receiptName), bytes);
    }
    await assert.rejects(prepareOfflineDatabase(input), kind);
  }
});
test('needed ecosystems are copied independently while unused receipt entries are still validated', async () => {
  const input = await fixture(), value = receipt();
  await mkdir(path.join(input.source, 'osv-scalibr', 'Go')); await writeFile(path.join(input.source, 'osv-scalibr', 'Go', 'all.zip'), data);
  value.entries.push({ ...value.entries[0]!, ecosystem: 'Go', url: databaseUrl('Go') });
  await writeFile(path.join(input.source, receiptName), JSON.stringify(value));
  const prepared = await prepareOfflineDatabase({ ...input, ecosystems: ['npm', 'Go'] });
  assert.deepEqual(prepared.observations.map(o => o.ecosystem), ['npm', 'Go']);
  await verifyPreparedDatabase(prepared, input.target, input.signal, input.timeoutMs);
  value.entries[1]!.url = 'https://attacker.invalid/';
  await writeFile(path.join(input.source, receiptName), JSON.stringify(value));
  await assert.rejects(prepareOfflineDatabase({ ...input, ecosystems: ['npm'] }), { code: 'invalid_database_receipt' });
});
test('abort and truncated private copy cannot yield completed verification', async () => {
  const input = await fixture();
  await assert.rejects(prepareOfflineDatabase({ ...input, signal: AbortSignal.abort() }));
  const prepared = await prepareOfflineDatabase(input);
  await assert.rejects(verifyPreparedDatabase(prepared, input.target, AbortSignal.abort(), input.timeoutMs));
  await writeFile(prepared.files[0]!.path, data.subarray(1));
  await assert.rejects(verifyPreparedDatabase(prepared, input.target, input.signal, input.timeoutMs), { code: 'database_size_mismatch' });
});
test('source and output outside-target and junction boundaries remain enforced', async () => {
  const input = await fixture();
  await assert.rejects(prepareOfflineDatabase({ ...input, target: input.source }), { code: 'path_inside_target' });
  await assert.rejects(prepareOfflineDatabase({ ...input, target: input.workspace }), { code: 'path_inside_target' });
  const alias = path.join(path.dirname(input.source), 'alias'); await symlink(input.source, alias, 'junction');
  await assert.rejects(prepareOfflineDatabase({ ...input, source: alias }), { code: 'linked_path' });
});
