import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { privateWorkspace } from '../src/private-storage.ts';
import { readSiwcCredentials } from '../src/siwc-credentials.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const controls = signal => ({ signal, expiresAt: performance.now() + 30000, commandTimeoutMs: 10000, cleanupTimeoutMs: 10000 });
async function fixture() {
  const directory = await privateWorkspace();
  test.after(() => removeTempDir(directory));
  const registration = { schema: 1, state: 'authorizing', clientId: 'oaiapp_synthetic' };
  const record = { schema: 1, state: 'active', issuer: 'https://auth.openai.com', clientId: registration.clientId, subject: 'synthetic-subject', accessToken: 'synthetic-access-only', refreshToken: 'synthetic-refresh-only', idToken: 'synthetic-id-only', scopes: ['openid','profile','email','offline_access','resource.invoke','chatgpt.tokens.use.direct'], expiresAt: Date.now() + 600000 };
  await fs.writeFile(path.join(directory, 'registration.json'), JSON.stringify(registration), { flag: 'wx', mode: 0o600 });
  await fs.writeFile(path.join(directory, 'credentials.json'), JSON.stringify(record), { flag: 'wx', mode: 0o600 });
  return { directory, registration, record };
}
async function receipts(directory) {
  const result = [];
  for (const name of (await fs.readdir(directory)).sort()) { const stat = await fs.lstat(path.join(directory,name)); if (stat.isFile()) { const bytes = await fs.readFile(path.join(directory,name)); result.push({ name, bytes: bytes.length, sha256: hash(bytes) }); } else result.push({ name, kind: stat.isSymbolicLink() ? 'link' : 'directory' }); }
  return result;
}
test('a dedicated synthetic authenticated record is read without creating locks or changing any file', async () => {
  const f = await fixture(), before = await receipts(f.directory), result = await readSiwcCredentials(f.directory, controls());
  assert.equal(result.accessToken, f.record.accessToken); assert.equal(result.expiresAt, f.record.expiresAt); assert.deepEqual(Object.keys(result).sort(), ['accessToken','expiresAt']);
  assert.deepEqual(await receipts(f.directory), before);
});
test('expired, mismatched, inactive, wrong issuer, missing scopes and unsafe header records are refused', async () => {
  for (const mutate of [r => { r.expiresAt = Date.now() - 1; }, r => { r.clientId = 'oaiapp_other'; }, r => { r.state = 'revoked'; },
    r => { r.issuer = 'https://example.invalid'; }, r => { r.scopes = ['openid']; }, r => { r.accessToken += '\r\nheader'; }, r => { r.accessToken = 'synthetic-\u00e9'; }]) {
    const f = await fixture(); mutate(f.record); await fs.writeFile(path.join(f.directory,'credentials.json'),JSON.stringify(f.record)); const before = await receipts(f.directory);
    await assert.rejects(readSiwcCredentials(f.directory,controls()),error => /^ai_credentials_(expired|unverified)$/.test(error.code)); assert.deepEqual(await receipts(f.directory),before);
  }
});
test('an existing auth operation lock prevents access and is preserved', async () => {
  const f=await fixture(); await fs.writeFile(path.join(f.directory,'operation.lock'),'synthetic-owner',{flag:'wx',mode:0o600}); const before=await receipts(f.directory);
  await assert.rejects(readSiwcCredentials(f.directory,controls()),/ai_credentials_locked/); assert.deepEqual(await receipts(f.directory),before);
});
test('hardlinked and directory credential records are rejected', async () => {
  for (const kind of ['hardlink','directory']) {
    const f=await fixture(),file=path.join(f.directory,'credentials.json'); await fs.rename(file,path.join(f.directory,'original.json'));
    if(kind==='hardlink')await fs.link(path.join(f.directory,'original.json'),file); else await fs.mkdir(file);
    await assert.rejects(readSiwcCredentials(f.directory,controls()),/ai_file_kind/);
  }
});
test('junction stores are rejected without following them', async () => {
  const f=await fixture(), holder=await privateWorkspace();
  test.after(() => removeTempDir(holder));
  const link=path.join(holder,'linked'); await fs.symlink(f.directory,link,'junction');
  await assert.rejects(readSiwcCredentials(link,controls()),/ai_file_alias/);
});

test('an inherited child store is refused unless its own permissions protect the store root', async () => {
  const f = await fixture(), directory = path.join(f.directory, 'inherited'); await fs.mkdir(directory);
  for (const name of ['registration.json', 'credentials.json']) await fs.copyFile(path.join(f.directory, name), path.join(directory, name));
  const before = await receipts(directory);
  await assert.rejects(readSiwcCredentials(directory, controls()), /ai_credentials_permissions/);
  assert.deepEqual(await receipts(directory), before);
});
test('invalid UTF-8 and oversized saved records fail without writes', async () => {
  for (const bytes of [Buffer.from([0xff]), Buffer.alloc(8*1024*1024+1,32)]) {
    const f=await fixture(); await fs.writeFile(path.join(f.directory,'credentials.json'),bytes); const before=await receipts(f.directory);
    await assert.rejects(readSiwcCredentials(f.directory,controls()),error => ['ai_file_json','ai_file_limit'].includes(error.code)); assert.deepEqual(await receipts(f.directory),before);
  }
});
test('pre-aborted and invalid controls cannot read or alter the store', async () => {
  const f=await fixture(),before=await receipts(f.directory),abort=new AbortController();abort.abort();
  await assert.rejects(readSiwcCredentials(f.directory,controls(abort.signal)),/ai_stopped/);
  await assert.rejects(readSiwcCredentials(f.directory,{...controls(),cleanupTimeoutMs:Infinity}),/ai_credentials_control/); assert.deepEqual(await receipts(f.directory),before);
});
