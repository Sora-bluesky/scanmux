import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, rename, writeFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { acquisitionBasis, acquisitionMarker, databaseUrl, markerName, osvEcosystems, receiptName, validateDatabaseReceipt } from '../src/osv-database.ts';
import { canonical, safeRelative, SafeError } from '../src/safety.ts';

export function parseAcquisitionArgs(args) {
  const fields = new Map(), allowed = ['--destination', '--ecosystems', '--max-bytes', '--timeout-ms'];
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    if (!allowed.includes(key) || fields.has(key) || typeof value !== 'string' || !value) throw new SafeError('invalid_acquisition_arguments');
    fields.set(key, value);
  }
  if (fields.size !== allowed.length) throw new SafeError('invalid_acquisition_arguments');
  const destination = fields.get('--destination');
  if (!path.isAbsolute(destination) || path.resolve(destination) !== destination || destination === path.parse(destination).root) throw new SafeError('invalid_acquisition_destination');
  safeRelative(path.basename(destination));
  const ecosystems = fields.get('--ecosystems').split(',');
  if (!ecosystems.length || new Set(ecosystems).size !== ecosystems.length || ecosystems.some(e => !osvEcosystems.includes(e))) throw new SafeError('invalid_database_ecosystem');
  const positive = key => {
    const value = fields.get(key);
    if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value))) throw new SafeError('invalid_acquisition_budget');
    return Number(value);
  };
  const maxBytes = positive('--max-bytes'), timeoutMs = positive('--timeout-ms');
  // Node timer's documented signed 32-bit range; do not silently clamp a budget.
  if (timeoutMs > 2147483647) throw new SafeError('invalid_acquisition_budget');
  return { destination, ecosystems, maxBytes, timeoutMs };
}
function responseMetadata(response, observedAt, remaining) {
  if (response.status !== 200 || response.redirected || !response.body) throw new SafeError('database_download_response_invalid');
  const length = response.headers.get('content-length'), generation = response.headers.get('x-goog-generation');
  const encoding = response.headers.get('content-encoding');
  if (!length || !/^[1-9][0-9]*$/.test(length) || !Number.isSafeInteger(Number(length)) ||
    !generation || !/^[1-9][0-9]*$/.test(generation) || (encoding !== null && encoding !== 'identity')) throw new SafeError('database_download_headers_invalid');
  if (Number(length) > remaining) throw new SafeError('database_download_byte_budget');
  const modified = response.headers.get('last-modified'), milliseconds = Date.parse(modified ?? '');
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toUTCString() !== modified || milliseconds > observedAt) throw new SafeError('database_download_time_invalid');
  const md5s = (response.headers.get('x-goog-hash') ?? '').split(',').map(v => v.trim()).filter(v => v.startsWith('md5='));
  if (md5s.length !== 1) throw new SafeError('database_download_hash_missing');
  const md5 = md5s[0].slice(4);
  if (!/^[A-Za-z0-9+/]{22}==$/.test(md5) || Buffer.from(md5, 'base64').toString('base64') !== md5) throw new SafeError('database_download_hash_invalid');
  return { bytes: Number(length), generation, sourceModifiedAt: new Date(milliseconds).toISOString(), md5 };
}
export async function acquireDatabase(options, dependencies = {}) {
  // Revalidate direct callers as well as the CLI before creating anything or fetching.
  const validated = parseAcquisitionArgs(['--destination', options.destination, '--ecosystems', options.ecosystems.join(','),
    '--max-bytes', String(options.maxBytes), '--timeout-ms', String(options.timeoutMs)]);
  const fetcher = dependencies.fetcher ?? fetch, now = dependencies.now ?? Date.now;
  const parent = await canonical(path.dirname(validated.destination));
  if (!(await lstat(parent)).isDirectory()) throw new SafeError('invalid_acquisition_destination');
  const destination = path.join(parent, path.basename(validated.destination));
  const signal = AbortSignal.timeout(validated.timeoutMs), startedAt = new Date(now()).toISOString();
  await mkdir(destination, { mode: 0o700 }); await canonical(destination);
  await writeFile(path.join(destination, markerName), acquisitionMarker, { flag: 'wx', mode: 0o600 });
  await mkdir(path.join(destination, 'osv-scalibr'), { mode: 0o700 });
  let totalBytes = 0; const entries = [];
  for (const ecosystem of validated.ecosystems) {
    signal.throwIfAborted();
    const url = databaseUrl(ecosystem), observedStartedAt = new Date(now()).toISOString();
    const response = await fetcher(url, { method: 'GET', redirect: 'error', credentials: 'omit', signal });
    const observedHeadersAt = now(); let metadata;
    try {
      if (response.url !== url) throw new SafeError('database_download_url_mismatch');
      metadata = responseMetadata(response, observedHeadersAt, validated.maxBytes - totalBytes);
    } catch (error) { await response.body?.cancel(); throw error; }
    const directory = path.join(destination, 'osv-scalibr', ecosystem);
    await mkdir(directory, { mode: 0o700 }); await canonical(directory);
    const partial = path.join(directory, 'all.zip.partial'), final = path.join(directory, 'all.zip');
    const sha = createHash('sha256'), md5 = createHash('md5'); let bytes = 0;
    const observer = new Transform({ transform(chunk, _encoding, callback) {
      bytes += chunk.length; totalBytes += chunk.length;
      if (bytes > metadata.bytes || totalBytes > validated.maxBytes) { callback(new SafeError('database_download_byte_budget')); return; }
      sha.update(chunk); md5.update(chunk); callback(null, chunk);
    } });
    await pipeline(Readable.fromWeb(response.body), observer, createWriteStream(partial, { flags: 'wx', mode: 0o600 }), { signal });
    if (bytes !== metadata.bytes) throw new SafeError('database_download_size_mismatch');
    if (md5.digest('base64') !== metadata.md5) throw new SafeError('database_download_digest_mismatch');
    signal.throwIfAborted(); await rename(partial, final);
    entries.push({ ecosystem, url, ...metadata, sha256: sha.digest('hex'), observedStartedAt, observedCompletedAt: new Date(now()).toISOString() });
  }
  signal.throwIfAborted();
  const receipt = validateDatabaseReceipt({ schema: 'scanmux.osv-database/v1', basis: acquisitionBasis,
    startedAt, completedAt: new Date(now()).toISOString(), entries }, now());
  await writeFile(path.join(destination, receiptName), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return receipt;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const receipt = await acquireDatabase(parseAcquisitionArgs(process.argv.slice(2)));
    console.log(JSON.stringify({ state: 'acquired', ecosystems: receipt.entries.map(e => e.ecosystem),
      bytes: receipt.entries.reduce((sum, e) => sum + e.bytes, 0), completedAt: receipt.completedAt, basis: receipt.basis }));
  } catch (error) {
    console.error(JSON.stringify({ state: 'failed', code: error instanceof SafeError ? error.code : 'database_acquisition_failed', completeReceipt: false }));
    process.exitCode = 4;
  }
}
