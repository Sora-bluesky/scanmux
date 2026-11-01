import { removeTempDirStrict } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { defaults } from '../src/config.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import {
  checkReleaseLog, encodeEntry, independence, matchRelease, measureDirectory, measureSnapshot, outcomes, parseLog, parsePin, planRecord, verifyRelease, zeroHead,
  type LogEntry, type LogRead, type Release, type Snapshot,
} from '../src/release-transparency.ts';

const limits = { maxFiles: defaults.maxFiles, maxFileBytes: defaults.maxFileBytes, maxSnapshotBytes: defaults.maxSnapshotBytes };
const sha = (text: string | Buffer) => createHash('sha256').update(text).digest('hex');
type Item = string | Buffer | 'link' | 'other';
function memory(items: Record<string, Item>): Snapshot {
  const listing = new Map<string, { kind: 'file'; bytes: number } | { kind: 'link' } | { kind: 'other' }>(), data = new Map<string, Buffer>();
  for (const [name, value] of Object.entries(items)) {
    if (value === 'link' || value === 'other') { listing.set(name, { kind: value }); continue; }
    const bytes = Buffer.from(value); listing.set(name, { kind: 'file', bytes: bytes.length }); data.set(name, bytes);
  }
  return { listing, async *read(paths) { for (const name of paths) yield { path: name, content: data.get(name)! }; } };
}
const manifest = (files: unknown, version: unknown = '1.0.0') => JSON.stringify({ name: 'demo', version, files });
const base = (extra: Record<string, Item> = {}, files: unknown = ['bin', 'src', 'README.md']) => memory({
  'package.json': manifest(files), 'package-lock.json': '{}\n', 'README.md': 'readme\r\n', 'bin/demo.mjs': 'run\n', 'src/a.ts': 'a\n', 'src/deep/b.ts': 'b\n',
  'test/a.test.ts': 'not packaged\n', 'transparency/releases.jsonl': '', ...extra,
});

test('the measurement is sha256 of the domain prefix and the sorted package file set, ignoring files outside it', async () => {
  const measured = await measureSnapshot(base(), limits);
  const contents: Record<string, string> = { 'README.md': 'readme\r\n', 'bin/demo.mjs': 'run\n', 'package-lock.json': '{}\n', 'package.json': manifest(['bin', 'src', 'README.md']), 'src/a.ts': 'a\n', 'src/deep/b.ts': 'b\n' };
  const files = Object.keys(contents).sort().map(name => ({ path: name, bytes: Buffer.byteLength(contents[name]), sha256: sha(contents[name]) }));
  assert.deepEqual(measured.files, files);
  assert.deepEqual(measured.release, { version: '1.0.0', measurement: { schema: 'scanmux.release-measurement/v1',
    sha256: sha('scanmux.release-measurement/v1\n' + JSON.stringify(files)), files: 6, bytes: files.reduce((sum, file) => sum + file.bytes, 0) } });
  const outside = await measureSnapshot(base({ 'test/a.test.ts': 'changed\n', 'transparency/releases.jsonl': '{}\n' }), limits);
  assert.deepEqual(outside.release, measured.release, 'tests and the release log are outside the package file set');
  const changed = await measureSnapshot(base({ 'src/deep/b.ts': 'b2\n' }), limits);
  assert.notEqual(changed.release.measurement.sha256, measured.release.measurement.sha256);
});

test('each measurement refusal has its own closed reason', async () => {
  const cases: [string, Snapshot][] = [
    ['link', base({ 'src/linked.ts': 'link' })],
    ['link', base({ 'package.json': 'link' })],
    ['outside_root', base({}, ['../outside'])],
    ['outside_root', base({}, ['/abs'])],
    ['case_collision', base({ 'src/A.ts': 'x\n' })],
    ['not_regular', base({ 'src/module': 'other' })],
    ['over_limit', base({ 'src/big.ts': Buffer.alloc(limits.maxFileBytes + 1) })],
    ['listed_path_missing', base({}, ['bin', 'missing'])],
    ['listed_path_missing', memory({ 'package.json': manifest(['bin']), 'bin/x': 'x' })],
    ['invalid_package', base({ 'package.json': '{' })],
    ['invalid_package', base({}, 'bin')],
    ['invalid_package', base({}, ['src/*.ts'])],
    ['invalid_package', base({ 'package.json': manifest(['bin'], '1.0.0 && echo') })],
    ['unsupported_path', base({ 'src/q"uote.ts': 'x\n' })],
    ['unsupported_path', base({ 'src/é.ts': 'x\n' })],
  ];
  for (const [reason, snapshot] of cases) await assert.rejects(measureSnapshot(snapshot, limits), { code: `release_measurement_${reason}` }, reason);
  await assert.rejects(measureSnapshot(base(), { ...limits, maxFiles: 3 }), { code: 'release_measurement_over_limit' });
  await assert.rejects(measureSnapshot(base(), { ...limits, maxSnapshotBytes: 10 }), { code: 'release_measurement_over_limit' });
});

test('an installed directory with a junction or symbolic link inside the file set is refused as a link', async () => {
  const root = await privateWorkspace(process.cwd());
  try {
    const dir = path.join(root, 'installed');
    await fs.mkdir(path.join(dir, 'src'), { recursive: true }); await fs.mkdir(path.join(root, 'elsewhere'));
    await fs.writeFile(path.join(dir, 'package.json'), manifest(['src'])); await fs.writeFile(path.join(dir, 'package-lock.json'), '{}\n');
    await fs.writeFile(path.join(dir, 'src', 'a.ts'), 'a\n'); await fs.writeFile(path.join(root, 'elsewhere', 'b.ts'), 'b\n');
    const plain = await measureDirectory(dir, limits);
    assert.deepEqual(plain.files.map(file => file.path), ['package-lock.json', 'package.json', 'src/a.ts']);
    await fs.symlink(path.join(root, 'elsewhere'), path.join(dir, 'src', 'linked'), 'junction');
    await assert.rejects(measureDirectory(dir, limits), { code: 'release_measurement_link' });
  } finally { await removeTempDirStrict(root, { recursive: true, force: true }); }
});

const release = (version: string, digest: string): Release => ({ version, measurement: { schema: 'scanmux.release-measurement/v1', sha256: digest, files: 3, bytes: 10 } });
function logOf(...releases: [string, Release][]): { bytes: Buffer; entries: LogEntry[]; heads: string[] } {
  let prev = zeroHead, text = '';
  const entries: LogEntry[] = [], heads = [zeroHead];
  for (const [index, [commit, value]] of releases.entries()) {
    const entry = { seq: index + 1, prev, version: value.version, sourceCommit: commit, measurement: value.measurement };
    const line = encodeEntry(entry); text += line + '\n'; prev = sha(line); entries.push(entry); heads.push(prev);
  }
  return { bytes: Buffer.from(text), entries, heads };
}
const r1 = release('1.0.0', 'a'.repeat(64)), r2 = release('1.1.0', 'b'.repeat(64)), c1 = '1'.repeat(40), c2 = '2'.repeat(40);
const twoEntries = logOf([c1, r1], [c2, r2]);
const read = (bytes: Buffer | string): LogRead => ({ kind: 'bytes', bytes: Buffer.from(bytes) });

test('the log is canonical UTF-8 JSON lines whose prev chains the sha256 of the previous line', () => {
  const parsed = parseLog(twoEntries.bytes);
  assert.ok(parsed.ok);
  assert.deepEqual(parsed.log.entries, twoEntries.entries); assert.equal(parsed.log.head, twoEntries.heads[2]);
  assert.deepEqual(parseLog(Buffer.alloc(0)), { ok: true, log: { entries: [], hashes: [], head: zeroHead } });
  const line = twoEntries.bytes.toString().split('\n')[0];
  assert.equal(line, `{"seq":1,"prev":"${zeroHead}","version":"1.0.0","sourceCommit":"${c1}","measurement":{"schema":"scanmux.release-measurement/v1","sha256":"${'a'.repeat(64)}","files":3,"bytes":10}}`);
  const nonCanonical = ['﻿' + line + '\n', line + '\r\n', line, line.replace('{"seq":1,', '{"seq": 1,') + '\n', line.replace('}}', ',"extra":1}}') + '\n',
    line.replace('"files":3', '"files":"3"') + '\n', '\n', line + '\n' + line.replace('"seq":1', '"seq":2').replace(zeroHead, 'Z'.repeat(64)) + '\n'];
  for (const bytes of nonCanonical) assert.deepEqual(parseLog(Buffer.from(bytes)), { ok: false, reason: 'non_canonical' }, JSON.stringify(bytes));
  assert.deepEqual(parseLog(Buffer.from([0xff, 0x0a])), { ok: false, reason: 'non_canonical' });
  const lines = twoEntries.bytes.toString().split('\n');
  for (const broken of [[lines[1], lines[0]], [lines[0], lines[1].replace('"seq":2', '"seq":3')], [lines[0], lines[1].replace(twoEntries.heads[1], 'c'.repeat(64))],
    [line.replace(zeroHead, 'c'.repeat(64))]]) assert.deepEqual(parseLog(Buffer.from(broken.join('\n') + '\n')), { ok: false, reason: 'broken_chain' });
});

test('the pin is <entries>:<head> and zero names the empty log', () => {
  assert.deepEqual(parsePin(`2:${twoEntries.heads[2]}`), { entries: 2, head: twoEntries.heads[2] });
  assert.deepEqual(parsePin(`0:${zeroHead}`), { entries: 0, head: zeroHead });
  for (const value of ['', '2', `-1:${zeroHead}`, `1:${'A'.repeat(64)}`, `01:${zeroHead}`, `1.5:${zeroHead}`]) assert.throws(() => parsePin(value), { code: 'invalid_release_pin' });
});

test('decision table: each verify situation maps to its verdict, reason and exit code', async () => {
  const pinAll = { entries: 2, head: twoEntries.heads[2] }, pinFirst = { entries: 1, head: twoEntries.heads[1] };
  const rows: [string, LogRead, ReturnType<typeof parsePin> | null, Release, string, number][] = [
    ['logged inside the pin', read(twoEntries.bytes), pinAll, r2, 'logged', 0],
    ['logged without a pin is not owner-approved', read(twoEntries.bytes), null, r1, 'logged_unpinned', 3],
    ['measurement not in the log', read(twoEntries.bytes), pinAll, release('2.0.0', 'c'.repeat(64)), 'not_logged/measurement_absent', 3],
    ['version logged with another measurement', read(twoEntries.bytes), pinAll, release('1.1.0', 'c'.repeat(64)), 'not_logged/version_logged_with_other_measurement', 4],
    ['present only after the pin', read(twoEntries.bytes), pinFirst, r2, 'not_logged/after_pin', 3],
    ['broken chain', read(twoEntries.bytes.toString().split('\n').reverse().join('\n').slice(1) + '\n'), null, r1, 'log_tampered/broken_chain', 4],
    ['non-canonical line', read(twoEntries.bytes.toString().replace('"seq":1,', '"seq": 1,')), null, r1, 'log_tampered/non_canonical', 4],
    ['pin prefix mismatch', read(twoEntries.bytes), { entries: 1, head: 'd'.repeat(64) }, r1, 'log_tampered/pin_mismatch', 4],
    ['pin longer than the log', read(twoEntries.bytes), { entries: 3, head: twoEntries.heads[2] }, r1, 'log_tampered/pin_mismatch', 4],
    ['log missing', { kind: 'absent' }, null, r1, 'log_unreadable/log_missing', 3],
    ['log over limit', { kind: 'unreadable', reason: 'over_limit' }, null, r1, 'log_unreadable/over_limit', 3],
    ['git failed', { kind: 'unreadable', reason: 'git_failed' }, null, r1, 'log_unreadable/git_failed', 3],
    ['not a file', { kind: 'unreadable', reason: 'not_a_file' }, null, r1, 'log_unreadable/not_a_file', 3],
  ];
  for (const [name, log, pin, measured, outcome, exit] of rows) {
    let measuredCalls = 0;
    const result = await verifyRelease(log, pin, async () => { measuredCalls++; return measured; });
    assert.equal(result.outcome, outcome, name); assert.equal(outcomes[result.outcome], exit, name);
    if (!outcome.startsWith('log_')) assert.equal(measuredCalls, 1, name);
  }
  const parsed = parseLog(twoEntries.bytes);
  assert.ok(parsed.ok);
  assert.deepEqual(matchRelease(parsed.log, pinAll, r2), { outcome: 'logged', seq: 2 });
});

test('a hand-appended line with a valid chain is tampering when it reuses a version with another measurement or a source commit', async () => {
  const conflicts: [string, Buffer, string][] = [
    ['version_conflict', logOf([c1, r1], [c2, release('1.0.0', 'c'.repeat(64))]).bytes, 'same version, other measurement'],
    ['duplicate_commit', logOf([c1, r1], [c1, r2]).bytes, 'same source commit twice'],
  ];
  const one = logOf([c1, r1]);
  for (const [reason, bytes, name] of conflicts) {
    assert.deepEqual(parseLog(bytes), { ok: false, reason }, name);
    const verified = await verifyRelease(read(bytes), { entries: 1, head: one.heads[1] }, async () => r1);
    assert.deepEqual([verified.outcome, outcomes[verified.outcome]], [`log_tampered/${reason}`, 4], name);
    const checked = await checkReleaseLog(read(one.bytes), read(bytes), async entry => entry.sourceCommit === c1 ? r1 : null);
    assert.equal(checked.outcome, `log_tampered/${reason}`, name);
  }
  assert.ok(parseLog(logOf([c1, r1], [c2, r1]).bytes).ok, 'one version may name one measurement from two commits');
});

test('overlapping files entries select one file set, so a directory measures like its commit under the file limit', async () => {
  const tight = { ...limits, maxFiles: 4 };
  for (const files of [['src', 'src/deep', 'package-lock.json'], ['src', 'package-lock.json', 'src/deep']]) {
    const items = { 'package.json': manifest(files), 'package-lock.json': '{}\n', 'src/a.ts': 'a\n', 'src/deep/b.ts': 'b\n' };
    const fromSnapshot = await measureSnapshot(memory(items), tight);
    const root = await privateWorkspace(process.cwd());
    try {
      for (const [name, text] of Object.entries(items)) {
        await fs.mkdir(path.dirname(path.join(root, name)), { recursive: true }); await fs.writeFile(path.join(root, name), text);
      }
      assert.deepEqual(await measureDirectory(root, tight), fromSnapshot, files.join(','));
      await assert.rejects(measureDirectory(root, { ...limits, maxFiles: 3 }), { code: 'release_measurement_over_limit' });
    } finally { await removeTempDirStrict(root, { recursive: true, force: true }); }
  }
});

test('independence is lost when the running package is inside the verified repository or measures the same as the target', () => {
  const own = release('1.0.0', 'a'.repeat(64)).measurement, other = release('1.0.0', 'b'.repeat(64)).measurement;
  const root = path.resolve('/work/scanmux'), elsewhere = path.resolve('/work/other');
  assert.equal(independence(path.join(root, 'node_modules', 'scanmux'), root, own, other), false, 'package inside the repository');
  assert.equal(independence(root, root, own, other), false, 'package is the repository');
  assert.equal(independence(elsewhere, root, own, own), false, 'same measurement as the target');
  assert.equal(independence(elsewhere, root, null, other), false, 'own measurement unknown');
  assert.equal(independence(elsewhere, root, own, null), false, 'target unmeasured');
  assert.equal(independence(elsewhere, root, own, other), true);
});

test('decision table: log-check requires a byte prefix, a valid chain and reproducible entries', async () => {
  const one = logOf([c1, r1]);
  const reproduce = (map: Record<string, Release | null>) => async (entry: LogEntry) => map[entry.sourceCommit] ?? null;
  const good = reproduce({ [c1]: r1, [c2]: r2 });
  const rows: [string, LogRead | null, LogRead, (entry: LogEntry) => Promise<Release | null>, string][] = [
    ['appended after the base', read(one.bytes), read(twoEntries.bytes), good, 'consistent'],
    ['no base (dispatch)', null, read(twoEntries.bytes), good, 'consistent'],
    ['base without a log file', { kind: 'absent' }, read(twoEntries.bytes), good, 'consistent'],
    ['empty head log', read(''), read(''), good, 'consistent'],
    ['base not a prefix', read(logOf([c2, r2]).bytes), read(twoEntries.bytes), good, 'log_tampered/base_not_prefix'],
    ['an entry removed', read(twoEntries.bytes), read(one.bytes), good, 'log_tampered/base_not_prefix'],
    ['entry not reproducible', read(one.bytes), read(twoEntries.bytes), reproduce({ [c1]: r1, [c2]: release('1.1.0', 'e'.repeat(64)) }), 'log_tampered/not_reproducible'],
    ['source commit unavailable', read(one.bytes), read(twoEntries.bytes), reproduce({ [c1]: r1 }), 'log_tampered/not_reproducible'],
    ['head non-canonical', null, read(twoEntries.bytes.toString().replace('\n', '\r\n')), good, 'log_tampered/non_canonical'],
    ['head broken chain', null, read(logOf([c2, r2]).bytes.toString().replace('"seq":1', '"seq":2')), good, 'log_tampered/broken_chain'],
    ['head missing', null, { kind: 'absent' }, good, 'log_unreadable/log_missing'],
    ['head not a file', null, { kind: 'unreadable', reason: 'not_a_file' }, good, 'log_unreadable/not_a_file'],
    ['base unreadable', { kind: 'unreadable', reason: 'git_failed' }, read(twoEntries.bytes), good, 'log_unreadable/git_failed'],
  ];
  for (const [name, baseLog, headLog, check, outcome] of rows) {
    const result = await checkReleaseLog(baseLog, headLog, check);
    assert.equal(result.outcome, outcome, name);
  }
  const checked = await checkReleaseLog(read(one.bytes), read(twoEntries.bytes), good);
  assert.deepEqual(checked, { outcome: 'consistent', base: { state: 'present', entries: 1, head: one.heads[1] },
    head: { entries: 2, head: twoEntries.heads[2] }, reproduced: 2 });
});

test('record appends one entry against the expected head, is idempotent and refuses a conflicting version', () => {
  const empty = parseLog(Buffer.alloc(0)), one = parseLog(logOf([c1, r1]).bytes);
  assert.ok(empty.ok && one.ok);
  const first = planRecord(empty.log, zeroHead, c1, r1);
  assert.equal(first.state, 'appended'); assert.deepEqual(first.entry, logOf([c1, r1]).entries[0]);
  assert.equal(first.state === 'appended' && first.line, encodeEntry(first.entry) + '\n');
  assert.deepEqual(planRecord(one.log, zeroHead, c1, r1), { state: 'existing', entry: one.log.entries[0] });
  assert.deepEqual(planRecord(one.log, one.log.head, c1, r1), { state: 'existing', entry: one.log.entries[0] });
  const second = planRecord(one.log, one.log.head, c2, r2);
  assert.equal(second.state, 'appended'); assert.equal(second.entry.seq, 2); assert.equal(second.entry.prev, one.log.head);
  assert.throws(() => planRecord(one.log, zeroHead, c2, r2), { code: 'release_log_head_mismatch' });
  assert.throws(() => planRecord(one.log, one.log.head, c2, release('1.0.0', 'f'.repeat(64))), { code: 'release_version_logged_with_other_measurement' });
  assert.throws(() => planRecord(one.log, one.log.head, c1, r2), { code: 'release_commit_logged_with_other_measurement' });
});
