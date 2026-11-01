import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { mkdir, mkdtemp, writeFile, readFile, stat, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { verifyFinding } from '../src/job-runner.ts';
import { readVerification } from '../src/reproduction.ts';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { defaults } from '../src/config.ts';
import { emptyRun } from '../src/engine-run.ts';
import { decide, exitCodes } from '../src/policy.ts';
import { digest, hash } from '../src/safety.ts';
import type { Report } from '../src/model.ts';

const profilePath = process.env.SCANMUX_REPRO_PROFILE;
test('real offline Linux job: vulnerable/fixed committed fixture with an unchanged retained regression', {
  skip: !profilePath && 'requires SCANMUX_REPRO_PROFILE naming an existing offline job profile and locally present image; no pull/build/host probe',
}, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'repro-real-')), root = path.join(directory, 'source');
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(root, '.git', 'objects'), { recursive: true });
  await mkdir(path.join(root, '.git', 'refs'), { recursive: true });
  // Construct only this disposable fixture's Git data. No git commit, checkout,
  // branch command, hooks or target code runs on the host.
  const object = async (kind: string, bytes: Buffer) => {
    const raw = Buffer.concat([Buffer.from(`${kind} ${bytes.length}\0`), bytes]), oid = createHash('sha1').update(raw).digest('hex');
    await mkdir(path.join(root, '.git', 'objects', oid.slice(0, 2)), { recursive: true });
    await writeFile(path.join(root, '.git', 'objects', oid.slice(0, 2), oid.slice(2)), deflateSync(raw)); return oid;
  };
  const probe = Buffer.from("import {pathToFileURL} from 'node:url';\nimport {join} from 'node:path';\nexport default async function({projectRoot}){const {allows}=await import(pathToFileURL(join(projectRoot,'src/access.mjs')).href);return {kind:'observed',problem:allows('../private')?'present':'absent'};}\n");
  const beforeFiles = new Map([['src/access.mjs', Buffer.from('export const allows = name => true;\n')], ['tests/repro/test.mjs', probe]]);
  const afterFiles = new Map(beforeFiles); afterFiles.set('src/access.mjs', Buffer.from("export const allows = name => !name.includes('..');\n"));
  const version = async (files: Map<string, Buffer>, parent?: string) => {
    const manifest: Report['plan']['files'] = [];
    for (const [name, bytes] of [...files].sort(([a], [b]) => a < b ? -1 : 1)) manifest.push({ path: name, oid: await object('blob', bytes), bytes: bytes.length, sha256: hash(bytes) });
    const tree = async (prefix = ''): Promise<string> => {
      const rows: { key: string; mode: string; name: string; oid: string }[] = [], directories = new Set<string>();
      for (const file of manifest.filter(file => file.path.startsWith(prefix))) {
        const name = file.path.slice(prefix.length), slash = name.indexOf('/');
        if (slash === -1) rows.push({ key: name, mode: '100644', name, oid: file.oid }); else directories.add(name.slice(0, slash));
      }
      for (const name of directories) rows.push({ key: name + '/', mode: '40000', name, oid: await tree(prefix + name + '/') });
      rows.sort((a, b) => a.key < b.key ? -1 : 1);
      return object('tree', Buffer.concat(rows.flatMap(row => [Buffer.from(row.mode + ' ' + row.name + '\0'), Buffer.from(row.oid, 'hex')])));
    };
    const treeHash = await tree(), commit = await object('commit', Buffer.from(`tree ${treeHash}\n${parent ? 'parent ' + parent + '\n' : ''}author Fixture <fixture@example.invalid> 1793404800 +0000\ncommitter Fixture <fixture@example.invalid> 1793404800 +0000\n\nSynthetic reproduction fixture\n`));
    return { commit, treeHash, manifest };
  };
  const before = await version(beforeFiles), after = await version(afterFiles, before.commit);
  for (const [name, bytes] of afterFiles) { await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), bytes); }
  await writeFile(path.join(root, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = false\n');
  await writeFile(path.join(root, '.git', 'HEAD'), after.commit + '\n');
  const entries = [];
  for (const file of after.manifest) {
    const stats = await stat(path.join(root, file.path)), name = Buffer.from(file.path), header = Buffer.alloc(62);
    const fields = [Math.floor(stats.ctimeMs / 1000), Math.floor(stats.ctimeMs % 1000 * 1000000), Math.floor(stats.mtimeMs / 1000), Math.floor(stats.mtimeMs % 1000 * 1000000),
      stats.dev, stats.ino, 0o100644, stats.uid, stats.gid, file.bytes];
    fields.forEach((value, index) => header.writeUInt32BE(value >>> 0, index * 4)); Buffer.from(file.oid, 'hex').copy(header, 40); header.writeUInt16BE(name.length, 60);
    entries.push(Buffer.concat([header, name, Buffer.alloc(8 - (62 + name.length) % 8)]));
  }
  const indexHeader = Buffer.alloc(12); indexHeader.write('DIRC'); indexHeader.writeUInt32BE(2, 4); indexHeader.writeUInt32BE(entries.length, 8);
  const index = Buffer.concat([indexHeader, ...entries]); await writeFile(path.join(root, '.git', 'index'), Buffer.concat([index, createHash('sha1').update(index).digest()]));
  const plan: Report['plan'] = { schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: hash(root), commit: before.commit, treeHash: before.treeHash,
    snapshotHash: digest(before.manifest), dirty: false, files: before.manifest, exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: [], required: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'],
    policyHash: digest(defaults), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 } };
  plan.planHash = digest(plan);
  const finding = { engine: 'codex-security' as const, fingerprint: hash('synthetic traversal finding') };
  const engines = plan.required.map(engine => {
    const run = emptyRun(engine, { plan, config: defaults, workspace: '/work', snapshot: '/work/snapshot', secretsCleared: true, signal: new AbortController().signal });
    run.execution = 'completed'; run.coverage = 'analyzed';
    if (engine === finding.engine) run.findings.push({ ...finding, category: 'code', severity: 'critical', confidence: 'high', evidenceState: 'candidate', disposition: 'open', file: 'src/access.mjs', line: 1,
      title: 'Synthetic traversal finding', originIds: [], fixedVersions: [], reachability: 'unknown', knownExploited: 'unknown' }); return run;
  });
  const judgment = decide(plan, engines), report: Report = { schema: 'scanmux.report/v2', runId: '11111111-1111-4111-8111-111111111111', plan, engines, startedAt: '2026-10-31T00:00:00.000Z', endedAt: '2026-10-31T00:00:00.000Z',
    runner: { platform: 'linux', node: 'v24.22.1', imageDigest: null, isolation: 'local-static-only' }, executionState: 'completed', coverageState: 'complete', ...judgment, exitCode: exitCodes[judgment.gate], integrityErrors: [] };
  const reportPath = path.join(directory, 'source-report.json'), reportBytes = Buffer.from(JSON.stringify(report) + '\n'); await writeFile(reportPath, reportBytes);
  const result = await verifyFinding(root, profilePath!, { reportPath, finding, testDirectory: 'tests/repro', mode: { kind: 'before_after', base: before.commit, head: after.commit } }, new AbortController().signal);
  t.after(() => rm(path.dirname(result.files.json), { recursive: true, force: true }));
  const saved = await readVerification(path.dirname(result.files.json));
  assert.equal(saved.verification.kind, 'same_test_no_longer_reproduces'); assert.equal(saved.assessment.gate, 'FAIL'); assert.equal(saved.runtimeEvidence?.state, 'runtime_reproduced');
  assert.deepEqual(await readFile(path.join(root, 'tests/repro/test.mjs')), probe); assert.deepEqual(await readFile(reportPath), reportBytes);
  assert.equal(saved.attempts?.kind, 'before_after');
  if (saved.attempts?.kind === 'before_after' && 'job' in saved.attempts.after) {
    assert.equal(saved.attempts.before.job?.container, 'verified_removed'); assert.equal(saved.attempts.after.job?.container, 'verified_removed');
    assert.equal(saved.attempts.before.binding?.testId, saved.attempts.after.binding?.testId);
  }
});
