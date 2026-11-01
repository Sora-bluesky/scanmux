import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { catalogIdentity } from '../src/advisory-catalog.ts';
import { createAdapters } from '../src/adapters.ts';
import { loadConfig } from '../src/config.ts';
import { scan } from '../src/controller.ts';
import { FrameDecoder } from '../src/process-tree.ts';
import { decide, exitCodes, type PolicyEngine, type PolicyFinding } from '../src/policy.ts';
import { digest, hash } from '../src/safety.ts';
import type { AdapterContext, Config, Engine, EngineRun, Execution, Finding, Plan } from '../src/model.ts';
import { contained } from './process-owner.ts';

const launches: string[] = [];
// On Windows a tool starts as a START frame (kind 2 in src/process-tree.ts) written to the process owner, not as a child_process call.
const ownerStartFrame = 2;
function countOwnerStarts(child: childProcess.ChildProcess): void {
  const stdin = child.stdin;
  if (!stdin) return;
  const decoder = new FrameDecoder(64 * 1024 * 1024), write = stdin.write.bind(stdin) as (chunk: Buffer, ...rest: unknown[]) => boolean;
  stdin.write = ((chunk: Buffer, ...rest: unknown[]) => {
    for (const frame of decoder.push(chunk)) if (frame.kind === ownerStartFrame) launches.push('owner-start');
    return write(chunk, ...rest);
  }) as typeof stdin.write;
}
for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'exec', 'execSync', 'fork'] as const) {
  const original = childProcess[name] as (...args: unknown[]) => unknown;
  (childProcess as unknown as Record<string, unknown>)[name] = function (this: unknown, ...args: unknown[]) {
    launches.push(name);
    const child = Reflect.apply(original, this, args);
    if (name === 'spawn' && path.basename(String(args[0])) === 'scanmux-windows-process-owner.exe') countOwnerStarts(child as childProcess.ChildProcess);
    return child;
  };
}
syncBuiltinESMExports();

type Exhaustive<All, Listed> = [Exclude<All, Listed>] extends [never] ? true : false;
const executions = ['completed', 'failed', 'cancelled', 'budget_exceeded', 'not_started'] as const satisfies readonly Execution[];
const coverages = ['analyzed', 'unsupported', 'skipped', 'partial'] as const satisfies readonly EngineRun['coverage'][];
const categories = ['secret', 'dependency', 'code', 'runtime', 'misconfiguration'] as const satisfies readonly Finding['category'][];
const severities = ['critical', 'high', 'medium', 'low', 'informational', 'unknown'] as const satisfies readonly Finding['severity'][];
const evidenceStates = ['candidate', 'source_supported', 'runtime_reproduced'] as const satisfies readonly Finding['evidenceState'][];
const engines = createAdapters().map(adapter => adapter.capabilities().engine);
// tsc rejects this line when a union member is missing from the lists above; CI runs tsc in its Typecheck step.
const listed: [
  Exhaustive<Execution, typeof executions[number]>, Exhaustive<EngineRun['coverage'], typeof coverages[number]>,
  Exhaustive<Finding['category'], typeof categories[number]>, Exhaustive<Finding['severity'], typeof severities[number]>,
  Exhaustive<Finding['evidenceState'], typeof evidenceStates[number]>,
] = [true, true, true, true, true];

type Slot = { execution: Execution; coverage: EngineRun['coverage'] } | null;
const slots: Slot[] = [null, ...executions.flatMap(execution => coverages.map(coverage => ({ execution, coverage })))];
const findingKinds: PolicyFinding[] = categories.flatMap(category => severities.flatMap(severity => evidenceStates.map(evidenceState => ({ category, severity, evidenceState }))));
const findingSets: PolicyFinding[][] = [[], ...findingKinds.map(f => [f]), ...findingKinds.flatMap((f, i) => findingKinds.slice(i + 1).map(g => [f, g]))];
const flagSets = [0, 1, 2, 3, 4, 5, 6, 7].map(bits => ({ blocked: Boolean(bits & 1), excluded: Boolean(bits & 2), integrity: Boolean(bits & 4) }));

/** The stated invariant, written from the documented conditions rather than from decide(). */
function passAllowed(required: readonly Engine[], runs: PolicyEngine[], flags: typeof flagSets[number]): boolean {
  const done = required.every(id => runs.some(run => run.engine === id && run.execution === 'completed' && run.coverage === 'analyzed'));
  const quiet = runs.every(run => run.execution !== 'failed' && run.findings.every(f => f.category !== 'secret' && !['critical', 'high', 'unknown'].includes(f.severity)));
  return done && quiet && !flags.blocked && !flags.excluded && !flags.integrity;
}
function judge(required: readonly Engine[], runs: PolicyEngine[], flags: typeof flagSets[number], seen: { total: number; pass: number; wrong: string[] }): void {
  const plan = { required: [...required], blockers: flags.blocked ? ['blocked'] : [], exclusions: flags.excluded ? [{ path: 'x', reason: 'excluded' }] : [] };
  const { gate } = decide(plan, runs, flags.integrity ? ['snapshot_changed'] : []);
  seen.total++; if (gate === 'PASS') seen.pass++;
  if ((gate === 'PASS') !== passAllowed(required, runs, flags) && seen.wrong.length < 5) seen.wrong.push(JSON.stringify({ gate, runs, flags }));
}

test('PASS appears exactly when every required engine completed with full coverage and nothing downgrades it', () => {
  assert.deepEqual([...engines].sort(), ['codex-security', 'gitleaks', 'osv', 'runtime-advisories'], 'every engine the code models is required here');
  const seen = { total: 0, pass: 0, wrong: [] as string[] };
  const product = (index: number, runs: PolicyEngine[]): void => {
    if (index === engines.length) { for (const flags of flagSets) judge(engines, runs, flags, seen); return; }
    for (const slot of slots) product(index + 1, slot ? [...runs, { engine: engines[index], ...slot, findings: [] }] : runs);
  };
  product(0, []);
  assert.equal(seen.total, slots.length ** engines.length * flagSets.length);
  assert.deepEqual(seen.wrong, []);
  assert.equal(seen.pass, 1, 'only the all-complete, unflagged state passes when no finding exists');

  const clean = (): PolicyEngine[] => engines.map(engine => ({ engine, execution: 'completed', coverage: 'analyzed', findings: [] }));
  const before = seen.pass;
  const placements = (count: number): number[][] => count === 0 ? [[]] : placements(count - 1).flatMap(rest => engines.map((_, index) => [index, ...rest]));
  let split = 0;
  for (const findings of findingSets) for (const placement of placements(findings.length)) for (const flags of flagSets) {
    const runs = clean();
    findings.forEach((finding, index) => runs[placement[index]].findings.push(finding));
    if (new Set(placement).size > 1) split++;
    judge(engines, runs, flags, seen);
  }
  assert.ok(split > 0, 'findings are also split across engines');
  findingSets.forEach((findings, index) => {
    for (const extra of slots) for (const flags of flagSets) {
      const runs = clean(); runs[index % engines.length].findings = findings;
      if (extra) runs.push({ engine: engines[(index + 1) % engines.length], ...extra, findings: [] });
      judge(engines, runs, flags, seen);
    }
  });
  assert.deepEqual(seen.wrong, []);
  assert.ok(seen.pass > before, 'some findings and duplicate runs still allow PASS, so the check is not vacuous');
});

test('the optional fifth required engine preserves the PASS invariant for every state, finding kind and downgrade', () => {
  const required: Engine[] = [...engines, 'trivy'];
  const clean = (): PolicyEngine[] => required.map(engine => ({ engine, execution: 'completed', coverage: 'analyzed', findings: [] }));
  const seen = { total: 0, pass: 0, wrong: [] as string[] };
  // Every state is placed on each required engine against a clean complement. Pairwise
  // states include the new engine and every old sibling; the v2 exhaustive product stays above.
  for (let index = 0; index < required.length; index++) for (const slot of slots) for (const flags of flagSets) {
    const runs = clean(); runs.splice(index, 1, ...(slot ? [{ engine: required[index], ...slot, findings: [] }] : []));
    judge(required, runs, flags, seen);
  }
  for (let sibling = 0; sibling < engines.length; sibling++) for (const left of slots) for (const right of slots) for (const flags of flagSets) {
    const runs = clean().filter((_, index) => index !== sibling && index !== required.length - 1);
    if (left) runs.push({ engine: engines[sibling], ...left, findings: [] });
    if (right) runs.push({ engine: 'trivy', ...right, findings: [] });
    judge(required, runs, flags, seen);
  }
  for (const finding of findingKinds) for (let index = 0; index < required.length; index++) for (const flags of flagSets) {
    const runs = clean(); runs[index].findings = [finding]; judge(required, runs, flags, seen);
  }
  assert.deepEqual(seen.wrong, []);
  assert.ok(seen.pass > 0, 'the additional engine does not make the invariant vacuous');
  assert.ok(seen.total < slots.length ** required.length, 'the new engine does not add a fifth exponential axis');
});

const plan = (root: string, config: Config): Plan => {
  const value: Plan = {
    schema: 'scanmux.plan/v2', advisoryCatalog: { ...catalogIdentity }, root, repoId: 'r', commit: 'a'.repeat(40), treeHash: 'b'.repeat(40), snapshotHash: 's', dirty: false,
    files: [{ path: 'source.ts', oid: 'a'.repeat(40), bytes: 10, sha256: 'c'.repeat(64) }], exclusions: [], blockers: [], languages: ['JS/TS'], lockfiles: [],
    required: [...engines], policyHash: digest(config), planHash: '', network: 'offline', transmissions: [], constraints: [], cost: { kind: 'not_applicable', aiCalls: 0 },
  };
  return { ...value, planHash: digest(value) };
};

test('a config whose tool pin is replaced by another valid digest starts no tool process', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-test-'));
  try {
    const marker = path.join(directory, 'tool-started');
    await writeFile(path.join(directory, 'version'), `require('node:fs').writeFileSync(${JSON.stringify(marker)}, '');\n`);
    const started = () => access(marker).then(() => true, () => false);
    const pinned = hash(await readFile(process.execPath));
    const replaced = (pinned[0] === '0' ? '1' : '0') + pinned.slice(1);
    const configured = async (sha256: string, name: string): Promise<Config> => {
      const file = path.join(directory, name);
      await writeFile(file, JSON.stringify({ schema: 1, tools: { gitleaks: { path: process.execPath, sha256, version: '8.30.1' } } }));
      return loadConfig(file);
    };
    const good = await configured(pinned, 'pinned.json'), mutated = await configured(replaced, 'mutated.json');
    assert.match(mutated.tools.gitleaks!.sha256, /^[a-f0-9]{64}$/, 'the replacement passes config validation');
    const context = (config: Config): AdapterContext => ({ plan: plan(path.resolve('test'), config), config, snapshot: directory, workspace: directory, signal: new AbortController().signal, secretsCleared: false });

    await contained(async () => {
      const before = launches.length;
      const refused = await createAdapters()[0].run(context(mutated));
      assert.deepEqual([launches.length, await started()], [before, false], 'no process starts for a replaced pin');
      assert.equal(refused.execution, 'failed'); assert.deepEqual(refused.errors, ['tool_digest_mismatch']);
      assert.equal(decide(context(mutated).plan, [refused]).gate, 'ERROR');

      const workspace = await mkdtemp(path.join(tmpdir(), 'scanmux-test-'));
      try {
        const report = await scan(plan(path.resolve('test'), good), mutated, workspace, new AbortController().signal);
        assert.deepEqual([report.gate, report.engines, report.integrityErrors], ['ERROR', [], ['plan_integrity']], 'a pin changed after planning is refused before any engine');
        assert.deepEqual([launches.length, await started()], [before, false]);
      } finally { await rm(workspace, { recursive: true, force: true }); }

      await createAdapters()[0].run(context(good));
      assert.ok(launches.length > before, `the launch counter sees the start on ${process.platform}`);
      assert.equal(await started(), true, 'the marker sees the start when the pin matches');
    });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const outsideFences = (text: string) => text.split(/\r?\n/).filter((_, index, lines) => lines.slice(0, index).filter(line => line.startsWith('```')).length % 2 === 0);
const headings = (text: string) => outsideFences(text).filter(line => /^#{1,6} /.test(line)).map(line => line.split(' ')[0]);
const sections = (text: string) => text.split(/^### /m).slice(1).map(body => body.split(/^## /m)[0]);
const labels = (section: string) => [...section.matchAll(/^\*\*(.+?)\*\*/gm)].map(match => match[1]);

test('docs/assumptions names only real gates and tool keys, and both languages share one structure', async () => {
  const english = await readFile('docs/assumptions.md', 'utf8'), japanese = await readFile('docs/assumptions.ja.md', 'utf8');
  for (const text of [english, japanese]) {
    const gates = new Set([...text.matchAll(/`([A-Z]{2,})`/g)].map(match => match[1]));
    assert.deepEqual([...gates].sort(), Object.keys(exitCodes).sort(), 'every gate named is a gate, and every gate is named');
  }
  const keys = (text: string) => [...new Set([...text.matchAll(/`tools\.([a-z-]+)`/g)].map(match => match[1]))].sort();
  assert.deepEqual(keys(japanese), keys(english));
  assert.ok(keys(english).length >= 4);
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-test-'));
  try {
    const tool = { path: process.execPath, sha256: 'a'.repeat(64), version: '1.0.0' };
    for (const key of [...keys(english), 'not-a-tool']) {
      const file = path.join(directory, `${key}.json`);
      await writeFile(file, JSON.stringify({ schema: 1, tools: { [key]: tool } }));
      if (key === 'not-a-tool') await assert.rejects(loadConfig(file), /invalid_tool/);
      else assert.deepEqual((await loadConfig(file)).tools[key as keyof Config['tools']], tool, `tools.${key} is a config key`);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }

  assert.deepEqual(headings(japanese), headings(english), 'same heading count and levels');
  const english4 = ['Assumption.', 'If it breaks.', 'How ScanMux or the user keeps it.', 'How it is checked.'];
  const japanese4 = ['前提。', '破れたら。', '守り方。', '検査。'];
  for (const [text, expected] of [[english, english4], [japanese, japanese4]] as const) {
    assert.ok(sections(text).length >= 7);
    for (const section of sections(text)) {
      assert.deepEqual(labels(section), expected, section.split('\n')[0]);
      assert.match(section.split(`**${expected[3]}**`)[1], text === english ? /\bnot a proof\b/ : /証明ではありません/, `${section.split('\n')[0]} says its check is not a proof`);
    }
  }
});
