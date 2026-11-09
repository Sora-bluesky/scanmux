import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { removeTempDir } from './temp-cleanup.mjs';
import { parsePins, scenarioOf, targetOf } from '../scripts/ci-produce.mjs';
import { optionalFeatures, producerWorkflowPath, testsWorkflowPath } from '../src/github-ci.ts';

const controller = 'c'.repeat(40), target = 'e'.repeat(40);

test('pins: closed schema, exact versions and the producer-only scenario', async () => {
  const pins = JSON.parse(await readFile('.github/scanmux/pins.json', 'utf8'));
  assert.deepEqual(Object.keys(parsePins(pins).tools), ['gitleaks', 'osv']);
  assert.equal(pins.tools.gitleaks.version, '8.30.1');
  assert.equal(pins.tools.osv.version, '2.7.0');
  assert.throws(() => parsePins({ ...pins, extra: true }), /invalid_pins/);
  assert.throws(() => parsePins({ ...pins, tools: { ...pins.tools, osv: { ...pins.tools.osv, url: 'https://example.com/osv.exe' } } }), /invalid_pins/);
  assert.equal(scenarioOf('workflow_dispatch', { inputs: { scenario: 'skip-scan' } }), 'skip-scan');
  assert.equal(scenarioOf('workflow_run', { inputs: { scenario: 'skip-scan' } }), 'none');
  assert.throws(() => scenarioOf('workflow_dispatch', { inputs: { scenario: 'rm -rf' } }), /invalid_scenario/);
  assert.equal(targetOf('workflow_run', { workflow_run: { head_sha: target, path: testsWorkflowPath } }, controller), target);
  assert.equal(targetOf('workflow_dispatch', {}, controller), controller);
  assert.throws(() => targetOf('workflow_run', { workflow_run: { head_sha: target, path: '.github/workflows/other.yml' } }, controller), /invalid_target/);
  assert.throws(() => targetOf('pull_request', {}, controller), /invalid_target/);
});

for (const [name, change, code] of [
  ['documented outcome with findings', () => {}, 0],
  ['ERROR', (_manifest, claim) => { claim.gate = 'ERROR'; claim.exitCode = 4; }, 4],
  ['FAIL', (_manifest, claim) => { claim.gate = 'FAIL'; claim.exitCode = 1; }, 1],
  ['PASS', (_manifest, claim) => { claim.gate = 'PASS'; claim.exitCode = 0; }, 1],
  ['wrong exit code', (_manifest, claim) => { claim.exitCode = 2; }, 2],
  ['integrity error', (_manifest, _claim, report) => { report.integrityErrors = ['report_hash_mismatch']; }, 3],
  ['second engine not started', (_manifest, _claim, report) => { report.engines[0].execution = 'not_started'; }, 3],
  ['codex-security completed', (_manifest, _claim, report) => { report.engines[2].execution = 'completed'; }, 3],
  ['report not completed', (_manifest, _claim, report) => { report.executionState = 'cancelled'; }, 3],
  ['failed manifest', manifest => { manifest.outcome = { kind: 'failed', stage: 'check', code: 'ci_check_failed' }; }, 4],
]) test(`Gate: ${name}`, async t => {
  const temp = await mkdtemp(path.join(tmpdir(), 'scanmux-producer-gate-'));
  t.after(() => removeTempDir(temp));
  const directory = path.join(temp, 'scanmux', 'delivery');
  await mkdir(directory, { recursive: true });
  const claim = { schema: 'scanmux.ci-result/v1', gate: 'INCOMPLETE', exitCode: 3 };
  const report = { executionState: 'completed', integrityErrors: [], findings: [{ engine: 'osv', severity: 'high' }],
    engines: ['gitleaks', 'osv', 'codex-security', 'runtime-advisories'].map(engine => ({ engine, execution: engine === 'codex-security' ? 'not_started' : 'completed' })) };
  const manifest = { schema: 'scanmux.github-delivery/v1',
    github: { repositoryId: 42, repository: 'example/scanmux', workflowPath: producerWorkflowPath, runId: 1001, attempt: 1, event: 'workflow_dispatch', runHeadSha: controller },
    source: null, targetHeadSha: controller, controllerSha: controller, pinsSha256: 'a'.repeat(64), ciRun: '11111111-2222-4333-8444-555555555555', scenario: 'none',
    git: { path: 'C:\\Program Files\\Git\\cmd\\git.exe', sha256: '1'.repeat(64), version: '2.51.0' }, outcome: { kind: 'produced' }, optional: optionalFeatures, files: [] };
  change(manifest, claim, report);
  const files = new Map([['ci-result.json', JSON.stringify(claim) + '\n'], ['report.json', JSON.stringify(report) + '\n']]);
  manifest.files = [...files].map(([name, text]) => ({ path: name, bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') }));
  files.set('manifest.json', JSON.stringify(manifest) + '\n');
  for (const [name, text] of files) await writeFile(path.join(directory, name), text);
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/ci-produce.mjs', 'gate'], { windowsHide: true,
      env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, RUNNER_TEMP: temp, GITHUB_EVENT_NAME: 'workflow_dispatch' }, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = [];
    child.stdout.on('data', chunk => out.push(chunk)); child.stderr.on('data', chunk => err.push(chunk)); child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
  assert.equal(result.code, code, result.stderr);
  assert.match(result.stdout, code === 0 ? /documented offline outcome: matched\./ : /documented offline outcome: did not match/);
  if (manifest.outcome.kind === 'failed') assert.match(result.stdout, /producer failed at check \(ci_check_failed\); exit 4\./);
  else assert.ok(result.stdout.includes(`ScanMux self-scan claim: ${claim.gate} (exit ${claim.exitCode}).\n`));
  if (claim.gate === 'PASS') assert.match(result.stdout, /unexpected PASS/);
  assert.equal(result.stdout.trim().split('\n').length, 2);
  for (const [name, text] of files) assert.equal(await readFile(path.join(directory, name), 'utf8'), text, `${name} stays unchanged`);
});
