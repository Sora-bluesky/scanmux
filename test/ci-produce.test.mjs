import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parsePins, scenarioOf, targetOf } from '../scripts/ci-produce.mjs';
import { testsWorkflowPath } from '../src/github-ci.ts';

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
