import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { jobRuntimeFiles } from '../src/job-runner.ts';
import { nativeSuitePassed } from '../scripts/ci-linux-job-native.mjs';

const summary = values => Object.entries({ tests: 18, pass: 18, fail: 0, cancelled: 0, skipped: 0, todo: 0, ...values })
  .map(([field, count]) => `# ${field} ${count}\n`).join('');
const result = (values = {}, overrides = {}) => ({ code: 0, signal: null, launchError: null, overflow: false,
  stdout: Buffer.from(summary(values)), ...overrides });

test('native suite gate requires complete, nonempty success without skips or cancellation', () => {
  assert.equal(nativeSuitePassed(result()), true);
  for (const counts of [{ tests: 0, pass: 0 }, { pass: 17, skipped: 1 }, { pass: 17, fail: 1 },
    { pass: 17, cancelled: 1 }, { pass: 17, todo: 1 }, { tests: 19 }]) {
    assert.equal(nativeSuitePassed(result(counts)), false, JSON.stringify(counts));
  }
  for (const overrides of [{ code: 1 }, { code: null }, { signal: 'SIGKILL' }, { launchError: 'spawn failed' },
    { overflow: true }, { stdout: Buffer.from('') }, { stdout: Buffer.from('# tests 18\n# pass 18\n') },
    { stdout: Buffer.from(summary({}) + summary({})) }]) {
    assert.equal(nativeSuitePassed(result({}, overrides)), false);
  }
});

test('Linux job integration has isolated read-only permissions and existing pinned actions', async () => {
  const workflow = await readFile('.github/workflows/checks.yml', 'utf8');
  const job = workflow.split('\n  linux-job-integration:\n')[1]?.split('\n  checks-linux:\n')[0];
  assert.ok(job);
  assert.match(job, /runs-on: ubuntu-24\.04\n/);
  assert.match(job, /timeout-minutes: [1-9][0-9]*\n/);
  assert.match(job, /permissions:\n {6}contents: read\n/);
  assert.match(job, /persist-credentials: false\n/);
  assert.doesNotMatch(job, /secrets\.|write|continue-on-error/);
  for (const action of ['checkout', 'setup-node', 'upload-artifact']) {
    const pattern = new RegExp(`uses: (actions/${action}@[0-9a-f]{40})`);
    const existing = await readFile('.github/workflows/offline-selfscan.yml', 'utf8');
    assert.equal(job.match(pattern)?.[1], existing.match(pattern)?.[1]);
  }
  assert.match(job, /run: bash scripts\/ci-linux-job\.sh\n/);
  // A job-level env cannot read the runner context; GitHub rejects the whole workflow file.
  assert.doesNotMatch(job, /^ {4}env:\n/m);
  assert.match(job, /path: \$\{\{ runner\.temp \}\}\/scanmux-linux-job\/evidence\/\n/);
});

test('Linux job source archive holds every job runtime file', async () => {
  const script = await readFile('scripts/ci-linux-job.sh', 'utf8');
  const archived = script.match(/tar --exclude=node_modules -cf "\$run\/source\.tar" -C "\$repository" -- \\n([^\n]*) \\n([^\n]*)\n/);
  assert.ok(archived);
  const roots = new Set(`${archived[1]} ${archived[2]}`.trim().split(/\s+/));
  for (const file of jobRuntimeFiles) assert.ok(roots.has(file.split('/')[0]), file);
});
