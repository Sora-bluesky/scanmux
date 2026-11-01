import assert from 'node:assert/strict';
import { lstat, rm } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { loadConfig } from '../src/config.ts';
import { privateWorkspace } from '../src/private-storage.ts';
import { buildPlan, prepareGitHubPlan } from '../src/repository.ts';
import { scan } from '../src/controller.ts';
import { checkedJson, saveReport } from '../src/output.ts';

const config = await loadConfig(process.argv[2]);
const workspace = await privateWorkspace();
let removable = true;
try {
  const plan = await prepareGitHubPlan('https://github.com/octocat/Hello-World', config, workspace);
  if (plan.blockers.some(code => code.endsWith('termination_unverified'))) removable = false;
  assert.deepEqual(plan.blockers, []);
  assert.match(plan.commit!, /^[0-9a-f]{40}$/);
  assert.equal(plan.source?.commit, plan.commit);
  assert.ok(plan.files.some(file => file.path === 'README'));
  assert.equal(await lstat(path.join(plan.root, 'README')).catch(() => null), null, 'No checkout');
  const strictLocal = await buildPlan(plan.root, config, workspace);
  assert.ok(strictLocal.blockers.includes('unsupported_git_layout'), 'Acquired receipt cannot be replaced by local API');
  await checkedJson({ commit: plan.commit, files: plan.files.length }, config, workspace);
  await checkedJson({ commit: plan.commit, exclusions: plan.exclusions.length }, config, workspace);
  const report = await scan(plan, config, workspace, new AbortController().signal);
  if (report.integrityErrors.some(code => code.endsWith('termination_unverified'))) removable = false;
  assert.equal(report.engines[0].execution, 'completed');
  assert.equal(report.engines[2].execution, 'not_started');
  assert.equal(report.gate, 'INCOMPLETE');
  const reportFile = await saveReport(report, config, workspace);
  console.log(JSON.stringify({ verified: 'public fixed commit; no checkout; local bypass refused; repeated output checks; real static scan', commit: plan.commit, files: plan.files.length, gate: report.gate, reportFile }));
} catch (error) {
  if (error instanceof Error && error.message.endsWith('termination_unverified')) removable = false;
  throw error;
} finally {
  if (removable) await rm(path.join(workspace, 'repository'), { recursive: true, force: true });
}
const cancelledWorkspace = await privateWorkspace();
await assert.rejects(prepareGitHubPlan('https://github.com/octocat/Hello-World', config, cancelledWorkspace, AbortSignal.abort()), /cancelled/);
assert.equal(await lstat(path.join(cancelledWorkspace, 'repository')).catch(() => null), null);
console.log('GITHUB_CHECKS_PASSED');
const activeWorkspace = await privateWorkspace();
const abort = new AbortController();
let finished = false;
let fetchRunning = false;
let fetchPid = 0;
const events: string[] = [];
const preparation = prepareGitHubPlan('https://github.com/octocat/Hello-World', config, activeWorkspace, abort.signal, (phase, state, pid) => {
  events.push(`${phase}:${state}`);
  if (phase === 'fetch') { fetchRunning = state === 'running'; if (pid) fetchPid = pid; }
})
  .then(plan => ({ plan, error: null }), error => ({ plan: null, error })).finally(() => { finished = true; });
while (!finished && !await lstat(path.join(activeWorkspace, 'repository', '.git', 'FETCH_HEAD')).catch(() => null)) await delay(5);
assert.equal(finished, false, 'Observe an active Git fetch before cancellation');
assert.equal(fetchRunning, true);
process.kill(fetchPid, 0);
events.push('user:abort');
abort.abort();
const cancelled = await preparation;
assert.match(cancelled.error?.message ?? '', /git_cancelled/);
assert.equal(await lstat(path.join(activeWorkspace, 'repository')).catch(() => null), null, 'Acquisition cleaned after verified stop');
assert.equal(fetchRunning, false);
assert.ok(!events.some(event => event.startsWith('bind:')));
assert.throws(() => process.kill(fetchPid, 0), { code: 'ESRCH' });
console.log(JSON.stringify({ verified: 'GITHUB_ACTIVE_CANCEL_PASSED', events }));
