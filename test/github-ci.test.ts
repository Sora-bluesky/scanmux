import { removeTempDir } from './temp-cleanup.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  anchorLine, approvedPinsSha256, producerWorkflowSha256, artifactName, collectEvidence, controllerSteps, deliverySteps, gateStep, judgeGithubRun, manifestName,
  optionalFeatures, parseDeliveryManifest, producerStages, producerWorkflowPath, testsWorkflowPath, type GithubApi,
} from '../src/github-ci.ts';
import { evaluateCi, parseCiExpectation, parseCiReceipt } from '../src/ci.ts';
import { localHeader, zip } from './zip-fixture.ts';
import { hash, SafeError } from '../src/safety.ts';
import { withTestProcessOwner } from './process-owner.ts';

const repository = 'Sora-bluesky/scanmux', repoId = 42, runId = 1001, attempt = 1, artifactId = 5, producerJobId = 77, sourceRunId = 900;
const controller = 'c'.repeat(40), target = 'e'.repeat(40), ciRun = '11111111-2222-4333-8444-555555555555';
const workflowBytes = await readFile(producerWorkflowPath);
const json = (value: unknown) => Buffer.from(JSON.stringify(value, null, 2) + '\n');

type Files = Map<string, Buffer>;
function produced(gate: 'PASS' | 'INCOMPLETE' = 'INCOMPLETE', commit = target): Files {
  const root = 'D:\\a\\_temp\\scanmux\\target';
  const plan = { schema: 'scanmux.plan/v2', root, repoId: hash(root), commit, policyHash: 'a'.repeat(64), planHash: 'b'.repeat(64), snapshotHash: 'd'.repeat(64) };
  const engines = [{ engine: 'gitleaks', execution: 'completed', coverage: 'analyzed' }, { engine: 'osv', execution: 'completed', coverage: 'analyzed' },
    { engine: 'codex-security', execution: gate === 'PASS' ? 'completed' : 'not_started', coverage: gate === 'PASS' ? 'analyzed' : 'unsupported' },
    { engine: 'runtime-advisories', execution: 'completed', coverage: 'analyzed' }];
  const report = json({ schema: 'scanmux.report/v2', runId: '99999999-8888-4777-8666-555555555555', plan, gate, executionState: 'completed',
    coverageState: gate === 'PASS' ? 'complete' : 'incomplete', engines });
  const expected = parseCiExpectation({ schema: 'scanmux.ci-expectation/v1', ciRun, jobs: [{ id: 'selfscan', targetRoot: root, repoId: plan.repoId, commit,
    policyHash: plan.policyHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash }] });
  const receipt = parseCiReceipt({ schema: 'scanmux.ci-receipt/v1', ciRun, jobId: 'selfscan', reportRunId: '99999999-8888-4777-8666-555555555555', reportHash: hash(report),
    repoId: plan.repoId, commit, policyHash: plan.policyHash, planHash: plan.planHash, snapshotHash: plan.snapshotHash,
    gate, executionState: 'completed', coverageState: gate === 'PASS' ? 'complete' : 'incomplete', engines });
  return new Map([['ci-receipt.json', json(receipt)], ['ci-result.json', json(evaluateCi(expected, [receipt]))], ['config.json', json({ schema: 2 })],
    ['expected.json', json(expected)], ['osv-database-receipt.json', json({ schema: 'scanmux.osv-database/v1' })], ['plan.json', json(plan)], ['report.json', report]]);
}
interface Options {
  event?: 'workflow_run' | 'workflow_dispatch'; scenario?: string; outcome?: object; manifest?: (value: Record<string, any>) => void;
  files?: Files; seal?: boolean; gate?: 'PASS' | 'INCOMPLETE';
}
function delivery(options: Options = {}): Files {
  const event = options.event ?? 'workflow_run';
  const files = options.files ?? produced(options.gate, event === 'workflow_run' ? target : controller);
  const manifest: Record<string, any> = {
    schema: 'scanmux.github-delivery/v1',
    github: { repositoryId: repoId, repository, workflowPath: producerWorkflowPath, runId, attempt, event, runHeadSha: controller },
    source: event === 'workflow_run' ? { runId: sourceRunId, attempt: 1, event: 'pull_request', headSha: target, pr: 7 } : null,
    targetHeadSha: event === 'workflow_run' ? target : controller, controllerSha: controller, pinsSha256: approvedPinsSha256, ciRun, scenario: options.scenario ?? 'none',
    git: { path: 'C:\\Program Files\\Git\\cmd\\git.exe', sha256: '1'.repeat(64), version: '2.51.0' }, outcome: options.outcome ?? { kind: 'produced' },
    optional: optionalFeatures, files: [...files].sort(([a], [b]) => a < b ? -1 : 1).map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: hash(bytes) })),
  };
  options.manifest?.(manifest);
  return new Map([...files, [manifestName, json(manifest)]]);
}
const success = (name: string) => ({ name, status: 'completed', conclusion: 'success', number: 1 });
function producerSteps(conclusions: Record<string, string | null> = {}, gate = 'failure') {
  const names = [...controllerSteps, ...producerStages.map(item => item.step), ...deliverySteps, gateStep];
  return [success('Set up job'), ...names.map(name => ({ ...success(name), conclusion: Object.hasOwn(conclusions, name) ? conclusions[name] : name === gateStep ? gate : 'success' })), success('Complete job')];
}
interface Fixture {
  event?: 'workflow_run' | 'workflow_dispatch'; head?: string; delivery?: Files; zip?: Buffer; run?: Record<string, unknown>; ancestry?: string; workflow?: Buffer;
  jobs?: unknown[]; steps?: unknown[]; artifacts?: unknown[]; log?: string; source?: Record<string, unknown>; tests?: string; fail?: RegExp; invalid?: RegExp;
}
function api(fixture: Fixture = {}): GithubApi {
  const event = fixture.event ?? 'workflow_run', head = fixture.head ?? controller;
  const files = fixture.delivery ?? delivery({ event });
  const archive = fixture.zip ?? zip([...files]);
  const log = fixture.log ?? `\uFEFF2026-10-25T00:00:00.0000000Z ##[group]Run node scripts/ci-produce.mjs anchor\n2026-10-25T00:00:01.0000000Z ${anchorLine(hash(files.get(manifestName)!), artifactId, runId, attempt)}\n`;
  const base = `repos/${repository}`;
  const runs: Record<string, unknown> = {
    [base]: { id: repoId, full_name: repository, default_branch: 'main', private: true },
    [`${base}/actions/runs/${runId}/attempts/${attempt}`]: { id: runId, run_attempt: attempt, repository: { id: repoId }, path: producerWorkflowPath, event,
      status: 'completed', conclusion: 'failure', head_sha: head, display_title: 'offline-selfscan scenario=none', ...fixture.run },
    [`${base}/compare/${head}...main`]: { status: fixture.ancestry ?? 'ahead' },
    [`${base}/actions/runs/${runId}/attempts/${attempt}/jobs`]: { total_count: (fixture.jobs ?? [0]).length, jobs: fixture.jobs ?? [{ id: producerJobId, name: 'selfscan',
      run_attempt: attempt, status: 'completed', conclusion: 'failure', steps: fixture.steps ?? producerSteps() }] },
    [`${base}/actions/runs/${runId}/artifacts`]: { total_count: (fixture.artifacts ?? [0]).length, artifacts: fixture.artifacts
      ?? [{ id: artifactId, name: artifactName(runId, attempt), expired: false, workflow_run: { id: runId, head_sha: controller } }] },
    [`${base}/actions/runs/${sourceRunId}/attempts/1`]: { id: sourceRunId, run_attempt: 1, repository: { id: repoId }, path: testsWorkflowPath, event: 'pull_request',
      status: 'completed', conclusion: 'success', head_sha: target, ...fixture.source },
    [`${base}/actions/runs/${sourceRunId}/attempts/1/jobs`]: { total_count: 1, jobs: [{ id: 66, name: 'checks', run_attempt: 1, status: 'completed', conclusion: fixture.tests ?? 'success', steps: [] }] },
  };
  const bytes: Record<string, Buffer> = {
    [`${base}/contents/${producerWorkflowPath}?ref=${head}`]: fixture.workflow ?? workflowBytes,
    [`${base}/actions/artifacts/${artifactId}/zip`]: archive,
    [`${base}/actions/jobs/${producerJobId}/logs`]: Buffer.from(log),
  };
  const guard = (endpoint: string) => { if (fixture.fail?.test(endpoint)) throw new Error('fetch failed'); };
  return {
    json: async endpoint => {
      guard(endpoint);
      const key = endpoint.replace(/\?.*$/, '');
      if (fixture.invalid?.test(endpoint)) return { unexpected: true };
      if (!Object.hasOwn(runs, key)) throw new Error('not found');
      return structuredClone(runs[key]);
    },
    bytes: async endpoint => { guard(endpoint); if (!Object.hasOwn(bytes, endpoint)) throw new Error('not found'); return bytes[endpoint]; },
  };
}
const request = { repository, runId, attempt };
async function judge(fixture: Fixture = {}, local?: Files) { return judgeGithubRun(await collectEvidence(api(fixture), request, local)); }
function expectReason(result: Awaited<ReturnType<typeof judge>>, reason: string, exitCode: number, failedCheck: string) {
  assert.equal(result.reason, reason);
  assert.equal(result.exitCode, exitCode);
  assert.equal(result.checks.find(item => item.state === 'failed')?.check, failedCheck);
  const failed = result.checks.findIndex(item => item.state === 'failed');
  assert.ok(result.checks.slice(failed + 1).every(item => item.state === 'unknown'), 'nothing after the first failure is judged');
}

test('approved workflow constant is the sha256 of the committed producer workflow bytes', () => {
  assert.equal(hash(workflowBytes), producerWorkflowSha256);
});

test('approved pins constant is the sha256 of the committed pins file bytes', async () => {
  assert.equal(hash(await readFile('.github/scanmux/pins.json')), approvedPinsSha256);
});

test('workflows: step names match the verifier tables, actions are SHA pinned and no expression reaches a shell', async () => {
  const producer = workflowBytes.toString('utf8');
  const names = [...producer.matchAll(/^ {6}- name: (.+)$/gm)].map(match => match[1]);
  assert.deepEqual(names, [...controllerSteps, ...producerStages.map(item => item.step), ...deliverySteps, gateStep]);
  for (const file of [producerWorkflowPath, testsWorkflowPath, '.github/workflows/release.yml']) {
    const text = await readFile(file, 'utf8');
    assert.ok(!/\r/.test(text) && !/pull_request_target|secrets\.|continue-on-error/.test(text), `${file}: no CR, pull_request_target, secrets or continue-on-error`);
    for (const [, uses] of text.matchAll(/uses: (\S+)/g)) assert.match(uses, /^actions\/(?:checkout|setup-node|upload-artifact|attest-build-provenance)@[0-9a-f]{40}$/);
    const runBlocks = [...text.matchAll(/^( +)run: (\|\n(?:\1  .*\n)+|.*\n)/gm)].map(match => match[2]);
    assert.ok(runBlocks.length > 5 && runBlocks.every(block => !block.includes('${{')), `${file}: shell bodies take values only through env`);
  }
  assert.match(producer, /permissions:\n {2}contents: read\n {2}actions: read\n/);
  assert.match(producer, /^run-name: offline-selfscan scenario=\$\{\{ inputs\.scenario \|\| 'none' \}\}\n/m);
  assert.match(producer, /^concurrency:\n {2}group: offline-selfscan-\$\{\{ github\.event\.workflow_run\.head_sha \|\| github\.sha \}\}\n {2}cancel-in-progress: false\n/m);
  assert.match(await readFile(testsWorkflowPath, 'utf8'), /permissions:\n {2}contents: read\n\n/);
});

test('pull requests run the suite on Linux and macOS with the same pinned actions and Node as Windows', async () => {
  const text = await readFile(testsWorkflowPath, 'utf8');
  const [header, windows, integration, linux, macos] = text.split(/\n(?= {2}[a-z-]+:\n {4}name: )/);
  assert.match(header, /^on:\n {2}pull_request:\n/m);
  assert.deepEqual([windows, integration, linux, macos].map(job => job.match(/^ {2}([a-z-]+):/)?.[1]),
    ['checks', 'linux-job-integration', 'checks-linux', 'checks-macos']);
  assert.equal(text.split(/\n(?= {2}[a-z-]+:\n {4}name: )/).length, 5);
  for (const [job, runner] of [[linux, 'ubuntu-24.04'], [macos, 'macos-15']]) {
    assert.ok(job.includes('    runs-on: ' + runner + '\n'));
    assert.match(job, /^ {4}timeout-minutes: 25$/m);
    for (const action of ['checkout', 'setup-node']) {
      const pattern = new RegExp('uses: (actions/' + action + '@[0-9a-f]{40})');
      assert.equal(job.match(pattern)?.[1], windows.match(pattern)?.[1]);
    }
    for (const options of ['persist-credentials: false\n          fetch-depth: 0', 'node-version: 24.22.1\n          package-manager-cache: false']) {
      assert.ok(job.includes(options)); assert.ok(windows.includes(options));
    }
    assert.deepEqual([...job.matchAll(/^ {6}- name: (.+)$/gm)].map(match => match[1]),
      ['Check out head', 'Set up Node', 'Install dependencies', 'Typecheck', 'Test']);
    assert.doesNotMatch(job, /permissions:|ci-produce|SCANMUX_REAL_CONFIG|^ {4}if: /m);
  }
  assert.deepEqual([...linux.matchAll(/^ {8}run: (.+)$/gm)].map(match => match[1]),
    ['npm ci --ignore-scripts --no-audit --no-fund', 'npm run typecheck', 'npm test']);
  assert.deepEqual([...macos.matchAll(/^ {8}run: (.+)$/gm)].map(match => match[1]),
    ['npm ci --ignore-scripts --no-audit --no-fund', 'npm run typecheck', '|']);
  assert.ok(macos.endsWith(`        run: |\n          export TMPDIR="$(node -e 'process.stdout.write(require("node:fs").realpathSync(process.env.TMPDIR))')"\n          npm test\n`));
});

test('release workflow dry run attests the dispatched commit without tags or release access', async () => {
  const text = await readFile('.github/workflows/release.yml', 'utf8');
  const dryRun = text.slice(text.indexOf('\n  dry-run:\n'), text.indexOf('\n  release:\n'));
  assert.match(text, /^on:\n {2}push:\n {4}tags: \["v\*"\]\n {2}workflow_dispatch:\n {4}inputs:\n {6}tag:\n {8}description: Existing release tag \(leave empty for a dry run\)\n {8}required: false\n {8}type: string\n {8}default: ""\n/m);
  assert.match(text, /^permissions: \{\}\n/m);
  assert.equal([...text.matchAll(/permissions:/g)].length, 3);
  assert.equal([...text.matchAll(/contents: write/g)].length, 1);
  assert.match(dryRun, /^ {4}if: github\.event_name == 'workflow_dispatch' && inputs\.tag == ''$/m);
  assert.match(dryRun, /^ {4}permissions:\n {6}contents: read\n {6}id-token: write\n {6}attestations: write\n {4}env:/m);
  assert.match(dryRun, /COMMIT: "\$\{\{ github\.sha \}\}"/);
  assert.match(dryRun, /ref: "\$\{\{ github\.sha \}\}"\n {10}persist-credentials: false/);
  assert.ok(dryRun.includes('test "$(git rev-parse HEAD)" = "$COMMIT"'));
  assert.ok(dryRun.includes('echo "SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$COMMIT")" >> "$GITHUB_ENV"'));
  assert.ok(dryRun.includes("const { version } = JSON.parse(readFileSync('package.json', 'utf8'))"));
  assert.ok(dryRun.includes('appendFileSync(process.env.GITHUB_ENV, `VERSION=${version}\\n`)'));
  assert.doesNotMatch(dryRun, /\bgh\b|\bTAG\b|refs\/tags\/|releases\/|--draft|contents: write/);
  assert.match(dryRun, /run: npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(dryRun, /npm pack --ignore-scripts --pack-destination dist/);
  assert.ok(dryRun.includes('test -f "dist/scanmux-$VERSION.tgz"'));
  assert.ok(dryRun.includes('npm sbom --sbom-format cyclonedx > "dist/scanmux-$VERSION.cdx.json"'));
  assert.match(dryRun, /uses: actions\/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8[^\n]*\n {8}with:\n {10}subject-path: dist\/\*/);
  assert.ok(dryRun.includes('sha256sum -- "scanmux-$VERSION.tgz" "scanmux-$VERSION.cdx.json"\n          ) > SHA256SUMS'));
  assert.match(dryRun, /uses: actions\/upload-artifact@[0-9a-f]{40}[^\n]*\n {8}with:\n {10}name: scanmux-provenance-\$\{\{ github\.run_id \}\}-a\$\{\{ github\.run_attempt \}\}\n {10}path: \|\n {12}dist\/scanmux-\$\{\{ env\.VERSION \}\}\.tgz\n {12}dist\/scanmux-\$\{\{ env\.VERSION \}\}\.cdx\.json\n {12}SHA256SUMS\n {10}if-no-files-found: error\n {10}retention-days: 3/);
  const names = [...dryRun.matchAll(/^ {6}- name: (.+)$/gm)].map(match => match[1]);
  assert.deepEqual(names, ['Check out the dispatched commit', 'Set up Node', 'Set build metadata from the dispatched commit', 'Install dependencies',
    'Build the package and SBOM', 'Attest the build provenance', 'Generate SHA256 checksums', 'Upload provenance artifacts']);
});

test('release workflow binds draft artifacts to an existing version tag with minimal permissions and provenance', async () => {
  const text = await readFile('.github/workflows/release.yml', 'utf8');
  const release = text.slice(text.indexOf('\n  release:\n'));
  assert.match(release, /^ {4}if: github\.event_name == 'push' \|\| \(github\.event_name == 'workflow_dispatch' && inputs\.tag != ''\)$/m);
  assert.match(release, /^ {4}permissions:\n {6}contents: write\n {6}id-token: write\n {6}attestations: write\n {4}env:/m);
  assert.match(text, /^concurrency:\n {2}group: "release-\$\{\{ inputs\.tag \|\| github\.ref_name \}\}"\n {2}cancel-in-progress: false\n/m);
  assert.match(release, /TAG: "\$\{\{ inputs\.tag \|\| github\.ref_name \}\}"/);
  assert.ok(release.includes('[[ "$TAG" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+$ ]]'));
  assert.match(release, /ref: "refs\/tags\/\$\{\{ env\.TAG \}\}"\n {10}persist-credentials: false\n {10}fetch-depth: 0/);
  assert.ok(release.includes('tag_commit=$(git rev-parse --verify "refs/tags/$TAG^{commit}")\n          test "$(git rev-parse HEAD)" = "$tag_commit"'));
  assert.ok(release.includes("JSON.parse(readFileSync('package.json', 'utf8'))"));
  assert.ok(release.includes("if (process.env.TAG !== `v${version}`) throw new Error('Tag/package version mismatch')"));
  assert.match(release, /if release_response=\$\(gh api --include --silent "repos\/\$GITHUB_REPOSITORY\/releases\/tags\/\$TAG"\); then\n {12}echo "Release already exists" >&2\n {12}exit 1\n/);
  assert.ok(release.includes('if [[ ! "$status_line" =~ ^HTTP/[0-9.]+[[:space:]]404([[:space:]]|$) ]]; then\n            echo "Could not determine whether the release exists" >&2\n            exit 1'));
  assert.match(release, /run: npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(release, /npm pack --ignore-scripts --pack-destination dist/);
  assert.ok(release.includes('test -f "dist/scanmux-$VERSION.tgz"'));
  assert.ok(release.includes('npm sbom --sbom-format cyclonedx > "dist/scanmux-$VERSION.cdx.json"'));
  assert.match(release, /uses: actions\/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8[^\n]*\n {8}with:\n {10}subject-path: dist\/\*/);
  assert.ok(release.includes('sha256sum -- "scanmux-$VERSION.tgz" "scanmux-$VERSION.cdx.json"\n          ) > SHA256SUMS'));
  assert.ok(release.includes('gh release create "$TAG" "dist/scanmux-$VERSION.tgz" "dist/scanmux-$VERSION.cdx.json" SHA256SUMS --draft --verify-tag'));
  const names = [...release.matchAll(/^ {6}- name: (.+)$/gm)].map(match => match[1]);
  assert.deepEqual(names, ['Validate the release tag before checkout', 'Check out the release tag', 'Verify the checked-out commit and set build metadata',
    'Set up Node', 'Verify the tag and package versions', 'Refuse to overwrite an existing release', 'Install dependencies', 'Build the package and SBOM',
    'Attest the build provenance', 'Generate SHA256 checksums', 'Create a draft release']);
});

test('manifest: closed parse refuses extra keys, unknown scenarios and a produced outcome without a CI run', () => {
  const value = JSON.parse(delivery().get(manifestName)!.toString('utf8'));
  assert.equal(parseDeliveryManifest(value).outcome.kind, 'produced');
  for (const change of [(m: any) => { m.extra = 1; }, (m: any) => { m.scenario = 'other'; }, (m: any) => { m.ciRun = null; }, (m: any) => { m.files.reverse(); },
    (m: any) => { m.outcome = { kind: 'failed', stage: 'acquire', code: 'invented' }; }, (m: any) => { m.files[0].path = '../report.json'; }]) {
    const copy = structuredClone(value); change(copy);
    assert.throws(() => parseDeliveryManifest(copy), /manifest_invalid/);
  }
});

test('judgment row normal: agreement exits with the claimed gate and reports the source checks as untrusted', async () => {
  const result = await judge();
  assert.equal(result.outcome, 'agreed');
  assert.equal(result.reason, null);
  assert.deepEqual(result.claimed, { gate: 'INCOMPLETE', exitCode: 3 });
  assert.equal(result.exitCode, 3);
  assert.deepEqual(result.sourceChecks, { conclusion: 'passed', trusted: false });
  assert.ok(!Object.hasOwn(result, 'tests'));
  assert.ok(result.checks.every(item => item.state === 'passed'));
  const pass = await judge({ delivery: delivery({ gate: 'PASS' }), steps: producerSteps({}, 'success') });
  assert.deepEqual([pass.gate, pass.exitCode], ['PASS', 0]);
  const dispatched = await judge({ event: 'workflow_dispatch' });
  assert.deepEqual([dispatched.outcome, dispatched.sourceChecks.conclusion, dispatched.exitCode], ['agreed', 'not_applicable', 3]);
  const failedTests = await judge({ tests: 'failure' });
  assert.deepEqual([failedTests.sourceChecks.conclusion, failedTests.exitCode], ['failed', 3]);
  const skippedTests = await judge({ tests: 'skipped' });
  assert.equal(skippedTests.sourceChecks.conclusion, 'skipped', 'a skipped test job is never reported as passed');
  const unmatched = await judge({ source: { head_sha: 'f'.repeat(40) } });
  assert.deepEqual([unmatched.reason, unmatched.sourceChecks.conclusion], ['source_run_mismatch', 'unknown'], 'a source run that does not match the anchored manifest reports nothing');
});

test('judgment row cancelled: a cancelled run or job is INCOMPLETE', async () => {
  expectReason(await judge({ run: { conclusion: 'cancelled' } }), 'run_cancelled', 3, 'run');
  expectReason(await judge({ run: { status: 'in_progress', conclusion: null } }), 'run_not_completed', 3, 'run');
  expectReason(await judge({ jobs: [{ id: producerJobId, name: 'selfscan', run_attempt: 1, status: 'completed', conclusion: 'cancelled', steps: producerSteps() }] }), 'producer_job_cancelled', 3, 'producer_jobs');
  expectReason(await judge({ steps: producerSteps({ Scan: 'cancelled', 'CI check': 'skipped' }) }), 'producer_step_cancelled', 3, 'producer_jobs');
});

test('judgment row job or step missing: absence and skips are INCOMPLETE, never PASS', async () => {
  expectReason(await judge({ jobs: [] }), 'producer_job_missing', 3, 'producer_jobs');
  expectReason(await judge({ steps: producerSteps().filter(step => step.name !== 'Scan') }), 'producer_step_missing', 3, 'producer_jobs');
  expectReason(await judge({ steps: producerSteps({ Scan: 'skipped', 'CI check': 'failure' }) }), 'producer_step_skipped', 3, 'producer_jobs');
  expectReason(await judge({ steps: producerSteps({ 'Upload delivery': 'skipped', 'Anchor delivery': 'skipped' }) }), 'delivery_step_incomplete', 3, 'producer_jobs');
  expectReason(await judge({ steps: producerSteps({ 'Install controller': 'failure' }) }), 'producer_step_failed', 4, 'producer_jobs');
});

test('judgment row artifact missing: no or expired artifact is INCOMPLETE; two candidates are an error', async () => {
  expectReason(await judge({ artifacts: [], event: 'workflow_dispatch' }), 'artifact_missing', 3, 'artifact');
  expectReason(await judge({ artifacts: [] }), 'artifact_missing', 3, 'artifact');
  const one = { id: artifactId, name: artifactName(runId, attempt), expired: true, workflow_run: { id: runId } };
  expectReason(await judge({ artifacts: [one], event: 'workflow_dispatch' }), 'artifact_expired', 3, 'artifact');
  expectReason(await judge({ artifacts: [{ ...one, expired: false }, { ...one, id: 6, expired: false }], event: 'workflow_dispatch' }), 'artifact_ambiguous', 4, 'artifact');
});

test('judgment row order: a missing upload or manifest stops at the same check with the same reason for both events', async () => {
  for (const event of ['workflow_run', 'workflow_dispatch'] as const) {
    expectReason(await judge({ event, artifacts: [] }), 'artifact_missing', 3, 'artifact');
    const files = delivery({ event }); files.delete(manifestName);
    expectReason(await judge({ event, delivery: files, log: `2026-10-25T00:00:01.0000000Z ${anchorLine('0'.repeat(64), artifactId, runId, attempt)}
` }), 'manifest_missing', 4, 'anchor');
    expectReason(await judge({ event, delivery: delivery({ event, manifest: m => { m.github.runHeadSha = 'f'.repeat(40); } }) }), 'manifest_run_mismatch', 4, 'manifest');
  }
  expectReason(await judge({ delivery: delivery({ manifest: m => { m.source = null; } }) }), 'manifest_run_mismatch', 4, 'manifest');
});

test('judgment row tampering: a changed file or a consistently edited claim is ERROR', async () => {
  const files = delivery();
  const report = Buffer.from(files.get('report.json')!); report[report.length - 3] ^= 1;
  expectReason(await judge({ delivery: new Map([...files, ['report.json', report]]) }), 'delivery_file_tampered', 4, 'manifest');
  const swapped = new Map([...files, ['notes.txt', Buffer.from('x')]]); swapped.delete('config.json');
  expectReason(await judge({ delivery: swapped }), 'delivery_archive_invalid', 4, 'artifact');
  const nested = new Map([...files, ['a/config.json', files.get('config.json')!]]); nested.delete('config.json');
  expectReason(await judge({ delivery: nested }), 'delivery_archive_invalid', 4, 'artifact');
  assert.equal((await collectEvidence(api({ delivery: nested }), request)).delivery.state, 'invalid', 'a nested name never reaches the copy that is written to disk');
  expectReason(await judge({}, nested), 'delivery_archive_invalid', 4, 'artifact');
  const short = new Map(files); short.delete('config.json');
  expectReason(await judge({ delivery: short }), 'delivery_files_mismatch', 4, 'manifest');
  expectReason(await judge({ delivery: new Map([...files, ['notes.txt', Buffer.from('x')]]) }), 'delivery_archive_invalid', 4, 'artifact');
  const passFiles = produced('PASS');
  const forged = delivery({ files: new Map([...produced(), ['ci-receipt.json', passFiles.get('ci-receipt.json')!], ['ci-result.json', passFiles.get('ci-result.json')!], ['report.json', passFiles.get('report.json')!]]) });
  const original = files.get(manifestName)!;
  const log = `2026-10-25T00:00:01.0000000Z ${anchorLine(hash(original), artifactId, runId, attempt)}\n`;
  expectReason(await judge({ delivery: forged, log }), 'anchor_mismatch', 4, 'anchor');
});

test('judgment row anchor mismatch: the log must carry exactly one anchor naming this manifest, artifact and attempt', async () => {
  const files = delivery(), digest = hash(files.get(manifestName)!);
  const line = (text: string) => `2026-10-25T00:00:01.0000000Z ${text}\n`;
  expectReason(await judge({ log: line(anchorLine(digest, 6, runId, attempt)) }), 'anchor_mismatch', 4, 'anchor');
  expectReason(await judge({ log: line(anchorLine(digest, artifactId, runId, 2)) }), 'anchor_mismatch', 4, 'anchor');
  expectReason(await judge({ log: line('scanmux-anchor v2 manifest=x') }), 'anchor_mismatch', 4, 'anchor');
  expectReason(await judge({ log: line('no anchor here') }), 'anchor_missing', 4, 'anchor');
  expectReason(await judge({ log: line(anchorLine(digest, artifactId, runId, attempt)).repeat(2) }), 'anchor_ambiguous', 4, 'anchor');
});

test('judgment row binding mismatch: source run, manifest, expectation and receipt bindings are ERROR', async () => {
  expectReason(await judge({ source: { head_sha: 'f'.repeat(40) } }), 'source_run_mismatch', 4, 'source_run');
  expectReason(await judge({ source: { path: '.github/workflows/other.yml' } }), 'source_run_mismatch', 4, 'source_run');
  expectReason(await judge({ source: { status: 'in_progress' } }), 'source_run_not_completed', 3, 'source_run');
  expectReason(await judge({ delivery: delivery({ manifest: m => { m.github.runHeadSha = 'f'.repeat(40); } }) }), 'manifest_run_mismatch', 4, 'manifest');
  expectReason(await judge({ event: 'workflow_dispatch', delivery: delivery({ event: 'workflow_dispatch', manifest: m => { m.targetHeadSha = target; } }) }), 'manifest_run_mismatch', 4, 'manifest');
  expectReason(await judge({ delivery: delivery({ manifest: m => { m.pinsSha256 = 'f'.repeat(64); } }) }), 'pins_unapproved', 4, 'manifest');
  const files = produced();
  const expected = JSON.parse(files.get('expected.json')!.toString('utf8')); expected.jobs[0].planHash = '0'.repeat(64);
  expectReason(await judge({ delivery: delivery({ files: new Map([...files, ['expected.json', json(expected)]]) }) }), 'expectation_mismatch', 4, 'content_binding');
  const receipt = JSON.parse(files.get('ci-receipt.json')!.toString('utf8')); receipt.reportHash = '0'.repeat(64);
  expectReason(await judge({ delivery: delivery({ files: new Map([...files, ['ci-receipt.json', json(receipt)]]) }) }), 'receipt_binding_mismatch', 4, 'content_binding');
  const report = JSON.parse(files.get('report.json')!.toString('utf8')); report.gate = 'PASS';
  const reportBytes = json(report), rebound = { ...JSON.parse(files.get('ci-receipt.json')!.toString('utf8')), reportHash: hash(reportBytes) };
  expectReason(await judge({ delivery: delivery({ files: new Map([...files, ['report.json', reportBytes], ['ci-receipt.json', json(rebound)]]) }) }), 'report_binding_mismatch', 4, 'content_binding');
});

test('judgment row acquisition failure: failed or malformed transport is ERROR', async () => {
  expectReason(await judge({ fail: /attempts\/1$/ }), 'github_fetch_failed', 4, 'run');
  expectReason(await judge({ fail: /\/zip$/ }), 'github_fetch_failed', 4, 'artifact');
  expectReason(await judge({ fail: /\/logs$/ }), 'github_fetch_failed', 4, 'anchor');
  expectReason(await judge({ zip: Buffer.from('not a zip') }), 'delivery_archive_invalid', 4, 'artifact');
  expectReason(await judge({ invalid: /\/jobs/ }), 'github_response_invalid', 4, 'producer_jobs');
  expectReason(await judge({ invalid: /^repos\/[^/]+\/[^/]+$/ }), 'github_response_invalid', 4, 'run');
});

test('judgment row acquisition failure: an artifact whose local headers contradict the central directory is ERROR', async () => {
  const files = delivery({ event: 'workflow_dispatch' });
  for (const [offset, value] of [[localHeader.flags, 1], [localHeader.method, 99]]) {
    const archive = zip([...files]); archive.writeUInt16LE(value, offset);
    expectReason(await judge({ event: 'workflow_dispatch', delivery: files, zip: archive }), 'delivery_archive_invalid', 4, 'artifact');
  }
  const described = await judge({ event: 'workflow_dispatch', delivery: files, zip: zip([...files], true, true) });
  assert.deepEqual([described.outcome, described.exitCode], ['agreed', 3]);
});

test('collection: cancellation and unverified termination stop collecting instead of becoming a failed fetch', async () => {
  for (const [code, kind, endpoint] of [['cancelled', 'json', /\/jobs/], ['termination_unverified', 'bytes', /\/contents\//]] as const) {
    const inner = api(), calls: string[] = [];
    let thrown = false;
    const wrapped: GithubApi = {
      json: async (path, jq) => { calls.push(path); if (thrown) throw new Error('called after stop'); if (kind === 'json' && endpoint.test(path)) { thrown = true; throw new SafeError(code); } return inner.json(path, jq); },
      bytes: async (path, accept) => { calls.push(path); if (thrown) throw new Error('called after stop'); if (kind === 'bytes' && endpoint.test(path)) { thrown = true; throw new SafeError(code); } return inner.bytes(path, accept); },
    };
    await assert.rejects(collectEvidence(wrapped, request), (error: unknown) => error instanceof SafeError && error.code === code);
    assert.ok(endpoint.test(calls.at(-1)!), `${code}: no request after the stop`);
  }
});

test('judgment row scenario: a failure demonstration or any non-none scenario is ERROR', async () => {
  const failed = delivery({ event: 'workflow_dispatch', scenario: 'tool-fetch-fail', outcome: { kind: 'failed', stage: 'acquire', code: 'tool_fetch_failed' },
    files: new Map([['config.json', json({})]]), manifest: m => { m.ciRun = null; } });
  const later = Object.fromEntries(producerStages.slice(2).map(item => [item.step, 'skipped']));
  const titled = (scenario: string) => ({ event: 'workflow_dispatch' as const, run: { display_title: `offline-selfscan scenario=${scenario}` } });
  const result = await judge({ ...titled('tool-fetch-fail'), delivery: failed, steps: producerSteps({ 'Acquire tools': 'failure', ...later }) });
  expectReason(result, 'producer_failed', 4, 'manifest');
  assert.deepEqual([result.producer, result.scenario, result.notes], [{ kind: 'failed', stage: 'acquire', code: 'tool_fetch_failed' }, 'tool-fetch-fail', ['failure_scenario']]);
  expectReason(await judge({ ...titled('tool-fetch-fail'), delivery: failed, steps: producerSteps({ ...later, 'Fetch OSV database': 'failure' }) }), 'outcome_step_mismatch', 4, 'manifest');
  expectReason(await judge({ ...titled('cancel-wait'), delivery: delivery({ event: 'workflow_dispatch', scenario: 'cancel-wait' }) }), 'scenario_run', 4, 'manifest');
  expectReason(await judge({ event: 'workflow_dispatch', run: { display_title: null }, delivery: delivery({ event: 'workflow_dispatch', scenario: 'cancel-wait' }) }), 'scenario_run', 4, 'manifest');
});

test('judgment row scenario: a run that stops early still reports an anchored or titled scenario, and a non-none scenario is flagged', async () => {
  const dispatch = (scenario: string) => ({ event: 'workflow_dispatch' as const, run: { display_title: `offline-selfscan scenario=${scenario}` } });
  const failedCheck = { kind: 'failed', stage: 'check', code: 'stage_not_completed' };
  const skipScan = await judge({ ...dispatch('skip-scan'), delivery: delivery({ event: 'workflow_dispatch', scenario: 'skip-scan', outcome: failedCheck }),
    steps: producerSteps({ Scan: 'skipped', 'CI check': 'failure' }) });
  expectReason(skipScan, 'producer_step_skipped', 3, 'producer_jobs');
  assert.deepEqual([skipScan.scenario, skipScan.producer, skipScan.notes], ['skip-scan', failedCheck, ['failure_scenario']]);
  const skipUpload = await judge({ ...dispatch('skip-upload'), artifacts: [], steps: producerSteps({ 'Upload delivery': 'skipped', 'Anchor delivery': 'skipped' }) });
  expectReason(skipUpload, 'delivery_step_incomplete', 3, 'producer_jobs');
  assert.deepEqual([skipUpload.scenario, skipUpload.producer, skipUpload.notes], ['skip-upload', null, ['failure_scenario']]);
  const cancelled = await judge({ event: 'workflow_dispatch', run: { conclusion: 'cancelled', display_title: 'offline-selfscan scenario=cancel-wait' }, artifacts: [] });
  expectReason(cancelled, 'run_cancelled', 3, 'run');
  assert.deepEqual([cancelled.scenario, cancelled.notes], ['cancel-wait', ['failure_scenario']]);
  const foreign = await judge({ event: 'workflow_dispatch', run: { conclusion: 'cancelled', display_title: 'offline-selfscan scenario=cancel-wait' }, artifacts: [], workflow: Buffer.from('x') });
  const disagreeing = await judge({ event: 'workflow_dispatch', run: { conclusion: 'cancelled', display_title: 'offline-selfscan scenario=cancel-wait' } });
  assert.deepEqual([disagreeing.scenario, disagreeing.notes], [null, ['failure_scenario']], 'a title and an anchored manifest that disagree report no scenario but stay flagged');
  assert.deepEqual([foreign.reason, foreign.scenario, foreign.notes], ['run_cancelled', null, []], 'nothing is reported from an unapproved workflow');
  const unapproved = await judge({ ...dispatch('skip-scan'), workflow: Buffer.concat([workflowBytes, Buffer.from('\n')]) });
  assert.deepEqual([unapproved.reason, unapproved.scenario, unapproved.producer], ['workflow_content_unapproved', null, null]);
  const untitled = await judge({ event: 'workflow_dispatch', run: { display_title: 'renamed' }, artifacts: [] });
  assert.deepEqual([untitled.reason, untitled.scenario], ['artifact_missing', null]);
  expectReason(await judge(dispatch('skip-scan')), 'manifest_run_mismatch', 4, 'manifest');
  const normal = await judge();
  assert.deepEqual([normal.scenario, normal.notes], ['none', []]);
});

test('judgment row claim disagrees with the result: re-evaluation or the gate step must match the claim', async () => {
  const files = produced();
  const claim = JSON.parse(files.get('ci-result.json')!.toString('utf8')); claim.gate = 'PASS'; claim.exitCode = 0;
  expectReason(await judge({ delivery: delivery({ files: new Map([...files, ['ci-result.json', json(claim)]]) }) }), 'result_disagrees', 4, 'agreement');
  expectReason(await judge({ steps: producerSteps({}, 'success') }), 'gate_step_disagrees', 4, 'agreement');
});

test('judgment row workflow content: an unapproved producer file or a head off the default branch is ERROR', async () => {
  expectReason(await judge({ workflow: Buffer.concat([workflowBytes, Buffer.from('\n')]) }), 'workflow_content_unapproved', 4, 'workflow_integrity');
  expectReason(await judge({ ancestry: 'diverged' }), 'run_head_not_on_default_branch', 4, 'workflow_integrity');
  expectReason(await judge({ run: { path: '.github/workflows/checks.yml' } }), 'run_mismatch', 4, 'run');
});

test('local copy: still requires every API check and is always marked', async () => {
  const files = delivery();
  const result = await judge({ fail: /\/zip$/ }, files);
  assert.deepEqual([result.outcome, result.exitCode, result.notes], ['agreed', 3, ['local_copy_supplied']]);
  expectReason(await judge({ fail: /\/logs$/ }, files), 'github_fetch_failed', 4, 'anchor');
  const report = Buffer.from(files.get('report.json')!); report[10] ^= 1;
  expectReason(await judge({}, new Map([...files, ['report.json', report]])), 'delivery_file_tampered', 4, 'manifest');
});

test('local copy: a PASS claim is held at INCOMPLETE and kept as the claim', async () => {
  const files = delivery({ gate: 'PASS' });
  const result = await judge({ delivery: files, steps: producerSteps({}, 'success') }, files);
  assert.deepEqual(result.claimed, { gate: 'PASS', exitCode: 0 });
  assert.deepEqual([result.outcome, result.gate, result.exitCode, result.notes], ['agreed', 'INCOMPLETE', 3, ['local_copy_supplied']]);
});

test('ci-github CLI: requires its flags, a config and a runtime policy v2 gh pin before any request', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'scanmux-ci-github-'));
  test.after(() => removeTempDir(directory));
  const config = path.join(directory, 'config.json');
  await writeFile(config, JSON.stringify(withTestProcessOwner({ schema: 1 })));
  const cli = (args: string[]) => new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ['bin/scanmux.mjs', ...args], { windowsHide: true, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR }, stdio: ['ignore', 'pipe', 'pipe'] });
    const out: Buffer[] = [], err: Buffer[] = [];
    child.stdout.on('data', chunk => out.push(chunk)); child.stderr.on('data', chunk => err.push(chunk));
    child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }));
  });
  const help = await cli(['--help']);
  assert.match(help.stdout, /scanmux ci-github --repo OWNER\/NAME --run ID --attempt N --config/);
  const flags = ['ci-github', '--repo', repository, '--run', String(runId), '--attempt', '1'];
  for (const [args, code] of [[flags, 'ci_github_config_required'], [['ci-github', '--repo', repository, '--config', config], 'invalid_command'],
    [[...flags, '--config', config, '--from', config], 'invalid_command'], [['scan', '.', '--from-dir', directory], 'invalid_command'],
    [[...flags.slice(0, 2), 'not a repo', ...flags.slice(3), '--config', config], 'invalid_command'], [[...flags, '--config', config], 'ci_github_gh_unpinned']] as const) {
    const result = await cli([...args]);
    assert.equal(result.code, 4);
    assert.equal(JSON.parse(result.stderr).error, code);
  }
});

test('round trip: the producer seal, anchor and gate commands feed the verifier', { skip: process.platform !== 'win32' && 'CI producer requires Windows runner tools' }, async () => {
  const head = await new Promise<string>((resolve, reject) => {
    const child = spawn('git', ['rev-parse', 'HEAD'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    const out: Buffer[] = [];
    child.stdout.on('data', chunk => out.push(chunk)); child.on('error', reject);
    child.on('close', code => code === 0 ? resolve(Buffer.concat(out).toString().trim()) : reject(new Error('git rev-parse failed')));
  });
  const produce = async (command: string, env: Record<string, string>) => new Promise<{ code: number | null; stdout: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/ci-produce.mjs', command], { windowsHide: true, env: { SystemRoot: process.env.SystemRoot!, WINDIR: process.env.WINDIR!, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    const out: Buffer[] = [];
    child.stdout.on('data', chunk => out.push(chunk)); child.stderr.resume(); child.on('error', reject);
    child.on('close', code => resolve({ code, stdout: Buffer.concat(out).toString() }));
  });
  const runProducer = async (eventName: 'workflow_run' | 'workflow_dispatch', payload: unknown, state: Record<string, string>, deliveryFiles: Files) => {
    const temp = await mkdtemp(path.join(tmpdir(), 'scanmux-ci-produce-'));
    test.after(() => removeTempDir(temp));
    const work = path.join(temp, 'scanmux');
    for (const directory of ['state', 'delivery']) await mkdir(path.join(work, directory), { recursive: true });
    for (const [name, text] of Object.entries(state)) await writeFile(path.join(work, 'state', name), text);
    for (const [name, bytes] of deliveryFiles) await writeFile(path.join(work, 'delivery', name), bytes);
    await writeFile(path.join(temp, 'event.json'), JSON.stringify(payload));
    const env = { RUNNER_TEMP: temp, GITHUB_EVENT_NAME: eventName, GITHUB_EVENT_PATH: path.join(temp, 'event.json'), GITHUB_REPOSITORY: repository,
      GITHUB_REPOSITORY_ID: String(repoId), GITHUB_WORKFLOW_REF: `${repository}/${producerWorkflowPath}@refs/heads/main`, GITHUB_RUN_ID: String(runId),
      GITHUB_RUN_ATTEMPT: String(attempt), GITHUB_SHA: head };
    assert.equal((await produce('seal', env)).code, 0, 'seal');
    const anchored = await produce('anchor', { ...env, SCANMUX_ARTIFACT_ID: String(artifactId) });
    assert.equal(anchored.code, 0, 'anchor');
    const gate = await produce('gate', env);
    const files: Files = new Map();
    for (const name of await readdir(path.join(work, 'delivery'))) files.set(name, await readFile(path.join(work, 'delivery', name)));
    return { gate: gate.code, files, log: `2026-10-25T00:00:01.0000000Z ${anchored.stdout}` };
  };
  const git = { path: 'C:\\Program Files\\Git\\cmd\\git.exe', sha256: '1'.repeat(64), version: '2.51.0' };
  const done = Object.fromEntries(producerStages.map(item => [`${item.stage}.done`, '']));
  const source = { workflow_run: { id: sourceRunId, run_attempt: 1, event: 'pull_request', head_sha: target, path: testsWorkflowPath, pull_requests: [{ number: 7 }] } };
  const producedRun = await runProducer('workflow_run', source, { ...done, 'run.json': JSON.stringify({ ciRun }), 'config.json': JSON.stringify({ tools: { git } }) }, produced());
  assert.equal(producedRun.gate, 3, 'gate exits with the INCOMPLETE claim');
  const manifest = parseDeliveryManifest(JSON.parse(producedRun.files.get(manifestName)!.toString('utf8')));
  assert.deepEqual([manifest.github.workflowPath, manifest.outcome, manifest.git, manifest.source?.pr], [producerWorkflowPath, { kind: 'produced' }, git, 7]);
  const agreed = await judge({ head, delivery: producedRun.files, log: producedRun.log });
  assert.deepEqual([agreed.outcome, agreed.reason, agreed.gate, agreed.exitCode, agreed.scenario, agreed.sourceChecks.conclusion], ['agreed', null, 'INCOMPLETE', 3, 'none', 'passed']);

  const failure = { kind: 'failed', stage: 'acquire', code: 'tool_fetch_failed' };
  const failedRun = await runProducer('workflow_dispatch', { inputs: { scenario: 'tool-fetch-fail' } }, { 'target.done': '', 'outcome.json': JSON.stringify(failure) }, new Map());
  assert.equal(failedRun.gate, 4, 'gate exits 4 for a producer failure');
  const sealed = parseDeliveryManifest(JSON.parse(failedRun.files.get(manifestName)!.toString('utf8')));
  assert.deepEqual([sealed.outcome, sealed.git, sealed.ciRun, sealed.files, sealed.scenario], [failure, null, null, [], 'tool-fetch-fail']);
  const later = Object.fromEntries(producerStages.slice(2).map(item => [item.step, 'skipped']));
  const failed = await judge({ event: 'workflow_dispatch', head, delivery: failedRun.files, log: failedRun.log, run: { display_title: 'offline-selfscan scenario=tool-fetch-fail' },
    steps: producerSteps({ 'Acquire tools': 'failure', ...later }) });
  expectReason(failed, 'producer_failed', 4, 'manifest');
  assert.deepEqual([failed.producer, failed.scenario, failed.notes], [failure, 'tool-fetch-fail', ['failure_scenario']]);
});
