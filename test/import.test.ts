import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { assessImports, importText, parseInputs, type CommitFacts, type ImportInput, type ImportRecord, type LevelSources } from '../src/import.ts';
import { digest, hash } from '../src/safety.ts';

const root = path.resolve('.local/import-synthetic-root');
const repoId = hash(root);
const head = 'a'.repeat(40), older = 'b'.repeat(40), side = 'c'.repeat(40), gone = 'd'.repeat(40), introduced = 'e'.repeat(40);
const facts = (overrides: Partial<CommitFacts> = {}): CommitFacts => ({
  head, dirty: false,
  commits: new Map([
    [head, { exists: true, ancestor: false, paths: ['package-lock.json', 'src/app.ts', 'config/settings.env'] }],
    [older, { exists: true, ancestor: true, paths: ['package-lock.json'] }],
    [side, { exists: true, ancestor: false, paths: ['package-lock.json', 'src/app.ts', 'config/settings.env'] }],
    [gone, { exists: false, ancestor: false, paths: [] }],
  ]),
  ...overrides,
});
const pii = ['person.name@example.invalid', 'Taro Example', 'rotate the key', 'C:/Users/someone', 'C:\\Users\\someone', 'file:///', 'example.invalid', 'SECRETVALUE123', '/home/someone'];

function osv(options: { revisions?: string[]; uri?: string; tool?: string; version?: string | null; results?: unknown[]; invocations?: unknown } = {}) {
  const driver: Record<string, unknown> = { name: options.tool ?? 'osv-scanner', informationUri: 'https://example.invalid/osv', rules: [{ id: 'GHSA-aaaa-bbbb-cccc', help: { markdown: 'see https://example.invalid/advisory' } }] };
  if (options.version !== null) driver.version = options.version ?? '2.7.0';
  return {
    version: '2.1.0', $schema: 'https://example.invalid/sarif-2.1.0.json',
    runs: [{
      tool: { driver },
      ...(options.revisions ? { versionControlProvenance: options.revisions.map(revisionId => ({ revisionId, repositoryUri: 'https://example.invalid/private/repo.git', branch: 'person.name@example.invalid' })) } : {}),
      invocations: options.invocations ?? [{ executionSuccessful: true }],
      results: options.results ?? [
        { ruleId: 'GHSA-aaaa-bbbb-cccc', level: 'warning', message: { text: 'Package lodash@4.17.20 is vulnerable; reported by person.name@example.invalid' },
          locations: [{ physicalLocation: { artifactLocation: { uri: options.uri ?? 'package-lock.json' } } }], partialFingerprints: { primaryLocationLineHash: 'f'.repeat(16) } },
        { ruleId: 'GHSA-dddd-eeee-ffff', level: 'warning', message: { text: 'second' },
          locations: [{ physicalLocation: { artifactLocation: { uri: options.uri ?? 'package-lock.json' } } }] },
      ],
    }],
  };
}
function gitleaks(options: { revisions?: string[]; uri?: string; results?: unknown[] } = {}) {
  return {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'gitleaks', semanticVersion: 'v8.0.0', rules: [{ id: 'generic-api-key', shortDescription: { text: 'Generic API Key' } }] } },
      ...(options.revisions ? { versionControlProvenance: options.revisions.map(revisionId => ({ revisionId })) } : {}),
      invocations: [{ executionSuccessful: true }],
      results: options.results ?? [{
        ruleId: 'generic-api-key', level: 'error', message: { text: 'generic-api-key has detected secret for file config/settings.env.' },
        locations: [{ physicalLocation: { artifactLocation: { uri: options.uri ?? 'config/settings.env' }, region: { startLine: 3, startColumn: 1, endLine: 3, endColumn: 30, snippet: { text: 'TOKEN=SECRETVALUE123' } } } }],
        partialFingerprints: { commitSha: introduced, email: 'person.name@example.invalid', author: 'Taro Example', date: '2026-01-01T00:00:00Z', commitMessage: 'rotate the key for person.name@example.invalid' },
        properties: { tags: ['person.name@example.invalid'] },
      }],
    }],
  };
}
const bytes = (value: unknown) => ({ kind: 'bytes' as const, bytes: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)) });
let runs = 0;
function run(inputs: (unknown | ImportInput)[], options: { declared?: string | null; facts?: CommitFacts; maxFiles?: number } = {}): ImportRecord {
  const normalized = inputs.map(input => input && typeof input === 'object' && 'kind' in input && (input.kind === 'bytes' || input.kind === 'over_limit') ? input as ImportInput : bytes(input));
  const parsed = parseInputs(normalized, { root, repoId, declared: options.declared ?? null, maxFiles: options.maxFiles ?? 10000, runId: digest(['test-run', runs++]) });
  return assessImports(parsed, options.facts ?? facts(), '2026-10-25T00:00:00.000Z');
}
const reasonsOf = (record: ImportRecord, index = 0) => record.view.inputs[index].reasons;
const observation = (record: ImportRecord, index = 0) => record.view.observations[index];

test('a recorded OSV SARIF bound to HEAD is accepted with a closed, separated record and no security effect', () => {
  const record = run([osv({ revisions: [head] })]);
  assert.deepEqual(Object.keys(record), ['schema', 'effect', 'rawRetained', 'facts', 'factsDigest', 'view']);
  assert.equal(record.schema, 'scanmux.import/v2');
  assert.deepEqual(record.effect, { gate: 'unchanged', substitutesEngine: false, scanVerified: false });
  assert.equal(record.rawRetained, false);
  assert.equal(record.view.inputs[0].state, 'accepted');
  const fact = record.facts.observations[0];
  assert.equal(fact.tool, 'osv-scanner'); assert.equal(fact.recordedToolVersion, '2.7.0');
  assert.deepEqual(fact.basis, { kind: 'recorded', commit: head });
  assert.equal(observation(record).relation, 'head');
  assert.equal(record.facts.findings.length, 2);
  assert.deepEqual(record.facts.findings.map(item => item.path), ['package-lock.json', 'package-lock.json']);
  assert.deepEqual(record.facts.findings.map(item => item.package), [null, null]);
  assert.ok(observation(record).reasons.includes('package_unavailable'), 'a message outside the fixed OSV sentence yields no package');
  assert.ok(observation(record).reasons.includes('line_unavailable'));
  assert.equal(record.view.exitCode, 3, 'missing optional values keep the import incomplete');
});

test('a fully observed Gitleaks result bound to HEAD exits 0, and Gitleaks commitSha is never the scanned commit', () => {
  const recorded = run([gitleaks({ revisions: [head] })]);
  assert.deepEqual(observation(recorded).reasons, []);
  assert.equal(recorded.view.exitCode, 0);
  const finding = recorded.facts.findings[0];
  assert.deepEqual({ tool: finding.tool, ruleId: finding.ruleId, path: finding.path, startLine: finding.startLine, package: finding.package },
    { tool: 'gitleaks', ruleId: 'generic-api-key', path: 'config/settings.env', startLine: 3, package: null });
  assert.deepEqual(finding.occurrences[0].imports[0].levels, [{ level: 'error', count: 1 }]);
  const unrecorded = run([gitleaks()]);
  assert.deepEqual(unrecorded.facts.observations[0].basis, { kind: 'unbound', commit: null });
  assert.ok(observation(unrecorded).reasons.includes('sha_missing'));
  assert.equal(observation(unrecorded).relation, null);
  assert.equal(JSON.stringify(unrecorded).includes(introduced), false);
});

test('messages, fingerprints, snippets, emails, authors, URLs and absolute paths never reach the output', () => {
  const outside = pathToFileURL(path.resolve('C:/Users/someone/project/config/settings.env')).href;
  const record = run([gitleaks({ revisions: [head] }), osv({ revisions: [head], uri: outside }), gitleaks({ uri: 'C:\\Users\\someone\\project\\settings.env' }), gitleaks({ uri: '/home/someone/settings.env' })]);
  const text = JSON.stringify(record);
  for (const value of pii) assert.equal(text.includes(value), false, value);
  assert.equal(text.includes(JSON.stringify(root).slice(1, -1)), false, 'the canonical root is not output');
  assert.equal(text.includes('lodash'), false, 'a message outside the fixed OSV sentence is not kept');
  assert.ok(observation(record, record.facts.observations.findIndex(item => item.tool === 'osv-scanner')).reasons.includes('location_outside_repository'));
  assert.deepEqual(record.facts.findings.filter(item => item.tool === 'osv-scanner').map(item => item.path), [null, null]);
});

test('file URIs, absolute local paths and relative URIs become repository-relative only inside the root', () => {
  const inside = pathToFileURL(path.join(root, 'src', 'app.ts')).href;
  const cases: [string, string | null, string | null][] = [
    [inside, 'src/app.ts', null], [path.join(root, 'src', 'app.ts'), 'src/app.ts', null], ['src/app.ts', 'src/app.ts', null], ['src%2Fapp.ts', 'src/app.ts', null],
    ['src\\app.ts', 'src/app.ts', null], ['../outside.txt', null, 'location_outside_repository'], ['src/../../outside.txt', null, 'location_outside_repository'],
    ['https://example.invalid/src/app.ts', null, 'location_unavailable'], ['%E0%A4%A', null, 'location_unavailable'], ['', null, 'location_unavailable'],
    ['\\\\server\\share\\app.ts', null, 'location_unavailable'], ['.', null, 'location_unavailable'],
  ];
  for (const [uri, expected, reason] of cases) {
    const record = run([gitleaks({ revisions: [head], uri })]);
    assert.equal(record.facts.findings[0].path, expected, uri);
    if (reason) assert.ok(observation(record).reasons.includes(reason as never), uri);
  }
  const based = run([gitleaks({ revisions: [head], results: [{ ruleId: 'generic-api-key', locations: [{ physicalLocation: { artifactLocation: { uri: 'src/app.ts', uriBaseId: 'SRCROOT' }, region: { startLine: 1 } } }] }] })]);
  assert.equal(based.facts.findings[0].path, null);
  assert.ok(observation(based).reasons.includes('location_base_unresolved'));
  const multiple = run([gitleaks({ revisions: [head], results: [{ ruleId: 'generic-api-key', locations: [
    { physicalLocation: { artifactLocation: { uri: 'src/app.ts' }, region: { startLine: 1 } } }, { physicalLocation: { artifactLocation: { uri: 'package-lock.json' }, region: { startLine: 1 } } }] }] })]);
  assert.ok(observation(multiple).reasons.includes('multiple_locations'));
});

test('structural failures reject the whole input as a listed row with its hash; the unknown tool name is not echoed', () => {
  const valid = JSON.stringify(osv({ revisions: [head] }));
  const cases: [unknown, string][] = [
    [valid.slice(0, valid.length - 20), 'invalid_json'],
    [{ kind: 'bytes', bytes: Buffer.from([0x7b, 0xff, 0x7d]) }, 'invalid_utf8'],
    ['{"version":"2.1.0","version":"2.1.0","runs":[]}', 'invalid_json'],
    ['['.repeat(200) + ']'.repeat(200), 'invalid_json'],
    ['{"version":"2.1.0","runs":[]} trailing', 'invalid_json'],
    [{ ...osv(), version: '2.0.0' }, 'unsupported_schema'],
    [{ ...osv(), runs: [...osv().runs, ...osv().runs] }, 'unsupported_schema'],
    [[1, 2], 'unsupported_schema'],
    [osv({ tool: 'PrivateScannerName' }), 'unsupported_tool'],
    [{ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } }, results: {} }] }, 'invalid_shape'],
    [{ version: '2.1.0', runs: [{ tool: { driver: { name: 'gitleaks' } } }] }, 'invalid_shape'],
    [{ version: '2.1.0', runs: [{ tool: {}, results: [] }] }, 'invalid_shape'],
    [osv({ invocations: [{ executionSuccessful: 'yes' }] }), 'invalid_shape'],
    [{ kind: 'over_limit', bytes: 123 }, 'over_limit'],
  ];
  for (const [input, reason] of cases) {
    const record = run([input]);
    const row = record.view.inputs[0];
    assert.equal(row.state, 'rejected', reason);
    assert.deepEqual(row.reasons, [reason], reason);
    assert.equal(record.facts.observations.length, 0, reason);
    assert.equal(record.view.exitCode, 3, reason);
    if (reason !== 'over_limit') assert.match(row.sha256!, /^[0-9a-f]{64}$/);
    assert.equal(JSON.stringify(record).includes('PrivateScannerName'), false);
  }
  const limited = run([osv({ revisions: [head] })], { maxFiles: 1 });
  assert.deepEqual(reasonsOf(limited), ['results_over_limit']);
});

test('a missing driver version, tool-reported failure, notifications and absent invocations are kept as reasons', () => {
  assert.ok(observation(run([osv({ revisions: [head], version: null })])).reasons.includes('tool_version_unrecorded'));
  assert.ok(observation(run([osv({ revisions: [head], version: 'latest build' })])).reasons.includes('tool_version_unrecorded'));
  assert.ok(observation(run([osv({ revisions: [head], invocations: [{ executionSuccessful: false }] })])).reasons.includes('tool_reported_incomplete'));
  const notified = run([osv({ revisions: [head], invocations: [{ executionSuccessful: true, toolExecutionNotifications: [{ message: { text: 'C:/Users/someone failed' } }] }] })]);
  assert.ok(observation(notified).reasons.includes('tool_reported_incomplete'));
  assert.equal(notified.facts.observations[0].execution.notifications, 1);
  assert.ok(observation(run([osv({ revisions: [head], invocations: [] })])).reasons.includes('execution_unrecorded'));
  const empty = run([gitleaks({ revisions: [head], results: [] })]);
  assert.equal(empty.view.inputs[0].state, 'accepted'); assert.equal(empty.facts.findings.length, 0); assert.equal(empty.view.exitCode, 0);
});

test('invalid optional result values become null with closed per-reason counts', () => {
  const record = run([gitleaks({ revisions: [head], results: [
    { ruleId: 'bad rule id with spaces', level: 'high', locations: [{ physicalLocation: { artifactLocation: { uri: 'src/app.ts' }, region: { startLine: 0 } } }] },
    { ruleId: 'generic-api-key' },
  ] })]);
  const fact = record.facts.observations[0];
  assert.deepEqual(fact.fieldReasons, [{ reason: 'level_unavailable', count: 1 }, { reason: 'line_unavailable', count: 2 }, { reason: 'location_unavailable', count: 1 }, { reason: 'rule_unavailable', count: 1 }]);
  assert.deepEqual(record.facts.findings.map(item => [item.ruleId, item.path, item.startLine]).sort(), [['generic-api-key', null, null], [null, 'src/app.ts', null]].sort());
});

test('commit binding: mixed, conflicting, declared, stale, diverged, unavailable and absent paths', () => {
  const mixed = run([osv({ revisions: [head, older] })]);
  assert.deepEqual(mixed.facts.observations[0].basis, { kind: 'unbound', commit: null });
  assert.ok(observation(mixed).reasons.includes('mixed_sha'));
  const conflict = run([osv({ revisions: [head] })], { declared: older });
  assert.deepEqual(conflict.facts.observations[0].basis, { kind: 'recorded', commit: head });
  assert.deepEqual(conflict.facts.observations[0].declaredCommits, [older]);
  assert.ok(observation(conflict).reasons.includes('declaration_conflict'));
  const declared = run([gitleaks()], { declared: head });
  assert.deepEqual(declared.facts.observations[0].basis, { kind: 'declared', commit: head });
  assert.equal(declared.view.exitCode, 0);
  const relations: [string, string][] = [[older, 'stale_commit'], [side, 'sha_mismatch'], [gone, 'commit_unavailable']];
  for (const [commit, relation] of relations) {
    const record = run([gitleaks({ revisions: [commit] })]);
    assert.equal(observation(record).relation, relation, relation);
    assert.ok(observation(record).reasons.includes(relation as never), relation);
    assert.equal(record.view.exitCode, 3);
  }
  const absent = run([gitleaks({ revisions: [older] })]);
  assert.ok(observation(absent).reasons.includes('referenced_paths_absent'));
  assert.equal(observation(absent).absentPaths, 1);
  assert.equal(absent.effect.scanVerified, false);
});

test('a dirty worktree is recorded and keeps the import incomplete', () => {
  const record = run([gitleaks({ revisions: [head] })], { facts: facts({ dirty: true }) });
  assert.ok(observation(record).reasons.includes('worktree_dirty_at_import'));
  assert.equal(record.facts.observations[0].dirtyAtImport, true);
  assert.equal(record.view.exitCode, 3);
});

test('the same bytes with the same binding are one import; another binding is another occurrence of the same finding', () => {
  const twice = run([gitleaks(), gitleaks()], { declared: head });
  assert.deepEqual(twice.view.inputs.map(row => [row.state, row.reasons]), [['accepted', []], ['duplicate', ['duplicate_input']]]);
  assert.equal(twice.facts.observations.length, 1);
  assert.equal(twice.view.exitCode, 0, 'a duplicate is not a missing observation');
  const first = run([gitleaks({ revisions: [head] })]), second = run([gitleaks({ revisions: [side] })]);
  assert.equal(first.facts.findings[0].findingId, second.facts.findings[0].findingId, 'findingId has no commit');
  const merged = run([gitleaks({ revisions: [head] }), gitleaks({ revisions: [side] })]);
  assert.equal(merged.facts.findings.length, 1);
  assert.deepEqual(merged.facts.findings[0].occurrences.map(item => [item.commit, item.count]), [[head, 1], [side, 1]]);
});

test('an earlier record is re-read with its digest checked and its relation re-derived; re-import adds no findings', () => {
  const sarif = gitleaks({ revisions: [head] });
  const earlier = run([sarif]);
  const moved = facts({ head: 'f'.repeat(40), commits: new Map([...facts().commits, [head, { exists: true, ancestor: true, paths: ['config/settings.env'] }]]) });
  const again = run([earlier, sarif], { facts: moved });
  assert.deepEqual(again.view.inputs.map(row => [row.state, row.reasons]), [['accepted', ['stale_commit']], ['duplicate', ['stale_commit', 'duplicate_input']]]);
  assert.equal(again.facts.findings.length, earlier.facts.findings.length);
  assert.deepEqual(again.facts.findings[0].occurrences, earlier.facts.findings[0].occurrences);
  assert.equal(again.facts.observations[0].importedAt, earlier.facts.observations[0].importedAt);
  assert.equal(observation(again).relation, 'stale_commit', 'the stored relation is not trusted');
  assert.equal(again.view.exitCode, 3);
  const tampered = structuredClone(earlier) as unknown as { facts: { findings: { startLine: number }[] } };
  tampered.facts.findings[0].startLine = 4;
  assert.deepEqual(reasonsOf(run([tampered])), ['record_digest_mismatch']);
  assert.deepEqual(reasonsOf(run([{ ...earlier, schema: 'scanmux.import/v3' }])), ['unsupported_schema']);
  assert.deepEqual(reasonsOf(run([{ ...earlier, extra: true }])), ['invalid_shape']);
  assert.deepEqual(reasonsOf(run([{ ...earlier, effect: { ...earlier.effect, scanVerified: true } }])), ['invalid_shape']);
  const foreign = parseInputs([bytes(earlier)], { root: path.resolve('.local/another-root'), repoId: hash(path.resolve('.local/another-root')), declared: null, maxFiles: 10000, runId: digest('foreign') });
  assert.deepEqual(foreign.rows[0].reasons, ['record_repository_mismatch']);
});

const advisory = 'GHSA-aaaa-bbbb-cccc';
const osvResult = (text: string, uri = 'package-lock.json') => ({ ruleId: advisory, level: 'warning', message: { text }, locations: [{ physicalLocation: { artifactLocation: { uri } } }] });
const sentence = (pkg: string, id = advisory, alias = true) => `Package '${pkg}' is vulnerable to '${id}'${alias ? " (also known as 'CVE-2020-11111')" : ''}.`;

test('OSV results of one advisory in different packages or versions stay separate findings, the package read only from the fixed sentence', () => {
  const record = run([osv({ revisions: [head], results: [
    osvResult(sentence('lodash@4.17.20')), osvResult(sentence('lodash@4.17.21', advisory, false)), osvResult(sentence('@scope/pkg@1.0.0-beta.1')),
    osvResult(sentence('Django@4.2.1'), 'uv.lock'),
  ] })]);
  assert.equal(record.facts.findings.length, 4);
  assert.deepEqual(record.facts.findings.map(item => item.package).sort((left, right) => JSON.stringify(left) < JSON.stringify(right) ? -1 : 1), [
    { ecosystem: 'PyPI', name: 'Django', version: '4.2.1' }, { ecosystem: 'npm', name: '@scope/pkg', version: '1.0.0-beta.1' },
    { ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
  ]);
  assert.equal(observation(record).reasons.includes('package_unavailable'), false);
  const text = JSON.stringify(record);
  for (const value of ['CVE-2020-11111', 'is vulnerable', 'also known as']) assert.equal(text.includes(value), false, value);
});

test('an OSV message off the fixed sentence leaves the package unavailable, and the results still do not merge', () => {
  const malformed = [
    sentence('Bad Name@1.0.0'), sentence('lodash@latest'), sentence('lodash@4.17.20', 'GHSA-zzzz-zzzz-zzzz'), sentence('lodash@4.17.20') + ' extra',
    ' ' + sentence('lodash@4.17.20'), sentence('lodash@4.17.20').replace(' (also', ' (aka'), "Package 'lodash@4.17.20' is vulnerable to 'GHSA-aaaa-bbbb-cccc' (also known as 'A', 'B').",
  ];
  const record = run([osv({ revisions: [head], results: [...malformed.map(text => osvResult(text)), osvResult(sentence('lodash@4.17.20'), 'pnpm-lock.yaml'), { ...osvResult(sentence('lodash@4.17.20')), message: 'not an object' }] })]);
  assert.equal(record.facts.findings.length, malformed.length + 2);
  assert.ok(record.facts.findings.every(item => item.package === null));
  assert.deepEqual(record.facts.observations[0].fieldReasons.find(item => item.reason === 'package_unavailable'), { reason: 'package_unavailable', count: malformed.length + 2 });
  assert.equal(JSON.stringify(record).includes('lodash'), false);
});

test('Gitleaks secrets of one rule without a path stay separate findings; only key order is normalized for the result digest', () => {
  const secret = (value: string) => ({ ruleId: 'generic-api-key', message: { text: `generic-api-key has detected secret ${value}` }, partialFingerprints: { email: 'person.name@example.invalid' } });
  const record = run([gitleaks({ revisions: [head], results: [secret('SECRETVALUE123'), secret('SECRETVALUE456')] })]);
  assert.equal(record.facts.findings.length, 2);
  assert.deepEqual(record.facts.findings.map(item => [item.path, item.startLine]), [[null, null], [null, null]]);
  const reordered = { partialFingerprints: { email: 'person.name@example.invalid' }, message: { text: 'generic-api-key has detected secret SECRETVALUE123' }, ruleId: 'generic-api-key' };
  const same = run([gitleaks({ revisions: [head], results: [secret('SECRETVALUE123'), reordered] })]);
  assert.deepEqual(same.facts.findings.map(item => item.occurrences[0].count), [2]);
  const tagged = (tags: string[]) => ({ ruleId: 'generic-api-key', properties: { tags } });
  assert.equal(run([gitleaks({ revisions: [head], results: [tagged(['a', 'b']), tagged(['b', 'a'])] })]).facts.findings.length, 2, 'array order is kept');
  const text = JSON.stringify(record);
  for (const value of ['SECRETVALUE', 'person.name@example.invalid', 'detected secret']) assert.equal(text.includes(value), false, value);
});

test('re-importing results of incomplete identity, alone or with the earlier record, gives the same findings and no more', () => {
  const sarif = osv({ revisions: [head], results: [osvResult(sentence('lodash@4.17.20')), osvResult('Package lodash is vulnerable'), osvResult('Package lodash is vulnerable too')] });
  const leaks = gitleaks({ revisions: [head], results: [{ ruleId: 'generic-api-key', message: { text: 'one' } }, { ruleId: 'generic-api-key', message: { text: 'two' } }] });
  const earlier = run([sarif, leaks]);
  assert.equal(earlier.facts.findings.length, 5);
  assert.deepEqual(run([sarif, leaks]).facts.findings.map(item => item.findingId), earlier.facts.findings.map(item => item.findingId));
  const again = run([earlier, sarif, leaks]);
  assert.deepEqual(again.view.inputs.map(row => row.state), ['accepted', 'duplicate', 'duplicate']);
  assert.deepEqual(again.facts.findings, earlier.facts.findings);
  const tampered = structuredClone(earlier) as unknown as { facts: { findings: { package: { name: string } | null }[] }; factsDigest: string };
  tampered.facts.findings.find(item => item.package)!.package!.name = 'Bad Name';
  tampered.factsDigest = digest(tampered.facts);
  assert.deepEqual(reasonsOf(run([tampered])), ['invalid_shape']);
});

const retag = <T extends { facts: unknown; factsDigest: string }>(record: T, change: (copy: T) => void): T => {
  const copy = structuredClone(record); change(copy); copy.factsDigest = digest(copy.facts); return copy;
};
const leakAt = (extra: Record<string, unknown> = {}) => ({ ruleId: 'generic-api-key', level: 'error',
  locations: [{ physicalLocation: { artifactLocation: { uri: 'config/settings.env' }, region: { startLine: 3 } } }], ...extra });
type Mutable = { facts: { observations: { fieldReasons: unknown[] }[]; findings: { ruleId: string | null; occurrences: { count: number; imports: { importId: string; count: number }[] }[] }[] }; factsDigest: string };

test('review 1: rejected inputs survive re-aggregation, and an empty record is not plain accepted', () => {
  const broken = run(['{']);
  assert.equal(broken.view.exitCode, 3);
  const again = run([broken]);
  assert.equal(again.view.exitCode, 3, 'a record of a rejected input stays incomplete');
  assert.ok(again.view.inputs[0].reasons.includes('record_carries_rejected' as never));
  assert.deepEqual((again.facts as unknown as { rejected: unknown[] }).rejected, [{ sha256: hash(Buffer.from('{')), bytes: 1, reason: 'invalid_json', unreadId: null }]);
  assert.equal(run([run([again])]).view.exitCode, 3, 'every later read re-emits the rejection');
  const mixed = run([run([gitleaks({ revisions: [head], results: [leakAt()] }), '{'])]);
  assert.equal(mixed.view.exitCode, 3);
  const empty = run([run([])]);
  assert.deepEqual(empty.view.inputs[0].reasons, ['record_empty']);
  assert.equal(empty.view.exitCode, 3);
});

test('review 2: a declaration conflict is kept whatever the input order and survives deduplication', () => {
  const sarif = gitleaks({ revisions: [head], results: [leakAt()] });
  const earlier = run([sarif]);
  assert.equal(earlier.view.exitCode, 0);
  const forward = run([earlier, sarif], { declared: older }), backward = run([sarif, earlier], { declared: older });
  for (const record of [forward, backward]) {
    assert.equal(record.view.exitCode, 3);
    for (const row of record.view.inputs) assert.ok(row.reasons.includes('declaration_conflict'), JSON.stringify(row));
  }
  assert.deepEqual(forward.facts, backward.facts, 'input order does not change the facts');
  assert.ok(observation(run([forward])).reasons.includes('declaration_conflict'), 'the conflict is stored, not only shown');
});

test('review 3: results without a ruleId are incomplete identities and stay separate', () => {
  const record = run([gitleaks({ revisions: [head], results: [leakAt({ ruleId: undefined, message: { text: 'one' } }), leakAt({ ruleId: undefined, message: { text: 'two' } })] })]);
  assert.equal(record.facts.findings.length, 2);
});

test('review 4: a saved record whose facts disagree with themselves is record_inconsistent', () => {
  const unnamed = run([gitleaks({ revisions: [head], results: [leakAt({ ruleId: undefined })] })]);
  assert.deepEqual(unnamed.facts.observations[0].fieldReasons, [{ reason: 'rule_unavailable', count: 1 }]);
  const cleared = retag(unnamed as unknown as Mutable, copy => { copy.facts.observations[0].fieldReasons = []; });
  assert.deepEqual(reasonsOf(run([cleared])), ['record_inconsistent']);
  const plain = run([gitleaks({ revisions: [head], results: [leakAt()] })]) as unknown as Mutable;
  const counted = retag(plain, copy => { copy.facts.findings[0].occurrences[0].count = 2; copy.facts.findings[0].occurrences[0].imports[0].count = 2; });
  assert.deepEqual(reasonsOf(run([counted])), ['record_inconsistent']);
  const orphan = retag(plain, copy => { copy.facts.findings[0].occurrences[0].imports[0].importId = 'f'.repeat(64); });
  assert.deepEqual(reasonsOf(run([orphan])), ['record_inconsistent']);
});

test('review 5: the same bytes under two bindings are marked input_rebound in either order', () => {
  const sarif = gitleaks({ results: [leakAt()] });
  const first = run([sarif], { declared: head });
  const forward = run([first, sarif], { declared: older }), backward = run([sarif, first], { declared: older });
  for (const record of [forward, backward]) {
    assert.equal(record.facts.observations.length, 2);
    for (const view of record.view.observations) assert.ok(view.reasons.includes('input_rebound' as never), JSON.stringify(view));
    assert.equal(record.view.exitCode, 3);
  }
});

test('review 7: level is kept per observation, so an old commit cannot set the level of HEAD', () => {
  const old = gitleaks({ revisions: [older], results: [leakAt({ level: 'none' })] }), current = gitleaks({ revisions: [head], results: [leakAt({ level: 'error' })] });
  const forward = run([old, current]), backward = run([current, old]);
  assert.deepEqual(forward.facts, backward.facts);
  const occurrence = forward.facts.findings[0].occurrences.find(item => item.commit === head)!;
  assert.deepEqual(occurrence.imports.map(item => (item as unknown as { levels: unknown }).levels), [[{ level: 'error', count: 1 }]]);
});

test('review 8: one invocation without executionSuccessful keeps the execution unrecorded', () => {
  const sarif = gitleaks({ revisions: [head], results: [leakAt()] });
  const partly = run([{ ...sarif, runs: [{ ...sarif.runs[0], invocations: [{ executionSuccessful: true }, {}] }] }]);
  assert.ok(observation(partly).reasons.includes('execution_unrecorded'));
  assert.equal(partly.view.exitCode, 3);
  const both = run([osv({ revisions: [head], invocations: [{ executionSuccessful: true }, { executionSuccessful: false }, {}] })]);
  assert.ok(observation(both).reasons.includes('execution_unrecorded'));
  assert.ok(observation(both).reasons.includes('tool_reported_incomplete'));
});

test('review 9: ruleIds follow a per-tool grammar, so paths and addresses never become a ruleId', () => {
  for (const ruleId of ['C:/Users/private-person', 'person@example', 'a\\b', 'with space', 'scheme:value']) {
    const leaks = run([gitleaks({ revisions: [head], results: [leakAt({ ruleId })] })]);
    assert.equal(leaks.facts.findings[0].ruleId, null, ruleId);
    assert.ok(observation(leaks).reasons.includes('rule_unavailable'), ruleId);
    assert.equal(JSON.stringify(leaks).includes(JSON.stringify(ruleId).slice(1, -1)), false, ruleId);
    const advisories = run([osv({ revisions: [head], results: [{ ...osvResult('x'), ruleId }] })]);
    assert.equal(advisories.facts.findings[0].ruleId, null, ruleId);
  }
  const accepted: [string, string][] = [['gitleaks', 'generic-api-key'], ['gitleaks', 'aws_access.token'], ['osv', 'GHSA-aaaa-bbbb-cccc'], ['osv', 'PYSEC-2021-1'], ['osv', 'CVE-2020-11111']];
  for (const [tool, ruleId] of accepted) {
    const record = tool === 'gitleaks' ? run([gitleaks({ revisions: [head], results: [leakAt({ ruleId })] })]) : run([osv({ revisions: [head], results: [{ ...osvResult('x'), ruleId }] })]);
    assert.equal(record.facts.findings[0].ruleId, ruleId);
  }
  const named = run([gitleaks({ revisions: [head], results: [leakAt()] })]) as unknown as Mutable;
  assert.deepEqual(reasonsOf(run([retag(named, copy => { copy.facts.findings[0].ruleId = 'C:/Users/private-person'; })])), ['invalid_shape']);
});

test('review 10: a saved record is held to maxFiles per observation like SARIF', () => {
  const two = run([gitleaks({ revisions: [head], results: [leakAt(), leakAt({ ruleId: 'other-rule' })] })]);
  assert.equal(two.view.exitCode, 0);
  assert.deepEqual(reasonsOf(run([two], { maxFiles: 1 })), ['results_over_limit']);
  assert.equal(run([two], { maxFiles: 2 }).view.inputs[0].state, 'accepted');
});

const withRules = (rules: unknown[], results: unknown[]) => {
  const sarif = gitleaks({ revisions: [head], results });
  (sarif.runs[0].tool.driver as Record<string, unknown>).rules = rules;
  return sarif;
};
const levelsOf = (record: ImportRecord) => record.facts.findings.map(item => item.occurrences[0].imports[0].levels);
type Sourced = { facts: { observations: { levelSources: Record<string, number> }[] }; factsDigest: string };

test('an absent level without a rule default is the SARIF default warning, as Gitleaks 8.30.1 writes it', () => {
  const record = run([gitleaks({ revisions: [head], results: [leakAt({ level: undefined })] })]);
  assert.deepEqual(levelsOf(record), [[{ level: 'warning', count: 1 }]]);
  assert.deepEqual(record.facts.observations[0].fieldReasons, []);
  assert.deepEqual(record.facts.observations[0].levelSources, { explicit: 0, ruleDefault: 0, sarifDefault: 1 });
  assert.equal(record.view.exitCode, 0);
  const again = run([record]);
  assert.equal(again.view.exitCode, 0, 'the saved record re-reads');
  assert.deepEqual(again.facts.observations[0].levelSources, record.facts.observations[0].levelSources);
});

test('an absent level takes the rule default by ruleIndex, then rule.index, then ruleId', () => {
  const rules = [{ id: 'other-rule', defaultConfiguration: { level: 'note' } }, { id: 'generic-api-key', defaultConfiguration: { level: 'error' } }, { id: 'bare-rule', defaultConfiguration: {} }];
  const cases: [Record<string, unknown>, string, keyof LevelSources][] = [
    [{ ruleIndex: 0 }, 'note', 'ruleDefault'],
    [{ rule: { index: 0 } }, 'note', 'ruleDefault'],
    [{}, 'error', 'ruleDefault'],
    [{ ruleIndex: 9 }, 'error', 'ruleDefault'],
    [{ rule: { index: 0, toolComponent: { index: 0 } } }, 'error', 'ruleDefault'],
    [{ ruleId: 'bare-rule' }, 'warning', 'sarifDefault'],
    [{ ruleId: 'unlisted-rule' }, 'warning', 'sarifDefault'],
  ];
  for (const [extra, level, source] of cases) {
    const record = run([withRules(rules, [leakAt({ level: undefined, ...extra })])]);
    const label = JSON.stringify(extra);
    assert.deepEqual(levelsOf(record), [[{ level, count: 1 }]], label);
    assert.equal(record.facts.observations[0].levelSources[source], 1, label);
    assert.equal(record.view.exitCode, 0, label);
  }
  const explicit = run([withRules(rules, [leakAt({ level: 'none' })])]);
  assert.deepEqual(levelsOf(explicit), [[{ level: 'none', count: 1 }]], 'a written level wins over the rule default');
  assert.deepEqual(explicit.facts.observations[0].levelSources, { explicit: 1, ruleDefault: 0, sarifDefault: 0 });
});

test('a present but unreadable level, or an unreadable rule default, is level_unavailable', () => {
  const cases: [unknown[], Record<string, unknown>][] = [
    [[], { level: 'high' }], [[], { level: null }], [[], { level: 1 }],
    [[{ id: 'generic-api-key', defaultConfiguration: { level: 'high' } }], { level: undefined }],
    [[{ id: 'generic-api-key', defaultConfiguration: 'error' }], { level: undefined }],
  ];
  for (const [rules, extra] of cases) {
    const record = run([withRules(rules, [leakAt(extra)])]);
    const label = JSON.stringify([rules, extra]);
    assert.deepEqual(record.facts.observations[0].fieldReasons, [{ reason: 'level_unavailable', count: 1 }], label);
    assert.deepEqual(record.facts.observations[0].levelSources, { explicit: 0, ruleDefault: 0, sarifDefault: 0 }, label);
    assert.equal(record.view.exitCode, 3, label);
    assert.equal(run([record]).view.exitCode, 3, label);
  }
});

test('saved level sources must account for every result and agree with the levels', () => {
  const record = run([gitleaks({ revisions: [head], results: [leakAt()] })]) as unknown as Sourced;
  assert.deepEqual(reasonsOf(run([retag(record, copy => { copy.facts.observations[0].levelSources.explicit = 2; })])), ['record_inconsistent']);
  assert.deepEqual(reasonsOf(run([retag(record, copy => { copy.facts.observations[0].levelSources = { explicit: 0, ruleDefault: 0, sarifDefault: 1 }; })])), ['record_inconsistent']);
  assert.deepEqual(reasonsOf(run([retag(record, copy => { delete (copy.facts.observations[0] as Partial<Sourced['facts']['observations'][0]>).levelSources; })])), ['invalid_shape']);
});

test('review small: an unreadable revisionId is a closed reason, not a rejected input', () => {
  for (const revision of ['A'.repeat(40), 'a'.repeat(64), 'main']) {
    const alone = run([gitleaks({ revisions: [revision], results: [leakAt()] })]);
    assert.equal(alone.view.inputs[0].state, 'accepted', revision);
    assert.deepEqual(alone.facts.observations[0].basis, { kind: 'unbound', commit: null });
    assert.ok(observation(alone).reasons.includes('recorded_sha_unreadable' as never));
    assert.equal(alone.view.exitCode, 3);
    assert.equal(JSON.stringify(alone.facts).includes(revision), false, 'the unreadable value is not output');
    const withValid = run([gitleaks({ revisions: [revision, head], results: [leakAt()] })]);
    assert.deepEqual(withValid.facts.observations[0].basis, { kind: 'recorded', commit: head });
    assert.ok(observation(withValid).reasons.includes('recorded_sha_unreadable' as never));
    const declared = run([gitleaks({ revisions: [revision], results: [leakAt()] })], { declared: head });
    assert.deepEqual(declared.facts.observations[0].basis, { kind: 'declared', commit: head });
    assert.equal(run([alone]).view.exitCode, 3, 'the reason survives re-reading');
  }
});

test('recheck 1: an empty record stays a lasting gap through every later re-aggregation', () => {
  const empty = run([]), sarif = gitleaks({ revisions: [head], results: [leakAt()] });
  assert.equal(run([sarif]).view.exitCode, 0);
  const once = run([empty, sarif]);
  assert.deepEqual(once.view.inputs[0].reasons, ['record_empty']);
  assert.equal(once.view.exitCode, 3);
  const twice = run([once]);
  assert.equal(twice.view.exitCode, 3, 'R(R(E,S)) still misses the empty record');
  assert.equal(run([twice, sarif]).view.exitCode, 3);
});

test('recheck 2: a record holding a result-count rejection re-reads with that rejection and its accepted finding', () => {
  const good = gitleaks({ revisions: [head], results: [leakAt()] }), many = gitleaks({ revisions: [head], results: [leakAt(), leakAt({ ruleId: 'other-rule' })] });
  const limited = run([good, many], { maxFiles: 1 });
  assert.equal(limited.facts.findings.length, 1);
  assert.deepEqual(limited.facts.rejected.map(item => [item.sha256, item.reason]), [[hash(Buffer.from(JSON.stringify(many))), 'results_over_limit']]);
  const again = run([limited], { maxFiles: 1 });
  assert.equal(again.view.inputs[0].state, 'accepted');
  assert.deepEqual(again.view.inputs[0].reasons, ['record_carries_rejected']);
  assert.equal(again.view.exitCode, 3);
  assert.deepEqual(again.facts.rejected, limited.facts.rejected, 'the original input and reason are kept, not replaced by the record');
  assert.deepEqual(again.facts.findings, limited.facts.findings);
  const unread = run([{ kind: 'over_limit', bytes: 10 }]);
  assert.deepEqual(unread.facts.rejected.map(item => [item.sha256, item.reason]), [[null, 'over_limit']]);
  assert.equal(run([unread]).view.inputs[0].state, 'accepted');
});

test('recheck 3: unread inputs of one size are counted one by one, and re-reading never multiplies them', () => {
  const unread = run([{ kind: 'over_limit', bytes: 100 }, { kind: 'over_limit', bytes: 100 }]);
  assert.equal(unread.facts.rejected.length, 2);
  assert.equal(run([unread]).facts.rejected.length, 2);
  assert.equal(run([unread, unread]).facts.rejected.length, 2);
  assert.equal(run([unread, run([unread])]).facts.rejected.length, 2);
  assert.equal(run([run([{ kind: 'over_limit', bytes: 100 }]), run([{ kind: 'over_limit', bytes: 100 }])]).facts.rejected.length, 2, 'two runs refused two inputs');
});

test('recheck 4: records that give one findingId two cores are record_inconsistent whatever the input order', () => {
  const sarif = gitleaks({ results: [leakAt({ ruleId: undefined })] });
  const atHead = run([sarif], { declared: head }), atOlder = run([sarif], { declared: older });
  assert.equal(atHead.facts.findings[0].findingId, atOlder.facts.findings[0].findingId);
  const moved = retag(atOlder as unknown as { facts: { findings: { startLine: number }[] }; factsDigest: string }, copy => { copy.facts.findings[0].startLine = 4; });
  for (const inputs of [[atHead, moved], [moved, atHead]]) {
    const record = run(inputs);
    assert.deepEqual(record.view.inputs.map(row => [row.state, row.reasons]), [['rejected', ['record_inconsistent']], ['rejected', ['record_inconsistent']]]);
    assert.equal(record.facts.findings.length, 0);
  }
  const forward = run([moved, sarif], { declared: head }), backward = run([sarif, moved], { declared: head });
  assert.deepEqual(forward.facts, backward.facts, 'input order does not choose the core');
  assert.deepEqual(forward.facts.findings.map(item => item.startLine), [3], 'the SARIF read is the truth');
  assert.deepEqual(forward.view.inputs.map(row => row.state), ['rejected', 'accepted']);
  assert.deepEqual(forward.view.inputs[0].reasons, ['record_inconsistent']);
});

type SavedFinding = { findingId: string; tool: string; ruleId: string | null; path: string | null; startLine: number | null; package: { ecosystem: string; name: string; version: string } | null };
test('recheck 5: a saved OSV package must agree with its ruleId, lockfile path and the ecosystem of that lockfile', () => {
  const record = run([osv({ revisions: [head], results: [osvResult(sentence('lodash@4.17.20'))] })]);
  assert.deepEqual(record.facts.findings[0].package, { ecosystem: 'npm', name: 'lodash', version: '4.17.20' });
  const rebuilt = (change: (finding: SavedFinding) => void) => retag(record as unknown as { facts: { findings: SavedFinding[] }; factsDigest: string }, copy => {
    const finding = copy.facts.findings[0]; change(finding);
    finding.findingId = digest(['import/v1', finding.tool, finding.ruleId, finding.path, finding.startLine, finding.package]);
  });
  assert.equal(run([rebuilt(() => {})]).view.inputs[0].state, 'accepted', 'an unchanged rebuild is still read');
  const changes: [string, (finding: SavedFinding) => void][] = [
    ['path off a lockfile', finding => { finding.path = 'config/settings.env'; }],
    ['ecosystem of another lockfile', finding => { finding.package = { ...finding.package!, ecosystem: 'PyPI' }; }],
    ['uv.lock with npm', finding => { finding.path = 'uv.lock'; }],
  ];
  for (const [label, change] of changes) assert.deepEqual(reasonsOf(run([rebuilt(change)])), ['record_inconsistent'], label);
});

test('recheck 6: import records are scanmux.import/v2, and a v1 record is refused with a hint to import its SARIF again', () => {
  const record = run([gitleaks({ revisions: [head], results: [leakAt()] })]);
  assert.equal(record.schema, 'scanmux.import/v2');
  const earlier = run([{ ...record, schema: 'scanmux.import/v1' }]);
  assert.deepEqual(earlier.view.inputs.map(row => [row.kind, row.state, row.reasons]), [['record', 'rejected', ['unsupported_schema']]]);
  assert.equal(earlier.view.exitCode, 3);
  assert.match(importText(earlier, 'import.json'), /^Input 1: .*import the original SARIF again/m);
});

test('recheck 8: driver.rules that is not an array is invalid_shape; an unreadable referenced rule is level_unavailable', () => {
  for (const rules of [{ x: 'unreadable' }, 'rules', 1, null]) {
    assert.deepEqual(reasonsOf(run([withRules(rules as unknown as unknown[], [leakAt({ level: undefined })])])), ['invalid_shape'], JSON.stringify(rules));
  }
  const listed = [{ id: 'generic-api-key', defaultConfiguration: { level: 'error' } }];
  const cases: [unknown[], Record<string, unknown>][] = [
    [['unreadable', ...listed], { ruleIndex: 0 }], [listed, { ruleIndex: '0' }], [listed, { ruleIndex: 1.5 }], [listed, { rule: 'generic-api-key' }],
    [['unreadable', ...listed], { ruleId: 'unlisted-rule' }],
  ];
  for (const [rules, extra] of cases) {
    const record = run([withRules(rules, [leakAt({ level: undefined, ...extra })])]);
    const label = JSON.stringify([rules, extra]);
    assert.deepEqual(record.facts.observations[0].fieldReasons, [{ reason: 'level_unavailable', count: 1 }], label);
    assert.equal(record.view.exitCode, 3, label);
  }
  const unlisted = run([withRules(listed, [leakAt({ level: undefined, ruleId: 'unlisted-rule' })])]);
  assert.equal(unlisted.facts.observations[0].levelSources.sarifDefault, 1, 'a readable list without the rule is the SARIF default');
});
