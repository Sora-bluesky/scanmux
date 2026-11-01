import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SafeError, digest, hash } from '../src/safety.ts';
import { decideRuntimePolicy, parseRuntimePolicy, parseRuntimePolicy2, runtimeComponents, runtimePolicyCode, runtimePolicyRef, type RuntimePolicy2, type RuntimeRefusal } from '../src/runtime-policy.ts';
import { nextLedgerLine, parseLedgerLine, readPinnedLedger, type LedgerEntry, type LedgerFields } from '../src/engine-ledger.ts';
import {
  ProvenanceRefusalError, decideProvenance, evaluateGhVerification, planProvenance, provenanceCode, provenanceSubjects,
  type GhExpectation, type ProvenanceSubject,
} from '../src/provenance.ts';

const id = '0f8e2c4a-6b1d-4e3f-9a7c-5d2b8e1f0a63';
const sha = (character: string) => character.repeat(64);
const zero = sha('0');
const absolute = (name: string) => path.join(os.tmpdir(), 'scanmux-provenance-fixed', name);
const publisher = {
  repository: 'google/osv-scanner',
  certIdentity: 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0',
  oidcIssuer: 'https://token.actions.githubusercontent.com', predicateType: 'https://slsa.dev/provenance/v0.2', runner: 'github-hosted',
};
const provenance = (overrides: Record<string, unknown> = {}) => ({
  verifier: { path: absolute('gh.exe'), sha256: sha('9'), version: '2.94.0' },
  ledger: { path: absolute('ledger.jsonl'), entries: 0, head: zero },
  require: [{ component: 'osv', level: 'publisher', publisher }, { component: 'gitleaks', level: 'recorded' }],
  ...overrides,
});
const policy2 = (overrides: Record<string, unknown> = {}) => ({ schema: 'scanmux.runtime-policy/v2', id, revision: 1, state: 'active', deny: [], provenance: provenance(), ...overrides });
const invalid = (error: unknown) => error instanceof SafeError && error.code === 'runtime_policy_invalid';
const mismatch = (error: unknown) => error instanceof SafeError && error.code === 'provenance_ledger_mismatch';

test('v2 accepts the exact shape, may name gh in deny, and refuses every malformed class', () => {
  const accepted = policy2({ deny: [{ kind: 'component', component: 'gh' }, { kind: 'digest', component: 'osv', sha256: sha('a') }] });
  assert.deepEqual(parseRuntimePolicy2(accepted), accepted);
  assert.deepEqual(parseRuntimePolicy2(policy2({ provenance: provenance({ ledger: { path: absolute('l'), entries: 3, head: sha('c') }, require: [] }) })).provenance.ledger.entries, 3);
  const shaped = (field: string, value: unknown) => policy2({ provenance: provenance({ [field]: value }) });
  const rejected: unknown[] = [
    policy2({ schema: 'scanmux.runtime-policy/v1' }), (() => { const value: Record<string, unknown> = policy2(); delete value.provenance; return value; })(),
    policy2({ provenance: null }), policy2({ provenance: { ...provenance(), extra: 1 } }), policy2({ deny: [{ kind: 'component', component: 'python' }] }),
    shaped('verifier', { path: 'gh.exe', sha256: sha('9'), version: '2.94.0' }), shaped('verifier', { path: absolute('gh.exe'), sha256: sha('G'), version: '2.94.0' }),
    shaped('verifier', { path: absolute('gh.exe'), sha256: sha('9'), version: '2.94' }), shaped('verifier', { path: absolute('gh.exe'), sha256: sha('9') }),
    shaped('ledger', { path: absolute('l'), entries: 0, head: sha('c') }), shaped('ledger', { path: absolute('l'), entries: -1, head: zero }),
    shaped('ledger', { path: absolute('l'), entries: 1.5, head: sha('c') }), shaped('ledger', { path: absolute('l'), entries: Number.MAX_SAFE_INTEGER + 1, head: sha('c') }),
    shaped('ledger', { path: 'relative/ledger', entries: 0, head: zero }), shaped('ledger', { path: absolute('l\n'), entries: 0, head: zero }),
    shaped('ledger', { path: absolute('l'), entries: 1, head: sha('C') }), shaped('require', {}),
    shaped('require', [{ component: 'gh', level: 'recorded' }]), shaped('require', [{ component: 'gh', level: 'publisher', publisher }]),
    shaped('require', [{ component: 'osv', level: 'recorded' }, { component: 'osv', level: 'publisher', publisher }]),
    shaped('require', [{ component: 'osv', level: 'signed' }]), shaped('require', [{ component: 'osv', level: 'recorded', publisher }]),
    shaped('require', [{ component: 'osv', level: 'publisher' }]),
    ...[
      { repository: 'osv-scanner' }, { repository: 'google/osv-scanner/extra' }, { repository: 'google/..' }, { repository: '-google/osv' },
      { certIdentity: 'http://github.com/x' }, { certIdentity: 'https://github.com/a b' }, { oidcIssuer: '' }, { predicateType: 7 },
      { runner: 'self-hosted' }, { extra: true },
    ].map(change => shaped('require', [{ component: 'osv', level: 'publisher', publisher: { ...publisher, ...change } }])),
  ];
  for (const input of rejected) assert.throws(() => parseRuntimePolicy2(input), invalid, JSON.stringify(input));
});

test('v1 is unchanged: gh is refused and the canonical identity is the old shape', () => {
  assert.throws(() => parseRuntimePolicy({ schema: 'scanmux.runtime-policy/v1', id, revision: 1, state: 'active', deny: [{ kind: 'component', component: 'gh' }] }), invalid);
  assert.throws(() => parseRuntimePolicy(policy2()), invalid);
  const v1 = parseRuntimePolicy({ schema: 'scanmux.runtime-policy/v1', id, revision: 2, state: 'stopped', deny: [{ kind: 'component', component: 'osv' }] });
  assert.equal(runtimePolicyRef(v1).sha256, digest({ schema: 'scanmux.runtime-policy/v1', id, revision: 2, state: 'stopped', deny: [{ kind: 'component', component: 'osv' }] }));
  assert.throws(() => decideRuntimePolicy(v1, [{ component: 'gh', sha256: sha('a') }]), invalid);
});

test('v2 identity covers provenance, ignores require order, and stop/deny applies to gh', () => {
  const base = parseRuntimePolicy2(policy2());
  const reordered = parseRuntimePolicy2(policy2({ provenance: provenance({ require: [...provenance().require].reverse() }) }));
  assert.equal(runtimePolicyRef(reordered).sha256, runtimePolicyRef(base).sha256);
  const variants = [
    provenance({ verifier: { path: absolute('gh.exe'), sha256: sha('8'), version: '2.94.0' } }),
    provenance({ verifier: { path: absolute('gh.exe'), sha256: sha('9'), version: '2.94.1' } }),
    provenance({ ledger: { path: absolute('ledger.jsonl'), entries: 1, head: sha('1') } }),
    provenance({ ledger: { path: absolute('other.jsonl'), entries: 0, head: zero } }),
    provenance({ require: [{ component: 'osv', level: 'recorded' }, { component: 'gitleaks', level: 'recorded' }] }),
    provenance({ require: [{ component: 'osv', level: 'publisher', publisher: { ...publisher, oidcIssuer: 'https://issuer.example' } }] }),
  ];
  const identities = new Set([runtimePolicyRef(base).sha256, ...variants.map(value => runtimePolicyRef(parseRuntimePolicy2(policy2({ provenance: value }))).sha256)]);
  assert.equal(identities.size, variants.length + 1);
  const denied = parseRuntimePolicy2(policy2({ deny: [{ kind: 'digest', component: 'gh', sha256: sha('9') }] }));
  const decision = decideRuntimePolicy(denied, [{ component: 'gh', sha256: sha('9') }]);
  assert.equal(runtimePolicyCode(decision as RuntimeRefusal), 'runtime_policy_denied_gh_digest');
  assert.equal(decideRuntimePolicy(parseRuntimePolicy2(policy2({ state: 'stopped' })), []).kind, 'stopped');
});

const sigstore = { kind: 'sigstore-slsa', bundle: { path: absolute('osv.sigstore'), sha256: sha('b') }, trustedRoot: { path: absolute('trusted_root.jsonl'), sha256: sha('d') },
  sourceRef: 'refs/tags/v2.7.0', sourceDigest: 'bfe2f84abd2f09fe0b83ba7f6dad40d296762f40' } as const;
const fields = (overrides: Partial<LedgerFields> = {}): LedgerFields => ({
  recordedAt: '2026-10-25T01:02:03.004Z', component: 'osv', platform: 'windows-x64', version: '2.7.0', sha256: sha('a'), change: 'initial osv',
  recordedBy: { scanmux: '0.1.0-poc.1', verifier: { sha256: sha('9'), version: '2.94.0' } }, evidence: sigstore, ...overrides,
});
function chain(list: LedgerFields[]): { entries: LedgerEntry[]; lines: Buffer[]; heads: string[] } {
  const entries: LedgerEntry[] = [], lines: Buffer[] = [], heads: string[] = [];
  for (const item of list) { const next = nextLedgerLine(entries, item); entries.push(next.entry); lines.push(next.bytes); heads.push(next.head); }
  return { entries, lines, heads };
}
const three = () => chain([fields(), fields({ component: 'gitleaks', version: '8.30.1', sha256: sha('e'), change: 'gitleaks', evidence: { kind: 'none', reason: 'publisher_evidence_unpublished' } }),
  fields({ sha256: sha('f'), change: 'osv update', recordedBy: { scanmux: '0.1.0-poc.1', verifier: null } })]);

test('ledger lines are canonical: seq and prev chain, and any non-canonical spelling is refused', () => {
  const { entries, lines, heads } = three();
  assert.deepEqual(entries.map(entry => [entry.seq, entry.prev]), [[1, zero], [2, heads[0]], [3, heads[1]]]);
  assert.equal(lines[0].toString(), '{"seq":1,"prev":"' + zero + '","recordedAt":"2026-10-25T01:02:03.004Z","component":"osv","platform":"windows-x64","version":"2.7.0","sha256":"' + sha('a')
    + '","change":"initial osv","recordedBy":{"scanmux":"0.1.0-poc.1","verifier":{"sha256":"' + sha('9') + '","version":"2.94.0"}},"evidence":{"kind":"sigstore-slsa","bundle":{"path":'
    + JSON.stringify(sigstore.bundle.path) + ',"sha256":"' + sha('b') + '"},"trustedRoot":{"path":' + JSON.stringify(sigstore.trustedRoot.path) + ',"sha256":"' + sha('d')
    + '"},"sourceRef":"refs/tags/v2.7.0","sourceDigest":"bfe2f84abd2f09fe0b83ba7f6dad40d296762f40"}}\n');
  assert.equal(heads[0], hash(lines[0].subarray(0, -1)));
  const line = lines[1].subarray(0, -1).toString();
  assert.deepEqual(parseLedgerLine(line), entries[1]);
  const value = JSON.parse(line);
  const rejected = [
    JSON.stringify(value, null, 1), JSON.stringify(Object.fromEntries(Object.entries(value).reverse())), line + ' ', JSON.stringify({ ...value, extra: 1 }),
    JSON.stringify({ ...value, seq: 0 }), JSON.stringify({ ...value, component: 'gh' }), JSON.stringify({ ...value, platform: 'darwin-arm64' }),
    JSON.stringify({ ...value, recordedAt: '2026-02-30T00:00:00.000Z' }), JSON.stringify({ ...value, change: 'bell\u0007' }),
    JSON.stringify({ ...value, evidence: { kind: 'none', reason: 'trust_me' } }), JSON.stringify({ ...value, sha256: sha('E') }),
    line.replace('"version":"8.30.1"', '"version":"8.30\\u002e1"'), '[]', 'not json',
  ];
  for (const input of rejected) assert.throws(() => parseLedgerLine(input), (error: unknown) => error instanceof SafeError && error.code === 'engine_ledger_line_invalid', input);
  assert.throws(() => nextLedgerLine([], fields({ change: '' })), SafeError);
});

test('readPinnedLedger trusts only the pinned prefix and refuses any change to it', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'scanmux-ledger-'));
  try {
    const { entries, lines, heads } = three();
    const file = path.join(directory, 'ledger.jsonl');
    const read = async (content: Buffer, entriesCount: number, head: string) => { await writeFile(file, content); return readPinnedLedger({ path: file, entries: entriesCount, head }); };
    const full = Buffer.concat(lines);
    assert.deepEqual(await read(full, 3, heads[2]), entries);
    assert.deepEqual(await read(full, 2, heads[1]), entries.slice(0, 2));
    assert.deepEqual(await read(Buffer.concat([full, Buffer.from('{"seq":4,"torn')]), 3, heads[2]), entries);
    assert.deepEqual(await read(Buffer.concat([lines[0], Buffer.from('garbage\n')]), 1, heads[0]), entries.slice(0, 1));
    assert.deepEqual(await readPinnedLedger({ path: path.join(directory, 'absent.jsonl'), entries: 0, head: zero }), []);
    const middle = Buffer.from(lines[1]); middle[middle.indexOf('gitleaks') + 1] ^= 0x01;
    const rewritten = chain([fields({ change: 'initial osX' })]).lines[0];
    const failures: Array<[Buffer, number, string]> = [
      [Buffer.concat([rewritten, lines[1]]), 2, heads[1]],
      [Buffer.concat([lines[0], middle, lines[2]]), 3, heads[2]],
      [Buffer.concat([lines[1], lines[0], lines[2]]), 3, heads[2]],
      [Buffer.concat([lines[0], lines[2]]), 3, heads[2]], [Buffer.concat([lines[0], lines[2]]), 2, heads[2]],
      [full, 3, heads[1]], [full, 4, heads[2]], [full.subarray(0, -1), 3, heads[2]], [Buffer.concat([Buffer.from('\n'), full]), 3, heads[2]],
    ];
    for (const [content, count, head] of failures) await assert.rejects(read(content, count, head), mismatch);
    await assert.rejects(readPinnedLedger({ path: path.join(directory, 'absent.jsonl'), entries: 1, head: heads[0] }), mismatch);
    await assert.rejects(readPinnedLedger({ path: file, entries: 0, head: zero }, directory), (error: unknown) => error instanceof SafeError && error.code === 'provenance_ledger_inside_target');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const parsedPolicy = (require: unknown[]): RuntimePolicy2 => parseRuntimePolicy2(policy2({ provenance: provenance({ require }) }));
const recordedOsv = { component: 'osv', level: 'recorded' }, publisherOsv = { component: 'osv', level: 'publisher', publisher };

test('decision table: requirement level x ledger x evidence x file and digest presence', () => {
  const ledgerWith = (evidence: LedgerFields['evidence']) => chain([fields({ sha256: sha('7'), change: 'unrelated' }), fields({ evidence })]).entries;
  const unpublished = { kind: 'none', reason: 'publisher_evidence_unpublished' } as const;
  const subject = (overrides: Partial<ProvenanceSubject> = {}): ProvenanceSubject => ({ component: 'osv', sha256: sha('a'), file: absolute('osv.exe'), ...overrides });
  const rows: Array<{ require: unknown[]; ledger: LedgerEntry[]; subject: ProvenanceSubject; plan: 'ready' | string; reason?: string; seq?: number | null }> = [
    { require: [], ledger: [], subject: subject({ sha256: null, file: null }), plan: 'ready' },
    { require: [{ component: 'gitleaks', level: 'recorded' }], ledger: [], subject: subject(), plan: 'ready' },
    { require: [recordedOsv], ledger: ledgerWith(sigstore), subject: subject(), plan: 'ready' },
    { require: [recordedOsv], ledger: ledgerWith(unpublished), subject: subject({ file: null }), plan: 'ready' },
    { require: [recordedOsv], ledger: [], subject: subject(), plan: 'provenance_unrecorded_osv', reason: 'not_in_ledger', seq: null },
    { require: [recordedOsv], ledger: ledgerWith(sigstore), subject: subject({ sha256: sha('b') }), plan: 'provenance_unrecorded_osv', reason: 'not_in_ledger', seq: null },
    { require: [recordedOsv], ledger: ledgerWith(sigstore), subject: subject({ sha256: null }), plan: 'provenance_unrecorded_osv', reason: 'unhashed', seq: null },
    { require: [publisherOsv], ledger: ledgerWith(sigstore), subject: subject(), plan: 'ready' },
    { require: [publisherOsv], ledger: [], subject: subject(), plan: 'provenance_unrecorded_osv', reason: 'not_in_ledger', seq: null },
    { require: [publisherOsv], ledger: ledgerWith(unpublished), subject: subject(), plan: 'provenance_unverifiable_osv', reason: 'publisher_evidence_unpublished', seq: 2 },
    { require: [publisherOsv], ledger: ledgerWith({ kind: 'none', reason: 'os_signature_not_offline' }), subject: subject(), plan: 'provenance_unverifiable_osv', reason: 'os_signature_not_offline', seq: 2 },
    { require: [publisherOsv], ledger: ledgerWith(sigstore), subject: subject({ file: null }), plan: 'provenance_unverifiable_osv', reason: 'not_a_file', seq: null },
    { require: [publisherOsv], ledger: ledgerWith(sigstore), subject: subject({ sha256: null }), plan: 'provenance_unverifiable_osv', reason: 'unhashed', seq: null },
    { require: [publisherOsv], ledger: [], subject: subject({ sha256: null, file: null }), plan: 'provenance_unverifiable_osv', reason: 'unhashed', seq: null },
    { require: [{ component: 'codex-security-sdk', level: 'publisher', publisher }], ledger: [], subject: subject({ component: 'codex-security-sdk', file: null }),
      plan: 'provenance_unverifiable_codex_security_sdk', reason: 'not_a_file', seq: null },
  ];
  for (const row of rows) {
    const value = parsedPolicy(row.require);
    const plan = planProvenance(value, row.ledger, [row.subject]);
    const label = JSON.stringify({ require: row.require, ledger: row.ledger.length, subject: row.subject });
    if (row.plan === 'ready') { assert.equal(plan.kind, 'ready', label); continue; }
    assert.equal(plan.kind, 'refused', label);
    if (plan.kind !== 'refused') continue;
    assert.equal(provenanceCode(plan.engine), row.plan, label);
    assert.deepEqual({ reason: plan.engine.reason, ledgerSeq: plan.engine.ledgerSeq }, { reason: row.reason, ledgerSeq: row.seq }, label);
    assert.deepEqual(plan.policy, runtimePolicyRef(value));
    const error = new ProvenanceRefusalError(plan);
    assert.equal(error.code, row.plan);
    assert.match(error.code, /^[a-z_]+$/);
    assert.deepEqual(error.engine, plan.engine);
  }
});

test('the plan names the evidence to verify, prefers a sigstore record over a later none record, and stops at the first refusal', () => {
  const ledger = chain([fields(), fields({ evidence: { kind: 'none', reason: 'locally_built' }, change: 'rebuilt' })]).entries;
  const value = parsedPolicy([publisherOsv, { component: 'gitleaks', level: 'recorded' }]);
  const osv: ProvenanceSubject = { component: 'osv', sha256: sha('a'), file: absolute('osv.exe') };
  assert.deepEqual(planProvenance(value, ledger, [osv]), { kind: 'ready', checks: [{
    component: 'osv', file: absolute('osv.exe'), ledgerSeq: 1, bundle: sigstore.bundle, trustedRoot: sigstore.trustedRoot,
    expected: { ...publisher, sha256: sha('a'), sourceRef: sigstore.sourceRef, sourceDigest: sigstore.sourceDigest },
  }] });
  const refused = planProvenance(value, ledger, [{ component: 'gitleaks', sha256: sha('e'), file: null }, osv]);
  assert.equal(refused.kind === 'refused' && provenanceCode(refused.engine), 'provenance_unrecorded_gitleaks');
  assert.deepEqual(provenanceSubjects(value, [osv]), [osv, { component: 'gh', sha256: sha('9'), file: absolute('gh.exe') }]);
  assert.deepEqual(provenanceSubjects(value, [{ component: 'gitleaks', sha256: sha('e'), file: null }]), [{ component: 'gitleaks', sha256: sha('e'), file: null }]);
  assert.equal(planProvenance(value, ledger, provenanceSubjects(value, [osv])).kind, 'ready');
});

test('verifier outcomes map to verified, invalid or unverifiable with the ledger sequence', () => {
  const value = parsedPolicy([publisherOsv]);
  const plan = planProvenance(value, chain([fields()]).entries, [{ component: 'osv', sha256: sha('a'), file: absolute('osv.exe') }]);
  assert.equal(plan.kind, 'ready');
  if (plan.kind !== 'ready') return;
  const [check] = plan.checks;
  assert.deepEqual(decideProvenance(value, check, 'verified'), { kind: 'verified' });
  for (const [outcome, code, state, reason] of [['rejected', 'provenance_invalid_osv', 'invalid', 'signature_rejected'], ['failed', 'provenance_unverifiable_osv', 'unverifiable', 'verifier_failed'],
    ['evidence_changed', 'provenance_unverifiable_osv', 'unverifiable', 'evidence_changed'], ['evidence_unreadable', 'provenance_unverifiable_osv', 'unverifiable', 'evidence_unreadable'],
    ['artifact_changed', 'provenance_unverifiable_osv', 'unverifiable', 'artifact_changed'], ['artifact_unreadable', 'provenance_unverifiable_osv', 'unverifiable', 'artifact_unreadable']] as const) {
    const decision = decideProvenance(value, check, outcome);
    assert.equal(decision.kind, 'refused');
    if (decision.kind !== 'refused') continue;
    assert.deepEqual(decision.engine, { component: 'osv', state, reason, ledgerSeq: 1 });
    assert.equal(new ProvenanceRefusalError(decision).code, code);
  }
});

const expected: GhExpectation = { ...publisher, runner: 'github-hosted', sha256: sha('a'), sourceRef: 'refs/tags/v2.7.0', sourceDigest: 'bfe2f84abd2f09fe0b83ba7f6dad40d296762f40' };
const ghElement = () => ({
  attestation: { bundle: { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json' } },
  verificationResult: {
    mediaType: 'application/vnd.dev.sigstore.verificationresult+json;version=0.1',
    signature: { certificate: {
      certificateIssuer: 'CN=sigstore-intermediate,O=sigstore.dev', subjectAlternativeName: publisher.certIdentity, issuer: publisher.oidcIssuer,
      runnerEnvironment: 'github-hosted', sourceRepositoryURI: 'https://github.com/google/osv-scanner', sourceRepositoryDigest: expected.sourceDigest,
      sourceRepositoryRef: 'refs/tags/v2.7.0',
    } },
    statement: { _type: 'https://in-toto.io/Statement/v0.1', predicateType: publisher.predicateType,
      subject: [{ name: 'osv-scanner_linux_amd64', digest: { sha256: sha('c') } }, { name: 'osv-scanner_windows_amd64.exe', digest: { sha256: sha('a') } }] },
  },
});

test('gh output is verified only on exit 0 with a matching structured result', () => {
  const output = (elements: unknown) => JSON.stringify(elements);
  assert.equal(evaluateGhVerification(0, output([ghElement()]), expected), 'verified');
  assert.equal(evaluateGhVerification(0, Buffer.from(output([{ unrelated: true }, ghElement()])), expected), 'verified');
  assert.equal(evaluateGhVerification(1, output([ghElement()]), expected), 'rejected');
  assert.equal(evaluateGhVerification(1, '', expected), 'rejected');
  for (const code of [null, 2, -1, 255]) assert.equal(evaluateGhVerification(code, output([ghElement()]), expected), 'failed', String(code));
  const changed = (mutate: (element: ReturnType<typeof ghElement>) => void) => { const element = ghElement(); mutate(element); return output([element]); };
  const failures = [
    '', 'not json', '{}', '[]', output([null]), output(Array.from({ length: 65 }, ghElement)), ' '.repeat(4 * 1024 * 1024 + 1),
    changed(element => { element.verificationResult.statement.subject[1].digest.sha256 = sha('b'); }),
    changed(element => { element.verificationResult.statement.subject = []; }),
    changed(element => { element.verificationResult.statement.predicateType = 'https://slsa.dev/provenance/v1'; }),
    changed(element => { element.verificationResult.signature.certificate.subjectAlternativeName += 'x'; }),
    changed(element => { element.verificationResult.signature.certificate.issuer = 'https://example.com'; }),
    changed(element => { element.verificationResult.signature.certificate.sourceRepositoryURI = 'https://github.com/google/osv-scanner-fork'; }),
    changed(element => { element.verificationResult.signature.certificate.sourceRepositoryRef = 'refs/tags/v0.0.0-not-the-release'; }),
    changed(element => { element.verificationResult.signature.certificate.sourceRepositoryDigest = 'f'.repeat(40); }),
    changed(element => { element.verificationResult.signature.certificate.runnerEnvironment = 'self-hosted'; }),
    changed(element => { delete (element.verificationResult.signature as Record<string, unknown>).certificate; }),
    changed(element => { (element.verificationResult.statement as Record<string, unknown>).subject = { digest: { sha256: sha('a') } }; }),
  ];
  for (const stdout of failures) assert.equal(evaluateGhVerification(0, stdout, expected), 'failed', stdout.slice(0, 120));
  assert.deepEqual(runtimeComponents.includes('gh' as never), false);
});
