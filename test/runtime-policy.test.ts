import test from 'node:test';
import assert from 'node:assert/strict';
import { SafeError, digest } from '../src/safety.ts';
import {
  decideRuntimePolicy, parseRuntimePolicy, runtimeComponents, runtimePolicyCode, runtimePolicyRef,
  type RuntimeComponent, type RuntimeRefusal, type RuntimeSubject,
} from '../src/runtime-policy.ts';

const id = '0f8e2c4a-6b1d-4e3f-9a7c-5d2b8e1f0a63';
const sha = (character: string) => character.repeat(64);
const policy = (overrides: Record<string, unknown> = {}) => ({ schema: 'scanmux.runtime-policy/v1', id, revision: 1, state: 'active', deny: [], ...overrides });
const parsed = (overrides: Record<string, unknown> = {}) => parseRuntimePolicy(policy(overrides));
const invalid = (error: unknown) => error instanceof SafeError && error.code === 'runtime_policy_invalid' && error.message === 'runtime_policy_invalid';
const subjects = (component: RuntimeComponent, digest: string | null): RuntimeSubject[] =>
  runtimeComponents.map(item => ({ component: item, sha256: item === component ? digest : sha('f') }));

test('the component set includes the optional Trivy engine', () => {
  assert.deepEqual([...runtimeComponents].sort(), ['codex-cli', 'codex-security-sdk', 'docker', 'git', 'gitleaks', 'linux-image', 'node', 'osv', 'trivy', 'windows-owner']);
});

test('decision table: every decision kind for every component, with fixed codes', () => {
  for (const component of runtimeComponents) {
    const name = component.replaceAll('-', '_');
    const rows: Array<{ deny: unknown[]; digest: string | null; kind: string; code: string | null }> = [
      { deny: [], digest: sha('a'), kind: 'continue', code: null },
      { deny: [], digest: null, kind: 'continue', code: null },
      { deny: [{ kind: 'digest', component, sha256: sha('b') }], digest: sha('a'), kind: 'continue', code: null },
      { deny: [{ kind: 'component', component }], digest: sha('a'), kind: 'denied', code: `runtime_policy_denied_${name}_component` },
      { deny: [{ kind: 'component', component }], digest: null, kind: 'denied', code: `runtime_policy_denied_${name}_component` },
      { deny: [{ kind: 'digest', component, sha256: sha('a') }], digest: sha('a'), kind: 'denied', code: `runtime_policy_denied_${name}_digest` },
      { deny: [{ kind: 'digest', component, sha256: sha('a') }], digest: null, kind: 'unidentified', code: `runtime_policy_unidentified_${name}` },
      { deny: [{ kind: 'digest', component, sha256: sha('b') }], digest: null, kind: 'unidentified', code: `runtime_policy_unidentified_${name}` },
    ];
    for (const row of rows) {
      const value = parsed({ deny: row.deny });
      const decision = decideRuntimePolicy(value, subjects(component, row.digest));
      assert.equal(decision.kind, row.kind, `${component} ${JSON.stringify(row)}`);
      if (decision.kind === 'continue') continue;
      assert.deepEqual(decision.policy, runtimePolicyRef(value));
      assert.equal(runtimePolicyCode(decision), row.code);
      assert.match(runtimePolicyCode(decision), /^[a-z_]+$/);
      if (decision.kind !== 'stopped') assert.equal(decision.component, component);
    }
    const stopped = parsed({ state: 'stopped', deny: [{ kind: 'component', component }] });
    const decision = decideRuntimePolicy(stopped, subjects(component, null));
    assert.deepEqual(decision, { kind: 'stopped', policy: runtimePolicyRef(stopped) });
    assert.equal(runtimePolicyCode(decision as RuntimeRefusal), 'runtime_policy_stopped');
  }
});

test('stopped wins over every deny rule, even with no subjects', () => {
  const value = parsed({ state: 'stopped', deny: runtimeComponents.map(component => ({ kind: 'component', component })) });
  assert.equal(decideRuntimePolicy(value, subjects('git', sha('a'))).kind, 'stopped');
  assert.equal(decideRuntimePolicy(value, []).kind, 'stopped');
  assert.deepEqual(decideRuntimePolicy(parsed(), []), { kind: 'continue' });
});

test('decision follows closure order and never consults another component rule', () => {
  const value = parsed({ deny: [{ kind: 'component', component: 'node' }, { kind: 'digest', component: 'docker', sha256: sha('a') }] });
  const first = decideRuntimePolicy(value, [{ component: 'docker', sha256: null }, { component: 'node', sha256: sha('b') }]);
  assert.equal(first.kind, 'unidentified');
  const second = decideRuntimePolicy(value, [{ component: 'node', sha256: sha('b') }, { component: 'docker', sha256: null }]);
  assert.equal(second.kind === 'denied' && second.component, 'node');
  assert.deepEqual(decideRuntimePolicy(value, [{ component: 'git', sha256: sha('a') }, { component: 'docker', sha256: sha('b') }]), { kind: 'continue' });
});

test('invalid subject lists are errors before stop or deny is considered', () => {
  const stopped = parsed({ state: 'stopped' });
  for (const subject of [{ component: 'python', sha256: null }, { component: 'git', sha256: sha('A') }, { component: 'git', sha256: 'a'.repeat(63) }, { component: 'git', sha256: '' }]) {
    assert.throws(() => decideRuntimePolicy(stopped, [subject as RuntimeSubject]), invalid);
  }
});

test('canonical identity ignores rule order and changes with state, id, revision and each rule', () => {
  const rules = [{ kind: 'digest', component: 'git', sha256: sha('b') }, { kind: 'component', component: 'osv' }, { kind: 'digest', component: 'git', sha256: sha('a') }, { kind: 'component', component: 'git' }];
  const base = runtimePolicyRef(parsed({ deny: rules }));
  assert.equal(base.sha256, 'a9da0eb23edff1032152d48f2fd6fad087143e4074aaf777d62bbe40dee14bbf');
  assert.deepEqual({ id: base.id, revision: base.revision, state: base.state }, { id, revision: 1, state: 'active' });
  for (const order of [[...rules].reverse(), [rules[2], rules[0], rules[3], rules[1]]]) {
    assert.equal(runtimePolicyRef(parsed({ deny: order })).sha256, base.sha256);
  }
  const keyOrder = { deny: rules.map(rule => Object.fromEntries(Object.entries(rule).reverse())), revision: 1, state: 'active', id, schema: 'scanmux.runtime-policy/v1' };
  assert.equal(runtimePolicyRef(parseRuntimePolicy(keyOrder)).sha256, base.sha256);
  const variants = [
    { state: 'stopped', deny: rules }, { id: '0f8e2c4a-6b1d-4e3f-9a7c-5d2b8e1f0a64', deny: rules }, { revision: 2, deny: rules },
    { deny: rules.slice(1) }, { deny: [...rules, { kind: 'component', component: 'node' }] },
    { deny: rules.map((rule, index) => index === 0 ? { ...rule, sha256: sha('c') } : rule) },
    { deny: rules.map((rule, index) => index === 1 ? { ...rule, component: 'docker' } : rule) },
  ];
  const identities = new Set([base.sha256, ...variants.map(variant => runtimePolicyRef(parsed(variant)).sha256)]);
  assert.equal(identities.size, variants.length + 1);
});

test('parser accepts the exact shape and rejects every malformed class with a fixed code', () => {
  assert.deepEqual(parsed({ revision: Number.MAX_SAFE_INTEGER, state: 'stopped' }), policy({ revision: Number.MAX_SAFE_INTEGER, state: 'stopped' }));
  const echoed = 'ECHO-THIS-INPUT';
  const rejected: unknown[] = [
    null, [], 'policy', policy({ schema: 'scanmux.runtime-policy/v2' }),
    (() => { const value: Record<string, unknown> = policy(); delete value.deny; return value; })(),
    (() => { const value: Record<string, unknown> = policy(); delete value.revision; return value; })(),
    policy({ extra: true }), policy({ [echoed]: echoed }),
    policy({ id: id.toUpperCase() }), policy({ id: echoed }), policy({ id: id.replaceAll('-', '') }), policy({ id: '{' + id + '}' }), policy({ id: 7 }),
    policy({ revision: 0 }), policy({ revision: -1 }), policy({ revision: 1.5 }), policy({ revision: '1' }), policy({ revision: Number.MAX_SAFE_INTEGER + 1 }), policy({ revision: Number.NaN }),
    policy({ state: 'paused' }), policy({ state: 'ACTIVE' }),
    policy({ deny: {} }), policy({ deny: null }), policy({ deny: 'git' }),
    policy({ deny: [{ kind: 'component', component: echoed }] }), policy({ deny: [{ kind: 'component', component: 'GIT' }] }),
    policy({ deny: [{ kind: 'component', component: 'git', sha256: sha('a') }] }), policy({ deny: [{ kind: 'component' }] }),
    policy({ deny: [{ kind: 'digest', component: 'git' }] }), policy({ deny: [{ kind: 'digest', component: 'git', sha256: sha('A') }] }),
    policy({ deny: [{ kind: 'digest', component: 'git', sha256: sha('a'), domain: 'image_sha256' }] }),
    policy({ deny: [{ kind: 'digest', component: 'git', sha256: 'a'.repeat(65) }] }), policy({ deny: [{ kind: 'allow', component: 'git' }] }), policy({ deny: [null] }), policy({ deny: [[]] }),
    policy({ deny: [{ kind: 'component', component: 'git' }, { component: 'git', kind: 'component' }] }),
    policy({ deny: [{ kind: 'digest', component: 'osv', sha256: sha('a') }, { kind: 'component', component: 'git' }, { sha256: sha('a'), kind: 'digest', component: 'osv' }] }),
  ];
  for (const input of rejected) {
    assert.throws(() => parseRuntimePolicy(input), (error: unknown) => invalid(error) && !String((error as Error).message).includes(echoed) && !String((error as Error).stack).includes(echoed), JSON.stringify(input));
  }
  const parsedDistinct = parsed({ deny: [{ kind: 'component', component: 'git' }, { kind: 'digest', component: 'git', sha256: sha('a') }, { kind: 'digest', component: 'git', sha256: sha('b') }] });
  assert.equal(parsedDistinct.deny.length, 3);
});
