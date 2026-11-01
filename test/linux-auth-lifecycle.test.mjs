import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { isProbeCommand, ProbeProcesses, ProofLifecycle, cleanupOwned, observeProtocolProcess, observeChildErrors } from '../scripts/linux-auth-lifecycle.mjs';

const command = '/usr/local/bin/node /fixture/auth-probe.mjs';
test('only complete fixed direct and observed bash argv can supply probe evidence', () => {
  for (const argv of [['/usr/local/bin/node', '/fixture/auth-probe.mjs'], ...['-c', '-lc'].map(flag => ['/usr/bin/bash', flag, command])]) {
    assert.equal(isProbeCommand(argv), true);
    const processes = new ProbeProcesses();
    assert.equal(processes.register('probe', argv), true);
    assert.equal(processes.has('probe'), true);
    assert.equal(processes.has('other'), false);
    assert.throws(() => processes.register('probe', argv));
  }
  for (const argv of [null, [], [command], ['/bin/sh', '-c', 'printf fabricated', '-c', command],
    ['/usr/bin/bash', '-c', 'printf fabricated', '-c', command],
    ['/usr/bin/bash', '-c', command, 'extra'], ['/usr/bin/bash', 'prefix', '-c', command],
    ['/other/program', '-c', command], ['/usr/bin/bash', '-c', ` ${command}`],
    ['/usr/bin/bash', '-c', `${command}; printf fabricated`], ['/usr/local/bin/node', '/fixture/auth-probe.mjs', 'extra']]) {
    const processes = new ProbeProcesses();
    assert.equal(processes.register('untrusted', argv), false);
    assert.equal(processes.has('untrusted'), false);
    assert.throws(() => processes.register('untrusted', ['/usr/bin/bash', '-c', command]));
  }
});

test('fatal failures at every lifecycle phase remain failed after observation and cleanup', async () => {
  for (const phase of ['before_observation', 'after_observation', 'after_exit', 'after_disconnect', 'during_cleanup']) {
    for (const failure of ['relay_output_invalid', 'relay_output_limit', 'websocket_failed', 'unexpected_worker_close', 'app_protocol_failed']) {
      const lifecycle = new ProofLifecycle();
      const operation = lifecycle.guard(new Promise(() => {}));
      lifecycle.fail(`${phase}_${failure}`);
      await assert.rejects(operation, { message: `${phase}_${failure}` });
      assert.throws(() => lifecycle.assertHealthy());
      lifecycle.fail('later_failure');
      assert.equal(lifecycle.failure, `${phase}_${failure}`);
      assert.equal(lifecycle.result('verified_auth_separation_program_unverified'), 'failed');
      assert.equal((await cleanupOwned([['normal', async () => {}]], lifecycle, e => e.message)).length, 0);
      assert.equal(lifecycle.result('verified_model_free'), 'failed');
    }
  }
  const healthy = new ProofLifecycle();
  healthy.assertHealthy();
  assert.equal(await healthy.guard(Promise.resolve('done')), 'done');
  assert.equal(healthy.result('verified_model_free'), 'verified_model_free');
  assert.equal(healthy.result('failed'), 'failed');
});

test('every owned cleanup runs after each possible failure and multiple failures', async () => {
  const resources = ['relay', 'child_inventory', 'app', 'children', 'child_absence', 'container', 'attachment', 'listener'];
  for (const failed of [[], ...resources.map(name => [name]), resources]) {
    const lifecycle = new ProofLifecycle();
    const attempted = [], confirmed = [];
    const errors = await cleanupOwned(resources.map(name => [name, async () => {
      attempted.push(name);
      if (failed.includes(name)) throw new Error('injected');
      confirmed.push(name);
    }]), lifecycle, e => e.message);
    assert.deepEqual(attempted, resources);
    assert.deepEqual(errors.map(e => e.resource), failed);
    assert.deepEqual(confirmed, resources.filter(name => !failed.includes(name)));
    assert.equal(lifecycle.result('verified_model_free'), failed.length ? 'failed' : 'verified_model_free');
  }
});

function harness(name, options = {}) {
  const child = Object.assign(new EventEmitter(), { stdin: new EventEmitter(), stdout: new EventEmitter(), stderr: new EventEmitter() });
  const lifecycle = new ProofLifecycle(), messages = [];
  let expected = false, bytes = 0;
  const protocol = observeProtocolProcess(child, {
    name, consume: data => { bytes += data.length; assert.ok(bytes <= 256); },
    onMessage: message => { if (options.throwMessage) throw new Error('injected'); messages.push(message); },
    onStderr: () => { if (options.throwStderr) throw new Error('injected'); },
    fail: code => lifecycle.fail(code),
    allowStdinError: error => expected && error.code === 'EPIPE',
    onClose: () => { if (options.throwClose) throw new Error('injected'); if (!expected) lifecycle.fail(`${name}_unexpected_close`); },
  });
  return { child, lifecycle, protocol, messages,
    expectClose: () => { expected = true; },
    end: () => { child.stdout.emit('end'); child.stdout.emit('close'); child.stderr.emit('end'); child.stderr.emit('close'); child.emit('close', 0); },
  };
}

test('actual app and worker handlers accept split UTF-8 records and settle only on close', async () => {
  for (const name of ['app', 'worker']) {
    const h = harness(name), record = Buffer.from('{"observed":"実測"}\n');
    for (const byte of record) h.child.stdout.emit('data', Buffer.from([byte]));
    assert.deepEqual(h.messages, [{ observed: '実測' }]);
    assert.equal(h.protocol.state.closed, false);
    h.expectClose(); h.end();
    assert.deepEqual(await h.protocol.closed, { stdoutEnded: true, stderrEnded: true, closed: true });
    assert.equal(h.lifecycle.failure, null);
  }
});

test('actual data/end/close handlers reject every unfinished or malformed tail before and after observation', async () => {
  for (const name of ['app', 'worker']) for (const observed of [false, true]) for (const intentional of [false, true]) {
    for (const tail of [Buffer.from('not-json'), Buffer.from('{}'), Buffer.from(' '), Buffer.from([0xc3]), Buffer.from('not-json\n'), Buffer.from([0xc3, 10])]) {
      const h = harness(name);
      if (observed) h.child.stdout.emit('data', Buffer.from('{"observed":true}\n'));
      h.child.stdout.emit('data', tail);
      if (intentional) h.expectClose();
      h.end(); await h.protocol.closed;
      assert.equal(h.messages.length, observed ? 1 : 0);
      assert.equal(h.lifecycle.failure, `${name}_protocol_failed`);
      assert.equal(h.lifecycle.result('verified_auth_separation_program_unverified'), 'failed');
    }
  }
});

test('actual stream and process error handlers reject the operation and allow independent cleanup', async () => {
  for (const name of ['app', 'worker']) for (const stream of ['stdin', 'stdout', 'stderr', 'child']) for (const observed of [false, true]) {
    const h = harness(name), attempted = [];
    if (observed) h.child.stdout.emit('data', Buffer.from('{"observed":true}\n'));
    h.expectClose();
    const operation = h.lifecycle.guard(new Promise(() => {}));
    assert.doesNotThrow(() => (stream === 'child' ? h.child : h.child[stream]).emit('error', new Error('injected_pipe_failure')));
    await assert.rejects(operation);
    await cleanupOwned(['app', 'children', 'container', 'attachment', 'listener'].map(resource => [resource, async () => {
      attempted.push(resource);
      if (resource === 'app') { h.end(); await h.protocol.closed; throw new Error('cleanup_injected'); }
    }]), h.lifecycle, e => e.message);
    assert.deepEqual(attempted, ['app', 'children', 'container', 'attachment', 'listener']);
    assert.equal(h.lifecycle.result('verified_auth_separation_program_unverified'), 'failed');
    assert.match(h.lifecycle.failure, new RegExp(`^${name}_`));
  }
});

test('actual handlers reject missing EOF, over-limit output and callback failures without escaping', async () => {
  for (const name of ['app', 'worker']) {
    for (const event of ['missing_stdout_end', 'missing_stderr_end', 'stdout_limit', 'stderr_limit', 'message_throw', 'stderr_throw', 'close_throw']) {
      const h = harness(name, { throwMessage: event === 'message_throw', throwStderr: event === 'stderr_throw', throwClose: event === 'close_throw' });
      h.expectClose();
      assert.doesNotThrow(() => {
        if (event === 'stdout_limit') h.child.stdout.emit('data', Buffer.alloc(257));
        if (event === 'stderr_limit') h.child.stderr.emit('data', Buffer.alloc(257));
        if (event === 'message_throw') h.child.stdout.emit('data', Buffer.from('{}\n'));
        if (event === 'stderr_throw') h.child.stderr.emit('data', Buffer.from('diagnostic'));
        if (event !== 'missing_stdout_end') h.child.stdout.emit('end');
        h.child.stdout.emit('close');
        if (event !== 'missing_stderr_end') h.child.stderr.emit('end');
        h.child.stderr.emit('close'); h.child.emit('close', 0);
      });
      await h.protocol.closed;
      assert.equal(h.lifecycle.result('verified_model_free'), 'failed');
    }
  }
});

test('control-process pipe errors use the same owned-error boundary; only expected EPIPE is allowed', () => {
  for (const stream of ['stdout', 'stderr', 'child']) {
    const child = Object.assign(new EventEmitter(), { stdout: new EventEmitter(), stderr: new EventEmitter() });
    const errors = [];
    observeChildErrors(child, 'control', code => errors.push(code));
    assert.doesNotThrow(() => (stream === 'child' ? child : child[stream]).emit('error', new Error('injected')));
    assert.equal(errors.length, 1);
  }
  const active = harness('app');
  active.child.stdin.emit('error', Object.assign(new Error('pipe'), { code: 'EPIPE' }));
  assert.equal(active.lifecycle.failure, 'app_stdin_failed');
  const closing = harness('app'); closing.expectClose();
  closing.child.stdin.emit('error', Object.assign(new Error('pipe'), { code: 'EPIPE' }));
  assert.equal(closing.lifecycle.failure, null);
  closing.child.stdin.emit('error', Object.assign(new Error('read'), { code: 'EIO' }));
  assert.equal(closing.lifecycle.failure, 'app_stdin_failed');
});
