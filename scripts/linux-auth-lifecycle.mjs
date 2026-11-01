import assert from 'node:assert/strict';

const command = '/usr/local/bin/node /fixture/auth-probe.mjs';
export function isProbeCommand(argv) {
  return Array.isArray(argv) && (
    (argv.length === 2 && argv[0] === '/usr/local/bin/node' && argv[1] === '/fixture/auth-probe.mjs') ||
    (argv.length === 3 && argv[0] === '/usr/bin/bash' && ['-c', '-lc'].includes(argv[1]) && argv[2] === command)
  );
}

export class ProbeProcesses {
  #processes = new Map();
  register(id, argv) {
    assert.ok(typeof id === 'string' && id.length > 0 && !this.#processes.has(id), 'invalid_or_reused_process_id');
    const exact = isProbeCommand(argv);
    this.#processes.set(id, exact);
    return exact;
  }
  has(id) { return this.#processes.get(id) === true; }
}

export class ProofLifecycle {
  failure = null;
  #reject;
  #failed = new Promise((_, reject) => { this.#reject = reject; });
  constructor() { this.#failed.catch(() => {}); }
  fail(code) {
    if (this.failure !== null) return;
    this.failure = code;
    this.#reject(new Error(code));
  }
  guard(operation) { return Promise.race([operation, this.#failed]); }
  assertHealthy() { if (this.failure !== null) throw new Error(this.failure); }
  result(proposed) { return this.failure === null ? proposed : 'failed'; }
}

// Every owned resource gets its cleanup attempt, including after another fails.
export async function cleanupOwned(steps, lifecycle, safeError) {
  const errors = [];
  for (const [resource, cleanup] of steps) {
    try { await cleanup(); }
    catch (error) {
      const code = safeError(error);
      errors.push({ resource, code });
      lifecycle.fail(`cleanup_${resource}_${code}`);
    }
  }
  return errors;
}

// One owner for all child stdio events, including termination without a final LF.
export function observeChildErrors(child, name, fail, allowStdinError = () => false) {
  child.on('error', () => fail(`${name}_spawn_failed`));
  child.stdout?.on('error', () => fail(`${name}_stdout_failed`));
  child.stderr?.on('error', () => fail(`${name}_stderr_failed`));
  child.stdin?.on('error', error => {
    try { if (!allowStdinError(error)) fail(`${name}_stdin_failed`); }
    catch { fail(`${name}_stdin_failed`); }
  });
}

export function observeProtocolProcess(child, { name, consume, onMessage, onStderr, fail, allowStdinError = () => false, onClose = () => {} }) {
  let buffer = Buffer.alloc(0);
  const state = { stdoutEnded: false, stderrEnded: false, closed: false };
  let resolveClosed;
  const closed = new Promise(resolve => { resolveClosed = resolve; });
  const safe = (code, operation) => (...args) => {
    try { operation(...args); } catch { fail(`${name}_${code}`); }
  };
  const finish = () => { if (buffer.length !== 0) throw new Error('incomplete_protocol_record'); };
  observeChildErrors(child, name, fail, allowStdinError);
  child.stdout.on('data', safe('protocol_failed', data => {
    assert.ok(!state.stdoutEnded && !state.closed);
    consume(data);
    buffer = Buffer.concat([buffer, data]);
    let end;
    while ((end = buffer.indexOf(10)) >= 0) {
      const line = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, end));
      buffer = buffer.subarray(end + 1);
      if (line.trim()) onMessage(JSON.parse(line));
    }
  }));
  child.stdout.on('end', safe('protocol_failed', () => { state.stdoutEnded = true; finish(); }));
  child.stdout.on('close', safe('protocol_failed', () => { assert.ok(state.stdoutEnded); finish(); }));
  child.stderr.on('data', safe('stderr_failed', data => {
    assert.ok(!state.stderrEnded && !state.closed);
    consume(data); onStderr(data);
  }));
  child.stderr.on('end', () => { state.stderrEnded = true; });
  child.stderr.on('close', () => { if (!state.stderrEnded) fail(`${name}_stderr_closed_without_end`); });
  child.once('close', safe('close_failed', (...args) => {
    try {
      if (!state.stdoutEnded || !state.stderrEnded) fail(`${name}_streams_not_ended`);
      try { finish(); } catch { fail(`${name}_protocol_failed`); }
      onClose(...args);
    } finally {
      state.closed = true;
      resolveClosed({ ...state });
    }
  }));
  return { closed, get state() { return { ...state }; } };
}
