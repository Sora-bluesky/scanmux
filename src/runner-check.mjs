import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { WebSocket, WebSocketServer } from 'ws';
import { ProofLifecycle, cleanupOwned, observeProtocolProcess, observeChildErrors } from './runner-lifecycle.mjs';
import { checkRemoteRequest, daybreakStatus, verifyContainerBoundary } from './runner-policy.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const endpoint = 'npipe:////./pipe/dockerDesktopLinuxEngine';
const allowedStdinClose = error => ['EPIPE', 'ERR_STREAM_DESTROYED', 'ERR_STREAM_WRITE_AFTER_END'].includes(error.code);
const errorCode = error => error instanceof assert.AssertionError ? 'boundary_assertion_failed' : /^[a-z_]+$/.test(error.message) ? error.message : 'runner_check_failed';

export async function checkRunner(config, workspace, signal) {
  const result = {
    schema: 'scanmux.runner-check/v1', runId: randomUUID(), createdAt: new Date().toISOString(), state: 'INCOMPLETE',
    provider: 'openai', authentication: 'unverified', aiTurns: 0, codeExecution: 'not_checked',
    ...daybreakStatus([], []), checks: {}, cleanup: {}, blockers: ['daybreak_effective_unknown', 'production_scan_not_integrated'],
  };
  if (!config.runner) { result.blockers.unshift('runner_not_configured'); return result; }
  if (process.platform !== 'win32') { result.blockers.unshift('runner_host_unsupported'); return result; }
  const runner = config.runner;
  const runRoot = path.join(workspace, `runner-${result.runId}`);
  const fixture = path.join(runRoot, 'fixture');
  const dockerConfig = path.join(runRoot, 'docker');
  const token = randomBytes(32).toString('base64url');
  const lifecycle = new ProofLifecycle();
  const controlEnv = { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, TEMP: runRoot, TMP: runRoot, DOCKER_CONFIG: dockerConfig };
  const pendingRemote = new Map();
  let app, worker, appRpc, workerProtocol, server, wss, connection, containerId, createAttempted = false, closing = false, remoteBytes = 0;
  let resolveConfig;
  const configRead = new Promise(resolve => { resolveConfig = resolve; });
  const fail = code => lifecycle.fail(code);
  const abort = () => fail('cancelled');
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  function count(b) { remoteBytes += b.length; assert.ok(remoteBytes <= config.maxOutputBytes, 'output_limit'); }
  function healthy() { lifecycle.assertHealthy(); }
  async function control(executable, args, decodeOutput = true) {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, { cwd: runRoot, env: controlEnv, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let bytes = 0, output = Buffer.alloc(0), failure;
      const stop = code => { failure ??= code; child.kill(); };
      observeChildErrors(child, 'control', stop);
      const timer = setTimeout(() => stop('control_timeout'), config.timeoutMs);
      const consume = b => { bytes += b.length; if (bytes > config.maxOutputBytes) stop('control_output_limit'); };
      child.stdout.on('data', b => { consume(b); if (!failure) output = Buffer.concat([output, b]); });
      child.stderr.on('data', consume);
      child.once('close', code => {
        clearTimeout(timer);
        if (failure) reject(new Error(failure));
        else { try { resolve({ code, output: decodeOutput ? new TextDecoder('utf-8', { fatal: true }).decode(output) : '' }); } catch { reject(new Error('control_encoding')); } }
      });
    });
  }
  async function docker(args, required = true) {
    const row = await control(runner.docker.path, ['--host', endpoint, '--config', dockerConfig, ...args]);
    if (required && row.code !== 0) throw new Error('docker_command_failed');
    return row;
  }
  async function inspect() {
    const row = await docker(['inspect', containerId], false);
    if (row.code === 0) {
      const info = JSON.parse(row.output)[0];
      assert.equal(info.Id, containerId); assert.equal(info.Config.Labels['scanmux.runner-check'], result.runId);
      return info;
    }
    await docker(['version', '--format', '{{.Server.Version}}']);
    const ids = (await docker(['ps', '-a', '--no-trunc', '--format', '{{.ID}}'])).output.trim().split(/\r?\n/);
    assert.ok(!ids.includes(containerId)); return null;
  }
  async function stopContainer() {
    if (!containerId && createAttempted) {
      const ids = (await docker(['ps', '-a', '--no-trunc', '--filter', `label=scanmux.runner-check=${result.runId}`, '--format', '{{.ID}}'])).output.trim().split(/\r?\n/).filter(Boolean);
      assert.ok(ids.length <= 1); containerId = ids[0];
    }
    if (!containerId) { result.cleanup.containerAbsent = true; return; }
    let info = await inspect();
    if (info?.State.Running) { await docker(['stop', '--time', '1', containerId], false); info = await inspect(); }
    if (info?.State.Running) { await docker(['kill', containerId], false); info = await inspect(); }
    if (info) { assert.equal(info.State.Running, false); await docker(['rm', containerId], false); }
    assert.equal(await inspect(), null); result.cleanup.containerAbsent = true;
  }
  function rpc(child) {
    let sequence = 0, bytes = 0;
    const pending = new Map();
    const dead = code => { if (!closing) fail(code); for (const row of pending.values()) { clearTimeout(row.timer); row.reject(new Error(code)); } pending.clear(); };
    const protocol = observeProtocolProcess(child, {
      name: 'app', fail, allowStdinError: e => closing && allowedStdinClose(e), consume(b) { bytes += b.length; assert.ok(bytes <= config.maxOutputBytes); }, onStderr() {}, onClose: () => dead('app_closed'),
      onMessage(message) {
        if (message.id !== undefined && message.method) {
          child.stdin.write(JSON.stringify({ id: message.id, error: { code: -32601, message: 'model_free_diagnostic' } }) + '\n');
          fail('unexpected_app_request'); return;
        }
        if (message.id !== undefined) {
          const row = pending.get(message.id); assert.ok(row); pending.delete(message.id); clearTimeout(row.timer);
          if (message.error) row.reject(new Error('app_request_failed')); else row.resolve(message.result);
        } else if (message.method === 'turn/started' || message.method === 'item/started') fail('unexpected_inference');
      },
    });
    return { protocol, request(method, params = {}) {
      healthy();
      return lifecycle.guard(new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error('app_request_timeout')); }, config.timeoutMs);
        pending.set(id, { resolve, reject, timer }); child.stdin.write(JSON.stringify({ id, method, params }) + '\n');
      }));
    } };
  }
  function workerMessage(message) {
    assert.ok(message && typeof message === 'object' && !Array.isArray(message));
    assert.ok(message.id !== undefined && message.method === undefined, 'unsolicited_worker_message');
    const method = pendingRemote.get(message.id); assert.ok(method); pendingRemote.delete(message.id);
    if (method === 'environmentConfig/read' && !message.error) {
      assert.equal(message.result.codexHomeDir, 'file:///work/codex-home');
      assert.deepEqual(message.result.config.layers, []); assert.deepEqual(message.result.requirements.layers, []);
      result.checks.workerConfigEmpty = true; resolveConfig();
    }
    if (connection?.readyState === WebSocket.OPEN) connection.send(JSON.stringify(message));
    else if (!closing) fail('worker_without_connection');
  }
  async function startRelay() {
    server = http.createServer((req, res) => { res.writeHead(403); res.end(); });
    server.on('error', () => fail('relay_server_error'));
    wss = new WebSocketServer({ noServer: true, maxPayload: config.maxOutputBytes, perMessageDeflate: false });
    wss.on('error', () => fail('relay_socket_error'));
    server.on('upgrade', (req, socket, head) => {
      const header = Buffer.from(req.headers.authorization ?? ''); const expected = Buffer.from(`Bearer ${token}`);
      const valid = !closing && !connection && req.headers.origin === undefined && req.url === '/' && header.length === expected.length && timingSafeEqual(header, expected);
      if (!valid) { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
      wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws));
    });
    wss.on('connection', ws => {
      connection = ws;
      ws.on('error', () => fail('relay_connection_error'));
      ws.on('close', () => { if (!closing) fail('relay_connection_closed'); });
      ws.on('message', (bytes, binary) => {
        try {
          count(bytes); assert.equal(binary, false);
          const message = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
          const action = checkRemoteRequest(message);
          if (action === 'deny_metadata') { ws.send(JSON.stringify({ id: message.id, error: { code: -32600, message: 'metadata_outside_diagnostic' } })); return; }
          if (message.id !== undefined) { assert.ok(!pendingRemote.has(message.id)); pendingRemote.set(message.id, message.method); }
          assert.ok(worker?.stdin.writable);
          if (!worker.stdin.write(JSON.stringify(message) + '\n')) ws.pause();
        } catch { fail('relay_request_rejected'); }
      });
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    return `ws://127.0.0.1:${server.address().port}/`;
  }
  async function closeChild(child, protocol, name) {
    if (!child) { result.cleanup[name] = true; return; }
    child.stdin.end();
    async function withinGrace() {
      let timer;
      try { return await Promise.race([protocol.closed.then(() => true), new Promise(resolve => { timer = setTimeout(() => resolve(false), 3000); })]); }
      finally { clearTimeout(timer); }
    }
    if (!await withinGrace()) {
      // taskkill emits localized console text; only its exit status is a contract.
      const stopped = await control(path.join(process.env.SystemRoot, 'System32/taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'], false);
      assert.ok(stopped.code === 0 || protocol.state.closed);
      assert.ok(await withinGrace());
    }
    assert.ok(protocol.state.stdoutEnded && protocol.state.stderrEnded && protocol.state.closed);
    result.cleanup[name] = true;
  }
  async function expectDenied(url, headers) {
    return new Promise((resolve, reject) => {
      let answered = false;
      const socket = new WebSocket(url, { headers, handshakeTimeout: 3000 });
      socket.on('unexpected-response', (request, response) => {
        answered = true; response.resume(); request.destroy();
        if (response.statusCode === 403) resolve(); else reject(new Error('unexpected_relay_status'));
      });
      socket.on('open', () => { socket.terminate(); reject(new Error('unauthorized_relay_connection')); });
      socket.on('error', () => { if (!answered) reject(new Error('relay_denial_probe_failed')); });
    });
  }
  try {
    healthy();
    await fs.mkdir(runRoot); await fs.mkdir(fixture); await fs.mkdir(dockerConfig);
    await fs.writeFile(path.join(dockerConfig, 'config.json'), '{}\n', { flag: 'wx', mode: 0o600 });
    for (const tool of [runner.codex, runner.linuxCodex, runner.docker]) {
      const stat = await fs.lstat(tool.path); assert.ok(stat.isFile() && !stat.isSymbolicLink());
      assert.equal(hash(await fs.readFile(tool.path)), tool.sha256);
    }
    assert.equal(runner.codex.version, '0.163.0'); assert.equal(runner.linuxCodex.version, '0.163.0');
    result.checks.binaryPins = true;
    const authStat = await fs.lstat(runner.authHome); assert.ok(authStat.isDirectory() && !authStat.isSymbolicLink());
    await assert.rejects(fs.access(path.join(runner.authHome, 'environments.toml')), { code: 'ENOENT' });
    healthy();
    const url = await startRelay();
    const inherited = Object.fromEntries(['SystemRoot', 'WINDIR', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'PATH', 'PATHEXT'].filter(k => process.env[k]).map(k => [k, process.env[k]]));
    const env = { ...inherited, TEMP: runRoot, TMP: runRoot, CODEX_HOME: runner.authHome, CODEX_EXEC_SERVER_URL: url };
    const overrides = {
      forced_login_method: 'chatgpt', model_provider: 'openai', sandbox_mode: 'read-only', approval_policy: 'on-request', allow_login_shell: false,
      project_doc_max_bytes: 0, web_search: 'disabled', 'plugins._default.enabled': false, 'features.apps': false, 'features.enable_mcp_apps': false,
      'features.js_repl': false, 'features.code_mode': false, 'features.code_mode_host.enabled': false, 'features.multi_agent': false,
      'features.skip_host_skill_discovery': true, 'features.shell_snapshot': false,
      openai_base_url: 'https://chatgpt.com/backend-api/codex', chatgpt_base_url: 'https://chatgpt.com/backend-api',
    };
    for (const name of runner.disabledMcpServers) overrides[`mcp_servers.${name}.enabled`] = false;
    for (const name of runner.disabledPlugins) overrides[`plugins.${name}.enabled`] = false;
    const args = ['app-server', '--stdio', ...Object.entries(overrides).flatMap(([k, v]) => ['-c', `${k}=${JSON.stringify(v)}`])];
    app = spawn(runner.codex.path, args, { cwd: fixture, env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    appRpc = rpc(app);
    await appRpc.request('initialize', { clientInfo: { name: 'scanmux_runner_check', version: '0.2.0' }, capabilities: { experimentalApi: true } });
    app.stdin.write(JSON.stringify({ method: 'initialized', params: {} }) + '\n');
    const effective = (await appRpc.request('config/read', { includeLayers: false })).config;
    assert.equal(effective.forced_login_method, 'chatgpt'); assert.equal(effective.model_provider, 'openai');
    assert.equal(effective.openai_base_url, overrides.openai_base_url); assert.equal(effective.chatgpt_base_url, overrides.chatgpt_base_url);
    assert.equal(effective.features.code_mode_host.enabled, false);
    for (const entry of Object.values(effective.mcp_servers ?? {})) assert.equal(entry.enabled, false);
    for (const entry of Object.values(effective.plugins ?? {})) assert.equal(entry.enabled, false);
    result.checks.connectionsDisabled = true;
    assert.equal((await appRpc.request('environment/status', { environmentId: 'local' })).status, 'unknown');
    result.checks.localEnvironmentAbsent = true;
    const account = await appRpc.request('account/read', { refreshToken: false });
    assert.equal(account.account?.type, 'chatgpt'); result.authentication = 'chatgpt';
    const models = [], features = [];
    for (const [method, rows] of [['model/list', models], ['experimentalFeature/list', features]]) {
      let cursor; const seen = new Set();
      do {
        const response = await appRpc.request(method, { ...(method === 'model/list' ? { includeHidden: true } : {}), ...(cursor ? { cursor } : {}) });
        assert.ok(Array.isArray(response.data)); rows.push(...response.data);
        cursor = response.nextCursor;
        if (cursor) { assert.equal(typeof cursor, 'string'); assert.ok(!seen.has(cursor)); seen.add(cursor); }
      } while (cursor);
    }
    Object.assign(result, daybreakStatus(models, features));
    if (!result.advertisedPrograms.includes('daybreakBlue')) result.blockers.push('daybreak_not_advertised');
    if (!result.cliDaybreakEnabled) result.blockers.push('cli_daybreak_disabled');
    healthy();
    const imageInfo = JSON.parse((await docker(['image', 'inspect', runner.image])).output)[0];
    assert.equal(imageInfo.Id, runner.image); assert.equal(imageInfo.Os, 'linux'); assert.equal(imageInfo.Architecture, 'amd64');
    createAttempted = true;
    const created = await docker(['create', '--pull=never', '--rm', '--name', `scanmux-check-${result.runId}`, '--label', `scanmux.runner-check=${result.runId}`,
      '--network', 'none', '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--ipc', 'private', '--cgroupns', 'private',
      '--pids-limit', '64', '--memory', '268435456', '--memory-swap', '268435456', '--cpus', '1', '--log-driver', 'none',
      '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=33554432,mode=1777', '--tmpfs', '/work:rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700',
      '--mount', `type=bind,source=${runner.linuxCodex.path},target=/tools/codex,readonly`, '--mount', `type=bind,source=${fixture},target=/fixture,readonly`,
      '--env', 'HOME=/work/home', '--env', 'CODEX_HOME=/work/codex-home', '--env', 'TMPDIR=/tmp', '--workdir', '/work', '--entrypoint', '/bin/sh', '-i', runner.image,
      '-c', 'mkdir -p /work/home /work/codex-home && exec /tools/codex exec-server --listen stdio']);
    containerId = created.output.trim(); assert.match(containerId, /^[a-f0-9]{64}$/); healthy();
    const info = await inspect();
    verifyContainerBoundary(info, runner.image);
    result.checks.containerBoundary = true;
    worker = spawn(runner.docker.path, ['--host', endpoint, '--config', dockerConfig, 'start', '--attach', '--interactive', containerId], { cwd: runRoot, env: controlEnv, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    workerProtocol = observeProtocolProcess(worker, { name: 'worker', fail, consume: count, onMessage: workerMessage, onStderr() {}, allowStdinError: e => closing && allowedStdinClose(e), onClose() { if (!closing) fail('worker_closed'); connection?.terminate(); } });
    worker.stdin.on('drain', () => connection?.resume());
    await expectDenied(url, {});
    await expectDenied(url, { Authorization: 'Bearer invalid' });
    await expectDenied(url, { Authorization: `Bearer ${token}`, Origin: 'https://example.invalid' });
    result.checks.unauthorizedConnectionsDenied = true;
    await appRpc.request('environment/add', { environmentId: 'remote', execServerUrl: url, authBearerToken: token, connectTimeoutMs: 3000 });
    const remote = await appRpc.request('environment/info', { environmentId: 'remote' });
    assert.equal(remote.cwd, 'file:///work'); assert.equal(remote.shell.path, '/usr/bin/bash');
    result.checks.linuxConnected = true;
    await expectDenied(url, { Authorization: `Bearer ${token}` });
    result.checks.secondConnectionDenied = true;
    const thread = await appRpc.request('thread/start', { model: 'gpt-6-sol', modelProvider: 'openai', allowProviderModelFallback: false, ephemeral: true, sandbox: 'read-only', approvalPolicy: 'on-request', environments: [{ environmentId: 'remote', cwd: '/work', runtimeWorkspaceRoots: ['/fixture'] }] });
    assert.equal(thread.sandbox.type, 'readOnly'); assert.equal(thread.modelProvider, 'openai'); assert.equal(thread.model, 'gpt-6-sol');
    assert.deepEqual(thread.thread.environments.map(e => e.environmentId), ['remote']);
    let timer;
    try { await lifecycle.guard(Promise.race([configRead, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('worker_config_timeout')), config.timeoutMs); })])); }
    finally { clearTimeout(timer); }
    assert.equal((await appRpc.request('environment/status', { environmentId: 'remote' })).status, 'ready');
    result.checks.linuxThreadReady = true; healthy();
  } catch (error) { result.state = 'ERROR'; result.failure = errorCode(error); }
  finally {
    closing = true;
    result.cleanup.errors = await cleanupOwned([
      ['relay', async () => { connection?.terminate(); worker?.stdin.end(); }],
      ['app', () => closeChild(app, appRpc?.protocol, 'appExited')],
      ['container', stopContainer],
      ['worker', () => closeChild(worker, workerProtocol, 'workerExited')],
      ['listener', async () => { wss?.close(); if (server) { server.closeAllConnections(); await new Promise((resolve, reject) => server.close(e => e ? reject(e) : resolve())); } result.cleanup.listenerClosed = true; }],
    ], lifecycle, errorCode);
    signal.removeEventListener('abort', abort);
    result.cleanup.protocols = { app: appRpc?.protocol.state ?? null, worker: workerProtocol?.state ?? null };
    if (lifecycle.failure) { result.state = 'ERROR'; result.failure ??= lifecycle.failure; }
    assert.ok(!JSON.stringify(result).includes(token));
  }
  return result;
}
