import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';

/** Single Linux stdio MCP owner. The caller supplies an exact trusted command,
 * runtime and finite byte bound; server output never chooses a command or tool.
 */
export function createStdioMcp({ command, args, cwd, environment, signal, expiresAt, maxBytes }) {
  if (process.platform !== 'linux' || !Number.isFinite(expiresAt) || !Number.isSafeInteger(maxBytes) || maxBytes < 1) throw Error('mcp_binding');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const pending = new Map();
  let child, started = false, closing = false, ended = false, failure, byteCount = 0, buffer = '', sequence = 0, exit;
  let resolveExit;
  const exited = new Promise(resolve => { resolveExit = resolve; });
  const rejectPending = () => { for (const p of pending.values()) p.reject(Error('mcp_unsettled')); pending.clear(); };
  const stop = code => {
    failure ??= code; rejectPending();
    if (child && !ended) try { process.kill(-child.pid, 'SIGKILL'); } catch {}
  };
  const check = () => {
    if (signal.aborted || performance.now() >= expiresAt) stop('mcp_stopped');
    if (failure || ended || closing) throw Error('mcp_unavailable');
  };
  const abort = () => stop('mcp_stopped');
  let timer;
  function write(value) {
    check(); const bytes = Buffer.from(JSON.stringify(value) + '\n');
    if (bytes.length > maxBytes) { stop('mcp_input_limit'); throw Error('mcp_input_limit'); }
    child.stdin.write(bytes, error => { if (error) stop('mcp_input_failed'); });
  }
  function call(method, params) {
    check();
    return new Promise((resolve, reject) => {
      const id = ++sequence; pending.set(id, { resolve, reject });
      try { write({ jsonrpc: '2.0', id, method, params }); } catch (e) { pending.delete(id); reject(e); }
    });
  }
  return {
    async start() {
      if (started) throw Error('mcp_already_started'); started = true; check();
      child = spawn(command, args, { cwd, env: environment, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      signal.addEventListener('abort', abort, { once: true });
      timer = setTimeout(abort, Math.max(1, Math.ceil(expiresAt - performance.now())));
      child.on('error', () => stop('mcp_start_failed'));
      child.stdin.on('error', () => stop('mcp_input_failed'));
      child.stderr.on('data', data => { byteCount += data.length; if (byteCount > maxBytes) stop('mcp_output_limit'); });
      child.stdout.on('data', data => {
        byteCount += data.length; if (byteCount > maxBytes) { stop('mcp_output_limit'); return; }
        if (failure) return;
        try {
          buffer += decoder.decode(data, { stream: true });
          for (;;) {
            const end = buffer.indexOf('\n'); if (end < 0) break;
            const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
            if (!line.trim()) continue;
            const message = JSON.parse(line);
            if (!message || message.jsonrpc !== '2.0' || !Number.isSafeInteger(message.id) || !pending.has(message.id) || Object.hasOwn(message, 'result') === Object.hasOwn(message, 'error') || Object.hasOwn(message, 'method')) throw Error('mcp_protocol');
            check(); const entry = pending.get(message.id); pending.delete(message.id);
            if (message.error) { entry.reject(Error('mcp_response_error')); stop('mcp_response_error'); }
            else entry.resolve(message.result);
          }
        } catch { stop('mcp_protocol_invalid'); }
      });
      child.on('close', (code, endSignal) => {
        ended = true; exit = { code, signal: endSignal };
        try { buffer += decoder.decode(); if (buffer.trim()) failure ??= 'mcp_truncated'; } catch { failure ??= 'mcp_utf8'; }
        if (pending.size) failure ??= 'mcp_unsettled'; rejectPending();
        if (!closing) failure ??= 'mcp_early_exit';
        resolveExit();
      });
      const result = await call('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'scanmux-internal-hosted', version: '1' } });
      if (result?.protocolVersion !== '2024-11-05') { stop('mcp_version'); throw Error('mcp_version'); }
      write({ jsonrpc: '2.0', method: 'notifications/initialized' });
    },
    listTools: () => call('tools/list', {}),
    recordDraft: draft => call('tools/call', { name: 'record_codex_security_scan_draft', arguments: draft }),
    async close() {
      if (!child) return { closed: true, quiescent: true, clean: !failure };
      if (!closing) {
        closing = true;
        if (pending.size || signal.aborted || performance.now() >= expiresAt) stop('mcp_unsettled');
        else if (!ended) child.stdin.end();
      }
      await exited;
      clearTimeout(timer); signal.removeEventListener('abort', abort);
      return { closed: ended, quiescent: ended, clean: !failure && exit.code === 0 && exit.signal === null };
    },
  };
}
