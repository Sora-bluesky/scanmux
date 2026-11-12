#!/usr/bin/env node
// A broken install must not look like a scan FAIL (1) or a pass (0). The exception is not printed: it can name local paths.
// shortcut: the command is read from the first argument only, as documented; options before it fall back to 4.
const startupFailed = () => {
  const deps = process.argv[2] === 'deps', code = deps ? 2 : 4;
  process.stderr.write(JSON.stringify({ schema: 'scanmux.error/v1', ...(deps ? {} : { gate: 'ERROR' }), exitCode: code, error: 'startup_failed' }) + '\n');
  process.exitCode = code;
};
let main;
try {
  await import('./typescript-bootstrap.mjs');
  ({ main } = await import('../src/cli.ts'));
  if (typeof main !== 'function') throw new TypeError('main is not exported');
} catch { startupFailed(); }
if (typeof main === 'function') {
  const code = await main(process.argv.slice(2));
  if (Number.isInteger(code) && code >= 0 && code <= 4) process.exitCode = code; else startupFailed();
}
