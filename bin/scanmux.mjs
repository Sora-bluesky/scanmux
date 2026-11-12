#!/usr/bin/env node
let main;
try {
  await import('./typescript-bootstrap.mjs');
  ({ main } = await import('../src/cli.ts'));
  if (typeof main !== 'function') throw new TypeError('main is not exported');
} catch {
  // A broken install must not look like a scan FAIL (1). The exception is not printed: it can name local paths.
  // shortcut: the command is read from the first argument only, as documented; options before it fall back to 4.
  const deps = process.argv[2] === 'deps', code = deps ? 2 : 4;
  process.stderr.write(JSON.stringify({ schema: 'scanmux.error/v1', ...(deps ? {} : { gate: 'ERROR' }), exitCode: code, error: 'startup_failed' }) + '\n');
  process.exitCode = code;
}
if (typeof main === 'function') process.exitCode = await main(process.argv.slice(2));
