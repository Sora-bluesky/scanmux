import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

// node --test starts one child per file without windowsHide. From a parent without a console
// (a background agent), Windows opens a terminal window for each child. One hidden runner gives
// the whole test tree a console without a window.
const files = process.argv.length > 2 ? process.argv.slice(2) : ['test/*.test.ts', 'test/*.test.mjs'];
const env = { ...process.env };
let scratch;
if (process.platform === 'win32') {
  // execute() needs the process owner on Windows, so every test file shares one build of it.
  scratch = mkdtempSync(path.join(tmpdir(), 'scanmux-test-owner-'));
  const powershell = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const built = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', '& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:SCANMUX_OWNER_SOURCE))) -OutputDirectory $env:SCANMUX_OWNER_DESTINATION -SourcePath $env:SCANMUX_OWNER_CS'],
    { encoding: 'utf8', windowsHide: true, env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR, SCANMUX_OWNER_SOURCE: path.resolve('scripts/build-windows-process-owner.ps1'), SCANMUX_OWNER_CS: path.resolve('internal/windows-process-owner.cs'), SCANMUX_OWNER_DESTINATION: path.join(scratch, 'owner') } });
  const receipt = built.status === 0 ? JSON.parse(built.stdout.trim().split(/\r?\n/).at(-1) ?? '{}') : {};
  const owner = path.join(scratch, 'owner', 'scanmux-windows-process-owner.exe');
  let actual = '';
  try { actual = createHash('sha256').update(readFileSync(owner)).digest('hex'); } catch { /* Reported below as a failed build. */ }
  if (receipt.schema !== 'scanmux.windows-process-owner-build/v1' || receipt.assemblySha256 !== actual) {
    process.stderr.write(`process owner build failed: ${built.status} ${built.stderr?.slice(0, 400) ?? ''}\n`);
    rmSync(scratch, { recursive: true, force: true });
    process.exit(1);
  }
  env.SCANMUX_TEST_PROCESS_OWNER = JSON.stringify({ path: owner, sha256: receipt.assemblySha256, version: receipt.version });
}
const finish = code => { if (scratch) rmSync(scratch, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); process.exit(code); };
const child = spawn(process.execPath, ['--test', ...files], { stdio: 'inherit', windowsHide: true, env });
child.once('error', () => finish(1));
child.once('close', code => finish(code ?? 1));
