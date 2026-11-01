import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

type Category = 'execute' | 'execute_owner' | 'tcb' | 'container' | 'job_admitted' | 'host_admitted' | 'owned_cleanup' | 'ai_admitted' | 'owner_helper';
// execute is the single admitted native door; job_admitted sites run only after the v2 job profile is admitted
// (stage 3), host_admitted sites only after the host closure is admitted (stage 4) and ai_admitted sites only
// after the ai-scan or runner-check closure is admitted at the CLI entry (stage 5). owned_cleanup sites remove a
// container already taken on and are never decided. tcb and container sites are outside policy. execute_owner sites start
// only what execute() handed to the Windows process owner, inside that request's Job. The execute site in process.ts
// serves process groups off Windows and the direct path that the callers in `direct` below may use.
const inventory: Readonly<Record<string, Partial<Record<Category, number>>>> = {
  'src/process.ts': { execute: 1 },
  'src/process-tree.ts': { owner_helper: 1 },
  'src/private-storage.ts': { tcb: 1 },
  'src/siwc-credentials.mjs': { tcb: 1 },
  'internal/projected-repository.mjs': { tcb: 1 },
  'src/job-runner.ts': { job_admitted: 2 },
  'src/host-job.ts': { host_admitted: 1, owned_cleanup: 1 },
  'src/runner-check.mjs': { ai_admitted: 3 },
  'internal/linux-hosted-runner.mjs': { ai_admitted: 2 },
  'internal/hosted-mcp.mjs': { container: 1 },
  'internal/linux-hosted-worker.mjs': { container: 1 },
  'internal/sdk-initialization-observer.mjs': { container: 3 },
  'internal/linux-job-controller.mjs': { container: 1 },
  'internal/linux-job-supervisor.py': { container: 2 },
  'src/retained-write.ts': { owner_helper: 2 },
  'internal/windows-job-owner.cs': { owner_helper: 1 },
  'internal/windows-process-owner.cs': { execute_owner: 1 },
};
const imports: Readonly<Record<string, string[]>> = {
  'src/process.ts': ['spawn'], 'src/process-tree.ts': ['spawn'], 'src/private-storage.ts': ['spawn'], 'src/siwc-credentials.mjs': ['spawn'],
  'internal/projected-repository.mjs': ['spawn'], 'src/job-runner.ts': ['spawn', 'type ChildProcessWithoutNullStreams'],
  'src/host-job.ts': ['spawn'], 'src/runner-check.mjs': ['spawn'], 'internal/linux-hosted-runner.mjs': ['spawn'],
  'internal/hosted-mcp.mjs': ['spawn'], 'internal/linux-hosted-worker.mjs': ['spawn'],
  'internal/linux-job-controller.mjs': ['spawn'],
  'internal/sdk-initialization-observer.mjs': ['default childProcess'], 'src/retained-write.ts': ['spawn', 'spawnSync'],
};

const count = (text: string, pattern: RegExp) => text.match(pattern)?.length ?? 0;
const importPattern = /^import\s+(?:(\w+)|\{([^}]*)\})\s+from\s+'node:child_process';$/gm;
function javascriptSites(text: string, file: string, found: Record<string, string[]>): number {
  const bindings: string[] = [];
  const defaults: string[] = [];
  let statements = 0;
  for (const match of text.matchAll(importPattern)) {
    statements++;
    if (match[1]) { defaults.push(match[1]); bindings.push(`default ${match[1]}`); }
    else bindings.push(...match[2].split(',').map(name => name.trim()).filter(Boolean));
  }
  assert.equal(count(text, /child_process/g), statements, `${file}: child_process is only reached through a static import`);
  if (bindings.length) found[file] = bindings;
  let sites = count(text, /(?<![.\w$])(?:spawn|spawnSync|execFile|execFileSync|execSync|fork)\s*\(/g);
  if (bindings.includes('exec')) sites += count(text, /(?<![.\w$])exec\s*\(/g);
  for (const name of defaults) {
    sites += count(text, new RegExp(`\\b${name}\\.\\w+\\s*\\(`, 'g'));
    for (const [, alias] of text.matchAll(new RegExp(`\\b(\\w+)\\s*=\\s*${name}\\.\\w+\\b(?!\\s*=)`, 'g'))) {
      sites += count(text, new RegExp(`(?<![.\\w$])${alias}\\s*\\(|\\bReflect\\.apply\\(\\s*${alias}\\b`, 'g'));
    }
  }
  return sites;
}
const pythonSites = (text: string) =>
  count(text, /\b(?:os\.(?:fork|forkpty|exec\w+|spawn\w+|posix_spawnp?|system|popen)|subprocess\.\w+|pty\.(?:fork|spawn)|multiprocessing\.\w+)\s*\(/g)
  + count(text, /^\s*(?:import|from)\s+(?:subprocess|multiprocessing|pty)\b/gm);
const csharpSites = (text: string) => count(text.split('\n').filter(line => !/\bextern\b/.test(line)).join('\n'),
  /\b(?:CreateProcess\w*|Process\.Start|ShellExecute\w*|ProcessStartInfo)\s*\(/g);

async function sources(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await sources(full));
    else if (/\.(?:ts|mjs|py|cs)$/.test(entry.name) && !/\.d\.(?:ts|mts)$/.test(entry.name)) files.push(full);
  }
  return files;
}

test('every direct process creation site in src and internal is classified', async () => {
  const observed: Record<string, number> = {}, found: Record<string, string[]> = {};
  for (const directory of ['src', 'internal']) for (const full of await sources(path.resolve(directory))) {
    const file = path.relative(process.cwd(), full).split(path.sep).join('/'), text = await fs.readFile(full, 'utf8');
    const sites = file.endsWith('.py') ? pythonSites(text) : file.endsWith('.cs') ? csharpSites(text) : javascriptSites(text, file, found);
    if (sites) observed[file] = sites;
  }
  const expected = Object.fromEntries(Object.entries(inventory).map(([file, classes]) => [file, Object.values(classes).reduce((sum, value) => sum + value, 0)]));
  assert.deepEqual(observed, expected);
  assert.deepEqual(found, imports);
  assert.deepEqual(Object.keys(inventory).filter(file => inventory[file].execute), ['src/process.ts']);
});

// The direct path runs before the process owner can be admitted, or outside any config; its stop is never verified on Windows.
const direct: Readonly<Record<string, number>> = { 'src/runtime-admission.ts': 2, 'src/host-job.ts': 1 };
test('only the pre-admission verifier and the host job owner check use the direct path', async () => {
  const observed: Record<string, number> = {};
  for (const directory of ['src', 'internal']) for (const full of await sources(path.resolve(directory))) {
    const file = path.relative(process.cwd(), full).split(path.sep).join('/'), text = await fs.readFile(full, 'utf8');
    const uses = file === 'src/process.ts' ? 0 : count(text.split('\n').filter(line => !line.startsWith('import ')).join('\n'), /\bexecuteDirect\b/g);
    if (uses) observed[file] = uses;
  }
  assert.deepEqual(observed, direct);
});
