import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Builds the v0.1.0 evaluation pairs into throwaway git repositories so the
// parent can scan base and head on a real host and run `reproduce --base --head`.
// It only assembles files and commits them; it never runs a scanner or Docker.
// Each pair is sourced from eval/pairs/<lang>/{base,head,test,pair.json}: `base`
// is the whole vulnerable tree, `head` overlays only the upgraded dependency
// files, and `test` is copied into the pair's test directory at both commits so
// it stays byte- and mode-identical.

export const languages = ['js', 'python', 'go'];
const pairsRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'eval', 'pairs');

function readTree(root, into = new Map(), prefix = '') {
  if (!existsSync(root)) return into;
  for (const entry of readdirSync(root, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) readTree(path.join(root, entry.name), into, name);
    else into.set(name, readFileSync(path.join(root, entry.name)));
  }
  return into;
}

export function materializePair(lang) {
  if (!languages.includes(lang)) throw new Error(`unknown pair language: ${lang}`);
  const dir = path.join(pairsRoot, lang);
  const meta = JSON.parse(readFileSync(path.join(dir, 'pair.json'), 'utf8'));
  const baseFiles = readTree(path.join(dir, 'base'));
  const headOverlay = readTree(path.join(dir, 'head'));
  const testFiles = meta.testDirectory ? readTree(path.join(dir, 'test')) : new Map();
  const base = new Map(baseFiles), head = new Map(baseFiles);
  for (const [name, bytes] of headOverlay) head.set(name, bytes);
  for (const [name, bytes] of testFiles) {
    const target = `${meta.testDirectory}/${name}`;
    base.set(target, bytes); head.set(target, bytes);
  }
  return { lang, meta, testDirectory: meta.testDirectory, sizeLimitBytes: meta.sizeLimitBytes, base, head };
}

export function lockedVersion(lang, bytes) {
  const text = bytes.toString('utf8');
  if (lang === 'js') return JSON.parse(text).packages['node_modules/lodash'].version;
  if (lang === 'python') return (/^PyYAML==(.+)$/m.exec(text) ?? [])[1];
  return (/^\s*require\s+golang\.org\/x\/text\s+(v\S+)\s*$/m.exec(text) ?? [])[1];
}

export function vendoredVersion(lang, files) {
  if (lang === 'js') return JSON.parse(files.get('vendor/lodash/package.json').toString('utf8')).version;
  if (lang === 'python') return (/^__version__ = '(.+)'$/m.exec(files.get('vendor/pyyaml/yaml/__init__.py').toString('utf8')) ?? [])[1];
  return null;
}

export function totalBytes(files) {
  let total = 0;
  for (const bytes of files.values()) total += bytes.length;
  return total;
}

function git(repo, args, extraEnv = {}) {
  const result = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.safecrlf=false', '-c', 'protocol.allow=never', '-C', repo, ...args], {
    encoding: 'utf8', windowsHide: true,
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: path.join(repo, '.empty-gitconfig'),
      GIT_AUTHOR_NAME: 'eval', GIT_AUTHOR_EMAIL: 'eval@example.invalid', GIT_COMMITTER_NAME: 'eval', GIT_COMMITTER_EMAIL: 'eval@example.invalid',
      GIT_AUTHOR_DATE: '2021-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2021-01-01T00:00:00Z', ...extraEnv },
  });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

function writeAll(repo, files) {
  for (const [name, bytes] of files) {
    const target = path.join(repo, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
}

export function buildRepo(lang, outDir) {
  const pair = materializePair(lang);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, '.empty-gitconfig'), '');
  git(outDir, ['init', '-q', '--initial-branch=main']);
  writeAll(outDir, pair.base);
  git(outDir, ['add', '-A']);
  git(outDir, ['commit', '-q', '-m', `base: ${pair.meta.package} ${pair.meta.base.version} (${pair.meta.advisory})`]);
  const baseCommit = git(outDir, ['rev-parse', 'HEAD']);
  writeAll(outDir, pair.head);
  git(outDir, ['add', '-A']);
  git(outDir, ['commit', '-q', '-m', `fix: ${pair.meta.package} ${pair.meta.head.version}`]);
  const headCommit = git(outDir, ['rev-parse', 'HEAD']);
  return { language: pair.meta.language, package: pair.meta.package, advisory: pair.meta.advisory,
    base: baseCommit, head: headCommit, testDirectory: pair.testDirectory, reproduces: pair.meta.reproduces, lockfile: pair.meta.lockfile };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const which = process.argv[2], outDir = process.argv[3];
  if (!which || !outDir || !path.isAbsolute(outDir)) {
    process.stderr.write('usage: node scripts/eval-pairs.mjs <js|python|go|all> <absolute-output-directory>\n');
    process.exit(2);
  }
  const targets = which === 'all' ? languages : [which];
  if (!targets.every(lang => languages.includes(lang))) { process.stderr.write(`unknown language: ${which}\n`); process.exit(2); }
  const results = targets.map(lang => buildRepo(lang, which === 'all' ? path.join(outDir, lang) : outDir));
  process.stdout.write(JSON.stringify(which === 'all' ? results : results[0], null, 2) + '\n');
}
