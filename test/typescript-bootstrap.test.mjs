import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { runInNewContext } from 'node:vm';
import { jobRuntimeFiles } from '../src/job-runner.ts';
import { removeTempDir } from './temp-cleanup.mjs';

const bootstrap = new URL('../bin/typescript-bootstrap.mjs', import.meta.url);
const source = (await readFile(bootstrap, 'utf8')).replace(/^import .*;\n/gm, '').replaceAll('import.meta.url', JSON.stringify(bootstrap.href));
const warning = 'stripTypeScriptTypes is an experimental feature and might change at any time';
function hook(stripTypeScriptTypes, emitWarning, readFileSync = () => 'const value: number = 1;', realpathSync = fileURLToPath) {
  let load;
  const process = { emitWarning };
  runInNewContext(source, { URL, process, readFileSync, realpathSync, pathToFileURL, stripTypeScriptTypes, registerHooks: hooks => { load = hooks.load; } });
  return { load, process };
}

test('the hook delegates a real TypeScript file outside its own src and every other URL unchanged', async () => {
  const directory = await mkdtemp(path.join(await realpath(tmpdir()), 'scanmux-loader-'));
  try {
    const file = path.join(directory, 'target.ts'); await writeFile(file, 'export const target: number = 1;\n');
    const { load } = hook(() => assert.fail('must not strip'), () => {}, () => assert.fail('must not read'));
    const root = new URL('../src/', bootstrap).href;
    for (const url of [pathToFileURL(file).href, root + '../target.ts', root + 'node_modules/dependency.ts', root + 'cli.mjs', 'node:fs', 'https://example.invalid/source.ts']) {
      const context = { format: 'module' }, sentinel = {};
      assert.equal(load(url, context, (nextUrl, nextContext) => { assert.equal(nextUrl, url); assert.equal(nextContext, context); return sentinel; }), sentinel);
    }
    const linked = hook(() => assert.fail('must not strip linked target'), () => {}, () => assert.fail('must not read linked target'), () => file);
    const sentinel = {};
    assert.equal(linked.load(root + 'linked.ts', {}, () => sentinel), sentinel);
  } finally { await removeTempDir(directory); }
});

test('only the exact API warning is suppressed during stripping, and emission is restored even on failure', () => {
  for (const fail of [false, true]) {
    const calls = [], emit = function (...args) { calls.push([this, args]); };
    let instance;
    instance = hook((text, options) => {
      assert.equal(text, 'const value: number = 1;'); assert.equal(options.mode, 'strip');
      instance.process.emitWarning(warning, 'ExperimentalWarning', undefined, undefined);
      instance.process.emitWarning('another API is experimental', 'ExperimentalWarning');
      instance.process.emitWarning(warning, 'Warning');
      instance.process.emitWarning(warning, 'ExperimentalWarning', 'OTHER_CODE');
      instance.process.emitWarning(new Error(warning), 'ExperimentalWarning');
      if (fail) throw Error('strip failure');
      return 'const value = 1;';
    }, emit);
    const load = () => instance.load(new URL('../src/probe.ts', bootstrap).href, {}, () => assert.fail('must strip'));
    if (fail) assert.throws(load, /strip failure/);
    else { const result = load(); assert.equal(result.source, 'const value = 1;'); assert.equal(result.format, 'module'); assert.equal(result.shortCircuit, true); }
    assert.equal(instance.process.emitWarning, emit); assert.equal(calls.length, 4);
    assert.ok(calls.every(([receiver]) => receiver === instance.process));
    instance.process.emitWarning(warning, 'ExperimentalWarning'); assert.equal(calls.length, 5);
  }
});

test('bootstrap bytes remain in the package, copied runtime and host-job hash inventory', () => {
  assert.ok(jobRuntimeFiles.includes('bin/typescript-bootstrap.mjs'));
});
