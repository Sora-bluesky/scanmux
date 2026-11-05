import test, { afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { parseArgs } from 'node:util';
import { stripTypeScriptTypes, syncBuiltinESMExports } from 'node:module';
import { performance } from 'node:perf_hooks';
import { privateWorkspace } from '../src/private-storage.ts';
import { defaults } from '../src/config.ts';
import * as cleanup from '../src/source-cleanup.ts';
import * as copyBudget from '../src/copy-budget.ts';
import * as jobDisk from '../src/job-disk.ts';
import * as safety from '../src/safety.ts';
import { RuntimePolicyRefusalError } from '../src/runtime-policy.ts';
import { ProvenanceRefusalError } from '../src/provenance.ts';
import { EngineLedgerUnpinnedTailError } from '../src/engine-record.ts';
import { parseReportLanguage } from '../src/report-language.ts';
import { ciArguments } from '../src/ci.ts';
import { commitPair } from '../src/comparison.ts';
import { staticError } from '../src/output.ts';
import { main as realMain } from '../src/cli.ts';
import { isolateStorage } from './isolated-storage.ts';
isolateStorage();
afterEach(() => { mock.restoreAll(); syncBuiltinESMExports(); });

async function command(overrides: Record<string, unknown> = {}) {
  const imports = { parseArgs, path, performance, privateWorkspace, ...cleanup, ...copyBudget, ...jobDisk, ...safety,
    RuntimePolicyRefusalError, ProvenanceRefusalError, EngineLedgerUnpinnedTailError, parseReportLanguage, staticError, ciArguments, commitPair,
    loadConfig: async () => structuredClone(defaults),
    withProcessRuntime: async (_profile: unknown, _admission: unknown, body: () => Promise<unknown>) => body(),
    checkedJson: async (value: unknown) => JSON.stringify(value) + '\n',
    buildPlan: async () => ({ files: [], lockfiles: [], blockers: [] }), ...overrides };
  const source = stripTypeScriptTypes(await fs.readFile('src/cli.ts', 'utf8'));
  const body = source.slice(source.indexOf('const help =')).replace(/^export /gm, '');
  return Function(...Object.keys(imports), body + '\nreturn main;')(...Object.values(imports)) as typeof realMain;
}
async function invoke(main: typeof realMain, args: string[]) {
  const output: string[] = [], errors: string[] = [], out = process.stdout.write, err = process.stderr.write;
  process.stdout.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (output.push(chunk), true) : out.call(process.stdout, chunk, ...rest)) as typeof out;
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: never[]) => typeof chunk === 'string' ? (errors.push(chunk), true) : err.call(process.stderr, chunk, ...rest)) as typeof err;
  try { return { code: await main(args), output: output.join(''), error: errors.join('') }; }
  finally { process.stdout.write = out; process.stderr.write = err; }
}
const empty = async () => assert.deepEqual(await fs.readdir(path.join(tmpdir(), 'scanmux-private')), []);

for (const mode of ['success', 'refusal', 'error', 'SIGINT', 'SIGTERM']) test(`deps removes its workspace after ${mode}`, async () => {
  let ran = false;
  const main = await command({ analyzeDependencies: async (_root: string, _config: unknown, workspace: string, signal: AbortSignal) => {
    ran = true;
    for (const name of ['head', 'base', 'osv-database']) {
      await fs.mkdir(path.join(workspace, name)); await fs.writeFile(path.join(workspace, name, 'copy'), 'temporary');
    }
    if (mode === 'SIGINT' || mode === 'SIGTERM') { process.emit(mode); assert.equal(signal.aborted, true); throw new safety.SafeError('cancelled'); }
    if (mode === 'error') throw new Error('injected failure');
    return { exitCode: mode === 'refusal' ? 2 : 0 };
  } });
  const result = await invoke(main, ['deps', await fs.mkdtemp(path.join(tmpdir(), 'target-')), '--config', path.join(tmpdir(), 'config.json'), '--json']);
  assert.equal(ran, true); assert.equal(result.code, mode === 'success' ? 0 : 2);
  if (mode === 'error' || mode.startsWith('SIG')) assert.equal(JSON.parse(result.error).exitCode, 2);
  await empty();
});

test('doctor removes its workspace', async () => {
  const result = await invoke(realMain, ['doctor', '--json']);
  assert.equal(result.code, 3); assert.equal(JSON.parse(result.output).schema, 'scanmux.doctor/v1');
  await empty();
});
test('runner-check without a configured runner removes its workspace', async () => {
  const result = await invoke(realMain, ['runner-check', '--json']);
  assert.equal(result.code, 3); assert.equal(JSON.parse(result.output).schema, 'scanmux.runner-check/v1'); await empty();
});
for (const name of ['plan', 'ai-plan']) test(`${name} removes its workspace`, async () => {
  const result = await invoke(await command({ buildAiPlan: (plan: unknown) => plan }), [name, await fs.mkdtemp(path.join(tmpdir(), 'target-')), '--config', path.join(tmpdir(), 'config.json'), '--json']);
  assert.equal(result.code, 0); assert.deepEqual(JSON.parse(result.output).blockers, []); await empty();
});

for (const name of ['deps', 'doctor']) test(`${name} preserves the cleanup failure exit for a disposable root`, async t => {
  const rmdir = fs.rmdir;
  t.mock.method(fs, 'rmdir', async (...args: Parameters<typeof fs.rmdir>) => {
    if (path.dirname(String(args[0])) === path.join(tmpdir(), 'scanmux-private')) throw Object.assign(new Error('locked'), { code: 'EBUSY' });
    return rmdir(...args);
  });
  const main = name === 'doctor' ? realMain : await command({ analyzeDependencies: async () => ({ exitCode: 0 }) });
  const result = await invoke(main, [name, ...(name === 'deps' ? [await fs.mkdtemp(path.join(tmpdir(), 'target-')), '--config', path.join(tmpdir(), 'config.json')] : []), '--json']);
  assert.equal(result.code, name === 'deps' ? 2 : 4);
  assert.equal(cleanup.sourceCleanupFailed(), true); assert.equal(JSON.parse(result.error).error, 'source_cleanup_failed');
});

for (const gate of ['PASS', 'ERROR']) test(`scan keeps its ${gate} report and checkpoints`, async () => {
  let workspace = '';
  const report = { gate, exitCode: gate === 'PASS' ? 0 : 4, engines: [] };
  const main = await command({ scan: async (_plan: unknown, _config: unknown, directory: string) => {
    workspace = directory; await fs.mkdir(path.join(directory, 'checkpoints')); await fs.writeFile(path.join(directory, 'checkpoints', 'receipt'), 'saved'); return report;
  }, saveReportBundle: async () => {
    const json = JSON.stringify(report), destination = path.join(workspace, 'report.json'); await fs.writeFile(destination, json); return { json, report, destination };
  } });
  const result = await invoke(main, ['scan', await fs.mkdtemp(path.join(tmpdir(), 'target-')), '--json']);
  assert.equal(result.code, report.exitCode); assert.deepEqual(JSON.parse(await fs.readFile(path.join(workspace, 'report.json'), 'utf8')), report);
  assert.equal(await fs.readFile(path.join(workspace, 'checkpoints', 'receipt'), 'utf8'), 'saved');
});
