import { lstat, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Config } from '../model.ts';
import { loadConfig } from '../config.ts';
import { checkedText } from '../output.ts';
import { privateWorkspace } from '../private-storage.ts';
import { parseReportLanguage, type ReportLanguage } from '../report-language.ts';
import { boundedRead, canonical, hash, SafeError, within } from '../safety.ts';
import { intelExitCode, matchIntel, readSource, type IntelMatch } from './match.ts';
import { renderIntelHtml, renderIntelSarif, renderIntelText } from './render.ts';
import { openStore, readIntel } from './store.ts';

export { refreshIntel, loadIntel } from './store.ts';
export { matchIntel, intelExitCode } from './match.ts';
export interface MatchOptions { readonly maxAgeMs: number | null; readonly requireFresh: boolean; readonly language: ReportLanguage; readonly now?: number; readonly checkText?: typeof checkedText }

export function parseMaxAgeHours(value: unknown): number | null {
  if (value === undefined) return null;
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,6}$/.test(value)) throw new SafeError('invalid_intel_max_age');
  return Number(value) * 3600000;
}
function insideTarget(store: string, repoId: string): boolean {
  for (let directory = store; ; directory = path.dirname(directory)) {
    if (hash(directory) === repoId) return true;
    if (path.dirname(directory) === directory) return false;
  }
}
export async function writeIntelBundle(match: IntelMatch, sourceFile: string, config: Config, workspace: string, language: ReportLanguage, checkText: typeof checkedText = checkedText) {
  const lang = parseReportLanguage(language);
  const parts = [['intel-match.json', JSON.stringify(match, null, 2) + '\n'], ['intel-match.html', renderIntelHtml(match, lang)],
    ['intel-match.txt', renderIntelText(match, lang)], ['intel-match.sarif', renderIntelSarif(match)]].map(([name, text]) => ({ destination: path.join(workspace, name), text }));
  for (const part of parts) await checkText(part.text, config, workspace);
  await checkText(JSON.stringify({ destinations: parts.map(part => part.destination) }, null, 2) + '\n', config, workspace);
  if (hash(await boundedRead(sourceFile, config.maxOutputBytes)) !== match.sourceSha256) throw new SafeError('intel_source_binding_mismatch');
  const written: string[] = [];
  try {
    for (const part of parts) {
      const handle = await open(part.destination, 'wx', 0o600);
      written.push(part.destination);
      try { await handle.writeFile(part.text); } finally { await handle.close(); }
    }
  } catch (error) {
    await Promise.all(written.map(file => rm(file, { force: true })));
    throw error;
  }
  const [json, html, text, sarif] = parts;
  return { json: json.text, text: text.text, destination: json.destination, htmlDestination: html.destination, textDestination: text.destination, sarifDestination: sarif.destination };
}
export async function matchIntelFiles(file: string, storeInput: string, configPath: string | undefined, config: Config, options: MatchOptions) {
  if (!path.isAbsolute(file)) throw new SafeError('invalid_intel_source_path');
  const input = await canonical(file), bytes = await boundedRead(input, config.maxOutputBytes);
  const source = readSource(bytes);
  let root: string | undefined;
  if (source.root !== null) {
    root = await canonical(source.root);
    if (!(await lstat(root)).isDirectory() || hash(root) !== source.repoId) throw new SafeError('intel_target_mismatch');
    await loadConfig(configPath, root, { runtimePolicy: config.schema === 2 ? 'accept' : 'reject' });
    if (within(root, input)) throw new SafeError('intel_input_inside_target');
  }
  const store = await openStore(storeInput, false);
  if (insideTarget(store, source.repoId)) throw new SafeError('intel_store_inside_target');
  const now = options.now ?? Date.now();
  const match = matchIntel(bytes, source, await readIntel(store, now), { now, maxAgeMs: options.maxAgeMs });
  if (insideTarget(await canonical(tmpdir()), source.repoId)) throw new SafeError('intel_output_inside_target');
  const workspace = await privateWorkspace(root);
  const bundle = await writeIntelBundle(match, input, config, workspace, options.language, options.checkText);
  return { match, ...bundle, exitCode: intelExitCode(match, options.requireFresh) };
}
