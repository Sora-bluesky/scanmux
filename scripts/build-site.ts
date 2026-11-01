import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { html, css, siteJavascript } from '../src/web-ui.ts';

export const siteFiles = ['.openai/hosting.json', 'dist/_headers', 'dist/app.css', 'dist/app.js', 'dist/index.html'].sort();
export function siteAssets() {
  const javascript = Buffer.from(siteJavascript, 'utf8');
  const integrity = `sha256-${createHash('sha256').update(javascript).digest('base64')}`;
  const policy = `default-src 'none'; script-src '${integrity}'; style-src 'self'; connect-src http://127.0.0.1:*; img-src 'self'; base-uri 'none'; form-action 'none'; worker-src 'none'`;
  const charset = '<meta charset="utf-8">';
  const script = '<script defer src="/app.js"></script>';
  assert.equal(html.split(charset).length, 2, 'Expected one charset marker');
  assert.equal(html.split(script).length, 2, 'Expected one application script');
  assert.ok(html.indexOf(charset) < html.indexOf('<script'), 'CSP must precede scripts');
  const document = html.replace(charset, `${charset}<meta http-equiv="Content-Security-Policy" content="${policy}">`)
    .replace(script, `<script defer src="/app.js" integrity="${integrity}"></script>`);
  const headers = `/*\n  Cache-Control: no-store\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  X-Frame-Options: DENY\n  Content-Security-Policy: ${policy}; frame-ancestors 'none'\n`;
  return { 'index.html': document, 'app.css': css, 'app.js': javascript, '_headers': headers };
}
export async function verifySiteFiles(root: string): Promise<void> {
  const files: string[] = [];
  async function visit(directory: string) {
    for (const entry of await readdir(path.join(root, directory), { withFileTypes: true })) {
      if (!directory && entry.name === '.git' && entry.isDirectory()) continue;
      const name = directory ? `${directory}/${entry.name}` : entry.name;
      assert.ok(!entry.isSymbolicLink(), 'Site symlinks are forbidden');
      if (entry.isDirectory()) await visit(name); else files.push(name);
    }
  }
  await visit('');
  assert.deepEqual(files.sort(), siteFiles, 'Unexpected or missing site source');
}
if (import.meta.main) {
  const root = path.resolve('site');
  const hosting = JSON.parse(await readFile(path.join(root, '.openai/hosting.json'), 'utf8'));
  assert.equal(hosting.static?.directory, 'dist');
  await mkdir(path.join(root, 'dist'), { recursive: true });
  for (const [name, bytes] of Object.entries(siteAssets())) {
    await writeFile(path.join(root, 'dist', name), bytes, 'utf8');
  }
  await verifySiteFiles(root);
  console.log(`SITE_SOURCE_VERIFIED: ${siteFiles.length} files`);
}
