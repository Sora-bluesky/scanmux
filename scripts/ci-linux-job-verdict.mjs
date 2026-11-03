import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export function criteriaPassed(results) {
  if (!Array.isArray(results) || results.length === 0) return false;
  if (!results.every(result => result !== null && typeof result === 'object'
    && !Array.isArray(result) && result.pass === true)) return false;
  return ['SETUP ', 'SOURCE ', 'NATIVE ', 'LIMIT ', 'CONTROL ', 'STOP '].every(prefix =>
    results.some(result => typeof result.criterion === 'string' && result.criterion.startsWith(prefix)));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = criteriaPassed(JSON.parse(await readFile(process.argv[2], 'utf8'))) ? 0 : 1;
  } catch {
    process.exitCode = 1;
  }
}
