import { readFile } from 'node:fs/promises';
import { withCopyBudget, scopedCopyBudget } from '../../src/copy-budget.ts';
import { prepareOfflineDatabase } from '../../src/osv-database.ts';

// Execute the production controller's init validation on Windows without Linux startup.
const source = await readFile(new URL('../../internal/linux-job-controller.mjs', import.meta.url), 'utf8');
const start = source.indexOf('const hasCopyBudget ='), end = source.indexOf('if (reproduction) ({ expected, operation }', start);
if (start < 0 || end < 0) throw Error('controller_init_parser_not_found');
const parse = Function('input', 'let copyBudgetBytes, maxJobDiskBytes;\n' + source.slice(start, end) + '\nreturn { copyBudgetBytes, maxJobDiskBytes };');
const chunks = []; for await (const chunk of process.stdin) chunks.push(chunk);
try {
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8')), { copyBudgetBytes: remaining, maxJobDiskBytes } = parse(input.init);
  if (process.argv.includes('--parse')) process.stdout.write(JSON.stringify({ present: remaining !== undefined, remaining,
    ...(maxJobDiskBytes === undefined ? {} : { maxJobDiskBytes }) }));
  else await withCopyBudget(remaining, async () => {
    const prepared = await prepareOfflineDatabase({ ...input.options, ecosystems: ['npm'], maxMetadataBytes: 1024,
      timeoutMs: 10000, signal: new AbortController().signal });
    process.stdout.write(JSON.stringify({ bytes: prepared.files[0].bytes, sha256: prepared.files[0].sha256, reserved: scopedCopyBudget()?.reservedBytes }));
  });
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.code ?? 'invalid_init' }));
  process.exitCode = error.code === 'job_disk_copy_limit' ? 3 : 4;
}
