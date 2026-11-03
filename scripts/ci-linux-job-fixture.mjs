import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

// One MiB per file, short ASCII lines, no random high-entropy strings or secrets.
// Per-file suffixes avoid identical Git object IDs without adding scanner inputs.
export async function generateFixture(root, mib) {
  await mkdir(root, { mode: 0o755 });
  const sentence = 'Ordinary public sample prose describes calm weather and green fields.\n';
  const body = Buffer.from(sentence.repeat(Math.ceil(1048576 / sentence.length)).slice(0, 1048544));
  for (let i = 0; i < mib; i++) {
    const tail = Buffer.from(`\nSample number ${String(i).padStart(6, '0')}.\n`);
    const file = Buffer.alloc(1048576, 32);
    body.copy(file); tail.copy(file, file.length - tail.length);
    await writeFile(path.join(root, `sample-${String(i).padStart(4, '0')}.txt`), file, { flag: 'wx', mode: 0o644 });
  }
}
