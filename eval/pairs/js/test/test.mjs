import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import path from 'node:path';

// Regression oracle for the lodash `template` code-injection advisory
// (GHSA-35jh-r3h4-6jhm / CVE-2021-23337). A crafted `variable` option escapes
// the compiled function body; 4.17.20 runs the injected statement, 4.17.21
// rejects the option with "Invalid `variable` option passed into `_.template`".
// The injected statement only sets an in-process marker, never a shell command.
const marker = '__scanmux_lodash_template_marker';

export default async function ({ projectRoot }) {
  const entry = path.join(projectRoot, 'vendor', 'lodash', 'template.js');
  if (!existsSync(entry)) return { kind: 'environment_missing', reason: 'fixture_missing' };
  const require = createRequire(path.join(projectRoot, 'vendor', 'lodash', 'package.json'));
  let template;
  try { template = require(entry); } catch { return { kind: 'environment_missing', reason: 'fixture_missing' }; }
  delete globalThis[marker];
  try {
    template('', { variable: `data = (globalThis[${JSON.stringify(marker)}] = 73)` })();
  } catch (error) {
    // 4.17.21 refuses the option before compiling, so the marker never runs.
    if (error instanceof Error && error.constructor === Error && error.message === 'Invalid `variable` option passed into `_.template`') {
      return { kind: 'observed', problem: 'absent' };
    }
    throw error;
  }
  return { kind: 'observed', problem: globalThis[marker] === 73 ? 'present' : 'absent' };
}
