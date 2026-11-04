import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

// Regression oracle for the PyYAML full_load code-execution advisory
// (CVE-2020-14343 / PYSEC-2021-142), run with the job image's /usr/bin/python3.
// 5.3.1 executes the crafted document and writes the marker; 5.4 raises a
// ConstructorError and writes nothing. The injected statement sets a marker file
// value only, never a shell command.
const here = path.dirname(fileURLToPath(import.meta.url));

export default async function ({ projectRoot }) {
  const python = '/usr/bin/python3';
  const packageDir = path.join(projectRoot, 'vendor', 'pyyaml');
  if (!existsSync(path.join(packageDir, 'yaml', '__init__.py'))) return { kind: 'environment_missing', reason: 'fixture_missing' };
  const scratch = mkdtempSync(path.join(tmpdir(), 'scanmux-pyyaml-'));
  const markerPath = path.join(scratch, 'marker');
  try {
    const result = spawnSync(python, ['-I', '-B', path.join(here, 'run_yaml.py'), packageDir, path.join(here, 'payload.yaml')],
      { encoding: 'utf8', env: { SCANMUX_MARKER_PATH: markerPath, PATH: '/usr/bin:/bin' }, windowsHide: true });
    if (result.error) {
      if (result.error.code === 'ENOENT') return { kind: 'environment_missing', reason: 'runtime_not_available' };
      throw result.error;
    }
    if (result.signal || result.status !== 0) throw new Error('Python probe did not exit cleanly');
    const outcome = (result.stdout ?? '').trim();
    if (outcome === 'IMPORT_FAIL') return { kind: 'environment_missing', reason: 'fixture_missing' };
    const hasMarker = existsSync(markerPath);
    const marker = hasMarker ? readFileSync(markerPath, 'ascii').trim() : '';
    if (outcome === 'MARKER_WRITTEN' && marker === '73') return { kind: 'observed', problem: 'present' };
    if (outcome === 'CONSTRUCTOR_ERROR' && !hasMarker) return { kind: 'observed', problem: 'absent' };
    throw new Error('Python probe returned an invalid result');
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}
