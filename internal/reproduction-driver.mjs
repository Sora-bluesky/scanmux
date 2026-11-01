import { writeSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

// This executable is only launched by the admitted Linux controller. The nominated
// oracle runs in this child, with no job-channel descriptors or ambient Node options.
const bindingDigest = /^[a-f0-9]{64}$/.test(process.argv[4] ?? '') ? process.argv[4] : null;
let result = { kind: 'failed', reason: 'test_error' };
try {
  if (process.platform !== 'linux' || process.getuid() !== 1000 || process.argv.length !== 5 || process.argv[2] !== '/work/snapshot' || !bindingDigest) throw Error();
  const directory = process.argv[3];
  if (!directory || directory.startsWith('/') || /[\\:\x00-\x1f\x7f]/.test(directory) || directory.split('/').some(part => !part || part === '.' || part === '..')) throw Error();
  const probe = await import(pathToFileURL(path.join(process.argv[2], directory, 'test.mjs')).href);
  if (typeof probe.default !== 'function') result = { kind: 'failed', reason: 'invalid_observation' };
  else {
    const observation = await probe.default(Object.freeze({ projectRoot: process.argv[2] }));
    const keys = observation && typeof observation === 'object' && !Array.isArray(observation) ? Object.keys(observation).sort().join(',') : '';
    if (keys === 'kind,problem' && observation.kind === 'observed' && ['present', 'absent'].includes(observation.problem)) {
      result = { kind: 'completed', outcome: observation.problem === 'present' ? 'reproduced' : 'not_reproduced' };
    } else if (keys === 'kind,reason' && observation.kind === 'environment_missing' && ['offline_dependency_missing', 'fixture_missing', 'runtime_not_available'].includes(observation.reason)) {
      result = { kind: 'environment_missing', reason: observation.reason };
    } else result = { kind: 'failed', reason: 'invalid_observation' };
  }
} catch { /* Exception details and target output never enter retained records. */ }
try { writeSync(3, JSON.stringify({ schema: 'scanmux.probe-completion/v1', bindingDigest, result }) + '\n'); }
catch { process.exitCode = 4; }
