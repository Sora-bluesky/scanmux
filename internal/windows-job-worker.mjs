import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { scanJob } from '../src/job-runner.ts';
import { jobRuntimeFiles } from '../src/job-runner.ts';
import { readHostJobIntent, verifyHostJobInputs, cleanupHostContainer } from '../src/host-job.ts';
import { hostRequire } from '../src/host-job-records.ts';
import { canonical } from '../src/safety.ts';

try {
  const [mode, directory, intentSha256, ...extra] = process.argv.slice(2);
  hostRequire(process.platform === 'win32' && process.arch === 'x64' && extra.length <= 1 && ['run', 'cleanup'].includes(mode)
    && path.isAbsolute(directory) && /^[a-f0-9]{64}$/.test(intentSha256));
  const { intent } = await readHostJobIntent(directory, intentSha256);
  const bounded = mode === 'run' && intent.offline.maxCopyBytes !== undefined;
  hostRequire(extra.length === (bounded ? 1 : 0));
  const copyBudgetBytes = bounded ? Number(extra[0]) : undefined;
  if (bounded) hostRequire(/^(0|[1-9][0-9]*)$/.test(extra[0]) && Number.isSafeInteger(copyBudgetBytes)
    && copyBudgetBytes >= 0 && copyBudgetBytes <= intent.offline.maxCopyBytes);
  hostRequire(intent.directory === await canonical(directory) && intent.host.node.path === process.execPath && intent.host.node.version === process.version.slice(1)
    && isDeepStrictEqual(intent.assets.map(asset => asset.path), jobRuntimeFiles));
  await verifyHostJobInputs(intent);
  if (mode === 'run') {
    await scanJob(intent.root, intent.host.offlineProfile, new AbortController().signal, intent.comparison ?? undefined,
      { jobId: intent.jobId, directory: intent.directory, metadataName: 'delegated-job.json', ...(bounded ? { copyBudgetBytes } : {}) });
  } else await cleanupHostContainer(intent, intentSha256);
  // The subordinate analysis gate lives in delegated-job.json; 0 means this fixed
  // worker returned normally, including a correctly recorded incomplete analysis.
  process.exitCode = 0;
} catch {
  // The owner records a process-object terminal fact. No target/error text crosses it.
  process.exitCode = 1;
}
