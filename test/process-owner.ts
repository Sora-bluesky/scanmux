import { withProcessRuntime } from '../src/process-tree.ts';
import type { Tool } from '../src/model.ts';

function shared(): Tool | undefined {
  if (process.platform !== 'win32') return undefined;
  const value = process.env.SCANMUX_TEST_PROCESS_OWNER;
  if (!value) throw new Error('SCANMUX_TEST_PROCESS_OWNER is unset; run the tests through npm test, which builds the process owner');
  return JSON.parse(value) as Tool;
}
/** The process owner that npm test built; undefined off Windows, where execute() needs none. */
export const testProcessOwner = shared();
export function withTestProcessOwner<T extends object>(config: T): T {
  if (!testProcessOwner) return config;
  const { tools } = config as { tools?: Record<string, unknown> };
  return { ...config, tools: { ...tools, 'windows-process-owner': testProcessOwner } };
}
export const contained = <T>(body: () => Promise<T>): Promise<T> =>
  withProcessRuntime({ helper: testProcessOwner, timeoutMs: 10000 }, { decide: () => {}, verify: async () => {} }, body);
