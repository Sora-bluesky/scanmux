import type { Adapter } from './model.ts';
export interface SyntheticAiRuntime {
  createSocket?: (url: string, options: Readonly<Record<string, unknown>>) => unknown;
  openWorker?: (options: Readonly<Record<string, unknown>>) => Promise<unknown>;
}
export function createAiAdapter(options: { acceptedPlanHash: string; expiresAt: number; runtime?: SyntheticAiRuntime }): Adapter;
