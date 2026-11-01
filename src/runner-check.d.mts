import type { Config } from './model.ts';
export function checkRunner(config: Config, workspace: string, signal: AbortSignal): Promise<{
  schema: 'scanmux.runner-check/v1'; state: 'INCOMPLETE' | 'ERROR'; [key: string]: unknown;
}>;
