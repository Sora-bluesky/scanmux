import type { RmOptions } from 'node:fs';

export function removeTempDir(directory: string): Promise<void>;
export function removeTempDirStrict(directory: string, rmOptions?: RmOptions): Promise<void>;
