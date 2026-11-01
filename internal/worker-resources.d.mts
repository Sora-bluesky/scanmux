import type { AiWorkerResources, WorkerResourceReport, WorkerResourceSnapshot } from '../src/model.ts';
export function parseWorkerResources(input: unknown): AiWorkerResources;
export function expectedResourceKernel(input: unknown): WorkerResourceSnapshot['kernel'];
export function parseResourceSnapshot(input: unknown, requested: unknown): WorkerResourceSnapshot;
export function readWorkerResourceSnapshot(requested: unknown): Promise<WorkerResourceSnapshot>;
export function buildWorkerResourceReport(input: { requested: unknown; boundaryVerified?: unknown; startupVerified?: unknown; snapshot?: unknown; terminal?: unknown; failureCode?: unknown; diskObserved?: unknown; deadlineExceeded?: unknown }): WorkerResourceReport;
export function workerResourcesComplete(input: unknown, requested: unknown): boolean;
export function classifyResourceStop(options: { reason: unknown; boundaryVerified: unknown; inputsUnchanged: unknown; workerClosed: unknown; containerAbsent: unknown; transportClosed: unknown; independentFailure: unknown; mcpEvidence: unknown; artifactEvidence: unknown; calls: unknown; tokensComplete: unknown; executionStatus: unknown; resources: unknown }): 'resource_memory_exceeded' | 'resource_disk_exceeded' | 'time_budget_exceeded' | null;
