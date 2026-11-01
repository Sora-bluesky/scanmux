export const jobFailureCodes: readonly ['engine_execution_failed', 'controller_integrity_failure', 'checkpoint_output_rejected', 'plan_failed', 'plan_output_rejected', 'final_output_rejected', 'controller_failed'];
export type JobFailureCode = typeof jobFailureCodes[number];
export interface JobChannelOptions { nonce: string; maxOutputBytes: number; retainedBytes: number; sender: 'controller' | 'host'; diskSampleLimit?: number }
export interface ChannelLimits { chunkBytes: number; maxFrameBytes: number; maxFrames: number; maxBytes: number }
type Common = { v: 1; nonce: string; seq: number };
export type ControllerFrame = Common & (
  { type: 'begin'; recordId: number; kind: 'plan' | 'checkpoint' | 'report'; slot: number; sizes: number[]; hashes: string[] }
  | { type: 'chunk'; recordId: number; data: string } | { type: 'end'; recordId: number }
  | { type: 'failure'; code: JobFailureCode } | { type: 'disk-sample'; bytes: string | null });
type DiskCause = 'job_disk_measured_limit' | 'job_disk_observation_unverified';
export type HostFrame = Common & ({ type: 'ack'; ackSeq: number; disposition: 'accepted' | 'retained' | 'deadline' | 'cancelled' }
  | { type: 'disk-ack'; sampleSeq: number; cause: DiskCause | null } | { type: 'disk-stop'; cause: DiskCause });
export interface FrameWriter { limits: ChannelLimits; encode(fields: Omit<ControllerFrame, keyof Common> | Omit<HostFrame, keyof Common> | Record<string, unknown>): { bytes: Buffer; seq: number } }
export function jobDiskSampleLimit(limits: { wallMs: number; cleanupTimeoutMs: number }): number;
export function jobChannelLimits(maxOutputBytes: number, retainedBytes: number, diskSampleLimit?: number): ChannelLimits;
export function createJobFrameWriter(options: JobChannelOptions): FrameWriter;
export class JobFrameDecoder {
  constructor(options: JobChannelOptions);
  push(input: Buffer): (ControllerFrame | HostFrame)[];
  finish(expectedOwnerStop?: boolean): { discardedBytes: number };
}
export type AssembledJobMessage = { type: 'failure'; code: JobFailureCode; ackSeq: number }
  | { type: 'record'; kind: 'plan' | 'checkpoint' | 'report'; slot: number; parts: Buffer[]; ackSeq: number };
export function jobRecordFrames(writer: FrameWriter, recordId: number, kind: 'plan' | 'checkpoint' | 'report', slot: number, parts: Buffer[]): Generator<{bytes: Buffer; seq: number}>;
export class JobRecordAssembler {
  constructor(maxOutputBytes: number);
  accept(frame: Exclude<ControllerFrame, { type: 'disk-sample' }>): AssembledJobMessage | null;
  acknowledged(sequence: number): void;
  finish(expectedOwnerStop?: boolean): { discardedRecord: boolean };
}
