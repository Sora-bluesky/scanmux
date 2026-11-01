import { rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { WebObservation } from './web-connection.ts';
import { SafeError } from './safety.ts';

// This is an independent persistence boundary, not a report serializer.
export function checkedObservation(value: WebObservation): WebObservation {
  const enums = {
    schema: ['scanmux.observation/v1'], operation: ['prepare', 'scan'],
    outcome: ['planned', 'blocked', 'completed', 'cancelled', 'error'],
    gate: ['PASS', 'FAIL', 'REVIEW', 'INCOMPLETE', 'ERROR', 'not_available'],
    reason: ['none', 'operation_failed', 'termination_unverified', 'source_cleanup_failed',
      'public_github_fetch_failed', 'public_github_head_unavailable', 'git_timeout', 'git_output_limit',
      'fetch_byte_limit', 'git_not_configured', 'tool_digest_mismatch', 'tool_version_mismatch',
      'output_secret_check_unavailable', 'output_secret_check_failed', 'output_size_limit', 'private_acl_unverified'],
  };
  if (!value || typeof value !== 'object' || Object.keys(value).sort().join(',') !== 'at,eventId,files,findings,gate,operation,outcome,reason,schema'
    || !Object.entries(enums).every(([key, allowed]) => allowed.includes(value[key as keyof WebObservation] as string))
    || typeof value.eventId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.eventId)
    || typeof value.at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.at)
    || !Number.isFinite(Date.parse(value.at))
    || ![value.files, value.findings].every(count => Number.isSafeInteger(count) && count >= 0)) throw new SafeError('invalid_observation');
  return structuredClone(value);
}

// The caller owns a freshly created private directory. Only closed events reach disk.
export function observationWriter(directory: string) {
  const destination = path.join(directory, 'observations.json');
  const counts: Record<string, number> = Object.create(null);
  let queue = Promise.resolve();
  function observe(input: WebObservation): Promise<void> {
    const event = checkedObservation(input);
    const next = queue.catch(() => {}).then(async () => {
      const key = [event.operation, event.outcome, event.gate, event.reason].join(':');
      const count = (counts[key] ?? 0) + 1;
      if (!Number.isSafeInteger(count)) throw new SafeError('observation_count_limit');
      const updated = { ...counts, [key]: count };
      const temporary = path.join(directory, `observation-${event.eventId}.tmp`);
      await writeFile(temporary, JSON.stringify({ schema: 'scanmux.observations/v1', latest: event, counts: updated }), { flag: 'wx', mode: 0o600 });
      await rename(temporary, destination);
      counts[key] = count;
    });
    queue = next;
    return next;
  }
  return { destination, observe };
}
