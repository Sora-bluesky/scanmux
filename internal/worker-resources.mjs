import fs from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { randomUUID } from 'node:crypto';

const plain = value => value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype;
const exact = (value, keys) => plain(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const count = value => Number.isSafeInteger(value) && value >= 0;
const positive = value => count(value) && value > 0;
const requireValue = (value, code) => { if (!value) throw Error(code); };
const resourceKeys = ['cpuCount', 'memoryBytes', 'tmpBytes', 'workBytes', 'shmBytes'];
const kernelKeys = ['cpuQuota', 'cpuPeriod', 'memoryMax', 'swapMax', 'tmpBytes', 'workBytes', 'shmBytes'];
const eventKeys = ['cpuThrottledPeriods', 'oom', 'oomKill'];
const pageBytes = 4096;

/** Operator-provided values only; kernel rounding must not silently expand them. */
export function parseWorkerResources(input) {
  requireValue(exact(input, resourceKeys) && Object.values(input).every(positive), 'invalid_worker_resources');
  requireValue(Number.isSafeInteger(input.cpuCount * 1000000000) && input.memoryBytes >= 6 * 1024 * 1024
    && resourceKeys.slice(1).every(key => input[key] % pageBytes === 0)
    && Number.isSafeInteger(input.tmpBytes + input.workBytes + input.shmBytes), 'invalid_worker_resources');
  return Object.fromEntries(resourceKeys.map(key => [key, input[key]]));
}

export function expectedResourceKernel(input) {
  const limits = parseWorkerResources(input);
  return { cpuQuota: limits.cpuCount * 100000, cpuPeriod: 100000, memoryMax: limits.memoryBytes, swapMax: 0,
    tmpBytes: limits.tmpBytes, workBytes: limits.workBytes, shmBytes: limits.shmBytes };
}

export function parseResourceSnapshot(input, requested) {
  requireValue(exact(input, ['kernel', 'events']) && exact(input.kernel, kernelKeys) && exact(input.events, eventKeys)
    && Object.values(input.kernel).every(count) && Object.values(input.events).every(count)
    && isDeepStrictEqual(input.kernel, expectedResourceKernel(requested)), 'resource_boundary_unverified');
  return structuredClone(input);
}

function counters(text, wanted) {
  const observed = new Map();
  for (const line of text.trim().split('\n')) {
    const match = /^([a-z_]+) ([0-9]+)$/.exec(line);
    requireValue(match && !observed.has(match[1]), 'resource_observation_invalid');
    observed.set(match[1], Number(match[2]));
  }
  requireValue(wanted.every(key => observed.has(key) && count(observed.get(key))), 'resource_observation_invalid');
  return Object.fromEntries(wanted.map(key => [key, observed.get(key)]));
}

/** Read only this fresh container's cgroup and its three bounded writable stores. */
export async function readWorkerResourceSnapshot(requested) {
  parseWorkerResources(requested);
  const read = async name => { const bytes = await fs.readFile('/sys/fs/cgroup/' + name); requireValue(bytes.length <= 16384, 'resource_observation_invalid'); return new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim(); };
  const cpu = /^([0-9]+) ([0-9]+)$/.exec(await read('cpu.max'));
  requireValue(cpu, 'resource_boundary_unverified');
  const decimal = text => { requireValue(/^[0-9]+$/.test(text) && count(Number(text)), 'resource_boundary_unverified'); return Number(text); };
  const kernel = { cpuQuota: decimal(cpu[1]), cpuPeriod: decimal(cpu[2]), memoryMax: decimal(await read('memory.max')), swapMax: decimal(await read('memory.swap.max')) };
  for (const [folder, key] of [['/tmp', 'tmpBytes'], ['/work', 'workBytes'], ['/dev/shm', 'shmBytes']]) {
    const stat = await fs.statfs(folder);
    requireValue(stat.bsize === pageBytes && count(stat.blocks) && count(stat.bsize * stat.blocks), 'resource_boundary_unverified');
    kernel[key] = stat.bsize * stat.blocks;
  }
  const cpuEvents = counters(await read('cpu.stat'), ['nr_throttled']), memoryEvents = counters(await read('memory.events'), ['oom', 'oom_kill']);
  return parseResourceSnapshot({ kernel, events: { cpuThrottledPeriods: cpuEvents.nr_throttled, oom: memoryEvents.oom, oomKill: memoryEvents.oom_kill } }, requested);
}

const terminalValue = input => exact(input, ['exitCode', 'oomKilled']) && count(input.exitCode) && input.exitCode <= 255 && typeof input.oomKilled === 'boolean';

/** Missing observations remain missing, including when the kernel killed PID 1. */
export function buildWorkerResourceReport({ requested, boundaryVerified, startupVerified, snapshot, terminal, failureCode, diskObserved, deadlineExceeded }) {
  const limits = parseWorkerResources(requested), ending = terminalValue(terminal) ? structuredClone(terminal) : null;
  let observed;
  try { observed = parseResourceSnapshot(snapshot, limits); } catch { observed = null; }
  const exceeded = [];
  if (ending?.oomKilled || observed?.events.oom || observed?.events.oomKill || failureCode === 'resource_memory_exceeded') exceeded.push('memory');
  if (failureCode === 'resource_disk_exceeded' || diskObserved === true) exceeded.push('disk');
  if (deadlineExceeded === true) exceeded.push('time');
  const common = { schema: 'scanmux.worker-resources/v1', requested: limits, exceeded };
  if (boundaryVerified === true && startupVerified === true && observed && ending) return { ...common, state: 'verified', ...observed, terminal: ending };
  return { ...common, state: 'not_verified', reason: boundaryVerified !== true ? 'boundary_unverified' : 'observation_missing', kernel: null, events: null, terminal: ending };
}

export function workerResourcesComplete(input, requested) {
  try {
    const limits = parseWorkerResources(requested);
    if (!exact(input, ['schema', 'requested', 'state', 'kernel', 'events', 'terminal', 'exceeded']) || input.schema !== 'scanmux.worker-resources/v1'
      || input.state !== 'verified' || !isDeepStrictEqual(parseWorkerResources(input.requested), limits) || !terminalValue(input.terminal)
      || input.terminal.exitCode !== 0 || input.terminal.oomKilled || !Array.isArray(input.exceeded) || input.exceeded.length) return false;
    const observed = parseResourceSnapshot({ kernel: input.kernel, events: input.events }, limits);
    return observed.events.oom === 0 && observed.events.oomKill === 0;
  } catch { return false; }
}

/** A known local limit cannot excuse an independent loss of evidence or ownership. */
export function classifyResourceStop(options) {
  const terminalReasons = ['bridge_early_eof', 'bridge_worker_exit', 'bridge_stopped', 'resource_memory_exceeded', 'resource_disk_exceeded',
    'ipc_input_closed', 'ipc_input_error', 'ipc_output_closed', 'ipc_output_error', 'ipc_stopped', 'ipc_deadline'];
  if (!terminalReasons.includes(options.reason) || options.boundaryVerified !== true || options.inputsUnchanged !== true || options.workerClosed !== true
    || options.containerAbsent !== true || options.transportClosed !== true || options.independentFailure !== false || !['not_started', 'closed'].includes(options.mcpEvidence) || !['none', 'verified'].includes(options.artifactEvidence) || !count(options.calls)
    || options.calls > 0 && (options.tokensComplete !== true || options.executionStatus !== 'completed')) return null;
  const exceeded = options.resources?.exceeded;
  if (!Array.isArray(exceeded) || exceeded.length === 0 || exceeded.some(value => !['memory', 'disk', 'time'].includes(value))) return null;
  if (exceeded.includes('memory')) return 'resource_memory_exceeded';
  if (exceeded.includes('disk')) return 'resource_disk_exceeded';
  return 'time_budget_exceeded';
}

/** A bounded write, rather than free-space arithmetic, witnesses ENOSPC. */
export async function probeWorkerDisk(io = fs) {
  const fullStores = []; let observationComplete = true;
  for (const [folder, store] of [['/tmp', 'tmp'], ['/work', 'work'], ['/dev/shm', 'shm']]) {
    const name = folder + '/.scanmux-resource-' + randomUUID(); let handle, full = false, valid = true;
    try { handle = await io.open(name, 'wx', 0o600); const result = await handle.write(Buffer.alloc(pageBytes)); valid = result.bytesWritten === pageBytes; }
    catch (error) { if (error.code === 'ENOSPC') full = true; else valid = false; }
    finally {
      if (handle) {
        try { await handle.close(); } catch { valid = false; }
        try { await io.unlink(name); } catch { valid = false; }
      }
    }
    if (!valid) observationComplete = false;
    if (full && valid) fullStores.push(store);
  }
  return { fullStores, observationComplete };
}

