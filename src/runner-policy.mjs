import assert from 'node:assert/strict';

const locations = new Set(['file:///work', 'file:///work/home', 'file:///work/codex-home', 'file:///fixture']);
function object(value) { assert.ok(value && typeof value === 'object' && !Array.isArray(value), 'invalid_rpc_object'); return value; }
function keys(value, allowed) { assert.ok(Object.keys(value).every(k => allowed.includes(k)), 'unknown_rpc_field'); }

// This is a model-free connection diagnostic, not a general execution proxy.
export function checkRemoteRequest(value) {
  const message = object(value);
  keys(message, ['jsonrpc', 'id', 'method', 'params']);
  assert.ok(message.jsonrpc === undefined || message.jsonrpc === '2.0', 'invalid_rpc_version');
  assert.ok(typeof message.method === 'string', 'invalid_rpc_method');
  if (message.id !== undefined) assert.ok(Number.isSafeInteger(message.id) || (typeof message.id === 'string' && /^[A-Za-z0-9_-]{1,200}$/.test(message.id)), 'invalid_rpc_id');
  const p = message.params == null ? {} : object(message.params);
  if (message.method === 'initialized') { assert.equal(message.id, undefined); keys(p, []); return 'forward'; }
  assert.notEqual(message.id, undefined, 'rpc_id_required');
  switch (message.method) {
    case 'initialize':
      keys(p, ['clientName', 'resumeSessionId']);
      assert.ok(typeof p.clientName === 'string' && /^[A-Za-z0-9_.-]{1,100}$/.test(p.clientName), 'invalid_client_name');
      assert.ok(p.resumeSessionId == null, 'resume_not_supported');
      return 'forward';
    case 'environment/info': case 'environment/status':
      keys(p, []); return 'forward';
    case 'environmentConfig/read':
      keys(p, ['cwd', 'configPaths', 'requirementsPaths']);
      assert.ok(['file:///work', 'file:///fixture'].includes(p.cwd), 'invalid_config_cwd');
      assert.deepEqual(p.configPaths, [['mcp_servers']]);
      assert.deepEqual(p.requirementsPaths, [['mcp_servers']]);
      return 'forward';
    case 'fs/getMetadata':
      keys(p, ['path', 'sandbox', 'followSymlinks']);
      assert.ok(typeof p.path === 'string', 'invalid_metadata_path');
      assert.ok(p.sandbox == null, 'metadata_sandbox_override');
      assert.ok(p.followSymlinks == null || p.followSymlinks === false, 'metadata_symlink_following');
      return locations.has(p.path) ? 'forward' : 'deny_metadata';
    default: throw new Error('remote_operation_not_allowed');
  }
}

export function daybreakStatus(models, features) {
  const model = models.find(row => row.model === 'gpt-6-sol');
  const advertised = model?.availableAccessPrograms?.cyber;
  return {
    modelRequested: 'gpt-6-sol', modelActual: 'unknown', accessProgramRequested: 'daybreak_blue',
    accessProgramEffective: 'unknown',
    advertisedPrograms: Array.isArray(advertised) ? ['standard', 'daybreakBlue', 'daybreakRed'].filter(p => advertised.includes(p)) : [],
    cliDaybreakEnabled: features.find(row => row.name === 'cli_daybreak')?.enabled === true,
  };
}

export function verifyContainerBoundary(info, image) {
  assert.equal(info.Image, image); assert.equal(info.Config.User, '65532:65532'); assert.equal(info.HostConfig.NetworkMode, 'none');
  assert.equal(info.HostConfig.ReadonlyRootfs, true); assert.equal(info.HostConfig.Privileged, false);
  assert.deepEqual(info.HostConfig.CapDrop.map(v => v.toUpperCase()), ['ALL']); assert.ok(info.HostConfig.SecurityOpt.includes('no-new-privileges'));
  assert.equal(info.HostConfig.IpcMode, 'private'); assert.equal(info.HostConfig.CgroupnsMode, 'private'); assert.ok(['', 'private'].includes(info.HostConfig.PidMode));
  assert.deepEqual(info.Mounts.map(m => [m.Destination, m.RW]).sort(), [['/fixture', false], ['/tools/codex', false]]);
  assert.equal(info.HostConfig.Memory, 268435456); assert.equal(info.HostConfig.MemorySwap, 268435456); assert.equal(info.HostConfig.NanoCpus, 1000000000);
  assert.equal(info.HostConfig.PidsLimit, 64); assert.equal(info.HostConfig.AutoRemove, true); assert.equal(info.HostConfig.LogConfig.Type, 'none');
  assert.equal(Object.keys(info.HostConfig.PortBindings ?? {}).length, 0);
  assert.ok(!info.Config.Env.some(v => /^(OPENAI_API_KEY|CODEX_API_KEY|CODEX_ACCESS_TOKEN)=/i.test(v)));
}
