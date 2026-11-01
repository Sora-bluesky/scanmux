import type { ConfigurationInventory, ConfigurationIssueReason, ConfigurationSignalKind } from './model.ts';

const axes = ['build', 'osDependencies', 'monorepo', 'generated'] as const;
export interface ConfigurationObservation {
  path: string; build: ConfigurationSignalKind[]; osDependencies: ConfigurationSignalKind[];
  monorepo: ConfigurationSignalKind[]; generated: ConfigurationSignalKind[]; issues: ConfigurationIssueReason[];
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function nonemptyStrings(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(item => typeof item === 'string' && item.trim().length > 0);
}
function manifest(value: unknown, observation: ConfigurationObservation): void {
  if (!object(value)) { observation.issues.push('unsupported_manifest_shape'); return; }
  let unsupported = false;
  if (Object.hasOwn(value, 'scripts')) {
    if (!object(value.scripts)) unsupported = true;
    else if (Object.hasOwn(value.scripts, 'build')) {
      if (typeof value.scripts.build === 'string' && value.scripts.build.trim().length > 0) observation.build.push('node_build_script_declared');
      else unsupported = true;
    }
  }
  if (Object.hasOwn(value, 'os')) {
    if (nonemptyStrings(value.os)) observation.osDependencies.push('node_os_constraint_declared');
    else unsupported = true;
  }
  if (Object.hasOwn(value, 'workspaces')) {
    if (nonemptyStrings(value.workspaces) || (object(value.workspaces) && nonemptyStrings(value.workspaces.packages))) observation.monorepo.push('node_workspaces_declared');
    else unsupported = true;
  }
  if (unsupported) observation.issues.push('unsupported_manifest_shape');
}

// The caller supplies only blobs already accepted into plan.files. No target text is retained.
export function observeConfiguration(file: string, content: Uint8Array): ConfigurationObservation {
  const result: ConfigurationObservation = { path: file, build: [], osDependencies: [], monorepo: [], generated: [], issues: [] };
  const segments = file.split('/');
  const name = segments.at(-1)!;
  const extension = name.slice(name.lastIndexOf('.')).toLowerCase();
  if (name === 'package.json') result.build.push('node_manifest');
  if (['pyproject.toml', 'setup.py', 'setup.cfg'].includes(name)) result.build.push('python_build_manifest');
  if (['Makefile', 'makefile', 'GNUmakefile'].includes(name)) result.build.push('makefile');
  if (name === 'CMakeLists.txt') result.build.push('cmake_manifest');
  if (name === 'go.mod') result.build.push('go_module');
  if (name === 'Cargo.toml') result.build.push('rust_manifest');
  if (['pom.xml', 'build.gradle', 'build.gradle.kts'].includes(name)) result.build.push('jvm_build_manifest');
  if (['.csproj', '.fsproj', '.vbproj'].includes(extension)) result.build.push('dotnet_project');
  if (name === 'Dockerfile' || name.startsWith('Dockerfile.')) result.osDependencies.push('container_definition');
  if (name === 'binding.gyp') result.osDependencies.push('native_binding_definition');
  if (extension === '.sh') result.osDependencies.push('posix_shell_file');
  if (extension === '.ps1') result.osDependencies.push('powershell_file');
  if (name === 'pnpm-workspace.yaml') result.monorepo.push('pnpm_workspace_file');
  if (name === 'go.work') result.monorepo.push('go_workspace_file');
  if (['lerna.json', 'nx.json', 'turbo.json'].includes(name)) result.monorepo.push('monorepo_tool_config');
  if (segments.slice(0, -1).some(segment => ['dist', 'build', 'coverage', 'node_modules'].includes(segment))) result.generated.push('generated_directory_hint');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(content); }
  catch { result.issues.push('invalid_utf8'); return result; }
  if (/^\/\/ Code generated .* DO NOT EDIT\.$/.test(text.split(/\r?\n/, 1)[0])) result.generated.push('generated_header_declaration');
  if (name === 'package.json') {
    let value: unknown;
    try { value = JSON.parse(text); }
    catch { result.issues.push('invalid_json'); return result; }
    manifest(value, result);
  }
  return result;
}

function compare(a: string, b: string): number { return a < b ? -1 : a > b ? 1 : 0; }
export function summarizeConfiguration(observations: ConfigurationObservation[]): ConfigurationInventory {
  const result: ConfigurationInventory = {
    schema: 'scanmux.configuration/v1', basis: 'accepted_commit_blobs', interpretation: 'declaration_hints_only',
    build: { state: 'unknown', signals: [] }, osDependencies: { state: 'unknown', signals: [] },
    monorepo: { state: 'unknown', signals: [] }, generated: { state: 'unknown', signals: [] }, issues: [],
    limitations: ['absence_not_proven', 'build_not_executed', 'os_requirements_unverified', 'workspace_membership_unverified', 'generated_status_unverified'],
  };
  for (const axis of axes) {
    const signals = observations.flatMap(observation => observation[axis].map(kind => ({ kind, path: observation.path })))
      .sort((a, b) => compare(a.path, b.path) || compare(a.kind, b.kind));
    result[axis].signals = signals.filter((signal, index) => !index || signal.path !== signals[index - 1].path || signal.kind !== signals[index - 1].kind);
    if (result[axis].signals.length) result[axis].state = 'signals_observed';
  }
  const issues = observations.flatMap(observation => observation.issues.map(reason => ({ path: observation.path, reason })))
    .sort((a, b) => compare(a.path, b.path) || compare(a.reason, b.reason));
  result.issues = issues.filter((issue, index) => !index || issue.path !== issues[index - 1].path || issue.reason !== issues[index - 1].reason);
  return result;
}
