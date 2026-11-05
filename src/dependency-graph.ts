import path from 'node:path';
import { hash, safeRelative } from './safety.ts';
import {
  admits, compareVersions, isExactSpec, isTomlTable, parseMarker, parseNpmName, parseNpmRange, parseNpmVersion, parsePep440Specifier, parsePypiName, parsePypiVersion,
  parseRequirement, parseToml, renderSpec, type Parsed, type Spec, type SyntaxReason, type TomlTable, type TomlValue, type Version,
} from './dependency-syntax.ts';

export type Ecosystem = 'npm' | 'uv';
export type GraphReason = 'lockfile_encoding' | 'lockfile_size_limit' | 'lockfile_invalid' | 'lockfile_version_unsupported' | 'instance_limit' | 'edge_limit' | SyntaxReason;
export type ManifestReason = 'manifest_missing' | 'manifest_encoding' | 'manifest_size_limit' | 'manifest_invalid' | 'manifest_depth_limit'
  | 'workspaces_outside_subset' | 'dynamic_dependencies_outside_subset' | SyntaxReason;
export interface DeclarationView { readonly spec: string | null; readonly reason: SyntaxReason | null; readonly extras: readonly string[]; readonly markerSha256: string | null }
export interface RequirementChange { readonly section: string; readonly name: string; readonly base: readonly DeclarationView[] | null; readonly head: readonly DeclarationView[] | null }
export type Explanation =
  | { readonly state: 'explained'; readonly via: readonly string[] }
  | { readonly state: 'unexplained'; readonly reason: 'reachable_only_via_unchanged' | 'not_reachable' }
  | { readonly state: 'undetermined'; readonly reason: 'manifest_undetermined' | 'manifest_lock_mismatch' | 'settings_unreadable' | 'overrides_changed' | 'via_limit' };
export type MetadataField = 'flags' | 'artifact' | 'declared_dependencies' | 'other';
export type DependencyChange =
  | { readonly kind: 'version_changed'; readonly key: string; readonly name: string; readonly from: string | null; readonly to: string | null; readonly explanation: Explanation }
  | { readonly kind: 'added'; readonly key: string; readonly name: string; readonly version: string | null; readonly explanation: Explanation }
  | { readonly kind: 'removed'; readonly key: string; readonly name: string; readonly version: string | null }
  | { readonly kind: 'relocated'; readonly from: string; readonly to: string; readonly name: string; readonly version: string }
  | { readonly kind: 'metadata_only'; readonly key: string; readonly name: string; readonly version: string | null; readonly fields: readonly MetadataField[] };
export interface OutsideItem { readonly key: string; readonly field: 'version' | 'source' | 'dependency'; readonly dependency: string | null; readonly reason: SyntaxReason }
export interface OutsideCount { readonly field: OutsideItem['field']; readonly reason: SyntaxReason; readonly count: number }
export interface GraphSummary { readonly instances: number; readonly edges: number; readonly unresolvedEdges: number; readonly outside: readonly OutsideItem[]; readonly outsideCount: number; readonly outsideByReason: readonly OutsideCount[] }
export interface SideInputs { readonly lockfileSha256: string | null; readonly manifestSha256: string | null }
export type ProjectStatus =
  | { readonly kind: 'complete' }
  | { readonly kind: 'undetermined'; readonly side: 'base' | 'head'; readonly reason: GraphReason }
  | { readonly kind: 'change_limit' };
export interface ProjectDiff {
  readonly lockfile: string;
  readonly ecosystem: Ecosystem;
  readonly inputs: { readonly base: SideInputs; readonly head: SideInputs };
  readonly manifest: { readonly base: ManifestReason | null; readonly head: ManifestReason | null };
  readonly graph: { readonly base: GraphSummary | null; readonly head: GraphSummary | null };
  readonly status: ProjectStatus;
  readonly requirements: readonly RequirementChange[];
  readonly changes: readonly DependencyChange[];
}
export interface DependencyDiff { readonly projects: readonly ProjectDiff[] }
export type DependencyInputs = ReadonlyMap<string, Uint8Array>;

export const dependencyLimits = { fileBytes: 32 * 1024 * 1024, instances: 20_000, edges: 200_000, via: 32, changes: 20_000, outsideListed: 32, manifestDepth: 64 } as const;
const inputNames = new Set(['package.json', 'package-lock.json', '.npmrc', 'pyproject.toml', 'uv.lock', 'uv.toml']);
const lockfileEcosystem: Readonly<Record<string, Ecosystem>> = { 'package-lock.json': 'npm', 'uv.lock': 'uv' };
const manifestName: Readonly<Record<Ecosystem, string>> = { npm: 'package.json', uv: 'pyproject.toml' };

export function dependencyInputPath(file: string): boolean {
  try { return inputNames.has(path.posix.basename(safeRelative(file))); } catch { return false; }
}

interface Declaration { readonly canonical: string; readonly view: DeclarationView }
interface Requirements { readonly section: string; readonly group: string; readonly name: string; readonly declarations: Declaration[] }
// Direct declarations per name, as comparable strings, so a manifest and a lockfile root can be checked for agreement.
type Direct = ReadonlyMap<string, readonly string[]>;
type Manifest =
  | {
    readonly kind: 'determined'; readonly requirements: ReadonlyMap<string, Requirements>; readonly direct: Direct;
    readonly overrides: string; readonly sources: string; readonly cutoff: boolean;
  }
  | { readonly kind: 'undetermined'; readonly reason: ManifestReason };
// version is output only after validation; versionId also identifies a version that failed validation, by hash.
interface Node {
  readonly key: string; readonly name: string; readonly version: string | null; readonly versionId: string | null; readonly root: boolean;
  readonly bundled: boolean; readonly nonRegistry: boolean; readonly digests: Readonly<Record<MetadataField, string>>;
}
interface Constraint { readonly spec: Parsed<Spec>; readonly marker: boolean }
interface Edge {
  readonly name: string; readonly constraints: readonly Constraint[] | 'not_recorded'; readonly duplicate: boolean;
  readonly marker: boolean; to: string | null; readonly extras: readonly string[]; readonly groups: readonly string[];
}
interface Graph {
  readonly nodes: Map<string, Node>;
  readonly edges: Map<string, Edge[]>;
  readonly outside: OutsideItem[];
  readonly direct: Direct;
  readonly workspaces: boolean;
  readonly overrides: string;
  readonly cutoff: boolean;
  readonly uvWorkspace?: { readonly members: readonly { readonly name: string; readonly source: TomlTable }[]; readonly manifest: TomlTable | undefined };
}
type Loaded<T, R> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: R };

class Invalid { readonly reason: GraphReason; constructor(reason: GraphReason) { this.reason = reason; } }
const invalid = (reason: GraphReason = 'lockfile_invalid'): never => { throw new Invalid(reason); };
const sortedKeys = (_: string, value: unknown) => value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.entries(value).sort(([left], [right]) => compareText(left, right))) : value;
const fingerprint = (value: unknown) => hash(JSON.stringify(value ?? null, sortedKeys));
const compareText = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const pypiName = (value: unknown) => {
  const name = typeof value === 'string' ? parsePypiName(value) : null;
  return name?.ok ? name.value : null;
};

function decode(bytes: Uint8Array): Loaded<string, 'encoding' | 'size_limit'> {
  if (bytes.byteLength > dependencyLimits.fileBytes) return { ok: false, reason: 'size_limit' };
  try { return { ok: true, value: new TextDecoder('utf-8', { fatal: true }).decode(bytes) }; } catch { return { ok: false, reason: 'encoding' }; }
}

function declaration(spec: Parsed<Spec>, raw: string, extras: readonly string[] = [], marker: string | null = null): Declaration {
  const markerSha256 = marker === null ? null : hash(marker);
  const body = spec.ok ? 'r:' + renderSpec(spec.value) : 'x:' + spec.reason + ':' + hash(raw);
  return {
    canonical: [extras.join(','), body, markerSha256 ?? ''].join('|'),
    view: { spec: spec.ok ? renderSpec(spec.value) : null, reason: spec.ok ? null : spec.reason, extras, markerSha256 },
  };
}
function addRequirement(map: Map<string, Requirements>, section: string, group: string, name: string, entry: Declaration) {
  const key = section + '\0' + name;
  const existing = map.get(key) ?? { section, group, name, declarations: [] };
  existing.declarations.push(entry);
  existing.declarations.sort((left, right) => compareText(left.canonical, right.canonical));
  map.set(key, existing);
}
function addDirect(map: Map<string, string[]>, name: string, comparable: string) {
  const list = map.get(name) ?? [];
  list.push(comparable);
  list.sort(compareText);
  map.set(name, list);
}
const sameDirect = (left: readonly string[] | undefined, right: readonly string[] | undefined) => (left ?? []).join('\n') === (right ?? []).join('\n');
const declared = (settings: Readonly<Record<string, unknown>>) => {
  const present = Object.entries(settings).filter(([, value]) => value !== undefined);
  return fingerprint(present.length ? Object.fromEntries(present) : null);
};
const unreadableSettings = fingerprint('unreadable');

function withinDepth(value: unknown, limit: number): boolean {
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length) {
    const [item, depth] = stack.pop()!;
    if (typeof item !== 'object' || item === null) continue;
    if (depth > limit) return false;
    for (const child of Object.values(item)) stack.push([child, depth + 1]);
  }
  return true;
}

const npmSections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'] as const;
const npmDirect = (section: string, raw: string) => section + '|' + declaration(parseNpmRange(raw), raw).canonical;
function npmManifest(text: string): Manifest {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return { kind: 'undetermined', reason: 'manifest_invalid' }; }
  if (!isRecord(json)) return { kind: 'undetermined', reason: 'manifest_invalid' };
  if (!withinDepth(json, dependencyLimits.manifestDepth)) return { kind: 'undetermined', reason: 'manifest_depth_limit' };
  if (json.workspaces !== undefined) return { kind: 'undetermined', reason: 'workspaces_outside_subset' };
  const requirements = new Map<string, Requirements>(), direct = new Map<string, string[]>();
  for (const section of npmSections) {
    const value = json[section];
    if (value === undefined) continue;
    if (!isRecord(value)) return { kind: 'undetermined', reason: 'manifest_invalid' };
    for (const [name, spec] of Object.entries(value)) {
      if (typeof spec !== 'string' || !parseNpmName(name).ok) return { kind: 'undetermined', reason: 'manifest_invalid' };
      addRequirement(requirements, section, section, name, declaration(parseNpmRange(spec), spec));
      addDirect(direct, name, npmDirect(section, spec));
    }
  }
  return { kind: 'determined', requirements, direct, overrides: fingerprint(json.overrides), sources: fingerprint(null), cutoff: false };
}

const declaresCutoff = (table: TomlValue | undefined) => isTomlTable(table) && Object.keys(table).some(key => key.startsWith('exclude-newer'));
function stringList(value: TomlValue | undefined): string[] | null {
  if (value === undefined) return [];
  return Array.isArray(value) && value.every(item => typeof item === 'string') ? value as string[] : null;
}
const specBody = (spec: Parsed<Spec>) => spec.ok ? 'r:' + renderSpec(spec.value) : 'x:' + spec.reason;
const uvDirect = (group: string, extras: readonly string[], spec: Parsed<Spec>, marker: string) => [group, extras.join(','), specBody(spec), marker].join('|');
const markerKey = (marker: string | null) => marker === null ? '' : hash(marker);
const uvResolution = (settings: TomlTable) =>
  declared({ override: settings['override-dependencies'], constraint: settings['constraint-dependencies'], metadata: settings['dependency-metadata'] });
const dynamicDependencyFields = new Set(['dependencies', 'optional-dependencies']);
function uvManifest(text: string, workspace = false, virtualRoot = false): Manifest {
  const toml = parseToml(text);
  if (!toml.ok) return { kind: 'undetermined', reason: toml.reason };
  const tool = toml.value.tool;
  const uv = isTomlTable(tool) ? tool.uv : undefined;
  const virtual = virtualRoot && toml.value.project === undefined;
  const project = virtual ? {} : toml.value.project;
  if (!isTomlTable(project) || (uv !== undefined && !isTomlTable(uv))) return { kind: 'undetermined', reason: 'manifest_invalid' };
  if (!workspace && uv?.workspace !== undefined) return { kind: 'undetermined', reason: 'workspaces_outside_subset' };
  const dynamic = stringList(project.dynamic);
  if (!dynamic) return { kind: 'undetermined', reason: 'manifest_invalid' };
  if (dynamic.some(field => dynamicDependencyFields.has(field))) return { kind: 'undetermined', reason: 'dynamic_dependencies_outside_subset' };
  const sections: [string, string, TomlValue | undefined][] = virtual ? []
    : [['project.dependencies', 'main', project.dependencies], ['tool.uv.dev-dependencies', 'dev:dev', uv?.['dev-dependencies']]];
  const groups = (prefix: string, kind: string, table: TomlValue | undefined) => {
    if (table === undefined) return true;
    if (!isTomlTable(table)) return false;
    for (const [group, list] of Object.entries(table)) {
      const name = parsePypiName(group);
      if (!name.ok) return false;
      sections.push([prefix + name.value, kind + name.value, list]);
    }
    return true;
  };
  if (!groups('project.optional-dependencies.', 'extra:', project['optional-dependencies']) || !groups('dependency-groups.', 'dev:', toml.value['dependency-groups'])) {
    return { kind: 'undetermined', reason: 'manifest_invalid' };
  }
  const requirements = new Map<string, Requirements>(), direct = new Map<string, string[]>();
  for (const [section, group, value] of sections) {
    const list = stringList(value);
    if (!list) return { kind: 'undetermined', reason: 'requirement_outside_subset' };
    for (const raw of list) {
      const requirement = parseRequirement(raw);
      if (!requirement.ok) return { kind: 'undetermined', reason: requirement.reason };
      const { name, extras, specifier, marker } = requirement.value;
      addRequirement(requirements, section, group, name, declaration(specifier, raw, extras, marker));
      addDirect(direct, name, uvDirect(group, extras, specifier, markerKey(marker)));
    }
  }
  return { kind: 'determined', requirements, direct, overrides: uvResolution(uv ?? {}), sources: fingerprint(uv?.sources ?? null), cutoff: declaresCutoff(uv) };
}

function loadManifest(ecosystem: Ecosystem, bytes: Uint8Array | undefined, lockPresent: boolean): Manifest {
  if (!bytes) {
    return lockPresent ? { kind: 'undetermined', reason: 'manifest_missing' }
      : { kind: 'determined', requirements: new Map(), direct: new Map(), overrides: fingerprint(null), sources: fingerprint(null), cutoff: false };
  }
  const text = decode(bytes);
  if (!text.ok) return { kind: 'undetermined', reason: text.reason === 'encoding' ? 'manifest_encoding' : 'manifest_size_limit' };
  return ecosystem === 'npm' ? npmManifest(text.value) : uvManifest(text.value);
}

class GraphBuilder {
  readonly nodes = new Map<string, Node>();
  readonly edges = new Map<string, Edge[]>();
  readonly outside: OutsideItem[] = [];
  private edgeCount = 0;
  edge(from: string, edge: Edge) {
    if (++this.edgeCount > dependencyLimits.edges) invalid('edge_limit');
    for (const { spec } of edge.constraints === 'not_recorded' ? [] : edge.constraints) {
      if (!spec.ok) this.outside.push({ key: from, field: 'dependency', dependency: edge.name, reason: spec.reason });
    }
    const list = this.edges.get(from) ?? [];
    list.push(edge);
    this.edges.set(from, list);
  }
  node(node: Node) { this.nodes.set(node.key, node); }
}

function npmPath(key: string): string[] | null {
  const parts = key ? key.split('/') : [], names: string[] = [];
  for (let index = 0; index < parts.length;) {
    if (parts[index] !== 'node_modules') return null;
    const scoped = parts[index + 1]?.startsWith('@');
    const name = scoped ? `${parts[index + 1]}/${parts[index + 2] ?? ''}` : parts[index + 1] ?? '';
    if (!parseNpmName(name).ok) return null;
    names.push(name);
    index += scoped ? 3 : 2;
  }
  return names;
}
const npmKey = (names: readonly string[]) => names.map(name => 'node_modules/' + name).join('/');

function npmGraph(text: string): Graph {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return invalid(); }
  if (!isRecord(json)) return invalid();
  if (json.lockfileVersion !== 2 && json.lockfileVersion !== 3) return invalid('lockfile_version_unsupported');
  if (!isRecord(json.packages)) return invalid();
  const entries = Object.entries(json.packages);
  if (entries.length > dependencyLimits.instances) invalid('instance_limit');
  const builder = new GraphBuilder(), locations = new Map<string, string[]>(), direct = new Map<string, string[]>();
  let workspaces = false;
  for (const [key, entry] of entries) {
    if (!isRecord(entry)) return invalid();
    const names = npmPath(key);
    if (!names) { workspaces = true; continue; }
    const root = key === '';
    if (root && entry.workspaces !== undefined) workspaces = true;
    const name = entry.name === undefined ? names.at(-1) ?? '' : typeof entry.name === 'string' && parseNpmName(entry.name).ok ? entry.name : invalid();
    let version: string | null = null;
    if (entry.link === true) builder.outside.push({ key, field: 'source', dependency: null, reason: 'non_registry_source' });
    else if (typeof entry.version === 'string' && /^\d{1,15}\.\d{1,15}\.\d{1,15}(?:[-+][0-9A-Za-z.+-]{1,48})?$/.test(entry.version)) {
      version = entry.version;
      const parsed = parseNpmVersion(version);
      if (!parsed.ok) builder.outside.push({ key, field: 'version', dependency: null, reason: parsed.reason });
    } else if (!root) builder.outside.push({ key, field: 'version', dependency: null, reason: 'version_outside_subset' });
    const sections = root ? npmSections : npmSections.filter(section => section !== 'devDependencies');
    const declarations: Record<string, Record<string, string>> = {}, bySection = new Map<string, Map<string, string>>();
    for (const section of sections) {
      const map = entry[section];
      if (map === undefined) continue;
      if (!isRecord(map)) return invalid();
      declarations[section] = {};
      for (const [dependency, raw] of Object.entries(map)) {
        if (typeof raw !== 'string' || !parseNpmName(dependency).ok) return invalid();
        declarations[section][dependency] = declaration(parseNpmRange(raw), raw).canonical;
        if (root) addDirect(direct, dependency, npmDirect(section, raw));
        const specs = bySection.get(dependency) ?? new Map<string, string>();
        specs.set(section, raw);
        bySection.set(dependency, specs);
      }
    }
    for (const [dependency, specs] of bySection) {
      // Arborist lets optionalDependencies replace a dependencies entry of the same name; other overlaps are not modeled.
      if (specs.has('optionalDependencies') && specs.has('dependencies') && specs.size === 2) specs.delete('dependencies');
      const constraints = [...specs.values()].map(raw => ({ spec: parseNpmRange(raw), marker: false }));
      builder.edge(key, { name: dependency, constraints, duplicate: specs.size > 1, marker: false, to: null, extras: [], groups: [...specs.keys()] });
    }
    const { version: _v, name: _n, dev, optional, devOptional, peer, inBundle, resolved, integrity, hasInstallScript, ...rest } = entry;
    for (const section of npmSections) delete rest[section];
    const nonRegistry = entry.link === true || (typeof resolved === 'string' && !/^https?:\/\//.test(resolved));
    builder.node({ key, name, version, versionId: version, root, bundled: inBundle === true, nonRegistry, digests: {
      flags: fingerprint([dev, optional, devOptional, peer, inBundle]),
      artifact: fingerprint([resolved, integrity, hasInstallScript]),
      declared_dependencies: fingerprint(declarations),
      other: fingerprint([entry.name, rest]),
    } });
    locations.set(key, names);
  }
  for (const [from, list] of builder.edges) {
    const names = locations.get(from)!;
    for (const edge of list) {
      for (let depth = names.length; depth >= 0 && edge.to === null; depth--) {
        const candidate = npmKey([...names.slice(0, depth), edge.name]);
        if (builder.nodes.has(candidate)) edge.to = candidate;
      }
    }
  }
  return { nodes: builder.nodes, edges: builder.edges, outside: builder.outside, direct, workspaces, overrides: fingerprint(null), cutoff: false };
}

interface UvDependency { readonly name: string; readonly version: string | null; readonly marker: boolean; readonly extras: readonly string[]; readonly declared: unknown; readonly markerText: unknown }
function uvDependencies(value: TomlValue | undefined): UvDependency[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return invalid();
  return value.map(item => {
    if (!isTomlTable(item) || typeof item.name !== 'string') return invalid();
    const name = parsePypiName(item.name);
    if (!name.ok) return invalid();
    if (item.version !== undefined && typeof item.version !== 'string') return invalid();
    const extras = (stringList(item.extra) ?? invalid()).map(extra => pypiName(extra) ?? invalid());
    const { marker, ...declared } = item;
    return { name: name.value, version: item.version ?? null, marker: marker !== undefined, extras, declared, markerText: marker };
  });
}
function uvGroups(value: TomlValue | undefined): [string, UvDependency[]][] {
  if (value === undefined) return [];
  if (!isTomlTable(value)) return invalid();
  return Object.entries(value).map(([group, list]) => {
    const name = parsePypiName(group);
    return [name.ok ? name.value : invalid(), uvDependencies(list)];
  });
}
const uvSourceKinds = ['registry', 'editable', 'virtual', 'git', 'path', 'directory', 'url'] as const;
const memberLabel = (member: string, label: string) => member === '.' ? label : member + ':' + label;
const uvVersion = (raw: string) => parsePypiVersion(raw).ok ? raw : null;
const uvVersionId = (raw: string | null) => raw === null ? null : uvVersion(raw) ?? 'sha256:' + hash(raw);

// A root requirement recorded in uv.lock metadata. group is null when its marker cannot be attributed to one group.
// marker is the comparable marker beyond the group's own extra marker.
interface RootEntry {
  readonly group: string | null; readonly name: string; readonly extras: readonly string[]; readonly spec: Parsed<Spec>; readonly conditional: boolean; readonly marker: string;
}
const extraGroup = /^extra == (['"])([^'"]*)\1$/;
function rootEntry(item: TomlValue, devGroup: string | null): RootEntry {
  if (!isTomlTable(item)) return invalid();
  const name = pypiName(item.name) ?? invalid();
  const extras = stringList(item.extras)?.map(pypiName);
  const marker = item.marker === undefined ? null : typeof item.marker === 'string' ? parseMarker(item.marker) : { ok: false as const };
  const typed = (item.specifier === undefined || typeof item.specifier === 'string') && extras !== undefined && !extras.includes(null) && marker?.ok !== false;
  const spec = typed ? parsePep440Specifier((item.specifier as string | undefined) ?? '') : { ok: false as const, reason: 'specifier_outside_subset' as const };
  const common = { name, extras: typed ? extras as string[] : [], spec, marker: markerKey(marker?.ok ? marker.value : marker ? 'invalid' : null) };
  if (devGroup !== null) return { ...common, group: 'dev:' + devGroup, conditional: marker !== null };
  if (!marker?.ok) return { ...common, group: marker ? null : 'main', conditional: false };
  const extra = extraGroup.exec(marker.value), group = extra ? pypiName(extra[2]) : null;
  if (extra) return { ...common, group: group === null ? null : 'extra:' + group, conditional: false, marker: '' };
  return { ...common, group: /\bextra\b/.test(marker.value.replace(/(['"])[^'"]*\1/g, '')) ? null : 'main', conditional: true };
}
function rootEntries(metadata: TomlValue | undefined): RootEntry[] {
  if (metadata === undefined) return [];
  if (!isTomlTable(metadata)) return invalid();
  const dist = metadata['requires-dist'], dev = metadata['requires-dev'];
  if ((dist !== undefined && !Array.isArray(dist)) || (dev !== undefined && !isTomlTable(dev))) return invalid();
  const entries = (dist as readonly TomlValue[] | undefined ?? []).map(item => rootEntry(item, null));
  for (const [group, list] of Object.entries(dev ?? {})) {
    const name = pypiName(group) ?? invalid();
    if (!Array.isArray(list)) return invalid();
    entries.push(...list.map(item => rootEntry(item, name)));
  }
  return entries;
}

function uvGraph(text: string): Graph {
  const toml = parseToml(text);
  if (!toml.ok) return invalid(toml.reason);
  const lock = toml.value;
  if (lock.version !== 1) return invalid('lockfile_version_unsupported');
  if (lock.revision !== undefined && typeof lock.revision !== 'number') return invalid();
  const packages = lock.package ?? [];
  if (!Array.isArray(packages)) return invalid();
  if (packages.length > dependencyLimits.instances) invalid('instance_limit');
  const manifest = lock.manifest;
  if (manifest !== undefined && !isTomlTable(manifest)) return invalid();
  const workspaces = Array.isArray(manifest?.members) && manifest.members.length > 0;
  const parsed = packages.map(item => {
    if (!isTomlTable(item) || typeof item.name !== 'string') return invalid();
    const name = parsePypiName(item.name);
    if (!name.ok || (item.version !== undefined && typeof item.version !== 'string') || (item.source !== undefined && !isTomlTable(item.source))) return invalid();
    const source = uvSourceKinds.find(kind => isTomlTable(item.source) && Object.hasOwn(item.source, kind)) ?? null;
    return { table: item as TomlTable, name: name.value, version: (item.version as string | undefined) ?? null, source };
  });
  const versionsByName = new Map<string, number>();
  for (const item of parsed) versionsByName.set(item.name, (versionsByName.get(item.name) ?? 0) + 1);
  const keyOf = (name: string, version: string | null) => (versionsByName.get(name) ?? 0) <= 1 ? name : `${name}@${uvVersionId(version) ?? ''}`;
  const builder = new GraphBuilder(), optional = new Map<string, Map<string, UvDependency[]>>(), direct = new Map<string, string[]>();
  const pending: [string, UvDependency, readonly Constraint[] | 'not_recorded', readonly string[]][] = [];
  for (const { table, name, version, source } of parsed) {
    const key = keyOf(name, version), root = source === 'editable' || source === 'virtual';
    if (builder.nodes.has(key)) return invalid();
    const check = version === null ? null : parsePypiVersion(version);
    if (check && !check.ok) builder.outside.push({ key, field: 'version', dependency: null, reason: check.reason });
    else if (!check && !root) builder.outside.push({ key, field: 'version', dependency: null, reason: 'version_outside_subset' });
    if (source !== 'registry' && !root) builder.outside.push({ key, field: 'source', dependency: null, reason: 'non_registry_source' });
    const dependencies = uvDependencies(table.dependencies), extras = uvGroups(table['optional-dependencies']), dev = uvGroups(table['dev-dependencies']);
    optional.set(key, new Map(extras));
    const entries = root ? rootEntries(table.metadata) : [];
    const member = root && isTomlTable(table.source) && typeof table.source[source!] === 'string' ? table.source[source!] as string : '.';
    const groupLabel = (group: string) => root && workspaces ? memberLabel(member, group) : group;
    for (const entry of entries) addDirect(direct, entry.name, uvDirect(groupLabel(entry.group ?? '?'), entry.extras, entry.spec, entry.marker));
    const specFor = (group: string, dependency: string): readonly Constraint[] | 'not_recorded' => {
      const matching = entries.filter(entry => entry.group === group && entry.name === dependency);
      return matching.length ? matching.map(entry => ({ spec: entry.spec, marker: entry.conditional || matching.length > 1 })) : 'not_recorded';
    };
    for (const dependency of dependencies) pending.push([key, dependency, root ? specFor('main', dependency.name) : 'not_recorded', root ? [groupLabel('main')] : []]);
    if (root) {
      for (const [group, list] of extras) for (const dependency of list) pending.push([key, dependency, specFor('extra:' + group, dependency.name), [groupLabel('extra:' + group)]]);
      for (const [group, list] of dev) for (const dependency of list) pending.push([key, dependency, specFor('dev:' + group, dependency.name), [groupLabel('dev:' + group)]]);
    }
    const all = [['', dependencies], ...extras.map(([group, list]) => ['extra:' + group, list]), ...dev.map(([group, list]) => ['dev:' + group, list])] as [string, UvDependency[]][];
    const { name: _n, version: _v, source: sourceTable, sdist, wheels, dependencies: _d, 'optional-dependencies': _o, 'dev-dependencies': _g, 'resolution-markers': markers, ...rest } = table;
    builder.node({ key, name, version: check?.ok ? version : null, versionId: uvVersionId(version), root, bundled: false, nonRegistry: source !== 'registry' && !root, digests: {
      flags: fingerprint([markers, all.map(([group, list]) => [group, list.map(item => item.markerText ?? null)])]),
      artifact: fingerprint([sourceTable, sdist, wheels]),
      declared_dependencies: fingerprint(all.map(([group, list]) => [group, list.map(item => item.declared)])),
      other: fingerprint(rest),
    } });
  }
  // uv records a virtual workspace root's groups in the lock manifest when it has no package entry.
  if (workspaces && manifest?.['dependency-groups'] !== undefined && !parsed.some(item => isTomlTable(item.table.source)
    && (item.table.source.editable === '.' || item.table.source.virtual === '.'))) {
    const entries = rootEntries({ 'requires-dev': manifest['dependency-groups'] });
    builder.node({ key: '.', name: '.', version: null, versionId: null, root: true, bundled: false, nonRegistry: false,
      digests: { flags: fingerprint(null), artifact: fingerprint(null), declared_dependencies: fingerprint(null), other: fingerprint(null) } });
    for (const entry of entries) {
      const group = entry.group!;
      addDirect(direct, entry.name, uvDirect(group, entry.extras, entry.spec, entry.marker));
      pending.push(['.', { name: entry.name, version: null, marker: entry.conditional, extras: entry.extras, declared: null, markerText: null },
        [{ spec: entry.spec, marker: entry.conditional || entries.filter(item => item.group === group && item.name === entry.name).length > 1 }], [group]]);
    }
  }
  const target = (dependency: UvDependency) => {
    const key = dependency.version === null ? dependency.name : keyOf(dependency.name, dependency.version);
    return builder.nodes.has(key) ? key : null;
  };
  const requested = new Set<string>();
  for (let index = 0; index < pending.length; index++) {
    const [from, dependency, constraints, groups] = pending[index]!;
    const to = target(dependency);
    builder.edge(from, { name: dependency.name, constraints, duplicate: false, marker: dependency.marker, to, extras: dependency.extras, groups });
    for (const extra of to === null ? [] : dependency.extras) {
      if (requested.has(to + '\0' + extra)) continue;
      requested.add(to + '\0' + extra);
      for (const item of optional.get(to!)?.get(extra) ?? []) pending.push([to!, item, 'not_recorded', []]);
    }
  }
  const resolution = declared({ overrides: manifest?.overrides, constraints: manifest?.constraints, metadata: manifest?.['dependency-metadata'] });
  const members = parsed.filter(item => isTomlTable(item.table.source) && (Object.hasOwn(item.table.source, 'editable') || Object.hasOwn(item.table.source, 'virtual')))
    .map(item => ({ name: item.name, source: item.table.source as TomlTable }));
  return { nodes: builder.nodes, edges: builder.edges, outside: builder.outside, direct, workspaces: false, overrides: resolution, cutoff: declaresCutoff(lock.options),
    uvWorkspace: { members, manifest } };
}

function loadGraph(ecosystem: Ecosystem, bytes: Uint8Array): Loaded<Graph, GraphReason> {
  const text = decode(bytes);
  if (!text.ok) return { ok: false, reason: text.reason === 'encoding' ? 'lockfile_encoding' : 'lockfile_size_limit' };
  try {
    return { ok: true, value: ecosystem === 'npm' ? npmGraph(text.value) : uvGraph(text.value) };
  } catch (error) {
    if (error instanceof Invalid) return { ok: false, reason: error.reason };
    if (error instanceof RangeError) return { ok: false, reason: 'lockfile_invalid' };
    throw error;
  }
}

function summary(graph: Graph): GraphSummary {
  const edges = [...graph.edges.values()].flat();
  const outside = [...graph.outside].sort((left, right) => compareText(left.key, right.key) || compareText(left.dependency ?? '', right.dependency ?? ''));
  const counts = new Map<string, OutsideCount>();
  for (const { field, reason } of outside) counts.set(field + ':' + reason, { field, reason, count: (counts.get(field + ':' + reason)?.count ?? 0) + 1 });
  return {
    instances: graph.nodes.size - (graph.uvWorkspace && graph.nodes.has('.') ? 1 : 0), edges: edges.length, unresolvedEdges: edges.filter(edge => edge.to === null).length,
    outside: outside.slice(0, dependencyLimits.outsideListed), outsideCount: outside.length,
    outsideByReason: [...counts].sort(([left], [right]) => compareText(left, right)).map(([, count]) => count),
  };
}

function changedRequirements(base: Manifest, head: Manifest): { readonly before: Requirements | undefined; readonly after: Requirements | undefined }[] {
  if (base.kind !== 'determined' || head.kind !== 'determined') return [];
  const keys = [...new Set([...base.requirements.keys(), ...head.requirements.keys()])].sort(compareText);
  const canonical = (entry: Requirements | undefined) => entry ? entry.declarations.map(item => item.canonical).join('\n') : null;
  return keys.flatMap(key => {
    const before = base.requirements.get(key), after = head.requirements.get(key);
    return canonical(before) === canonical(after) ? [] : [{ before, after }];
  });
}
const requirementChange = ({ before, after }: ReturnType<typeof changedRequirements>[number]): RequirementChange => {
  const { section, name } = (after ?? before)!;
  return { section, name, base: before?.declarations.map(item => item.view) ?? null, head: after?.declarations.map(item => item.view) ?? null };
};

const ref = (node: Node) => node.version === null ? node.name : `${node.name}@${node.version}`;
function explainer(graph: Graph, starts: readonly string[], touched: ReadonlySet<string>, mismatched: ReadonlySet<string>) {
  const search = (restricted: boolean) => {
    const parent = new Map<string, string | null>(starts.map(start => [start, null]));
    const queue = [...starts];
    for (let index = 0; index < queue.length; index++) {
      const current = queue[index]!;
      if (restricted && !touched.has(current)) continue;
      const next = [...new Set((graph.edges.get(current) ?? []).flatMap(edge => edge.to === null ? [] : [edge.to]))].sort(compareText);
      for (const key of next) if (!parent.has(key)) { parent.set(key, current); queue.push(key); }
    }
    return parent;
  };
  const restricted = search(true), reachable = search(false);
  return (key: string): Explanation => {
    if (restricted.has(key)) {
      const chain: string[] = [];
      for (let current: string | null = key; current !== null; current = restricted.get(current)!) chain.unshift(current);
      return chain.length > dependencyLimits.via ? { state: 'undetermined', reason: 'via_limit' }
        : chain.some(key => mismatched.has(key)) ? { state: 'undetermined', reason: 'manifest_lock_mismatch' }
        : { state: 'explained', via: chain.map(key => ref(graph.nodes.get(key)!)) };
    }
    return { state: 'unexplained', reason: reachable.has(key) ? 'reachable_only_via_unchanged' : 'not_reachable' };
  };
}

const identity = (node: Node) => node.versionId === null ? node.name : `${node.name}@${node.versionId}`;
const metadataFields: readonly MetadataField[] =['flags', 'artifact', 'declared_dependencies', 'other'];
type Raw = { kind: 'version_changed'; node: Node; from: string | null } | { kind: 'added'; node: Node } | Exclude<DependencyChange, { kind: 'version_changed' | 'added' }>;
function nodeChanges(base: Graph | null, head: Graph): Raw[] {
  const before = base?.nodes ?? new Map<string, Node>(), after = head.nodes;
  const keys = [...new Set([...before.keys(), ...after.keys()])].sort(compareText);
  const raw: Raw[] = [], added: Node[] = [], removed = new Map<string, Node[]>();
  for (const key of keys) {
    const left = before.get(key), right = after.get(key);
    if (left?.root || right?.root) continue;
    if (left && right) {
      if (left.versionId !== right.versionId) raw.push({ kind: 'version_changed', node: right, from: left.version });
      else {
        const fields = metadataFields.filter(field => left.digests[field] !== right.digests[field]);
        if (fields.length) raw.push({ kind: 'metadata_only', key, name: right.name, version: right.version, fields });
      }
    } else if (right) added.push(right);
    else if (left) removed.set(identity(left), [...removed.get(identity(left)) ?? [], left]);
  }
  for (const node of added) {
    const moved = node.version === null ? undefined : removed.get(identity(node))?.shift();
    raw.push(moved ? { kind: 'relocated', from: moved.key, to: node.key, name: node.name, version: node.version! } : { kind: 'added', node });
  }
  for (const node of [...removed.values()].flat()) raw.push({ kind: 'removed', key: node.key, name: node.name, version: node.version });
  return raw;
}

interface Side {
  readonly lockfile: Uint8Array | undefined; readonly manifest: Uint8Array | undefined; readonly settings: Uint8Array | undefined;
  readonly inputs: DependencyInputs; readonly directory: string;
}
const sha = (bytes: Uint8Array | undefined) => bytes ? hash(Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength)) : null;
const settingsName: Readonly<Record<Ecosystem, string>> = { npm: '.npmrc', uv: 'uv.toml' };

function workspacePath(value: unknown): value is string {
  if (value === '.') return true;
  try { return typeof value === 'string' && safeRelative(value) === value && !/[*?\[\]{}]/.test(value); } catch { return false; }
}
function workspacePatterns(value: TomlValue | undefined): string[] | null {
  const patterns = stringList(value);
  return patterns?.every(pattern => workspacePath(pattern.endsWith('/*') ? pattern.slice(0, -2) : pattern)) ? patterns : null;
}
const selectsMember = (patterns: readonly string[], member: string) => patterns.some(pattern => pattern.endsWith('/*')
  ? path.posix.dirname(member) === pattern.slice(0, -2) && member !== '.' : pattern === member);

function projectManifest(ecosystem: Ecosystem, side: Side, graph: Graph | null): { manifest: Manifest; sha256: string | null } {
  const single = { manifest: loadManifest(ecosystem, side.manifest, !!side.lockfile), sha256: sha(side.manifest) };
  if (ecosystem !== 'uv' || !graph?.uvWorkspace) return single;
  const { members, manifest: locked } = graph.uvWorkspace;
  const memberPath = (source: TomlTable) => source.editable ?? source.virtual;
  const lockWorkspace = Array.isArray(locked?.members) && locked.members.length > 0;
  if (!side.manifest) return lockWorkspace ? { manifest: { kind: 'undetermined', reason: 'workspaces_outside_subset' }, sha256: null } : single;
  const text = decode(side.manifest);
  if (!text.ok) return single;
  const parsed = parseToml(text.value);
  if (!parsed.ok) return single;
  const root = parsed.value, uv = isTomlTable(root.tool) && isTomlTable(root.tool.uv) ? root.tool.uv : {};
  if (uv.workspace === undefined && !lockWorkspace) return single;
  if (root.project === undefined && uv.workspace === undefined) return single;
  const sibling = (relative: string) => side.directory === '.' ? relative : side.directory + '/' + relative;
  const rootFile = sibling('pyproject.toml'), files = new Map<string, Uint8Array>([[rootFile, side.manifest]]);
  for (const { source } of members) {
    const member = memberPath(source);
    if (!workspacePath(member)) continue;
    const file = sibling(member === '.' ? 'pyproject.toml' : member + '/pyproject.toml'), bytes = side.inputs.get(file);
    if (bytes) files.set(file, bytes);
  }
  const sha256 = fingerprint([...files].sort(([left], [right]) => compareText(left, right)).map(([file, bytes]) => [file, sha(bytes)]));
  const outside = { manifest: { kind: 'undetermined', reason: 'workspaces_outside_subset' } as const, sha256 };
  if (uv.workspace !== undefined && !isTomlTable(uv.workspace)) return outside;
  const workspace = uv.workspace ?? {}, patterns = workspacePatterns(workspace.members), exclude = workspacePatterns(workspace.exclude);
  if (!patterns || !exclude) return outside;
  const paths = new Map<string, string>(), packageNames = new Set<string>();
  for (const { name, source } of members) {
    const member = memberPath(source);
    if (Object.keys(source).length !== 1 || !workspacePath(member) || paths.has(member) || packageNames.has(name)) return outside;
    if (member !== '.' && (uv.workspace === undefined || !selectsMember(patterns, member) || selectsMember(exclude, member))) return outside;
    paths.set(member, name);
    packageNames.add(name);
  }
  if (root.project !== undefined && !paths.has('.')) return outside;
  const names = locked === undefined ? (paths.has('.') ? [paths.get('.')!] : null) : stringList(locked.members);
  const normalized = names?.map(pypiName);
  if (!normalized || normalized.includes(null) || new Set(normalized).size !== normalized.length || normalized.length !== paths.size
    || normalized.some(name => !packageNames.has(name!))) return outside;
  for (const file of side.inputs.keys()) {
    if (!dependencyInputPath(file) || path.posix.basename(file) !== 'pyproject.toml') continue;
    const relative = path.posix.relative(side.directory, path.posix.dirname(file));
    if (relative && workspacePath(relative) && selectsMember(patterns, relative) && !selectsMember(exclude, relative) && !paths.has(relative)) return outside;
  }
  for (const member of paths.keys()) {
    if (!files.has(sibling(member === '.' ? 'pyproject.toml' : member + '/pyproject.toml'))) return outside;
  }
  const requirements = new Map<string, Requirements>(), direct = new Map<string, string[]>(), sources: [string, string][] = [];
  let rootManifest: Extract<Manifest, { kind: 'determined' }> | null = null;
  for (const [file, bytes] of [...files].sort(([left], [right]) => compareText(left, right))) {
    const member = file === rootFile ? '.' : path.posix.relative(side.directory, path.posix.dirname(file));
    const decoded = decode(bytes);
    if (!decoded.ok) return { manifest: { kind: 'undetermined', reason: decoded.reason === 'encoding' ? 'manifest_encoding' : 'manifest_size_limit' }, sha256 };
    const toml = parseToml(decoded.value);
    if (!toml.ok) return { manifest: { kind: 'undetermined', reason: toml.reason }, sha256 };
    const tool = toml.value.tool, settings = isTomlTable(tool) && isTomlTable(tool.uv) ? tool.uv : {};
    if (member !== '.' && settings.workspace !== undefined) return { ...outside, sha256 };
    const manifest = uvManifest(decoded.value, true, member === '.');
    if (manifest.kind === 'undetermined') return { manifest, sha256 };
    if (paths.has(member) && !(member === '.' && toml.value.project === undefined)
      && (!isTomlTable(toml.value.project) || pypiName(toml.value.project.name) !== paths.get(member))) return { ...outside, sha256 };
    if (member === '.') rootManifest = manifest;
    for (const entry of manifest.requirements.values()) for (const item of entry.declarations) {
      const group = memberLabel(member, entry.group);
      addRequirement(requirements, memberLabel(member, entry.section), group, entry.name, item);
    }
    for (const [name, comparables] of manifest.direct) for (const comparable of comparables) addDirect(direct, name, memberLabel(member, comparable));
    if (manifest.sources !== fingerprint(null)) sources.push([member, manifest.sources]);
  }
  return { manifest: { kind: 'determined', requirements, direct, overrides: rootManifest!.overrides,
    sources: sources.some(([member]) => member !== '.') ? fingerprint(sources) : rootManifest!.sources, cutoff: rootManifest!.cutoff }, sha256 };
}

interface Settings { readonly overrides: string; readonly cutoff: boolean; readonly readable: boolean }
function loadSettings(ecosystem: Ecosystem, bytes: Uint8Array | undefined): Settings {
  if (!bytes) return { overrides: fingerprint(null), cutoff: false, readable: true };
  const text = decode(bytes);
  if (!text.ok) return ecosystem === 'uv' ? { overrides: unreadableSettings, cutoff: true, readable: false } : { overrides: fingerprint(null), cutoff: true, readable: true };
  if (ecosystem === 'npm') return { overrides: fingerprint(null), cutoff: /^[ \t]*before[ \t]*=/m.test(text.value), readable: true };
  const toml = parseToml(text.value);
  return toml.ok ? { overrides: uvResolution(toml.value), cutoff: declaresCutoff(toml.value), readable: true } : { overrides: unreadableSettings, cutoff: true, readable: false };
}

function diffProject(lockfile: string, ecosystem: Ecosystem, sides: { base: Side; head: Side }): ProjectDiff {
  const settings = { base: loadSettings(ecosystem, sides.base.settings), head: loadSettings(ecosystem, sides.head.settings) };
  const graphs = {
    base: sides.base.lockfile ? loadGraph(ecosystem, sides.base.lockfile) : null,
    head: sides.head.lockfile ? loadGraph(ecosystem, sides.head.lockfile) : null,
  };
  const loadedManifests = {
    base: projectManifest(ecosystem, sides.base, graphs.base?.ok ? graphs.base.value : null),
    head: projectManifest(ecosystem, sides.head, graphs.head?.ok ? graphs.head.value : null),
  };
  const manifests = { base: loadedManifests.base.manifest, head: loadedManifests.head.manifest };
  const changed = changedRequirements(manifests.base, manifests.head), requirements = changed.map(requirementChange);
  const common = {
    lockfile, ecosystem,
    inputs: {
      base: { lockfileSha256: sha(sides.base.lockfile), manifestSha256: loadedManifests.base.sha256 },
      head: { lockfileSha256: sha(sides.head.lockfile), manifestSha256: loadedManifests.head.sha256 },
    },
    manifest: { base: manifests.base.kind === 'undetermined' ? manifests.base.reason : null, head: manifests.head.kind === 'undetermined' ? manifests.head.reason : null },
    graph: { base: graphs.base?.ok ? summary(graphs.base.value) : null, head: graphs.head?.ok ? summary(graphs.head.value) : null },
  };
  for (const side of ['base', 'head'] as const) {
    const graph = graphs[side];
    if (graph && !graph.ok) return { ...common, status: { kind: 'undetermined', side, reason: graph.reason }, requirements, changes: [] };
  }
  const base = graphs.base?.ok ? graphs.base.value : null;
  const head: Graph = graphs.head?.ok ? graphs.head.value
    : { nodes: new Map(), edges: new Map(), outside: [], direct: new Map(), workspaces: false, overrides: fingerprint(null), cutoff: false };
  const raw = nodeChanges(base, head);
  if (raw.length > dependencyLimits.changes || requirements.length > dependencyLimits.changes) return { ...common, status: { kind: 'change_limit' }, requirements: [], changes: [] };
  const touched = new Set(raw.flatMap(change => change.kind === 'version_changed' || change.kind === 'added' ? [change.node.key] : []));
  // Workspace packages are omitted from change rows but can carry a version change along an explanation path.
  if ((head.uvWorkspace?.members.length ?? 0) > 1 && Array.isArray(head.uvWorkspace?.manifest?.members)
    && head.uvWorkspace.manifest.members.length > 0) for (const node of head.nodes.values()) {
    if (node.root && (!base?.nodes.has(node.key) || base.nodes.get(node.key)!.versionId !== node.versionId)) touched.add(node.key);
  }
  const changedDeclarations = new Set(changed.flatMap(({ after }) => after ? [after.group + '\0' + after.name] : []));
  const starts = [...new Set([...head.nodes.values()].filter(node => node.root).flatMap(node => (head.edges.get(node.key) ?? [])
    .flatMap(edge => edge.to !== null && edge.groups.some(group => changedDeclarations.has(group + '\0' + edge.name)) ? [edge.to] : [])))].sort(compareText);
  const mismatched = new Set<string>();
  if (manifests.head.kind === 'determined') for (const from of head.nodes.values()) if (from.root) for (const edge of head.edges.get(from.key) ?? []) {
    if (edge.to === null) continue;
    const node = head.nodes.get(edge.to)!, version = node.version === null ? null : parseVersion(ecosystem, node.version);
    if (!sameDirect(manifests.head.direct.get(edge.name), head.direct.get(edge.name))
      || version && edge.constraints !== 'not_recorded' && edge.constraints.some(({ spec }) => spec.ok && !admitsVersion(spec.value, version))) mismatched.add(node.key);
  }
  const explain = explainer(head, starts, touched, mismatched);
  const undetermined = manifests.base.kind === 'undetermined' || manifests.head.kind === 'undetermined' || head.workspaces || !!base?.workspaces;
  const unreadable = !settings.base.readable || !settings.head.readable;
  const manifestOverrides = manifests.base.kind === 'determined' && manifests.head.kind === 'determined'
    && (manifests.base.overrides !== manifests.head.overrides || manifests.base.sources !== manifests.head.sources);
  const overridesChanged = manifestOverrides || (base?.overrides ?? fingerprint(null)) !== head.overrides || settings.base.overrides !== settings.head.overrides;
  const explanation = (key: string): Explanation => undetermined ? { state: 'undetermined', reason: 'manifest_undetermined' }
    : unreadable ? { state: 'undetermined', reason: 'settings_unreadable' }
    : overridesChanged ? { state: 'undetermined', reason: 'overrides_changed' } : explain(key);
  const changes = raw.map((change): DependencyChange => {
    if (change.kind === 'version_changed') return { kind: change.kind, key: change.node.key, name: change.node.name, from: change.from, to: change.node.version, explanation: explanation(change.node.key) };
    if (change.kind === 'added') return { kind: change.kind, key: change.node.key, name: change.node.name, version: change.node.version, explanation: explanation(change.node.key) };
    return change;
  });
  return { ...common, status: { kind: 'complete' }, requirements, changes };
}

export function diffDependencies(base: DependencyInputs, head: DependencyInputs): DependencyDiff {
  const lockfiles = new Map<string, Ecosystem>();
  for (const file of [...base.keys(), ...head.keys()]) {
    const ecosystem = lockfileEcosystem[path.posix.basename(file)];
    if (ecosystem && dependencyInputPath(file)) lockfiles.set(file, ecosystem);
  }
  const projects = [...lockfiles].sort(([left], [right]) => compareText(left, right)).map(([lockfile, ecosystem]) => {
    const directory = path.posix.dirname(lockfile), sibling = (name: string) => directory === '.' ? name : `${directory}/${name}`;
    const side = (inputs: DependencyInputs): Side =>
      ({ lockfile: inputs.get(lockfile), manifest: inputs.get(sibling(manifestName[ecosystem])), settings: inputs.get(sibling(settingsName[ecosystem])), inputs, directory });
    return diffProject(lockfile, ecosystem, { base: side(base), head: side(head) });
  });
  return { projects };
}

export interface UpgradeFinding {
  readonly lockfile: string;
  readonly name: string;
  readonly version: string;
  readonly advisories: readonly string[];
  readonly fixedVersions: readonly string[];
  readonly fixEvents: 'complete' | 'incomplete';
}
export type UpgradeState = 'allowed' | 'blocked' | 'undetermined';
export type UndeterminedUpgradeReason = 'ecosystem_not_supported' | 'project_undetermined' | 'package_not_in_lockfile' | 'non_registry_source'
  | 'version_outside_subset' | 'no_recorded_fix' | 'fix_events_incomplete' | 'overrides_declared' | 'manifest_lock_mismatch' | 'incoming_edges_incomplete'
  | 'duplicate_requirement' | 'conditional_requirement' | 'transitive_spec_not_recorded' | 'constraint_outside_subset' | 'cutoff_declared';
export type BlockedUpgradeReason = 'no_newer_fixed_version' | 'bundled_by_parent' | 'exact_pin' | 'range_excludes_fixed' | 'transitive_constraint';
export type UpgradeReason = UndeterminedUpgradeReason | BlockedUpgradeReason;
export interface UpgradeBlocker { readonly from: string; readonly kind: 'manifest_exact' | 'manifest_range' | 'transitive'; readonly spec: string }
export interface InstanceUpgrade {
  readonly key: string; readonly state: UpgradeState; readonly reason: UpgradeReason | null;
  readonly target: string | null; readonly blockers: readonly UpgradeBlocker[];
}
export interface UpgradeAssessment {
  readonly lockfile: string; readonly ecosystem: Ecosystem | null; readonly name: string; readonly version: string;
  readonly advisories: readonly string[]; readonly fixedVersions: readonly string[];
  readonly state: UpgradeState; readonly reason: UpgradeReason | null; readonly target: string | null;
  readonly instances: readonly InstanceUpgrade[];
}
export type HeadProjectReason = GraphReason | ManifestReason | 'lockfile_missing';
export interface HeadProject { readonly lockfile: string; readonly ecosystem: Ecosystem; readonly status: 'complete' | 'undetermined'; readonly reason: HeadProjectReason | null }
export interface UpgradeReport { readonly projects: readonly HeadProject[]; readonly upgrades: readonly UpgradeAssessment[] }

export const upgradeLimits = { blockers: 8 } as const;
const stateRank: Readonly<Record<UpgradeState, number>> = { allowed: 0, undetermined: 1, blocked: 2 };
const blockerRank: Readonly<Record<UpgradeBlocker['kind'], number>> = { manifest_exact: 0, manifest_range: 1, transitive: 2 };
const blockerReason: Readonly<Record<UpgradeBlocker['kind'], BlockedUpgradeReason>> = { manifest_exact: 'exact_pin', manifest_range: 'range_excludes_fixed', transitive: 'transitive_constraint' };

interface LoadedProject {
  readonly summary: HeadProject;
  readonly graph: Graph | null;
  readonly manifest: Manifest;
  readonly versionUnsupported: boolean;
  readonly overrides: boolean;
  readonly cutoff: boolean;
  readonly mismatched: ReadonlySet<string>;
  readonly unresolved: ReadonlySet<string>;
}

function loadHeadProject(lockfile: string, ecosystem: Ecosystem, head: DependencyInputs): LoadedProject {
  const directory = path.posix.dirname(lockfile), sibling = (name: string) => directory === '.' ? name : `${directory}/${name}`;
  const bytes = head.get(lockfile), loaded = bytes ? loadGraph(ecosystem, bytes) : null;
  const graph = loaded?.ok ? loaded.value : null;
  const { manifest } = projectManifest(ecosystem, { lockfile: bytes, manifest: head.get(sibling(manifestName[ecosystem])),
    settings: head.get(sibling(settingsName[ecosystem])), inputs: head, directory }, graph);
  const reason: HeadProjectReason | null = !loaded ? 'lockfile_missing' : !loaded.ok ? loaded.reason
    : manifest.kind === 'undetermined' ? manifest.reason : loaded.value.workspaces ? 'workspaces_outside_subset' : null;
  const settings = loadSettings(ecosystem, head.get(sibling(settingsName[ecosystem])));
  const mismatched = new Set<string>();
  if (graph && manifest.kind === 'determined') {
    for (const name of new Set([...manifest.direct.keys(), ...graph.direct.keys()])) if (!sameDirect(manifest.direct.get(name), graph.direct.get(name))) mismatched.add(name);
  }
  return {
    summary: { lockfile, ecosystem, status: reason === null ? 'complete' : 'undetermined', reason },
    graph, manifest, versionUnsupported: loaded?.ok === false && loaded.reason === 'lockfile_version_unsupported',
    overrides: [graph?.overrides, manifest.kind === 'determined' ? manifest.overrides : undefined, settings.overrides].some(value => value !== undefined && value !== fingerprint(null)),
    cutoff: settings.cutoff || !!graph?.cutoff || (manifest.kind === 'determined' && manifest.cutoff),
    mismatched, unresolved: new Set([...graph?.edges.values() ?? []].flat().filter(edge => edge.to === null).map(edge => edge.name)),
  };
}

const parseVersion = (ecosystem: Ecosystem, text: string): Version | null => {
  const parsed = ecosystem === 'npm' ? parseNpmVersion(text) : parsePypiVersion(text);
  return parsed.ok ? parsed.value : null;
};
const admitsVersion = admits as (spec: Spec, version: Version) => boolean;
type Verdict = 'admits' | 'excludes' | 'marker' | 'not_recorded' | 'outside' | 'duplicate';
interface Incoming { readonly from: Node; readonly edge: Edge }
interface Judged { readonly verdict: Verdict; readonly spec: Spec | null }
const constraintRank: Readonly<Record<'admits' | 'outside' | 'marker' | 'excludes', number>> = { admits: 0, outside: 1, marker: 2, excludes: 3 };
function verdict({ edge }: Incoming, version: Version): Judged {
  if (edge.duplicate) return { verdict: 'duplicate', spec: null };
  if (edge.constraints === 'not_recorded') return { verdict: 'not_recorded', spec: null };
  let worst: { readonly verdict: keyof typeof constraintRank; readonly spec: Spec | null } = { verdict: 'admits', spec: null };
  for (const { spec, marker } of edge.constraints) {
    const judged = !spec.ok ? 'outside' : marker || edge.marker ? 'marker' : admitsVersion(spec.value, version) ? 'admits' : 'excludes';
    if (constraintRank[judged] > constraintRank[worst.verdict]) worst = { verdict: judged, spec: spec.ok ? spec.value : null };
  }
  return worst;
}
const undeterminedOrder: readonly [Verdict, UndeterminedUpgradeReason][] = [
  ['duplicate', 'duplicate_requirement'], ['marker', 'conditional_requirement'], ['not_recorded', 'transitive_spec_not_recorded'], ['outside', 'constraint_outside_subset'],
];

function assessInstance(project: LoadedProject, graph: Graph, node: Node, finding: UpgradeFinding): InstanceUpgrade {
  const ecosystem = project.summary.ecosystem;
  const result = (state: UpgradeState, reason: UpgradeReason | null, target: string | null = null, blockers: readonly UpgradeBlocker[] = []): InstanceUpgrade =>
    ({ key: node.key, state, reason, target, blockers });
  if (node.nonRegistry) return result('undetermined', 'non_registry_source');
  const current = node.version === null ? null : parseVersion(ecosystem, node.version);
  const fixed = finding.fixedVersions.map(text => ({ text, version: parseVersion(ecosystem, text) }));
  if (!current || fixed.some(item => !item.version)) return result('undetermined', 'version_outside_subset');
  if (!fixed.length) return result('undetermined', 'no_recorded_fix');
  const candidates = fixed.filter(item => compareVersions(item.version!, current) > 0).sort((left, right) => compareVersions(left.version!, right.version!));
  if (!candidates.length) return finding.fixEvents === 'complete' ? result('blocked', 'no_newer_fixed_version') : result('undetermined', 'fix_events_incomplete');
  if (node.bundled) return result('blocked', 'bundled_by_parent');
  if (project.overrides) return result('undetermined', 'overrides_declared');
  if (project.mismatched.has(node.name) && (ecosystem === 'uv' || node.key === npmKey([node.name]))) return result('undetermined', 'manifest_lock_mismatch');
  const incoming: Incoming[] = [...graph.edges].flatMap(([from, list]) => list.filter(edge => edge.to === node.key).map(edge => ({ from: graph.nodes.get(from)!, edge })));
  if (!incoming.length || project.unresolved.has(node.name)) return result('undetermined', 'incoming_edges_incomplete');
  const evaluated = candidates.map(candidate => ({ candidate, verdicts: incoming.map(item => ({ item, judged: verdict(item, candidate.version!) })) }));
  const passing = evaluated.find(entry => entry.verdicts.every(item => item.judged.verdict === 'admits'));
  if (passing) return project.cutoff ? result('undetermined', 'cutoff_declared') : result('allowed', null, passing.candidate.text);
  if (evaluated.every(entry => entry.verdicts.some(item => item.judged.verdict === 'excludes'))) {
    const blockers = new Map<string, UpgradeBlocker>();
    for (const { item, judged } of evaluated.flatMap(entry => entry.verdicts.filter(item => item.judged.verdict === 'excludes'))) {
      const spec = judged.spec!;
      const blocker: UpgradeBlocker = { from: ref(item.from), kind: !item.from.root ? 'transitive' : isExactSpec(spec) ? 'manifest_exact' : 'manifest_range', spec: renderSpec(spec) };
      blockers.set(JSON.stringify(blocker), blocker);
    }
    const sorted = [...blockers.values()].sort((left, right) => blockerRank[left.kind] - blockerRank[right.kind] || compareText(left.from, right.from) || compareText(left.spec, right.spec));
    return result('blocked', blockerReason[sorted[0]!.kind], null, sorted.slice(0, upgradeLimits.blockers));
  }
  const open = new Set(evaluated.filter(entry => !entry.verdicts.some(item => item.judged.verdict === 'excludes')).flatMap(entry => entry.verdicts.map(item => item.judged.verdict)));
  return result('undetermined', undeterminedOrder.find(([kind]) => open.has(kind))?.[1] ?? 'constraint_outside_subset');
}

type FindingOutcome = { readonly state: 'undetermined'; readonly reason: UndeterminedUpgradeReason } | { readonly instances: readonly InstanceUpgrade[] };
function assessFinding(project: LoadedProject | undefined, finding: UpgradeFinding): FindingOutcome {
  if (!project || project.versionUnsupported) return { state: 'undetermined', reason: 'ecosystem_not_supported' };
  if (project.summary.status !== 'complete' || !project.graph) return { state: 'undetermined', reason: 'project_undetermined' };
  const npm = project.summary.ecosystem === 'npm', graph = project.graph, name = npm ? finding.name : pypiName(finding.name);
  const versionId = npm ? finding.version : uvVersionId(finding.version);
  const nodes = [...graph.nodes.values()].filter(node => !node.root && node.name === name && node.versionId === versionId).sort((left, right) => compareText(left.key, right.key));
  if (!nodes.length) return { state: 'undetermined', reason: 'package_not_in_lockfile' };
  return { instances: nodes.map(node => assessInstance(project, graph, node, finding)) };
}

export function assessUpgrades(head: DependencyInputs, findings: readonly UpgradeFinding[]): UpgradeReport {
  const projects = new Map<string, LoadedProject>();
  const project = (lockfile: string) => {
    const ecosystem = lockfileEcosystem[path.posix.basename(lockfile)];
    if (!ecosystem || !dependencyInputPath(lockfile)) return undefined;
    if (!projects.has(lockfile)) projects.set(lockfile, loadHeadProject(lockfile, ecosystem, head));
    return projects.get(lockfile);
  };
  for (const file of head.keys()) project(file);
  const upgrades = findings.map((finding): UpgradeAssessment => {
    const loaded = project(finding.lockfile), assessed = assessFinding(loaded, finding);
    const common = { lockfile: finding.lockfile, ecosystem: loaded?.summary.ecosystem ?? null, name: finding.name, version: finding.version,
      advisories: [...finding.advisories].sort(compareText), fixedVersions: [...finding.fixedVersions].sort(compareText) };
    if ('state' in assessed) return { ...common, state: assessed.state, reason: assessed.reason, target: null, instances: [] };
    const worst = assessed.instances.reduce((left, right) => stateRank[right.state] > stateRank[left.state] ? right : left);
    const targets = new Set(assessed.instances.map(item => item.target));
    return { ...common, state: worst.state, reason: worst.reason, target: worst.state === 'allowed' && targets.size === 1 ? worst.target : null, instances: assessed.instances };
  }).sort((left, right) => compareText(left.lockfile, right.lockfile) || compareText(left.name, right.name) || compareText(left.version, right.version)
    || compareText(left.advisories.join(','), right.advisories.join(',')));
  return { projects: [...projects.values()].map(item => item.summary).sort((left, right) => compareText(left.lockfile, right.lockfile)), upgrades };
}
