export const syntaxReasons = [
  'toml_outside_subset', 'toml_duplicate_key', 'toml_depth_limit', 'toml_token_limit', 'toml_string_limit',
  'version_outside_subset', 'prerelease_outside_subset', 'post_release_outside_subset', 'local_version_outside_subset', 'epoch_outside_subset',
  'range_outside_subset', 'dist_tag_outside_subset', 'non_registry_source', 'specifier_outside_subset', 'requirement_outside_subset',
  'name_outside_subset',
] as const;
export type SyntaxReason = typeof syntaxReasons[number];
export type Parsed<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly reason: SyntaxReason };
const pass = <T>(value: T): Parsed<T> => ({ ok: true, value });
const fail = (reason: SyntaxReason): { readonly ok: false; readonly reason: SyntaxReason } => ({ ok: false, reason });

export interface NpmVersion { readonly ecosystem: 'npm'; readonly release: readonly [number, number, number] }
export interface PypiVersion { readonly ecosystem: 'pypi'; readonly release: readonly number[] }
export type Version = NpmVersion | PypiVersion;

type Release = readonly number[];
function compareRelease(left: Release, right: Release): number {
  for (let index = 0; index < Math.max(left.length, right.length); index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference) return Math.sign(difference);
  }
  return 0;
}
const numeral = /^\d{1,15}$/;
const renderRelease = (release: Release) => release.join('.');

// Names

export function parseNpmName(text: string): Parsed<string> {
  return text.length <= 214 && /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9_~-][a-z0-9._~-]*$/i.test(text) ? pass(text) : fail('name_outside_subset');
}
export function parsePypiName(text: string): Parsed<string> {
  return text.length <= 214 && /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(text)
    ? pass(text.toLowerCase().replace(/[-_.]+/g, '-')) : fail('name_outside_subset');
}

// npm versions and ranges

export function parseNpmVersion(text: string): Parsed<NpmVersion> {
  const match = /^[v=]?(0|[1-9]\d{0,14})\.(0|[1-9]\d{0,14})\.(0|[1-9]\d{0,14})(.*)$/.exec(text.trim());
  if (!match) return fail('version_outside_subset');
  if (match[4]) return /^[-+][0-9A-Za-z.+-]+$/.test(match[4]) ? fail('prerelease_outside_subset') : fail('version_outside_subset');
  return pass({ ecosystem: 'npm', release: [Number(match[1]), Number(match[2]), Number(match[3])] });
}

type NpmOperator = '<' | '<=' | '>' | '>=' | '=';
export interface NpmComparator { readonly op: NpmOperator; readonly release: readonly [number, number, number] }
export interface NpmRange { readonly ecosystem: 'npm'; readonly sets: readonly (readonly NpmComparator[])[] }

type Partial = readonly number[];
const unsatisfiable: NpmComparator[] = [{ op: '<', release: [0, 0, 0] }];
const pad = (partial: Partial): [number, number, number] => [partial[0] ?? 0, partial[1] ?? 0, partial[2] ?? 0];
const bump = (partial: Partial, at: number): [number, number, number] => {
  const release = pad(partial.slice(0, at + 1));
  release[at]++;
  return release;
};
function upperOfPartial(partial: Partial): NpmComparator { return { op: '<', release: bump(partial, partial.length - 1) }; }

function parsePartial(text: string): Parsed<Partial> {
  const match = /^v?([0-9]+|[xX*])(?:\.([0-9]+|[xX*]))?(?:\.([0-9]+|[xX*]))?$/.exec(text);
  if (!match) return /^v?\d+\.\d+\.\d+[-+]/.test(text) ? fail('prerelease_outside_subset') : fail('range_outside_subset');
  const numbers: number[] = [];
  let wildcard = false;
  for (const part of match.slice(1)) {
    if (part === undefined || /^[xX*]$/.test(part)) { wildcard = true; continue; }
    if (wildcard || !numeral.test(part) || (part.length > 1 && part.startsWith('0'))) return fail('range_outside_subset');
    numbers.push(Number(part));
  }
  return pass(numbers);
}

function desugar(op: string, partial: Partial): NpmComparator[] {
  const count = partial.length;
  if (op === '' || op === '=') return count === 3 ? [{ op: '=', release: pad(partial) }] : count === 0 ? [] : [{ op: '>=', release: pad(partial) }, upperOfPartial(partial)];
  if (op === '>=') return count === 0 ? [] : [{ op: '>=', release: pad(partial) }];
  if (op === '>') return count === 0 ? unsatisfiable : count === 3 ? [{ op: '>', release: pad(partial) }] : [{ op: '>=', release: bump(partial, count - 1) }];
  if (op === '<') return count === 0 ? unsatisfiable : [{ op: '<', release: pad(partial) }];
  if (op === '<=') return count === 0 ? [] : count === 3 ? [{ op: '<=', release: pad(partial) }] : [upperOfPartial(partial)];
  if (op === '~') return count === 0 ? [] : [{ op: '>=', release: pad(partial) }, { op: '<', release: bump(partial, count === 1 ? 0 : 1) }];
  if (count === 0) return [];
  const significant = partial[0] !== 0 || count === 1 ? 0 : partial[1] !== 0 || count === 2 ? 1 : 2;
  return [{ op: '>=', release: pad(partial) }, { op: '<', release: bump(partial, significant) }];
}

export function parseNpmRange(text: string): Parsed<NpmRange> {
  const trimmed = text.trim();
  if (trimmed.length > 1024) return fail('range_outside_subset');
  if (/[/:]/.test(trimmed)) return fail('non_registry_source');
  if (/^[A-Za-z][A-Za-z0-9._-]*$/.test(trimmed) && !/^[xX]$/.test(trimmed)) return fail('dist_tag_outside_subset');
  const sets: NpmComparator[][] = [];
  for (const raw of trimmed.split('||')) {
    const part = raw.trim();
    const hyphen = /^(\S+)\s+-\s+(\S+)$/.exec(part);
    if (hyphen) {
      const low = parsePartial(hyphen[1]!), high = parsePartial(hyphen[2]!);
      if (!low.ok) return low;
      if (!high.ok) return high;
      sets.push([...desugar('>=', low.value), ...desugar('<=', high.value)]);
      continue;
    }
    const set: NpmComparator[] = [];
    for (const token of part.replace(/(<=|>=|<|>|=|\^|~)\s+/g, '$1').split(/\s+/).filter(Boolean)) {
      const match = /^(<=|>=|<|>|=|\^|~)?(.*)$/.exec(token)!;
      const partial = parsePartial(match[2]!);
      if (!partial.ok) return partial;
      set.push(...desugar(match[1] ?? '', partial.value));
    }
    sets.push(set);
  }
  return pass({ ecosystem: 'npm', sets });
}

function holds(op: NpmOperator | '==' | '!=', order: number): boolean {
  switch (op) {
    case '<': return order < 0;
    case '<=': return order <= 0;
    case '>': return order > 0;
    case '>=': return order >= 0;
    case '!=': return order !== 0;
    default: return order === 0;
  }
}

// PEP 440 and PEP 508

export function parsePypiVersion(text: string): Parsed<PypiVersion> {
  const value = text.trim().toLowerCase().replace(/^v/, '');
  if (value.length > 128) return fail('version_outside_subset');
  if (/^\d+!/.test(value)) return fail('epoch_outside_subset');
  const match = /^(\d+(?:\.\d+)*)(.*)$/.exec(value);
  if (!match) return fail('version_outside_subset');
  const rest = match[2]!;
  if (rest) {
    if (rest.includes('+')) return fail('local_version_outside_subset');
    if (/^[-_.]?(post|rev|r)\d*$|^-\d+$/.test(rest)) return fail('post_release_outside_subset');
    if (/^[-_.]?(a|b|c|rc|alpha|beta|pre|preview|dev)/.test(rest)) return fail('prerelease_outside_subset');
    return fail('version_outside_subset');
  }
  const parts = match[1]!.split('.');
  if (parts.length > 6 || !parts.every(part => numeral.test(part))) return fail('version_outside_subset');
  return pass({ ecosystem: 'pypi', release: parts.map(Number) });
}

type Pep440Operator = '==' | '!=' | '<' | '<=' | '>' | '>=' | '~=';
export interface Pep440Clause { readonly op: Pep440Operator; readonly release: readonly number[]; readonly prefix: boolean }
export interface Pep440Specifier { readonly ecosystem: 'pypi'; readonly clauses: readonly Pep440Clause[] }

export function parsePep440Specifier(text: string): Parsed<Pep440Specifier> {
  const trimmed = text.trim();
  if (trimmed.length > 1024) return fail('specifier_outside_subset');
  if (!trimmed) return pass({ ecosystem: 'pypi', clauses: [] });
  const clauses: Pep440Clause[] = [];
  for (const raw of trimmed.split(',')) {
    const match = /^(===|~=|==|!=|<=|>=|<|>)\s*(\S+)$/.exec(raw.trim());
    if (!match || match[1] === '===') return fail('specifier_outside_subset');
    const op = match[1] as Pep440Operator, prefix = match[2]!.endsWith('.*');
    if (prefix && op !== '==' && op !== '!=') return fail('specifier_outside_subset');
    const version = parsePypiVersion(prefix ? match[2]!.slice(0, -2) : match[2]!);
    if (!version.ok) return version;
    if (op === '~=' && version.value.release.length < 2) return fail('specifier_outside_subset');
    clauses.push({ op, release: version.value.release, prefix });
  }
  return pass({ ecosystem: 'pypi', clauses });
}

function admitsClause(clause: Pep440Clause, release: Release): boolean {
  if (clause.prefix) {
    const head = clause.release.map((_, index) => release[index] ?? 0);
    return holds(clause.op as '==' | '!=', compareRelease(head, clause.release));
  }
  if (clause.op === '~=') {
    const stem = clause.release.slice(0, -1);
    return compareRelease(release, clause.release) >= 0 && compareRelease(stem.map((_, index) => release[index] ?? 0), stem) === 0;
  }
  return holds(clause.op, compareRelease(release, clause.release));
}

export interface Requirement {
  readonly name: string;
  readonly extras: readonly string[];
  readonly specifier: Parsed<Pep440Specifier>;
  readonly marker: string | null;
}

const markerVariables = new Set(['python_version', 'python_full_version', 'os_name', 'sys_platform', 'platform_release', 'platform_system', 'platform_version',
  'platform_machine', 'platform_python_implementation', 'implementation_name', 'implementation_version', 'extra', 'extras', 'dependency_groups']);
type MarkerToken = { readonly kind: 'value' | 'op' | 'and' | 'or' | 'open' | 'close'; readonly text: string };
const markerDepth = 16;
// PEP 508 python_str_c plus the other quote character.
const markerString = /^[ \tA-Za-z0-9().{}\-_*#:;,/?[\]!~`@$%^&=+|<>'"]*$/;

function markerTokens(text: string): MarkerToken[] | null {
  const tokens: MarkerToken[] = [];
  for (let index = 0; index < text.length;) {
    const character = text[index]!, rest = text.slice(index);
    if (character === ' ' || character === '\t') { index++; continue; }
    if (character === '(' || character === ')') { tokens.push({ kind: character === '(' ? 'open' : 'close', text: character }); index++; continue; }
    if (character === '"' || character === "'") {
      const end = text.indexOf(character, index + 1);
      if (end < 0 || !markerString.test(text.slice(index + 1, end))) return null;
      tokens.push({ kind: 'value', text: text.slice(index, end + 1) });
      index = end + 1;
      continue;
    }
    const op = /^(?:===|==|!=|<=|>=|~=|<|>)/.exec(rest)?.[0];
    if (op) { tokens.push({ kind: 'op', text: op }); index += op.length; continue; }
    const word = /^[A-Za-z_][A-Za-z0-9_]*/.exec(rest)?.[0];
    if (!word) return null;
    index += word.length;
    if (word === 'and' || word === 'or') tokens.push({ kind: word, text: word });
    else if (word === 'in') tokens.push({ kind: 'op', text: 'in' });
    else if (word === 'not') {
      const tail = /^[ \t]+in(?![A-Za-z0-9_])/.exec(text.slice(index))?.[0];
      if (!tail) return null;
      index += tail.length;
      tokens.push({ kind: 'op', text: 'not in' });
    } else if (markerVariables.has(word)) tokens.push({ kind: 'value', text: word });
    else return null;
  }
  return tokens;
}

function markerGrammar(tokens: readonly MarkerToken[]): boolean {
  let position = 0, depth = 0;
  const at = (kind: MarkerToken['kind'], offset = 0) => tokens[position + offset]?.kind === kind;
  const atom = (): boolean => {
    if (at('open')) {
      if (++depth > markerDepth) return false;
      position++;
      if (!expression() || !at('close')) return false;
      position++;
      depth--;
      return true;
    }
    if (!at('value') || !at('op', 1) || !at('value', 2)) return false;
    position += 3;
    return true;
  };
  const sequence = (part: () => boolean, joiner: 'and' | 'or') => {
    if (!part()) return false;
    while (at(joiner)) { position++; if (!part()) return false; }
    return true;
  };
  const expression = (): boolean => sequence(() => sequence(atom, 'and'), 'or');
  return expression() && position === tokens.length;
}

export function parseMarker(text: string): Parsed<string> {
  const tokens = text.length > 4096 ? null : markerTokens(text);
  if (!tokens || !markerGrammar(tokens)) return fail('requirement_outside_subset');
  return pass(tokens.map((token, index) => (index && tokens[index - 1]!.kind !== 'open' && token.kind !== 'close' ? ' ' : '') + token.text).join(''));
}

export function parseRequirement(text: string): Parsed<Requirement> {
  if (text.length > 4096 || /[\x00-\x08\x0a-\x1f\x7f]/.test(text)) return fail('requirement_outside_subset');
  const separator = text.indexOf(';');
  const body = (separator < 0 ? text : text.slice(0, separator)).trim();
  const parsedMarker = separator < 0 ? null : parseMarker(text.slice(separator + 1));
  if (parsedMarker && !parsedMarker.ok) return parsedMarker;
  const marker = parsedMarker?.value ?? null;
  const match = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[([^\]]*)\])?\s*(.*)$/s.exec(body);
  if (!match) return fail('requirement_outside_subset');
  const name = parsePypiName(match[1]!);
  if (!name.ok) return fail('requirement_outside_subset');
  const extras = new Set<string>();
  for (const raw of (match[2] ?? '').split(',').map(part => part.trim()).filter(Boolean)) {
    const extra = parsePypiName(raw);
    if (!extra.ok) return fail('requirement_outside_subset');
    extras.add(extra.value);
  }
  let rest = match[3]!.trim();
  if (rest.startsWith('(') && rest.endsWith(')')) rest = rest.slice(1, -1);
  const specifier = rest.startsWith('@') ? fail('non_registry_source') : parsePep440Specifier(rest);
  return pass({ name: name.value, extras: [...extras].sort(), specifier, marker });
}

// Shared

export type Spec = NpmRange | Pep440Specifier;
export function admits(spec: NpmRange, version: NpmVersion): boolean;
export function admits(spec: Pep440Specifier, version: PypiVersion): boolean;
export function admits(spec: Spec, version: Version): boolean {
  if (spec.ecosystem === 'npm') return spec.sets.some(set => set.every(comparator => holds(comparator.op, compareRelease(version.release, comparator.release))));
  return spec.clauses.every(clause => admitsClause(clause, version.release));
}

export function compareVersions(left: Version, right: Version): number { return compareRelease(left.release, right.release); }
export function isExactSpec(spec: Spec): boolean {
  return spec.ecosystem === 'npm' ? spec.sets.length === 1 && spec.sets[0]!.length === 1 && spec.sets[0]![0]!.op === '='
    : spec.clauses.length === 1 && spec.clauses[0]!.op === '==' && !spec.clauses[0]!.prefix;
}

export function renderSpec(spec: Spec): string {
  if (spec.ecosystem === 'npm') {
    return spec.sets.map(set => set.length ? set.map(item => (item.op === '=' ? '' : item.op) + renderRelease(item.release)).join(' ') : '*').join(' || ');
  }
  return spec.clauses.map(clause => clause.op + renderRelease(clause.release) + (clause.prefix ? '.*' : '')).sort().join(',');
}

// TOML subset

export class TomlOpaque {
  readonly kind: 'float' | 'datetime';
  constructor(kind: 'float' | 'datetime') { this.kind = kind; }
}
export type TomlValue = string | number | boolean | TomlOpaque | readonly TomlValue[] | TomlTable;
export interface TomlTable { readonly [key: string]: TomlValue }
export const tomlLimits = { depth: 16, tokens: 200_000, stringChars: 65_536 } as const;
export function isTomlTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof TomlOpaque);
}

class Outside {
  readonly reason: SyntaxReason;
  constructor(reason: SyntaxReason) { this.reason = reason; }
}
type MutableTable = Record<string, TomlValue>;
type Frame =
  | { readonly kind: 'array'; readonly items: TomlValue[]; expect: 'value' | 'comma' }
  | { readonly kind: 'inline'; readonly table: MutableTable; expect: 'key' | 'value' | 'comma'; key: string[] };

const escapes: Readonly<Record<string, string>> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };

class TomlReader {
  private position = 0;
  private tokens = 0;
  private readonly root: MutableTable = Object.create(null);
  private readonly explicit = new WeakSet<object>();
  private readonly dotted = new WeakSet<object>();
  private readonly frozen = new WeakSet<object>();
  private readonly tableArrays = new WeakSet<object>();
  private readonly text: string;
  constructor(text: string) { this.text = text; }

  read(): TomlTable {
    let current = this.root;
    for (;;) {
      this.skipBlank(true);
      if (this.position >= this.text.length) return this.root;
      if (this.text[this.position] === '[') current = this.header();
      else {
        const key = this.key();
        this.expect('=');
        this.skipBlank(false);
        this.assign(current, key, this.value());
      }
      this.endOfLine();
    }
  }

  private outside(reason: SyntaxReason = 'toml_outside_subset'): never { throw new Outside(reason); }
  private count() { if (++this.tokens > tomlLimits.tokens) this.outside('toml_token_limit'); }
  private peek(offset = 0) { return this.text[this.position + offset]; }
  private newlineAt(): number {
    if (this.peek() === '\n') return 1;
    if (this.peek() === '\r') return this.peek(1) === '\n' ? 2 : this.outside();
    return 0;
  }
  private skipBlank(newlines: boolean) {
    for (;;) {
      const character = this.peek();
      if (character === ' ' || character === '\t') this.position++;
      else if (character === '#') {
        while (this.position < this.text.length && this.peek() !== '\n' && this.peek() !== '\r') {
          if (/[\x00-\x08\x0b-\x1f\x7f]/.test(this.peek()!)) this.outside();
          this.position++;
        }
      } else if (newlines && this.newlineAt()) this.position += this.newlineAt();
      else return;
    }
  }
  private endOfLine() {
    this.skipBlank(false);
    if (this.position >= this.text.length) return;
    const width = this.newlineAt();
    if (!width) this.outside();
    this.position += width;
  }
  private expect(character: string) {
    this.skipBlank(false);
    if (this.peek() !== character) this.outside();
    this.position++;
    this.count();
  }

  private key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipBlank(false);
      const character = this.peek();
      if (character === '"' || character === "'") {
        if (this.peek(1) === character && this.peek(2) === character) this.outside();
        parts.push(this.string());
      }
      else {
        const match = /^[A-Za-z0-9_-]+/.exec(this.text.slice(this.position, this.position + 256));
        if (!match) this.outside();
        parts.push(match[0]);
        this.position += match[0].length;
        this.count();
      }
      if (parts.length > tomlLimits.depth) this.outside('toml_depth_limit');
      this.skipBlank(false);
      if (this.peek() !== '.') return parts;
      this.position++;
    }
  }

  private header(): MutableTable {
    const array = this.peek(1) === '[';
    this.position += array ? 2 : 1;
    this.count();
    const key = this.key();
    this.skipBlank(false);
    if (this.text.slice(this.position, this.position + (array ? 2 : 1)) !== (array ? ']]' : ']')) this.outside();
    this.position += array ? 2 : 1;
    let table = this.root;
    for (const part of key.slice(0, -1)) {
      const existing = table[part];
      if (existing === undefined) table = this.child(table, part);
      else if (Array.isArray(existing) && this.tableArrays.has(existing)) table = existing.at(-1) as MutableTable;
      else if (isTomlTable(existing) && !this.frozen.has(existing)) table = existing as MutableTable;
      else this.outside('toml_duplicate_key');
    }
    const last = key.at(-1)!, existing = table[last];
    if (array) {
      const created: MutableTable = Object.create(null);
      if (existing === undefined) { const items = [created]; this.tableArrays.add(items); table[last] = items; }
      else if (Array.isArray(existing) && this.tableArrays.has(existing)) (existing as TomlValue[]).push(created);
      else this.outside('toml_duplicate_key');
      return created;
    }
    if (existing === undefined) { const created = this.child(table, last); this.explicit.add(created); return created; }
    if (isTomlTable(existing) && !this.explicit.has(existing) && !this.dotted.has(existing) && !this.frozen.has(existing)) {
      this.explicit.add(existing);
      return existing as MutableTable;
    }
    return this.outside('toml_duplicate_key');
  }
  private child(table: MutableTable, key: string): MutableTable {
    const created: MutableTable = Object.create(null);
    table[key] = created;
    return created;
  }
  private assign(table: MutableTable, key: readonly string[], value: TomlValue) {
    for (const part of key.slice(0, -1)) {
      const existing = table[part];
      if (existing === undefined) { table = this.child(table, part); this.dotted.add(table); }
      else if (isTomlTable(existing) && this.dotted.has(existing) && !this.frozen.has(existing)) table = existing as MutableTable;
      else this.outside('toml_duplicate_key');
    }
    if (Object.hasOwn(table, key.at(-1)!)) this.outside('toml_duplicate_key');
    table[key.at(-1)!] = value;
  }

  private value(): TomlValue {
    const stack: Frame[] = [];
    for (;;) {
      const frame = stack.at(-1);
      if (frame) this.skipBlank(frame.kind === 'array');
      let produced: TomlValue | undefined;
      const character = this.peek();
      if (frame?.kind === 'array' && character === ']') {
        this.position++; this.count(); stack.pop(); produced = frame.items;
      } else if (frame?.kind === 'inline' && character === '}' && (frame.expect === 'comma' || (frame.expect === 'key' && !Object.keys(frame.table).length))) {
        this.position++; this.count(); stack.pop(); this.frozen.add(frame.table); produced = frame.table;
      } else if (frame?.expect === 'comma') {
        if (character !== ',') this.outside();
        this.position++; this.count();
        frame.expect = frame.kind === 'array' ? 'value' : 'key';
        continue;
      } else if (frame?.kind === 'inline' && frame.expect === 'key') {
        frame.key = this.key();
        this.expect('=');
        this.skipBlank(false);
        frame.expect = 'value';
        continue;
      } else if (character === '[' || character === '{') {
        this.position++; this.count();
        if (stack.length >= tomlLimits.depth) this.outside('toml_depth_limit');
        stack.push(character === '[' ? { kind: 'array', items: [], expect: 'value' } : { kind: 'inline', table: Object.create(null), expect: 'key', key: [] });
        continue;
      } else produced = this.scalar();
      const parent = stack.at(-1);
      if (!parent) return produced;
      if (parent.kind === 'array') parent.items.push(produced);
      else this.assign(parent.table, parent.key, produced);
      parent.expect = 'comma';
    }
  }

  private scalar(): TomlValue {
    const character = this.peek();
    if (character === '"' || character === "'") return this.string();
    const run = /^[^\s,\]}#]+/.exec(this.text.slice(this.position, this.position + 128))?.[0];
    if (!run) return this.outside();
    this.position += run.length;
    this.count();
    if (run === 'true' || run === 'false') return run === 'true';
    if (/^[+-]?(0|[1-9](_?\d)*)$/.test(run)) {
      const number = Number(run.replaceAll('_', ''));
      return Number.isSafeInteger(number) ? number : this.outside();
    }
    if (/^[+-]?(inf|nan)$/.test(run) || /^[+-]?(0|[1-9](_?\d)*)(\.\d(_?\d)*)?([eE][+-]?\d(_?\d)*)?$/.test(run)) return new TomlOpaque('float');
    let date = run;
    const time = /^ \d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?/.exec(this.text.slice(this.position, this.position + 64));
    if (/^\d{4}-\d{2}-\d{2}$/.test(run) && time) { this.position += time[0].length; date += 'T' + time[0].slice(1); }
    if (/^\d{4}-\d{2}-\d{2}([Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})?)?$/.test(date) || /^\d{2}:\d{2}:\d{2}(\.\d+)?$/.test(date)) return new TomlOpaque('datetime');
    return this.outside();
  }

  private string(): string {
    const quote = this.peek()!;
    const multiline = this.peek(1) === quote && this.peek(2) === quote;
    this.position += multiline ? 3 : 1;
    this.count();
    if (multiline && this.newlineAt()) this.position += this.newlineAt();
    let result = '';
    for (;;) {
      if (result.length > tomlLimits.stringChars) this.outside('toml_string_limit');
      if (this.position >= this.text.length) this.outside();
      const character = this.peek()!;
      if (character === quote && (!multiline || (this.peek(1) === quote && this.peek(2) === quote))) {
        if (!multiline) { this.position++; return result; }
        let run = 3;
        while (this.peek(run) === quote) run++;
        if (run > 5) this.outside();
        this.position += run;
        return result + quote.repeat(run - 3);
      }
      const newline = this.newlineAt();
      if (newline) {
        if (!multiline) this.outside();
        result += '\n';
        this.position += newline;
      } else if (character === '\\' && quote === '"') {
        result += this.escape(multiline);
      } else {
        if (/[\x00-\x08\x0b-\x1f\x7f]/.test(character)) this.outside();
        result += character;
        this.position++;
      }
    }
  }
  private escape(multiline: boolean): string {
    const next = this.peek(1)!;
    if (escapes[next] !== undefined) { this.position += 2; return escapes[next]; }
    if (next === 'u' || next === 'U') {
      const width = next === 'u' ? 4 : 8, digits = this.text.slice(this.position + 2, this.position + 2 + width);
      const code = /^[0-9A-Fa-f]+$/.test(digits) && digits.length === width ? parseInt(digits, 16) : -1;
      if (code < 0 || code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) this.outside();
      this.position += 2 + width;
      return String.fromCodePoint(code);
    }
    if (multiline) {
      const trim = /^\\[ \t]*(\r?\n)[\s]*/.exec(this.text.slice(this.position, this.position + tomlLimits.stringChars));
      if (trim) { this.position += trim[0].length; return ''; }
    }
    return this.outside();
  }
}

export function parseToml(text: string): Parsed<TomlTable> {
  try {
    return pass(new TomlReader(text).read());
  } catch (error) {
    if (error instanceof Outside) return fail(error.reason);
    throw error;
  }
}
