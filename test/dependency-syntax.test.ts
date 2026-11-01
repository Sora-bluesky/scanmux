import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  admits, isTomlTable, parseNpmRange, parseMarker, parseNpmVersion, parsePep440Specifier, parsePypiVersion, parseRequirement, parseToml, renderSpec,
  TomlOpaque, type NpmVersion, type PypiVersion, type SyntaxReason,
} from '../src/dependency-syntax.ts';

const npm = (text: string): NpmVersion => { const parsed = parseNpmVersion(text); assert.ok(parsed.ok, text); return parsed.value; };
const pypi = (text: string): PypiVersion => { const parsed = parsePypiVersion(text); assert.ok(parsed.ok, text); return parsed.value; };
const reason = (parsed: { ok: boolean; reason?: SyntaxReason }) => parsed.ok ? 'ok' : parsed.reason;

test('npm ranges in the subset desugar to canonical comparators and admit exactly their versions', () => {
  const rows: [string, string, string[], string[]][] = [
    ['^1.2.3', '>=1.2.3 <2.0.0', ['1.2.3', '1.9.9'], ['1.2.2', '2.0.0']],
    ['^0.2.3', '>=0.2.3 <0.3.0', ['0.2.9'], ['0.3.0', '0.2.2']],
    ['^0.0.3', '>=0.0.3 <0.0.4', ['0.0.3'], ['0.0.4']],
    ['^1.2', '>=1.2.0 <2.0.0', ['1.2.0'], ['1.1.9', '2.0.0']],
    ['^0.x', '>=0.0.0 <1.0.0', ['0.9.0'], ['1.0.0']],
    ['~1.2.3', '>=1.2.3 <1.3.0', ['1.2.9'], ['1.3.0']],
    ['~1', '>=1.0.0 <2.0.0', ['1.5.0'], ['2.0.0']],
    ['1.2.x', '>=1.2.0 <1.3.0', ['1.2.5'], ['1.3.0']],
    ['1', '>=1.0.0 <2.0.0', ['1.0.0'], ['0.9.9']],
    ['*', '*', ['0.0.0', '99.0.0'], []],
    ['', '*', ['3.1.4'], []],
    ['1.2.3 - 2.3', '>=1.2.3 <2.4.0', ['2.3.9'], ['2.4.0', '1.2.2']],
    ['1.2 - 2.3.4', '>=1.2.0 <=2.3.4', ['2.3.4'], ['2.3.5']],
    ['>=1.0.0 <2', '>=1.0.0 <2.0.0', ['1.9.0'], ['2.0.0']],
    ['> 1.2', '>=1.3.0', ['1.3.0'], ['1.2.9']],
    ['>1.2.3', '>1.2.3', ['1.2.4'], ['1.2.3']],
    ['<=1.2', '<1.3.0', ['1.2.9'], ['1.3.0']],
    ['=v1.2.3', '1.2.3', ['1.2.3'], ['1.2.4']],
    ['^0.34.3 || ^0.35.5', '>=0.34.3 <0.35.0 || >=0.35.5 <0.36.0', ['0.34.5', '0.35.5'], ['0.35.0', '0.36.0']],
  ];
  for (const [text, canonical, admitted, refused] of rows) {
    const range = parseNpmRange(text);
    assert.ok(range.ok, text);
    assert.equal(renderSpec(range.value), canonical, text);
    for (const version of admitted) assert.equal(admits(range.value, npm(version)), true, `${text} admits ${version}`);
    for (const version of refused) assert.equal(admits(range.value, npm(version)), false, `${text} refuses ${version}`);
  }
});

test('npm versions and ranges outside the subset return a closed reason instead of a guess', () => {
  const rows: [string, SyntaxReason][] = [
    ['^1.0.0-beta.1', 'prerelease_outside_subset'], ['^19.0.0-0', 'prerelease_outside_subset'], ['latest', 'dist_tag_outside_subset'], ['next', 'dist_tag_outside_subset'],
    ['npm:string-width@^4.2.0', 'non_registry_source'], ['file:../local', 'non_registry_source'], ['https://example.invalid/a.tgz', 'non_registry_source'],
    ['github:user/repo', 'non_registry_source'], ['user/repo', 'non_registry_source'], ['workspace:*', 'non_registry_source'],
    ['~>1.2', 'range_outside_subset'], ['1.x.3', 'range_outside_subset'], ['01.2.3', 'range_outside_subset'],
  ];
  for (const [text, expected] of rows) assert.equal(reason(parseNpmRange(text)), expected, text);
  assert.equal(reason(parseNpmVersion('1.2.3-rc.1')), 'prerelease_outside_subset');
  assert.equal(reason(parseNpmVersion('1.2.3+build')), 'prerelease_outside_subset');
  assert.equal(reason(parseNpmVersion('1.2')), 'version_outside_subset');
  assert.deepEqual(npm('v1.2.3').release, [1, 2, 3]);
});

test('PEP 440 specifiers in the subset admit by release with zero padding, prefix matching and compatible release', () => {
  const rows: [string, string, string[], string[]][] = [
    ['==1.2', '==1.2', ['1.2', '1.2.0'], ['1.2.1']],
    ['==1.2.*', '==1.2.*', ['1.2', '1.2.9'], ['1.3', '1.1.9']],
    ['!=1.5', '!=1.5', ['1.4', '1.5.1'], ['1.5.0']],
    ['!=1.5.*', '!=1.5.*', ['1.6'], ['1.5.3']],
    ['~=2.2', '~=2.2', ['2.2', '2.9'], ['3.0', '2.1']],
    ['~=1.4.5', '~=1.4.5', ['1.4.9'], ['1.5.0', '1.4.4']],
    ['>=1.0, <2', '<2,>=1.0', ['1.5'], ['2.0', '0.9']],
    ['>1,<=3', '<=3,>1', ['3.0.0'], ['1', '3.0.1']],
    ['', '', ['0.1'], []],
  ];
  for (const [text, canonical, admitted, refused] of rows) {
    const specifier = parsePep440Specifier(text);
    assert.ok(specifier.ok, text);
    assert.equal(renderSpec(specifier.value), canonical, text);
    for (const version of admitted) assert.equal(admits(specifier.value, pypi(version)), true, `${text} admits ${version}`);
    for (const version of refused) assert.equal(admits(specifier.value, pypi(version)), false, `${text} refuses ${version}`);
  }
});

test('PEP 440 versions and specifiers outside the subset return a closed reason', () => {
  const versions: [string, SyntaxReason][] = [
    ['1!2.0', 'epoch_outside_subset'], ['1.0rc1', 'prerelease_outside_subset'], ['1.0.dev3', 'prerelease_outside_subset'], ['1.0a1', 'prerelease_outside_subset'],
    ['2.9.0.post0', 'post_release_outside_subset'], ['1.0-1', 'post_release_outside_subset'], ['1.0+local', 'local_version_outside_subset'], ['1.2.3.4.5.6.7', 'version_outside_subset'],
  ];
  for (const [text, expected] of versions) assert.equal(reason(parsePypiVersion(text)), expected, text);
  assert.deepEqual(pypi('1.2.3.4.5.6').release, [1, 2, 3, 4, 5, 6]);
  const specifiers: [string, SyntaxReason][] = [
    ['===1.0', 'specifier_outside_subset'], ['>=1.*', 'specifier_outside_subset'], ['~=1', 'specifier_outside_subset'], ['>=1.0,', 'specifier_outside_subset'],
    ['>=1!1.0', 'epoch_outside_subset'], ['<2.0b1', 'prerelease_outside_subset'],
  ];
  for (const [text, expected] of specifiers) assert.equal(reason(parsePep440Specifier(text)), expected, text);
});

test('PEP 508 requirements carry normalized names, extras and an unevaluated marker; URL requirements are non-registry', () => {
  const full = parseRequirement('Requests[socks, Security] >=2.0 ; python_version < "3.13"');
  assert.ok(full.ok);
  assert.equal(full.value.name, 'requests');
  assert.deepEqual(full.value.extras, ['security', 'socks']);
  assert.ok(full.value.specifier.ok);
  assert.equal(renderSpec(full.value.specifier.value), '>=2.0');
  assert.equal(full.value.marker, 'python_version < "3.13"');
  const parenthesized = parseRequirement('Foo_Bar.baz (>=1.0)');
  assert.ok(parenthesized.ok && parenthesized.value.specifier.ok);
  assert.equal(parenthesized.value.name, 'foo-bar-baz');
  assert.equal(admits(parenthesized.value.specifier.value, pypi('1.0')), true);
  const url = parseRequirement('pkg @ https://example.invalid/pkg.whl');
  assert.ok(url.ok);
  assert.equal(url.value.name, 'pkg');
  assert.equal(reason(url.value.specifier), 'non_registry_source');
  const outside = parseRequirement('pkg >=1.0rc1');
  assert.ok(outside.ok);
  assert.equal(reason(outside.value.specifier), 'prerelease_outside_subset');
  for (const text of ['[x]', 'pkg; ', 'pkg ; os_name == "nt', 'pkg[bad name]']) assert.equal(reason(parseRequirement(text)), 'requirement_outside_subset', text);
});

test('TOML subset parses comments, tables, arrays of tables, keys, strings, integers, booleans, arrays and inline tables', () => {
  const text = [
    '# leading comment', 'version = 1 # trailing', 'big = 1_000', 'negative = -3', 'flag = true', 'ratio = 0.5', 'when = 1979-05-27 07:32:00Z', 'day = 1979-05-27',
    '"quoted key" = "basic \\"esc\\" \\t \\u00e9 \\U0001F600"', "literal = 'C:\\\\path\\n'", 'site."dotted.part" = "x"',
    'multi = """', 'one \\', '   two"""', "raw = '''", "first", "second''''", '',
    '[table]', 'list = [', '  1, # one', '  2,', ']', 'inline = { a = 1, b.c = "d" }', 'empty = []',
    '[[package]]', 'name = "a"', '[package.metadata]', 'note = "first"',
    '[[package]]', 'name = "b"', 'deps = [{ name = "a" }, { name = "c", extra = ["x"] }]',
  ].join('\r\n');
  const parsed = parseToml(text);
  assert.ok(parsed.ok, reason(parsed));
  const value = parsed.value;
  assert.equal(value.version, 1);
  assert.equal(value.big, 1000);
  assert.equal(value.negative, -3);
  assert.equal(value.flag, true);
  assert.ok(value.ratio instanceof TomlOpaque && value.ratio.kind === 'float');
  assert.ok(value.when instanceof TomlOpaque && value.when.kind === 'datetime');
  assert.ok(value.day instanceof TomlOpaque && value.day.kind === 'datetime');
  assert.equal(value['quoted key'], 'basic "esc" \t \u00e9 \u{1F600}');
  assert.equal(value.literal, 'C:\\\\path\\n');
  assert.ok(isTomlTable(value.site));
  assert.equal(value.site['dotted.part'], 'x');
  assert.equal(value.multi, 'one two');
  assert.equal(value.raw, "first\nsecond'");
  assert.ok(isTomlTable(value.table));
  assert.deepEqual(value.table.list, [1, 2]);
  assert.deepEqual(value.table.empty, []);
  assert.ok(isTomlTable(value.table.inline) && isTomlTable(value.table.inline.b));
  assert.equal(value.table.inline.b.c, 'd');
  assert.ok(Array.isArray(value.package) && value.package.length === 2);
  const [first, second] = value.package as unknown as Record<string, any>[];
  assert.equal(first!.name, 'a');
  assert.equal(first!.metadata.note, 'first');
  assert.deepEqual(second!.deps[1].extra, ['x']);
});

test('TOML outside the subset or over the limits returns a closed reason', () => {
  const deep = 'a = ' + '['.repeat(17) + ']'.repeat(17);
  const rows: [string, SyntaxReason][] = [
    ['a = 1\na = 2', 'toml_duplicate_key'], ['[a]\n[a]', 'toml_duplicate_key'], ['[a]\nb.c = 1\n[a.b]', 'toml_duplicate_key'],
    ['a = { b = 1 }\n[a.c]', 'toml_duplicate_key'], ['a = [1]\n[[a]]', 'toml_duplicate_key'],
    [deep, 'toml_depth_limit'], ['[' + Array.from({ length: 17 }, (_, index) => 'k' + index).join('.') + ']', 'toml_depth_limit'],
    ['a = [' + '1,'.repeat(200_001) + ']', 'toml_token_limit'], ['a = "' + 'x'.repeat(70_000) + '"', 'toml_string_limit'],
    ['a = "\\q"', 'toml_outside_subset'], ['a = 0x10', 'toml_outside_subset'], ['a = { b = 1,\n c = 2 }', 'toml_outside_subset'],
    ['a = { b = 1, }', 'toml_outside_subset'], ['a = "open', 'toml_outside_subset'], ['a = 1 b = 2', 'toml_outside_subset'], ['a = 99999999999999999999', 'toml_outside_subset'],
    ['a\r= 1', 'toml_outside_subset'], ['= 1', 'toml_outside_subset'],
  ];
  for (const [text, expected] of rows) assert.equal(reason(parseToml(text)), expected, text.slice(0, 40));
  assert.equal(reason(parseToml('a = ' + '['.repeat(16) + ']'.repeat(16))), 'ok');
});

test('TOML keys accept only single-line basic and literal strings', () => {
  for (const text of ['"""project""" = 1', "'''project''' = 1", '["""a"""]', 'a = { """b""" = 1 }']) assert.equal(reason(parseToml(text)), 'toml_outside_subset', text);
  for (const text of ['"" = 1', "'a b' = 1", '"a".b = 1']) assert.equal(reason(parseToml(text)), 'ok', text);
});

test('markers keep quoted values verbatim, normalize spacing between tokens, and must follow the marker grammar', () => {
  const marker = (text: string) => { const parsed = parseRequirement('foo>=1; ' + text); assert.ok(parsed.ok, text); return parsed.value.marker; };
  assert.equal(marker("platform_version == 'a  b'"), "platform_version == 'a  b'");
  assert.notEqual(marker("platform_version == 'a  b'"), marker("platform_version == 'a b'"));
  assert.equal(marker('os_name=="nt"   and (python_version<"3.13" or extra == "x")'), 'os_name == "nt" and (python_version < "3.13" or extra == "x")');
  assert.equal(marker("'linux' in sys_platform and platform_machine not  in 'x86_64 aarch64'"), "'linux' in sys_platform and platform_machine not in 'x86_64 aarch64'");
  for (const text of ['arbitrary text', 'os_name ==', 'unknown_var == "x"', '(os_name == "nt"', 'os_name == "nt")', 'os_name == "nt" and', 'os_name "nt"',
    'os_name == "nt" or or python_version > "3"', '"a" == "b" == "c"', '()']) {
    assert.equal(reason(parseRequirement('foo>=1; ' + text)), 'requirement_outside_subset', text);
  }
});

test('only dependency-graph.ts imports dependency-syntax.ts among shipped sources', async () => {
  const importers: string[] = [];
  for (const directory of ['src', 'internal']) {
    for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
      if (!entry.isFile() || !/\.(ts|mts|mjs|js|cjs)$/.test(entry.name)) continue;
      const file = path.join(entry.parentPath, entry.name);
      if (/\b(?:from|import|require)\s*\(?\s*['"][^'"]*dependency-syntax(?:\.ts)?['"]/.test(await readFile(file, 'utf8'))) importers.push(path.relative('.', file).replaceAll('\\', '/'));
    }
  }
  assert.deepEqual(importers, ['src/dependency-graph.ts']);
});

test('a marker quoted string allows only PEP 508 string characters; a newline or control character is outside the subset', () => {
  for (const text of ["os_name == 'a\nb'", "os_name == 'a\rb'", "os_name == 'a\u0001b'", "os_name == 'a\u007fb'", 'os_name == "a\nb"']) {
    assert.equal(reason(parseMarker(text)), 'requirement_outside_subset', JSON.stringify(text));
  }
  for (const text of ["os_name == 'a\tb'", 'platform_version == \'#1 SMP (x86_64) "y"\'', "os_name == 'a  b'"]) assert.equal(reason(parseMarker(text)), 'ok', JSON.stringify(text));
});

