import { SafeError } from '../safety.ts';
import { isTimestamp, toCveId, type CveId } from './syntax.ts';

export interface JvnItem { readonly identifier: string; readonly link: string; readonly modified: string; readonly cves: readonly CveId[] }
export interface JvnWindow { readonly modified: string | null; readonly items: readonly JvnItem[]; readonly oldest: string; readonly newest: string }
function drift(condition: unknown): asserts condition { if (!condition) throw new SafeError('intel_schema_drift'); }
const known = ['title', 'link', 'description', 'dc:identifier', 'dc:date', 'dcterms:issued', 'dcterms:modified'];
const entities: Readonly<Record<string, string>> = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
// The XML 1.0 Char production: tab, LF, CR and every other code point except surrogates, FFFE and FFFF.
const notXmlChar = /[^\t\n\r\x20-\uD7FF\uE000-\uFFFD\u{10000}-\u{10FFFF}]/u;
function decode(raw: string): string {
  return raw.replace(/&([^;&]{0,12});|&/g, (match, name: string | undefined) => {
    if (name === undefined) throw new SafeError('intel_schema_drift');
    if (Object.hasOwn(entities, name)) return entities[name];
    const code = /^#x([0-9a-fA-F]{1,6})$/.exec(name)?.[1] ?? /^#([0-9]{1,7})$/.exec(name)?.[1];
    const point = code === undefined ? NaN : Number.parseInt(code, name.startsWith('#x') ? 16 : 10);
    drift(Number.isSafeInteger(point) && point > 0 && point <= 0x10ffff);
    const character = String.fromCodePoint(point);
    drift(!notXmlChar.test(character));
    return character;
  });
}

interface Element { readonly name: string; readonly children: Element[]; text: string }
const qualified = '[A-Za-z_][\\w.-]*(?::[A-Za-z_][\\w.-]*)?';
// One grammar for both the start tag and the duplicate and entity checks on its attributes.
const attributePattern = `\\s+([A-Za-z_][\\w.:-]*)\\s*=\\s*(?:"([^"<]*)"|'([^'<]*)')`;
const startTag = new RegExp(`<(${qualified})((?:${attributePattern})*)\\s*(?<empty>/?)>`, 'y');
const attribute = new RegExp(attributePattern, 'g');
const endTag = new RegExp(`</(${qualified})\\s*>`, 'y');
const declaration = /^﻿?<\?xml\s[^<>?]*\?>/;
// The recent-update window holds about 20 items; a thousand bounds a broken or hostile body.
const maxItems = 1000;

function documentRoot(source: string): { root: Element; items: number } {
  drift(!notXmlChar.test(source));
  const top: Element = { name: '', children: [], text: '' }, stack = [top];
  let index = declaration.exec(source)?.[0].length ?? (source.startsWith('﻿') ? 1 : 0), items = 0;
  while (index < source.length) {
    const open = source.indexOf('<', index), text = source.slice(index, open < 0 ? source.length : open), parent = stack.at(-1)!;
    if (stack.length === 1) drift(!text.trim()); else parent.text += decode(text);
    if (open < 0) break;
    index = open;
    if (source.startsWith('<!--', index)) {
      const close = source.indexOf('-->', index + 4), body = source.slice(index + 4, close);
      drift(close >= 0 && !body.includes('--') && !body.endsWith('-')); index = close + 3; continue;
    }
    if (source.startsWith('<![CDATA[', index)) {
      const close = source.indexOf(']]>', index + 9);
      drift(stack.length > 1 && close >= 0); parent.text += source.slice(index + 9, close); index = close + 3; continue;
    }
    endTag.lastIndex = index;
    const end = endTag.exec(source);
    if (end) { drift(stack.length > 1 && parent.name === end[1]); stack.pop(); index = endTag.lastIndex; continue; }
    startTag.lastIndex = index;
    const start = startTag.exec(source);
    drift(start && (stack.length > 1 || !top.children.length));
    const names = [...start[2].matchAll(attribute)].map(([, name, double, single]) => { decode(double ?? single); return name; });
    drift(new Set(names).size === names.length);
    const element: Element = { name: start[1], children: [], text: '' };
    if (element.name === 'item') drift(++items <= maxItems);
    parent.children.push(element);
    if (!start.groups!.empty) stack.push(element);
    index = startTag.lastIndex;
  }
  drift(stack.length === 1 && top.children.length === 1 && top.children[0].name === 'rdf:RDF');
  return { root: top.children[0], items };
}
function fields(element: Element | undefined): Map<string, string> {
  const found = new Map<string, string>();
  for (const child of element?.children ?? []) {
    if (!known.includes(child.name)) continue;
    drift(!found.has(child.name) && !child.children.length);
    found.set(child.name, child.text.trim());
  }
  return found;
}
const time = (value: string | undefined): string | undefined => isTimestamp(value) ? value : undefined;
const cvePattern = /(?<![A-Za-z0-9_-])CVE-\d{4}-\d{4,}(?![A-Za-z0-9_-])/gi;

export function parseJvnRss(bytes: Buffer): JvnWindow {
  let source: string;
  try { source = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new SafeError('intel_schema_drift'); }
  const { root, items: total } = documentRoot(source);
  const blocks = root.children.filter(child => child.name === 'item');
  drift(blocks.length > 0 && blocks.length === total);
  const items = blocks.map(block => {
    const found = fields(block);
    const identifier = found.get('dc:identifier'), link = found.get('link'), title = found.get('title');
    const modified = time(found.get('dcterms:modified') ?? found.get('dc:date'));
    drift(identifier !== undefined && /^JVN[A-Z]*#[0-9A-Za-z-]{1,32}$/.test(identifier) && title !== undefined && modified !== undefined
      && link !== undefined && /^https:\/\/jvn\.jp\/[\x21-\x7e]{1,500}$/.test(link));
    const text = `${title}\n${found.get('description') ?? ''}`;
    const cves = [...new Set([...text.matchAll(cvePattern)].map(match => toCveId(match[0])).filter(id => id !== null))].sort();
    return { identifier, link, modified, cves };
  });
  const channel = fields(root.children.find(child => child.name === 'channel'));
  const sorted = items.map(item => item.modified).sort((left, right) => Date.parse(left) - Date.parse(right));
  return { modified: time(channel.get('dcterms:modified') ?? channel.get('dc:date')) ?? null, items, oldest: sorted[0], newest: sorted.at(-1)! };
}
