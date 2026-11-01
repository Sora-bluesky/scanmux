import path from 'node:path';
import type { InputUnit, IaCKind, NonEmpty, TrivyPlan } from './model.ts';
import { safeRelative } from './safety.ts';

const containerFile = (name: string): boolean => /^(?:(?:Dockerfile|Containerfile)(?:\..+)?|.+\.(?:dockerfile|containerfile))$/i.test(path.posix.basename(name));
const candidateName = (name: string): boolean => /\.(?:ya?ml|json|template|tf|hcl)$/i.test(name) || containerFile(name);
// Compose files and CI pipelines are not read by the embedded config scanners, so they are not candidates.
const pipelineOrCompose = (name: string, text: string): boolean => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(name)
  || /^(?:\.gitlab-ci|azure-pipelines|bitbucket-pipelines|\.travis)\.ya?ml$/i.test(name) || /^\.circleci\/config\.ya?ml$/i.test(name)
  || (/^(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i.test(path.posix.basename(name)) && /(?:^|\n)services\s*:/.test(text));

/** Conservative candidates from accepted commit bytes, never from scanner output. */
export function inventoryTrivy(files: ReadonlyMap<string, Buffer>): TrivyPlan {
  const names = [...files.keys()].sort();
  names.forEach(safeRelative);
  const charts = names.filter(name => path.posix.basename(name) === 'Chart.yaml').map(name => path.posix.dirname(name)).sort((a, b) => b.length - a.length);
  const units = new Map<string, { kind: InputUnit['kind']; files: string[]; unresolved: boolean }>();
  const add = (kind: IaCKind | 'unresolved', root: string, file: string, unresolved = false) => {
    const key = `${kind}:${root}`;
    const unit = units.get(key) ?? { kind, files: [], unresolved: false };
    unit.files.push(file); unit.unresolved ||= unresolved; units.set(key, unit);
  };
  for (const name of names) {
    const candidate = candidateName(name);
    const content = files.get(name)!;
    let text: string;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(content); }
    catch { if (candidate) add('unresolved', name, name, true); continue; }
    const chart = charts.find(root => name.startsWith(root === '.' ? '' : root + '/'));
    if (chart !== undefined) {
      const relative = path.posix.relative(chart, name);
      if (/^templates\/.*\.ya?ml$/i.test(relative)) {
        add('helm', chart, name, /(?:trivy|tfsec|checkov).*ignore/i.test(text));
        continue;
      }
      // Only chart metadata and template helpers are consumed exclusively by Helm.
      // Other config candidates retain their ordinary inventory and missing-result checks.
      if (['Chart.yaml', 'values.yaml', 'values.schema.json'].includes(relative) || /^templates\/.*\.tpl$/i.test(relative)) {
        if (relative === 'Chart.yaml' && /(?:^|\n)\s*dependencies\s*:/.test(text) || /(?:trivy|tfsec|checkov).*ignore/i.test(text)) add('unresolved', name, name, true);
        continue;
      }
    }
    if (!candidate) continue;
    if (containerFile(name)) add('dockerfile', name, name, /(?:^|\n)\s*#\s*(?:trivy|tfsec|checkov).*ignore/i.test(text));
    else if (/\.(?:tf|tf\.json)$/i.test(name)) add('terraform', path.posix.dirname(name), name,
      /(?:\bmodule\s+|\bsource\s*=|(?:trivy|tfsec):ignore)/.test(text));
    else if (/\.hcl$/i.test(name)) add('unresolved', name, name, true);
    else if (/\.(?:ya?ml|json|template)$/i.test(name)) {
      if (/\b(?:apiVersion|kind)\s*[":]/.test(text)) add('kubernetes', name, name, /trivy.*ignore/i.test(text));
      else if (/\b(?:AWSTemplateFormatVersion|Resources|AWS::)\b/.test(text)) add('cloudformation', name, name, /(?:AWS::Include|AWS::Serverless|trivy.*ignore)/i.test(text));
      // Unknown YAML could be an unreadable config. JSON package metadata is not an IaC candidate.
      else if (/\.ya?ml$/i.test(name) && !pipelineOrCompose(name, text)) add('unresolved', name, name, true);
    }
  }
  for (const root of charts) if (!units.has(`helm:${root}`)) add('unresolved', root, root === '.' ? 'Chart.yaml' : root + '/Chart.yaml', true);
  return { schema: 'scanmux.trivy-plan/v1', profile: 'embedded-config-v1', inputs: [...units].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, unit]) =>
    ({ key, kind: unit.kind, files: unit.files as unknown as NonEmpty<string>, unresolved: unit.unresolved })) };
}
