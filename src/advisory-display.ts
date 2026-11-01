import { catalog, type Advisory } from './advisory-catalog.ts';
import type { AdvisoryDetails, Declaration } from './model.ts';
import { displayValue, parseReportLanguage, reportText, type ReportLanguage, type ReportText } from './report-language.ts';

const products: Record<string, string> = { php: 'PHP', node: 'Node.js', next: 'Next.js', nginx: 'NGINX', gitlab: 'GitLab', tomcat: 'Apache Tomcat' };
const states: Record<string, ReportText> = { matched: '影響版に一致（候補）', outside_recorded_ranges: '既知区間と不一致', unknown: '未確認' };
const reasons: Record<string, ReportText> = {
  exact_declaration: '完全版の宣言', invalid_version: '完全版を特定できません', ambiguous_declaration: '宣言が曖昧です', unsupported_docker_syntax: '未対応のDocker構文です',
  unsupported_image: '対応する公式イメージではありません', unsupported_image_variant: '未対応のイメージvariantです', dynamic_image: '固定の版タグではありません',
  npm_alias: '別名の依存は比較できません', npm_link: 'リンク依存は比較できません', npm_source: '依存の取得元は未対応です', npm_entry_ambiguous: '依存の項目を確定できません',
  affected_version: '記録した影響範囲に一致', outside_recorded_ranges: '記録した影響範囲に不一致（安全の保証ではありません）', comparison_domain_unknown: 'この通知で比較できる系列の外です', declaration_unknown: '宣言版を確定できません',
};
export const conditionLabels: Record<string, ReportText> = {
  web_sapi: 'Web SAPIと実配備版を確認（mod_phpの実証を他SAPIへ流用しない）', node_features: '公式通知にあるNode.js機能・設定と実際の利用を確認',
  cache_components_typed_arrays: 'App Router・Cache Components・複数TypedArray返却を確認', linux_glibc_image_optimizer: 'glibc Linux・画像最適化・実際のsharp/librsvg版を確認',
  app_router_server_actions: 'App RouterとServer Actionsの利用を確認', nginx_configuration: '公式通知ごとのNGINXモジュール・設定条件を確認', gitlab_regex: '正規表現処理と実配備版・修正適用を確認',
  ajp: 'AJPの利用・設定を確認', http2_async: 'HTTP/2と非同期処理を確認', jndi_realm: 'JNDIRealmの利用・設定を確認', tls13: 'TLS 1.3の利用・設定を確認', http2_trailers: 'HTTP/2 trailersの利用・設定を確認',
};
export function advisoryReason(value: string, inputLanguage: ReportLanguage = 'ja'): string {
  const language = parseReportLanguage(inputLanguage);
  const text = (value: ReportText) => reportText(language, value);
  return text(displayValue(reasons, value, "未解釈の理由"));
}
export function declarationPlace(value: Declaration, inputLanguage: ReportLanguage = 'ja'): string {
  const language = parseReportLanguage(inputLanguage);
  const text = (value: ReportText) => reportText(language, value);
 
  const safe = (input: string) => input && !/[\\:\x00-\x1f\x7f]/.test(input) && !input.startsWith('/') && input.split('/').every(part => part && part !== '.' && part !== '..');
  const file = safe(value.file) ? value.file : text("場所は非表示");
  const selector = value.selector && safe(value.selector) ? ` / ${value.selector}` : '';
  return file + (Number.isSafeInteger(value.line) && value.line! > 0 ? `:${value.line}` : '') + selector;
}
export function advisoryInfo(row: Advisory, inputLanguage: ReportLanguage = 'ja') {
  const language = parseReportLanguage(inputLanguage);
  const text = (value: ReportText) => reportText(language, value);
 
  const allowedSources = new Set(catalog.records.flatMap(row => row.sources));
  return { id: /^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/.test(row.id) ? row.id : text("通知未確認"),
    severity: ['Critical', 'High', 'Medium', 'Low', 'Important', 'Unverified'].includes(row.officialSeverity) ? row.officialSeverity : 'Unverified',
    conditions: row.conditions.map(value => text(displayValue(conditionLabels, value, "条件未確認"))), sources: row.sources.filter(value => allowedSources.has(value)),
    fixed: row.fixed.filter(value => /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)),
  };
}
export function advisoryView(details: AdvisoryDetails, inputLanguage: ReportLanguage = 'ja') {
  const language = parseReportLanguage(inputLanguage);
  const text = (value: ReportText) => reportText(language, value);
 
  return {
    confirmedAt: /^\d{4}-\d{2}-\d{2}$/.test(details.catalog.asOf) ? details.catalog.asOf : text("未記録"),
    hash: /^[a-f0-9]{64}$/.test(details.catalog.sha256) ? details.catalog.sha256 : text("未記録"),
    limitation: text("宣言版だけを照合しています。実稼働環境・配布元の修正・到達可能性・実悪用は未確認です。"),
    declarations: details.declarations.map(row => ({
      product: row.product ? displayValue(products, row.product, text("製品未確認")) : text("製品未確認"), version: row.version && /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(row.version) ? row.version : text("版未確認"),
      place: declarationPlace(row, language), edition: row.edition === 'ce' ? 'CE' : row.edition === 'ee' ? 'EE' : '', reason: advisoryReason(row.reason, language),
      assessments: row.assessments.map(assessment => ({ id: /^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)$/.test(assessment.id) ? assessment.id : text("通知未確認"), state: text(displayValue(states, assessment.state, "未確認")), reason: advisoryReason(assessment.reason, language) })),
    })),
    advisories: details.advisories.map(row => advisoryInfo(row, language)),
  };
}
export function advisoryText(details: AdvisoryDetails): string {
  const view = advisoryView(details);
  return [`緊急脆弱性の版宣言照合 — カタログ確認日 ${view.confirmedAt} / SHA-256 ${view.hash}`, view.limitation,
    ...view.declarations.flatMap(row => [`${row.product} ${row.version} ${row.edition} — ${row.place} — ${row.reason}`, ...row.assessments.map(item => `  ${item.id}: ${item.state} / ${item.reason}`)]),
    ...(!view.declarations.length ? ['版宣言なし・実環境は未確認'] : []),
    ...view.advisories.filter(row => view.declarations.some(declaration => declaration.assessments.some(item => item.id === row.id))).flatMap(row => [`${row.id} / 公式重要度 ${row.severity} / 修正版候補 ${row.fixed.join(', ')}`, ...row.conditions, ...row.sources]),
  ].join('\n') + '\n';
}
