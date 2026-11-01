import { createHash } from 'node:crypto';
import { advisoryInfo, advisoryView } from './advisory-display.ts';
import type { Report, Finding, Gate, AdvisoryDetails, EngineRun } from './model.ts';
import { comparisonSummary } from './comparison.ts';
import { aiTransportFailures, displayValue, parseReportLanguage, reportText, type ReportLanguage, type ReportText } from './report-language.ts';

const style = `:root{color-scheme:light;font-family:system-ui,-apple-system,"Yu Gothic",Meiryo,sans-serif;color:#172a3e;background:#edf1f5;font-size:15px;line-height:1.65}*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:32px auto;background:#fff;padding:48px}header{border-top:6px solid #234c73;padding-top:24px}h1{font-size:2rem;margin:8px 0}h2{font-size:1.35rem;border-bottom:2px solid #dce4ec;padding-bottom:8px;margin-top:36px}h3{font-size:1.05rem;margin:0 0 12px}p{margin:8px 0 14px}.eyebrow{font-size:.8rem;letter-spacing:.12em;color:#49627a;font-weight:700}.muted,small{color:#52667b}.verdict{border-left:6px solid #9c6d15;background:#fff8e8;padding:20px;margin:24px 0}.verdict.PASS{border-color:#28705c;background:#edf7f2}.verdict.FAIL,.verdict.ERROR{border-color:#a53535;background:#fff1f0}.verdict strong{display:block;font-size:1.4rem}.disclosure{border-left:6px solid #9c6d15;background:#fff8e8;padding:12px 20px;margin:16px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{background:#f3f6f9;border:1px solid #dde5ed;padding:14px}.metric b{display:block;font-size:1.55rem}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}th{text-align:left;background:#edf2f7;color:#29435d}th,td{padding:11px;border-bottom:1px solid #dfe6ed;vertical-align:top;overflow-wrap:anywhere}dl{display:grid;grid-template-columns:160px 1fr;gap:8px 18px}dt{font-weight:700;color:#49627a}dd{margin:0;overflow-wrap:anywhere}code,.mono{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.finding{border:1px solid #dce4ec;border-left:4px solid #526d89;padding:20px;margin:16px 0;break-inside:avoid}.badge{font-size:.8rem;font-weight:700;background:#edf2f7;padding:3px 8px;display:inline-block}.critical,.high{background:#fff0ee;color:#902b2b}.medium{background:#fff4dc;color:#805a0b}a{color:#245a88}nav{display:flex;flex-wrap:wrap;gap:8px 20px;border-block:1px solid #dce4ec;padding:14px 0;margin-top:24px}li{margin:6px 0}footer{border-top:1px solid #ccd7e2;margin-top:36px;padding-top:16px;font-size:.8rem;color:#52667b}.print-only{display:none}.target-group{border:1px solid #cddbe7;border-radius:8px;padding:22px;margin:20px 0;break-inside:auto}.target-group h3{font-size:1.25rem;margin-bottom:6px}.target-meta{display:flex;flex-wrap:wrap;gap:8px 18px;color:#49627a;font-size:.9rem}.target-action{margin:12px 0}.target-group details{border-top:1px solid #dce4ec;margin-top:16px;padding-top:12px}summary{cursor:pointer;font-weight:700;color:#234c73}summary:focus-visible{outline:3px solid #477eac;outline-offset:4px}.individual{padding:16px 0;border-bottom:1px solid #e1e8ee;break-inside:avoid}.individual h4{margin:0 0 8px;font-size:1rem}.individual dl{font-size:.9rem;grid-template-columns:130px 1fr}.individual p{overflow-wrap:anywhere}.catalog-declaration{margin:16px 0;padding:14px;background:#f5f8fb}.catalog-declaration h3{overflow-wrap:anywhere}.catalog-declaration li{overflow-wrap:anywhere}.advisory-source{font-size:.8rem;color:#52667b;overflow-wrap:anywhere}@media(max-width:600px){main{margin:0;padding:22px 16px}h1{font-size:1.6rem}.grid{grid-template-columns:1fr}dl{grid-template-columns:1fr;gap:2px}dd{margin-bottom:10px}th,td{padding:8px}.finding{padding:14px}.target-group{padding:15px}.individual dl{grid-template-columns:1fr}}@page{size:A4;margin:16mm}@media print{.screen-only{display:none!important}.print-only{display:block!important}.target-group{padding:14px;margin:14px 0}.individual{break-inside:auto}:root{background:#fff;font-size:10pt}main{max-width:none;margin:0;padding:0}nav{display:none}h2{break-after:avoid}table{font-size:9pt}thead{display:table-header-group}.table-wrap{overflow:visible}.grid{grid-template-columns:repeat(3,1fr)}a{color:inherit;text-decoration:none}.finding{break-inside:auto}footer{break-inside:avoid}}`;
export const reportCsp = `default-src 'none'; script-src 'none'; style-src 'sha256-${createHash('sha256').update(style).digest('base64')}'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
const gates: Record<Gate, [ReportText, ReportText]> = {
  PASS: ['設定された判定条件を満たしました', '今回の検査範囲と判定条件における結果です。脆弱性の不存在や稼働環境の安全を保証するものではありません。'],
  FAIL: ['対応が必要な指摘があります', '判定を阻害する指摘が検出されました。根拠と適用条件を確認し、修正後に同じ範囲を再検査してください。'],
  REVIEW: ['人による確認が必要です', '自動検査だけでは結論が確定していません。指摘の根拠と実際の利用状況を確認してください。'],
  INCOMPLETE: ['必要な検査が完了していません', '未実施・未対応・除外された範囲があります。指摘が0件でも、安全と判断できる結果ではありません。'],
  ERROR: ['検査または整合性の確認に失敗しました', '結果の利用に制限があります。失敗した処理を解消し、必要な検査を再実行してください。'],
};
const labels: Record<string, ReportText> = {
  trivy: '設定不備検査（Trivy）', misconfiguration: '設定不備の候補', parse_failed: '構文解析失敗', excluded: '除外', unresolved: '未解決',
  'runtime-advisories': '緊急脆弱性の版宣言照合', runtime: '版宣言の脆弱性候補', gitleaks: '秘密情報検査（Gitleaks）', osv: '依存関係検査（OSV）', 'codex-security': 'AIコード検査（Codex Security）',
  completed: '完了', failed: '失敗', cancelled: '中断', budget_exceeded: '予算超過', not_started: '未実施',
  analyzed: '対象範囲を検査', unsupported: '未対応', skipped: '未検査', partial: '一部のみ検査',
  critical: '緊急', high: '高', medium: '中', low: '低', informational: '参考', unknown: '不明',
  candidate: '検出候補', source_supported: 'ソースの根拠あり', runtime_reproduced: '実行時の再現あり',
  secret: '秘密情報の検出候補', dependency: '依存パッケージの脆弱性候補', code: 'コードの問題候補',
};
const reasons: Record<string, ReportText> = {
  no_recognized_config: '認識できる設定入力がありません。',
  offline_scope_unavailable: 'オフライン検査の範囲を成立させられません。',
  process_appcontainer_unsupported_platform: 'Trivyの制限実行はWindowsだけに対応します。',
  process_appcontainer_owner_unavailable: 'Trivyの制限実行に必要な所有者を利用できません。',
  process_appcontainer_owner_version_unsupported: 'Trivyの制限実行に必要な所有者の版に対応していません。',
  process_owner_appcontainer_unavailable: 'TrivyのAppContainerを利用できません。',
  process_owner_appcontainer_elevated_owner: '所有者が昇格しているため、TrivyのAppContainerを起動できません。',
  process_owner_appcontainer_profile_unavailable: 'TrivyのAppContainerプロファイルAPIを利用できません。',
  process_owner_appcontainer_profile_failed: 'TrivyのAppContainerプロファイルの作成に失敗しました。',
  process_owner_appcontainer_owner_token_invalid: 'TrivyのAppContainer所有者のトークンを確認できません。',
  process_owner_appcontainer_roots_invalid: 'TrivyのAppContainerの対象ディレクトリが要件を満たしていません。',
  process_owner_appcontainer_hardlink_present: 'TrivyのAppContainerに渡すディレクトリにハードリンクのファイルがあるため、起動しませんでした。',
  process_owner_appcontainer_journal_failed: 'TrivyのAppContainerの記録を書けないため、起動しませんでした。',
  process_owner_appcontainer_grant_failed: 'TrivyのAppContainerへのアクセス権付与に失敗しました。',
  process_owner_appcontainer_create_failed: 'TrivyのAppContainerプロセスの作成または属性の設定に失敗しました。',
  process_owner_appcontainer_token_mismatch: 'TrivyのAppContainer子プロセスのトークンが要件を満たしていません。',
  process_owner_appcontainer_setup_failed: 'TrivyのAppContainerの準備中に予期しないエラーが発生しました。',
  process_owner_appcontainer_cleanup_failed: 'TrivyのAppContainerの後始末に失敗しました。',
  trivy_input_result_missing: '計画した設定入力に検査結果がありません。',
  trivy_target_ambiguous: 'Trivyの結果が計画した複数の入力に当てはまり、どれの結果か決められません。',
  trivy_target_not_planned:'Trivyが計画に無いファイルの結果を返しました。その結果は報告に含めていません。',
  trivy_input_unresolved: '計画した設定入力に未解決事項があります。',
  trivy_reported_parse_error: '設定入力の構文解析に失敗しました。',
  trivy_empty_result_receipt: '設定入力の完了を確認する規則の記録がありません。',
  trivy_checks_excluded: '設定不備の検査規則が除外されました。',
  trivy_scanner_diagnostics: 'Trivyの診断に未解決の警告または失敗があります。',
  runtime_environment_unverified: '実稼働環境は未確認です。', vendor_patches_unverified: '配布元の修正適用は未確認です。', no_runtime_declarations: '版宣言なし・実環境は未確認です。', advisory_input_invalid: '版宣言の入力形式を読み取れません。', advisory_plan_mismatch: 'カタログまたは形式が変わったため再計画が必要です。', blocking_finding: '判定を阻害する指摘があります。', finding_requires_review: '人による確認が必要な指摘があります。',
  snapshot_entries_excluded: '検査対象から除外されたファイルがあります。', missing_required_engines: '必要な検査の実行記録がありません。',
  ai_isolation_unverified: 'AI検査の隔離と認証分離が未検証のため実施していません。', isolation_unverified: '実行隔離が未検証です。',
  offline_database_not_configured: 'オフライン脆弱性データベースが設定されていません。', offline_database_unavailable: 'オフライン脆弱性データベースを利用できません。',
  no_dependency_inputs: '対応する依存関係入力がありません。', empty_snapshot: '検査可能なファイルがありません。',
  dirty_worktree_unsupported: '未コミットの変更を含む対象は未対応です。', cancelled: '処理を中断しました。',
  timeout: '処理が制限時間を超えました。', output_limit: '出力量が上限を超えました。', termination_unverified: '処理の終了を確認できません。',
  snapshot_integrity: '検査対象の整合性を確認できません。', plan_integrity: '検査計画の整合性を確認できません。',
  binary: 'バイナリファイル', symlink: 'シンボリックリンク', submodule: 'サブモジュール', lfs_pointer: 'Git LFS参照',
  binary_content_unsupported: '未対応のバイナリファイル', symlink_or_submodule: 'シンボリックリンクまたはサブモジュール',
  gitleaks_default_exclusions: 'Gitleaks標準の除外規則',
  ai_synthetic_evidence: '合成通信による実装試験です。実サービスの検査完了や実効Blueの証拠には使えません。',
  ai_effective_program_unverified: '実効プログラムを確認できず、AI検査の成果を受け入れていません。',
  ai_scope_incomplete: 'AI検査の対象範囲に未確認事項があります。', ai_scope_exclusions: 'AI検査に除外があります。',
  ai_scope_deferred: 'AI検査に保留した対象があります。', ai_scope_open_questions: 'AI検査に未解決の確認事項があります。', ai_scope_limitations: 'AI検査に制限事項があります。',
  ai_source_secret_scan_missing: 'AI送信に必要なソースの秘密検査が成立していません。', ai_plan_not_accepted: '現在のAI検査計画が明示的に受諾されていません。',
  ai_usage_records_incomplete: 'AI使用量の保存記録をすべて照合できません。取得できた値だけを部分観測として残しています。',
  ai_closure_termination_unverified: 'AI実行経路の終了を確認できず、作業領域を保持しています。',
  runner_auth_unverified: 'AI実行環境の認証分離が未検証です。', daybreak_effective_unknown: 'Daybreakの実効適用を確認できていません。',
  tool_not_configured: '必要な検査ツールが設定されていません。', unsupported_tool_version: '未対応の検査ツール版です。',
  no_supported_lockfile: '対応する依存関係ファイルがありません。', cancelled_before_start: '開始前に中断しました。',
  builtin_rules_exclude_paths: '標準ルールで除外されたパスがあります。', dependency_sources_not_reported: '一部の依存関係入力に検査記録がありません。',
  offline_package_matching_incomplete: 'オフラインのパッケージ照合が不完全です。', no_dependency_coverage_receipt: '依存関係の検査範囲を確認できません。',
  scanner_exit_failure: '検査ツールが異常終了しました。', scanner_json_missing: '検査結果が出力されませんでした。', scanner_json_invalid: '検査結果の形式が不正です。',
  exit_report_disagreement: '終了状態と検査結果が一致しません。', tool_digest_mismatch: '検査ツールのハッシュが設定値と一致しません。',
};
const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
export interface FindingGroup { items: { value: Finding; index: number }[]; knownSeverity: string | null; unknownCount: number; places: number }
export function groupFindings(findings: Finding[]): FindingGroup[] {
  const groups = new Map<string, FindingGroup>();
  findings.forEach((value, index) => {
    const key = JSON.stringify(value.package ? [value.engine, value.category, value.package.ecosystem, value.package.name, value.package.version] : [value.engine, value.category, value.file]);
    let group = groups.get(key);
    if (!group) { group = { items: [], knownSeverity: null, unknownCount: 0, places: 0 }; groups.set(key, group); }
    group.items.push({ value, index });
  });
  for (const group of groups.values()) {
    group.knownSeverity = severityOrder.find(severity => group.items.some(({ value }) => value.severity === severity)) ?? null;
    group.unknownCount = group.items.filter(({ value }) => !severityOrder.includes(value.severity)).length;
    group.places = new Set(group.items.map(({ value }) => JSON.stringify(value.engine === 'trivy' ? [value.file, value.line, value.endLine] : [value.file, value.line]))).size;
  }
  const rank = (value: FindingGroup) => value.knownSeverity ? severityOrder.indexOf(value.knownSeverity) : severityOrder.length;
  return [...groups.values()].sort((a, b) => rank(a) - rank(b) || a.items[0].index - b.items[0].index);
}
function createRenderer(language: ReportLanguage) {
  const text = (value: ReportText) => reportText(language, value);
function e(value: string | number): string { return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!); }
function label(value: string): string { return text(displayValue(labels, value, "未確認")); }
function reason(value: string): string {
  if (Object.hasOwn(reasons, value)) return text(reasons[value]);
  for (const engine of ['gitleaks', 'osv', 'codex-security', 'runtime-advisories', 'trivy']) {
    if (value === `required_${engine}_incomplete`) return `${label(engine)}${text("が完了していません。")}`;
    if (value === `${engine}_execution_failed`) return `${label(engine)}${text("の実行に失敗しました。")}`;
  }
  return text("自動説明に未対応の理由があります。非公開のJSON記録で確認してください。");
}
function relative(value: string | null): string {
  if (value === null) return text("場所は不明です");
  return value && !/[\\:\x00-\x1f\x7f]/.test(value) && !value.startsWith('/') && value.split('/').every(part => part && part !== '.' && part !== '..') ? value : text("場所は非表示");
}
function identifier(value: string): string { return /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|[a-z][a-z0-9-]{0,100})$/i.test(value) ? value : text("識別子は非表示"); }
function version(value: string): string { return /^[a-z0-9][a-z0-9.+_~^<>=| -]{0,120}$/i.test(value) ? value : text("版の表記は非表示"); }
function hash(value: string | null): string { return value && /^[a-f0-9]{40,64}$/.test(value) ? value : text("未記録"); }
function time(value: string): string { const date = new Date(value); return Number.isFinite(date.valueOf()) ? date.toISOString() : text("未記録"); }
function list(values: string[]): string { return values.length ? `<ul>${values.map(value => `<li>${e(value)}</li>`).join('')}</ul>` : `<p class="muted">${text("記録なし")}</p>`; }
function details(rows: [string, string | number][]): string { return `<dl>${rows.map(([key, value]) => `<dt>${e(key)}</dt><dd>${e(value)}</dd>`).join('')}</dl>`; }
function packageName(value: Finding): string {
  return value.package && /^@?[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*$/i.test(value.package.name) ? value.package.name : text("対象名は非表示");
}
function individual(value: Finding, index: number, mode: 'screen' | 'print'): string {
  const info = value.advisory ? advisoryInfo(value.advisory, language) : null;
  const start = Number.isSafeInteger(value.line) && value.line! > 0 ? value.line! : null;
  const end = value.engine === 'trivy' && start !== null && Number.isSafeInteger(value.endLine) && value.endLine! >= start ? value.endLine : null;
  return `<article class="individual" id="${mode}-finding-${index + 1}"><h4>${index + 1}. ${e(value.originIds.map(identifier).join(' / ') || text("識別子未記録"))}</h4><p><span class="badge ${Object.hasOwn(labels, value.severity) ? e(value.severity) : ''}${text("\">重要度：")}${e(label(value.severity))}</span> <span class="badge">${e(label(value.evidenceState))}</span></p>
    ${details([[text("場所"), relative(value.file) + (value.file !== null && start !== null ? `${text("：")}${start}${end !== null && end !== start ? `–${end}` : ''}${text("行")}` : '')], [text("修正版の候補"), value.fixedVersions.map(version).join(' / ') || text("検査結果に記録なし")], [text("確度"), label(value.confidence)], [text("到達可能性・実悪用"), text("未確認")]])}
    ${info ? `<p>${text("公式重要度：")}${e(info.severity)}${text("。以下の適用条件は未確認です。")}</p>${list(info.conditions)}${info.sources.map(source => `<p class="advisory-source">${e(source)}</p>`).join('')}` : ''}</article>`;
}
function targetGroup(group: FindingGroup, index: number): string {
  const first = group.items[0].value;
  const title = first.package ? packageName(first) + ' ' + version(first.package.version) : label(first.category) + ' — ' + relative(first.file);
  const action = first.category === 'secret' ? text("所有者が秘密情報か確認し、該当する場合は失効・再発行と利用箇所の修正を進めてください。値は掲載しません。")
    : first.category === 'misconfiguration' ? text("設定不備の候補です。規則の識別子と設定を照合し、実際の適用条件を人が確認してください。")
    : first.category === 'runtime' ? text("宣言と実配備の版を照合し、通知ごとの適用条件と配布元の修正を確認してください。")
    : text("実際の依存・利用箇所を確認し、下の通知に対応する修正版を選定してください。");
  return `<section class="target-group" id="target-${index + 1}"><h3>${index + 1}. ${e(title)}</h3><div class="target-meta"><span>${e(label(first.engine))}</span><span>${text("候補")} ${group.items.length}${text("件")}</span><span>${text("場所")} ${group.places}${text("か所")}</span><span>${text("既知最大：")}${e(group.knownSeverity ? label(group.knownSeverity) : text("記録なし"))}${group.unknownCount ? ` ${text("/ 重要度不明")} ${group.unknownCount}${text("件")}` : ''}</span></div><p class="target-action">${e(action)}</p>
    <details class="screen-only"><summary>${text("個別の根拠・修正版を読む（")}${group.items.length}${text("件）")}</summary>${group.items.map(({ value, index }) => individual(value, index, 'screen')).join('')}</details>
    <div class="print-only">${group.items.map(({ value, index }) => individual(value, index, 'print')).join('')}</div></section>`;
}
function runtimeSection(details: AdvisoryDetails): string {
  const view = advisoryView(details, language);
  const fold = (title: string, body: string) => `<details class="screen-only"><summary>${e(title)}</summary>${body}</details><div class="print-only">${body}</div>`;
  const declarations = view.declarations.map((row, index) => {
    const assessments = details.declarations[index].assessments;
    const matched = assessments.filter(item => item.state === 'matched').length;
    const outside = assessments.filter(item => item.state === 'outside_recorded_ranges').length;
    const unknown = assessments.length - matched - outside;
    return `<div class="catalog-declaration"><h3>${e(row.product)} ${e(row.version)} ${e(row.edition)}</h3><p>${e(row.place)} — ${e(row.reason)}</p><p>${text("影響版に一致")} ${matched}${text("件 / 既知区間と不一致")} ${outside}${text("件 / 未確認")} ${unknown}${text("件")}</p>${row.assessments.length ? fold(text("通知ごとの照合結果を読む"), list(row.assessments.map(item => `${item.id}${text("：")}${item.state} / ${item.reason}`))) : `<p>${text("製品を確定できないため通知との比較は未実施です。")}</p>`}</div>`;
  }).join('');
  const sources = view.advisories.filter(row => view.declarations.some(declaration => declaration.assessments.some(item => item.id === row.id))).map(row => `<div class="individual"><h4>${e(row.id)} ${text("/ 公式重要度")} ${e(row.severity)}</h4><p>${text("修正版候補：")}${e(row.fixed.join(' / '))}</p>${list(row.conditions)}${row.sources.map(source => `<p class="advisory-source">${e(source)}</p>`).join('')}</div>`).join('');
  return `<p>${e(view.limitation)}</p><p class="mono">${text("カタログ確認日")} ${e(view.confirmedAt)} / SHA-256 ${e(view.hash)}</p>
    ${view.declarations.length ? declarations : `<p>${text("版宣言なし・実環境は未確認")}</p>`}${sources ? fold(text("公式通知・修正版・確認条件"), sources) : ''}`;
}

/** Closed display projection: never copy target text, absolute host paths or arbitrary reason strings. */
function aiExecutionDetails(run: EngineRun): string {
  const ai = run.aiExecution;
  if (!ai) return '';
  const number = (value: number) => Number.isSafeInteger(value) && value >= 0 ? value : text("未確認");
  const states = { not_started: text("未開始"), completed: text("完了"), failed: text("失敗"), canceled: text("中断"), budget_exceeded: text("上限到達"), acceptance_unknown: text("確定不能") };
  const program = { daybreak_blue: 'Blue', standard: text("通常（standard）"), daybreak_red: 'Red', unknown: text("未確認") };
  const synthetic = ai.classification === 'synthetic', observation = ai.tokens;
  const amount = observation.kind === 'unknown' ? text("未確認") : number(observation.observed.totalTokens);
  const completeness = observation.kind === 'complete' ? text("今回の全呼出しで観測") : observation.kind === 'partial' ? text("部分観測。未取得分を含まない") : text("使用量は未確認");
  const model = !synthetic && run.modelActual && /^gpt-6-sol(?:-\d{4}-\d{2}-\d{2})?$/.test(run.modelActual) ? run.modelActual : text("未確認");
  const diagnostics = aiTransportFailures(ai).map(row => `<p class="mono">${text("AI通信の診断")} #${row.sequence}: ${e(row.failureCode)}</p>`).join('');
  return `<h3>${text("AI実行と観測使用量")}</h3>${details([
    [text("証拠の種類"), synthetic ? text("合成通信による実装試験。実サービスの検査・実効Blueの証拠ではありません。") : text("実サービス用の実行経路")],
    [text("AI実行状態"), displayValue(states, ai.status, text("未確認"))], [text("要求プログラム"), displayValue(program, run.accessProgramRequested ?? 'unknown', text("未確認"))], [text("実効プログラム"), synthetic ? text("未確認（合成応答）") : displayValue(program, run.accessProgramEffective ?? 'unknown', text("未確認"))],
    [text("実効モデル"), model], [text("呼出関数の実行回数"), number(ai.submitInvocations)], [text("接続試行"), number(ai.connectionAttempts)], [text("アプリケーション送信試行"), number(ai.sendInvocations)],
    [text("観測トークン合計"), amount], [text("使用量の範囲"), completeness], [text("金額"), text("N/A（この認証経路では金額を取得できません）")], [text("アカウント利用枠"), text("未確認")],
    [text("Linux境界"), ai.runtime.boundaryVerified ? text("実行前に確認済み") : text("未確認")], [text("実行後の終了確認"), ai.cleanup.closed && ai.cleanup.quiescent && ai.cleanup.containerAbsent ? text("確認済み") : text("未確認")],
    [text("元コミット"), hash(ai.originalCommit)], [text("解析用コミット"), hash(ai.derivedRevision)], [text("対象ファイルの秘密検査"), ai.sourcePreflight === 'completed' ? text("全対象を確認済み") : text("未完了")],
    [text("SDK成果物"), ai.artifactsAccepted ? `${number(ai.artifacts.length)}${text("ファイルを受入")}` : text("未受入")], [text("SDKの未解決事項"), ai.coverage ? number(ai.coverage.openQuestions) : text("未確認")],
    [text("SDKの保留・除外・制限"), ai.coverage ? `${number(ai.coverage.deferred)}${text("件・")}${number(ai.coverage.exclusions)}${text("件・")}${number(ai.coverage.limitations)}${text("件")}` : text("未確認")],
    [text("送信時の保存要求"), text("store:false。プロバイダー側の保持・学習条件は未確認です。")],
  ])}${diagnostics}<p class="muted">${text("送信試行はサーバーの受領確定数ではありません。合成結果と不完全な実行を検査完了や安全性の合格に使いません。SDK原本と対応ハッシュは、同じ非公開作業領域のai-attempt/artifactsとJSONで確認できます。")}</p>`;
}
function destinationDetails(report: Report): string {
  const value = report.plan.destinations;
  if (!value || !Array.isArray(value.destinations)) return '';
  const sides = { local: text("この端末（ローカル）"), provider: text("プロバイダー") };
  const components = { 'linux-image': text("Linux作業イメージ"), 'codex-security-sdk': text("Codex Security SDK資材"), docker: 'Docker', git: text("Git（コンテナ内）"),
    node: text("Node.js（コンテナ内）"), 'openai-responses': 'OpenAI Responses API' };
  const levels = { publisher_verified_at_admission: text("起動前に配布者の署名を検証"), ledger_recorded_at_admission: text("起動前に台帳の記録を確認"),
    digest_pinned_only: text("ハッシュの固定のみ"), unidentified: text("識別できていません"), unattestable: text("検証できません（プロバイダーがソフトウェアの証明を提供していません）") };
  const rows = value.destinations.map(item => `<tr><td>${e(displayValue(sides, item.side, text("未確認")))}</td><td>${e(displayValue(components, item.component, text("未確認")))}</td><td>${e(displayValue(levels, item.side === 'local' ? item.level : item.attestation, text("未確認")))}</td></tr>`).join('');
  return `<h3>${text("AIの送信先と検証できる範囲")}</h3><div class="disclosure"><p>${text("「検証済みのソフトウェアにだけ送る」条件は満たしていません。送信先のプロバイダー側のソフトウェアは検証できません。")}</p>
    <div class="table-wrap"><table><thead><tr><th scope="col">${text("送信先")}</th><th scope="col">${text("構成要素")}</th><th scope="col">${text("確認の水準")}</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}
function trivyEvidence(report: Report): string {
  if (report.schema !== 'scanmux.report/v3') return '';
  const planned = new Map(report.plan.trivy?.inputs.map(unit => [unit.key, unit]) ?? []);
  return report.engines.filter(run => run.engine === 'trivy').map(run => {
    const coverage = run.trivyCoverage;
    if (!coverage) return `<h3>${text("Trivyの検査範囲の証拠")}</h3><p>${text("検査範囲の受領記録がありません。")}</p>`;
    const receipts = coverage.state === 'unsupported' ? [] : coverage.receipts;
    const coverageReasons = coverage.state === 'unsupported' ? [coverage.reason] : coverage.state === 'partial' ? coverage.reasons : [];
    const rows = receipts.map(receipt => {
      const unit = planned.get(receipt.unit);
      return `<tr><td>${e(unit ? unit.files.map(relative).join(' / ') : text("場所は非表示"))}</td><td>${e(label(receipt.state))}</td></tr>`;
    }).join('');
    return `<h3>${text("Trivyの検査範囲の証拠")}</h3>${details([[text("計画した入力単位"), planned.size], [text("範囲"), label(coverage.state)], [text("受領記録数"), receipts.length]])}<p>${text("終了コード0や候補0件だけでは、全対象の解析完了を示しません。検出は人による確認が必要な候補です。")}</p>${coverageReasons.length ? list(coverageReasons.map(reason)) : ''}${rows ? `<div class="table-wrap"><table><thead><tr><th scope="col">${text("相対パス")}</th><th scope="col">${text("範囲")}</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}`;
  }).join('');
}
function render(report: Report): string {
  const findings = report.engines.flatMap(run => run.findings);
  const verdict = gates[report.gate];
  const groups = groupFindings(findings);
  const engines = [...new Set([...report.plan.required, ...report.engines.map(run => run.engine)])];
  const source = report.plan.source?.url;
  const publicSource = source && /^https:\/\/github\.com\/[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(source) ? source : text("ローカルGitリポジトリ（端末のパスは非掲載）");
  const count = (severity: string) => findings.filter(value => value.severity === severity).length;
  const priority = findings.filter(value => ['critical', 'high'].includes(value.severity));
  const comparison = comparisonSummary(report.plan);
  const comparisonDetails = comparison ? details([[text("検査方式"), text("差分起点・head全体の静的検査")], [text("baseコミット"), comparison.baseCommit],
    [text("headコミット"), comparison.headCommit], [text("変更パス数"), comparison.changedPaths], [text("比較基準"), text("baseの検査結果とは未比較。修正済み判定は行っていません。")]]) : '';
  return `<!doctype html><html lang="${language}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="${e(reportCsp)}"><meta name="referrer" content="no-referrer"><title>${text("ScanMux セキュリティ監査レポート")}</title><style>${style}</style></head><body><main>
    <header><div class="eyebrow">SCANMUX / SECURITY ASSESSMENT</div><h1>${text("セキュリティ監査レポート")}</h1><p class="muted">${text("固定コミットに対する自動静的検査の結果")}<br>${text("取扱区分：機密・所有者向け")}</p>${details([[text("対象"), publicSource], [text("コミット"), hash(report.plan.commit)], [text("検査終了（UTC）"), time(report.endedAt)]])}</header>
    ${comparisonDetails}<nav aria-label="${text("レポート内の移動")}"><a href="#summary">${text("総合評価")}</a><a href="#scope">${text("検査範囲")}</a><a href="#findings">${text("対応対象と根拠")}</a><a href="#runtime">${text("版宣言の照合")}</a><a href="#limits">${text("制限・未検査")}</a><a href="#evidence">${text("証拠")}</a></nav>
    <section id="summary"><h2>${text("1. 総合評価と優先対応")}</h2><div class="verdict ${e(report.gate)}"><strong>${e(text(verdict[0]))}${text("（")}${e(report.gate)}${text("）")}</strong><p>${e(text(verdict[1]))}</p></div>
    <div class="grid"><div class="metric">${text("確認・対応する対象")}<b>${groups.length}${language === 'en' ? ' targets' : text("対象")}</b>${text("製品・パッケージと版で整理")}</div><div class="metric">${text("検出した候補")}<b>${findings.length}${text("件")}</b>${text("うち緊急・高")} ${priority.length}${text("件")}</div><div class="metric">${text("全体の検査状況")}<b>${report.coverageState === 'complete' ? text("完了") : text("未完了")}</b>${text("実行状態：")}${e(label(report.executionState))}</div></div>
    <p>${text("重要度別：緊急")} ${count('critical')} ${text("/ 高")} ${count('high')} ${text("/ 中")} ${count('medium')} ${text("/ 低")} ${count('low')} ${text("/ 参考")} ${count('informational')} ${text("/ 不明")} ${count('unknown')}</p>
    <h3>${text("判定の根拠")}</h3>${list([...new Set(report.reasons.map(reason))])}<h3>${text("優先する確認")}</h3><ol>${report.coverageState !== 'complete' || report.gate === 'ERROR' ? `<li>${text("失敗・未実施・除外された範囲を確認し、不足する検査を補ってください。")}</li>` : ''}<li>${priority.length ? text("緊急・高の指摘から、対象の版と公式情報の影響条件を照合してください。") : text("指摘の有無にかかわらず、今回の対象範囲が運用上必要な範囲を満たしているか確認してください。")}</li><li>${text("対応後は固定コミットで再検査し、検査条件と変更内容を比較してください。")}</li></ol></section>
    <section id="scope"><h2>${text("2. 検査対象と実施状況")}</h2>${details([[text("対象ファイル数"), report.plan.files.length], [text("依存関係入力数"), report.plan.lockfiles.length], [text("除外された項目数"), report.plan.exclusions.length], [text("検査開始（UTC）"), time(report.startedAt)], [text("手法"), text("対象のビルド・スクリプト実行を伴わない静的検査")]])}<div class="table-wrap"><table><thead><tr><th scope="col">${text("検査")}</th><th scope="col">${text("実行")}</th><th scope="col">${text("範囲")}</th><th scope="col">${text("候補数")}</th></tr></thead><tbody>${engines.map(engine => { const runs = report.engines.filter(run => run.engine === engine); return runs.length ? runs.map(run => `<tr><th scope="row">${e(label(engine))}</th><td>${e(label(run.execution))}</td><td>${e(label(run.coverage))}</td><td>${run.findings.length}</td></tr>`).join('') : `<tr><th scope="row">${e(label(engine))}</th><td>${text("未実施")}</td><td>${text("実行記録なし")}</td><td>—</td></tr>`; }).join('')}</tbody></table></div><p class="muted">${text("対象コードが稼働環境で実行可能か、攻撃が成立するかをこの静的検査だけで証明するものではありません。")}</p></section>
    ${report.engines.map(aiExecutionDetails).join('')}${destinationDetails(report)}
    <section id="findings"><h2>${text("3. 対応対象と個別の根拠")}</h2><p>${text("同じ製品・パッケージと版の候補をまとめています。対象数は脆弱性の件数ではありません。場所数はファイルと行番号の組合せです。")}</p>${groups.length ? groups.map(targetGroup).join('') : `<p>${text("指摘の記録は0件です。未検査・除外範囲の有無を併せて確認してください。")}</p>`}<p class="muted">${text("修正版は通知ごとの候補です。複数の通知を一つの更新先へ統合していません。実際の利用系列・バックポート・影響条件を確認し、対応後は動作確認と再検査を行ってください。到達可能性と実悪用は未確認です。")}</p></section>
    <section id="runtime"><h2>${text("版宣言と緊急脆弱性通知の照合")}</h2>${report.engines.some(run => run.advisoryDetails) ? report.engines.map(run => run.advisoryDetails ? runtimeSection(run.advisoryDetails) : '').join('') : `<p>${text("版宣言の照合記録がありません。実稼働環境は未確認です。")}</p>`}</section>
    <section id="limits"><h2>${text("4. 制限・除外・未検査事項")}</h2><p>${text("Git履歴、ビルド結果、配備先の実測、実悪用の有無はこのレポートでは保証しません。対象由来の任意説明や端末の絶対パスは掲載しません。AI検査の利用可否は上の実施状況を参照してください。")}</p>
    ${engines.map(engine => { const runs = report.engines.filter(run => run.engine === engine); return `<h3>${e(label(engine))}</h3>${runs.length ? runs.map(run => list([...run.errors.map(reason), ...run.exclusions.map(value => text("除外対象：") + relative(value))])).join('') : `<p>${text("必要な検査の実行記録がありません。")}</p>`}`; }).join('')}
    <h3>${text("対象ファイルの除外")}</h3>${report.plan.exclusions.length ? `<div class="table-wrap"><table><thead><tr><th scope="col">${text("相対パス")}</th><th scope="col">${text("理由")}</th></tr></thead><tbody>${report.plan.exclusions.map(item => `<tr><td>${e(relative(item.path))}</td><td>${e(reason(item.reason))}</td></tr>`).join('')}</tbody></table></div>` : `<p>${text("計画上のファイル除外は記録されていません。")}</p>`}<h3>${text("整合性の確認")}</h3>${list(report.integrityErrors.map(reason))}</section>
    <section id="evidence"><h2>${text("5. 証拠と再確認用の情報")}</h2>${details([[text("形式"), report.schema === 'scanmux.report/v3' ? 'scanmux.report/v3' : report.schema === 'scanmux.report/v2' ? 'scanmux.report/v2' : 'scanmux.report/v1'], [text("実行識別子"), /^[a-f0-9-]{36}$/.test(report.runId) ? report.runId : text("未記録")], [text("計画SHA-256"), hash(report.plan.planHash)], [text("対象SHA-256"), hash(report.plan.snapshotHash)], [text("判定条件SHA-256"), hash(report.plan.policyHash)]])}${trivyEvidence(report)}
    ${report.engines.map(run => `<h3>${e(label(run.engine))}</h3>${details([[text("ツール版"), run.version ? version(run.version) : text("未記録")], [text("実行ファイルSHA-256"), hash(run.executableHash)]])}${run.database.map(db => details([[text("データベース種別"), /^[a-z0-9._-]+$/i.test(db.ecosystem) ? db.ecosystem : text("非表示")], [text("データベースSHA-256"), hash(db.sha256)], [text("ファイル更新時刻（UTC）"), time(db.modifiedAt)]])).join('')}`).join('')}<p class="muted">${text("データベースのファイル更新時刻は収録情報の最新性を保証しません。詳細な機械可読記録は同時に保存したJSONを参照してください。")}</p></section>
    <footer>${text("ScanMuxによる自動生成。独立した人手の監査、侵入試験、保証意見を示す文書ではありません。総合判定はJSONのReportを正本とし、本書はその表示形式です。ブラウザーの印刷機能からPDFにも保存できます。")}</footer>
  </main></body></html>\n`;
}

  return render;
}

export function renderHtmlReport(report: Report, inputLanguage: ReportLanguage = 'ja'): string {
  return createRenderer(parseReportLanguage(inputLanguage))(report);
}
