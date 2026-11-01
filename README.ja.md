[English](README.md) | [日本語](README.ja.md)

# ScanMux

ScanMuxは、自分のPCで固定したGit commitを検査したい開発者向けの、ローカルで動くセキュリティ検査コントローラーです。

検査ツールを別々に使うと、何が実行され、何が失敗し、どのファイルが未検査なのかを自分で確かめる必要があります。
ScanMuxはそれらの状態を指摘と一緒に記録し、対象リポジトリの外へ非公開のレポートを保存します。

## 概念実証の段階です

ScanMuxは概念実証（PoC）の段階で、製品版のセキュリティサービスではありません。
通常のコマンドは、固定したcommitにローカルの静的検査を行います。
Web画面は公開リポジトリの取得時にGitHubへ接続します。

別の`ai-plan`と`ai-scan`は、Windowsと隔離LinuxのCodex Securityを接続する手順です。
実行には計画の明示受諾、事前配置した固定資産、専用認証、実行境界の検証が必要です。
開発時の実証は合成応答によるもので、実Blue推論の成功を示しません。

## v0.1.0 の範囲

JS/TS（`npm`）、Python（`PyPI`）、Go（`Go`）への対応とは、以下の入力の読取り、
オフラインOSVの依存関係検査、Gitleaksの秘密検査、明示受諾したAI検査を指します。
通常の`scan`はAIを動かしません。対応は全範囲の検査完了や`PASS`を保証しません。

| 言語 | 依存関係の入力 |
|---|---|
| JS/TS | `package-lock.json`、`pnpm-lock.yaml`、`yarn.lock` |
| Python | `requirements.txt`、`poetry.lock`、`uv.lock` |
| Go | `go.mod`、`go.sum` |
| Rust（`crates.io`） | `Cargo.lock`。依存関係検査だけで、Cargo buildやcall analysisは行いません。 |

緊急の脆弱性については、`runtime-advisories`がPHP・Node.js・Next.js・NGINX・GitLab・Apache Tomcatの版宣言を照合します。
2026-10-22に公式の配布元情報を確認した固定カタログを使います。
一致、記録した範囲での不一致、未確認を報告し、一致したものには修正版を示します。
検査範囲は部分的か非対応のままです。検査中にカタログを更新しません。

これとは別に、`intel-refresh`が公式のCISA Known Exploited Vulnerabilities（KEV、悪用確認済み脆弱性）カタログとJVN更新RSSを取得します。
`intel-match`は保存した検査・取込み結果のCVE IDをオフラインで照合します。
KEVの悪用確認済み一覧への掲載と、JVNの最近の更新への掲載を、別のレポートに書きます。
取得時刻、配布元の日付、鮮度、失敗を表示します。
`--max-age-hours`がなければ鮮度は未判定です。
以前の有効な複製を使う場合も更新失敗を表示します。
鮮度の上限を指定して`--require-fresh`を使うと、照合用フィードが使えないか状態が`fresh`以外なら終了コード3です。
JVN iPediaは状態の表示だけです。

これらの検査は、対象での悪用可能性、適用済みの修正、安全性を証明せず、修正を適用しません。
フィード照合は検査の判定・レポート・終了コードを変えません。
フィードの制約は[公開フィードとの照合](docs/threat-intel.md)（英語のみ）を参照してください。

以下は対象外です。

| 項目 | 対応の限界 |
|---|---|
| 実Linuxホストでの計測と停止 | この資源制御を実証したのは、WindowsとDocker DesktopのLinux engineだけです。 |
| macOS対応 | ホストの資源計測と終了確認は実証していません。 |
| 物理ディスクquota | 登録したジョブ領域の推定量が上限を超えたら停止します。計測間の増加を見逃す場合があります。OS設定は変更しません。 |
| 配布元の証拠がない部品の署名・来歴確認 | v2の実行方針では、用意したOSV-ScannerのSigstore/SLSA証拠を`gh`でオフライン検証できます。Gitleaks 8.30.1は署名の証拠を公開していません。Git for Windows・コンテナ内部品・image・資産manifestの配布元はオフライン検証できません。`gh`は固定しますが自己検証しません。ローカルのSHA-256・版の固定だけでは配布元を確認しません。 |
| 実効Daybreak Blueの保証 | Blueは任意の要求です。要求値と実効値を別々に記録します。実効値が`standard`でもAI検査として認めますが、それだけでは検査完了になりません。 |
| 他のSDKや後段処理でのネイティブメモリ・ディスク増加の原因特定 | 文書化したSDKの原因観測は、固定SDKが最初に行うPythonの検査登録でのネイティブSQLite FULLに限ります。 |
| ソースコピー削除の再試行 | 削除できなかったコピーは`source_cleanup_failed`として報告し、パスを標準エラー出力に表示します。後続の実行に向けた記録や再試行はしません。 |
| 作業領域の識別前の競合 | 同じ利用者として動くプロセスは、`mkdtemp`から最初の識別情報の読取りまでの間にディレクトリを差し替えられます。 |
| 削除中の祖先ディレクトリの競合 | 同じ利用者として動くプロセスは、削除中に祖先ディレクトリをジャンクションへ差し替えられます。 |
| 親ディレクトリのACL変更 | 同じ利用者として動く所有者のプロセスは、プロセス内の最初の完全な確認後に親ディレクトリのACLを広げられます。 |
| 最初の作業領域の作成 | プロセス内の最初の作業領域は親ディレクトリのACL確認より先に作成するため、同じ利用者として動くプロセスによる競合の余地があります。確認に失敗した場合、その作業領域には何も書き込みません。 |
| 品質評価の規模 | v0.1.0の品質評価は対応言語（JS/TS、Python、Go）ごとに脆弱版・修正版の1組で行い、大規模なコーパスでの評価はしていません。Goの組は、再現ジョブがコンパイル済みバイナリを実行できないため、スキャナーの結果だけを根拠にしています。 |
| リリース成果物の検証 | リリース成果物にはCycloneDX SBOMと、パッケージ・SBOMのGitHubビルド来歴証明を含みます。それぞれを`gh attestation verify PATH/TO/ARTIFACT --repo OWNER/REPO`で検証してください。 |

## できること

- 変更のないリポジトリを調べ、commitとファイルhashを固定します。
- 非公開のsnapshotで静的検査を順番に実行します。
- 指摘、失敗、除外、検査範囲の不足を分けて表示します。
- HTML・JSON・SARIFレポートを対象外へ非公開で保存します。

通信の列はコマンドの動作を示します。OS全体の通信0を保証するものではありません。

| コマンド | 行うこと | ネットワークへ接続するか |
|---|---|---|
| `doctor` | 実行ファイルのhash・版と、不足している実行条件を確認します。 | しません |
| `plan` | 1つのcommitの検査範囲、除外、送信、費用を記録します。 | しません |
| `scan` | オフライン検査を実行し、レポートを保存します。 | しません |
| `plan-list`、`scan-list` | 明示したリポジトリ一覧を順番に計画・検査します。 | 公開GitHubの取得時 |
| `deps` | 依存関係の脆弱性情報・更新可否・lockfile差分をオフラインで比較します。0.2.0から終了値は0（追加・現存なし）・10（追加・現存あり）・2（検査失敗・未完了）です。 | しません |
| `ai-plan` | 単一リポジトリのAI送信範囲と有限の上限を開示します。 | しません |
| `ai-scan` | 計画hashの明示受諾後に隔離AI検査を実行します。 | OpenAI |
| `runner-check` | ChatGPT認証の種類、提示されたDaybreakプログラム、モデルを使わないLinux接続、終了処理を確認します。推論やAIの有効化はしません。 | OpenAIのアカウント・モデル情報 |
| `serve` | 個人用loopback画面で公開GitHubのcommitを確認・検査し、HTML・JSONを保存します。 | GitHubの取得時 |
| `ci-check` | ローカルの完了記録と、対応するAIレポートを確認します。 | しません |
| `ci-github` | GitHub Actionsから届いた自己検査の成果を検証します。 | 固定した`gh`でGitHubへ接続 |
| `history`、`recover`、`resume` | 指定した保存レポートを読む、エンジン記録を復旧する、中断したオフライン検査を再実行する操作です。 | しません |
| `dispositions`、`policy-check` | 人の判断を記録するか、保存レポートへ明示的な例外を適用します。 | しません |
| `engine-record`、`engine-history` | エンジンの更新を検証・記録するか、固定した台帳の記録を表示します。 | しません |
| `job-scan`、`host-job-scan` | 資源上限付きの単一オフラインLinuxジョブを実行し、任意でWindowsの調整役にも上限を加えます。 | しません |
| `job-export`、`job-recover` | 保存ジョブの結果を書き出すか、検証できた途中保存を復旧します。 | しません |
| `intel-refresh` | 固定の公開脆弱性フィードを取得します。 | CISA/JVN |
| `intel-match` | 保存フィードとCVE IDを照合し、元の検査判定は変えません。 | しません |
| `release-record`、`release-log-check`、`release-verify` | リリースの記録、記録の連鎖の確認、測定値の検証を行います。 | しません |

## 必要なもの

- Node.js 24の24.16.0以上、25未満と、通常のSHA-1リポジトリを扱うGit。
- 公式配布元から別途導入したGitleaks 8.30.1とOSV-Scanner 2.7.0。
- 検査前に取得したOSVのオフラインDB。
- ローカルCLI検査では、commit済みで変更のないGitルート。
- Windowsで設定済みツールを起動する場合は、固定したプロセス所有者。

DBの配置、入力条件、設定、プラットフォームの制限は[導入と最初の検査](docs/getting-started.ja.md)にあります。
AIと資源上限付きジョブには、それぞれのガイドに追加の必要条件があります。

## 導入と操作

[最初のオフライン検査](docs/getting-started.ja.md)の手順に従ってください。
番号順にツールと取得記録付きDBを用意し、信頼する設定を作り、計画を確認して検査します。

## 判定と終了コードの早見表

gateは全体の判定を表します。表の上ほど優先します。
エラーが優先される場合も、得られた指摘はレポートに残します。

| 判定 | 終了コード | 意味 |
|---|---:|---|
| `ERROR` | 4 | 実行・レポート解析・整合性の失敗 |
| `FAIL` | 1 | 秘密検出、またはソースで裏付けられたHigh/Criticalの指摘 |
| `INCOMPLETE` | 3 | 必須範囲の不足・除外・非対応・中断・時間切れ |
| `REVIEW` | 2 | 範囲は完了したものの、High/Criticalの候補か重要度不明の指摘がある |
| `PASS` | 0 | 必須検査がすべて完了し、対応や確認の要る指摘がない |

このPoCの通常scanは、必須のAI検査が起動しないため`PASS`になりません。
必須の`runtime-advisories`も、`ai-scan`を含め、部分的か非対応のままです。
`doctor`は必要な条件が欠けている間は3を返します。
`plan`の0は計画作成の成功だけで、セキュリティの合格ではありません。
詳しい判定方針と保存記録の操作は[結果の読み方と保存](docs/results.ja.md)を参照してください。

## 安全性

- 対象の指示ファイル、`.gitleaks.toml`、`osv-scanner.toml`は信頼できない入力として扱います。
- 対象の内容を、権限・認証・送信先・判定方針を変える指示として扱いません。
- コントローラー設定、固定ツール、DB、レポートは対象外に置きます。
- 検査するのは追跡済みsnapshotで、Git履歴全体ではありません。対象ファイルは変更しません。
- scanでは、対象のスクリプト、依存導入、Git checkout filterは実行しません。対象のコードを実行するのは`reproduce`だけで、指定した`test.mjs`をLinuxの隔離環境で実行します。
- 検査には最小限の環境とコントローラーの明示設定を渡します。通常のAPIキーは再利用しません。
- 通常のオフラインコマンドはソースを送信しません。明示的な`ai-scan`だけが、受諾した範囲を固定のホスト中継で送信します。
- Gitleaksのallowコメントは無効です。組込み規則によるパス除外は部分的な検査範囲として残します。
- AI中継は、worker起動前に受け入れる全テキストを秘密検査します。
- ローカルの静的実行は設定した実行ファイル・Git・OSを信頼し、OSのセキュリティ隔離ではありません。
- hash確認は、同じ利用者による同時変更や侵害されたネイティブツールを防ぎません。ネイティブのCPU・メモリ隔離とOSレベルの通信0の証明は対象外です。
- 時間・出力・snapshotの上限は通常の実行を制限するもので、悪意ある実行ファイルを防ぎません。機微情報のあるホストで敵対的な素材を検査しないでください。
- レポートは非公開で扱います。パスやパッケージ識別子から対象の情報が分かる場合があります。

信頼の前提と計測上の限界は[結果の前提](docs/assumptions.ja.md)を参照してください。

## 関連文書

| ガイド | 読む場面 |
|---|---|
| [導入と最初の検査](docs/getting-started.ja.md) | ツール・DBの準備、オフライン検査、commitの指定、依存関係の確認。 |
| [緊急脆弱性の照合](docs/urgent-advisories.ja.md) | 版宣言を固定カタログと照合するとき。 |
| [Web画面](docs/web-interface.ja.md) | ローカル画面や所有者限定のSitesを使うとき。 |
| [AI検査](docs/ai-scan.ja.md) | Linux接続を確認し、隔離AI計画を受諾するとき。 |
| [結果の読み方と保存](docs/results.ja.md) | レポート、CI完了確認、履歴、復旧、人による判断を扱うとき。 |
| [実行時の制御](docs/runtime-controls.ja.md) | 部品の拒否、配布元の検証、Linux・Windowsジョブの制限。 |
| [結果の前提](docs/assumptions.ja.md) | 結果が前提とすることや未確認点を調べるとき。 |
| [Trivy](docs/trivy.ja.md) | 任意のオフライン構成ファイル検査を設定するとき。 |
| [GitHub Actions](docs/github-actions.md)（英語のみ） | リポジトリのworkflowから届いた自己検査の成果を検証するとき。 |
| [公開フィードとの照合](docs/threat-intel.md)（英語のみ） | KEV/JVN照合と鮮度の規則を調べるとき。 |
| [リリースの透明性](docs/transparency.md)（英語のみ） | 外部に保存したpinとリリースの測定値を照合するとき。 |
| [Windowsのプロセス終了](docs/windows-process-termination.md)（英語のみ） | プロセス所有者をビルド・固定するか、停止の保証を調べるとき。 |

## 関連プロジェクトとライセンス

- [Codex Security](https://github.com/openai/codex-security)：Apache-2.0。OpenAIのサービス・アクセス条件は別途適用します。
- `@openai/codex-security` 0.5.1のdraft入力スキーマは`test/fixtures/codex-security-draft-input-schema.json`に保存しています（Apache-2.0）。
- [OSV-Scanner](https://github.com/google/osv-scanner)：Apache-2.0。DB・アドバイザリーの条件は各情報源に帰属します。
- [Gitleaks](https://github.com/gitleaks/gitleaks)：MIT。CLI・組込み規則は別途導入します。`src/adapters.ts`には8.30.1のグローバルパス許可リストを検査対象外のパスとして記録しています。
- [Trivy](https://github.com/aquasecurity/trivy) 0.76.1：Apache-2.0。`test/fixtures/trivy-offline.json`に規則の説明文と参照URLを含む出力を保存しています。
- `src/advisory-catalog.ts`には、PHP・Node.js・Next.js・NGINX・GitLab・Apache Tomcatが公開したアドバイザリーの識別子と、影響を受ける版・修正版を記録しています。各記録に出典のリンクを付け、アドバイザリーの本文は複製していません。
- [lodash](https://github.com/lodash/lodash) 4.17.20・4.17.21（MIT）と[PyYAML](https://github.com/yaml/pyyaml) 5.3.1・5.4（MIT）：オフライン評価ペア用に、必要最小限のファイルとライセンスを`eval/pairs/`配下にvendorしています。[golang.org/x/text](https://cs.opensource.google/go/x/text) v0.3.6・v0.3.7（BSD-3-Clause）は`eval/pairs/go/*/go.mod`で版を指定するのみで、ソースは同梱しません。

ScanMux本体は[MIT](LICENSE)です。外部エンジン・DB・認証情報は同梱しません。
npmには公開していません。配布パッケージはGitHub Releasesに添付します。
独立したプロジェクトであり、OpenAI、Google、Gitleaksの公式製品ではありません。
