[English](results.md) | [日本語](results.ja.md)

# 結果を読み、保存して確認する

判定、監査レポート、CI完了確認、履歴、復旧、人による判断を説明します。検査結果を読み、保存記録を扱うときに使ってください。

## 判定と終了コードを読む

| 判定 | 終了コード | 意味 |
|---|---:|---|
| `ERROR` | 4 | 実行・レポート解析・整合性の失敗 |
| `FAIL` | 1 | 秘密検出、または根拠を確認したHigh/Critical |
| `INCOMPLETE` | 3 | 必要検査の不足・除外・非対応・中断・時間切れ |
| `REVIEW` | 2 | 検査範囲は満たすが、重大な候補や重大度不明が残る |
| `PASS` | 0 | 必要検査がすべて完了し、阻害する指摘がない |

優先順位は表の上からです。エラーでも、それまでに得た指摘は残します。OSVの一致とAIの指摘は候補であり、実行時の悪用可能性を確認した結果ではありません。Gitleaksの検出にも有効性・失効の確認が必要です。

AI検査が未実施のため、このPoCの通常scanは**PASSになりません**。`doctor`も不足がある間は3を返します。`plan`の0は計画作成の成功であり、セキュリティ合格ではありません。

## 検証の根拠と限界を確認する

`npm test`で判定の優先順位、不正なレポート・パス、認証環境変数の除外、AIの起動拒否、中断、時間切れ、出力量上限、実行ファイルhash不一致を確認します。合成データを使う試験で、実モデルは呼びません。

信頼されたツールと4言語のDBを用意した環境では、次で実ツールを検証できます。

```sh
npm run verify:real -- /absolute/controller.json
```

通常のGit hooksを維持して専用の自作Git fixtureを作ります。OSVの4言語照合、Gitleaksの検出・秘匿、対象設定の無視、変更ありの拒否、doctor、JSONを確認します。fixtureの依存導入はしません。合成秘密は専用snapshotでだけ生成し、commitしません。検証用ディレクトリとレポートは非公開のローカル成果として残ります。

Windowsでの実測ではOSVが4言語から57件の候補を返し、Gitleaksが別の合成秘密を検出しました。DB更新で件数は変わるため、試験は固定件数を合格条件にしません。総合判定は未完了です。Linuxの隔離経路は別のオフライン実検査で確認しており、本番AI検査は未実施です。

小さな公開GitHubリポジトリで、固定commitの計画・実静的検査・ブラウザーからのJSON保存と、実Git fetch中の中断を実証しました。
容量確認は取得後であり、転送中の厳密なdisk quotaではありません。
`node scripts/verify-github.ts /absolute/controller.json`で取得と中断を再検証できます。
取得時だけネットワークを使います。

Web単体試験では認証・別サイトからの要求・古いID・二重実行・中断待ち・停止未確認時のデータ保持を別途確認します。

> Q. `termination_unverified`で作業データが残るのはなぜですか。
>
> A. Windowsで子プロセス全体の終了を確認できなかったためです。独立して終了を確認するまでは、代わりの処理を始めたりデータを削除したりしないでください。確認済みの中断とは区別し、異常終了からの自動回復は行いません。

SARIFのアップロードとCI連携、永続履歴・baseの指摘との比較、Linux本番scan、モデル利用枠・費用制御、永続的な再開、修正案、配布署名は後続です。
指摘0件でも、安全性は保証しません。

## 監査レポートを読んで保存する

`scan`は同じ非公開ディレクトリへ`report.html`、`report.json`とSARIF 2.1.0を保存し、それぞれの場所を表示します。
`--json`の標準出力は機械可読のJSONです（現行schemaはv2）。
保存先の追記はありません。
全形式と保存先情報の秘密検査を終えてから保存し、既存ファイルは上書きしません。
保存時のI/O失敗では検査済みの部分出力が残り得ます。

Webの「HTML監査レポートを保存」と「JSONをダウンロード」は、bundle全体の保存が成功した場合だけ取得できます。
SARIFはローカルCLIの保存ファイルだけで、Webからはダウンロードできません。

SARIFは全指摘を元の順序で保持し、fingerprint、ScanMuxの総合判定、実行・検査範囲の状態を記録します。
必須検査の未実施・不足・失敗は、指摘0件でも未完了のままです。
SARIFの重要度で総合判定を置き換えません。
未対応の付随情報や危険なパスは省略フラグを残し、指摘自体は保持します。
端末の絶対パス、ソース断片、任意の見出し、生のエラー文は掲載しません。
相対パスやパッケージ名を含むため、SARIFも非公開で扱います。

1ファイル1実行・最大5,000件で、設定されたUTF-8出力上限とgzip圧縮後10 MiB以内に分割します。
通常は`report.sarif`、分割時は`report-0001.sarif`、`report-0002.sarif`のように保存し、CLIと各ファイルに部分番号・総数・全指摘件数を記録します。
アップロードは行いません。

指摘は検査・製品またはパッケージ・版ごとにまとめ、既知の重要度順に表示します。各対象に候補数・場所数・重要度不明の件数を示し、個別の根拠は展開して読めます。印刷では開閉状態にかかわらず全記録を掲載します。修正版は通知ごとに残し、一つの更新先で全件が解消するとは推定しません。

HTMLは、総合評価、優先対応、対象範囲と検査別の実施状況、指摘事項、除外・制限、再確認用のハッシュで構成します。
JSONの判定を維持し、未完了・失敗や必須検査の記録欠落を明示します。
スクリプトと外部資産のない単一ファイルで、オフライン閲覧とブラウザー印刷に対応します。
端末の絶対パスや任意の診断文はHTMLへ掲載せず、詳細は非公開のJSONに保持します。
影響条件や修正版の適用可否は公式情報と稼働環境で確認してください。

自動検査結果であり、人手の監査意見ではありません。

HTMLの既定言語は日本語です。
`scan`・`ai-scan`・`resume`・`scan-list`・`recover`・`job-export`・`job-recover`・`intel-match`に`--report-language en`を付けると英語、`ja`を付けると明示的に日本語で保存します。
例：`scanmux scan /absolute/repo --config /absolute/config.json --report-language en`。

変更するのはアプリが用意したHTMLのラベルと説明だけです。
JSON・SARIF・判定・識別子・ソース位置・元の根拠は変えず、ソース名やモデルの文章は翻訳しません。
Webからの保存は従来どおり日本語です。
他のcommandではこの指定を拒否し、未対応の言語は検査開始前に拒否します。

## ローカルでCIの完了を確認する

単一の`scan`に`--ci-run UUID --ci-job ID`を組で指定すると、全レポートの保存完了後に非公開の`ci-receipt.json`を保存します。検査ごとに新しいUUIDを生成し、各jobに異なるIDを付けてください。完了記録には固定した識別情報と検査状態だけを含め、対象本文やローカルのrepoパスは含めません。

```powershell
node bin/scanmux.mjs scan C:/repos/project --config C:/scanmux/controller.json --ci-run 11111111-2222-4333-8444-555555555555 --ci-job project
node bin/scanmux.mjs ci-check C:/scanmux/expected.json C:/private-run/ci-receipt.json --config C:/scanmux/controller.json
```

例のUUIDは毎回新しく生成します。
検査前に、同一configとbase/head指定で`plan`を実行し、全対象の外へ期待集合を固定してください。
形式は`{ "schema": "scanmux.ci-expectation/v1", "ciRun": "<fresh UUID>", "jobs": [...] }`。

各jobには`id`、canonicalな絶対`targetRoot`、事前planの`repoId`・`commit`・`policyHash`・`planHash`・`snapshotHash`をそのまま指定します。
完了記録から期待値を補完しないでください。
job集合は空にできず、IDは重複不可です。
このv1経路はローカルの単一offline `scan`用で、jobごとに実行します。
指定だけでAIを有効化せず、元の判定も変わりません。

`ci-check`へ全完了記録のパスを渡します。
記録0個なら全jobが未完了になります。
期待した全jobと4系統すべての完了、検査ID・repo・commit・policy・plan・snapshotの一致を確認し、重複や余分な記録を拒否します。
判定の優先順位を維持し、skip・欠落・未完了を成功にしません。
現在の実offline検査はAIが未実施のため非0です。
レポートや完了記録の保存失敗は終了値4で、保存済みの成果は残します。

`--json`ではstdoutに検査レポート、stderrに完了記録の場所を出します。
最終判定は非公開の`ci-result.json`にも保存し、入力manifestの合計bytesにはconfigの最大出力量を適用します。

この機能はローカルcontroller用で、GitHub Actionsへ配備済みのworkflowではありません。
新しいUUIDの生成、期待集合・実行コード・config・完了記録の受渡しを対象から変更できないようにする責任はcontroller側にあります。
パスとhashは実行元の認証にも、信頼側による古い検査IDの再利用防止にもなりません。

CIポリシーは保護されたbaseまたは外部設定から供給し、未信頼PRのcheckout内の仕組みを実行しないでください。
全入力・設定済みtool/DB/runner・出力workspaceはcanonicalな全対象rootの外に置きます。
URL取得先の記録継承と保護checkは未対応です。
実CIは[GitHub Actions](github-actions.md)（英語のみ）を参照。
CI指定なしの従来の`scan`も使えます。

### 明示受諾したAI検査を含める

AI用のjobは、先に`ai-plan`の開示を読み、実行前に期待集合を固定します。
形式は`scanmux.ci-expectation/v2`で、最上位は同じ`ciRun`と`jobs`です。
各jobのv1識別項目に、AIなら`analysis: "ai"`、通常検査なら`analysis: "offline"`を追加します。
AIの識別値は`ai-plan`から取得し、offline planや検査後の完了記録から補完しません。

v2ではofflineとAIのjobを混在でき、offlineの完了記録は従来どおりv1です。

```sh
node bin/scanmux.mjs ai-scan C:/repos/project --config C:/scanmux/controller.json --accept-plan <planHash> --ci-run <fresh-UUID> --ci-job project
node bin/scanmux.mjs ci-check C:/scanmux/expected-v2.json C:/private-run/ci-receipt.json --ci-report C:/private-run/report.json --config C:/scanmux/controller.json --json
```

`ai-scan`の計画受諾・秘密検査・隔離・上限はそのままです。
全レポートを保存した後に、`analysis: "ai"`を持つ`scanmux.ci-receipt/v2`を作成します。
AI記録ごとに、保存したままの`report.json`を`--ci-report`（複数なら繰返し）で渡します。
整形だけでもhashは変わります。

最終確認はreportのbytes・実行ID・repo/commit/policy/plan/snapshot・判定・実行/範囲・engine行を照合し、履歴と共通の保存結果の完了条件を使います。
実効プログラムが`standard`または`daybreak_blue`ならプログラム条件を満たします。
合成応答、不明・欠落・要求していないプログラム、成果物未受理、使用量不明、停止/範囲不足は、上位項目が成功を宣言してもPASSにしません。

より強いFAIL/ERRORは維持します。
reportの欠落は不完全、取り違え・重複・余分なreportやモード不一致は拒否かERRORです。
v1期待集合へAI記録や`--ci-report`は渡せません。

保存結果は`scanmux.ci-result/v2`で、各jobに`analysis`、`reportState`（`not_required`・`missing`・`verified`）と`reportHash`を追加します。
hashが入るのは対応の照合に成功した場合だけです。
テキスト要約には、照合済みreportに記録されたAI jobの実効プログラムを表示します。
保存形式は変えていません。
対象本文や生の指摘は載せません。

入力の合計bytes上限にはreportも含めます。
最終確認は対象の解析・推論・ネットワークを開始せず、既存のローカル出力秘密検査だけを継続します。
GitHub上の受渡しの認証や実Blueの成立を証明するものではありません。

> Q. 検査は実行済みですが、CI記録の秘密検査や保存だけが失敗しました。再実行しますか。
>
> A. 記録の修復だけを目的に推論を繰り返さないでください。終了値は4で、保存済みレポートは残ります。stderrに検査済みである旨と、確認済みrun ID・JSON保存先を表示します。

CI job指定はWeb・一覧・resume・`ai-plan`では受け付けません。

## 保存済みの実行履歴を読む

`node bin/scanmux.mjs history C:/private-run/report.json C:/another-run/report.json --config C:/scanmux/controller.json`で、明示したreportだけを読み、新しい非公開`history.json`を保存します。
`--json`はその要約を出します。
終了0は読取りと保存の成立で、PASSではありません。

原本を変更せず、入力合計にconfigの最大出力量を適用します。
canonicalなローカル対象rootが残っている記録だけを扱い、入力・config/tool・出力workspaceは全対象の外に置きます。

各行に元の判定・実行/範囲の状態・commit・policy/plan/snapshotの識別情報を残し、異なるrunやSHAは別行にします。
必要engineが欠落した場合は未記録とし、呼出0で補いません。
元PASSと未完了状態が矛盾するときは明示しますが、所見の再判定はしません。
同run IDかつ同じbytesだけを重複除外し、同run IDで異なるbytes（JSON再整形も含む）とengineの重複は拒否します。

合計は「指定した一意な実行の、記録がある分の呼出数」で、未記録engine数を併記します。費用unknownとnot_applicable（適用なし）を分け、どちらも実測0円へ変換しません。hashで記録の真正性を認定せず、アカウント全体の請求・残枠とは称しません。予算予約・再開実行・抑制・ディレクトリ自動探索・過去結果の新判定への取込みは行いません。

## 完了済みエンジンの記録を復旧する

各エンジンが結果を返すたびに秘密情報を検査して途中保存し、保存確認が終わってから次のエンジンへ進みます。
CLI・AI・一覧の各リポジトリ・再開・Webは共通controllerを通ります。
記録は実行専用の非公開ディレクトリ内の`checkpoints`へ残り、正常終了後も保持します。
実行ディレクトリはOSの一時ディレクトリ内にあり、OSの整理処理で消える場合があります。
計画作成・取得は完了済みエンジンの記録を作りません。

```text
scanmux recover /absolute/private-run/checkpoints --config /absolute/config.json --json
scanmux recover /absolute/private-run/checkpoints --config /absolute/config.json --report-language en
```

復旧は完全な連続記録を照合し、最後に確認できた結果を新しいJSON・HTML・SARIFへ保存します。エンジン・推論の再実行、認証記録の読取り、プロバイダーへの通信は行いません。元の対象ディレクトリは記録された実体パスに存在する必要があります。controllerが取得後に削除したGitHub用ディレクトリを復旧用に再取得しません。通常の最終レポートがあれば、そちらを使ってください。

全エンジンの記録が揃っていても、controllerがまだ動いていても、復旧結果は必ず`ERROR`・終了値4と`controller_completion_unverified`を返します。
途中保存だけでは最終処理やプロセス停止を証明できないためです。
完了済みエンジンの検出内容・記録済み使用量は保持します。
この記録を中断・時間超過用の`resume`入力にはできません。
元のプロセス状態が未確認の間は、代わりの検査を開始しないでください。

本文は秘密検査・排他的な新規書込み・同期・クローズ後に確認記録を書き、次エンジンはその同期・クローズ成功を待ちます。
復旧が確認するのは読めた本文と完全な確認記録の一致であり、過去の確認応答の復帰、来歴の認証、電源断への耐久性は保証しません。
末尾の不完全な確認記録は通知して無視し、完全な確認記録と本文の不一致・途中の欠落は拒否します。
途中保存は1実行あたり最大10ファイル（Trivyなしでは最大8ファイル）、各`maxOutputBytes`以内です。

これは論理バイト数の上限で、物理ディスクの割当やjob全体のCPU・メモリ・ディスク上限ではありません。
記録は非公開で保持し、同じ実行の異なる途中記録を一緒に`history`へ入れないでください。

## 中断した検査を再実行する

```powershell
node bin/scanmux.mjs resume C:/repos/project --from C:/private-run/report.json --config C:/scanmux/controller.json --json
```

`resume`は、保存済みreportが`cancelled`（中断）または`budget_exceeded`（時間上限）であることを確認し、新しい実行IDで全検査を1回行います。
全engineを再評価し、以前の所見やengine結果は再利用しません。
reportは対象外へ置き、現在のroot・controller設定から作った新planと対象・commit・policy・plan・snapshotの一致が必要です。

差分検査では同じ`--base`・`--head`を指定し、ソースや設定を変えたら通常の新しい`scan`を使います。
不正な記録、プロセス終了未確認、完了済みrun、識別情報の不一致はscanner開始前に拒否します。
自動再試行はしません。

開始前にstderrへ、前回の記録済み使用量・未記録engine数、新しい検査の時間上限、現offline契約での追加AI呼出予定0・費用適用なしを出します。
前回費用が不明なら不明のままです。
新しいレポート一式の保存後、元と新しいreportのhash・実行ID、各回の使用量を分けた非公開`resume.json`を保存します。
合算のセキュリティ判定や請求情報ではなく、hashは記録の真正性を認定しません。

`--json`では新reportをstdout、対応記録の保存先をstderrへ出し、原本は変更しません。

> Q. 新しい検査は終了しましたが、`resume.json`だけ保存できませんでした。再実行しますか。
>
> A. 記録の修復だけを目的に検査を繰り返さないでください。新しいレポート一式は残ります。終了値は4で、stderrに実行済みである旨と確認済みJSON保存先を表示します。

対象はローカル単一リポジトリです。
CI指定やWeb・一覧の再開操作は追加しません。
AIの起動制限と未完了判定は維持します。

## 人による判断を記録する

```powershell
node bin/scanmux.mjs dispositions C:/private-run/report.json --config C:/scanmux/controller.json --json
node bin/scanmux.mjs dispositions C:/private-run/report.json --decisions C:/private/decisions.json --config C:/scanmux/controller.json --json
```

1行目は各指摘のengine・fingerprintと、report全体の正確なhashを表示します。
2行目は、人が作った`schema: "scanmux.dispositions/v1"`と`entries`配列を持つJSONを照合します。
各行には次の項目が必要です。

| 項目 | 必要な内容 |
|---|---|
| `reportHash`、`engine`、`fingerprint` | 保存reportと指摘の正確な識別情報 |
| `decision` | `false_positive`（誤検出）、`risk_accepted`（リスク受容）、`out_of_scope`（対象外） |
| `reason`、`reviewer` | 空白のみではない理由と、申告した確認者名 |
| `reviewedAt`、`expiresAt` | `2026-10-22T10:00:00Z`のようなUTC時刻 |

確認者は申告値であり、本人認証は行いません。
プログラムは判断、理由、期限を選びません。
未来の確認時刻、確認時刻以前の期限、不正な項目、同engine/fingerprintの重複は拒否します。

`current`は、その保存reportと指摘に完全一致する期限内の記録です。
期限時刻ちょうどで`expired`（期限切れ）になります。
reportのbytesが変わった場合や指摘が見つからない場合は`reconfirmation_required`（再確認が必要）となり、同時に期限切れならその理由も残します。
不一致の判断も残し、判断のない現reportの指摘は`open`（未判断）として一覧に残します。
指摘消失を修正確認済みにはしません。

コード・根拠・設定・別run・JSONの再整形も含め、保存bytesが変わると再確認が必要です。
別runへの自動継承はありません。

新しい非公開`dispositions.json`を保存し、入力原本は変更しません。
終了0は照合・保存の成功で、元の判定と未完了範囲はそのまま表示します。
元scanの所見はopenのままで、scanやCIの判定を緩和しません。
`--json`では検査済み要約、通常出力では件数と保存先を表示します。
入力合計はconfigの最大出力量以内、canonicalな通常fileで、実在する対象rootの外へ置きます。

config/tool/出力も履歴と同じ対象外条件を適用します。
自由記述と保存先を含む出力全体を秘密検査してから保存・表示し、対象本文・任意タイトル・ソースpathは要約へコピーしません。

## 例外を明示的に適用する

```powershell
node bin/scanmux.mjs policy-check C:/private-run/report.json --decisions C:/private/decisions.json --config C:/scanmux/controller.json --json
```

上記の形式で人が作成した判断fileを指定します。
`policy-check`はreportと判断fileの両方を必須とし、別の非公開`policy-result.json`を保存します。
判定と終了コードは、保存reportへ有効な例外を適用した結果です。
元scanのreport・指摘・CI完了記録は変更しません。
現在のcheckoutの再検査や確認者の本人認証は行わず、`ci-check`もこの派生結果を読み込みません。

終了0は保存記録への今回の判定が`PASS`という意味で、新しい検査の完了ではありません。

report全体のhashと指摘のidentityが一致し、期限内の判断だけを、派生する合否の計算へ適用します。
出力には全指摘のidentity、元の判定と理由、各判断、適用の有無を残します。
期限切れや不一致の判断は、指摘が消えていても再確認が必要で、`PASS`を妨げます。
実行失敗、process停止の確認不能、未実施・部分検査・非対応、中断、予算停止、計画の除外は例外で解除できません。

たとえば未完了の検査で秘密の指摘を例外扱いにすると、派生判定は`FAIL`から`INCOMPLETE`へ変わり得ますが、未実施のAI解析を合格にはしません。
不正な型や内部矛盾のある記録は拒否します。

入力path・合計サイズ上限・非公開保存・出力全体の秘密検査は`dispositions`と同じです。対象の再検査とAI呼出しは行わず、設定済みGitleaksによる出力秘密検査は実行します。判断を追跡できるよう、元report・人の判断file・派生結果を一緒に保管してください。reportが変われば、新しい人の確認が必要です。

## 関連文書

- [導入と最初の検査](getting-started.ja.md)
- [実行時の制御](runtime-controls.ja.md)
- [結果の前提](assumptions.ja.md)
- [GitHub Actions](github-actions.md)（英語のみ）
- [ScanMux](../README.ja.md)
