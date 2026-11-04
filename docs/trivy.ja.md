[English](trivy.md) | [日本語](trivy.ja.md)

# 任意のオフライン Trivy 検査

任意のオフラインTrivy設定検査を使うときに、取得、固定、実行の方法と、検査範囲・隔離の限界を確認するガイドです。

この日本語版が正本です。英語版はこの文書の翻訳です。

Trivy は任意です。
`tools.trivy` の存在だけで有効になり、独立したフラグや任意の引数設定はありません。
この項目がなければ、v2 の計画・レポート、既存の必須4エンジンと順序、設定・計画・スナップショット・検出の既存ハッシュ入力を維持します。
有効にすると、既存4件の後に5番目の必須エンジンを加え、v3 の計画・レポートを生成します。
必須の AI 検査や runtime-advisories を完了させたり置き換えたりしません。

現時点で `PASS` に届くコマンドはありません。
[結果の前提](assumptions.ja.md)を参照してください。

## Trivyを取得して設定する

Windows x64 向け Trivy **0.76.1** の配布物を、検査対象リポジトリと検査処理の外で、[固定版の公式リリース](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)から取得します。
Trivy のライセンスは **Apache-2.0** です。
適用されるライセンスと通知を保管してください。
ScanMux は検査中に取得・導入・更新しません。

受け入れる実行ファイルの SHA-256 は `94618922c9eb324d7099bf217b01504bfc1f87a0d46d6008cb24ec89b1d1a4bb` です。
Windows x64 ZIP の取得証拠で使う SHA-256 は `1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf` です。

ZIP と展開した実行ファイルを別々に確認し、ZIP と実行ファイルの対応を取得記録に残します。
ZIP の証明だけでは実行ファイルの配布元の証明になりません。
`publisher`では、`sigstore-slsa-archive`の証拠で、検証したZIPの証明と固定した実行ファイルを結び付けられます。ScanMuxはZIPを非公開の領域へコピーしてハッシュを再確認し、正確な`trivy.exe`メンバーのSHA-256がエンジンの固定値と一致することを要求します。その後、ZIPのハッシュと設定した配布元の識別情報に対して、`gh`でZIPのコピーを検証します。メンバーの欠落・重複・サイズ超過・不一致、またはZIPの解析失敗は不正として拒否します。実行許可の確認時にZIPを読めない場合や変更されている場合は、検証不能として拒否します（`archive_unreadable`または`archive_changed`）。`engine-record`では、ZIPの欠落はbundleの欠落と同じ一般的な入力エラーです。ZIP内の名前に非ASCIIバイトを含む場合は、UTF-8フラグが必要です。全エントリーのヘッダーを検証し、正確に一致するメンバーだけを、エンジンの非公開コピーのバイト数まで展開します。
`engine-record`要求の証拠に、`bundle`・`trustedRoot`・`sourceRef`・`sourceDigest`とともに、ZIPの絶対パスを`archive`として、`"member":"trivy.exe"`を指定します。ZIPは検査対象の外に置き、ほかの証拠パスと同じ規則に従います。コピー予算は実行許可の確認時に適用し、`engine-record`はどの証拠ファイルにも設定しません。[実行時の制御](runtime-controls.ja.md)を参照してください。

この検証手順は、公式のTrivy 0.76.1 Windows x64 ZIPに対して、`gh` 2.94.0で実行しました。その際、Trivy自体のプロセスは起動していません。検証には次の値を使いました。

| 項目 | 値 |
|---|---|
| `repository` | `aquasecurity/trivy` |
| `certIdentity` | `https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.76.1` |
| `sourceRef` | `refs/tags/v0.76.1` |
| `sourceDigest` | `e713f67f7d54decdcd9b3132c9751833dcced698` |
| `predicateType` | `https://slsa.dev/provenance/v1` |
| `member` | `trivy.exe` |

検査処理の外で、`<zip>`を取得済みZIPのパスに置き換えて証拠を取得します。trusted rootの出力は、`trustedRoot`に指定するファイルへ保存します。

```sh
gh attestation download <zip> --repo aquasecurity/trivy
gh attestation trusted-root
```
ダイジェストの一致が固定するのはバイト列です。
配布物や内蔵規則の正しさ・鮮度・誠実さは示しません。

既存の外部設定 schema 1 または 2 の `tools` に次の項目を追加します。Windows のプロセス所有者を含む、ほかの必須ツールの固定は残します。この断片だけでは完全な設定になりません。パスは絶対パスで、検査対象リポジトリの外に置きます。

```json
{
  "trivy": {
    "path": "C:/ScanMux/tools/trivy/0.76.1/trivy.exe",
    "sha256": "94618922c9eb324d7099bf217b01504bfc1f87a0d46d6008cb24ec89b1d1a4bb",
    "version": "0.76.1"
  }
}
```

```powershell
scanmux doctor --config C:/ScanMux/config.json --json
scanmux plan C:/work/project --config C:/ScanMux/config.json --json
scanmux scan C:/work/project --config C:/ScanMux/config.json --report-language en --json
scanmux resume C:/work/project --from C:/ScanMux/runs/report.json --config C:/ScanMux/config.json --report-language en --json
```

`plan` は Trivy を起動せず、選択、候補のファイル・モジュール・チャート単位、実行条件を記録します。ランタイムポリシーの部品名は `trivy` です。取得証拠で満たせない配布元の証明要求は拒否します。固定値や手元の取得記録を、配布元の証明として扱ってはいけません。

## 対応する操作と実行

初版の対応は、Windows のローカル `plan`、`scan`、`resume`、`doctor` と、それらが保存した v3 結果の `history`、`recover`、`engine-record`、`engine-history` に限ります。
AI 実行、バッチ・一覧実行、Web、ジョブ、リモート取得、CI 生成、ほかの未対応 v3 取込み・読込み経路は拒否します。

`resume` は同じ計画の必須エンジンすべてを再実行し、以前の Trivy の完了を再利用しません。
`recover` の結果は従来どおり `ERROR` です。
無効化するには任意の固定項目を削除して計画を作り直します。
既存計画から実行時だけ省いたり、過去の結果を書き換えたりしてはいけません。

実行するのは固定の `embedded-config-v1` プロファイルだけです。
Dockerfile、Kubernetes、Terraform、CloudFormation、Helm の設定を検査します。
コミット済みのスナップショットを使い、計画した Terraform モジュールと Helm チャートも単位として扱います。
外部参照、抑制、読めない入力、照合できない計画対象を解析完了にはしません。

Dockerfile の対象には `Containerfile`、`Containerfile.*`、`*.containerfile` も含めます。
compose ファイルと CI の定義は、これらのスキャナーが読まないため計画に入れません。
ただし、中身が Kubernetes や CloudFormation の形をしていれば、その種類として計画します。
ここでいう compose ファイルは、最上位に `services:` がある YAML です。

CI の定義は `.github/workflows/*`、`.gitlab-ci.yml`、`.circleci/config.yml`、`azure-pipelines.yml`、`bitbucket-pipelines.yml`、`.travis.yml` です。
それ以外の判別できない YAML は未解決のままです。

版確認も検査も Windows の制限所有者を通します。版確認は正確に `trivy.exe --version` です。次の固定引数で、`S` は確認済みスナップショット、`W` は非公開の作業領域を表します。

```text
trivy.exe config --config W/trivy.yaml --ignorefile W/empty.ignore --cache-dir W/cache --skip-check-update --skip-version-check --disable-telemetry --misconfig-scanners dockerfile,kubernetes,terraform,cloudformation,helm --include-non-failures --exit-code 0 --format json S
```

ScanMux が空の設定と ignore ファイルを作り、作業・ホーム・一時・キャッシュの場所を `W` 内に固定します。
資格情報、proxy 設定、`TRIVY_*` は継承しません。
対象由来の設定や独自規則は選択しません。
昇格せず、能力を付与しない AppContainer が所有者の Job 内で動きます。
スナップショットと非公開の兄弟領域にある実行ファイルの複製へ読取り・実行を与えます。

`W` の中身には変更権限を与えますが、`W` そのものは削除・名前の変更・権限の変更ができません。
これらの領域にハードリンクのファイルがあれば、権限を与える前に実行を止めます。
通常プロセスへの代替起動はありません。
所有者がない、所有者が昇格している、プロファイル API が使えない、Windows 以外の場合は未起動・非対応です。

`process_owner_appcontainer_elevated_owner` と `process_owner_appcontainer_profile_unavailable` を除くすべての `process_owner_appcontainer_*` コードは `ERROR` になります。
時間と出力量には既存の上限を適用します。

## 結果と検査範囲の証拠

不合格の規則だけを `misconfiguration` の検出にし、根拠の状態は常に `candidate` です。
Trivy 由来の説明文・コード・URL はレポートへ転送しません。
正規化した検出は規則 ID、重要度、fingerprint、確認した相対位置と開始・終了行を保ちます。
位置不明はテキスト・HTML に明記し、SARIF の `locations` を省きます。
検出には人の確認が必要です。
候補0件は設定が安全だという証明ではありません。

Helm の行番号は、元テンプレートではなく生成後の YAML を指します。ScanMux は確認したテンプレートのパスを保ち、元の開始行・終了行は不明として記録します。生成後の範囲は観測を区別するハッシュ入力だけに使い、別の生成資源を同一の検出へまとめません。

検査範囲の受領記録は、計画したファイル・モジュール・チャートの各単位と結果を照合します。
不合格でない規則も完了証拠に使います。
認識対象なしは非対応、欠落・省略・除外・未解決・構文解析失敗の単位は部分的な範囲です。
終了コード0や空でない結果だけでは全単位の解析を示しません。
スナップショット内にあって計画していない対象の結果が返ると、範囲を部分的にして `trivy_target_not_planned` を記録し、その結果の行は報告しません。

スナップショットの外を指す対象は、これまでどおりエラーです。
固定版の試作では、Dockerfile・Kubernetes・Terraform・CloudFormation・Helm でそれぞれ **2・17・8・8・17 件の不合格の規則**、**計52件**を観測しました。
不正な Kubernetes ファイルは Trivy が黙って省略しました。
そのファイル自身の計画単位は部分的な範囲のままにし、ほかの単位の成功によって解析済みにしてはいけません。

ほかのエンジンが完了している場合、Trivy の欠落・未起動・非対応・部分的な範囲は `INCOMPLETE` です。
設定の版が **0.76.1** 以外なら非対応として `INCOMPLETE`、ダイジェストの不一致や実行ファイルが報告する版の不一致は `ERROR` です。
プロセス失敗と不正出力も `ERROR`、全対象を解析した High/Critical または重要度不明の候補は `REVIEW` です。

ツリーの停止未確認、スナップショット変更、計画不整合は `ERROR` です。
既存の優先順位 `ERROR > FAIL > INCOMPLETE > REVIEW > PASS` を維持します。

## 信頼と計測した限界

GitHub-hosted Windows CI のように昇格したランナー、またはプロファイル API を利用できない環境では、AppContainer の実行テストはスキップします。
隔離の証拠は非昇格のローカル実行から得ます。
`SCANMUX_REQUIRE_APPCONTAINER=1` を設定して `npm test -- test/trivy-owner.test.ts` を実行すると、これらのスキップも失敗になります。

ほかのセットアップ失敗は、この設定に関係なくテスト失敗です。

利用者は固定した配布物と内蔵規則を信頼します。侵害された配布物は、検出を見落としたり、与えられた権限を悪用しようとしたりできます。AppContainer の試作では DNS の失敗 **11001** と直接の TCP 接続の拒否 **10013** を観測しました。UDP の `SendTo` は成功し、配送は観測していません。UDP の拒否やすべての通信の遮断の証明ではありません。

試作では、**All Application Packages** に読取りが許された、意図した範囲外の兄弟ファイルを読めました。
Less Privileged AppContainer を使えばこの読取りを塞げます。
ただし、能力を付与しない状態で手元で測ったところ、.NET の検査用プログラムも `trivy.exe --version` も起動できなかったため、ScanMux は使いません。

Windows は AppContainer のプロファイル保存領域も作ります。
後始末の前に所有者が止まった場合は、次に起動した所有者がその所有者の記録をもとに、プロファイルと権限付与を回収します。
詳しくは [Windows のプロセス終了](windows-process-termination.md)（英語のみ）にあります。
上記の権限付与は、厳密なファイルシステムのパスの許可リストや、`W` だけが書込み可能だという保証を成立させません。

計測した場合を超えるライブリポジトリと資格情報の隔離は未確認です。
52件の観測は、形式への完全対応、外部参照の安全、規則の鮮度、配備の安全、設定不備がないことを証明しません。
前提、破れた場合の影響、検査、未確認点は [assumptions.ja.md](assumptions.ja.md) にも記録しています。


## 関連文書

- [導入と最初の検査](getting-started.ja.md)
- [結果の読み方と保存](results.ja.md)
- [実行時の制御](runtime-controls.ja.md)
- [Windowsのプロセス終了](windows-process-termination.md)（英語のみ）
- [ScanMux](../README.ja.md)
