[English](runtime-controls.md) | [日本語](runtime-controls.ja.md)

# 実行時の許可と資源上限を設定する

実行する部品や資源上限を管理するときに、実行方針、配布元の検証、LinuxとWindowsの制限を確認するガイドです。

## 実行時の部品を停止・拒否する

設定schema `2`は、schema 1に必須の`runtimePolicy`を加えた形式です。
`scanmux.job-profile/v2`も同じオブジェクトを持ちます。次のIDとhashは合成値です。

```json
{
  "schema": 2,
  "runtimePolicy": {
    "schema": "scanmux.runtime-policy/v1",
    "id": "00000000-0000-4000-8000-000000000001",
    "revision": 1,
    "state": "active",
    "deny": [
      { "kind": "component", "component": "osv" },
      { "kind": "digest", "component": "git", "sha256": "1111111111111111111111111111111111111111111111111111111111111111" }
    ]
  }
}
```

`state: "stopped"`は、方針を確認する全コマンドを拒否します。保存記録の閲覧も含みます。
`component`規則は部品全体を拒否し、`digest`規則は1つの識別値を拒否します。
ネイティブツールの識別値はファイルのSHA256です。
`codex-security-sdk`は資産manifestのSHA256、`linux-image`はimage IDの16進数を使います。

部品名は`git`、`gitleaks`、`osv`、`docker`、`codex-cli`、`codex-security-sdk`、`linux-image`、`windows-owner`、`node`です。
各コマンドは最初のプロセス起動、認証情報の読取り、接続より前に判定します。
`host-job-scan`は委任先workerでも再判定します。

| コマンド | 確認する部品 |
|---|---|
| `doctor`、`scan`、`deps`、`resume`、`scan-list` | 設定したGit・Gitleaks・OSV |
| `plan`、`plan-list` | Git・Gitleaks |
| `ai-plan`、`ai-scan` | それぞれ`plan`・`scan`と同じツールにAI部品を追加 |
| `runner-check` | runnerのCodex CLI群・Docker・image・Gitleaks |
| `history`、`ci-check`、`recover`、`dispositions`、`policy-check`、`job-export`、`job-recover` | 出力検査用のGitleaksだけ |
| `job-scan`、`host-job-scan` | プロファイルで指定した部品 |

拒否時は同じ固定コードを返し、`deps`の終了値は`2`（失敗）、他のコマンドは`4`です。
検査が完了した`deps`は、base指定時に追加分があるか、base未指定時に現存する脆弱性情報があれば終了`10`、それ以外は`0`です。終了`0`は安全性の`PASS`ではありません。
部品名のハイフンはコード内ではアンダースコアになります。

| コード | 意味 |
|---|---|
| `runtime_policy_stopped` | 方針が停止状態 |
| `runtime_policy_denied_<component>_component` | 部品全体の拒否 |
| `runtime_policy_denied_<component>_digest` | 識別値の拒否 |
| `runtime_policy_unidentified_<component>` | 識別値を確認できない部品 |

`deps`以外のコマンドでは、エラーに拒否した方針を記録します。

```json
{"schema":"scanmux.error/v1","gate":"ERROR","exitCode":4,"error":"runtime_policy_stopped","policy":{"id":"00000000-0000-4000-8000-000000000001","revision":1,"state":"stopped","sha256":"<canonical policy SHA256>"}}
```

`deps`は同じ拒否コードを`{"schema":"scanmux.error/v1","exitCode":2,"error":"runtime_policy_stopped"}`の形式で返します。

v1の方針は配布元の検証や更新記録を行いません。
一致する拒否規則がない`active`も安全性の表明ではありません。
実行中のプロセスは停止せず、設定を再読込みしません。
Web画面はschema 2に対応せず、`runtime_policy_entry_unsupported`で拒否します。

hashなしで起動するランタイムは3つあります。
AI経路のDocker、AIコンテナ内の`/usr/bin/git`、AI・`job-scan`・`host-job-scan`のコンテナ内の`/usr/local/bin/node`です。
これらの部品へdigest規則を指定すると、コマンドを拒否します。
そのdigestがhash済みホスト`git`か`node`と一致すると`runtime_policy_denied_<component>_digest`です。
一致しなければ`runtime_policy_unidentified_<component>`です。
component規則は通常どおり拒否します。ホストジョブのコンテナ終了処理は確認対象外です。

## 配布元を検証してエンジンの更新を記録する

`scanmux.runtime-policy/v2`の`provenance`は、固定した`gh`、ローカル台帳の固定値、部品ごとの要求を追加します。
次の値は合成例です。

```json
"provenance":{
  "verifier":{"path":"C:/scanmux/tools/gh.exe","sha256":"<gh SHA256>","version":"2.0.0"},
  "ledger":{"path":"C:/scanmux/engine-ledger.jsonl","entries":0,"head":"0000000000000000000000000000000000000000000000000000000000000000"},
  "require":[
    {"component":"gitleaks","level":"recorded"},
    {"component":"osv","level":"publisher","publisher":{"repository":"example/scanner",
      "certIdentity":"https://github.com/example/scanner/.github/workflows/release.yml@refs/tags/v1.0.0",
      "oidcIssuer":"https://token.actions.githubusercontent.com","predicateType":"https://slsa.dev/provenance/v1","runner":"github-hosted"}}
  ]
}
```

| 要求 | 起動前に行う確認 |
|---|---|
| `recorded` | エンジンのSHA256が固定した台帳内にあること |
| `publisher` | 上記に加え、配布元の証拠をオフラインで検証すること |

エンジン、bundle、trusted rootを非公開のコピーへ移し、hashを再確認します。
固定した版の`gh`へ渡し、`attestation verify`を`--custom-trusted-root`付き、tokenなしで実行します。
終了0と、エンジンSHA256・predicate type・全証明書期待値に一致するJSONが必要です。
GitHub-hosted runnerであることも照合します。

更新を記録する要求を作ります。
`evidence`は`{"kind":"none","reason":"publisher_evidence_unpublished"}`でも構いません。

```json
{"schema":"scanmux.engine-record/v1","component":"osv","platform":"windows-x64","version":"1.0.0","change":"Update OSV","artifact":"C:/scanmux/tools/osv.exe","evidence":{"kind":"sigstore-slsa","bundle":"C:/scanmux/osv.sigstore.json","trustedRoot":"C:/scanmux/trusted-root.jsonl","sourceRef":"refs/tags/v1.0.0","sourceDigest":"<source commit SHA>"}}
```

`scanmux engine-record /absolute/request.json --config /absolute/config.json`でファイルをhashし、同じ方法でSigstore証拠を検証します。
失敗時は台帳へ追記しません。固定範囲内に同じ識別値と証拠があれば、既存の記録を返します。

固定位置より後に有効な行がある場合は拒否します。
その行の`seq`・`component`・`sha256`・`change`と、ファイルの`entries`・`head`を`ledger`に表示します。
ハードリンク、実行中に置換された台帳、UNCの証拠も拒否します。
`version`の形式は`x.y.z`です。
出力されたツール固定値を`tools`へ、台帳固定値を`provenance.ledger`へ貼り、方針の`revision`を上げてください。

同じ`--config`で`engine-history`を実行すると、固定した記録を`current`・`superseded`・`denied`として表示します。
終了0は台帳を読めた意味で、PASSではありません。

拒否はエンジン起動前に行い、`deps`の終了値は`2`（失敗）、他のコマンドは`4`です。

| コード | 原因 |
|---|---|
| `provenance_invalid_<component>` | 署名を拒否 |
| `provenance_unverifiable_<component>` | 使える証拠がない、コピーを読めない・変更された、`gh`が失敗 |
| `provenance_unrecorded_<component>` | hash未確認、または台帳にない |
| `provenance_ledger_mismatch` | 台帳の固定値が不一致 |

`deps`以外では、最初の3つは`policy`の後に`"engine":{"component":"osv","state":"invalid","reason":"signature_rejected","ledgerSeq":1}`のような情報を追加します。
`provenance_ledger_mismatch`には`policy`も`engine`も追加しません。

ネイティブコマンド、`job-scan`、`host-job-scan`でv2を適用します。
ジョブのLinuxエンジンはmount前にホストで検証します。`serve`はschema 2を拒否します。

台帳が検出するのは固定した設定に対する変更だけで、認証済みの履歴ではありません。
`recordedAt`はローカル時計です。
Gitleaks 8.30.1は署名の証拠を公開していないため、`publisher`では必ず拒否します。`recorded`を使ってください。
Git for WindowsのAuthenticode、コンテナ内部品、image、資産manifestの配布元はオフライン検証できません。
`gh`は信頼の基点です。固定し、停止とv2の`deny`規則を適用しますが、自己検証はしません。

## 資源上限を指定して単一のオフラインLinux検査を実行する

`job-scan`は、計画・スナップショット作成・オフライン検査・DBコピー・正規化・出力の秘密検査を、一つのLinux/x64コンテナ内で実行します。
完了したエンジンの記録はコンテナ外に保存し、ホスト側の書込み・同期・クローズと確認応答の完了まで次のエンジンを始めません。
対応対象はWindowsまたはLinux上の、通常の単一ローカルGitリポジトリです。
AI、URL取得、別jobの再開、従来のネイティブ検査への自動切替はしません。

利用者が管理するローカルDocker、正確なimage IDで固定して事前配置したイメージ、固定版のLinux用Gitleaks/OSV、必要に応じてオフラインDBを用意してください。
イメージには申告したNode.js、`/usr/bin/python3`、`/usr/bin/git`が必要です。
版とSHA-256を照合し、対象外の場所に専用profileを作成します。

Windowsのローカル`npipe:`、Linuxのローカル`unix:`接続だけを受け付けます。
既存Docker認証設定の利用やimageの自動取得はありません。

### オフラインジョブのプロファイルを作る

次はプロファイルの全項目を含む例です。
山括弧の値は、それぞれ独立して確認した実値へ置き換えてください。
容量と時間は試験用の明示値で、既定値、推奨性能、サービス保証ではありません。
Windowsのパスはホスト上のファイルを指します。Gitleaks/OSVにはLinux用バイナリが必要です。
Linuxではホストの絶対パスと、`unix:///var/run/docker.sock`などのローカル接続先を使います。

```json
{
  "schema": "scanmux.job-profile/v1",
  "name": "offline-local",
  "scope": "offline-local",
  "docker": {
    "tool": { "path": "C:\\ScanMux\\tools\\docker.exe", "sha256": "<verified Docker executable SHA-256>", "version": "<verified version>" },
    "endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine"
  },
  "image": "sha256:<verified local image ID>",
  "runtime": {
    "nodeVersion": "24.22.1",
    "python": { "path": "/usr/bin/python3", "sha256": "<verified image Python SHA-256>", "version": "<verified version>" },
    "git": { "path": "/usr/bin/git", "sha256": "<verified image Git SHA-256>", "version": "<verified version>" }
  },
  "tools": {
    "gitleaks": { "path": "C:\\ScanMux\\tools\\gitleaks-linux", "sha256": "<verified Linux Gitleaks SHA-256>", "version": "8.30.1" },
    "osv": { "path": "C:\\ScanMux\\tools\\osv-linux", "sha256": "<verified Linux OSV SHA-256>", "version": "2.7.0" }
  },
  "osvDatabase": "C:\\ScanMux\\offline-db",
  "scan": { "timeoutMs": 300000, "maxOutputBytes": 8388608, "maxFileBytes": 8388608, "maxSnapshotBytes": 67108864, "maxFiles": 10000 },
  "limits": {
    "cpuCount": 2, "memoryBytes": 2147483648,
    "tmpBytes": 67108864, "workBytes": 536870912, "shmBytes": 1048576,
    "pids": 128, "wallMs": 300000, "cleanupTimeoutMs": 30000, "retainedBytes": 134217728
  }
}
```

| 項目 | 意味 |
|---|---|
| `schema` / `scope` | `scanmux.job-profile/v1` / `offline-local`で固定 |
| `docker.tool` / `docker.endpoint` | ホスト実行ファイルの絶対パス・SHA-256・版と、明示したローカル接続先 |
| `image` / `runtime` | 事前配置したimage ID、Node.jsの版、イメージ内Python/Gitの固定パス・SHA-256・版 |
| `tools` | Linux用Gitleaks 8.30.1と、任意のOSV 2.7.0のホスト上の絶対パス・SHA-256・版 |
| `osvDatabase` | 対象外のDBディレクトリ、または`null` |
| `scan` | 従来の有限な検査時間・出力サイズ・ファイルサイズ・スナップショットサイズ・件数 |
| `limits` | `cpuCount`、`memoryBytes`、`tmpBytes`、`workBytes`、`shmBytes`、`pids`、`wallMs`、`cleanupTimeoutMs`、`retainedBytes`をすべて明示 |

Docker Desktopを更新すると、`docker.tool`で固定したDocker実行ファイルのパス・SHA-256・クライアント版が変わる場合があります。
その場合、`job-scan`と`host-job-scan`は、ハッシュ不一致なら`job_asset_mismatch`、クライアント版の不一致なら`job_boundary_unverified`で停止します。
更新後の実行ファイルを確認し、移動していれば`docker.tool.path`を直し、`docker.tool.sha256`を再計算して、`docker.tool.version`を`docker version`に表示されるクライアント版へ変更してください。
例のWindowsパスでは、次のコマンドで新しいSHA-256とクライアント版を表示できます。

```powershell
(Get-FileHash -LiteralPath 'C:\ScanMux\tools\docker.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
& 'C:\ScanMux\tools\docker.exe' version --format '{{.Client.Version}}'
```

ScanMux自身がこれらの固定値を更新することはありません。

未知の項目、任意コマンド、環境変数の追加、任意mount、資格情報、対象内のprofile・ツール・設定は拒否します。
DBの親ディレクトリは渡さず、対応4エコシステムの`osv-scalibr/<ecosystem>/all.zip`、`database-receipt.json`、`acquisition-started`のうち実在する固定ファイルだけを読み取り専用で渡します。
欠落や不正を自動取得で補いません。

`tools.osv`を省略した場合も、必要な検査が未実施であることを残します。

### Linuxジョブを実行して結果を書き出す

```text
scanmux job-scan C:\source\repository --job-profile C:\ScanMux\job-profile.json --json
scanmux job-scan C:\source\repository --job-profile C:\ScanMux\job-profile.json --base BASE_SHA --head HEAD_SHA --json
scanmux job-export C:\private-run\job.json --config C:\ScanMux\native-reader.json --report-language ja
scanmux job-recover C:\private-run --config C:\ScanMux\native-reader.json --report-language en
```

閲覧用設定は従来のConfig形式で、ホスト用Gitleaksを出力検査に使います。
記録された元のホストディレクトリが必要ですが、閲覧・復旧で対象Git、検査エンジン、SDK、Dockerは動かしません。
`job-export`は元の解析bytesを保持したJSON/HTML/SARIFを、新しい非公開ディレクトリへ出力します。

実在するReportも完全な途中保存もない場合は`job_analysis_unavailable`として拒否し、元の`job.json`を残します。
説明用の空Planや空Reportは作りません。

`job-recover`は最終Reportや保存済み終了状態を信用せず、検証できた途中保存だけをERROR/4で出力します。検査やコンテナを再起動せず、実際の終了が確認できたとも主張しません。従来の閲覧・再開コマンドは新しいjob記録を拒否し、自動で中身を取り出しません。

`job.json`の実行判定と、Linuxで作った解析Reportの判定は別々に表示します。
元のホストパスと実際のLinuxパスを併記し、内側のPlanをWindows用や承認済みAI Planへ書き換えません。
資源停止と終了を確認した外側の実行がINCOMPLETEでも、途中保存の解析は完了未確認のERRORのままです。
検出済みのFAILは保持し、独立した障害や終了未確認があればERRORを優先します。

保存bytesだけでは、メタデータ自身の保存完了や現在のプロセス終了を再認証できません。

### Linuxの上限の適用範囲を確認する

上限の適用範囲は次のとおりです。

- `cpuCount`はCPUの使用率上限で、累積CPU秒数ではありません。メモリにはswapを認めず、`/tmp`、`/work`、`/dev/shm`を申告容量に制限します。容量は4096の正の倍数です。`pids`には監督側と全子孫を含みます。
- `wallMs`はLinuxの検査処理と、保存確認応答を受け付ける期間に適用します。終了処理とホスト側の最終確認には別の`cleanupTimeoutMs`を使い、その間に新しい検査を始めません。コマンド全体の所要時間を保証するものではありません。
- `retainedBytes`は結果ファイルの論理bytesの累計上限です。job計画1個、4エンジン分の本文と保存票8個、最終Report1個、job記録1個の最大11ファイルを扱います。中間保存を始める前に、最終2ファイル分の`2 * maxOutputBytes`を予約し、計画の実サイズも残りに収まることを確認します。書込み前の容量拒否や未確認の末尾から、次のエンジンを始めません。
- ホスト側の制御、Docker基盤、固定アプリ資材、保存結果の閲覧・出力は、Linux側のCPU・メモリ上限の外です。ホスト上の保持出力には物理ファイルシステムの容量制限がありません。これらは記録にも明示し、この限定経路だけでjob全体の資源要件を完成扱いしません。

ディスク不足の原因観測は、上記3領域の通常ファイルに対する`write`/`pwrite64`に対応します。
未対応の書込み、壊れた出力、単なるSIGKILL、観測欠落を容量不足へ読み替えません。
同じ利用者によるホスト側の同時変更は未対応です。
コンテナは通信なし、root・対象・資材は読み取り専用、UID 1000、追加権限なしで動作します。
カーネル・追跡・イメージ・隔離条件を確認できなければ対象処理を始めず、権限を増やした再試行もしません。

macOS、AI、URL、Web、複数repo、再開は本コマンドの対応範囲外です。
従来コマンドへの`--job-profile`も拒否します。

## Windowsの調整役と子孫プロセスに上限を設定する

`host-job-scan`は、上記のオフラインLinuxジョブにWindows Job Objectによる制限を加えます。Windows/x64、Node 24.x、Docker DesktopのローカルLinux用パイプに対応します。専用のホストプロファイルが必要です。従来の`job-scan`とそのプロファイルは引き続き利用できます。UNC・デバイスパス、ネットワーク先のDocker接続は拒否します。

### Windowsジョブの管理役をビルドする

信頼する小さな管理プログラムを、導入済みWindows PowerShell 5.1/.NETコンパイラで明示的にビルドします。対象リポジトリ外に、新しい専用の非公開ディレクトリを指定してください。

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\build-windows-job-owner.ps1 -OutputDirectory C:\ScanMux\owner-build
C:\ScanMux\owner-build\scanmux-windows-job-owner.exe --version
Get-FileHash -Algorithm SHA256 C:\ScanMux\owner-build\scanmux-windows-job-owner.exe
Get-FileHash -Algorithm SHA256 C:\Tools\node.exe
C:\Tools\node.exe --version
```

パッケージには管理プログラムの2つのソースとビルドスクリプトを含め、実行ファイルや自動ビルド・インストール処理は含めません。
ビルド結果には各ソースと実行ファイルのSHA-256を出力します。
現行ビルドの管理プログラムはversion `1.1.0`です。
実ファイルのハッシュを小文字の16進数で記録してください。
ScanMux起動時とプロファイルには、同じNodeの絶対パスと実際のversionを指定します。

コンパイルできない場合はローカルの前提環境を確認してください。
実行ポリシーの変更やコンパイラの自動導入は行いません。

### ホストプロファイルを作る

対象リポジトリ外に、次の形式の非公開JSONプロファイルを作成します。

```json
{
  "schema": "scanmux.host-job-profile/v1",
  "name": "windows_offline",
  "scope": "windows-offline-local",
  "offlineProfile": "C:\\ScanMux\\job-profile.json",
  "owner": {
    "path": "C:\\ScanMux\\owner-build\\scanmux-windows-job-owner.exe",
    "sha256": "REPLACE_WITH_ACTUAL_LOWERCASE_SHA256",
    "version": "1.1.0"
  },
  "node": {
    "path": "C:\\Tools\\node.exe",
    "sha256": "REPLACE_WITH_ACTUAL_LOWERCASE_SHA256",
    "version": "24.22.1"
  },
  "limits": {
    "cpuRate": 2500,
    "memoryBytes": 536870912,
    "wallMs": 300000,
    "cleanupTimeoutMs": 30000
  }
}
```

ハッシュ2か所とNodeのversion例は、確認した実値に置き換えてください。
`offlineProfile`は従来の`scanmux.job-profile/v1`を指し、Linux側の制限を維持します。
`cpuRate`はWindows CPU-rate単位の1〜10000の整数で、コア数ではありません。
`memoryBytes`はJobのコミット済みメモリの上限で、4096の正の倍数にします。

2つの時間は正のミリ秒値で、合計2147483647以下が必要です。
これらは利用者が明示する値で、自動の既定値ではありません。

既存のホストプロファイルv1は、明示的に固定した管理役`1.0.0`を維持することも、別にビルドして固定した`1.1.0`を使うこともできます。プロファイルや実行ファイルのハッシュは自動移行しません。再ビルドは新しいディレクトリへ行い、プロファイルも明示的に更新してください。

### v2で保存記録の割当量を制限する

ホストの固定保存ファイルのデータ割当量も制限する場合は、上記の全項目を保持し、管理役を`1.1.0`とした別の**ホストプロファイルv2**を作成します。ルート階層の変更項目は次のとおりです。

```json
{
  "schema": "scanmux.host-job-profile/v2",
  "retained": { "allocatedBytes": 134217728 }
}
```

このブロックは変更項目だけです。
他の項目と確認済みハッシュを残し、完成したプロファイルを別の非公開ファイルへ保存して`--host-job-profile`で指定します。
v2はローカルNTFS専用です。
`allocatedBytes`は利用者が明示する正の安全な整数で、実測したボリュームのクラスタサイズの倍数にします。
上限の切上げや通常書込みへの切替は行いません。

65536 bytesの実行前記録、4096 bytesの制御記録2つ、参照先の下位プロファイルの`scan.maxOutputBytes`を上限とする記録7つについて、それぞれクラスタ単位に丸めた最大予約量が収まる必要があります。
予約不足や未対応の保存先はコンテナ作成前に拒否します。
下位プロファイルの`retainedBytes`は別の論理バイト予算です。

実行用コピーの各固定ファイルも`scan.maxOutputBytes`に収まる必要があり、小さすぎる出力設定では、割当予約が収まっても実行準備に失敗します。

v2では、実際のデータ割当量と未使用の管理情報予約に、保存要求全体が収まるかを確認します。
途中保存の本文と受領票は、作成前にまとめて受け付けます。
予算による拒否では両ファイルを作らず、確定済みの途中保存と割当量による停止原因を保持します。
正常な終了を確認できた停止はINCOMPLETEですが、先行エラー・入出力失敗・保存helperの消失・終了未確認はERRORです。
未受理や書込み途中のファイルも計上し、上書きや再試行はしません。

設定上限より前のディスク満杯は、上限到達とは扱いません。

v2の`host-job.json`は、外側の結果を保存する前の実測値と、その結果用に残した予約を`retained.snapshot`へ記録します。
まだ書いていない結果ファイルを測定済みとは主張しません。
`retained.stop`は割当量による拒否、`retained.scope`は元の実行で保存した観測の範囲を示します。
出力ではこれらをJSON・HTML・SARIFへ保持します。

記録された割当量の証拠がない復旧では、実測値を未確認のままERRORにします。
コピー先・出力先へ、元の容量制限が適用されるわけではありません。

対象は、書込み途中の残存ファイルを含む、固定された保存記録のデータ割当です。NTFSのディレクトリ・利用者quotaやジョブ全体のディスク上限ではありません。実行用コピー、空の管理用ディレクトリ、ファイルシステム管理情報、OS/Dockerの保存領域、出力先は対象外です。管理用領域に想定外の内容があれば、その実行の保証を認めません。同じWindows利用者の別プロセスによる同時変更には対応しません。

### Windowsジョブを実行して結果を書き出す

```powershell
C:\Tools\node.exe .\bin\scanmux.mjs host-job-scan C:\source\repository --host-job-profile C:\ScanMux\host-job-profile.json --json
C:\Tools\node.exe .\bin\scanmux.mjs host-job-scan C:\source\repository --host-job-profile C:\ScanMux\host-job-profile.json --base BASE_SHA --head HEAD_SHA --json
scanmux job-export C:\private-run\host-job.json --config C:\ScanMux\native-reader.json --report-language ja
scanmux job-recover C:\private-run --config C:\ScanMux\native-reader.json --report-language en
```

Windowsの主処理は停止状態で作成され、最初の命令を実行する前から設定済みJobに所属します。
子孫はJobから離脱できません。
管理役の最後のJob handleが閉じられると、所属するプロセス群が終了します。
終了確認には、生成時刻を照合した全プロセスhandleの終端と、OSの累積生成件数との一致を要求します。
追跡欠落・容量超過・終了未確認はエラーです。

主処理の全終了確認後に、同じ資源上限の別Jobで終了処理を行い、全体で1つの`cleanupTimeoutMs`を共有します。
コンテナは事前確定した名前・image・job labelだけで照合し、保存IDがあればその一致も要求します。
識別情報が違えば操作しません。

外側の結果は`host-job.json`です。
内部の`delegated-job.json`は下位の観測記録で、通常ジョブとして直接出力できません。
期限や中断の後も、確定したエンジンの途中保存を利用できます。
最終解析ファイルの書込みと応答確認が済んでも、実行完了を確認できなければ途中保存を選び、最終ファイルを完了結果へ昇格させません。
先に受理したエラーは維持します。
メモリ上限の設定や一般的なプロセス失敗だけでは、メモリ不足が原因とは判定しません。

`job-export`は保存結果を照合し、外側の判定と途中解析であることを付けたJSON・HTML・SARIFを新たに出力します。
`job-recover`は保存済みの途中解析だけを使い、常にERROR/4を返します。
管理プログラム・Docker操作・再検査は開始しません。
保存ファイルから現在の所有権や停電時の耐久性は再認証できません。
管理役が消失すると終了未確認となり、コンテナが残ることがあり、復旧処理はその除去を主張しません。

別途片付けるときは、記録された正確なコンテナ識別情報を利用者が照合します。

### ホストの上限と期限を確認する

WindowsとLinuxの予算は別々です。
信頼する管理役、最初の受付、保存結果の読取りと出力はWindowsの強制上限から除外します。
v1のホスト保存出力は論理的な容量計上だけです。
明示的なv2では、前述の固定保存データの割当量制限を追加します。
どちらもディレクトリ全体の物理quotaは設定しません。

| 時間枠 | 上限と結果 |
|---|---|
| `host-job-scan`全体 | 開始から`wallMs + 4 × cleanupTimeoutMs` |
| 管理役の起動前 | 共通の`3 × cleanupTimeoutMs`。超過時は管理役を起動せず`host_job_admission_deadline` |
| 各`gh`の版確認と来歴検証 | 共通の起動前枠に残っている時間以内 |
| 管理役 | `wallMs + cleanupTimeoutMs` |
| 管理役の終了処理期限を過ぎた後 | `host_job_command_deadline`で停止し、`host-job.json`は書かない |

起動前の期限で確認が打ち切られた場合も、実行方針と来歴の拒否はそれぞれのコードを維持します。

> Q. コマンドの期限は厳密な実時間の保証ですか。
>
> A. いいえ。途中で止められない処理は超過するため、報告では`totalCommandWallGuarantee: false`を維持します。

超過する処理には、ツール確認での実行ファイル全体の読取り、管理役のあとの保存記録の読取りと確認、記録1回分の書込みがあります。
管理役を止めてから終了するまでの時間も上限を超える場合があります。
ホストとLinuxの合計予算や、ジョブ全体の資源要件の完了を意味しません。
同じ利用者による同時変更、macOS、AI・URL・Web・複数リポジトリ・再開ジョブは、このコマンドの対象外です。

## CIでのLinuxジョブの結合検証

すべてのプルリクエストで、`ubuntu-24.04`上の`linux-job-integration`を実行します。
生成した`SCANMUX_NATIVE_JOB_PROFILE`でnative supervisorのテストを実行し、失敗・スキップ・テスト件数ゼロを不合格にします。
固定したLinux用DockerとGitleaksを使い、128 MiBのテキストを対象に実際の`job-scan`も実行します。
LIMITは実測ディスク上限とINCOMPLETE/3、CONTROLはその上限に達しない検査完了、STOPは実行中のGitleaksを観測してからの中断を確認します。
CONTROLではGitleaksの完了も要求します。
LIMITとSTOPでは、記録された終了確認項目、独立したコンテナ消失確認、Docker daemonの応答を要求します。
STOPでは、既知の断続的な問題である`job_closure_unverified`がないことを要求せず、既存の終了確認項目を維持します。

LIMITが検出するのはスナップショットの増加です。
これらのシナリオは、書込み途中のscannerを強制終了できた証拠ではなく、対象も1種類のLinuxホストです。
検証用プログラムの出力と判定一覧をartifactへ保存し、認証情報や環境変数の一覧は含めません。
ソースと非公開の一時ディレクトリはアップロード対象から外しています。

LinuxのDockerホストで`bash scripts/ci-linux-job.sh`を実行できます。
`SCANMUX_LINUX_JOB_WORK`で実行ごとに新しい実行可能な専用bind mount先を指定し、省略時は`$RUNNER_TEMP/scanmux-linux-job`を使います。
Docker Desktopでは`/tmp`が`noexec`のため、daemonのLinuxホスト上の`/opt/scanmux-linux-job`の下で実行ごとに別のディレクトリを使います。
準備にはネットワーク接続と`.github/scanmux/linux-job-pins.json`の確認済みimage digestが必要です。
検査コンテナのネットワークは無効です。
検証用プログラムはUID 1000へ権限を下げ、Docker socketのグループだけを引き継ぎます。
証拠と実行ディレクトリは確認用に残します。

## 関連文書

- [導入と最初の検査](getting-started.ja.md)
- [AI検査](ai-scan.ja.md)
- [結果の読み方と保存](results.ja.md)
- [Windowsのプロセス終了](windows-process-termination.md)（英語のみ）
- [ScanMux](../README.ja.md)
