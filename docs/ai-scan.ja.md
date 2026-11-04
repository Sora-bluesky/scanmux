[English](ai-scan.md) | [日本語](ai-scan.ja.md)

# Linux接続を確認してAI検査を実行する

任意のLinux接続診断と隔離AI検査の手順です。専用の実行資材と認証を準備し、送信範囲を確認するときに使ってください。

## 推論せずにLinux接続を確認する

追加の `runner-check` は、ChatGPT認証の種類、利用者に提示されたDaybreakの対応プログラム、モデルを使わない隔離Linux接続、終了処理を製品CLIから診断します。推論や対象ソースの送信は行わず、AI検査を有効化する機能ではありません。

現在の対応はWindowsホスト、Docker DesktopのLinux engine、公式Codex **0.163.0** のWindows/Linux実行ファイルです。
この明示的な診断だけがOpenAIへ認証・モデル情報を照会します。
通常のoffline検査と `doctor` は診断を実行しません。
既存のChatGPTログインを利用し、環境変数のAPIキーへ切り替えたり、資格情報をコンテナへコピーしたりしません。

対象リポジトリ外の信頼する設定へ`runner`を追加します。

| 項目 | 値 |
|---|---|
| `codex`、`linuxCodex`、`docker` | ほかのツールと同じ、絶対`path`・`sha256`・`version`を持つ実行ファイルの記録 |
| `image` | 導入済みの対応Linux imageの`sha256:…` |
| `authHome` | 既存ホストのCodex home |

`disabledMcpServers` と `disabledPlugins` に、この診断プロセスで無効化する設定済み接続名の配列を指定します。実効設定も診断threadの作成前に照合します。バイナリやimageの自動取得はなく、hash不一致、想定外の接続・要求は拒否します。端末固有の設定は非公開にしてください。

モデルを使わない診断を明示的に実行します。

```sh
node bin/scanmux.mjs runner-check --config /absolute/config.json --json
```

使い捨てコンテナは通信なし・capabilityなし・root読取り専用で、固定executorと空の診断フォルダーだけをmountします。
中継は全プロセス要求、ファイル内容の読取り、書込みを拒否します。
| 結果の項目 | 値 | 意味 |
|---|---|---|
| `codeExecution` | `"not_checked"` | コード実行は未確認です。 |
| `accessProgramEffective` | `"unknown"` | モデル一覧は利用可能な選択肢を提示しますが、固定app-serverの仕様は応答ごとの実効プログラムの証拠を返しません。 |

出力の項目は`codeExecution: "not_checked"`と`accessProgramEffective: "unknown"`です。

| 診断の結果 | 判定 | 終了コード |
|---|---|---:|
| 接続検査が成功 | `INCOMPLETE` | 3 |
| 検査が失敗 | `ERROR` | 4 |

この診断は対象検査を許可せず、実効Daybreakを証明しません。対象検査には別のAI計画の手順を使います。

## 計画を確認して隔離AI検査を行う

### AI実行に必要なもの

AI経路はWindowsとDocker DesktopのLinux engine、変更のないローカル単一Gitルートに対応します。
Codex Security **0.5.1**、bundled plugin **0.1.95**、`ai-plan`が開示する固定imageと資産manifestを使います。
資産は事前に用意してください。
ScanMuxは導入・ダウンロードしません。

資産と、認証済みで所有者だけがアクセスできる専用SIWC storeを、対象の外かつ互いに重ならない場所へ置きます。
通常のCodex認証・APIキー・ブラウザーsessionは読みません。

Codex Security 0.5.1のCLI/SDK契約を確認しました。
AI経路はChatGPT認証とOpenAIを使い、`daybreak_blue`を任意の上位設定として要求します。
実効値が`standard`でもAI検査として認めます。要求値と実効値は別々に記録します。
API従量課金には自動で切り替えません。
ホストのChatGPTログインは、実効Daybreakアクセスやアカウントの利用枠を証明しません。
通常のオフラインコマンドのAI呼出しは0です。明示的なAI実行は観測した使用量を個別に記録します。
実行時検証を省略するフラグはありません。

### AI実行を設定する

外部のコントローラー設定へ`ai`を追加します。
例の上限は実推論への推奨値ではありません。処理量に合わせて正の整数を明示してください。
時間の単位はすべてミリ秒です。

```json
{
  "ai": {
    "assetsRoot": "C:/operator/scanmux-assets",
    "credentialStore": "C:/operator/scanmux-siwc",
    "reasoningEffort": "high",
    "commandTimeoutMs": 120000,
    "cleanupTimeoutMs": 120000,
    "workerResources": {
      "cpuCount": 4,
      "memoryBytes": 536870912,
      "tmpBytes": 33554432,
      "workBytes": 67108864,
      "shmBytes": 4194304
    },
    "limits": {
      "maxRequests": 5,
      "maxTotalOutputTokens": 20,
      "maxOutputTokensPerRequest": 5,
      "maxInputBytesPerRequest": 1048576,
      "maxResponseBytesPerRequest": 262144,
      "maxToolCalls": 13,
      "maxToolResultBytes": 262144,
      "timeoutMs": 900000
    },
    "ipc": { "maxFrameBytes": 8388608, "maxBytes": 8388608, "maxFrames": 18 }
  }
}
```

| 項目 | 必要な値 |
|---|---|
| `assetsRoot`、`credentialStore` | 実在する絶対パスのディレクトリ |
| `reasoningEffort` | `high` |
| `limits` | `maxRequests`、`maxTotalOutputTokens`、`maxOutputTokensPerRequest`、`maxInputBytesPerRequest`、`maxResponseBytesPerRequest`、`maxToolCalls`、`maxToolResultBytes`、`timeoutMs` |
| `ipc` | `maxFrameBytes`、`maxBytes`、`maxFrames` |
| `workerResources` | `cpuCount`、`memoryBytes`、`tmpBytes`、`workBytes`、`shmBytes` |
| `commandTimeoutMs`、`cleanupTimeoutMs`、各`timeoutMs` | ミリ秒単位の時間 |

最上位の`timeoutMs`は計画作成・静的検査・Linux起動を含むコマンド全体の期限です。
工程ごとの上限で延長しません。
`cleanupTimeoutMs`は別枠の有限な終了時間で、推論を開始できません。
全候補ソースの秘密検査とLinux起動が済んだ後、最初の許可された呼出しで専用認証を読取り専用で読みます。
期限切れ・lock中・リンク・形式不正・非公開権限不足なら停止します。
ログイン、更新、自動再試行は行いません。

### workerの資源上限を設定する

`workerResources`はLinux workerとその子孫に、CPU使用率の上限、swapなしのメモリ上限、`/tmp`・`/work`・`/dev/shm`それぞれの容量を設定します。
各byte値は4096の倍数、memoryは6MiB以上、CPU数は正の整数です。
一時領域と共有メモリもメモリ上限へ算入されます。
CPUの抑制回数は上限が働いた観測として残し、それだけで失敗とはしません。
累積CPU時間の予算とは別です。
上の設定例の数値は開発検証の例で、本番向け推奨値ではありません。

### 資源とSDKの停止原因を確認する

固定Linux環境にはcgroup v2が必要です。
起動前のcontainer設定に加え、worker内の実cgroup値とファイル領域の容量を確認します。
観測の欠落や要求値との不一致は検査完了にしません。
メモリ・容量・期限の超過が判明し、ソース不変・使用量・停止が確認できた場合は原因付き未完了とします。
別の失敗や停止未確認はエラーを維持し、既存FAIL/ERRORの優先を下げません。

終了値・OOM状態を観測してから自分のcontainerを除去し、自動で再推論しません。

SDKの失敗は、容量不足の文章や同時の資源超過観測だけではエラーのままです。
固定SDKが最初に行うPythonの検査登録では、SQLite本来の容量不足例外を保持し、同じ例外で子プロセスが終了したことを確認します。
呼出しの対応、workerの保全、SDKの後始末、ホスト側の終了確認も成立した場合だけ、容量不足による未完了とします。
別の異常との混在、異なる終了例外、観測の欠落、後段のSDK失敗は元の失敗分類を維持します。

任意項目`runtime.sdkInitializationObservation`には、この限定した証拠をSQL・エラー本文・スタックなしで保存します。
SDK内部の容量不足を網羅しません。
workerの直接観測と、ホストが確認したOOM・期限超過は別の証拠経路です。

GitHub-hostedの`ubuntu-24.04` runnerでSDK 0.5.1を使い、ネットワーク接続とprovider呼出しなしで、空きブロックのないファイルシステムを計測した結果は次のとおりです。

| SDKの処理 | ファイルシステム | 子プロセスでのSQLiteの結果 | ScanMuxの結果 |
|---|---|---|---|
| 最初の`register-cli-scan`、新規データベース | tmpfs | `SQLITE_FULL` | 上記の条件を満たす場合は`resource_disk_exceeded` |
| その他のworkbench command、既存データベース | tmpfs | `SQLITE_IOERR_SHMSIZE` | 容量不足の原因として扱わない |
| `register-cli-scan`を含むすべてのworkbench command | ext4 | `SQLITE_CANTOPEN` | 容量不足の原因として扱わない |

計測したその他のworkbench commandは`get-cli-scan-resume`、`get-scan`、`get-scan-feedback`、`set-scan-thread`、`set-scan-cost-limit`、`prepare-scan-completion`、`finalize-scan-usage`、`fail-scan`です。いずれもデータベースを開いてマイグレーションを適用するため、読取りも失敗します。

`SQLITE_IOERR_SHMSIZE`と`SQLITE_CANTOPEN`には他の原因もあるため、ScanMuxはディスク容量不足の原因として扱いません。これらの失敗でSDKの実行が終わる場合は、`worker_sdk_initialization_failed`や`worker_sdk_finalization_failed`など、元の段階のエラーコードを維持します。SDK自身のエラーチェーンにはネイティブエラーコードがなく、すべての`code`はnullでした。workbenchの失敗は終了ステータスとテキストとしてのみNodeに届きます。

他のファイルシステム、空きブロックはあるがinodeがないファイルシステム、SDK自身のNode書込み、MCPの処理経路、実際のproviderを使った実行、メモリ上限は計測していません。

### 旧AI設定を移行する

この制限はWindows controller、ホスト側Git/Gitleaks/OSV、認証中継、GitHub取得、保存レポートの総容量までを保証しません。
job全体の資源受入は別に残ります。
旧AI設定は、history・CIを含めどのcommandでも利用前に`workerResources`の追加が必要です。
`ai`を含まないoffline設定は継続利用できます。
AIの開示と実行観測はv2 schemaになったため、移行後は再計画してください。

有効な設定で旧v1 AI reportを読むことはでき、資源証拠は未記録と示します。
現行の完了確認では保存planのhashを再計算し、v2資源観測と受諾planの一致を要求します。
資源項目を削除して元のCI plan identityのまま通ることはできません。
保存記録やhashは署名ではありません。

### 計画を確認して実行する

```sh
node bin/scanmux.mjs ai-plan /absolute/repository --config /absolute/controller.json --json
node bin/scanmux.mjs ai-scan /absolute/repository --config /absolute/controller.json --accept-plan <planHash> --json
```

開示内容を読んでから、その`planHash`を渡してください。
ソース・設定・予算が変われば再計画します。
`ai-plan`は認証内容を読まず、worker起動もprovider接続もしません。
終了値0は計画作成の完了です。
`ai-scan`では受諾したソース本文、固定SDK指示、上限内の会話・ツール結果を、固定OpenAI Responses接続先へ送る可能性があります。
全要求と結果を秘密検査します。

`store:false`を要求しますが、providerの保持期間と学習利用方針は未確認です。

### 要求と使用量の記録を読む

認証、呼出し予約、使用量はホストが管理します。Linuxへ渡すのは元commitとの対応を持つ読取り専用の派生Gitです。報告には受理した候補指摘、呼出し・接続・アプリ送信の回数、観測トークン、未確認範囲、終了状態を残します。呼出しや送信はサーバー受理の証明ではありません。欠けた使用量は不明、金額は該当なし、口座の利用枠は不明です。実効プログラムが`standard`または`daybreak_blue`なら、AI検査として認めます。不明・欠落・要求していないプログラムや壊れた通信ではAI指摘を受理しません。終了未確認なら非公開の作業領域を保持します。

`aiExecution.transportRequests`には、リクエストごとの通信診断を記録します。

| フィールド | 意味 |
| --- | --- |
| `sequence` | AI実行内のリクエスト番号。 |
| `receivedBytes`, `receivedMessages` | decoderへ届いた完全なWebSocketメッセージのバイト数と件数。decoderが拒否したメッセージも含みます。WebSocketライブラリがサイズ超過で遮断したメッセージは含みません。 |
| `firstEvent` | 最初に届いたWebSocketメッセージの形。届かなければ`null`。`kind`（`object`、`non_object`、`invalid_json`）、`type`（`^[a-z][a-z0-9_.]{0,63}$`に合うイベント種別。合わなければ`other`、無ければ`absent`）、`^[a-z][a-z0-9_]{0,39}$`に合う最上位のキー名を並べ替えて最大16個と残りの数`otherKeys`、`sequence_number`と`sequence`の値の分類（`integer`、`absent`、またはJavaScriptの型名）、`stream_id`の有無（`absent`、`null`、`present`）を残します。期限後に届いたメッセージや拒否したメッセージでも記録します。中身の値は残しません。 |
| `rejectedEvent`, `rejectedAt` | decoderのpushが最初に例外を投げたメッセージの形と、リクエスト内での受信順（1始まりの整数）。形の項目・件数上限・イベント種別とキー名のパターンは`firstEvent`と同じです。`rejectedEvent`には`valueShapes`も入り、記録した最上位のキーごとにJSONの型（`string`、`number`、`boolean`、`null`、`array`、`object`）と`size`（文字列と配列は長さ、objectはキーの数、それ以外は`null`）を残します。`response`がobjectなら`response.output`の型と`size`、`response.status`の型（`statusType`。無ければ`absent`）も残します。`safety_buffering`がobjectなら、同じパターンに合うキー名と残りの数`otherKeys`を残します。decoderが受信メッセージを拒否しなければ両方`null`とし、後続メッセージでは上書きしません。中身の値は残しません。旧レポートでは省略できます。 |
| `terminal`, `terminalKind` | 終端イベントを読み取ったかと、その種類。`completed`、`incomplete`、`failed`（プロトコルの`error`イベントも含む）、`none`。終端を見たことだけでは受理を示しません。 |
| `closeCode` | 観測したWebSocket終了コード。未取得なら`null`。 |
| `sendOk` | アプリ送信のコールバックが成功したか。プロバイダーの受理は証明しません。 |
| `failureCode` | 最初に通信を止めた規則。例は`response_limit`（累積バイト数またはイベント数の上限）、`message_too_large`、`unexpected_event`、`sequence_mismatch`、`socket_error`、`early_eof`。通信・decoderの規則違反がなければ`null`。 |
| `providerErrorCode`, `incompleteReason` | 任意項目。フラット形式・入れ子形式の`error`イベント、または`response.failed`から許可リストにあるエラーコード（例：`server_error`、`cyber_policy`、`insufficient_quota`、`rate_limit_exceeded`）を記録します。未知の文字列コードは`other`とし、`null`や欠落したコード、エラーの詳細は保存しません。未完了理由は`max_output_tokens`などの許可リスト内だけを記録し、未知の理由は保存しません。 |
| `outputIdentityMismatch` | `response.completed`終端の`output`が、ストリームで受け取った出力項目と一致しないときだけ記録します。それ以外は無いか`null`です。項目は`streamedItemCount`、`terminalOutputLength`、比較した受信順の`index`、`kind`（`missing_index`、`type`、`id`、`call`、`name`）、`streamedType`と`terminalType`（`message`、`function_call`、`reasoning`、`other`。項目が無いか文字列の`type`が無ければ`null`）です。failureCodeは`output_identity`のままです。項目のid、call_id、名前は残しません。 |

ホストの各submitに診断行を作り、transport生成前の失敗も記録します。この場合、受信バイト数と件数は0、終端と終了コードは未観測、`sendOk: false`とし、固定の認証失敗コードまたは`transport_setup`を残します。ホストのclose成功だけでは、ソケットの接続は確認できません。

応答本文、プロンプト、認証情報、内容を識別する追加IDは診断に残しません。イベント名が未知であることを理由に拒否したときは、固定の失敗コード`unexpected_event`にします。`sequence_number`の欠落など、それより前の検査で失敗したときは、その検査のコードになります。イベント名を残すのは`firstEvent`と`rejectedEvent`の`type`だけで、上の形に合うものに限ります。失敗コードがあれば英日HTMLとCI要約に短い診断行を表示します。正常に届いた`incomplete`終端は`terminalKind: "incomplete"`となり、通信の失敗コードは付きません。既存の実行理由と受理条件を引き続き適用します。配列は既存の`scanmux.ai-execution/v1`と`/v2`の任意項目です。保存結果の読取り処理は実行記録へのフィールド追加を許容し、完了判定にも使わないため、スキーマの版は変更しません。配列のない旧記録も読み取れます。

開発実証は合成認証・loopback応答と実Linux SDKによるものです。
合成結果は常に部分完了で、実Blueの権限や脆弱性発見の品質を実証しません。
通常の`scan`、Web、一覧、`resume`はオフラインでAIを起動しません。
明示受諾した`ai-scan`は、[ローカルCI完了確認](results.ja.md#ローカルでciの完了を確認する)のv2記録を作成できます。
AI報告からの`resume`は拒否します。

製品CLIに合成モードや接続先の上書き指定はありません。

## 関連文書

- [導入と最初の検査](getting-started.ja.md)
- [実行時の制御](runtime-controls.ja.md)
- [結果の読み方と保存](results.ja.md)
- [結果の前提](assumptions.ja.md)
- [ScanMux](../README.ja.md)
