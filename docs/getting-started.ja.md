[English](getting-started.md) | [日本語](getting-started.ja.md)

# 導入と最初の検査

初めてローカルリポジトリを検査するときに、ツール、DB、設定をこの手順で準備してください。

## 必要なもの

- Node.js 24の24.16.0以上、25未満と、通常のSHA-1リポジトリを扱うGit。
- 公式配布元から別途導入したGitleaks 8.30.1とOSV-Scanner 2.7.0。
- 検査前に取得したOSVのオフラインDB。
- ローカルCLI検査では、commit済みで変更のないGitルート。
- Windowsで設定済みツールを起動する場合は、固定したプロセス所有者。ビルド手順は後述します。

OSV-Scanner 2.7.0 / SCALIBR 0.5.3は`<database-root>/osv-scalibr/<ecosystem>/all.zip`を読みます。
ecosystemには`npm`、`PyPI`、`Go`、`crates.io`があります。
上流文書の一部にある、旧`osv-scanner`サブディレクトリは使わないでください。
検査中にDBを取得・更新しません。

worktree、リンクしたメタデータ、ローカルのshallow clone、変更・未追跡ファイル、非標準Git設定はこのPoCの対象外です。
Web画面では公開GitHubのcommitを別途取得します。
submodule、symlink、LFS pointer、NULを含むバイナリはsnapshotから除外します。
対応する残りのファイルを検査し、除外は未完了の範囲として残します。

Windowsと固定したLinuxコンテナでオフライン静的検査を実証しました。
Linuxの確認対象は通常入力、DB欠落、合成秘密です。
対象は変わらず、検査区間の通信counter差分は毎回0でした。
テストスイートはCIでmacOS上でも実行しますが、ジョブコマンドと本番AI runnerは引き続き非対応です。
macOSの`/tmp`や`/var`など、祖先にシンボリックリンクがある対象は`linked_path`で拒否します。
Windowsでは実行ごとの非公開アクセス制御リスト（ACL）を使います。
そのディレクトリを作成・利用できない環境では失敗として扱い、ACLを緩めて回避しません。

## 最初のオフライン検査

### 1. ソースの作業環境を確認する

コントローラーの依存を導入し、ソースを検証して、コマンド一覧を表示します。

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
node bin/scanmux.mjs --help
```

検証が成功するとエラーなく終了し、最後のコマンドがCLIのヘルプを表示します。

### 2. 取得記録付きのオフラインDBを用意する

ソースの作業環境で、選んだ公式OSV DBを全検査対象の外にある新しい絶対パスへ取得します。

```sh
node scripts/fetch-osv-db.mjs --destination /absolute/new-database --ecosystems npm,PyPI,Go,crates.io --max-bytes <total-byte-limit> --timeout-ms <total-timeout-ms>
```

指定した全DBの取得に成功したときだけ、`database-receipt.json`が作られます。
このスクリプトはリポジトリの運用用ツールで、npmパッケージには同梱しません。
プレースホルダーは、現在のDBサイズ、取得合計バイト数の予算、全体の制限時間に合う正の整数へ置き換えてください。時間の単位はミリ秒です。

通信先は4言語の固定された公式公開DBだけです。
認証情報、リダイレクト、自動再試行は使いません。
応答のサイズとMD5を取得内容へ照合し、SHA-256を計算します。
既存の保存先は拒否します。
新しいDBが揃うまで、以前のDBと設定は残してください。
成功後に`osvDatabase`を新しいルートへ切り替え、戻すときは以前のパスを指定します。

> Q. DBの取得に失敗したらどうなりますか。
>
> A. 取得途中の印付きディレクトリが残り、検査はそれを拒否します。再取得には新しい保存先を指定してください。

検査では必要なDBを非公開の実行領域へコピーし、hashを確認してからOSVへ渡します。
結果を受け入れる前にコピーを再確認します。
取得記録では、取得完了時刻、配布元オブジェクトの更新時刻、元ファイルのfilesystemの`modifiedAt`を区別します。
`dbAsOf`はnullのままです。配布物の更新時刻だけではアドバイザリーの収録時点を断定できません。
印も記録もない従来DBは、`provenance.state: "unknown"`で使えます。
記録が不正、またはDB内容が不一致なら`osv scan source`を起動しません。
既存のOSV `--version`確認は先に行われる場合があります。
記録はローカルの取得記録であり、配布元の署名確認や鮮度の保証ではありません。

### 3. 信頼するコントローラー設定を作る

このひな形のパスとhashを確認済みの実値へ置き換え、検査対象外に保存します。

```json
{
  "schema": 1,
  "timeoutMs": 120000,
  "tools": {
    "git": { "path": "/opt/git/bin/git", "sha256": "REPLACE_WITH_64_HEX_DIGITS", "version": "2.54.0" },
    "gitleaks": { "path": "/opt/scanners/gitleaks", "sha256": "REPLACE_WITH_64_HEX_DIGITS", "version": "8.30.1" },
    "osv": { "path": "/opt/scanners/osv-scanner", "sha256": "REPLACE_WITH_64_HEX_DIGITS", "version": "2.7.0" }
  },
  "osvDatabase": "/opt/osv-data"
}
```

保存する設定には、symlinkのランチャーではなく、実ファイルの絶対パスを指定します。
信頼する導入済みファイルかリリースから各実行ファイルのSHA-256を取得し、確認した版を記録してください。
`osvDatabase`には準備したDBルートを指定します。
WindowsのJSONパスにもスラッシュを使えます。
Windowsでは`Get-FileHash -Algorithm SHA256 <executable>`、Linuxでは`sha256sum <executable>`でhashを計算します。
手元のhashはバイト列を固定するもので、配布元の真正性までは証明しません。

### 4. Windowsのプロセス所有者をビルドして固定する

Windowsでは、検査対象外にある新しい非公開ディレクトリへ補助プログラムをビルドします。

```powershell
powershell -NoProfile -File scripts/build-windows-process-owner.ps1 -OutputDirectory C:\absolute\new\directory
```

成功すると、版、ソースのSHA-256、実行ファイルのSHA-256とサイズを含む`scanmux.windows-process-owner-build/v1`のJSON記録を表示します。
設定の`tools.windows-process-owner`へ、実行ファイルのパス、hash、版を追加してください。
正確な設定形式と条件は[Windowsのプロセス終了](windows-process-termination.md)（英語のみ）にあります。
ほかのプラットフォームはプロセスグループを使い、この固定値を無視します。

### 5. ツールを確認する

計画前に、設定済み実行ファイルの識別情報と不足条件を確認します。

```sh
node bin/scanmux.mjs doctor --config /absolute/controller.json --json
```

JSONにツールと実行条件の状態を表示します。必須条件が欠けている場合は終了3で、セキュリティの判定ではありません。

### 6. 計画を確認する

検査する前に、固定commit、入力、除外、検査範囲、送信、費用を確認します。

```sh
node bin/scanmux.mjs plan /absolute/repository --config /absolute/controller.json --json
```

成功時の終了0は計画作成の完了だけを示します。
出力は確認用であり、後で取り込める承認済み計画ではありません。

### 7. オフライン検査を実行する

通常の出力で検査するか、JSONが必要なら2行目のコマンドを選びます。

```sh
node bin/scanmux.mjs scan /absolute/repository --config /absolute/controller.json
node bin/scanmux.mjs scan /absolute/repository --config /absolute/controller.json --json
```

通常の要約には、非公開のHTML・JSON・SARIFレポートの保存先を表示します。
`--json`では保存先を付けず、レポートを表示します。
`scan`は実行直前に計画を作り直します。
通常の検査は必須AIが起動せず、ランタイムの照合範囲も部分的か非対応のため、未完了のままです。

## 検査結果を非公開で扱う

- レポートにはパッケージ名、ファイル名、リポジトリのパスが含まれる場合があります。
- 生の検査出力と検出した秘密値は保存しません。
- 出力前に、シリアライズしたレポートと保存先をGitleaksで検査します。
- 秘密を検出した場合や出力検査が成立しない場合は、固定文言のエラーだけを返します。

## コピーするバイト数を制限する

`scan`の設定（schema 1/2）には、最上位に任意の`maxCopyBytes`を追加できます。
`job-scan`と`host-job-scan`では、オフラインジョブプロファイル（v1/v2）の`scan`や`limits`と同じ階層に置きます。
`host-job-scan`はホストプロファイルが参照するオフラインプロファイルから読み取ります。
リポジトリごとに、バイト単位の正の安全な整数を指定してください。
既定値はありません。

省略時は既存の設定・保存形式・schemaの版・保存記録の容量計上を維持します。

対象は、ScanMux自身が作る来歴確認用の実行資材・bundle・trusted root、OSV DBのZIP、固定ジョブアプリ、Windowsのプロセス所有者、Trivyのコピーの論理バイト数です。
出力先を作る前にコピー元のサイズ分を予約し、ストリームの各部分を書き込む前にも上限を確認します。
途中でコピー元が増えても予約分を超えて書きません。
検証済みサイズとの不一致やコピー中のサイズ変化は、呼出し元の完全性エラーとして扱います。

来歴確認用の実行資材・bundle・trusted rootには期待サイズを記録していないため、大きいファイルへの差替えで残予算を超えると、ハッシュ検査が変更を`ERROR`として報告する前に`job_disk_copy_limit`（`INCOMPLETE`）となります。
成功したコピーは、後で削除されても予算を使います。
拒否・失敗したコピーは、途中の出力を削除するまで予約を解放しません。
削除失敗は予約を保持したまま入出力エラーにします。

単独ジョブでは、ホスト側の受付とアプリコピーで使った分を差し引いた残予算をLinux管理役へ渡し、保存計画や報告には項目を加えません。

単一スキャンのコマンド（`scan`・`ai-scan`・`resume`）では、受付時のコピー、プロセス所有者の実行ファイル、スキャン中のコピーで1つの予算を共有します。
`serve`・`scan-list`など複数のスキャンを実行するコマンドでは、各`scan()`が自身の設定から新しい予算を作ります。
コマンド側の受付とプロセス所有者のコピーには、コマンドの設定上限を使う別の予算を割り当てます。

スキャン側でキーを省略した場合、コマンド側に予算があっても、この項目によるスキャンのコピー制限は設けません。

上限到達は`job_disk_copy_limit`を原因とする`INCOMPLETE`（終了3）です。
先行する`FAIL`や`ERROR`があれば優先します。
管理役の起動前の拒否では、既存の`scanmux.error/v1`形式にこの判定と原因を記録します。`deps`では、スキャンの判定を付けずに終了2と失敗原因を記録します。
`host-job-scan`では、Windowsの親が受付コピーを計上し、残予算だけを一時的な管理役・workerの起動引数で渡します。

workerは自分の受付コピーとアプリコピーを差し引き、残りを既存の起動メッセージでLinuxへ渡します。
`D/app`を作る前にアプリ全体のmanifestと残予算を比較するため、予算不足で部分的なアプリは残しません。
サイズやハッシュの変化は完全性エラーのままです。
予算は後段へだけ渡し、前段へ戻しません。
ホストv1/v2の保存形式・検証器・保存記録の容量計上は変えず、キー省略時は管理役の起動引数も維持します。

workerやLinuxでの不足は既存の報告理由に記録し、先行エラー・取消・期限の優先順位を維持します。

外部エンジンの書込み、Gitスナップショットの展開、報告・途中保存の生成、Docker/OSの保存領域、ファイルシステム管理情報、書出し先は対象外です。ディレクトリ全体の物理quotaを意味しません。物理割当量は論理バイト数を超えることがあり、物理quotaにはOS側の設定が必要です。ScanMuxはOS設定を変更しません。登録したジョブ領域は、以下の任意の計測上限で別に扱います。

## ジョブのディスク使用量を測って制限する

設定（schema 1/2）の最上位で`maxCopyBytes`の隣に、任意の`maxJobDiskBytes`を置けます。
バイト単位の正の安全な整数をリポジトリごとに指定し、既定値はありません。
`scan`・`ai-scan`・`resume`は、来歴確認・プロセス所有者・スキャンを一つの計測範囲で扱います。

`serve`・`scan-list`では各`scan()`が新しい計測範囲を持ち、そのスキャン領域と共用するプロセス所有者の実行ファイル領域を含めます。
`job-scan`でもジョブプロファイルの最上位に指定でき、`host-job-scan`では参照先のオフラインジョブプロファイルの値を使います。
ホストの`limits`や`retained`には項目を追加しません。
値は実行時の起動メッセージで渡し、保存するLinux Configには含めません。

省略時は既存の動作・管理役とworkerの引数・保存形式を維持します。

これらのジョブコマンドでは、登録したホスト側のジョブ領域（アプリのコピーと保存記録を含む）と、コンテナー内の`/work`・`/tmp`・`/dev/shm`を合算します。
ホスト側は、`job-scan`ではTypeScriptの親、`host-job-scan`ではWindows workerが計測します。

コンテナーの管理役も同じ走査処理を使い、既存のsupervisor通信で計測値を送り、ホスト側が最新のホスト計測値と合算してエンジンの停止を要求します。
両側の計測は同時刻ではありません。
読取り専用の`/app`は重複計上せず、計測によって保存容量のカウンターは増やしません。
既存のLinux tmpfs制限は別に適用します。
Dockerデーモン・イメージやVM・OSの保存領域、ファイルシステムのメタデータは対象外で、物理quotaは保証しません。

ScanMuxが作成時に登録する対象は、スキャン領域（snapshot、エンジンのTEMP・cache、準備したOSV ZIP、チェックポイントを含む）、プロセス所有者の領域、`W`・`bin`を含むTrivy領域、一時的な来歴確認領域です。
登録時に実体パスへ正規化し、入れ子や別名（Windowsでの大文字・小文字の違いを含む）による同じ領域の登録を重複計上せず、削除する一時領域は登録を解除します。

通常ファイルのサイズを、それぞれのファイルシステムのクラスタサイズ（`statfs().bsize`）単位で切り上げて合算します。
ディレクトリは0バイトとし、シンボリックリンクやジャンクションの参照先はたどりません。
v2の保存記録を含め、登録領域の外側は計上しません。

外部プロセスの実行中は100ミリ秒間隔で計測し、プロセスの終了確認後と各エンジンの終了時にも計測します。
推定量の上限を超えたら、既存のプロセスツリー終了確認の経路で解析を停止します。
`job_disk_measured_limit`は`INCOMPLETE`、終了を確認できなければ既存の`termination_unverified`による`ERROR`です。
走査中に消えたエントリは存在しないものとして扱い、置換されたエントリは読み直します。

親ディレクトリの再列挙で名前が見つからない場合（Windowsでは大文字・小文字を区別せず比較）、またはその後のstatで消失を確認できた場合に、存在しないものとして扱います。
再列挙でも名前が残り、読み取れない場合は`ERROR`のままです。
登録ルートの欠落、継続する権限・statのエラー、クラスタサイズを取得・確認できない場合は、0バイトとして扱わず、`job_disk_observation_unverified`で停止して`ERROR`にします。

利用者の中止やスキャン期限が先なら、終了時の計測で後から容量超過や観測エラーが生じても、最初の停止理由を維持します。
先に出た`FAIL`・`ERROR`の優先順位は維持します。
停止原因を保存するため、容量停止後も既存の上限がある出力の秘密検査と最終記録・レポートの書込みは行います。
この完了処理の書込み量は制限しません。

これは計測した推定量であり、物理割当量やファイルシステムのquotaではありません。
ScanMuxはOS設定を変更しません。
疎ファイル・圧縮ファイル・ハードリンクでは物理割当量と異なる場合があります。
計測間の増加や、計測前に作成・削除された短命なファイルは見逃すことがあります。
計測中に名前が変わったディレクトリは、次の計測まで見逃す場合もあります。

書込み速度に上限がある場合でも、計測間隔、走査・スケジューリングの遅延、終了確認にかかる時間の間の増加量に、一括書込みと各ファイルのクラスタ切上げ分を加えた超過余裕が必要です。
これらに上限がなければ、一律のバイト超過上限は保証できません。
ファイルシステムのメタデータ、代替データストリーム、Docker・OSの保存領域（AppContainerのプロファイル領域を含む）、共用する所有者ジャーナル、エクスポート先は推定量の対象外です。

したがって、物理的な強制上限は保証しません。

## 固定commitや複数リポジトリを指定する

ローカル対象の`plan`・`scan`には、`--base <40-character-commit-SHA>`と`--head <40-character-commit-SHA>`を組で指定できます。ブランチ名・短縮SHA・片側だけの指定は拒否します。両commitが対象リポジトリ内に必要で、作業ツリーはcleanのままにしてください。検査するheadは現在チェックアウトしているHEADと異なっていても構いません。

計画には両commit・treeと、追加・削除・変更・mode変更のパスを記録します。名前変更は削除＋追加です。**検査するのはheadの全snapshot**で、変更のない依存関係入力も含みます。空差分でも必要検査を省略しません。変更行だけの検査や、baseの指摘との比較ではなく、今回の変更で指摘が生じた・修正されたとは判定しません。この範囲をJSON・HTML・SARIFに明記します。

複数対象は、すべての対象の外側に置いた一覧ファイルで指定します。

```json
{
  "schema": 1,
  "repositories": [
    { "id": "library", "path": "/absolute/library" },
    { "id": "service", "path": "/absolute/service" }
  ]
}
```

ローカル行には`base`・`head`の組を追加できます。公開GitHub行は`path`の代わりに`url`を指定し、Webと同じ許可URL制限を適用します。URL取得は固定HEADだけなので、URL行のbase/head指定には対応しません。未知の項目、ID・URLの重複、同一または内包関係にあるローカル対象、対象内にある一覧・設定・ツール・DBは、最初の処理前に拒否します。

```sh
node bin/scanmux.mjs plan-list /absolute/repositories.json --config /absolute/controller.json --json
node bin/scanmux.mjs scan-list /absolute/repositories.json --config /absolute/controller.json --json
```

各対象を別々の非公開作業領域で順番に処理し、一覧の全行を`batch.json`へ残します。
完了した行は固有の計画・実行ID・成果物の保存先と対応します。
終了確認済みの失敗でも先行成果は残します。
取消・一覧全体の`timeoutMs`到達・プロセス終了確認不能では次の対象を開始しません。
時間制限は計画・取得・検査に適用し、その後の秘密検査と保存は、既存の処理ごとの時間制限を持つ後処理として完了させます。
終了を確認できなくても、取得ソースの複製は各jobの最後に削除します。削除に失敗した場合は`source_cleanup_failed`を報告し、そのディレクトリを残します。

ローカル対象自体は削除しません。

`plan-list`の終了値0は全対象の計画作成成功だけを意味し、セキュリティ判定`PASS`を返しません。`scan-list`は全行を[判定の優先順](results.ja.md#判定と終了コードを読む)で集約し、未実施を合格へ変えません。JSON出力には`batch.json`の全内容を含めます。
出力検査・保存の失敗はエラーとして扱います。プロセスやOSが異常終了した場合は、それまでに保存した個別成果だけが残ることがあります。一覧実行の自動再開は未実装です。

## 依存関係の脆弱性情報・更新可否・lockfile差分を比較する

`deps`は指定した各commitを計画し、それぞれのlockfileを個別の非公開スナップショットでオフラインOSVにかけます。両側で固定した同じOSV-Scanner・データベースのコピー・空の設定を使い、`osv.database`にデータベースの識別情報を一度だけ、`osv.sides`に各側の完了状態を記録します。更新可否・差分の解析では、commit内の`package.json`・`.npmrc`・`pyproject.toml`・`uv.toml`も`maxFileBytes`と計画のLFS・バイナリ除外の範囲で読みます。
対象リポジトリへの書込み、checkout・install・lock再生成・通信はしません。

```sh
node bin/scanmux.mjs deps /absolute/repo --config /absolute/controller.json --base <SHA> --head <SHA> --json
```

npm v2/v3とuv.lock v1のOSV指摘ごとに、`allowed`（宣言が新しい修正版を許す。
解決・installの証明ではない）・`blocked`・`undetermined`を定められた理由付きで返します。
base/headでは変更されたlockfile項目を分類し、版の変更と追加を、変更された直接依存からの経路で説明するか未説明として列挙します。
JSONは`scanmux.dependencies/v2`で、インストール済みパッケージから取得した`tool: { name: "scanmux", version }`を含みます。`advisories`はlockfileパス・ecosystem・パッケージ名・OSV IDごとに1件です。`status`は`removed`（baseだけ）、`added`（headだけ）、`unchanged`（両側。版が変わっても同じ）で、base未指定なら`present`です。`advisoryCounts`で4種類を集計し、テキストでは追加分を先に表示します。片側でも検査が失敗・未完了なら脆弱性情報を比較せず、観測が0件でも終了値2にします。

各項目には`baseVersion`・`headVersion`（存在しなければnull。複数の版はソートして`, `で連結）、`id`・`aliases`・`severity`（レコードの`database_specific.severity`。なければnull。スコアは計算しない）、該当するaffected範囲の修正版`fixedVersions`（記録がなければ空配列）が入ります。`dev`はnpm lockfileの`dev`・`devOptional`から読み、headにパッケージがあればhead、なければbaseを使います。該当する全インスタンスが開発用の場合だけtrue、それ以外のecosystemではnullです。npm v2/v3のlockfileで宣言されたlink・workspaceパッケージはローカルと判定し、オフライン照合の欠けに数えません。ローカルと宣言されていない版なしパッケージは未完了のままです。workspaceの更新可否は`workspaces_outside_subset`で`undetermined`になり得ます。

リポジトリ外のresolver設定は読みません。

**0.2.0で`deps`の終了値を変更しました。** 従来の解析結果0・3に代わり、2は片側でもOSVが失敗・未完了、計画したlockfileの読取り・解析不能、commitの解決不能、その他の計画阻害を表します。10はbase指定時に追加分あり、base未指定時に現存する脆弱性情報ありです。0は必要な検査がすべて完了し、追加分（base未指定なら現存分）がない場合です。既存の`unchanged`が残っていても0になるため、安全性のPASSではありません。更新可否の`undetermined`は出力に残り、終了値には影響しません。

## 1件の指摘を再現し、変更していない回帰テストで修正後を確かめる

元のReport v2/v3の指摘と、利用者が用意した`test.mjs`を含む専用の追跡済みディレクトリを指定します。
既存のオフラインLinuxジョブ内だけで実行し、ローカルの固定image、通常の制限、コンテナ削除確認を使います。image取得、依存導入、ホスト上の対象コード実行、AI送信は行いません。

```sh
node bin/scanmux.mjs reproduce ./project --job-profile /absolute/offline-profile.json --from /absolute/before-report.json --finding codex-security:FINGERPRINT --test tests/repro/example --json
# 修正前後を比べる場合は --base FULL_BASE_COMMIT --head FULL_HEAD_COMMIT も指定する。
```

`FINGERPRINT`は元レポートの64文字の値に、両commitは異なる小文字40桁のhashに置き換えてください。
元レポートはbaseのものを使います。補助コードやfixtureを含むテストディレクトリ全体が両commitに存在し、パス・モード・内容が同一である必要があります。変更があれば、両方のテスト実行前に拒否します。
1時点だけの実行は既定で調査用の補助証拠です。`--required`を付けると必須検証として記録され、前後比較は常に必須です。どの場合も、要求した検証が成立したときだけ`reproduce`はPASS/0を返せます。

テストは`default async function ({ projectRoot })`を公開し、`{ kind: 'observed', problem: 'present' }`または`problem: 'absent'`を返します。
前提不足は`{ kind: 'environment_missing', reason: 'offline_dependency_missing' }`で示し、理由に`fixture_missing`、`runtime_not_available`も使えます。例外、skip、不正な戻り値、非0終了、時間超過は「再現しない」とは扱いません。利用者が判定の妥当性を確認し、補助コード・fixtureを指定ディレクトリにまとめてください。

baseでの再現を記録し、同じテスト・実行環境のheadで再現せず、両コンテナの削除を確認した場合だけ、「The same test no longer reproduces at head, with the test unchanged.」という限定した結果を返します。
別の非公開ファイル`verification.json`、HTML、SARIF、実行記録に結果を残し、元レポートのbytesもそのまま保存します。検証が成立した場合の判定と終了codeは元レポートの時点についてのものなので、修正後のテストに成功しても、High/Criticalのbaseで再現した指摘はFAIL/1です。headの判定には別途通常の検査を行ってください。
保存記録の照合は、結果を誤って別の指摘やテストに適用する取り違えを検出します。記録は署名のないローカルファイルなので、誰かが意図的に書き換えることに対する保護にはなりません。
`not_verified`の場合は、元レポートの判定や補助・必須の指定にかかわらずINCOMPLETE/3を返します。整合性違反や既存の実行エラーはERROR/4です。元レポートは書き換えません。
論理保存容量は結果一式で共有し、実行制限はジョブごとに適用します。実行用ソースコピーは削除し、検証結果だけを非公開で残します。コマンド全体の所要時間や物理保存容量の保証はありません。

v0.1.0では、テスト・パッチの生成、baseとheadの間でのテスト追加・変更、テストの強さやテスト群全体の弱体化の意味的判定、フレームワーク検出、build・依存導入、オンライン前提、別runtime、Trivyの指摘選択、自動disposition・レポート書換え、head全体の安全判定、過去の実行証拠の取込み、再試行・再開、cache、batch・Web・SDK・host-job経路には対応しません。

## 関連文書

- [Web画面](web-interface.ja.md)
- [緊急脆弱性の照合](urgent-advisories.ja.md)
- [AI検査](ai-scan.ja.md)
- [実行時の制御](runtime-controls.ja.md)
- [結果の読み方と保存](results.ja.md)
- [ScanMux](../README.ja.md)
