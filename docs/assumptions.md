[English](assumptions.md) | [日本語](assumptions.ja.md)

# What ScanMux results rely on

Read this page before relying on a ScanMux result: it lists the trust assumptions and claims that ScanMux cannot verify for itself.

The Japanese version, [assumptions.ja.md](assumptions.ja.md), is authoritative. This English file is a translation of it.

Each statement describes the code at the date in the change history at the end.

## Scope of v0.2.5

See [Scope of v0.2.5 in the README](../README.md#scope-of-v025) for supported language inputs, urgent-advisory checks and exclusions. Support describes the available checks, not a guarantee of completion; the result meanings and trust assumptions below still apply.

## What a result means

ScanMux gives one of five results: `PASS` (exit 0) when every required engine completed with full coverage and no finding needs action or review; `FAIL` (exit 1) for a secret, or for a High/Critical finding that is supported by source or reproduced at runtime; `REVIEW` (exit 2) for a High/Critical candidate or a finding of unknown severity; `INCOMPLETE` (exit 3) when a required check is missing, excluded, blocked, unsupported, partial, cancelled or over its time budget.

`ERROR` (exit 4) is a fifth result, for an execution failure or an integrity error, and it takes precedence over the other four, followed by `FAIL`, `INCOMPLETE`, `REVIEW` and `PASS` in that order.
Today no command can produce `PASS`.

Every plan requires the `runtime-advisories` engine, and that engine always reports partial or unsupported coverage, so a required check is never complete, in `ai-scan` as in an ordinary `scan`.
An ordinary `scan` also leaves the required AI engine unrun.

## Optional logical copy budget

The optional top-level `maxCopyBytes` in controller configs (schema 1/2) and offline job profiles (v1/v2), including those referenced by `host-job-scan`, is a positive safe integer in bytes, chosen per repository profile with no default.
It bounds the logical bytes of ScanMux-owned provenance artifact/bundle/trusted-root, OSV ZIP, fixed application, Windows process-owner and Trivy copies.

Each source size is reserved before destination creation; each streamed chunk is checked before writing, including when the source grows.
A verified-size mismatch or a source changing size during copying follows the caller's integrity-error path.

No expected size is recorded for provenance artifacts, bundles or trusted roots, so a larger replacement that exceeds the remaining allowance reports `job_disk_copy_limit` (`INCOMPLETE`) before the hash check can report the change (`ERROR`).
Successful copies remain charged; refused or failed copies keep their reservation until partial output is removed.

Failed cleanup is an IO error and stays charged.
The standalone host hands its remaining allowance to the Linux controller through the transient bootstrap, without changing saved-result schemas or retained-record accounting.
Omitting the key preserves existing behavior and formats.

A single-scan command (`scan`, `ai-scan` or `resume`) shares one budget across its admission copies, process-owner executable and scan copies.
In commands running multiple scans, including `serve` and `scan-list`, each `scan()` gets a fresh budget from its own config.
Command-level admission and process-owner copies have a separate budget using the command config's limit.

A scan whose config omits the key does not inherit the command's budget.

Exhaustion gives `INCOMPLETE` and `job_disk_copy_limit`, preserving earlier `FAIL`/`ERROR` precedence.
Refusal before the owner starts uses the existing error envelope with exit 3; `deps` reports these failures with exit 2 instead.
Windows `host-job-scan` reads the referenced offline profile's top-level key: the outer parent charges admission copies, then passes only the remainder through transient owner/worker arguments.

The worker charges its own admission and app copies, then hands the remainder to the existing Linux bootstrap; no stage returns allowance upstream.
The whole app manifest must fit before `D/app` is created, so shortfall cannot leave a partial app; size/hash changes stay integrity errors.
Worker/Linux shortfalls use existing report reasons and preserve error, cancellation and deadline precedence.

Host v1/v2 record formats, validators and retained-byte accounting stay unchanged, as do owner arguments when the key is omitted.

This budget does not bound external engine writes, snapshot materialization, generated reports/checkpoints, Docker or OS stores, filesystem metadata, or export destinations.
Logical bytes are not physical allocation.
It is not a hard physical cap; a physical quota requires OS configuration that ScanMux does not change.

The optional measured job disk limit below observes registered directories separately from this copy budget.
Tests exercise exact and exceeded limits, shared reservations, growing/interrupted sources, failed cleanup, refusal propagation and unchanged legacy records; they do not prove a physical quota.

## Optional measured job disk limit

`maxJobDiskBytes` is an optional top-level scan-config key (schema 1/2), next to `maxCopyBytes`: a positive safe integer in bytes chosen per repository, with no default.
`scan`, `ai-scan` and `resume` share one observation scope across admission, the process owner and the scan.

Each `scan()` in `serve`/`scan-list` starts a fresh scope and includes its scan workspace and the shared process-owner executable workspace.
`job-scan` also accepts the key at the job profile's top level; `host-job-scan` uses the referenced offline job profile's value, without adding host `limits` or `retained` keys.
The value travels in runtime bootstrap messages, outside the saved Linux Config.

Omitting it preserves behavior, owner/worker arguments and saved formats.

For these job commands, the estimate sums registered host job directories (including the application copy and retained files) and the container's `/work`, `/tmp` and `/dev/shm`.
The TypeScript parent measures the host side for `job-scan`; the Windows worker does so for `host-job-scan`.

The container controller uses the same walker and reports samples through the existing supervisor channel; the host combines each with its latest host observation and requests engine termination through that channel.
The two sides are sampled at different instants.
The read-only `/app` bind is not counted again, and measurement does not charge retained-byte counters.

Existing Linux tmpfs limits still apply independently.
Docker daemon/image stores, VM/OS stores and filesystem metadata are excluded; this estimate provides no physical quota.

ScanMux registers job directories as it creates them: the scan workspace (including snapshot, engine TEMP/cache, prepared OSV ZIPs and checkpoints), process-owner workspace, Trivy root with its `W` and `bin` areas, and temporary provenance workspaces.
Roots are canonicalized at registration, so nested roots and aliases (including Windows case variants) count once.

Retired temporary roots are released.
Each observation sums regular-file sizes, rounding each file up to its filesystem's cluster size (`statfs().bsize`); directories count as zero, and symbolic links/junctions are not followed.
Nothing outside registered roots, including v2 retained records, is counted.

External process lifetimes are sampled every 100 ms and again after the process settles; the controller also observes each engine's end.
Exceeding the estimate stops analysis through the existing verified process-tree termination path: `job_disk_measured_limit` gives `INCOMPLETE`; unverified termination keeps `termination_unverified` and `ERROR`.

Entries that vanish during a walk count as absent; replaced entries are re-read.
A name counts as absent when a fresh parent listing no longer contains it (names are compared case-insensitively on Windows), or a later stat confirms it is gone.
A name that stays listed but unreadable remains `ERROR`.

A missing registered root, persistent permission/stat failures or unavailable/unknown cluster size stop with `job_disk_observation_unverified` and `ERROR`, never a zero-byte reading.
An earlier user cancellation or scan deadline keeps its reason if final disk sampling subsequently signals a limit or observation error.
Earlier `FAIL`/`ERROR` keeps precedence.

Bounded output secret checks and final record/report writing still run after a disk stop so its cause can be saved; this limit does not cap those completion writes.

This is a measured estimate, not physical allocation or a filesystem quota: ScanMux does not change OS configuration.
Sparse/compressed files and hard links can differ from this estimate.
Growth between samples and files created and removed between observations can be missed.
A directory renamed during a sample can also be missed until the next sample.

With a bounded write rate, allow overshoot for growth during the sampling interval, traversal and scheduling delay, and verified termination, plus write bursts and per-file cluster rounding.
There is no universal byte overshoot bound when those quantities are unbounded.

Filesystem metadata, alternate data streams, Docker/OS stores (including AppContainer profile storage), the shared owner journal and export destinations are outside this estimate.
It therefore does not provide a hard physical cap.

## Tools and services a result trusts

Each item has four parts. A check under "How it is checked" detects some ways the assumption can break. A check is not a proof that the assumption holds.

### Pinned tool binaries and their versions

**Assumption.** The executables pinned under `tools.git`, `tools.gitleaks` and `tools.osv` are genuine releases of their versions, and they behave as their publishers describe. ScanMux supports Gitleaks 8.30.1 and OSV-Scanner 2.7.0.

**If it breaks.** If the pin was taken from a tampered or faulty binary, ScanMux runs that binary faithfully. A scanner that misses a finding produces a clean engine result, and that result counts toward `PASS`.

**How ScanMux or the user keeps it.** The user pins each tool by absolute path, SHA-256 and version in the config, and the path must be outside the scanned repository.
Before every start ScanMux reads the file and compares its SHA-256 with the pin (`tool_digest_mismatch` otherwise), and the tool's version output must contain the pinned version.

A configured version other than the supported one makes the engine unsupported.
For a tool started through the Windows process owner, the owner hashes the image it holds open without write sharing, so the hashed bytes are the bytes that start.
A runtime policy v2 can additionally require a recorded or publisher-attested provenance for a tool before it is admitted.

**How it is checked.** Tests check that the tool's process does not start when its SHA-256 does not match the pin (`test/assumptions.test.ts`, `test/core.test.ts`, `test/process-tree.test.ts`). A matching digest shows that the bytes read are the pinned bytes. It does not show that the pinned release is honest or correct. This check is not a proof.

### Optional Trivy distribution and embedded checks

**Assumption.** When `tools.trivy` is configured, the user trusts the acquired Trivy 0.76.1 distribution, its embedded misconfiguration checks and their coverage and freshness.
The fixed executable digest identifies bytes, not a publisher.
A compromised distribution or check can miss problems or try to misuse the permissions available to its process.

**If it breaks.** Wrong or old embedded checks can produce missing or wrong misconfiguration candidates even when every planned input has a result.
A compromised executable can try to read other accessible files, modify writable files or communicate.
AppContainer does not establish an exact filesystem allowlist or prove that all network traffic is blocked; the known gaps below remain relevant.

**How ScanMux or the user keeps it.** The optional pin is Trivy 0.76.1 with executable SHA-256 `94618922c9eb324d7099bf217b01504bfc1f87a0d46d6008cb24ec89b1d1a4bb`.
The user acquires and verifies it outside a scan; ScanMux does not download Trivy or update checks during a scan.
Version probing uses only `--version`.

Config scanning uses fixed arguments, an explicit empty config and ignore file, a private cache, disabled check updates, version checks and telemetry, and includes non-failing checks as completion evidence.

On Windows the restricted path uses a non-elevated, zero-capability AppContainer profile inside the existing owner's Job, with read/execute access to the snapshot and private binary copy and Modify access to the private working area.
There is no ordinary-process fallback.

A missing owner, unavailable profile or non-Windows host leaves Trivy unstarted and unsupported, giving `INCOMPLETE` unless a higher-priority result applies.
The runtime-policy component is `trivy`.
See [Trivy](trivy.md) for the fixed scope and acquisition responsibilities.

**How it is checked.** Fixed-version prototype results contained 2, 17, 8, 8 and 17 failing check observations for Dockerfile, Kubernetes, Terraform, CloudFormation and Helm respectively (52 total).

A malformed Kubernetes input was silently omitted by Trivy, so exit zero or a nonempty result cannot prove coverage: the planned file/module/chart inventory must be reconciled with result targets, and each missing unit remains partial and `INCOMPLETE`, never analyzed because another unit succeeded.

Prototype network and filesystem observations are listed below; they are limited measurements, not a proof of isolation or check correctness.

### The OSV offline database and its receipt

**Assumption.** The copy of the OSV database named by `osvDatabase` holds the data that OSV published for each ecosystem at the time of acquisition, and OSV-Scanner matches lockfiles against it correctly.

**If it breaks.** An altered, truncated or old database leads to missed or wrong dependency findings. The result can still reach every gate that the other inputs allow, `PASS` included.

**How ScanMux or the user keeps it.** The database must be outside the scanned repository.
ScanMux copies each `all.zip` into a private workspace and hashes it.
When a `database-receipt.json` (`scanmux.osv-database/v1`) exists, the size and SHA-256 must match it; an acquisition marker without a receipt is refused.
After the scan the copy is hashed again (`database_changed_during_scan`).

The report records the SHA-256, the file time and the provenance of each database, as `recorded` from the receipt or `unknown` without one.
ScanMux does not refuse an old database.
Its age is recorded for the reader.

**How it is checked.** The receipt's basis is `locally_recorded_https_acquisition_not_authenticated`.
It is written on the machine that downloaded the database, it records what arrived over HTTPS, and it is not signed.
A receipt match shows that the database has not changed since the receipt was written.
This check is not a proof that the data is what OSV published.

### Operating system, Node runtime and the Windows process owner

**Assumption.** The operating system enforces user separation, file permissions and process control as documented. The Node.js runtime that runs ScanMux (24.16 or later, before 25) is genuine. On Windows, Job Objects stop every process in a tool's tree, as described in [Windows process termination](windows-process-termination.md).

**If it breaks.** A compromised kernel, Node.js or administrator account controls ScanMux itself, so no result from that machine means anything. A process that outlives its stop could change the snapshot or the output after ScanMux reports.

**How ScanMux or the user keeps it.** On Windows, Git and the scanners that the engines run start through the pinned process owner (`tools.windows-process-owner`), each inside its own Job Object with kill-on-close and no breakaway, and a command that would start a configured tool refuses to run without the pin.
A stop counts only when the whole tree has ended.

Otherwise the run records `termination_unverified`, which makes the result `ERROR`.
Not every process goes through the owner, as [Windows process termination](windows-process-termination.md) lists.

The gh publisher check that runs before the runtime policy admits the run and the `--version` check of the host job owner start directly, and a stop on these paths is always reported as `termination_unverified`.
`doctor` without tools, `runner-check` without Gitleaks, `engine-history`, `job-scan` and `host-job-scan` do not need the owner.

ScanMux also starts several helper processes directly, outside any Job: PowerShell for ACL setup, `taskkill` in the `runner-check` cleanup, the Codex CLI in `runner-check`, the Docker CLI on the `job-scan`, `host-job-scan`, `runner-check` and `ai-scan` paths, and the owner processes themselves.
This list comes from reading the spawn sites and is not claimed to be exhaustive.

The stop confirmation of these processes is not the Job guarantee, and the processes that the Docker daemon starts are outside any Job.
Private working directories are restricted to the current user.
Plans carry the constraint `same_user_concurrent_mutation_not_supported`.

**How it is checked.** Process tree tests stop real trees on Windows and require `termination_unverified` when confirmation fails. An ordinary `scan` does not hash the Node.js binary, and the report records only its version. These checks observe the cases they exercise. They are not a proof about the operating system.

### Git and the repository's objects

**Assumption.** The pinned Git returns the committed contents of the target faithfully, and the commit at HEAD is what the user intends to check.

**If it breaks.** A corrupt object store, or a Git that returns other content, makes every engine scan something other than the commit.

**How ScanMux or the user keeps it.** Git is a pinned tool like the scanners.
It runs with system and global configuration disabled, hooks redirected to a private directory, `core.fsmonitor` off and `protocol.allow=never`.
The same deny-by-default policy applies to the target's `.git/config` and `.git/config.worktree` (section and variable names are case-insensitive):

- Existing keys: `core.repositoryformatversion` (only `0`), `core.bare` (only `false`), `core.filemode`, `core.logallrefupdates`, `core.symlinks`, `core.ignorecase`, `remote.<name>.url`, `remote.<name>.fetch`, `branch.<name>.remote`, `branch.<name>.merge`, and `extensions.worktreeconfig` (only `true|false`).
- Inert metadata: `user.name`, `user.email`, `user.signingkey`, `user.useconfigonly`, `push.default`, `push.followtags`, `push.autosetupremote`, `lfs.<url>.access`, `remote.<name>.pushurl`, `url.<base>.pushinsteadof`, and `branch.<name>.description`, `.rebase`, `.pushremote`, `.vscode-merge-base`. No commit, signing, push, git-lfs, rebase or editor operation reads these keys during scanning.
- Overridden settings: `core.hookspath`, `core.fsmonitor`, `core.attributesfile`, `core.excludesfile`. Every target Git invocation forces private or disabled values, so the configured hooks, monitor and external files are not used.
- Validated conversion settings: `core.autocrlf=false|true|input`, `core.safecrlf=false|true|warn`, `core.eol=lf|crlf|native`. They remain effective for `status`; a Git-clean CRLF checkout may differ from the committed LF blobs. Snapshots always contain committed blobs.

Only these exact keys are accepted, never a whole section. Includes, aliases, filter drivers, SSH commands, unsupported extensions and all other keys are refused before scanning. The restricted grammar requires single-line `variable = value` settings and quoted subsections; malformed and continued lines are refused.
Refusals use `unsupported_git_config:<section>.<variable>` in `plan.blockers` and dependency `missing[].code`, naming only normalized section/variable tokens (at most 64 characters each), never subsection names or values. Malformed or oversized identifiers use plain `unsupported_git_config`. Consumers must handle the suffixed form as well as the plain code.
A dirty worktree blocks the plan.

The plan records each file's object ID, size and SHA-256, and the snapshot is compared with it after every engine (`snapshot_changed` makes the result `ERROR`).
Plans carry the constraints `tracked_files_only` and `git_history_not_scanned`, and plans of a local repository also carry `clean_committed_git_only`.

**How it is checked.** The snapshot hashes come from the same Git that made the plan. They detect a change during the run, not a wrong answer from Git at planning time. This check is not a proof.

### The optional AI engine

**Assumption.** When the user runs `ai-scan`, the provider and the Linux worker process only the accepted projection of the commit, and a person reviews the candidates it returns.

**If it breaks.** Source is sent to a provider whose retention and training policy ScanMux records as `unverified`. A model that misses a problem still completes its review.

**How ScanMux or the user keeps it.** The AI engine (`codex-security`) is required in every plan.
An ordinary `scan` never runs it: the engine reports `isolation_unverified`, so the result is at best `INCOMPLETE`.
In `ai-scan`, the engine runs only for the exact plan hash the user accepted, within the limits recorded in that plan.
Daybreak Blue is requested as an optional higher setting.

Effective `standard` or `daybreak_blue` satisfies the AI program condition; unknown, missing or unrequested programs remain unverified.
Synthetic responses, incomplete evidence, unknown usage and unverified termination still prevent completion.
Its findings are always candidates in the `code` category.

A High/Critical or unknown-severity candidate adds a review reason to the decision and never gives `FAIL`.
It does not change today's final result.
`ai-scan` also requires `runtime-advisories`, which never completes with full coverage, and `INCOMPLETE` outranks `REVIEW`, so the result is `INCOMPLETE`.
The engine is still not advice only.

A failed AI run gives `ERROR`, an unfinished one keeps the result at `INCOMPLETE`, and its completion with full coverage is one of the conditions for `PASS`, a result that no command reaches today.

**How it is checked.** The report records requested and effective access programs separately, along with the attempt, the usage, the destinations and whether the worker boundary was verified. The provider offers no software attestation, so the destination record says `unattestable`. These records are not a proof of what the provider did.

### Public feed matching (KEV and JVN)

**Assumption.** The CISA KEV catalog and the JVN update RSS, fetched over HTTPS from fixed URLs, are what CISA and JVN published, and the local clock is right when freshness is judged.

**If it breaks.** A CVE is labelled `listed`, `not_listed`, `observed` or `not_observed_in_window` wrongly, or a copy is called `fresh` when it is not.

**How ScanMux or the user keeps it.** `intel-refresh` sends one GET to each fixed URL, refuses redirects, limits each body, and parses it strictly.
Attempts are appended to a private store and every read checks sizes and digests again.
`intel-match` writes its result to a separate set of files and never changes a gate, a report or a scan's exit code ([Public feed match](threat-intel.md)).

**How it is checked.** Parser and store tests run against a replaced network function. Nothing verifies a signature on either feed, because neither is signed. These checks are not a proof that a feed is correct.

### The user's config and runtime policy

**Assumption.** The user writes the config and the runtime policy, they say what the user intends, and nobody else, the target repository included, can change them.

**If it breaks.** A pin to the wrong file, a runtime policy that admits too much, or limits that are too small change what runs.
Limits that are too small give `INCOMPLETE` or `ERROR`, never a wrong `PASS`.
A time limit can give either: for example, a version check that times out becomes a failed engine and so `ERROR`.
A wrong pin is the case in the first item.

**How ScanMux or the user keeps it.** The config path must be absolute (`config_must_be_absolute`), outside the target (`path_inside_target`) and at most 64 KiB (`file_limit`), and the config may hold only known keys (`invalid_config`).
A tool entry with an unknown name, or a pin object with the wrong keys or values, gives `invalid_tool`.

Other malformed shapes are also refused, with a different code (a tool value that is not an object gives `invalid_report`).
The plan records `policyHash`, the digest of the config, and `scan` refuses a plan whose config has changed (`plan_integrity`, result `ERROR`).
A runtime policy in state `stopped` starts nothing, and its deny rules refuse a component by name or by digest.

A runtime policy v2 also pins its verifier and its ledger, both outside the target.
Keeping the files writable only by the user is the user's job.

**How it is checked.** Config parsing and plan binding have tests. ScanMux cannot know whether the choices in a config are the right ones. This check is not a proof.

## What ScanMux guarantees and what it does not

An assumption is something a result relies on: if it is false, a result can be wrong without ScanMux noticing. Out of scope is different. It is something ScanMux makes no claim about at all, whether the assumptions hold or not. The right column lists what is out of scope.

| ScanMux guarantees | ScanMux does not guarantee |
|---|---|
| `PASS` only when every required engine completed with full coverage, nothing was blocked or excluded, no engine failed, no integrity error occurred, and no finding is a secret, High/Critical or of unknown severity. No command reaches `PASS` today (see What a result means). | A `PASS` is not a statement that the repository is safe. It covers the tracked files of one commit as the pinned tools and rules see them. |
| A missing, failed, cancelled, time-limited or partial required check never becomes `PASS`. | Secrets that the pinned Gitleaks 8.30.1 default rules do not match are not found. Paths in Gitleaks's default allowlist are recorded as excluded, not scanned. |
| Before a tool that ScanMux pins and verifies starts, its file is hashed and compared with the pinned SHA-256, and a tool that does not match is not started. This does not cover the Docker CLI on the AI/Linux worker path, which starts from a fixed path without hashing (the plan records its identity as unknown). Through the Windows process owner, the image that starts is the image that was hashed. Off Windows and on the direct paths, a file replaced between the hash and the start is not detected (see Known unverified points). | A pinned tool is not shown to be honest or correct. The pin fixes which bytes are allowed to start. |
| At scan start, a plan or loaded config that does not match the recorded hashes ends in `ERROR` (`plan_integrity`). During the run, the snapshot copy is compared with the plan after each engine, and a change ends in `ERROR` (`snapshot_changed`). The config file is not read again during the run. | Git history, other branches, untracked files, build output that is untracked or generated later, and the deployed environment are not scanned. Tracked build outputs are tracked files and are scanned. |
| A stop that cannot be confirmed is `ERROR`, never success. | The OSV engine reports dependency vulnerabilities only from the local OSV copy and only in files that OSV-Scanner reads. The database's age is not enforced. The `runtime-advisories` engine matches declared runtime versions against its built-in catalog without OSV. |
| A feed match is written separately and never changes a gate, a report or a scan's exit code. | A KEV listing does not prove that the vulnerability can be exploited in the target. `not_listed` does not prove that it is not exploited. |
| | An AI candidate is not a confirmed finding, and a completed AI review with no candidates does not show that there are none. |
| Optional Trivy supplements the existing four required engines; enabling it does not remove or complete any of them. Unanswered planned input units remain partial and `INCOMPLETE`. | Trivy covers only the five configured IaC formats through pinned embedded checks. It does not prove deployability, runtime safety, complete format support, check freshness or the absence of misconfiguration. Its findings are candidates. |

## Dependency project analysis

uv workspace analysis starts only when the root declares `[tool.uv.workspace]` or the lock has non-empty `[manifest] members`; editable path dependencies alone retain single-project analysis. Workspaces are determined only from the dependency inputs already collected for each commit. `uv.lock` supplies the editable/virtual member paths; safe relative paths, collected member manifests, matching normalized project names and an exact `[manifest] members` set are required. A missing `[manifest]` means only the root. Workspace `members` and `exclude` support literal paths and a single trailing `/*`; every selected collected manifest must be locked, and nested member workspaces are unsupported. Membership outside this subset remains `undetermined` with `workspaces_outside_subset`. A member's invalid manifest or dynamic dependencies makes the whole project undetermined with that member's reason.

A virtual root may omit `[project]` when it declares a workspace; it contributes only dependency groups and resolution settings. Other roots without `[project]` remain `manifest_invalid`. Member requirements are merged with path-labelled sections, root-only resolution settings and sources from all members. The manifest digest covers all member manifests. Existing input budgets and exclusions apply without additional filesystem reads. Base and head are independent. npm workspaces still use `workspaces_outside_subset`, and advisory matching is unchanged. A project status of `complete` does not establish manifest-to-lock requirement agreement: single projects and workspaces report `manifest_lock_mismatch` on affected upgrades separately. It is also not proof that a candidate upgrade can be resolved or installed.

For dependency diffs, `manifest_lock_mismatch` also makes an otherwise explained version change or addition undetermined when a node's locked version on its head-side path violates an unconditional, judgeable head manifest requirement in the same group or section as its root edge, or an unconditional, judgeable constraint recorded on that edge. A directly declared name on the path with no root edge in the lock also produces this reason. Marker-bearing requirements and edges, unjudgeable specs or versions, and different specifier spellings or ordering that admit the version do not establish a violation. Upgrade assessments also report `manifest_lock_mismatch` when a locked instance violates an unconditional, judgeable constraint recorded on a root edge reaching it, even if the manifest and lock record the same requirement. Unexplained entries, project status, `missing` and exit codes are unchanged.

deps checks only `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `go.mod`, `go.sum` and `Cargo.lock`. Other dependency files from a fixed list (for example `Pipfile.lock`, `composer.lock` or `requirements-dev.txt`), and `package.json`, `pyproject.toml` or `Cargo.toml` with no matching lockfile in their own or a parent directory, are listed per side as `missing[]` entries of kind `unsupported_dependency_file` with their path. They do not change `osv.state` or the exit code, so `not_applicable` with exit 0 can still leave such files unchecked.

## Known unverified points

- Trivy's restricted Windows prototype observed a failed DNS lookup (11001) and denied direct TCP connection (10013). A UDP `SendTo` call succeeded, but delivery was not observed. UDP denial and a claim that all network traffic is blocked are unproven.
- The Trivy AppContainer prototype could read siblings outside the intended input set when they were readable by All Application Packages. Windows also creates profile storage. Read/execute grants on the snapshot and binary and Modify access to the working area's contents do not prove an exact path allowlist or that the working area is the only writable location. Live-repository and credential isolation beyond the measured cases remains unverified.
- The 52 Trivy prototype observations establish only the exercised inputs. They do not establish completeness for the five formats, external references, Terraform modules or Helm charts. Silently omitted malformed Kubernetes input is a known reason to retain partial coverage. Trivy's embedded checks are not refreshed by a scan, and ScanMux does not establish their freshness or independently authenticate their publisher.
- DNS lookups made by `intel-refresh` were not measured. The feed tests replace the network function, so no test observed real traffic. The requests carry no repository data, but the lookups reveal the feed hosts and the time of a refresh.
- The POSIX branches of the feed store's permission checks (owner and mode 0700) have not run on a POSIX machine in this project's CI. Both workflows run on `windows-2025`.
- The Docker CLI on the AI/Linux worker path is started from a fixed path without hashing, so the SHA-256 guarantee does not apply to it. Helper processes that ScanMux starts directly (PowerShell, `taskkill`, the Codex CLI in `runner-check`, the Docker CLI, the owner processes) run outside any Job, and their stop confirmation is not the Job guarantee.
- Off Windows, and on the Windows paths that start a tool directly, the SHA-256 check and the start of a tool are two steps. ScanMux hashes the file and then starts it by path, so a file replaced between the two is not detected. For a tool started through the Windows process owner, the owner hashes the image it starts.
- On Windows, the private copy of the process owner can be rewritten by another process of the same user, or by an administrator, between its write and its start. The SHA-256 check does not cover that window.
- The OSV database receipt is not authenticated, as described above.
- The terms of the JVN update RSS have not been verified.

## Change history

| Date | Change | Approved |
|---|---|---|
| 2026-10-26 | Initial version | pending |
| 2026-10-26 | Optional pinned Trivy scope, trust base and measured isolation limitations | pending |

approved: pending


## Related docs

- [Get started](getting-started.md)
- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Windows process termination](windows-process-termination.md)
- [ScanMux](../README.md)
