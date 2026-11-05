[English](getting-started.md) | [日本語](getting-started.ja.md)

# Run your first offline scan

Prepare the tools, database and configuration here before scanning your first local repository.

## Requirements

- Node.js 24, version 24.16.0 or newer, before 25; Git with ordinary SHA-1 repositories.
- Gitleaks 8.30.1 and OSV-Scanner 2.7.0, installed separately from their official releases.
- OSV databases downloaded before scanning.
- A clean, committed Git root for local CLI scans.
- On Windows, a pinned process owner when a configured tool will start; see the build instructions below.

OSV-Scanner 2.7.0 / SCALIBR 0.5.3 reads `<database-root>/osv-scalibr/<ecosystem>/all.zip`.
The ecosystems include `npm`, `PyPI`, `Go` and `crates.io`.
Do not use the older `osv-scanner` subdirectory shown in some upstream documentation.
Scans never download or update databases.

Worktrees, linked metadata, local shallow repositories, dirty/untracked files and nonstandard Git configuration are outside this PoC.
The Web interface acquires public GitHub commits separately.
Submodules, symlinks, LFS pointers and binary blobs containing NUL are excluded from snapshots.
Remaining supported files can be scanned; the exclusions remain incomplete coverage.

Windows and a fixed Linux container path have been tested for offline static scanning.
Linux checks cover normal input, a missing database and a synthetic secret.
Targets stayed unchanged, and each scan had zero packet-counter change.
The test suite runs on macOS in CI; job commands and the production AI runner remain unsupported there.
Targets under a symlinked ancestor, such as macOS `/tmp` or `/var`, are refused with `linked_path`.
Windows uses a private per-run access control list (ACL).
If the environment cannot create or access that directory, report failure; do not weaken the ACL.

## Run your first offline scan

### 1. Check the source checkout

Install the controller dependencies, check the source and print the command list.

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
node bin/scanmux.mjs --help
```

Successful checks finish without errors. The final command prints the CLI help.

You can also install a downloaded release tarball into a separate consumer directory:

```sh
npm install --prefix /absolute/consumer --ignore-scripts --omit=dev --no-audit --no-fund "/absolute/scanmux-<version>.tgz"
/absolute/consumer/node_modules/.bin/scanmux --version
/absolute/consumer/node_modules/.bin/scanmux deps /absolute/committed-repository --config /absolute/config.json --json
```

On Windows, invoke `scanmux.cmd` in that `.bin` directory. Prepare the pinned tools, offline database and configuration below first.
Release CI installs the actual tarball and checks `--version` and completed offline dependency analysis of a committed npm fixture.
This check does not establish installed AI-runner or release-transparency verification support.

### 2. Prepare a recorded offline database

From a source checkout, download the selected official OSV databases to a new absolute path outside every scan target.

```sh
node scripts/fetch-osv-db.mjs --destination /absolute/new-database --ecosystems npm,PyPI,Go,crates.io --max-bytes <total-byte-limit> --timeout-ms <total-timeout-ms>
```

Success creates `database-receipt.json` only after all requested downloads finish.
The script is a repository operator tool; it is not included in the npm package.
Replace the placeholders with positive integers for the current database sizes, total transfer budget and total timeout in milliseconds.

The tool contacts only the four fixed official public database URLs.
It uses no credentials, redirects or retries.
It verifies response length and MD5 against downloaded bytes, then computes SHA-256.
It refuses an existing destination.
Keep the previous dataset and configuration until the new dataset is ready.
Then set `osvDatabase` to the new root; restore the old path to roll back.

> Q. What happens if a download fails?
>
> A. A marked incomplete directory remains, and scans reject it. Choose a new destination for another attempt.

During scanning, required databases are copied into the private run workspace, hashed and used by OSV there.
The copies are checked again before results are accepted.
Recorded provenance distinguishes acquisition completion, the provider object's last-modified time and the source filesystem's `modifiedAt`.
`dbAsOf` remains null. An object's modification time does not prove an advisory-completeness cutoff.
Unmarked datasets without a receipt stay usable with `provenance.state: "unknown"`.
An invalid receipt or mismatched database is rejected before `osv scan source` starts.
The existing OSV `--version` check can still run.
Receipts are local records, not authenticated publisher signatures or a freshness guarantee.

### 3. Create trusted controller configuration

Save this template outside the scanned repository, replacing every path and digest placeholder with verified local values.

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

The saved configuration names absolute paths to real files, not symlink launchers.
Obtain each binary's SHA-256 from a trusted installation or release and record its verified version.
Set `osvDatabase` to the prepared database root.
Windows JSON paths can use forward slashes.
On Windows, calculate a digest with `Get-FileHash -Algorithm SHA256 <executable>`; on Linux, use `sha256sum <executable>`.
A local hash pins bytes; it does not independently establish the publisher.

### 4. Build and pin the Windows process owner

On Windows, build the helper into a new private directory outside the scanned repository.

```powershell
powershell -NoProfile -File scripts/build-windows-process-owner.ps1 -OutputDirectory C:\absolute\new\directory
```

Success prints a `scanmux.windows-process-owner-build/v1` JSON receipt with version, source SHA-256, assembly SHA-256 and assembly size.
Add the assembly path, digest and version as `tools.windows-process-owner` in the configuration.
See [Windows process termination](windows-process-termination.md) for the exact pin shape and requirements.
Other platforms use process groups and ignore this pin.

### 5. Check the tools

Inspect the configured executable identities and missing capabilities before planning.

```sh
node bin/scanmux.mjs doctor --config /absolute/controller.json --json
```

The JSON reports tool and capability states. Missing required conditions return exit 3; this is not a security verdict.

### 6. Inspect a plan

Read the fixed commit, accepted inputs, exclusions, coverage, transmission and cost before scanning.

```sh
node bin/scanmux.mjs plan /absolute/repository --config /absolute/controller.json --json
```

A successful plan returns exit 0 for planning only.
Its output is an inspection artifact, not an approval token that can be imported later.

### 7. Run the offline scan

Run the scan with plain output, or choose the second command for JSON output.

```sh
node bin/scanmux.mjs scan /absolute/repository --config /absolute/controller.json
node bin/scanmux.mjs scan /absolute/repository --config /absolute/controller.json --json
```

The plain summary prints private HTML, JSON and SARIF report locations.
`--json` prints the report without report paths.
`scan` recalculates its plan immediately before execution.
An ordinary scan remains incomplete because required AI analysis is blocked and runtime-advisory coverage is partial or unsupported.

## Keep scan output private

- Reports can contain package names, file names and repository paths.
- Raw scanner output and detected secret values are not retained.
- Gitleaks checks the serialized report and its destination before output.
- A detected secret or unavailable output check returns a fixed error instead.

## Limit copy bytes

For `scan`, the controller config (schema 1 or 2) accepts an optional top-level `maxCopyBytes`.
For `job-scan` and `host-job-scan`, put the same optional key at the top level of the offline job profile (v1 or v2), alongside `scan` and `limits`; `host-job-scan` reads the profile referenced by its host profile.
Set a positive safe integer number of bytes per repository profile; there is no default.

Omitting it preserves the existing configuration and saved-result formats, including their schema versions and retained-record accounting.

This is a logical byte budget for the copies ScanMux makes of provenance artifacts, bundles and trusted roots, OSV database ZIPs, the fixed job application, the Windows process owner and Trivy.
ScanMux reserves each source's size before creating its destination, then checks each streamed chunk before writing it.

A growing source cannot write beyond its reservation; a verified-size mismatch or a source changing size during copying follows the caller's integrity-error path.

No expected size is recorded for provenance artifacts, bundles or trusted roots, so a larger replacement that exceeds the remaining allowance reports `job_disk_copy_limit` (`INCOMPLETE`) before the hash check can report the change (`ERROR`).
Successful copies consume the allowance, including copies later removed.

A refused or failed copy releases its reservation only after its partial output is removed; failed removal stays charged and is an IO error.
The standalone job passes the allowance left after host admission and application copying to its Linux controller without adding fields to saved plans or reports.

A single-scan command (`scan`, `ai-scan` or `resume`) shares one budget across admission copies, its process-owner executable and the scan's copies.
In commands that run multiple scans, including `serve` and `scan-list`, every `scan()` gets a fresh budget from that scan's own config.
Command-level admission and process-owner copies use a separate budget with the command config's limit.

Omitting the key from a scan's config leaves that scan's copies unbounded by this option, even if the command has a budget.

An exhausted allowance is `INCOMPLETE` with `job_disk_copy_limit` (exit 3); an earlier `FAIL` or `ERROR` keeps its priority.
Refusal before the owner starts uses the existing `scanmux.error/v1` envelope with that gate and cause; `deps` instead reports failure with exit 2 and the cause, without a scan gate.
In `host-job-scan`, the Windows parent charges admission copies and passes only the remainder through transient owner/worker arguments.

The worker charges its own admission copies and the app copy, then passes the remainder to Linux through the existing bootstrap.
Before creating `D/app`, it checks the whole app manifest against the remainder, so a budget shortfall leaves no partial app; size or hash changes remain integrity errors.
Allowance flows forward only.

Host v1/v2 record formats, validators and retained-byte accounting are unchanged; omitting the key also preserves owner arguments.
Worker or Linux shortfalls use existing report reasons, with earlier errors, cancellation and deadlines retaining precedence.

The budget does not bound external engine writes, Git snapshot materialization, generated reports or checkpoints, Docker/OS stores, filesystem metadata, or export destinations.
It does not supply a whole-directory physical quota.
Physical allocation can exceed logical file bytes; a physical quota needs operating-system configuration, which ScanMux does not change.

The optional measured limit below observes registered job directories separately.

## Measure and limit job disk use

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

## Choose fixed commits or multiple repositories

For local repositories, pass both `--base <40-character-commit-SHA>` and `--head <40-character-commit-SHA>` to `plan` or `scan`. Branch names, abbreviated SHAs and a lone option are rejected. Both commits must already exist in that repository, and its working tree must remain clean. The selected head can differ from the checked-out HEAD.

The plan records both commit/tree identities and added, deleted, modified or mode-changed paths.
Renames are deletion plus addition.
**All accepted files in the head snapshot are scanned**, including unchanged dependency inputs; an empty diff does not skip required checks.
This is a diff-context scan, not a changed-lines-only scan.

Base findings are not compared, and the report does not claim a finding was introduced or fixed by the change.
JSON, HTML and SARIF distinguish this scope from an ordinary whole-snapshot run.

To configure multiple repositories, save an explicit manifest outside every target:

```json
{
  "schema": 1,
  "repositories": [
    { "id": "library", "path": "/absolute/library" },
    { "id": "service", "path": "/absolute/service" }
  ]
}
```

Each local entry can include a paired `base` and `head` SHA.
A public GitHub entry uses `url` instead of `path`, with the same URL restrictions as the Web interface; base/head is unsupported for URLs because acquisition fetches one fixed HEAD without history.

Unknown fields, duplicate or overlapping local roots, duplicate URLs/IDs and controller files/tools/databases inside any target are rejected before the first job.

```sh
node bin/scanmux.mjs plan-list /absolute/repositories.json --config /absolute/controller.json --json
node bin/scanmux.mjs scan-list /absolute/repositories.json --config /absolute/controller.json --json
```

Jobs run sequentially with separate private workspaces.
Every manifest entry remains in the batch JSON, including failed or unstarted jobs; each completed job records its run ID and references its own secret-checked plan and report files.
A terminated job failure keeps earlier results.
Cancellation, the batch `timeoutMs` deadline or unverified process termination stops new jobs.

The deadline covers planning, acquisition and scanning; secret checking and result storage then run as bounded finalization using the existing per-operation timeouts.
Source copies are still removed at the end of each job, even when termination is unverified. If removal fails, the job reports `source_cleanup_failed` and the directory is kept.
Local repositories are never deleted.

`plan-list` returns 0 only for successful planning of every target and never emits a security `PASS`.
`scan-list` aggregates all entries using the [result precedence](results.md#read-the-gate-and-exit-code); missing work prevents `PASS`.
The batch summary is stored separately as `batch.json`; JSON output contains its complete contents.
A save/check failure is an error, not a completed report.

Abrupt process/OS termination can leave only already-saved per-job files; automatic batch resume is not provided.

## Compare dependency advisories, upgrades and lockfile changes

`deps` plans each selected commit and runs offline OSV on each side's planned lockfiles in separate private snapshots. Both sides use the same pinned OSV-Scanner, copied database and empty configuration; `osv.database` records the database identity once and `osv.sides` records each side's completion. Upgrade/diff analysis also reads committed `package.json`, `.npmrc`, `pyproject.toml` and `uv.toml`, within `maxFileBytes` and the plan's LFS/binary exclusions. It never writes to the target repository, checks out, installs, regenerates locks or fetches.

```sh
node bin/scanmux.mjs deps /absolute/repo --config /absolute/controller.json --base <SHA> --head <SHA> --json
```

Each OSV finding in an npm v2/v3 or uv.lock v1 lockfile is `allowed` (declarations admit a newer fixed version; not a resolution or install proof), `blocked` or `undetermined` with a closed reason.
With base/head, changed lockfile entries are classified; version changes and additions are explained by a path from a changed direct requirement or listed as unexplained.

JSON uses `scanmux.dependencies/v2` and includes `tool: { name: "scanmux", version }` from the installed package. `advisories` has one entry per lockfile path, ecosystem, package name and OSV id. Status is `removed` (base only), `added` (head only), or `unchanged` (both, even across a version change); without a base it is `present`. `advisoryCounts` counts all four statuses. Text output lists added advisories first. A failed/incomplete side prevents advisory comparison and returns exit 2, even when no advisories were observed.

Each entry includes `baseVersion`/`headVersion` (null when absent; multiple locked versions are sorted and joined with `, `), `id`, `aliases`, `severity` (the record's `database_specific.severity`, otherwise null; no score is calculated), and `fixedVersions` from matching affected ranges (empty when none). `dev` uses npm lockfile `dev`/`devOptional`, choosing head when present, otherwise base; it is true only when every matching instance is a development dependency, and null for other ecosystems. npm v2/v3 links and workspace packages declared in the lockfile are local and do not cause incomplete offline matching. An undeclared versionless package still does. npm workspace project analysis remains `undetermined` with `workspaces_outside_subset`.

uv workspace analysis starts only when the root declares `[tool.uv.workspace]` or the lock has non-empty `[manifest] members`. Other uv projects keep single-project analysis, including editable path dependencies. Workspace analysis accepts the `editable` and `virtual` member paths recorded in `uv.lock`, relative to its directory. Every member's committed `pyproject.toml` must be among that side's collected inputs, and its normalized project name must match the lock package name. The lock's `[manifest] members` must match those packages; an omitted `[manifest]` means a root-only workspace. Paths must stay inside the lock directory without absolute paths, `..` or backslashes. Workspace `members` and `exclude` accept literal paths or one trailing `/*` segment. Every collected manifest selected by those patterns must be locked, and members cannot declare nested workspaces. A membership failure stays `undetermined` with `workspaces_outside_subset`; a member's invalid manifest or dynamic dependencies retain their own reason. No extra filesystem discovery occurs, and the existing input budgets and exclusions still apply.

A virtual workspace root without `[project]` contributes dependency groups and resolution settings; without a workspace it remains `manifest_invalid`. Requirements are merged for comparison and upgrade judgments, with non-root sections labelled by relative member path (for example, `servers/member:project.dependencies`). Overrides, constraints and cutoff settings come from the root; sources cover every member. `manifestSha256` covers the root and member manifests, and base and head use their own inputs. A project status of `complete` does not mean its requirements agree with the lock: in both single projects and workspaces, affected upgrades report `manifest_lock_mismatch` separately. These rules do not change advisory matching.

Resolver settings outside the repository are not read.
**The `deps` exit codes changed in 0.2.0**, replacing the previous 0/3 analysis result: 2 means a failed/incomplete OSV check on either side, an unreadable/unparseable planned lockfile, an unresolved commit or another plan blocker; 10 means added advisories with a base, or present advisories without one; 0 means all required checks completed with no added (or present) advisories. Existing unchanged advisories may remain at exit 0, so it is never a security `PASS`. Upgrade-analysis `undetermined` results remain visible and do not change the exit code.

## Reproduce one finding and check an unchanged regression test

Choose an original Report v2/v3 finding and a dedicated, tracked directory containing the caller's `test.mjs`.
It runs only in the existing offline Linux job, with a locally present pinned image, normal limits and verified removal; no pull, installation, host project execution or AI call occurs.

```sh
node bin/scanmux.mjs reproduce ./project --job-profile /absolute/offline-profile.json --from /absolute/before-report.json --finding codex-security:FINGERPRINT --test tests/repro/example --json
# For a fix check, also pass --base FULL_BASE_COMMIT --head FULL_HEAD_COMMIT.
```

Replace `FINGERPRINT` with the report's complete 64-character fingerprint and both commits with different lowercase 40-character hashes.
The original report must belong to base. The entire test directory (paths, file modes and bytes, including helpers and fixtures) must already exist unchanged in both commits; a change is refused before either probe runs.
The default single-snapshot check supplies supporting evidence; `--required` records it as required. A before/after check is always required. Every requested check must be verified for `reproduce` to return PASS/0.

The probe exports `default async function ({ projectRoot })`, returning `{ kind: 'observed', problem: 'present' }` or `problem: 'absent'`.
Unavailable prerequisites return `{ kind: 'environment_missing', reason: 'offline_dependency_missing' }` (`fixture_missing` and `runtime_not_available` are also supported). Exceptions, skips, invalid returns, nonzero exits and timeouts never mean absence. The caller owns the oracle's correctness and bundles its helpers/fixtures in that directory.

Only a recorded positive base followed by a completed negative head, with the same test and runtime and both containers removed, yields “The same test no longer reproduces at head, with the test unchanged.”
The separate confidential `verification.json`, HTML, SARIF and attempt receipts retain the original report bytes. When verification holds, the policy gate and exit code still describe the original report snapshot, so a successful fix check can return FAIL/1 for a reproduced High/Critical base finding. Scan head separately for its policy result.
Saved-record checks catch a result being applied to the wrong finding or test by mistake. These records are local files without signatures; the checks do not protect against someone deliberately rewriting them.
Any `not_verified` result returns INCOMPLETE/3 regardless of the original report's gate or the supporting/required setting; integrity violations and existing execution errors return ERROR/4. The original report is never rewritten.
The profile's retained budget covers the whole bundle; execution limits remain per job. Runtime/source copies are removed; the private verification bundle remains. Whole-command time and physical storage are not guaranteed.

v0.2.2 leaves out generated tests or patches, newly added/edited tests between base and head, semantic test-strength or suite-wide weakening analysis, framework discovery, builds/installation, online prerequisites, other runtimes, Trivy selection, automatic dispositions/report rewrites, head-wide safety verdicts, imported runtime evidence, retries/resume, caches, batch/web/SDK/host-job execution.

## Related docs

- [Web interface](web-interface.md)
- [Urgent advisories](urgent-advisories.md)
- [AI scan](ai-scan.md)
- [Runtime controls](runtime-controls.md)
- [Read, save and check results](results.md)
- [ScanMux](../README.md)
