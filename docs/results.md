[English](results.md) | [日本語](results.ja.md)

# Read, save and check results

Use this guide to interpret gates, save reports, check CI completion, inspect history, recover records and record human judgments.

## Read the gate and exit code

| Result | Exit | Meaning |
|---|---:|---|
| `ERROR` | 4 | Execution, report parsing or integrity failure |
| `FAIL` | 1 | Secret finding or source-supported High/Critical finding |
| `INCOMPLETE` | 3 | Missing, excluded, unsupported, cancelled or time-limited required coverage |
| `REVIEW` | 2 | High/Critical candidate or unknown severity with otherwise complete coverage |
| `PASS` | 0 | All required checks completed without a blocking or review finding |

Precedence follows table order.
Findings remain in reports even when an error takes priority.
OSV matches and AI findings are candidates, not runtime confirmation of exploitability.
Gitleaks findings require validity/revocation review.
The blocked AI adapter means a complete ordinary PoC scan **cannot produce PASS**.
`doctor` returns 3 while these missing conditions remain.

A successful `plan` returns 0 for planning only; it is not a security verdict.

## Check verification evidence and limits

`npm test` covers the decision table, malformed reports, unsafe paths, ignored credentials, AI blocking, process cancellation, timeouts, output limits and executable digest mismatch. These tests use synthetic data and do not run an AI model.

With trusted local tools and the four downloaded databases:

```sh
npm run verify:real -- /absolute/controller.json
```

This creates its own private Git fixture using normal Git hooks.
It checks real OSV matching for four ecosystems, Gitleaks detection/redaction, ignored target settings, dirty-tree rejection, doctor and JSON output.
It never installs fixture packages.
Synthetic secret material is generated only in a disposable snapshot and is never committed.

Fixture/report directories remain private local artifacts for inspection.

Observed Windows run: OSV returned 57 advisory candidates across four ecosystems; Gitleaks completed, and detected a separately generated synthetic credential.
Combined coverage remained incomplete.
Database updates can change the count; the verifier checks the outcome, not an exact count.
Separate Linux offline tests cover the isolated execution path; no production AI scan has run.

The Web acquisition path was exercised with a small public GitHub repository, including fixed-commit planning, real static scanning, browser JSON download and cancellation during an active Git fetch.
Its object size check runs after transfer and is not a hard disk quota.

`node scripts/verify-github.ts /absolute/controller.json` repeats acquisition and cancellation checks with network access during acquisition only.
Web unit tests cover authentication, cross-site requests, stale IDs, duplicate execution, pending cancellation and retained data after unverified termination.

> Q. Why are working data retained after `termination_unverified`?
>
> A. Windows could not verify termination of the entire child process tree. Confirm termination independently before starting a replacement or removing data. This differs from confirmed cancellation; there is no automatic crash recovery.

SARIF upload/CI integration, persistent history and base-finding comparisons, production Linux scans, model allowance/cost enforcement, persistent resume, fixes and release signing are future work. A zero-finding report is not a guarantee of safety.

## Read and save the audit report

`scan` saves `report.html`, `report.json` and SARIF 2.1.0 in the same private run directory and prints their locations.
`--json` prints the JSON without report paths.
All formats and destination metadata pass secret checks before any report is saved; existing files are never overwritten.
An I/O failure may leave checked partial output there.

The Web result offers **HTML監査レポートを保存** and **JSONをダウンロード** only after the bundle is saved.
SARIF is available only as local CLI files, not as a Web download.

SARIF keeps every finding in its original order, with its fingerprint, ScanMux decision and execution/coverage states.
An incomplete or failed required check remains incomplete even when no findings exist; SARIF severity levels do not replace the ScanMux decision.
Unsupported metadata and unsafe locations are omitted with explicit flags; the finding is kept.

Absolute repository paths, source snippets, arbitrary titles and raw errors are excluded.
Treat SARIF as private: supported relative paths and package identifiers can still disclose project details.
Files contain one run and at most 5,000 results, within the configured UTF-8 output limit and a 10 MiB gzip limit.

Large exports use `report-0001.sarif`, `report-0002.sarif` and so on, otherwise `report.sarif`; the CLI and each part record the part number, part count and total findings.
No upload is performed.

The HTML groups findings by engine, package/product and version, ordered by known severity.
Each target shows candidate and location counts plus unknown severity separately.
Expand individual evidence as needed; printing includes every record regardless of expansion.
Fixed-version suggestions remain attached to each advisory, not merged into one promised upgrade.

The HTML report includes the decision, priority actions, scope and engine coverage, findings, exclusions, limitations, and reproducibility hashes.
It preserves the JSON decision, including incomplete and failed checks, and identifies missing required engine records.
It is standalone, with no scripts or external resources, for offline viewing and browser printing.

HTML omits local absolute paths and arbitrary diagnostic text; JSON remains the detailed private record.
Findings and suggested fixed versions still require verification against the relevant official advisory and deployed environment.
It is not a human audit opinion.

HTML defaults to Japanese.
`scan`, `ai-scan`, `resume`, `scan-list`, `recover`, `job-export`, `job-recover` and `intel-match` accept `--report-language en` for English or `ja` for explicit Japanese, e.g.
`scanmux scan /absolute/repo --config /absolute/config.json --report-language en`.
It changes only application-owned HTML labels and explanations.

JSON, SARIF, decisions, identifiers, source locations and original evidence remain unchanged; source names and model text are not translated.
Web downloads stay Japanese.
Other commands reject this option; unsupported languages are rejected before scanning.

## Check local CI completion

`scan` with paired `--ci-run UUID --ci-job ID` can write a private `ci-receipt.json` after all report files have been saved. The receipt contains fixed identities and engine states, without source text or the local repository path. Use a fresh UUID for each CI attempt and a distinct job identifier for each expected scan:

```powershell
node bin/scanmux.mjs scan C:/repos/project --config C:/scanmux/controller.json --ci-run 11111111-2222-4333-8444-555555555555 --ci-job project
node bin/scanmux.mjs ci-check C:/scanmux/expected.json C:/private-run/ci-receipt.json --config C:/scanmux/controller.json
```

Generate a new UUID before each attempt; the one above is illustrative.
Before scanning, run `plan` with the same configuration and base/head options and freeze an expectation outside every target.
Its shape is `{ "schema": "scanmux.ci-expectation/v1", "ciRun": "<fresh UUID>", "jobs": [...] }`.

Each job has `id`, the canonical absolute `targetRoot`, and the exact `repoId`, `commit`, `policyHash`, `planHash`, and `snapshotHash` from that pre-scan plan.
Never derive expectations from completed receipts.
The job list must be nonempty with unique IDs.
This v1 workflow covers a single local offline `scan`, run once per expected job.
The tags never enable AI or change the scan decision.

Pass every available receipt to `ci-check`; passing none records every expected job as missing.
The checker requires each expected job and all four engines to complete, matches the attempt/repository/commit/policy/plan/snapshot identities, rejects duplicate or unexpected receipts, and preserves the strongest decision.

A skipped, missing or incomplete check cannot succeed, so the current AI block keeps real offline runs nonzero.
A receipt or report save failure returns 4 and keeps files already saved.
`--json` keeps the scan report on stdout and writes the receipt location to stderr.
The checker saves its own private `ci-result.json`; manifest inputs together must fit the configured output byte limit.

This is a local controller primitive, not a deployed GitHub Actions workflow.
The controller must create a fresh attempt UUID and protect the expectation, executable code, configuration and receipt transport from target changes.
Paths and hashes do not authenticate an execution or prevent a trusted operator from reusing an old attempt.

Use protected-base or external CI policy; do not execute this machinery from an untrusted PR checkout.
All input files, configured tools/database/runner paths and output workspaces must stay outside the canonical local target roots.
Public-URL checkout receipts and protected checks are not implemented.
For real CI, see [GitHub Actions](github-actions.md).

The usual `scan` command remains available without CI tags.

### Include an explicitly accepted AI scan

For an AI job, first run `ai-plan`, review its disclosure, and fix the expectation before execution.
Use `scanmux.ci-expectation/v2` with the same top-level `ciRun` and `jobs` keys.
Each job has all v1 identity fields plus `analysis: "ai"` for an AI job or `analysis: "offline"` for an ordinary scan.
Take the AI job identities from `ai-plan`, not from the offline plan or a completed receipt.

V2 can combine offline and AI jobs; offline jobs still produce v1 receipts.

```sh
node bin/scanmux.mjs ai-scan C:/repos/project --config C:/scanmux/controller.json --accept-plan <planHash> --ci-run <fresh-UUID> --ci-job project
node bin/scanmux.mjs ci-check C:/scanmux/expected-v2.json C:/private-run/ci-receipt.json --ci-report C:/private-run/report.json --config C:/scanmux/controller.json --json
```

`ai-scan` retains its exact Plan acceptance, source checks, isolation and limits.
After saving the complete report bundle it writes `scanmux.ci-receipt/v2` with `analysis: "ai"`.
Pass each AI receipt's exact saved `report.json` with a repeated `--ci-report`; reformatting changes its hash.

The checker matches report bytes, run/repository/commit/policy/plan/snapshot, gate, execution/coverage and engine rows, then uses the shared saved-report completion rule.
Effective `standard` or `daybreak_blue` satisfies the program condition.

Synthetic responses, unknown/missing or unrequested programs, rejected artifacts, missing usage and incomplete cleanup/scope cannot yield PASS, even when the input's top-level fields declare success.
Stronger FAIL/ERROR decisions remain stronger.
A missing report is incomplete; wrong, duplicate or unused reports and mode mismatches are refused or ERROR.

V1 expectations cannot consume AI receipts or `--ci-report` inputs.

V2 saves `scanmux.ci-result/v2`.
Its job rows add `analysis`, `reportState` (`not_required`, `missing` or `verified`) and `reportHash`; the hash is non-null only after association checks succeed.
The text summary shows each AI job's effective program from its associated report; saved schemas are unchanged.
It contains no source text or raw findings.

Report and receipt inputs together count toward the configured aggregate input limit.
Final checking starts no target analysis, inference or network traffic; the existing local output secret check still runs.
It does not authenticate GitHub transport or establish real Blue access.

> Q. The scan ran, but CI receipt checking or saving failed. Should I rerun it?
>
> A. Do not repeat inference just to repair a missing CI record. Exit status is 4, and the saved bundle remains available. Stderr says the scan already ran and gives its checked run ID and JSON path.

These job tags are not accepted by Web, batch, resume or `ai-plan`.

## Read saved execution history

`node bin/scanmux.mjs history C:/private-run/report.json C:/another-run/report.json --config C:/scanmux/controller.json` reads only the report files you name and saves a new private `history.json`.
`--json` emits that summary.
Exit 0 means reading and saving succeeded, not a security PASS.
Originals stay unchanged.

The files together must fit the configured output byte limit, and their canonical local target roots must still exist.
Inputs, controller configuration and tools, and the output workspace must be outside all target roots.

Each row keeps its recorded decision, execution/coverage states, commit and policy/plan/snapshot identities.
Different runs and revisions remain separate.
Missing required engine records are shown as missing, never filled with zero calls.
A recorded PASS that conflicts with incomplete execution is explicitly flagged; findings are not rejudged.

Exact duplicate report bytes with the same run ID count once.
Different bytes under one run ID, including reformatted JSON, and duplicate engine records are rejected.

Call totals mean recorded calls in the selected unique runs, with missing engine records counted separately.
Unknown cost stays unknown; not-applicable cost is a distinct state and neither means a measured zero price.
Hashes do not authenticate records.

The command does not establish account billing or remaining allowance, reserve budgets, resume execution, suppress findings, scan directories, or import old results into a new decision.

## Recover completed engine records

Every scan saves a secret-checked checkpoint after an engine returns and before starting the next engine.
Checkpoints are retained in the private run directory's `checkpoints` subdirectory, including after normal completion.
Run directories are under the operating system's temporary directory and may be removed by its cleanup policy.

This covers CLI scans, AI scans, each batch repository, resumed scans, and Web scans through their common controller.
Planning and acquisition do not create completed-engine checkpoints.

```text
scanmux recover /absolute/private-run/checkpoints --config /absolute/config.json --json
scanmux recover /absolute/private-run/checkpoints --config /absolute/config.json --report-language en
```

Recovery verifies the latest continuous sequence of complete records and saves a new JSON/HTML/SARIF bundle.
It never reruns engines, reads authentication records, retries inference or contacts a provider.
The original target directory must still exist at its recorded physical path; deleted controller-acquired GitHub directories cannot be recreated by recovery.

Use the normal final report when available.
Recovery always returns `ERROR`/4 with `controller_completion_unverified`, even with every engine record present or the controller still running, because a checkpoint cannot establish finalization or process termination.
Completed engine findings and recorded usage remain unchanged.

A recovered record cannot be used as a cancelled/time-limited resume source.
Do not start replacement work while the original process state remains unverified.

Each checkpoint body is secret-checked, written exclusively, synced and closed before its receipt is written.
The next engine waits for the receipt to sync and close.
Recovery verifies readable receipt/body bytes; it cannot prove a past acknowledgment return, authenticated provenance, or power-loss durability.

An incomplete final receipt is ignored with an explicit notice; a complete receipt with mismatched data or a gap is rejected.
A scan retains at most ten checkpoint files (eight without Trivy), each bounded by `maxOutputBytes`: a logical byte bound, not a physical disk quota or a job-wide CPU/memory/disk limit.

Keep checkpoint files private and do not combine different snapshots of the same run in `history`.

## Rerun a stopped scan

```powershell
node bin/scanmux.mjs resume C:/repos/project --from C:/private-run/report.json --config C:/scanmux/controller.json --json
```

`resume` starts one full scan with a new run ID after checking a saved `cancelled` or `budget_exceeded` report.
Every engine runs again; previous findings and engine results are not reused.
The report must be outside the target, and its target, commit, policy, plan and snapshot must match a fresh plan made from the current root and controller configuration.

A comparison run needs the same `--base` and `--head`.
A changed source or policy needs an ordinary new `scan`.
Invalid records, known unverified process termination, completed runs and identity mismatches are refused before starting scanners.
There is no automatic retry.

Before scanning, stderr records the previous reported usage, missing engine records, new scan time limit, and the current offline estimate of zero additional AI calls with not-applicable cost.
Unknown previous cost remains unknown.
Once the new report bundle is saved, a private `resume.json` links the exact old and new report hashes and run IDs, with their usage kept separate.

It is neither an aggregate security decision nor a billing statement; hashes do not authenticate the saved records.
`--json` keeps the new report on stdout and sends the resume record path to stderr.
Original files stay unchanged.

> Q. The new scan finished, but saving `resume.json` failed. Should I run it again?
>
> A. Do not rerun solely to repair that record. The new report bundle remains available. Exit status is 4, and stderr says the scan already ran and gives its checked JSON path.

The command applies to local single-repository scans.
It does not accept CI tags or add Web/batch resume controls.
AI remains blocked, and the existing incomplete decision remains visible.

## Record human judgments

```powershell
node bin/scanmux.mjs dispositions C:/private-run/report.json --config C:/scanmux/controller.json --json
node bin/scanmux.mjs dispositions C:/private-run/report.json --decisions C:/private/decisions.json --config C:/scanmux/controller.json --json
```

The first command lists each finding's engine and fingerprint with the exact report hash.
The second assesses a human-authored JSON file with `schema: "scanmux.dispositions/v1"` and an `entries` array.
Every entry needs these fields:

| Field | Required content |
|---|---|
| `reportHash`, `engine`, `fingerprint` | Exact saved report and finding identity |
| `decision` | `false_positive` (false positive), `risk_accepted` (accepted risk) or `out_of_scope` (outside scope) |
| `reason`, `reviewer` | Nonblank reason and declared reviewer name |
| `reviewedAt`, `expiresAt` | UTC timestamps, such as `2026-10-22T10:00:00Z` |

The reviewer is a declared name, not an authenticated identity.
The program never chooses the decision, reason or expiry for you.
Future review times, expiry at or before review time, malformed fields and duplicate engine/fingerprint keys are rejected.

`current` means an unexpired judgment on that exact saved report and finding.
Expiry is inclusive: at the expiry instant the record is `expired`.
Different report bytes or a missing finding require `reconfirmation_required`, with every reason retained, including concurrent expiry.
Unmatched judgments stay visible beside unreviewed current findings marked `open`.
A missing finding is not proof of a verified fix.

Changed code, evidence, configuration, a different run or even JSON reformatting requires reconfirmation; nothing carries over between runs automatically.

The command saves a new private `dispositions.json` and leaves both inputs unchanged.
Exit 0 means assessment and saving completed.
The original decision and incomplete coverage stay visible; findings stay open in the original scan, and these records never override scan or CI decisions.
`--json` prints the checked summary; plain output prints counts and its saved location.

Inputs together must fit the configured output limit, use canonical regular files outside the still-existing target root, and pass the same controller/tool/output path boundaries as history.
Free-text judgments and destination metadata pass secret checks before saving or printing.
No source text, arbitrary finding titles or source paths are copied into the summary.

## Apply explicit exceptions

```powershell
node bin/scanmux.mjs policy-check C:/private-run/report.json --decisions C:/private/decisions.json --config C:/scanmux/controller.json --json
```

Use the human-authored decision format above.
`policy-check` requires both files explicitly and saves a separate private `policy-result.json`.
Its gate and exit code describe that exact saved report after applying eligible exceptions; the original scan report, findings and CI receipt remain unchanged.

It does not inspect the current checkout or authenticate the reviewer, and `ci-check` does not consume this policy result.
An exit of 0 means this saved-record policy result is `PASS`, not that a new scan completed.

Only a current, unexpired decision matching the complete report hash and finding identity removes that finding from the derived blocking/review calculation.
The output retains every finding identity, the original gate and reasons, each decision, and whether it was applied.
Expired or mismatched decisions remain visible and prevent `PASS`, even when their finding has disappeared.

Exceptions never waive failed execution, uncertain process termination, missing/partial/unsupported analysis, cancellation, budget stops or plan exclusions.
For example, excepting a secret finding in an incomplete scan changes the derived result from `FAIL` to `INCOMPLETE`; it cannot make unperformed AI analysis pass.
Malformed or internally inconsistent gating fields are rejected.

Input paths, combined size limits, private output and full output-secret checks follow `dispositions`.
The target is not rescanned and no AI call is made; the configured Gitleaks output-secret check still runs.
Store the original report together with the human decision file and the derived result so the decision remains auditable.

A changed report requires a fresh human review instead of automatic carryover.

## Evaluation: vulnerable/fixed pairs for v0.1.0

The `eval/pairs/` trees let you show on a real host that the OSV engine reports a
dependency advisory before its official fix and not after, and that `reproduce
--base --head` moves from reproduced to not-reproduced across the same upgrade.
Each pair is one public advisory and its official fix, pinned to the exact
released versions; the reproduce tests only set a harmless in-process marker
(JavaScript) or write a marker value (Python) and never run a shell command.
`eval/README.md` holds the exact build, scan and reproduce commands.

| Pair | Advisory | Base → fix | Method |
|---|---|---|---|
| JS/TS `lodash` | GHSA-35jh-r3h4-6jhm / CVE-2021-23337 | 4.17.20 → 4.17.21 | OSV scan + `reproduce` (Node oracle) |
| Python `PyYAML` | CVE-2020-14343 / PYSEC-2021-142 | 5.3.1 → 5.4 | OSV scan + `reproduce` (Node oracle driving `/usr/bin/python3`) |
| Go `golang.org/x/text` | GO-2021-0113 / CVE-2021-38561 | v0.3.6 → v0.3.7 | OSV scan only |

Go is scanner-only: the offline reproduce job mounts `/tmp` and `/work` as
`noexec` tmpfs and all source read-only, so a freshly compiled Go binary cannot
be executed and `go run`/`go test` fail; the default job image also carries no Go
toolchain, and Go has no interpreted mode to drive the panic in-process the way
Node and `python3` drive the other two. The go.mod version alone is enough for the
OSV engine to flag the advisory at base and clear it at head.

### Results (2026-10-31)

On 2026-11-04, the lodash and PyYAML pairs were rerun with stricter tests that accept only the fix’s own rejection as “not reproduced”, and gave the same result.

Host: Windows 11 with Docker Desktop 29.9.2 (Linux engine); job image node 24.22.1
with python3 3.11.2; OSV-Scanner 2.7.0 with npm, PyPI and Go offline databases
acquired 2026-10-31. Both scans of every pair completed with OSV coverage
`analyzed`.

| Pair | Target at base | Target at head | `reproduce --base --head` |
|---|---|---|---|
| JS/TS `lodash` | reported (4.17.20) | not reported (4.17.21) | base reproduced, head not reproduced; `same_test_no_longer_reproduces`, exit 1 |
| Python `PyYAML` | reported (5.3.1) | not reported | base reproduced, head not reproduced; `same_test_no_longer_reproduces`, exit 1 |
| Go `golang.org/x/text` | reported (v0.3.6) | not reported (v0.3.7) | not run (scanner-only) |

The target advisory is reported at base and not at head for all three pairs.
Other advisories for the same package remain at head because their fixes are in
later releases: lodash GHSA-f23m-r3pf-42rh, GHSA-r5fr-rjxr-66jc and
GHSA-xxjr-mmjv-4gpg (GHSA-29mw-wpgm-hmr9, also reported at base, is gone at head);
golang.org/x/text GO-2022-1059, GO-2026-5970 and GO-2026-6629. PyYAML had no other
advisory at either commit.

For JS/TS and Python, `reproduce` printed "The same test no longer reproduces at
head, with the test unchanged." and exited 1, because its exit code follows the
original base report, which still has a High finding, as documented in
[Get started](getting-started.md#reproduce-one-finding-and-check-an-unchanged-regression-test). Go has scanner evidence only because the
reproduce job cannot run a compiled Go binary.

## Evaluation: 90 dependency advisories (2026-11-04)

This evaluation measures whether the OSV engine matches published dependency advisories from a lockfile, and how often a published advisory can get a harmless offline test. It does not measure discovery of unknown vulnerabilities, Gitleaks, Trivy, or the AI scan. GitHub Advisory Database also feeds the OSV database, so high detection is expected and is not a general detection rate.

### Selection, fixed before any scan

From GitHub Advisory Database commit `d29f93b34c304df05cd3a23ea898c61ebb69d2ea`, select reviewed advisories published before 2026-10-01, not withdrawn, with exactly one ecosystem range having one introduced and one fixed event. The candidate counts were npm 8141, PyPI 10447 and Go 7026. Rank by SHA-256 of seed, ecosystem, package and advisory id, using seed `d29f93b34c304df05cd3a23ea898c61ebb69d2ea|scanmux-l06-v1`, with one case per package. Use the first 30 eligible cases per ecosystem. A case is ineligible when the fixed version is not a stable registry release or no affected stable version exists; scanner results played no part. The base is the highest stable version below the fix, and the head is the fix.

### Detection

A lockfile containing only the target package was scanned with `job-scan` at both versions, using OSV-Scanner 2.7.0 and an offline database acquired 2026-10-31. All 180 scans completed with OSV coverage `analyzed`.

| Ecosystem | Pairs | Skipped as ineligible | Reported at base | Not reported at base | Still reported at head |
|---|---|---|---|---|---|
| npm | 30 | 3 | 29 | 1 | 0 |
| PyPI | 30 | 1 | 30 | 0 | 1 |
| Go | 30 | 22 | 30 | 0 | 0 |

The one not reported is `lodash-amd` 4.18.0 for GHSA-f23m-r3pf-42rh: the advisory snapshot says fixed in 4.18.1, while the older offline database says 4.18.0, so the scanner followed its database. The advisory snapshot is dated 2026-11-04 and the database 2026-10-31; that gap is a flaw in this run.

The one still reported is `python-jose` 3.4.0: GHSA-6c5p-j8vq-pqhj says fixed in 3.4.0, while an aliased advisory, GHSA-3qf3-8w2g-rqmx, lists it as affected through 3.5.0.

Most Go skips are cases where the fix is not a stable release, so those cases are not represented. Other advisories were reported too, 1640 at base and 1517 at head. They were not judged, so this gives no false positive rate.

### Reproduction

The first 20 eligible cases each for npm and PyPI were attempted in rank order, with no replacement. Go was not attempted because the job cannot run compiled Go binaries. Tests set a harmless in-process marker or compare a value, and run only in the offline job. A separate review read each test and each refusal against the code; this classification is a review judgement.

| Result | npm | PyPI |
|---|---|---|
| Shows the defect's effect; base reproduced, head not | 9 | 7 |
| Shows only a sign of the fix | 3 | 0 |
| Tested another change, not counted | 1 | 0 |
| The test failed in the job | 0 | 1 |
| No test, reason confirmed against the code | 6 | 10 |
| No test, a route may have been missed | 1 | 2 |

Common reasons for no test include behaviour needing a browser or a running server, a wheel unavailable for the job's Python 3.11, a fix outside the package or in a large bundle over the 2 MB limit used here, and a fix depending on a dependency that a stand-in would replace.

Forty attempts are too few to give a per-language rate. Several of the 16 show only part of the chain: the first step of the defect, or small inputs rather than exhaustion. Some use stand-ins for code other than the fixed code. A reproduction proves nothing about the rest of the package.

The corpus, tests and raw results are not in this repository.

## Related docs

- [Get started](getting-started.md)
- [Runtime controls](runtime-controls.md)
- [Result assumptions](assumptions.md)
- [GitHub Actions](github-actions.md)
- [ScanMux](../README.md)
