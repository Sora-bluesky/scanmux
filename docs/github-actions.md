[English](github-actions.md)

# Verify GitHub Actions self-scans

Use this guide when checking a completed self-scan: it explains the workflows, delivered files and local acceptance checks.

ScanMux runs its own tests and an offline self-scan on GitHub Actions. A maintainer then checks a finished self-scan run from a local machine with `scanmux ci-github`. This page describes the two workflows, what they deliver, and what the local check accepts.

A normal self-scan run is red. `codex-security` is a required engine and stays `not_started` in an offline run, so the claimed gate is `INCOMPLETE` (exit 3). A successful verification means that the claim, the delivered files, and a local re-evaluation agree. It never means PASS unless the claim is PASS.

## Choose a workflow

| File | Trigger | Runner | Permissions | Trust |
| --- | --- | --- | --- | --- |
| `.github/workflows/checks.yml` | `pull_request` (opened, synchronize, reopened, ready_for_review) and `workflow_dispatch` | `windows-2025`, 25 minutes | `contents: read` | Runs pull request code. Produces nothing trusted. |
| `.github/workflows/offline-selfscan.yml` | `workflow_run` after `checks` completes, and `workflow_dispatch` | `windows-2025`, 20 minutes | `contents: read`, `actions: read` | The workflow file and the controller come from the default branch. |

Both workflows use only `actions/checkout`, `actions/setup-node`, and `actions/upload-artifact`, each pinned by a full commit SHA. They use no secrets and no `pull_request_target`. Workflow expressions reach scripts only through environment variables, never inside a `run:` body.

`checks` installs dependencies with `npm ci --ignore-scripts`, runs the typecheck, acquires the pinned tools and the OSV database, and runs `npm test` with `SCANMUX_REAL_CONFIG`. Tests that need a native job profile are reported as skipped, not as passed.

`checks` checks out the full history (`fetch-depth: 0`) and runs `scanmux release-log-check` after the config is derived.
For a pull request the base is the pull request's base SHA, passed through the `BASE_SHA` environment variable, and the head is the checked-out commit.
For `workflow_dispatch` the base is `none`.

`scripts/ci-release-log.ts` runs the check in a fresh repository under `RUNNER_TEMP` that holds only the base and head commits, with no hooks and none of the checkout's config, because `actions/checkout` leaves `.git/config.worktree` behind and `release-log-check` refuses that layout.

The step fails when the base release log is not a byte prefix of the head log, the chain is broken, or an entry does not reproduce from its source commit.
It runs pull request code like every other step, so it is a consistency check and not a trust anchor.
Owners verify releases against their own pin, as described in [Release transparency](transparency.md).

`offline-selfscan` clones the target commit from the controller checkout into a separate directory and scans it.
For `workflow_run`, the target is the head SHA of the `checks` run that triggered it.
For `workflow_dispatch`, the target is the dispatched commit.
The run name is `offline-selfscan scenario=<scenario>`, with `none` outside `workflow_dispatch`.

Runs for the same target commit share one concurrency group with `cancel-in-progress: false`, so a running producer is never cancelled by a newer one.
GitHub keeps only the newest waiting run in the group and cancels older waiting runs, which `ci-github` reports as `run_cancelled`.
Network access happens only before the scan, for checkout, npm, and tool and database acquisition.

Target output never goes to the job log.

## Check download pins

`.github/scanmux/pins.json` (`scanmux.ci-pins/v1`) fixes everything the self-scan downloads.

| Field | Content |
| --- | --- |
| `tools.gitleaks` | Gitleaks 8.30.1 Windows x64 release URL, the archive sha256 from the release checksum file, and the `gitleaks.exe` sha256. |
| `tools.osv` | OSV-Scanner 2.7.0 Windows amd64 release URL and sha256. The release asset is the executable itself, so both values are equal. |
| `database` | OSV ecosystems (`npm`, and `PyPI` for the dependency test fixtures), byte budget, and time budget for `scripts/fetch-osv-db.mjs`. |
| `runtimePolicy` | The runtime policy v1 written into the derived config. |

A change to the pins file needs the same change to the approved pins sha256 in `src/github-ci.ts`, and a test checks that they match. `scripts/ci-produce.mjs` derives the scan config from these pins. The runner's own Git is not pinned. The derived config and the manifest record its path, sha256, and version.

## Inspect delivered files

Each self-scan attempt uploads one artifact, `scanmux-selfscan-<run id>-a<attempt>`, kept for 7 days. It holds these files:

| File | Content |
| --- | --- |
| `manifest.json` | `scanmux.github-delivery/v1`. Run, source run, target and controller SHAs, pins sha256, CI run UUID, scenario, Git identity, outcome, and the size and sha256 of every other file. |
| `plan.json` | The plan that fixed the expectation. |
| `expected.json` | `scanmux.ci-expectation/v1`, written before the scan. |
| `report.json`, `ci-receipt.json` | The scan report and its CI receipt. |
| `ci-result.json` | The `ci-check` result. Its gate is the claim. |
| `osv-database-receipt.json` | The database acquisition receipt. |
| `config.json` | The derived config. |

If a stage fails, the outcome is `failed` with the stage and a closed failure code, and the artifact holds only the files that exist. The producer never writes a stand-in report or receipt.

After the upload succeeds, the `Anchor delivery` step prints one line to the job log:

```text
scanmux-anchor v1 manifest=<sha256> artifact=<id> run=<id> attempt=<n>
```

The last step, `Gate`, exits with the claimed exit code, or 4 when the producer failed.

The self-scan does not upload code scanning results or attest its delivery artifact. The manifest records these as `not_uploaded` and `not_attested`, and neither counts as success. On a private repository, these features would require GitHub Code Security and GitHub Enterprise Cloud, respectively. The separate `Release` workflow attests release packages.

## Verify a run

`ci-github` reads the run through `gh`, the GitHub CLI pinned as the runtime policy v2 verifier in the config. The config must be schema 2 with runtime policy v2, and `gh` is admitted with Gitleaks before any request.

```powershell
$env:GH_TOKEN = gh auth token
node bin/scanmux.mjs ci-github --repo OWNER/NAME --run RUN_ID --attempt 1 --config C:\absolute\config.json
```

The token is passed only to the pinned `gh` process. The command writes `github-verification.json` (`scanmux.github-verification/v1`) and a copy of the delivered files to a new private directory.

The checks run in this order. The first failure stops the run, and every later check is reported as unknown.

1. `run`: the repository ID, the attempt, `.github/workflows/offline-selfscan.yml`, the event, and a completed, not cancelled run.
2. `workflow_integrity`: the run head is on the default branch, and the workflow file at that commit has the approved sha256 in `src/github-ci.ts`.
3. `producer_jobs`: the `selfscan` job and every named step exist. No step is skipped or cancelled unless an earlier stage failed.
4. `artifact`: exactly one unexpired artifact with the expected name, downloaded and unpacked with a strict ZIP reader, holding no name outside the delivery files listed above.
5. `anchor`: exactly one anchor line, naming the downloaded manifest, the artifact ID, the run, and the attempt.
6. `manifest`: a closed parse, run fields equal to the API, the pins sha256 approved in `src/github-ci.ts`, and the exact file set with matching sizes and sha256 values.
7. `source_run`: for `workflow_run`, the `checks` run named by the anchored manifest has the same attempt, event, and head SHA as the target.
8. `content_binding`: the expectation equals the one derived from `plan.json`, the receipt names the report hash, and the report matches the receipt.
9. `agreement`: a local `evaluateCi` over the expectation and the receipt equals `ci-result.json`, and the `Gate` step conclusion matches the claim.

The result reports `scenario` from the manifest named by the log anchor, or from the run name when the run stops before a manifest exists.
Both are read only when the run identity and the workflow content check out, so a cancelled `cancel-wait` run still shows its scenario.
If the two disagree, `scenario` is null.
A scenario other than `none` from either source adds the note `failure_scenario`.

`--from-dir C:\absolute\copy` checks an already downloaded copy instead of downloading it. Every API check still runs, and the result always carries `local_copy_supplied`. A local copy never gives PASS: a PASS claim stays in `claimed`, and the gate is INCOMPLETE (exit 3).

## Exit codes

| Result | Exit |
| --- | --- |
| All checks agree | The claimed gate: 0 PASS, 1 FAIL, 2 REVIEW, 3 INCOMPLETE, 4 ERROR. |
| A run, job, step, or artifact is missing, cancelled, skipped, or expired | 3 |
| Tampering, a binding mismatch, a failed or malformed download, a disagreement, a producer failure, or a scenario other than `none` | 4 |

`sourceChecks` carries the conclusion of the `checks` job in the source run as `passed`, `failed`, `skipped`, `cancelled`, `unknown`, or `not_applicable`, always with `trusted: false`.
A pull request can change `checks.yml`, so this is what the source run reports, not a verified result, and it never affects the gate.
It is `unknown` unless the source run matched the anchored manifest.

A skipped test job is never reported as passed.
`checks` tests the pull request merge commit, while the self-scan scans the pull request head.

## Exercise failure cases

`workflow_dispatch` on `offline-selfscan` takes a `scenario` input. Use the scenarios only on the default branch.

| Scenario | What the run does | `ci-github` result |
| --- | --- | --- |
| `tool-fetch-fail` | Downloads the first tool with a 1-byte budget. | `producer_failed`, exit 4 |
| `db-fetch-fail` | Fetches the OSV database with a 1-byte budget. | `producer_failed`, exit 4 |
| `hash-mismatch` | Changes 1 byte of the downloaded executable before the hash check. | `producer_failed`, exit 4 |
| `skip-scan` | Skips the `Scan` step. | `producer_step_skipped`, exit 3 |
| `skip-upload` | Skips the upload and the anchor. | `delivery_step_incomplete`, exit 3 |
| `cancel-wait` | Waits up to 10 minutes in `Wait for cancellation`. Cancel the run with `gh run cancel`. | `run_cancelled`, exit 3 |

To show tampering, verify a copy with `--from-dir` after you change it. A changed byte in `report.json` gives `delivery_file_tampered`. A receipt, result, and manifest edited to agree with each other no longer match the log anchor and give `anchor_mismatch`. Both exit 4.

## Limitations

- The pull request that adds or changes `offline-selfscan.yml` cannot run it through `workflow_run`, because `workflow_run` uses the default-branch file. The first real verification happens after merge.
- The self-scan is not a required status check, because it stays red while `codex-security` is not run.
- The anchor and the API state prove which run produced the files. They are not a signature. Anyone with write access to the repository workflows can change what a later run does, which the approved workflow and pins sha256 values detect for those two files only.
- Windows runners bill at twice the Linux rate.


## Check release provenance before tagging

Maintainers can run the `Release` workflow once with **Run workflow**, selecting the commit's branch and leaving `tag` empty (the default dry run). It builds the dispatched commit without a tag or release, attests the package and CycloneDX SBOM, and uploads both files plus `SHA256SUMS` as `scanmux-provenance-<run id>-a<attempt>`, kept for 3 days. Download and extract that artifact, then verify each attested file:

```sh
gh attestation verify dist/scanmux-<version>.tgz --repo <owner>/<repo>
gh attestation verify dist/scanmux-<version>.cdx.json --repo <owner>/<repo>
```

GitHub artifact attestations require a public repository, or GitHub Enterprise Cloud for a private repository. The dry run never reads, creates or edits a release. Pushing a version tag, or manually supplying an existing tag, still creates the draft release after the tag and package versions match.

## Related docs

- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Result assumptions](assumptions.md)
- [ScanMux](../README.md)
