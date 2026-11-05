[English](README.md) | [日本語](README.ja.md)

# ScanMux

ScanMux is a local security scanner controller for developers who need to inspect a fixed Git commit on their own PC.

Separate scanners leave you to work out which checks ran, which failed and which files were never examined.
ScanMux records those states alongside findings and saves private reports outside the target repository.

## Proof-of-concept status

ScanMux is a proof of concept (PoC), not a production security service.
Default commands run local static checks on a fixed commit.
The Web interface contacts GitHub to acquire public repositories.

A separate `ai-plan` / `ai-scan` workflow connects Windows to an isolated Linux Codex Security worker.
It requires exact plan acceptance, prepared pinned assets, dedicated credentials and verified runtime boundaries.
Development evidence uses synthetic responses, not real Blue inference.

## Scope of v0.2.3

For JS/TS (`npm`), Python (`PyPI`) and Go (`Go`), support means reading these inputs,
running offline OSV dependency checks, Gitleaks secret checks and explicitly accepted AI checks.
Ordinary `scan` does not run AI. Support does not guarantee full coverage or `PASS`.

| Language | Dependency inputs |
|---|---|
| JS/TS | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Python | `requirements.txt`, `poetry.lock`, `uv.lock` |
| Go | `go.mod`, `go.sum` |
| Rust (`crates.io`) | `Cargo.lock`; dependency checks only, with no Cargo build or call analysis |

For urgent vulnerabilities, `runtime-advisories` compares declared PHP, Node.js, Next.js, NGINX, GitLab and Apache Tomcat versions.
It uses a fixed catalog of official vendor advisories confirmed on 2026-10-22.
It reports matches, recorded non-matches and unknown assessments, with fixed versions for matches.
Coverage stays partial or unsupported. Scans never refresh the catalog.

Separately, `intel-refresh` retrieves the official CISA Known Exploited Vulnerabilities (KEV) catalog and JVN update RSS.
`intel-match` compares saved report/import CVE IDs offline.
It writes separate reports of KEV exploitation listings and JVN recent-update mentions.
Fetch times, source dates, freshness and failures are shown.
Without `--max-age-hours`, freshness is unjudged.
A failed refresh stays visible even when an older usable copy is used.
With an age limit, `--require-fresh` returns exit 3 for an unusable matching feed or one whose state is not `fresh`.
JVN iPedia is status-only.

These checks do not establish exploitability, deployed patch state or safety, and do not apply fixes.
Feed matches do not change the scan gate, report or exit code.
See [Public feed match](docs/threat-intel.md) for feed limits.

The following are outside this scope:

| Item | Boundary |
|---|---|
| Real Linux host measurement and stopping | This resource workflow is verified on Windows with Docker Desktop's Linux engine and, in CI, on GitHub-hosted `ubuntu-24.04` (native supervisor suite and large job scans). Other Linux hosts are not verified. |
| macOS support | The test suite runs on macOS in CI. Job commands and the AI runner remain unsupported. Targets under a symlinked ancestor, such as macOS `/tmp` or `/var`, are refused with `linked_path`. |
| Physical disk quota | ScanMux estimates registered job data and stops on excess. Sampling can miss growth. ScanMux does not change OS settings. |
| Publisher checks without upstream evidence | A v2 policy can verify supplied OSV-Scanner Sigstore/SLSA evidence offline through `gh`. ZIP evidence (`sigstore-slsa-archive`) requires both a verified ZIP attestation and an exact member-to-engine SHA-256 match; a ZIP attestation alone never proves the executable. The [Trivy Windows x64 ZIP](docs/trivy.md) can be verified this way. This proves the configured publisher identity and byte relationship, not correctness, freshness or safety. Gitleaks 8.30.1 publishes no signature evidence and is always refused at `publisher`. Git for Windows, container components, images and the asset manifest cannot be publisher-verified offline. `gh` is pinned, not self-verified. Local SHA-256/version pins alone do not verify a publisher. |
| Guaranteed effective Daybreak Blue | Blue is an optional request. Requested and effective programs are recorded separately. Effective `standard` is accepted as an AI check; this alone does not establish completion. |
| Native memory or disk growth in other SDKs or later phases | The documented SDK cause observation covers only native SQLite FULL during the pinned SDK's initial Python scan registration. The same full disk produced other SQLite results in other paths, which ScanMux keeps as stage errors; see [AI scan](docs/ai-scan.md). |
| Retrying source cleanup | Copies that could not be removed are reported as `source_cleanup_failed`, with the path on stderr. They are not recorded or retried by later runs. |
| Workspace identity race | A process running as the same user can swap a directory between `mkdtemp` and the first identity read. |
| Cleanup ancestor race | A process running as the same user can swap an ancestor for a junction during removal. |
| Parent ACL changes | A process running as the same user, as owner, can widen the parent ACL after the first full check in a process. |
| First workspace creation | The first workspace in a process is created before the parent ACL check, leaving a race window for a process running as the same user. Nothing is written into that workspace if the check fails. |
| Quality evaluation size | The evaluation covers three smoke pairs plus the 90-advisory dependency evaluation in [docs/results.md](docs/results.md), which measures matching and is not a general detection rate. The Go pair has scanner-only evidence because the reproduction job cannot run a compiled binary. |
| Release artifact verification | Release artifacts include a CycloneDX SBOM and GitHub build provenance attestations for the package and SBOM. Verify each with `gh attestation verify PATH/TO/ARTIFACT --repo OWNER/REPO`. |

## What it does

- Inventory a clean repository and pin its commit and file hashes.
- Run static tools in sequence on a private snapshot.
- Keep findings, failures, exclusions and incomplete coverage visible.
- Save private HTML, JSON and SARIF reports outside the repository.

The network column describes command activity, not an OS-level zero-egress guarantee.

| Command | What it does | Contacts the network? |
|---|---|---|
| `doctor` | Check executable hashes, versions and missing capabilities. | No |
| `plan` | Record coverage, exclusions, transmission and cost for one commit. | No |
| `scan` | Run the offline checks and save reports. | No |
| `plan-list`, `scan-list` | Plan or scan an explicit list of repositories sequentially. | For public GitHub acquisition |
| `deps` | Compare dependency advisories, upgradeability and lockfile changes offline. Since 0.2.0: exit 0 (no added/present advisory), 10 (added/present), 2 (check failed/incomplete). | No |
| `ai-plan` | Disclose one repository's AI source scope and finite limits. | No |
| `ai-scan` | Run isolated AI checks after exact plan-hash acceptance. | OpenAI |
| `runner-check` | Check ChatGPT authentication type, advertised Daybreak programs, model-free Linux connection and cleanup. No inference or AI enablement. | OpenAI account/model metadata |
| `serve` | Review a public GitHub commit, start a scan and download HTML/JSON through a personal loopback page. | GitHub acquisition |
| `ci-check` | Check local completion receipts and associated AI reports. | No |
| `ci-github` | Verify a delivered GitHub Actions self-scan. | GitHub through pinned `gh` |
| `history`, `recover`, `resume` | Read selected saved reports, recover engine records or rerun a stopped offline scan. | No |
| `dispositions`, `policy-check` | Record human judgments or apply explicit saved-report exceptions. | No |
| `engine-record`, `engine-history` | Verify and record engine updates or list pinned ledger entries. | No |
| `job-scan`, `host-job-scan` | Run one bounded offline Linux job, optionally with Windows coordinator limits. | No |
| `job-export`, `job-recover` | Export saved job results or recover their verified checkpoints. | No |
| `intel-refresh` | Retrieve the fixed public advisory feeds. | CISA/JVN |
| `intel-match` | Match CVE IDs against saved feeds without changing a scan decision. | No |
| `release-record`, `release-log-check`, `release-verify` | Record releases, check the release chain or verify a measurement. | No |

## Requirements

- Node.js 24, version 24.16.0 or newer, before 25; Git with ordinary SHA-1 repositories.
- Separately installed Gitleaks 8.30.1 and OSV-Scanner 2.7.0 from their official releases.
- OSV databases downloaded before scanning.
- A clean, committed local Git root for CLI scans.
- On Windows, the pinned process owner when a configured tool will start.

See [Get started](docs/getting-started.md) for database layout, supported inputs, configuration and platform limits.
AI and bounded jobs have additional requirements in their guides.

## Get started

Follow [Run your first offline scan](docs/getting-started.md).
Its numbered instructions prepare the tools and recorded database, create trusted configuration, inspect a plan and run the scan.

## Results at a glance

A gate is the overall decision. Higher rows take precedence.
Findings remain in reports even when an error takes priority.

| Gate | Exit code | Meaning |
|---|---:|---|
| `ERROR` | 4 | Execution, report parsing or integrity failure |
| `FAIL` | 1 | Secret finding or source-supported High/Critical finding |
| `INCOMPLETE` | 3 | Missing, excluded, unsupported, cancelled or time-limited required coverage |
| `REVIEW` | 2 | High/Critical candidate or unknown severity with otherwise complete coverage |
| `PASS` | 0 | All required checks completed without a blocking or review finding |

An ordinary PoC scan cannot produce `PASS`: its required AI check is blocked.
The required `runtime-advisories` check also stays partial or unsupported, including in `ai-scan`.
`doctor` returns 3 while required conditions are missing.
A successful `plan` returns 0 for planning only, not a security verdict.
See [Read, save and check results](docs/results.md) for the full policy and saved-record workflows.

## Security

- Treat target instruction files, `.gitleaks.toml` and `osv-scanner.toml` as untrusted input.
- Target content cannot authorize permissions, credentials, destinations or result-policy changes.
- Keep controller configuration, pinned tools, databases and reports outside the target.
- Scan tracked snapshots, not Git history. ScanMux does not change target files.
- Scans never run target scripts, install dependencies or invoke Git checkout filters. Only `reproduce` runs target code: the `test.mjs` you name, inside Linux isolation.
- Scanners receive a minimal environment and explicit controller settings. Ambient API keys are not reused.
- Default offline commands never upload source. Explicit `ai-scan` sends only the accepted scope through its fixed host relay.
- Gitleaks allow-comments are disabled. Its built-in path exclusions remain partial coverage.
- The AI relay checks every accepted text file for secrets before worker startup.
- The local static runner trusts the configured binaries, Git and OS; it is not an OS security sandbox.
- Hash checks do not cover same-user concurrent mutation or compromised native tools. Native CPU/memory isolation and OS-level zero-egress proof are unsupported.
- Time, output and snapshot limits bound normal runs, not malicious native executables. Do not scan hostile material on a sensitive host.
- Keep reports private. Their paths and package identifiers can disclose project details.

See [Result assumptions](docs/assumptions.md) for the trust base and measured limits.

## Related docs

| Guide | Read it when |
|---|---|
| [Get started](docs/getting-started.md) | Prepare tools and databases, run offline scans, choose commits or check dependencies. |
| [Urgent advisories](docs/urgent-advisories.md) | Check declared runtime versions against the fixed catalog. |
| [Web interface](docs/web-interface.md) | Use the local page or an owner-private Site. |
| [AI scan](docs/ai-scan.md) | Check Linux connectivity and accept an isolated AI plan. |
| [Results](docs/results.md) | Read reports, check CI completion, inspect history, recover or judge findings. |
| [Runtime controls](docs/runtime-controls.md) | Deny components, verify publishers or limit Linux/Windows jobs. |
| [Result assumptions](docs/assumptions.md) | Review what a result relies on and leaves unverified. |
| [Trivy](docs/trivy.md) | Configure optional offline infrastructure-as-code checks. |
| [GitHub Actions](docs/github-actions.md) | Verify self-scan delivery from the repository workflows. |
| [Public feed match](docs/threat-intel.md) | Read KEV/JVN matching and freshness rules. |
| [Release transparency](docs/transparency.md) | Check a release measurement against an external pin. |
| [Windows process termination](docs/windows-process-termination.md) | Build and pin the process owner or inspect stop guarantees. |

## Upstream and license

- [Codex Security](https://github.com/openai/codex-security): Apache-2.0; OpenAI service and access terms apply separately.
- The draft input schema from `@openai/codex-security` 0.5.1 is stored in `test/fixtures/codex-security-draft-input-schema.json` (Apache-2.0).
- [OSV-Scanner](https://github.com/google/osv-scanner): Apache-2.0; advisory/database terms belong to their sources.
- [Gitleaks](https://github.com/gitleaks/gitleaks): MIT; separately installed CLI and built-in rules. `src/adapters.ts` records its 8.30.1 global path allowlist as coverage exclusions.
- [Trivy](https://github.com/aquasecurity/trivy) 0.76.1: Apache-2.0; `test/fixtures/trivy-offline.json` contains its output, including rule text and reference URLs.
- `src/advisory-catalog.ts` records identifiers and affected and fixed versions from public advisories by PHP, Node.js, Next.js, NGINX, GitLab and Apache Tomcat. Each record links its source; no advisory text is copied.
- [lodash](https://github.com/lodash/lodash) 4.17.20 and 4.17.21 (MIT) and [PyYAML](https://github.com/yaml/pyyaml) 5.3.1 and 5.4 (MIT): minimal files vendored under `eval/pairs/` with their licenses for the offline evaluation pairs. [golang.org/x/text](https://cs.opensource.google/go/x/text) v0.3.6 and v0.3.7 (BSD-3-Clause) are named by version in `eval/pairs/go/*/go.mod` only.

ScanMux code is [MIT](LICENSE). External engines, databases and credentials are not bundled.
ScanMux is not published to npm. Release packages are attached to GitHub Releases.
ScanMux is an independent project and is not an official OpenAI, Google or Gitleaks product.
