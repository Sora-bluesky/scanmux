[English](runtime-controls.md) | [日本語](runtime-controls.ja.md)

# Control runtime permissions and resource limits

Use this guide to deny runtime components, verify publishers and configure bounded offline Linux and Windows jobs.

## Stop or deny runtime components

Config schema `2` is a schema 1 configuration plus a required `runtimePolicy`. A `scanmux.job-profile/v2` job profile carries the same object. The ID and hash below are synthetic.

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

`state: "stopped"` refuses every command that checks the policy, saved-record viewers included.
A `component` rule refuses that whole component.
A `digest` rule refuses one identity: the file SHA256 for native tools, the asset manifest SHA256 for `codex-security-sdk` and the image ID hex for `linux-image`.

The components are `git`, `gitleaks`, `osv`, `docker`, `codex-cli`, `codex-security-sdk`, `linux-image`, `windows-owner` and `node`.

Each command decides before its first process start, credential read or connection.
`host-job-scan` decides again in its delegated worker.

| Command | Components checked |
|---|---|
| `doctor`, `scan`, `deps`, `resume`, `scan-list` | Configured Git, Gitleaks and OSV |
| `plan`, `plan-list` | Git and Gitleaks |
| `ai-plan`, `ai-scan` | The tools checked by `plan` or `scan`, respectively, plus AI components |
| `runner-check` | The runner's Codex CLIs, Docker, image and Gitleaks |
| `history`, `ci-check`, `recover`, `dispositions`, `policy-check`, `job-export`, `job-recover` | Only the Gitleaks output check |
| `job-scan`, `host-job-scan` | Their profile's components |

A refusal exits `2` for `deps` (failure), or `4` for other commands, with the same fixed code.
Completed `deps` checks exit `10` for added advisories with a base, or present advisories without one; otherwise they exit `0`, never a security `PASS`.
Hyphens in component names become underscores in the code.

| Code | Meaning |
|---|---|
| `runtime_policy_stopped` | Policy stopped |
| `runtime_policy_denied_<component>_component` | Whole component denied |
| `runtime_policy_denied_<component>_digest` | One identity denied |
| `runtime_policy_unidentified_<component>` | Component identity unavailable |

For commands other than `deps`, the error names the policy that refused:

```json
{"schema":"scanmux.error/v1","gate":"ERROR","exitCode":4,"error":"runtime_policy_stopped","policy":{"id":"00000000-0000-4000-8000-000000000001","revision":1,"state":"stopped","sha256":"<canonical policy SHA256>"}}
```

`deps` reports the same refusal code as `{"schema":"scanmux.error/v1","exitCode":2,"error":"runtime_policy_stopped"}`.

A v1 policy does not verify publishers or record updates.
A policy in state `active` with no matching rule is not a safety claim.
A running process is not stopped and the configuration is not reloaded.
The Web interface does not support schema 2 and refuses it with `runtime_policy_entry_unsupported`.

Three runtimes start unhashed: Docker on the AI path, `/usr/bin/git` in the AI container, and `/usr/local/bin/node` in the AI, `job-scan` and `host-job-scan` containers.
A digest rule for one of these components refuses the command.

The code is `runtime_policy_denied_<component>_digest` when that digest matches the hashed host `git` or `node`, and `runtime_policy_unidentified_<component>` when it does not.
A component rule refuses the command as usual.
Host job container cleanup is not checked.

## Verify publishers and record engine updates

A `scanmux.runtime-policy/v2` policy adds `provenance`: a pinned `gh`, a local ledger pin and per-component requirements (synthetic values below).

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

| Requirement | Check before start |
|---|---|
| `recorded` | Engine SHA256 appears in the pinned ledger |
| `publisher` | The same ledger check plus offline publisher verification |

Private re-hashed copies of the engine, bundle and trusted root go to the pinned, version-checked `gh` `attestation verify` with `--custom-trusted-root` and no token.

It passes only on exit 0 with JSON matching the engine SHA256, predicate type and every expected certificate value, GitHub-hosted runner included.

Record an update with a request (`evidence` may also be `{"kind":"none","reason":"publisher_evidence_unpublished"}`):

```json
{"schema":"scanmux.engine-record/v1","component":"osv","platform":"windows-x64","version":"1.0.0","change":"Update OSV","artifact":"C:/scanmux/tools/osv.exe","evidence":{"kind":"sigstore-slsa","bundle":"C:/scanmux/osv.sigstore.json","trustedRoot":"C:/scanmux/trusted-root.jsonl","sourceRef":"refs/tags/v1.0.0","sourceDigest":"<source commit SHA>"}}
```

`scanmux engine-record /absolute/request.json --config /absolute/config.json` hashes the files, verifies Sigstore evidence alike and appends nothing on failure.
The same identity and evidence within the pin returns the existing entry.

It refuses valid lines past the pin (with their `seq`, `component`, `sha256`, `change` and the file's `entries`/`head` in `ledger`), hard links, a ledger replaced mid-run and UNC evidence; `version` is `x.y.z`.
Paste the printed tool pin into `tools` and ledger pin into `provenance.ledger`; raise the policy `revision`.

`engine-history` with the same `--config` lists pinned entries as `current`, `superseded` or `denied`.
Exit 0 means the ledger was read, not PASS.

Refusals exit `2` for `deps` (failure), or `4` for other commands, before any engine starts.

| Code | Cause |
|---|---|
| `provenance_invalid_<component>` | Signature rejected |
| `provenance_unverifiable_<component>` | No usable evidence, an unreadable or changed copy, or failed `gh` |
| `provenance_unrecorded_<component>` | Unhashed or not in the ledger |
| `provenance_ledger_mismatch` | Ledger pin mismatch |

For commands other than `deps`, the first three add `"engine":{"component":"osv","state":"invalid","reason":"signature_rejected","ledgerSeq":1}` after `policy`.
`provenance_ledger_mismatch` adds neither a `policy` nor an `engine` object.

Native commands, `job-scan` and `host-job-scan` apply v2; job Linux engines are host-verified before mounting. `serve` refuses schema 2.

The ledger detects changes only against the pinned config; it is not an authenticated history (`recordedAt` is the local clock).
Gitleaks 8.30.1 publishes no signature evidence, so `publisher` always refuses it; use `recorded`.
Git for Windows (Authenticode), container components, images and the asset manifest cannot be publisher-verified offline.

`gh` is the trust anchor: pinned, subject to stop and v2 `deny` rules, never self-verified.

## Run one bounded offline Linux job

`job-scan` runs planning, snapshot creation, offline scanners, database copying, normalization and output secret checks inside one Linux/x64 container.
Completed engine records are saved outside that container; the next engine waits for the host to write, sync and close both checkpoint files and acknowledge them.
This command supports one ordinary local Git repository on Windows or Linux.

It does not select AI, fetch a URL, resume another job or fall back to a native scan.

Prepare a local Docker engine, a preloaded image pinned by its exact image ID, fixed Linux Gitleaks/OSV binaries, and an optional offline OSV database.
The image must contain the declared Node.js, `/usr/bin/python3` and `/usr/bin/git`.
Verify their versions and SHA-256 values, then create an operator-owned profile outside the target.

Only local `npipe:` endpoints on Windows and `unix:` endpoints on Linux are supported.
The command uses a fresh empty Docker configuration, never stored Docker credentials, and never pulls images.

### Create an offline job profile

The following shows the complete profile shape.
Replace every angle-bracket placeholder with an independently verified value.
The capacities and durations are explicit fixture examples, not defaults, performance recommendations or service guarantees.
Windows paths refer to host files; the Gitleaks/OSV files must be Linux binaries.

On Linux, use absolute Linux host paths and a local endpoint such as `unix:///var/run/docker.sock`.

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

| Field | Meaning |
|---|---|
| `schema` / `scope` | Fixed as `scanmux.job-profile/v1` / `offline-local` |
| `docker.tool` / `docker.endpoint` | Host executable absolute path, SHA-256 and version, plus an explicit local endpoint |
| `image` / `runtime` | Preloaded image ID, Node.js version, and pinned in-image Python/Git paths, SHA-256 values and versions |
| `tools` | Host absolute paths, SHA-256 values and versions for Linux Gitleaks 8.30.1 and optional OSV 2.7.0 |
| `osvDatabase` | Database directory outside the target, or `null` |
| `scan` | Finite scan time, output bytes, file bytes, snapshot bytes and file count |
| `limits` | All of `cpuCount`, `memoryBytes`, `tmpBytes`, `workBytes`, `shmBytes`, `pids`, `wallMs`, `cleanupTimeoutMs`, `retainedBytes` |

A Docker Desktop update can change the Docker executable path, SHA-256 and client version pinned in `docker.tool`.
`job-scan` and `host-job-scan` then stop with `job_asset_mismatch` for a hash mismatch or `job_boundary_unverified` for a client version mismatch.
Verify the updated executable, update `docker.tool.path` if it moved, recompute `docker.tool.sha256`, and set `docker.tool.version` to the client version shown by `docker version`.
For the example Windows path, these commands print the new SHA-256 and client version:

```powershell
(Get-FileHash -LiteralPath 'C:\ScanMux\tools\docker.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
& 'C:\ScanMux\tools\docker.exe' version --format '{{.Client.Version}}'
```

ScanMux never updates these pins itself.

`tools.osv` may be omitted and `osvDatabase` may be `null`; required missing analysis remains incomplete.
Unknown keys, shell commands, environment overrides, arbitrary mounts, credentials and target-owned profiles/tools/configuration are rejected.
The DB root is never mounted as a directory.

Only the four supported `osv-scalibr/<ecosystem>/all.zip` files, `database-receipt.json` and `acquisition-started`, when present, are admitted as individual readonly files.
Missing or invalid inputs do not trigger acquisition.

### Run and export the Linux job

```text
scanmux job-scan C:\source\repository --job-profile C:\ScanMux\job-profile.json --json
scanmux job-scan C:\source\repository --job-profile C:\ScanMux\job-profile.json --base BASE_SHA --head HEAD_SHA --json
scanmux job-export C:\private-run\job.json --config C:\ScanMux\native-reader.json --report-language ja
scanmux job-recover C:\private-run --config C:\ScanMux\native-reader.json --report-language en
```

The reader configuration uses the ordinary Config schema and a verified native Gitleaks executable for output checks.
Viewing and recovery need the recorded host origin directory but never run target Git, scan engines, an SDK or Docker.
`job-export` writes a fresh self-contained JSON/HTML/SARIF bundle in a new private directory and preserves the selected analysis bytes.

Without an actual report or complete checkpoint it returns `job_analysis_unavailable` and leaves the job metadata intact.
It creates no explanatory empty Plan or Report.
`job-recover` ignores any final report and saved closure claims, exports only the verified checkpoint prefix, and always returns ERROR/4.
It never restarts work.

Existing readers reject a job envelope instead of unwrapping or resuming it.

`job.json` records the outer job outcome separately from the unchanged Linux analysis report.
Host origin and actual mapped Linux paths are both shown; the inner Plan is never rewritten into a Windows Plan or an accepted AI Plan.
A checkpoint remains provisional ERROR even when the live owner separately records a verified resource stop as INCOMPLETE, or preserves a prior FAIL.

Known independent failures and unknown termination stay ERROR.
Saved viewers display recorded claims; readable metadata does not authenticate its own durable commit or current process closure.

### Read Linux limit scopes

The limits have these scopes:

- `cpuCount` caps CPU rate, not accumulated CPU seconds. Memory has no swap; `/tmp`, `/work` and `/dev/shm` have the exact finite capacities requested. Byte capacities are positive multiples of 4096. PIDs include the supervisor and all descendants.
- `wallMs` governs the Linux payload and admission of durable-record acknowledgements. Cleanup and host final checks use the separately declared `cleanupTimeoutMs`; no payload work is allowed during cleanup. The command does not promise a hard total duration.
- `retainedBytes` admits cumulative logical bytes for at most eleven result files: one job plan, four checkpoint body/receipt pairs, one final report and one job record. Two reservations (`2 * maxOutputBytes`) protect the final report and metadata before intermediate writes are admitted. The initial plan must also fit. Refusal happens before a new write; unaccepted tails never release the next engine.
- Host coordination, Docker infrastructure, the fixed application bundle and saved-result exports are outside the payload's hard CPU/memory limits. Retained host output has no physical filesystem quota. These exclusions are always recorded; this limited command does not complete the full job-resource requirement.

Native disk-cause observation covers `write`/`pwrite64` failures on regular files in the three bounded stores.
Other write mechanisms, malformed output, generic SIGKILL or missing observations stay errors, not inferred resource exhaustion.
Same-user concurrent host mutation is unsupported.

The container runs with no network, a readonly root/source/assets, UID 1000, all capabilities dropped and no-new-privileges.
Unsupported kernel, tracing, image or isolation conditions stop before target processing, with no permission retry.
macOS and AI/URL/Web/batch/resume jobs are outside this command's supported scope.
`--job-profile` on an older command is rejected.

## Limit the Windows coordinator and its descendants

`host-job-scan` adds Windows Job Object limits to the offline Linux job above. It supports Windows/x64 with Node 24.x and the local Docker Desktop Linux pipe. It requires an explicit host profile; existing `job-scan` behavior and its profile remain unchanged. UNC paths, device paths and network Docker endpoints are rejected.

### Build the Windows job owner

Build the small trusted owner explicitly with the installed Windows PowerShell 5.1/.NET compiler. Choose a new dedicated directory outside the source repository and keep it private:

```powershell
powershell.exe -NoProfile -NonInteractive -File .\scripts\build-windows-job-owner.ps1 -OutputDirectory C:\ScanMux\owner-build
C:\ScanMux\owner-build\scanmux-windows-job-owner.exe --version
Get-FileHash -Algorithm SHA256 C:\ScanMux\owner-build\scanmux-windows-job-owner.exe
Get-FileHash -Algorithm SHA256 C:\Tools\node.exe
C:\Tools\node.exe --version
```

The package contains both owner source files and their build script, without a compiled executable or an automatic build/install hook.
The script reports each source SHA-256 and the assembly SHA-256.
The current build produces owner version `1.1.0`; record the actual executable hashes as lowercase hex.
Launch ScanMux with the same absolute Node executable and exact version as the profile.

Fix the local prerequisite after a compilation failure; ScanMux never alters execution policy or installs a compiler.

### Create a host profile

Create a private JSON profile outside the target:

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

Replace both hash placeholders and the example Node version with verified local values.
`offlineProfile` is the existing `scanmux.job-profile/v1` profile and retains the Linux limits.
`cpuRate` is an integer from 1 through 10000 in Windows CPU-rate units; it is not a core count.
`memoryBytes` limits job committed memory and must be a positive multiple of 4096.

The two positive timer values must sum to at most 2147483647 milliseconds.
These are explicit operator inputs, not automatic defaults.

An existing host profile v1 may keep its explicitly pinned owner `1.0.0` binary or use a separately built and pinned `1.1.0` binary. Neither the profile nor its executable hash is migrated automatically. Rebuild into a new directory and update the profile deliberately.

### Bound retained record allocation with v2

To also bound the allocated data of the fixed host result records, create a separate **host profile v2** with all the fields above, owner `1.1.0`, and these root-level changes:

```json
{
  "schema": "scanmux.host-job-profile/v2",
  "retained": { "allocatedBytes": 134217728 }
}
```

This block shows only the changes.
Keep the other fields and verified hashes, save the complete profile under a new private filename, and pass it with `--host-job-profile`.
V2 supports local NTFS only.
`allocatedBytes` is an explicit positive safe integer aligned to the volume's measured cluster size; ScanMux never rounds it up or falls back to ordinary writes.

It must fit cluster-rounded maximum reservations for the 65536-byte intent, two 4096-byte control records, and seven records bounded by the referenced offline profile's `scan.maxOutputBytes`.
Insufficient reservations or unsupported storage fail before container creation.
The lower profile's `retainedBytes` stays a separate logical-byte budget.

Each fixed runtime-copy file must also fit `scan.maxOutputBytes`, so an undersized output setting can fail runtime preparation even when the reservation fits.

V2 admits each complete proposed record against actual allocated data plus outstanding control-record reservations.
A checkpoint body and receipt are admitted together before either is created.
A budget refusal creates neither file, keeps the committed prefix and records the allocated-data stop separately.

A clean, verified stop is INCOMPLETE; an earlier error, an I/O failure, lost helper or unverified closure remains ERROR.
Unaccepted or partial files stay counted and are never overwritten or retried.
A disk-full error below the configured cap is not evidence that the configured limit was reached.

The v2 `host-job.json` records `retained.snapshot` before writing the outer envelope, including its still-held reservation, without claiming to have measured the envelope first.
`retained.stop` identifies an allocation refusal, while `retained.scope` identifies original recorded observations.
Saved exports keep these facts in JSON, HTML and SARIF.

Recovery without recorded allocation evidence leaves the snapshot unverified and returns ERROR.
A copied or exported result does not carry the allocation cap to its new destination.

This boundary covers the fixed retained record data, including partial tails.
It is not an NTFS directory/user quota or a bound on all job disk: runtime copies, empty infrastructure directories, filesystem metadata, OS/Docker stores and export destinations are excluded.
Unexpected infrastructure entries invalidate a guarded run.

Concurrent mutation by another process with the same Windows identity is unsupported.

### Run and export the Windows job

```powershell
C:\Tools\node.exe .\bin\scanmux.mjs host-job-scan C:\source\repository --host-job-profile C:\ScanMux\host-job-profile.json --json
C:\Tools\node.exe .\bin\scanmux.mjs host-job-scan C:\source\repository --host-job-profile C:\ScanMux\host-job-profile.json --base BASE_SHA --head HEAD_SHA --json
scanmux job-export C:\private-run\host-job.json --config C:\ScanMux\native-reader.json --report-language ja
scanmux job-recover C:\private-run --config C:\ScanMux\native-reader.json --report-language en
```

The primary Windows worker is created suspended inside the configured Job before its first instruction, and its descendants cannot break away.
Closing the owner's last Job handle terminates the owned tree.

Successful closure requires exact process-generation handles to be signaled and their count to match the OS cumulative process count; a missing capture, capacity failure or unverified termination remains an error.
Cleanup uses a separate, equally limited Job after the primary tree has closed, within one shared `cleanupTimeoutMs` interval.

It reconciles only the precommitted container name, image and job label, plus a saved container ID when available, and leaves a mismatched identity untouched.

The outer result is `host-job.json`.
Internal `delegated-job.json` is subordinate evidence, not exportable as an ordinary job.
Complete engine checkpoints remain available after a deadline or cancellation.
Even with an acknowledged final report, unverified worker completion selects the verified checkpoint prefix instead of promoting the raw final file.
Earlier accepted errors remain errors.

A memory cap or generic process failure alone does not prove an out-of-memory cause.

`job-export` reconstructs the recorded result and writes fresh JSON/HTML/SARIF with the outer outcome and provisional-analysis status.
`job-recover` uses only saved checkpoints and always returns ERROR/4; it starts no native owner, Docker operation or scan.
Saved files do not authenticate current ownership or power-loss durability.

If the owner disappears, closure stays unverified and a container can remain; recovery does not claim to remove it.
An operator must verify the exact recorded container identity before any separate cleanup.

### Read the host limits and deadlines

Windows and Linux limits are separate budgets.
The trusted owner, initial admission, output readers and exports are excluded from the Windows hard limits.
V1 host-retained output has logical accounting only.
Explicit v2 adds the controlled record-data allocation boundary described above.
Neither mode provides a whole-directory physical quota.

| Window | Bound and result |
|---|---|
| Complete `host-job-scan` command | `wallMs + 4 × cleanupTimeoutMs` from its start |
| Work before the owner | One shared `3 × cleanupTimeoutMs`; expiration gives `host_job_admission_deadline` without launching the owner |
| Each `gh` version or attestation call | At most the time left in the shared admission window |
| Owner | `wallMs + cleanupTimeoutMs` |
| After the owner's closing deadline | Stop with `host_job_command_deadline` and write no `host-job.json` |

Runtime-policy and provenance refusals keep their own codes, even when the admission window cuts a check short.

> Q. Is the command deadline a hard wall-clock guarantee?
>
> A. No. Steps that cannot stop midway can overrun it, so reports keep `totalCommandWallGuarantee: false`.

Overrunning steps include reading an entire tool image for verification, reading and checking saved records after the owner, and one record write.
The interval between killing the owner and its exit can also overrun the bound.
The limits do not form an aggregate host/Linux budget or complete the job-resource requirement.
Same-user concurrent mutation, macOS and AI/URL/Web/batch/resume jobs remain unsupported by this command.

## Linux job integration in CI

Every pull request runs `linux-job-integration` on `ubuntu-24.04`. It runs the
native supervisor suite with a generated `SCANMUX_NATIVE_JOB_PROFILE`; failures,
skipped tests and an empty suite fail the job. With pinned Linux Docker and
Gitleaks tools, it also runs the real `job-scan` CLI against a 128 MiB text fixture:
LIMIT requires the measured disk limit and INCOMPLETE/3, CONTROL requires a
completed scan without that limit, and STOP interrupts an observed Gitleaks scan.
LIMIT and STOP require the recorded closure fields, independent container absence
and daemon health. STOP does not require absence of `job_closure_unverified`, a
known intermittent issue; its existing closure checks still apply.

The limit run detects snapshot growth. These scenarios do not show a scanner
killed mid-write, and cover one Linux host type. Harness output and the criteria
matrix are uploaded as an artifact; credentials and environment dumps are excluded.
The source and private temporary directories are outside the uploaded evidence.

Run `bash scripts/ci-linux-job.sh` on a Linux Docker host. `SCANMUX_LINUX_JOB_WORK`
selects a fresh dedicated executable bind-mount path for each invocation, defaulting to
`$RUNNER_TEMP/scanmux-linux-job`. For Docker Desktop, use `/opt/scanmux-linux-job` on the
daemon's Linux host (with a separate subdirectory per run) because its `/tmp` is mounted `noexec`. Preparation needs
network access and the reviewed image digest in `.github/scanmux/linux-job-pins.json`;
the scan containers have no network. The harness drops to UID 1000 and uses only
the Docker socket's group. Evidence and run directories remain for inspection.

## Related docs

- [Get started](getting-started.md)
- [AI scan](ai-scan.md)
- [Read, save and check results](results.md)
- [Windows process termination](windows-process-termination.md)
- [ScanMux](../README.md)
