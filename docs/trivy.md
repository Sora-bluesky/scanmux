[English](trivy.md) | [日本語](trivy.ja.md)

# Optional offline Trivy checks

Use this guide to acquire, pin and run optional offline Trivy configuration checks, and to understand their coverage and isolation limits.

The Japanese version, [trivy.ja.md](trivy.ja.md), is authoritative. This English file is its translation.

Trivy is optional.
Only the presence of `tools.trivy` enables it; there is no separate flag or arbitrary argument setting.
Without that entry, ScanMux retains the v2 plan/report format, the original four required engines and their order, and the existing config, plan, snapshot and finding hash inputs.
Enabling Trivy adds a fifth required engine after those four and produces v3 plans/reports.

It does not complete or replace the required AI or runtime-advisories checks.
No command reaches `PASS` today; see [result assumptions](assumptions.md).

## Acquire and configure Trivy

Acquire the Windows x64 Trivy **0.76.1** distribution outside the scanned repository and outside a scan, using the [versioned upstream release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1).
Trivy is licensed under **Apache-2.0**; preserve its applicable license and notices.
ScanMux does not acquire, install or update it during scanning.

The accepted executable SHA-256 is `94618922c9eb324d7099bf217b01504bfc1f87a0d46d6008cb24ec89b1d1a4bb`.
The acquisition evidence for the Windows x64 ZIP uses SHA-256 `1051f49cb22d5284f43425f72aad9cda63ca12ceb92e7caa06903490c82dc9bf`.
Verify the ZIP and the extracted executable separately and retain the ZIP-to-executable relationship with the acquisition record.

A ZIP attestation is not proof of the executable's publisher.
A matching digest fixes bytes; it does not establish that the distribution or its embedded checks are correct, fresh or honest.

Add the following entry to `tools` in the existing external schema 1 or 2 config. Keep the other required tool pins, including the Windows process owner; this fragment is not a complete config. Paths must be absolute and outside the target repository.

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

`plan` records selection, candidate file/module/chart units and execution conditions without starting Trivy. The runtime-policy component is `trivy`. A publisher requirement that the acquired evidence cannot satisfy is refused; a pin or locally recorded acquisition must not be presented as publisher attestation.

## Supported workflow and execution

The first version supports only local Windows `plan`, `scan`, `resume`, `doctor`, and the corresponding v3 saved-result `history`, `recover`, `engine-record` and `engine-history` paths.
AI execution, batch/list execution, Web serving, jobs, remote acquisition, CI generation and other unsupported v3 import/read paths are refused.

`resume` reruns all required engines for the same plan; it does not reuse a previous Trivy completion.
`recover` retains its `ERROR` result.
To disable Trivy, remove the optional pin and make a new plan.
Do not omit it from an existing plan at execution time or rewrite historical results.

Only the fixed `embedded-config-v1` profile runs: Dockerfile, Kubernetes, Terraform, CloudFormation and Helm configuration checks.
It uses the committed snapshot, including planned Terraform modules and Helm charts as units.
External references, suppression, unreadable inputs and unaccounted planned units do not become completed analysis.

Dockerfile candidates include `Containerfile`, `Containerfile.*` and `*.containerfile`.
These scanners do not read compose files or CI pipelines, so ScanMux does not plan them, unless their content looks like a Kubernetes or CloudFormation file; then they are planned as that kind.
A compose file here is one with a top-level `services:` key.

A CI pipeline is `.github/workflows/*`, `.gitlab-ci.yml`, `.circleci/config.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml` or `.travis.yml`.
Other unrecognized YAML stays unresolved.

Both version probing and scanning use the restricted Windows owner. Version probing is exactly `trivy.exe --version`. In the following fixed scan arguments, `S` is the verified snapshot and `W` is the private working area:

```text
trivy.exe config --config W/trivy.yaml --ignorefile W/empty.ignore --cache-dir W/cache --skip-check-update --skip-version-check --disable-telemetry --misconfig-scanners dockerfile,kubernetes,terraform,cloudformation,helm --include-non-failures --exit-code 0 --format json S
```

ScanMux creates an empty config and ignore file, fixes working/home/temp/cache locations under `W`, and does not inherit credentials, proxy settings or `TRIVY_*`.
Repository settings and custom checks are not selected.
A non-elevated AppContainer with zero capabilities runs inside the owner's Job.
The snapshot and a private sibling binary copy receive read/execute access.

The contents of `W` receive Modify access, but `W` itself cannot be deleted, renamed or re-permissioned.
A hardlinked file in any of these roots stops the run before any grant.
There is no ordinary-process fallback.
A missing owner, elevated owner, unavailable profile API or non-Windows host leaves Trivy unstarted and unsupported.

Every `process_owner_appcontainer_*` code except `process_owner_appcontainer_elevated_owner` and `process_owner_appcontainer_profile_unavailable` yields `ERROR`.
Existing time and output limits apply.

## Results and coverage evidence

Only failing checks become `misconfiguration` findings, always with `candidate` evidence.
Trivy-provided prose, code and URLs are not copied into reports.
A normalized finding preserves its rule ID, severity, fingerprint and validated relative location, including start/end lines.
An unknown location is explicit in text/HTML and has no SARIF `locations` field.

Findings require human review; an empty candidate list is not proof that configuration is safe.

Helm line numbers refer to rendered YAML rather than the original template. ScanMux retains the validated template path but reports its source line and end line as unknown. The rendered range contributes only to the hashed observation identity, so separate rendered resources remain distinct.

Coverage receipts reconcile each planned file/module/chart unit with the result.
Non-failing checks contribute completion evidence.
No recognized config gives unsupported coverage; missing, omitted, excluded, unresolved or parse-failed units give partial coverage.
Neither exit zero nor a nonempty result proves that every unit was analyzed.

A result for a target inside the snapshot that was not planned makes coverage partial with `trivy_target_not_planned`, and its rows are not reported.
A target outside the snapshot is still an error.
The fixed-version prototype observed **2 / 17 / 8 / 8 / 17 failing checks** for Dockerfile / Kubernetes / Terraform / CloudFormation / Helm, **52 total**.

Trivy silently omitted a malformed Kubernetes file.
That file's own planned unit must remain partial, never analyzed because another unit succeeded.

With the other engines complete, missing/unstarted/unsupported/partial Trivy coverage yields `INCOMPLETE`.
A configured version other than **0.76.1** is unsupported and yields `INCOMPLETE`; a digest mismatch or a mismatch in the version reported by the executable yields `ERROR`.

A failed process or malformed output also yields `ERROR`; a fully analyzed High/Critical or unknown-severity candidate yields `REVIEW`.
A stopped tree that cannot be verified, changed snapshot or inconsistent plan yields `ERROR`.
Existing precedence is `ERROR > FAIL > INCOMPLETE > REVIEW > PASS`.

## Trust and measured limitations

AppContainer execution tests are skipped on elevated runners such as GitHub-hosted Windows CI, or when the profile API is unavailable.
Isolation evidence comes from non-elevated local runs.
Set `SCANMUX_REQUIRE_APPCONTAINER=1` when running `npm test -- test/trivy-owner.test.ts` to make those skips fail; any other setup failure fails regardless of this flag.

The user trusts the pinned distribution and embedded checks.
A compromised distribution can miss findings or attempt to misuse available permissions.
The AppContainer prototype observed DNS failure **11001** and denied direct TCP connection **10013**.
UDP `SendTo` succeeded; delivery was not observed.
This is not proof of UDP denial or a complete network block.

An out-of-scope sibling readable by **All Application Packages** was readable in the prototype.
A Less Privileged AppContainer would close that gap.
In a local measurement with zero capabilities, neither a .NET probe nor `trivy.exe --version` could start in one, so ScanMux does not use it.
Windows also creates AppContainer profile storage.

If the owner dies before cleanup, a later owner reclaims the profile and its grants from the owner's journal.
See [windows-process-termination.md](windows-process-termination.md).
The grants above do not establish an exact filesystem path allowlist or that `W` is the only writable location.
Isolation of the live repository and credentials beyond measured cases remains unverified.

The 52 observations do not prove complete format support, external-reference safety, rule freshness, deployment safety or absence of misconfiguration.
These trust assumptions, consequences, checks and unverified points are also recorded in [assumptions.md](assumptions.md).


## Related docs

- [Get started](getting-started.md)
- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Windows process termination](windows-process-termination.md)
- [ScanMux](../README.md)
