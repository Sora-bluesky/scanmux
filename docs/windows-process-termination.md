[English](windows-process-termination.md)

# Build and use the Windows process owner

Use this guide when Windows tools need verified process-tree termination: it covers building, pinning and the owner’s guarantees and limits.

On Windows, ScanMux starts every tool (Git, Gitleaks, OSV-Scanner, gh) through a small resident helper, the Windows process owner. The helper puts each tool in its own Job Object, so a cancel, a timeout or an output limit stops the tool and everything it started. ScanMux reports a stop only after it has seen the whole tree end.

## Build the process owner

The helper is built from `internal/windows-process-owner.cs` with the .NET Framework compiler that ships with Windows PowerShell 5.1:

```powershell
powershell -NoProfile -File scripts/build-windows-process-owner.ps1 -OutputDirectory C:\absolute\new\directory
```

The output directory must not exist yet. The script prints one JSON receipt (`scanmux.windows-process-owner-build/v1`) with the version, the source SHA-256, the assembly SHA-256 and the assembly size.

## Pin the process owner

Add the assembly to the config as an ordinary tool. Config schema 1 and schema 2 both accept the key, so a schema 1 config keeps working on Windows:

```json
"tools": {
  "windows-process-owner": { "path": "C:\\absolute\\new\\directory\\scanmux-windows-process-owner.exe", "sha256": "<assemblySha256>", "version": "1.4.0" }
}
```

The pinned path must be canonical, with no junction or symbolic link.
ScanMux reads the file once and checks the SHA-256 of those bytes against the pin.
It writes the same bytes to a new file in a private directory that only the current user can open, starts that copy, and removes the directory when the command ends.
A later change to the pinned file does not change the running helper.

After it starts, the helper must announce the pinned version.
With a runtime policy v2, the helper is also a runtime subject named `windows-process-owner`, so a deny rule can stop it.
A runtime policy v1 cannot name it.

## When it is required

On Windows, a command that would start a configured tool refuses to run without the pin.
It fails with `process_containment_unavailable` before any tool starts, the gh publisher check included; `deps` exits 2 (failure), while other commands exit 4.
Only a stop or deny decision of the runtime policy, which starts nothing, is reported before it.

`doctor` without tools, `runner-check` without Gitleaks, `engine-history`, `job-scan` and `host-job-scan` do not need it.
Other platforms keep process groups and ignore the pin.

## What is guaranteed

- Each tool is created suspended, inside its own Job Object, with kill-on-close and no breakaway. Its membership is checked before it runs, and its descendants inherit the Job.
- A stop terminates the Job. It counts as complete only when the root process has exited and the Job reports no active processes in two samples, the second taken after the helper has yielded to the scheduler.
- Each request has one stop deadline. After a cancel or an output limit it is 5000 ms after the stop request. After a timeout, which the helper starts by itself, it is the tool's deadline plus 5000 ms. The deadline covers the confirmation, the drain of the tool's output and ScanMux's wait for the helper's answer. An answer that arrives at or after it makes that request `termination_unverified`, and other open requests are not affected.
- ScanMux starts its deadline when it sends the stop, and the helper starts its own when it reads the stop. A stop the helper confirms within its own budget can therefore still be reported as `termination_unverified`. The error is always toward failure.
- When a tool exits by itself but leaves descendants behind, the helper keeps the Job until the tool's deadline and then stops it as `timeout`.
- If the budget passes, the helper is lost or its answers break the protocol, the result is `termination_unverified`, never a success.
- Standard input goes to the helper in frames of at most 64 KiB, so its size has no limit of its own, and NUL bytes pass unchanged.
- If ScanMux exits, the helper sees the end of its input and terminates every Job. If the helper dies, kill-on-close still removes the trees, but ScanMux reports every open request as `termination_unverified`.

Off Windows, a stop kills the process group and then waits, within the same 5000 ms budget, until no process in the group remains. Otherwise the result is `termination_unverified`.

## Trivy AppContainer execution

Version 1.2.0 adds the optional request field `appContainer: { snapshot, work }`.
Ordinary requests omit the field and keep the existing Job Object behavior.
Trivy requires this field for both its version check and its config scan; there is no ordinary-process fallback.
Version 1.4.0 keeps that field and changes how W is granted and which files may be granted, as described below.

ScanMux refuses the request on other platforms, without an admitted owner, or with an owner version other than 1.4.0.
These cases produce an unsupported Trivy result, not an analysis result.
The diagnostics are respectively `process_appcontainer_unsupported_platform`, `process_appcontainer_owner_unavailable`, and `process_appcontainer_owner_version_unsupported`.

The coordinator must be non-elevated and outside AppContainer.
Each request creates a unique disposable profile with zero capabilities.
The owner grants that profile SID ReadAndExecute on the snapshot and executable directory.
On the private work directory W it grants Modify only through an inherit-only entry, so the contents of W are modifiable.

W itself gets only list, read, create-file and create-directory rights.
The tool can empty W but cannot delete, rename or re-permission it.
The executable directory must be a sibling of W; none of these three roots may overlap.
The current directory must be inside W.
Reparse points in the roots, their ancestors or their existing contents are rejected.

Every existing file in the three roots must have a single link: a hardlinked file shares one ACL with a name that may lie outside the root, so the owner refuses it before granting anything.
Before launch, the owner creates `W/local/Packages/<profile>/AC/Temp` and sets `LOCALAPPDATA` to `W/local` because Windows derives AppContainer temp paths from it.

The process is created suspended with the AppContainer security-capabilities attribute and the same Job and inherited-handle list as ordinary execution.
Before resuming it, the owner verifies that the token is non-elevated, has zero capabilities and has the expected AppContainer SID.
The Job still owns descendants and confirms timeout, cancellation and output-limit stops.

Setup failures do not resume the tool and retain distinct operation diagnostics:

| Diagnostic | Cause |
|---|---|
| `process_owner_appcontainer_elevated_owner` | the owner is elevated. |
| `process_owner_appcontainer_profile_unavailable` | the profile API is absent or reports E_NOTIMPL; the native error field retains the HRESULT. When the DLL or entry point is missing, the native error field holds the .NET exception HRESULT. Other profile-creation errors use `process_owner_appcontainer_profile_failed` and also retain the HRESULT. |
| `process_owner_appcontainer_owner_token_invalid` | the owner's token cannot be verified or is already an AppContainer. |
| `process_owner_appcontainer_roots_invalid` | roots overlap, have invalid layout or contain reparse points. |
| `process_owner_appcontainer_hardlink_present` | a file in a root has more than one link. |
| `process_owner_appcontainer_grant_failed` | applying a SID grant failed. |
| `process_owner_appcontainer_create_failed` | process creation or attribute setup failed. |
| `process_owner_appcontainer_token_mismatch` | the suspended child's token is elevated, has capabilities, has the wrong SID or cannot be verified. This is execution failure (`ERROR`), not unsupported execution. |
| `process_owner_appcontainer_setup_failed` | another unexpected setup exception occurred. Existing native operation codes also remain distinct for Job, pipe, membership and resume failures. |

Every `process_owner_appcontainer_*` code except `process_owner_appcontainer_elevated_owner` and `process_owner_appcontainer_profile_unavailable` yields `ERROR`.

The exceptions to AppContainer setup diagnostics are digest mismatch (`process_owner_tool_digest_mismatch`), request-parse errors (`process_owner_descriptor`, or `process_owner_unexpected` for malformed JSON/UTF-8), and cleanup failure (`process_owner_appcontainer_cleanup_failed`), which overrides the preceding result.

A suspended process already created during setup must first have its entire Job stopped; an unconfirmed stop remains `termination_unverified`.

After the Job is confirmed empty, the owner removes its SID grants, checks all three trees for residual SID ACEs, and deletes the disposable profile.
Cleanup failure reports `process_owner_appcontainer_cleanup_failed` and is an error, even if the tool exited successfully.
An unverified tree stop leaves the profile and grants intact so cleanup cannot race a surviving process.

ScanMux retains the work area in that case.

Since version 1.4.0 each owner keeps a journal in `%LOCALAPPDATA%\scanmux-owner-journal`.
The folder allows only the current user and must not be a reparse point.
The owner holds its own journal file open without sharing for its whole life.
Before creating a profile, it appends the profile name and the three roots, flushed to disk.
After the profile is deleted, it appends an end mark.

A journal that cannot be written stops the request before any profile exists, with `process_owner_appcontainer_journal_failed`.
This also happens when the folder is not private: it has another owner, other access entries, inherited entries or is a reparse point.
Remove the folder by hand while no ScanMux command is running; the next owner recreates it.

Journals still in the folder are lost with it, and their profiles and grants then need manual cleanup.
A folder owned by Administrators may need an elevated shell to remove.
An elevated owner refuses AppContainer requests, so it neither creates the folder nor reclaims anything.
After stdin closes, Main waits up to 4.5 seconds for open requests to finish cleanup.
A clean exit removes the journal.

When an owner dies with entries still open, for example after a crash, `taskkill /F` or an unverified stop, a later owner reclaims them after sending Ready.
It opens each other journal exclusively.
A sharing violation means the owner is alive, and its entries are left alone.

Any other failure to open means liveness cannot be decided; the entries are kept with `process_owner_appcontainer_recovery_liveness_unknown`.
For a dead owner's open entry, it removes every ACE for the profile SID from each root that still exists, checks the trees for residual ACEs, deletes the profile and appends the end mark.
Reclaiming only removes ACEs; it never adds one.

A root that has become a reparse point is not touched, and the profile is kept with `process_owner_appcontainer_recovery_root_invalid`.
Other kept cases report `recovery_residual_ace`, `recovery_profile_failed`, `recovery_journal_invalid`, `recovery_journal_delete_failed` or `recovery_failed`, each with the `process_owner_appcontainer_` prefix.

A journal folder that cannot be used reports `process_owner_appcontainer_journal_failed` here as well.
A residual ACE that the tool caused, for example through a reparse point it left inside W, is reported again at every start until someone removes it.
The owner sends the result in frame kind 10.

When something was kept, ScanMux writes one line to standard error after the command; it does not change any scan result.
Profiles from owners older than 1.4.0 have no journal and are not reclaimed.
The tool may not be started again through an unrestricted path.

`execute(..., { captureStderr: true })` exposes stderr as an internal Buffer for the Trivy parser. Stdout and stderr share the configured output bound. Without this option the return value has no stderr field, preserving the existing interface. Raw Trivy output is not a public diagnostic or persisted report field.

This is Windows AppContainer isolation, not a strict filesystem path allowlist.
An AAP-readable resource outside the granted roots can remain readable; profile storage also has an AppContainer SID grant.
The synthetic private sibling in the isolation test is denied, while a deliberately AAP-readable sibling is readable.

Do not place live repositories or credentials in AAP-readable locations or interpret this boundary as exclusive access to S/bin/W.

The measured prototype failed DNS with 11001 and remote TCP with 10013.
The repeatable owner test uses loopback only: TCP does not reach a listening host socket (10013 or a bounded 10060 timeout).
UDP SendTo can return success; UDP delivery or denial remains unverified.
No external network probe is part of the owner test, and no stronger UDP guarantee is claimed.

AppContainer execution tests skip only for an elevated owner or unavailable profile API.
Elevated runners, including GitHub-hosted Windows CI, skip these tests; isolation evidence therefore comes from non-elevated local runs.
`SCANMUX_REQUIRE_APPCONTAINER=1 npm test -- test/trivy-owner.test.ts` turns either environment skip into a failure.

Grant, creation and token-verification failures always fail the tests.

## Limits

- Processes started through other services, such as the Task Scheduler or the Docker daemon, are outside the Job. Docker keeps its own cleanup.
- A protected process that denies termination cannot be stopped. That stop is reported as `termination_unverified`.
- Two narrow paths still start a tool directly: the gh publisher check that runs before the runtime is admitted, and the `--version` check of the host job owner. On Windows, a stop on these paths is always reported as `termination_unverified`.
- Process IDs are shown for display only. Ownership and stopping never use them.
- The private copy of the helper can be rewritten by another process of the same user, or by an administrator, between its write and its start. The SHA-256 check does not cover that window. Removing the copy when the command ends is best effort.


## Related docs

- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Result assumptions](assumptions.md)
- [ScanMux](../README.md)
