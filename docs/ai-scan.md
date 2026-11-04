[English](ai-scan.md) | [日本語](ai-scan.ja.md)

# Check the Linux connection and run an AI scan

Use this guide to check the optional Linux connection, prepare isolated AI execution and review the source scope before accepting a plan.

## Check the Linux connection without inference

The diagnostic checks ChatGPT authentication type, advertised Daybreak programs, a model-free isolated Linux connection and resource cleanup.
It starts no inference turn, sends no target source and never enables AI scanning.

The optional `runner-check` diagnostic currently supports a Windows host with Docker Desktop's Linux engine and official Codex **0.163.0** host/Linux binaries.
It contacts OpenAI for account/model metadata; ordinary offline scans and `doctor` do not perform this diagnostic.
Use an existing ChatGPT login.
Ambient API keys are ignored, and no credentials are copied to the container.

Add a `runner` object to trusted external configuration.

| Field | Value |
|---|---|
| `codex`, `linuxCodex`, `docker` | Executable records with absolute `path`, `sha256` and `version`, as for other tools |
| `image` | A `sha256:…` digest for a locally available compatible Linux image |
| `authHome` | The existing host Codex home |

Set `disabledMcpServers` and `disabledPlugins` to arrays of the configured connection names that must be disabled for this process.
Effective connections are checked before the diagnostic thread starts.
Images and binaries are never downloaded; missing tools, mismatched hashes, unexpected connections or protocol requests fail closed.
Keep this machine-specific configuration private.

Run the model-free diagnostic explicitly:

```sh
node bin/scanmux.mjs runner-check --config /absolute/config.json --json
```

The disposable container has no network, no capabilities, a read-only root, and only the pinned executor plus an empty diagnostic directory mounted.
The relay rejects every process, file-content and mutation request.

| Result field | Value | Meaning |
|---|---|---|
| `codeExecution` | `"not_checked"` | Code execution was not checked. |
| `accessProgramEffective` | `"unknown"` | Model discovery advertises eligible selections; the fixed app-server protocol returns no per-response program evidence. |

The output fields are `codeExecution: "not_checked"` and `accessProgramEffective: "unknown"`.

| Diagnostic result | Gate | Exit code |
|---|---|---:|
| Connection checks succeeded | `INCOMPLETE` | 3 |
| Check failed | `ERROR` | 4 |

It cannot make a target scan eligible or prove effective Daybreak treatment; target scans use the separate AI plan workflow.

## Plan and run an isolated AI scan

### Requirements for AI execution

The AI workflow supports one clean local Git root on Windows with Docker Desktop's Linux engine.
It uses Codex Security **0.5.1**, bundled plugin **0.1.95**, and the fixed image and asset manifest disclosed by `ai-plan`.
Prepare those assets separately.
ScanMux does not install or download them.

Place the assets and an already authenticated, owner-private SIWC credential store outside the target and outside each other.
Ambient Codex credentials, API keys and browser sessions are not used.

Codex Security 0.5.1 CLI/SDK contracts were inspected.
The AI route uses ChatGPT authentication and OpenAI, and requests `daybreak_blue` as an optional higher setting.
Effective `standard` is a valid AI check. Requested and effective programs are recorded separately.
API billing never activates automatically.
Host ChatGPT login establishes neither effective Daybreak access nor account allowance.
Default offline commands make zero AI calls. Explicit AI runs record observed usage separately.
No flag bypasses runtime verification.

### Configure AI execution

Add `ai` to the trusted controller configuration. The following limits are an example, not a recommended budget for real inference. Choose explicit positive integer limits for your workload. All durations are milliseconds.

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

| Field | Required values |
|---|---|
| `assetsRoot`, `credentialStore` | Existing absolute directories |
| `reasoningEffort` | `high` |
| `limits` | `maxRequests`, `maxTotalOutputTokens`, `maxOutputTokensPerRequest`, `maxInputBytesPerRequest`, `maxResponseBytesPerRequest`, `maxToolCalls`, `maxToolResultBytes`, `timeoutMs` |
| `ipc` | `maxFrameBytes`, `maxBytes`, `maxFrames` |
| `workerResources` | `cpuCount`, `memoryBytes`, `tmpBytes`, `workBytes`, `shmBytes` |
| `commandTimeoutMs`, `cleanupTimeoutMs`, each `timeoutMs` | Durations in milliseconds |

The top-level `timeoutMs` covers the complete command, including planning, static checks and Linux startup.
Phase limits cannot extend that deadline.
`cleanupTimeoutMs` is a separate bounded shutdown allowance.
It cannot initiate inference.
Credential loading is read-only and happens at the first authorized submit, after complete source secret checks and Linux startup.

Expired, locked, linked, malformed or insufficiently private stores stop the attempt.
ScanMux does not log in, refresh credentials or retry requests.

### Set worker resource limits

`workerResources` is required for every configuration that contains `ai`.
It sets the isolated Linux worker's CPU rate ceiling, memory ceiling without swap, and separate `/tmp`, `/work` and `/dev/shm` capacities.
Choose values per repository profile; ScanMux supplies no resource defaults.
Byte values must be multiples of 4096 and memory must be at least 6 MiB.
The CPU count is a positive integer.

The example is for development verification, not a recommended production profile.
Tmpfs and shared memory count toward the memory limit.
CPU throttling records enforcement of the rate ceiling; it is not a cumulative CPU-time budget or a failure by itself.

### Verify resource and SDK stops

The fixed Linux runtime must expose cgroup v2.
ScanMux verifies the container configuration before start, then checks the actual cgroup and filesystem capacities inside the worker.
Missing or mismatched observations cannot establish completion.

Known memory, disk-capacity or deadline exhaustion is recorded as incomplete when source integrity, usage and termination are established; independent failures or unknown termination remain errors.
Existing FAIL/ERROR findings keep their priority, and no request is retried.
Reports keep resource observations and the worker's final exit/OOM state from before its owned container is removed.

SDK failures stay errors when only message text or a concurrent resource observation suggests a full disk. For the pinned SDK's initial Python scan registration, ScanMux can retain a native SQLite FULL exception and verify that it caused the child to exit.
A disk-capacity stop also requires verified invocation, worker integrity, SDK cleanup and host termination. Mixed errors, a different terminal exception, missing observations and later SDK phases keep their original classification. The optional `runtime.sdkInitializationObservation` records this bounded evidence without SQL, error messages or stack traces. Not every SDK capacity failure is identified; direct worker errors, host-observed OOM and deadlines remain separate evidence paths.

On a GitHub-hosted `ubuntu-24.04` runner with SDK 0.5.1, no network or provider call, and filesystems with no free blocks, the results were:

| SDK path | Filesystem | SQLite result in the child | ScanMux result |
|---|---|---|---|
| Initial `register-cli-scan`, new database | tmpfs | `SQLITE_FULL` | `resource_disk_exceeded` when the conditions above hold |
| Other workbench commands, existing database | tmpfs | `SQLITE_IOERR_SHMSIZE` | No capacity cause |
| All workbench commands, including `register-cli-scan` | ext4 | `SQLITE_CANTOPEN` | No capacity cause |

The other workbench commands measured were `get-cli-scan-resume`, `get-scan`, `get-scan-feedback`, `set-scan-thread`, `set-scan-cost-limit`, `prepare-scan-completion`, `finalize-scan-usage` and `fail-scan`. Even reads fail because each command opens the database and applies migrations.

ScanMux does not treat `SQLITE_IOERR_SHMSIZE` or `SQLITE_CANTOPEN` as a disk-capacity cause because these codes also have other causes. When these failures end the SDK run, they keep their stage code, such as `worker_sdk_initialization_failed` or `worker_sdk_finalization_failed`. The SDK's own error chain carried no native error code: every `code` was null. The workbench failure reaches Node only as exit status and text.

Not measured: other filesystems, a filesystem with free blocks but no inodes, the SDK's own Node writes, MCP paths, a live provider run and memory limits.

### Migrate older AI configurations

These limits cover the Linux worker and its descendants.
They do not bound the Windows controller, host-side Git/Gitleaks/OSV, credential relay, GitHub acquisition or retained host reports.
Worker limits do not establish whole-job resource acceptance.
Older AI configurations must add `workerResources` before use with **any** command, including history and CI; configurations without `ai` stay offline.

Replan after migrating: AI disclosures and execution observations now use their v2 schemas.
Saved v1 AI reports remain readable with a valid configuration and show resource evidence as unrecorded.
Completion checks recompute the saved plan hash and require the v2 resource observations to match the accepted plan; deleting them cannot keep the original CI plan identity.

Saved records and hashes are not signatures.

### Review and run the plan

```sh
node bin/scanmux.mjs ai-plan /absolute/repository --config /absolute/controller.json --json
node bin/scanmux.mjs ai-scan /absolute/repository --config /absolute/controller.json --accept-plan <planHash> --json
```

Read the disclosure before supplying its exact `planHash`.
Source, configuration or budget changes require a new plan.
`ai-plan` reads no credential contents, starts no worker and contacts no provider.
Its exit 0 means planning completed.
`ai-scan` may send the accepted source text, fixed SDK instructions and bounded conversation or tool results to the fixed OpenAI Responses endpoint.

Full requests and results pass secret checks.
`store:false` is requested.
Provider retention and training policy remain unverified.

### Read request and usage evidence

The host owns credentials, request reservations and usage records. Linux receives a read-only Git projection with an explicit mapping to the original commit. Reports preserve accepted candidate findings, actual submit, connection and application-send counts, observed tokens, scope limitations and cleanup results. A submit or send does not prove server acceptance. Missing usage stays unknown; cost is N/A for this route and account allowance is unknown. Effective `standard` and `daybreak_blue` are valid AI checks. Unknown, missing or unrequested programs and corrupt responses cannot produce accepted AI findings. Unverified termination retains private work data.

`aiExecution.transportRequests` records bounded transport diagnostics for each request:

| Field | Meaning |
| --- | --- |
| `sequence` | Request number within the AI execution. |
| `receivedBytes`, `receivedMessages` | Bytes and complete WebSocket messages delivered to the decoder, including a message it rejects. An oversized message blocked by the WebSocket library is not included. |
| `firstEvent` | Shape of the first WebSocket message, or `null` when none arrived: `kind` (`object`, `non_object` or `invalid_json`), `type` (the event type when it matches `^[a-z][a-z0-9_.]{0,63}$`, otherwise `other` or `absent`), up to 16 sorted top-level key names that match `^[a-z][a-z0-9_]{0,39}$` plus `otherKeys` for the rest, the value class of `sequence_number` and `sequence` (`integer`, `absent` or a JavaScript type name), and whether `stream_id` is `absent`, `null` or `present`. It is taken even when the message arrives after the deadline or is rejected. No payload value is kept. |
| `rejectedEvent`, `rejectedAt` | Shape of the first message whose decoder push throws, using the same bounded fields and type/key patterns as `firstEvent`, and its 1-based message index within the request. `rejectedEvent` also has `valueShapes`: for each recorded top-level key, the JSON type (`string`, `number`, `boolean`, `null`, `array` or `object`) and `size` (string or array length, object key count, otherwise `null`). For an object `response` it adds the type and size of `response.output` and the type of `response.status` (`statusType`, `absent` when missing); for an object `safety_buffering` it adds that object's key names and `otherKeys` under the same key pattern. Both are `null` when no received message was rejected by the decoder. Later messages do not overwrite them. No payload value is kept. These fields are optional in older reports. |
| `terminal`, `terminalKind` | Whether a terminal event was decoded and its kind: `completed`, `incomplete`, `failed` (also a protocol `error` event), or `none`. Seeing a terminal event does not establish acceptance. |
| `closeCode` | Observed WebSocket close code, or `null` when unavailable. |
| `sendOk` | Whether the application send callback succeeded; this does not prove provider acceptance. |
| `failureCode` | First stream failure rule, such as `response_limit` (cumulative bytes or event count), `message_too_large`, `unexpected_event`, `sequence_mismatch`, `socket_error`, or `early_eof`; `null` if no transport/decoder rule failed. |
| `providerErrorCode`, `incompleteReason` | Optional allow-listed provider error code from flat or nested `error` events or `response.failed`, such as `server_error`, `cyber_policy`, `insufficient_quota` or `rate_limit_exceeded`. Unknown string codes are recorded as `other`; null or absent codes and all error details are omitted. Incomplete reasons remain allow-listed, such as `max_output_tokens`; unknown reasons are omitted. |
| `outputIdentityMismatch` | Recorded only when the `output` of a `response.completed` terminal disagrees with the streamed output items; otherwise absent or `null`. Fields: `streamedItemCount`, `terminalOutputLength`, the checked wire `index`, `kind` (`missing_index`, `type`, `id`, `call` or `name`), and `streamedType`/`terminalType` (`message`, `function_call`, `reasoning`, `other`, or `null` when the item is missing or has no string type). The failure code stays `output_identity`. No item ids, call ids or names are kept. |

Every host submit invocation gets a diagnostic row, including failures before a transport is created. Such rows have zero received bytes/messages, no terminal or close code, `sendOk: false`, and a fixed credential failure code or `transport_setup`. A successful host close alone does not prove that a socket was opened.

Diagnostics retain no response body, prompt text, credentials, or additional content identifiers. An event rejected because its name is unknown gets the fixed `unexpected_event` failure code; an earlier check that fails first, such as a missing `sequence_number`, sets its own code instead. Event names are kept only in the `type` fields of `firstEvent` and `rejectedEvent`, limited to the pattern above. English/Japanese HTML and the CI summary show a short diagnostic line when a failure code is present. A normal `incomplete` terminal has `terminalKind: "incomplete"` and no stream failure code; existing execution reasons and acceptance decisions still apply. The array is optional under the existing `scanmux.ai-execution/v1` and `/v2` schemas: saved-report readers allow additional execution fields and do not use them for completion decisions, so no schema version change is needed. Records without the array remain readable.

Development checks exercise this command workflow with synthetic credentials, loopback responses and a real Linux SDK.
Synthetic evidence always remains partial and cannot establish real Blue access or vulnerability-detection quality.
Ordinary `scan`, Web, batch and `resume` remain offline with AI blocked.

An explicitly accepted `ai-scan` can create a v2 CI receipt in [local CI completion checks](results.md#check-local-ci-completion).
AI reports cannot authorize `resume`.
No synthetic flag or endpoint override is exposed by the production CLI.

## Related docs

- [Get started](getting-started.md)
- [Runtime controls](runtime-controls.md)
- [Read, save and check results](results.md)
- [Result assumptions](assumptions.md)
- [ScanMux](../README.md)
