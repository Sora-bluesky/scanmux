# Evaluation pairs

Three vulnerable/fixed dependency pairs for v0.1.0, one per supported language.
Each is one public advisory and its official fix at the exact released versions,
assembled so the OSV engine reports the advisory at base and clears it at head,
and so `reproduce --base --head` goes from reproduced to not-reproduced over the
same upgrade.

```
eval/pairs/<js|python|go>/
  base/       whole vulnerable tree (manifest/lockfile + vendored dependency)
  head/       overlay: only the files the upgrade changes
  test/       shared regression test, copied into tests/repro at both commits
  pair.json   advisory, versions, lockfile, size limit, whether it reproduces
```

The reproduce tests only observe a safe effect: the lodash test sets an
in-process marker, the PyYAML test writes a marker value to a temporary file;
neither runs a shell command. The vendored dependency is the minimal set of files
the test needs at that version, with its license.

The lodash oracle reports absence only for the exact invalid-variable `Error`
thrown by 4.17.21. A completed template with the marker reports presence;
one without it throws and is recorded as a failure. The PyYAML harness
distinguishes a written marker, `yaml.constructor.ConstructorError`,
and an import failure with separate stdout tokens. Its oracle requires a clean
exit and the expected marker for presence, or a clean constructor-error result
with no marker for absence. Missing runtimes or imports are environment failures;
unexpected exceptions, signals and other child failures are not observations.

## 1. Build the throwaway repositories

`eval-pairs.mjs` assembles each pair into a fresh git repository, commits base,
commits the fix, and prints the two 40-character commit IDs and the test
directory. It never runs a scanner or Docker.

```sh
node scripts/eval-pairs.mjs all /absolute/eval-out
# or one language:
node scripts/eval-pairs.mjs js /absolute/eval-out-js
```

With `all`, each language is built under `/absolute/eval-out/<lang>`. Keep the
printed `base`, `head` and `testDirectory` for each language.

The builder runs git with `core.autocrlf=false` and without the global or system
git config, so each file is committed with the bytes in `eval/pairs/`, and the
built `.git/config` holds only keys that `job-scan` accepts. Check out commits
with the same `-c core.autocrlf=false -c core.attributesFile=` shown below. A
plain `git checkout` under a global `core.autocrlf=true` (the Git for Windows
default) rewrites the changed files with CRLF, and `job-scan`, which runs git
without your global config, then refuses the repository with
`dirty_worktree_unsupported`. The pair's own `.git/config` may set
`core.autocrlf=false|true|input`; `job-scan` preserves it for status checks but
scans committed blobs. Keep `false` for the byte-identical evaluation procedure.
Other keys outside the [accepted policy](../docs/assumptions.md) are refused with
`unsupported_git_config:<section>.<variable>` (plain `unsupported_git_config`
for malformed or oversized identifiers). If a checkout already wrote CRLF,
rebuild the pair or restore it with the matching conversion setting.

## 2. Fetch the offline OSV databases

```sh
node scripts/fetch-osv-db.mjs --destination /absolute/osv-db --ecosystems npm,PyPI,Go --max-bytes <total-byte-limit> --timeout-ms <total-timeout-ms>
```

`fetch-osv-db.mjs` downloads `all.zip` per ecosystem from the public OSV storage
bucket (`npm`, `PyPI` and `Go` are the three the pairs need) and writes them under
`osv-scalibr/<ecosystem>/` with a receipt. This is the only networked step; the
scans below are fully offline.

## 3. Prepare an offline job profile

Use a `scanmux.job-profile/v1` (or `v2`) pointing `osvDatabase` at
`/absolute/osv-db`, with `tools.gitleaks` and `tools.osv`, the pinned offline
Linux image, `runtime.python` at `/usr/bin/python3`, and normal `scan`/`limits`.
See [Runtime controls](../docs/runtime-controls.md) for the schema and the
`job-scan`/`reproduce` commands.

## 4. Scan and reproduce each pair

For `js` and `python` (the reproducible pairs), work in the built repository
(`/absolute/eval-out/<lang>`):

```sh
# a. scan the base commit to get a report that belongs to base
git -c core.autocrlf=false -c core.attributesFile= -C /absolute/eval-out/<lang> checkout <BASE_40>
scanmux job-scan /absolute/eval-out/<lang> --job-profile /absolute/profile.json --json   # save as base-report.json
# read the osv finding's 64-character fingerprint for the advisory package from base-report.json

# b. before/after reproduce with the unchanged test
git -c core.autocrlf=false -c core.attributesFile= -C /absolute/eval-out/<lang> checkout <HEAD_40>
scanmux reproduce /absolute/eval-out/<lang> --job-profile /absolute/profile.json \
  --from /absolute/base-report.json --finding osv:<FINGERPRINT> --test tests/repro \
  --base <BASE_40> --head <HEAD_40> --json

# c. scan the head commit for its own policy result
scanmux job-scan /absolute/eval-out/<lang> --job-profile /absolute/profile.json --json   # save as head-report.json
```

Expect the base scan to report the advisory (a source-supported High/Critical
finding returns `FAIL`/1), the reproduce verification to be
`same_test_no_longer_reproduces` ("The same test no longer reproduces at head,
with the test unchanged."), and the head scan to be clean for that advisory.

For `go` (scanner-only), there is no test directory; run only the base and head
`job-scan` and record that the OSV engine flags GO-2021-0113 at v0.3.6 and clears
it at v0.3.7. The reproduce job cannot execute Go: `/tmp` and `/work` are `noexec`
tmpfs and source is mounted read-only, so a compiled Go binary cannot run, and the
job image has no Go toolchain.

## 5. Record the results

The v0.1.0 results are in
[docs/results.md](../docs/results.md#evaluation-vulnerablefixed-pairs-for-v010):
for each pair, whether the target advisory is reported at base and at head, the
other advisories that remain at head, and the `reproduce` verification and exit
code.
Record only figures you observed; do not invent them.
