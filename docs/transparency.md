[English](transparency.md)

# Verify release transparency

Use this guide to reproduce a package measurement and verify an installation against a release-log pin kept outside the repository.

ScanMux keeps an append-only release log in `transparency/releases.jsonl`. Anyone with the repository can check that an installed ScanMux, or a commit, is a release in that log. The check needs only Git and Node, not ScanMux itself, so a ScanMux build can be checked without trusting that build.

A match means "this is the logged release". It is not a security result. The log is tamper-evident only against a pin the owner keeps outside the repository. There is no public log, witness or signature, so the log is not an authenticated history.

## What is measured

The measured file set is the package file set:

- every path in the `files` field of `package.json`, with directories taken recursively
- `package.json`
- `package-lock.json`

`node_modules`, Node, Docker and the operating system are not measured. Dependencies are bound only through the measured `package-lock.json`. The `transparency/` directory is outside `files`, so the log never measures itself.

Each file is recorded as `{"path":"<posix path>","bytes":<size>,"sha256":"<hex>"}`. The records are sorted by path in ordinal (byte) order and joined into one JSON array with no spaces. The measurement is:

```text
sha256("scanmux.release-measurement/v1\n" + <that JSON array>)
```

The measurement holds no time, absolute path or owner data.

ScanMux refuses to measure, with a closed reason, a link or reparse point, a path outside the package root, a case-insensitive name collision, an entry that is not a regular file, a size over the configured limits, a listed path that does not exist, a `files` entry with a glob pattern, and a path that is longer than 1024 characters, is not printable ASCII, or contains `"`, `\` or `:`.

A path segment that is empty, `.` or `..`, ends in a dot or a space, or is a Windows device name (`con`, `prn`, `aux`, `nul`, `com0`-`com9`, `lpt0`-`lpt9`, with or without an extension) is refused too.

## Read and append the release log

Each line is one `scanmux.release-entry/v1` record, in UTF-8 without BOM, ending in LF:

```json
{"seq":1,"prev":"<64 zeros>","version":"0.1.0","sourceCommit":"<commit>","measurement":{"schema":"scanmux.release-measurement/v1","sha256":"<hex>","files":120,"bytes":1234567}}
```

`prev` is the sha256 of the previous line's bytes without its LF, and 64 zeros on the first line. The head of the log is the sha256 of the last line, or 64 zeros for an empty log. A line whose canonical re-encoding differs from its bytes is rejected.

A release is logged in two steps. The release commit lands first. A follow-up pull request then appends the entry, with `sourceCommit` naming the release commit:

```text
scanmux release-record <repo> --commit <release commit> --expect-head <current head or zero> --config <abs config>
```

`release-record` measures the commit from Git blobs, never from the worktree, and appends one line.
It refuses when the log head is not `--expect-head`, or when the version is already logged with another measurement.
Running it again for a release that is already logged appends nothing and prints the existing line.
It is the only command that writes the log.

It holds `transparency/.releases.lock` from reading the log until the new log replaces the old one, so a second writer reads the new head and is refused with a head mismatch.
A lock left by a crashed writer is not removed: the next writer waits up to the configured timeout and then refuses with `release_log_locked`, and you delete the lock after checking that no writer runs.

On every pull request, the `checks` workflow runs `release-log-check`.
It requires the base branch log to be a byte prefix of the pull request log, a valid chain, each version logged with one measurement, each source commit logged once, and every entry to be reproducible from its source commit.
This runs inside the repository being checked, so it is not a trust anchor.

## Reproduce a measurement without ScanMux

Save this script as `measure.mjs` and run `node measure.mjs <repository> <commit>`. It uses only Git and Node. It prints the version and the measurement.

```js
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const [repository, commit] = process.argv.slice(2);
const git = args => execFileSync('git', ['--no-replace-objects', '-C', repository, ...args], { maxBuffer: 1 << 30 });
const tree = new Map(git(['ls-tree', '-r', '-z', '-l', '--full-tree', commit]).toString('utf8').split('\0').filter(Boolean).map(line => {
  const tab = line.indexOf('\t'), [mode, , oid] = line.slice(0, tab).split(/ +/);
  return [line.slice(tab + 1), { mode, oid }];
}));
const blob = name => git(['cat-file', 'blob', tree.get(name).oid]);
const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(blob('package.json')));
const selected = new Set();
for (const entry of [...manifest.files, 'package.json', 'package-lock.json']) {
  const name = entry.replace(/\/$/, '');
  const found = tree.has(name) ? [name] : [...tree.keys()].filter(path => path.startsWith(name + '/'));
  if (!found.length) throw new Error(`listed path missing: ${name}`);
  for (const path of found) selected.add(path);
}
const files = [...selected].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map(path => {
  if (!['100644', '100755'].includes(tree.get(path).mode)) throw new Error(`not a regular file: ${path}`);
  const content = blob(path);
  return { path, bytes: content.length, sha256: createHash('sha256').update(content).digest('hex') };
});
const sha256 = createHash('sha256').update('scanmux.release-measurement/v1\n' + JSON.stringify(files)).digest('hex');
console.log(JSON.stringify({ version: manifest.version, sha256, files: files.length, bytes: files.reduce((sum, file) => sum + file.bytes, 0) }));
```

The manifest is decoded as strict UTF-8, and a leading byte order mark is dropped before parsing, as ScanMux does.
The bytes of `package.json`, a byte order mark included, are measured unchanged.
Compare the output with the `version` and `measurement` of a line in the log.
Read the log from a commit, not from a worktree: `git cat-file blob <log commit>:transparency/releases.jsonl`.

To print the entry count and head of a log, as used in a pin, save this script as `head.mjs` and run `node head.mjs <repository> <log commit>`.
It refuses every log that ScanMux refuses: a log over 1 MiB, a byte order mark, a CR, a missing final LF, a line that is not in the canonical encoding, a broken chain, a version logged with two measurements, and a source commit logged twice.

```js
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const [repository, commit] = process.argv.slice(2);
const bytes = execFileSync('git', ['--no-replace-objects', '-C', repository, 'cat-file', 'blob', `${commit}:transparency/releases.jsonl`], { maxBuffer: 1 << 30 });
if (bytes.length > 1024 * 1024) throw new Error('the log exceeds 1 MiB');
const log = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
if (log && !log.endsWith('\n')) throw new Error('the log does not end with LF');
const canonical = /^\{"seq":([1-9][0-9]*),"prev":"([0-9a-f]{64})","version":"([0-9A-Za-z][0-9A-Za-z.+-]{0,63})","sourceCommit":"([0-9a-f]{40})","measurement":(\{"schema":"scanmux\.release-measurement\/v1","sha256":"[0-9a-f]{64}","files":([1-9][0-9]*),"bytes":(0|[1-9][0-9]*)\})\}$/;
let head = '0'.repeat(64), entries = 0;
const versions = new Map(), commits = new Set();
for (const line of log ? log.slice(0, -1).split('\n') : []) {
  const match = canonical.exec(line);
  if (!match || ![match[1], match[6], match[7]].every(number => Number.isSafeInteger(Number(number)))) throw new Error(`line ${entries + 1} is not canonical`);
  const [, seq, prev, version, sourceCommit, measurement] = match;
  if (Number(seq) !== entries + 1 || prev !== head) throw new Error(`broken chain at line ${entries + 1}`);
  if (commits.has(sourceCommit)) throw new Error(`source commit logged twice at line ${entries + 1}`);
  if (versions.has(version) && versions.get(version) !== measurement) throw new Error(`version logged with two measurements at line ${entries + 1}`);
  commits.add(sourceCommit); versions.set(version, measurement);
  head = createHash('sha256').update(line).digest('hex');
  entries++;
}
console.log(`${entries}:${head}`);
```

## Verify an installation

The measurement is taken over the exact bytes of the files.
The repository has a root `.gitattributes` with `* -text`, so a checkout is byte-identical to the Git blobs even when `core.autocrlf` is set.
For a checkout of an older commit, clone without line-ending conversion: `git -c core.autocrlf=false clone <url>`.
A checkout with converted line endings measures differently and is never `logged`.

```text
scanmux release-verify <repo> --log-commit <commit> --installed <abs dir> --pin <entries>:<head> --config <abs config>
scanmux release-verify <repo> --log-commit <commit> --commit <commit> --pin <entries>:<head> --config <abs config>
```

Installed-tree verification currently fails with `release_measurement_listed_path_missing` because the package omits `package-lock.json`, which the measurement lists; use `--commit` until this is fixed.

| Situation | Verdict | Exit |
| --- | --- | --- |
| The measurement is in the log inside the pinned prefix, and the chain and pin are valid | `logged` | 0 |
| The measurement is in the log, and no `--pin` was given | `logged_unpinned` | 3 |
| The measurement is not in the log | `not_logged/measurement_absent` | 3 |
| The measurement is in the log only after the pinned prefix | `not_logged/after_pin` | 3 |
| The same version is logged with another measurement | `not_logged/version_logged_with_other_measurement` | 4 |
| Broken chain, non-canonical line, a version logged with two measurements (`version_conflict`), a source commit logged twice (`duplicate_commit`), or pin prefix mismatch | `log_tampered/<reason>` | 4 |
| Log missing, over the size limit, Git failed, or not a file | `log_unreadable/<reason>` | 3 |

Every result carries `scope`: the package file set is measured, dependencies are lockfile-bound and not measured, there is no witness, and the history is not authenticated.
`independent` is `true` only when the running ScanMux package is outside the repository being verified and its own package file set measures differently from the target.

It is `false` when the running package is inside that repository, when it measures the same as the target, or when either measurement is unavailable, because a build cannot vouch for itself.
Check such a target again with a ScanMux from another location, or with the scripts above.

## Keep and update your pin

The pin is `<entries>:<head>` of a log you reviewed. It is the trust anchor, so keep it outside the repository, for example in your own notes or deployment configuration. Never take a pin from the repository, a pull request or a log line.

1. When a log pull request merges, check its new lines. Reproduce each new measurement with `measure.mjs` from the release commit, and confirm the version is the one you meant to release.
2. Print the new pin with `head.mjs` at the merged log commit, or take it from the `release-record` output when it matches.
3. Replace your stored pin with the new one only after both checks pass.
4. Verify installations with `--pin`. Without `--pin`, a match is `logged_unpinned` with exit 3, the result says `pin: none`, and it is not owner-approved.

A `log_tampered/pin_mismatch` result means the log no longer extends what you pinned. Treat it as a rewritten history: do not update the pin, and find out who changed the log.


## Related docs

- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Result assumptions](assumptions.md)
- [ScanMux](../README.md)
