[English](threat-intel.md)

# Match CVEs against public feeds

Use this guide to refresh public advisory feeds and match saved CVE IDs without changing the original scan decision.

ScanMux can compare the CVE IDs in a saved report or import record with two public feeds: the CISA Known Exploited Vulnerabilities (KEV) catalog and the JVN update RSS.
The match runs offline against a local copy, and the result is saved as a separate set of files in a new private directory under the system temporary directory, never next to the input.

`scan` never contacts these feeds, and the match never changes a gate, a report or an exit code based on what it finds.

## Refresh feeds and match CVEs

```
scanmux intel-refresh --store /absolute/intel-store [--json]
scanmux intel-match /absolute/report.json --store /absolute/intel-store --config /absolute/config.json [--max-age-hours N] [--require-fresh] [--report-language ja|en] [--json]
```

`intel-refresh` takes no target and no findings. It sends one GET to each fixed URL below and nothing else: no query, no extra header and no data from any repository. Redirects are refused. Because every user fetches the same URLs, the requests do not reveal which CVEs a repository contains.

| Feed | URL | Kept |
|---|---|---|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Whole catalog. License: CC0 (`https://www.cisa.gov/sites/default/files/licenses/kev/license.txt`) |
| JVN update RSS | `https://jvn.jp/rss/jvn.rdf` | The recent-update window (about 20 items). Terms not verified |
| JVN iPedia (JVNDB) | `https://jvndb.jvn.jp/ja/feed/detail/jvndb_detail_<year>.rdf` | Status only. The service answered 503 with a "stopped, restart undecided" notice when this was written, so no parser exists. A 200 answer is recorded as `unsupported` |

`intel-match` reads a saved `report.json` from `scan` or an `import.json` from `import`, plus the store, and writes `intel-match.json`, `intel-match.html`, `intel-match.txt` and `intel-match.sarif` to a new private directory under the system temporary directory; without `--json`, the command prints the four paths.

The JSON records the SHA-256 of the exact input bytes; if the input changes while the files are prepared, nothing is written and the command exits 4.

Exit codes: 0 means the files were written.
3 is returned only with `--require-fresh`, when KEV or the JVN RSS is unusable or not `fresh`.
`--require-fresh` needs `--max-age-hours`; without it the command is invalid.

JVN iPedia (JVNDB) is a status-only feed: its state is shown in every output, including as a SARIF notification, but it never decides the exit code or the SARIF `executionSuccessful` flag.
4 means invalid input, an invalid or non-private store, a store or output directory inside the scanned repository, or a binding failure.

For an import record, which names no root, the temporary directory and its parents are checked against the record's repository ID before the output directory is created.
A KEV listing never changes the exit code.

## What a match says

CVE IDs come from a finding's `originIds` in a report, or from the rule ID in an import record.
Only exact `CVE-YYYY-NNNN` IDs are used.
In the JVN RSS, a CVE ID is taken from an item's title and description only as a whole token: the characters on both sides must not be ASCII letters, digits, `_` or `-`, so `CVE-2026-0001x` yields nothing.

A GHSA or other ID is never translated into a CVE, and findings without a CVE are counted, not guessed.

For each CVE the KEV result is `listed` (with the date added, the due date and the ransomware field), `not_listed`, or `not_evaluated`.
The JVN result is `observed` (with the advisory ID and link), `not_observed_in_window`, or `not_evaluated`.
There is no result meaning "not in JVN": the RSS shows only recent updates, so its absence says nothing about the full database.

## Check feed freshness

There is no default freshness limit. Each feed shows when it was fetched, its own version or date, and one of these states:

| State | Meaning |
|---|---|
| `never_attempted` | No refresh has been recorded |
| `unavailable` | No usable copy; the latest attempt failed or was unsupported |
| `refresh_failed_previous` | The latest refresh failed. This is shown first, and the match uses the previous copy; never `fresh` |
| `fresh` | The latest refresh succeeded within `--max-age-hours` |
| `stale` | Older than `--max-age-hours` |
| `unjudged` | No limit was given, so the copy is not called current |
| `corrupt` | The newest stored data failed validation; an older valid copy is used if one exists |
| `clock_unknown` | Every record for the feed has a fetch time later than the current clock or unreadable; never `fresh` |

Attempts are ordered by completion time, and a failed attempt wins a tie. A record dated after the current clock or with an impossible time is listed as `clock_unverified` and never decides the state while a readable record exists. A record whose feed cannot be identified is listed for every feed and decides none.

## Keep the feed store private

The store is an absolute directory that ScanMux creates and restricts to the current user.

Every refresh and every match checks this again before reading: the store and its `attempts` and `blobs` directories must be owned by the current user, and nobody else may be granted access (on Windows, the store's protected access list holds a single full-control entry for the current user and the two directories grant access to no one else; elsewhere, mode 0700 or stricter).

Otherwise the command exits 4 with `intel_store_not_private`.
An existing empty directory, or one holding only `attempts` or `blobs` after an interrupted refresh, is adopted only when the current user owns it; on POSIX the store and any existing `attempts` or `blobs` directory are then set to mode 0700.

On Windows, a directory owned by the Administrators group also counts as owned by the current user while the session runs elevated as administrator, because Windows makes that group the owner of everything an elevated session creates; an unelevated session does not accept that owner.

A store this command created but whose owner fails the check is removed, and the command exits 4 with `intel_store_owner_not_user`.
Each refresh appends one attempt record per feed under `attempts/`, and each body is kept once under `blobs/` by its SHA-256.
Nothing is overwritten or shared between attempts, so two refreshes at the same time cannot corrupt each other.

Every read checks the records, sizes and digests again and falls back to the previous valid copy when something is damaged.
Old attempts are not pruned.
The store must be outside the scanned repository.

Download limits stop a runaway body and are not meaning thresholds: 16 MiB for KEV, 1 MiB for the JVN RSS and 60 seconds per feed.

## Parsing rules

A body that breaks any rule below is recorded as `schema_drift` and never becomes a usable copy; the previous copy stays in use.

- KEV: every entry needs its text fields and real calendar dates (`2026-02-31` is refused). An entry listed twice must agree on every known field, including `shortDescription` and `requiredAction`.
- JVN RSS: the whole document is read as XML. Only the XML declaration may appear as a processing instruction; DOCTYPE and ENTITY declarations are refused; comments are skipped, so an item inside a comment is not an item; CDATA may be mixed with text; and the elements must nest correctly under a single closed `rdf:RDF` root. Each item needs an identifier, a `https://jvn.jp/` link, a title and a real RFC 3339 modification time. A known item field that holds child elements, such as markup inside a description, cannot be read, so the whole body is refused instead of reading it as empty.


## Related docs

- [Read, save and check results](results.md)
- [Runtime controls](runtime-controls.md)
- [Result assumptions](assumptions.md)
- [ScanMux](../README.md)
