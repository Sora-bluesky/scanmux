[English](urgent-advisories.md) | [日本語](urgent-advisories.ja.md)

# Check urgent advisories offline

Use this guide to see which declared runtime versions the fixed advisory catalog checks and what remains unverified.

The built-in `runtime-advisories` engine compares PHP, Node.js, Next.js, NGINX, GitLab and Apache Tomcat version declarations.
Its attributed catalog was confirmed against official vendor sources on 2026-10-22.

## What it does not check

- Files are never executed. Images are not pulled, dependencies are not resolved and no advisory service is contacted.
- Dynamic tags, aliases, prereleases, unsupported series and ambiguous declarations remain unverified.
- Vendor patches and the deployed environment remain unverified.
- OpenSSL's actual linked version and BeyondTrust patch state are outside this static check.
- A non-match is not a safety verdict.

## Read supported declarations

Only supported exact stable versions and image variants are compared.

| Tracked input | Declaration read |
|---|---|
| `.nvmrc`, `.node-version`, `.php-version`, `.tool-versions` | Runtime version declarations |
| Dockerfiles | Simple official-image `FROM` declarations |
| npm lockfile versions 1–3 | Next.js resolutions |

## Read the assessment

Every declaration keeps a per-advisory assessment, including when there are no findings.

| Assessment | Meaning |
|---|---|
| Match | The declared version matches a catalog entry; fixed versions are reported. |
| Recorded non-match | The declared version does not match within a recorded range. |
| Unknown | The declaration cannot be assessed by the recorded catalog. |

The engine is required in every plan and always has partial or unsupported coverage.
Omitting it cannot produce `PASS`.
The plan and result bind the catalog hash and confirmation date.
A catalog change needs a new plan.

> Q. Does a scan refresh the catalog?
>
> A. No. Updates require source verification and regression checks outside scanning.

## Use matching schemas

| Contract | Schema |
|---|---|
| Plan | `scanmux.plan/v2` |
| Report | `scanmux.report/v2` |
| Web | `scanmux.web/v2` |

This describes the baseline contracts; optional Trivy uses the v3 plan/report contracts described in its guide.
Saved v1 JSON remains unchanged. Old plans cannot be executed.
Mismatched PC/Sites clients cannot initiate mutations.
The configuration remains schema 1 for this built-in check.
It accepts no executable setting for `runtime-advisories`.

## Related docs

- [Get started](getting-started.md)
- [Read, save and check results](results.md)
- [Trivy](trivy.md)
- [Public feed match](threat-intel.md)
- [ScanMux](../README.md)
