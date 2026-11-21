# Sherlock: Username OSINT, Verification & Ethical Investigation

_Upstream installation guidance reviewed: 2026-11-21. Public site outputs were not tested._

> [!CAUTION]
> **Use lawfully & respectfully.** Public account discovery does not establish identity, ownership or consent for harassment. Use a self-owned handle or fictional training fixture; observe website policies and avoid collecting sensitive personal data. See [Legal Notice](../LEGAL.md).

## Overview

[Sherlock](https://github.com/sherlock-project/sherlock) searches participating websites for a supplied username. It is useful for self-audits, impersonation monitoring and consent-based OSINT investigations. It **does not** prove the profiles belong to the same person and can produce false positives or false negatives when sites change their response patterns.

| Task | Sherlock Helps With | Human Analyst Must Do |
|---|---|---|
| Self-service footprint check | Find candidate pages with a self-owned username | Verify and decide whether to keep each account |
| Brand impersonation triage | Identify public lookalikes | Prove misuse without equating matching names |
| Case research | Collect leads | Record provenance, timestamp, confidence & lawful purpose |
| Incident response | Find potentially related public handles | Corroborate independently and protect case subjects |

## Installation & First Run

Install from the project-maintained package using isolated Python packaging, as described by the [official installation instructions](https://sherlockproject.xyz/installation). Older guidance that installs a package simply named `sherlock` can resolve to the wrong distribution; use `sherlock-project`.

```bash
pipx install sherlock-project
sherlock --help
```

The tool makes HTTP requests to websites when searching a handle. Obtain approval for any organizational investigation and use a benign self-owned handle for the example below.

```bash
# Replace your_own_test_handle with a username you control.
sherlock your_own_test_handle
```

Version-dependent flags (output formats, site filters, proxies and timeouts) should be checked with the locally installed `--help` rather than copied from outdated tutorials.

## Evidence-First Investigation

1. Record the exact username and reason it is in scope.
2. Run one limited query; avoid spraying variants across sites.
3. For every candidate, open the public profile manually and confirm the handle, content & page status.
4. Distinguish an account's presence from **attribution**: matching handles, avatars or interests are not conclusive.
5. Preserve the original URL, observation date, screenshot or compliant capture and your confidence notes.
6. Revisit false positives, stale results and profiles hidden behind login before reporting.

### Confidence Matrix

| Evidence | What It Supports | Limitation |
|---|---|---|
| Same public username | Candidate match | Common aliases are reused |
| Shared self-published link | Stronger association | Links can become stale or spoofed |
| Consistent original content | Corroborating context | Screenshots/reposts are copyable |
| Verified platform identity marker | Platform-specific signal | Verification policies vary |
| `Not found` result | No match using current site rule | Rate limits and site changes can hide accounts |

## Privacy, Safety & Defensive Uses

Restrict your investigation to a legitimate case. Redact addresses, private phone numbers and sensitive details from reports. Do not use username matches to dox, stalk, target or pressure individuals. For impersonation, report through the relevant platform's official process and retain the original evidence.

## Troubleshooting & Verification

| Symptom | Likely Cause | Next Step |
|---|---|---|
| Many unexpected matches | Generic username or site-rule behavior | Manual per-site corroboration |
| Known profile missing | API/site changes, blocking or rate limits | Check the public site directly |
| CLI not found after pipx | PATH configuration | Run `pipx ensurepath` and check shell |
| Site temporarily inaccessible | Timeouts or bot protection | Do not bypass access controls |

## Related Guides & Official Sources

- [OSINT Tools Catalog](./OSINT_TOOLS_CATALOG.md) — broader toolkit context
- [OSINT Social Media](./OSINT_socialmedia.md) — corroboration approaches
- [Investigator Playbook](./Playbook/README.md) — case records & provenance
- [Sherlock Project](https://github.com/sherlock-project/sherlock) & [Official Installation](https://sherlockproject.xyz/installation)

---

[OSINT Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
