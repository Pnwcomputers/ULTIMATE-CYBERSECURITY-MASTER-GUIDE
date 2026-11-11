# External URL Audit — November 11, 2026

[Full online GitHub Actions run](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/actions/runs/43053899677) · Baseline commit `95c89771b27551c12848cdd5b07b1d215fa3853e` · Completed 2026-11-11 16:05 UTC.

The informational online lychee scan reported **205 failed URL occurrences** (across **148 distinct URLs**); some references recur across documents. It returned this count even though the workflow **job status is green**, because that job deliberately uses `fail: false` to avoid blocking CI on third-party bot protections.

| HTTP Response / Status | Failed occurrences | Interpretation |
|---|---:|---|
| 400 | 2 | Provider/server/network failure or timeout; must be rechecked |
| 401 | 1 | Authentication, bot protection or rate limit; **not** a confirmed dead link |
| 403 | 126 | Authentication, bot protection or rate limit; **not** a confirmed dead link |
| 404 | 17 | Suspected missing page; publisher replacement or removal reviewed |
| 429 | 32 | Authentication, bot protection or rate limit; **not** a confirmed dead link |
| 502 | 3 | Provider/server/network failure or timeout; must be rechecked |
| 503 | 17 | Provider/server/network failure or timeout; must be rechecked |
| 521 | 1 | Provider/server/network failure or timeout; must be rechecked |
| TIMEOUT | 6 | Provider/server/network failure or timeout; must be rechecked |

## Corrections & Exceptions

The [complete individual results and dispositions](EXTERNAL-LINK-AUDIT-2026-11-11.json) include **all 205 failed occurrences**, exact baseline paths and lines, source URLs, outcome and any verified proposed replacement. For the **17 occurrences of 404** (13 distinct URLs), PR #195 corrects or retires the recorded links using official publishers' current destination/documentation where verifiable; examples include Apache Arrow Parquet, GitGuardian API, BinaryEdge, Hex-Rays, osquery releases, NXP PN532 datasheet, WorldDAB, an internal nzyme link, and h8mail. The original dead video is removed rather than replaced with an invented recording.

The separate [HTTP candidate classifications](HTTP-LINKS-CLASSIFICATION.md) distinguish intentional loopback, Docker-only networking, instance metadata, synthetic targets, and captive-portal demonstrations from externally navigated references. The Arduino ESP8266 board-manager URL now uses HTTPS; unverified plaintext vendor downloads have been withdrawn from recommended install examples; a public vulnerable-web-host example now defaults to **an authorized localhost test environment**.

## Still Unverified

- **403/429/401** do not establish that a resource is gone; they may be site protection, quotas, authentication, or geo filtering.
- **502/503/521/timeouts** are transient or environment dependent until independently rechecked.
- A successful URL request cannot prove accuracy of vendor firmware/API/version claims. Current links must be checked in context, especially installers, chipset specifications, and ToS.
- This sweep reports a baseline *before* the link repairs. The PR offline internal link, lint, syntax and fixture checks are separate gates. A clean subsequent online sweep has not yet been established, and the number of unresolved external errors must not be misrepresented as zero.

## Repeatable Follow-up

Run the [Link Check workflow](../.github/workflows/link-check.yml) using its scheduled or manual **external-links** job and save the output. Record exact URL, relevant product/version, source owner, redirect/final host, HTTP status and queried date for each reviewed resource. Continue to distinguish hard 404 from bot-denied or rate-limited access. Do not automate active offensive test endpoints or bypass vendor anti-bot controls.

---

[Documentation Index](README.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) · [Issue #187](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/187)
