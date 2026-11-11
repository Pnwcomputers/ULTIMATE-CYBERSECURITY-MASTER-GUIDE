# Empty Tables, Placeholders & Missing Instructions

_Review baseline: November 11, 2026 · The offline audit reported roughly 166 empty-table candidates. Those are **candidates**, not 166 verified defects. This guide defines dispositions and provides operator instructions, not fictional data._

## Triage For Each Candidate

| Classification | Real Meaning | Required Treatment |
|---|---|---|
| Operator-fill template | Blank approval, date, version, scope, asset, owner, report score or contact field | Explain who fills it in, when, validation and secure storage; display “Not recorded” or “Not tested” in examples, not an invented value |
| Historical unknown | Prior environment, earlier test, author or status not preserved in available records | Write “Historical value not recorded” and describe evidence needed; do not reconstruct history from assumptions |
| Source-backed reference gap | Public configuration/version/compatibility fact genuinely omitted | Find dated vendor documentation, identify specific product/firmware release and cite source before entering the field |
| Missing feature/procedure | Text describes a working menu, worker, export or automation absent from source | Implement it with tests, **or** explicitly label unavailable with a precise next step; do not mark deployed |
| Parser false positive | Empty cell created by escaped `\|`, inline code, separator or non-table prose | Improve scanner/ignore legitimate syntax rather than changing correct source |
| Unresolved | Context/source unknown and no client/hardware access | Leave a review candidate linked to file/line; do not close it or invent operational evidence |

## Instructions For Intentional Blanks

**Assessment and consent forms:** engagement owner supplies legal entity, scoped IPs/hostnames, dates, authorized methods, excluded assets, escalation contacts and sign-off **before** any active test. Blank scope is not consent. Store signed forms and private environment names outside the public repository.

**Detection records:** lab operator supplies test ID, expected alert and field mapping, positive and negative fixtures, observed data, rule/SIEM version, false-positive tally, time and approval. Enter **“Not tested”** when telemetry is unavailable. See [Lab Matrix](LAB-VERIFICATION-MATRIX.md).

**Security remediation plans:** where historical base SHAs, ownership or test records are absent, use **“Historical value not recorded”**; assign fresh verification owner/date only after actual validation. See [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md).

**Configuration examples:** placeholders such as `YOUR_KEY`, `HOST_IP`, `example.com`, `CVE-YYYY-NNNN` remain deliberately incomplete. Explain substitution, bounds, privileges, secure storage and expected errors; do not use real API keys or customer targets in examples.

## Machine-Readable Review Queue

Run from a checked-out repository:

~~~bash
python3 -B tools/maintenance_candidate_triage.py --root . --output /tmp/markdown-triage.json
python3 -B tools/repository_quality_audit.py --strict-syntax
python3 -B -m unittest discover -s tools/tests -v
~~~

The report tags candidate HTML/code-table contexts, HTTP examples and missing cells by path/line; the automated classification is **heuristic**. A reviewer must make the final determination and link each correction to a scoped PR. We deliberately do not fill every historical or client-specific field in bulk.

This guide records a concrete review process and representative dispositions for [issue #189](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/189), but **issue closure requires the full candidate list to be reviewed individually** and CI to confirm any actual corrections.

---

[Documentation Index](README.md) · [Maintenance Operations](REPOSITORY-MAINTENANCE-OPERATIONS.md)
