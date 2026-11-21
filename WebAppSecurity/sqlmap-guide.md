# sqlmap: SQL Injection Assessment & Defensive Validation

_Upstream manual reviewed: 2026-11-21. No live target was tested._

> [!CAUTION]
> **Authorized use only.** sqlmap can send many requests, alter application state or expose database contents. This guide limits exercises to a synthetic local training application and detection-focused use. Do not retrieve third-party data or attempt OS-level access. See [Legal Notice](../LEGAL.md).

## Overview

[sqlmap](https://sqlmap.org/) is an automated SQL injection (SQLi) testing framework. Its input is an HTTP request or URL containing candidate parameters, and it probes whether database-related input handling is unsafe. Automated hits require manual verification and context. A scanner result does **not** automatically prove data compromise, privileges or exploitability.

## Prerequisites & Lab Architecture

Use a deliberately vulnerable local training environment with synthetic records, a disposable database, no real users, no outbound access and reversible VM/container state. Turn on HTTP access logs, application exception logs and database statement/audit logs where available. Confirm a signed testing scope, even within organizational networks.

Install via the [official GitHub repository](https://github.com/sqlmapproject/sqlmap) or trusted platform package. If using the upstream checkout, inspect dependencies and run:

```bash
python3 sqlmap.py --version
python3 sqlmap.py -h
```

The executable may be called `sqlmap` on a packaged installation; adjust examples accordingly.

## Detection-Oriented Workflow

| Step | Action | Expected Evidence |
|---|---|---|
| Baseline | Inspect an application request through a proxy | Method, path, parameter, normal response |
| Isolate | Choose a single lab query parameter | Clear test scope and synthetic record |
| Probe | Use the lowest reasonable test settings | Request trace, affected parameter, tool uncertainty |
| Confirm | Compare request/response against application & DB logs | Reproducible variation without sensitive extraction |
| Repair | Use parameterized queries and least privilege | Changed query construction and test coverage |
| Retest | Repeat a bounded equivalent request | Prior behavior no longer reproducible |

### Local Test Example

```bash
# Local training service only; /items?id=1 is an illustrative fixture.
# It must be provided by your own intentionally vulnerable lab.
sqlmap -u "http://127.0.0.1:8000/items?id=1" -p id \
  --batch --level=1 --risk=1 --threads=1 --delay=0.5
```

The example remains an **active SQLi probe**. Review request logs and stop if the app resets, errors unexpectedly or changes data. Low risk/level settings reduce the test set; they do not guarantee harmlessness.

### Supplying a Captured Request

For an application that uses POST, headers or cookies, save a **sanitized** HTTP request captured from a local lab into `lab-request.txt`, removing production tokens and personally identifiable information. Then consult `sqlmap -hh` and the official `-r` option documentation. Never commit actual cookies, session tokens or query dumps.

## Avoid High-Impact Options

Do not enable database dumping, schema exfiltration, filesystem access, shell functionality or large concurrency as part of routine discovery. Consider dynamic pages, CSRF tokens, WAF interference, caching, redirects and timing-based probes when interpreting a result.

## Fixing SQL Injection

Use bound parameters/prepared statements for data values, allow-list identifiers that cannot be parameterized, restrict database privileges, avoid dynamic SQL concatenation and validate authorization separately. A WAF can reduce exposure but does not repair unsafe query construction.

### Secure Query Pattern (Python / SQLite)

```python
# The parameter is bound as data, not appended to SQL source.
cursor.execute("SELECT name FROM items WHERE id = ?", (item_id,))
```

For each finding, capture the vulnerable endpoint, parameter, request/response evidence (sanitized), environment, database error class, impact hypothesis, fix and reproducible retest result.

## What Defenders Can Monitor

HTTP anomaly bursts, atypical SQL error patterns, DB audit exceptions and unexpected spikes in query latency may justify investigation. SQLmap can use custom headers and randomization, so a single User-Agent signature is unreliable. Prefer request+identity+DB correlation and alert testing against benign fixtures.

## Further Reading & References

- [Web App Security Methodology](./methodology.md) — manual-first assessment workflow
- [OWASP ASVS/WSTG & Nuclei](./owasp-assessment-and-nuclei.md) — verification & evidence requirements
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Official sqlmap Manual](https://github.com/sqlmapproject/sqlmap/wiki/Usage) & [Project](https://github.com/sqlmapproject/sqlmap)

---

[Web Application Security Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
