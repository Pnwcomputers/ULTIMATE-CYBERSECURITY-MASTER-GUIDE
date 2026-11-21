# THC Hydra: Authentication Security & Controlled Credential Auditing

_Upstream reference reviewed: 2026-11-21. Commands were not executed against a service._

> [!CAUTION]
> **Authorized use only.** Online authentication testing can lock accounts, trigger incidents or deny service. Use **dedicated lab accounts and a strict attempt budget**. Do not perform credential stuffing, password spraying or unapproved enumeration. See [Legal Notice](../LEGAL.md).

## What Hydra Does

[THC Hydra](https://github.com/vanhauser-thc/thc-hydra) is a network-login testing utility supporting numerous authentication protocols. It tests supplied credential candidates against network services; it **does not recover stored password hashes**, bypass multi-factor authentication or establish the legitimacy of a discovered account.

| Concept | Meaning | Defensive Question |
|---|---|---|
| Network protocol module | Protocol-specific login behavior | Is password authentication allowed or properly protected? |
| Candidate credential | User/password pair in a controlled test | Do lockout & throttling function? |
| Concurrent tasks | Parallel login attempts | Would rate limits / IDS detect abnormal volumes? |
| Failed-login telemetry | Server, IAM, MFA & network logs | Can attempts be correlated by user, source & time? |

## Installation & Local Verification

Prefer a distribution-maintained package or review the [upstream README](https://github.com/vanhauser-thc/thc-hydra) and manual before a source build. Confirm the installed protocol modules and syntax rather than assuming every build contains the same features.

```bash
hydra -h
hydra -U ssh
```

These commands display help without contacting another host. Module support, TLS behavior & option names vary with the installed build.

## Safe Lab Design

1. Use an isolated SSH or HTTP authentication fixture, **one disposable synthetic account**, a known test password and separate logs.
2. Specify maximum attempts, allowed source IP and test window in writing. Check lockout policies before testing.
3. Establish a baseline of one normal success and one intentionally failed login through the application's own client, where feasible.
4. If online testing is approved, begin with **one** non-production attempt, stop immediately on a lockout or alert, and do not automatically scale.
5. Review server-side auth logs, source IP, username, timestamp, rate-limit counters, MFA/IdP events and alert latency.

### Single-Candidate Lab Illustration

```bash
# Example ONLY: run if 127.0.0.1 hosts your disposable SSH lab,
# the synthetic account exists and this one attempt is authorized.
hydra -l training_user -p definitely-wrong -t 1 -f ssh://127.0.0.1
```

This is not a production audit recipe. Do not apply password lists or large candidate sets to customer accounts without separately scoped approval, owner-approved lockout controls and a recovery plan.

## Evidence Interpretation

A reported accepted credential must be independently validated within the approved lab and could reflect test misconfiguration or protocol-specific behavior. A failed attempt does not prove a robust password policy. Consider passwordless sign-in, MFA, SSO enforcement, account lockout, adaptive throttling, generic error messages and notification policies.

| Observable | Detection Opportunity | False-Positive Caveat |
|---|---|---|
| Repeated failures for one user | Authentication log grouping | User typo or stale credential in a client |
| Failures across many users | Password-spray heuristic | Shared proxy or benign migration |
| Successful login after failures | Sequence correlation | A legitimate user recovering access |
| Burst from one source | Rate limiting & alerting | Authorized health checks / QA tests |

## Defensive Hardening & Remediation

- Enforce MFA or phishing-resistant passkeys where supported; disallow legacy/password-only paths.
- Limit guessing attempts at identity and application layers, while avoiding predictable user lockouts as a denial-of-service vector.
- Alert on distributed source patterns, impossible travel, suspicious service accounts and repeated MFA challenges.
- Restrict remote administration to approved networks, monitor SSH authentication and disable unused protocols.
- Store no real passwords in shell histories, tickets or public repository artifacts.

## Troubleshooting & Limits

Hydra results depend on protocol implementation, redirects, response interpretation, network latency and account state. Avoid concluding that credentials are correct without an independent server-side audit. For web-login forms, custom error strings and CSRF flows complicate interpretation; prefer instrumented application tests to high-volume attempts.

## Related Guides & Sources

- [Credential Access Checklist](../Checklists/Credential-Access.md) — awareness & controls
- [Web Application Assessment Methodology](../WebAppSecurity/methodology.md) — session & login controls
- [Purple Team Detection Validation](../PlayBooks/purple-team-detection-validation.md) — log/alert evidence
- [Official THC Hydra Repository](https://github.com/vanhauser-thc/thc-hydra) & [Manual Page Source](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.1)

---

[Tradecraft Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
