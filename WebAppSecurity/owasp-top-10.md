# 🔟 OWASP Top 10 - Deep Dive

> [!CAUTION]
> **Authorized use only.** The exploitation techniques below are for authorized
> testing, education, and defensive research. Testing systems you do not own or
> lack explicit written permission to assess is illegal. See [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
A working reference for the OWASP Top 10 web application risks - each category
covering what it is, how it is exploited, how to test for it, and how to defend
against it.

## ⚙️ Function
Walks all ten categories of the **OWASP Top 10:2025** (Release Candidate), with a
mapping back to the stable **2021** list. Each entry pairs offensive testing notes
with defensive controls and links to the relevant OWASP Cheat Sheet.

## 🏆 Goal
Let a reader look up any Top 10 category and immediately know how it manifests,
how to test for it in an authorized engagement, and what remediation to recommend.

## 📋 When to Use
- Testing a web application against a specific risk class
- Writing a finding and needing the OWASP/CWE mapping plus remediation guidance
- Reviewing an application or design defensively against the current risk list

---

## 📋 Table of Contents

- [Version Note: 2025 RC vs 2021](#-version-note-2025-rc-vs-2021)
- [A01: Broken Access Control](#a01-broken-access-control)
- [A02: Security Misconfiguration](#a02-security-misconfiguration)
- [A03: Software Supply Chain Failures](#a03-software-supply-chain-failures)
- [A04: Cryptographic Failures](#a04-cryptographic-failures)
- [A05: Injection](#a05-injection)
- [A06: Insecure Design](#a06-insecure-design)
- [A07: Authentication Failures](#a07-authentication-failures)
- [A08: Software or Data Integrity Failures](#a08-software-or-data-integrity-failures)
- [A09: Security Logging and Alerting Failures](#a09-security-logging-and-alerting-failures)
- [A10: Mishandling of Exceptional Conditions](#a10-mishandling-of-exceptional-conditions)
- [2021 to 2025 Mapping](#2021-to-2025-mapping)
- [Resources](#-resources)

---

## 🗓️ Version Note: 2025 RC vs 2021

At the time of writing, **OWASP Top 10:2025 is a Release Candidate** and
**2021 is the last finalized edition**. This guide follows the 2025 ordering and
category names (verified against <https://owasp.org/Top10/2025/>) because it
reflects current data, and provides a [2021→2025 mapping](#2021-to-2025-mapping)
so findings written against either edition line up. Confirm the current status at
<https://owasp.org/Top10/> before citing an edition in a formal report.

Two structural changes in 2025 are worth noting:

- **A03: Software Supply Chain Failures** broadens 2021's "Vulnerable and Outdated
  Components" to cover the whole dependency/build/distribution chain.
- **A10: Mishandling of Exceptional Conditions** is new, covering error-handling
  and fail-open logic (SSRF from 2021's A10 folds into Broken Access Control /
  Server-Side Request areas).

---

## A01: Broken Access Control

The most prevalent risk in both 2021 and 2025. The application fails to enforce
what an authenticated user is allowed to do.

- **How it is exploited:** changing an identifier to access another user's data
  (IDOR / horizontal), reaching admin functionality as a normal user (vertical),
  forced browsing to unlinked endpoints, or tampering with a JWT/cookie role claim.
- **How to test:** with two accounts of different privilege, replay each request
  as the other (Burp's *Autorize*/*Auth Analyzer* extensions help); enumerate
  object IDs; request admin routes directly; verify server-side enforcement rather
  than hidden-in-the-UI controls.
- **How to defend:** deny by default; enforce authorization **server-side** on
  every request against the authenticated principal; use opaque/unguessable
  references or ownership checks; centralize access-control logic; log failures.
- **CWE:** CWE-284, CWE-639, CWE-862. **Cheat sheet:** [Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

---

## A02: Security Misconfiguration

Insecure defaults, incomplete hardening, verbose errors, and unnecessary features.

- **How it is exploited:** default/administrative credentials, exposed admin
  consoles or `.git`/backup files, missing security headers, directory listing,
  overly permissive CORS, verbose stack traces revealing internals.
- **How to test:** enumerate exposed paths and files; review response headers
  (CSP, HSTS, `X-Content-Type-Options`); check CORS with a rogue `Origin`; probe
  default credentials on any admin surface; diff against a hardening baseline.
- **How to defend:** a repeatable hardening process; remove unused features and
  sample apps; set security headers; suppress verbose errors in production; keep
  environments consistent; automate configuration checks.
- **CWE:** CWE-16, CWE-548. **Cheat sheet:** [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/).

---

## A03: Software Supply Chain Failures

Expanded in 2025 from "Vulnerable and Outdated Components" to the whole chain:
dependencies, build pipelines, and distribution.

- **How it is exploited:** known-vulnerable libraries (n-day), typosquatted or
  compromised packages, poisoned build/CI steps, unsigned artifacts, or a
  compromised update channel (cf. the SolarWinds and `xz`/CVE-2024-3094 cases).
- **How to test:** inventory dependencies (SBOM); run SCA against known-CVE
  databases; check for pinned, integrity-verified dependencies; review CI/CD trust
  boundaries and who can publish artifacts.
- **How to defend:** maintain an SBOM; pin and verify dependencies (hashes/lock
  files); use signed artifacts and provenance (e.g. SLSA, Sigstore); restrict and
  monitor the build pipeline; patch promptly.
- **CWE:** CWE-1104, CWE-1357. **Cheat sheet:** [Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html).

---

## A04: Cryptographic Failures

Weak, misused, or missing cryptography that exposes data in transit or at rest.

- **How it is exploited:** cleartext transport, weak/deprecated ciphers or hashes
  (MD5, SHA-1, ECB), hard-coded or reused keys, missing encryption of sensitive
  data, predictable IVs/nonces, unsalted password hashes.
- **How to test:** check TLS configuration and certificate validity; look for
  sensitive data sent or stored in cleartext; review password storage
  (algorithm/salt); inspect for hard-coded secrets; verify token/randomness quality.
- **How to defend:** enforce TLS (HSTS); use vetted algorithms (AES-GCM,
  ChaCha20-Poly1305; Argon2/bcrypt/scrypt for passwords); manage keys in a KMS/HSM;
  classify data and encrypt sensitive fields; never roll your own crypto.
- **CWE:** CWE-259, CWE-327, CWE-331. **Cheat sheet:** [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

---

## A05: Injection

Untrusted input is interpreted as code or a command. Includes SQL, NoSQL, OS
command, LDAP, and (server-side) template injection, plus cross-site scripting.

- **How it is exploited:** breaking out of a query/command context - `' OR 1=1--`
  (SQLi), `{{7*7}}` (SSTI), backtick/`;` chaining (command injection), or reflected
  /stored/DOM **XSS** injecting script into a page.
- **How to test:** fuzz every input (params, headers, JSON, path) with
  context-specific payloads; use Burp Intruder/Scanner; confirm SQLi with `sqlmap`
  in scope; test XSS across reflected, stored, and DOM sinks.
- **How to defend:** parameterized queries / prepared statements; safe ORMs;
  context-aware output encoding and a strong Content-Security-Policy for XSS;
  allow-list input validation; avoid passing input to shells/interpreters.
- **CWE:** CWE-89, CWE-79, CWE-78, CWE-94. **Cheat sheets:** [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html), [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

---

## A06: Insecure Design

Flaws in the design itself - missing or ineffective controls that no amount of
clean implementation can fix.

- **How it is exploited:** abusing a workflow that was never threat-modeled - e.g.
  no rate limiting on a password-reset or OTP flow, trusting client-side controls,
  or a recovery process that leaks information.
- **How to test:** threat-model the feature; look for missing anti-automation,
  trust-boundary violations, and assumptions the client can break; test negative
  and abuse cases, not just the happy path.
- **How to defend:** threat modeling in design; secure design patterns and
  reference architectures; establish trust boundaries; write abuse/misuse cases and
  test them; apply defense in depth.
- **CWE:** CWE-73, CWE-602, CWE-657. **Cheat sheet:** [Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

---

## A07: Authentication Failures

Weaknesses in confirming identity and managing sessions.

- **How it is exploited:** credential stuffing and brute force (no lockout/rate
  limit), weak password policies, session fixation, exposed or non-expiring session
  tokens, flawed MFA, and weak JWT handling (`alg:none`, weak secret, no expiry).
- **How to test:** probe login for lockout/rate limiting; test session lifecycle
  (fixation, invalidation on logout, rotation); inspect JWTs (algorithm, signature,
  expiry, claims); test password reset and MFA bypasses.
- **How to defend:** rate limiting and lockout; MFA; strong password storage
  (Argon2/bcrypt) and breached-password checks; secure, `HttpOnly`, `SameSite`
  session cookies with rotation and expiry; validate JWT `alg` and signature server-side.
- **CWE:** CWE-287, CWE-384, CWE-613. **Cheat sheet:** [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).

---

## A08: Software or Data Integrity Failures

Code or data trusted without verifying integrity - including insecure
deserialization and unverified updates.

- **How it is exploited:** insecure deserialization leading to RCE, unsigned or
  unverified auto-updates, CI/CD that trusts untrusted input, or client-side
  integrity assumptions (no Subresource Integrity on third-party scripts).
- **How to test:** identify serialized objects crossing trust boundaries; test
  deserialization with known gadget chains (in scope); check update mechanisms for
  signature verification; look for missing SRI on external resources.
- **How to defend:** avoid native deserialization of untrusted data (use data-only
  formats with schema validation); sign and verify updates and artifacts; enforce
  integrity in CI/CD; use Subresource Integrity for third-party scripts.
- **CWE:** CWE-502, CWE-345, CWE-829. **Cheat sheet:** [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html).

---

## A09: Security Logging and Alerting Failures

Insufficient logging, monitoring, and alerting - which lets attacks proceed
undetected. (2021: "Logging and Monitoring Failures".)

- **How it is exploited:** not a direct exploit but an amplifier - failed logins,
  access-control denials, and input-validation failures go unlogged, so intrusions
  are neither detected nor investigable.
- **How to test:** verify security-relevant events are logged (authn/authz
  failures, high-value actions); confirm logs are tamper-resistant and shipped off
  host; check that alerts actually fire on suspicious patterns.
- **How to defend:** log security events with enough context; centralize logs to a
  [SIEM](../IncidentResponse/SIEM/README.md); protect log integrity; define and
  test alerting; align retention with response needs.
- **CWE:** CWE-778, CWE-223. **Cheat sheet:** [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).

---

## A10: Mishandling of Exceptional Conditions

New in 2025: error-handling and edge-case logic that fails insecurely.

- **How it is exploited:** fail-open logic (an error path that grants access),
  inconsistent state after a partial failure, information disclosure through error
  messages, or race conditions in exceptional paths.
- **How to test:** force error and edge conditions (malformed input, timeouts,
  concurrent requests); observe whether failures fail **open** or closed; check
  error responses for leaked internals; test race conditions on state-changing ops.
- **How to defend:** fail closed by default; handle errors explicitly and
  uniformly; avoid leaking internals in messages; make state changes atomic; test
  exceptional paths as first-class scenarios.
- **CWE:** CWE-755, CWE-209, CWE-362. **Cheat sheet:** [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).

---

## 2021 to 2025 Mapping

| 2021 | 2025 |
|------|------|
| A01 Broken Access Control | A01 Broken Access Control |
| A02 Cryptographic Failures | A04 Cryptographic Failures |
| A03 Injection | A05 Injection |
| A04 Insecure Design | A06 Insecure Design |
| A05 Security Misconfiguration | A02 Security Misconfiguration |
| A06 Vulnerable and Outdated Components | A03 Software Supply Chain Failures (expanded) |
| A07 Identification and Authentication Failures | A07 Authentication Failures |
| A08 Software and Data Integrity Failures | A08 Software or Data Integrity Failures |
| A09 Security Logging and Monitoring Failures | A09 Security Logging and Alerting Failures |
| A10 Server-Side Request Forgery (SSRF) | folded into A01 / server-side request areas |
| *(new in 2025)* | A10 Mishandling of Exceptional Conditions |

---

## 📚 Resources

- [OWASP Top 10](https://owasp.org/Top10/) - authoritative source (check current edition)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - how to test each category
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) - defensive guidance per topic
- [MITRE CWE](https://cwe.mitre.org/) - weakness identifiers used above
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - hands-on labs per vulnerability class

---

## Related Files
- [README.md](README.md) - Web Application Security section index
- [methodology.md](methodology.md) - the assessment workflow that applies these categories
- [../GLOSSARY.md](../GLOSSARY.md) - Acronyms (OWASP, CWE, SSRF, XSS, SSTI…)
