# 🧭 Web Application Penetration Testing Methodology

> [!CAUTION]
> **Authorized use only.** This methodology is for authorized penetration testing,
> education, and defensive research. Only test applications you own or have
> **explicit written permission** and a signed scope to assess. See
> [LEGAL.md](../LEGAL.md).

## 🎯 Purpose
A repeatable, phase-by-phase methodology for authorized web application assessments -
from scoping through reporting - aligned with the OWASP Web Security Testing Guide.

## ⚙️ Function
Covers pre-engagement scoping, reconnaissance and mapping, a practical Burp Suite
workflow, configuration/authentication/authorization/input/business-logic testing,
API and GraphQL testing, and reporting. Complements the
[OWASP Top 10 deep-dive](owasp-top-10.md), which details the individual risk classes.

## 🏆 Goal
Enable a tester to run a consistent, thorough web assessment that maps findings to
OWASP/CWE with reproducible evidence and actionable remediation.

## 📋 When to Use
- Executing an authorized web application or API penetration test
- Standardizing a team's web testing workflow and tooling
- Preparing a scoped methodology for a client engagement

---

## 📋 Table of Contents

- [Phase 0: Scoping & Rules of Engagement](#phase-0-scoping--rules-of-engagement)
- [Phase 1: Reconnaissance & Mapping](#phase-1-reconnaissance--mapping)
- [Phase 2: Burp Suite Workflow](#phase-2-burp-suite-workflow)
- [Phase 3: Configuration & Deployment Testing](#phase-3-configuration--deployment-testing)
- [Phase 4: Authentication & Session Testing](#phase-4-authentication--session-testing)
- [Phase 5: Authorization Testing](#phase-5-authorization-testing)
- [Phase 6: Input & Injection Testing](#phase-6-input--injection-testing)
- [Phase 7: Business Logic Testing](#phase-7-business-logic-testing)
- [Phase 8: API & GraphQL Testing](#phase-8-api--graphql-testing)
- [Phase 9: Reporting](#phase-9-reporting)
- [Tooling Reference](#-tooling-reference)
- [Resources](#-resources)

---

## Phase 0: Scoping & Rules of Engagement

Before any traffic is sent:

- Confirm **written authorization**, in-scope hosts/domains, and excluded targets.
- Agree testing windows, rate limits, and whether destructive tests (e.g. DoS,
  mass data modification) are permitted (usually **not**).
- Identify test accounts (ideally two per role for access-control testing).
- Establish an emergency contact and a stop condition.
- Record everything - scope defines what is legal to touch. See
  [LEGAL.md](../LEGAL.md) and the [OSINT Playbook](../OSINT/Playbook/README.md)
  for engagement-documentation patterns.

---

## Phase 1: Reconnaissance & Mapping

Build a complete picture of the application before testing it.

- **Passive:** technology fingerprinting (Wappalyzer, response headers), subdomain
  and content discovery, JS review for endpoints and secrets. See
  [OSINT/scripts/Domain_IP_Recon.md](../OSINT/scripts/Domain_IP_Recon.md).
- **Active:** spider/crawl the app, enumerate directories and parameters
  (`ffuf`, `feroxbuster`), map every role's reachable functionality.
- **Output:** an endpoint/parameter inventory and a per-role functionality map -
  the input to every later phase.

```bash
# Content discovery (authorized scope only)
ffuf -u https://TARGET/FUZZ -w wordlist.txt -mc 200,204,301,302,401,403
feroxbuster -u https://TARGET -w wordlist.txt

# Passive tech/endpoint hints
curl -sI https://TARGET            # headers: server, framework, security headers
```

---

## Phase 2: Burp Suite Workflow

Burp Suite (Community or Professional) is the core interception proxy.

1. **Proxy setup:** route the browser through Burp; install Burp's CA cert for TLS.
2. **Target scope:** set scope to in-scope hosts so tooling never strays.
3. **Crawl & map:** browse the app to populate the site map; review every request.
4. **Repeater:** manually manipulate individual requests to probe behavior.
5. **Intruder:** automate payload injection (fuzzing, brute force) within scope.
6. **Decoder / Comparer:** encode/decode data and diff responses.
7. **Extensions (BApp Store):** *Autorize*/*Auth Analyzer* (access control),
   *Logger++*, *JWT Editor*, *Param Miner*, *Active Scan++*.
8. **Scanner (Pro):** automated scanning to complement - not replace - manual testing.

> [!TIP]
> Automated scanners find the easy issues; access-control and business-logic flaws
> almost always require manual testing with two accounts and an understanding of the
> app's intent.

---

## Phase 3: Configuration & Deployment Testing

Maps to [A02 Security Misconfiguration](owasp-top-10.md#a02-security-misconfiguration)
and [A04 Cryptographic Failures](owasp-top-10.md#a04-cryptographic-failures).

- TLS configuration and certificate validity; HSTS.
- Security headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, frame options.
- Exposed files: `.git/`, backups, `/actuator`, `.env`, source maps, admin consoles.
- CORS policy (test with a rogue `Origin`); cookie flags (`HttpOnly`, `Secure`, `SameSite`).
- Default credentials on any administrative surface.

---

## Phase 4: Authentication & Session Testing

Maps to [A07 Authentication Failures](owasp-top-10.md#a07-authentication-failures).

- Login: rate limiting / lockout, username enumeration, credential stuffing exposure.
- Password reset and MFA flows for bypasses and information leaks.
- Session lifecycle: fixation, rotation on privilege change, invalidation on logout,
  idle/absolute expiry.
- Tokens/JWT: validate `alg` and signature server-side; check for `alg:none`, weak
  secrets, missing expiry, and sensitive claims.

---

## Phase 5: Authorization Testing

Maps to [A01 Broken Access Control](owasp-top-10.md#a01-broken-access-control) - the
highest-prevalence risk, and the phase automation misses most.

- **Horizontal:** with two same-role accounts, replay each user's requests as the
  other; increment/swap object identifiers (IDOR).
- **Vertical:** attempt admin/privileged functionality as a low-privileged user;
  request privileged endpoints directly (forced browsing).
- **Method/param tampering:** change HTTP verbs, toggle role parameters, remove
  authorization headers.
- Use Burp *Autorize*/*Auth Analyzer* to systematize the two-account replay.

---

## Phase 6: Input & Injection Testing

Maps to [A05 Injection](owasp-top-10.md#a05-injection).

- Fuzz every input surface (query/body/path/headers/JSON) with context-specific
  payloads; observe reflected, stored, and DOM contexts for XSS.
- SQL/NoSQL injection: confirm manually, then `sqlmap` within scope.
- Command and template injection (SSTI); LDAP/XPath where applicable.
- File upload: type/content validation, path traversal, dangerous extensions.

```bash
# SQL injection confirmation (authorized scope only)
sqlmap -u "https://TARGET/item?id=1" --batch --risk=1 --level=1
# note: coordinate risk/level and data-modifying options with the ROE
```

---

## Phase 7: Business Logic Testing

Maps to [A06 Insecure Design](owasp-top-10.md#a06-insecure-design). These flaws
abuse legitimate functionality and require understanding the app's intent.

- Workflow bypasses (skip steps, replay, out-of-order requests).
- Value/quantity tampering (negative amounts, price manipulation, coupon reuse).
- Missing anti-automation on sensitive actions (OTP, reset, checkout).
- Race conditions on state-changing operations (concurrent requests).

---

## Phase 8: API & GraphQL Testing

APIs are a major modern attack surface (see the OWASP API Security Top 10).

- **REST:** enumerate endpoints (Swagger/OpenAPI if exposed); test object- and
  function-level authorization (BOLA/BFLA - the API analogue of A01); mass
  assignment; excessive data exposure; rate limiting.
- **GraphQL:** attempt introspection to map the schema; test authorization per
  resolver; watch for nested-query/batching abuse (DoS) and injection via arguments.
- Tooling: Burp, Postman, `graphql-cog`/`clairvoyance` (introspection), and the
  [OWASP API Security Top 10](https://owasp.org/API-Security/).

---

## Phase 9: Reporting

- Each finding: title, severity (with CVSS where useful), affected endpoint,
  reproducible steps/evidence, impact, and **remediation**.
- Map findings to [OWASP Top 10](owasp-top-10.md) categories and CWE IDs.
- Separate confirmed vulnerabilities from informational/hardening observations.
- Provide an executive summary and a prioritized remediation roadmap.

---

## 🛠️ Tooling Reference

| Tool | Role |
|------|------|
| [Burp Suite](https://portswigger.net/burp) | Interception proxy, repeater, intruder, scanner |
| [OWASP ZAP](https://www.zaproxy.org/) | Open-source proxy/scanner alternative |
| [ffuf](https://github.com/ffuf/ffuf) / [feroxbuster](https://github.com/epi052/feroxbuster) | Content & parameter discovery |
| [sqlmap](https://sqlmap.org/) | SQL injection confirmation/exploitation |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |
| [Postman](https://www.postman.com/) | API request crafting |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | JWT analysis and attacks |

---

## 📚 Resources

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - the definitive methodology
- [OWASP API Security Top 10](https://owasp.org/API-Security/) - API-specific risks
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) - verification requirements
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - hands-on labs

---

## Related Files
- [README.md](README.md) - Web Application Security section index
- [owasp-top-10.md](owasp-top-10.md) - the risk classes this methodology tests for
- [../OSINT/scripts/Domain_IP_Recon.md](../OSINT/scripts/Domain_IP_Recon.md) - recon that feeds Phase 1
- [../IncidentResponse/SIEM/README.md](../IncidentResponse/SIEM/README.md) - the defensive/detection side
