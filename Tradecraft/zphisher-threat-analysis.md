# Zphisher: Phishing Framework Analysis, Detection & Safe Awareness Labs

_Upstream project & repository metadata reviewed: 2026-11-21. No phishing page was deployed._

> [!CAUTION]
> **Defensive research only.** Zphisher is designed to generate imitation login pages and can capture credentials. Do not deploy real brand impersonation, distribute phishing links or collect usernames, passwords, session tokens or visitor IPs. Use approved, non-deceptive synthetic training instead. See [Legal Notice](../LEGAL.md).

## Overview & Threat Model

[Zphisher](https://github.com/htr-tech/zphisher) is an automated phishing framework with prebuilt page templates and hosting/tunneling integration. Its existence is useful to understand because attackers can shorten the time between an impersonated page and credential collection. This guide documents how to **recognize, investigate and defend against** such campaigns; it intentionally does not provide operational phishing instructions.

The upstream README describes login-page templates, URL masking and tunnel support. These capabilities make source authentication, credential protection and incident triage more important. Upstream documentation is **not a trust endorsement**, and author disclaimers do not replace authorization.

## How a Credential-Phishing Event Unfolds

| Phase | Observed Behavior | Defensible Evidence |
|---|---|---|
| Lure | Email, SMS or social post asks a user to sign in urgently | Message headers, sender domain, URL, timestamp |
| Redirect | Link opens a lookalike login page | Redirect chain, resolved host, TLS certificate metadata |
| Input request | Form asks for credentials or other secrets | Sanitized screenshot, page fields, DOM notes |
| Exfiltration attempt | Browser sends entered data to another endpoint | Proxy/network flow logs; **never submit real credentials** |
| Follow-on access | Stolen credentials may be used elsewhere | Identity provider sign-ins, device/IP anomalies, MFA logs |

A lookalike page alone does not establish that Zphisher specifically generated it. Avoid attribution based only on superficial HTML, URL structure or an indicator copied into a template.

## Safe Awareness Exercise (No Credential Collection)

1. Create a **clearly identified, fictitious** web page in an isolated lab or static document, not a real login lookalike.
2. Show participants a synthetic message and ask them to inspect the sender, URL hostname and password-manager behavior.
3. Provide a button labeled "Report Suspicious Message" with no input fields for passwords or tokens.
4. Record only voluntary training outcomes in aggregate; no real names, account identifiers or IP-based tracking.
5. Debrief with phishing-resistant MFA, verified sign-in bookmarks and the organization's reporting process.

Avoid public hosting, brand impersonation, cloaked redirects, tunnel deployment or credential-collection simulation. The educational objective is user decision-making and defender telemetry, not testing whether someone can be tricked into submitting a password.

## Investigation Playbook

- **Preserve:** Export the original message with headers; record UTC and screenshot before links are removed.
- **Analyze offline:** Extract URLs as text and inspect their domains through approved threat-intelligence services. Avoid submitting private customer URLs to public tools without permission.
- **Correlate:** Check email security logs, DNS/proxy logs, IdP sign-in attempts and suspicious MFA events.
- **Contain:** Block confirmed malicious domains/URLs through approved controls and report to the hosting provider.
- **Recover:** If credentials were submitted, revoke active sessions, reset affected secrets from a clean device and review account changes.
- **Retest:** Use synthetic messages or replayed log fixtures to confirm alerts without sending another live phishing lure.

## Detection & Defensive Controls

| Signal | Suggested Control | Caveat |
|---|---|---|
| Newly observed lookalike domain | Brand monitoring & security gateway | Legitimate test domains may resemble a brand |
| Untrusted login redirect | Browser isolation and URL protection | Redirect chains are not inherently malicious |
| Login from anomalous device or region | Conditional access / IdP alerting | VPNs and travel can explain changes |
| Unexpected MFA prompt after suspicious email | User reporting & helpdesk escalation | May reflect normal sign-in |
| Reused password in a fraudulent form | Passkeys, FIDO2 & password managers | MFA is not equally phishing resistant |

## Reporting Template

Document source message, timestamps, normalized URL/hostname, screenshots with secrets removed, telemetry IDs, confidence, impacted users (stored privately), containment actions and analyst attribution caveats. Never publish live phishing URLs that may still collect credentials.

## Further Reading & Sources

- [Phishing Analysis SOP](../PlayBooks/sop_phishing_analysis.md) — investigation & response
- [Security Keys, FIDO2 & Passkeys](../Cryptography/security-keys-passkeys.md) — phishing-resistant authentication
- [Incident Response](../IncidentResponse/README.md) — containment & recovery
- [Zphisher Upstream](https://github.com/htr-tech/zphisher) — source for **threat analysis**, not a deployment recommendation
- [CISA Phishing Guidance](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)

---

[Tradecraft Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
