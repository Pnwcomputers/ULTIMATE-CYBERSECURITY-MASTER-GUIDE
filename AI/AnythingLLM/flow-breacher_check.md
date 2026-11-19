# Breach Exposure Check AgentFlow

## Purpose

Use Have I Been Pwned (HIBP) breach metadata to help an organization or account owner assess exposure. Run checks only for an account owner, a verified domain administrator, or an assessment expressly authorized in writing.

HIBP reports whether an address appears in known breach records and which data classes were involved. Its account and paste endpoints do **not** return stolen passwords, hashes, or dump contents. A match does not prove that an account is currently compromised or that a password is reusable.

## Scope and privacy

- Check only addresses covered by documented consent or an approved organizational scope.
- Domain searches require HIBP domain verification and an API key with the appropriate access.
- Treat queried addresses and results as sensitive personal data. Minimize what enters prompts, logs, and reports; follow retention policy.
- Never test credentials, build a password-spraying list, or ask the model to infer passwords from breach metadata.
- Store API keys in the platform’s secret store. Do not put secrets in URLs, prompts, flow variables, or exported flow definitions.
- Review HIBP’s current [API documentation](https://haveibeenpwned.com/scalar/) for authentication, access, response fields, and rate limits.

## Flow inputs and outputs

| Variable | Description |
|---|---|
| `email_address` | One authorized email address, URL-encoded by the connector |
| `breach_metadata` | HIBP breach metadata response |
| `paste_metadata` | Optional HIBP paste metadata response |
| `summary` | Minimized analyst summary and owner-focused next steps |

Do not use one input field interchangeably for an email address and a domain. For verified-domain monitoring, configure the separate `breacheddomain/{domain}` operation and verify the domain through HIBP first.

## Suggested flow

### 1. HIBP account breach lookup

Configure the HTTP/API block to call:

```text
GET https://haveibeenpwned.com/api/v3/breachedaccount/{URL_ENCODED_EMAIL}
```

Use the `hibp-api-key` header and a descriptive `user-agent` header, with values supplied by the approved secret manager or connector settings. Do not paste a real key into this document. A no-match response may be HTTP 404; handle that as “no matching breach returned,” not as proof that the address is safe.

### 2. Optional paste metadata lookup

If the authorized workflow needs this check and the API subscription permits it, call:

```text
GET https://haveibeenpwned.com/api/v3/pasteaccount/{URL_ENCODED_EMAIL}
```

This returns paste metadata, not paste contents or credentials. Omit this step if the result is not needed for the stated purpose.

### 3. Summarize without exposing raw personal data

Give the model only the fields needed for the report, such as breach name, breach date, and listed data classes. Exclude account addresses where practical, and never include credentials or raw breach material.

Prompt:

```text
Summarize the supplied HIBP metadata for the authorized account owner.
Report only the breach name, breach date, and data classes explicitly present.
Do not infer passwords, password reuse, account takeover, identity, or user behavior.
State that a result is historical exposure metadata and does not establish current compromise.
If the input is empty or malformed, say that the lookup result is unavailable.
Recommend owner-directed actions: use a unique password, enable MFA or passkeys,
review account sign-in activity, and follow the organization’s incident process
if there is independent evidence of compromise.
```

## Example report

```text
Lookup: completed for an authorized account (address omitted)
Result: one matching breach record
Breach: Example Service (date reported by HIBP)
Data classes: email addresses, usernames
Interpretation: historical exposure metadata; no password or current account access was assessed.
Next steps: account owner should use a unique password and MFA/passkeys; investigate further only if separate evidence warrants it.
```

## Operational guidance

- Verify the account or domain is in scope before querying.
- Record the authorization basis, lookup date, source, and minimal result needed for the report.
- A missing result is not proof that an account was never exposed; HIBP coverage is not exhaustive.
- Do not mandate an organization-wide password reset solely from breach metadata. Follow the incident response process and assess current risk using approved identity-provider signals.
- If accidental sensitive data enters the flow, stop processing, restrict access, and follow the organization’s data-handling procedure.

## Official references

- [HIBP API reference](https://haveibeenpwned.com/scalar/)
- [HIBP API key](https://haveibeenpwned.com/API/Key)
- [HIBP domain search](https://haveibeenpwned.com/DomainSearch)

## Related flows

- [EmailOSINT](flow-email_osint.md) — consent-based account security checks
- [CompanyOSINT](flow-company_osint.md) — organization-level public information
