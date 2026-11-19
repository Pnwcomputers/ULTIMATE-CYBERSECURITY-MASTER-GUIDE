# Email Account Exposure Review

## Purpose

This flow supports an account owner or an authorized security team reviewing whether an email address appears in HIBP breach metadata. It is not a people-profiling or credential-discovery workflow.

## Authorized use and privacy

Use only an address belonging to the requester or one covered by written organizational authorization. Keep results private, minimize retention, and do not submit addresses to public search engines or unrelated data brokers. Do not infer identity or collect personal details, social profiles, relationships, location, or psychological traits.

A HIBP breach match describes historical records and listed data classes. It does not return passwords, prove current compromise, or establish password reuse. Do not use results for password testing, spraying, account enumeration, pretexting, or targeting.

## Flow input

| Variable | Description |
|---|---|
| `email_address` | One consented or explicitly authorized address |
| `breach_metadata` | Minimal HIBP response fields needed for the owner report |
| `review_summary` | Minimized result and account-owner guidance |

Use an email-only lookup. Do not pass a domain to the account endpoint; domain search is a separate HIBP operation requiring domain verification and the appropriate API access.

## Step 1: Query HIBP

Configure the connector to call:

```text
GET https://haveibeenpwned.com/api/v3/breachedaccount/{URL_ENCODED_EMAIL}
```

Send the API key in the `hibp-api-key` header and a descriptive `user-agent` header. Configure both through the approved secret manager or connector settings. Never place a key in the URL, prompt, exported flow, or source control.

Review the current [HIBP API reference](https://haveibeenpwned.com/scalar/) for authentication, response fields, subscription requirements, and rate limits. Do not replace the API with scraping or another source unless that source has been separately approved and its privacy impact assessed.

## Step 2: Create a minimized summary

Pass only the necessary metadata to the model. Exclude the address if possible. Use this instruction:

```text
Summarize the supplied HIBP breach metadata for the authorized account owner.
List only breach names, reported dates, and data classes present in the input.
Do not infer passwords, password reuse, current compromise, identity, behavior,
or social-engineering opportunities. Clearly state that HIBP metadata is
historical and does not show that an account is currently compromised.
If there are no matching records, say only that no matching record was returned.
Offer owner-directed steps: use unique passwords, enable MFA or passkeys, review
sign-in activity, and contact the service provider if there is independent
evidence of unauthorized access.
```

## Example request

```text
@agent use Email Account Exposure Review
email_address: authorized-user@example.invalid
authorization: account owner requested a check
```

The reserved `.invalid` address is a placeholder. Replace it only in an approved, authorized environment; do not query real addresses while testing a flow.

## Example report

```text
Result: one matching historical breach record
Breach/date: Example Service / date as reported by HIBP
Data classes: email address, username
Limit: no password or current account access was assessed.
Owner guidance: use unique credentials, enable MFA or passkeys, and review sign-in activity.
```

## Handling and escalation

- Store the authorization basis and lookup date, not unnecessary personal details.
- Do not include raw API responses in shared LLM context, tickets, or public reports.
- A match alone does not justify an account reset or incident declaration. Follow the organization’s policy and use independent sign-in or endpoint evidence to determine whether escalation is needed.
- If current unauthorized access is suspected, notify the account owner and incident lead through approved channels.

## References

- [HIBP API reference](https://haveibeenpwned.com/scalar/)
- [HIBP API key](https://haveibeenpwned.com/API/Key)
- [HIBP privacy policy](https://haveibeenpwned.com/Privacy)

## Related flows

- [Breach Exposure Check](flow-breacher_check.md)
- [CompanyOSINT](flow-company_osint.md)
