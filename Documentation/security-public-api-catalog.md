# Security API Catalog and Integration Cookbook

**Reviewed:** November 2, 2026. **Scope:** APIs relevant to authorized OSINT, vulnerability prioritization, incident response, external asset discovery, web/API testing and data pipelines.

[Documentation](README.md) · [OSINT](../OSINT/README.md) · [Incident response](../IncidentResponse/README.md) · [Data ingestion](../Data-Engineering/Phase2/api_file_ingestion.md) · [Repository](../README.md)

> [!IMPORTANT]
> The list below is **curated from** [public-apis/public-apis](https://github.com/public-apis/public-apis), not a full import. Listing an API does not establish live availability, a free tier, permission to scan, or suitability for customer information. Pricing, credentials, quotas, schemas, product restrictions and privacy terms can change. Check official provider terms and docs before use. Never submit customer data or private indicators to public scan/sandbox services without approval.

## Source selection and integration status

The source directory is [MIT licensed](https://github.com/public-apis/public-apis/blob/master/LICENSE); each service has its own usage restrictions. Descriptions, triage steps and request examples below are independently written and linked to official providers. When the upstream directory points to a paid wrapper, obsolete feed or unclear authentication model, prefer the canonical source.

**Existing in repo** means PNWC docs/scripts already reference the provider—not that a live API test passed. **Reference** means a candidate for a future integration, not that a key, scheduler, or connector exists. **Official companion** means an authoritative API/feed included alongside the directory's entry.

## Threat-intelligence APIs

| API | Security workflow | Integration status | Official documentation |
| --- | --- | --- | --- |
| AbuseIPDB | IP reputation and reported abuse context | Existing OSINT script; key required | [API v2](https://docs.abuseipdb.com/) |
| AlienVault OTX | Threat pulses and IOC context | Existing OSINT script; key-based workflows | [OTX API](https://otx.alienvault.com/api) |
| VirusTotal | Existing domain, IP and file-hash reputation | Existing OSINT script; key and restrictive quota | [API v3](https://docs.virustotal.com/reference/overview) |
| URLhaus | Malware-distribution URLs and optional IDS feeds | Existing OSINT script; current Auth-Key rules require review | [Community API](https://urlhaus.abuse.ch/api/) |
| urlscan.io | Search existing website scans and associated indicators | Existing OSINT script; API key for normal use | [API docs](https://docs.urlscan.io/) |
| GreyNoise Community | Assess background internet scanning versus targeted activity | Reference; limited unauthenticated access | [Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) |
| Google Safe Browsing | Known unsafe URL verdicts for permitted use cases | Reference; API key and terms | [Official docs](https://developers.google.com/safe-browsing/) |
| Hybrid Analysis | Malware sandbox report enrichment | Reference; key and upload/data-handling restrictions | [API v2](https://www.hybrid-analysis.com/docs/api/v2) |

**Existing-script caveat:** [`threat_feed_check.sh`](../OSINT/Playbook/scripts/threat_feed_check.sh) currently uses an unauthenticated `POST https://urlhaus-api.abuse.ch/v1/`. The [current URLhaus community documentation](https://urlhaus.abuse.ch/api/) requires an Auth-Key for API/dataset use. Do **not** treat its missing/error response as a clean verdict. Authenticate and retest that script separately before production use; this documentation change does not alter live code.

Related: [OSINT toolkit](../OSINT/OSINT_TOOLS_CATALOG.md) · [Threat intelligence AgentFlow](../AI/AnythingLLM/flow-threat_intel.md) · [SIEM](../IncidentResponse/SIEM/README.md) · [IDS/IPS](../IncidentResponse/IDS%26IPS/readme.md).

## Passive infrastructure and identity-research APIs

| API | Security workflow | Integration status | Official documentation |
| --- | --- | --- | --- |
| Shodan | Internet-visible services and in-scope device inventory | Existing catalog; key / plan | [API](https://developer.shodan.io/) |
| Censys | Hosts, certificates and exposed services | Existing catalog; key / plan | [API](https://search.censys.io/api) |
| BinaryEdge | Supplemental attack surface and host context | Existing catalog; key / plan | [API v2](https://docs.binaryedge.io/api-v2.html) |
| SecurityTrails | Current/historical DNS and domain relationships | Existing catalog; key / plan | [Documentation](https://securitytrails.com/corp/apidocs) |
| EmailRep | Email reputation context (not identity proof) | Existing catalog; check current quota/access | [Documentation](https://docs.emailrep.io/) |
| Have I Been Pwned | Breach-awareness and authorized domain exposure auditing | Existing catalog; key/eligibility by endpoint | [API v3](https://haveibeenpwned.com/API/v3) |
| IPinfo | ASN, network owner, approximate location | Reference; public/paid endpoints vary | [Developer docs](https://ipinfo.io/developers) |
| Cloudflare DNS over HTTPS | DNS record lookups through read-only DoH resolver | Official companion; no key for resolver | [DoH guide](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/) |

Use passive, authorized context only. Geolocation is approximate, an exposed socket is not automatically a vulnerability, and correlation is not proof of a person's identity.

Related: [domain/IP recon](../OSINT/scripts/Domain_IP_Recon.md) · [email OSINT](../OSINT/scripts/Email_OSINT.md) · [web security](../WebAppSecurity/README.md).

## Vulnerability management and supply-chain APIs

| API | Security workflow | Integration status | Official documentation |
| --- | --- | --- | --- |
| National Vulnerability Database (NVD) | CVE/CPE queries and severity/product context | Official API 2.0; anonymous low-rate / optional key | [CVE API](https://nvd.nist.gov/developers/vulnerabilities) |
| CISA Known Exploited Vulnerabilities | Prioritize known-exploited CVEs over score-only queues | **Official public JSON feed**, not the directory's third-party RapidAPI wrapper | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| GitHub Global Security Advisories | Package/ecosystem vulnerabilities (GHSA) | Official companion; public read API | [GitHub REST](https://docs.github.com/en/rest/security-advisories/global-advisories) |
| GitGuardian | Detect exposed secrets in repositories you may inspect | Reference; credentials and data-handling review | [API docs](https://api.gitguardian.com/doc) |
| CRXcavator | Risk review for browser extensions | Reference; key | [API docs](https://crxcavator.io/apidocs) |

**Decision workflow:** verify installed product/version and exposure → read vendor guidance → correlate NVD/GHSA → mark KEV where present → determine patch/mitigation priority and ownership. KEV inclusion means exploitation has been observed somewhere, **not** that this particular asset was compromised.

Related: [Incident response](../IncidentResponse/README.md) · [Cloud](../Cloud/README.md) · [Containers](../ContainerSecurity/README.md).

## Web API security, DevSecOps and operations

| API | Security workflow | Integration status | Official documentation |
| --- | --- | --- | --- |
| APIs.guru | Find OpenAPI specifications for owned/lab API contract testing | Reference; public catalog | [API directory](https://apis.guru/api-doc/) |
| Postman Echo | Synthetic HTTP request/response testing | Reference; public demo service | [Echo docs](https://www.postman-echo.com/) |
| Cloudflare | Manage authorized DNS/edge configuration via scoped tokens | Reference; token and plan | [Official API](https://developers.cloudflare.com/api/) |
| Bitwarden | Vault/organization governance (appropriate deployment) | Reference; OAuth and plan/deployment conditions | [API guide](https://bitwarden.com/help/api/) |
| Bugcrowd | Approved bounty/disclosure report lifecycle | Reference; program credentials | [Official API](https://docs.bugcrowd.com/api/getting-started/) |
| HackerOne | Authorized vulnerability reporting/triage | Reference; program credentials | [API](https://api.hackerone.com/) |

A published OpenAPI specification is **not** permission to test the provider's service. Do not submit sensitive requests to public echo endpoints. Separate report-management APIs from scanning tools.

Related: [Web app methodology](../WebAppSecurity/methodology.md) · [Cloud](../Cloud/README.md) · [Data Engineering](../Data-Engineering/Phase2/api_file_ingestion.md).

## Read-only command cookbook

Illustrative commands use public reference records; they have **not** been executed against every current version/service. Requires `curl` and `jq`. Observe provider quotas. Inspect `HTTP` status and JSON error objects before making a verdict.

### DNS and scanning context (no client data)

```bash
# Public example domain; Cloudflare JSON DoH format.
curl -fsS --get -H 'accept: application/dns-json' \
  --data-urlencode 'name=example.com' --data-urlencode 'type=A' \
  'https://cloudflare-dns.com/dns-query' | jq '.Answer // []'

# GreyNoise anonymous community quota is limited; 429 is not a benign verdict.
curl -fsS 'https://api.greynoise.io/v3/community/8.8.8.8' | jq .
```

### Vulnerability intelligence (no API key)

```bash
curl -fsS --get --data-urlencode 'cveId=CVE-2021-44228' \
  'https://services.nvd.nist.gov/rest/json/cves/2.0' \
  | jq '[.vulnerabilities[]?.cve.id]'

curl -fLsS --retry 2 \
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' \
  -o kev.json
jq '{catalogVersion, dateReleased, count}' kev.json
jq -r '.vulnerabilities[] | select(.cveID=="CVE-2021-44228") | .vulnerabilityName' kev.json

curl -fsS -G -H 'Accept: application/vnd.github+json' \
  --data-urlencode 'cve_id=CVE-2021-44228' \
  'https://api.github.com/advisories' | jq '.[].ghsa_id'
```

### Authenticated, read-only indicator context

Provide keys through an approved secrets manager/environment, **never**
include real values in committed files, logs or screenshots. **Caution:**
interpolating keys into `curl -H` arguments can expose them to local process
inspection on some systems; for production use, prefer a protected
`curl --config` file (mode `0600`), a credential-aware client library or a
secret-injection mechanism that avoids command-line arguments. Both queries
below use Google's public resolver IP only as a **synthetic example**.

```bash
: "${ABUSEIPDB_API_KEY:?configure in approved secret store}"
: "${VT_API_KEY:?configure in approved secret store}"

curl -fsS -G -H "Key: ${ABUSEIPDB_API_KEY}" \
  -H 'Accept: application/json' \
  --data-urlencode 'ipAddress=8.8.8.8' \
  --data-urlencode 'maxAgeInDays=90' \
  'https://api.abuseipdb.com/api/v2/check' \
  | jq '{ip:.data.ipAddress, reports:.data.totalReports}'

curl -fsS -H "x-apikey: ${VT_API_KEY}" \
  'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8' \
  | jq '{id:.data.id, reputation:.data.attributes.reputation}'
```

### API development lab (synthetic only)

```bash
curl -fsS -G --data-urlencode 'case=synthetic-lab' \
  'https://postman-echo.com/get' | jq '.args'

# Inspect a known-good local OpenAPI document. Do not auto-execute methods.
jq '{version:.openapi, paths:(.paths | keys)}' ./approved-openapi.json
```

## Recommended API integration contract

1. **Scope and privacy:** record owner, permitted indicator/data types, and whether request data may be disclosed to a third party. A hash is not necessarily anonymous.
2. **Credentials:** use scoped/rotated keys; never commit an actual `api_keys.conf`. Implement least privilege and redact headers from logs.
3. **Transport and quota:** TLS verification, timeout, 429/`Retry-After` handling, bounded exponential backoff, checkpointed pagination, response-size caps and caching.
4. **Provenance:** retain request timestamp (UTC), provider name, response status, schema/version, source indicator, source reliability and lookup result separately.
5. **Error handling:** unavailable, unauthorized, throttled, malformed and unknown are **not clean/benign**. Do not auto-block or delete assets based on one provider score.
6. **Validation:** use synthetic data first; get consent before public site submissions or sample uploads. Test rate limits, schema drift, conflicting intelligence and recovery.
7. **SIEM design:** normalize enrichment outputs, correlate with local alerts, add human-review gates, document retention. [Wazuh](../IncidentResponse/SIEM/wazuh.md) should not ingest raw API keys.

Suggested future workflow (**not deployed**): in-scope inventory → passive exposure/DNS queries → NVD + GHSA + KEV prioritization → approved reputation lookups → time-stamped JSON → [SIEM](../IncidentResponse/SIEM/README.md) triage and analyst review.

## Source and review boundaries

- Source catalog: [public-apis/public-apis](https://github.com/public-apis/public-apis), [MIT license](https://github.com/public-apis/public-apis/blob/master/LICENSE). Provider APIs have **separate** terms.
- Priority official sources: [NVD](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [URLhaus](https://urlhaus.abuse.ch/api/), [VirusTotal](https://docs.virustotal.com/docs/api-overview), [urlscan.io](https://docs.urlscan.io/), [Cloudflare DoH](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/), [GreyNoise](https://docs.greynoise.io/docs/using-the-greynoise-community-api).
- **Verification limits:** providers/doc links were reviewed selectively; API live responses, costs, quota entitlements and data-processing terms were not tested across every provider. No account was created, key used, API scheduled, file uploaded or client asset scanned for this change.
