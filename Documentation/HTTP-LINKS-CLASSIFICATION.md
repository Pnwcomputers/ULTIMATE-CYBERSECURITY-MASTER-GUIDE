# HTTP & External Link Classification

_Reviewed November 11, 2026 · This document describes classifications and corrected examples. It does **not** claim that every public URL was reachable or content-verified._

The [Link Check workflow](../.github/workflows/link-check.yml) verifies relative paths and anchors on pull requests. Its online job runs on schedule/manual dispatch, flags 401/403/429 for follow-up instead of treating them as passing, and is **informational**. A green PR therefore does not certify vendor uptime, firmware maintenance, safe installer binaries, or current terms.

## HTTP Reference Dispositions

| Reference Type | Example / Source | Action |
|---|---|---|
| Loopback HTTP | `http://127.0.0.1:11434`, `http://localhost:9000` | Accept only for a service bound to the actual loopback interface; containers/VMs may change what “localhost” means |
| Private lab HTTP | `http://192.168.1.50:9000` (documentation address) | Mark **lab-only**; do not expose authenticated admin UI or credentials over untrusted LAN/WAN; use TLS or VPN/management controls |
| Container-internal HTTP | `http://opensearch:9200`, `http://mongodb:27017` | Potentially appropriate inside a segmented container network; not suitable as an internet URL |
| IMDS link-local HTTP | `http://169.254.169.254/latest` | AWS instance metadata endpoints are special host-local services; use IMDSv2 token flow and host controls; do not “fix” by changing scheme blindly |
| Test/attack demonstration | `http://target.com`, `http://attacker/...` | Synthetic targets and offensive examples are not a recommendation to use plaintext on actual networks |
| Signature-test endpoint | `http://testmynids.org/uid/index.html` | Deliberate HTTP signature payload from a vendor-documented IDS lab; no credentials/customer data, only in an authorized isolated test; see [Security Onion documentation](https://docs.securityonion.net/en/3/main/suricata/) |
| Tor onion service | `http://example.onion` (illustrative only) | Tor-specific destination; must be reviewed for authenticity, v3 address and the site's trust boundary; plain HTTP string alone does not establish public-cleartext routing |
| External vendor reference | Public `http://` documentation or downloads | Verify canonical HTTPS replacement **and content** from the official publisher; log redirect/status, maintenance date, license and required version |
| Historic/invalid endpoint | Previously referenced `http://timetravel.mementoweb.org/` | Replaced in [historical OSINT workflow](../Tradecraft/osint-threat-intel.md) with Internet Archive's HTTPS CDX endpoint; document API rate limits and missing capture ambiguity |
| Commercial/unlicensed HTTP API | Previously referenced `http://ip-api.com/json/` | Removed from the remaining [OSINT investigation guide](../OSINT/Playbook/investigation_guide.md); use TLS-only RDAP for allocation metadata, not physical geolocation |

## Review A Public Link Completely

1. Identify whether it is a navigable public reference, a command/fixture string or simply a mention of a scheme; record exact path, line, URL and context.
2. For public documentation, open the official HTTPS page and verify that it **actually** describes the cited function, product and version; confirm its publication/revision date and license.
3. Treat 401, 403 and 429 as **unknown** rather than live-and-correct. Do not bypass authentication or anti-bot restrictions; record the limitation. Check final redirect destinations for trusted origin and HTTPS downgrade.
4. Separate genuine defects from intentionally HTTP-only lab and metadata references; record why an exception is acceptable and what controls are necessary.
5. Review changed Markdown with offline internal link/fragment validation and Markdown lint. For external status, use the scheduled or manually dispatched online workflow, archive its results and document host-level skips/timeouts.

The [automated candidate triage](../tools/maintenance_candidate_triage.py) produces a path-and-line inventory, including empty-table candidates. It reports **candidates**, never certifies a URL. Follow up unverified public sites in [issue #187](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/187).

---

[Documentation Index](README.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md)
