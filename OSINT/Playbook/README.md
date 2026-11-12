# OSINT Investigator Playbook — Case Management & Evidence Collection

_Reviewed: 2026-11-11 against the repository source and regression-test fixtures. **Third-party lookups, installed tool versions, and a full live case were not exercised in this review.**_

## Purpose & Scope

The [manual investigation guide](investigation_guide.md) remains the authoritative workflow for planning, authorization, provenance, corroboration, and reporting. The `osint_investigator.sh` Bash menu is a **partially implemented operator toolkit**, not an autonomous investigator or a courtroom-certified evidence system. Optional third-party resources are collected in the [Curated Awesome OSINT List](../awesome-osint-list-curated.md); the Bash menu does **not** automatically run the curated catalog.

Work only on accounts, assets, people, and data you have lawful authorization to investigate. Confirm a provider's terms and data-sharing rules before submitting email addresses, usernames, phone numbers, or IPs to it.

## Actual Feature Status

| Feature | Current source behavior | Boundary |
|---|---|---|
| New/load/list cases | Implemented in the interactive menu; creates private case directories and JSON case state | Existing cases must have valid state. Legacy executable `.case_state` is rejected, not executed or migrated |
| Add indicators & save state | Bash case menus and `lib/case_state.py` handle configured indicator arrays | A saved indicator does **not** establish its truth or authorization |
| Email | Runs optional Holehe / h8mail if available | Provider results can be stale or incomplete; omitted tools are reported as skipped |
| Phone | Runs optional PhoneInfoga if available | It does not verify a subscriber's identity |
| Domain | WHOIS, selected `dig` record types, optional Subfinder | DNS/WHOIS are point-in-time observations, not proof of ownership |
| IP | WHOIS, HTTPS RDAP network-registration lookup, reverse DNS | **RDAP is not geolocation.** No insecure HTTP geolocation call is made by the main script |
| Username | Optional Maigret or Sherlock | Matches require independent corroboration; usernames are not unique identities |
| Run all | Invokes the above indicator-based modules | An individual missing/failed tool does not mean there were no findings |
| Raw output & run evidence | `lib/collect_evidence.py` stores `*.stdout`, `*.stderr`, `*.meta.json`, and SHA-256 and appends an evidence-log entry | Review each `complete`/`partial`/`not_run` status before reporting; evidence is not independently certified |
| API settings / dependency installer | Configuration menu and `--config`, `--status`, `--install` options are implemented | Secrets stay in private local config; installer changes the system after approval |
| External integration | The integration menu can call local scripts if correctly configured | Optional integration functions/dependencies require separate testing |
| Abuse report generator | Separate `abuse_report_generator.sh` can be launched via **A** in the reports submenu | Numbered report entries 1–5 in that menu are **not wired** to report-generation actions |
| Web UI | `--web` and **W** menu option check for a file | `web_interface.py` is **absent** in this repository; no working web UI is included |
| Crypto investigation | Separate scripts may exist in the toolkit | There is no dedicated crypto item in the main investigation menu |

These statuses come from current source inspection plus the scope of existing local fixture tests; they do not establish service availability, safe target selection, or successful live runs.

**Scripts Directory:** [Available OSINT Investigation Scripts](scripts/README.md) — use the script-specific prerequisites and authorization limits rather than assuming every script is part of the main interactive menu.

**Operator Support:** [FAQ](../docs/FAQ.md) · [Troubleshooting](../docs/TROUBLESHOOTING.md) · [Installation](../docs/INSTALLATION.md). Missing or failed lookups are not negative findings.

## Prerequisites & Safe Start

Use Bash, Python 3, `curl`, and whichever optional tools you specifically require. The case menu can be explored without installing every OSINT tool. Run as a regular, non-root user in a disposable or carefully controlled workspace.

~~~bash
cd OSINT/Playbook
bash osint_investigator.sh --help
bash osint_investigator.sh --status
bash osint_investigator.sh
~~~

Interactive flow: **Create New Case → Add Only Approved Indicators → Choose Investigation → Review Every Evidence Status → Document Interpretation & Sources → Generate/Review Reports Manually.** The exact menu entries may change; inspect `--help` and the on-screen menu before use.

The optional `install_dependencies.sh` supports additional programs. **Do not run it through `sudo`**; it refuses root and may request scoped `sudo` for OS packages. Python dependencies are installed into per-tool environments beneath `~/.local/share/osint-investigator/`. Read [PINNING.md](../../Scripts/PINNING.md) and the installer source before approving downloads. Unpinned or unavailable packages can be skipped and reported; a skipped tool cannot be considered a completed lookup.

## IP Lookup: Important Security & Accuracy Change

The main IP module previously queried `http://ip-api.com/json/`, a plaintext external service whose [published terms](https://ip-api.com/docs/legal) prohibit commercial use of the free endpoint. This has been removed from the main script's default path.

The updated workflow requests `https://rdap.org/ip/<IP-address>` with HTTPS-only redirects; the service routes the request to the appropriate registry. This yields **registered network allocations**, not physical position, an individual's identity, or live network reachability. The lookup still discloses the IP being researched to the bootstrap/registry provider; consent and minimization still apply. See [RDAP.org](https://about.rdap.org/) and the [ARIN RDAP guide](https://www.arin.net/resources/rdap.html).

**Do not label an RDAP address or registration contact as device geolocation or attacker attribution.** If a separate geolocation provider is needed, document its licensing, API terms, TLS, uncertainty, privacy review and authorization before enabling it in a separate workflow.

## Evidence, Privacy & Limitations

- Cases are stored beneath `~/OSINT_Cases`; `umask 077` and private JSON files reduce accidental exposure but do not replace an encrypted filesystem, authenticated audit trail, external timestamps, legal holds, or chain-of-custody review.
- `.case_state.json` replaces the old shell-source state. The old `.case_state` file is refused; re-enter authorized indicators. The data file is validated and not `source`d.
- Every collector step writes complete stdout/stderr (subject to explicit size/time limits) and metadata containing timestamps, checksums and exit status. A timeout, nonzero exit or size cap makes the step `partial`; unavailable tools are `not_run`. A saved Markdown report is **not automatically a successful investigation**.
- Avoid storing API keys, real personal identifiers, client lists or sensitive evidence in the public repository. Locally configured `api_keys.conf` and `branding.conf` must be trusted user-owned files, not broadly writable. Restrict evidence sharing and retention according to the engagement agreement.
- Investigators must independently validate vendor findings, search results, attribution, and conclusions. Empty/no-match output is not proof of absence.

## Testing & Known Gaps

Local regression fixtures are defined in [`test_osint_investigator.py`](../../tests/hardening/test_osint_investigator.py) and [`test_osint_state_evidence.py`](../../tests/hardening/test_osint_state_evidence.py). The CI [guide-tests workflow](../../.github/workflows/guide-tests.yml) includes these fixtures and checks selected Shell scripts. Tests mock external commands; they do not verify commercial provider terms, API authentication, live internet success, report acceptance by any agency, or the entire installation.

Priorities for actual new development: replace/report unfinished report-menu actions, decide whether to implement a separately secured local web UI or remove its menu option, improve indicator validation and explicit collection consent, test provider adapters, and create exportable case manifests with independent evidence review. **Do not advertise these as implemented until tests prove them.**

---

[Manual Investigation Workflow](investigation_guide.md) · [OSINT Index](../README.md) · [Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md) · [Main Index](../../README.md)
