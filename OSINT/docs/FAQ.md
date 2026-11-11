# OSINT Investigator — Frequently Asked Questions

_Reviewed: 2026-11-11 against the current source tree. This is a feature/usage review, not a live API or compatibility certification._

## General & Scope

**What is the PNWC OSINT toolkit for?**

It is a collection of manual and partially automated investigation workflows for authorized research into domains, IP allocations, public technical records, emails, usernames, and possible scam infrastructure. The main menu is **not** an autonomous investigator or a forensic evidence certification system. Start with the [Investigator Playbook feature matrix](../Playbook/README.md) and the [manual investigation guide](../Playbook/investigation_guide.md).

**Is the toolkit legal to use?**

Lawful use depends on the activity, jurisdiction, data, provider terms, and authorization. Passive public research, queries that transmit information to outside providers, active scans, interception, and testing third-party infrastructure have different requirements. Do not scan or retrieve personal data outside an approved scope. See [LEGAL.md](../../LEGAL.md).

**Where do I start?**

From the repository root, run `cd OSINT/Playbook && bash osint_investigator.sh --help`. For the interactive menu, run `bash osint_investigator.sh`. Create or load a case, use **Edit Case Indicators** to enter approved values, then run a selected investigation. Review metadata and any failed or skipped lookups before drawing conclusions.

## Installation & Compatibility

**Which Linux distributions are supported?**

The [Compatibility Guide](COMPATIBILITY.md) documents intended distributions. Treat platform lists as compatibility targets, not proof that every external program was installed and run on each currently available release. Check the individual tool's system requirements and versions.

**Must I install every optional tool?**

No. The main case menu requires Bash and Python 3; optional collectors such as Holehe, PhoneInfoga, Maigret, Sherlock, WHOIS, and `dig` require their respective binaries. Missing tools are skipped or recorded as `not_run`. `nmap` is not a required prerequisite merely to create a case or run a passive DNS collection.

**How should I install dependencies?**

Review [Installation](INSTALLATION.md), [PINNING.md](../../Scripts/PINNING.md), and the [installer source](../Playbook/install_dependencies.sh). Run the installer as an ordinary user, **not** with `sudo`; package operations may request approval. Avoid unreviewed third-party install commands, and do not assume a pinned top-level package locks all transitive dependencies.

## API Keys & Data Sharing

**Are API keys required?**

They are optional for some workflows and essential for others. The available providers, quotas, terms, and subscription requirements may change. A missing key, rate limit, blocked provider, or nonzero exit must be recorded as unavailable or incomplete, **not** as a negative finding.

**Where are API keys stored?**

The main script supports `bash osint_investigator.sh --config` and a private local `~/.config/osint-investigator/api_keys.conf`. Keep the file user-owned and private (`chmod 600`) and do not commit it. Follow the actual installer/help output rather than older references to a `playbook/api_keys.conf` template.

**What information is shared externally?**

Any API call can disclose the submitted domain, IP address, email, phone, username, and request metadata to the provider. The main IP workflow now uses HTTPS RDAP for **network registration**, not geolocation, and still shares the queried IP with the provider. Check provider terms and engagement permissions before a lookup.

## Investigation Workflow

**What's the difference between `osint_investigator.sh` and `scammer_audit.sh`?**

The first is a case-oriented interactive menu with selected evidence-preserving lookups and JSON state. The separate `scammer_audit.sh` script can run broader investigations and active scans with different prerequisites and risks. Treat the latter as a **separate assessment tool** requiring its own authorization, target validation, and test results.

**How do I investigate a suspicious email?**

Create a case, use the **Edit Case Indicators** menu to save the address (and any separately authorized domain/IP indicators), then choose Email Investigation. Optional provider commands may be absent or incomplete. Verify every result independently; do not infer that a person controls an account solely from an automated match.

**Can I enter multiple targets?**

Yes, in the case indicator editor. It accepts multiple entries per category and saves the validated case state. The independent `scammer_audit.sh` offers its own command-line options; check `--help` and **do not** run active network scans against unapproved addresses.

**Where is output stored?**

Case-specific metadata, reports, raw tool stdout/stderr, checksums and run statuses are kept under `~/OSINT_Cases/<CASE_ID>/`. Restrict access and retention according to the investigation. Check the `complete`, `partial`, and `not_run` statuses before describing a collection as finished.

**Does the Reports menu generate all displayed reports?**

No. Its **A** option launches the separate abuse-report generator if present and executable. The numbered report actions are not wired up in the current main script. Generated reports require human review; never present them as automatically verified or accepted by a registry or agency.

## Troubleshooting

**Why did Holehe or another lookup return nothing?**

The provider might block enumeration, be rate-limited or unavailable, or the tool may fail. Inspect stderr, exit status, and evidence metadata. A non-result is not proof of account absence.

**How do I fix a missing tool?**

Use `bash osint_investigator.sh --status`, then check the specific installer and the corresponding vendor's supported installation process. Do not install obsolete interpreters merely to run an archived sample.

**Do I need root for Nmap?**

Some Nmap modes require elevated privileges or capabilities; the OSINT case menu does not grant general sudo permission automatically. Choose a compatible unprivileged scan or obtain separately approved privileges when warranted.

**Why won't the web UI launch?**

`--web` is recognized, but `web_interface.py` is **not included** in the current repository. Installing Flask alone will not create it. Use the terminal menu until an actual, secured web interface has been implemented and tested.

## Related References

[OSINT Index](../README.md) · [Investigator Playbook](../Playbook/README.md) · [Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md) · [Main Index](../../README.md)
