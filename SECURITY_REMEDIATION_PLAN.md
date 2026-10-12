# Repository Security Remediation and Staging Plan

Repository: Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE
Working branch: security/review-remediation
Prepared: 2026-10-12
Status: DRAFT — implementation and validation tracking
Base commit: TO BE RECORDED
Review owner: TO BE ASSIGNED

## 1. Scope and limitations

This document consolidates all findings and follow-up work identified in the
conversation. It is a remediation specification, not a tested patch, a complete
repository audit, or an authorization to change production systems.

Several edits were reported as saved by the maintainer. Their commits, resulting
diffs, and runtime behavior have not been independently verified. The assistant
could not run its local shell, deployment tests, or a complete Git-history scan.

Earlier generated patches/updaters were untested drafts. Do not run or apply them
blindly, especially after the manual edits already made. Reconcile each change
with the current branch and record its commit.

No real credentials, incident evidence, private reports, or .env contents belong
in this document, GitHub issues, pull requests, or CI artifacts.

### Status vocabulary

- REPORTED: maintainer said the edit was saved; verification remains open.
- PROVIDED: instructions were supplied; completion is not confirmed.
- OPEN: implementation or investigation remains necessary.
- VERIFIED: use only after attaching a commit and relevant test evidence.
- CONTAINED: exposure is temporarily restricted; the underlying defect is not closed.
- IMPLEMENTED: committed on `security/fix-review-findings` with passing local tests (`python3 -B -m unittest discover -s tests/hardening`) and clean `shellcheck -S warning`; not VERIFIED until merged with CI green.

## 2. Findings and current progress

| ID | Area | Conversation status | Closure condition |
|---|---|---|---|
| R1 | Root installers and unverified downloads | PARTIAL: shared verified-install library, SHA-256/HTTPS checks, safe extraction, required pins in data-only `Scripts/tool_pins.conf` IMPLEMENTED for both installers. NOT closed: `pnwc_install_tools.sh` still needs root for system paths; pins are populated for pip, git, Go, cargo and download sources (dl hashes are trust-on-first-use; see `Scripts/PINNING.md`); only `gem:evil-winrm`, `dl:wazuh-gpg-key`, `exploitdb` and the documentation clone remain unpinned and are skipped/reported unless `--allow-unpinned` is used in a lab; transitive Python dependencies are not hash-locked; third-party apt repositories unchanged | Least-privilege, pinned, verified installation paths pass failure tests |
| R2 | ELK deployment defaults | Lab labeling/network edits REPORTED; secret handling IMPLEMENTED in `elk_stack.md` (required `${VAR:?}` secrets, generated 0600 `.env`, least-privilege `logstash_writer`, `kibana_system` password via API on stdin, no sample passwords); compose rendering checked with `docker compose config`, full stack NOT started; role privileges may need adjusting per pipeline; production design OPEN | Lab changes validated; production claims withheld until TLS/identity/secret tests pass |
| R3 | Wrong Sherlock package | IMPLEMENTED (`sherlock-project` in an isolated per-tool venv; tested with shims, not against the live package) | Both installation paths corrected; expected executable verified in an isolated environment |
| R4 | Missing-tool counter under set -e | IMPLEMENTED (zero/one/multiple-missing tests; nonzero exit on any missing tool or failure) | Zero/one/multiple-missing-tool tests pass |
| R5 | Executable case-state files | IMPLEMENTED: `OSINT/Playbook/lib/case_state.py` (schema-validated, atomic, 0600 JSON; never sourced); legacy `.case_state` is refused, not migrated; API/branding configs load only if owner-only. all consumers (`abuse_report_generator.sh`, `toolkit_integration.sh`, `scripts/*.sh`) now use the JSON loader and `source_trusted` (`lib/trusted_conf.sh`); static test forbids raw `source` of config/state | JSON state and safe migration/refusal implemented across affected consumers |
| R6 | Ambiguous object-authorization advice | REPORTED | Correct wording and validation instructions confirmed in the branch |
| R7 | CIS, Sysmon and Zeek guidance | REPORTED | Correct mappings, prerequisites and supporting references confirmed |
| R8 | Truncated/suppressed evidence | DONE. All OSINT `scripts/` collectors (`domain_monitor.sh`, `ssl_cert_audit.sh`, `email_audit.sh`, `username_audit.sh`, `metadata_stripper.sh`, `scammer_audit.sh`, `crypto_audit.sh`, `threat_feed_check.sh`, `phone_audit.sh`) keep stdout/stderr/exit-status evidence and report a failed/unreachable/timed-out lookup as FAILED or UNVERIFIED instead of silently "not found"/"no change"/"closed". `whois_bulk.sh` and `screenshot_archive.sh` already did this correctly. `lib/collect_evidence.py` + `osint_investigator.sh` were already fixed. `toolkit_integration.sh`: 9 of its `run_*` wrapper functions (threat feed, crypto, domain-monitor init, username, SSL cert, case report, bulk WHOIS, metadata strip, screenshot) ran the underlying script and then printed success unconditionally, discarding its exit status — fixed to check the real exit code and report FAILED. `web_interface.py` does not exist in this repo; the one reference to it (`launch_web_interface` in `osint_investigator.sh`) already checks for the file and errors cleanly if it's missing, so there was nothing to fix | Full raw output, errors and failure status preserved across collection paths |
| R9 | CI and repository controls | PARTIAL: `guide-tests.yml` runs `bash -n`, ShellCheck and hardening tests; `.gitignore` covers case data; secret-literal regression test added. actions are pinned to commit SHAs resolved from each action's repository, write permission is job-scoped, Dependabot keeps pins current; a test enforces all of it. NOT done: owner-side settings (rulesets, secret scanning, push protection) | Workflow hardening and tests implemented; owner-only settings verified |

Nothing in this table certifies the entire repository as secure.

## 3. File-level work map

### Existing files to inspect/edit

- OSINT/Playbook/install_dependencies.sh
- Scripts/pnwc_install_tools.sh
- OSINT/Playbook/osint_investigator.sh
- OSINT/Playbook/README.md
- WebAppSecurity/owasp-top-10.md
- PlayBooks/BlueTeam_IncResp_Enhanced.md
- IncidentResponse/SIEM/elk_stack.md
- .github/workflows/link-check.yml
- .gitignore
- README.md
- STYLE_GUIDE.md
- AUDIT_FINDINGS.md

Also inventory actual web UI, reporting, configuration and integration consumers.
Do not assume that a filename mentioned in documentation exists in this checkout.

### Proposed new files — names to confirm before implementation

- OSINT/Playbook/lib/case_state.py
- OSINT/Playbook/lib/safe_case_state.sh
- OSINT/Playbook/lib/collect_evidence.py
- tests/hardening/test_case_state.py
- tests/hardening/test_evidence_collection.py
- tests/hardening/test_installer_checks.py
- .github/workflows/security-regression.yml
- SECURITY_UPDATE.md

The proposed files are not implied to exist or be tested. Keep the implementation
and all required callers/tests together in an atomic commit.

## 4. Staging order

1. Record the current branch and immutable commit; preserve existing work.
2. Verify the already-reported small fixes and documentation corrections.
3. Complete and validate ELK lab containment and secret handling.
4. Refactor or explicitly contain unsafe installer paths.
5. Implement case-state migration/refusal with compatibility tests.
6. Implement complete evidence collection and failure reporting.
7. Add CI, documentation controls and owner-side repository protections.
8. Run regression, deployment and full-scope audit gates before closing findings.

Separate these into reviewable commits or PRs. A documentation correction may be
merged separately after its own checks; a multi-file runtime change must not be
split into a temporarily broken state.

---

## 5. R3/R4 — OSINT dependency installer

File: OSINT/Playbook/install_dependencies.sh

### Required edits

In both Python package-installation lists, use:

```bash
        sherlock-project \
```

Replace the misleading package-name comment with:

```bash
    # The Sherlock OSINT package is sherlock-project; its executable is sherlock.
```

Leave executable checks such as command -v sherlock unchanged.

In verify_installation(), replace the post-increment with:

```bash
            missing=$((missing + 1))
```

With set -e, the original arithmetic post-increment can terminate verification
when its initial value is zero. Define an explicit final verification status
after reporting every missing dependency.

### Follow-up requirements

- Use isolated environments for Python CLI tools; do not treat
  --break-system-packages as the normal installation strategy.
- Verify package provenance, reviewed versions, command paths and entry points.
- Do not install tools merely to test the counter.

### Acceptance checks

- [ ] Both package lists use sherlock-project.
- [ ] Executable checks still use sherlock.
- [ ] Comment matches implementation.
- [ ] Zero missing dependencies produces the expected success result.
- [ ] One and multiple missing dependencies produce a complete summary.
- [ ] Failure does not silently produce an installation-success claim.
- [ ] Installation behavior is tested only in a disposable environment.

---

## 6. R6 — Object-level authorization guidance

File: WebAppSecurity/owasp-top-10.md
Section: A01: Broken Access Control

Replace the How to defend bullet with:

```markdown
- **How to defend:** deny access by default and enforce authorization
  **server-side on every request**. Verify that the authenticated principal
  is permitted to perform the requested action on the specific object,
  including applicable ownership, role, and tenant-boundary checks.
  Use opaque or unpredictable identifiers only as **defense in depth**,
  never as a substitute for authorization. Centralize access-control
  logic and log authorization failures without recording credentials
  or unnecessary sensitive data.
```

Add immediately afterward, before the existing CWE/reference bullet:

```markdown
- **Validation:** in an authorized test environment, create two ordinary
  users with separate private objects. Confirm that each user can perform
  permitted actions on their own objects but cannot read, modify, delete,
  or export the other user's private objects, even when the identifier
  is known. Also test administrative functions with an ordinary account
  and cross-tenant access where applicable. Verify both the response and
  resulting data state; an error response alone does not prove that an
  unauthorized change was prevented.
```

Acceptance:
- [ ] The text never treats identifier entropy as a replacement for authorization.
- [ ] Existing headings, references and unrelated sections are preserved.
- [ ] The rendered Markdown and internal links remain correct.

---

## 7. R7 — Incident-response guidance

File: PlayBooks/BlueTeam_IncResp_Enhanced.md

### CIS attribution

Replace the alert-response bullet that attributes 15 minutes to CIS Control 19:

```markdown
- **Example organizational SLA:** begin triage of High/Critical alerts
  within 15 minutes of receipt. Obtain approval for this target and define
  coverage hours, escalation paths, and how response time is measured.
  This is a proposed local service target, not a CIS-mandated deadline.
  For CIS Controls v8/v8.1, map incident-response procedures to
  **Control 17: Incident Response Management** and document the
  applicable safeguards.
```

### Windows telemetry

Replace the service/task bullet that maps those events directly to Sysmon 1/7:

```markdown
- **Unexpected services or scheduled tasks:** investigate Windows
  Security Event 4697 for service installation and Event 4698 for
  scheduled-task creation, where supported and the relevant auditing
  is enabled. Correlate these with service/task configuration, executable
  paths, initiating accounts, and approved change records.
  Sysmon Event 1 records process creation; Event 7 records image loading.
  Use these as supporting telemetry, not as direct service/task
  registration events. Event 7 requires explicit configuration.
  Validate event generation and SIEM ingestion with benign lab tests.
```

### Packet captures and Zeek

Replace the bullet describing zeek-cut as a PCAP exporter:

```markdown
- **Packet captures:** export available PCAP from the organization's
  authorized packet-capture platform. Record the capture source,
  interface, time range, timezone, filters, and known collection gaps.
  Preserve the original capture and record its SHA-256 hash.
- **Zeek logs:** preserve the original logs separately. Use zeek-cut
  to extract fields from Zeek TSV logs, or a JSON-aware parser for JSON
  logs. zeek-cut does not export PCAP, and Zeek connection logs do not
  contain the original packet payloads.
```

Acceptance:
- [ ] No malformed chat citation tokens remain in pasted repository text.
- [ ] Framework edition and locally chosen SLA are distinguished.
- [ ] Audit-policy and telemetry prerequisites are stated.
- [ ] Detection examples have a documented benign validation procedure.
- [ ] NIST references elsewhere are reviewed against SP 800-61 Rev. 3 without
      inventing a revision-label defect in a file that was not checked.

---

## 8. R2 — ELK lab containment and secrets

File: IncidentResponse/SIEM/elk_stack.md

This section contains interim lab controls. It does not provide a production
deployment or authorize changes to an existing cluster.

### 8.1 Scope and warning

Replace the production-ready introductory claim with:

```markdown
This guide provides an isolated-lab ELK example for learning deployment
and telemetry workflows. It is not a validated production deployment.
```

Add directly below the main title:

```markdown
> **SECURITY STATUS — ISOLATED LAB ONLY**
>
> This walkthrough is undergoing security remediation. Existing examples
> include plaintext connections, sample credentials, and privileged service
> accounts. Do not deploy them unchanged, expose them to the internet, or
> use real incident data.
>
> Production use requires separately validated TLS, least-privilege service
> identities, protected secrets, supported versions, network restrictions,
> and operational testing. A warning banner or loopback binding alone
> does not satisfy those requirements.
```

### 8.2 Port publishing

In the existing Compose example, replace only the service-specific ports blocks.

Elasticsearch:

```yaml
    ports:
      - "127.0.0.1:9200:9200"
      - "127.0.0.1:9300:9300"
```

Logstash:

```yaml
    ports:
      - "127.0.0.1:5044:5044"
      - "127.0.0.1:5000:5000/tcp"
      - "127.0.0.1:5000:5000/udp"
      - "127.0.0.1:9600:9600"
```

Kibana:

```yaml
    ports:
      - "127.0.0.1:5601:5601"
```

Further reduce exposure by removing unnecessary published ports after testing.
Do not confuse loopback host publishing with complete container-network isolation.

Require a supported, patched Docker Engine release, at least 28.0.0, because
older releases have a documented same-Layer-2 localhost-publishing limitation.
Version 28.0.0 is a minimum for that specific issue, not a claim that every
28.x release is currently supported or safe.

Replace the UFW/Firewalld allow-all examples with:

```markdown
This lab example intentionally binds published ports to the Docker host's
loopback interface. Do not add broad firewall allowances, router port
forwards, or public reverse-proxy access for these plaintext examples.

Validate the actual Docker networking and host firewall behavior before
using the lab. Do not enable direct routing to the container network.

Remote Windows/Linux agents cannot use these loopback-only host mappings.
The remote-agent sections require a separately designed and tested
TLS-protected ingestion path; they are not ready-to-run instructions for
this local-only configuration.
```

The local Kibana example becomes http://127.0.0.1:5601.
Explain that the browser must run on the Docker host; localhost on a different
computer is not the ELK host.

### 8.3 Required Compose secrets

Within the Compose example only:

| Replace | With |
|---|---|
| ${ELASTIC_PASSWORD:-changeme} | ${ELASTIC_PASSWORD:?Set ELASTIC_PASSWORD in your private .env file} |
| ${KIBANA_PASSWORD:-changeme} | ${KIBANA_PASSWORD:?Set KIBANA_PASSWORD in your private .env file} |

Replace the entire Kibana saved-object encryption-key environment entry with:

```yaml
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${ENCRYPTION_KEY:?Set ENCRYPTION_KEY in your private .env file}
```

Do not apply Compose's :? syntax blindly to mounted Logstash or other application
configuration files. Each application has its own substitution rules.

### 8.4 New disposable-lab secret generation

Replace the sample-password .env section with a local-only creation procedure.
The following code belongs inside the GUIDE, not in a committed .env file.
It requires Python 3 on the lab host.

```bash
python3 - <<'PY'
import os
import secrets

try:
    fd = os.open(".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    raise SystemExit(
        "Refusing to overwrite .env. Existing deployments require "
        "a coordinated credential/key rotation procedure."
    )

with os.fdopen(fd, "w", encoding="utf-8") as stream:
    os.fchmod(stream.fileno(), 0o600)
    for name in ("ELASTIC_PASSWORD", "KIBANA_PASSWORD", "ENCRYPTION_KEY"):
        stream.write(f"{name}={secrets.token_hex(32)}\n")

print("Created private .env; secret values were not displayed.")
PY
```

Required adjacent documentation:

- Every generated value contains 64 hexadecimal characters.
- Do not commit .env, display it in CI, or source an untrusted file as shell code.
- This is a lab convenience, not a production secret-management system.
- Keep encryption keys stable and backed up securely; rotate them deliberately.
- Generating KIBANA_PASSWORD does not set the kibana_system account password.
- Updating .env does not automatically rotate credentials stored in Elasticsearch.
- Do not delete data volumes to reset credentials.
- Audit all other fixed passwords in agent examples and verification commands.

A configuration-only check, without printing resolved secrets:

```bash
docker compose --env-file .env config --quiet
```

For the existing local-lab curl verification example, use a password prompt:

```bash
curl --fail --show-error --user elastic \
  "http://127.0.0.1:9200/_cluster/health?pretty"
```

This is still plaintext HTTP. Do not present it as production-secure access.

### 8.5 Logstash credential wiring — OPEN

The reviewed pipeline uses the elastic superuser and references a password
variable. A Compose .env file does not automatically export every variable into
every container or interpolate every bind-mounted application configuration.

Required implementation:

1. Provision a dedicated ingestion identity or appropriately scoped API key.
2. Scope access to the intended indices/data streams.
3. Derive exact privileges from the selected output-plugin version and its
   template, ILM and data-stream behavior; separate setup from runtime privileges.
4. Deliver credentials through the selected protected secret/keystore mechanism.
5. Update Compose and mounted pipeline configuration together.
6. Remove routine Logstash use of the elastic superuser.
7. Document provisioning and rotation without embedding actual credentials.

For an INTERIM LAB environment-variable implementation, the wiring pattern is:

```yaml
# Merge into the logstash service's existing environment mapping.
# Do not create a second environment key or replace unrelated entries.
LOGSTASH_WRITER_USERNAME: ${LOGSTASH_WRITER_USERNAME:?Set the provisioned ingestion username}
LOGSTASH_WRITER_PASSWORD: ${LOGSTASH_WRITER_PASSWORD:?Set its private password}
```

The corresponding existing Elasticsearch output settings become:

```text
user => "${LOGSTASH_WRITER_USERNAME}"
password => "${LOGSTASH_WRITER_PASSWORD}"
```

These are wiring fragments, NOT a complete output configuration or production
secret solution. Do not paste them into a list-style environment block without
converting the block consistently. The original three-secret generator does
not create or provision this ingestion account: extend the documented setup
only after selecting and testing its identity/provisioning design.

### 8.6 Production release gates — OPEN

- [ ] Select a supported Elastic Stack version and compatible plugins.
- [ ] Pin reviewed images/releases; document digest and update policy.
- [ ] Remove contradictory old version references in Linux and Windows examples.
- [ ] Implement certificate creation, trust distribution, renewal and rotation.
- [ ] Verify TLS on every required client/server and inter-service hop.
- [ ] Do not use disabled certificate verification as a fix.
- [ ] Separate human administration, Kibana system and ingestion identities.
- [ ] Use appropriately scoped service credentials and protected secret delivery.
- [ ] Configure distinct persistent Kibana keys where required for security,
      reporting and encrypted saved objects; test backup and rotation.
- [ ] Remove secrets from process arguments, healthcheck definitions and logs.
- [ ] Complete remote-agent instructions for the actual secured topology.
- [ ] Verify unauthorized requests are rejected and authorized ingestion succeeds.
- [ ] Verify invalid certificates, missing secrets and insufficient privileges fail.
- [ ] Verify intended and unintended interface reachability, including IPv6.
- [ ] Test restart, backup, restore and credential/key rotation without data loss.

Do not label the ELK finding closed merely because the banner or lab bindings
were changed.

---

## 9. R1 — Installer supply-chain and privilege controls

Files:
- Scripts/pnwc_install_tools.sh
- OSINT/Playbook/install_dependencies.sh
- Any installer entry points or documentation that invoke these scripts

Observed patterns included elevated installation, predictable /tmp paths,
downloaded executable content without verification in reviewed paths, and
mutable latest/release/branch references. This is not a claim that all
distribution package-manager verification is absent.

Required changes:

- [ ] Inventory each downloaded artifact, package, source repository and installer.
- [ ] Separate distribution packages from user-level tooling and build operations.
- [ ] Build/install user tools without root; elevate only for narrow operations.
- [ ] Replace predictable shared temporary paths with private mktemp directories.
- [ ] Set restrictive permissions and add safe cleanup/error handling.
- [ ] Pin reviewed versions, commits and artifact identities.
- [ ] Verify authenticated signatures or independently trusted checksums BEFORE
      extracting, executing or installing artifacts.
- [ ] Never invent expected checksums or silently skip verification.
- [ ] Do not execute network responses through curl-to-shell pipelines.
- [ ] Validate archive contents, destinations, permissions and symlink behavior.
- [ ] Detect supported OS/architecture explicitly and reject unsupported targets.
- [ ] Use isolated Python environments; review other ecosystems' lock/verification controls.
- [ ] Preserve actionable failure status without leaking credentials.
- [ ] Document upgrades, rollback and supported configurations.

Failure tests:
- Failed/partial download.
- Invalid signature or checksum.
- Unavailable pinned release.
- Unsupported architecture.
- Concurrent installer runs.
- Pre-existing files and attempted path substitution.
- Insufficient privileges and failed package installation.

Temporary option:
The maintainer may explicitly disable affected installer entry points while
refactoring. Mark this CONTAINED, not FIXED. Explain the compatibility break
in the README and provide no silent unsafe bypass. Do not disable unrelated
entry points or change production machines merely to stage this repository PR.

---

## 10. R5 — Replace executable case state

Primary file: OSINT/Playbook/osint_investigator.sh

### Implementation requirements

- [ ] Replace sourced case-state data with versioned, schema-validated JSON.
- [ ] Never use source, eval, bash or shell command substitution to load case data.
- [ ] Inventory and preserve every required array/scalar field.
- [ ] Validate types, lengths, collection counts and allowed field names.
- [ ] Reject unknown schema versions, duplicate keys and malformed documents.
- [ ] Bind state to the selected case ID.
- [ ] Derive filesystem paths from a validated case root/ID, not imported values.
- [ ] Enforce safe case IDs and contain all paths within the case directory.
- [ ] Require owned/private directories and state files; reject unsafe symlinks.
- [ ] Use secure temporary files and atomic replacement for saves.
- [ ] Validate the entire document before changing active in-memory state.
- [ ] Preserve the previous valid state if saving fails.
- [ ] Propagate save/load failures to menus and reports instead of claiming success.
- [ ] Avoid clobbering existing cases or silently reusing another case's target state.

### Migration and compatibility

Treat JSON migration as a breaking change until proven compatible.

- Preserve originals and make an evidence-preserving backup.
- Refuse legacy executable state by default.
- Provide manual re-entry or a separately reviewed data-only migration tool.
- Never migrate by executing the legacy file.
- Test CLI, web UI, report generation and integration consumers that actually exist.
- Update filenames, requirements and migration instructions in the README.

### API and other configuration

Sourcing API/branding configuration still executes code. Until all consumers
use a data-only format, identify it as trusted local operator configuration,
verify ownership/permissions, and refuse untrusted imported files. Do not claim
that replacing case state fixes every sourced configuration path.

Acceptance tests:
- [ ] Round-trip empty arrays, spaces, quotes, newlines and Unicode.
- [ ] Shell metacharacters remain literal data and execute nothing.
- [ ] Unknown fields, wrong types, oversized input and case-ID mismatch are rejected.
- [ ] Legacy/symlinked/unowned/publicly accessible state is rejected safely.
- [ ] Failed load leaves the active case unchanged.
- [ ] Failed save preserves the previous valid file.
- [ ] Existing workflows have explicit compatibility results.

---

## 11. R8 — Preserve complete evidence and collection failures

Primary file: OSINT/Playbook/osint_investigator.sh

The reviewed collection paths included head-limited h8mail, WHOIS and subfinder
output, plus stderr suppression. Review every collection path rather than
assuming these examples are exhaustive.

Required changes:

1. Capture full stdout and stderr separately before generating previews.
2. Record UTC start/end time, tool/version, safe command metadata and return code.
3. Use collision-resistant artifact directories with restrictive permissions.
4. Preserve timeout/interruption output and mark it partial.
5. Manage subprocesses safely; avoid shell evaluation of target data.
6. Record SHA-256 hashes for raw streams and metadata.
7. Keep originals separate from filtered output and human-readable reports.
8. Do not expose secrets in arguments, metadata, logs or report previews.
9. Report aggregated failures/partial completion accurately in the UI.
10. Enforce retention, storage limits and access controls for sensitive evidence.
11. Verify tool-generated files as well as captured console output.
12. Keep evidence, real targets and API results out of Git and CI artifacts.

Hash manifests detect changes when compared with a trusted record; they are not
by themselves an immutable audit trail or complete chain of custody.

Acceptance tests:
- [ ] At least 1,000 output lines survive intact.
- [ ] Stderr is preserved for both success and failure.
- [ ] Nonzero exit status is recorded and not reported as full success.
- [ ] Timeout/interruption produces clearly marked partial evidence.
- [ ] Hashes match exact stored bytes.
- [ ] Preview filtering cannot truncate original evidence.
- [ ] Concurrent collections do not overwrite each other.
- [ ] Permission and disk-full failures are visible.
- [ ] Synthetic fixtures are used; no live investigation targets are queried.

---

## 12. R9 — CI and GitHub controls

Reviewed workflow: .github/workflows/link-check.yml

### Workflow changes

- [ ] Pin every reviewed third-party action to a verified full commit SHA.
- [ ] Resolve SHAs from the actual upstream repository; do not copy invented
      hashes or leave placeholder SHAs in runnable workflows.
- [ ] Record the corresponding release/tag and update through reviewed PRs.
- [ ] Keep workflow permissions minimal, normally contents: read.
- [ ] Set checkout credential persistence off where not needed.
- [ ] Include relevant workflow/configuration changes in path triggers.
- [ ] Add a manual trigger where useful and explicit timeouts.
- [ ] Do not run untrusted PR code with privileged tokens or secrets.
- [ ] Do not execute installers or privileged/deployment code in ordinary PR checks.
- [ ] Add Bash syntax, reviewed ShellCheck rules and isolated regression tests.
- [ ] Validate Markdown, internal paths/anchors and relevant YAML/config examples.
- [ ] Add redacted secret scanning; never print detected secret values.
- [ ] Distinguish external-link transient/rate-limit failures from content defects.
- [ ] Document justified exceptions rather than silently suppressing failures.

Inspect all workflows before asserting that a check is absent. Add dependency
update configuration only after reconciling any existing configuration.

### Owner-side settings

These cannot be fixed by a Markdown commit:

- [ ] Branch protection/rulesets.
- [ ] Required reviews and status checks.
- [ ] Workflow token/default permissions.
- [ ] Restrictions for outside contributors and privileged workflows.
- [ ] Available secret scanning and push protection.
- [ ] Maintainer access, release/tag protections and disclosure contact.

Record platform/plan limitations rather than claiming unavailable controls exist.

---

## 13. Documentation, privacy and maintenance

Files: README.md, OSINT/Playbook/README.md, STYLE_GUIDE.md,
AUDIT_FINDINGS.md, .gitignore, and affected chapters.

- [ ] Choose canonical source documents for duplicated master-guide content.
- [ ] Generate secondary views where practical; keep links consistent.
- [ ] Correct feature claims that are not demonstrated by implementation/tests.
- [ ] Label commands as read-only, modifying, privileged, destructive or lab-only.
- [ ] Put authorization and operational warnings beside relevant commands.
- [ ] Record tested tool/platform versions, prerequisites and expected output.
- [ ] Add failure handling, validation, rollback and evidence/privacy requirements.
- [ ] Track findings by ID, owner, commit, regression evidence and closure status.
- [ ] Preserve historical audit reports without implying current cleanliness.
- [ ] Remove accidental citation tokens or damaged pasted Markdown.
- [ ] Review .gitignore for local secrets, case state, evidence and generated files.
- [ ] Do not assume .gitignore removes files already tracked or present in history.

Suggested ignore entries, to merge with existing policy rather than overwrite it:

```gitignore
.env
.env.*
!.env.example
.case_state
.case_state.json
OSINT_Cases/
__pycache__/
```

Only sanitized placeholder data belongs in any allowed example file.

Procedure metadata template:

```markdown
- Owner / intended audience:
- Authorization / scope:
- Prerequisites and tested versions:
- Last validation date and evidence:
- Command class:
- Expected output and negative tests:
- Failure handling and rollback:
- Evidence handling, privacy and retention:
- Primary references:
```

### Separate credential concern

The uploaded reference material contained apparent credentials. Their validity
was not tested and public exposure in this GitHub repository was not established.
Handle this privately: if genuine, revoke/rotate them through their providers,
review usage, and restrict further distribution. Do not publish values, partial
tokens, or sensitive incident details in a public PR.

---

## 14. Validation and full-audit completion

All boxes below remain open until supported by actual results:

- [ ] Record exact source and final commit IDs.
- [ ] Inventory all tracked files.
- [ ] Scan the full checkout and complete reachable Git history for secrets.
- [ ] Review every executable/configuration and privileged/destructive example.
- [ ] Run Bash syntax and isolated regression tests.
- [ ] Validate referenced snippets, YAML and Compose configuration.
- [ ] Test installers in disposable environments, never a production workstation.
- [ ] Test ELK in an isolated environment using synthetic data.
- [ ] Validate internal links/anchors and review external-link failures.
- [ ] Check chapter coverage, unsupported claims, duplicates and references.
- [ ] Verify owner-only GitHub settings.
- [ ] Record failures, approved deferrals, owners and remediation deadlines.

A passing syntax check is not a passing runtime test. A green link checker is
not proof that security guidance is correct. A shallow clone is not a complete
history scan.

## 15. Website-only staging workflow

1. Remain on security/review-remediation, or create a new review branch from
   the correct base if that branch has already been merged.
2. Add this document as SECURITY_REMEDIATION_PLAN.md at repository root.
3. Review the branch's existing diff before reapplying any reported changes.
4. Use separate commits for documentation, installer work, ELK work, case-state
   migration, evidence collection and CI.
5. Keep new helper files, callers, tests and migration instructions together.
6. Open a draft pull request targeting the intended base branch.
7. Use GitHub's Checks and Files changed views for review.
8. Obtain real CI/lab results for work that cannot be validated in the editor.
9. Merge only the reviewed, tested scope; leave remaining findings explicitly open.

If the current file differs from an expected snippet, reconcile the change
instead of overwriting the whole file or forcing an old patch.

### Suggested PR body

```markdown
## Scope
Consolidates security remediation for the cybersecurity guide repository.

## Changes included
- [ ] Installer package/counter fixes
- [ ] Authorization and incident-response documentation corrections
- [ ] ELK lab restrictions and explicit secret requirements
- [ ] Validated ELK identity/TLS deployment work, if actually included
- [ ] Installer supply-chain refactor or clearly labeled containment
- [ ] JSON case-state implementation and migration/refusal
- [ ] Complete evidence collection and failure reporting
- [ ] CI and documentation maintenance improvements

## Breaking changes
List changed case formats, installer availability, network bindings,
required secrets, tool versions and integration compatibility.

## Validation
Base commit:
Final commit:
CI run:
Isolated test results:
Deployment results:
Known failures and approved deferrals:

## Remaining work
List finding IDs, owners and deadlines. Do not mark containment as a full fix.

## Rollback
Explain a tested, non-destructive rollback and any data-format limitations.
Do not restore executable untrusted case state or public insecure defaults.
```

## 16. Merge and rollout criteria

- Every changed file is reviewed.
- No real secrets, case evidence or generated private configuration are included.
- Tests relevant to the PR scope actually passed.
- Lab-only restrictions remain unless a separately validated deployment replaces them.
- Compatibility changes and remaining risks are explicit.
- Each closed finding has evidence; unresolved work remains tracked.
- No statement claims a full audit or production approval that was not performed.

Repository rollback and operational rollback are different. Reverting a commit
does not rotate exposed credentials, restore encryption keys, or reverse a data
migration. Plan those operations separately and never destroy data as a shortcut.

## 17. Primary references

These references support the remediation design; consult documentation matching
the versions selected for implementation. They are not evidence that tests passed.

- Sherlock installation: https://sherlockproject.xyz/installation
- OWASP IDOR prevention: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- CIS incident response: https://www.cisecurity.org/controls/incident-response-management
- Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Windows event 4697: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697
- Windows event 4698: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
- Zeek log handling: https://docs.zeek.org/en/current/tutorial/logs.html
- Docker port publishing: https://docs.docker.com/engine/network/port-publishing/
- Compose interpolation: https://docs.docker.com/reference/compose-file/interpolation/
- Compose validation: https://docs.docker.com/reference/cli/docker/compose/config/
- Kibana Docker configuration: https://www.elastic.co/guide/en/kibana/8.12/docker.html
- Elasticsearch built-in users: https://www.elastic.co/guide/en/elasticsearch/reference/8.12/built-in-users.html
- Python secrets: https://docs.python.org/3/library/secrets.html
- GitHub Actions secure use: https://docs.github.com/en/actions/reference/security/secure-use
- NIST SP 800-61 Rev. 3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
