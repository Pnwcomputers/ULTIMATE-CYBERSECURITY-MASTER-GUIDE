# OSINT Investigator — Troubleshooting & Failure Diagnosis

[OSINT Index](../README.md) · [FAQ](FAQ.md) · [Installation](INSTALLATION.md) · [Compatibility](COMPATIBILITY.md) · [Investigator Playbook](../Playbook/README.md)

**Scope:** This supports the partially implemented OSINT Investigator toolkit as documented in November 2026. It does not establish that a third-party service, optional package, or every platform works today. Use authorized systems and keep all client records private.

## Safe Initial Checks

From the repository root, inspect commands and local dependencies without submitting any lookup:

```bash
pwd
test -f OSINT/Playbook/osint_investigator.sh && echo "Main script present"
bash -n OSINT/Playbook/osint_investigator.sh
bash OSINT/Playbook/osint_investigator.sh --help
bash OSINT/Playbook/osint_investigator.sh --status
python3 --version
command -v curl || true
```

Use an ordinary, non-root account. Do not run the installer with `sudo` to work around a failing tool: the documented installer may request scoped permission for individual system operations.

## Diagnose By Symptom

| Symptom | Verify & Correct | Result Classification |
| --- | --- | --- |
| Main script not found | Check working directory and exact case-sensitive path `OSINT/Playbook/osint_investigator.sh` | Checkout/path failure |
| Permission denied launching a script | Try `bash <script>` for a readable shell script; do not broadly change permissions or ownership | Launch failure |
| `python3`, `curl`, or an optional collector missing | Check `command -v <tool>` and [installation documentation](INSTALLATION.md). Only install approved dependencies | Collector unavailable, not a negative lookup |
| Collector marked `not_run` | Inspect evidence metadata and confirm the optional binary and approved case indicators exist | Not executed |
| Collector marked `partial` | Review `*.stdout`, `*.stderr`, `*.meta.json`, exit code, timeout and output-size limit | Incomplete, not a clean result |
| Empty provider match | Check input validity, service scope and corroborating sources | Cannot conclude absence or identity |
| HTTP 401/403 | Verify account access, approved config and provider policies without printing tokens | Authorization/access failure |
| HTTP 429 | Observe rate limits and record a deferred query rather than bypassing controls | Rate limited |
| WHOIS, DNS or HTTPS RDAP error | Check general connectivity, certificate/time and exact stderr; record the provider and failed call | Unavailable/failed lookup |
| Old case cannot load | Legacy executable `.case_state` is deliberately rejected; follow the current JSON case workflow | Old state must not be sourced |
| Numbered reports 1–5 do nothing | See [feature matrix](../Playbook/README.md#actual-feature-status); the numbered report entries are not wired | Unimplemented |
| `--web` or Web menu fails | `web_interface.py` is absent from this repository | No working web UI shipped |
| IP results do not show location | Current main IP routine uses HTTPS RDAP for registration details, **not geolocation** | Expected scope limitation |

## Evidence & Privacy

The toolkit documents local case folders under `~/OSINT_Cases` and user-restricted JSON state. A case record or output hash alone does not independently certify its source. Before interpreting a result, review its raw stdout/stderr, metadata, status, UTC timestamps, provider and collection limits. Treat `partial`, `not_run`, missing data, or failed calls as **unverified**, never as a confirmed negative finding.

Optional providers may receive searched IPs, emails, domains, usernames and other indicators. Confirm the provider's terms and the engagement's scope and privacy requirements before any external request.

Use the documented configuration flow and protect private settings (including `~/.config/osint-investigator/api_keys.conf` where applicable). Do not paste API keys, real names, client data, contact details, raw captures, or private case files into public issues.

## Escalate With A Reproducible Report

If the problem persists, open a [GitHub issue using an appropriate template](../../.github/CONTRIBUTING.md#-reporting-issues). Provide the OS and tool versions, the exact **redacted** command, exit code, observed vs expected result, relevant sanitized stderr, and whether evidence was marked `complete`, `partial`, or `not_run`.

**Related:** [Investigator Feature Matrix](../Playbook/README.md#actual-feature-status) · [Manual Investigation Guide](../Playbook/investigation_guide.md) · [Verification Protocol](../../Documentation/REPOSITORY-VERIFICATION-PROTOCOL.md).
