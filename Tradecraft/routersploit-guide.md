# RouterSploit: Embedded Device Security & Controlled Router Assessments

_Upstream repository and available documentation reviewed: 2026-11-21. Modules were not executed._

> [!CAUTION]
> **Authorized lab use only.** RouterSploit includes exploitation and credential-testing modules. Do not run scanners, default-credential attempts or exploits against client, ISP or production devices without a written, device-specific test plan. Embedded devices can crash or lose connectivity. See [Legal Notice](../LEGAL.md).

## Overview & Module Families

[RouterSploit](https://github.com/threat9/routersploit) is a Python-based penetration-testing framework for routers and other embedded devices. The upstream project describes exploit, credential, scanner, payload and generic module families. Use the guide to build an **inventory-to-validation** workflow, with manual firmware/CVE confirmation before any active test.

| Module Family | Intended Role | Key Risk |
|---|---|---|
| Scanners | Evaluate selected vulnerability conditions | False positives, service stress |
| Exploits | Exercise published vulnerability behavior | Instability, configuration damage |
| Creds | Check authentication configurations | Lockout, unintended account access |
| Payloads | Support target-specific payload behaviors | Unauthorized command execution |
| Generic | Reusable protocol/security checks | Variable network impact |

No tool result replaces checking actual firmware, model, patch level, vulnerability prerequisites or exposure.

## Lab & Source Review

Use a spare router or virtualized embedded-services fixture, with a dedicated management VLAN, a reset/reflash path, non-production credentials and no WAN forwarding. Record exact hardware revision, firmware image/hash, test period, network isolation and backup configuration.

Prefer a package from your supported distribution or obtain the upstream source. **Older upstream instructions mention outdated Python environments and dependencies**; validate current compatibility before installation. Do not install an unreviewed dependency stack system-wide.

```bash
# Inspect the checked-out repository and dependency manifest before setup.
git clone https://github.com/threat9/routersploit.git
cd routersploit
git log -1 --oneline
sed -n '1,160p' requirements.txt
```

Only after reviewing the current project state should you choose a supported, disposable Python virtual environment and follow the official installation instructions. A successful installation does not confirm module safety.

## Console Orientation (No Target Activity)

Within a working authorized lab installation, review the console's available commands and module metadata. Command syntax can change with releases; use built-in help.

```text
# In a locally started rsf.py console, inspect commands and modules:
help
show scanners
show exploits
search router
```

The text above illustrates command discovery, **not a scan or an exploitation sequence**. Before selecting any module, inspect its source, prerequisites, network requests and cleanup implications. Do not run automated all-target scanners on a live network.

## Recommended Assessment Workflow

1. **Inventory:** Identify owner, router model, revision, firmware, management interfaces and reachable services.
2. **Scope:** Confirm whether active testing is allowed; for fragile gear prefer a configuration-only review.
3. **Correlate:** Compare version and features to vendor advisories, NVD entries and exploit preconditions.
4. **Lab:** Reproduce only on an isolated matching device/firmware if needed for the remediation decision.
5. **Protect:** Export configuration, confirm recovery image and power/network access before testing.
6. **Report:** Separate scanner assertion, verified observation, tested consequence and untested hypothesis.
7. **Remediate:** Update firmware, rotate device credentials, disable WAN administration, isolate IoT services.
8. **Retest:** Re-verify the corrected configuration using bounded, documented methods.

## Firmware & Finding Validation

| Claim | Required Corroboration |
|---|---|
| "Router is vulnerable" | Exact model/firmware + relevant advisory prerequisites |
| "Port open" | Nmap scan, firewall configuration & service listener |
| "Default credentials" | Vendor documentation, management policy; no unapproved login attempts |
| "Exploit succeeded" | Explicit lab evidence, reproducible conditions, no collateral damage |
| "Fixed" | Firmware/config change, exposure test & documented retest |

## Defensive Hardening

Use supported firmware, disable UPnP/remote administration where unnecessary, isolate management access, monitor outbound DNS and admin logins, back up known-good configurations and replace end-of-life appliances. Where vendor documentation is unclear, avoid assuming a version string alone establishes risk.

## Troubleshooting

| Issue | Safe Next Step |
|---|---|
| Dependency conflicts | Use clean virtual environment; compare supported Python versions |
| Module unsupported | Review source and target preconditions; avoid forcing |
| Device becomes unstable | Stop, restore known-good configuration or factory image |
| Scanner contradicts advisory | Check firmware revision and exploit prerequisites |
| No logs | Enable router syslog or passive traffic monitoring in the lab |

## Related Guides & Official Sources

- [Nmap Guide](../Documentation/nmap-guide.md) — bounded service inventory
- [Network Detection](./network-detection.md) — router traffic & IDS visibility
- [Hardware Hacking Index](../HardwareHacking/README.md) — embedded devices
- [RouterSploit Upstream](https://github.com/threat9/routersploit) & [Kali Tool Reference](https://www.kali.org/tools/routersploit/)

---

[Tradecraft Index](./README.md) | [Start Here](../START_HERE.md) | [Legal Notice](../LEGAL.md)
