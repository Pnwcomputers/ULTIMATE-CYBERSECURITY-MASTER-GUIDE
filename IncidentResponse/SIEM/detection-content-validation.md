# Detection Engineering: Sigma, Elastic and Wazuh

_Last reviewed: 2026-11-02 (source mapping; no rules deployed)_

**Prerequisites:** [SIEM index](README.md) · [Endpoint visibility](../Endpoint-Visibility/README.md) · [Purple Team exercises](../../PlayBooks/purple-team-detection-validation.md).

## Sources by role

| Project | Reference application |
| --- | --- |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Detection logic, logsource definitions, rule IDs, metadata and ATT&CK tags |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | Elastic-specific query implementations and testing conventions |
| [osquery defense kit](https://github.com/chainguard-dev/osquery-defense-kit) | Defensive endpoint queries; verify performance, privileges and OS compatibility |
| [Falco rules](https://github.com/falcosecurity/rules) | Container/runtime threat signals, not native Wazuh or Sigma rules |
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique and telemetry mapping, not proof a rule will fire |

## Repeatable test and promotion workflow

1. Define the malicious or suspicious behavior, required sensors and minimum observable event fields.
2. Pin upstream repository commit/rule UUID and inspect individual license, prerequisites, exclusions and known false positives.
3. Confirm the field names and logs **actually ingested** by your platform. Wazuh decoder/rule XML, Elastic EQL/KQL, Splunk SPL and Sigma YAML are not interchangeable.
4. Convert or reimplement logic for the supported backend; review comparisons, regex, case, time window and aggregation semantics.
5. Test with sanitized positive and negative samples in a dedicated lab. Validate expected alert level, decoder, service integration and timestamps.
6. Simulate missing fields or agent disconnection; record as **not observable**, not secure.
7. Adjust sensitivity, suppression and severity with written rationale, peer review and regression tests; version native rules and keep rollback.
8. Document detection coverage, evidence and owner. Link remediation to [findings management](../../PlayBooks/assessment-findings-lifecycle.md).

| Test | Pass criteria |
| --- | --- |
| Positive event | Correct decoder and intended alert fires |
| Negative/benign event | No incorrect high-priority alert |
| Missing field | Predictable failure, gap documented |
| Sensor offline | Health alert or acknowledged loss of visibility |
| Correlation | Correct timestamps, event identity and confidence |

## PNWC sensor integration

Treat [Snort](../IDS%26IPS/snort.md), [Kismet](../IDS%26IPS/kismet-wazuh-wireless-lab.md), [nzyme](../IDS%26IPS/nzyme-wazuh-integration.md), [Wazuh](wazuh.md) and [honeypots](../HoneyPot/wazuh-honeypot-integration.md) as separate producers. Record normalization and time-skew assumptions before correlating. A VM on an unmanaged switch does not automatically see all LAN traffic without SPAN/TAP/router mirroring.

## Provenance

SigmaHQ and Elastic rules may have separate repository/file license terms: check before importing. [Falco rules](https://github.com/falcosecurity/rules) and [osquery defense kit](https://github.com/chainguard-dev/osquery-defense-kit) provide Apache-2.0 components. This guide does not import or deploy any rule.

---

[SIEM index](README.md) · [Main guide](../../README.md) · [Legal terms](../../LEGAL.md)
