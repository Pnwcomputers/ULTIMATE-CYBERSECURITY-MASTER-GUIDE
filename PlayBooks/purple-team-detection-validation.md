# Purple Team Detection Validation: Atomic Red Team, Sigma and Wazuh

_Last reviewed: 2026-11-02 (references only; no attack simulations run)_

> [!CAUTION]
> Use **isolated, client-approved test systems** only. Obtain written authorization,
> select non-destructive tests, review commands and prerequisites, keep a rollback
> image and notify defenders. Some Atomic Red Team tests are destructive or alter
> security controls: never run tests merely because they are in a public directory.

**Prerequisites:** [Detailed Purple Team Playbook](PurpleTeam_Detailed.md) ·
[SIEM index](../IncidentResponse/SIEM/README.md) ·
[Endpoint Visibility](../IncidentResponse/Endpoint-Visibility/README.md).

## A repeatable detection experiment

1. Choose one control gap and MITRE ATT&CK technique from a **current**
   [ATT&CK technique](https://attack.mitre.org/) page.
2. Select an [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
   definition and **read its test command, prerequisites, cleanup and platform
   support in full**. Prefer harmless, synthetic, reversible behavior.
3. Record baseline host configuration, time synchronization, Sysmon/auditd,
   process and network telemetry. Confirm Wazuh/Elastic/Splunk ingest first.
4. Map expected telemetry to one or more
   [Sigma rules](https://github.com/SigmaHQ/sigma) and compare with
   [Elastic detection rules](https://github.com/elastic/detection-rules).
   Sigma rules are detection logic, **not** directly executable Wazuh rules;
   use supported conversion, test output and platform-specific rewrites.
5. Run the selected test on a disposable VM under the approved window.
   Record test ID, timestamp, host, user, source commit, rule/engine version.
6. Correlate the observable events. Record whether the detection fired, when,
   what event fields were present and why a miss happened.
7. Clean up and restore the baseline; validate no accounts, persistence,
   exclusions or test files remain.
8. Adjust detections and rerun with an independent negative/benign scenario
   to measure false positives. Submit final results to the
   [findings lifecycle](assessment-findings-lifecycle.md).

## Validation worksheet

| Field | Example of what to record |
| --- | --- |
| Authorization | ROE reference, approved lab scope and operator |
| Technique | ATT&CK ID + definition version/URL |
| Test | Atomic test ID, repository commit and safety review |
| Evidence | Host/time, Sysmon/auditd event, Wazuh alert ID, sanitized log URI |
| Detection logic | Sigma UUID/commit or native rule ID, field mapping, backend |
| Results | Expected event? Ingested? Rule matched? Alert delivered? |
| Quality | True positive, false negative or inconclusive; benign negative controls |
| Follow-up | Tuning owner, regression test, retest date |

## Important SIEM integration distinctions

- A rule's existence does **not** prove a functioning sensor; ensure events
  reach the correct index/decoder and survive field normalization.
- Logs can be missing due to agent configuration, time drift, log rotation,
  dropped network packets or inadequate permissions.
- Alert severity should reflect source confidence and impact; keep an
  auditable reason for each mapping and threshold.
- For wireless workflows, correlate with
  [Kismet Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md),
  [nzyme](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) and
  [Snort](../IncidentResponse/IDS%26IPS/snort.md); these are **independent**
  detection pipelines and may lack common event fields.

## Sources

- [Red Canary Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT);
  [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
  is an optional PowerShell execution framework, not a required installation.
- [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma) (license varies by
  components; review repository license before reuse).
- [Elastic detection rules](https://github.com/elastic/detection-rules)
  (review source license and individual rule notes).
- [MITRE ATT&CK](https://attack.mitre.org/).
- [Wazuh deployment](../IncidentResponse/SIEM/wazuh.md) ·
  [SIEM hub](../IncidentResponse/SIEM/README.md).

**Integration status:** methodology and links only; no rules or tests were
automatically imported, run or deployed on PNWC/client systems.

---

[Playbooks](README.md) · [Main README](../README.md) · [Legal notice](../LEGAL.md)
