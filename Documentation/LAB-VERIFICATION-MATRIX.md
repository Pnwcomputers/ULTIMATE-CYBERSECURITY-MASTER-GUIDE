# Lab, SIEM/EDR & Hardware Verification Matrix

_Opened: November 11, 2026 · This is an evidence ledger and reproducible acceptance plan, **not** proof that these deployments work in a current environment._

## Interpretation & Evidence Tiers

**Static only** means syntax, documentation or a specific isolated fixture may be checked; **lab blocked** means no real device/SIEM/provider outcome has been provided; **external provider required** means an authorized API tenant, version and credentials are required. Do not copy a successful source parser status onto network coverage, a physical radio, a live endpoint agent or a customer device.

This matrix inventories high-use **canonical guides** and separates observed, supported evidence from still-required experiments. Dates below refer to *inventory review*, not runtime verification. For a live test to count, use the record template below and link the sanitized evidence **only** if it contains no private deployment details. Keep client names, internal IPs, raw alerts and credentials in secure engagement records.

## Initial Procedure Inventory

| Canonical Procedure | Evidence Available | Unverified Condition / Acceptance Experiment | Current Status |
|---|---|---|---|
| [OSINT Case Investigator](../OSINT/Playbook/README.md) | Isolated shell fixtures in [hardening tests](../tests/hardening/test_osint_investigator.py) cover named behavior | Current registry/API network response, rate limits, actual report quality and consent | Static fixture only |
| [Kismet → Wazuh Wireless Alerts](../IncidentResponse/IDS&IPS/kismet-wazuh-wireless-lab.md) | Source/configuration and synthetic bridge fixtures exist | Kismet release, capture chipset, firmware, monitor mode, real 802.11 frames, end-to-end Wazuh ingestion and rule firing | Lab blocked |
| [nzyme → Wazuh](../IncidentResponse/IDS&IPS/nzyme-wazuh-integration.md) | Guide and local adapter/config content | nzyme version, webhook semantics, signature, TLS, observed source/destination timestamps, false-positive handling | External provider / lab blocked |
| [Suricata & Zeek](../IncidentResponse/IDS&IPS/suricata+zeek.md) | Documentation and example detection configuration | Verified TAP/SPAN visibility, sensor interface, IDS ruleset revision, PCAP replay and actual alert + Zeek log correlation | Lab blocked |
| [Wi-Fi Disconnect Detection](wifi-deauthentication-detection.md) | Defensive detection guidance and filter examples | 802.11 frame capture, PMF state, negative benign disconnect fixtures, severity fidelity in SIEM | Lab blocked |
| [Graylog Deployment](../IncidentResponse/SIEM/graylog.md) | Historical Docker example (Graylog 5.2; OpenSearch 2.12.0) | Supported version/migration, TLS, secrets, inputs, index writes, alert-to-notification chain | Historical; not deployment-verified |
| [Elastic SIEM/ELK](../IncidentResponse/SIEM/elk_stack.md) | Example compose/health check procedure | Current image compatibility, secure account setup, ingestion, query/rule results and recovery after restart | Lab blocked |
| [Snort/IDS Integration](../IncidentResponse/IDS&IPS/readme.md) | Architectural guides | Actual mirrored traffic reaching monitored interface; rule and SIEM event chain with timestamped capture | Lab blocked |
| [DIY Sensor Honeypot](../IncidentResponse/HoneyPot/diy-sensor-lab.md) | Local-only demonstration instructions | Isolated canary health-check, synthetic hit, JSONL/event schema validation, Wazuh intake, cleanup | Lab blocked |
| [Raspberry Pi Honeypot](../IncidentResponse/HoneyPot/raspberry-pi-honeypot-lab.md) | Hardware setup procedure | Specific Pi model, OS kernel, network segmentation, capture, watchdog and SIEM correlation | Hardware blocked |
| [NanoVNA](../SDR/nanovna/README.md) | [Fixture test runner](../SDR/nanovna/testdata/run_tests.sh) for lab files | Actual model, calibration standards, firmware, connection, measured sweep against known reference and RF safe handling | Fixtures only; hardware blocked |
| [ESP32 Security Firmware](esp32-security-firmware-catalog.md) | Catalog/source metadata only | Exact board revision, bootloader/flasher release, backup/recovery, passive receive test, approved RF scope | Hardware blocked |
| [M5StickC Plus2](../HardwareHacking/m5stickc-plus2-hackstarterpack.md) | Source and board guidance | Actual display/IR/RF peripherals, battery, firmware compatibility and reset/recovery | Hardware blocked |
| [PowerShell Port Scanner](../Scripts/PowerShell/port_scanner.ps1) | Source parser checks; bounds corrected | Owned loopback listener, refused/timeout paths, DNS errors, timeouts, outbound-scope control and observed PowerShell version | Static syntax only |
| [AnythingLLM CVE Lookup](../AI/AnythingLLM/flow-cve_lookup.md) | Reviewed reference and risk boundaries | Actual NVD/CISA/FIRST provider responses, valid JSON parsing, stale/unknown values, no invented remediation | External provider required |
| [Data Engineering Fixtures](../Data-Engineering/README.md) | CI calls [offline runner](../tools/run_data_labs.py) | External broker/store and real telemetry behavior, ingestion latency, security of credentials and rollback | Static/fixture only |

## Repeatable Test Sequence

1. **Approve scope:** record named operator, authorization window, written owner approval, isolated lab network, allowed simulated activity, stop conditions, and emergency contact. A fixture is not approval for external or production targeting.
2. **Baseline:** record OS/kernel, device model and revision, firmware/build, SIEM/EDR release, ruleset ID/revision, time sync, listening interfaces, monitoring points, target host, and expected sensor visibility. Use artificial IDs and RFC 5737 documentation addresses in public examples.
3. **Positive test:** feed an approved PCAP or synthetic event into the pipeline; document event/alert time, log fields, source component, collector, rule identifier, rule version, and exact expected/observed detection. Do not automatically execute LLM-generated exploit code.
4. **Negative/benign test:** supply similar harmless activity and empty/invalid input; measure false positives, dropped events, parse errors, crash/retry behavior and missing telemetry. A positive alert with zero negatives is insufficient to rate the rule effective.
5. **Score:** score separately for **sensor visibility**, **telemetry completeness**, **rule trigger**, **correlation/context**, **latency**, and **false-positive behavior**. Use `observed/failed/not-tested` for every dimension instead of manufacturing a composite detection percentage.
6. **Cleanup & sign-off:** record final state, disable test accounts, stop temporary listeners, delete synthetic artifacts per retention policy, roll back agent/rule changes, and have a human approve deployment or mark it blocked.

## Copyable Per-Test Record (Fill Privately For Client Systems)

| Field | Operator Entry |
|---|---|
| Lab/engagement authorization and scope | **Required before executing; store sensitive details privately** |
| Guide path and exact Git commit | **Not recorded — supply commit under test** |
| Test ID, operator and UTC date | **Not tested — fill on execution** |
| Device/VM model, OS, kernel and firmware | **Not tested — identify exact versions** |
| SIEM/EDR and detection rule/version | **Not tested — name product/build and rule ID** |
| Positive synthetic fixture and checksum | **Not recorded — use approved non-sensitive fixture** |
| Benign/negative fixture and checksum | **Not recorded — must be independently reviewed** |
| Expected alert source, fields and severity | **Not recorded — derive from tested rule, not a guess** |
| Observed source/collector/alert timestamps | **Not tested — preserve redacted evidence privately** |
| Detection/false positive/false negative results | **Not tested — specify sample sizes** |
| Telemetry gaps and vendor/API limitations | **Not tested — document failures too** |
| Rollback, data retention and cleanup | **Not performed — document exact completion** |
| Approval and next action | **Awaiting authorized operator review** |

## Evidence & Publication Policy

Only anonymized fixture outputs, SHA-256 checksums of synthetic data, public documentation references, scoped test commands and non-sensitive summarized outcomes belong in this repository. Do not publish client log streams, telemetry containing personal data, deployment-specific addresses, tokens, proprietary SIEM rules or detailed exploitation output.

This is the starting work product for [issue #190](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/190). The issue is **not closed** until specific hardware/vendor/SIEM tests have been performed and reviewed by an authorized operator.

---

[Documentation Index](README.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md) · [Maintenance Operations](REPOSITORY-MAINTENANCE-OPERATIONS.md)
