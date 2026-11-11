# Wazuh Synthetic Rule Validation & Recovery

_Reviewed: November 11, 2026. **Expected values below are not observed Wazuh results.**_

## Purpose

The November 2026 source review identified malformed Wazuh rule XML: rule `100340` (Kismet correlation) was embedded inside a `<group>` label of rule `100300`, and rule `100402` (ESP32 honeypot) inside the label of rule `100400`. Both have been moved to direct child rules, with text-only group labels.

The [new offline rule regression test](../tools/tests/test_wazuh_rule_contracts.py) checks XML structure, unique SIDs, parent references and synthetic positive/negative field regex behavior. **This is not a Wazuh manager, an accurate emulation of frequency/window matching, or proof of an EDR alert.** A real manager evaluation requires authorized, isolated access and the installed engine version.

| Installed Rule File | Expected Event Family | Relevant Candidate SIDs |
|---|---|---|
| [Kismet & PCAP](../IncidentResponse/IDS&IPS/kismet-wazuh/kismet_wids_rules.xml) | Kismet alert, passive disconnect burst and correlated summary | 100301, 100340, 100331 |
| [nzyme](../IncidentResponse/IDS&IPS/nzyme-wazuh/nzyme_wids_rules.xml) | Normalized nzyme events | 100352, 100354 |
| [Honeypot](../IncidentResponse/HoneyPot/lab/honeypot_rules.xml) | DIY HTTP / ESP32 / OpenCanary / Cowrie | 100400, 100401, 100402 |

## Offline Preflight

~~~bash
python3 -B -m unittest discover -s tools/tests -v
python3 -B -m unittest discover -s 'IncidentResponse/IDS&IPS/kismet-wazuh' -p 'test_*.py' -v
python3 -B -m unittest discover -s 'IncidentResponse/IDS&IPS/nzyme-wazuh' -p 'test_*.py' -v
python3 -B -m unittest discover -s 'IncidentResponse/HoneyPot/lab' -p 'test_*.py' -v
~~~

Expected: the tests pass on the commit being reviewed. A test passing here does not establish that Wazuh recognizes the rules.

## Real Wazuh Manager Test: Authorized Isolated Lab Only

1. Record written authorization, Wazuh release, host OS/kernel, installed ruleset revision, exact repository commit and SHA-256 of each test XML file. Ensure IDs 100300–100354 and 100400–100423 do not collide with local rules.
2. Snapshot the canary VM and back up its current local rules. Do **not** overwrite production rules. Inspect and copy only the reviewed custom files into the lab manager's `/var/ossec/etc/rules/` according to the [Wazuh custom rules instructions](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).
3. Run `sudo /var/ossec/bin/wazuh-logtest` interactively on the lab manager; paste **one** synthetic JSON line at a time from the examples below. Capture the actual matching rule ID and severity, parse errors and exit behavior. If the manager fails to load a rule, investigate before deploying it.
4. Test at least one unrelated/benign JSON event, check that no high-severity custom alert is generated, and record negative outcomes as well as positive outcomes.
5. Only in an approved change window, perform any restart/reload required by the actual installed Wazuh version. Send a synthetic JSONL event from an enrolled canary agent and verify ingestion, timestamp, source, actual manager rule ID, final dashboard alert, and absence of the equivalent alert for the benign fixture.
6. On any unexpected high-severity match, parse failure or lost telemetry, restore the backed-up files and VM snapshot. Confirm normal ingestion and log the rollback/cleanup completion.

## Synthetic Logtest Inputs

Each line is an **independent** test event, not an array, and all identifiers are synthetic:

~~~json
{"wids":{"integration":"kismet","event":"DEAUTHFLOOD","bssid":"02:11:22:33:44:55","sensor":"synthetic-kismet"}}
{"wids":{"integration":"kismet","event":"CHANCHANGE","bssid":"02:11:22:33:44:55","sensor":"synthetic-kismet"}}
{"wids":{"integration":"correlator","event":"KISMET_PCAP_CORRELATED","sensor":"synthetic-correlator"}}
{"wids":{"integration":"nzyme","category":"disconnect_anomaly","event":"SYNTHETIC_WIDS_DISCONNECT_ANOMALY"}}
{"wids":{"integration":"nzyme","category":"system_event","event":"SOME_SYSTEM_EVENT"}}
{"honeypot":{"integration":"diy_http","event":"http_probe","method":"GET","sensor":"synthetic-decoy"}}
{"honeypot":{"integration":"diy_http","event":"http_probe","method":"POST","sensor":"synthetic-decoy"}}
{"honeypot":{"integration":"esp32_serial","event":"tcp_connection","sensor":"synthetic-esp32"}}
{"wids":{"integration":"unrelated","event":"DEAUTHFLOOD"}}
~~~

| Synthetic Case | Expected SID/Severity (Must Confirm In Real Manager) | Negative Check |
|---|---|---|
| Kismet DEAUTHFLOOD | 100301 / 10 | CHANCHANGE should not match 100301 |
| Kismet CHANCHANGE | 100308 / 5 | Not a deauth alert |
| Related Kismet + PCAP summary | 100340 / 12 | Correlation is not independent proof of an attack |
| nzyme disconnect anomaly | 100352 / 10 | System event should not match 100352 |
| nzyme system event | 100354 / 5 | Not a disconnect alert |
| DIY decoy GET | 100400 / 3 | Not higher-risk write method |
| DIY decoy POST | 100401 / 7 | Compare with GET result |
| ESP32 decoy metadata | 100402 / 5 | Does not prove real ESP32 was observed |
| Unrelated WIDS integration | No matching custom WIDS SID | No false-positive high-severity WIDS alert |

**Observed results: Not tested.** Wazuh may reject the rule configuration or select a different final rule, so these expectations are explicitly not a claim of actual manager outcomes. Document any discrepancy instead of fabricating an alert.

## Private Evidence Template

| Field | Status To Enter |
|---|---|
| Written lab scope, operator and UTC test date | Not recorded in this public guide |
| Wazuh version, OS, rule checksum and git revision | Not tested |
| Actual positive and benign-negative logtest outputs and SIDs | Not tested |
| Actual SIEM agent, manager and dashboard events | Not tested |
| False positives, dropped events and alert latency | Not tested |
| Change approval, cleanup and rollback | Not performed |
| Physical radio, ESP32/Pi device and monitor visibility | Not tested |

Keep all private infrastructure, real BSSIDs, customer identities, tokens and forensic alerts out of this public repository.

---

[Lab Verification Matrix](LAB-VERIFICATION-MATRIX.md) · [Documentation Index](README.md) · [Verification Protocol](REPOSITORY-VERIFICATION-PROTOCOL.md)
