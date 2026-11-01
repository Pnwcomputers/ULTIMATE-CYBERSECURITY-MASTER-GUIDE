# Honeypot Telemetry in Wazuh: OpenCanary, Cowrie, DIY and IoT

_Last reviewed: 2026-10-31 · Reference configuration, NOT live deployment_

> [!CAUTION]
> Put decoys on isolated, controlled networks with **deny-by-default outbound access**. Restrict management to a separate administrative network. Do not execute captured payloads. Telemetry contains IP addresses, usernames and potentially passwords: limit access, retention and sharing.

## Architecture

~~~text
Decoy VLAN / isolated vNIC
   ├─ Raspberry Pi → OpenCanary JSONL
   ├─ Proxmox VM  → Cowrie JSONL
   ├─ Pi / VM     → DIY minimal HTTP sensor JSONL
   └─ ESP32       → local/on-device log; OPTIONAL trusted relay
             |
       Wazuh agents on Linux decoys
             | encrypted enrolled agent channel
       Wazuh manager + rule IDs 100400-100423
             |
       Wazuh alerts, dashboard and incident timeline
             |
       correlate with Kismet/nzyme WIDS + UniFi/controller logs
~~~

**Avoid an unnecessary forwarder** when the honeypot already writes newline-delimited JSON. Wazuh supports a JSON localfile directly on an enrolled agent. The included [XML custom rules](./lab/honeypot_rules.xml) match actual documented OpenCanary and Cowrie fields, and a [minimal DIY HTTP logger](./lab/diy_http_decoy.py) outputs a namespaced honeypot JSON object.

## Log sources: actual format and limitations

| Source | Native event shape | Wazuh integration | Notes |
| --- | --- | --- | --- |
| OpenCanary | node_id, logtype (integer), src_host, dst_port, logdata | Direct JSON localfile | Logdata can contain **credentials** |
| Cowrie | eventid, sensor, session, src_ip, timestamp and event-specific fields | Direct JSON localfile | Sessions may include passwords, typed commands, captured artifacts |
| Minimal DIY HTTP decoy | honeypot.integration = diy_http, method, path, src_ip | Direct JSON localfile | Does not record query strings, headers except limited user-agent, or POST bodies |
| Dionaea | Version- and handler-specific structured output | Configure and verify log_json first | Do not pretend its SQLite log is JSON; never run captured files |
| HoneyPi | Scripts / PSAD / syslog depend on fork/version | Prefer host Wazuh agent and verified format | Inspect installed project, not the unrelated beehive-monitoring repository |
| T-Pot | Own Docker/Elastic ingestion, multi-sensor logs | Separate curated export / agent on approved feed | Avoid two conflicting OpenSearch pipelines and duplicate storage |
| NanoC6/ESP32 | Project's Discord-style JSON content field or on-device SPIFFS | **Not directly compatible** with this native JSON ruleset | An authenticated, schema-validated relay is needed; see [ESP32 guide](./esp32-diy-honeypots.md) |

Authoritative schemas: [OpenCanary setup and sample JSON](https://github.com/thinkst/opencanary/blob/master/docs/starting/opencanary.rst), [OpenCanary event codes](https://github.com/thinkst/opencanary/blob/master/opencanary/logger.py), [Cowrie output event codes](https://docs.cowrie.org/en/stable/OUTPUT.html) and [Wazuh JSON logcollector](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).

## 1. Configure direct collection

### OpenCanary on the Raspberry Pi or VM

First make sure the OpenCanary logger writes **one JSON object per line** to a protected file and verify with a real local test, rather than assuming all stdout or syslog messages are JSON.

Example logger handler inside its existing JSON config:

~~~json
"logger": {
  "class": "PyLogger",
  "kwargs": {
    "formatters": {"plain": {"format": "%(message)s"}},
    "handlers": {
      "file": {
        "class": "logging.FileHandler",
        "filename": "/var/log/opencanary/opencanary.log",
        "formatter": "plain"
      }
    }
  }
}
~~~

This is a **fragment**, not a replacement for the full OpenCanary JSON config. Create the directory, set ownership to the actual OpenCanary service account, and verify the service can write it. Use your actual configured path; the older reference guide uses /var/tmp/opencanary.log.

Wazuh agent on the **same host**, inside the existing ossec_config root in /var/ossec/etc/ossec.conf:

~~~xml
<localfile>
  <location>/var/log/opencanary/opencanary.log</location>
  <log_format>json</log_format>
</localfile>
~~~

### Cowrie on Pi, VM or mini PC

Cowrie's supported Python virtualenv install writes **var/log/cowrie/cowrie.json** relative to its initialized work directory, according to the [official Cowrie guide](https://docs.cowrie.org/en/stable/README.html). Use the actual absolute directory for the existing Cowrie account. Example:

~~~xml
<localfile>
  <location>/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json</location>
  <log_format>json</log_format>
</localfile>
~~~

Cowrie eventid types include cowrie.session.connect, cowrie.login.failed, cowrie.login.success, cowrie.command.input, cowrie.session.file_download and cowrie.session.file_upload. Logs may carry attacker-supplied credentials: restrict access; avoid posting complete real records to support tickets or public dashboards.

### DIY low-interaction HTTP decoy

After reviewing [the DIY guide](./diy-sensor-lab.md), use:

~~~xml
<localfile>
  <location>/var/log/honeypot/http.jsonl</location>
  <log_format>json</log_format>
</localfile>
~~~

The DIY listener starts on localhost and must be **explicitly** bound to its isolated decoy NIC for a network test. It never implements a shell, upload or executable content.

On each Linux decoy, restart the **existing** Wazuh agent after editing configuration, then verify it is enrolled:

~~~bash
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent --no-pager
~~~

## 2. Wazuh custom rules on the manager

Custom Wazuh IDs **100400–100423**, separate from the Kismet 100300–100340 and nzyme 100350–100354 ranges. Confirm there are no collisions with local rules before installation.

On the **Wazuh manager** (native/package deployment):

~~~bash
sudo install -m 0640 \
  'IncidentResponse/HoneyPot/lab/honeypot_rules.xml' \
  /var/ossec/etc/rules/honeypot_rules.xml
sudo /var/ossec/bin/wazuh-logtest
# Paste ONE JSON line from lab/synthetic-events.jsonl.
sudo systemctl restart wazuh-manager
~~~

For a Docker Wazuh manager, mount the file into its **persistent** rules configuration, and use the manager's supported container test/restart commands.

| Rule | Level | Condition | Interpretation |
| --- | --- | --- | --- |
| 100400 | 3 | DIY HTTP contact | Baseline evidence of decoy contact |
| 100401 | 7 | DIY POST, PUT, PATCH, DELETE | Unexpected request method |
| 100410 | 5 | OpenCanary JSON log with node_id and numeric logtype | Potential probe or configured service activity |
| 100411 | 7 | OpenCanary selected login-related codes | Credential-attempt investigation |
| 100420 | 3 | Cowrie eventid starts cowrie. | Session/context |
| 100421 | 7 | Cowrie authentication event | Emulated auth attempt |
| 100422 | 10 | Cowrie file upload/download into decoy | Preserve/quarantine artifact |
| 100423 | 7 | Cowrie fake-shell command entered | Session investigation |

These are *investigation priorities*, not proof of maliciousness. Normal vulnerability scanners, backup/inventory agents and your own testing may trigger them. Higher levels depend on corroboration with asset/maintenance records.

The sample fixtures use **RFC 5737 documentation IPs** and synthetic hostnames. Do not ingest sample fixtures into production alert streams without labeling and isolating the test.

For Wazuh JSON field matching and validation: [rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), [custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html), [wazuh-logtest](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).

## 3. A shared deception and WIDS dashboard

In the Wazuh Dashboard search indexed alerts using **wazuh-alerts-*** or your installed pattern and a suitable time range.

| Panel | Filter and fields |
| --- | --- |
| Deception events over time | rule.groups includes honeypot, date histogram |
| Severity / investigation priority | rule.level by rule.groups |
| Cowrie sessions | eventid / session, src_ip (actual indexed fields) |
| OpenCanary service activity | node_id / logtype / src_host / dst_port |
| DIY HTTP events | data.honeypot.integration, data.honeypot.src_ip |
| WIDS context | rule.groups includes wireless_wids, source Kismet or nzyme |
| Case correlation timeline | common time window, sensor/site inventory, controller/endpoint logs |

Actual indexed paths **can vary** with Wazuh version and decoder representation; check a real Wazuh alert before saving a terms aggregation. Use keyword variants if required. Do not invent an existing exported dashboard artifact.

### Correlation examples

- **Potential lateral movement:** A managed workstation's IP contacts an internal decoy SMB/SSH service, shortly after an endpoint/Wazuh alert. Review inventory, health checks, scan schedules, NAC and endpoint telemetry.
- **Wireless plus decoy:** Kismet DEAUTHFLOOD or nzyme monitored-network anomaly near a Cowrie session from a client IP. This is *time coincidence*, not attack attribution. Verify AP/client/controller evidence, network addressing, NAT and station association.
- **External internet scan:** A public source attempts Cowrie logins. Common background noise, not automatic incident.
- **Artifact transfer:** Cowrie logs a sample. Alert level 10; store under least privilege, hash and quarantine, do not execute. Consult [DFIR](../Digital-Forensics/README.md).

No simplistic source-IP matching across Wi-Fi and Ethernet proves that a wireless transmitter also touched the honeypot. MAC spoofing and NAT make unsupervised joins unreliable.

## 4. Validation and troubleshooting

1. Run the repository's unit tests (see [DIY lab](./diy-sensor-lab.md)).
2. On the Wazuh manager use wazuh-logtest on each synthetic JSON fixture. Confirm the intended rule ID and level.
3. On an isolated lab host, use curl to GET /test from another authorized lab node to your DIY listener. Verify a JSONL event and Wazuh ingestion.
4. For OpenCanary and Cowrie, trigger a benign authorized local probe/failed login and inspect the **actual JSON format** before applying live rules.
5. Verify time synchronization, source inventory, sensor labels and Wazuh time zone.
6. For firmware events, demand a version-specific JSON example and authenticated bridge before accepting them as trusted Wazuh telemetry.

| Problem | Check |
| --- | --- |
| No alerts | Agent enrollment, exact file path, permissions, JSON lines, manager XML |
| Incorrect rule matching | Compare actual field names and ID collisions with rules |
| Production credentials in logs | Restrict access, redact or prevent capture where possible |
| Duplicate alerts | Check multiple agents/processes watching same file, T-Pot pipeline overlap |
| False positive | Inventory scan/asset management/approved exercise/monitoring |

## 5. Isolation and retention

Isolate decoy VLAN or Proxmox bridge; allow **only** narrowly scoped egress to Wazuh/updates as required; deny decoy-to-production and unnecessary internet egress. Keep management on a separate trusted channel and maintain patches. Do not log application secrets intentionally. Preserve chain of custody and rotation policy; Wazuh is not a backup of all original honeypot evidence. Do not publicly publish attacker-submitted payloads or passwords.

## Related guides

[Raspberry Pi](./raspberry-pi-honeypot-lab.md) · [Proxmox VMs](./proxmox-vm-honeynet.md) · [ESP32](./esp32-diy-honeypots.md) · [DIY service](./diy-sensor-lab.md) · [OpenCanary](./opencanary.md) · [Cowrie](./cowrie.md) · [Dionaea](./dionaea.md) · [T-Pot](./tpot.md) · [Kismet + Wazuh WIDS](../IDS%26IPS/kismet-wazuh-wireless-lab.md) · [nzyme + Wazuh WIDS](../IDS%26IPS/nzyme-wazuh-integration.md)

---

[Honeypot Index](./readme.md) | [Incident Response](../README.md) | [Main Index](../../README.md) | [Legal Notice](../../LEGAL.md)
