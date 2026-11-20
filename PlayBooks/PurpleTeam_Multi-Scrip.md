# Purple Team Playbook - Multi-Platform Scripts

---

## 🎯 Purpose

Use **Python**, **PowerShell**, and **Batch** to generate harmless telemetry canaries and run approved, scoped simulations for detection validation.

## ⚙️ Function

A repeatable loop (choose a detection question → select a harmless canary or vendor-approved simulation → run it within the authorized scope → compare expected and observed telemetry). This is the **script-centric variant** of the purple team playbooks: `PurpleTeam_Simple.md` and `PurpleTeam_Detailed.md` describe the exercise process and tooling ecosystem, while this file focuses on safe signals organized by scripting language and platform.

## 🏆 Goal

Make detection exercises repeatable without sending credentials, contacting unrelated hosts, installing persistence, or downloading payloads. Synthetic canaries validate collection and parsing; they do not prove that a full attack technique is detected.

## 📋 When to Use

- You already have a purple team process (see `PurpleTeam_Simple.md`/`PurpleTeam_Detailed.md`) and need a harmless signal or approved simulation for a detection question
- Comparing telemetry collection across platforms or languages without treating a synthetic canary as proof of technique-level detection
- Building a reusable library of harmless canaries and documented vendor-approved simulations mapped to detection objectives

---

## Tools to Keep Ready

| Type | Tool | Example |
|------|------|---------|
| Python | Custom scripts, Atomic Red Team helpers | Parse synthetic JSONL detections in an isolated fixture |
| PowerShell | Windows-native canary event generation | Emit a harmless, uniquely tagged test event on an owned Windows VM |
| Batch | Batch wrappers in a disconnected lab | Write a tagged benign command-output file, then verify expected logs |

---

## Workflow (Recap)

1️⃣ State a detection question

2️⃣ Select a harmless canary or approved simulation in Python/PowerShell/Batch

3️⃣ Run in isolated lab

4️⃣ Check SIEM/EDR for logs & alerts

5️⃣ Tune detection

6️⃣ Document and iterate

---

> [!WARNING]
> The examples below are harmless simulations. They do not attempt logins, alter autorun locations, or fetch files. For behavior-level testing, use the endpoint or SIEM vendor's documented test facility or a separately reviewed simulation in an isolated, explicitly authorized lab.

## Safe validation flow

1. Confirm written authorization, hosts, time window, data handling, and a stop contact.
2. Snapshot or reset the lab and confirm test accounts/devices contain no real secrets.
3. Choose a harmless canary and state exactly which telemetry it can exercise.
4. Generate the signal locally or send it only to a listener bound to the lab host.
5. Compare expected events with observed telemetry; record missing, delayed, and unavailable data as unverified.
6. Stop on unexpected network or system changes, clean up, restore the snapshot, and report evidence and limits.

~~~mermaid
flowchart LR
    A[Written scope and stop conditions] --> B[Isolated lab snapshot]
    B --> C[Harmless canary or approved test signal]
    C --> D[Telemetry collection]
    D --> E[Analyst checks expected event and source]
    E --> F[Record observed, missing, or unavailable]
    F --> G[Cleanup and restore lab]
    A -. Scope unclear .-> X[Stop]
    C -. External effect or real credential requested .-> X
~~~

## Example playbook entries

### Example 1 — Synthetic authentication-failure event

This only tests whether the local script output is collected and parsed. It does **not** create an operating-system authentication failure or validate lockout controls.

~~~python
import json

event = {
    "event": "purple_test",
    "scenario": "synthetic_auth_failure",
    "user": "lab-user",
    "result": "simulated_failure",
}
print(json.dumps(event, separators=(",", ":")))
~~~

~~~powershell
$Event = [pscustomobject]@{
    event = "purple_test"
    scenario = "synthetic_auth_failure"
    user = "lab-user"
    result = "simulated_failure"
}
$Event | ConvertTo-Json -Compress
~~~

~~~batch
@echo off
echo event=purple_test scenario=synthetic_auth_failure user=lab-user result=simulated_failure
~~~

For an end-to-end authentication detection test, use a documented vendor test facility or a purpose-built local test application with synthetic credentials and explicit rate/lockout bounds.

### Example 2 — Benign encoded PowerShell canary

This tests process-command telemetry for an encoded command. The decoded content only writes a fixed marker to standard output.

~~~powershell
$Command = "Write-Output 'PURPLE_TEST_CANARY'"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$Encoded = [Convert]::ToBase64String($Bytes)
powershell.exe -NoProfile -EncodedCommand $Encoded
~~~

This is a narrow test of the encoded-command signal. It does not reproduce malicious obfuscation or validate every PowerShell policy.

### Example 3 — Startup-detection validation

Do not write test files into a real user's Startup folder. Use an endpoint-vendor simulation or a disposable VM snapshot with a reviewed test fixture. A harmless marker file in a temporary directory can validate file-write telemetry, but it does not test persistence detection.

~~~powershell
$Canary = Join-Path $env:TEMP "purple-test-canary.txt"
Set-Content -LiteralPath $Canary -Value "PURPLE_TEST_STARTUP_SIMULATION"
Get-Item -LiteralPath $Canary | Select-Object FullName, Length
Remove-Item -LiteralPath $Canary
~~~

### Example 4 — Local syslog canary

Use only when a test collector is listening on loopback at port 5514. This sends one synthetic message to the same host.

~~~python
import socket

message = b"<134>1 - - - - - PURPLE_TEST_CANARY"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(message, ("127.0.0.1", 5514))
~~~

Do not replace loopback with a third-party or production collector without written authorization and a confirmed change window.

## Reporting template

| Field | Record |
|---|---|
| Scope / authorization | |
| Scenario and canary | |
| Host snapshot / test identity | |
| Expected telemetry source and event | |
| Observed result and timestamp | |
| Missing, delayed, or unavailable data | |
| Cleanup / restoration result | |
| Follow-up owner | |

A missing alert is a finding only after confirming that the event was generated, collected, parsed, and routed through the expected pipeline. Otherwise record the result as unverified.


## Version Control

Store:

- `/scripts/python/`
- `/scripts/powershell/`
- `/scripts/batch/`
- `/docs/playbook.md`

Use `git` so you track edits & additions over time.

---

## Security and Ethical Considerations ⚠️

**IMPORTANT**: These tools are for **authorized security testing only**. Unauthorized use is illegal.

* **Marauder Use:** Get **written permission** before testing any network. Only test networks you own or have explicit authorization to test.
* **Cracking Use:** All cracking attempts (Hashcat) must be done in an **isolated lab environment** against hashes you are authorized to possess.
* **Legal Compliance:** Strictly comply with all local laws and regulations.

**Legal Use Cases:**
* Penetration testing with client authorization.
* Testing your own home or lab network security.
* Security research in isolated lab environments.

---
## Related Files
- [README.md](README.md) - PlayBooks section index
