# Hak5 USB Rubber Ducky — Authorized HID Security Field Guide

## Purpose & Device Variants
The USB Rubber Ducky is a programmable USB HID testing device. Modern models use DuckyScript 3 features that are **not necessarily supported by older devices or encoders**. Always identify the hardware generation, firmware, and compiler/encoder before using a sample. The exercises below deliberately avoid credential harvesting, persistence, evasion, and destructive execution.

## Authorization & Lab Requirements
Written permission must identify host, user account, date/time, test window, acceptable keystrokes, and observer. Use a dedicated unlocked lab workstation or VM with an open text editor and synthetic data. Disable automatic execution on insertion until the payload has been inspected and approved. Record a hash of the payload and retain the source, not just the compiled artifact.

## DuckyScript Fundamentals
DuckyScript is a keystroke-oriented scripting language; it is **not Bash or PowerShell**. Statements such as `DELAY`, `STRING`, `ENTER`, and `REM` express timing, text entry, keys, and comments. Advanced features vary by DuckyScript version. Compile with the matching official encoder and validate its reported errors before deploying.

### Example A — Safe Marker Payload
```text
REM Harmless HID test; focus a text editor first
DELAY 1500
STRING PNWC-HID-AUTHORIZED-TEST
ENTER
```
**Procedure:** open a blank text document, position the cursor, insert the device once, confirm the marker, capture the endpoint event, and remove the device. The delay is illustrative and may require tuning. Never use an uncontrolled desktop where the marker could be sent to chat, email, or a terminal.

### Example B — Keyboard Layout & Timing
```text
REM Test only in an open text editor
DELAY 2000
STRING Keyboard layout test 12345
ENTER
DELAY 500
STRING Symbols require locale validation
ENTER
```
Compare output with expected text, then repeat with different approved keyboard layouts. If characters differ, confirm compiler locale and host layout. Avoid assuming that punctuation and special characters map identically.

### Example C — Physical Access Drill
1. Have an assessor attempt a single marker injection while the test workstation is locked; do not attempt to bypass the lock.
2. Record whether the host enumerates HID, whether text is accepted, and whether any alert appears.
3. Unlock the machine with the test user and repeat with a visible text editor.
4. Compare expected policy, workstation auto-lock settings, and physical access procedures.
5. Report outcomes without claiming a successful compromise.

### Example D — Endpoint Detection Validation
1. Confirm EDR and USB-device logs are healthy.
2. Record baseline device insertions.
3. Run Example A once.
4. Collect device ID, time, host, process/foreground context if logged, and alert IDs.
5. Verify the detection rule distinguishes an unexpected HID from a legitimate keyboard and assess false positives.

### Example E — Controlled Awareness Exercise
With management approval, demonstrate how an unattended unlocked workstation can accept input from a newly inserted HID. Use the marker-only payload, no secret collection, no simulated password prompts, and no covert employee monitoring. Debrief on locking screens and reporting unknown USB devices.

## Development Workflow
1. Write the smallest payload necessary for one objective.
2. Review every statement for unintended key combinations, privilege changes, and focus assumptions.
3. Compile using the official tool compatible with the device generation.
4. Run on a sacrificial VM with snapshots; confirm output and timing.
5. Record source version, compiled file hash, locale, host OS, and test results.
6. Require explicit sign-off before any client execution.

## Defensive Interpretation
A successful marker only demonstrates that a HID was enumerated and input reached the focused application. It does not prove elevated privileges, code execution, data access, or a security control bypass. Evaluate against USB policy, workstation lock policy, EDR telemetry, physical access, and business requirements.

## Troubleshooting
| Problem | Likely checks |
|---|---|
| No keystrokes | Model/firmware, payload compilation, USB enumeration, device control |
| Garbled text | Host layout versus payload language mapping |
| Text in wrong window | Application focus; stop and retest in an isolated editor |
| Inconsistent timing | Boot/enumeration latency; use conservative delays |
| No alert | USB/HID telemetry availability and detection configuration |

## Cleanup & Report
Remove the device, delete test text where appropriate, collect logs, restore snapshots, and document the expected and observed policy outcome. Avoid storing personal data in payloads or evidence.

## References
- [Hak5 Documentation](https://docs.hak5.org/)
- [Hardware Hacking Index](./README.md)
- [Endpoint Visibility](../IncidentResponse/Endpoint-Visibility/README.md)
- [Assessment Service Blueprint](../PlayBooks/assessment-service-integration-map.md)
