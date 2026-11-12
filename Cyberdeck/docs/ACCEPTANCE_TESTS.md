# Acceptance & Qualification Matrix

[Cyberdeck Home](../README.md) · [Bring-Up Runbook](BUILD_AND_OPERATIONS.md) · [Qualification Record](../templates/QUALIFICATION_RECORD.example.md)

These are manual qualification procedures for owned lab fixtures. No checks below have been performed on physical hardware by this public edition. Software tests qualify only the behaviors they exercise.

Use PASS, FAIL, BLOCKED or NOT TESTED. NOT APPLICABLE requires a reason and reviewer. Record actual device/firmware, source and destination, interface, address family, procedure, expected result, observed result, UTC time and evidence reference for each run.

| ID | Procedure | Pass condition | Release gate |
| --- | --- | --- | --- |
| Q01 | Reconstruct cabling and routing from inventory | Every active interface and bypass path is accounted for | All connected builds |
| Q02 | Try approved management service from MGMT and disallowed zones using owned fixtures | Named operator path succeeds; disallowed paths fail with attributable policy evidence | All connected builds |
| Q03 | Exercise allowed and denied zone pairs in IPv4 and IPv6 where supported | Observed results match the reviewed policy matrix; unsupported paths are documented | All connected builds |
| Q04 | Check isolated client fixture for unintended transit, DHCP and RA | No unapproved service, route or bridge reaches the fixture | Client interface use |
| Q05 | Produce a known benign exchange at the intended sensor feed | Expected packets/events are attributable to the correct source and vantage | Sensor coverage claim |
| Q06 | Lock storage and attempt access; unlock with approved recovery process | Access restriction and recovery both work; keys are separately controlled | Real evidence storage |
| Q07 | Restore a synthetic case to separate protected storage and compare against protected manifest | All expected regular files match; discrepancies are investigated | Real evidence storage |
| Q08 | Trigger emergency stop while owned fixtures are active | Each independent collector stops; remaining background activity is recorded and resolved | Active collection |
| Q09 | Exercise approved power-loss and recovery scenario using synthetic data | No unexplained evidence loss, corrupt baseline or unintended automatic testing | Portable field use |
| Q10 | Run representative simultaneous load and measure power, temperature and runtime | Documented operating envelope meets the planned session with reserve | Battery/enclosure qualification |
| Q11 | Inspect intended local portal listeners and access controls | Only approved binding/access paths work; no unintended uplink exposure | Private portal release |
| Q12 | Simulate expired scope, excluded target and missing approval in a private implementation | Execution is refused before collection; reason is recorded | Private execution features |
| Q13 | Transfer synthetic evidence and independently verify destination | Inventory and bytes match the separately protected baseline | Evidence delivery |
| Q14 | Complete synthetic report and publication review | Each claim has evidence, limitation and review state; no real client information | Public reference release |

For deny tests, an unreachable destination alone is weak evidence: first show that the intended listener is healthy from an allowed path and corroborate enforcement with router/configuration evidence. For an IDS check, independently prove the event reached the sensor before interpreting a missing alert.

## Completion Definitions

**Public reference ready:** documented navigation resolves, Python tests pass, the offline create/verify rehearsal passes, synthetic examples are reviewed, limitations are explicit and publication checks are completed. This does not require claiming physical qualification.

**Private lab ready:** inventory, topology and relevant Q01–Q11 records are complete for the actual build; restore and stop procedures are repeatable. Failures have owners and client connection remains blocked where applicable.

**Private field ready:** the lab gates plus engagement-specific authorization, Q12 for any execution feature, Q13 delivery checks, reviewed report and a documented operating envelope. Repeat affected qualification after firmware, topology, storage, power or execution-policy changes.
