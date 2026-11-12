# Staged Cyberdeck Assessment Workflow

[Cyberdeck Home](../README.md) · [Portable Wireless Field Operations](PORTABLE_WIRELESS_FIELD_DEVICES.md) · [Architecture](ARCHITECTURE.md) · [Example Plan](../templates/ENGAGEMENT_PLAN.example.md)

This workflow is a **manual reference**, not a command queue, automated scanning orchestration service or legal authorization instrument. The operator must document exact authorization, assessed systems and results.

## Engagement Types

| Profile | Reasonable Scope | Major Limitations |
| --- | --- | --- |
| Time-boxed network exposure review | Small named target set, prioritized perimeter/configuration checks, selected onsite observations | Cannot claim exhaustive coverage, especially where offsite origin is unavailable |
| Extended network infrastructure assessment | Approved LAN/VLAN, firewall, wireless and representative endpoint reviews | Bound to the signed asset list, allowable services and actual visibility |
| Controlled defensive resilience review | Benign synthetic canaries, segmentation validation, monitored detection checks | Requires separate written method, test source, observer, rollback and emergency stop |

## Seven Stages & Deliverables

| Stage | Operator Questions | Minimum Record |
| --- | --- | --- |
| Intake & Authorization | Who owns the assets? Are cloud/ISP/tenant permissions covered? Which sources, methods, windows and exclusions apply? | Reviewed permission, approved plan, contacts and STOP process |
| External Network | Is observation truly from a separately authorized offsite location? | Vantage proof, precise targets, source and no-test reasons |
| Internal Network | Which approved physical port, VLAN or local endpoint is used? | Asset mapping and factual, non-exploit observations |
| Resilience | Is a separate method approved and safe to abort? | Actual source, synthetic test, expected alert, independent observer and measured outcome |
| Specialist Wireless/Device | Is the proposed board/firmware qualified for this exact procedure? Start with the [portable device workflow](PORTABLE_WIRELESS_FIELD_DEVICES.md). | Device and firmware version, receive/transmit mode, controller/accessory, export and STOP state |
| Evidence & Findings | What raw outputs exist? Are they attributable? Which statements remain hypotheses? | SHA-256, UTC time, acquisition origin, limitations and reviewer |
| Report & Close | What was covered, failed or skipped? Was temporary equipment removed? | Redacted report, remediation/retest plan, secure transfer and retention decision |

## Method-First, Not Device-First

A [Flipper Zero](https://flipper.net/products/flipper-zero), [Kismet](https://www.kismetwireless.net/) sensor, [RouterOS](https://manual.mikrotik.com/docs/introduction/) read-only query, ordinary laptop or other tool is not permission by itself. Define the **approved method and effects** first; choose the least intrusive eligible tool and record what actually ran. If tool substitution changes the source network, action, risk or target behavior, obtain an amended approval before proceeding.

Do **not** turn a planning profile or downloaded payload into an automatically authorized operation. Specialist activities such as credential capture, deauthentication, HID execution, exploitation or RF transmission are outside the default passive workflow and require separate risk and legal review.

## Validation & Report Language

| Finding Class | Report Language |
| --- | --- |
| Confirmed configuration weakness | Specify the configuration evidence, affected asset, exposure boundary and independent verification |
| Observed service or port | Describe observation only; an open port is not automatically a vulnerability |
| Potential candidate | Label **unconfirmed**, provide verification requirements and avoid severity overstatement |
| No sensor alert observed | Distinguish missing visibility/telemetry from a confirmed detection failure |
| Skipped or failed test | State why, scope impact and any required retest |

[Evidence & Custody](EVIDENCE_AND_PRIVACY.md) · [Network Audit Playbook](../../PlayBooks/NetworkAuditPlayBook.md).
