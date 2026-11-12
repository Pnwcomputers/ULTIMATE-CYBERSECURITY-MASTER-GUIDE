# Build, Bring-Up & Field Operations

[Cyberdeck Home](../README.md) · [Acceptance Tests](ACCEPTANCE_TESTS.md) · [Private Implementation Roadmap](IMPLEMENTATION_ROADMAP.md)

This runbook turns the reference architecture into a sequence of decisions and checks. It supplies no vendor configuration or private application code. Complete the inventory for the actual equipment before connecting a client interface.

## 1. Establish a Minimum Build

Start with an operator workstation, one segmentation router, an approved uplink and separately protected evidence storage. Add a passive sensor only after its traffic feed is demonstrated. Optional RF devices and an external runner are later milestones, not prerequisites for an offline workflow.

| Item | Record before purchase or reuse | Acceptance requirement |
| --- | --- | --- |
| Operator host | OS/support lifecycle, architecture, RAM, ports, recovery media | Runs offline tools, locks sessions, has verified storage protection |
| Upstream router | Exact model, firmware, operating mode, power input | Uplink works without exposing operator administration |
| Segmentation router | Port map, firmware, VLAN and IPv6 support, recovery method | Enforces the documented zone matrix on actual paths |
| Evidence storage | Usable capacity, encryption mechanism, recovery-key custody | Unlock, access restriction, backup and restore demonstrated |
| Sensor, if used | NIC/chipset, driver, OS, approved feed, storage needs | Observes the intended lab traffic without bridging zones |
| Power system | Per-device input voltage/current, adapters, cable ratings | Stable under representative simultaneous load |
| Enclosure/cabling | Airflow, strain relief, labels, spare cables | Ports accessible, no exposed contacts or obstructed cooling |

Keep serial numbers, invoices, credentials and real configurations in the private inventory. Publish only generic roles and synthetic measurements. Model compatibility and prices must be checked against current manufacturer documentation before procurement.

## 2. Map Interfaces and Policy

Draw the physical cabling and logical routes separately. Record interface labels, VLANs, address families, gateway placement and management access. Do not paste a generic subnet plan into an existing site without checking overlap.

| Source | Destination | Reference policy | How to qualify |
| --- | --- | --- | --- |
| UPSTREAM | MGMT, SENSOR, LAB | Deny new inbound sessions | Owned upstream fixture cannot open approved test listeners |
| LAB | MGMT and STORAGE | Deny | Test each relevant routed path and address family |
| SENSOR | MGMT | Deny unsolicited access | Sensor cannot open management listeners |
| MGMT | Router administration | Allow only named operator source and service | Approved operator succeeds; other zones fail |
| MGMT | Evidence import endpoint | Explicit, minimal exception if needed | Import works; unrelated services remain inaccessible |
| CLIENT TEST | Other deck zones | Deny unless a specific approved method requires a path | No accidental transit, DHCP, RA, forwarding or bridging |
| Any zone | Internet | Explicit decision per zone | Required egress succeeds; disallowed egress fails |

This is a policy worksheet, not a preconfigured firewall. Stateful return traffic, DNS, time synchronization, software updates and IPv6 need explicit decisions. Test same-subnet and offloaded paths separately because routed firewall tests do not cover them.

## 3. Bring Up in an Owned Lab

1. Keep all client cables disconnected. Label uplink, management, sensor and lab ports.
2. Establish console/recovery access and save a protected configuration backup.
3. Configure one zone at a time. Use the [acceptance matrix](ACCEPTANCE_TESTS.md) to record both allowed and denied paths.
4. Connect a sensor only to its approved feed. Generate a benign exchange between owned fixtures and identify it at the sensor.
5. Create a synthetic case outside Git. Verify encryption and a restore to a separate protected location.
6. Run the offline manifest rehearsal below. Record tool revision and outcomes.
7. Exercise loss of uplink, low storage, power interruption recovery and emergency stop in the lab. Stop each independent device; terminating a dashboard does not stop separate hardware.
8. Mark every unresolved gate as failed, blocked or not tested. Do not reinterpret missing results as passes.

## 4. Rehearse the Offline Evidence Workflow

From the parent repository root, choose a new output filename each run. The destination parent must exist and must be outside the evidence folder.

```bash
python Cyberdeck/tools/evidence_manifest.py --input Cyberdeck/examples/synthetic-evidence --output /tmp/cyberdeck-demo-manifest.json
python Cyberdeck/tools/verify_manifest.py --input Cyberdeck/examples/synthetic-evidence --manifest /tmp/cyberdeck-demo-manifest.json
python -m unittest discover -s Cyberdeck/tests -v
```

PowerShell equivalent:

```powershell
$demoManifest = Join-Path $env:TEMP ('cyberdeck-' + [guid]::NewGuid().ToString() + '.json')
py -3 Cyberdeck/tools/evidence_manifest.py --input Cyberdeck/examples/synthetic-evidence --output $demoManifest
py -3 Cyberdeck/tools/verify_manifest.py --input Cyberdeck/examples/synthetic-evidence --manifest $demoManifest
py -3 -m unittest discover -s Cyberdeck/tests -v
```

Verification exits with `0` for a matching inventory, `1` for added/missing/changed regular files and `2` for invalid input or an operational error. Do not overwrite the original manifest after a mismatch. Preserve it and investigate. Both tools exclude symlinks; neither proves the absence of skipped objects or protects against hostile concurrent filesystem changes. Work on a quiescent, access-controlled copy. Protect the baseline separately: replacing both evidence and manifest defeats this comparison.

## 5. Field Start and Close

Before attachment, review the specific signed scope, actual interface, target list, exclusions, test window and stop contacts. Check clocks and note offsets; record acquisition time separately from hashing time. Confirm storage capacity, recovery access and independent device stop controls.

After collection, preserve originals, create hashes, review derivatives and use the [report template](../templates/ASSESSMENT_REPORT.example.md). Verify transferred evidence at the destination against a separately protected manifest. Remove temporary access, disconnect the client interface, confirm equipment removal and record the agreed retention/deletion action. Flash storage deletion guarantees depend on the medium and encryption lifecycle; do not claim secure erasure merely because files were deleted.

## Troubleshooting

| Symptom | Check | Required disposition |
| --- | --- | --- |
| No sensor packets | Actual feed, interface, mirror direction, offload and capture filters | Restore proven visibility or report coverage as unavailable |
| Unexpected cross-zone access | Same-subnet paths, bridge membership, IPv6, alternate uplinks | Disconnect client interface and resolve before field use |
| Hash mismatch | Changed bytes, partial transfer, wrong case or baseline | Preserve both versions; investigate without regenerating away the discrepancy |
| Empty manifest | Selected directory, file types, symlink-only content | Confirm intended files exist; an empty inventory is not collection evidence |
| Read error or storage full | Permissions, media health, capacity and locks | Stop evidence writes; preserve existing material and record the failure |
| Local portal unreachable | Binding, process state, local firewall and logs | Use recovery access; do not expose the portal publicly as a workaround |
| Time discrepancy | UTC settings, clock source, offline drift | Record offset and uncertainty; do not silently rewrite originals |
