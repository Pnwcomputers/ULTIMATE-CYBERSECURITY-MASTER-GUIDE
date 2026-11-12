# Cyberdeck Architecture & Network Zones

[Cyberdeck Home](../README.md) · [Hardware & Status](HARDWARE_AND_STATUS.md) · [Evidence & Privacy](EVIDENCE_AND_PRIVACY.md)

## Design Intent

A portable field system separates operator management from sensor work, a controlled lab and any approved customer test interface. The topology below is **illustrative**, and deployments must use the *actual* model, firmware, port maps and network policies of the chosen equipment.

| Zone | Possible Components | Security & Verification Objective |
| --- | --- | --- |
| UPSTREAM | Approved hotspot or client-provided uplink; GL.iNet WISP/repeater | Know whether the uplink is NAT, routed or bridged; do not assume transparent packet visibility |
| ROUTER | MikroTik RouterOS WAN & VLAN-capable downstream interfaces | Default-deny management exposure, restrict cross-zone routes, check IPv4 and IPv6 |
| MGMT | Windows 11 mini PC or Linux laptop, out-of-band console such as ESPKVM | Local operator access, administrative isolation, explicit session security |
| SENSOR | ZimaBoard/ZimaBlade, Pi/Kismet, wired inspection sensor | Manual logs/exports; only observe traffic actually presented to its interface |
| LAB | Isolated hosts, test fixtures and optionally a separate AP | Validate controls without using customer production systems |
| CLIENT TEST | Dedicated interface for a named authorized customer environment | Written scope, interface approval, no unauthorized DHCP/RA or bridging |
| STORAGE | Independently verified encrypted drive or vault | Distinct cases, access controls, integrity logs, tested backups and restores |

## Traffic-Visibility Realities

- A GL.iNet WISP/repeater configuration usually routes rather than transparently bridges; verify the exact operating mode.
- Devices directly on a GL.iNet-side subnet may bypass a downstream MikroTik; a downstream access point can be needed to place clients within MikroTik policy.
- MikroTik filters only flows it processes. Same-subnet switching, hardware offload and upstream traffic can bypass an expected inspection point.
- A passive IDS in a VM attached to an ordinary LAN port does **not** automatically receive all switch traffic. Use explicitly approved SPAN/mirror, TAP, gateway placement or suitable host-local telemetry.
- Separate **true external vantage** testing from observations made inside a client LAN. No external scan runner is shipped here.
- RF surveys must distinguish passive reception from active transmission and respect applicable law, privacy and client scope.

## Safe Bring-Up Sequence

| Step | Verification Evidence |
| --- | --- |
| 1. Record hardware revisions and draw the real cabling map while disconnected from customer equipment | Model/firmware list and photos with identifiers redacted for publication |
| 2. Verify the upstream GL.iNet mode and network ownership | WAN/LAN interface and routing table checks |
| 3. Configure MikroTik zones with deny-by-default policy and a recovery path | Configuration review and negative cross-zone tests |
| 4. Check that sensors have the expected actual traffic feed | Known, benign packet tests from owned lab endpoints |
| 5. Set up encrypted storage, unique case directories, backup and restore | Unlock, permission and recovery evidence; an encrypted directory name alone is insufficient |
| 6. Keep operator tools on localhost or approved secured operator desktop sessions | No public port forwarding or unauthenticated reverse proxy |
| 7. Test disconnect, emergency stop and independent device shutdown | Documented stop result for each separately running device |
| 8. Attach a client interface only after written, verified and specific authorization | Signed ROE, exclusion list, time window and emergency contacts |

## Recommended Reading

[Proxmox traffic visibility](../../Homelab/proxmox-security-monitoring-visibility.md) · [Wireless surveying](../../Wardriving/README.md) · [Evidence workflow](EVIDENCE_AND_PRIVACY.md) · [Private/public boundary](PUBLISHING_AND_RELEASE.md).
