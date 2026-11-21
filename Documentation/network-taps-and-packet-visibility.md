# LAN TAPs, Passive & Active Network Taps, SPAN & Packet Visibility

_Reviewed: 2026-11-21. Product claims come from manufacturer documentation; no Ethernet link or throughput was physically tested._

> [!CAUTION]
> **Authorized in-line work only.** Inserting a network TAP means unplugging a production link, which can interrupt service and alter negotiation. Treat changes as scheduled maintenance with rollback and packet-data confidentiality controls. A monitoring tool's access to copied packets is sensitive. See [Legal Notice](../LEGAL.md).

## Overview: Where a TAP Fits

A **network TAP (test access point)** provides a copy of link traffic to a separate capture/monitoring system. It can be installed between a router and switch, firewall and router, server and switch, or another **specifically authorized** pair of endpoints. Not all taps are electrically passive, and no TAP makes traffic decrypted by itself.

```text
             original production Ethernet link
  Router / Firewall ──[  NETWORK TAP  ]── LAN Switch
                              │
                        copy/copies only
                              │
                    Capture / IDS machine
                  Wireshark, Zeek, Suricata
```

**The observation point matters.** A TAP between firewall and switch sees traffic crossing that link, not necessarily east–west traffic between two hosts on the switch. Inter-VLAN routing and Wi-Fi controller traffic can take different paths. A TAP is also not a cure for an incorrectly bridged or NAT-only VM sensor.

## TAP Categories & What They Mean

| Type | Media / Operating Principle | Monitoring Outputs | Power & Failure Behavior | Typical Use |
|---|---|---|---|---|
| **Passive copper 10/100** | Physical coupling on 10BASE-T / 100BASE-TX wiring | Often **separate transmit/receive directions** | No power required; signal loss/negotiation still matters | Small wired labs; [Throwing Star](#great-scott-gadgets-throwing-star-lan-tap) |
| **Active copper 1G/2.5G/10G** | Powered electronics copy/reconstruct copper Ethernet | Breakout, aggregation or regeneration by model | Depends on relay bypass, power and firmware | Gigabit/multi-gig production visibility |
| **Passive optical fiber splitter** | Optical split of light on supported fiber type | Usually separate directions, model-specific | No electronics needed for splitting; optical budget reduced | Fiber links with adequate power margin |
| **Active optical TAP** | Powered optical reception/regeneration/conversion | One or multiple monitored links | Depends on design and power redundancy | Long-haul/low-optical-budget or special tool interfaces |
| **Breakout / non-aggregation TAP** | Exposes each direction separately | **Two capture interfaces** commonly required | Fewer merge-related bottlenecks | Full-duplex evidence and timing |
| **Aggregation TAP** | Combines both directions into one output | One tool port | Can **drop frames** if output oversubscribed | Single-port IDS or capture host |
| **Regeneration TAP** | Replicates a capture feed | Multiple monitoring ports | Model-specific buffer and bandwidth | Simultaneous IDS + recorder + packet broker |
| **Bypass TAP / inline failover** | Can route production traffic around a failed inspection device | Out-of-band and/or inline paths | **Fail-open vs fail-closed must be configured/tested** | Inline IPS / security appliance availability |
| **SPAN / port mirror** | Managed switch makes copies of selected ports/VLANs | Configured mirror destination | No in-line TAP, but subject to mirror-port capacity and switch behavior | Low-cost supported-switch observation |
| **RSPAN / ERSPAN** | Encapsulates or routes mirrored traffic to a remote collector | Remote destination | Bandwidth, MTU, time accuracy and encapsulation matter | Centralized or remote visibility |
| **Virtual TAP / vSwitch mirror** | Hypervisor/software switch duplicates virtual traffic | VM/container collector | Only traffic visible to that virtual switch | VM east–west or hypervisor traffic |

**"Passive" is not the same as "invisible with zero impact."** Any in-line insertion can cause a link flap, insertion loss or a change in auto-negotiation. A powered copper TAP might have fail-safe relays while still being an **active** device during normal operation.

### Breakout vs Aggregation Example

```text
Link direction A ─────────► Monitor NIC 1 ─┐
                                          ├─ timestamp-aware merge or separate PCAPs
Link direction B ─────────► Monitor NIC 2 ─┘

Both directions ──► aggregation TAP ──► ONE monitor NIC
                         ▲
                 output can oversubscribe
```

For full-duplex 1 Gbps links, each direction can individually reach 1 Gbps. Aggregating both into **one** 1 Gbps tool port may lose packets when simultaneous traffic exceeds output capacity. Choose adequate output bandwidth and record packet drops before claiming complete visibility.

## Great Scott Gadgets Throwing Star LAN Tap

The [Throwing Star LAN Tap](https://greatscottgadgets.com/throwingstar/) from **Great Scott Gadgets** is an educational, open-hardware **passive 10/100 Ethernet** TAP. It exists as a DIY kit and as an assembled **Throwing Star LAN Tap Pro**; Great Scott states the Pro is electrically equivalent to the kit. This is not GreatFET One or HackRF.

| Port | Intended Role |
|---|---|
| **J1 / J2** | Two in-line ends of the approved Ethernet link |
| **J3** | Receive-only copy of **one traffic direction** |
| **J4** | Receive-only copy of **the other direction** |

The receiver monitor ports are wired so a connected monitoring NIC does **not** have a transmit path back to the production link, per the manufacturer's design. A single monitor port cannot show the complete two-way conversation; two monitoring interfaces (or a later synchronized merge) are normally required.

### Critical Speed & Negotiation Limitation

The original design targets **10BASE-T and 100BASE-TX** and **does not transparently sniff true 1000BASE-T**. The two on-board capacitors deliberately impair gigabit negotiation, typically forcing a gigabit-capable link to negotiate a lower speed (commonly 100 Mbps) so the passive 10/100 wiring can be monitored. On some links, negotiation can instead fail, throughput can suffer, or errors can rise. Great Scott explicitly notes signal quality degradation, particularly with long cables.

**Do not insert a Throwing Star into a production gigabit link expecting an unchanged 1 Gbps service.** It is a teaching/lab tool, not a general-purpose full-speed gigabit TAP. Avoid Power over Ethernet (PoE) setups unless the specific entire electrical path and device design have been validated for that power use; this open-hardware 10/100 reference should not be assumed PoE-safe.

See the [manufacturer's theory/usage instructions](https://greatscottgadgets.com/throwingstar/) and the [open hardware source](https://github.com/greatscottgadgets/throwing-star-lan-tap).

## Product & Architecture Comparison

These are **categories and examples**, not current pricing recommendations. Validate a model's link speeds, break-out/aggregation, power failure and connector compatibility from its current datasheet.

| Example / Vendor | Category | Good For | Major Qualification |
|---|---|---|---|
| [Great Scott Throwing Star](https://greatscottgadgets.com/throwingstar/) | Passive 10/100 copper kit/Pro | Teaching two-direction Ethernet capture | **Not transparent gigabit**; low-speed lab only |
| [Datacom Systems Copper TAPs](https://www.datacomsystems.com/copper-network-taps-101/) | Passive 10/100 and active higher-rate copper products | Separate directions vs aggregation | Exact model, copper speed and power-loss behavior |
| [Garland Technology](https://www.garlandtechnology.com/network-tap) | Copper/fiber, aggregation, regeneration, bypass | Production IDS visibility and multi-tool feeds | Inline failover/monitor-output bandwidth vary |
| [Keysight Network TAPs](https://www.keysight.com/zz/en/products/network-visibility/network-taps.html) | Passive/active copper & optical | Fiber links and enterprise visibility | Fiber budget, connector/polarity & media selection |
| [Niagara Network TAPs](https://www.niagaranetworks.com/products/network-tap-how-to-guide) | Copper, fiber, inline bypass architectures | Managed enterprise monitoring | Failure design and deployment-specific optics |
| [NETSCOUT TAP Overview](https://www.netscout.com/what-is/network-tap) | TAP, aggregation and regeneration concepts | Planning sensor access | Product capabilities differ by model |
| Managed switch SPAN | Software-managed copy | Existing lab switch and initial IDS PoC | Switch can filter/drop/reshape mirrored traffic |
| Virtual switch mirror | Hypervisor/software copy | Observe VM-to-VM flows without extra box | **Only** traffic on mirrored virtual switching plane |

## Passive vs Active: What to Buy or Build For Each Task

| Scenario | Most Suitable Starting Option | Why |
|---|---|---|
| Teaching Ethernet RX/TX at 100 Mbps | Throwing Star / equivalent passive 10/100 | Simple read-only two-port physical demonstration |
| Client network is gigabit copper | Properly rated **active copper TAP** | Maintains negotiated speed when designed for link |
| Fiber backbone | Appropriate passive fiber TAP **with power budget verified** | Optical split without powered regeneration |
| Existing managed switch, low traffic, lab | SPAN/mirror | Minimal hardware, convenient monitoring |
| IDS must see both directions through one NIC | Aggregating TAP with **adequate** output capacity | Avoid manual merge; watch oversubscription |
| IDS + forensic PCAP recorder simultaneously | Regeneration TAP / packet broker | Multiple tool feeds |
| Inline IPS must survive tool outage | Documented bypass/fail-open or fail-closed product | Availability behavior must be explicitly tested |
| Proxmox Snort/Suricata VM behind unmanaged switch | Add a **rated TAP**, replace unmanaged switch with SPAN-capable one, or mirror at upstream gateway | Ordinary unmanaged switches **cannot be assumed** to provide configurable SPAN |

### Fail-Open, Fail-Closed & Monitor Failure

- **Fail-open (bypass):** if the powered inline inspection system fails, production connectivity continues, but inspection may cease.
- **Fail-closed:** disconnects/blocks the production path during relevant failure modes; availability tradeoff must be authorized.
- **Monitor-port failure:** an out-of-band TAP might continue forwarding the production link while the sensor stops recording.
- **Power-loss bypass:** a particular active TAP may use relays, but only if its documentation says so. Don't treat "active" as synonymous with fail-safe.

For fiber: insertion of a splitter reduces available optical power on the production path and the monitor path. Check transmitter power, link budget, splitter ratio, receiver sensitivity, patch-cord losses and transceiver optics first. **A passive splitter does not make the link lossless.**

## Snort, Suricata, Zeek & Wireshark Integration

The basic architecture is:

```text
Production link ──[ approved TAP ]── production endpoint
                        │
            breakout A + breakout B
                        │
               Capture NIC(s) on Linux
                        │
        tcpdump/Wireshark, Zeek, Snort, Suricata
                        │
         Protected evidence disk + alerts/SIEM
```

| Component | Requirement |
|---|---|
| TAP | Correct speed/media and both link directions represented |
| Linux host | Supported physical NIC(s), capture driver and storage |
| Proxmox guest | USB/PCI passthrough, dedicated vSwitch mirror or upstream TAP feed |
| IDS software | Sensor mode, correct interface and timestamp source |
| Promiscuous mode | Allows receiving frames delivered by NIC, **does not itself make switch mirror other ports** |
| Privacy | Captured packets can contain secrets; restrict, encrypt, minimize and expire |

### Safe Local Read-Only Preflight

```bash
ip -brief link
ethtool eno2  # Replace with the approved lab capture NIC.
tcpdump --list-interfaces
```

Once an approved lab TAP/capture interface is configured, a bounded capture can be collected under documented data handling rules:

```bash
# Only on an authorized isolated test link; PCAP may contain sensitive data.
sudo timeout 30 tcpdump -i eno2 -nn -s 0 -w ./lab-tap-capture.pcap
sha256sum ./lab-tap-capture.pcap
```

A data diode or a receive-only monitor output can prevent sensor-originated frames from entering the tapped link **by physical design**. In contrast, a mirrored switch port still has its own switch-dependent configuration and security properties; don't describe all SPAN ports as hardware one-way taps.

## Preflight, Acceptance & Evidence Record

Before installing: identify link endpoints, scheduled maintenance, service owner, port/interface labels, link speed/duplex, cable category/length, PoE or industrial power, fiber connectors, routing visibility, data restrictions, rollback and permission to see each direction.

| Validation | Passing Evidence |
|---|---|
| Link baseline | Known measured speed/duplex/error counters before insertion |
| Maintenance | Change ticket, outage window & rollback plan |
| Link after insertion | Negotiated speed/duplex unchanged **unless explicitly allowed**; error count stable |
| Both directions visible | Owned synthetic request/response observed on proper ports |
| Capture quality | Packet drops reported, no unexplained one-way traffic |
| Performance | Throughput/latency acceptable for that site |
| Failure test | If allowed, power-loss and sensor-disconnect behavior validated |
| Security | Tool interface isolated, no bridge back to production, evidence access controlled |
| Recovery | Unplugging/reversion procedure and post-change validation |

## Common Errors & Limitations

| Symptom | Likely Explanation | Next Step |
|---|---|---|
| Only requests or responses appear | Breakout TAP exposes one direction per port | Use second capture NIC / merge with timestamp controls |
| 1 Gbps link becomes 100 Mbps | 10/100 passive tap intentionally changes negotiation | Remove it; use proper 1G-rated active TAP |
| Packets missing at high throughput | Aggregation oversubscription or sensor CPU/drop | Increase output capacity, check capture statistics |
| Mirror port shows only part of the network | SPAN scope, switch resources, VLAN filter | Verify configured source ports/VLANs |
| Sensor receives no traffic | Wrong port, link down, unpowered TAP, bad passthrough | Check cable LEDs, NIC state and tap manual |
| Ethernet traffic appears encrypted | TLS, IPsec, MACsec or application encryption | TAP does not decrypt; use permitted endpoint logs |
| Active TAP loses power and path drops | Model lacks bypass or failure behavior differs | Restore link, review vendor power-fail spec |
| Fiber link fails after splitter | Optical loss budget exhausted or connector error | Recalculate budget/clean and inspect optics |

## Sources & Existing Repository Guides

- [Great Scott Gadgets Throwing Star / Pro](https://greatscottgadgets.com/throwingstar/) & [open hardware](https://github.com/greatscottgadgets/throwing-star-lan-tap)
- [Datacom Systems: Copper Network TAPs 101](https://www.datacomsystems.com/copper-network-taps-101/)
- [Garland Technology TAP Guide](https://www.garlandtechnology.com/network-tap)
- [Niagara Networks: Network TAP Guide](https://www.niagaranetworks.com/products/network-tap-how-to-guide)
- [Network Detection](../Tradecraft/network-detection.md)
- [Wireshark](./wireshark.md) & [Wireshark Capture / Display Filter Guide](./wireshark-master-filters.md)
- [Homelab: Proxmox Security Visibility](../Homelab/proxmox-security-monitoring-visibility.md)
- [IDS/IPS](../IncidentResponse/IDS%26IPS/readme.md)
- [Cyberdeck Portable Device Architecture](../Cyberdeck/docs/PORTABLE_WIRELESS_FIELD_DEVICES.md)
- [SBC & Radio Add-Ons](./sbc-radio-addon-compatibility.md)

---

[Documentation Index](./README.md) | [Homelab Index](../Homelab/README.md) | [Legal Notice](../LEGAL.md)
