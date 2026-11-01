# Wireshark Field Cheat Sheet

*Reviewed: October 31, 2026 · For Wireshark/TShark 4.x*

[**Master guide**](./wireshark-master-filters.md) · [133 searchable display filters (TSV)](./wireshark-filter-catalog.tsv) · [Advanced captures](./wireshark.md) · [PDF reference (legacy)](../PDF/Wireshark_Cheat_Sheet.pdf) · [Documentation index](./README.md)

## The two filter languages

| Situation | Display filter (Wireshark / `tshark -Y`) | Capture filter (pcap BPF / `tshark -f`) |
| --- | --- | --- |
| TCP 443 | `tcp.port == 443` | `tcp port 443` |
| One host | `ip.addr == 192.0.2.10` | `host 192.0.2.10` |
| DNS port | `udp.port == 53 || tcp.port == 53` | `port 53` |
| All traffic in subnet | `ip.addr == 10.0.0.0/8` | `net 10.0.0.0/8` |
| Exclude SSH | `!(tcp.port == 22)` | `not tcp port 22` |

**Display** = show/hide packets **already collected**. **Capture** = determine which traffic is saved. Neither changes the traffic on the network. Replace sample IPs with actual in-scope addresses.

## Copy/paste display filters

| Investigating | Expression |
| --- | --- |
| All TCP / UDP | `tcp` / `udp` |
| All ICMP / ARP | `icmp || icmpv6` / `arp` |
| Device by IPv4 | `ip.addr == 192.0.2.10` |
| Two IPv4 endpoints | `ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20` |
| IPv6 device | `ipv6.addr == 2001:db8::1` |
| TCP stream | `tcp.stream == 0` |
| TCP connection attempts | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| SYN-ACK responses | `tcp.flags.syn == 1 && tcp.flags.ack == 1` |
| TCP resets | `tcp.flags.reset == 1` |
| Retransmissions | `tcp.analysis.retransmission` |
| Duplicate ACKs | `tcp.analysis.duplicate_ack` |
| TCP zero window | `tcp.analysis.zero_window` |
| TCP payload segments | `tcp.len > 0` |
| DNS queries / answers | `dns.flags.response == 0` / `dns.flags.response == 1` |
| DNS NXDOMAIN | `dns.flags.rcode == 3` |
| DNS failures | `dns.flags.response == 1 && dns.flags.rcode != 0` |
| DHCP Discover | `dhcp.option.dhcp == 1` |
| DHCP Offer | `dhcp.option.dhcp == 2` |
| DHCP Request | `dhcp.option.dhcp == 3` |
| DHCP ACK | `dhcp.option.dhcp == 5` |
| ARP replies | `arp.opcode == 2` |
| IPv6 router advertisements | `icmpv6.type == 134` |
| HTTP requests | `http.request` |
| HTTP errors | `http.response.code >= 400` |
| TLS ClientHello | `tls.handshake.type == 1` |
| TLS ServerHello | `tls.handshake.type == 2` |
| QUIC | `quic` |
| HTTP/3 transport candidate | `udp.port == 443` |
| Windows file shares | `smb2` |
| Kerberos / LDAP | `kerberos` / `ldap` |
| SSH / RDP default TCP port | `tcp.port == 22` / `tcp.port == 3389` |
| Local discovery | `mdns || llmnr || ssdp || nbns` |
| MQTT / CoAP | `mqtt` / `coap` |
| Wi-Fi management frames | `wlan.fc.type == 0` |
| Wi-Fi beacons | `wlan.fc.type_subtype == 0x08` |
| Wi-Fi deauthentication | `wlan.fc.type_subtype == 0x0c` |
| Wi-Fi disassociation | `wlan.fc.type_subtype == 0x0a` |
| Both wireless disconnect types | `wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a` |
| EAPOL | `eapol` |
| BLE / Zigbee | `btle` / `zbee_nwk` |

**Important:** An ARP reply is not automatically poisoning; a SYN isn't automatically a scan; a deauth isn't automatically spoofed; a long DNS name isn't automatically exfiltration. Encrypted traffic generally reveals metadata, not application contents.

## In a client visit or blue-team incident

1. **Find device:** `ip.addr == 192.0.2.10` → Statistics → Conversations.
2. **Find broken connection:** SYN and SYN-ACK filters → resets → retransmissions → TCP stream.
3. **Find DNS or address failures:** DNS response and DHCP sequence filters; cross-reference endpoint logs.
4. **Assess suspicious access:** prioritize destinations and repeated failed attempts, not individual ports.
5. **Assess Wi-Fi disconnects:** a proper **monitor-mode, fixed-channel** capture is required; check AP/controller and PMF evidence. See [wireless packet investigation](./wifi-deauthentication-detection.md).

## Most useful menus

| Wireshark menu | Why |
| --- | --- |
| **Capture → Options** | Choose interface, capture filter, ring buffer |
| **Statistics → Protocol Hierarchy** | High-level protocol mix |
| **Statistics → Endpoints / Conversations** | Top communicating devices and flows |
| **Statistics → I/O Graphs** | Compare rates and drops over time |
| **Analyze → Expert Information** | Heuristic errors/warnings to validate |
| **Right-click a packet → Follow → TCP Stream** | Trace visible application conversation |
| **Analyze → Display Filters…** | Save named display filters for reuse |

## TShark command crib

~~~bash
# Discover interfaces
dumpcap -D

# Two-minute scoped capture using BPF; interface is an example
sudo dumpcap -i eth0 -f 'host 192.0.2.10' -a duration:120 -w capture.pcapng

# Read a saved trace with a display filter
tshark -n -r capture.pcapng -Y 'tcp.analysis.retransmission'

# DNS question names, with fields in CSV
tshark -n -r capture.pcapng -Y 'dns.flags.response == 0' \
  -T fields -E header=y -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e dns.qry.name

# Hash the unchanged original before creating derived output
sha256sum capture.pcapng

# Check all catalog expressions in a local TShark installation
python3 tools/check_wireshark_filters.py
~~~

**Scope/privacy:** Capture only authorized networks and data, protect original PCAP/PCAPNG files, and preserve timestamps/interface information. A display filter does not sanitize a capture. SPAN/TAP or suitable AP/radio telemetry is essential for network-wide visibility; promiscuous mode alone is insufficient on a switched network.

[Official display grammar](https://www.wireshark.org/docs/man-pages/wireshark-filter) · [Official field reference](https://www.wireshark.org/docs/dfref/) · [Capture/BPF reference](https://wiki.wireshark.org/CaptureFilters) · [Legal guidance](../LEGAL.md)
