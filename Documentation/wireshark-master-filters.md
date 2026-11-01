# Wireshark Master Filter List — Display, Capture and TShark

*Reviewed: October 31, 2026 · Target: Wireshark/TShark 4.x · Passive authorized analysis*

[**One-page field cheat sheet**](./wireshark-cheatsheet.md) · [**133-entry filter catalog (TSV)**](./wireshark-filter-catalog.tsv) · [Advanced Wireshark/capture guide](./wireshark.md) · [Documentation index](./README.md) · [Main repository](../README.md)

> [!IMPORTANT]
> A **display filter** changes which *captured* packets you see; a **capture filter** decides what is retained. They are **different languages**. Filters are investigative selectors, not attack verdicts. This index uses example-only RFC 5737/3849 IP addresses and dummy MACs; replace with authorized targets. A switched Ethernet NIC or ordinary VM interface cannot see all LAN traffic or over-the-air 802.11 management frames merely because Wireshark is in promiscuous mode.

## Find the right tool

| Need | Go here | How |
| --- | --- | --- |
| Searchable master list of usable display expressions | [Filter catalog](./wireshark-filter-catalog.tsv) | 133 named filters grouped into 9 categories, plus usage caveats |
| Short everyday reference | [Field cheat sheet](./wireshark-cheatsheet.md) | Top filters, capture BPF, CLI and GUI workflows |
| Detailed remote capture, Bluetooth, Zigbee and router operations | [Existing advanced guide](./wireshark.md) | Longer procedure reference; review hardware/version caveats |
| Verify syntax against your installed Wireshark | [Catalog test tool](../tools/check_wireshark_filters.py) | No-packet-data validation with TShark; CI runs on changes |
| Investigate deauth/disassociation | [802.11 analysis](./wifi-deauthentication-detection.md) | PMF, frame subtype, capture limitations |
| Correlate Wi-Fi incidents and honeypots | [Kismet + Wazuh](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md) · [nzyme](../IncidentResponse/IDS%26IPS/nzyme-wazuh-integration.md) · [Honeypots](../IncidentResponse/HoneyPot/wazuh-honeypot-integration.md) | Additional evidence from distinct telemetry sources |

## Filter languages: do not mix

| Goal | Display filter (Wireshark green toolbar; `tshark -Y`) | Capture filter (libpcap BPF; `tcpdump` / `tshark -f`) |
| --- | --- | --- |
| See web-port TCP | `tcp.port == 443` | `tcp port 443` |
| One IPv4 host | `ip.addr == 192.0.2.10` | `host 192.0.2.10` |
| DNS on traditional ports | `udp.port == 53 || tcp.port == 53` | `port 53` |
| IP network | `ip.addr == 10.0.0.0/8` | `net 10.0.0.0/8` |
| Exclude SSH management during remote capture | `!(tcp.port == 22)` | `not tcp port 22` |

- **Capture filters are applied before packets are saved**; an excluded packet cannot be recovered from that capture. Capture filters cannot be changed mid-capture. Choose least-invasive scope compatible with the investigation.
- **Display filters don't delete bytes in the PCAP**; saved files still contain hidden credentials, payloads and personal data. An exported **displayed-only** subset is a separate derived artifact, not the original evidence.
- **Decoded protocol ≠ port number**. `tls` only shows TLS packets that Wireshark decoded, and encrypted HTTP content stays hidden without authorized decryption. HTTP/3/QUIC commonly uses UDP 443. DNS may use DNS-over-TLS/HTTPS/QUIC, so port 53 cannot find every lookup.
- **Filter snippets must contain only the expression.** Explanatory comments are placed *outside* the filter, never pasted into the Wireshark toolbar.

## Quick display-filter selection

Each example below is a complete **display filter** suitable for the green toolbar or `tshark -Y`.

### Devices, flows and network visibility

| Question | Filter | Reading |
| --- | --- | --- |
| All packets to/from one IPv4 host | `ip.addr == 192.0.2.10` | Any direction |
| Two IPv4 endpoints | `ip.addr == 192.0.2.10 && ip.addr == 198.51.100.20` | Both endpoint addresses |
| IPv4 subnet | `ip.addr == 10.0.0.0/8` | Either side in subnet |
| IPv6 host | `ipv6.addr == 2001:db8::1` | IPv6 address selector |
| TCP session ID | `tcp.stream == 0` | Change ID based on **this** capture |
| UDP conversation ID | `udp.stream == 0` | Change ID based on capture |
| Frames after 10 seconds | `frame.time_relative > 10` | Relative to start of file |
| Only larger frames | `frame.len > 1400` | Size alone isn't suspicious |
| VLAN frames | `vlan` | Tags may be stripped by NIC/driver |

Use **Statistics → Conversations / Endpoints / Protocol Hierarchy / I/O Graphs** before drawing conclusions from a single filtered frame. Right-click a packet → **Follow → TCP Stream** for the reconstructed visible conversation; avoid exposing client payloads in screenshots.

### Slow networks, broken connections and intermittent problems

| Symptom | Filter | Investigate |
| --- | --- | --- |
| Starting a connection | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Compare SYN and SYN-ACK timing |
| Handshake reply | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | Was a server reached? |
| TCP resets | `tcp.flags.reset == 1` | Wrong port, application close, middlebox |
| Retransmissions | `tcp.analysis.retransmission` | Loss, congestion, capture artifacts |
| Duplicate ACKs | `tcp.analysis.duplicate_ack` | Loss/reordering clue |
| Out-of-order segments | `tcp.analysis.out_of_order` | Multi-path/reordering or capture vantage |
| Receiver cannot accept more | `tcp.analysis.zero_window` | App/host processing bottleneck |
| Relative TCP gap >1 second | `tcp.time_delta > 1` | Context-dependent per-conversation gap |

A missing packet or missing SYN-ACK can also be a **capture-path problem** (asymmetric routing, SPAN overload, wrong interface, packet drops). Don't automatically label retransmissions as WAN packet loss.

### DHCP, DNS, ARP and IPv6 neighbor discovery

| Question | Filter | Notes |
| --- | --- | --- |
| DHCPv4 discovery | `dhcp.option.dhcp == 1` | DHCP Discover |
| DHCPv4 server offer | `dhcp.option.dhcp == 2` | DHCP Offer |
| DHCPv4 request | `dhcp.option.dhcp == 3` | DHCP Request |
| DHCPv4 ACK / NAK | `dhcp.option.dhcp == 5 || dhcp.option.dhcp == 6` | Check server and client sequence |
| DNS queries | `dns.flags.response == 0` | Only decoded DNS |
| DNS failures | `dns.flags.response == 1 && dns.flags.rcode != 0` | Many benign reasons |
| NXDOMAIN | `dns.flags.rcode == 3` | Nonexistent names may be ordinary |
| Long question names | `dns.qry.name.len > 50` | Heuristic only, not DNS exfil proof |
| ARP replies | `arp.opcode == 2` | Not all replies are forged |
| IPv6 router advertisements | `icmpv6.type == 134` | Confirm source/authorized routers |

When verifying DHCP, take a capture that starts *before* client renewal and includes broadcast traffic. For possible ARP poisoning, compare multiple packets, ARP cache changes, known router MAC, switches and management telemetry.

### HTTP, TLS, QUIC, identity and service activity

| Area | Filter | Caveat |
| --- | --- | --- |
| HTTP requests | `http.request` | Only visible when decoded |
| HTTP error responses | `http.response.code >= 400` | Routine errors included |
| HTTP server name | `http.host contains "example"` | Only visible HTTP/1.x host |
| TLS ClientHello | `tls.handshake.type == 1` | Metadata when visible |
| TLS SNI | `tls.handshake.extensions_server_name contains "example"` | Encrypted ClientHello may hide it |
| QUIC packets | `quic` | HTTP/3 commonly uses QUIC |
| Common QUIC/HTTP3 port | `udp.port == 443` | Port alone does not prove QUIC |
| SMB2 / SMB3 | `smb2` | Useful in Windows sharing analysis |
| Kerberos | `kerberos` | AD authentication traffic |
| LDAP | `ldap` | LDAPS contents usually opaque |
| NTLMSSP | `ntlmssp` | Context required before labeling an attack |
| RDP default TCP port | `tcp.port == 3389` | RDP can also use UDP |
| SSH default TCP port | `tcp.port == 22` | Contents encrypted |

Never present a single SSH connection, Kerberos ticket, RDP flow, POST request, long DNS query or port scan-like SYN as proof of unauthorized activity. Use timing, volume, scope and endpoint logs.

### 802.11 / wireless and IoT

> [!WARNING]
> `wlan` filters need a **raw 802.11 monitor-mode capture** with supported hardware, appropriate driver and correct channel. Ordinary wired/VM captures generally cannot show the original management frames. Claimed BSSID/source addresses can be spoofed.

| Event | Filter | Limits |
| --- | --- | --- |
| Beacons | `wlan.fc.type_subtype == 0x08` | AP announcements |
| Probe requests | `wlan.fc.type_subtype == 0x04` | Normal client discovery |
| Authentication | `wlan.fc.type_subtype == 0x0b` | 802.11 authentication subtype |
| Disassociation | `wlan.fc.type_subtype == 0x0a` | Legitimate or forged |
| Deauthentication | `wlan.fc.type_subtype == 0x0c` | Legitimate or forged |
| Both disconnect subtypes | `wlan.fc.type_subtype == 0x0a || wlan.fc.type_subtype == 0x0c` | No verdict from count alone |
| Claimed BSSID | `wlan.bssid == aa:bb:cc:dd:ee:ff` | Verify against trusted AP/controller |
| EAPOL exchange | `eapol` | Not a deauth packet |
| BLE | `btle` | Requires appropriate capture hardware |
| Zigbee network | `zbee_nwk` | Requires 802.15.4 capture |
| MQTT | `mqtt` | Decoded IoT transport |
| Modbus | `modbus` | OT/ICS context; passive analysis only |

Corroborate deauth/disassociation *rate* with actual client disconnect logs, PMF negotiated state, channel coverage, Kismet/nzyme detections and planned network maintenance. Kismet alerts and an exported PCAP recorded by the same sensor do not constitute independent physical confirmation.

## Capture filters (BPF) — use BEFORE starting

These are examples of **capture filters**, **not display filters**:

| Capture purpose | BPF |
| --- | --- |
| One host, both directions | `host 192.0.2.10` |
| A pair of hosts | `host 192.0.2.10 and host 198.51.100.20` |
| Traditional DNS | `port 53` |
| SSH + HTTPS | `tcp port 22 or tcp port 443` |
| Only subnet | `net 10.0.0.0/8` |
| Exclude unrelated SSH control connection | `not tcp port 22` |
| Only IPv4 ICMP | `icmp` |
| All ARP | `arp` |
| Exclude ARP while measuring TCP | `tcp and not arp` |

Wireless BPF depends on the capture link type; do **not** assume Ethernet expressions such as `ether host` work on every monitor-mode capture. VLAN tags may require BPF syntax adjustments, and packet truncation can hide fields needed for analysis.

## TShark, dumpcap and safe evidence collection

These are **shell commands**; change paths, interface names and addresses to match your environment. Capture only authorized data.

~~~bash
# Discover local capture interfaces and versions
tshark --version
dumpcap -D

# PCAP of a limited period and file size (capture filter, NOT display filter)
sudo dumpcap -i eth0 -f 'host 192.0.2.10' -a duration:120 -w capture.pcapng

# Display-filter previously collected PCAP without touching original
tshark -n -r capture.pcapng -Y 'tcp.analysis.retransmission'

# Extract a small, reviewable table from selected packets
tshark -n -r capture.pcapng -Y 'dns.flags.response == 0' \
  -T fields -E header=y -E separator=, -E quote=d \
  -e frame.time_epoch -e ip.src -e ip.dst -e dns.qry.name \
  > dns-queries.csv

# Print counts by protocol; useful for orientation, not incident verdicts
tshark -n -r capture.pcapng -q -z io,phs

# Preserve original evidence integrity BEFORE any derived export
sha256sum capture.pcapng

# Check every filter in this repo's TSV catalog (requires TShark)
python3 tools/check_wireshark_filters.py
~~~

**If capturing over SSH:** a remote `tcpdump -w -` pipe carries binary bytes over stdout; remote profile banners/interactive shell output can corrupt the stream. Filter out the management session **only** when appropriate, prevent unbounded captures, and keep remote credentials/logs out of shared examples. See the [advanced guide](./wireshark.md).

## Reusable filters and personal workflows

1. In Wireshark, open **Analyze → Display Filters…** (or the display-filter bookmark dropdown → **Manage Display Filters**).
2. Name a filter after its question, e.g., "TCP resets" rather than "bad connections"; paste only the `display_filter` cell from the [catalog](./wireshark-filter-catalog.tsv).
3. Save the filter and keep original PCAPs separate from notes, derived CSVs and screenshots.
4. To update the repository, add a **single row** to the tab-separated catalog with category, descriptive name, expression and evidence caveat.
5. Run `python3 tools/check_wireshark_filters.py --structure-only` or, with TShark installed, the full syntax check. CI uses TShark for expression compilation. The TSV catalog is **not** the native Wireshark profile `dfilters` import format; it is a documented source for manually saved filters.

## Common analysis traps

- **False confidence from a port:** `tcp.port == 443` is not equivalent to "all HTTPS," `dns` does not cover all encrypted DNS, `tcp.port == 3389` is not proof of RDP use.
- **Non-scoping of negative filters:** `!(ip.addr == 192.0.2.10)` still permits other protocols and both IPv4/IPv6 as allowed by the filter engine.
- **Uncaptured packets:** no filter can reveal traffic that the tap, mirror, monitor channel or NIC never recorded.
- **Sensitive captures:** packet files can include usernames, filenames, tokens, DNS history and unencrypted content even if the current display filter hides them.
- **Heuristic alerts:** large packets, DNS name lengths, ARP replies, SYNs and 802.11 deauth frames are evidence to contextualize, not attack confirmation.
- **Version-specific fields:** confirm in Wireshark's field expression builder or official reference when opening a PCAP with a different Wireshark version; the catalog validator establishes syntax on the TShark build it actually runs.

## Source of truth and related guides

- [Wireshark display-filter grammar](https://www.wireshark.org/docs/man-pages/wireshark-filter)
- [Wireshark display-filter field index](https://www.wireshark.org/docs/dfref/)
- [Wireshark capture filters](https://wiki.wireshark.org/CaptureFilters)
- [libpcap filter grammar](https://www.wireshark.org/docs/man-pages/pcap-filter.html)
- [Wireshark saved filter management](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkDefineFilterSection.html)
- [802.11 deauthentication and PMF guide](./wifi-deauthentication-detection.md)
- [Kismet/Wazuh wireless lab](../IncidentResponse/IDS%26IPS/kismet-wazuh-wireless-lab.md)
- [Snort guide](../IncidentResponse/IDS%26IPS/snort.md) · [Suricata + Zeek](../IncidentResponse/IDS%26IPS/suricata+zeek.md) · [Honeypots](../IncidentResponse/HoneyPot/readme.md)
- [Legal and scope requirements](../LEGAL.md)

*Version and validation note: filter syntax and fields are checked against the installed TShark version in CI; hardware captures, decryption, and incident interpretations require separate, real-world validation.*
