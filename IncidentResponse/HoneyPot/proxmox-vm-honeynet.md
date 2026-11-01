# Proxmox VM Honeynet: Isolation, Decoys and Wazuh

_Last reviewed: 2026-10-31 · Works conceptually with PVE 9 and current Linux guests_

## Why start with VMs?

VMs simplify isolated networking, disposable rebuilds, revertable configurations and separate log collectors. **Snapshots are not backups** and a compromised guest still has network connectivity unless the host/firewall prevents it. A honeypot must not share the management plane or trust boundary of a production VM.

## Reference design

~~~text
Internet / authorized test client
          |
UniFi / router, explicit VLAN or firewall rules
          |
       vmbr-decoy (isolated, no direct management trust)
         |                 |
         |            VM-B: Cowrie SSH/Telnet
         |
     VM-A: OpenCanary, low-interaction ports

Wazuh agent → narrowly permitted egress → Wazuh manager
PVE management + backup storage live on separate trusted interface/VLAN
~~~

**Proxmox deployment notes:** Avoid assuming a Linux bridge is a firewall. Use correct VLAN awareness, PVE firewall rules and upstream gateway policies. Verify guest isolation *from inside the guest* before exposing decoy listeners. Avoid host USB passthrough for something unrelated unless the security boundary requires it. If using a dedicated internal-only bridge with no uplink, have an approved test VM on that bridge; do not expect internet traffic.

## VM sizing and install order

| Guest | Example baseline (not vendor minimum) | Notes |
| --- | --- | --- |
| OpenCanary | 1 vCPU, 1-2 GiB RAM, 10-20 GiB disk | Prefer unprivileged app user and service config |
| Cowrie | 2 vCPU, 2 GiB RAM, 20+ GiB disk | Session logs and captured artifacts grow |
| T-Pot Hive | Officially ~16 GiB RAM, 256 GiB SSD | Dedicated VM, review current supported distro/release |
| T-Pot Sensor | Officially ~8 GiB RAM, 128 GiB SSD | Distributed Hive/Sensor configuration |

Choose minimal server distributions and patch before starting decoys. Install Wazuh agents **within the Linux guests**; for T-Pot, use its supported collection pipeline rather than injecting an arbitrary agent into containers.

## Practical defensive steps

1. Create a decoy-specific VLAN / isolated bridge, separate from trusted PVE management, storage and client networks.
2. Deny decoy-to-trusted network access **at the router/firewall**. Allow only declared Wazuh, time sync, and patching egress; explicitly test DNS and IPv6 paths.
3. Build VM-A and VM-B from known-good images; do not store credentials or mount host shares into the guests.
4. Configure OpenCanary and Cowrie using their respective guides; prefer high-numbered ports initially so SSH management remains intact.
5. Enroll each guest's Wazuh agent; connect native JSON output using [Wazuh Honeypot Reporting](./wazuh-honeypot-integration.md).
6. From an authorized test VM, trigger a benign connection. Confirm the host firewall isolation, service log, Wazuh rule and dashboard.
7. Preserve a sanitized baseline template and document rebuild paths; do not depend solely on PVE snapshots after compromise.

## T-Pot caveats

T-Pot uses Docker, a collection of honeypots, and its own Elastic stack; running it **alongside** a full Wazuh stack may duplicate large data volumes and consume substantial resources. Its official documentation lists both Hive and Sensor deployment modes and supported minimal distributions, and these can change.

Avoid directly deploying internet-wide exposure until you have isolated outbound controls, restricted management, verified resource headroom and an incident handling plan. **Do not run an unreviewed remote curl-to-shell installer or grant blanket passwordless sudo as a convenience.** Clone official repo/review installer/choose pinned release, then follow upstream supported process. See [T-Pot guide](./tpot.md) and [official T-Pot reference](https://github.com/telekom-security/tpotce).

## Cross-correlation with wireless sensors

- Kismet and nzyme on monitor-capable radios capture Wi-Fi security **events**; a PVE VM with virtual Ethernet sees wired IP flows instead.
- A wireless event and a Cowrie login near the same time **may be unrelated**. Require site/asset mapping, controller/endpoint logs and session evidence.
- For internal lateral movement tripwires, a honeypot in a controlled decoy VLAN with explicit access from a production segment can show unexpected access attempts; follow written authorization and preserve a fallback.

## Cross-links

[Wazuh Reporting](./wazuh-honeypot-integration.md) · [T-Pot](./tpot.md) · [OpenCanary](./opencanary.md) · [Cowrie](./cowrie.md) · [Kismet + Wazuh](../IDS%26IPS/kismet-wazuh-wireless-lab.md) · [nzyme + Wazuh](../IDS%26IPS/nzyme-wazuh-integration.md) · [Homelab](../../Homelab/README.md)

---

[Honeypot Index](./readme.md) | [Incident Response](../README.md) | [Main Index](../../README.md)
