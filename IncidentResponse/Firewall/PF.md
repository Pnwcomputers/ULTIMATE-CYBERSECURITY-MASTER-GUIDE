# 🔥 OpenBSD PF Firewall: The Practical Guide

<div align="center">

**Rulesets, NAT, DMZs, bridges, wireless, high availability, adaptive defense, traffic shaping, and NetFlow monitoring — end to end**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Domain](https://img.shields.io/badge/Domain-Network_Defense-blue?style=for-the-badge)
![Packet Filter](https://img.shields.io/badge/Tool-PF_Packet_Filter-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-OpenBSD_%7C_FreeBSD-red?style=for-the-badge)
![Verified](https://img.shields.io/badge/Sources-Man_Pages_Verified-brightgreen?style=for-the-badge)

</div>

---

## 🎯 Purpose
A hands-on, build-it-yourself reference for OpenBSD's Packet Filter (PF) — the tool that turns a BSD box into a stateful firewall, NAT gateway, load balancer, and network sensor. Covers IPv4 **and** IPv6 across LANs, NAT, DMZs, bridges, and routed networks, with FreeBSD differences flagged throughout.

## ⚙️ Function
Walks from the PF evaluation model up through progressively harder deployments: baseline rulesets, multi-interface gateways, wireless APs with `authpf`, redundancy via CARP/pfsync/relayd, adaptive brute-force and spam defense, the modern queue/`prio` traffic shaper, and native NetFlow/IPFIX export with `pflow`.

## 🏆 Goal
Enable an operator to reason about a ruleset rather than copy-paste one — to design a redundant, self-defending, observable network edge and understand *why* every line is there.

## 📋 When to Use
- Standing up a new OpenBSD/FreeBSD firewall, NAT gateway, or DMZ segment from scratch
- Adding high availability (CARP + pfsync) or load balancing (relayd) to an existing edge
- Building adaptive defenses against brute-force, floods, or spam
- Shaping traffic to kill bufferbloat, or wiring the firewall into a SIEM via NetFlow/IPFIX
- Learning PF properly in a lab before touching production

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The Mental Model](#-the-mental-model)
- [Ruleset Fundamentals](#-ruleset-fundamentals)
- [Network Scenarios](#-network-scenarios)
- [Wireless & authpf](#-wireless--authpf)
- [High Availability](#-high-availability)
- [Adaptive Defense](#-adaptive-defense)
- [Traffic Shaping](#-traffic-shaping)
- [Monitoring & Visualization](#-monitoring--visualization)
- [Workflow & Testing](#-workflow--testing)
- [⚠️ CRITICAL Operational & Legal Warning](#️-critical-operational--legal-warning)
- [Contributing](#-contributing)
- [References & Resources](#-references--resources)

---

## 🎯 Overview

PF is the OpenBSD packet filter: a single, readable `/etc/pf.conf` drives stateful filtering, NAT, redirection, queueing, and normalization. This guide targets **modern OpenBSD (6.x / 7.x)** and calls out FreeBSD's forked PF inline.

> **Status:** Technical claims here were verified against the OpenBSD manual pages (`man.openbsd.org`) and the official [OpenBSD PF FAQ](https://www.openbsd.org/faq/pf/). PF syntax still drifts between releases — treat the man pages on *your* box as the final authority, and validate every ruleset with `pfctl -nf` before loading it.

### 🧭 Version & Syntax Timeline

PF has had breaking syntax changes; configs from old blog posts frequently won't load. Know which era you're in:

| Release | Change | Impact |
|---------|--------|--------|
| **OpenBSD 4.6** | `scrub` became a `match` action | `match in all scrub (...)`; standalone `scrub` rules removed |
| **OpenBSD 4.7** (2010) | NAT folded into the main ruleset | `nat-to` / `rdr-to` / `binat-to` replace separate `nat`/`rdr`/`binat` sections |
| **OpenBSD 5.5** (2014) | New `queue` / `prio` shaper introduced | ALTQ deprecated (still usable that release via `oldqueue`) |
| **OpenBSD 5.6** (2014) | **ALTQ removed entirely** | Only the new queueing system remains on OpenBSD |
| **OpenBSD 6.3** (2018) | `set syncookies` added | Adaptive SYN-flood protection |
| **FreeBSD PF** | Fork of older OpenBSD PF | Keeps **ALTQ**, adds **Dummynet**, no `match … scrub`, differing keywords |

> **Golden rule:** the authoritative reference for *your* box is the man pages on *your* box — `man pf.conf`, `man pf`, `man pfctl`, `man carp`, `man authpf`, `man spamd`, `man relayd.conf`, `man pflow`. `man` beats any blog (including this one).

---

## 🧠 The Mental Model

Most PF confusion is really confusion about evaluation order. Internalize this before writing a rule.

### 🔄 The Processing Model

- PF reads `/etc/pf.conf` top to bottom for **every** packet.
- **Last matching rule wins** — unless a rule uses `quick`, which stops evaluation immediately. This is the single most important sentence in this guide.
- Three verbs:

| Verb | Meaning |
|------|---------|
| `block` | Drop or reject the packet |
| `pass` | Allow it (and, by default, **create state** — see fundamentals) |
| `match` | Don't decide pass/block, but apply actions (NAT, queueing, scrub, marking) |

### 🚦 block-policy: drop vs return

```pf
set block-policy drop      # silently discard (stealthy; sender sees a timeout)
# set block-policy return  # actively reject (RST for TCP, ICMP unreachable otherwise)
```

`drop` is stealthier; `return` is friendlier to your own hosts. A common approach: `drop` globally, override with `block return` on internal rules.

### 🛠️ Enabling and Driving PF

```sh
# OpenBSD: PF is on by default. Ruleset path is set in rc.conf(8): pf_rules=/etc/pf.conf
# FreeBSD: /etc/rc.conf -> pf_enable="YES"  and  pflog_enable="YES"

pfctl -e                 # enable PF
pfctl -d                 # disable PF (careful on a remote box!)
pfctl -nf /etc/pf.conf   # PARSE ONLY - validate syntax, load nothing. Do this every time.
pfctl -f  /etc/pf.conf   # load the ruleset
pfctl -sr                # show current rules
pfctl -ss                # show state table
pfctl -si                # show global info/counters
pfctl -sa                # show (almost) everything
```

> **🔒 Remote-admin safety:** never `pfctl -f` a ruleset you haven't `-nf`-checked, and when working remotely, arrange an auto-revert so a mistake can't lock you out:
> ```sh
> pfctl -f /etc/pf.conf && sleep 60 && pfctl -f /etc/pf.conf.known-good
> ```
> Better still: a cron/at job that reloads the last-known-good ruleset in N minutes unless you cancel it.

---

## 🧱 Ruleset Fundamentals

### 📦 Macros, Lists, and Tables

**Macros** are variables — so a re-IP or interface swap is a one-line change:

```pf
ext_if = "em0"
int_if = "em1"
int_net = "10.0.0.0/24"
tcp_services = "{ ssh, http, https }"
```

**Lists** (`{ ... }`) expand into multiple rules automatically:

```pf
pass in on $ext_if proto tcp to port $tcp_services   # expands to 3 rules
```

**Tables** are the workhorse for large or dynamic address sets — hashed (fast at thousands of entries) and modifiable live without a full reload, which is why adaptive defense leans on them:

```pf
table <bruteforce> persist                                # empty, survives reloads
table <trusted> const { 10.0.0.0/24, 192.168.9.0/24 }     # immutable
table <spamd> persist file "/etc/mail/spamd.block"        # loaded from file
```

```sh
pfctl -t bruteforce -T show           # list entries
pfctl -t bruteforce -T add 1.2.3.4    # add live
pfctl -t bruteforce -T delete 1.2.3.4 # remove live
pfctl -t bruteforce -T expire 86400   # drop entries idle > 1 day (cron this!)
```

### 🧼 Normalization (scrub) and antispoof

Scrub reassembles fragments and sanitizes packets. On modern OpenBSD it's a `match` action:

```pf
match in all scrub (no-df random-id max-mss 1440)
```

> **⚙️ FreeBSD difference:** FreeBSD PF does **not** understand `match … scrub`. Use the standalone form: `scrub in all no-df random-id max-mss 1440`

`antispoof` auto-generates rules dropping packets that claim a network on the wrong interface:

```pf
antispoof quick for { lo $int_if }
```

### 🔗 Stateful Filtering — the Default That Saves You

A matching `pass` rule creates a **state entry**, and reply traffic is allowed automatically — you almost never write rules for return traffic. Keeping state is the default; tune it:

```pf
pass in on $ext_if proto tcp to port 22 \
    keep state (max-src-conn 15, max-src-conn-rate 5/3)
```

### 🧩 A Complete Single-Host Baseline

A sane starting ruleset for one machine. Read every line.

```pf
# ---------- macros ----------
ext_if = "em0"

# ---------- tables ----------
table <bruteforce> persist

# ---------- options ----------
set block-policy drop
set loginterface $ext_if
set skip on lo0                 # never filter loopback - do this, always

# ---------- normalization ----------
match in all scrub (no-df random-id max-mss 1440)

# ---------- spoofing ----------
antispoof quick for { lo0 $ext_if }

# ---------- default deny ----------
block log all                   # deny everything, log it, then poke holes below

# ---------- brute-force jail ----------
block quick from <bruteforce>

# ---------- outbound: let the host talk ----------
pass out quick inet
pass out quick inet6

# ---------- ICMP / ICMPv6 (don't skip v6 - see note) ----------
pass in inet proto icmp icmp-type { echoreq, unreach }
pass in inet6 proto icmp6 icmp6-type { echoreq, unreach, neighbrsol, neighbradv, routersol, routeradv }

# ---------- inbound services ----------
pass in on $ext_if proto tcp to port 22 \
    keep state (max-src-conn 15, max-src-conn-rate 5/3, \
    overload <bruteforce> flush global)
```

> **🚨 Critical IPv6 note:** IPv6 *depends* on ICMPv6 — Neighbor Discovery replaces ARP, and Path MTU Discovery relies on "packet too big" messages. Blanket-blocking ICMPv6 the way people historically blocked ICMP on v4 breaks IPv6 in confusing, intermittent ways. Always pass neighbor solicitation/advertisement and unreachables on any v6 interface.

### ⚖️ Dual-Stack Discipline

`inet` = IPv4, `inet6` = IPv6; a rule with neither applies to both. Be explicit to avoid the classic "tight on v4, wide open on v6" failure.

---

## 🌐 Network Scenarios

The box becomes a **gateway/firewall** with multiple interfaces. The `egress` keyword means "whichever interface holds the default route," so rules survive an uplink change. This section mirrors the official PF FAQ "Building a Router" example.

### 🔀 IPv4 NAT (Hiding a LAN)

```pf
ext_if = "em0"          # WAN
int_if = "em1"          # LAN
int_net = "10.0.0.0/24"

# Translate outbound LAN traffic to the firewall's external address.
match out on egress inet from $int_net to any nat-to (egress:0)

pass out quick on egress inet
pass in  on $int_if inet from $int_net to any     # let the LAN out
```

- `nat-to (egress:0)` uses the egress interface's current primary address; parentheses re-evaluate it if the IP changes (DHCP WAN), and `:0` avoids alias addresses.
- NAT is part of the ruleset, so order matters: `match … nat-to` applies translation, then a later `pass` must still allow the packet.

> **⚙️ FreeBSD:** same `nat-to` syntax. Very old docs show the legacy `nat on $ext_if … -> ($ext_if)` form.

### ↪️ Port Forwarding / Inbound Redirection (rdr-to)

```pf
webserver = "10.0.0.10"
sshhost   = "10.0.0.11"

pass in on egress inet proto tcp to (egress) port { 80, 443 } rdr-to $webserver
pass in on egress inet proto tcp to (egress) port 2222 rdr-to $sshhost port 22
```

Redirect and filter decision are the same rule now. If you split them, PF filters on the **translated** (post-rdr) address for inbound.

### 🌍 IPv6 — No NAT, Just Routing + Filtering

IPv6 hosts get globally routable addresses; the firewall **routes** rather than translates. Your job is filtering, not hiding.

```pf
int6_net = "2001:db8:10::/64"

pass out quick on egress inet6 from $int6_net to any
pass in  on $int_if inet6 from $int6_net to any

# Inbound to a specific v6 service host - reachable directly, so filter tightly:
pass in on egress inet6 proto tcp to 2001:db8:10::10 port { 80, 443 }

# ICMPv6 essentials on BOTH sides (see the v6 warning above)
pass inet6 proto icmp6 icmp6-type { echoreq, unreach, timex, paramprob, \
    neighbrsol, neighbradv, routersol, routeradv, toobig }
```

Need to translate v6 (renumber avoidance)? OpenBSD supports **NPTv6** via `binat-to` on the prefix — but reach for it rarely.

### 🧱 A DMZ (Three-Legged Firewall)

Segment public-facing services onto their own interface so a compromise there can't pivot into the LAN.

```pf
ext_if = "em0"           # WAN
int_if = "em1"           # trusted LAN   10.0.0.0/24
dmz_if = "em2"           # DMZ           10.0.2.0/24
dmz_web = "10.0.2.10"

match out on egress inet from { 10.0.0.0/24, 10.0.2.0/24 } to any nat-to (egress:0)

block log all

# Internet -> DMZ web only
pass in on egress inet proto tcp to (egress) port { 80, 443 } rdr-to $dmz_web

# LAN -> anywhere
pass in on $int_if inet from 10.0.0.0/24 to any

# DMZ -> Internet ONLY (never let the DMZ initiate into the LAN)
pass in on $dmz_if inet from 10.0.2.0/24 to !10.0.0.0/24
block quick on $dmz_if from 10.0.2.0/24 to 10.0.0.0/24   # belt-and-suspenders
```

**Model:** the DMZ is untrusted. Traffic flows Internet→DMZ and DMZ→Internet, but DMZ→LAN is denied. If the LAN needs a DMZ service, allow that *specific* flow explicitly.

### 🌉 Filtering Bridges (Transparent / Layer-2 Firewall)

A bridge firewall passes traffic between segments with **no IP on the data path** — invisible to hosts, which keep their addresses. Great for inserting a firewall in front of a segment without re-IPing anything.

```sh
# OpenBSD: create the bridge (e.g. /etc/hostname.bridge0)
#   add em1
#   add em2
#   up
```

```pf
# You still filter normally; rules match on the member interfaces.
block log all
pass on em1 inet proto tcp to port { 80, 443 }
pass on em2 inet proto tcp to port { 80, 443 }
```

- No NAT, no routing — you filter frames as they cross.
- OpenBSD provides `bridge(4)`; newer OpenBSD also has `veb(4)`/`vport(4)` for VLAN-aware bridging.
- **⚙️ FreeBSD** uses `if_bridge` and needs `net.link.bridge.pfil_bridge=1` for PF to see bridged frames.

### 🗺️ Wider / Routed Networks

Routing between many internal subnets (branch offices, VLANs, VPN tunnels)? Lean on **tables** ("all internal networks"), **interface groups** (match a tagged group of VLAN ifs), and **tagging** (`tag`/`tagged`) to carry a decision across rules:

```pf
table <internal> const { 10.0.0.0/24, 10.0.2.0/24, 10.8.0.0/24 }
pass in on $int_if from <internal> to <internal> tag INTERNAL
pass out on $ext_if tagged INTERNAL nat-to (egress:0)
```

---

## 📶 Wireless & authpf

### 📡 Standing Up an Access Point on OpenBSD

OpenBSD can run a supported wireless card as an AP in **hostap** mode. Configure it persistently in `/etc/hostname.<iface>` (e.g. `/etc/hostname.athn0`):

```sh
# /etc/hostname.athn0
mediaopt hostap
mode 11a
chan 36
nwid PNWC-LAB
wpakey "use-a-long-random-passphrase-here"
wpaprotos wpa2
inet 10.0.5.1 255.255.255.0
up
```

Then treat that wireless interface as just another (untrusted) firewall leg — routing it is cleaner than bridging if you want to filter wireless clients distinctly:

```pf
wifi_if  = "athn0"
wifi_net = "10.0.5.0/24"

match out on egress inet from $wifi_net to any nat-to (egress:0)
block log on $wifi_if all
pass in on $wifi_if inet proto { tcp, udp } to port domain          # DNS
pass in on $wifi_if inet proto tcp to port { http, https }          # web only, say
```

> WPA2-PSK protects the *link layer*; it does **not** authorize *who* can use the network for what. That's `authpf`.

### 🔑 authpf — the Authenticating Gateway

`authpf` is a login shell that loads **per-user PF rules** the moment a user authenticates over SSH, and tears them down on disconnect. It turns a flat wireless segment into per-user policy.

| Step | Action |
|------|--------|
| 1 | Set the account's shell to `/usr/sbin/authpf` (in `/etc/passwd`) |
| 2 | Create `/etc/authpf/authpf.conf` — may be **empty**, but must exist to enable authpf |
| 3 | Add `anchor "authpf/*"` to `/etc/pf.conf` where per-user rules get injected |
| 4 | Write template rules (global or per-user) using the `$user_ip` macro |

```pf
# /etc/authpf/users/nathan/authpf.rules
pass in quick from $user_ip to 10.0.0.0/24        # this user reaches the LAN
pass in quick from $user_ip to port { http, https }
```

**Flow:** connect to WiFi → get an IP but limited/no access → SSH to the gateway → authpf loads your rules into the anchor → access for your session only → on logout/disconnect, rules vanish. Authenticated, auditable, per-identity firewalling with no client software beyond SSH.

**Lock-down patterns:**
- Keep the *base* ruleset restrictive (DNS + the authpf gateway only) so an unauthenticated client can do nothing but log in.
- `/etc/authpf/banned/<username>` instantly refuses a user with a message.
- Combine with a captive-portal splash for a browser flow instead of SSH.

---

## 🔁 High Availability

No single firewall should be a single point of failure, and connections should survive failover without dropping.

### 🛟 CARP — Shared Virtual IP Failover

**CARP** (Common Address Redundancy Protocol) lets two or more firewalls share a virtual IP. One is master; if it dies, a backup takes over in ~seconds. Configure a `carp` pseudo-interface per shared address.

```sh
# OpenBSD /etc/hostname.carp1 on the MASTER
#   inet 10.0.0.1 255.255.255.0 vhid 1 carpdev em1 advskew 0 pass sharedsecret
#
# On the BACKUP, same line but higher advskew (advertises "less eager"):
#   inet 10.0.0.1 255.255.255.0 vhid 1 carpdev em1 advskew 100 pass sharedsecret
```

```sh
# Let the winner grab the IP the instant the master weakens:
sysctl net.inet.carp.preempt=1
echo 'net.inet.carp.preempt=1' >> /etc/sysctl.conf     # persist across reboots
```

| Parameter | Meaning |
|-----------|---------|
| `vhid` | Virtual host ID — must match across the pair, unique per subnet |
| `advskew` | Advertisement skew — **lower wins**. Master 0, backup 100+ |
| `pass` | Shared CARP authentication password |
| `carpdev` | Physical interface the carp device attaches to |

Run a CARP group on **each** interface needing a floating IP (WAN and LAN). With `preempt`, if any one physical interface on the master fails, all its carp interfaces demote together so the backup takes the whole group. Let advertisements through PF: `pass on { $int_if $ext_if } proto carp`.

### 🔄 pfsync — So Failover Doesn't Drop Connections

CARP moves the *IP*; **pfsync** moves the *state table*. Without it, every live connection resets on failover. With it, the backup already knows about live connections and picks them up seamlessly. Use a dedicated crossover link.

```sh
# /etc/hostname.pfsync0
#   syncdev em2
#   up
```

```pf
pass on em2 proto pfsync                 # allow sync traffic on the dedicated link
pass quick on { em0 em1 } proto carp     # allow CARP advertisements
```

> Keep pfsync on an isolated, trusted link — it's unauthenticated state data.

### ⚖️ relayd — Load Balancing, Health Checks, Layer-7 Relaying

`relayd` does three jobs: **redirects** (fast L3/4 balancing via a PF anchor), **relays** (L7 proxying with content inspection / TLS), and **health checking** so dead backends drop out of rotation. It needs an anchor in `/etc/pf.conf`:

```pf
anchor "relayd/*"
```

> **⚙️ FreeBSD difference:** on FreeBSD the filter section needs `rdr-anchor "relayd/*"` instead of `anchor "relayd/*"`.

Minimal `/etc/relayd.conf` load-balancing two web backends with an HTTP health check and ICMP fallback (mirrors the base-system example):

```
web1 = "10.0.2.10"
web2 = "10.0.2.11"

table <webhosts> { $web1, $web2 }
table <fallback> { 127.0.0.1 }

redirect "www" {
    listen on egress port 80
    forward to <webhosts> check http "/" code 200
    forward to <fallback> check icmp
}
```

A **relay** (layer 7) terminates TLS and forwards cleartext to a local backend:

```
relay "tlsproxy" {
    listen on egress port 443 tls
    forward to 127.0.0.1 port 8080
}
```

```sh
relayd -n                                    # check config
rcctl enable relayd && rcctl start relayd    # OpenBSD service management
relayctl show hosts                          # watch health-check status live
```

Use **redirect** blocks for fast L3/4 balancing; **relay** blocks when you need TLS termination, header rewriting, or protocol-aware routing.

### 🔁 Plain Redirection-Based Balancing (No relayd)

Simple round-robin without a daemon, using a table:

```pf
table <webpool> persist { 10.0.2.10, 10.0.2.11 }
pass in on egress proto tcp to (egress) port 80 \
    rdr-to <webpool> round-robin sticky-address
```

`sticky-address` pins a client to the same backend (session affinity). No health checking, though — that's relayd's value-add.

---

## 🛡️ Adaptive Defense

"Adaptive" means the firewall reacts to behavior — a misbehaving address is added to a penalty table automatically and dropped going forward. Stateful defense that scales without babysitting logs.

### 🔨 Brute-Force / Flood Protection with Overload Tables

Set connection-rate limits on a service rule; a source that exceeds them is tabled and `flush global` kills its existing states too.

```pf
table <bruteforce> persist
block quick from <bruteforce>

pass in on egress proto tcp to port 22 \
    keep state (max-src-conn 15, max-src-conn-rate 5/3, \
    overload <bruteforce> flush global)
```

| Clause | Effect |
|--------|--------|
| `max-src-conn 15` | At most 15 simultaneous connections from one source |
| `max-src-conn-rate 5/3` | At most 5 new connections per 3 seconds from one source |
| `overload <bruteforce>` | A source that trips either limit is added to the table |
| `flush global` | Immediately drop **all** of that source's existing states, not just new ones |

**Don't let the table grow forever** — expire idle offenders on a schedule:

```sh
# crontab: nightly, drop anyone quiet for 24h
0 3 * * *  /sbin/pfctl -t bruteforce -T expire 86400
```

Apply the same shape to web (`port { 80, 443 }`), SMTP, etc. Tune the numbers to real traffic so you don't table your own busy clients.

### 🧯 Global State Defense Knobs

```pf
set optimization aggressive        # reap idle states faster under pressure
# Adaptive syncookies blunt SYN floods by only committing state once a handshake completes:
set syncookies adaptive (start 25%, end 12%)
```

`set syncookies adaptive` (OpenBSD 6.3+) answers SYNs with syncookies once half-open connections fill the given percentage of the state table, and stops when it drops back — so a flood can't exhaust state.

### 📧 spamd — Greylisting and Greytrapping for Mail

`spamd` is OpenBSD's spam-deferral daemon (unrelated to SpamAssassin's `spamd`). No content scanning — it exploits the fact that real mail servers retry and spam engines usually don't (**greylisting**), and it can tarpit known-bad senders and auto-trap anyone mailing a bait address (**greytrapping**).

**PF side** — send inbound SMTP to spamd, with allow-lists bypassing it. This matches the current spamd(8) man page, which uses `divert-to` (preserves the original destination):

```pf
table <spamd-white> persist
table <nospamd> persist file "/etc/mail/nospamd"

pass in on egress proto tcp to any port smtp \
    divert-to 127.0.0.1 port spamd
pass in on egress proto tcp from <nospamd> to any port smtp
pass in log on egress proto tcp from <spamd-white> to any port smtp
pass out log on egress proto tcp to any port smtp
```

> Older tutorials (and many running systems) use `rdr-to 127.0.0.1 port spamd` instead of `divert-to`; both work, but `divert-to` is what the current man page documents. spamd listens on port 8025 (the `spamd` service name) by default.

**spamd side** — `/etc/mail/spamd.conf` defines blacklists/allow-lists (cgetent format); then:

```sh
spamd-setup            # load/refresh lists (cron this; -b for blacklist-only)
spamdb                 # inspect/manage the greylist + whitelist database
spamdb -t -a trap@yourdomain.example   # add a greytrap bait address
```

**Behavior:**
- Unknown sender → **greylisted**: first attempt gets a temporary defer; a legitimate server retries and is allowed (and moves toward `<spamd-white>`). Most spam never retries. (Default greylist expiry ~4 hours.)
- Known-bad / greytrapped → stuttered one byte at a time (tarpit), wasting *their* time.
- Combine with reputable blacklists in `spamd.conf` for a low-false-positive front door with zero content inspection.

> 💡 spamd is underused. For any org still running its own MX, greylisting + greytrapping cuts junk load dramatically before it reaches your real mail filter.

---

## 🚦 Traffic Shaping

Keep a link responsive under load — interactive traffic (SSH, VoIP, DNS) stays snappy while bulk transfers use the rest. **This is the biggest OpenBSD/FreeBSD divergence in PF.**

> **First principle: shape egress, not ingress.** You control what you *send*; you can't directly slow packets already arriving. Shape outbound and prioritize ACKs to influence remote senders, and set your root bandwidth slightly **below** your true uplink so the queue — not your ISP's buffer — manages congestion. That's what defeats bufferbloat.

### 🅾️ OpenBSD: the Modern `queue` / `prio` System (5.5+, ALTQ removed in 5.6)

**(1) Simple priority** — `set prio` (0–7, higher = more urgent; **default is 3**):

```pf
pass out on egress proto tcp to port 22 set prio 6
pass out on egress proto tcp to port { 80, 443 } set prio 3
# Two-value form: normal packets get the first prio; TCP ACKs with no payload and
# lowdelay-TOS packets get the second (higher) one - the classic ACK-speedup trick:
pass out on egress proto tcp set prio (3, 7)
```

> **⚙️ FreeBSD difference:** FreeBSD's `set prio` is a *different* feature — it sets 802.1p VLAN priority bits, not OpenBSD-style queue prioritization. Don't copy these lines to FreeBSD expecting the same effect.

**(2) Queues** — hierarchical bandwidth allocation (HFSC under the hood). Root queue at real interface bandwidth, then children, then assign with `set queue`:

```pf
queue rootq on egress bandwidth 100M max 100M
    queue bulk    parent rootq bandwidth 60M default
    queue web     parent rootq bandwidth 30M
    queue interac parent rootq bandwidth 10M min 5M

match out on egress proto tcp to port 22            set queue interac
match out on egress proto tcp to port { 80, 443 }   set queue web
```

Two-subqueue assignment (e.g. `set queue (ssh_bulk, ssh_interactive)`) splits a service's bulk vs. latency-sensitive packets. Key parameters (pf.conf(5) QUEUEING): `bandwidth`, `min`, `max`, `qlimit`, `burst … for …`, and `flows` + `quantum` for fair per-flow queueing. Suffixes `K`/`M`/`G` = bits/sec.

### 🅱️ FreeBSD: ALTQ

FreeBSD PF still ships ALTQ (`cbq`, `priq`, `hfsc`). Requires kernel support (`options ALTQ` + a discipline, e.g. `options ALTQ_HFSC`):

```pf
# FreeBSD PF (ALTQ)
altq on em0 hfsc bandwidth 100Mb queue { bulk, web, interac }
queue bulk    bandwidth 60Mb hfsc (default)
queue web     bandwidth 30Mb
queue interac bandwidth 10Mb hfsc (realtime 5Mb)

pass out on em0 proto tcp to port 22          queue interac
pass out on em0 proto tcp to port { 80, 443 } queue web
```

Note: `altq on …`, bandwidth as `100Mb`, `queue` (not `set queue`) to assign. The OpenBSD `queue … parent …` syntax will **not** load on FreeBSD.

### 🌀 FreeBSD: Dummynet (via pf + dnctl)

Dummynet is FreeBSD's pipe/queue shaper. Modern FreeBSD PF hands traffic to pipes with `dnpipe`/`dnqueue`, configured out-of-band with `dnctl`:

```sh
# 20 Mbit pipe with 50ms induced latency (hard cap, or WAN emulation for tests)
dnctl pipe 1 config bw 20Mbit/s delay 50ms
```

```pf
# FreeBSD pf.conf
match out on em0 proto tcp to port ftp-data dnpipe 1
```

Dummynet shines for **hard rate caps, per-flow queues, and simulating WAN conditions** (latency/loss).

### 🧾 Which Shaper?

| Platform | Quick prioritization | Bandwidth guarantees | Hard caps / WAN emulation |
|----------|---------------------|----------------------|---------------------------|
| **OpenBSD** | `set prio` | `queue` (HFSC) | — |
| **FreeBSD** | — (prio ≠ same) | ALTQ (HFSC) | Dummynet |

> Don't apply ALTQ and Dummynet to the same traffic.

---

## 👁️ Monitoring & Visualization

You can't defend or tune what you can't see. PF gives you counters, a live state view, a dedicated log interface, and native flow export.

### 🔢 Counters, States, and Rule Accounting

```pf
# Label rules to get named, per-rule byte/packet counters:
pass in on egress proto tcp to port 443 label "https-in"
```

```sh
pfctl -si                 # global stats: state count, searches, inserts, match rate
pfctl -ss                 # dump the live state table
pfctl -sl                 # per-label counters ("how much traffic per service?")
pfctl -vsr                # rules WITH hit counters (find dead or hot rules)
pfctl -vsq                # queues with per-queue bandwidth/packet/byte counters
pfctl -t bruteforce -Ts   # what's currently in a table
```

`label` counters are your cheapest, most durable telemetry — per-service accounting with zero extra tooling.

### 🪵 pflog — Logging and Live Packet Capture

`block log` / `pass log` copy matching packets to the **pflog0** pseudo-interface. `pflogd` writes a pcap; watch live with tcpdump:

```sh
tcpdump -n -e -ttt -i pflog0                        # live, all logged packets
tcpdump -n -e -ttt -i pflog0 'port 22'              # just SSH
tcpdump -n -r /var/log/pflog                        # read the saved capture
```

It's real pcap, so all your tcpdump/Wireshark filters apply. Tip: `log (to pflog1)` on noisy rules splits their logging onto a second interface.

### 📟 Live Dashboards: systat and pftop

```sh
systat states       # live state table, sortable
systat rules        # live rule hit rates
systat queues       # live per-queue utilization
pftop               # top(1)-style live view of states/rules (pkg: pftop)
```

`pftop` is the fastest way to answer "what is my firewall doing *right now*, and who's driving the traffic."

### 📈 NetFlow / IPFIX Export with pflow(4)

OpenBSD exports flow records natively through the **pflow** pseudo-interface (present since OpenBSD 4.5) — no third-party agent. Point it at a collector and mark states for export.

```sh
# /etc/hostname.pflow0
#   flowsrc 10.0.0.1 flowdst 10.0.0.50:9995 pflowproto 10
#   up
```

- `flowdst` = collector IP:port; `flowsrc` = the source address the collector sees.
- `pflowproto` = export format: **`5` (NetFlow v5)** or **`10` (IPFIX)**. Current OpenBSD pflow supports these two. (NetFlow v9 existed briefly around 5.1 but is not in current pflow — confirm with `man pflow`.)

Mark which states get exported — globally or per-rule:

```pf
set state-defaults pflow                        # export all states, or...
pass in on egress proto tcp to port 443 keep state (pflow)   # ...just these
```

**Collectors / analysis:**

| Tool | Role |
|------|------|
| **flowd** | Small, privilege-separated flow collector — a natural OpenBSD fit |
| **nfdump / NfSen** | Classic capture + web-visualization stack |
| **SIEM (Elastic, Grafana + flow source)** | Ingest IPFIX into your existing observability pipeline |

Flows to a collector give you per-talker bandwidth, top-N conversations, and historical baselines — exactly what makes "this host is suddenly beaconing outbound" visible.

> **⚙️ FreeBSD difference:** pflow there is a port configured with `pflowctl`, not `ifconfig` (e.g. `pflowctl -s pflow0 src 10.0.0.1 dst 10.0.0.2:9995`, then `pflowctl -s pflow0 proto 10`).

### 🖼️ Historical Graphing: pfstat

`pfstat` (pkg) samples `pfctl` counters over time and renders PNG graphs of pass/block rates, state counts, and per-label throughput — a lightweight, PF-native trend view without a full metrics stack.

---

## 🚀 Workflow & Testing

### ✅ A Safe Editing Loop

```text
1. Edit /etc/pf.conf
   └─> Make the smallest change that accomplishes the goal.

2. pfctl -nf /etc/pf.conf
   └─> PARSE ONLY. Never skip this. Catches syntax errors before they bite.

3. pfctl -f /etc/pf.conf
   └─> Load it. On remote boxes, pair with a timed auto-revert (see Mental Model).

4. pfctl -vsr  +  tcpdump -ni pflog0
   └─> Observe, don't assume. Confirm rules match and counters move.

5. cp /etc/pf.conf /etc/pf.conf.known-good
   └─> Snapshot the working ruleset for rollback.
```

### 🧪 Test Your Logic Deliberately

- **Load, then generate the traffic** and watch `pflog0` / label counters. Observe, don't assume.
- Test **both address families** — a ruleset tight on v4 and open on v6 is a classic silent failure. Re-run every acceptance test over IPv6.
- Test **failover for real** — pull the master's cable and confirm CARP moved the IP *and* pfsync kept the connection alive.
- Watch for **rule-order surprises** — last-match-wins; check for a later overriding rule or a missing `quick`.

### 🏗️ A Suggested Learning Lab

Build it all in VMs (vmm(4) on OpenBSD, or bhyve/VirtualBox):

```text
1. Firewall VM (3 vNICs: WAN, LAN, DMZ)
   └─> Implement Fundamentals + Network Scenarios.

2. Second firewall VM
   └─> Build a CARP + pfsync pair. Break the master on purpose.

3. Wireless segment (virtualized/routed)
   └─> Gate it with authpf.

4. Overload tables + spamd
   └─> Point spamd at a throwaway domain and watch it greylist.

5. pflow0 -> flowd/nfdump
   └─> Export and graph your own lab traffic.
```

Each step is small; the sequence takes you from "I can write a pass rule" to "I can architect a redundant, self-defending, observable edge."

---

## ⚠️ CRITICAL Operational & Legal Warning

### 🔴 FIREWALL CHANGE-CONTROL & AUTHORIZATION GUIDELINES

```
═══════════════════════════════════════════════════════════════
                    ⚠️ CRITICAL WARNING ⚠️
═══════════════════════════════════════════════════════════════

This guide covers DEFENSIVE network configuration. The risk here is not
"attack" - it is breaking connectivity, exposing services, or touching a
network you are not authorized to change.

1. DON'T LOCK YOURSELF OUT
   ► ALWAYS validate with `pfctl -nf` before loading a ruleset.
   ► On any remote or headless box, arrange a timed auto-revert to a known-good
     ruleset before you load a risky change.
   ► Keep /etc/pf.conf.known-good current. Losing access to a firewall you
     can't physically reach is the #1 real-world failure.

2. FAIL CLOSED, VERIFY OPEN
   ► Default-deny, then explicitly pass. A typo should DROP traffic, not
     silently expose a service.
   ► Test BOTH IPv4 and IPv6. "Tight on v4, wide open on v6" is a common,
     silent exposure. Never blanket-block ICMPv6 (it breaks IPv6).
   ► After every change, confirm what is actually reachable from outside -
     don't assume the ruleset does what you intended.

3. AUTHORIZATION TO MODIFY NETWORKS
   ► Only configure, redirect, or shape traffic on networks you OWN or are
     explicitly authorized (in writing) to administer.
   ► Deploying a gateway, transparent bridge, authpf portal, or traffic
     interception on a network you don't control can constitute unauthorized
     access or interception under the CFAA/ECPA and similar laws.
   ► NetFlow/pflow and pflog capture metadata about real users - handle,
     store, and share it in line with your org's privacy obligations
     (GDPR, HIPAA, CCPA, PCI-DSS as applicable).

4. TEST IN A LAB FIRST
   ► Build and break these configurations in VMs before production.
   ► Version-check every example against the man pages for YOUR release -
     PF syntax has real breaking changes across OpenBSD/FreeBSD versions.

═══════════════════════════════════════════════════════════════
```

---

## 🤝 Contributing

Contributions from network engineers, BSD admins, and blue-team operators are welcome.

**What We Accept:**
- ✅ Additional, tested PF rulesets (VPN gateways, IPv6-only edges, multi-WAN, VLAN segmentation).
- ✅ FreeBSD/NetBSD parity notes and syntax differences.
- ✅ Collector/visualization recipes (flowd, nfdump/NfSen, Grafana + IPFIX).
- ✅ Hardening patterns and adaptive-defense table tuning.

**Submission Guidelines:**
1. Fork the repository.
2. Validate every config with `pfctl -nf` and note the OpenBSD/FreeBSD version tested.
3. Sanitize real addresses, hostnames, and keys before sharing.
4. Submit a Pull Request describing the defensive value and the release you verified against.

---

## 📚 References & Resources

Prefer these primary sources over any third-party blog (this one included), and always cross-check the man pages for *your* installed release.

### 📖 OpenBSD Manual Pages
- **[pf.conf(5)](https://man.openbsd.org/pf.conf.5)** — ruleset syntax, NAT, queueing, scrub, options
- **[pf(4)](https://man.openbsd.org/pf.4)** — the packet filter itself
- **[pfctl(8)](https://man.openbsd.org/pfctl.8)** — control utility
- **[carp(4)](https://man.openbsd.org/carp.4)** / **[pfsync(4)](https://man.openbsd.org/pfsync.4)** — redundancy & state sync
- **[authpf(8)](https://man.openbsd.org/authpf.8)** — authenticating gateway
- **[relayd.conf(5)](https://man.openbsd.org/relayd.conf.5)** — load balancer / relay
- **[spamd(8)](https://man.openbsd.org/spamd.8)** — spam deferral daemon
- **[pflow(4)](https://man.openbsd.org/pflow.4)** — NetFlow/IPFIX export
- **[hostname.if(5)](https://man.openbsd.org/hostname.if.5)** — interface configuration

### 📘 Guides & Books
- **OpenBSD PF FAQ** — the canonical, version-tracked tutorial: [openbsd.org/faq/pf](https://www.openbsd.org/faq/pf/)
- **FreeBSD Handbook — Firewalls** (pf, ALTQ, Dummynet): [docs.freebsd.org](https://docs.freebsd.org/en/books/handbook/firewalls/)
- **The Book of PF** — Peter N. M. Hansteen (No Starch Press): the definitive book-length treatment; its chapter structure closely tracks this guide.

---

## 🔗 Quick Links

### Internal Links
- [🏠 Main Repository](../README.md)
- [🎯 START HERE Guide](../START_HERE.md)
- [💻 Cybersecurity Master Guide](../ultimate_cybersecurity_master_guide.md)
- [🏠 Homelab Setup](../Homelab/README.md)
- [✅ Security Checklists](../Checklists/README.md)
- [📚 Documentation](../Documentation/README.md)
- [🔒 OPSEC Guidelines](../OPSEC/README.md)

---

## 📊 Repository Statistics

```
📁 Topics: Rulesets, NAT/DMZ, Bridges, Wireless/authpf, CARP/pfsync/relayd, spamd, Queueing, NetFlow
🔍 Focus: Defensive network engineering, gateway/firewall design, traffic visibility
💻 Core Platforms: OpenBSD (6.x/7.x), FreeBSD (ALTQ/Dummynet notes)
✅ Verification: Cross-checked against OpenBSD man pages + official PF FAQ
🔄 Last Updated: September 2026
👥 Maintained by: Pacific Northwest Computers (PNWC)
📝 Status: Active - Defensive Operations Ready
```

---

<div align="center">

## Related Files
- [../IncidentResponse/log_agg.md](../IncidentResponse/log_agg.md) - Point pflow/NetFlow and pflog output into the SIEM described here
- [../IncidentResponse/network_intrusion.md](../IncidentResponse/network_intrusion.md) - PF is the enforcement layer for the wireless/rogue-AP response procedures
- [../Documentation/wireshark.md](../Documentation/wireshark.md) - Analyze the pcap that pflog0 produces
- [../Homelab/](../Homelab/) - Where to build and break these configurations before production

---

**🛡️ Use These Resources Responsibly: Authorization is MANDATORY**

*A firewall is only as trustworthy as the change-control around it - test in a lab, fail closed, and only touch networks you're authorized to administer.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

⚠️ **Only configure networks you own or are explicitly authorized (in writing) to administer** ⚠️

⚠️ **Always `pfctl -nf` before loading, and keep a known-good rollback on remote boxes** ⚠️

⚠️ **Verify every example against the man pages for YOUR OpenBSD/FreeBSD release** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
