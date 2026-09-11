# The Practical PF Firewall Guide

*A hands-on path to mastering OpenBSD's Packet Filter (with FreeBSD notes throughout)*

> **Status:** Technical claims in this guide were verified against the OpenBSD manual
> pages (`man.openbsd.org`) and the official [OpenBSD PF FAQ](https://www.openbsd.org/faq/pf/).
> Firewall syntax still changes across releases — treat the man pages on *your* box as the
> final authority, and validate every ruleset with `pfctl -nf` before loading it.

---

## How to use this guide

This is a learning guide, not just a cheat sheet. Each section builds on the last:
fundamentals first, then progressively harder network scenarios, then the "grown-up"
subsystems (HA, adaptive defense, shaping, monitoring). Every example is a pattern you
can adapt, not a drop-in production config — read it, understand *why* each line is there,
then rewrite it for your topology.

### Version target and the big syntax changes

All PF syntax here targets **modern OpenBSD (6.x / 7.x)**. PF's syntax has changed in
breaking ways across releases, and old configs from the internet frequently won't load:

- **OpenBSD 4.6** changed traffic normalization: standalone `scrub` rules became a `match`
  action, e.g. `match in all scrub (...)`.
- **OpenBSD 4.7** (2010) folded NAT into the main ruleset — `nat-to` / `rdr-to` / `binat-to`
  replaced the old separate `nat` / `rdr` / `binat` sections.
- **OpenBSD 5.5** (2014) introduced the new `queue` / `prio` traffic-shaping system and
  **deprecated ALTQ** (still usable that release via the `oldqueue` keyword).
- **OpenBSD 5.6** (2014) **removed ALTQ entirely.** From 5.6 on, OpenBSD has only the new
  queueing system.
- **OpenBSD 6.3** (2018) added `set syncookies` (adaptive SYN-flood protection).
- **FreeBSD's** PF is a fork of an older OpenBSD PF: it still uses **ALTQ**, adds **Dummynet**,
  does **not** understand `match … scrub` (uses standalone `scrub`), and differs on a few
  keywords. FreeBSD differences are flagged inline throughout.

> **Golden rule:** the authoritative reference for *your* box is always the man pages on
> *your* box — `man pf.conf`, `man pf`, `man pfctl`, `man carp`, `man authpf`, `man spamd`,
> `man relayd.conf`, `man pflow`. When in doubt, `man` beats any blog (including this one).

---

## Table of contents

1. [Mental model: how PF reads a ruleset](#1-mental-model)
2. [Ruleset fundamentals (v4 + v6)](#2-ruleset-fundamentals)
3. [Real network scenarios: LAN, NAT, DMZ, bridges, routed nets](#3-network-scenarios)
4. [Wireless APs, authpf, and per-user access control](#4-wireless-and-authpf)
5. [High availability: CARP, pfsync, relayd, redirection](#5-high-availability)
6. [Adaptive defense: brute-force tables and spamd](#6-adaptive-defense)
7. [Traffic shaping: OpenBSD queues/prio, FreeBSD ALTQ + Dummynet](#7-traffic-shaping)
8. [Monitoring and visualization, including NetFlow](#8-monitoring)
9. [Workflow, testing, and where to go next](#9-workflow)
10. [References](#10-references)

---

## 1. Mental model {#1-mental-model}

Before writing a single rule, internalize how PF evaluates traffic. Most PF confusion is
really confusion about evaluation order.

### The processing model

- PF reads `/etc/pf.conf` top to bottom for **every** packet.
- **Last matching rule wins** — unless a rule uses `quick`, in which case evaluation stops
  there immediately. This is the single most important sentence in this guide. Put your
  broad default-deny near the top and specific `pass` rules below it, *or* use `quick` on
  specific rules — but don't mix the two mental models carelessly.
- Rules come in three verbs:
  - `block` — drop or reject the packet.
  - `pass` — allow it (and, by default, **create state** — see §2).
  - `match` — don't decide pass/block, but *do* apply actions (NAT, queueing, scrub, marking)
    to matching packets.

### block-policy: drop vs return

```pf
set block-policy drop      # silently discard (stealthy; sender sees a timeout)
# set block-policy return  # actively reject (RST for TCP, ICMP unreachable otherwise)
```

`drop` is stealthier; `return` is friendlier to your own hosts (no waiting on timeouts for
services you intentionally refuse internally). A common approach: `drop` globally, override
with `block return` on internal rules.

### Enabling and driving PF

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

> **Remote-admin safety:** never `pfctl -f` a ruleset you haven't `-nf`-checked, and when
> working on a remote firewall, arrange an auto-revert so a mistake can't lock you out. A
> crude but effective net:
> ```sh
> pfctl -f /etc/pf.conf && sleep 60 && pfctl -f /etc/pf.conf.known-good
> ```
> Better: a cron/at job that reloads the last-known-good ruleset in N minutes unless you
> cancel it. Locking yourself out of a firewall you can't physically reach is a rite of
> passage you can skip.

---

## 2. Ruleset fundamentals {#2-ruleset-fundamentals}

### Macros, lists, and tables

**Macros** are variables — use them so a re-IP or interface swap is a one-line change:

```pf
ext_if = "em0"
int_if = "em1"
int_net = "10.0.0.0/24"
tcp_services = "{ ssh, http, https }"
```

**Lists** (`{ ... }`) get expanded by PF into multiple rules automatically:

```pf
pass in on $ext_if proto tcp to port $tcp_services   # expands to 3 rules
```

**Tables** are the workhorse for large or dynamic address sets. They're hashed (fast even
with thousands of entries) and can be modified live without reloading the whole ruleset —
which is exactly why adaptive defense (§6) leans on them.

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

### Normalization (scrub) and antispoof

**Scrub** reassembles fragments and sanitizes packets. On modern OpenBSD it's a `match`
action, not a standalone rule:

```pf
match in all scrub (no-df random-id max-mss 1440)
```

> **FreeBSD difference:** FreeBSD PF does **not** understand `match … scrub`. Use the older
> standalone form: `scrub in all no-df random-id max-mss 1440`

**antispoof** auto-generates rules that drop packets claiming to come from a network on the
wrong interface (a basic spoofing defense):

```pf
antispoof quick for { lo $int_if }
```

### Stateful filtering — the default that saves you

When a `pass` rule matches, PF creates a **state entry**, and the return traffic for that
connection is allowed automatically. You almost never write rules for reply traffic. Keeping
state is the default; you can tune it:

```pf
pass in on $ext_if proto tcp to port 22 \
    keep state (max-src-conn 15, max-src-conn-rate 5/3)
```

### A complete single-host baseline

A sane starting ruleset for one machine (a server or workstation). Read every line.

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

> **Critical IPv6 note:** IPv6 *depends* on ICMPv6 to function — Neighbor Discovery replaces
> ARP, and Path MTU Discovery relies on "packet too big" messages. If you blanket-block
> ICMPv6 the way people historically blocked ICMP on v4, IPv6 will break in confusing,
> intermittent ways. Always explicitly pass neighbor solicitation/advertisement and
> unreachables on any interface carrying v6.

### Dual-stack discipline

Write v4 and v6 rules deliberately. `inet` = IPv4, `inet6` = IPv6; a rule with neither
keyword applies to both. Being explicit prevents "I only firewalled half my stack" bugs — a
very common way a host ends up locked down on v4 but wide open on v6.

---

## 3. Network scenarios {#3-network-scenarios}

Now the box becomes a **gateway/firewall** with multiple interfaces. The `egress` keyword is
your friend: it means "whichever interface holds the default route," so rules survive an
uplink change. (This whole section mirrors the official OpenBSD PF FAQ "Building a Router"
example, which is worth reading alongside it.)

### 3a. IPv4 NAT (hiding a LAN)

```pf
ext_if = "em0"          # WAN
int_if = "em1"          # LAN
int_net = "10.0.0.0/24"

# Translate outbound LAN traffic to the firewall's external address.
match out on egress inet from $int_net to any nat-to (egress:0)

pass out quick on egress inet
pass in  on $int_if inet from $int_net to any     # let the LAN out
```

- `nat-to (egress:0)` uses the current primary address of the egress interface — parentheses
  make it re-evaluate if the IP changes (DHCP WAN). The `:0` avoids alias addresses.
- Because NAT is part of the ruleset, order matters: a `match … nat-to` applies the
  translation, then a later `pass` still has to allow the packet.
- The FAQ's equivalent one-liner, `match out on egress inet from !(egress:network) to any
  nat-to (egress:0)`, translates everything that isn't already on the egress network.

> **FreeBSD:** same `nat-to` syntax on modern FreeBSD PF. Very old docs show the legacy
> `nat on $ext_if from $int_net to any -> ($ext_if)` form.

### 3b. Port forwarding / inbound redirection (rdr-to)

Expose an internal web server and an SSH host to the world:

```pf
webserver = "10.0.0.10"
sshhost   = "10.0.0.11"

pass in on egress inet proto tcp to (egress) port { 80, 443 } rdr-to $webserver
pass in on egress inet proto tcp to (egress) port 2222 rdr-to $sshhost port 22
```

The redirect and the filter decision are the same rule now. If you split translation and
filtering, remember PF filters on the **translated** (post-rdr) address for inbound.

### 3c. IPv6 — no NAT, just routing + filtering

IPv6 hosts get globally routable addresses; the firewall **routes** rather than translates.
Your job is filtering, not hiding.

```pf
int6_net = "2001:db8:10::/64"

pass out quick on egress inet6 from $int6_net to any
pass in  on $int_if inet6 from $int6_net to any

# Inbound to a specific v6 service host - reachable directly, so filter tightly:
pass in on egress inet6 proto tcp to 2001:db8:10::10 port { 80, 443 }

# ICMPv6 essentials on BOTH sides (see the v6 warning in section 2)
pass inet6 proto icmp6 icmp6-type { echoreq, unreach, timex, paramprob, \
    neighbrsol, neighbradv, routersol, routeradv, toobig }
```

If you genuinely need to translate v6 (e.g. renumber avoidance), OpenBSD supports **NPTv6**
via `binat-to` on the prefix — but reach for it rarely; NAT is not a security feature and v6
is designed to avoid it.

### 3d. A DMZ (three-legged firewall)

Segment public-facing services onto their own interface so a compromise there can't pivot
into the LAN.

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

The mental model: **the DMZ is untrusted.** Traffic flows Internet→DMZ and DMZ→Internet, but
DMZ→LAN is denied. If the LAN needs a DMZ service (e.g. internal users hitting the web app),
allow that *specific* flow explicitly.

### 3e. Filtering bridges (transparent / layer-2 firewall)

A bridge firewall passes traffic between segments with **no IP of its own on the data path** —
invisible to the hosts, which keep their addresses. Great for dropping a firewall in front of
an existing segment without re-IPing anything.

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

Notes:
- On a bridge there's no NAT and no routing — you're filtering frames as they cross.
- OpenBSD provides `bridge(4)`; newer OpenBSD also has `veb(4)`/`vport(4)` for VLAN-aware
  bridging.
- **FreeBSD** does transparent bridging via `if_bridge` and requires
  `net.link.bridge.pfil_bridge=1` (sysctl) for PF to see bridged frames.

### 3f. Wider / routed networks

When you're routing between many internal subnets (branch offices, VLANs, VPN tunnels),
lean on:

- **Tables** for "all internal networks" so one edit covers every subnet.
- **Interface groups**: tag interfaces (e.g. all VLAN ifs) and match the group name, so
  `pass on vlans …` covers them all.
- **Tagging** (`tag` / `tagged`) to carry a decision across rules — mark a packet in one
  rule, match the mark later, which keeps complex multi-segment logic readable.

```pf
table <internal> const { 10.0.0.0/24, 10.0.2.0/24, 10.8.0.0/24 }
pass in on $int_if from <internal> to <internal> tag INTERNAL
pass out on $ext_if tagged INTERNAL nat-to (egress:0)
```

---

## 4. Wireless and authpf {#4-wireless-and-authpf}

### 4a. Standing up an access point on OpenBSD

OpenBSD can run a supported wireless card as an AP in **hostap** mode. Configure it
persistently in `/etc/hostname.<iface>` (e.g. `/etc/hostname.athn0`):

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

Then treat that wireless interface as just another (untrusted) firewall leg. Bridge it to a
wired segment, or route it — routing is cleaner if you want to filter wireless clients
distinctly:

```pf
wifi_if  = "athn0"
wifi_net = "10.0.5.0/24"

match out on egress inet from $wifi_net to any nat-to (egress:0)
block log on $wifi_if all
pass in on $wifi_if inet proto { tcp, udp } to port domain          # DNS
pass in on $wifi_if inet proto tcp to port { http, https }          # web only, say
```

> WPA2-PSK protects the link layer; it does **not** authorize *who* can use the network for
> what. That's where authpf comes in.

### 4b. authpf — the authenticating gateway

`authpf` is a login shell that loads **per-user PF rules** the moment a user authenticates
(via SSH), and tears them down when they disconnect. Perfect for "the WiFi is locked at the
link layer, but you get *network* access only after you log in, and only the access your role
allows." It turns a flat wireless segment into per-user policy.

**Setup:**

1. Give the account `authpf` as its shell:
   ```sh
   # /etc/passwd entry ends in:  /usr/sbin/authpf
   ```
2. Create `/etc/authpf/authpf.conf` — it may be **empty**, but it must exist to enable authpf.
3. Add an anchor to `/etc/pf.conf` where per-user rules get injected:
   ```pf
   anchor "authpf/*"
   ```
4. Write the template rules. Global default in `/etc/authpf/authpf.rules`, or per-user in
   `/etc/authpf/users/<username>/authpf.rules`. authpf provides the `$user_ip` macro (the
   address the user logged in from):

   ```pf
   # /etc/authpf/users/nathan/authpf.rules
   pass in quick from $user_ip to 10.0.0.0/24        # this user reaches the LAN
   pass in quick from $user_ip to port { http, https }
   ```

**Flow:** user connects to WiFi → gets an IP but limited/no access → SSHes to the gateway →
authpf authenticates them and loads their rules into the anchor → access granted for their
session only → on logout/disconnect, rules vanish. You get authenticated, auditable,
per-identity firewalling with no client software beyond an SSH client.

**Lock-down patterns:**
- Keep the *base* ruleset restrictive (DNS + the authpf gateway only) so an unauthenticated
  client can do nothing but log in.
- Use `/etc/authpf/banned/<username>` to instantly refuse a user with a message.
- Combine with a captive-portal-style splash if you want a browser flow instead of SSH.

---

## 5. High availability {#5-high-availability}

The goal: no single firewall is a single point of failure, and connections survive a
failover without dropping.

### 5a. CARP — shared virtual IP failover

**CARP** (Common Address Redundancy Protocol) lets two or more firewalls share a virtual IP.
One is master; if it dies, a backup takes the IP over in ~seconds. Configure a `carp`
pseudo-interface per shared address.

```sh
# OpenBSD /etc/hostname.carp1 on the MASTER
#   inet 10.0.0.1 255.255.255.0 vhid 1 carpdev em1 advskew 0 pass sharedsecret
#
# On the BACKUP, same line but higher advskew (it advertises "less eager"):
#   inet 10.0.0.1 255.255.255.0 vhid 1 carpdev em1 advskew 100 pass sharedsecret
```

```sh
# Allow the winner to grab the IP the instant the master weakens:
sysctl net.inet.carp.preempt=1
echo 'net.inet.carp.preempt=1' >> /etc/sysctl.conf     # persist across reboots
```

- `vhid` = virtual host ID; must match across the pair and be unique per subnet.
- `advskew` = advertisement skew; **lower wins.** Master 0, backup 100 (any higher value works).
- `pass` = shared CARP authentication password.
- Run a CARP group on **each** interface that needs a floating IP (WAN and LAN both). With
  `preempt` enabled, if any one physical interface on the master fails, all of that host's
  carp interfaces demote together so the backup takes over the whole group cleanly.
- Let CARP advertisements through PF: `pass on { $int_if $ext_if } proto carp`.

### 5b. pfsync — so failover doesn't drop connections

CARP moves the *IP*; **pfsync** moves the *state table*. Without it, every existing
connection resets on failover (users notice). With it, the backup already knows about live
connections and picks them up seamlessly. Use a dedicated crossover link between the
firewalls for sync traffic.

```sh
# /etc/hostname.pfsync0
#   syncdev em2
#   up
```

```pf
pass on em2 proto pfsync                 # allow sync traffic on the dedicated link
pass quick on { em0 em1 } proto carp     # allow CARP advertisements
```

> Keep pfsync on an isolated, trusted link — it's unauthenticated state data. A dedicated
> cable (or a locked-down VLAN) between the two boxes is the norm.

### 5c. relayd — load balancing, health checks, and layer-7 relaying

`relayd` does three related jobs: **redirects** (fast layer 3/4 load balancing via a PF
anchor), **relays** (layer-7 proxying with content inspection / TLS), and **health checking**
of backends so dead servers drop out of rotation automatically.

relayd needs an anchor in `/etc/pf.conf`:

```pf
anchor "relayd/*"
```

> **FreeBSD difference:** on FreeBSD the filter section needs `rdr-anchor "relayd/*"` instead
> of `anchor "relayd/*"`.

Minimal `/etc/relayd.conf` load-balancing two web backends with an HTTP health check and an
ICMP fallback (this mirrors the base-system example config):

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

A **relay** (layer 7) is what you use when you need TLS termination or header inspection —
for example, terminate HTTPS and forward cleartext to a local backend:

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

Use **redirect** blocks for fast layer-3/4 balancing; use **relay** blocks when you need TLS
termination, header rewriting, or protocol-aware routing.

### 5d. Plain redirection-based balancing (no relayd)

For simple round-robin without a daemon, PF alone can spread inbound connections across a
pool using a table:

```pf
table <webpool> persist { 10.0.2.10, 10.0.2.11 }
pass in on egress proto tcp to (egress) port 80 \
    rdr-to <webpool> round-robin sticky-address
```

`sticky-address` keeps a given client pinned to the same backend (helps session affinity).
No health checking, though — that's relayd's value-add.

---

## 6. Adaptive defense {#6-adaptive-defense}

"Adaptive" means the firewall reacts to behavior — an address that misbehaves gets added to a
penalty table automatically and is dropped going forward. This is stateful defense that
scales without you babysitting logs.

### 6a. Brute-force / flood protection with overload tables

The pattern: on a service rule, set connection-rate limits; when a source exceeds them, PF
adds it to a table and `flush global` kills its existing states too.

```pf
table <bruteforce> persist
block quick from <bruteforce>

pass in on egress proto tcp to port 22 \
    keep state (max-src-conn 15, max-src-conn-rate 5/3, \
    overload <bruteforce> flush global)
```

Line by line:
- `max-src-conn 15` — at most 15 simultaneous connections from one source.
- `max-src-conn-rate 5/3` — at most 5 new connections per 3 seconds from one source.
- `overload <bruteforce>` — a source that trips either limit is added to the table.
- `flush global` — immediately drop *all* of that source's existing states, not just new ones.

**Don't let the table grow forever** — expire idle offenders on a schedule:

```sh
# crontab: nightly, drop anyone quiet for 24h
0 3 * * *  /sbin/pfctl -t bruteforce -T expire 86400
```

Apply the same shape to web (`port { 80, 443 }`), SMTP, etc. Tune the numbers to real traffic
so you don't table your own busy clients.

### 6b. Global state defense knobs

```pf
set optimization aggressive        # reap idle states faster under pressure
# Adaptive syncookies blunt SYN floods by only committing state once a handshake completes:
set syncookies adaptive (start 25%, end 12%)
```

`set syncookies adaptive` (OpenBSD 6.3+) is a strong, low-effort SYN-flood mitigation: PF
starts answering SYNs with syncookies once half-open connections fill the given percentage of
the state table, and stops when it drops back down — so a flood can't exhaust the state table.

### 6c. spamd — greylisting and greytrapping for mail

`spamd` is OpenBSD's spam-deferral daemon (unrelated to SpamAssassin's `spamd`). It doesn't
scan content; it exploits the fact that real mail servers retry and spam engines usually don't
(**greylisting**), and it can tarpit known-bad senders and auto-trap anyone who mails a bait
address (**greytrapping**).

**PF side** — send inbound SMTP to spamd, with allow-lists bypassing it. This matches the
current spamd(8) man page, which uses `divert-to` (an in-place divert that preserves the
original destination):

```pf
table <spamd-white> persist
table <nospamd> persist file "/etc/mail/nospamd"

pass in on egress proto tcp to any port smtp \
    divert-to 127.0.0.1 port spamd
pass in on egress proto tcp from <nospamd> to any port smtp
pass in log on egress proto tcp from <spamd-white> to any port smtp
pass out log on egress proto tcp to any port smtp
```

> Older tutorials (and plenty of running systems) use `rdr-to 127.0.0.1 port spamd` instead
> of `divert-to`; both work, but `divert-to` is the form the current man page documents.
> spamd listens on port 8025 by default (the `spamd` service name).

**spamd side** — `/etc/mail/spamd.conf` defines blacklists/allow-lists (cgetent format); then:

```sh
spamd-setup            # load/refresh the configured lists (cron this; -b for blacklist-only)
spamdb                 # inspect/manage the greylist + whitelist database
spamdb -t -a trap@yourdomain.example   # add a greytrap bait address
```

How it behaves:
- Unknown sender → **greylisted**: the first delivery attempt gets a temporary defer; a
  legitimate server retries and is then allowed (and moves toward `<spamd-white>`). Most spam
  never retries. (Default greylist expiry is ~4 hours — the point by which most real MTAs
  have retried.)
- Known-bad or greytrapped sender → stuttered one byte at a time (tarpit), wasting *their*
  time.
- Combine with reputable blacklists in `spamd.conf` for a very effective, low-false-positive
  front door — with essentially zero content inspection.

> spamd is the piece people underuse. For any org still running its own MX, greylisting +
> greytrapping cuts the junk load dramatically before it ever reaches your real mail filter.

---

## 7. Traffic shaping {#7-traffic-shaping}

Shaping keeps a link responsive under load — interactive traffic (SSH, VoIP, DNS) stays snappy
while bulk transfers use the rest. **This is the biggest OpenBSD/FreeBSD divergence in PF**, so
the two platforms are covered separately.

> **First principle: shape egress, not ingress.** You control the traffic you *send*. You
> can't directly slow packets already arriving from the Internet — so shape outbound and
> prioritize ACKs to influence remote senders. Set your root bandwidth slightly **below** your
> true uplink rate so the queue (not your ISP's buffer) is where congestion is managed. That's
> what actually defeats bufferbloat.

### 7a. OpenBSD: the modern `queue` / `prio` system (5.5+, ALTQ removed in 5.6)

ALTQ is **gone** from OpenBSD as of 5.6. The current system has two mechanisms:

**(1) Simple priority** — `set prio` (0–7, higher = more urgent; the default priority is **3**).
Cheap and effective for "make ACKs and SSH beat bulk":

```pf
pass out on egress proto tcp to port 22 set prio 6
pass out on egress proto tcp to port { 80, 443 } set prio 3
# Two-value form: normal packets get the first prio; TCP ACKs with no payload and
# lowdelay-TOS packets get the second (higher) one - the classic ACK-speedup trick:
pass out on egress proto tcp set prio (3, 7)
```

> **FreeBSD difference:** FreeBSD's `set prio` is **not** the same feature — there it sets the
> 802.1p priority bits in VLAN headers, and doesn't behave like OpenBSD's queue prioritization.
> Don't copy OpenBSD `set prio` lines onto FreeBSD expecting the same effect.

**(2) Queues** — hierarchical bandwidth allocation (HFSC under the hood). Define a root queue
bound to the egress interface's real bandwidth, then children, then assign traffic with
`set queue`:

```pf
queue rootq on egress bandwidth 100M max 100M
    queue bulk    parent rootq bandwidth 60M default
    queue web     parent rootq bandwidth 30M
    queue interac parent rootq bandwidth 10M min 5M

match out on egress proto tcp to port 22            set queue interac
match out on egress proto tcp to port { 80, 443 }   set queue web
```

You can also assign two subqueues at once to split a service's bulk vs. latency-sensitive
packets, e.g. `set queue (ssh_bulk, ssh_interactive)`.

Key parameters (see pf.conf(5) QUEUEING): `bandwidth` (target share), `min` (guaranteed
floor), `max` (ceiling), `qlimit` (queue depth), `burst … for …`, and `flows` + `quantum`
(fair-queue each flow separately — great for sharing a link fairly among many clients).
Bandwidth suffixes are `K`, `M`, `G` (bits/sec).

### 7b. FreeBSD: ALTQ

FreeBSD PF still ships ALTQ. You declare an `altq` discipline on the interface, then `queue`s,
then assign with `queue` on pass rules. Disciplines: `cbq`, `priq`, `hfsc`. This requires ALTQ
support compiled into the kernel (`options ALTQ` plus the discipline, e.g. `options ALTQ_HFSC`).

```pf
# FreeBSD PF (ALTQ)
altq on em0 hfsc bandwidth 100Mb queue { bulk, web, interac }
queue bulk    bandwidth 60Mb hfsc (default)
queue web     bandwidth 30Mb
queue interac bandwidth 10Mb hfsc (realtime 5Mb)

pass out on em0 proto tcp to port 22          queue interac
pass out on em0 proto tcp to port { 80, 443 } queue web
```

Note the differences from OpenBSD: `altq on …`, bandwidth written as `100Mb`, and `queue`
(not `set queue`) as the assignment keyword. The OpenBSD `queue … parent …` syntax will **not**
load on FreeBSD.

### 7c. FreeBSD: Dummynet (via pf + dnctl)

Dummynet is FreeBSD's pipe/queue shaper. Modern FreeBSD PF hands traffic to Dummynet pipes
with `dnpipe` / `dnqueue`, configured out-of-band with `dnctl`:

```sh
# Define a 20 Mbit pipe with 50ms of induced latency (a hard cap, or WAN emulation for tests)
dnctl pipe 1 config bw 20Mbit/s delay 50ms
```

```pf
# FreeBSD pf.conf - send matching traffic into pipe 1
match out on em0 proto tcp to port ftp-data dnpipe 1
```

Dummynet shines for **hard rate caps, per-flow queues, and simulating WAN conditions**
(latency/loss) for testing — a genuinely useful lab tool alongside its production role.

> **Which do I use?** OpenBSD: `set prio` for quick wins, `queue` when you need real bandwidth
> guarantees. FreeBSD: ALTQ (especially HFSC) for hierarchical shaping, Dummynet for hard caps
> and network emulation. Don't apply ALTQ and Dummynet to the same traffic.

---

## 8. Monitoring and visualization {#8-monitoring}

You can't defend or tune what you can't see. PF gives you counters, a live state view, a
dedicated log interface, and native flow export.

### 8a. Counters, states, and rule accounting

```pf
# Label rules to get named, per-rule byte/packet counters:
pass in on egress proto tcp to port 443 label "https-in"
```

```sh
pfctl -si                 # global stats: state count, searches, inserts, match rate
pfctl -ss                 # dump the live state table
pfctl -sl                 # per-label counters (great for "how much traffic per service?")
pfctl -vsr                # rules WITH their hit counters (find dead or hot rules)
pfctl -vsq                # queues with per-queue bandwidth/packet/byte counters
pfctl -t bruteforce -Ts   # what's currently in a table
```

`label` counters are your cheapest, most durable telemetry — attach them to the rules you
care about and you have per-service accounting with zero extra tooling.

### 8b. pflog — logging and live packet capture

`block log` / `pass log` copy matching packets to the **pflog0** pseudo-interface. `pflogd`
writes them to a pcap; you can also watch live with tcpdump:

```sh
tcpdump -n -e -ttt -i pflog0                        # live, all logged packets
tcpdump -n -e -ttt -i pflog0 'port 22'              # just SSH
tcpdump -n -r /var/log/pflog                        # read the saved capture
```

Because it's real pcap, everything you know about tcpdump/Wireshark filters applies. Tip: use
`log (to pflog1)` on specific rules to split noisy logging onto a second pflog interface.

### 8c. Live dashboards: systat and pftop

```sh
systat states       # live state table, sortable
systat rules        # live rule hit rates
systat queues       # live per-queue utilization
pftop               # top(1)-style live view of states/rules (pkg: pftop)
```

`pftop` is the fastest way to answer "what is my firewall doing *right now*, and who's driving
the traffic."

### 8d. NetFlow / IPFIX export with pflow(4)

OpenBSD exports flow records natively through the **pflow** pseudo-interface (present since
OpenBSD 4.5) — no third-party agent needed. Point it at a collector and mark states for export.

```sh
# /etc/hostname.pflow0
#   flowsrc 10.0.0.1 flowdst 10.0.0.50:9995 pflowproto 10
#   up
```

- `flowdst` = your collector's IP:port; `flowsrc` = the source address the collector sees.
- `pflowproto` = export format: **`5` (NetFlow v5)** or **`10` (IPFIX)**. Current OpenBSD pflow
  supports these two. (NetFlow v9 support existed briefly around OpenBSD 5.1 but is not in
  current pflow — confirm with `man pflow` on your release.)

Mark which states get exported — globally or per-rule:

```pf
set state-defaults pflow                        # export all states, or...
pass in on egress proto tcp to port 443 keep state (pflow)   # ...just these
```

**Collectors / analysis** to point it at:
- **flowd** (Damien Miller's small, privilege-separated flow collector) — a natural OpenBSD fit.
- **nfdump / NfSen** — the classic capture + web-visualization stack.
- Modern pipelines: ingest IPFIX into your existing SIEM/observability stack (Elastic,
  Grafana + a flow source, etc.).

With flows going to a collector you get per-talker bandwidth, top-N conversations, and
historical baselines — exactly what makes "this host is suddenly beaconing outbound" visible.

> **FreeBSD difference:** pflow on FreeBSD is provided via a port and is configured with the
> `pflowctl` utility rather than `ifconfig`
> (e.g. `pflowctl -s pflow0 src 10.0.0.1 dst 10.0.0.2:9995`, then `pflowctl -s pflow0 proto 10`).

### 8e. Historical graphing: pfstat

`pfstat` (pkg) samples `pfctl` counters over time and renders PNG graphs of pass/block rates,
state counts, and per-label throughput — a lightweight, PF-native way to get trend lines
without standing up a full metrics stack.

---

## 9. Workflow, testing, and where to go next {#9-workflow}

### A safe editing loop

1. Edit `/etc/pf.conf`.
2. `pfctl -nf /etc/pf.conf` — **parse only.** Never skip this.
3. `pfctl -f /etc/pf.conf` — load it.
4. `pfctl -vsr` and `tcpdump -ni pflog0` — confirm it does what you think.
5. Keep a `/etc/pf.conf.known-good` and, on remote boxes, a timed auto-revert (see §1).

### Test your logic deliberately

- **`pfctl -f`, then generate the traffic** and watch `pflog0` / label counters — don't
  assume, observe.
- Test **both address families.** A ruleset that's tight on v4 and open on v6 is a classic,
  silent failure. Re-run every acceptance test over IPv6.
- Test **failover** for real: pull the master's cable and confirm CARP moves the IP *and*
  pfsync kept the connection alive.
- Watch for **rule-order surprises** — if a packet isn't matching the rule you expect, remember
  last-match-wins and check for a later overriding rule (or a missing `quick`).

### A suggested learning lab

Build the whole thing in VMs (vmm(4) on OpenBSD, or bhyve/VirtualBox):

1. One OpenBSD "firewall" VM with three vNICs: WAN, LAN, DMZ. Implement §2–3.
2. Add a second firewall VM and build a CARP + pfsync pair (§5). Break the master on purpose.
3. Stand up a wireless segment (even virtualized/routed) and gate it with authpf (§4).
4. Add overload tables and point spamd at a throwaway domain (§6).
5. Turn on `pflow0` → flowd/nfdump and graph your own lab traffic (§8).

Each step is small; the sequence takes you from "I can write a pass rule" to "I can architect
a redundant, self-defending, observable edge."

---

## 10. References {#10-references}

Authoritative, primary sources — prefer these over any third-party blog (this one included),
and always cross-check against the man pages for *your* installed release:

**OpenBSD man pages**
- pf.conf(5) — ruleset syntax, NAT, queueing, scrub, options: <https://man.openbsd.org/pf.conf.5>
- pf(4) — the packet filter itself: <https://man.openbsd.org/pf.4>
- pfctl(8) — control utility: <https://man.openbsd.org/pfctl.8>
- carp(4) — redundancy protocol: <https://man.openbsd.org/carp.4>
- pfsync(4) — state synchronization: <https://man.openbsd.org/pfsync.4>
- authpf(8) — authenticating gateway: <https://man.openbsd.org/authpf.8>
- relayd(8) / relayd.conf(5) — load balancer/relay: <https://man.openbsd.org/relayd.conf.5>
- spamd(8) / spamd.conf(5) — spam deferral: <https://man.openbsd.org/spamd.8>
- pflow(4) — NetFlow/IPFIX export: <https://man.openbsd.org/pflow.4>
- ifconfig(8) / hostname.if(5) — interface config: <https://man.openbsd.org/hostname.if.5>

**Guides and books**
- OpenBSD PF FAQ (the canonical, version-tracked tutorial): <https://www.openbsd.org/faq/pf/>
- FreeBSD Handbook, Firewalls chapter (pf on FreeBSD, ALTQ, Dummynet):
  <https://docs.freebsd.org/en/books/handbook/firewalls/>
- *The Book of PF*, Peter N. M. Hansteen (No Starch Press) — the definitive book-length
  treatment; its chapter structure closely tracks this guide, so it's the natural next step
  for depth on any section here. (The 3rd edition covers the ALTQ-to-new-queueing transition;
  later editions track newer releases.)

---

*Built as a learning scaffold — read it at the shell with the man pages open, break things in
a lab, and adapt every config to your own topology before it goes anywhere near production.
Verified against OpenBSD man pages and the OpenBSD PF FAQ; re-verify against your installed
release, since PF syntax evolves.*
