# Alpine Linux Network Auditing Toolkit Guide

## 🎯 Purpose

Provide a practical Alpine Linux reference for mobile network diagnostics and authorized client audits through UserLAnd.

## ⚙️ Function

Documents package setup, two independent Python workflows, service review, optional assessment tools, packet analysis, and report transfer.

## 🏆 Goal

Produce repeatable inventory and assessment evidence with accurate scope, clear limitations, and organized client outputs.

## 📋 When to Use

- Preparing an Alpine UserLAnd environment for field diagnostics.
- Adapting service inventory to different client networks.
- Running the baseline or advanced audit examples.
- Reviewing, organizing, and transferring assessment evidence.

**Environment:** Alpine Linux on Android through UserLAnd, with optional tools for an Alpine host that has actual packet-capture privileges.

**Purpose:** Install the toolkit, adapt it to different client networks, run service inventories, perform selected follow-up checks, organize findings, inspect packet captures, and transfer reports to a workstation.

This guide documents two separate Python programs: `network_audit.py` for service and credential review, and `advanced_audit.py` for web assessment, selected Nmap scripts, and optional packet tools. Each program is self-contained. Copy its complete code block into its own file.

The original conversation has been consolidated, duplicate versions removed, and broken Markdown and command examples corrected. The code examples have also been revised where the original behavior contradicted the documented workflow. They are reference implementations, not a complete vulnerability scanner; device-specific operation still needs validation on your Alpine/UserLAnd installation.

## Contents

1. [Alpine and UserLAnd basics](#1-alpine-and-userland-basics)
2. [Install and maintain the toolkit](#2-install-and-maintain-the-toolkit)
3. [Choose the right script](#3-choose-the-right-script)
4. [Client networks and output folders](#4-client-networks-and-output-folders)
5. [Command options explained](#5-command-options-explained)
6. [Baseline script: network_audit.py](#6-baseline-script-network_auditpy)
7. [Advanced script: advanced_audit.py](#7-advanced-script-advanced_auditpy)
8. [Run an audit and review the results](#8-run-an-audit-and-review-the-results)
9. [Packet capture and offline analysis](#9-packet-capture-and-offline-analysis)
10. [Additional Nmap NSE checks](#10-additional-nmap-nse-checks)
11. [Transfer reports off Android](#11-transfer-reports-off-android)
12. [Troubleshooting](#12-troubleshooting)
13. [Corrections to the original notes](#13-corrections-to-the-original-notes)

## 1. Alpine and UserLAnd basics

Alpine is a compact Linux distribution built around musl libc, BusyBox, and the `apk` package manager. UserLAnd runs a Linux userspace on Android using PRoot. The Linux filesystem and its apparent root account do not provide the same privileges as root on the Android host. [PRoot documentation](https://proot-me.github.io/)

The practical distinction is between tools that use ordinary network connections and tools that need raw packet access:

| Capability | Unrooted UserLAnd | Notes |
| --- | --- | --- |
| Python scripts, DNS queries, HTTP requests | Generally usable | Still subject to connectivity and Android restrictions. |
| Nmap TCP connect inventory | Usually usable | Use the unprivileged settings documented below. |
| Hydra and Nikto | Potentially usable | Package availability, compiled protocol support, and target behavior vary. |
| Reading existing PCAP files | Generally usable | TShark and Termshark can analyze captures made elsewhere. |
| Live tcpdump capture | Generally unavailable | Requires real packet-capture permissions. |
| Masscan | Generally unavailable | Its raw-packet networking requirements are not removed by reducing scan speed. |
| Wi-Fi monitor mode and frame injection | Unavailable through ordinary PRoot alone | Require appropriate host privileges, hardware, and drivers. |

These compatibility expectations follow from PRoot's privilege model, Nmap's use of `connect()` for `-sT`, and Masscan's separate TCP/IP stack. They are not a guarantee for every Android build. [Nmap TCP connect scanning](https://nmap.org/book/man-port-scanning-techniques.html), [Masscan documentation](https://github.com/robertdavidgraham/masscan)

Even a privileged packet capture only sees traffic available at its capture interface. Capturing on a phone or laptop does not automatically expose all traffic on a switched client network.

## 2. Install and maintain the toolkit

### Check your installation

Run package-management commands from a session that can manage Alpine packages. Add your configured `sudo` or `doas` prefix if the session requires it.

```sh
cat /etc/alpine-release
apk --print-arch
cat /etc/apk/repositories
```

Enable `main` and, where needed, `community` for the **same Alpine release**. Package availability depends on release, architecture, and repository. Do not assume that a package listed for `edge/testing` exists on your installed stable branch. [Alpine package-management documentation](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html)

If an editor is needed:

```sh
apk add nano
nano /etc/apk/repositories
```

### Update Alpine packages

```sh
apk update
apk upgrade
```

This refreshes indexes and updates packages within the configured repositories. Moving to another Alpine release is a separate procedure.

### Install the baseline

```sh
apk add python3 nmap iproute2 nano curl git
```

Use `python3`, not the unavailable generic `python` package from the original notes. `iproute2` supplies the JSON-capable `ip` command used for optional interface-based subnet detection. No third-party Python modules are required by the two audit scripts.

### Check optional packages before installation

The commands below search your configured repositories. Install each optional group only after confirming that its packages are available.

```sh
apk search -x hydra
apk search -x nikto
apk search -x nmap-scripts
apk search -x nmap-nselibs
apk search -x tshark
apk search -x termshark
apk search -x tcpdump
apk search -x masscan
```

| Purpose | Installation command, when available |
| --- | --- |
| Credential checks | `apk add hydra` |
| Web server assessment | `apk add nikto` |
| Nmap scripting libraries and scripts | `apk add nmap-scripts nmap-nselibs` |
| Offline packet analysis | `apk add tshark termshark` |
| Live capture on a capable host | `apk add tcpdump` |
| Raw-packet discovery on a capable host | `apk add masscan` |
| DNS, registration, and HTTP diagnostics | `apk add bind-tools whois curl wget` |
| Connection and relay utilities | `apk add netcat-openbsd socat` |
| Optional offline password auditing | `apk add john` |
| SSH file transfer client | `apk add openssh-client` |

Ncrack is not a dependency of this guide. The source reported it unavailable on the user's configured installation; that is not evidence that it can never exist on any Alpine branch. No source compilation or distribution change is required for this workflow.

### Verify installed tools

```sh
python3 --version
nmap --version
ip -Version
```

For optional tools, consult their local help before enabling their script options:

```sh
hydra -h
nikto -Help
tshark --version
```

### Package-management quick reference

| Task | Command |
| --- | --- |
| Refresh repository indexes | `apk update` |
| Upgrade installed packages | `apk upgrade` |
| Install packages | `apk add curl htop git` |
| Search by name | `apk search package_name` |
| Search an exact package name | `apk search -x package_name` |
| Check whether a package is installed | `apk info -e package_name` |
| Remove a package | `apk del package_name` |
| Clean obsolete cached packages | `apk cache clean` |

For Docker images, the compact installation pattern is `RUN apk add --no-cache curl`. Docker image maintenance is separate from this UserLAnd workflow.

## 3. Choose the right script

| Capability | `network_audit.py` | `advanced_audit.py` |
| --- | --- | --- |
| Main purpose | Service inventory and protocol/credential review | Service inventory with optional web, NSE, and packet tools |
| Explicit IPv4 address or CIDR | Yes | Yes |
| Actual interface prefix detection | Yes, where Android permits it | Yes, where Android permits it |
| Nmap TCP connect and service scan | Yes | Yes |
| XML and readable Nmap output | Yes | Yes |
| Separate client summary | `client_security_report.txt` | `orchestrated_audit_report.txt` |
| Protocol review notes | Included | Raw inventory observations |
| Hydra integration | Enabled with account and password-list arguments | Not included |
| Nikto integration | Not included | Enabled with `--nikto` |
| Selected NSE checks | Use manual commands in Section 10 | Enabled with `--nse` |
| Background tcpdump capture | Not included | Enabled with `--capture-interface`, when permitted |
| Supplementary Masscan sweep | Not included | Enabled with `--masscan`, when permitted |
| Client and timestamp output folders | Yes | Yes |

Both scripts work independently and run their own inventory scan. The advanced script does not invoke the baseline script or inherit its Hydra checks. Running both against the same scope therefore repeats the Nmap inventory.

Masscan is retained as an optional supplementary stage. Its output is saved separately; it does **not** feed a reduced target list into Nmap in this implementation. The advanced script therefore makes no automatic large-network speedup claim.

## 4. Client networks and output folders

### Specify the network accurately

A local address alone does not identify its subnet mask. The earlier scripts selected an outbound address and appended `/24`, which could miss devices or scan the wrong range.

Use an explicit client network whenever possible:

```sh
python3 network_audit.py --client ACME_CORP --target 10.0.1.0/24
```

For a single device:

```sh
python3 network_audit.py --client ACME_CORP --target 10.0.1.50
```

If Android permits interface inspection, use the actual interface address and prefix:

```sh
ip -j -4 address show dev wlan0
python3 network_audit.py --client ACME_CORP --interface wlan0
```

The script accepts interface detection only when it finds one unambiguous IPv4 network. It stops if detection fails and asks for `--target`; it does not silently substitute loopback or a guessed `/24`. The interface name is an example—use the one present on your device.

The examples accept one IPv4 address or CIDR per run. They do not discover every VLAN, handle IPv6 inventory, or implement exclusion lists. For networks with excluded equipment, use individual approved targets or separate approved CIDRs. VPNs and guest Wi-Fi may expose a different network from the client LAN you intend to inspect.

### Output structure

Each run creates a private folder under `./workspace`, grouped by client and a UTC timestamp. The timestamp includes microseconds, and an existing run folder is never intentionally reused.

Example run directory:

```text
workspace/ACME_CORP/20260902T150000_123456Z_network/
```

| File | Purpose |
| --- | --- |
| `nmap_output.xml` | Structured inventory for parsing and later review |
| `nmap_output.txt` | Nmap's readable scan output |
| `nmap_execution.log` | Command, tool output, errors, and exit status |
| `client_security_report.txt` | Baseline inventory and review notes |
| `orchestrated_audit_report.txt` | Advanced workflow summary and evidence references |
| `hydra_<ip>_<port>.json` and `.log` | Restricted credential-test evidence, when enabled |
| `nikto_<ip>_<port>.txt` and `.log` | Web assessment results, when enabled |
| `nse_<ip>_<port>.txt` and `.log` | Selected NSE results, when enabled |
| `masscan_raw.txt` and `masscan.log` | Supplementary discovery results, when enabled and supported |
| `audit_traffic.pcap` and `tcpdump.log` | Capture and capture status, when enabled and supported |

Choose another output parent with `--output /path/to/audits`. Keep working files inside the Linux filesystem; shared Android storage may not preserve Unix permission restrictions. Credential evidence and PCAPs can contain sensitive client data, so review them separately from the customer-facing summary.

## 5. Command options explained

### Nmap inventory

The scripts use the following baseline:

```sh
nmap --unprivileged -sT -Pn -n -sV --version-light -F \
  -oX nmap_output.xml -oN nmap_output.txt 10.0.1.0/24
```

| Option | Purpose |
| --- | --- |
| `--unprivileged` | Tells Nmap not to assume raw-packet privileges, even if PRoot presents a root UID. |
| `-sT` | Uses ordinary TCP connections. |
| `-Pn` | Skips host discovery and tries the requested scan on every target address. |
| `-n` | Disables reverse DNS lookup. |
| `-sV` | Sends service-identification probes. |
| `--version-light` | Uses fewer service probes than the normal version-detection setting. |
| `-F` | Scans the 100 most common ports for the selected protocol; the scripts select TCP. |
| `-oX` / `-oN` | Saves XML and readable output. |

`-Pn` can make large or mostly unused ranges slow because every address is attempted. `-F` is a limited inventory, not all-port coverage: ordinary Nmap defaults cover 1,000 common ports, while `-p-` selects all ports from 1 through 65,535. [Nmap host discovery](https://nmap.org/book/man-host-discovery.html), [port selection](https://nmap.org/book/man-port-specification.html)

### Hydra credential checks

The corrected pattern uses a real password-list file:

```sh
hydra -l approved_account -P /path/to/approved-passwords.txt \
  -t 1 -f -s 22 10.0.1.50 ssh
```

`-l` supplies one account; `-P` supplies a file with one password per line; `-t 1` limits concurrency; `-f` stops after a match for that target. The original `-y` inline-list interpretation was incorrect. Hydra's `-u` changes password/login iteration order; it does not bypass account lockouts. [Hydra manual](https://github.com/vanhauser-thc/thc-hydra/blob/master/hydra.1)

Enable credential testing only for the client-approved scope and account list, accounting for the client's lockout policy. A single concurrent attempt can still trigger lockout after repeated failures. The script requires both credential arguments to enable this stage and writes raw results to separate evidence files.

### Nikto, Masscan, and capture

Nikto must receive the correct `http://` or `https://` URL. `-Format txt` selects the report format and `-output` selects its destination. IP-based requests may reach a default virtual host; use the actual hostname when reviewing name-based sites. [Nikto option reference](https://github.com/sullo/nikto/wiki/Annotated-Option-List)

Masscan's `--rate` controls transmission speed, not privileges. The example rate of 100 packets per second is adjustable, not a guarantee of suitability for every network. Its selected-port sweep runs sequentially before Nmap when enabled.

The advanced script checks whether it can open a raw packet socket before attempting Masscan or tcpdump. A successful check does not guarantee that a particular interface or capture driver will work; tool logs remain authoritative. Unsupported stages are recorded as skipped.

## 6. Baseline script: network_audit.py

Create `network_audit.py` and paste the entire code block below. It provides:

- An explicit target or actual interface-prefix detection.
- Nmap inventory with XML validation and retained error output.
- A separate text report with protocol review notes.
- Optional Hydra checks for identified SSH, Telnet, and FTP services.
- Separate credential evidence and an explicit distinction between incomplete tests and tests that reported no matches.

The wrapper uses Python's standard library but depends on the installed command-line tools. It does not install packages during a scan. Its Nmap subprocess timeout is 30 minutes, and each credential check has a two-minute limit. Larger scopes may need smaller runs or a deliberate timeout adjustment.


```python
#!/usr/bin/env python3
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET


def resolve_target(target, interface):
    if target:
        network = ipaddress.ip_network(target, strict=False)
    else:
        result = subprocess.run(
            ["ip", "-j", "-4", "address", "show", "dev", interface],
            capture_output=True, text=True, check=True, timeout=10,
        )
        candidates = {
            str(ipaddress.ip_network(
                f"{address['local']}/{address['prefixlen']}", strict=False
            ))
            for device in json.loads(result.stdout)
            for address in device.get("addr_info", [])
            if address.get("family") == "inet"
            and address.get("scope") == "global"
        }
        if len(candidates) != 1:
            raise ValueError("Interface has zero or multiple IPv4 networks; use --target.")
        network = ipaddress.ip_network(candidates.pop())
    if network.version != 4:
        raise ValueError("These examples support IPv4 only.")
    return str(network)


def new_run(output, client, kind):
    os.umask(0o077)
    label = re.sub(r"[^A-Za-z0-9_-]+", "_", client).strip("_") or "client"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    folder = Path(output).expanduser().resolve() / label / f"{stamp}_{kind}"
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    return folder


def require_tools(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ValueError("Missing tools: " + ", ".join(missing))


def run_logged(command, logfile, timeout=1800):
    # Keep partial output and errors even if a tool fails or times out.
    with Path(logfile).open("w", encoding="utf-8") as log:
        log.write("Command: " + json.dumps(command) + "\n\n")
        log.flush()
        try:
            result = subprocess.run(
                command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                cwd=Path(logfile).parent,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(f"\nExecution error: {error}\n")
            return False
        log.write(f"\nExit code: {result.returncode}\n")
        return result.returncode == 0


def read_inventory(xml_file):
    root = ET.parse(xml_file).getroot()
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap XML does not record a successfully completed scan.")
    rows = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = service.attrib if service is not None else {}
            rows.append({
                "ip": address.get("addr"),
                "port": int(port.get("portid")),
                "service": details.get("name", "unknown"),
                "method": details.get("method", "unknown"),
                "tunnel": details.get("tunnel", ""),
                "banner": " ".join(details.get(key, "") for key in
                                   ("product", "version", "extrainfo")).strip(),
            })
    return rows


def inventory_scan(target, folder):
    command = [
        "nmap", "--unprivileged", "-sT", "-Pn", "-n", "-sV",
        "--version-light", "-F", "-oX", str(folder / "nmap_output.xml"),
        "-oN", str(folder / "nmap_output.txt"), target,
    ]
    if not run_logged(command, folder / "nmap_execution.log"):
        raise RuntimeError(f"Nmap failed or timed out. Review {folder / 'nmap_execution.log'}")
    return read_inventory(folder / "nmap_output.xml")


def target_arguments(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="One IPv4 address or CIDR network")
    group.add_argument("--interface", help="Derive CIDR from this interface, e.g. wlan0")
    parser.add_argument("--client", required=True)
    parser.add_argument("--output", default="./workspace")


def append_report(report, text):
    with report.open("a", encoding="utf-8") as stream:
        stream.write(text + "\n")


def protocol_note(row):
    service, port = row["service"], row["port"]
    if row["tunnel"] == "ssl" or service == "https":
        return "TLS service observed; certificate and protocol settings need separate review."
    if service == "telnet":
        return "Telnet identified; review cleartext login exposure and replace where possible."
    if service == "ftp":
        return "FTP identified; verify whether TLS is required for login and data transfer."
    if service == "http":
        return "HTTP identified; check redirects and whether sensitive data travels unencrypted."
    if service == "ssh":
        return "SSH identified; review access policy and configuration. Open SSH is not itself a flaw."
    if service in {"microsoft-ds", "netbios-ssn", "smb"}:
        return "SMB-related service; validate dialects, signing, and access controls separately."
    if row["method"] != "probed" and port in {21, 22, 23, 80, 139, 445}:
        return "Common administration/service port; confirm its actual protocol before classification."
    return "Inventory observation; no vulnerability established by this scan."


def credential_check(row, username, passwords, folder, report):
    stem = f"hydra_{row['ip']}_{row['port']}"
    evidence = folder / f"{stem}.json"
    command = [
        "hydra", "-l", username, "-P", str(passwords), "-t", "1", "-f",
        "-s", str(row["port"]), "-b", "jsonv1", "-o", str(evidence),
        row["ip"], row["service"],
    ]
    ok = run_logged(command, folder / f"{stem}.log", timeout=120)
    try:
        result = json.loads(evidence.read_text(encoding="utf-8"))
        matches = result.get("results", [])
        if matches:
            status = f"Tool reported {len(matches)} credential match(es); validate and remediate."
            if not ok or result.get("success") is not True:
                status += " Run also had errors or was incomplete."
        elif ok and result.get("success") is True:
            status = "No match reported for the tested account/password list; this is limited coverage."
        else:
            status = "Incomplete or unsuccessful check; review tool logs."
    except (OSError, ValueError, AttributeError):
        status = "No usable structured result; review tool logs."
    append_report(report, f"Credential check {row['ip']}:{row['port']}: {status}")
    append_report(report, f"Restricted evidence: {stem}.json and {stem}.log")


def main():
    parser = argparse.ArgumentParser(description="IPv4 inventory and optional credential review")
    target_arguments(parser)
    parser.add_argument("--hydra-user", help="Enable checks for this account with --passwords")
    parser.add_argument("--passwords", type=Path, help="One approved candidate per line")
    args = parser.parse_args()
    if bool(args.hydra_user) != bool(args.passwords):
        parser.error("Supply both --hydra-user and --passwords, or neither.")
    if args.passwords:
        args.passwords = args.passwords.expanduser().resolve()
        if not args.passwords.is_file():
            parser.error("Password list does not exist.")
    require_tools(["nmap"] + (["ip"] if args.interface else [])
                  + (["hydra"] if args.hydra_user else []))
    target = resolve_target(args.target, args.interface)
    folder = new_run(args.output, args.client, "network")
    report = folder / "client_security_report.txt"
    append_report(report, f"CLIENT NETWORK REVIEW\nClient: {args.client}\nTarget: {target}")
    append_report(report, "Coverage: Nmap fast TCP ports; IPv4; service probes; no UDP scan.")
    append_report(report, "Observations require review before being reported as confirmed vulnerabilities.\n")
    print(f"Target: {target}\nOutput: {folder}", flush=True)
    try:
        rows = inventory_scan(target, folder)
        for row in rows:
            append_report(report, f"{row['ip']}:{row['port']}/tcp - {row['service']}")
            append_report(report, f"  Banner: {row['banner'] or 'Not identified'}")
            append_report(report, "  Review: " + protocol_note(row))
            if (args.hydra_user and row["method"] == "probed"
                    and row["service"] in {"ssh", "telnet", "ftp"}
                    and row["tunnel"] != "ssl"):
                credential_check(row, args.hydra_user, args.passwords, folder, report)
        append_report(report, f"\nInventory complete: {len(rows)} open TCP port observations.")
        if not args.hydra_user:
            append_report(report, "Credential checks were not enabled.")
        print(f"Report: {report}")
    except (OSError, ValueError, RuntimeError, ET.ParseError) as error:
        append_report(report, f"\nINCOMPLETE: {error}")
        raise


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as error:
        raise SystemExit(f"Audit stopped: {error}")
```

### Baseline usage

Inventory and protocol review:

```sh
python3 network_audit.py --client ACME_CORP --target 10.0.1.0/24
```

Inventory plus an explicitly selected credential check:

```sh
python3 network_audit.py --client ACME_CORP --target 10.0.1.50 \
  --hydra-user approved_account --passwords ./approved-passwords.txt
```

The password list is supplied by you; the script does not generate or download one. Hydra runs only for services identified by a probe as SSH, Telnet, or FTP, without an SSL tunnel. Port number alone does not trigger a guessed login protocol. Raw credential results remain in the run folder; the main report records the outcome without copying recovered passwords.

Hydra's structured output distinguishes execution success from credentials found. An incomplete result must not be interpreted as proof that passwords are strong. [Hydra output documentation](https://github.com/vanhauser-thc/thc-hydra)

## 7. Advanced script: advanced_audit.py

Create `advanced_audit.py` and paste this entire block into it. This second program is independent of `network_audit.py`. It provides the same basic inventory setup and separate options for web assessment, selected NSE scripts, capture, and supplementary Masscan discovery.

Optional checks run sequentially after inventory, except tcpdump, which runs in the background until 500 packets are captured or the workflow finishes. Cleanup also stops capture when the foreground workflow raises an exception or receives a normal keyboard interrupt. A forced process termination cannot guarantee cleanup.

The subprocess limits are 30 minutes for inventory, 10 minutes for Masscan, 5 minutes per Nikto target, and 3 minutes per NSE target. No periodic scheduler is installed or enabled.


```python
#!/usr/bin/env python3
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET


def resolve_target(target, interface):
    if target:
        network = ipaddress.ip_network(target, strict=False)
    else:
        result = subprocess.run(
            ["ip", "-j", "-4", "address", "show", "dev", interface],
            capture_output=True, text=True, check=True, timeout=10,
        )
        candidates = {
            str(ipaddress.ip_network(
                f"{address['local']}/{address['prefixlen']}", strict=False
            ))
            for device in json.loads(result.stdout)
            for address in device.get("addr_info", [])
            if address.get("family") == "inet"
            and address.get("scope") == "global"
        }
        if len(candidates) != 1:
            raise ValueError("Interface has zero or multiple IPv4 networks; use --target.")
        network = ipaddress.ip_network(candidates.pop())
    if network.version != 4:
        raise ValueError("These examples support IPv4 only.")
    return str(network)


def new_run(output, client, kind):
    os.umask(0o077)
    label = re.sub(r"[^A-Za-z0-9_-]+", "_", client).strip("_") or "client"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
    folder = Path(output).expanduser().resolve() / label / f"{stamp}_{kind}"
    folder.mkdir(parents=True, exist_ok=False, mode=0o700)
    return folder


def require_tools(names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise ValueError("Missing tools: " + ", ".join(missing))


def run_logged(command, logfile, timeout=1800):
    # Keep partial output and errors even if a tool fails or times out.
    with Path(logfile).open("w", encoding="utf-8") as log:
        log.write("Command: " + json.dumps(command) + "\n\n")
        log.flush()
        try:
            result = subprocess.run(
                command, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                cwd=Path(logfile).parent,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            log.write(f"\nExecution error: {error}\n")
            return False
        log.write(f"\nExit code: {result.returncode}\n")
        return result.returncode == 0


def read_inventory(xml_file):
    root = ET.parse(xml_file).getroot()
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap XML does not record a successfully completed scan.")
    rows = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            details = service.attrib if service is not None else {}
            rows.append({
                "ip": address.get("addr"),
                "port": int(port.get("portid")),
                "service": details.get("name", "unknown"),
                "method": details.get("method", "unknown"),
                "tunnel": details.get("tunnel", ""),
                "banner": " ".join(details.get(key, "") for key in
                                   ("product", "version", "extrainfo")).strip(),
            })
    return rows


def inventory_scan(target, folder):
    command = [
        "nmap", "--unprivileged", "-sT", "-Pn", "-n", "-sV",
        "--version-light", "-F", "-oX", str(folder / "nmap_output.xml"),
        "-oN", str(folder / "nmap_output.txt"), target,
    ]
    if not run_logged(command, folder / "nmap_execution.log"):
        raise RuntimeError(f"Nmap failed or timed out. Review {folder / 'nmap_execution.log'}")
    return read_inventory(folder / "nmap_output.xml")


def target_arguments(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--target", help="One IPv4 address or CIDR network")
    group.add_argument("--interface", help="Derive CIDR from this interface, e.g. wlan0")
    parser.add_argument("--client", required=True)
    parser.add_argument("--output", default="./workspace")


def append_report(report, text):
    with report.open("a", encoding="utf-8") as stream:
        stream.write(text + "\n")

import signal
import socket


def raw_packet_access():
    # A PRoot uid of zero does not prove actual Android kernel capabilities.
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)):
            return True
    except (OSError, AttributeError):
        return False


def start_capture(interface, target, folder, report):
    logfile = (folder / "tcpdump.log").open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            ["tcpdump", "-i", interface, "-nn", "-U", "-c", "500",
             "-w", str(folder / "audit_traffic.pcap"), "net", target],
            stdout=subprocess.DEVNULL, stderr=logfile,
        )
    except OSError:
        logfile.close()
        raise
    append_report(report, f"Capture started on {interface}; filter: net {target}.")
    return process, logfile


def stop_capture(capture, report):
    if capture is None:
        return
    process, logfile = capture
    try:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            code = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            append_report(report, "Capture forced to stop; inspect PCAP completeness.")
        else:
            append_report(report, f"Capture exit code: {code}; review tcpdump.log and PCAP.")
    finally:
        logfile.close()


def web_check(row, folder, report):
    tls = row["tunnel"] == "ssl" or row["service"] == "https" or row["port"] == 443
    scheme = "https" if tls else "http"
    url = f"{scheme}://{row['ip']}:{row['port']}"
    stem = f"nikto_{row['ip']}_{row['port']}"
    ok = run_logged(
        ["nikto", "-h", url, "-Format", "txt", "-output", str(folder / f"{stem}.txt")],
        folder / f"{stem}.log", timeout=300,
    )
    status = "finished; review findings" if ok else "failed or timed out; review partial evidence"
    append_report(report, f"Nikto {url}: {status}. Evidence: {stem}.txt / {stem}.log")


def nse_check(row, folder, report):
    if row["service"] in {"http", "https", "http-alt", "ssl/http"}:
        scripts = "http-title,http-security-headers"
    elif row["service"] in {"microsoft-ds", "smb"} and row["port"] == 445:
        scripts = "smb-protocols,smb2-security-mode"
    else:
        return
    stem = f"nse_{row['ip']}_{row['port']}"
    ok = run_logged(
        ["nmap", "--unprivileged", "-sT", "-Pn", "-n", "-sV", "--version-light",
         "-p", str(row["port"]), "--script", scripts,
         "-oN", str(folder / f"{stem}.txt"), row["ip"]],
        folder / f"{stem}.log", timeout=180,
    )
    status = "finished; inspect script results" if ok else "failed or timed out"
    append_report(report, f"NSE {row['ip']}:{row['port']}: {status}. Evidence: {stem}.txt")


def main():
    parser = argparse.ArgumentParser(description="IPv4 inventory with optional web, NSE, and capture tools")
    target_arguments(parser)
    parser.add_argument("--nikto", action="store_true")
    parser.add_argument("--nse", action="store_true")
    parser.add_argument("--capture-interface", help="Requires actual packet-capture permission")
    parser.add_argument("--masscan", action="store_true", help="Optional supplementary raw-packet sweep")
    parser.add_argument("--masscan-rate", type=int, default=100)
    args = parser.parse_args()
    if args.masscan_rate < 1:
        parser.error("--masscan-rate must be positive.")
    names = ["nmap"] + (["ip"] if args.interface else [])
    if args.nikto:
        names.append("nikto")
    if args.capture_interface:
        names.append("tcpdump")
    if args.masscan:
        names.append("masscan")
    require_tools(names)
    target = resolve_target(args.target, args.interface)
    folder = new_run(args.output, args.client, "advanced")
    report = folder / "orchestrated_audit_report.txt"
    append_report(report, f"ADVANCED NETWORK REVIEW\nClient: {args.client}\nTarget: {target}")
    append_report(report, "Coverage: fast TCP inventory; selected optional tools. Inspect raw evidence.\n")
    print(f"Target: {target}\nOutput: {folder}", flush=True)
    capture = None
    try:
        can_capture = raw_packet_access() if (args.masscan or args.capture_interface) else False
        if args.capture_interface:
            if can_capture:
                capture = start_capture(args.capture_interface, target, folder, report)
            else:
                append_report(report, "SKIPPED tcpdump: raw-packet access unavailable.")
        if args.masscan:
            if can_capture:
                ok = run_logged(
                    ["masscan", target, "-p21,22,23,80,443,445",
                     f"--rate={args.masscan_rate}", "-oL", str(folder / "masscan_raw.txt")],
                    folder / "masscan.log", timeout=600,
                )
                append_report(report, "Masscan: " + ("finished; review masscan_raw.txt."
                                                    if ok else "failed or timed out; review masscan.log."))
            else:
                append_report(report, "SKIPPED masscan: raw-packet access unavailable.")
        # Masscan is supplementary. Its results do not filter or accelerate this scan.
        rows = inventory_scan(target, folder)
        for row in rows:
            append_report(report, f"{row['ip']}:{row['port']}/tcp - {row['service']} {row['banner']}")
            if args.nikto and row["service"] in {"http", "https", "http-alt", "ssl/http"}:
                web_check(row, folder, report)
            if args.nse:
                nse_check(row, folder, report)
        append_report(report, f"\nInventory complete: {len(rows)} open TCP port observations.")
        append_report(report, "Optional stages may be skipped, incomplete, or require manual interpretation.")
    except (OSError, ValueError, RuntimeError, ET.ParseError) as error:
        append_report(report, f"\nINCOMPLETE: {error}")
        raise
    finally:
        stop_capture(capture, report)
    print(f"Report: {report}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as error:
        raise SystemExit(f"Audit stopped: {error}")
```

### Advanced usage

Inventory only:

```sh
python3 advanced_audit.py --client ACME_CORP --target 10.0.1.0/24
```

Inventory with web and selected NSE checks:

```sh
python3 advanced_audit.py --client ACME_CORP --target 10.0.1.0/24 \
  --nikto --nse
```

On an Alpine host with actual raw-packet privileges:

```sh
python3 advanced_audit.py --client ACME_CORP --target 10.0.1.0/24 \
  --nikto --nse --capture-interface eth0 --masscan --masscan-rate 100
```

Replace `eth0` with the actual capture interface. These packet options are retained for a capable host; ordinary unrooted UserLAnd generally cannot run them. Each requested tool must also be installed. Missing tools stop the run before scanning, while unavailable raw-packet access causes the relevant installed stages to be skipped and recorded.

The advanced report points to individual tool reports rather than embedding every raw line. A finished Nmap process does not prove that every possible vulnerability was tested, and a finished NSE process may contain no output from a script that did not apply to a service.

## 8. Run an audit and review the results

### Practical sequence

1. Connect to the intended client network and establish the target range, exclusions, and applicable test scope.
2. Verify the needed packages and choose one script based on the intended checks.
3. Supply the client name and an explicit target, or a verified interface.
4. Run the selected workflow and note the printed output-folder path.
5. Review `nmap_execution.log` and the main report for failures, timeouts, and skipped stages.
6. Inspect raw tool evidence before classifying observations as vulnerabilities.
7. Prepare the client summary, then transfer the appropriate files to your workstation.

Both scripts support `--help`:

```sh
python3 network_audit.py --help
python3 advanced_audit.py --help
```

### Interpret observations accurately

| Observation | What it establishes | Follow-up |
| --- | --- | --- |
| An open TCP port | A service accepted a connection from the scan location | Identify the application and intended access policy. |
| HTTP identified | An HTTP endpoint responded | Check HTTPS redirects and whether sensitive pages accept cleartext requests. |
| FTP identified | An FTP service responded | Determine whether explicit TLS is supported and required. |
| Telnet identified | A Telnet service is exposed | Review the login channel and replace unnecessary cleartext administration. |
| SSH identified | An SSH service is available | Review versions, algorithms, access restrictions, and authentication policy. |
| SMB-related service identified | A service consistent with SMB is exposed | Test supported dialects, signing, permissions, and guest access. |
| A software version banner | The service reported or resembled that version | Confirm patch status; vendor backports can complicate version-only conclusions. |
| No credential match | The completed test reported no success for that tested set | Do not generalize to untested accounts, passwords, or authentication paths. |
| No output / tool failure | The stage did not produce usable evidence | Resolve the failure before drawing a security conclusion. |

An open port alone is not proof of a vulnerability, and an inventory is scoped to the scanner's network position. [Nmap port-state definitions](https://nmap.org/book/man-port-scanning-basics.html)

### Client summary outline

Use the generated reports as evidence for a concise customer-facing write-up:

| Field | Include |
| --- | --- |
| Client and date | Client name, assessment date, and reviewer |
| Scope | Networks and devices actually tested; excluded systems |
| Method | Inventory ports, service probes, optional tools, and scan location |
| Coverage limits | Unreachable targets, skipped stages, errors, and untested areas |
| Validated finding | A concrete issue, affected asset, and supporting evidence |
| Recommended action | The proposed remediation and its priority |
| Follow-up | Owner, target completion date, and retest result |

Avoid copying recovered passwords or unrelated captured content into the customer report.

## 9. Packet capture and offline analysis

### Obtain a capture

In unrooted UserLAnd, the practical workflow is to analyze a capture collected on a router, firewall, mirrored switch port, or workstation with capture permissions. Import the PCAP using one of the transfer methods in Section 11.

For a host that does have capture permissions, a manual example is:

```sh
tcpdump -i eth0 -nn -s 0 -c 500 -w audit_traffic.pcap 'net 10.0.1.0/24'
```

`-c 500` stops after a packet count, not after a number of seconds. Use Ctrl+C to stop a quiet manual capture. The advanced script handles capture shutdown when its workflow ends. An empty or very small PCAP may reflect a short capture, restricted visibility, or capture failure—check the accompanying log.

### Inspect a capture in the terminal

Replace `audit_traffic.pcap` with the actual file path. TShark's `-r` reads an existing capture; `-Y` applies a display filter; `-T fields` and `-e` select tabular fields. [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

**Protocol summary:**

```sh
tshark -r audit_traffic.pcap -q -z io,phs
```

**Visible DNS queries:**

```sh
tshark -r audit_traffic.pcap -Y 'dns.flags.response == 0' \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

This shows DNS requests present in the capture. It does not expose the contents of encrypted DNS sessions.

**Unencrypted HTTP requests:**

```sh
tshark -r audit_traffic.pcap -Y 'http.request' \
  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri
```

These fields show visible HTTP metadata. They are not a complete browsing history and may contain sensitive URL parameters.

**ServerHello messages advertising older TLS versions:**

```sh
tshark -r audit_traffic.pcap \
  -Y 'tls.handshake.type == 2 && (tls.handshake.version == 0x0301 || tls.handshake.version == 0x0302)' \
  -T fields -e ip.src -e ip.dst -e tls.handshake.version
```

Treat this as a review filter, not an exhaustive TLS assessment. ClientHello and compatibility fields alone can be misleading, and a capture may not include the relevant handshake. Use a targeted TLS assessment to determine what a server currently supports.

### Interactive Termshark review

```sh
termshark -r audit_traffic.pcap
```

Use arrow keys to move between packet records and Tab to move between panes. Useful display filters include:

| Filter | Purpose |
| --- | --- |
| `ip.addr == 10.0.1.50` | Traffic involving one IPv4 device |
| `dns` | DNS packets |
| `http.request` | Visible HTTP requests |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Initial TCP SYN packets |

The audit itself generates traffic, so a capture taken during a scan contains the scanner's connections as well as any other traffic visible at the capture point.

## 10. Additional Nmap NSE checks

Nmap's scripting engine provides targeted protocol checks. On Alpine, script files and libraries may be separate packages:

```sh
apk add nmap-scripts nmap-nselibs
```

The conventional script directory is `/usr/share/nmap/scripts/`. Verify the scripts you intend to use:

```sh
nmap --script-help http-title,http-security-headers,smb-protocols,smb2-security-mode
```

The `--nse` option in `advanced_audit.py` uses the named HTTP and SMB checks below. It does not launch broad vulnerability wildcards.

### HTTP title and security headers

```sh
nmap --unprivileged -sT -Pn -n -sV -p 80,443 \
  --script http-title,http-security-headers 10.0.1.50
```

Review the results in the context of the application and the page tested. Header absence alone does not establish an exploitable vulnerability.

### SMB dialects and signing

```sh
nmap --unprivileged -sT -Pn -n -p 445 \
  --script smb-protocols,smb2-security-mode 10.0.1.50
```

`SMBv1` support needs particular attention; an open port 445 does not by itself establish which dialect is enabled. SMBv2 and SMBv3 should not be labeled obsolete merely because they are detected. [Nmap SMB protocol enumeration](https://nmap.org/nsedoc/scripts/smb-protocols.html)

### TLS configuration

```sh
nmap --unprivileged -sT -Pn -n -sV -p 443 \
  --script ssl-cert,ssl-enum-ciphers 10.0.1.50
```

Run this separately when TLS testing is appropriate for the target. `ssl-enum-ciphers` makes repeated connections and is categorized as intrusive by Nmap. It is not part of the advanced script's default named set. [Nmap cipher enumeration documentation](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)

Wildcard selections such as `http-vuln*` or `smb-vuln*` can include intrusive checks. A `safe` category label is also not an absolute guarantee that a script has no operational impact. Inspect the individual script descriptions before selecting them. [Nmap NSE usage and categories](https://nmap.org/book/nse-usage.html)

## 11. Transfer reports off Android

Use the actual run-folder path printed by your script. The paths and hostnames below are examples to replace.

### Method A: SCP or SFTP

The simplest direction is often to send files from UserLAnd to a workstation that already accepts SSH connections:

```sh
apk add openssh-client
scp -r ./workspace/ACME_CORP workstation_user@workstation_ip:/path/to/ClientReports/
```

Confirm the destination SSH host key and use the workstation's configured authentication. An SFTP client provides an interactive alternative.

If your existing UserLAnd session exposes a working SSH/SFTP service, you can instead pull from the workstation:

```sh
scp -P 2222 -r userland_user@android_ip:/actual/path/to/workspace/ACME_CORP ./ClientReports/
```

Use the session's actual username, port, and Linux path. A UserLAnd login service may only listen locally and may require additional configuration for LAN access. Do not assume that assigning a root password and launching a second `sshd` creates a working or appropriate transfer service.

### Method B: Magic Wormhole

Magic Wormhole can transfer a file between machines using a short shared code and an encrypted transfer. Network connectivity to its rendezvous/relay infrastructure may be required. [Magic Wormhole documentation](https://magic-wormhole.readthedocs.io/en/latest/welcome.html)

Keep its Python dependencies in a virtual environment:

```sh
apk add python3 py3-pip
python3 -m venv ~/wormhole-venv
. ~/wormhole-venv/bin/activate
python -m pip install magic-wormhole
```

On some Alpine architectures, dependencies may need compilation. If installation fails, use the actual build error to identify the needed packages. Do not force changes into the system Python environment with `--break-system-packages`.

Send the desired report:

```sh
wormhole send /actual/path/to/client_security_report.txt
```

On the receiving computer, with Wormhole installed:

```sh
wormhole receive
```

Enter the code shown by the sender. Share that code only with the intended recipient.

### Method C: Android shared storage

UserLAnd documents storage bindings under `/storage/internal` and, where available, `/storage/sdcard`. Inspect the locations your session actually exposes:

```sh
ls -ld /storage/internal /storage/sdcard
```

If `/storage/internal` exists and is writable:

```sh
mkdir -p /storage/internal/AuditReports
cp -r ./workspace/ACME_CORP /storage/internal/AuditReports/
```

Use Android's file picker or UserLAnd document provider to access the exported files. Do not assume `/sdcard/Download` is a valid binding. Copy anything you need to retain outside UserLAnd's app-scoped storage before uninstalling the app. [UserLAnd file import/export guide](https://github.com/CypherpunkArmory/UserLAnd/wiki/Importing-and-exporting-files-in-UserLAnd)

## 12. Troubleshooting

| Symptom | Likely issue | Next step |
| --- | --- | --- |
| `python (no such package)` | Wrong package name | Install `python3`; use `py3-pip` when pip is needed. |
| An optional package cannot be found | Repository, release, architecture, or package-name mismatch | Check exact local availability with `apk search -x`; omit unavailable optional modules. |
| `/bin/bbsuid: Permission denied` during an APK trigger | A privileged BusyBox operation may be blocked in PRoot | Check the APK exit status, installed-package state, and affected commands; do not assume every warning is harmless. |
| `ip` cannot read addresses or routing data | Android restricts interface or netlink access | Supply a verified `--target` explicitly. |
| Nmap complains about privileges | Raw-packet assumptions or platform restrictions | Confirm `--unprivileged -sT -Pn`; read the complete execution log. |
| Scan finds few or no devices | Wrong scope, guest/client isolation, filtering, VPN route, or limited scanned ports | Verify the network and test a known reachable client device. |
| Inventory times out | Large scope, filtered hosts, or slow probes | Inspect partial logs; divide the scope into smaller runs. |
| Masscan/tcpdump skipped | No real raw-packet access | Use the unprivileged inventory workflow or collect packet evidence on a capable host. |
| PCAP missing or unreadable | Capture failed or never produced usable packets | Read `tcpdump.log`; distinguish interface failure from a quiet capture. |
| Hydra reports an unsupported service | Installed build lacks that protocol module | Check `hydra -h` and `hydra -U ssh` or the relevant module. |
| Hydra times out or returns no valid JSON | Incomplete check, unsupported behavior, or tool error | Inspect its `.log`; do not report a clean credential assessment. |
| No Nikto result for a web device | Service was not identified as HTTP, tool timeout, TLS issue, or virtual hosting | Review Nmap and Nikto evidence; retry the correct hostname and scheme as appropriate. |
| NSE gives no script output | Missing scripts, script rules did not match, or connection failure | Use `--script-help` and inspect the tool log and target service. |
| Existing results seem mixed together | Old scripts reused static output paths | Use the timestamped run directories in this guide. |
| Android stops a long-running session | Background-process or battery-management restrictions | Keep the session active or perform longer audits from a suitable workstation. |

## 13. Corrections to the original notes

This consolidation preserves the requested two-script organization while resolving the following contradictions and code defects:

| Original issue | Treatment in this guide |
| --- | --- |
| Repeated conversation fragments, browser controls, and search-result text | Removed from the guide. |
| Broken code fences, escaped identifiers, and missing indentation | Rebuilt as complete, separately labeled Python blocks. |
| Two scripts accidentally merged despite the stated preference | Kept as independent programs in one Markdown document. |
| Every detected network forced to `/24` | Uses an explicit CIDR or the interface's real prefix. |
| Silent loopback fallback after detection failure | Stops with an actionable error. |
| Masscan and live capture promised to work in unrooted UserLAnd | Described as optional, privilege-dependent stages. |
| Masscan described as feeding targeted Nmap, despite no such implementation | Clearly labeled supplementary; Nmap still scans the requested range. |
| Hydra `-y` described as an inline password list | Replaced with a supplied `-P` file. |
| Hydra `-u` described as defeating account lockouts | Corrected; no lockout avoidance is claimed. |
| Port 23 could be mapped incorrectly to an FTP credential test | Credential checks require the identified service. |
| Open SSH or SMB treated as a confirmed flaw | Reported as observations needing appropriate validation. |
| All web endpoints passed to Nikto with `http://` | Selects HTTPS for identified TLS/HTTPS endpoints and port 443. |
| Tool errors suppressed while printing success | Retains error output, return codes, timeout notes, and incomplete statuses. |
| Static reports overwritten between clients or runs | Uses client names and unique timestamped directories. |
| Broad vulnerability NSE wildcards described as non-intrusive | Uses a named baseline and documents separate targeted checks. |
| Assumed `/sdcard/Download` access and forced system Python installation | Uses documented UserLAnd bindings and a Python virtual environment. |

**Validation status:** Markdown structure and embedded Python syntax were checked. Selected script behavior was checked with simulated command results, without scanning a network. The examples have not been tested end to end on your Android device or a client network. Optional-tool availability and live behavior must be checked on the installation where you use them.

## Related Files

- [UserLAnd overview](readme.md) - General subsection guide and navigation.
- [Mobile Security section](../) - Parent mobile-security resources.
- [ULTIMATE CYBERSECURITY MASTER GUIDE](../../) - Repository root.
