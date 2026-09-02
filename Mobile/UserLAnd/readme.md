# 📱 UserLAnd - Linux on Android

<div align="center">

**Portable Linux environments, administration, scripting, and authorized security auditing on Android**

*Part of the [Mobile Security section](../) in the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../)*

![UserLAnd](https://img.shields.io/badge/UserLAnd-Linux_on_Android-blue?style=for-the-badge)
![Android](https://img.shields.io/badge/Android-Userspace-green?style=for-the-badge)
![Linux](https://img.shields.io/badge/Linux-CLI_and_Automation-orange?style=for-the-badge)

</div>

---

## 🎯 Purpose

Provide a central reference for using **UserLAnd to run Linux environments on Android** for command-line work, system administration, scripting, troubleshooting, and authorized security assessments. This subsection covers general UserLAnd workflows and links to distribution-specific guides.

## ⚙️ Function

Covers Linux filesystem and session setup, package management, terminal access, optional graphical sessions, network diagnostics, Python automation, file organization, report transfer, and the practical limits of an unrooted Android userspace environment.

## 🏆 Goal

Build a useful mobile Linux workspace that can support field diagnostics and repeatable technical work, with clear instructions about which tasks work through ordinary userspace access and which require another host, additional privileges, or specialized hardware.

## 📋 When to Use

- Setting up or maintaining a Linux session in UserLAnd.
- Running Linux command-line tools from an Android phone or tablet.
- Performing SSH administration, DNS lookups, HTTP checks, or basic network diagnostics.
- Creating and running Python or shell scripts during field work.
- Conducting an authorized service inventory or web configuration review.
- Reading existing packet captures and preparing assessment reports.
- Transferring working files between Android and a workstation.
- Choosing the correct distribution-specific guide for the current session.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Current Content](#-current-content)
- [Capabilities and Limitations](#-capabilities-and-limitations)
- [Getting Started](#-getting-started)
- [Package Management](#-package-management)
- [UserLAnd Toolchain](#-userland-toolchain)
- [Practical Workflow](#-practical-workflow)
- [Files, Reports, and Backups](#-files-reports-and-backups)
- [Troubleshooting](#-troubleshooting)
- [Suggested Future Content](#-suggested-future-content)
- [Contributing](#-contributing)
- [Resources](#-resources)
- [Related Files](#related-files)
- [Authorized Use and Data Handling](#-authorized-use-and-data-handling)

---

## 🎯 Overview

[UserLAnd](https://github.com/CypherpunkArmory/UserLAnd) provides Linux userspace environments on Android without requiring the phone to be rooted. A filesystem holds the selected Linux distribution and its installed packages; a session connects to that filesystem through the configured access method, such as SSH or VNC. [UserLAnd getting-started guide](https://github.com/CypherpunkArmory/UserLAnd/wiki/Getting-Started-in-UserLAnd)

The Linux environment uses the Android host's kernel. PRoot can translate filesystem access and present an apparent Linux root identity, but it does not grant Android kernel privileges. Installing a tool successfully therefore does not prove that every feature of the tool can operate. [PRoot documentation](https://proot-me.github.io/)

### What You'll Find Here

- **Distribution guides** with package names and commands specific to the selected Linux environment.
- **Field workflows** for diagnostics, service inventory, and technical administration.
- **Automation examples** for repeatable collection, parsing, and reporting.
- **Compatibility notes** for Android permissions, networking, storage, and session behavior.
- **Evidence-handling guidance** for keeping client files organized and moving them off the device.

The current distribution-specific guide covers **Alpine Linux**. Other distribution guides can be added as they are written and validated.

---

## 📂 Current Content

The subsection currently uses this structure under `Mobile/UserLAnd/`:

| File | Description |
| --- | --- |
| **[readme.md](readme.md)** | General UserLAnd overview, navigation, setup concepts, tool categories, limitations, and workflow reference. |
| **[alpinelinux.md](alpinelinux.md)** | Alpine package setup, network-audit examples, separate baseline and advanced Python scripts, report organization, packet analysis, NSE checks, and file transfer. |

### Alpine Network Auditing Guide

The [Alpine guide](alpinelinux.md) documents two separate programs:

| Program documented in the guide | Focus |
| --- | --- |
| `network_audit.py` | TCP service inventory, protocol review notes, and optional credential checks. |
| `advanced_audit.py` | TCP inventory with optional Nikto, selected NSE scripts, and privilege-dependent packet tools. |

Their source is embedded in `alpinelinux.md`; they are not listed here as separate repository files. Copy each complete code block into its corresponding `.py` file when using the examples.

---

## 🧭 Capabilities and Limitations

| Task | Typical suitability in unrooted UserLAnd | Key consideration |
| --- | --- | --- |
| Shell scripting, Python, Git, and text processing | Good | Install packages for the selected distribution and architecture. |
| SSH client administration and file transfer | Good | Requires reachable hosts and valid access. |
| DNS queries and HTTP requests | Good | Subject to network filtering and Android connectivity. |
| Nmap TCP connect scanning | Often suitable | Use explicit unprivileged options and a verified target scope. |
| Web assessment and selected NSE scripts | Often suitable | Tool dependencies and target behavior vary. |
| Offline PCAP analysis | Good | Analyze captures collected on a suitable capture device. |
| Lightweight graphical applications | Environment-dependent | Requires a working graphical session and sufficient resources. |
| Live packet capture and Masscan | Generally unavailable | Require real packet access that ordinary PRoot does not grant. |
| Wi-Fi monitor mode or frame injection | Unavailable through PRoot alone | Needs compatible host privileges, drivers, and hardware. |
| Kernel modules, host firewall administration, or USB gadget features | Unavailable through PRoot alone | These are host-kernel capabilities. |
| Long unattended jobs | Limited reliability | Android can suspend or terminate background processes. |

Nmap's TCP connect mode uses ordinary socket connections. Masscan uses a separate TCP/IP stack and has different access requirements; lowering its rate does not turn it into an unprivileged connect scanner. [Nmap scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html), [Masscan documentation](https://github.com/robertdavidgraham/masscan)

For a task that requires direct hardware or kernel access, use an appropriately configured platform from the broader [Mobile Security section](../) or a suitable workstation. Running a different distribution inside the same unrooted PRoot environment does not itself remove those limits.

---

## 🚀 Getting Started

### 1. Create a Filesystem and Session

Install UserLAnd from a distribution source linked by the [official project](https://github.com/CypherpunkArmory/UserLAnd). Choose a distribution or application offered by your installed version and create its filesystem and session. Allow the initial assets to download, then connect using the configured terminal or graphical access method. Exact menus and available distributions can vary by release.

### 2. Identify the Environment

Inside the Linux session:

```sh
cat /etc/os-release
uname -m
id
pwd
```

Use the distribution information to choose package commands. An apparent UID of `0` inside the session is not proof of Android root access.

### 3. Update and Install the Basics

Use the matching package manager in the next section. Start with a text editor, Python, an SSH client, Git, and the diagnostic tools needed for your task.

For Alpine, continue with the [Alpine Linux guide](alpinelinux.md).

### 4. Verify One Small Task

Confirm the installed tools run before building a larger workflow:

```sh
python3 --version
git --version
ssh -V
```

Check connectivity to a known, intended destination, then proceed with the actual task. Package installation and tool startup are only the first checks; permissions and network reachability affect live operations.

### 5. Add Graphical Access Only When Needed

UserLAnd supports session types such as VNC alongside terminal access. Desktop packages and startup commands depend on the selected distribution and session configuration. Follow its current instructions rather than assuming a desktop command from another distribution applies. [UserLAnd session setup](https://github.com/CypherpunkArmory/UserLAnd/wiki/Getting-Started-in-UserLAnd)

---

## 📦 Package Management

Use commands for the distribution actually running in the session. Execute administrative package operations with the session's configured privileges; `sudo` or `doas` may need to be added where available.

| Task | Alpine Linux | Debian / Ubuntu / Kali |
| --- | --- | --- |
| Refresh indexes | `apk update` | `apt update` |
| Upgrade installed packages | `apk upgrade` | `apt upgrade` |
| Search for a package | `apk search package_name` | `apt search package_name` |
| Install a package | `apk add package_name` | `apt install package_name` |
| Remove a package | `apk del package_name` | `apt remove package_name` |
| Python 3 package | `python3` | `python3` |
| pip package | `py3-pip` | `python3-pip` |

These are package-manager examples, not a promise that every named distribution is offered by every UserLAnd release. Repository availability and package names vary. Check your configured release and architecture before adding optional tools. [Alpine package management](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html), [UserLAnd package-management basics](https://github.com/CypherpunkArmory/UserLAnd/wiki/Getting-Started-in-UserLAnd)

For Python applications with additional dependencies, prefer a virtual environment. On Debian-family installations, the distribution's `python3-venv` package may be needed:

```sh
python3 -m venv ~/venvs/tooling
. ~/venvs/tooling/bin/activate
python -m pip install package_name
```

Replace `package_name` with the actual Python package required. Keep system package management separate from project-specific Python dependencies.

---

## 🧰 UserLAnd Toolchain

This is a task-oriented reference. Installation commands belong in the relevant distribution guide so package availability can be checked there.

| Tool or category | Purpose | Practical note |
| --- | --- | --- |
| Python 3 | Automation, parsing, report generation | Prefer standard-library solutions when they meet the need. |
| Shell and text utilities | File handling, filtering, small workflows | BusyBox and GNU command options can differ. |
| Git | Repository and script management | Keep local changes and credentials organized. |
| OpenSSH client | Remote administration, SCP, and SFTP | A client connection does not require exposing a server on the phone. |
| Curl / Wget | HTTP requests and file retrieval | Useful for endpoint checks and approved downloads. |
| Dig / Whois | DNS and registration lookups | Separate public records from directly verified infrastructure facts. |
| Nmap | TCP inventory and service identification | Use an explicit target and compatible scan options. |
| Netcat / Socat | Connection tests and data streams | Bind listeners deliberately and keep their scope controlled. |
| Nikto | Web server configuration assessment | Review results and use the correct hostname and URL scheme. |
| Hydra | Approved account/password checks | Optional; account lockout and incomplete-test handling matter. |
| TShark / Termshark | Offline packet analysis | Opening a PCAP does not require the ability to capture traffic live. |
| Nano or another editor | Edit scripts, notes, and configuration | Choose an editor that is practical on the device. |

Detailed installation and auditing examples are in [alpinelinux.md](alpinelinux.md).

---

## 🔬 Practical Workflow

### Prepare

Identify the task, distribution, required tools, and intended targets. For customer work, record the relevant test scope and exclusions. Check available storage and keep the session active for work that should not be interrupted.

### Work

Run a small diagnostic or inventory first. Check its outcome, then perform the additional steps needed for the task. Use actual network prefixes instead of assuming every client subnet is `/24`.

For example, the Alpine baseline program can inventory an explicit client subnet:

```sh
python3 network_audit.py --client CLIENT_NAME --target 10.0.1.0/24
```

This command assumes you have already created the script from the [Alpine guide](alpinelinux.md) and installed its dependencies.

### Review

Retain output and errors. Distinguish completed checks from skipped, failed, or timed-out stages. An open port is an inventory observation; it needs context before it becomes a security finding.

### Document

Record what was tested, the observed result, supporting evidence, coverage limits, and any recommended follow-up. Keep customer-facing summaries separate from raw credentials or sensitive captures.

### Export and Close

Copy the required files to the intended destination, verify the transfer, stop temporary listeners or background processes, and retain or remove local copies according to the working arrangement.

---

## 💾 Files, Reports, and Backups

Use a consistent workspace organization:

| Location | Intended content |
| --- | --- |
| `~/scripts/` | Reusable scripts and supporting code |
| `~/workspace/<client>/<run>/` | Task-specific output and evidence |
| `~/venvs/` | Python virtual environments |
| A verified shared-storage location | Files deliberately exported to Android |

These are suggested working locations, not additional files already present in this repository subsection.

UserLAnd documents shared-storage bindings such as `/storage/internal` and `/storage/sdcard`. Inspect your session before using a path; `/sdcard/Download` is not a universal location. Its app-scoped storage can be deleted when the app is uninstalled. [UserLAnd file-transfer guide](https://github.com/CypherpunkArmory/UserLAnd/wiki/Importing-and-exporting-files-in-UserLAnd)

Common transfer options include SCP/SFTP, an appropriate encrypted transfer tool, or the UserLAnd document provider. Keep a copy outside the phone for files that need to survive device loss, app removal, or filesystem replacement.

---

## 🔧 Troubleshooting

| Issue | What to check |
| --- | --- |
| A package cannot be found | Distribution, release, architecture, repository configuration, and exact package name. |
| A command works on another Linux host but fails here | Android/PRoot limits, missing dependencies, or BusyBox/GNU differences. |
| A program reports permission denied despite a root-looking prompt | Whether the operation requires real host privileges rather than filesystem-level access. |
| Interface or routing inspection fails | Android restrictions; provide a verified target address or CIDR explicitly. |
| A service manager is unavailable | Whether that init system is actually running in the session; use the documented session startup method. |
| A long job disappears | Android battery management, background-process termination, session state, or memory pressure. |
| Files are not visible in the Android file manager | Actual storage bindings, document-provider access, and app storage permissions. |
| A desktop session fails | Selected graphical access method, installed desktop packages, startup logs, and available resources. |
| A Python dependency fails to build | Python version, architecture, musl compatibility on Alpine, and the specific compiler/dependency error. |
| An audit reports nothing useful | Correct scope, target reachability, tool logs, and what the selected scan actually covers. |

For reproducible issues, record the Android version, UserLAnd version, distribution release, architecture, exact command, and complete error output. Remove credentials and customer-sensitive details before sharing logs.

---

## 📋 Suggested Future Content

The following are **proposed additions**, not existing guides or implemented features. Filenames are shown as text so the index does not link to files that have not been added.

| Proposed file | Content |
| --- | --- |
| `setup.md` | General installation, filesystem/session lifecycle, SSH/VNC setup, and device resource considerations. |
| `troubleshooting.md` | Common PRoot, Android permissions, package, networking, and session errors with verified fixes. |
| `files-and-backups.md` | Storage bindings, secure transfer, backup, restore, and device migration. |
| `python-automation.md` | Virtual environments, subprocess handling, logging, configuration, and repeatable reports. |
| `debian.md` | Debian-specific package and administration workflows, when a supported session is available. |
| `ubuntu.md` | Ubuntu-specific setup and tool compatibility, when a supported session is available. |
| `kali.md` | Kali userspace tools and the distinction between ordinary UserLAnd and a rooted NetHunter platform. |
| `desktop-sessions.md` | Lightweight graphical environments, session startup, usability, and resource limits. |

Add a guide to **Current Content** only after the file exists. Add standalone script links only when those scripts are actually committed as separate files.

---

## 🤝 Contributing

To contribute to this subsection:

1. Follow the four-header introduction: `## 🎯 Purpose`, `## ⚙️ Function`, `## 🏆 Goal`, and `## 📋 When to Use`.
2. Include a `## Related Files` section and add reciprocal links where relevant.
3. Preserve exact filename casing in relative links, including `readme.md` and `alpinelinux.md`.
4. Use hyphens instead of em-dashes for prose separators.
5. Record the distribution, release, architecture, Android/UserLAnd version, and actual validation performed.
6. Verify package names and command flags before presenting examples as tested.
7. Distinguish unrooted userspace tasks from features requiring Android root, kernel capabilities, or special hardware.
8. Document errors, incomplete outcomes, and coverage limits alongside successful examples.
9. Keep credentials and customer evidence out of committed examples.
10. Include appropriate scope and authorization context for active security testing.

---

## 📚 Resources

### UserLAnd and PRoot

- [UserLAnd official repository](https://github.com/CypherpunkArmory/UserLAnd)
- [UserLAnd getting started](https://github.com/CypherpunkArmory/UserLAnd/wiki/Getting-Started-in-UserLAnd)
- [UserLAnd FAQ](https://github.com/CypherpunkArmory/UserLAnd/wiki/FAQ)
- [UserLAnd importing and exporting files](https://github.com/CypherpunkArmory/UserLAnd/wiki/Importing-and-exporting-files-in-UserLAnd)
- [PRoot project documentation](https://proot-me.github.io/)

### Tools Used in the Current Guide

- [Alpine package-management documentation](https://docs.alpinelinux.org/user-handbook/0.1a/Working/apk.html)
- [Nmap scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [Nmap scripting-engine usage](https://nmap.org/book/nse-usage.html)
- [Nikto option reference](https://github.com/sullo/nikto/wiki/Annotated-Option-List)
- [Hydra documentation](https://github.com/vanhauser-thc/thc-hydra)
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

---

## Related Files

- [Alpine Linux Network Auditing Toolkit Guide](alpinelinux.md) - Current distribution-specific guide and embedded scripts.
- [Mobile Security section](../) - Parent section for mobile platforms and assessments.
- [ULTIMATE CYBERSECURITY MASTER GUIDE](../../) - Repository root and main navigation.

---

## ⚠️ Authorized Use and Data Handling

Use active auditing tools only against devices and networks covered by the owner's explicit authorization. Keep the approved targets, time window, methods, and exclusions clear before testing. Credential checks and intrusive scripts need particular care because they can affect accounts or services.

Protect any collected credentials, logs, and packet captures. Share only the evidence needed for the agreed task, and report failures or untested areas honestly. UserLAnd is a working environment; it does not change the scope of permission granted by a client or system owner.

---

<div align="center">

**Linux tools on Android, with clear scope and practical expectations.**

**Repository:** [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by:** [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>
