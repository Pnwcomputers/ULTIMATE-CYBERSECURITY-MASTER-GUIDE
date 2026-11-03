# Cheat Sheet & Reference Documents — Review Index

_Review date: October 31, 2026 (Pacific time). This is a targeted content and safety audit, not a guarantee every historical command or third-party link has been executed or freshly verified._

[Main guide](../README.md) · [Start here](../START_HERE.md) · [Documentation index](./README.md) · [Legal terms](../LEGAL.md)

**November 2 addition:** [CLI Field Cheat Sheet (Devhints-informed)](./devhints-cli-field-reference.md) — a new, independently written reference. It was not part of the October 31 audit and its commands have not been run on every supported platform.

## Reader-first quick reference collection

| Topic | Reference | Status / intended use |
| --- | --- | --- |
| Debian / Ubuntu / WSL | [Linux Command Cheat Sheet](./LinuxCheatSheet.md) | Reviewed riskier package, Python and shell installer examples; packages/WSL require local verification |
| Arch / Manjaro | [Arch Linux Cheat Sheet](./ArchLinux_CheatSheet.md) | Replaced dangerous blanket overwrite, dep-bypass and keyring deletion recipes; Manjaro-specific changes still require upstream verification |
| Ports, HTTP and regex | [Networking Reference](./references.md) | Clarified service-port assumptions, IANA references and regex limitations |
| Glossary | [Cybersecurity Glossary](../GLOSSARY.md) | Modernized selected networking/blue-team terms and corrected NetExec migration claim |
| Aircrack-ng | [Aircrack-ng Commands](./Aircrack-ng_Commands.md) | Clarified active RF interference, PMF and WPA3 versus WPA2 capture assumptions |
| ESP32 Wi-Fi Marauder | [Marauder Cheat Sheet](./WifiMarauder_CheatSheet.md) | Firmware-specific UI and active-mode cautions; WPA3-SAE correction |
| Pwnagotchi | [Pwnagotchi Cheat Sheet](./pwnagotchi_cheatsheet.md) | Updated release image, plugin, capture format, web UI credential and reflash caution |
| OSINT | [OSINT Investigator Cheat Sheet](../OSINT/OSINT_CHEATSHEET.md) | Deduplicated quick-start introduction, clarified tool coverage/privacy and credential handling |
| Memory forensics | [Volatility 3 Cheat Sheet](../IncidentResponse/Digital-Forensics/Memory/volatility_cheatsheet.md) | Removed unsupported claim of official third-party container image; isolated Python and symbol cautions |
| NanoVNA | [Quick Reference](../SDR/nanovna/07-quick-reference.md) | Clarified approximate formulas and antenna-length guidance |
| Bash scripting | [Bash Cheat Sheet](../Scripts/Bash/bash_scripting_cheat-sheet.md) | Removed direct remote script execution and fixed some unsafe admin examples; adversarial lab sections remain marked |
| CLI field operations (new November 2) | [Devhints-informed CLI Field Cheat Sheet](./devhints-cli-field-reference.md) | Added after this October 31 audit; original examples with official-doc links, not comprehensively runtime tested |
| General security | [Cybersecurity Cliff Notes](../cybersecurity_cliff_notes.md) | Clarified 2025 OWASP taxonomy versus historical examples; updated WPA2/WPA3 caveats |
| Wireshark and packets | [Advanced Wireshark Reference](./wireshark.md) | Existing indexed reference; separate [PR #145](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/pull/145) adds a master filter catalog and field quick sheet; merge separately |
| Wireless incident investigation | [Deauth/PMF Guide](./wifi-deauthentication-detection.md) | Previously reviewed Kismet/nzyme cross-linked guide |

## Key corrections that matter in practice

1. **Arch Linux:** Avoid wildcard `--overwrite '*'`, `pacman -Rdd`, standalone `pacman -Sy`, and routine keyring deletion. Diagnose ownership/trust errors and maintain a supported full upgrade path. Check [ArchWiki system maintenance](https://wiki.archlinux.org/title/System_maintenance) and [pacman troubleshooting](https://wiki.archlinux.org/title/Pacman#Troubleshooting).
2. **Debian/Python:** Prefer isolated `venv` or `pipx` on externally managed Python installations; review scripts instead of running a moving network installer via `curl | sh`.
3. **RF/Wi-Fi:** Distinguish passive observation from active deauth/beacon injection; WPA3-SAE is not just a WPA2-PSK hashcat 22000 workflow. Check real hardware/PMF/firmware.
4. **Pwnagotchi:** Older 32-bit image, capture path, default password and plugin examples should not be blindly pasted onto newer jayofelony releases. Confirm boot image, architecture and release notes before erasing media.
5. **Volatility:** Use validated Python/Volatility version, symbols and tool/image provenance; memory evidence can contain secrets and may not include all artifacts claimed by an introductory table.
6. **Port and regex references:** Ports are conventions not proof of C2, malware or applications; lexical regexes are not full IP/URL/credit-card validators.
7. **OWASP:** The [official Top 10:2025](https://top10.owasp.org/2025/) is current; numbered historical vulnerability examples are not the official current ranking.

## Static PDF reference inventory (not silently rewritten)

These repository files are preserved as separate references, not asserted to have been updated or validated in this audit:

- [Wireshark Cheat Sheet PDF](../PDF/Wireshark_Cheat_Sheet.pdf) — retained as legacy/static PDF; prefer the editable Markdown and current official field reference for changing syntax.
- [OSCP Cheat Sheet PDF](../PDF/OSCP_Cheat_Sheet.pdf) — version/syllabus, provenance and distribution rights should be verified with the publisher before replacing.
- [ReactJS Cheat Sheet PDF](../PDF/ReactJs_Cheatsheet.pdf) — may not match current React releases; defer to official maintained docs.
- [SAST Scanners PDF](./SAST.Scanners.-.We.Hack.Purple.Cheat.Sheet.pdf) — third-party/static content; not edited.
- [Ethical Hacking Mind Map](./Ethical.Hacking.MindMap.pdf) — static file, not re-audited.

> Avoid claiming an externally sourced PDF is current just because an internal link resolves. If the source licenses are unclear, prefer links to the publisher over silently modifying/rehosting copyrighted content.

## Validation scope and follow-up

- Audit methodology: inspect all repository files whose names explicitly include **cheat sheet**, **cliff notes**, **glossary**, **references**, or **quick reference**; prioritize Markdown documents that contain copyable commands. Review the main Documentation index and contextual linked guides.
- Edit scope: **12 Markdown cheat sheets/references**, this audit index, and reader-first navigation entries. The existing Wireshark catalog/cheat sheet work is tracked independently by PR #145.
- Automated GitHub checks: Markdown formatting and offline internal Markdown links/anchors; existing repository guide/hardening checks where changes trigger them. These verify structure, **not** all hardware, all shell scripts in a file, version availability, external URLs or legal compliance.
- Deferred validation: actual Arch/Manjaro/WSL installations, microcontroller firmware, credential-sensitive memory dumps, third-party PDFs and real device-specific behavior. Use a disposable VM/hardware test bench to validate an example before endorsing it operationally.
- External reference sources: [ArchWiki](https://wiki.archlinux.org/), [Debian](https://www.debian.org/doc/), [OWASP Top 10](https://top10.owasp.org/2025/), [Pwnagotchi releases](https://github.com/jayofelony/pwnagotchi/releases), [Volatility 3](https://volatility3.readthedocs.io/en/latest/), [IANA port registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml), [Wireshark](https://www.wireshark.org/docs/dfref/).
