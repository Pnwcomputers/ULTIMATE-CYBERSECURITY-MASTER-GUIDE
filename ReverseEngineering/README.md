# 🔬 Reverse Engineering

Last reviewed: 2026-09-29

> [!CAUTION]
> **Authorized use only.** Reverse engineering, disassembly, decompilation, binary
> patching, and comparison techniques in this section are for systems you own,
> have explicit written authorization to analyze, or that are provided as legal
> lab or CTF material. Unauthorized analysis or modification of software can
> violate license terms and criminal law. See [LEGAL.md](../LEGAL.md).

<div align="center">

**Software reverse engineering with Ghidra: from first listing to headless pipelines**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

</div>

---

## 🎯 Purpose

Index and entry point for software reverse engineering (SRE) in this repository.
The working tool is [Ghidra](https://github.com/NationalSecurityAgency/ghidra/),
NSA's open-source SRE suite. The long-form text lives in
[ghidra-guide-index.md](./ghidra-guide-index.md).

## ⚙️ Function

Routes a reader to the right chapter of the Ghidra guide, the official install
docs, and the neighboring repo sections (firmware, IR, lab) without forcing a
linear read of all 23 chapters.

## 🏆 Goal

Get an authorized analyst from "I extracted a zip" to a repeatable workflow:
classify the file, import it honestly, repair the listing, type the data,
automate what repeats, and compare versions.

## When to use

- First Ghidra install, or a JDK mismatch after a Ghidra upgrade
- Malware or unknown-binary triage after the sample is contained
- Firmware dumped in [HardwareHacking](../HardwareHacking/) that now needs a listing
- An IDA habit you want to map onto Ghidra keys and project layout
- Standing up headless analysis or a shared Ghidra Server later

**Prerequisites:** command line, basic C, how a program lands in memory.
Practice only in an isolated lab: [Homelab](../Homelab/).

> [!NOTE]
> Public Ghidra **12.1.x** wants a 64-bit **JDK 21**. Development docs already
> describe **12.2** and **JDK 25**. Trust the `GettingStarted.md` inside *your*
> extracted zip, not a remembered version number.

---

## Start here

| If you need… | Open |
| --- | --- |
| The full standalone guide | [ghidra-guide-index.md](./ghidra-guide-index.md) |
| Official release zip only | [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases) (`ghidra_<version>_PUBLIC_<date>.zip`) |
| Current JDK / launch / server notes | [GettingStarted.md](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md) |
| Official classroom labs | [GhidraClass](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass) |

Download only the `PUBLIC` zip. The two GitHub "Source Code" archives are not
the runnable release.

---

## Guide map

All chapter text is in [ghidra-guide-index.md](./ghidra-guide-index.md). Use
the anchors below, or scroll the file's own table of contents.

| Part | Chapters | Jump |
| --- | --- | --- |
| I. Getting Started | 1–3 Disassembly theory, lab tools, install Ghidra | [Part I](./ghidra-guide-index.md#part-i-getting-started) |
| II. Basic usage | 4–10 Import, windows, listing repair, types, xrefs, graphs | [Part II](./ghidra-guide-index.md#part-ii-basic-ghidra-usage) |
| III. Extending Ghidra | 11–16 Server, config, extensions, PyGhidra, GhidraDev, headless | [Part III](./ghidra-guide-index.md#part-iii-customizing-and-extending-ghidra) |
| IV. Deeper dive | 17–20 Loaders, SLEIGH processors, decompiler, compiler output | [Part IV](./ghidra-guide-index.md#part-iv-a-deeper-dive) |
| V. Applications | 21–23 Obfuscation, patching, BSim and other diffs | [Part V](./ghidra-guide-index.md#part-v-real-world-applications) |
| Appendix | IDA keymap and first-session checklist | [Appendix](./ghidra-guide-index.md#appendix-ghidra-for-ida-users) |

### Reading order

```
New to SRE?
  -> Part I (what a listing is, then install)
  -> Part II through Chapter 9 (stop when you can name a function from a string xref)
  -> Appendix lab checklist
  -> Parts III–V when a real sample demands them

Comfortable in IDA?
  -> Appendix first (keys and project model)
  -> Chapter 8 (types) and Chapter 19 (decompiler)
  -> Chapter 11 or 16 if you need a team or a pipeline

Need a pipeline, not a GUI?
  -> Chapter 3 (install layout) then Chapter 16 (analyzeHeadless)
  -> Chapter 14 (PyGhidra) if the script is the product
```

---

## Neighboring sections

| Section | Why it sits next to this one |
| --- | --- |
| [Homelab](../Homelab/) | Where you run Ghidra and untrusted binaries |
| [HardwareHacking](../HardwareHacking/) | Firmware comes off the bench; this section reads it |
| [IncidentResponse](../IncidentResponse/) | Sample intake, containment, and what the listing must answer |
| [Tradecraft](../Tradecraft/) | Capability questions the listing is often asked to confirm |
| [GLOSSARY.md](../GLOSSARY.md) | Shared terms |

## See also

- [LEGAL.md](../LEGAL.md)
- [START_HERE.md](../START_HERE.md)

---
[Back to Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
