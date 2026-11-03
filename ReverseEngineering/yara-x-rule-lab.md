# YARA-X Rule Authoring and Malware Triage Lab

_Last reviewed: 2026-11-02 (source/docs review; no malware samples scanned)_

> [!CAUTION]
> Handle malware, memory images and downloaded test samples inside an
> isolated, access-controlled research environment. Never execute live
> samples on business workstations or against client hosts without written
> authorization and an approved containment plan. See [legal terms](../LEGAL.md).

**Prerequisites:** [Reverse Engineering](README.md) · [REMnux](remnux-malware-analysis-guide.md) · [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md).

## Project role

[VirusTotal YARA-X](https://github.com/VirusTotal/yara-x) is a newer YARA
implementation in Rust with its own version and compatibility considerations.
It is useful for learning artifact classification and testing detection rules;
it is not an antivirus replacement or proof that a matched binary is malware.

Existing YARA rules from other projects (including
[signature-base](https://github.com/Neo23x0/signature-base)) should be checked
for license, condition syntax, dependencies, false positives and YARA-X
compatibility before use. Do not bulk-import unreviewed rules.

## Safe synthetic lab

1. Create a disposable VM with no inbound production shares and a
   read-only or disposable workspace.
2. Install a **pinned, verified** YARA-X release using its upstream
   installation documentation. Confirm current command syntax/CLI support.
3. Generate two synthetic text fixtures locally: one containing an
   invented test marker and another without it. No malware required.
4. Write an original test rule requiring the marker and constraining the
   file type/context. Test positive and negative fixtures separately.
5. Test with benign variants and document false positives. Never claim
   detection coverage from one toy fixture.
6. Record rule ID, author, revision, engine version, fixture hashes and
   expected output; preserve rules and test results in version control.
7. For genuine incident samples, preserve acquisition, hashes and
   chain-of-custody and perform independent triage rather than trusting
   a single signature result.

## Detection-quality matrix

| Check | Desired result |
| --- | --- |
| Synthetic positive | Expected rule match |
| Synthetic negative | No match |
| Benign lookalike | No false positive or documented exception |
| Unsupported rule feature | Clear compile/compatibility failure |
| Untrusted sample | Never executed by the rule-evaluation process |
| Report | Source hash, rule revision and confidence shown |

YARA matching is pattern recognition; encrypted/packed samples or memory-only
behaviors can evade static signatures. Correlate with
[Volatility](../IncidentResponse/Digital-Forensics/Memory/volatility_cheatsheet.md),
[Velociraptor triage](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md)
and incident timeline evidence.

## Sources

- [YARA-X](https://github.com/VirusTotal/yara-x) (BSD-3-Clause).
- [YARA-X documentation](https://virustotal.github.io/yara-x/).
- [signature-base](https://github.com/Neo23x0/signature-base) (review licensing before copying individual rule files).

**Integration status:** educational workflow and source links only; no binary
downloads, scanning or rules execution.

---

[Reverse Engineering](README.md) · [Main README](../README.md) ·
[Legal terms](../LEGAL.md)
