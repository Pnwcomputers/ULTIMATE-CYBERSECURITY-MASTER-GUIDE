# Security Project Source Register and Integration Coverage

_Last reviewed: 2026-11-02 (source repository review; external tools not deployed)_

This is a provenance and maintenance register for the **newly curated GitHub
projects** woven into the Ultimate Cybersecurity Master Guide. The referenced
source is not necessarily licensed for bulk reproduction; use links, original
instructions and appropriate attribution instead of copying upstream files
without checking their license. “Integrated” here means **documented and
cross-linked**, NOT installed, synchronized or production tested.

| Upstream source | PNWC integration | License/reuse note |
| --- | --- | --- |
| [OWASP/WSTG]
| [Astrosp/Awesome-OSINT-List](https://github.com/Astrosp/Awesome-OSINT-List) | [Curated OSINT reference and evidence-first workflows](../OSINT/awesome-osint-list-curated.md) | GPL-3.0 at repository root; no bulk mirroring of upstream content or provider datasets |
(https://github.com/OWASP/wstg) | [Web testing and mapping](../WebAppSecurity/owasp-assessment-and-nuclei.md) | CC BY-SA 4.0 |
| [OWASP/ASVS](https://github.com/OWASP/ASVS) | [Versioned security requirements](../WebAppSecurity/owasp-assessment-and-nuclei.md) | CC BY-SA 4.0; pin 5.0.0 IDs when using that version |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | [Template selection and verification](../WebAppSecurity/owasp-assessment-and-nuclei.md) | MIT at repository level; review individual files |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | [Purple Team test workflow](../PlayBooks/purple-team-detection-validation.md) | MIT |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) and [Elastic rules](https://github.com/elastic/detection-rules) | [Detection content validation](../IncidentResponse/SIEM/detection-content-validation.md) | Review repository and rule-level terms |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | [Endpoint evidence triage](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) | Check exact code/artifact license |
| [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) | [Artifact collection mapping](../IncidentResponse/Digital-Forensics/velociraptor-artifact-triage.md) | Apache-2.0 |
| [CISA ScubaGear](https://github.com/cisagov/ScubaGear) | [M365 security baselines](../Cloud/m365-scuba-assessment.md) | CC0-1.0 |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | [Findings lifecycle](../PlayBooks/assessment-findings-lifecycle.md) | BSD-3-Clause |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | [Supply-chain](../ContainerSecurity/software-supply-chain-assessment.md) | Apache-2.0 |
| [Syft](https://github.com/anchore/syft) and [OSV-Scanner](https://github.com/google/osv-scanner) | [SBOM and dependency vulnerability checks](../ContainerSecurity/software-supply-chain-assessment.md) | Apache-2.0 |
| [Trivy](https://github.com/aquasecurity/trivy) and [Cosign](https://github.com/sigstore/cosign) | [Scan/signature verification workflow](../ContainerSecurity/software-supply-chain-assessment.md) | Apache-2.0 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | [Secrets audit](../ContainerSecurity/software-supply-chain-assessment.md) | MIT |
| [Bellingcat Toolkit](https://github.com/bellingcat/toolkit) | [OSINT evidence verification](../OSINT/bellingcat-source-verification.md) | Review file license and provider terms |
| [Mobile Verification Toolkit](https://github.com/mvt-project/mvt) | [Mobile forensic triage](../Mobile/mvt-forensic-triage.md) | Review source license per file |
| [YARA-X](https://github.com/VirusTotal/yara-x) | [Malware detection lab](../ReverseEngineering/yara-x-rule-lab.md) | BSD-3-Clause |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | [AI agent evals](../AI/llm-security-evaluation-promptfoo.md) | MIT |
| [rtl_433](https://github.com/merbanan/rtl_433) | [Passive IoT telemetry](../SDR/rtl433-passive-telemetry-lab.md) | GPL-2.0 |
| [Falco rules](https://github.com/falcosecurity/rules) and [osquery defense kit](https://github.com/chainguard-dev/osquery-defense-kit) | [Additional detection content](../IncidentResponse/SIEM/detection-content-validation.md) | Apache-2.0 |

## What is and is not delivered

- **Delivered:** original, focused PNWC instructions; use-case decisions;
  safety limits; local navigation; outbound citations and source/license notes.
- **Not delivered:** upstream code mirroring, installation, cloud or Microsoft
  tenant connection, customer scans, automatic rule deployment, scanner
  configurations, CI integrations or a production assessment service.

## Ongoing update protocol

1. Review the upstream **release/tag and documentation** before changing
   procedural commands. Do not automatically assume the default branch
   represents a released stable version.
2. Confirm project ownership, archived status, license and safe usage.
3. Pin source URLs to a commit or release for imported rules, test cases,
   YAML templates, parsers and configuration—not just the moving main branch.
4. Re-run local Markdown link and duplicated-section checks, then review
   runtime examples on isolated fixtures before marking “tested.”
5. Record which vendor instructions are *references* and which PNWC workflows
   have **actually been deployed, reviewed and accepted** in a lab.
6. For a source that becomes stale or breaks, retain historical context
   and replace its recommendation with a maintained alternative after review.

## Main navigation

[Source-backed client workflow](../PlayBooks/assessment-service-integration-map.md) ·
[Repository style guide](../STYLE_GUIDE.md) ·
[Technical docs index](README.md) · [Main guide](../README.md).

---

[Documentation](README.md) · [Main README](../README.md) ·
[Legal notice](../LEGAL.md)
