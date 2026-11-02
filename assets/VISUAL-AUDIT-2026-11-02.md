# Repository Visual Coverage Review — November 2, 2026

_Last reviewed: 2026-11-02 (repository tree inventory, selected content review, diagram placement and automated repository checks)_

[Master README](../README.md) · [Image/Diagram Index](./README.md) · [START HERE](../START_HERE.md)

## Scope and approach

This is a **repository-wide visual-content audit**, **not** a line-by-line accuracy certification of every guide, an exploit verification exercise, or a complete external URL review.

- Inspected the Git tree across all top-level sections and inventoried **302 Markdown files** on the pre-expansion reference branch.
- Cross-checked prior asset usage and selected representative section indexes and operational guides for places where a picture or flow diagram would help explain a trust boundary, evidence lifecycle, system architecture, or assessment process.
- Preserved existing diagrams: hardware interface/electrical measurements, existing PNWC figures, and the previously introduced FIDO2, storage and press-freedom illustrations.
- Added **16 new original static SVG diagrams**, each embedded near the relevant section, with Markdown alt text and a caption describing its conceptual scope.
- Kept an [indexed asset inventory](./README.md) so readers can reach all new visuals without browsing GitHub's Code file list.
- Prefer complete, accurate prose and tested procedures to excessive decorative images. An illustration must not imply a certification, tool compatibility or network deployment that has not been verified.

## Diagrams integrated in this pass

| Section | Diagram | Scope and caveat |
|---|---|---|
| [Cloud](../Cloud/README.md) | [Shared responsibility](./diagrams/cloud-shared-responsibility.svg) | Provider/customer responsibilities are service-dependent |
| [Container Security](../ContainerSecurity/README.md) | [Trust boundaries](./diagrams/container-security-boundaries.svg) | Containers may share a host kernel |
| [Compliance](../Compliance/README.md) | [Controls and evidence](./diagrams/grc-controls-evidence.svg) | Mapping alone does not certify compliance |
| [Data Engineering](../Data-Engineering/Phase2/README.md) | [Pipeline reliability](./diagrams/data-pipeline-reliability.svg) | Schemas, idempotency, observability and recovery |
| [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md) | [Evidence lifecycle](./diagrams/dfir-evidence-custody.svg) | Legal scope, volatility, custody and verification |
| [Honeypots](../IncidentResponse/HoneyPot/readme.md) | [Segmentation and Wazuh](./diagrams/honeypot-segmented-logging.svg) | Decoy is untrusted; restrict production/egress |
| [Wireless IDS](../IncidentResponse/IDS%26IPS/readme.md) | [Alert correlation](./diagrams/wireless-ids-correlation.svg) | Sensor visibility and validation required |
| [SIEM](../IncidentResponse/SIEM/README.md) | [Telemetry to decision](./diagrams/siem-telemetry-correlation.svg) | Correlation is not proof of compromise |
| [Incident Response](../IncidentResponse/README.md) | [Response lifecycle](./diagrams/incident-response-cycle.svg) | Preserve evidence and authorize containment |
| [Mobile](../Mobile/README.md) | [Device/account layers](./diagrams/mobile-security-boundaries.svg) | OS/model/cloud-copy differences |
| [OSINT](../OSINT/README.md) | [Verification workflow](./diagrams/osint-verification-workflow.svg) | Corroboration, harm minimization and provenance |
| [Reverse Engineering](../ReverseEngineering/README.md) | [Safe analysis](./diagrams/reverse-engineering-workflow.svg) | Lab isolation and immutable original |
| [SDR/NanoVNA](../SDR/nanovna/README.md) | [Calibration plane](./diagrams/nanovna-calibration-plane.svg) | Device/cable-specific reference plane |
| [Space Security](../SpaceSecurity/README.md) | [System segments](./diagrams/space-security-segments.svg) | Conceptual; not a mission flight configuration |
| [Wardriving](../Wardriving/README.md) | [Collection lifecycle](./diagrams/wardriving-collection-lifecycle.svg) | Authorized passive collection and privacy |
| [Web App Security](../WebAppSecurity/README.md) | [Assessment lifecycle](./diagrams/webapp-assessment-cycle.svg) | Written scope and independently verified findings |

## Previously integrated figures — preserved

- The master guide, hardware hacking Chapters 1–5 and several foundational guides already have topic-specific illustrations; they were not duplicated.
- Existing FIDO2, encrypted storage, press freedom, AD attack paths, home-lab networking, AI orchestration, repair diagnostics, wireless auditing, penetration-test lifecycle and JWrapper illustrations remain available in [the asset index](./README.md).

## Future visual improvements that require stronger source material

- **Real hardware photos:** for SoloKeys revisions, PhantomDrive board revisions, NanoVNA port/cable setups and field-test gear, use clearly licensed or owner-supplied photos with verified model identification, rather than synthetic pictures presented as authentic.
- **Screenshots:** current OS settings, SIEM dashboards and Wireshark workflows should be captured from a known version of actual software with secrets, personal data, GPS coordinates and client information redacted.
- **Network maps:** user-specific UniFi/Proxmox/honeypot network layouts should be produced only after confirming actual VLANs, device addresses, routes and sensor placement. Example diagrams must not masquerade as a verified environment.
- **Historical diagrams:** review the unplaced [advnacedflows.jpg](./advnacedflows.jpg) before choosing a section or renaming it; its intended topic was not established in this review.
- **Diagram maintenance:** when command sequences, protocols, versions or topology change, revise the source SVG and its explanatory caption together.

## Quality gates

- [x] All newly added SVGs use static local vector markup, no scripts, no externally loaded images/fonts, and descriptive `title`/`desc` tags.
- [x] Illustrations are placed next to the relevant concept and accompanied by explanatory Markdown alt text/captions.
- [x] Relative links used for image assets and cross-section navigation.
- [ ] Manual test on all browsers/screen readers: not performed.
- [ ] Every external documentation URL validated in real time: not performed.
- [ ] All 302 Markdown files manually reviewed line-by-line: not performed.
- [ ] Hands-on hardware, firmware, network and dashboard validation: not performed.

Check the current GitHub Actions status (Markdown lint and link checks) on the related pull request before merge. Do not mark a check passed until its run finishes.

---

[Image and Diagram Index](./README.md) | [Master README](../README.md) | [Legal Notice](../LEGAL.md)
