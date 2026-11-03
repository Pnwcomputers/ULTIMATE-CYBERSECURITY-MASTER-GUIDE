# Software Supply-Chain Assessment and SBOM Workflow

_Last reviewed: 2026-11-02 (upstream reference review; no artifacts scanned)_

**Prerequisites:** [Container security](containers.md) · [Docker diagnostics](docker-cli-operations-reference.md) · [Script index](../Scripts/README.md).

## Curated upstream projects

| Source | Assessment role |
| --- | --- |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | Repository security controls and supply-chain practices |
| [Syft](https://github.com/anchore/syft) | Software Bill of Materials (SBOM) for owned filesystem/image |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Match supported dependency inventories to OSV advisories |
| [Trivy](https://github.com/aquasecurity/trivy) | Image/source vulnerability, misconfiguration and secrets checks |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Find potential accidental secrets in a permitted repository |
| [Sigstore Cosign](https://github.com/sigstore/cosign) | Verify signed build artifacts and relevant identity/provenance metadata |

These checks complement one another. A Scorecard result is not a security certificate; an SBOM is not proof of software integrity; a matching CVE may not be exploitable in the deployed environment.

## Inspect-first engagement workflow

1. Define source, repo commit, image digest, registry, scope, owner and asset criticality. Confirm permitted scanning.
2. Pin and record tool releases, vulnerability database timestamps, data-handling policies and any required API credentials.
3. Assess repository security hygiene with Scorecard using documented read-only privileges.
4. Generate an SBOM from a **pinned, approved** artifact using Syft; prefer standard CycloneDX or SPDX format and hash the result.
5. Evaluate dependency issues using OSV-Scanner and/or Trivy with supported source formats; document advisory IDs, affected versions, false positives and available mitigations.
6. Run secrets detection against only authorized repository history. Store candidate secrets confidentially; do not paste into a public issue. Coordinate rotation of confirmed exposed credentials.
7. Verify build provenance and signatures with Cosign when applicable; compare signer identity and attestation policy to expected release origin.
8. Deduplicate, risk-rank, assign remediation and retest through [client findings](../PlayBooks/assessment-findings-lifecycle.md).

## Safe read-only local version queries

~~~bash
syft version
osv-scanner --version
trivy --version
gitleaks version
cosign version
~~~

These fail normally if tools are not installed. No packages or CI workflows were added by this guide. Review current upstream installation steps; do not execute downloaded shell scripts blindly.

## Controls and deliverables

Produce a source/digest inventory, SBOM hash and format, vulnerability status, verified secret exposure status (never the secret value), signing policy outcomes, remediation owner and retest date. Recheck lockfile and build metadata; SBOMs and advisories can be incomplete.

## Sources

[Syft](https://github.com/anchore/syft) · [OSV-Scanner](https://github.com/google/osv-scanner) · [OpenSSF Scorecard](https://github.com/ossf/scorecard) · [Trivy](https://github.com/aquasecurity/trivy) · [Gitleaks](https://github.com/gitleaks/gitleaks) · [Cosign](https://github.com/sigstore/cosign). Verify license terms before copying code: OpenSSF, Syft, OSV-Scanner, Trivy and Cosign are Apache-2.0 projects; Gitleaks uses MIT.

---

[Container index](README.md) · [Main guide](../README.md) · [Legal terms](../LEGAL.md)
