# Public/Private Separation & Publication Checklist

[Cyberdeck Home](../README.md) · [Status Matrix](HARDWARE_AND_STATUS.md)

## Release Intent

This directory is a **public reference companion**. The original `PNWC-Cyberdeck` is a separate, private and proprietary prototype. Do **not** change that repository's visibility or mirror its commit history to publish a community edition. This public version was drafted as new summary documentation, fictional templates and an offline-only helper—not a mass copy of proprietary files.

## Exclusion Rules

| Never Export Without Specific Review | Safe Public Alternative |
| --- | --- |
| Credentials, secrets, OAuth material, service tokens, certificates or private key material | Placeholder variable names without live values |
| Client evidence, signed scopes, scans, customer identifiers or internal reports | Synthetic example artifacts with fictional metadata |
| Real router/VPN configuration, SSH endpoints, IP mappings, hostnames, access paths | Generic zone diagram and a policy checklist |
| Private application source, proprietary automation logic or commercial legal packet | Concept-level architecture and non-operational example records |
| Internal operational schedules, inventory serials and confidential device registrations | Hardware categories and explicitly unverified role descriptions |
| Photos or logs containing GPS, EXIF, private SSIDs or MAC addresses | Redrawn generic diagrams, no embedded site metadata |

## Pre-Publication Checklist

| Gate | Required Verification |
| --- | --- |
| 1. Source separation | Prepare a **fresh public tree**; never publish the private repo's history |
| 2. Secret check | Review source and history for credentials, API keys, auth headers, email, addresses and embedded configuration |
| 3. Privacy check | Inspect fictional examples, documents, image metadata and generated sample output |
| 4. Third-party attribution | Link upstream documentation; don't copy proprietary firmware, payloads, logos or third-party docs |
| 5. Licensing decision | Explicitly choose a public license if use/redistribution is intended; private `LICENSE` does not become open-source by copying |
| 6. Technical review | Validate relative links, run offline unit tests, check status claims and hardware qualifications |
| 7. Security review | No network-facing administrative interface, unsafe default collector or auto-execution in public samples |
| 8. Publication | Link the final **verified** public URL from the Guide after the files exist; never link to an inaccessible private repo |

## Standalone GitHub Repository Handoff

If you later create a separate public repository, a suggested name is `PNWC-Cyberdeck-Public`. Initialize it as an **empty repository** and copy only the vetted files in this `Cyberdeck/` directory—not the private `.git` directory, its branch history or proprietary app source. Review the standalone folder links (`../README.md` and `../../...` links refer to the Guide and should become explicit GitHub URLs). Then replace Guide links with the actual public repository URL.

No standalone repository creation or publication is implied by the existence of this directory. A public GitHub page does not by itself grant an open-source license. Keep project permissions and third-party notices explicit.

[GitHub Guide Home](../../README.md) · [Evidence Handling](EVIDENCE_AND_PRIVACY.md).
