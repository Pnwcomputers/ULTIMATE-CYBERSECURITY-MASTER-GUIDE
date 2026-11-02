# Diagram and Image Asset Index

_Last reviewed: 2026-11-01 (repository path and placement review; visual content not re-authenticated against live equipment)_

Return to [the main guide](../README.md) or [the visual reference notes](./imageplacement.md).

This folder stores diagrams as shared assets. Embed them in the **topic guide where they clarify a specific procedure** rather than repeating the same figure across multiple unrelated README pages. Captions should identify a diagram as conceptual when it does not describe a validated PNWC deployment.

## Integrated PNG and SVG diagrams

| Image | Used in | Explanation |
|---|---|---|
| [AD attack paths](./ad_attack_paths.png) | [AD attacks and defenses](../Tradecraft/active-directory.md#kerberos-attacks) | Kerberos and AD risk-path illustration |
| [AI agent architecture](./ai_agent_arch.png) | [AI section](../AI/README.md) | Conceptual file-system-first agent/tool boundaries |
| [Hardware diagnostics](./hardware_diagnostics.png) | [Hardware Testing](../HardwareTesting/README.md) | Reference board-level diagnostic workflow |
| [Network architecture](./network_security_arch.png) | [Homelab](../Homelab/README.md) | Example segmented design, not a verified live topology |
| [RAM versus storage](./ram_vs_storage.png) | [Manjaro test bench](../HardwareTesting/Manjaro_Intel_TestBench.md#5-memory-and-storage-diagnostics) | Introductory CPU/RAM/storage mental model |
| [VM compartmentalization](./vm_compartmentalization.png) | [OPSEC guide](../OPSEC/README.md#principles) | Boundary illustration with important host/guest limitations |
| [Wireless auditing](./wireless_auditing.png) | [Network Audit Playbook](../PlayBooks/NetworkAuditPlayBook.md#section-2-wireless-specific-testing-procedures) | Wireless engagement workflow |
| [Penetration-test lifecycle](./pentest_lifecycle.png) | [Playbooks](../PlayBooks/README.md) | Assessment lifecycle overview |
| [JWrapper abuse case study](./jwrapper_attack.png) | [Incident Response](../IncidentResponse/README.md) | Illustrative remote-access-software abuse path, not proof of infection |
| [FIDO2 / passkey authentication](./fido2-passkey-authentication-flow.svg) | [Hardware keys and passkeys](../Cryptography/security-keys-passkeys.md#what-is-a-security-key) | **New accessible vector figure**, showing registration and sign-in |
| [Encrypted storage boundaries](./encrypted-storage-protection-boundaries.svg) | [Encrypted storage](../Cryptography/encrypted-storage.md#choose-the-right-design) | **New accessible vector figure**, locked versus unlocked data and backup limitations |
| [Journalist source-data lifecycle](./journalist-source-data-lifecycle.svg) | [Press freedom / source protection](../OPSEC/press-freedom/README.md#mission) | **New accessible vector figure**, preservation holds and approved disposition |

## Already embedded in hardware chapters

| Asset | Chapter |
|---|---|
| [Trust boundary](./CollapsingtheTrustBoundary.jpg) | [Hardware Hacking — Chapter 1](../HardwareHacking/Chapter1.md) |
| [UART](./UART.jpg), [SPI](./SPI.jpg), [I²C](./i2c.jpg), [JTAG](./JTAG.jpg), [Shunt setup](./ShuntSetup.jpg) | [Hardware Hacking — Chapter 2](../HardwareHacking/Chapter2.md) |
| [Clock/voltage glitch](./ClockvsVoltage.jpg), [EMFI](./ElectromagneticFaultInjection.jpg), [Laser FI](./LaserFaultInjection.jpg) | [Hardware Hacking — Chapter 3](../HardwareHacking/Chapter3.md) |
| [SPA on RSA](./SPAonRSA.jpg) | [Hardware Hacking — Chapter 4](../HardwareHacking/Chapter4.md) |
| [CPA correlation](./CPACorrelationProcess.jpg) | [Hardware Hacking — Chapter 5](../HardwareHacking/Chapter5.md) |
| [Master guide banner](./cybersecurityguide.png) | [Master README](../README.md) and [START HERE](../START_HERE.md) |

## Additional asset awaiting placement

- [advnacedflows.jpg](./advnacedflows.jpg) — a large image with an ambiguous filename. **Not embedded automatically** because its intended subject has not been visually verified; avoid mismatched or misleading placement. Review the image and rename or document its subject before assigning it.

## Image guidelines

1. Use a **relative path from the embedding Markdown file**; for a root-level page use `./assets/image.png`, for a one-level-deep section use `../assets/image.png`, and for a two-level-deep section use `../../assets/image.svg`.
2. Provide meaningful Markdown alt text and a short caption, including whether the image is *conceptual* or based on verified deployment/test data.
3. Avoid claiming an illustration proves encryption security, exploitability, network isolation, or real-world device behavior.
4. Keep SVG assets static: no script, animation, external fonts or third-party image dependencies. Preserve the embedded `title` and `desc` for accessibility.
5. When an image is superseded, update all backlinks and run repository lint/link checks. Maintain this table.

---

[Master README](../README.md) | [Role Navigation](../START_HERE.md) | [Visual reference notes](./imageplacement.md)
