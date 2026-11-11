# Tesla Model S Key-Fob Cryptanalysis (2018)

**Case type:** Demonstrated authorized security research, not evidence of a specific fleet-wide criminal campaign.

## Research & Root Cause

In September 2018, KU Leuven/imec researchers published a demonstration against an earlier Tesla Model S passive keyless entry/start system. The work exposed weaknesses in the proprietary **DST40-based** key-fob authentication design. Researchers reported demonstrating the attack on two Model S vehicles and coordinating disclosure with Tesla in August 2017.

An important technical distinction: subsequent Tesla key-fob revisions used **DST80**; researchers later analyzed those systems separately. A 2018 demonstration does **not** prove that current Tesla vehicles or all DST80 deployments share the exact issue.

## Defensive Implications

| Risk | Architecture & Fleet Review |
|---|---|
| Proprietary RF cryptography | Do not equate secrecy of an algorithm with strong security; independently evaluate protocol and key length |
| Wireless credential exposure | Inventory fob type, firmware and supported passive-entry protections; keep keys physically secured |
| Vehicle-wide remediation | Validate supported updates and features for the **specific** vehicle and model year |
| User safety | Researchers advised disabling passive entry and using **PIN to Drive** where supported in relevant versions; check current Tesla instructions before recommending settings |

The case does not include wireless capture, cloning, replay, or vehicle-access instructions.

## Primary Sources

- [imec/KU Leuven — September 10, 2018 Research Announcement](https://www.imec-int.com/en/articles/security-flaws-in-passive-keyless-entry-and-start-systems).
- [KU Leuven COSIC — DST80 Follow-up & Voltage-Fault Injection](https://www.esat.kuleuven.be/cosic/blog/dismantling-dst80-based-immobiliser-systems/).

[RF/SDR Index](../../SDR/README.md) · [Hardware Threat Modeling](../../HardwareHacking/Chapter1.md) · [All Cases](../README.md)
