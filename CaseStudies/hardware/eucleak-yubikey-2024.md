# EUCLEAK: ECDSA Side-Channel Exposure in Infineon Secure Elements (2024)

**Case type:** Published physical side-channel vulnerability with a coordinated vendor advisory. **CVE:** CVE-2024-45678. **Disclosure:** September 3, 2024.

## What Was Demonstrated

NinjaLab researchers reported an electromagnetic side-channel weakness in an Infineon cryptographic library's **non-constant-time modular inversion** during ECDSA operations. They demonstrated recovery of a signing secret from a YubiKey 5Ci under controlled conditions. Because a cryptographic library may be reused across hardware products, its implementation can undermine security even when key storage is designed to resist direct extraction.

Yubico's YSA-2024-03 advisory lists YubiKey 5/Security Key Series firmware **before 5.7.0** and YubiHSM 2 firmware **before 2.4.0**. These are historical affected ranges; verify exact device model and firmware against the vendor's current notice. Firmware on some hardware tokens is not upgradeable in place; plan authorized replacement/migration.

## Threat Model & Defensive Response

| Prerequisite or Concern | Interpretation |
|---|---|
| Attacker needs physical possession | This is **not** a remote Internet compromise of every token |
| Specialist EM equipment & knowledge | High skill/resource barrier; the original paper and advisory should define practical bounds |
| ECDSA signing operation leakage | Protect physical custody and verify cryptographic primitive/firmware/model |
| Credential replacement | Consider vendor-recommended migration or replacement if risk warrants; revoke and re-enroll credentials as part of controlled response |
| Certification assumptions | A certification result is not a guarantee that new cryptanalytic/side-channel research cannot identify issues |

**Do not disable phishing-resistant MFA solely because of this research.** NinjaLab explicitly emphasizes that using a security key remains safer than not using one for most account-protection use cases.

No fault-injection or EM sampling reproduction commands are included here; demonstrations belong on owned lab devices with authorized procedures.

## Sources

- [NinjaLab — EUCLEAK Primary Research](https://ninjalab.io/eucleak/).
- [Yubico — Security Advisory YSA-2024-03](https://www.yubico.com/support/security-advisories/ysa-2024-03/).
- [CVE-2024-45678 Record](https://www.cve.org/CVERecord?id=CVE-2024-45678).

[Hardware Side Channels](../../HardwareHacking/Chapter4.md) · [Security Keys & Passkeys](../../Cryptography/security-keys-passkeys.md) · [All Cases](../README.md)
