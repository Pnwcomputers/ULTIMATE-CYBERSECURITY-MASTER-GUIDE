# Cybersecurity Case Studies

Documented security research and incidents, separated from operational attack tutorials. Each entry records original publication, affected product or sector, root cause, demonstrated scope, limitations, vendor response, defensive lessons and primary sources. These are **historical reports, not proof of current exploitability**; check vendor advisories and the actual installed firmware before making a present-day claim.

## Attack Case Studies (Historical References)

Historical incident and disclosure references from the main repository index. These links point to external background sources; they are separate from the detailed hardware research entries below.

| Incident | Type |
|---|---|
| [Stuxnet](https://en.wikipedia.org/wiki/Stuxnet) | Nation-state cyberweapon - Iranian nuclear facilities |
| [WannaCry](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware) | Global ransomware outbreak |
| [EternalBlue / NSA Leak](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) | NSA exploit leaked by Shadow Brokers |
| [SolarWinds](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) | Software supply chain compromise |
| [Carbanak](https://cloud.google.com/blog/topics/threat-intelligence/behind-the-carbanak-backdoor) | APT banking theft campaign |
| [NotPetya](https://www.wired.com/story/notpetya-cyberattack-ukraine-russia-code-crashed-the-world/) | Destructive malware disguised as ransomware |
| [Edward Snowden / NSA](https://www.theguardian.com/world/edward-snowden) | Mass surveillance program revelations |

## Hardware, RFID & Embedded Security

| Case Study | Published | Primary Failure | Related Guides |
|---|---|---|---|
| [Unsaflok: Three Million Hotel-Lock Exposure](hardware/unsaflok-3m-hotel-locks.md) | March 2024 | RFID keycard and lock authorization weaknesses | [RFID & NFC](../SDR/rfid.md), [Hardware Hacking](../HardwareHacking/README.md) |
| [Onity Hotel-Lock Research](hardware/onity-locks-2012.md) | 2012 | Physical maintenance-port trust boundary | [Hardware Threat Modeling](../HardwareHacking/Chapter1.md) |
| [Tesla Model S Key-Fob Cloning Research](hardware/tesla-model-s-key-fob-2018.md) | September 2018 | Weak proprietary RF immobilizer authentication | [SDR Security](../SDR/README.md) |
| [EUCLEAK: YubiKey/Infineon Side Channel](hardware/eucleak-yubikey-2024.md) | September 2024 | Non-constant-time ECDSA processing | [Side Channels](../HardwareHacking/Chapter4.md), [Security Keys](../Cryptography/security-keys-passkeys.md) |

The term **“3M hack”** is used here to mean the **approximately three million Saflok doors** reported in Unsaflok research, **not a confirmed incident involving 3M Company**. If a different 3M incident was intended, that needs a separate verified case study.

## Case Study Review Checklist

1. Distinguish **disclosed research** from confirmed criminal exploitation; do not imply the latter unless evidence exists.
2. Record which exact devices, deployments, firmware and date were covered by the original research; avoid universal claims.
3. Separate lab reproduction from real-world incident statistics.
4. Attribute dates and versions to the original source. An old patch-deployment percentage is **not** a current compliance rate.
5. Link to related defensive and threat-modeling guides; never publish unauthorized entry techniques, live access credentials or card-cloning recipes.

[Hardware Hacking Index](../HardwareHacking/README.md) · [Main Index](../README.md)
