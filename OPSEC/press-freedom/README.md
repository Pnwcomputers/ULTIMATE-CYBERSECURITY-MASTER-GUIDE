# Press Freedom, Journalist Safety, Source Protection and Digital Security

_Last reviewed: 2026-11-01 (documentation and primary-source review; not a legal opinion or hands-on device audit)_

Part of [OPSEC](../README.md) and the [Ultimate Cybersecurity Master Guide](../../README.md).

> [!IMPORTANT]
> This section supports journalists, press-freedom advocates, whistleblower-support teams and newsrooms in **lawful, preventive protection** of people and information. It is **not legal advice**. Legal privileges, search powers, compelled unlocking, data-preservation orders and retention duties vary greatly by jurisdiction and context. Involve qualified local counsel before high-risk work, border crossings or responding to a demand for access.

## Mission

Protect the human beings first, then confidential sources, records, communications and devices. Security controls should make information harder to expose **before** a dangerous incident, not depend on a risky last-minute action.

## Begin here

| Topic | Focus |
|---|---|
| [Computers, Phones and Network Protection](./device-network-protection.md) | Device hardening, FDE, biometrics, accounts, secure communications, network isolation, backups and travel devices |
| [Data Retention, Minimization and Lawful Disposal](./data-retention-removal.md) | Source-risk classification, retention schedules, encrypted archives, verified deletion, copies and legal holds |
| [Duress, Device Seizure and Emergency Response](./duress-seizure-response.md) | Preventive preparation, panic avoidance, personal safety, escalation, incident preservation, post-seizure recovery |
| [Cryptography: Encrypted Storage](../../Cryptography/encrypted-storage.md) | Storage choices, backups and recovery checks |
| [Cryptography: FIDO2, Passkeys and Security Keys](../../Cryptography/security-keys-passkeys.md) | Phishing-resistant login protection for newsroom and journalist accounts |

## Risk assessment and source confidentiality

Before starting a story or assignment, ask:

1. Whose physical safety, liberty, livelihood or reputation could be affected?
2. Which identities, devices, location data, photos, metadata, cloud accounts, logs and colleagues can connect a source to the reporting?
3. Who could demand, seize, steal, image or remotely access the data? What is their technical and legal power?
4. Can information be **collected less often**, **stored for less time**, **pseudonymized**, or **kept out of the journalist's personal device**?
5. What must be preserved for journalism, legal, evidentiary, contractual or regulatory reasons?
6. Who has authority to approve access, retention, transfer, destruction and emergency response?

Write a story-specific risk register and review it with the editor, source-protection lead or counsel when appropriate. Do not promise a source secrecy or anonymity you cannot actually guarantee.

## Protection layers

- **Human safety:** independent check-ins, trusted emergency contact, travel plan, access to local counsel; avoid risky operations while threatened.
- **Identity and account security:** unique credentials, password manager, hardware-backed FIDO2/passkeys, two independently registered authenticators, hardened recovery.
- **Endpoints:** supported OS versions, patches, full-disk encryption, strong unlock credential, least privilege, locked screens, controlled peripherals.
- **Communications:** vetted end-to-end encryption, independent identity verification, minimal metadata and limited account/device exposure; transport encryption alone is insufficient.
- **Network:** trusted router/AP, current firmware, guest segmentation, encrypted DNS/HTTPS as appropriate, approved VPN when appropriate, avoidance of unknown captive portals.
- **Storage and retention:** small data footprint, encrypted segregation and backups, classification, documented retention and defensible sanitization at the end of authorized retention.
- **Response:** pre-agreed check-ins, legal and editorial escalation, incident recording, credential/session revocation after compromise and careful preservation of necessary evidence.

## What different controls protect

| Control | Helps with | Does **not** reliably prevent |
|---|---|---|
| Full-disk encryption + powered-off device | Offline reading of locked storage | Compromised firmware, coerced disclosure, data already synced or unlocked |
| Hardware FIDO2 security key | Password phishing and many account-takeover methods | Malicious endpoint sessions or weak account-recovery paths |
| End-to-end encrypted communications | Content interception between valid endpoints | Infected endpoints, exposed contact relationships or backups |
| VPN | Some local-network visibility and IP exposure | Endpoint compromise, account tracking, compelled access or guaranteed anonymity |
| Encrypted backup with tested restore | Theft-related data exposure and operational recovery | Bad retention policy, backup key loss or unauthorized decrypted access |
| Minimal retention + approved disposal | Unnecessary data exposure | Existing cloud copies, third-party records, legal duties to preserve |

## A minimal field checklist

- [ ] Risk assessment and editor/legal contact established
- [ ] Strong passcode, automatic lock, OS updates and full-disk encryption confirmed
- [ ] Password manager, FIDO2/passkeys and independent backup authenticator tested
- [ ] Confidential source identities separated from routine personal accounts
- [ ] Approved secure communications and counterpart verification tested
- [ ] Only necessary data stored on travel/field devices
- [ ] Encrypted backups and restoration checked; records of lawful holds reviewed
- [ ] Emergency check-in and missing-device response agreed
- [ ] Device and communications security rechecked after high-risk encounter

## Legal and ethical boundaries

Protecting journalism and sources is an important purpose, but this guide **does not recommend destroying or concealing records in response to a subpoena, seizure, legal hold, preservation obligation or ongoing investigation**. Routine data-minimization and disposal schedules should be established **before** an incident and paused when preservation is required. When a person is threatened, prioritize physical safety and legal advice—not a device trick that may escalate danger.

## Primary sources and assistance

- [Freedom of the Press Foundation — 2026 digital security checklist](https://freedom.press/digisec/blog/journalists-digital-security-checklist/)
- [Freedom of the Press Foundation — threat modeling on behalf of sources](https://freedom.press/digisec/blog/threat-modeling-sources-module/)
- [Committee to Protect Journalists — Safety Kit](https://cpj.org/safety-kit/)
- [CPJ Digital Safety Kit (updated 2026)](https://cpj.org/2019/07/digital-safety-kit-journalists/)
- [Electronic Frontier Foundation — Surveillance Self-Defense](https://ssd.eff.org/)
- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
- [NIST SP 800-88 Revision 2, media sanitization](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
- [Freedom of the Press Foundation — safeguarding sources in a raid](https://freedom.press/digisec/blog/safeguarding-sources-and-sensitive-information-in-the-event-of-a-raid/)
- [Reporters Committee for Freedom of the Press — Reporter's Privilege Compendium](https://www.rcfp.org/introduction-to-the-reporters-privilege-compendium/)

## See also

- [OPSEC fundamentals](../README.md)
- [Tails portable workstation guide](../tails-usb-setup-guide.md)
- [Whonix/Kicksecure](../whonix-kicksecure-usb-guide.md)
- [Encrypted storage and backups](../../Cryptography/encrypted-storage.md)
- [FIDO2 security keys and passkeys](../../Cryptography/security-keys-passkeys.md)

---

[OPSEC Index](../README.md) | [Master Index](../../README.md) | [Legal Notice](../../LEGAL.md)
