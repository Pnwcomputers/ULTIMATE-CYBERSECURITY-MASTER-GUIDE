# Unsaflok: Approximately Three Million Hotel Doors (2024)

**Case type:** Coordinated hardware/RFID security disclosure — **not** a confirmed mass intrusion.

**Source review:** November 11, 2026. Original findings published March 21, 2024; current patch adoption rate **not established by this page**.

## Summary & Scope

Security researchers Lennert Wouters, Ian Carroll and collaborators disclosed **Unsaflok**, a chain of weaknesses in dormakaba Saflok RFID room-lock systems. The team estimated exposure at **more than three million doors across over 13,000 properties in 131 countries**. The described exposure involves certain Saflok product lines and management configurations; brand appearance alone cannot prove whether a particular door is updated.

## Technical Root Cause (Non-Operational)

The research connected weaknesses in MIFARE Classic-based cards, manufacturer-specific key handling and the lock's authorization logic. The investigators showed that knowledge from a card associated with a property could undermine separation between room credentials in affected installations. This illustrates why **encrypted storage alone** does not solve weak authorization or key-management design.

This case study intentionally omits credential-writing commands, construction of forged cards and lock-opening sequences. No hotel room or access-control system should be tested without written authorization.

## Disclosure & Response

- Researchers began work in 2022 and reported the findings to dormakaba in September 2022.
- Dormakaba began coordinating property upgrades in November 2023.
- The research site reported approximately **36%** of affected locks upgraded **as of March 2024**. This is a historical figure, **not** a 2026 upgrade estimate.
- Updates may involve lock reprogramming or replacement, keycard reissuance, front-desk management changes and dependent integration upgrades.
- The original researchers stated that they **were not aware of confirmed real-world attacks** using the findings at publication; lack of evidence is not evidence of none.

## Defensive Lessons & Authorized Assessment

| Question | Evidence to Collect | Protection |
|---|---|---|
| Which system/lock/reader versions are deployed? | Model, firmware, reader and card technology, vendor upgrade status | Coordinate vendor-provided remediation across **all** affected doors |
| What is the credential trust model? | Management configuration and credential issuance policy | Per-property/per-room authorization, authenticated credentials and appropriate key management |
| Can patch status be demonstrated? | Vendor deployment record, post-upgrade inventory and read-only tests | Do not infer patch status from the lock's external appearance |
| Are system logs reliable for attribution? | Management audit configuration, clock integrity, access-log limitations | Corroborate with independently collected evidence |
| Are guests adequately protected? | Physical secondary-door protection and operator procedures | Communicate mitigation without promising that an electronic deadbolt alone prevents bypass |

## Primary Sources & Boundaries

- [Unsaflok — Researcher Disclosure, FAQ & Timeline](https://unsaflok.com/) — first-party findings, explicit limits and historical patch percentage.
- [KU Leuven COSIC — Researchers' Announcement](https://www.esat.kuleuven.be/cosic/news/hackers-found-a-way-to-open-any-of-3-million-hotel-keycard-locks-in-seconds/) — institutional source.
- [WIRED — March 21, 2024 Reporting](https://www.wired.com/story/saflok-hotel-lock-unsaflok-hack-technique/) — interview and vendor response.

**Follow-up:** [RFID & NFC Access Security](../../SDR/rfid.md) · [Hardware Threat Modeling](../../HardwareHacking/Chapter1.md) · [All Case Studies](../README.md)
