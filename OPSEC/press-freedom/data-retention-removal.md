# Press and Source Data Retention, Minimization, Backups and Lawful Disposal

_Last reviewed: 2026-11-01 (standards review; apply local legal/editorial policy)_

**Prerequisites:** [Press Freedom and Source Security](./README.md) · [Encrypted Storage](../../Cryptography/encrypted-storage.md)

## Principle: protect fewer records, for a defensible period

Journalists and newsrooms should design source-data handling **before collection**. Keeping only necessary information for an appropriately documented period reduces harm from theft, compelled exposure, mistaken sharing and account compromise. Retention periods must reflect legitimate journalism, litigation, statutory, contractual, editorial and source-safety duties.

> [!CAUTION]
> **Do not delete, alter, remotely wipe or conceal records to frustrate a known legal hold, subpoena, court order, preservation request or investigation.** If a legal request or credible preservation duty exists or is reasonably anticipated, suspend routine disposal of relevant material, preserve relevant records and consult qualified counsel. This document is not a guide to destroying evidence under pressure.

## Data inventory

For each collection, assign:

| Field | Example |
|---|---|
| Collection ID | STORY-2026-001 |
| Purpose | Verify a reported allegation |
| Data classes | Source contact, interview recording, document, metadata |
| Risk and sensitivity | Confidential source — high impact if identified |
| Authorized owner | Assigned journalist and editor |
| Storage locations | Encrypted laptop, approved archive, encrypted offsite backup |
| Copies/derivatives | Phone, transcript, thumbnails, auto-sync, messaging account |
| Retention basis | Editorial policy + counsel-approved exceptions |
| Scheduled review | Review on closure or named date |
| Hold status | None / preservation hold (reviewed by counsel) |
| Disposal authority | Named role + second-person approval for sensitive material |

Avoid real source identities, passcodes, or document contents in an unprotected inventory.

## Retention decision workflow

1. **Collect minimally:** ask whether a sensitive identifier or original file is needed.
2. **Classify:** categorize source risk, publication/evidentiary importance, and legal obligations.
3. **Separate:** place identities, unredacted documents and public-ready working copies in different access-controlled locations when sensible.
4. **Encrypt:** use vetted at-rest encryption and access-controlled backup. Protect keys and recovery information independently.
5. **Limit copies:** check mobile camera rolls, transcripts, autosaves, editors, temporary exports, browser downloads, collaborative tools and cloud sync.
6. **Set review dates:** use a written retention schedule, not an ad hoc deletion triggered by an encounter.
7. **Check for legal holds:** if applicable, block disposal and preserve chain-of-custody information.
8. **Approve disposition:** document who authorized disposal and what approved standard/method applies to each medium.
9. **Verify:** confirm scope and outcome, including known backup/replica lifecycles; document residual copies that cannot immediately be removed.

> [!NOTE]
> “Deleted” in an application may only mean hidden, placed in trash, or scheduled for later purge. SSD wear leveling, snapshots, caches, cloud version history, phone backups, recipients and service-provider logs can retain material after local deletion.

## Media sanitization and what it can/cannot guarantee

Refer to **[NIST SP 800-88 Revision 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)** (September 2025), which supersedes Revision 1 and emphasizes an organizational media-sanitization program, suitable methods, evidence and validation.

- **Clear:** logical techniques appropriate for a lower-risk reuse scenario where supported by the standard and device type.
- **Purge:** stronger techniques (including properly designed cryptographic erase where appropriate) that depend on media and implementation assurance.
- **Destroy:** physical destruction for approved high-risk disposal when reuse and recovery are not desired.
- **Cryptographic erase:** can be effective if **all relevant data** was correctly encrypted, keys are fully controlled and destroyed as specified, and no alternate keys/copies remain. It is **not simply deleting a passphrase file**.
- **Verification/validation:** check successful operation and that the selected method fits the medium, architecture and risk; record outcome.

For SSDs, flash drives, encrypted USB hardware and modern phones, **traditional file overwrite scripts are not a reliable assurance of erasure**. Use manufacturer-supported, standards-conformant sanitization processes as part of a documented policy. A factory reset is not by itself proof that every backup or cloud copy has gone away.

## Storage lifecycle

| Phase | Protection |
|---|---|
| Intake | Inspect metadata and malware risk; classify; use approved encrypted transport |
| Active work | Least privilege; log custody; restrict sharing and unapproved sync |
| Publish/archive | Separate source-identifying originals from redacted publication copies |
| Preservation hold | Lock retention, audit access, protect originals and record hold ownership |
| End-of-retention | Obtain approval and use a media-appropriate sanitized-disposition workflow |
| Post-disposal | Record date, scope, authority, method and validation; track immutable/remote copy expiration where applicable |

## Safe example: documented local assessment, not a wipe

Use **read-only discovery** to determine which disk or encrypted volume is present. Never run a sanitization command against a drive until ownership, serial, retention requirements, backups and authority are verified.

~~~bash
lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE,FSTYPE,MOUNTPOINTS
~~~

The command inventories Linux block devices; it **does not** delete files or establish a right to dispose of records.

## Suggested newsroom retention policy skeleton

- **Policy owner:** editor + security lead + counsel.
- **Covered categories:** intake tips, source identity records, draft interviews, original evidence, public outputs, communications metadata, routine business records.
- **Period:** fill from the organization's documented legal and editorial requirements, not this guide.
- **Access:** defined roles, audit logs, separation for high-risk records.
- **Copies:** map all devices, service backups, collaborative tools and remote archives.
- **Hold process:** named point of contact and automatic suspension of affected disposal.
- **Disposition:** approved method by medium, documented review and validation.
- **Exceptions:** safety needs, court/regulatory requirements and protected public-interest records.
- **Review cadence:** at story start, publication, editorial closure, platform changes and incident response.

## See also

- [Journalist device and network protection](./device-network-protection.md)
- [Duress and seizure response](./duress-seizure-response.md)
- [Encrypted storage and backups](../../Cryptography/encrypted-storage.md)
- [NIST SP 800-88 Revision 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final)
- [Freedom of the Press Foundation — source risk](https://freedom.press/digisec/blog/threat-modeling-sources-module/)
- [FPF: Safeguarding sources and sensitive material in the event of a raid](https://freedom.press/digisec/blog/safeguarding-sources-and-sensitive-information-in-the-event-of-a-raid/)
- [CPJ Digital Safety Kit](https://cpj.org/2019/07/digital-safety-kit-journalists/)

---

[Press Freedom Index](./README.md) | [OPSEC Index](../README.md) | [Master Index](../../README.md)
