# Duress, Detention, Device Seizure and Emergency Digital-Safety Plan

_Last reviewed: 2026-11-01 (journalist safety and platform guidance reviewed; not legal advice)_

**Prerequisites:** [Press Freedom and Source Security](./README.md) · [Device and Network Security](./device-network-protection.md) · [Data Retention](./data-retention-removal.md)

> [!WARNING]
> **Physical safety comes first.** A confrontation is not the time to improvise technical countermeasures. This document does not recommend threatening behavior, resistance, covert evidence destruction, wiping on demand, or attempts to circumvent a lawful preservation obligation. Follow qualified local legal advice: the rules on search, compulsory unlocking, source privilege and border crossings are jurisdiction-specific.

## Before an assignment: design for safe failure

See the [journalist and source-data lifecycle diagram](../../assets/journalist-source-data-lifecycle.svg) for the distinction between **ordinary policy-approved disposal** and **emergency safety/evidence-preservation response**.

Set up protective defaults **well before** an unexpected confrontation.

1. **Minimize sensitive local data.** Carry only the documents essential for the assignment and use a separate, fully encrypted field device when possible.
2. **Use a long passcode and FDE.** Avoid relying on biometric-only unlocking; verify device behavior **before** travel or assignment.
3. **Set a check-in plan.** Give a trusted editor/contact the itinerary, regular contact window and escalation contacts without sharing source identities unnecessarily.
4. **Arrange legal support.** Identify a qualified lawyer and emergency phone number relevant to the reporting jurisdiction; understand how to ask for counsel.
5. **Protect accounts.** Use FIDO2 authenticators, device inventories, strong recovery, signed-in-session tracking and independent backup access. Keep backup authenticator away from the field device.
6. **Keep recoverable encrypted backups.** Use an approved offsite recovery plan; confirm you can restore without the field device.
7. **Plan a lawful response to seizure or loss.** Define who evaluates legal notices, checks preservation obligations, informs affected people and revokes compromised access **when lawful and appropriate**.
8. **Test the plan**, including a communications outage and unavailable primary contact. Do not rehearse dangerous encounters.

## Ordinary security controls versus misleading “panic” claims

| Control | Helpful purpose | Boundary |
|---|---|---|
| Phone power-off / locked-device state | Reduce casual access to local decrypted data | No guarantee against coercion, device vulnerabilities or access to cloud-held copies |
| Android **Lockdown** option | Temporarily disables biometric unlocking/lock-screen features until next unlock, on supported devices | Not an emergency wipe, not available identically on every phone |
| iPhone temporary Face ID disable | Requires passcode for the next unlock on supported iPhones | Different from Apple's anti-spyware Lockdown Mode |
| Apple **Lockdown Mode** | Reduces attack surface for rare, highly sophisticated spyware threats | Not a data shredder, emergency seizure mode or substitute for passcode/FDE |
| Preplanned low-retention field device | Reduces sensitive data present at seizure | Remote backups and external records may remain |
| Duress PIN / secret-wipe claims | Some niche projects advertise them | **Do not rely on unverified panic triggers or hidden deletion.** They can fail, lose lawful records, falsely signal cooperation, or heighten physical and legal risk |

### Verified platform references

- [Google Android Lockdown](https://support.google.com/android/answer/9075927?hl=en) — use the device's current UI, since manufacturer menus differ.
- [Apple temporary Face ID disable](https://support.apple.com/guide/iphone/set-up-face-id-iph6d162927a/ios) — separate from Apple's Lockdown Mode.
- [Apple Lockdown Mode](https://support.apple.com/en-us/105120) — targeted-spyware protection on compatible Apple systems.

## Remote wiping, shutdown triggers, and retention limits

A newsroom may evaluate **remote-wipe management** for a genuinely lost or stolen device as part of a previously approved, legally compliant incident-response policy. Its use must be considered against the risks to people, evidence and preservation duties. Remote wiping is **not reliable after a seizure**: a device may be isolated from networks, and wiping during a legal process may create additional hazards.

For a safety-oriented automatic response, consider **lock or shutdown-only** behavior on supported laptops rather than an irreversible wiping trigger; test it in a controlled setting so accidental disconnections do not cause data loss. A device that powers off with strong full-disk encryption still requires a secure backup and may remain vulnerable to forensic, legal or physical coercion.

The [Freedom of the Press Foundation's guide on raids](https://freedom.press/digisec/blog/safeguarding-sources-and-sensitive-information-in-the-event-of-a-raid/) explains the limits of remote wiping, pre-incident minimization and safer encryption practices. Seek legal advice before configuring any destructive response, and do not rely on a panic mechanism to protect a source during confrontation.

## During detention, threat or seizure

1. **Prioritize your personal safety and de-escalation.** Do not physically resist or put anyone at risk to protect a phone or laptop.
2. **Know and seek legal counsel** as applicable, especially before making decisions about access or disclosures. Do not rely on generalized internet claims about constitutional protections or journalist privileges.
3. **Do not trigger emergency deletion or remotely destroy records** in response to a demand; known holds, subpoenas and investigations can create preservation obligations. An emergency wipe may also create danger.
4. **Observe and remember** the time, agencies or people involved, devices taken, apparent condition, instructions received, and witnesses **when it is safe and lawful to do so**.
5. **Activate the prearranged human check-in/escalation plan** when safe; do not expose sources or contacts through insecure communications.
6. If physically threatened, seek emergency help through locally appropriate services as soon as you safely can.

## After release, device return or suspected compromise

- **Get to safety first.** Notify your editor, newsroom security lead and lawyer; document what happened while memories are fresh.
- **Treat accessed, seized or modified devices as potentially compromised.** Preserve them for professional examination when evidence or legal holds require; avoid blindly reconnecting the device to sensitive work.
- **Protect accounts from a different trusted device**, as coordinated with counsel and the incident lead: review sign-in sessions, revoke compromised tokens, replace exposed credentials, update authenticator enrollments and check recovery options. Do not disrupt material under a preservation hold.
- **Assess source impact**, including copies held by cloud providers, telecoms, colleagues, recipients and backup services. Contact at-risk sources through an independently vetted safe channel and plan their protection.
- **Record chain of custody, legal notices and actions taken.** Preserve originals when required; use clean replacement devices and documented restoration.
- **Review the risk model.** Determine whether additional spyware triage, travel policy, device segmentation or source-protection training is necessary.

## Incident response record template

| Field | Fill in |
|---|---|
| Incident ID and start/end times | |
| Person safe? Immediate help needed? | |
| Trusted contacts / lawyer notified | |
| Device type, serial, OS, last known secure state | |
| Last known custody and access | |
| Communications or account exposure suspected | |
| Legal process or hold relevant? | |
| Evidence preserved and chain of custody | |
| Post-incident containment authorized by | |
| Sources potentially affected (stored in restricted annex) | |
| Follow-up and support resources | |

Do not store source identities or private legal advice in a broadly accessible incident ticket.

## Source support and professional help

- [FPF: Safeguarding sources and sensitive information in the event of a raid](https://freedom.press/digisec/blog/safeguarding-sources-and-sensitive-information-in-the-event-of-a-raid/)
- [CPJ Safety Kit](https://cpj.org/safety-kit/) — press safety resources and emergency assistance.
- [CPJ Digital Safety Kit](https://cpj.org/2019/07/digital-safety-kit-journalists/) — device, account, travel and confiscation guidance.
- [Freedom of the Press Foundation 2026 checklist](https://freedom.press/digisec/blog/journalists-digital-security-checklist/)
- [Freedom of the Press Foundation source threat modeling](https://freedom.press/digisec/blog/threat-modeling-sources-module/)
- [Access Now Digital Security Helpline](https://www.accessnow.org/help/) — assistance for at-risk civil society and journalists.
- [EFF Surveillance Self-Defense](https://ssd.eff.org/) — practical protective guides.

## See also

- [Press Freedom Index](./README.md)
- [Device and Network Security](./device-network-protection.md)
- [Retention, Deletion and Legal Holds](./data-retention-removal.md)
- [FIDO2 Security Keys](../../Cryptography/security-keys-passkeys.md)
- [Encrypted Storage](../../Cryptography/encrypted-storage.md)

---

[Press Freedom Index](./README.md) | [OPSEC Index](../README.md) | [Master Index](../../README.md)
