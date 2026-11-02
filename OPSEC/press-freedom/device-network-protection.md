# Journalist Device, Mobile, Account and Network Protection

_Last reviewed: 2026-11-01 (documentation review; verify UI against actual OS release)_

**Prerequisites:** [Press Freedom and Source Security](./README.md) · [Encrypted Drives](../../Cryptography/encrypted-storage.md) · [Security Keys](../../Cryptography/security-keys-passkeys.md)

## Why endpoints matter

A well-encrypted message is still exposed to someone controlling either endpoint. A reporter's laptop or phone may disclose source identities through contacts, message previews, app backups, location metadata, synchronized photo libraries, browser histories and Wi-Fi association records. Assess **accounts and backups**, not just the phone.

## Laptop and desktop protection

### Windows

- Use a supported, patched Windows edition and enable the appropriate **BitLocker / device encryption** configuration; verify the status and securely store a recovery key separate from the laptop.
- Use an individually assigned standard user, unique admin credentials, quick automatic screen lock, secure boot where supported and approved endpoint protection.
- Review OneDrive, browser sync, cloud file histories, clipboard/screenshot integrations, and external-drive handling. Do not store source records in personal sync folders by default.
- Confirm full shutdown vs sleep behavior for sensitive travel; a sleeping or unlocked machine can retain secrets in accessible memory.

### macOS

- Enable **FileVault**, maintain a strong login password and a separately protected recovery plan. Use current OS/security updates and screen-lock settings.
- Review iCloud Drive/Photos, Messages, backups, AirDrop, nearby-device sharing, and location/metadata exposure. Avoid sharing sensitive documents before reviewing embedded metadata.
- For those at elevated risk of mercenary spyware, evaluate Apple's **Lockdown Mode** on supported devices; it restricts features and is distinct from ordinary screen locking.

### Linux

- Prefer an installation with **LUKS2 full-disk encryption**; verify swap, temporary directories, snapshots and backup locations are included in the security model.
- Use up-to-date packages, least privilege and a firewall; check remote-access services, mounted network shares, USB automount and SSH keys.
- For temporary research work, evaluate [Tails](../tails-usb-setup-guide.md); for separated persistent workspaces evaluate [Whonix + Kicksecure](../whonix-kicksecure-usb-guide.md). Neither protects against compromised host hardware or exposed online accounts.

## Android phones

- Install manufacturer security updates and use a strong PIN or password instead of a short predictable PIN; configure fast auto-lock and keep notifications private on the lock screen.
- Review **Google account sync**, photo and messaging backups, notification-access permissions, device-administrator apps, accessibility services, sideloading, USB debugging, location and permissions.
- On Android versions that provide **Lockdown**, that feature temporarily disables biometric unlocking and lock-screen notification display / extended unlock until the next unlock. The exact menu and key combinations vary by manufacturer/version. Review [Google's Android Lockdown instructions](https://support.google.com/android/answer/9075927?hl=en). **This is a local screen-lock feature**, not the same as Apple's anti-spyware Lockdown Mode.
- Avoid assuming that manufacturer secure folders, work profiles or second users defeat forensic extraction or coercion. Validate the actual device/OS and attacker model.
- When a phone is confiscated or searched, treat all signed-in accounts and copied identifiers as potentially exposed and follow the [incident plan](./duress-seizure-response.md).

## iPhone and iPad

- Enable a strong device passcode and short auto-lock; review iCloud, Photos, Messages, backups, shared albums, Find My, location sharing, lock-screen previews and trusted devices.
- Apple's **Lockdown Mode** is an optional **anti-spyware attack-surface reduction** mode for people at unusually high risk of targeted attacks: Settings → Privacy & Security → Lockdown Mode, on supported systems. It can limit attachments, calls, links and app functionality; it is **not** a covert or emergency wipe feature.
- **Temporarily disabling Face ID** is a different action. On supported Face ID iPhones, Apple documents holding Side + either Volume for about two seconds until sliders appear, then pressing Side to lock; the next unlock requires the passcode. See [Apple's Face ID guide](https://support.apple.com/guide/iphone/set-up-face-id-iph6d162927a/ios). Do not assume equivalent steps for every hardware revision.
- High-risk users should review [Apple Lockdown Mode documentation](https://support.apple.com/en-us/105120) before deployment and test compatibility with necessary reporting tools.

## Account and communication hardening

1. Place email, cloud storage, password managers, code repositories and newsroom identity providers behind **FIDO2/WebAuthn**, ideally with **two independently enrolled keys**.
2. Use distinct personal, newsroom and source-contact identities where the reporting threat model requires separation.
3. Limit push notifications and lock-screen message previews; verify endpoints when first establishing a sensitive encrypted conversation.
4. Prefer end-to-end encrypted communication tools configured with appropriate disappearing-message and backup policies **only where compatible with legal/editorial preservation needs**.
5. Audit shared drives, mobile photo sync, contact backups, communications metadata, secondary devices and account recovery. Encryption in transit does not remove stored copies.
6. Use an editor-approved source-submission channel when receiving documents; isolate unknown files and consider document metadata before circulating.

## Network protections and travel

- Upgrade router and access-point firmware, disable remote administration unless needed, use WPA2-AES/WPA3 and unique credentials, and place guest/IoT devices on separate networks.
- Treat public Wi-Fi as untrusted: prefer HTTPS, verify captive-portal addresses and use a trusted VPN where appropriate. **VPN does not guarantee anonymity or secure a compromised device.**
- Avoid automatically joining previously used SSIDs; check for unauthorized mobile hotspots and nearby-pairing prompts.
- Carry a **minimal-data travel device** for high-risk assignments when feasible; prepare it before travel and arrange secure access to only what is needed.
- For field travel, share a check-in plan with someone trusted without placing source or story details into insecure location-sharing services.

## Field validation checklist

- [ ] Encryption enabled and recovery tested
- [ ] Restart/shutdown lock state evaluated
- [ ] OS and browser patches current
- [ ] Hardware key + backup registered and tested
- [ ] Source contacts not exposed by notification, sync or messaging backup
- [ ] Sensitive folders excluded from unapproved cloud sync
- [ ] Trusted communication channel and verification phrase confirmed
- [ ] VPN/firewall and safe network settings checked
- [ ] Emergency contact, response plan and secure backups available

## Official references

- [CPJ Digital Safety Kit](https://cpj.org/2019/07/digital-safety-kit-journalists/)
- [Freedom of the Press Foundation — digital security checklist](https://freedom.press/digisec/blog/journalists-digital-security-checklist/)
- [Apple Lockdown Mode](https://support.apple.com/en-us/105120)
- [Apple Face ID settings](https://support.apple.com/guide/iphone/set-up-face-id-iph6d162927a/ios)
- [Google Android Lockdown](https://support.google.com/android/answer/9075927?hl=en)
- [EFF Surveillance Self-Defense](https://ssd.eff.org/)

## See also

- [Press Freedom Index](./README.md)
- [Retention and Disposal](./data-retention-removal.md)
- [Duress and Seizure Response](./duress-seizure-response.md)

---

[Press Freedom Index](./README.md) | [OPSEC Index](../README.md) | [Master Index](../../README.md)
