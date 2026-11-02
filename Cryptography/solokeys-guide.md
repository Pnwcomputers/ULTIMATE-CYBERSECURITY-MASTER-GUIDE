# SoloKeys and Solo 2: FIDO2, Passkeys, and Multi-Protocol Keys

_Last reviewed: 2026-11-01 (official documentation reviewed; device firmware not tested)_

**Prerequisites:** [Hardware Security Keys and FIDO2](./security-keys-passkeys.md) · [Applied Cryptography](./applied-crypto.md)

## What SoloKeys are (and are not)

For the browser–relying-party–authenticator trust boundaries, see the [FIDO2/WebAuthn visual walkthrough](./security-keys-passkeys.md#what-is-a-security-key) and its [authentication diagram](../assets/fido2-passkey-authentication-flow.svg).

[SoloKeys](https://solokeys.com/) produces open-source security authenticators. Solo and Solo 2 support FIDO protocols for phishing-resistant account sign-in. **They are not conventional encrypted USB flash drives**; their FIDO functionality protects authentication credentials, not a mounted USB data volume.

The [Solo 2 upstream project](https://github.com/solokeys/solo2) documents **FIDO2/WebAuthn**, and separate application support for **OATH (TOTP/HOTP), PIV, and OpenPGP**. Specific capabilities, host software and support depend on model and firmware. Do not equate the availability of an app in source code with certification or successful operation on every shipping device.

### Solo 2 model/security choice

| Model | Firmware/security properties | Suggested context |
|---|---|---|
| **Solo 2 Secure** | Vendor-signed firmware enforcement and disabled debugging in the vendor's documented security model | Consumer or managed enterprise sign-in, subject to exact-product certification and policy |
| **Solo 2 Hacker** | Unlocked firmware for experimenting, modifying and flashing custom code; secure-boot sealing absent by design | Lab firmware development and security research; not interchangeable with a sealed production-key assurance claim |

A hacked/unlocked variant may still perform legitimate FIDO authentication, but it **must not be represented** as providing the same firmware-integrity guarantees as the Secure version.

## First-time registration on a test account

1. Confirm the **exact device model**, vendor purchase channel, connector and NFC compatibility.
2. Read the [Solo 2 guide](https://solokeys.com/pages/solo-2-guide) and [firmware security notes](https://github.com/solokeys/solo2/blob/main/SECURITY.md).
3. Ensure operating-system, browser and authenticator support for the intended service. Use a **test account** first.
4. Visit the service's own security settings, select **Add passkey / security key**, and choose the external hardware authenticator.
5. Follow system prompts to set/enter a FIDO PIN **if prompted** and touch the key to confirm registration.
6. Sign out, test sign-in on a second clean browser/session, and record only the account name and key inventory ID.
7. Add a **second key** as backup, test it separately and store it safely. Keep account recovery materials separately secured.
8. Review and disable weak alternate sign-in paths where supported and compatible with the account recovery plan.

> [!CAUTION]
> Do not reset, reflash or replace firmware on a key holding production credentials without confirming **every affected account** has working alternate access. A reset can invalidate registrations; backup keys are enrolled with each service, not made by copying the FIDO private key.

## Linux lab verification (non-destructive)

~~~bash
# Debian/Ubuntu, where approved to install lab tooling:
sudo apt install fido2-tools
# List detected FIDO authenticators without resetting them:
fido2-token -L
# Optional: list attached USB devices
lsusb
~~~

For alternate distributions, use their package manager and current libfido2 instructions. Device enumeration confirms connectivity, **not** hardware authenticity, firmware integrity or FIDO certification.

For supported Solo 2 OpenPGP app configurations, a separate read-only probe is:

~~~bash
gpg --card-status
~~~

This requires GnuPG and the relevant supported OpenPGP application; a failure does not necessarily mean FIDO2 is broken. Do not initialize or erase a card merely to test presence.

## FIDO vs OpenPGP, PIV, OATH and SSH

| Function | Concept | Important boundary |
|---|---|---|
| **FIDO2/WebAuthn** | Challenge signatures for website and application authentication | Does **not** encrypt an arbitrary disk or directly expose a file-encryption private key |
| **FIDO U2F** | Legacy phishing-resistant second factor | Often requires password sign-in as well |
| **OATH TOTP/HOTP** | Generates rotating shared-secret codes | Codes can be phished or relayed |
| **OpenPGP (supported variants)** | Private-key operations for signing, encryption/decryption and authentication | Configure separately, back up/revoke carefully, check current implementation |
| **PIV (supported variants)** | Certificate/smart-card authentication and crypto operations | Requires separate PKI, PIN and certificate management |
| **OpenSSH FIDO integration** | OpenSSH supports hardware-backed FIDO security-key SSH identities on compatible devices | Support depends on OpenSSH/libfido2, firmware and policy; plan backup SSH access |

### Optional SSH lab concept

On a compatible OpenSSH + FIDO host, a test key can be created using:

~~~bash
# Test environment only; this creates a local SSH identity requiring a compatible key.
ssh-keygen -t ed25519-sk -C "lab-fido2-auth"
~~~

Not all firmware/platform combinations support this algorithm. Follow the prompts, **do not overwrite an existing identity**, and validate backup access before making an SSH server key-only. Do not equate SSH hardware-key enrollment with FIDO website enrollment.

## Updating and lifecycle management

- Review the upstream [Solo 2 releases and source](https://github.com/solokeys/solo2) for currently supported firmware and tooling.
- Verify model and the documented update pathway before any firmware operation. **Secure** and **Hacker** models have different firmware-trust assumptions.
- Use manufacturer-signed firmware where the model requires it; never flash third-party firmware onto a production authenticator without an explicit risk acceptance.
- Maintain a device inventory (physical identifier, owner, service enrollment, issue/return date).
- On loss, revoke the missing authenticator from every enrolled service, review sign-in logs, and register a replacement.

## Failure and recovery drills

- [ ] Register daily key and independent backup key on the test service
- [ ] Verify each key separately on an unrelated clean browser session
- [ ] Confirm PIN vs touch enforcement and the expected user-verification policy
- [ ] Simulate loss by setting aside one key; confirm backup recovery works
- [ ] Confirm documented recovery routes do not bypass required assurance
- [ ] Record firmware version where vendor tooling makes it available
- [ ] Review FIDO certification using the **exact** certified model and revision
- [ ] Confirm OpenPGP/PIV are managed as distinct credential systems, if used

## See also

- [FIDO2, WebAuthn, passkeys and L1/L2/L3 certification](./security-keys-passkeys.md)
- [Encrypted drives and storage](./encrypted-storage.md)
- [PhantomDrive research](./phantomdrive-guide.md)
- [Applied cryptography](./applied-crypto.md)
- [Solo 2 official project](https://github.com/solokeys/solo2)
- [Solo 2 official user guide](https://solokeys.com/pages/solo-2-guide)

---

[Section Index](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
