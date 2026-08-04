# 🔧 Applied Cryptography

> [!IMPORTANT]
> Educational reference. Use vetted libraries and validated modules; the failures
> below are common **misuses**, not algorithm weaknesses. See the
> [section notice](README.md#-important-notice).

## 🎯 Purpose

How to apply cryptography correctly in practice - transport security (TLS),
password storage, MFA/2FA, key management, randomness, and the recurring
mistakes to avoid.

## ⚙️ Function

Covers TLS configuration, password storage, phishing-resistant MFA/2FA,
key management and rotation, secure randomness, and a catalog of common
cryptographic mistakes with fixes.

## 🏆 Goal

Let a reader implement or review the everyday uses of cryptography and
authentication without falling into well-known security traps.

## 📋 When to Use

- Configuring or reviewing TLS
- Implementing password storage
- Implementing or reviewing MFA/2FA
- Selecting passkeys, hardware security keys, TOTP, or other authentication methods
- Implementing key management
- Reviewing code for cryptographic misuse

---

## 📋 Table of Contents

- [Transport Security (TLS)](#transport-security-tls)
- [Password Storage](#password-storage)
- [Multi-Factor Authentication (MFA/2FA)](#multi-factor-authentication-mfa2fa)
- [Hardware Security Keys](#hardware-security-keys)
- [Key Management](#key-management)
- [Randomness](#randomness)
- [Common Mistakes](#common-mistakes)
- [Resources](#-resources)

---

## Transport Security (TLS)

- **Use TLS 1.3** (TLS 1.2 acceptable); disable TLS 1.0/1.1 and SSLv3
  ([RFC 8996](https://datatracker.ietf.org/doc/html/rfc8996)).
- **Cipher suites:** AEAD only (AES-GCM, ChaCha20-Poly1305); enable **forward
  secrecy** (ECDHE/X25519).
- **Certificates:** 2048-bit RSA or ECDSA P-256; validate the full chain; automate
  renewal (ACME/Let's Encrypt); enable **HSTS**.
- **Test:** `testssl.sh`, Qualys SSL Labs, or `sslyze` to grade a configuration.

```bash
# Inspect a server's negotiated protocol/cipher
openssl s_client -connect example.com:443 -tls1_3 </dev/null 2>/dev/null | grep -E "Protocol|Cipher"
```

---

## Password Storage

- Hash with a **memory-hard KDF** - **Argon2id** (preferred), scrypt, or bcrypt -
  never a fast hash (see
  [algorithms.md](algorithms.md#key-derivation-functions-passwords)).
- Use a **unique random salt per password**; the KDF normally handles this.
- Tune the work factor or cost to the deployment hardware.
- Consider a server-side **pepper** stored separately in a KMS or HSM.
- Check credentials against breached-password lists and support MFA.
- Never log, email, or store plaintext passwords.
- Never use reversible encryption as a substitute for password hashing.

---

## Multi-Factor Authentication (MFA/2FA)

Multi-factor authentication requires proof from at least two **different**
authentication-factor categories:

| Factor | Meaning | Examples |
|---|---|---|
| Something you know | Knowledge controlled by the user | Password, PIN |
| Something you have | A device or credential the user possesses | Passkey, hardware security key, authenticator app, smart card |
| Something you are | A biometric characteristic | Fingerprint, facial recognition, iris scan |

A password and a PIN are both knowledge factors and therefore do **not**
constitute 2FA. Two-factor authentication uses exactly two distinct factors,
while MFA may use two or more.

### Recommended Authentication Methods

Use the strongest practical option for the application and its threat model:

1. **Passkeys or FIDO2/WebAuthn security keys**
   - Preferred for administrative, privileged, financial, and high-risk accounts.
   - Resistant to credential phishing because authentication is bound to the
     legitimate application or domain.
   - Use device-bound or hardware-backed credentials when stronger assurance
     and non-exportable keys are required.
   - Allow users to register more than one authenticator to prevent lockout.

2. **Time-Based One-Time Passwords (TOTP)**
   - An acceptable fallback when passkeys or security keys are unavailable.
   - Use the standards-based TOTP protocol defined by RFC 6238.
   - Protect TOTP enrollment secrets using encryption and restricted access.
   - Display the enrollment QR code only during initial setup.
   - Use short validity periods, strict attempt limits, and replay prevention.
   - TOTP codes are still vulnerable to real-time phishing and adversary-in-the-middle attacks.

3. **Push-Based Authentication**
   - Display number matching, the requesting application, location, and device
     information when supported.
   - Rate-limit requests and block repeated prompts to reduce MFA-fatigue attacks.
   - Never rely on a simple, context-free **Approve/Deny** prompt for privileged access.
   - Push approval is not automatically phishing-resistant.

4. **SMS or Voice Codes**
   - Use only when stronger methods are unavailable or as a carefully controlled
     recovery option.
   - SMS and voice authentication are vulnerable to SIM swapping, number
     reassignment, interception, social engineering, and telecom-provider compromise.
   - Do not use SMS as the preferred factor for privileged or high-value accounts.

5. **Email Codes**
   - Email is generally a weak second factor when the same password, device,
     browser session, or identity provider controls both accounts.
   - Do not treat email as an independent factor unless the threat model and
     account separation justify it.

### Implementation Requirements

- Require MFA for administrators, remote access, cloud-management consoles,
  email, financial systems, source-code repositories, and other sensitive services.
- Offer a phishing-resistant authentication option wherever practical.
- Apply MFA consistently across web, mobile, API, VPN, legacy, and recovery paths.
- Require step-up authentication before sensitive actions, including:
  - Changing a password or primary email address
  - Adding, replacing, or removing an MFA factor
  - Disabling MFA
  - Viewing or regenerating recovery codes
  - Elevating to an administrative session
  - Changing payment, security, or account-recovery settings
- Require recent reauthentication with an existing enrolled factor before
  allowing factor replacement.
- Do not rely solely on an active session when changing authentication settings.
- Notify the user through a separate channel when a factor is added, removed,
  replaced, or used for account recovery.
- Rate-limit failed authentication attempts and detect repeated MFA prompts.
- Prevent reuse of OTPs, recovery codes, challenges, and authentication assertions.
- Log enrollment, use, failure, removal, and recovery events without logging secrets.
- Protect authentication sessions using secure, `HttpOnly`, and appropriately
  scoped cookies.

### TOTP Secret Handling

Unlike passwords, a server normally needs access to the original TOTP secret to
verify future codes. A one-way password hash is therefore not sufficient.

- Generate TOTP secrets using a cryptographically secure random-number generator.
- Encrypt TOTP secrets at rest using a KMS, HSM, or protected application key.
- Restrict decryption access to the authentication service.
- Never log or expose TOTP secrets in telemetry, support tools, or error messages.
- Rate-limit verification attempts.
- Reject a previously accepted code within its valid time window.
- Rotate the TOTP secret when compromise is suspected or a factor is re-enrolled.

### Recovery and Factor Replacement

Account recovery must not become an easier way to bypass MFA.

- Generate high-entropy, **single-use recovery codes** with a CSPRNG.
- Store recovery codes using a one-way hash rather than plaintext.
- Show recovery codes only when created or regenerated.
- Invalidate each recovery code immediately after use.
- Invalidate old recovery codes when a new set is generated.
- Encourage enrollment of multiple authenticators, such as two hardware keys.
- Require strong identity verification for help-desk or support-assisted recovery.
- Apply additional review, delays, or step-up verification to recovery requests
  involving privileged or high-value accounts.
- Notify users immediately when recovery is attempted or completed.
- Never use security questions as an authentication or recovery factor.

---

## Hardware Security Keys

Hardware security keys, including YubiKeys, Google Titan Security Keys, FEITIAN
keys, and other FIDO-certified authenticators, store cryptographic credentials
in dedicated hardware.

For FIDO2/WebAuthn authentication, the private key remains on the security key.
The service stores only the corresponding public key. Authentication requires
the key to sign a challenge issued by the legitimate service.

### Why Use a Hardware Security Key?

- **Phishing resistance:** FIDO2/WebAuthn credentials are bound to the legitimate
  website or application and cannot be used on a look-alike phishing domain.
- **No reusable server-side secret:** The service stores a public key rather than
  a password-equivalent shared secret.
- **Hardware-backed key protection:** Private keys are generated and retained
  inside the authenticator.
- **Replay resistance:** Each authentication uses a new challenge and signature.
- **User presence:** Keys normally require a physical touch, button press, PIN,
  or biometric verification.
- **Portability:** A single key can protect supported accounts across multiple
  computers and mobile devices.
- **Reduced dependence on phones:** Authentication does not require SMS service,
  cellular coverage, or a phone-based authenticator.

> [!IMPORTANT]
> A hardware key is phishing-resistant only when used with a phishing-resistant
> protocol such as **FIDO2/WebAuthn** or FIDO U2F. Using a YubiKey to generate
> TOTP or HOTP codes does not make those codes phishing-resistant.

### Common Hardware-Key Categories

| Category | Examples | Primary Use |
|---|---|---|
| FIDO2/WebAuthn security key | Yubico Security Key Series, Google Titan Security Key, FEITIAN FIDO keys | Phishing-resistant web, cloud, and identity-provider authentication |
| Multi-protocol security key | YubiKey 5 Series | FIDO2, U2F, PIV, OpenPGP, OATH-TOTP/HOTP, and supported legacy authentication |
| Biometric security key | YubiKey Bio Series, FEITIAN BioPass | Hardware-backed FIDO authentication with on-key fingerprint verification |
| Compliance-focused key | FIPS-validated models from supported vendors | Regulated environments requiring specific cryptographic-module validation |

Features vary by model, firmware, connector, and vendor. Confirm protocol,
platform, FIPS, and interface requirements before purchasing or deploying keys.

### Supported Protocols

#### FIDO2 and WebAuthn

FIDO2 combines the FIDO Client to Authenticator Protocol (CTAP) with the W3C
Web Authentication API.

Use FIDO2/WebAuthn for:

- Phishing-resistant MFA
- Passwordless authentication
- Device-bound passkeys
- Administrative and privileged accounts
- Cloud applications and identity providers
- Supported Windows, Linux, macOS, Android, and iOS authentication workflows

A FIDO2 key may store:

- **Non-discoverable credentials:** Commonly used as a second factor alongside
  a username and password.
- **Discoverable credentials:** Also called device-bound passkeys; these can
  identify the account and support passwordless authentication.

Hardware keys have finite storage for discoverable credentials. Capacity varies
by model and firmware, so confirm limits before large deployments.

#### FIDO U2F

FIDO U2F is the predecessor to FIDO2 and remains useful as a phishing-resistant
second factor for compatible legacy applications.

Prefer FIDO2/WebAuthn for new deployments, but retain U2F compatibility when
required by older services.

#### OATH-TOTP and HOTP

Some multi-protocol keys can store OATH-TOTP or HOTP secrets and generate codes
through an authenticator application.

- Codes remain vulnerable to real-time phishing.
- The key stores the shared OTP secret, but the service also requires that secret.
- Backing up OTP credentials may require enrolling multiple keys when the original
  QR code or shared secret is issued.
- Do not confuse hardware-stored TOTP with FIDO2/WebAuthn authentication.

#### PIV Smart Card

PIV-compatible keys can store certificates and private keys for:

- Smart-card authentication
- Certificate-based workstation login
- Client TLS authentication
- Document or code signing
- Encryption and decryption
- Supported SSH and administrative authentication workflows

Change default PIV PINs, PUKs, and management keys before deployment. Protect
management keys separately and document certificate issuance, renewal,
revocation, and recovery procedures.

#### OpenPGP

Supported keys can store OpenPGP keys for:

- Email and file encryption
- Digital signatures
- Git commit signing
- Authentication
- Supported SSH workflows

Generate and securely protect offline recovery or revocation material before
moving an OpenPGP private key to hardware.

### Selecting a Security Key

Consider the following requirements:

- **Protocol support:** FIDO2/WebAuthn only or multi-protocol support
- **Connector:** USB-A, USB-C, Lightning, or another supported interface
- **Wireless interface:** NFC support for compatible phones and tablets
- **User verification:** PIN, touch, or on-key biometric verification
- **Platform support:** Windows, Linux, macOS, Android, iOS, browsers, and identity providers
- **Durability:** Water, dust, crush, and tamper resistance
- **Credential capacity:** Number of supported discoverable FIDO credentials
- **Compliance:** FIPS 140-3 or other required certification
- **Attestation:** Device and model verification for managed enterprise deployments
- **Management:** Centralized inventory, provisioning, configuration, and revocation support

Purchase security keys directly from the manufacturer or an authorized reseller.
For high-assurance deployments, verify the device, packaging, firmware, and
certification status using manufacturer-supported tools and documentation.

### Recommended Enrollment Process

1. Sign in from a trusted and fully updated device.
2. Confirm the domain before beginning enrollment.
3. Require recent authentication with an existing trusted factor.
4. Initialize a FIDO2 PIN when supported or required.
5. Register the primary hardware security key.
6. Register a separate backup security key.
7. Clearly name each key in the account's security settings.
8. Generate and securely store single-use recovery codes.
9. Test both keys before ending the enrollment session.
10. Confirm that login, recovery, and factor-removal notifications are enabled.

For business deployments, record the assigned user, key model, asset identifier,
issue date, and revocation status without recording PINs, private keys, OTP
secrets, or recovery codes.

### Backup-Key Strategy

A user should not depend on a single physical key.

- Register at least **two separate hardware keys** for important accounts.
- Keep the primary key available for regular use.
- Store the backup key in a secure and physically separate location.
- Test the backup key periodically.
- Never attach the PIN directly to the key.
- Do not store the only recovery code beside the backup key.
- Consider an additional controlled spare for critical business or administrative accounts.
- Revoke a lost or stolen key immediately.
- Register the replacement before removing the final working authenticator.

FIDO private keys are intentionally non-exportable. Registering a second
hardware key creates a separate credential; it does not clone the first key.

### Priority Accounts

Use hardware security keys first on accounts that could be used to compromise
other systems:

- Primary email accounts
- Password managers
- Identity providers and single sign-on platforms
- Domain registrars and DNS providers
- Cloud-management consoles
- Source-code repositories
- Remote-access and VPN platforms
- Financial and payment accounts
- Social-media administration accounts
- Backup-management consoles
- Microsoft 365 and Google Workspace administrator accounts
- Server, hypervisor, firewall, and network-controller administration

Consider using a separate key for highly privileged administration instead of
sharing the same authenticator between routine personal activity and critical
infrastructure access.

### Enterprise Deployment

- Require FIDO2/WebAuthn for administrators and privileged roles.
- Maintain an inventory of issued, spare, lost, revoked, and returned keys.
- Define enrollment, replacement, revocation, and offboarding procedures.
- Keep controlled spare keys available for emergency replacement.
- Require reauthentication before registering or removing a key.
- Notify users and administrators when authentication factors change.
- Use attestation only when the organization must verify approved authenticator
  models or device-bound credentials.
- Test keys with every supported browser, operating system, mobile device, VPN,
  and identity provider.
- Disable or restrict weaker fallback methods that would allow attackers to
  bypass the security key.
- Verify the exact FIPS certificate, hardware model, and firmware version when
  compliance requires a validated cryptographic module.

### Lost, Stolen, or Damaged Keys

1. Use a registered backup key or approved recovery method.
2. Revoke the missing key from every associated account.
3. Review recent authentication and account-recovery activity.
4. Replace the missing key and register the replacement.
5. Investigate any unexpected login, recovery, or factor-change notifications.
6. Update the organization's asset and revocation records.

Possession of a lost key should not be sufficient for authentication when PIN or
biometric user verification is properly configured. However, the key must still
be treated as a potentially compromised authenticator.

### Resetting or Reassigning a Key

Resetting a security key can permanently delete its stored credentials.

Before resetting or reassigning a key:

- Confirm that every protected account has another working authenticator.
- Remove or revoke the key from each account when possible.
- Document the key's return or reassignment.
- Reset each enabled application according to manufacturer guidance.
- Verify that FIDO, PIV, OpenPGP, and OTP credentials have been removed.
- Reinitialize PINs, management keys, and organizational configuration.

Do not reset a key merely because its PIN was forgotten until another recovery
path has been confirmed.

### Limitations

Hardware security keys significantly improve authentication but do not prevent:

- Session-cookie or token theft after authentication
- Malware controlling an already authenticated endpoint
- Malicious OAuth or application-consent grants
- Weak account-recovery procedures
- Social engineering of help-desk personnel
- Authorization and access-control failures
- Abuse by an already authenticated user
- Compromise of applications that retain weaker fallback authentication

Continue to protect endpoints, sessions, recovery workflows, authorization
controls, and identity-provider configurations.

### Common Hardware-Key Mistakes

| Mistake | Fix |
|---|---|
| Enrolling only one key | Register a primary and physically separate backup key |
| Assuming hardware-stored TOTP is phishing-resistant | Use FIDO2/WebAuthn for phishing resistance |
| Leaving default PIV management credentials unchanged | Change PIN, PUK, and management keys during provisioning |
| Keeping SMS as an unrestricted fallback | Restrict or remove weaker recovery methods |
| Resetting a key before confirming account recovery | Verify another authenticator for every protected account first |
| No lost-key or revocation procedure | Document and test replacement and revocation workflows |
| Treating every key model as equivalent | Verify protocols, firmware, interfaces, capacity, and certifications |
| Buying keys from an unknown reseller | Purchase from the manufacturer or an authorized source |
| Assuming the key protects authenticated sessions | Continue protecting endpoints, cookies, tokens, and session lifetimes |
| Reusing one key for every risk level | Consider separate authenticators for privileged administration |

---

## Key Management

Key management is where most real deployments fail. See
[NIST SP 800-57](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final).

- **Never hardcode keys** in source, images, or configuration committed to Git;
  scan for leaked secrets.
- **Store keys in a KMS/HSM** such as a cloud KMS or HashiCorp Vault and grant
  least-privilege access.
- **Rotate keys** on a defined schedule and after suspected compromise.
- Support key versioning so older encrypted data remains decryptable during rotation.
- **Separate** key-encryption keys from data-encryption keys using envelope encryption.
- **Limit blast radius** with per-tenant or per-purpose keys where feasible.
- Log and monitor key usage without exposing key material.

---

## Randomness

- Use a **cryptographically secure PRNG**:
  - `/dev/urandom`
  - `getrandom(2)`
  - `secrets` in Python
  - `crypto.randomBytes` in Node.js
  - `SecureRandom` in Java
- **Never** use `rand()`, `random`, `Math.random()`, or a time-seeded PRNG for
  keys, tokens, OTPs, recovery codes, IVs, salts, or session IDs.
- Generate IVs and nonces according to the cipher's requirements.
- **Never reuse** a `(key, nonce)` pair with GCM or ChaCha20-Poly1305.

---

## Common Mistakes

| Mistake | Fix |
|---|---|
| Rolling your own crypto or authentication protocol | Use vetted libraries, identity providers, and standard protocols |
| ECB mode | Use an AEAD mode such as GCM or ChaCha20-Poly1305 |
| Reused IV/nonce with GCM | Use a unique nonce per encryption and rotate keys before exhaustion |
| Encryption without authentication | Use AEAD or encrypt-then-MAC with HMAC |
| Fast hash such as MD5 or SHA for passwords | Use Argon2id, scrypt, or bcrypt with a per-password salt |
| Hardcoded or committed keys | Use a KMS/HSM and secret scanning in CI |
| `Math.random()` for tokens or recovery codes | Use a CSPRNG |
| Textbook or PKCS#1 v1.5 RSA | Use OAEP for encryption and PSS for signatures |
| Trusting unauthenticated ciphertext | Verify the authentication tag before decrypting or using data |
| Calling a password and PIN “2FA” | Use factors from two different authentication categories |
| Using SMS as the preferred second factor | Prefer passkeys, WebAuthn security keys, or TOTP |
| Assuming all MFA is phishing-resistant | Use FIDO2/WebAuthn or another verifier-bound cryptographic method |
| Storing TOTP seeds in plaintext | Encrypt secrets with a KMS/HSM and restrict decryption access |
| Reusable or predictable recovery codes | Generate high-entropy single-use codes and store them hashed |
| Weak MFA reset or replacement workflow | Require existing-factor reauthentication, notify the user, and apply risk checks |
| Unlimited push requests | Rate-limit requests and use number matching to reduce MFA fatigue |
| Ignoring the quantum horizon | Build crypto-agility and plan a hybrid PQC migration |

---

## 📚 Resources

### Cryptography and TLS

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [NIST SP 800-57 Part 1 - Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [testssl.sh](https://testssl.sh/) - TLS configuration testing
- [libsodium](https://doc.libsodium.org/) - misuse-resistant cryptography library

### MFA and Authentication

- [NIST SP 800-63B-4 - Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [FIDO Alliance Passkeys](https://fidoalliance.org/passkeys/)
- [Web Authentication: WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 6238 - Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [FIDO Alliance](https://fidoalliance.org/) - FIDO standards, certification, and deployment resources
- [FIDO Certified Products](https://fidoalliance.org/certification/fido-certified-products/) - Searchable directory of certified authenticators
- [YubiKey 5 Series Technical Manual](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/)
- [YubiKey Protocols and Applications](https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-index.html)
- [Yubico Hardware-Backed Passkey Guidance](https://docs.yubico.com/hardware/yubikey-guidance/best-practices/all-faq-passkeys.html)

---

## Related Files

- [README.md](README.md) - Cryptography section index
- [algorithms.md](algorithms.md) - Algorithm reference by primitive
- [../Documentation/VPN.md](../Documentation/VPN.md) - Applied transport encryption
- [../WebAppSecurity/owasp-top-10.md](../WebAppSecurity/owasp-top-10.md) - A04 Cryptographic Failures
