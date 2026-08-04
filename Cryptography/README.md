# 🔐 Cryptography

<div align="center">

**Practical cryptography reference - algorithms, applied use, and what to avoid**

*Part of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

![Focus](https://img.shields.io/badge/Focus-Cryptography-blue?style=for-the-badge)
![Standards](https://img.shields.io/badge/Standards-NIST_%7C_FIPS-orange?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Reference-green?style=for-the-badge)

</div>

---

## 🎯 Purpose
Dedicated home for cryptography - which algorithms to use (and avoid), how to apply
them correctly (TLS, password storage, key management), and where the field is
heading (post-quantum).

## ⚙️ Function
Indexes the Cryptography section: fundamentals and a current-vs-deprecated summary
(this file), an algorithm reference by primitive
([algorithms.md](./algorithms.md)), and applied cryptography - TLS, password
storage, key management, and common mistakes ([applied-crypto.md](./applied-crypto.md)).

## 🏆 Goal
Give practitioners a single reference for making correct, current cryptographic
choices and recognizing the recurring mistakes - grounded in NIST guidance.

## 📋 When to Use
- Choosing an algorithm, key size, or mode for a design or review
- Reviewing password storage, TLS config, or key management
- Understanding the post-quantum transition and crypto-agility
- Recognizing deprecated/broken primitives in existing code

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The One Rule](#-the-one-rule)
- [Current vs Deprecated (Quick Reference)](#-current-vs-deprecated-quick-reference)
- [Post-Quantum Cryptography](#-post-quantum-cryptography)
- [Folder Contents](#-folder-contents)
- [Important Notice](#-important-notice)
- [Resources](#-resources)

---

## 🎯 Overview

Cryptography is referenced throughout this repository (TLS, hashing, password
storage, VPNs, disk encryption) but had no dedicated home. This section
consolidates it into fundamentals, an algorithm reference, and applied guidance -
all aligned with current **NIST/FIPS** standards.

The three primitive families:

- **Symmetric** - one shared key for encryption (fast; AES, ChaCha20).
- **Asymmetric** - public/private key pairs for key exchange and signatures
  (RSA, ECC).
- **Hashing** - one-way integrity fingerprints (SHA-2, SHA-3); with **KDFs** for
  password storage (Argon2, bcrypt).

---

## 🛑 The One Rule

> [!WARNING]
> **Don't roll your own crypto.** Use well-reviewed, maintained libraries
> (libsodium, the platform's TLS stack, `cryptography` for Python, Tink) and
> vetted protocols. Almost every real-world cryptographic failure is a
> *misuse* - wrong mode, reused nonce, hardcoded key, fast hash for passwords -
> not a broken algorithm. Prefer **high-level, misuse-resistant** APIs.

---

## 📊 Current vs Deprecated (Quick Reference)

| Use | ✅ Use | 🚫 Avoid / Deprecated |
|-----|--------|------------------------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305 (AEAD) | DES, 3DES, RC4, AES-ECB |
| Hashing (integrity) | SHA-256/384/512, SHA-3 | MD5, SHA-1 |
| Password storage | Argon2id, scrypt, bcrypt, PBKDF2 | MD5/SHA "fast" hashes, unsalted hashes |
| Asymmetric / key exchange | RSA ≥ 3072, ECC (P-256, Curve25519), ECDH | RSA ≤ 1024, static DH, custom curves |
| Signatures | Ed25519, ECDSA (P-256), RSA-PSS | RSA ≤ 1024, DSA |
| Transport | TLS 1.3 (1.2 acceptable) | TLS 1.0/1.1, SSLv3 |

Deprecations follow **NIST SP 800-131A Rev 2** - e.g. 3DES is disallowed and SHA-1
is being retired. Details in [algorithms.md](./algorithms.md).

---

## 🔮 Post-Quantum Cryptography

A sufficiently large quantum computer would break RSA and ECC. The threat is
already relevant via **"harvest now, decrypt later"** - adversaries capturing
encrypted data today to decrypt once quantum is viable.

**NIST finalized the first PQC standards in August 2024:**

- **FIPS 203 - ML-KEM** (based on CRYSTALS-Kyber) - key encapsulation.
- **FIPS 204 - ML-DSA** (based on CRYSTALS-Dilithium) - digital signatures.
- **FIPS 205 - SLH-DSA** (based on SPHINCS+) - stateless hash-based signatures.

**What to do now:** inventory where you use public-key crypto, build
**crypto-agility** (the ability to swap algorithms), and plan migration - starting
with long-lived secrets and hybrid (classical + PQC) key exchange.

---

## 📂 Folder Contents

| File | Description | Status |
|------|-------------|--------|
| **[algorithms.md](./algorithms.md)** | Algorithm reference by primitive - symmetric, asymmetric, hashing, KDFs, and PQC, with key sizes and deprecations | ✅ Complete |
| **[applied-crypto.md](./applied-crypto.md)** | Applied cryptography - TLS, password storage, key management, randomness, and common mistakes | ✅ Complete |

---

## ⚠️ Important Notice

> [!IMPORTANT]
> **Educational reference, not a substitute for a cryptographer.** For
> high-assurance or novel designs, engage a specialist and prefer FIPS-validated
> modules where required. Standards and recommended key sizes change - verify
> against the current NIST publications before relying on specifics.

---

## 📚 Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST SP 800-57 Part 1 (Key Management)](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [NIST SP 800-131A Rev 2 (Transitions)](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Cryptographic Right Answers (Latacora)](https://www.latacora.com/blog/2018/04/03/cryptographic-right-answers/)
- [libsodium documentation](https://doc.libsodium.org/)

---

<div align="center">

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

</div>

---

## Related Files
- [algorithms.md](algorithms.md) - algorithm reference by primitive
- [applied-crypto.md](applied-crypto.md) - TLS, password storage, key management
- [../Documentation/VPN.md](../Documentation/VPN.md) - applied transport encryption
- [../GLOSSARY.md](../GLOSSARY.md) - acronyms (AEAD, KDF, PKI…)

---
[⬅️ Back to Master Index](../README.md) |
