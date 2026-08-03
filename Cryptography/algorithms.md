# 🧮 Cryptographic Algorithm Reference

> [!IMPORTANT]
> Educational reference. Recommended key sizes and algorithm status change over
> time - verify against current [NIST](https://csrc.nist.gov/) guidance for
> high-assurance work, and use vetted libraries rather than implementing primitives.

## 🎯 Purpose
A quick, current reference to cryptographic algorithms by primitive - what to use,
recommended parameters, and what is deprecated.

## ⚙️ Function
Covers symmetric ciphers, asymmetric algorithms, hash functions, key-derivation
functions, and the new post-quantum standards, with key sizes and deprecation
status per NIST SP 800-131A / SP 800-57.

## 🏆 Goal
Let a reader pick a correct algorithm and parameters for a given need, and
recognize deprecated primitives in existing systems.

## 📋 When to Use
- Selecting an algorithm/key size for a design or code review
- Checking whether a primitive in existing code is still acceptable

---

## 📋 Table of Contents

- [Symmetric Encryption](#symmetric-encryption)
- [Asymmetric Cryptography](#asymmetric-cryptography)
- [Hash Functions](#hash-functions)
- [Key Derivation Functions (Passwords)](#key-derivation-functions-passwords)
- [Post-Quantum Algorithms](#post-quantum-algorithms)
- [Resources](#-resources)

---

## Symmetric Encryption

One shared secret key; fast; used for bulk data.

| Algorithm | Status | Notes |
|-----------|--------|-------|
| **AES-256 / AES-128 (GCM)** | ✅ Recommended | AEAD (authenticated); GCM is the default choice |
| **ChaCha20-Poly1305** | ✅ Recommended | AEAD; strong on platforms without AES hardware |
| AES-CBC / AES-CTR | ⚠️ Use with care | Not authenticated - must add a MAC (encrypt-then-MAC); prefer AEAD |
| AES-ECB | 🚫 Never | Leaks patterns (identical blocks → identical ciphertext) |
| 3DES | 🚫 Disallowed | Deprecated by NIST SP 800-131A; small block size (Sweet32) |
| DES / RC4 | 🚫 Broken | Do not use |

**Prefer AEAD** (GCM, ChaCha20-Poly1305) - it provides confidentiality **and**
integrity in one primitive. Never reuse a (key, nonce) pair.

---

## Asymmetric Cryptography

Public/private key pairs; used for key exchange and signatures (slow - typically
used to protect a symmetric key).

| Algorithm | Status | Notes |
|-----------|--------|-------|
| **Curve25519 / X25519** | ✅ Recommended | Fast, safe ECDH key exchange |
| **Ed25519** | ✅ Recommended | Fast signatures, misuse-resistant |
| **ECDSA / ECDH (P-256, P-384)** | ✅ Acceptable | NIST curves; widely supported |
| **RSA ≥ 3072** | ✅ Acceptable | 2048 acceptable near-term; use OAEP (enc) / PSS (sig) |
| RSA ≤ 1024 | 🚫 Deprecated | Insufficient strength |
| DSA | 🚫 Deprecated | Avoid; use EdDSA/ECDSA |
| Static Diffie-Hellman | ⚠️ | Prefer ephemeral (DHE/ECDHE) for forward secrecy |

Use **ephemeral** key exchange (ECDHE/X25519) for **forward secrecy**. Use OAEP
padding for RSA encryption and PSS for RSA signatures - never textbook/PKCS#1 v1.5
for new designs.

---

## Hash Functions

One-way integrity fingerprints (not for passwords - see KDFs).

| Algorithm | Status | Notes |
|-----------|--------|-------|
| **SHA-256 / SHA-384 / SHA-512** | ✅ Recommended | SHA-2 family; general-purpose integrity |
| **SHA-3 / SHAKE** | ✅ Recommended | Different construction (sponge); good alternative |
| **BLAKE2 / BLAKE3** | ✅ Good | Fast, modern (non-NIST) |
| SHA-1 | 🚫 Deprecated | Collisions demonstrated (SHAttered); NIST retiring by 2030 |
| MD5 | 🚫 Broken | Trivial collisions; never for security |

For message authentication use **HMAC** (e.g. HMAC-SHA-256) or an AEAD cipher, not
a bare hash.

---

## Key Derivation Functions (Passwords)

Password hashing needs a **deliberately slow, salted** function - never a fast hash.

| Function | Status | Notes |
|----------|--------|-------|
| **Argon2id** | ✅ Preferred | Memory-hard; winner of the Password Hashing Competition |
| **scrypt** | ✅ Good | Memory-hard |
| **bcrypt** | ✅ Acceptable | Long-established; ~72-byte input limit |
| **PBKDF2** | ⚠️ Acceptable | FIPS-approved but not memory-hard; use a high iteration count |
| MD5/SHA(-256) of a password | 🚫 Never | Fast hashes are trivially brute-forced even when salted |

Always use a **unique random salt** per password; tune cost parameters to your
hardware. See the [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

---

## Post-Quantum Algorithms

NIST finalized the first standards in **August 2024**:

| Standard | Algorithm | Purpose |
|----------|-----------|---------|
| **FIPS 203** | **ML-KEM** (CRYSTALS-Kyber) | Key encapsulation / key exchange |
| **FIPS 204** | **ML-DSA** (CRYSTALS-Dilithium) | Digital signatures (primary) |
| **FIPS 205** | **SLH-DSA** (SPHINCS+) | Hash-based signatures (conservative backup) |

Adopt via **hybrid** schemes first (classical + PQC, e.g. X25519+ML-KEM) so a
weakness in either still leaves the other. Prioritize long-lived data against
"harvest now, decrypt later." See the
[README post-quantum section](README.md#-post-quantum-cryptography).

---

## 📚 Resources

- [NIST SP 800-131A Rev 2 (algorithm transitions)](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final) / [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final) / [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

## Related Files
- [README.md](README.md) - Cryptography section index
- [applied-crypto.md](applied-crypto.md) - applying these algorithms correctly
