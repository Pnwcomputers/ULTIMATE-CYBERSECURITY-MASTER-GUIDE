# 🔧 Applied Cryptography

> [!IMPORTANT]
> Educational reference. Use vetted libraries and validated modules; the failures
> below are common **misuses**, not algorithm weaknesses. See the
> [section notice](README.md#-important-notice).

## 🎯 Purpose
How to apply cryptography correctly in practice - transport (TLS), password
storage, key management, randomness - and the recurring mistakes to avoid.

## ⚙️ Function
Covers TLS configuration, password storage, key management and rotation, secure
randomness, and a catalog of common cryptographic mistakes with fixes.

## 🏆 Goal
Let a reader implement or review the everyday uses of cryptography without falling
into the well-known traps.

## 📋 When to Use
- Configuring or reviewing TLS
- Implementing password storage or key management
- Reviewing code for cryptographic misuse

---

## 📋 Table of Contents

- [Transport Security (TLS)](#transport-security-tls)
- [Password Storage](#password-storage)
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
  never a fast hash (see [algorithms.md](algorithms.md#key-derivation-functions-passwords)).
- **Unique random salt per password** (the KDF handles this); tune cost to your hardware.
- Consider a server-side **pepper** stored separately (e.g. in a KMS/HSM).
- Check credentials against **breached-password** lists; support MFA.
- Never log, email, or store plaintext passwords; never "encrypt" (reversible) them.

---

## Key Management

Key management is where most real deployments fail (see NIST SP 800-57).

- **Never hardcode keys** in source, images, or config committed to git; scan for
  leaked secrets.
- **Store keys in a KMS/HSM** (cloud KMS, HashiCorp Vault); grant least-privilege access.
- **Rotate** keys on a schedule and after suspected compromise; support key
  versioning so old data stays decryptable.
- **Separate** key-encryption keys from data-encryption keys (envelope encryption).
- **Limit blast radius:** per-tenant/per-purpose keys where feasible; log key usage.

---

## Randomness

- Use a **cryptographically secure PRNG** - `/dev/urandom`, `getrandom(2)`,
  `secrets` (Python), `crypto.randomBytes` (Node), `SecureRandom` (Java).
- **Never** use `rand()`, `random`, `Math.random()`, or a time-seeded PRNG for keys,
  tokens, IVs, salts, or session IDs.
- Generate IVs/nonces per the cipher's rules (random or counter) and **never reuse**
  a (key, nonce) pair with GCM/ChaCha20-Poly1305.

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Rolling your own crypto/protocol | Use vetted libraries (libsodium, Tink) and standard protocols |
| ECB mode | Use an AEAD mode (GCM, ChaCha20-Poly1305) |
| Reused IV/nonce with GCM | Unique nonce per encryption; rotate keys before exhaustion |
| Encryption without authentication | Use AEAD, or encrypt-then-MAC (HMAC) |
| Fast hash (MD5/SHA) for passwords | Argon2id/scrypt/bcrypt with per-password salt |
| Hardcoded / committed keys | KMS/HSM; secret scanning in CI |
| `Math.random()` for tokens | CSPRNG |
| Textbook/PKCS#1 v1.5 RSA | OAEP for encryption, PSS for signatures |
| Trusting unauthenticated ciphertext | Verify the MAC/tag before decrypting/using |
| Ignoring the quantum horizon | Build crypto-agility; plan hybrid PQC migration |

---

## 📚 Resources

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [NIST SP 800-57 Part 1 (Key Management)](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
- [testssl.sh](https://testssl.sh/) - TLS configuration testing
- [libsodium](https://doc.libsodium.org/) - misuse-resistant crypto library

---

## Related Files
- [README.md](README.md) - Cryptography section index
- [algorithms.md](algorithms.md) - algorithm reference by primitive
- [../Documentation/VPN.md](../Documentation/VPN.md) - applied transport encryption
- [../WebAppSecurity/owasp-top-10.md](../WebAppSecurity/owasp-top-10.md) - A04 Cryptographic Failures
