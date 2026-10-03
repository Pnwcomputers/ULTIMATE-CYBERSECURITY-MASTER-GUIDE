# 🛡️ Security Relevance

_Last reviewed: 2026-10-02_

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized security
> testing, education, and defensive research. Using them against systems you do
> not own or lack explicit written permission to test is illegal. See
> [LEGAL.md](../../LEGAL.md).

> [!IMPORTANT]
> **Historical and educational content.** Nothing in this section is secure for real
> data. For protecting information, use the modern algorithms in
> [algorithms.md](../algorithms.md) and [applied-crypto.md](../applied-crypto.md).

[← Cryptanalysis](cryptanalysis.md) · [🏠 Classical Index](README.md)

Leet in password cracking, IDN homograph attacks, and filter evasion versus Unicode normalization.

---


## Leet in Passwords

Leet substitutions add almost no strength to a password. Cracking tools apply them automatically as **rules** to every word in a wordlist. Hashcat ships rule files for exactly this purpose, including `leetspeak.rule`, `unix-ninja-leetspeak.rule` and `Incisive-leetspeak.rule`:

```bash
# Try every wordlist entry with common leet substitutions
hashcat -a 0 -m <hash-mode> hashes.txt wordlist.txt -r rules/unix-ninja-leetspeak.rule
```

`P@55w0rd` falls almost as quickly as `password`. Length and randomness (a passphrase or a password manager) matter; character swaps do not.

## Homograph (IDN) Attacks

Internationalized Domain Names allow non-Latin characters in domain names. An attacker can register a domain built from Cyrillic look-alikes that is visually identical to a real brand. Defenses:

* Browsers display suspicious mixed-script domains in **Punycode** (`xn--...`) instead of rendering them.
* Mail and web filters should flag **mixed-script** strings (Latin plus Cyrillic in one label).
* The Unicode Consortium publishes the `confusables.txt` data and the "skeleton" algorithm in **UTS #39 (Unicode Security Mechanisms)** for detecting look-alikes.

## Filter Evasion and Normalization

Content filters often apply **Unicode NFKC normalization** before matching. It folds many styled alphabets back to plain ASCII, but not all of them:

| Input | After NFKC | Caught by filter? |
| :--- | :--- | :---: |
| Fullwidth `ＨＡＣＫ` | `HACK` | ✅ |
| Circled `ⒽⒶⒸⓀ` | `HACK` | ✅ |
| Fraktur / Bold / Script / Double-struck | `HACK` | ✅ |
| Small caps `ʜᴀᴄᴋ` | `ʜᴀᴄᴋ` (unchanged) | ❌ |
| Cyrillic homoglyphs `НАСК` | `НАСК` (unchanged) | ❌ |
| Leet `H4CK` | `H4CK` (unchanged) | ❌ |

A robust filter layers **NFKC**, then a **confusables skeleton** (UTS #39), then a **leet de-substitution** map before matching.

```python
import unicodedata
unicodedata.normalize("NFKC", "ＨＡＣＫ")   # -> 'HACK'
unicodedata.normalize("NFKC", "ʜᴀᴄᴋ")       # -> 'ʜᴀᴄᴋ' (unchanged)
```

---

[← Cryptanalysis](cryptanalysis.md) · [🏠 Classical Index](README.md)

## See also

- [../applied-crypto.md](../applied-crypto.md) - correct password storage
- [../../Documentation/hcxtoolshashcat.md](../../Documentation/hcxtoolshashcat.md) - hashcat rule-based attacks in practice
- [../../Tradecraft/osint-threat-intel.md](../../Tradecraft/osint-threat-intel.md) - lookalike-domain discovery with dnstwist
- [../../AI/offensive_ai.md](../../AI/offensive_ai.md) - homoglyph attacks against ML filters
- [../../GLOSSARY.md](../../GLOSSARY.md) - acronyms

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
