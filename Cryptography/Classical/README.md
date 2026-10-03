# 🗝️ Classical Ciphers, Leetspeak & Alternative Alphabets

_Last reviewed: 2026-10-02_

*Part of the [Cryptography](../README.md) section of the [ULTIMATE CYBERSECURITY MASTER GUIDE](../../README.md)*

## 🎯 Purpose
A reference for character replacement and pre-modern cryptography, from leetspeak and Unicode look-alikes to the Vigenère cipher and the one-time pad.

## ⚙️ Function
Charts for every alphabet and cipher covered, methods for building new ones, the statistics used to break them, and a dependency-free Python toolkit.

## 🏆 Goal
Recognize, decode, and explain obfuscated or classically encrypted text (CTFs, OSINT, phishing analysis, filter evasion), and understand the limits of historical ciphers and the strict assumptions behind one-time-pad secrecy.

## 📋 When to Use
- Decoding puzzle, CTF, or OSINT text that uses leet, Morse, Braille, Polybius, etc.
- Analyzing homoglyph phishing domains or filter-evasion attempts
- Teaching the history and fundamentals of cryptanalysis

From internet slang to mathematically unbreakable encryption, altering text to hide or disguise its meaning has a long history. This section is a reference for character-replacement alphabets (leetspeak, Unicode styles, homoglyphs), classical ciphers, methods for building your own alphabets, and the mathematics used to break them, with charts and a working Python toolkit.

> [!IMPORTANT]
> **Historical and educational content.** Ordinary classical ciphers and obfuscation are unsuitable for real data. A true one-time pad is a special case with strict key requirements; it does not provide authentication. Use the modern algorithms in [algorithms.md](../algorithms.md) and [applied-crypto.md](../applied-crypto.md).

---

## Contents

| Guide | What's inside |
| :--- | :--- |
| [Leetspeak (1337)](leetspeak.md) | Leet tiers, basic and advanced replacement charts, and leet grammar and slang. |
| [Alternative Alphabets](alphabets.md) | Unicode styled alphabets, upside-down text, homoglyphs, and signal/tactile/machine encodings (Morse, NATO, Braille, ASCII). |
| [Classical Ciphers](ciphers.md) | Substitution master chart, transposition, Playfair, Vigenère and its variants, and the one-time pad. |
| [Building Your Own Alphabet](build-your-own.md) | Construction methods, keyed alphabets, homophonic substitution, and a design checklist. |
| [Mary, Queen of Scots](mary-queen-of-scots.md) | Nomenclators, the Babington Plot, Phelippes, the 2023 decipherment, and an original practice example. |
| [Deciphering Workbook](deciphering-workbook.md) | Cipher comparison, affine and Hill arithmetic, reverse transposition, Playfair, Vigenère variants, ADFGVX, rotors, XOR, and exercises. |
| [Cryptanalysis](cryptanalysis.md) | Frequency analysis, n-grams, Kasiski examination, and the Index of Coincidence with a worked key-length attack. |
| [Security Relevance](security.md) | Leet in password cracking, IDN homograph attacks, and filter evasion versus Unicode normalization. |
| [Python toolkit](cipher_toolkit.py) | Dependency-free script for leet, Unicode styles, Caesar/ROT13, Atbash, Vigenère, keyed alphabets and IC analysis. |

**Suggested reading order:** Leetspeak → Alternative Alphabets → Classical Ciphers → Cryptanalysis → Deciphering Workbook → Building Your Own → Security Relevance.

---

## Quick Reference

| System | Type | Key? | Preserves letter frequency? | Breaks with |
| :--- | :--- | :---: | :---: | :--- |
| Leetspeak | Obfuscation | No | Yes | Reading it / rule lists |
| Unicode styles | Obfuscation | No | Yes | NFKC normalization |
| Homoglyphs | Deception | No | Yes | Confusables skeleton (UTS #39) |
| Morse, Braille, NATO, ASCII | Encoding | No | Yes | Lookup table |
| Caesar / ROT13 | Monoalphabetic | 1–25 | Yes | Brute force (25 tries) |
| Atbash | Monoalphabetic | No | Yes | Recognition |
| Keyword / general substitution | Monoalphabetic | Alphabet | Yes | Frequency analysis |
| Homophonic | Monoalphabetic (many-to-one) | Table | Mostly flattened | N-gram statistics |
| Rail fence / columnar | Transposition | Rails / keyword | Yes (exactly) | Anagramming, brute force |
| Playfair | Polygraphic | 5×5 square | Partially | Digraph frequency |
| Vigenère | Polyalphabetic | Keyword | No (flattened) | Kasiski + IC |
| One-time pad | Polyalphabetic | Random, message-length | No | Perfect secrecy only with an independent, uniformly random, secret, single-use pad |

---

## Python Toolkit

[`cipher_toolkit.py`](cipher_toolkit.py) is a single Python 3 script with no third-party dependencies. It supports leet, Unicode styles, Caesar/ROT13, Atbash, Vigenère, keyed alphabets, and IC analysis; it does not implement every cipher described in these guides.

```bash
python3 Cryptography/Classical/cipher_toolkit.py leet "hacker" --tier 3     # |-|/-\(|<3|2
python3 Cryptography/Classical/cipher_toolkit.py style "hacker" fraktur     # ℌ𝔄ℭ𝔎𝔈ℜ
python3 Cryptography/Classical/cipher_toolkit.py rot13 "HELLO"              # URYYB
python3 Cryptography/Classical/cipher_toolkit.py vigenere "HIDDEN" KEY      # RMBNIL
python3 Cryptography/Classical/cipher_toolkit.py ic-scan "<ciphertext>"     # key-length bar chart
```

It can also be imported as a module:

Run from the repository root:

```python
import sys; sys.path.insert(0, "Cryptography/Classical")
import cipher_toolkit as ct

ct.style("hacker", "fraktur")          # 'ℌ𝔄ℭ𝔎𝔈ℜ'
ct.keyed_alphabet("ZEBRAS")            # 'ZEBRASCDFGHIJKLMNOPQTUVWXY'
ct.ic_scan(ciphertext, max_len=12)     # [(key_len, avg_ic), ...]
```

---

## Further Reading

* Unicode Technical Standard #39, *Unicode Security Mechanisms*: <https://www.unicode.org/reports/tr39/>
* Hashcat rule-based attack documentation: <https://hashcat.net/wiki/doku.php?id=rule_based_attack>
* David Kahn, *The Codebreakers* (1967; revised 1996)
* Simon Singh, *The Code Book* (1999)
* William F. Friedman, *The Index of Coincidence and Its Applications in Cryptography* (1922)

---

## Related Files
- [../README.md](../README.md) - Cryptography section index
- [../algorithms.md](../algorithms.md) - modern algorithm reference
- [../applied-crypto.md](../applied-crypto.md) - applied cryptography

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)

