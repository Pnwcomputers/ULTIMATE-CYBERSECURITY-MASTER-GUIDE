# 🛠️ Building Your Own Alphabet

_Last reviewed: 2026-10-02_

> [!IMPORTANT]
> **Historical and educational content.** Nothing in this section is secure for real
> data. For protecting information, use the modern algorithms in
> [algorithms.md](../algorithms.md) and [applied-crypto.md](../applied-crypto.md).

[← Classical Ciphers](ciphers.md) · [🏠 Classical Index](README.md) · [Cryptanalysis →](cryptanalysis.md)

Construction methods, keyed alphabets, homophonic substitution, and a design checklist.

---


Every alphabet in this guide is built from one or more of the methods below. Combine them to create your own.

## Construction Methods

| Method | How it works | Example |
| :--- | :--- | :--- |
| **Shape similarity** | Pick a glyph that *looks* like the letter | `E`→`3`, `A`→`/-\` |
| **Phonetic** | Pick something that *sounds* like it | `F`→`ph`, `X`→`ks`, `Q`→`kw` |
| **Positional / numeric** | Use the letter's index or coordinates | A1Z26, Polybius |
| **Geometric / mirror** | Rotate, mirror or reverse the alphabet | Atbash, upside-down text |
| **Keyed alphabet** | A keyword (duplicates removed) starts the cipher alphabet | Keyword cipher (below) |
| **Homophonic** | Frequent letters get *several* symbols | `E` → `17`, `42` or `88` at random |
| **Code-point swap** | Same letter, different Unicode block | Fraktur, fullwidth |
| **Binary/steganographic** | Two states hide five bits per letter | Baconian (bold/italic, upper/lower) |
| **Layering** | Apply two or more methods in sequence | Atbash, then leet |

## Keyed (Keyword) Alphabet

Write a keyword, drop repeated letters, then append the remaining letters of the alphabet in order. With keyword **ZEBRAS**:

| Plain | A | B | C | D | E | F | G | H | I | J | K | L | M |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cipher** | Z | E | B | R | A | S | C | D | F | G | H | I | J |

| Plain | N | O | P | Q | R | S | T | U | V | W | X | Y | Z |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Cipher** | K | L | M | N | O | P | Q | T | U | V | W | X | Y |

`ATTACK AT DAWN` → `ZQQZBH ZQ RZVK`

## Homophonic Substitution

The weakness of every one-for-one alphabet is that it preserves letter frequency (see [Breaking Simple Substitution](cryptanalysis.md#breaking-simple-substitution)). Homophonic ciphers counter this by giving common letters multiple symbols in proportion to their frequency. For example, `E` (≈13%) might get 13 different symbols while `Z` gets one. The ciphertext frequency then looks nearly flat.

## Design Checklist for Your Own Leet/Symbol Alphabet

1. **Reversibility:** Can every symbol be decoded to exactly one letter? `1` meaning both `I` and `L` (and `|3` vs `13`) creates ambiguity. That is acceptable for leet, but not for a cipher.
2. **Tokenization:** Multi-character symbols (`|-|`, `|\/|`) need separators, or a decoder cannot tell where one letter ends.
3. **Rendering:** Test on GitHub, Discord and mobile. Some Unicode characters are missing from common fonts and show as boxes (tofu).
4. **Markdown safety:** `|`, `*`, `_`, `` ` `` and `\` all have meaning in Markdown. Inside GitHub tables, every `|` must be escaped as `\|`, even inside code spans.
5. **Normalization survival:** Decide whether you *want* the text to survive Unicode NFKC normalization (see [Filter Evasion and Normalization](security.md#filter-evasion-and-normalization)).

---

[← Classical Ciphers](ciphers.md) · [🏠 Classical Index](README.md) · [Cryptanalysis →](cryptanalysis.md)

## See also

- [ciphers.md](ciphers.md) - the classical systems these methods come from
- [cryptanalysis.md](cryptanalysis.md) - test your design against frequency analysis

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
