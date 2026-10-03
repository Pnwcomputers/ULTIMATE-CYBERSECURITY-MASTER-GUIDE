# 🔍 Cryptanalysis

_Last reviewed: 2026-10-02_

> [!IMPORTANT]
> **Historical and educational content.** Nothing in this section is secure for real
> data. For protecting information, use the modern algorithms in
> [algorithms.md](../algorithms.md) and [applied-crypto.md](../applied-crypto.md).

[← Building Your Own Alphabet](build-your-own.md) · [🏠 Classical Index](README.md) · [Security Relevance →](security.md)

Frequency analysis, n-grams, Kasiski examination, and the Index of Coincidence with a worked key-length attack.

**On this page:**

- [Breaking Simple Substitution](#breaking-simple-substitution)
- [Breaking Polyalphabetic Ciphers](#breaking-polyalphabetic-ciphers)

---

## Breaking Simple Substitution

### English Letter Frequency

Monoalphabetic ciphers keep the "fingerprint" of the language. The standard English frequency ranking is `ETAOIN SHRDLU`:

```
E  12.70%  ███████████████████████████████████████████████████
T   9.06%  ████████████████████████████████████
A   8.17%  █████████████████████████████████
O   7.51%  ██████████████████████████████
I   6.97%  ████████████████████████████
N   6.75%  ███████████████████████████
S   6.33%  █████████████████████████
H   6.09%  ████████████████████████
R   5.99%  ████████████████████████
D   4.25%  █████████████████
L   4.03%  ████████████████
C   2.78%  ███████████
U   2.76%  ███████████
M   2.41%  ██████████
W   2.36%  █████████
F   2.23%  █████████
G   2.02%  ████████
Y   1.97%  ████████
P   1.93%  ████████
B   1.29%  █████
V   0.98%  ████
K   0.77%  ███
J   0.15%  █
X   0.15%  █
Q   0.10%  
Z   0.07%  
```

### Attack Techniques

* **Frequency analysis:** Count each ciphertext symbol and match the most common ones to E, T, A, O and so on, then refine.
* **Single-letter words:** In English these are almost always `A` or `I`.
* **Doubled letters:** Common doubles are `LL`, `EE`, `SS`, `OO`, `TT`.
* **N-grams:** Common digraphs (`TH`, `HE`, `IN`, `ER`, `AN`) and trigraphs (`THE`, `AND`, `ING`).
* **Pattern words (crib dragging):** `THAT` has the pattern `1-2-3-1`, `PEOPLE` has `1-2-3-1-4-2`. A ciphertext word with the same pattern is a candidate.
* **Brute force:** A Caesar cipher has only 25 non-trivial keys, so try them all. A general substitution alphabet has 26! (about 4 × 10²⁶) keys, which is too many to brute-force, but frequency analysis plus hill-climbing solves it in seconds.

---

## Breaking Polyalphabetic Ciphers

To break a Vigenère cipher, first find the key length *L*. Then the ciphertext splits into *L* columns, each a plain Caesar cipher that falls to frequency analysis.

### The Kasiski Examination

Common words (like `THE`) sometimes line up with the same part of the repeating key and produce identical ciphertext sequences. Measure the distances between repeated sequences; the key length is likely a common factor of those distances.

### The Index of Coincidence (IC)

William F. Friedman's Index of Coincidence (published 1922) measures how "rough" a letter distribution is: the probability that two letters drawn at random from the text are identical.

```
IC = Σ nᵢ(nᵢ − 1) / (N(N − 1))
```

where *nᵢ* is the count of each letter and *N* is the total number of letters.

| Text type | Expected IC |
| :--- | :--- |
| Uniformly random letters | 1/26 ≈ **0.0385** |
| English plaintext | ≈ **0.0667** |
| Sample English text in this section | **0.0738** |

**Worked demo.** A passage of English was encrypted with a 6-letter key. The ciphertext begins:

```
KBLHW KJMQL WKQNI PQVUQ IDEJV PTDSI UBDMX ZOMHP XNCAI OIRIM DMAZU LDTMK ...
```

The scan below splits the ciphertext into *L* columns for each guessed key length and averages the IC of the columns. Wrong guesses stay near random; the correct length (and its multiples) jumps toward English:

```
len  1  IC 0.0413  ████████████████████
len  2  IC 0.0480  ███████████████████████
len  3  IC 0.0522  ██████████████████████████
len  4  IC 0.0502  █████████████████████████
len  5  IC 0.0400  ███████████████████
len  6  IC 0.0761  ██████████████████████████████████████   ← key length
len  7  IC 0.0442  ██████████████████████
len  8  IC 0.0548  ███████████████████████████
len  9  IC 0.0494  ████████████████████████
len 10  IC 0.0471  ███████████████████████
len 11  IC 0.0403  ████████████████████
len 12  IC 0.0823  █████████████████████████████████████████
```

Once *L* is known, each column is a Caesar cipher. Its shift is the one whose decryption best matches English letter frequencies (a chi-squared test).

---

[← Building Your Own Alphabet](build-your-own.md) · [🏠 Classical Index](README.md) · [Security Relevance →](security.md)

## See also

- [ciphers.md](ciphers.md) - the ciphers being attacked
- [cipher_toolkit.py](cipher_toolkit.py) - IC scan implementation

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
