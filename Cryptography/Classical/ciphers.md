# 📜 Classical Ciphers

_Last reviewed: 2026-10-02_

> [!IMPORTANT]
> **Historical and educational content.** Nothing in this section is secure for real
> data. For protecting information, use the modern algorithms in
> [algorithms.md](../algorithms.md) and [applied-crypto.md](../applied-crypto.md).

[← Alternative Alphabets](alphabets.md) · [🏠 Classical Index](README.md) · [Building Your Own Alphabet →](build-your-own.md)

Substitution master chart, transposition, Playfair, Vigenère and its variants, and the one-time pad.

**On this page:**

- [Classical Substitution Master Chart](#classical-substitution-master-chart)
- [Transposition Ciphers](#transposition-ciphers)
- [Polygraphic: The Playfair Cipher](#polygraphic-the-playfair-cipher)
- [Polyalphabetic: The Vigenère Cipher](#polyalphabetic-the-vigenère-cipher)
- [The One-Time Pad](#the-one-time-pad)

---

## Classical Substitution Master Chart

Substitution ciphers replace each letter with another symbol while keeping its position. One chart, eight systems:

| Letter | A1Z26 | ROT13 | Atbash | QWERTY →1 | Polybius | Tap code | Baconian | Binary (5-bit) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A** | 1 | N | Z | S | 11 | · · | `aaaaa` | `00000` |
| **B** | 2 | O | Y | N | 12 | · ·· | `aaaab` | `00001` |
| **C** | 3 | P | X | V | 13 | · ··· | `aaaba` | `00010` |
| **D** | 4 | Q | W | F | 14 | · ···· | `aaabb` | `00011` |
| **E** | 5 | R | V | R | 15 | · ····· | `aabaa` | `00100` |
| **F** | 6 | S | U | G | 21 | ·· · | `aabab` | `00101` |
| **G** | 7 | T | T | H | 22 | ·· ·· | `aabba` | `00110` |
| **H** | 8 | U | S | J | 23 | ·· ··· | `aabbb` | `00111` |
| **I** | 9 | V | R | O | 24 | ·· ···· | `abaaa` | `01000` |
| **J** | 10 | W | Q | K | 24 | ·· ····· | `abaab` | `01001` |
| **K** | 11 | X | P | L | 25 | · ··· | `ababa` | `01010` |
| **L** | 12 | Y | O | A | 31 | ··· · | `ababb` | `01011` |
| **M** | 13 | Z | N | Z | 32 | ··· ·· | `abbaa` | `01100` |
| **N** | 14 | A | M | M | 33 | ··· ··· | `abbab` | `01101` |
| **O** | 15 | B | L | P | 34 | ··· ···· | `abbba` | `01110` |
| **P** | 16 | C | K | Q | 35 | ··· ····· | `abbbb` | `01111` |
| **Q** | 17 | D | J | W | 41 | ···· · | `baaaa` | `10000` |
| **R** | 18 | E | I | T | 42 | ···· ·· | `baaab` | `10001` |
| **S** | 19 | F | H | D | 43 | ···· ··· | `baaba` | `10010` |
| **T** | 20 | G | G | Y | 44 | ···· ···· | `baabb` | `10011` |
| **U** | 21 | H | F | I | 45 | ···· ····· | `babaa` | `10100` |
| **V** | 22 | I | E | B | 51 | ····· · | `babab` | `10101` |
| **W** | 23 | J | D | E | 52 | ····· ·· | `babba` | `10110` |
| **X** | 24 | K | C | C | 53 | ····· ··· | `babbb` | `10111` |
| **Y** | 25 | L | B | U | 54 | ····· ···· | `bbaaa` | `11000` |
| **Z** | 26 | M | A | X | 55 | ····· ····· | `bbaab` | `11001` |

**How each column works:**

* **A1Z26:** Letter position in the alphabet. `HELLO` → `8-5-12-12-15`.
* **ROT13 / Caesar:** Shift the alphabet by *n* (ROT13 uses 13). Applying ROT13 twice returns the original. `HELLO` → `URYYB`.
* **Atbash:** Mirror the alphabet (A↔Z, B↔Y). Originally used with the Hebrew alphabet. `HELLO` → `SVOOL`.
* **QWERTY →1:** Each letter becomes the key to its right on the same row, wrapping at row ends (P→Q, L→A, M→Z). Wrap conventions vary between puzzles; some include punctuation keys.
* **Polybius square:** Letters placed in a 5×5 grid and written as row/column coordinates. **I and J share a cell.**
* **Tap code:** Same grid idea, tapped as two groups (row, then column). Used by U.S. POWs in Vietnam. **C and K share a cell**, so J gets its own.
* **Baconian:** Francis Bacon's 5-symbol `a`/`b` code (a binary code in disguise). Shown here in the modern 26-letter form; Bacon's original merged I/J and U/V. The `a`/`b` can be hidden as two typefaces, so the message is *steganographic* (hidden in plain sight).
* **Pigpen:** Letters replaced by fragments of tic-tac-toe and X grids (with and without dots). It is a graphical alphabet, so it is not shown in the table.

**Polybius square and tap code grids:**

```
 Polybius (I/J)         Tap code (C/K)
    1 2 3 4 5              1 2 3 4 5
 1  A B C D E           1  A B C D E
 2  F G H I K           2  F G H I J
 3  L M N O P           3  L M N O P
 4  Q R S T U           4  Q R S T U
 5  V W X Y Z           5  V W X Y Z
```

---

## Transposition Ciphers

Transposition ciphers keep every letter but **scramble the order**. Letter frequency is unchanged (a clue that you are looking at a transposition, not a substitution).

### Rail Fence

Write the message in a zig-zag across *n* rails, then read each rail left to right. With 3 rails:

```
W . . . E . . . C . . . R . . .
. E . R . D . S . O . E . E . .
. . A . . . I . . . V . . . D .
```

`WEAREDISCOVERED` → `WECRERDSOEEAIVD`

### Columnar Transposition

Write the message in rows under a keyword, then read the columns in the alphabetical order of the keyword's letters. With keyword **ZEBRA** (column order A=1, B=2, E=3, R=4, Z=5):

```
Z E B R A
---------
A T T A C
K A T D A
W N
```

`ATTACKATDAWN` → `CATTTANADAKW`

Combining substitution **and** transposition (as in the WWI German ADFGVX cipher) is far stronger than either alone, and this "confusion plus diffusion" idea underlies modern block ciphers.

---

## Polygraphic: The Playfair Cipher

Playfair (Charles Wheatstone, 1854, promoted by Lord Playfair) encrypts **pairs of letters** with a 5×5 keyed square (I/J combined). Because it works on digraphs, single-letter frequency analysis no longer applies directly. Key square for keyword **MONARCHY**:

```
M O N A R
C H Y B D
E F G I K
L P Q S T
U V W X Z
```

**Rules** (split the plaintext into pairs; insert `X` between doubled letters and pad an odd final letter):

1. **Same row:** Take the letter to the right of each (wrapping). `AR` → `RM`
2. **Same column:** Take the letter below each (wrapping).
3. **Rectangle:** Take the letter in the same row but in the other letter's column.

---

## Polyalphabetic: The Vigenère Cipher

The Vigenère cipher encrypts using a series of interwoven Caesar ciphers chosen by the letters of a keyword. Repeat the keyword over the message, then use the **Tabula Recta** (a 26×26 grid of shifted alphabets) to find the intersection of the plaintext letter and the key letter. Mathematically, `C = (P + K) mod 26`.

**Tabula recta (excerpt):**

| **Key ↓ / Plain →** | A | B | C | D | E | F | G | H | I | J | K | L | M |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **A** | A | B | C | D | E | F | G | H | I | J | K | L | M |
| **B** | B | C | D | E | F | G | H | I | J | K | L | M | N |
| **C** | C | D | E | F | G | H | I | J | K | L | M | N | O |
| **D** | D | E | F | G | H | I | J | K | L | M | N | O | P |
| **E** | E | F | G | H | I | J | K | L | M | N | O | P | Q |
| **K** | K | L | M | N | O | P | Q | R | S | T | U | V | W |
| **Y** | Y | Z | A | B | C | D | E | F | G | H | I | J | K |

**Example:**

| | | | | | | |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Plaintext** | H | I | D | D | E | N |
| **Keyword** | K | E | Y | K | E | Y |
| **Ciphertext** | R | M | B | N | I | L |

### Why It's Harder to Crack

1. **Flattened frequencies:** Because the shift changes with the key, `E` encrypts to several different letters.
2. **Same letter, different output:** The double `D` in `HIDDEN` became `B` and `N`.
3. **Key length matters:** Security scales with the length and randomness of the keyword. A key as long as the message, used once, becomes a one-time pad ([The One-Time Pad](#the-one-time-pad)).

### Variants

| Variant | Difference from Vigenère |
| :--- | :--- |
| **Beaufort** | `C = (K − P) mod 26`. Encryption and decryption are the same operation. |
| **Autokey** | After the initial key, the *plaintext itself* extends the key, so there is no repeating period for Kasiski to find. |
| **Running key** | The key is a long passage from a book. It is still breakable, because both key and plaintext are natural language. |
| **Gronsfeld** | The key is digits (shifts 0–9) instead of letters. |

---

## The One-Time Pad

If a Vigenère-style cipher uses a **truly random** key at least as long as the message, and the key is **never reused**, it becomes the **One-Time Pad (OTP)**, which is provably unbreakable.

It achieves *perfect secrecy* (Shannon, 1949): the ciphertext contains no information about the plaintext. Every plaintext of the same length is an equally valid decryption under some key.

**The key distribution problem:** The flaw is logistical. To encrypt a 1 GB file, you must first securely share a 1 GB truly random key. If you had a channel secure enough for the key, you could send the message over it. OTPs were therefore reserved for the highest-value links, such as the Cold War Washington–Moscow hotline, with key material physically carried by couriers.

**Reuse is fatal:** If two messages use the same pad, `C₁ ⊕ C₂ = P₁ ⊕ P₂`; the key cancels out. The U.S. VENONA project exploited exactly this against reused Soviet pads.

---

[← Alternative Alphabets](alphabets.md) · [🏠 Classical Index](README.md) · [Building Your Own Alphabet →](build-your-own.md)

## See also

- [cryptanalysis.md](cryptanalysis.md) - how these ciphers are broken
- [../algorithms.md](../algorithms.md) - modern replacements

---
[⬅️ Back to Master Index](../../README.md) | [🎯 Role Navigation](../../START_HERE.md) | [Legal Notice](../../LEGAL.md)
