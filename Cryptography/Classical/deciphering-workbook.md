# Cipher Types and a Practical Deciphering Workbook

_Last reviewed: 2026-10-03_

[Classical index](README.md) · [Cryptography index](../README.md)

## Purpose and scope

Learn how to recognize cipher families, decrypt with a known key, and approach
cryptanalysis when the key is missing. Use the exercises on this page with your
own text or authorized educational challenges.

**Reading connection:** Panos Louridas, *Cryptography*, MIT Press, 2024, offers
a progression from classical cryptography to modern cryptographic systems.
The publisher's description and public author excerpt were consulted; the full
book was not available for a chapter-by-chapter comparison. This is an original
supplement, with independently constructed exercises, not a reproduction of the
book. The additional cipher coverage below is not a claim that every system
appears in that book. See [Sources](#sources).

Read [Classical Ciphers](ciphers.md) for the alphabet charts and
[Cryptanalysis](cryptanalysis.md) for frequency analysis, Kasiski examination,
and the index of coincidence (IC).

## Contents

- [Vocabulary](#vocabulary)
- [Cipher comparison](#cipher-comparison)
- [A repeatable deciphering workflow](#a-repeatable-deciphering-workflow)
- [Caesar and affine ciphers](#caesar-and-affine-ciphers)
- [General and homophonic substitution](#general-and-homophonic-substitution)
- [Scytale and columnar transposition](#scytale-and-columnar-transposition)
- [Playfair decryption](#playfair-decryption)
- [Vigenère and its variants](#vigenère-and-its-variants)
- [Hill cipher](#hill-cipher)
- [ADFGX and ADFGVX](#adfgx-and-adfgvx)
- [Rotor machines](#rotor-machines)
- [XOR and reused pads](#xor-and-reused-pads)
- [What changes with modern cryptography](#what-changes-with-modern-cryptography)
- [Practice and answers](#practice-and-answers)
- [Tools](#tools)
- [Sources](#sources)

## Vocabulary

| Term | Meaning |
| :--- | :--- |
| Encoding | Changes representation using a public rule, such as hex or Base64. No secret key is required. |
| Encryption | Uses a key to transform plaintext into ciphertext for confidentiality. |
| Decryption | Reverses encryption using the required key and parameters. |
| Cryptanalysis | Investigates weaknesses or recovers information without the intended secret. It may recover plaintext without recovering the original key. |
| Steganography | Hides the existence of a message, for example through two typefaces. It can accompany encryption. |
| Hashing | Produces a digest, not reversibly encrypted text. Candidate guessing is not hash decryption. |
| Crib | A suspected plaintext fragment used to constrain a solution. A guess remains a guess until verified. |

For the letter arithmetic below, use **A=0, B=1, …, Z=25**. Modulo 26 means
wrapping into the range 0–25; for example, −3 modulo 26 is 23.
Preserve the original message before removing spaces or changing case.

## Cipher comparison

| Family | What changes | Known-key decryption | Useful unknown-key approach |
| :--- | :--- | :--- | :--- |
| Caesar / ROT13 | One fixed shift | Subtract the shift | Enumerate all 26 shifts, including identity |
| Affine | Multiply, then shift | Use a modular inverse | Enumerate 312 valid parameter pairs |
| General substitution | Fixed alphabet permutation | Invert the mapping | Word patterns, frequencies, n-gram scoring |
| Homophonic substitution | Several symbols may represent one letter | Map each symbol back | Symbol relationships, repeated phrases, language scoring |
| Scytale / rail fence / columnar | Character positions | Reverse the route or column order | Try dimensions, routes, rails, or column permutations |
| Playfair | Letter pairs | Reverse square rules | Digraph constraints and candidate-square search |
| Repeating-key Vigenère | Position-dependent shifts | Subtract repeating key | Kasiski, IC, then per-column shift scoring |
| Plaintext autokey | Initial key followed by plaintext | Recover plaintext sequentially | Cribs and feedback consistency |
| Running key | A long key passage | Subtract the key passage | Joint language constraints or candidate source texts |
| Hill | Blocks multiplied by a matrix | Multiply by inverse matrix | Known-plaintext linear equations |
| ADFGX / ADFGVX | Coordinates followed by transposition | Undo transposition, then coordinates | Search transposition and substitution structure |
| Rotor machine | Substitution changes as rotors step | Reproduce machine and initial settings | Cribs, machine constraints, procedural weaknesses |
| Repeated-key XOR | Bytes XORed with periodic key | XOR with the same key | Key-period estimates and per-column byte scoring |
| True one-time pad | Independent random pad | Combine with the secret pad | No ciphertext-only recovery under the perfect-secrecy assumptions |

Clues overlap. A 26-letter alphabet does not identify a cipher, and a short
message may support several equally plausible solutions.

## A repeatable deciphering workflow

1. **Record the evidence.** Save the exact symbols, length, spaces, line breaks,
   source context, and any known language or format.
2. **Check the representation.** Consider hex, Base64, Morse, coordinate pairs,
   or a symbol font. Successful decoding may reveal another layer rather than
   plaintext. Five-letter groups may be formatting, not five-letter blocks.
3. **Make a small set of hypotheses.** Unchanged letter counts suggest
   transposition; relabeled frequency patterns suggest substitution. These are
   clues, not proofs. Compression can also resemble encrypted data.
4. **Try cheap, reversible checks.** Test Caesar shifts, Atbash, plausible
   rail counts, and stated alphabet conventions before expensive searches.
5. **Measure structure.** Count symbols and n-grams, inspect word patterns,
   and compare IC across candidate key periods. Short samples are noisy.
6. **Constrain and rank.** Use the expected language, known format, and cribs.
   Keep several candidates; the highest language score need not be correct.
7. **Verify the whole message.** Re-encrypt the candidate with the recovered
   settings and compare against the normalized ciphertext. This proves
   consistency, not necessarily uniqueness or historical authenticity.
8. **Record uncertainty.** State preprocessing, padding, conventions, alternate
   solutions, and what further evidence would distinguish them.

### Know what information the method assumes

| Model | Information available | Example |
| :--- | :--- | :--- |
| Ciphertext-only | Ciphertext and perhaps its language | Frequency analysis of substitution |
| Known-plaintext | Some matching plaintext/ciphertext | Recovering a Hill matrix |
| Chosen-plaintext | Ability to encrypt selected messages | Probing how an educational cipher maps input |
| Chosen-ciphertext | Access to selected decryption results | Studying a decryption oracle in a lab |

A worked known-plaintext attack does not establish that arbitrary ciphertext
can be solved with no other information.

## Caesar and affine ciphers

Caesar encryption is `C = (P + b) mod 26`. Subtract `b` to decrypt.
For `b=3`, `PNWC` becomes `SQZF`. Try every shift when the key is unknown.
ROT13 is the special case `b=13`; applying it twice restores the input.

Affine encryption adds a multiplier:

`C = (aP + b) mod 26`

Choose `a` coprime to 26: **1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25**.
Otherwise different plaintext letters can collapse to the same ciphertext.
There are 12 choices of `a` and 26 choices of `b`: **312 keys**.

Decrypt using `P = a⁻¹(C − b) mod 26`, where `a⁻¹` is the modular inverse.
With `a=5, b=8`, the inverse is 21 because `5×21 mod 26 = 1`.

**Worked example:** `PNWC` → `FVOS`.
The first ciphertext letter F is 5; `21×(5−8) mod 26 = 15`, or P.
Apply the same operation to the remaining letters to recover `PNWC`.

Without the key, enumerate the 312 pairs and rank candidate text. Four letters
are too little to expect a language score to identify a unique answer.

## General and homophonic substitution

For ordinary substitution, maintain both a cipher-to-plain and a plain-to-cipher
mapping: each letter must have one partner. Repeated-letter patterns survive.
For example, `LETTER` has pattern `1-2-3-3-2-4`; `PEOPLE` has
`1-2-3-1-4-2`. Test a guessed word against all occurrences of those symbols.

Frequency counts narrow choices but are not a deterministic lookup table.
The most common symbol in a short sample need not stand for E. Names, jargon,
language, and deliberate omission of common letters can change the distribution.

An automated search can swap two letters in a candidate key and score the
result using language n-grams. Hill climbing keeps improvements; simulated
annealing sometimes accepts worse moves to escape local optima. Multiple
restarts help, but there is no guaranteed time or successful result.

Homophonic systems allow multiple ciphertext symbols for one plaintext letter.
Do not impose an ordinary substitution permutation on them. Flattened symbol
frequencies can frustrate single-symbol analysis while longer language patterns
still provide evidence. Tokenization matters if symbols use variable-length
numbers: preserve separators until their role is understood.

## Scytale and columnar transposition

A scytale can be modeled as writing in a rectangle and reading along a different
direction. State the exact route, dimensions, and padding: implementations vary.
Try plausible widths and inspect the resulting rows when the dimensions are
unknown. Letter counts remain exactly the same if no padding was added.

**Original rectangular exercise:** write `PNWCCOMPUTER` in three rows of four:

| Column 1 | Column 2 | Column 3 | Column 4 |
| :---: | :---: | :---: | :---: |
| P | N | W | C |
| C | O | M | P |
| U | T | E | R |

Reading down each column produces `PCUNOTWMECPR`.
To reverse it with the dimensions known, split into `PCU`, `NOT`, `WME`,
`CPR`, place them as columns, and read the rows.

### Unequal column lengths

For an unpadded message of length `N` written left-to-right in `k` columns,
let `q=N//k` and `r=N%k`. The first `r` **original** columns contain `q+1`
characters; the rest contain `q`. Allocate these lengths in the keyword's
readout order, then restore the columns to their original positions.

For the existing `ZEBRA` example, `N=12, k=5`: Z and E contain three letters;
B, R, and A contain two. The readout order A, B, E, R, Z therefore splits
`CATTTANADAKW` as `CA / TT / TAN / AD / AKW`.
Restoring Z, E, B, R, A and reading rows recovers `ATTACKATDAWN`.
For repeated keyword letters, specify a tie rule, such as left-to-right order.

## Playfair decryption

Use the `MONARCHY` square in [Classical Ciphers](ciphers.md):

- Same row: move each ciphertext letter **left**, wrapping around.
- Same column: move each letter **up**, wrapping around.
- Rectangle: take the letter on the same row in the other letter's column.

`IN` forms opposite corners. Replacing each corner by the other column on its
row gives `GA`. For a same-row example, `RM` decrypts to `AR`.
Keep ciphertext pair boundaries aligned.

Inserted fillers and merged I/J cannot always be reversed uniquely.
Do not delete every X: an X may belong to the actual message. Square-search
methods use digraph or longer language scores; short messages can be ambiguous.

## Vigenère and its variants

Repeating-key Vigenère uses `Cᵢ = (Pᵢ + Kᵢ) mod 26`.
Decryption subtracts the repeated key: `Pᵢ = (Cᵢ − Kᵢ) mod 26`.

**Worked example:** key `KEYKEY` decrypts `ZRUMMR` to `PNWCIT`.
For the first letter, Z=25 and K=10, so `25−10=15`, or P.

For an unknown repeating key:

1. Measure distances between repeated ciphertext sequences; test their factors
   as candidate periods. Accidental repeats also occur.
2. Split text by position modulo each candidate period and compare column ICs.
   Multiples of the true period can score well too; tiny columns are unreliable.
3. Try each of 26 shifts per column. One scoring rule is
   `χ² = Σ((Oᵢ − n·pᵢ)² / (n·pᵢ))`, using observed counts `Oᵢ`,
   column length `n`, and reference language proportions `pᵢ`.
4. Combine promising shifts and evaluate complete plaintext. Lower chi-squared
   is a ranking heuristic, not a proof that the key is correct.

Do not apply this recipe unchanged to every polyalphabetic cipher:

| Variant | Decryption rule or difference | Analysis implication |
| :--- | :--- | :--- |
| Beaufort | `P = K − C mod 26` | Same operation encrypts and decrypts; repeated keys still permit period analysis |
| Variant Beaufort | If `C = P − K`, then `P = C + K mod 26` | Check the tool's convention rather than relying on its label |
| Plaintext autokey | Initial secret followed by recovered plaintext | Decrypt sequentially; a crib can constrain later key letters |
| Running key | Subtract a long external key text | Natural-language redundancy exists in both streams; ordinary repeating-key Kasiski is not the general solution |
| Gronsfeld | Key digits specify shifts 0–9 | Period analysis can apply, with fewer shift candidates per position |

## Hill cipher

Hill encrypts letter blocks as vectors: `C = KP mod 26`. The matrix must be
invertible modulo 26; a nonzero determinant alone is insufficient.
Require `gcd(det(K),26)=1`. Decryption is `P = K⁻¹C mod 26`.

**Original two-letter exercise, using column vectors:**

`K = [[3,3],[2,5]]`, `K⁻¹ = [[15,17],[20,9]]`.
The determinant is 9, whose inverse modulo 26 is 3.
`HI = [7,8]ᵀ` encrypts to `[45,54]ᵀ mod 26 = [19,2]ᵀ = TC`.
Decrypting TC gives `[319,398]ᵀ mod 26 = [7,8]ᵀ = HI`.

For known-plaintext recovery, arrange matching plaintext blocks as columns of
a matrix `P` and ciphertext blocks as columns of `C`. If `P` is invertible,
`K = CP⁻¹ mod 26`. Singular samples require other blocks or additional
equations; the number of known letters alone does not guarantee recovery.
Verify the recovered matrix against unused matching blocks.

## ADFGX and ADFGVX

These combine coordinate substitution and columnar transposition.
ADFGX uses a 5×5 square; ADFGVX uses a 6×6 square for 36 symbols.
The ciphertext letters label coordinates rather than representing ordinary
plaintext letters directly.

Known-key decryption reverses the stages:

1. Undo the columnar transposition with the correct keyword and column lengths.
2. Split the restored coordinate stream into pairs.
3. Look up each pair in the keyed square.

Pairing the final transmitted text before undoing transposition generally fails.
An alphabet restricted to A, D, F, G, V, X is a useful clue, not proof.
Without keys, search and scoring must account for both the column order and
the square; cribs and related messages can constrain the problem.
This historical composition should not be used to protect modern data.

## Rotor machines

Rotor systems change their substitution as the machine steps. To decrypt an
Enigma example, identify the model, rotor order, ring settings, starting
positions, reflector, plugboard, and stepping behavior. Reset the simulator
before replaying a message; different starting states produce different text.

For standard reflector-based military Enigma, encryption is reciprocal at a
given state and a letter cannot encrypt to itself. A crib alignment containing
a same-position match can therefore be rejected for that model. Crib consistency
and known machine wiring constrain candidate settings; historical attacks also
benefited from operating procedures and repeated message structures.
This is not equivalent to solving Enigma through simple letter frequencies.

## XOR and reused pads

XOR is self-inverting: `(P XOR K) XOR K = P`. A fixed single-byte key has
only 256 possibilities. A repeated multi-byte key introduces a period that
can permit separate analysis of byte positions. XOR itself is an operation,
not evidence of either strong or weak encryption.

A true one-time pad requires a uniformly random, independent, secret pad as
long as the message, used once. It provides perfect secrecy for message content
under those assumptions; it does not hide length or authenticate the message.
A book passage or a human-generated string does not meet the random-pad requirement.

Reusing an XOR pad gives `C₁ XOR C₂ = P₁ XOR P₂` over the overlap.
This leaks a relationship, not automatically both complete messages.
Guessing a fragment of P₁ derives a corresponding candidate fragment of P₂.

**Original byte exercise:** ASCII `CAT` XOR ASCII `DOG` equals hex
`07 0e 13`. Any two ciphertexts produced from those texts with the same pad
have that same XOR. A guess of `CAT` derives `DOG`; other pairs are also
mathematically possible without language or contextual evidence.

## What changes with modern cryptography

Classical frequency analysis is not a general method for decrypting correctly
implemented modern encryption. A secure design aims to prevent useful plaintext
patterns from appearing in ciphertext.

| Topic | What to investigate | What not to infer |
| :--- | :--- | :--- |
| AES and stream ciphers | Mode, nonce/IV requirements, authentication, key handling | That English letter counts reveal the key |
| Password-protected files | File format, password-based KDF, authorized candidate guesses | That a weak password attack breaks the underlying cipher |
| RSA | Parameters, padding, key generation, implementation | That factoring a toy modulus demonstrates practical recovery of properly sized keys |
| Diffie–Hellman | Authentication and group/parameter validation | That key agreement by itself authenticates participants |
| Side channels | Timing, power, cache behavior, or other implementation leakage | That an implementation failure necessarily breaks the mathematical primitive |

For a hand-sized RSA example, take `p=5, q=11, n=55, e=3, d=27`.
Then `7³ mod 55 = 13`, and `13²⁷ mod 55 = 7`.
Factoring 55 exposes the parameters easily. This is textbook arithmetic only:
tiny primes and raw RSA are unsuitable for real data.

Continue with [Algorithms](../algorithms.md) and
[Applied Cryptography](../applied-crypto.md) for modern practice.

## Practice and answers

Use the page's A=0 convention. These are original exercises, not book excerpts.

| Exercise | Given | Task |
| :--- | :--- | :--- |
| 1 | Caesar ciphertext `SQZF` | Enumerate shifts; explain why a short candidate needs context |
| 2 | Affine `FVOS`, `a=5, b=8` | Decrypt with the inverse of 5 modulo 26 |
| 3 | `PCUNOTWMECPR`, three rows and four columns | Reverse column readout |
| 4 | `ZRUMMR`, repeating Vigenère key `KEY` | Subtract the key |
| 5 | Hill `TC`, matrix `[[3,3],[2,5]]` | Recover the plaintext using column vectors |
| 6 | Reused-pad ciphertext XOR `07 0e 13`; proposed first text `CAT` | Derive the corresponding second text |
| 7 | A fresh, secret, uniformly random pad used once | Explain why a ciphertext-only language attack cannot establish its plaintext |

<details>
<summary>Show answers</summary>

1. Shift 3 produces `PNWC`; the four-letter ciphertext alone does not establish
   that it is the intended solution.
2. `PNWC`, using `a⁻¹=21`.
3. `PNWCCOMPUTER`.
4. `PNWCIT`.
5. `HI`.
6. `DOG`. The proposed first plaintext is a hypothesis, not recovered evidence.
7. Every equal-length plaintext has a compatible pad. Under the OTP assumptions,
   observing the ciphertext does not update the prior probabilities of those
   plaintexts; it does not make all natural-language messages equally probable.

</details>

## Tools

| Tool | Use | Scope |
| :--- | :--- | :--- |
| [Repository Python toolkit](cipher_toolkit.py) | Existing Caesar, Atbash, Vigenère, and IC functions | Python 3; this workbook does not add new toolkit subcommands |
| [CrypTool-Online](https://www.cryptool.org/en/cto/) | Explore ciphers and frequency analysis interactively | Browser; use synthetic practice text |
| [CrypTool 2](https://www.cryptool.org/en/ct2/) | Visual workflows and classical cryptanalysis templates | Desktop; check its installation requirements |

Match alphabet, padding, key advancement, and route conventions when comparing
tools. Different preprocessing can produce different answers with the same key.

## Sources

- Panos Louridas, *Cryptography*, MIT Press, 2024:
  [publisher page](https://mitpress.mit.edu/9780262549028/cryptography/).
  Reading context; full-book coverage was not verified.
- Panos Louridas, [A History of Cryptography From the Spartans to the FBI](https://thereader.mitpress.mit.edu/a-history-of-cryptography-from-the-spartans-to-the-fbi/),
  MIT Press Reader. Public discussion of scytale, substitution, and polyalphabetic analysis.
- CrypTool Contributors: [Scytale](https://legacy.cryptool.org/en/cto/scytale),
  [Hill](https://legacy.cryptool.org/en/cto/hill),
  [ADFG(V)X](https://legacy.cryptool.org/en/cto/adfg-v-x), and
  [interactive tools](https://www.cryptool.org/en/cto/).
- [Bletchley Park Cryptographic Dictionary (1944), entry for crash](https://codesandciphers.org.uk/documents/cryptdict/page22.htm).
  Historical terminology for rejecting Enigma crib alignments.
- Dan Boneh and Victor Shoup, [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us/),
  author-hosted textbook, version 0.6, 2023. Further study of modern encryption,
  attack models, integrity, public-key systems, and protocols.
- Victor Shoup, [A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/),
  Cambridge University Press, second edition, 2008. Further study of modular
  arithmetic and algebra.

---

[Classical index](README.md) · [Cryptography index](../README.md) ·
[Master index](../../README.md) · [Legal notice](../../LEGAL.md)
