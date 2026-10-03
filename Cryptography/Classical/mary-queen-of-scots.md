# Mary, Queen of Scots: Ciphers, Codebreaking, and Compromised Letters

_Last reviewed: 2026-10-03_

[Classical index](README.md) · [Deciphering workbook](deciphering-workbook.md)

## Why this case matters

Mary Stuart's correspondence connects cipher design with the security of an
entire communication process. A message can be encrypted yet intercepted,
deciphered, altered, and delivered without the sender knowing.

There was no single universal “Mary, Queen of Scots cipher.” The National
Archives reports that more than 100 ciphers were among papers seized after
the discovery of the Babington Plot in 1586. A surviving cipher sheet uses
symbols for letters and entries for frequently mentioned names, including
political and religious figures. [1]

## Two different codebreaking stories

| Case | Correspondence | Decipherment |
| :--- | :--- | :--- |
| Babington Plot | Mary's correspondence with Anthony Babington in 1586 | Intercepted and deciphered during the plot by Thomas Phelippes, working for Francis Walsingham [2] |
| Rediscovered letters | A separate body of letters from 1578–1584, largely to French ambassador Michel de Castelnau | Research published in 2023 by George Lasry, Norbert Biermann, and Satoshi Tomokiyo [4][5] |

The 2023 research was not the first decipherment of the Babington Plot letters.
Do not use a key from one correspondence to explain another without evidence
that the same system and settings were used.

## How the cipher family works

A **nomenclator** combines letter substitution with code entries for whole
words or names. This describes the mixed letter-and-name structure visible
in the National Archives material. It is more than a Caesar shift. [1]

| Component | Function | Consequence for deciphering |
| :--- | :--- | :--- |
| Letter substitution | A symbol stands for a letter | Repeated patterns and language statistics can survive |
| Whole-word or name code | One entry stands for a longer expression | Treating every symbol as one letter gives incorrect results |
| Homophones, where present | Several symbols can stand for one letter | Single-symbol frequencies become less direct |
| Nulls, where present | An entry contributes no plaintext | Assuming every token must produce a letter distorts the message |

The last two rows explain general historical-cipher features to check for;
they are not a transcription of the Babington key. An exact reconstruction
must cite a particular key sheet and establish its symbol meanings and
special rules. This guide deliberately does not invent a historical alphabet.

**View an actual document:** the National Archives provides an image of
[ciphers used by Mary, c.1586, SP 53/22 f.1](https://www.nationalarchives.gov.uk/education/resources/elizabeth-monarchy/ciphers-used-by-mary-queen-of-scots/).
For the Babington correspondence specifically, the British Library article
includes an image of a cipher bearing Babington's signed acknowledgment. [2]

## The Babington Plot and Thomas Phelippes

In 1586, Walsingham's network controlled a concealed correspondence channel
using beer barrels. Letters were intercepted, opened, deciphered, resealed,
and forwarded. Phelippes deciphered Mary's letter to Babington dated
17 July 1586 and drew a gallows on its address leaf. [2]

The British Library describes amendments and an added postscript intended
to elicit the identities of the proposed assassins. That postscript must
not be presented as Mary's authenticated original wording. The Library also
identifies the displayed Gallows Letter as a contemporary copy; the original
sent to Babington was burned. [2]

Mary was tried for treason in October 1586 and executed at Fotheringhay
on 8 February 1587. [3]

### What we can and cannot infer about the attack

The archival accounts establish interception and Phelippes's decipherment.
They do not provide a complete, reproducible record of each statistical step
he used. Frequency analysis, repeated patterns, cribs, and codebook inference
are useful ways to study this cipher family, but the teaching workflow below
is not a claim to reproduce his exact historical procedure.

## A modern analysis workflow for this kind of document

1. **Identify the document and version.** Record the archive reference, date,
   language hypothesis, and whether the image is an original, copy, key,
   decipherment, or later transcription.
2. **Transcribe cautiously.** Assign stable labels such as S01 and S02 to
   distinct symbols. Preserve line breaks and mark uncertain readings.
   Similar handwriting does not prove two glyphs are the same symbol.
3. **Keep separate token classes.** Test whether a symbol is a letter,
   whole-word entry, separator, or special instruction. Do not discard
   an inconvenient symbol by simply declaring it a null.
4. **Analyze repetitions.** Compare symbol counts, repeated sequences,
   greeting formulas, endings, and probable names. Use language-appropriate
   expectations, allowing for historical spelling.
5. **Test candidate mappings globally.** A proposed name must fit grammar
   and all relevant occurrences. One attractive sentence is insufficient.
6. **Use related documents carefully.** A confirmed plaintext, surviving
   key, or parallel copy can constrain the mapping. Verify that the evidence
   actually belongs to the same system.
7. **Preserve ambiguity.** Distinguish certain readings from editorial
   expansions and guesses. Re-encryption checks consistency; it cannot prove
   that an intercepted message was never altered.

This workflow is an original teaching synthesis. For the mathematical tools,
see [Cryptanalysis](cryptanalysis.md) and the
[Deciphering Workbook](deciphering-workbook.md).

## Original practice example

**This miniature system is invented for this guide. It is not Mary's actual
cipher, a historical quotation, or a reconstruction of a surviving letter.**
Its separated numeric tokens make the mixed system easy to inspect.

| Token | Meaning |
| :--- | :--- |
| 11 | M |
| 12 or 42 | E |
| 13 | T |
| 14 | A |
| 15 | G |
| 80 | THE |
| 90 | MARY |
| 00 | Null: omit during decryption |
| / | Word boundary |

Decode:

```text
11 12 42 13 / 90 / 14 13 / 80 / 15 14 13 00 12
```

<details>
<summary>Show the worked answer</summary>

1. `11 12 42 13` gives `MEET`; the two E symbols differ.
2. `90` expands to the whole name `MARY`.
3. `14 13` gives `AT`.
4. `80` expands to `THE`.
5. `15 14 13 00 12` gives `GATE` after omitting the defined null.

Plaintext: **MEET MARY AT THE GATE**.

A one-symbol-to-one-letter solver would mishandle 80 and 90. An ordinary
permutation solver would also reject the two different tokens for E.
The message is too short to justify reliable frequency-only recovery.

</details>

**Integrity exercise:** Change token 90's codebook meaning to another person's
name. The ciphertext can still be perfectly well-formed. Syntax and successful
decoding alone do not authenticate the intended sender or the original message.

## The letters deciphered in 2023

Lasry, Biermann, and Tomokiyo published *Deciphering Mary Stuart's lost letters
from 1578–1584* in *Cryptologia* in February 2023. Their work concerns documents
in the Bibliothèque nationale de France, including correspondence with
Castelnau. The paper describes transcription and computer-assisted analysis
that recovered French plaintext. [4]

CrypTool's project report emphasizes the combination of simulated annealing
and extensive manual work, lasting more than a year. This is a useful
counterexample to the idea that every old cipher falls instantly to a frequency
counter. Recognizing symbols, testing language hypotheses, and resolving
historical references matter alongside automated search. [5]

## Lessons for modern security

These are present-day interpretations, not claims that Tudor correspondents
used modern security terminology:

- **Confidentiality:** Can an interceptor read the message?
- **Integrity:** Can someone modify it without detection?
- **Authentication:** Can the recipient verify who produced it?
- **Channel security:** Who handles, copies, delays, or replaces it in transit?
- **Evidence quality:** Which version survives, and whose interventions does
  it contain?

Encryption alone does not answer all five questions. Continue with
[Applied Cryptography](../applied-crypto.md) for modern authenticated encryption,
key management, and protocol guidance.

## Sources and further reading

1. The National Archives,
   [Ciphers used by Mary Queen of Scots](https://www.nationalarchives.gov.uk/education/resources/elizabeth-monarchy/ciphers-used-by-mary-queen-of-scots/).
   Archival cipher sheet, c.1586, SP 53/22 f.1, and explanatory notes.
2. Alan Bryson, British Library,
   [The Gallows Letter](https://www.bl.uk/stories/blogs/posts/the-gallows-letter),
   5 February 2022. Interception, Phelippes, documentary copies, and alterations.
3. National Museums Scotland,
   [Life and deathline of Mary, Queen of Scots](https://www.nms.ac.uk/discover-catalogue/life-and-deathline-of-mary-queen-of-scots).
   Chronology of the plot, trial, and execution.
4. George Lasry, Norbert Biermann, and Satoshi Tomokiyo,
   [Deciphering Mary Stuart's lost letters from 1578–1584](https://doi.org/10.1080/01611194.2022.2160677),
   *Cryptologia* 47(2), 101–202, 2023. Original research.
5. Nils Kopal, CrypTool,
   [Report on the Mary Stuart decipherment](https://www.cryptool.org/en/posts/marystuartciphers/),
   7 February 2023. Includes a link to George Lasry's research talk.

---

[Classical index](README.md) · [Cryptography index](../README.md) ·
[Master index](../../README.md) · [Legal notice](../../LEGAL.md)
