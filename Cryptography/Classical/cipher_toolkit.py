#!/usr/bin/env python3
"""cipher_toolkit.py - leetspeak, Unicode styles, classical ciphers & IC analysis.
Usage examples:
  python3 cipher_toolkit.py leet "hacker" --tier 2
  python3 cipher_toolkit.py style "hacker" fraktur
  python3 cipher_toolkit.py vigenere "HIDDEN" KEY
  python3 cipher_toolkit.py ic-scan "<ciphertext>"
"""
import random, string, sys, unicodedata
from collections import Counter

A = string.ascii_uppercase

LEET = {
    1: {"A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7"},
    2: {"A": "4", "B": "8", "E": "3", "G": "6", "I": "1", "L": "1",
        "O": "0", "S": "5", "T": "7", "Z": "2"},
    3: {"A": "/-\\", "B": "|3", "C": "(", "D": "|)", "E": "3", "F": "|=",
        "G": "6", "H": "|-|", "I": "!", "J": "_|", "K": "|<", "L": "|_",
        "M": "|\\/|", "N": "/\\/", "O": "()", "P": "|*", "Q": "(,)",
        "R": "|2", "S": "5", "T": "+", "U": "|_|", "V": "\\/",
        "W": "\\/\\/", "X": "><", "Y": "'/", "Z": "7_"},
}

def leet(text, tier=2, chaos=1.0, seed=None):
    """Replace letters using a tier map. chaos<1.0 replaces only some letters."""
    rng = random.Random(seed)
    table = LEET[tier]
    out = []
    for ch in text:
        sub = table.get(ch.upper())
        out.append(sub if sub and rng.random() < chaos else ch)
    return "".join(out)

STYLES = {
    "fullwidth": ["FULLWIDTH LATIN CAPITAL LETTER {}"],
    "circled":   ["CIRCLED LATIN CAPITAL LETTER {}"],
    "squared":   ["SQUARED LATIN CAPITAL LETTER {}"],
    "bold":      ["MATHEMATICAL BOLD CAPITAL {}"],
    "script":    ["MATHEMATICAL SCRIPT CAPITAL {}", "SCRIPT CAPITAL {}"],
    "fraktur":   ["MATHEMATICAL FRAKTUR CAPITAL {}", "BLACK-LETTER CAPITAL {}"],
    "double":    ["MATHEMATICAL DOUBLE-STRUCK CAPITAL {}", "DOUBLE-STRUCK CAPITAL {}"],
    "mono":      ["MATHEMATICAL MONOSPACE CAPITAL {}"],
    "smallcaps": ["LATIN LETTER SMALL CAPITAL {}"],
}

def style_char(c, style):
    for pattern in STYLES[style]:
        try:
            return unicodedata.lookup(pattern.format(c))
        except KeyError:
            pass
    return c  # no glyph exists (e.g. small-cap X) -> leave as-is

def style(text, name):
    return "".join(style_char(c.upper(), name) if c.upper() in A else c for c in text)

def caesar(text, shift):
    return "".join(A[(A.index(c) + shift) % 26] if c in A else c for c in text.upper())

def atbash(text):
    return "".join(A[25 - A.index(c)] if c in A else c for c in text.upper())

def vigenere(text, key, decrypt=False):
    key = [A.index(k) for k in key.upper() if k in A]
    out, i = [], 0
    for c in text.upper():
        if c in A:
            k = -key[i % len(key)] if decrypt else key[i % len(key)]
            out.append(A[(A.index(c) + k) % 26]); i += 1
        else:
            out.append(c)
    return "".join(out)

def keyed_alphabet(keyword):
    """Keyword cipher alphabet: keyword letters (deduped) then the rest of A-Z."""
    seen = []
    for c in keyword.upper() + A:
        if c in A and c not in seen:
            seen.append(c)
    return "".join(seen)

def ic(text):
    letters = [c for c in text.upper() if c in A]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))

def ic_scan(ciphertext, max_len=12):
    """Average IC of each column for key lengths 1..max_len."""
    letters = "".join(c for c in ciphertext.upper() if c in A)
    results = []
    for L in range(1, max_len + 1):
        cols = [letters[i::L] for i in range(L)]
        results.append((L, sum(ic(c) for c in cols) / L))
    return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, text = sys.argv[1], sys.argv[2]
    if cmd == "leet":
        tier = int(sys.argv[4]) if "--tier" in sys.argv else 2
        print(leet(text, tier))
    elif cmd == "style":
        print(style(text, sys.argv[3]))
    elif cmd == "rot13":
        print(caesar(text, 13))
    elif cmd == "atbash":
        print(atbash(text))
    elif cmd == "vigenere":
        print(vigenere(text, sys.argv[3]))
    elif cmd == "ic-scan":
        for L, v in ic_scan(text):
            print(f"{L:>2}  {v:.4f}  {'#' * int(v * 600)}")
    else:
        sys.exit(__doc__)
