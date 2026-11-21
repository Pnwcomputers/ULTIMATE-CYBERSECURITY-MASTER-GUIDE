# Rainbow Tables, Precomputed Lookups & Modern Password-Hash Protection

_Reference review: 2026-11-21. No real-user tables were generated or distributed._

> [!CAUTION]
> **Authorized research only.** Never obtain or share tables containing unauthorized real-user credential material. The examples use fictional values and explain defensive design. See [Legal Notice](../LEGAL.md).

## Purpose & Theory

A **rainbow table** is a **time–memory tradeoff** approach for password-hash recovery over a known search space. It builds chains of candidate generation, hashing and reduction; storing chain endpoints can save memory compared with storing every candidate and hash pair. Reconstructing chains at lookup time trades compute time for reduced storage. Tables cannot reliably cover arbitrary passwords or algorithm parameters, and collisions create additional lookup work.

A rainbow table is **not** a wordlist, an offline password dictionary, an exhaustive database or Hashcat's newer *table attack* candidate generator. See the [Wordlist Guide](./wordlists-password-auditing.md).

## Comparison

| Method | Reusable Precomputation? | Storage & Cost | Salt Resistance |
|---|---|---|---|
| Plain candidate list | No hash precomputation | Store candidates | Must recompute each salted hash |
| Direct precomputed hash lookup | Yes | High storage, fast lookup | Unique salts break reuse |
| Rainbow chains | Yes | Reduced storage vs full table; lookup compute | Unique salts break useful amortization |
| Rules & masks | Candidates computed at runtime | Low disk; compute intensive | Each hash still requires work |
| Modern password KDF | Defensive salted, costly derivation | Cost per guess | Designed to resist precomputation |

## Minimal Toy Illustration

This is an explicit hash-to-word dictionary, **not** an implementation of rainbow chains. It demonstrates why a fixed unsalted digest lets the same attacker work be reused.

```python
import hashlib
words = ('sample-a', 'sample-b', 'sample-c')
lookup = {hashlib.sha256(w.encode()).hexdigest(): w for w in words}
target = hashlib.sha256(b'sample-b').hexdigest()
assert lookup[target] == 'sample-b'
print('Synthetic unsalted digest matched a precomputed entry')
```

For the same password, salts should be random and distinct per record:

```python
import hashlib
password = b'sample-b'
a = hashlib.sha256(b'illustrative-salt-A' + password).hexdigest()
b = hashlib.sha256(b'illustrative-salt-B' + password).hexdigest()
assert a != b
```

**Important:** `SHA256(salt + password)` is for concept illustration **only** and is **not** a secure production password-storage construction. Use Argon2id, scrypt or appropriately configured PBKDF2 through vetted libraries.

## Tool & Historical Context

| Resource | What It Covers | Caveat |
|---|---|---|
| [RainbowCrack Project](http://project-rainbowcrack.com/) | Historical rainbow-chain approach | Legacy software/docs; independently verify availability |
| [rainbowcrackalack](https://github.com/jtesta/rainbowcrackalack) | Time–memory tradeoff research | Specialist and historically targeted formats |
| [Hashcat](./hashcat-guide.md) | Modern offline candidate evaluation | Not a rainbow table implementation |
| [John the Ripper](https://github.com/openwall/john) | Alternative offline auditing | Not a substitute for salts or a proper KDF |

## Why Modern Defenses Work

A unique per-user salt means an attacker cannot reuse one unsalted precomputation table across all users. A slow, tunable and preferably memory-hard password KDF increases the cost of every guess. The defender must additionally control credential exposure, phishing, session theft and online rate limits; strong hashing **cannot** protect a password that was directly stolen.

## Assessment Checklist

| Question | Evidence |
|---|---|
| Is a raw unsalted digest used for login password storage? | Source/config and schema review |
| Are salts unique and randomly generated? | Verified KDF implementation and per-record fields |
| Is the algorithm fit for passwords? | Argon2id/scrypt/PBKDF2 design and parameters |
| Is hash migration planned? | Versioned records and transparent upgrade strategy |
| Are resets and breach handling defined? | Incident plan and retest results |

## Related References

- [Hashcat](./hashcat-guide.md)
- [Wordlists & Candidate Generation](./wordlists-password-auditing.md)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63](https://pages.nist.gov/800-63-4/)

---

[Documentation Index](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
