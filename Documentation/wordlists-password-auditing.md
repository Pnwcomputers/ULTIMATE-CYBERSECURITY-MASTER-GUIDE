# Wordlists, Candidate Generation & Ethical Password Auditing

_Reference review: 2026-11-21. Commands use fictional words; no external corpora were downloaded._

> [!CAUTION]
> **Authorized use only.** Leaked password corpora can contain sensitive data. Do not scrape people, collect real credentials, or run candidate lists against live accounts without independent written authorization. See [Legal Notice](../LEGAL.md).

## Purpose & Concepts

A **wordlist** holds candidate strings. **Rules** transform entries, **masks** enumerate constrained character sets, and **combinators** join parts. **Rainbow tables** instead precompute hash-chain lookup material; do not conflate the two. Offline candidate auditing is distinct from online password guessing.

## Relevant Tools & Sources

| Project | Role | Status / Safety Boundary |
|---|---|---|
| [SecLists](https://github.com/danielmiessler/SecLists) | Broad security-test wordlist/reference collection | Review license and sensitive subsets; do not automatically download entire collection |
| [Crunch](https://www.kali.org/tools/crunch/) | Generate bounded pattern-based candidates | Huge keyspace/disk requirements; run against synthetic data |
| [CeWL](https://github.com/digininja/CeWL) | Build dictionary candidates from web content | Crawl only an owned test website |
| [CUPP](https://github.com/Mebus/cupp) | Profile-based password candidate modeling | Use entirely fictional profiles; privacy risk |
| [John the Ripper](https://github.com/openwall/john) | Offline format handling, rules & recovery | Jumbo/core commands and capabilities differ |
| [Hashcat](https://hashcat.net/hashcat/) | Rules/masks & offline hash auditing | See [Hashcat Guide](./hashcat-guide.md) |
| [Pipal](https://github.com/digininja/pipal) | Password dataset statistics | Only approved, non-public data in isolated environment |
| [Weakpass](https://weakpass.com/) | External corpus catalog | Potentially sensitive breached material; review before accessing |
| [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) | Password policy & compromised-password checks | Prefer policy controls over aggressive guessing |

## Small, Synthetic Dictionary Lab

```bash
mkdir -p ./wordlist-lab && cd ./wordlist-lab
cat > tiny-demo.txt <<'EOF'
TrainingPass-A
TrainingPass-B
TrainingPass-A
TestOnly-C
EOF
LC_ALL=C sort -u tiny-demo.txt > unique-demo.txt
wc -l tiny-demo.txt unique-demo.txt
sha256sum unique-demo.txt
```

Sorting removes duplicate entries but alters order and destroys observed frequency. Preserve source data separately if it has evidentiary value. Always document encoding, Unicode normalization, line endings and locale.

## How Quickly Candidates Grow

```python
for n in (4, 8):
    count = 10 ** n  # Decimal digits only
    print(f'{n} digits -> {count:,} combinations')
```

These are mathematical search-space sizes, not projected cracking speeds. Salts, cost parameters, hardware and memory requirements change throughput.

## Candidate Generator Checklist

| Stage | Required Check |
|---|---|
| Source | Origin, ownership, permission, license |
| Format | UTF-8, normalization, line endings |
| Size | Count before executing or storing |
| Hygiene | Duplicates, hidden sensitive values, PII |
| Storage | Encrypted workspace and restricted access |
| Testing | Synthetic lab target and exact stop budget |
| Reporting | Aggregate statistics rather than recovered plaintext |
| Disposal | Secure retention schedule and derivative cleanup |

### Read-Only Tool Orientation

```bash
crunch --help 2>&1 | head -n 25
cewl --help 2>&1 | head -n 25
john --help 2>&1 | head -n 25
hashcat --help 2>&1 | head -n 25
```

Only execute commands for tools installed from vetted sources. Version, package and option behavior vary; **do not presume the help syntax above will work identically on every build**.

## Safer Defensive Alternatives

Rather than importing leaked lists into a production network, use a reputable breached-password screening service with an appropriate privacy design, long unique passwords, passkeys, rate limiting and phishing-resistant MFA. Use parameterized, salted, memory-hard password hashing for storage; never store reversible passwords in test reports.

## Related Guides & Sources

| Guide | Purpose |
|---|---|
| [Hashcat](./hashcat-guide.md) | Offline test workflow |
| [Rainbow Tables](./rainbow-tables-guide.md) | Precomputation limitations |
| [Hydra](../Tradecraft/hydra-guide.md) | Separate online-authentication risk and controls |
| [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | Authentication policy |
| [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Implementation |

---

[Documentation Index](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
