# Hex & ASCII Field Reference & Offline Labs

**Prerequisites:** [Hexadecimal](./hexadecimal-and-binary-analysis.md) & [ASCII](./ascii-and-character-encoding.md).

> [!CAUTION]
> All labs use invented data on your own computer, without external traffic or real credentials. Run in a new disposable directory. Never modify original evidence.

## Quick Conversion & Inspection

| Need | Command Or Tool |
|---|---|
| Dump bytes | `xxd -g 1 FILE` or `hexdump -C FILE` |
| Read 4 bytes at offset 8 | `xxd -g 1 -s 8 -l 4 FILE` |
| Binary to plain hex | `xxd -p FILE` |
| Plain hex to binary | `xxd -r -p INPUT.hex > NEW.bin` |
| Windows byte view | `Format-Hex -Path FILE` |
| Printable strings with hex offsets (GNU) | `strings -a -t x -n 4 FILE` |
| UTF-16LE candidate strings (GNU) | `strings -a -e l -t x -n 4 FILE` |
| Byte comparison | `cmp -l ORIGINAL COPY` (1-based positions, octal values) |
| Python hex to bytes | `bytes.fromhex("41 42")` |
| Python bytes to hex | `b"AB".hex(" ")` |
| Python safe text display | `repr(raw.decode("ascii", errors="backslashreplace"))` (display only; preserve raw) |
| GUI editing | ImHex, HxD, Hex Fiend; overwrite on a working copy |
| Capture analysis | Wireshark Packet Bytes pane; select fields and inspect hex + ASCII |

## Complete ASCII Lookup Table

Decimal and hexadecimal values for the entire 7-bit ASCII range. SP = space; PIPE = vertical bar; GRAVE = backtick; BACKSLASH = reverse solidus. Control names are abbreviations.

| Dec | Hex | ASCII | Dec | Hex | ASCII | Dec | Hex | ASCII | Dec | Hex | ASCII |
|---:|---|---|---:|---|---|---:|---|---|---:|---|---|
| 0 | 00 | NUL | 32 | 20 | SP | 64 | 40 | @ | 96 | 60 | GRAVE |
| 1 | 01 | SOH | 33 | 21 | ! | 65 | 41 | A | 97 | 61 | a |
| 2 | 02 | STX | 34 | 22 | " | 66 | 42 | B | 98 | 62 | b |
| 3 | 03 | ETX | 35 | 23 | # | 67 | 43 | C | 99 | 63 | c |
| 4 | 04 | EOT | 36 | 24 | $ | 68 | 44 | D | 100 | 64 | d |
| 5 | 05 | ENQ | 37 | 25 | % | 69 | 45 | E | 101 | 65 | e |
| 6 | 06 | ACK | 38 | 26 | & | 70 | 46 | F | 102 | 66 | f |
| 7 | 07 | BEL | 39 | 27 | ' | 71 | 47 | G | 103 | 67 | g |
| 8 | 08 | BS | 40 | 28 | ( | 72 | 48 | H | 104 | 68 | h |
| 9 | 09 | HT | 41 | 29 | ) | 73 | 49 | I | 105 | 69 | i |
| 10 | 0A | LF | 42 | 2A | * | 74 | 4A | J | 106 | 6A | j |
| 11 | 0B | VT | 43 | 2B | + | 75 | 4B | K | 107 | 6B | k |
| 12 | 0C | FF | 44 | 2C | , | 76 | 4C | L | 108 | 6C | l |
| 13 | 0D | CR | 45 | 2D | - | 77 | 4D | M | 109 | 6D | m |
| 14 | 0E | SO | 46 | 2E | . | 78 | 4E | N | 110 | 6E | n |
| 15 | 0F | SI | 47 | 2F | / | 79 | 4F | O | 111 | 6F | o |
| 16 | 10 | DLE | 48 | 30 | 0 | 80 | 50 | P | 112 | 70 | p |
| 17 | 11 | DC1 | 49 | 31 | 1 | 81 | 51 | Q | 113 | 71 | q |
| 18 | 12 | DC2 | 50 | 32 | 2 | 82 | 52 | R | 114 | 72 | r |
| 19 | 13 | DC3 | 51 | 33 | 3 | 83 | 53 | S | 115 | 73 | s |
| 20 | 14 | DC4 | 52 | 34 | 4 | 84 | 54 | T | 116 | 74 | t |
| 21 | 15 | NAK | 53 | 35 | 5 | 85 | 55 | U | 117 | 75 | u |
| 22 | 16 | SYN | 54 | 36 | 6 | 86 | 56 | V | 118 | 76 | v |
| 23 | 17 | ETB | 55 | 37 | 7 | 87 | 57 | W | 119 | 77 | w |
| 24 | 18 | CAN | 56 | 38 | 8 | 88 | 58 | X | 120 | 78 | x |
| 25 | 19 | EM | 57 | 39 | 9 | 89 | 59 | Y | 121 | 79 | y |
| 26 | 1A | SUB | 58 | 3A | : | 90 | 5A | Z | 122 | 7A | z |
| 27 | 1B | ESC | 59 | 3B | ; | 91 | 5B | [ | 123 | 7B | { |
| 28 | 1C | FS | 60 | 3C | < | 92 | 5C | BACKSLASH | 124 | 7C | PIPE |
| 29 | 1D | GS | 61 | 3D | = | 93 | 5D | ] | 125 | 7D | } |
| 30 | 1E | RS | 62 | 3E | > | 94 | 5E | ^ | 126 | 7E | ~ |
| 31 | 1F | US | 63 | 3F | ? | 95 | 5F | _ | 127 | 7F | DEL |

## Lab 1 — Create, Parse & Edit A Synthetic Binary Record

Requires Python 3.8+; save as lab.py in an empty directory. The invented format uses magic LAB1 (4 bytes), version (1), flags (1), little-endian payload length (2), payload (variable), then a fixed four-byte trailer. The following parser rejects inconsistent lengths and unexpected magic/version/trailer, and enforces a toy maximum payload length. It does not represent a production protocol.

```python
from pathlib import Path
import hashlib
import struct

def parse(data):
    if len(data) < 12:
        raise ValueError("truncated record")
    magic, version, flags, length = struct.unpack_from("<4sBBH", data)
    if magic != b"LAB1" or version != 1 or flags != 0:
        raise ValueError("invalid header")
    if length > 256 or len(data) != 8 + length + 4:
        raise ValueError("invalid length")
    if data[-4:] != bytes.fromhex("0d 0a 00 ff"):
        raise ValueError("invalid trailer")
    return data[8:8 + length]

original = bytes.fromhex("4c 41 42 31 01 00 04 00 54 45 53 54 0d 0a 00 ff")
assert parse(original) == b"TEST"
edited = bytearray(original)
edited[8] = 0x42
assert parse(edited) == b"BEST"
assert len(edited) == len(original) == 16
assert [i for i, (a, b) in enumerate(zip(original, edited)) if a != b] == [8]

for name, data in [("lab-original.bin", original), ("lab-edited.bin", edited)]:
    with Path(name).open("xb") as f:  # Refuse to overwrite
        f.write(data)
    print(name, hashlib.sha256(data).hexdigest())

for invalid in (original[:-1], original[:6] + b"\xff\xff" + original[8:]):
    try:
        parse(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed fixture was accepted")
print("PASS: round-trip interpretation, one-byte edit, malformed-input rejection")
```

Run `python lab.py` (or python3). Expected: two distinct 64-digit SHA-256 values and PASS. Re-running in the same directory intentionally fails rather than overwriting fixtures. GUI and CLI exercises in the companion guides use these files.

## Lab 2 — Safe Character Encoding Validation

```python
import unicodedata

samples = [b"ABC", b"", "é".encode("utf-8"), b"e\xcc\x81", b"\xff", b"A\x00B"]
for raw in samples:
    try:
        text = raw.decode("utf-8", errors="strict")
        normalized = unicodedata.normalize("NFC", text)
        print(raw.hex(), len(raw), len(text), repr(normalized))
    except UnicodeDecodeError:
        print(raw.hex(), "invalid UTF-8")
```

Expected: C3 A9 is two bytes but one code point; 65 CC 81 is three bytes and two code points before NFC; FF is rejected; NUL is valid UTF-8 but may be disallowed by the application. Use the application specification to decide acceptance.

## Lab 3 — Byte & Text Detection With YARA

Save as lab-marker.yar and run with an installed classic YARA CLI. This toy rule identifies the specific 16-byte original fixture and does not represent malware.

```yara
rule PNWC_Lab_Record {
    strings:
        $magic = { 4C 41 42 31 01 00 04 00 }
        $text = "TEST" ascii
        $trailer = { 0D 0A 00 FF }
    condition:
        filesize == 16 and $magic at 0 and $text at 8 and $trailer at 12
}
```

```bash
yara lab-marker.yar lab-original.bin
yara lab-marker.yar lab-edited.bin
```

Expected: the first emits PNWC_Lab_Record and the second has no match. A tool error is not a negative match. Test a benign unrelated fixture too. In real detection engineering, measure false positives, version compatibility, and context. See [YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html) and [YARA-X lab](../ReverseEngineering/yara-x-rule-lab.md).

## Lab 4 — Packet Bytes Without Live Network Traffic

1. In Wireshark, open a trusted authorized training capture already available locally, or use File → Import from Hex Dump with the following invented Ethernet frame in a text file. Select the Ethernet encapsulation type and no dummy headers; offsets are hexadecimal.
```text
000000 02 00 00 00 00 02 02 00 00 00 00 01 08 00 45 00
000010 00 20 00 01 00 00 40 11 f6 c8 c0 00 02 01 c0 00
000020 02 02 27 10 27 11 00 0c 00 00 54 45 53 54
```
2. Select the imported packet. Expand Ethernet, IPv4 and UDP in Packet Details. Inspect the highlighted bytes. The documentation-only IPs are 192.0.2.1 and 192.0.2.2, UDP ports 10000 and 10001, and payload TEST. The IPv4 header declares 32 bytes; UDP length is 12; zero UDP checksum is permitted for IPv4. The synthetic capture omits Ethernet padding and FCS.
3. Compare raw and interpreted data. Locate TEST at frame offset 42 (0x2A). Try display filter `udp.dstport == 10001`; do not confuse display filters with capture filters.
4. Save the synthetic capture separately if needed. Do not transmit it. See [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/) and [master filters](../Documentation/wireshark-master-filters.md).

## Evidence & Reporting Checklist

| Record | Why |
|---|---|
| File or capture identifier, SHA-256, acquisition time (UTC) | Provenance and integrity checks |
| Offset, length and coordinate system | Reproducible location |
| Raw byte excerpt, interpreted value, encoding/endianness | Separate observation from interpretation |
| Tool name/version and transformation steps | Repeatability |
| Expected vs observed, limitations, positive/negative tests | Distinguish a finding from a hypothesis |
| Working-copy hash and precise changed offsets | Trace edits without altering original evidence |

## Related Guides

| Guide | Focus |
|---|---|
| [Hexadecimal & Binary Analysis](./hexadecimal-and-binary-analysis.md) | Hex editors, format interpretation |
| [ASCII & Character Encoding](./ascii-and-character-encoding.md) | Text, Unicode and validation |
| [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md) | Evidence handling |
| [Cryptography](../Cryptography/README.md) | Digests and representations |
| [Reverse Engineering](../ReverseEngineering/README.md) | Binary inspection |
| [Web Application Security](../WebAppSecurity/README.md) | Input validation |
| [Hardware Hacking](../HardwareHacking/README.md) | Firmware and UART |

---
[⬅️ Algorithms Index](./README.md) | [Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
