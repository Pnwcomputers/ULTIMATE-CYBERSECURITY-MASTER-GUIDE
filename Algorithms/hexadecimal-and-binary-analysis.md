# Hexadecimal & Binary Data Analysis

*Part of the [Algorithms & Computational Foundations](./README.md) section.*

> [!CAUTION]
> Work only with authorized captures, firmware, binaries and lab fixtures. Preserve original evidence and modify copies. See [LEGAL.md](../LEGAL.md).

## Purpose & Learning Outcomes

Hexadecimal (hex) is base 16, a compact way of representing numbers and raw bytes. Security practitioners use it to read data that does not have a meaningful text representation: packet headers, executable files, memory, firmware, hashes and binary protocol messages. Hex is not a programming language, encryption or a file format by itself.

## Number Systems & Byte Representation

| Decimal | Binary (8 Bits) | Hex | ASCII Meaning |
|---:|---|---|---|
| 0 | 00000000 | 00 | NUL |
| 10 | 00001010 | 0A | LF |
| 15 | 00001111 | 0F | SI |
| 16 | 00010000 | 10 | DLE |
| 32 | 00100000 | 20 | Space |
| 65 | 01000001 | 41 | A |
| 127 | 01111111 | 7F | DEL |
| 255 | 11111111 | FF | Outside ASCII |

Digits are 0–9 and A–F (values 10–15). Four bits form a nibble; two nibbles form one byte. One byte ranges from 0x00 to 0xFF (0–255 unsigned). For example, 0xAF = 10 × 16 + 15 = 175. Conversely, 175 divided by 16 yields quotient 10 and remainder 15 → AF. Hex case does not change numeric value.

Common notation: `0x41` is a numeric literal, `41` is a pair of hex digits, and `\x41` is a byte escape in languages that support that syntax. Literal text "41" consists of bytes 34 31, whereas decoding it as hex yields a single byte 41.

## Reading A Hex Dump

```text
Offset    Bytes (hex)                                       ASCII
00000000  4c 41 42 31 01 00 04 00 54 45 53 54 0d 0a 00 ff   LAB1....TEST....
          | magic   | |flags/len| | payload  | | trailer |
```

The offset is the zero-based byte position (not necessarily a memory address). Each pair is one byte. The right column is a printable representation of those same bytes, not extra file content. Dots usually represent nonprintable or non-ASCII bytes; a literal dot (2E) also looks like a dot. A row of 16 bytes advances the offset by 0x10. The sample's bytes at offset 0x08 through 0x0B spell TEST.

In a typical editor, selecting a byte highlights its position in both views. Use a data inspector to interpret a selection as a signed/unsigned integer, float or text; correct interpretation depends on width, byte order and the actual format specification.

## Endianness, Addresses & Bit Fields

| Interpretation | Bytes | Result |
|---|---|---|
| Unsigned 16-bit big endian | 12 34 | 0x1234 = 4660 |
| Unsigned 16-bit little endian | 12 34 | 0x3412 = 13330 |
| Unsigned 8-bit | FF | 255 |
| Signed two's complement 8-bit | FF | -1 |
| IPv4 address octets | C0 00 02 01 | 192.0.2.1 (documentation address) |

Big endian stores the most significant byte first; little endian stores the least significant byte first. Network byte order conventionally means big endian, but individual protocols can specify otherwise. Bit numbering is a separate convention. A file offset, virtual address, physical address and relative virtual address are different coordinate systems; consult the loader or file mapping before translating them.

Flags: for 0xA5 (binary 10100101), mask 0x04 tests bit 2 when the least significant bit is bit 0. `value & 0x04` is nonzero; `value | 0x02` sets bit 1 and `value & ~0x04` clears bit 2. Interpret reserved bits and field widths using the format's specification.

## File Signatures & Structural Analysis

| Format | Typical Initial Bytes | Qualification |
|---|---|---|
| PNG | 89 50 4E 47 0D 0A 1A 0A | Eight-byte signature |
| PDF | 25 50 44 46 2D | %PDF- header; validate structure |
| ZIP | 50 4B 03 04 | Common local file header; empty ZIP can begin differently |
| ELF | 7F 45 4C 46 | ELF identification; inspect class and byte order |
| PE/DOS | 4D 5A | MZ alone is insufficient to prove a valid PE |
| gzip | 1F 8B | Check method and remaining structure |

Signatures are clues, not proof of validity or maliciousness. Use format parsers, sizes, offsets, checksums and corroborating metadata. Compressed and encrypted data may both look random; entropy cannot reliably distinguish them alone.

## Tools & Practical Selection

| Tool | Platform & Purpose |
|---|---|
| [ImHex](https://github.com/WerWolv/ImHex) | Windows/Linux/macOS; hex editor, data inspector, pattern-based structure analysis |
| [HxD](https://mh-nexus.de/en/hxd/) | Windows; file hex editing, byte search and comparison |
| [Hex Fiend](https://hexfiend.com/) | macOS; large file editing and comparison |
| [GHex](https://gitlab.gnome.org/GNOME/ghex) | Linux/GNOME; graphical hex editing |
| [wxHexEditor](https://github.com/EUA/wxHexEditor) | Cross-platform source project; large binary inspection; check current build support |
| [xxd](https://vimhelp.org/xxd.txt.html) / hexdump / od | CLI byte dumps and conversion; availability depends on OS/packages |
| [Wireshark](https://www.wireshark.org/docs/wsug_html_chunked/ChUsePacketBytesPaneSection.html) | Packet byte inspection, protocol-field highlighting, reassembly views |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Binary disassembly, decompilation and bytes/memory inspection |
| [CyberChef](https://github.com/gchq/CyberChef) | Local/offline data transformation; From Hex, To Hex and parsing |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware signature analysis; use an isolated environment for extraction |
| [Python](https://docs.python.org/3/library/stdtypes.html#bytes) | Reproducible parsing, conversion and controlled editing |

Install from official packages or releases. For sensitive data use local tools, not public web converters; verify downloaded executables and review permissions.

## GUI Workflow: Inspect, Search & Edit

1. Create the synthetic file in the [field lab](./hex-ascii-field-reference.md). Keep the original untouched, record a SHA-256 digest, and open the working copy in ImHex, HxD or Hex Fiend.
2. Inspect the offset, hex and text columns. Jump to offset 0x08 (check whether the dialog expects decimal or hex). Select four bytes and search for hex `54 45 53 54` or text TEST. Confirm the match offset.
3. Select the two length bytes at 0x06; interpret as unsigned little-endian 16-bit value 4. Compare to big endian (1024).
4. Enable overwrite rather than insert mode, replace TEST with BEST (change 54 to 42 at offset 0x08), and Save As a new file.
5. Reopen, compare the original and edited file and verify the size is unchanged and precisely one byte changed. Record offset, before/after bytes and both hashes.

Insert mode shifts subsequent offsets; overwrite preserves length when replacing equal-length data. Real formats may contain length fields, offsets, CRCs, digital signatures and compressed regions. A change can break them, and a valid checksum does not authenticate a file. Do not patch production executables, live memory, disks or firmware with this exercise.

## CLI & Python Workflows

Run the following on the invented fixture in a dedicated lab folder. `xxd` may require a Vim/xxd package; `sha256sum` is GNU/Linux, while macOS commonly has `shasum -a 256`.

```bash
xxd -g 1 lab-original.bin
xxd -g 1 -s 8 -l 4 lab-original.bin
hexdump -C lab-original.bin
od -Ax -tx1 -v lab-original.bin
xxd -p lab-original.bin > lab.hex
xxd -r -p lab.hex > lab-roundtrip.bin
cmp lab-original.bin lab-roundtrip.bin
sha256sum lab-original.bin lab-roundtrip.bin
```

`xxd -r -p` expects plain hex; do not feed arbitrary annotated dumps to it. Redirect only to new output files. In PowerShell, `Format-Hex -Path .\lab-original.bin` displays bytes and `Get-FileHash -Algorithm SHA256 .\lab-original.bin` calculates the digest.

```python
import struct
raw = bytes.fromhex("4c 41 42 31 01 00 04 00 54 45 53 54 0d 0a 00 ff")
assert raw[8:12] == b"TEST"
assert int.from_bytes(raw[6:8], "little") == 4
assert struct.unpack_from("<H", raw, 6)[0] == 4
print(raw.hex(" "))
print(f"Offset 0x08: {raw[8]:02X}")
```

In the struct format above, the prefix specifies little endian; H is an unsigned 16-bit value under this standard-size format. Check buffer length before parsing untrusted data.

## Cybersecurity & Penetration Testing Applications

| Task | Practical Use & Interpretation |
|---|---|
| Network protocol review | Select an authorized packet in Wireshark, expand protocol fields, inspect highlighted bytes and compare sizes, flags, ports and declared lengths to the specification. Reassembled data may differ from individual frame bytes. |
| Digital forensics | Validate file headers and embedded artifacts, document offsets, compare copies and preserve hashes/custody; never edit the original. |
| Reverse engineering | Map file offsets to code/data sections using Ghidra and a format parser; distinguish raw bytes from architecture-dependent instructions and decoded text. |
| Embedded & hardware testing | Inspect owned-device firmware dumps and recorded UART/SPI data offline; account for endianness, flash layouts, checksums and signed-update policies. |
| Authorized parser assessment | Construct well-formed and malformed synthetic records, check bounds, lengths, flags, error handling and stability. Use an isolated harness; report reproducible failures and remediation. |
| Detection engineering | Match specific byte sequences in YARA or protocol fields; test positive and negative fixtures and avoid relying on a generic magic value alone. |
| Cryptography | Read digest, nonce, key and certificate byte representations. A SHA-256 digest is 32 bytes or 64 hex digits; hex does not conceal the value. Never publish secret key material. |

For a capture, start with the protocol tree rather than guessing byte offsets; VLAN tags, options, encapsulation and truncation can shift fields. TLS application data may remain encrypted even if the packet has printable bytes. For testing, compare observed behavior against the expected specification rather than treating malformed data or a pattern match as proof of a vulnerability.

## References & Related Guides

| Resource | Description |
|---|---|
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base16 and other binary-to-text encodings |
| [ImHex Hex Editor View](https://docs.werwolv.net/imhex/views/hex-editor) | Editor UI and inspection |
| [ASCII & Character Encoding](./ascii-and-character-encoding.md) | Interpreting text and control bytes |
| [Hex & ASCII Field Reference & Labs](./hex-ascii-field-reference.md) | Shared practical exercises and cheat sheet |
| [Wireshark Master Filters](../Documentation/wireshark-master-filters.md) | Network display/capture filters |
| [Reverse Engineering](../ReverseEngineering/README.md) | Ghidra and binary analysis |
| [Digital Forensics](../IncidentResponse/Digital-Forensics/README.md) | Evidence handling and artifact examination |
| [Hardware Hacking](../HardwareHacking/README.md) | Embedded and physical interfaces |
| [Cryptography](../Cryptography/README.md) | Correct use of cryptographic algorithms |

---
[⬅️ Algorithms Index](./README.md) | [Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
