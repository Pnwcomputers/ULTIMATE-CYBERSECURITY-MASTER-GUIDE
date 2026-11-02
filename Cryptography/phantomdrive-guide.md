# PhantomDrive: Experimental Hidden Encrypted USB Research Guide

_Last reviewed: 2026-11-01 (upstream documentation reviewed; build and hardware not tested)_

**Prerequisites:** [Encrypted storage fundamentals](./encrypted-storage.md) · [Applied cryptography](./applied-crypto.md)

> [!WARNING]
> **Research-only project.** The [upstream PhantomDrive project](https://github.com/o7-machinehum/phantomdrive) explicitly states that its code has **not been professionally audited**. Use only a disposable microSD card and **non-sensitive synthetic files**. Do not deploy it for client records, regulated data, or irreplaceable material without independent security evaluation and an appropriate recovery plan.

## Purpose and architecture

For the difference between **locked ciphertext**, **mounted plaintext**, and the host's remaining attack surface, review the [encrypted-storage protection-boundary diagram](../assets/encrypted-storage-protection-boundaries.svg) before experimenting with firmware variants.

PhantomDrive is an open-source encrypted USB drive experiment with a decoy or visible volume and a second encrypted area that can remain hidden until unlocked.

- Main project: [o7-machinehum/phantomdrive](https://github.com/o7-machinehum/phantomdrive)
- Controller: WCH **CH569W** system-on-chip with USB 3, SDIO and AES hardware.
- Hardware design and firmware are published in the project repository.
- Unlock is triggered by writing content containing a **password:** marker to the locked volume. The drive then changes exposed storage. This is **not** equivalent to proven plausible deniability.
- The repository documents builds using **AES-256-CTR or AES-256-XTS** with **PBKDF2-HMAC-SHA256** at **100,000 or 600,000 iterations**, depending on the firmware variant. The build parameters affect the encrypted on-disk format.

> [!IMPORTANT]
> **Verify the firmware actually flashed.** Do not assume XTS simply because it appears in the main README. CTR and XTS have materially different storage-security considerations, and changing the AES mode or PBKDF2 settings can make existing data inaccessible without migration.

## Why it is interesting

PhantomDrive is a useful lab for investigating USB mass storage presentation, on-device key derivation, AES encryption modes, FAT32 decoy volumes, microcontroller firmware trust and the gap between hidden storage and independently verified confidentiality.

### Main security limitations

| Concern | Why it matters |
|---|---|
| No professional audit | Security claims have not been independently established |
| CTR build options | Reusing counter-derived keystream across rewritten sectors can leak relationships between plaintext versions |
| XTS build options | XTS addresses different storage confidentiality requirements but does **not** authenticate writes |
| Password-file unlock | Content-based marker detection can interact with ordinary writes; the file need not have a particular filename |
| Host artifacts | Shell history, editors, file indexing, swap, backups and logs may retain entered secrets or access history |
| Firmware and KDF changes | Incompatible builds can make stored data unreadable |
| Hidden partition | Not a guarantee against forensic discovery, physical attack, tamper detection or compelled disclosure |
| Sudden removal / corruption | In-place operations and FAT filesystems need controlled testing and recoverable backups |

## Safe hands-on research workflow

1. Read the current upstream README and any test documentation **at the commit you will use**.
2. Assemble only supported hardware according to published schematics and bill of materials; verify the board revision and power requirements.
3. Prepare a dedicated Linux lab machine or VM with authorized USB access and a **blank, disposable** microSD card. Disconnect any other removable drives that could be mistaken for the target.
4. Clone the upstream repository for local inspection:

~~~bash
git clone https://github.com/o7-machinehum/phantomdrive.git
cd phantomdrive
git rev-parse HEAD
git submodule status
~~~

5. Inspect the exact revision's README, Makefile, firmware options, and test results. Follow the upstream build/flash instructions only after validating toolchain and board compatibility. The upstream references the patched HydraUSB3 xPack toolchain and the WCH USB ISP programmer; those steps are hardware- and revision-dependent.
6. **Record** firmware variant (CTR or XTS), KDF rounds, commit hash, test media identifier, and observations in a lab notebook. Never publish passwords or test credentials.
7. Use a fresh random **lab-only** password. Prefer the upstream's interactive or controlled input workflow over entering secrets in a command line; do not paste a real secret into a shell command, editor with swap/autosave, ticket, or shared chat.
8. With synthetic data only, inspect the decoy view, unlock via the **current official procedure**, and verify the expected encrypted view appears. Safe-eject before disconnecting.
9. Power-cycle, test correct and incorrect credentials, file readability, and SHA-256 hashes. Treat any corruption or unexpected unlock as a test failure.
10. Record findings, securely dispose of the lab-only media or reinitialize it as appropriate, and preserve independent copies of your dummy test set.

### Read-only device identification

~~~bash
lsusb
lsblk -o NAME,MODEL,SIZE,TRAN,FSTYPE,MOUNTPOINTS
sha256sum ./test-files/example.bin
~~~

The final hash command is for a **local dummy test file**. Compare it with the hash of its independently retained original; hashing alone does not prove encryption safety.

## Questions for a hardware/firmware review

- Does firmware authenticate itself or support secure boot? If so, is the mechanism independently verified?
- Is the password derivation salted per device or per volume? How are salt, keys and reset conditions handled?
- Are password attempts limited, and can unauthorized writes falsely trigger unlock detection?
- Can changing exposed volumes leak state to the operating system or USB monitoring tools?
- What happens on power loss during an in-place operation?
- What is actually tested: encryption round trips, repeated-sector rewrites, corrupted sectors, power cycling, and filesystem recovery?
- Does a claimed decoy partition withstand the specific forensic adversary in your threat model? **Do not assume so.**

## Lab evidence template

| Field | Record |
|---|---|
| Date/operator | |
| Board revision and serial | |
| Upstream URL and exact commit | |
| Build mode / KDF rounds | |
| Test-media model and size | |
| Test-file SHA-256 before / after | |
| Lock/unlock observations | |
| Wrong-password outcome | |
| Power-cycle and recovery result | |
| Known limitations / follow-up issues | |

## See also

- [Encrypted Drives and Removable Storage](./encrypted-storage.md)
- [SoloKeys: different category of cryptographic device](./solokeys-guide.md)
- [Hardware Security Keys and Passkeys](./security-keys-passkeys.md)
- [Hardware Hacking](../HardwareHacking/README.md)
- [OPSEC](../OPSEC/README.md)
- [Upstream PhantomDrive](https://github.com/o7-machinehum/phantomdrive)

---

[Section Index](./README.md) | [Master Index](../README.md) | [Legal Notice](../LEGAL.md)
