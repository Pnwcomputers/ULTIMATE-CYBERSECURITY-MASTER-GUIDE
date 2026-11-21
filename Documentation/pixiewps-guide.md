# Pixiewps: WPS Weak-Entropy Analysis & Mitigation

_Upstream Pixiewps project and Kali documentation reviewed: 2026-11-21. No WPS PIN recovery performed._

> [!CAUTION]
> **Authorized use only.** WPS protocol testing can disclose the enrolment PIN or PSK on vulnerable APs. This guide covers validation design and mitigation, **not** live PIN-recovery parameters. Use dedicated, owned lab access points only. See [Legal Notice](../LEGAL.md).

## What Pixiewps Actually Tests

[Pixiewps](https://github.com/wiire-a/pixiewps) is an **offline WPS PIN analysis utility** that exploits weak or predictable entropy in **some** WPS implementations ("Pixie Dust"). It is not a generic WPA2 passphrase cracker, not a universal WPS PIN recovery guarantee and does not mean any WPS-capable AP is vulnerable.

Different attacks are frequently conflated:

| Method | Interaction | Preconditions |
|---|---|---|
| WPS status detection | Receive WPS-related advertisement or inspect AP config | Visibility, correct frame decoding |
| WPS online PIN guessing | Active authentication messages | Enabled PIN enrollment; may lock out/disrupt |
| Pixiewps offline weak-entropy analysis | Offline evaluation of WPS exchange values | Specific weak PRNG/implementation and sufficient valid evidence |
| WPA2 PSK dictionary audit | Offline comparison with eligible PMKID/EAPOL records | Applicable PSK exchange, selected candidates |
| WPA3-SAE | Different protocol | Do not treat as ordinary WPA2 capture format |

## Safe Lab & Installation Review

Use a spare AP whose firmware/configuration and WPS implementation you can reset. Never run automated online attempts as a first diagnostic.

```bash
pixiewps --version
pixiewps --help
```

The above checks locally installed tooling only. Consult the [Kali package](https://www.kali.org/tools/pixiewps/) or [upstream manual](https://github.com/wiire-a/pixiewps) for correct version-specific syntax. Do not store real recovered PINs in notebooks or Git.

## Assessment Decision Tree

| Condition | Conclusion / Next Step |
|---|---|
| WPS disabled at the AP | Confirm via authorized configuration and observation |
| WPS enabled but PIN disabled | Record support for push-button-only vs PIN where known |
| WPS PIN enabled | Recommend disabling PIN, auditing firmware and enrolment logs |
| Vendor advisory for weak WPS entropy | Verify exact firmware/hardware version and affected conditions |
| Offline tool says "not vulnerable" | Not definitive: incomplete exchange or unsupported implementation possible |
| PIN recovered in a **synthetic lab** | Document affected version, restore lab and propose mitigation |

## Defensive Remediation

Prefer disabling WPS PIN enrollment altogether; disable WPS fully if not required. Keep router firmware current, enforce WPA2-AES or WPA3-SAE where compatible, protect administrator accounts and log enrolment changes. **A strong PSK alone does not correct a vulnerable WPS PIN mechanism.**

## Evidence Record

Write down AP model, board revision, firmware, WPS methods, exact source, permission, packet coverage, whether evidence was captured actively or receive-only, tool version and limitations. Redact PINs, PSKs and MAC addresses from public examples.

## References & Related Guides

- [Pixiewps Upstream](https://github.com/wiire-a/pixiewps) & [FAQ](https://github.com/wiire-a/pixiewps/wiki/FAQ)
- [Wifite Comparison](./wifite-guide.md) | [Fern GUI](./fern-wifi-cracker-guide.md)
- [Aircrack-ng](./Aircrack-ng_Commands.md) | [Wi-Fi Adapter Selection](./wifi-adapter-selection-guide.md)
- [HCXTools](./hcxtoolshashcat.md) — different WPA2 PSK offline format

---

[Documentation Index](./README.md) | [Wardriving](../Wardriving/README.md) | [Legal Notice](../LEGAL.md)
