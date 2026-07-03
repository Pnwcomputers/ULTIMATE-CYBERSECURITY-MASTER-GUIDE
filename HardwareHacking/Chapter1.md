# Chapter 1: Threat Modeling for Hardware Security

## 🎯 Purpose
Framework for analyzing hardware security threats — covering physical access threat models, STRIDE applied to embedded systems, trust boundary identification, and the hardware security properties that software threat modeling ignores.

## ⚙️ Function
Introduces hardware-specific threat modeling concepts: physical access attack vectors (JTAG, SWD, UART, voltage glitching, side-channel), asset identification on embedded systems, STRIDE table applied to hardware, countermeasures, and a structured threat model template for documenting findings.

## 🏆 Goal
Produce a hardware threat model for a target device that identifies the physically accessible attack surfaces, the assets at risk, and appropriate countermeasures — before tool selection or hands-on work begins.

## 📋 When to Use
- Starting a hardware security assessment: build the threat model before touching the device
- Designing a new embedded product: identify security requirements before hardware is finalized
- Scoping a hardware pen test engagement: determine which physical attack vectors are in scope

> *Part of the [Hardware Hacking Guide](./README.md) — [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

### Why Hardware Threat Modeling Differs

Software threat modeling assumes the attacker is remote and logical. Hardware threat modeling must also account for **physical access** — an attacker who can touch the device has capabilities unavailable over any network:

- Direct memory reads via debug interfaces (JTAG, SWD, UART)
- Signal probing on internal buses
- Voltage and clock manipulation to bypass security checks
- Chip decapping and microprobing
- Side-channel observation of power, EM emissions, and timing

The classic security model of "inside the trust boundary = trusted" collapses when an attacker can physically manipulate the hardware. Hardware threat modeling rebuilds the trust boundary from the silicon up.

<p align="center">
  <img src="/assets/CollapsingtheTrustBoundary.jpg" alt="Figure 1: Threat Modeling Boundaries. (Left) The logical model, where a remote attacker is stopped by a network firewall. (Right) The hardware model, where an attacker with physical access uses techniques like probing and glitching to bypass the now-meaningless logical trust boundary." width="600"/>
</p>

---

### Attacker Profiles

Defining a realistic attacker profile before assessment scopes the attack surface and prevents both under- and over-engineering of defenses.

| Profile | Access Level | Budget | Skill | Time | Example |
|---------|-------------|--------|-------|------|---------|
| **Script Kiddie** | Physical device | <$100 | Low | Hours | Running published exploit against consumer device |
| **Motivated Hobbyist** | Physical device | $100–$1K | Medium | Days–weeks | Jailbreaking a game console |
| **Security Researcher** | Physical device + teardown | $1K–$10K | High | Weeks | Academic fault injection work |
| **Organized Criminal** | Physical device + supply chain | $10K–$100K | High | Months | Payment card skimming, ATM black-box attacks |
| **Nation-State** | Any access including supply chain | Unlimited | Expert | Years | IC-level implants, foundry-level compromise |

Use these profiles to bound your analysis. A consumer IoT device likely needs defenses against the Motivated Hobbyist and below; a HSM or satellite payload needs to consider Nation-State capabilities.

---

### Assets

Hardware assets differ from software assets because they are often **physical objects** whose compromise has physical consequences.

#### Asset Categories

| Category | Examples | Sensitivity |
|----------|---------|------------|
| **Cryptographic keys** | Root keys, device identity keys, session keys | Critical — disclosure often irrecoverable |
| **Firmware / IP** | Proprietary algorithms, product firmware | High — enables cloning, piracy, vulnerability research |
| **Configuration / fuses** | Security state bits, feature enables, calibration | High — manipulation enables bypass |
| **Runtime data** | PINs, passwords, intermediate crypto values | High — transient but frequently targeted |
| **Physical device** | PCB, chips, interfaces | Medium — extraction enables all other attacks |
| **Manufacturing data** | Test modes, debug interfaces, factory keys | High — often left active in production |

#### Asset-Attack Surface Mapping

```
Asset: AES Root Key
  └─> Stored in: OTP fuses / secure element / battery-backed SRAM
  └─> Used by: Crypto accelerator / software AES
  └─> Observable via: Power trace during encrypt/decrypt
  └─> Extractable via: SPA/DPA on crypto operations
                        Fault injection to skip key zeroization
                        JTAG if debug not locked
                        Glitching secure boot to unlock debug
```

---

### Objectives

Map attacker objectives to the assets they require and the attacks that enable them:

| Objective | Assets Required | Likely Attack Path |
|-----------|---------------|-------------------|
| **Clone device** | Firmware, device keys | JTAG extraction, SPI flash dump, fault injection to unlock |
| **Extract secret key** | Cryptographic keys | DPA/SPA, SEMA, microprobing |
| **Bypass authentication** | Auth logic, firmware | Fault injection (skip compare), UART console exploit |
| **Unlock debug interface** | Security fuse state | Voltage glitching to bypass fuse check, laser fault injection |
| **Persistent implant** | Firmware write access | Bootloader exploit, flash reprogramming after extraction |
| **Forge signatures** | Signing keys | DPA against signing operation |
| **Denial of service** | Power/clock inputs | Voltage spike, overclock |

---

### Countermeasures

Hardware countermeasures operate at multiple levels — silicon, firmware, and physical:

#### Silicon / Chip Level

| Countermeasure | Attacks Mitigated | Notes |
|----------------|------------------|-------|
| Active shield mesh | Microprobing, laser FI | Top-metal layer that triggers tamper on probe contact |
| Glitch detectors (voltage/clock) | Voltage and clock FI | On-die sensors; trigger zeroization or reset |
| PLL with frequency limits | Clock glitching | Reject CLK outside valid range |
| True Random Number Generator | Fault injection timing, DPA | Randomizes operation timing; adds noise to power trace |
| Redundant logic / dual-rail | Fault injection | Executing critical ops twice; comparison before acting |
| Memory encryption | Cold boot, bus probing | Transparent encryption of SRAM/Flash |

#### Firmware Level

| Countermeasure | Attacks Mitigated | Implementation |
|----------------|------------------|---------------|
| Secure boot chain | Firmware tampering | Cryptographic signature verification at each stage |
| Debug lock | JTAG/SWD extraction | Burn fuses; disable SWD in firmware; JTAG authentication |
| Key diversification | Key extraction | Derive device-unique keys from root + UID; limit blast radius |
| Anti-timing (constant-time ops) | Timing side-channel | Avoid data-dependent branches and memory access patterns |
| Masking | DPA | XOR sensitive intermediate values with random masks |
| Instruction shuffling | SPA, DPA | Randomize non-dependent operation order |
| Integrity checks | Fault injection | Verify results of critical operations; detect glitch artifacts |

#### Physical Level

| Countermeasure | Attacks Mitigated |
|----------------|------------------|
| Epoxy potting | Decapping, probing |
| Tamper-evident seals | Physical access detection |
| Enclosure intrusion detect | Fault injection rigs |
| PCB layer count increase | Bus probing complexity |
| BGA packaging (no exposed pads) | Test point probing |

---

### Threat Model Template

For each target device, document:

```
TARGET: [Device name / model]
ATTACKER PROFILE: [Relevant profiles and assumed capabilities]

ASSETS:
  - [Asset 1]: [Location] [Sensitivity]
  - [Asset 2]: [Location] [Sensitivity]

ATTACK SURFACE:
  - External interfaces: [UART, SPI, I2C, JTAG, USB, RF, etc.]
  - Power input: [Accessible? Filtering present?]
  - Clock input: [External crystal / internal RC / PLL]
  - Physical access: [Enclosure protection level]

THREAT SCENARIOS:
  [ID] [Threat] [Asset] [Attack Path] [Likelihood] [Impact]

COUNTERMEASURES:
  [ID] [Control] [Threats Mitigated] [Implementation Status]

RESIDUAL RISK:
  [Threats not fully mitigated and accepted rationale]
```

---

## Related Files
- [Chapter2.md](Chapter2.md) — Electrical fundamentals: the physical layer knowledge underlying every threat in this model
- [JTAGulator.md](JTAGulator.md) — Primary tool for exploiting the JTAG/UART debug-interface threat identified in threat models
- [T48_TL866-3G.md](T48_TL866-3G.md) — IC programmer for the firmware extraction threat vector
- [Chapter3.md](Chapter3.md) — Fault injection: one of the key hardware attacks this chapter helps scope
- [Chapter4.md](Chapter4.md) — Side-channel: the passive observation threat class this chapter introduces

---

<div align="center">

**Next:** [Chapter 2 — Electrical Fundamentals →](./Chapter2.md)

[← Back to Hardware Hacking README](./README.md)

</div>
