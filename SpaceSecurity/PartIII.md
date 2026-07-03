# 🚀 Part III: The Space Segment

## 🎯 Purpose
Space segment attack and defense guide — covering onboard computer (OBC) architecture, flight software (FSW) vulnerabilities, RTOS security (VxWorks, RTEMS, FreeRTOS), memory corruption in space-grade processors, and supply chain risks in COTS satellite components.

## ⚙️ Function
Covers: spacecraft software architecture layering (mission apps/FSW/RTOS/BSP), memory protection unit limitations, RTOS-specific vulnerabilities, FSW patching constraints (bandwidth-limited uplinks), SEU/radiation-induced fault injection, and CubeSat COTS hardware attack surface.

## 🏆 Goal
Understand the unique constraints of space-segment software security — where patching may require months, memory protection is limited, and hardware faults (SEU) can be weaponized — to assess and improve spacecraft software security posture.

## 📋 When to Use
- Assessing a spacecraft FSW codebase for vulnerabilities before launch
- Understanding why space software security differs from terrestrial embedded systems
- Red-teaming a CubeSat or small satellite with COTS OBC hardware

## Chapter 8: Onboard Software

#### Spacecraft Software Architecture

```
┌────────────────────────────────────┐
│        Mission Application          │  Payload control, science, imaging
├────────────────────────────────────┤
│       Flight Software (FSW)         │  Attitude control, power mgmt, thermal
├────────────────────────────────────┤
│    RTOS / Executive / Middleware    │  VxWorks, RTEMS, FreeRTOS, LEON-RTEMS
├────────────────────────────────────┤
│         BSP / Drivers               │  Hardware abstraction layer
├────────────────────────────────────┤
│       Onboard Computer (OBC)        │  RAD750, LEON3/4, ARM Cortex, SPARC
└────────────────────────────────────┘
```

#### Common RTOS Platforms

| RTOS | Usage | Known Issues |
|------|-------|-------------|
| **VxWorks** | Legacy GEO satellites, many heritage platforms | CVE-2019-12255 (URGENT/11 TCP/IP stack bugs); numerous historical CVEs |
| **RTEMS** | Open-source; many CubeSats, NASA missions | Smaller CVE surface but limited security hardening |
| **FreeRTOS** | Proliferated LEO, smallsats | CVE-2018-16528 (SafeRTOS heap overflow) and related |
| **Linux** | Modern commercial satellites | Kernel CVEs; often unpatched in flight due to update risk |
| **INTEGRITY (GHS)** | High-assurance defense platforms | Proprietary; limited public vulnerability data |

#### Flight Software Languages and Vulnerabilities

| Language | Usage | Key Risk |
|----------|-------|---------|
| **C** | Dominant in heritage FSW | Memory safety: buffer overflows, use-after-free, integer overflows |
| **C++** | Modern FSW, NASA F Prime | Same as C plus class/template complexity |
| **Ada / SPARK** | High-assurance (ESA, some DoD) | Formally verified subsets; lower risk but not immune |
| **Python** | Ground tools, some modern smallsats | Injection risks, dependency vulnerabilities |
| **Rust** | Emerging (experimental satellite use) | Memory-safe by design |

#### Software Upload Security

Telecommand software uploads (patches, parameter updates, full FSW loads) represent the highest-risk command type:

- **Integrity verification** — Is the uplinked binary cryptographically signed and verified before execution?
- **Authentication** — Is the command chain that initiates an upload authenticated end-to-end?
- **Rollback protection** — Can an attacker upload a known-vulnerable older version?
- **Execution path** — Is uploaded code loaded into protected memory? Can it overwrite the bootloader?

Many legacy satellites have no meaningful software upload authentication — the only protection is the difficulty of gaining uplink access.

---

### Chapter 9: Spacecraft Hacking

> **Context:** Direct spacecraft hacking in the wild requires either compromise of the ground segment command chain or physical/RF proximity with a transmitter. The scenarios below apply to authorized research, CTF environments, and red team engagements with spacecraft operators.

#### Attack Scenarios

**Scenario 1: Command Injection via Compromised MCS**
- Attacker has achieved MCS access through ground segment compromise
- Issues malformed or malicious telecommand frames through the legitimate uplink chain
- Target: mode changes, FSW upload, AOCS commands (attitude change), power cycling

**Scenario 2: Rogue Uplink (Research/Lab)**
- Attacker operates an SDR-based transmitter aimed at the spacecraft
- Requires: knowledge of uplink frequency, modulation, frame format, and command structure
- Practical for unencrypted CubeSats with publicly documented protocols
- Applicable to the growing body of amateur/educational satellites with open TT&C specs

**Scenario 3: Side-Channel via Telemetry**
- Passive collection of downlinked telemetry reveals operational state
- Can be used for reconnaissance: when is the spacecraft unattended? What mode is it in?
- Timing attacks on encrypted telemetry (traffic analysis)

#### CubeSat Security Research

CubeSats represent the most accessible research target for spacecraft security:

- Many use open-source FSW (OpenSatCom, KubOS, FreeRTOS + custom)
- Frequencies and protocols often published in amateur satellite databases (AMSAT, SatNOGS)
- Some have open command interfaces for ground station operators

```bash
# SatNOGS global ground station network — passive telemetry collection
# https://network.satnogs.org

# Decode AX.25-framed CubeSat telemetry
gr_satellites <satellite-name> --wavfile capture.wav --doppler_csv doppler.csv

# Parse decoded frames with mission-specific decoder
python decode_telemetry.py --frames decoded.json
```

#### Hardening the Space Segment

| Control | Detail |
|---------|--------|
| **Command authentication** | CCSDS Telecommand Authentication (TCA); HMAC or asymmetric signatures on all telecommands |
| **Sequence counters** | Enforce strict monotonic counters; reject replays |
| **Encrypted uplink** | AES-256 or equivalent for all command and data uplinks |
| **Software signing** | Cryptographic signature verification before any FSW load/patch execution |
| **Watchdog timers** | Hardware watchdog to recover from FSW compromise or corruption |
| **Safe mode** | Autonomous safe mode entry on anomaly; limited command set in safe mode |
| **Memory protection** | MPU/MMU enforcement; non-executable data regions |
| **Radiation hardening** | Redundant memory, scrubbing, error-correcting codes (EDAC) — also relevant to fault injection |

---

<div align="center">

**📖 Use These Techniques Responsibly: Authorization is MANDATORY**

*Space systems are critical infrastructure — treat them accordingly.*

**Repository**: [ULTIMATE CYBERSECURITY MASTER GUIDE](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE)

**Maintained by**: [Pacific Northwest Computers](https://github.com/Pnwcomputers)

---

## Related Files
- [PartII.md](PartII.md) — Ground segment: the uplink path to the FSW
- [PartIV.md](PartIV.md) — User segment: the downstream satellite services
- [../HardwareHacking/Chapter3.md](../HardwareHacking/Chapter3.md) — Fault injection: SEU/radiation fault injection has parallels to hardware glitching

⚠️ **RF transmission toward satellites requires EXPLICIT WRITTEN AUTHORIZATION** ⚠️

⚠️ **Unauthorized access to space systems is a FEDERAL CRIME** ⚠️

⚠️ **ITAR/EAR export controls may apply to satellite security tools and techniques** ⚠️

⭐ **Star this repo if you find it useful!** ⭐

</div>
