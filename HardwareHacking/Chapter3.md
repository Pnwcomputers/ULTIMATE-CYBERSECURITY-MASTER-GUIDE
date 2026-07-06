
# Chapter 3: Fault Injection Attacks

## 🎯 Purpose
Practical guide to fault injection attacks - covering voltage glitching, clock glitching, EM fault injection, laser fault injection, and the parameter-space search methodology for finding exploitable fault windows in embedded security checks.

## ⚙️ Function
Covers: FI attack concept and goals (skipping security checks, corrupting comparisons), voltage glitch hardware setup, clock glitch circuit design, EM/laser injection, timing parameters (offset and width), parameter-space sweeping methodology, Python scripting for automated fault campaigns, and a matplotlib-based result visualization pattern.

## 🏆 Goal
Successfully inject a transient fault at the right CPU cycle to bypass a security check (secure boot, PIN verification, cryptographic key comparison) on a target embedded device.

## 📋 When to Use
- When a target device's firmware is encrypted or signed and cannot be dumped via JTAG
- Testing secure boot bypass resistance on development hardware
- Advanced hardware security assessments where passive methods are exhausted
- Research on fault countermeasure effectiveness (masking, redundancy)

> *Part of the [Hardware Hacking Guide](./README.md) - [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

### Concept

Fault injection (FI) introduces a transient error into a target system at a controlled moment to cause incorrect behavior - most commonly to skip a security check, corrupt a comparison, or force a branch taken/not-taken.

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
  [FAULT INJECTED HERE - branch skipped]
  [Access granted]  ← attacker wins
```

---

### Fault Injection Methods

<p align="center">
  <img src="/assets/ClockvsVoltage.jpg" alt="Figure 7: Fault Injection Comparison. (Top) Clock Glitching modifies a clock edge to violate internal setup time. (Bottom) Voltage Glitching briefly dips the supply voltage (crowbar fault) to cause propagation delays or memory corruption." width="600"/>
</p>

#### Clock Glitching

Introduce a glitch (shortened or extended clock pulse) into the target's clock line. The CPU executes an instruction in less time than it needs, producing incorrect results.

```
Normal clock:   _____|‾‾‾‾‾|_____|‾‾‾‾‾|_____|‾‾‾‾‾|_____
Glitched clock: _____|‾‾‾‾‾|_____|‾|_____|‾‾‾‾‾|_____
                                     ^
                                 Short pulse (glitch)
                                 CPU sees a "half cycle" -
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
- `offset` - clock cycles after trigger before firing glitch
- `width` - duration of the glitch pulse (often sub-nanosecond)
- `repeat` - number of consecutive glitch pulses

---

#### Voltage Glitching

Briefly drop (or spike) the supply voltage. Creates setup/hold time violations and logic errors similar to clock glitching, but attacks the power supply instead of the clock.

```
Normal VCC: ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
Glitched:   ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|_|‾‾‾‾‾‾‾‾
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

**Critical:** The glitch must propagate through the target's power distribution network (PDN) to the sensitive logic. Bulk decoupling capacitors on the target board will absorb the glitch - **remove or bypass the nearest decoupling cap** to the target chip for best results.

---

<p align="center">
  <img src="/assets/ElectromagneticFaultInjection.jpg" alt="Figure 8: EMFI Probe Setup. An specialized injection coil (the probe) is held less than 1mm above the surface of the target chip." width="600"/>
</p>

#### Electromagnetic Fault Injection (EMFI)

A focused EM pulse induces transient currents in the target IC through inductive coupling, causing localized bit flips or logic faults without requiring physical contact to the supply or clock.

**Advantages over voltage/clock glitching:**
- No electrical connection to target required - works on encapsulated or potted boards
- Spatially selective - target specific regions of the die
- Can fault through packaging material (up to several mm of plastic)

**Equipment:**
- **Riscure EM Fault Injector** - Professional; ~$15K+
- **ChipSHOUTER** (NewAE Technology) - Affordable research EMFI tool; ~$1K
- **DIY:** EMFI coil + high-voltage pulse generator + FPGA trigger; buildable for <$500 but requires careful tuning

**Practical tips:**
- Use an XY stage for repeatable positioning
- Start with the coil perpendicular to the PCB surface; tilt for sensitivity
- Sweep position across the IC surface systematically - optimal position is non-obvious
- Higher voltage = stronger fault but higher crash probability; sweep the parameter

---

<p align="center">
  <img src="/assets/LaserFaultInjection.jpg" alt="Figure 9: LFI Laboratory Setup. The target chip must be mechanically 'decapped' to expose the silicon die." width="600"/>
</p>

#### Laser Fault Injection (LFI)

Focused laser light on the chip die generates electron-hole pairs in transistors, causing localized bit flips. Highest precision of all fault injection methods - can target individual cells.

**Requirements:**
- Decapped (delayered) chip - protective coating and packaging must be removed
- IR laser (1064 nm penetrates silicon from backside) or visible laser (requires thinned front side)
- Precision XY (optionally Z) stage
- Trigger synchronization

**Chip decapping:**
1. **Chemical:** Hot fuming nitric or sulfuric acid etches epoxy (not suitable for copper wire bonds)
2. **Mechanical:** Dremel + fine grinding; labor-intensive; risk of die damage
3. **Laser ablation:** Expensive equipment; most precise

| Approach | Laser | Requirements |
|----------|-------|-------------|
| Frontside | 532 nm / 660 nm green/red | Remove/thin passivation |
| Backside | 1064 nm IR | Grind silicon to ~100 μm; flip chip |

---

#### Body Biasing Injection (BBI)

A voltage pulse applied to the **substrate (body) contact** of the chip through the backside or exposed substrate. Modulates transistor threshold voltages, causing logic faults.

**Advantages:**
- Does not require decapping (works through thinned or backside-polished chip)
- More spatially selective than voltage glitching, less equipment-intensive than laser
- Effective on FD-SOI and bulk CMOS processes

---

### Injection Point Identification

Finding where and when to inject is often harder than the injection itself.

#### Temporal Targeting

| Strategy | Method | When to Use |
|----------|--------|------------|
| **Fixed offset from trigger** | UART TX start bit, GPIO toggle, power-on reset | Deterministic code paths |
| **Side-channel correlation** | Align fault offset with power/EM signature of target instruction | Variable-latency paths |
| **Incremental sweep** | Automated sweep of offset in fine steps | Unknown target offset |
| **Loop amplification** | Fault inside a repeated loop - each iteration is another attempt | Crypto operations |

**Trigger sources:**

```
Hardware trigger: GPIO from target (e.g., "auth check starting" LED)
Power trigger: Sudden current change detected on shunt
UART trigger: Specific byte sequence in target's output
Time-after-reset: Fixed delay from VCC ramp (deterministic early boot)
Logic analyzer: Decode serial comms; trigger on specific transaction
```

#### Spatial Targeting (EMFI / LFI)

- **Die photographs** from published datasheets or delayered samples
- **Function mapping** - correlate die regions with observed fault effects
- **Systematic XY raster scan** - grid sweep with fixed timing; map fault rate by position

---

### Practical Injection Tips

**Start with the easiest method first.** Voltage glitching requires minimal equipment; try it before investing in EMFI or laser setups.

**Automate everything:** Manual parameter sweeps are untenable - write a Python script to iterate offset, width, and voltage parameters, reset the target between attempts, capture and classify the result.

**Classify results carefully:**

| Result | Meaning | Action |
|--------|---------|--------|
| **Normal (expected output)** | No fault or fault missed | Adjust offset/width |
| **Crash / hang / no response** | Fault too strong or wrong location | Reduce width; adjust offset |
| **Unexpected output / partial data** | Fault too early or too late | Fine-tune offset |
| **Target behavior (e.g., auth bypass)** | Fault hit the right instruction | Record all parameters; repeat to confirm |

**Build a fault map:** Plot fault type vs. (offset, width) as a 2D heatmap. Successful faults cluster - the "sweet spot" becomes visually clear.

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

## Related Files
- [Chapter2.md](Chapter2.md) - Electrical fundamentals: voltage supply manipulation and oscilloscope setup required for fault injection
- [Chapter4.md](Chapter4.md) - Power analysis: passive counterpart to active fault injection; complementary techniques
- [Chapter1.md](Chapter1.md) - Threat modeling: fault injection is one of the key attack classes to model in scope

---

<div align="center">

**Next:** [Chapter 4 - Timing and Power Analysis Attacks →](./Chapter4.md)

[← Chapter 2: Electrical Fundamentals](./Chapter2.md) · [Back to Hardware Hacking README](./README.md)

</div>
