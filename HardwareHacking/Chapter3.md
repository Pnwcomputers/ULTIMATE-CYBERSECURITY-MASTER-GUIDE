
# Chapter 3: Fault Injection Attacks

## 🎯 Purpose
Explain how transient hardware disturbances can affect device behavior, how to evaluate fault-injection resilience on authorized development targets, and how to interpret results without treating a single outcome as proof of exploitability.

## ⚙️ Function
Covers clock, supply-voltage, electromagnetic, and optical fault-injection concepts; target-dependent timing and coupling; controlled evaluation; outcome classification; and defensive validation.

## 🏆 Goal
Assess whether a device detects, tolerates, or mishandles faults under a documented and authorized test scope, and produce repeatable evidence for remediation.

## 📋 When to Use
- Evaluating a device or development board you own or are explicitly authorized to test
- Reviewing secure-boot, authentication, or cryptographic fault countermeasures
- Planning a specialist laboratory assessment and defining measurable outcomes
- Documenting reset, detection, recovery, and unexpected-output behavior

> *Part of the [Hardware Hacking Guide](./README.md) - [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

### Concept

Fault injection (FI) deliberately perturbs a device's operating conditions to study whether the resulting behavior is detected, safely contained, or incorrect. Faults can cause resets, corrupted data, timing errors, or security-relevant failures; the result depends on the target, disturbance, and countermeasures.

A useful evaluation records the complete chain: the intended property, the observed disturbance, the device response, and independently checked evidence. A crash or unexpected output alone does not prove that a security boundary was bypassed. The diagram below summarizes this evidence flow; it is conceptual and does not represent a tested circuit.

![Conceptual fault-injection evaluation flow from authorized scope and disturbance class through target response to recorded evidence](../assets/diagrams/fault-injection-evaluation-flow.svg)

---

### Fault Injection Methods

<p align="center">
  <img src="../assets/ClockvsVoltage.jpg" alt="Figure 7: Fault Injection Comparison. (Top) Clock Glitching modifies a clock edge to violate internal setup time. (Bottom) Voltage Glitching briefly dips the supply voltage (crowbar fault) to cause propagation delays or memory corruption." width="600"/>
</p>

#### Clock Glitching

A clock disturbance can violate timing margins or alter clock edges. Depending on the device and injection path, outcomes range from no observable effect to reset, detected fault, or incorrect computation; it does not simply make an instruction execute faster.

Evaluation requires a target-specific, documented test fixture and instruments appropriate to the clock interface and electrical limits. A repeatable trigger and capture method are useful, but achievable timing resolution, pulse shape, and relation to the target clock depend on the hardware and clocking configuration.

Some instruments expose controls such as `offset`, `width`, and `repeat`. Their units, ranges, resolution, and effect are instrument- and target-specific. Record actual settings and observed behavior rather than assuming a parameter maps directly to a target clock cycle.

See [ChipWhisperer's notes on glitch timing controls](https://chipwhisperer.readthedocs.io/en/sca101/cw_tips_tricks/advanced_usage/improving_glitch_precision.html).

#### Voltage Glitching

Supply-voltage fault injection perturbs a target rail. The transient that reaches the silicon depends on the power-distribution network, regulator, package, board layout, load, and measurement point; no generic amplitude or duration predicts the effect. Test only on a current-limited, replaceable development target using documented limits and suitable equipment.

**Keep decoupling capacitors in place by default.** Capacitors can shape or attenuate transients, but removing or bypassing them changes the target and can cause instability or damage. Only make a board modification when the exact target documentation specifies it for the measurement path. For example, NewAE's [CW305 documentation](https://rtfm.newae.com/Targets/CW305%20Artix%20FPGA/) describes particular optional capacitors associated with its shunt measurement design; this is not a general instruction for other boards.

<p align="center">
  <img src="../assets/ElectromagneticFaultInjection.jpg" alt="Figure 8: EMFI Probe Setup. An specialized injection coil (the probe) is held less than 1mm above the surface of the target chip." width="600"/>
</p>

#### Electromagnetic Fault Injection (EMFI)

EM fault injection applies a transient electromagnetic disturbance that can couple into a circuit without a direct electrical connection. The coupling path, affected region, repeatability, and resulting fault depend strongly on the target package, board, probe, and setup. Do not infer spatial precision or penetration through packaging from an illustrative image. Specialized equipment and controlled laboratory methods are typically required; prices and capabilities vary by current model.

<p align="center">
  <img src="../assets/LaserFaultInjection.jpg" alt="Figure 9: LFI Laboratory Setup. The target chip must be mechanically 'decapped' to expose the silicon die." width="600"/>
</p>

#### Laser Fault Injection (LFI)

Optical fault injection uses focused light to perturb semiconductor behavior. Access to a suitable die surface, wavelength, and device construction are target-specific; achievable spatial resolution and effects must be established experimentally. Package opening, delayering, laser use, and chemical processing are specialist failure-analysis activities with serious equipment, eye, chemical, and device hazards. This guide does not provide a decapsulation procedure. Treat the supplied figure as illustrative, not as proof that a device must be opened or that a particular wavelength will work.

#### Body Biasing Injection (BBI)

Body-bias fault injection is a specialized research technique that perturbs substrate or body bias where a device process and physical access make this possible. Its feasibility, coupling, and effects depend strongly on the semiconductor process and package. It is not a general board-level technique; avoid assuming that a commercial device exposes a usable body contact.

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
