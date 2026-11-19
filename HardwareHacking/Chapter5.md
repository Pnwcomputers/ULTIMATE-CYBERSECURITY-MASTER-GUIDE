
# Chapter 5: Power Analysis - Practical Techniques

## 🎯 Purpose
A practical overview of authorized power-analysis evaluation, including safe measurement setup, trace provenance, preprocessing limits, CPA interpretation, and leakage testing.

## ⚙️ Function
Covers target-dependent shunt and probe selection, controlled trace collection, signal-processing cautions, correlation power analysis (CPA), visualization, and Test Vector Leakage Assessment (TVLA).

## 🏆 Goal
Determine whether a documented implementation leaks information under a defined lab setup, preserve enough evidence to reproduce the result, and report both findings and limits.

## 📋 When to Use
- Evaluating a cryptographic implementation on owned or explicitly authorized development hardware
- Planning measurement setup after reviewing the fundamentals in Chapter 2
- Learning how collection and preprocessing choices affect leakage analysis
- Checking countermeasures with documented statistical methods

> *Part of the [Hardware Hacking Guide](./README.md) - [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

### Measurement Setup

A measurement must preserve the target's normal operating conditions closely enough for the stated experiment. Choose a documented, current-limited development target and follow its board and instrument manuals.

#### Hardware Configuration

The shunt value and placement depend on the target's current, allowable supply drop, resistor dissipation, power-distribution path, and measurement bandwidth. There is no universal value. Keep decoupling capacitors in place unless the exact target documentation specifies a topology-specific change.

Use the shunt calculation and conceptual figure in [Chapter 2](./Chapter2.md#shunt-resistors-for-power-measurement). That chapter explains why probe common-mode limits, scope grounding, loading, and 50 Ω termination must be checked before connecting instruments.

![Conceptual shunt measurement with a series resistor and target-dependent voltage-drop checks](../assets/diagrams/shunt-current-measurement.svg)

Select a differential or single-ended measurement only after confirming the target reference, scope/probe grounding, common-mode range, and safe input limits. A ×1 probe is not automatically more suitable: attenuation, bandwidth, capacitance, input resistance, and voltage limits vary by probe and scope.

Amplification is optional and target-dependent. Check amplifier noise, bandwidth, gain, input range, common-mode range, and risk of saturation. A larger displayed waveform is not necessarily a more faithful measurement.

#### ChipWhisperer Setup

ChipWhisperer hardware and API defaults vary by capture platform, firmware, target board, and software release. Do not copy fixed gain, sample count, clock, trigger, or serial settings into an unrelated target configuration. Start with the current [ChipWhisperer documentation and tutorials](https://chipwhisperer.readthedocs.io/en/latest/) for the exact capture hardware and target; record software versions and configuration in the experiment notes.

### Trace Acquisition

#### Collection Best Practices

- **Define the experiment first:** Specify the security property, controlled inputs, expected operation, target revision, and stop conditions.
- **Choose inputs to fit the test:** Fixed-versus-random TVLA and known-plaintext CPA use different input designs. Follow the method's documented requirements and preserve input/response metadata.
- **Check trigger and capture behavior:** Confirm that captures contain the intended operation and that the trigger is stable enough for the planned analysis. Timing jitter and misalignment can weaken or distort results.
- **Preserve raw traces:** Keep an unmodified copy with instrument settings, sample rate, target/environment details, trigger configuration, input data, output data, and software versions.
- **Use repeatable conditions:** Record temperature, supply, clock, board state, and any changes during acquisition. Do not assume a fixed warm-up interval or trace count applies to all setups.
- **Set collection size from evidence:** Start with a bounded pilot collection, examine quality and convergence, then justify any larger collection from the target and analysis rather than a universal number.

For an end-to-end example, use the [current ChipWhisperer SCA101 capture notebooks](https://chipwhisperer.readthedocs.io/en/sca101/). Their examples are tied to specified target and capture hardware; adapt only after checking the exact configuration.

### Filtering and Signal Processing

Preprocessing can make traces easier to compare, but it can also remove leakage, introduce artifacts, or create misleading correlations. Preserve raw data and record every transformation so results can be reproduced.

- Select filters from the measurement bandwidth, sample rate, probe response, and experiment question. A cutoff based only on the target clock is not sufficient.
- Check that digital filtering parameters are valid for the actual sample rate and that filtering does not distort edges or points of interest.
- Align traces only when the offset model is justified. Cross-correlation or sum-of-absolute-differences alignment can align unrelated features or leak selection bias into the analysis.
- Apply the same documented preprocessing to comparison groups. Keep a raw-versus-processed comparison and report the transformation.
- PCA and other dimensionality-reduction methods are exploratory; they can mix or discard leakage and should not be treated as proof of security or insecurity.

Use manufacturer or research examples that match the exact data format and setup. The alignment routines formerly shown here had edge-case and truncation problems and have been removed.

### Correlation Power Analysis (CPA)

CPA compares measured traces with a predicted leakage model for candidate intermediate values. For an authorized lab exercise, use a documented, owned development target or a provided simulation dataset and verify results with known test vectors.

ChipWhisperer's maintained analyzer supports CPA for compatible projects. Its documented flow is to open the project, select a leakage model, run the analyzer, and inspect the key guess and convergence plots. See the [Analyzer API documentation](https://chipwhisperer.readthedocs.io/en/latest/analyzer-api.html) and the [SCA101 CPA tutorial](https://github.com/newaetech/chipwhisperer-tutorials/blob/master/courses_sca101_SOLN_Lab%204_2%20-%20CPA%20on%20Firmware%20Implementation%20of%20AES-CWNANO-CWNANO.rst).

A Pearson-correlation peak is a candidate, not standalone confirmation. Review the leakage model, sampling/alignment choices, candidate ranking over traces, controls, and whether the guessed key correctly predicts outputs on independent test vectors. Report the target, software version, analysis settings, and limits. The chapter intentionally omits a generic copy-paste key-recovery script because the required project format, leakage model, and target configuration are specific to the lab.

### Visualization

#### Trace Overlay Plot

```python
def plot_trace_overlay(traces, n_show=100, title="Power Traces"):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), sharex=True)
    
    for i in range(min(n_show, len(traces))):
        ax1.plot(traces[i], alpha=0.05, color='blue', linewidth=0.5)
    ax1.plot(np.mean(traces, axis=0), color='red', linewidth=1.5, label='Mean')
    ax1.set_ylabel('Power (ADC units)')
    ax1.set_title(f'{title} - Overlay ({n_show} traces)')
    ax1.legend()
    
    ax2.plot(np.std(traces, axis=0), color='orange', linewidth=1)
    ax2.set_xlabel('Sample index')
    ax2.set_ylabel('Std Dev')
    ax2.set_title('Trace Variance (high = potential POI)')
    
    plt.tight_layout()
    plt.show()
```

#### CPA Correlation Map

```python
def plot_cpa_result(correlation_matrix, true_key_byte=None, byte_idx=0):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8))
    
    im = ax1.imshow(np.abs(correlation_matrix), aspect='auto', cmap='hot', interpolation='nearest')
    ax1.set_xlabel('Sample index')
    ax1.set_ylabel('Key guess (0x00 – 0xFF)')
    ax1.set_title(f'CPA Correlation Map - Key Byte {byte_idx}')
    plt.colorbar(im, ax=ax1, label='|Pearson r|')
    
    if true_key_byte is not None:
        ax1.axhline(y=true_key_byte, color='cyan', linewidth=1.5, linestyle='--',
                   label=f'True key: 0x{true_key_byte:02X}')
        ax1.legend()
    
    max_corr = np.max(np.abs(correlation_matrix), axis=1)
    ax2.bar(range(256), max_corr, width=1, color='steelblue', alpha=0.7)
    ax2.set_xlabel('Key guess')
    ax2.set_ylabel('Max |correlation|')
    ax2.set_title('Peak Correlation per Key Guess')
    
    recovered = np.argmax(max_corr)
    ax2.axvline(x=recovered, color='red', linewidth=2, label=f'Recovered: 0x{recovered:02X}')
    if true_key_byte is not None:
        ax2.axvline(x=true_key_byte, color='green', linewidth=2, linestyle='--',
                   label=f'True: 0x{true_key_byte:02X}')
    ax2.legend()
    
    plt.tight_layout()
    plt.show()
    return recovered
```

#### Success Rate vs. Trace Count

```python
def plot_success_curve(traces, plaintexts, true_key, byte_idx=0, step=50, n_trials=10):
    trace_counts = range(step, len(traces) + 1, step)
    success_rates = []
    
    for n in trace_counts:
        successes = 0
        for trial in range(n_trials):
            idx = np.random.choice(len(traces), n, replace=False)
            corr = cpa_attack(traces[idx], plaintexts[idx], byte_idx)
            max_corr = np.max(np.abs(corr), axis=1)
            if np.argmax(max_corr) == true_key[byte_idx]:
                successes += 1
        success_rates.append(successes / n_trials)
    
    plt.figure(figsize=(10, 5))
    plt.plot(trace_counts, success_rates, 'o-', color='steelblue')
    plt.axhline(y=1.0, color='green', linestyle='--', alpha=0.5, label='100% success')
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
    t1 = traces[:, poi1] - np.mean(traces[:, poi1])
    t2 = traces[:, poi2] - np.mean(traces[:, poi2])
    combined = t1 * t2  # Product of centered leakages
    return combined     # Run standard CPA on combined value
```

#### Template Attacks

Template attacks (Chari et al., 2002) are the most powerful single-trace attacks. They require a training phase on a copy of the target device where the key is known, then a matching phase on the actual target.

Template attacks can recover keys from a **single trace** against unprotected implementations - the theoretical optimum for passive side-channel attacks.

#### Leakage Assessment: t-TVLA

Before investing in full CPA, use **Test Vector Leakage Assessment (TVLA)** to determine whether a device leaks at all, and where:

```python
from scipy.stats import ttest_ind

def tvla_assessment(traces_fixed, traces_random):
    t_stats = np.zeros(traces_fixed.shape[1])
    
    for t in range(traces_fixed.shape[1]):
        t_stat, _ = ttest_ind(
            traces_fixed[:, t], traces_random[:, t], equal_var=False
        )
        t_stats[t] = t_stat
    
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

## Related Files
- [Chapter4.md](Chapter4.md) - Theory foundation: DPA, CPA, and EM side-channel concepts implemented in this chapter
- [Chapter2.md](Chapter2.md) - Electrical fundamentals: shunt resistor calculation, probe loading, and decoupling cap removal for clean power traces
- [Chapter3.md](Chapter3.md) - Fault injection: the active attack complement; often combined with power analysis in advanced assessments

---

<div align="center">

**End of Hardware Hacking Guide**

[← Chapter 4: Timing & Power Analysis](./Chapter4.md) · [Back to Hardware Hacking README](./README.md)

</div>
