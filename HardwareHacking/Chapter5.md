
# Chapter 5: Power Analysis — Practical Techniques

## 🎯 Purpose
Hands-on guide to real-world power analysis — covering measurement hardware setup, trace acquisition scripts, signal processing (filtering, alignment, PCA), CPA attack implementation in Python/NumPy, and Test Vector Leakage Assessment (TVLA) for validating leakage before committing to a full attack campaign.

## ⚙️ Function
Covers: oscilloscope/current probe hardware configuration, shunt resistor insertion, Python trace acquisition via scope API (Rigol/PicoScope), trigger synchronization, trace preprocessing (bandpass filter, cross-correlation alignment, PCA dimensionality reduction), CPA attack on AES SubBytes with NumPy, and TVLA Welch t-test leakage detection.

## 🏆 Goal
Successfully acquire clean power traces, align them by trigger, and execute a CPA attack that recovers the AES key from a target microcontroller, or confirm via TVLA whether meaningful side-channel leakage exists before investing in a full trace campaign.

## 📋 When to Use
- After Chapter 4 theory: applying DPA/CPA concepts in a real lab setup
- Setting up a power analysis testbed for a new target device
- Validating whether a device leaks before investing in 10,000+ trace campaigns
- Measuring the effectiveness of masking or other countermeasures

> *Part of the [Hardware Hacking Guide](./README.md) — [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

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

**Amplification:** For small current devices, the power signal may be only 1–5 mV. Add a low-noise amplifier (e.g., Stanford Research SR560) with 20–40 dB gain between the shunt and oscilloscope.

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

- **Interleave plaintext randomization:** Use a CSPRNG for plaintext generation, not sequential values
- **Temperature stability:** Let the bench warm up 15–30 minutes; temperature drift causes trace misalignment
- **Capture sufficient traces:** Start with 1,000; increase if CPA peak is ambiguous
- **Validate trigger consistency:** Check trigger-to-first-sample jitter — even 1 clock cycle of jitter significantly degrades DPA quality

```python
import chipwhisperer as cw
import numpy as np

N_TRACES = 5000
traces = np.zeros((N_TRACES, scope.adc.samples))
plaintexts = np.zeros((N_TRACES, 16), dtype=np.uint8)
ciphertexts = np.zeros((N_TRACES, 16), dtype=np.uint8)

ktp = cw.ktp.Basic()

for i in range(N_TRACES):
    key, pt = ktp.next()
    cw.capture_trace(scope, target, pt, key)
    wave = scope.get_last_trace()
    
    if wave is not None:
        traces[i] = wave
        plaintexts[i] = list(pt)
        ciphertexts[i] = list(target.simpleserial_read('r', 16))
    
    if i % 100 == 0:
        print(f"Captured {i}/{N_TRACES}")

np.save('traces.npy', traces)
np.save('plaintexts.npy', plaintexts)
```

---

### Filtering and Signal Processing

#### Low-Pass Filtering

Removes high-frequency noise above the target signal band:

```python
from scipy.signal import butter, filtfilt
import numpy as np

def lowpass_filter(traces, cutoff_hz, sample_rate_hz, order=4):
    nyq = sample_rate_hz / 2
    normal_cutoff = cutoff_hz / nyq
    b, a = butter(order, normal_cutoff, btype='low', analog=False)
    return filtfilt(b, a, traces, axis=1)

# Example: target at 7.37 MHz clock, captured at 100 MSa/s
filtered_traces = lowpass_filter(traces, cutoff_hz=15e6, sample_rate_hz=100e6)
```

#### Band-Pass Filtering

```python
def bandpass_filter(traces, low_hz, high_hz, sample_rate_hz, order=4):
    nyq = sample_rate_hz / 2
    low = low_hz / nyq
    high = high_hz / nyq
    b, a = butter(order, [low, high], btype='band', analog=False)
    return filtfilt(b, a, traces, axis=1)
```

#### Trace Alignment — SAD Method

Timing jitter between traces destroys DPA correlation. Alignment corrects this.

```python
def align_traces_sad(traces, reference_trace, search_window=50):
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
        
        if best_offset >= 0:
            aligned[i, :ref_len - best_offset] = trace[best_offset:ref_len]
        else:
            aligned[i, -best_offset:] = trace[:ref_len + best_offset]
    
    return aligned

reference = np.mean(traces[:50], axis=0)
aligned_traces = align_traces_sad(traces, reference, search_window=100)
```

#### Cross-Correlation Alignment (More Robust)

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

### Correlation Power Analysis (CPA)

<p align="center">
  <img src="/assets/CPACorrelationProcess.jpg" alt="Figure 11: CPA Process Diagram. Summarizing the statistical key guessing attack." width="600"/>
</p>

CPA (Brier et al., 2004) is the modern standard — more efficient than original DPA's difference-of-means. Uses Pearson correlation coefficient.

```python
def cpa_attack(traces, plaintexts, byte_idx, poi_start=0, poi_end=None):
    if poi_end is None:
        poi_end = traces.shape[1]
    
    N = traces.shape[0]
    T = poi_end - poi_start
    traces_poi = traces[:, poi_start:poi_end]
    
    traces_mean = np.mean(traces_poi, axis=0)
    traces_std = np.std(traces_poi, axis=0) + 1e-10
    
    correlation_matrix = np.zeros((256, T))
    
    for k_guess in range(256):
        hw = np.array([
            hamming_weight(SBOX[int(plaintexts[i, byte_idx]) ^ k_guess])
            for i in range(N)
        ])
        
        hw_mean = np.mean(hw)
        hw_std = np.std(hw) + 1e-10
        
        centered_hw = hw - hw_mean
        centered_traces = traces_poi - traces_mean
        
        numerator = np.dot(centered_hw, centered_traces) / N
        correlation_matrix[k_guess] = numerator / (hw_std * traces_std)
    
    return correlation_matrix

corr = cpa_attack(aligned_traces, plaintexts, byte_idx=0)
max_corr_per_guess = np.max(np.abs(corr), axis=1)
recovered_byte = np.argmax(max_corr_per_guess)
print(f"Recovered key byte 0: 0x{recovered_byte:02X}")
print(f"Correlation: {max_corr_per_guess[recovered_byte]:.4f}")
```

---

### Visualization

#### Trace Overlay Plot

```python
def plot_trace_overlay(traces, n_show=100, title="Power Traces"):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 8), sharex=True)
    
    for i in range(min(n_show, len(traces))):
        ax1.plot(traces[i], alpha=0.05, color='blue', linewidth=0.5)
    ax1.plot(np.mean(traces, axis=0), color='red', linewidth=1.5, label='Mean')
    ax1.set_ylabel('Power (ADC units)')
    ax1.set_title(f'{title} — Overlay ({n_show} traces)')
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
    ax1.set_title(f'CPA Correlation Map — Key Byte {byte_idx}')
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

Template attacks can recover keys from a **single trace** against unprotected implementations — the theoretical optimum for passive side-channel attacks.

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
- [Chapter4.md](Chapter4.md) — Theory foundation: DPA, CPA, and EM side-channel concepts implemented in this chapter
- [Chapter2.md](Chapter2.md) — Electrical fundamentals: shunt resistor calculation, probe loading, and decoupling cap removal for clean power traces
- [Chapter3.md](Chapter3.md) — Fault injection: the active attack complement; often combined with power analysis in advanced assessments

---

<div align="center">

**End of Hardware Hacking Guide**

[← Chapter 4: Timing & Power Analysis](./Chapter4.md) · [Back to Hardware Hacking README](./README.md)

</div>
