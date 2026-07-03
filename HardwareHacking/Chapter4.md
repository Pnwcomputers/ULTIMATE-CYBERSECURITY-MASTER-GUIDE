
# Chapter 4: Timing and Power Analysis Attacks

## 🎯 Purpose
Introduction to passive side-channel attacks — covering timing attacks, Simple Power Analysis (SPA), Differential Power Analysis (DPA), Correlation Power Analysis (CPA), electromagnetic (EM) side-channel, and acoustic side-channel, including the statistical foundations and trace collection methodology.

## ⚙️ Function
Covers: what leaks via power/time/EM/acoustic, timing attack theory and implementation, SPA trace interpretation, DPA statistical approach (difference of means), CPA with Pearson correlation, EM measurement setup, acoustic analysis, and sample size requirements for different attack levels (unprotected AES, masked AES, RSA).

## 🏆 Goal
Extract a cryptographic key (AES, RSA) or reveal secret-dependent computation paths from a target device's physical observables without triggering any software-level security detection.

## 📋 When to Use
- Evaluating whether a cryptographic implementation leaks key material via power consumption
- When active attacks (JTAG, fault injection) are blocked but passive observation is feasible
- Validating the effectiveness of masking countermeasures on development hardware
- Advanced red-team assessments requiring key extraction from HSMs or secure elements

> *Part of the [Hardware Hacking Guide](./README.md) — [ULTIMATE CYBERSECURITY MASTER GUIDE](../README.md)*

---

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

If a security-sensitive operation takes different amounts of time depending on the secret value or on secret-dependent branches, an attacker can recover the secret by measuring execution time.

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

An attacker can recover the password one character at a time — the correct first character takes slightly longer (comparison proceeds to byte 2).

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

The total time correlates with the Hamming weight of `d`. Countermeasure: **Montgomery ladder** (always square and multiply, discard one result) or **blinding** (randomize inputs before exponentiation).

---

#### Cache Timing (Software Side-Channel)

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

- **Switching activity:** CMOS gates consume power only when switching (0→1 or 1→0)
- **Hamming weight model:** Power ∝ number of 1-bits in the data being processed
- **Hamming distance model:** Power ∝ number of bits that change between consecutive operations

<p align="center">
  <img src="/assets/SPAonRSA.jpg" alt="Figure 10: Annotated SPA Trace of RSA. Visualizing modular Square versus Multiply operations during modular exponentiation." width="600"/>
</p>

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
plt.show()
```

---

### Differential Power Analysis (DPA)

DPA uses **statistical analysis across many traces** to extract secret key bits, even when individual traces are too noisy for visual analysis. Introduced by Kocher, Jaffe, and Jun in 1999.

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

SBOX = [0x63, 0x7c, 0x77, ...]  # Full 256-entry AES S-Box table

def dpa_aes_byte(traces, plaintexts, byte_idx):
    N, T = traces.shape
    correlations = np.zeros(256)
    
    for k_guess in range(256):
        hyp = np.array([
            hamming_weight(SBOX[plaintexts[i, byte_idx] ^ k_guess])
            for i in range(N)
        ])
        r_values = np.array([pearsonr(hyp, traces[:, t])[0] for t in range(T)])
        correlations[k_guess] = np.max(np.abs(r_values))
    
    return correlations

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

## Related Files
- [Chapter5.md](Chapter5.md) — Practical power analysis: hands-on measurement setup, trace acquisition, and TVLA analysis
- [Chapter2.md](Chapter2.md) — Electrical fundamentals: shunt resistor measurement and oscilloscope techniques for trace collection
- [Chapter3.md](Chapter3.md) — Fault injection: active attack complement to passive side-channel analysis

---

<div align="center">

**Next:** [Chapter 5 — Power Analysis Practicals →](./Chapter5.md)

[← Chapter 3: Fault Injection](./Chapter3.md) · [Back to Hardware Hacking README](./README.md)

</div>
