# Software Defined Radio (SDR)

> **Scope:** Software Defined Radio theory, practice, and applications — from building your first virtual receiver in GNU Radio through advanced signal intelligence, protocol reversing, wideband monitoring, and FPGA-accelerated DSP. Bridges foundational tutorials and advanced RF security applications including Wi-Fi, Bluetooth, cellular, GPS, and satellite systems.
>
> **Legal notice:** Transmitting on licensed frequencies without authorization violates FCC regulations (47 CFR) and equivalent international law. Receiving and analyzing signals is generally legal in most jurisdictions; decrypting communications you're not authorized to receive may not be. Always verify local law. This section is written for licensed radio operators, security researchers, and students with appropriate authorization.

---

## Table of Contents

- [Part I: Foundations](#part-i-foundations)
  - [Chapter 1: What is SDR?](#chapter-1-what-is-sdr)
  - [Chapter 2: IQ Sampling and the Complex Signal Model](#chapter-2-iq-sampling-and-the-complex-signal-model)
  - [Chapter 3: SDR Hardware](#chapter-3-sdr-hardware)
  - [Chapter 4: Antennas and RF Front End](#chapter-4-antennas-and-rf-front-end)
- [Part II: GNU Radio Companion](#part-ii-gnu-radio-companion)
  - [Chapter 5: GNU Radio Fundamentals](#chapter-5-gnu-radio-fundamentals)
  - [Chapter 6: Building an AM Receiver](#chapter-6-building-an-am-receiver)
  - [Chapter 7: Building an FM Receiver](#chapter-7-building-an-fm-receiver)
  - [Chapter 8: Building a Transmitter](#chapter-8-building-a-transmitter)
- [Part III: Signal Processing Deep Dive](#part-iii-signal-processing-deep-dive)
  - [Chapter 9: Filters and Gain Control](#chapter-9-filters-and-gain-control)
  - [Chapter 10: Modulation and Demodulation](#chapter-10-modulation-and-demodulation)
  - [Chapter 11: Digital Signal Processing in Python](#chapter-11-digital-signal-processing-in-python)
- [Part IV: Protocols and Applications](#part-iv-protocols-and-applications)
  - [Chapter 12: Trunked Radio and APRS](#chapter-12-trunked-radio-and-aprs)
  - [Chapter 13: Wi-Fi, Bluetooth, and Short-Range RF](#chapter-13-wi-fi-bluetooth-and-short-range-rf)
  - [Chapter 14: Cellular Communications](#chapter-14-cellular-communications)
  - [Chapter 15: GPS and Satellite Signals](#chapter-15-gps-and-satellite-signals)
- [Part V: Advanced Techniques](#part-v-advanced-techniques)
  - [Chapter 16: SIGINT and Signal Reversal](#chapter-16-sigint-and-signal-reversal)
  - [Chapter 17: Wideband Monitoring and High-Speed Converters](#chapter-17-wideband-monitoring-and-high-speed-converters)
  - [Chapter 18: FPGA and High-Speed DSP Acceleration](#chapter-18-fpga-and-high-speed-dsp-acceleration)
  - [Chapter 19: Cognitive Radio and Adaptive Waveforms](#chapter-19-cognitive-radio-and-adaptive-waveforms)
- [Appendix A: Frequency Reference](#appendix-a-frequency-reference)
- [Appendix B: Recommended Software Stack](#appendix-b-recommended-software-stack)

---

## Part I: Foundations

### Chapter 1: What is SDR?

#### The Traditional Radio Problem

A conventional radio receiver is a collection of discrete hardware components: tuned LC circuits for frequency selection, mixers for down-conversion, IF amplifiers, detectors, and audio stages. To receive a different frequency band or a different modulation type, you need different hardware — different capacitors, inductors, crystals, and filter networks.

This is expensive, inflexible, and fundamentally limiting. A police scanner that handles P25 digital trunking cannot be repurposed to decode ADS-B aircraft transponders without different hardware.

**SDR flips this model:** Move the analog-to-digital conversion as close to the antenna as possible, then do everything else — tuning, filtering, demodulation, decoding — in software running on a general-purpose computer. Changing what the radio does means changing the software, not the hardware.

```
Traditional Radio:
  Antenna → [Tuned Circuit] → [Mixer] → [IF Filter] → [Detector] → [Audio Amp] → Speaker
  (Hardware for each function; one radio = one purpose)

Software Defined Radio:
  Antenna → [LNA] → [Mixer + ADC] → USB/PCIe → [Computer: everything else in software]
  (Hardware only up to digitization; one hardware = infinite software radios)
```

#### What SDR Can Do

With appropriate hardware and software, a single SDR platform can function as:

- AM/FM broadcast receiver
- Aircraft transponder (ADS-B) decoder
- Weather satellite image receiver (NOAA APT, Meteor-M LRPT)
- Trunked public safety radio scanner
- GPS/GNSS receiver (with appropriate processing)
- Spectrum analyzer and signal monitor
- Digital modes receiver (FT8, WSPR, APRS, DMR, P25, TETRA)
- RF signal intelligence platform
- Cellular network monitor (passive)
- Bluetooth and ZigBee traffic analyzer
- Custom protocol decoder for proprietary/unknown signals

#### The SDR Signal Chain

```
RF Environment
     │
  [Antenna]          Converts electromagnetic wave to voltage
     │
  [Optional LNA]     Low-noise amplification before signal degradation
     │
  [Optional Filter]  Band-pass filter to reject out-of-band signals
     │
  [SDR Hardware]
    ├── [RF Tuner / Down-converter]    Shifts desired frequency to baseband
    ├── [ADC]                          Digitizes the analog signal
    └── [USB / PCIe interface]         Transfers samples to computer
     │
  [Computer - Software Domain]
    ├── [Sample buffer]                Raw IQ samples arrive here
    ├── [Digital down-conversion]      Fine frequency tuning in software
    ├── [Decimation / filtering]       Reduce sample rate; select bandwidth
    ├── [Demodulation]                 AM/FM/PM/digital demod
    ├── [Decoding]                     Protocol-specific processing
    └── [Output]                       Audio, data, display
```

---

### Chapter 2: IQ Sampling and the Complex Signal Model

Understanding IQ (In-phase / Quadrature) sampling is the single most important conceptual foundation for SDR work. Everything in the software domain operates on IQ data.

#### Why Not Just Sample the RF Signal Directly?

A 100 MHz FM signal, sampled directly, would require an ADC running at >200 MSa/s (Nyquist). A 2.4 GHz Wi-Fi signal would need >4.8 GSa/s. These sample rates are expensive and generate enormous data streams.

Instead, SDR hardware **down-converts** the desired signal to near-DC (baseband) before sampling. The RF tuner acts as a mixer, multiplying the incoming RF signal by a local oscillator (LO) at the desired center frequency. The result is a baseband signal whose frequency is the offset between the original signal and the LO.

#### The I and Q Components

When down-converting to baseband, you need to capture **two** quadrature components to preserve complete information about the original signal (both amplitude and phase):

```
I (In-phase):     Result of mixing RF with LO: cos(2π·f_LO·t)
Q (Quadrature):   Result of mixing RF with LO: sin(2π·f_LO·t) = cos(2π·f_LO·t - 90°)

Together: s(t) = I(t) + j·Q(t)  (complex baseband signal)
```

The key insight: **a complex (IQ) sample represents a rotating phasor in the complex plane.** The phasor's magnitude is signal amplitude; its angle is instantaneous phase; its rotation rate is instantaneous frequency offset from the LO.

```
       Q
       │
   s = I + jQ
       │ /
       │/ ← magnitude = √(I² + Q²) = amplitude
   ────┼────── I
       │  ← angle = arctan(Q/I) = phase
       │
```

#### Why IQ Matters for SDR Work

| Application | What IQ Tells You |
|-------------|-------------------|
| **AM demodulation** | Magnitude: `√(I² + Q²)` is the audio envelope |
| **FM demodulation** | Phase derivative: `d/dt[arctan(Q/I)]` is audio |
| **Phase modulation** | Phase angle directly encodes data |
| **QAM** | Both I and Q encode symbols in the constellation |
| **Frequency offset** | DC offset in spectrum = tuning error between LO and signal |
| **Direction finding** | Phase difference between two antennas encodes angle of arrival |

#### IQ Imbalance

Real hardware has imperfect IQ components. Small amplitude or phase mismatches between I and Q paths create a **mirror image** artifact in the spectrum — a weaker copy of every signal reflected around the center frequency. This is a common source of confusion for new SDR users.

```
Perfect IQ:           IQ with amplitude imbalance:
  [signal] [noise]      [signal] [noise] [mirror image]
   -1MHz    0    +1MHz   -1MHz    0    +1MHz
```

Correction: GNU Radio includes an IQ Balance block; RTL-SDR Blog's SDR# has automatic IQ correction.

#### Sampling Rate vs. Bandwidth

The sample rate (samples per second) directly equals the observable bandwidth:

```
Sample rate 2.4 MSa/s = 2.4 MHz bandwidth visible around center frequency
Sample rate 20 MSa/s = 20 MHz bandwidth (HackRF, USRP at modest rates)
```

To observe a 100 kHz FM station at 100.1 MHz: tune LO to 100.1 MHz; use sample rate of at least 200 kSa/s. The station appears as energy centered near 0 Hz in the baseband spectrum.

---

### Chapter 3: SDR Hardware

#### Entry-Level: RTL-SDR Receivers

The RTL2832U USB TV tuner chipset, originally designed for DVB-T digital television, was discovered in 2012 to support raw IQ sample output — creating the RTL-SDR revolution.

##### RTL-SDR Blog V3 (Recommended Entry Point)

The current reference standard for budget SDR.

| Specification | Value |
|--------------|-------|
| **Frequency range** | 500 kHz – 1.75 GHz (with direct sampling mod for HF) |
| **Sample rate** | Up to 3.2 MSa/s (2.56 MSa/s reliable) |
| **ADC resolution** | 8-bit |
| **Dynamic range** | ~50 dB |
| **LNA** | Built-in, software-controlled gain |
| **Cost** | ~$30 |
| **Interface** | USB 2.0 |
| **Connector** | SMA |

**Unique features of V3:**
- Direct sampling mode: SW1/SW2 ports allow HF (below 24 MHz) reception via direct ADC sampling — bypasses the tuner for shortwave, MW, and LW
- Bias tee (software-enabled): 4.5V DC on antenna connector to power inline LNAs
- TCXO oscillator: temperature-compensated crystal for better frequency stability than earlier RTL-SDR sticks

**Driver installation:**

```bash
# Linux (most distros)
sudo apt install rtl-sdr
sudo rtl_test -t          # Verify device detected; check for dropped samples

# Windows: use Zadig to install WinUSB driver
# https://zadig.akeo.ie — select RTL2838UHIDIR, install WinUSB

# Test: receive and display FM spectrum
rtl_fm -f 100.1M -M wbfm -s 200000 -r 48000 - | aplay -r 48k -f S16_LE
```

##### Nooelec NESDR Series

Popular alternatives to the RTL-SDR Blog V3. Multiple variants:

| Model | Notes |
|-------|-------|
| **NESDR Smart** | Standard RTL-SDR; aluminum enclosure; TCXO |
| **NESDR Smart XTR** | Extended range to 2.2 GHz; different tuner (E4000) |
| **NESDR SMArt Bundle** | Includes antennas, case; good starter kit |
| **NESDR Mini 2+** | Compact; good for portable use |

Nooelec also produces:
- **Ham It Up Plus** — Upconverter for HF; shifts HF signals up into RTL-SDR's tuning range (100 MHz + HF input)
- **Ham It Down** — Downconverter for microwave frequencies (2.4–6 GHz) down into receive range
- **LaNA** — Low-noise amplifier (20 dB gain, 0.5–4 GHz) for weak signal work
- **Flamingo FM filter** — Band-stop filter to reject 88–108 MHz FM broadcast; reduces overloading in wideband scans

---

#### Mid-Range: Airspy

Significant step up from RTL-SDR in dynamic range and sample rate.

##### Airspy R2

| Specification | Value |
|--------------|-------|
| **Frequency range** | 24 – 1800 MHz |
| **Sample rate** | 2.5 or 10 MSa/s (real); 20 MSPS IQ |
| **ADC resolution** | 12-bit |
| **Dynamic range** | ~80 dB (vs. ~50 dB for RTL-SDR) |
| **Spurious-free dynamic range** | ~65 dB |
| **Cost** | ~$109 |

The 12-bit ADC is the key advantage: 4 additional bits over RTL-SDR's 8-bit = 24 dB more dynamic range. Strong signals no longer saturate the ADC and mask weaker signals in the same band.

##### Airspy HF+ Discovery

Specialized for HF and VHF reception; exceptional performance in its range.

| Specification | Value |
|--------------|-------|
| **Frequency range** | 0.5 kHz – 31 MHz (HF), 60 – 260 MHz (VHF) |
| **ADC resolution** | 18-bit sigma-delta |
| **Dynamic range** | >110 dB in HF |
| **Cost** | ~$169 |

Best-in-class for shortwave, amateur HF, medium wave, and VHF air band. Not suitable for UHF or above.

##### Airspy Accessories

| Accessory | Purpose |
|-----------|---------|
| **SpyVerter** | Upconverter for HF; pairs with Airspy R2 |
| **Airspy YouLoop** | Passive magnetic loop antenna; excellent for HF |
| **Airspy Mini** | Budget version; 6 MHz bandwidth; 12-bit |

---

#### High Performance: HackRF One

The benchmark open-source SDR platform for security research.

| Specification | Value |
|--------------|-------|
| **Frequency range** | 1 MHz – 6 GHz |
| **Sample rate** | Up to 20 MSa/s |
| **ADC/DAC resolution** | 8-bit |
| **Duplex** | Half-duplex (TX or RX, not simultaneous) |
| **TX capability** | Yes — 1 mW to ~10 mW output |
| **Cost** | ~$340 (Great Scott Gadgets); ~$50-80 (clones — quality varies) |
| **Interface** | USB 2.0 (bandwidth-limited at high sample rates) |
| **Open source** | Fully open hardware and firmware |

**Key advantage:** Transmit capability across 1 MHz – 6 GHz makes it essential for RF security testing, signal generation, replay attacks (authorized testing only), and custom protocol development.

**Key limitation:** 8-bit ADC gives lower dynamic range than Airspy; USB 2.0 interface limits sustained high sample rate performance; half-duplex means no simultaneous TX/RX.

**HackRF One accessories:**
- **PortaPack H2** — Standalone operation without a PC; touchscreen; battery power; enables portable spectrum analysis and signal generation
- **SMA antenna set** — Quarter-wave for various bands
- **Clock reference input** — For GPS-disciplined or rubidium-locked timing

**Common security research workflows:**

```bash
# Capture raw IQ to file (10 MHz around 433 MHz for ISM band analysis)
hackrf_transfer -r capture_433.iq -f 433920000 -s 10000000 -g 40 -l 32 -n 100000000

# Transmit from IQ file (authorized testing only)
hackrf_transfer -t payload.iq -f 433920000 -s 10000000 -x 40

# Sweep spectrum and output power vs. frequency
hackrf_sweep -f 2400:2500 -g 40 -l 32 -w 100000 > wifi_sweep.csv
```

---

#### Research Grade: USRP and Others

| Platform | Range | Sample Rate | ADC | Cost | Notes |
|----------|-------|------------|-----|------|-------|
| **USRP B200mini** | 70 MHz – 6 GHz | 61.44 MSa/s | 12-bit | ~$700 | Full-duplex; USB 3.0 |
| **USRP B210** | 70 MHz – 6 GHz | 61.44 MSa/s (2ch) | 12-bit | ~$1,100 | 2TX/2RX; MIMO |
| **USRP N310** | 10 MHz – 6 GHz | 250 MSa/s | 14-bit | ~$8,000 | 4-channel; 10GbE |
| **LimeSDR** | 100 kHz – 3.8 GHz | 61.44 MSa/s | 12-bit | ~$300 | Full-duplex; FPGA |
| **LimeSDR Mini 2** | 10 MHz – 3.5 GHz | 30.72 MSa/s | 12-bit | ~$200 | Compact; USB 3.0 |
| **Pluto SDR** | 325 MHz – 3.8 GHz | 61.44 MSa/s | 12-bit | ~$150 | Xilinx Zynq; hackable |

---

#### SDR Hardware Comparison Matrix

| Device | Freq Range | RX BW | TX | ADC | Dynamic Range | Best For |
|--------|-----------|-------|-----|-----|--------------|---------|
| RTL-SDR V3 | 500 kHz–1.75 GHz | 2.4 MHz | No | 8-bit | ~50 dB | Learning, ADS-B, FM, cheap scanning |
| Nooelec NESDR Smart | 25 MHz–1.75 GHz | 2.4 MHz | No | 8-bit | ~50 dB | Same as RTL-SDR V3 |
| Airspy R2 | 24–1800 MHz | 10 MHz | No | 12-bit | ~80 dB | FM DX, monitoring, better sensitivity |
| Airspy HF+ Discovery | 0–31 MHz / 60–260 MHz | 660 kHz | No | 18-bit | >110 dB | HF/shortwave; best HF receiver |
| HackRF One | 1 MHz–6 GHz | 20 MHz | Yes | 8-bit | ~50 dB | Security research; full spectrum TX/RX |
| LimeSDR Mini 2 | 10 MHz–3.5 GHz | 30 MHz | Yes | 12-bit | ~65 dB | Full-duplex research |
| USRP B210 | 70 MHz–6 GHz | 56 MHz | Yes | 12-bit | ~70 dB | Professional research; MIMO |

---

### Chapter 4: Antennas and RF Front End

#### Antenna Fundamentals

An antenna converts electromagnetic waves to electrical signals (and vice versa for TX). **No SDR setup performs better than its antenna.** A $300 SDR with a poor antenna will be outperformed by a $30 RTL-SDR with a well-chosen antenna.

**Key antenna parameters:**

| Parameter | Description | Impact |
|-----------|-------------|--------|
| **Gain (dBi)** | Signal amplification relative to isotropic radiator | Higher gain = more sensitive but narrower beam |
| **Bandwidth** | Frequency range over which antenna is resonant | Must cover target frequency |
| **Impedance** | Should match feed line (50 Ω for most SDR hardware) | Mismatch causes reflection loss (VSWR) |
| **Polarization** | Orientation of E-field (horizontal, vertical, circular) | Must match signal polarization |
| **Directionality** | Omnidirectional vs. directional | Omni for scanning; directional for DXing/targeting |

#### Quarter-Wave Monopole (Whip)

The simplest and most common antenna. Length = λ/4 at resonant frequency.

```
Frequency (MHz) → Wavelength (m) = 300 / freq → λ/4 length (cm) = 7500 / freq(MHz)

Examples:
  433 MHz → λ/4 = 17.3 cm
  915 MHz → λ/4 = 8.2 cm
  1090 MHz (ADS-B) → λ/4 = 6.9 cm
  2.4 GHz → λ/4 = 3.1 cm
```

Requires a ground plane (radials or metal surface) perpendicular to the element. Most RTL-SDR kits include a telescoping whip that can be adjusted to appropriate length.

#### Dipole

Two λ/4 elements in opposite directions. Does not require a ground plane. Total length = λ/2.

The **V-dipole** (elements in a V-shape, ~120° angle) provides good satellite signal reception at moderate elevation angles — recommended for NOAA and Meteor weather satellites.

#### Discone

Wideband omnidirectional. A cone-shaped ground element with a disc-shaped top. Operates from approximately 25 MHz to 1.3 GHz with usable gain across the entire range.

**Best general-purpose scanning antenna** for 25 MHz – 1.3 GHz. Essential for SDR kit.

Recommended: Tram 1411 or Diamond D-130J (~$60-90). Mount as high as possible; feed with low-loss coax (LMR-195 or LMR-400 for longer runs).

#### Yagi-Uda

Highly directional, high-gain. A driven element plus multiple parasitic directors and a reflector.

- 3-element Yagi: ~7 dBd gain, ~60° beamwidth
- 10-element Yagi: ~12 dBd gain, ~25° beamwidth

Use for: satellite tracking, weak signal DXing, point-to-point microwave, signal direction-finding when combined with rotation.

#### Patch and Panel Antennas

Flat, moderate-gain directional antennas. Common for 1.2 GHz, 1.575 GHz (GPS L1), 2.4 GHz, and 5.8 GHz.

- **GPS patch antenna** — Right-hand circular polarized (RHCP); center-fed; typically 3–5 dBi gain; active (built-in LNA, requires bias tee power)
- **2.4 GHz panel** — Good for Wi-Fi monitoring; 10–15 dBi typical
- **L-band patch** — Iridium, GPS, weather satellite reception

#### Recommended Antenna Kit by Use Case

| Use Case | Recommended Antenna | Approximate Cost |
|----------|-------------------|-----------------|
| **General scanning (25 MHz – 1.3 GHz)** | Discone (Tram 1411, Diamond D-130J) | $60–90 |
| **ADS-B (1090 MHz)** | FlightAware 1090 MHz antenna or 1/4-wave with groundplane | $20–45 |
| **NOAA/Meteor satellites** | V-dipole (DIY from coax) or turnstile | $0–20 |
| **HF/shortwave** | Airspy YouLoop, random wire with 9:1 unun, magnetic loop | $30–150 |
| **Wi-Fi/2.4 GHz monitoring** | 2.4 GHz patch panel or Yagi | $15–40 |
| **Wideband scanning (1–6 GHz)** | HackRF stock antenna + SMA log-periodic | $20–80 |
| **APRS/VHF** | J-pole or 5/8-wave ground plane for 144 MHz | $20–50 |
| **Direction finding** | Yagi + rotator, or handheld directional | $50–200 |

---

#### RF Front End Components

**Low-Noise Amplifiers (LNA)**

An LNA placed between the antenna and the SDR amplifies weak signals before the SDR's own noise figure degrades them. Effective only if placed close to the antenna (before coax loss).

The **Friis noise formula** explains why: the first component in the chain dominates total noise figure. A good LNA (NF < 1 dB) before a lossy coax run dramatically improves system sensitivity.

| LNA | Frequency | Gain | NF | Notes |
|-----|----------|------|-----|-------|
| **RTL-SDR Blog Triple-Filtered LNA** | 0–2 GHz | 20 dB | <1 dB | Three filter stages; prevents FM/cellular overload |
| **Nooelec LaNA** | 0.5–4 GHz | 20 dB | <0.5 dB | Excellent wideband LNA |
| **Uputronics ADS-B LNA** | ~1 GHz | 20 dB | 0.8 dB | 1090 MHz bandpass + LNA combined |
| **SAWbird+ NOAA** | 137–138 MHz | 20 dB | 0.8 dB | For NOAA weather satellite band |
| **SAWbird+ GPS** | 1.575 GHz | 20 dB | <1 dB | GPS L1 band optimized |
| **Mini-Circuits ZX60-P33ULN+** | DC–3.5 GHz | 14 dB | 0.47 dB | Research grade; low NF |

**Bandpass Filters**

Filters reject out-of-band signals that would otherwise overload or desensitize the SDR. Essential in RF-dense environments.

| Filter | Band | Purpose |
|--------|------|---------|
| **FM broadcast notch filter** | Rejects 88–108 MHz | Prevents FM overload on wideband scans |
| **ADS-B bandpass (1090 MHz)** | Passes ~1080–1100 MHz | Rejects all other signals for clean ADS-B |
| **NOAA bandpass (137 MHz)** | Passes ~136–138 MHz | Weather satellite reception |
| **GPS bandpass (1575 MHz)** | Passes ~1570–1580 MHz | GPS signal isolation |
| **LTE/cellular notch** | Rejects 700 MHz–2.7 GHz (LTE) | Prevents cellular overload |
| **Cavity filters (custom)** | Narrow bandpass; project-specific | High Q; requires tuning |

**Coaxial Cable and Connectors**

Loss in coax cable increases with frequency. At 1 GHz, even 10 feet of RG-58 introduces significant signal loss.

| Cable | Loss at 100 MHz | Loss at 1 GHz | Notes |
|-------|----------------|--------------|-------|
| RG-174 | 4 dB/100ft | ~14 dB/100ft | Thin, flexible; short runs only |
| RG-58 | 2.5 dB/100ft | 9 dB/100ft | Common; usable to ~500 MHz |
| RG-8X | 1.8 dB/100ft | 6 dB/100ft | Good balance of flexibility and loss |
| **LMR-195** | 1.1 dB/100ft | 4.4 dB/100ft | Recommended for SDR antenna runs |
| **LMR-400** | 0.6 dB/100ft | 2.2 dB/100ft | Low-loss; for longer runs |
| LMR-600 | 0.4 dB/100ft | 1.5 dB/100ft | Large diameter; mast/tower use |

**Rule:** Keep coax runs short. Place the LNA at the antenna end of any long coax run to amplify before cable loss occurs.

---

## Part II: GNU Radio Companion

### Chapter 5: GNU Radio Fundamentals

#### What is GNU Radio?

GNU Radio is an open-source signal processing framework and visual programming environment. It provides:

- A library of signal processing blocks (sources, sinks, filters, modulators, demodulators, etc.)
- **GNU Radio Companion (GRC)** — a graphical flowgraph editor that connects blocks visually
- Python and C++ APIs for programmatic use
- Hardware abstraction (gr-osmosdr) supporting virtually all SDR hardware

Everything in GNU Radio is a **flowgraph**: data (streams of complex or real samples) flows from source blocks through processing blocks to sink blocks.

#### Installation

```bash
# Ubuntu/Debian
sudo apt install gnuradio gqrx-sdr gr-osmosdr

# Arch Linux
sudo pacman -S gnuradio gnuradio-companion gr-osmosdr

# macOS (Homebrew)
brew install gnuradio

# Windows: use GNU Radio installer from gnuradio.org
# Or WSL2 with X11 forwarding

# Verify installation
gnuradio-config-info --version
python3 -c "import gnuradio; print(gnuradio.__version__)"

# Launch GRC
gnuradio-companion
```

#### The GRC Interface

```
┌──────────────────────────────────────────────────────────┐
│  Menu bar                                                │
├────────────────────────────────┬─────────────────────────┤
│                                │  Block library          │
│  Flowgraph canvas              │  (searchable)           │
│                                │                         │
│  [Block]──>[Block]──>[Block]   │  Sources                │
│                                │  Sinks                  │
│  [Block]──>[Block]             │  Filters                │
│                                │  Modulators             │
│                                │  Math operators         │
│                                │  Visualizations         │
│                                │  Instrumentation        │
│                                │  ...                    │
├────────────────────────────────┴─────────────────────────┤
│  Status bar / error messages                             │
└──────────────────────────────────────────────────────────┘
```

**Key concepts:**

- **Blocks** are connected by ports — output port → input port
- **Port colors** indicate data type: blue = complex, orange = float, yellow = short, purple = byte
- **Sample rate** flows through the graph; changes require decimation/interpolation blocks
- **Parameters** (variables) can be set at graph level and referenced by any block
- **QT GUI** blocks provide real-time visualization (spectrum, waterfall, time domain, constellation)

#### Essential Block Categories

| Category | Key Blocks | Purpose |
|----------|-----------|---------|
| **Sources** | osmocom Source, File Source, Signal Source | Inputs to the flowgraph |
| **Sinks** | Audio Sink, File Sink, QT GUI Sink | Outputs from the flowgraph |
| **Visualization** | QT GUI Frequency Sink, Waterfall Sink, Time Sink, Constellation Sink | Real-time display |
| **Filtering** | Low Pass Filter, High Pass Filter, Band Pass Filter, Rational Resampler | Signal shaping and rate change |
| **Math** | Multiply, Add, Complex to Mag, Complex to Arg | Mathematical operations on samples |
| **Modulators** | NBFM Receive, WBFM Receive, AM Demod, GMSK, PSK | Modulation/demodulation |
| **Synchronization** | Costas Loop, Symbol Sync, Clock Recovery MM | Carrier and timing recovery |
| **Gain** | AGC, Multiply Const | Amplitude control |

#### Your First Flowgraph: Spectrum Display

A minimal flowgraph to display what your SDR is receiving:

```
[osmocom Source] → [QT GUI Frequency Sink]
                 → [QT GUI Waterfall Sink]
```

**Block configuration:**

*osmocom Source:*
- Device Arguments: `rtlsdr=0` (for RTL-SDR) or `hackrf=0`
- Sample Rate: `samp_rate` (set variable to 2400000)
- Center Freq: `center_freq` (set variable, e.g., 100100000 for 100.1 MHz)
- Gain: 30 dB
- IF Gain: 20 dB (HackRF only)

*QT GUI Frequency Sink:*
- Sample Rate: `samp_rate`
- Center Frequency: `center_freq`
- Bandwidth: `samp_rate`

This produces a live spectrum display showing all signals within the SDR's current sample bandwidth.

---

### Chapter 6: Building an AM Receiver

#### How AM Works

Amplitude Modulation encodes audio by varying the carrier wave's amplitude:

```
Carrier:     sin(2π·f_c·t)
Audio:       m(t)  (normalized to -1 to +1 range)
AM signal:   [1 + m(t)] · sin(2π·f_c·t)
```

The audio signal appears as two sidebands (upper and lower) symmetrically around the carrier frequency. Demodulation recovers the audio by extracting the envelope (amplitude) of the received signal.

```
Spectrum of AM signal:
    carrier (f_c)
         │
    LSB  ↓  USB
  ──────│────── frequency
 f_c-BW f_c f_c+BW
```

#### AM Demodulation Methods

**Envelope detection (simple):**
`audio = √(I² + Q²)` — the magnitude of the complex baseband signal

**Synchronous AM demodulation:**
Multiplies received signal by a phase-locked copy of the carrier; more noise-resistant but requires carrier recovery.

#### AM Receiver Flowgraph

```
[osmocom Source] 
     │ (complex, 2.4 MSa/s)
     ▼
[Low Pass Filter]          ← Keep only AM station bandwidth (~10 kHz)
     │ (complex, 2.4 MSa/s)
     ▼
[Rational Resampler]       ← Decimate to 240 kSa/s (divide by 10)
     │ (complex, 240 kSa/s)
     ▼
[AGC]                      ← Automatic Gain Control for level normalization
     │ (complex, 240 kSa/s)
     ▼
[AM Demod]                 ← Complex to magnitude (envelope detection)
     │ (float, 240 kSa/s)
     ▼
[Rational Resampler]       ← Decimate to 48 kSa/s for audio output
     │ (float, 48 kSa/s)
     ▼
[Audio Sink]               ← Output to speakers
```

**Block parameters:**

*Low Pass Filter:*
- Decimation: 1 (keep sample rate; decimate in next block)
- Cutoff Freq: 5000 Hz (5 kHz = AM station half-bandwidth)
- Transition Width: 1000 Hz
- Window: Hamming

*Rational Resampler (first):*
- Interpolation: 1
- Decimation: 10

*AGC:*
- Rate: 1e-3
- Reference: 1.0
- Max Gain: 65536

*AM Demod:*
- Channel Rate: 240000
- Audio Decimation: 5 (final output at 48 kHz)
- Audio Pass: 5000 Hz
- Audio Stop: 5500 Hz

---

### Chapter 7: Building an FM Receiver

#### How FM Works

Frequency Modulation encodes audio by varying the instantaneous frequency of the carrier:

```
FM signal:   sin(2π·f_c·t + 2π·k_f·∫m(τ)dτ)
```

Where `k_f` is the frequency deviation constant. For wideband FM broadcast (WBFM), the maximum deviation is ±75 kHz. For narrowband FM (NBFM) used in voice communications, it's ±5 kHz or ±2.5 kHz.

**FM demodulation:** Extract instantaneous frequency from the baseband IQ signal:

```
Instantaneous phase: φ(t) = arctan(Q(t)/I(t))
Instantaneous frequency: f(t) = (1/2π) · dφ/dt
```

In discrete form: `f[n] = angle(conj(s[n-1]) * s[n])` — the angle of the product of consecutive samples with one conjugated.

#### WBFM (Broadcast FM) Receiver Flowgraph

```
[osmocom Source]           ← 2.4 MSa/s, center on station
     │ (complex, 2.4 MSa/s)
     ▼
[Rational Resampler]       ← Decimate to 480 kSa/s
     │ (complex, 480 kSa/s)
     ▼
[WBFM Receive]             ← FM discriminator + stereo pilot decode
     │ (float, 48 kSa/s)
     ▼
[Multiply Const]           ← Volume control (0.0 to 1.0)
     │ (float, 48 kSa/s)
     ▼
[Audio Sink]               ← Output to speakers (stereo)
```

The `WBFM Receive` block in GNU Radio handles the complete FM demodulation including de-emphasis (75 μs for North America; 50 μs for Europe) and stereo pilot tone decoding.

**WBFM Receive parameters:**
- Quadrature Rate: 480000 (must equal input sample rate)
- Audio Decimation: 10 (480000/10 = 48000 output)

#### NBFM (Voice/Public Safety) Receiver Flowgraph

```
[osmocom Source]           ← 2.4 MSa/s
     │
     ▼
[Low Pass Filter]          ← Pass only desired channel (~15 kHz)
     │
     ▼
[Rational Resampler]       ← Decimate to 48 kSa/s
     │
     ▼
[NBFM Receive]             ← Narrowband FM demodulation
     │ (float, 48 kSa/s)
     ▼
[Simple Squelch]           ← Mute when no signal present
     │
     ▼
[Audio Sink]
```

**NBFM vs WBFM comparison:**

| Parameter | WBFM (Broadcast) | NBFM (Voice) |
|-----------|-----------------|-------------|
| Max deviation | ±75 kHz | ±5 kHz |
| Channel spacing | 200 kHz | 12.5 or 25 kHz |
| Audio quality | Hi-fi stereo | Voice bandwidth only |
| Required sample rate | >200 kSa/s | >15 kSa/s |

#### FM Subcarriers: RDS Decoding

Broadcast FM stations multiplex additional data on subcarriers above 19 kHz:
- **19 kHz:** Stereo pilot tone
- **38 kHz:** Stereo difference signal (L-R)
- **57 kHz:** RDS (Radio Data System) — station name, song title, traffic info

```
WBFM RDS Decoder flow (extending the WBFM receiver):

[After FM demodulation, before audio sink]
     │
     ├─→ [Audio path] → [Audio Sink]
     │
     └─→ [Band Pass Filter (54-60 kHz)]
              │
              ▼
         [Rational Resampler] → 19 kSa/s
              │
              ▼
         [PSK Demod] → [Differential Decoder] → [RDS Parser]
              │
              ▼
         [Message Debug / QT GUI]
```

`gr-rds` is the standard GNU Radio module for RDS decoding.

---

### Chapter 8: Building a Transmitter

> **⚠️ Legal warning:** Transmitting on any frequency without appropriate authorization (ham radio license, FCC license, or explicit test authorization) is illegal. Transmit only on frequencies you are authorized to use, at authorized power levels, in authorized modes. The following covers transmitter design for licensed amateur radio operators and authorized testing environments.

#### FM Transmitter Flowgraph

An NBFM transmitter for amateur radio (licensed operators only):

```
[Audio Source / Microphone]     ← Input audio
     │ (float, 48 kSa/s)
     ▼
[High Pass Filter]              ← Remove DC offset from microphone
     │
     ▼
[Rational Resampler]            ← Upsample to 480 kSa/s
     │
     ▼
[NBFM Transmit]                 ← FM modulation (±5 kHz deviation)
     │ (complex, 480 kSa/s)
     ▼
[Rational Resampler]            ← Upsample to HackRF sample rate (2 MSa/s)
     │ (complex, 2 MSa/s)
     ▼
[osmocom Sink]                  ← HackRF TX output
```

**NBFM Transmit parameters:**
- Audio Rate: 48000
- Quadrature Rate: 480000
- Max Deviation: 5000 Hz (NBFM standard)
- Pre-emphasis: 75 μs (or 0 for flat response)

#### Signal Generator (Test Tone)

Useful for antenna range testing, filter characterization, and authorized transmitter testing:

```
[Signal Source]        ← Sine wave at desired frequency
     │ (complex)
     ▼
[Multiply Const]       ← Amplitude control
     │
     ▼
[osmocom Sink]         ← Transmit output
```

---

## Part III: Signal Processing Deep Dive

### Chapter 9: Filters and Gain Control

#### Filter Types and Applications

Filters are the most-used DSP building block in SDR work. Every signal extraction involves filtering to isolate the desired signal from noise and interference.

**Low-Pass Filter (LPF):** Passes frequencies below cutoff; rejects above.
- Use: Select a channel from a wideband capture; remove high-frequency noise; decimate preparation

**High-Pass Filter (HPF):** Passes frequencies above cutoff; rejects below.
- Use: Remove DC bias (offset at 0 Hz); remove low-frequency interference; AC-couple a signal path

**Band-Pass Filter (BPF):** Passes a range of frequencies; rejects above and below.
- Use: Isolate a specific signal from a crowded spectrum; match a specific protocol's bandwidth

**Band-Stop / Notch Filter:** Rejects a narrow frequency range; passes everything else.
- Use: Remove a strong interference source (e.g., FM broadcast) from a wideband scan

#### Window Functions

Finite impulse response (FIR) filters are built from a set of tap coefficients. The window function applied to those taps controls the tradeoff between stopband attenuation and transition band sharpness.

| Window | Stopband Attenuation | Transition Width | Use Case |
|--------|---------------------|-----------------|---------|
| **Rectangular** | 21 dB | Narrowest | Rarely used; high sidelobes |
| **Hamming** | 53 dB | Moderate | General purpose; good default |
| **Hann** | 44 dB | Moderate | Spectral analysis |
| **Blackman** | 74 dB | Wide | High attenuation needed |
| **Kaiser (β=8)** | 80 dB | Moderate | Flexible; tune β for tradeoff |
| **Blackman-Harris** | 92 dB | Widest | Maximum attenuation; wide transition |

In GNU Radio: the Low Pass Filter block accepts Window Type as a parameter. For most receive work, **Kaiser** or **Hamming** is appropriate.

#### Decimation and Interpolation

Decimation (reducing sample rate) and interpolation (increasing sample rate) are essential for managing computational load and matching interface requirements.

```python
# In GNU Radio: Rational Resampler block
# Decimation by 10: 2.4 MSa/s → 240 kSa/s
# Interpolation by 2, Decimation by 5: 2.4 MSa/s → 960 kSa/s

# In Python with SciPy:
from scipy.signal import decimate, resample_poly
import numpy as np

# Decimate by factor of 10 with anti-aliasing filter
decimated = decimate(iq_samples, q=10, ftype='fir', zero_phase=True)

# Rational resampling: multiply rate by (up/down)
resampled = resample_poly(iq_samples, up=1, down=10)
```

**Decimation rule:** Always apply a low-pass filter before decimation to avoid aliasing. GNU Radio's `rational_resampler` does this automatically. If decimating manually, apply an LPF with cutoff = `new_sample_rate / 2` first.

#### Automatic Gain Control (AGC)

AGC maintains a constant output signal level despite varying input amplitude. Essential for receivers that must handle signals of widely varying strength.

```python
# Simple AGC implementation concept
class SimpleAGC:
    def __init__(self, rate=1e-3, reference=1.0, max_gain=65536):
        self.gain = 1.0
        self.rate = rate
        self.reference = reference
        self.max_gain = max_gain
    
    def process(self, sample):
        output = sample * self.gain
        # Update gain: increase if output too low, decrease if too high
        error = self.reference - abs(output)
        self.gain += self.rate * error * abs(output)
        self.gain = min(max(self.gain, 0), self.max_gain)
        return output
```

In GNU Radio: `AGC` block for single-channel, `AGC2` for faster attack/slower decay (better for voice).

---

### Chapter 10: Modulation and Demodulation

#### Analog Modulations

| Mode | Demodulation | Typical Use |
|------|-------------|------------|
| **AM (DSB-LC)** | Envelope detector | Broadcast AM, aviation voice (VHF) |
| **DSB-SC** | Synchronous detection | Data links, SSB component |
| **SSB (USB/LSB)** | Product detector + BFO | Amateur HF voice, military |
| **WBFM** | FM discriminator | Broadcast FM |
| **NBFM** | FM discriminator | VHF/UHF voice communications |
| **CW (Morse)** | BFO + AM detect | Amateur radio Morse code |

#### Digital Modulations

| Mode | Type | Bits/Symbol | Typical Use |
|------|------|------------|------------|
| **OOK** | Amplitude | 1 | 433 MHz ISM devices, simple remotes |
| **ASK** | Amplitude | 1+ | RFID, simple data links |
| **FSK** | Frequency | 1 | APRS, POCSAG, AX.25 |
| **GFSK** | Frequency | 1 | Bluetooth, ZigBee |
| **BPSK** | Phase | 1 | GPS, satellite links |
| **QPSK** | Phase | 2 | Satellite, some LTE |
| **QAM-16** | Amp+Phase | 4 | Wi-Fi, LTE downlink |
| **QAM-64** | Amp+Phase | 6 | Wi-Fi (802.11ac+), cable TV |
| **OFDM** | Multi-carrier | Variable | Wi-Fi, LTE, DVB-T |

#### Building a BPSK Demodulator

BPSK uses two phases (0° and 180°) to encode binary data. A complete BPSK demodulator chain in GNU Radio:

```
[osmocom Source]
     │
     ▼
[Low Pass Filter]           ← Isolate the signal channel
     │
     ▼
[Costas Loop]               ← Carrier phase and frequency recovery
     │                         (tracks rotating phase; locks to carrier)
     ▼
[Symbol Sync]               ← Symbol timing recovery
     │                         (finds symbol boundaries)
     ▼
[Constellation Decoder]     ← Map complex symbols to bits (BPSK: 1 symbol = 1 bit)
     │
     ▼
[Differential Decoder]      ← Resolve 180° phase ambiguity
     │
     ▼
[Byte Output / Data]
```

**Costas Loop** is the key block: it tracks and removes the carrier frequency and phase offset, bringing the BPSK constellation to a fixed orientation (0° and 180°) regardless of Doppler, oscillator error, or initial phase.

---

### Chapter 11: Digital Signal Processing in Python

Working outside GNU Radio — Python with NumPy, SciPy, and PySDR enables flexible offline analysis of captured IQ files.

#### Reading and Processing IQ Files

```python
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import welch, butter, sosfilt
from scipy.fft import fft, fftfreq, fftshift

# RTL-SDR raw IQ file: interleaved uint8, range 0-255
def load_rtlsdr_iq(filename):
    raw = np.fromfile(filename, dtype=np.uint8)
    # Convert uint8 to float, center on 0
    samples = raw.astype(np.float32) - 127.5
    # Combine I and Q
    iq = samples[0::2] + 1j * samples[1::2]
    return iq / 127.5  # Normalize to ±1

# HackRF raw IQ: interleaved int8
def load_hackrf_iq(filename):
    raw = np.fromfile(filename, dtype=np.int8)
    iq = raw[0::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)
    return iq / 128.0

# GNU Radio IQ file: complex64 (numpy native)
def load_gnuradio_iq(filename):
    return np.fromfile(filename, dtype=np.complex64)
```

#### Spectrum Analysis

```python
def plot_spectrum(iq_samples, sample_rate, center_freq=0, title="Spectrum"):
    """Plot PSD of IQ data"""
    # FFT with frequency shift so DC is in center
    N = min(len(iq_samples), 8192)  # FFT size
    spectrum = fftshift(fft(iq_samples[:N] * np.hanning(N)))
    
    freqs = fftshift(fftfreq(N, 1/sample_rate)) + center_freq
    power_db = 20 * np.log10(np.abs(spectrum) / N + 1e-12)
    
    plt.figure(figsize=(12, 4))
    plt.plot(freqs / 1e6, power_db, linewidth=0.5)
    plt.xlabel('Frequency (MHz)')
    plt.ylabel('Power (dB)')
    plt.title(title)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.show()

def plot_waterfall(iq_samples, sample_rate, fft_size=512, title="Waterfall"):
    """Plot spectrogram (time-frequency waterfall)"""
    n_ffts = len(iq_samples) // fft_size
    waterfall = np.zeros((n_ffts, fft_size))
    
    for i in range(n_ffts):
        chunk = iq_samples[i*fft_size:(i+1)*fft_size]
        spectrum = fftshift(fft(chunk * np.hanning(fft_size)))
        waterfall[i] = 20 * np.log10(np.abs(spectrum) / fft_size + 1e-12)
    
    plt.figure(figsize=(12, 6))
    plt.imshow(waterfall, aspect='auto', cmap='plasma',
               extent=[0, sample_rate/1e6, n_ffts/sample_rate*fft_size, 0])
    plt.xlabel('Frequency offset (MHz)')
    plt.ylabel('Time (s)')
    plt.title(title)
    plt.colorbar(label='Power (dB)')
    plt.tight_layout()
    plt.show()
```

#### Manual FM Demodulation

```python
def demodulate_fm(iq_samples, sample_rate, audio_rate=48000):
    """Demodulate WBFM signal from complex baseband IQ"""
    from scipy.signal import decimate, firwin, lfilter
    
    # FM discriminator: d/dt of instantaneous phase
    # Efficient form: angle(conj(s[n-1]) * s[n])
    discriminated = np.angle(np.conj(iq_samples[:-1]) * iq_samples[1:])
    
    # De-emphasis filter (75 μs for North America)
    # H(s) = 1 / (1 + s·τ), τ = 75e-6
    tau = 75e-6
    dt = 1 / sample_rate
    alpha = dt / (tau + dt)
    deemph = np.zeros_like(discriminated)
    deemph[0] = discriminated[0]
    for i in range(1, len(discriminated)):
        deemph[i] = alpha * discriminated[i] + (1 - alpha) * deemph[i-1]
    
    # Decimate to audio rate
    decimation_factor = int(sample_rate / audio_rate)
    audio = decimate(deemph, decimation_factor, ftype='fir', zero_phase=True)
    
    # Normalize
    audio = audio / np.max(np.abs(audio))
    return audio.astype(np.float32)

# Save as WAV
import scipy.io.wavfile as wavfile
audio = demodulate_fm(iq_samples, sample_rate=2_400_000)
wavfile.write('output.wav', 48000, (audio * 32767).astype(np.int16))
```

---

## Part IV: Protocols and Applications

### Chapter 12: Trunked Radio and APRS

#### Trunked Radio Systems

Trunked radio systems dynamically assign radio channels from a pool rather than dedicating a channel per group. A **control channel** broadcasts assignments; radios tune to the assigned voice channel for each transmission.

**Common trunking systems:**

| System | Protocol | Frequencies | Notes |
|--------|---------|------------|-------|
| **Motorola Type II** | Proprietary | VHF/UHF | Most common public safety in US |
| **P25 Phase 1 (IMBE)** | APCO-25 | VHF/UHF/700/800 MHz | US public safety digital standard |
| **P25 Phase 2 (AMBE+2)** | APCO-25 | Same | Two-slot TDMA; more efficient |
| **DMR Tier III** | ETSI DMR | UHF/700 MHz | Commercial trunking; some public safety |
| **TETRA** | ETSI TETRA | 380–400 MHz (EU) | European public safety; encrypted |
| **NXDN** | Kenwood/Icom | UHF | Commercial; some public safety |

#### SDR-Trunk

The primary open-source tool for trunked radio decoding on SDR hardware.

```bash
# Install SDR-Trunk (Java application)
# Download from: https://github.com/DSheirer/sdr-trunk/releases
java -jar sdr-trunk.jar

# Alternatively:
sudo apt install default-jre
# Download .zip release, extract, run start script
```

**Configuration workflow:**
1. Add SDR device (RTL-SDR, HackRF, Airspy, etc.)
2. Import RadioReference.com database for local area (requires free account)
3. SDR-Trunk automatically maps control channels and follows traffic
4. Configure audio output per talkgroup

**RR Playlist import:** SDR-Trunk can import RadioReference CSV exports for automated channel setup. Create a free RadioReference account, navigate to your county, export the system data.

#### Scanning Workflow with SDR#

For non-trunked scanning:

```
Useful SDR# plugins:
  - DSD+ FastLane: Digital voice decoding (P25, DMR, D-STAR)
  - Scanner (built-in): Frequency scanning with squelch
  - Frequency Manager: Organize frequencies by category
  - IF Recorder: Record raw IQ for later analysis
```

```python
# Python scanning script using rtlsdr library
from rtlsdr import RtlSdr
import numpy as np
from scipy.signal import welch

sdr = RtlSdr()
sdr.sample_rate = 2.4e6
sdr.gain = 'auto'

scan_frequencies = np.arange(144e6, 148e6, 25e3)  # 2m amateur band in 25 kHz steps
power_threshold_db = -60  # Signal detection threshold

for freq in scan_frequencies:
    sdr.center_freq = freq
    samples = sdr.read_samples(256 * 1024)
    
    # Calculate power in channel
    freqs_psd, psd = welch(samples, sdr.sample_rate, nperseg=1024)
    peak_power = 10 * np.log10(np.max(psd))
    
    if peak_power > power_threshold_db:
        print(f"Signal detected at {freq/1e6:.3f} MHz: {peak_power:.1f} dB")

sdr.close()
```

---

#### APRS (Automatic Packet Reporting System)

APRS is a digital communications system for real-time position reporting, weather data, messaging, and telemetry. Operates primarily on **144.390 MHz** (North America), 144.800 MHz (Europe).

**Protocol stack:**
```
APRS application data
    └─→ AX.25 packet (amateur radio layer 2)
         └─→ AFSK 1200 baud (Bell 202: 1200 Hz = mark, 2200 Hz = space)
              └─→ NBFM audio on 144.390 MHz
```

#### Receiving APRS

```bash
# Method 1: Direwolf (software modem + APRS decoder)
sudo apt install direwolf

# Configure: /etc/direwolf.conf
# ADEVICE plughw:1,0    (audio device from RTL-SDR pipe)
# CHANNEL 0
# MYCALL N0CALL         (your callsign or N0CALL for receive-only)
# MODEM 1200

# Pipe RTL-SDR audio into Direwolf
rtl_fm -f 144.39M -M fm -s 200000 -r 48000 -g 50 - | \
  direwolf -c direwolf.conf -r 48000 -D 1 -

# Method 2: GNU Radio + gr-ax25
# Use NBFM receiver flowgraph → audio output → Direwolf STDIN

# Method 3: GQRX → virtual audio → Direwolf
# Set GQRX to NBFM on 144.390 MHz; route audio to virtual cable; connect to Direwolf
```

#### APRS Data Types

| Symbol | Data | Example |
|--------|------|---------|
| `/` + char | Position + timestamp | `/092345z4903.50N/07201.75W>` |
| `!` | Position without timestamp | `!4903.50N/07201.75W>` |
| `@` | Position + time + messaging | Mobile tracker |
| `>` | Status message | Software version, activity |
| `:` | Message | Point-to-point text |
| `_` | Weather data | Wind, temperature, humidity, rain |
| `T` | Telemetry | Analog/digital sensor data |

#### Plotting APRS Data

```python
# Parse Direwolf output and plot positions
import re
import folium  # pip install folium

def parse_aprs_position(packet_text):
    """Extract lat/lon from APRS position packet"""
    # Matches !DDmm.mmN/DDDmm.mmW format
    pattern = r'(\d{2})(\d{2}\.\d+)([NS])/(\d{3})(\d{2}\.\d+)([EW])'
    m = re.search(pattern, packet_text)
    if m:
        lat_deg, lat_min, lat_dir = int(m[1]), float(m[2]), m[3]
        lon_deg, lon_min, lon_dir = int(m[4]), float(m[5]), m[6]
        lat = lat_deg + lat_min/60
        lon = lon_deg + lon_min/60
        if lat_dir == 'S': lat = -lat
        if lon_dir == 'W': lon = -lon
        return lat, lon
    return None

# Create interactive map
m = folium.Map(location=[45.5, -122.6], zoom_start=10)
# Add markers for each decoded position
folium.Marker([lat, lon], popup=callsign).add_to(m)
m.save('aprs_map.html')
```

---

### Chapter 13: Wi-Fi, Bluetooth, and Short-Range RF

#### Wi-Fi (802.11) Monitoring

Wi-Fi operates on 2.4 GHz (channels 1–14, 20 MHz each) and 5 GHz (many channels). Modulation is OFDM with variable QAM order (BPSK through QAM-256).

**Passive monitoring with SDR:**

```bash
# Spectrum analysis of 2.4 GHz ISM band
# HackRF sweep across Wi-Fi channels
hackrf_sweep -f 2400:2500 -g 32 -l 16 -w 1000000 | \
  python3 -c "
import sys, csv
reader = csv.reader(sys.stdin)
for row in reader:
    # row: date, time, hz_low, hz_high, hz_bin_width, num_samples, *powers
    print(f'{float(row[2])/1e9:.3f}-{float(row[3])/1e9:.3f} GHz: {max(float(p) for p in row[6:])} dBm')
"

# Channel occupancy measurement
python3 << 'EOF'
import numpy as np
from rtlsdr import RtlSdr

WIFI_CHANNELS_2_4 = {
    1: 2412e6, 6: 2437e6, 11: 2462e6  # Non-overlapping channels
}

sdr = RtlSdr()
sdr.sample_rate = 2.4e6
sdr.gain = 40

for channel, freq in WIFI_CHANNELS_2_4.items():
    sdr.center_freq = freq
    samples = sdr.read_samples(512*1024)
    power = 10 * np.log10(np.mean(np.abs(samples)**2))
    print(f"Ch {channel:2d} ({freq/1e6:.0f} MHz): {power:.1f} dBm")

sdr.close()
EOF
```

**For deep 802.11 packet capture:** Use a dedicated Wi-Fi adapter in monitor mode (`iw dev wlan0 set type monitor`). SDR-based Wi-Fi packet decode is theoretically possible but challenging — OFDM requires tight synchronization that most SDR hardware doesn't easily provide.

#### Bluetooth Analysis

Bluetooth Classic (BT Classic) hops across 79 channels in the 2.402–2.480 GHz band at up to 1600 hops/second. BLE (Bluetooth Low Energy) uses 40 channels, 3 of which are advertising channels.

**Ubertooth One** is the purpose-built Bluetooth SDR tool:

```bash
# Install Ubertooth tools
sudo apt install ubertooth

# Sniff BLE advertising packets
ubertooth-btle -f -A 37  # Advertising channel 37

# Follow a BLE connection (requires clock recovery)
ubertooth-btle -f -c [access address]

# Capture Bluetooth Classic (hopping — requires clock + offset recovery)
ubertooth-rx -c [clock] -n [LAP]

# Specan: spectrum analyzer mode (shows 2.4 GHz occupancy)
ubertooth-specan
```

**With HackRF and GNU Radio:**

```python
# BLE advertising channel detection at 2.402 GHz (channel 37)
# BLE uses GFSK with 250 kHz deviation, 1 Mbit/s
# Channel 37: 2402 MHz, Channel 38: 2426 MHz, Channel 39: 2480 MHz
```

`gr-bluetooth` is the GNU Radio module for Bluetooth signal processing.

#### ISM Band (433 MHz, 868 MHz, 915 MHz) Analysis

The ISM bands contain a dense population of consumer devices: weather stations, garage door openers, tire pressure monitors, smart meters, wireless doorbells, keyfobs, and sensors.

**rtl_433** is the essential tool for decoding ISM band sensor data:

```bash
# Install
sudo apt install rtl-433
# or: pip install rtl-433

# Run continuously decoding all known protocols
rtl_433 -f 433.92M -s 250000

# Output to JSON for logging
rtl_433 -f 433.92M -F json -o /tmp/rtl433.json

# Output to MQTT for home automation integration
rtl_433 -f 433.92M -F "mqtt://localhost:1883,retain=1,devices=rtl433/[model]"

# List all supported protocols (~200+)
rtl_433 -R list

# Force specific protocol
rtl_433 -R 40 -f 433.92M  # Protocol 40 = LaCrosse weather station
```

---

### Chapter 14: Cellular Communications

> **⚠️ Legal note:** Intercepting cellular communications is illegal under the Electronic Communications Privacy Act and equivalent laws worldwide. Passive monitoring of unencrypted control channels for research purposes exists in a gray area — consult applicable law. Active attacks against cellular networks are illegal without explicit authorization.

#### 2G GSM (Legacy, Research Value)

GSM uses TDMA on 900 MHz (GSM-900) and 1800 MHz (GSM-1800). Partially unencrypted control channels allow passive monitoring.

```bash
# gr-gsm: GNU Radio-based GSM receiver
sudo apt install gr-gsm

# Live capture of GSM control channel (BCCH)
grgsm_livemon_headless -f 939.4M -g 40

# Decode captured GSM frames
grgsm_decode -c /tmp/gsm_capture.cfile -f 939.4M --cch

# Kalibrate-rtl: find local GSM base station frequencies
sudo apt install kalibrate-rtl
kal -s GSM900 -g 40    # Scan for GSM-900 towers
kal -c [channel] -g 40  # Lock to specific channel; measure frequency offset
```

#### LTE / 4G (Modern)

LTE uses OFDM, multiple frequency bands, and mandatory encryption. Passive control channel monitoring (cell broadcast, system information) is possible; user data is encrypted.

```bash
# srsRAN: open-source 4G/5G software radio suite
# Useful for lab environments with your own base station (srsENB)
sudo apt install srsran

# LTE cell scanner
sudo srsran_cell_search  # Scans for LTE cells; reports MCC, MNC, EARFCN

# Monitor LTE downlink (system information, broadcast)
sudo srsran_pdsch_ue -f [earfcn_freq]
```

#### ADS-B (Aircraft Transponders)

ADS-B is the most common SDR "first application" — aircraft broadcast their position, altitude, speed, and ID on 1090 MHz in the clear.

```bash
# dump1090: THE standard ADS-B decoder
sudo apt install dump1090-fa

# Run with web display
dump1090-fa --interactive --net --net-http-port 8080 --gain 50
# Open http://localhost:8080 for live map

# FlightAware integration (feed sharing)
sudo apt install piaware

# With RTL-SDR optimized settings
dump1090-fa --device-index 0 --gain 49.6 --ppm 0 \
  --net --net-ro-port 30002 --net-sbs-port 30003 \
  --lat [your_lat] --lon [your_lon] --interactive

# Python ADS-B parser
pip install pyModeS
import pyModeS as pms
msg = "8D4B17E5F8210002004BB8B1F1"
print(pms.adsb.callsign(msg))   # Aircraft callsign
print(pms.adsb.altitude(msg))   # Altitude in feet
```

---

### Chapter 15: GPS and Satellite Signals

#### GNSS Reception with SDR

Receiving and decoding GPS/GNSS signals is technically demanding but achievable:

- GPS L1: 1575.42 MHz, BPSK with 1.023 MHz C/A code chip rate
- Requires ~2 MHz bandwidth minimum; 4 MHz recommended
- Signal is 20 dB below noise floor — requires code correlation
- Active GPS patch antenna with bias tee power strongly recommended

```bash
# GNSS-SDR: open-source GNSS software receiver
sudo apt install gnss-sdr

# Configure for GPS L1 with RTL-SDR (gnss-sdr config file)
cat > gps_l1.conf << 'EOF'
[GNSS-SDR]
GNSS-SDR.internal_fs_sps=2000000

[SignalSource]
implementation=Osmosdr_Signal_Source
item_type=gr_complex
sampling_frequency=2000000
freq=1575420000
gain=40
AGC_enabled=true

[Channels_1C]
count=8

[Channel0]
signal=1C
EOF

gnss-sdr --config_file=gps_l1.conf
```

#### Weather Satellites: NOAA APT

NOAA weather satellites (15, 18, 19) transmit analog APT images on 137.500 MHz, 137.100 MHz, and 137.9125 MHz. The easiest satellite image project:

```bash
# Receive and decode NOAA APT
# Step 1: Get pass prediction
sudo apt install predict
predict -p "NOAA 19"  # Shows next pass time, max elevation

# Step 2: Record IQ during pass
rtl_fm -f 137.9125M -M fm -s 60000 -r 11025 -E deemp noaa19.wav &
# Wait for pass and stop recording

# Step 3: Decode
sudo apt install noaa-apt  # or WXtoImg (legacy)
noaa-apt noaa19.wav -o image.png

# Automated full pipeline
# gr-satellites handles pass scheduling + decode
```

#### Meteor-M LRPT (Higher Quality)

Russian Meteor-M N2-3 satellite transmits digital LRPT images on 137.100 MHz — higher quality than NOAA APT.

```bash
# Receive as FM, decode with LRPTofflineDecoder or SatDump
# SatDump handles full pipeline from IQ to georeferenced image
satdump live meteor_m2-x_lrpt baseband \
  --source rtlsdr --samplerate 1e6 --frequency 137.1e6 \
  --gain 49 --biast 0
```

---

## Part V: Advanced Techniques

### Chapter 16: SIGINT and Signal Reversal

#### Signal Identification Workflow

Identifying an unknown signal is a systematic process combining visual analysis, measurement, and database lookup.

```
Step 1: Visual identification (spectrum + waterfall)
  └─> Note: center frequency, bandwidth, modulation appearance,
             on/off timing, duty cycle, any visible structure

Step 2: Measurement
  └─> Bandwidth at -3 dB, -20 dB, -60 dB
  └─> Symbol rate (if digital)
  └─> Burst duration and repetition rate (if pulsed)
  └─> Polarization (H, V, or circular)

Step 3: Database lookup
  └─> Sigidwiki.com — community signal identification wiki with spectrograms
  └─> ACRN/RadioReference — frequency allocations
  └─> Priyom.org — numbers stations
  └─> EiBi/HFCC — shortwave broadcast schedules

Step 4: Demodulation probing
  └─> Try obvious demodulations: FM, AM, USB, LSB
  └─> Listen to audio output for patterns (tones, voice, digital sounds)
  └─> Look at constellation plot (QPSK? QAM? BPSK?)

Step 5: Symbol rate estimation
  └─> Autocorrelation of |IQ|² reveals symbol rate
  └─> Eye diagram analysis
  └─> Spectral analysis of demodulated signal
```

#### Symbol Rate Detection

```python
def estimate_symbol_rate(iq_samples, sample_rate):
    """
    Estimate symbol rate by finding peaks in the power spectral density
    of the squared magnitude (exploits AM-to-PM coupling in most modulations).
    """
    # Non-linear transform to expose symbol rate
    power = np.abs(iq_samples) ** 2
    
    # FFT of power signal
    N = len(power)
    spectrum = np.abs(np.fft.fft(power - np.mean(power)))
    freqs = np.fft.fftfreq(N, 1/sample_rate)
    
    # Find peaks (positive frequencies only)
    pos_mask = freqs > 0
    pos_freqs = freqs[pos_mask]
    pos_spectrum = spectrum[pos_mask]
    
    # Peak frequency = symbol rate
    from scipy.signal import find_peaks
    peaks, props = find_peaks(pos_spectrum, height=np.max(pos_spectrum)*0.3)
    
    if len(peaks) > 0:
        symbol_rate = pos_freqs[peaks[0]]
        print(f"Estimated symbol rate: {symbol_rate:.1f} Hz ({symbol_rate/1000:.3f} kBaud)")
    
    return symbol_rate
```

#### Protocol Reverse Engineering

Once a signal is identified and demodulated to bits, reverse engineering the protocol structure:

```python
def analyze_bit_stream(bits, name="unknown"):
    """
    Basic protocol analysis of decoded bit stream.
    """
    # Convert to bytes
    # Ensure length is multiple of 8
    bits = bits[:len(bits)//8*8]
    byte_array = np.packbits(bits)
    
    print(f"\n=== {name} Analysis ===")
    print(f"Bit count: {len(bits)}")
    print(f"Byte count: {len(byte_array)}")
    
    # Check for preamble (common patterns)
    hex_str = byte_array.tobytes().hex()
    print(f"First 32 bytes (hex): {hex_str[:64]}")
    
    # Look for sync words
    common_syncs = ['aaaa', 'ffff', '5555', 'd391', 'e6d0']
    for sync in common_syncs:
        if sync in hex_str:
            pos = hex_str.index(sync)
            print(f"Possible sync word '{sync}' found at byte position {pos//2}")
    
    # Entropy analysis (detect encrypted vs. plaintext regions)
    from scipy.stats import entropy
    byte_freqs = np.bincount(byte_array, minlength=256) / len(byte_array)
    byte_entropy = entropy(byte_freqs + 1e-12, base=2)
    print(f"Byte entropy: {byte_entropy:.2f} bits (8.0 = encrypted/random)")
    
    # Find repeated patterns
    for pattern_len in [2, 4, 8]:
        patterns = {}
        for i in range(0, len(byte_array) - pattern_len, pattern_len):
            pat = byte_array[i:i+pattern_len].tobytes().hex()
            patterns[pat] = patterns.get(pat, 0) + 1
        common = sorted(patterns.items(), key=lambda x: -x[1])[:3]
        print(f"\nTop {pattern_len}-byte patterns: {common}")
```

#### Replay Attack Analysis

For ISM band devices (garage doors, keyfobs, weather sensors):

```bash
# Capture a transmission
hackrf_transfer -r keyfob_capture.iq -f 433920000 -s 2000000 -g 40 -l 32 -n 2000000

# Analyze with inspectrum (visual tool for binary analysis)
sudo apt install inspectrum
inspectrum keyfob_capture.iq  # Opens GUI for visual analysis

# Replay capture (AUTHORIZED TESTING ONLY)
hackrf_transfer -t keyfob_capture.iq -f 433920000 -s 2000000 -x 47 -a 1

# More sophisticated: use Universal Radio Hacker (URH)
pip install urh
urh  # Full GUI for signal capture, demodulation, and protocol analysis
```

**Universal Radio Hacker (URH)** is the premier tool for ISM band protocol analysis — combines signal capture, bit decoding, and protocol structure analysis in a single application.

---

### Chapter 17: Wideband Monitoring and High-Speed Converters

#### Wideband Spectrum Monitoring

Simultaneous monitoring across wide frequency ranges requires either multiple SDRs or hardware capable of wide instantaneous bandwidth.

**Multi-SDR approach:**

```python
# Synchronize multiple RTL-SDRs for wideband coverage
# Each SDR covers ~2.4 MHz; multiple cover wider bands
import rtlsdr
import threading
import numpy as np

class MultiSDRMonitor:
    def __init__(self, center_freqs, sample_rate=2.4e6):
        self.sdrs = []
        self.threads = []
        self.data = {f: None for f in center_freqs}
        
        for i, freq in enumerate(center_freqs):
            sdr = rtlsdr.RtlSdr(i)  # Device index
            sdr.center_freq = freq
            sdr.sample_rate = sample_rate
            sdr.gain = 40
            self.sdrs.append((sdr, freq))
    
    def capture_segment(self, sdr, freq, n_samples=1024*1024):
        samples = sdr.read_samples(n_samples)
        self.data[freq] = samples
    
    def capture_all(self):
        threads = []
        for sdr, freq in self.sdrs:
            t = threading.Thread(target=self.capture_segment, args=(sdr, freq))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return self.data
```

**HackRF Sweep for fast spectrum coverage:**

```bash
# Sweep 0–6 GHz in ~1 second
hackrf_sweep -f 0:6000 -g 40 -l 24 -w 1000000 -1 | \
  python3 plot_sweep.py

# Real-time sweep with SDR Angel
# Or: GQRX's SDR Play/HackRF mode at 20 MHz bandwidth
```

#### High-Speed ADC Platforms

For professional wideband coverage requiring simultaneous capture across many MHz or GHz:

| Platform | Bandwidth | ADC | Interface | Notes |
|----------|----------|-----|-----------|-------|
| **USRP X310** | 160 MHz (dual) | 14-bit | 10 GbE | Research standard |
| **Ettus N321** | 250 MHz | 14-bit | 10 GbE | Up to 6 GHz |
| **Epiq Solutions Sidekiq** | 60 MHz | 12-bit | PCIe/USB | Compact; commercial |
| **Difi (Digital IF)** | Varies | Varies | 10 GbE | Standard for EW |
| **Analog Devices ADRV9009** | 200 MHz | 14-bit | JESD204B | FPGA-based system |
| **Xilinx RFSoC** | DC–6 GHz | 12-bit | Built-in FPGA | 8 ADC channels; state of art |

**Xilinx RFSoC** (e.g., ZCU111, RFSoC4x2) represents the current state of the art for wideband SDR research: an FPGA with built-in multi-GSa/s ADCs and DACs, enabling 100+ MHz instantaneous bandwidth with FPGA processing close to the ADC.

```python
# RFSoC deployment with PYNQ framework
# pip install pynq
import pynq
import numpy as np

# Access RF data converter
from pynq.lib import dma
overlay = pynq.Overlay("rfsoc_design.bit")  # Custom bitstream
adc = overlay.radio.receiver.channel[0]

# Capture IQ samples from ADC
adc.transfer.start()
samples = np.array(adc.dma.recvchannel.buf, dtype=np.complex64)
adc.transfer.stop()
```

#### Electronic Warfare (EW) Applications

SDR at scale forms the foundation of modern EW systems:

| EW Function | SDR Capability | Hardware Required |
|-------------|---------------|------------------|
| **ESM (Electronic Support Measures)** | Detect, identify, locate emitters | Wideband SDR array |
| **ECM (Electronic Countermeasures)** | Jamming, spoofing | High-power TX SDR |
| **ELINT** | Collect emitter parameters for intelligence | Wideband SDR + recording |
| **SIGINT** | Intercept communications | Multi-channel SDR |
| **Direction Finding** | Locate signal sources | Phase-coherent SDR array |

**TDOA (Time Difference of Arrival) direction finding:**

```python
def tdoa_localization(positions, timestamps, c=3e8):
    """
    Locate an emitter using TDOA from multiple receiver positions.
    positions: array of (x,y) receiver positions
    timestamps: array of signal arrival times at each receiver
    c: propagation speed (speed of light)
    """
    from scipy.optimize import minimize
    
    # Convert timestamps to time differences relative to first receiver
    tdoa = timestamps - timestamps[0]
    
    def residuals(source_pos):
        x, y = source_pos
        distances = [np.sqrt((x-px)**2 + (y-py)**2) 
                    for px, py in positions]
        predicted_tdoa = [(d - distances[0])/c for d in distances]
        return sum((p-m)**2 for p, m in zip(predicted_tdoa[1:], tdoa[1:]))
    
    # Initial guess: center of receiver array
    x0 = np.mean([p[0] for p in positions])
    y0 = np.mean([p[1] for p in positions])
    
    result = minimize(residuals, [x0, y0], method='Nelder-Mead')
    return result.x
```

---

### Chapter 18: FPGA and High-Speed DSP Acceleration

#### Why FPGAs for SDR?

General-purpose CPUs process data sequentially. FPGAs implement parallel logic — hundreds or thousands of operations in the same clock cycle. For real-time SDR at high sample rates, FPGA acceleration is often essential.

| DSP Task | CPU Limitation | FPGA Advantage |
|----------|---------------|---------------|
| FFT at 100 MSa/s | High CPU load; latency | Pipelined 1024-pt FFT in single clock cycle |
| FIR filter (1000 taps) | Sequential; too slow | 1000 multiply-accumulates in parallel |
| Matched filter | Cross-correlation; compute-intensive | Parallel correlator banks |
| Protocol decode | Real-time constraint hard to meet | Dedicated decode logic |
| Multi-channel processing | Single CPU overwhelmed | Per-channel parallel logic |

#### FPGA SDR Platforms

| Platform | FPGA | ADC | Software | Notes |
|----------|------|-----|---------|-------|
| **Red Pitaya** | Xilinx ZYNQ 7010 | 125 MSa/s / 14-bit | Open-source | $350; web-based DSP |
| **LimeSDR** | Altera Cyclone IV | 12-bit | Custom | Open-source hardware |
| **Pluto SDR** | Xilinx Zynq 7010 | 61.44 MSa/s / 12-bit | libiio + custom | Hackable; good value |
| **USRP X310** | Kintex-7 | 14-bit | UHD + RFNoC | Professional |
| **RFSoC ZCU111** | Zynq UltraScale+ | 4 GSa/s / 12-bit | PYNQ + custom | State of art |

#### GNU Radio with FPGA Acceleration (RFNoC)

Ettus Research's **RFNoC (RF Network on Chip)** framework allows custom FPGA blocks to appear as GNU Radio blocks:

```
GNU Radio flowgraph:
  [osmocom Source] → [RFNoC FFT Block*] → [RFNoC Filter Block*] → [Python Sink]
                                          ↑
                          * Running in FPGA hardware on USRP X310
```

```bash
# Check for RFNoC blocks
uhd_rfnoc_graph --list-blocks

# Typical RFNoC blocks available
# DDC (Digital Down Converter) — frequency shifting + decimation
# DUC (Digital Up Converter) — interpolation + frequency shifting  
# FFT — fast Fourier transform
# FIR Filter — programmable FIR
# Replay — circular buffer for waveform replay
```

#### HLS (High-Level Synthesis) for Custom DSP Blocks

Write C/C++ code; synthesize to FPGA logic:

```c
// Xilinx HLS: FIR filter for SDR application
#include "ap_fixed.h"
#include "hls_stream.h"

typedef ap_fixed<16,2> sample_t;    // 16-bit fixed point, 2 integer bits
typedef ap_fixed<32,4> acc_t;       // Accumulator

void fir_filter(
    hls::stream<sample_t> &in,
    hls::stream<sample_t> &out,
    const sample_t coeffs[64],      // 64-tap filter
    int N_taps
) {
    #pragma HLS PIPELINE II=1       // Process one sample per clock cycle
    #pragma HLS INTERFACE axis port=in
    #pragma HLS INTERFACE axis port=out
    
    static sample_t shift_reg[64];
    #pragma HLS ARRAY_PARTITION variable=shift_reg complete
    
    sample_t input = in.read();
    
    // Shift register
    for (int i = N_taps-1; i > 0; i--) {
        shift_reg[i] = shift_reg[i-1];
    }
    shift_reg[0] = input;
    
    // Multiply-accumulate
    acc_t acc = 0;
    for (int i = 0; i < N_taps; i++) {
        acc += coeffs[i] * shift_reg[i];
    }
    
    out.write((sample_t)acc);
}
```

---

### Chapter 19: Cognitive Radio and Adaptive Waveforms

#### What is Cognitive Radio?

Cognitive Radio (CR) is an SDR that **senses its RF environment** and **autonomously adapts** its operating parameters to optimize performance while avoiding interference.

The cognitive cycle:
```
┌─────────────────────────────────────────────────────┐
│                 COGNITIVE CYCLE                      │
│                                                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────────┐  │
│  │   SENSE   │───▶│ ANALYZE  │───▶│    DECIDE    │  │
│  │ RF environ│    │ spectrum │    │ adapt params │  │
│  │           │◀───│ activity │◀───│              │  │
│  └──────────┘    └──────────┘    └──────────────┘  │
│                                          │           │
│                                          ▼           │
│                                   ┌──────────┐      │
│                                   │   ACT    │      │
│                                   │ change   │      │
│                                   │ freq/mod │      │
│                                   │ power    │      │
│                                   └──────────┘      │
└─────────────────────────────────────────────────────┘
```

Adaptable parameters: frequency, bandwidth, modulation, power level, spreading code, antenna beam, protocol.

#### Spectrum Sensing

The core cognitive radio capability — detecting whether a frequency band is occupied:

```python
import numpy as np
from scipy.signal import welch
from rtlsdr import RtlSdr

class SpectrumSensor:
    def __init__(self, device_index=0, sample_rate=2.4e6):
        self.sdr = RtlSdr(device_index)
        self.sdr.sample_rate = sample_rate
        self.sdr.gain = 40
        self.sample_rate = sample_rate
    
    def energy_detection(self, freq, n_samples=256*1024, 
                          threshold_db=-60):
        """Simple energy detection — occupied if power > threshold"""
        self.sdr.center_freq = freq
        samples = self.sdr.read_samples(n_samples)
        
        power_db = 10 * np.log10(np.mean(np.abs(samples)**2))
        occupied = power_db > threshold_db
        return occupied, power_db
    
    def cyclostationary_detection(self, freq, n_samples=512*1024):
        """
        Cyclostationary feature detection — more reliable than energy
        detection; exploits periodicity inherent in modulated signals.
        """
        self.sdr.center_freq = freq
        samples = self.sdr.read_samples(n_samples)
        
        # Spectral correlation function
        N = len(samples)
        alpha_test = np.arange(-5, 5) / N * self.sample_rate
        
        features = {}
        for alpha in alpha_test:
            # Cyclic autocorrelation at cyclic frequency alpha
            n = np.arange(N)
            shifted = samples * np.exp(-2j * np.pi * alpha * n / self.sample_rate)
            correlation = np.abs(np.correlate(samples, shifted[:N//2]))
            features[alpha] = np.max(correlation)
        
        # Strong feature at non-zero alpha indicates modulated signal
        max_feature = max(features.values())
        return max_feature, features
    
    def scan_band(self, freq_start, freq_end, freq_step, threshold_db=-60):
        """Scan a frequency band and report occupied channels"""
        occupied_channels = []
        
        for freq in np.arange(freq_start, freq_end, freq_step):
            occupied, power = self.energy_detection(freq, threshold_db=threshold_db)
            if occupied:
                occupied_channels.append((freq, power))
                print(f"Occupied: {freq/1e6:.3f} MHz ({power:.1f} dBm)")
        
        return occupied_channels
    
    def close(self):
        self.sdr.close()
```

#### Dynamic Spectrum Access (DSA)

Cognitive radio enables secondary users to opportunistically use spectrum when primary users are absent:

```python
class DynamicSpectrumAccessRadio:
    def __init__(self, candidate_frequencies, primary_user_threshold_db=-70):
        self.candidates = candidate_frequencies
        self.threshold = primary_user_threshold_db
        self.sensor = SpectrumSensor()
        self.current_freq = None
        self.channel_history = {f: [] for f in candidate_frequencies}
    
    def find_available_channel(self):
        """Return first unoccupied channel from candidate list"""
        for freq in self.candidates:
            occupied, power = self.sensor.energy_detection(freq, 
                threshold_db=self.threshold)
            self.channel_history[freq].append(power)
            
            if not occupied:
                return freq, power
        
        return None, None  # No channel available
    
    def adaptive_frequency_hop(self, data_to_send):
        """
        Continuously monitor current channel; hop if primary user appears.
        """
        while True:
            # Check current channel
            if self.current_freq:
                occupied, power = self.sensor.energy_detection(
                    self.current_freq, threshold_db=self.threshold)
                
                if occupied:
                    print(f"Primary user detected on {self.current_freq/1e6:.3f} MHz, "
                          f"power={power:.1f} dBm — vacating")
                    self.current_freq = None
            
            # Find new channel if needed
            if self.current_freq is None:
                new_freq, power = self.find_available_channel()
                if new_freq:
                    self.current_freq = new_freq
                    print(f"Hopped to {new_freq/1e6:.3f} MHz")
                    # Transmit data on new_freq
                    self.transmit(data_to_send, new_freq)
    
    def transmit(self, data, frequency):
        """Placeholder for actual transmission"""
        pass  # Implement with GNU Radio/HackRF for authorized operation
```

#### Adaptive Modulation and Coding (AMC)

Select modulation order and coding rate based on measured channel quality:

```python
def select_modulation(snr_db):
    """
    Select modulation scheme based on measured SNR.
    Returns (modulation, code_rate, bits_per_symbol, threshold).
    """
    AMC_TABLE = [
        # (min_snr_db, modulation, code_rate, spectral_efficiency)
        (25,  'QAM-256', '5/6', 6.67),
        (20,  'QAM-64',  '3/4', 4.50),
        (15,  'QAM-16',  '1/2', 2.00),
        (10,  'QPSK',    '3/4', 1.50),
        (5,   'QPSK',    '1/2', 1.00),
        (-5,  'BPSK',    '1/2', 0.50),
        (-99, 'BPSK',    '1/3', 0.33),  # Minimum viable
    ]
    
    for min_snr, modulation, code_rate, efficiency in AMC_TABLE:
        if snr_db >= min_snr:
            return modulation, code_rate, efficiency
    
    return 'BPSK', '1/3', 0.33

def measure_snr(received_samples, noise_floor_db):
    """Estimate SNR from received IQ samples"""
    signal_power_db = 10 * np.log10(np.mean(np.abs(received_samples)**2))
    return signal_power_db - noise_floor_db
```

---

## Appendix A: Frequency Reference

### Frequency Allocations by Band

| Frequency | Band | Common Uses |
|-----------|------|------------|
| 530–1700 kHz | AM broadcast (MF) | Commercial AM radio |
| 1.8–2.0 MHz | 160m amateur | Amateur HF voice/CW |
| 3.5–4.0 MHz | 80m amateur | Amateur HF; regional comms |
| 7.0–7.3 MHz | 40m amateur | Amateur HF; international |
| 14.0–14.35 MHz | 20m amateur | Most active amateur HF band |
| 26–28 MHz | CB / 10m | CB radio; amateur 10m |
| 29.7–50 MHz | VHF low | Land mobile; some broadcast |
| 88–108 MHz | FM broadcast | Commercial FM radio |
| 108–137 MHz | VHF air | Aviation navigation (VOR/ILS) |
| 118–136 MHz | VHF air voice | Aviation voice (AM) |
| 136–138 MHz | VHF Met | NOAA/Meteor weather satellites |
| 144–148 MHz | 2m amateur | Most active VHF amateur band; APRS 144.390 |
| 156–174 MHz | VHF marine/land | Marine VHF (Ch. 16: 156.800); public safety |
| 222–225 MHz | 1.25m amateur | Less common amateur VHF |
| 433.050–434.790 MHz | ISM (EU/ROW) | Consumer devices; FSK sensors |
| 420–450 MHz | 70cm amateur + UHF | Amateur UHF; GMRS; FRS |
| 450–512 MHz | UHF business | LMR public safety and commercial |
| 902–928 MHz | ISM (US) | US consumer devices; LoRa |
| 960–1215 MHz | UHF aeronautical | DME; TACAN |
| 1090 MHz | ADS-B | Aircraft transponders |
| 1176.45 MHz | GPS L5 | Modern GPS |
| 1227.6 MHz | GPS L2 | Military/precision GPS |
| 1525–1559 MHz | L-band sat | Inmarsat; mobile satellite |
| 1575.42 MHz | GPS L1 | GPS civilian |
| 1.7–1.9 GHz | DCS/PCS cellular | LTE Bands 2/4 |
| 2.4–2.4835 GHz | ISM | Wi-Fi 2.4 GHz; Bluetooth; ZigBee |
| 5.15–5.85 GHz | U-NII / ISM | Wi-Fi 5 GHz |

---

## Appendix B: Recommended Software Stack

### SDR Receiver Applications

| Software | Platform | Best For |
|----------|---------|---------|
| **SDR#** (SDRSharp) | Windows | General-purpose; excellent plugin ecosystem |
| **GQRX** | Linux/macOS | GNU Radio-based; clean UI; good for monitoring |
| **CubicSDR** | Cross-platform | Simple; good FM/voice monitoring |
| **SDR Console** | Windows | Advanced features; satellite tracking |
| **Airspy SDR#** | Windows | Optimized for Airspy hardware |
| **OpenWebRX** | Web (Linux) | Browser-based; multi-user; remote access |

### Specialized Decoders

| Software | Purpose |
|----------|---------|
| **dump1090-fa** | ADS-B aircraft transponders |
| **rtl_433** | ISM band sensors and devices |
| **direwolf** | APRS / AX.25 packet radio |
| **SDR-Trunk** | Trunked radio systems |
| **DSD+** | Digital voice (P25, DMR, D-STAR) |
| **WSJT-X** | Weak signal digital modes (FT8, WSPR, JT65) |
| **Fldigi** | 100+ analog and digital modes |
| **gr-satellites** | Amateur/CubeSat satellite telemetry |
| **SatDump** | Weather satellite imagery |
| **gnss-sdr** | GPS/GNSS signal processing |
| **kalibrate-rtl** | GSM frequency calibration |

### Signal Analysis

| Software | Purpose |
|----------|---------|
| **GNU Radio + GRC** | DSP flowgraph development |
| **inspectrum** | Visual binary signal analysis |
| **Universal Radio Hacker (URH)** | ISM protocol reversing |
| **Baudline** | High-resolution spectrum analysis |
| **SigDigger** | Signal analysis and demodulation |
| **PySDR** (textbook + library) | SDR learning with Python |

### Installation Script (Ubuntu/Debian)

```bash
#!/bin/bash
# SDR software stack installation

set -e

echo "[*] Installing SDR software stack..."

# RTL-SDR support
sudo apt install -y rtl-sdr librtlsdr-dev

# GNU Radio
sudo apt install -y gnuradio gnuradio-dev gr-osmosdr

# Decoders
sudo apt install -y dump1090-fa direwolf rtl-433

# gr-satellites
pip3 install gnuradio-satellites

# HackRF
sudo apt install -y hackrf libhackrf-dev

# Airspy
sudo apt install -y airspy libairspy-dev

# SatDump
sudo apt install -y libairspy-dev libsdrplay-dev
git clone https://github.com/altillimity/SatDump.git
cd SatDump && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j4
sudo make install

# Universal Radio Hacker
pip3 install urh

# PySDR library
pip3 install pyrtlsdr scipy matplotlib numpy

# Gqrx
sudo apt install -y gqrx-sdr

# SDR-Trunk (Java)
sudo apt install -y default-jre
echo "[*] Download SDR-Trunk from: https://github.com/DSheirer/sdr-trunk/releases"

# Add user to plugdev group for USB access
sudo usermod -aG plugdev $USER

echo "[*] Installation complete. Log out and back in for USB permissions to take effect."
```

---

## Further Reading

**Books and Online Courses:**
- *PySDR: A Guide to SDR and DSP using Python* — pysdr.org (free online; highly recommended)
- *Software Defined Radio for Engineers* — Analog Devices (free PDF)
- *Understanding Digital Signal Processing* — Lyons (classic DSP textbook)
- *Hack the RF Spectrum* — DEF CON RF Village talks (YouTube)
- *The RTL-SDR Blog* — rtl-sdr.com (extensive tutorials and project guides)

**Communities:**
- /r/RTLSDR and /r/amateursatellites (Reddit)
- RadioReference.com (frequency database + forums)
- Sigidwiki.com (signal identification wiki)
- Sdr-radio.com (SDR Console + community)
- groups.io/g/HRDRX (HRD/digital modes)
- Discord: SDR++ server; GNU Radio server

**Hardware Sources:**
- rtl-sdr.com/store — RTL-SDR Blog hardware
- nooelec.com — Nooelec hardware and bundles
- greatscottgadgets.com — HackRF One (original)
- airspy.com — Airspy receivers
- analog.com/pluto — Pluto SDR

---

*Document maintained as part of the ULTIMATE-CYBERSECURITY-MASTER-GUIDE. For corrections or contributions, submit a PR to the repository. Amateur radio callsign references and RF transmission examples assume appropriate licensing — obtain your amateur radio license (Technician class and above) for legal transmit privileges.*
