# rtl_433 Passive IoT Telemetry and Detection Lab

_Last reviewed: 2026-11-02 (upstream reference review; no RF reception performed)_

> [!CAUTION]
> **Receive-only and authorized environment.** Check local laws, privacy
> expectations and organizational permission before capturing RF data. Do not
> intercept protected communications, rebroadcast, replay, jam or impersonate
> devices. Do not publish raw device identifiers, precise locations or logs
> tying traffic to individuals.

**Prerequisites:** [SDR index](README.md) · [Sub-GHz overview](subghz.md) ·
[Target Frequencies & Protocols](target_frequencies_protocols.md) ·
[SIEM integrations](../IncidentResponse/SIEM/README.md).

## Project role and hardware fit

[rtl_433](https://github.com/merbanan/rtl_433) is a receiver/decoder
for various unlicensed-band device signals; its name is historical and it
supports multiple regions/bands and SDR backends. Use a compatible,
receive-only RTL-SDR or supported SDR backend, with the antenna/band matched
to the environment. Always verify the installed build's options and the
country's permitted frequencies.

It can decode some wireless sensors and telemetry but cannot decode every
protocol or encrypted transmission. Observing RF telemetry is **not**
equivalent to authenticating the sender or confirming malicious activity.

## Controlled lab procedure

1. Inventory owned lab sensors and their make/model, channel/frequency and
   expected update intervals. Use known non-sensitive synthetic fixtures first.
2. In a separate research machine, install a pinned and verified release
   from [upstream](https://github.com/merbanan/rtl_433); document tuner,
   SDR backend, sample rate and firmware.
3. Test receiver health with known, permitted sensor transmissions. Avoid
   claiming an absent sensor is offline if it might be out of range,
   transmitting infrequently or using unsupported modulation.
4. Restrict capture to the appropriate band and time window. Retain only
   necessary metadata; strip addresses or identifiable sensor IDs in
   customer reports.
5. Where supported, emit local JSON events into a segregated lab collector
   with timestamp, device class, protocol/decoder ID, received measurement
   and confidence; validate JSON/schema before SIEM ingestion.
6. Create synthetic alerts for impossible temperature jumps, repeated
   unexpected IDs or unusual frequency of messages. Include benign
   environment tests and assess decoder error rates.
7. Compare with [Kismet](../Wardriving/kismet.md),
   [Snort](../IncidentResponse/IDS%26IPS/snort.md) or Wazuh where relevant,
   but do not assume shared 802.11 or Ethernet visibility. These sources
   observe different protocols and can produce independent false positives.

## Test data shape

A *normalized illustration*, not guaranteed literal rtl_433 output:

~~~json
{
  "observed_at_utc": "2026-11-02T12:00:00Z",
  "sensor_alias": "lab-weather-01",
  "radio_band": "region-appropriate",
  "protocol": "verified-decoder-name",
  "measurement": {"temperature_c": 21.0},
  "provenance": {"decoder_version": "record-installed-version"},
  "confidence": "lab-verified"
}
~~~

The real decoder output varies by hardware/protocol/version. Use the
[rtl_433 protocol and output documentation](https://github.com/merbanan/rtl_433)
before building parser contracts.

## Sources

- [rtl_433 source and docs](https://github.com/merbanan/rtl_433) (GPL-2.0).
- [SDR target list](target_frequencies_protocols.md) ·
  [NanoVNA antenna validation](nanovna/README.md) ·
  [Wazuh integration](../IncidentResponse/SIEM/README.md).

**Status:** guide only. No RF data collected, service enabled, decoder
installed, radio transmissions or client monitoring performed.

---

[SDR index](README.md) · [Main guide](../README.md) ·
[Legal notice](../LEGAL.md)
