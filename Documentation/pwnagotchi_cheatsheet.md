# Pwnagotchi Fork-Aware Setup & Capture Reference

> **Source review: November 11, 2026.** This page compares project documentation;
> it does not record a firmware build, flash, radio test or hardware test. Check
> the release-specific documentation before installation because the original
> project and its forks differ.

## Identify The Project & Hardware First

“Pwnagotchi” refers to multiple software lineages. Their supported boards,
images, AI behavior, configuration and capture paths are not interchangeable.

| Project lineage | What its upstream currently documents | Use |
|---|---|---|
| [Original evilsocket project](https://github.com/evilsocket/pwnagotchi) and [project documentation](https://pwnagotchi.ai/) | Raspberry Pi Zero W is the baseline; the installation guide describes Pi 3/4 and other Linux hosts as possible with configuration changes. The legacy docs describe MANU, AUTO and optional AI modes. | Historical reference for that lineage and its releases; do not apply its assumptions to forks. |
| [jayofelony fork](https://github.com/jayofelony/pwnagotchi) and [maintained wiki](https://github.com/jayofelony/pwnagotchi/wiki) | The README lists the Zero W as a legacy 32-bit target and lists Zero 2 W, Pi 3, Pi 4 and Pi 5 for 64-bit builds. The reviewed `noai` default branch removes the legacy AI component. | Follow the fork wiki and exact release asset for the selected board. |
| Other forks or images | Support and behavior depend on their own source, release and image. | Verify that project's own target list and instructions. |

Do not call a board “supported” just because it shares a Raspberry Pi
processor family. Select the exact model, image architecture, fork and release
before flashing. The repository's [device-first firmware references](../firmware-hardware-compatibility.md)
provide additional selection links.

## Modes & Radio Behavior

The original project's [usage guide](https://pwnagotchi.ai/usage/) documents
MANU, AUTO and AI behavior for that lineage: MANU does not capture handshakes;
AUTO uses configured behavior; AI is available only when enabled and supported
by that image. The jayofelony `noai` branch is a separate lineage and does not
have that legacy AI component.

Pwnagotchi is **not inherently passive-only**. The jayofelony README describes
both passive capture and active authentication/association behavior. Check the
selected release's radio settings and mode before use. Only observe networks
you own or have explicit authorization to assess, and avoid transmitting unless
the authorization specifically covers it.

## Displays, Plugins & Configuration

Display types, plugin names, settings and configuration paths can vary by
lineage and release. The original project's
[configuration guide](https://pwnagotchi.ai/configuration/) lists specific
supported e-ink and OLED implementations; a generic “OLED” or “Waveshare”
label does not establish compatibility with a particular board.

For a current fork:

1. Use its own [installation wiki](https://github.com/jayofelony/pwnagotchi/wiki)
   and release notes.
2. Back up the image and configuration before changing settings or plugins.
3. Use the fork's documented plugin manager or installation method. Do not
   download a moving-branch plugin file into a privileged path without review.
4. Use its current defaults and configuration examples. Do not copy legacy
   plugin keys, service paths or commands from another fork.

[FancyGotchi](./fancygotchi-pwnagotchi.md) is a separate theme/plugin project,
not a Pwnagotchi image or radio stack. A theme does not change the device's
radio behavior.

## Capture Files & Offline Analysis

The jayofelony README describes captures as **PCAPNG** and lists PMKIDs and
full or half WPA handshakes among the supported material. Do not assume old
`.pcap` paths or filenames; locate captures using the selected image's current
documentation and inspect the actual file format.

For authorized captures, use the repository's
[hcxtools & Hashcat reference](./hcxtoolshashcat.md) for conversion and
offline analysis. Capture possession and permission to analyze captured
material must be within the same approved scope. Do not enable automatic
third-party upload plugins unless the owner has explicitly approved the
destination and data handling.

## Install, Update & Recover

- Download the image from the chosen project's official release page.
- Match the image to the exact device and architecture; verify the published
  checksum or signature when provided.
- Confirm the destination device by model and capacity before writing. Flashing
  erases the selected storage.
- Follow the project's current first-boot and credential-change instructions.
  Do not assume a default username, password, network address, file path or
  service name from an older guide.
- Back up the working image and configuration before updating. Use the
  project's supported upgrade or reflash procedure rather than a blind
  `git pull` or global package installation.
- If boot or display fails, restore the known-good image and follow the
  version-specific recovery guide before changing more variables.

## Verification Status

**Verified: source** means upstream pages were reviewed on the date above.
No device was flashed and no capture was produced during this review. Any
hardware or runtime claim requires a dated record of the exact board, image,
release, configuration and observed result, as described in the
[Repository Verification Protocol](./REPOSITORY-VERIFICATION-PROTOCOL.md).

## Related Files

- [Device-first firmware references](../firmware-hardware-compatibility.md)
- [ESP32 & related firmware catalog](./esp32-security-firmware-catalog.md)
- [FancyGotchi & Pwnagotchi project boundaries](./fancygotchi-pwnagotchi.md)
- [hcxtools & Hashcat reference](./hcxtoolshashcat.md)
- [Documentation index](./README.md)
