# M5Stack CardputerZero Field Guide

[Main Repository](../../README.md) · [Cyberdeck Home](../README.md) · [Device & Firmware Catalog](../../Documentation/device-firmware-list.md) · [Evidence & Privacy](EVIDENCE_AND_PRIVACY.md) · [Wireshark Filters](../../Documentation/wireshark-master-filters.md)

Use the CardputerZero as a pocket Linux terminal for network troubleshooting, supervised administration, offline packet review and field notes. Procedures below target the M5Stack CardputerZero image and use an isolated lab or a known, authorized endpoint. Hardware controls were checked against M5Stack documentation. The labs require validation on your image and hardware before field deployment.

## Hardware & Compatibility

| Component | What to expect |
| --- | --- |
| Compute | Raspberry Pi Compute Module 0, quad-core Cortex-A53 at 1 GHz, 512 MB RAM. Choose ARM packages that match the installed userspace. |
| Storage | Linux boots from microSD. Standard includes a 32 GB card. Lite requires a separate card. |
| Controls | 46-key keyboard and 320 × 170 display. Use the built-in CLI for short commands and a workstation for large output. |
| Network | Built-in 2.4 GHz Wi-Fi, Bluetooth and 10/100 Ethernet. Plan around the documented bands and shared USB hub. |
| Power | 1,750 mAh internal battery. M5Stack recommends 5 V / 2 A. Charge through USB-C2. |
| Standard vs. Lite | The standard unit includes a built-in camera. Lite omits it. Check the exact variant before relying on camera or compass workflows. |
| Original Cardputer / ADV | ESP32-S3 devices with their own firmware targets. Use M5 Imager for CardputerZero Linux images. ESP32 binaries and Cardputer ADV accessory compatibility do not carry over. |

[M5Stack hardware specifications](https://docs.m5stack.com/en/CardputerZero) · [M5Stack model lineup](https://docs.m5stack.com/en/products)

### USB Roles & Expansion

| Task | Mode | Connection |
| --- | --- | --- |
| USB peripherals or wired networking | Host, switch right/down | USB-A, USB-C1, supported top expansion USB or built-in Ethernet |
| ADB or USB recovery from a trusted computer | Device, labeled Slave in M5Stack docs, switch left/up | USB-C2 on the right side |
| Charging | Either | USB-C2 |

The switch changes where the CM0 USB connection goes. In device mode, expect the internal hub and its Ethernet path to be unavailable. For Cap modules, shut down and turn off the device before fitting or removing the module. Fit the matching accessory, then enable its supply via **Settings → ExtPort** if required. M5Stack documents the top EXT connector and a Grove connector with I²C/UART. Check the pinout and voltage before wiring bare hardware.

| Accessory | Benign checkout | Success criterion |
| --- | --- | --- |
| Cap LoRa-1262 | Open GPS outdoors and wait for a fix | Fix status and coordinates appear. Keep coordinates out of shared notes. |
| Cap CC1101 | Open NFC and present your own blank practice tag | Reader information appears and the tag details match your test inventory. |
| USB storage | In host mode, attach a spare drive containing a test text file. Run `lsblk -o NAME,SIZE,TRAN,MOUNTPOINTS` and open the file in Files once mounted. | Expected USB disk and file appear. Unmount before removing. |

[M5Stack usage and interface guide](https://docs.m5stack.com/en/compute/cardputerzero/usage)

## Install & Recover The System

1. For a stock standard unit, first try its supplied card. For Lite or a clean installation, use a spare microSD and a reader on a trusted computer. Back up any existing data before writing.
2. Download [M5 Imager](https://github.com/CardputerZero/m5stack-imager/releases) for the workstation OS. Select **CardputerZero** and the corresponding vendor image. Record the selected version and verify a publisher-provided digest if available.
3. Match the storage target to the card's capacity and name. Writing the image overwrites the selected disk. Set a unique username and strong password, select an approved Wi-Fi network if needed and enable inbound SSH only if you plan to use it.
4. Start writing and let the imager complete verification if offered. Eject the card, insert it with the handheld powered off and turn the device on.
5. Allow extra time for first boot. Complete the first-run wizard if customization was skipped, then restart when prompted. Open **FactoryTest** and check the display, keyboard and hardware you intend to use.
6. Keep a known-good spare card. After software shutdown, move the physical power switch left to finish powering off before swapping cards. Back up logs and any local configuration before reinstalling on the same card.

**USB recovery if no card reader is available.** With a microSD inserted, set USB to device mode and connect a USB-C **data** cable from USB-C2 to a trusted workstation. Start the vendor-documented Raspberry Pi `rpiboot` build. Hold Boot, move the power switch to ON and hold Boot for more than five seconds before releasing. Once the card is exposed as a disk, write the image using M5 Imager and double-check the destination. If the workstation offers to format an unfamiliar partition, decline. If enumeration fails, use a card reader.

[M5Stack flashing guide and rpiboot version instructions](https://docs.m5stack.com/en/compute/cardputerzero/image)

## Daily Controls & Preflight

| Action | Control |
| --- | --- |
| Navigate and open an app | `fn + F/X/Z/C` for up/down/left/right, then `OK` / `ENTER` |
| Help and exit | `fn + H` in apps with help. Hold `ESC` for Home. |
| Symbols and modifiers | `sym` for blue symbols, `shift` for capitals and `fn` for orange functions. Tap once for the next keystroke, twice to latch, again to release. |
| Terminal wide output | `fn + 6` toggles the CLI viewport. Use `fn + 4/5/7/8` to pan. |
| Lock and wake | Hold `TAB` on Home. Wake with a key, then `TAB`, then `ENTER`. This launcher sequence provides no credential prompt. |
| File actions | Open **Files**, select an item, then press `TAB` for file operations. |

In **CLI**, take a small baseline before installing packages or changing network settings:

```bash
cat /etc/os-release
uname -r
dpkg --print-architecture
free -h
df -h /
ip -br address
ip route
timedatectl status
ss -lntu
```

Record the image build, installed architecture and kernel with your notes. Before collecting evidence, check time synchronization and free space. Keep vendor app updates (Settings → System → Software) and OS maintenance in the same maintenance window, but review Debian package changes with `apt list --upgradable` after `sudo apt update` before accepting them on the vendor image. Check the display, keyboard, networking and clean shutdown after changes. Retain the bootable spare until those checks pass.

## Lab 1 — Trace A Known Network Path

1. In host mode, connect Ethernet to an approved lab port, or join an approved **2.4 GHz** SSID. Open **IP Panel** and record the address of the link you intend to test.
2. In CLI, inspect the route to a known lab server. These IPs and hostname are placeholders for your own lab. Use a service that you already know is running and approve a single connection to it.

   ```bash
   ip -br link
   ip -br address
   ip route get 192.0.2.10
   getent ahostsv4 lab.example.test
   curl --connect-timeout 5 --max-time 10 --head https://lab.example.test/
   ```

3. Check the route's `dev` and `src` against IP Panel. If the interface is down, check cabling, USB mode or the Wi-Fi association. If the interface is up but has no expected address, check DHCP and the access port or SSID. If route and IP are correct but name lookup fails, check the lab DNS configuration. If HTTPS fails after resolution, record the error and check time, certificate name, trust chain and server status. Keep certificate validation enabled.
4. Save the interface, UTC time and shortest useful output in the ticket. When both Ethernet and Wi-Fi are present, use the route result to document which path was actually tested. An HTTP response such as 405 can still confirm the network and TLS path when the endpoint rejects HEAD.

## Lab 2 — Use The Zero As An SSH Console

1. Use a trusted admin network and an approved low-privilege account on a single known lab server. Obtain the server's host-key fingerprint by a trusted channel, such as its local console. For an Ed25519 host key, an admin can run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on that server.
2. Open **SSH Client** on the CardputerZero, or use CLI. Save connection details only if your handling policy allows it. Compare any first-connect fingerprint prompt to the independently recorded fingerprint before accepting.

```bash
ssh -o ConnectTimeout=5 operator@lab.example.test
```

3. Run a read-only check such as `hostname` and `uptime`, document the outcome, then `exit`. Investigate unexpected host-key changes through the trusted channel before reconnecting.
4. Enable inbound SSH to the CardputerZero only for workstation management, with a trusted management network and key authentication. Check the listener with `ss -lnt` and test key login before tightening any server settings. Leave ADB disabled when unused. For local debugging, follow the vendor's Developer menu and use USB-C2 in device mode.

## Lab 3 — Review A Small Packet Capture Offline

Use a short approved capture exported from your own sensor, or a synthetic capture from a classroom lab. Keep the original on the evidence workstation and copy only the necessary review sample to the Zero. For production monitoring, use a dedicated sensor with an approved mirror/TAP or compatible radio. The built-in wired connection on a normal switch port shows traffic at that port's vantage point. Listening to Wi-Fi as a client does not establish raw 802.11 monitor-mode support.

1. In the vendor image, check for `tshark --version`. If absent and the vendor image uses Debian package repositories, install via `sudo apt update` then `sudo apt install tshark`. Decline permission for regular users to capture packets if you only need offline analysis.
2. With your normal account, create a private case directory outside the repository and place a preapproved sample named `sample.pcapng` there. Work from that directory. If a digest came with the sample, verify it before review.

   ```bash
   umask 077
   TZ=UTC date -Is
   sha256sum -- sample.pcapng > SHA256SUMS
   tshark -n -r sample.pcapng -c 20
   tshark -n -r sample.pcapng -Y 'dns.flags.response == 1' -T fields \
     -e frame.number -e dns.qry.name -e dns.flags.rcode
   ```

3. Match frame numbers to your lab timeline. DNS response code 0 is NOERROR, 2 is SERVFAIL and 3 is NXDOMAIN. An empty result can mean the trace lacked matching DNS responses or contained only encrypted DNS traffic. Open the same file in workstation Wireshark and apply the same display filter to confirm.
4. Verify the digest with `sha256sum -c SHA256SUMS`. Label notes with the capture vantage point, tool version, time basis and source digest. A matching hash checks byte integrity relative to the recorded value. Move the report and necessary artifacts to approved encrypted storage. Follow the engagement retention policy for remaining copies.

[Wireshark filter reference](../../Documentation/wireshark-master-filters.md) · [Cyberdeck evidence handling](EVIDENCE_AND_PRIVACY.md)

## Troubleshooting & Field Checklist

| Symptom | Check in order |
| --- | --- |
| Blank display after imaging | Confirm charge, a verified vendor image and fully seated microSD. Allow time for first boot, then test the known-good card. |
| Internal Ethernet disappeared | Return USB switch to host mode. Inspect link LEDs if available and compare `ip -br link` before and after plugging in. Check switch port policy and cable. |
| Device absent in ADB or rpiboot | Set device mode, use USB-C2 and try a known data cable. Confirm the ADB setting for debugging or the Boot-button sequence for recovery. |
| Terminal output truncates | Use viewport mode, redirect to a local file, or review over SSH. |
| Offline review is slow | Check RAM and storage with `free -h` and `df -h /`. Restrict work to short approved samples and move heavy analysis to a workstation. |
| Cap missing in the app | Power down, confirm exact Cap model and orientation, reseat, boot, check ExtPort power and verify app/image support. |
| Time jumps or logs disagree | Check `timedatectl status` and compare to a trusted UTC clock. Record any known offset or uncertainty before correlating. |

Before leaving for a job, verify boot and shutdown, keyboard modifiers, the intended network path, a known SSH host key, one small offline trace and a valid export hash. Carry a known-good spare card, data cable and power source. Use minimal evidence on removable boot media and avoid storing client secrets there. The launcher lock is for casual screen access and provides no encryption at rest.

## Related Guides & Upstream Documentation

- [Cyberdeck assessment workflow](ASSESSMENT_WORKFLOW.md) and [Evidence & Privacy](EVIDENCE_AND_PRIVACY.md)
- [Device & Hardware Firmware List](../../Documentation/device-firmware-list.md) and [Wireshark Master Filters](../../Documentation/wireshark-master-filters.md)
- [M5Stack CardputerZero specs](https://docs.m5stack.com/en/CardputerZero), [usage](https://docs.m5stack.com/en/compute/cardputerzero/usage) and [flashing](https://docs.m5stack.com/en/compute/cardputerzero/image)
- [CardputerZero community apps and development tools](https://github.com/CardputerZero) and [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
