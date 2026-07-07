# OnePlus 6 (A3006 / "enchilada")
### Bootloader Unlock, TWRP, LineageOS 22.2 & Magisk Root

This is the prep guide that gets you to the exact state the NetHunter guide assumes: unlocked bootloader, TWRP installed, running LineageOS 22.2, rooted with Magisk. Do these phases in order — don't skip ahead.

**Read the whole guide once before starting.** Every phase here wipes data at least once. Back up anything you care about (photos, app data via a cloud backup, etc.) before you begin — the very first step erases everything.

---

## Phase 0 — Before you start

- Charge to at least 50%.
- On your PC, install the Android SDK Platform Tools (adb + fastboot): https://developer.android.com/studio/releases/platform-tools
- On the phone: **Settings → About phone**, tap **Build number** 7 times to unlock Developer options.
- **Settings → System → Developer options**: enable **USB debugging**, **OEM unlocking**, and **Advanced reboot**.
- Confirm you're on the latest official **OxygenOS** before doing anything else (Settings → System updates → check for update). LineageOS's install requirements for this device specify a particular Android-11-era stock firmware baseline needs to be on the phone first — flashing LineageOS on top of very old firmware can cause boot failures. If you're not sure what firmware you're on, update to the latest available OOS build over-the-air first.

---

## Phase 1 — Unlock the bootloader

**This wipes all data on the phone.**

1. Connect the phone to your PC via USB.
2. Reboot to bootloader:
   ```
   adb reboot bootloader
   ```
   (or power off, then hold Volume Up + Power)
3. Confirm the PC sees the device:
   ```
   fastboot devices
   ```
4. Unlock:
   ```
   fastboot oem unlock
   ```
5. Use the volume keys to select **Yes** on the on-screen warning, then the power button to confirm.
6. The phone wipes itself and reboots. Go back through initial setup, then re-enable Developer options → USB debugging (it resets every time the bootloader state changes).

---

## Phase 2 — Flash the extra partition LineageOS needs (dtbo)

The OnePlus 6/6T platform needs an extra `dtbo.img` flashed before a custom recovery will work correctly on it. Skipping this is one of the most common causes of "recovery won't boot" on this device.

1. Download `dtbo.img` from the official LineageOS device downloads page for `enchilada`: https://download.lineageos.org/devices/enchilada (grab it from the same listing as the recovery/build files).
2. Boot to bootloader (Volume Up + Power while off).
3. Flash it:
   ```
   fastboot flash dtbo dtbo.img
   ```
4. Reboot to bootloader again:
   ```
   fastboot reboot bootloader
   ```

---

## Phase 3 — Install LineageOS 22.2

LineageOS's own install process uses its own recovery ("Lineage Recovery") rather than TWRP for the actual OS flash — the project explicitly warns other recoveries may not sideload the package correctly. So: use Lineage Recovery to get LineageOS installed, then swap in TWRP afterward (Phase 4) for your day-to-day custom recovery (which is also what you'll use later to flash NetHunter).

1. From https://download.lineageos.org/devices/enchilada, download:
   - The **recovery image**, named `boot.img` (this is Lineage Recovery, not your final boot image)
   - The **LineageOS 22.2 zip** for enchilada
2. Flash the recovery:
   ```
   fastboot flash boot boot.img
   ```
3. Boot into recovery from the bootloader menu (volume keys to navigate, power to select). Confirm you see the LineageOS logo — if you see stock recovery instead, you flashed/booted the wrong thing.
4. In Lineage Recovery: **Factory Reset → Format data / factory reset**, and confirm. This removes encryption and wipes internal storage — expected and required at this stage.
5. Back at the main recovery menu: **Apply update → Apply from ADB**.
6. On the PC:
   ```
   adb sideload lineage-22.2-*-enchilada-signed.zip
   ```
   (replace with your actual downloaded filename)
7. When it finishes, **don't reboot yet** if you also want Google apps or other add-ons — sideload those the same way (**Apply from ADB** again for each add-on zip). If not, skip to the next step.
8. Reboot into the OS: back arrow → **Reboot system now**. First boot can take up to ~15 minutes.
9. Complete LineageOS setup.

At this point you're running LineageOS 22.2 — the exact base the NetHunter image for this device expects — but your recovery is currently Lineage Recovery, not TWRP.

---

## Phase 4 — Install TWRP (replacing Lineage Recovery)

TWRP's official install method for enchilada:

1. Download the current TWRP image for `enchilada` from https://dl.twrp.me/enchilada/ (rename to `twrp.img` and place it next to your platform-tools, and also copy it to the phone's storage).
2. Reboot to bootloader:
   ```
   adb reboot bootloader
   ```
3. **Temporarily** boot the TWRP image (don't flash yet):
   ```
   fastboot boot twrp.img
   ```
4. Once TWRP boots, go to **Advanced → Flash Current TWRP**. This installs the image you just booted permanently, overwriting Lineage Recovery.
5. Still in Advanced, run **Fix Recovery Bootloop** — TWRP's own instructions call this out as required on enchilada to avoid boot-looping after a permanent TWRP install.
6. Reboot to system, then reboot back to recovery once to confirm TWRP now loads instead of Lineage Recovery.

⚠️ Don't `fastboot flash boot twrp.img` directly — TWRP's own docs warn that flashing (rather than temporarily booting first) can leave you needing to reflash a factory boot image to recover. Always `fastboot boot` first, then use the in-recovery "Flash Current TWRP" option.

---

## Phase 5 — Root with Magisk

Magisk's currently recommended method is patching the boot image directly (their custom-recovery flashable-zip method is deprecated). You need a copy of the **boot.img actually used by your installed LineageOS 22.2** — not the Lineage Recovery image from Phase 3.

1. Get the LineageOS boot image. The straightforward way: extract it from the same LineageOS 22.2 zip you sideloaded in Phase 3, using a payload dumper (the zip contains a `payload.bin`; tools like `payload-dumper-go` extract `boot.img` from it). Copy the resulting `boot.img` to your phone.
2. Install the latest Magisk app APK on the phone (from Magisk's GitHub releases).
3. Open Magisk → **Install** → **Select and Patch a File** → choose the `boot.img` you copied over.
4. Let it patch. It'll drop a `magisk_patched_[random].img` in your Downloads folder.
5. Pull it to your PC:
   ```
   adb pull /sdcard/Download/magisk_patched_[random].img
   ```
6. Reboot to bootloader and flash it to the boot partition:
   ```
   fastboot flash boot magisk_patched_[random].img
   ```
7. Reboot to system, open the Magisk app — it'll finish setting itself up (may prompt a further reboot to fix its environment).

Never reuse a patched image from another device or another phone of the "same model" — always patch on the exact device you're installing it to.

---

## Verifying you're ready for NetHunter

- **Settings → About phone** shows LineageOS 22.2 (Android 15).
- Magisk app shows root granted, no errors.
- Rebooting into recovery shows TWRP, not Lineage Recovery.
- Bootloader still shows unlocked (`fastboot flashing get_unlock_ability` or just check the boot warning screen).

That's the exact state the NetHunter install guide assumes — you're ready to move on to flashing the `kali-nethunter-2026.2-oneplus6-los-fifteen-full.zip` image.

---

### Sources

- [How to Unlock the Bootloader on Your OnePlus 6 (Gadget Hacks)](https://oneplus.gadgethacks.com/how-to/unlock-bootloader-your-oneplus-6-0185473/)
- [TWRP for OnePlus 6 (enchilada) — official](https://twrp.me/oneplus/oneplus6.html)
- [TWRP downloads for enchilada](https://dl.twrp.me/enchilada/)
- [LineageOS Wiki — Install on enchilada](https://wiki.lineageos.org/devices/enchilada/install/)
- [LineageOS downloads — enchilada](https://download.lineageos.org/devices/enchilada)
- [Magisk official installation guide](https://topjohnwu.github.io/Magisk/install.html)
