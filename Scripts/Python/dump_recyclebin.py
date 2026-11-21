"""List entries in readable SID folders in the system drive's Recycle Bin."""

import ntpath
import os
from pathlib import Path
import sys


def sid_to_user(sid):
    from winreg import HKEY_LOCAL_MACHINE, OpenKey, QueryValueEx

    profile_list = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    try:
        with OpenKey(HKEY_LOCAL_MACHINE, profile_list + "\\" + sid) as key:
            value, _ = QueryValueEx(key, "ProfileImagePath")
    except OSError:
        return sid

    if isinstance(value, str):
        return ntpath.basename(value.rstrip("\\/")) or sid
    return sid


def return_dir():
    system_root = Path(os.environ.get("SystemDrive", "C:") + "\\")
    for name in ("$Recycle.Bin", "Recycler", "Recycled"):
        candidate = system_root / name
        if candidate.is_dir():
            return candidate
    return None


def find_recycled(recycle_dir):
    complete = True
    for folder in sorted(Path(recycle_dir).iterdir()):
        if not folder.name.startswith("S-1-"):
            continue
        try:
            entries = sorted(folder.iterdir())
        except OSError as exc:
            print(f"Could not list {folder.name}: {exc}", file=sys.stderr)
            complete = False
            continue

        print(f"\n[*] Listing Files For User: {sid_to_user(folder.name)}")
        for entry in entries:
            print(f"[+] Found File: {entry.name}")
    return complete


def main():
    if os.name != "nt":
        print("This inventory requires Windows.", file=sys.stderr)
        return 1

    try:
        recycled_dir = return_dir()
        if recycled_dir is None:
            print("No Recycle Bin directory was found on the system drive.", file=sys.stderr)
            return 1
        return 0 if find_recycled(recycled_dir) else 1
    except OSError as exc:
        print(f"Could not open the system drive's Recycle Bin: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
