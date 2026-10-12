#!/usr/bin/env python3
"""Schema-validated, atomic case state for the OSINT investigator playbook.

Replaces the former ``.case_state`` file, which was a shell fragment that the
playbook ``source``d.  Anything that could write to that file (a synced folder,
a restored backup, a shared case directory) could therefore run code as the
investigator.  The state is now plain JSON that is validated against a fixed
schema and never evaluated.

Usage (all data crosses the shell boundary as NUL-delimited records, never as
shell syntax)::

    case_state.py check-id ID
    case_state.py save CASE_DIR  < records     # records: key NUL value NUL ...
    case_state.py load CASE_DIR  > records     # same format, validated

Exit status: 0 success, 1 invalid data / refusal, 2 usage error.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile

SCHEMA_VERSION = 1
STATE_NAME = ".case_state.json"

CASE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

SCALAR_KEYS = (
    "CASE_ID",
    "CASE_TYPE",
    "COMPANY_NAME_TARGET",
    "HOSTING_PROVIDER",
    "HOSTING_ASN",
    "HOSTING_ISP",
    "HOSTING_REGISTRY",
    "HOSTING_GEOLOCATION",
    "HOSTING_COORDINATES",
    "HOSTING_TIMEZONE",
)
ARRAY_KEYS = (
    "EMAILS",
    "PHONES",
    "DOMAINS",
    "IPS",
    "IPV6S",
    "USERNAMES",
    "CRYPTO_ADDRESSES",
    "SUBDOMAINS",
)

MAX_VALUE_LEN = 1024
MAX_ITEMS = 2000
MAX_FILE_BYTES = 4 * 1024 * 1024


class StateError(Exception):
    pass


def valid_case_id(value: str) -> bool:
    return bool(CASE_ID_RE.match(value))


def _check_text(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise StateError(f"{name}: expected string")
    if len(value) > MAX_VALUE_LEN:
        raise StateError(f"{name}: value longer than {MAX_VALUE_LEN} characters")
    # Control characters (including newline, NUL, ESC) have no business in
    # indicators and are how terminal/log injection is done.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise StateError(f"{name}: control characters are not allowed")
    return value


def validate(state: object) -> dict:
    """Return a normalised copy of *state* or raise StateError."""
    if not isinstance(state, dict):
        raise StateError("state must be a JSON object")
    allowed = {"schema_version", *SCALAR_KEYS, *ARRAY_KEYS}
    unknown = sorted(set(state) - allowed)
    if unknown:
        raise StateError(f"unknown field(s): {', '.join(unknown)}")
    if state.get("schema_version") != SCHEMA_VERSION:
        raise StateError(f"unsupported schema_version: {state.get('schema_version')!r}")

    out: dict = {"schema_version": SCHEMA_VERSION}
    for key in SCALAR_KEYS:
        out[key] = _check_text(key, state.get(key, ""))
    if not valid_case_id(out["CASE_ID"]):
        raise StateError("CASE_ID is missing or not a valid case id")
    for key in ARRAY_KEYS:
        items = state.get(key, [])
        if not isinstance(items, list):
            raise StateError(f"{key}: expected array")
        if len(items) > MAX_ITEMS:
            raise StateError(f"{key}: more than {MAX_ITEMS} items")
        out[key] = [_check_text(f"{key}[{i}]", v) for i, v in enumerate(items)]
    return out


def parse_records(data: bytes) -> dict:
    """Parse ``key NUL value NUL`` records into a state dict (repeat key = array item)."""
    if not data:
        parts: list[bytes] = []
    else:
        if not data.endswith(b"\0"):
            raise StateError("malformed record stream")
        parts = data.split(b"\0")[:-1]
    if len(parts) % 2:
        raise StateError("malformed record stream (odd field count)")
    state: dict = {"schema_version": SCHEMA_VERSION}
    for i in range(0, len(parts), 2):
        try:
            key = parts[i].decode("utf-8")
            value = parts[i + 1].decode("utf-8")
        except UnicodeDecodeError:
            raise StateError("record is not valid UTF-8") from None
        if key in ARRAY_KEYS:
            state.setdefault(key, []).append(value)
        elif key in SCALAR_KEYS:
            if key in state:
                raise StateError(f"{key}: given more than once")
            state[key] = value
        else:
            raise StateError(f"unknown field: {key[:40]!r}")
    return state


def emit_records(state: dict) -> bytes:
    chunks: list[bytes] = []
    for key in SCALAR_KEYS:
        chunks += [key.encode(), state[key].encode()]
    for key in ARRAY_KEYS:
        for item in state[key]:
            chunks += [key.encode(), item.encode()]
    return b"".join(c + b"\0" for c in chunks)


def _state_path(case_dir: str) -> str:
    return os.path.join(case_dir, STATE_NAME)


def _check_case_dir(case_dir: str) -> None:
    try:
        st = os.lstat(case_dir)
    except OSError as exc:
        raise StateError(f"case directory unavailable: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise StateError("case directory must be a real directory (not a symlink)")
    if st.st_uid != os.geteuid():
        raise StateError("case directory is not owned by the current user")
    if st.st_mode & 0o022:
        raise StateError("case directory is group- or world-writable; refusing to use it")


def save(case_dir: str, state: dict) -> None:
    state = validate(state)
    _check_case_dir(case_dir)
    payload = (json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    # Temp file in the same directory so os.replace() is an atomic rename.
    fd, tmp = tempfile.mkstemp(prefix=".case_state.", suffix=".tmp", dir=case_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, _state_path(case_dir))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(case_dir, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def load(case_dir: str) -> dict:
    _check_case_dir(case_dir)
    path = _state_path(case_dir)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise StateError("no saved state for this case") from None
    if not stat.S_ISREG(st.st_mode):
        raise StateError("state file is not a regular file (symlink or special file)")
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise StateError("state file is not owned by you or is group/world-writable")
    if st.st_size > MAX_FILE_BYTES:
        raise StateError("state file is unreasonably large")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as fh:
        raw = fh.read(MAX_FILE_BYTES + 1)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise StateError(f"state file is not valid JSON: {exc}") from None
    return validate(data)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    cmd, arg = argv[1], argv[2]
    try:
        if cmd == "check-id":
            return 0 if valid_case_id(arg) else 1
        if cmd == "save":
            save(arg, parse_records(sys.stdin.buffer.read(MAX_FILE_BYTES + 1)))
            return 0
        if cmd == "load":
            sys.stdout.buffer.write(emit_records(load(arg)))
            return 0
    except StateError as exc:
        print(f"case_state: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"case_state: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print(f"case_state: unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
