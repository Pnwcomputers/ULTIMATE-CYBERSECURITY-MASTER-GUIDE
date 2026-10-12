#!/usr/bin/env python3
"""Run one external tool and preserve its output as evidence.

The previous playbook discarded stderr (``2>/dev/null``), truncated stdout
(``| head -N``) and wrote no exit status, so a failed or cut-off collection
looked identical to a complete one.  This wrapper never truncates stored
output and always records what happened.

For ``--out BASE`` it writes (all mode 0600, created exclusively so existing
evidence is never overwritten):

    BASE.stdout        full standard output
    BASE.stderr        full standard error
    BASE.meta.json     argv, UTC start/end, exit code, status, SHA-256 of both streams

``status`` is one of:
    complete   exit code 0, not timed out, output within the size cap
    partial    non-zero exit, timeout, or output exceeded the cap (stored data is cut off)
    not_run    the executable was not found / could not be started

Usage:
    collect_evidence.py --out BASE [--label TEXT] [--timeout SEC] [--max-bytes N]
                        [--log evidence_log.md] -- CMD [ARG ...]

Exit status: 0 complete, 3 partial, 4 not_run, 2 usage error, 1 other failure.
The command is executed directly (no shell), so arguments are never re-parsed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import threading

DEFAULT_TIMEOUT = 300
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
EXIT_COMPLETE, EXIT_FAIL, EXIT_USAGE, EXIT_PARTIAL, EXIT_NOT_RUN = 0, 1, 2, 3, 4


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_exclusive(path: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    return os.fdopen(fd, "wb")


def _pump(src, dst, limit: int, result: dict, key: str) -> None:
    """Copy *src* to *dst*, hashing everything stored; stop storing past *limit*."""
    h = hashlib.sha256()
    stored = 0
    truncated = False
    while True:
        chunk = src.read(65536)
        if not chunk:
            break
        room = limit - stored
        if room <= 0:
            truncated = True
            continue  # keep draining so the child never blocks on a full pipe
        if len(chunk) > room:
            chunk = chunk[:room]
            truncated = True
        dst.write(chunk)
        h.update(chunk)
        stored += len(chunk)
    result[key] = {"sha256": h.hexdigest(), "bytes": stored, "truncated": truncated}


def _md_cell(text: str) -> str:
    cleaned = "".join(c if c.isprintable() else " " for c in text)
    return cleaned.replace("|", "\\|").replace("\n", " ")[:200]


def _append_log(log_path: str, meta: dict, label: str, base: str) -> None:
    row = "| {ts} | {label} | {status} (rc={rc}) | {sha} | {src} |\n".format(
        ts=meta["finished_utc"],
        label=_md_cell(label or os.path.basename(base)),
        status=meta["status"],
        rc=meta["returncode"],
        sha=meta["stdout"]["sha256"],
        src=_md_cell(os.path.basename(base)),
    )
    # Append-only; never rewrites earlier rows.
    fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(row)


def run(argv: list[str], base: str, label: str, timeout: int, max_bytes: int, log: str | None) -> int:
    meta: dict = {
        "label": label,
        "argv": argv,
        "started_utc": utcnow(),
        "timeout_seconds": timeout,
        "max_bytes_per_stream": max_bytes,
    }
    out_path, err_path, meta_path = base + ".stdout", base + ".stderr", base + ".meta.json"
    result: dict = {}
    timed_out = False
    status = "complete"
    rc: int | None = None

    with _create_exclusive(out_path) as fout, _create_exclusive(err_path) as ferr:
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except OSError as exc:
            status = "not_run"
            meta["error"] = f"{type(exc).__name__}: {exc.strerror or exc}"
            result["stdout"] = {"sha256": hashlib.sha256().hexdigest(), "bytes": 0, "truncated": False}
            result["stderr"] = dict(result["stdout"])
        else:
            threads = [
                threading.Thread(target=_pump, args=(proc.stdout, fout, max_bytes, result, "stdout")),
                threading.Thread(target=_pump, args=(proc.stderr, ferr, max_bytes, result, "stderr")),
            ]
            for t in threads:
                t.start()
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                rc = proc.wait()
            for t in threads:
                t.join()
            if timed_out or rc != 0 or result["stdout"]["truncated"] or result["stderr"]["truncated"]:
                status = "partial"

    meta.update(
        finished_utc=utcnow(),
        returncode=rc,
        timed_out=timed_out,
        status=status,
        stdout=result["stdout"],
        stderr=result["stderr"],
    )
    with _create_exclusive(meta_path) as fm:
        fm.write((json.dumps(meta, indent=2, sort_keys=True) + "\n").encode())
    if log:
        _append_log(log, meta, label, base)
    return {"complete": EXIT_COMPLETE, "partial": EXIT_PARTIAL, "not_run": EXIT_NOT_RUN}[status]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Run a tool and preserve complete output as evidence.")
    parser.add_argument("--out", required=True, help="output path prefix (BASE)")
    parser.add_argument("--label", default="")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--log", help="evidence_log.md to append a row to")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else 0
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd or args.timeout <= 0 or args.max_bytes <= 0:
        print("collect_evidence: need a command after '--' and positive limits", file=sys.stderr)
        return EXIT_USAGE
    try:
        return run(cmd, args.out, args.label, args.timeout, args.max_bytes, args.log)
    except FileExistsError as exc:
        print(f"collect_evidence: refusing to overwrite existing evidence: {exc.filename}", file=sys.stderr)
        return EXIT_FAIL
    except OSError as exc:
        print(f"collect_evidence: {exc.strerror or exc}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv))
