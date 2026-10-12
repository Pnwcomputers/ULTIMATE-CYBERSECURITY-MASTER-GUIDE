# OSINT Investigator Playbook — prototype

## Purpose

This folder contains a manual [investigation guide](investigation_guide.md) and
an experimental Bash menu, `osint_investigator.sh`. Use the manual guide for
investigations; the menu is a case-directory prototype.

## Implemented functionality

- Creates a case directory under `~/OSINT_Cases` and writes basic case metadata.
- Creates a local API-key configuration template.
- Contains a DNS/WHOIS helper that is not connected to the menu.

Case loading, the investigation menu, and settings are placeholders. Email,
phone, IP, username, and crypto modules, evidence hashing, chain-of-custody logs,
and report generation are **not implemented**. The script does not support
`--config` or `--install` flags. Its outputs are not a verified evidence package.

## Try the prototype

Run as a regular user in a disposable lab with Bash and Python 3:

```bash
bash osint_investigator.sh
```

The broad `install_dependencies.sh` installer supports tools discussed by the
manual guide; it is not required to create a case directory. Run it as your
**normal user** (it refuses to run as root and uses `sudo` only for distro
packages). Python tools go into isolated per-tool virtual environments under
`~/.local/share/osint-investigator/`, and only versions pinned in
[`Scripts/tool_pins.conf`](../../Scripts/PINNING.md) are installed; tools
without a pin are skipped and reported. The installer exits non-zero if any
expected tool is missing. Review its package changes before running it. Only
investigate systems and data within your authority.

### Changes that affect existing users

- **Do not run the installer with `sudo`.** Re-run it as your normal user.
- **Case state is now `.case_state.json`**, validated and never executed.
  A legacy `.case_state` shell file is ignored (not sourced); re-enter the
  indicators for that case.
- **Evidence is preserved in full.** Each tool run stores `*.stdout`, `*.stderr`
  and `*.meta.json` (exit code, UTC times, SHA-256, `complete`/`partial`/`not_run`)
  next to the report, and appends a row to `evidence_log.md`. Treat any
  `PARTIAL` or `NOT RUN` entry as an incomplete collection.
- **Config files must be private.** `api_keys.conf` and `branding.conf` are only
  loaded if you own them and they are not group/world-writable (`chmod 600`).
- **The web interface needs the installer's Flask environment**; the script no
  longer runs `pip install` at runtime.

## Development priorities

Add tested case persistence and input validation before connecting investigation
modules. Define evidence integrity and reporting requirements before advertising
those capabilities. Do not assume directories named `evidence` or `reports`
contain an automatically verified record.

[Manual workflow](investigation_guide.md) · [OSINT index](../README.md)
