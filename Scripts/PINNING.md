# Tool pinning policy

`Scripts/pnwc_install_tools.sh` and `OSINT/Playbook/install_dependencies.sh`
install third-party tools only at versions recorded in `Scripts/tool_pins.conf`.
The file is **data, not code**: it is parsed line by line against a strict
pattern and is never `source`d. Both installers refuse a pins file or helper
library that is a symlink or is group/world-writable.

## Key format

| Key | Value | Used for |
|---|---|---|
| `pip:<package>` | exact version | Python tools (isolated venv per tool) |
| `gem:<name>` | exact version | Ruby gems |
| `go:<module/path>` | exact version | `go install` (checksum database enforced) |
| `cargo:<crate>` | exact version | `cargo install --locked` |
| `git:<name>` | full 40-hex commit | `git` checkouts (fetched at that commit) |
| `dl:<name>:version` | version string | release archives / installer scripts |
| `dl:<name>:sha256:<amd64\|arm64\|any>` | 64-hex SHA-256 | the file that is downloaded |

## Behaviour

* **No pin, no install.** A tool without a pin is skipped and listed in the
  summary under "no pin". It is never installed from `latest` or a branch head.
* **Downloads, repository keys and installer scripts are never unpinned.** They
  require a SHA-256 pin; `--allow-unpinned` does not apply to them. The hash is
  checked before extraction or execution, over HTTPS only.
* **`--allow-unpinned` / `PNWC_ALLOW_UNPINNED=1`** is a lab-only override for
  pip, gem, go, cargo and git tools. Every use is reported in the summary.
* **A malformed pin is a hard failure**, not a fallback to unpinned.
* The installers exit non-zero if any tool failed or (OSINT installer) any
  expected tool is missing.

## Adding or updating a pin

1. Choose the version from the project's official release page or package index
   and read its release notes.
2. For a download, fetch the artifact yourself and compute the hash:
   `sha256sum <file>`. Compare it with the checksum or signature the project
   publishes where one exists. Do not copy a hash from a mirror or a comment.
3. For a git tool, record the full commit hash you reviewed (`git rev-parse HEAD`).
4. Add the line to `Scripts/tool_pins.conf`, then run
   `python3 -B -m unittest discover -s tests/hardening`. (`--print-pins` is not
   a dry run: it performs the install and then prints suggested pins for any
   unpinned items, so use it only on a disposable lab machine.)

## Known limits

* Only `pip:` pins are populated today. Git, Go, release-download and gem/cargo
  pins are empty because they must be resolved and hash-verified against the
  upstream projects; until then those tools are skipped and reported.
* Pinning a top-level Python package does not hash-lock its dependencies.
  For stronger guarantees generate a hash-locked requirements file per tool
  (`pip-compile --generate-hashes`) and install with `--require-hashes`.
* `pnwc_install_tools.sh` still runs as root for system package and `/opt`
  installs; the OSINT installer refuses to run as root.
