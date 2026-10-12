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
| `dl:<name>:commit` | full 40-hex commit | raw files served from a repository (URL is built from the commit, never a moving branch) |
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

* Pins were resolved on 2026-10-12: PyPI versions from PyPI, git commits and Go
  versions from upstream tags via `git ls-remote`, the cargo version from the
  crates.io index, and download hashes by hashing the artifacts as fetched over
  HTTPS. Download hashes are trust-on-first-use (most projects publish no checksum
  file); none of the pins is a security review of that release.
* Deliberately unpinned (skipped and reported): `gem:evil-winrm` and
  `dl:wazuh-gpg-key` (their hosts were unreachable when pins were resolved),
  `exploitdb` (gitlab.com unreachable; use the distro package) and the
  documentation clone of this repository (a pin would go stale on every merge).
* Go versions come from git tags; availability on the Go proxy is checked when
  `go install` runs, and the checksum database verifies the content.
* Ghidra is pinned at 12.1.4 (latest stable as of 2026-10-12); bump it
  deliberately when a newer release comes out — the installer's folder-name
  check (`ghidra_${GHIDRA_VER}_PUBLIC`) needs updating along with the pin.
* Pinning a top-level Python package does not hash-lock its dependencies.
  For stronger guarantees generate a hash-locked requirements file per tool
  (`pip-compile --generate-hashes`) and install with `--require-hashes`.
* `pnwc_install_tools.sh` still runs as root for system package and `/opt`
  installs; the OSINT installer refuses to run as root.
