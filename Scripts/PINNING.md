# Tool pinning policy

`Scripts/pnwc_install_tools.sh` and `OSINT/Playbook/install_dependencies.sh`
install third-party tools only at versions recorded in `Scripts/tool_pins.conf`.
The file is **data, not code**: it is parsed line by line against a strict
pattern and is never `source`d. Both installers refuse a pins file or helper
library that is a symlink or is group/world-writable.

## Restored manifest: October 31, 2026

The original `Scripts/tool_pins.conf` was unintentionally absent from GitHub (see [issue #142](https://github.com/Pnwcomputers/ULTIMATE-CYBERSECURITY-MASTER-GUIDE/issues/142)). The repository's broad `*.conf` ignore rule is now narrowly overridden for **only** this data-only, reviewed manifest; other private configuration files remain ignored.

The replacement pins were **rebuilt**, not claimed to be a recovery of the original, from these independently checked sources:

- `git:*`: full 40-character commit SHA values returned by the official GitHub repository commits API. PEASS-ng migrated to the `peass-ng` GitHub organization and the pin uses that canonical repository's commit.
- `go:*`: exact versioned release tags from the upstream projects' GitHub Releases; the older Amass v4 module intentionally uses **v4.2.0** rather than the incompatible v5 series. The untagged assetfinder source uses a standard Go pseudo-version constructed from its verified commit timestamp and short hash. **Availability on Go's module proxy and runtime compatibility must still be tested.**
- `pip:*`: release versions checked on the matching PyPI project pages, including the required Python bootstrap tools and the packages listed by installer regression tests. A top-level version is not a full dependency lock.
- `dl:*`: artifact SHA-256 bytes from the GitHub Release API's **asset.digest** field, for **feroxbuster (amd64/arm64)**, **jadx**, **apktool** and the existing 12.1.4 **Ghidra** release. The hashes match the *specific filenames* requested by the installer, not similarly named assets.

**Not yet hash-verified:** phoneinfoga Linux archives, dex2jar, the raw asn and Metasploit installer scripts, rockyou wordlist and Wazuh package signing key. Upstream release metadata for some of these assets lacks a SHA-256 digest. Their version/commit strings alone **do not authorize a download**: `fetch_pinned` rejects an absent hash, records a skipped tool and never executes the content. We will add those SHA-256 pins only after independently checking the exact downloaded bytes or authentic upstream checksums. No placeholder or all-zero hashes have been used.

This fix restores a safely tracked manifest and testable supply-chain controls; it does **not** claim all optional tools now install, that every source has been security-audited, or that hashes have been validated by downloading them on a target machine.

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

* **Current tracked pins were reconstructed October 31, 2026**, as documented above. Earlier notes referring to a fully resolved October 12 manifest describe historical work that did **not** make it into Git; do not interpret them as verification of today's complete installer inventory.
* Deliberately unpinned (skipped and reported): `gem:evil-winrm`, unavailable artifact hashes listed above, `exploitdb` (GitLab source, use distro package) and the documentation clone of this repository (a pin would go stale on each merge). `pip` apps not yet individually verified also skip.
* Go versions come from git tags; availability on the Go proxy is checked when
  `go install` runs, and the checksum database verifies the content.
* Ghidra is pinned at 12.1.4 (the exact currently hardcoded installer artifact); bump it
  deliberately when a newer release comes out — the installer's folder-name
  check (`ghidra_${GHIDRA_VER}_PUBLIC`) needs updating along with the pin.
* Pinning a top-level Python package does not hash-lock its dependencies.
  For stronger guarantees generate a hash-locked requirements file per tool
  (`pip-compile --generate-hashes`) and install with `--require-hashes`.
* `pnwc_install_tools.sh` still runs as root for system package and `/opt`
  installs; the OSINT installer refuses to run as root.
