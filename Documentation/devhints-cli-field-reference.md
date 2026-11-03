# CLI Field Cheat Sheet: Devhints-Informed Quick Reference

**Scope:** Practical Linux, shell, network, transfer, Git and container commands for
authorized IT administration, security assessments and incident-response labs.

[Cheat sheet index](CHEATSHEET-REFERENCE-AUDIT-2026-10-31.md) ·
[Linux](LinuxCheatSheet.md) ·
[Bash scripting](../Scripts/Bash/bash_scripting_cheat-sheet.md) ·
[Container security](../ContainerSecurity/README.md) ·
[Repository home](../README.md)

> [!IMPORTANT]
> Examples are written for this guide, not copied from Devhints. They are illustrative
> and have **not** been executed across every distribution or tool version. Review
> commands before running them; limit collection to systems and data you are
> authorized to access. Replace example paths and hostnames, and protect sensitive
> command output. Do not disable TLS verification or execute unreviewed remote
> shell scripts.

## 1. Shell and Bash safety checks

```bash
bash -n script.sh                    # Syntax check; does not execute the script
shellcheck script.sh                 # Static analysis (if ShellCheck is installed)
type -a curl                         # Find the command/aliases on PATH
command -v gpg                       # Check whether a command is available
printf '%q\n' "a file name.txt"      # Show shell-escaped representation
find ./scripts -type f -name '*.sh' -print
```

For shell scripts, use `set -euo pipefail` thoughtfully: `-e` can surprise when
commands are used in tests or pipelines. Prefer explicit error handling, quoted
variables and inspection of command exit statuses. See the
[Bash scripting reference](../Scripts/Bash/bash_scripting_cheat-sheet.md) for
control flow and error-handling patterns.

Source pointers:
[Devhints Bash](https://devhints.io/bash) ·
[GNU Bash manual](https://www.gnu.org/software/bash/manual/).

## 2. File discovery and log triage

```bash
find /var/log -type f -name '*.log' -print
find /var/log -type f -mmin -60 -print         # Modified in past 60 minutes
find /var/log -type f -size +100M -print       # Files larger than 100 MiB
find . -type f -iname '*config*' -print
grep -RIn --include='*.conf' 'PermitRootLogin' /etc/ssh
grep -nE 'error|failed|denied' ./example.log
grep -c 'Failed password' ./auth-sample.log
tail -n 100 /var/log/syslog                   # If this log exists on the host
journalctl -p warning --since '1 hour ago' --no-pager
journalctl -u ssh --since 'today' --no-pager  # Unit name is distro-dependent
```

Use `grep -F` for literal text, `grep -E` for extended regular expressions, and
`grep -i` for case-insensitive matching. Large searches may expose secrets;
collect only relevant logs and redact before sharing.

Source pointers:
[Devhints find](https://devhints.io/find) ·
[Devhints grep](https://devhints.io/grep) ·
[GNU findutils](https://www.gnu.org/software/findutils/manual/html_mono/find.html).

## 3. HTTP and TLS diagnostics with curl

Use a test domain, a service you operate, or an explicitly authorized target.

```bash
curl -I --max-time 10 https://example.com
curl -L -I --max-redirs 5 https://example.com
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' https://example.com
curl --fail --silent --show-error -o response.json https://example.com/api/health
curl -v --max-time 10 https://example.com/ -o /dev/null   # Verbose output can reveal headers
curl --cacert ./trusted-ca.pem https://example.com/       # Private PKI, trusted CA file
curl --request OPTIONS -i https://example.com/            # Inspect permitted HTTP methods
openssl s_client -connect example.com:443 -servername example.com </dev/null
```

`curl -I` sends a HEAD request; some applications do not support HEAD correctly.
Use an ordinary GET when necessary. Never put authentication tokens in committed
scripts or share `curl -v` output before checking for credentials. `--cacert`
provides a trust anchor; do not substitute `-k`/`--insecure`.

Source pointers:
[Devhints curl](https://devhints.io/curl) ·
[curl documentation](https://curl.se/docs/manpage.html) ·
[OpenSSL s_client](https://docs.openssl.org/master/man1/openssl-s_client/).

## 4. Hosts, sockets and routing

```bash
ip -br address                       # Short interface/address listing
ip route                             # Local routing table
ip route get 1.1.1.1                 # Local route decision; does not ping
ss -lnt                              # Listening TCP sockets
ss -lun                              # Listening UDP sockets
ss -tulpn                            # Socket details; process names may need privilege
getent ahosts example.com            # Hostname resolution via NSS
hostnamectl                          # Host and OS details (systemd hosts)
```

Do not confuse a listening socket with evidence that a particular product or
process is secure. For packet filters and investigation, use the
[Wireshark field reference](wireshark-cheatsheet.md); for service conventions,
see [ports and regex](references.md).

## 5. File transfer and backup verification

```bash
rsync -aHvn --stats ./evidence/ ./staging/       # Dry run first
rsync -aHv --stats ./evidence/ ./staging/        # Copies directory contents
rsync -aHvn --delete ./source/ ./mirror/        # DANGEROUS if run without -n
rsync -aHvn -e ssh ./evidence/ analyst@labhost:/srv/triage/
scp ./report.txt analyst@labhost:/srv/triage/
sftp analyst@labhost                             # Interactive transfer
sha256sum ./evidence/sample.bin
sha256sum -c ./checksums.sha256                  # Verify an existing manifest
tar -czf ./triage-bundle.tar.gz ./triage/        # Archive (not encryption)
```

**Important:** `rsync source/ destination/` copies the *contents* of `source`;
`rsync source destination/` also creates the `source` directory under the
destination. With `--delete`, first inspect a dry run carefully; a wrong
destination can erase data. `sha256sum` checks integrity, not authenticity.
Keep original evidence write-protected where your procedure requires it.

Source pointers:
[Devhints rsync](https://devhints.io/rsync) ·
[Devhints scp](https://devhints.io/scp) ·
[rsync manual](https://download.samba.org/pub/rsync/rsync.1).

## 6. GnuPG keys, encryption and signature verification

```bash
gpg --list-keys --keyid-format LONG
gpg --list-secret-keys --keyid-format LONG
gpg --fingerprint recipient@example.com         # Verify out-of-band
gpg --import ./public-key.asc
gpg --armor --export recipient@example.com > recipient-public.asc
gpg --encrypt --recipient recipient@example.com --output report.gpg report.txt
gpg --decrypt --output report-restored.txt report.gpg
gpg --detach-sign --armor --output report.sig.asc report.txt
gpg --verify report.sig.asc report.txt
openssl dgst -sha256 ./report.txt                 # Hash, not a signature
```

Verify a key fingerprint through an independent, trusted channel before
encrypting to it. Never publish secret key material. `gpg --verify` proves
a cryptographic signature matches a key, but you must independently assess
whether that key belongs to the claimed signer. Avoid plaintext copies of
sensitive reports where encrypted handling is required.

Source pointers:
[Devhints GnuPG](https://devhints.io/gnupg) ·
[GnuPG manual](https://gnupg.org/documentation/manuals/gnupg/).

## 7. Git change review and provenance

```bash
git status --short
git diff --check                      # Whitespace/conflict-marker sanity
git diff --stat
git diff --name-only
git log -n 10 --oneline --decorate
git log -1 --show-signature           # If the commit is signed
git grep -n 'TODO' -- '*.md'
git switch -c docs/my-reference-update
git add -- Documentation/README.md
git diff --cached --check
git diff --cached
```

Review staged changes before committing. `git diff --check` catches whitespace
errors, but does not validate links, command syntax, licensing or correctness.
Read [repository contribution conventions](../STYLE_GUIDE.md) before changes.

Source pointers:
[Devhints Git tricks](https://devhints.io/git-tricks) ·
[Devhints Git branches](https://devhints.io/git-branch) ·
[Git reference](https://git-scm.com/docs).

## 8. Docker and Compose inspection

These are **inspection-first** commands. Docker daemon access is effectively
privileged on many hosts; inspect only systems you manage or may assess.

```bash
docker version
docker info
docker ps --all
docker images
docker logs --tail 100 my-container
docker inspect my-container
docker image inspect debian:bookworm-slim
docker system df
docker compose config --quiet          # Validate effective Compose configuration
docker compose ps
docker compose logs --tail 100
docker events --since 10m --until 0m   # Recent daemon events; support varies
```

Avoid making `docker system prune`, `volume prune` or `docker rm -f` routine
copy-paste commands on production hosts. For runtime hardening, image trust
and escape risks, see the [container security guide](../ContainerSecurity/containers.md).

Source pointers:
[Devhints Docker](https://devhints.io/docker) ·
[Devhints Compose](https://devhints.io/docker-compose) ·
[Docker CLI reference](https://docs.docker.com/reference/cli/docker/).

## 9. Screen, tmux and scheduled-job troubleshooting

```bash
screen -ls
screen -D -r session_name             # Detach elsewhere and reattach; may interrupt operator
tmux ls
tmux new -s incident-notes
tmux attach -t incident-notes
tmux list-panes -a
crontab -l                            # Current user's crontab
systemctl list-timers --all
systemctl list-units --failed
```

Treat `screen -D -r` carefully on shared systems: it takes over an attached
session. `crontab -l` is not an inventory of every scheduled task; also inspect
system timers, applicable service accounts and system cron locations.

Source pointers:
[Devhints screen](https://devhints.io/screen) ·
[Devhints tmux](https://devhints.io/tmux) ·
[Devhints cron](https://devhints.io/cron).

## 10. Next references and maintenance

- [Bash scripting](../Scripts/Bash/bash_scripting_cheat-sheet.md) for program structure,
  trap handling and reusable scripts.
- [Linux command reference](LinuxCheatSheet.md) for distro-specific administration,
  WSL and security tooling.
- [Network/regex reference](references.md) and
  [Wireshark/TShark](wireshark-cheatsheet.md) for protocol investigations.
- [Container Security](../ContainerSecurity/README.md) for threat modeling and
  hardening; this page intentionally does not replace it.
- [Official tool manuals](https://www.gnu.org/software/coreutils/manual/) for version-specific behavior.

**Provenance:** Prepared November 2, 2026, using Devhints as a discovery index,
with original examples and additional operational cautions. Devhints is
maintained at [devhints.io](https://devhints.io/) and
[github.com/rstacruz/cheatsheets](https://github.com/rstacruz/cheatsheets).
The source repository did not declare a license in its GitHub repository
metadata when checked; this page is **not a mirror, transcription or bulk import**
of upstream cheat sheets. Commands represent common CLI syntax, not an
endorsement that every example fits every platform. Check upstream/official
docs when the installed version differs.
