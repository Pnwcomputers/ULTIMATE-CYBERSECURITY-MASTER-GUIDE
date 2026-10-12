"""Regression tests for Scripts/lib/safe_install.sh.

Hermetic: no network, no root, only temporary directories. Run with:

    python3 -B -m unittest discover -s tests/hardening -v
"""
import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "Scripts" / "lib" / "safe_install.sh"


def bash(script, env=None, cwd=None):
    """Run a bash snippet with the library sourced; return CompletedProcess."""
    full_env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
    full_env.update(env or {})
    return subprocess.run(
        ["bash", "-c", f'source "{LIB}"\n{script}'],
        capture_output=True, text=True, env=full_env, cwd=cwd,
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TempDirTests(unittest.TestCase):
    def test_private_dir_and_cleanup(self):
        r = bash('safe_mktemp_dir d; stat -c "%a" "$d"; echo "$d"; safe_cleanup; '
                 '[[ -d "$d" ]] && echo STILL || echo GONE')
        self.assertEqual(r.returncode, 0, r.stderr)
        mode, path, state = r.stdout.split()
        self.assertEqual(mode, "700")
        self.assertIn("pnwc.", path)
        self.assertEqual(state, "GONE")

    def test_two_dirs_are_distinct(self):
        r = bash('safe_mktemp_dir a; safe_mktemp_dir b; [[ "$a" != "$b" ]] && echo OK; safe_cleanup')
        self.assertEqual(r.stdout.strip(), "OK", r.stderr)


class ChecksumTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Path(self.tmp.name) / "a.bin"
        self.f.write_bytes(b"hello")

    def test_match(self):
        r = bash(f'safe_verify_sha256 "{self.f}" {sha256(b"hello")}')
        self.assertEqual(r.returncode, 0)

    def test_uppercase_hex_accepted(self):
        r = bash(f'safe_verify_sha256 "{self.f}" {sha256(b"hello").upper()}')
        self.assertEqual(r.returncode, 0)

    def test_mismatch(self):
        r = bash(f'safe_verify_sha256 "{self.f}" {sha256(b"other")}')
        self.assertEqual(r.returncode, 1)

    def test_malformed_expected_is_distinct_error(self):
        for bad in ("", "abc", "g" * 64, "0" * 63):
            r = bash(f'safe_verify_sha256 "{self.f}" "{bad}"')
            self.assertEqual(r.returncode, 2, bad)

    def test_symlink_refused(self):
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.f)
        r = bash(f'safe_verify_sha256 "{link}" {sha256(b"hello")}')
        self.assertEqual(r.returncode, 1)


class FetchTests(unittest.TestCase):
    ENV = {"SAFE_ALLOW_FILE_URLS": "1"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = Path(self.tmp.name) / "src.bin"
        self.src.write_bytes(b"artifact-bytes")
        self.dest = Path(self.tmp.name) / "out.bin"

    def fetch(self, url, want, env=None):
        return bash(f'safe_fetch_verified "{url}" "{want}" "{self.dest}"; echo "rc=$?"',
                    env=env if env is not None else self.ENV)

    def test_verified_download_lands(self):
        r = self.fetch(self.src.as_uri(), sha256(b"artifact-bytes"))
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertEqual(self.dest.read_bytes(), b"artifact-bytes")

    def test_mismatch_leaves_no_file(self):
        self.dest.write_bytes(b"stale")
        r = self.fetch(self.src.as_uri(), sha256(b"different"))
        self.assertIn("rc=3", r.stdout)
        self.assertFalse(self.dest.exists())

    def test_invalid_expected_hash_refused_before_download(self):
        r = self.fetch(self.src.as_uri(), "not-a-hash")
        self.assertIn("rc=2", r.stdout)
        self.assertFalse(self.dest.exists())

    def test_missing_source_is_download_failure(self):
        r = self.fetch((Path(self.tmp.name) / "nope").as_uri(), sha256(b"x"))
        self.assertIn("rc=4", r.stdout)
        self.assertFalse(self.dest.exists())

    def test_plain_http_refused(self):
        r = self.fetch("http://example.invalid/x", sha256(b"x"), env={})
        self.assertIn("rc=5", r.stdout)

    def test_file_scheme_refused_without_opt_in(self):
        r = self.fetch(self.src.as_uri(), sha256(b"artifact-bytes"), env={})
        self.assertIn("rc=5", r.stdout)
        self.assertFalse(self.dest.exists())

    def test_fetch_leaves_no_temp_dirs_behind(self):
        scratch = Path(self.tmp.name) / "scratch"
        scratch.mkdir()
        env = dict(self.ENV, TMPDIR=str(scratch))
        for want in (sha256(b"artifact-bytes"), sha256(b"wrong")):
            bash(f'safe_fetch_verified "{self.src.as_uri()}" "{want}" "{self.dest}"', env=env)
        self.assertEqual(list(scratch.iterdir()), [])


class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()

    def make_tar(self, entries):
        p = self.root / "a.tar.gz"
        with tarfile.open(p, "w:gz") as t:
            for name, kind, payload in entries:
                ti = tarfile.TarInfo(name)
                if kind == "file":
                    ti.size = len(payload)
                    import io
                    t.addfile(ti, io.BytesIO(payload))
                elif kind == "symlink":
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = payload
                    t.addfile(ti)
        return p

    def extract(self, archive, member):
        return bash(f'safe_extract_member "{archive}" "{member}" "{self.out}"; echo "rc=$?"')

    def test_tar_regular_member(self):
        a = self.make_tar([("tool", "file", b"#!/bin/sh\n"), ("README", "file", b"x")])
        r = self.extract(a, "tool")
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertEqual((self.out / "tool").read_bytes(), b"#!/bin/sh\n")
        self.assertFalse((self.out / "README").exists())

    def test_tar_symlink_member_refused(self):
        a = self.make_tar([("tool", "symlink", "/etc/passwd")])
        r = self.extract(a, "tool")
        self.assertNotIn("rc=0", r.stdout)
        self.assertFalse((self.out / "tool").exists())

    def test_tar_missing_member(self):
        a = self.make_tar([("other", "file", b"x")])
        self.assertNotIn("rc=0", self.extract(a, "tool").stdout)

    def test_unsafe_member_names_refused(self):
        a = self.make_tar([("tool", "file", b"x")])
        for name in ("../evil", "/etc/passwd", "a/../../b", "..", "-x", "*", "t?ol", "t[o]ol"):
            r = self.extract(a, name)
            self.assertNotIn("rc=0", r.stdout, name)

    def test_zip_regular_member(self):
        p = self.root / "a.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("bin/tool", b"zipdata")
        r = self.extract(p, "bin/tool")
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertEqual((self.out / "tool").read_bytes(), b"zipdata")

    def test_zip_symlink_member_refused(self):
        p = self.root / "s.zip"
        with zipfile.ZipFile(p, "w") as z:
            zi = zipfile.ZipInfo("tool")
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, "/etc/passwd")
        r = self.extract(p, "tool")
        self.assertNotIn("rc=0", r.stdout)
        self.assertFalse((self.out / "tool").exists())

    def test_unsupported_archive_type(self):
        p = self.root / "a.rar"
        p.write_bytes(b"x")
        self.assertNotIn("rc=0", self.extract(p, "tool").stdout)


class ExtractAllTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"
        self.out.mkdir()

    def run_extract(self, archive):
        return bash(f'safe_extract_all "{archive}" "{self.out}"; echo "rc=$?"')

    def test_clean_tar_extracts_tree(self):
        p = self.root / "t.tar.gz"
        src = self.root / "src"
        (src / "bin").mkdir(parents=True)
        (src / "bin" / "tool").write_text("x")
        with tarfile.open(p, "w:gz") as t:
            t.add(src, arcname="pkg")
        r = self.run_extract(p)
        self.assertIn("rc=0", r.stdout, r.stderr)
        self.assertEqual((self.out / "pkg" / "bin" / "tool").read_text(), "x")

    def test_tar_with_symlink_rejected_and_nothing_extracted(self):
        p = self.root / "t.tar.gz"
        with tarfile.open(p, "w:gz") as t:
            import io
            ti = tarfile.TarInfo("ok"); ti.size = 1
            t.addfile(ti, io.BytesIO(b"x"))
            ln = tarfile.TarInfo("evil"); ln.type = tarfile.SYMTYPE; ln.linkname = "/etc/passwd"
            t.addfile(ln)
        r = self.run_extract(p)
        self.assertNotIn("rc=0", r.stdout)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_tar_traversal_rejected(self):
        p = self.root / "t.tar.gz"
        with tarfile.open(p, "w:gz") as t:
            import io
            ti = tarfile.TarInfo("../escape"); ti.size = 1
            t.addfile(ti, io.BytesIO(b"x"))
        r = self.run_extract(p)
        self.assertNotIn("rc=0", r.stdout)
        self.assertFalse((self.root / "escape").exists())

    def test_zip_clean_and_traversal(self):
        good = self.root / "g.zip"
        with zipfile.ZipFile(good, "w") as z:
            z.writestr("pkg/bin/tool", b"ok")
        self.assertIn("rc=0", self.run_extract(good).stdout)
        self.assertEqual((self.out / "pkg" / "bin" / "tool").read_bytes(), b"ok")

        evil = self.root / "e.zip"
        with zipfile.ZipFile(evil, "w") as z:
            z.writestr("../escape", b"no")
        out2 = self.root / "out2"
        out2.mkdir()
        r = bash(f'safe_extract_all "{evil}" "{out2}"; echo "rc=$?"')
        self.assertNotIn("rc=0", r.stdout)
        self.assertFalse((self.root / "escape").exists())

    def test_zip_symlink_rejected(self):
        p = self.root / "s.zip"
        with zipfile.ZipFile(p, "w") as z:
            zi = zipfile.ZipInfo("link")
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, "/etc/passwd")
        r = self.run_extract(p)
        self.assertNotIn("rc=0", r.stdout)
        self.assertEqual(list(self.out.iterdir()), [])


class ArchTests(unittest.TestCase):
    def test_supported(self):
        for m, want in (("x86_64", "amd64"), ("amd64", "amd64"),
                        ("aarch64", "arm64"), ("arm64", "arm64")):
            r = bash("safe_detect_arch", env={"SAFE_UNAME_M": m})
            self.assertEqual((r.returncode, r.stdout.strip()), (0, want), m)

    def test_unsupported_rejected(self):
        for m in ("armv7l", "i686", "riscv64", "ppc64le", ""):
            r = bash("safe_detect_arch", env={"SAFE_UNAME_M": m})
            self.assertNotEqual(r.returncode, 0, m)


class PinTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pins = Path(self.tmp.name) / "pins.conf"

    def get(self, key):
        return bash(f'safe_pin_get "{self.pins}" "{key}"', cwd=self.tmp.name)

    def test_reads_value(self):
        self.pins.write_text("# c\n\ngit:tool=" + "a" * 40 + "\ngo:x/y=v1.2.3\n")
        self.assertEqual(self.get("git:tool").stdout.strip(), "a" * 40)
        self.assertEqual(self.get("go:x/y").stdout.strip(), "v1.2.3")

    def test_missing_and_empty_are_absent(self):
        self.pins.write_text("go:empty=\n")
        self.assertNotEqual(self.get("go:empty").returncode, 0)
        self.assertNotEqual(self.get("go:none").returncode, 0)

    def test_missing_file_is_absent(self):
        self.assertNotEqual(self.get("anything").returncode, 0)

    def test_shell_metacharacters_are_never_executed(self):
        marker = Path(self.tmp.name) / "pwned"
        self.pins.write_text(
            f'bad1=$(touch {marker})\n'
            f'bad2=`touch {marker}`\n'
            f'bad3=a;touch {marker}\n'
            f'bad4="quoted"\n'
            f'bad5=a b\n'
        )
        for k in ("bad1", "bad2", "bad3", "bad4", "bad5"):
            r = self.get(k)
            self.assertNotEqual(r.returncode, 0, k)
        self.assertFalse(marker.exists())

    def test_symlinked_pin_file_refused(self):
        real = Path(self.tmp.name) / "real.conf"
        real.write_text("k=v1\n")
        self.pins.symlink_to(real)
        self.assertNotEqual(self.get("k").returncode, 0)

    def test_value_validators(self):
        self.assertEqual(bash(f'safe_is_commit {"a" * 40}').returncode, 0)
        self.assertNotEqual(bash('safe_is_commit main').returncode, 0)
        self.assertNotEqual(bash(f'safe_is_commit {"A" * 40}').returncode, 0)
        for ok in ("v1.2.3", "1.2.3", "v2.0.0-rc1"):
            self.assertEqual(bash(f'safe_is_version "{ok}"').returncode, 0, ok)
        for bad in ("latest", "", "v1;rm", "../x"):
            self.assertNotEqual(bash(f'safe_is_version "{bad}"').returncode, 0, bad)

    def test_allow_unpinned_flag(self):
        self.assertNotEqual(bash("safe_allow_unpinned").returncode, 0)
        self.assertEqual(bash("safe_allow_unpinned", env={"PNWC_ALLOW_UNPINNED": "1"}).returncode, 0)
        self.assertNotEqual(bash("safe_allow_unpinned", env={"PNWC_ALLOW_UNPINNED": "yes"}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
