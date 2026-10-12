"""R8: ssl_cert_audit.sh fetches the certificate once, keeps the evidence, and reports failures."""
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "OSINT" / "Playbook" / "scripts" / "ssl_cert_audit.sh"
BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(OPENSSL, "openssl not installed")
class SslAuditTests(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = Path(self._t.name)
        self.out = self.root / "out"
        self.out.mkdir()
        self.home = self.root / "home"
        self.home.mkdir()
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.stdin.close()
            self.server.kill()
            self.server.wait()
        self._t.cleanup()

    def start_server(self):
        key, crt = self.root / "k.pem", self.root / "c.pem"
        subprocess.run([OPENSSL, "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", str(key),
                        "-out", str(crt), "-subj", "/CN=scam.test/O=Example", "-days", "30"],
                       capture_output=True, check=True)
        self.crt = crt
        self.port = free_port()
        self.srv_path = self.root / "srv.log"
        with open(self.srv_path, "w") as log:
            self.server = subprocess.Popen(
                [OPENSSL, "s_server", "-accept", str(self.port), "-cert", str(crt), "-key", str(key)],
                stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)  # s_server exits on stdin EOF
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.3)
        self.baseline = self.srv_path.read_text().count("CIPHER is")  # readiness probe never handshakes

    def run_audit(self, host, port):
        snippet = (f'source "{SCRIPT}"; set +e; OUTPUT_DIR="{self.out}"; TIMESTAMP=T1; '
                   f'LOG_FILE="{self.out}/log.txt"; audit_cert "{host}" "{port}"')
        return subprocess.run([BASH, "-c", snippet], capture_output=True, text=True, errors="replace",
                              env={"PATH": os.environ["PATH"], "HOME": str(self.home), "TERM": "dumb",
                                   "LC_ALL": "C.UTF-8"})

    def test_single_handshake_and_consistent_fingerprint_with_saved_evidence(self):
        self.start_server()
        r = self.run_audit("127.0.0.1", self.port)
        base = self.out / f"cert_127.0.0.1_{self.port}_T1"
        out = r.stdout + r.stderr
        self.assertTrue(Path(f"{base}.pem").exists(), out)
        self.assertTrue(Path(f"{base}.s_client.txt").exists())
        self.assertIn("s_client exit status: 0", Path(f"{base}.err").read_text())
        expected = subprocess.run([OPENSSL, "x509", "-noout", "-fingerprint", "-sha256", "-in", str(self.crt)],
                                  capture_output=True, text=True).stdout.split("=", 1)[1].strip()
        self.assertIn(expected, out)
        self.assertIn("scam.test", out)
        time.sleep(0.3)
        handshakes = self.srv_path.read_text().count("CIPHER is") - self.baseline
        # one fetch + one liveness probe at most; never one per field (was 8+)
        self.assertLessEqual(handshakes, 2, f"saw {handshakes} handshakes")

    def test_unreachable_port_is_reported_with_error_file(self):
        r = self.run_audit("127.0.0.1", free_port())
        self.assertIn("No TLS certificate retrieved", r.stdout + r.stderr)
        errs = list(self.out.glob("cert_*.err"))
        self.assertTrue(errs and "s_client exit status" in errs[0].read_text())
        self.assertFalse(list(self.out.glob("*.pem")))

    def test_only_two_live_s_client_calls_remain(self):
        live = [ln for ln in SCRIPT.read_text().splitlines()
                if "openssl s_client" in ln and not ln.lstrip().startswith("#")]
        self.assertEqual(len(live), 2, live)  # fetch_cert + the liveness probe


if __name__ == "__main__":
    unittest.main()
