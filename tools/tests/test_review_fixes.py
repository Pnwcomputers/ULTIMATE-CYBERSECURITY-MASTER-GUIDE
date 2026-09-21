"""Local fixtures only: no network, package installation, or hardware workloads."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


HW = module('hardware_fixture', 'HardwareTesting/py/full_hw_suite.py')
SDR = ROOT / 'SDR/nanovna/tools/s1pdiff.py'


class HardwareTests(unittest.TestCase):
    def test_storage_preserves_existing_file_even_when_command_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            old = os.getcwd()
            try:
                os.chdir(folder)
                sentinel = Path('testfile.fio')
                sentinel.write_text('existing user data')
                tester = HW.StorageTest()
                tester.run_cmd = lambda *a, **kw: ''
                tester.run()
                self.assertEqual(sentinel.read_text(), 'existing user data')
                self.assertEqual(list(Path('.').iterdir()), [sentinel])
            finally:
                os.chdir(old)

    def test_stream_failure_is_recorded(self):
        tester = HW.HardwareTester()
        _, timeout = tester.run_streaming(f'{shlex.quote(sys.executable)} -c "raise SystemExit(7)"', timeout=3)
        self.assertFalse(timeout)
        self.assertTrue(any('status 7' in e for e in tester.data['errors']))

    def test_timeout_stops_descendant_work(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'still-running'
            child = "import time,pathlib; time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
            tester = HW.HardwareTester()
            _, timed_out = tester.run_streaming(
                f'{shlex.quote(sys.executable)} -c {shlex.quote(child)}', timeout=1)
            self.assertTrue(timed_out)
            time.sleep(1.2)
            self.assertFalse(marker.exists())


class NanoVNATests(unittest.TestCase):
    def run_sweep(self, text, *args):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'input.s1p'
            p.write_text(text)
            return subprocess.run([sys.executable, str(SDR), 'analyze', str(p), *args], capture_output=True, text=True)

    def test_invalid_measurements_fail(self):
        for text in ('# Hz S RI R 50\n1 nan 0\n', '# Hz S RI R 0\n1 0 0\n',
                     '# Hz S RI R inf\n1 0 0\n', '# Hz S RI R bad\n1 0 0\n',
                     '# Hz S RI R 50\n1 0\n', '# Hz S RI R 50\n1 0 0\n1 0.1 0\n',
                     '# Hz S DB R 50\n1 100000 0\n'):
            with self.subTest(text=text):
                result = self.run_sweep(text)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_nonfinite_options_fail(self):
        result = self.run_sweep('# Hz S RI R 50\n1 0 0\n', '--swr-limit', 'nan')
        self.assertEqual(result.returncode, 3)

    def test_json_infinite_derived_result_is_null(self):
        result = self.run_sweep('# Hz S RI R 50\n1 1 0\n2 1 0\n3 1 0\n', '--format', 'json')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout, parse_constant=lambda value: self.fail(value))
        self.assertIsNone(data['resonance_vswr'])


class InstallerTests(unittest.TestCase):
    def shell(self, folder, body):
        prefix = f'ANYTHINGLLM_SOURCE_ONLY=1\n. {shlex.quote(str(ROOT / "installer.sh"))}\n'
        prefix += f'INSTALL_DIR={shlex.quote(folder)}\nAPPIMAGE_FILE=app\nAPPIMAGE_URL=fixture\n'
        prefix += 'arch=x86_64\nOLLAMA_VERSION=fixture\nOLLAMA_ENGINE_DIR="$INSTALL_DIR/engine"\n'
        return subprocess.run(['sh', '-c', prefix + body], capture_output=True, text=True)

    def test_failed_appimage_download_preserves_previous(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / 'app'
            p.write_text('old application')
            r = self.shell(folder, 'curl() { return 22; }; download_appimage')
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(p.read_text(), 'old application')
            self.assertEqual(list(Path(folder).iterdir()), [p])

    def test_appimage_publishes_only_valid_download(self):
        for valid in (False, True):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as folder:
                p = Path(folder) / 'app'
                p.write_text('old application')
                payload = "printf '\\177ELFfixture'" if valid else "printf 'error page'"
                body = 'curl() { while [ "$1" != -o ]; do shift; done; shift; ' + payload + ' > "$1"; }; download_appimage'
                r = self.shell(folder, body)
                self.assertEqual(r.returncode == 0, valid, r.stderr)
                self.assertEqual(p.read_bytes(), b'\x7fELFfixture' if valid else b'old application')

    def test_engine_failure_preserves_old_engine(self):
        for fail in ('download', 'extract', 'missing_binary'):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as folder:
                p = Path(folder) / 'engine'
                p.mkdir()
                (p / 'sentinel').write_text('working')
                body = 'zstd() { :; }; curl() { return ' + ('22' if fail == 'download' else '0') + '; }; '
                body += 'tar() { return ' + ('1' if fail == 'extract' else '0') + '; }; '
                body += 'if ! install_ollama_engine; then printf "CONTINUED\\n"; fi'
                r = self.shell(folder, body)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn('CONTINUED', r.stdout)
                self.assertEqual((p / 'sentinel').read_text(), 'working')
                self.assertEqual(list(Path(folder).iterdir()), [p])


class AdditionalInstallerTests(unittest.TestCase):
    shell = InstallerTests.shell

    def test_engine_publish_and_rollback(self):
        for fail_publish in (False, True):
            with self.subTest(fail_publish=fail_publish), tempfile.TemporaryDirectory() as folder:
                p = Path(folder) / 'engine'
                p.mkdir()
                (p / 'sentinel').write_text('working')
                body = '''
zstd() { :; }
curl() { :; }
tar() {
    while [ "$1" != -C ]; do shift; done
    shift
    mkdir -p "$1/bin"
    printf 'new engine' > "$1/bin/ollama"
}
'''
                if fail_publish:
                    body += '''mv() {
    case "$1" in */new) return 1 ;; esac
    command mv "$@"
}
'''
                body += 'install_ollama_engine'
                result = self.shell(folder, body)
                self.assertEqual(result.returncode == 0, not fail_publish, result.stderr)
                if fail_publish:
                    self.assertEqual((p / 'sentinel').read_text(), 'working')
                else:
                    self.assertEqual((p / 'bin/llm').read_text(), 'new engine')
                    self.assertEqual((p / '.ollama-version').read_text(), 'fixture')
                    self.assertFalse((p / 'sentinel').exists())
                self.assertEqual(list(Path(folder).iterdir()), [p])

    def test_missing_zstd_is_nonfatal_when_handled(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.shell(folder, 'command() { return 1; }; if ! install_ollama_engine; then printf "CONTINUED"; fi')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('CONTINUED', result.stdout)
            self.assertEqual(list(Path(folder).iterdir()), [])


class PackageManagerTests(unittest.TestCase):
    def test_arch_never_refreshes_metadata_separately(self):
        for answer in ('n', 'y'):
            with self.subTest(answer=answer):
                script = f'source {shlex.quote(str(ROOT / "Scripts/pnwc_install_tools.sh"))}\n'
                script += '''info() { :; }; warn() { :; }
PKG_MGR=pacman
pacman() { printf 'UNEXPECTED PACMAN'; return 99; }
pkg_update
'''
                result = subprocess.run(['bash', '-c', script], input=answer+'\n', text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, answer == 'y', result.stderr)
                self.assertNotIn('UNEXPECTED PACMAN', result.stdout)


if __name__ == '__main__':
    unittest.main()
