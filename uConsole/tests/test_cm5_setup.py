"""Run with python3 -m unittest discover -s uConsole/tests -v.

All mutations are confined to temporary fixtures. Never run the setup on this host.
"""
import pathlib
import subprocess
import tempfile
import unittest
import shlex

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'scripts/uconsole-cm5-setup.sh'

class SetupTests(unittest.TestCase):
    def shell(self, body, root):
        prefix = f'source {shlex.quote(str(SCRIPT))}\n'
        prefix += f'fixture={shlex.quote(str(root))}\n'
        prefix += '''LOG_FILE="$fixture/log"
STATE_DIR="$fixture/state"
STATE_FILE="$STATE_DIR/cm5-state"
VERSION_FILE="$STATE_DIR/cm5-version"
APT_DIR="$fixture/apt"
OS_RELEASE="$fixture/os-release"
MODEL_FILE="$fixture/model"
'''
        return subprocess.run(['bash', '-c', prefix + body], text=True, capture_output=True)

    def test_default_phases_do_not_run_commands_or_edit_desktop(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            sentinel = root / 'lightdm.conf'
            sentinel.write_text('user-session=vendor-desktop\n')
            r = self.shell('''run() { printf 'unexpected mutation' >&2; return 99; }
phase_preflight && phase_update && phase_kali_tools && phase_aio && phase_peripherals
''', root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn('unexpected mutation', r.stderr)
            self.assertEqual(sentinel.read_text(), 'user-session=vendor-desktop\n')

    def test_sources(self):
        examples = [
            ('kali.list', 'deb http://http.kali.org/kali kali-rolling main\n', False),
            ('mirror.list', 'deb https://mirror.example/os kali-rolling main\n', False),
            ('kali.sources', 'Types: deb\nURIs: https://mirror.example/os\nSuites:\n kali-rolling\n', False),
            ('kali.sources', 'Types: deb\nURIs: http://http.kali.org/kali\nSuites: kali-rolling\nEnabled: no\n', True),
            ('debian.list', '# deb http://http.kali.org/kali kali-rolling main\ndeb https://deb.debian.org/debian trixie main\n', True),
            ('multi.sources', 'Types: deb\nURIs: http://http.kali.org/kali\nEnabled: no\n\nTypes: deb\nURIs: https://mirror.example\nSuites: kali-rolling\n', False),
        ]
        for name, content, allowed in examples:
            with self.subTest(name=name, content=content), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                sources = root / 'apt/sources.list.d'
                sources.mkdir(parents=True)
                (sources / name).write_text(content)
                r = self.shell('check_debian_sources', root)
                self.assertEqual(r.returncode == 0, allowed, r.stderr)

    def test_os_version_validation(self):
        for release, expected in [('ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n', 'trixie'),
                                  ('ID=debian\nVERSION_ID=14\nVERSION_CODENAME=forky\n', None),
                                  ('ID=debian\nVERSION_ID=14\nVERSION_CODENAME=trixie\n', None),
                                  ('ID=kali\n', 'kali')]:
            with tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                (root / 'os-release').write_text(release)
                r = self.shell('detect_os', root)
                self.assertEqual(r.stdout.strip() if r.returncode == 0 else None, expected)

    def test_package_failure_stops_before_install(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.shell('''run() { printf '%s\n' "$*"; return 42; }
INSTALL_AIO=yes
phase_aio
''', pathlib.Path(d))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('APT::Update::Error-Mode=any update', r.stdout)
            self.assertNotIn('install', r.stdout)

    def test_main_failure_never_records_completion(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            r = self.shell('''preflight_checks() { :; }
backup_config() { :; }
phase_aio() { return 42; }
main --yes
''', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse((root / 'state/cm5-state').exists())
            self.assertNotIn('Phase: peripherals', r.stdout)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            r = self.shell('''preflight_checks() { :; }
main --dry-run --with-aio
''', root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('--no-remove install', r.stdout)
            self.assertEqual(list(root.iterdir()), [])

    def test_forced_phase_does_not_advance_state(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            r = self.shell('''preflight_checks() { :; }
backup_config() { :; }
main --phase=preflight --yes
''', root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertFalse((root / 'state/cm5-state').exists())

    def test_reset_and_dry_run_order(self):
        for options in ['--reset --dry-run', '--dry-run --reset']:
            with tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                (root / 'state').mkdir()
                (root / 'state/cm5-state').write_text('preflight\n')
                r = self.shell(f'main {options}', root)
                # Reset requires root; fixture tests run in the build container.
                if r.returncode != 0 and 'requires sudo' in r.stderr:
                    self.skipTest('reset test requires root')
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual((root / 'state/cm5-state').read_text(), 'preflight\n')
                self.assertEqual(len(list((root / 'state').iterdir())), 1)

    def test_preflight_guards_forced_and_legacy_runs(self):
        for mode in ['source', 'legacy', 'kali_on_debian']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                (root / 'os-release').write_text('ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n')
                (root / 'model').write_text('Raspberry Pi Compute Module 5 Rev 1.0')
                sources = root / 'apt/sources.list.d'
                sources.mkdir(parents=True)
                if mode == 'source':
                    (sources / 'kali.list').write_text('deb https://http.kali.org/kali kali-rolling main\n')
                elif mode == 'legacy':
                    (root / 'state').mkdir()
                    (root / 'state/cm5-state').write_text('update\n')
                flags = '--install-kali-tools' if mode == 'kali_on_debian' else ''
                r = self.shell('dpkg() { :; }\nmain --phase=aio --yes ' + flags, root)
                if r.returncode != 0 and 'Run with sudo' in r.stderr:
                    self.skipTest('preflight test requires root')
                self.assertNotEqual(r.returncode, 0)
                self.assertFalse((root / 'log').exists())
                self.assertNotIn('Phase: aio', r.stdout)

    def test_reject_shell_injection(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.shell("parse_args '--hostname=x;touch /tmp/should-not-exist'", pathlib.Path(d))
            self.assertNotEqual(r.returncode, 0)

if __name__ == '__main__':
    unittest.main()
