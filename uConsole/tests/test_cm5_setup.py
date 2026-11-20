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
HOSTS_FILE="$fixture/hosts"
CONFIG_TXT="$fixture/config.txt"
CMDLINE_TXT="$fixture/cmdline.txt"
SYS_ROOT="$fixture/sys"
DEV_ROOT="$fixture/dev"
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

GOOD_CONFIG = """# Rex-style layout
[cm4]
dtparam=pciex1=off
[all]
dtparam=uart0
dtoverlay=spi1-1cs
dtparam=rtc=off
dtoverlay=i2c-rtc,pcf85063a,i2c_csi_dsi0
dtparam=pciex1
"""


class HardwareCheckTests(unittest.TestCase):
    shell = SetupTests.shell

    def fixture(self, root, config=GOOD_CONFIG, cmdline='console=tty1 root=PARTUUID=x\n'):
        (root / 'model').write_text('Raspberry Pi Compute Module 5 Rev 1.0')
        (root / 'config.txt').write_text(config)
        (root / 'cmdline.txt').write_text(cmdline)
        (root / 'dev').mkdir()
        for node in ('ttyAMA0', 'spidev1.0'):
            (root / 'dev' / node).write_text('')
        rtc = root / 'sys/class/rtc/rtc0'
        rtc.mkdir(parents=True)
        (rtc / 'name').write_text('rtc-pcf85063\n')
        nvme = root / 'sys/class/nvme/nvme0'
        nvme.mkdir(parents=True)
        (nvme / 'model').write_text('Test NVMe  \n')
        usb = root / 'sys/bus/usb/devices/1-1'
        usb.mkdir(parents=True)
        (usb / 'idVendor').write_text('0bda\n')
        (usb / 'idProduct').write_text('2838\n')
        bat = root / 'sys/class/power_supply/axp20x-battery'
        bat.mkdir(parents=True)
        for name, value in (('capacity', '80'), ('status', 'Discharging'), ('voltage_now', '3900000')):
            (bat / name).write_text(value + '\n')

    def snapshot(self, root):
        return {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}

    def test_good_configuration_passes_without_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root)
            before = self.snapshot(root)
            r = self.shell('main --hw-check', root)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn('[FAIL]', r.stdout)
            self.assertIn('NVMe controller: Test NVMe', r.stdout)
            self.assertEqual(before, self.snapshot(root))

    def test_config_parser_error_fails_the_hardware_report(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root)
            r = self.shell('check_config_txt() { return 2; }\nmain --hw-check', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('[FAIL] Could not evaluate', r.stdout)

    def test_rex_pciex1_off_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root, GOOD_CONFIG.replace('dtparam=pciex1\n', 'dtparam=pciex1=off\n'))
            r = self.shell('main --hw-check', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('pciex1=off', r.stdout)

    def test_lines_under_other_model_filters_are_ignored(self):
        config = '[cm4]\ndtparam=uart0\ndtoverlay=spi1-1cs\n[all]\n'
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root, config)
            r = self.shell('check_config_txt', root)
            self.assertIn('[FAIL] GPS UART', r.stdout)
            self.assertIn('[FAIL] LoRa SPI1', r.stdout)

    def test_cm5_filter_and_combined_dtparams_apply(self):
        config = ('[cm5]\ndtparam=uart0=on,rtc=off,pciex1\ndtoverlay=spi1-1cs\n'
                  'dtoverlay=i2c-rtc,i2c_csi_dsi0,pcf85063a\n')
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root, config)
            r = self.shell('check_config_txt', root)
            self.assertNotIn('[FAIL]', r.stdout)

    def test_console_on_gps_uart_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            self.fixture(root, cmdline='console=ttyAMA0,115200 console=tty1\n')
            r = self.shell('main --hw-check', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('console=ttyAMA0', r.stdout)


class SafetyFixTests(unittest.TestCase):
    shell = SetupTests.shell

    def test_v14_state_is_not_treated_as_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'os-release').write_text('ID=kali\n')
            (root / 'model').write_text('Raspberry Pi Compute Module 5 Rev 1.0')
            (root / 'state').mkdir()
            (root / 'state/cm5-state').write_text('finalize\n')
            (root / 'state/cm5-version').write_text('1.4\n')
            if __import__('os').geteuid() != 0:
                self.skipTest('preflight test requires root')
            r = self.shell('dpkg() { :; }\npreflight_checks', root)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_hostname_updates_hosts_entry(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'hosts').write_text('127.0.0.1\tlocalhost\n127.0.1.1\tclockworkpi\n')
            r = self.shell('HOSTNAME_NEW=field-uc5\nrun() { "$@"; }\nupdate_hosts_entry', root)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((root / 'hosts').read_text(), '127.0.0.1\tlocalhost\n127.0.1.1\tfield-uc5\n')

    def test_wifi_dkms_refused_off_kali(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / 'os-release').write_text('ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n')
            r = self.shell('run() { printf "unexpected\\n"; }\nINSTALL_WIFI_DKMS=yes\nphase_peripherals', root)
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn('unexpected', r.stdout)


if __name__ == '__main__':
    unittest.main()
