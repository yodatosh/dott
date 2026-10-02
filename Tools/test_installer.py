"""Exercise the real installer offline with fixture downloads and temporary paths."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.destination = self.root / 'installation with spaces'
        self.destination.mkdir()
        self.mock = self.root / 'commands'
        self.mock.mkdir()
        self.fixture = self.root / 'fixture'
        self.fixture.mkdir()
        binary = self.fixture / 'dott'
        binary.write_text("#!/bin/sh\necho 'dott 0.7.0'\n")
        binary.chmod(0o755)
        archive = self.fixture / 'archive.tar.gz'
        with tarfile.open(archive, 'w:gz') as bundle:
            bundle.add(binary, arcname='dott')
        (self.fixture / 'checksum').write_text(
            f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  dott-target.tar.gz\n')
        (self.fixture / 'release.json').write_text('{\n  "tag_name": "v0.7.0"\n}\n')
        curl = self.mock / 'curl'
        curl.write_text('''#!/bin/sh
set -eu
url=""
out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) shift; out="$1" ;;
    https://*) url="$1" ;;
  esac
  shift
done
case "$url" in
  */latest) cp "$DOTT_FIXTURE/release.json" "$out" ;;
  *.sha256) cp "$DOTT_FIXTURE/checksum" "$out" ;;
  *.tar.gz) cp "$DOTT_FIXTURE/archive.tar.gz" "$out" ;;
  *) exit 1 ;;
esac
''')
        curl.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{self.mock}:/usr/bin:/bin',
                        DOTT_INSTALL_DIR=str(self.destination), DOTT_FIXTURE=str(self.fixture))

    def run_installer(self):
        return subprocess.run(['sh', str(INSTALLER)], env=self.env, capture_output=True, text=True, timeout=20)

    def test_installs_updates_and_records_destination(self):
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.destination / '.dott-install').read_text().strip(),
                         str((self.destination / 'dott').resolve()))
        (self.destination / 'dott').write_text('old binary')
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('dott 0.7.0', (self.destination / 'dott').read_text())
        self.assertEqual(list(self.destination.glob('.dott-install.*')), [])

    def test_bad_checksum_preserves_existing_binary(self):
        (self.destination / 'dott').write_text('old binary')
        (self.fixture / 'checksum').write_text(f'{"0" * 64}  dott-target.tar.gz\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256 mismatch', result.stderr)
        self.assertEqual((self.destination / 'dott').read_text(), 'old binary')

    def test_refuses_to_overwrite_brew_symlink(self):
        cellar = self.root / 'Cellar/dott/0.6.9/bin'
        cellar.mkdir(parents=True)
        binary = cellar / 'dott'
        binary.write_text('old brew binary')
        (self.destination / 'dott').symlink_to(binary)
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary.read_text(), 'old brew binary')
        self.assertTrue((self.destination / 'dott').is_symlink())

    def test_mismatched_binary_version_preserves_old_copy(self):
        (self.destination / 'dott').write_text('old binary')
        (self.fixture / 'release.json').write_text('{\n  "tag_name": "v0.8.0"\n}\n')
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.destination / 'dott').read_text(), 'old binary')


if __name__ == '__main__':
    unittest.main()
