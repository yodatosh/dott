import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import release


class ReleaseTests(unittest.TestCase):
    def test_version_and_lock_must_match_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Cargo.toml').write_text('[package]\nname = "dott"\nversion = "0.7.0"\n')
            lock = root / 'Cargo.lock'
            lock.write_text('[[package]]\nname = "dott"\nversion = "0.7.0"\n')
            self.assertEqual(release.validate_version('v0.7.0', root), '0.7.0')
            self.assertEqual(release.validate_version('v0.7.0', root, 'v0.6.9'), '0.7.0')
            for previous in ['v0.7.0', 'v0.8.0', 'v0.7.0-rc.1']:
                with self.assertRaises(ValueError):
                    release.validate_version('v0.7.0', root, previous)
            for tag in ['v0.6.9', '0.7.0', 'v0.7.0-rc.1', 'v0.7.0.1']:
                with self.assertRaises(ValueError):
                    release.validate_version(tag, root)
            lock.write_text('[[package]]\nname = "dott"\nversion = "0.6.9"\n')
            with self.assertRaises(ValueError):
                release.validate_version('v0.7.0', root)

    def test_all_assets_required_and_checksums_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target in release.TARGETS:
                archive = root / f'dott-{target}.tar.gz'
                with tarfile.open(archive, 'w:gz') as bundle:
                    info = tarfile.TarInfo('dott')
                    info.size = 6
                    info.mode = 0o755
                    bundle.addfile(info, io.BytesIO(b'binary'))
                (root / f'{archive.name}.sha256').write_text(
                    f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
            sums = release.verify_assets(root)
            formula = release.formula('0.7.0', 'yodatosh/dott', sums)
            self.assertEqual(formula.count('/releases/download/v0.7.0/'), 4)
            self.assertIn('dott 0.7.0', formula)
            first = root / f'dott-{release.TARGETS[0]}.tar.gz'
            first.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                release.verify_assets(root)

    def test_archive_cannot_contain_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = release.TARGETS[0]
            archive = root / f'dott-{target}.tar.gz'
            with tarfile.open(archive, 'w:gz') as bundle:
                info = tarfile.TarInfo('dott')
                info.type = tarfile.SYMTYPE
                info.linkname = '/tmp/other'
                bundle.addfile(info)
            (root / f'{archive.name}.sha256').write_text(
                f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
            with self.assertRaises(ValueError):
                release.verify_assets(root)


if __name__ == '__main__':
    unittest.main()
