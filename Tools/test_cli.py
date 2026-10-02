"""Local CLI smoke tests; require cargo build first and never query registries."""
import os
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

BINARY = Path(__file__).resolve().parents[1] / 'target/debug/dott'


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.exists():
            raise RuntimeError('Run cargo build --locked before running CLI tests')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, HOME=str(self.root), DOTT_NO_UPDATE_CHECK='1')

    def run_cli(self, *args, input=''):
        return subprocess.run([str(BINARY), *args], input=input, env=self.env,
                              capture_output=True, text=True, timeout=5)

    def test_version_and_help(self):
        import release
        result = self.run_cli('--version')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f'dott {release.validate_version()}')
        self.assertIn('--update', self.run_cli('--help').stdout)

    def test_invalid_search_and_tlds_do_not_emit_result_rows(self):
        for args in [('name.invalid', '--plain'), ('name', '--tlds', 'com,invalid'),
                     ('not a name', '--plain')]:
            result = self.run_cli(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertIn('dott:', result.stderr)
        self.assertFalse((self.root / '.dott/update-check.json').exists())
        self.assertFalse((self.root / '.dott/prices.json').exists())

    def test_empty_pipe_has_no_banner(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')
        self.assertFalse((self.root / '.dott/prices.json').exists())

    def test_update_rejects_other_actions_and_source_installations(self):
        result = self.run_cli('--update', '--watch', 'example.com')
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / '.dott').exists())
        result = self.run_cli('--update')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Reinstall with: curl', result.stderr)

    def test_corrupt_watchlist_is_preserved(self):
        folder = self.root / '.dott'
        folder.mkdir()
        file = folder / 'watchlist.json'
        file.write_text('corrupt json')
        result = self.run_cli('--watching')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Could not read watchlist', result.stderr)
        self.assertEqual(file.read_text(), 'corrupt json')

    def test_background_skips_unsupported_legacy_entries(self):
        folder = self.root / '.dott'
        folder.mkdir()
        file = folder / 'watchlist.json'
        data = '[{"domain":"example.invalid","last_status":"taken"}]'
        file.write_text(data)
        result = self.run_cli('--background-check')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(file.read_text(), data)
        self.assertFalse((folder / 'update-check.json').exists())
        self.assertFalse((folder / 'prices.json').exists())

    def seed_watchlist(self):
        file = self.root / '.dott/watchlist.json'
        file.parent.mkdir()
        file.write_text('[{"domain":"example.com","last_status":"taken"}]')
        return file

    def mock_scheduler(self):
        folder = self.root / 'mock-bin'
        folder.mkdir()
        command = folder / 'launchctl'
        command.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(os.environ['HOME'])
with (root / 'commands.jsonl').open('a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
state = root / 'loaded'
action = sys.argv[1]
if action == 'list':
    sys.exit(0 if state.exists() else 113)
if action == 'load':
    if os.environ.get('FAIL_LOAD'):
        print('mock load failed', file=sys.stderr)
        sys.exit(1)
    state.touch()
elif action == 'unload':
    state.unlink(missing_ok=True)
''')
        command.chmod(0o755)
        self.env['PATH'] = str(folder) + os.pathsep + self.env.get('PATH', '')

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS scheduler')
    def test_repeated_watch_repairs_unloaded_agent_without_duplicate_entries(self):
        file = self.seed_watchlist()
        original = file.read_text()
        self.mock_scheduler()
        result = self.run_cli('--watch', 'EXAMPLE.COM')
        self.assertEqual(result.returncode, 0, result.stderr)
        plist = self.root / 'Library/LaunchAgents/com.dott.watch.plist'
        import plistlib
        data = plistlib.loads(plist.read_bytes())
        self.assertEqual(data['ProgramArguments'], [str(BINARY.resolve()), '--background-check'])
        self.assertEqual(data['StartCalendarInterval'], {'Hour': 9, 'Minute': 0})
        self.assertEqual(file.read_text(), original)
        (self.root / 'loaded').unlink()
        result = self.run_cli('--watch', 'example.com')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'loaded').exists())
        commands = [json.loads(line)[0] for line in (self.root / 'commands.jsonl').read_text().splitlines()]
        self.assertEqual(commands.count('load'), 2)
        result = self.run_cli('--watch', 'example.com')
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = [json.loads(line)[0] for line in (self.root / 'commands.jsonl').read_text().splitlines()]
        self.assertEqual(commands.count('load'), 2, 'loaded job must not be reloaded')

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS scheduler')
    def test_watch_reports_scheduler_failure_and_preserves_entries(self):
        file = self.seed_watchlist()
        original = file.read_text()
        self.mock_scheduler()
        self.env['FAIL_LOAD'] = '1'
        result = self.run_cli('--watch', 'example.com')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mock load failed', result.stderr)
        self.assertEqual(file.read_text(), original)

    def test_unwatch_normalizes_domain_and_preserves_other_entries(self):
        file = self.seed_watchlist()
        entries = json.loads(file.read_text())
        entries.append({'domain': 'python.org', 'last_status': 'taken'})
        file.write_text(json.dumps(entries))
        result = self.run_cli('--unwatch', ' EXAMPLE.COM ')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(file.read_text()), entries[1:])
        result = self.run_cli('--unwatch', 'example.com')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('not in watchlist', result.stdout)

    @unittest.skipIf(sys.platform == 'win32', 'uses POSIX flock to hold the app lock')
    def test_unwatch_waits_for_another_process_and_reads_its_latest_changes(self):
        import fcntl
        import time
        file = self.seed_watchlist()
        with file.with_suffix('.lock').open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            process = subprocess.Popen([str(BINARY), '--unwatch', 'example.com'], env=self.env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                time.sleep(0.3)
                self.assertIsNone(process.poll(), 'unwatch must wait for the transaction lock')
                entries = json.loads(file.read_text())
                entries.append({'domain': 'python.org', 'last_status': 'taken'})
                file.write_text(json.dumps(entries))
                fcntl.flock(lock, fcntl.LOCK_UN)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
                self.assertEqual(json.loads(file.read_text()), entries[1:])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()


if __name__ == '__main__':
    unittest.main()
