#!/usr/bin/env python3
"""Explicit live watch test with isolated HOME and mocked macOS commands."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    if sys.platform != 'darwin':
        raise SystemExit('This smoke test exercises the macOS watch integration.')
    binary = Path(__file__).resolve().parents[1] / 'target/debug/dott'
    with tempfile.TemporaryDirectory(prefix='dott-watch-smoke-') as folder:
        root = Path(folder)
        commands = root / 'mock-bin'
        commands.mkdir()
        script = f'''#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(os.environ['HOME'])
name = pathlib.Path(sys.argv[0]).name
with (root / 'commands.jsonl').open('a') as log:
    log.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
if name == 'osascript' and os.environ.get('FAIL_NOTIFICATION'):
    print('simulated notification failure', file=sys.stderr)
    sys.exit(1)
if name == 'launchctl':
    state = root / 'loaded'
    if sys.argv[1] == 'list':
        sys.exit(0 if state.exists() else 113)
    if sys.argv[1] == 'load':
        state.touch()
    if sys.argv[1] == 'unload':
        state.unlink(missing_ok=True)
'''
        for name in ['launchctl', 'osascript', 'open']:
            command = commands / name
            command.write_text(script)
            command.chmod(0o755)
        env = dict(os.environ, HOME=str(root), DOTT_NO_UPDATE_CHECK='1',
                   PATH=str(commands) + os.pathsep + os.environ.get('PATH', ''))

        def run(*args, succeeds=True):
            result = subprocess.run([str(binary), *args], env=env, text=True,
                                    capture_output=True, timeout=90)
            assert (result.returncode == 0) == succeeds, (args, result.stdout, result.stderr)
            return result

        def notification_count():
            logs = [json.loads(line) for line in (root / 'commands.jsonl').read_text().splitlines()]
            return sum(row[0] == 'osascript' and 'now available' in row[-1] for row in logs)

        run('--watch', 'GOOGLE.COM')
        file = root / '.dott/watchlist.json'
        entries = json.loads(file.read_text())
        assert entries == [{'domain': 'google.com', 'last_status': 'taken'}], entries
        assert (root / 'loaded').exists()
        assert 'google.com' in run('--watching').stdout
        run('--watch', 'google.com')
        assert len(json.loads(file.read_text())) == 1
        print('New watch, list, normalization, duplicate protection, and scheduler setup passed.', flush=True)

        domain = f'dott-watch-probe-{time.time_ns()}.org'
        run('--watch', domain)
        entries = json.loads(file.read_text())
        assert entries[1]['last_status'] == 'available', entries
        # Simulate the previous observation being taken to exercise release alerts.
        entries[1]['last_status'] = 'taken'
        file.write_text(json.dumps(entries))
        run('--background-check')
        assert json.loads(file.read_text())[1]['last_status'] == 'available'
        assert notification_count() == 1
        run('--background-check')
        assert notification_count() == 1, 'unchanged availability notified twice'
        print('Live background lookup, availability transition, and duplicate-alert prevention passed.', flush=True)

        entries[1]['last_status'] = 'taken'
        file.write_text(json.dumps(entries))
        env['FAIL_NOTIFICATION'] = '1'
        result = run('--background-check', succeeds=False)
        assert 'simulated notification failure' in result.stderr
        assert json.loads(file.read_text())[1]['last_status'] == 'taken'
        del env['FAIL_NOTIFICATION']
        run('--background-check')
        assert json.loads(file.read_text())[1]['last_status'] == 'available'
        print('Failed notification was reported, preserved the prior status, and retried successfully.', flush=True)
        run('--unwatch', 'GOOGLE.COM')
        run('--unwatch', domain)
        assert json.loads(file.read_text()) == []
        run('--background-check')
        print('Unwatch and empty-list checks passed. Real watchlist, scheduler, and notifications untouched.', flush=True)


if __name__ == '__main__':
    main()
