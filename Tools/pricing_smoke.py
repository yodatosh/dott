#!/usr/bin/env python3
"""Explicit live terminal pricing check with an isolated cache."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import time


def main():
    binary = Path(__file__).resolve().parents[1] / 'target/debug/dott'
    with tempfile.TemporaryDirectory(prefix='dott-pricing-smoke-') as folder:
        root = Path(folder)
        env = dict(os.environ, HOME=str(root), DOTT_NO_UPDATE_CHECK='1')
        name = f'dott-price-probe-{time.time_ns()}'
        cache = root / '.dott/prices.json'

        def terminal():
            master, slave = pty.openpty()
            process = subprocess.Popen([str(binary), name, '--tlds', 'com,org'],
                                       stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)
            output = b''
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output += os.read(master, 65536)
                    except OSError:
                        break
                elif process.poll() is not None:
                    break
            if process.poll() is None:
                process.kill()
            process.wait()
            os.close(master)
            assert process.returncode == 0, output.decode(errors='replace')
            return output.decode(errors='replace')

        output = terminal()
        assert 'Porkbun' in output and 'est $' in output and 'renew/yr' in output, output
        data = json.loads(cache.read_text())
        assert 'com' in data['prices'] and 'org' in data['prices'], data
        print(f'Live Porkbun fetch and terminal estimates passed: {len(data["prices"])} supported TLD prices.', flush=True)
        original = cache.read_bytes()
        terminal()
        assert cache.read_bytes() == original, 'second session refreshed within 24 hours'
        print('Second terminal session reused the persisted cache without refreshing.', flush=True)
        # Simulate old saved prices and a failed refresh attempted today.
        now = int(time.time())
        data['attempted_at'] = now
        for price in data['prices'].values():
            price['fetched_at'] = now - 86401
        cache.write_text(json.dumps(data))
        original = cache.read_bytes()
        output = terminal()
        assert 'cached' in output and 'est $' in output, output
        assert cache.read_bytes() == original
        print('Saved-price fallback is labeled cached and does not retry a recent failed attempt.', flush=True)
        plain = subprocess.run([str(binary), name, '--tlds', 'com,org', '--plain'],
                               env=env, text=True, capture_output=True, timeout=90)
        assert plain.returncode == 0 and plain.stderr == '', plain
        assert len(plain.stdout.splitlines()) == 2
        assert 'est $' not in plain.stdout and 'Porkbun' not in plain.stdout
        assert cache.read_bytes() == original
        print('Plain output remained two domain/status rows and left the pricing cache untouched.', flush=True)


if __name__ == '__main__':
    main()
