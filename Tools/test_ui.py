"""Deterministic terminal interaction tests; build Rust tests first (cargo test --no-run)."""
import json
import functools
import codecs
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import tempfile
import time
import unittest

if os.name != 'nt':
    import fcntl
    import pty
    import termios

ROOT = Path(__file__).resolve().parents[1]
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


@functools.cache
def test_binary():
    binaries = [p for p in (ROOT / 'target/debug/deps').glob('dott-*')
                if p.is_file() and '.' not in p.name and os.access(p, os.X_OK)]
    for binary in sorted(binaries, key=lambda p: p.stat().st_mtime, reverse=True):
        listed = subprocess.run([str(binary), '--list'], capture_output=True, text=True, timeout=5)
        if 'ui::tests::terminal_fixture: test' in listed.stdout:
            return binary
    raise RuntimeError('Run cargo test --locked --no-run first')


class Terminal:
    def __init__(self, home, columns=90, rows=24):
        binary = test_binary()
        env = dict(os.environ, HOME=str(home), DOTT_UI_FIXTURE='1',
                   DOTT_NO_UPDATE_CHECK='1', TERM='xterm-256color')
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            os.execve(str(binary), [str(binary), '--ignored', '--exact',
                                   'ui::tests::terminal_fixture', '--nocapture'], env)
        self.output = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
        self.pending = ''
        self.x = self.y = 0
        self.columns, self.rows = columns, rows
        self.screen = [[' '] * columns for _ in range(rows)]
        self.wrap = True
        self.position = 0
        self.closed = False
        self.resize(columns, rows)
        try:
            self.ready()
        except BaseException:
            self.close()
            raise

    def resize(self, columns, rows):
        self.columns, self.rows = columns, rows
        self.screen = [(line[:columns] + [' '] * columns)[:columns] for line in self.screen[:rows]]
        self.screen += [[' '] * columns for _ in range(rows - len(self.screen))]
        self.x, self.y = min(self.x, columns - 1), min(self.y, rows - 1)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
        os.kill(self.pid, signal.SIGWINCH)

    def consume(self, data):
        text = self.decoder.decode(data)
        self.output += text
        self.pending += text
        while self.pending:
            char = self.pending[0]
            if char == '\x1b':
                match = re.match(r'\x1b\[([0-?]*)([ -/]*)([@-~])', self.pending)
                if not match:
                    if len(self.pending) < 2 or self.pending.startswith('\x1b['):
                        return
                    self.pending = self.pending[2:]
                    continue
                raw, _, code = match.groups()
                self.pending = self.pending[match.end():]
                values = [int(v or 0) for v in raw.lstrip('?').split(';')]
                value = values[0]
                if code == 'n' and raw == '6':
                    self.send(f'\x1b[{self.y + 1};{self.x + 1}R')
                elif code in ('H', 'f'):
                    self.y = min(self.rows - 1, max(0, value - 1))
                    self.x = min(self.columns - 1, max(0, (values[1] if len(values) > 1 else 1) - 1))
                elif code == 'G':
                    self.x = min(self.columns - 1, max(0, value - 1))
                elif code == 'K':
                    start, end = (0, self.columns) if value == 2 else (self.x, self.columns)
                    self.screen[self.y][start:end] = [' '] * (end - start)
                elif code == 'A':
                    self.y = max(0, self.y - (value or 1))
                elif code == 'B':
                    self.y = min(self.rows - 1, self.y + (value or 1))
                elif code == 'h' and raw == '?7':
                    self.wrap = True
                elif code == 'l' and raw == '?7':
                    self.wrap = False
                continue
            self.pending = self.pending[1:]
            if char == '\r':
                self.x = 0
            elif char == '\n':
                self.y += 1
                if self.y >= self.rows:
                    self.screen.pop(0)
                    self.screen.append([' '] * self.columns)
                    self.y = self.rows - 1
            elif char >= ' ':
                self.screen[self.y][min(self.x, self.columns - 1)] = char
                self.x += 1
                if self.x >= self.columns:
                    if self.wrap:
                        self.x = 0
                        self.y = min(self.rows - 1, self.y + 1)
                    else:
                        self.x = self.columns - 1

    def send(self, text):
        os.write(self.master, text.encode())

    def expect(self, text, timeout=8):
        deadline = time.monotonic() + timeout
        while True:
            found = self.output.find(text, self.position)
            if found >= 0:
                captured = self.output[self.position:found + len(text)]
                self.position = found + len(text)
                return captured
            if time.monotonic() >= deadline:
                raise AssertionError(f'Terminal did not show {text!r}:\n{ANSI.sub("", self.output)}')
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    data = b''
                if not data:
                    raise AssertionError(f'Terminal ended before {text!r}:\n{self.output}')
                self.consume(data)

    def ready(self):
        captured = self.expect('FIXTURE_READY')
        self.expect('> ')
        return captured

    def close(self):
        if self.closed:
            return
        self.closed = True
        os.close(self.master)
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if os.waitpid(self.pid, os.WNOHANG)[0]:
                return
            time.sleep(0.02)
        raise AssertionError('PTY fixture did not exit after its terminal closed')


@unittest.skipIf(os.name == 'nt', 'PTY tests require macOS or Linux')
class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dott-ui-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.terminal = Terminal(self.home)
        self.addCleanup(self.terminal.close)

    def test_cursor_tracks_the_single_chevron_prompt_and_edited_text(self):
        t = self.terminal
        t.expect('\x1b[5G')  # Two spaces, >, one space: input starts in column 5.
        self.assertEqual(t.x, 4)
        t.send('abc')
        t.expect('> abc')
        t.expect('\x1b[8G')
        self.assertEqual(t.x, 7)
        t.send('\x1b[D')
        t.expect('\x1b[7G')
        self.assertEqual(t.x, 6)
        t.send('X\r')
        t.expect('INPUT:abXc')
        t.ready()

    def test_history_cursor_editing_clear_and_multiline_paste(self):
        t = self.terminal
        t.send('first\r')
        t.expect('INPUT:first')
        t.ready()
        t.send('draft\x1b[A\x1b[B\x1b[H\x1b[C\x1b[3~X\x1b[F\x7f\r')
        t.expect('INPUT:dXaf')
        t.ready()
        t.send('discard\x15\x1b[200~name\n/watch example.com\x1b[201~')
        t.expect('name /watch example.com')
        t.send('\r')
        t.expect('INPUT:name /watch example.com')
        t.ready()

    def test_slash_menu_opens_immediately_and_completes_domain_arguments(self):
        t = self.terminal
        t.send('/')
        t.expect('Choose extensions')
        self.assertNotIn('INPUT:/', t.output)
        t.send('wa')
        t.expect('> /wa')
        self.assertIn('Watch a domain', '\n'.join(''.join(row) for row in t.screen))
        self.assertNotIn('/tlds', '\n'.join(''.join(row) for row in t.screen))
        t.send('\r')
        t.expect('> /watch ')
        self.assertFalse((self.home / '.dott/watchlist.json').exists())
        t.send('example.si\r')
        t.expect('ACTION:Watch("example.si")')
        t.ready()
        self.assertFalse((self.home / 'Library/LaunchAgents').exists())

    def test_slash_menu_arrows_select_and_escape_only_dismisses_the_menu(self):
        t = self.terminal
        t.send('/re')
        t.expect('Retry inconclusive checks')
        t.send('\x1b[B\r')
        t.expect('ACTION:Retry')
        t.ready()
        t.send('/')
        t.expect('Choose extensions')
        t.expect('> /')
        t.position = len(t.output)
        t.send('\x1b')
        t.expect('> /')
        self.assertNotIn('Choose extensions', '\n'.join(''.join(row) for row in t.screen))
        t.send('\x15still-here\r')
        t.expect('INPUT:still-here')
        t.ready()

    def test_slash_menu_reflows_and_scrolls_without_switching_screens(self):
        t = self.terminal
        t.send('/')
        t.expect('enter select')
        t.resize(28, 6)
        t.expect('↑/↓ · enter · esc')
        t.send('\x1b[A')
        t.expect('/help')
        t.resize(90, 24)
        t.expect('Show help')
        t.send('\r')
        t.expect('INPUT:/help')
        t.ready()
        self.assertNotIn('Show help', '\n'.join(''.join(row) for row in t.screen))
        self.assertNotIn('\x1b[?1049', t.output)
        self.assertNotIn('\x1b[?1000h', t.output)

    def test_results_are_regular_text_without_tab_or_mouse_modes(self):
        t = self.terminal
        t.send('show\r')
        raw = t.ready()
        output = ANSI.sub('', raw)
        self.assertIn('1 available · 1 taken · 1 reserved · 1 inconclusive', output)
        self.assertIn('expires Mar 2027', output)
        self.assertIn('$11.08 first year', output)
        self.assertNotIn('$12.00', output)
        self.assertNotIn('Registered:', output)
        self.assertNotIn('price unavailable', output)
        self.assertIn('registry rate limited', output)
        self.assertIn('/retry to check that domain again', output)
        self.assertNotIn('[Copy]', output)
        self.assertNotIn('\x1b[?1049', t.output)
        for mode in ['1000', '1002', '1003', '1006']:
            self.assertNotIn(f'\x1b[?{mode}h', t.output)
        t.send('\tnew-query\r')
        t.expect('INPUT:new-query')
        t.ready()
        # Final output includes every row even when the live area cannot fit it.
        t.position = len(t.output)
        t.resize(90, 6)
        t.expect('> ')
        t.send('show\r')
        output = ANSI.sub('', t.ready())
        self.assertIn('example.com', output)
        self.assertIn('example.io', output)
        self.assertIn('example.gg', output)
        self.assertIn('example.dev', output)

    def test_escape_cancels_a_pending_search_and_returns_to_prompt(self):
        t = self.terminal
        t.send('cancel\r')
        t.expect('esc cancel')
        t.send('\t')
        t.send('\x1b')
        t.expect('CANCELLED')
        t.ready()
        t.send('still-here\r')
        t.expect('INPUT:still-here')

    def test_taken_since_last_check_uses_small_persisted_history(self):
        t = self.terminal
        t.send('show\r')
        t.ready()
        t.send('taken\r')
        output = t.ready()
        self.assertIn('example.com · taken since your last check', output)
        cache = self.home / '.dott/checks.json'
        data = json.loads(cache.read_text())
        self.assertEqual(data['domains']['example.com']['status'], 'taken')
        self.assertNotIn('example.gg', data['domains'])
        self.assertLess(cache.stat().st_size, 1024)
        t.send('taken\r')
        t.ready()
        lines = [''.join(row) for row in t.screen]
        latest = max(i for i, line in enumerate(lines) if 'example.com' in line)
        self.assertNotIn('taken since your last check', '\n'.join(lines[latest:]))



if __name__ == '__main__':
    unittest.main()
