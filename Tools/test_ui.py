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
    # Ask cargo where the test binary is; its directory layout changes between releases.
    built = subprocess.run(['cargo', 'test', '--locked', '--no-run', '--message-format=json'],
                           cwd=ROOT, capture_output=True, text=True)
    binaries = [Path(message['executable']) for message in map(json.loads, built.stdout.splitlines())
                if message.get('reason') == 'compiler-artifact' and message.get('executable')
                and message.get('profile', {}).get('test')]
    for binary in binaries:
        listed = subprocess.run([str(binary), '--list'], capture_output=True, text=True, timeout=5)
        if 'ui::tests::terminal_fixture: test' in listed.stdout:
            return binary
    raise RuntimeError('Run cargo test --locked --no-run first')


class Terminal:
    def __init__(self, home, columns=90, rows=24, truecolor=None):
        binary = test_binary()
        env = dict(os.environ, HOME=str(home), DOTT_UI_FIXTURE='1',
                   DOTT_NO_UPDATE_CHECK='1', TERM='xterm-256color')
        if truecolor is not None:
            env.pop('NO_COLOR', None)
            env['CLICOLOR_FORCE'] = '1'
            if truecolor:
                env['COLORTERM'] = 'truecolor'
            else:
                env.pop('COLORTERM', None)
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
                elif code == 'J':
                    if value == 2:
                        self.screen = [[' '] * self.columns for _ in range(self.rows)]
                    else:
                        self.screen[self.y][self.x:] = [' '] * (self.columns - self.x)
                        for row in range(self.y + 1, self.rows):
                            self.screen[row] = [' '] * self.columns
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
        self.expect('❯❯❯ ')
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
        t.expect(';7H')  # Inline prompt: margin, ❯❯❯, space.
        self.assertEqual(t.x, 6)
        t.send('abc')
        t.expect('❯❯❯ abc')
        t.expect(';10H')
        self.assertEqual(t.x, 9)
        t.send('\x1b[D')
        t.expect(';9H')
        self.assertEqual(t.x, 8)
        t.send('X\r')
        t.expect('INPUT:abXc')
        t.ready()

    def test_opens_on_a_clean_window_with_the_classic_banner_and_bottom_prompt(self):
        t = self.terminal
        t.expect(';7H')
        screen = [''.join(line).rstrip() for line in t.screen]
        logo = next(i for i, line in enumerate(screen) if line.startswith('  |____/'))
        self.assertIn('v', screen[logo])
        self.assertIn('  type a name and hit enter. /help for commands · esc to quit.', screen)
        # The prompt sits on the last row; the rows between are free for output.
        self.assertEqual(t.y, len(screen) - 1)
        self.assertEqual(screen[t.y].strip(), '❯❯❯')
        ready = screen.index('FIXTURE_READY')  # Printed by the test fixture.
        self.assertTrue(all(line == '' for line in screen[ready + 1:t.y]))
        for glyph in ['╭', '╰', '│']:
            self.assertNotIn(glyph, t.output)

    def test_menu_opens_above_the_bottom_prompt_and_keeps_finished_results(self):
        t = self.terminal
        t.send('show\r')
        t.ready()
        t.send('/')
        t.expect('enter select')
        screen = [''.join(line) for line in t.screen]
        prompt = next(i for i, line in enumerate(screen) if '❯❯❯ /' in line)
        menu = next(i for i, line in enumerate(screen) if 'Choose extensions' in line)
        self.assertLess(menu, prompt)
        self.assertEqual(prompt, len(screen) - 1)
        for domain in ['example.com', 'example.io', 'example.gg', 'example.dev']:
            self.assertIn(domain, '\n'.join(screen))
        t.position = len(t.output)
        t.send('\x1b')
        t.expect('❯❯❯ /')
        self.assertNotIn('Choose extensions', '\n'.join(''.join(line) for line in t.screen))

    def test_live_rows_spin_inline_below_the_query(self):
        t = self.terminal
        t.send('cancel\r')
        t.expect('example.com')
        screen = [''.join(line).rstrip() for line in t.screen]
        query = next(i for i, line in enumerate(screen) if line == '  ❯❯❯ cancel')
        row = next(i for i, line in enumerate(screen) if 'example.com' in line)
        self.assertEqual(row, query + 2)
        self.assertNotIn('Checking domains', t.output)
        t.send('\x1b')
        t.expect('CANCELLED')
        t.ready()

    def test_composer_is_a_plain_prompt_without_placeholder_or_footer(self):
        t = self.terminal
        for text in ['Search a name or type /', 'enter search', '╭']:
            self.assertNotIn(text, t.output)
        t.send('/')
        t.expect('Choose extensions')
        self.assertNotIn('\x1b[?1049', t.output)

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
        t.expect('❯❯❯ /wa')
        self.assertIn('Watch a domain', '\n'.join(''.join(row) for row in t.screen))
        self.assertNotIn('/tlds', '\n'.join(''.join(row) for row in t.screen))
        t.send('\r')
        t.expect('❯❯❯ /watch ')
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
        t.expect('❯❯❯ /')
        t.position = len(t.output)
        t.send('\x1b')
        t.expect('❯❯❯ /')
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

    def test_narrowing_keeps_results_and_the_prompt(self):
        t = self.terminal
        t.send('show\r')
        t.ready()
        t.expect(';7H')
        t.resize(60, 24)
        t.send('x')
        t.expect('❯❯❯ x')
        screen = [''.join(row).rstrip() for row in t.screen]
        for domain in ['example.com', 'example.io', 'example.gg', 'example.dev']:
            self.assertTrue(any(domain in line for line in screen), domain)
        self.assertEqual(screen[t.y], '  ❯❯❯ x')

    def test_tab_completes_without_submitting_and_word_editing_stays_local(self):
        t = self.terminal
        t.send('/he\t')
        t.expect('❯❯❯ /help')
        self.assertNotIn('INPUT:/help', t.output)
        t.send('\r')
        t.expect('INPUT:/help')
        t.ready()
        t.send('/wa\texample.com extra\x17\r')
        t.expect('ACTION:Watch("example.com ")')
        t.ready()
        self.assertFalse((self.home / '.dott/watchlist.json').exists())

    def test_extension_picker_scrolls_to_focus_and_keeps_apply_visible(self):
        t = self.terminal
        t.resize(28, 6)
        t.expect('❯❯❯ ')
        t.send('/tlds\r')
        t.expect('Choose extensions')
        t.send('\x1b[F')  # End focuses Apply, scrolling to the last grid row.
        t.expect('[Apply]')
        t.expect('space toggle')
        screen = '\n'.join(''.join(row) for row in t.screen)
        self.assertIn('[Apply]', screen)
        t.send('\x1b[H')
        t.expect('.com')
        t.send(' \r')
        t.expect('ACTION:Tlds(Some(["io"]))')
        t.ready()
        self.assertFalse((self.home / '.dott/extensions.json').exists())

    def test_pending_results_scroll_by_page_and_reflow_after_resize(self):
        t = self.terminal
        t.resize(50, 7)
        t.expect('❯❯❯ ')
        t.send('browse\r')
        t.expect('1–4/32')
        t.send('\x1b[6~')
        t.expect('5–8/32')
        t.send('\x1b[F')
        t.expect('29–32/32')
        t.resize(90, 12)
        t.expect('24–32/32')
        t.send('\x1b[H')
        t.expect('1–9/32')
        t.send('\x1b')
        t.expect('CANCELLED')
        t.ready()

    def test_escape_clears_typed_text_before_quitting(self):
        t = self.terminal
        t.send('example')
        t.expect('❯❯❯ example')
        t.send('\x1b')
        t.expect('esc again to quit')
        self.assertNotIn('example', '\n'.join(''.join(row) for row in t.screen[-4:]))
        t.send('\x1b')
        t.expect('FIXTURE_DONE')

    def test_ctrl_d_exits_an_empty_composer(self):
        self.terminal.send('\x04')
        self.terminal.expect('FIXTURE_DONE')

    def test_results_are_regular_text_without_tab_or_mouse_modes(self):
        t = self.terminal
        t.send('show\r')
        raw = t.ready()
        output = ANSI.sub('', raw)
        self.assertIn('example.com', output)
        self.assertIn('reg 2020-01-01  upd 2026-01-01  exp 2027-03-11', output)
        self.assertIn('$11.08 on Porkbun', output)
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
        t.expect('❯❯❯ ')
        t.send('show\r')
        output = ANSI.sub('', t.ready())
        self.assertIn('example.com', output)
        self.assertIn('example.io', output)
        self.assertIn('example.gg', output)
        self.assertIn('example.dev', output)

    def test_available_and_taken_stay_distinct_with_and_without_truecolor(self):
        for truecolor in [False, True]:
            with self.subTest(truecolor=truecolor):
                t = Terminal(self.home, truecolor=truecolor)
                try:
                    t.send('show\r')
                    output = t.ready()

                    def style(text):
                        match = re.search(r'\x1b\[([0-9;]+)m' + re.escape(text), output)
                        self.assertIsNotNone(match, text)
                        return [int(value) for value in match.group(1).split(';')]

                    available, taken = style('✓'), style('✗')
                    self.assertNotEqual(available, taken)
                    self.assertNotEqual(style('example.com'), style('example.io'))
                finally:
                    t.close()

    def test_escape_cancels_a_pending_search_and_returns_to_prompt(self):
        t = self.terminal
        t.send('cancel\r')
        t.expect('example.com')
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
