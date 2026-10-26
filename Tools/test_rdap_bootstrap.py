import unittest

from update_rdap_bootstrap import generate


class BootstrapTests(unittest.TestCase):
    def fixture(self, services):
        return {'publication': '2026-10-22T23:00:04Z', 'services': services}

    def test_directory_is_deterministic_and_preserves_paths(self):
        first = [(['zz', 'aa'], ['http://registry.test/rdap', 'https://registry.test/rdap']),
                 (['bb'], ['https://other.test/bb/v1/'])]
        a = generate(self.fixture(first))
        b = generate(self.fixture(list(reversed(first))))
        self.assertEqual(a, b)
        self.assertIn('&["aa", "zz"], "https://registry.test/rdap/"', a)
        self.assertIn('https://other.test/bb/v1/', a)

    def test_invalid_or_duplicate_tlds_are_rejected(self):
        for tld in ['bad.name', 'UPPER', '-bad', 'a' * 64, 'é']:
            with self.subTest(tld=tld), self.assertRaises(ValueError):
                generate(self.fixture([([tld], ['https://registry.test/'])]))
        with self.assertRaises(ValueError):
            generate(self.fixture([(['aa', 'aa'], ['https://registry.test/'])]))

    def test_invalid_routes_and_empty_directories_are_rejected(self):
        for url in ['file:///tmp/a', 'https://user:pass@registry.test/',
                    'https://registry.test/?domain=foo', 'https://registry.test/#fragment']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                generate(self.fixture([(['aa'], [url])]))
        for services in [[], [(['aa'], [])], [([], ['https://registry.test/'])]]:
            with self.assertRaises(ValueError):
                generate(self.fixture(services))
