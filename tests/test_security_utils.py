import os
import tempfile
import unittest
from pathlib import Path

import security_utils as su


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self, limit):
        return self.payload


class TestSecurityUtils(unittest.TestCase):
    def test_normalizes_safe_url_without_credentials(self):
        parsed = su.validate_url('https://example.com/path?q=1')
        self.assertEqual(parsed.scheme, 'https')
        self.assertEqual(parsed.netloc, 'example.com')

    def test_rejects_credentials_and_fragments(self):
        with self.assertRaises(ValueError):
            su.validate_url('https://user:pass@example.com/')
        with self.assertRaises(ValueError):
            su.validate_url('https://example.com/#fragment')

    def test_blocks_private_target_by_default(self):
        with self.assertRaises(ValueError):
            su.validate_url('https://127.0.0.1/')
        self.assertEqual(su.validate_url('https://127.0.0.1/', allow_private=True).hostname, '127.0.0.1')

    def test_bounds_remote_response(self):
        with self.assertRaises(ValueError):
            su.bounded_read(FakeResponse(b'01234567890'), limit=10)
        self.assertEqual(su.bounded_read(FakeResponse(b'0123'), limit=10), b'0123')

    def test_reads_regular_local_file_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'data.txt'
            path.write_text('safe', encoding='utf-8')
            self.assertEqual(su.read_local_file(path), b'safe')
            if hasattr(os, 'symlink'):
                link = Path(directory) / 'link.txt'
                os.symlink(path, link)
                with self.assertRaises(ValueError):
                    su.read_local_file(link)


if __name__ == '__main__':
    unittest.main()
