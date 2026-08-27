import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

import common
import security_utils as su


class FakeResponse:
    def read(self, limit):
        return b'ok'


class TestAbuseCases(unittest.TestCase):
    def test_http_method_and_timeout_are_rejected_before_network(self):
        with self.assertRaises(ValueError):
            su.open_no_redirect(Request('https://example.com', method='TRACE'))
        with self.assertRaises(ValueError):
            su.open_no_redirect(Request('https://example.com'), timeout=31)

    def test_origin_cannot_contain_path_or_query(self):
        with self.assertRaises(ValueError):
            su.valid_origin('https://example.com/path')
        with self.assertRaises(ValueError):
            su.valid_origin('https://example.com/?q=1')

    def test_private_dns_result_is_blocked(self):
        with patch('security_utils.socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 0))]):
            with self.assertRaises(ValueError):
                su.connect_tls('example.com', 443, object())

    def test_path_nul_and_file_limit_are_rejected(self):
        with self.assertRaises(ValueError):
            su.read_local_file('bad\x00path')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.txt'
            path.write_bytes(b'x' * 12)
            with self.assertRaises(ValueError):
                su.read_local_file(path, max_bytes=10)

    def test_response_limit_cannot_be_raised_arbitrarily(self):
        with self.assertRaises(ValueError):
            su.bounded_read(FakeResponse(), limit=su.MAX_RESPONSE_BYTES + 1)

    def test_html_output_escapes_untrusted_values(self):
        output = common.page('<script>alert(1)</script>', [('field', '<img>', 'text', '"x"')], common.render_json({'value': '<script>bad</script>'}))
        self.assertNotIn('<script>bad</script>', output)
        self.assertNotIn('<img>', output)


if __name__ == '__main__':
    unittest.main()
