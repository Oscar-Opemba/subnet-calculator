import unittest
from urllib.request import Request

import common
import security_utils as su


class TestDeeperHardening(unittest.TestCase):
    def test_web_server_rejects_privileged_and_invalid_ports(self):
        with self.assertRaises(ValueError):
            common.serve('demo', [], lambda _values: {}, 80)
        with self.assertRaises(ValueError):
            common.serve('demo', [], lambda _values: {}, 70000)

    def test_request_body_limit_is_checked_before_dns(self):
        oversized = b'x' * (su.MAX_REQUEST_BODY + 1)
        with self.assertRaises(ValueError):
            su.open_no_redirect(Request('https://example.com', data=oversized, method='POST'))

    def test_request_header_count_limit(self):
        headers = {f'X-Test-{index}': '1' for index in range(common.MAX_HEADERS + 1)}
        self.assertFalse(common._valid_request_headers(headers))

    def test_request_method_allowlist_is_strict(self):
        with self.assertRaises(ValueError):
            su.open_no_redirect(Request('https://example.com', method='TRACE'))


if __name__ == '__main__':
    unittest.main()
