import unittest

import app


class TestSubnetDomainHardening(unittest.TestCase):
    def test_large_network_skips_host_enumeration(self):
        result = app.analyze({'cidr': '10.0.0.0/8'})
        self.assertIsNone(result['first_usable'])
        self.assertIn('note', result)


if __name__ == '__main__': unittest.main()
