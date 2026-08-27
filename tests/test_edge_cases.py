import unittest
from app import analyze

class TestSubnetEdgeCases(unittest.TestCase):
    def test_handles_ipv6_without_broadcast(self):
        result = analyze({'cidr':'2001:db8::/126'})
        self.assertEqual(result['version'], 6)
        self.assertIsNone(result['broadcast_address'])
        self.assertEqual(result['total_addresses'], 4)

if __name__ == '__main__': unittest.main()
