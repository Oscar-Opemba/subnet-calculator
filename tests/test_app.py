import unittest
from app import analyze

class TestSubnet(unittest.TestCase):
    def test_ipv4_range(self):
        result = analyze({'cidr':'192.168.1.0/24'})
        self.assertEqual(result['usable_host_count'], 254)
        self.assertEqual(result['first_usable'], '192.168.1.1')

if __name__ == '__main__': unittest.main()
