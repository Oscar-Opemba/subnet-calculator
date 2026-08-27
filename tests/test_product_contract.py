import unittest

import app


class TestProductContract(unittest.TestCase):
    def test_analyzer_contract_returns_a_dictionary(self):
        result = app.analyze({})
        self.assertIsInstance(result, dict)

    def test_help_entrypoint_exists(self):
        self.assertTrue(callable(getattr(app, 'main', None)))


if __name__ == '__main__':
    unittest.main()
