import unittest
from src.scanner.engine import Engine

class TestEngine(unittest.TestCase):

    def setUp(self):
        self.engine = Engine()

    def test_run_scan(self):
        result = self.engine.run_scan("http://example.com")
        self.assertIsNotNone(result)
        self.assertIn("vulnerabilities", result)

    def test_load_plugins(self):
        plugins = self.engine.load_plugins()
        self.assertGreater(len(plugins), 0)

if __name__ == '__main__':
    unittest.main()