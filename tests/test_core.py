import unittest
from src.scanner.core import Scanner

class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = Scanner()

    def test_start_scan(self):
        result = self.scanner.start_scan()
        self.assertTrue(result)

    def test_stop_scan(self):
        self.scanner.start_scan()
        result = self.scanner.stop_scan()
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()