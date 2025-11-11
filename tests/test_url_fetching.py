import unittest
from unittest.mock import patch

from src.scanner.plugins.csrf_scanner import CSRFScanner
from src.scanner.plugins.auth_flaws_scanner import AuthenticationFlawsScanner
from src.scanner.plugins.insecure_deserialization_scanner import InsecureDeserializationScanner


class TestURLFetchingScanners(unittest.TestCase):
    """Mock-based tests to validate URL-fetching code paths in scanners."""

    @patch("src.utils.network.make_get_request")
    def test_csrf_scanner_fetches_url_and_detects_missing_token(self, mock_get):
        html = '<form method="POST" action="/submit"><input name="user" /></form>'
        mock_get.return_value = html

        scanner = CSRFScanner()
        result = scanner.scan("http://example.com/page")
        vulnerabilities = result["vulnerabilities"]

        self.assertTrue(any(v.get("issue") == "missing_csrf_token" for v in vulnerabilities))

    @patch("src.utils.network.make_get_request")
    def test_auth_scanner_fetches_url_and_detects_default_creds(self, mock_get):
        content = 'admin_user: "admin", admin_password: "admin"'
        mock_get.return_value = content

        scanner = AuthenticationFlawsScanner()
        result = scanner.scan("https://example.com/config")
        vulnerabilities = result["vulnerabilities"]

        self.assertTrue(any(v.get("issue") == "default_credentials" for v in vulnerabilities))

    @patch("src.utils.network.make_get_request")
    def test_deserialization_scanner_fetches_code_and_detects_pickle(self, mock_get):
        code = 'data = request.POST["data"]\nobj = pickle.loads(data)'
        mock_get.return_value = code

        scanner = InsecureDeserializationScanner()
        result = scanner.scan("https://example.com/api/deserialize")
        vulnerabilities = result["vulnerabilities"]

        self.assertTrue(any(v.get("issue") == "unsafe_pickle" for v in vulnerabilities))

    @patch("src.utils.network.make_get_request")
    def test_scanner_handles_unreachable_url(self, mock_get):
        mock_get.return_value = None

        scanner = CSRFScanner()
        result = scanner.scan("https://example.com/notfound")
        # Should return a finding about unreachable resource OR an empty list
        self.assertIn("vulnerabilities", result)
        self.assertTrue(isinstance(result["vulnerabilities"], list))


if __name__ == "__main__":
    unittest.main()
