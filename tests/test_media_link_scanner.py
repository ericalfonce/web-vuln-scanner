import unittest
from unittest.mock import patch
from src.scanner.plugins.media_link_scanner import MediaLinkScanner


class TestMediaLinkScanner(unittest.TestCase):
    """Test the media/link scanner plugin."""

    def setUp(self):
        self.scanner = MediaLinkScanner()

    def test_extract_links_from_html(self):
        """Test extracting links from HTML content."""
        html = '''
        <html>
            <a href="https://example.com">Link</a>
            <img src="https://example.com/image.jpg" />
            <script src="http://unsafe.com/script.js"></script>
        </html>
        '''
        links = self.scanner._extract_links(html)
        self.assertEqual(len(links), 3)
        self.assertIn("https://example.com", links)
        self.assertIn("https://example.com/image.jpg", links)
        self.assertIn("http://unsafe.com/script.js", links)

    def test_insecure_protocol_detection(self):
        """Test detection of insecure HTTP links."""
        self.assertTrue(self.scanner._is_insecure("http://unsafe.com"))
        self.assertFalse(self.scanner._is_insecure("https://safe.com"))

    def test_suspicious_domain_detection(self):
        """Test detection of suspicious domains in watchlist."""
        self.assertTrue(self.scanner._is_suspicious("https://malicious.test/page"))
        self.assertTrue(self.scanner._is_suspicious("bad.example"))
        self.assertFalse(self.scanner._is_suspicious("https://legitimate.com"))

    def test_scan_with_html_content(self):
        """Test scanning raw HTML content for vulnerabilities."""
        html = '''
        <html>
            <a href="http://insecure.com">Bad Link</a>
            <a href="https://malicious.test">Bad Domain</a>
            <a href="https://safe.com">Good Link</a>
        </html>
        '''
        result = self.scanner.scan(html)
        self.assertIn("vulnerabilities", result)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find 2 issues (insecure + suspicious domain)
        self.assertGreaterEqual(len(vulnerabilities), 2)
        
        # Check for insecure protocol
        insecure_found = any(
            v.get("issue") == "insecure_protocol" for v in vulnerabilities
        )
        self.assertTrue(insecure_found)
        
        # Check for suspicious domain
        suspicious_found = any(
            v.get("issue") == "suspicious_domain" for v in vulnerabilities
        )
        self.assertTrue(suspicious_found)

    @patch("src.scanner.plugins.media_link_scanner.network.make_get_request")
    def test_scan_with_url(self, mock_get_request):
        """Test scanning a URL (fetches and parses the content)."""
        mock_html = '<a href="http://bad.com">Link</a>'
        mock_get_request.return_value = mock_html
        
        result = self.scanner.scan("https://example.com")
        self.assertIn("vulnerabilities", result)
        mock_get_request.assert_called_once_with("https://example.com")

    @patch("src.scanner.plugins.media_link_scanner.network.make_get_request")
    def test_scan_unreachable_url(self, mock_get_request):
        """Test handling of unreachable URL during scan."""
        mock_get_request.return_value = None
        
        result = self.scanner.scan("https://unreachable.com")
        self.assertIn("vulnerabilities", result)
        vulnerabilities = result["vulnerabilities"]
        
        # Should have an unreachable finding
        unreachable_found = any(
            v.get("issue") == "unreachable" for v in vulnerabilities
        )
        self.assertTrue(unreachable_found)

    def test_scan_empty_html(self):
        """Test scanning empty HTML returns no vulnerabilities."""
        result = self.scanner.scan("<html></html>")
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)

    def test_link_severity_levels(self):
        """Test that findings have appropriate severity levels."""
        html = '''
        <a href="http://bad.com">Bad</a>
        <a href="https://malicious.test">Malicious</a>
        <a href="https://safe.com">Safe</a>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Insecure protocol should be medium severity
        insecure = next(
            (v for v in vulnerabilities if v.get("issue") == "insecure_protocol"),
            None
        )
        if insecure:
            self.assertEqual(insecure.get("severity"), "medium")
        
        # Suspicious domain should be high severity
        suspicious = next(
            (v for v in vulnerabilities if v.get("issue") == "suspicious_domain"),
            None
        )
        if suspicious:
            self.assertEqual(suspicious.get("severity"), "high")


if __name__ == "__main__":
    unittest.main()
