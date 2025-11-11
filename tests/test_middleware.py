import unittest
from unittest.mock import patch, MagicMock
from src.api.app import create_app
from src.api.middleware import BLOCKED_IPS, _request_counts


class TestProtectionMiddleware(unittest.TestCase):
    """Test the WAF-like protection middleware."""

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        # Clear global state before each test
        BLOCKED_IPS.clear()
        _request_counts.clear()

    def test_security_headers_present(self):
        """Test that security headers are added to responses."""
        response = self.client.get("/scan/status/123")
        
        # Check for security headers
        self.assertIn("X-Content-Type-Options", response.headers)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        
        self.assertIn("X-Frame-Options", response.headers)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        
        self.assertIn("Referrer-Policy", response.headers)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        
        self.assertIn("Content-Security-Policy", response.headers)

    def test_csp_header_content(self):
        """Test that CSP header has expected directives."""
        response = self.client.get("/scan/status/123")
        csp = response.headers.get("Content-Security-Policy", "")
        
        self.assertIn("default-src 'self'", csp)
        self.assertIn("img-src 'self' data:", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_response_has_status_codes(self):
        """Test that endpoints return expected status codes."""
        # Test /scan endpoint
        response = self.client.post(
            "/scan",
            json={"target": "https://example.com"}
        )
        self.assertEqual(response.status_code, 202)  # Accepted
        
        # Test status endpoint
        response = self.client.get("/scan/status/123")
        self.assertEqual(response.status_code, 200)

    def test_app_creates_successfully(self):
        """Test that the app initializes with middleware without errors."""
        self.assertIsNotNone(self.app)
        self.assertTrue(self.app.debug is False or self.app.debug is True)

    def test_security_headers_on_all_responses(self):
        """Test that security headers are present on multiple endpoints."""
        endpoints = [
            ("/scan/status/123", "GET"),
            ("/scan/results/123", "GET"),
        ]
        
        for endpoint, method in endpoints:
            if method == "GET":
                response = self.client.get(endpoint)
            else:
                response = self.client.post(endpoint, json={})
            
            # All should have security headers
            self.assertIn("X-Content-Type-Options", response.headers)
            self.assertIn("X-Frame-Options", response.headers)
            self.assertIn("Content-Security-Policy", response.headers)


class TestMiddlewareIntegration(unittest.TestCase):
    """Integration tests for middleware with the Flask app."""

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_json_response_has_headers(self):
        """Test that JSON responses also include security headers."""
        response = self.client.post(
            "/scan",
            json={"target": "https://example.com"}
        )
        
        # Should be JSON
        self.assertTrue(response.is_json)
        
        # Should have security headers
        self.assertIn("X-Content-Type-Options", response.headers)


if __name__ == "__main__":
    unittest.main()
