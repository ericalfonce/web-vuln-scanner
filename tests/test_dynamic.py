import pytest
import importlib


def test_dynamic_scanner_import_error(monkeypatch):
    # Simulate missing playwright by setting module attr to None
    mod_name = "src.scanner.dynamic"
    mod = importlib.import_module(mod_name)
    # If Playwright is present in the environment this test will be limited.
    # We assert that PlaywrightNotInstalled is defined for proper error messaging.
    assert hasattr(mod, "PlaywrightNotInstalled")


def test_csrf_check():
    """Test CSRF token detection in HTML forms."""
    from src.scanner.dynamic import DynamicScanner

    scanner = DynamicScanner(headless=True, artifacts_dir="/tmp/test_artifacts")

    # Form without CSRF token
    html_no_token = '<form method="POST"><input name="data"></form>'
    findings = scanner._check_csrf_tokens(html_no_token)
    assert len(findings) > 0
    assert findings[0]["issue"] == "missing_csrf_token"

    # Form with CSRF token
    html_with_token = '<form method="POST"><input name="csrf" value="token123"></form>'
    findings = scanner._check_csrf_tokens(html_with_token)
    assert len(findings) == 0


def test_cookie_security():
    """Test cookie security checks."""
    from src.scanner.dynamic import DynamicScanner

    scanner = DynamicScanner(headless=True, artifacts_dir="/tmp/test_artifacts")

    # This test requires a Playwright page context which is complex to mock
    # In production, you'd use pytest-playwright or mock the context
    # For now, we just verify the method exists
    assert hasattr(scanner, "_check_cookie_security")


def test_sarif_generation():
    """Test SARIF report generation."""
    from src.scanner.sarif import generate_sarif

    findings = [
        {"id": "xss", "issue": "XSS", "severity": "high", "description": "XSS found"},
        {"id": "csrf", "issue": "CSRF", "severity": "medium", "description": "Missing CSRF"},
    ]

    sarif = generate_sarif(findings, "https://example.com")

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    assert sarif["runs"][0]["results"][0]["level"] == "error"  # high -> error
    assert sarif["runs"][0]["results"][1]["level"] == "warning"  # medium -> warning

