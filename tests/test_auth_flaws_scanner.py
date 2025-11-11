import unittest
from src.scanner.plugins.auth_flaws_scanner import AuthenticationFlawsScanner


class TestAuthenticationFlawsScanner(unittest.TestCase):
    """Test authentication flaws scanner."""

    def setUp(self):
        self.scanner = AuthenticationFlawsScanner()

    def test_detect_weak_password_minlength(self):
        """Test detection of weak password minimum length."""
        html = '<input type="password" name="password" minlength="2" />'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        weak_pwd_issues = [v for v in vulnerabilities if v.get("issue") == "weak_password_requirement"]
        self.assertGreater(len(weak_pwd_issues), 0)

    def test_detect_password_over_get(self):
        """Test detection of password field in GET form."""
        html = '''
        <form method="GET">
            <input type="password" name="password" />
        </form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        get_pwd_issues = [v for v in vulnerabilities if v.get("issue") == "password_over_get"]
        self.assertGreater(len(get_pwd_issues), 0)

    def test_detect_password_over_http(self):
        """Test detection of password form on HTTP."""
        html = 'http://example.com/login?password=secret'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        http_pwd_issues = [v for v in vulnerabilities if v.get("issue") == "password_over_http"]
        self.assertGreater(len(http_pwd_issues), 0)

    def test_detect_default_credentials(self):
        """Test detection of default credentials."""
        html = 'admin_user: "admin", admin_password: "admin"'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        default_cred_issues = [v for v in vulnerabilities if v.get("issue") == "default_credentials"]
        self.assertGreater(len(default_cred_issues), 0)

    def test_detect_weak_session_id(self):
        """Test detection of weak session IDs."""
        html = 'var sessionId = "abc123"'  # Only 6 chars
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        session_issues = [v for v in vulnerabilities if v.get("issue") == "weak_session_id"]
        self.assertGreater(len(session_issues), 0)

    def test_detect_predictable_session_generation(self):
        """Test detection of predictable session generation."""
        code = '''
        var sessionId = Math.random() * 1000;
        '''
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        predictable_issues = [v for v in vulnerabilities if v.get("issue") == "predictable_session_generation"]
        self.assertGreater(len(predictable_issues), 0)

    def test_detect_missing_password_confirmation(self):
        """Test detection of missing password confirmation."""
        html = '''
        <form>
            <label>New Password:</label>
            <input type="password" name="new_password" />
            <button>Change Password</button>
        </form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        confirm_issues = [v for v in vulnerabilities if v.get("issue") == "missing_password_confirmation"]
        self.assertGreater(len(confirm_issues), 0)

    def test_password_with_confirmation_is_safe(self):
        """Test that password forms with confirmation are safe."""
        html = '''
        <form>
            <input type="password" name="new_password" />
            <input type="password" name="confirm_password" />
        </form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        confirm_issues = [v for v in vulnerabilities if v.get("issue") == "missing_password_confirmation"]
        self.assertEqual(len(confirm_issues), 0)

    def test_detect_plaintext_password_in_comments(self):
        """Test detection of plaintext passwords in comments."""
        html = '''
        // TODO: fix this
        // User: admin, Password: "SecurePass123"
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        comment_pwd_issues = [v for v in vulnerabilities if v.get("issue") == "plaintext_password_in_comments"]
        self.assertGreater(len(comment_pwd_issues), 0)

    def test_detect_no_password_hashing(self):
        """Test detection of plaintext password storage."""
        code = 'password = plaintext_value'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        hash_issues = [v for v in vulnerabilities if v.get("issue") == "no_password_hashing"]
        self.assertGreater(len(hash_issues), 0)

    def test_empty_input_returns_no_issues(self):
        """Test handling of empty input."""
        result = self.scanner.scan(None)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)

    def test_safe_password_form_returns_minimal_issues(self):
        """Test that properly implemented password forms return few issues."""
        html = '''
        <form method="POST" action="/change-password">
            <input type="password" name="current_password" required minlength="8" />
            <input type="password" name="new_password" required minlength="12" />
            <input type="password" name="confirm_password" required minlength="12" />
            <button type="submit">Update Password</button>
        </form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        # Should find very few or no issues
        self.assertLess(len(vulnerabilities), 3)

    def test_finding_has_required_fields(self):
        """Test that findings have required fields."""
        html = 'http://example.com?password=test'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        for finding in vulnerabilities:
            self.assertIn("url", finding)
            self.assertIn("issue", finding)
            self.assertIn("severity", finding)


if __name__ == "__main__":
    unittest.main()
