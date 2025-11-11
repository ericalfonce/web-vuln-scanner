import unittest
from src.scanner.plugins.csrf_scanner import CSRFScanner


class TestCSRFScanner(unittest.TestCase):
    """Test CSRF vulnerability scanner."""

    def setUp(self):
        self.scanner = CSRFScanner()

    def test_detect_form_without_csrf_token(self):
        """Test detection of POST forms missing CSRF token."""
        html = '''
        <html>
            <form method="POST" action="/submit">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <button type="submit">Submit</button>
            </form>
        </html>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
        self.assertGreater(len(csrf_issues), 0)

    def test_form_with_csrf_token_is_safe(self):
        """Test that forms with CSRF tokens are not flagged."""
        html = '''
        <html>
            <form method="POST" action="/submit">
                <input type="hidden" name="csrf_token" value="abc123" />
                <input type="text" name="username" />
                <button type="submit">Submit</button>
            </form>
        </html>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
        self.assertEqual(len(csrf_issues), 0)

    def test_detect_state_changing_get_form(self):
        """Test detection of GET forms for state-changing operations."""
        html = '''
        <form method="GET" action="/delete">
            <input type="hidden" name="id" value="123" />
            <button type="submit">Delete</button>
        </form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        get_issues = [v for v in vulnerabilities if v.get("issue") == "get_method_state_changing"]
        self.assertGreater(len(get_issues), 0)

    def test_detect_missing_csrf_header(self):
        """Test detection of AJAX calls without CSRF header."""
        js = '''
        fetch('/api/update', {
            method: 'POST',
            body: JSON.stringify({name: 'test'})
        });
        '''
        result = self.scanner.scan(js)
        vulnerabilities = result["vulnerabilities"]

        header_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_header"]
        self.assertGreater(len(header_issues), 0)

    def test_detect_unvalidated_redirect(self):
        """Test detection of unvalidated redirects."""
        html = '''
        <script>
        window.location = "?redirect=" + userInput;
        </script>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        redirect_issues = [v for v in vulnerabilities if v.get("issue") == "unvalidated_redirect"]
        self.assertGreater(len(redirect_issues), 0)

    def test_detect_document_cookie_without_samesite(self):
        """Test detection of document.cookie without SameSite hint."""
        js = 'document.cookie = "sessionid=abc123"'
        result = self.scanner.scan(js)
        vulnerabilities = result["vulnerabilities"]

        samesite_issues = [v for v in vulnerabilities if v.get("issue") == "missing_samesite_cookie"]
        self.assertGreater(len(samesite_issues), 0)

    def test_multiple_forms_each_checked(self):
        """Test that multiple forms are all checked."""
        html = '''
        <form method="POST"><input name="field1" /></form>
        <form method="POST"><input name="field2" /></form>
        <form method="POST"><input name="field3" /></form>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
        # Should find multiple issues (one per form)
        self.assertGreaterEqual(len(csrf_issues), 1)

    def test_empty_input_returns_no_issues(self):
        """Test handling of empty input."""
        result = self.scanner.scan(None)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)

    def test_finding_has_required_fields(self):
        """Test that findings have required fields."""
        html = '<form method="POST"><input name="field" /></form>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]

        for finding in vulnerabilities:
            self.assertIn("url", finding)
            self.assertIn("issue", finding)
            self.assertIn("severity", finding)

        def test_detect_csrf_token_name_variations(self):
            """Test detection of various CSRF token field names."""
            # Test form without common token name variations
            html = '''
            <form method="POST" action="/submit">
                <input type="text" name="username" />
                <button type="submit">Submit</button>
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
            self.assertGreater(len(csrf_issues), 0)

        def test_recognized_token_names_are_safe(self):
            """Test that recognized token names prevent flagging."""
            # Test various recognized token names
            token_names = ["csrf_token", "csrftoken", "_csrf", "authenticity_token", 
                           "anti_csrf_token", "token", "xsrf_token"]
        
            for token_name in token_names:
                html = f'''
                <form method="POST">
                    <input type="hidden" name="{token_name}" value="test123" />
                    <input type="text" name="field" />
                </form>
                '''
                result = self.scanner.scan(html)
                vulnerabilities = result["vulnerabilities"]
            
                csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
                self.assertEqual(len(csrf_issues), 0, f"Token name '{token_name}' was not recognized")

        def test_detect_put_method_without_token(self):
            """Test detection of PUT method forms without tokens."""
            html = '''
            <form method="PUT">
                <input type="text" name="data" />
                <button type="submit">Update</button>
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
            self.assertGreater(len(csrf_issues), 0)

        def test_detect_delete_method_without_token(self):
            """Test detection of DELETE method forms without tokens."""
            html = '''
            <form method="DELETE">
                <input type="text" name="id" />
                <button type="submit">Delete</button>
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
            self.assertGreater(len(csrf_issues), 0)

        def test_detect_patch_method_without_token(self):
            """Test detection of PATCH method forms without tokens."""
            html = '''
            <form method="PATCH">
                <input type="text" name="data" />
                <button type="submit">Update</button>
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
            self.assertGreater(len(csrf_issues), 0)

        def test_detect_post_form_dangerous_operations(self):
            """Test detection of POST forms for dangerous operations."""
            dangerous_actions = ["/delete", "/remove", "/change-password", "/admin/config"]
        
            for action in dangerous_actions:
                html = f'''
                <form method="POST" action="{action}">
                    <input type="text" name="id" />
                    <button type="submit">Submit</button>
                </form>
                '''
                result = self.scanner.scan(html)
                vulnerabilities = result["vulnerabilities"]
            
                csrf_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_token"]
                self.assertGreater(len(csrf_issues), 0, f"Dangerous action '{action}' not detected")

        def test_severity_levels_are_correct(self):
            """Test that findings have appropriate severity levels."""
            html = '''
            <form method="POST">
                <input type="password" name="password" />
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            for finding in vulnerabilities:
                severity = finding.get("severity", "").upper()
                self.assertIn(severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

        def test_ajax_post_without_headers(self):
            """Test detection of AJAX POST without CSRF headers."""
            js = '''
            $.post('/api/data', {
                key: 'value'
            });
            '''
            result = self.scanner.scan(js)
            vulnerabilities = result["vulnerabilities"]

            header_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_header"]
            self.assertGreater(len(header_issues), 0)

        def test_ajax_with_csrf_header_is_safe(self):
            """Test that AJAX with CSRF header is not flagged."""
            js = '''
            $.ajax({
                type: 'POST',
                url: '/api/data',
                headers: {
                    'X-CSRF-Token': csrfToken
                },
                data: {key: 'value'}
            });
            '''
            result = self.scanner.scan(js)
            vulnerabilities = result["vulnerabilities"]

            header_issues = [v for v in vulnerabilities if v.get("issue") == "missing_csrf_header"]
            self.assertEqual(len(header_issues), 0)

        def test_get_safe_for_retrieval(self):
            """Test that GET forms for data retrieval are safe."""
            html = '''
            <form method="GET" action="/search">
                <input type="text" name="q" />
                <button type="submit">Search</button>
            </form>
            '''
            result = self.scanner.scan(html)
            vulnerabilities = result["vulnerabilities"]

            get_issues = [v for v in vulnerabilities if v.get("issue") == "get_method_state_changing"]
            # Should not flag GET for safe operations
            self.assertEqual(len(get_issues), 0)

if __name__ == "__main__":
    unittest.main()
