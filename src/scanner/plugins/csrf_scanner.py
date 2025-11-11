"""CSRF (Cross-Site Request Forgery) vulnerability scanner plugin.

This plugin detects CSRF vulnerabilities and missing protections in web applications.
"""
import re
from typing import List, Dict, Any


class CSRFScanner:
    """Scan for CSRF vulnerabilities and missing protections.
    
    Detects:
    - Missing CSRF tokens in forms
    - Missing CSRF headers/cookies
    - Unvalidated state-changing requests
    - Missing SameSite cookie attributes
    - GET methods for state-changing operations
    """

    # Patterns for detecting forms
    FORM_PATTERN = re.compile(r"<form[^>]*>", re.IGNORECASE)
    INPUT_PATTERN = re.compile(r"<input[^>]*>", re.IGNORECASE)
    
    # CSRF token names (common patterns)
    CSRF_TOKEN_NAMES = {
        "csrf_token",
        "csrftoken",
        "_csrf",
        "_token",
        "authenticity_token",
        "__RequestVerificationToken",
        "csrf",
        "xsrf-token",
        "x-csrf-token",
    }

    # State-changing HTTP methods
    STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # State-changing form methods
    STATE_CHANGING_ACTIONS = {
        "submit",
        "checkout",
        "purchase",
        "delete",
        "remove",
        "update",
        "create",
        "edit",
        "change",
        "save",
    }

    def scan(self, target=None):
        """Scan target for CSRF vulnerabilities.
        
        Args:
            target: HTML content to scan, or URL to fetch
            
        Returns:
            Dict with "vulnerabilities" key containing list of findings
        """
        if not target:
            return {"vulnerabilities": []}

        # If it's a URL, fetch content
        if isinstance(target, str) and target.startswith("http"):
            from src.utils import network
            content = network.make_get_request(target)
            if not content:
                return {"vulnerabilities": [{"url": target, "issue": "unreachable", "severity": "high"}]}
        else:
            content = target

        if not content:
            return {"vulnerabilities": []}

        findings = []

        # Check for various CSRF vulnerabilities
        findings.extend(self._check_forms_without_tokens(content))
        findings.extend(self._check_state_changing_gets(content))
        findings.extend(self._check_missing_samesite_hints(content))
        findings.extend(self._check_missing_csrf_headers(content))
        findings.extend(self._check_unvalidated_redirects(content))

        return {"vulnerabilities": findings}

    def _check_forms_without_tokens(self, content: str) -> List[Dict[str, Any]]:
        """Check for forms missing CSRF tokens."""
        findings = []
        forms = self.FORM_PATTERN.finditer(content)

        for form_match in forms:
            # Get the form element and content
            form_start = form_match.start()
            form_end = content.find("</form>", form_start)
            if form_end == -1:
                form_end = form_start + 500  # Look ahead 500 chars if no closing tag

            form_content = content[form_start:form_end]

            # Check if form has POST/PUT/DELETE method (state-changing)
            method_match = re.search(r'method\s*=\s*["\']?(\w+)["\']?', form_content, re.IGNORECASE)
            method = (method_match.group(1).upper() if method_match else "GET").upper()

            # Check if it's a state-changing form
            is_state_changing = method in self.STATE_CHANGING_METHODS or any(
                action in form_content.lower() for action in self.STATE_CHANGING_ACTIONS
            )

            if is_state_changing:
                # Check for CSRF token
                has_token = any(token_name in form_content.lower() for token_name in self.CSRF_TOKEN_NAMES)

                if not has_token:
                    # Extract form action
                    action_match = re.search(r'action\s*=\s*["\']?([^"\'>\s]+)["\']?', form_content, re.IGNORECASE)
                    action = action_match.group(1) if action_match else "unknown"

                    findings.append({
                        "url": action,
                        "issue": "missing_csrf_token",
                        "severity": "high",
                        "description": f"Form with {method} method missing CSRF token protection",
                        "method": method,
                    })

        return findings

    def _check_state_changing_gets(self, content: str) -> List[Dict[str, Any]]:
        """Check for state-changing operations using GET."""
        findings = []

        # Look for forms with GET method and state-changing action
        get_forms = re.finditer(r'<form[^>]*method\s*=\s*["\']?get["\']?[^>]*>.*?</form>', content, re.IGNORECASE | re.DOTALL)

        for form_match in get_forms:
            form_content = form_match.group(0)

            # Check for state-changing keywords in form
            if any(action in form_content.lower() for action in self.STATE_CHANGING_ACTIONS):
                findings.append({
                    "url": "inline",
                    "issue": "get_method_state_changing",
                    "severity": "medium",
                    "description": "GET method used for state-changing operation (should be POST)",
                    "context": form_content[:100],
                })

        return findings

    def _check_missing_samesite_hints(self, content: str) -> List[Dict[str, Any]]:
        """Check for hints about missing SameSite cookie attributes."""
        findings = []

        # Look for Set-Cookie headers or cookie-setting JavaScript
        if re.search(r"document\.cookie\s*=", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "missing_samesite_cookie",
                "severity": "medium",
                "description": "Cookie set via JavaScript - verify SameSite attribute is properly configured",
            })

        return findings

    def _check_missing_csrf_headers(self, content: str) -> List[Dict[str, Any]]:
        """Check for missing CSRF protection headers."""
        findings = []

        # Look for AJAX/fetch calls without CSRF headers
        ajax_patterns = [
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"].*?POST",
            r"XMLHttpRequest\(\)",
            r"\$.ajax\s*\(",
            r"axios\s*\.\s*(?:post|put|delete)",
        ]

        for pattern in ajax_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                # Check if CSRF header is mentioned (case-insensitive)
                if not re.search(r"x[-_]?csrf|csrf[-_]?token|x[-_]?xsrf", content, re.IGNORECASE):
                    findings.append({
                        "url": "inline",
                        "issue": "missing_csrf_header",
                        "severity": "high",
                        "description": "AJAX/Fetch calls detected without CSRF header validation",
                    })
                    break  # Only report once

        return findings

    def _check_unvalidated_redirects(self, content: str) -> List[Dict[str, Any]]:
        """Check for unvalidated redirects that could be CSRF vectors."""
        findings = []

        # Look for redirects based on user input parameters
        redirect_patterns = [
            r"window\.location\s*=\s*['\"]\s*\?redirect",
            r"window\.location\.href\s*=\s*req\.",
            r"redirect\s*\(\s*\$_GET",
            r"redirect\s*\(\s*request\.args",
            r"window\.location\s*=\s*\?redirect",
            r"window\.location\s*=\s*\"\?redirect",
        ]

        for pattern in redirect_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "url": "inline",
                    "issue": "unvalidated_redirect",
                    "severity": "high",
                    "description": "Unvalidated redirect based on user input detected - CSRF/open redirect risk",
                })
                break

        return findings


    def _get_html_context(self, content: str, match_start: int, context_length: int = 100) -> str:
        """Get surrounding HTML context."""
        start = max(0, match_start - context_length // 2)
        end = min(len(content), match_start + context_length // 2)
        return content[start:end].replace("\n", " ").strip()
