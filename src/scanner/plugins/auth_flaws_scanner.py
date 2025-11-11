"""Authentication vulnerabilities scanner plugin.

This plugin detects common authentication flaws and weak password practices.
"""
import re
from typing import List, Dict, Any


class AuthenticationFlawsScanner:
    """Scan for authentication vulnerabilities and weak practices.
    
    Detects:
    - Weak password requirements
    - Missing password confirmation
    - Session fixation indicators
    - Missing authentication on sensitive endpoints
    - Password stored in code/comments
    - SQL injection in login forms
    - Default credentials patterns
    """

    # Weak password patterns
    WEAK_PASSWORD_PATTERNS = {
        r"password\s*[:=]\s*['\"].*?['\"]",  # Password in code
        r"pwd\s*[:=]\s*['\"].*?['\"]",        # pwd variable
        r"pass\s*[:=]\s*['\"].*?['\"]",       # pass variable
    }

    # Default credential patterns
    DEFAULT_CREDENTIALS = {
        "admin:admin",
        "admin:password",
        "admin:123456",
        "root:root",
        "root:password",
        "test:test",
        "guest:guest",
        "user:user",
    }

    # Session/cookie names that might indicate issues
    SESSION_PATTERNS = {
        r"session\s*[:=]\s*['\"]?[a-zA-Z0-9]{1,8}['\"]?",  # Short session IDs
        r"jsessionid\s*=\s*[a-zA-Z0-9_-]{1,10}",            # Short JSESSIONID
    }

    # Login-related endpoints
    LOGIN_ENDPOINTS = {
        "/login",
        "/signin",
        "/auth",
        "/authenticate",
        "/user/login",
        "/admin/login",
        "/account/login",
    }

    def scan(self, target=None):
        """Scan target for authentication vulnerabilities.
        
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

        # Check for various auth vulnerabilities
        findings.extend(self._check_weak_password_handling(content))
        findings.extend(self._check_default_credentials(content))
        findings.extend(self._check_session_fixation_indicators(content))
        findings.extend(self._check_missing_password_confirmation(content))
        findings.extend(self._check_sql_injection_in_forms(content))
        findings.extend(self._check_plaintext_password_storage(content))

        return {"vulnerabilities": findings}

    def _check_weak_password_handling(self, content: str) -> List[Dict[str, Any]]:
        """Check for weak password handling practices."""
        findings = []
"""Authentication vulnerabilities scanner plugin.

This plugin detects common authentication flaws and weak password practices.
"""
import re
from typing import List, Dict, Any


class AuthenticationFlawsScanner:
    """Scan for authentication vulnerabilities and weak practices.
    
    Detects:
    - Weak password requirements
    - Missing password confirmation
    - Session fixation indicators
    - Missing authentication on sensitive endpoints
    - Password stored in code/comments
    - SQL injection in login forms
    - Default credentials patterns
    """

    # Default credential patterns
    DEFAULT_CREDENTIALS = {
        "admin:admin",
        "admin:password",
        "admin:123456",
        "root:root",
        "root:password",
        "test:test",
        "guest:guest",
        "user:user",
    }

    # Login-related endpoints
    LOGIN_ENDPOINTS = {
        "/login",
        "/signin",
        "/auth",
        "/authenticate",
        "/user/login",
        "/admin/login",
        "/account/login",
    }

    def scan(self, target=None):
        """Scan target for authentication vulnerabilities.
        
        Args:
            target: HTML content to scan, or URL to fetch
            
        Returns:
            Dict with "vulnerabilities" key containing list of findings
        """
        if not target:
            return {"vulnerabilities": []}

        # If it's a URL, fetch content
        if isinstance(target, str) and target.startswith("http"):
            # If URL contains plaintext password parameter over HTTP, flag it without fetching
            if target.startswith("http://") and "password=" in target:
                return {"vulnerabilities": [{"url": target, "issue": "password_over_http", "severity": "critical", "description": "Password transmitted over HTTP in URL"}]}

            from src.utils import network

            content = network.make_get_request(target)
            if not content:
                return {"vulnerabilities": [{"url": target, "issue": "unreachable", "severity": "high"}]}
        else:
            content = target

        if not content:
            return {"vulnerabilities": []}

        findings: List[Dict[str, Any]] = []

        # Check for various auth vulnerabilities
        findings.extend(self._check_weak_password_handling(content))
        findings.extend(self._check_default_credentials(content))
        findings.extend(self._check_session_fixation_indicators(content))
        findings.extend(self._check_missing_password_confirmation(content))
        findings.extend(self._check_sql_injection_in_forms(content))
        findings.extend(self._check_plaintext_password_storage(content))

        return {"vulnerabilities": findings}

    def _check_weak_password_handling(self, content: str) -> List[Dict[str, Any]]:
        """Check for weak password handling practices."""
        findings: List[Dict[str, Any]] = []

        # Check for insufficient password requirements
        if re.search(r"minlength\s*[:=]\s*['\"]?[0-3]['\"]?", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "weak_password_requirement",
                "severity": "high",
                "description": "Password field with very weak minimum length (< 4 characters)",
            })

        # Check for passwords transmitted via GET
        if re.search(r"<form[^>]*method\s*=\s*['\"]?get['\"]?[^>]*>.*?<input[^>]*type\s*=\s*['\"]?password", content, re.IGNORECASE | re.DOTALL):
            findings.append({
                "url": "inline",
                "issue": "password_over_get",
                "severity": "critical",
                "description": "Password field in form using GET method - passwords visible in URL/logs",
            })

        # Check for password sent unencrypted (naive check)
        if re.search(r"http://[^\s'\" ]+password|password=.*?http://", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "password_over_http",
                "severity": "critical",
                "description": "Password field on non-HTTPS form - credentials transmitted in plaintext",
            })

        # Check for weak password reset
        if re.search(r"forgot.*?password.*?email\s*only|reset.*?password.*?username\s*only", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "weak_password_reset",
                "severity": "medium",
                "description": "Password reset using only email or username - susceptible to account takeover",
            })

        return findings

    def _check_default_credentials(self, content: str) -> List[Dict[str, Any]]:
        """Check for default credentials in code."""
        findings: List[Dict[str, Any]] = []

        for credential in self.DEFAULT_CREDENTIALS:
            # Look for hardcoded defaults (case-insensitive)
            if credential.lower() in content.lower():
                findings.append({
                    "url": "inline",
                    "issue": "default_credentials",
                    "severity": "critical",
                    "description": f"Default credentials found in code: {credential}",
                })
                break

        # Try to detect username/password key-value pairs on the same line (e.g. admin_user: "admin", admin_password: "admin")
        up_match = re.search(r"(?P<ukey>\w*user\w*|username)\s*[:=]\s*[\"'](?P<u>[^\"']+)[\"'].*?(?P<pkey>\w*pass\w*|password)\s*[:=]\s*[\"'](?P<p>[^\"']+)[\"']", content, re.IGNORECASE)
        if up_match:
            u = up_match.group("u")
            p = up_match.group("p")
            pair = f"{u}:{p}".lower()
            if pair in set(c.lower() for c in self.DEFAULT_CREDENTIALS):
                findings.append({
                    "url": "inline",
                    "issue": "default_credentials",
                    "severity": "critical",
                    "description": f"Default credentials found in code: {pair}",
                })

        return findings

    def _check_session_fixation_indicators(self, content: str) -> List[Dict[str, Any]]:
        """Check for session fixation vulnerabilities."""
        findings: List[Dict[str, Any]] = []

        # Check for very short session IDs (< 32 chars typically)
        short_session_matches = re.finditer(
            r"(?:session|jsessionid|sid|sessionid)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{1,16})['\"]?",
            content,
            re.IGNORECASE,
        )

        for match in short_session_matches:
            findings.append({
                "url": "inline",
                "issue": "weak_session_id",
                "severity": "high",
                "description": f"Session ID appears too short for cryptographic safety: {match.group(1)}",
            })
            break  # Report only once

        # Check for predictable session generation indicators (rand, time, counter)
        if re.search(r"session.*?(?:rand|time|counter)", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "predictable_session_generation",
                "severity": "high",
                "description": "Session ID generation uses predictable methods (rand, time, counter)",
            })

        return findings

    def _check_missing_password_confirmation(self, content: str) -> List[Dict[str, Any]]:
        """Check for missing password confirmation in change forms."""
        findings: List[Dict[str, Any]] = []

        # Look for password change/reset forms
        if re.search(r"change.*?password|reset.*?password|new.*?password", content, re.IGNORECASE):
            # Check if there's a confirmation field
            has_confirmation = any(
                re.search(pattern, content, re.IGNORECASE)
                for pattern in [
                    r"password.*?confirm",
                    r"confirm.*?password",
                    r"re-?enter.*?password",
                    r"repeat.*?password",
                    r"verify.*?password",
                ]
            )

            if not has_confirmation:
                findings.append({
                    "url": "inline",
                    "issue": "missing_password_confirmation",
                    "severity": "medium",
                    "description": "Password change form missing password confirmation field - users can lock themselves out",
                })

        return findings

    def _check_sql_injection_in_forms(self, content: str) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities in authentication forms."""
        findings: List[Dict[str, Any]] = []

        # Look for login forms
        login_forms = re.finditer(
            r"<form[^>]*(?:login|auth|signin)[^>]*>.*?</form>",
            content,
            re.IGNORECASE | re.DOTALL,
        )

        for form_match in login_forms:
            form_content = form_match.group(0)

            # Check for SQL injection patterns (user input directly in query-like context)
            if re.search(r"(?:query|sql|execute)\s*[+*]\s*(?:username|email|password)", form_content, re.IGNORECASE):
                findings.append({
                    "url": "inline",
                    "issue": "sql_injection_in_login",
                    "severity": "critical",
                    "description": "Potential SQL injection in login form - user input concatenated with SQL",
                })
                break

        return findings

    def _check_plaintext_password_storage(self, content: str) -> List[Dict[str, Any]]:
        """Check for indicators of plaintext password storage."""
        findings: List[Dict[str, Any]] = []

        # Look for comments about passwords
        comments_with_passwords = re.finditer(
            r"(?://|#|<!--).*?(?:password|pwd|pass).*?[:=].*?['\"][^'\"]{3,}['\"]",
            content,
            re.IGNORECASE,
        )

        for match in comments_with_passwords:
            findings.append({
                "url": "inline",
                "issue": "plaintext_password_in_comments",
                "severity": "critical",
                "description": "Plaintext password found in code comments",
                "context": match.group(0)[:80],
            })
            break  # Report only once

        # Check for missing password hashing
        if re.search(r"password.*?=.*?plaintext|password.*?=.*?str|store.*?password.*?without.*?hash", content, re.IGNORECASE):
            findings.append({
                "url": "inline",
                "issue": "no_password_hashing",
                "severity": "critical",
                "description": "Passwords stored in plaintext without hashing - critical security flaw",
            })

        return findings
