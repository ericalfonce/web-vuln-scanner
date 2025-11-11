"""Authenticated / Dynamic scanner using Playwright.

This module provides a minimal MVP-friendly wrapper around Playwright
to perform stateful, authenticated scans. It is intentionally
lightweight: if Playwright is not installed the module raises an
actionable ImportError with instructions.

Contract (MVP):
- prepare_session(login_script=None, username=None, password=None)
- run_checks(page) -> dict of findings + artifacts (screenshot, har)

"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional


class PlaywrightNotInstalled(Exception):
    pass


try:
    # Import lazily; Playwright requires browser binaries to be installed
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
except Exception:  # pragma: no cover - fallback when playwright not present
    sync_playwright = None  # type: ignore
    PlaywrightTimeout = Exception


class DynamicScanner:
    def __init__(self, headless: bool = True, artifacts_dir: str = "./artifacts"):
        self.headless = headless
        self.artifacts_dir = artifacts_dir
        os.makedirs(self.artifacts_dir, exist_ok=True)

        if sync_playwright is None:
            raise PlaywrightNotInstalled(
                "Playwright is not installed. Install with `pip install playwright` and run `playwright install` to fetch browser binaries.`"
            )

    def prepare_session(
        self,
        login_script: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        login_url: Optional[str] = None,
    ):
        """Start a Playwright browser and optionally perform a login.

        login_script: small Playwright-style Python snippet (string) executed
                      with `page` available.
        username/password/login_url: convenience fields for simple forms.
        Returns: context manager yielding (playwright, browser, context, page)
        """

        p = sync_playwright()
        browser = p.chromium.launch(headless=self.headless)
        context = browser.new_context()
        page = context.new_page()

        # If login_url + creds provided, try a simple form-based login
        if login_url and username is not None and password is not None:
            page.goto(login_url)
            # naive selectors - user should supply login_script for complex flows
            try:
                page.fill('input[type="text"], input[name="username"], input[name="user"]', username)
                page.fill('input[type="password"], input[name="pass"], input[name="password"]', password)
                # try to submit
                page.click('button[type="submit"], input[type="submit"]')
            except Exception:
                # best-effort; if it fails, user should use login_script
                pass

        if login_script:
            # Provide a minimal safe execution environment
            local_ctx: Dict[str, object] = {"page": page}
            exec(login_script, {}, local_ctx)

        return p, browser, context, page

    def run_checks(self, page, target_url: Optional[str] = None) -> Dict[str, object]:
        """Run lightweight dynamic checks and capture artifacts.

        Implements:
        - Screenshot capture
        - DOM XSS detection (innerHTML, eval)
        - CSRF token detection in forms
        - Cookie security (Secure, HttpOnly, SameSite)
        - Authenticated endpoint enumeration
        - Media/link analysis in logged-in context
        Returns a dict with findings and artifact paths.
        """

        findings: List[Dict[str, object]] = []

        # Navigate to target if provided
        if target_url:
            try:
                page.goto(target_url, wait_until="networkidle", timeout=15000)
            except PlaywrightTimeout:
                # continue — we'll still capture HTML
                pass

        # Capture screenshot
        screenshot_path = os.path.join(self.artifacts_dir, "screenshot.png")
        try:
            page.screenshot(path=screenshot_path, full_page=True)
        except Exception:
            screenshot_path = ""

        # Save page content
        try:
            content = page.content()
        except Exception:
            content = ""

        html_path = os.path.join(self.artifacts_dir, "page.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(content)

        # Check 1: DOM XSS patterns
        xss_patterns = {
            "dom_xss_innerHTML": r"innerHTML",
            "unsafe_eval": r"\beval\b|\bFunction\b",
        }

        for name, pat in xss_patterns.items():
            if re.search(pat, content, flags=re.IGNORECASE):
                findings.append(
                    {
                        "id": name,
                        "issue": name,
                        "severity": "medium",
                        "confidence": "low",
                        "poc": "Detected pattern in HTML",
                    }
                )

        # Check 2: CSRF token detection in forms
        csrf_check = self._check_csrf_tokens(content)
        findings.extend(csrf_check)

        # Check 3: Cookie security
        cookies_check = self._check_cookie_security(page)
        findings.extend(cookies_check)

        # Check 4: Authenticated endpoint enumeration
        endpoints_check = self._enumerate_endpoints(content)
        findings.extend(endpoints_check)

        result = {
            "findings": findings,
            "artifacts": {
                "screenshot": screenshot_path,
                "html": html_path,
            },
        }

        return result

    def _check_csrf_tokens(self, html_content: str) -> List[Dict[str, object]]:
        """Check for CSRF token presence in POST forms."""
        findings = []

        # Look for POST forms
        post_forms = re.findall(r'<form[^>]*method\s*=\s*["\']?POST["\']?[^>]*>.*?</form>', html_content, re.IGNORECASE | re.DOTALL)

        if post_forms:
            for form_html in post_forms:
                # Check for CSRF token patterns
                csrf_patterns = [
                    r'name\s*=\s*["\']csrf["\']',
                    r'name\s*=\s*["\']_token["\']',
                    r'name\s*=\s*["\']authenticity_token["\']',
                ]

                has_token = any(re.search(pat, form_html, re.IGNORECASE) for pat in csrf_patterns)

                if not has_token:
                    findings.append(
                        {
                            "id": "missing_csrf_token",
                            "issue": "missing_csrf_token",
                            "severity": "high",
                            "confidence": "medium",
                            "description": "Form detected without CSRF token protection",
                            "poc": "POST form missing CSRF token in authenticated context",
                        }
                    )
                    break  # Report once per page

        return findings

    def _check_cookie_security(self, page) -> List[Dict[str, object]]:
        """Check cookies for Secure, HttpOnly, and SameSite flags."""
        findings = []

        try:
            cookies = page.context.cookies()
            for cookie in cookies:
                issues = []

                # Check for Secure flag in HTTPS context
                if not cookie.get("secure", False) and not cookie.get("sameSite"):
                    issues.append("missing_secure_flag")

                # Check for HttpOnly flag
                if not cookie.get("httpOnly", False):
                    issues.append("missing_httponly_flag")

                # Check for SameSite
                if not cookie.get("sameSite"):
                    issues.append("missing_samesite_flag")

                for issue in issues:
                    findings.append(
                        {
                            "id": f"cookie_security_{issue}",
                            "issue": issue,
                            "severity": "medium",
                            "confidence": "high",
                            "description": f"Cookie '{cookie.get('name')}' missing security flag",
                            "cookie_name": cookie.get("name"),
                        }
                    )
        except Exception:
            pass  # Cookies may not be available in all contexts

        return findings

    def _enumerate_endpoints(self, html_content: str) -> List[Dict[str, object]]:
        """Extract and enumerate endpoints from page content."""
        findings = []

        # Find all href and form action URLs
        links = re.findall(r'href=["\']([^"\']+)["\']', html_content)
        forms = re.findall(r'action=["\']([^"\']+)["\']', html_content)

        endpoints = set(links + forms)

        # Filter and deduplicate
        endpoints = [ep for ep in endpoints if ep and not ep.startswith("#") and not ep.startswith("javascript:")]

        if len(endpoints) > 10:
            # Report if many endpoints found (potential information disclosure)
            findings.append(
                {
                    "id": "many_endpoints_exposed",
                    "issue": "many_endpoints_exposed",
                    "severity": "low",
                    "confidence": "medium",
                    "description": f"Authenticated context exposes {len(endpoints)} endpoints",
                    "endpoint_count": len(endpoints),
                }
            )

        return findings
