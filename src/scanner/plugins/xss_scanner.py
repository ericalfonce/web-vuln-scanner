"""XSS (Cross-Site Scripting) vulnerability scanner plugin.

This plugin detects common XSS vulnerabilities and injection points
in HTML and JavaScript content.
"""
import re
from typing import List, Dict, Any


class XSSScanner:
    """Scan for XSS vulnerabilities and injection points.
    
    Detects:
    - Unescaped user input in HTML/JavaScript
    - Dangerous functions (eval, innerHTML, etc.)
    - Event handlers with suspicious patterns
    - Template injection indicators
    - JavaScript protocol handlers
    """

    # XSS payload patterns that might indicate vulnerabilities
    XSS_PATTERNS = {
        "script_tags": re.compile(r"<script[^>]*>", re.IGNORECASE),
        "event_handlers": re.compile(
            r"on(?:load|error|click|mouseover|focus|blur|change|submit|keydown|keyup)\s*=\s*[\"']?([^\"'>]*)[\"']?",
            re.IGNORECASE,
        ),
        "javascript_protocol": re.compile(r"(?:href|src|action)\s*=\s*[\"']?javascript:", re.IGNORECASE),
        "eval_usage": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "innerhtml_assignment": re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
        "innertext_assignment": re.compile(r"\.innerText\s*=", re.IGNORECASE),
        "unescaped_output": re.compile(r"\{\{[^}]*\}\}|\$\{[^}]*\}"),
        "data_uri": re.compile(r"(?:href|src)\s*=\s*[\"']?data:[^\"';\s]*", re.IGNORECASE),
        "form_action": re.compile(r"<form[^>]*action\s*=\s*[\"']?([^\"'>\s]+)[\"']?", re.IGNORECASE),
    }

    # Suspicious patterns in JavaScript code
    SUSPICIOUS_JS_PATTERNS = {
        "document_write": re.compile(r"document\.write", re.IGNORECASE),
        "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
        "function_constructor": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
        "settimeout_eval": re.compile(r"(?:setTimeout|setInterval)\s*\(\s*[\"']?.*(?:eval|Function)", re.IGNORECASE),
    }

    def scan(self, target=None):
        """Scan target for XSS vulnerabilities.
        
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

        # Check for various XSS patterns
        findings.extend(self._check_script_tags(content))
        findings.extend(self._check_event_handlers(content))
        findings.extend(self._check_javascript_protocol(content))
        findings.extend(self._check_dangerous_functions(content))
        findings.extend(self._check_unescaped_output(content))
        findings.extend(self._check_data_uris(content))
        findings.extend(self._check_form_targets(content, target))
        findings.extend(self._check_suspicious_js(content))

        return {"vulnerabilities": findings}

    def _check_script_tags(self, content: str) -> List[Dict[str, Any]]:
        """Check for inline script tags."""
        findings = []
        matches = self.XSS_PATTERNS["script_tags"].finditer(content)
        
        for match in matches:
            # Extract context around the match
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 100)
            context = content[start:end].replace("\n", " ")
            
            findings.append({
                "url": "inline",
                "issue": "inline_script_tag",
                "severity": "high",
                "context": context.strip(),
                "line": content[:match.start()].count("\n") + 1,
            })
        
        return findings

    def _check_event_handlers(self, content: str) -> List[Dict[str, Any]]:
        """Check for suspicious event handlers."""
        findings = []
        matches = self.XSS_PATTERNS["event_handlers"].finditer(content)
        
        for match in matches:
            handler_value = match.group(1) if match.groups() else ""
            
            # Check if handler contains suspicious patterns
            if any(
                x in handler_value.lower()
                for x in ["alert", "eval", "document", "window", "fetch", "xhr"]
            ):
                findings.append({
                    "url": "inline",
                    "issue": "suspicious_event_handler",
                    "severity": "high",
                    "handler": match.group(0),
                    "value": handler_value,
                })
        
        return findings

    def _check_javascript_protocol(self, content: str) -> List[Dict[str, Any]]:
        """Check for javascript: protocol handlers."""
        findings = []
        matches = self.XSS_PATTERNS["javascript_protocol"].finditer(content)
        
        for match in matches:
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 50)
            context = content[start:end].replace("\n", " ")
            
            findings.append({
                "url": "inline",
                "issue": "javascript_protocol",
                "severity": "high",
                "context": context.strip(),
            })
        
        return findings

    def _check_dangerous_functions(self, content: str) -> List[Dict[str, Any]]:
        """Check for dangerous function usage."""
        findings = []
        
        # Check for eval
        if self.XSS_PATTERNS["eval_usage"].search(content):
            findings.append({
                "url": "inline",
                "issue": "eval_usage",
                "severity": "critical",
                "description": "Use of eval() function detected - major XSS risk",
            })
        
        # Check for innerHTML
        if self.XSS_PATTERNS["innerhtml_assignment"].search(content):
            findings.append({
                "url": "inline",
                "issue": "innerhtml_assignment",
                "severity": "high",
                "description": "Direct innerHTML assignment - potential XSS vector",
            })
        
        # Check for innerText
        if self.XSS_PATTERNS["innertext_assignment"].search(content):
            findings.append({
                "url": "inline",
                "issue": "innertext_assignment",
                "severity": "medium",
                "description": "Direct innerText assignment - may have XSS risk",
            })
        
        return findings

    def _check_unescaped_output(self, content: str) -> List[Dict[str, Any]]:
        """Check for unescaped template variables."""
        findings = []
        matches = self.XSS_PATTERNS["unescaped_output"].finditer(content)
        
        for match in matches:
            findings.append({
                "url": "inline",
                "issue": "unescaped_output",
                "severity": "medium",
                "context": match.group(0),
                "description": "Unescaped template variable - may be XSS vector",
            })
        
        return findings[:5]  # Limit to first 5 to avoid spam

    def _check_data_uris(self, content: str) -> List[Dict[str, Any]]:
        """Check for data: URI handlers."""
        findings = []
        matches = self.XSS_PATTERNS["data_uri"].finditer(content)
        
        for match in matches:
            findings.append({
                "url": "inline",
                "issue": "data_uri",
                "severity": "medium",
                "context": match.group(0),
                "description": "data: URI detected - potential XSS vector",
            })
        
        return findings[:5]  # Limit to first 5

    def _check_form_targets(self, content: str, target: str = None) -> List[Dict[str, Any]]:
        """Check for suspicious form targets."""
        findings = []
        matches = self.XSS_PATTERNS["form_action"].finditer(content)
        
        for match in matches:
            form_action = match.group(1) if match.groups() else ""
            
            # Check if form submits to external domain
            if form_action and not form_action.startswith("/") and "javascript:" not in form_action.lower():
                if target and isinstance(target, str):
                    # Extract domain from target
                    from urllib.parse import urlparse
                    try:
                        target_domain = urlparse(target).netloc
                        action_domain = urlparse(form_action).netloc
                        
                        if action_domain and action_domain != target_domain:
                            findings.append({
                                "url": form_action,
                                "issue": "form_to_external_domain",
                                "severity": "medium",
                                "description": f"Form submits to external domain: {action_domain}",
                            })
                    except Exception:
                        pass
        
        return findings

    def _check_suspicious_js(self, content: str) -> List[Dict[str, Any]]:
        """Check for suspicious JavaScript patterns."""
        findings = []
        
        # Check for document.write (generally bad practice)
        if self.SUSPICIOUS_JS_PATTERNS["document_write"].search(content):
            count = len(self.SUSPICIOUS_JS_PATTERNS["document_write"].findall(content))
            findings.append({
                "url": "inline",
                "issue": "document_write_usage",
                "severity": "medium",
                "description": f"document.write() found {count} times - deprecated and risky",
            })
        
        # Check for Function constructor
        if self.SUSPICIOUS_JS_PATTERNS["function_constructor"].search(content):
            findings.append({
                "url": "inline",
                "issue": "function_constructor",
                "severity": "high",
                "description": "new Function() constructor detected - potential code injection",
            })
        
        # Check for setTimeout/setInterval with eval
        if self.SUSPICIOUS_JS_PATTERNS["settimeout_eval"].search(content):
            findings.append({
                "url": "inline",
                "issue": "timeout_eval",
                "severity": "critical",
                "description": "setTimeout/setInterval with eval - critical XSS risk",
            })
        
        return findings
