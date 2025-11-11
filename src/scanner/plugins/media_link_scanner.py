import re
from typing import List

from src.utils import network


class MediaLinkScanner:
    """Scan a target (URL or HTML content) for media and links and report security issues.

    Finds href/src attributes and flags:
    - insecure_protocol: link uses http:// instead of https://
    - unreachable: HEAD request did not return 200
    - suspicious_domain: domain in a small internal watchlist
    """

    SUSPICIOUS_DOMAINS = {"malicious.test", "bad.example", "phish.local"}

    LINK_RE = re.compile(r"(?:href|src)=[\"']([^\"'#]+)[\"']", re.IGNORECASE)

    def _extract_links(self, content: str) -> List[str]:
        return self.LINK_RE.findall(content)

    def _is_insecure(self, link: str) -> bool:
        return link.lower().startswith("http://")

    def _is_suspicious(self, link: str) -> bool:
        for d in self.SUSPICIOUS_DOMAINS:
            if d in link:
                return True
        return False

    def scan(self, target):
        # Accept raw HTML (contains '<') or a URL
        if isinstance(target, str) and "<" in target:
            html = target
        else:
            html = network.make_get_request(target)
            if html is None:
                return {"vulnerabilities": [{"url": target, "issue": "unreachable", "severity": "high"}]}

        links = self._extract_links(html or "")
        findings = []

        for link in links:
            issue = None
            severity = "low"

            if self._is_insecure(link):
                issue = "insecure_protocol"
                severity = "medium"
            elif self._is_suspicious(link):
                issue = "suspicious_domain"
                severity = "high"
            else:
                # check reachability
                reachable = network.check_url_reachable(link) if link.startswith("http") else True
                if not reachable:
                    issue = "unreachable"
                    severity = "medium"

            if issue:
                findings.append({"url": link, "issue": issue, "severity": severity})

        return {"vulnerabilities": findings}
