"""SARIF (Static Analysis Results Format) export for scan findings.

This module converts scanner findings to SARIF format for CI/CD integration.
SARIF is supported by GitHub, GitLab, Azure DevOps, and other platforms.

Ref: https://sarifweb.azureedge.net/
"""
import json
from datetime import datetime
from typing import Dict, List, Optional


def generate_sarif(
    findings: List[Dict],
    target: str,
    tool_name: str = "web-vuln-scanner",
    tool_version: str = "1.0.0",
) -> Dict:
    """Generate SARIF report from findings.

    Args:
        findings: List of finding dicts with 'issue', 'severity', 'description', etc.
        target: Target URL or file scanned
        tool_name: Name of the scanning tool
        tool_version: Tool version

    Returns:
        SARIF object as a dict
    """

    # Map severity levels to SARIF levels
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }

    results = []

    for finding in findings:
        severity = finding.get("severity", "low").lower()
        level = severity_map.get(severity, "note")

        result = {
            "ruleId": finding.get("id", "unknown"),
            "message": {
                "text": finding.get("description", finding.get("issue", "Unknown issue"))
            },
            "level": level,
            "locations": [
                {
                    "physicalLocation": {
                        "address": {"uri": target},
                        "region": {
                            "startLine": 1,
                        },
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "confidence": finding.get("confidence", "medium"),
            },
        }

        # Add POC if present
        if finding.get("poc"):
            result["properties"]["poc"] = finding["poc"]

        results.append(result)

    # Build SARIF report
    sarif_report = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/ericalfonce/web-vuln-scanner",
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z",
                    }
                ],
            }
        ],
    }

    return sarif_report


def save_sarif(sarif_report: Dict, path: str = "scan-results.sarif") -> str:
    """Save SARIF report to file.

    Args:
        sarif_report: SARIF dict
        path: Output file path

    Returns:
        Path where file was saved
    """
    with open(path, "w") as f:
        json.dump(sarif_report, f, indent=2)
    return path
