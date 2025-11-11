#!/usr/bin/env python3
"""Simple CLI wrapper to run an authenticated dynamic scan (MVP).

Usage:
  python scripts/auth_scan.py --url https://example.com --username user --password pass

This script is intentionally small: it demonstrates how to call
`src.scanner.dynamic.DynamicScanner` and save JSON output.
"""
import argparse
import json
import sys
from pathlib import Path

from src.scanner.dynamic import DynamicScanner, PlaywrightNotInstalled


def main():
    parser = argparse.ArgumentParser(description="Run an authenticated dynamic scan (MVP)")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--username", help="Username for login (optional)")
    parser.add_argument("--password", help="Password for login (optional)")
    parser.add_argument("--login-url", help="Login page URL (optional)")
    parser.add_argument("--artifacts", default="./artifacts", help="Directory to write artifacts")
    args = parser.parse_args()

    try:
        scanner = DynamicScanner(headless=True, artifacts_dir=args.artifacts)
    except PlaywrightNotInstalled as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)

    # Prepare session and run
    p, browser, context, page = scanner.prepare_session(
        login_script=None, username=args.username, password=args.password, login_url=args.login_url
    )
    try:
        result = scanner.run_checks(page, target_url=args.url)
        out_path = Path(args.artifacts) / "scan_result.json"
        out_path.write_text(json.dumps(result, indent=2))
        print(f"Scan complete. Results saved to {out_path}")
    finally:
        try:
            browser.close()
            p.stop()
        except Exception:
            pass


if __name__ == "__main__":
    main()
