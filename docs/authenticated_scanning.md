# Authenticated Dynamic Scanning (MVP)

This document describes how to use the new Authenticated Dynamic Scanning MVP.

Key features

- Scripted login with Playwright (or username/password best-effort)

- Safe default checks (non-destructive)

- Artifacts: screenshot, page HTML, JSON findings


Quick run (local)

1. Install dependencies and Playwright browsers:

```powershell
pip install -r requirements.txt
playwright install
```

1. Run an authenticated scan (example):

```powershell
python scripts/auth_scan.py --url https://example.com --username test --password test --login-url https://example.com/login
```

Output
`./artifacts/scan_result.json` — findings

`./artifacts/screenshot.png` — full-page screenshot

`./artifacts/page.html` — saved HTML snapshot

Notes
Use `--artifacts` to change artifacts folder.

For complex logins provide a `login_script` (Playwright snippet) in the future.
