# Iteration 3 Summary — OWASP Top 10 Scanners

Date: 2025-11-11

Overview
--------
Iteration 3 extends the web-vuln-scanner with three new scanner plugins focused on OWASP Top 10 related issues:

- CSRFScanner — detects missing CSRF tokens, missing CSRF headers in AJAX calls, unvalidated redirects, and state-changing operations using GET.
- AuthenticationFlawsScanner — detects weak password policies, default credentials, password transmission over HTTP/GET, missing confirmation fields, plaintext password storage, and session generation weaknesses.
- InsecureDeserializationScanner — detects unsafe deserialization patterns such as Python pickle/load usage on untrusted input, unsafe YAML loading, XML parsers that can lead to XXE, unsafe JSON object_hook usage, gadget-chain indicators in Java code, and unsafe eval/exec usage.

What I changed
--------------
- Added three scanner plugins under `src/scanner/plugins/`:
  - `csrf_scanner.py`
  - `auth_flaws_scanner.py`
  - `insecure_deserialization_scanner.py`
- Added new unit tests under `tests/`:
  - `test_csrf_scanner.py` (expanded)
  - `test_auth_flaws_scanner.py` (new)
  - `test_insecure_deserialization_scanner.py` (new)
  - `test_url_fetching.py` (mock-based URL-fetch tests)
- Updated `README.md` with Iteration 3 usage examples and notes.

Testing
-------
- Ran full test suite locally in the configured virtual environment.
- Final results: `89 passed, 0 failed` across the entire test suite.

Notes & Implementation Details
------------------------------
- Network calls: scanners will call `src.utils.network.make_get_request(url)` when supplied with a URL. Tests include mock-based coverage for those paths.
- Findings schema: each finding is a dict containing `url`, `issue`, `severity`, and optional `description`/`context`.
- Severity mapping follows existing conventions: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

Next steps
----------
- Create a PR branch and open a Pull Request. The local branch is created and committed; pushing the branch requires remote credentials (I attempted a push; if push fails you can run the provided commands locally or supply a remote URL).
- Add additional tests that simulate HTTP responses (404, 500) to exercise error handling for URL fetches.
- Add documentation pages with remediation guidance for each issue type.

Commands run (local development)
--------------------------------
The following commands were executed in the repository during development (local branch created and committed):

```powershell
# create branch and commit
git checkout -b iteration-3-owasp
git add .
git commit -m "Iteration 3: OWASP scanners, tests, docs"
# attempt to push (may require remote credentials)
git push -u origin iteration-3-owasp
```

If push fails due to no remote or missing credentials, run the same commands locally after configuring your remote.

Contact & Troubleshooting
-------------------------
If tests fail on your machine:
- Ensure the virtual environment is active and dependencies are installed (`pip install -r requirements.txt`).
- Run `pytest -q` to rerun tests and inspect failing output.
- If network-based tests fail, ensure there's no interfering network mocking in your global environment.

---

Iteration 3 delivered new OWASP-focused scanning capabilities, test coverage for both content and URL-fetch code paths, and updated docs and README examples.
