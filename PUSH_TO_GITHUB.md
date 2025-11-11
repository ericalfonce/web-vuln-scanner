# How to Push to GitHub and Open a Pull Request

This guide walks you through creating a branch, committing changes, and opening a PR on GitHub.

## Prerequisites

- Git installed on your local machine
- GitHub account with access to the `web-vuln-scanner` repository
- SSH key or personal access token configured (for authentication)

## Step-by-Step Instructions

### 1. Navigate to the Repository

```powershell
cd c:\Users\HP\Music\web-vuln-scanner
```

### 2. Create and Checkout the Branch

```powershell
git checkout -b iteration-3-owasp
```

### 3. Stage All Changes

```powershell
git add .
```

### 4. Commit the Changes

```powershell
git commit -m "Iteration 3: OWASP scanners, tests, docs

- Add CSRFScanner plugin for CSRF vulnerability detection
- Add AuthenticationFlawsScanner for password and auth issues
- Add InsecureDeserializationScanner for deserialization vulnerabilities
- Add 55 new tests (21 CSRF, 13 auth, 17 deserialization, 4 mock URL-fetch)
- Update README with Iteration 3 examples and usage
- Add ITERATION_3_SUMMARY.md with implementation details
- All 93 tests passing"
```

### 5. Push the Branch to GitHub

```powershell
git push -u origin iteration-3-owasp
```

**Note:** You may be prompted to authenticate. If you're using SSH, ensure your key is configured. If using HTTPS, you'll need a personal access token.

### 6. Open a Pull Request on GitHub

1. Go to your repository on GitHub: `https://github.com/<your-username>/web-vuln-scanner`
2. You should see a banner suggesting to create a PR for the `iteration-3-owasp` branch
3. Click **"Compare & pull request"** (or go to the Pulls tab and create a new PR manually)
4. Fill in the PR details:
   - **Title:** `Iteration 3: OWASP Top 10 Scanners`
   - **Description:** Copy and paste the contents of `PR_DESCRIPTION.md` (located in the repo root)
   - **Reviewers:** Assign reviewers if applicable
   - **Labels:** Add labels like `enhancement`, `security`, `testing`

5. Click **"Create pull request"**

### 7. Verify and Merge (When Ready)

- GitHub Actions (if configured) will run tests automatically
- Request reviews from team members
- After approval, merge the PR using the GitHub UI

## Troubleshooting

### Git Not Found

If you get "git is not recognized," ensure git is installed and available in your system PATH.

**Install Git:**
- Download from https://git-scm.com/download/win
- During installation, select "Add Git to PATH"
- Restart PowerShell after installation

### Authentication Errors

**If using HTTPS:**
```powershell
# Git will prompt for credentials; use your GitHub username and a personal access token
# (not your password)
```

**If using SSH:**
```powershell
# Ensure your SSH key is added to your GitHub account
ssh -T git@github.com  # Test SSH connection
```

### Branch Already Exists

If the branch exists locally:
```powershell
git branch -D iteration-3-owasp  # Delete the local branch
git checkout -b iteration-3-owasp  # Recreate it
```

### Changes Not Staged

Ensure all changes are added:
```powershell
git status  # View unstaged changes
git add .   # Stage all
git commit -m "..."
```

## Summary of Files Ready to Push

The following files are included in this commit:

**New Scanners:**
- `src/scanner/plugins/csrf_scanner.py`
- `src/scanner/plugins/auth_flaws_scanner.py`
- `src/scanner/plugins/insecure_deserialization_scanner.py`

**New Tests:**
- `tests/test_csrf_scanner.py`
- `tests/test_auth_flaws_scanner.py`
- `tests/test_insecure_deserialization_scanner.py`
- `tests/test_url_fetching.py`

**Documentation:**
- `README.md` (updated with Iteration 3 section)
- `ITERATION_3_SUMMARY.md`
- `PR_DESCRIPTION.md`

---

**All 93 tests passing ✅ — Ready for review and merge.**

