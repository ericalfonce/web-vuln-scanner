# 🎨 Web Dashboard — Quick Start Guide

## Launch the Dashboard in 30 Seconds

### Step 1: Activate Environment

```bash
cd c:\Users\HP\Music\web-vuln-scanner
.venv\Scripts\activate
```

### Step 2: Start Flask Server

```bash
python -m flask --app src.api.app:app run
```

**Expected output:**

```text
 * Running on http://127.0.0.1:5000
```

### Step 3: Open Browser

Open [http://localhost:5000](http://localhost:5000)

**You should see:** A modern dashboard with a scan form on the left and results panel on the right.

---

## Using the Dashboard

### Scan a Website

1. **Paste URL:**

   ```text
   https://example.com
   ```

2. **Select Scanners:**
   - ☑️ Media & Links
   - ☑️ XSS Detection
   - ☑️ CSRF Protection
   - ☐ Auth Flaws (optional)
   - ☐ Deserialization (optional)

3. **Click "Start Scan"** → Wait for results

4. **View Results:**
   - 🔴 Critical (red) — Must fix
   - 🟠 High (orange) — Should fix
   - 🟡 Medium (yellow) — Consider fixing
   - 🟢 Low (green) — Informational

5. **Export JSON:**
   - Click "📥 Export Results (JSON)"
   - Save for your security reports

---

## Scan Examples

### Example 1: Scan a Real Website

```text
Target: https://github.com
Scanners: All selected
Result: Displays media/link issues
```

### Example 2: Scan HTML Form

Paste this HTML:

```html
<html>
  <form method="POST" action="/login">
    <input type="text" name="user" />
    <input type="password" name="pass" />
    <button>Login</button>
  </form>
</html>
```

Result: Detects missing CSRF token

### Example 3: Scan for XSS

Paste this code:

```html
<script>
  document.body.innerHTML = userInput;
  eval(someCode);
</script>
```

Result: Detects innerHTML and eval vulnerabilities

### Example 4: Scan for Auth Issues

Paste this Python code:

```python
if password_length < 4:
    allow_login()
```

Result: Detects weak password policy

### Example 5: Scan for Deserialization

Paste this code:

```python
import pickle
user_obj = pickle.loads(request.data)
```

Result: Detects unsafe pickle usage

---

## Debugging in Browser

### Open Developer Console

```text
F12 or Ctrl+Shift+I
```

### Check Scan State

```javascript
window.debugDashboard.state
// Shows:
// {
//   scanResults: {...},
//   isScanning: false,
//   lastScanTime: Date
// }
```

### Manually Render Results

```javascript
const vulns = [
  {url: "example.com", issue: "test_issue", severity: "high"}
];
window.debugDashboard.displayResults(vulns, "test");
```

### Show Custom Notification

```javascript
window.debugDashboard.showNotification("Test message", "success");
// Types: "success", "error", "info"
```

---

## Troubleshooting

### Problem: "Cannot connect to server"

**Solution:** Make sure Flask is running

```bash
python -m flask --app src.api.app:app run
```

### Problem: "Dashboard loads but won't scan"

**Solution:** Check browser console (F12) for errors

- Look at Console tab
- Look at Network tab → /scan request
- Check if scanners are selected

### Problem: "Results don't appear"

**Solution:**

1. Clear browser cache (Ctrl+Shift+Delete)
2. Refresh page (F5)
3. Check Network tab to see response

### Problem: "CSS/styling looks broken"

**Solution:**

1. Hard refresh: Ctrl+Shift+R (or Cmd+Shift+R on Mac)
2. Clear all browser cache
3. Check if `static/css/style.css` is loading (Network tab)

### Problem: "Export button doesn't work"

**Solution:** Check browser console for errors

```javascript
// Manually download results
const data = window.debugDashboard.state.scanResults;
console.log(data);
// Copy and paste into a text file
```

---

## Features Overview

| Feature | Description |
|---------|-------------|
| 🎯 URL Input | Scan websites by URL or paste HTML/code |
| ☑️ Scanner Selection | Choose which scanners to run |
| 🚀 Start Scan | Begin scanning with visual feedback |
| 📊 Real-time Results | See vulnerabilities as they're detected |
| 🎨 Color Coding | Severity levels shown in color |
| 📥 Export JSON | Download results for reporting |
| 📈 Statistics | Summary of findings by severity |
| 🔍 Debugging | Browser console tools for developers |

---

## API Endpoints (Advanced)

### Scan via curl

```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "scanners": ["XSSScanner", "CSRFScanner"]
  }'
```

### Get Available Scanners

```bash
curl http://localhost:5000/scanners
```

### Health Check

```bash
curl http://localhost:5000/health
```

---

## Performance Tips

### For Large Scans

- Start with fewer scanners
- Use simple HTML snippets instead of full pages
- Monitor network tab for request time

### For Best Results

- Use Firefox or Chrome (latest versions)
- Disable extensions that might interfere
- Keep the tab focused while scanning

### Export Results

- Results are saved as JSON
- Timestamp in filename: `scan-results-2025-11-11.json`
- Can be parsed by any JSON reader

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `F12` | Open Developer Tools |
| `Ctrl+Shift+I` | Open Developer Tools (alt) |
| `F5` | Refresh page |
| `Ctrl+Shift+R` | Hard refresh (clear cache) |
| `Tab` | Navigate form fields |
| `Enter` | Submit form (if focused) |

---

## Next Steps

1. ✅ Run your first scan
2. ✅ Try different inputs (URL, HTML, code)
3. ✅ Export results
4. ✅ Check browser console
5. ✅ Explore the code in `src/api/static/`

**Questions?** Check `GUI_FEATURE_SUMMARY.md` for technical details.

---

**Dashboard is production-ready!** 🚀
