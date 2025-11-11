# Quick Reference Card

## 🚀 Quick Start

```bash
# Setup
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Test
pytest tests/ -v          # All tests (50 ✅)
pytest tests/test_xss_scanner.py -v

# Run
python -m flask --app src.api.app:app run
```

## 📍 API Endpoints

```bash
# Start scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Check status
curl http://localhost:5000/scan/status/123

# Get results
curl http://localhost:5000/scan/results/123
```

## 🔧 Configuration

```python
# Get config
from src.config import get_config
config = get_config()

# Set environment
FLASK_ENV=development   # Debug ON, lax limits
FLASK_ENV=production    # Debug OFF, strict (50 req/60s)
FLASK_ENV=testing       # Fast, no rate limiting
```

## 🧬 Scanning

```python
# XSS Scanner
from src.scanner.plugins.xss_scanner import XSSScanner
scanner = XSSScanner()
result = scanner.scan("<script>alert(1)</script>")

# Link Scanner
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
scanner = MediaLinkScanner()
result = scanner.scan("https://example.com")

# Multiple Plugins
from src.scanner.engine import Engine
engine = Engine()
engine.load_plugins([XSSScanner(), MediaLinkScanner()])
results = engine.run_scan("https://example.com")
```

## 📋 Features Detected

### XSS Scanner
- Script tags: `<script>...</script>`
- Event handlers: `onclick="..."`, `onerror="..."`
- JavaScript protocol: `href="javascript:"`
- Dangerous functions: `eval()`, `innerHTML`, `new Function()`
- Unescaped output: `{{ var }}`, `${ var }`

### Link Scanner
- Insecure protocols: `http://`
- Suspicious domains: malicious.test, bad.example
- Unreachable resources: dead links

## 🧪 Test Coverage

```
✅ 50 Total Tests
  - 17 Configuration tests
  - 15 XSS scanner tests
  - 8 Link scanner tests
  - 6 Middleware tests
  - 4 Core/Engine tests
```

## 📚 Documentation

| File | Purpose |
|------|---------|
| README.md | Main documentation |
| USAGE_GUIDE.md | API examples |
| ADVANCED_FEATURES.md | Advanced usage |
| ITERATION_2_SUMMARY.md | Recent changes |
| PROJECT_STATUS.md | Complete status |

## 🔐 Security Headers (Auto-Applied)

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; ...
```

## ⚡ Performance

- **Regex-based detection**: O(n) complexity
- **Single-pass scanning**: No multiple passes
- **Singleton config**: Minimal overhead
- **Memory efficient**: No large intermediates

## 🛠️ Create Custom Plugin

```python
# src/scanner/plugins/my_plugin.py
class MyPlugin:
    def scan(self, target=None):
        findings = []
        # Your logic
        return {"vulnerabilities": findings}

# Use it
from src.scanner.engine import Engine
engine = Engine()
engine.load_plugins([MyPlugin()])
```

## 🔍 Severity Levels

```
🔴 CRITICAL: eval(), setTimeout(eval())
🟠 HIGH: Script tags, event handlers, javascript:
🟡 MEDIUM: document.write(), unescaped output
🟢 LOW: Informational
```

## 🐛 Troubleshooting

```bash
# Check config
python -c "from src.config import get_config; print(get_config().to_json())"

# Verify app starts
python -c "from src.api.app import create_app; print('OK' if create_app() else 'FAIL')"

# Run specific test
pytest tests/test_xss_scanner.py::TestXSSScanner::test_detect_eval_usage -v
```

## 📦 Dependencies

- Flask >= 2.3.0 (Web framework)
- requests >= 2.25.1 (HTTP client)
- beautifulsoup4 >= 4.9.0 (HTML parsing)
- pytest >= 6.2.4 (Testing)

## 🚢 Deployment

```bash
# Production
FLASK_ENV=production gunicorn -w 4 -b 0.0.0.0:5000 src.api.app:app

# Development
FLASK_ENV=development python -m flask --app src.api.app:app run

# Docker
docker build -t web-vuln-scanner .
docker run -p 5000:5000 web-vuln-scanner
```

## 📞 Status

✅ **50/50 Tests Passing**  
✅ **Production Ready**  
✅ **Fully Documented**  

---

**Last Updated**: November 11, 2025  
**Version**: 2.0 - With XSS Scanner & Config System
