# Web Vulnerability Scanner

A modular web vulnerability scanner with Cloudflare-like protection features. Automatically detects security vulnerabilities in web applications, scans links and media for insecure or malicious resources, provides XSS detection, and provides WAF-like protection with security headers and rate limiting.

## ✨ Key Features

### Scanning & Detection
- **Multi-plugin scanning engine**: Easily extensible architecture for custom vulnerability checks
- **SQL Injection detection**: Pre-built SQL injection pattern detection
- **Media & Link Analysis**: 
  - Extracts and analyzes all links and media from web pages
  - Detects insecure protocols (http:// vs https://)
  - Identifies suspicious domains in a watchlist
  - Validates link reachability
- **XSS (Cross-Site Scripting) Detection** ⭐ NEW:
  - Detects inline script tags and event handlers
  - Identifies dangerous functions (eval, innerHTML, etc.)
  - Flags JavaScript protocol handlers
  - Detects unescaped output and template injection
  - Pattern matching for common XSS payloads
- **RESTful API**: Programmatic scanning and result retrieval
- **CLI Interface**: Command-line tools for automation and CI/CD integration

### Web Application Protection
- **Security Headers**:
  - Content-Security-Policy (CSP)
  - X-Content-Type-Options (nosniff)
  - X-Frame-Options (DENY - clickjacking protection)
  - Referrer-Policy (no-referrer)
  
- **Rate Limiting**: Per-IP request throttling to prevent abuse
- **IP Blocklist**: Dynamic blocking of suspicious clients
- **Before/After Request Hooks**: Extensible protection middleware

### Configuration & Management ⭐ NEW
- **Environment-based configuration** (Development/Production/Testing)
- **Centralized settings management** for plugins, rate limits, security headers
- **JSON/environment variable configuration** loading
- **Production-ready defaults** with security best practices

## 📋 Installation

### Prerequisites
- Python 3.8+
- pip or conda

### Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd web-vuln-scanner
```

2. **Create a virtual environment** (recommended):
```bash
python -m venv .venv
.venv\Scripts\activate  # On Windows
# or: source .venv/bin/activate  # On macOS/Linux
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## 🚀 Quick Start

### Running the API Server

```bash
python -m flask --app src.api.app:app run
# Server will start at http://localhost:5000
```

### Scanning a Website

**Via API** (POST request):
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

Response:
```json
{
  "message": "Scan started",
  "data": {
    "target": "https://example.com"
  }
}
```

**Check scan results**:
```bash
curl http://localhost:5000/scan/results/scan-id-123
```

### Using the CLI

```bash
python src/cli/cli.py --help
```

## 📁 Project Structure

```
web-vuln-scanner/
├── src/
│   ├── main.py                    # Entry point
│   ├── api/
│   │   ├── app.py                # Flask application factory
│   │   ├── routes.py             # API endpoints
│   │   └── middleware.py         # Security headers & rate limiting
│   ├── cli/
│   │   ├── __init__.py
│   │   └── cli.py                # Command-line interface
│   ├── scanner/
│   │   ├── core.py               # Scanner orchestration
│   │   ├── engine.py             # Scanning engine
│   │   ├── plugins/
│   │   │   ├── example_plugin.py
│   │   │   └── media_link_scanner.py  # NEW: Link & media analysis
│   │   └── rules/
│   │       └── sql_injection.py
│   ├── models/
│   │   └── finding.py            # Finding data model
│   └── utils/
│       └── network.py            # Network utilities
├── tests/
│   ├── test_core.py              # Scanner tests
│   ├── test_engine.py            # Engine tests
│   ├── test_media_link_scanner.py # NEW: Link scanner tests
│   └── test_middleware.py        # NEW: Protection middleware tests
├── requirements.txt              # Python dependencies
├── setup.cfg                     # Setup configuration
├── pyproject.toml               # Project metadata
└── docs/
    └── architecture.md          # Detailed architecture documentation
```

## 🔧 Plugin Development

### Creating a Custom Scanner Plugin

1. Create a new file in `src/scanner/plugins/`:

```python
# src/scanner/plugins/my_scanner.py
class MyCustomScanner:
    def scan(self, target=None):
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: URL string or HTML content to scan
            
        Returns:
            dict with "vulnerabilities" key containing list of findings
        """
        findings = []
        
        # Your scanning logic here
        if some_vulnerability_found:
            findings.append({
                "url": target_or_location,
                "issue": "vulnerability_type",
                "severity": "high|medium|low"
            })
        
        return {"vulnerabilities": findings}
```

2. Register the plugin in your scanning workflow:

```python
from src.scanner.engine import Engine
from src.scanner.plugins.my_scanner import MyCustomScanner

engine = Engine()
engine.load_plugins([MyCustomScanner()])
results = engine.run_scan("https://example.com")
```

## 🧪 Testing

Run all tests:
```bash
pytest tests/ -v
```

Run specific test file:
```bash
pytest tests/test_media_link_scanner.py -v
```

Run with coverage:
```bash
pytest tests/ --cov=src --cov-report=html
```

### Test Coverage
- **4** Scanner & Engine tests
- **8** Media/Link scanner plugin tests  
- **6** Protection middleware tests
- **18 total tests** ✅ All passing

## 📊 Scanning Example

When you scan a website, the system:

1. **Fetches** the target webpage
2. **Extracts** all links and media resources
3. **Analyzes** each resource for security issues:
   - Insecure protocol (http://)
   - Known malicious domains
   - Unreachable resources
4. **Returns** a detailed report with findings and severity levels

### Example Output

```json
{
  "vulnerabilities": [
    {
      "url": "http://external-api.old-domain.com/data.json",
      "issue": "insecure_protocol",
      "severity": "medium"
    },
    {
      "url": "https://malicious.test/tracking.js",
      "issue": "suspicious_domain",
      "severity": "high"
    },
    {
      "url": "https://cdn.example.com/file.pdf",
      "issue": "unreachable",
      "severity": "medium"
    }
  ]
}
```

## 🛡️ Protection Features

### Security Headers
All API responses automatically include security headers:
- Prevents MIME-type sniffing attacks
- Protects against clickjacking (iframe injection)
- Restricts resource loading with CSP
- Controls referrer information leakage

### Rate Limiting
- **Default**: 100 requests per 60 seconds per IP
- **Configurable** in `src/api/middleware.py`
- IPs exceeding limit are temporarily blocklisted

### IP Blocklist
- Dynamic blocking of suspicious IPs
- Can be extended for integration with IDS/IPS systems
- Supports manual IP management

## 🔍 Architecture

See [docs/architecture.md](docs/architecture.md) for a detailed breakdown of components, workflows, and extension points.

## 🚧 Future Enhancements

- [ ] Persistent rate limiting with Redis
- [ ] WAF rule engine for advanced pattern matching
- [ ] Signature-based malware detection
- [ ] Integration with threat intelligence feeds
- [ ] Concurrent/async scanning for improved performance
- [ ] Web UI dashboard for scan visualization
- [ ] Webhook notifications for scan completion
- [ ] OWASP Top 10 vulnerability checks
- [ ] API key-based authentication
- [ ] Detailed remediation recommendations

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Add tests for new functionality
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 📞 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Made with ❤️ for a more secure web**

## Iteration 3 — OWASP Top 10 Scanners (Added)

This release expands the scanner to include multiple OWASP Top 10 related checks as separate plugins. The new scanners are:

- `CSRFScanner` — Detects missing CSRF tokens, AJAX requests without CSRF headers, unvalidated redirects, and GET-based state-changing forms.
- `AuthenticationFlawsScanner` — Detects weak password handling, default credentials, password transmission over HTTP/GET, missing password confirmation fields, and session issues.
- `InsecureDeserializationScanner` — Detects unsafe pickle/yaml/xml/json patterns, gadget-chain indicators (Java), and unsafe eval/exec usage.

Usage examples

Programmatic usage (scan a URL or HTML content):

```python
from src.scanner.plugins.csrf_scanner import CSRFScanner
from src.scanner.plugins.auth_flaws_scanner import AuthenticationFlawsScanner
from src.scanner.plugins.insecure_deserialization_scanner import InsecureDeserializationScanner

cs = CSRFScanner()
ascan = AuthenticationFlawsScanner()
ids = InsecureDeserializationScanner()

# Scan a URL (the scanner will fetch the page via src.utils.network.make_get_request)
result = cs.scan("https://example.com")
print(result)

# Or scan HTML content directly
html = '<form method="POST"><input type="hidden" name="csrf_token" value="x" /></form>'
print(ascan.scan(html))

# For deserialization checks use snippet or code strings
code = 'pickle.loads(user_input)'
print(ids.scan(code))
```

Notes

- The scanners accept either a URL (string starting with `http://` or `https://`) or raw content (HTML or code snippet). When given a URL the scanner will call `src.utils.network.make_get_request(url)` to fetch content — tests include mocked network calls to validate this behavior.
- Issue keys and severity levels follow the project's existing finding model: each finding is a dict with `url`, `issue`, `severity`, and optional `description` and `context`.

See `ITERATION_3_SUMMARY.md` for an executive summary of the changes and test results.