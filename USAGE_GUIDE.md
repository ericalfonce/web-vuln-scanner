# Web Vuln Scanner - Usage Examples

This guide demonstrates the new Cloudflare-like scanning and protection features added to the web vulnerability scanner.

## Quick Start

### 1. Install & Setup

```bash
# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Tests

```bash
# Run all tests (18 tests, all passing)
pytest tests/ -v

# Run specific test suite
pytest tests/test_media_link_scanner.py -v
pytest tests/test_middleware.py -v
```

### 3. Start the API Server

```bash
# Using Flask development server
python -m flask --app src.api.app:app run

# Using Python directly
python -m src.api.app
```

The server will start at `http://localhost:5000`

## API Endpoints

### Initiate a Scan

**Endpoint**: `POST /scan`

**Request**:
```json
{
  "target": "https://example.com"
}
```

**Response** (202 Accepted):
```json
{
  "message": "Scan started",
  "data": {
    "target": "https://example.com"
  }
}
```

**Example using curl**:
```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

### Check Scan Status

**Endpoint**: `GET /scan/status/<scan_id>`

**Response**:
```json
{
  "scan_id": "123",
  "status": "in progress"
}
```

### Get Scan Results

**Endpoint**: `GET /scan/results/<scan_id>`

**Response**:
```json
{
  "scan_id": "123",
  "results": [
    {
      "url": "http://insecure.com/data.json",
      "issue": "insecure_protocol",
      "severity": "medium"
    },
    {
      "url": "https://malicious.test/tracking.js",
      "issue": "suspicious_domain",
      "severity": "high"
    }
  ]
}
```

## Security Headers

All responses automatically include Cloudflare-like security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none';
```

**Verify headers**:
```bash
curl -I http://localhost:5000/scan/status/123

# Output includes:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Content-Security-Policy: ...
```

## Media & Link Scanner Plugin

The new `MediaLinkScanner` plugin analyzes web pages for security issues.

### How It Works

1. **Extracts links** from HTML (href, src attributes)
2. **Checks for insecure protocols** (http:// flagged as medium severity)
3. **Checks for suspicious domains** (matches watchlist, high severity)
4. **Validates reachability** (performs HEAD requests)

### Programmatic Usage

```python
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.engine import Engine

# Initialize scanner
scanner = MediaLinkScanner()

# Scan raw HTML content
html_content = '''
<html>
  <a href="http://insecure.com">Bad Link</a>
  <a href="https://malicious.test">Suspicious</a>
  <img src="https://safe.com/image.jpg" />
</html>
'''

result = scanner.scan(html_content)
print(result)

# Output:
# {
#   "vulnerabilities": [
#     {"url": "http://insecure.com", "issue": "insecure_protocol", "severity": "medium"},
#     {"url": "https://malicious.test", "issue": "suspicious_domain", "severity": "high"}
#   ]
# }
```

### Scan from URL

```python
from src.scanner.plugins.media_link_scanner import MediaLinkScanner

scanner = MediaLinkScanner()

# Scan from URL (fetches page automatically)
result = scanner.scan("https://example.com")

print(f"Found {len(result['vulnerabilities'])} security issues")
for finding in result['vulnerabilities']:
    print(f"  - {finding['url']}: {finding['issue']} ({finding['severity']})")
```

### Using with Engine

```python
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner

# Create engine and load plugin
engine = Engine()
engine.load_plugins([MediaLinkScanner()])

# Run scan
results = engine.run_scan("https://example.com")

# Results are normalized
print(results)
# Output: {"vulnerabilities": [...]}
```

## Protection Features

### Rate Limiting

The middleware includes per-IP rate limiting:

- **Limit**: 100 requests per 60-second window
- **Violation**: Returns `429 Too Many Requests`

**Configuration** (in `src/api/middleware.py`):
```python
RATE_LIMIT = 100  # requests per window
WINDOW_SECONDS = 60  # time window
```

### IP Blocklist

The middleware maintains a dynamic IP blocklist:

```python
from src.api.middleware import BLOCKED_IPS

# Manually add an IP to blocklist
BLOCKED_IPS.add("192.168.1.100")

# Blocked IPs receive 403 Forbidden
```

## Advanced Usage

### Creating a Custom Scanner Plugin

```python
# src/scanner/plugins/my_custom_scanner.py
from src.utils import network

class MyCustomScanner:
    def scan(self, target=None):
        """Custom vulnerability scanner."""
        findings = []
        
        # Fetch content if URL provided
        if target and target.startswith("http"):
            content = network.make_get_request(target)
            if not content:
                return {"vulnerabilities": [{"url": target, "issue": "unreachable", "severity": "high"}]}
        else:
            content = target
        
        # Your scanning logic
        if "dangerous_pattern" in (content or ""):
            findings.append({
                "url": target,
                "issue": "dangerous_pattern_detected",
                "severity": "high"
            })
        
        return {"vulnerabilities": findings}
```

Register and use:
```python
from src.scanner.engine import Engine
from src.scanner.plugins.my_custom_scanner import MyCustomScanner

engine = Engine()
engine.load_plugins([MyCustomScanner()])
results = engine.run_scan("https://example.com")
```

### Extending the Middleware

Add custom security checks:

```python
# Modify src/api/middleware.py
def init_app(app):
    @app.before_request
    def _custom_security_check():
        # Add your custom logic
        ip = request.remote_addr
        if is_suspicious_ip(ip):
            return {"error": "Access denied"}, 403
    
    @app.after_request
    def _add_custom_header(response):
        response.headers["X-Custom-Header"] = "value"
        return response
```

## Severity Levels

Findings are categorized by severity:

- **high**: Critical security issue (e.g., suspicious/malicious domain)
- **medium**: Important to address (e.g., insecure protocol, unreachable resource)
- **low**: Informational or minor issue

## Test Coverage

The project includes comprehensive test coverage:

- **4 tests** for core Scanner and Engine
- **8 tests** for MediaLinkScanner plugin
  - Link extraction
  - Protocol security
  - Domain reputation
  - Reachability checks
  - Severity levels
  - Error handling

- **6 tests** for protection middleware
  - Security headers presence
  - CSP content validation
  - Response codes
  - Header application on all endpoints

**Run tests**:
```bash
# All tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src --cov-report=html
```

## Performance Tips

1. **Cache DNS lookups** when scanning many links
2. **Use async requests** for concurrent scanning (future enhancement)
3. **Implement Redis-backed rate limiting** for production (future enhancement)
4. **Add request timeout** to prevent hanging on unresponsive sites

## Troubleshooting

### Flask app won't start
```bash
# Verify imports work
python -c "from src.api.app import create_app; print('OK')"

# Check Python path
set PYTHONPATH=%CD%
python -m flask --app src.api.app:app run
```

### Tests failing with import errors
```bash
# Ensure virtual environment is activated
.venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Media scanner missing links
- Check regex pattern in `MediaLinkScanner._extract_links()`
- Use BeautifulSoup instead (can add to requirements):
  ```bash
  pip install beautifulsoup4
  ```

## Next Steps

- Add more plugins for OWASP Top 10 vulnerabilities
- Implement persistent rate limiting with Redis
- Build a web UI dashboard
- Add webhook notifications
- Integrate threat intelligence feeds
- Support for authenticated scanning

---

For more details, see [docs/architecture.md](../docs/architecture.md)
