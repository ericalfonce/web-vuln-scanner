# Architecture of the Web Vulnerability Scanner

## Overview
The Web Vulnerability Scanner is designed to identify and report security vulnerabilities in web applications while providing Cloudflare-like protection features. It employs a modular architecture that allows for easy extension and customization through plugins. The scanner now includes:

- **Vulnerability Detection**: Multi-plugin scanning engine
- **Media & Link Analysis**: Detects insecure links, suspicious domains, and unreachable resources
- **Web Application Protection**: Security headers, basic rate-limiting, and blocklist support
- **REST API**: Easy integration for automated scanning workflows

## Components

### 1. Core
The core of the scanner is responsible for managing the scanning process. It includes the `Scanner` class, which orchestrates the scanning workflow, including starting and stopping scans.

### 2. Engine
The scanning engine is implemented in the `Engine` class. This component is responsible for executing the scans, loading plugins, and applying rules to detect vulnerabilities. It normalizes plugin outputs into a standard `{"vulnerabilities": [...]}` structure.

**Features**:
- Plugin discovery and loading
- Multi-plugin parallel execution
- Error handling for plugin failures
- Standard output normalization

### 3. Plugins
The plugin system allows for the addition of custom vulnerability checks. Each plugin is a separate module that implements a specific vulnerability detection method.

**Built-in Plugins**:
- **ExamplePlugin**: Demonstrates the plugin interface
- **MediaLinkScanner**: Scans HTML content for insecure links, suspicious domains, and unreachable resources

**Plugin Interface**:
```python
class PluginName:
    def scan(self, target=None):
        """
        Args:
            target: URL string, HTML string, or any scannable content
        
        Returns:
            {"vulnerabilities": [
                {"url": "...", "issue": "...", "severity": "..."},
                ...
            ]}
        """
        pass
```

### 4. Rules
The rules directory contains predefined rules for detecting specific types of vulnerabilities, such as SQL injection. Each rule is encapsulated in its own class, making it easy to add new rules as needed.

### 5. API & Protection Middleware
The API component provides a web interface for interacting with the scanner using Flask. It now includes WAF-like protection features:

**Security Headers**:
- `X-Content-Type-Options: nosniff` - Prevents MIME-sniffing
- `X-Frame-Options: DENY` - Prevents clickjacking
- `Content-Security-Policy` - Restricts resource loading
- `Referrer-Policy: no-referrer` - Controls referrer information

**Protection Features**:
- **Rate Limiting**: Configurable per-IP request windows
- **IP Blocklist**: Dynamic blocking of suspicious IPs
- **Request Inspection**: Before/after request hooks for custom logic

### 6. CLI
The command-line interface (CLI) allows users to interact with the scanner via terminal commands. This component is useful for automation and integration into CI/CD pipelines.

### 7. Models
The models define the data structures used throughout the application. The `Finding` class represents the results of a scan, including details about the vulnerabilities detected.

### 8. Utilities
Utility functions for network operations are provided to simplify tasks such as:
- Making HTTP GET/POST requests
- Checking URL reachability
- Handling network errors gracefully

## Workflow

### Scanning Workflow
1. The user initiates a scan via the CLI or API with a target URL or HTML content.
2. The `Scanner` class starts the scanning process, utilizing the `Engine` to run the scan.
3. The `Engine` loads plugins and executes them sequentially or in parallel.
4. Each plugin returns findings in a normalized format.
5. Results are aggregated and stored as instances of the `Finding` class.
6. Results can be accessed through the API or displayed in the CLI.

### Protection Workflow
1. Client request arrives at the Flask app.
2. **before_request hook** checks if the IP is blocklisted (returns 403 if blocked).
3. **before_request hook** enforces rate limiting per IP/time-window (returns 429 if exceeded).
4. Request is processed normally.
5. **after_request hook** appends security headers to the response.

## Media & Link Scanner Details

The `MediaLinkScanner` plugin:
- **Extracts links** from HTML using regex (href, src attributes)
- **Checks protocol security**: Flags `http://` as insecure (medium severity)
- **Checks domain reputation**: Flags suspicious domains (high severity)
- **Validates reachability**: Performs HEAD requests to verify link accessibility
- **Handles errors**: Returns "unreachable" findings for failed requests

Example scan result:
```json
{
  "vulnerabilities": [
    {
      "url": "http://insecure.com",
      "issue": "insecure_protocol",
      "severity": "medium"
    },
    {
      "url": "https://malicious.test",
      "issue": "suspicious_domain",
      "severity": "high"
    }
  ]
}
```

## Extending the System

### Adding a New Plugin
1. Create a new file in `src/scanner/plugins/` (e.g., `my_scanner.py`)
2. Implement a class with `scan(self, target=None)` method
3. Return findings as `{"vulnerabilities": [...]}`
4. Register in `Engine.load_plugins()` or wire into your scan initiation logic

### Adding Protection Rules
Modify `src/api/middleware.py` to add custom logic:
- Add validators in `before_request`
- Add response transformers in `after_request`
- Integrate with external WAF/IDS systems

## Conclusion
This architecture provides a flexible and extensible framework for building a web vulnerability scanner with integrated protection features. By separating concerns into distinct components, the system can be easily maintained and enhanced with new features. The system is designed to be simple to start with and scalable for production use.