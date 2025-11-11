from flask import Blueprint, request, jsonify, render_template
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.plugins.xss_scanner import XSSScanner
from src.scanner.plugins.csrf_scanner import CSRFScanner
from src.scanner.plugins.auth_flaws_scanner import AuthenticationFlawsScanner
from src.scanner.plugins.insecure_deserialization_scanner import InsecureDeserializationScanner
from src.scanner.dynamic import DynamicScanner, PlaywrightNotInstalled
from src.scanner.sarif import generate_sarif

routes_bp = Blueprint('routes', __name__)

# Scanner registry mapping class names to scanner instances
SCANNER_REGISTRY = {
    'MediaLinkScanner': MediaLinkScanner(),
    'XSSScanner': XSSScanner(),
    'CSRFScanner': CSRFScanner(),
    'AuthenticationFlawsScanner': AuthenticationFlawsScanner(),
    'InsecureDeserializationScanner': InsecureDeserializationScanner()
}

# ============================================================================
# GUI ROUTES
# ============================================================================

@routes_bp.route('/', methods=['GET'])
def dashboard():
    """Serve the main dashboard page"""
    return render_template('index.html')

# ============================================================================
# API ROUTES
# ============================================================================

@routes_bp.route('/scan', methods=['POST'])
def start_scan():
    """
    Execute a scan on the target with selected scanners.
    
    Request body:
    {
        "target": "https://example.com or HTML content",
        "scanners": ["CSRFScanner", "XSSScanner", ...]  # optional
    }
    
    Response:
    {
        "vulnerabilities": [
            {"url": "...", "issue": "...", "severity": "..."},
            ...
        ]
    }
    """
    try:
        data = request.json or {}
        target = data.get('target', '').strip()
        requested_scanners = data.get('scanners', list(SCANNER_REGISTRY.keys()))
        
        if not target:
            return jsonify({"error": "Target URL or content is required"}), 400
        
        # Validate scanner names
        available_scanners = [s for s in requested_scanners if s in SCANNER_REGISTRY]
        if not available_scanners:
            available_scanners = list(SCANNER_REGISTRY.keys())
        
        # Run scans
        all_vulnerabilities = []
        for scanner_name in available_scanners:
            try:
                scanner = SCANNER_REGISTRY[scanner_name]
                result = scanner.scan(target)
                if result and 'vulnerabilities' in result:
                    all_vulnerabilities.extend(result['vulnerabilities'])
            except Exception as e:
                print(f"Error running {scanner_name}: {str(e)}")
                # Continue with other scanners if one fails
                continue
        
        return jsonify({
            "target": target,
            "vulnerabilities": all_vulnerabilities,
            "scanners_used": available_scanners,
            "count": len(all_vulnerabilities)
        }), 200
    
    except Exception as e:
        print(f"Scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@routes_bp.route('/scan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    """Get status of a specific scan"""
    # For now, since we run synchronously, status is always complete
    return jsonify({"scan_id": scan_id, "status": "complete"}), 200

@routes_bp.route('/scan/results/<scan_id>', methods=['GET'])
def scan_results(scan_id):
    """Get results of a specific scan"""
    # For now, returns empty results
    return jsonify({"scan_id": scan_id, "results": []}), 200

@routes_bp.route('/scanners', methods=['GET'])
def get_scanners():
    """Get list of available scanners"""
    return jsonify({
        "scanners": list(SCANNER_REGISTRY.keys()),
        "count": len(SCANNER_REGISTRY)
    }), 200


@routes_bp.route('/scan/auth', methods=['POST'])
def start_authenticated_scan():
    """
    Start an authenticated, headless browser-driven scan.

    Request body (JSON):
    {
        "target": "https://example.com",
        "username": "user",            # optional
        "password": "pass",            # optional
        "login_url": "https://example.com/login",  # optional
        "login_script": "<python snippet>",      # optional
        "safe_mode": true                # optional (default true)
    }

    Response: JSON with findings and artifact paths (screenshot, html)
    """
    try:
        data = request.json or {}
        target = data.get('target', '').strip()
        username = data.get('username')
        password = data.get('password')
        login_url = data.get('login_url')
        login_script = data.get('login_script')
        safe_mode = data.get('safe_mode', True)

        if not target:
            return jsonify({"error": "Target URL is required"}), 400

        try:
            scanner = DynamicScanner(headless=True, artifacts_dir=data.get('artifacts_dir', './artifacts'))
        except PlaywrightNotInstalled as e:
            return jsonify({"error": str(e)}), 500

        p, browser, context, page = scanner.prepare_session(
            login_script=login_script, username=username, password=password, login_url=login_url
        )

        try:
            result = scanner.run_checks(page, target_url=target)
        finally:
            try:
                browser.close()
                p.stop()
            except Exception:
                pass

        return jsonify({
            "target": target,
            "findings": result.get('findings', []),
            "artifacts": result.get('artifacts', {})
        }), 200

    except Exception as e:
        print(f"Authenticated scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@routes_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "scanners_available": len(SCANNER_REGISTRY)
    }), 200


@routes_bp.route('/scan/export/sarif', methods=['POST'])
def export_sarif():
    """Export findings to SARIF format (GitHub Code Scanning compatible).

    Request body:
    {
        "findings": [...],
        "target": "https://example.com"
    }

    Response: SARIF JSON
    """
    try:
        data = request.json or {}
        findings = data.get('findings', [])
        target = data.get('target', 'unknown')

        sarif_report = generate_sarif(findings, target)

        return jsonify(sarif_report), 200

    except Exception as e:
        print(f"SARIF export error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def setup_routes(app):
    """Register all routes with the Flask app"""
    app.register_blueprint(routes_bp)