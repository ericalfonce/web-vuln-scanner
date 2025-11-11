from flask import Blueprint, request, jsonify, render_template
from src.scanner.engine import Engine
from src.scanner.plugins.media_link_scanner import MediaLinkScanner
from src.scanner.plugins.xss_scanner import XSSScanner
from src.scanner.plugins.csrf_scanner import CSRFScanner
from src.scanner.plugins.auth_flaws_scanner import AuthenticationFlawsScanner
from src.scanner.plugins.insecure_deserialization_scanner import InsecureDeserializationScanner

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

@routes_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "scanners_available": len(SCANNER_REGISTRY)
    }), 200

def setup_routes(app):
    """Register all routes with the Flask app"""
    app.register_blueprint(routes_bp)