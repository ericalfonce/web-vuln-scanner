"""
GUI tests for the Web Vulnerability Scanner dashboard.
Tests template rendering, form submission, and results display.
"""

import pytest
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.api.app import create_app


@pytest.fixture
def app():
    """Create and configure a test Flask app"""
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()


class TestDashboardGUI:
    """Test dashboard template rendering"""
    
    def test_dashboard_loads(self, client):
        """Test that dashboard page loads"""
        response = client.get('/')
        assert response.status_code == 200
        assert b'Web Vulnerability Scanner' in response.data
        assert b'Start a Scan' in response.data
    
    def test_dashboard_has_form(self, client):
        """Test that dashboard has scan form"""
        response = client.get('/')
        assert b'scanForm' in response.data
        assert b'targetUrl' in response.data
        assert b'Start Scan' in response.data
    
    def test_dashboard_has_scanner_options(self, client):
        """Test that dashboard lists all scanners"""
        response = client.get('/')
        assert b'Media & Links' in response.data
        assert b'XSS Detection' in response.data
        assert b'CSRF Protection' in response.data
        assert b'Auth Flaws' in response.data
        assert b'Deserialization' in response.data
    
    def test_dashboard_has_results_container(self, client):
        """Test that dashboard has results display area"""
        response = client.get('/')
        assert b'resultsContainer' in response.data
        assert b'Scan Results' in response.data
    
    def test_dashboard_has_static_files(self, client):
        """Test that CSS and JS files are referenced"""
        response = client.get('/')
        assert b'style.css' in response.data
        assert b'dashboard.js' in response.data
    
    def test_dashboard_has_statistics(self, client):
        """Test that dashboard has statistics section"""
        response = client.get('/')
        assert b'scanCount' in response.data
        assert b'criticalCount' in response.data
        assert b'highCount' in response.data
        assert b'mediumCount' in response.data


class TestScanAPI:
    """Test scan API endpoint"""
    
    def test_scan_requires_target(self, client):
        """Test that scan requires target parameter"""
        response = client.post('/scan', json={})
        assert response.status_code == 400
        assert b'required' in response.data or b'error' in response.data.lower()
    
    def test_scan_accepts_url(self, client):
        """Test that scan accepts URL as target"""
        response = client.post('/scan', json={
            'target': 'https://example.com',
            'scanners': ['MediaLinkScanner']
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'vulnerabilities' in data
        assert isinstance(data['vulnerabilities'], list)
    
    def test_scan_accepts_html_content(self, client):
        """Test that scan accepts HTML content"""
        html = '<form method="POST"><input name="user" /></form>'
        response = client.post('/scan', json={
            'target': html,
            'scanners': ['CSRFScanner']
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'vulnerabilities' in data
    
    def test_scan_accepts_code_snippet(self, client):
        """Test that scan accepts code snippets"""
        code = 'import pickle\nobj = pickle.loads(user_input)'
        response = client.post('/scan', json={
            'target': code,
            'scanners': ['InsecureDeserializationScanner']
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'vulnerabilities' in data
    
    def test_scan_returns_vulnerabilities_format(self, client):
        """Test that scan returns properly formatted vulnerabilities"""
        response = client.post('/scan', json={
            'target': '<form method="POST"></form>',
            'scanners': ['CSRFScanner']
        })
        data = response.get_json()
        
        for vuln in data['vulnerabilities']:
            assert 'issue' in vuln
            assert 'severity' in vuln
            assert vuln['severity'] in ['critical', 'high', 'medium', 'low']
    
    def test_scan_with_multiple_scanners(self, client):
        """Test scanning with multiple scanners"""
        response = client.post('/scan', json={
            'target': '<html><script>alert("xss")</script></html>',
            'scanners': ['XSSScanner', 'MediaLinkScanner']
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data['scanners_used'] == ['XSSScanner', 'MediaLinkScanner']
    
    def test_scan_default_all_scanners(self, client):
        """Test that scan uses all scanners by default"""
        response = client.post('/scan', json={
            'target': '<html></html>'
        })
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['scanners_used']) > 0
    
    def test_scan_ignores_invalid_scanner(self, client):
        """Test that invalid scanner names are ignored"""
        response = client.post('/scan', json={
            'target': '<html></html>',
            'scanners': ['InvalidScanner', 'XSSScanner']
        })
        assert response.status_code == 200
        data = response.get_json()
        assert 'XSSScanner' in data['scanners_used']
        assert 'InvalidScanner' not in data['scanners_used']
    
    def test_scan_response_includes_metadata(self, client):
        """Test that scan response includes metadata"""
        response = client.post('/scan', json={
            'target': '<html></html>',
            'scanners': ['XSSScanner']
        })
        data = response.get_json()
        assert 'target' in data
        assert 'vulnerabilities' in data
        assert 'scanners_used' in data
        assert 'count' in data


class TestHealthEndpoints:
    """Test health check and info endpoints"""
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
        assert data['scanners_available'] > 0
    
    def test_scanners_endpoint(self, client):
        """Test scanners list endpoint"""
        response = client.get('/scanners')
        assert response.status_code == 200
        data = response.get_json()
        assert 'scanners' in data
        assert len(data['scanners']) > 0
        assert 'MediaLinkScanner' in data['scanners']
        assert 'XSSScanner' in data['scanners']
        assert 'CSRFScanner' in data['scanners']
        assert 'AuthenticationFlawsScanner' in data['scanners']
        assert 'InsecureDeserializationScanner' in data['scanners']


class TestStaticFiles:
    """Test that static files are served correctly"""
    
    def test_css_file_exists(self, client):
        """Test that CSS file is served"""
        response = client.get('/static/css/style.css')
        assert response.status_code == 200
        assert b'--color-primary' in response.data or b'background' in response.data
    
    def test_js_file_exists(self, client):
        """Test that JavaScript file is served"""
        response = client.get('/static/js/dashboard.js')
        assert response.status_code == 200
        assert b'dashboard' in response.data.lower()


class TestErrorHandling:
    """Test error handling"""
    
    def test_scan_handles_empty_target(self, client):
        """Test that empty target is handled"""
        response = client.post('/scan', json={
            'target': '   ',
            'scanners': ['XSSScanner']
        })
        assert response.status_code == 400
    
    def test_scan_handles_malformed_json(self, client):
        """Test that malformed JSON is handled"""
        response = client.post('/scan', 
            data='invalid json',
            content_type='application/json'
        )
        assert response.status_code in [400, 500]
    
    def test_404_for_undefined_routes(self, client):
        """Test that undefined routes return 404"""
        response = client.get('/undefined-route')
        assert response.status_code == 404


class TestIntegration:
    """Integration tests"""
    
    def test_full_scan_workflow(self, client):
        """Test complete scan workflow"""
        # 1. Load dashboard
        response = client.get('/')
        assert response.status_code == 200
        
        # 2. Submit scan
        html_content = '''
        <html>
            <form method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
            </form>
            <script>alert("xss")</script>
        </html>
        '''
        
        scan_response = client.post('/scan', json={
            'target': html_content,
            'scanners': ['CSRFScanner', 'XSSScanner']
        })
        
        assert scan_response.status_code == 200
        data = scan_response.get_json()
        
        # 3. Verify response structure
        assert 'vulnerabilities' in data
        assert 'scanners_used' in data
        assert data['scanners_used'] == ['CSRFScanner', 'XSSScanner']
    
    def test_health_indicates_all_scanners_loaded(self, client):
        """Test that health check shows all scanners are loaded"""
        response = client.get('/health')
        data = response.get_json()
        
        # Should have at least 5 scanners loaded
        assert data['scanners_available'] >= 5
