import time
from flask import request, jsonify
from src.config import get_config

# Simple in-memory rate limiter and blocklist for demonstration only
_request_counts = {}
_window_start = {}
BLOCKED_IPS = set()


def init_app(app):
    @app.before_request
    def _check_blocklist_and_rate_limit():
        config = get_config()
        
        if not config.RATE_LIMIT_ENABLED:
            return
        
        ip = request.remote_addr or "unknown"
        if ip in BLOCKED_IPS:
            return jsonify({"error": "Your IP is blocked"}), 403

        now = int(time.time())
        window = now // config.RATE_LIMIT_WINDOW
        key = f"{ip}:{window}"
        count = _request_counts.get(key, 0) + 1
        _request_counts[key] = count
        # cleanup slightly older windows
        _window_start[ip] = window

        if count > config.RATE_LIMIT_REQUESTS:
            # add to blocked list for a short time (demonstration)
            BLOCKED_IPS.add(ip)
            return jsonify({"error": "Rate limit exceeded"}), 429

    @app.after_request
    def _set_security_headers(response):
        config = get_config()
        
        if not config.SECURITY_HEADERS_ENABLED:
            return response
        
        # Apply custom security headers from config
        for header_name, header_value in config.CUSTOM_SECURITY_HEADERS.items():
            response.headers.setdefault(header_name, header_value)
        
        return response
