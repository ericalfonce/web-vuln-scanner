from flask import Flask
from .routes import setup_routes
from .middleware import init_app as init_middleware

def create_app():
    app = Flask(__name__)
    # initialize protection middleware (security headers, basic rate limiting)
    try:
        init_middleware(app)
    except Exception:
        # don't hard-fail if middleware initialization has issues
        pass
    setup_routes(app)
    return app

app = create_app()