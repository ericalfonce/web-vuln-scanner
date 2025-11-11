from flask import Flask
from .routes import setup_routes
from .middleware import init_app as init_middleware
import os

def create_app():
    # Get absolute path for template and static folders
    base_dir = os.path.dirname(__file__)
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')
    
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir
    )
    
    # initialize protection middleware (security headers, basic rate limiting)
    try:
        init_middleware(app)
    except Exception:
        # don't hard-fail if middleware initialization has issues
        pass
    
    setup_routes(app)
    return app

app = create_app()