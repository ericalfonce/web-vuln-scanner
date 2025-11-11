"""Configuration management for the web vulnerability scanner.

This module provides centralized configuration for scanner behavior,
rate limiting, IP blocklists, and plugin settings.
"""
import os
from typing import Dict, List, Set, Any
import json


class Config:
    """Base configuration class."""

    # Scanner Settings
    SCANNER_TIMEOUT = 30  # seconds
    SCANNER_MAX_RETRIES = 3
    SCANNER_FOLLOW_REDIRECTS = True

    # Rate Limiting
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 100
    RATE_LIMIT_WINDOW = 60  # seconds

    # IP Blocklist
    BLOCKLIST_ENABLED = True
    BLOCKLIST_PERSISTENCE = False  # Set to True for Redis

    # Security Headers
    SECURITY_HEADERS_ENABLED = True
    CUSTOM_SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'self'; img-src 'self' data:; "
            "object-src 'none'; frame-ancestors 'none';"
        ),
    }

    # Plugin Settings
    ENABLED_PLUGINS = [
        "MediaLinkScanner",
        "XSSScanner",
    ]

    # Suspicious Domains (for media/link scanner)
    SUSPICIOUS_DOMAINS = {
        "malicious.test",
        "bad.example",
        "phish.local",
        "exploit.site",
    }

    # XSS Scanner Settings
    XSS_CHECK_PATTERNS = True
    XSS_CHECK_EVENT_HANDLERS = True
    XSS_CHECK_DANGEROUS_FUNCTIONS = True

    # API Settings
    API_HOST = "0.0.0.0"
    API_PORT = 5000
    API_DEBUG = False

    # Logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()

        # Override from environment
        if os.getenv("RATE_LIMIT_ENABLED"):
            config.RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED").lower() == "true"

        if os.getenv("RATE_LIMIT_REQUESTS"):
            config.RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS"))

        if os.getenv("RATE_LIMIT_WINDOW"):
            config.RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW"))

        if os.getenv("SCANNER_TIMEOUT"):
            config.SCANNER_TIMEOUT = int(os.getenv("SCANNER_TIMEOUT"))

        if os.getenv("API_PORT"):
            config.API_PORT = int(os.getenv("API_PORT"))

        if os.getenv("API_DEBUG"):
            config.API_DEBUG = os.getenv("API_DEBUG").lower() == "true"

        return config

    @classmethod
    def from_file(cls, filepath: str) -> "Config":
        """Load configuration from JSON file."""
        config = cls()

        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                data = json.load(f)
                for key, value in data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            k: v for k, v in self.__class__.__dict__.items() if k.isupper()
        }

    def to_json(self) -> str:
        """Convert configuration to JSON."""
        return json.dumps(self.to_dict(), indent=2, default=str)


class DevelopmentConfig(Config):
    """Development configuration."""

    API_DEBUG = True
    LOG_LEVEL = "DEBUG"
    SCANNER_TIMEOUT = 60
    RATE_LIMIT_ENABLED = False  # Disable rate limiting in dev


class ProductionConfig(Config):
    """Production configuration."""

    API_DEBUG = False
    LOG_LEVEL = "INFO"
    SCANNER_TIMEOUT = 30
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 50  # More strict
    BLOCKLIST_PERSISTENCE = True  # Use Redis in production


class TestingConfig(Config):
    """Testing configuration."""

    API_DEBUG = True
    LOG_LEVEL = "DEBUG"
    SCANNER_TIMEOUT = 5
    RATE_LIMIT_ENABLED = False
    BLOCKLIST_PERSISTENCE = False


# Global configuration instance
_config = None


def get_config() -> Config:
    """Get the current configuration instance."""
    global _config
    if _config is None:
        env = os.getenv("FLASK_ENV", "development")
        if env == "production":
            _config = ProductionConfig()
        elif env == "testing":
            _config = TestingConfig()
        else:
            _config = DevelopmentConfig()
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config


def reload_config() -> None:
    """Reload configuration from environment."""
    global _config
    env = os.getenv("FLASK_ENV", "development")
    if env == "production":
        _config = ProductionConfig.from_env()
    elif env == "testing":
        _config = TestingConfig.from_env()
    else:
        _config = DevelopmentConfig.from_env()


def load_config_from_file(filepath: str) -> None:
    """Load configuration from a file."""
    global _config
    env = os.getenv("FLASK_ENV", "development")
    if env == "production":
        _config = ProductionConfig.from_file(filepath)
    elif env == "testing":
        _config = TestingConfig.from_file(filepath)
    else:
        _config = DevelopmentConfig.from_file(filepath)
