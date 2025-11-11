import unittest
import json
import os
import tempfile
from src.config import (
    Config,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    get_config,
    set_config,
)


class TestConfig(unittest.TestCase):
    """Test configuration management."""

    def test_base_config_has_required_attributes(self):
        """Test that base config has required attributes."""
        config = Config()

        self.assertTrue(hasattr(config, "RATE_LIMIT_ENABLED"))
        self.assertTrue(hasattr(config, "RATE_LIMIT_REQUESTS"))
        self.assertTrue(hasattr(config, "RATE_LIMIT_WINDOW"))
        self.assertTrue(hasattr(config, "SCANNER_TIMEOUT"))
        self.assertTrue(hasattr(config, "API_PORT"))

    def test_development_config_has_debug_enabled(self):
        """Test that development config has debug enabled."""
        config = DevelopmentConfig()
        self.assertTrue(config.API_DEBUG)

    def test_production_config_has_debug_disabled(self):
        """Test that production config has debug disabled."""
        config = ProductionConfig()
        self.assertFalse(config.API_DEBUG)

    def test_production_config_stricter_rate_limits(self):
        """Test that production config has stricter rate limits."""
        dev_config = DevelopmentConfig()
        prod_config = ProductionConfig()

        self.assertLess(prod_config.RATE_LIMIT_REQUESTS, dev_config.RATE_LIMIT_REQUESTS)

    def test_testing_config_disabled_rate_limiting(self):
        """Test that testing config disables rate limiting."""
        config = TestingConfig()
        self.assertFalse(config.RATE_LIMIT_ENABLED)

    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        config = Config()
        config_dict = config.to_dict()

        self.assertIsInstance(config_dict, dict)
        self.assertIn("RATE_LIMIT_ENABLED", config_dict)
        self.assertIn("API_PORT", config_dict)

    def test_config_to_json(self):
        """Test converting config to JSON."""
        config = Config()
        config_json = config.to_json()

        self.assertIsInstance(config_json, str)
        parsed = json.loads(config_json)
        self.assertIsInstance(parsed, dict)
        self.assertIn("RATE_LIMIT_ENABLED", parsed)

    def test_config_from_file(self):
        """Test loading config from JSON file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            config_data = {
                "RATE_LIMIT_REQUESTS": 200,
                "SCANNER_TIMEOUT": 45,
                "API_PORT": 8080,
            }
            json.dump(config_data, f)
            temp_path = f.name

        try:
            config = Config.from_file(temp_path)
            self.assertEqual(config.RATE_LIMIT_REQUESTS, 200)
            self.assertEqual(config.SCANNER_TIMEOUT, 45)
            self.assertEqual(config.API_PORT, 8080)
        finally:
            os.unlink(temp_path)

    def test_config_from_env(self):
        """Test loading config from environment variables."""
        os.environ["RATE_LIMIT_REQUESTS"] = "150"
        os.environ["SCANNER_TIMEOUT"] = "60"

        try:
            config = Config.from_env()
            self.assertEqual(config.RATE_LIMIT_REQUESTS, 150)
            self.assertEqual(config.SCANNER_TIMEOUT, 60)
        finally:
            del os.environ["RATE_LIMIT_REQUESTS"]
            del os.environ["SCANNER_TIMEOUT"]

    def test_get_config_returns_singleton(self):
        """Test that get_config returns a singleton instance."""
        # Reset the global config
        import src.config
        src.config._config = None

        config1 = get_config()
        config2 = get_config()

        self.assertIs(config1, config2)

    def test_set_config(self):
        """Test setting a custom config."""
        custom_config = DevelopmentConfig()
        custom_config.RATE_LIMIT_REQUESTS = 999

        set_config(custom_config)
        retrieved_config = get_config()

        self.assertEqual(retrieved_config.RATE_LIMIT_REQUESTS, 999)

    def test_suspicious_domains_configured(self):
        """Test that suspicious domains are configured."""
        config = Config()
        self.assertGreater(len(config.SUSPICIOUS_DOMAINS), 0)
        self.assertIsInstance(config.SUSPICIOUS_DOMAINS, set)

    def test_security_headers_configured(self):
        """Test that security headers are configured."""
        config = Config()
        self.assertGreater(len(config.CUSTOM_SECURITY_HEADERS), 0)
        self.assertIn("X-Content-Type-Options", config.CUSTOM_SECURITY_HEADERS)
        self.assertIn("X-Frame-Options", config.CUSTOM_SECURITY_HEADERS)

    def test_enabled_plugins_list(self):
        """Test that enabled plugins are listed."""
        config = Config()
        self.assertIsInstance(config.ENABLED_PLUGINS, list)
        self.assertGreater(len(config.ENABLED_PLUGINS), 0)

    def test_log_level_configured(self):
        """Test that log level is configured."""
        config = Config()
        self.assertIn(config.LOG_LEVEL, ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])

    def test_config_attribute_types(self):
        """Test that config attributes have expected types."""
        config = Config()

        self.assertIsInstance(config.RATE_LIMIT_ENABLED, bool)
        self.assertIsInstance(config.RATE_LIMIT_REQUESTS, int)
        self.assertIsInstance(config.RATE_LIMIT_WINDOW, int)
        self.assertIsInstance(config.SCANNER_TIMEOUT, int)
        self.assertIsInstance(config.API_PORT, int)
        self.assertIsInstance(config.CUSTOM_SECURITY_HEADERS, dict)
        self.assertIsInstance(config.SUSPICIOUS_DOMAINS, set)
        self.assertIsInstance(config.ENABLED_PLUGINS, list)

    def test_xss_scanner_settings(self):
        """Test XSS scanner configuration."""
        config = Config()

        self.assertTrue(hasattr(config, "XSS_CHECK_PATTERNS"))
        self.assertTrue(hasattr(config, "XSS_CHECK_EVENT_HANDLERS"))
        self.assertTrue(hasattr(config, "XSS_CHECK_DANGEROUS_FUNCTIONS"))

        self.assertTrue(config.XSS_CHECK_PATTERNS)
        self.assertTrue(config.XSS_CHECK_EVENT_HANDLERS)
        self.assertTrue(config.XSS_CHECK_DANGEROUS_FUNCTIONS)


if __name__ == "__main__":
    unittest.main()
