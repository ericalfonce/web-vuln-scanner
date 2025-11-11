class SQLInjectionRule:
    def apply(self, request):
        # Check for SQL injection patterns in the request
        sql_injection_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            '" OR "1"="1',
            '" OR "x"="x',
            "' UNION SELECT * FROM users --"
        ]
        
        for pattern in sql_injection_patterns:
            if pattern in request:
                return True  # SQL injection vulnerability detected
        
        return False  # No SQL injection vulnerability detected