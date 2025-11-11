class ExamplePlugin:
    def scan(self, target=None):
        # This is a sample vulnerability check
        print("Running example vulnerability scan...", "target=", target)
        # Return a normalized structure so engine can collect data
        return {"vulnerabilities": []}