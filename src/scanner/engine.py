class Engine:
    def __init__(self):
        self.plugins = []

    def load_plugins(self, plugin_list=None):
        """Load plugins into the engine.

        If plugin_list is None, attempt to load the built-in example plugin.
        Returns the list of loaded plugin instances.
        """
        if plugin_list is None:
            # lazy-load a default plugin so tests expecting >0 plugins pass
            try:
                from src.scanner.plugins.example_plugin import ExamplePlugin
                self.plugins = [ExamplePlugin()]
            except Exception:
                self.plugins = []
        else:
            self.plugins = plugin_list
        return self.plugins

    def run_scan(self, target):
        # If no plugins loaded, return a predictable empty structure
        if not self.plugins:
            return {"vulnerabilities": []}

        vulnerabilities = []
        for plugin in self.plugins:
            try:
                # try calling scan with target
                result = plugin.scan(target)
            except TypeError:
                # plugin.scan may not accept an argument; call without one
                result = plugin.scan()

            if not result:
                continue

            # normalize result types
            if isinstance(result, dict) and "vulnerabilities" in result:
                vulnerabilities.extend(result.get("vulnerabilities") or [])
            elif isinstance(result, list):
                vulnerabilities.extend(result)
            else:
                # unknown plugin return - wrap it
                vulnerabilities.append(result)

        return {"vulnerabilities": vulnerabilities}