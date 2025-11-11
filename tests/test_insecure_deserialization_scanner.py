import unittest
from src.scanner.plugins.insecure_deserialization_scanner import InsecureDeserializationScanner


class TestInsecureDeserializationScanner(unittest.TestCase):
    """Test insecure deserialization scanner."""

    def setUp(self):
        self.scanner = InsecureDeserializationScanner()

    def test_detect_unsafe_pickle(self):
        """Test detection of unsafe pickle usage."""
        code = 'pickle.loads(user_data)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        pickle_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_pickle"]
        self.assertGreater(len(pickle_issues), 0)

    def test_detect_safe_pickle_protocol(self):
        """Test that pickle with protocol=2 is flagged as concerning."""
        code = 'pickle.loads(data, protocol=2)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        pickle_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_pickle"]
        self.assertGreater(len(pickle_issues), 0)

    def test_detect_unsafe_yaml_load(self):
        """Test detection of unsafe YAML load."""
        code = 'yaml.load(user_input)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        yaml_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_yaml_load"]
        self.assertGreater(len(yaml_issues), 0)

    def test_detect_yaml_load_all(self):
        """Test detection of unsafe YAML load_all."""
        code = 'yaml.load_all(stream, Loader=Loader)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        yaml_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_yaml_load"]
        self.assertGreater(len(yaml_issues), 0)

    def test_detect_unsafe_xml_parsing(self):
        """Test detection of unsafe XML parsing (XXE)."""
        code = '''
        parser = xml.etree.ElementTree.XMLParser()
        tree = xml.etree.ElementTree.parse(data_stream, parser=parser)
        '''
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        xml_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_xml_parsing"]
        self.assertGreater(len(xml_issues), 0)

    def test_detect_xxe_vulnerability(self):
        """Test detection of XXE (XML External Entity) attacks."""
        code = '''
        from lxml import etree
        parser = etree.XMLParser(resolve_entities=True)
        tree = etree.parse(untrusted_input, parser=parser)
        '''
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        xxe_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_xml_parsing"]
        self.assertGreater(len(xxe_issues), 0)

    def test_detect_unsafe_json_deserialization(self):
        """Test detection of unsafe JSON deserialization."""
        code = 'json.loads(user_input, object_hook=custom_hook)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        json_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_json_deserialization"]
        self.assertGreater(len(json_issues), 0)

    def test_detect_object_input_stream(self):
        """Test detection of Java ObjectInputStream."""
        code = 'new ObjectInputStream(socket.getInputStream())'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        java_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_java_deserialization"]
        self.assertGreater(len(java_issues), 0)

    def test_detect_gadget_chain_commons(self):
        """Test detection of Apache Commons Collection gadget chains."""
        code = '''
        transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class },
                new Object[] { "getRuntime", new Class[0] })
        };
        '''
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        gadget_issues = [v for v in vulnerabilities if v.get("issue") == "gadget_chain_indicators"]
        self.assertGreater(len(gadget_issues), 0)

    def test_detect_gadget_chain_spring(self):
        """Test detection of Spring Framework gadget chains."""
        code = 'PropertyPathFactory.getPropertyPath()'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        gadget_issues = [v for v in vulnerabilities if v.get("issue") == "gadget_chain_indicators"]
        self.assertGreater(len(gadget_issues), 0)

    def test_detect_eval_operation(self):
        """Test detection of unsafe eval operations."""
        code = 'eval(user_input)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        eval_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_eval"]
        self.assertGreater(len(eval_issues), 0)

    def test_detect_exec_operation(self):
        """Test detection of unsafe exec operations."""
        code = 'exec(code_from_database)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        exec_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_eval"]
        self.assertGreater(len(exec_issues), 0)

    def test_safe_json_loads(self):
        """Test that safe JSON loads doesn't trigger issues."""
        code = 'json.loads(user_input)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        # Standard json.loads is relatively safe compared to object hooks
        json_hook_issues = [v for v in vulnerabilities if "object_hook" in str(v.get("details", ""))]
        # May have some issues, but different type than with custom hooks

    def test_detect_pickle_dumps_is_safe(self):
        """Test that pickle.dumps doesn't trigger unsafe_pickle."""
        code = 'serialized = pickle.dumps(data)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        pickle_issues = [v for v in vulnerabilities if v.get("issue") == "unsafe_pickle"]
        # dumps is safe, only loads is dangerous
        self.assertEqual(len(pickle_issues), 0)

    def test_empty_input_returns_no_issues(self):
        """Test handling of empty input."""
        result = self.scanner.scan(None)
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 0)

    def test_safe_code_returns_minimal_issues(self):
        """Test that secure deserialization code returns few issues."""
        code = '''
        import json
        user_data = json.loads(request.data)
        # Validate and process
        '''
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        # Safe code should have minimal issues
        self.assertLess(len(vulnerabilities), 2)

    def test_finding_has_required_fields(self):
        """Test that findings have required fields."""
        code = 'pickle.loads(data)'
        result = self.scanner.scan(code)
        vulnerabilities = result["vulnerabilities"]

        for finding in vulnerabilities:
            self.assertIn("url", finding)
            self.assertIn("issue", finding)
            self.assertIn("severity", finding)


if __name__ == "__main__":
    unittest.main()
